#!/usr/bin/env python3
"""
plot_resources.py - graph what resource_monitor.py recorded during a run.

    python3 plot_resources.py captures/<stamp>              # one picture, a grid of graphs
    python3 plot_resources.py captures/<stamp> --separate   # plus one picture per graph

Reads resources-system.csv and resources-frr.csv from the folder, and events.json
if it is there (robot moves are drawn as thin vertical lines). Needs matplotlib.

Writes <folder>/analysis/resources.png: one graph per metric, one line per switch,
every graph on the same time axis so a move can be followed down the page. With
--separate it also writes analysis/resources-<metric>.png for use in a report.

resource_monitor.py runs this by itself when a run ends (MONITOR_PLOT=0 turns
that off); run it by hand to redraw an old capture.

To add or change a graph, edit PANELS below. The live page
(templates/resource_chart.html) has the same list - keep the two in step.
"""
import argparse
import csv
import json
import math
import os
import re
import sys

# Colours: one fixed colour per switch, in name order, the same in every graph.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SURFACE, INK, INK_2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"


def num(row, *keys):
    """Sum of the named columns, or None if any of them is blank."""
    values = [row.get(k) for k in keys]
    return None if any(v is None for v in values) else sum(values)


# (id, title, unit, source file, value per row, running total?, y axis from zero?)
#   running total = the column only ever grows; plot its change per second instead.
PANELS = [
    ("bgpd-cpu", "bgpd CPU", "% of one core", "system", lambda r: num(r, "bgpd_cpu_pct"), False, True),
    ("zebra-cpu", "zebra CPU", "% of one core", "system", lambda r: num(r, "zebra_cpu_pct"), False, True),
    ("bgpd-memory", "bgpd memory", "MB", "system",
     lambda r: None if r.get("bgpd_rss_kb") is None else r["bgpd_rss_kb"] / 1024.0, False, False),
    ("zebra-memory", "zebra memory", "MB", "system",
     lambda r: None if r.get("zebra_rss_kb") is None else r["zebra_rss_kb"] / 1024.0, False, False),
    ("mac-table", "MAC table (kernel)", "MACs", "system",
     lambda r: num(r, "k_fdb_local", "k_fdb_remote"), False, True),
    ("vrf-routes", "Routes in tenant VRF", "routes", "system", lambda r: num(r, "k_vrf_routes"), False, True),
    ("evpn-routes", "EVPN routes in BGP", "routes", "frr", lambda r: num(r, "bgp_evpn_prefixes"), False, True),
    ("bgp-messages", "BGP messages", "per second", "frr",
     lambda r: num(r, "bgp_msgs_rcvd", "bgp_msgs_sent"), True, True),
    ("bestpath-runs", "BGP best-path runs", "per second", "frr",
     lambda r: num(r, "bgp_bestpath_runs"), True, True),
    ("machine-cpu", "Whole machine CPU", "%", "machine", lambda r: num(r, "host_cpu_pct"), False, True),
]


# -------------------------------------------------------------------- input ---
def read_csv(path):
    """CSV -> list of rows; numbers as float, blank cells as None."""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, newline="") as fh:
        for raw in csv.DictReader(fh):
            row = {}
            for key, value in raw.items():
                if key in ("node", "error"):
                    row[key] = value
                else:
                    try:
                        row[key] = float(value)
                    except (TypeError, ValueError):
                        row[key] = None
            if row.get("t_unix") is not None:
                rows.append(row)
    return rows


def natural(name):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", name)]


def read_moves(folder):
    """Times of robot moves from events.json (unix seconds); empty if there is none."""
    path = os.path.join(folder, "events.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path) as fh:
            events = json.load(fh)
    except (OSError, ValueError):
        return []
    for name in ("move_start", "move_call_start"):
        times = [e["unix_time"] for e in events if isinstance(e, dict) and e.get("event") == name]
        if times:
            return times
    return []


def build(rows, value, running_total, t0):
    """{switch: (seconds, values)} for one graph; gaps where a value is missing."""
    out, last = {}, {}
    for row in sorted(rows, key=lambda r: r["t_unix"]):
        node, t, v = row["node"], row["t_unix"], value(row)
        if running_total:
            before = last.get(node)
            last[node] = (t, v)
            if before is None or v is None or before[1] is None or t <= before[0] or v < before[1]:
                v = None                             # first sample, or the daemon restarted
            else:
                v = (v - before[1]) / (t - before[0])
        xs, ys = out.setdefault(node, ([], []))
        xs.append(t - t0)
        ys.append(math.nan if v is None else v)
    return out


# --------------------------------------------------------------------- draw ---
def compact(names):
    """['leaf1', 'leaf2', 'leaf3', 'spine1'] -> 'leaf1-3, spine1'."""
    plain, numbered = [], {}
    for name in names:
        m = re.match(r"^(.*?)(\d+)$", name)
        if m:
            numbered.setdefault(m.group(1), []).append(int(m.group(2)))
        else:
            plain.append(name)
    for prefix, nums in numbered.items():
        nums.sort()
        parts, start, prev = [], nums[0], nums[0]
        for x in nums[1:] + [None]:
            if x is not None and x == prev + 1:
                prev = x
                continue
            parts.append(str(start) if start == prev else "{}-{}".format(start, prev))
            start = prev = x
        plain.append(prefix + ",".join(parts))
    return ", ".join(plain)


def end_labels(ax, data):
    """Name the lines at their right-hand end. Lines that finish on top of each
    other share one label, so a hidden line is still accounted for."""
    ends = sorted((ys[i], node) for node, (xs, ys) in data.items()
                  for i in [max((k for k, y in enumerate(ys) if not math.isnan(y)), default=None)]
                  if i is not None)
    if not ends:
        return
    lo, hi = ax.get_ylim()
    groups = []                                     # [value of the lowest line, [switches]]
    for y, node in ends:
        if groups and y - groups[-1][0] <= (hi - lo) * 0.035:
            groups[-1][1].append(node)
        else:
            groups.append([y, [node]])
    floor = -math.inf
    for y, members in groups:
        at = max(y, floor)                          # keep labels from printing over each other
        floor = at + (hi - lo) * 0.085
        text = compact(sorted(members, key=natural))
        if len(members) == len(data) and len(members) > 1:
            text = "all"
        elif len(text) > 9:                         # too long for the margin
            text = "{} switches".format(len(members))
        ax.annotate(text, xy=(1.0, min(at, hi)), xycoords=("axes fraction", "data"), xytext=(5, 0),
                    textcoords="offset points", va="center", fontsize=7.5, color=INK_2, annotation_clip=False)


def style(ax, title, unit, from_zero, xlim):
    ax.set_facecolor(SURFACE)
    ax.set_title("{}  ({})".format(title, unit), loc="left", fontsize=10, color=INK, pad=6)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(colors=INK_2, labelsize=8, length=0)
    ax.set_xlim(*xlim)
    values = [y for line in ax.get_lines() for y in line.get_ydata() if not math.isnan(y)]
    lo, hi = (min(values), max(values)) if values else (0.0, 1.0)
    if from_zero:
        ax.set_ylim(0, hi * 1.1 if hi > 0 else 1)
    else:
        # Show at least a tenth of the value, so a change of a few kB is not
        # stretched over the whole graph.
        span = max(hi - lo, 0.1 * abs(hi), 1e-6)
        mid = (hi + lo) / 2.0
        ax.set_ylim(mid - span * 0.6, mid + span * 0.6)


def draw(ax, panel, data, colors, moves, xlim):
    _, title, unit, source, _, _, from_zero = panel
    for node, (xs, ys) in data.items():
        ax.plot(xs, ys, color=INK_2 if source == "machine" else colors.get(node, MUTED),
                linewidth=1.6, solid_joinstyle="round", solid_capstyle="round", zorder=2, clip_on=False)
    style(ax, title, unit, from_zero, xlim)
    for x in moves:
        ax.axvline(x, color=AXIS, linewidth=0.8, zorder=1)
    if source != "machine":
        end_labels(ax, data)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", help="capture folder holding resources-system.csv / resources-frr.csv")
    ap.add_argument("--separate", action="store_true", help="also save one picture per graph")
    ap.add_argument("--out", help="output folder (default: <folder>/analysis)")
    args = ap.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.lines import Line2D
    except ImportError:
        sys.exit("matplotlib is not installed - no graphs (python3 -m pip install matplotlib)")

    system = read_csv(os.path.join(args.folder, "resources-system.csv"))
    frr = read_csv(os.path.join(args.folder, "resources-frr.csv"))
    if not system and not frr:
        sys.exit("{}: no resources-system.csv / resources-frr.csv with data".format(args.folder))

    t0 = min(r["t_unix"] for r in system + frr)
    t_end = max(r["t_unix"] for r in system + frr) - t0
    xlim = (0, max(t_end, 1.0))
    nodes = sorted({r["node"] for r in system + frr}, key=natural)
    colors = {n: SERIES[i] for i, n in enumerate(nodes) if i < len(SERIES)}   # never reuse a colour
    moves = [t - t0 for t in read_moves(args.folder) if -1 <= t - t0 <= t_end + 1]

    # The machine columns repeat on every row of a sweep: take them from one switch.
    one = system[0]["node"] if system else None
    machine = [dict(r, node="machine") for r in system if r["node"] == one]
    rows_for = {"system": system, "frr": frr, "machine": machine}
    panels = [(p, build(rows_for[p[3]], p[4], p[5], t0)) for p in PANELS if rows_for[p[3]]]

    out = args.out or os.path.join(args.folder, "analysis")
    os.makedirs(out, exist_ok=True)
    name = os.path.basename(os.path.normpath(args.folder))
    note = "one line per switch" + (" · vertical lines: robot moves ({})".format(len(moves)) if moves else "")
    keys = [Line2D([0], [0], color=colors.get(n, MUTED), linewidth=2) for n in nodes]

    def legend(fig, y):
        fig.legend(keys, nodes, loc="upper left", bbox_to_anchor=(0.045, y), ncol=len(nodes), frameon=False,
                   fontsize=9, labelcolor=INK_2, handlelength=1.6, columnspacing=1.6)

    rows = (len(panels) + 1) // 2
    fig, axes = plt.subplots(rows, 2, figsize=(13, 1.2 + 2.6 * rows), sharex=True, squeeze=False)
    fig.patch.set_facecolor(SURFACE)
    for ax, (panel, data) in zip(axes.flat, panels):
        draw(ax, panel, data, colors, moves, xlim)
    for ax in axes.flat[len(panels):]:
        ax.set_visible(False)
    for ax in axes.flat[max(0, len(panels) - 2):len(panels)]:
        ax.set_xlabel("seconds since monitoring started", fontsize=9, color=INK_2)
        ax.tick_params(labelbottom=True)
    top = 1 - 1.4 / fig.get_figheight()
    fig.subplots_adjust(left=0.05, right=0.935, top=top, bottom=0.6 / fig.get_figheight(), hspace=0.42, wspace=0.24)
    fig.text(0.05, 1 - 0.32 / fig.get_figheight(), "Switch resources - {}".format(name), fontsize=14,
             color=INK, weight="bold")
    fig.text(0.05, 1 - 0.56 / fig.get_figheight(), note, fontsize=9.5, color=INK_2)
    legend(fig, 1 - 0.62 / fig.get_figheight())
    path = os.path.join(out, "resources.png")
    fig.savefig(path, dpi=130, facecolor=SURFACE)
    plt.close(fig)
    print("wrote {}".format(path))

    if args.separate:
        for panel, data in panels:
            fig, ax = plt.subplots(figsize=(8, 3.8))
            fig.patch.set_facecolor(SURFACE)
            draw(ax, panel, data, colors, moves, xlim)
            ax.set_xlabel("seconds since monitoring started", fontsize=9, color=INK_2)
            fig.subplots_adjust(left=0.08, right=0.9, top=0.74, bottom=0.14)
            fig.text(0.08, 0.93, "Switch resources - {}".format(name), fontsize=12, color=INK, weight="bold")
            if panel[3] != "machine":
                legend(fig, 0.9)
            path = os.path.join(out, "resources-{}.png".format(panel[0]))
            fig.savefig(path, dpi=130, facecolor=SURFACE)
            plt.close(fig)
            print("wrote {}".format(path))


if __name__ == "__main__":
    main()