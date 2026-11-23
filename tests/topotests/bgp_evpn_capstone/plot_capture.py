#!/usr/bin/env python3
"""
plot_capture.py — rebuild the "RT-2 / queue / EVPN routes / DAD over time" chart
from one bgp_evpn_capstone capture folder.

Works for both test styles and works out which one it is on its own:
  * Make-before-break  (movement.json moves have "old_link_removed")
  * Break-before-make  (movement.json moves have "detached"/"attached")

Usage
-----
    python3 plot_capture.py <capture_dir> [-o OUT_PREFIX] [--spine spine1] [--title "..."]

    # e.g.
    python3 plot_capture.py "MBB - multiple movement/captures/20261117T191537-954125Z"
    python3 plot_capture.py multiple_robot_movement/captures/20261117T183906-697951Z -o bbm_run

By default it writes  <capture_dir>/analysis/<run_id>-chart.png  and  .svg

What it reads from the capture folder (all produced by the existing tests):
    movement.json              batch / move timing, DAD settings, dwell or break timers
    analysis/summary.json      EVPN route counts per checkpoint, DAD events + duplicate flags
    analysis/rt2_events.csv    every RT-2 NLRI seen in the spine pcaps

What each line means
--------------------
    RT-2 Advertisements  running total of originating Type-2 advertisements received at the spine
    RT-2 Withdrawals     running total of originating Type-2 withdrawals received at the spine
    Total EVPN routes    EVPN routes summed across all leafN tables at each batch checkpoint
    Spine update queue   RT-2 NLRI the spine has received minus re-sent (1 s rolling max)
    DAD flags            running total of isDuplicate flags on the leaves at each checkpoint
    Red triangles        batches where zebra logged new DAD detections (MBB, when present)

Requires: python3, matplotlib, numpy   (pip install matplotlib numpy)
"""
import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import textwrap
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------- styling
C = dict(routes="#2a78d6", adv="#1baf7a", wd="#6250d6", queue="#eda100", dad="#e34948",
         ink="#0b0b0b", ink2="#52514e", muted="#8a8984", grid="#e6e5e0", surf="#fcfcfb",
         band="#f0efea", keybg="#f4f3ef", keyedge="#dcdad3")
WD_LS = (0, (1.5, 1.5))
ROUTES_LS = (0, (6, 3))


# ---------------------------------------------------------------- loading
def load(cap, spine):
    mv = json.load(open(os.path.join(cap, "movement.json")))
    summ = json.load(open(os.path.join(cap, "analysis", "summary.json")))
    rows = list(csv.DictReader(open(os.path.join(cap, "analysis", "rt2_events.csv"))))

    first = mv["batches"][0]["moves"][0]
    if "old_link_removed" in first:
        mode, end_key = "MBB", "old_link_removed"
        dwell = mv.get("dwell_after_handoff_s", 0.0)
    elif "detached" in first:
        mode, end_key = "BBM", "learn_end"
        dwell = mv.get("dwell_after_learning_s", 0.0)
    else:
        sys.exit("movement.json: can't tell MBB from BBM (no old_link_removed / detached in moves)")

    T0 = min(m["started"] for m in mv["batches"][0]["moves"])
    batches = []
    for b in mv["batches"]:
        st = min(m["started"] for m in b["moves"]) - T0
        en = max(m.get(end_key) or m["learn_end"] for m in b["moves"]) - T0
        batches.append(dict(n=b["batch"], start=st, end=en, ckpt=en + dwell, moves=b["moves"]))

    rows = [r for r in rows if r["capture"] == spine]
    if not rows:
        sys.exit(f"rt2_events.csv has no rows for capture '{spine}' (try --spine spine2)")
    for r in rows:
        r["t"] = float(r["unix_time"]) - T0
    rows.sort(key=lambda r: r["t"])

    robots = sorted({m["robot"] for b in batches for m in b["moves"]})
    leaves = sorted({m[k] for b in batches for m in b["moves"] for k in ("new_leaf", "old_leaf") if m.get(k)})
    n_moves = sum(len(b["moves"]) for b in batches)
    spines = sorted(k for k in summ["evpn_route_counts"].get("before", {}) if k.startswith("spine"))
    run_id = os.path.basename(os.path.normpath(cap))
    return dict(mv=mv, summ=summ, rows=rows, mode=mode, T0=T0, batches=batches, robots=robots,
                leaves=leaves, n_moves=n_moves, spines=spines, run_id=run_id, spine=spine)


# ---------------------------------------------------------------- series
def series(d):
    rows, batches, summ = d["rows"], d["batches"], d["summ"]

    def cum(action):
        ts = [r["t"] for r in rows if r["direction"] == "in" and r["originated"] == "True"
              and r["action"] == action and r["t"] >= 0]
        return np.r_[0.0, ts], np.arange(0, len(ts) + 1)

    adv_t, adv_n = cum("advertise")
    wd_t, wd_n = cum("withdraw")

    # spine queue: RT-2 NLRI received but not yet re-sent
    t_end = batches[-1]["ckpt"] + 1.0
    step = 0.05
    grid = np.arange(-1.0, t_end, step)
    in_t = np.sort([r["t"] for r in rows if r["direction"] == "in"])
    out_t = np.sort([r["t"] for r in rows if r["direction"] == "out"])
    backlog = np.searchsorted(in_t, grid, "right") - np.searchsorted(out_t, grid, "right")
    w = int(1.0 / step)
    roll = np.array([backlog[max(0, i - w // 2): i + w // 2 + 1].max() for i in range(len(backlog))])
    queue = np.convolve(roll, np.ones(9) / 9, mode="same")

    # total EVPN routes summed across leaf tables, one point per checkpoint
    erc = summ["evpn_route_counts"]

    def leafsum(cp):
        return sum(v for k, v in erc[cp].items() if k.startswith("leaf"))

    rt = [(0.0, leafsum("before"))] if "before" in erc else []
    for b in batches:
        cp = f"batch-{b['n']}"
        if cp in erc:
            rt.append((b["ckpt"], leafsum(cp)))

    # DAD: cumulative duplicate flags at checkpoints
    flags = Counter(s["checkpoint"] for s in summ["dad"].get("duplicate_samples", []))
    dad_x, dad_y, c = [0.0], [0], 0
    for b in batches:
        c += flags.get(f"batch-{b['n']}", 0)
        dad_x.append(b["ckpt"]); dad_y.append(c)
    dad_x, dad_y = np.array(dad_x), np.array(dad_y)

    # zebra DAD detections (log lines start "YYYY/MM/DD HH:MM:SS", UTC) -> batch
    det = Counter()
    for e in summ["dad"].get("events", []):
        m = re.match(r"(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)", e.get("log", ""))
        if not m:
            continue
        t = dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").replace(
            tzinfo=dt.timezone.utc).timestamp() - d["T0"]
        # log is truncated to the second: pick the batch that started inside that second, else the latest before it
        b = next((b for b in batches if t - 0.05 <= b["start"] < t + 1.0), None) \
            or max((b for b in batches if b["start"] <= t + 1.0), key=lambda b: b["start"], default=batches[0])
        det[b["n"]] += 1
    det_batches = [(b, det[b["n"]]) for b in batches if det[b["n"]]]

    return dict(adv_t=adv_t, adv_n=adv_n, wd_t=wd_t, wd_n=wd_n, grid=grid, queue=queue,
                queue_peak=int(roll.max()) if len(roll) else 0, routes=rt,
                dad_x=dad_x, dad_y=dad_y, det_batches=det_batches,
                total_flags=sum(flags.values()), n_events=len(summ["dad"].get("events", [])))


# ---------------------------------------------------------------- key panel
def add_key(fig, entries, left=0.725, bottom=0.12, width=0.26, height=0.72):
    k = fig.add_axes([left, bottom, width, height])
    k.set_xlim(0, 1); k.set_ylim(0, 1); k.axis("off")
    k.add_patch(mpatches.FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0,rounding_size=0.02",
                fc=C["keybg"], ec=C["keyedge"], lw=1, transform=k.transAxes, clip_on=False))
    k.text(0.06, 0.965, "How to read this chart", fontsize=12.5, fontweight="bold", color=C["ink"], va="top")
    wrapped = [textwrap.wrap(e["body"], 37) for e in entries]
    title_h, line_h, gap = 0.040, 0.031, 0.030
    need = sum(title_h + len(w) * line_h + gap for w in wrapped)
    s = min(1.0, 0.86 / need)
    title_h, line_h, gap = title_h * s, line_h * s, gap * s
    y = 0.88
    for e, w in zip(entries, wrapped):
        x0, x1 = 0.06, 0.20
        if e["kind"] == "line":
            k.plot([x0, x1], [y, y], color=e["color"], lw=e.get("lw", 2.4), ls=e.get("ls", "-"),
                   solid_capstyle="round")
        elif e["kind"] == "band":
            k.add_patch(mpatches.Rectangle((x0, y - 0.022), x1 - x0, 0.044, fc=e["color"], ec="#cfcdc5", lw=0.6))
        elif e["kind"] == "marker":
            k.scatter([(x0 + x1) / 2], [y], marker=e["marker"], s=70, color=e["color"])
        k.text(0.25, y + 0.004, e["title"], fontsize=10.8, fontweight="bold", color=C["ink"], va="center")
        for i, line in enumerate(w):
            k.text(0.25, y - title_h * 0.75 - i * line_h, line, fontsize=9.3, color=C["ink2"], va="top")
        y -= title_h + len(w) * line_h + gap


# ---------------------------------------------------------------- plot
def plot(d, S, out_prefix, title=None, svg=True):
    batches, mv, mode, spine = d["batches"], d["mv"], d["mode"], d["spine"]
    dad_settings = next(iter(mv.get("dad_settings", {}).values()), {}) or {}
    max_moves = dad_settings.get("maxMoves", "?")
    det_time = dad_settings.get("detectionTime", "?")
    freeze = "on" if dad_settings.get("isDetectionFreeze") else "off"

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12})
    fig, ax = plt.subplots(figsize=(13.33, 7.5), dpi=200)
    fig.patch.set_facecolor(C["surf"]); ax.set_facecolor(C["surf"])

    x_last = batches[-1]["ckpt"]
    xmax = x_last + 9
    top = max(S["adv_n"][-1], S["wd_n"][-1], S["dad_y"][-1], S["queue_peak"],
              max((v for _, v in S["routes"]), default=0))
    ymax = float(np.ceil(top * 1.12 / 25.0) * 25)

    for b in batches:
        ax.axvspan(b["start"], b["end"], color=C["band"], lw=0, zorder=0)

    # --- series
    if S["routes"]:
        rx = [p[0] for p in S["routes"]] + [x_last + 0.4]
        ry = [p[1] for p in S["routes"]] + [S["routes"][-1][1]]
        ax.step(rx, ry, where="post", color=C["routes"], lw=2, ls=ROUTES_LS, zorder=3)
    ax.plot(S["adv_t"], S["adv_n"], color=C["adv"], lw=2, zorder=4)
    ax.plot(S["wd_t"], S["wd_n"], color=C["wd"], lw=2, ls=WD_LS, zorder=4)
    ax.plot(S["grid"], S["queue"], color=C["queue"], lw=2, zorder=3)

    dx, dy = S["dad_x"], S["dad_y"]
    xs = np.linspace(0, dx[-1], 600)
    ys = np.interp(xs, dx, dy)
    if dy[-1] > 0:
        ys = np.convolve(np.pad(ys, 15, mode="edge"), np.ones(31) / 31, mode="valid")
    ax.plot(xs, ys, color=C["dad"], lw=3.2, zorder=5)
    ax.scatter(dx[1:], dy[1:], s=22, color=C["dad"], edgecolor=C["surf"], lw=1.2, zorder=6)

    # --- DAD annotations
    if S["det_batches"]:
        first = S["det_batches"][0][0]
        ax.axvline(first["start"], color=C["dad"], lw=1, ls=(0, (2, 3)), zorder=1)
        ax.annotate("", xy=(first["start"], -0.042 * ymax), xytext=(0, -0.042 * ymax),
                    arrowprops=dict(arrowstyle="<->", color=C["ink"], lw=1.4), annotation_clip=False)
        quiet = f"batches 1–{first['n'] - 1}" if first["n"] > 2 else "batch 1"
        ax.text(first["start"] / 2, -0.07 * ymax, f"ΔT ≈ {first['start']:.0f} s  ({quiet}, no DAD)",
                ha="center", va="top", fontsize=11.5, fontweight="bold", color=C["ink"], clip_on=False)
        for b, n in S["det_batches"]:
            ax.text(b["start"] + 0.35, 0.088 * ymax, f"+{n} DAD\n(B{b['n']})", ha="left", va="bottom",
                    fontsize=8.8, color=C["dad"], fontweight="bold", linespacing=1.0)
            ax.scatter([b["start"]], [0], marker="v", s=60, color=C["dad"], zorder=7, clip_on=False)
    elif S["total_flags"] == 0:
        ax.text(0.8, 0.95 * ymax, f"{S['n_events']} Zebra DAD detections · 0 duplicate flags",
                fontsize=11, color=C["dad"], fontweight="bold", va="top")
        if mode == "BBM":
            adv = [r for r in d["rows"] if r["direction"] == "in" and r["originated"] == "True"
                   and r["action"] == "advertise" and r["t"] >= 0]
            noseq = sum(1 for r in adv if not r["sequence"])
            ax.text(0.8, 0.905 * ymax,
                    "Old route is withdrawn before the new leaf\nlearns the MAC, so each move is a fresh learn:\n"
                    f"{noseq}/{len(adv)} adverts carry no MAC-mobility\n"
                    f"sequence and the {max_moves}-move counter never builds.",
                    fontsize=9.8, color=C["dad"], va="top", linespacing=1.3)

    if mode == "BBM":
        gaps = [(m["attached"] - m["detached"]) * 1000 for b in batches for m in b["moves"]
                if m.get("attached") and m.get("detached")]
        if gaps:
            brk = mv.get("break_s")
            ax.text(0.2, -0.07 * ymax,
                    f"Break before make: old link down → new link up ≈ {np.mean(gaps):.0f} ms per move"
                    + (f" (break timer {brk * 1000:.0f} ms)" if brk else ""),
                    ha="left", va="top", fontsize=11.5, fontweight="bold", color=C["ink"], clip_on=False)

    # route dip callout (any checkpoint below the starting total)
    if S["routes"]:
        base = S["routes"][0][1]
        low = min(S["routes"][1:], key=lambda p: p[1], default=None)
        if low and low[1] < base - 2:
            bn = next((b["n"] for b in batches if abs(b["ckpt"] - low[0]) < 1e-6), "?")
            ax.annotate(f"dip to {low[1]} at B{bn}\n({base - low[1]} routes missing)", xy=(low[0] + 1.0, low[1]),
                        xytext=(low[0] + 1.0, base + 0.06 * ymax), fontsize=9, color=C["ink2"], ha="left",
                        bbox=dict(boxstyle="round,pad=0.2", fc=C["surf"], ec="none", alpha=0.9),
                        arrowprops=dict(arrowstyle="-", color=C["muted"], lw=0.8))

    # --- direct labels
    lab = dict(fontsize=12.5, va="center", fontweight="bold", color=C["ink"])
    a_end, w_end = S["adv_n"][-1], S["wd_n"][-1]
    sep = 0.03 * ymax if abs(a_end - w_end) < 0.06 * ymax else 0
    ax.text(S["adv_t"][-1] + 0.8, a_end + sep, f"RT-2 Adv.  ({a_end})", **lab)
    ax.text(S["wd_t"][-1] + 0.8, w_end - sep - (0.01 * ymax if sep else 0), f"RT-2 Withd.  ({w_end})", **lab)
    if S["routes"]:
        last = S["routes"][-1][1]
        vals = {v for _, v in S["routes"][1:]}
        desc = f"flat at {last}" if len(vals) == 1 or (max(vals) - min(vals) <= 2 and min(vals) >= S["routes"][0][1] - 2) else f"{last} at end"
        ax.text(x_last + 0.8, last - 0.02 * ymax, f"Total EVPN routes\n(leaf sum, {desc})",
                fontsize=11.5, fontweight="bold", va="top", color=C["ink"])
    if dy[-1] > 0:
        ax.text(dx[-1] + 0.6, dy[-1] + 0.01 * ymax, f"DAD flags\n({dy[-1]} by B{batches[-1]['n']})",
                **{**lab, "color": C["dad"]})
    else:
        ax.text(x_last + 0.6, 0.13 * ymax, "DAD flags (0)", **{**lab, "color": C["dad"]})
    ax.text(S["grid"][-1] + 0.4, 0.065 * ymax, f"{spine.capitalize()} update\nqueue (in − out)",
            color=C["ink"], fontsize=11, va="center")
    gq = S["grid"]; qi = int(np.argmax(S["queue"]))
    ax.annotate(f"peak {S['queue_peak']} NLRI", xy=(gq[qi], S["queue"][qi]),
                xytext=(gq[qi] + 1.6, S["queue"][qi] + 0.02 * ymax + 4), fontsize=9, color=C["ink2"], zorder=8,
                bbox=dict(boxstyle="round,pad=0.2", fc=C["surf"], ec="none", alpha=0.9),
                arrowprops=dict(arrowstyle="-", color=C["muted"], lw=0.8))

    # --- axes
    ax.set_xlim(-0.5, xmax); ax.set_ylim(0, ymax)
    for s_ in ("top", "right"):
        ax.spines[s_].set_visible(False)
    for s_ in ("left", "bottom"):
        ax.spines[s_].set_color(C["ink2"]); ax.spines[s_].set_linewidth(1.2)
    ax.plot(1, 0, ">", transform=ax.get_yaxis_transform(), clip_on=False, color=C["ink2"], ms=7)
    ax.plot(0, 1, "^", transform=ax.get_xaxis_transform(), clip_on=False, color=C["ink2"], ms=7)
    ax.yaxis.grid(True, color=C["grid"], lw=0.8); ax.set_axisbelow(True)
    ax.tick_params(colors=C["ink2"], length=0, pad=6)
    every = max(1, len(batches) // 20)  # thin out batch labels on long runs
    ax.set_xticks([b["start"] for b in batches][::every])
    ax.set_xticklabels([f"B{b['n']}" for b in batches][::every], fontsize=9.5, color=C["ink2"])
    per = len(batches[0]["moves"])
    ax.set_xlabel(f"time (s since first move) — each tick = one batch of {per} simultaneous robot moves",
                  color=C["ink2"], fontsize=11, labelpad=30)
    sec = ax.secondary_xaxis("top")
    sec.set_xticks(range(0, int(xmax), 10)); sec.tick_params(colors=C["muted"], length=0, labelsize=9.5)
    sec.spines["top"].set_visible(False); sec.set_xlabel("seconds", color=C["muted"], fontsize=9.5)
    ax.set_ylabel("# of RT-2 Adv / Withd · queue depth · total EVPN routes · DAD flags", color=C["ink2"], fontsize=11)

    # --- titles + footer
    name = "Make-before-break" if mode == "MBB" else "Break-before-make"
    if title is None:
        title = (f"{name} — {len(d['robots'])} robots on {len(d['leaves'])} leafs over "
                 f"{len(d['spines']) or '?'} spines, {d['n_moves']} moves")
    if S["det_batches"]:
        sub = (f"Routing stays linear; duplicate-address detection (max-moves {max_moves} / {det_time} s, "
               f"freeze {freeze}) takes over from batch {S['det_batches'][0][0]['n']}")
    elif S["total_flags"]:
        sub = f"DAD settings: max-moves {max_moves} / {det_time} s, freeze {freeze}"
    else:
        sub = (f"DAD settings max-moves {max_moves} / {det_time} s, freeze {freeze} — DAD never fires in this run")
    fig.text(0.055, 0.955, title, fontsize=19, fontweight="bold", color=C["ink"])
    fig.text(0.055, 0.915, sub, fontsize=12, color=C["ink2"])
    summ = d["summ"]
    bgp = summ.get("bgp_sessions", {})
    drops = sum(v.get("drops", 0) for v in bgp.values() if isinstance(v, dict)) if isinstance(bgp, dict) and bgp else None
    fig.text(0.055, 0.018,
             f"Run {d['run_id']} · RT-2 = originating Type-2 NLRI (MAC + MAC/IP) received at {spine} (pcap) · "
             f"queue = {spine} RT-2 in − out, 1 s rolling max\n"
             "DAD flags = cumulative duplicate flags on the leaves at each batch checkpoint "
             "(repeat flags can be the same detection) · "
             f"{summ.get('moves_completed', '?')}/{summ.get('moves_planned', '?')} moves completed, "
             f"{summ.get('batch_mappings_correct', '?')}/{summ.get('moves_planned', '?')} correct mappings"
             + (f", {drops} BGP session drops" if drops is not None else ""),
             fontsize=8.3, color=C["muted"])

    fig.subplots_adjust(left=0.07, right=0.60, top=0.82, bottom=0.18)
    entries = [
        dict(kind="line", color=C["adv"], title="RT-2 Advertisements",
             body=f"Type-2 routes sent by the new leaf when a robot arrives (running total, seen at {spine})."),
        dict(kind="line", color=C["wd"], ls=WD_LS, title="RT-2 Withdrawals",
             body=f"Type-2 routes pulled by the old leaf when a robot leaves (running total, seen at {spine})."),
        dict(kind="line", color=C["routes"], ls=ROUTES_LS, title="Total EVPN routes",
             body="EVPN routes held across all leaf tables at each checkpoint."),
        dict(kind="line", color=C["queue"], title=f"{spine.capitalize()} update queue",
             body=f"Updates {spine} has received but not yet passed on to the other leaves."),
        dict(kind="line", color=C["dad"], lw=3.4, title="DAD flags",
             body=f"Running total of duplicate-address flags on the leaves. FRR flags after "
                  f"{max_moves} moves / {det_time} s."),
    ]
    if S["det_batches"]:
        entries.append(dict(kind="marker", marker="v", color=C["dad"], title="Red triangles",
                            body="Batches where zebra logged new DAD detections."))
    entries.append(dict(kind="band", color=C["band"], title="Grey bands",
                        body=f"One batch: {per} robots moving at once."))
    add_key(fig, entries)

    fig.savefig(out_prefix + ".png", facecolor=C["surf"])
    if svg:
        fig.savefig(out_prefix + ".svg", facecolor=C["surf"])
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture_dir", help="capture folder containing movement.json and analysis/")
    ap.add_argument("-o", "--out", help="output path prefix (default: <capture>/analysis/<run>-chart)")
    ap.add_argument("--spine", default="spine1", help="which spine's pcap to count RT-2 at (default spine1)")
    ap.add_argument("--title", help="override the chart title")
    ap.add_argument("--no-svg", action="store_true", help="only write the PNG")
    a = ap.parse_args()

    d = load(a.capture_dir, a.spine)
    S = series(d)
    out = a.out or os.path.join(a.capture_dir, "analysis", f"{d['run_id']}-chart")
    plot(d, S, out, title=a.title, svg=not a.no_svg)
    print(f"[{d['mode']}] {len(d['batches'])} batches, {d['n_moves']} moves · "
          f"RT-2 adv {S['adv_n'][-1]} / withd {S['wd_n'][-1]} · queue peak {S['queue_peak']} · "
          f"DAD flags {S['total_flags']} ({S['n_events']} zebra detections)")
    print("wrote", out + ".png" + ("" if a.no_svg else f" and {out}.svg"))


if __name__ == "__main__":
    main()
