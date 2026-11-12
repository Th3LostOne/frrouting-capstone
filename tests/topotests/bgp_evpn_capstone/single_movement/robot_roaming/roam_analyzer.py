#!/usr/bin/env python3
"""
roam_analyzer.py - did the controller's router (leaf5) keep track of the robot?

    python3 roam_analyzer.py captures/<stamp> [--plot] [--budget-ms 1000]

Reads a folder written by test_robot_roaming.py. Needs tshark; reuses read_pcap /
bgp_type2 from single_movement/analyze_leaf_traffic.py (and evpn_move_analyzer.py).
Optional: matplotlib for --plot.

Truth:   events.json - where the robot is plugged in at every instant
         (between "detached" and "attached" it is in transit).
Views:   views.jsonl - where every node thinks it is, polled every 50 ms:
         leaf1-4 EVPN MAC table, spine1/2 RT-2 routes held, leaf5 BGP best path,
         leaf5 installed /32 (the controller's data).
Packets: <node>.pcap - the robot's RT-2 MAC+IP route seen at every capture point.

Out of sync = leaf5's installed /32 points anywhere but the leaf the robot is on
(stale: an old leaf, missing: no route, mixed: old and new). Time in transit is
reported separately - nobody can be right while the cable is out.

For every hop the update is followed through the fabric from the pcaps and polls:
    robot attached -> robot ARP -> new leaf learns MAC -> new leaf sends RT-2
    -> spine1/spine2 receive -> spines send to leaf5 -> leaf5 receives
    -> leaf5 BGP best path -> leaf5 /32 installed  (= synced)
so every out-of-sync millisecond is charged to the stage the update was stuck in.

Writes <folder>/analysis/:
    roam_report.html   open in a browser (no network needed): topology with a time
                       slider and the RT-2 moving through it, per-hop flow chart of the
                       update path, swim-lane timeline, out-of-sync windows, metrics
    roam_summary.json  everything, machine-readable
    hops.csv           one row per move: every stage time, sync time, outage
    desync.csv         one row per out-of-sync window with its cause
    roam_timeline.png  static swim lanes (with --plot)
Times are ms after T0 = the first move.
"""
import argparse
import bisect
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "single_movement"))
from analyze_leaf_traffic import read_pcap, bgp_type2, read_jsonl, read_probe  # noqa: E402

GRID_MS = 5.0
STAGES = [  # (key, label)  - the order an update moves through the fabric
    ("attached", "robot plugged into new leaf"),
    ("robot_arp", "robot's ARP reaches new leaf"),
    ("learned", "new leaf learns robot MAC"),
    ("dst_tx", "new leaf sends RT-2 MAC+IP"),
    ("spine_rx", "first spine receives it"),
    ("spine_tx_leaf5", "spine sends it to leaf5"),
    ("leaf5_rx", "leaf5 receives it"),
    ("leaf5_best", "leaf5 BGP picks new path"),
    ("leaf5_fib", "leaf5 installs /32 via new leaf"),
]
STUCK_TEXT = {
    "attached": "robot not yet plugged in",
    "robot_arp": "waiting for the robot's first frame on the new leaf",
    "learned": "new leaf has not learned the robot yet",
    "dst_tx": "new leaf learned the robot but has not advertised it",
    "spine_rx": "RT-2 on its way to the spines",
    "spine_tx_leaf5": "spines have the route but have not sent it to leaf5",
    "leaf5_rx": "RT-2 on its way from the spines to leaf5",
    "leaf5_best": "leaf5 has the new route but BGP still prefers the old path",
    "leaf5_fib": "leaf5 BGP chose the new path, zebra has not installed it",
}


class Series:
    def __init__(self, initial=None):
        self.t, self.v, self.initial = [], [], initial

    def add(self, t, v):
        if self.v and self.v[-1] == v:
            return
        self.t.append(t)
        self.v.append(v)

    def at(self, t):
        i = bisect.bisect_right(self.t, t) - 1
        return self.v[i] if i >= 0 else self.initial

    def first(self, t_from, t_to, pred):
        "First time in [t_from, t_to) the value satisfies pred (checking the value at t_from too)."
        if pred(self.at(t_from)):
            return t_from
        i = bisect.bisect_right(self.t, t_from)
        while i < len(self.t) and self.t[i] < t_to:
            if pred(self.v[i]):
                return self.t[i]
            i += 1
        return None


def ifindex_map(folder, node):
    names = defaultdict(set)
    for f in sorted(os.listdir(folder)):
        if f.startswith(node + "-links-") and f.endswith(".txt"):
            for line in open(os.path.join(folder, f)):
                m = re.match(r"\s*(\d+):\s+([^:@\s]+)", line)
                if m:
                    names[m.group(1)].add(m.group(2))
    return {k: "/".join(sorted(v)) for k, v in names.items()}


def reply_gaps(replies):
    "Outages in [(t, seq)] ping replies: missing seq numbers or > 3x interval silence."
    replies = sorted(set(replies))
    if len(replies) < 3:
        return [], None
    iv = sorted(b[0] - a[0] for a, b in zip(replies, replies[1:]))
    med = iv[len(iv) // 2]
    gaps = []
    for (t1, s1), (t2, s2) in zip(replies, replies[1:]):
        if (s2 - s1 > 1 and t2 - t1 > 1.5 * med) or t2 - t1 > 3 * med:
            gaps.append({"a": t1 + med, "b": t2, "ms": round(max(t2 - t1 - med, 0) * 1000, 1),
                         "lost": max(s2 - s1 - 1, 0)})
    return gaps, med


def intervals(flags, grid):
    out, start = [], None
    for t, f in zip(grid, flags):
        if f and start is None:
            start = t
        elif not f and start is not None:
            out.append((start, t))
            start = None
    if start is not None:
        out.append((start, grid[-1]))
    return out


def status_of(owners, actual):
    if actual is None:
        return "transit"
    if owners == (actual,):
        return "synced"
    if not owners:
        return "missing"
    return "mixed" if actual in owners else "stale"


# ================================================================ analysis ===
def analyse(folder, budget_ms):
    cfg = json.load(open(os.path.join(folder, "roam.json")))
    events = sorted(json.load(open(os.path.join(folder, "events.json"))), key=lambda e: e["unix_time"])
    robot, ctl = cfg["robot"], cfg["controller"]
    vteps = cfg["vteps"]
    lo = {leaf: v for v, leaf in vteps.items()}
    leaf5 = ctl["leaf"]
    spines = cfg["spines"]
    rleaves = cfg["robot_leaves"]
    nodes = spines + rleaves + [leaf5]
    vt = lambda ip: vteps.get(ip, ip)  # noqa: E731

    moves = [e for e in events if e["event"] == "move_start"]
    if not moves:
        sys.exit("{}: no moves in events.json".format(folder))
    t0 = moves[0]["unix_time"]
    rel = lambda t: None if t is None else round((t - t0) * 1000.0, 1)  # noqa: E731

    # ---- truth ----------------------------------------------------------------
    truth = Series(initial=robot["home"])
    for e in events:
        if e["event"] == "detached":
            truth.add(e["unix_time"], None)
        elif e["event"] == "attached":
            truth.add(e["unix_time"], e["leaf"])

    # ---- views ----------------------------------------------------------------
    home = (robot["home"],)
    views = {}
    for n in rleaves:
        views[(n, "mac")] = Series(initial={"owners": home, "dup": False, "seq": None})
    for n in spines:
        views[(n, "bgp")] = Series(initial={"owners": home, "best": home})
    views[(leaf5, "bgp")] = Series(initial={"owners": home, "best": home})
    views[(leaf5, "route")] = Series(initial={"owners": home})
    for r in sorted(read_jsonl(os.path.join(folder, "views.jsonl")), key=lambda r: r["unix_time"]):
        st, key = r["state"], (r["node"], r["kind"])
        if "error" in st or key not in views:
            continue
        if r["kind"] == "mac":
            kind = st.get("type")
            owners = (r["node"],) if kind == "local" else ((vt(st.get("remoteVtep", "")),) if kind == "remote" else ())
            seq = max(int(st.get("localSequence") or 0), int(st.get("remoteSequence") or 0)) if kind != "absent" else None
            v = {"owners": owners, "dup": bool(st.get("isDuplicate")), "seq": seq,
                 "dad_count": st.get("detectionCount")}
        elif r["kind"] == "bgp":
            v = {"owners": tuple(sorted(vt(x) for x in st.get("vteps", []))),
                 "best": tuple(sorted(vt(x) for x in st.get("best", [])))}
        else:
            v = {"owners": tuple(sorted(vt(x) for x in st.get("vteps", []))), "protocol": st.get("protocol")}
        views[key].add(r["unix_time"], v)
    fib = views[(leaf5, "route")]
    best5 = views[(leaf5, "bgp")]

    # ---- packets ----------------------------------------------------------------
    rt2 = []          # every robot RT-2 observation at every capture point
    arps = defaultdict(list)
    for n in nodes:
        path = os.path.join(folder, "{}.pcap".format(n))
        if not os.path.exists(path):
            continue
        pkts = read_pcap(path, ifindex_map(folder, n))
        for r in bgp_type2(pkts, robot["mac"]) or []:
            r["node"] = n
            r["peer"] = (re.search(r"eth-((?:leaf|spine)\d+)", r["uplink"]) or [None, None])[1]
            rt2.append(r)
        if n in rleaves:
            for p in pkts:
                if p["what"] == "ARP request" and p["role"] == "access" and p["src_mac"] == robot["mac"] \
                        and p["dir"].startswith("in"):
                    arps[n].append(p["t_abs"])
    rt2.sort(key=lambda r: r["t_abs"])
    # a leaf sends the same UPDATE to both spines: keep one per (node, dir, peer, action, nh, rd) per 50 ms
    dedup, last = [], {}
    for r in rt2:
        k = (r["node"], r["dir"], r["peer"], r["action"], r["nlri"], r["next_hop"], r["rd"], r["seq"])
        if k in last and r["t_abs"] - last[k] < 0.05:
            continue
        last[k] = r["t_abs"]
        dedup.append(r)
    rt2 = dedup

    # ---- probes -----------------------------------------------------------------
    probes = {}
    for name in ("controller", "robot"):
        f = os.path.join(folder, "probe-{}.log".format(name))
        if os.path.exists(f):
            replies = read_probe(f)
            gaps, med = reply_gaps(replies)
            seqs = sorted({s for _, s in replies})
            probes[name] = {"gaps": [g for g in gaps if g["b"] > t0], "interval": med,
                            "lost": (seqs[-1] - seqs[0] + 1 - len(seqs)) if seqs else 0}

    # ---- hops: follow the update -----------------------------------------------
    t_end = max([events[-1]["unix_time"]] + [s.t[-1] for s in views.values() if s.t])
    hops = []
    for i, m in enumerate(moves):
        hs = m["unix_time"]
        he = moves[i + 1]["unix_time"] if i + 1 < len(moves) else t_end
        src, dst, h = m["src"], m["dst"], m["hop"]
        ev = {e["event"]: e["unix_time"] for e in events if e.get("hop") == h}
        att = ev.get("attached", hs)
        new_ip, old_ip = lo.get(dst), lo.get(src)
        T = {"move_start": hs, "detached": ev.get("detached"), "attached": att}
        arp = [t for t in arps.get(dst, []) if att <= t < he]
        T["robot_arp"] = arp[0] if arp else ev.get("learn_start")
        T["learned"] = views[(dst, "mac")].first(att, he, lambda v: v["owners"] == (dst,)) if (dst, "mac") in views else None

        def pk(pred):
            for r in rt2:
                if att - 0.05 <= r["t_abs"] < he and pred(r):
                    return r
            return None

        adv = lambda r: r["action"] == "advertise" and r["nlri"] == "MAC+IP" and r["next_hop"] == new_ip  # noqa
        r_tx = pk(lambda r: adv(r) and r["node"] == dst and r["dir"] == "tx")
        r_srx = pk(lambda r: adv(r) and r["node"] in spines and r["dir"] == "rx")
        r_stx = pk(lambda r: adv(r) and r["node"] in spines and r["dir"] == "tx" and r["peer"] == leaf5)
        r_5rx = pk(lambda r: adv(r) and r["node"] == leaf5 and r["dir"] == "rx")
        T["dst_tx"] = r_tx and r_tx["t_abs"]
        T["spine_rx"] = r_srx and r_srx["t_abs"]
        T["spine_tx_leaf5"] = r_stx and r_stx["t_abs"]
        T["leaf5_rx"] = r_5rx and r_5rx["t_abs"]
        T["leaf5_best"] = best5.first(att, he, lambda v: v["best"] == (dst,))
        T["leaf5_fib"] = fib.first(att, he, lambda v: v["owners"] == (dst,))
        per_spine = {}
        for s in spines:
            a = pk(lambda r, s=s: adv(r) and r["node"] == s and r["dir"] == "rx")
            b = pk(lambda r, s=s: adv(r) and r["node"] == s and r["dir"] == "tx" and r["peer"] == leaf5)
            per_spine[s] = {"rx_ms": rel(a and a["t_abs"]), "tx_leaf5_ms": rel(b and b["t_abs"])}
        wd = lambda r: r["action"] == "withdraw" and r["rd"].split(":")[0] == old_ip  # noqa: E731
        w_tx = next((r for r in rt2 if hs - 0.05 <= r["t_abs"] < he and wd(r) and r["node"] == src and r["dir"] == "tx"), None)
        w_5rx = next((r for r in rt2 if hs - 0.05 <= r["t_abs"] < he and wd(r) and r["node"] == leaf5 and r["dir"] == "rx"), None)
        # stale: leaf5 still receiving advertisements for an old VTEP after the new one arrived
        late_old = [r for r in rt2 if r["node"] == leaf5 and r["dir"] == "rx" and r["action"] == "advertise"
                    and r["nlri"] == "MAC+IP" and r["next_hop"] not in ("", new_ip)
                    and T["leaf5_rx"] and T["leaf5_rx"] < r["t_abs"] < he]

        # synced for good = last unsynced moment in [attached, end of hop)
        last_bad, t = None, att
        while t < he:
            if status_of(fib.at(t)["owners"], truth.at(t)) != "synced":
                last_bad = t
            t += GRID_MS / 1000
        never = last_bad is not None and last_bad >= he - 2 * GRID_MS / 1000
        sync_t = None if never else (att if last_bad is None else last_bad + GRID_MS / 1000)
        reached = [k for k, _ in STAGES if T.get(k) is not None]
        stuck = None
        if never:
            stuck = next((k for k, _ in STAGES if T.get(k) is None), "leaf5_fib")
        gaps = [(n, g) for n, p in probes.items() for g in p["gaps"] if hs <= max(g["a"], t0) < he]
        dad = [n for n in rleaves if views[(n, "mac")].first(hs, he, lambda v: v["dup"]) is not None]
        steps = []
        prev_t = att
        for k, label in STAGES[1:]:
            tk = T.get(k)
            steps.append({"stage": k, "label": label, "t_ms": rel(tk),
                          "delta_ms": None if tk is None or prev_t is None else round((tk - prev_t) * 1000, 1)})
            if tk is not None:
                prev_t = tk
        slow = max((s for s in steps if s["delta_ms"] is not None), key=lambda s: s["delta_ms"], default=None)
        hops.append({
            "hop": h, "src": src, "dst": dst, "start_ms": rel(hs), "end_ms": rel(he),
            "detached_ms": rel(T["detached"]), "attached_ms": rel(att),
            "stages": {k: rel(T.get(k)) for k, _ in STAGES},
            "steps": steps, "slowest_step": slow and slow["stage"],
            "per_spine": per_spine,
            "withdraw": {"src_tx_ms": rel(w_tx and w_tx["t_abs"]), "leaf5_rx_ms": rel(w_5rx and w_5rx["t_abs"])},
            "seq": r_tx["seq"] if r_tx else None,
            "sync_ms": None if sync_t is None else round((sync_t - att) * 1000, 1),
            "synced_at_ms": rel(sync_t), "never_synced": never, "stuck_at": stuck,
            "reached": reached,
            "late_old_updates": len(late_old),
            "controller_outage_ms": max([g["ms"] for n, g in gaps if n == "controller"], default=0.0),
            "lost": sum(g["lost"] for _, g in gaps),
            "dad_on": dad,
        })

    # ---- out-of-sync windows ---------------------------------------------------
    t_start = t0 - 1.0
    grid = [t_start + k * GRID_MS / 1000 for k in range(int((t_end - t_start) * 1000 / GRID_MS) + 1)]
    st_fib = [status_of(fib.at(t)["owners"], truth.at(t)) for t in grid]
    st_best = [status_of(best5.at(t)["best"], truth.at(t)) for t in grid]
    desync_flags = [s in ("stale", "missing", "mixed") and t >= t0 for s, t in zip(st_fib, grid)]
    hop_of = lambda t: next((h for h in reversed(hops) if t >= h["start_ms"] / 1000 + t0), hops[0])  # noqa

    def stuck_at(t):
        h = hop_of(t)
        for k, _ in STAGES[1:]:
            v = h["stages"].get(k)
            if v is None or v / 1000 + t0 > t:
                return k
        return "leaf5_fib"

    windows = []
    for a, b in intervals(desync_flags, grid):
        causes = Counter()
        t = a
        while t < b:
            if any(views[(n, "mac")].at(t)["dup"] for n in rleaves):
                causes["MAC flagged duplicate (DAD): the new leaf stops advertising moves"] += GRID_MS
            else:
                causes[STUCK_TEXT[stuck_at(t)]] += GRID_MS
            t += GRID_MS / 1000
        mid = (a + b) / 2
        windows.append({
            "start_ms": rel(a), "end_ms": rel(b), "ms": round((b - a) * 1000, 1),
            "hop": hop_of(a)["hop"], "robot_at": truth.at(mid),
            "leaf5_route": list(fib.at(mid)["owners"]), "leaf5_best": list(best5.at(mid)["best"]),
            "kind": status_of(fib.at(mid)["owners"], truth.at(mid)),
            "open_at_end": b >= grid[-1] - 0.01,
            "causes": [{"why": k, "ms": round(v, 1)} for k, v in causes.most_common()],
        })

    # ---- metrics -----------------------------------------------------------------
    ms_of = lambda flags: round(sum(flags) * GRID_MS, 1)  # noqa: E731
    after = [t >= t0 for t in grid]
    desync_ms = ms_of(desync_flags)
    stale_ms = ms_of([s == "stale" and a for s, a in zip(st_fib, after)])
    missing_ms = ms_of([s == "missing" and a for s, a in zip(st_fib, after)])
    mixed_ms = ms_of([s == "mixed" and a for s, a in zip(st_fib, after)])
    transit_ms = ms_of([s == "transit" and a for s, a in zip(st_fib, after)])
    best_desync_ms = ms_of([s in ("stale", "missing", "mixed") and a for s, a in zip(st_best, after)])
    syncs = [h["sync_ms"] for h in hops if h["sync_ms"] is not None]
    never = [h for h in hops if h["never_synced"]]
    end_ok = any(e["event"] == "leaf5_synced_at_end" for e in events)
    end_bad = next((e for e in events if e["event"] == "leaf5_out_of_sync_at_end"), None)
    dad_first = None
    for n in rleaves:
        s = views[(n, "mac")]
        t = s.first(t0, t_end + 1, lambda v: v["dup"])
        if t is not None and (dad_first is None or t < dad_first[0]):
            dad_first = (t, n)
    stage_delay = defaultdict(list)
    for h in hops:
        for s in h["steps"]:
            if s["delta_ms"] is not None:
                stage_delay[s["stage"]].append(s["delta_ms"])
    long_windows = [w for w in windows if w["ms"] > budget_ms or w["open_at_end"]]
    ctl = probes.get("controller", {"gaps": [], "lost": 0})

    breaks = []
    if never:
        breaks.append("leaf5 never caught up on hop{} {}".format(
            "s" if len(never) > 1 else "", ", ".join("{} ({}->{})".format(h["hop"], h["src"], h["dst"]) for h in never)))
    if end_bad:
        breaks.append("after the walk leaf5 still routes the robot via {}".format(
            ",".join(vt(x) for x in end_bad.get("leaf5_route", {}).get("vteps", [])) or "nothing"))
    if dad_first:
        breaks.append("{} flagged the robot MAC as duplicate at {:+.0f} ms".format(dad_first[1], rel(dad_first[0])))
    if long_windows and not never:
        breaks.append("leaf5 out of sync for {:.0f} ms (> {:.0f} ms budget)".format(
            max(w["ms"] for w in long_windows), budget_ms))
    verdict = "BROKEN" if breaks else ("OUT OF SYNC BRIEFLY" if windows else "IN SYNC")
    first_break = None
    cands = [w["start_ms"] for w in long_windows]
    if dad_first:
        cands.append(rel(dad_first[0]))
    if cands:
        first_break = min(cands)
    headline = ("; ".join(breaks) if breaks else
                "leaf5 caught up after every move (worst {:.0f} ms after the robot was plugged in)".format(max(syncs or [0])))

    metrics = [
        ("Moves", len(hops), ""),
        ("Moves where leaf5 caught up", len(hops) - len(never), "of {}".format(len(hops))),
        ("Worst time for leaf5 to catch up", max(syncs) if syncs else None, "ms after attach"),
        ("Median time for leaf5 to catch up", sorted(syncs)[len(syncs) // 2] if syncs else None, "ms after attach"),
        ("leaf5 /32 out of sync (robot plugged in)", desync_ms, "ms total"),
        ("  of which: points at an old leaf", stale_ms, "ms"),
        ("  of which: no route at all", missing_ms, "ms"),
        ("  of which: old and new together", mixed_ms, "ms"),
        ("leaf5 BGP best path out of sync", best_desync_ms, "ms total"),
        ("Robot in transit (cable out)", transit_ms, "ms total"),
        ("Controller pings lost", ctl["lost"], "pings"),
        ("Longest controller ping outage", max([g["ms"] for g in ctl["gaps"]], default=0.0), "ms"),
        ("Stale RT-2 reaching leaf5 after the new one", sum(h["late_old_updates"] for h in hops), "updates"),
        ("Duplicate address detection", "flagged on {} at {:+.0f} ms".format(dad_first[1], rel(dad_first[0]))
         if dad_first else "not triggered", ""),
        ("leaf5 in sync when the walk ended", "yes" if end_ok else ("no" if end_bad else "unknown"), ""),
    ]
    stage_rows = [{"stage": k, "label": label, "n": len(stage_delay[k]),
                   "avg_ms": round(sum(stage_delay[k]) / len(stage_delay[k]), 1) if stage_delay[k] else None,
                   "max_ms": max(stage_delay[k]) if stage_delay[k] else None}
                  for k, label in STAGES[1:]]

    # ---- payload -----------------------------------------------------------------
    def ser(series, conv):
        out = [{"t": rel(t_start), **conv(series.at(t_start))}]
        out += [{"t": rel(t), **conv(v)} for t, v in zip(series.t, series.v) if t >= t_start]
        return out

    conv = lambda v: {k: (list(x) if isinstance(x, tuple) else x) for k, x in v.items()}  # noqa: E731
    return {
        "folder": os.path.abspath(folder), "robot": robot, "controller": ctl_info(cfg),
        "path": cfg["path"], "dwell_s": cfg.get("dwell_s"), "budget_ms": budget_ms,
        "verdict": verdict, "headline": headline, "break_ms": first_break,
        "range_ms": [rel(t_start), rel(t_end)],
        "spines": spines, "robot_leaves": rleaves, "leaf5": leaf5,
        "truth": ser(truth, lambda v: {"leaf": v}),
        "views": {"{}:{}".format(*k): ser(s, conv) for k, s in views.items()},
        "rt2": [{"t": rel(r["t_abs"]), "node": r["node"], "dir": r["dir"], "peer": r["peer"],
                 "action": r["action"], "nlri": r["nlri"], "nh": vt(r["next_hop"]) if r["next_hop"] else "",
                 "rd": r["rd"], "seq": r["seq"]} for r in rt2 if r["t_abs"] >= t_start],
        "probes": {n: {"lost": p["lost"], "gaps": [{"a": rel(g["a"]), "b": rel(g["b"]), "ms": g["ms"],
                                                    "lost": g["lost"]} for g in p["gaps"]]} for n, p in probes.items()},
        "hops": hops, "windows": windows, "metrics": [{"label": a, "value": b, "unit": c} for a, b, c in metrics],
        "stages": stage_rows, "stage_labels": dict(STAGES),
        "events": [{"t": rel(e["unix_time"]), "event": e["event"], "leaf": e.get("leaf") or e.get("dst"),
                    "hop": e.get("hop")} for e in events if e["unix_time"] >= t_start],
    }


def ctl_info(cfg):
    return cfg["controller"]


# ================================================================== outputs ==
def write_outputs(s, out):
    os.makedirs(out, exist_ok=True)
    json.dump(s, open(os.path.join(out, "roam_summary.json"), "w"), indent=2)
    with open(os.path.join(out, "hops.csv"), "w", newline="") as fh:
        cols = ["hop", "src", "dst", "attached_ms"] + ["{}_ms".format(k) for k, _ in STAGES[1:]] + \
               ["sync_ms", "never_synced", "stuck_at", "slowest_step", "seq", "late_old_updates",
                "controller_outage_ms", "lost", "dad_on"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for h in s["hops"]:
            row = {k: h.get(k) for k in cols}
            row.update({"{}_ms".format(k): h["stages"].get(k) for k, _ in STAGES[1:]})
            row["dad_on"] = " ".join(h["dad_on"])
            w.writerow(row)
    with open(os.path.join(out, "desync.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["start_ms", "end_ms", "ms", "hop", "robot_at", "leaf5_route", "leaf5_best", "kind", "main_cause"])
        for x in s["windows"]:
            w.writerow([x["start_ms"], x["end_ms"], x["ms"], x["hop"], x["robot_at"], " ".join(x["leaf5_route"]),
                        " ".join(x["leaf5_best"]), x["kind"], x["causes"][0]["why"] if x["causes"] else ""])
    tpl = open(os.path.join(HERE, "roam_report_template.html")).read()
    html = tpl.replace("/*__REPORT_DATA__*/null", json.dumps(s).replace("</", "<\\/"))
    open(os.path.join(out, "roam_report.html"), "w").write(html)


COLORS = {"leaf1": "#2a6fdb", "leaf2": "#1a9e5c", "leaf3": "#e08a00", "leaf4": "#7a5cc7", "leaf5": "#5c6b7a"}


def plot(s, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    lo, hi = s["range_ms"]
    lanes = [("truth", "robot is at")] + [("{}:route".format(s["leaf5"]), "leaf5 /32 (controller)"),
                                          ("{}:bgp".format(s["leaf5"]), "leaf5 BGP best")]
    lanes += [("{}:bgp".format(x), x + " RT-2s held") for x in s["spines"]]
    lanes += [("{}:mac".format(x), x + " MAC table") for x in s["robot_leaves"]] + [("ping", "controller ping")]
    fig, ax = plt.subplots(figsize=(14, 0.45 * len(lanes) + 2))
    ys = {k: len(lanes) - 1 - i for i, (k, _) in enumerate(lanes)}

    def segs(series):
        for a, b in zip(series, series[1:] + [{"t": hi}]):
            yield a, a["t"], b["t"]
    for st, a, b in segs(s["truth"]):
        ax.barh(ys["truth"], b - a, left=a, height=0.6, color=COLORS.get(st["leaf"], "#cccccc"))
    for key, _ in lanes[1:-1]:
        field = "best" if key == "{}:bgp".format(s["leaf5"]) else "owners"
        for st, a, b in segs(s["views"][key]):
            owners = st.get(field) or []
            for j, o in enumerate(owners or [None]):
                n = max(len(owners), 1)
                ax.barh(ys[key] - 0.3 + (j + 0.5) * 0.6 / n, b - a, left=a, height=0.6 / n,
                        color=COLORS.get(o, "#dddddd"))
    for w in s["windows"]:
        ax.axvspan(w["start_ms"], w["end_ms"], color="#d1453b", alpha=0.12, lw=0)
    for g in s["probes"].get("controller", {}).get("gaps", []):
        ax.barh(ys["ping"], g["b"] - g["a"], left=g["a"], height=0.6, color="#d1453b")
    for h in s["hops"]:
        ax.axvline(h["attached_ms"], color="#888", ls=":", lw=0.8)
    ax.set_yticks([ys[k] for k, _ in lanes])
    ax.set_yticklabels([l for _, l in lanes], fontsize=8)
    ax.set_xlim(lo, hi)
    ax.set_xlabel("ms after the first move (red bands: leaf5 out of sync with the robot)")
    ax.set_title("{} - {}".format(s["verdict"], s["headline"])[:150], fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--budget-ms", type=float, default=1000.0,
                    help="how long leaf5 may lag behind the robot before it counts as broken (default 1000)")
    ap.add_argument("--plot", action="store_true")
    a = ap.parse_args()
    s = analyse(a.folder, a.budget_ms)
    out = os.path.join(a.folder, "analysis")
    write_outputs(s, out)
    if a.plot:
        try:
            plot(s, os.path.join(out, "roam_timeline.png"))
        except ImportError:
            print("matplotlib missing - no roam_timeline.png")
    print("{}: {}".format(s["verdict"], s["headline"]))
    for m in s["metrics"]:
        print("  {:<48} {} {}".format(m["label"], "-" if m["value"] is None else m["value"], m["unit"]))
    print("\n  hop  move           sync_ms  stuck at / slowest step")
    for h in s["hops"]:
        print("  {:>3}  {:<5}->{:<6}  {:>8}  {}".format(
            h["hop"], h["src"], h["dst"], "never" if h["never_synced"] else h["sync_ms"],
            "STUCK: " + STUCK_TEXT[h["stuck_at"]] if h["stuck_at"] else "slowest: " + str(h["slowest_step"])))
    print("\n  report: {}".format(os.path.join(out, "roam_report.html")))


if __name__ == "__main__":
    main()