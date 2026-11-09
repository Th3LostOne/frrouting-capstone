#!/usr/bin/env python3
"""
extract_metrics.py - save the capstone mobility metrics from leaf captures.

    python3 extract_metrics.py captures/<stamp>-leaves                 # one run
    python3 extract_metrics.py captures/*-leaves --out metrics.csv     # many runs, one row each
    python3 extract_metrics.py ... --detailed                          # every intermediate timestamp

Default CSV columns: run, movement_timestamp, direction, evpn_update_ms,
l2_convergence_ms, l3_convergence_ms, reachability_recovery_ms, packet_loss, notes.
The list below documents the --detailed columns the defaults are taken from.

Input: folders written by capture_leaf_traffic.py (leaf1.pcap, leaf2.pcap,
events.json; the *-fdb/neigh.jsonl and probe-*.log files are used when present).
Needs tshark, plus analyze_leaf_traffic.py and evpn_move_analyzer.py in the same folder.

Every time is in milliseconds after T0 = move_call_start (events.json), on the
same clock as the pcaps.

Metrics (column names in brackets)
1. Movement timestamp
   [move_call_start_utc]   when the test moved the cable (T0)
   [detach_ms]             last frame from the robot on the old leaf's access port   (pcap)
   [detach_kernel_ms]      old leaf kernel deletes the robot's MAC (port left bridge) (fdb.jsonl)
   [attach_ms]             first frame from the robot entering the new leaf - on its access
                           port, or flooded from the new leaf into the tunnel        (pcap)
2. EVPN update / convergence time
   [withdraw_tx_ms]        old leaf sends the BGP withdraw for the robot            (pcap, old leaf)
   [mac_adv_tx_ms]         new leaf sends the MAC route (MAC Mobility seq = [mac_mobility_seq])
   [mac_rx_remote_ms]      old leaf receives that route - first copy, either spine   (pcap, old leaf)
   [mac_rx_via_spine1_ms] / [mac_rx_via_spine2_ms] and [spine1_relay_ms] / [spine2_relay_ms]
   [l2_installed_ms]       old leaf kernel FDB points the robot at the new VTEP     (fdb.jsonl)
   [robot_arp_ms]          robot's first ARP to the gateway on the new leaf; this is what
                           lets the leaf learn the robot's IP                       (pcap)
   [macip_adv_tx_ms] [macip_rx_remote_ms]  same for the MAC+IP route
   [l3_installed_ms]       old leaf kernel installs the robot's ARP entry from EVPN (neigh.jsonl)
   [evpn_l2_convergence_ms] = l2_installed_ms, or mac_rx_remote_ms if no kernel log
   [evpn_l3_convergence_ms] = l3_installed_ms, or macip_rx_remote_ms if no kernel log
   [l3_after_arp_ms]       evpn_l3_convergence_ms - robot_arp_ms (removes test-harness delay)
   [dataplane_learn_ms]    old leaf bridge learned the new location from traffic (no extern_learn)
3. Reachability recovery time, per probe host (pcap; probe-<host>.log if present)
   [<host>_recovery_ms]    first ping reply delivered after the outage
   [<host>_outage_ms]      gap between the last reply before and first reply after, minus one interval
   [reachability_recovery_ms] worst (largest) recovery over all probes
4. Packet loss, per probe host
   [<host>_lost]           pings sent during the outage that never got a reply
   [packet_loss_total]     sum over probes;  [probe_interval_ms] for converting to time

Also: [bgp_updates_*] / [bgp_bytes_*] per leaf during the move, and [notes] for
anything that could not be measured.
"""
import argparse, csv, json, os, re, statistics, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from analyze_leaf_traffic import read_pcap, ifindex_map, bgp_type2, read_jsonl  # noqa: E402

WINDOW_AFTER_S = 5.0     # look for the move's effects up to 5 s after T0


def first(items, key=lambda x: True):
    for it in items:
        if key(it):
            return it
    return None


def ms(t, t0):
    return None if t is None else round((t - t0) * 1000, 1)


def probe_from_log(path):
    """ping -D log -> {seq: reply_time}; requests are implied by the seq numbers."""
    rep = {}
    for line in open(path):
        m = re.match(r"\[(\d+\.\d+)\] \d+ bytes from .*icmp_seq=(\d+)", line)
        if m:
            rep.setdefault(int(m.group(2)), float(m.group(1)))
    return rep


def probes_from_pcap(pkts_by_leaf, robot_ip):
    """{prober_ip: (requests {seq: t}, replies {seq: t})} from the probers' access ports."""
    out = {}
    for pkts in pkts_by_leaf.values():
        for p in pkts:
            if p["role"] != "access" or not p["what"].startswith("ICMP "):
                continue
            m = re.match(r"(\S+) -> (\S+) seq (\d+)", p["detail"])
            if not m:
                continue
            src, dst, seq = m.group(1), m.group(2), int(m.group(3))
            if p["what"] == "ICMP echo" and dst == robot_ip and p["dir"].startswith("in"):
                out.setdefault(src, ({}, {}))[0].setdefault(seq, p["t_abs"])
            elif p["what"] == "ICMP reply" and src == robot_ip and p["dir"] == "out":
                out.setdefault(dst, ({}, {}))[1].setdefault(seq, p["t_abs"])
    return out


def outage(requests, replies, t0):
    """Find the reply gap around the move. Returns recovery, outage, lost, interval."""
    rt = sorted(replies.items(), key=lambda kv: kv[1])
    if len(rt) < 3:
        return None
    iv = statistics.median(b[1] - a[1] for a, b in zip(rt, rt[1:]))
    cand = [(b[1] - a[1], a, b) for a, b in zip(rt, rt[1:])
            if b[1] > t0 and a[1] < t0 + WINDOW_AFTER_S]
    if not cand:
        return None
    gap, a, b = max(cand)
    if gap <= 2 * iv:                       # no visible interruption
        return {"recovery": 0.0, "outage": 0.0, "lost": 0, "interval": iv * 1000}
    seqs = range(a[0] + 1, b[0])
    if requests:
        lost = sum(1 for s in seqs if s in requests and s not in replies)
    else:
        lost = sum(1 for s in seqs if s not in replies)
    return {"recovery": (b[1] - t0) * 1000, "outage": (gap - iv) * 1000, "lost": lost,
            "interval": iv * 1000}


def extract(folder, mac, ip, gateway="45.0.0.1"):
    row, notes = {"capture_folder": os.path.basename(os.path.normpath(folder))}, []
    events = json.load(open(os.path.join(folder, "events.json")))
    ev = {e["event"]: e for e in events}
    if "move_call_start" not in ev:
        raise SystemExit(f"{folder}: events.json has no move_call_start")
    t0 = ev["move_call_start"]["unix_time"]
    t_end = t0 + WINDOW_AFTER_S
    row["move_call_start_utc"] = datetime.fromtimestamp(t0, timezone.utc).isoformat(timespec="milliseconds")
    row["move_call_end_ms"] = ms(ev.get("move_call_end", {}).get("unix_time"), t0)

    leaves = sorted(f[:-5] for f in os.listdir(folder) if re.match(r"leaf\d+\.pcap$", f))
    pkts, bgp = {}, {}
    for leaf in leaves:
        pkts[leaf] = read_pcap(os.path.join(folder, f"{leaf}.pcap"), ifindex_map(folder, leaf))
        bgp[leaf] = bgp_type2(pkts[leaf], mac) or []

    # ---- who moved where: BGP first, access-port frames as fallback -------------------
    new_leaf = old_leaf = new_vtep = old_vtep = None
    origin_adverts = sorted(
        (r["t_abs"], leaf, r["next_hop"]) for leaf in leaves for r in bgp[leaf]
        if r["dir"] == "tx" and r["action"] == "advertise" and t0 <= r["t_abs"] <= t_end
        and len(r["as_path"].split()) == 1)          # own route: AS path is just the leaf
    if origin_adverts:
        _, new_leaf, new_vtep = origin_adverts[0]
    wds = sorted((r["t_abs"], leaf, r["rd"]) for leaf in leaves for r in bgp[leaf]
                 if r["dir"] == "tx" and r["action"] == "withdraw" and t0 <= r["t_abs"] <= t_end)
    if wds:
        _, old_leaf, rd = wds[0]
        old_vtep = rd.split(":")[0]
    robot_frames = {leaf: [p for p in pkts[leaf] if p["role"] == "access" and p["src_mac"] == mac
                           and p["dir"].startswith("in")] for leaf in leaves}
    if old_leaf is None:
        old_leaf = first(leaves, lambda l: any(p["t_abs"] < t0 for p in robot_frames[l]))
    if new_leaf is None:
        new_leaf = first(leaves, lambda l: l != old_leaf and any(p["t_abs"] >= t0 for p in robot_frames[l]))
    row.update(old_leaf=old_leaf, new_leaf=new_leaf, old_vtep=old_vtep, new_vtep=new_vtep,
               direction=f"{old_leaf}->{new_leaf}")
    if not (old_leaf and new_leaf):
        notes.append("could not tell which leaf the robot left/joined")

    # ---- 1. movement ------------------------------------------------------------------
    if old_leaf:
        last = [p for p in robot_frames[old_leaf] if p["t_abs"] <= t_end]
        last = [p for p in last if p["t_abs"] < (first(robot_frames.get(new_leaf, []),
                lambda p: p["t_abs"] >= t0) or {"t_abs": t_end})["t_abs"]]
        row["detach_ms"] = ms(last[-1]["t_abs"], t0) if last else None
        fdb_del = first(read_jsonl(os.path.join(folder, f"{old_leaf}-fdb.jsonl")),
                        lambda r: r["unix_time"] >= t0 and r["line"].startswith(f"Deleted {mac} "))
        row["detach_kernel_ms"] = ms(fdb_del and fdb_del["unix_time"], t0)
    if new_leaf:
        # Robot frames entering the new leaf: on the access port, or (if the access-port copy
        # was not captured) the same frame flooded from the new leaf into the tunnel.
        entered = [p for p in robot_frames[new_leaf] if p["t_abs"] >= t0] + \
                  [p for p in pkts[new_leaf] if p["t_abs"] >= t0 and p["vni"] and p["role"] == "uplink"
                   and p["dir"] == "out" and p["src_mac"] == mac]
        f = min(entered, key=lambda p: p["t_abs"]) if entered else None
        row["attach_ms"] = ms(f and f["t_abs"], t0)
        arp = first(robot_frames[new_leaf], lambda p: p["t_abs"] >= t0 and p["what"] == "ARP request"
                    and p["detail"] == f"{ip} -> {gateway}")
        row["robot_arp_ms"] = ms(arp and arp["t_abs"], t0)

    # ---- 2. EVPN ----------------------------------------------------------------------
    if old_leaf and new_leaf:
        o, n = bgp[old_leaf], bgp[new_leaf]
        in_win = lambda r: t0 <= r["t_abs"] <= t_end
        wd = first(o, lambda r: in_win(r) and r["dir"] == "tx" and r["action"] == "withdraw")
        mac_tx = first(n, lambda r: in_win(r) and r["dir"] == "tx" and r["action"] == "advertise"
                       and r["next_hop"] == new_vtep and len(r["as_path"].split()) == 1)
        macip_tx = first(n, lambda r: in_win(r) and r["dir"] == "tx" and r["action"] == "advertise"
                         and r["nlri"] == "MAC+IP" and len(r["as_path"].split()) == 1)
        rx = [r for r in o if in_win(r) and r["dir"] == "rx" and r["action"] == "advertise"
              and r["next_hop"] == new_vtep]
        mac_rx = first(rx)
        macip_rx = first(rx, lambda r: r["nlri"] == "MAC+IP")
        row.update(withdraw_tx_ms=ms(wd and wd["t_abs"], t0),
                   mac_adv_tx_ms=ms(mac_tx and mac_tx["t_abs"], t0),
                   mac_mobility_seq=mac_tx["seq"] if mac_tx else None,
                   mac_rx_remote_ms=ms(mac_rx and mac_rx["t_abs"], t0),
                   macip_adv_tx_ms=ms(macip_tx and macip_tx["t_abs"], t0),
                   macip_rx_remote_ms=ms(macip_rx and macip_rx["t_abs"], t0))
        for sp in ("spine1", "spine2"):
            r = first(rx, lambda r: r["uplink"] == f"eth-{sp}" and (mac_tx is None or r["nlri"] == mac_tx["nlri"]))
            row[f"mac_rx_via_{sp}_ms"] = ms(r and r["t_abs"], t0)
            row[f"{sp}_relay_ms"] = (round((r["t_abs"] - mac_tx["t_abs"]) * 1000, 1)
                                     if r and mac_tx else None)
        if not mac_tx:
            notes.append("no BGP MAC advert from the new leaf in the pcap")

        # kernel programming on the old leaf (= the remote leaf after the move)
        fdb = [r for r in read_jsonl(os.path.join(folder, f"{old_leaf}-fdb.jsonl"))
               if t0 <= r["unix_time"] <= t_end and mac in r["line"] and not r["line"].startswith("Deleted")]
        neigh = [r for r in read_jsonl(os.path.join(folder, f"{old_leaf}-neigh.jsonl"))
                 if t0 <= r["unix_time"] <= t_end and r["line"].startswith(ip + " ")
                 and "extern_learn" in r["line"]]
        l2 = first(fdb, lambda r: new_vtep and f"dst {new_vtep}" in r["line"] and "extern_learn" in r["line"])
        dp = first(fdb, lambda r: "extern_learn" not in r["line"] and "master" in r["line"])
        row["l2_installed_ms"] = ms(l2 and l2["unix_time"], t0)
        row["l3_installed_ms"] = ms(neigh[0]["unix_time"] if neigh else None, t0)
        row["dataplane_learn_ms"] = ms(dp and dp["unix_time"], t0)
        if not fdb and not neigh:
            notes.append("no kernel fdb/neigh logs - convergence taken from BGP receive time")
    row["evpn_l2_convergence_ms"] = row.get("l2_installed_ms") or row.get("mac_rx_remote_ms")
    row["evpn_l3_convergence_ms"] = row.get("l3_installed_ms") or row.get("macip_rx_remote_ms")
    if row["evpn_l3_convergence_ms"] is not None and row.get("robot_arp_ms") is not None:
        row["l3_after_arp_ms"] = round(row["evpn_l3_convergence_ms"] - row["robot_arp_ms"], 1)

    # ---- 3 + 4. reachability and loss ---------------------------------------------------
    names = {}
    for host in (ev.get("probes_started", {}).get("probes") or {}):
        names[host] = host
    from_pcap = probes_from_pcap(pkts, ip)
    results, worst, lost_total, ivs = {}, None, 0, []
    host_by_ip = {}
    for prober_ip in from_pcap:
        m = re.match(r"\d+\.\d+\.\d+\.(\d+)$", prober_ip)
        host_by_ip[prober_ip] = f"host{m.group(1)}" if m else prober_ip
    sources = {}
    for prober_ip, (req, rep) in from_pcap.items():
        sources[host_by_ip[prober_ip]] = ("pcap", req, rep)
    for f in os.listdir(folder):          # probe logs win when present (they also cover L3 probes)
        m = re.match(r"probe-(.+)\.log$", f)
        if m:
            sources[m.group(1)] = ("log", {}, probe_from_log(os.path.join(folder, f)))
    for host, (src, req, rep) in sorted(sources.items()):
        r = outage(req, rep, t0)
        if r is None:
            notes.append(f"{host}: not enough ping replies to measure")
            continue
        row[f"{host}_recovery_ms"] = round(r["recovery"], 1)
        row[f"{host}_outage_ms"] = round(r["outage"], 1)
        row[f"{host}_lost"] = r["lost"]
        row[f"{host}_source"] = src
        worst = r["recovery"] if worst is None else max(worst, r["recovery"])
        lost_total += r["lost"]; ivs.append(r["interval"])
    if not sources:
        notes.append("no ping probes found (run with CAPTURE_PROBES=1 to measure reachability/loss)")
    row["reachability_recovery_ms"] = round(worst, 1) if worst is not None else None
    row["packet_loss_total"] = lost_total if sources else None
    row["probe_interval_ms"] = round(statistics.median(ivs), 1) if ivs else None

    # ---- BGP volume during the move ---------------------------------------------------
    for leaf in leaves:
        for d, name in (("out", "tx"), ("in", "rx")):
            u = [p for p in pkts[leaf] if p["what"].startswith("BGP UPDATE") and p["dir"] == d
                 and t0 <= p["t_abs"] <= t_end]
            row[f"bgp_updates_{name}_{leaf}"] = len(u)
            row[f"bgp_bytes_{name}_{leaf}"] = sum(p["len"] for p in u)
    row["notes"] = "; ".join(notes)
    return row


# Default output: one column per capstone metric. --detailed writes everything above.
SIMPLE_COLS = [                                     # (csv column, internal key)
    ("run", "capture_folder"),
    ("movement_timestamp", "move_call_start_utc"),  # 1. movement timestamp (T0, UTC)
    ("direction", "direction"),
    ("evpn_update_ms", "mac_adv_tx_ms"),            # 2. new leaf sends the EVPN update
    ("l2_convergence_ms", "evpn_l2_convergence_ms"),#    old leaf now forwards to the new leaf
    ("l3_convergence_ms", "evpn_l3_convergence_ms"),#    old leaf has the robot's IP route
    ("reachability_recovery_ms", "reachability_recovery_ms"),  # 3. first ping reply after the move
    ("packet_loss", "packet_loss_total"),           # 4. pings lost during the move
    ("notes", "notes"),                             # empty unless something could not be measured
]

FIRST_COLS = ["capture_folder", "move_call_start_utc", "direction", "old_leaf", "new_leaf",
              "old_vtep", "new_vtep", "move_call_end_ms", "detach_ms", "detach_kernel_ms", "attach_ms",
              "withdraw_tx_ms", "mac_adv_tx_ms", "mac_mobility_seq", "mac_rx_remote_ms",
              "mac_rx_via_spine1_ms", "mac_rx_via_spine2_ms", "spine1_relay_ms", "spine2_relay_ms",
              "l2_installed_ms", "dataplane_learn_ms", "evpn_l2_convergence_ms",
              "robot_arp_ms", "macip_adv_tx_ms", "macip_rx_remote_ms", "l3_installed_ms",
              "evpn_l3_convergence_ms", "l3_after_arp_ms",
              "reachability_recovery_ms", "packet_loss_total", "probe_interval_ms"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folders", nargs="+", help="capture folders from capture_leaf_traffic.py")
    ap.add_argument("--out", default="metrics.csv")
    ap.add_argument("--mac", default="00:00:00:00:00:11")
    ap.add_argument("--ip", default="45.0.0.11")
    ap.add_argument("--gateway", default="45.0.0.1", help="anycast gateway the robot ARPs for")
    ap.add_argument("--detailed", action="store_true",
                    help="write every intermediate timestamp (and a .json copy), not just the metrics")
    a = ap.parse_args()
    rows = []
    for folder in a.folders:
        if not os.path.isdir(folder):          # e.g. a metrics.csv caught by a glob
            continue
        try:
            rows.append(extract(folder, a.mac, a.ip, a.gateway))
        except Exception as exc:  # keep going: one broken run must not stop a 100-run batch
            rows.append({"capture_folder": os.path.basename(os.path.normpath(folder)),
                         "notes": f"FAILED: {exc}"})
        r = rows[-1]
        print(f"{r['capture_folder']}: {r.get('direction', '?')}  "
              f"L2 {r.get('evpn_l2_convergence_ms')} ms  L3 {r.get('evpn_l3_convergence_ms')} ms  "
              f"reach {r.get('reachability_recovery_ms')} ms  lost {r.get('packet_loss_total')}"
              + (f"  [{r['notes']}]" if r.get("notes") else ""))
    if a.detailed:
        extra = sorted({k for r in rows for k in r} - set(FIRST_COLS) - {"notes"})
        cols = FIRST_COLS + extra + ["notes"]
        with open(a.out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols); w.writeheader(); w.writerows(rows)
        with open(os.path.splitext(a.out)[0] + ".json", "w") as fh:
            json.dump(rows, fh, indent=2)
        print(f"\nwrote {len(rows)} run(s) to {a.out} (+ .json), detailed")
    else:
        with open(a.out, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow([c for c, _ in SIMPLE_COLS])
            for r in rows:
                w.writerow(["" if r.get(k) is None else r.get(k) for _, k in SIMPLE_COLS])
        print(f"\nwrote {len(rows)} run(s) to {a.out}")


if __name__ == "__main__":
    main()