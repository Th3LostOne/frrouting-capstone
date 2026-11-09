#!/usr/bin/env python3
"""
analyze_leaf_traffic.py - explain what leaf1 and leaf2 did during a robot move.

Reads a folder written by capture_leaf_traffic.py:
    python3 analyze_leaf_traffic.py captures/<stamp>-leaves [--plot] [--mac 00:00:00:00:00:11]

Needs tshark. Optional: matplotlib (--plot). For BGP EVPN decoding it imports
evpn_move_analyzer.py from the same folder (skipped with a note if missing).

Writes <folder>/analysis/:
    <leaf>_packets.csv   every captured packet: time, interface, direction, what it is
                         (BGP / VXLAN with outer VTEPs + VNI + inner frame / ARP / ICMP / ND)
    timeline.csv         one merged, time-ordered list of everything about the robot:
                         test events, BGP Type-2 routes, kernel FDB/ARP changes,
                         FRR MAC state, first/last tunnel packets, probe outages
    summary.json         the numbers printed to the screen
    leaf_timeline.png    swim-lane chart (with --plot)

How to read a leaf capture ("tshark -i any"): one frame shows up once per
interface it crosses. A ping from host12 to the moved robot on leaf1 is seen
  1. arriving on eth-host12           (access port, bridged frame)
  2. leaving on vni1000               (the VXLAN device, still the plain frame)
  3. leaving on eth-spine1/eth-spine2 (now UDP/4789 with VNI 1000 and outer
                                       10.0.0.1 -> 10.0.0.2 - this is the tunnel)
The analyzer labels each copy by interface role so you can follow it.
"""
import argparse, csv, json, os, re, subprocess, sys
from collections import Counter, defaultdict

PKTTYPE = {"0": "in", "1": "in-bcast", "2": "in-mcast", "3": "in-bridged", "4": "out"}
ICMP6 = {"133": "RS", "134": "RA", "135": "NS", "136": "NA", "143": "MLDv2"}
FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "sll.ifindex", "sll.pkttype",
          "sll.src.eth", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.srcport", "udp.dstport",
          "vxlan.vni", "eth.src", "eth.dst", "arp.opcode", "arp.src.proto_ipv4",
          "arp.dst.proto_ipv4", "icmp.type", "icmp.seq", "icmpv6.type", "tcp.srcport",
          "tcp.dstport", "tcp.seq_raw", "tcp.len", "tcp.payload", "bgp.type"]


# ------------------------------------------------------------------ input ---
def ifindex_map(folder, leaf):
    """ifindex -> interface name from the 'ip -o link' snapshots (start and end)."""
    names = defaultdict(set)
    for phase in ("start", "end"):
        path = os.path.join(folder, f"{leaf}-links-{phase}.txt")
        if not os.path.exists(path):
            continue
        for line in open(path):
            m = re.match(r"\s*(\d+):\s+([^:@\s]+)", line)
            if m:
                names[m.group(1)].add(m.group(2))
    return {k: "/".join(sorted(v)) for k, v in names.items()}


def role(ifname):
    if ifname.startswith("eth-host"): return "access"
    if ifname.startswith("eth-spine"): return "uplink"
    if ifname.startswith("vni"): return "vxlan-dev"
    if ifname.startswith("br"): return "bridge"
    return "other"


def read_pcap(path, ifnames):
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=a", "-E", "aggregator=|"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"tshark failed on {path}: {out.stderr.strip()}")
    pkts = []
    for line in out.stdout.splitlines():
        v = dict(zip(FIELDS, line.split("\t")))
        lst = lambda f: [x for x in v.get(f, "").split("|") if x]
        ip_src, ip_dst = lst("ip.src"), lst("ip.dst")
        ifname = ifnames.get(v["sll.ifindex"], f"if{v['sll.ifindex']}" if v["sll.ifindex"] else "?")
        p = {"frame": int(v["frame.number"]), "t_abs": float(v["frame.time_epoch"]),
             "len": int(v["frame.len"]), "ifname": ifname, "role": role(ifname),
             "dir": PKTTYPE.get(v["sll.pkttype"], v["sll.pkttype"]),
             "src_mac": "", "dst_mac": "", "outer_src": "", "outer_dst": "", "vni": "",
             "what": "", "detail": "", "ip_dst": "", "robot_related": False}
        inner = ""
        if v["vxlan.vni"]:
            p["vni"] = v["vxlan.vni"].split("|")[0]
            p["outer_src"], p["outer_dst"] = ip_src[0], ip_dst[0]
            eth_s, eth_d = lst("eth.src"), lst("eth.dst")
            p["src_mac"], p["dst_mac"] = (eth_s or [""])[-1], (eth_d or [""])[-1]
            inner = "VXLAN "
            ip_src, ip_dst = ip_src[1:], ip_dst[1:]
        else:
            p["src_mac"] = v["sll.src.eth"] or (lst("eth.src") or [""])[-1]
            p["dst_mac"] = (lst("eth.dst") or [""])[-1]
        if v["tcp.srcport"] == "179" or v["tcp.dstport"] == "179":
            types = lst("bgp.type")
            names = {"1": "OPEN", "2": "UPDATE", "3": "NOTIFICATION", "4": "KEEPALIVE"}
            p["what"] = "BGP " + "+".join(names.get(t, t) for t in types) if types else "BGP (TCP ack)"
            p["outer_src"], p["outer_dst"] = (lst("ipv6.src") or ip_src or [""])[0], (lst("ipv6.dst") or ip_dst or [""])[0]
            p["_tcp"] = {"src": p["outer_src"], "dst": p["outer_dst"], "sport": int(v["tcp.srcport"]),
                         "dport": int(v["tcp.dstport"]), "seq": int(v["tcp.seq_raw"] or 0),
                         "tcp_len": int(v["tcp.len"] or 0),
                         "payload": bytes.fromhex(v["tcp.payload"].replace(":", "")) if v["tcp.payload"] else b""}
        elif v["arp.opcode"]:
            op = {"1": "request", "2": "reply"}.get(v["arp.opcode"], v["arp.opcode"])
            p["what"] = inner + "ARP " + op
            p["detail"] = f"{v['arp.src.proto_ipv4']} -> {v['arp.dst.proto_ipv4']}"
            p["ip_dst"] = v["arp.dst.proto_ipv4"]
        elif v["icmp.type"]:
            t = v["icmp.type"].split("|")[-1]
            p["what"] = inner + {"8": "ICMP echo", "0": "ICMP reply"}.get(t, f"ICMP type {t}")
            p["detail"] = f"{(ip_src or [''])[-1]} -> {(ip_dst or [''])[-1]} seq {v['icmp.seq'].split('|')[-1]}"
            p["ip_dst"] = (ip_dst or [""])[-1]
        elif v["icmpv6.type"]:
            t = v["icmpv6.type"].split("|")[-1]
            p["what"] = inner + "ICMPv6 " + ICMP6.get(t, t)
        else:
            p["what"] = inner + "other"
        pkts.append(p)
    return pkts


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path) if l.strip()]


def read_probe(path):
    """ping -D output -> list of (unix_time, seq) replies."""
    replies = []
    if not os.path.exists(path):
        return replies
    for line in open(path):
        m = re.match(r"\[(\d+\.\d+)\] \d+ bytes from .*icmp_seq=(\d+)", line)
        if m:
            replies.append((float(m.group(1)), int(m.group(2))))
    return replies


# --------------------------------------------------------------- analysis ---
def bgp_type2(pkts, mac):
    """Decode BGP EVPN Type-2 routes for the robot using evpn_move_analyzer's parser."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from evpn_move_analyzer import extract_messages, parse_update
    except ImportError:
        return None
    segs = []
    for p in pkts:
        if "_tcp" in p:
            s = dict(p["_tcp"]); s.update(t=p["t_abs"], ifname=p["ifname"], dir=p["dir"]); segs.append(s)
    out = []
    for mm in extract_messages(segs):
        if mm["type"] != "UPDATE":
            continue
        attrs, nlris = parse_update(mm["raw"])
        for r in nlris:
            if r.get("route_type") != 2 or r.get("mac") != mac:
                continue
            s = mm["seg"]
            out.append({"t_abs": s["t"], "dir": "tx" if s["dir"] == "out" else "rx",
                        "uplink": s["ifname"], "action": r["action"],
                        "nlri": "MAC+IP" if r.get("ip") else "MAC", "ip": r.get("ip", ""),
                        "rd": r.get("rd", ""), "next_hop": attrs["next_hop"],
                        "as_path": " ".join(map(str, attrs["as_path"])), "seq": attrs["mac_mob_seq"]})
    return out


def robot_related(p, mac, ip):
    return mac in (p["src_mac"], p["dst_mac"]) or ip in p["detail"]


def outages(replies, gap_factor=3.0):
    """Gaps in ping replies longer than gap_factor x the median interval."""
    if len(replies) < 3:
        return [], None
    iv = sorted(b[0] - a[0] for a, b in zip(replies, replies[1:]))
    med = iv[len(iv) // 2]
    gaps = []
    for (t1, s1), (t2, s2) in zip(replies, replies[1:]):
        if t2 - t1 > gap_factor * med:
            gaps.append({"last_reply_before": t1, "first_reply_after": t2,
                         "outage_ms": round((t2 - t1 - med) * 1000, 1), "lost_pings": s2 - s1 - 1})
    return gaps, med


def phase_of(t, ev):
    if "move_call_start" in ev and t < ev["move_call_start"]:
        return "before"
    end = ev.get("new_location_observed")
    if end is not None and t <= end:
        return "during"
    return "after"


def analyse(folder, mac, ip):
    ev_list = json.load(open(os.path.join(folder, "events.json")))
    ev = {e["event"]: e["unix_time"] for e in ev_list}
    t0 = ev.get("move_call_start", ev_list[0]["unix_time"])
    rel = lambda t: round((t - t0) * 1000, 1)          # ms relative to move_call_start
    leaves = sorted(f[:-5] for f in os.listdir(folder) if re.match(r"leaf\d+\.pcap$", f))
    summary = {"folder": folder, "mac": mac, "ip": ip, "t0": "move_call_start", "leaves": {}}
    timeline = [{"t_ms": rel(e["unix_time"]), "where": "test", "what": e["event"], "detail": ""}
                for e in ev_list]
    all_pkts = {}

    for leaf in leaves:
        ifn = ifindex_map(folder, leaf)
        pkts = read_pcap(os.path.join(folder, f"{leaf}.pcap"), ifn)
        for p in pkts:
            p["robot_related"] = robot_related(p, mac, ip)
            p["t_ms"] = rel(p["t_abs"]); p["phase"] = phase_of(p["t_abs"], ev)
        all_pkts[leaf] = pkts
        s = {"packets": len(pkts), "bytes": sum(p["len"] for p in pkts)}

        # what crossed which interface
        table = Counter(); tbytes = Counter()
        for p in pkts:
            k = (p["ifname"], p["role"], p["dir"], p["what"])
            table[k] += 1; tbytes[k] += p["len"]
        s["by_interface"] = [{"ifname": k[0], "role": k[1], "dir": k[2], "what": k[3],
                              "packets": c, "bytes": tbytes[k]} for k, c in table.most_common()]

        # tunnels: one row per (dir, outer VTEPs, VNI, inner frame type)
        tun = defaultdict(lambda: {"packets": 0, "first_ms": None, "last_ms": None, "robot_packets": 0})
        for p in pkts:
            if p["vni"] and p["role"] == "uplink":
                k = (p["dir"], p["outer_src"], p["outer_dst"], p["vni"], p["what"].replace("VXLAN ", ""))
                r = tun[k]; r["packets"] += 1; r["robot_packets"] += p["robot_related"]
                r["first_ms"] = p["t_ms"] if r["first_ms"] is None else r["first_ms"]; r["last_ms"] = p["t_ms"]
        s["vxlan_tunnels"] = [{"dir": k[0], "outer": f"{k[1]} -> {k[2]}", "vni": k[3], "inner": k[4], **v}
                              for k, v in sorted(tun.items(), key=lambda x: x[1]["first_ms"])]

        # where did frames addressed TO the robot go, per phase (local port vs tunnel to which VTEP)
        paths = defaultdict(Counter)
        for p in pkts:
            to_robot = p["dst_mac"] == mac or p["ip_dst"] == ip
            if to_robot and p["dir"] == "out":
                if p["role"] == "access":
                    paths[p["phase"]][f"local port {p['ifname']}"] += 1
                elif p["role"] == "uplink" and p["vni"]:
                    paths[p["phase"]][f"VXLAN to {p['outer_dst']} via {p['ifname']}"] += 1
        s["robot_traffic_paths"] = {ph: dict(c) for ph, c in paths.items()}

        # first / last tunnel packet that carried the robot, per phase, direction & VTEP pair
        for (ph, d, a, b), grp in _group([p for p in pkts if p["robot_related"] and p["vni"] and p["role"] == "uplink"],
                                         lambda p: (p["phase"], p["dir"], p["outer_src"], p["outer_dst"])).items():
            timeline.append({"t_ms": grp[0]["t_ms"], "where": leaf, "what": f"first robot frame in tunnel {d} ({ph})",
                             "detail": f"{a} -> {b} VNI {grp[0]['vni']} {grp[0]['what']} via {grp[0]['ifname']}"})
            timeline.append({"t_ms": grp[-1]["t_ms"], "where": leaf, "what": f"last robot frame in tunnel {d} ({ph})",
                             "detail": f"{a} -> {b} ({len(grp)} frames this phase)"})
        for p in pkts:
            if p["robot_related"] and p["what"].startswith(("ARP", "ICMPv6")) and p["role"] == "access":
                timeline.append({"t_ms": p["t_ms"], "where": leaf, "what": f"{p['what']} on {p['ifname']} ({p['dir']})",
                                 "detail": p["detail"]})

        # BGP EVPN Type-2 routes for the robot
        t2 = bgp_type2(pkts, mac)
        if t2 is None:
            s["bgp_type2"] = "evpn_move_analyzer.py not found next to this script - BGP not decoded"
        else:
            s["bgp_type2"] = []
            for r in t2:
                r["t_ms"] = rel(r.pop("t_abs"))
                s["bgp_type2"].append(r)
                timeline.append({"t_ms": r["t_ms"], "where": leaf,
                                 "what": f"BGP {r['dir']} {r['action']} {r['nlri']} via {r['uplink']}",
                                 "detail": f"nh {r['next_hop'] or '-'} rd {r['rd']} seq {r['seq']} path [{r['as_path']}]"})

        # kernel FDB / ARP table changes and FRR's view
        for kind in ("fdb", "neigh"):
            for r in read_jsonl(os.path.join(folder, f"{leaf}-{kind}.jsonl")):
                if mac in r["line"] or ip + " " in r["line"]:
                    timeline.append({"t_ms": rel(r["unix_time"]), "where": leaf,
                                     "what": f"kernel {kind} change", "detail": r["line"].strip()})
        summary["leaves"][leaf] = s

    for r in read_jsonl(os.path.join(folder, "mac_state.jsonl")):
        timeline.append({"t_ms": rel(r["unix_time"]), "where": r["leaf"], "what": "FRR MAC state",
                         "detail": json.dumps(r["state"])})

    summary["probes"] = {}
    for f in sorted(os.listdir(folder)):
        m = re.match(r"probe-(.+)\.log$", f)
        if not m:
            continue
        replies = read_probe(os.path.join(folder, f))
        gaps, med = outages(replies)
        summary["probes"][m.group(1)] = {
            "replies": len(replies), "interval_ms": round(med * 1000, 1) if med else None,
            "outages": [{**g, "last_reply_before": rel(g["last_reply_before"]),
                         "first_reply_after": rel(g["first_reply_after"])} for g in gaps]}
        for g in gaps:
            timeline.append({"t_ms": rel(g["last_reply_before"]), "where": f"probe {m.group(1)}",
                             "what": "last ping reply before outage", "detail": f"{g['lost_pings']} pings lost"})
            timeline.append({"t_ms": rel(g["first_reply_after"]), "where": f"probe {m.group(1)}",
                             "what": "first ping reply after outage", "detail": f"outage {g['outage_ms']} ms"})

    timeline.sort(key=lambda r: r["t_ms"])
    return summary, timeline, all_pkts, ev, t0


def _group(items, key):
    g = defaultdict(list)
    for it in items:
        g[key(it)].append(it)
    return g


# ------------------------------------------------------------------- plot ---
def plot(summary, timeline, all_pkts, ev, t0, mac, path, full=False):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    lanes, pts = [], defaultdict(list)
    for leaf, pkts in all_pkts.items():
        for lane, sel in ((f"{leaf} access ports", lambda p: p["role"] == "access"),
                          (f"{leaf} VXLAN tunnel", lambda p: p["role"] == "uplink" and p["vni"]),
                          (f"{leaf} BGP", lambda p: p["what"].startswith("BGP UPDATE"))):
            lanes.append(lane)
            for p in pkts:
                if sel(p) and (p["robot_related"] or lane.endswith("BGP")):
                    pts[lane].append(p["t_ms"])
        lanes.append(f"{leaf} kernel FDB/ARP")
        for r in timeline:
            if r["where"] == leaf and r["what"].startswith("kernel"):
                pts[f"{leaf} kernel FDB/ARP"].append(r["t_ms"])
    for host in summary["probes"]:
        lanes.append(f"probe {host}")
    fig, ax = plt.subplots(figsize=(12, 0.45 * len(lanes) + 2.4))
    for i, lane in enumerate(lanes):
        if lane.startswith("probe"):
            host = lane.split()[1]
            for g in summary["probes"][host]["outages"]:
                ax.plot([g["last_reply_before"], g["first_reply_after"]], [i, i], color="#d1453b", lw=6,
                        solid_capstyle="butt")
                ax.text(g["first_reply_after"], i, f"  {g['outage_ms']:.0f} ms outage", va="center", fontsize=8)
            continue
        col = "#2a6fdb" if "access" in lane else "#1a9e5c" if "VXLAN" in lane else "#7a5cc7" if "BGP" in lane else "#e08a00"
        ax.scatter(pts[lane], [i] * len(pts[lane]), marker="|", s=120, color=col)
    marks = [(n, (t - t0) * 1000) for n, t in ev.items()
             if n.startswith(("move_call", "learn_host", "new_location"))]
    for i, (name, x) in enumerate(sorted(marks, key=lambda m: m[1])):
        ax.axvline(x, color="#999", ls=":", lw=1)
        ax.text(x, len(lanes) - 0.3 + 0.55 * i, " " + name, fontsize=7, color="#555", va="center")
    ax.set_yticks(range(len(lanes))); ax.set_yticklabels(lanes, fontsize=8)
    ax.set_ylim(-0.7, len(lanes) + 0.55 * len(marks))
    if not full:                                   # zoom on the move itself
        ends = [x for _, x in marks] + [g["first_reply_after"] for p in summary["probes"].values()
                                        for g in p["outages"]]
        ax.set_xlim(-400, max(ends + [0]) + 600)
    ax.set_xlabel("ms since move_call_start")
    ax.set_title(f"Leaf traffic for robot {mac} (packet marks = frames that carry the robot; BGP = all UPDATEs)", fontsize=10)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


# ------------------------------------------------------------------- main ---
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--mac", default="00:00:00:00:00:11")
    ap.add_argument("--ip", default="45.0.0.11")
    ap.add_argument("--plot", action="store_true")
    ap.add_argument("--full", action="store_true", help="plot the whole capture instead of zooming on the move")
    a = ap.parse_args()
    summary, timeline, all_pkts, ev, t0 = analyse(a.folder, a.mac, a.ip)
    out = os.path.join(a.folder, "analysis"); os.makedirs(out, exist_ok=True)

    cols = ["frame", "t_ms", "phase", "ifname", "role", "dir", "what", "detail", "src_mac", "dst_mac",
            "outer_src", "outer_dst", "vni", "len", "robot_related"]
    for leaf, pkts in all_pkts.items():
        with open(os.path.join(out, f"{leaf}_packets.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(pkts)
    with open(os.path.join(out, "timeline.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["t_ms", "where", "what", "detail"]); w.writeheader(); w.writerows(timeline)
    with open(os.path.join(out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    if a.plot:
        plot(summary, timeline, all_pkts, ev, t0, a.mac, os.path.join(out, "leaf_timeline.png"), a.full)

    print(f"Robot {a.mac} / {a.ip} - times in ms from move_call_start\n")
    for leaf, s in summary["leaves"].items():
        print(f"== {leaf}: {s['packets']} packets, {s['bytes']} bytes")
        print("   traffic by interface (top 12):")
        for r in s["by_interface"][:12]:
            print(f"     {r['ifname']:<12} {r['role']:<9} {r['dir']:<10} {r['what']:<22} {r['packets']:>5} pkts {r['bytes']:>7} B")
        print("   VXLAN tunnels on the uplinks:")
        for r in s["vxlan_tunnels"]:
            print(f"     {r['dir']:<4} {r['outer']:<24} VNI {r['vni']:<5} {r['inner']:<14} {r['packets']:>4} pkts "
                  f"({r['robot_packets']} robot) {r['first_ms']} .. {r['last_ms']} ms")
        print("   where frames addressed to the robot were sent:")
        for ph in ("before", "during", "after"):
            if ph in s["robot_traffic_paths"]:
                print(f"     {ph:<7} {s['robot_traffic_paths'][ph]}")
        if isinstance(s["bgp_type2"], str):
            print("   " + s["bgp_type2"])
        print()
    for host, p in summary["probes"].items():
        o = "; ".join(f"{g['outage_ms']} ms ({g['lost_pings']} lost) from {g['last_reply_before']} ms" for g in p["outages"]) or "none"
        print(f"probe {host}: {p['replies']} replies every {p['interval_ms']} ms, outages: {o}")
    print("\nTimeline (robot only):")
    for r in timeline:
        print(f"  {r['t_ms']:>9.1f}  {r['where']:<14} {r['what']:<42} {r['detail']}")
    print(f"\nWrote {out}/")


if __name__ == "__main__":
    main()