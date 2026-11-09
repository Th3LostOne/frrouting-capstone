#!/usr/bin/env python3
"""
evpn_move_analyzer.py - measure EVPN MAC-mobility convergence and BGP overhead
from a spine (or leaf) packet capture.

Requirements: tshark on PATH (Wireshark CLI). Optional: matplotlib for --plot.

Usage:
    python3 evpn_move_analyzer.py spine1-bgp.pcap
    python3 evpn_move_analyzer.py spine1-bgp.pcap --spine-asn 65000 --out results/ --plot
    python3 evpn_move_analyzer.py run*.pcap --out results/      # many runs -> runs_summary.csv

    # bgp_evpn_capstone topotest layout (captures/<stamp>/spine1-bgp.pcap + events.json):
    python3 evpn_move_analyzer.py captures/*/spine1-bgp.pcap --plot \
        --names 65011=leaf1,65012=leaf2,65013=leaf3,65014=leaf4,65015=leaf5

If an events.json (list of {"event", "unix_time"}) sits next to the pcap it is
loaded automatically; "move_call_start" becomes the move trigger, so metrics are
also reported from the moment the test moved the cable. Test-harness and pcap
timestamps share one clock in topotests (same host kernel), so they line up.

Outputs (in --out, default ./evpn_out):
    <name>_messages.csv   one row per BGP message / NLRI (the raw timeline)
    <name>_summary.json   sessions, timers, byte counts, every detected move + metrics
    <name>_timeline.png   swim-lane chart of the move (with --plot)
    runs_summary.csv      one row per move per capture (handy for averaging over N runs)

How it works: pulls the raw TCP payload of every port-179 segment with tshark,
reassembles each TCP direction, and parses BGP itself (OPEN/UPDATE/KEEPALIVE/
NOTIFICATION, EVPN route types 2/3/5, MAC Mobility extended community). That
avoids tshark's JSON flattening repeated fields.
"""
import argparse, csv, json, os, subprocess, sys
from collections import defaultdict, Counter

SLL_OUTGOING = "4"   # Linux cooked capture packet type "sent by us"

# ------------------------------------------------------------------ tshark ---
def read_segments(pcap):
    fields = ["frame.number", "frame.time_epoch", "frame.len", "sll.pkttype",
              "ipv6.src", "ipv6.dst", "ip.src", "ip.dst", "ipv6.plen", "ip.len",
              "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.len", "tcp.payload",
              "tcp.analysis.retransmission"]
    cmd = ["tshark", "-r", pcap, "-Y", "tcp.port==179", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("tshark failed: " + out.stderr.strip())
    segs = []
    for line in out.stdout.splitlines():
        v = dict(zip(fields, line.split("\t")))
        src = v["ipv6.src"] or v["ip.src"]
        dst = v["ipv6.dst"] or v["ip.dst"]
        if v["ipv6.plen"]:
            ip_bytes = int(v["ipv6.plen"]) + 40
        elif v["ip.len"]:
            ip_bytes = int(v["ip.len"])
        else:
            ip_bytes = 0
        segs.append(dict(
            frame=int(v["frame.number"]), t=float(v["frame.time_epoch"]),
            frame_len=int(v["frame.len"]), pkttype=v["sll.pkttype"],
            src=src, dst=dst, sport=int(v["tcp.srcport"]), dport=int(v["tcp.dstport"]),
            seq=int(v["tcp.seq_raw"] or 0), tcp_len=int(v["tcp.len"] or 0),
            payload=bytes.fromhex(v["tcp.payload"].replace(":", "")) if v["tcp.payload"] else b"",
            retrans=bool(v["tcp.analysis.retransmission"]), ip_bytes=ip_bytes))
    return segs

# ------------------------------------------------------------- BGP parsing ---
def fmt_mac(b): return ":".join(f"{x:02x}" for x in b)
def fmt_ip(b):
    if len(b) == 4: return ".".join(str(x) for x in b)
    if len(b) == 16:
        import ipaddress; return str(ipaddress.IPv6Address(b))
    return b.hex()

def fmt_rd(b):
    t = int.from_bytes(b[0:2], "big")
    if t == 0: return f"{int.from_bytes(b[2:4],'big')}:{int.from_bytes(b[4:8],'big')}"
    if t == 1: return f"{fmt_ip(b[2:6])}:{int.from_bytes(b[6:8],'big')}"
    if t == 2: return f"{int.from_bytes(b[2:6],'big')}:{int.from_bytes(b[6:8],'big')}"
    return b.hex()

def parse_evpn_nlri(buf):
    """Yield dicts for each EVPN NLRI in buf."""
    i = 0
    while i + 2 <= len(buf):
        rtype, ln = buf[i], buf[i + 1]
        b = buf[i + 2:i + 2 + ln]
        i += 2 + ln
        r = {"route_type": rtype, "rd": fmt_rd(b[0:8]) if len(b) >= 8 else ""}
        try:
            if rtype == 2:                      # MAC/IP advertisement
                p = 8 + 10 + 4                  # RD + ESI + EthTag
                maclen = b[p]; p += 1
                r["mac"] = fmt_mac(b[p:p + 6]); p += 6
                iplen = b[p]; p += 1
                r["ip"] = fmt_ip(b[p:p + iplen // 8]) if iplen else ""
                p += iplen // 8
                r["vni_l2"] = int.from_bytes(b[p:p + 3], "big") if p + 3 <= len(b) else ""
                p += 3
                r["vni_l3"] = int.from_bytes(b[p:p + 3], "big") if p + 3 <= len(b) else ""
            elif rtype == 3:                    # Inclusive multicast (BUM / VTEP discovery)
                p = 8 + 4
                iplen = b[p]; p += 1
                r["ip"] = fmt_ip(b[p:p + iplen // 8])
            elif rtype == 5:                    # IP prefix
                p = 8 + 10 + 4
                plen = b[p]; p += 1
                alen = 4 if ln == 34 else 16
                r["ip"] = f"{fmt_ip(b[p:p + alen])}/{plen}"; p += 2 * alen
                r["vni_l3"] = int.from_bytes(b[p:p + 3], "big")
        except IndexError:
            pass
        yield r

def parse_update(m):
    """m = full BGP message bytes. Returns (attrs, list_of_nlri_dicts)."""
    p = 19
    wlen = int.from_bytes(m[p:p + 2], "big"); p += 2 + wlen
    alen = int.from_bytes(m[p:p + 2], "big"); p += 2
    end = p + alen
    attrs = {"as_path": [], "next_hop": "", "mac_mob_seq": "", "sticky": "",
             "ext_comms": [], "origin": ""}
    nlris = []
    while p < end:
        flags, code = m[p], m[p + 1]
        if flags & 0x10:
            ln = int.from_bytes(m[p + 2:p + 4], "big"); v = m[p + 4:p + 4 + ln]; p += 4 + ln
        else:
            ln = m[p + 2]; v = m[p + 3:p + 3 + ln]; p += 3 + ln
        if code == 1:
            attrs["origin"] = {0: "IGP", 1: "EGP", 2: "?"}.get(v[0], v[0])
        elif code == 2:                         # AS_PATH (assume 4-byte ASN)
            q = 0
            while q < len(v):
                n = v[q + 1]; q += 2
                for k in range(n):
                    attrs["as_path"].append(int.from_bytes(v[q:q + 4], "big")); q += 4
        elif code == 16:                        # extended communities
            for q in range(0, len(v), 8):
                c = v[q:q + 8]
                if c[0] == 0x06 and c[1] == 0x00:   # MAC Mobility
                    attrs["mac_mob_seq"] = int.from_bytes(c[4:8], "big")
                    attrs["sticky"] = c[2] & 1
                elif c[0] == 0x00 and c[1] == 0x02:
                    attrs["ext_comms"].append(f"RT:{int.from_bytes(c[2:4],'big')}:{int.from_bytes(c[4:8],'big')}")
                elif c[0] == 0x03 and c[1] == 0x0c:
                    attrs["ext_comms"].append("encap:" + {8: "VXLAN"}.get(int.from_bytes(c[6:8], 'big'), str(int.from_bytes(c[6:8], 'big'))))
                elif c[0] == 0x06 and c[1] == 0x03:
                    attrs["ext_comms"].append("rmac:" + fmt_mac(c[2:8]))
        elif code == 14:                        # MP_REACH_NLRI
            afi, safi = int.from_bytes(v[0:2], "big"), v[2]
            nhl = v[3]; nh = v[4:4 + nhl]
            attrs["next_hop"] = fmt_ip(nh[:16] if nhl >= 16 else nh)
            q = 4 + nhl + 1
            if afi == 25 and safi == 70:
                for r in parse_evpn_nlri(v[q:]):
                    r["action"] = "advertise"; nlris.append(r)
        elif code == 15:                        # MP_UNREACH_NLRI
            afi, safi = int.from_bytes(v[0:2], "big"), v[2]
            if afi == 25 and safi == 70:
                for r in parse_evpn_nlri(v[3:]):
                    r["action"] = "withdraw"; nlris.append(r)
    return attrs, nlris

MSG_TYPES = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}

def extract_messages(segs):
    """Reassemble each TCP direction and split into BGP messages."""
    buf, nxt, msgs = defaultdict(bytes), {}, []
    for s in segs:
        key = (s["src"], s["sport"], s["dst"], s["dport"])
        if not s["payload"]:
            continue
        if key in nxt and s["seq"] < nxt[key]:      # retransmission -> skip duplicate bytes
            continue
        nxt[key] = s["seq"] + s["tcp_len"]
        buf[key] += s["payload"]
        while len(buf[key]) >= 19:
            ln = int.from_bytes(buf[key][16:18], "big")
            if len(buf[key]) < ln:
                break
            m, buf[key] = buf[key][:ln], buf[key][ln:]
            msgs.append(dict(seg=s, key=key, raw=m, type=MSG_TYPES.get(m[18], str(m[18])), length=ln))
    return msgs

# --------------------------------------------------------------- analysis ---
def load_events(pcap, t0):
    path = os.path.join(os.path.dirname(os.path.abspath(pcap)), "events.json")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        ev = json.load(fh)
    return [{"event": e["event"], "t": round(e["unix_time"] - t0, 6)} for e in ev]


def analyse(pcap, spine_asn=None, window=5.0, names=None):
    names = names or {}
    segs = read_segments(pcap)
    if not segs:
        sys.exit(f"{pcap}: no TCP/179 packets found")
    t0 = segs[0]["t"]
    events = load_events(pcap, t0)
    msgs = extract_messages(segs)

    # Work out which side of each session is "us" (the capture point).
    local_ips = {s["src"] for s in segs if s["pkttype"] == SLL_OUTGOING}
    rows = []
    for mm in msgs:
        s = mm["seg"]
        row = dict(frame=s["frame"], t_abs=s["t"], t=round(s["t"] - t0, 6),
                   src=s["src"], dst=s["dst"], msg=mm["type"], bgp_bytes=mm["length"])
        if mm["type"] == "UPDATE":
            attrs, nlris = parse_update(mm["raw"])
            for r in nlris or [{"route_type": "", "action": "other"}]:
                rr = dict(row); rr.update(attrs); rr.update(r)
                rr["as_path"] = " ".join(map(str, attrs["as_path"]))
                rr["ext_comms"] = " ".join(attrs["ext_comms"])
                rows.append(rr)
        else:
            rows.append(row)

    # Fallback direction detection when capture is not Linux-cooked:
    if not local_ips:
        firsts = Counter(r["as_path"].split()[0] for r in rows if r.get("as_path"))
        guess = spine_asn or (int(firsts.most_common(1)[0][0]) if firsts else None)
        local_ips = {r["src"] for r in rows if r.get("as_path", "").split()[:1] == [str(guess)]}
    for r in rows:
        r["dir"] = "tx" if r["src"] in local_ips else "rx"
        r["peer"] = r["dst"] if r["dir"] == "tx" else r["src"]

    # Spine ASN = first AS on what we transmit.
    if spine_asn is None:
        c = Counter(r["as_path"].split()[0] for r in rows if r["dir"] == "tx" and r.get("as_path"))
        spine_asn = int(c.most_common(1)[0][0]) if c else None

    # Peer ASN = first AS on what we receive (that isn't an echo of our own route).
    peer_asn = {}
    for r in rows:
        if r["dir"] == "rx" and r.get("as_path"):
            peer_asn.setdefault(r["peer"], int(r["as_path"].split()[0]))

    # Classify every row.
    rd_owner = {}
    for r in rows:
        ap = [int(x) for x in r.get("as_path", "").split()] if r.get("as_path") else []
        if r["msg"] != "UPDATE":
            r["kind"] = r["msg"].lower()
        elif r.get("action") == "withdraw":
            r["kind"] = "withdraw"
        elif r["dir"] == "rx" and spine_asn in ap:
            r["kind"] = "echo (AS-loop, dropped)"
        elif r["dir"] == "rx":
            r["kind"] = "origin advert"
            rd_owner[r.get("rd")] = r.get("next_hop")
        else:
            r["kind"] = "reflected advert"
        if r.get("route_type") == 2:
            r["nlri"] = "MAC+IP" if r.get("ip") else "MAC"

    # ------------------------------------------------ sessions & timers ---
    sessions = defaultdict(lambda: {"keepalives_rx": [], "keepalives_tx": []})
    for r in rows:
        if r["msg"] == "KEEPALIVE":
            sessions[r["peer"]]["keepalives_" + r["dir"]].append(r["t"])
    sess_out = {}
    for peer in sorted({r["peer"] for r in rows}):
        k = sessions[peer]
        iv = [round(b - a, 3) for a, b in zip(k["keepalives_tx"], k["keepalives_tx"][1:])]
        sess_out[peer] = {"peer_asn": peer_asn.get(peer),
                          "keepalive_interval_s": (sum(iv) / len(iv)) if iv else None,
                          "likely_hold_time_s": (3 * sum(iv) / len(iv)) if iv else None}

    # ------------------------------------------------------- byte budget ---
    seg_cat = {}
    for mm in msgs:
        seg_cat.setdefault(mm["seg"]["frame"], mm["type"])
    budget = Counter(); count = Counter()
    for s in segs:
        cat = seg_cat.get(s["frame"], "TCP ACK only")
        budget[(cat, "bgp")] += 0
        budget[(cat, "ip")] += s["ip_bytes"]
        budget[(cat, "eth")] += s["ip_bytes"] + 14
        count[cat] += 1
    bgp_bytes = Counter()
    for mm in msgs:
        bgp_bytes[mm["type"]] += mm["length"]
    by_kind = defaultdict(lambda: {"nlri_rows": 0, "bgp_bytes": 0})
    seen_frames = set()
    for r in rows:
        if r["msg"] == "UPDATE":
            by_kind[r["kind"]]["nlri_rows"] += 1
            if (r["frame"], r["kind"]) not in seen_frames:
                by_kind[r["kind"]]["bgp_bytes"] += r["bgp_bytes"]; seen_frames.add((r["frame"], r["kind"]))
    bytes_out = {
        "capture_seconds": round(segs[-1]["t"] - t0, 6),
        "packets": len(segs),
        "per_category": {c: {"packets": count[c], "bgp_bytes": bgp_bytes.get(c, 0),
                              "ip_bytes": budget[(c, "ip")], "ethernet_bytes": budget[(c, "eth")]}
                         for c in count},
        "update_breakdown": dict(by_kind),
        "total_ip_bytes": sum(s["ip_bytes"] for s in segs),
        "total_ethernet_bytes": sum(s["ip_bytes"] + 14 for s in segs),
    }

    # ---------------------------------------------------- move detection ---
    t2 = [r for r in rows if r.get("route_type") == 2]
    owner = {}         # mac -> (vtep, rd)
    moves = []
    for r in t2:
        if r["kind"] != "origin advert":
            continue
        mac, vtep = r["mac"], r["next_hop"]
        if mac in owner and owner[mac][0] != vtep:
            moves.append({"mac": mac, "old_vtep": owner[mac][0], "old_rd": owner[mac][1],
                          "new_vtep": vtep, "new_rd": r["rd"], "t_new_first": r["t"]})
        owner[mac] = (vtep, r["rd"])

    for mv in moves:
        mac = mv["mac"]; tn = mv["t_new_first"]
        win = [r for r in t2 if r["mac"] == mac and tn - window <= r["t"] <= tn + window]
        old_wd_rx = [r for r in win if r["kind"] == "withdraw" and r["dir"] == "rx" and r["rd"] == mv["old_rd"]]
        old_wd_tx = [r for r in win if r["kind"] == "withdraw" and r["dir"] == "tx" and r["rd"] == mv["old_rd"]]
        new_rx = [r for r in win if r["kind"] == "origin advert" and r["rd"] == mv["new_rd"]]
        new_tx = [r for r in win if r["kind"] == "reflected advert" and r["rd"] == mv["new_rd"]]
        echoes = [r for r in win if r["kind"].startswith("echo") and r["rd"] == mv["new_rd"]]
        f = lambda L: min(x["t"] for x in L) if L else None
        l = lambda L: max(x["t"] for x in L) if L else None
        rx_mac = [r for r in new_rx if r["nlri"] == "MAC"]; rx_ip = [r for r in new_rx if r["nlri"] == "MAC+IP"]
        tx_mac = [r for r in new_tx if r["nlri"] == "MAC"]; tx_ip = [r for r in new_tx if r["nlri"] == "MAC+IP"]
        trigger = min(x for x in [f(old_wd_rx), f(new_rx)] if x is not None)
        ms = lambda a, b: round((a - b) * 1000, 3) if a is not None and b is not None else None
        # Harness trigger from events.json: last move_call_start before the first BGP sign of the move.
        starts = [e["t"] for e in events if e["event"] == "move_call_start" and e["t"] <= trigger]
        t_start = max(starts) if starts else None
        mv.update({
            "ip": next((r["ip"] for r in rx_ip), ""),
            "mac_mobility_seq": next((r["mac_mob_seq"] for r in new_rx if r["mac_mob_seq"] != ""), ""),
            "old_leaf_asn": next((peer_asn.get(r["peer"]) for r in old_wd_rx), None),
            "new_leaf_asn": next((peer_asn.get(r["peer"]) for r in new_rx), None),
            "t_move_call_start": t_start,
            "t_trigger": trigger,
            "t_old_withdraw_rx": f(old_wd_rx), "t_old_withdraw_tx_last": l(old_wd_tx),
            "t_new_mac_rx": f(rx_mac), "t_new_mac_tx_last": l(tx_mac),
            "t_new_macip_rx": f(rx_ip), "t_new_macip_tx_last": l(tx_ip),
            "t_last_echo": l(echoes),
            "peers_updated": len({r["peer"] for r in new_tx}),
            "metrics_ms": {
                "withdraw_to_new_advert_at_spine": ms(f(new_rx), f(old_wd_rx)),
                "spine_processing_mac": ms(f(tx_mac), f(rx_mac)),
                "spine_processing_macip": ms(f(tx_ip), f(rx_ip)),
                "spine_fanout_spread_mac": ms(l(tx_mac), f(tx_mac)),
                "mac_to_macip_gap_at_new_leaf": ms(f(rx_ip), f(rx_mac)),
                "L2_control_plane_convergence": ms(l(tx_mac) or l(tx_ip), trigger),
                "L3_host_route_convergence": ms(l(tx_ip), trigger),
                "no_route_window_remote_leaves_L2": ms(f(tx_mac) or f(tx_ip), l(old_wd_tx)),
                "no_hostroute_window_remote_leaves_L3": ms(f(tx_ip), l(old_wd_tx)),
                "until_last_echo": ms(l(echoes), trigger),
            },
            "metrics_from_move_call_ms": None if t_start is None else {
                "old_leaf_withdraw_seen": ms(f(old_wd_rx), t_start),
                "new_leaf_mac_advert_seen": ms(f(rx_mac) or f(rx_ip), t_start),
                "new_leaf_macip_advert_seen": ms(f(rx_ip), t_start),
                "L2_converged_all_peers": ms(l(tx_mac) or l(tx_ip), t_start),
                "L3_converged_all_peers": ms(l(tx_ip), t_start),
            },
        })
        lo, hi = trigger - 0.001, (l(echoes) or l(tx_ip) or l(tx_mac)) + 0.001
        wseg = [s for s in segs if lo <= s["t"] - t0 <= hi]
        wmsg = [mm for mm in msgs if lo <= mm["seg"]["t"] - t0 <= hi]
        mv["move_overhead"] = {
            "packets": len(wseg),
            "updates": sum(1 for mm in wmsg if mm["type"] == "UPDATE"),
            "update_bgp_bytes": sum(mm["length"] for mm in wmsg if mm["type"] == "UPDATE"),
            "ip_bytes_all": sum(s["ip_bytes"] for s in wseg),
            "ethernet_bytes_all": sum(s["ip_bytes"] + 14 for s in wseg),
        }

    for mv in moves:
        mv["old_leaf"] = names.get(mv["old_leaf_asn"], f"AS{mv['old_leaf_asn']}")
        mv["new_leaf"] = names.get(mv["new_leaf_asn"], f"AS{mv['new_leaf_asn']}")
    return dict(pcap=os.path.basename(pcap), t0_epoch=t0, spine_asn=spine_asn, events=events, names=names,
                local_ips=sorted(local_ips), sessions=sess_out, bytes=bytes_out,
                macs={m: {"vtep": v, "rd": rd} for m, (v, rd) in owner.items()},
                moves=moves), rows

# ------------------------------------------------------------------ plot ---
def plot(summary, rows, path):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    peers = sorted({r["peer"] for r in rows}, key=lambda p: summary["sessions"][p]["peer_asn"] or 0)
    nm = {int(k): v for k, v in summary.get("names", {}).items()}
    lab = {}
    for p in peers:
        a = summary["sessions"][p]["peer_asn"]
        lab[p] = f"{nm[a]} (AS{a})" if a in nm else f"AS{a}"
    style = {"origin advert": ("o", "#2a6fdb"), "reflected advert": (">", "#1a9e5c"),
             "withdraw": ("x", "#d1453b"), "echo (AS-loop, dropped)": (".", "#999999"),
             "keepalive": ("|", "#c9c9c9")}
    fig, ax = plt.subplots(figsize=(11, 0.6 * len(peers) + 2.8))
    for k, (mk, col) in style.items():
        pts = [(r["t"], peers.index(r["peer"])) for r in rows if r.get("kind") == k]
        if pts:
            ax.scatter(*zip(*pts), marker=mk, color=col, s=55 if mk != "." else 30, label=k, zorder=3)
    for e in summary.get("events", []):
        ax.axvline(e["t"], color="#7a5cc7", ls=":", lw=1)
        ax.text(e["t"], -0.55, " " + e["event"], rotation=90, fontsize=7, color="#7a5cc7", va="bottom")
    for mv in summary["moves"]:
        start = mv.get("t_move_call_start") or mv["t_trigger"]
        fm = mv.get("metrics_from_move_call_ms") or mv["metrics_ms"]
        l2 = fm.get("L2_converged_all_peers", mv["metrics_ms"]["L2_control_plane_convergence"])
        l3 = fm.get("L3_converged_all_peers", mv["metrics_ms"]["L3_host_route_convergence"])
        if mv["t_new_macip_tx_last"]:
            ax.axvspan(start, mv["t_new_macip_tx_last"], color="#f4c542", alpha=0.18)
            ax.text(start, len(peers) - 0.4,
                    f"  {mv['mac']} {mv['old_leaf']} -> {mv['new_leaf']}: L2 {l2:.0f} ms, L3 {l3:.0f} ms "
                    f"({'from move_call_start' if mv.get('t_move_call_start') is not None else 'from first BGP sign'})",
                    fontsize=8, va="bottom")
    ax.set_yticks(range(len(peers))); ax.set_yticklabels([lab[p] for p in peers])
    ax.set_xlabel("seconds since first packet"); ax.set_ylim(-0.6, len(peers) + 0.3)
    ax.set_title(f"BGP EVPN messages seen at the capture point (AS{summary['spine_asn']}) - {summary['pcap']}")
    ax.grid(axis="x", alpha=0.3)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), fontsize=8, ncol=5, frameon=False)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)

# ------------------------------------------------------------------ main ---
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--spine-asn", type=int, help="ASN of the capture point (auto-detected if omitted)")
    ap.add_argument("--out", default="evpn_out")
    ap.add_argument("--plot", action="store_true")
    ap.add_argument("--names", default="", help="ASN=name pairs, e.g. 65011=leaf1,65012=leaf2")
    a = ap.parse_args()
    names = {int(k): v for k, v in (x.split("=") for x in a.names.split(",") if x)}
    os.makedirs(a.out, exist_ok=True)
    all_moves = []
    cols = ["frame", "t", "dir", "peer", "msg", "kind", "action", "route_type", "nlri", "rd", "mac", "ip",
            "vni_l2", "vni_l3", "next_hop", "as_path", "mac_mob_seq", "sticky", "ext_comms", "bgp_bytes"]
    for pcap in a.pcaps:
        summary, rows = analyse(pcap, a.spine_asn, names=names)
        name = os.path.splitext(os.path.basename(pcap))[0]
        with open(os.path.join(a.out, f"{name}_messages.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)
        with open(os.path.join(a.out, f"{name}_summary.json"), "w") as fh:
            json.dump(summary, fh, indent=2, default=str)
        if a.plot:
            plot(summary, rows, os.path.join(a.out, f"{name}_timeline.png"))
        print(f"\n=== {pcap}  (capture point AS{summary['spine_asn']}, {summary['bytes']['capture_seconds']} s, "
              f"{summary['bytes']['packets']} packets) ===")
        for p, s in summary["sessions"].items():
            print(f"  session {p:<28} AS{s['peer_asn']} {names.get(s['peer_asn'], '')}  keepalive {s['keepalive_interval_s']} s")
        for e in summary["events"]:
            print(f"  event  {e['event']:<24} t={e['t']} s")
        for mv in summary["moves"]:
            print(f"  MOVE {mv['mac']} ({mv['ip']})  {mv['old_leaf']} {mv['old_vtep']} -> "
                  f"{mv['new_leaf']} {mv['new_vtep']}  seq={mv['mac_mobility_seq']}")
            for k, v in mv["metrics_ms"].items():
                print(f"      {k:<40} {v} ms")
            if mv.get("metrics_from_move_call_ms"):
                print("    measured from move_call_start (events.json):")
                for k, v in mv["metrics_from_move_call_ms"].items():
                    print(f"      {k:<40} {v} ms")
            print(f"      overhead: {mv['move_overhead']}")
            flat = {"pcap": summary["pcap"], "mac": mv["mac"], "ip": mv["ip"],
                    "old_vtep": mv["old_vtep"], "new_vtep": mv["new_vtep"], "seq": mv["mac_mobility_seq"],
                    **mv["metrics_ms"],
                    **{"from_move_call_" + k: v for k, v in (mv.get("metrics_from_move_call_ms") or {}).items()},
                    **{"overhead_" + k: v for k, v in mv["move_overhead"].items()}}
            all_moves.append(flat)
        if not summary["moves"]:
            print("  no MAC move detected (need an advert of the same MAC from two different VTEPs)")
    if all_moves:
        with open(os.path.join(a.out, "runs_summary.csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(all_moves[0].keys())); w.writeheader(); w.writerows(all_moves)
        print(f"\nwrote {len(all_moves)} move(s) to {os.path.join(a.out, 'runs_summary.csv')}")

if __name__ == "__main__":
    main()