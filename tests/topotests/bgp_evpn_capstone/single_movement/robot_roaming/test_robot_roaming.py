#!/usr/bin/env python3
"""test_robot_roaming.py - one robot moves between many leaves; does the controller's
router keep up?

Built on single_movement/single_robot_movement.py: the same cable move (eth-host11
is pulled out of one leaf's bridge and plugged into the next leaf's br1000), repeated
along ROAM_PATH, with the same scapy ARP (learn_host) after every move.

Run (from tests/topotests, as root like every topotest):
    sudo -E pytest -s bgp_evpn_capstone/robot_roaming/test_robot_roaming.py
    ROAM_DWELL_S=0.3 sudo -E pytest -s ...          # move faster than BGP converges

The question this answers
-------------------------
The controller (20.0.0.51) sits behind leaf5 in another L2VNI, so it reaches the
robot only through leaf5's VRF500 /32 route, which is built from the EVPN Type-2
MAC+IP route the robot's current leaf advertises:

    robot ARP -> new leaf learns MAC/IP -> RT-2 to spine1/spine2 -> spines to leaf5
              -> leaf5 BGP best path -> zebra /32 via the new VTEP

Whenever leaf5's /32 (or BGP best path) points anywhere other than the leaf the
robot is plugged into, the controller's data is out of sync with the robot.

What is recorded in robot_roaming/captures/<stamp>/
---------------------------------------------------
  <node>.pcap       tshark -i any on spine1, spine2 (BGP + VXLAN) and leaf1..leaf5
                    (BGP, VXLAN, ARP, ICMP): the same RT-2 seen at every hop of its path
  <node>-links-*.txt  ifindex -> interface name, saved at start and after every move
  <leaf>-fdb.jsonl / <leaf>-neigh.jsonl   kernel MAC / ARP table changes
  views.jsonl       every node's idea of where the robot is, polled every 50 ms,
                    one line per change:
                      leaf1..leaf4  mac    FRR EVPN MAC table (local / remote VTEP, seq, DAD)
                      spine1/2      bgp    VTEPs the spine holds an RT-2 MAC+IP route from
                      leaf5         bgp    VRF500 BGP paths to 45.0.0.11/32 and the best one
                      leaf5         route  zebra's installed /32 next-hop  <- the controller's data
  probe-controller.log  controller -> robot pings (20/s)
  probe-robot.log       robot -> controller pings
  events.json       move_start / detached / attached / learned per hop (the truth)
  roam.json         path, parameters, node -> VTEP map
  snapshots/        tables before and after the walk

Afterwards roam_analyzer.py runs on the folder (ROAM_ANALYZE=0 to skip) and writes
analysis/roam_report.html.

Knobs: ROAM_PATH (comma list, default walks every leaf pair), ROAM_DWELL_S (2),
ROAM_PROBE_INTERVAL (0.05), ROAM_SETTLE_S (5), ROAM_ANALYZE (1).
"""

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../.."))

from bgp_evpn_capstone.single_movement import capture_leaf_traffic as base  # noqa: E402
from bgp_evpn_capstone.single_movement import capture_single_robot_movement as single  # noqa: E402

lab = base.lab
setup_module = lab.setup_module
teardown_module = lab.teardown_module

ROBOT, ROBOT_MAC, ROBOT_IP = "host11", single.MAC, "45.0.0.11"
HOME = "leaf1"
CONTROLLER, CONTROLLER_IP = "controller", "20.0.0.51"
CONTROLLER_LEAF = "leaf5"
ROBOT_LEAVES = ["leaf1", "leaf2", "leaf3", "leaf4"]
LEAVES = ROBOT_LEAVES + [CONTROLLER_LEAF]
SPINES = ["spine1", "spine2"]

PATH = [x.strip() for x in os.environ.get(
    "ROAM_PATH", "leaf2,leaf3,leaf4,leaf1,leaf3,leaf2,leaf4,leaf3,leaf1,leaf2").split(",") if x.strip()]
DWELL_S = float(os.environ.get("ROAM_DWELL_S", "2.0"))
PROBE_INTERVAL = os.environ.get("ROAM_PROBE_INTERVAL", "0.05")
SETTLE_S = float(os.environ.get("ROAM_SETTLE_S", "5.0"))
RUN_ANALYZER = os.environ.get("ROAM_ANALYZE", "1") != "0"
POLL_INTERVAL = 0.05

SPINE_FILTER = "tcp port 179 or udp port 4789"
SNAPSHOT_CMDS = {
    "leaf": [("show evpn", "vtysh"), ("show evpn mac vni 1000", "vtysh"),
             ("show evpn mac vni 1000 duplicate", "vtysh"),
             ("show bgp l2vpn evpn route type macip", "vtysh"), ("bridge fdb show br br1000", "shell")],
    "leaf5": [("show bgp vrf VRF500 ipv4 unicast {ip}/32", "vtysh"),
              ("show ip route vrf VRF500", "vtysh"), ("show bgp l2vpn evpn route type macip", "vtysh")],
    "spine": [("show bgp l2vpn evpn route type macip", "vtysh"), ("show bgp l2vpn evpn summary", "vtysh")],
}


# ------------------------------------------------------------- views ---
def view_mac(router):
    "Robot-leaf view: FRR's EVPN MAC entry for the robot."
    data = router.vtysh_cmd("show evpn mac vni 1000 json", isjson=True)
    entry = data.get("macs", data).get(ROBOT_MAC, {})
    keep = ("type", "intf", "remoteVtep", "localSequence", "remoteSequence", "detectionCount", "isDuplicate")
    return {k: entry.get(k) for k in keep if k in entry} or {"type": "absent"}


def _walk_paths(obj):
    "Yield every path dict (has 'nexthops') below obj."
    if isinstance(obj, dict):
        if "nexthops" in obj:
            yield obj
        for v in obj.values():
            yield from _walk_paths(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_paths(v)


def view_spine(router):
    "Spine view: which VTEPs it holds an RT-2 MAC+IP route for the robot from."
    data = router.vtysh_cmd("show bgp l2vpn evpn route type macip json", isjson=True)
    vteps, best = set(), set()
    for rd, routes in data.items():
        if not isinstance(routes, dict):
            continue
        for prefix, route in routes.items():
            if ROBOT_MAC not in prefix or ROBOT_IP not in prefix:
                continue
            for path in _walk_paths(route):
                for nh in path.get("nexthops", []):
                    if nh.get("ip"):
                        vteps.add(nh["ip"])
                        if path.get("bestpath") or path.get("best"):
                            best.add(nh["ip"])
    return {"vteps": sorted(vteps), "best": sorted(best)}


def view_leaf5_bgp(router):
    "Controller-side BGP: every VRF500 path to the robot /32 and the best one."
    data = router.vtysh_cmd("show bgp vrf VRF500 ipv4 unicast {}/32 json".format(ROBOT_IP), isjson=True)
    vteps, best = set(), set()
    for path in data.get("paths", []):
        hops = [nh.get("ip") for nh in path.get("nexthops", []) if nh.get("ip")]
        vteps.update(hops)
        if (path.get("bestpath") or {}).get("overall") or path.get("best"):
            best.update(hops)
    return {"vteps": sorted(vteps), "best": sorted(best)}


def view_leaf5_route(router):
    "Controller-side FIB: the /32 zebra installed - what the controller's traffic follows."
    prefix = "{}/32".format(ROBOT_IP)
    data = router.vtysh_cmd("show ip route vrf VRF500 {} json".format(prefix), isjson=True)
    for entry in data.get(prefix, []):
        if entry.get("selected") or entry.get("installed"):
            hops = sorted({nh.get("ip") for nh in entry.get("nexthops", []) if nh.get("ip")})
            return {"protocol": entry.get("protocol"), "vteps": hops}
    return {"protocol": None, "vteps": []}


class ViewPoller(threading.Thread):
    "Poll one view of one node; write a line to views.jsonl when the answer changes."

    def __init__(self, node, kind, func, out, lock):
        super().__init__(daemon=True)
        self.node, self.kind, self.func, self.out, self.lock = node, kind, func, out, lock
        self.stop_event = threading.Event()
        self.last = None

    def run(self):
        while not self.stop_event.is_set():
            try:
                state = self.func()
            except Exception as exc:  # pylint: disable=broad-except
                state = {"error": str(exc)}
            if state != self.last:
                self.last = state
                with self.lock:
                    self.out.write(json.dumps({"unix_time": time.time(), "node": self.node,
                                               "kind": self.kind, "state": state}) + "\n")
                    self.out.flush()
            self.stop_event.wait(POLL_INTERVAL)

    def stop(self):
        self.stop_event.set()
        self.join(timeout=5)


# ------------------------------------------------------------ helpers ---
def start_tshark(node, pcap_path, log_path, capture_filter):
    "tshark -i any, Linux cooked v2 when available (keeps the ifindex of every frame)."
    cmd = ["tshark", "-n", "-i", "any", "-f", capture_filter, "-F", "pcap", "-w", "-"]
    for linktype in (["-y", "LINUX_SLL2"], []):
        packets, log = open(pcap_path, "wb"), open(log_path, "a")
        proc = node.popen(cmd[:4] + linktype + cmd[4:], stdout=packets, stderr=log)
        time.sleep(1)
        if proc.poll() is None:
            return base.Running(proc, (packets, log), linktype[1] if linktype else "LINUX_SLL")
        packets.close()
        log.close()
    raise AssertionError("tshark failed on {}; read {}".format(node.name, log_path))


def move_cable(topology, src, dst):
    """single_robot_movement.test_move(), generalised to any src -> dst leaf."""
    old, new = topology.net[src], topology.net[dst]
    old.cmd_raises("ip link set eth-host11 nomaster")
    old.cmd_raises("ip link set eth-host11 netns {}".format(new.pids[-1]))
    yield "detached"
    links = topology.net.links
    for key in [k for k in links if k.startswith("host11:eth0-")]:
        links.pop(key)
    links["host11:eth0-{}:eth-host11".format(dst)] = ("host11", "eth0", dst, "eth-host11")
    new.cmd_raises("ip link set eth-host11 master br1000")
    new.cmd_raises("ip link set eth-host11 up")
    yield "attached"
    lab._viz_post({"action": "DEL_LINK", "source": src, "target": ROBOT})
    lab._viz_post({"action": "ADD_LINK", "source": dst, "target": ROBOT})


def leaf5_synced(topology, leaf):
    want = lab.LEAVES[leaf]["lo"]
    return view_leaf5_route(topology.gears[CONTROLLER_LEAF]).get("vteps") == [want]


# --------------------------------------------------------------- test ---
def test_robot_roaming():
    topology = lab.get_topogen()
    if topology.routers_have_failure():
        pytest.skip(topology.errors)
    lab.test_bgp_underlay_established()
    lab.test_evpn_sessions_established()
    lab.test_evpn_vnis_present()
    lab._prime_host_adjacencies(topology)
    for i, (a, b) in enumerate(zip([HOME] + PATH, PATH)):
        assert a != b and b in ROBOT_LEAVES, "ROAM_PATH step {}: {} -> {} is not a move".format(i, a, b)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    out = Path(CWD) / "captures" / stamp
    out.mkdir(parents=True)
    events, captures, monitors, pollers, probes, files = [], {}, [], [], {}, []

    def event(name, **extra):
        events.append(dict({"event": name, "unix_time": time.time()}, **extra))

    def save_links(phase):
        for node in LEAVES + SPINES:
            (out / "{}-links-{}.txt".format(node, phase)).write_text(topology.net[node].cmd("ip -o link show"))

    def snapshot(phase):
        folder = out / "snapshots"
        folder.mkdir(exist_ok=True)
        for node in LEAVES + SPINES:
            group = "spine" if node in SPINES else ("leaf5" if node == CONTROLLER_LEAF else "leaf")
            with (folder / "{}-{}.txt".format(node, phase)).open("w") as fh:
                for cmd, kind in SNAPSHOT_CMDS[group]:
                    cmd = cmd.format(ip=ROBOT_IP)
                    fh.write("\n### {}\n".format(cmd))
                    try:
                        fh.write(topology.gears[node].vtysh_cmd(cmd) if kind == "vtysh"
                                 else topology.net[node].cmd(cmd))
                    except Exception as exc:  # pylint: disable=broad-except
                        fh.write("<failed: {}>\n".format(exc))

    where = HOME
    try:
        save_links("start")
        for node in SPINES:
            captures[node] = start_tshark(topology.net[node], out / "{}.pcap".format(node),
                                          out / "{}-capture.log".format(node), SPINE_FILTER)
        for leaf in LEAVES:
            node = topology.net[leaf]
            captures[leaf] = start_tshark(node, out / "{}.pcap".format(leaf),
                                          out / "{}-capture.log".format(leaf), base.CAPTURE_FILTER)
            monitors.append(base.LineMonitor(node, ["bridge", "monitor", "fdb"], out / "{}-fdb.jsonl".format(leaf)))
            monitors.append(base.LineMonitor(node, ["ip", "monitor", "neigh"], out / "{}-neigh.jsonl".format(leaf)))
        event("capture_started", linktype={n: c.linktype for n, c in captures.items()})

        single.learn_host(topology)                       # robot known at leaf1 everywhere
        deadline = time.monotonic() + 60
        while not leaf5_synced(topology, HOME):
            assert time.monotonic() < deadline, "leaf5 never learned the robot at leaf1"
            time.sleep(0.2)
        event("baseline_learned", leaf=HOME)
        snapshot("before")

        lock = threading.Lock()
        views = open(out / "views.jsonl", "w")
        files.append(views)
        for leaf in ROBOT_LEAVES:
            r = topology.gears[leaf]
            pollers.append(ViewPoller(leaf, "mac", lambda r=r: view_mac(r), views, lock))
        for spine in SPINES:
            r = topology.gears[spine]
            pollers.append(ViewPoller(spine, "bgp", lambda r=r: view_spine(r), views, lock))
        r5 = topology.gears[CONTROLLER_LEAF]
        pollers.append(ViewPoller(CONTROLLER_LEAF, "bgp", lambda: view_leaf5_bgp(r5), views, lock))
        pollers.append(ViewPoller(CONTROLLER_LEAF, "route", lambda: view_leaf5_route(r5), views, lock))
        for p in pollers:
            p.start()

        probes["controller"] = base.start_probe(topology.net[CONTROLLER], ROBOT_IP, out / "probe-controller.log")
        probes["robot"] = base.start_probe(topology.net[ROBOT], CONTROLLER_IP, out / "probe-robot.log")
        event("probes_started", interval_s=float(PROBE_INTERVAL))
        time.sleep(2)

        for hop, dst in enumerate(PATH):
            event("move_start", hop=hop, src=where, dst=dst)
            if hop == 0:
                event("move_call_start")                  # T0, same name as single_movement
            steps = move_cable(topology, where, dst)
            event(next(steps), hop=hop, leaf=where)       # detached
            event(next(steps), hop=hop, leaf=dst)         # attached
            next(steps, None)
            where = dst
            event("learn_start", hop=hop, leaf=dst)
            single.learn_host(topology)                   # the robot's ARP on its new leaf
            event("learned", hop=hop, leaf=dst)
            save_links("hop{}".format(hop))
            time.sleep(DWELL_S)
        event("walk_done", leaf=where)

        deadline = time.monotonic() + SETTLE_S
        synced = False
        while time.monotonic() < deadline:
            if leaf5_synced(topology, where):
                synced = True
                event("leaf5_synced_at_end", leaf=where)
                break
            time.sleep(0.1)
        if not synced:
            event("leaf5_out_of_sync_at_end", leaf=where,
                  leaf5_route=view_leaf5_route(r5), leaf5_bgp=view_leaf5_bgp(r5))
        time.sleep(1)
        for p in probes.values():
            p.stop()
        snapshot("after")
        save_links("end")
    finally:
        for p in pollers:
            p.stop()
        for fh in files:
            fh.close()
        for p in probes.values():
            p.stop()
        for m in monitors:
            m.stop()
        for c in captures.values():
            c.stop()
        (out / "events.json").write_text(json.dumps(events, indent=2) + "\n")
        (out / "roam.json").write_text(json.dumps({
            "robot": {"name": ROBOT, "mac": ROBOT_MAC, "ip": ROBOT_IP, "home": HOME},
            "controller": {"name": CONTROLLER, "ip": CONTROLLER_IP, "leaf": CONTROLLER_LEAF},
            "path": PATH, "dwell_s": DWELL_S, "probe_interval_s": float(PROBE_INTERVAL),
            "vteps": {spec["lo"]: leaf for leaf, spec in lab.LEAVES.items()},
            "robot_leaves": ROBOT_LEAVES, "spines": SPINES,
        }, indent=2) + "\n")
        print("\nRoaming capture: {}".format(out))

    for node, cap in captures.items():
        assert cap.returncode == 0, "capture on {} failed; read {}/{}-capture.log".format(node, out, node)

    if RUN_ANALYZER:
        log = out / "analyzer.log"
        with log.open("w") as fh:
            res = subprocess.run([sys.executable, os.path.join(CWD, "roam_analyzer.py"), str(out), "--plot"],
                                 stdout=fh, stderr=subprocess.STDOUT, check=False)
        print("Report: {}".format(out / "analysis" / "roam_report.html") if res.returncode == 0
              else "roam_analyzer.py failed; read {}".format(log))


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", os.path.realpath(__file__)] + sys.argv[1:]))