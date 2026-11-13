#!/usr/bin/env python3
"""Capture EVPN RT-2 during repeated host11 roaming across leaf1/2/3.

Install beside test_evpn_capstone.py in tests/topotests/bgp_evpn_capstone/.
Run this module alone with pytest (see README).
"""
import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

import pytest
from lib.topogen import Topogen, get_topogen
from bgp_evpn_capstone import test_evpn_capstone as baseline

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

ROBOT = "host11"
IP = "45.0.0.11/24"
MAC = "00:00:00:00:00:11"
GW = "45.0.0.1"
VNI = 1000
LEAFS = ("leaf1", "leaf2", "leaf3")
INTERFACES = {"leaf1": "eth0", "leaf2": "eth1", "leaf3": "eth2"}
ACCESS = "eth-host11"
VTEPS = {name: baseline.LEAVES[name]["lo"] for name in LEAFS}
OBSERVER = "leaf4"  # Never hosts the moving robot, imports L2VNI 1000.


def build_topo(tgen):
    baseline.build_topo(tgen)
    # Original host11--leaf1 link is already built by baseline.build_topo.
    for leaf in ("leaf2", "leaf3"):
        tgen.add_link(tgen.gears[ROBOT], tgen.gears[leaf],
                      INTERFACES[leaf], ACCESS)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, spec in baseline.LEAVES.items():
        baseline._setup_leaf_dataplane(tgen, name, spec)

    for leaf in ("leaf2", "leaf3"):
        node = tgen.net[leaf]
        node.cmd_raises("ip link set {} master br1000".format(ACCESS))
        # Keep the new leaf access ports disabled until selected.
        node.cmd_raises("ip link set {} down".format(ACCESS))

    robot = tgen.net[ROBOT]
    for leaf in ("leaf2", "leaf3"):
        nic = INTERFACES[leaf]
        robot.cmd_raises("ip link set {} down".format(nic))
        robot.cmd_raises("ip link set dev {} address {}".format(nic, MAC))

    for spec in baseline.LEAVES.values():
        for name, (_ip, mac) in spec["hosts"].items():
            tgen.net[name].cmd_raises("ip link set dev eth0 address " + mac)

    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(baseline.CWD, name, "frr.conf"))
    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class CaptureSession:
    def __init__(self, tgen):
        self.tgen = tgen
        out = os.environ.get("TYPE2_OUTPUT_DIR")
        self.directory = Path(out).expanduser().resolve() if out else (
            Path(tgen.logdir).resolve() / "type2_host11")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.events_path = self.directory / "movement_events.jsonl"
        self.snap_path = self.directory / "route_snapshots.txt"
        self.processes = []
        self.logs = []
        print("\nTYPE2 RESULTS DIRECTORY: {}\n".format(self.directory), flush=True)

    def event(self, event, **fields):
        obj = {"event": event, "timestamp_utc": utc_now(),
               "timestamp_unix_ns": time.time_ns(), **fields}
        with self.events_path.open("a", encoding="utf8") as stream:
            stream.write(json.dumps(obj, sort_keys=True) + "\n")
        print("TYPE2_EVENT {}".format(json.dumps(obj)), flush=True)

    def start(self):
        if not shutil.which("tcpdump"):
            pytest.fail("tcpdump missing in FRR development environment")
        # Capture each physical BGP adjacency in ONE direction/at ONE router.
        # The leaf uplinks show what each leaf sends/receives to each spine.
        # The spine side shows how the updates are distributed to other leaves.
        targets = {}
        for leaf in ("leaf1", "leaf2", "leaf3", "leaf4"):
            targets[leaf] = ["eth-spine1", "eth-spine2"]
        for spine in ("spine1", "spine2"):
            targets[spine] = ["eth-leaf1", "eth-leaf2", "eth-leaf3", "eth-leaf4"]
        for node, ifnames in targets.items():
            for iface in ifnames:
                label = "{}__{}".format(node, iface)
                pcap = self.directory / (label + ".pcap")
                err = (self.directory / (label + ".tcpdump.log")).open("wb")
                self.logs.append(err)
                proc = self.tgen.net[node].popen(
                    ["tcpdump", "-i", iface, "-nn", "-s", "0", "-U",
                     "-w", str(pcap), "tcp port 179"],
                    stdout=subprocess.DEVNULL, stderr=err)
                self.processes.append((label, proc))
        time.sleep(1.0)
        failed = [label for label, proc in self.processes if proc.poll() is not None]
        if failed:
            raise RuntimeError("tcpdump exited early on: {}".format(failed))
        self.event("CAPTURE_STARTED", pcap_count=len(self.processes))

    def snapshot(self, label, move_number=None):
        # Preserve snapshots for comparison; no packet-timing conclusions needed.
        with self.snap_path.open("a", encoding="utf8") as stream:
            stream.write("\n===== {} move={} at {} =====\n".format(
                label, move_number, utc_now()))
            for leaf in ("leaf1", "leaf2", "leaf3", "leaf4"):
                stream.write("\n--- {} ---\n".format(leaf))
                for command in (
                    "show evpn mac vni 1000 mac " + MAC,
                    "show bgp l2vpn evpn route type macip",
                ):
                    stream.write("$ vtysh -c {!r}\n".format(command))
                    stream.write(self.tgen.gears[leaf].vtysh_cmd(command))
                    stream.write("\n")

    def stop(self):
        self.event("CAPTURE_STOPPING")
        for label, proc in self.processes:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        for stream in self.logs:
            stream.close()
        self.event("CAPTURE_STOPPED", pcap_count=len(self.processes))


def observer_location(tgen):
    """Read Leaf4's MAC entry; return current remote VTEP or None.

    Inspect the detailed MAC entry only, not the entire EVPN table, to avoid
    matching the leaf1/2/3 VTEP strings from unrelated hosts.
    """
    raw = tgen.gears[OBSERVER].vtysh_cmd(
        "show evpn mac vni 1000 mac " + MAC + " json", isjson=True)
    # FRR versions differ in whether the MAC entry is nested under its MAC key.
    item = raw.get(MAC, raw) if isinstance(raw, dict) else {}
    if not isinstance(item, dict):
        return None
    if item.get("type") != "remote":
        return None
    text = json.dumps(item)
    found = [name for name, addr in VTEPS.items() if addr in text]
    return found[0] if len(found) == 1 else None


def wait_for_location(tgen, leaf, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if observer_location(tgen) == leaf:
            return True
        time.sleep(0.25)
    return False


def generate_learning(tgen, nic):
    # ARP/ICMP from new attachment stimulates local MAC and IP learning.
    tgen.net[ROBOT].cmd("ping -n -I {} -c 2 -W 1 {}".format(nic, GW))
    # A stationary host behind Leaf4 also requests the moving endpoint.
    tgen.net["host41"].cmd("ping -n -c 2 -W 1 45.0.0.11")


def move_once(tgen, recorder, source, target, number):
    oldnic, newnic = INTERFACES[source], INTERFACES[target]
    robot = tgen.net[ROBOT]
    recorder.event("MOVE_START", move_id=number, source=source, target=target)
    # Break-before-make: never leave two interfaces active with the same MAC/IP.
    robot.cmd_raises("ip addr del {} dev {}".format(IP, oldnic))
    robot.cmd_raises("ip link set {} down".format(oldnic))
    tgen.net[source].cmd_raises("ip link set {} down".format(ACCESS))
    recorder.event("OLD_ATTACHMENT_DOWN", move_id=number, leaf=source)
    time.sleep(float(os.environ.get("TYPE2_BREAK_GAP_S", "0.3")))
    tgen.net[target].cmd_raises("ip link set {} up".format(ACCESS))
    robot.cmd_raises("ip link set {} up".format(newnic))
    robot.cmd_raises("ip addr add {} dev {}".format(IP, newnic))
    robot.cmd_raises("ip route replace default via {} dev {}".format(GW, newnic))
    recorder.event("NEW_ATTACHMENT_UP", move_id=number, leaf=target)
    generate_learning(tgen, newnic)
    success = wait_for_location(tgen, target,
                                timeout=float(os.environ.get("TYPE2_VERIFY_TIMEOUT_S", "45")))
    recorder.event("MOVE_VERIFY", move_id=number, leaf=target,
                   leaf4_observed=observer_location(tgen), success=success)
    recorder.snapshot("after_move", move_number=number)
    assert success, "Leaf4 did not learn host11 at {}".format(target)


def test_host11_repeated_type2_roaming():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    cycles = int(os.environ.get("TYPE2_CYCLES", "2"))
    dwell = float(os.environ.get("TYPE2_DWELL_S", "3"))
    assert 1 <= cycles <= 50
    assert dwell >= 0

    # Prime the initial location before capture: only capture experiment traffic.
    for attempt in range(40):
        generate_learning(tgen, "eth0")
        if observer_location(tgen) == "leaf1":
            break
        time.sleep(0.5)
    else:
        pytest.fail("Baseline: Leaf4 never learned host11 at leaf1")

    recorder = CaptureSession(tgen)
    recorder.start()
    try:
        recorder.event("BASELINE_READY", location="leaf1", cycles=cycles)
        recorder.snapshot("before_first_move")
        time.sleep(2)
        current = "leaf1"
        number = 0
        # One cycle: leaf1 -> leaf2 -> leaf3 -> leaf2 -> leaf1 (4 moves).
        for cycle in range(1, cycles + 1):
            for target in ("leaf2", "leaf3", "leaf2", "leaf1"):
                number += 1
                move_once(tgen, recorder, current, target, number)
                current = target
                time.sleep(dwell)
        recorder.event("EXPERIMENT_COMPLETE", moves=number,
                       final_location=current)
        time.sleep(2)
    finally:
        recorder.stop()
