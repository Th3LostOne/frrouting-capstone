"""Capture leaf1 + leaf2 traffic around the single host11 move; run with pytest -s.

Same process as capture_single_robot_movement.py, but recorded on the two leaves
involved in the move instead of spine1, so you can see what a leaf does:

  * leaf1.pcap / leaf2.pcap   - tshark "-i any" on each leaf: BGP (tcp/179),
                                VXLAN (udp/4789), ARP, ICMP and ICMPv6, on the
                                access ports, the bridge/VXLAN devices and the
                                spine uplinks (Linux cooked v2 keeps the ifindex)
  * <leaf>-links-*.txt        - "ip -o link" so the analyzer can turn ifindex
                                into interface names (eth-host11 changes leaf)
  * <leaf>-fdb.jsonl          - "bridge monitor fdb", one line per kernel FDB
                                change, stamped with time.time()
  * <leaf>-neigh.jsonl        - "ip monitor neigh" (ARP table changes)
  * mac_state.jsonl           - FRR's view of host11 on each leaf, polled from
                                move_call_start (local / remote via which VTEP,
                                MAC mobility sequence numbers)
  * probe-<host>.log          - "ping -D" from host12 (stays on leaf1) and
                                host21 (stays on leaf2) to host11, so you can
                                see bridged traffic switch between local
                                switching and the VXLAN tunnel; set
                                CAPTURE_PROBES=0 to keep the move as quiet as
                                the spine1 capture
  * snapshots/<leaf>-<phase>.txt - FDB, ARP, EVPN MAC/ARP tables, Type-2 routes
                                and VRF500 routes before and after the move
  * events.json               - same format as the spine1 capture, plus extra
                                events (learn_host_start/end, probes)

All timestamps share one clock (one host kernel), so the files line up with
each other and with events.json.
Analyse with:  python3 analyze_leaf_traffic.py captures/<stamp>-leaves --plot
"""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Make "bgp_evpn_capstone" (and topotests' "lib") importable no matter how this
# file is started - same trick test_evpn_capstone.py / mobility_moves.py use.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from bgp_evpn_capstone import single_robot_movement as movement  # noqa: E402
from bgp_evpn_capstone import capture_single_robot_movement as single  # noqa: E402

lab = movement.lab
setup_module = lab.setup_module
teardown_module = lab.teardown_module

MAC = single.MAC                    # 00:00:00:00:00:11 (host11, the robot)
ROBOT_IP = "45.0.0.11"
LEAVES = ("leaf1", "leaf2")
OLD_VTEP, NEW_VTEP = "10.0.0.1", "10.0.0.2"

# Hosts that stay put and ping the robot during the move.
#   host12 sits on leaf1: before the move leaf1 switches it locally, after the
#   move the same ping has to cross the VXLAN tunnel to leaf2 (and the reverse
#   for host21 on leaf2).
PROBES = {"host12": ROBOT_IP, "host21": ROBOT_IP}
PROBE_INTERVAL = os.environ.get("CAPTURE_PROBE_INTERVAL", "0.05")   # 20 pings/s
ENABLE_PROBES = os.environ.get("CAPTURE_PROBES", "1") != "0"

CAPTURE_FILTER = "tcp port 179 or udp port 4789 or arp or icmp or icmp6"
POLL_INTERVAL = 0.05                # FRR MAC-state polling (each vtysh call adds ~10-50 ms)

SNAPSHOT_CMDS = [
    ("ip -o link show", "shell"),
    ("bridge fdb show br br1000", "shell"),
    ("ip neigh show", "shell"),
    ("show evpn mac vni 1000", "vtysh"),
    ("show evpn arp-cache vni 1000", "vtysh"),
    ("show bgp l2vpn evpn route type macip", "vtysh"),
    ("show ip route vrf VRF500", "vtysh"),
]


# ------------------------------------------------------------- helpers ---
class Running:
    """A started process plus the files it writes to (closed after it stops)."""

    def __init__(self, proc, files=(), linktype=None):
        self.proc, self.files, self.linktype = proc, files, linktype

    def stop(self):
        stop_process(self.proc)
        for fh in self.files:
            if not fh.closed:
                fh.close()

    @property
    def returncode(self):
        return self.proc.returncode


def start_capture(node, pcap_path, log_path):
    """tshark -i any on one node, Linux cooked v2 if available (keeps ifindex).

    The output file is opened here so tshark's privilege drop cannot block the
    shared folder (same trick as the spine1 capture).
    """
    base = ["tshark", "-n", "-i", "any", "-f", CAPTURE_FILTER, "-F", "pcap", "-w", "-"]
    for linktype in (["-y", "LINUX_SLL2"], []):
        packets = open(pcap_path, "wb")
        log = open(log_path, "a")
        proc = node.popen(base[:4] + linktype + base[4:], stdout=packets, stderr=log)
        time.sleep(1)
        if proc.poll() is None:
            return Running(proc, (packets, log), linktype[1] if linktype else "LINUX_SLL")
        packets.close()
        log.close()
    raise AssertionError("tshark failed on {}; read {}".format(node.name, log_path))


class LineMonitor:
    """Run a monitor command in a node and stamp every output line with time.time()."""

    def __init__(self, node, cmd, out_path):
        self.out = open(out_path, "w")
        # stdbuf -oL: make iproute2 flush each line so our timestamps are tight.
        self.proc = node.popen(["stdbuf", "-oL"] + cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, universal_newlines=True)
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self):
        for line in self.proc.stdout:
            self.out.write(json.dumps({"unix_time": time.time(), "line": line.rstrip("\n")}) + "\n")
            self.out.flush()

    def stop(self):
        stop_process(self.proc)
        self.thread.join(timeout=2)
        self.out.close()


def stop_process(proc, sig=signal.SIGINT):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(sig)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def start_probe(node, target, out_path):
    """ping -D (unix timestamps) -O (report missing replies) at a fixed interval."""
    out = open(out_path, "w")
    proc = node.popen(["ping", "-D", "-O", "-n", "-i", PROBE_INTERVAL, "-W", "1", target],
                      stdout=out, stderr=subprocess.STDOUT)
    return Running(proc, (out,))


def snapshot(topology, leaf, phase, folder):
    folder.mkdir(exist_ok=True)
    node, router = topology.net[leaf], topology.gears[leaf]
    with (folder / "{}-{}.txt".format(leaf, phase)).open("w") as fh:
        fh.write("# {} {} unix_time={}\n".format(leaf, phase, time.time()))
        for cmd, kind in SNAPSHOT_CMDS:
            fh.write("\n### {}\n".format(cmd))
            try:
                fh.write(router.vtysh_cmd(cmd) if kind == "vtysh" else node.cmd(cmd))
            except Exception as exc:  # pylint: disable=broad-except
                fh.write("<failed: {}>\n".format(exc))


def save_links(topology, output, phase):
    for leaf in LEAVES:
        (output / "{}-links-{}.txt".format(leaf, phase)).write_text(
            topology.net[leaf].cmd("ip -o link show"))


def mac_state(router):
    """Reduce FRR's MAC entry for host11 to the fields that change on a move."""
    data = router.vtysh_cmd("show evpn mac vni 1000 json", isjson=True)
    entry = data.get("macs", data).get(MAC, {})
    keep = ("type", "intf", "remoteVtep", "localSequence", "remoteSequence")
    return {k: entry.get(k) for k in keep if k in entry} or {"type": "absent"}


class MacStatePoller(threading.Thread):
    """Record every change in FRR's view of host11 on leaf1 and leaf2."""

    def __init__(self, topology, out_path):
        super().__init__(daemon=True)
        self.topology = topology
        self.out = open(out_path, "w")
        self.stop_event = threading.Event()
        self.last = {}

    def run(self):
        while not self.stop_event.is_set():
            for leaf in LEAVES:
                try:
                    state = mac_state(self.topology.gears[leaf])
                except Exception as exc:  # pylint: disable=broad-except
                    state = {"error": str(exc)}
                if state != self.last.get(leaf):
                    self.last[leaf] = state
                    self.out.write(json.dumps({"unix_time": time.time(), "leaf": leaf,
                                               "state": state}) + "\n")
                    self.out.flush()
            self.stop_event.wait(POLL_INTERVAL)

    def stop(self):
        self.stop_event.set()
        self.join(timeout=5)
        self.out.close()


# ---------------------------------------------------------------- test ---
def test_capture_leaf_traffic():
    topology = lab.get_topogen()
    lab.test_bgp_underlay_established()
    lab.test_evpn_sessions_established()
    lab.test_evpn_vnis_present()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    output = Path(__file__).parent / "captures" / "{}-leaves".format(stamp)
    output.mkdir(parents=True)
    events = []
    captures, monitors, probes = {}, [], {}
    poller = None

    def event(name, **extra):
        events.append(dict({"event": name, "unix_time": time.time()}, **extra))

    try:
        save_links(topology, output, "start")
        for leaf in LEAVES:
            captures[leaf] = start_capture(topology.net[leaf], output / "{}.pcap".format(leaf),
                                           output / "{}-capture.log".format(leaf))
            monitors.append(LineMonitor(topology.net[leaf], ["bridge", "monitor", "fdb"],
                                        output / "{}-fdb.jsonl".format(leaf)))
            monitors.append(LineMonitor(topology.net[leaf], ["ip", "monitor", "neigh"],
                                        output / "{}-neigh.jsonl".format(leaf)))
        event("capture_started", linktype={l: c.linktype for l, c in captures.items()})

        # Same baseline as the spine1 capture: host11 is learned on leaf1.
        single.learn_host(topology)
        single.wait_for_remote_mac(topology, "leaf2", OLD_VTEP)
        event("baseline_learned")
        for leaf in LEAVES:
            snapshot(topology, leaf, "before", output / "snapshots")

        if ENABLE_PROBES:
            for host, target in PROBES.items():
                probes[host] = start_probe(topology.net[host], target,
                                           output / "probe-{}.log".format(host))
            event("probes_started", probes=PROBES, interval_s=float(PROBE_INTERVAL))
        time.sleep(2)                       # steady state before the move

        poller = MacStatePoller(topology, output / "mac_state.jsonl")
        poller.start()

        event("move_call_start")
        movement.test_move()
        event("move_call_end")

        event("learn_host_start")           # scapy start-up time lands between these two
        single.learn_host(topology)
        event("learn_host_end")

        single.wait_for_remote_mac(topology, "leaf1", NEW_VTEP)
        event("new_location_observed")
        time.sleep(3)                       # steady state after the move

        for probe in probes.values():
            probe.stop()
        event("probes_stopped")
        for leaf in LEAVES:
            snapshot(topology, leaf, "after", output / "snapshots")
        save_links(topology, output, "end")
    finally:
        if poller is not None:
            poller.stop()
        for probe in probes.values():
            probe.stop()                    # no-op if already stopped
        for mon in monitors:
            mon.stop()
        for cap in captures.values():
            cap.stop()
        (output / "events.json").write_text(json.dumps(events, indent=2) + "\n")
        print("\nLeaf captures: {}".format(output))

    for leaf, cap in captures.items():
        assert cap.returncode == 0, "Capture on {} exited with an error; read {}/{}-capture.log".format(
            leaf, output, leaf)


if __name__ == "__main__":
    # "python3 capture_leaf_traffic.py" = "pytest -s capture_leaf_traffic.py"
    import pytest
    sys.exit(pytest.main(["-s", os.path.realpath(__file__)] + sys.argv[1:]))