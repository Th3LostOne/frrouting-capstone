"""Controlled dual-attachment MBB handoffs for six robots on the capstone fabric."""

import importlib.util
import json
import math
import os
from pathlib import Path
import select
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

CWD = Path(__file__).resolve().parent
# Support pytest and direct execution from the requested folder with spaces.
sys.path.insert(0, str(CWD))
sys.path.insert(0, str(CWD.parent.parent))

import analyze_mbb
# Load shared BBM helpers from the renamed experiment folder.
_bbm_spec = importlib.util.spec_from_file_location(
    "mbb_bbm_helpers",
    CWD.parent / "multiple_robot_movement - BBM" / "test_multiple_robot_movement.py",
)
bbm = importlib.util.module_from_spec(_bbm_spec)
_bbm_spec.loader.exec_module(bbm)
from bgp_evpn_capstone.resource_monitor import ResourceMonitor
from bgp_evpn_capstone.single_movement.capture_leaf_traffic import LineMonitor
from bgp_evpn_capstone.single_movement.robot_roaming.test_robot_roaming import start_tshark

lab = bbm.lab
setup_module = lab.setup_module
teardown_module = lab.teardown_module

CYCLES = int(os.environ.get("MBB_CYCLES", "4"))
OVERLAP_S = float(os.environ.get("MBB_OVERLAP_S", "0.5"))
DWELL_S = float(os.environ.get("MBB_DWELL_S", "2.0"))
POLL_S = 0.1


def configure_robot(topology, host):
    """One bond owns the robot identity, with one access cable to each moving leaf."""
    robot = bbm.ROBOTS[host]
    node = topology.net[host]
    leaves = [robot["home"], *[leaf for leaf in bbm.MOVING_LEAVES if leaf != robot["home"]]]
    interfaces = {leaf: f"eth{index}" for index, leaf in enumerate(leaves)}
    node.cmd_raises(["ip", "route", "del", "default"])
    node.cmd_raises(["ip", "addr", "flush", "dev", "eth0"])
    node.cmd_raises(["ip", "link", "set", "eth0", "down"])
    node.cmd_raises([
        "ip", "link", "add", "bond0", "type", "bond", "mode", "active-backup",
        "miimon", "100", "num_grat_arp", "0", "all_slaves_active", "1",
    ])
    node.cmd_raises(["ip", "link", "set", "bond0", "address", robot["mac"]])
    for leaf, interface in interfaces.items():
        if interface != "eth0":
            topology.net.add_link(host, leaf, interface, f"eth-{host}")
            node.cmd_raises(["ip", "link", "set", interface, "down"])
            topology.net[leaf].cmd_raises(["ip", "link", "set", f"eth-{host}", "down"])
        node.cmd_raises(["ip", "link", "set", interface, "master", "bond0"])
    node.cmd_raises(["ip", "link", "set", "eth0", "up"])
    node.cmd_raises(["ip", "link", "set", "bond0", "up"])
    node.cmd_raises(["ip", "addr", "add", f"{robot['ip']}/24", "dev", "bond0"])
    node.cmd_raises(["ip", "route", "add", "default", "via", "45.0.0.1", "dev", "bond0"])
    return interfaces


class RobotAgent:
    """A single persistent ARP sender per robot, used by one worker at a time."""

    def __init__(self, node, robot, log_path):
        self.log = log_path.open("w")
        self.proc = node.popen(
            ["python3", "-u", str(CWD / "robot_agent.py"), robot["mac"], robot["ip"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True,
        )
        try:
            if not self.read()["ready"]:
                raise RuntimeError("Robot ARP sender did not become ready")
        except Exception:
            self.stop()
            raise

    def read(self):
        ready, _, _ = select.select([self.proc.stdout], [], [], 15)
        if not ready:
            raise TimeoutError("Robot ARP sender did not respond")
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("Robot ARP sender exited")
        return json.loads(line)

    def announce(self):
        self.proc.stdin.write("send\n")
        self.proc.stdin.flush()
        result = self.read()
        if not result["sent"]:
            raise RuntimeError(result["error"])
        return result

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for stream in (self.proc.stdin, self.proc.stdout, self.log):
            if stream is not None:
                stream.close()


class Observer(threading.Thread):
    """Save every sample of leaf4's selected MAC mappings, including failures."""

    def __init__(self, router, path):
        super().__init__(daemon=True)
        self.router = router
        self.path = path
        self.finished = threading.Event()

    def run(self):
        with self.path.open("w") as file:
            while not self.finished.is_set():
                row = {"sample_start": time.time()}
                try:
                    data = self.router.vtysh_cmd(
                        "show evpn mac vni 1000 json", isjson=True, raises=True
                    )
                    entries = data.get("macs", data)
                    row["macs"] = {
                        info["mac"]: entries.get(info["mac"]) for info in bbm.ROBOTS.values()
                    }
                except Exception as exc:
                    row["error"] = str(exc)
                row["sample_end"] = time.time()
                file.write(json.dumps(row) + "\n")
                file.flush()
                self.finished.wait(POLL_S)

    def stop(self):
        self.finished.set()
        self.join(timeout=15)
        if self.is_alive():
            raise RuntimeError("Observer did not stop")


def check_port(node, interface, master=None):
    """Verify administrative and carrier state, plus the bridge when supplied."""
    data = json.loads(node.cmd_raises(["ip", "-j", "link", "show", "dev", interface]))[0]
    if not {"UP", "LOWER_UP"}.issubset(data["flags"]):
        raise RuntimeError(f"{node.name}/{interface} is not ready")
    if master:
        ports = json.loads(node.cmd_raises(["ip", "-j", "link", "show", "master", master]))
        if not any(port["ifname"] == interface for port in ports):
            raise RuntimeError(f"{node.name}/{interface} is not on {master}")


def handoff(topology, move, interfaces, agent, barrier):
    host = move["robot"]
    node = topology.net[host]
    old, new = topology.net[move["old_leaf"]], topology.net[move["new_leaf"]]
    old_if, new_if = interfaces[move["old_leaf"]], interfaces[move["new_leaf"]]
    port = f"eth-{host}"
    switched = False
    try:
        barrier.wait(timeout=10)
        move["started"] = time.time()
        new.cmd_raises(["ip", "link", "set", port, "master", "br1000"])
        new.cmd_raises(["ip", "link", "set", port, "up"])
        node.cmd_raises(["ip", "link", "set", new_if, "up"])
        # Allow one miimon interval to recognize the new slave's carrier.
        time.sleep(0.2)
        check_port(new, port, "br1000")
        check_port(old, port, "br1000")
        check_port(node, new_if)
        move["new_link_ready"] = time.time()
        node.cmd_raises(["ip", "link", "set", "bond0", "type", "bond",
                         "active_slave", new_if])
        switched = True
        move["active_switched"] = time.time()
        move["learn_start"] = time.time()
        announcement = agent.announce()
        move.update(announcement)
        move["learning_ok"] = True
        move["learn_end"] = time.time()
        # Retain the old link for this minimum hold after sending the learning ARP.
        time.sleep(OVERLAP_S)
        check_port(new, port, "br1000")
        check_port(old, port, "br1000")
        node.cmd_raises(["ip", "link", "set", old_if, "down"])
        old.cmd_raises(["ip", "link", "set", port, "down"])
        old.cmd_raises(["ip", "link", "set", port, "nomaster"])
        move["old_link_removed"] = time.time()
        move.update(status="completed", actual_leaf=move["new_leaf"])
    except Exception as exc:
        move.update(status="failed", error=str(exc))
        if "learn_start" in move and "learn_end" not in move:
            move.update(learning_ok=False, learning_error=str(exc), learn_end=time.time())
        # Restore a single old attachment and stop scheduling this robot.
        try:
            if switched:
                node.cmd_raises(["ip", "link", "set", old_if, "up"])
                old.cmd_raises(["ip", "link", "set", port, "master", "br1000"])
                old.cmd_raises(["ip", "link", "set", port, "up"])
                time.sleep(0.2)
                node.cmd_raises(["ip", "link", "set", "bond0", "type", "bond",
                                 "active_slave", old_if])
            node.cmd_raises(["ip", "link", "set", new_if, "down"])
            new.cmd_raises(["ip", "link", "set", port, "down"])
            new.cmd_raises(["ip", "link", "set", port, "nomaster"])
            move["actual_leaf"] = move["old_leaf"]
            move["rollback"] = "restored old attachment"
        except Exception as cleanup_error:
            move.update(actual_leaf=None, rollback_error=str(cleanup_error))


def save_interfaces(topology, out, run):
    run["leaf_ports"] = {}
    for leaf in bbm.MOVING_LEAVES:
        ports = json.loads(topology.net[leaf].cmd_raises(["ip", "-j", "link", "show"]))
        run["leaf_ports"][leaf] = {
            host: next(port["ifindex"] for port in ports if port["ifname"] == f"eth-{host}")
            for host in bbm.ROBOTS
        }
    for name in (*bbm.NODES, *bbm.ROBOTS):
        (out / f"{name}-interfaces.txt").write_text(
            topology.net[name].cmd_raises("ip -o link show")
        )


def test_mbb_multiple_movement():
    assert CYCLES > 0 and all(math.isfinite(t) and t >= 0 for t in (OVERLAP_S, DWELL_S))
    topology = lab.get_topogen()
    if topology.routers_have_failure():
        pytest.skip(topology.errors)
    lab.test_bgp_underlay_established()
    lab.test_evpn_sessions_established()
    lab.test_evpn_vnis_present()

    out = CWD / "captures" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    out.mkdir(parents=True)
    resource_monitor = ResourceMonitor(topology, out)
    plan = [{
        "batch": index + 1, "cycle": index // len(bbm.CYCLE_OFFSETS) + 1,
        "moves": [
            {"robot": host, "new_leaf": bbm.MOVING_LEAVES[
                (bbm.MOVING_LEAVES.index(info["home"]) + offset) % len(bbm.MOVING_LEAVES)
            ]} for host, info in bbm.ROBOTS.items()
        ],
    } for index, offset in enumerate(bbm.CYCLE_OFFSETS * CYCLES)]
    run = {
        "mode": "MBB", "robots": bbm.ROBOTS, "observer": bbm.OBSERVER,
        "vteps": {leaf: lab.LEAVES[leaf]["lo"] for leaf in bbm.MOVING_LEAVES},
        "plan": plan, "batches": [], "dad_settings": {}, "interfaces": {},
        "hold_after_arp_s": OVERLAP_S, "dwell_after_handoff_s": DWELL_S,
        "observer_interval_s": POLL_S, "spine_peers": bbm.peer_addresses(topology),
    }
    agents, captures, monitors = {}, {}, []
    observer = None
    where = {host: info["home"] for host, info in bbm.ROBOTS.items()}
    disabled = set()
    bbm.save_json(out / "movement.json", run)
    print(f"\nMBB results: {out}", flush=True)
    try:
        resource_monitor.start()
        for host, robot in bbm.ROBOTS.items():
            run["interfaces"][host] = configure_robot(topology, host)
            agents[host] = RobotAgent(
                topology.net[host], robot, out / f"{host}-agent.log"
            )
        save_interfaces(topology, out, run)
        for spine in bbm.SPINES:
            captures[spine] = start_tshark(
                topology.net[spine], out / f"{spine}-bgp.pcap",
                out / f"{spine}-capture.log", "tcp port 179",
            )
        for leaf in bbm.MOVING_LEAVES:
            captures[leaf] = start_tshark(
                topology.net[leaf], out / f"{leaf}-arp.pcap",
                out / f"{leaf}-capture.log", "arp",
            )
        # Reuse existing monitors for timestamped Linux FDB and neighbor events.
        for leaf in (*bbm.MOVING_LEAVES, bbm.OBSERVER):
            run["dad_settings"][leaf] = topology.gears[leaf].vtysh_cmd(
                "show evpn json", isjson=True
            )
            for label, command in (("fdb", ["bridge", "monitor", "fdb"]),
                                   ("neigh", ["ip", "monitor", "neigh"])):
                monitors.append(LineMonitor(
                    topology.net[leaf], command, out / f"{leaf}-{label}.jsonl"
                ))
        for host in bbm.ROBOTS:
            agents[host].announce()
            bbm.wait_for_baseline(
                topology, bbm.ROBOTS[host]["mac"], run["vteps"][where[host]]
            )
        run["before"] = bbm.snapshot(topology)
        observer = Observer(topology.gears[bbm.OBSERVER], out / "observer.jsonl")
        observer.start()
        with ThreadPoolExecutor(max_workers=len(bbm.ROBOTS)) as workers:
            for item in plan:
                batch = {"batch": item["batch"], "cycle": item["cycle"], "moves": []}
                run["batches"].append(batch)
                for step in item["moves"]:
                    host = step["robot"]
                    batch["moves"].append(dict(
                        step, old_leaf=where[host], actual_leaf=where[host],
                        status="skipped" if host in disabled else "pending",
                    ))
                batch["start"] = time.time()
                active = [m for m in batch["moves"] if m["status"] == "pending"]
                if active:
                    barrier = threading.Barrier(len(active))
                    jobs = [workers.submit(
                        handoff, topology, move, run["interfaces"][move["robot"]],
                        agents[move["robot"]], barrier,
                    ) for move in active]
                    for job in jobs:
                        job.result()
                for move in active:
                    where[move["robot"]] = move["actual_leaf"]
                    if move["status"] != "completed":
                        disabled.add(move["robot"])
                time.sleep(DWELL_S)
                batch["state"] = bbm.snapshot(topology)
                batch["end"] = time.time()
                bbm.save_json(out / "movement.json", run)
                completed = sum(m["status"] == "completed" for m in batch["moves"])
                print(f"MBB batch {batch['batch']}: {completed}/6 completed", flush=True)
        time.sleep(max(DWELL_S, 1))
        run["after"] = bbm.snapshot(topology)
    finally:
        resource_monitor.stop()
        if observer:
            observer.stop()
        for monitor in monitors:
            monitor.stop()
        for capture in captures.values():
            capture.stop()
        for agent in agents.values():
            agent.stop()
        run["capture_returncodes"] = {name: cap.returncode for name, cap in captures.items()}
        bbm.save_json(out / "movement.json", run)
        bbm.copy_router_logs(topology, out / "router_logs")
    summary = analyze_mbb.analyze(out)
    planned = sum(len(batch["moves"]) for batch in plan)
    assert summary["moves_completed"] == planned, "See movement.json for failed handoffs"
    assert all(code == 0 for code in run["capture_returncodes"].values()), "Check capture logs"
    assert not summary["capture_errors"], "Check summary.json for decode errors"
    assert summary["mbb"]["valid_overlaps"] == planned, "Some moves failed the MBB ordering checks"
    assert not summary["mbb"]["arp_capture_errors"], "Check ARP capture decoding"
    assert summary["mbb"]["new_leaf_arp_before_break"] == planned, "Check new-port ARP evidence"


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", str(Path(__file__).resolve()), *sys.argv[1:]]))
