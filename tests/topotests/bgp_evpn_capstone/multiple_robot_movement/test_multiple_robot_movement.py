"""Eight coordinated break-before-make batches on the capstone fabric."""

import json
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bgp_evpn_capstone import test_evpn_capstone as lab
from bgp_evpn_capstone.multiple_robot_movement import analyze_movement
from bgp_evpn_capstone.single_movement.robot_roaming.test_robot_roaming import (
    start_tshark,
)

setup_module = lab.setup_module
teardown_module = lab.teardown_module

MOVING_LEAVES = ("leaf1", "leaf2", "leaf3")
OBSERVER = "leaf4"
SPINES = ("spine1", "spine2")
NODES = (*MOVING_LEAVES, OBSERVER, "leaf5", *SPINES)
VNI = 1000
BREAK_S = 0.05
DWELL_S = 2.0
ROBOTS = {
    host: {"home": leaf, "ip": cidr.split("/")[0], "mac": mac}
    for leaf in MOVING_LEAVES
    for host, (cidr, mac) in lab.LEAVES[leaf]["hosts"].items()
}
# A -> B -> C -> B -> A, offset by each robot's home leaf.
CYCLE_OFFSETS = (1, 2, 1, 0)

ARP_REQUEST = """
import sys
from scapy.all import ARP, Ether, srp1

mac, ip = sys.argv[1:]
reply = srp1(
    Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    / ARP(op=1, hwsrc=mac, psrc=ip, pdst="45.0.0.1"),
    iface="eth0", timeout=3, verbose=False,
)
if reply is None:
    sys.exit("No gateway reply to the learning ARP")
"""


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def learn(topology, host):
    robot = ROBOTS[host]
    topology.net[host].cmd_raises(
        ["python3", "-c", ARP_REQUEST, robot["mac"], robot["ip"]], timeout=15
    )


def run_learning(topology, move):
    move["learn_start"] = time.time()
    try:
        learn(topology, move["robot"])
        move["learning_ok"] = True
    except Exception as exc:
        move["learning_ok"] = False
        move["learning_error"] = str(exc)
    finally:
        move["learn_end"] = time.time()


def move_robot(topology, move, start, links_lock):
    """Move the leaf-facing veth, keeping Munet's cleanup metadata current."""
    host = move["robot"]
    src, dst = move["old_leaf"], move["new_leaf"]
    old, new = topology.net[src], topology.net[dst]
    port = f"eth-{host}"
    links = topology.net.links
    old_key = f"{host}:eth0-{src}:{port}"
    new_key = f"{host}:eth0-{dst}:{port}"

    try:
        start.wait(timeout=10)
        move["started"] = time.time()
        old.cmd_raises(["ip", "link", "set", port, "nomaster"], timeout=5)
        move["detached"] = time.time()
        move["actual_leaf"] = None
        time.sleep(BREAK_S)
        old.cmd_raises(
            ["ip", "link", "set", port, "netns", str(new.pids[-1])], timeout=5
        )
        with links_lock:
            links.pop(old_key, None)
            links[new_key] = (host, "eth0", dst, port)
        new.cmd_raises(["ip", "link", "set", port, "master", "br1000"], timeout=5)
        new.cmd_raises(["ip", "link", "set", port, "up"], timeout=5)
        attached = json.loads(
            new.cmd_raises(["ip", "-j", "link", "show", "master", "br1000"], timeout=5)
        )
        if not any(p["ifname"] == port and "UP" in p["flags"] for p in attached):
            raise RuntimeError(f"{port} is not up on {dst}/br1000")
        move.update(actual_leaf=dst, status="completed", attached=time.time())
    except Exception as exc:
        move.update(status="failed", error=str(exc))


def snapshot(topology):
    views = {}
    for name in NODES:
        router = topology.gears[name]
        started = time.time()
        routes = router.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)
        peers = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
        views[name] = {
            "sample_start": started,
            "num_routes": routes.get("numPrefix"),
            "peers": peers.get("peers"),
        }
        if name in (*MOVING_LEAVES, OBSERVER):
            mac = router.vtysh_cmd(f"show evpn mac vni {VNI} json", isjson=True)
            entries = mac.get("macs", mac)
            views[name]["macs"] = {
                info["mac"]: entries.get(info["mac"]) for info in ROBOTS.values()
            }
            views[name]["duplicates"] = router.vtysh_cmd(
                f"show evpn mac vni {VNI} duplicate json", isjson=True
            )
        views[name]["sample_end"] = time.time()
    return views


def peer_addresses(topology):
    """Map each spine's incoming TCP endpoint to its connected leaf."""
    addresses = {}
    for spine in SPINES:
        addresses[spine] = {}
        for leaf in (*MOVING_LEAVES, OBSERVER, "leaf5"):
            links = json.loads(topology.net[leaf].cmd_raises(
                ["ip", "-j", "-6", "addr", "show", "dev", f"eth-{spine}", "scope", "link"]
            ))
            for link in links:
                for addr in link["addr_info"]:
                    addresses[spine][addr["local"]] = leaf
    return addresses


def copy_router_logs(topology, dest):
    dest.mkdir(exist_ok=True)
    for name in NODES:
        source = Path(topology.logdir) / name
        for daemon in ("zebra", "bgpd"):
            log = source / f"{daemon}.log"
            if log.is_file():
                shutil.copyfile(log, dest / f"{name}-{daemon}.log")


def test_multiple_robot_movement():
    topology = lab.get_topogen()
    if topology.routers_have_failure():
        pytest.skip(topology.errors)
    lab.test_bgp_underlay_established()
    lab.test_evpn_sessions_established()
    lab.test_evpn_vnis_present()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    out = Path(__file__).parent / "captures" / stamp
    out.mkdir(parents=True)
    vteps = {name: lab.LEAVES[name]["lo"] for name in MOVING_LEAVES}
    locations = {host: robot["home"] for host, robot in ROBOTS.items()}
    disabled, batches, captures = set(), [], {}
    plan = [{
        "batch": index + 1,
        "cycle": index // len(CYCLE_OFFSETS) + 1,
        "moves": [
            {"robot": host, "new_leaf": MOVING_LEAVES[
                (MOVING_LEAVES.index(robot["home"]) + offset) % len(MOVING_LEAVES)
            ]}
            for host, robot in ROBOTS.items()
        ],
    } for index, offset in enumerate(CYCLE_OFFSETS * 4)]
    run = {
        "robots": ROBOTS, "vteps": vteps, "observer": OBSERVER, "break_s": BREAK_S,
        "dwell_after_learning_s": DWELL_S, "spine_peers": peer_addresses(topology),
        "plan": plan, "batches": batches, "dad_settings": {},
    }
    save_json(out / "movement.json", run)
    print(f"\nMultiple robot movement results: {out}", flush=True)

    try:
        for spine in SPINES:
            captures[spine] = start_tshark(
                topology.net[spine], out / f"{spine}-bgp.pcap",
                out / f"{spine}-capture.log", "tcp port 179",
            )
            (out / f"{spine}-interfaces.txt").write_text(
                topology.net[spine].cmd_raises("ip -o link show")
            )
        for leaf in (*MOVING_LEAVES, OBSERVER):
            run["dad_settings"][leaf] = topology.gears[leaf].vtysh_cmd(
                "show evpn json", isjson=True
            )
        for host in ROBOTS:
            learn(topology, host)
            wait_for_baseline(topology, ROBOTS[host]["mac"], vteps[locations[host]])

        run["before"] = snapshot(topology)
        links_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=len(ROBOTS)) as workers:
            for planned in plan:
                moves = []
                batch = dict(batch=planned["batch"], cycle=planned["cycle"], moves=moves)
                batches.append(batch)
                for step in planned["moves"]:
                    host = step["robot"]
                    moves.append(dict(
                        step, old_leaf=locations[host], actual_leaf=locations[host],
                        status="skipped" if host in disabled else "pending",
                    ))
                active = [move for move in moves if move["status"] == "pending"]
                batch["start"] = time.time()
                if active:
                    barrier = threading.Barrier(len(active))
                    jobs = [workers.submit(move_robot, topology, move, barrier, links_lock)
                            for move in active]
                    for job in jobs:
                        job.result()
                completed = []
                for move in active:
                    host = move["robot"]
                    locations[host] = move["actual_leaf"]
                    if move["status"] == "completed":
                        completed.append(move)
                    else:
                        disabled.add(host)
                jobs = [workers.submit(run_learning, topology, move) for move in completed]
                for job in jobs:
                    job.result()
                time.sleep(DWELL_S)
                batch["state"] = snapshot(topology)
                batch["end"] = time.time()
                save_json(out / "movement.json", run)
                print(f"Batch {batch['batch']}: {len(completed)}/{len(moves)} attachments completed",
                      flush=True)
        time.sleep(DWELL_S)
        run["after"] = snapshot(topology)
    finally:
        for capture in captures.values():
            capture.stop()
        run["capture_returncodes"] = {name: cap.returncode for name, cap in captures.items()}
        save_json(out / "movement.json", run)
        copy_router_logs(topology, out / "router_logs")

    summary = analyze_movement.analyze(out)
    print(f"Summary: {out / 'analysis' / 'summary.json'}")
    assert summary["moves_completed"] == 96, "See movement.json for failed attachments"
    assert set(run["capture_returncodes"].values()) == {0}, "Check capture logs"
    assert not summary["capture_errors"], "Check analysis/summary.json for decode errors"
    # Protocol mismatches are findings and are reported separately from harness failures.


def wait_for_baseline(topology, mac, vtep):
    """Verify that leaf4 starts from the expected remote mapping."""
    observer = topology.gears[OBSERVER]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        data = observer.vtysh_cmd(f"show evpn mac vni {VNI} json", isjson=True)
        entry = data.get("macs", data).get(mac, {})
        if entry.get("type") == "remote" and entry.get("remoteVtep") == vtep:
            return
        time.sleep(0.1)
    pytest.fail(f"{OBSERVER} did not learn baseline MAC {mac} through {vtep}")
