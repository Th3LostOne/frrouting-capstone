"""One host move with continuous ICMP traffic and a controller-side capture."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

import pytest
from bgp_evpn_capstone import test_evpn_capstone as lab

setup_module = lab.setup_module
teardown_module = lab.teardown_module
pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def wait_for_ping(node, address):
    success, _ = lab.topotest.run_and_expect(
        lambda: "1 received" in node.cmd(f"ping -n -c 1 -W 1 {address}"),
        True, count=30, wait=0.5,
    )
    assert success, f"Initial connectivity failed: {address}"


def stop_process(process):
    if process and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def save_routes(topology, directory, label):
    state = {}
    for leaf in ("leaf1", "leaf2", "leaf5"):
        router = topology.gears[leaf]
        state[leaf] = {
            "mac_table": router.vtysh_cmd("show evpn mac vni 1000 json", isjson=True),
            "type2_routes": router.vtysh_cmd("show bgp l2vpn evpn route type macip json", isjson=True),
        }
    (directory / f"routes-{label}.json").write_text(json.dumps(state, indent=2))


def capture_metrics(directory, report):
    """Match echo requests/replies by identifier and sequence at the controller."""
    result = subprocess.run([
        "tshark", "-r", str(directory / "controller.pcapng"),
        "-Y", "icmp.type == 8 || icmp.type == 0", "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "icmp.type", "-e", "icmp.ident", "-e", "icmp.seq",
    ], capture_output=True, text=True, check=True)
    requests, replies = {}, {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            continue
        stamp, src, dst, kind, ident, seq = fields
        key = (ident, seq)
        if kind == "8" and src == "20.0.0.51" and dst == "45.0.0.11":
            requests.setdefault(key, float(stamp))
        elif kind == "0" and src == "45.0.0.11" and dst == "20.0.0.51":
            replies.setdefault(key, float(stamp))
    samples = [dict(identifier=k[0], sequence=int(k[1]), sent_unix=t,
                    reply_unix=replies.get(k),
                    rtt_ms=round((replies[k] - t) * 1000, 3) if k in replies else None)
               for k, t in sorted(requests.items(), key=lambda item: item[1])]
    (directory / "probes.json").write_text(json.dumps(samples, indent=2))
    matched = sum(s["reply_unix"] is not None for s in samples)
    report["traffic"] = dict(captured_requests=len(samples), matched_replies=matched,
                             unmatched_requests=len(samples) - matched,
                             loss_percent=round(100 * (len(samples) - matched) / len(samples), 3) if samples else None)
    attached = report.get("attached_unix")
    if attached is not None:
        # Exclude replies to probes transmitted before the new attachment existed.
        after = [s for s in samples if s["sent_unix"] >= attached]
        for index in range(len(after) - 2):
            group = after[index:index + 3]
            consecutive = (len({s["identifier"] for s in group}) == 1
                           and group[1]["sequence"] == group[0]["sequence"] + 1
                           and group[2]["sequence"] == group[1]["sequence"] + 1)
            if consecutive and all(s["reply_unix"] is not None for s in group):
                report["first_of_three_successful_replies_after_attachment_ms"] = round(
                    (group[0]["reply_unix"] - attached) * 1000, 3)
                report["three_reply_confirmation_from_move_start_ms"] = round(
                    (max(s["reply_unix"] for s in group) - report["move_start_unix"]) * 1000, 3)
                break
    if "move_start_unix" in report:
        start = report["move_start_unix"]
        end_ms = report.get("three_reply_confirmation_from_move_start_ms")
        end = start + end_ms / 1000 if end_ms is not None else float("inf")
        for name, subset in (
            ("before_move", [s for s in samples if s["sent_unix"] < start]),
            ("move_to_recovery_confirmation", [s for s in samples if start <= s["sent_unix"] <= end]),
            ("after_recovery_confirmation", [s for s in samples if s["sent_unix"] > end]),
        ):
            lost = sum(s["reply_unix"] is None for s in subset)
            report[name] = dict(requests=len(subset), unmatched_requests=lost,
                               loss_percent=round(100 * lost / len(subset), 3) if subset else None)
    # Tshark reports capture-drop statistics here when available; retain the log.
    report["measurement_note"] = (
        "100 ms sampled ICMP observations at controller eth0. Unmatched requests "
        "must be interpreted alongside capture.log and ping.log. Recovery values "
        "include learning/probe timing and are not exact EVPN convergence times. "
        "Gateway ping is an explicit learning stimulus. Route snapshots are untimed "
        "before/after observations, not route-churn or control-plane-delay measurements."
    )


def test_measured_robot_move():
    topology = lab.get_topogen()
    robot, controller = topology.net["host11"], topology.net["controller"]
    leaf1, leaf2 = topology.net["leaf1"], topology.net["leaf2"]
    directory = Path(lab.CWD) / "results" / (time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}")
    directory.mkdir(parents=True)
    revision = subprocess.check_output(["git", "-C", lab.CWD, "rev-parse", "HEAD"], text=True).strip()
    report = dict(robot="host11", ip="45.0.0.11", mac="00:00:00:00:00:11",
                  source="leaf1", destination="leaf2", source_revision=revision,
                  working_tree_diff=subprocess.check_output(["git", "-C", lab.CWD, "diff", "--", "."], text=True),
                  probe_interval_seconds=0.1, validation_passed=False)
    # Preserve the experiment source because a Git commit may not include it yet.
    (directory / "experiment-source.py").write_text(Path(__file__).read_text())
    capture = traffic = None
    capture_log = ping_log = None
    try:
        wait_for_ping(robot, "45.0.0.1")
        wait_for_ping(controller, "45.0.0.11")
        wait_for_ping(robot, "20.0.0.51")
        save_routes(topology, directory, "before")

        capture_log = open(directory / "capture.log", "w")
        capture = controller.popen([
            "tshark", "-n", "-i", "eth0", "-f", "icmp",
            "-w", str(directory / "controller.pcapng"),
        ], stdout=capture_log, stderr=subprocess.STDOUT)
        for _ in range(50):
            assert capture.poll() is None, "Capture exited; inspect capture.log"
            if "Capturing on" in (directory / "capture.log").read_text():
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Capture did not become ready; inspect capture.log")

        ping_log = open(directory / "ping.log", "w")
        traffic = controller.popen([
            "stdbuf", "-oL", "ping", "-n", "-D", "-O", "-i", "0.1", "-W", "1", "45.0.0.11",
        ], stdout=ping_log, stderr=subprocess.STDOUT)
        time.sleep(3)
        replies = re.findall(r"^\[([\d.]+)\] \d+ bytes from", (directory / "ping.log").read_text(), re.M)
        assert len(replies) >= 3, "Continuous baseline traffic is not working"
        assert traffic.poll() is None, "Traffic generator exited"

        report["move_start_unix"] = time.time()
        move_start = time.monotonic()
        leaf1.cmd_raises("ip link set eth-host11 nomaster")
        leaf1.cmd_raises(f"ip link set eth-host11 netns {leaf2.pids[-1]}")
        # Update the registered link immediately so teardown uses the correct leaf.
        topology.net.links["host11:eth0-leaf2:eth-host11"] = ("host11", "eth0", "leaf2", "eth-host11")
        del topology.net.links["host11:eth0-leaf1:eth-host11"]
        leaf2.cmd_raises("ip link set eth-host11 master br1000")
        leaf2.cmd_raises("ip link set eth-host11 up")
        report["attached_unix"] = time.time()
        report["attachment_change_ms"] = round((time.monotonic() - move_start) * 1000, 3)
        report["learning_trigger_unix"] = time.time()
        robot.cmd("ping -n -c 1 -W 1 45.0.0.1")
        lab._viz_post({"action": "DEL_LINK", "source": "leaf1", "target": "host11"})
        lab._viz_post({"action": "ADD_LINK", "source": "leaf2", "target": "host11"})

        for _ in range(60):
            table = topology.gears["leaf2"].vtysh_cmd("show evpn mac vni 1000 json", isjson=True)
            local = table.get("macs", table).get(report["mac"], {}).get("type", "").lower() == "local"
            replies = re.findall(r"^\[([\d.]+)\] \d+ bytes from", (directory / "ping.log").read_text(), re.M)
            if local and sum(float(t) >= report["attached_unix"] for t in replies) >= 3:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("No local MAC learning and traffic recovery within polling window")
        wait_for_ping(robot, "20.0.0.51")
        identity = json.loads(robot.cmd_raises("ip -j addr show dev eth0"))[0]
        assert identity["address"] == report["mac"]
        assert any(a.get("local") == report["ip"] for a in identity["addr_info"])
        save_routes(topology, directory, "after")
        report["validation_passed"] = True
        time.sleep(3)
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        stop_process(traffic)
        # Allow in-flight replies to reach the controller before closing capture.
        time.sleep(1)
        stop_process(capture)
        for handle in (capture_log, ping_log):
            if handle:
                handle.close()
        if (directory / "controller.pcapng").exists():
            try:
                capture_metrics(directory, report)
            except Exception as error:
                report["analysis_error"] = str(error)
        (directory / "summary.json").write_text(json.dumps(report, indent=2))
        print(f"\nMEASURED MOVE RESULTS: {directory}", flush=True)
    assert report["traffic"]["captured_requests"] > 0
    assert "first_of_three_successful_replies_after_attachment_ms" in report, "Capture did not verify sustained post-attachment delivery"
