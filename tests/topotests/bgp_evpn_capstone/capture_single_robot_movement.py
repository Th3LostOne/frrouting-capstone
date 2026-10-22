"""Capture BGP around the existing single host11 move; run with pytest -s."""

import json
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from bgp_evpn_capstone import single_robot_movement as movement

lab = movement.lab
setup_module = lab.setup_module
teardown_module = lab.teardown_module
MAC = "00:00:00:00:00:11"


def learn_host(topology):
    """One ARP request/reply with the gateway, not application test traffic."""
    topology.net["host11"].cmd_raises([
        "python3", "-c",
        "from scapy.all import ARP, Ether, srp1; "
        "reply = srp1(Ether(src='00:00:00:00:00:11', "
        "dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, "
        "hwsrc='00:00:00:00:00:11', psrc='45.0.0.11', "
        "pdst='45.0.0.1'), iface='eth0', timeout=3, verbose=False); "
        "assert reply is not None, 'Gateway did not answer the learning ARP'",
    ])


def wait_for_remote_mac(topology, leaf, vtep):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        data = topology.gears[leaf].vtysh_cmd(
            "show evpn mac vni 1000 json", isjson=True
        )
        entry = data.get("macs", data).get(MAC, {})
        if entry.get("type") == "remote" and entry.get("remoteVtep") == vtep:
            return
        time.sleep(0.2)
    raise AssertionError(f"{leaf} did not learn {MAC} through VTEP {vtep}")


def test_capture_move():
    topology = lab.get_topogen()
    lab.test_bgp_underlay_established()
    lab.test_evpn_sessions_established()
    lab.test_evpn_vnis_present()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%fZ")
    output = Path(__file__).parent / "captures" / stamp
    output.mkdir(parents=True)
    events = []
    capture = None

    # Open output here so TShark's privilege drop cannot block the shared folder.
    with (output / "spine1-bgp.pcap").open("wb") as packets, \
         (output / "capture.log").open("w") as log:
        try:
            capture = topology.net["spine1"].popen(
                ["tshark", "-n", "-i", "any", "-f", "tcp port 179",
                 "-F", "pcap", "-w", "-"],
                stdout=packets, stderr=log,
            )
            time.sleep(1)
            assert capture.poll() is None, f"Capture failed; read {output}/capture.log"

            learn_host(topology)
            wait_for_remote_mac(topology, "leaf2", "10.0.0.1")
            events.append({"event": "baseline_learned", "unix_time": time.time()})
            time.sleep(2)

            events.append({"event": "move_call_start", "unix_time": time.time()})
            movement.test_move()
            events.append({"event": "move_call_end", "unix_time": time.time()})
            learn_host(topology)

            for leaf in ("leaf1", "leaf3", "leaf4"):
                wait_for_remote_mac(topology, leaf, "10.0.0.2")
            events.append({"event": "new_location_observed", "unix_time": time.time()})
            time.sleep(3)
        finally:
            if capture is not None and capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                try:
                    capture.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    capture.kill()
                    capture.wait()
            (output / "events.json").write_text(json.dumps(events, indent=2) + "\n")
            print(f"\nControl-plane capture: {output}/spine1-bgp.pcap")

    assert capture.returncode == 0, f"Capture exited with an error; read {output}/capture.log"
