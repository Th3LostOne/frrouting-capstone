from bgp_evpn_capstone import test_evpn_capstone as lab

# Reuse the course topology's setup and cleanup.
setup_module = lab.setup_module
teardown_module = lab.teardown_module


def wait_for_ping(source, destination):
    """Wait until a ping succeeds."""
    success, _ = lab.topotest.run_and_expect(
        lambda: "1 received" in source.cmd(
            f"ping -n -c 1 -W 1 {destination}"
        ),
        True,
        count=30,
        wait=0.5,
    )
    assert success, f"Cannot reach {destination}"


def test_first_move():
    topology = lab.get_topogen()

    robot = topology.net["host11"]
    controller = topology.net["controller"]
    leaf1 = topology.net["leaf1"]
    leaf2 = topology.net["leaf2"]

    # Establish communication before movement.
    wait_for_ping(robot, "45.0.0.1")
    wait_for_ping(controller, "45.0.0.11")

    # Move the leaf-facing end of the robot's virtual cable.
    leaf1.cmd_raises("ip link set eth-host11 nomaster")
    leaf1.cmd_raises(
        f"ip link set eth-host11 netns {leaf2.pids[-1]}"
    )

    leaf2.cmd_raises("ip link set eth-host11 master br1000")
    leaf2.cmd_raises("ip link set eth-host11 up")

    # Keep framework cleanup pointed at the interface's new location.
    old_link = "host11:eth0-leaf1:eth-host11"
    new_link = "host11:eth0-leaf2:eth-host11"
    topology.net.links[new_link] = (
        "host11", "eth0", "leaf2", "eth-host11"
    )
    del topology.net.links[old_link]

    # Show the new attachment in the browser.
    lab._viz_post({"action": "DEL_LINK", "source": "leaf1", "target": "host11"})
    lab._viz_post({"action": "ADD_LINK", "source": "leaf2", "target": "host11"})

    # Make the robot transmit so leaf2 learns its location.
    wait_for_ping(robot, "45.0.0.1")

    # Verify communication through the new attachment.
    wait_for_ping(controller, "45.0.0.11")
    wait_for_ping(robot, "20.0.0.51")

    print("\nPASS: host11 remains attached to leaf2 until topology teardown")
