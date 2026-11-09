from bgp_evpn_capstone import test_evpn_capstone as lab

setup_module = lab.setup_module
teardown_module = lab.teardown_module

def test_move():
    topology = lab.get_topogen()
    leaf1 = topology.net["leaf1"]
    leaf2 = topology.net["leaf2"]

    print("\nMoving host11 from leaf1 to leaf2...")

    # Move the existing robot-facing interface into leaf2.
    leaf1.cmd_raises("ip link set eth-host11 nomaster")
    leaf1.cmd_raises(f"ip link set eth-host11 netns {leaf2.pids[-1]}")

    # Keep framework cleanup aligned with the new attachment.
    topology.net.links.pop("host11:eth0-leaf1:eth-host11")
    topology.net.links["host11:eth0-leaf2:eth-host11"] = (
        "host11", "eth0", "leaf2", "eth-host11"
    )

    leaf2.cmd_raises("ip link set eth-host11 master br1000")
    leaf2.cmd_raises("ip link set eth-host11 up")

    # Update the visualizer.
    lab._viz_post({
        "action": "DEL_LINK", "source": "leaf1", "target": "host11"
    })
    lab._viz_post({
        "action": "ADD_LINK", "source": "leaf2", "target": "host11"
    })
    
    print("\nHost11 is attached to leaf2.")
    
    # print("\nHost11 is attached to leaf2. Inspect the topology; quit to finish.")
    # topology.cli()
