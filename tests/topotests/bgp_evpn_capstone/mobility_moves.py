import os                                   # for building file paths
import sys                                  # for editing the import path
import time                                 # for sleep() between moves
import random                               # for picking robots and destinations
 
CWD = os.path.dirname(os.path.realpath(__file__))   # folder this file lives in
sys.path.append(os.path.join(CWD, "../"))           # so "lib" is importable (same trick topotests use)
 
from lib.topogen import get_topogen                 # hands us the running topology
from .test_evpn_capstone import setup_module, teardown_module  # reuse the test's fabric setup/teardown (dot = same package)
from .test_evpn_capstone import _viz_post           # the test's own helper that POSTs JSON to the visualizer's /event
 
# The leaves in a line: a robot can only step to the next one over
LEAVES = ["leaf1", "leaf2", "leaf3", "leaf4"]
 
# One anchor host per leaf. It never moves, its eth0 carries visiting robots
ANCHOR = {"leaf1": "host11", "leaf2": "host21", "leaf3": "host31", "leaf4": "host41"}
 
# Roaming robots: name -> (home leaf, IP, MAC). Same values as in the test file
ROBOTS = {
    "host12": ("leaf1", "45.0.0.12", "00:00:00:00:00:12"),
    "host22": ("leaf2", "45.0.0.22", "00:00:00:00:00:22"),
    "host32": ("leaf3", "45.0.0.32", "00:00:00:00:00:32"),
    "host42": ("leaf4", "45.0.0.42", "00:00:00:00:00:42"),
}
 
GATEWAY = "45.0.0.1"                        # anycast SVI, every leaf answers for it
 
 
def neighbors(leaf):
    i = LEAVES.index(leaf)                  # position of this leaf in the line
    out = []                                # leaves it's allowed to move to
    if i > 0:                               # not the first leaf, so there's one on the left
        out.append(LEAVES[i - 1])
    if i < len(LEAVES) - 1:                 # not the last leaf, so there's one on the right
        out.append(LEAVES[i + 1])
    return out
 
 
def leave(tgen, robot, leaf):
    home = ROBOTS[robot][0]                 # this robot's home leaf
    if leaf == home:                        # it's at home, so it's on its own eth0
        tgen.net[robot].cmd("ip link set eth0 down")          # unplug it
    else:                                   # it's visiting, so it's a macvlan on the anchor
        anchor = tgen.net[ANCHOR[leaf]]     # the anchor host at that leaf
        anchor.cmd("ip link del rob-{}".format(robot))        # delete the visiting interface
 
 
def arrive(tgen, robot, leaf):
    home, ip, mac = ROBOTS[robot]           # unpack identity (same MAC/IP every time)
    if leaf == home:                        # going back home
        node = tgen.net[robot]              # its own host
        node.cmd("ip link set eth0 up")     # plug eth0 back in (IP is still on it)
        node.cmd("ping -c 2 -W 1 {}".format(GATEWAY))         # send traffic so the leaf learns the MAC
    else:                                   # visiting another leaf
        node = tgen.net[ANCHOR[leaf]]       # the anchor host there
        name = "rob-{}".format(robot)       # interface name for the visitor
        node.cmd("ip link add {} link eth0 address {} type macvlan".format(name, mac))  # new iface with the robot's MAC
        node.cmd("ip addr add {}/24 dev {}".format(ip, name))  # give it the robot's IP
        node.cmd("ip link set {} up".format(name))             # bring it up
        node.cmd("ping -c 2 -W 1 -I {} {}".format(ip, GATEWAY))  # ping from that IP so the leaf learns it
 
 
def viz_move(robot, old_leaf, new_leaf):
    _viz_post({"action": "DEL_LINK", "source": old_leaf, "target": robot})  # erase the old cable (edge id "old_leaf-robot")
    _viz_post({"action": "ADD_LINK", "source": new_leaf, "target": robot})  # draw the new cable to the new leaf
 
 
def keepalive(tgen, where):
    for anchor in ANCHOR.values():          # anchors stay quiet otherwise
        tgen.net[anchor].cmd("ping -c 1 -W 1 {}".format(GATEWAY))
    for robot, leaf in where.items():       # re-announce every robot where it currently is
        ip = ROBOTS[robot][1]
        if leaf == ROBOTS[robot][0]:        # at home: ping from its own host
            tgen.net[robot].cmd("ping -c 1 -W 1 {}".format(GATEWAY))
        else:                               # visiting: ping from the anchor using the robot's IP
            tgen.net[ANCHOR[leaf]].cmd("ping -c 1 -W 1 -I {} {}".format(ip, GATEWAY))
 
 
def simulate(tgen, steps=20, p_move=0.6, pause=3):
    where = {r: ROBOTS[r][0] for r in ROBOTS}   # everyone starts at home
    for step in range(steps):                   # run this many rounds
        robot = random.choice(list(ROBOTS))     # pick a robot
        if random.random() < p_move:            # p_move = chance it actually moves
            dest = random.choice(neighbors(where[robot]))   # adjacent leaf only
            print("step {}: {} {} -> {}".format(step, robot, where[robot], dest))
            leave(tgen, robot, where[robot])    # disconnect from the old leaf
            arrive(tgen, robot, dest)           # reconnect at the new one, same MAC/IP
            viz_move(robot, where[robot], dest) # visualizer: drop the old line, draw the new one (must run before the next line)
            where[robot] = dest                 # remember where it is now
        else:
            print("step {}: {} stays at {}".format(step, robot, where[robot]))
        keepalive(tgen, where)                  # stop MAC entries aging out (300s)
        time.sleep(pause)                       # wait before the next round
 
 
def test_robots_roam():
    tgen = get_topogen()                        # the topology setup_module built
    simulate(tgen)                              # run the sim