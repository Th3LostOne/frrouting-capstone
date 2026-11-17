# Multiple Robot Movement

Run the six-robot EVPN correctness experiment inside `frr-dev`.

```bash
cd /home/frr/frr/tests/topotests
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s -q \
  bgp_evpn_capstone/multiple_robot_movement/test_multiple_robot_movement.py
```

The test uses the existing five-leaf, two-spine topology. Two robots start on each of
`leaf1`, `leaf2`, and `leaf3`. Each follows the same pattern relative to its home
leaf: home → next → third → next → home. Two cycles give eight batches and 48
planned moves. Workers start each batch together, wait 50 ms after detaching
each robot, attach it to the next leaf, and send one controlled ARP per robot.
After the learning requests finish, the test waits two seconds before sampling
the batch checkpoint. `leaf4` observes the remote MAC-to-VTEP mappings.
There are no continuous ping probes.

Each run prints its UTC-stamped directory under `captures/`.

- `movement.json` records the plan, actual attachments, timestamps, ARP outcomes,
  BGP and MAC snapshots, duplicate state, and DAD settings.
- `spine1-bgp.pcap` and `spine2-bgp.pcap` contain the BGP traffic. Interface maps
  and peer addresses identify the corresponding leaf links.
- `router_logs/` holds available Zebra and BGP logs.
- `analysis/summary.json` covers all seven metrics. `rt2_events.csv` links
  the route counts and sequence observations to captured frames.
  `report.md` summarizes the outcome and any mismatched locations.

The summary distinguishes per-session wire counts from estimated origin events.
The origin estimate takes the larger per-spine count for each matching robot,
origin RD, IP, action and sequence within a batch. It is an estimate when identical
events recur in a batch or one capture is incomplete. The success rate uses verified
attachments as its denominator. The report shows failed attachments separately from
wrong or missing remote mappings. An observed mismatch is an experimental result;
attachment or capture failures fail the harness.

Reprocess saved evidence with `python3 analyze_movement.py /absolute/path/to/run`
from this folder. The test measures correctness at checkpoints within one fixed
workload. A capacity limit requires a separate set of runs at different loads.
