# MBB Multiple Robot Movement

Run this experiment inside the existing `frr-dev` container. The folder name contains spaces, so quote the path.

```bash
cd /home/frr/frr/tests/topotests
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"
```

## Live resource dashboard

The MBB test starts the same `ResourceMonitor` used by BBM and stops it in its
cleanup block. It records all seven switches, including robot bond setup,
baseline learning, and every handoff batch. The shared dashboard resets its
previous samples when the new monitor connects.

In a container terminal, start the visualizer (restart an older process with
Ctrl+C first):

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
python3 visualizer_server.py
```

On your Mac, open <http://localhost:5001/resource-chart>. Leave the server running.
In a second terminal attached to `frr-dev`, run:

```bash
cd /home/frr/frr/tests/topotests
sudo -E env ENABLE_LIVE_RESOURCE_GRAPH=true ENABLE_LIVE_ROUTE_GRAPH=false \
  MONITOR_INTERVAL_S=1 MONITOR_FRR_INTERVAL_S=5 \
  pytest -s "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"
```

System measurements normally arrive every second and FRR measurements every
five seconds. CPU and counter-rate graphs need two samples. When monitoring
finishes, the page retains the measurements and shows "Run complete". Run BBM
and MBB separately; they share one live resource dashboard.

Each MBB capture folder also contains `resources-system.csv` and
`resources-frr.csv`. CSV recording continues if the visualizer is unavailable.
Use `ENABLE_LIVE_RESOURCE_GRAPH=false` to disable live publishing while keeping
the CSVs. `MONITOR_FRR_INTERVAL_S=0` disables FRR polling. The separate route-count
dashboard can be enabled with `ENABLE_LIVE_ROUTE_GRAPH=true`.

## Handoff model

Six existing robots keep their original IP and MAC identities. A Linux active-backup bond called `bond0` owns each identity. The original cable and two additional cables connect that same robot namespace to leaf1–leaf3. The standby cables begin down and outside the leaf bridges. Only the current and destination cables are enabled during a handoff.

For each robot, the test enables and verifies the destination cable, selects it as the bond's transmit interface, sends one controlled learning ARP, holds the old cable for at least 500 ms after that send completes, then disables and removes the old access port from its bridge. Both cables can receive during overlap through `all_slaves_active=1`. Automatic bond gratuitous ARPs are disabled through `num_grat_arp=0`; the persistent Scapy sender issues the learning stimulus.

There is a 200 ms carrier-recognition wait before switching the transmit interface. The measured physical overlap includes that preparation and command overhead as applicable. `MBB_OVERLAP_S` is the minimum hold after the explicit ARP send, and `mbb_checks.csv` reports the actual overlap.

This is a dual-attachment emulation for control-plane experiments. Only one bond interface transmits ordinary traffic at a time. The existing single-homed EVPN configuration resolves mobility. The test does not configure EVPN all-active multihoming or run application traffic to establish outage-free service.

## Workload and settings

The default workload matches the current BBM paths and robot identities. Four cycles give 16 batches and 96 planned movements. Each robot follows home → next leaf → third leaf → next leaf → home. After each batch's old links are removed, the test waits two seconds and records router state. Leaf4 stays outside the handoffs and observes remote MAC mappings.

```bash
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false MBB_CYCLES=4 \
  MBB_OVERLAP_S=0.5 MBB_DWELL_S=2.0 pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"
```

For a short validation use `MBB_CYCLES=1`, giving 24 planned moves. To display the existing route chart, start the visualizer first and set `ENABLE_LIVE_ROUTE_GRAPH=true`. Its route-count plot receives the regular sampler updates. The topology drawing does not model the additional bond cables.

The MBB ARP sender is preloaded and sends without waiting for an ARP reply. The current BBM test starts Scapy for each request and waits for replies. A comparison of event timings or achieved move rate must account for that difference. Record both the handoff model and actual offered load with your results.

## Saved evidence

Each run prints a timestamped directory under this folder's `captures/`.

- `movement.json` contains the complete plan, verified handoffs, overlap timestamps, parameters, settings, and batch snapshots.
- `spine1-bgp.pcap` and `spine2-bgp.pcap` record both spines' BGP adjacencies.
- `leaf1-arp.pcap`, `leaf2-arp.pcap`, and `leaf3-arp.pcap` verify learning packets at the access ports.
- `*-interfaces.txt` and `movement.json/leaf_ports` map captured interface indices to names.
- `observer.jsonl` samples all six MAC mappings on leaf4, including during overlaps.
- `*-fdb.jsonl`, `*-neigh.jsonl`, and `router_logs/` preserve kernel changes and available FRR logs.
- `analysis/report.md` and `summary.json` cover the seven EVPN metrics and the MBB ordering checks.
- `analysis/rt2_events.csv` gives the per-session captured route events.
- `analysis/mbb_checks.csv` records actual overlap, new-port ARP evidence, advertisements and withdrawals before break, and observer samples per move.

The analyzer reuses the existing Multiple Robot Movement metric calculations. Origin counts across both spines are estimates that group matching copies within each batch. During overlap either connected VTEP is acceptable for the sampled MAC mapping. Batch and final checkpoints require the completed destination VTEP.

The pytest assertions validate completed handoffs, captures and the MBB ordering evidence. Protocol mapping mismatches and duplicate flags remain explicit experimental findings in the report. After a handoff command failure, the worker attempts to restore the old attachment and skips further moves for that robot. The log retains those failures.

## Reanalyze a saved run

```bash
cd "/home/frr/frr/tests/topotests/bgp_evpn_capstone/multiple_robot_movement - MBB"
python3 analyze_mbb.py captures/YOUR_RUN_FOLDER
```

The scripts reuse the shared baseline and the existing BBM/capture/analyzer helpers in the same checkout. Keep the capstone folder structure intact. Linux bonding support was verified in the current Colima VM.

The local conftest hook uses an internal test ID without spaces because FRR's log helpers invoke shell commands on that ID. The folder and source paths keep the requested name.
