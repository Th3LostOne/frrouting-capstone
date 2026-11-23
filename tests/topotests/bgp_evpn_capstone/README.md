# bgp_evpn_capstone

How to run every test, analyzer and chart in this folder. It emulates robots
(IP hosts) moving between leaves of an eBGP-underlay, VXLAN-EVPN fabric built
with FRRouting.

- [1. What's in this folder](#1-whats-in-this-folder)
- [2. Setup](#2-setup)
- [3. Live visualizer (optional)](#3-live-visualizer-optional)
- [4. Tests](#4-tests)
- [5. Analysis scripts](#5-analysis-scripts)
- [6. Charts: plot_capture.py](#6-charts-plot_capturepy)
- [7. Typical workflow](#7-typical-workflow)
- [8. Environment variables](#8-environment-variables)
- [9. Troubleshooting](#9-troubleshooting)

---

## 1. What's in this folder

```
bgp_evpn_capstone/
├── test_evpn_capstone.py            Fabric bring-up test; every other test reuses its topology
├── test_host11_type2_roaming.py     host11 roams leaf1/2/3 repeatedly, RT-2 captured
├── mobility_moves.py                Random roaming demo for the live topology view
├── resource_monitor.py              CPU / memory / table-size recorder (used by BBM and MBB)
├── plot_resources.py                Graphs resource_monitor output
├── plot_capture.py                  RT-2 / queue / EVPN routes / DAD chart for BBM and MBB runs
├── visualizer_server.py             Live web dashboard (topology, route counts, resources)
├── templates/                       HTML pages served by visualizer_server.py
├── leaf1..leaf5/, spine1..spine2/   frr.conf for each router
├── project_topology.pdf             Topology drawing
│
├── single_movement/                 One robot (host11) moves once, leaf1 -> leaf2
│   ├── single_robot_movement.py         the move only, no captures
│   ├── capture_single_robot_movement.py the move with a spine1 BGP capture
│   ├── capture_leaf_traffic.py          the move with leaf1 + leaf2 captures
│   ├── evpn_move_analyzer.py            convergence + BGP overhead from a pcap
│   ├── analyze_leaf_traffic.py          timeline of what the two leaves did
│   ├── extract_metrics.py               one CSV row of metrics per run
│   └── robot_roaming/                   One robot roams many leaves; can the controller keep up?
│       ├── test_robot_roaming.py
│       └── roam_analyzer.py
│
├── multiple_robot_movement - BBM/   6 robots, break-before-make, 96 moves
│   ├── test_multiple_robot_movement.py
│   └── analyze_movement.py
│
└── multiple_robot_movement - MBB/   6 robots, make-before-break, 96 moves
    ├── test_mbb_multiple_movement.py
    ├── analyze_mbb.py
    └── robot_agent.py                   ARP sender kept running inside each robot
```

**Topology** (`project_topology.pdf`, set up by `test_evpn_capstone.py`):

- **spine1, spine2:** eBGP underlay and EVPN transit (AS 65000).
- **leaf1–leaf4:** VTEPs on L2VNI 1000 (45.0.0.0/24, anycast gateway
  45.0.0.1). Each has two hosts: `host11/host12` on leaf1 through
  `host41/host42` on leaf4.
- **leaf5:** VTEP on L2VNI 2000 (20.0.0.1), with the Controller (20.0.0.51)
  behind it.
- **All leaves:** L3VNI 500 in VRF500 (symmetric IRB).
- **Sessions:** eBGP-unnumbered between every leaf and both spines, and EVPN
  runs over those same sessions.

## 2. Setup

Everything runs **inside the `frr-dev` container**, from `tests/topotests`,
**as root** (`sudo -E`), like every FRR topotest:

```bash
docker exec -it frr-dev bash          # or however you attach to the container
cd /home/frr/frr/tests/topotests
```

**Tools the tests and analyzers need:**

| Tool | Used by | Install |
|---|---|---|
| FRR build + topotest deps (`pytest`, `munet`, ...) | every test | already in `frr-dev` |
| `scapy` | every movement test (learning ARPs) | `pip install scapy` |
| `tshark` | all analyzers and capture tests | `apt install tshark` |
| `matplotlib`, `numpy` | `--plot` options, `plot_resources.py`, `plot_capture.py` | `pip install matplotlib numpy` |
| `flask`, `flask-socketio` | `visualizer_server.py` only | `pip install flask flask-socketio` |

On a system-managed Python, add `--break-system-packages` to `pip`, or use a
virtualenv.

**Notes on running tests:**

- **Live graph off:** most commands below set `ENABLE_LIVE_ROUTE_GRAPH=false`.
  Without it, the tests try to post to the visualizer. Leave it out only when
  the visualizer is running (section 3).
- **Folders with spaces:** the BBM and MBB folder names contain spaces, so
  always quote those paths.
- **Where results go:** each test prints the folder it wrote to (usually
  `captures/<UTC stamp>/` next to the test).

## 3. Live visualizer (optional)

A web page that shows the topology, robot moves, route counts and switch
resources live while a test runs.

```bash
# Terminal 1, inside frr-dev: restart any older copy first with Ctrl+C
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
python3 visualizer_server.py
```

The server listens on port 5000 inside the container. Open it from your
machine through whatever port the container maps to 5000 (the current setup
maps it to **5001**):

| Page | URL (from your Mac) |
|---|---|
| Topology + moves | <http://localhost:5001/> |
| Route counts | <http://localhost:5001/route-chart> |
| Resources (CPU, memory, tables) | <http://localhost:5001/resource-chart> |

Then run a test in a second terminal with the live graphs turned on:

```bash
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=true ENABLE_LIVE_RESOURCE_GRAPH=true \
  pytest -s "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"
```

Run BBM and MBB one at a time, because they share one resource dashboard. The
page resets when a new run connects and shows "Run complete" when it ends.

## 4. Tests

All commands are run from `/home/frr/frr/tests/topotests`.

### 4.1 Fabric bring-up: `test_evpn_capstone.py`

Checks that the fabric comes up, and nothing moves. It verifies:

- every FRR daemon is running;
- the underlay and EVPN sessions are Established;
- every leaf has its L2VNI and L3VNI 500;
- Type-2 and Type-5 routes are imported.

```bash
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s bgp_evpn_capstone/test_evpn_capstone.py
```

Run this first after any `frr.conf` change.

### 4.2 Single robot, single move: `single_movement/`

host11 moves from leaf1 to leaf2 once.

```bash
# Just the move (no captures). Useful with the visualizer open.
sudo -E pytest -s bgp_evpn_capstone/single_movement/single_robot_movement.py

# The move with a spine1 BGP capture -> single_movement/captures/<stamp>/
sudo -E pytest -s bgp_evpn_capstone/single_movement/capture_single_robot_movement.py

# The move with leaf1 + leaf2 captures -> single_movement/captures/<stamp>-leaves/
sudo -E pytest -s bgp_evpn_capstone/single_movement/capture_leaf_traffic.py
sudo -E env CAPTURE_PROBES=0 pytest -s bgp_evpn_capstone/single_movement/capture_leaf_traffic.py  # no pings
```

`capture_leaf_traffic.py` records the following on each leaf:

- BGP, VXLAN, ARP and ICMP packets (`leaf1.pcap`, `leaf2.pcap`);
- kernel FDB and ARP changes (`*-fdb.jsonl`, `*-neigh.jsonl`);
- table snapshots before and after the move;
- `events.json`;
- by default, 20 pings/s probes across the move.

Analyze the results with the scripts in [5.1](#51-single-movement-analyzers).

### 4.3 One robot roaming many leaves: `single_movement/robot_roaming/`

Answers whether the controller's router (leaf5) keeps track of a robot that
keeps moving. host11 follows `ROAM_PATH` and waits `ROAM_DWELL_S` at each leaf.
Captures go to `single_movement/robot_roaming/captures/<stamp>/`, and the
analyzer runs automatically at the end.

```bash
sudo -E pytest -s bgp_evpn_capstone/single_movement/robot_roaming/test_robot_roaming.py

# Move faster than BGP converges
sudo -E env ROAM_DWELL_S=0.3 pytest -s bgp_evpn_capstone/single_movement/robot_roaming/test_robot_roaming.py

# Custom path
sudo -E env ROAM_PATH=leaf2,leaf3,leaf1 pytest -s bgp_evpn_capstone/single_movement/robot_roaming/test_robot_roaming.py
```

The results are in `analysis/roam_report.html` (open it in a browser) plus
CSVs. To re-run the analysis by hand, see [5.1](#51-single-movement-analyzers).

### 4.4 host11 repeated RT-2 roaming: `test_host11_type2_roaming.py`

host11 moves leaf1 → leaf2 → leaf3 for `TYPE2_CYCLES` cycles, with the RT-2
routes captured. By default the output goes to the topotest log dir
(`.../type2_host11`). Set `TYPE2_OUTPUT_DIR` to choose another folder.

```bash
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false TYPE2_CYCLES=3 TYPE2_DWELL_S=2 \
  TYPE2_OUTPUT_DIR=~/type2_run pytest -s bgp_evpn_capstone/test_host11_type2_roaming.py
```

### 4.5 Random roaming demo: `mobility_moves.py`

host12, host22, host32 and host42 wander randomly between neighbouring leaves
for 20 rounds. This is mainly for watching the live topology page. It doesn't
take any measurements.

```bash
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=true pytest -s bgp_evpn_capstone/mobility_moves.py
```

### 4.6 Six robots, break-before-make: `multiple_robot_movement - BBM/`

**The experiment:**

- **Robots:** two start on each of leaf1–leaf3.
- **Pattern:** each robot goes home → next → third → next → home.
- **Size:** 4 cycles = **16 batches, 96 moves**. All 6 robots in a batch move
  at once.
- **Each move:** the old link is detached, the test waits 50 ms
  (`BREAK_S`), attaches the new link and sends one learning ARP.
- **Between batches:** a 2 s dwell (`DWELL_S`), then a checkpoint is taken.
- **Observer:** leaf4 checks the remote MAC-to-VTEP mappings.

```bash
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - BBM/test_multiple_robot_movement.py"
```

**Output** (`multiple_robot_movement - BBM/captures/<stamp>/`):

- `movement.json`;
- `spine1-bgp.pcap` and `spine2-bgp.pcap`;
- `router_logs/`;
- `resources-system.csv` and `resources-frr.csv`;
- `analysis/` with `summary.json`, `rt2_events.csv` and `report.md`.

`BREAK_S`, `DWELL_S` and the cycle count are constants at the top of
`test_multiple_robot_movement.py`, not environment variables. Edit the file to
change them.

### 4.7 Six robots, make-before-break: `multiple_robot_movement - MBB/`

The robots and paths are the same as BBM, but each robot is a Linux
active-backup bond with a cable to leaf1, leaf2 and leaf3. For each move, the
test:

1. brings up the new cable;
2. switches transmit to it;
3. sends one learning ARP;
4. holds the old cable for at least `MBB_OVERLAP_S`;
5. removes the old cable.

```bash
# Default: 4 cycles = 16 batches, 96 moves
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"

# Short check: 1 cycle = 24 moves
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false MBB_CYCLES=1 pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"

# Change overlap and dwell
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false MBB_CYCLES=4 MBB_OVERLAP_S=0.5 MBB_DWELL_S=2.0 \
  pytest -s -q "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"

# With the live resource dashboard (start visualizer_server.py first)
sudo -E env ENABLE_LIVE_RESOURCE_GRAPH=true ENABLE_LIVE_ROUTE_GRAPH=false \
  MONITOR_INTERVAL_S=1 MONITOR_FRR_INTERVAL_S=5 \
  pytest -s "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"
```

**Output** (`multiple_robot_movement - MBB/captures/<stamp>/`): everything
BBM writes, plus:

- `leaf1-3-arp.pcap`;
- `observer.jsonl`;
- `*-fdb.jsonl` and `*-neigh.jsonl`;
- `analysis/mbb_checks.csv` (actual overlap and ordering for each move).

The MBB README in that folder explains the handoff model in detail.

## 5. Analysis scripts

All analyzers need `tshark`. Run them from the folder they live in, or give
the full path to the script.

### 5.1 Single-movement analyzers

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone/single_movement
```

| Script | Input | What you get |
|---|---|---|
| `evpn_move_analyzer.py` | any BGP pcap (e.g. `captures/<stamp>/spine1-bgp.pcap`) | MAC-mobility convergence and BGP overhead; `runs_summary.csv` for many runs |
| `analyze_leaf_traffic.py` | a `captures/<stamp>-leaves/` folder | `analysis/` with per-leaf packet CSVs, a merged `timeline.csv`, `summary.json` |
| `extract_metrics.py` | one or more `-leaves` folders | one CSV row per run: EVPN update, L2/L3 convergence, reachability recovery, packet loss |
| `robot_roaming/roam_analyzer.py` | a `robot_roaming/captures/<stamp>/` folder | `roam_report.html`, out-of-sync time at leaf5, per-move CSVs |

```bash
# Spine pcap -> convergence metrics, with leaf names and plots
python3 evpn_move_analyzer.py captures/<stamp>/spine1-bgp.pcap --plot --out results/ \
  --names 65011=leaf1,65012=leaf2,65013=leaf3,65014=leaf4,65015=leaf5
python3 evpn_move_analyzer.py captures/*/spine1-bgp.pcap --out results/   # many runs

# Leaf captures -> timeline (+ zoomed plot of the move)
python3 analyze_leaf_traffic.py captures/<stamp>-leaves --plot
python3 analyze_leaf_traffic.py captures/<stamp>-leaves --plot --full     # whole capture

# Many leaf runs -> one metrics CSV
python3 extract_metrics.py captures/*-leaves --out metrics.csv
python3 extract_metrics.py captures/*-leaves --out metrics_detailed.csv --detailed

# Roaming run -> HTML report (budget = how long leaf5 may be out of sync)
python3 robot_roaming/roam_analyzer.py robot_roaming/captures/<stamp> --plot --budget-ms 1000
```

`--mac` and `--ip` (defaults `00:00:00:00:00:11`, `45.0.0.11`) choose a
different robot for `analyze_leaf_traffic.py` and `extract_metrics.py`.

### 5.2 BBM and MBB analyzers

The tests run these automatically. Run them by hand to reprocess a saved
capture, for example after changing the analyzer:

```bash
cd "/home/frr/frr/tests/topotests/bgp_evpn_capstone/multiple_robot_movement - BBM"
python3 analyze_movement.py "$PWD/captures/<stamp>"

cd "/home/frr/frr/tests/topotests/bgp_evpn_capstone/multiple_robot_movement - MBB"
python3 analyze_mbb.py captures/<stamp>
```

Both write `analysis/summary.json`, `analysis/rt2_events.csv` and
`analysis/report.md`. MBB also writes `analysis/mbb_checks.csv`.

### 5.3 Resource graphs: `plot_resources.py`

`resource_monitor.py` records CPU, memory and table sizes on every switch
during BBM and MBB runs (`resources-system.csv`, `resources-frr.csv`). Run
`plot_resources.py` on the capture folder to graph them. It writes
`analysis/resources.png`:

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone
python3 plot_resources.py "multiple_robot_movement - MBB/captures/<stamp>"             # one grid picture
python3 plot_resources.py "multiple_robot_movement - MBB/captures/<stamp>" --separate  # + one picture per graph
python3 plot_resources.py "<capture>" --out ~/slides                                   # different output folder
```

The `resource_monitor.py` docstring lists what every CSV column means.

## 6. Charts: `plot_capture.py`

Draws the "RT-2 / queue / EVPN routes / DAD over time" chart for one BBM or
MBB capture. It works out which test type the run is from `movement.json`.

```bash
cd /home/frr/frr/tests/topotests/bgp_evpn_capstone

python3 plot_capture.py "multiple_robot_movement - MBB/captures/20261117T191537-954125Z"
python3 plot_capture.py "multiple_robot_movement - BBM/captures/20261117T183906-697951Z"
```

It needs `movement.json`, `analysis/summary.json` and `analysis/rt2_events.csv`
in the capture folder. If `analysis/` is missing, run the analyzer first
(5.2).

The output goes into the capture's `analysis/` folder:

```
<capture>/analysis/<run_id>-chart.png    (use this one in slides)
<capture>/analysis/<run_id>-chart.svg    (scalable, editable)
```

| Option | What it does | Default |
|---|---|---|
| `-o PATH` | Output path without extension | `<capture>/analysis/<run>-chart` |
| `--spine NAME` | Which spine's pcap to count RT-2 and the queue at | `spine1` |
| `--title "TEXT"` | Replace the auto-generated title | built from the run |
| `--no-svg` | Write only the PNG | both |

```bash
# Every BBM and MBB capture at once
for d in "multiple_robot_movement - MBB"/captures/*/ "multiple_robot_movement - BBM"/captures/*/; do
    python3 plot_capture.py "$d"
done
```

**Reading the chart:**

| Line | Meaning |
|---|---|
| Green, solid: **RT-2 Advertisements** | Running total of Type-2 routes the new leaf sends when a robot arrives (seen at the spine) |
| Purple, dotted: **RT-2 Withdrawals** | Running total of Type-2 routes the old leaf withdraws when a robot leaves |
| Blue, dashed: **Total EVPN routes** | EVPN routes summed across all leaf tables at each checkpoint |
| Yellow: **Spine update queue** | RT-2 NLRI the spine has received minus re-sent (1 s rolling max) |
| Red, thick: **DAD flags** | Running total of duplicate-address flags on the leaves at each checkpoint |
| Red triangles | Batches where zebra logged new DAD detections |
| Grey bands | One batch: all robots in the batch moving at once |

**Annotations added automatically:**

- the ΔT arrow, from the first move until DAD first fires;
- "+N DAD (Bx)" labels;
- route dips below the starting total;
- for BBM, the average old-link-down to new-link-up gap;
- a "0 DAD" note when DAD never fires.

**Caveats:**

- DAD flags are read at every checkpoint, so one detection can be counted
  more than once.
- Zebra log times are read as UTC, with one-second precision.
- Label positions are tuned for runs of about 16 batches.

## 7. Typical workflow

```bash
cd /home/frr/frr/tests/topotests

# 1. Fabric still healthy?
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s bgp_evpn_capstone/test_evpn_capstone.py

# 2. Run the experiments (each prints its capture folder)
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - BBM/test_multiple_robot_movement.py"
sudo -E env ENABLE_LIVE_ROUTE_GRAPH=false pytest -s -q \
  "bgp_evpn_capstone/multiple_robot_movement - MBB/test_mbb_multiple_movement.py"

# 3. Charts for both
cd bgp_evpn_capstone
python3 plot_capture.py "multiple_robot_movement - BBM/captures/<bbm stamp>"
python3 plot_capture.py "multiple_robot_movement - MBB/captures/<mbb stamp>"

# 4. Read the findings
cat "multiple_robot_movement - MBB/captures/<mbb stamp>/analysis/report.md"
```

## 8. Environment variables

Set these in front of `pytest` with `sudo -E env NAME=value ... pytest ...`.

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `ENABLE_LIVE_ROUTE_GRAPH` | `true` | all tests | Post route counts and topology to the visualizer |
| `ROUTE_SAMPLE_INTERVAL_SECONDS` | `1.0` | all tests | Route-count sampling period (min 0.5) |
| `VISUALIZER_URL` | `http://127.0.0.1:5000` | all tests | Where the visualizer runs |
| `ENABLE_LIVE_RESOURCE_GRAPH` | `true` | BBM, MBB | Post resource samples to the visualizer (CSVs are always written) |
| `VISUALIZER_EVENT_URL` | `http://127.0.0.1:5000/event` | BBM, MBB | Where resource samples are posted |
| `MONITOR_INTERVAL_S` | `1.0` | BBM, MBB | System sample period (CPU, memory, kernel tables) |
| `MONITOR_FRR_INTERVAL_S` | `5.0` | BBM, MBB | FRR (vtysh) sample period; `0` turns it off |
| `MBB_CYCLES` | `4` | MBB | Cycles of 4 batches (4 = 96 moves, 1 = 24) |
| `MBB_OVERLAP_S` | `0.5` | MBB | Minimum time the old cable stays up after the ARP |
| `MBB_DWELL_S` | `2.0` | MBB | Wait after a batch before the checkpoint |
| `ROAM_PATH` | `leaf2,leaf3,leaf4,leaf1,leaf3,leaf2,leaf4,leaf3,leaf1,leaf2` | robot_roaming | Leaves host11 visits, in order |
| `ROAM_DWELL_S` | `2.0` | robot_roaming | Time at each leaf |
| `ROAM_PROBE_INTERVAL` | `0.05` | robot_roaming | Ping interval from the controller |
| `ROAM_SETTLE_S` | `5.0` | robot_roaming | Wait after the last move |
| `ROAM_ANALYZE` | `1` | robot_roaming | `0` skips running `roam_analyzer.py` at the end |
| `CAPTURE_PROBES` | `1` | capture_leaf_traffic | `0` turns off the pings during the move |
| `CAPTURE_PROBE_INTERVAL` | `0.05` | capture_leaf_traffic | Ping interval |
| `TYPE2_CYCLES` | `2` | host11 type2 roaming | Number of leaf1→2→3 cycles |
| `TYPE2_DWELL_S` | `3` | host11 type2 roaming | Time at each leaf |
| `TYPE2_BREAK_GAP_S` | `0.3` | host11 type2 roaming | Gap between detach and attach |
| `TYPE2_VERIFY_TIMEOUT_S` | `45` | host11 type2 roaming | How long to wait for the observer to see the move |
| `TYPE2_OUTPUT_DIR` | topotest log dir | host11 type2 roaming | Where results are written |

BBM has no environment variables. Its `BREAK_S` (0.05 s), `DWELL_S` (2 s)
and cycle count (4) are constants in `test_multiple_robot_movement.py`.

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| `Permission denied` / namespace errors | Run tests with `sudo -E`, from `tests/topotests` |
| `ModuleNotFoundError: bgp_evpn_capstone` or `lib` | You're not in `tests/topotests`; `cd` there first |
| `file or directory not found` for BBM/MBB | Quote the path, since the folder names contain spaces |
| Test hangs or slows down posting to the visualizer | Start `visualizer_server.py`, or set `ENABLE_LIVE_ROUTE_GRAPH=false` (and `ENABLE_LIVE_RESOURCE_GRAPH=false`) |
| Old dashboard data or a port already in use | Stop the old `visualizer_server.py` with Ctrl+C and start it again |
| `tshark: command not found` | `apt install tshark` in the container |
| `No module named scapy` | `pip install scapy` in the container |
| `No module named matplotlib` | `pip install matplotlib numpy` |
| `plot_capture.py`: `.../analysis/summary.json` missing | Run `analyze_movement.py` / `analyze_mbb.py` on the capture first |
| `plot_capture.py`: `no rows for capture 'spine1'` | Use `--spine spine2` |
