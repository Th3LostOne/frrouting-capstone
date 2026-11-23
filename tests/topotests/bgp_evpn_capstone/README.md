# plot_capture.py

Builds the "RT-2 / queue / EVPN routes / DAD over time" chart from one
`bgp_evpn_capstone` capture folder. Works for both test types:

- **Make-before-break (MBB)**: `MBB - multiple movement/captures/<run>`
- **Break-before-make (BBM)**: `multiple_robot_movement/captures/<run>`

The script works out which type a run is from `movement.json`.

---

## 1. Requirements

- Python 3.8 or newer
- matplotlib and numpy

```bash
pip install matplotlib numpy
```

(On a system-managed Python, such as Ubuntu 23.04+ or the topotest VM, add
`--break-system-packages` or use a virtualenv.)

## 2. Run a test first

The script only reads files that the tests already write. After a run, the
capture folder must contain:

```
<capture_dir>/
├── movement.json             batch and move timing, DAD settings, timers
└── analysis/
    ├── summary.json          EVPN route counts, DAD events and duplicate flags
    └── rt2_events.csv        every RT-2 NLRI seen in the spine pcaps
```

If `analysis/` is missing, run the analysis step for that test first (for MBB
that is `analyze_mbb.py`).

## 3. Make the chart

```bash
python3 plot_capture.py "<path to capture folder>"
```

Examples, run from `tests/topotests/bgp_evpn_capstone/`:

```bash
# Make-before-break run
python3 plot_capture.py "MBB - multiple movement/captures/20261117T191537-954125Z"

# Break-before-make run
python3 plot_capture.py multiple_robot_movement/captures/20261117T183906-697951Z
```

Put quotes around paths that contain spaces (like `MBB - multiple movement`).

By default the output goes into the capture's own `analysis/` folder:

```
<capture_dir>/analysis/<run_id>-chart.png    (use this one in slides)
<capture_dir>/analysis/<run_id>-chart.svg    (scalable, editable)
```

The script also prints a one-line summary, for example:

```
[MBB] 16 batches, 96 moves · RT-2 adv 191 / withd 191 · queue peak 16 · DAD flags 162 (18 zebra detections)
wrote .../analysis/20261117T191537-954125Z-chart.png and .../20261117T191537-954125Z-chart.svg
```

### Options

| Option | What it does | Default |
|---|---|---|
| `-o PATH`, `--out PATH` | Output path without extension (`.png`/`.svg` are added) | `<capture>/analysis/<run>-chart` |
| `--spine NAME` | Which spine's pcap to count RT-2 messages and the queue at | `spine1` |
| `--title "TEXT"` | Replace the auto-generated title | built from the run |
| `--no-svg` | Write only the PNG | writes both |
| `-h`, `--help` | Show help | |

```bash
# Save to a slides folder, count at spine2, custom title, PNG only
python3 plot_capture.py "MBB - multiple movement/captures/20261117T191537-954125Z" \
    -o ~/slides/mbb_run2 --spine spine2 --title "MBB, run 2" --no-svg
```

### Do every capture at once

```bash
for d in "MBB - multiple movement"/captures/*/ multiple_robot_movement/captures/*/; do
    python3 plot_capture.py "$d"
done
```

## 4. Reading the chart

| Line | Meaning |
|---|---|
| Green, solid: **RT-2 Advertisements** | Running total of Type-2 (MAC and MAC/IP) routes sent by the new leaf when a robot arrives, as received at the spine |
| Purple, dotted: **RT-2 Withdrawals** | Running total of Type-2 routes withdrawn by the old leaf when a robot leaves |
| Blue, dashed: **Total EVPN routes** | EVPN routes summed across all `leafN` tables at each batch checkpoint |
| Yellow: **Spine update queue** | RT-2 NLRI the spine has received minus re-sent to other leaves (1 s rolling max) |
| Red, thick: **DAD flags** | Running total of `isDuplicate` flags on the leaves at each checkpoint |
| Red triangles | Batches where zebra logged new DAD detections (only when DAD fires) |
| Grey bands | One batch: all robots in that batch moving at once |

The chart adds these annotations automatically:

- **ΔT arrow**: time from the first move until DAD first fires.
- **"+N DAD (Bx)"**: how many zebra DAD detections landed in that batch.
- **Route dip**: any checkpoint where total EVPN routes fell below the
  starting value.
- **BBM gap**: average old-link-down to new-link-up time per move, plus the
  break timer.
- **"0 DAD" note**: shown when a run has no DAD detections, with the share of
  adverts that carry no MAC-mobility sequence.

The title, subtitle (DAD max-moves, detection time, freeze), robot, leaf and
spine counts, and the footer (moves completed, correct mappings, BGP session
drops) all come from the capture files.

## 5. Notes

- **DAD flags can count the same detection more than once.** Flags are read at
  every checkpoint, so a MAC that stays flagged is counted again at each one.
  The red curve shows how the flags build up, not a count of separate events.
- **The final "after" snapshot is left out of the curve**, so the label shows
  the total up to the last batch. The total printed in the terminal includes it.
- **Zebra log times are read as UTC** and only have one-second precision. Each
  detection is assigned to the batch that started in that second.
- **Label positions are tuned for runs of about 16 batches and 50–60 s.**
  Longer runs still plot correctly; on very long runs only every Nth batch
  tick is labelled, and some labels may crowd together.

## 6. Troubleshooting

| Message | Fix |
|---|---|
| `No such file or directory: .../analysis/summary.json` | Run the test's analysis step first, or check the path |
| `rt2_events.csv has no rows for capture 'spine1'` | That spine wasn't captured; try `--spine spine2` |
| `can't tell MBB from BBM` | `movement.json` is from a different test type; this script only supports MBB and BBM moves |
| `ModuleNotFoundError: matplotlib` | `pip install matplotlib numpy` |
| Fonts look different | The chart uses DejaVu Sans, which matplotlib ships with. Other fonts only change the look |
