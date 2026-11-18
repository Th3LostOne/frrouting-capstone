"""Summarize a saved Multiple Robot Movement run. Requires TShark on PATH."""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "single_movement"))
from evpn_move_analyzer import extract_messages, parse_update, read_segments  # noqa: E402


def route_events(folder, run):
    """Collect one row per decoded robot RT-2 on each observed session."""
    rows, errors = [], {}
    by_mac = {info["mac"]: host for host, info in run["robots"].items()}
    for spine, peers in run["spine_peers"].items():
        try:
            segments = read_segments(str(folder / f"{spine}-bgp.pcap"))
            if not segments:
                raise ValueError("No BGP TCP segments captured")
            for message in extract_messages(segments):
                if message["type"] != "UPDATE":
                    continue
                seg = message["seg"]
                attrs, routes = parse_update(message["raw"])
                for route in routes:
                    robot = by_mac.get(route.get("mac"))
                    if route["route_type"] != 2 or robot is None:
                        continue
                    incoming = seg["pkttype"] != "4"
                    leaf = peers.get(seg["src"] if incoming else seg["dst"])
                    vtep = run["vteps"].get(leaf)
                    originated = bool(incoming and vtep and route["rd"] == f"{vtep}:1000")
                    if originated and route["action"] == "advertise":
                        originated = attrs["next_hop"] == vtep and len(attrs["as_path"]) == 1
                    rows.append({
                        "capture": spine, "frame": seg["frame"], "unix_time": seg["t"],
                        "direction": "in" if incoming else "out", "peer": leaf,
                        "originated": originated, "robot": robot, "mac": route["mac"],
                        "action": route["action"], "rd": route["rd"], "ip": route["ip"],
                        "kind": "MAC/IP" if route["ip"] else "MAC-only",
                        "next_hop": attrs["next_hop"] if route["action"] == "advertise" else None,
                        "sequence": attrs["mac_mob_seq"] if attrs["mac_mob_seq"] != "" else None,
                    })
        except (Exception, SystemExit) as exc:
            errors[spine] = str(exc)
    return sorted(rows, key=lambda row: row["unix_time"]), errors


def locations_at(state, run, expected):
    """Compare the observer's selected mapping with verified attachments."""
    macs = state.get(run["observer"], {}).get("macs", {})
    results = {}
    for host, leaf in expected.items():
        entry = macs.get(run["robots"][host]["mac"])
        observed = entry.get("remoteVtep") if entry and entry.get("type") == "remote" else None
        target = run["vteps"].get(leaf)
        results[host] = {
            "actual_leaf": leaf, "expected_vtep": target, "observed_vtep": observed,
            "correct": bool(target and observed == target),
        }
    return results


def dad_evidence(folder, run, checkpoints):
    """Keep event log counts separate from duplicate flags sampled at checkpoints."""
    events = []
    missing_logs = []
    hosts = {info["mac"]: name for name, info in run["robots"].items()}
    for leaf, settings in run.get("dad_settings", {}).items():
        path = folder / "router_logs" / f"{leaf}-zebra.log"
        if not path.is_file():
            missing_logs.append(leaf)
            continue
        for line in path.read_text(errors="replace").splitlines():
            match = re.search(r"VNI 1000: MAC ([0-9a-f:]+) detected as duplicate during", line, re.I)
            if match and match[1].lower() in hosts:
                events.append({
                    "leaf": leaf, "robot": hosts[match[1].lower()],
                    "freeze_configured": settings.get("isDetectionFreeze"), "log": line,
                })
    samples = []
    for phase, state in checkpoints:
        for leaf, data in state.items():
            for mac, entry in data.get("macs", {}).items():
                if entry and entry.get("isDuplicate"):
                    samples.append({
                        "checkpoint": phase, "leaf": leaf, "robot": hosts[mac],
                        "freeze_configured": run.get("dad_settings", {}).get(leaf, {}).get(
                            "isDetectionFreeze"
                        ),
                    })
    return {"events": events, "duplicate_samples": samples, "missing_zebra_logs": missing_logs}


def session_changes(checkpoints):
    """Track each adjacency once, using its spine-side counters."""
    baseline = checkpoints[0][1]
    results = {}
    for spine in ("spine1", "spine2"):
        before = (baseline.get(spine, {}).get("peers") or {})
        for peer, first in before.items():
            states = [(phase, (view.get(spine, {}).get("peers") or {}).get(peer, {}))
                      for phase, view in checkpoints]
            drops = [peer_state.get("connectionsDropped") for _, peer_state in states]
            opened = [peer_state.get("connectionsEstablished") for _, peer_state in states]
            available = all(isinstance(n, int) for n in drops + opened)
            monotonic = available and drops == sorted(drops) and opened == sorted(opened)
            results[f"{spine}/{peer}"] = {
                "down_checkpoints": [phase for phase, peer_state in states
                                     if peer_state.get("state") not in (None, "Established")],
                "missing_checkpoints": [phase for phase, peer_state in states if not peer_state],
                "drops": drops[-1] - first["connectionsDropped"] if monotonic else None,
                "establishments": opened[-1] - first["connectionsEstablished"] if monotonic else None,
                "counter_reset": available and not monotonic,
            }
    return results


def analyze(folder):
    folder = Path(folder)
    run = json.loads((folder / "movement.json").read_text())
    rows, errors = route_events(folder, run)
    batches = run["batches"]
    checkpoints = [("before", run.get("before", {}))]
    locations = {host: info["home"] for host, info in run["robots"].items()}
    planned = sum(len(batch["moves"]) for batch in run["plan"])
    completed_by_host, correct_by_host = Counter(), Counter()
    counts_by_host = defaultdict(Counter)
    sequences = defaultdict(list)
    batch_results = []
    learning_timeouts = []
    for batch in batches:
        batch_id = batch["batch"]
        state = batch.get("state", {})
        checkpoints.append((f"batch-{batch_id}", state))
        for move in batch["moves"]:
            locations[move["robot"]] = move["actual_leaf"]
        mappings = locations_at(state, run, locations)
        completed = [move for move in batch["moves"] if move["status"] == "completed"]
        for move in completed:
            host = move["robot"]
            if move.get("learning_ok") is False:
                learning_timeouts.append({
                    "batch": batch_id, "robot": host, "error": move["learning_error"],
                })
            completed_by_host[host] += 1
            correct_by_host[host] += mappings[host]["correct"]

        # Count per-session wire copies from both spines. For an origin estimate,
        # use the larger count for each matching event identity across the spines.
        copies = defaultdict(Counter)
        for row in rows:
            if not batch["start"] <= row["unix_time"] < batch.get("end", float("inf")):
                continue
            row["batch"] = batch_id
            if not row["originated"]:
                continue
            identity = tuple(row[key] for key in ("robot", "peer", "rd", "ip", "action",
                                                  "kind", "sequence"))
            copies[identity][row["capture"]] += 1
        for (host, leaf, rd, ip, action, kind, sequence), per_spine in copies.items():
            counts_by_host[host][f"{action} {kind}"] += max(per_spine.values())
            if sequence is not None and action == "advertise":
                sequences[host].append(dict(batch=batch_id, leaf=leaf, rd=rd, ip=ip, value=sequence))
        launches = [move["started"] for move in batch["moves"] if "started" in move]
        batch_results.append({
            "batch": batch_id, "launch_spread_ms": round((max(launches) - min(launches)) * 1000, 3)
            if launches else None,
            "completed": len(completed), "correct": sum(mappings[m["robot"]]["correct"] for m in completed),
            "mappings": mappings,
        })

    checkpoints.append(("after", run.get("after", {})))
    final = locations_at(checkpoints[-1][1], run, locations)
    totals = Counter()
    for counts in counts_by_host.values():
        totals.update(counts)
    completed = sum(completed_by_host.values())
    correct = sum(correct_by_host.values())
    dad = dad_evidence(folder, run, checkpoints)
    sessions = session_changes(checkpoints)
    summary = {
        "moves_planned": planned, "moves_completed": completed, "batch_mappings_correct": correct,
        "mobility_success_rate": correct / completed if completed else None,
        "final_mappings_correct": sum(view["correct"] for view in final.values()),
        "final_mappings": final, "batches": batch_results,
        "origin_nlri_estimate": dict(totals),
        "wire_nlri_counts": {
            spine: dict(Counter(f"{row['direction']} {row['action']} {row['kind']}"
                                for row in rows if row["capture"] == spine and "batch" in row))
            for spine in run["spine_peers"]
        },
        "evpn_route_counts": {phase: {node: data["num_routes"] for node, data in view.items()}
                              for phase, view in checkpoints},
        "dad": dad, "bgp_sessions": sessions, "capture_errors": errors,
        "learning_errors": learning_timeouts,
        "robots": {
            host: {"moves_completed": completed_by_host[host], "correct_mappings": correct_by_host[host],
                   "origin_nlri_estimate": dict(counts_by_host[host]), "sequence_observations": sequences[host]}
            for host in locations
        },
    }
    out = folder / "analysis"
    out.mkdir(exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    fields = ("batch", "capture", "frame", "unix_time", "direction", "peer", "originated",
              "robot", "mac", "action", "rd", "ip", "kind", "next_hop", "sequence")
    with (out / "rt2_events.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Multiple Robot Movement Results", "",
        f"- Completed attachments: {completed}/{planned}.",
        f"- Correct observer mappings at batch checkpoints: {correct}/{completed}.",
        f"- Correct observer mappings at the final checkpoint: {summary['final_mappings_correct']}/{len(final)}.",
        f"- Type 2 origin event estimates: {dict(totals)}.",
        f"- Learning ARP errors: {len(learning_timeouts)} "
        "(see the move log for each error).",
        f"- Matching Zebra duplicate detection log entries: {len(dad['events'])}.",
        f"- Duplicate flags observed at checkpoints: {len(dad['duplicate_samples'])}.",
        f"- Observed BGP session drops: {sum(item['drops'] or 0 for item in sessions.values())} "
        f"across {sum(item['drops'] is not None for item in sessions.values())}/{len(sessions)} tracked peers.",
    ]
    for batch in batch_results:
        mismatches = [f"{host} (expected {view['expected_vtep']}, saw {view['observed_vtep']})"
                      for host, view in batch["mappings"].items() if not view["correct"]]
        if mismatches:
            lines.append(f"- Batch {batch['batch']} mismatches: {', '.join(mismatches)}.")
            for host, mapping in batch["mappings"].items():
                if mapping["correct"]:
                    continue
                batch_id = batch["batch"]
                robot_rows = [row for row in rows if row.get("batch") == batch_id
                              and row["robot"] == host and row["originated"]]
                if any(item["batch"] == batch_id and item["robot"] == host
                       for item in learning_timeouts):
                    lines.append(f"- {host} also had a learning ARP error in batch {batch_id}.")
                if not errors and mapping["actual_leaf"] and not any(
                    row["action"] == "advertise" and row["peer"] == mapping["actual_leaf"]
                    for row in robot_rows
                ):
                    lines.append(
                        f"- The spine captures show no originating Type 2 advertisement "
                        f"from {mapping['actual_leaf']} for {host} in batch {batch_id}."
                    )
    if errors:
        lines.append(f"- Capture decode errors: {errors}.")
    if dad["missing_zebra_logs"]:
        lines.append(f"- Missing Zebra logs: {', '.join(dad['missing_zebra_logs'])}.")
    lines += [
        "", "Batch checkpoints verify selected locations after the configured dwell. "
        "Transient state between checkpoints may go unobserved. The origin estimate groups "
        "matching copies across spines within each batch. DAD freeze policy is recorded separately "
        "from observed duplicate state. Use the captures and router logs to investigate mismatches.",
    ]
    (out / "report.md").write_text("\n".join(lines) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_folder", type=Path)
    args = parser.parse_args()
    analyze(args.run_folder)
    print(args.run_folder / "analysis" / "report.md")
