"""Analyze the seven EVPN metrics and MBB ordering in a saved run."""

import argparse
import importlib.util
import csv
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
# Keep standalone reanalysis working after the BBM folder rename.
_base_spec = importlib.util.spec_from_file_location(
    "mbb_base_analyzer",
    Path(__file__).resolve().parent.parent / "multiple_robot_movement - BBM" / "analyze_movement.py",
)
base = importlib.util.module_from_spec(_base_spec)
_base_spec.loader.exec_module(base)


def captured_arps(folder, leaves):
    """Return incoming gateway ARPs with their Linux interface index."""
    result, errors = {}, {}
    for leaf in leaves:
        try:
            fields = ["frame.number", "frame.time_epoch", "arp.src.hw_mac",
                      "sll.ifindex", "sll.pkttype"]
            command = [
                "tshark", "-n", "-r", str(folder / f"{leaf}-arp.pcap"),
                "-Y", "arp.opcode == 1 && arp.dst.proto_ipv4 == 45.0.0.1",
                "-T", "fields", "-E", "occurrence=f",
            ]
            for field in fields:
                command.extend(["-e", field])
            output = subprocess.run(command, text=True, capture_output=True, check=True)
            result[leaf] = []
            for line in output.stdout.splitlines():
                frame, stamp, mac, index, direction = line.split("\t")
                result[leaf].append({
                    "frame": int(frame), "time": float(stamp), "mac": mac,
                    "ifindex": int(index) if index else None, "direction": direction,
                })
        except Exception as exc:
            errors[leaf] = str(exc)
    return result, errors


def analyze(folder):
    folder = Path(folder)
    summary = base.analyze(folder)
    run = json.loads((folder / "movement.json").read_text())
    events, _ = base.route_events(folder, run)
    arps, arp_errors = captured_arps(folder, run["vteps"])
    samples = []
    observer_file = folder / "observer.jsonl"
    if observer_file.is_file():
        samples = [json.loads(line) for line in observer_file.read_text().splitlines()]
    checks = []
    for batch in run["batches"]:
        for move in batch["moves"]:
            host = move["robot"]
            mac = run["robots"][host]["mac"]
            ready, removed = move.get("new_link_ready"), move.get("old_link_removed")
            switched, sent = move.get("active_switched"), move.get("send_end")
            valid = bool(
                move["status"] == "completed" and
                all(value is not None for value in (ready, switched, sent, removed)) and
                ready <= switched <= sent <= removed and
                removed - sent >= run["hold_after_arp_s"]
            )
            usable = {run["vteps"].get(move["old_leaf"]), run["vteps"].get(move["new_leaf"])}
            selected, unusable, errors = 0, 0, 0
            if valid:
                window = [sample for sample in samples
                          if ready <= sample["sample_start"] and sample["sample_end"] <= removed]
                for sample in window:
                    if "error" in sample:
                        errors += 1
                        continue
                    entry = sample["macs"].get(mac) or {}
                    observed = entry.get("remoteVtep") if entry.get("type") == "remote" else None
                    selected += observed == run["vteps"][move["new_leaf"]]
                    unusable += observed not in usable

            route_rows = [row for row in events if valid and row["robot"] == host
                          and row["originated"] and ready <= row["unix_time"] < removed]
            access_index = run.get("leaf_ports", {}).get(move["new_leaf"], {}).get(host)
            arp_rows = [row for row in arps.get(move["new_leaf"], []) if valid and
                        row["mac"] == mac and row["ifindex"] == access_index and
                        row["direction"] != "4" and switched <= row["time"] < removed]
            checks.append({
                "batch": batch["batch"], "robot": host, "status": move["status"],
                "mbb_order_verified": valid,
                "physical_overlap_ms": round((removed - ready) * 1000, 3) if valid else None,
                "hold_after_arp_ms": round((removed - sent) * 1000, 3) if valid else None,
                "new_leaf_arp_before_break": bool(arp_rows),
                "arp_frames": ";".join(str(row["frame"]) for row in arp_rows),
                "new_leaf_advert_before_break": any(row["action"] == "advertise" and
                                                    row["peer"] == move["new_leaf"] for row in route_rows),
                "old_leaf_withdraw_before_break": any(row["action"] == "withdraw" and
                                                      row["peer"] == move["old_leaf"] for row in route_rows),
                "new_vtep_samples_during_overlap": selected,
                "unusable_mapping_samples_during_overlap": unusable,
                "observer_error_samples": errors,
            })
    summary["mbb"] = {
        "valid_overlaps": sum(row["mbb_order_verified"] for row in checks),
        "new_leaf_arp_before_break": sum(row["new_leaf_arp_before_break"] for row in checks),
        "new_advert_before_break": sum(row["new_leaf_advert_before_break"] for row in checks),
        "arp_capture_errors": arp_errors,
        "observer_samples": len(samples),
        "observer_errors": sum("error" in sample for sample in samples),
        "moves": checks,
    }
    out = folder / "analysis"
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with (out / "mbb_checks.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(checks[0]) if checks else ["batch", "robot"])
        writer.writeheader()
        writer.writerows(checks)
    report = (out / "report.md").read_text()
    report = report.replace("# Multiple Robot Movement Results", "# MBB Multiple Robot Movement Results")
    report = report.replace("Learning ARP errors:", "Learning ARP send errors:")
    report += (
        "\n\n## Make-before-break evidence\n\n"
        f"- Verified attachment and announcement ordering in {summary['mbb']['valid_overlaps']} moves.\n"
        f"- Gateway ARP observed on the new access port before the old link went down in "
        f"{summary['mbb']['new_leaf_arp_before_break']} moves.\n"
        f"- New-leaf originating advertisement observed at a spine before the old link went down in "
        f"{summary['mbb']['new_advert_before_break']} moves.\n"
        f"- Recorded {len(samples)} observer samples and {summary['mbb']['observer_errors']} query errors.\n\n"
        "The attachment overlap uses a Linux active-backup bond. Its IP and MAC stay on bond0. "
        "The old and new links can receive during overlap, while the new link is selected for transmission. "
        "Overlap samples accept either attached VTEP, and batch checkpoints require the destination VTEP. "
        "Timing records bracket commands and queries. The leaf ARP captures verify the learning stimulus "
        "on the new access port. Snapshot and polling coverage can miss short-lived state changes.\n"
    )
    if arp_errors:
        report += f"\nARP capture decode errors were recorded for {', '.join(arp_errors)}.\n"
    (out / "report.md").write_text(report)
    print(f"MBB report: {out / 'report.md'}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_folder", type=Path)
    analyze(parser.parse_args().run_folder)
