#!/usr/bin/env python3
"""
resource_monitor.py - record CPU, memory and table sizes on every spine and leaf
while a bgp_evpn_capstone topotest is running.

Put this file in tests/topotests/bgp_evpn_capstone/ and start it from inside a
test, next to the existing pollers and captures:

    from bgp_evpn_capstone.resource_monitor import ResourceMonitor

    monitor = ResourceMonitor(topology, out)      # out = the capture folder
    monitor.start()
    ...                                           # move robots
    monitor.stop()                                # put this in the "finally:" block

or:  with ResourceMonitor(topology, out): ...

It only looks at the routers (spine1/2, leaf1..5), never at the hosts. Two
background threads write two CSV files, one row per switch per sample. All
timestamps are time.time(), the same clock as events.json and the pcaps.

resources-system.csv   every MONITOR_INTERVAL_S (default 1 s)
    Read straight from the kernel inside each switch's namespace. FRR is not
    asked anything, so sampling does not add work to the daemons it measures.
      <daemon>_cpu_pct     CPU used since the previous sample; 100 = one full core
      <daemon>_rss_kb      resident memory
      <daemon>_threads     thread count
      <daemon>_pid         changes if the daemon restarted (a crash)
      k_fdb_local          robot/host MACs learned on this leaf's own ports
      k_fdb_remote         MACs installed from EVPN, pointing at another leaf
      k_fdb_leftover       local MACs that still carry an old EVPN entry pointing
                           at another leaf (left behind after a robot moved in)
      k_fdb_rmacs          router MACs of other leaves on the L3VNI
      k_neigh_local        ARP entries this leaf learned itself
      k_neigh_evpn         ARP entries installed from EVPN (hosts on other leaves)
      k_neigh_failed       ARP entries stuck FAILED / INCOMPLETE
      k_l3_nexthops        other leaves reachable through the L3VNI
      k_vrf_routes         BGP routes installed in the tenant VRF (VRF500)
      k_vrf_host_routes    of those, host routes (/32) - one per remote robot
      k_underlay_routes    BGP routes in the default table (loopbacks)
      host_cpu_pct         whole machine, 0-100; every switch shares this machine
      host_mem_avail_mb    whole machine
      sweep_ms             how long sampling all switches took (the monitor's cost)

resources-frr.csv      every MONITOR_FRR_INTERVAL_S (default 5 s; 0 = off)
    Asked from FRR with vtysh. These queries cost bgpd/zebra a little work, so
    they run less often and in their own thread: if FRR is slow to answer, the
    system samples above keep their rhythm.
      bgp_peers_up / bgp_peers            EVPN sessions Established / configured
      bgp_msgs_rcvd / bgp_msgs_sent       BGP messages, running totals
      bgp_inq / bgp_outq                  messages waiting, summed over peers
      bgp_evpn_pfx_rcvd / _sent           EVPN prefixes, summed over peers
      bgp_evpn_prefixes / bgp_evpn_paths  size of the EVPN table (routes / paths)
      bgp_bestpath_runs                   best-path computations, running total
      evpn_l2_macs / evpn_l2_neighs       zebra's MAC and ARP tables (L2 VNIs)
      evpn_remote_vteps                   remote VTEPs known on the L2 VNIs
      evpn_l3_rmacs / evpn_l3_nexthops    L3VNI router MACs and next hops
      query_ms                            how long this switch took to answer

Live dashboard: ENABLE_LIVE_RESOURCE_GRAPH=true (default) publishes to
VISUALIZER_EVENT_URL (default http://127.0.0.1:5000/event). Network I/O
runs separately from sampling. CSV files are always recorded.

Running totals (msgs, bestpath_runs) only ever grow; subtract consecutive rows
to get a rate. Blank cells mean "could not be read" (see the error column).
"""
import csv
import json
import queue
import urllib.request
import os
import threading
import time
from pathlib import Path

INTERVAL_S = float(os.environ.get("MONITOR_INTERVAL_S", "1.0"))
FRR_INTERVAL_S = float(os.environ.get("MONITOR_FRR_INTERVAL_S", "5.0"))
MIN_INTERVAL_S = 0.2

DAEMONS = ("bgpd", "zebra")
CLK_TCK = os.sysconf("SC_CLK_TCK")                  # kernel CPU accounting unit (100/s)
PAGE_KB = os.sysconf("SC_PAGE_SIZE") / 1024.0

# One shell command per switch per sample. Daemon stats come from bash builtins
# (no extra processes); "@@" lines separate the sections for parse_sample().
_SCRIPT = r"""
echo "@@T ${EPOCHREALTIME:-}"
for d in %(daemons)s; do
  { read -r p < %(rundir)s/$d.pid && read -r s < /proc/$p/stat; } 2>/dev/null && echo "@@P $d $s"
done
echo "@@S fdb";      bridge fdb show 2>/dev/null
echo "@@S neigh";    ip -4 neigh show 2>/dev/null
echo "@@S vrf";      ip -4 route show vrf %(vrf)s 2>/dev/null
echo "@@S underlay"; ip -4 route show proto bgp 2>/dev/null
true
"""


# ----------------------------------------------------------------- parsing ---
def parse_sample(text):
    """Split the script output into {'t': float|None, 'procs': {}, 'sections': {}}."""
    out = {"t": None, "procs": {}, "sections": {}}
    section = None
    for line in text.splitlines():
        if line.startswith("@@T"):
            stamp = line[3:].strip().replace(",", ".")
            out["t"] = float(stamp) if stamp else None
        elif line.startswith("@@P "):
            _, daemon, stat = line.split(" ", 2)
            out["procs"][daemon] = stat
        elif line.startswith("@@S "):
            section = out["sections"].setdefault(line[4:].strip(), [])
        elif section is not None:
            section.append(line)
    return out


def parse_proc_stat(stat):
    """One /proc/<pid>/stat line -> pid, CPU ticks (all threads), threads, RSS pages."""
    if not stat:
        return None
    pid = int(stat.split(" ", 1)[0])
    rest = stat[stat.rindex(")") + 2:].split()      # the name may contain spaces
    return {"pid": pid, "ticks": int(rest[11]) + int(rest[12]),   # utime + stime
            "threads": int(rest[17]), "rss_pages": int(rest[21])}


def count_fdb(lines, l3_devs):
    """'bridge fdb show' -> distinct MACs: learned locally, from EVPN, L3VNI router MACs."""
    local, remote, rmacs = set(), set(), set()
    for line in lines:
        p = line.split()
        if len(p) < 3 or p[1] != "dev" or "permanent" in p or p[0] == "00:00:00:00:00:00":
            continue
        mac, dev = p[0], p[2]
        master = p[p.index("master") + 1] if "master" in p[:-1] else None
        if "extern_learn" in p:                     # installed by zebra from an EVPN route
            (rmacs if dev in l3_devs or master in l3_devs else remote).add(mac)
        elif master and master not in l3_devs:      # learned from traffic on a bridge port
            local.add(mac)
    # A MAC that is local here can still carry old EVPN entries from before it
    # moved in. The bridge forwards to the local port, so count it as local and
    # report the old entries separately.
    return {"k_fdb_local": len(local), "k_fdb_remote": len(remote - local),
            "k_fdb_leftover": len(remote & local), "k_fdb_rmacs": len(rmacs)}


def count_neigh(lines, l3_devs):
    """'ip -4 neigh show' -> ARP entries by where they came from."""
    c = {"k_neigh_local": 0, "k_neigh_evpn": 0, "k_neigh_failed": 0, "k_l3_nexthops": 0}
    for line in lines:
        p = line.split()
        if len(p) < 4 or p[1] != "dev" or ":" in p[0]:    # skip IPv6 neighbours
            continue
        if "extern_learn" in p:
            c["k_l3_nexthops" if p[2] in l3_devs else "k_neigh_evpn"] += 1
        elif "FAILED" in p or "INCOMPLETE" in p:
            c["k_neigh_failed"] += 1
        elif "PERMANENT" not in p and "NOARP" not in p:
            c["k_neigh_local"] += 1
    return c


def count_routes(lines):
    """'ip route show' -> (BGP routes, BGP host routes). Indented lines are extra next hops."""
    bgp = host = 0
    for line in lines:
        if not line or line[0] in " \t" or " proto bgp" not in line:
            continue
        bgp += 1
        if "/" not in line.split()[0]:              # the kernel prints a /32 without "/32"
            host += 1
    return bgp, host


def _int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def parse_bgp_summary(data):
    """'show bgp l2vpn evpn summary json' -> totals over all peers."""
    peers = [p for p in (data or {}).get("peers", {}).values() if isinstance(p, dict)]
    total = lambda key: sum(_int(p.get(key)) for p in peers)  # noqa: E731
    return {"bgp_peers": len(peers),
            "bgp_peers_up": sum(1 for p in peers if p.get("state") == "Established"),
            "bgp_msgs_rcvd": total("msgRcvd"), "bgp_msgs_sent": total("msgSent"),
            "bgp_inq": total("inq"), "bgp_outq": total("outq"),
            "bgp_evpn_pfx_rcvd": total("pfxRcd"), "bgp_evpn_pfx_sent": total("pfxSnt")}


def parse_bgp_stats(data):
    """'show bgp l2vpn evpn statistics json' -> table size and best-path counter."""
    pending = [data]
    while pending:
        entry = pending.pop()
        if isinstance(entry, list):
            pending.extend(entry)
        elif isinstance(entry, dict):
            if "totalPrefixes" in entry:
                result = {"bgp_evpn_prefixes": _int(entry["totalPrefixes"])}
                for column, key in (("bgp_evpn_paths", "totalAdvertisements"),
                                    ("bgp_bestpath_runs", "bgpBestPathCalls")):
                    if key in entry:
                        result[column] = _int(entry[key])
                return result
            pending.extend(entry.values())
    return {}


def parse_evpn_vni(data):
    """'show evpn vni json' -> zebra's EVPN table sizes. Empty on a spine (no VNIs)."""
    vnis = [v for v in (data or {}).values() if isinstance(v, dict) and "type" in v]
    if not vnis:
        return {}
    l2 = [v for v in vnis if v["type"] == "L2"]
    l3 = [v for v in vnis if v["type"] == "L3"]
    return {"evpn_l2_macs": sum(_int(v.get("numMacs")) for v in l2),
            "evpn_l2_neighs": sum(_int(v.get("numArpNd")) for v in l2),
            "evpn_remote_vteps": max([_int(v.get("numRemoteVteps")) for v in l2], default=0),
            "evpn_l3_rmacs": sum(_int(v.get("numMacs")) for v in l3),
            "evpn_l3_nexthops": sum(_int(v.get("numArpNd")) for v in l3)}


class _LivePublisher(threading.Thread):
    """Publish bounded batches off the sampling threads; CSVs work without a server."""

    def __init__(self, url, label):
        super().__init__(daemon=True)
        self.url, self.label = url, label
        self.pending = queue.Queue(maxsize=64)

    def submit(self, kind, rows, state="running"):
        event = {"action": "RESOURCE_SAMPLE", "kind": kind, "rows": rows,
                 "state": state, "label": self.label, "sent_at": time.time()}
        try:
            self.pending.put_nowait(event)
        except queue.Full:
            # Keep recent live data if the server is slow. The CSV keeps every row.
            try:
                self.pending.get_nowait()
            except queue.Empty:
                pass
            self.pending.put_nowait(event)

    def post(self, event):
        request = urllib.request.Request(
            self.url, data=json.dumps(event, allow_nan=False).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=0.5) as response:
            response.read()

    def run(self):
        reset, warned = False, False
        while True:
            event = self.pending.get()
            try:
                if not reset:
                    self.post({"action": "RESOURCE_RESET"})
                    reset = True
                self.post(event)
            except (OSError, ValueError) as exc:
                if not warned:
                    print("Resource dashboard unavailable; CSV recording continues: {}".format(exc),
                          flush=True)
                    warned = True
            if event["state"] == "complete":
                return


# ---------------------------------------------------------------- samplers ---
class _Sampler(threading.Thread):
    """Call sweep() on a fixed time grid and append its rows to one CSV file."""

    columns = []

    def __init__(self, path, interval, started):
        super().__init__(daemon=True)
        self.path, self.interval, self.started = path, max(MIN_INTERVAL_S, interval), started
        self.halt = threading.Event()
        self.publish = None

    def sweep(self):
        raise NotImplementedError

    def run(self):
        begin = time.monotonic()
        with open(self.path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=self.columns, restval="", extrasaction="ignore")
            writer.writeheader()
            while not self.halt.is_set():
                t0 = time.monotonic()
                rows = self.sweep()
                took = round((time.monotonic() - t0) * 1000, 1)
                for row in rows:
                    row.setdefault("sweep_ms", took)
                    row["t_s"] = round(row["t_unix"] - self.started, 3)
                    writer.writerow(row)
                fh.flush()                          # a crashed run still keeps its data
                if self.publish:
                    self.publish("system" if isinstance(self, _SystemSampler) else "frr", rows)
                # Sleep to the next grid point; if a sweep overran, skip the missed ones.
                tick = int((time.monotonic() - begin) / self.interval) + 1
                self.halt.wait(max(0.0, begin + tick * self.interval - time.monotonic()))

    def stop(self):
        self.halt.set()
        self.join(timeout=30)


class _SystemSampler(_Sampler):
    """CPU and memory of the FRR daemons plus kernel table sizes - no FRR involvement."""

    def __init__(self, tgen, nodes, path, interval, started, daemons, vrf, l3_devs, rundir):
        super().__init__(path, interval, started)
        self.tgen, self.nodes, self.daemons, self.l3_devs = tgen, nodes, daemons, set(l3_devs)
        self.script = _SCRIPT % {"daemons": " ".join(daemons), "rundir": rundir, "vrf": vrf}
        self.prev = {}                              # node -> daemon -> (time, stat)
        self.prev_host = None
        self.columns = ["t_unix", "t_s", "node", "host_cpu_pct", "host_mem_avail_mb"]
        for d in daemons:
            self.columns += [d + "_cpu_pct", d + "_rss_kb", d + "_threads", d + "_pid"]
        self.columns += ["k_fdb_local", "k_fdb_remote", "k_fdb_leftover", "k_fdb_rmacs", "k_neigh_local",
                         "k_neigh_evpn", "k_neigh_failed", "k_l3_nexthops", "k_vrf_routes",
                         "k_vrf_host_routes", "k_underlay_routes", "sweep_ms", "error"]

    def host(self):
        """Whole-machine CPU since the last sweep, and available memory."""
        out = {}
        try:
            with open("/proc/stat") as fh:
                v = [int(x) for x in fh.readline().split()[1:9]]
            cur = (sum(v), v[3] + v[4])             # total, idle + iowait
            if self.prev_host and cur[0] > self.prev_host[0]:
                busy = 1.0 - (cur[1] - self.prev_host[1]) / (cur[0] - self.prev_host[0])
                out["host_cpu_pct"] = round(100.0 * busy, 1)
            self.prev_host = cur
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemAvailable:"):
                        out["host_mem_avail_mb"] = int(line.split()[1]) // 1024
                        break
        except (OSError, ValueError, IndexError):
            pass
        return out

    def sweep(self):
        host, rows = self.host(), []
        for name in self.nodes:
            row = dict(host, node=name, t_unix=time.time())
            try:
                _, text, _ = self.tgen.net[name].cmd_status(self.script, warn=False)
                sample = parse_sample(text)
                now = sample["t"] or time.time()    # stamped inside the switch if bash >= 5
                row["t_unix"] = round(now, 6)
                seen = {}
                for d in self.daemons:
                    stat = parse_proc_stat(sample["procs"].get(d))
                    if stat is None:                # daemon not running: leave its cells blank
                        continue
                    seen[d] = (now, stat)
                    row[d + "_pid"] = stat["pid"]
                    row[d + "_threads"] = stat["threads"]
                    row[d + "_rss_kb"] = int(stat["rss_pages"] * PAGE_KB)
                    before = self.prev.get(name, {}).get(d)
                    if before and before[1]["pid"] == stat["pid"] and now > before[0]:
                        used_s = (stat["ticks"] - before[1]["ticks"]) / CLK_TCK
                        row[d + "_cpu_pct"] = round(100.0 * used_s / (now - before[0]), 1)
                self.prev[name] = seen
                sections = sample["sections"]
                row.update(count_fdb(sections.get("fdb", []), self.l3_devs))
                row.update(count_neigh(sections.get("neigh", []), self.l3_devs))
                row["k_vrf_routes"], row["k_vrf_host_routes"] = count_routes(sections.get("vrf", []))
                row["k_underlay_routes"] = count_routes(sections.get("underlay", []))[0]
            except Exception as exc:  # pylint: disable=broad-except
                row["error"] = str(exc)[:200]       # switch starting/stopping: keep going
            rows.append(row)
        return rows


class _FrrSampler(_Sampler):
    """BGP and EVPN table sizes and counters, asked from FRR with vtysh."""

    columns = ["t_unix", "t_s", "node", "bgp_peers_up", "bgp_peers", "bgp_msgs_rcvd",
               "bgp_msgs_sent", "bgp_inq", "bgp_outq", "bgp_evpn_pfx_rcvd", "bgp_evpn_pfx_sent",
               "bgp_evpn_prefixes", "bgp_evpn_paths", "bgp_bestpath_runs", "evpn_l2_macs",
               "evpn_l2_neighs", "evpn_remote_vteps", "evpn_l3_rmacs", "evpn_l3_nexthops",
               "query_ms", "error"]
    queries = [("show bgp l2vpn evpn summary json", "bgpd", parse_bgp_summary),
               ("show bgp l2vpn evpn statistics json", "bgpd", parse_bgp_stats),
               ("show evpn vni json", "zebra", parse_evpn_vni)]

    def __init__(self, tgen, nodes, path, interval, started):
        super().__init__(path, interval, started)
        self.tgen, self.nodes = tgen, nodes

    def sweep(self):
        rows = []
        for name in self.nodes:
            t0 = time.monotonic()
            row = {"node": name, "t_unix": round(time.time(), 6)}
            try:
                router = self.tgen.gears[name]
                for command, daemon, parse in self.queries:
                    row.update(parse(router.vtysh_cmd(command, isjson=True, daemon=daemon)))
            except Exception as exc:  # pylint: disable=broad-except
                row["error"] = str(exc)[:200]
            row["query_ms"] = round((time.monotonic() - t0) * 1000, 1)
            rows.append(row)
        return rows


# ------------------------------------------------------------------ public ---
class ResourceMonitor:
    """Record resources on every router of a running topotest. See the module docstring.

    tgen          the Topogen object (get_topogen())
    out_dir       folder for the two CSV files (created if missing)
    interval      seconds between system samples (MONITOR_INTERVAL_S, default 1)
    frr_interval  seconds between FRR samples (MONITOR_FRR_INTERVAL_S, default 5; 0 = off)
    nodes         router names; default = every router in the topology (no hosts)
    daemons       FRR daemons to track; add "mgmtd" / "staticd" if you want them
    vrf, l3_devs  tenant VRF and the L3VNI bridge + VXLAN device, as built by
                  test_evpn_capstone._setup_leaf_dataplane()
    """

    def __init__(self, tgen, out_dir, interval=INTERVAL_S, frr_interval=FRR_INTERVAL_S,
                 nodes=None, daemons=DAEMONS, vrf="VRF500", l3_devs=("br500", "vni500"),
                 rundir="/var/run/frr"):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        nodes = list(nodes) if nodes else sorted(tgen.routers().keys())
        started = time.time()
        self.samplers = [_SystemSampler(tgen, nodes, self.out_dir / "resources-system.csv",
                                        interval, started, tuple(daemons), vrf, l3_devs, rundir)]
        if frr_interval and frr_interval > 0:
            self.samplers.append(_FrrSampler(tgen, nodes, self.out_dir / "resources-frr.csv",
                                             frr_interval, started))

    def start(self):
        enabled = os.environ.get("ENABLE_LIVE_RESOURCE_GRAPH", "true").lower()
        self.publisher = None
        if enabled in ("1", "true", "yes", "on"):
            self.publisher = _LivePublisher(
                os.environ.get("VISUALIZER_EVENT_URL", "http://127.0.0.1:5000/event"),
                str(self.out_dir))
            self.publisher.start()
        for sampler in self.samplers:
            sampler.publish = self.publisher.submit if self.publisher else None
            sampler.start()
        return self

    def stop(self):
        for sampler in self.samplers:
            sampler.halt.set()                      # tell both first, then wait for both
        for sampler in self.samplers:
            if sampler.is_alive():
                sampler.stop()
        if getattr(self, "publisher", None):
            self.publisher.submit("status", [], state="complete")
            self.publisher.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False