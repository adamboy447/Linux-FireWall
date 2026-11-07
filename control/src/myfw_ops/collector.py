"""myfw-collector: low-privileged event and metrics collection.

Runs as its own user in group myfw-read; it can only use the agent's read
operations. Every INTERVAL seconds it:
  * reads events since its cursor (persisted), appends them to JSONL files
    (rotated by size and age, bounded total), and records a `gap` line with
    the number of lost events when the kernel ring overwrote some, or when the
    module was reloaded (sequence numbers restarted);
  * caches counters/status for the metrics endpoint.

Metrics (127.0.0.1:9108/metrics) follow the semantics in docs/observability.md.
When the last collection failed, traffic metrics are NOT exported as zero:
they are omitted and myfw_up / myfw_collector_up say why.
"""
from __future__ import annotations

import glob
import json
import os
import sys
import threading
import time

from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY, CounterMetricFamily, GaugeMetricFamily

from . import client
from .abi import DROP_REASONS

INTERVAL = float(os.environ.get("MYFW_COLLECT_INTERVAL", "5"))
LOG_DIR = os.environ.get("MYFW_LOG_DIR", "/var/log/myfw")
CURSOR = os.environ.get("MYFW_COLLECTOR_CURSOR", "/var/lib/myfw-collector/cursor.json")
MAX_FILE_BYTES = int(os.environ.get("MYFW_LOG_FILE_BYTES", str(10 * 1024 * 1024)))
MAX_TOTAL_BYTES = int(os.environ.get("MYFW_LOG_TOTAL_BYTES", str(200 * 1024 * 1024)))
MAX_AGE_S = float(os.environ.get("MYFW_LOG_MAX_AGE", str(3 * 86400)))
LISTEN = os.environ.get("MYFW_METRICS_LISTEN", "127.0.0.1:9108")


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = False
        self.error = "not collected yet"
        self.last_success = 0.0
        self.counters = None
        self.status = None
        self.zone_names = {}
        self.lost_total = 0
        self.gaps_total = 0
        self.events_written = 0
        self.verify = None
        self.history = []


S = State()


def load_cursor() -> dict:
    try:
        with open(CURSOR) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"next_seq": 0, "boot_id": None, "lost_total": 0, "gaps_total": 0}


def save_cursor(c: dict) -> None:
    os.makedirs(os.path.dirname(CURSOR), exist_ok=True)
    tmp = CURSOR + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, CURSOR)


def _current_file() -> str:
    return os.path.join(LOG_DIR, time.strftime("events-%Y%m%d.jsonl"))


def rotate() -> None:
    files = sorted(glob.glob(os.path.join(LOG_DIR, "events-*.jsonl*")), key=os.path.getmtime)
    now = time.time()
    total = sum(os.path.getsize(f) for f in files)
    for f in list(files):
        if now - os.path.getmtime(f) > MAX_AGE_S or total > MAX_TOTAL_BYTES:
            total -= os.path.getsize(f)
            os.unlink(f)
            files.remove(f)
    cur = _current_file()
    if os.path.exists(cur) and os.path.getsize(cur) > MAX_FILE_BYTES:
        os.rename(cur, f"{cur}.{int(now)}")


def write_lines(records: list[dict]) -> None:
    if not records:
        return
    os.makedirs(LOG_DIR, exist_ok=True)
    rotate()
    with open(_current_file(), "a") as f:
        for r in records:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def boot_id() -> str:
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read().strip()


def collect_once(cursor: dict) -> dict:
    st = client.call("counters")
    if not st.get("ok"):
        raise RuntimeError(st.get("message", "agent error"))
    show = client.call("show")
    zones = {}
    if show.get("ok") and show.get("canonical"):
        for i, z in enumerate(show["canonical"]["zones"]):
            zones[i + 1] = z["name"]
    zones[0], zones[9] = "none", "local"

    bid = boot_id()
    records = []
    since = cursor["next_seq"]
    status = st["status"]
    if cursor.get("boot_id") != bid or since > status["event_next_seq"]:
        if cursor.get("boot_id") is not None:
            records.append({"type": "gap", "reason": "reboot or module reload: sequence restarted",
                            "time": time.time(), "boot_id": bid, "previous_next_seq": since})
            cursor["gaps_total"] = cursor.get("gaps_total", 0) + 1
        since = 0
    ev = client.call("events", since=since, max=4000)
    if not ev.get("ok"):
        raise RuntimeError(ev.get("message", "events failed"))
    if ev.get("lost"):
        records.append({"type": "gap", "reason": "kernel ring overwrote events before they were read",
                        "lost": ev["lost"], "first_available_seq": ev["first_seq"],
                        "time": time.time(), "boot_id": bid})
        cursor["lost_total"] = cursor.get("lost_total", 0) + ev["lost"]
        cursor["gaps_total"] = cursor.get("gaps_total", 0) + 1
    for e in ev["events"]:
        e = dict(e, type="event", boot_id=bid, zone=zones.get(e.get("zone_slot"), str(e.get("zone_slot"))))
        records.append(e)
    write_lines(records)
    if ev["events"]:
        cursor["next_seq"] = ev["events"][-1]["seq"] + 1
    else:
        cursor["next_seq"] = max(since, ev.get("first_seq", since))
    cursor["boot_id"] = bid
    save_cursor(cursor)

    verify = client.call("last_verify")
    hist = client.call("history", limit=200)
    with S.lock:
        S.ok, S.error, S.last_success = True, "", time.time()
        S.counters, S.status, S.zone_names = st["counters"], status, zones
        S.lost_total, S.gaps_total = cursor.get("lost_total", 0), cursor.get("gaps_total", 0)
        S.events_written += len(ev["events"])
        S.verify = verify.get("verify") if verify.get("ok") else None
        S.history = hist.get("changes", []) if hist.get("ok") else []
        S.agent_status = client.call("status")
    return cursor


class MyfwCollector:
    def collect(self):
        with S.lock:
            up = GaugeMetricFamily("myfw_collector_up", "1 if the last collection succeeded")
            up.add_metric([], 1 if S.ok else 0)
            yield up
            ls = GaugeMetricFamily("myfw_collector_last_success_timestamp_seconds",
                                   "Unix time of the last successful collection")
            ls.add_metric([], S.last_success)
            yield ls
            lost = CounterMetricFamily("myfw_collector_events_lost", "Kernel events lost before collection")
            lost.add_metric([], S.lost_total)
            yield lost
            gaps = CounterMetricFamily("myfw_collector_gaps", "Recorded gaps in the event stream")
            gaps.add_metric([], S.gaps_total)
            yield gaps
            if not S.ok or not S.counters:
                return          # never report missing data as zero traffic
            c, st = S.counters, S.status
            g = lambda n, h, v: (GaugeMetricFamily(n, h, value=v))  # noqa: E731
            yield g("myfw_up", "1 if the kernel module answered", 1)
            yield g("myfw_generation", "Active policy generation (boot-scoped)", st["generation"])
            yield g("myfw_managed", "1 if the active policy is owned by fwctl", 1 if st["managed"] else 0)
            yield g("myfw_connections", "Tracked flows", c["conns"])
            yield g("myfw_connection_limit", "Flow table limit (max_conns)", c["max_conns"])
            yield g("myfw_last_gate_seconds", "Duration of the last commit gate", st["last_gate_ns"] / 1e9)
            yield g("myfw_last_commit_timestamp_seconds", "Time of the last commit",
                    st["last_commit_ns"] / 1e9)
            pk = CounterMetricFamily("myfw_packets", "Final verdicts on managed packets", labels=["verdict"])
            pk.add_metric(["accept"], c["accept_pkts"])
            pk.add_metric(["drop"], c["drop_pkts"])
            yield pk
            by = CounterMetricFamily("myfw_bytes", "Bytes by final verdict", labels=["verdict"])
            by.add_metric(["accept"], c["accept_bytes"])
            by.add_metric(["drop"], c["drop_bytes"])
            yield by
            dr = CounterMetricFamily("myfw_drops", "Dropped packets by reason", labels=["reason"])
            for r in DROP_REASONS[1:]:
                dr.add_metric([r], c["drop_reason"].get(r, 0))
            yield dr
            zp = CounterMetricFamily("myfw_zone_packets", "Final verdicts by ingress zone (since the "
                                     "active generation)", labels=["zone", "verdict"])
            for i, name in S.zone_names.items():
                zp.add_metric([name, "accept"], c["zone_accept"][i])
                zp.add_metric([name, "drop"], c["zone_drop"][i])
            yield zp
            nf = CounterMetricFamily("myfw_new_flows", "Rule/default decisions on new flows", labels=["action"])
            nf.add_metric(["accept"], c["new_flow_accept"])
            nf.add_metric(["drop"], c["new_flow_drop"])
            yield nf
            for name, key, h in (
                ("myfw_stateful_hits", "stateful_hits", "Packets accepted by the flow fast path"),
                ("myfw_nat_translations", "nat_translations", "Header rewrites"),
                ("myfw_flow_create_failures", "flow_create_failed", "New flows refused for lack of state"),
                ("myfw_nat_allocation_failures", "nat_alloc_failed", "SNAT port pool exhausted"),
                ("myfw_events_suppressed", "events_suppressed", "Packet events dropped by the rate limit"),
                ("myfw_events_overwritten", "events_overwritten", "Ring overwrites in the kernel"),
                ("myfw_commits", "commits", "Committed generations"),
                ("myfw_commit_rejected", "commit_rejected", "Rejected commits"),
                ("myfw_stage_aborted", "stage_aborted", "Abandoned staging sessions"),
            ):
                cm = CounterMetricFamily(name, h)
                cm.add_metric([], c[key])
                yield cm
            a = getattr(S, "agent_status", None) or {}
            pend = a.get("pending")
            yield g("myfw_change_pending", "1 while a change awaits confirmation", 1 if pend else 0)
            if pend:
                yield g("myfw_change_deadline_seconds", "Seconds left before automatic rollback",
                        max(0.0, pend["deadline"] - time.time()))
            gd = a.get("guard") or {}
            yield g("myfw_guard_up", "1 if the rollback guard heartbeat is fresh", 1 if gd.get("alive") else 0)
            states = CounterMetricFamily("myfw_changes", "Change records by final state", labels=["state"])
            counts = {}
            for ch in S.history:
                counts[ch["state"]] = counts.get(ch["state"], 0) + 1
            for k in ("confirmed", "rolled_back", "failed", "noop", "pending"):
                states.add_metric([k], counts.get(k, 0))
            yield states
            if S.verify:
                pr = GaugeMetricFamily("myfw_service_probe_success", "Last required-service probe result",
                                       labels=["probe", "expect"])
                for r in S.verify["results"]:
                    pr.add_metric([r["name"], r["expect"]], 1 if r["pass"] else 0)
                yield pr
                yield g("myfw_service_probe_timestamp_seconds", "When the probes last ran", S.verify["time"])


def main() -> int:
    host, port = LISTEN.rsplit(":", 1)
    REGISTRY.register(MyfwCollector())
    start_http_server(int(port), addr=host)
    cursor = load_cursor()
    print(f"myfw-collector: metrics on {LISTEN}, logs in {LOG_DIR}", flush=True)
    while True:
        try:
            cursor = collect_once(cursor)
        except Exception as e:
            with S.lock:
                S.ok, S.error = False, str(e)
            print(f"collection failed: {e}", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
