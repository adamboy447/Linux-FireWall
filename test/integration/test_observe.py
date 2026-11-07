"""Collector gaps, metrics semantics, diagnose for three different faults."""
import glob
import json
import time
import urllib.request

from conftest import counters, fwctl, https_get, ns, policy_variant, sh, status


def metrics() -> str:
    return urllib.request.urlopen("http://127.0.0.1:9108/metrics", timeout=5).read().decode()


def metric(text, name, labels=""):
    """Value of the first sample of NAME whose labels include LABELS ('{a="x",b="y"}', any order)."""
    want = set(labels.strip("{}").split(",")) - {""}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        series, value = line.rsplit(" ", 1)
        n, _, lab = series.partition("{")
        if n == name and want <= set(lab.rstrip("}").split(",")) - {""}:
            return float(value)
    return None


def test_metrics_are_meaningful(demo_confirmed):
    time.sleep(6)
    m = metrics()
    assert metric(m, "myfw_up") == 1
    assert metric(m, "myfw_generation") == status()["generation"]
    assert metric(m, "myfw_packets_total", '{verdict="accept"}') > 0
    assert metric(m, "myfw_zone_packets_total", '{zone="lan",verdict="accept"}') is not None
    assert metric(m, "myfw_guard_up") == 1
    assert 'reason="spoofed_source"' in m


def test_collection_failure_is_not_reported_as_zero_traffic(demo_confirmed):
    sh("systemctl stop myfw-agent", check=True)
    try:
        time.sleep(12)
        m = metrics()
        assert metric(m, "myfw_collector_up") == 0
        assert "myfw_packets_total" not in m
    finally:
        sh("systemctl start myfw-agent", check=True)
        time.sleep(1)


def test_event_gap_is_recorded(demo_confirmed):
    sh("systemctl stop myfw-collector", check=True)
    open("/sys/module/myfw/parameters/event_rate", "w").write("0")
    try:
        # >1024 logged drops (default policy is logged): UDP to closed paths
        ns("lan", "python3 - <<'EOF'\n"
           "import socket\n"
           "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
           "for p in range(1500):\n"
           "    s.sendto(b'x', ('10.10.20.10', 20000 + p))\n"
           "EOF", check=True)
    finally:
        open("/sys/module/myfw/parameters/event_rate", "w").write("500")
        sh("systemctl start myfw-collector", check=True)
    time.sleep(10)
    gaps = []
    for f in glob.glob("/var/log/myfw/events-*.jsonl"):
        for line in open(f):
            r = json.loads(line)
            if r.get("type") == "gap" and r.get("lost"):
                gaps.append(r)
    assert gaps, "no gap record"
    assert metric(metrics(), "myfw_collector_events_lost_total") > 0
    assert counters()["events_overwritten"] > 0


def test_diagnose_tells_three_faults_apart(demo_confirmed):
    def diag():
        p = sh(["fwctl", "diagnose", "--from", "lan-client", "--to", "10.10.20.10", "--port", "443",
                "--check", "https", "--json"], timeout=120)
        return json.loads(p.stdout)

    ok = diag()
    assert ok["conclusion"]["confirmed"] and "works" in ok["conclusion"]["cause"]

    sh("myfw-lab fault route-break dmz-web", check=True)
    try:
        r = diag()
    finally:
        sh("myfw-lab fault route-fix dmz-web", check=True)
    assert r["prediction"]["verdict"] == "accept"
    assert "route back" in r["conclusion"]["cause"], r["conclusion"]

    sh("myfw-lab fault service-stop dmz-web", check=True)
    try:
        r = diag()
    finally:
        sh("myfw-lab fault service-start dmz-web", check=True)
        time.sleep(2)
    assert "nothing listens" in r["conclusion"]["cause"], r["conclusion"]

    def block(d):   # the operator mistake: the allow rule turned into a drop
        r = next(r for r in d["rules"] if r["id"] == "lan-dmz-web")
        r.update(id="block-dmz-web", action="drop", reason="fault injection")
    drop = policy_variant(block)
    p = sh(["fwctl", "apply", drop, "--no-verify", "--confirm-timeout", "120", "--json"])
    assert json.loads(p.stdout)["ok"], p.stdout
    try:
        r = diag()
    finally:
        fwctl("rollback", "--reason", "fault injection done")
    assert r["prediction"]["verdict"] == "drop" and r["prediction"]["rule"] == "block-dmz-web"
    assert r["conclusion"]["confirmed"] and "policy drops it" in r["conclusion"]["cause"]
    assert https_get("lan", "https://10.10.20.10/").returncode == 0


def test_kernel_log_is_clean():
    out = sh("dmesg").stdout
    for bad in ("BUG:", "WARNING:", "Oops", "general protection", "circular locking", "sleeping function"):
        assert bad not in out, bad
