"""Candidate validation, interrupted staging, concurrent writers, atomic switching,
connection semantics, automatic rollback, process crashes."""
import json
import os
import subprocess
import threading
import time

import yaml

from conftest import (DEMO, UAPP, apply_confirmed, counters, delta, drops, fwctl, https_get,
                      leak_count, ns, pending_id, policy_variant, sh, status, uapp_json)


def export_blob(path="/tmp/active.bin"):
    sh([UAPP, "policy", "export", path], check=True)
    return path


def test_invalid_candidates_never_touch_the_active_policy(demo_confirmed):
    st0 = status()
    bad = policy_variant(lambda d: d["rules"].append({"id": "open-ssh", "ingress_zone": "wan",
                                                      "destination": "192.0.2.1/32", "protocol": "tcp",
                                                      "destination_ports": [22], "action": "accept",
                                                      "owner": "x", "reason": "y"}))
    rc, r = fwctl("apply", bad)
    assert rc == 2 and r["error"] == "invalid"
    assert any(f["code"] == "opens-mgmt-service" for f in r["detail"]["findings"])
    # garbage and truncated blobs straight to the kernel
    open("/tmp/garbage.bin", "wb").write(os.urandom(4000))
    blob = open(export_blob(), "rb").read()
    open("/tmp/trunc.bin", "wb").write(blob[: len(blob) - 50])
    for f in ("/tmp/garbage.bin", "/tmp/trunc.bin"):
        p = sh([UAPP, "--json", "policy", "apply", f, "--expected-gen", str(st0["generation"])])
        assert p.returncode != 0 and not json.loads(p.stdout)["ok"]
    st1 = status()
    assert (st1["generation"], st1["policy_hash"]) == (st0["generation"], st0["policy_hash"])


def test_interrupted_staging_is_released(demo_confirmed):
    st0 = status()
    p = sh([UAPP, "policy", "apply", export_blob(), "--expected-gen", "current",
            "--chunk-size", "256", "--debug-stop-after-chunks", "2"])
    assert p.returncode != 0
    time.sleep(2)
    st1 = status()
    assert st1["stage_state"] == 0 and st1["generation"] == st0["generation"]
    assert counters()["stage_aborted"] >= 1


def test_two_writers_one_generation(demo_confirmed):
    blob = export_blob()
    g = status()["generation"]
    procs = [subprocess.Popen([UAPP, "--json", "policy", "apply", blob, "--expected-gen", str(g),
                               "--debug-hold", "1"], stdout=subprocess.PIPE, text=True)
             for _ in range(2)]
    res = [json.loads(p.communicate()[0]) for p in procs]
    assert sorted(r["ok"] for r in res) == [False, True], res
    assert status()["generation"] == g + 1
    # the loser retried with a stale generation is refused as a conflict
    p = sh([UAPP, "--json", "policy", "apply", blob, "--expected-gen", str(g)])
    assert json.loads(p.stdout)["errno"] == 116      # ESTALE


def test_concurrent_fwctl_applies(demo_confirmed):
    a = policy_variant(lambda d: d["rules"][0].update(destination_ports=[443, 4443]))
    out = []

    def run():
        p = sh(["fwctl", "apply", a, "--json", "--no-verify", "--confirm-timeout", "60"])
        out.append(json.loads(p.stdout))
    ts = [threading.Thread(target=run) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    oks = [r for r in out if r.get("ok")]
    assert len(oks) == 1, out
    other = [r for r in out if not r.get("ok")][0]
    assert other["error"] in ("pending", "busy", "conflict"), other
    fwctl("rollback", "--reason", "test")


def test_commits_under_load_never_mix_policies(demo_confirmed):
    """Hammer the published service and the LAN path while 20 commits alternate
    two policies. Every completed response must be complete and come from the
    right service; packets decided by an old generation are dropped, not
    translated by the new one; nothing leaks untranslated."""
    a = export_blob("/tmp/A.bin")
    b_yaml = policy_variant(lambda d: d["rules"][0].update(destination_ports=[443, 4443]))
    apply_confirmed(b_yaml)
    b = export_blob("/tmp/B.bin")
    apply_confirmed(DEMO)
    d0, c0 = drops(), counters()
    stop = threading.Event()
    stats = {"ok": 0, "fail": 0, "bad": 0}

    def client(namespace, url, svc):
        while not stop.is_set():
            r = https_get(namespace, url, timeout=4)
            if r.returncode != 0:
                stats["fail"] += 1
                continue
            try:
                ok = json.loads(r.stdout)["service"] == svc
            except ValueError:
                ok = False
            stats["ok" if ok else "bad"] += 1

    ts = [threading.Thread(target=client, args=("wan", "https://192.0.2.1:8443/", "dmz-web")),
          threading.Thread(target=client, args=("lan", "https://10.10.20.10/", "dmz-web")),
          threading.Thread(target=client, args=("lan", "https://192.0.2.10/", "wan-host"))]
    [t.start() for t in ts]
    gates = []
    for i in range(20):
        g = status()["generation"]
        p = sh([UAPP, "--json", "policy", "apply", a if i % 2 else b, "--expected-gen", str(g)])
        r = json.loads(p.stdout)
        assert r["ok"], r
        gates.append(r["gate_ns"] / 1e6)
        time.sleep(0.3)
    stop.set()
    [t.join() for t in ts]
    d = delta(d0, drops())
    print(f"\nresponses ok={stats['ok']} failed={stats['fail']} wrong={stats['bad']}; "
          f"gate ms max={max(gates):.3f} median={sorted(gates)[10]:.3f}; drops {d}")
    os.makedirs("/var/lib/myfw-tests", exist_ok=True)
    json.dump({"responses": stats, "gate_ms": gates, "drop_deltas": d},
              open("/var/lib/myfw-tests/commit-under-load.json", "w"))
    assert stats["bad"] == 0 and stats["ok"] > 0
    assert leak_count() == 0
    assert counters()["commits"] - c0["commits"] == 20


def test_flow_reset_is_reported_and_new_connections_work(demo_confirmed):
    # a long download through SNAT, then a commit
    p = subprocess.Popen(["ip", "netns", "exec", "lan", "curl", "-s", "--cacert",
                          "/var/lib/myfw-lab/pki/ca.pem", "--limit-rate", "500k", "-m", "40",
                          "-o", "/dev/null", "-w", "%{size_download}", "https://192.0.2.10/bytes?n=8000000"],
                         stdout=subprocess.PIPE, text=True)
    time.sleep(8)
    b = policy_variant(lambda d: d["rules"][0].update(destination_ports=[443, 4443]))
    rc, r = fwctl("apply", b, "--confirm-timeout", "60")
    assert rc == 0 and r["flows_reset"] >= 1, r
    got = int(p.communicate()[0] or 0)
    fwctl("confirm", r["change_id"])
    print(f"\nSNAT download across a commit: {got} of 8000000 bytes (the NAT session is reset by design)")
    assert 0 < got < 8000000        # the translated session started, and does not survive...
    assert https_get("lan", "https://192.0.2.10/").returncode == 0   # ...a new one works
    assert leak_count() == 0


def test_failed_required_service_rolls_back_immediately(demo_confirmed):
    st0 = status()
    broken = policy_variant(lambda d: d.update(rules=[r for r in d["rules"] if r["id"] != "lan-dmz-web"]))
    rc, r = fwctl("apply", broken)
    assert rc == 4 and r["state"] == "rolled_back", r
    assert "lan-to-dmz-https" in r["rollback"]["reason"]
    st1 = status()
    assert st1["policy_hash"] == st0["policy_hash"] and st1["generation"] == st0["generation"] + 2
    assert https_get("lan", "https://10.10.20.10/").returncode == 0


def test_unconfirmed_change_is_rolled_back_by_the_guard(demo_confirmed):
    st0 = status()
    b = policy_variant(lambda d: d["rules"][0].update(destination_ports=[443, 4443]))
    t0 = time.time()
    rc, r = fwctl("apply", b, "--confirm-timeout", "10")
    assert rc == 0 and r["state"] == "pending"
    deadline = r["deadline"]
    while status()["policy_hash"] != st0["policy_hash"] and time.time() < deadline + 15:
        time.sleep(0.5)
    t1 = time.time()
    assert status()["policy_hash"] == st0["policy_hash"]
    late = t1 - deadline
    print(f"\nrolled back {late:.1f}s after the 10 s deadline ({t1 - t0:.1f}s after apply)")
    assert late < 5
    _, h = fwctl("history", "--limit", "3")
    assert next(c for c in h["changes"] if c["id"] == r["change_id"])["state"] == "rolled_back"
    os.makedirs("/var/lib/myfw-tests", exist_ok=True)
    json.dump({"deadline_s": 10, "rollback_after_deadline_s": late},
              open("/var/lib/myfw-tests/guard-rollback.json", "w"))


def test_agent_crash_does_not_stop_the_data_plane_or_the_guard(demo_confirmed):
    st0 = status()
    b = policy_variant(lambda d: d["rules"][0].update(destination_ports=[443, 4443]))
    rc, r = fwctl("apply", b, "--confirm-timeout", "15")
    assert rc == 0
    sh("systemctl kill -s KILL myfw-agent")
    time.sleep(0.5)
    assert https_get("lan", "https://10.10.20.10/").returncode == 0      # data plane unaffected
    sh("systemctl kill -s KILL myfw-agent")                               # keep it down a while
    while time.time() < r["deadline"] + 8 and status()["policy_hash"] != st0["policy_hash"]:
        time.sleep(0.5)
    assert status()["policy_hash"] == st0["policy_hash"], "guard did not roll back without the agent"
    for _ in range(30):
        if sh("systemctl is-active myfw-agent").stdout.strip() == "active":
            break
        time.sleep(1)
    _, s = fwctl("status")
    assert s["pending"] is None and s["in_sync"]


def test_guard_is_restarted_and_apply_refuses_without_it(demo_confirmed):
    sh("systemctl stop myfw-guard", check=True)
    time.sleep(6)
    b = policy_variant(lambda d: d["rules"][0].update(destination_ports=[443, 4443]))
    rc, r = fwctl("apply", b)
    assert rc != 0 and r["error"] == "guard-down", r
    sh("systemctl start myfw-guard", check=True)
    sh("systemctl kill -s KILL myfw-guard")
    for _ in range(20):
        time.sleep(1)
        if sh("systemctl is-active myfw-guard").stdout.strip() == "active":
            break
    _, s = fwctl("status")
    assert s["guard"]["alive"] or time.sleep(2) or fwctl("status")[1]["guard"]["alive"]


def test_capacity_flow_limit_fails_closed(demo_confirmed):
    c0 = counters()
    limit = c0["conns"] + 1
    open("/sys/module/myfw/parameters/max_conns", "w").write(str(limit))
    try:
        rs = [https_get("lan", "https://192.0.2.10/", timeout=3).returncode for _ in range(3)]
    finally:
        open("/sys/module/myfw/parameters/max_conns", "w").write("16384")
    d = delta(c0["drop_reason"], drops())
    assert d.get("flow_table_full", 0) >= 1 and any(rs)
    assert leak_count() == 0


def test_snat_pool_exhaustion_fails_closed(demo_confirmed):
    small = policy_variant(lambda d: d["nat"][0].update(port_range=[20000, 20001]))
    apply_confirmed(small)
    try:
        c0 = counters()
        # two outbound TCP sessions hold both ports of the pool; the third must be refused
        r = ns("lan", "python3 - <<'EOF'\n"
               "import socket, time\n"
               "held = [socket.create_connection(('192.0.2.10', 443), timeout=10) for _ in range(2)]\n"
               "try:\n"
               "    socket.create_connection(('192.0.2.10', 443), timeout=4)\n"
               "    print('third-connected')\n"
               "except OSError as e:\n"
               "    print('third-refused', type(e).__name__)\n"
               "EOF")
        print("\n" + r.stdout.strip(), r.stderr.strip()[-200:])
        c1 = counters()
        assert r.stdout.startswith("third-refused"), r.stdout + r.stderr
        assert c1["nat_alloc_failed"] > c0["nat_alloc_failed"]
        assert c1["drop_reason"]["nat_allocation_failed"] > c0["drop_reason"]["nat_allocation_failed"]
        assert leak_count() == 0
    finally:
        apply_confirmed(DEMO)
