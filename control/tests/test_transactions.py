"""Transaction state machine against a fake kernel with the real generation rules."""
import errno
import os
import threading
import time

import pytest
import yaml

from myfw_ops import abi, backend, probe
from myfw_ops import transactions as tx
from myfw_ops.state import Store


class FakeKernel:
    def __init__(self):
        self.gen, self.hash, self.managed, self.label = 1, "initial", False, "module load"
        self.commits = []
        self.fail_next = None
        self.lock = threading.Lock()

    def status(self):
        return {"generation": self.gen, "policy_hash": self.hash, "managed": self.managed,
                "label": self.label, "event_next_seq": 1}

    def apply_blob(self, blob, expected, validate_only=False):
        with self.lock:
            if self.fail_next:
                e, self.fail_next = self.fail_next, None
                raise e
            if expected != self.gen:
                raise backend.BackendError(f"generation conflict: expected {expected}, active is {self.gen}",
                                           errno.ESTALE)
            h = abi.unpack_header(blob)
            self.gen += 1
            self.hash, self.managed, self.label = h["policy_hash"], bool(h["flags"] & 1), h["label"]
            self.commits.append((self.gen, self.hash, self.label))
            return {"ok": True, "committed": True, "generation": self.gen, "gate_ns": 1000,
                    "flows_reset": 3, "policy_hash": self.hash}


@pytest.fixture
def env(tmp_path, monkeypatch):
    k = FakeKernel()
    monkeypatch.setattr(backend, "status", k.status)
    monkeypatch.setattr(backend, "apply_blob", k.apply_blob)
    monkeypatch.setattr(backend, "check_abi", lambda: None)
    monkeypatch.setattr(tx, "live_interfaces", lambda: {"lo", "mgmt0", "veth-lan", "veth-dmz", "veth-wan"})
    hb = tmp_path / "guard.heartbeat"
    monkeypatch.setattr(tx, "HEARTBEAT", str(hb))
    hb.write_text("1")
    probes = {"result": []}
    monkeypatch.setattr(probe, "run_suite", lambda inv, required_only=True, names=None: probes["result"])
    store = Store(str(tmp_path / "state"))
    return k, store, probes, hb


def apply(store, inv, text, **kw):
    return tx.apply(store, text, 1000, "tester", inv, **kw)


def variant(text, port):
    d = yaml.safe_load(text)
    d["rules"][0]["destination_ports"] = [port]
    return yaml.safe_dump(d)


def test_apply_confirm(env, inv, demo_text):
    k, store, _, _ = env
    r = apply(store, inv, demo_text)
    assert r["ok"] and r["state"] == "pending" and r["generation"] == 2
    assert k.label == r["change_id"] and k.managed
    ch = store.change(r["change_id"])
    assert ch["state"] == "pending" and ch["previous_hash"] is None and ch["deadline"] > time.time()
    c = tx.confirm(store, r["change_id"], 1000, "tester")
    assert c["state"] == "confirmed"
    assert store.meta("last_confirmed_hash") == r["policy_hash"]
    assert store.has_snapshot(r["policy_hash"])


def test_same_semantics_is_a_noop(env, inv, demo_text):
    k, store, _, _ = env
    r = apply(store, inv, demo_text)
    tx.confirm(store, r["change_id"], 1000, "t")
    n = apply(store, inv, demo_text.replace("owner: demo-web", "owner: other-team"))
    assert n["no_op"] and k.gen == 2 and store.change(n["change_id"])["state"] == "noop"


def test_second_change_refused_while_pending(env, inv, demo_text):
    _, store, _, _ = env
    apply(store, inv, demo_text)
    with pytest.raises(tx.TxnError) as e:
        apply(store, inv, variant(demo_text, 8443))
    assert e.value.code == "pending"


def test_invalid_policy_changes_nothing(env, inv, demo_text):
    k, store, _, _ = env
    bad = demo_text.replace("ingress_zone: lan", "ingress_zone: office", 1)
    with pytest.raises(tx.TxnError) as e:
        apply(store, inv, bad)
    assert e.value.code == "invalid" and k.gen == 1 and store.history() == []


def test_refused_without_guard(env, inv, demo_text):
    k, store, _, hb = env
    os.utime(hb, (time.time() - 60, time.time() - 60))
    with pytest.raises(tx.TxnError) as e:
        apply(store, inv, demo_text)
    assert e.value.code == "guard-down" and k.gen == 1


def test_guard_rolls_back_unconfirmed_change(env, inv, demo_text):
    k, store, _, _ = env
    first = apply(store, inv, demo_text)
    tx.confirm(store, first["change_id"], 1000, "t")
    second = apply(store, inv, variant(demo_text, 8443), confirm_timeout=10)
    assert k.hash == second["policy_hash"]
    assert tx.guard_tick(store, inv, now=time.time() + 5) is None          # not yet
    res = tx.guard_tick(store, inv, now=time.time() + 11)
    assert res["to_hash"] == first["policy_hash"] and k.hash == first["policy_hash"]
    assert res["generation"] == 4 and k.label.startswith("rollback-")
    assert store.change(second["change_id"])["state"] == "rolled_back"
    with pytest.raises(tx.TxnError) as e:
        tx.confirm(store, second["change_id"], 1000, "t")
    assert e.value.code == "not-pending"


def test_rollback_without_confirmed_policy_goes_to_baseline(env, inv, demo_text):
    k, store, _, _ = env
    r = apply(store, inv, demo_text, confirm_timeout=10)
    tx.guard_tick(store, inv, now=time.time() + 11)
    assert k.hash == tx.semantic_hash(tx.baseline_only(inv))
    assert store.change(r["change_id"])["state"] == "rolled_back"


def test_confirm_after_deadline_is_refused(env, inv, demo_text, monkeypatch):
    _, store, _, _ = env
    r = apply(store, inv, demo_text, confirm_timeout=10)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 11)
    with pytest.raises(tx.TxnError) as e:
        tx.confirm(store, r["change_id"], 1000, "t")
    assert e.value.code == "expired"


def test_confirm_refuses_when_kernel_moved_on(env, inv, demo_text):
    k, store, _, _ = env
    r = apply(store, inv, demo_text)
    k.gen += 1                      # someone committed behind fwctl's back
    with pytest.raises(tx.TxnError) as e:
        tx.confirm(store, r["change_id"], 1000, "t")
    assert e.value.code == "stale"


def test_commit_conflict_marks_change_failed(env, inv, demo_text):
    k, store, _, _ = env
    k.fail_next = backend.BackendError("generation conflict", errno.ESTALE)
    with pytest.raises(tx.TxnError) as e:
        apply(store, inv, demo_text)
    assert e.value.code == "conflict"
    assert store.history()[0]["state"] == "failed" and store.pending() == []


def test_failed_probe_rolls_back_immediately(env, inv, demo_text):
    k, store, probes, _ = env
    first = apply(store, inv, demo_text)
    tx.confirm(store, first["change_id"], 1000, "t")
    probes["result"] = [{"name": "lan-to-dmz-https", "pass": False, "outcome": "timeout"}]
    r = apply(store, inv, variant(demo_text, 8443))
    assert r["state"] == "rolled_back" and not r["ok"]
    assert k.hash == first["policy_hash"]
    assert store.change(r["change_id"])["state"] == "rolled_back"


def test_boot_restore_abandons_pending_and_restores_confirmed(env, inv, demo_text):
    k, store, _, _ = env
    first = apply(store, inv, demo_text)
    tx.confirm(store, first["change_id"], 1000, "t")
    second = apply(store, inv, variant(demo_text, 8443))
    k.gen, k.hash, k.managed = 1, "initial", False          # "reboot": module reloaded
    res = tx.boot_restore(store, inv)
    assert res["policy_hash"] == first["policy_hash"] and k.hash == first["policy_hash"]
    assert store.change(second["change_id"])["state"] == "rolled_back"


def test_confirm_and_guard_race_has_exactly_one_outcome(env, inv, demo_text, monkeypatch):
    k, store, _, _ = env
    first = apply(store, inv, demo_text)
    tx.confirm(store, first["change_id"], 1000, "t")
    r = apply(store, inv, variant(demo_text, 8443), confirm_timeout=10)
    deadline = store.change(r["change_id"])["deadline"]
    results = {}

    def do_confirm():
        try:
            results["confirm"] = tx.confirm(Store(store.root), r["change_id"], 1000, "t")["state"]
        except tx.TxnError as e:
            results["confirm"] = e.code

    def do_guard():
        results["guard"] = tx.guard_tick(Store(store.root), inv, now=deadline + 0.001)

    ts = [threading.Thread(target=do_confirm), threading.Thread(target=do_guard)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    final = store.change(r["change_id"])["state"]
    if results["confirm"] == "confirmed":
        assert final == "confirmed" and results["guard"] is None
        assert k.hash == r["policy_hash"]
    else:
        assert final == "rolled_back" and results["confirm"] in ("not-pending", "expired")
        assert k.hash == first["policy_hash"]
