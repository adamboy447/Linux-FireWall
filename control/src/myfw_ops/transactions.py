"""apply / confirm / rollback / guard tick / boot restore.

One library, used by three independent programs (agent, guard, boot), so
whichever of them is alive can finish a transaction the same way.

apply (docs/transaction-design.md):
  1. validate + compile (semantic hash).
  2. under the state lock: refuse if another change is pending (even a no-op
     must not look like success while someone else's change is unconfirmed).
     Same hash as the active, managed policy -> recorded as a no-op; nothing
     is committed, no flow is reset. Otherwise persist the candidate snapshot
     and a `prepared` record (previous = last confirmed).
  3. refuse unless the rollback guard is alive (fresh heartbeat), because
     nobody else would undo an unconfirmed change.
  4. record `pending` with its deadline, THEN commit to the kernel with the
     generation we read under the lock (a concurrent writer gets a conflict).
  5. outside the lock: run the required-service probes; a failure rolls the
     change back immediately.
  6. the operator confirms (change id + generation + hash must still be the
     active ones) before the deadline, or the guard rolls back.

Rollback re-applies the last confirmed snapshot as a NEW generation. It does
not resurrect TCP or NAT sessions that the forward change reset.
"""
from __future__ import annotations

import os
import time
from typing import Optional

from . import backend, probe
from .compiler import canonical, diff, semantic_hash, to_blob
from .models import Defaults, Inventory, Metadata, Policy, load_yaml_model
from .state import Store, boot_id
from .validator import validate

INVENTORY = os.environ.get("MYFW_INVENTORY", "/etc/myfw/inventory.yaml")
RUN_DIR = os.environ.get("MYFW_RUN_DIR", "/run/myfw")
HEARTBEAT = os.path.join(RUN_DIR, "guard.heartbeat")
GUARD_STALE_S = 5.0
MIN_TIMEOUT, MAX_TIMEOUT = 10, 3600


class TxnError(Exception):
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def as_dict(self):
        return {"ok": False, "error": self.code, "message": str(self), "detail": self.detail}


def load_inventory(path: Optional[str] = None) -> Inventory:
    with open(path or INVENTORY) as f:
        return load_yaml_model(Inventory, f.read())


def live_interfaces() -> set:
    try:
        return set(os.listdir("/sys/class/net"))
    except OSError:
        return set()


def parse_policy(text: str) -> Policy:
    try:
        return load_yaml_model(Policy, text)
    except Exception as e:  # pydantic / yaml errors -> one readable message
        raise TxnError("invalid", f"policy does not match the schema: {e}") from None


def compile_text(text: str, inv: Inventory, check_live: bool = True):
    pol = parse_policy(text)
    rep = validate(pol, inv, live_interfaces() if check_live else None)
    return pol, rep


def baseline_only(inv: Inventory) -> dict:
    """The safe fallback: baseline (management + loopback) and default drop."""
    pol = Policy(schema_version=1, metadata=Metadata(name="baseline-only", owner="system",
                 reason="fallback when no confirmed policy exists"),
                 defaults=Defaults(action="drop", log_mode="sampled"), zones={}, rules=[], nat=[])
    return canonical(pol, inv)


def guard_alive() -> tuple[bool, Optional[float]]:
    try:
        age = time.time() - os.stat(HEARTBEAT).st_mtime
    except OSError:
        return False, None
    return age < GUARD_STALE_S, age


def _active_canonical(store: Store, st: dict) -> Optional[dict]:
    h = st.get("policy_hash", "")
    return store.get_snapshot(h) if store.has_snapshot(h) else None


# ------------------------------------------------------------------- views

def status(store: Store) -> dict:
    st = backend.status()
    alive, age = guard_alive()
    pend = store.pending()
    last = store.meta("last_confirmed_hash")
    return {"kernel": st, "pending": pend[0] if pend else None,
            "last_confirmed_hash": last,
            "in_sync": bool(st.get("managed")) and st.get("policy_hash") == (pend[0]["policy_hash"] if pend else last),
            "guard": {"alive": alive, "heartbeat_age_s": None if age is None else round(age, 2)},
            "boot_id": boot_id()}


def diff_against_active(store: Store, text: str, inv: Inventory) -> dict:
    pol, rep = compile_text(text, inv)
    if not rep.ok:
        raise TxnError("invalid", "policy rejected by validation", rep.as_dict())
    st = backend.status()
    old = _active_canonical(store, st)
    d = diff(old, rep.canonical)
    d["active_hash"] = st.get("policy_hash")
    d["candidate_hash"] = rep.policy_hash
    d["active_known"] = old is not None
    return {"validation": rep.as_dict(), "diff": d}


# ------------------------------------------------------------------- apply

def apply(store: Store, text: str, actor_uid: int, actor: str, inv: Inventory,
          confirm_timeout: int = 60, verify: bool = True, require_guard: bool = True,
          reason: str = "") -> dict:
    if not MIN_TIMEOUT <= confirm_timeout <= MAX_TIMEOUT:
        raise TxnError("invalid", f"confirm timeout must be {MIN_TIMEOUT}-{MAX_TIMEOUT}s")
    pol, rep = compile_text(text, inv)
    if not rep.ok:
        raise TxnError("invalid", "policy rejected by validation", rep.as_dict())
    c, h = rep.canonical, rep.policy_hash

    with store.lock("apply"):
        backend.check_abi()
        st = backend.status()
        pend = store.pending()
        if pend:
            raise TxnError("pending", f"change {pend[0]['id']} is still pending: confirm it or roll it "
                           "back first", {"pending": pend[0]["id"]})
        if st.get("managed") and st.get("policy_hash") == h:
            cid = store.new_id()
            store.create_change(cid, actor_uid, actor, h, h, state="noop",
                                reason=reason or pol.metadata.reason)
            store.update_change(cid, generation=st["generation"])
            return {"ok": True, "change_id": cid, "no_op": True, "generation": st["generation"],
                    "policy_hash": h, "message": "same semantic hash as the active policy: nothing committed"}
        if require_guard and not guard_alive()[0]:
            raise TxnError("guard-down", "the rollback guard is not running; refusing an unconfirmed "
                           "change that nobody could undo")
        prev = store.meta("last_confirmed_hash")
        old = _active_canonical(store, st)
        cid = store.new_id()
        store.put_snapshot(h, c)
        store.create_change(cid, actor_uid, actor, h, prev, reason=reason or pol.metadata.reason)
        deadline = time.time() + confirm_timeout
        store.update_change(cid, state="pending", deadline=deadline,
                            detail={"diff": diff(old, c), "metadata": pol.metadata.model_dump()})
        try:
            res = backend.apply_blob(to_blob(c, cid), st["generation"])
        except backend.BackendError as e:
            store.update_change(cid, state="failed", detail={"error": str(e), "errno": e.errnum})
            store.audit(cid, actor_uid, "commit-failed", {"error": str(e)})
            raise TxnError("conflict" if e.conflict else "commit-failed", str(e)) from None
        store.update_change(cid, generation=res["generation"])
        store.audit(cid, actor_uid, "committed", {"generation": res["generation"],
                                                  "gate_ns": res["gate_ns"], "flows_reset": res["flows_reset"]})

    out = {"ok": True, "change_id": cid, "no_op": False, "generation": res["generation"],
           "policy_hash": h, "deadline": deadline, "gate_ns": res["gate_ns"],
           "flows_reset": res["flows_reset"], "state": "pending"}
    if verify:
        results = probe.run_suite(inv, required_only=True)
        out["verify"] = results
        failed = [r for r in results if not r["pass"]]
        if failed:
            rb = rollback(store, actor_uid, actor, inv,
                          reason="required service check failed: " + ", ".join(r["name"] for r in failed),
                          only_change=cid)
            out.update(state="rolled_back", rollback=rb, ok=False)
    return out


def confirm(store: Store, change_id: str, actor_uid: int, actor: str) -> dict:
    with store.lock("confirm"):
        ch = store.change(change_id)
        if not ch:
            raise TxnError("unknown", f"no change {change_id}")
        if ch["state"] != "pending":
            raise TxnError("not-pending", f"change {change_id} is {ch['state']}, not pending")
        if time.time() > ch["deadline"]:
            raise TxnError("expired", f"change {change_id} passed its deadline; the guard rolls it back")
        st = backend.status()
        if st["generation"] != ch["generation"] or st["policy_hash"] != ch["policy_hash"]:
            raise TxnError("stale", f"the active policy is generation {st['generation']} "
                           f"({st['policy_hash'][:12]}), not the one change {change_id} committed "
                           f"(generation {ch['generation']})")
        store.update_change(change_id, state="confirmed")
        store.set_meta("last_confirmed_hash", ch["policy_hash"])
        store.audit(change_id, actor_uid, "confirmed", {"by": actor, "generation": ch["generation"]})
    return {"ok": True, "change_id": change_id, "state": "confirmed", "generation": ch["generation"],
            "policy_hash": ch["policy_hash"]}


def _rollback_locked(store: Store, inv: Inventory, actor_uid: int, reason: str,
                     ch: Optional[dict]) -> dict:
    target = store.meta("last_confirmed_hash")
    if target and store.has_snapshot(target):
        c = store.get_snapshot(target)
    else:
        c = baseline_only(inv)
        target = semantic_hash(c)
        store.put_snapshot(target, c)
    st = backend.status()
    label = f"rollback-{ch['id'][4:]}" if ch else "rollback"
    t0 = time.time()
    res = backend.apply_blob(to_blob(c, label), st["generation"])
    took = time.time() - t0
    if ch:
        store.update_change(ch["id"], state="rolled_back",
                            detail={"reason": reason, "to_hash": target, "generation": res["generation"]})
    store.audit(ch["id"] if ch else None, actor_uid, "rolled-back",
                {"reason": reason, "to_hash": target, "generation": res["generation"],
                 "seconds": round(took, 3)})
    return {"ok": True, "to_hash": target, "generation": res["generation"], "reason": reason,
            "seconds": round(took, 3)}


def rollback(store: Store, actor_uid: int, actor: str, inv: Inventory, reason: str = "manual",
             only_change: Optional[str] = None) -> dict:
    with store.lock("rollback"):
        pend = store.pending()
        ch = pend[0] if pend else None
        if only_change and (not ch or ch["id"] != only_change):
            return {"ok": True, "skipped": True, "message": f"{only_change} is no longer pending"}
        return _rollback_locked(store, inv, actor_uid, f"{reason} (by {actor})", ch)


def guard_tick(store: Store, inv: Inventory, now: Optional[float] = None) -> Optional[dict]:
    """Called every second by the guard: roll back expired pending changes."""
    now = now or time.time()
    with store.lock("guard", timeout=10):
        for ch in store.pending():
            if ch["deadline"] is not None and now > ch["deadline"]:
                return _rollback_locked(store, inv, 0,
                                        f"not confirmed within the deadline ({ch['id']})", ch)
    return None


def boot_restore(store: Store, inv: Inventory) -> dict:
    """At boot, before forwarding is enabled: pending changes are abandoned and
    the last confirmed policy (or the baseline) is committed."""
    with store.lock("boot", timeout=60):
        for ch in store.pending():
            store.update_change(ch["id"], state="rolled_back",
                                detail={"reason": "rebooted while pending", "boot_id": boot_id()})
            store.audit(ch["id"], 0, "rolled-back", {"reason": "rebooted while pending"})
        target = store.meta("last_confirmed_hash")
        source = "last confirmed"
        if target and store.has_snapshot(target):
            c = store.get_snapshot(target)
        else:
            c, source = baseline_only(inv), "baseline only (nothing confirmed yet)"
            target = semantic_hash(c)
            store.put_snapshot(target, c)
        backend.check_abi()
        st = backend.status()
        res = backend.apply_blob(to_blob(c, "boot-restore"), st["generation"])
        store.audit(None, 0, "boot-restore", {"hash": target, "generation": res["generation"],
                                              "source": source})
    return {"ok": True, "policy_hash": target, "generation": res["generation"], "source": source}
