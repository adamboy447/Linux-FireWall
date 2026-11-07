"""Agent protocol: peer credentials, roles, schema enforcement."""
import os
import threading

import pytest

from myfw_ops import agent, client
from myfw_ops import transactions as tx


@pytest.fixture
def server(tmp_path, monkeypatch):
    sock = str(tmp_path / "agent.sock")
    calls = []

    def fake_handle(op, args, uid, who):
        calls.append((op, args, uid))
        return {"ok": True, "op": op, "uid": uid}
    monkeypatch.setattr(agent, "handle", fake_handle)

    class NoAudit:
        def audit(self, *a, **k):
            pass
    monkeypatch.setattr(agent, "store", lambda: NoAudit())
    # roles come from /etc/group; tests run as any user (root locally, an
    # unprivileged runner in CI), so grant both unless a test says otherwise
    monkeypatch.setattr(agent, "roles", lambda uid, gid: {"read", "write"})
    srv = agent.Server(sock, agent.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield sock, calls, monkeypatch
    srv.shutdown()


def test_peer_uid_comes_from_the_kernel(server):
    sock, calls, _ = server
    r = client.call("status", socket_path=sock)
    assert r["ok"] and r["uid"] == os.getuid()


def test_unknown_op_and_arguments_are_refused(server):
    sock, calls, _ = server
    assert client.call("run_command", socket_path=sock, cmd="id")["error"] == "bad-request"
    assert client.call("events", socket_path=sock, path="/etc/shadow")["error"] == "bad-request"
    assert client.call("events", socket_path=sock, since="5")["error"] == "bad-request"
    assert client.call("apply", socket_path=sock, policy="x" * (300 * 1024))["error"] == "bad-request"
    assert all(c[0] != "run_command" for c in calls)


def test_write_needs_the_write_role(server):
    sock, calls, mp = server
    mp.setattr(agent, "roles", lambda uid, gid: {"read"})
    assert client.call("status", socket_path=sock)["ok"]
    r = client.call("rollback", socket_path=sock, reason="x")
    assert r["error"] == "forbidden"
    mp.setattr(agent, "roles", lambda uid, gid: set())
    assert client.call("status", socket_path=sock)["error"] == "forbidden"


def test_roles():
    assert agent.roles(0, 0) == {"read", "write"}
    assert agent.roles(65534, 65534) == set() or "write" not in agent.roles(65534, 65534)


def test_txn_errors_are_reported_not_raised(server):
    sock, _, mp = server

    def boom(op, args, uid, who):
        raise tx.TxnError("pending", "change X is still pending")
    mp.setattr(agent, "handle", boom)
    r = client.call("rollback", socket_path=sock, reason="x")
    assert r == {"ok": False, "error": "pending", "message": "change X is still pending", "detail": None}
