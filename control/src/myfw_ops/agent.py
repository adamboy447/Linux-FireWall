"""myfw-agent: the only process that changes the firewall on request.

Trust boundary (docs/architecture.md):
  * listens on a Unix socket (/run/myfw/agent.sock, mode 0660, group
    myfw-read); every connection's peer UID/GID come from SO_PEERCRED, never
    from the request;
  * READ operations need group myfw-read (or myfw, or root); WRITE
    operations need group myfw or root;
  * only the operations listed in OPS exist, each with a fixed set of
    argument names and types; there is no "run a command" or "write a file"
    operation, and no request field is used as a path;
  * policies arrive as text (<= 256 KiB) and the inventory is read from the
    fixed path, so a client cannot point the agent at arbitrary files;
  * the kernel still checks CAP_NET_ADMIN on every netlink request.
The VM's root user remains fully trusted: this does not protect against
root unloading the module or editing the state directory.
"""
from __future__ import annotations

import grp
import json
import os
import pwd
import socket
import socketserver
import struct
import sys
import time
import traceback

from . import backend, probe, transactions as tx
from .state import Store

SOCKET = os.environ.get("MYFW_AGENT_SOCKET", "/run/myfw/agent.sock")
MAX_REQUEST = 512 * 1024
MAX_POLICY = 256 * 1024
WRITE_GROUP, READ_GROUP = "myfw", "myfw-read"

# op -> (needs write, {arg: type})
OPS = {
    "ping": (False, {}),
    "status": (False, {}),
    "counters": (False, {}),
    "events": (False, {"since": int, "max": int}),
    "conns": (False, {}),
    "show": (False, {}),
    "history": (False, {"limit": int}),
    "audit": (False, {"limit": int}),
    "last_verify": (False, {}),
    "validate": (False, {"policy": str}),
    "diff": (False, {"policy": str}),
    "verify": (True, {"names": list, "record": bool}),
    "apply": (True, {"policy": str, "confirm_timeout": int, "verify": bool, "reason": str}),
    "confirm": (True, {"change_id": str}),
    "rollback": (True, {"reason": str}),
}

def store() -> Store:
    # one SQLite connection per request: connections are not shared between
    # handler threads; the state lock (flock) serialises transitions
    return Store()


def peer(sock: socket.socket) -> tuple[int, int, int]:
    data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", data)          # pid, uid, gid


def roles(uid: int, gid: int) -> set:
    if uid == 0:
        return {"read", "write"}
    try:
        name = pwd.getpwuid(uid).pw_name
        gids = set(os.getgrouplist(name, gid))
    except KeyError:
        gids = {gid}
    have = set()
    for gname, role in ((WRITE_GROUP, "write"), (READ_GROUP, "read")):
        try:
            if grp.getgrnam(gname).gr_gid in gids:
                have.add(role)
        except KeyError:
            pass
    if "write" in have:
        have.add("read")
    return have


def check_args(op: str, args: dict) -> None:
    _, schema = OPS[op]
    unknown = set(args) - set(schema)
    if unknown:
        raise tx.TxnError("bad-request", f"unknown argument(s) for {op}: {', '.join(sorted(unknown))}")
    for k, v in args.items():
        if not isinstance(v, schema[k]) or (schema[k] is int and isinstance(v, bool)):
            raise tx.TxnError("bad-request", f"argument {k} must be {schema[k].__name__}")
    if "policy" in args and len(args["policy"].encode()) > MAX_POLICY:
        raise tx.TxnError("bad-request", "policy text larger than 256 KiB")
    if "names" in args and not all(isinstance(n, str) for n in args["names"]):
        raise tx.TxnError("bad-request", "names must be strings")


def handle(op: str, args: dict, uid: int, who: str) -> dict:
    s = store()
    inv = tx.load_inventory()
    if op == "ping":
        return {"ok": True, "pong": time.time()}
    if op == "status":
        return {"ok": True, **tx.status(s)}
    if op == "counters":
        return {"ok": True, "counters": backend.counters(), "status": backend.status()}
    if op == "events":
        return {"ok": True, **backend.events(args.get("since", 0), args.get("max"))}
    if op == "conns":
        return {"ok": True, **backend.conns()}
    if op == "show":
        st = backend.status()
        snap = s.get_snapshot(st["policy_hash"]) if s.has_snapshot(st["policy_hash"]) else None
        return {"ok": True, "status": st, "canonical": snap, "kernel": backend.policy_show()}
    if op == "history":
        return {"ok": True, "changes": s.history(min(max(args.get("limit", 20), 1), 500))}
    if op == "audit":
        return {"ok": True, "audit": s.audit_log(min(max(args.get("limit", 50), 1), 1000))}
    if op == "last_verify":
        raw = s.meta("last_verify")
        return {"ok": True, "verify": json.loads(raw) if raw else None}
    if op == "validate":
        _, rep = tx.compile_text(args["policy"], inv)
        return {"ok": rep.ok, "validation": rep.as_dict()}
    if op == "diff":
        return {"ok": True, **tx.diff_against_active(s, args["policy"], inv)}
    if op == "verify":
        results = probe.run_suite(inv, required_only=False, names=args.get("names") or None)
        rec = {"time": time.time(), "results": results, "generation": backend.status()["generation"]}
        if args.get("record"):
            s.set_meta("last_verify", json.dumps(rec))
        return {"ok": all(r["pass"] for r in results), **rec}
    if op == "apply":
        return tx.apply(s, args["policy"], uid, who, inv, args.get("confirm_timeout", 60),
                        args.get("verify", True), reason=args.get("reason", ""))
    if op == "confirm":
        return tx.confirm(s, args["change_id"], uid, who)
    if op == "rollback":
        return tx.rollback(s, uid, who, inv, reason=args.get("reason", "manual"))
    raise tx.TxnError("bad-request", f"unknown operation {op}")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        pid, uid, gid = peer(self.request)
        try:
            who = pwd.getpwuid(uid).pw_name
        except KeyError:
            who = f"uid{uid}"
        try:
            line = self.rfile.readline(MAX_REQUEST + 1)
            if len(line) > MAX_REQUEST:
                raise tx.TxnError("bad-request", "request too large")
            req = json.loads(line or b"{}")
            if not isinstance(req, dict) or set(req) - {"op", "args"}:
                raise tx.TxnError("bad-request", "request must be {op, args}")
            op, args = req.get("op"), req.get("args") or {}
            if op not in OPS or not isinstance(args, dict):
                raise tx.TxnError("bad-request", f"unknown operation {op!r}")
            need_write = OPS[op][0]
            have = roles(uid, gid)
            if ("write" if need_write else "read") not in have:
                raise tx.TxnError("forbidden", f"{who} may not {op} (needs group "
                                  f"{WRITE_GROUP if need_write else READ_GROUP})")
            check_args(op, args)
            if need_write:
                store().audit(None, uid, f"request:{op}", {"pid": pid, "user": who})
            resp = handle(op, args, uid, who)
        except tx.TxnError as e:
            resp = e.as_dict()
        except backend.BackendError as e:
            resp = {"ok": False, "error": e.kind, "message": str(e)}
        except TimeoutError as e:
            resp = {"ok": False, "error": "busy", "message": str(e)}
        except Exception as e:  # never leak a traceback to the client; log it
            traceback.print_exc(file=sys.stderr)
            resp = {"ok": False, "error": "internal", "message": type(e).__name__}
        self.wfile.write((json.dumps(resp, default=str) + "\n").encode())


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main() -> int:
    os.makedirs(os.path.dirname(SOCKET), exist_ok=True)
    if os.path.exists(SOCKET):
        os.unlink(SOCKET)
    old = os.umask(0o117)
    srv = Server(SOCKET, Handler)
    os.umask(old)
    try:
        os.chown(SOCKET, 0, grp.getgrnam(READ_GROUP).gr_gid)
    except (KeyError, PermissionError):
        pass
    os.chmod(SOCKET, 0o660)
    print(f"myfw-agent listening on {SOCKET}", flush=True)
    from .guard import sd_notify
    sd_notify("READY=1")
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
