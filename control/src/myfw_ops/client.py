"""Client side of the agent protocol: one JSON request line, one JSON reply line."""
from __future__ import annotations

import json
import os
import socket

SOCKET = os.environ.get("MYFW_AGENT_SOCKET", "/run/myfw/agent.sock")


class AgentUnavailable(Exception):
    pass


def call(op: str, timeout: float = 120, socket_path: str | None = None, **args) -> dict:
    path = socket_path or SOCKET
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
    except (FileNotFoundError, ConnectionRefusedError) as e:
        raise AgentUnavailable(f"myfw-agent is not reachable at {path}: {e}") from None
    except PermissionError:
        raise AgentUnavailable(f"no permission on {path} (join group myfw-read / myfw)") from None
    with s:
        s.sendall((json.dumps({"op": op, "args": args}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    if not buf:
        raise AgentUnavailable("agent closed the connection without answering")
    return json.loads(buf)
