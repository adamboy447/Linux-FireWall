"""Active service probes.

`run_suite` executes the inventory's required-service probes from inside the
endpoint namespaces (ip netns exec ... python -m myfw_ops.probe), in
parallel, and compares the outcome with the expectation:

    connected  - TCP handshake completed (https: TLS verified against the
                 lab CA and an HTTP 200 from the lab service)
    refused    - the packet reached the host but nothing listens (RST)
    timeout    - nothing came back: dropped on the way (or the host is gone)

An `allow` probe passes only when connected; a `deny` probe passes only on
timeout (a refusal means the firewall let the packet through).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

LAB_CA = os.environ.get("MYFW_LAB_CA", "/var/lib/myfw-lab/pki/ca.pem")


def probe_here(check: str, to: str, port: int, timeout: float = 2.0) -> dict:
    t0 = time.monotonic()
    res = {"check": check, "to": to, "port": port}
    try:
        if check == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.connect((to, port))
            s.send(b"myfw-probe")
            s.recv(2048)
            res["outcome"] = "connected"
        else:
            s = socket.create_connection((to, port), timeout=timeout)
            res["local"] = "%s:%d" % s.getsockname()
            if check == "https":
                ctx = ssl.create_default_context(cafile=LAB_CA)
                with ctx.wrap_socket(s, server_hostname=to) as t:
                    t.settimeout(timeout)
                    t.sendall(f"GET / HTTP/1.1\r\nHost: {to}\r\nConnection: close\r\n\r\n".encode())
                    data = b""
                    while chunk := t.recv(4096):
                        data += chunk
                head, _, body = data.partition(b"\r\n\r\n")
                status = head.split(b"\r\n", 1)[0].decode(errors="replace")
                res["http_status"] = status
                if " 200 " not in status + " ":
                    res["outcome"] = "bad-response"
                else:
                    res["outcome"] = "connected"
                    try:
                        res["server"] = json.loads(body)
                    except ValueError:
                        res["outcome"] = "bad-response"
            else:
                res["outcome"] = "connected"
                s.close()
    except ConnectionRefusedError:
        res["outcome"] = "refused"
    except (socket.timeout, TimeoutError):
        res["outcome"] = "timeout"
    except ssl.SSLError as e:
        res["outcome"] = "tls-error"
        res["error"] = str(e)
    except OSError as e:
        res["outcome"] = "unreachable" if e.errno in (101, 113) else "error"
        res["error"] = str(e)
    res["seconds"] = round(time.monotonic() - t0, 3)
    return res


def probe_from(namespace: str, check: str, to: str, port: int, timeout: float = 2.0) -> dict:
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=pkg_root + os.pathsep + os.environ.get("PYTHONPATH", ""))
    cmd = ["ip", "netns", "exec", namespace, sys.executable, "-m", "myfw_ops.probe",
           "--check", check, "--to", str(to), "--port", str(port), "--timeout", str(timeout)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15, env=env)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"outcome": "error", "error": (p.stderr or p.stdout).strip()[:300]}


def run_suite(inv, required_only: bool = True, names=None, timeout: float = 2.0) -> list[dict]:
    probes = [p for p in inv.required_services
              if (p.required or not required_only) and (not names or p.name in names)]

    def one(p):
        ep = inv.endpoints[p.from_]
        r = probe_from(ep.namespace, p.check, str(p.to), p.port, timeout)
        ok = r.get("outcome") == "connected" if p.expect == "allow" else r.get("outcome") == "timeout"
        return {"name": p.name, "from": p.from_, "to": f"{p.to}:{p.port}", "check": p.check,
                "expect": p.expect, "outcome": r.get("outcome"), "pass": ok,
                "server_saw": (r.get("server") or {}).get("client"), "detail": r}

    with ThreadPoolExecutor(max_workers=8) as ex:
        return list(ex.map(one, probes))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="myfw probe (runs inside an endpoint namespace)")
    ap.add_argument("--check", choices=["tcp", "https", "udp"], default="tcp")
    ap.add_argument("--to", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args(argv)
    r = probe_here(a.check, a.to, a.port, a.timeout)
    print(json.dumps(r))
    return 0 if r["outcome"] == "connected" else 1


if __name__ == "__main__":
    sys.exit(main())
