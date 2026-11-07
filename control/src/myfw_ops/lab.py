"""Build, tear down and break the lab topology described by the inventory.

    python3 -m myfw_ops.lab up | down | status
    python3 -m myfw_ops.lab fault route-break|route-fix ENDPOINT
    python3 -m myfw_ops.lab fault service-stop|service-start ENDPOINT

Each endpoint is a network namespace with ONE veth to the gateway (the
initial namespace, where myfw runs). There is no bridge, so traffic between
zones cannot bypass the firewall. IPv6 is disabled on every lab interface
(and myfw additionally drops IPv6 on managed interfaces). Services run as
transient systemd units (myfw-lab-<endpoint>-<service>), so `down` leaves no
process behind. Nothing here touches the laptop's real network.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

from .transactions import load_inventory

PKI = os.environ.get("MYFW_LAB_PKI", "/var/lib/myfw-lab/pki")


def sh(*args, check=True, quiet=False) -> subprocess.CompletedProcess:
    p = subprocess.run(list(args), capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {p.stderr.strip()}")
    if not quiet and p.returncode == 0 and p.stdout.strip():
        pass
    return p


def netns_list() -> set:
    p = sh("ip", "netns", "list", check=False)
    return {line.split()[0] for line in p.stdout.splitlines() if line.strip()}


def sysctl(key: str, value: str, ns: str | None = None) -> None:
    path = "/proc/sys/" + key.replace(".", "/")
    if ns:
        sh("ip", "netns", "exec", ns, "sh", "-c", f"echo {value} > {path}", check=False)
    else:
        try:
            with open(path, "w") as f:
                f.write(value)
        except OSError:
            pass


def ensure_pki(inv) -> None:
    os.makedirs(PKI, mode=0o755, exist_ok=True)
    ca, cakey = f"{PKI}/ca.pem", f"{PKI}/ca.key"
    if not os.path.exists(ca):
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
           "-subj", "/CN=myfw lab CA", "-keyout", cakey, "-out", ca)
    ips = sorted({str(e.address) for e in inv.endpoints.values()} |
                 {str(z.gateway_address.ip) for z in inv.zones.values()})
    crt, key = f"{PKI}/service.pem", f"{PKI}/service.key"
    if not os.path.exists(crt):
        san = ",".join(f"IP:{ip}" for ip in ips)
        sh("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=myfw-lab-service",
           "-keyout", key, "-out", f"{PKI}/service.csr")
        with open(f"{PKI}/ext.cnf", "w") as f:
            f.write(f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n")
        sh("openssl", "x509", "-req", "-in", f"{PKI}/service.csr", "-CA", ca, "-CAkey", cakey,
           "-CAcreateserial", "-days", "3650", "-extfile", f"{PKI}/ext.cnf", "-out", crt)
    os.chmod(key, 0o644)  # lab-only key, readable by the service processes


def unit_name(ep: str, svc: str) -> str:
    return f"myfw-lab-{ep}-{svc}"


def start_service(ep_name, ep, svc) -> None:
    unit = unit_name(ep_name, svc.name)
    if sh("systemctl", "is-active", "--quiet", unit, check=False).returncode == 0:
        return
    sh("systemctl", "reset-failed", unit, check=False)
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = ["ip", "netns", "exec", ep.namespace, sys.executable, "-m", "myfw_ops.labsvc",
           "--name", ep_name, "--port", str(svc.port)]
    if svc.name.startswith("https"):
        cmd += ["--cert", f"{PKI}/service.pem", "--key", f"{PKI}/service.key"]
    sh("systemd-run", f"--unit={unit}", "--collect", "--quiet",
       f"--setenv=PYTHONPATH={pkg_root}", "--property=Restart=on-failure", *cmd)


def up() -> dict:
    inv = load_inventory()
    ensure_pki(inv)
    have = netns_list()
    created = []
    for name, ep in inv.endpoints.items():
        z = inv.zones[ep.zone]
        if ep.namespace not in have:
            sh("ip", "netns", "add", ep.namespace)
            created.append(ep.namespace)
        if not os.path.exists(f"/sys/class/net/{z.interface}"):
            sh("ip", "link", "add", z.interface, "type", "veth", "peer", "name", "eth0",
               "netns", ep.namespace)
        sysctl(f"net.ipv6.conf.{z.interface}.disable_ipv6", "1")
        sysctl("net.ipv6.conf.all.disable_ipv6", "1", ep.namespace)
        sh("ip", "addr", "replace", str(z.gateway_address), "dev", z.interface)
        sh("ip", "link", "set", z.interface, "up")
        prefix = z.gateway_address.network.prefixlen
        sh("ip", "-n", ep.namespace, "addr", "replace", f"{ep.address}/{prefix}", "dev", "eth0")
        sh("ip", "-n", ep.namespace, "link", "set", "lo", "up")
        sh("ip", "-n", ep.namespace, "link", "set", "eth0", "up")
        gw = str(z.gateway_address.ip)
        if ep.zone == inv.default_route_zone:
            # the "outside": routes only to the published addresses' network and,
            # like an attacker that knows the inside ranges, to the inside subnets
            for oname, oz in inv.zones.items():
                if oname != ep.zone:
                    sh("ip", "-n", ep.namespace, "route", "replace", str(oz.gateway_address.network),
                       "via", gw)
        else:
            sh("ip", "-n", ep.namespace, "route", "replace", "default", "via", gw)
        for svc in ep.services:
            start_service(name, ep, svc)
    return {"ok": True, "created_namespaces": created, "pki": PKI}


def down() -> dict:
    inv = load_inventory()
    for name, ep in inv.endpoints.items():
        for svc in ep.services:
            sh("systemctl", "stop", unit_name(name, svc.name), check=False)
        if ep.namespace in netns_list():
            sh("ip", "netns", "del", ep.namespace, check=False)
        z = inv.zones[ep.zone]
        if os.path.exists(f"/sys/class/net/{z.interface}"):
            sh("ip", "link", "del", z.interface, check=False)
    return {"ok": True}


def status() -> dict:
    inv = load_inventory()
    out = {}
    have = netns_list()
    for name, ep in inv.endpoints.items():
        z = inv.zones[ep.zone]
        out[name] = {
            "namespace": ep.namespace in have,
            "gateway_link": os.path.exists(f"/sys/class/net/{z.interface}"),
            "services": {s.name: sh("systemctl", "is-active", unit_name(name, s.name),
                                    check=False).stdout.strip() for s in ep.services},
        }
    return out


def fault(kind: str, endpoint: str) -> dict:
    inv = load_inventory()
    ep = inv.endpoints[endpoint]
    gw = str(inv.zones[ep.zone].gateway_address.ip)
    if kind == "route-break":
        if ep.zone == inv.default_route_zone:
            for oname, oz in inv.zones.items():
                if oname != ep.zone:
                    sh("ip", "-n", ep.namespace, "route", "del", str(oz.gateway_address.network), check=False)
        else:
            sh("ip", "-n", ep.namespace, "route", "del", "default", check=False)
    elif kind == "route-fix":
        if ep.zone == inv.default_route_zone:
            for oname, oz in inv.zones.items():
                if oname != ep.zone:
                    sh("ip", "-n", ep.namespace, "route", "replace", str(oz.gateway_address.network),
                       "via", gw)
        else:
            sh("ip", "-n", ep.namespace, "route", "replace", "default", "via", gw)
    elif kind == "service-stop":
        for s in ep.services:
            sh("systemctl", "stop", unit_name(endpoint, s.name), check=False)
    elif kind == "service-start":
        for s in ep.services:
            start_service(endpoint, ep, s)
    else:
        raise SystemExit(f"unknown fault {kind}")
    return {"ok": True, "fault": kind, "endpoint": endpoint}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="myfw-lab")
    ap.add_argument("action", choices=["up", "down", "status", "fault"])
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("myfw-lab must run as root", file=sys.stderr)
        return 1
    if a.action == "up":
        r = up()
    elif a.action == "down":
        r = down()
    elif a.action == "status":
        r = status()
    else:
        if len(a.args) != 2:
            ap.error("fault KIND ENDPOINT")
        r = fault(a.args[0], a.args[1])
    print(json.dumps(r, indent=1))
    return 0


if __name__ == "__main__":
    shutil.which("ip") or sys.exit("iproute2 is required")
    sys.exit(main())
