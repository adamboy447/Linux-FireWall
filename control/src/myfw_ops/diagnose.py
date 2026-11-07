"""fwctl diagnose: why does (or doesn't) a connection work?

Steps, each producing evidence (docs/runbook.md#diagnose):
  1. active generation / policy hash / when the data was taken;
  2. the source endpoint: namespace, address, route to the destination;
  3. PREDICTION from the active canonical policy, using the kernel's rules:
     anti-spoof, first matching rule or default, NAT plan, egress (this is
     only a prediction);
  4. a REAL new connection from the source namespace, with the kernel's drop
     counters, flows and events read before and after;
  5. destination side: is something listening, does it have a route back;
     optionally a short, filtered tcpdump on the gateway;
  6. a conclusion that is either confirmed by the evidence or explicitly
     "not enough evidence", with the next thing to check.

"Policy says ACCEPT but the test timed out" is never reported as "the
firewall is fine".
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from typing import Optional

from . import backend, probe
from .state import Store
from .transactions import load_inventory


def _run(*args, timeout=10) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)


def _in(net: str, ip: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(net)


def predict(c: dict, inv, src_zone: Optional[str], src: str, dst: str, proto: str, dport: int,
            sport: int = 40000) -> dict:
    """Evaluate a NEW flow against a canonical policy exactly as hooks.c does."""
    out: dict = {"source_zone": src_zone}
    zone = next((z for z in c["zones"] if z["name"] == src_zone), None)
    if zone and zone["sources"] and not any(_in(s, src) for s in zone["sources"]):
        out.update(verdict="drop", reason="spoofed_source",
                   explanation=f"{src} is not an allowed source of zone {src_zone}")
        return out
    hit = None
    for r in c["rules"]:
        if r["scope"] != "ingress":
            continue
        if r["zone"] and r["zone"] != src_zone:
            continue
        if r["protocol"] not in ("any", proto):
            continue
        if not (_in(r["source"], src) and _in(r["destination"], dst)):
            continue
        if proto in ("tcp", "udp") and not (r["sport"][0] <= sport <= r["sport"][1]
                                            and r["dport"][0] <= dport <= r["dport"][1]):
            continue
        hit = r
        break
    action = hit["action"] if hit else c["defaults"]["action"]
    out.update(verdict=action, rule=hit["id"] if hit else None,
               explanation=f"first match: {hit['id']}" if hit else "no rule matches: default policy")
    if action != "accept":
        out["reason"] = "rule" if hit else "default_policy"
        return out
    eff_dst, nat = dst, None
    for n in c["nat"]:
        if n["type"] == "dnat" and n["protocol"] == proto and n["destination"] == f"{dst}/32" \
                and n["dport"] == dport and (n["zone"] in (None, src_zone)):
            nat = {"type": "dnat", "id": n["id"], "to": f"{n['to_address']}:{n['to_ports'][0]}"}
            eff_dst = n["to_address"]
            break
    if not nat:
        for n in c["nat"]:
            if n["type"] != "snat" or n["protocol"] not in ("any", proto):
                continue
            if n["zone"] not in (None, src_zone) or not _in(n["source"], src):
                continue
            if not _in(n["destination"], dst):
                continue
            nat = {"type": "snat", "id": n["id"], "to": n["to_address"],
                   "egress_interface": n["egress_interface"]}
            break
    out["nat"] = nat
    out["effective_destination"] = eff_dst
    egress = next((zn for zn, z in inv.zones.items() if ipaddress.ip_address(eff_dst)
                   in z.gateway_address.network), inv.default_route_zone)
    out["egress_zone"] = egress
    if nat and nat["type"] == "snat" and egress and inv.zones[egress].interface != nat["egress_interface"]:
        out.update(verdict="drop", reason="egress_mismatch",
                   explanation=f"SNAT {nat['id']} expects {nat['egress_interface']}, route uses "
                   f"{inv.zones[egress].interface}")
    return out


def _endpoint_by_ip(inv, ip: str):
    for name, ep in inv.endpoints.items():
        if str(ep.address) == ip:
            return name, ep
    return None, None


def diagnose(src_endpoint: str, dst: str, port: int, proto: str = "tcp", check: str = "tcp",
             capture: bool = False) -> dict:
    inv = load_inventory()
    store = Store()
    ev: dict = {"query": {"from": src_endpoint, "to": dst, "port": port, "protocol": proto}}
    st = backend.status()
    ev["active"] = {"generation": st["generation"], "policy_hash": st["policy_hash"],
                    "managed": st["managed"], "taken_at": time.time()}
    c = store.get_snapshot(st["policy_hash"]) if store.has_snapshot(st["policy_hash"]) else None
    if c is None:
        ev["conclusion"] = {"confirmed": False, "cause": "the active policy is not one fwctl knows "
                            "(legacy change?): cannot predict", "next": "fwctl status; fwctl rollback"}
        return ev

    ep = inv.endpoints.get(src_endpoint)
    if not ep:
        raise SystemExit(f"unknown endpoint {src_endpoint}; known: {', '.join(inv.endpoints)}")
    ns_ok = ep.namespace in _run("ip", "netns", "list").stdout.split()
    addr = _run("ip", "-n", ep.namespace, "-j", "addr", "show", "dev", "eth0") if ns_ok else None
    has_ip = bool(addr and str(ep.address) in addr.stdout)
    route = _run("ip", "-n", ep.namespace, "route", "get", dst) if ns_ok else None
    gw = str(inv.zones[ep.zone].gateway_address.ip)
    ev["source"] = {"namespace": ep.namespace, "exists": ns_ok, "address": str(ep.address),
                    "address_present": has_ip,
                    "route": route.stdout.strip() if route and route.returncode == 0 else None,
                    "route_via_gateway": bool(route and route.returncode == 0 and f"via {gw}" in route.stdout)}

    pred = predict(c, inv, ep.zone, str(ep.address), dst, proto, port)
    ev["prediction"] = pred

    before = backend.counters()
    seq0 = backend.status()["event_next_seq"]
    tcpd = None
    if capture:
        ifs = [inv.zones[ep.zone].interface]
        if pred.get("egress_zone"):
            ifs.append(inv.zones[pred["egress_zone"]].interface)
        tcpd = []
        for i in dict.fromkeys(ifs):
            path = f"/tmp/myfw-diagnose-{int(time.time())}-{i}.pcap"
            tcpd.append((path, subprocess.Popen(["timeout", "6", "tcpdump", "-i", i, "-n", "-c", "50",
                                                 "-w", path, f"port {port} or icmp"],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)))
        time.sleep(1)
    live = probe.probe_from(ep.namespace, check, dst, port, 2.0) if ns_ok else {"outcome": "no-namespace"}
    if tcpd:
        for _, p in tcpd:
            p.wait(timeout=10)
    time.sleep(0.2)
    after = backend.counters()
    deltas = {k: after["drop_reason"][k] - before["drop_reason"].get(k, 0)
              for k in after["drop_reason"] if after["drop_reason"][k] != before["drop_reason"].get(k, 0)}
    events = [e for e in backend.events(seq0)["events"] if e["kind"] == "packet"
              and (e["src"] == str(ep.address) or e["dst"] == str(ep.address))]
    ev["live"] = {"outcome": live.get("outcome"), "detail": live, "drop_counter_deltas": deltas,
                  "events": events[-5:],
                  "captures": [p for p, _ in tcpd] if tcpd else None}

    dname, dep = _endpoint_by_ip(inv, pred.get("effective_destination", dst))
    if dep:
        nat = pred.get("nat") or {}
        dst_port = int(nat["to"].split(":")[1]) if nat.get("type") == "dnat" else port
        listening = _run("ip", "netns", "exec", dep.namespace, "ss", "-Hltn", f"sport = :{dst_port}")
        reply_to = str(ep.address)
        if (pred.get("nat") or {}).get("type") == "snat":
            reply_to = pred["nat"]["to"]
        back = _run("ip", "-n", dep.namespace, "route", "get", reply_to)
        ev["destination"] = {"endpoint": dname, "namespace": dep.namespace,
                             "listening": bool(listening.stdout.strip()),
                             "route_back": back.stdout.strip() if back.returncode == 0 else None,
                             "reply_to": reply_to}
    ev["conclusion"] = conclude(ev)
    return ev


def conclude(ev: dict) -> dict:
    p, live, src = ev["prediction"], ev["live"], ev["source"]
    out, d = live["outcome"], live["drop_counter_deltas"]
    dest = ev.get("destination") or {}
    if not src["exists"] or not src["address_present"]:
        return {"confirmed": True, "cause": "the source endpoint is not set up (namespace or address "
                "missing)", "next": "myfw-lab up"}
    if p["verdict"] == "drop":
        if out == "timeout" and d.get(p.get("reason", "rule"), 0) > 0:
            return {"confirmed": True, "cause": f"firewall policy drops it: {p['explanation']}",
                    "evidence": f"{p['reason']} drop counter +{d[p['reason']]}",
                    "next": "change the policy (fwctl diff / apply) if this flow should be allowed"}
        if out == "timeout":
            return {"confirmed": False, "cause": f"predicted drop ({p['explanation']}) and the test timed "
                    "out, but no matching drop counter moved", "next": "check the route from the source"}
        return {"confirmed": False, "cause": f"policy predicts DROP but the live test says {out}",
                "next": "fwctl status: is the active generation the policy you think it is?"}
    # predicted accept
    if out == "connected":
        return {"confirmed": True, "cause": "works: policy allows it and the live connection succeeded"}
    if not src["route_via_gateway"]:
        return {"confirmed": True, "cause": "the source has no route to the destination via the gateway",
                "evidence": src["route"], "next": "fix the source routing (ip -n NS route ...)"}
    if d:
        r = max(d, key=d.get)
        return {"confirmed": True, "cause": f"dropped by the firewall for a non-policy reason: {r}",
                "evidence": d, "next": "see docs/runbook.md for this drop reason"}
    if dest and not dest["listening"]:
        if out == "refused" or out == "timeout":
            return {"confirmed": True, "cause": f"nothing listens on the destination "
                    f"({dest['endpoint']}); the packet was allowed", "next": "start the service"}
    if dest and not dest["route_back"]:
        return {"confirmed": True, "cause": f"the destination has no route back to {dest['reply_to']}",
                "evidence": "ip route get failed in the destination namespace",
                "next": "fix the destination routing, or use SNAT"}
    return {"confirmed": False, "cause": f"policy allows it but the test said {out}; no drop counter "
            "moved and the destination looks ready: not enough evidence",
            "next": "re-run with --capture and compare both interfaces' packets"}


def text(ev: dict) -> str:
    p = ev["prediction"]
    lines = [
        f"1. active policy: generation {ev['active']['generation']}, hash {ev['active']['policy_hash'][:16]}"
        f"{'' if ev['active']['managed'] else ' (NOT managed by fwctl)'}",
        f"2. source {ev['query']['from']} ({ev['source']['address']} in netns {ev['source']['namespace']}): "
        f"route {'via the gateway' if ev['source']['route_via_gateway'] else 'NOT via the gateway'}"
        f" [{ev['source']['route']}]",
        f"3. prediction: {p['verdict'].upper()} - {p['explanation']}"
        + (f"; NAT {p['nat']['type']} {p['nat']['id']} -> {p['nat']['to']}" if p.get("nat") else ""),
        f"4. live test: {ev['live']['outcome']}; drop counters moved: {ev['live']['drop_counter_deltas'] or 'none'}",
    ]
    if ev.get("destination"):
        d = ev["destination"]
        lines.append(f"5. destination {d['endpoint']}: listening={d['listening']}, "
                     f"route back to {d['reply_to']}: {'yes' if d['route_back'] else 'NO'}")
    if ev["live"].get("captures"):
        lines.append(f"   captures: {', '.join(ev['live']['captures'])}")
    c = ev["conclusion"]
    lines.append(f"6. {'CONFIRMED' if c['confirmed'] else 'NOT CONFIRMED'}: {c['cause']}")
    if c.get("evidence"):
        lines.append(f"   evidence: {json.dumps(c['evidence']) if not isinstance(c['evidence'], str) else c['evidence']}")
    if c.get("next"):
        lines.append(f"   next: {c['next']}")
    return "\n".join(lines)
