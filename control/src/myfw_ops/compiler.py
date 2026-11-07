"""Canonical policy, semantic hash, diff and kernel blob.

Pipeline (docs/policy-semantics.md):
    YAML -> Pydantic models -> validator (semantic checks)
         -> canonical effective policy  = baseline (from the inventory)
                                          + business policy (from Git)
         -> semantic hash (sha256 of the canonical JSON)
         -> kernel blob (abi.pack_policy)

The canonical form keeps only what changes packet handling: owner/reason
and comments do not change the hash, so re-applying a policy whose meaning
did not change is a no-op and does not reset flows.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Optional

from . import abi
from .models import ANY_PORTS, Inventory, Policy

BASELINE_PREFIX = "baseline:"


def _cidr(n) -> str:
    return str(ipaddress.ip_network(str(n)))


def _rule(id_, origin, scope, zone, src, dst, proto, sport, dport, action, log):
    return {"id": id_, "origin": origin, "scope": scope, "zone": zone,
            "source": _cidr(src), "destination": _cidr(dst), "protocol": proto,
            "sport": [sport.lo, sport.hi], "dport": [dport.lo, dport.hi],
            "action": action, "log": bool(log)}


def baseline(inv: Inventory) -> tuple[list[dict], list[dict]]:
    """Zones and rules that protect the box itself. Always first in the chain.

    - loopback traffic and management services from the admin sources;
    - everything else towards the management subnet is dropped (data zones
      can never reach or be forwarded to it);
    - management service ports on every router address are dropped for
      everyone else, before any business rule is evaluated;
    - the router may talk to itself, loopback and the management subnet.
    """
    m = inv.management
    zones = [
        {"name": "loopback", "interface": "lo", "sources": []},
        {"name": "mgmt", "interface": m.interface, "sources": [_cidr(m.address.network)]},
    ]
    from .models import PortRange
    one = lambda port: PortRange(lo=port, hi=port)  # noqa: E731
    any_net = "0.0.0.0/0"
    rules = [_rule(f"{BASELINE_PREFIX}loopback-in", "baseline", "ingress", "loopback", any_net, any_net,
                   "any", ANY_PORTS, ANY_PORTS, "accept", False)]
    for svc in m.services:
        for i, src in enumerate(m.admin_sources):
            rules.append(_rule(f"{BASELINE_PREFIX}mgmt-{svc.name}-{i}", "baseline", "ingress", "mgmt",
                               src, f"{m.address.ip}/32", svc.protocol, ANY_PORTS, one(svc.port),
                               "accept", False))
    rules.append(_rule(f"{BASELINE_PREFIX}deny-to-mgmt-net", "baseline", "ingress", None, any_net,
                       m.address.network, "any", ANY_PORTS, ANY_PORTS, "drop", True))
    for svc in m.services:
        for i, addr in enumerate(inv.router_addresses()):
            rules.append(_rule(f"{BASELINE_PREFIX}deny-{svc.name}-{i}", "baseline", "ingress", None,
                               any_net, f"{addr}/32", svc.protocol, ANY_PORTS, one(svc.port),
                               "drop", True))
    rules.append(_rule(f"{BASELINE_PREFIX}local-loopback", "baseline", "local_out", None, any_net,
                       "127.0.0.0/8", "any", ANY_PORTS, ANY_PORTS, "accept", False))
    for i, addr in enumerate(inv.router_addresses()):
        rules.append(_rule(f"{BASELINE_PREFIX}local-self-{i}", "baseline", "local_out", None, any_net,
                           f"{addr}/32", "any", ANY_PORTS, ANY_PORTS, "accept", False))
    rules.append(_rule(f"{BASELINE_PREFIX}local-mgmt", "baseline", "local_out", None, any_net,
                       m.address.network, "any", ANY_PORTS, ANY_PORTS, "accept", False))
    return zones, rules


def business_rules(policy: Policy) -> list[dict]:
    """Expand port lists: one kernel rule per (source range, destination range)."""
    out = []
    for r in policy.rules:
        combos = [(s, d) for s in r.source_ports for d in r.destination_ports]
        for k, (s, d) in enumerate(combos):
            rid = r.id if len(combos) == 1 else f"{r.id}:{k + 1}"
            out.append(_rule(rid, "policy", r.scope, r.ingress_zone, r.source, r.destination,
                             r.protocol, s, d, r.action, r.log))
    return out


def canonical(policy: Policy, inv: Inventory) -> dict:
    bz, br = baseline(inv)
    zones = bz + [{"name": n, "interface": z.interface,
                   "sources": sorted(_cidr(s) for s in z.allowed_sources)}
                  for n, z in policy.zones.items()]
    nats = []
    for n in policy.nat:
        if n.type == "snat":
            lo, hi = n.snat_ports
            nats.append({"id": n.id, "type": "snat", "zone": n.ingress_zone,
                         "egress_interface": n.egress_interface, "source": _cidr(n.source),
                         "destination": _cidr(n.destination), "protocol": n.protocol,
                         "dport": 0, "to_address": str(n.to_address), "to_ports": [lo, hi]})
        else:
            port = n.to_port or n.dnat_port
            nats.append({"id": n.id, "type": "dnat", "zone": n.ingress_zone,
                         "egress_interface": "", "source": "0.0.0.0/0",
                         "destination": _cidr(n.destination), "protocol": n.protocol,
                         "dport": n.dnat_port, "to_address": str(n.to_address),
                         "to_ports": [port, port]})
    return {
        "uapi_version": abi.UAPI_VERSION,
        "defaults": {"action": policy.defaults.action, "log": policy.defaults.log_mode != "none"},
        "zones": sorted(zones, key=lambda z: z["name"]),
        "rules": br + business_rules(policy),
        "nat": nats,
    }


def canonical_json(c: dict) -> str:
    return json.dumps(c, sort_keys=True, separators=(",", ":"))


def semantic_hash(c: dict) -> str:
    return hashlib.sha256(canonical_json(c).encode()).hexdigest()


def _mask(prefix: int) -> int:
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0


def _net_pair(cidr: str) -> tuple[int, int]:
    n = ipaddress.ip_network(cidr)
    return int(n.network_address), _mask(n.prefixlen)


def to_blob(c: dict, label: str, managed: bool = True) -> bytes:
    """Encode a canonical policy for the kernel. The label (change id) is not
    part of the semantic hash."""
    zone_idx = {z["name"]: i + 1 for i, z in enumerate(c["zones"])}
    zones = [{"name": z["name"], "ifname": z["interface"],
              "srcs": [_net_pair(s) for s in z["sources"]]} for z in c["zones"]]
    rules = []
    for r in c["rules"]:
        sa, sm = _net_pair(r["source"])
        da, dm = _net_pair(r["destination"])
        rules.append({"id": r["id"], "saddr": sa, "smask": sm, "daddr": da, "dmask": dm,
                      "sport": r["sport"], "dport": r["dport"],
                      "scope": {"ingress": abi.SCOPE_INGRESS, "local_out": abi.SCOPE_LOCAL_OUT,
                                "any": abi.SCOPE_ANY}[r["scope"]],
                      "zone": zone_idx[r["zone"]] if r["zone"] else 0,
                      "proto": abi.PROTO[r["protocol"]],
                      "action": abi.ACT_ACCEPT if r["action"] == "accept" else abi.ACT_DROP,
                      "log": 1 if r["log"] else 0})
    nats = []
    for n in c["nat"]:
        sa, sm = _net_pair(n["source"])
        da, dm = _net_pair(n["destination"])
        nats.append({"id": n["id"], "out_ifname": n["egress_interface"] or "",
                     "saddr": sa, "smask": sm, "daddr": da, "dmask": dm,
                     "to_addr": int(ipaddress.ip_address(n["to_address"])),
                     "dport": n["dport"], "to_ports": n["to_ports"],
                     "type": abi.NAT_SNAT if n["type"] == "snat" else abi.NAT_DNAT,
                     "proto": abi.PROTO[n["protocol"]],
                     "zone": zone_idx[n["zone"]] if n["zone"] else 0})
    hdr = {"default_action": abi.ACT_ACCEPT if c["defaults"]["action"] == "accept" else abi.ACT_DROP,
           "default_log": 1 if c["defaults"]["log"] else 0,
           "flags": abi.POLICY_F_MANAGED if managed else 0,
           "policy_hash": semantic_hash(c), "label": label[: abi.LABEL_LEN - 1]}
    return abi.pack_policy(hdr, zones, rules, nats)


def diff(old: Optional[dict], new: dict) -> dict:
    """What a change does, by id. Every committed change resets all flows
    (one generation per commit), unless the semantic hash is unchanged."""
    old_hash = semantic_hash(old) if old else None
    if old is None:
        old = {"defaults": {}, "zones": [], "rules": [], "nat": []}
    out: dict = {"no_op": semantic_hash(new) == old_hash}

    def by_id(items, key):
        return {i[key]: i for i in items}

    for section, key in (("rules", "id"), ("nat", "id"), ("zones", "name")):
        a, b = by_id(old.get(section, []), key), by_id(new.get(section, []), key)
        added = [k for k in b if k not in a]
        removed = [k for k in a if k not in b]
        changed = {k: {f: [a[k].get(f), b[k].get(f)] for f in b[k] if a[k].get(f) != b[k].get(f)}
                   for k in b if k in a and a[k] != b[k]}
        out[section] = {"added": added, "removed": removed, "modified": changed}
    old_order = [r["id"] for r in old.get("rules", []) if r["id"] in by_id(new["rules"], "id")]
    new_order = [r["id"] for r in new["rules"] if r["id"] in by_id(old.get("rules", []), "id")]
    out["rules"]["reordered"] = old_order != new_order
    out["defaults"] = None if old.get("defaults") == new["defaults"] else \
        {"from": old.get("defaults"), "to": new["defaults"]}
    out["resets_flows"] = not out["no_op"]
    return out


def diff_text(d: dict) -> str:
    if d["no_op"]:
        return "no semantic change (same policy hash): applying is a no-op, flows are kept"
    lines = []
    if d["defaults"]:
        lines.append(f"~ defaults {d['defaults']['from']} -> {d['defaults']['to']}")
    for section in ("zones", "rules", "nat"):
        s = d[section]
        lines += [f"+ {section[:-1] if section != 'nat' else 'nat'} {k}" for k in s["added"]]
        lines += [f"- {section[:-1] if section != 'nat' else 'nat'} {k}" for k in s["removed"]]
        for k, fields in s["modified"].items():
            for f, (a, b) in fields.items():
                lines.append(f"~ {section[:-1] if section != 'nat' else 'nat'} {k}: {f} {a} -> {b}")
    if d["rules"].get("reordered"):
        lines.append("~ rule order changed (first match wins)")
    lines.append("! committing resets every tracked flow (new generation); "
                 "translated (NAT) TCP sessions do not survive")
    return "\n".join(lines)
