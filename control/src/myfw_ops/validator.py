"""Semantic validation of a policy against the inventory.

Levels (docs/policy-semantics.md):
  error        definitely wrong: unknown zone, duplicate id, unreachable NAT target...
  unsupported  meaningful, but outside what this firewall implements
               (overlapping zones, double NAT, hairpin NAT, ambiguous return path)
  danger       would weaken the protection of the box itself
               (opening the management network or services, touching the baseline)
  warning      legal but suspicious (shadowed / redundant rules, published but blocked)
  info         things only traffic tests can prove

error/unsupported/danger always block. Shadowing blocks when
defaults.shadowing is "error". Everything here is decided from the policy
and inventory alone; nothing is claimed about application-level behaviour.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

from . import abi
from .compiler import BASELINE_PREFIX, business_rules, canonical, semantic_hash
from .models import RESERVED_ZONES, Inventory, Policy

BLOCKING = {"error", "unsupported", "danger"}


@dataclass
class Finding:
    level: str
    code: str
    message: str
    ref: Optional[str] = None

    def as_dict(self):
        return {"level": self.level, "code": self.code, "message": self.message, "ref": self.ref}


@dataclass
class Report:
    findings: list = field(default_factory=list)
    canonical: Optional[dict] = None
    policy_hash: Optional[str] = None

    def add(self, level, code, message, ref=None):
        self.findings.append(Finding(level, code, message, ref))

    @property
    def ok(self) -> bool:
        return not any(f.level in BLOCKING for f in self.findings)

    def as_dict(self):
        return {"ok": self.ok, "policy_hash": self.policy_hash,
                "findings": [f.as_dict() for f in self.findings]}


def _net(s) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(str(s))


def _overlap(a, b) -> bool:
    return _net(a).overlaps(_net(b))


def _subset(a, b) -> bool:
    return _net(a).subnet_of(_net(b))


def _route_zone(inv: Inventory, dst) -> tuple[Optional[str], str]:
    """Which zone a destination is routed to, from the fixed lab routing.
    Returns (zone, "") or (None, reason)."""
    dst = _net(dst)
    inside = [n for n, z in inv.zones.items() if dst.subnet_of(z.gateway_address.network)]
    if len(inside) == 1:
        return inside[0], ""
    touching = [n for n, z in inv.zones.items() if dst.overlaps(z.gateway_address.network)]
    if not touching and inv.default_route_zone:
        return inv.default_route_zone, ""
    if touching:
        return None, f"{dst} spans zones {', '.join(touching)}"
    return None, f"{dst} is not inside any zone and there is no default_route_zone"


def _covers(a: dict, b: dict) -> bool:
    """Does rule a match every packet rule b matches? (decidable subset only)"""
    if a["scope"] != b["scope"]:
        return False
    if a["zone"] is not None and a["zone"] != b["zone"]:
        return False
    if a["protocol"] != "any" and a["protocol"] != b["protocol"]:
        return False
    if not (_subset(b["source"], a["source"]) and _subset(b["destination"], a["destination"])):
        return False
    if b["protocol"] in ("tcp", "udp") or a["protocol"] in ("tcp", "udp"):
        if not (a["sport"][0] <= b["sport"][0] and b["sport"][1] <= a["sport"][1]
                and a["dport"][0] <= b["dport"][0] and b["dport"][1] <= a["dport"][1]):
            return False
    return True


def validate(policy: Policy, inv: Inventory, live_interfaces: Optional[set] = None) -> Report:
    rep = Report()
    mgmt_net = inv.management.address.network
    router_addrs = inv.router_addresses()
    inv_ifaces = {z.interface: n for n, z in inv.zones.items()}

    # ---- zones ---------------------------------------------------------
    seen_if = {}
    for name, z in policy.zones.items():
        if name in RESERVED_ZONES:
            rep.add("danger", "reserved-zone", f"zone name {name!r} is reserved for the baseline", name)
        if z.interface in (inv.management.interface, "lo"):
            rep.add("danger", "zone-on-mgmt", f"zone {name} uses the management/loopback interface "
                    f"{z.interface}", name)
        elif z.interface not in inv_ifaces:
            rep.add("error", "unknown-interface", f"zone {name}: interface {z.interface} is not a "
                    "data interface in the inventory", name)
        if z.interface in seen_if:
            rep.add("error", "duplicate-interface", f"zones {seen_if[z.interface]} and {name} both use "
                    f"{z.interface}", name)
        seen_if[z.interface] = name
        for s in z.allowed_sources:
            if s.overlaps(mgmt_net):
                rep.add("danger", "zone-claims-mgmt", f"zone {name} accepts sources in the management "
                        f"network {mgmt_net}", name)
    names = list(policy.zones)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            for sa in policy.zones[a].allowed_sources:
                for sb in policy.zones[b].allowed_sources:
                    if sa.overlaps(sb):
                        rep.add("unsupported", "overlapping-zones", f"zones {a} and {b} both accept "
                                f"{sa} / {sb}: the ingress zone of a source would be ambiguous", f"{a},{b}")
    inv_names = list(inv.zones)
    for i, a in enumerate(inv_names):
        for b in inv_names[i + 1:]:
            if inv.zones[a].gateway_address.network.overlaps(inv.zones[b].gateway_address.network):
                rep.add("unsupported", "overlapping-subnets", f"inventory zones {a} and {b} have "
                        "overlapping subnets", f"{a},{b}")
    if live_interfaces is not None:
        for name, z in policy.zones.items():
            if z.interface not in live_interfaces:
                rep.add("error", "interface-missing", f"zone {name}: interface {z.interface} does not "
                        "exist on this host now", name)

    # ---- rules ---------------------------------------------------------
    ids = set()
    for r in policy.rules:
        if r.id in ids:
            rep.add("error", "duplicate-id", f"rule id {r.id} is used twice", r.id)
        ids.add(r.id)
        if r.ingress_zone and r.ingress_zone not in policy.zones:
            rep.add("error", "unknown-zone", f"rule {r.id}: zone {r.ingress_zone} is not defined", r.id)
        if r.action == "accept":
            if r.scope == "ingress" and r.destination.overlaps(mgmt_net):
                rep.add("danger", "opens-mgmt-net", f"rule {r.id} would allow traffic into the "
                        f"management network {mgmt_net}", r.id)
            for svc in inv.management.services:
                if r.protocol not in (svc.protocol, "any"):
                    continue
                if not any(p.lo <= svc.port <= p.hi for p in r.destination_ports):
                    continue
                for a in router_addrs:
                    if a in r.destination:
                        rep.add("danger", "opens-mgmt-service", f"rule {r.id} would open the "
                                f"management service {svc.name} ({svc.protocol}/{svc.port}) on {a}", r.id)
                        break
    expanded = business_rules(policy)
    if len(expanded) + 20 > abi.MAX_RULES:
        rep.add("error", "too-many-rules", f"{len(expanded)} kernel rules after port expansion; "
                f"the kernel holds {abi.MAX_RULES} including the baseline")

    # ---- NAT -----------------------------------------------------------
    nat_ids = set()
    for n in policy.nat:
        if n.id in nat_ids or n.id in ids:
            rep.add("error", "duplicate-id", f"NAT id {n.id} is already used", n.id)
        nat_ids.add(n.id)
        if n.ingress_zone not in policy.zones:
            rep.add("error", "unknown-zone", f"nat {n.id}: zone {n.ingress_zone} is not defined", n.id)
            continue
        if n.type == "dnat" and n.to_address in router_addrs:
            rep.add("unsupported", "nat-to-gateway", f"nat {n.id}: publishing a service of the gateway "
                    "itself is not supported", n.id)
        if n.type == "snat":
            if n.egress_interface == inv.management.interface:
                rep.add("danger", "nat-to-mgmt", f"nat {n.id} would send traffic out of the "
                        "management interface", n.id)
                continue
            if n.egress_interface not in inv_ifaces:
                rep.add("error", "unknown-interface", f"nat {n.id}: egress interface "
                        f"{n.egress_interface} is not a data interface", n.id)
                continue
            if n.destination.prefixlen == 0:
                rep.add("unsupported", "snat-unbounded", f"nat {n.id}: SNAT must name its destination "
                        "(cross-zone traffic is not translated wholesale)", n.id)
                continue
            zone, why = _route_zone(inv, n.destination)
            egress_zone = inv_ifaces[n.egress_interface]
            if zone is None:
                rep.add("unsupported", "ambiguous-egress", f"nat {n.id}: {why}", n.id)
            elif zone != egress_zone:
                rep.add("error", "egress-mismatch", f"nat {n.id}: {n.destination} is routed via "
                        f"{inv.zones[zone].interface}, not {n.egress_interface}", n.id)
            if str(n.to_address) != str(inv.zones[egress_zone].gateway_address.ip):
                rep.add("error", "snat-address", f"nat {n.id}: to_address must be the gateway address "
                        f"on {n.egress_interface} ({inv.zones[egress_zone].gateway_address.ip}) so "
                        "replies come back to this box", n.id)
        else:
            inside = [zn for zn, z in inv.zones.items() if n.to_address in z.gateway_address.network]
            zone = inside[0] if len(inside) == 1 else None
            if zone is None:
                rep.add("error", "nat-target-unreachable", f"nat {n.id}: {n.to_address} is not on a "
                        "directly connected zone network (published services must be inside)", n.id)
            else:
                in_if = policy.zones[n.ingress_zone].interface
                if inv.zones[zone].interface == in_if:
                    rep.add("unsupported", "hairpin-nat", f"nat {n.id}: target is in the ingress zone "
                            "(hairpin NAT is not implemented)", n.id)
            if n.destination.network_address not in router_addrs:
                rep.add("unsupported", "vip-not-local", f"nat {n.id}: the published address "
                        f"{n.destination.network_address} must be one of this box's addresses", n.id)
            covered = any(r.action == "accept" and r.ingress_zone == n.ingress_zone
                          and r.protocol in (n.protocol, "any")
                          and n.destination.subnet_of(r.destination)
                          and any(p.lo <= n.dnat_port <= p.hi for p in r.destination_ports)
                          for r in policy.rules)
            if not covered:
                rep.add("warning", "published-but-blocked", f"nat {n.id}: no accept rule allows "
                        f"{n.destination.network_address}:{n.dnat_port} from {n.ingress_zone}; the "
                        "mapping alone does not open anything", n.id)
    dnats = [n for n in policy.nat if n.type == "dnat"]
    for i, a in enumerate(dnats):
        for b in dnats[i + 1:]:
            if a.destination == b.destination and a.dnat_port == b.dnat_port and a.protocol == b.protocol:
                rep.add("error", "overlapping-vip", f"nat {a.id} and {b.id} publish the same address "
                        "and port", f"{a.id},{b.id}")
    for d in dnats:
        for s in (n for n in policy.nat if n.type == "snat"):
            if s.ingress_zone == d.ingress_zone and d.destination.subnet_of(s.destination) \
                    and d.destination.overlaps(s.destination):
                rep.add("unsupported", "double-nat", f"nat {d.id} and {s.id} could both apply to one "
                        "flow (double NAT is not implemented)", f"{d.id},{s.id}")

    # ---- shadowing (on the expanded kernel rules, baseline first) --------
    if rep.ok:
        try:
            c = canonical(policy, inv)
        except ValueError as e:
            rep.add("error", "compile", str(e))
            return rep
        level = "error" if policy.defaults.shadowing == "error" else "warning"
        rules = c["rules"]
        for j, b in enumerate(rules):
            if b["id"].startswith(BASELINE_PREFIX):
                continue
            for a in rules[:j]:
                if _covers(a, b):
                    if a["id"].startswith(BASELINE_PREFIX) and b["action"] == "accept" \
                            and a["action"] == "drop":
                        rep.add("danger", "baseline-blocks", f"rule {b['id']} is overridden by the "
                                f"protected baseline rule {a['id']}", b["id"])
                    else:
                        kind = "redundant" if a["action"] == b["action"] else "shadowed"
                        rep.add(level, kind, f"rule {b['id']} never decides anything: every packet it "
                                f"matches is decided earlier by {a['id']} ({a['action']})", b["id"])
                    break
        if rep.ok:
            rep.canonical = c
            rep.policy_hash = semantic_hash(c)
            rep.add("info", "needs-traffic-test", "the policy is consistent; whether services really "
                    "work is proven by `fwctl verify`, not by validation")
    return rep
