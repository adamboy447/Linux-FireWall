"""Policy and inventory schema.

Two documents describe the system:

* the INVENTORY (lab/inventory.yaml, installed as /etc/myfw/inventory.yaml)
  is owned by the operator of the box: management interface and admin
  sources, data zones with their interface and subnet, test endpoints and the
  required-service probes. The protected baseline is generated from it.
* the POLICY (policies/*.yaml, kept in Git) is the business request: zones
  (bound to inventory interfaces), filter rules and NAT, each with an owner
  and a reason.

Only IPv4 is accepted anywhere: an IPv6 address is a validation error, not
something that is silently ignored.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,55}$")
IFNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,15}$")
RESERVED_ZONES = {"mgmt", "loopback", "local"}


def _check_id(v: str) -> str:
    if not ID_RE.fullmatch(v):
        raise ValueError("ids are 1-56 characters of A-Z a-z 0-9 . _ - (starting alphanumeric)")
    return v


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _net(v) -> ipaddress.IPv4Network:
    if isinstance(v, ipaddress.IPv4Network):
        return v
    s = str(v).strip()
    if s in ("any", "0/0"):
        s = "0.0.0.0/0"
    try:
        obj = ipaddress.ip_network(s, strict=True)
    except ValueError as e:
        raise ValueError(f"{s!r} is not a valid IPv4 CIDR with host bits clear ({e})") from None
    if obj.version != 4:
        raise ValueError(f"{s!r}: IPv6 is not supported (IPv4 only)")
    return obj


def _addr(v) -> ipaddress.IPv4Address:
    try:
        obj = ipaddress.ip_address(str(v).strip())
    except ValueError:
        raise ValueError(f"{v!r} is not an IPv4 address") from None
    if obj.version != 4:
        raise ValueError(f"{v!r}: IPv6 is not supported (IPv4 only)")
    return obj


def _iface(v) -> ipaddress.IPv4Interface:
    try:
        obj = ipaddress.ip_interface(str(v).strip())
    except ValueError:
        raise ValueError(f"{v!r} is not an IPv4 address/prefix") from None
    if obj.version != 4:
        raise ValueError(f"{v!r}: IPv6 is not supported (IPv4 only)")
    return obj


class PortRange(Strict):
    lo: int = Field(ge=0, le=65535)
    hi: int = Field(ge=0, le=65535)

    @model_validator(mode="after")
    def _order(self):
        if self.lo > self.hi:
            raise ValueError(f"port range {self.lo}-{self.hi} is reversed")
        return self

    @classmethod
    def parse(cls, v) -> "PortRange":
        if isinstance(v, PortRange):
            return v
        if isinstance(v, bool):
            raise ValueError("a port must be a number or 'lo-hi'")
        if isinstance(v, int):
            return cls(lo=v, hi=v)
        if isinstance(v, dict) and set(v) == {"lo", "hi"}:
            return cls(**v)
        s = str(v).strip()
        if s == "any":
            return cls(lo=0, hi=65535)
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", s)
        if m:
            return cls(lo=int(m.group(1)), hi=int(m.group(2)))
        if s.isdigit():
            return cls(lo=int(s), hi=int(s))
        raise ValueError(f"{v!r} is not a port or a 'lo-hi' range")

    def __str__(self) -> str:
        if self.lo == 0 and self.hi == 65535:
            return "any"
        return str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}"

    def contains(self, other: "PortRange") -> bool:
        return self.lo <= other.lo and other.hi <= self.hi


ANY_PORTS = PortRange(lo=0, hi=65535)


def _ports(v) -> list[PortRange]:
    if v is None:
        return [ANY_PORTS]
    if not isinstance(v, list):
        v = [v]
    if not v:
        raise ValueError("port list is empty (omit it for 'any')")
    return [PortRange.parse(x) for x in v]


# ------------------------------------------------------------------ inventory

class Service(Strict):
    name: str
    protocol: Literal["tcp", "udp"] = "tcp"
    port: int = Field(ge=1, le=65535)


class Management(Strict):
    interface: str
    address: ipaddress.IPv4Interface
    admin_sources: list[ipaddress.IPv4Network]
    services: list[Service] = [Service(name="ssh", port=22)]

    @field_validator("address", mode="before")
    @classmethod
    def _a(cls, v):
        return _iface(v)

    @field_validator("admin_sources", mode="before")
    @classmethod
    def _s(cls, v):
        return [_net(x) for x in v]


class InvZone(Strict):
    interface: str
    gateway_address: ipaddress.IPv4Interface     # router address + subnet on that link
    @field_validator("gateway_address", mode="before")
    @classmethod
    def _g(cls, v):
        return _iface(v)

    @field_validator("interface")
    @classmethod
    def _ifn(cls, v):
        if not IFNAME_RE.fullmatch(v):
            raise ValueError(f"bad interface name {v!r}")
        return v


class Endpoint(Strict):
    namespace: str
    zone: str
    address: ipaddress.IPv4Address
    services: list[Service] = []
    @field_validator("address", mode="before")
    @classmethod
    def _a(cls, v):
        return _addr(v)


class Probe(Strict):
    name: str
    from_: str = Field(alias="from")
    to: ipaddress.IPv4Address
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    check: Literal["tcp", "https", "udp"] = "tcp"
    expect: Literal["allow", "deny"] = "allow"
    required: bool = True
    @field_validator("to", mode="before")
    @classmethod
    def _t(cls, v):
        return _addr(v)

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Inventory(Strict):
    schema_version: Literal[1]
    gateway: str = "fwlab"
    management: Management
    zones: dict[str, InvZone]
    default_route_zone: Optional[str] = None
    endpoints: dict[str, Endpoint] = {}
    required_services: list[Probe] = []

    @model_validator(mode="after")
    def _check(self):
        for z in self.zones:
            if z in RESERVED_ZONES:
                raise ValueError(f"zone name {z!r} is reserved for the baseline")
        if self.default_route_zone and self.default_route_zone not in self.zones:
            raise ValueError(f"default_route_zone {self.default_route_zone!r} is not a zone")
        for name, e in self.endpoints.items():
            if e.zone not in self.zones:
                raise ValueError(f"endpoint {name}: unknown zone {e.zone!r}")
        for p in self.required_services:
            if p.from_ not in self.endpoints:
                raise ValueError(f"probe {p.name}: unknown endpoint {p.from_!r}")
        return self

    def router_addresses(self) -> list[ipaddress.IPv4Address]:
        return [self.management.address.ip] + [z.gateway_address.ip for z in self.zones.values()]


# --------------------------------------------------------------------- policy

class Metadata(Strict):
    name: str
    owner: str
    reason: str


class Defaults(Strict):
    action: Literal["drop", "accept"] = "drop"
    log_mode: Literal["none", "sampled"] = "sampled"   # sampled = kernel rate-limited events
    shadowing: Literal["warn", "error"] = "warn"


class Zone(Strict):
    interface: str
    allowed_sources: list[ipaddress.IPv4Network]
    @field_validator("allowed_sources", mode="before")
    @classmethod
    def _s(cls, v):
        return [_net(x) for x in v]

    @field_validator("allowed_sources")
    @classmethod
    def _n(cls, v):
        if not 1 <= len(v) <= 8:
            raise ValueError("a zone needs 1 to 8 allowed source CIDRs")
        return v


class Rule(Strict):
    id: str
    scope: Literal["ingress", "local_out"] = "ingress"
    ingress_zone: Optional[str] = None
    source: ipaddress.IPv4Network = ipaddress.IPv4Network("0.0.0.0/0")
    destination: ipaddress.IPv4Network = ipaddress.IPv4Network("0.0.0.0/0")
    protocol: Literal["tcp", "udp", "icmp", "any"] = "any"
    source_ports: list[PortRange] = [ANY_PORTS]
    destination_ports: list[PortRange] = [ANY_PORTS]
    action: Literal["accept", "drop"]
    log: bool = False
    owner: str
    reason: str

    @field_validator("source", "destination", mode="before")
    @classmethod
    def _nets(cls, v):
        return _net(v)

    @field_validator("source_ports", "destination_ports", mode="before")
    @classmethod
    def _p(cls, v):
        return _ports(v)

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        return _check_id(v)

    @model_validator(mode="after")
    def _shape(self):
        if self.scope == "local_out" and self.ingress_zone:
            raise ValueError(f"rule {self.id}: a local_out rule has no ingress zone")
        if self.scope == "ingress" and not self.ingress_zone:
            raise ValueError(f"rule {self.id}: an ingress rule must name its ingress_zone")
        if self.protocol in ("icmp", "any") and (self.source_ports != [ANY_PORTS]
                                                 or self.destination_ports != [ANY_PORTS]):
            raise ValueError(f"rule {self.id}: ports need protocol tcp or udp")
        return self


class Nat(Strict):
    id: str
    type: Literal["snat", "dnat"]
    ingress_zone: str
    egress_interface: Optional[str] = None
    source: ipaddress.IPv4Network = ipaddress.IPv4Network("0.0.0.0/0")
    destination: ipaddress.IPv4Network = ipaddress.IPv4Network("0.0.0.0/0")
    protocol: Literal["tcp", "udp", "icmp", "any"] = "any"
    destination_ports: Optional[list[PortRange]] = None
    to_address: ipaddress.IPv4Address
    to_port: Optional[int] = Field(default=None, ge=1, le=65535)
    port_range: Optional[list[int]] = None

    @field_validator("source", "destination", mode="before")
    @classmethod
    def _nets(cls, v):
        return _net(v)

    @field_validator("to_address", mode="before")
    @classmethod
    def _a(cls, v):
        return _addr(v)

    @field_validator("destination_ports", mode="before")
    @classmethod
    def _p(cls, v):
        return None if v is None else _ports(v)

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        return _check_id(v)

    @model_validator(mode="after")
    def _shape(self):
        if self.type == "snat":
            if not self.egress_interface:
                raise ValueError(f"nat {self.id}: SNAT needs egress_interface")
            if self.destination_ports or self.to_port:
                raise ValueError(f"nat {self.id}: SNAT takes port_range, not destination_ports/to_port")
            pr = self.port_range or [1024, 65535]
            if len(pr) != 2 or not 1 <= pr[0] <= pr[1] <= 65535:
                raise ValueError(f"nat {self.id}: port_range must be [lo, hi] within 1-65535")
        else:
            if self.protocol not in ("tcp", "udp"):
                raise ValueError(f"nat {self.id}: DNAT needs protocol tcp or udp")
            if self.destination.prefixlen != 32:
                raise ValueError(f"nat {self.id}: DNAT destination must be a single /32 address")
            dp = self.destination_ports or []
            if len(dp) != 1 or dp[0].lo != dp[0].hi or dp[0].lo == 0:
                raise ValueError(f"nat {self.id}: DNAT needs exactly one destination port")
            if self.port_range or self.egress_interface:
                raise ValueError(f"nat {self.id}: DNAT takes to_port, not port_range/egress_interface")
        return self

    @property
    def dnat_port(self) -> int:
        return self.destination_ports[0].lo if self.destination_ports else 0

    @property
    def snat_ports(self) -> tuple[int, int]:
        pr = self.port_range or [1024, 65535]
        return pr[0], pr[1]


class Policy(Strict):
    schema_version: Literal[1]
    metadata: Metadata
    defaults: Defaults = Defaults()
    zones: dict[str, Zone]
    rules: list[Rule] = []
    nat: list[Nat] = []


def load_yaml_model(cls, text: str):
    import yaml

    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("document is empty or not a mapping")
    return cls.model_validate(data)


AnyModel = Union[Policy, Inventory]
