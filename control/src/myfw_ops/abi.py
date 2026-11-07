"""Binary layout of the policy blob (include/fw_proto.h, UAPI v3).

Every format below is little-endian with explicit padding, matching the C
structures byte for byte. The sizes are cross-checked against the running
module (`uapp abi --json`) before anything is applied, and against the C
header at test time (tests/test_abi.py compiles a probe).
"""
from __future__ import annotations

import struct

UAPI_VERSION = 3
POLICY_MAGIC = 0x4D594657
ID_LEN = 64
IFNAME_LEN = 16
HASH_LEN = 72
LABEL_LEN = 64
MAX_ZONES = 8
MAX_ZONE_SRCS = 8
MAX_RULES = 128
MAX_NATS = 32
MAX_POLICY_BYTES = 64 * 1024

ACT_DROP, ACT_ACCEPT = 0, 1
SCOPE_ANY, SCOPE_INGRESS, SCOPE_LOCAL_OUT = 0, 1, 2
POLICY_F_MANAGED, POLICY_F_LEGACY = 0x01, 0x02
NAT_SNAT, NAT_DNAT = 1, 2
PROTO = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}

POLICY_HDR = struct.Struct("<5I4B72s64s4I")
ZONE_SPEC = struct.Struct("<64s16sII" + "I" * (2 * MAX_ZONE_SRCS))
RULE_SPEC = struct.Struct("<64s4I4H5B3x")
NAT_SPEC = struct.Struct("<64s16s5I4H4B")

# index of each struct in the size list returned by FW_REQ_ABI (FW_ABI_LIST)
ABI_INDEX = {"fw_policy_hdr": 3, "fw_zone_spec": 4, "fw_rule_spec": 5, "fw_nat_spec": 6}
EXPECTED_SIZES = {"fw_policy_hdr": 176, "fw_zone_spec": 152, "fw_rule_spec": 96, "fw_nat_spec": 112}

assert POLICY_HDR.size == 176 and ZONE_SPEC.size == 152
assert RULE_SPEC.size == 96 and NAT_SPEC.size == 112

# FW_R_* order in fw_proto.h; names match uapp's reason_name()
DROP_REASONS = [
    "none", "rule", "default_policy", "spoofed_source", "flow_interface",
    "flow_table_full", "no_memory", "nat_allocation_failed", "nat_state_missing",
    "nat_rewrite_failed", "parse_error", "unsupported_fragment", "unsupported_protocol",
    "update_gate", "generation_mismatch", "ipv6", "egress_mismatch",
]


def check_module_abi(report: dict) -> list[str]:
    """Compare `uapp abi --json` with this module's layout; return problems."""
    problems = []
    if report.get("uapi_version") != UAPI_VERSION:
        problems.append(f"module speaks UAPI {report.get('uapi_version')}, fwctl speaks {UAPI_VERSION}")
        return problems
    sizes = report.get("module", [])
    for name, idx in ABI_INDEX.items():
        if idx >= len(sizes) or sizes[idx] != EXPECTED_SIZES[name]:
            got = sizes[idx] if idx < len(sizes) else None
            problems.append(f"{name}: module {got} bytes, fwctl {EXPECTED_SIZES[name]}")
    if report.get("module") != report.get("uapp"):
        problems.append("uapp and the loaded module were built from different headers")
    return problems


def _cstr(s: str, n: int) -> bytes:
    b = s.encode("ascii")
    if len(b) >= n:
        raise ValueError(f"string too long for a {n}-byte field: {s!r}")
    return b


def ip_int(addr) -> int:
    return int(addr)


def pack_policy(hdr: dict, zones: list[dict], rules: list[dict], nats: list[dict]) -> bytes:
    if len(zones) > MAX_ZONES or len(rules) > MAX_RULES or len(nats) > MAX_NATS:
        raise ValueError("policy exceeds kernel limits "
                         f"({MAX_ZONES} zones, {MAX_RULES} rules, {MAX_NATS} NAT)")
    out = [POLICY_HDR.pack(
        POLICY_MAGIC, UAPI_VERSION, len(zones), len(rules), len(nats),
        hdr["default_action"], hdr["default_log"], hdr["flags"], 0,
        _cstr(hdr["policy_hash"], HASH_LEN), _cstr(hdr["label"], LABEL_LEN), 0, 0, 0, 0)]
    for z in zones:
        srcs = []
        for a, m in z["srcs"]:
            srcs += [a, m]
        srcs += [0] * (2 * MAX_ZONE_SRCS - len(srcs))
        out.append(ZONE_SPEC.pack(_cstr(z["name"], ID_LEN), _cstr(z["ifname"], IFNAME_LEN),
                                  len(z["srcs"]), 0, *srcs))
    for r in rules:
        out.append(RULE_SPEC.pack(
            _cstr(r["id"], ID_LEN), r["saddr"], r["smask"], r["daddr"], r["dmask"],
            r["sport"][0], r["sport"][1], r["dport"][0], r["dport"][1],
            r["scope"], r["zone"], r["proto"], r["action"], r["log"]))
    for n in nats:
        out.append(NAT_SPEC.pack(
            _cstr(n["id"], ID_LEN), _cstr(n["out_ifname"], IFNAME_LEN),
            n["saddr"], n["smask"], n["daddr"], n["dmask"], n["to_addr"],
            n["dport"], n["to_ports"][0], n["to_ports"][1], 0,
            n["type"], n["proto"], n["zone"], 0))
    blob = b"".join(out)
    if len(blob) > MAX_POLICY_BYTES:
        raise ValueError("policy blob too large")
    return blob


def unpack_header(blob: bytes) -> dict:
    f = POLICY_HDR.unpack_from(blob, 0)
    return {"magic": f[0], "version": f[1], "n_zones": f[2], "n_rules": f[3], "n_nats": f[4],
            "default_action": f[5], "default_log": f[6], "flags": f[7],
            "policy_hash": f[9].split(b"\0", 1)[0].decode(),
            "label": f[10].split(b"\0", 1)[0].decode()}
