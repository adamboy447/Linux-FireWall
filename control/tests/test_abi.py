"""The Python encoder against the C structures (compiled from include/ and cmd/)."""
import ipaddress
import json
import os
import shutil
import subprocess

import pytest

from conftest import ROOT
from myfw_ops import abi
from myfw_ops.compiler import to_blob
from myfw_ops.validator import validate

pytestmark = pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")


@pytest.fixture(scope="module")
def blobdump(tmp_path_factory):
    out = tmp_path_factory.mktemp("c") / "blobdump"
    cmd = ROOT + "/cmd"
    subprocess.run(["gcc", "-O0", "-Wall", "-Werror", f"-I{ROOT}/include", f"-I{cmd}", "-o", str(out),
                    os.path.join(os.path.dirname(__file__), "c", "blobdump.c"),
                    f"{cmd}/policy.c", f"{cmd}/util.c", f"{cmd}/sha256.c", f"{cmd}/nl.c"], check=True)
    return str(out)


def test_layout_matches_c(blobdump):
    lay = json.loads(subprocess.run([blobdump, "--layout"], capture_output=True, text=True).stdout)
    for name, size in abi.EXPECTED_SIZES.items():
        assert lay[name] == size
    assert lay["fw_policy_hdr"] == abi.POLICY_HDR.size
    assert lay["fw_zone_spec"] == abi.ZONE_SPEC.size
    assert lay["rule.scope"] == 64 + 16 + 8
    assert lay["nat.type"] == 64 + 16 + 20 + 8
    assert lay["hdr.policy_hash"] == 24
    assert lay["zone.srcs"] == 88


def test_demo_blob_decodes_identically_in_c(tmp_path, blobdump, demo, inv):
    rep = validate(demo, inv)
    assert rep.ok
    blob = to_blob(rep.canonical, "chg-test")
    p = tmp_path / "demo.bin"
    p.write_bytes(blob)
    d = json.loads(subprocess.run([blobdump, str(p)], capture_output=True, text=True).stdout)
    c = rep.canonical
    assert d["hash"] == rep.policy_hash and d["label"] == "chg-test"
    assert d["flags"] == abi.POLICY_F_MANAGED and d["default_action"] == abi.ACT_DROP
    assert [z["name"] for z in d["zones"]] == [z["name"] for z in c["zones"]]
    assert [r["id"] for r in d["rules"]] == [r["id"] for r in c["rules"]]
    web = next(r for r in d["rules"] if r["id"] == "lan-dmz-web")
    assert web["d"] == [int(ipaddress.ip_address("10.10.20.10")), 0xFFFFFFFF]
    assert web["dp"] == [443, 443] and web["proto"] == 6 and web["action"] == 1
    assert web["scope"] == abi.SCOPE_INGRESS
    assert d["zones"][web["zone"] - 1]["name"] == "lan"
    dn = next(n for n in d["nats"] if n["id"] == "publish-web")
    assert dn["type"] == abi.NAT_DNAT and dn["dport"] == 8443 and dn["tp"] == [443, 443]
    assert dn["to"] == int(ipaddress.ip_address("10.10.20.10"))
    sn = next(n for n in d["nats"] if n["id"] == "lan-outbound")
    assert sn["out"] == "veth-wan" and sn["tp"] == [20000, 20999]


def test_check_module_abi():
    good = {"uapi_version": 3, "module": [16, 16, 144, 176, 152, 96, 112], "uapp": [16, 16, 144, 176, 152, 96, 112]}
    assert abi.check_module_abi(good) == []
    bad = dict(good, module=[16, 16, 144, 176, 152, 100, 112])
    assert abi.check_module_abi(bad)
    assert abi.check_module_abi(dict(good, uapi_version=2))
