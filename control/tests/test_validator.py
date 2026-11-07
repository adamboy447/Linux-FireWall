import glob
import os

import pytest

from conftest import ROOT
from myfw_ops.models import Policy, load_yaml_model
from myfw_ops.validator import validate

CASES = sorted(glob.glob(os.path.join(ROOT, "policies", "invalid", "*.yaml")))


def test_demo_is_valid(demo, inv):
    rep = validate(demo, inv)
    assert rep.ok, rep.as_dict()
    assert rep.policy_hash and len(rep.policy_hash) == 64
    assert [f.code for f in rep.findings] == ["needs-traffic-test"]


@pytest.mark.parametrize("path", CASES, ids=[os.path.basename(c) for c in CASES])
def test_invalid_policy_is_rejected_for_the_right_reason(path, inv):
    text = open(path).read()
    expect = text.splitlines()[0].split("expect:")[1].strip()
    if expect == "schema":
        with pytest.raises(Exception):
            load_yaml_model(Policy, text)
        return
    rep = validate(load_yaml_model(Policy, text), inv)
    assert not rep.ok
    codes = {f.code for f in rep.findings if f.level in ("error", "unsupported", "danger", "warning")}
    assert expect in codes, rep.as_dict()


def test_every_invalid_case_is_listed():
    assert len(CASES) >= 12


def test_live_interface_check(demo, inv):
    rep = validate(demo, inv, live_interfaces={"lo", "mgmt0", "veth-lan", "veth-dmz"})
    assert not rep.ok
    assert any(f.code == "interface-missing" and f.ref == "wan" for f in rep.findings)


def test_shadowing_warn_mode_does_not_block(inv):
    text = open(os.path.join(ROOT, "policies", "invalid", "shadowed.yaml")).read()
    text = text.replace("shadowing: error", "shadowing: warn")
    rep = validate(load_yaml_model(Policy, text), inv)
    assert rep.ok
    assert any(f.code == "shadowed" and f.level == "warning" for f in rep.findings)


def test_published_but_blocked_warning(demo_text, inv):
    pol = load_yaml_model(Policy, demo_text)
    d = pol.model_dump(by_alias=True)
    d["rules"] = [r for r in d["rules"] if r["id"] != "wan-published-web"]
    rep = validate(Policy.model_validate(d), inv)
    assert rep.ok
    assert any(f.code == "published-but-blocked" for f in rep.findings)
