import yaml

from myfw_ops.compiler import BASELINE_PREFIX, canonical, diff, semantic_hash, to_blob
from myfw_ops.models import Policy
from myfw_ops import abi


def mod(text, f):
    d = yaml.safe_load(text)
    f(d)
    return Policy.model_validate(d)


def test_hash_ignores_owner_reason_and_zone_order(demo_text, inv):
    h0 = semantic_hash(canonical(Policy.model_validate(yaml.safe_load(demo_text)), inv))

    def cosmetic(d):
        d["metadata"]["reason"] = "different words"
        d["rules"][0]["owner"] = "someone-else"
        d["zones"] = dict(reversed(list(d["zones"].items())))
    assert semantic_hash(canonical(mod(demo_text, cosmetic), inv)) == h0


def test_hash_changes_with_meaning(demo_text, inv):
    h0 = semantic_hash(canonical(Policy.model_validate(yaml.safe_load(demo_text)), inv))
    h1 = semantic_hash(canonical(mod(demo_text, lambda d: d["rules"][0].update(destination_ports=[443, 8443])), inv))
    h2 = semantic_hash(canonical(mod(demo_text, lambda d: d["rules"].reverse()), inv))
    assert len({h0, h1, h2}) == 3


def test_baseline_is_first_and_protects_mgmt(demo, inv):
    c = canonical(demo, inv)
    ids = [r["id"] for r in c["rules"]]
    first_business = next(i for i, x in enumerate(ids) if not x.startswith(BASELINE_PREFIX))
    assert all(x.startswith(BASELINE_PREFIX) for x in ids[:first_business])
    assert not any(x.startswith(BASELINE_PREFIX) for x in ids[first_business:])
    deny = next(r for r in c["rules"] if r["id"] == "baseline:deny-to-mgmt-net")
    assert deny["destination"] == "10.0.2.0/24" and deny["action"] == "drop" and deny["zone"] is None
    ssh = next(r for r in c["rules"] if r["id"] == "baseline:mgmt-ssh-0")
    assert ssh["zone"] == "mgmt" and ssh["source"] == "10.0.2.2/32" and ssh["dport"] == [22, 22]
    assert {z["name"] for z in c["zones"]} == {"loopback", "mgmt", "lan", "dmz", "wan"}


def test_port_lists_expand_to_one_kernel_rule_each(demo_text, inv):
    p = mod(demo_text, lambda d: d["rules"][0].update(destination_ports=[443, "8000-8100"]))
    ids = [r["id"] for r in canonical(p, inv)["rules"]]
    assert "lan-dmz-web:1" in ids and "lan-dmz-web:2" in ids and "lan-dmz-web" not in ids


def test_blob_is_deterministic_except_label(demo, inv):
    c = canonical(demo, inv)
    a, b = to_blob(c, "x"), to_blob(c, "x")
    assert a == b
    assert abi.unpack_header(to_blob(c, "y"))["label"] == "y"
    assert abi.unpack_header(a)["policy_hash"] == semantic_hash(c)


def test_diff(demo_text, inv):
    old = canonical(Policy.model_validate(yaml.safe_load(demo_text)), inv)
    assert diff(old, old)["no_op"] is True

    def change(d):
        d["rules"] = d["rules"][:2]
        d["rules"][0]["destination_ports"] = [443, 8443]
        d["rules"].append({"id": "new-rule", "ingress_zone": "dmz", "destination": "192.0.2.10/32",
                           "protocol": "udp", "destination_ports": [53], "action": "accept",
                           "owner": "x", "reason": "y"})
    new = canonical(mod(demo_text, change), inv)
    d = diff(old, new)
    assert not d["no_op"] and d["resets_flows"]
    assert "new-rule" in d["rules"]["added"]
    assert "wan-published-web" in d["rules"]["removed"]
    assert "lan-dmz-web:1" in d["rules"]["added"] and "lan-dmz-web" in d["rules"]["removed"]
    assert diff(None, new)["rules"]["added"]
