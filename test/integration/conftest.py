"""Full-VM integration tests. Run as root on the lab VM after deploy/ansible:

    sudo /opt/myfw/venv/bin/python -m pytest -v test/integration

They drive the real system (module, uapp, agent, guard, collector, lab
namespaces) and leave the demo policy confirmed when they finish.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time

import pytest
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEMO = os.path.join(ROOT, "policies", "demo.yaml")
FWCTL = shutil.which("fwctl") or "/usr/local/bin/fwctl"
UAPP = "/usr/local/sbin/uapp"


def sh(cmd, check=False, timeout=300, **kw):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True,
                       timeout=timeout, **kw)
    if check and p.returncode:
        raise AssertionError(f"{cmd}: rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def ns(name, cmd, **kw):
    return sh(["ip", "netns", "exec", name, "sh", "-c", cmd], **kw)


def fwctl(*args, timeout=300):
    p = sh([FWCTL, *args, "--json"], timeout=timeout)
    try:
        return p.returncode, json.loads(p.stdout)
    except json.JSONDecodeError:
        return p.returncode, {"raw": p.stdout, "err": p.stderr}


def uapp_json(*args):
    return json.loads(sh([UAPP, "--json", *args], check=True).stdout)


def status():
    return uapp_json("status")


def counters():
    return uapp_json("counters")


def drops():
    return counters()["drop_reason"]


def delta(before, after):
    return {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}


def policy_variant(mutate) -> str:
    d = yaml.safe_load(open(DEMO))
    mutate(d)
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, dir="/tmp")
    yaml.safe_dump(d, f, sort_keys=False)
    f.close()
    return f.name


def pending_id():
    rc, s = fwctl("status")
    return (s.get("pending") or {}).get("id")


def ensure_demo_confirmed():
    """Put the system back to: demo policy active and confirmed, nothing pending."""
    pid = pending_id()
    if pid:
        fwctl("rollback", "--reason", "test cleanup")
    rc, r = fwctl("apply", DEMO, "--confirm-timeout", "120")
    if r.get("change_id") and not r.get("no_op") and r.get("state") == "pending":
        rc2, c = fwctl("confirm", r["change_id"])
        assert rc2 == 0, c
    st = status()
    assert st["managed"] and st["stage_state"] == 0
    return st


def apply_confirmed(path):
    rc, r = fwctl("apply", path, "--confirm-timeout", "120")
    assert rc == 0, r
    if not r.get("no_op"):
        rc, c = fwctl("confirm", r["change_id"])
        assert rc == 0, c
    return r


@pytest.fixture(scope="session", autouse=True)
def lab():
    assert os.geteuid() == 0, "integration tests run as root on the lab VM"
    sh("systemctl start myfw-lab myfw-boot myfw-agent myfw-guard myfw-collector", check=True)
    # NAT leak detector: the outside host counts packets from inside addresses
    ns("wan", "nft delete table inet leak 2>/dev/null; nft -f - <<'EOF'\n"
       "table inet leak {\n"
       "  counter inside { }\n"
       "  chain in {\n"
       "    type filter hook prerouting priority -300;\n"
       "    ip saddr 10.10.0.0/16 counter name \"inside\"\n"
       "  }\n"
       "}\n"
       "EOF", check=True)
    ensure_demo_confirmed()
    yield
    ensure_demo_confirmed()


def leak_count() -> int:
    out = ns("wan", "nft -j list counter inet leak inside", check=True).stdout
    for item in json.loads(out)["nftables"]:
        if "counter" in item:
            return item["counter"]["packets"]
    return -1


@pytest.fixture
def demo_confirmed():
    yield ensure_demo_confirmed()
    ensure_demo_confirmed()


def https_get(namespace, url, timeout=5, extra=""):
    return ns(namespace, f"curl -s --cacert /var/lib/myfw-lab/pki/ca.pem -m {timeout} {extra} {url}")
