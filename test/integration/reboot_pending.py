"""Reboot while a change is pending.

A pending (unconfirmed) change must not survive a reboot: at boot, myfw-boot
restores the last *confirmed* policy before forwarding is enabled and marks
the pending change as rolled back.

    sudo python3 test/integration/reboot_pending.py prepare
    sudo reboot
    sudo python3 test/integration/reboot_pending.py check
"""
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
STATE = "/var/lib/myfw-tests/reboot-pending.json"


def fwctl(*args):
    p = subprocess.run(["fwctl", *args, "--json"], capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


def prepare():
    rc, st = fwctl("status")
    assert rc == 0 and st["pending"] is None and st["in_sync"], st
    d = yaml.safe_load(open(os.path.join(ROOT, "policies", "demo.yaml")))
    d["rules"][0]["destination_ports"] = [443, 4443]
    path = "/var/lib/myfw-tests/reboot-variant.yaml"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    yaml.safe_dump(d, open(path, "w"), sort_keys=False)
    rc, r = fwctl("apply", path, "--confirm-timeout", "3600")
    assert rc == 0 and r["state"] == "pending", r
    json.dump({"confirmed_hash": st["last_confirmed_hash"], "change_id": r["change_id"],
               "pending_hash": r["policy_hash"], "boot_id": st["boot_id"]}, open(STATE, "w"))
    print(f"pending change {r['change_id']} (deadline in 1 h) - now reboot")


def check():
    s = json.load(open(STATE))
    rc, st = fwctl("status")
    assert st["boot_id"] != s["boot_id"], "not rebooted"
    k = st["kernel"]
    assert k["policy_hash"] == s["confirmed_hash"], "booted into the unconfirmed policy"
    assert k["label"] == "boot-restore" and st["pending"] is None and st["in_sync"]
    _, h = fwctl("history", "--limit", "10")
    ch = next(c for c in h["changes"] if c["id"] == s["change_id"])
    assert ch["state"] == "rolled_back", ch
    log = subprocess.run(["journalctl", "-b", "-u", "myfw-boot", "-o", "cat"],
                         capture_output=True, text=True).stdout
    print(log.strip().splitlines()[-1])
    print(f"PASS: change {s['change_id']} was rolled back at boot; "
          f"kernel runs the last confirmed policy {k['policy_hash'][:16]} (generation {k['generation']})")


if __name__ == "__main__":
    {"prepare": prepare, "check": check}[sys.argv[1]]()
