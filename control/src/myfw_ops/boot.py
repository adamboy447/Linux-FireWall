"""myfw-boot: bring the firewall up safely at boot.

Order (myfw-boot.service, Before=myfw-agent/guard, After=myfw-lab):
  1. forwarding OFF (IPv4 and IPv6);
  2. load the module with initial_action=0 (default DROP until a policy is in);
  3. pending changes from before the reboot are marked rolled_back; the last
     CONFIRMED policy is committed (or the baseline if nothing was confirmed);
  4. only if that succeeded: IPv4 forwarding ON.
If any step fails, forwarding stays off and the unit fails visibly; the
baseline (management access) is still attempted so the box can be reached.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

from . import backend, transactions as tx
from .compiler import to_blob
from .state import Store


def sysctl(key: str, value: str) -> None:
    with open("/proc/sys/" + key.replace(".", "/"), "w") as f:
        f.write(value)


def module_loaded() -> bool:
    return os.path.exists("/sys/module/myfw")


def main() -> int:
    sysctl("net.ipv4.ip_forward", "0")
    try:
        sysctl("net.ipv6.conf.all.forwarding", "0")
    except OSError:
        pass
    if not module_loaded():
        opts = os.environ.get("MYFW_MODULE_OPTS", "").split()
        p = subprocess.run(["modprobe", "myfw", "initial_action=0", *opts], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"modprobe myfw failed: {p.stderr.strip()}", file=sys.stderr)
            return 1
    inv = tx.load_inventory()
    store = Store()
    try:
        res = tx.boot_restore(store, inv)
    except Exception as e:
        print(f"restoring the confirmed policy failed: {e}; trying the baseline", file=sys.stderr)
        try:
            st = backend.status()
            backend.apply_blob(to_blob(tx.baseline_only(inv), "boot-baseline"), st["generation"])
        except Exception as e2:
            print(f"baseline failed too: {e2}", file=sys.stderr)
        return 1
    sysctl("net.ipv4.ip_forward", "1")
    print(json.dumps({**res, "forwarding": True}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
