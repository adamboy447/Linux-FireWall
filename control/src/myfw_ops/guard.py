"""myfw-guard: independent rollback guard.

A separate systemd service (not a timer inside the agent or the CLI): if the
operator's terminal disconnects, the CLI is killed, or the agent crashes
while a change is pending, the guard still rolls it back at its deadline,
using the same transaction library and the same state database.

Every second it writes a heartbeat (apply refuses to start a pending change
when the heartbeat is stale) and, because the unit sets WatchdogSec, it
really sends WATCHDOG=1 to systemd; a hung guard is restarted.
"""
from __future__ import annotations

import os
import socket
import sys
import time
import traceback

from . import transactions as tx
from .state import Store

INTERVAL = float(os.environ.get("MYFW_GUARD_INTERVAL", "1.0"))


def sd_notify(msg: str) -> None:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.connect(addr)
        s.sendall(msg.encode())


def heartbeat() -> None:
    os.makedirs(tx.RUN_DIR, exist_ok=True)
    tmp = tx.HEARTBEAT + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{os.getpid()} {time.time():.3f}\n")
    os.replace(tmp, tx.HEARTBEAT)


def main() -> int:
    store = Store()
    inv = tx.load_inventory()
    sd_notify("READY=1")
    print(f"myfw-guard running, interval {INTERVAL}s", flush=True)
    failures = 0
    while True:
        try:
            heartbeat()
            res = tx.guard_tick(store, inv)
            if res:
                print(f"rolled back: {res}", flush=True)
            failures = 0
            sd_notify("WATCHDOG=1")
        except Exception:
            failures += 1
            traceback.print_exc()
            # keep beating the watchdog only while failures are transient
            if failures < 5:
                sd_notify("WATCHDOG=1")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
