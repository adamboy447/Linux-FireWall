"""Summarize test/perf/run.sh results: median and range per configuration."""
import glob
import json
import os
import statistics
import sys

out = sys.argv[1]
order = ["baseline", "nftables", "original", "v2-dataplane", "v2"]
rows = {}
for name in order:
    tput = []
    for f in sorted(glob.glob(os.path.join(out, f"{name}-iperf-*.json"))):
        try:
            tput.append(json.load(open(f))["end"]["sum_received"]["bits_per_second"] / 1e6)
        except (KeyError, ValueError):
            pass
    conn, failed = [], 0
    for f in sorted(glob.glob(os.path.join(out, f"{name}-conn-*.json"))):
        r = json.load(open(f))
        conn.append(r["conn_per_s"])
        failed += r["failed"]
    if tput or conn:
        rows[name] = {"throughput_mbps": tput, "conn_per_s": conn, "conn_failed": failed}

def fmt(v):
    if not v:
        return "n/a"
    return f"{statistics.median(v):.0f} ({min(v):.0f}–{max(v):.0f})"

base = rows.get("baseline")
print(f"| configuration | TCP throughput Mbit/s median (range) | vs baseline | new connections/s median (range) | vs baseline | failed connects |")
print("|---|---|---|---|---|---|")
for name, r in rows.items():
    rel_t = rel_c = "—"
    if base and name != "baseline" and r["throughput_mbps"] and base["throughput_mbps"]:
        rel_t = f"{statistics.median(r['throughput_mbps']) / statistics.median(base['throughput_mbps']) * 100:.0f}%"
    if base and name != "baseline" and r["conn_per_s"] and base["conn_per_s"]:
        rel_c = f"{statistics.median(r['conn_per_s']) / statistics.median(base['conn_per_s']) * 100:.0f}%"
    print(f"| {name} | {fmt(r['throughput_mbps'])} | {rel_t} | {fmt(r['conn_per_s'])} | {rel_c} | {r['conn_failed']} |")
json.dump(rows, open(os.path.join(out, "summary.json"), "w"), indent=1)

saw = os.path.join(out, "server-saw.txt")
if os.path.exists(saw):
    print("\nSource address seen by wan-host (proves SNAT where it applies):")
    for line in open(saw):
        print("  " + line.strip())
