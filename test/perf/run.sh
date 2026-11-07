#!/bin/bash
# Forwarding performance: baseline routing vs. nftables vs. the original myfw
# vs. myfw v2 (with and without its control plane running), on the lab topology (lan-client -> wan-host through SNAT).
#
#   sudo ORIG_SRC=/path/to/original/tree test/perf/run.sh
#
# ORIG_SRC is a checkout of the original myfw (e.g. `git archive main | tar -x
# -C /tmp/orig`); without it that configuration is skipped.
# Each configuration: REPS x iperf3 single-stream TCP for DUR seconds, and
# REPS x connection-setup rate for CDUR seconds, after one unrecorded warm-up.
# Results: median and range.
# Run on the lab VM only: it unloads the module and replaces the ruleset, then
# restores the last confirmed policy and the demo policy.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REPS=${REPS:-5}; DUR=${DUR:-8}; CDUR=${CDUR:-5}
OUT=${OUT:-/var/lib/myfw-tests/perf}
ORIG_SRC=${ORIG_SRC:-}
KDIR=/lib/modules/$(uname -r)/build
mkdir -p "$OUT"
W=$(mktemp -d)

restore() {   # always leave the managed stack running, even after a failure
	set +e
	ip netns exec wan pkill -f "iperf3 -s"; ip netns exec wan pkill -f "connrate serve"
	nft flush ruleset
	if [[ -n "${ORIG_SRC:-}" ]] && lsmod | grep -q '^myfw ' && [[ ! -e /sys/module/myfw/parameters/stage_timeout ]]; then
		rmmod myfw          # the original module (it has no stage_timeout parameter)
	fi
	modprobe myfw initial_action=0
	systemctl restart myfw-boot
	systemctl start myfw-agent myfw-guard myfw-collector myfw-verify.timer
	rm -rf "$W"
}
trap restore EXIT

gcc -O2 -Wall -o "$W/connrate" "$ROOT/test/perf/connrate.c"
{
	echo "date: $(date -Is)"
	echo "kernel: $(uname -r)"
	echo "cpu: $(lscpu | sed -n 's/^Model name: *//p') x $(nproc)"
	echo "hypervisor: $(systemd-detect-virt 2>/dev/null || echo unknown)"
	echo "memory: $(free -m | awk '/Mem:/ {print $2}') MiB"
	echo "reps: $REPS, iperf3 ${DUR}s single stream, connrate ${CDUR}s"
	echo "veth offloads: $(ethtool -k veth-wan 2>/dev/null | grep -E '^(tcp-segmentation|generic-receive)-offload' | tr '\n' ' ')"
} > "$OUT/env.txt"
lan() { ip netns exec lan "$@"; }
wan() { ip netns exec wan "$@"; }

start_servers() {
	wan pkill -f "iperf3 -s" 2>/dev/null || true; wan pkill -f "connrate serve" 2>/dev/null || true
	wan iperf3 -s -D -p 5201
	wan "$W/connrate" serve 9000 & sleep 1
}

measure() {   # $1 = configuration name
	local name=$1 i
	echo ">>> $name"
	# warm-up (not recorded): caches, ARP, the first SNAT allocations
	lan iperf3 -c 192.0.2.10 -p 5201 -t 3 > /dev/null 2>&1 || true
	lan "$W/connrate" run 192.0.2.10 9000 2 > /dev/null || true
	# which source address does the server see? (SNAT on, except for the baseline)
	echo "$name: $(lan curl -s -m 10 --cacert /var/lib/myfw-lab/pki/ca.pem https://192.0.2.10/)" >> "$OUT/server-saw.txt"
	sleep 11
	for i in $(seq "$REPS"); do
		lan iperf3 -c 192.0.2.10 -p 5201 -t "$DUR" -J > "$OUT/$name-iperf-$i.json" || echo '{}' > "$OUT/$name-iperf-$i.json"
		sleep 1
		lan "$W/connrate" run 192.0.2.10 9000 "$CDUR" > "$OUT/$name-conn-$i.json"
		sleep 11          # let closed flows expire (myfw tcp_close_timeout = 10 s)
	done
}

apply_confirmed() {   # apply through fwctl and confirm (a no-op needs no confirmation)
	fwctl apply "$1" --no-verify --confirm-timeout 600 --json > "$W/apply.json"
	python3 - "$W/apply.json" <<'PY' | while read -r id; do fwctl confirm "$id" > /dev/null; done
import json, sys
r = json.load(open(sys.argv[1]))
if not r.get("no_op"):
    print(r["change_id"])
PY
}

stop_myfw() {
	systemctl stop myfw-verify.timer myfw-collector myfw-guard myfw-agent || true
	rmmod myfw 2>/dev/null || true
	sysctl -qw net.ipv4.ip_forward=1
}

start_servers

# ---- myfw v2 (the deployed stack, through fwctl) -------------------------
apply_confirmed "$ROOT/test/perf/policy.yaml"
measure v2
uapp --json counters > "$OUT/v2-counters.json"

# ---- myfw v2 data plane only: same module and policy, control plane stopped -
# (separates the cost of the kernel path from agent/guard/collector/probe
#  activity sharing the VM's two vCPUs)
systemctl stop myfw-verify.timer myfw-collector myfw-guard myfw-agent
measure v2-dataplane
systemctl start myfw-agent myfw-guard myfw-collector myfw-verify.timer

# ---- baseline: plain routing, no filtering, no NAT ------------------------
stop_myfw
nft flush ruleset
measure baseline

# ---- nftables equivalent ---------------------------------------------------
nft -f "$ROOT/test/perf/nftables.nft"
measure nftables
nft list ruleset > "$OUT/nftables-ruleset.txt"
nft flush ruleset

# ---- the original myfw ------------------------------------------------------
if [[ -n "$ORIG_SRC" ]]; then
	make -s -C "$ORIG_SRC/kernel_mod" KDIR="$KDIR" >/dev/null 2>&1
	make -s -C "$ORIG_SRC/cmd" >/dev/null
	U=$ORIG_SRC/cmd/uapp
	insmod "$ORIG_SRC/kernel_mod/myfw.ko"
	$U rule add --name ssh --dport 22 --proto tcp --action accept
	$U rule add --name lan-dmz --src 10.10.10.0/24 --dst 10.10.20.10 --dport 443 --proto tcp --action accept
	for p in 443 5201 9000; do
		$U rule add --name lan-wan-$p --src 10.10.10.0/24 --dst 192.0.2.10 --dport $p --proto tcp --action accept
	done
	$U rule add --name wan-pub --src 192.0.2.0/24 --dst 192.0.2.1 --dport 8443 --proto tcp --action accept
	$U nat add --type snat --src 10.10.10.0/24 --to 192.0.2.1 --ports 20000-59999
	$U nat add --type dnat --dst 192.0.2.1 --dport 8443 --proto tcp --to 10.10.20.10:443
	$U rule default drop
	measure original
	$U rule default accept
	rmmod myfw
fi

# ---- restore the managed stack, then the demo policy ---------------------------
trap - EXIT
restore
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
apply_confirmed "$ROOT/policies/demo.yaml"

python3 "$ROOT/test/perf/report.py" "$OUT"
