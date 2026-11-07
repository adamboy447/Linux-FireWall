"""Access matrix, zones/anti-spoofing, NAT evidence, packet edge cases."""
import json
import time

from conftest import (DEMO, counters, delta, drops, fwctl, https_get, leak_count, ns, sh, status,
                      uapp_json)


def test_access_matrix(demo_confirmed):
    rc, r = fwctl("verify")
    failed = [x for x in r["results"] if not x["pass"]]
    assert rc == 0 and not failed, failed
    by = {x["name"]: x for x in r["results"]}
    # NAT seen from the servers' side
    snat_peer = by["lan-to-wan-https-snat"]["server_saw"]
    assert snat_peer.startswith("192.0.2.1:") and 20000 <= int(snat_peer.split(":")[1]) <= 20999
    assert by["wan-published-https"]["server_saw"].startswith("192.0.2.10:")   # DNAT keeps the source
    assert by["lan-to-dmz-https"]["server_saw"].startswith("10.10.10.10:")


def test_dnat_large_transfer_content(demo_confirmed):
    # 20 MB through DNAT, compared with the known pattern
    p = https_get("wan", "https://192.0.2.1:8443/bytes?n=20000000", timeout=120,
                  extra="-o /tmp/dnat.bin -w '%{size_download}'")
    assert p.stdout.strip() == "20000000"
    data = open("/tmp/dnat.bin", "rb").read()
    pattern = bytes(range(256)) * (len(data) // 256 + 1)
    assert data == pattern[: len(data)]


def test_spoofed_sources_are_dropped_before_the_flow_lookup(demo_confirmed):
    b = drops()
    # wan pretends to be a LAN host towards the DMZ service
    ns("wan", "ip addr add 10.10.10.10/32 dev eth0", check=True)
    try:
        r = ns("wan", "curl -s -m 3 --interface 10.10.10.10 http://10.10.20.10:443/")
        assert r.returncode != 0
        # wan pretends to be the admin laptop towards the gateway's SSH
        ns("wan", "ip addr add 10.0.2.2/32 dev eth0", check=True)
        ns("wan", "ip route add 10.0.2.15/32 via 192.0.2.1 src 10.0.2.2", check=True)
        r2 = ns("wan", "timeout 4 bash -c 'echo > /dev/tcp/10.0.2.15/22'")
        assert r2.returncode != 0
    finally:
        ns("wan", "ip route del 10.0.2.15/32 2>/dev/null; ip addr del 10.0.2.2/32 dev eth0 2>/dev/null; "
           "ip addr del 10.10.10.10/32 dev eth0")
    d = delta(b, drops())
    assert d.get("spoofed_source", 0) >= 2, d
    ev = uapp_json("events", "--since", str(max(0, status()["event_next_seq"] - 200)))["events"]
    assert any(e["reason"] == "spoofed_source" and e["src"] == "10.10.10.10" for e in ev)


def test_nothing_leaves_untranslated(demo_confirmed):
    assert leak_count() == 0


def test_fragments_unsupported_protocols_and_truncated_headers(demo_confirmed):
    b = drops()
    ns("lan", "ping -c 1 -W 1 -s 3000 10.10.20.10")                      # fragmented
    ns("lan", "ping -c 1 -W 1 10.10.20.10")                              # echo: allowed type, default drop
    # ICMP timestamp request (type 13), GRE (proto 47) and a truncated TCP header
    ns("lan", "python3 - <<'EOF'\n"
       "import socket\n"
       "s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n"
       "s.sendto(bytes([13, 0, 0xf2, 0xff, 0, 0, 0, 0]) + bytes(12), ('10.10.20.10', 0))\n"
       "g = socket.socket(socket.AF_INET, socket.SOCK_RAW, 47)\n"
       "g.sendto(bytes(8), ('10.10.20.10', 0))\n"
       "t = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)\n"
       "t.sendto(bytes(8), ('10.10.20.10', 0))   # 8 bytes: shorter than a TCP header\n"
       "EOF", check=True)
    time.sleep(0.5)
    d = delta(b, drops())
    assert d.get("unsupported_fragment", 0) >= 1, d
    assert d.get("unsupported_protocol", 0) >= 2, d
    assert d.get("parse_error", 0) >= 1, d
    assert d.get("default_policy", 0) >= 1, d


def test_ipv6_on_a_managed_interface_is_dropped(demo_confirmed):
    b = drops()
    sh("sysctl -qw net.ipv6.conf.veth-lan.disable_ipv6=0")
    ns("lan", "sysctl -qw net.ipv6.conf.all.disable_ipv6=0; sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0")
    try:
        time.sleep(3)   # link-local + DAD
        ll = sh("ip -6 -j addr show dev veth-lan").stdout
        addr = next((a["local"] for i in json.loads(ll) for a in i.get("addr_info", [])
                     if a["local"].startswith("fe80")), None)
        assert addr, "no link-local address"
        ns("lan", f"ping -6 -c 2 -W 1 {addr}%eth0")
    finally:
        sh("sysctl -qw net.ipv6.conf.veth-lan.disable_ipv6=1")
        ns("lan", "sysctl -qw net.ipv6.conf.all.disable_ipv6=1")
    assert delta(b, drops()).get("ipv6", 0) >= 1


def test_management_is_isolated_from_data_zones(demo_confirmed):
    for src, dst in (("lan", "10.0.2.15"), ("dmz", "10.0.2.2"), ("wan", "10.10.10.1")):
        r = ns(src, f"timeout 3 bash -c 'echo > /dev/tcp/{dst}/22'")
        assert r.returncode != 0, f"{src} reached {dst}:22"
    st = counters()
    assert st["drop_reason"]["rule"] > 0


def test_counters_have_one_final_verdict_per_packet(demo_confirmed):
    c0 = counters()
    https_get("lan", "https://10.10.20.10/")
    c1 = counters()
    acc = c1["accept_pkts"] - c0["accept_pkts"]
    assert acc >= 10                                 # handshake + TLS + HTTP both ways
    assert c1["new_flow_accept"] - c0["new_flow_accept"] <= 3   # decided once per flow
    assert c1["stateful_hits"] - c0["stateful_hits"] >= acc - 6


def test_no_op_reapply_keeps_flows(demo_confirmed):
    g0 = status()["generation"]
    rc, r = fwctl("apply", DEMO)
    assert rc == 0 and r["no_op"] and status()["generation"] == g0
