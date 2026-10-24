#!/bin/sh
# End-to-end test of myfw. Runs as root inside the test VM (see test/vm/run.sh),
# but works on any disposable Linux box that has the module, uapp and fwtest
# in $FW. It builds this topology with network namespaces:
#
#   [client ns] 10.0.1.2 --veth-- 10.0.1.1 [router = firewall host] 10.0.2.1 --veth-- 10.0.2.2 [server ns]
#
# The firewall runs in the router (the initial namespace), so client<->server
# traffic is forwarded through it, and traffic from the router itself goes
# through its LOCAL_OUT hook.

FW=${FW:-/fw}
# busybox sh prefers its own (netns-less) ip applet over $PATH
[ -x /usr/local/sbin/ip ] && ip() { /usr/local/sbin/ip "$@"; }
UAPP="$FW/uapp"
C="ip netns exec client"
S="ip netns exec server"
PASS=0
FAIL=0
YEAR=$(date +%Y)

section() { echo; echo "======== $* ========"; }
pass()    { PASS=$((PASS + 1)); echo "  [PASS] $*"; }
fail()    { FAIL=$((FAIL + 1)); echo "  [FAIL] $*"; }
show()    { echo "  \$ $*"; "$@" 2>&1 | sed 's/^/      /'; }

# expect_ok "description" command...   (the command must exit 0)
expect_ok() {
	d=$1; shift
	if out=$("$@" 2>&1); then pass "$d"; else fail "$d"; fi
	echo "$out" | sed 's/^/        /'
}
expect_fail() {
	d=$1; shift
	if out=$("$@" 2>&1); then fail "$d"; else pass "$d"; fi
	echo "$out" | sed 's/^/        /'
}
# expect_match "description" "regex" command...   (output must match)
expect_match() {
	d=$1; re=$2; shift 2
	out=$("$@" 2>&1)
	if echo "$out" | grep -Eq -- "$re"; then pass "$d"; else fail "$d (wanted /$re/)"; fi
	echo "$out" | sed 's/^/        /'
}
expect_nomatch() {
	d=$1; re=$2; shift 2
	out=$("$@" 2>&1)
	if echo "$out" | grep -Eq -- "$re"; then fail "$d (unwanted /$re/)"; else pass "$d"; fi
	echo "$out" | sed 's/^/        /'
}

tcp()  { $C $FW/fwtest send tcp "$@"; }        # from the client
udp()  { $C $FW/fwtest send udp "$@"; }
ping1() { $C ping -c 1 -W 1 "$1" >/dev/null 2>&1; }
last_peer() { tail -n 1 "/tmp/$1.log" | sed 's/^PEER //'; }

# ----------------------------------------------------------------------
section "0. topology"
ip netns add client
ip netns add server
ip link add c0 type veth peer name r1
ip link add s0 type veth peer name r2
ip link set c0 netns client
ip link set s0 netns server
ip addr add 10.0.1.1/24 dev r1 && ip link set r1 up
ip addr add 10.0.2.1/24 dev r2 && ip link set r2 up
ip link set lo up
$C ip addr add 10.0.1.2/24 dev c0; $C ip link set c0 up; $C ip link set lo up
$C ip route add default via 10.0.1.1
$S ip addr add 10.0.2.2/24 dev s0; $S ip link set s0 up; $S ip link set lo up
$S ip route add 10.0.1.0/24 via 10.0.2.1    # removed later to prove SNAT
sysctl -qw net.ipv4.ip_forward=1
show uname -r
show ip -br addr

# echo servers (each logs the peer address it saw)
for p in 80 8080 9000; do $S $FW/fwtest listen tcp $p 3600 > /tmp/s_tcp$p.log 2>&1 & done
for p in 9000 9001; do $S $FW/fwtest listen udp $p 3600 > /tmp/s_udp$p.log 2>&1 & done
$C $FW/fwtest listen tcp 2222 3600 > /tmp/c_tcp2222.log 2>&1 &
$C $FW/fwtest listen udp 9500 3600 > /tmp/c_udp9500.log 2>&1 &
sleep 1

expect_ok "baseline without firewall: client -> server tcp/80" tcp 10.0.2.2 80

# ----------------------------------------------------------------------
section "1. load the module"
DMESG_START=$(dmesg | wc -l)
expect_ok "insmod myfw.ko (short udp/icmp timeouts for the test)" \
	insmod $FW/myfw.ko udp_timeout=5 icmp_timeout=5
expect_match "uapp status works" "default action +ACCEPT" $UAPP status
show sh -c "dmesg | grep myfw"

# ----------------------------------------------------------------------
section "2. only root may control the firewall (was: any user)"
NOBODY="/usr/bin/setpriv --reuid=65534 --regid=65534 --clear-groups"
expect_match "status as nobody is refused" "permission denied" $NOBODY $UAPP status
expect_fail  "rule add as nobody is refused" \
	$NOBODY $UAPP rule add --name evil --action drop
expect_match "...and no rule was added" "filter rules +0" $UAPP status

# ----------------------------------------------------------------------
section "3. default ACCEPT: everything flows"
expect_ok "client -> server tcp/80"  tcp 10.0.2.2 80
expect_ok "client -> server udp/9000" udp 10.0.2.2 9000
expect_ok "client -> server ping"    ping1 10.0.2.2

# ----------------------------------------------------------------------
section "4. blacklist rule, protocol-aware, with logging"
expect_ok "add drop rule for udp/9000" \
	$UAPP rule add --name no-udp9000 --dst 10.0.2.2 --dport 9000 --proto udp --action drop --log
expect_fail "udp/9000 is now blocked"        udp 10.0.2.2 9000
expect_ok   "tcp/9000 still works (proto)"   tcp 10.0.2.2 9000
expect_ok   "udp/9001 still works (port)"    udp 10.0.2.2 9001
expect_match "log has the DROP with today's date (was: 1970)" \
	"\\[$YEAR-.* DROP +udp .*10\\.0\\.2\\.2:9000 .*rule=no-udp9000" $UAPP log
expect_match "rule hit counter counts the packet" "no-udp9000 .* [1-9][0-9]* +[0-9]+$" $UAPP rule ls

# ----------------------------------------------------------------------
section "5. rule order: first match wins, --head / --after"
expect_ok "insert an accept rule for the client at the head" \
	$UAPP rule add --name allow-cli --src 10.0.1.2 --proto udp --dport 9000 --action accept --head
expect_ok "udp/9000 works again (accept matched first)" udp 10.0.2.2 9000
expect_fail "--after a rule that does not exist is refused" \
	$UAPP rule add --name x --action drop --after nosuchrule
expect_ok "insert after allow-cli" \
	$UAPP rule add --name mid --dport 1234 --proto tcp --action drop --after allow-cli
expect_match "order is allow-cli, mid, no-udp9000" \
	"^0 +allow-cli.*" $UAPP rule ls
expect_match "...mid is second" "^1 +mid " $UAPP rule ls
expect_ok "delete allow-cli" $UAPP rule del allow-cli
expect_fail "deleting it twice fails" $UAPP rule del allow-cli

# ----------------------------------------------------------------------
section "6. whitelist (default DROP) and real stateful replies"
expect_ok "flush rules" $UAPP rule flush
expect_ok "allow client net -> server tcp/80 only" \
	$UAPP rule add --name web --src 10.0.1.0/24 --dst 10.0.2.2 --dport 80 --proto tcp --action accept --log
expect_ok "default drop (logged)" $UAPP rule default drop --log
expect_ok   "client -> server tcp/80 works: replies pass with NO reverse rule" tcp 10.0.2.2 80
expect_ok   "large transfer (2 MB) over the tracked flow" tcp 10.0.2.2 80 2000000
expect_fail "client -> server tcp/8080 dropped" tcp 10.0.2.2 8080
expect_fail "client -> server ping dropped" ping1 10.0.2.2
expect_fail "server -> client tcp/2222 (inbound) dropped" $S $FW/fwtest send tcp 10.0.1.2 2222
expect_match "conn table shows the flow with reply packets" \
	"tcp +10\\.0\\.1\\.2:[0-9]+ -> 10\\.0\\.2\\.2:80 .* [0-9]+/[1-9][0-9]*" $UAPP conn
expect_match "default-policy drops are logged" "DROP .*\\(default policy\\)" $UAPP log 5
section "6b. traffic from the firewall host itself (LOCAL_OUT hook)"
expect_fail "router -> server tcp/80 dropped (rule only allows the client net)" \
	$FW/fwtest send tcp 10.0.2.2 80
expect_ok "allow the router's own address" \
	$UAPP rule add --name router --src 10.0.2.1 --action accept
expect_ok "router -> server tcp/80 works" $FW/fwtest send tcp 10.0.2.2 80

# ----------------------------------------------------------------------
section "7. connection timeout (udp_timeout=5)"
expect_ok "allow udp/9001" $UAPP rule add --name u9001 --dport 9001 --proto udp --action accept
expect_ok "client -> server udp/9001" udp 10.0.2.2 9001
expect_match "the udp flow is tracked" "udp +10\\.0\\.1\\.2.* -> 10\\.0\\.2\\.2:9001" $UAPP conn
sleep 7
expect_nomatch "after 7s idle it has expired" "10\\.0\\.2\\.2:9001" $UAPP conn

# ----------------------------------------------------------------------
section "8. a new DROP rule cuts flows that are already established"
expect_ok "client -> server udp/9001 (flow established)" udp 10.0.2.2 9001
expect_ok "add drop rule for udp/9001 at the head" \
	$UAPP rule add --name cut9001 --dport 9001 --proto udp --action drop --head
expect_nomatch "the existing flow was removed" "10\\.0\\.2\\.2:9001" $UAPP conn
expect_fail "udp/9001 now blocked" udp 10.0.2.2 9001

# ----------------------------------------------------------------------
section "9. save / load"
expect_ok "save ruleset" $UAPP save /tmp/rules.fw
show cat /tmp/rules.fw
$UAPP save | grep -v '^#' > /tmp/before.txt
expect_ok "flush" $UAPP rule flush
expect_match "nothing left" "no rules" $UAPP rule ls
expect_ok "load it back" $UAPP load /tmp/rules.fw
$UAPP save | grep -v '^#' > /tmp/after.txt
expect_ok "restored ruleset is identical" cmp /tmp/before.txt /tmp/after.txt
show $UAPP rule ls

# ----------------------------------------------------------------------
section "10. interactive mode (kept from the original)"
expect_ok "rule add with answers on stdin" sh -c \
	"printf '\nicmp-ok\n10.0.1.0/24\n\n10.0.2.2\n\nicmp\naccept\nno\n' | $UAPP rule add"
expect_ok "ping now allowed by the interactive rule" ping1 10.0.2.2

# ----------------------------------------------------------------------
section "11. input validation"
expect_fail "bad address 10.0.1.300"   $UAPP rule add --name b --src 10.0.1.300 --action drop
expect_fail "bad port 70000"           $UAPP rule add --name b --dport 70000 --action drop
expect_fail "reversed port range"      $UAPP rule add --name b --dport 90-80 --action drop
expect_fail "bad protocol"             $UAPP rule add --name b --proto xyz --action drop
expect_fail "name too long"            $UAPP rule add --name abcdefghijklmnopq --action drop
expect_fail "missing --action"         $UAPP rule add --name b
expect_fail "delete NAT rule 99"       $UAPP nat del 99

# ----------------------------------------------------------------------
section "12. SNAT (masquerade the client network)"
expect_ok "back to default accept, clear rules and logs" sh -c \
	"$UAPP rule flush && $UAPP rule default accept && $UAPP log clear"
$S ip route del 10.0.1.0/24 via 10.0.2.1
echo "  (server no longer has a route back to 10.0.1.0/24)"
expect_fail "without NAT the server cannot answer the client" tcp 10.0.2.2 80
expect_ok "add SNAT 10.0.1.0/24 -> 10.0.2.1 ports 20000-20999" \
	$UAPP nat add --type snat --src 10.0.1.0/24 --to 10.0.2.1 --ports 20000-20999
expect_ok "client -> server tcp/80 works through SNAT" tcp 10.0.2.2 80
expect_match "server saw the NAT address and a port from the pool" \
	"^10\\.0\\.2\\.1:20[0-9]{3}$" last_peer s_tcp80
expect_ok "client -> server udp/9000 through SNAT" udp 10.0.2.2 9000
expect_match "server saw 10.0.2.1 for udp too" "^10\\.0\\.2\\.1:" last_peer s_udp9000
expect_ok "ping through SNAT" ping1 10.0.2.2
expect_ok "8 MB echo through SNAT, every byte verified (checksums, GSO)" \
	tcp 10.0.2.2 80 8000000
expect_match "conn shows the SNAT reply tuple" \
	"reply: 10\\.0\\.2\\.2:80 -> 10\\.0\\.2\\.1:20[0-9]{3}" $UAPP conn

section "12b. stress: parallel NAT traffic while rules change underneath"
pids=""
for i in 1 2 3 4; do
	(tcp 10.0.2.2 80 4000000 > /tmp/stress$i.out 2>&1; echo $? > /tmp/stress$i.rc) &
	pids="$pids $!"
done
for i in 1 2 3 4; do udp 10.0.2.2 9000 >/dev/null 2>&1 & pids="$pids $!"; done
n=0
while [ $n -lt 150 ]; do
	$UAPP rule add --name churn$n --dport 1234 --proto tcp --action drop >/dev/null
	$UAPP rule del churn$n >/dev/null
	$UAPP conn >/dev/null
	$UAPP log 50 >/dev/null
	$UAPP status >/dev/null
	n=$((n + 1))
done
wait $pids     # not a bare wait: the echo servers are children too
ok=0
for i in 1 2 3 4; do [ "$(cat /tmp/stress$i.rc)" = 0 ] && ok=$((ok + 1)); cat /tmp/stress$i.out | sed 's/^/        /'; done
if [ $ok -eq 4 ]; then pass "4 x 4 MB transfers intact during 150 rule add/del + 450 dumps"; else fail "only $ok/4 transfers intact"; fi
expect_match "rule chain is back to empty" "filter rules +0" $UAPP status

# ----------------------------------------------------------------------
section "13. DNAT (port forwarding into the client network)"
expect_ok "forward 10.0.2.1:8080/tcp -> 10.0.1.2:2222" \
	$UAPP nat add --type dnat --dst 10.0.2.1 --dport 8080 --proto tcp --to 10.0.1.2:2222
expect_ok "forward 10.0.2.1:5353/udp -> 10.0.1.2:9500" \
	$UAPP nat add --type dnat --dst 10.0.2.1 --dport 5353 --proto udp --to 10.0.1.2:9500
expect_ok "server -> 10.0.2.1:8080 reaches the client's tcp/2222" \
	$S $FW/fwtest send tcp 10.0.2.1 8080
expect_match "client saw the real external address" "^10\\.0\\.2\\.2:" last_peer c_tcp2222
expect_ok "8 MB echo through DNAT, every byte verified" \
	$S $FW/fwtest send tcp 10.0.2.1 8080 8000000
expect_ok "server -> 10.0.2.1:5353/udp reaches the client's udp/9500" \
	$S $FW/fwtest send udp 10.0.2.1 5353
expect_match "conn shows the DNAT reply tuple" \
	"reply: 10\\.0\\.1\\.2:2222 -> 10\\.0\\.2\\.2:" $UAPP conn
show $UAPP nat ls
expect_ok "delete NAT rule 0 (the SNAT)" $UAPP nat del 0
expect_fail "client -> server fails again without SNAT" tcp 10.0.2.2 80
expect_ok "flush NAT" $UAPP nat flush
expect_match "no NAT rules left" "no NAT rules" $UAPP nat ls
$S ip route add 10.0.1.0/24 via 10.0.2.1

# ----------------------------------------------------------------------
section "14. status"
show $UAPP status

# ----------------------------------------------------------------------
section "15. unload / reload"
expect_ok "rmmod myfw" rmmod myfw
expect_match "uapp explains the module is gone" "not loaded" $UAPP status
expect_ok "traffic still flows without the module" tcp 10.0.2.2 80
expect_ok "insmod again" insmod $FW/myfw.ko
expect_match "starts clean" "filter rules +0" $UAPP status
expect_ok "rmmod again" rmmod myfw

# ----------------------------------------------------------------------
section "16. kernel log health"
show sh -c "dmesg | grep myfw"
expect_nomatch "no BUG / WARNING / Oops / lockdep splat in dmesg" \
	"BUG|WARNING|Oops|sleeping function|corruption|circular locking|general protection" \
	sh -c "dmesg | tail -n +$((DMESG_START + 1))"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
