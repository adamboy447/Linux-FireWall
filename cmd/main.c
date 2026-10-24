/*
 * uapp - command line front end of the myfw firewall.
 * Run "uapp help" for usage.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <netinet/in.h>
#include "uapp.h"

#define MAX_ARGS 64

static int dispatch(int argc, char **argv);

static void usage(FILE *f)
{
	fprintf(f,
"usage: uapp <command> [arguments]\n"
"\n"
"  status                               module state, policy and counters\n"
"\n"
"  rule ls                              list filter rules with hit counters\n"
"  rule add                             add a rule interactively\n"
"  rule add --name N --action accept|drop [options]\n"
"        --src CIDR   --dst CIDR        e.g. 10.0.1.0/24, 1.2.3.4, any (default any)\n"
"        --sport R    --dport R         e.g. 80, 8000-8100, any (default any)\n"
"        --proto P                      tcp, udp, icmp, any (default any)\n"
"        --log                          log packets that hit this rule\n"
"        --head | --after NAME          position (default: end of the chain)\n"
"  rule del NAME                        delete every rule with this name\n"
"  rule flush                           delete all rules\n"
"  rule default accept|drop [--log]     policy when no rule matches\n"
"\n"
"  nat ls                               list NAT rules\n"
"  nat add --type snat --src CIDR --to IP [--ports R]\n"
"  nat add --type dnat --dst IP --dport PORT --proto tcp|udp --to IP[:PORT]\n"
"  nat del SEQ                          delete NAT rule number SEQ (see nat ls)\n"
"  nat flush\n"
"\n"
"  log [N]                              show the last N log entries (default all)\n"
"  log clear\n"
"  conn                                 show tracked connections\n"
"  conn flush\n"
"\n"
"  save [FILE]                          write the ruleset as uapp commands\n"
"  load FILE                            replace rules and NAT with a saved ruleset\n"
"\n"
"  ls rule|nat|log|conn                 short forms kept from the original tool\n");
}

/* ------------------------------------------------------------------ */

static int call(struct fw_request *req, struct fw_rsp_hdr **hdr, void **body)
{
	int err = fw_call(req, hdr, body);

	if (err) {
		if (err != -EPROTONOSUPPORT && err != -EPERM && *hdr && (*hdr)->type == FW_RSP_ERR)
			fprintf(stderr, "error: %s\n", (*hdr)->msg);
		else
			fprintf(stderr, "error: %s\n", fw_strerror(err));
		if (*hdr)
			free(*hdr);
		*hdr = NULL;
	}
	return err;
}

/* simple request with a text answer */
static int simple(struct fw_request *req)
{
	struct fw_rsp_hdr *hdr = NULL;
	void *body;

	if (call(req, &hdr, &body))
		return 1;
	printf("%s\n", hdr->msg);
	free(hdr);
	return 0;
}

static int fetch(uint32_t type, uint32_t arg, struct fw_rsp_hdr **hdr, void **body)
{
	struct fw_request req = { .type = type, .arg = arg };

	*hdr = NULL;
	return call(&req, hdr, body) ? -1 : 0;
}

static void truncated_note(const struct fw_rsp_hdr *h)
{
	if (h->count < h->total)
		printf("(showing %u of %u)\n", h->count, h->total);
}

/* ---------------------------- status ------------------------------ */

static int cmd_status(void)
{
	struct fw_rsp_hdr *h;
	struct fw_status *s;

	if (fetch(FW_REQ_STATUS, 0, &h, (void **)&s))
		return 1;
	printf("myfw module         loaded (protocol v%u)\n", s->version);
	printf("default action      %s%s\n", s->default_action == FW_ACT_ACCEPT ? "ACCEPT" : "DROP",
	       s->log_default ? " (logged)" : "");
	printf("filter rules        %u\n", s->n_rules);
	printf("NAT rules           %u\n", s->n_nats);
	printf("connections         %u / %u\n", s->n_conns, s->max_conns);
	printf("log entries         %u / %u\n", s->n_logs, s->max_logs);
	printf("timeouts            tcp %us, udp %us, icmp %us\n",
	       s->tcp_timeout, s->udp_timeout, s->icmp_timeout);
	printf("packets             %llu new accepted, %llu dropped, %llu stateful, %llu NATed\n",
	       (unsigned long long)s->pkts_accepted, (unsigned long long)s->pkts_dropped,
	       (unsigned long long)s->pkts_stateful, (unsigned long long)s->pkts_natted);
	free(h);
	return 0;
}

/* ----------------------------- rules ------------------------------ */

static int cmd_rule_ls(void)
{
	struct fw_rsp_hdr *h;
	struct fw_rule *r;
	char src[24], dst[24], sp[16], dp[16];
	uint32_t i;

	if (fetch(FW_REQ_GET_RULES, 0, &h, (void **)&r))
		return 1;
	if (h->count == 0) {
		printf("no rules\n");
	} else {
		printf("%-3s %-15s %-18s %-11s %-18s %-11s %-5s %-6s %-3s %10s %12s\n",
		       "#", "name", "source", "sport", "destination", "dport", "proto",
		       "action", "log", "packets", "bytes");
		for (i = 0; i < h->count; i++) {
			fmt_cidr(r[i].saddr, r[i].smask, src, sizeof(src));
			fmt_cidr(r[i].daddr, r[i].dmask, dst, sizeof(dst));
			if (r[i].proto == IPPROTO_ICMP) {
				strcpy(sp, "-");
				strcpy(dp, "-");
			} else {
				fmt_ports(r[i].sport_min, r[i].sport_max, sp, sizeof(sp));
				fmt_ports(r[i].dport_min, r[i].dport_max, dp, sizeof(dp));
			}
			printf("%-3u %-15s %-18s %-11s %-18s %-11s %-5s %-6s %-3s %10llu %12llu\n",
			       i, r[i].name, src, sp, dst, dp, proto_name(r[i].proto),
			       r[i].action == FW_ACT_ACCEPT ? "accept" : "drop",
			       r[i].log ? "yes" : "no",
			       (unsigned long long)r[i].hit_pkts, (unsigned long long)r[i].hit_bytes);
		}
		truncated_note(h);
	}
	free(h);
	return 0;
}

static int send_rule(struct fw_rule *r, uint32_t where, const char *after)
{
	struct fw_request req = { .type = FW_REQ_ADD_RULE, .arg = where };

	if (after)
		strncpy(req.name, after, FW_NAME_LEN - 1);
	req.u.rule = *r;
	return simple(&req);
}

static int bad(const char *what, const char *val)
{
	fprintf(stderr, "error: invalid %s '%s'\n", what, val);
	return 1;
}

static int set_name(char *dst, const char *val)
{
	if (!*val || strlen(val) >= FW_NAME_LEN) {
		fprintf(stderr, "error: rule name must be 1-%d characters\n", FW_NAME_LEN - 1);
		return -1;
	}
	strcpy(dst, val);
	return 0;
}

static void rule_defaults(struct fw_rule *r)
{
	memset(r, 0, sizeof(*r));
	r->sport_max = r->dport_max = 65535;
	r->action = 0xff;               /* "unset" */
}

/* fgets-based prompt; returns the trimmed answer or the default */
static const char *ask(const char *q, const char *def, char *buf, size_t n)
{
	printf("%s [%s]: ", q, def);
	fflush(stdout);
	if (!fgets(buf, (int)n, stdin))
		exit(1);
	buf[strcspn(buf, "\r\n")] = '\0';
	return *buf ? buf : def;
}

static int cmd_rule_add_interactive(void)
{
	struct fw_rule r;
	char buf[64], after[FW_NAME_LEN] = "";
	const char *a;

	rule_defaults(&r);
	a = ask("insert after rule (empty = end of chain, ^ = top)", "", buf, sizeof(buf));
	if (*a && strlen(a) >= FW_NAME_LEN)
		return bad("rule name", a);
	strcpy(after, a);
	if (set_name(r.name, ask("rule name", "", buf, sizeof(buf))))
		return 1;
	a = ask("source ip/mask", "any", buf, sizeof(buf));
	if (parse_cidr(a, &r.saddr, &r.smask))
		return bad("address", a);
	a = ask("source ports (80, 8000-8100, any)", "any", buf, sizeof(buf));
	if (parse_ports(a, &r.sport_min, &r.sport_max))
		return bad("port range", a);
	a = ask("destination ip/mask", "any", buf, sizeof(buf));
	if (parse_cidr(a, &r.daddr, &r.dmask))
		return bad("address", a);
	a = ask("destination ports", "any", buf, sizeof(buf));
	if (parse_ports(a, &r.dport_min, &r.dport_max))
		return bad("port range", a);
	a = ask("protocol (tcp/udp/icmp/any)", "any", buf, sizeof(buf));
	if (parse_proto(a, &r.proto))
		return bad("protocol", a);
	a = ask("action (accept/drop)", "drop", buf, sizeof(buf));
	if (parse_action(a, &r.action))
		return bad("action", a);
	a = ask("log matching packets (yes/no)", "no", buf, sizeof(buf));
	r.log = (a[0] == 'y' || a[0] == 'Y' || a[0] == '1');

	if (!after[0])
		return send_rule(&r, FW_ADD_TAIL, NULL);
	if (strcmp(after, "^") == 0)
		return send_rule(&r, FW_ADD_HEAD, NULL);
	return send_rule(&r, FW_ADD_AFTER, after);
}

/* argv points at the first option */
static int cmd_rule_add(int argc, char **argv)
{
	struct fw_rule r;
	uint32_t where = FW_ADD_TAIL;
	const char *after = NULL;
	int i;

	if (argc == 0)
		return cmd_rule_add_interactive();
	rule_defaults(&r);
	for (i = 0; i < argc; i++) {
		const char *o = argv[i];
		const char *v = i + 1 < argc ? argv[i + 1] : NULL;

		if (!strcmp(o, "--log")) { r.log = 1; continue; }
		if (!strcmp(o, "--head")) { where = FW_ADD_HEAD; continue; }
		if (!v) {
			fprintf(stderr, "error: option %s needs a value\n", o);
			return 1;
		}
		i++;
		if (!strcmp(o, "--name")) {
			if (set_name(r.name, v))
				return 1;
		} else if (!strcmp(o, "--src")) {
			if (parse_cidr(v, &r.saddr, &r.smask)) return bad("address", v);
		} else if (!strcmp(o, "--dst")) {
			if (parse_cidr(v, &r.daddr, &r.dmask)) return bad("address", v);
		} else if (!strcmp(o, "--sport")) {
			if (parse_ports(v, &r.sport_min, &r.sport_max)) return bad("port range", v);
		} else if (!strcmp(o, "--dport")) {
			if (parse_ports(v, &r.dport_min, &r.dport_max)) return bad("port range", v);
		} else if (!strcmp(o, "--proto")) {
			if (parse_proto(v, &r.proto)) return bad("protocol", v);
		} else if (!strcmp(o, "--action")) {
			if (parse_action(v, &r.action)) return bad("action", v);
		} else if (!strcmp(o, "--after")) {
			if (strlen(v) >= FW_NAME_LEN) return bad("rule name", v);
			where = FW_ADD_AFTER;
			after = v;
		} else {
			fprintf(stderr, "error: unknown option %s\n", o);
			return 1;
		}
	}
	if (!r.name[0] || r.action == 0xff) {
		fprintf(stderr, "error: --name and --action are required\n");
		return 1;
	}
	return send_rule(&r, where, after);
}

static int cmd_rule(int argc, char **argv)
{
	struct fw_request req = { 0 };

	if (argc < 1 || !strcmp(argv[0], "ls") || !strcmp(argv[0], "list"))
		return cmd_rule_ls();
	if (!strcmp(argv[0], "add"))
		return cmd_rule_add(argc - 1, argv + 1);
	if (!strcmp(argv[0], "del") || !strcmp(argv[0], "delete")) {
		if (argc < 2) {
			fprintf(stderr, "usage: uapp rule del NAME\n");
			return 1;
		}
		req.type = FW_REQ_DEL_RULE;
		strncpy(req.name, argv[1], FW_NAME_LEN - 1);
		return simple(&req);
	}
	if (!strcmp(argv[0], "flush")) {
		req.type = FW_REQ_FLUSH_RULES;
		return simple(&req);
	}
	if (!strcmp(argv[0], "default")) {
		uint8_t act;

		if (argc < 2 || parse_action(argv[1], &act)) {
			fprintf(stderr, "usage: uapp rule default accept|drop [--log]\n");
			return 1;
		}
		req.type = FW_REQ_SET_DEFAULT;
		req.arg = act | (argc > 2 && !strcmp(argv[2], "--log") ? FW_DEFAULT_LOG : 0);
		return simple(&req);
	}
	usage(stderr);
	return 1;
}

/* ------------------------------ NAT ------------------------------- */

static int cmd_nat_ls(void)
{
	struct fw_rsp_hdr *h;
	struct fw_nat_rule *n;
	char a[24], b[24], c[24];
	uint32_t i;

	if (fetch(FW_REQ_GET_NATS, 0, &h, (void **)&n))
		return 1;
	if (h->count == 0)
		printf("no NAT rules\n");
	for (i = 0; i < h->count; i++) {
		if (n[i].type == FW_NAT_SNAT) {
			fmt_cidr(n[i].saddr, n[i].smask, a, sizeof(a));
			fmt_ip(n[i].to_addr, b, sizeof(b));
			fmt_ports(n[i].to_port_min, n[i].to_port_max, c, sizeof(c));
			printf("%-3u SNAT  from %-18s -> source %s ports %s   (%llu flows)\n",
			       i, a, b, c, (unsigned long long)n[i].hits);
		} else {
			fmt_endpoint(n[i].daddr, n[i].dport, n[i].proto, a, sizeof(a));
			fmt_endpoint(n[i].to_addr, n[i].to_port_min, n[i].proto, b, sizeof(b));
			printf("%-3u DNAT  %s %-21s -> %s   (%llu flows)\n",
			       i, proto_name(n[i].proto), a, b, (unsigned long long)n[i].hits);
		}
	}
	free(h);
	return 0;
}

static int cmd_nat_add(int argc, char **argv)
{
	struct fw_request req = { .type = FW_REQ_ADD_NAT };
	struct fw_nat_rule *n = &req.u.nat;
	int i, have_src = 0, have_dst = 0, have_dport = 0, have_to = 0, to_port = 0;
	uint16_t lo, hi;

	n->to_port_min = 1;
	n->to_port_max = 65535;
	for (i = 0; i + 1 < argc; i += 2) {
		const char *o = argv[i], *v = argv[i + 1];

		if (!strcmp(o, "--type")) {
			if (!strcasecmp(v, "snat")) n->type = FW_NAT_SNAT;
			else if (!strcasecmp(v, "dnat")) n->type = FW_NAT_DNAT;
			else return bad("NAT type", v);
		} else if (!strcmp(o, "--src")) {
			if (parse_cidr(v, &n->saddr, &n->smask)) return bad("address", v);
			have_src = 1;
		} else if (!strcmp(o, "--dst")) {
			if (parse_ip(v, &n->daddr)) return bad("address", v);
			have_dst = 1;
		} else if (!strcmp(o, "--dport")) {
			if (parse_ports(v, &lo, &hi) || lo != hi || lo == 0) return bad("port", v);
			n->dport = lo;
			have_dport = 1;
		} else if (!strcmp(o, "--proto")) {
			if (parse_proto(v, &n->proto)) return bad("protocol", v);
		} else if (!strcmp(o, "--ports")) {
			if (parse_ports(v, &lo, &hi)) return bad("port range", v);
			n->to_port_min = lo ? lo : 1;
			n->to_port_max = hi;
		} else if (!strcmp(o, "--to")) {
			char ip[32], *colon;

			if (strlen(v) >= sizeof(ip)) return bad("address", v);
			strcpy(ip, v);
			colon = strchr(ip, ':');
			if (colon) {
				*colon = '\0';
				if (parse_ports(colon + 1, &lo, &hi) || lo != hi || lo == 0)
					return bad("port", colon + 1);
				n->to_port_min = n->to_port_max = lo;
				to_port = 1;
			}
			if (parse_ip(ip, &n->to_addr)) return bad("address", ip);
			have_to = 1;
		} else {
			fprintf(stderr, "error: unknown option %s\n", o);
			return 1;
		}
	}
	if (i != argc) {
		fprintf(stderr, "error: option %s needs a value\n", argv[argc - 1]);
		return 1;
	}
	if (!n->type) {
		/* the original tool only had source NAT: keep that as the default */
		n->type = FW_NAT_SNAT;
	}
	if (n->type == FW_NAT_SNAT && (!have_src || !have_to)) {
		fprintf(stderr, "error: snat needs --src CIDR and --to IP\n");
		return 1;
	}
	if (n->type == FW_NAT_DNAT) {
		if (!have_dst || !have_dport || !have_to ||
		    (n->proto != IPPROTO_TCP && n->proto != IPPROTO_UDP)) {
			fprintf(stderr, "error: dnat needs --dst IP --dport PORT --proto tcp|udp --to IP[:PORT]\n");
			return 1;
		}
		if (!to_port)
			n->to_port_min = n->to_port_max = n->dport;   /* keep the port */
	}
	return simple(&req);
}

static int cmd_nat(int argc, char **argv)
{
	struct fw_request req = { 0 };

	if (argc < 1 || !strcmp(argv[0], "ls") || !strcmp(argv[0], "list"))
		return cmd_nat_ls();
	if (!strcmp(argv[0], "add"))
		return cmd_nat_add(argc - 1, argv + 1);
	if (!strcmp(argv[0], "del") || !strcmp(argv[0], "delete")) {
		char *end;

		if (argc < 2 || (req.arg = (uint32_t)strtoul(argv[1], &end, 10), *end)) {
			fprintf(stderr, "usage: uapp nat del SEQ\n");
			return 1;
		}
		req.type = FW_REQ_DEL_NAT;
		return simple(&req);
	}
	if (!strcmp(argv[0], "flush")) {
		req.type = FW_REQ_FLUSH_NATS;
		return simple(&req);
	}
	usage(stderr);
	return 1;
}

/* --------------------------- log / conn --------------------------- */

static int cmd_log(int argc, char **argv)
{
	struct fw_rsp_hdr *h;
	struct fw_log *l;
	unsigned long want = 0;
	char tbuf[32], src[32], dst[32];
	uint32_t i;

	if (argc > 0 && !strcmp(argv[0], "clear")) {
		struct fw_request req = { .type = FW_REQ_CLEAR_LOGS };

		return simple(&req);
	}
	if (argc > 0 && (!strcmp(argv[0], "ls") || !strcmp(argv[0], "list")))
		argc--, argv++;
	if (argc > 0)
		want = strtoul(argv[0], NULL, 10);
	if (fetch(FW_REQ_GET_LOGS, (uint32_t)want, &h, (void **)&l))
		return 1;
	if (h->count == 0)
		printf("no log entries\n");
	for (i = 0; i < h->count; i++) {
		time_t t = (time_t)l[i].ts;
		struct tm tm;

		localtime_r(&t, &tm);
		strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
		fmt_endpoint(l[i].saddr, l[i].sport, l[i].proto, src, sizeof(src));
		fmt_endpoint(l[i].daddr, l[i].dport, l[i].proto, dst, sizeof(dst));
		printf("[%s] %-6s %-4s %21s -> %-21s len=%-5u %s%s\n", tbuf,
		       l[i].action == FW_ACT_ACCEPT ? "ACCEPT" : "DROP",
		       proto_name(l[i].proto), src, dst, l[i].len,
		       l[i].by_default ? "(default policy)" : "rule=",
		       l[i].by_default ? "" : l[i].rule);
	}
	if (h->total > h->count && want == 0)
		truncated_note(h);
	free(h);
	return 0;
}

static int cmd_conn(int argc, char **argv)
{
	struct fw_rsp_hdr *h;
	struct fw_conn *c;
	char a[32], b[32], ra[32], rb[32];
	uint32_t i;

	if (argc > 0 && !strcmp(argv[0], "flush")) {
		struct fw_request req = { .type = FW_REQ_FLUSH_CONNS };

		return simple(&req);
	}
	if (fetch(FW_REQ_GET_CONNS, 0, &h, (void **)&c))
		return 1;
	if (h->count == 0) {
		printf("no connections\n");
		free(h);
		return 0;
	}
	printf("%-5s %-45s %-5s %-8s %s\n", "proto", "original direction", "nat", "expires", "packets (orig/reply)");
	for (i = 0; i < h->count; i++) {
		char flow[80];

		fmt_endpoint(c[i].saddr, c[i].sport, c[i].proto, a, sizeof(a));
		fmt_endpoint(c[i].daddr, c[i].dport, c[i].proto, b, sizeof(b));
		snprintf(flow, sizeof(flow), "%s -> %s", a, b);
		printf("%-5s %-45s %-5s %6us   %llu/%llu\n", proto_name(c[i].proto), flow,
		       c[i].nat_type == FW_NAT_SNAT ? "SNAT" : c[i].nat_type == FW_NAT_DNAT ? "DNAT" : "-",
		       c[i].expires_in, (unsigned long long)c[i].pkts_orig,
		       (unsigned long long)c[i].pkts_reply);
		if (c[i].nat_type != FW_NAT_NONE) {
			fmt_endpoint(c[i].r_saddr, c[i].r_sport, c[i].proto, ra, sizeof(ra));
			fmt_endpoint(c[i].r_daddr, c[i].r_dport, c[i].proto, rb, sizeof(rb));
			printf("      reply: %s -> %s\n", ra, rb);
		}
	}
	printf("%u connection(s)\n", h->total);
	truncated_note(h);
	free(h);
	return 0;
}

/* --------------------------- save / load -------------------------- */

static int cmd_save(int argc, char **argv)
{
	struct fw_rsp_hdr *hs, *hr, *hn;
	struct fw_status *s;
	struct fw_rule *r;
	struct fw_nat_rule *n;
	FILE *f = stdout;
	char a[32], b[32], c[32], d[32];
	time_t now = time(NULL);
	uint32_t i;

	if (fetch(FW_REQ_STATUS, 0, &hs, (void **)&s))
		return 1;
	if (fetch(FW_REQ_GET_RULES, 0, &hr, (void **)&r))
		return 1;
	if (fetch(FW_REQ_GET_NATS, 0, &hn, (void **)&n))
		return 1;
	if (argc > 0 && !(f = fopen(argv[0], "w"))) {
		perror(argv[0]);
		return 1;
	}
	fprintf(f, "# myfw ruleset saved %s", ctime(&now));
	fprintf(f, "rule default %s%s\n", s->default_action == FW_ACT_ACCEPT ? "accept" : "drop",
		s->log_default ? " --log" : "");
	for (i = 0; i < hr->count; i++) {
		fmt_cidr(r[i].saddr, r[i].smask, a, sizeof(a));
		fmt_cidr(r[i].daddr, r[i].dmask, b, sizeof(b));
		fmt_ports(r[i].sport_min, r[i].sport_max, c, sizeof(c));
		fmt_ports(r[i].dport_min, r[i].dport_max, d, sizeof(d));
		fprintf(f, "rule add --name %s --src %s --dst %s --sport %s --dport %s --proto %s --action %s%s\n",
			r[i].name, a, b, c, d, proto_name(r[i].proto),
			r[i].action == FW_ACT_ACCEPT ? "accept" : "drop", r[i].log ? " --log" : "");
	}
	for (i = 0; i < hn->count; i++) {
		if (n[i].type == FW_NAT_SNAT) {
			fmt_cidr(n[i].saddr, n[i].smask, a, sizeof(a));
			fmt_ip(n[i].to_addr, b, sizeof(b));
			fmt_ports(n[i].to_port_min, n[i].to_port_max, c, sizeof(c));
			fprintf(f, "nat add --type snat --src %s --to %s --ports %s\n", a, b, c);
		} else {
			fmt_ip(n[i].daddr, a, sizeof(a));
			fmt_ip(n[i].to_addr, b, sizeof(b));
			fprintf(f, "nat add --type dnat --dst %s --dport %u --proto %s --to %s:%u\n",
				a, n[i].dport, proto_name(n[i].proto), b, n[i].to_port_min);
		}
	}
	if (f != stdout) {
		fclose(f);
		printf("saved %u rule(s) and %u NAT rule(s) to %s\n", hr->count, hn->count, argv[0]);
	}
	free(hs);
	free(hr);
	free(hn);
	return 0;
}

static int cmd_load(int argc, char **argv)
{
	struct fw_request req = { 0 };
	char line[512];
	FILE *f;
	int lineno = 0, ok = 0, failed = 0;

	if (argc < 1) {
		fprintf(stderr, "usage: uapp load FILE\n");
		return 1;
	}
	if (!(f = fopen(argv[0], "r"))) {
		perror(argv[0]);
		return 1;
	}
	req.type = FW_REQ_FLUSH_RULES;
	if (simple(&req))
		goto out;
	req.type = FW_REQ_FLUSH_NATS;
	if (simple(&req))
		goto out;
	while (fgets(line, sizeof(line), f)) {
		char *args[MAX_ARGS], *tok, *save;
		int n = 0;

		lineno++;
		line[strcspn(line, "\r\n")] = '\0';
		for (tok = strtok_r(line, " \t", &save); tok && n < MAX_ARGS; tok = strtok_r(NULL, " \t", &save))
			args[n++] = tok;
		if (n == 0 || args[0][0] == '#')
			continue;
		if (strcmp(args[0], "rule") && strcmp(args[0], "nat")) {
			fprintf(stderr, "%s:%d: only 'rule' and 'nat' commands are allowed\n", argv[0], lineno);
			failed++;
			continue;
		}
		if (n == 2 && !strcmp(args[1], "add")) {    /* never go interactive */
			fprintf(stderr, "%s:%d: incomplete command\n", argv[0], lineno);
			failed++;
			continue;
		}
		if (dispatch(n, args)) {
			fprintf(stderr, "%s:%d: command failed\n", argv[0], lineno);
			failed++;
		} else {
			ok++;
		}
	}
out:
	fclose(f);
	printf("loaded %d command(s) from %s, %d failed\n", ok, argv[0], failed);
	return failed ? 1 : 0;
}

/* ------------------------------------------------------------------ */

/* argv[0] is the command (no program name) */
static int dispatch(int argc, char **argv)
{
	const char *c = argv[0];

	if (!strcmp(c, "status"))
		return cmd_status();
	if (!strcmp(c, "rule") || !strcmp(c, "r"))
		return cmd_rule(argc - 1, argv + 1);
	if (!strcmp(c, "nat") || !strcmp(c, "n"))
		return cmd_nat(argc - 1, argv + 1);
	if (!strcmp(c, "log") || !strcmp(c, "logs"))
		return cmd_log(argc - 1, argv + 1);
	if (!strcmp(c, "conn") || !strcmp(c, "conns") || !strcmp(c, "connect"))
		return cmd_conn(argc - 1, argv + 1);
	if (!strcmp(c, "save"))
		return cmd_save(argc - 1, argv + 1);
	if (!strcmp(c, "load"))
		return cmd_load(argc - 1, argv + 1);
	if (!strcmp(c, "ls") || !strcmp(c, "l")) {
		const char *w = argc > 1 ? argv[1] : "";

		if (w[0] == 'r') return cmd_rule_ls();
		if (w[0] == 'n') return cmd_nat_ls();
		if (w[0] == 'l') return cmd_log(argc - 2, argv + 2);
		if (w[0] == 'c') return cmd_conn(0, NULL);
	}
	if (!strcmp(c, "help") || !strcmp(c, "-h") || !strcmp(c, "--help")) {
		usage(stdout);
		return 0;
	}
	usage(stderr);
	return 1;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return 1;
	}
	return dispatch(argc - 1, argv + 1);
}
