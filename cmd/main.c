/*
 * uapp - command line front end of the myfw firewall (UAPI v3).
 *
 * Two kinds of commands:
 *   - low-level, machine-friendly ones used by the fwctl control plane
 *     (status/counters/policy/conn/events/abi, all with --json);
 *   - the legacy rule/nat/zone/log/save/load commands of the original tool.
 *     They no longer modify the kernel piece by piece: each one reads the
 *     complete active policy, edits a copy and commits it as one new
 *     generation (load commits the whole file once, or nothing). When the
 *     active policy is owned by fwctl (managed flag) they refuse unless
 *     --force-legacy is given, so the versioned control plane cannot be
 *     bypassed by accident.
 * Run "uapp help" for usage.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "uapp.h"

#define MAX_ARGS 64
#define LOG_MARK_DIR "/run/myfw"
#define LOG_MARK LOG_MARK_DIR "/uapp-log-mark"

static struct fw_nl g_nl = { .fd = -1 };
static int g_force_legacy;
static int g_json;

static void usage(FILE *f)
{
	fprintf(f,
"usage: uapp [--force-legacy] <command> [arguments]\n"
"\n"
"machine interface (used by fwctl; add --json for JSON output)\n"
"  status | counters | abi             module state, verdict counters, ABI sizes\n"
"  policy show                          decode the active policy\n"
"  policy export FILE                   write the complete active policy blob\n"
"  policy apply FILE --expected-gen N|current [--validate-only]\n"
"                                       stage, validate and commit a policy blob\n"
"  conn [flush]                         tracked flows (all pages)\n"
"  events [--since SEQ] [--max N]       sequenced kernel events\n"
"\n"
"legacy commands (each one commits a complete new generation)\n"
"  rule ls\n"
"  rule add                             interactive\n"
"  rule add --name ID --action accept|drop [options]\n"
"        --src CIDR --dst CIDR --sport R --dport R --proto tcp|udp|icmp|any --log\n"
"        --scope any|ingress|local_out  --zone NAME   --head | --after ID\n"
"  rule del ID | rule flush | rule default accept|drop [--log]\n"
"  zone ls | zone add --name N --if IFNAME [--src CIDR]... | zone del N\n"
"  nat ls\n"
"  nat add --type snat --src CIDR --to IP [--ports R] [--dst CIDR] [--zone N] [--out IF]\n"
"  nat add --type dnat --dst IP --dport PORT --proto tcp|udp --to IP[:PORT] [--zone N]\n"
"  nat del SEQ | nat flush\n"
"  log [N] | log clear                  packet events (clear = hide older ones)\n"
"  save [FILE] | load FILE              ruleset as uapp commands; load is all-or-nothing\n");
}

/* ------------------------------------------------------------------ */

static int session(void)
{
	int err;

	if (g_nl.fd >= 0)
		return 0;
	err = fw_open(&g_nl);
	if (err)
		fprintf(stderr, "error: %s\n", fw_strerror(err));
	return err;
}

static int request(uint32_t type, const void *pl, size_t len, struct fw_rsp_hdr **h, void **body)
{
	int err;

	if (session())
		return -1;
	err = fw_req(&g_nl, type, pl, len, h, body);
	if (err) {
		if (*h && (*h)->type == FW_RSP_ERR && (*h)->msg[0] && err != -EPERM)
			fprintf(stderr, "error: %s\n", (*h)->msg);
		else
			fprintf(stderr, "error: %s\n", fw_strerror(err));
		free(*h);
		*h = NULL;
	}
	return err;
}

static int bad(const char *what, const char *val)
{
	fprintf(stderr, "error: invalid %s '%s'\n", what, val);
	return 1;
}

/* ------------------------------------------------------------ status */

static int cmd_status(void)
{
	struct fw_rsp_hdr *h, *hc;
	struct fw_status *s;
	struct fw_counters *c;

	if (request(FW_REQ_STATUS, NULL, 0, &h, (void **)&s))
		return 1;
	if (request(FW_REQ_COUNTERS, NULL, 0, &hc, (void **)&c)) {
		free(h);
		return 1;
	}
	if (g_json) {
		printf("{\"uapi_version\": %u, \"generation\": %u, \"default_action\": \"%s\", "
		       "\"default_log\": %s, \"managed\": %s, \"legacy\": %s, \"gate\": %u, "
		       "\"zones\": %u, \"rules\": %u, \"nats\": %u, \"conns\": %u, \"max_conns\": %u, "
		       "\"tcp_timeout\": %u, \"udp_timeout\": %u, \"icmp_timeout\": %u, "
		       "\"stage_state\": %u, \"stage_bytes\": %u, \"commits\": %llu, "
		       "\"last_gate_ns\": %llu, \"last_commit_ns\": %lld, \"last_flows_reset\": %llu, "
		       "\"event_next_seq\": %llu, \"policy_hash\": ",
		       s->uapi_version, s->generation, s->default_action ? "accept" : "drop",
		       s->default_log ? "true" : "false",
		       s->flags & FW_POLICY_F_MANAGED ? "true" : "false",
		       s->flags & FW_POLICY_F_LEGACY ? "true" : "false", s->gate,
		       s->n_zones, s->n_rules, s->n_nats, s->n_conns, s->max_conns,
		       s->tcp_timeout, s->udp_timeout, s->icmp_timeout, s->stage_state, s->stage_bytes,
		       (unsigned long long)s->commits, (unsigned long long)s->last_gate_ns,
		       (long long)s->last_commit_ns, (unsigned long long)s->last_flows_reset,
		       (unsigned long long)s->event_next_seq);
		json_str(stdout, s->policy_hash);
		printf(", \"label\": ");
		json_str(stdout, s->label);
		printf(", \"blob_sha256\": ");
		json_str(stdout, s->blob_sha256);
		printf("}\n");
	} else {
		printf("myfw module         loaded (UAPI v%u)\n", s->uapi_version);
		printf("generation          %u%s\n", s->generation,
		       s->flags & FW_POLICY_F_MANAGED ? "  (managed by fwctl)" : "");
		printf("policy              hash %s, label \"%s\"\n", s->policy_hash, s->label);
		printf("default action      %s%s\n", s->default_action == FW_ACT_ACCEPT ? "ACCEPT" : "DROP",
		       s->default_log ? " (logged)" : "");
		printf("zones               %u\n", s->n_zones);
		printf("filter rules        %u\n", s->n_rules);
		printf("NAT rules           %u\n", s->n_nats);
		printf("connections         %u / %u\n", s->n_conns, s->max_conns);
		printf("timeouts            tcp %us, udp %us, icmp %us\n",
		       s->tcp_timeout, s->udp_timeout, s->icmp_timeout);
		printf("packets             %llu accepted, %llu dropped, %llu stateful hits, %llu NAT rewrites\n",
		       (unsigned long long)c->accept_pkts, (unsigned long long)c->drop_pkts,
		       (unsigned long long)c->stateful_hits, (unsigned long long)c->nat_translations);
		printf("commits             %llu (last gate %.3f ms, %llu flows reset)\n",
		       (unsigned long long)s->commits, s->last_gate_ns / 1e6,
		       (unsigned long long)s->last_flows_reset);
		printf("events              next seq %llu\n", (unsigned long long)s->event_next_seq);
		if (s->stage_state)
			printf("staging             a candidate is %s (%u bytes)\n",
			       s->stage_state == 1 ? "being received" : "validated", s->stage_bytes);
	}
	free(h);
	free(hc);
	return 0;
}

static int cmd_counters(void)
{
	struct fw_rsp_hdr *h;
	struct fw_counters *c;
	int i;

	if (request(FW_REQ_COUNTERS, NULL, 0, &h, (void **)&c))
		return 1;
	if (g_json) {
		printf("{\"generation\": %u, \"conns\": %u, \"max_conns\": %u, "
		       "\"accept_pkts\": %llu, \"accept_bytes\": %llu, \"drop_pkts\": %llu, \"drop_bytes\": %llu, "
		       "\"new_flow_accept\": %llu, \"new_flow_drop\": %llu, \"stateful_hits\": %llu, "
		       "\"nat_translations\": %llu, \"flow_create_failed\": %llu, \"nat_alloc_failed\": %llu, "
		       "\"events_suppressed\": %llu, \"events_overwritten\": %llu, \"commits\": %llu, "
		       "\"commit_rejected\": %llu, \"stage_aborted\": %llu, \"drop_reason\": {",
		       c->generation, c->n_conns, c->max_conns,
		       (unsigned long long)c->accept_pkts, (unsigned long long)c->accept_bytes,
		       (unsigned long long)c->drop_pkts, (unsigned long long)c->drop_bytes,
		       (unsigned long long)c->new_flow_accept, (unsigned long long)c->new_flow_drop,
		       (unsigned long long)c->stateful_hits, (unsigned long long)c->nat_translations,
		       (unsigned long long)c->flow_create_failed, (unsigned long long)c->nat_alloc_failed,
		       (unsigned long long)c->events_suppressed, (unsigned long long)c->events_overwritten,
		       (unsigned long long)c->commits, (unsigned long long)c->commit_rejected,
		       (unsigned long long)c->stage_aborted);
		for (i = 1; i < FW_R__COUNT; i++)
			printf("%s\"%s\": %llu", i > 1 ? ", " : "", reason_name(i),
			       (unsigned long long)c->drop_reason[i]);
		printf("}, \"zone_accept\": [");
		for (i = 0; i < FW_ZONE_SLOTS; i++)
			printf("%s%llu", i ? ", " : "", (unsigned long long)c->zone_accept[i]);
		printf("], \"zone_drop\": [");
		for (i = 0; i < FW_ZONE_SLOTS; i++)
			printf("%s%llu", i ? ", " : "", (unsigned long long)c->zone_drop[i]);
		printf("]}\n");
	} else {
		printf("generation %u, flows %u / %u\n", c->generation, c->n_conns, c->max_conns);
		printf("final verdicts      %llu accepted (%llu bytes), %llu dropped (%llu bytes)\n",
		       (unsigned long long)c->accept_pkts, (unsigned long long)c->accept_bytes,
		       (unsigned long long)c->drop_pkts, (unsigned long long)c->drop_bytes);
		printf("new flow decisions  %llu accept, %llu drop; %llu stateful hits\n",
		       (unsigned long long)c->new_flow_accept, (unsigned long long)c->new_flow_drop,
		       (unsigned long long)c->stateful_hits);
		printf("failures            %llu flow creations, %llu SNAT allocations\n",
		       (unsigned long long)c->flow_create_failed, (unsigned long long)c->nat_alloc_failed);
		printf("drop reasons\n");
		for (i = 1; i < FW_R__COUNT; i++)
			if (c->drop_reason[i])
				printf("  %-24s %llu\n", reason_name(i), (unsigned long long)c->drop_reason[i]);
		printf("events              %llu suppressed by rate limit, %llu overwritten\n",
		       (unsigned long long)c->events_suppressed, (unsigned long long)c->events_overwritten);
		printf("control             %llu commits, %llu rejected, %llu staging aborted\n",
		       (unsigned long long)c->commits, (unsigned long long)c->commit_rejected,
		       (unsigned long long)c->stage_aborted);
	}
	free(h);
	return 0;
}

static int cmd_abi(void)
{
	struct fw_rsp_hdr *h;
	struct fw_abi *a;
	uint32_t i;

	if (request(FW_REQ_ABI, NULL, 0, &h, (void **)&a))
		return 1;
	printf("{\"uapi_version\": %u, \"module\": [", a->uapi_version);
	for (i = 0; i < a->n; i++)
		printf("%s%u", i ? ", " : "", a->size[i]);
	printf("], \"uapp\": [");
	i = 0;
#define X(name) printf("%s%zu", i++ ? ", " : "", sizeof(struct name));
	FW_ABI_LIST(X)
#undef X
	printf("]}\n");
	free(h);
	return 0;
}

/* ------------------------------------------------- policy load/commit */

static int load_active(struct pol *p, uint32_t *gen)
{
	uint8_t *blob;
	size_t len;
	char err[128];
	int ret;

	if (session())
		return -1;
	ret = fw_fetch_policy(&g_nl, &blob, &len, gen);
	if (ret) {
		fprintf(stderr, "error: cannot read the active policy: %s\n",
			ret == -EBADMSG ? "incomplete or corrupted export" : fw_strerror(ret));
		return -1;
	}
	ret = pol_decode(blob, len, p, err, sizeof(err));
	free(blob);
	if (ret)
		fprintf(stderr, "error: %s\n", err);
	return ret;
}

static int edit_begin(struct pol *p, uint32_t *gen)
{
	if (load_active(p, gen))
		return -1;
	if ((p->h.flags & FW_POLICY_F_MANAGED) && !g_force_legacy) {
		fprintf(stderr, "error: the active policy is managed by fwctl; change it with fwctl "
			"(or pass --force-legacy, which the fwctl audit will report as drift)\n");
		return -1;
	}
	return 0;
}

static int commit_pol(struct pol *p, uint32_t gen, const char *what)
{
	struct apply_opts o = { .expected_gen = gen, .stop_after_chunks = -1 };
	struct fw_commit_result res;
	char err[128], hex[65];
	uint8_t *blob;
	size_t len;
	int ret;

	p->h.flags = (p->h.flags & ~FW_POLICY_F_MANAGED) | FW_POLICY_F_LEGACY;
	memset(p->h.policy_hash, 0, sizeof(p->h.policy_hash));
	memset(p->h.label, 0, sizeof(p->h.label));
	snprintf(p->h.label, sizeof(p->h.label), "uapp %s", what);
	len = pol_size(p);
	blob = malloc(len);
	if (!blob)
		return 1;
	pol_encode(p, blob);
	sha256_hex(blob, len, hex);
	snprintf(p->h.policy_hash, sizeof(p->h.policy_hash), "legacy-%.24s", hex);
	pol_encode(p, blob);
	ret = fw_apply_blob(&g_nl, blob, len, &o, &res, err, sizeof(err));
	free(blob);
	if (ret) {
		fprintf(stderr, "error: %s\n", err);
		return 1;
	}
	printf("%s: generation %u, %llu flow(s) reset\n", what, res.generation,
	       (unsigned long long)res.flows_reset);
	return 0;
}

/* ------------------------------------------------- editing operations */

static void rule_defaults(struct fw_rule_spec *r)
{
	memset(r, 0, sizeof(*r));
	r->sport_max = r->dport_max = 65535;
	r->action = 0xff;               /* "unset" */
}

static int set_id(char *dst, const char *val, const char *what)
{
	if (!valid_id(val)) {
		fprintf(stderr, "error: %s must be 1-%d characters of A-Z a-z 0-9 . _ : -\n",
			what, FW_ID_LEN - 1);
		return -1;
	}
	strcpy(dst, val);
	return 0;
}

static int parse_scope(const char *s, uint8_t *scope)
{
	if (!strcmp(s, "any"))
		*scope = FW_SCOPE_ANY;
	else if (!strcmp(s, "ingress"))
		*scope = FW_SCOPE_INGRESS;
	else if (!strcmp(s, "local_out") || !strcmp(s, "local-out"))
		*scope = FW_SCOPE_LOCAL_OUT;
	else
		return -1;
	return 0;
}

static int insert_rule(struct pol *p, const struct fw_rule_spec *r, int head, const char *after)
{
	int pos = (int)p->h.n_rules, a;

	if (p->h.n_rules >= FW_MAX_RULES) {
		fprintf(stderr, "error: rule limit (%d) reached\n", FW_MAX_RULES);
		return 1;
	}
	if (pol_rule_index(p, r->id) >= 0) {
		fprintf(stderr, "error: a rule named %s already exists\n", r->id);
		return 1;
	}
	if (head)
		pos = 0;
	if (after) {
		a = pol_rule_index(p, after);
		if (a < 0) {
			fprintf(stderr, "error: no rule named %s\n", after);
			return 1;
		}
		pos = a + 1;
	}
	memmove(&p->rules[pos + 1], &p->rules[pos], (p->h.n_rules - pos) * sizeof(p->rules[0]));
	p->rules[pos] = *r;
	p->h.n_rules++;
	return 0;
}

/* argv points at the first option; edits p only */
static int op_rule_add(struct pol *p, int argc, char **argv)
{
	struct fw_rule_spec r;
	const char *after = NULL;
	int head = 0, i;

	rule_defaults(&r);
	for (i = 0; i < argc; i++) {
		const char *o = argv[i];
		const char *v = i + 1 < argc ? argv[i + 1] : NULL;

		if (!strcmp(o, "--log")) { r.log = 1; continue; }
		if (!strcmp(o, "--head")) { head = 1; continue; }
		if (!v) {
			fprintf(stderr, "error: option %s needs a value\n", o);
			return 1;
		}
		i++;
		if (!strcmp(o, "--name") || !strcmp(o, "--id")) {
			if (set_id(r.id, v, "rule name"))
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
		} else if (!strcmp(o, "--scope")) {
			if (parse_scope(v, &r.scope)) return bad("scope", v);
		} else if (!strcmp(o, "--zone")) {
			int z = pol_zone_index(p, v);

			if (!z) return bad("zone (see uapp zone ls)", v);
			r.zone = (uint8_t)z;
		} else if (!strcmp(o, "--after")) {
			if (!valid_id(v)) return bad("rule name", v);
			after = v;
		} else {
			fprintf(stderr, "error: unknown option %s\n", o);
			return 1;
		}
	}
	if (!r.id[0] || r.action == 0xff) {
		fprintf(stderr, "error: --name and --action are required\n");
		return 1;
	}
	if (r.zone && r.scope == FW_SCOPE_LOCAL_OUT) {
		fprintf(stderr, "error: a local_out rule cannot name an ingress zone\n");
		return 1;
	}
	if (r.zone && r.scope == FW_SCOPE_ANY)
		r.scope = FW_SCOPE_INGRESS;
	return insert_rule(p, &r, head, after);
}

static int op_rule_del(struct pol *p, const char *id)
{
	int i = pol_rule_index(p, id);

	if (i < 0) {
		fprintf(stderr, "error: no rule named %s\n", id);
		return 1;
	}
	memmove(&p->rules[i], &p->rules[i + 1], (p->h.n_rules - i - 1) * sizeof(p->rules[0]));
	p->h.n_rules--;
	return 0;
}

static int op_zone_add(struct pol *p, int argc, char **argv)
{
	struct fw_zone_spec z;
	int i;

	memset(&z, 0, sizeof(z));
	for (i = 0; i + 1 < argc; i += 2) {
		const char *o = argv[i], *v = argv[i + 1];

		if (!strcmp(o, "--name")) {
			if (set_id(z.name, v, "zone name"))
				return 1;
		} else if (!strcmp(o, "--if")) {
			if (!*v || strlen(v) >= FW_IFNAME_LEN) return bad("interface", v);
			strcpy(z.ifname, v);
		} else if (!strcmp(o, "--src")) {
			if (z.n_srcs >= FW_MAX_ZONE_SRCS) return bad("source (too many)", v);
			if (parse_cidr(v, &z.srcs[z.n_srcs].addr, &z.srcs[z.n_srcs].mask))
				return bad("address", v);
			z.n_srcs++;
		} else {
			fprintf(stderr, "error: unknown option %s\n", o);
			return 1;
		}
	}
	if (i != argc || !z.name[0] || !z.ifname[0]) {
		fprintf(stderr, "error: zone add needs --name N --if IFNAME [--src CIDR]...\n");
		return 1;
	}
	if (pol_zone_index(p, z.name)) {
		fprintf(stderr, "error: zone %s already exists\n", z.name);
		return 1;
	}
	if (p->h.n_zones >= FW_MAX_ZONES) {
		fprintf(stderr, "error: zone limit (%d) reached\n", FW_MAX_ZONES);
		return 1;
	}
	p->zones[p->h.n_zones++] = z;
	return 0;
}

static int op_zone_del(struct pol *p, const char *name)
{
	int z = pol_zone_index(p, name);
	uint32_t i;

	if (!z) {
		fprintf(stderr, "error: no zone named %s\n", name);
		return 1;
	}
	for (i = 0; i < p->h.n_rules; i++)
		if (p->rules[i].zone == z) {
			fprintf(stderr, "error: rule %s still uses zone %s\n", p->rules[i].id, name);
			return 1;
		}
	for (i = 0; i < p->h.n_nats; i++)
		if (p->nats[i].zone == z) {
			fprintf(stderr, "error: NAT %s still uses zone %s\n", p->nats[i].id, name);
			return 1;
		}
	/* renumber references to the zones after it */
	for (i = 0; i < p->h.n_rules; i++)
		if (p->rules[i].zone > z)
			p->rules[i].zone--;
	for (i = 0; i < p->h.n_nats; i++)
		if (p->nats[i].zone > z)
			p->nats[i].zone--;
	memmove(&p->zones[z - 1], &p->zones[z], (p->h.n_zones - z) * sizeof(p->zones[0]));
	p->h.n_zones--;
	return 0;
}

static int op_nat_add(struct pol *p, int argc, char **argv)
{
	struct fw_nat_spec n;
	int i, have_src = 0, have_dst = 0, have_dport = 0, have_to = 0, to_port = 0;
	uint16_t lo, hi;
	uint32_t k;

	memset(&n, 0, sizeof(n));
	n.to_port_min = 1;
	n.to_port_max = 65535;
	for (i = 0; i + 1 < argc; i += 2) {
		const char *o = argv[i], *v = argv[i + 1];

		if (!strcmp(o, "--type")) {
			if (!strcasecmp(v, "snat")) n.type = FW_NAT_SNAT;
			else if (!strcasecmp(v, "dnat")) n.type = FW_NAT_DNAT;
			else return bad("NAT type", v);
		} else if (!strcmp(o, "--id")) {
			if (set_id(n.id, v, "NAT id"))
				return 1;
		} else if (!strcmp(o, "--src")) {
			if (parse_cidr(v, &n.saddr, &n.smask)) return bad("address", v);
			have_src = 1;
		} else if (!strcmp(o, "--dst")) {
			if (parse_cidr(v, &n.daddr, &n.dmask)) return bad("address", v);
			have_dst = 1;
		} else if (!strcmp(o, "--dport")) {
			if (parse_ports(v, &lo, &hi) || lo != hi || lo == 0) return bad("port", v);
			n.dport = lo;
			have_dport = 1;
		} else if (!strcmp(o, "--proto")) {
			if (parse_proto(v, &n.proto)) return bad("protocol", v);
		} else if (!strcmp(o, "--ports")) {
			if (parse_ports(v, &lo, &hi)) return bad("port range", v);
			n.to_port_min = lo ? lo : 1;
			n.to_port_max = hi;
		} else if (!strcmp(o, "--zone")) {
			int z = pol_zone_index(p, v);

			if (!z) return bad("zone", v);
			n.zone = (uint8_t)z;
		} else if (!strcmp(o, "--out")) {
			if (!*v || strlen(v) >= FW_IFNAME_LEN) return bad("interface", v);
			strcpy(n.out_ifname, v);
		} else if (!strcmp(o, "--to")) {
			char ip[32], *colon;

			if (strlen(v) >= sizeof(ip)) return bad("address", v);
			strcpy(ip, v);
			colon = strchr(ip, ':');
			if (colon) {
				*colon = '\0';
				if (parse_ports(colon + 1, &lo, &hi) || lo != hi || lo == 0)
					return bad("port", colon + 1);
				n.to_port_min = n.to_port_max = lo;
				to_port = 1;
			}
			if (parse_ip(ip, &n.to_addr)) return bad("address", ip);
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
	if (!n.type)
		n.type = FW_NAT_SNAT;   /* the original tool only had source NAT */
	if (n.type == FW_NAT_SNAT && (!have_src || !have_to)) {
		fprintf(stderr, "error: snat needs --src CIDR and --to IP\n");
		return 1;
	}
	if (n.type == FW_NAT_DNAT) {
		if (!have_dst || n.dmask != 0xffffffffu || !have_dport || !have_to ||
		    (n.proto != IPPROTO_TCP && n.proto != IPPROTO_UDP)) {
			fprintf(stderr, "error: dnat needs --dst IP --dport PORT --proto tcp|udp --to IP[:PORT]\n");
			return 1;
		}
		if (!to_port)
			n.to_port_min = n.to_port_max = n.dport;
	}
	(void)have_dst;
	if (!n.id[0]) {                 /* legacy: invent a free id */
		for (k = 0;; k++) {
			uint32_t j, used = 0;

			snprintf(n.id, sizeof(n.id), "nat%u", k);
			for (j = 0; j < p->h.n_nats; j++)
				used |= !strcmp(p->nats[j].id, n.id);
			if (!used)
				break;
		}
	}
	for (k = 0; k < p->h.n_nats; k++)
		if (!strcmp(p->nats[k].id, n.id)) {
			fprintf(stderr, "error: NAT id %s already exists\n", n.id);
			return 1;
		}
	if (p->h.n_nats >= FW_MAX_NATS) {
		fprintf(stderr, "error: NAT limit (%d) reached\n", FW_MAX_NATS);
		return 1;
	}
	p->nats[p->h.n_nats++] = n;
	return 0;
}

static int op_nat_del(struct pol *p, const char *arg)
{
	uint32_t seq;

	if (parse_u32(arg, &seq) || seq >= p->h.n_nats) {
		fprintf(stderr, "error: no NAT rule number '%s' (see uapp nat ls)\n", arg);
		return 1;
	}
	memmove(&p->nats[seq], &p->nats[seq + 1], (p->h.n_nats - seq - 1) * sizeof(p->nats[0]));
	p->h.n_nats--;
	return 0;
}

/* Apply one rule/nat/zone command to p without committing. */
static int apply_line(struct pol *p, int argc, char **argv)
{
	const char *w = argc > 0 ? argv[0] : "";
	const char *v = argc > 1 ? argv[1] : "";

	if (!strcmp(w, "rule")) {
		if (!strcmp(v, "add") && argc > 2)
			return op_rule_add(p, argc - 2, argv + 2);
		if ((!strcmp(v, "del") || !strcmp(v, "delete")) && argc == 3)
			return op_rule_del(p, argv[2]);
		if (!strcmp(v, "flush") && argc == 2) {
			p->h.n_rules = 0;
			return 0;
		}
		if (!strcmp(v, "default") && argc >= 3) {
			uint8_t act;

			if (parse_action(argv[2], &act) || (argc == 4 && strcmp(argv[3], "--log")) || argc > 4)
				return bad("default policy", argv[2]);
			p->h.default_action = act;
			p->h.default_log = argc == 4;
			return 0;
		}
	} else if (!strcmp(w, "nat")) {
		if (!strcmp(v, "add") && argc > 2)
			return op_nat_add(p, argc - 2, argv + 2);
		if ((!strcmp(v, "del") || !strcmp(v, "delete")) && argc == 3)
			return op_nat_del(p, argv[2]);
		if (!strcmp(v, "flush") && argc == 2) {
			p->h.n_nats = 0;
			return 0;
		}
	} else if (!strcmp(w, "zone")) {
		if (!strcmp(v, "add") && argc > 2)
			return op_zone_add(p, argc - 2, argv + 2);
		if ((!strcmp(v, "del") || !strcmp(v, "delete")) && argc == 3)
			return op_zone_del(p, argv[2]);
	}
	fprintf(stderr, "error: not an editing command\n");
	return 1;
}

/* edit = fetch active policy, apply one command, commit one generation */
static int edit_cmd(int argc, char **argv, const char *what)
{
	struct pol *p = malloc(sizeof(*p));
	uint32_t gen;
	int ret = 1;

	if (!p)
		return 1;
	if (!edit_begin(p, &gen) && !apply_line(p, argc, argv))
		ret = commit_pol(p, gen, what);
	free(p);
	return ret;
}

/* ------------------------------------------------------------ listing */

static int with_active(int (*fn)(const struct pol *p))
{
	struct pol *p = malloc(sizeof(*p));
	uint32_t gen;
	int ret = 1;

	if (p && !load_active(p, &gen))
		ret = fn(p);
	free(p);
	return ret;
}

static int fetch_rule_stats(struct fw_rule_stat **out, uint32_t *n)
{
	struct fw_page_req pr = { 0 };
	struct fw_rule_stat *all = NULL;
	struct fw_rsp_hdr *h;
	void *body;
	uint64_t total = 1;

	*n = 0;
	while (pr.offset < total) {
		if (request(FW_REQ_RULE_STATS, &pr, sizeof(pr), &h, &body)) {
			free(all);
			return -1;
		}
		total = h->total;
		if (!all)
			all = calloc(total ? total : 1, sizeof(*all));
		if (!all || pr.offset + h->count > total) {
			free(h);
			free(all);
			return -1;
		}
		memcpy(all + pr.offset, body, h->count * sizeof(*all));
		pr.offset += h->count;
		if (h->count == 0) {
			free(h);
			break;
		}
		free(h);
	}
	*out = all;
	*n = (uint32_t)pr.offset;
	return 0;
}

static uint64_t stat_for(const struct fw_rule_stat *st, uint32_t n, const char *id, int bytes)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(st[i].id, id))
			return bytes ? st[i].bytes : st[i].flows;
	return 0;
}

static int print_rules(const struct pol *p)
{
	struct fw_rule_stat *st = NULL;
	char src[24], dst[24], sp[16], dp[16];
	uint32_t i, n = 0;

	fetch_rule_stats(&st, &n);
	if (p->h.n_rules == 0) {
		printf("no rules\n");
	} else {
		printf("%-3s %-15s %-18s %-11s %-18s %-11s %-5s %-6s %-3s %-9s %-6s %10s %12s\n",
		       "#", "name", "source", "sport", "destination", "dport", "proto",
		       "action", "log", "scope", "zone", "flows", "bytes");
		for (i = 0; i < p->h.n_rules; i++) {
			const struct fw_rule_spec *r = &p->rules[i];

			fmt_cidr(r->saddr, r->smask, src, sizeof(src));
			fmt_cidr(r->daddr, r->dmask, dst, sizeof(dst));
			if (r->proto == IPPROTO_ICMP) {
				strcpy(sp, "-");
				strcpy(dp, "-");
			} else {
				fmt_ports(r->sport_min, r->sport_max, sp, sizeof(sp));
				fmt_ports(r->dport_min, r->dport_max, dp, sizeof(dp));
			}
			printf("%-3u %-15s %-18s %-11s %-18s %-11s %-5s %-6s %-3s %-9s %-6s %10llu %12llu\n",
			       i, r->id, src, sp, dst, dp, proto_name(r->proto),
			       r->action == FW_ACT_ACCEPT ? "accept" : "drop", r->log ? "yes" : "no",
			       scope_name(r->scope), r->zone ? p->zones[r->zone - 1].name : "-",
			       (unsigned long long)stat_for(st, n, r->id, 0),
			       (unsigned long long)stat_for(st, n, r->id, 1));
		}
		printf("(flows = new flows decided by the rule; later packets of a flow take the stateful path)\n");
	}
	free(st);
	return 0;
}

static int print_zones(const struct pol *p)
{
	char c[24];
	uint32_t i, j;

	if (p->h.n_zones == 0)
		printf("no zones\n");
	for (i = 0; i < p->h.n_zones; i++) {
		printf("%-3u %-15s if %-12s sources", i + 1, p->zones[i].name, p->zones[i].ifname);
		if (!p->zones[i].n_srcs)
			printf(" any");
		for (j = 0; j < p->zones[i].n_srcs; j++) {
			fmt_cidr(p->zones[i].srcs[j].addr, p->zones[i].srcs[j].mask, c, sizeof(c));
			printf(" %s", c);
		}
		printf("\n");
	}
	return 0;
}

static int print_nats(const struct pol *p)
{
	char a[24], b[24], c[24];
	uint32_t i;

	if (p->h.n_nats == 0)
		printf("no NAT rules\n");
	for (i = 0; i < p->h.n_nats; i++) {
		const struct fw_nat_spec *n = &p->nats[i];

		if (n->type == FW_NAT_SNAT) {
			fmt_cidr(n->saddr, n->smask, a, sizeof(a));
			fmt_ip(n->to_addr, b, sizeof(b));
			fmt_ports(n->to_port_min, n->to_port_max, c, sizeof(c));
			printf("%-3u SNAT  %-12s from %-18s -> source %s ports %s%s%s\n",
			       i, n->id, a, b, c, n->out_ifname[0] ? " via " : "", n->out_ifname);
		} else {
			fmt_endpoint(n->daddr, n->dport, n->proto, a, sizeof(a));
			fmt_endpoint(n->to_addr, n->to_port_min, n->proto, b, sizeof(b));
			printf("%-3u DNAT  %-12s %s %-21s -> %s\n", i, n->id, proto_name(n->proto), a, b);
		}
	}
	return 0;
}

static void json_cidr(const char *key, uint32_t a, uint32_t m)
{
	char c[24];

	fmt_cidr(a, m, c, sizeof(c));
	if (m == 0)
		strcpy(c, "0.0.0.0/0");
	else if (!strchr(c, '/'))
		strcat(c, "/32");
	printf("\"%s\": \"%s\"", key, c);
}

static int print_policy_json(const struct pol *p)
{
	char ip[24];
	uint32_t i, j;

	printf("{\"version\": %u, \"default_action\": \"%s\", \"default_log\": %s, \"managed\": %s, "
	       "\"policy_hash\": ", p->h.version, p->h.default_action ? "accept" : "drop",
	       p->h.default_log ? "true" : "false", p->h.flags & FW_POLICY_F_MANAGED ? "true" : "false");
	json_str(stdout, p->h.policy_hash);
	printf(", \"label\": ");
	json_str(stdout, p->h.label);
	printf(", \"zones\": [");
	for (i = 0; i < p->h.n_zones; i++) {
		printf("%s{\"name\": ", i ? ", " : "");
		json_str(stdout, p->zones[i].name);
		printf(", \"interface\": ");
		json_str(stdout, p->zones[i].ifname);
		printf(", \"sources\": [");
		for (j = 0; j < p->zones[i].n_srcs; j++) {
			char c[24];

			fmt_cidr(p->zones[i].srcs[j].addr, p->zones[i].srcs[j].mask, c, sizeof(c));
			printf("%s\"%s%s\"", j ? ", " : "", c, strchr(c, '/') ? "" : "/32");
		}
		printf("]}");
	}
	printf("], \"rules\": [");
	for (i = 0; i < p->h.n_rules; i++) {
		const struct fw_rule_spec *r = &p->rules[i];

		printf("%s{\"id\": ", i ? ", " : "");
		json_str(stdout, r->id);
		printf(", \"scope\": \"%s\", \"zone\": ", scope_name(r->scope));
		if (r->zone)
			json_str(stdout, p->zones[r->zone - 1].name);
		else
			printf("null");
		printf(", ");
		json_cidr("source", r->saddr, r->smask);
		printf(", ");
		json_cidr("destination", r->daddr, r->dmask);
		printf(", \"protocol\": \"%s\", \"source_ports\": [%u, %u], \"destination_ports\": [%u, %u], "
		       "\"action\": \"%s\", \"log\": %s}", proto_name(r->proto), r->sport_min, r->sport_max,
		       r->dport_min, r->dport_max, r->action ? "accept" : "drop", r->log ? "true" : "false");
	}
	printf("], \"nat\": [");
	for (i = 0; i < p->h.n_nats; i++) {
		const struct fw_nat_spec *n = &p->nats[i];

		printf("%s{\"id\": ", i ? ", " : "");
		json_str(stdout, n->id);
		printf(", \"type\": \"%s\", \"zone\": ", n->type == FW_NAT_SNAT ? "snat" : "dnat");
		if (n->zone)
			json_str(stdout, p->zones[n->zone - 1].name);
		else
			printf("null");
		printf(", \"egress_interface\": ");
		json_str(stdout, n->out_ifname);
		printf(", ");
		json_cidr("source", n->saddr, n->smask);
		printf(", ");
		json_cidr("destination", n->daddr, n->dmask);
		fmt_ip(n->to_addr, ip, sizeof(ip));
		printf(", \"protocol\": \"%s\", \"destination_port\": %u, \"to_address\": \"%s\", "
		       "\"to_ports\": [%u, %u]}", proto_name(n->proto), n->dport, ip,
		       n->to_port_min, n->to_port_max);
	}
	printf("]}\n");
	return 0;
}

static int print_policy_text(const struct pol *p)
{
	printf("policy hash %s, label \"%s\"%s\n", p->h.policy_hash, p->h.label,
	       p->h.flags & FW_POLICY_F_MANAGED ? ", managed by fwctl" : "");
	printf("default action %s%s\n\nzones\n", p->h.default_action ? "accept" : "drop",
	       p->h.default_log ? " (logged)" : "");
	print_zones(p);
	printf("\nrules\n");
	print_rules(p);
	printf("\nnat\n");
	return print_nats(p);
}

/* -------------------------------------------------------------- rules */

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
	char ans[9][80], *args[24];
	static const char *q[9][2] = {
		{ "insert after rule (empty = end of chain, ^ = top)", "" },
		{ "rule name", "" },
		{ "source ip/mask", "any" },
		{ "source ports (80, 8000-8100, any)", "any" },
		{ "destination ip/mask", "any" },
		{ "destination ports", "any" },
		{ "protocol (tcp/udp/icmp/any)", "any" },
		{ "action (accept/drop)", "drop" },
		{ "log matching packets (yes/no)", "no" },
	};
	int i, n = 0;

	for (i = 0; i < 9; i++) {
		char buf[80];
		const char *a = ask(q[i][0], q[i][1], buf, sizeof(buf));

		snprintf(ans[i], sizeof(ans[i]), "%s", a);
	}
	args[n++] = "rule";
	args[n++] = "add";
	args[n++] = "--name"; args[n++] = ans[1];
	args[n++] = "--src"; args[n++] = ans[2];
	args[n++] = "--sport"; args[n++] = ans[3];
	args[n++] = "--dst"; args[n++] = ans[4];
	args[n++] = "--dport"; args[n++] = ans[5];
	args[n++] = "--proto"; args[n++] = ans[6];
	args[n++] = "--action"; args[n++] = ans[7];
	if (ans[8][0] == 'y' || ans[8][0] == 'Y' || ans[8][0] == '1')
		args[n++] = "--log";
	if (!strcmp(ans[0], "^"))
		args[n++] = "--head";
	else if (ans[0][0]) {
		args[n++] = "--after";
		args[n++] = ans[0];
	}
	return edit_cmd(n, args, "rule added");
}

static int cmd_rule(int argc, char **argv)
{
	if (argc < 1 || !strcmp(argv[0], "ls") || !strcmp(argv[0], "list"))
		return with_active(print_rules);
	if (!strcmp(argv[0], "add") && argc == 1)
		return cmd_rule_add_interactive();
	if (!strcmp(argv[0], "add"))
		return edit_cmd(argc + 1, argv - 1, "rule added");
	if ((!strcmp(argv[0], "del") || !strcmp(argv[0], "delete"))) {
		if (argc != 2) {
			fprintf(stderr, "usage: uapp rule del NAME\n");
			return 1;
		}
		return edit_cmd(argc + 1, argv - 1, "rule deleted");
	}
	if (!strcmp(argv[0], "flush"))
		return edit_cmd(argc + 1, argv - 1, "rules flushed");
	if (!strcmp(argv[0], "default")) {
		if (argc < 2) {
			fprintf(stderr, "usage: uapp rule default accept|drop [--log]\n");
			return 1;
		}
		return edit_cmd(argc + 1, argv - 1, "default policy set");
	}
	usage(stderr);
	return 1;
}

static int cmd_nat(int argc, char **argv)
{
	if (argc < 1 || !strcmp(argv[0], "ls") || !strcmp(argv[0], "list"))
		return with_active(print_nats);
	if (!strcmp(argv[0], "add"))
		return edit_cmd(argc + 1, argv - 1, "NAT rule added");
	if (!strcmp(argv[0], "del") || !strcmp(argv[0], "delete")) {
		if (argc != 2) {
			fprintf(stderr, "usage: uapp nat del SEQ\n");
			return 1;
		}
		return edit_cmd(argc + 1, argv - 1, "NAT rule deleted");
	}
	if (!strcmp(argv[0], "flush"))
		return edit_cmd(argc + 1, argv - 1, "NAT rules flushed");
	usage(stderr);
	return 1;
}

static int cmd_zone(int argc, char **argv)
{
	if (argc < 1 || !strcmp(argv[0], "ls") || !strcmp(argv[0], "list"))
		return with_active(print_zones);
	if (!strcmp(argv[0], "add"))
		return edit_cmd(argc + 1, argv - 1, "zone added");
	if ((!strcmp(argv[0], "del") || !strcmp(argv[0], "delete")) && argc == 2)
		return edit_cmd(argc + 1, argv - 1, "zone deleted");
	usage(stderr);
	return 1;
}

/* ------------------------------------------------------ events / log */

static int fetch_events(uint64_t since, struct fw_event **out, uint32_t *n,
			uint64_t *first, uint64_t *next, uint64_t *lost)
{
	struct fw_page_req pr = { .offset = since };
	struct fw_event *all = NULL;
	struct fw_rsp_hdr *h;
	void *body;
	uint32_t cnt = 0;
	int first_page = 1;

	for (;;) {
		struct fw_event *tmp;

		if (request(FW_REQ_GET_EVENTS, &pr, sizeof(pr), &h, &body)) {
			free(all);
			return -1;
		}
		if (first_page) {
			*first = h->a;
			*lost = h->c;
			first_page = 0;
		}
		*next = h->b;
		tmp = realloc(all, (cnt + h->count + 1) * sizeof(*all));
		if (!tmp) {
			free(h);
			free(all);
			return -1;
		}
		all = tmp;
		memcpy(all + cnt, body, h->count * sizeof(*all));
		cnt += h->count;
		if (h->count == 0 || h->b <= all[cnt - 1].seq + 1) {
			free(h);
			break;
		}
		pr.offset = all[cnt - 1].seq + 1;
		free(h);
	}
	*out = all;
	*n = cnt;
	return 0;
}

static void fmt_time(int64_t ns, char *buf, size_t n)
{
	time_t t = (time_t)(ns / 1000000000LL);
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm);
}

static int cmd_events(int argc, char **argv)
{
	struct fw_event *ev;
	uint64_t since = 0, first, next, lost;
	uint32_t n, i, max = 0;
	char a[32], b[32], t[32];

	for (i = 0; i + 1 < (uint32_t)argc; i += 2) {
		uint32_t v;

		if (parse_u32(argv[i + 1], &v))
			return bad("number", argv[i + 1]);
		if (!strcmp(argv[i], "--since"))
			since = v;
		else if (!strcmp(argv[i], "--max"))
			max = v;
		else
			return bad("option", argv[i]);
	}
	if (fetch_events(since, &ev, &n, &first, &next, &lost))
		return 1;
	if (max && n > max)
		n = max;
	if (g_json) {
		printf("{\"first_seq\": %llu, \"next_seq\": %llu, \"lost\": %llu, \"events\": [",
		       (unsigned long long)first, (unsigned long long)next, (unsigned long long)lost);
		for (i = 0; i < n; i++) {
			const struct fw_event *e = &ev[i];

			fmt_ip(e->saddr, a, sizeof(a));
			fmt_ip(e->daddr, b, sizeof(b));
			printf("%s{\"seq\": %llu, \"ts_ns\": %lld, \"generation\": %u, \"kind\": \"%s\", "
			       "\"src\": \"%s\", \"dst\": \"%s\", \"sport\": %u, \"dport\": %u, \"proto\": \"%s\", "
			       "\"verdict\": \"%s\", \"reason\": \"%s\", \"zone_slot\": %u, \"len\": %u, "
			       "\"ifindex\": %d, \"ref\": ", i ? ", " : "", (unsigned long long)e->seq,
			       (long long)e->ts_ns, e->generation,
			       e->kind == FW_EV_PACKET ? "packet" : e->kind == FW_EV_COMMIT ? "commit" :
			       e->kind == FW_EV_STAGE_ABORT ? "stage_abort" : "commit_rejected",
			       a, b, e->sport, e->dport, proto_name(e->proto),
			       e->verdict == FW_ACT_ACCEPT ? "accept" : "drop", reason_name(e->reason),
			       e->zone, e->len, e->ifindex);
			json_str(stdout, e->rule_id);
			printf("}");
		}
		printf("]}\n");
	} else {
		if (lost)
			printf("(%llu event(s) before seq %llu were overwritten)\n",
			       (unsigned long long)lost, (unsigned long long)first);
		for (i = 0; i < n; i++) {
			const struct fw_event *e = &ev[i];

			fmt_time(e->ts_ns, t, sizeof(t));
			if (e->kind != FW_EV_PACKET) {
				printf("%6llu [%s] %-16s gen %u %s\n", (unsigned long long)e->seq, t,
				       e->kind == FW_EV_COMMIT ? "COMMIT" : e->kind == FW_EV_STAGE_ABORT ?
				       "STAGE-ABORT" : "COMMIT-REJECTED", e->generation, e->rule_id);
				continue;
			}
			fmt_endpoint(e->saddr, e->sport, e->proto, a, sizeof(a));
			fmt_endpoint(e->daddr, e->dport, e->proto, b, sizeof(b));
			printf("%6llu [%s] %-6s %-4s %21s -> %-21s reason=%s %s\n",
			       (unsigned long long)e->seq, t, e->verdict ? "ACCEPT" : "DROP",
			       proto_name(e->proto), a, b, reason_name(e->reason), e->rule_id);
		}
	}
	free(ev);
	return 0;
}

static uint64_t read_mark(void)
{
	FILE *f = fopen(LOG_MARK, "r");
	unsigned long long m = 0;

	if (f) {
		if (fscanf(f, "%llu", &m) != 1)
			m = 0;
		fclose(f);
	}
	return m;
}

static int cmd_log(int argc, char **argv)
{
	struct fw_event *ev;
	uint64_t first, next, lost;
	uint32_t n, i, shown = 0, want = 0, start = 0, npk = 0;
	char tbuf[32], src[32], dst[32];

	if (argc > 0 && !strcmp(argv[0], "clear")) {
		struct fw_rsp_hdr *h;
		struct fw_status *s;
		FILE *f;

		if (request(FW_REQ_STATUS, NULL, 0, &h, (void **)&s))
			return 1;
		mkdir(LOG_MARK_DIR, 0755);
		f = fopen(LOG_MARK, "w");
		if (!f) {
			perror(LOG_MARK);
			free(h);
			return 1;
		}
		fprintf(f, "%llu\n", (unsigned long long)s->event_next_seq);
		fclose(f);
		printf("log cleared (events before seq %llu are hidden from 'uapp log')\n",
		       (unsigned long long)s->event_next_seq);
		free(h);
		return 0;
	}
	if (argc > 0 && (!strcmp(argv[0], "ls") || !strcmp(argv[0], "list")))
		argc--, argv++;
	if (argc > 0 && parse_u32(argv[0], &want))
		return bad("count", argv[0]);
	if (fetch_events(read_mark(), &ev, &n, &first, &next, &lost))
		return 1;
	for (i = 0; i < n; i++)
		npk += ev[i].kind == FW_EV_PACKET;
	if (want && npk > want)
		start = npk - want;
	for (i = 0; i < n; i++) {
		const struct fw_event *e = &ev[i];

		if (e->kind != FW_EV_PACKET || start-- > 0)
			continue;
		start = 0;
		fmt_time(e->ts_ns, tbuf, sizeof(tbuf));
		fmt_endpoint(e->saddr, e->sport, e->proto, src, sizeof(src));
		fmt_endpoint(e->daddr, e->dport, e->proto, dst, sizeof(dst));
		printf("[%s] %-6s %-4s %21s -> %-21s len=%-5u ", tbuf,
		       e->verdict == FW_ACT_ACCEPT ? "ACCEPT" : "DROP",
		       proto_name(e->proto), src, dst, e->len);
		if (e->reason == FW_R_DEFAULT || (e->verdict && !e->rule_id[0]))
			printf("(default policy)\n");
		else if (e->reason == FW_R_RULE || e->verdict)
			printf("rule=%s\n", e->rule_id);
		else
			printf("reason=%s %s\n", reason_name(e->reason), e->rule_id);
		shown++;
	}
	if (!shown)
		printf("no log entries\n");
	free(ev);
	return 0;
}

/* --------------------------------------------------------------- conns */

static int cmd_conn(int argc, char **argv)
{
	struct fw_page_req pr = { 0 };
	struct fw_rsp_hdr *h;
	struct fw_conn_info *c;
	uint64_t total = 1, shown = 0;
	char a[32], b[32], ra[32], rb[32];
	uint32_t i;

	if (argc > 0 && !strcmp(argv[0], "flush")) {
		if (request(FW_REQ_FLUSH_CONNS, NULL, 0, &h, (void **)&c))
			return 1;
		printf("%u flow(s) flushed\n", h->count);
		free(h);
		return 0;
	}
	if (g_json)
		printf("{\"flows\": [");
	while (pr.offset < total) {
		if (request(FW_REQ_GET_CONNS, &pr, sizeof(pr), &h, (void **)&c))
			return 1;
		total = h->total;
		if (!g_json && pr.offset == 0) {
			if (h->count == 0) {
				printf("no connections\n");
				free(h);
				return 0;
			}
			printf("%-5s %-45s %-5s %-8s %s\n", "proto", "original direction", "nat",
			       "expires", "packets (orig/reply)");
		}
		for (i = 0; i < h->count; i++) {
			char flow[80];

			fmt_endpoint(c[i].saddr, c[i].sport, c[i].proto, a, sizeof(a));
			fmt_endpoint(c[i].daddr, c[i].dport, c[i].proto, b, sizeof(b));
			fmt_endpoint(c[i].r_saddr, c[i].r_sport, c[i].proto, ra, sizeof(ra));
			fmt_endpoint(c[i].r_daddr, c[i].r_dport, c[i].proto, rb, sizeof(rb));
			if (g_json) {
				printf("%s{\"proto\": \"%s\", \"orig\": \"%s -> %s\", \"reply\": \"%s -> %s\", "
				       "\"nat\": \"%s\", \"expires_in\": %u, \"generation\": %u, "
				       "\"in_if\": [%d, %d], \"pkts\": [%llu, %llu], \"bytes\": [%llu, %llu], "
				       "\"rule\": ", shown ? ", " : "", proto_name(c[i].proto), a, b, ra, rb,
				       c[i].nat_type == FW_NAT_SNAT ? "snat" : c[i].nat_type == FW_NAT_DNAT ? "dnat" : "none",
				       c[i].expires_in, c[i].generation, c[i].in_if[0], c[i].in_if[1],
				       (unsigned long long)c[i].pkts[0], (unsigned long long)c[i].pkts[1],
				       (unsigned long long)c[i].bytes[0], (unsigned long long)c[i].bytes[1]);
				json_str(stdout, c[i].rule_id);
				printf("}");
			} else {
				snprintf(flow, sizeof(flow), "%s -> %s", a, b);
				printf("%-5s %-45s %-5s %6us   %llu/%llu\n", proto_name(c[i].proto), flow,
				       c[i].nat_type == FW_NAT_SNAT ? "SNAT" : c[i].nat_type == FW_NAT_DNAT ? "DNAT" : "-",
				       c[i].expires_in, (unsigned long long)c[i].pkts[0],
				       (unsigned long long)c[i].pkts[1]);
				if (c[i].nat_type != FW_NAT_NONE)
					printf("      reply: %s -> %s\n", ra, rb);
			}
			shown++;
		}
		pr.offset += h->count;
		if (h->count == 0)
			pr.offset = total;
		free(h);
	}
	if (g_json)
		printf("], \"total\": %llu, \"consistency\": \"pages taken at different instants\"}\n",
		       (unsigned long long)total);
	else
		printf("%llu connection(s)\n", (unsigned long long)shown);
	return 0;
}

/* ------------------------------------------------------------- policy */

static int read_file(const char *path, uint8_t **buf, size_t *len)
{
	FILE *f = fopen(path, "rb");
	long sz;

	if (!f) {
		perror(path);
		return -1;
	}
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	rewind(f);
	if (sz < 0 || sz > FW_MAX_POLICY_BYTES) {
		fprintf(stderr, "error: %s: size %ld out of range\n", path, sz);
		fclose(f);
		return -1;
	}
	*buf = malloc(sz ? (size_t)sz : 1);
	if (!*buf || fread(*buf, 1, (size_t)sz, f) != (size_t)sz) {
		fprintf(stderr, "error: cannot read %s\n", path);
		fclose(f);
		free(*buf);
		return -1;
	}
	fclose(f);
	*len = (size_t)sz;
	return 0;
}

static int cmd_policy(int argc, char **argv)
{
	if (argc < 1 || !strcmp(argv[0], "show"))
		return with_active(g_json ? print_policy_json : print_policy_text);

	if (!strcmp(argv[0], "export") && argc == 2) {
		uint8_t *blob;
		size_t len;
		uint32_t gen;
		FILE *f;
		int ret;

		if (session())
			return 1;
		ret = fw_fetch_policy(&g_nl, &blob, &len, &gen);
		if (ret) {
			fprintf(stderr, "error: %s\n", ret == -EBADMSG ?
				"export incomplete or corrupted (SHA-256 mismatch)" : fw_strerror(ret));
			return 1;
		}
		f = fopen(argv[1], "wb");
		if (!f || fwrite(blob, 1, len, f) != len || fclose(f)) {
			perror(argv[1]);
			free(blob);
			return 1;
		}
		printf("exported generation %u (%zu bytes, complete)\n", gen, len);
		free(blob);
		return 0;
	}

	if (!strcmp(argv[0], "apply") && argc >= 2) {
		struct apply_opts o = { .stop_after_chunks = -1 };
		struct fw_commit_result res;
		char err[128];
		uint8_t *blob;
		size_t len;
		int i, have_gen = 0, ret;

		for (i = 2; i < argc; i++) {
			const char *v = i + 1 < argc ? argv[i + 1] : NULL;
			uint32_t x;

			if (!strcmp(argv[i], "--validate-only")) {
				o.validate_only = 1;
				continue;
			}
			if (!v || (strcmp(v, "current") && parse_u32(v, &x)))
				return bad("option value for", argv[i]);
			if (!strcmp(argv[i], "--expected-gen")) {
				if (!strcmp(v, "current")) {
					struct fw_rsp_hdr *h;
					struct fw_status *s;

					if (request(FW_REQ_STATUS, NULL, 0, &h, (void **)&s))
						return 1;
					x = s->generation;
					free(h);
				}
				o.expected_gen = x;
				have_gen = 1;
			} else if (!strcmp(argv[i], "--debug-stop-after-chunks")) {
				o.stop_after_chunks = (int)x;
			} else if (!strcmp(argv[i], "--debug-hold")) {
				o.hold_seconds = (int)x;
			} else if (!strcmp(argv[i], "--chunk-size")) {
				o.chunk_size = (int)x;
			} else {
				return bad("option", argv[i]);
			}
			i++;
		}
		if (!have_gen && !o.validate_only) {
			fprintf(stderr, "error: --expected-gen N|current is required\n");
			return 1;
		}
		if (read_file(argv[1], &blob, &len) || session())
			return 1;
		ret = fw_apply_blob(&g_nl, blob, len, &o, &res, err, sizeof(err));
		free(blob);
		if (g_json) {
			if (ret)
				printf("{\"ok\": false, \"errno\": %d, \"error\": ", -ret);
			else if (o.validate_only)
				printf("{\"ok\": true, \"validated\": true, \"committed\": false");
			else
				printf("{\"ok\": true, \"committed\": true, \"generation\": %u, \"gate_ns\": %llu, "
				       "\"flows_reset\": %llu, \"policy_hash\": ", res.generation,
				       (unsigned long long)res.gate_ns, (unsigned long long)res.flows_reset);
			if (ret)
				json_str(stdout, err);
			else if (!o.validate_only)
				json_str(stdout, res.policy_hash);
			printf("}\n");
		} else if (ret) {
			fprintf(stderr, "error: %s\n", err);
		} else if (o.validate_only) {
			printf("%s\n", err);
		} else {
			printf("committed generation %u (gate %.3f ms, %llu flow(s) reset)\n",
			       res.generation, res.gate_ns / 1e6, (unsigned long long)res.flows_reset);
		}
		return ret ? (ret == -ESTALE ? 3 : 2) : 0;
	}
	usage(stderr);
	return 1;
}

/* --------------------------------------------------------- save / load */

static void save_pol(const struct pol *p, FILE *f)
{
	char a[32], b[32], c[32], d[32];
	time_t now = time(NULL);
	uint32_t i, j;

	fprintf(f, "# myfw ruleset saved %s", ctime(&now));
	for (i = 0; i < p->h.n_zones; i++) {
		fprintf(f, "zone add --name %s --if %s", p->zones[i].name, p->zones[i].ifname);
		for (j = 0; j < p->zones[i].n_srcs; j++) {
			fmt_cidr(p->zones[i].srcs[j].addr, p->zones[i].srcs[j].mask, a, sizeof(a));
			fprintf(f, " --src %s", a);
		}
		fprintf(f, "\n");
	}
	fprintf(f, "rule default %s%s\n", p->h.default_action == FW_ACT_ACCEPT ? "accept" : "drop",
		p->h.default_log ? " --log" : "");
	for (i = 0; i < p->h.n_rules; i++) {
		const struct fw_rule_spec *r = &p->rules[i];

		fmt_cidr(r->saddr, r->smask, a, sizeof(a));
		fmt_cidr(r->daddr, r->dmask, b, sizeof(b));
		fmt_ports(r->sport_min, r->sport_max, c, sizeof(c));
		fmt_ports(r->dport_min, r->dport_max, d, sizeof(d));
		fprintf(f, "rule add --name %s --src %s --dst %s --sport %s --dport %s --proto %s --action %s%s",
			r->id, a, b, c, d, proto_name(r->proto),
			r->action == FW_ACT_ACCEPT ? "accept" : "drop", r->log ? " --log" : "");
		if (r->scope != FW_SCOPE_ANY)
			fprintf(f, " --scope %s", scope_name(r->scope));
		if (r->zone)
			fprintf(f, " --zone %s", p->zones[r->zone - 1].name);
		fprintf(f, "\n");
	}
	for (i = 0; i < p->h.n_nats; i++) {
		const struct fw_nat_spec *n = &p->nats[i];

		if (n->type == FW_NAT_SNAT) {
			fmt_cidr(n->saddr, n->smask, a, sizeof(a));
			fmt_ip(n->to_addr, b, sizeof(b));
			fmt_ports(n->to_port_min, n->to_port_max, c, sizeof(c));
			fprintf(f, "nat add --type snat --id %s --src %s --to %s --ports %s", n->id, a, b, c);
			if (n->dmask) {
				fmt_cidr(n->daddr, n->dmask, d, sizeof(d));
				fprintf(f, " --dst %s", d);
			}
			if (n->proto)
				fprintf(f, " --proto %s", proto_name(n->proto));
		} else {
			fmt_ip(n->daddr, a, sizeof(a));
			fmt_ip(n->to_addr, b, sizeof(b));
			fprintf(f, "nat add --type dnat --id %s --dst %s --dport %u --proto %s --to %s:%u",
				n->id, a, n->dport, proto_name(n->proto), b, n->to_port_min);
		}
		if (n->zone)
			fprintf(f, " --zone %s", p->zones[n->zone - 1].name);
		if (n->out_ifname[0])
			fprintf(f, " --out %s", n->out_ifname);
		fprintf(f, "\n");
	}
}

static int cmd_save(int argc, char **argv)
{
	struct pol *p = malloc(sizeof(*p));
	uint32_t gen;
	FILE *f = stdout;

	if (!p || load_active(p, &gen)) {
		free(p);
		return 1;
	}
	if (argc > 0 && !(f = fopen(argv[0], "w"))) {
		perror(argv[0]);
		free(p);
		return 1;
	}
	save_pol(p, f);
	if (f != stdout) {
		fclose(f);
		printf("saved %u zone(s), %u rule(s) and %u NAT rule(s) of generation %u to %s\n",
		       p->h.n_zones, p->h.n_rules, p->h.n_nats, gen, argv[0]);
	}
	free(p);
	return 0;
}

/* All-or-nothing: every line is applied to an in-memory copy; only if all
 * of them succeed is the result committed, as one generation. */
static int cmd_load(int argc, char **argv)
{
	struct pol *p = malloc(sizeof(*p)), *cur = malloc(sizeof(*cur));
	char line[1024];
	uint32_t gen;
	FILE *f;
	int lineno = 0, ok = 0, ret = 1;

	if (argc < 1) {
		fprintf(stderr, "usage: uapp load FILE\n");
		goto out;
	}
	if (!p || !cur || edit_begin(cur, &gen))
		goto out;
	if (!(f = fopen(argv[0], "r"))) {
		perror(argv[0]);
		goto out;
	}
	pol_init(p, FW_ACT_ACCEPT);
	while (fgets(line, sizeof(line), f)) {
		char *args[MAX_ARGS], *tok, *save;
		int n = 0;

		lineno++;
		line[strcspn(line, "\r\n")] = '\0';
		for (tok = strtok_r(line, " \t", &save); tok && n < MAX_ARGS; tok = strtok_r(NULL, " \t", &save))
			args[n++] = tok;
		if (n == 0 || args[0][0] == '#')
			continue;
		if (apply_line(p, n, args)) {
			fprintf(stderr, "%s:%d: rejected; nothing was changed\n", argv[0], lineno);
			fclose(f);
			goto out;
		}
		ok++;
	}
	fclose(f);
	ret = commit_pol(p, gen, "ruleset loaded");
	if (!ret)
		printf("loaded %d command(s) from %s as one generation\n", ok, argv[0]);
out:
	free(p);
	free(cur);
	return ret;
}

/* ------------------------------------------------------------------ */

static int dispatch(int argc, char **argv)
{
	const char *c = argv[0];

	if (!strcmp(c, "status"))
		return cmd_status();
	if (!strcmp(c, "counters"))
		return cmd_counters();
	if (!strcmp(c, "abi"))
		return cmd_abi();
	if (!strcmp(c, "policy"))
		return cmd_policy(argc - 1, argv + 1);
	if (!strcmp(c, "events"))
		return cmd_events(argc - 1, argv + 1);
	if (!strcmp(c, "rule") || !strcmp(c, "r"))
		return cmd_rule(argc - 1, argv + 1);
	if (!strcmp(c, "nat") || !strcmp(c, "n"))
		return cmd_nat(argc - 1, argv + 1);
	if (!strcmp(c, "zone"))
		return cmd_zone(argc - 1, argv + 1);
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

		if (w[0] == 'r') return with_active(print_rules);
		if (w[0] == 'n') return with_active(print_nats);
		if (w[0] == 'z') return with_active(print_zones);
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
	char *args[MAX_ARGS];
	int i, n = 0, ret;

	for (i = 1; i < argc && n < MAX_ARGS; i++) {
		if (!strcmp(argv[i], "--force-legacy"))
			g_force_legacy = 1;
		else if (!strcmp(argv[i], "--json"))
			g_json = 1;
		else
			args[n++] = argv[i];
	}
	if (n < 1) {
		usage(stderr);
		return 1;
	}
	ret = dispatch(n, args);
	fw_close(&g_nl);
	return ret;
}
