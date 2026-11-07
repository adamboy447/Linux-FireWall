/* Decode a policy blob with uapp's own decoder and print it as JSON, so the
 * Python encoder is checked against the C structures byte for byte. Also
 * prints sizeof/offsetof of the blob structures. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "uapp.h"

int main(int argc, char **argv)
{
	static uint8_t buf[FW_MAX_POLICY_BYTES + 1];
	struct pol p;
	char err[128];
	size_t n;
	uint32_t i;
	FILE *f;

	if (argc > 1 && !strcmp(argv[1], "--layout")) {
		printf("{\"fw_policy_hdr\": %zu, \"fw_zone_spec\": %zu, \"fw_rule_spec\": %zu, \"fw_nat_spec\": %zu,"
		       " \"rule.scope\": %zu, \"rule.log\": %zu, \"nat.type\": %zu, \"nat.to_addr\": %zu,"
		       " \"hdr.policy_hash\": %zu, \"zone.srcs\": %zu}\n",
		       sizeof(struct fw_policy_hdr), sizeof(struct fw_zone_spec), sizeof(struct fw_rule_spec),
		       sizeof(struct fw_nat_spec), offsetof(struct fw_rule_spec, scope),
		       offsetof(struct fw_rule_spec, log), offsetof(struct fw_nat_spec, type),
		       offsetof(struct fw_nat_spec, to_addr), offsetof(struct fw_policy_hdr, policy_hash),
		       offsetof(struct fw_zone_spec, srcs));
		return 0;
	}
	f = fopen(argv[1], "rb");
	if (!f)
		return 2;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (pol_decode(buf, n, &p, err, sizeof(err))) {
		printf("{\"error\": \"%s\"}\n", err);
		return 1;
	}
	printf("{\"default_action\": %u, \"flags\": %u, \"hash\": \"%s\", \"label\": \"%s\", \"zones\": [",
	       p.h.default_action, p.h.flags, p.h.policy_hash, p.h.label);
	for (i = 0; i < p.h.n_zones; i++)
		printf("%s{\"name\": \"%s\", \"if\": \"%s\", \"n_srcs\": %u, \"src0\": [%u, %u]}", i ? ", " : "",
		       p.zones[i].name, p.zones[i].ifname, p.zones[i].n_srcs, p.zones[i].srcs[0].addr,
		       p.zones[i].srcs[0].mask);
	printf("], \"rules\": [");
	for (i = 0; i < p.h.n_rules; i++) {
		struct fw_rule_spec *r = &p.rules[i];

		printf("%s{\"id\": \"%s\", \"s\": [%u, %u], \"d\": [%u, %u], \"sp\": [%u, %u], \"dp\": [%u, %u], "
		       "\"scope\": %u, \"zone\": %u, \"proto\": %u, \"action\": %u, \"log\": %u}", i ? ", " : "",
		       r->id, r->saddr, r->smask, r->daddr, r->dmask, r->sport_min, r->sport_max,
		       r->dport_min, r->dport_max, r->scope, r->zone, r->proto, r->action, r->log);
	}
	printf("], \"nats\": [");
	for (i = 0; i < p.h.n_nats; i++) {
		struct fw_nat_spec *x = &p.nats[i];

		printf("%s{\"id\": \"%s\", \"out\": \"%s\", \"type\": %u, \"proto\": %u, \"zone\": %u, "
		       "\"d\": [%u, %u], \"dport\": %u, \"to\": %u, \"tp\": [%u, %u]}", i ? ", " : "",
		       x->id, x->out_ifname, x->type, x->proto, x->zone, x->daddr, x->dmask, x->dport,
		       x->to_addr, x->to_port_min, x->to_port_max);
	}
	printf("]}\n");
	return 0;
}
