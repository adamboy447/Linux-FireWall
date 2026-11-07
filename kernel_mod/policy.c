/*
 * policy.c - immutable policy snapshots.
 *
 * A snapshot is built from a staged blob (see fw_proto.h) and never modified
 * afterwards, except for its statistics counters. The packet path reads the
 * active snapshot under RCU (netfilter hooks already run inside an RCU
 * read-side section); stage.c replaces it with rcu_replace_pointer() and
 * frees the old one only after synchronize_rcu().
 *
 * The kernel re-validates every field even though fwctl validated the
 * policy first: user space is not trusted to produce well-formed input.
 */
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>
#include <net/net_namespace.h>
#include <crypto/sha2.h>
#include "fw.h"

struct fw_snap __rcu *fw_active;
int fw_gate;
DEFINE_MUTEX(fw_cfg_mutex);

bool fw_ip_match(u32 ip, u32 net, u32 mask)
{
	return (ip & mask) == (net & mask);
}

int fw_zone_of(const struct fw_snap *s, int ifindex)
{
	u32 i;

	for (i = 0; i < s->nz; i++)
		if (s->zones[i].ifindex == ifindex)
			return i + 1;
	return 0;
}

void fw_snap_free(struct fw_snap *s)
{
	if (!s)
		return;
	kvfree(s->rules);
	kvfree(s->nats);
	kvfree(s->blob);
	kfree(s);
}

static void hexify(const u8 *in, size_t n, char *out)
{
	static const char hx[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = hx[in[i] >> 4];
		out[2 * i + 1] = hx[in[i] & 15];
	}
	out[2 * n] = '\0';
}

#define ERR(...) do { snprintf(err, errlen, __VA_ARGS__); goto bad; } while (0)

/* NUL-terminated, non-empty, [A-Za-z0-9._:-] only */
static bool valid_id(const char *s, size_t cap)
{
	size_t n = strnlen(s, cap);

	if (n == 0 || n == cap)
		return false;
	while (*s) {
		if (!isalnum(*s) && *s != '.' && *s != '_' && *s != '-' && *s != ':')
			return false;
		s++;
	}
	return true;
}

static bool valid_text(const char *s, size_t cap)
{
	size_t n = strnlen(s, cap);

	if (n == cap)
		return false;
	while (*s) {
		if (*s < 0x20 || *s > 0x7e)
			return false;
		s++;
	}
	return true;
}

static bool valid_mask(u32 m)
{
	/* a prefix mask: ones followed by zeros */
	return (m | (m - 1)) == 0xffffffffu || m == 0;
}

static int resolve_if(const char *name)
{
	struct net_device *dev;
	int idx = 0;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(&init_net, name);
	if (dev)
		idx = dev->ifindex;
	rcu_read_unlock();
	return idx;
}

static struct fw_snap *snap_alloc(u32 nr, u32 nn)
{
	struct fw_snap *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		return NULL;
	if (nr) {
		s->rules = kvcalloc(nr, sizeof(*s->rules), GFP_KERNEL);
		if (!s->rules)
			goto oom;
	}
	if (nn) {
		s->nats = kvcalloc(nn, sizeof(*s->nats), GFP_KERNEL);
		if (!s->nats)
			goto oom;
	}
	return s;
oom:
	fw_snap_free(s);
	return NULL;
}

struct fw_snap *fw_snap_build(const u8 *blob, u32 len, char *err, size_t errlen)
{
	const struct fw_policy_hdr *h = (const void *)blob;
	const struct fw_zone_spec *zs;
	const struct fw_rule_spec *rs;
	const struct fw_nat_spec *ns;
	struct fw_snap *s = NULL;
	u8 digest[SHA256_DIGEST_SIZE];
	size_t need;
	u32 i, j;

	if (len < sizeof(*h))
		ERR("blob shorter than the header");
	if (h->magic != FW_POLICY_MAGIC)
		ERR("bad magic");
	if (h->version != FW_UAPI_VERSION)
		ERR("policy version %u, module speaks %u", h->version, FW_UAPI_VERSION);
	if (h->n_zones > FW_MAX_ZONES || h->n_rules > FW_MAX_RULES || h->n_nats > FW_MAX_NATS)
		ERR("too many entries (limits: %u zones, %u rules, %u nat)",
		    FW_MAX_ZONES, FW_MAX_RULES, FW_MAX_NATS);
	need = sizeof(*h) + h->n_zones * sizeof(*zs) + h->n_rules * sizeof(*rs) +
	       h->n_nats * sizeof(*ns);
	if (len != need)
		ERR("blob is %u bytes, header says %zu", len, need);
	if (h->default_action > FW_ACT_ACCEPT || h->default_log > 1)
		ERR("bad default action");
	if (h->flags & ~(FW_POLICY_F_MANAGED | FW_POLICY_F_LEGACY))
		ERR("unknown policy flags");
	if (!valid_text(h->policy_hash, sizeof(h->policy_hash)) ||
	    !valid_text(h->label, sizeof(h->label)))
		ERR("policy hash / label not printable text");

	if (fw_debug_fail_stage_alloc) {
		fw_debug_fail_stage_alloc--;
		ERR("allocation failed (debug_fail_stage_alloc)");
	}
	s = snap_alloc(h->n_rules, h->n_nats);
	if (!s)
		ERR("out of memory");
	s->blob = kvmalloc(len, GFP_KERNEL);
	if (!s->blob)
		ERR("out of memory");
	memcpy(s->blob, blob, len);
	s->blob_len = len;
	sha256(blob, len, digest);
	hexify(digest, sizeof(digest), s->blob_sha);

	s->default_action = h->default_action;
	s->default_log = h->default_log;
	s->flags = h->flags;
	s->nz = h->n_zones;
	s->nr = h->n_rules;
	s->nn = h->n_nats;
	strscpy(s->policy_hash, h->policy_hash, sizeof(s->policy_hash));
	strscpy(s->label, h->label, sizeof(s->label));

	zs = (const void *)(h + 1);
	for (i = 0; i < s->nz; i++) {
		const struct fw_zone_spec *z = &zs[i];
		struct fw_zone_k *k = &s->zones[i];

		if (!valid_id(z->name, sizeof(z->name)))
			ERR("zone %u: bad name", i);
		if (strnlen(z->ifname, sizeof(z->ifname)) == 0 ||
		    strnlen(z->ifname, sizeof(z->ifname)) == sizeof(z->ifname))
			ERR("zone %s: bad interface name", z->name);
		if (z->n_srcs > FW_MAX_ZONE_SRCS || z->flags)
			ERR("zone %s: bad source list", z->name);
		k->ifindex = resolve_if(z->ifname);
		if (!k->ifindex)
			ERR("zone %s: interface %s does not exist", z->name, z->ifname);
		for (j = 0; j < i; j++) {
			if (!strcmp(s->zones[j].name, z->name))
				ERR("duplicate zone %s", z->name);
			if (s->zones[j].ifindex == k->ifindex)
				ERR("zones %s and %s use the same interface", s->zones[j].name, z->name);
		}
		for (j = 0; j < z->n_srcs; j++) {
			if (!valid_mask(z->srcs[j].mask) || (z->srcs[j].addr & ~z->srcs[j].mask))
				ERR("zone %s: source %u is not a valid CIDR", z->name, j);
			k->srcs[j] = z->srcs[j];
		}
		strscpy(k->name, z->name, sizeof(k->name));
		strscpy(k->ifname, z->ifname, sizeof(k->ifname));
		k->n_srcs = z->n_srcs;
	}

	rs = (const void *)(zs + s->nz);
	for (i = 0; i < s->nr; i++) {
		const struct fw_rule_spec *r = &rs[i];

		if (!valid_id(r->id, sizeof(r->id)))
			ERR("rule %u: bad id", i);
		for (j = 0; j < i; j++)
			if (!strcmp(s->rules[j].s.id, r->id))
				ERR("duplicate rule id %s", r->id);
		if (!valid_mask(r->smask) || !valid_mask(r->dmask) ||
		    (r->saddr & ~r->smask) || (r->daddr & ~r->dmask))
			ERR("rule %s: address is not a valid CIDR", r->id);
		if (r->sport_min > r->sport_max || r->dport_min > r->dport_max)
			ERR("rule %s: reversed port range", r->id);
		if (r->proto != 0 && r->proto != IPPROTO_TCP && r->proto != IPPROTO_UDP &&
		    r->proto != IPPROTO_ICMP)
			ERR("rule %s: unsupported protocol %u", r->id, r->proto);
		if (r->scope > FW_SCOPE_LOCAL_OUT || r->action > FW_ACT_ACCEPT || r->log > 1)
			ERR("rule %s: bad scope/action/log", r->id);
		if (r->zone > s->nz)
			ERR("rule %s: zone %u does not exist", r->id, r->zone);
		if (r->zone && r->scope == FW_SCOPE_LOCAL_OUT)
			ERR("rule %s: local_out rules cannot name an ingress zone", r->id);
		if (r->pad[0] || r->pad[1] || r->pad[2])
			ERR("rule %s: padding not zero", r->id);
		s->rules[i].s = *r;
	}

	ns = (const void *)(rs + s->nr);
	for (i = 0; i < s->nn; i++) {
		const struct fw_nat_spec *n = &ns[i];
		struct fw_nat_k *k = &s->nats[i];

		if (!valid_id(n->id, sizeof(n->id)))
			ERR("nat %u: bad id", i);
		for (j = 0; j < i; j++)
			if (!strcmp(s->nats[j].s.id, n->id))
				ERR("duplicate nat id %s", n->id);
		if (!valid_mask(n->smask) || !valid_mask(n->dmask) ||
		    (n->saddr & ~n->smask) || (n->daddr & ~n->dmask))
			ERR("nat %s: address is not a valid CIDR", n->id);
		if (n->zone > s->nz)
			ERR("nat %s: zone %u does not exist", n->id, n->zone);
		if (!n->to_addr)
			ERR("nat %s: missing target address", n->id);
		if (strnlen(n->out_ifname, sizeof(n->out_ifname)) == sizeof(n->out_ifname))
			ERR("nat %s: bad egress interface", n->id);
		if (n->type == FW_NAT_SNAT) {
			if (!n->to_port_min || n->to_port_min > n->to_port_max)
				ERR("nat %s: bad SNAT port range", n->id);
			if (n->proto && n->proto != IPPROTO_TCP && n->proto != IPPROTO_UDP &&
			    n->proto != IPPROTO_ICMP)
				ERR("nat %s: unsupported protocol", n->id);
			if (n->dport)
				ERR("nat %s: SNAT takes no destination port", n->id);
		} else if (n->type == FW_NAT_DNAT) {
			if (n->proto != IPPROTO_TCP && n->proto != IPPROTO_UDP)
				ERR("nat %s: DNAT needs tcp or udp", n->id);
			if (n->dmask != 0xffffffffu || !n->dport || !n->to_port_min)
				ERR("nat %s: DNAT needs a /32 address, a port and a target port", n->id);
			if (n->to_port_max != n->to_port_min)
				ERR("nat %s: DNAT target is a single port", n->id);
			for (j = 0; j < i; j++) {
				const struct fw_nat_spec *o = &s->nats[j].s;

				if (o->type == FW_NAT_DNAT && o->daddr == n->daddr &&
				    o->dport == n->dport && o->proto == n->proto)
					ERR("nat %s overlaps %s (same address/port)", n->id, o->id);
			}
		} else {
			ERR("nat %s: bad type", n->id);
		}
		if (n->out_ifname[0]) {
			k->out_ifindex = resolve_if(n->out_ifname);
			if (!k->out_ifindex)
				ERR("nat %s: interface %s does not exist", n->id, n->out_ifname);
		}
		k->s = *n;
	}
	return s;
bad:
	fw_snap_free(s);
	return NULL;
}

/* interfaces may have been recreated between VALIDATE and COMMIT */
int fw_snap_recheck_ifaces(const struct fw_snap *s, char *err, size_t errlen)
{
	u32 i;

	for (i = 0; i < s->nz; i++)
		if (resolve_if(s->zones[i].ifname) != s->zones[i].ifindex) {
			snprintf(err, errlen, "interface %s changed since validation; re-stage",
				 s->zones[i].ifname);
			return -ENODEV;
		}
	for (i = 0; i < s->nn; i++)
		if (s->nats[i].out_ifindex &&
		    resolve_if(s->nats[i].s.out_ifname) != s->nats[i].out_ifindex) {
			snprintf(err, errlen, "interface %s changed since validation; re-stage",
				 s->nats[i].s.out_ifname);
			return -ENODEV;
		}
	return 0;
}

/* The snapshot in force right after insmod: no rules, default action from the
 * initial_action parameter. Its blob is a real, exportable empty policy. */
struct fw_snap *fw_snap_initial(void)
{
	struct fw_policy_hdr h = {
		.magic = FW_POLICY_MAGIC,
		.version = FW_UAPI_VERSION,
		.default_action = fw_initial_action ? FW_ACT_ACCEPT : FW_ACT_DROP,
		.flags = FW_POLICY_F_LEGACY,
	};
	char err[96];
	unsigned int saved = fw_debug_fail_stage_alloc;
	struct fw_snap *s;

	strscpy(h.policy_hash, "initial", sizeof(h.policy_hash));
	strscpy(h.label, "module load", sizeof(h.label));
	fw_debug_fail_stage_alloc = 0;
	s = fw_snap_build((const u8 *)&h, sizeof(h), err, sizeof(err));
	fw_debug_fail_stage_alloc = saved;
	if (s)
		s->gen = 1;
	return s;
}
