/*
 * conn.c - flow table.
 *
 * Every flow stores two tuples: the ORIGINAL direction (first packet) and the
 * expected REPLY direction. Both are indexed in one red-black tree, so a
 * lookup finds a flow from either side. NAT is expressed by rewriting the
 * reply tuple, the same way the kernel's conntrack does it:
 *
 *   SNAT  c:cp -> s:sp   orig (c:cp -> s:sp)   reply (s:sp -> NAT:np)
 *   DNAT  x:xp -> P:pp   orig (x:xp -> P:pp)   reply (in:ip -> x:xp)
 *
 * v2 additions
 *   - each flow belongs to the generation it was created under; flows of
 *     older generations are never used (and are flushed at commit);
 *   - each direction records the interface its packets must arrive on
 *     (orig: the ingress of the first packet; reply: the egress the first
 *     packet left through, or "local"); a mismatch is a drop, so a known
 *     tuple cannot be injected from another interface;
 *   - the NAT decision is taken by the filter when the flow is created; a
 *     flow that needs SNAT and cannot get a port, leaves through the wrong
 *     interface, or whose state is missing is DROPPED: a packet is never
 *     sent untranslated when the policy says it must be translated.
 *
 * All access goes through one spinlock taken with BHs disabled.
 */
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include "fw.h"

#define DIR_ORIG  0
#define DIR_REPLY 1
#define GC_INTERVAL HZ

struct conn_hnode {
	struct rb_node rb;
	u8 dir;
};

struct conn {
	struct list_head list;
	struct conn_hnode h[2];
	struct fw_tuple t[2];
	unsigned long expires;
	u64 pkts[2], bytes[2];
	u32 gen;
	int in_if[2];
	struct fw_nat_plan plan;
	u8 nat_type;            /* translation actually in force */
	u8 closing;             /* TCP FIN/RST seen */
	char rule_id[FW_ID_LEN];
};

static struct rb_root conn_root = RB_ROOT;
static LIST_HEAD(conn_list);
static DEFINE_SPINLOCK(conn_lock);
static u32 conn_cnt;
static struct timer_list gc_timer;

static int tuple_cmp(const struct fw_tuple *a, const struct fw_tuple *b)
{
	if (a->saddr != b->saddr) return a->saddr < b->saddr ? -1 : 1;
	if (a->daddr != b->daddr) return a->daddr < b->daddr ? -1 : 1;
	if (a->sport != b->sport) return a->sport < b->sport ? -1 : 1;
	if (a->dport != b->dport) return a->dport < b->dport ? -1 : 1;
	if (a->proto != b->proto) return a->proto < b->proto ? -1 : 1;
	return 0;
}

static struct conn *conn_of(struct conn_hnode *h)
{
	return container_of(h - h->dir, struct conn, h[0]);
}

static void invert(const struct fw_tuple *in, struct fw_tuple *out)
{
	out->saddr = in->daddr;
	out->daddr = in->saddr;
	out->sport = in->dport;
	out->dport = in->sport;
	out->proto = in->proto;
}

static unsigned int timeout_of(const struct conn *c)
{
	switch (c->t[DIR_ORIG].proto) {
	case IPPROTO_TCP:
		return c->closing ? fw_tcp_close_timeout : fw_tcp_timeout;
	case IPPROTO_UDP:
		return fw_udp_timeout;
	default:
		return fw_icmp_timeout;
	}
}

/* ----- tree primitives, conn_lock held ----- */

static struct conn *__find(const struct fw_tuple *t, int *dir)
{
	struct rb_node *n = conn_root.rb_node;

	while (n) {
		struct conn_hnode *h = rb_entry(n, struct conn_hnode, rb);
		struct conn *c = conn_of(h);
		int r = tuple_cmp(t, &c->t[h->dir]);

		if (r < 0)
			n = n->rb_left;
		else if (r > 0)
			n = n->rb_right;
		else {
			if (dir)
				*dir = h->dir;
			return c;
		}
	}
	return NULL;
}

static int __insert(struct conn *c, int dir)
{
	struct rb_node **p = &conn_root.rb_node, *parent = NULL;

	while (*p) {
		struct conn_hnode *h = rb_entry(*p, struct conn_hnode, rb);
		int r = tuple_cmp(&c->t[dir], &conn_of(h)->t[h->dir]);

		parent = *p;
		if (r < 0)
			p = &(*p)->rb_left;
		else if (r > 0)
			p = &(*p)->rb_right;
		else
			return -EEXIST;
	}
	rb_link_node(&c->h[dir].rb, parent, p);
	rb_insert_color(&c->h[dir].rb, &conn_root);
	return 0;
}

static void __erase(struct conn *c)
{
	int d;

	for (d = 0; d < 2; d++)
		if (!RB_EMPTY_NODE(&c->h[d].rb))
			rb_erase(&c->h[d].rb, &conn_root);
	list_del(&c->list);
	conn_cnt--;
	kfree(c);
}

/* find, and silently retire a flow left over from an older generation */
static struct conn *__find_live(const struct fw_tuple *t, int *dir, u32 gen)
{
	struct conn *c = __find(t, dir);

	if (c && c->gen != gen) {
		__erase(c);
		return NULL;
	}
	return c;
}

/*
 * Lookup for the hooks that run after PRE_ROUTING translation. A DNATed
 * original packet now looks like the inverse of the reply tuple, and an
 * un-SNATed reply like the inverse of the original tuple; *dir is the
 * packet's real direction.
 */
static struct conn *__find_pkt(const struct fw_tuple *t, u32 gen, int *dir)
{
	struct fw_tuple inv;
	struct conn *c = __find_live(t, dir, gen);

	if (c)
		return c;
	invert(t, &inv);
	c = __find_live(&inv, dir, gen);
	if (c && *dir == DIR_REPLY && c->nat_type == FW_NAT_DNAT) {
		*dir = DIR_ORIG;
		return c;
	}
	if (c && *dir == DIR_ORIG && c->nat_type == FW_NAT_SNAT) {
		*dir = DIR_REPLY;
		return c;
	}
	return NULL;
}

static int __rekey_reply(struct conn *c, const struct fw_tuple *nt)
{
	struct fw_tuple old = c->t[DIR_REPLY];

	rb_erase(&c->h[DIR_REPLY].rb, &conn_root);
	c->t[DIR_REPLY] = *nt;
	if (__insert(c, DIR_REPLY) == 0)
		return 0;
	c->t[DIR_REPLY] = old;
	__insert(c, DIR_REPLY);
	return -EEXIST;
}

/* ----- packet path ----- */

int fw_conn_lookup(const struct fw_tuple *t, u8 flags, u32 len, int ifidx, u32 gen)
{
	struct conn *c;
	int dir, ret = 0;

	spin_lock_bh(&conn_lock);
	c = __find_live(t, &dir, gen);
	if (c) {
		if (c->in_if[dir] != ifidx) {
			ret = -FW_R_FLOW_IFACE;
		} else {
			c->pkts[dir]++;
			c->bytes[dir] += len;
			if (flags & FW_TCP_FIN_RST)
				c->closing = 1;
			c->expires = jiffies + timeout_of(c) * HZ;
			ret = 1;
		}
	}
	spin_unlock_bh(&conn_lock);
	return ret;
}

int fw_conn_add(const struct fw_tuple *t, u32 len, int ifidx, u32 gen,
		const struct fw_nat_plan *nat, const char *rule_id)
{
	struct conn *c, *old;
	int ret = 0;

	if (READ_ONCE(fw_debug_fail_flow_alloc)) {
		WRITE_ONCE(fw_debug_fail_flow_alloc, fw_debug_fail_flow_alloc - 1);
		return -ENOMEM;
	}
	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c)
		return -ENOMEM;
	c->t[DIR_ORIG] = *t;
	invert(t, &c->t[DIR_REPLY]);
	c->h[DIR_ORIG].dir = DIR_ORIG;
	c->h[DIR_REPLY].dir = DIR_REPLY;
	RB_CLEAR_NODE(&c->h[DIR_ORIG].rb);
	RB_CLEAR_NODE(&c->h[DIR_REPLY].rb);
	c->gen = gen;
	c->in_if[DIR_ORIG] = ifidx;
	c->in_if[DIR_REPLY] = FW_IF_UNSET;
	c->pkts[DIR_ORIG] = 1;
	c->bytes[DIR_ORIG] = len;
	if (nat)
		c->plan = *nat;
	if (rule_id)
		strscpy(c->rule_id, rule_id, sizeof(c->rule_id));
	if (c->plan.type == FW_NAT_DNAT) {
		c->t[DIR_REPLY].saddr = c->plan.to_addr;
		c->t[DIR_REPLY].sport = c->plan.port_min;
		c->nat_type = FW_NAT_DNAT;
	}

	spin_lock_bh(&conn_lock);
	/* retire stale holders of either tuple first */
	old = __find(&c->t[DIR_ORIG], NULL);
	if (old && old->gen != gen)
		__erase(old);
	old = __find(&c->t[DIR_REPLY], NULL);
	if (old && old->gen != gen)
		__erase(old);

	if (conn_cnt >= READ_ONCE(fw_max_conns)) {
		ret = -ENOSPC;
	} else if (__insert(c, DIR_ORIG)) {
		ret = -EEXIST;                  /* another CPU created it first */
	} else if (__insert(c, DIR_REPLY)) {
		rb_erase(&c->h[DIR_ORIG].rb, &conn_root);
		ret = -EADDRINUSE;              /* reply tuple belongs to another flow */
	} else {
		c->expires = jiffies + timeout_of(c) * HZ;
		list_add_tail(&c->list, &conn_list);
		conn_cnt++;
	}
	spin_unlock_bh(&conn_lock);
	if (ret)
		kfree(c);
	return ret;
}

void fw_conn_local_in(const struct fw_tuple *t, u32 gen)
{
	struct conn *c;
	int dir;

	spin_lock_bh(&conn_lock);
	c = __find_pkt(t, gen, &dir);
	if (c && dir == DIR_ORIG && c->in_if[DIR_REPLY] == FW_IF_UNSET)
		c->in_if[DIR_REPLY] = FW_IF_LOCAL;      /* we answer from LOCAL_OUT */
	spin_unlock_bh(&conn_lock);
}

/* PRE_ROUTING, after the filter: DNAT and un-SNAT of replies. */
unsigned int fw_conn_nat_pre(struct sk_buff *skb, const struct fw_tuple *t, u32 gen)
{
	struct conn *c;
	bool mangle = false;
	u32 addr = 0;
	u16 port = 0;
	int dir;

	spin_lock_bh(&conn_lock);
	c = __find_live(t, &dir, gen);
	if (!c) {
		spin_unlock_bh(&conn_lock);
		return fw_drop(skb, FW_R_NAT_STATE, -1);
	}
	if (dir == DIR_ORIG && c->nat_type == FW_NAT_DNAT) {
		addr = c->t[DIR_REPLY].saddr;           /* the published host */
		port = c->t[DIR_REPLY].sport;
		mangle = true;
	} else if (dir == DIR_REPLY && c->nat_type == FW_NAT_SNAT) {
		addr = c->t[DIR_ORIG].saddr;            /* back to the inside host */
		port = c->t[DIR_ORIG].sport;
		mangle = true;
	}
	spin_unlock_bh(&conn_lock);

	if (mangle) {
		if (fw_pkt_mangle(skb, false, addr, port))
			return fw_drop(skb, FW_R_NAT_MANGLE, -1);
		fw_stat_add(FW_S_NAT, 1);
	}
	return NF_ACCEPT;
}

/* Pick a NAT source port whose reply tuple is unused. conn_lock held. */
static bool __pick_snat_port(const struct fw_nat_plan *p, struct fw_tuple *nt, u16 orig_port)
{
	u32 span, i, start;

	if (nt->proto != IPPROTO_TCP && nt->proto != IPPROTO_UDP)
		return __find(nt, NULL) == NULL;        /* ICMP: keep the echo id */

	if (orig_port >= p->port_min && orig_port <= p->port_max) {
		nt->dport = orig_port;
		if (!__find(nt, NULL))
			return true;
	}
	span = (u32)p->port_max - p->port_min + 1;
	start = get_random_u32() % span;
	for (i = 0; i < span; i++) {
		nt->dport = p->port_min + (start + i) % span;
		if (!__find(nt, NULL))
			return true;
	}
	return false;
}

/* POST_ROUTING: SNAT and un-DNAT of replies; learns the reply interface. */
unsigned int fw_conn_nat_post(struct sk_buff *skb, const struct fw_tuple *t, u32 gen,
			      const struct net_device *out)
{
	struct conn *c;
	bool mangle = false;
	u32 addr = 0;
	u16 port = 0;
	int dir, fail = 0;

	spin_lock_bh(&conn_lock);
	c = __find_pkt(t, gen, &dir);
	if (!c) {
		spin_unlock_bh(&conn_lock);
		return fw_drop(skb, FW_R_NAT_STATE, -1);
	}
	if (dir == DIR_ORIG && c->in_if[DIR_REPLY] == FW_IF_UNSET)
		c->in_if[DIR_REPLY] = (out->flags & IFF_LOOPBACK) ? FW_IF_LOCAL : out->ifindex;

	if (dir == DIR_ORIG && c->plan.type == FW_NAT_SNAT && c->nat_type == FW_NAT_NONE) {
		struct fw_tuple nt = c->t[DIR_REPLY];

		nt.daddr = c->plan.to_addr;
		if (c->plan.out_ifindex && c->plan.out_ifindex != out->ifindex) {
			fail = FW_R_EGRESS;
		} else if (!__pick_snat_port(&c->plan, &nt, t->sport) || __rekey_reply(c, &nt)) {
			fail = FW_R_NAT_ALLOC;
		} else {
			c->nat_type = FW_NAT_SNAT;
		}
		if (fail) {
			__erase(c);     /* never fall back to an untranslated flow */
			spin_unlock_bh(&conn_lock);
			if (fail == FW_R_NAT_ALLOC)
				fw_stat_add(FW_S_NAT_ALLOC_FAIL, 1);
			return fw_drop(skb, fail, -1);
		}
	}
	if (dir == DIR_REPLY && c->nat_type == FW_NAT_DNAT) {
		addr = c->t[DIR_ORIG].daddr;            /* look like the public address */
		port = c->t[DIR_ORIG].dport;
		mangle = true;
	} else if (dir == DIR_ORIG && c->nat_type == FW_NAT_SNAT) {
		addr = c->t[DIR_REPLY].daddr;
		port = c->t[DIR_REPLY].dport;
		mangle = true;
	}
	spin_unlock_bh(&conn_lock);

	if (mangle) {
		if (fw_pkt_mangle(skb, true, addr, port))
			return fw_drop(skb, FW_R_NAT_MANGLE, -1);
		fw_stat_add(FW_S_NAT, 1);
	}
	return NF_ACCEPT;
}

/* ----- management ----- */

u32 fw_conn_flush_all(void)
{
	struct conn *c, *tmp;
	u32 n = 0;

	spin_lock_bh(&conn_lock);
	list_for_each_entry_safe(c, tmp, &conn_list, list) {
		__erase(c);
		n++;
	}
	spin_unlock_bh(&conn_lock);
	return n;
}

u32 fw_conn_flush_stale(u32 gen)
{
	struct conn *c, *tmp;
	u32 n = 0;

	spin_lock_bh(&conn_lock);
	list_for_each_entry_safe(c, tmp, &conn_list, list) {
		if (c->gen != gen) {
			__erase(c);
			n++;
		}
	}
	spin_unlock_bh(&conn_lock);
	return n;
}

u32 fw_conn_count(void)
{
	u32 c;

	spin_lock_bh(&conn_lock);
	c = conn_cnt;
	spin_unlock_bh(&conn_lock);
	return c;
}

u32 fw_conn_dump(struct fw_conn_info *buf, u32 start, u32 max, u32 *total)
{
	struct conn *c;
	u32 i = 0, n = 0;

	spin_lock_bh(&conn_lock);
	*total = conn_cnt;
	list_for_each_entry(c, &conn_list, list) {
		struct fw_conn_info *o;

		if (i++ < start)
			continue;
		if (n >= max)
			break;
		o = &buf[n++];
		memset(o, 0, sizeof(*o));
		o->saddr = c->t[DIR_ORIG].saddr;
		o->daddr = c->t[DIR_ORIG].daddr;
		o->sport = c->t[DIR_ORIG].sport;
		o->dport = c->t[DIR_ORIG].dport;
		o->r_saddr = c->t[DIR_REPLY].saddr;
		o->r_daddr = c->t[DIR_REPLY].daddr;
		o->r_sport = c->t[DIR_REPLY].sport;
		o->r_dport = c->t[DIR_REPLY].dport;
		o->proto = c->t[DIR_ORIG].proto;
		o->nat_type = c->nat_type;
		o->closing = c->closing;
		o->expires_in = time_after(c->expires, jiffies) ?
				(c->expires - jiffies + HZ - 1) / HZ : 0;
		o->generation = c->gen;
		o->in_if[0] = c->in_if[0];
		o->in_if[1] = c->in_if[1];
		o->pkts[0] = c->pkts[0];
		o->pkts[1] = c->pkts[1];
		o->bytes[0] = c->bytes[0];
		o->bytes[1] = c->bytes[1];
		memcpy(o->rule_id, c->rule_id, sizeof(o->rule_id));
	}
	spin_unlock_bh(&conn_lock);
	return n;
}

/* ----- garbage collection ----- */

static void gc_timer_fn(struct timer_list *unused)
{
	struct conn *c, *tmp;
	struct fw_snap *s;
	u32 gen = 0;

	rcu_read_lock();
	s = rcu_dereference(fw_active);
	if (s)
		gen = s->gen;
	rcu_read_unlock();

	spin_lock_bh(&conn_lock);
	list_for_each_entry_safe(c, tmp, &conn_list, list)
		if (time_after_eq(jiffies, c->expires) || c->gen != gen)
			__erase(c);
	spin_unlock_bh(&conn_lock);
	mod_timer(&gc_timer, jiffies + GC_INTERVAL);
}

int fw_conn_init(void)
{
	timer_setup(&gc_timer, gc_timer_fn, 0);
	mod_timer(&gc_timer, jiffies + GC_INTERVAL);
	return 0;
}

void fw_conn_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	timer_shutdown_sync(&gc_timer);
#else
	del_timer_sync(&gc_timer);
#endif
	fw_conn_flush_all();
}
