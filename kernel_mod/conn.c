/*
 * conn.c - connection (flow) table.
 *
 * Every flow stores two tuples: the ORIGINAL direction (first packet) and the
 * expected REPLY direction. Both are indexed in one red-black tree, so a
 * lookup finds a flow from either side; that is what makes replies pass
 * without a reverse rule. NAT is expressed by rewriting the reply tuple, the
 * same way the kernel's own conntrack does it:
 *
 *   SNAT  c:cp -> s:sp   becomes   orig  (c:cp -> s:sp)
 *                                  reply (s:sp -> NAT:np)
 *   DNAT  x:xp -> P:pp   becomes   orig  (x:xp -> P:pp)
 *                                  reply (in:ip -> x:xp)
 *
 * All access goes through one spinlock taken with BHs disabled (the packet
 * path can run in softirq or, for LOCAL_OUT, in process context).
 */
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include "fw.h"

#define DIR_ORIG  0
#define DIR_REPLY 1
#define GC_INTERVAL HZ          /* expire flows once per second */

struct conn_hnode {
	struct rb_node rb;
	u8 dir;
};

struct conn {
	struct list_head list;
	struct conn_hnode h[2];
	struct fw_tuple t[2];
	unsigned long expires;
	u64 pkts[2];
	u8 nat_type;
	u8 by_default;          /* accepted by the default policy, not a rule */
	u8 dnat_checked, snat_checked;
	u8 closing;             /* TCP FIN/RST seen */
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

/* Replace the reply tuple (NAT). Fails if the new tuple is already in use. */
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

bool fw_conn_lookup(const struct fw_tuple *t, u8 flags)
{
	struct conn *c;
	int dir;

	spin_lock_bh(&conn_lock);
	c = __find(t, &dir);
	if (c) {
		c->pkts[dir]++;
		if (flags & FW_TCP_FIN_RST)
			c->closing = 1;
		c->expires = jiffies + timeout_of(c) * HZ;
	}
	spin_unlock_bh(&conn_lock);
	return c != NULL;
}

int fw_conn_add(const struct fw_tuple *t, bool by_default)
{
	struct conn *c;
	int ret = 0;

	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c)
		return -ENOMEM;
	c->t[DIR_ORIG] = *t;
	invert(t, &c->t[DIR_REPLY]);
	c->h[DIR_ORIG].dir = DIR_ORIG;
	c->h[DIR_REPLY].dir = DIR_REPLY;
	RB_CLEAR_NODE(&c->h[DIR_ORIG].rb);
	RB_CLEAR_NODE(&c->h[DIR_REPLY].rb);
	c->by_default = by_default;
	c->pkts[DIR_ORIG] = 1;

	spin_lock_bh(&conn_lock);
	if (conn_cnt >= fw_max_conns) {
		ret = -ENOSPC;
	} else if (__insert(c, DIR_ORIG)) {
		ret = -EEXIST;                  /* another CPU created it first */
	} else if (__insert(c, DIR_REPLY)) {
		rb_erase(&c->h[DIR_ORIG].rb, &conn_root);
		ret = -EEXIST;
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

/* PRE_ROUTING, after the filter: destination translation. */
unsigned int fw_conn_nat_pre(struct sk_buff *skb, const struct fw_tuple *t)
{
	struct fw_nat_rule nr;
	struct conn *c;
	bool mangle = false;
	u32 addr = 0;
	u16 port = 0;
	int dir;

	spin_lock_bh(&conn_lock);
	c = __find(t, &dir);
	if (!c)
		goto out;
	if (dir == DIR_ORIG && c->nat_type == FW_NAT_DNAT) {
		addr = c->t[DIR_REPLY].saddr;           /* forwarded-to host */
		port = c->t[DIR_REPLY].sport;
		mangle = true;
	} else if (dir == DIR_REPLY && c->nat_type == FW_NAT_SNAT) {
		addr = c->t[DIR_ORIG].saddr;            /* back to the inside host */
		port = c->t[DIR_ORIG].sport;
		mangle = true;
	} else if (dir == DIR_ORIG && c->nat_type == FW_NAT_NONE && !c->dnat_checked) {
		c->dnat_checked = 1;
		if (fw_nat_match_dnat(t, &nr)) {
			struct fw_tuple nt = c->t[DIR_REPLY];

			nt.saddr = nr.to_addr;
			nt.sport = nr.to_port_min;
			if (__rekey_reply(c, &nt) == 0) {
				c->nat_type = FW_NAT_DNAT;
				addr = nr.to_addr;
				port = nr.to_port_min;
				mangle = true;
			}
		}
	}
out:
	spin_unlock_bh(&conn_lock);

	if (mangle) {
		if (fw_pkt_mangle(skb, false, addr, port))
			return NF_DROP;
		atomic64_inc(&fw_stat_natted);
	}
	return NF_ACCEPT;
}

/* Pick a NAT source port whose reply tuple is unused. conn_lock held. */
static bool __pick_snat_port(const struct fw_nat_rule *nr, struct fw_tuple *nt, u16 orig_port)
{
	u32 span, i, start;

	if (nt->proto != IPPROTO_TCP && nt->proto != IPPROTO_UDP)
		return __find(nt, NULL) == NULL;        /* ICMP: keep the echo id */

	/* keep the original port when possible, like Linux does */
	if (orig_port >= nr->to_port_min && orig_port <= nr->to_port_max) {
		nt->dport = orig_port;
		if (!__find(nt, NULL))
			return true;
	}
	span = (u32)nr->to_port_max - nr->to_port_min + 1;
	start = get_random_u32() % span;
	for (i = 0; i < span; i++) {
		nt->dport = nr->to_port_min + (start + i) % span;
		if (nt->dport == 0)
			continue;
		if (!__find(nt, NULL))
			return true;
	}
	return false;
}

/* POST_ROUTING: source translation. */
unsigned int fw_conn_nat_post(struct sk_buff *skb, const struct fw_tuple *t)
{
	struct fw_nat_rule nr;
	struct conn *c;
	bool mangle = false;
	u32 addr = 0;
	u16 port = 0;
	int dir;

	spin_lock_bh(&conn_lock);
	c = __find(t, &dir);
	if (!c)
		goto out;
	if (dir == DIR_REPLY && c->nat_type == FW_NAT_DNAT) {
		addr = c->t[DIR_ORIG].daddr;            /* look like the public address */
		port = c->t[DIR_ORIG].dport;
		mangle = true;
	} else if (dir == DIR_ORIG && c->nat_type == FW_NAT_SNAT) {
		addr = c->t[DIR_REPLY].daddr;
		port = c->t[DIR_REPLY].dport;
		mangle = true;
	} else if (dir == DIR_ORIG && c->nat_type == FW_NAT_NONE && !c->snat_checked) {
		c->snat_checked = 1;
		if (fw_nat_match_snat(t, &nr)) {
			struct fw_tuple nt = c->t[DIR_REPLY];

			nt.daddr = nr.to_addr;
			if (__pick_snat_port(&nr, &nt, t->sport) && __rekey_reply(c, &nt) == 0) {
				c->nat_type = FW_NAT_SNAT;
				addr = nt.daddr;
				port = nt.dport;
				mangle = true;
			} else {
				pr_warn_ratelimited(FW_TAG "SNAT: no free port in %u-%u\n",
						    nr.to_port_min, nr.to_port_max);
			}
		}
	}
out:
	spin_unlock_bh(&conn_lock);

	if (mangle) {
		if (fw_pkt_mangle(skb, true, addr, port))
			return NF_DROP;
		atomic64_inc(&fw_stat_natted);
	}
	return NF_ACCEPT;
}

/* ----- management ----- */

static u32 flush_if(bool (*pred)(const struct conn *, const void *), const void *arg)
{
	struct conn *c, *tmp;
	u32 n = 0;

	spin_lock_bh(&conn_lock);
	list_for_each_entry_safe(c, tmp, &conn_list, list) {
		if (!pred || pred(c, arg)) {
			__erase(c);
			n++;
		}
	}
	spin_unlock_bh(&conn_lock);
	return n;
}

static bool pred_rule(const struct conn *c, const void *arg)
{
	return fw_rule_matches(arg, &c->t[DIR_ORIG]);
}

static bool pred_default(const struct conn *c, const void *arg)
{
	return c->by_default;
}

static bool pred_nat(const struct conn *c, const void *arg)
{
	return c->nat_type != FW_NAT_NONE;
}

u32 fw_conn_flush_matching(const struct fw_rule *r) { return flush_if(pred_rule, r); }
u32 fw_conn_flush_default(void) { return flush_if(pred_default, NULL); }
u32 fw_conn_flush_nat(void) { return flush_if(pred_nat, NULL); }
u32 fw_conn_flush_all(void) { return flush_if(NULL, NULL); }

u32 fw_conn_count(void)
{
	u32 c;

	spin_lock_bh(&conn_lock);
	c = conn_cnt;
	spin_unlock_bh(&conn_lock);
	return c;
}

u32 fw_conn_dump(struct fw_conn *buf, u32 max, u32 *total)
{
	struct conn *c;
	u32 i = 0;

	spin_lock_bh(&conn_lock);
	*total = conn_cnt;
	list_for_each_entry(c, &conn_list, list) {
		struct fw_conn *o = &buf[i];

		if (i >= max)
			break;
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
		o->expires_in = time_after(c->expires, jiffies) ?
				(c->expires - jiffies + HZ - 1) / HZ : 0;
		o->pkts_orig = c->pkts[DIR_ORIG];
		o->pkts_reply = c->pkts[DIR_REPLY];
		i++;
	}
	spin_unlock_bh(&conn_lock);
	return i;
}

/* ----- garbage collection ----- */

static void gc_timer_fn(struct timer_list *unused)
{
	struct conn *c, *tmp;

	spin_lock_bh(&conn_lock);
	list_for_each_entry_safe(c, tmp, &conn_list, list)
		if (time_after_eq(jiffies, c->expires))
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
