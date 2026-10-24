/*
 * nat.c - SNAT / DNAT rule list. The per-flow translation state lives in the
 * connection table (conn.c); this file only answers "which rule applies".
 */
#include <linux/slab.h>
#include "fw.h"

struct nat_node {
	struct list_head list;
	struct fw_nat_rule r;
	atomic64_t hits;
};

static LIST_HEAD(nat_list);
static DEFINE_SPINLOCK(nat_lock);
static u32 nat_cnt;

bool fw_nat_match_snat(const struct fw_tuple *t, struct fw_nat_rule *out)
{
	struct nat_node *n;
	bool found = false;

	spin_lock_bh(&nat_lock);
	list_for_each_entry(n, &nat_list, list) {
		const struct fw_nat_rule *r = &n->r;

		if (r->type != FW_NAT_SNAT)
			continue;
		/* from inside the subnet, to outside of it, not to the NAT address */
		if (fw_ip_match(t->saddr, r->saddr, r->smask) &&
		    !fw_ip_match(t->daddr, r->saddr, r->smask) &&
		    t->daddr != r->to_addr) {
			atomic64_inc(&n->hits);
			*out = *r;
			found = true;
			break;
		}
	}
	spin_unlock_bh(&nat_lock);
	return found;
}

bool fw_nat_match_dnat(const struct fw_tuple *t, struct fw_nat_rule *out)
{
	struct nat_node *n;
	bool found = false;

	spin_lock_bh(&nat_lock);
	list_for_each_entry(n, &nat_list, list) {
		const struct fw_nat_rule *r = &n->r;

		if (r->type != FW_NAT_DNAT)
			continue;
		if (t->daddr == r->daddr && t->proto == r->proto && t->dport == r->dport) {
			atomic64_inc(&n->hits);
			*out = *r;
			found = true;
			break;
		}
	}
	spin_unlock_bh(&nat_lock);
	return found;
}

int fw_nat_add(const struct fw_nat_rule *r)
{
	struct nat_node *n;

	if (r->type != FW_NAT_SNAT && r->type != FW_NAT_DNAT)
		return -EINVAL;
	if (r->type == FW_NAT_DNAT && r->proto != IPPROTO_TCP && r->proto != IPPROTO_UDP)
		return -EINVAL;
	if (r->to_port_min > r->to_port_max)
		return -EINVAL;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;
	n->r = *r;
	spin_lock_bh(&nat_lock);
	list_add_tail(&n->list, &nat_list);    /* listed (and matched) in insertion order */
	nat_cnt++;
	spin_unlock_bh(&nat_lock);
	return 0;
}

int fw_nat_del(u32 seq)
{
	struct nat_node *n, *victim = NULL;
	u32 i = 0;

	spin_lock_bh(&nat_lock);
	list_for_each_entry(n, &nat_list, list) {
		if (i++ == seq) {
			victim = n;
			list_del(&n->list);
			nat_cnt--;
			break;
		}
	}
	spin_unlock_bh(&nat_lock);
	if (!victim)
		return -ENOENT;
	kfree(victim);
	/* translated flows would keep using the old mapping: drop them */
	fw_conn_flush_nat();
	return 0;
}

int fw_nat_flush(void)
{
	struct nat_node *n, *tmp;
	LIST_HEAD(dead);
	int count;

	spin_lock_bh(&nat_lock);
	list_splice_init(&nat_list, &dead);
	count = nat_cnt;
	nat_cnt = 0;
	spin_unlock_bh(&nat_lock);
	list_for_each_entry_safe(n, tmp, &dead, list)
		kfree(n);
	if (count)
		fw_conn_flush_nat();
	return count;
}

u32 fw_nat_count(void)
{
	u32 c;

	spin_lock_bh(&nat_lock);
	c = nat_cnt;
	spin_unlock_bh(&nat_lock);
	return c;
}

u32 fw_nat_dump(struct fw_nat_rule *buf, u32 max, u32 *total)
{
	struct nat_node *n;
	u32 i = 0;

	spin_lock_bh(&nat_lock);
	*total = nat_cnt;
	list_for_each_entry(n, &nat_list, list) {
		if (i >= max)
			break;
		buf[i] = n->r;
		buf[i].hits = atomic64_read(&n->hits);
		i++;
	}
	spin_unlock_bh(&nat_lock);
	return i;
}
