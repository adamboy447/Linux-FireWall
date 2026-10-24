/*
 * rules.c - the ordered filter rule chain (first match wins).
 */
#include <linux/slab.h>
#include <linux/string.h>
#include "fw.h"

struct rule_node {
	struct list_head list;
	struct fw_rule r;
	atomic64_t pkts, bytes;
};

static LIST_HEAD(rule_list);
static DEFINE_RWLOCK(rule_lock);   /* readers: packet path; writers: netlink */
static u32 rule_cnt;

bool fw_rule_matches(const struct fw_rule *r, const struct fw_tuple *t)
{
	if (!fw_ip_match(t->saddr, r->saddr, r->smask) ||
	    !fw_ip_match(t->daddr, r->daddr, r->dmask))
		return false;
	if (r->proto && r->proto != t->proto)
		return false;
	/* port ranges only mean something for TCP and UDP */
	if (t->proto == IPPROTO_TCP || t->proto == IPPROTO_UDP) {
		if (t->sport < r->sport_min || t->sport > r->sport_max)
			return false;
		if (t->dport < r->dport_min || t->dport > r->dport_max)
			return false;
	}
	return true;
}

bool fw_rules_match(const struct fw_tuple *t, u32 len, struct fw_rule *out)
{
	struct rule_node *n;
	bool found = false;

	read_lock_bh(&rule_lock);
	list_for_each_entry(n, &rule_list, list) {
		if (fw_rule_matches(&n->r, t)) {
			atomic64_inc(&n->pkts);
			atomic64_add(len, &n->bytes);
			*out = n->r;
			found = true;
			break;
		}
	}
	read_unlock_bh(&rule_lock);
	return found;
}

int fw_rules_add(const struct fw_rule *r, u32 where, const char *after)
{
	struct rule_node *n, *pos;
	int ret = 0;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;
	n->r = *r;
	n->r.name[FW_NAME_LEN - 1] = '\0';
	n->r.hit_pkts = n->r.hit_bytes = 0;

	write_lock_bh(&rule_lock);
	switch (where) {
	case FW_ADD_HEAD:
		list_add(&n->list, &rule_list);
		break;
	case FW_ADD_TAIL:
		list_add_tail(&n->list, &rule_list);
		break;
	case FW_ADD_AFTER:
		ret = -ENOENT;
		list_for_each_entry(pos, &rule_list, list) {
			if (strcmp(pos->r.name, after) == 0) {
				list_add(&n->list, &pos->list);
				ret = 0;
				break;
			}
		}
		break;
	default:
		ret = -EINVAL;
	}
	if (!ret)
		rule_cnt++;
	write_unlock_bh(&rule_lock);

	if (ret) {
		kfree(n);
		return ret;
	}
	/* a new DROP rule must also stop flows that are already established */
	if (r->action == FW_ACT_DROP)
		fw_conn_flush_matching(r);
	return 0;
}

int fw_rules_del(const char *name)
{
	struct rule_node *n, *tmp;
	LIST_HEAD(dead);
	int count = 0;

	write_lock_bh(&rule_lock);
	list_for_each_entry_safe(n, tmp, &rule_list, list) {
		if (strcmp(n->r.name, name) == 0) {
			list_move(&n->list, &dead);
			rule_cnt--;
			count++;
		}
	}
	write_unlock_bh(&rule_lock);

	/* flows that a deleted ACCEPT rule let in must be re-evaluated */
	list_for_each_entry_safe(n, tmp, &dead, list) {
		if (n->r.action == FW_ACT_ACCEPT)
			fw_conn_flush_matching(&n->r);
		kfree(n);
	}
	return count;
}

int fw_rules_flush(void)
{
	struct rule_node *n, *tmp;
	LIST_HEAD(dead);
	int count;

	write_lock_bh(&rule_lock);
	list_splice_init(&rule_list, &dead);
	count = rule_cnt;
	rule_cnt = 0;
	write_unlock_bh(&rule_lock);

	list_for_each_entry_safe(n, tmp, &dead, list)
		kfree(n);
	return count;
}

u32 fw_rules_count(void)
{
	u32 c;

	read_lock_bh(&rule_lock);
	c = rule_cnt;
	read_unlock_bh(&rule_lock);
	return c;
}

u32 fw_rules_dump(struct fw_rule *buf, u32 max, u32 *total)
{
	struct rule_node *n;
	u32 i = 0;

	read_lock_bh(&rule_lock);
	*total = rule_cnt;
	list_for_each_entry(n, &rule_list, list) {
		if (i >= max)
			break;
		buf[i] = n->r;
		buf[i].hit_pkts = atomic64_read(&n->pkts);
		buf[i].hit_bytes = atomic64_read(&n->bytes);
		i++;
	}
	read_unlock_bh(&rule_lock);
	return i;
}
