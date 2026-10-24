/*
 * log.c - fixed-size ring buffer of filter decisions (oldest entries are
 * overwritten). No allocation happens on the packet path.
 */
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include "fw.h"

static struct fw_log ring[FW_MAX_LOGS];
static u32 ring_head;     /* index of the oldest entry */
static u32 ring_cnt;
static DEFINE_SPINLOCK(log_lock);

void fw_log_add(const struct fw_tuple *t, u32 len, u8 action, bool by_default, const char *rule)
{
	struct fw_log *e;

	spin_lock_bh(&log_lock);
	if (ring_cnt < FW_MAX_LOGS) {
		e = &ring[(ring_head + ring_cnt) % FW_MAX_LOGS];
		ring_cnt++;
	} else {
		e = &ring[ring_head];
		ring_head = (ring_head + 1) % FW_MAX_LOGS;
	}
	memset(e, 0, sizeof(*e));
	e->ts = ktime_get_real_seconds();   /* wall-clock time, not time since boot */
	e->saddr = t->saddr;
	e->daddr = t->daddr;
	e->sport = t->sport;
	e->dport = t->dport;
	e->proto = t->proto;
	e->len = len;
	e->action = action;
	e->by_default = by_default;
	if (rule)
		strscpy(e->rule, rule, FW_NAME_LEN);
	spin_unlock_bh(&log_lock);
}

void fw_log_clear(void)
{
	spin_lock_bh(&log_lock);
	ring_head = ring_cnt = 0;
	spin_unlock_bh(&log_lock);
}

u32 fw_log_count(void)
{
	u32 c;

	spin_lock_bh(&log_lock);
	c = ring_cnt;
	spin_unlock_bh(&log_lock);
	return c;
}

/* Copies the newest min(max, count) entries, oldest first. */
u32 fw_log_dump(struct fw_log *buf, u32 max, u32 *total)
{
	u32 i, n, skip;

	spin_lock_bh(&log_lock);
	*total = ring_cnt;
	n = min(max, ring_cnt);
	skip = ring_cnt - n;
	for (i = 0; i < n; i++)
		buf[i] = ring[(ring_head + skip + i) % FW_MAX_LOGS];
	spin_unlock_bh(&log_lock);
	return n;
}
