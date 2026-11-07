/*
 * events.c - sequenced event ring.
 *
 * Every event gets a 64-bit sequence number that starts at 1 when the module
 * loads and never repeats while it stays loaded. Readers ask for events
 * "since seq N"; when the ring has already overwritten some of them the reply
 * says how many were lost, so a collector can record a gap instead of
 * silently missing data. Packet events are rate limited (fw_event_rate per
 * second); suppressed events are counted. Control events (commit, abort,
 * rejected commit) are never rate limited.
 */
#include <linux/timekeeping.h>
#include <linux/jiffies.h>
#include "fw.h"

static struct fw_event ring[FW_MAX_EVENTS];
static u64 next_seq = 1;                /* seq the next event will get */
static DEFINE_SPINLOCK(ev_lock);
static unsigned long bucket_start;
static u32 bucket_used;

static struct fw_event *__slot(void)
{
	struct fw_event *e = &ring[next_seq % FW_MAX_EVENTS];

	if (next_seq > FW_MAX_EVENTS)
		fw_stat_add(FW_S_EV_OVERWRITTEN, 1);
	memset(e, 0, sizeof(*e));
	e->seq = next_seq++;
	e->ts_ns = ktime_get_real_ns();
	return e;
}

void fw_event_packet(const struct fw_tuple *t, u32 len, u32 gen, u8 verdict,
		     u8 reason, u8 zone, int ifindex, const char *rule_id)
{
	unsigned long flags;
	struct fw_event *e;
	u32 rate = READ_ONCE(fw_event_rate);

	spin_lock_irqsave(&ev_lock, flags);
	if (rate) {
		if (time_after_eq(jiffies, bucket_start + HZ)) {
			bucket_start = jiffies;
			bucket_used = 0;
		}
		if (bucket_used >= rate) {
			spin_unlock_irqrestore(&ev_lock, flags);
			fw_stat_add(FW_S_EV_SUPPRESSED, 1);
			return;
		}
		bucket_used++;
	}
	e = __slot();
	e->kind = FW_EV_PACKET;
	e->generation = gen;
	e->saddr = t->saddr;
	e->daddr = t->daddr;
	e->sport = t->sport;
	e->dport = t->dport;
	e->proto = t->proto;
	e->verdict = verdict;
	e->reason = reason;
	e->zone = zone;
	e->len = len;
	e->ifindex = ifindex;
	if (rule_id)
		strscpy(e->rule_id, rule_id, sizeof(e->rule_id));
	spin_unlock_irqrestore(&ev_lock, flags);
}

void fw_event_control(u32 kind, u32 gen, const char *text)
{
	unsigned long flags;
	struct fw_event *e;

	spin_lock_irqsave(&ev_lock, flags);
	e = __slot();
	e->kind = kind;
	e->generation = gen;
	if (text)
		strscpy(e->rule_id, text, sizeof(e->rule_id));
	spin_unlock_irqrestore(&ev_lock, flags);
}

u64 fw_event_next_seq(void)
{
	unsigned long flags;
	u64 n;

	spin_lock_irqsave(&ev_lock, flags);
	n = next_seq;
	spin_unlock_irqrestore(&ev_lock, flags);
	return n;
}

u32 fw_event_dump(struct fw_event *buf, u64 since, u32 max, u64 *first, u64 *next, u64 *lost)
{
	unsigned long flags;
	u64 oldest, s;
	u32 n = 0;

	spin_lock_irqsave(&ev_lock, flags);
	oldest = next_seq > FW_MAX_EVENTS ? next_seq - FW_MAX_EVENTS : 1;
	*first = oldest;
	*next = next_seq;
	if (since == 0)
		since = 1;
	*lost = since < oldest ? oldest - since : 0;
	for (s = max_t(u64, since, oldest); s < next_seq && n < max; s++)
		buf[n++] = ring[s % FW_MAX_EVENTS];
	spin_unlock_irqrestore(&ev_lock, flags);
	return n;
}
