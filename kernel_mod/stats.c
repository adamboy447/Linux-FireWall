/*
 * stats.c - per-CPU counters.
 *
 * Each managed packet gets exactly one FINAL verdict:
 *   - drop: counted where the packet is dropped, with an FW_R_* reason;
 *   - accept: counted at the last hook it passes (POST_ROUTING for
 *     forwarded/locally generated packets, LOCAL_IN for local delivery).
 * Rule/default decisions on new flows are counted separately
 * (FW_S_NEW_ACCEPT / FW_S_NEW_DROP), as are stateful fast-path hits.
 * Per-zone counters live in the policy snapshot, so they restart with each
 * generation and their index always refers to the zone list in force.
 */
#include <linux/percpu.h>
#include "fw.h"

struct fw_pcpu {
	u64 v[FW_S__COUNT];
};

static struct fw_pcpu __percpu *fw_pcpu;

int fw_stats_init(void)
{
	fw_pcpu = alloc_percpu(struct fw_pcpu);
	return fw_pcpu ? 0 : -ENOMEM;
}

void fw_stats_exit(void)
{
	free_percpu(fw_pcpu);
}

void fw_stat_add(enum fw_stat s, u64 v)
{
	this_cpu_add(fw_pcpu->v[s], v);
}

u64 fw_stat_read(enum fw_stat s)
{
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += per_cpu_ptr(fw_pcpu, cpu)->v[s];
	return sum;
}

unsigned int fw_drop(const struct sk_buff *skb, int reason, int zone_slot)
{
	struct fw_snap *s;

	this_cpu_inc(fw_pcpu->v[FW_S_DROP_PKTS]);
	this_cpu_add(fw_pcpu->v[FW_S_DROP_BYTES], skb->len);
	if (reason > 0 && reason < FW_R_SLOTS)
		this_cpu_inc(fw_pcpu->v[FW_S_REASON0 + reason]);
	if (zone_slot >= 0 && zone_slot < FW_ZONE_SLOTS) {
		s = rcu_dereference(fw_active);
		if (s)
			atomic64_inc(&s->zone_drop[zone_slot]);
	}
	return NF_DROP;
}

void fw_count_accept(const struct sk_buff *skb, int zone_slot)
{
	struct fw_snap *s;

	this_cpu_inc(fw_pcpu->v[FW_S_ACCEPT_PKTS]);
	this_cpu_add(fw_pcpu->v[FW_S_ACCEPT_BYTES], skb->len);
	if (zone_slot >= 0 && zone_slot < FW_ZONE_SLOTS) {
		s = rcu_dereference(fw_active);
		if (s)
			atomic64_inc(&s->zone_accept[zone_slot]);
	}
}
