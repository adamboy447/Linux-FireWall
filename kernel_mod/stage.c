/*
 * stage.c - candidate staging and the atomic policy switch.
 *
 * There is one staging slot. A candidate is owned by the netlink port that
 * began it; it is released on ABORT, on a successful or failed COMMIT, when
 * it has been idle for stage_timeout seconds, or when the owning socket is
 * closed (e.g. the uapp process was killed half-way). Until COMMIT succeeds
 * the active snapshot is not touched, so an invalid or interrupted candidate
 * can never leave a half-applied policy behind.
 *
 * COMMIT (fw_cfg_mutex held, process context):
 *   1. the caller's expected generation must equal the active one
 *      (optimistic concurrency: two writers cannot both win);
 *   2. interfaces are re-resolved (they may have been recreated);
 *   3. the gate closes: the filter drops new managed packets (FW_R_GATE);
 *   4. the candidate becomes active with generation+1 (rcu_replace_pointer);
 *   5. synchronize_rcu_expedited(): every hook that could still see the old
 *      snapshot has finished;
 *   6. the gate opens; the old snapshot is freed;
 *   7. every flow of an older generation is removed (they are already
 *      unusable: lookups ignore flows of another generation).
 * Packets that were filtered under the old generation and are still between
 * hooks carry the old generation in skb->mark and are dropped by the NAT and
 * delivery hooks (FW_R_GENERATION), so one packet can never be filtered by
 * one policy and translated by another.
 */
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/netlink.h>
#include <linux/notifier.h>
#include <linux/timekeeping.h>
#include <crypto/sha2.h>
#include "fw.h"

enum { ST_IDLE, ST_RECEIVING, ST_VALIDATED };

static struct {
	int state;
	u32 owner;
	u8 *buf;
	u32 size, recv;
	u8 sha[SHA256_DIGEST_SIZE];
	unsigned long touched;
	struct fw_snap *cand;
} st;

static u32 next_gen = 2;        /* the boot snapshot is generation 1 */
static atomic_t released_portid = ATOMIC_INIT(0);
static struct delayed_work stage_work;
u64 fw_last_gate_ns, fw_last_flows_reset;
s64 fw_last_commit_ns;

/* fw_cfg_mutex held */
static void stage_release(const char *why)
{
	bool had = st.state != ST_IDLE;

	kvfree(st.buf);
	fw_snap_free(st.cand);
	memset(&st, 0, sizeof(st));
	if (had && why) {
		fw_stat_add(FW_S_STAGE_ABORTED, 1);
		fw_event_control(FW_EV_STAGE_ABORT, 0, why);
	}
}

static int __owner_check(u32 portid, char *err, size_t errlen)
{
	if (st.state == ST_IDLE) {
		snprintf(err, errlen, "no candidate is staged");
		return -ENOENT;
	}
	if (st.owner != portid) {
		snprintf(err, errlen, "candidate belongs to another session");
		return -EBUSY;
	}
	st.touched = jiffies;
	return 0;
}

static void stage_work_fn(struct work_struct *w)
{
	u32 gone = atomic_xchg(&released_portid, 0);

	mutex_lock(&fw_cfg_mutex);
	if (st.state != ST_IDLE) {
		if (gone && st.owner == gone)
			stage_release("owner closed its socket");
		else if (time_after(jiffies, st.touched + fw_stage_timeout * HZ))
			stage_release("staging timed out");
	}
	mutex_unlock(&fw_cfg_mutex);
	schedule_delayed_work(&stage_work, HZ);
}

static int nl_notify(struct notifier_block *nb, unsigned long what, void *ptr)
{
	struct netlink_notify *n = ptr;

	if (what == NETLINK_URELEASE && n->protocol == NETLINK_MYFW && n->portid) {
		atomic_set(&released_portid, n->portid);
		mod_delayed_work(system_wq, &stage_work, 0);
	}
	return NOTIFY_DONE;
}

static struct notifier_block nl_nb = { .notifier_call = nl_notify };

int fw_stage_begin(u32 portid, const struct fw_stage_begin *b, char *err, size_t errlen)
{
	int ret = 0;

	mutex_lock(&fw_cfg_mutex);
	if (st.state != ST_IDLE) {
		if (st.owner == portid) {
			stage_release(NULL);        /* the same session restarts */
		} else {
			snprintf(err, errlen, "another candidate is being staged");
			ret = -EBUSY;
			goto out;
		}
	}
	if (b->size < sizeof(struct fw_policy_hdr) || b->size > FW_MAX_POLICY_BYTES) {
		snprintf(err, errlen, "candidate size %u out of range (max %u)",
			 b->size, FW_MAX_POLICY_BYTES);
		ret = -EINVAL;
		goto out;
	}
	st.buf = kvmalloc(b->size, GFP_KERNEL);
	if (!st.buf) {
		snprintf(err, errlen, "out of memory");
		ret = -ENOMEM;
		goto out;
	}
	st.state = ST_RECEIVING;
	st.owner = portid;
	st.size = b->size;
	st.recv = 0;
	memcpy(st.sha, b->sha256, sizeof(st.sha));
	st.touched = jiffies;
out:
	mutex_unlock(&fw_cfg_mutex);
	return ret;
}

int fw_stage_chunk(u32 portid, const struct fw_stage_chunk *c, const u8 *data,
		   char *err, size_t errlen)
{
	int ret;

	mutex_lock(&fw_cfg_mutex);
	ret = __owner_check(portid, err, errlen);
	if (ret)
		goto out;
	if (st.state != ST_RECEIVING) {
		snprintf(err, errlen, "candidate already validated");
		ret = -EINVAL;
	} else if (c->offset != st.recv || c->len > FW_MAX_CHUNK || c->len > st.size - st.recv) {
		snprintf(err, errlen, "chunk at %u+%u does not continue %u/%u",
			 c->offset, c->len, st.recv, st.size);
		ret = -EINVAL;
	} else {
		memcpy(st.buf + st.recv, data, c->len);
		st.recv += c->len;
	}
out:
	mutex_unlock(&fw_cfg_mutex);
	return ret;
}

int fw_stage_validate(u32 portid, char *err, size_t errlen)
{
	u8 digest[SHA256_DIGEST_SIZE];
	int ret;

	mutex_lock(&fw_cfg_mutex);
	ret = __owner_check(portid, err, errlen);
	if (ret)
		goto out;
	if (st.state != ST_RECEIVING || st.recv != st.size) {
		snprintf(err, errlen, "candidate incomplete (%u of %u bytes)", st.recv, st.size);
		ret = -EINVAL;
		goto out;
	}
	sha256(st.buf, st.size, digest);
	if (memcmp(digest, st.sha, sizeof(digest))) {
		snprintf(err, errlen, "SHA-256 of the received candidate does not match");
		ret = -EBADMSG;
		goto out;
	}
	st.cand = fw_snap_build(st.buf, st.size, err, errlen);
	if (!st.cand) {
		ret = -EINVAL;
		goto out;
	}
	st.state = ST_VALIDATED;
out:
	if (ret && st.state != ST_IDLE && st.owner == portid)
		stage_release("validation failed");
	mutex_unlock(&fw_cfg_mutex);
	return ret;
}

int fw_stage_commit(u32 portid, const struct fw_stage_commit *c, struct fw_commit_result *res,
		    char *err, size_t errlen)
{
	struct fw_snap *old, *cand;
	u64 t0, flows;
	int ret;

	mutex_lock(&fw_cfg_mutex);
	ret = __owner_check(portid, err, errlen);
	if (ret)
		goto out;
	if (st.state != ST_VALIDATED) {
		snprintf(err, errlen, "candidate not validated");
		ret = -EINVAL;
		goto reject;
	}
	old = rcu_dereference_protected(fw_active, lockdep_is_held(&fw_cfg_mutex));
	if (c->expected_generation != old->gen) {
		snprintf(err, errlen, "generation conflict: expected %u, active is %u",
			 c->expected_generation, old->gen);
		ret = -ESTALE;
		goto reject;
	}
	if (next_gen >= U32_MAX - 1) {
		snprintf(err, errlen, "generation space exhausted; reload the module");
		ret = -EOVERFLOW;
		goto reject;
	}
	ret = fw_snap_recheck_ifaces(st.cand, err, errlen);
	if (ret)
		goto reject;

	cand = st.cand;
	st.cand = NULL;
	cand->gen = next_gen++;

	t0 = ktime_get_ns();
	WRITE_ONCE(fw_gate, 1);
	smp_mb();
	old = rcu_replace_pointer(fw_active, cand, lockdep_is_held(&fw_cfg_mutex));
	synchronize_rcu_expedited();
	smp_mb();
	WRITE_ONCE(fw_gate, 0);
	fw_last_gate_ns = ktime_get_ns() - t0;
	flows = fw_conn_flush_stale(cand->gen);

	fw_last_flows_reset = flows;
	fw_last_commit_ns = ktime_get_real_ns();
	fw_snap_free(old);
	fw_stat_add(FW_S_COMMITS, 1);
	fw_event_control(FW_EV_COMMIT, cand->gen, cand->policy_hash);

	memset(res, 0, sizeof(*res));
	res->generation = cand->gen;
	res->gate_ns = fw_last_gate_ns;
	res->flows_reset = flows;
	strscpy(res->policy_hash, cand->policy_hash, sizeof(res->policy_hash));
	stage_release(NULL);
	goto out;
reject:
	fw_stat_add(FW_S_COMMIT_REJECTED, 1);
	fw_event_control(FW_EV_COMMIT_REJECTED, 0, err);
	stage_release(NULL);
out:
	mutex_unlock(&fw_cfg_mutex);
	return ret;
}

int fw_stage_abort(u32 portid, char *err, size_t errlen)
{
	int ret;

	mutex_lock(&fw_cfg_mutex);
	ret = __owner_check(portid, err, errlen);
	if (!ret)
		stage_release("aborted by request");
	mutex_unlock(&fw_cfg_mutex);
	return ret;
}

void fw_stage_info(u32 *state, u32 *bytes)
{
	mutex_lock(&fw_cfg_mutex);
	*state = st.state;
	*bytes = st.recv;
	mutex_unlock(&fw_cfg_mutex);
}

int fw_stage_init(void)
{
	int ret;

	INIT_DELAYED_WORK(&stage_work, stage_work_fn);
	ret = netlink_register_notifier(&nl_nb);
	if (ret)
		return ret;
	schedule_delayed_work(&stage_work, HZ);
	return 0;
}

void fw_stage_exit(void)
{
	netlink_unregister_notifier(&nl_nb);
	cancel_delayed_work_sync(&stage_work);
	mutex_lock(&fw_cfg_mutex);
	stage_release(NULL);
	mutex_unlock(&fw_cfg_mutex);
}
