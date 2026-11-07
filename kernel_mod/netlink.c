/*
 * netlink.c - control channel (NETLINK_MYFW), UAPI v3.
 *
 * Every request carries struct fw_req_hdr with the UAPI version; a mismatch
 * is refused with -EPROTO, so an old uapp cannot misinterpret new structures.
 * Every request requires CAP_NET_ADMIN, checked here in the kernel (the
 * Python agent adds its own checks but is not trusted for this). Replies go
 * to the sender's real port id. Large answers are paged: the caller passes
 * an offset and the reply says how many elements exist in total, so nothing
 * is silently truncated.
 */
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/capability.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include "fw.h"

static struct sock *nl_sk;

static void send_reply(u32 portid, const struct fw_rsp_hdr *hdr, const void *body, size_t blen)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	size_t len = sizeof(*hdr) + blen;

	skb = nlmsg_new(len, GFP_KERNEL);
	if (!skb)
		return;
	nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return;
	}
	memcpy(nlmsg_data(nlh), hdr, sizeof(*hdr));
	if (blen)
		memcpy((u8 *)nlmsg_data(nlh) + sizeof(*hdr), body, blen);
	netlink_unicast(nl_sk, skb, portid, MSG_DONTWAIT);
}

static void reply_code(u32 portid, int code, u32 count, const char *msg)
{
	struct fw_rsp_hdr h = {
		.type = code ? FW_RSP_ERR : FW_RSP_OK,
		.code = code,
		.version = FW_UAPI_VERSION,
		.count = count,
	};

	if (msg)
		strscpy(h.msg, msg, sizeof(h.msg));
	send_reply(portid, &h, NULL, 0);
}

static void do_abi(u32 portid)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_ABI, .version = FW_UAPI_VERSION, .count = 1 };
	struct fw_abi a = { .uapi_version = FW_UAPI_VERSION };

#define X(name) a.size[a.n++] = sizeof(struct name);
	FW_ABI_LIST(X)
#undef X
	send_reply(portid, &h, &a, sizeof(a));
}

static void do_status(u32 portid)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_STATUS, .version = FW_UAPI_VERSION, .count = 1 };
	struct fw_status st = { .uapi_version = FW_UAPI_VERSION };
	struct fw_snap *s;

	fw_stage_info(&st.stage_state, &st.stage_bytes);
	rcu_read_lock();
	s = rcu_dereference(fw_active);
	st.generation = s->gen;
	st.default_action = s->default_action;
	st.default_log = s->default_log;
	st.flags = s->flags;
	st.n_zones = s->nz;
	st.n_rules = s->nr;
	st.n_nats = s->nn;
	memcpy(st.policy_hash, s->policy_hash, sizeof(st.policy_hash));
	memcpy(st.label, s->label, sizeof(st.label));
	memcpy(st.blob_sha256, s->blob_sha, sizeof(st.blob_sha256));
	rcu_read_unlock();
	st.gate = READ_ONCE(fw_gate);
	st.n_conns = fw_conn_count();
	st.max_conns = fw_max_conns;
	st.tcp_timeout = fw_tcp_timeout;
	st.udp_timeout = fw_udp_timeout;
	st.icmp_timeout = fw_icmp_timeout;
	st.commits = fw_stat_read(FW_S_COMMITS);
	st.last_gate_ns = fw_last_gate_ns;
	st.last_commit_ns = fw_last_commit_ns;
	st.last_flows_reset = fw_last_flows_reset;
	st.event_next_seq = fw_event_next_seq();
	send_reply(portid, &h, &st, sizeof(st));
}

static void do_counters(u32 portid)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_COUNTERS, .version = FW_UAPI_VERSION, .count = 1 };
	struct fw_counters c = {};
	struct fw_snap *s;
	int i;

	rcu_read_lock();
	s = rcu_dereference(fw_active);
	c.generation = s->gen;
	for (i = 0; i < FW_ZONE_SLOTS; i++) {
		c.zone_accept[i] = atomic64_read(&s->zone_accept[i]);
		c.zone_drop[i] = atomic64_read(&s->zone_drop[i]);
	}
	rcu_read_unlock();
	c.n_conns = fw_conn_count();
	c.max_conns = fw_max_conns;
	c.accept_pkts = fw_stat_read(FW_S_ACCEPT_PKTS);
	c.accept_bytes = fw_stat_read(FW_S_ACCEPT_BYTES);
	c.drop_pkts = fw_stat_read(FW_S_DROP_PKTS);
	c.drop_bytes = fw_stat_read(FW_S_DROP_BYTES);
	for (i = 0; i < FW_R_SLOTS; i++)
		c.drop_reason[i] = fw_stat_read(FW_S_REASON0 + i);
	c.new_flow_accept = fw_stat_read(FW_S_NEW_ACCEPT);
	c.new_flow_drop = fw_stat_read(FW_S_NEW_DROP);
	c.stateful_hits = fw_stat_read(FW_S_STATEFUL);
	c.nat_translations = fw_stat_read(FW_S_NAT);
	c.flow_create_failed = fw_stat_read(FW_S_FLOW_FAIL);
	c.nat_alloc_failed = fw_stat_read(FW_S_NAT_ALLOC_FAIL);
	c.events_suppressed = fw_stat_read(FW_S_EV_SUPPRESSED);
	c.events_overwritten = fw_stat_read(FW_S_EV_OVERWRITTEN);
	c.commits = fw_stat_read(FW_S_COMMITS);
	c.commit_rejected = fw_stat_read(FW_S_COMMIT_REJECTED);
	c.stage_aborted = fw_stat_read(FW_S_STAGE_ABORTED);
	send_reply(portid, &h, &c, sizeof(c));
}

/* The snapshot is copied under RCU into a private buffer, then sent. */
static void do_get_policy(u32 portid, const struct fw_page_req *p)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_POLICY, .version = FW_UAPI_VERSION };
	struct fw_snap *s;
	u8 *buf = kvmalloc(FW_MAX_RSP_BYTES, GFP_KERNEL);
	u32 n = 0;

	if (!buf) {
		reply_code(portid, -ENOMEM, 0, "out of memory");
		return;
	}
	rcu_read_lock();
	s = rcu_dereference(fw_active);
	h.total = s->blob_len;
	h.a = p->offset;
	h.b = s->gen;
	if (p->offset < s->blob_len) {
		n = min_t(u32, s->blob_len - p->offset, FW_MAX_RSP_BYTES);
		memcpy(buf, s->blob + p->offset, n);
	}
	strscpy(h.msg, s->blob_sha, sizeof(h.msg));
	rcu_read_unlock();
	h.count = n;
	send_reply(portid, &h, buf, n);
	kvfree(buf);
}

static void do_rule_stats(u32 portid, const struct fw_page_req *p)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_RULE_STATS, .version = FW_UAPI_VERSION };
	u32 cap = FW_MAX_RSP_BYTES / sizeof(struct fw_rule_stat), n = 0, i;
	struct fw_rule_stat *buf;
	struct fw_snap *s;

	if (p->max && p->max < cap)
		cap = p->max;
	buf = kvcalloc(cap, sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		reply_code(portid, -ENOMEM, 0, "out of memory");
		return;
	}
	rcu_read_lock();
	s = rcu_dereference(fw_active);
	h.total = s->nr;
	h.a = p->offset;
	h.b = s->gen;
	for (i = p->offset; i < s->nr && n < cap; i++, n++) {
		memcpy(buf[n].id, s->rules[i].s.id, FW_ID_LEN);
		buf[n].flows = atomic64_read(&s->rules[i].flows);
		buf[n].bytes = atomic64_read(&s->rules[i].bytes);
	}
	rcu_read_unlock();
	h.count = n;
	send_reply(portid, &h, buf, n * sizeof(*buf));
	kvfree(buf);
}

static void do_get_conns(u32 portid, const struct fw_page_req *p)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_CONNS, .version = FW_UAPI_VERSION };
	u32 cap = FW_MAX_RSP_BYTES / sizeof(struct fw_conn_info), total, n;
	struct fw_conn_info *buf;
	struct fw_snap *s;

	if (p->max && p->max < cap)
		cap = p->max;
	buf = kvcalloc(cap, sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		reply_code(portid, -ENOMEM, 0, "out of memory");
		return;
	}
	n = fw_conn_dump(buf, p->offset, cap, &total);
	rcu_read_lock();
	s = rcu_dereference(fw_active);
	h.b = s->gen;
	rcu_read_unlock();
	h.count = n;
	h.total = total;
	h.a = p->offset;
	strscpy(h.msg, "flow pages are taken at different instants", sizeof(h.msg));
	send_reply(portid, &h, buf, n * sizeof(*buf));
	kvfree(buf);
}

static void do_get_events(u32 portid, const struct fw_page_req *p)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_EVENTS, .version = FW_UAPI_VERSION };
	u32 cap = FW_MAX_RSP_BYTES / sizeof(struct fw_event);
	struct fw_event *buf;

	if (p->max && p->max < cap)
		cap = p->max;
	buf = kvcalloc(cap, sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		reply_code(portid, -ENOMEM, 0, "out of memory");
		return;
	}
	h.count = fw_event_dump(buf, p->offset, cap, &h.a, &h.b, &h.c);
	h.total = h.b - h.a;
	send_reply(portid, &h, buf, h.count * sizeof(*buf));
	kvfree(buf);
}

static void do_commit(u32 portid, const struct fw_stage_commit *c)
{
	struct fw_rsp_hdr h = { .type = FW_RSP_COMMIT, .version = FW_UAPI_VERSION, .count = 1 };
	struct fw_commit_result res;
	char err[96] = "";
	int ret;

	ret = fw_stage_commit(portid, c, &res, err, sizeof(err));
	if (ret) {
		reply_code(portid, ret, 0, err);
		return;
	}
	strscpy(h.msg, "committed", sizeof(h.msg));
	send_reply(portid, &h, &res, sizeof(res));
}

#define NEED(sz) do { if (rh->len < (sz)) { reply_code(portid, -EINVAL, 0, "payload too short"); return; } } while (0)

static void nl_input(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	const struct fw_req_hdr *rh;
	const void *pl;
	u32 portid = NETLINK_CB(skb).portid;
	char err[96] = "";
	int ret;

	if (skb->len < NLMSG_HDRLEN || nlh->nlmsg_len < NLMSG_HDRLEN ||
	    nlh->nlmsg_len > skb->len || nlmsg_len(nlh) < (int)sizeof(*rh))
		return;
	rh = nlmsg_data(nlh);
	pl = rh + 1;

	if (!netlink_capable(skb, CAP_NET_ADMIN)) {
		reply_code(portid, -EPERM, 0, "permission denied (CAP_NET_ADMIN required)");
		return;
	}
	if (rh->version != FW_UAPI_VERSION) {
		reply_code(portid, -EPROTO, 0, "UAPI version mismatch: rebuild uapp and the module together");
		return;
	}
	if (rh->len > nlmsg_len(nlh) - sizeof(*rh)) {
		reply_code(portid, -EINVAL, 0, "payload length exceeds message");
		return;
	}

	switch (rh->type) {
	case FW_REQ_ABI:
		do_abi(portid);
		break;
	case FW_REQ_STATUS:
		do_status(portid);
		break;
	case FW_REQ_COUNTERS:
		do_counters(portid);
		break;
	case FW_REQ_GET_POLICY:
		NEED(sizeof(struct fw_page_req));
		do_get_policy(portid, pl);
		break;
	case FW_REQ_RULE_STATS:
		NEED(sizeof(struct fw_page_req));
		do_rule_stats(portid, pl);
		break;
	case FW_REQ_GET_CONNS:
		NEED(sizeof(struct fw_page_req));
		do_get_conns(portid, pl);
		break;
	case FW_REQ_FLUSH_CONNS:
		reply_code(portid, 0, fw_conn_flush_all(), "flows flushed");
		break;
	case FW_REQ_GET_EVENTS:
		NEED(sizeof(struct fw_page_req));
		do_get_events(portid, pl);
		break;
	case FW_REQ_STAGE_BEGIN:
		NEED(sizeof(struct fw_stage_begin));
		ret = fw_stage_begin(portid, pl, err, sizeof(err));
		reply_code(portid, ret, 0, ret ? err : "staging");
		break;
	case FW_REQ_STAGE_CHUNK: {
		const struct fw_stage_chunk *c = pl;

		NEED(sizeof(*c));
		if (c->len > rh->len - sizeof(*c)) {
			reply_code(portid, -EINVAL, 0, "chunk length exceeds payload");
			break;
		}
		ret = fw_stage_chunk(portid, c, (const u8 *)(c + 1), err, sizeof(err));
		reply_code(portid, ret, 0, ret ? err : "chunk stored");
		break;
	}
	case FW_REQ_STAGE_VALIDATE:
		ret = fw_stage_validate(portid, err, sizeof(err));
		reply_code(portid, ret, 0, ret ? err : "candidate valid");
		break;
	case FW_REQ_STAGE_COMMIT:
		NEED(sizeof(struct fw_stage_commit));
		do_commit(portid, pl);
		break;
	case FW_REQ_STAGE_ABORT:
		ret = fw_stage_abort(portid, err, sizeof(err));
		reply_code(portid, ret, 0, ret ? err : "candidate discarded");
		break;
	default:
		reply_code(portid, -EINVAL, 0, "unknown request");
	}
}

int fw_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = { .input = nl_input };

	nl_sk = netlink_kernel_create(&init_net, NETLINK_MYFW, &cfg);
	return nl_sk ? 0 : -ENOMEM;
}

void fw_netlink_exit(void)
{
	netlink_kernel_release(nl_sk);
}
