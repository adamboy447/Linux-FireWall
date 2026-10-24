/*
 * netlink.c - control channel to uapp.
 *
 * Every request needs CAP_NET_ADMIN (the original accepted commands from any
 * local user). Replies go to the sender's real port id from the socket
 * metadata, not to the pid claimed inside the message.
 */
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <net/sock.h>
#include <net/netlink.h>
#include "fw.h"

static struct sock *nlsk;

static void reply(u32 portid, u32 type, int code, u32 count, u32 total,
		  const void *body, size_t body_len, const char *msg)
{
	struct fw_rsp_hdr hdr = { .type = type, .code = code, .count = count, .total = total };
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	size_t len = sizeof(hdr) + body_len;

	if (msg)
		strscpy(hdr.msg, msg, sizeof(hdr.msg));
	skb = nlmsg_new(len, GFP_KERNEL);
	if (!skb)
		return;
	nlh = nlmsg_put(skb, 0, 0, 0, len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return;
	}
	memcpy(nlmsg_data(nlh), &hdr, sizeof(hdr));
	if (body_len)
		memcpy((u8 *)nlmsg_data(nlh) + sizeof(hdr), body, body_len);
	netlink_unicast(nlsk, skb, portid, MSG_DONTWAIT);
}

static void reply_ok(u32 portid, u32 count, const char *msg)
{
	reply(portid, FW_RSP_OK, 0, count, count, NULL, 0, msg);
}

static void reply_err(u32 portid, int err, const char *msg)
{
	reply(portid, FW_RSP_ERR, err, 0, 0, NULL, 0, msg);
}

/* Allocate a body buffer for up to FW_MAX_RSP_BYTES worth of elements. */
#define DUMP(portid, rsp, elem_t, dumpfn, ...) do {				\
	u32 _max = FW_MAX_RSP_BYTES / sizeof(elem_t), _total, _n;		\
	elem_t *_buf = kvmalloc_array(_max, sizeof(elem_t), GFP_KERNEL);	\
	if (!_buf) { reply_err(portid, -ENOMEM, "out of memory"); break; }	\
	_n = dumpfn(__VA_ARGS__ _buf, _max, &_total);				\
	reply(portid, rsp, 0, _n, _total, _buf, _n * sizeof(elem_t), NULL);	\
	kvfree(_buf);								\
} while (0)

static u32 dump_logs_last(u32 want, struct fw_log *buf, u32 max, u32 *total)
{
	return fw_log_dump(buf, want && want < max ? want : max, total);
}

static void handle(u32 portid, struct fw_request *req)
{
	char msg[64];
	int ret;

	req->name[FW_NAME_LEN - 1] = '\0';
	if (req->type == FW_REQ_ADD_RULE)       /* u is a union: only then is it a rule */
		req->u.rule.name[FW_NAME_LEN - 1] = '\0';

	switch (req->type) {
	case FW_REQ_STATUS: {
		struct fw_status st = {
			.version = FW_PROTO_VERSION,
			.default_action = READ_ONCE(fw_default_action),
			.log_default = READ_ONCE(fw_log_default),
			.n_rules = fw_rules_count(),
			.n_nats = fw_nat_count(),
			.n_conns = fw_conn_count(),
			.n_logs = fw_log_count(),
			.max_conns = fw_max_conns,
			.max_logs = FW_MAX_LOGS,
			.tcp_timeout = fw_tcp_timeout,
			.udp_timeout = fw_udp_timeout,
			.icmp_timeout = fw_icmp_timeout,
			.pkts_accepted = atomic64_read(&fw_stat_accepted),
			.pkts_dropped = atomic64_read(&fw_stat_dropped),
			.pkts_stateful = atomic64_read(&fw_stat_stateful),
			.pkts_natted = atomic64_read(&fw_stat_natted),
		};
		reply(portid, FW_RSP_STATUS, 0, 1, 1, &st, sizeof(st), NULL);
		break;
	}
	case FW_REQ_GET_RULES:
		DUMP(portid, FW_RSP_RULES, struct fw_rule, fw_rules_dump);
		break;
	case FW_REQ_ADD_RULE: {
		struct fw_rule *r = &req->u.rule;

		if (!r->name[0])
			{ reply_err(portid, -EINVAL, "rule name is empty"); break; }
		if (r->sport_min > r->sport_max || r->dport_min > r->dport_max)
			{ reply_err(portid, -EINVAL, "bad port range"); break; }
		if (r->action != FW_ACT_ACCEPT && r->action != FW_ACT_DROP)
			{ reply_err(portid, -EINVAL, "bad action"); break; }
		ret = fw_rules_add(r, req->arg, req->name);
		if (ret == -ENOENT)
			reply_err(portid, ret, "no rule with that name to insert after");
		else if (ret)
			reply_err(portid, ret, "cannot add rule");
		else
			reply_ok(portid, 1, "rule added");
		break;
	}
	case FW_REQ_DEL_RULE:
		ret = fw_rules_del(req->name);
		if (!ret)
			reply_err(portid, -ENOENT, "no such rule");
		else {
			snprintf(msg, sizeof(msg), "deleted %d rule(s)", ret);
			reply_ok(portid, ret, msg);
		}
		break;
	case FW_REQ_FLUSH_RULES:
		ret = fw_rules_flush();
		fw_conn_flush_all();            /* nothing is allowed by a rule any more */
		snprintf(msg, sizeof(msg), "flushed %d rule(s)", ret);
		reply_ok(portid, ret, msg);
		break;
	case FW_REQ_SET_DEFAULT: {
		unsigned int act = req->arg & 0xff;

		if (act != FW_ACT_ACCEPT && act != FW_ACT_DROP)
			{ reply_err(portid, -EINVAL, "bad action"); break; }
		WRITE_ONCE(fw_log_default, !!(req->arg & FW_DEFAULT_LOG));
		WRITE_ONCE(fw_default_action, act);
		/* flows that only exist because the old default allowed them */
		if (act == FW_ACT_DROP)
			fw_conn_flush_default();
		snprintf(msg, sizeof(msg), "default action is now %s%s",
			 act == FW_ACT_ACCEPT ? "ACCEPT" : "DROP",
			 fw_log_default ? " (logged)" : "");
		reply_ok(portid, 0, msg);
		break;
	}
	case FW_REQ_GET_LOGS:
		DUMP(portid, FW_RSP_LOGS, struct fw_log, dump_logs_last, req->arg,);
		break;
	case FW_REQ_CLEAR_LOGS:
		fw_log_clear();
		reply_ok(portid, 0, "logs cleared");
		break;
	case FW_REQ_GET_CONNS:
		DUMP(portid, FW_RSP_CONNS, struct fw_conn, fw_conn_dump);
		break;
	case FW_REQ_FLUSH_CONNS:
		ret = fw_conn_flush_all();
		snprintf(msg, sizeof(msg), "flushed %d connection(s)", ret);
		reply_ok(portid, ret, msg);
		break;
	case FW_REQ_GET_NATS:
		DUMP(portid, FW_RSP_NATS, struct fw_nat_rule, fw_nat_dump);
		break;
	case FW_REQ_ADD_NAT:
		ret = fw_nat_add(&req->u.nat);
		if (ret)
			reply_err(portid, ret, "invalid NAT rule");
		else
			reply_ok(portid, 1, "NAT rule added");
		break;
	case FW_REQ_DEL_NAT:
		ret = fw_nat_del(req->arg);
		if (ret)
			reply_err(portid, ret, "no NAT rule with that number");
		else
			reply_ok(portid, 1, "NAT rule deleted");
		break;
	case FW_REQ_FLUSH_NATS:
		ret = fw_nat_flush();
		snprintf(msg, sizeof(msg), "flushed %d NAT rule(s)", ret);
		reply_ok(portid, ret, msg);
		break;
	default:
		reply_err(portid, -EOPNOTSUPP, "unknown request");
	}
}

static void fw_nl_recv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	u32 portid = NETLINK_CB(skb).portid;
	struct fw_request req;

	if (skb->len < NLMSG_HDRLEN || nlh->nlmsg_len < NLMSG_HDRLEN ||
	    skb->len < nlh->nlmsg_len)
		return;
	if (!netlink_capable(skb, CAP_NET_ADMIN)) {
		reply_err(portid, -EPERM, "CAP_NET_ADMIN required (run as root)");
		return;
	}
	if (nlmsg_len(nlh) < (int)sizeof(req)) {
		reply_err(portid, -EINVAL, "request too short (uapp/module version mismatch?)");
		return;
	}
	memcpy(&req, nlmsg_data(nlh), sizeof(req));
	handle(portid, &req);
}

int fw_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = { .input = fw_nl_recv };

	nlsk = netlink_kernel_create(&init_net, NETLINK_MYFW, &cfg);
	return nlsk ? 0 : -ENOMEM;
}

void fw_netlink_exit(void)
{
	netlink_kernel_release(nlsk);
}
