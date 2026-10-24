/*
 * fw_proto.h - wire protocol shared by the myfw kernel module and the uapp CLI.
 *
 * Both sides include this one file, so the structures can never drift apart.
 * Every address and port in these structures is in HOST byte order.
 */
#ifndef FW_PROTO_H
#define FW_PROTO_H

#include <linux/types.h>

#define NETLINK_MYFW        17      /* netlink protocol number (unused by mainline) */
#define FW_PROTO_VERSION    2
#define FW_NAME_LEN         16      /* rule name buffer, including the NUL */
#define FW_MAX_RSP_BYTES    (60 * 1024)  /* responses are truncated to this size */

/* ---------- requests (uapp -> kernel) ---------- */
enum fw_req_type {
	FW_REQ_STATUS = 1,
	FW_REQ_GET_RULES,
	FW_REQ_ADD_RULE,
	FW_REQ_DEL_RULE,
	FW_REQ_FLUSH_RULES,
	FW_REQ_SET_DEFAULT,
	FW_REQ_GET_LOGS,
	FW_REQ_CLEAR_LOGS,
	FW_REQ_GET_CONNS,
	FW_REQ_FLUSH_CONNS,
	FW_REQ_GET_NATS,
	FW_REQ_ADD_NAT,
	FW_REQ_DEL_NAT,
	FW_REQ_FLUSH_NATS,
};

/* ---------- responses (kernel -> uapp) ---------- */
enum fw_rsp_type {
	FW_RSP_OK = 100,        /* no body, see hdr.msg */
	FW_RSP_ERR,             /* hdr.code holds -errno, hdr.msg a reason */
	FW_RSP_STATUS,          /* body: struct fw_status */
	FW_RSP_RULES,           /* body: struct fw_rule[count] */
	FW_RSP_LOGS,            /* body: struct fw_log[count] */
	FW_RSP_CONNS,           /* body: struct fw_conn[count] */
	FW_RSP_NATS,            /* body: struct fw_nat_rule[count] */
};

#define FW_ACT_DROP     0
#define FW_ACT_ACCEPT   1

/* FW_REQ_ADD_RULE flags (fw_request.arg) */
#define FW_ADD_HEAD     0       /* insert at the top of the chain */
#define FW_ADD_TAIL     1       /* append at the end of the chain */
#define FW_ADD_AFTER    2       /* insert after the rule named in fw_request.name */

/* FW_REQ_SET_DEFAULT: fw_request.arg = action | (log ? FW_DEFAULT_LOG : 0) */
#define FW_DEFAULT_LOG  0x100

struct fw_rule {
	char  name[FW_NAME_LEN];
	__u32 saddr, smask;
	__u32 daddr, dmask;
	__u16 sport_min, sport_max;     /* ports are ignored for ICMP */
	__u16 dport_min, dport_max;
	__u8  proto;                    /* IPPROTO_TCP/UDP/ICMP, 0 = any */
	__u8  action;                   /* FW_ACT_* */
	__u8  log;
	__u8  pad;
	__u64 hit_pkts;                 /* filled in by the kernel */
	__u64 hit_bytes;
};

#define FW_NAT_NONE     0
#define FW_NAT_SNAT     1
#define FW_NAT_DNAT     2

/*
 * SNAT: packets from saddr/smask going to a destination outside that subnet
 *       get their source rewritten to to_addr, with a source port picked from
 *       [to_port_min, to_port_max].
 * DNAT: packets to daddr:dport (proto TCP or UDP) get their destination
 *       rewritten to to_addr:to_port_min (port forwarding).
 */
struct fw_nat_rule {
	__u8  type;                     /* FW_NAT_SNAT / FW_NAT_DNAT */
	__u8  proto;                    /* DNAT only */
	__u16 dport;                    /* DNAT only */
	__u32 saddr, smask;             /* SNAT only */
	__u32 daddr;                    /* DNAT only */
	__u32 to_addr;
	__u16 to_port_min, to_port_max;
	__u64 hits;                     /* filled in by the kernel */
};

struct fw_log {
	__s64 ts;                       /* unix time (seconds) */
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8  proto;
	__u8  action;                   /* FW_ACT_* */
	__u8  by_default;               /* 1 = decided by the default policy */
	__u8  pad;
	__u32 len;                      /* IP payload length */
	char  rule[FW_NAME_LEN];        /* matching rule, empty if by default */
};

struct fw_conn {
	/* original direction, as seen by the first packet */
	__u32 saddr, daddr;
	__u16 sport, dport;
	/* expected reply direction (differs from the inverse when NAT is applied) */
	__u32 r_saddr, r_daddr;
	__u16 r_sport, r_dport;
	__u8  proto;
	__u8  nat_type;                 /* FW_NAT_* */
	__u16 pad;
	__u32 expires_in;               /* seconds until the entry times out */
	__u64 pkts_orig, pkts_reply;
};

struct fw_status {
	__u32 version;
	__u8  default_action;
	__u8  log_default;
	__u16 pad;
	__u32 n_rules, n_nats, n_conns, n_logs;
	__u32 max_conns, max_logs;
	__u32 tcp_timeout, udp_timeout, icmp_timeout;
	__u32 pad2;
	__u64 pkts_accepted, pkts_dropped, pkts_stateful, pkts_natted;
};

struct fw_request {
	__u32 type;                     /* enum fw_req_type */
	__u32 arg;                      /* add flags / default action / log count / NAT seq */
	char  name[FW_NAME_LEN];        /* rule to delete, or "insert after" anchor */
	union {
		struct fw_rule rule;
		struct fw_nat_rule nat;
	} u;
};

struct fw_rsp_hdr {
	__u32 type;                     /* enum fw_rsp_type */
	__s32 code;                     /* 0 or -errno */
	__u32 count;                    /* number of elements in the body */
	__u32 total;                    /* number available (count < total => truncated) */
	char  msg[64];
};

#endif /* FW_PROTO_H */
