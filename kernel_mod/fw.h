/*
 * fw.h - internal interfaces of the myfw kernel module.
 */
#ifndef MYFW_FW_H
#define MYFW_FW_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/netfilter.h>

#include "fw_proto.h"

#define FW_TAG "myfw: "

/* ---------- module parameters (mod_main.c) ---------- */
extern unsigned int fw_tcp_timeout;        /* idle timeout of a TCP flow, seconds */
extern unsigned int fw_tcp_close_timeout;  /* after FIN/RST, seconds */
extern unsigned int fw_udp_timeout;
extern unsigned int fw_icmp_timeout;
extern unsigned int fw_max_conns;

/* ---------- global policy & counters (hooks.c) ---------- */
extern unsigned int fw_default_action;     /* FW_ACT_* */
extern unsigned int fw_log_default;        /* log packets decided by the default policy */
extern atomic64_t fw_stat_accepted, fw_stat_dropped, fw_stat_stateful, fw_stat_natted;

/* ---------- packets (pkt.c) ---------- */
struct fw_tuple {
	u32 saddr, daddr;       /* host byte order */
	u16 sport, dport;       /* TCP/UDP ports; ICMP echo id in both; else 0 */
	u8  proto;
};

#define FW_TCP_FIN_RST  0x1

int  fw_pkt_tuple(const struct sk_buff *skb, struct fw_tuple *t, u8 *flags);
u32  fw_pkt_payload_len(const struct sk_buff *skb);
int  fw_pkt_mangle(struct sk_buff *skb, bool src, u32 new_addr, u16 new_port);
bool fw_ip_match(u32 ip, u32 net, u32 mask);

/* ---------- filter rules (rules.c) ---------- */
/* Returns true if a rule matched; *out receives a copy (counters updated). */
bool fw_rules_match(const struct fw_tuple *t, u32 len, struct fw_rule *out);
bool fw_rule_matches(const struct fw_rule *r, const struct fw_tuple *t);
int  fw_rules_add(const struct fw_rule *r, u32 where, const char *after);
int  fw_rules_del(const char *name);
int  fw_rules_flush(void);
u32  fw_rules_count(void);
u32  fw_rules_dump(struct fw_rule *buf, u32 max, u32 *total);

/* ---------- connection table (conn.c) ---------- */
int  fw_conn_init(void);
void fw_conn_exit(void);
/* Looks up a flow in either direction and refreshes it; true if found. */
bool fw_conn_lookup(const struct fw_tuple *t, u8 flags);
int  fw_conn_add(const struct fw_tuple *t, bool by_default);
/* NAT hooks: decide and apply translation for this packet. */
unsigned int fw_conn_nat_pre(struct sk_buff *skb, const struct fw_tuple *t);
unsigned int fw_conn_nat_post(struct sk_buff *skb, const struct fw_tuple *t);
/* Drop flows whose original direction matches the rule (proto ignored if 0). */
u32  fw_conn_flush_matching(const struct fw_rule *r);
u32  fw_conn_flush_default(void);
u32  fw_conn_flush_nat(void);
u32  fw_conn_flush_all(void);
u32  fw_conn_count(void);
u32  fw_conn_dump(struct fw_conn *buf, u32 max, u32 *total);

/* ---------- NAT rules (nat.c) ---------- */
bool fw_nat_match_snat(const struct fw_tuple *t, struct fw_nat_rule *out);
bool fw_nat_match_dnat(const struct fw_tuple *t, struct fw_nat_rule *out);
int  fw_nat_add(const struct fw_nat_rule *r);
int  fw_nat_del(u32 seq);
int  fw_nat_flush(void);
u32  fw_nat_count(void);
u32  fw_nat_dump(struct fw_nat_rule *buf, u32 max, u32 *total);

/* ---------- log ring (log.c) ---------- */
#define FW_MAX_LOGS 1000
void fw_log_add(const struct fw_tuple *t, u32 len, u8 action, bool by_default, const char *rule);
void fw_log_clear(void);
u32  fw_log_count(void);
u32  fw_log_dump(struct fw_log *buf, u32 max, u32 *total);

/* ---------- netlink (netlink.c) ---------- */
int  fw_netlink_init(void);
void fw_netlink_exit(void);

/* ---------- hooks (hooks.c) ---------- */
int  fw_hooks_init(void);
void fw_hooks_exit(void);

#endif
