#ifndef UAPP_H
#define UAPP_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "fw_proto.h"

_Static_assert(sizeof(struct fw_req_hdr) == 16, "ABI");
_Static_assert(sizeof(struct fw_rsp_hdr) == 144, "ABI");
_Static_assert(sizeof(struct fw_policy_hdr) == 176, "ABI");
_Static_assert(sizeof(struct fw_zone_spec) == 152, "ABI");
_Static_assert(sizeof(struct fw_rule_spec) == 96, "ABI");
_Static_assert(sizeof(struct fw_nat_spec) == 112, "ABI");
_Static_assert(sizeof(struct fw_event) == 112, "ABI");

/* ------------------------------------------------------------- nl.c
 * One session = one netlink socket. A staged candidate belongs to the
 * session that began it, so stage/chunk/validate/commit use one session. */
struct fw_nl {
	int fd;
};

int  fw_open(struct fw_nl *nl);
void fw_close(struct fw_nl *nl);
/* Send one request, receive its response. Returns 0 or -errno. On return
 * *hdr (if not NULL) points to a malloc'd buffer: header followed by body. */
int  fw_req(struct fw_nl *nl, uint32_t type, const void *payload, size_t len,
	    struct fw_rsp_hdr **hdr, void **body);
const char *fw_strerror(int err);

/* --------------------------------------------------------- policy.c */
struct pol {
	struct fw_policy_hdr h;
	struct fw_zone_spec zones[FW_MAX_ZONES];
	struct fw_rule_spec rules[FW_MAX_RULES];
	struct fw_nat_spec nats[FW_MAX_NATS];
};

void   pol_init(struct pol *p, int default_action);
int    pol_decode(const uint8_t *blob, size_t len, struct pol *p, char *err, size_t errlen);
size_t pol_size(const struct pol *p);
size_t pol_encode(const struct pol *p, uint8_t *out);           /* out >= pol_size() */
int    pol_zone_index(const struct pol *p, const char *name);   /* 1-based, 0 = none */
int    pol_rule_index(const struct pol *p, const char *id);     /* -1 = none */

/* read the complete active policy (paged; verifies size and SHA-256) */
int fw_fetch_policy(struct fw_nl *nl, uint8_t **blob, size_t *len, uint32_t *gen);

struct apply_opts {
	uint32_t expected_gen;
	int validate_only;      /* stage + validate, then abort */
	int stop_after_chunks;  /* test hook: exit after N chunks (-1 = off) */
	int hold_seconds;       /* test hook: wait between validate and commit */
	int chunk_size;
};
/* stage, validate and commit a blob in one session */
int fw_apply_blob(struct fw_nl *nl, const uint8_t *blob, size_t len,
		  const struct apply_opts *o, struct fw_commit_result *res,
		  char *err, size_t errlen);

/* ----------------------------------------------------------- util.c */
int  parse_cidr(const char *s, uint32_t *ip, uint32_t *mask);
int  parse_ip(const char *s, uint32_t *ip);
int  parse_ports(const char *s, uint16_t *lo, uint16_t *hi);
int  parse_proto(const char *s, uint8_t *proto);
int  parse_action(const char *s, uint8_t *action);
int  parse_u32(const char *s, uint32_t *v);
int  valid_id(const char *s);
void fmt_ip(uint32_t ip, char *buf, size_t n);
void fmt_cidr(uint32_t ip, uint32_t mask, char *buf, size_t n);
void fmt_ports(uint16_t lo, uint16_t hi, char *buf, size_t n);
void fmt_endpoint(uint32_t ip, uint16_t port, uint8_t proto, char *buf, size_t n);
const char *proto_name(uint8_t proto);
const char *reason_name(int reason);
const char *scope_name(int scope);
void json_str(FILE *f, const char *s);

/* --------------------------------------------------------- sha256.c */
void sha256_buf(const void *data, size_t len, uint8_t out[32]);
void sha256_hex(const void *data, size_t len, char out[65]);

#endif
