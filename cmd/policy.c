/*
 * policy.c - encode/decode policy blobs, fetch the active policy, and stage,
 * validate and commit a candidate in one netlink session.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "uapp.h"

void pol_init(struct pol *p, int default_action)
{
	memset(p, 0, sizeof(*p));
	p->h.magic = FW_POLICY_MAGIC;
	p->h.version = FW_UAPI_VERSION;
	p->h.default_action = default_action;
}

size_t pol_size(const struct pol *p)
{
	return sizeof(p->h) + p->h.n_zones * sizeof(struct fw_zone_spec) +
	       p->h.n_rules * sizeof(struct fw_rule_spec) + p->h.n_nats * sizeof(struct fw_nat_spec);
}

size_t pol_encode(const struct pol *p, uint8_t *out)
{
	uint8_t *o = out;

	memcpy(o, &p->h, sizeof(p->h));
	o += sizeof(p->h);
	memcpy(o, p->zones, p->h.n_zones * sizeof(p->zones[0]));
	o += p->h.n_zones * sizeof(p->zones[0]);
	memcpy(o, p->rules, p->h.n_rules * sizeof(p->rules[0]));
	o += p->h.n_rules * sizeof(p->rules[0]);
	memcpy(o, p->nats, p->h.n_nats * sizeof(p->nats[0]));
	o += p->h.n_nats * sizeof(p->nats[0]);
	return (size_t)(o - out);
}

int pol_decode(const uint8_t *blob, size_t len, struct pol *p, char *err, size_t errlen)
{
	const uint8_t *q = blob;

	if (len < sizeof(p->h)) {
		snprintf(err, errlen, "policy blob too short");
		return -1;
	}
	memset(p, 0, sizeof(*p));
	memcpy(&p->h, q, sizeof(p->h));
	if (p->h.magic != FW_POLICY_MAGIC || p->h.version != FW_UAPI_VERSION ||
	    p->h.n_zones > FW_MAX_ZONES || p->h.n_rules > FW_MAX_RULES || p->h.n_nats > FW_MAX_NATS ||
	    pol_size(p) != len) {
		snprintf(err, errlen, "not a valid UAPI v%d policy blob", FW_UAPI_VERSION);
		return -1;
	}
	q += sizeof(p->h);
	memcpy(p->zones, q, p->h.n_zones * sizeof(p->zones[0]));
	q += p->h.n_zones * sizeof(p->zones[0]);
	memcpy(p->rules, q, p->h.n_rules * sizeof(p->rules[0]));
	q += p->h.n_rules * sizeof(p->rules[0]);
	memcpy(p->nats, q, p->h.n_nats * sizeof(p->nats[0]));
	return 0;
}

int pol_zone_index(const struct pol *p, const char *name)
{
	uint32_t i;

	for (i = 0; i < p->h.n_zones; i++)
		if (!strcmp(p->zones[i].name, name))
			return (int)i + 1;
	return 0;
}

int pol_rule_index(const struct pol *p, const char *id)
{
	uint32_t i;

	for (i = 0; i < p->h.n_rules; i++)
		if (!strcmp(p->rules[i].id, id))
			return (int)i;
	return -1;
}

int fw_fetch_policy(struct fw_nl *nl, uint8_t **blob, size_t *len, uint32_t *gen)
{
	struct fw_page_req pr = { 0 };
	struct fw_rsp_hdr *h;
	uint8_t *buf = NULL;
	uint64_t total = 0;
	uint32_t g = 0;
	char want[FW_HASH_LEN] = "", got[65];
	void *body;
	int err;

	do {
		err = fw_req(nl, FW_REQ_GET_POLICY, &pr, sizeof(pr), &h, &body);
		if (err) {
			free(h);
			free(buf);
			return err;
		}
		if (pr.offset == 0) {
			total = h->total;
			g = (uint32_t)h->b;
			memcpy(want, h->msg, sizeof(want) - 1);
			buf = malloc(total ? total : 1);
			if (!buf) {
				free(h);
				return -ENOMEM;
			}
		} else if (h->total != total || (uint32_t)h->b != g) {
			/* the policy was replaced while we were reading it: start over */
			free(h);
			pr.offset = 0;
			free(buf);
			buf = NULL;
			continue;
		}
		if (h->count == 0 && pr.offset < total) {
			free(h);
			free(buf);
			return -EIO;
		}
		memcpy(buf + pr.offset, body, h->count);
		pr.offset += h->count;
		free(h);
	} while (pr.offset < total);

	sha256_hex(buf, total, got);
	if (strcmp(got, want)) {
		free(buf);
		return -EBADMSG;        /* export incomplete or corrupted */
	}
	*blob = buf;
	*len = total;
	if (gen)
		*gen = g;
	return 0;
}

static int simple_req(struct fw_nl *nl, uint32_t type, const void *pl, size_t len,
		      char *err, size_t errlen)
{
	struct fw_rsp_hdr *h;
	void *body;
	int ret = fw_req(nl, type, pl, len, &h, &body);

	if (ret)
		snprintf(err, errlen, "%s", h && h->type == FW_RSP_ERR && h->msg[0] ? h->msg : fw_strerror(ret));
	free(h);
	return ret;
}

int fw_apply_blob(struct fw_nl *nl, const uint8_t *blob, size_t len,
		  const struct apply_opts *o, struct fw_commit_result *res,
		  char *err, size_t errlen)
{
	struct fw_stage_begin b = { .size = (uint32_t)len };
	struct fw_stage_commit c = { .expected_generation = o->expected_gen };
	size_t off = 0, csz = o->chunk_size > 0 ? (size_t)o->chunk_size : FW_MAX_CHUNK;
	struct fw_rsp_hdr *h;
	void *body;
	uint8_t *msg;
	int ret, chunks = 0;

	sha256_buf(blob, len, b.sha256);
	ret = simple_req(nl, FW_REQ_STAGE_BEGIN, &b, sizeof(b), err, errlen);
	if (ret)
		return ret;
	msg = malloc(sizeof(struct fw_stage_chunk) + csz);
	if (!msg)
		return -ENOMEM;
	while (off < len) {
		struct fw_stage_chunk *ch = (struct fw_stage_chunk *)msg;
		size_t n = len - off < csz ? len - off : csz;

		if (o->stop_after_chunks >= 0 && chunks == o->stop_after_chunks) {
			/* test hook: vanish mid-transfer, leaving the candidate staged */
			free(msg);
			snprintf(err, errlen, "stopped after %d chunk(s) (test hook)", chunks);
			return -EINTR;
		}
		ch->offset = (uint32_t)off;
		ch->len = (uint32_t)n;
		memcpy(ch + 1, blob + off, n);
		ret = simple_req(nl, FW_REQ_STAGE_CHUNK, msg, sizeof(*ch) + n, err, errlen);
		if (ret) {
			free(msg);
			return ret;
		}
		off += n;
		chunks++;
	}
	free(msg);
	ret = simple_req(nl, FW_REQ_STAGE_VALIDATE, NULL, 0, err, errlen);
	if (ret)
		return ret;
	if (o->validate_only) {
		char e2[96];

		simple_req(nl, FW_REQ_STAGE_ABORT, NULL, 0, e2, sizeof(e2));
		snprintf(err, errlen, "candidate valid (not committed)");
		return 0;
	}
	if (o->hold_seconds > 0)
		sleep((unsigned int)o->hold_seconds);
	ret = fw_req(nl, FW_REQ_STAGE_COMMIT, &c, sizeof(c), &h, &body);
	if (ret) {
		snprintf(err, errlen, "%s", h && h->msg[0] ? h->msg : fw_strerror(ret));
		free(h);
		return ret;
	}
	memcpy(res, body, sizeof(*res));
	free(h);
	return 0;
}
