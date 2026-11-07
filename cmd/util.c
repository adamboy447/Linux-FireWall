/*
 * util.c - parsing and formatting of addresses, ports and protocols.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "uapp.h"

int parse_ip(const char *s, uint32_t *ip)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		return -1;
	*ip = ntohl(a.s_addr);
	return 0;
}

/* "any", "a.b.c.d" (= /32) or "a.b.c.d/n" */
int parse_cidr(const char *s, uint32_t *ip, uint32_t *mask)
{
	char buf[32], *slash, *end;
	long bits = 32;

	if (strcasecmp(s, "any") == 0) {
		*ip = *mask = 0;
		return 0;
	}
	if (strlen(s) >= sizeof(buf))
		return -1;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (slash) {
		*slash = '\0';
		errno = 0;
		bits = strtol(slash + 1, &end, 10);
		if (errno || *end || end == slash + 1 || bits < 0 || bits > 32)
			return -1;
	}
	if (parse_ip(buf, ip))
		return -1;
	*mask = bits ? 0xFFFFFFFFu << (32 - bits) : 0;
	*ip &= *mask;
	return 0;
}

static int parse_port(const char *s, uint16_t *p)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno || *end || end == s || v < 0 || v > 65535)
		return -1;
	*p = (uint16_t)v;
	return 0;
}

/* "any", "80" or "8000-8100" */
int parse_ports(const char *s, uint16_t *lo, uint16_t *hi)
{
	char buf[16], *dash;

	if (strcasecmp(s, "any") == 0) {
		*lo = 0;
		*hi = 65535;
		return 0;
	}
	if (strlen(s) >= sizeof(buf))
		return -1;
	strcpy(buf, s);
	dash = strchr(buf, '-');
	if (!dash)
		return parse_port(buf, lo) ? -1 : (*hi = *lo, 0);
	*dash = '\0';
	if (parse_port(buf, lo) || parse_port(dash + 1, hi) || *lo > *hi)
		return -1;
	return 0;
}

int parse_proto(const char *s, uint8_t *proto)
{
	if (!strcasecmp(s, "tcp"))
		*proto = IPPROTO_TCP;
	else if (!strcasecmp(s, "udp"))
		*proto = IPPROTO_UDP;
	else if (!strcasecmp(s, "icmp"))
		*proto = IPPROTO_ICMP;
	else if (!strcasecmp(s, "any") || !strcasecmp(s, "ip"))
		*proto = 0;
	else
		return -1;
	return 0;
}

int parse_action(const char *s, uint8_t *action)
{
	if (!strcasecmp(s, "accept") || !strcmp(s, "1"))
		*action = FW_ACT_ACCEPT;
	else if (!strcasecmp(s, "drop") || !strcmp(s, "0"))
		*action = FW_ACT_DROP;
	else
		return -1;
	return 0;
}

const char *proto_name(uint8_t proto)
{
	switch (proto) {
	case 0: return "any";
	case IPPROTO_TCP: return "tcp";
	case IPPROTO_UDP: return "udp";
	case IPPROTO_ICMP: return "icmp";
	default: return "other";
	}
}

void fmt_ip(uint32_t ip, char *buf, size_t n)
{
	struct in_addr a = { .s_addr = htonl(ip) };

	inet_ntop(AF_INET, &a, buf, n);
}

void fmt_cidr(uint32_t ip, uint32_t mask, char *buf, size_t n)
{
	char s[INET_ADDRSTRLEN];
	int bits = __builtin_popcount(mask);

	if (mask == 0) {
		snprintf(buf, n, "any");
		return;
	}
	fmt_ip(ip, s, sizeof(s));
	if (bits == 32)
		snprintf(buf, n, "%s", s);
	else
		snprintf(buf, n, "%s/%d", s, bits);
}

void fmt_ports(uint16_t lo, uint16_t hi, char *buf, size_t n)
{
	if (lo == 0 && hi == 65535)
		snprintf(buf, n, "any");
	else if (lo == hi)
		snprintf(buf, n, "%u", lo);
	else
		snprintf(buf, n, "%u-%u", lo, hi);
}

/* "ip:port" for TCP/UDP, plain "ip" otherwise */
void fmt_endpoint(uint32_t ip, uint16_t port, uint8_t proto, char *buf, size_t n)
{
	char s[INET_ADDRSTRLEN];

	fmt_ip(ip, s, sizeof(s));
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
		snprintf(buf, n, "%s:%u", s, port);
	else
		snprintf(buf, n, "%s", s);
}

int parse_u32(const char *s, uint32_t *v)
{
	char *end;
	unsigned long x;

	if (!s || !*s)
		return -1;
	errno = 0;
	x = strtoul(s, &end, 10);
	if (errno || *end || x > 0xffffffffUL || *s == '-')
		return -1;
	*v = (uint32_t)x;
	return 0;
}

/* ids: 1-63 characters of [A-Za-z0-9._:-] (no spaces: they must survive save/load) */
int valid_id(const char *s)
{
	size_t n = strlen(s);

	if (n == 0 || n >= FW_ID_LEN)
		return 0;
	for (; *s; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		      (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-' || *s == ':'))
			return 0;
	return 1;
}

const char *reason_name(int r)
{
	static const char *names[] = {
		[FW_R_NONE] = "none", [FW_R_RULE] = "rule", [FW_R_DEFAULT] = "default_policy",
		[FW_R_SPOOF] = "spoofed_source", [FW_R_FLOW_IFACE] = "flow_interface",
		[FW_R_FLOW_FULL] = "flow_table_full", [FW_R_NOMEM] = "no_memory",
		[FW_R_NAT_ALLOC] = "nat_allocation_failed", [FW_R_NAT_STATE] = "nat_state_missing",
		[FW_R_NAT_MANGLE] = "nat_rewrite_failed", [FW_R_PARSE] = "parse_error",
		[FW_R_FRAGMENT] = "unsupported_fragment", [FW_R_UNSUPPORTED] = "unsupported_protocol",
		[FW_R_GATE] = "update_gate", [FW_R_GENERATION] = "generation_mismatch",
		[FW_R_IPV6] = "ipv6", [FW_R_EGRESS] = "egress_mismatch",
	};

	if (r >= 0 && r < FW_R__COUNT && names[r])
		return names[r];
	return "unknown";
}

const char *scope_name(int s)
{
	return s == FW_SCOPE_INGRESS ? "ingress" : s == FW_SCOPE_LOCAL_OUT ? "local_out" : "any";
}

void json_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		if (*s == '"' || *s == '\\')
			fprintf(f, "\\%c", *s);
		else if ((unsigned char)*s < 0x20)
			fprintf(f, "\\u%04x", *s);
		else
			fputc(*s, f);
	}
	fputc('"', f);
}
