#ifndef UAPP_H
#define UAPP_H

#include <stdint.h>
#include <stdio.h>
#include "fw_proto.h"

/* nl.c: send one request, receive one response. Returns 0 or -errno.
 * On success *hdr and *body point into a malloc'd buffer (free(*hdr)). */
int fw_call(const struct fw_request *req, struct fw_rsp_hdr **hdr, void **body);
const char *fw_strerror(int err);

/* util.c */
int  parse_cidr(const char *s, uint32_t *ip, uint32_t *mask);
int  parse_ip(const char *s, uint32_t *ip);
int  parse_ports(const char *s, uint16_t *lo, uint16_t *hi);
int  parse_proto(const char *s, uint8_t *proto);
int  parse_action(const char *s, uint8_t *action);
void fmt_ip(uint32_t ip, char *buf, size_t n);
void fmt_cidr(uint32_t ip, uint32_t mask, char *buf, size_t n);
void fmt_ports(uint16_t lo, uint16_t hi, char *buf, size_t n);
void fmt_endpoint(uint32_t ip, uint16_t port, uint8_t proto, char *buf, size_t n);
const char *proto_name(uint8_t proto);

#endif
