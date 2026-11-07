/*
 * nl.c - netlink sessions with the myfw module.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include "uapp.h"

#define RECV_BUF (FW_MAX_RSP_BYTES + 8192)

const char *fw_strerror(int err)
{
	switch (err) {
	case -EPROTONOSUPPORT:
		return "the myfw kernel module is not loaded (sudo insmod kernel_mod/myfw.ko)";
	case -EPERM:
		return "permission denied: controlling the firewall needs root (CAP_NET_ADMIN)";
	case -ETIMEDOUT:
	case -EAGAIN:
		return "no answer from the kernel module";
	case -EPROTO:
		return "UAPI version mismatch between uapp and the loaded module";
	case -ESTALE:
		return "generation conflict: the policy changed meanwhile";
	default:
		return strerror(-err);
	}
}

int fw_open(struct fw_nl *nl)
{
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 10 };
	int err;

	nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_MYFW);
	if (nl->fd < 0)
		return -errno;
	/* nl_pid = 0: the kernel assigns a unique port id */
	if (bind(nl->fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		err = -errno;
		close(nl->fd);
		nl->fd = -1;
		return err;
	}
	setsockopt(nl->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return 0;
}

void fw_close(struct fw_nl *nl)
{
	if (nl->fd >= 0)
		close(nl->fd);
	nl->fd = -1;
}

int fw_req(struct fw_nl *nl, uint32_t type, const void *payload, size_t len,
	   struct fw_rsp_hdr **hdr, void **body)
{
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct nlmsghdr *nlh, *rnlh;
	struct fw_req_hdr *rh;
	size_t mlen = NLMSG_LENGTH(sizeof(*rh) + len);
	char *buf, *out;
	ssize_t n;
	int err;

	if (hdr)
		*hdr = NULL;
	nlh = calloc(1, NLMSG_SPACE(sizeof(*rh) + len));
	if (!nlh)
		return -ENOMEM;
	nlh->nlmsg_len = mlen;
	rh = NLMSG_DATA(nlh);
	rh->type = type;
	rh->version = FW_UAPI_VERSION;
	rh->len = len;
	if (len)
		memcpy(rh + 1, payload, len);
	n = sendto(nl->fd, nlh, mlen, 0, (struct sockaddr *)&kernel, sizeof(kernel));
	free(nlh);
	if (n < 0)
		return -errno;

	buf = malloc(RECV_BUF);
	if (!buf)
		return -ENOMEM;
	n = recv(nl->fd, buf, RECV_BUF, 0);
	if (n < 0) {
		err = -errno;
		free(buf);
		return err;
	}
	rnlh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(rnlh, (size_t)n) || NLMSG_PAYLOAD(rnlh, 0) < sizeof(struct fw_rsp_hdr)) {
		free(buf);
		return -EBADMSG;
	}
	out = malloc(NLMSG_PAYLOAD(rnlh, 0));
	if (!out) {
		free(buf);
		return -ENOMEM;
	}
	memcpy(out, NLMSG_DATA(rnlh), NLMSG_PAYLOAD(rnlh, 0));
	free(buf);
	err = ((struct fw_rsp_hdr *)out)->type == FW_RSP_ERR ? ((struct fw_rsp_hdr *)out)->code : 0;
	if (hdr) {
		*hdr = (struct fw_rsp_hdr *)out;
		if (body)
			*body = out + sizeof(struct fw_rsp_hdr);
	} else {
		free(out);
	}
	return err;
}
