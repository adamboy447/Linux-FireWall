/*
 * nl.c - netlink request/response exchange with the myfw module.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include "uapp.h"

#define RECV_BUF (FW_MAX_RSP_BYTES + 4096)

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
	default:
		return strerror(-err);
	}
}

int fw_call(const struct fw_request *req, struct fw_rsp_hdr **hdr, void **body)
{
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 3 };
	struct {
		struct nlmsghdr nlh;
		struct fw_request req;
	} msg;
	struct nlmsghdr *rnlh;
	char *buf;
	ssize_t n;
	int fd, err;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_MYFW);
	if (fd < 0)
		return -errno;
	/* nl_pid = 0: let the kernel assign a unique port id */
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		err = -errno;
		close(fd);
		return err;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&msg, 0, sizeof(msg));
	msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(msg.req));
	msg.req = *req;
	if (sendto(fd, &msg, msg.nlh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	buf = malloc(RECV_BUF);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	n = recv(fd, buf, RECV_BUF, 0);
	err = n < 0 ? -errno : 0;
	close(fd);
	if (err) {
		free(buf);
		return err;
	}
	rnlh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(rnlh, (size_t)n) || NLMSG_PAYLOAD(rnlh, 0) < sizeof(struct fw_rsp_hdr)) {
		free(buf);
		return -EBADMSG;
	}
	/* move the payload to the start of the buffer so free(*hdr) works */
	memmove(buf, NLMSG_DATA(rnlh), NLMSG_PAYLOAD(rnlh, 0));
	*hdr = (struct fw_rsp_hdr *)buf;
	*body = buf + sizeof(struct fw_rsp_hdr);
	return (*hdr)->type == FW_RSP_ERR ? (*hdr)->code : 0;
}
