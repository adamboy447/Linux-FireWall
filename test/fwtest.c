/*
 * fwtest - tiny traffic generator used by the end-to-end tests.
 *
 *   fwtest listen tcp|udp PORT SECONDS     echo server; prints "PEER ip:port"
 *   fwtest send   tcp|udp IP PORT [BYTES]  send BYTES (default 32), expect them
 *                                          echoed back intact; prints OK/FAIL
 *
 * Exit status 0 means the echo came back complete and byte-for-byte correct.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TIMEOUT_MS 2000

static unsigned char pattern(size_t i) { return (unsigned char)(i * 7 + 13); }

static void peer_line(const char *what, struct sockaddr_in *a)
{
	char ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
	printf("%s %s:%u\n", what, ip, ntohs(a->sin_port));
	fflush(stdout);
}

static int do_listen(int tcp, int port, int seconds)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
	int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0), one = 1;
	char buf[65536];

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || (tcp && listen(fd, 16) < 0)) {
		perror("bind/listen");
		return 1;
	}
	alarm(seconds);
	for (;;) {
		struct sockaddr_in p;
		socklen_t pl = sizeof(p);

		if (!tcp) {
			ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&p, &pl);

			if (n < 0)
				continue;
			peer_line("PEER", &p);
			sendto(fd, buf, n, 0, (struct sockaddr *)&p, pl);
			continue;
		}
		int c = accept(fd, (struct sockaddr *)&p, &pl);

		if (c < 0)
			continue;
		peer_line("PEER", &p);
		for (;;) {
			ssize_t n = read(c, buf, sizeof(buf)), off = 0;

			if (n <= 0)
				break;
			while (off < n) {
				ssize_t w = write(c, buf + off, n - off);

				if (w <= 0)
					break;
				off += w;
			}
		}
		close(c);
	}
}

static int do_send(int tcp, const char *ip, int port, size_t bytes)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) }, l;
	socklen_t ll = sizeof(l);
	size_t sent = 0, got = 0;
	unsigned char buf[65536];
	int fd, flags;

	if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
		return 2;
	fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0 && errno != EINPROGRESS) {
		printf("FAIL connect: %s\n", strerror(errno));
		return 1;
	}
	if (tcp) {
		struct pollfd pf = { .fd = fd, .events = POLLOUT };
		int err = 0;
		socklen_t el = sizeof(err);

		if (poll(&pf, 1, TIMEOUT_MS) <= 0) {
			printf("FAIL connect timeout\n");
			return 1;
		}
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
		if (err) {
			printf("FAIL connect: %s\n", strerror(err));
			return 1;
		}
	} else if (bytes > 1400) {
		bytes = 1400;
	}
	getsockname(fd, (struct sockaddr *)&l, &ll);

	/* send and receive concurrently so a large echo cannot deadlock */
	while (got < bytes) {
		struct pollfd pf = { .fd = fd, .events = POLLIN | (sent < bytes ? POLLOUT : 0) };

		if (poll(&pf, 1, TIMEOUT_MS) <= 0) {
			printf("FAIL timeout (sent %zu, received %zu of %zu)\n", sent, got, bytes);
			return 1;
		}
		if ((pf.revents & POLLOUT) && sent < bytes) {
			size_t n = bytes - sent > sizeof(buf) ? sizeof(buf) : bytes - sent, i;
			ssize_t w;

			for (i = 0; i < n; i++)
				buf[i] = pattern(sent + i);
			w = send(fd, buf, n, 0);
			if (w > 0)
				sent += w;
			else if (errno != EAGAIN) {
				printf("FAIL send: %s\n", strerror(errno));
				return 1;
			}
		}
		if (pf.revents & (POLLIN | POLLERR | POLLHUP)) {
			ssize_t n = recv(fd, buf, sizeof(buf), 0), i;

			if (n <= 0) {
				printf("FAIL recv: %s\n", n == 0 ? "connection closed" : strerror(errno));
				return 1;
			}
			for (i = 0; i < n; i++) {
				if (buf[i] != pattern(got + i)) {
					printf("FAIL corrupted byte at offset %zu\n", got + i);
					return 1;
				}
			}
			got += n;
		}
	}
	printf("OK %zu bytes echoed intact, ", got);
	peer_line("local", &l);
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	int tcp;

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);
	if (argc >= 5 && !strcmp(argv[1], "listen")) {
		tcp = !strcmp(argv[2], "tcp");
		return do_listen(tcp, atoi(argv[3]), atoi(argv[4]));
	}
	if (argc >= 5 && !strcmp(argv[1], "send")) {
		tcp = !strcmp(argv[2], "tcp");
		return do_send(tcp, argv[3], atoi(argv[4]), argc > 5 ? strtoul(argv[5], NULL, 10) : 32);
	}
	fprintf(stderr, "usage: fwtest listen tcp|udp PORT SECONDS | send tcp|udp IP PORT [BYTES]\n");
	return 2;
}
