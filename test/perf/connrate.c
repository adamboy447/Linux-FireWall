/* connrate: TCP connection-setup rate through the firewall.
 *
 *   connrate serve PORT                 accept and close, forever
 *   connrate run IP PORT SECONDS        connect/close in a loop, print conn/s
 *
 * Each connection is a full three-way handshake followed by an abortive close
 * (SO_LINGER 0, so the client does not pile up TIME_WAIT sockets); the firewall
 * still has to create a flow (and, through SNAT, allocate a port) for each one.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static int serve(int port)
{
	int one = 1, s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(s, (void *)&a, sizeof(a)) || listen(s, 1024)) {
		perror("bind/listen");
		return 1;
	}
	for (;;) {
		int c = accept(s, NULL, NULL);
		if (c >= 0)
			close(c);
	}
}

static int run(const char *ip, int port, double secs)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
	struct linger lg = { 1, 0 };
	struct timeval tv = { 2, 0 };
	long ok = 0, failed = 0;
	double t0 = now(), end = t0 + secs;

	inet_pton(AF_INET, ip, &a.sin_addr);
	while (now() < end) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (connect(s, (void *)&a, sizeof(a)) == 0)
			ok++;
		else
			failed++;
		close(s);
	}
	printf("{\"conn_per_s\": %.1f, \"ok\": %ld, \"failed\": %ld, \"seconds\": %.2f}\n",
	       ok / (now() - t0), ok, failed, now() - t0);
	return 0;
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	if (argc == 3 && !strcmp(argv[1], "serve"))
		return serve(atoi(argv[2]));
	if (argc == 5 && !strcmp(argv[1], "run"))
		return run(argv[2], atoi(argv[3]), atof(argv[4]));
	fprintf(stderr, "usage: connrate serve PORT | connrate run IP PORT SECONDS\n");
	return 2;
}
