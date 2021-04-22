#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "connect.h"

/*
 * dev_t in userspace is 8-bytes long but 4-byte long in kernel
 * work around this
 */
#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)
#define MKDEV(ma, mi)     ((ma)<<MINORBITS | (mi))
#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))

struct acache_info *inbuf, *outbuf;
struct connection *conn;

void print_infos(const char *prefix, struct acache_info *infos, size_t length)
{
	size_t i;
	struct acache_info *info;

	for (i = 0; i < length; i++) {
		info = infos + i;

		printf("%4s,%20lu,%8u,%8u,%15lu,%12lu\n",
			prefix, info->start_time, MAJOR(info->dev),
			MINOR(info->dev), info->offset, info->length);
	}
}

int malloc_buffers(struct acache_info **inbuf, struct acache_info **outbuf,
		   size_t capacity)
{
	/* prepare buffers to store incoming or outgoing items */
	*inbuf = (struct acache_info *)malloc(sizeof(struct acache_info) * capacity);
	*outbuf = (struct acache_info *)malloc(sizeof(struct acache_info) * capacity);

	if (!*inbuf || !*outbuf) {
		fprintf(stderr, "error malloc memory: %s\n, size: %lu, %lu\n",
			strerror(errno),
			sizeof(struct acache_info) * capacity,
			sizeof(struct acache_info) * capacity);
		return -errno;
	}
	return 0;
}

void free_buffer(struct acache_info **buf)
{
	if (buf && *buf) {
		free(*buf);
		*buf = NULL;
	}
}

void elegant_exit(int sig) {
	printf("exiting...");
	free_buffer(&inbuf);
	free_buffer(&outbuf);
	conn->ops.close(conn);
	exit(0);
}

int main(int argc, char **argv)
{
	int debug = 0;
	int ret;
	int outbuf_tail;
	size_t capacity;

	conn = initialize_conn_rw();

	if (conn == NULL) {
		fprintf(stderr, "error initialzied connnection\n");
		return -1;
	}

	if (argc > 1 && strcmp("-d", argv[1]) == 0)
		debug = 1;

	/* prepare buffers to store incoming or outgoing items */
	capacity = conn->ops.get_capacity(conn);
	ret = malloc_buffers(&inbuf, &outbuf, capacity);

	if (ret < 0)
		return ret;

	if (debug) {
		printf("%4s,%20s,%8s,%8s,%15s,%12s\n",
			"op","time(ns)","majorDev","minorDev","offset(B)","length(B)");
	}
	/* main loop */
	if (signal(SIGINT, elegant_exit) == SIG_ERR) {
		fprintf(stderr, "error handling SIGINT: %s\n", strerror(errno));
	}
	if (signal(SIGTERM, elegant_exit) == SIG_ERR) {
		fprintf(stderr, "error handling SIGTERM: %s\n", strerror(errno));
	}
	while (1) {
		unsigned int i, inlen;

		inlen = conn->ops.fetch_items(conn, inbuf, capacity);
		if (!inlen) {
			usleep(100);
			continue;
		}

		outbuf_tail = 0;
		for (i = 0; i < inlen; i++) {
			/* customize prefetch strategy here */
			memcpy(outbuf + outbuf_tail, inbuf + i, sizeof(struct acache_info));
			outbuf[outbuf_tail].offset += outbuf[outbuf_tail].length >> 9;
			outbuf_tail++;
		}
		if (debug) {
			print_infos("R", inbuf, inlen);
			print_infos("P", outbuf, outbuf_tail);
		}
		if (outbuf_tail) {
			conn->ops.send_items(conn, outbuf, outbuf_tail);
		}
	}
	return 0;
}
