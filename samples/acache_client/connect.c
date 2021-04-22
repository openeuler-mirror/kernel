#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#include "connect.h"

static int ACACHE_READWRITE_CAPACITY = 4096;
static struct connection readwrite_conn;
static struct readwrite_conn_metadata {
	int initialized;
	int fd;
} private;

void *initialize(struct connection *self)
{
	long ret;

	private.fd = open(acache_path, O_RDWR | O_SYNC);
	if (private.fd == -1) {
		fprintf(stderr, "error opening device: %s\n", strerror(errno));
		exit(-1);
	}

	struct acache_metadata {
		uint32_t magic;
		uint32_t conntype;
		uint32_t devsize;
	} acache_metadata;
#define  ACACHE_GET_METADATA    _IOR('a', 1, struct acache_metadata)
	ret = ioctl(private.fd, ACACHE_GET_METADATA, &acache_metadata);
	if (ret) {
		fprintf(stderr, "error getting device memory length: %s\n",  strerror(errno));
		exit(-1);
	}
	if (acache_metadata.magic != ACACHE_MAGIC) {
		fprintf(stderr, "version not match; client: %u kernel: %u\n",
		        ACACHE_MAGIC, acache_metadata.magic);
		exit(-1);
	}
	if (acache_metadata.conntype != ACACHE_READWRITE_CONN) {
		fprintf(stderr, "connect type not match; client: %u kernel: %u\n",
		        ACACHE_READWRITE_CONN, acache_metadata.conntype);
		exit(-1);
	}
	printf("got dev size %u\n", acache_metadata.devsize);
	private.initialized = 1;

	return (void *)&private;
}

struct readwrite_conn_metadata* get_metadata(struct connection *self)
{
	struct readwrite_conn_metadata *metadata;

	if (self == NULL) {
		fprintf(stderr, "connenction uninitailized\n");
		return NULL;
	}

	metadata = (struct readwrite_conn_metadata *)self->private;

	if (metadata->initialized == 0) {
		fprintf(stderr, "connenction uninitailized\n");
		return NULL;
	}
	return metadata;
}

int send_items(struct connection *self, struct acache_info *infos,
		    size_t count)
{
	long ret;
	struct readwrite_conn_metadata *metadata = get_metadata(self);

	if (!metadata) {
		return 0;
	}
	ret = write(metadata->fd, (void*)infos, count * sizeof(struct acache_info));
	if (ret < 0) {
		fprintf(stderr, "error writing data: %ld\n", ret);
		return 0;
	}
	if (ret % sizeof(struct acache_info)) {
		fprintf(stderr, "error writing data: data length is not multiple of sizeof(struct acache_info): %ld %ld\n",
			ret, sizeof(struct acache_info));
		return 0;
	}
	return ret / sizeof(struct acache_info);
}

int fetch_items(struct connection *self, struct acache_info *infos,
		     size_t count)
{
	long ret;
	struct readwrite_conn_metadata *metadata = get_metadata(self);

	if (!metadata) {
		return 0;
	}
	ret = read(metadata->fd, (void*)infos, count * sizeof(struct acache_info));
	if (ret < 0) {
		fprintf(stderr, "error reading data: %ld\n", ret);
		return 0;
	}
	if (ret % sizeof(struct acache_info)) {
		fprintf(stderr, "error reading data: data length is not multiple of sizeof(struct acache_info): %ld %ld\n",
			ret, sizeof(struct acache_info));
		return 0;
	}
	return ret / sizeof(struct acache_info);
}

int get_capacity() {
	return ACACHE_READWRITE_CAPACITY;
}

int close_conn(struct connection *self)
{
	struct readwrite_conn_metadata *metadata = get_metadata(self);

	if (!metadata) {
		return 0;
	}
	close(metadata->fd);
	return 0;

}

struct connection *initialize_conn_rw(void)
{
	readwrite_conn.ops.close = close_conn;
	readwrite_conn.ops.initialize = initialize;
	readwrite_conn.ops.send_items = send_items;
	readwrite_conn.ops.fetch_items = fetch_items;
	readwrite_conn.ops.get_capacity = get_capacity;
	readwrite_conn.private = initialize(&readwrite_conn);
	return &readwrite_conn;
}
