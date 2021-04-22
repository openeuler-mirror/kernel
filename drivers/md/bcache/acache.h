// SPDX-License-Identifier: GPL-2.0

#ifndef _ACHACHE_INTERFACE_H_
#define _ACHACHE_INTERFACE_H_

#define ACACHE_NR_DEVS 1

#define RING_SIZE

#include "bcache.h"

struct mem_reg {
	char *data;
	unsigned long size;
};

struct acache_info {
	uint64_t length;
	uint64_t offset;
	uint64_t start_time;
	dev_t dev;
	int type;
};

enum acache_info_type {
	ACACHE_INFO_READ = 0,
	ACACHE_INFO_WRITE,
	ACACHE_INFO_CACHE_INSERT,
	ACACHE_INFO_LATENCY,
};

struct acache_circ {
	spinlock_t lock;
	int tail;
	int head;
	int size;
	int item_size;
	struct acache_info data[0];
};

struct acache_metadata {
	uint32_t magic;
	uint32_t conntype;
	uint32_t devsize;
};

#define ACACHE_DEV_SIZE acache_dev_size
#define ACACHE_MAGIC 2

enum acache_conn_types {
	ACACHE_NO_CONN = 0,
	ACACHE_READWRITE_CONN = 2,
};

#define ACACHE_CIRC_SIZE \
	({int i = (ACACHE_DEV_SIZE - sizeof(struct acache_circ))/sizeof(struct acache_info); \
	int bits = 0; \
	while (i > 0) {i >>= 1; bits++; } \
	  1 << (bits - 1); })


#define  ACACHE_GET_METADATA	_IOR('a', 1, struct acache_metadata)

int acache_dev_init(void);
void acache_dev_exit(void);
struct acache_info *fetch_circ_item(struct acache_circ *circ);
void save_circ_item(struct acache_info *data);

struct inflight_queue_ops {
	void (*init)(void);
	void (*exit)(void);

	int (*insert)(struct search *s);
	int (*remove)(struct search *s);
	bool (*wait)(struct search *s);
};
extern const struct inflight_queue_ops inflight_list_ops;

#endif
