// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#ifndef _INNER_H_
#define _INNER_H_

#include <time.h>
#include <stdint.h>

static inline uint64_t _get_ts(void)
{
	struct timespec now = {0};
	(void)clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
	return (uint64_t)now.tv_sec;
}

/* io context for loader and writeback */
struct io_context {
	uint32_t id;		/* msg id */
	uint64_t off;		/* io offset in fd */
	uint64_t len;		/* io length */
	uint16_t numaid;	/* numa node of this io, -1 means non-bind */
	int fd;			/* io file handle */
	char *path;		/* fullpath of this io */
	void *buf;		/* flighting buffer for writeback */

	uint64_t seq;

	void *private;
	void (*end_io)(int ret, void *private);
};

void loader_update_curseq(uint64_t seq);
int loader_evict_submit(struct io_context *ioctx);
int loader_io_submit(struct io_context *ioctx);

#endif
