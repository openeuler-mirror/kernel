// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#ifndef _MAIO_H_
#define _MAIO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct maio_entry {
	char *fpath;
	uint64_t toff;
	uint64_t tlen;
	uint8_t tnuma;
	uint64_t seq;
};

struct maio {
	/* IN */
	int fd;
	uint64_t off;
	uint64_t len;
	int pid;
	uint8_t op;
	uint64_t ts;
	uint32_t cksz;

	/* OUT */
	uint16_t flags;
#define MAIO_WITH_SEQ  0x0001
	uint64_t curseq;
	struct maio_entry entries[];
};

struct maio_operation {
	int	max_io;
	int	(*init) (void);
	void	(*exit) (void);
	int	(*load) (struct maio **io);
	int	(*evict) (struct maio **io);
};

char *_get_fullpath(char *fpath, int fd);
void maio_preload(struct maio *maio, int nio);

#ifdef __cplusplus
}
#endif

#endif
