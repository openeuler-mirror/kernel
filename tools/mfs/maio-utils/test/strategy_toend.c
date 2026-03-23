// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include "maio.h"
#include <stddef.h>

int demo_init(void)
{
	return 0;
}

void demo_exit(void)
{
}

int demo_load(struct maio **io)
{
	struct maio_entry *entry;

	entry = (*io)->entries;
	entry[0].toff = (*io)->off + (*io)->len;
	/* Read Ahead until the end */
	entry[0].tlen = 0;
	entry[0].fpath = NULL;
	entry[0].tnuma = -1;
	return 1;
}

int demo_evict(struct maio **io)
{
	((void)io);
	return 0;
}

const struct maio_operation demo_strategy = {
	.max_io = 1,
	.init	= demo_init,
	.exit	= demo_exit,
	.load	= demo_load,
	.evict	= demo_evict,
};

struct maio_operation *register_strategy(void)
{
	return (struct maio_operation *)&demo_strategy;
}
