/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_DB_H
#define ROCE_DB_H

#include <rdma/ib_umem.h>
#include <linux/types.h>
#include <linux/list.h>

struct roce3_db_page {
	struct list_head list;
	struct ib_umem *umem;
	unsigned long user_virt;
	int refcnt;
};

struct roce3_db {
	__be32 *db_record;
	dma_addr_t dma;
	struct roce3_db_page *user_page;
};

static inline void roce3_write64(u32 val[2], void __iomem *dest)
{
	__raw_writeq(*(u64 *)(void *)val, dest);
}

#endif // ROCE_DB_H
