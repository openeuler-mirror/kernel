/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_ABI_H
#define _UDMA_ABI_H

#include <linux/types.h>

#define MAP_COMMAND_MASK		0xff
#define UDMA_ADDR_4K_MASK		0xfffUL

enum {
	UDMA_MMAP_UAR_PAGE,
};

struct udma_create_jfc_ucmd {
	uint64_t		buf_addr;
	uint64_t		db_addr;
};

enum udma_jfc_cap_flags {
	UDMA_JFC_CAP_RECORD_DB = 1 << 0,
};

struct udma_create_jfc_resp {
	uint32_t jfc_caps;
};

struct udma_create_ctx_resp {
	uint32_t num_comp_vectors;
	uint32_t num_qps_shift;
	uint32_t num_jfs_shift;
	uint32_t num_jfr_shift;
	uint32_t num_jetty_shift;
	uint32_t max_jfc_cqe;
	uint32_t cqe_size;
	uint32_t max_jfr_wr;
	uint32_t max_jfr_sge;
	uint32_t max_jfs_wr;
	uint32_t max_jfs_sge;
};

#endif /* _UDMA_ABI_H */
