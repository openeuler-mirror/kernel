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
#define UDMA_JETTY_X_PREFIX_BIT_NUM	2
#define UDMA_JFR_QPN_PREFIX		0x1
#define UDMA_ADDR_4K_MASK		0xfffUL
#define URMA_SEG_ACCESS_GUARD		(1UL << 5)

enum {
	UDMA_MMAP_UAR_PAGE,
};

enum udma_jfc_init_attr_mask {
	UDMA_JFC_NOTIFY_CREATE_FLAGS = 1 << 0,
};

enum udma_jfc_create_flags {
	UDMA_JFC_CREATE_ENABLE_NOTIFY = 1 << 1,
};

enum udma_jfc_notify_mode {
	UDMA_JFC_NOTIFY_MODE_64B_ALIGN,
	UDMA_JFC_NOTIFY_MODE_4B_ALIGN,
	UDMA_JFC_NOTIFY_MODE_DDR_64B_ALIGN,
	UDMA_JFC_NOTIFY_MODE_DDR_4B_ALIGN,
};

struct udma_create_jfr_ucmd {
	uint64_t buf_addr;
	uint64_t idx_addr;
	uint64_t db_addr;
};

enum udma_jfr_cap_flags {
	UDMA_JFR_CAP_RECORD_DB = 1 << 0,
};

struct udma_create_jfr_resp {
	uint32_t jfr_caps;
};

struct udma_jfc_attr_ex {
	uint64_t	jfc_ex_mask; /* Use enum udma_jfc_init_attr_mask */
	uint64_t	create_flags; /* Use enum udma_jfc_create_flags */
	uint64_t	notify_addr;
	uint8_t		notify_mode; /* Use enum udma_jfc_notify_mode */
};

struct udma_create_jfc_ucmd {
	uint64_t		buf_addr;
	uint64_t		db_addr;
	struct udma_jfc_attr_ex	jfc_attr_ex;
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
