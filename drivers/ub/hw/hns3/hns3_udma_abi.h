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
#define MAP_INDEX_MASK			0xffffff
#define MAP_INDEX_SHIFT			8
#define UDMA_DWQE_PAGE_SIZE		65536
#define UDMA_JETTY_X_PREFIX_BIT_NUM	2
#define UDMA_JFS_QPN_PREFIX		0x2
#define UDMA_JFR_QPN_PREFIX		0x1
#define UDMA_JETTY_QPN_PREFIX		0x3
#define UDMA_ADDR_4K_MASK		0xfffUL
#define URMA_SEG_ACCESS_GUARD		(1UL << 5)
#define UDMA_DCA_ATTACH_FLAGS_NEW_BUFFER BIT(0)
#define UDMA_DCA_INVALID_DCA_NUM ~0U

enum {
	UDMA_MMAP_UAR_PAGE,
	UDMA_MMAP_DWQE_PAGE,
	UDMA_MMAP_DCA_PAGE,
	UDMA_MMAP_RESET_PAGE,
	UDMA_MMAP_TYPE_DCA
};

enum udma_jfc_init_attr_mask {
	UDMA_JFC_NOTIFY_OR_POE_CREATE_FLAGS = 1 << 0,
};

enum udma_jfc_create_flags {
	UDMA_JFC_CREATE_ENABLE_POE_MODE = 1 << 0,
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
	uint64_t wqe_buf_addr;
	uint32_t sqe_cnt;
	uint32_t sqe_shift;
	uint32_t sge_cnt;
	uint32_t sge_shift;
	bool     share_jfr;
};

enum udma_jfr_cap_flags {
	UDMA_JFR_CAP_RECORD_DB = 1 << 0,
};

struct udma_create_jfr_resp {
	uint32_t jfr_caps;
	uint32_t srqn;
};

struct udma_jfc_attr_ex {
	uint64_t	jfc_ex_mask; /* Use enum udma_jfc_init_attr_mask */
	uint64_t	create_flags; /* Use enum udma_jfc_create_flags */
	uint64_t	notify_addr;
	uint8_t		poe_channel; /* poe channel to use */
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

struct udma_create_tp_ucmd {
	bool			is_jetty;
	union {
		uint32_t	jfs_id;
		uint32_t	jetty_id;
	} ini_id;
	union {
		uint32_t	jfr_id;
		uint32_t	jetty_id;
	} tgt_id;
	/* used for create_qp */
	uint64_t		buf_addr;
	uint64_t		db_addr;
	uint64_t		sdb_addr;
};

struct udma_create_jetty_ucmd {
	struct udma_create_tp_ucmd	create_tp_ucmd;
	uint32_t			jfr_id;
	uint64_t			buf_addr;
	uint64_t			sdb_addr;
};

enum udma_qp_cap_flags {
	UDMA_QP_CAP_RQ_RECORD_DB = 1 << 0,
	UDMA_QP_CAP_SQ_RECORD_DB = 1 << 1,
	UDMA_QP_CAP_OWNER_DB = 1 << 2,
	UDMA_QP_CAP_DYNAMIC_CTX_ATTACH = 1 << 4,
	UDMA_QP_CAP_DIRECT_WQE = 1 << 5,
};

struct udp_srcport {
	uint16_t	um_data_udp_start;
	bool		um_spray_en;
	uint8_t		um_udp_range;
};

struct udma_create_tp_resp {
	uint64_t		cap_flags;
	uint32_t		qpn;
	uint32_t		path_mtu;
	uint8_t			priority;
	struct udp_srcport	um_srcport;
};

struct udma_create_jetty_resp {
	struct udma_create_tp_resp create_tp_resp;
};

struct udma_create_jfs_ucmd {
	struct udma_create_tp_ucmd create_tp_ucmd;
};

struct udma_create_jfs_resp {
	struct udma_create_tp_resp create_tp_resp;
};

struct udma_create_ctx_ucmd {
	uint32_t comp;
	uint32_t dca_max_qps;
	uint32_t dca_unit_size;
};

enum udma_context_comp_mask {
	UDMA_CONTEXT_MASK_DCA_PRIME_QPS = 1 << 0,
	UDMA_CONTEXT_MASK_DCA_UNIT_SIZE = 1 << 1,
	UDMA_CONTEXT_MASK_DCA_MAX_SIZE = 1 << 2,
	UDMA_CONTEXT_MASK_DCA_MIN_SIZE = 1 << 3,
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
	uint32_t poe_ch_num;
	uint64_t db_addr;
	uint32_t dca_qps;
	uint32_t dca_mmap_size;
	uint32_t dca_mode;
	uint8_t chip_id;
	uint8_t die_id;
	uint8_t func_id;
	bool rm_support;
};

struct flush_cqe_param {
	uint32_t qpn;
	uint32_t sq_producer_idx;
};

struct udma_poe_info {
	uint8_t		en;
	uint8_t		poe_channel;
	uint64_t	poe_addr;
};

struct udma_dca_reg_attr {
	uintptr_t	key;
	uintptr_t	addr;
	uint32_t	size;
};

struct udma_dca_dereg_attr {
	uintptr_t	free_key;
	struct dca_mem	*mem;
};

struct udma_dca_shrink_attr {
	uint64_t reserved_size;
};

struct udma_dca_shrink_resp {
	struct dca_mem	*mem;
	uintptr_t	free_key;
	uint32_t	free_mems;
};

struct udma_dca_attach_attr {
	uint64_t	qpn;
	uint32_t	sq_offset;
	uint32_t	sge_offset;
};

struct udma_dca_attach_resp {
	uint32_t	alloc_flags;
	uint32_t	alloc_pages;
	uint32_t	dcan;
};

struct udma_dca_detach_attr {
	uint64_t	qpn;
	uint32_t	sq_idx;
};

struct udma_dca_query_attr {
	uint64_t	qpn;
	uint32_t	page_idx;
};

struct udma_dca_query_resp {
	uintptr_t	mem_key;
	uint32_t	mem_ofs;
	uint32_t	page_count;
};

enum udma_user_ctl_handlers {
	UDMA_USER_CTL_FLUSH_CQE,
	UDMA_CONFIG_POE_CHANNEL,
	UDMA_QUERY_POE_CHANNEL,
	UDMA_DCA_MEM_REG,
	UDMA_DCA_MEM_DEREG,
	UDMA_DCA_MEM_SHRINK,
	UDMA_DCA_MEM_ATTACH,
	UDMA_DCA_MEM_DETACH,
	UDMA_DCA_MEM_QUERY,
	UDMA_OPCODE_NUM,
};

#endif /* _UDMA_ABI_H */
