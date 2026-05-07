/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef __GRC_COUNTERS_H
#define __GRC_COUNTERS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>

#define NBL_VF_NUM 64
#define NBL_STATS_GROUP_START_NUM 2

#define NBL_VF_CNTS 8
#define NBL_STATS_GROUP_CNTS 256
#define NBL_STATS_GROUP_OPCODE_CNTS 128
#define NBL_STATS_GROUP_ERR_CNTS 128
#define NBL_ERR_QPN_CNTS 128

#define SPDK_NBL_COUNTERS_ALIGN			64	/* 64-bit aligned */

/**
 * op_info
 *	[0]:op_status
 *	[1]:op_err_warning
 *	[2]:op_rc
 *	[6:3]op_table_sel
 *	[15:7]op_id
 *	[23:16]op_len
 *	[31:24]op_add_sel
 */
#define NBL_STATS_OP_STATUS_S 0
#define NBL_STATS_OP_STATUS_M BIT_ULL(NBL_STATS_OP_STATUS_S)
#define NBL_STATS_OP_ERR_WARN_S 1
#define NBL_STATS_OP_ERR_WARN_M BIT_ULL(NBL_STATS_OP_ERR_WARN_S)
#define NBL_STATS_OP_RC_S 2
#define NBL_STATS_OP_RC_M BIT_ULL(NBL_STATS_OP_RC_S)
#define NBL_STATS_OP_TABLE_SEL_S 3
#define NBL_STATS_OP_TABLE_SEL_M (0xfULL << NBL_STATS_OP_TABLE_SEL_S)
#define NBL_STATS_OP_ID_S 7
#define NBL_STATS_OP_ID_M (0x1ffULL << NBL_STATS_OP_ID_S)
#define NBL_STATS_OP_LEN_S 16
#define NBL_STATS_OP_LEN_M (0xffULL << NBL_STATS_OP_LEN_S)
#define NBL_STATS_OP_ADD_SEL_S 24
#define NBL_STATS_OP_ADD_SEL_M (0xffULL << NBL_STATS_OP_ADD_SEL_S)

#define LS_32(val, field) (((val) << field##_S) & (field##_M))
#define RS_32(val, field) (((val) & field##_M) >> field##_S)
#define U64_HI(val) ((u32)(((u64)(val)) >> 32))
#define U64_LO(val) ((u32)(((u64)(val)) & 0xFFFFFFFF))

#define NBL_WRITE_REG(a, reg, value) writel((value), ((a)->hw_addr + (reg)))
#define NBL_READ_REG(a, reg) readl((a)->hw_addr + (reg))

struct nbl_qp_func {
	struct list_head list;
	u32 qpn;
	u16 func_id;
};

int get_hw_status(struct nbl_grc *grc);

void nbl_rdma_stat_init(struct nbl_grc *grc);
void nbl_rdma_stat_deinit(struct nbl_grc *grc);
void grc_add_stat_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
		     struct nbl_chan_rdma_resp *mbx_resp);
void grc_del_stat_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
		     struct nbl_chan_rdma_resp *mbx_resp);
void grc_mod_stat_id(struct nbl_grc *grc, void *req_msg, u16 msg_len,
		     struct nbl_chan_rdma_resp *mbx_resp);
void grc_get_used_cnt(struct nbl_grc *grc, void *msg, u16 msg_len,
			  struct nbl_chan_rdma_resp *mbx_resp);
void nbl_grc_hw_stat_read(struct nbl_grc *grc, void *req_msg, u16 msg_len,
			  struct nbl_chan_rdma_resp *mbx_resp);
void grc_hw_stat_clear(struct nbl_grc *grc, void *msg, u16 msg_len,
		       struct nbl_chan_rdma_resp *mbx_resp);
void grc_hw_stat_errcode_enable(struct nbl_grc *grc, void *msg, u16 msg_len,
				struct nbl_chan_rdma_resp *mbx_resp);
#endif /* __GRC_COUNTERS_H */
