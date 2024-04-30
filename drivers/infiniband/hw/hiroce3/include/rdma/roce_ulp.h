/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_ULP_H
#define ROCE_ULP_H

#include "pub_base_defs.h"

/* *********ECN alpha SHIFT******* */
#define ECN_ALPHA_MAGNIFICATION_SHIFT (21)

/* ********************** NOFAA start ************************ */
enum ROCE_NOFAA_QP_CTX_OFF_E {
	ROCE_NOFAA_CTX_TIMER_OFF = 0,
	ROCE_NOFAA_CTX_SW_OFF = 32,
	ROCE_NOFAA_CTX_SW_SQC_OFF = 96,
	ROCE_NOFAA_CTX_SW_SQAC_OFF = 116,
	ROCE_NOFAA_CTX_SW_RQC_OFF = 148,
	ROCE_NOFAA_CTX_SW_RQAC_OFF = 168
};

#define ROCE_VERBS_NOFAA_TIMERC_OFFSET_16B_ALIGN (ROCE_NOFAA_CTX_TIMER_OFF >> 4)
#define ROCE_VERBS_NOFAA_SW_OFFSET_16B_ALIGN (ROCE_NOFAA_CTX_SW_OFF >> 4)

/* API */
#define ROCE_NOFAA_WQE2HOST_SM_NODE NODE_ID_SMF0
#define ROCE_NOFAA_CMIDINFO_SM_MODE NODE_ID_SMF0
#define SML_INST_MASTER_QPC 20

#define ROCE_BMP_LOAD_BYTE 64
#define ROCE_BMP_ENTRY_BY_64B ((ROCE_QPC_TABLE_SIZE>>6) + 1)
#define ROCE_BMP_RSVD_BYTE 32
#define ROCE_NOFAA_QPN_RSVD 0x2
#define ROCE_REVERSE_PER_64B_SHIFT 4

#define ROCE_MQP_LT_RSVD 100 // (64 + 12kbit / 8) / 16
#define ROCE_ACT_HOST_LT_RSVD 4 // (64) / 16
#define ROCE_HASH_LT_RSVD 17920 // (0xA1000 - 0x5B000) / 16
#define ROCE_SHARD_HASH_LT_RSVD 8960 // (0x8DC00 - 0x6AC00) / 16
#define ROCE_HASH_LT_RSVD_MUL_SML (ROCE_HASH_LT_RSVD >> ROCE_NOFAA_PORT_NUM_SHIFT)
#define ROCE_LT_64B_IDX_SHIFT 2
#define ROCE_LT_64B_ENTRY_NUM 4

#define ROCE_NOFAA_HASH_WORD_EN 0x400
#define ROCE_NOFAA_HASH_API_KEY_LEN 4
#define ROCE_NOFAA_BITHEAP_ID0 0
#define ROCE_NOFAA_RSVD_BMPIDX_NUM 2
#define ROCE_NOFAA_MASTER_BMPIDX_BASE 0x3002
#define ROCE_NOFAA_CM_QPN_INDEX 0x3001
#define ROCE_NOFAA_FLR_STUB_INDEX 0x2fff
#define ROCE_NOFAA_QPN2BMPIDX(xid) ((xid) + ROCE_NOFAA_MASTER_BMPIDX_BASE - ROCE_NOFAA_QPN_RSVD)
#define ROCE_NOFAA_BMPIDX2QPN(bmp_idx) \
	((bmp_idx) + ROCE_NOFAA_QPN_RSVD - ROCE_NOFAA_MASTER_BMPIDX_BASE)
#define ROCE_NOFAA_GET_ACT_HOST_IDX(xid, host_id) (((xid) << 2) + (((host_id) & 0x3) ^ 0x3))

#define ROCE_NOFAA_GIDIDX_MASK 0x3f
#define ROCE_NOFAA_GIDIDX_RSVD_MASK 0xc0

/* cfg */
#define NOFAA_SRC_TAG_L (global_share_space.global_config.dw6.bs.master_func)
#define ROCE_NOFAA_HOSTID_MASK (global_share_space.global_config.dw6.bs.host_mask)
#define ROCE_NOFAA_HOST_NUM (global_share_space.global_config.dw6.bs.host_num)
#define ROCE_NOFAA_PORT_NUM (global_share_space.global_config.dw6.bs.port_num)
#define ROCE_NOFAA_HOST_NUM_SHIFT (global_share_space.global_config.dw6.bs.host_shift)
#define ROCE_NOFAA_PORT_NUM_SHIFT (global_share_space.global_config.dw6.bs.port_shift)
#define ROCE_NOFAA_PORT_NUM_MASK (global_share_space.global_config.dw6.bs.port_mask)
#define ROCE_NOFAA_MAX_HOST_NUM 4
#define ROCE_NOFAA_HASH_POOL_IO_NUM (ROCE_NOFAA_MAX_HASH_NUM >> ROCE_NOFAA_PORT_NUM_SHIFT)
#define ROCE_NOFAA_SRQN_BASE 2
#define ROCE_NOFAA_SRQN_MASK 0x7
#define ROCE_NOFAA_SRQN_NUM 8

#define ROCE_NOFAA_MAX_QPN_SHIFT 12
#define ROCE_NOFAA_PORT_QP_NUM_SHIFT (ROCE_NOFAA_MAX_QPN_SHIFT - ROCE_NOFAA_PORT_NUM_SHIFT)
#define ROCE_NOFAA_PORT_QP_NUM (1u << ROCE_NOFAA_PORT_QP_NUM_SHIFT)
#define ROCE_NOFAA_PORT_QP_NUM_MASK (ROCE_NOFAA_PORT_QP_NUM - 1)
#define ROCE_AA_SWITCH_QP_NUM 4
#define ROCE_AA_SWITCH_QPN (4095 + 1)
#define ROCE_AA_SWITCH_MAX_QPN (ROCE_AA_SWITCH_QPN + ROCE_AA_SWITCH_QP_NUM)
#define ROCE_QP0 0x0
#define ROCE_CM_QPN 0x1
#define ROCE_AA_QID_NUM 9
#define ROCE_NVME_QID_GP_SHIFT 1
#define ROCE_NVME_QID_GP_MASK 1

#define NEXT_IO_SPF_GET(start_spf, index) ((start_spf) + ((index) << 7))
#define NEXT_SPF_GET(start_spf, index) ((start_spf) + ((index) << 6))

#define ROCE_NOFAA_VFID2HOSTIDX(vf_id) \
	(((vf_id) >> ROCE_NOFAA_PORT_NUM_SHIFT) & ROCE_NOFAA_HOSTID_MASK)
#define ROCE_NOFAA_VFID2PORTID(vf_id) ((vf_id) & ROCE_NOFAA_PORT_NUM_MASK)
#define ROCE_NOFAA_SLAVE_ALIVE_GET(active_bmp, slave_id) \
	((active_bmp) & (1u << ((slave_id) & ROCE_NOFAA_HOSTID_MASK)))
#define ROCE_AA_SRCCHNL2HOST(src_chnl) (((src_chnl) >> 3) & 0x3)
#define ROCE_NOFAA_GET_GID_IDX(qpc, host_id) \
	(*((u8 *)&((qpc)->nofaa_ctx.dw1.value) + (host_id)) & 0x3f)
/* ROCE NOFAA(QPC512):CID[19:0] = {XID[12:4],XID[12:4],XID[3:2]} */
#define roce_nofaa_calc_cid_by_xid(xid) ((((xid)&0x3ffe0) << 6) | (((xid)&0x7ff8) >> 3))
#define ROCE_NOFAA_BITMAP_CLEAR(bmp, idx) ((bmp) &= ((1u << (idx)) ^ 0xffffffff))
#define ROCE_NOFAA_BITMAP_SET(bmp, idx) ((bmp) |= (1u << (idx)))
#define ROCE_NOFAA_BITMAP_GET(bmp, idx) ((bmp) & (1u << (idx)))
#define ROCE_NOFAA_BITWISE_COMPARE(x, y) ((x) ^ (y))
/* GET CMINFO TABLE */
#define ROCE_GET_CMINFO_ADDR(sp_addr, index) \
		((struct tag_roce_nof_cm_ctx *)(sp_addr) + \
		(((index) >> ROCE_LT_XID_LB_SHIFT) & ROCE_CMINFO_PER_16B_MASK))

#define ROCE_NOFAA_QUERY_BMP_SIZE ((ROCE_NOFAA_PORT_QP_NUM) >> 3)
#define ROCE_NOFAA_GET_PORT_QPNUM_BYTE(port_id) \
	((u32)((port_id) << ROCE_NOFAA_PORT_QP_NUM_SHIFT) >> 3)

/* switch */
#define ROCE_SWITCH_COUNTER_BASE 0x4000

/* timer */
#define ROCE_NOFAA_TIME_DLY_STEP 2047
#define ROCEAA_TIMER_DLY_STEP(dly_step) (((dly_step) < ROCE_NOFAA_TIME_DLY_STEP) ? \
	(dly_step) : ROCE_NOFAA_TIME_DLY_STEP)

/* data struct */
struct tag_roce_nof_cm_ctx {
	u32 local_comm_id;
	u32 remote_comm_id;
};

struct tag_nofaa_shard_hash_key {
	u32 xid : 16;
	u32 lun_id : 16;
};

struct tag_nofaa_shard_hash_item {
	struct {
		u32 volume_id : 24;
		u32 dd_id : 8;
	} bs;

	u8 hash_low_cnt;
	u8 hash_high_cnt;
	u8 hash_low_offset;
	u8 hash_high_offset;
};

struct tag_nofaa_shard_hash_entry {
	struct tag_nofaa_shard_hash_key key;
	struct tag_nofaa_shard_hash_item item;
};

struct tag_nofaa_shard_hash_value {
	union {
		struct {
			u32 code : 2;
			u32 rsvd0 : 30;
		} bs;
		u32 value;
	} dw0;
	u32 rsvd0;
	struct tag_nofaa_shard_hash_item item;
};

struct tag_nofaa_shard_lt_value {
	union {
		struct {
			u32 v : 1;
			u32 s : 1;
			u32 b : 1;
			u32 rsvd0 : 5;
			u32 hash_value : 16;
			u32 rsvd1 : 8;
		} bs;
		u32 value;
	} dw0;
	struct tag_nofaa_shard_hash_key key;
	struct tag_nofaa_shard_hash_item item;
};

/* ********************** NOFAA end ************************ */

#endif /* ROCE_ULP_H */
