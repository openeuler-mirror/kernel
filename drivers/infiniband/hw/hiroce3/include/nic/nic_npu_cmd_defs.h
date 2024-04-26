/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */


#ifndef NIC_NPU_CMD_DEFS_H
#define NIC_NPU_CMD_DEFS_H

#include "typedef.h"
#include "nic_cfg_comm.h"

/*
 * NIC Command Queue Header
 * queues context follow this header should be consecutive
 */
struct nic_cmdq_header {
	union {
		struct {
#if (BYTE_ORDER == BIG_ENDIAN)
			/* 0x0:SQ, 0x1:RQ */
			u16 queue_type;
			/* queue number in buffer follow this header */
			u16 queue_num;
#else
			u16 queue_num;
			u16 queue_type;
#endif
		} cmdq_ctx_dw0;

		u32 ctx_dw0;
	};

#if (BYTE_ORDER == BIG_ENDIAN)
	u16 rsvd;
	u16 start_qid;
#else
	u16 start_qid;
	u16 rsvd;
#endif
};

struct nic_cmdq_context_modify_s {
	struct nic_cmdq_header hdr;
	u8 data[2016];
};

struct nic_cmdq_clean_q_space {
	/*
	 * queue_type = 0, TSO
	 * queue_type = 1, LRO
	 */
	union {
		struct {
#if (BYTE_ORDER == BIG_ENDIAN)
			u16 queue_type;
			u16 queue_num;
#else
			u16 queue_num;
			u16 queue_type;
#endif
		} cmdq_space_dw0;

		u32 space_dw0;
	};

#if (BYTE_ORDER == BIG_ENDIAN)
	u16 rsvd;
	u16 start_qid;
#else
	u16 start_qid;
	u16 rsvd;
#endif

	u32 rsvd1;
};

struct nic_cmdq_flush_rq_task {
	union {
		struct {
#if (BYTE_ORDER == BIG_ENDIAN)
			u16 q_id;
			u16 glb_rq_id;
#else
			u16 glb_rq_id;
			u16 q_id;
#endif
		} bs;

		u32 value;
	} dw0;
};

/* arm sq/rq */
union nic_cmdq_arm {
	struct cmdq_arm_dw0_s {
#if (BYTE_ORDER == BIG_ENDIAN)
		u16 qpn;
		u16 pi;
#else
		u16 pi;
		u16 qpn;
#endif
	} dw0;

	u32 arm_dw0;
};


/* rss */
struct nic_rss_indirect_tbl {
	u32 rsvd[4]; // Make sure that 16B beyond entry[]
	u16 entry[NIC_RSS_INDIR_SIZE];
};

struct nic_rss_glb_qid_indirect_tbl {
	u32 group_index;
	u32 offset;
	u32 size;
	u32 rsvd;   /* Make sure that 16B beyond entry[] */
	u16 entry[NIC_RSS_INDIR_SIZE];
};

struct nic_rss_context_tbl {
	u32 rsvd[4];
	u32 ctx;
};

struct nic_vlan_ctx {
	u32 func_id;
	u32 qid; /* if qid = 0xFFFF, config current function all queue */
	u32 vlan_id;
	u32 vlan_mode;
	u32 vlan_sel;
};

#endif /* NIC_NPU_CMD_DEFS_H */
