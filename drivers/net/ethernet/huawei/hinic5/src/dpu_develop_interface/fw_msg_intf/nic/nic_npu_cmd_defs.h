/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_npu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2019/4/25
 * Last Modified : 2026/09/16
 * Description   : NIC NPU command definitions
 */

#ifndef NIC_NPU_CMD_DEFS_H
#define NIC_NPU_CMD_DEFS_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#endif

#include "nic_cfg_comm.h"

/**
 * @brief struct nic_cmdq_header
 * @details nic cmdq header info
 */
struct nic_cmdq_header {
	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		/* 0x0:SQ, 0x1:RQ */
		u16 queue_type; /**< queue type */
		/* queue number in buffer follow this header */
		u16 queue_num;  /**< queue number */
#else
		u16 queue_num;  /**< queue number */
		u16 queue_type; /**< queue type */
#endif
	} cmdq_ctx_dw0;

	u32 ctx_dw0;    /**< context word 0 */
	};

#if (BYTE_ORDER == BIG_ENDIAN)
	u16 rsvd;   /**< reserved */
	u16 start_qid;  /**< start queue id */
#else
	u16 start_qid;  /**< start queue id */
	u16 rsvd;   /**< reserved */
#endif
};

/**
 * @brief struct nic_cmdq_context_modify_s
 * @details nic cmdq context modify info
 */
struct nic_cmdq_context_modify_s {
	struct nic_cmdq_header hdr; /**< cmdq header */
	u8 data[2016];  /**< cmdq context data */
};

struct cmdq_space_dw0_s {
#if (BYTE_ORDER == BIG_ENDIAN)
	u16 queue_type; /**< queue type */
	u16 queue_num;  /**< queue number */
#else
	u16 queue_num;  /**< queue number */
	u16 queue_type; /**< queue type */
#endif
};

/**
 * @brief struct nic_cmdq_clean_q_space
 * @details nic cmdq queue space info
 */
struct nic_cmdq_clean_q_space {
    /* queue_type = 0, TSO
	queue_type = 1, LRO */
	union {
	struct cmdq_space_dw0_s cmdq_space_dw0;
	u32 space_dw0;  /**< space word 0 */
	};

#if (BYTE_ORDER == BIG_ENDIAN)
	u16 rsvd;   /**< reserved */
	u16 start_qid;  /**< start queue id */
#else
	u16 start_qid;  /**< start queue id */
	u16 rsvd;   /**< reserved */
#endif

	u32 rsvd1;  /**< reserved */
};

/**
 * @brief truct nic_cmdq_flush_rq_task
 * @details nic cmdq rq drain task info
 */
struct nic_cmdq_flush_rq_task {
	union {
	struct {
#if (BYTE_ORDER == BIG_ENDIAN)
		u16 q_id;   /**< queue id */
		u16 glb_rq_id;  /**< global rq id */
#else
		u16 glb_rq_id;  /**< global rq id */
		u16 q_id;   /**< queue id */
#endif
	} bs;

	u32 value;  /**< value */
	} dw0;
};

/**
 * @brief union nic_cmdq_arm
 * @details nic cmdq arm info
 */
union nic_cmdq_arm {
	struct cmdq_arm_dw0_s {
#if (BYTE_ORDER == BIG_ENDIAN)
	u16 qpn;    /**< queue pair number */
	u16 pi;     /**< produce index */
#else
	u16 pi;     /**< produce index */
	u16 qpn;    /**< queue pair number */
#endif
	} dw0;

	u32 arm_dw0;    /**< arm word 0 */
};


/**
 * @brief truct nic_rss_indirect_tbl
 * @details nic rss indirect table
 */
struct nic_rss_indirect_tbl {
	u32 user_data[2];
	u32 rsvd[2]; // Make sure that 16B beyond entry[]
	u16 entry[NIC_RSS_INDIR_SIZE];  /**< rss indirect table entry */
};

/**
 * @brief struct nic_rss_glb_qid_indirect_tbl
 * @details nic rss glb qid indirect table
 */
struct nic_rss_glb_qid_indirect_tbl {
	u32 group_index;    /**< group index */
	u32 offset;    /**< offset */
	u32 size;   /**< size */
	u32 rsvd;   /* Make sure that 16B beyond entry[] */
	u16 entry[NIC_RSS_INDIR_SIZE];  /**< rss indirect table entry */
};

/**
 * @brief struct nic_rss_context_tbl
 * @details nic vlan context info
 */
struct nic_rss_context_tbl {
	u32 rsvd[4]; /**< reserved */
	u32 ctx;    /**< rss context */
};

/**
 * @brief struct nic_vlan_ctx
 * @details nic vlan context info
 */
struct nic_vlan_ctx {
	u32 func_id;    /**< function id */
	u32 qid; /* if qid = 0xFFFF, config current function all queue */
	u32 vlan_id;    /**< vlan id */
	u32 vlan_mode;  /**< vlan mode */
	u32 vlan_sel;   /**< vlan select */
};

/**
 * @brief struct nic_cmdq_vport_stats
 * @details nic cmdq vport stats info
 */
struct nic_cmdq_vport_stats {
	u64 tx_uc_pkts_vport;
	u64 tx_uc_bytes_vport;
	u64 tx_mc_pkts_vport;
	u64 tx_mc_bytes_vport;
	u64 tx_bc_pkts_vport;
	u64 tx_bc_bytes_vport;

	u64 rx_uc_pkts_vport;
	u64 rx_uc_bytes_vport;
	u64 rx_mc_pkts_vport;
	u64 rx_mc_bytes_vport;
	u64 rx_bc_pkts_vport;
	u64 rx_bc_bytes_vport;

	u64 tx_discard_vport;
	u64 rx_discard_vport;
	u64 tx_err_vport;
	u64 rx_err_vport;

	u64 rsvd[8]; /* Reserved 8 counters */
};

#endif /* NIC_CMDQ_INTF_H */
