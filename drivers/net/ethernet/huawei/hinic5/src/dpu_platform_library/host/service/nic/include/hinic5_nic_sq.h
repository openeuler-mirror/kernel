/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_sq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_SQ_H
#define HINIC5_NIC_SQ_H

#include "hinic5_common.h"

#define TX_MSS_DEFAULT 0x3E00
#define TX_MSS_MIN 0x50

#define HINIC5_MAX_SQ_SGE 18

struct hinic5_sq_wqe_desc {
	u32 ctrl_len;
	u32 queue_info;
	u32 hi_addr;
	u32 lo_addr;
};

/* Engine only pass first 12B TS field directly to uCode through metadata
 * vlan_offoad is used for hardware when vlan insert in tx
 */
struct hinic5_sq_task {
	u32 pkt_info0;
	u32 ip_identify;
	u32 pkt_info2; /* ipsec used as spi */
	u32 vlan_offload;
};

struct hinic5_sq_bufdesc {
	u32 len; /* 31-bits Length, L2NIC only use length[17:0] */
	u32 rsvd;
	u32 hi_addr;
	u32 lo_addr;
};

struct hinic5_sq_compact_wqe {
	struct hinic5_sq_wqe_desc wqe_desc;
};

struct hinic5_sq_extend_wqe {
	struct hinic5_sq_wqe_desc wqe_desc;
	struct hinic5_sq_task task;
	struct hinic5_sq_bufdesc buf_desc[];
};

struct hinic5_sq_wqe {
	union {
		struct hinic5_sq_compact_wqe compact_wqe;
		struct hinic5_sq_extend_wqe extend_wqe;
	};
};

/* use section pointer for support non continuous wqe */
struct hinic5_sq_wqe_combo {
	struct hinic5_sq_wqe_desc *ctrl_bd0;
	struct hinic5_sq_task *task;
	struct hinic5_sq_bufdesc *bds_head;
	struct hinic5_sq_bufdesc *bds_sec2;

	u16 first_bds_num;
	u8 wqe_type;
	u8 task_type;

	u16 wqebb_cnt;
	u8 offload;
	u8 rsvd;
};

/* ************* SQ_CTRL ************** */
enum sq_wqe_data_format {
	SQ_NORMAL_WQE = 0,
};

enum sq_wqe_ec_type {
	SQ_WQE_COMPACT_TYPE = 0,
	SQ_WQE_EXTENDED_TYPE = 1,
};

enum sq_wqe_tasksect_len_type {
	SQ_WQE_TASKSECT_4BYTES = 0,
	SQ_WQE_TASKSECT_16BYTES = 1,
};

struct hinic5_offload_info {
	u8 encapsulation;
	u8 esp_next_proto;
	u8 inner_l4_en;
	u8 inner_l3_en;
	u8 out_l4_en;
	u8 out_l3_en;
	u8 ipsec_offload;
	u8 pkt_1588;
	u8 vlan_sel;
	u8 vlan_valid;
	u16 vlan1_tag;
	u32 ip_identify;
};

struct hinic5_queue_info {
	u8 pri;
	u8 uc;
	u8 sctp;
	u8 udp_dp_en;
	u8 tso;
	u8 ufo;
	u8 payload_offset;
	u8 pkt_type;
	u16 mss;
};

#define SQ_CTRL_BD0_LEN_SHIFT 0
#define SQ_CTRL_RSVD_SHIFT 18
#define SQ_CTRL_BUFDESC_NUM_SHIFT 19
#define SQ_CTRL_TASKSECT_LEN_SHIFT 27
#define SQ_CTRL_DATA_FORMAT_SHIFT 28
#define SQ_CTRL_DIRECT_SHIFT 29
#define SQ_CTRL_EXTENDED_SHIFT 30
#define SQ_CTRL_OWNER_SHIFT 31

#define SQ_CTRL_BD0_LEN_MASK 0x3FFFFU
#define SQ_CTRL_RSVD_MASK 0x1U
#define SQ_CTRL_BUFDESC_NUM_MASK 0xFFU
#define SQ_CTRL_TASKSECT_LEN_MASK 0x1U
#define SQ_CTRL_DATA_FORMAT_MASK 0x1U
#define SQ_CTRL_DIRECT_MASK 0x1U
#define SQ_CTRL_EXTENDED_MASK 0x1U
#define SQ_CTRL_OWNER_MASK 0x1U

#define SQ_CTRL_SET(val, member) \
	(((u32)(val) & SQ_CTRL_##member##_MASK) << SQ_CTRL_##member##_SHIFT)

#define SQ_CTRL_GET(val, member) \
	(((val) >> SQ_CTRL_##member##_SHIFT) & SQ_CTRL_##member##_MASK)

#define SQ_CTRL_CLEAR(val, member) \
	((val) & (~(SQ_CTRL_##member##_MASK << SQ_CTRL_##member##_SHIFT)))

#define SQ_CTRL_QUEUE_INFO_PKT_TYPE_SHIFT 0
#define SQ_CTRL_QUEUE_INFO_PLDOFF_SHIFT 2
#define SQ_CTRL_QUEUE_INFO_UFO_SHIFT 10
#define SQ_CTRL_QUEUE_INFO_TSO_SHIFT 11
#define SQ_CTRL_QUEUE_INFO_UDP_DP_EN_SHIFT 12
#define SQ_CTRL_QUEUE_INFO_MSS_SHIFT 13
#define SQ_CTRL_QUEUE_INFO_SCTP_SHIFT 27
#define SQ_CTRL_QUEUE_INFO_UC_SHIFT 28
#define SQ_CTRL_QUEUE_INFO_PRI_SHIFT 29

#define SQ_CTRL_QUEUE_INFO_PKT_TYPE_MASK 0x3U
#define SQ_CTRL_QUEUE_INFO_PLDOFF_MASK 0xFFU
#define SQ_CTRL_QUEUE_INFO_UFO_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_TSO_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_UDP_DP_EN_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_MSS_MASK 0x3FFFU
#define SQ_CTRL_QUEUE_INFO_SCTP_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_UC_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_PRI_MASK 0x7U

#define SQ_CTRL_QUEUE_INFO_SET(val, member) \
	(((u32)(val) & SQ_CTRL_QUEUE_INFO_##member##_MASK) << \
	 SQ_CTRL_QUEUE_INFO_##member##_SHIFT)

#define SQ_CTRL_QUEUE_INFO_GET(val, member) \
	(((val) >> SQ_CTRL_QUEUE_INFO_##member##_SHIFT) & \
	 SQ_CTRL_QUEUE_INFO_##member##_MASK)

#define SQ_CTRL_QUEUE_INFO_CLEAR(val, member) \
	((val) & (~(SQ_CTRL_QUEUE_INFO_##member##_MASK << \
		    SQ_CTRL_QUEUE_INFO_##member##_SHIFT)))

#define SQ_TASK_INFO0_TUNNEL_FLAG_SHIFT 19
#define SQ_TASK_INFO0_ESP_NEXT_PROTO_SHIFT 22
#define SQ_TASK_INFO0_INNER_L4_EN_SHIFT 24
#define SQ_TASK_INFO0_INNER_L3_EN_SHIFT 25
#define SQ_TASK_INFO0_INNER_L4_PSEUDO_SHIFT 26
#define SQ_TASK_INFO0_OUT_L4_EN_SHIFT 27
#define SQ_TASK_INFO0_OUT_L3_EN_SHIFT 28
#define SQ_TASK_INFO0_OUT_L4_PSEUDO_SHIFT 29
#define SQ_TASK_INFO0_ESP_OFFLOAD_SHIFT 30
#define SQ_TASK_INFO0_IPSEC_PROTO_SHIFT 31

#define SQ_TASK_INFO0_TUNNEL_FLAG_MASK 0x1U
#define SQ_TASK_INFO0_ESP_NEXT_PROTO_MASK 0x3U
#define SQ_TASK_INFO0_INNER_L4_EN_MASK 0x1U
#define SQ_TASK_INFO0_INNER_L3_EN_MASK 0x1U
#define SQ_TASK_INFO0_INNER_L4_PSEUDO_MASK 0x1U
#define SQ_TASK_INFO0_OUT_L4_EN_MASK 0x1U
#define SQ_TASK_INFO0_OUT_L3_EN_MASK 0x1U
#define SQ_TASK_INFO0_OUT_L4_PSEUDO_MASK 0x1U
#define SQ_TASK_INFO0_ESP_OFFLOAD_MASK 0x1U
#define SQ_TASK_INFO0_IPSEC_PROTO_MASK 0x1U

#define SQ_TASK_INFO0_SET(val, member) \
	(((u32)(val) & SQ_TASK_INFO0_##member##_MASK) << \
	 SQ_TASK_INFO0_##member##_SHIFT)
#define SQ_TASK_INFO0_GET(val, member) \
	(((val) >> SQ_TASK_INFO0_##member##_SHIFT) & \
	 SQ_TASK_INFO0_##member##_MASK)

#define SQ_TASK_INFO1_SET(val, member) \
	(((val) & SQ_TASK_INFO1_##member##_MASK) << \
	 SQ_TASK_INFO1_##member##_SHIFT)
#define SQ_TASK_INFO1_GET(val, member) \
	(((val) >> SQ_TASK_INFO1_##member##_SHIFT) & \
	 SQ_TASK_INFO1_##member##_MASK)

#define SQ_TASK_INFO3_VLAN_TAG_SHIFT 0
#define SQ_TASK_INFO3_VLAN_TYPE_SHIFT 16
#define SQ_TASK_INFO3_VLAN_TAG_VALID_SHIFT 19

#define SQ_TASK_INFO3_VLAN_TAG_MASK 0xFFFFU
#define SQ_TASK_INFO3_VLAN_TYPE_MASK 0x7U
#define SQ_TASK_INFO3_VLAN_TAG_VALID_MASK 0x1U

#define SQ_TASK_INFO3_SET(val, member) \
	(((val) & SQ_TASK_INFO3_##member##_MASK) << \
	 SQ_TASK_INFO3_##member##_SHIFT)
#define SQ_TASK_INFO3_GET(val, member) \
	(((val) >> SQ_TASK_INFO3_##member##_SHIFT) & \
	 SQ_TASK_INFO3_##member##_MASK)

/* the task section format in compact wqe */
#define	SQ_TASK_INFO_PKT_1588_SHIFT         31
#define	SQ_TASK_INFO_IPSEC_PROTO_SHIFT		30
#define	SQ_TASK_INFO_OUT_L3_EN_SHIFT        28
#define	SQ_TASK_INFO_OUT_L4_EN_SHIFT        27
#define	SQ_TASK_INFO_INNER_L3_EN_SHIFT		25
#define	SQ_TASK_INFO_INNER_L4_EN_SHIFT		24
#define	SQ_TASK_INFO_ESP_NEXT_PROTO_SHIFT	22
#define	SQ_TASK_INFO_VLAN_VALID_SHIFT		19
#define	SQ_TASK_INFO_VLAN_SEL_SHIFT         16
#define	SQ_TASK_INFO_VLAN_TAG_SHIFT         0

#define	SQ_TASK_INFO_PKT_1588_MASK          0x1U
#define	SQ_TASK_INFO_IPSEC_PROTO_MASK		0x1U
#define	SQ_TASK_INFO_OUT_L3_EN_MASK         0x1U
#define	SQ_TASK_INFO_OUT_L4_EN_MASK         0x1U
#define	SQ_TASK_INFO_INNER_L3_EN_MASK		0x1U
#define	SQ_TASK_INFO_INNER_L4_EN_MASK		0x1U
#define	SQ_TASK_INFO_ESP_NEXT_PROTO_MASK	0x3U
#define	SQ_TASK_INFO_VLAN_VALID_MASK		0x1U
#define	SQ_TASK_INFO_VLAN_SEL_MASK          0x7U
#define	SQ_TASK_INFO_VLAN_TAG_MASK          0xFFFFU

#define SQ_TASK_INFO_SET(val, member)			\
		(((u32)(val) & SQ_TASK_INFO_##member##_MASK) <<	\
		SQ_TASK_INFO_##member##_SHIFT)
#define SQ_TASK_INFO_GET(val, member)			\
		(((val) >> SQ_TASK_INFO_##member##_SHIFT) &	\
		SQ_TASK_INFO_##member##_MASK)

#define SQ_CTRL_15BIT_QUEUE_INFO_PKT_TYPE_SHIFT 14
#define SQ_CTRL_15BIT_QUEUE_INFO_PLDOFF_SHIFT 16
#define SQ_CTRL_15BIT_QUEUE_INFO_UFO_SHIFT 24
#define SQ_CTRL_15BIT_QUEUE_INFO_TSO_SHIFT 25
#define SQ_CTRL_15BIT_QUEUE_INFO_UDP_DP_EN_SHIFT 26
#define SQ_CTRL_15BIT_QUEUE_INFO_SCTP_SHIFT 27

#define SQ_CTRL_15BIT_QUEUE_INFO_PKT_TYPE_MASK 0x3U
#define SQ_CTRL_15BIT_QUEUE_INFO_PLDOFF_MASK 0xFFU
#define SQ_CTRL_15BIT_QUEUE_INFO_UFO_MASK 0x1U
#define SQ_CTRL_15BIT_QUEUE_INFO_TSO_MASK 0x1U
#define SQ_CTRL_15BIT_QUEUE_INFO_UDP_DP_EN_MASK 0x1U
#define SQ_CTRL_15BIT_QUEUE_INFO_SCTP_MASK 0x1U

#define SQ_CTRL_15BIT_QUEUE_INFO_SET(val, member) \
	(((u32)(val) & SQ_CTRL_15BIT_QUEUE_INFO_##member##_MASK) << \
	 SQ_CTRL_15BIT_QUEUE_INFO_##member##_SHIFT)

#define SQ_CTRL_15BIT_QUEUE_INFO_GET(val, member) \
	(((val) >> SQ_CTRL_15BIT_QUEUE_INFO_##member##_SHIFT) & \
	 SQ_CTRL_15BIT_QUEUE_INFO_##member##_MASK)

#define SQ_CTRL_15BIT_QUEUE_INFO_CLEAR(val, member) \
	((val) & (~(SQ_CTRL_15BIT_QUEUE_INFO_##member##_MASK << \
		    SQ_CTRL_15BIT_QUEUE_INFO_##member##_SHIFT)))

#endif
