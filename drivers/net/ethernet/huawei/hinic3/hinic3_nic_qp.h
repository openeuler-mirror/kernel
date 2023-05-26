/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Huawei Technologies Co., Ltd */

#ifndef HINIC3_NIC_QP_H
#define HINIC3_NIC_QP_H

#include "hinic3_common.h"

#define TX_MSS_DEFAULT 0x3E00
#define TX_MSS_MIN 0x50

#define HINIC3_MAX_SQ_SGE 18

#define RQ_CQE_OFFOLAD_TYPE_PKT_TYPE_SHIFT 0
#define RQ_CQE_OFFOLAD_TYPE_IP_TYPE_SHIFT 5
#define RQ_CQE_OFFOLAD_TYPE_ENC_L3_TYPE_SHIFT 7
#define RQ_CQE_OFFOLAD_TYPE_TUNNEL_PKT_FORMAT_SHIFT 8
#define RQ_CQE_OFFOLAD_TYPE_PKT_UMBCAST_SHIFT 19
#define RQ_CQE_OFFOLAD_TYPE_VLAN_EN_SHIFT 21
#define RQ_CQE_OFFOLAD_TYPE_RSS_TYPE_SHIFT 24

#define RQ_CQE_OFFOLAD_TYPE_PKT_TYPE_MASK 0x1FU
#define RQ_CQE_OFFOLAD_TYPE_IP_TYPE_MASK 0x3U
#define RQ_CQE_OFFOLAD_TYPE_ENC_L3_TYPE_MASK 0x1U
#define RQ_CQE_OFFOLAD_TYPE_TUNNEL_PKT_FORMAT_MASK 0xFU
#define RQ_CQE_OFFOLAD_TYPE_PKT_UMBCAST_MASK 0x3U
#define RQ_CQE_OFFOLAD_TYPE_VLAN_EN_MASK 0x1U
#define RQ_CQE_OFFOLAD_TYPE_RSS_TYPE_MASK 0xFFU

#define RQ_CQE_OFFOLAD_TYPE_GET(val, member) \
	(((val) >> RQ_CQE_OFFOLAD_TYPE_##member##_SHIFT) & \
	 RQ_CQE_OFFOLAD_TYPE_##member##_MASK)

#define HINIC3_GET_RX_PKT_TYPE(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, PKT_TYPE)
#define HINIC3_GET_RX_IP_TYPE(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, IP_TYPE)
#define HINIC3_GET_RX_ENC_L3_TYPE(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, ENC_L3_TYPE)
#define HINIC3_GET_RX_TUNNEL_PKT_FORMAT(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, TUNNEL_PKT_FORMAT)

#define HINIC3_GET_RX_PKT_UMBCAST(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, PKT_UMBCAST)

#define HINIC3_GET_RX_VLAN_OFFLOAD_EN(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, VLAN_EN)

#define HINIC3_GET_RSS_TYPES(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, RSS_TYPE)

#define RQ_CQE_SGE_VLAN_SHIFT 0
#define RQ_CQE_SGE_LEN_SHIFT 16

#define RQ_CQE_SGE_VLAN_MASK 0xFFFFU
#define RQ_CQE_SGE_LEN_MASK 0xFFFFU

#define RQ_CQE_SGE_GET(val, member) \
	(((val) >> RQ_CQE_SGE_##member##_SHIFT) & RQ_CQE_SGE_##member##_MASK)

#define HINIC3_GET_RX_VLAN_TAG(vlan_len) RQ_CQE_SGE_GET(vlan_len, VLAN)

#define HINIC3_GET_RX_PKT_LEN(vlan_len) RQ_CQE_SGE_GET(vlan_len, LEN)

#define RQ_CQE_STATUS_CSUM_ERR_SHIFT 0
#define RQ_CQE_STATUS_NUM_LRO_SHIFT 16
#define RQ_CQE_STATUS_LRO_PUSH_SHIFT 25
#define RQ_CQE_STATUS_LRO_ENTER_SHIFT 26
#define RQ_CQE_STATUS_LRO_INTR_SHIFT 27

#define RQ_CQE_STATUS_BP_EN_SHIFT 30
#define RQ_CQE_STATUS_RXDONE_SHIFT 31
#define RQ_CQE_STATUS_DECRY_PKT_SHIFT 29
#define RQ_CQE_STATUS_FLUSH_SHIFT 28

#define RQ_CQE_STATUS_CSUM_ERR_MASK 0xFFFFU
#define RQ_CQE_STATUS_NUM_LRO_MASK 0xFFU
#define RQ_CQE_STATUS_LRO_PUSH_MASK 0X1U
#define RQ_CQE_STATUS_LRO_ENTER_MASK 0X1U
#define RQ_CQE_STATUS_LRO_INTR_MASK 0X1U
#define RQ_CQE_STATUS_BP_EN_MASK 0X1U
#define RQ_CQE_STATUS_RXDONE_MASK 0x1U
#define RQ_CQE_STATUS_FLUSH_MASK 0x1U
#define RQ_CQE_STATUS_DECRY_PKT_MASK 0x1U

#define RQ_CQE_STATUS_GET(val, member) \
	(((val) >> RQ_CQE_STATUS_##member##_SHIFT) & \
	 RQ_CQE_STATUS_##member##_MASK)

#define HINIC3_GET_RX_CSUM_ERR(status) RQ_CQE_STATUS_GET(status, CSUM_ERR)

#define HINIC3_GET_RX_DONE(status) RQ_CQE_STATUS_GET(status, RXDONE)

#define HINIC3_GET_RX_FLUSH(status) RQ_CQE_STATUS_GET(status, FLUSH)

#define HINIC3_GET_RX_BP_EN(status) RQ_CQE_STATUS_GET(status, BP_EN)

#define HINIC3_GET_RX_NUM_LRO(status) RQ_CQE_STATUS_GET(status, NUM_LRO)

#define HINIC3_RX_IS_DECRY_PKT(status) RQ_CQE_STATUS_GET(status, DECRY_PKT)

#define RQ_CQE_SUPER_CQE_EN_SHIFT 0
#define RQ_CQE_PKT_NUM_SHIFT 1
#define RQ_CQE_PKT_LAST_LEN_SHIFT 6
#define RQ_CQE_PKT_FIRST_LEN_SHIFT 19

#define RQ_CQE_SUPER_CQE_EN_MASK 0x1
#define RQ_CQE_PKT_NUM_MASK 0x1FU
#define RQ_CQE_PKT_FIRST_LEN_MASK 0x1FFFU
#define RQ_CQE_PKT_LAST_LEN_MASK 0x1FFFU

#define RQ_CQE_PKT_NUM_GET(val, member) \
	(((val) >> RQ_CQE_PKT_##member##_SHIFT) & RQ_CQE_PKT_##member##_MASK)
#define HINIC3_GET_RQ_CQE_PKT_NUM(pkt_info) RQ_CQE_PKT_NUM_GET(pkt_info, NUM)

#define RQ_CQE_SUPER_CQE_EN_GET(val, member) \
	(((val) >> RQ_CQE_##member##_SHIFT) & RQ_CQE_##member##_MASK)
#define HINIC3_GET_SUPER_CQE_EN(pkt_info) \
	RQ_CQE_SUPER_CQE_EN_GET(pkt_info, SUPER_CQE_EN)

#define RQ_CQE_PKT_LEN_GET(val, member) \
	(((val) >> RQ_CQE_PKT_##member##_SHIFT) & RQ_CQE_PKT_##member##_MASK)

#define RQ_CQE_DECRY_INFO_DECRY_STATUS_SHIFT 8
#define RQ_CQE_DECRY_INFO_ESP_NEXT_HEAD_SHIFT 0

#define RQ_CQE_DECRY_INFO_DECRY_STATUS_MASK 0xFFU
#define RQ_CQE_DECRY_INFO_ESP_NEXT_HEAD_MASK 0xFFU

#define RQ_CQE_DECRY_INFO_GET(val, member) \
	(((val) >> RQ_CQE_DECRY_INFO_##member##_SHIFT) & \
	 RQ_CQE_DECRY_INFO_##member##_MASK)

#define HINIC3_GET_DECRYPT_STATUS(decry_info) \
	RQ_CQE_DECRY_INFO_GET(decry_info, DECRY_STATUS)

#define HINIC3_GET_ESP_NEXT_HEAD(decry_info) \
	RQ_CQE_DECRY_INFO_GET(decry_info, ESP_NEXT_HEAD)

struct hinic3_rq_cqe {
	u32 status;
	u32 vlan_len;

	u32 offload_type;
	u32 hash_val;
	u32 xid;
	u32 decrypt_info;
	u32 rsvd6;
	u32 pkt_info;
};

struct hinic3_sge_sect {
	struct hinic3_sge sge;
	u32 rsvd;
};

struct hinic3_rq_extend_wqe {
	struct hinic3_sge_sect buf_desc;
	struct hinic3_sge_sect cqe_sect;
};

struct hinic3_rq_normal_wqe {
	u32 buf_hi_addr;
	u32 buf_lo_addr;
	u32 cqe_hi_addr;
	u32 cqe_lo_addr;
};

struct hinic3_rq_wqe {
	union {
		struct hinic3_rq_normal_wqe normal_wqe;
		struct hinic3_rq_extend_wqe extend_wqe;
	};
};

struct hinic3_sq_wqe_desc {
	u32 ctrl_len;
	u32 queue_info;
	u32 hi_addr;
	u32 lo_addr;
};

/* Engine only pass first 12B TS field directly to uCode through metadata
 * vlan_offoad is used for hardware when vlan insert in tx
 */
struct hinic3_sq_task {
	u32 pkt_info0;
	u32 ip_identify;
	u32 pkt_info2; /* ipsec used as spi */
	u32 vlan_offload;
};

struct hinic3_sq_bufdesc {
	u32 len; /* 31-bits Length, L2NIC only use length[17:0] */
	u32 rsvd;
	u32 hi_addr;
	u32 lo_addr;
};

struct hinic3_sq_compact_wqe {
	struct hinic3_sq_wqe_desc wqe_desc;
};

struct hinic3_sq_extend_wqe {
	struct hinic3_sq_wqe_desc wqe_desc;
	struct hinic3_sq_task task;
	struct hinic3_sq_bufdesc buf_desc[0];
};

struct hinic3_sq_wqe {
	union {
		struct hinic3_sq_compact_wqe compact_wqe;
		struct hinic3_sq_extend_wqe extend_wqe;
	};
};

/* use section pointer for support non continuous wqe */
struct hinic3_sq_wqe_combo {
	struct hinic3_sq_wqe_desc *ctrl_bd0;
	struct hinic3_sq_task *task;
	struct hinic3_sq_bufdesc *bds_head;
	struct hinic3_sq_bufdesc *bds_sec2;
	u16 first_bds_num;
	u32 wqe_type;
	u32 task_type;
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
	SQ_WQE_TASKSECT_46BITS = 0,
	SQ_WQE_TASKSECT_16BYTES = 1,
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
#define SQ_CTRL_QUEUE_INFO_TCPUDP_CS_SHIFT 12
#define SQ_CTRL_QUEUE_INFO_MSS_SHIFT 13
#define SQ_CTRL_QUEUE_INFO_SCTP_SHIFT 27
#define SQ_CTRL_QUEUE_INFO_UC_SHIFT 28
#define SQ_CTRL_QUEUE_INFO_PRI_SHIFT 29

#define SQ_CTRL_QUEUE_INFO_PKT_TYPE_MASK 0x3U
#define SQ_CTRL_QUEUE_INFO_PLDOFF_MASK 0xFFU
#define SQ_CTRL_QUEUE_INFO_UFO_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_TSO_MASK 0x1U
#define SQ_CTRL_QUEUE_INFO_TCPUDP_CS_MASK 0x1U
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

#ifdef static
#undef static
#define LLT_STATIC_DEF_SAVED
#endif

static inline u32 hinic3_get_pkt_len_for_super_cqe(const struct hinic3_rq_cqe *cqe,
						   bool last)
{
	u32 pkt_len = hinic3_hw_cpu32(cqe->pkt_info);

	if (!last)
		return RQ_CQE_PKT_LEN_GET(pkt_len, FIRST_LEN);
	else
		return RQ_CQE_PKT_LEN_GET(pkt_len, LAST_LEN);
}

/* *
 * hinic3_set_vlan_tx_offload - set vlan offload info
 * @task: wqe task section
 * @vlan_tag: vlan tag
 * @vlan_type: 0--select TPID0 in IPSU, 1--select TPID0 in IPSU
 * 2--select TPID2 in IPSU, 3--select TPID3 in IPSU, 4--select TPID4 in IPSU
 */
static inline void hinic3_set_vlan_tx_offload(struct hinic3_sq_task *task,
					      u16 vlan_tag, u8 vlan_type)
{
	task->vlan_offload = SQ_TASK_INFO3_SET(vlan_tag, VLAN_TAG) |
			     SQ_TASK_INFO3_SET(vlan_type, VLAN_TYPE) |
			     SQ_TASK_INFO3_SET(1U, VLAN_TAG_VALID);
}

#endif
