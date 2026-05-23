/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_rq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_RQ_H
#define HINIC5_NIC_RQ_H

#include "hinic5_common.h"

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

#define HINIC5_GET_RX_PKT_TYPE(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, PKT_TYPE)
#define HINIC5_GET_RX_IP_TYPE(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, IP_TYPE)
#define HINIC5_GET_RX_ENC_L3_TYPE(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, ENC_L3_TYPE)
#define HINIC5_GET_RX_TUNNEL_PKT_FORMAT(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, TUNNEL_PKT_FORMAT)

#define HINIC5_GET_RX_PKT_UMBCAST(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, PKT_UMBCAST)

#define HINIC5_GET_RX_VLAN_OFFLOAD_EN(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, VLAN_EN)

#define HINIC5_GET_RSS_TYPES(offload_type) \
	RQ_CQE_OFFOLAD_TYPE_GET(offload_type, RSS_TYPE)

#define RQ_CQE_SGE_VLAN_SHIFT 0
#define RQ_CQE_SGE_LEN_SHIFT 16

#define RQ_CQE_SGE_VLAN_MASK 0xFFFFU
#define RQ_CQE_SGE_LEN_MASK 0xFFFFU

#define RQ_CQE_SGE_GET(val, member) \
	(((val) >> RQ_CQE_SGE_##member##_SHIFT) & RQ_CQE_SGE_##member##_MASK)

#define HINIC5_GET_RX_VLAN_TAG(vlan_len) RQ_CQE_SGE_GET(vlan_len, VLAN)

#define HINIC5_GET_RX_PKT_LEN(vlan_len) RQ_CQE_SGE_GET(vlan_len, LEN)

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

#define HINIC5_GET_RX_CSUM_ERR(status) RQ_CQE_STATUS_GET(status, CSUM_ERR)

#define HINIC5_GET_RX_DONE(status) RQ_CQE_STATUS_GET(status, RXDONE)

#define HINIC5_GET_RX_FLUSH(status) RQ_CQE_STATUS_GET(status, FLUSH)

#define HINIC5_GET_RX_BP_EN(status) RQ_CQE_STATUS_GET(status, BP_EN)

#define HINIC5_GET_RX_NUM_LRO(status) RQ_CQE_STATUS_GET(status, NUM_LRO)

#define HINIC5_RX_IS_DECRY_PKT(status) RQ_CQE_STATUS_GET(status, DECRY_PKT)

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
#define HINIC5_GET_RQ_CQE_PKT_NUM(pkt_info) RQ_CQE_PKT_NUM_GET(pkt_info, NUM)

#define RQ_CQE_SUPER_CQE_EN_GET(val, member) \
	(((val) >> RQ_CQE_##member##_SHIFT) & RQ_CQE_##member##_MASK)
#define HINIC5_GET_SUPER_CQE_EN(pkt_info) \
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

#define HINIC5_GET_DECRYPT_STATUS(decry_info) \
	RQ_CQE_DECRY_INFO_GET(decry_info, DECRY_STATUS)

#define HINIC5_GET_ESP_NEXT_HEAD(decry_info) \
	RQ_CQE_DECRY_INFO_GET(decry_info, ESP_NEXT_HEAD)

/* compact cqe field */
/* cqe dw0 */
#define RQ_COMPACT_CQE_STATUS_RXDONE_SHIFT			31
#define RQ_COMPACT_CQE_STATUS_CQE_TYPE_SHIFT			30
#define RQ_COMPACT_CQE_STATUS_TS_FLAG_SHIFT			29
#define RQ_COMPACT_CQE_STATUS_VLAN_EN_SHIFT			28
#define RQ_COMPACT_CQE_STATUS_PKT_FORMAT_SHIFT			25
#define RQ_COMPACT_CQE_STATUS_IP_TYPE_SHIFT			24
#define RQ_COMPACT_CQE_STATUS_CQE_LEN_SHIFT			23
#define RQ_COMPACT_CQE_STATUS_PKT_MC_SHIFT			21
#define RQ_COMPACT_CQE_STATUS_CSUM_ERR_SHIFT			19
#define RQ_COMPACT_CQE_STATUS_PKT_TYPE_SHIFT			16
#define RQ_COMPACT_CQE_STATUS_PKT_LEN_SHIFT			0

#define RQ_COMPACT_CQE_STATUS_RXDONE_MASK			0x1U
#define RQ_COMPACT_CQE_STATUS_CQE_TYPE_MASK			0x1U
#define RQ_COMPACT_CQE_STATUS_TS_FLAG_MASK			0x1U
#define RQ_COMPACT_CQE_STATUS_VLAN_EN_MASK			0x1U
#define RQ_COMPACT_CQE_STATUS_PKT_FORMAT_MASK			0x7U
#define RQ_COMPACT_CQE_STATUS_IP_TYPE_MASK			0x1U
#define RQ_COMPACT_CQE_STATUS_PKT_MC_MASK			0x3U
#define RQ_COMPACT_CQE_STATUS_CQE_LEN_MASK			0x1U
#define RQ_COMPACT_CQE_STATUS_CSUM_ERR_MASK			0x3U
#define RQ_COMPACT_CQE_STATUS_PKT_TYPE_MASK			0x7U
#define RQ_COMPACT_CQE_STATUS_PKT_LEN_MASK			0xFFFFU

#define RQ_COMPACT_CQE_STATUS_GET(val, member) \
	((((val) >> RQ_COMPACT_CQE_STATUS_##member##_SHIFT) & \
	 RQ_COMPACT_CQE_STATUS_##member##_MASK))

/* cqe dw2 */
#define RQ_COMPACT_CQE_OFFLOAD_NUM_LRO_SHIFT			24
#define RQ_COMPACT_CQE_OFFLOAD_VLAN_SHIFT				8
#define RQ_COMPACT_CQE_OFFLOAD_PFE_PKT_SRC_SHIFT		5
#define RQ_COMPACT_CQE_OFFLOAD_PFE_PORT_ID_SHIFT		3
#define RQ_COMPACT_CQE_OFFLOAD_FLOW_MARK_VLD_SHIFT		2
#define RQ_COMPACT_CQE_OFFLOAD_SRC_FUNC_ID_HIGH_SHIFT	0
#define RQ_COMPACT_CQE_OFFLOAD_SRC_FUNC_ID_SHIFT		8

/* cqe dw3 */
#define RQ_COMPACT_CQE_OFFLOAD_SRC_FUNC_ID_LOW_SHIFT	24
#define RQ_COMPACT_CQE_OFFLOAD_FLOW_MARK_SHIFT			0

#define RQ_COMPACT_CQE_OFFLOAD_NUM_LRO_MASK				0xFFU
#define RQ_COMPACT_CQE_OFFLOAD_VLAN_MASK				0xFFFFU
#define RQ_COMPACT_CQE_OFFLOAD_PFE_PKT_SRC_MASK			0x1U
#define RQ_COMPACT_CQE_OFFLOAD_PFE_PORT_ID_MASK			0x3U
#define RQ_COMPACT_CQE_OFFLOAD_FLOW_MARK_VLD_MASK		0x1U
#define RQ_COMPACT_CQE_OFFLOAD_SRC_FUNC_ID_HIGH_MASK	0x3U
#define RQ_COMPACT_CQE_OFFLOAD_SRC_FUNC_ID_LOW_MASK		0xFFU
#define RQ_COMPACT_CQE_OFFLOAD_FLOW_MARK_MASK			0xFFFFFFU

#define RQ_COMPACT_CQE_OFFLOAD_GET(val, member) \
	(((val) >> RQ_COMPACT_CQE_OFFLOAD_##member##_SHIFT) & \
	 RQ_COMPACT_CQE_OFFLOAD_##member##_MASK)

#define RQ_COMPACT_CQE_16BYTE	0
#define RQ_COMPACT_CQE_8BYTE	1

enum RQ_CAST_TYPE {
	UNICAST = 0,
	BROADCAST,
	MULTICAST,
	RESERVED,
};

struct hinic5_rq_cqe {
	u32 status;
	u32 vlan_len;

	u32 offload_type;
	u32 hash_val;
	u32 xid;
	u32 decrypt_info;
	u32 rsvd6;
	u32 pkt_info;
};

struct hinic5_cqe_info {
	u8 packet_offset;

	u8 pkt_mc;
	u8 pfe_pkt_src;
	u8 pfe_port_id;

	u8 lro_num;
	u8 vlan_offload;
	u8 pkt_fmt;
	u8 ip_type;

	u8 pkt_type;
	u8 cqe_len;
	u8 cqe_type;
	u8 ts_flag;

	u16 csum_err;
	u16 vlan_tag;

	u16 pkt_len;
	u16 rss_type;

	u32 rss_hash_value;

	/* CQE info for PFE */
	u16 src_func_id;
	u8 flow_mark_vld;
	u8 rsvd0;

	u32 flow_mark;
} __aligned(32);

struct hinic5_sge_sect {
	struct hinic5_sge sge;
	u32 rsvd;
};

struct hinic5_rq_extend_wqe {
	struct hinic5_sge_sect buf_desc;
	struct hinic5_sge_sect cqe_sect;
};

struct hinic5_rq_normal_wqe {
	u32 buf_hi_addr;
	u32 buf_lo_addr;
	u32 cqe_hi_addr;
	u32 cqe_lo_addr;
};

struct hinic5_rq_compact_wqe {
	u32 buf_hi_addr;
	u32 buf_lo_addr;
};

struct hinic5_rq_wqe {
	union {
		struct hinic5_rq_compact_wqe compact_wqe;
		struct hinic5_rq_normal_wqe normal_wqe;
		struct hinic5_rq_extend_wqe extend_wqe;
	};
};

#endif
