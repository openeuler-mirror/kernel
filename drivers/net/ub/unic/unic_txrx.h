/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_TXRX_H__
#define __UNIC_TXRX_H__

#include <linux/netdevice.h>

struct unic_dev;

#define UNIC_CTX_SHIFT_BASE	6

#define UNIC_CQE_VA_L_OFFSET 12
#define UNIC_CQE_VA_L_VALID_BIT GENMASK(19, 0)
#define UNIC_CQE_VA_H_OFFSET 32
#define UNIC_CQE_VA_H_VALID_BIT GENMASK(31, 0)

#define UNIC_CEQN_VALID_BIT GENMASK(7, 0)

#define UNIC_JFC_DB_OFFSET		0x40

enum unic_armed_jfc {
	UNIC_CTX_NO_ARMED,
	UNIC_CTX_ALWAY_ARMED,
	UNIC_CTX_REG_NEXT_CEQE,
	UNIC_CTX_REG_NEXT_SOLICITED_CEQE,
};

enum unic_jfc_state {
	UNIC_JFC_STATE_INVALID,
	UNIC_JFC_STATE_VALID,
	UNIC_JFC_STATE_ERROR,
};

enum unic_jfc_type {
	UNIC_NORMAL_JFC_TYPE,
	UNIC_RAW_JFC_TYPE,
};

enum unic_jfc_inline {
	UNIC_NO_INLINE_DATA,
	UNIC_INLINE_DATA,
};

enum unic_cqe_size {
	UNIC_64_JFC_CQE_SIZE,
	UNIC_128_JFC_CQE_SIZE,
};

enum unic_cq_cnt_mode {
	UNIC_CQE_CNT_MODE_BY_COUNT,
	UNIC_CQE_CNT_MODE_BY_CI_PI_GAP,
};

enum unic_record_db {
	UNIC_NO_RECORD_EN,
	UNIC_RECORD_EN,
};

enum unic_cq_type {
	UNIC_CQ_SQ = 0,
	UNIC_CQ_RQ,
};

enum unic_jfc_db_type {
	UNIC_JFC_CQ_DB,
	UNIC_JFC_CQ_ARM_DB,
};

enum unic_jfc_db_notify {
	UNIC_JFC_NOTIFY_UNSOLICITED,
	UNIC_JFC_NOTIFY_SOLICITED,
};

enum unic_pkt_l3_type {
	/* 0 ~ 3 is also used by the raw sqe L3T */
	UNIC_L3_TYPE_IPV4,
	UNIC_L3_TYPE_IPV6,
	UNIC_L3_TYPE_NON_IP,

	UNIC_L3_TYPE_ARP,
	UNIC_L3_TYPE_RARP,
	UNIC_L3_TYPE_LLDP,
	UNIC_L3_TYPE_STP,
	UNIC_L3_TYPE_MAC_PAUSE,
	UNIC_L3_TYPE_PFC_PAUSE,
	UNIC_L3_TYPE_CNM,
	UNIC_L3_TYPE_PTP,

	UNIC_L3_TYPE_RESV
};

struct unic_jfc_ctx {
	/* DW0 */
	u32 state : 2;
	u32 arm_st : 2;
	u32 shift : 4;
	u32 cqe_size : 1;
	u32 record_db_en : 1;
	u32 jfc_type : 1;
	u32 inline_en : 1;
	u32 cqe_base_addr_l : 20;
	/* DW1 */
	u32 cqe_base_addr_h;
	/* DW2 */
	union {
		struct {
			u32 queue_token_id : 20;
			u32 cq_cnt_mode : 1;
			u32 rsv0 : 3;
			u32 ceqn : 8;
		} dw2_ceqn8;
		struct {
			u32 queue_token_id : 20;
			u32 cq_cnt_mode : 1;
			u32 rsv0 : 2;
			u32 ceqn : 9;
		} dw2_ceqn9;
	};
	/* DW3 */
	u32 ad : 24;
	u32 rsv1 : 8;
	/* DW4 */
	u32 pi : 22;
	u32 cqe_coalesce_cnt : 10;
	/* DW5 */
	u32 ci : 22;
	u32 cqe_coalesce_period : 3;
	u32 rsv2 : 7;
	/* DW6 */
	u32 record_db_addr_l;
	/* DW7 */
	u32 record_db_addr_h : 26;
	u32 rsv3 : 6;
	/* DW8 */
	u32 queue_position : 1;
	u32 push_cqe_en : 1;
	u32 token_en : 1;
	u32 rsv4 : 9;
	u32 tpn : 20;
	/* DW9 ~ DW12 */
	u32 rmt_eid[4];
	/* DW13 */
	u32 seid_idx : 10;
	u32 rmt_token_id : 20;
	u32 rsv5 : 2;
	/* DW14 */
	u32 remote_token_value;
	/* DW15 */
	u32 int_vector : 16;
	u32 stars_en : 1;
	u32 rsv6 : 15;
	/* DW16 */
	u32 poll : 1;
	u32 cqe_report_timer : 24;
	u32 se : 1;
	u32 arm_sn : 2;
	u32 rsv7 : 4;
	/* DW17 */
	u32 se_cqe_idx : 24;
	u32 rsv8 : 8;
	/* DW18 */
	u32 wr_cqe_idx : 22;
	u32 rsv9 : 10;
	/* DW19 */
	u32 cqe_cnt : 24;
	u32 rsv10 : 8;
	/* DW20 ~ DW31 */
	u32 rsv12[12];
};

union unic_cqe {
	struct {
		/* DW0 */
		u8 resv0 : 2;
		u8 owner : 1;
		u8 resv1 : 4;
		u8 fd : 1;
		u8 resv2;
		u8 sub_status;
		u8 status;
		/* DW1 */
		u16 raw_ci;
		u16 lcl_jfsn_low;
		/* DW2 */
		u32 lcl_jfsn_high : 4;
		u32 resv3 : 28;
		/* DW3 ~ DW15 */
		u32 resv4[13];
	} tx;

	struct {
		/* DW0 */
		u8 owner : 1;
		u8 doi : 1;
		u8 ol3_err : 1;
		u8 ol4_err : 1;
		u8 ts_vld : 1;
		u8 udp0 : 1;
		u8 trunc : 1;
		u8 resv1 : 1;
		u8 crcp : 1;
		u8 l3l4p : 1;
		u8 hoi : 1;
		u8 l2_type : 2;
		u8 l2_err : 1;
		u8 l3_err : 1;
		u8 l4_err : 1;
		u8 ptype;
		u8 ol2_type : 2;
		u8 resv2 : 6;
		/* DW1 */
		u16 start_rqe_idx;
		u16 packet_len;
		/* DW2 */
		u32 lcl_jfrn : 20;
		u32 resv3 : 12;
		/* DW3 */
		u32 rss_hash;
		/* DW4 ~ DW5 */
		u64 timestamp;
		/* DW6 */
		u16 unknown_pkt_l2_checksum;
		u16 resv4;
		/* DW7 ~ DW15 */
		u32 resv5[9];
	} rx;
};

struct unic_jfc_db {
	__le32 ci : 24;
	__le32 notify : 1;
	__le32 cmd_ssn : 2;
	__le32 type : 1;
	__le32 rsv0 : 4;

	__le32 jfc_num : 20;
	__le32 rsv1 : 12;
};

struct unic_cq {
	void __iomem		*db_addr;
	union unic_cqe		*cqe;
	dma_addr_t		cqe_dma_addr;
	struct unic_jfc_ctx	jfc_ctx;
	u32			jfcn;
	u32			ci; /* the start of next to consume */
};

static inline u8 unic_get_cqe_size(void)
{
	return sizeof(union unic_cqe);
}

static inline bool unic_cqe_owner_is_soft(u8 jfc_shift, u32 ci, u8 owner)
{
	return owner != ((ci >> jfc_shift) & 1);
}

bool unic_jfc_support_ceqn9(struct unic_dev *unic_dev);
int unic_create_cq(struct unic_dev *unic_dev, u32 idx, enum unic_cq_type type);
void unic_destroy_cq(struct unic_dev *unic_dev, u32 num, enum unic_cq_type);
int unic_napi_poll(struct napi_struct *napi, int budget);
void unic_cq_doorbell(struct unic_cq *cq, u32 last_ci);
void unic_clear_all_queue(struct net_device *netdev);

#endif /* __UNIC_TXRX_H__ */
