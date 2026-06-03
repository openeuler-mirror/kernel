/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_TX_H__
#define __UNIC_TX_H__

#include <linux/netdevice.h>

struct unic_dev;

enum unic_jfs_ctx_mode {
	UNIC_JFS,
	UNIC_JETTY,
};

#define UNIC_RAW_TYPE			0
#define UNIC_RAW_SQEBB_SIZE		64

#define UNIC_SQE_VA0_OFFSET		12
#define UNIC_SQE_VA0_VALID_BIT		GENMASK(19, 0)
#define UNIC_SQE_VA1_OFFSET		32
#define UNIC_SQE_VA1_VALID_BIT		GENMASK(31, 0)
#define UNIC_SQE_TOKEN_ID_L_MASK	GENMASK(11, 0)
#define UNIC_SQE_TOKEN_ID_H_OFFSET	12U
#define UNIC_SQE_TOKEN_ID_H_MASK	GENMASK(7, 0)
#define UNIC_SQE_SL_BIT			GENMASK(3, 0)

#define UNIC_JFS_DB_BASE_OFFSET		0x1080
#define UNIC_JFS_DB_4K_OFFSET		0x1000
#define UNIC_JFS_DB_64K_OFFSET		0x10000

#define UNIC_PAGE_SIZE_4K		4096
#define UNIC_AVAIL_SGMT_OST_INIT	512

#define UNIC_CQE_STATUS_MAX		8
#define UNIC_CQE_OTHERS_STATUS		7
#define UNIC_CQE_SUB_STATUS_MAX		6
#define UNIC_CQE_OTHERS_SUB_STATUS	5

#define unic_sq_stats_inc(sq, cnt)	do {		\
		typeof(sq) _sq = (sq);			\
		u64_stats_update_begin(&(_sq)->syncp);	\
		((_sq)->stats.cnt)++;			\
		u64_stats_update_end(&(_sq)->syncp);	\
	} while (0)

union l3_hdr_info {
	struct iphdr *v4;
	struct ipv6hdr *v6;
	u8 *hdr;
};

union l4_hdr_info {
	struct tcphdr *tcp;
	struct udphdr *udp;
	u8 *hdr;
};

enum unic_pkt_l4_type {
	UNIC_L4_TYPE_UNKNOWN,
	UNIC_L4_TYPE_TCP,
	UNIC_L4_TYPE_UDP,
	UNIC_L4_TYPE_RESERVE
};

enum unic_pkt_tun_type {
	UNIC_TUN_NONE,
	UNIC_TUN_UDP,
	UNIC_TUN_NVGRE,
	UNIC_TUN_OTHER
};

enum unic_jfs_ta_timeout {
	UNIC_TIMEOUT_128MS,
	UNIC_TIMEOUT_1S,
	UNIC_TIMEOUT_8S,
	UNIC_TIMEOUT_64S
};

enum unic_jfs_state {
	UNIC_JFS_STATE_RESET,
	UNIC_JFS_STATE_READY,
	UNIC_JFS_STATE_ERROR,
	UNIC_JFS_STATE_SUSPEND,
	UNIC_JFS_STATE_RESERVED
};

struct unic_sq_stats {
	u64 pad_err;
	u64 bytes;
	u64 packets;
	u64 busy;
	u64 more;
	u64 restart_queue;
	u64 over_max_sge_num;
	u64 csum_err;
	u64 ci_mismatch;
	u64 vlan_err;
	u64 fd_cnt;
	u64 drop_cnt;
	u64 cfg5_drop_cnt;
	u64 polled_old_pi;
	u64 polled_skb_null;
	u64 pi_ci_over_depth;
	u64 abn_cqe_total_cnt;
	u64 abn_cqe_cnt[UNIC_CQE_STATUS_MAX][UNIC_CQE_SUB_STATUS_MAX];
};

struct unic_jfs_ctx {
	/* DW0 */
	u32 ta_timeout : 2;
	u32 rnr_retry_num : 3;
	u32 type : 3;
	u32 sqe_bb_shift : 4;
	u32 sl : 4;
	u32 state : 3;
	u32 jfs_mode : 1;
	u32 sqe_token_id_l : 12;
	/* DW1 */
	u32 sqe_token_id_h : 8;
	u32 err_mode : 1;
	u32 rsv0 : 1;
	u32 cmp_odr : 1;
	u32 rsv1 : 1;
	u32 sqe_base_addr_l : 20;
	/* DW2 */
	u32 sqe_base_addr_h;
	/* DW3 */
	u32 rsv2;
	/* DW4 */
	u32 tx_jfcn : 20;
	u32 jfrn : 12;
	/* DW5 */
	u32 jfrn1 : 8;
	u32 rsv3 : 4;
	u32 rx_jfcn : 20;
	/* DW6 */
	u32 seid_idx : 10;
	u32 pi_type : 1;
	u32 rsv4 : 21;
	/* DW7 */
	u32 user_data_l;
	/* DW8 */
	u32 user_data_h;
	/* DW9 */
	u32 sqe_position : 1;
	u32 sqe_pld_position : 1;
	u32 sqe_pld_tokenid : 20;
	u32 rsv5 : 10;
	/* DW10 */
	u32 tpn : 24;
	u32 rsv6 : 8;
	/* DW11 */
	u32 rmt_eid : 20;
	u32 rsv7 : 12;
	/* DW12 */
	u32 rmt_tokenid : 20;
	u32 rsv8 : 12;
	/* DW13 - DW15 */
	u32 rsv8_1[3];
	/* DW16 */
	u32 next_send_ssn : 16;
	u32 src_order_wqe : 16;
	/* DW17 */
	u32 src_order_ssn : 16;
	u32 src_order_sgme_cnt : 16;
	/* DW18 */
	u32 src_order_sgme_send_cnt : 16;
	u32 CI : 16;
	/* DW19 */
	u32 wqe_sgmt_send_cnt : 20;
	u32 src_order_wqebb_num : 4;
	u32 src_order_wqe_vld : 1;
	u32 no_wqe_send_cnt : 4;
	u32 so_lp_vld : 1;
	u32 fence_lp_vld : 1;
	u32 strong_fence_lp_vld : 1;
	/* DW20 */
	u32 PI : 16;
	u32 sq_db_doing : 1;
	u32 ost_rce_credit : 15;
	/* DW21 */
	u32 sq_db_retrying : 1;
	u32 wmtp_rsv0 : 31;
	/* DW22 */
	u32 wait_ack_timeout : 1;
	u32 wait_rnr_timeout : 1;
	u32 cqe_ie : 1;
	u32 cqe_sz : 1;
	u32 wml_rsv0 : 28;
	/* DW23 */
	u32 wml_rsv1 : 32;
	/* DW24 */
	u32 next_rcv_ssn : 16;
	u32 next_cpl_bb_idx : 16;
	/* DW25 */
	u32 next_cpl_sgmt_num : 20;
	u32 we_rsv0 : 12;
	/* DW26 */
	u32 next_cpl_bb_num : 4;
	u32 next_cpl_cqe_en : 1;
	u32 next_cpl_info_vld : 1;
	u32 rpting_cqe : 1;
	u32 not_rpt_cqe : 1;
	u32 flush_ssn : 16;
	u32 flush_ssn_vld : 1;
	u32 flush_vld : 1;
	u32 flush_cqe_done : 1;
	u32 we_rsv1 : 5;
	/* DW27 */
	u32 rcved_cont_ssn_num : 20;
	u32 we_rsv2 : 12;
	/* DW28 */
	u32 sq_timer;
	/* DW29 */
	u32 rnr_cnt : 3;
	u32 abt_ssn : 16;
	u32 abt_ssn_vld : 1;
	u32 taack_timeout_flag : 1;
	u32 we_rsv3 : 9;
	u32 err_type_l : 2;
	/* DW30 */
	u32 err_type_h : 7;
	u32 sq_flush_ssn : 16;
	u32 we_rsv4 : 9;
	/* DW31 */
	u32 avail_sgmt_ost : 10;
	u32 read_op_cnt : 10;
	u32 we_rsv5 : 12;
};

struct unic_sqe_ctrl_section {
	__le16 sqe_bd_idx;
	__le16 l3_type : 2;
	__le16 l4_type : 2;
	__le16 l3_csum : 1;
	__le16 l4_csum : 1;
	__le16 ol3_type : 2;
	__le16 ol4_csum : 1;
	__le16 tun_type : 4;
	__le16 tsyn : 1;
	__le16 tso : 1;
	__le16 owner : 1;

	u8 l2hdr_len;
	u8 l3hdr_len;
	u8 l4hdr_len;
	u8 sge_num : 5;
	u8 rsv1 : 2;
	u8 dip_type : 1;

	u8 ol2hdr_len;
	u8 ol3hdr_len;
	u8 ol4hdr_len;
	u8 rsv2;

	__le32 mss : 14;
	__le32 rsv3 : 18;

	__le32 dip0;
	__le32 dip1;
	__le32 dip2;
	__le32 dip3;
};

struct unic_sqe_sge_section {
	__le32 length;
	__le32 token_id : 20;
	__le32 rsv : 12;
	__le64 address;
};

struct unic_sqebb {
	u64 data[8];
};

struct unic_jfs_db {
	__le16 pi;
	__le16 rsv;
};

struct unic_tx_comp_stats {
	u64	bytes;
	u64	packets;
	u64	abn_bytes;
	u64	abn_packets;
};

struct unic_tx_page_info {
	struct page	*p;
	void		*sge_va_addr;
	dma_addr_t	sge_dma_addr;
};

struct unic_tx_buff {
	struct unic_tx_page_info	*page_info;
	u16				num;
	u16				pi;
	u16				ci;
};

struct unic_sq {
	void __iomem		*db_addr;
	struct device		*parent_dev;
	struct unic_sq_stats	stats;
	struct u64_stats_sync	syncp;
	struct unic_jfs_ctx	jfs_ctx;
	struct unic_sqebb	*sqebb;
	dma_addr_t		sqebb_dma_addr;
	struct sk_buff		**skbs;
	struct unic_cq		*cq;
	u16			pi; /* the start of next to product */
	u16			ci; /* the start of next to consume */
	u16			last_pi;
	u16			start_pi;
	bool			check_ci_late;
	u16			queue_index;
	struct net_device	*netdev;
	struct unic_tx_buff	*tx_buff;
};

static inline void unic_sq_abn_cqe_inc(struct unic_sq *sq,
				       unsigned int status,
				       unsigned int sub_status)
{
	if (status > UNIC_CQE_OTHERS_STATUS)
		status = UNIC_CQE_OTHERS_STATUS;
	if (sub_status > UNIC_CQE_OTHERS_SUB_STATUS)
		sub_status = UNIC_CQE_OTHERS_SUB_STATUS;
	u64_stats_update_begin(&sq->syncp);
	sq->stats.abn_cqe_total_cnt++;
	sq->stats.abn_cqe_cnt[status][sub_status]++;
	u64_stats_update_end(&sq->syncp);
}

void unic_poll_tx(struct unic_sq *sq, int budget);
int unic_create_sq(struct unic_dev *unic_dev, u32 idx);
void unic_destroy_sq(struct unic_dev *unic_dev, u32 num);

netdev_tx_t unic_start_xmit(struct sk_buff *skb, struct net_device *netdev);
void unic_clear_sq(struct unic_sq *sq);
void unic_reset_tx_queue(struct net_device *netdev);
void unic_dump_sq_stats(struct net_device *netdev, u32 queue_idx);
void unic_mask_key_words(void *sqebb);

#endif /* __UNIC_TX_H__ */
