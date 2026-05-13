/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_RX_H__
#define __UNIC_RX_H__

#include <linux/netdevice.h>

struct unic_dev;

#define UNIC_RQE_VA_L_PAGE_4K_OFFSET 12
#define UNIC_RQE_VA_L_VALID_BIT GENMASK(19, 0)
#define UNIC_RQE_VA_H_OFFSET 20
#define UNIC_RQE_VA_H_PAGE_4K_OFFSET (UNIC_RQE_VA_H_OFFSET + \
	UNIC_RQE_VA_L_PAGE_4K_OFFSET)
#define UNIC_RQE_VA_H_VALID_BIT GENMASK(31, 0)

#define UNIC_JFR_JFCN_L_VALID_BIT GENMASK(11, 0)
#define UNIC_JFR_JFCN_H_OFFSET 12U
#define UNIC_JFR_JFCN_H_VALID_BIT GENMASK(7, 0)

#define UNIC_RQE_DB_VA_L_64B_OFFSET 6
#define UNIC_RQE_DB_VA_L_VALID_BIT GENMASK(23, 0)
#define UNIC_RQE_DB_VA_M_OFFSET 24
#define UNIC_RQE_DB_VA_M_64B_OFFSET \
	(UNIC_RQE_DB_VA_M_OFFSET + UNIC_RQE_DB_VA_L_64B_OFFSET)
#define UNIC_RQE_DB_VA_M_VALID_BIT GENMASK(31, 0)
#define UNIC_RQE_DB_VA_H_OFFSET 32
#define UNIC_RQE_DB_VA_H_64B_OFFSET \
	(UNIC_RQE_DB_VA_H_OFFSET + UNIC_RQE_DB_VA_M_64B_OFFSET)
#define UNIC_RQE_DB_VA_H_VALID_BIT GENMASK(1, 0)

#define UNIC_RQE_TOKEN_ID_L_MASK GENMASK(13, 0)
#define UNIC_RQE_TOKEN_ID_H_OFFSET 14U
#define UNIC_RQE_TOKEN_ID_H_MASK GENMASK(5, 0)

#define UNIC_JFR_DB_SIZE		4

#define UNIC_RX_BUF_LEN_2K 2048
#define UNIC_RX_BUF_LEN_4K 4096

#define unic_rq_stats_inc(rq, cnt)	do {		\
		typeof(rq) _rq = (rq);			\
		u64_stats_update_begin(&(_rq)->syncp);	\
		((_rq)->stats.cnt)++;			\
		u64_stats_update_end(&(_rq)->syncp);	\
	} while (0)

enum unic_jfr_state {
	UNIC_JFR_STATE_RESET,
	UNIC_JFR_STATE_READY,
	UNIC_JFR_STATE_ERROR,
	UNIC_JFR_STATE_RESERVED,
};

struct unic_channel;

struct unic_rx_ptype {
	u32 ptype : 8;
	u32 csum_level : 2;
	u32 ip_summed : 2;
	u32 l3_type : 4;
	u32 valid : 1;
	u32 hash_type : 3;
	u32 resv : 12;
};

struct unic_rq_stats {
	u64 alloc_skb_err;
	u64 bytes;
	u64 packets;
	u64 err_pkt_len_cnt;
	u64 doi_cnt;
	u64 trunc_cnt;
	u64 multicast;
	u64 l2_err;
	u64 l3_l4_csum_err;
	u64 csum_complete;
	u64 alloc_frag_err;
};

struct unic_jfr_ctx {
	/* DW0 */
	u32 state : 2;
	u32 limit_wl : 2;
	u32 rqe_size_shift : 3;
	u32 token_en : 1;
	u32 rqe_shift : 4;
	u32 rnr_timer : 5;
	u32 record_db_en : 1;
	u32 rqe_token_id_l : 14;
	/* DW1 */
	u32 rqe_token_id_h : 6;
	u32 type : 3;
	u32 rsv : 3;
	u32 rqe_base_addr_l : 20;
	/* DW2 */
	u32 rqe_base_addr_h;
	/* DW3 */
	u32 rqe_position : 1;
	u32 pld_position : 1;
	u32 pld_token_id : 20;
	u32 rsv1 : 10;
	/* DW4 */
	u32 token_value;
	/* DW5 */
	u32 user_data_l;
	/* DW6 */
	u32 user_data_h;
	/* DW7 */
	u32  pi : 16;
	u32  ci : 16;
	/* DW8 */
	u32 idx_que_addr_l;
	/* DW9 */
	u32 idx_que_addr_h : 20;
	u32 jfcn_l : 12;
	/* DW10 */
	u32 jfcn_h : 8;
	u32 record_db_addr_l : 24;
	/* DW11 */
	u32 record_db_addr_m;
	/* DW12 */
	u32 record_db_addr_h : 2;
	u32 cqeie : 1;
	u32 cqesz : 1;
	u32 rsv3 : 28;
	/* DW13 - DW15 */
	u32 rsv4[3];
};

struct unic_rqe {
	__le64 rsv;
	__le64 buff_addr;
};

struct unic_rqe_info {
	void		*buf;
	struct page	*p;
	dma_addr_t	rqe_dma_addr;
	u32		page_offset;
};

struct unic_sw_db {
	void		*db_addr;
	dma_addr_t	db_dma_addr;
};

struct unic_rq {
	struct device		*parent_dev;
	struct unic_rq_stats	stats;
	struct u64_stats_sync	syncp;
	struct unic_jfr_ctx	jfr_ctx;
	struct unic_rqe		*rqe;
	dma_addr_t		rqe_base_dma_addr;
	struct unic_rqe_info	*rqe_info;
	struct unic_sw_db	sw_db;
	struct unic_cq		*cq;
	struct sk_buff		*skb;
	u16			pi; /* the start of next to product */
	u16			ci; /* the start of next to consume */
	u16			queue_index;
	u16			pending_buf;
	struct net_device	*netdev;
	struct page_pool	*page_pool;
};

int unic_create_rq(struct unic_dev *unic_dev, u32 idx);
void unic_destroy_rq(struct unic_dev *unic_dev, u32 idx);
int unic_poll_rx(struct unic_channel *c, int budget,
		 void (*rx_fn)(struct unic_channel *, struct sk_buff *));
void unic_clear_rq(struct unic_rq *rq);
void unic_send_skb_to_stack(struct unic_channel *c, struct sk_buff *skb);

#endif /* __UNIC_RX_H__ */
