/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_JFS_H__
#define __UBASEPROXY_JFS_H__

#include <linux/dma-mapping.h>

#include "ubaseproxy_dev.h"

#define UBASEPROXY_JETTY_CTX_JFRN_H_OFFSET 12
#define DEFAULT_AVAIL_SGMT_OST_VAL 512

#define UBASEPROXY_SQEBB_SIZE			64
#define UBASEPROXY_SQE_VA0_OFFSET		12
#define UBASEPROXY_SQE_VA0_VALID_BIT		GENMASK(19, 0)
#define UBASEPROXY_SQE_VA1_OFFSET		32
#define UBASEPROXY_SQE_VA1_VALID_BIT		GENMASK(31, 0)
#define UBASEPROXY_SQE_TOKEN_ID_L_MASK		GENMASK(11, 0)
#define UBASEPROXY_SQE_TOKEN_ID_H_OFFSET	12U
#define UBASEPROXY_SQE_TOKEN_ID_H_MASK		GENMASK(7, 0)

enum ubaseproxy_jetty_state {
	UBASEPROXY_JETTY_STATE_RESET,
	UBASEPROXY_JETTY_STATE_READY,
	UBASEPROXY_JETTY_STATE_ERROR,
	UBASEPROXY_JETTY_STATE_SUSPEND,
	UBASEPROXY_JETTY_STATE_RESERVE,
};

enum ubaseproxy_jetty_mode {
	UBASEPROXY_JFS_MODE,
	UBASEPROXY_JETTY_MODE,
};

enum ubaseproxy_jetty_type {
	UBASEPROXY_JETTY_TYPE_RAW_OR_NIC,
	UBASEPROXY_JETTY_TYPE_UM,
	UBASEPROXY_JETTY_TYPE_RC,
	UBASEPROXY_JETTY_TYPE_RM,
	UBASEPROXY_JETTY_TYPE_RESERVED,
};

enum ubaseproxy_jtg_bind_state {
	UBASEPROXY_JETTY_GRP_UNBIND,
	UBASEPROXY_JETTY_GRP_BIND,
};

struct ubaseproxy_jetty_key_words {
	enum ubaseproxy_jetty_state	state;
	void				*safety_sqe_addr;
	dma_addr_t			safety_sqe_dma_addr;
	u32				sqebb_depth;
	u32				tx_jfcn;
	u32				rx_jfcn;
	enum ubaseproxy_jetty_mode	mode;
	enum ubaseproxy_jtg_bind_state	jtg_bind_state;
};

struct ubaseproxy_jetty_ctx {
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
	u32 exp_mode : 1;
	u32 ctp_rc_mul_path_mode : 1;
	u32 cmp_odr : 1;
	u32 wqe_lock_buffer_en : 1;
	u32 sqe_base_addr_l : 20;
	/* DW2 */
	u32 sqe_base_addr_h;
	/* DW3 */
	u32 rsv0;
	/* DW4 */
	u32 tx_jfcn : 20;
	u32 jfrn_l : 12;
	/* DW5 */
	u32 jfrn_h : 8;
	u32 rsv1 : 4;
	u32 rx_jfcn : 20;
	/* DW6 */
	u32 seid_idx : 10;
	u32 pi_type : 1;
	u32 rsv2 : 21;
	/* DW7 */
	u32 user_data_l;
	/* DW8 */
	u32 user_data_h;
	/* DW9 */
	u32 sqe_position : 1;
	u32 sqe_pld_position : 1;
	u32 sqe_pld_tokenid : 20;
	u32 rsv3 : 10;
	/* DW10 */
	u32 tpn : 24;
	u32 rsv4 : 8;
	/* DW11 */
	u32 rmt_eid : 20;
	u32 rsv5 : 12;
	/* DW12 */
	u32 rmt_tokenid : 20;
	u32 rsv6 : 4;
	u32 safety_sqe_tokenid_l : 8;
	/* DW13 */
	u32 safety_sqe_tokenid_h : 12;
	u32 safety_sqe_base_addr_l : 20;
	/* DW14 */
	u32 safety_sqe_base_addr_h;
	/* DW15 */
	u32 stash_en : 1;
	u32 rsv7 : 31;
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
	u32 stash_SrcID : 9;
	u32 stash_LPID : 5;
	u32 stash_rsv : 2;
	u32 wmtp_rsv0 : 15;
	/* DW22 */
	u32 wait_ack_timeout : 1;
	u32 wait_rnr_timeout : 1;
	u32 cqe_ie : 1;
	u32 cqe_sz : 1;
	u32 wml_rsv0 : 28;
	/* DW23 */
	u32 cur_wqe_bb_num : 4;
	u32 add_rd_op_cnt_val : 10;
	u32 wm_rsv0 : 18;
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
	u32 sub_rd_op_cnt_val : 10;
	u32 we_rsv5 : 2;
	/* DW32 - DW63 */
	u32 taack_nack_bm[32];
};

struct ubaseproxy_jetty_default {
	struct ubaseproxy_jetty_ctx	create_mask;
	struct ubaseproxy_jetty_ctx	modify_mask;
	struct ubaseproxy_jetty_ctx	default_value;
};

int ubaseproxy_handle_create_jfs_ctx_req(struct ubaseproxy_dev *udev,
					 struct ubase_proxy_req_msg *req);

#endif /* __UBASEPROXY_JFS_H__ */
