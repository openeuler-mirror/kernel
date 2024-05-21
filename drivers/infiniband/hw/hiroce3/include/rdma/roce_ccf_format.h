/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_CCF_FORMAT_H
#define ROCE_CCF_FORMAT_H

/* Align each field with 4bytes. */
#pragma pack(push, 4)

#ifndef BIG_ENDIAN
#define BIG_ENDIAN	0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN	0x1234
#endif

enum ROCE3_CCF_PARAM_ALGO_ID {
	ROCE_CCF_ALGO_ID,
	ROCE_DCQCN_ALGO_ID,
	ROCE_HC3_2_0_ALGO_ID,
	ROCE_LDCP_ALGO_ID,
	ROCE_MIBO_ALGO_ID,
	ROCE_BW_CTRL_ALGO_ID,
	ROCE_CCF_PARAM_MAX_ID = 7
};
#define ROCE_IPQCN_ALGO_ID ROCE_DCQCN_ALGO_ID
#define ROCE_CCF_PARAM_INDEX_GET(vf_id, algo_id) (((vf_id) << 3) | (algo_id))

enum ROCE_CC_ALGO_E {
	ROCE_CC_DISABLE = 0,
	ROCE_CC_DCQCN_ALGO,
	ROCE_CC_LDCP_ALGO,
	ROCE_CC_IPQCN_ALGO,
	ROCE_CC_MIBO_ALGO
};

#define CTX_TBL_WR_KEY_OFFSET 16
#define CTX_TBL_CPY_BYTE_TYPE 48

/* *************************** EVENT *************************** */
enum dcc_event {
	DCC_EVENT_NEW_FLOW = 0,
	DCC_EVENT_DATA_TX = 1,
	DCC_EVENT_RETRANSMIT,
	DCC_EVENT_NACK,
	DCC_EVENT_RTT_RESP,
	DCC_EVENT_CNP_TX = 5,
	DCC_EVENT_CNP_RX,
	DCC_EVENT_ACK = 7,
	DCC_EVENT_REPEAT_READ,
	DCC_EVENT_NORMAL_READ,
	DCC_EVENT_RSVD4 = 10,
	DCC_EVENT_RSVD5,
	DCC_EVENT_TIMER,
	DCC_EVENT_RX,
	DCC_EVENT_ACK_TX,
	DCC_EVENT_ACK_DATA_TX = 15,
	DCC_EVENT_ACK_DATA_RX,
	DCC_EVENT_LESS_MTU_TX,
	DCC_EVENT_LESS_MTU_RSPTX,
	DCC_EVENT_UPDATE_TOKEN,
	DCC_EVENT_VERBS_INIT = 20,
	DCC_EVENT_VERBS_DEINIT,
	DCC_EVENT_RSVD1,
	DCC_EVENT_RSVD2,
	DCC_EVENT_RSVD3,

	DCC_MATCH_RX_CTL = 25,
	DCC_MOD_TX_SW,
	DCC_MOD_TX_READ,
	DCC_MOD_ACK_TX_ACK,
	DCC_MOD_ACK_TX_RR,
	DCC_CTR_AVA_WND = 30,
	DCC_PKT_ACK_EXT,
	DCC_PKT_DATA_EXT,
	DCC_PKT_ACK_DATA_EXT,
	DCC_PKT_ACK_EXT_RX,
	DCC_PKT_DATA_EXT_RX = 35,
	DCC_PKT_ACK_DATA_EXT_RX
};

/* *************************** QPC *************************** */
struct ucode_ccf_sq_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 12;
			u32 retrans_read_req : 1;
			u32 retrans_mark : 1;
			u32 sw_send_sn : 16;
			u32 sw_wnd_timer_stat : 2;
#else
			u32 sw_wnd_timer_stat : 2;
			u32 sw_send_sn : 16;
			u32 retrans_mark : 1;
			u32 retrans_read_req : 1;
			u32 rsvd : 12;
#endif
		} ldcpw;

		u32 value;
	} dw0;
};

struct ucode_ccf_sqa_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 6;
			u32 sw_zero_avail_wnd : 1;
			u32 rr_zero_avail_wnd : 1;
			u32 change2rqa_stg_cnt : 8;
			u32 rr_rcv_sn : 16;
#else
			u32 rr_rcv_sn : 16;
			u32 change2rqa_stg_cnt : 8;
			u32 rr_zero_avail_wnd : 1;
			u32 sw_zero_avail_wnd : 1;
			u32 rsvd : 6;
#endif
		} ldcpw;

		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sw_ack_sn : 16;
			u32 rr_ack_sn : 16;
#else
			u32 rr_ack_sn : 16;
			u32 sw_ack_sn : 16;
#endif
		} ldcpw;

		u32 value;
	} dw1;
};

struct ucode_ccf_rq_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sw_rcv_sn : 16;
			u32 rcv_timestamp : 16;
#else
			u32 rcv_timestamp : 16;
			u32 sw_rcv_sn : 16;
#endif
		} ldcpw;

		u32 value;
	} dw0;
};

struct ucode_ccf_rqa_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rr_send_sn : 16;
			u32 rr_send_ce_sn : 11;
			u32 rr_rsp_ack_cnt : 1;
			u32 rcv_read_rsp : 1;
			u32 ext_hdr_flip : 1;
			u32 rr_wnd_timer_stat : 2;
#else
			u32 rr_wnd_timer_stat : 2;
			u32 ext_hdr_flip : 1;
			u32 rcv_read_rsp : 1;
			u32 rr_rsp_ack_cnt : 1;
			u32 rr_send_ce_sn : 11;
			u32 rr_send_sn : 16;
#endif
		} ldcpw;

		u32 value;
	} dw0;
};

/* *************************** EXT TABLE *************************** */
/* ccf common param tbl */
struct roce_ccf_param {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 np_enable : 8;
			u32 rp_enable : 8;
			u32 ecn_ver : 4;
			u32 cnp_prio_enable : 1;
			u32 ip_enable : 8;
			u32 port_mode : 1;
			u32 rsvd : 2;
#else
			u32 rsvd : 2;
			u32 port_mode : 1;
			u32 ip_enable : 8;
			u32 cnp_prio_enable : 1;
			u32 ecn_ver : 4;
			u32 rp_enable : 8;
			u32 np_enable : 8;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cnp_cos : 3;
			u32 cnp_prio : 3;
			u32 ccf_appid : 8;
			u32 rsvd : 18;
#else
			u32 rsvd : 18;
			u32 ccf_appid : 8;
			u32 cnp_prio : 3;
			u32 cnp_cos : 3;
#endif
		} bs;
		u32 value;
	} dw1;

	u32 rsvd[2];
};

struct roce_dcqcn_param {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 18;
			u32 flow_min_rate : 6;
			u32 token_period : 8;
#else
			u32 token_period : 8;
			u32 flow_min_rate : 6;
			u32 rsvd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_inc_period : 10;
			u32 rsvd : 3;
			u32 cnp_cnt_threshold : 4;
			u32 alpha_dec_period : 10;
			u32 alpha_threshold : 5;
#else
			u32 alpha_threshold : 5;
			u32 alpha_dec_period : 10;
			u32 cnp_cnt_threshold : 4;
			u32 rsvd : 3;
			u32 rate_inc_period : 10;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_inc_period : 16;
			u32 alpha_dec_period : 16;
#else
			u32 alpha_dec_period : 16;
			u32 rate_inc_period : 16;
#endif
		} bs1;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_inc_ai : 8;
			u32 rate_inc_hai : 8;
			u32 rate_dec_period : 8;
			u32 min_cnp_period : 8;
#else
			u32 min_cnp_period : 8;
			u32 rate_dec_period : 8;
			u32 rate_inc_hai : 8;
			u32 rate_inc_ai : 8;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 factor_gita : 4;
			u32 rt_clamp : 1;
			u32 rsvd : 1;
			u32 initial_alpha : 10;
			u32 rate_first_set : 16;
#else
			u32 rate_first_set : 16;
			u32 initial_alpha : 10;
			u32 rsvd : 1;
			u32 rt_clamp : 1;
			u32 factor_gita : 4;
#endif
		} bs;
		u32 value;
	} dw3;
};

struct roce_ipqcn_param {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 18;
			u32 flow_min_rate : 6;
			u32 token_period : 8;
#else
			u32 token_period : 8;
			u32 flow_min_rate : 6;
			u32 rsvd : 18;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_inc_period : 10;
			u32 rsvd : 3;
			u32 cnp_cnt_threshold : 4;
			u32 alpha_dec_period : 10;
			u32 alpha_threshold : 5;
#else
			u32 alpha_threshold : 5;
			u32 alpha_dec_period : 10;
			u32 cnp_cnt_threshold : 4;
			u32 rsvd : 3;
			u32 rate_inc_period : 10;
#endif
		} bs;

		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_inc_period : 16;
			u32 alpha_dec_period : 16;
#else
			u32 alpha_dec_period : 16;
			u32 rate_inc_period : 16;
#endif
		} bs1;
		u32 value;
	} dw1;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rate_inc_ai : 8;
			u32 rate_inc_hai : 8;
			u32 rate_dec_period : 8;
			u32 min_cnp_period : 8;
#else
			u32 min_cnp_period : 8;
			u32 rate_dec_period : 8;
			u32 rate_inc_hai : 8;
			u32 rate_inc_ai : 8;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 factor_gita : 4;
			u32 rt_clamp : 1;
			u32 rsvd : 1;
			u32 initial_alpha : 10;
			u32 rate_first_set : 16;
#else
			u32 rate_first_set : 16;
			u32 initial_alpha : 10;
			u32 rsvd : 1;
			u32 rt_clamp : 1;
			u32 factor_gita : 4;
#endif
		} bs;
		u32 value;
	} dw3;
};

struct roce_ldcp_param {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 alpha : 2;
			u32 beta : 2;
			u32 gamma : 2;
			u32 eta : 2;
			u32 set_flag : 1;
			u32 rsvd : 23;
#else
			u32 rsvd : 23;
			u32 set_flag : 1;
			u32 eta : 2;
			u32 gamma : 2;
			u32 beta : 2;
			u32 alpha : 2;
#endif
		} bs;
		u32 value;
	} dw0;

	u32 rsvd1[3];
};

struct ucode_dcc_ip_table_rate_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 alpha : 14;
			u32 ip_rate : 18;		/* cur_rate, unit:1M */
#else
			u32 ip_rate : 18;		/* cur_rate, unit:1M */
			u32 alpha : 14;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 cnp_flag : 1;
			u32 rsvd : 6;
			u32 cnp_receive : 1;
			u32 f_cnt : 3;
			u32 ai_cnt : 3;
			u32 ip_target_rate : 18;
#else
			u32 ip_target_rate : 18;
			u32 ai_cnt : 3;
			u32 f_cnt : 3;
			u32 cnp_receive : 1;
			u32 rsvd : 6;
			u32 cnp_flag : 1;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 alpha_timestamp : 16;
			u32 rate_timestamp : 16; /* last update rate */
#else
			u32 rate_timestamp : 16; /* last update rate */
			u32 alpha_timestamp : 16;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rcnp_timestamp : 32;
#else
			u32 rcnp_timestamp : 32;
#endif
		} bs;
		u32 value;
	} dw3;
};

struct ucode_dcc_bw_ctrl_ctx {
	union {
		struct {
			u32  bw_ctrl_thd_def : 32;
		} bs;

		u32 value;
	} dw0;

	u32 rsvd1[3];
};

/* *************************** RC EXT TABLE *************************** */
/* dcc ext qpc table struct  */
struct ucode_ext_table_sq_ctx {
	/* DW0 */
	union {
		u32 ldcpw_rsvd;

		u32 value;
	} dw0;

	u32 rsvd;
};

struct ucode_ext_table_sqa_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 21;
			u32 rr_rcv_ce_sn : 11;
#else
			u32 rr_rcv_ce_sn : 11;
			u32 rsvd : 21;
#endif
		} ldcpw;

		u32 value;
	} dw0;

	u32 rsvd;
};

struct ucode_ext_table_rq_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 20;
			u32 sw_rcv_ce_sn : 12;
#else
			u32 sw_rcv_ce_sn : 12;
			u32 rsvd : 20;
#endif
		} ldcpw;

		u32 value;
	} dw0;

	u32 rsvd;
};

struct ucode_ext_table_rqa_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 20;
			u32 sw_send_ce_sn : 12;
#else
			u32 sw_send_ce_sn : 12;
			u32 rsvd : 20;
#endif
		} ldcpw;

		u32 value;
	} dw0;

	u32 rsvd;
};

struct ucode_ext_table_dcc_ctx {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 alpha : 12;
			u32 cur_rate : 20;
#else
			u32 cur_rate : 20;
			u32 alpha : 12;
#endif
		} hc3_1_0;

		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 target_rate : 20;
			u32 ai_cnt : 3;
			u32 f_cnt : 3;
			u32 flow_min_rate : 6;
#else
			u32 flow_min_rate : 6;
			u32 f_cnt : 3;
			u32 ai_cnt : 3;
			u32 target_rate : 20;
#endif
		} hc3_1_0;

		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 alpha_timestamp : 16;
			u32 rate_timestamp : 16;
#else
			u32 rate_timestamp : 16;
			u32 alpha_timestamp : 16;
#endif
		} hc3_1_0;

		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 14;
			u32 cnp_flag : 1;
			u32 cnp_receive : 1;
			u32 rcnp_timestamp : 16;
#else
			u32 rcnp_timestamp : 16;
			u32 cnp_receive : 1;
			u32 cnp_flag : 1;
			u32 rsvd : 14;
#endif
		} hc3_1_0;

		u32 value;
	} dw3;

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 16;
			u32 token_timestamp : 16;
#else
			u32 token_timestamp : 16;
			u32 rsvd : 16;
#endif
		} hc3_1_0;

		u32 value;
	} dw4;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 16;
			u32 cnp_tx_filter_ts : 16;
#else
			u32 cnp_tx_filter_ts : 16;
			u32 rsvd : 16;
#endif
		} hc3_1_0;

		u32 value;
	} dw5;
};

struct smf_rdma_dcc_ip_table {
	struct ucode_dcc_ip_table_rate_ctx algo_para; // dw0-dw3
};

struct ucode_ext_table_qpc_ctx {
	struct ucode_ext_table_sq_ctx sq;
	struct ucode_ext_table_sqa_ctx sqa;
	struct ucode_ext_table_rq_ctx rq;
	struct ucode_ext_table_rqa_ctx rqa;
};


struct tag_iqpcn_hash_entry {
	u32 dw0;
	union {
		struct {
			u32 rsvd_key[7];
			u8 dgid[16];
			u32 srctagl;
		} bs;
		u32 value[12];
	} key;
	union {
		struct {
			u32 rsvd : 4;
			u32 cnt : 28;
		} bs;
		u32 item;
	} dw13;
};

struct tag_ipqcn_hash_value {
	union {
		struct {
			u32 code : 2;
			u32 subcode : 2;
			u32 rsvd : 13;
			u32 node_index : 15;
		} bs;
		u32 value;
	} dw0;
	union {
		struct {
			u32 w : 1;
			u32 sm_id : 3;
			u32 cnt : 28;
		} bs;
		u32 value;
	} dw1;
	u32 rsvd[2];
};

#pragma pack(pop)

#endif // ROCE_CCF_FORMAT_H
