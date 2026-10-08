// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include "counters.h"
#include "dump_fields.h"

#define DEFAULT_DESCRIPTION ""
#define DEFAULT_BUSINESS_TYPE ALL_BIZ
#define MASK_SELECTOR(_1, _2, NAME, ...) NAME
#define BIT_OR_GENMASK_ULL(...)\
	MASK_SELECTOR(__VA_ARGS__, GENMASK_ULL, BIT_ULL)(__VA_ARGS__)
#define INIT_DUMP_FIELD_INFO(name, mask_array)\
	{name, BIT_OR_GENMASK_ULL mask_array, DEFAULT_DESCRIPTION, ALL_BIZ}
#define INIT_DUMP_FIELD_INFO_1(name, mask_array, desc)\
	{name, BIT_OR_GENMASK_ULL mask_array, desc, ALL_BIZ}
#define INIT_DUMP_FIELD_INFO_2(name, mask_array, desc, biz)\
	{name, BIT_OR_GENMASK_ULL mask_array, desc, biz}
#define FIELD_NAME_SIZE 30
#define DESCRIPTION_SIZE 200
#define ONE_DUMP_MAX_FIELD_SIZE 30

enum business_e {
	ALL_BIZ,
	SOFTWARE,
	HARDWARE
};

struct nbl_dump_field_info {
	char field_name[FIELD_NAME_SIZE];
	u64 mask;
	char description[DESCRIPTION_SIZE];
	enum business_e business_type;
};

struct nbl_cache_dump {
	u32 byte_index;
	struct nbl_dump_field_info fields[ONE_DUMP_MAX_FIELD_SIZE];
};

static const struct nbl_cache_dump nbl_qpc_dump_table_v2[] = {
	{0x00, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63)), */
			INIT_DUMP_FIELD_INFO("mig", (62)),
			INIT_DUMP_FIELD_INFO("tver", (61, 60)),
			INIT_DUMP_FIELD_INFO("stat_id", (59, 52)),
			INIT_DUMP_FIELD_INFO_1("host_id", (51, 49),
				"0- rsv; 1- host; 2- ecpu; 3- icpu"),
			INIT_DUMP_FIELD_INFO("vfid", (48, 40)),
			INIT_DUMP_FIELD_INFO("qpn", (39, 16)),
			INIT_DUMP_FIELD_INFO("p_key", (15, 0)),
		}
	},
	{0x08, {
			INIT_DUMP_FIELD_INFO("service_type", (63, 60)),
			INIT_DUMP_FIELD_INFO("qp_state", (59, 56)),
			INIT_DUMP_FIELD_INFO("pmtu", (55, 52)),
			INIT_DUMP_FIELD_INFO("iorq_ba", (51, 0)),
		}
	},
	{0x10, {
			INIT_DUMP_FIELD_INFO_1("qp1_mode", (63), "0- QP0; 1- QP1"),
			INIT_DUMP_FIELD_INFO("sch_net_tc", (62, 60)),
			INIT_DUMP_FIELD_INFO("pd_index", (59, 36)),
			/* INIT_DUMP_FIELD_INFO("rsv", (35)), */
			INIT_DUMP_FIELD_INFO("sport_id", (34, 24)),
			INIT_DUMP_FIELD_INFO_1("credit_en", (23),
				"AETH credit enable: 0- Disabled; 1- Enabled"),
			INIT_DUMP_FIELD_INFO_1("cc_pkt_num_en", (22),
				"0- pkt_blk_cnt is rounded down; 1- pkt_blk_cnt is rounded up"),
			INIT_DUMP_FIELD_INFO("wqe_prefetch_en", (21)),
			INIT_DUMP_FIELD_INFO_1("tunnel_en", (20),
				"0- The packet will not go through the tunnel; "
				"1- The packet will go through the tunnel."),
			INIT_DUMP_FIELD_INFO("rq_size", (19, 16)),
			INIT_DUMP_FIELD_INFO("rqwqe_ts", (15, 12)),
			INIT_DUMP_FIELD_INFO_1("qp_type", (11, 10),
				"0- Normal QP; 1- ini_qp; 2- tgt_qp"),
			INIT_DUMP_FIELD_INFO_1("sq_pm", (9, 8),
				"0- Level 0 addressing; 1- Level 1 addressing"),
			INIT_DUMP_FIELD_INFO_1("rq_pm", (7, 6),
				"0- Level 0 addressing; 1- Level 1 addressing"),
			INIT_DUMP_FIELD_INFO_1("atomic_en", (5),
				"0- Does not support Atomic operations; "
				"1- Supports Atomic operations"),
			INIT_DUMP_FIELD_INFO("local_rnr_timer_value", (4, 0)),
		}
	},
	{0x18, {
			INIT_DUMP_FIELD_INFO("swrqpi_th", (63, 61)),
			INIT_DUMP_FIELD_INFO_1("cc_mode", (60, 58),
				"0- CC Disabled; 1- NBL_CC; 2- DCQCN; 3- NBL_SCC"),
			INIT_DUMP_FIELD_INFO("hw_rqci_th", (57, 55)),
			INIT_DUMP_FIELD_INFO("qpc_shadowarea_ba", (54, 0)),
		}
	},
	{0x20, {
			INIT_DUMP_FIELD_INFO("vlan_tag", (63, 48)),
			INIT_DUMP_FIELD_INFO("ipv4", (47)),
			/* INIT_DUMP_FIELD_INFO("rsv", (46, 40)), */
			INIT_DUMP_FIELD_INFO_1("atomic_no_fence", (40),
				"0- Atomic operations will fence; "
				"1- Atomic operations won't fence"),
			INIT_DUMP_FIELD_INFO("rq_pd_ba/srqn", (39, 0)),
		}
	},
	{0x28, {
			INIT_DUMP_FIELD_INFO("rq_pd_ba/srqn", (63, 52)),
			INIT_DUMP_FIELD_INFO("cc_targetwin_min", (51, 32)),
			INIT_DUMP_FIELD_INFO("ud_qkey", (31, 0)),
		}
	},
	{0x30, {
			INIT_DUMP_FIELD_INFO("sq_size", (63, 60)),
			INIT_DUMP_FIELD_INFO("dest_qpn", (59, 36)),
			INIT_DUMP_FIELD_INFO("tx_retry_th", (35, 33)),
			INIT_DUMP_FIELD_INFO("srp_en", (32)),
			INIT_DUMP_FIELD_INFO("srq_en", (31)),
			INIT_DUMP_FIELD_INFO("irq_size", (30, 28)),
			/* INIT_DUMP_FIELD_INFO("rsv", (27, 20)), */
			INIT_DUMP_FIELD_INFO("rto_timer_value", (19, 15)),
			INIT_DUMP_FIELD_INFO("txmr_frmr_en", (14)),
			INIT_DUMP_FIELD_INFO("cc_rttminth_add_mult", (13, 12)),
			/* INIT_DUMP_FIELD_INFO("rsv", (11, 8)), */
			INIT_DUMP_FIELD_INFO("src_addr_seq_num", (7, 4)),
			INIT_DUMP_FIELD_INFO("oamack_tc_en", (3)),
			INIT_DUMP_FIELD_INFO("oamack_net_tc", (2, 0)),
		}
	},
	{0x38, {
			INIT_DUMP_FIELD_INFO_1("oamreq_tc_en", (63),
				"0- OAM req uses service packet priority sch_net_tc; "
				"1- Uses special priority oamreq_net_tc"),
			INIT_DUMP_FIELD_INFO("oamreq_net_tc", (62, 60)),
			INIT_DUMP_FIELD_INFO("rnr_retry_th", (59, 56)),
			INIT_DUMP_FIELD_INFO("xr_domain", (55, 32)),
			INIT_DUMP_FIELD_INFO("srqwc_ba", (51, 0)),
		}
	},
	{0x40, {
			INIT_DUMP_FIELD_INFO("rss_lag_en", (63)),
			INIT_DUMP_FIELD_INFO_1("fwd", (62, 61),
				"0- Discard; 1- Normal forwarding; "
				"2- Reserved; 3- Send to CPU-specified destination"),
			INIT_DUMP_FIELD_INFO_1("dport", (60, 58),
				"Only valid when fwd==3: 0- eth; 1- host; "
				"2- ecpu; 3- icpu; Default is 0"),
			INIT_DUMP_FIELD_INFO("dport_id", (57, 47)),
			INIT_DUMP_FIELD_INFO_1("vlan_en", (46),
				"0- VLAN tag disabled; 1- VLAN tag enabled"),
			INIT_DUMP_FIELD_INFO("src_addr_index", (45, 36)),
			INIT_DUMP_FIELD_INFO("flow_table", (35, 16)),
			INIT_DUMP_FIELD_INFO("udp_sport", (15, 0)),
		}
	},
	{0x48, {
			INIT_DUMP_FIELD_INFO("destmac", (63, 16)),
			INIT_DUMP_FIELD_INFO("tclass", (15, 8)),
			INIT_DUMP_FIELD_INFO("hop_limit", (7, 0)),
		}
	},
	{0x50, {
			INIT_DUMP_FIELD_INFO("destip_high_64_bits", (63, 0)),
		}
	},
	{0x58, {
			INIT_DUMP_FIELD_INFO("destip_low_64_bits", (63, 0)),
		}
	},
	{0x60, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 52)), */
			INIT_DUMP_FIELD_INFO("unaq_ba", (51, 0)),
		}
	},
	{0x68, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 62)), */
			INIT_DUMP_FIELD_INFO("local_nofence_en", (61)),
			INIT_DUMP_FIELD_INFO("sq_ce_en", (60)),
			INIT_DUMP_FIELD_INFO("ackreq_th", (59, 52)),
			INIT_DUMP_FIELD_INFO("sq_pd_ba", (51, 0)),
		}
	},
	{0x70, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 56)), */
			INIT_DUMP_FIELD_INFO("ceaq_sq_th", (55, 52)),
			INIT_DUMP_FIELD_INFO("ceaq_rq_th", (51, 48)),
			INIT_DUMP_FIELD_INFO("sq_cqn", (47, 24)),
			INIT_DUMP_FIELD_INFO("rq_cqn", (23, 0)),
		}
	},
	{0x78, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 15)), */
			INIT_DUMP_FIELD_INFO("seq_num", (14, 0)),
		}
	},
	{0x80, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 44)), */
			INIT_DUMP_FIELD_INFO("qcn_last_recdb_time", (43, 20)),
			INIT_DUMP_FIELD_INFO("qcn_last_state_curr_rp", (19, 0)),
		}
	},
	{0x88, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63)), */
			INIT_DUMP_FIELD_INFO("qcn_sendpkt_targetwin", (62, 52)),
			INIT_DUMP_FIELD_INFO("qcn_last_db_sendtotal_blk", (51, 32)),
			INIT_DUMP_FIELD_INFO("qcn_mid_sendblk", (31, 20)),
			/* INIT_DUMP_FIELD_INFO("rsv", (19, 0)), */
		}
	},
	{0x90, {
			INIT_DUMP_FIELD_INFO("qcn_sendtime_moreth_cnt", (63, 60)),
			INIT_DUMP_FIELD_INFO("qcn_sendblk_moreth_cnt", (59, 56)),
			INIT_DUMP_FIELD_INFO("qcn_last_sendpkt_moreth_time", (55, 28)),
			INIT_DUMP_FIELD_INFO("qcn_remain_trans_bits", (27, 6)),
			/* INIT_DUMP_FIELD_INFO("rsv", (5, 0)), */
		}
	},
	{0x98, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 53)), */
			INIT_DUMP_FIELD_INFO("qcn_remain_trans_bits_sym", (52)),
			INIT_DUMP_FIELD_INFO("qcn_once_entered_fr_flag", (51)),
			INIT_DUMP_FIELD_INFO("qcn_first_recdb_flag", (50)),
			INIT_DUMP_FIELD_INFO("qcn_limit_rp", (49, 30)),
			INIT_DUMP_FIELD_INFO("qcn_target_rp", (29, 10)),
			INIT_DUMP_FIELD_INFO_1("qcn_main_status", (9, 8),
				"0- Initialization phase; "
				"1- Rate fast recovery phase; "
				"2- Rate proactive increase phase; "
				"3- Rate hyper proactive increase phase"),
			INIT_DUMP_FIELD_INFO("qcn_fast_reduc_rp_cnt", (7, 0)),
		}
	},
	{0xA0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 29)), */
			INIT_DUMP_FIELD_INFO("sq_next_wqe_cap", (28, 24)),
			INIT_DUMP_FIELD_INFO("next_fload_wqe_ci_phase", (23)),
			INIT_DUMP_FIELD_INFO("next_fload_wqe_ci", (22, 8)),
			INIT_DUMP_FIELD_INFO("ackreq_cnt", (7, 0)),
		}
	},
	{0xA8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 57)), */
			INIT_DUMP_FIELD_INFO("orq_sync_flag", (56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 50)), */
			INIT_DUMP_FIELD_INFO_1("txp_unaq_full_flag", (49),
				"1- TXP detects UNAQ full"),
			INIT_DUMP_FIELD_INFO_1("txp_irq_full_flag", (48),
				"1- TXP detects IRQ full"),
			/* INIT_DUMP_FIELD_INFO("rsv", (47, 45)), */
			INIT_DUMP_FIELD_INFO("raq_next_wqe_cap", (44, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv", (39, 32)), */
			INIT_DUMP_FIELD_INFO("sq_sendlen", (31, 0)),
		}
	},
	{0xB0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63)), */
			INIT_DUMP_FIELD_INFO("repeat_orq_en", (62)),
			INIT_DUMP_FIELD_INFO("repeat_orq_id", (61, 56)),
			INIT_DUMP_FIELD_INFO("tx_lsn", (55, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 8)), */
			INIT_DUMP_FIELD_INFO("sr_tx_r_id", (7, 0)),
		}
	},
	{0xB8, {
			INIT_DUMP_FIELD_INFO("sr_tx_rr_fpsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("rto_db_psn", (39, 16)),
			INIT_DUMP_FIELD_INFO("sr_tx_rq_id", (15, 0)),
		}
	},
	{0xC0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 13)), */
			INIT_DUMP_FIELD_INFO_1("txp_recheck_db_flag", (12),
				"1- TXP has triggered recheck_db"),
			INIT_DUMP_FIELD_INFO_1("txp_sq_db_flag", (11),
				"1- TXP has triggered sq_db"),
			INIT_DUMP_FIELD_INFO_1("rto_db_flag", (10),
				"1- TXP has triggered rto_db"),
			INIT_DUMP_FIELD_INFO_1("retry_load_flag", (9),
				"1- In retry load state"),
			INIT_DUMP_FIELD_INFO_1("rto_retry_flag", (8),
				"1- RNR or out-of-order retransmission between two TQ_RTO_DB"),
			INIT_DUMP_FIELD_INFO_1("txp_waitack_db_flag", (7),
				"1- TXP has triggered waitack_db to prevent re-entry"),
			INIT_DUMP_FIELD_INFO_1("txp_retry_err_flag", (6),
				"1- Exceeded retransmissions due to RTO or PSN error"),
			/* INIT_DUMP_FIELD_INFO("rsv", (5, 3)), */
			INIT_DUMP_FIELD_INFO("retry_cnt", (2, 0)),
		}
	},
	{0xC8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 32)), */
			INIT_DUMP_FIELD_INFO("wqe_ci_max", (31, 16)),
			INIT_DUMP_FIELD_INFO("txp_sqe_bid_ci_phase", (15)),
			INIT_DUMP_FIELD_INFO("txp_sqe_bid_ci", (14, 0)),
		}
	},
	{0xD0, {
			INIT_DUMP_FIELD_INFO("txmr_req_err", (63)),
			INIT_DUMP_FIELD_INFO("txmr_resp_err", (62)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (61, 56)),
			 * INIT_DUMP_FIELD_INFO("rsv", (55, 24)),
			 */
			INIT_DUMP_FIELD_INFO("txp_sq_retry_cnt_psn", (23, 0)),
		}
	},
	{0xD8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 28)), */
			INIT_DUMP_FIELD_INFO("txp_sendreq_db_cnt", (27, 12)),
			INIT_DUMP_FIELD_INFO("oamreq_next_psn", (11, 0)),
		}
	},
	{0xE0, {
			INIT_DUMP_FIELD_INFO("raq_sendlen", (63, 32)),
			INIT_DUMP_FIELD_INFO("txp_raq_readres_cur_psn", (31, 8)),
			/* INIT_DUMP_FIELD_INFO("rsv", (7, 6)), */
			INIT_DUMP_FIELD_INFO("sq_sendsge", (5, 0)),
		}
	},
	{0xE8, {
			INIT_DUMP_FIELD_INFO("sq_sendsgelen", (63, 32)),
			INIT_DUMP_FIELD_INFO("rsv", (31, 24)),
			INIT_DUMP_FIELD_INFO("raqp_record_wqe_psn", (23, 0)),
		}
	},
	{0xF0, {
			INIT_DUMP_FIELD_INFO("dup_read_raq_ci_phase", (63)),
			INIT_DUMP_FIELD_INFO("dup_read_raq_ci", (62, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 49)), */
			INIT_DUMP_FIELD_INFO_1("dup_read_flag", (48),
				"Duplicate read request flag: TXP resets to 0 when detected; "
				"RAQP sets to 1 when conditions are met"),
			/* INIT_DUMP_FIELD_INFO("rsv", (47, 40)),
			 * INIT_DUMP_FIELD_INFO("rsv*", (39, 33)),
			 */
			INIT_DUMP_FIELD_INFO_1("raq_full_flag", (32),
				"RAQP sets to 1 on first full RAQ queue detection"),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 25)), */
			INIT_DUMP_FIELD_INFO_1("last_ack_flag", (24),
				"Whether the last written RAQE had an ACK WQE"),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 17)), */
			INIT_DUMP_FIELD_INFO_1("raqp_raq_db_flag", (16),
				"Whether DSCH exist raqp_raq_db"),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 9)), */
			INIT_DUMP_FIELD_INFO_1("txp_raq_db_flag", (8),
				"Whether DSCH exist txp_raq_db"),
			INIT_DUMP_FIELD_INFO("raqp_raq_pi_phase", (7)),
			INIT_DUMP_FIELD_INFO("raqp_raq_pi", (6, 0)),
		}
	},
	{0xF8, {
			INIT_DUMP_FIELD_INFO("txp_raq_ci_phase", (63)),
			INIT_DUMP_FIELD_INFO("txp_raq_ci", (62, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 52)), */
			INIT_DUMP_FIELD_INFO("raq_ba", (51, 0)),
		}
	},
	{0x100, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 48)), */
			INIT_DUMP_FIELD_INFO("rxp_rqe_bld_ci_phase", (47)),
			INIT_DUMP_FIELD_INFO("rxp_srq_bid_ci_phase", (47)),
			INIT_DUMP_FIELD_INFO("rxp_rqe_bld_ci", (46, 32)),
			INIT_DUMP_FIELD_INFO("rxp_srq_bid_ci", (46, 32)),
			INIT_DUMP_FIELD_INFO("rxp_req_pre_opcode", (31, 24)),
			INIT_DUMP_FIELD_INFO("rnr_flag", (23)),
			INIT_DUMP_FIELD_INFO("rnr_time", (22, 0)),
		}
	},
	{0x108, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63 56)), */
			INIT_DUMP_FIELD_INFO("epsn", (55, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 30)), */
			INIT_DUMP_FIELD_INFO("sr_ack_wait", (29)),
			INIT_DUMP_FIELD_INFO("req_seq_err", (28)),
			INIT_DUMP_FIELD_INFO("rxp_srq_cnt", (27, 24)),
			INIT_DUMP_FIELD_INFO("rxp_raq_msn", (23, 0)),
		}
	},
	{0x110, {
			INIT_DUMP_FIELD_INFO("rxp_w_va", (63, 0)),
			INIT_DUMP_FIELD_INFO("epsn_bitmap_127_64", (63, 0)),
		}
	},
	{0x118, {
			INIT_DUMP_FIELD_INFO("rxp_w_rkey", (63, 32)),
			INIT_DUMP_FIELD_INFO("rxp_w_dma_len", (31, 0)),
			INIT_DUMP_FIELD_INFO("epsn_bitmap_63_0", (63, 0)),
		}
	},
	{0x120, {
			INIT_DUMP_FIELD_INFO("cc_sendack_mid_blk_cnt", (63, 52)),
			/* INIT_DUMP_FIELD_INFO("rsv", (51, 48)), */
			INIT_DUMP_FIELD_INFO("cc_high_priorrtt_midcnt", (47, 40)),
			INIT_DUMP_FIELD_INFO("cc_rttmid_oamack_cnt", (39, 32)),
			INIT_DUMP_FIELD_INFO("cc_rttmin", (31, 16)),
			INIT_DUMP_FIELD_INFO("cc_oamack_next_psn", (15, 0)),
		}
	},
	{0x128, {
			INIT_DUMP_FIELD_INFO_1("qcn_rececn_flag", (63),
				"1- ECN-flagged packet receipt by CC module, cc_rececn_flag is 0"),
			INIT_DUMP_FIELD_INFO_1("cc_more_rttminth_flag", (62),
				"1- Calculated RTT is below QPC's RTTmin upper threshold"),
			INIT_DUMP_FIELD_INFO_1("cc_less_rttminth_flag", (61),
				"1- Calculated RTT is below QPC's RTTmin lower threshold"),
			INIT_DUMP_FIELD_INFO_1("cc_recack_rttflag", (60),
				"1- RXP_CC receives an RTT probe response; "
				"0- On OAMACK receipt with a value of 1, set WINM_busy to 0"),
			/* INIT_DUMP_FIELD_INFO("rsv", (59, 52)), */
			INIT_DUMP_FIELD_INFO("cc_recreq_blk_cnt", (51, 32)),
			INIT_DUMP_FIELD_INFO("cc_recreq_mid_blk_cnt", (31, 12)),
			INIT_DUMP_FIELD_INFO("cc_recreq_epsn", (11, 0)),
		}
	},
	{0x130, {
			INIT_DUMP_FIELD_INFO("cc_time_lastta", (63, 32)),
			INIT_DUMP_FIELD_INFO("ccqcn_reqcarry_sendqcn_time", (31, 0)),
		}
	},
	{0x138, {
			INIT_DUMP_FIELD_INFO("cc_recreq_sendtx_blk_cnt", (63, 44)),
			INIT_DUMP_FIELD_INFO_1("cc_winm_busy", (43),
				"1- During the TargetWin measurement period"),
			INIT_DUMP_FIELD_INFO_1("cc_rcvack_flag", (42),
				"1- Begin with 0, after receiving oamack become to 1 "),
			/* INIT_DUMP_FIELD_INFO("rsv", (41, 36)), */
			INIT_DUMP_FIELD_INFO("cc_recack_lastwinm_blk_cnt", (35, 16)),
			INIT_DUMP_FIELD_INFO("cc_recack_epsn", (15, 0)),
		}
	},
	{0x140, {
			INIT_DUMP_FIELD_INFO("ocq_bitmap", (63, 0)),
		}
	},
	{0x148, {
			INIT_DUMP_FIELD_INFO("rxmr_req_err", (63)),
			INIT_DUMP_FIELD_INFO("rxmr_resp_err", (62)),
			/* INIT_DUMP_FIELD_INFO("rsv", (61, 51)), */
			INIT_DUMP_FIELD_INFO("srq_srqe_vld", (50)),
			INIT_DUMP_FIELD_INFO("srq_rqwqe_ts", (49, 46)),
			INIT_DUMP_FIELD_INFO("srq_pm", (45, 44)),
			INIT_DUMP_FIELD_INFO("srq_cqn", (43, 20)),
			INIT_DUMP_FIELD_INFO("srq_sub_id", (19, 12)),
			INIT_DUMP_FIELD_INFO("ocq_ci_phase", (18)),
			INIT_DUMP_FIELD_INFO("ocq_ci", (17, 12)),
			INIT_DUMP_FIELD_INFO("srq_pd", (11, 0)),
		}
	},
	{0x150, {
			INIT_DUMP_FIELD_INFO("srq_pd", (63, 52)),
			INIT_DUMP_FIELD_INFO("rxp_rq_fpga", (51, 0)),
			INIT_DUMP_FIELD_INFO("rxp_srq_ba", (51, 0)),
		}
	},
	{0x158, {
			INIT_DUMP_FIELD_INFO("pre_srqn", (63, 40)),
			INIT_DUMP_FIELD_INFO("glb_srqn", (39, 16)),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 0)), */
		}
	},
	{0x160, {
			INIT_DUMP_FIELD_INFO("una_bitmap", (63, 0)),
		}
	},
	/**
	 * {0x168, {
	 *		INIT_DUMP_FIELD_INFO("rsv", (63, 0)),
	 *	}
	 *},
	 */
	{0x170, {
			INIT_DUMP_FIELD_INFO("rxp_read_length", (63, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 29)), */
			INIT_DUMP_FIELD_INFO("resp_psn_err", (28)),
			INIT_DUMP_FIELD_INFO("rnr_retry_num", (27, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 0)), */
		}
	},
	{0x178, {
			INIT_DUMP_FIELD_INFO("rx_resp_pre_opcode", (63, 59)),
			/*INIT_DUMP_FIELD_INFO("rsv", (58, 48)),*/
			INIT_DUMP_FIELD_INFO("rxp_unaq_msn", (47, 24)),
			INIT_DUMP_FIELD_INFO("una_psn_pre", (23, 0)),
		}
	},
	{0x180, {
			INIT_DUMP_FIELD_INFO("una_psn", (63, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv", (39, 34)), */
			INIT_DUMP_FIELD_INFO_1("rxp_irqe_cnt_sta", (33, 32),
				"0- Normal prediction and reception state; "
				"1- Prediction rapid rollback state; "
				"2- Flush erroneous prediction"),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 30)), */
			INIT_DUMP_FIELD_INFO("rxp_irq_ci_phase", (29)),
			INIT_DUMP_FIELD_INFO("rxp_irqe_ci", (28, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 22)), */
			INIT_DUMP_FIELD_INFO("txp_irq_pi_phase", (21)),
			INIT_DUMP_FIELD_INFO("txp_irqe_pi", (20, 16)),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 14)), */
			INIT_DUMP_FIELD_INFO("rxp_irq_cnt_ci_phase", (13)),
			INIT_DUMP_FIELD_INFO("rxp_irqe_cnt_ci", (12, 8)),
			/* INIT_DUMP_FIELD_INFO("rsv", (7, 6)), */
			INIT_DUMP_FIELD_INFO("rxp_irqe_cnt_pi_phase", (5)),
			INIT_DUMP_FIELD_INFO("rxp_irqe_cnt_pi", (4, 0)),
		}
	},
	{0x188, {
			INIT_DUMP_FIELD_INFO("rxp_send_msg_len_31_8", (63, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv", (39, 38)), */
			INIT_DUMP_FIELD_INFO("txp_orqe_ci_phase", (38)),
			INIT_DUMP_FIELD_INFO("txp_orqe_ci", (37, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 30)), */
			INIT_DUMP_FIELD_INFO("rxp_orqe_pi_phase", (29)),
			INIT_DUMP_FIELD_INFO("rxp_orqe_pi", (28, 24)),
			INIT_DUMP_FIELD_INFO("txp_recv_rtodb_cnt", (23, 20)),
			INIT_DUMP_FIELD_INFO("txp_send_rtodb_cnt", (19, 16)),
			INIT_DUMP_FIELD_INFO("txp_recv_raqdb_cnt", (15, 12)),
			INIT_DUMP_FIELD_INFO("txp_send_raqdb_cnt", (11, 8)),
			INIT_DUMP_FIELD_INFO("txp_recv_sqdb_cnt", (7, 4)),
			INIT_DUMP_FIELD_INFO("txp_send_sqdb_cnt", (3, 0)),
		}
	},
	{0x190, {
			INIT_DUMP_FIELD_INFO("psn_max", (63, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (39, 36)), */
			INIT_DUMP_FIELD_INFO("cc_rttm_psnts", (35, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (23, 20)), */
			INIT_DUMP_FIELD_INFO("txp_sendpld_blk_cnt", (19, 0)),
		}
	},
	{0x198, {
			INIT_DUMP_FIELD_INFO("rxp_send_msg_len_7_0", (63, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (55, 49)), */
			INIT_DUMP_FIELD_INFO_1("rxp_qcn_reccnp_flag", (48),
				"Whether RXP has received CNP packets"),
			/* INIT_DUMP_FIELD_INFO("rsv*", (47, 42)),*/
			INIT_DUMP_FIELD_INFO_1("cc_high_prior_oam", (41),
				"0- OAM req packet uses the service packet priority sch_net_tc; "
				"1- OAM ACK packet uses special priority oamreq_net_tc"),
			INIT_DUMP_FIELD_INFO_1("cc_rttm_busy", (40),
				"Whether to initiate RTT measurement"),
			INIT_DUMP_FIELD_INFO("cc_recack_rectx_blk_cnt", (39, 20)),
			INIT_DUMP_FIELD_INFO("cc_targetWin", (19, 0)),
		}
	},
	{0x1A0, {
			INIT_DUMP_FIELD_INFO("msn_eop_bitmap", (63, 0)),
			INIT_DUMP_FIELD_INFO("rxp_rq_nxt_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("rxp_rq_nxt_pdpa", (51, 0)),
		}
	},
	{0x1A8, {
			INIT_DUMP_FIELD_INFO("read_bitmap", (63, 0)),
			INIT_DUMP_FIELD_INFO("rxp_rq_cur_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("rxp_rq_cur_pdpa", (51, 0)),
		}
	},
	{0x1B0, {
			INIT_DUMP_FIELD_INFO("ext_msnbp_idx_vld", (63)),
			INIT_DUMP_FIELD_INFO("ext_msnbp_idx", (62, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 53)), */
			INIT_DUMP_FIELD_INFO("txp_sq_nxt_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("txp_sq_nxt_pdpa", (51, 0)),
		}
	},
	{0x1B8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 62)), */
			INIT_DUMP_FIELD_INFO("ceaq_load_nxt_cnt", (61, 59)),
			INIT_DUMP_FIELD_INFO("ceaq_load_cur_cnt", (58, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 53)), */
			INIT_DUMP_FIELD_INFO("txp_sq_cur_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("txp_sq_cur_pdpa", (51, 0)),
		}
	},
	{0x1C0, {
			INIT_DUMP_FIELD_INFO("rx_lsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("retry_psn", (39, 16)),
			INIT_DUMP_FIELD_INFO("unaqe_ci_phase", (15)),
			INIT_DUMP_FIELD_INFO("unaqe_ci", (14, 8)),
			INIT_DUMP_FIELD_INFO("unaqe_pi_phase", (7)),
			INIT_DUMP_FIELD_INFO("unaqe_pi", (6, 0)),
		}
	},
	{0x1C8, {
			INIT_DUMP_FIELD_INFO("retry_fpsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("sq_cqe_wqebid_phase", (39)),
			INIT_DUMP_FIELD_INFO("sq_cqe_wqebid", (38, 24)),
			INIT_DUMP_FIELD_INFO("srp_retry_rq_id", (23, 8)),
			/* INIT_DUMP_FIELD_INFO("rsv", (7, 4)), */
			INIT_DUMP_FIELD_INFO_1("retry_st", (3, 0),
				"0- Normal; 1- psn_err; 2- rnr_err"),
		}
	},
	{0x1D0, {
			INIT_DUMP_FIELD_INFO("txp_sq_cur_psn", (63, 40)),
			INIT_DUMP_FIELD_INFO("ceaq_psn_dvalue", (39, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 28)), */
			INIT_DUMP_FIELD_INFO_1("e2e_fc_limit_flag", (27), "1- e2e fc limit"),
			INIT_DUMP_FIELD_INFO_1("psn_overflow_flag", (26), "1- psn overflow"),
			INIT_DUMP_FIELD_INFO_1("unaq_full_flag", (25), "1- UNAQ is full"),
			INIT_DUMP_FIELD_INFO_1("irq_full_flag", (24), "1- IRQ is full"),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 17)), */
			INIT_DUMP_FIELD_INFO_1("waitack_db_flag", (16),
				"1- waitack_db has been triggered; "
				"TXP writes 0 upon receiving waitack_db; "
				"CEAQ writes 1 when triggering waitack_db."),
			INIT_DUMP_FIELD_INFO("sqe_dif_err_cnt", (15, 14)),
			INIT_DUMP_FIELD_INFO("txp_load_nxt_cnt", (13, 11)),
			INIT_DUMP_FIELD_INFO("txp_load_cur_cnt", (10, 8)),
			INIT_DUMP_FIELD_INFO("srp_retry_r_id", (7, 0)),
		}
	},
	{0x1D8, {
			INIT_DUMP_FIELD_INFO("tx_sq_err_bid_phase", (63)),
			INIT_DUMP_FIELD_INFO("tx_sq_err_bid", (62, 48)),
			INIT_DUMP_FIELD_INFO("rq_cqe_wqebid_phase", (47)),
			INIT_DUMP_FIELD_INFO("rq_cqe_wqebid", (46, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31)), */
			INIT_DUMP_FIELD_INFO("ceaq_srq_cnt", (30, 26)),
			INIT_DUMP_FIELD_INFO_1("ae_flag", (25),
				"1- QP reported an AE once (excluding RAQ_full and RAQ_flush)"),
			INIT_DUMP_FIELD_INFO("e2e_fc_en", (24)),
			INIT_DUMP_FIELD_INFO("ssn", (23, 0)),
		}
	},
	/* {0x1E0, {
	 *		INIT_DUMP_FIELD_INFO("rsv", (63, 0)),
	 *	}
	 * },
	 */
	{0x1E8, {
			INIT_DUMP_FIELD_INFO("hw_seq_num", (63, 49)),
			INIT_DUMP_FIELD_INFO("hw_drop_db_sq_ci_phase", (47)),
			INIT_DUMP_FIELD_INFO("hw_drop_db_sq_ci", (46, 32)),
			INIT_DUMP_FIELD_INFO("hw_rq_ci_phase", (31)),
			INIT_DUMP_FIELD_INFO("hw_rq_ci", (30, 16)),
			INIT_DUMP_FIELD_INFO("hw_sq_ci_phase", (15)),
			INIT_DUMP_FIELD_INFO("hw_sq_ci", (14, 0)),
		}
	},
	{0x1F0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 55)), */
			INIT_DUMP_FIELD_INFO("sw_qpc_ba", (54, 0))
		}
	},
	{0x1F8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 36)), */
			INIT_DUMP_FIELD_INFO("sw_seq_num", (35, 32)),
			INIT_DUMP_FIELD_INFO("sw_rq_pi_phase", (31)),
			INIT_DUMP_FIELD_INFO("sw_rq_pi", (30, 16)),
			INIT_DUMP_FIELD_INFO("sw_sq_pi_phase", (15)),
			INIT_DUMP_FIELD_INFO("sw_sq_pi", (14, 0)),
		}
	},
};

static const struct nbl_cache_dump nbl_qpc_dump_table_v4[] = {
	{0x00, {
			INIT_DUMP_FIELD_INFO("spray", (63)),
			INIT_DUMP_FIELD_INFO("mig", (62)),
			INIT_DUMP_FIELD_INFO("tver", (61, 60)),
			INIT_DUMP_FIELD_INFO("stat_id", (59, 52)),
			INIT_DUMP_FIELD_INFO_1("host_id", (51, 49),
				"0- rsv; 1- host; 2- ecpu; 3- icpu"),
			INIT_DUMP_FIELD_INFO("vfid", (48, 40)),
			INIT_DUMP_FIELD_INFO("qpn", (39, 16)),
			INIT_DUMP_FIELD_INFO("p_key", (15, 0)),
		}
	},
	{0x08, {
			INIT_DUMP_FIELD_INFO("service_type", (63, 60)),
			INIT_DUMP_FIELD_INFO("qp_state", (59, 56)),
			INIT_DUMP_FIELD_INFO("pmtu", (55, 52)),
			INIT_DUMP_FIELD_INFO("iorq_ba", (51, 0)),
		}
	},
	{0x10, {
			INIT_DUMP_FIELD_INFO_1("qp1_mode", (63), "0- QP0; 1- QP1"),
			INIT_DUMP_FIELD_INFO("sch_net_tc", (62, 60)),
			INIT_DUMP_FIELD_INFO("pd_index", (59, 36)),
			INIT_DUMP_FIELD_INFO("read_optimize_en", (35)),
			INIT_DUMP_FIELD_INFO("sport_id", (34, 24)),
			INIT_DUMP_FIELD_INFO_1("credit_en", (23),
				"AETH credit enable: 0- Disabled; 1- Enabled"),
			INIT_DUMP_FIELD_INFO_1("cc_pkt_num_en", (22),
				"0- pkt_blk_cnt is rounded down; 1- pkt_blk_cnt is rounded up"),
			INIT_DUMP_FIELD_INFO("wqe_prefetch_en", (21)),
			INIT_DUMP_FIELD_INFO_1("tunnel_en", (20),
				"0- The packet will not go through the tunnel; "
				"1- The packet will go through the tunnel."),
			INIT_DUMP_FIELD_INFO("rq_size", (19, 16)),
			INIT_DUMP_FIELD_INFO("rqwqe_ts", (15, 12)),
			INIT_DUMP_FIELD_INFO_1("qp_type", (11, 10),
				"0- Normal QP; 1- ini_qp; 2- tgt_qp"),
			INIT_DUMP_FIELD_INFO_1("sq_pm", (9, 8),
				"0- Level 0 addressing; 1- Level 1 addressing"),
			INIT_DUMP_FIELD_INFO_1("rq_pm", (7, 6),
				"0- Level 0 addressing; 1- Level 1 addressing"),
			INIT_DUMP_FIELD_INFO_1("atomic_en", (5),
				"0- Does not support Atomic operations; "
				"1- Supports Atomic operations"),
			INIT_DUMP_FIELD_INFO("local_rnr_timer_value", (4, 0)),
		}
	},
	{0x18, {
			INIT_DUMP_FIELD_INFO("swrqpi_th", (63, 61)),
			INIT_DUMP_FIELD_INFO_1("cc_mode", (60, 58),
				"0- CC Disabled; 1- NBL_CC; 2- DCQCN; 3- NBL_SCC"),
			INIT_DUMP_FIELD_INFO("hw_rqci_th", (57, 55)),
			INIT_DUMP_FIELD_INFO("qpc_shadowarea_ba", (54, 0)),
		}
	},
	{0x20, {
			INIT_DUMP_FIELD_INFO("vlan_tag", (63, 48)),
			INIT_DUMP_FIELD_INFO("ipv4", (47)),
			INIT_DUMP_FIELD_INFO("srack_timer_value", (46, 42)),
			INIT_DUMP_FIELD_INFO("sr_ext_bmp_en", (41)),
			INIT_DUMP_FIELD_INFO_1("atomic_no_fence", (40),
				"0- Atomic operations will fence; "
				"1- Atomic operations won't fence"),
			INIT_DUMP_FIELD_INFO("rq_pd_ba/srqn", (39, 0)),
		}
	},
	{0x28, {
			INIT_DUMP_FIELD_INFO("rq_pd_ba/srqn", (63, 52)),
			INIT_DUMP_FIELD_INFO("cc_targetwin_min", (51, 32)),
			INIT_DUMP_FIELD_INFO("ud_qkey", (31, 0)),
		}
	},
	{0x30, {
			INIT_DUMP_FIELD_INFO("sq_size", (63, 60)),
			INIT_DUMP_FIELD_INFO("dest_qpn", (59, 36)),
			INIT_DUMP_FIELD_INFO("tx_retry_th", (35, 33)),
			INIT_DUMP_FIELD_INFO("srp_en", (32)),
			INIT_DUMP_FIELD_INFO("srq_en", (31)),
			INIT_DUMP_FIELD_INFO("irq_size", (30, 28)),
			/* INIT_DUMP_FIELD_INFO("rsv", (27, 20)), */
			INIT_DUMP_FIELD_INFO("rto_timer_value", (19, 15)),
			INIT_DUMP_FIELD_INFO("txmr_frmr_en", (14)),
			INIT_DUMP_FIELD_INFO("cc_rttminth_add_mult", (13, 12)),
			INIT_DUMP_FIELD_INFO("read_en", (11)),
			INIT_DUMP_FIELD_INFO("write_en", (10)),
			/* INIT_DUMP_FIELD_INFO("rsv", (9, 8)), */
			INIT_DUMP_FIELD_INFO("src_addr_seq_num", (7, 4)),
			INIT_DUMP_FIELD_INFO("oamack_tc_en", (3)),
			INIT_DUMP_FIELD_INFO("oamack_net_tc", (2, 0)),
		}
	},
	{0x38, {
			INIT_DUMP_FIELD_INFO_1("oamreq_tc_en", (63),
				"0- OAM req uses service packet priority sch_net_tc; "
				"1- Uses special priority oamreq_net_tc"),
			INIT_DUMP_FIELD_INFO("oamreq_net_tc", (62, 60)),
			INIT_DUMP_FIELD_INFO("rnr_retry_th", (59, 56)),
			INIT_DUMP_FIELD_INFO("xr_domain", (55, 32)),
			INIT_DUMP_FIELD_INFO("srqwc_ba", (51, 0)),
		}
	},
	{0x40, {
			INIT_DUMP_FIELD_INFO("rss_lag_en", (63)),
			INIT_DUMP_FIELD_INFO_1("fwd", (62, 61),
				"0- Discard; 1- Normal forwarding; "
				"2- Reserved; 3- Send to CPU-specified destination"),
			INIT_DUMP_FIELD_INFO_1("dport", (60, 58),
				"Only valid when fwd==3: 0- eth; 1- host; "
				"2- ecpu; 3- icpu; Default is 0"),
			INIT_DUMP_FIELD_INFO("dport_id", (57, 47)),
			INIT_DUMP_FIELD_INFO_1("vlan_en", (46),
				"0- VLAN tag disabled; 1- VLAN tag enabled"),
			INIT_DUMP_FIELD_INFO("src_addr_index", (45, 36)),
			INIT_DUMP_FIELD_INFO("flow_table", (35, 16)),
			INIT_DUMP_FIELD_INFO("udp_sport", (15, 0)),
		}
	},
	{0x48, {
			INIT_DUMP_FIELD_INFO("destmac", (63, 16)),
			INIT_DUMP_FIELD_INFO("tclass", (15, 8)),
			INIT_DUMP_FIELD_INFO("hop_limit", (7, 0)),
		}
	},
	{0x50, {
			INIT_DUMP_FIELD_INFO("destip_high_64_bits", (63, 0)),
		}
	},
	{0x58, {
			INIT_DUMP_FIELD_INFO("destip_low_64_bits", (63, 0)),
		}
	},
	{0x60, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 52)), */
			INIT_DUMP_FIELD_INFO("unaq_ba", (51, 0)),
		}
	},
	{0x68, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 62)), */
			INIT_DUMP_FIELD_INFO("local_nofence_en", (61)),
			INIT_DUMP_FIELD_INFO("sq_ce_en", (60)),
			INIT_DUMP_FIELD_INFO("ackreq_th", (59, 52)),
			INIT_DUMP_FIELD_INFO("sq_pd_ba", (51, 0)),
		}
	},
	{0x70, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 56)), */
			INIT_DUMP_FIELD_INFO("ceaq_sq_th", (55, 52)),
			INIT_DUMP_FIELD_INFO("ceaq_rq_th", (51, 48)),
			INIT_DUMP_FIELD_INFO("sq_cqn", (47, 24)),
			INIT_DUMP_FIELD_INFO("rq_cqn", (23, 0)),
		}
	},
	{0x78, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 15)), */
			INIT_DUMP_FIELD_INFO("seq_num", (14, 0)),
		}
	},
	{0x80, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 56)), */
			INIT_DUMP_FIELD_INFO("qcn_last_recdb_time", (55, 31)),
			/* INIT_DUMP_FIELD_INFO("rsv", (30, 25)), */
			INIT_DUMP_FIELD_INFO("qcn_last_update_a_time", (24, 0)),
		}
	},
	{0x88, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 57)), */
			INIT_DUMP_FIELD_INFO("qcn_sendpkt_targetwin", (56, 46)),
			INIT_DUMP_FIELD_INFO("qcn_last_db_sendtotal_blk", (45, 25)),
			INIT_DUMP_FIELD_INFO("qcn_mid_sendblk", (24, 10)),
			INIT_DUMP_FIELD_INFO("qcn_alpha", (9, 0)),
		}
	},
	{0x90, {
			INIT_DUMP_FIELD_INFO("qcn_sendtime_moreth_cnt", (63, 60)),
			INIT_DUMP_FIELD_INFO("qcn_sendblk_moreth_cnt", (59, 56)),
			INIT_DUMP_FIELD_INFO("qcn_last_sendpkt_moreth_time", (55, 31)),
			INIT_DUMP_FIELD_INFO("qcn_remain_trans_bits", (30, 9)),
			/* INIT_DUMP_FIELD_INFO("rsv", (8, 0)), */
		}
	},
	{0x98, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 45)), */
			INIT_DUMP_FIELD_INFO("qcn_remain_trans_bits_sym", (44)),
			INIT_DUMP_FIELD_INFO("qcn_once_entered_fr_flag", (43)),
			INIT_DUMP_FIELD_INFO("qcn_first_recdb_flag", (42)),
			INIT_DUMP_FIELD_INFO("qcn_limit_rp", (41, 22)),
			INIT_DUMP_FIELD_INFO("qcn_target_rp", (21, 2)),
			INIT_DUMP_FIELD_INFO_1("qcn_main_status", (1, 0),
				"0- Initialization phase; "
				"1- Rate fast recovery phase; "
				"2- Rate proactive increase phase; "
				"3- Rate hyper proactive increase phase"),
		}
	},
	{0xA0, {
			INIT_DUMP_FIELD_INFO("frmr_key_record", (63, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 29)), */
			INIT_DUMP_FIELD_INFO("sq_next_wqe_cap", (28, 24)),
			INIT_DUMP_FIELD_INFO("next_fload_wqe_ci_phase", (23)),
			INIT_DUMP_FIELD_INFO("next_fload_wqe_ci", (22, 8)),
			INIT_DUMP_FIELD_INFO("ackreq_cnt", (7, 0)),
		}
	},
	{0xA8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 57)), */
			INIT_DUMP_FIELD_INFO("orq_sync_flag", (56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 50)), */
			INIT_DUMP_FIELD_INFO_1("txp_unaq_full_flag", (49),
				"1- TXP detects UNAQ full"),
			INIT_DUMP_FIELD_INFO_1("txp_irq_full_flag", (48),
				"1- TXP detects IRQ full"),
			/* INIT_DUMP_FIELD_INFO("rsv", (47, 45)), */
			INIT_DUMP_FIELD_INFO("raq_next_wqe_cap", (44, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv", (39, 32)), */
			INIT_DUMP_FIELD_INFO("sq_sendlen", (31, 0)),
		}
	},
	{0xB0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 56)), */
			INIT_DUMP_FIELD_INFO("tx_lsn", (55, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 8)), */
			INIT_DUMP_FIELD_INFO("sr_tx_r_id", (7, 0)),
		}
	},
	{0xB8, {
			INIT_DUMP_FIELD_INFO("sr_tx_rr_fpsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("rto_db_psn", (39, 16)),
			INIT_DUMP_FIELD_INFO("sr_tx_rq_id", (15, 0)),
		}
	},
	{0xC0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 56)), */
			INIT_DUMP_FIELD_INFO("tlp_timer_value", (55, 51)),
			INIT_DUMP_FIELD_INFO("tlp_retry_th", (50, 48)),
			/* INIT_DUMP_FIELD_INFO("rsv", (47, 43)), */
			INIT_DUMP_FIELD_INFO("tlp_retry_cnt", (42, 40)),
			INIT_DUMP_FIELD_INFO("tlp_db_psn", (39, 16)),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 14)), */
			INIT_DUMP_FIELD_INFO("tlp_retry_flag", (13)),
			INIT_DUMP_FIELD_INFO_1("txp_recheck_db_flag", (12),
				"1- TXP has triggered recheck_db"),
			INIT_DUMP_FIELD_INFO_1("txp_sq_db_flag", (11),
				"1- TXP has triggered sq_db"),
			INIT_DUMP_FIELD_INFO_1("rto_db_flag", (10),
				"1- TXP has triggered rto_db"),
			INIT_DUMP_FIELD_INFO_1("retry_load_flag", (9),
				"1- In retry load state"),
			INIT_DUMP_FIELD_INFO_1("rto_retry_flag", (8),
				"1- RNR or out-of-order retransmission between two TQ_RTO_DB"),
			INIT_DUMP_FIELD_INFO_1("txp_waitack_db_flag", (7),
				"1- TXP has triggered waitack_db to prevent re-entry"),
			INIT_DUMP_FIELD_INFO_1("txp_retry_err_flag", (6),
				"1- Exceeded retransmissions due to RTO or PSN error"),
			/* INIT_DUMP_FIELD_INFO("rsv", (5, 3)), */
			INIT_DUMP_FIELD_INFO("retry_cnt", (2, 0)),
		}
	},
	{0xC8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 32)), */
			INIT_DUMP_FIELD_INFO("wqe_ci_max", (31, 16)),
			INIT_DUMP_FIELD_INFO("txp_sqe_bid_ci_phase", (15)),
			INIT_DUMP_FIELD_INFO("txp_sqe_bid_ci", (14, 0)),
		}
	},
	{0xD0, {
			INIT_DUMP_FIELD_INFO("txmr_req_err", (63)),
			INIT_DUMP_FIELD_INFO("txmr_resp_err", (62)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (61, 56)),
			 * INIT_DUMP_FIELD_INFO("rsv", (55, 24)),
			 */
			INIT_DUMP_FIELD_INFO("txp_sq_retry_cnt_psn", (23, 0)),
		}
	},
	{0xD8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 48)), */
			INIT_DUMP_FIELD_INFO("txp_sendtx_blk_cnt", (47, 28)),
			INIT_DUMP_FIELD_INFO("txp_sendreq_db_cnt", (27, 12)),
			INIT_DUMP_FIELD_INFO("oamreq_next_psn", (11, 0)),
		}
	},
	{0xE0, {
			INIT_DUMP_FIELD_INFO("raq_sendlen", (63, 32)),
			INIT_DUMP_FIELD_INFO("txp_raq_readres_cur_psn", (31, 8)),
			/* INIT_DUMP_FIELD_INFO("rsv", (7, 6)), */
			INIT_DUMP_FIELD_INFO("sq_sendsge", (5, 0)),
		}
	},
	{0xE8, {
			INIT_DUMP_FIELD_INFO("sq_sendsgelen", (63, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 24)), */
			INIT_DUMP_FIELD_INFO("raqp_record_wqe_psn", (23, 0)),
		}
	},
	{0xF0, {
			INIT_DUMP_FIELD_INFO("dup_read_raq_ci_phase", (63)),
			INIT_DUMP_FIELD_INFO("dup_read_raq_ci", (62, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 49)), */
			INIT_DUMP_FIELD_INFO_1("dup_read_flag", (48),
				"Duplicate read request flag: TXP resets to 0 when detected; "
				"RAQP sets to 1 when conditions are met"),
			/* INIT_DUMP_FIELD_INFO("rsv", (47, 40)),
			 * INIT_DUMP_FIELD_INFO("rsv*", (39, 33)),
			 */
			INIT_DUMP_FIELD_INFO_1("raq_full_flag", (32),
				"RAQP sets to 1 on first full RAQ queue detection"),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 25)), */
			INIT_DUMP_FIELD_INFO_1("last_ack_flag", (24),
				"Whether the last written RAQE had an ACK WQE"),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 17)), */
			INIT_DUMP_FIELD_INFO_1("raqp_raq_db_flag", (16),
				"Whether DSCH exist raqp_raq_db"),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 9)), */
			INIT_DUMP_FIELD_INFO_1("txp_raq_db_flag", (8),
				"Whether DSCH exist txp_raq_db"),
			INIT_DUMP_FIELD_INFO("raqp_raq_pi_phase", (7)),
			INIT_DUMP_FIELD_INFO("raqp_raq_pi", (6, 0)),
		}
	},
	{0xF8, {
			INIT_DUMP_FIELD_INFO("txp_raq_ci_phase", (63)),
			INIT_DUMP_FIELD_INFO("txp_raq_ci", (62, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 52)), */
			INIT_DUMP_FIELD_INFO("raq_ba", (51, 0)),
		}
	},
	{0x100, {
			INIT_DUMP_FIELD_INFO("rxp_send_msg_len", (63, 32)),
			INIT_DUMP_FIELD_INFO("rxp_rqe_bld_ci_phase", (31)),
			INIT_DUMP_FIELD_INFO("rxp_srq_bid_ci_phase", (31)),
			INIT_DUMP_FIELD_INFO("rxp_rqe_bld_ci", (30, 16)),
			INIT_DUMP_FIELD_INFO("rxp_srq_bid_ci", (30, 16)),
			INIT_DUMP_FIELD_INFO("rnr_flag", (15)),
			INIT_DUMP_FIELD_INFO("rnr_time", (14, 0)),
		}
	},
	{0x108, {
			INIT_DUMP_FIELD_INFO("rnr_time", (63, 56)),
			INIT_DUMP_FIELD_INFO("epsn", (55, 32)),
			INIT_DUMP_FIELD_INFO("sr_epsn", (55, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 30)), */
			INIT_DUMP_FIELD_INFO("rqe_load_flag", (29)),
			INIT_DUMP_FIELD_INFO("req_seq_err", (28)),
			INIT_DUMP_FIELD_INFO("rxp_srq_cnt", (27, 24)),
			INIT_DUMP_FIELD_INFO("rxp_raq_msn", (23, 0)),
		}
	},
	{0x110, {
			INIT_DUMP_FIELD_INFO("rxp_w_va", (63, 0)),
			INIT_DUMP_FIELD_INFO("ext_epsnbm_idx_vld", (63)),
			INIT_DUMP_FIELD_INFO("ext_epsnbm_idx", (62, 0)),
		}
	},
	{0x118, {
			INIT_DUMP_FIELD_INFO("rxp_w_rkey", (63, 32)),
			INIT_DUMP_FIELD_INFO("rxp_w_dma_len", (31, 0)),
			INIT_DUMP_FIELD_INFO("epsn_bitmap_63_0", (63, 0)),
		}
	},
	{0x120, {
			INIT_DUMP_FIELD_INFO_1("qcn_rececn_flag", (63),
				"1- ECN-flagged packet receipt by CC module, cc_rececn_flag is 0"),
			INIT_DUMP_FIELD_INFO_1("cc_recack_rttflag", (62),
				"1- RXP_CC receives an RTT probe response; "
				"0- On OAMACK receipt with a value of 1, set WINM_busy to 0"),
			INIT_DUMP_FIELD_INFO("cc_rtt_measure", (61, 47)),
			INIT_DUMP_FIELD_INFO("cc_high_priorrtt_midcnt", (46, 39)),
			INIT_DUMP_FIELD_INFO("cc_rttmid_oamack_cnt", (38, 31)),
			INIT_DUMP_FIELD_INFO("cc_rttmin", (30, 16)),
			INIT_DUMP_FIELD_INFO("cc_oamack_next_psn", (15, 0)),
		}
	},
	{0x128, {
			INIT_DUMP_FIELD_INFO("cc_sendack_mid_blk_cnt", (63, 52)),
			INIT_DUMP_FIELD_INFO("cc_recreq_blk_cnt", (51, 32)),
			INIT_DUMP_FIELD_INFO("cc_recreq_mid_blk_cnt", (31, 12)),
			INIT_DUMP_FIELD_INFO("cc_recreq_epsn", (11, 0)),
		}
	},
	{0x130, {
			INIT_DUMP_FIELD_INFO_1("cc_more_rttminth_flag", (63),
				"1- Calculated RTT is below QPC's RTTmin upper threshold"),
			INIT_DUMP_FIELD_INFO_1("cc_less_rttminth_flag", (62),
				"1- Calculated RTT is below QPC's RTTmin lower threshold"),
			INIT_DUMP_FIELD_INFO("init_rec_ecn_cnt", (61, 54)),
			INIT_DUMP_FIELD_INFO("cc_time_lastta", (53, 32)),
			INIT_DUMP_FIELD_INFO("ccqcn_reqcarry_sendqcn_time", (31, 0)),
		}
	},
	{0x138, {
			INIT_DUMP_FIELD_INFO("rmt_rec_ecn_cnt", (63, 58)),
			INIT_DUMP_FIELD_INFO_1("cc_winm_busy", (57),
				"1- During the TargetWin measurement period"),
			INIT_DUMP_FIELD_INFO_1("cc_rcvack_flag", (56),
				"1- Begin with 0, after receiving oamack become to 1 "),
			INIT_DUMP_FIELD_INFO("cc_recreq_sendtx_blk_cnt", (55, 36)),
			INIT_DUMP_FIELD_INFO("cc_recack_lastwinm_blk_cnt", (35, 16)),
			INIT_DUMP_FIELD_INFO("cc_recack_epsn", (15, 0)),
		}
	},
	{0x140, {
			INIT_DUMP_FIELD_INFO("ocq_bitmap_127_64", (63, 0)),
		}
	},
	{0x148, {
			INIT_DUMP_FIELD_INFO("rxmr_req_err", (63)),
			INIT_DUMP_FIELD_INFO("rxmr_resp_err", (62)),
			/* INIT_DUMP_FIELD_INFO("rsv", (61, 51)), */
			INIT_DUMP_FIELD_INFO("srq_srqe_vld", (50)),
			INIT_DUMP_FIELD_INFO("srq_rqwqe_ts", (49, 46)),
			INIT_DUMP_FIELD_INFO("srq_pm", (45, 44)),
			INIT_DUMP_FIELD_INFO("srq_cqn", (43, 20)),
			INIT_DUMP_FIELD_INFO("sr_ack_wait", (43)),
			INIT_DUMP_FIELD_INFO("sr_ack_wait_time", (42, 20)),
			INIT_DUMP_FIELD_INFO("srq_sub_id", (19, 12)),
			INIT_DUMP_FIELD_INFO("ocq_ci_phase", (19)),
			INIT_DUMP_FIELD_INFO("ocq_ci", (18, 12)),
			INIT_DUMP_FIELD_INFO("srq_pd", (11, 0)),
		}
	},
	{0x150, {
			INIT_DUMP_FIELD_INFO("srq_pd", (63, 52)),
			INIT_DUMP_FIELD_INFO("rxp_srq_ba", (51, 0)),
			INIT_DUMP_FIELD_INFO("ocq_bitmap_63_0", (63, 0)),
		}
	},
	{0x158, {
			INIT_DUMP_FIELD_INFO("pre_srqn", (63, 40)),
			INIT_DUMP_FIELD_INFO("glb_srqn", (39, 16)),
			INIT_DUMP_FIELD_INFO("rxp_req_pre_opcode", (15, 8)),
			INIT_DUMP_FIELD_INFO("cqe_bitmap", (63, 0))
		}
	},
	{0x160, {
			INIT_DUMP_FIELD_INFO("una_bitmap", (63, 0)),
		}
	},
	{0x168, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 52)), */
			INIT_DUMP_FIELD_INFO("rq_fpdpa", (51, 0)),
		}
	},
	{0x170, {
			INIT_DUMP_FIELD_INFO("rxp_read_length", (63, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 29)), */
			INIT_DUMP_FIELD_INFO("resp_psn_err", (28)),
			INIT_DUMP_FIELD_INFO("rnr_retry_num", (27, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 0)), */
		}
	},
	{0x178, {
			INIT_DUMP_FIELD_INFO("rx_resp_pre_opcode", (63, 59)),
			/*INIT_DUMP_FIELD_INFO("rsv", (58, 48)),*/
			INIT_DUMP_FIELD_INFO("rxp_unaq_msn", (47, 24)),
			INIT_DUMP_FIELD_INFO("una_psn_pre/sr_una_psn", (23, 0)),
		}
	},
	{0x180, {
			INIT_DUMP_FIELD_INFO("una_psn", (63, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv", (39, 34)), */
			INIT_DUMP_FIELD_INFO_1("rxp_irqe_cnt_sta", (33, 32),
				"0- Normal prediction and reception state; "
				"1- Prediction rapid rollback state; "
				"2- Flush erroneous prediction"),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 30)), */
			INIT_DUMP_FIELD_INFO("rxp_irq_ci_phase", (29)),
			INIT_DUMP_FIELD_INFO("rxp_irqe_ci", (28, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 22)), */
			INIT_DUMP_FIELD_INFO("txp_irq_pi_phase", (21)),
			INIT_DUMP_FIELD_INFO("txp_irqe_pi", (20, 16)),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 14)), */
			INIT_DUMP_FIELD_INFO("rxp_irq_cnt_ci_phase", (13)),
			INIT_DUMP_FIELD_INFO("rxp_irqe_cnt_ci", (12, 8)),
			/* INIT_DUMP_FIELD_INFO("rsv", (7, 6)), */
			INIT_DUMP_FIELD_INFO("rxp_irqe_cnt_pi_phase", (5)),
			INIT_DUMP_FIELD_INFO("rxp_irqe_cnt_pi", (4, 0)),
		}
	},
	{0x188, {
			INIT_DUMP_FIELD_INFO("ext_msnbp_idx_vld", (63)),
			INIT_DUMP_FIELD_INFO("ext_msnbp_idx", (62, 48)),
			INIT_DUMP_FIELD_INFO("rxp_send_msg_len_31_8", (63, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv", (39, 38)), */
			INIT_DUMP_FIELD_INFO("txp_orqe_ci_phase", (37)),
			INIT_DUMP_FIELD_INFO("txp_orqe_ci", (36, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 30)), */
			INIT_DUMP_FIELD_INFO("rxp_orqe_pi_phase", (29)),
			INIT_DUMP_FIELD_INFO("rxp_orqe_pi", (28, 24)),
			INIT_DUMP_FIELD_INFO("txp_recv_rtodb_cnt", (23, 20)),
			INIT_DUMP_FIELD_INFO("txp_send_rtodb_cnt", (19, 16)),
			INIT_DUMP_FIELD_INFO("txp_recv_raqdb_cnt", (15, 12)),
			INIT_DUMP_FIELD_INFO("txp_send_raqdb_cnt", (11, 8)),
			INIT_DUMP_FIELD_INFO("txp_recv_sqdb_cnt", (7, 4)),
			INIT_DUMP_FIELD_INFO("txp_send_sqdb_cnt", (3, 0)),
		}
	},
	{0x190, {
			INIT_DUMP_FIELD_INFO("psn_max", (63, 40)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (39, 36)), */
			INIT_DUMP_FIELD_INFO("cc_rttm_psnts", (35, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (23, 20)), */
			INIT_DUMP_FIELD_INFO("txp_sendpld_blk_cnt", (19, 0)),
		}
	},
	{0x198, {
			/* INIT_DUMP_FIELD_INFO("rsv*", (63, 58)),*/
			INIT_DUMP_FIELD_INFO_1("cc_high_prior_oam", (57),
				"0- OAM req packet uses the service packet priority sch_net_tc; "
				"1- OAM ACK packet uses special priority oamreq_net_tc"),
			INIT_DUMP_FIELD_INFO_1("cc_rttm_busy", (56),
				"Whether to initiate RTT measurement"),
			/* INIT_DUMP_FIELD_INFO("rsv*", (55, 49)), */
			INIT_DUMP_FIELD_INFO_1("rxp_qcn_reccnp_flag", (48),
				"Whether RXP has received CNP packets"),
			/* INIT_DUMP_FIELD_INFO("rsv*", (47, 44)),*/
			INIT_DUMP_FIELD_INFO("cc_recack_rectx_blk_cnt", (43, 24)),
			/* INIT_DUMP_FIELD_INFO("rsv*", (23, 21)),*/
			INIT_DUMP_FIELD_INFO("cc_lock", (20)),
			INIT_DUMP_FIELD_INFO("cc_targetWin", (19, 0)),
		}
	},
	{0x1A0, {
			INIT_DUMP_FIELD_INFO("msn_eop_bitmap", (63, 0)),
			INIT_DUMP_FIELD_INFO("rxp_rq_nxt_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("rxp_rq_nxt_pdpa", (51, 0)),
		}
	},
	{0x1A8, {
			INIT_DUMP_FIELD_INFO("read_bitmap", (63, 0)),
			INIT_DUMP_FIELD_INFO("rxp_rq_cur_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("rxp_rq_cur_pdpa", (51, 0)),
		}
	},
	{0x1B0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 53)), */
			INIT_DUMP_FIELD_INFO("txp_sq_nxt_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("txp_sq_nxt_pdpa", (51, 0)),
		}
	},
	{0x1B8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 62)), */
			INIT_DUMP_FIELD_INFO("ceaq_load_nxt_cnt", (61, 59)),
			INIT_DUMP_FIELD_INFO("ceaq_load_cur_cnt", (58, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 53)), */
			INIT_DUMP_FIELD_INFO("txp_sq_cur_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("txp_sq_cur_pdpa", (51, 0)),
		}
	},
	{0x1C0, {
			INIT_DUMP_FIELD_INFO("rx_lsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("sr_retry_rr_fpsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("rq_id_max", (63, 40)),
			INIT_DUMP_FIELD_INFO("retry_psn", (39, 16)),
			/* INIT_DUMP_FIELD_INFO("rsv", (15, 10)), */
			INIT_DUMP_FIELD_INFO("unaqe_pi_phase", (9)),
			INIT_DUMP_FIELD_INFO("unaqe_pi", (8, 0)),
		}
	},
	{0x1C8, {
			INIT_DUMP_FIELD_INFO("retry_fpsn", (63, 40)),
			INIT_DUMP_FIELD_INFO("sq_cqe_wqebid_phase", (39)),
			INIT_DUMP_FIELD_INFO("sq_cqe_wqebid", (38, 24)),
			INIT_DUMP_FIELD_INFO("sr_retry_rq_id", (23, 8)),
			/* INIT_DUMP_FIELD_INFO("rsv", (7, 4)), */
			INIT_DUMP_FIELD_INFO_1("retry_st", (3, 0),
				"0- Normal; 1- psn_err; 2- rnr_err"),
		}
	},
	{0x1D0, {
			INIT_DUMP_FIELD_INFO("txp_sq_cur_psn", (63, 40)),
			INIT_DUMP_FIELD_INFO("sr_retry_r_id", (39, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31, 28)), */
			INIT_DUMP_FIELD_INFO_1("e2e_fc_limit_flag", (27), "1- e2e fc limit"),
			INIT_DUMP_FIELD_INFO_1("psn_overflow_flag", (26), "1- psn overflow"),
			INIT_DUMP_FIELD_INFO_1("unaq_full_flag", (25), "1- UNAQ is full"),
			INIT_DUMP_FIELD_INFO_1("irq_full_flag", (24), "1- IRQ is full"),
			/* INIT_DUMP_FIELD_INFO("rsv", (23, 17)), */
			INIT_DUMP_FIELD_INFO_1("waitack_db_flag", (16),
				"1- waitack_db has been triggered; "
				"TXP writes 0 upon receiving waitack_db; "
				"CEAQ writes 1 when triggering waitack_db."),
			INIT_DUMP_FIELD_INFO("sqe_dif_err_cnt", (15, 14)),
			INIT_DUMP_FIELD_INFO("txp_load_nxt_cnt", (13, 11)),
			INIT_DUMP_FIELD_INFO("txp_load_cur_cnt", (10, 8)),
			INIT_DUMP_FIELD_INFO("tx_sq_err_code", (7, 0)),
		}
	},
	{0x1D8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 58)), */
			INIT_DUMP_FIELD_INFO("unaqe_ci_phase", (57)),
			INIT_DUMP_FIELD_INFO("unaqe_ci", (56, 48)),
			INIT_DUMP_FIELD_INFO("rq_cqe_wqebid_phase", (47)),
			INIT_DUMP_FIELD_INFO("rq_cqe_wqebid", (46, 32)),
			/* INIT_DUMP_FIELD_INFO("rsv", (31)), */
			INIT_DUMP_FIELD_INFO("ceaq_srq_cnt", (30, 26)),
			INIT_DUMP_FIELD_INFO_1("ae_flag", (25),
				"1- QP reported an AE once (excluding RAQ_full and RAQ_flush)"),
			INIT_DUMP_FIELD_INFO("e2e_fc_en", (24)),
			INIT_DUMP_FIELD_INFO("ssn", (23, 0)),
			INIT_DUMP_FIELD_INFO("rq_id_copy", (23, 0)),
		}
	},
	/* {0x1E0, {
	 *		INIT_DUMP_FIELD_INFO("rsv", (63, 0)),
	 *	}
	 * },
	 */
	{0x1E8, {
			INIT_DUMP_FIELD_INFO("hw_seq_num", (63, 49)),
			INIT_DUMP_FIELD_INFO("hw_drop_db_sq_ci_phase", (47)),
			INIT_DUMP_FIELD_INFO("hw_drop_db_sq_ci", (46, 32)),
			INIT_DUMP_FIELD_INFO("hw_rq_ci_phase", (31)),
			INIT_DUMP_FIELD_INFO("hw_rq_ci", (30, 16)),
			INIT_DUMP_FIELD_INFO("hw_sq_ci_phase", (15)),
			INIT_DUMP_FIELD_INFO("hw_sq_ci", (14, 0)),
		}
	},
	{0x1F0, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 55)), */
			INIT_DUMP_FIELD_INFO("sw_qpc_ba", (54, 0))
		}
	},
	{0x1F8, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 36)), */
			INIT_DUMP_FIELD_INFO("sw_seq_num", (35, 32)),
			INIT_DUMP_FIELD_INFO("sw_rq_pi_phase", (31)),
			INIT_DUMP_FIELD_INFO("sw_rq_pi", (30, 16)),
			INIT_DUMP_FIELD_INFO("sw_sq_pi_phase", (15)),
			INIT_DUMP_FIELD_INFO("sw_sq_pi", (14, 0)),
		}
	},
};

static const struct nbl_cache_dump nbl_mrt_dump_table_v2[] = {
	{0x00, {
			INIT_DUMP_FIELD_INFO_1("state", (63, 62),
				"0- invalid; 1- free; 2- valid; 3- reserved"),
			INIT_DUMP_FIELD_INFO_1("Type", (61, 60),
				"0- MR; 1- MW-Type1; 2- MW-Type2; 3- reserved"),
			INIT_DUMP_FIELD_INFO_1("addr_type", (59),
				"0- MR based on 0 mode; 1- MR based on VA mode"),
			INIT_DUMP_FIELD_INFO_1("leaf_size", (58),
				"0- No PBL; 1- With PBL"),
			INIT_DUMP_FIELD_INFO_1("page_size", (57, 56),
				"0- 4KB/page; 1- 2MB/page; 2- 1GB/page; 3- reserved"),
			INIT_DUMP_FIELD_INFO_1("lr", (55), "local read"),
			INIT_DUMP_FIELD_INFO_1("lw", (54), "local write"),
			INIT_DUMP_FIELD_INFO_1("rr", (53), "remote read"),
			INIT_DUMP_FIELD_INFO_1("rw", (52), "remote write"),
			INIT_DUMP_FIELD_INFO_1("a", (51), "atomic"),
			INIT_DUMP_FIELD_INFO_1("b", (50), "bind"),
			INIT_DUMP_FIELD_INFO_1("Invalidate", (49),
				"0- Not allow invalid operations; 1- Allow invalid operations"),
			INIT_DUMP_FIELD_INFO_1("MR_BRANCH", (48),
				"0- Normal branch; 1- Special branch"),
			INIT_DUMP_FIELD_INFO("Key", (47, 40)),
			INIT_DUMP_FIELD_INFO("mrt_op_record", (39, 24)),
			INIT_DUMP_FIELD_INFO("MR_Index", (23, 0)),
		}
	},
	{0x08, {
			INIT_DUMP_FIELD_INFO("Len", (61, 16)),
			INIT_DUMP_FIELD_INFO("MW_Num", (9, 0)),
		}
	},
	{0x10, {
			INIT_DUMP_FIELD_INFO("VA_Start", (63, 0)),
		}
	},
	{0x18, {
			INIT_DUMP_FIELD_INFO("First_PBL_Index", (27, 0)),
			INIT_DUMP_FIELD_INFO("Physical_Buffer_Address", (63, 0)),
		}
	},
	{0x20, {
			INIT_DUMP_FIELD_INFO("pa0", (63, 0)),
		}
	},
	{0x28, {
			INIT_DUMP_FIELD_INFO("pa1", (63, 0)),
		}
	},
	{0x30, {
			INIT_DUMP_FIELD_INFO("PD", (63, 40)),
			INIT_DUMP_FIELD_INFO("Bdf_num", (39, 24)),
			INIT_DUMP_FIELD_INFO("pbl_key", (23, 13)),
		}
	},
};

static const struct nbl_cache_dump nbl_cqc_dump_table_v2[] = {
	{0x00, {
			INIT_DUMP_FIELD_INFO_1("cq_pm", (63, 62), "0- continue; 1- not continue"),
			INIT_DUMP_FIELD_INFO_1("cq_size", (61, 58), "cq depth is 2^cq_size"),
			INIT_DUMP_FIELD_INFO("ceqn", (57, 51)),
			/* INIT_DUMP_FIELD_INFO("rsv", (50, 38)); */
			INIT_DUMP_FIELD_INFO("shadow_rth", (37, 24)),
			INIT_DUMP_FIELD_INFO("qp_cnt", (23, 0)),
		}
	},
	/* {0x08, ()}, */
	{0x10, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 61)), */
			INIT_DUMP_FIELD_INFO("cqc_shadow_ba", (60, 0)),
		}
	},
	{0x18, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 52)), */
			INIT_DUMP_FIELD_INFO("cq_pd_ba", (51, 0)),
			INIT_DUMP_FIELD_INFO("cq_start_pa", (51, 0)),
		}
	},
	{0x20, {
			INIT_DUMP_FIELD_INFO_1("state", (63, 62),
				"0- initial; 1- valid; 2- invalid; 3- overflow"),
			INIT_DUMP_FIELD_INFO("arm_next", (61)),
			INIT_DUMP_FIELD_INFO("arm_next_se", (60)),
			INIT_DUMP_FIELD_INFO("hw_sel_cnt", (59, 58)),
			INIT_DUMP_FIELD_INFO("load_cnt", (57, 56)),
			/* INIT_DUMP_FIELD_INFO("rsv", (55, 33)), */
			INIT_DUMP_FIELD_INFO("cq_pi_phase", (32, 31)),
			INIT_DUMP_FIELD_INFO("cq_pi", (30, 16)),
			INIT_DUMP_FIELD_INFO("cq_se_pi_phase", (15)),
			INIT_DUMP_FIELD_INFO("cq_se_pi", (14, 0)),
		}
	},
	{0x28, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 53)), */
			INIT_DUMP_FIELD_INFO("cq_cur_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("cq_cur_pdpa", (51, 0)),
		}
	},
	{0x30, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 53)), */
			INIT_DUMP_FIELD_INFO("cq_nxt_pdpa_vld", (52)),
			INIT_DUMP_FIELD_INFO("cq_nxt_pdpa", (51, 0)),
		}
	},
	{0x38, {
			/* INIT_DUMP_FIELD_INFO("rsv", (63, 18)), */
			INIT_DUMP_FIELD_INFO("sw_sel_cnt", (17, 16)),
			INIT_DUMP_FIELD_INFO("cq_ci_phase", (15)),
			INIT_DUMP_FIELD_INFO("cq_ci", (14, 0)),
		}
	},
};

/**
 * dbg_vsnprintf -
 * @fmt: print formatting string
 */
void write_to_file_buffer(struct nbl_func_file *func_file, char *fmt, ...)
{
	int cnt;
	va_list argp;
	size_t available_space;

	va_start(argp, fmt);
	available_space = func_file->total_len - func_file->used_len;
	if (available_space == 0) {
		va_end(argp);
		return;
	}

	cnt = vsnprintf(func_file->buf + func_file->used_len, available_space, fmt, argp);
	va_end(argp);

	if ((size_t)cnt < available_space) {
		func_file->used_len += cnt;
	} else {
		func_file->used_len = func_file->total_len;
		func_file->buf[func_file->total_len - 1] = '\0';
	}
}

void nbl_dump_hex_to_file_buffer(struct nbl_func_file *func_file, u8 *buf, int len)
{
	int ix = 0;

	while (ix < len) {
		write_to_file_buffer(func_file,
			"[%d-%d]%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
			ix, ix + 15,
			buf[ix], buf[ix + 1], buf[ix + 2], buf[ix + 3],
			buf[ix + 4], buf[ix + 5], buf[ix + 6], buf[ix + 7],
			buf[ix + 8], buf[ix + 9], buf[ix + 10], buf[ix + 11],
			buf[ix + 12], buf[ix + 13], buf[ix + 14], buf[ix + 15]);
		ix += 16;
	}
}

void nbl_dump_fields(struct nbl_pci_f *rf, struct nbl_func_file *func_file,
		u8 *data, enum NBL_DBG_DUMP_TYPE type)
{
	u64 temp;
	u64 value;
	u64 span_two_mem_prev_value = 0;
	u64 now_mask;
	const char *cur_field_name;
	const char *next_field_name;
	u8 i;
	u8 j;
	int depth;
	int field_len;
	const struct nbl_cache_dump *table;

	if (data == NULL)
		return;

	switch (type) {
	case NBL_DBG_DUMP_QPC:
		if (rf->product->debug_layout.ext_qpc_v4) {
			table = nbl_qpc_dump_table_v4;
			depth = ARRAY_SIZE(nbl_qpc_dump_table_v4);
			field_len = ARRAY_SIZE(nbl_qpc_dump_table_v4[0].fields);
		} else {
			table = nbl_qpc_dump_table_v2;
			depth = ARRAY_SIZE(nbl_qpc_dump_table_v2);
			field_len = ARRAY_SIZE(nbl_qpc_dump_table_v2[0].fields);
		}
		break;
	case NBL_DBG_DUMP_MRT:
		table = nbl_mrt_dump_table_v2;
		depth = ARRAY_SIZE(nbl_mrt_dump_table_v2);
		field_len = ARRAY_SIZE(nbl_mrt_dump_table_v2[0].fields);
		break;
	case NBL_DBG_DUMP_CQC:
		table = nbl_cqc_dump_table_v2;
		depth = ARRAY_SIZE(nbl_cqc_dump_table_v2);
		field_len = ARRAY_SIZE(nbl_cqc_dump_table_v2[0].fields);
		break;
	default:
		pr_err("no such dump type %d", type);
		return;
	}

	for (i = 0; i < depth; i++) {
		get_64bit_val((__be64 *)data, table[i].byte_index, &temp);
		write_to_file_buffer(func_file, "[%#x] ", table[i].byte_index);
		/*
		 * In order to check if the field spans across two 8-byte boundaris,
		 * we need to get the first field name of next row
		 */
		if (i < depth - 1)
			next_field_name = table[i+1].fields[0].field_name;
		else
			next_field_name = NULL;
		for (j = 0; j < field_len; j++) {
			if (table[i].fields[j].field_name[0] == '\0')
				break;
			now_mask = table[i].fields[j].mask;
			cur_field_name = table[i].fields[j].field_name;
			value = (temp & now_mask) >> __ffs(now_mask);
			/*
			 * Certain fields might span two 8-byte memory dumps.
			 * When this happens, we capture the value from the first memory dump
			 * and combine it with the value from the second memory dump.
			 */
			if (table[i].fields[j+1].field_name[0] == '\0' &&
					next_field_name &&
					strcmp(next_field_name, cur_field_name) == 0) {
				span_two_mem_prev_value = value;
				continue;
			} else {
				/*
				 * If a field value spans across two 8-byte boundaries,
				 * shift the previous value,
				 * then add the subsequent value.
				 */
				if (span_two_mem_prev_value != 0) {
					value +=
						(span_two_mem_prev_value << (64 - __ffs(now_mask)));
					span_two_mem_prev_value = 0;
				}
				write_to_file_buffer(func_file,
					"%s:0x%llx ", cur_field_name, value);
				if (table[i].fields[j].description[0] != '\0')
					write_to_file_buffer(func_file, "(%s) ",
						table[i].fields[j].description);
			}
			write_to_file_buffer(func_file, "\t");
		}
		write_to_file_buffer(func_file, "\n");
	}

}
