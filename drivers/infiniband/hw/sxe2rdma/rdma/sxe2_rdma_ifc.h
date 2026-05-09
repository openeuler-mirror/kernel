/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_rdma_ifc.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_RDMA_IFC_H__
#define __SXE2_RDMA_IFC_H__

#include "sxe2_mbx_public.h"

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define SXE2_PF_DB_PROC_BAR_OFFSET 0x240000
#define SXE2_VF_DB_PROC_BAR_OFFSET 0xBE00

#define SXE2_GLINT_CTRL_BAR_OFFSET 0x260000

#define PF_SXE2_RCMS_MAN_BAR_OFFSET 0x250000
#define VF_SXE2_RCMS_MAN_BAR_OFFSET 0x22000

#define PF_QSET_APPLY_REQ_OFFSET    (SXE2_PF_DB_PROC_BAR_OFFSET + 0x6000)
#define PF_QSET_APPLY_RESP_OFFSET   (SXE2_PF_DB_PROC_BAR_OFFSET + 0x6004)
#define PF_QSET_QUERY_REQ_OFFSET    (SXE2_PF_DB_PROC_BAR_OFFSET + 0x6008)
#define PF_QSET_QUERY_RESP_OFFSET   (SXE2_PF_DB_PROC_BAR_OFFSET + 0x600c)
#define PF_QSET_RELEASE_REQ_OFFSET  (SXE2_PF_DB_PROC_BAR_OFFSET + 0x6010)
#define PF_QSET_RELEASE_RESP_OFFSET (SXE2_PF_DB_PROC_BAR_OFFSET + 0x6014)
#define PF_QSET_QP_BIND_REQ_OFFSET  (SXE2_PF_DB_PROC_BAR_OFFSET + 0x6018)
#define PF_QSET_QP_BIND_RESP_OFFSET (SXE2_PF_DB_PROC_BAR_OFFSET + 0x601c)

#define GLINT_CTRL_PF_INT_AEQCTL_OFFSET (SXE2_GLINT_CTRL_BAR_OFFSET + 0x80)
#define GLINT_CTRL_PF_INT_CEQCTL_OFFSET(_I)                                    \
	(0x26492c + ((_I)*4))
#define PF_GLINT_CTRL_DYN_CTL_OFFSET(_I) (0x269530 + ((_I)*4))
#define VF_GLINT_CTRL_DYN_CTL_OFFSET(_I) (0x2800 + ((_I)*4))

#define VF_QSET_APPLY_REQ_OFFSET    (SXE2_VF_DB_PROC_BAR_OFFSET + 0x0)
#define VF_QSET_APPLY_RESP_OFFSET   (SXE2_VF_DB_PROC_BAR_OFFSET + 0x4)
#define VF_QSET_QUERY_REQ_OFFSET    (SXE2_VF_DB_PROC_BAR_OFFSET + 0x8)
#define VF_QSET_QUERY_RESP_OFFSET   (SXE2_VF_DB_PROC_BAR_OFFSET + 0xC)
#define VF_QSET_RELEASE_REQ_OFFSET  (SXE2_VF_DB_PROC_BAR_OFFSET + 0x10)
#define VF_QSET_RELEASE_RESP_OFFSET (SXE2_VF_DB_PROC_BAR_OFFSET + 0x14)
#define VF_QSET_QP_BIND_REQ_OFFSET  (SXE2_VF_DB_PROC_BAR_OFFSET + 0x18)
#define VF_QSET_QP_BIND_RESP_OFFSET (SXE2_VF_DB_PROC_BAR_OFFSET + 0x1c)

#define SXE2_PF_MQ_BAR_OFFSET (0x250000 + 0xE000)
#define SXE2_VF_MQ_BAR_OFFSET (0x22000 + 0x300)

#define PF_MQC_ADDR_HIGH_OFFEST (SXE2_PF_MQ_BAR_OFFSET + 0x0)
#define PF_MQC_ADDR_LOW_OFFEST	(SXE2_PF_MQ_BAR_OFFSET + 0x4)
#define PF_MQC_ADDR_VLD_OFFEST	(SXE2_PF_MQ_BAR_OFFSET + 0x8)
#define PF_MQ_STATUS_OFFEST	(SXE2_PF_MQ_BAR_OFFSET + 0xC)
#define PF_MQ_DB_OFFEST		(SXE2_PF_MQ_BAR_OFFSET + 0x10)
#define PF_MQ_WQE_DONE_OFFEST	(SXE2_PF_MQ_BAR_OFFSET + 0x18)
#define PF_MQ_ERRCODES_OFFEST	(SXE2_PF_MQ_BAR_OFFSET + 0x1C)

#define VF_MQC_ADDR_HIGH_OFFEST (SXE2_VF_MQ_BAR_OFFSET + 0x0)
#define VF_MQC_ADDR_LOW_OFFEST	(SXE2_VF_MQ_BAR_OFFSET + 0x4)
#define VF_MQC_ADDR_VLD_OFFEST	(SXE2_VF_MQ_BAR_OFFSET + 0x8)
#define VF_MQ_STATUS_OFFEST	(SXE2_VF_MQ_BAR_OFFSET + 0xC)
#define VF_MQ_DB_OFFEST		(SXE2_VF_MQ_BAR_OFFSET + 0x10)
#define VF_MQ_WQE_DONE_OFFEST	(SXE2_VF_MQ_BAR_OFFSET + 0x18)
#define VF_MQ_ERRCODES_OFFEST	(SXE2_VF_MQ_BAR_OFFSET + 0x1C)
#define PF_RCMS_SPT_CACHE_FAST_INVALID_MASK_OFFSET                             \
	(PF_SXE2_RCMS_MAN_BAR_OFFSET + 0x90)
#define VF_RCMS_SPT_CACHE_FAST_INVALID_MASK_OFFSET                             \
	(VF_SXE2_RCMS_MAN_BAR_OFFSET + 0x90)
#define PF_RCMS_SPT_CACHE_FAST_INVALID_IDX_OFFSET                              \
	(PF_SXE2_RCMS_MAN_BAR_OFFSET + 0x94)
#define VF_RCMS_SPT_CACHE_FAST_INVALID_IDX_OFFSET                              \
	(VF_SXE2_RCMS_MAN_BAR_OFFSET + 0x94)

#define SXE2_PF_TXRX_COM_BAR_OFFSET 0x1F0000
#define SXE2_VF_TXRX_COM_BAR_OFFSET 0x8C00

#define PF_RDMA_CONFIG_PKEY_OFFSET                                             \
	(SXE2_PF_TXRX_COM_BAR_OFFSET + 0x4D800 + 0x1000)
#define VF_RDMA_CONFIG_PKEY_OFFSET (SXE2_VF_TXRX_COM_BAR_OFFSET + 0x0)

struct sxe2_mqc {
	u64 enable_fine_grained_timers : 1;
	u64 disable_FPDU_packing : 1;
	u64 RoCEv2_RTO_policy : 1;
	u64 protocol_used : 2;
	u64 rsv0 : 3;
	u64 SQ_size : 4;
	u64 rsv1 : 12;
	u64 struct_version : 8;
	u64 num_CEQs_per_VF : 8;
	u64 rsv2 : 24;
	u64 rsv3 : 9;
	u64 SQ_base : 55;
	u64 rcms_profile_type : 3;
	u64 remote_endpoint_trk_en : 1;
	u64 rdpa_assist : 4;
	u64 cache_line_64byte_en : 1;
	u64 rsv4 : 23;
	u64 PE_enabled_vf_count : 6;
	u64 rsv5 : 26;
	u64 QP_completion_context;
	u64 hw_minor_version : 16;
	u64 hw_major_version : 16;
	u64 rsv6 : 16;
	u64 dcqcn_min_rate : 8;
	u64 dcqcn_min_dec_factor : 8;
	u64 rsv7;
	u64 dcqcn_T : 16;
	u64 rsv8 : 16;
	u64 cc_hai_factor : 16;
	u64 cc_rai_factor : 16;
	u64 dcqcn_B : 25;
	u64 dcqcn_F : 3;
	u64 rsv9 : 3;
	u64 cc_cfg_valid : 1;
	u64 dcqcn_rreduce_mperiod : 32;
};

enum sxe2_hw_mq_op {
	SXE2_MQ_OP_CREATE_QP		     = 0x00,
	SXE2_MQ_OP_MODIFY_QP		     = 0x01,
	SXE2_MQ_OP_DESTROY_QP		     = 0x02,
	SXE2_MQ_OP_CREATE_CQ		     = 0x03,
	SXE2_MQ_OP_MODIFY_CQ		     = 0x04,
	SXE2_MQ_OP_DESTROY_CQ		     = 0x05,
	SXE2_MQ_OP_ALLOC_MR_key		     = 0x09,
	SXE2_MQ_OP_REG_MR		     = 0x0a,
	SXE2_MQ_OP_QUERY_MR_key		     = 0x0b,
	SXE2_MQ_OP_DEALLOC_MR_key	     = 0x0d,
	SXE2_MQ_OP_MANAGE_PBLE_BP	     = 0x10,
	SXE2_MQ_OP_QUERY_QP		     = 0x13,
	SXE2_MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE = 0x15,
	SXE2_MQ_OP_CREATE_CEQ		     = 0x16,
	SXE2_MQ_OP_DESTROY_CEQ		     = 0x18,
	SXE2_MQ_OP_CREATE_AEQ		     = 0x19,
	SXE2_MQ_OP_DESTROY_AEQ		     = 0x1b,
	SXE2_MQ_OP_CREATE_ADDR_HANDLE	     = 0x1c,
	SXE2_MQ_OP_MODIFY_ADDR_HANDLE	     = 0x1d,
	SXE2_MQ_OP_DESTROY_ADDR_HANDLE	     = 0x1e,
	SXE2_MQ_OP_UPDATE_FPT		     = 0x1f,
	SXE2_MQ_OP_QUERY_FPM_VAL	     = 0x20,
	SXE2_MQ_OP_COMMIT_FPM_VAL	     = 0x21,
	SXE2_MQ_OP_NOP			     = 0x24,
	SXE2_MQ_OP_GATHER_STATS		     = 0x2e,
	SXE2_MQ_OP_CREATE_SRQ		     = 0x30,
	SXE2_MQ_OP_MODIFY_SRQ		     = 0x31,
	SXE2_MQ_OP_DESTROY_SRQ		     = 0x32,
	SXE2_MQ_OP_DEREGISTER_MR	     = 0x33,
	SXE2_MQ_OP_MODIFY_CEQ		     = 0x34,
	SXE2_MQ_OP_QUERY_CEQ		     = 0x35,
	SXE2_MQ_OP_MODIFY_AEQ		     = 0x36,
	SXE2_MQ_OP_QUERY_AEQ		     = 0x37,
	SXE2_MQ_OP_QUERY_CQ		     = 0x38,
	SXE2_MQ_OP_QUERY_SRQ		     = 0x39,
	SXE2_MQ_OP_QUERY_MR		     = 0x3b,
	SXE2_MQ_OP_MAX			     = 0x50,
};

struct mcq_cqe {
	u64 rsv0;
	u64 MQ_completion_context;
	u64 operation_return_value : 32;
	u64 rsv1 : 32;
	u64 minor_error_code : 16;
	u64 major_error_code : 16;
	u64 MQ_desc_index : 15;
	u64 rsv2 : 8;
	u64 error : 1;
	u64 op : 6;
	u64 SQ : 1;
	u64 CQE_valid : 1;
	u64 rsv3;
	u64 CQE_timestamp;
	u64 rsv4;
	u64 rsv5;
};

struct sxe2_cq_wqe {
	u64 pbl_index;
	u64 dbr_addr;

	u64 eqn : 10;
	u64 log_dbr_size : 5;
	u64 log_cq_size : 5;
	u64 rsv1 : 1;
	u64 scqe_break_moderation_en : 1;
	u64 oi : 1;
	u64 sw_owner_bit : 1;
	u64 sw_status : 4;
	u64 rsv2 : 4;
	u64 log_page_size : 5;
	u64 page_offset : 15;
	u64 pbl_mode : 2;
	u64 TPH_value : 8;
	u64 rsv3 : 2;

	u64 rsv4 : 32;
	u64 op : 6;
	u64 cqn : 19;
	u64 rsv5 : 6;
	u64 WQE_Valid : 1;

	u64 rsv6 : 8;
	u64 physical_buffer_address : 56;

	u64 cq_max_count : 16;
	u64 cq_period : 12;
	u64 TPH_en : 1;
	u64 rsv7 : 3;
	u64 vsi_index : 10;
	u64 rsv8 : 1;
	u64 rsv9 : 2;
	u64 rsv10 : 19;

	u64 rsv11;
	u64 rsv12;
};

struct drv_rdma_soft_cqc {
	u64 pbl_index;
	u64 dbr_addr;

	u64 eqn : 10;
	u64 log_dbr_size : 5;
	u64 log_cq_size : 5;
	u64 rsv1 : 1;
	u64 scqe_break_moderation_en : 1;
	u64 oi : 1;
	u64 sw_owner_bit : 1;
	u64 sw_status : 4;
	u64 rsv2 : 4;
	u64 log_page_size : 5;
	u64 page_offset : 15;
	u64 pbl_mode : 2;
	u64 TPH_value : 8;
	u64 rsv3 : 2;

	u64 cq_max_count : 16;
	u64 cq_period : 12;
	u64 TPH_en : 1;
	u64 rsv4 : 3;
	u64 vsi_index : 10;
	u64 rsv6 : 1;
	u64 rsv7 : 21;
};

struct drv_rdma_hw_cqc {
	u32 hw_owner_bit : 1;
	u32 st : 4;
	u32 cmd : 1;
	u32 cmd_sn : 2;
	u32 hw_status : 1;
	u32 last_sol_index_en : 1;
	u32 fid : 12;
	u32 hw_eqn : 10;
	u32 last_notified_index : 24;
	u32 last_solicited_index_l : 8;
	u32 last_solicited_index_h : 16;
	u32 consumer_counter_l : 16;
	u32 consumer_counter_h : 8;
	u32 producer_counter : 24;

	u32 page_addr_odd_l;
	u32 page_addr_odd_h;

	u32 page_addr_even_l;
	u32 page_addr_even_h;
};

struct sxe2_rdma_cqc {
	struct drv_rdma_soft_cqc scqc;
	struct drv_rdma_hw_cqc hcqc;
};

#define SXE2_OP_TYPE_RDMA_WRITE	    0x00
#define SXE2_OP_TYPE_RDMA_READ	    0x01
#define SXE2_OP_TYPE_RSVD1	    0x02
#define SXE2_OP_TYPE_SEND	    0x03
#define SXE2_OP_TYPE_SEND_INV	    0x04
#define SXE2_OP_TYPE_SEND_SOL	    0x05
#define SXE2_OP_TYPE_SEND_SOL_INV   0x06
#define SXE2_OP_TYPE_RSVD2	    0x07
#define SXE2_OP_TYPE_BIND_MW	    0x08
#define SXE2_OP_TYPE_FAST_REG_MR    0x09
#define SXE2_OP_TYPE_LOCAL_INV	    0x0a
#define SXE2_OP_TYPE_RDMA_READ_INV  0x0b
#define SXE2_OP_TYPE_NOP	    0x0c
#define SXE2_OP_TYPE_RDMA_WRITE_SOL 0x0d
#define SXE2_OP_TYPE_RSVD3	    0x0e

struct sxe2_qpc {
	__u64 ack_timeout : 5;
	__u64 retry_mode : 1;
	__u64 credit_en : 1;
	__u64 comm_est : 1;
	__u64 rqe_lwm : 16;
	__u64 rsv0 : 4;
	__u64 qp_state : 4;
	__u64 dqpn : 24;
	__u64 qp_type : 8;

	__u64 llwqe_page_index : 12;
	__u64 llwqe_mode_enable : 1;
	__u64 rsv1 : 8;
	__u64 retry_resp_op_sel : 1;
	__u64 log_rtm : 2;
	__u64 log_msg_max : 5;
	__u64 pmtu : 3;
	__u64 page_offset : 13;
	__u64 rsv2 : 11;
	__u64 log_rq_size : 4;
	__u64 log_sq_size : 4;

	__u64 cqn_snd : 19;
	__u64 rsv3 : 5;
	__u64 log_rq_stride : 2;
	__u64 rsv4 : 1;
	__u64 log_page_size : 5;
	__u64 cqn_rcv : 19;
	__u64 rsv5 : 5;
	__u64 min_rnr_nak : 5;
	__u64 rsv6 : 2;
	__u64 fl : 1;

	__u64 srqn : 18;
	__u64 rsv7 : 3;
	__u64 bucket_type : 3;
	__u64 stat_rate : 4;
	__u64 rq_type : 3;
	__u64 ipv4 : 1;
	__u64 pd : 18;
	__u64 rsv8 : 6;
	__u64 log_rra_max : 4;
	__u64 log_sra_max : 4;

	__u64 send_start_psn : 24;
	__u64 tmo_retry : 3;
	__u64 udpriv_cqenable : 1;
	__u64 rnr_retry : 3;
	__u64 rsv9 : 1;
	__u64 rcv_start_psn : 24;
	__u64 ack_mode : 1;
	__u64 rsv10 : 7;

	__u64 pkey_index : 5;
	__u64 rq_flush_flag : 1;
	__u64 sq_flush_flag : 1;
	__u64 rsv46 : 9;
	__u64 log_ack_req_freq : 4;
	__u64 rsv11 : 4;
	__u64 hop_limit : 8;
	__u64 q_key : 32;

	__u64 smac_low : 32;
	__u64 smac_high : 16;
	__u64 src_port_num : 16;

	__u64 rmac_low : 32;
	__u64 rmac_high : 16;
	__u64 dest_port_num : 16;

	__u64 qp_completion_contex;

	__u64 sq_tph_value : 8;
	__u64 rq_tph_value : 8;
	__u64 sq_tph_en : 1;
	__u64 rq_tph_en : 1;
	__u64 xmit_tph_en : 1;
	__u64 rcv_tph_en : 1;
	__u64 rsv12 : 4;
	__u64 cnp_dscp : 6;
	__u64 cnp_ecn : 2;
	__u64 flow_label : 20;
	__u64 dscp : 6;
	__u64 ecn : 2;
	__u64 rsv13 : 4;

	__u64 dest_ipaddr3 : 32;
	__u64 dest_ipaddr2 : 32;

	__u64 dest_ipaddr1 : 32;
	__u64 dest_ipaddr0 : 32;

	__u64 local_ipaddr_3 : 32;
	__u64 local_ipaddr_2 : 32;

	__u64 local_ipaddr_1 : 32;
	__u64 local_ipaddr_0 : 32;

	__u64 dbr_addr;

	__u64 pbl_pointer;

	__u64 tpid_index : 2;
	__u64 rsv14 : 4;
	__u64 wq_acces_mode : 1;
	__u64 use_statistics_intance : 1;
	__u64 statistics_instance_index : 1;
	__u64 rsv15 : 6;
	__u64 insert_vlan_tag : 1;
	__u64 vlan_tag : 16;
	__u64 src_vsi : 10;
	__u64 rsv16 : 6;
	__u64 dispatch_min_unit : 14;
	__u64 dispatch_mode : 1;
	__u64 rsv17 : 1;
	__u32 hw_sq_wqebb_counter : 16;
	__u32 txw_sq_retry_end_ptr : 16;

	__u32 wqe_page_pa1_low;

	__u32 wqe_page_pa1_high;

	__u32 wqe_page_pa2_low;

	__u32 wqe_page_pa2_high;

	__u32 wqe_page_pa_vld : 2;
	__u32 wqe_page_pa_sel : 1;
	__u32 txw_resp_retry_flag : 1;
	__u32 wqe_send_bk_vld : 1;
	__u32 wqe_send_sge_addr : 4;
	__u32 txw_resp_occupty : 1;
	__u32 wqe_polarity : 1;
	__u32 wqe_rx_sqretry : 1;
	__u32 txw_sq_occupty : 1;
	__u32 txw_resp_break_all : 1;
	__u32 txw_ll_type : 1;
	__u32 txw_resp_go_back_n : 1;
	__u32 wqe_rx_ack_retry : 1;
	__u32 wqe_tx_eng_retry : 1;
	__u32 wqe_resp_bk_valid : 1;
	__u32 txw_sq_retry_flag : 1;
	__u32 txw_nxt_need_irrl_num : 4;
	__u32 txw_ll_wqe_drop : 1;
	__u32 txw_sq_retry_type : 1;
	__u32 txw_sq_retry_start_psn_low : 6;

	__u32 txw_sq_retry_start_psn : 18;
	__u32 txw_resp_retry_finish_flag : 1;
	__u32 rsv18 : 3;
	__u32 txw_send_try_flag : 1;
	__u32 wqe_proc_qp_state : 1;
	__u32 stat_rate_already_init : 1;
	__u32 last_wqe_already_sent : 1;
	__u32 wqe_nak_retry_cnt : 3;
	__u32 wqe_rnr_retry_cnt : 3;

	__u32 wqe_send_offest;

	__u32 txw_resp_retry_cnt : 8;
	__u32 txw_resp_retry_end_ptr : 8;
	__u32 txw_resp_retry_finish_back_ptr : 8;
	__u32 txw_resp_retry_exit_ptr : 8;

	__u32 wqe_ssn_send : 24;
	__u32 wqe_ssn_nocredit_cnt_low : 8;

	__u32 wqe_ssn_nocredit_cnt_high : 16;
	__u32 wqe_next_send_psn_low : 16;

	__u32 wqe_next_send_psn_high : 8;
	__u32 respcache_msn : 24;

	__u32 respcache_credit : 5;
	__u32 wqe_credit_check_en : 1;
	__u32 wqe_outsdanding_check_en : 1;
	__u32 sq_stop : 1;
	__u32 respcache_psn : 24;

	__u32 respcache_r_va_low;

	__u32 respcache_r_va_high;

	__u32 respcache_r_key;

	__u32 respcache_dma_len;

	__u32 mcrt_busy : 1;
	__u32 txw_rtr2rts_flag : 1;
	__u32 wqe_resp_first_rd_flag : 1;
	__u32 wqe_resp_rd_ptr_out : 8;
	__u32 wqe_resp_rd_ptr_sel : 1;
	__u32 wqe_resp_rd_ptr_in : 9;
	__u32 txw_wqe_irrl_wptr : 8;
	__u32 wqe_psn_check_en : 1;
	__u32 wqe_nop_check_en : 1;
	__u32 wqe_read_fence_check_en : 1;

	__u32 resp_newest_psn : 24;
	__u32 wqe_local_fence_check_en : 1;
	__u32 txw_chx_st : 5;
	__u32 txw_resp_err : 1;
	__u32 wqe_proc_cnp_flag : 1;

	__u32 mcrt_wqe_idx : 16;
	__u32 txw_rate_bucket_low : 16;

	__u32 txw_nxt_wqe_psn : 24;
	__u32 txw_rate_bucket_high : 2;
	__u32 txw_nak_flag : 1;
	__u32 rsv20 : 5;

	__u32 txw_token_num : 24;
	__u32 txw_sq_retry_end_psn : 8;

	__u32 txw_rate_timestamp;

	__u32 txw_wqe_start_psn : 24;
	__u32 rsv22 : 8;
	__u32 txeng_qpc_rtr2rts_flag : 1;
	__u32 txeng_req_err_flag : 1;
	__u32 txeng_resp_err_flag : 1;
	__u32 rsv23 : 1;
	__u32 rsv24 : 1;
	__u32 txeng_flush_err_retry_flag : 1;
	__u32 txeng_flush_err_retry_wqe_idx : 16;
	__u32 txeng_wqe_start_flag : 1;
	__u32 rsv25 : 5;
	__u32 txeng_qp_state : 4;

	__u32 txeng_ok_req_ssn : 24;
	__u32 txeng_sq_err_syndrom : 8;

	__u32 txeng_tx2rx_retry_end_psn : 24;
	__u32 txeng_resp_err_psn_l : 4;
	__u32 txeng_resp_wait_nak_flag : 1;
	__u32 rsv26 : 1;
	__u32 txeng_syn_sch2rxi_retry_phase_tag : 1;
	__u32 txeng_sq_flush_flag : 1;

	__u32 txeng_send_req_next_ssn : 24;
	__u32 txeng_token_num_l : 8;

	__u32 txeng_npsn : 24;
	__u32 txeng_ssnt_tx_wr_totptr : 8;

	__u32 rsv27 : 1;
	__u32 txeng_irrl_tx_first_wr_flag : 1;
	__u32 txeng_irrl_tx_first_wr_sel : 1;
	__u32 txeng_irrl_tx_first_wr_inptr : 10;
	__u32 txeng_irrl_tx_wr_sel : 1;
	__u32 txeng_irrl_tx_wr_inptr : 10;
	__u32 txeng_irrl_tx_wr_outptr : 8;

	__u32 rsv28 : 2;
	__u32 txeng_ssnt_tx_first_wr_in_flag : 1;
	__u32 txeng_ssnt_tx_first_wr_inptr : 10;
	__u32 txeng_ssnt_tx_rd2wr_flag : 1;
	__u32 txeng_ssnt_tx_wr_inptr : 10;
	__u32 txeng_ssnt_tx_wr_outptr : 8;

	__u32 txeng_irrl_pa_0_31;

	__u32 txeng_irrl_pa_32_63;

	__u32 txeng_irrl_pa_64_95;

	__u32 txeng_irrl_pa_96_127;

	__u32 txeng_ssnt_pa_0_31;

	__u32 txeng_ssnt_pa_32_63;

	__u32 txeng_ssnt_pa_64_95;

	__u32 txeng_ssnt_pa_96_127;

	__u32 rsv29 : 12;
	__u32 txeng_resp_err_psn_h : 20;

	__u32 txeng_newest_ack_req_psn : 24;
	__u32 txeng_token_num_m : 8;

	__u32 txeng_newest_unack_psn : 24;
	__u32 txeng_token_num_h : 8;

	__u32 txeng_oldest_unack_psn : 24;
	__u32 rsv30 : 4;
	__u32 txeng_tmo_log_rtm : 4;

	__u32 txeng_tmo_stamp_h;
	__u32 rxi_newest_unack_psn : 24;
	__u32 rxi_qp_error_cqe_syndrome : 8;

	__u32 rxi_qp_state : 4;
	__u32 rxi_req_rnr_retry_flag : 1;
	__u32 rxi_resp_rnr_nak_tmr : 5;
	__u32 rxi_retring_flag : 1;
	__u32 rxi_retry_phase_tag : 1;
	__u32 rxi_ssnt_wqe_sge_ce : 1;
	__u32 rxi_ssnt_in_wr_ptr_from_rx : 10;
	__u32 rxi_ssnt_out_rd_ptr : 8;
	__u32 rxi_ssnt_ll_wqe_drop : 1;

	__u32 rxi_ssnt_wqe_data_length;

	__u32 rxi_ssnt_wqe_start_psn : 24;
	__u32 rxi_ssnt_rx_rd2wr_flag : 1;
	__u32 rxi_ssnt_rx_first_rd_flag : 1;
	__u32 rxi_ssnt_info_flag : 1;
	__u32 rxi_credit : 5;

	__u32 rxi_ssnt_unack_wqe_ssn : 24;
	__u32 rxi_ssnt_total_rd_ptr : 8;

	__u32 rxi_ssnt_wqe_wrid : 16;
	__u32 rxi_ssnt_in_rd_ptr : 10;
	__u32 rxi_ssnt_opcode : 6;

	__u32 rxi_resp_msn : 24;
	__u32 rxi_irrl_wr_outptr : 8;

	__u32 rxi_ack_time_stamp;

	__u32 rxi_ae_code : 12;
	__u32 rsv31 : 7;
	__u32 rxeng_dif_breack_point : 12;
	__u32 rx_dif_flag : 1;

	__u32 rxeng_dif_ref_tag;

	__u32 rxeng_dif_crc_seed : 16;
	__u32 rxeng_dif_check_speed : 16;
	__u32 rxt_qp_state : 4;
	__u32 rsv32 : 9;
	__u32 rxt_resp_pa_type : 1;
	__u32 rxt_newest_credit : 5;
	__u32 rx_cnp_flag : 1;
	__u32 rxt_resp_retry_wr_cnt : 8;
	__u32 rxt_ack_type : 2;
	__u32 rxt_nak_flag : 1;
	__u32 rxt_ack_retry_flag : 1;

	__u32 rxt_ack_syndrome : 8;
	__u32 rxt_ack_msn : 24;

	__u32 rxt_resp_paddr_96_127;

	__u32 rxt_resp_paddr_64_95;

	__u32 rxt_resp_paddr_32_63;

	__u32 rxt_resp_paddr_0_31;

	__u32 rxt_resp_rd_flag : 1;
	__u32 rxt_resp_boundary_done : 1;
	__u32 rxt_resp_first_wr_ptr_in : 9;
	__u32 rxt_resp_first_wr_ptr_sel : 1;
	__u32 rxt_resp_first_wr_flag : 1;
	__u32 rxt_resp_wr_ptr_in : 9;
	__u32 rxt_resp_wr_ptr_out : 8;
	__u32 rxt_resp_wr_ptr_sel : 1;
	__u32 rxt_resp_pa_vld : 1;

	__u32 rxt_resp_newest_psn : 24;
	__u32 rxt_resp_retry_start_ptr : 8;

	__u32 rxt_rmsm : 24;
	__u32 rxt_resp_retry_end_ptr : 8;

	__u32 rx_cnp_disp_timing;
	__u32 rpp_ini_irrl_rd_ptr_in : 10;
	__u32 rsv33 : 3;
	__u32 rpp_ini_irrl_rd_ptr_out : 8;
	__u32 rpp_ini_irrl_rd_ptr_sel : 1;
	__u32 rpp_ini_irrl_first_rd_flag : 1;
	__u32 rpp_ini_irrl_delete_en : 1;
	__u32 rpp_ini_irrl_delete_done : 1;
	__u32 rsv34 : 7;

	__u32 rpp_ini_irrl_sge_va_low;

	__u32 rpp_ini_irrl_sge_va_high;

	__u32 rpp_ini_irrl_sge_lkey;

	__u32 rpp_ini_irrl_sge_len;

	__u32 rpp_ini_irrl_sge_totallen;

	__u32 rsv35 : 8;
	__u32 rpp_ini_irrl_sge_spsn : 24;

	__u32 rpp_ini_irrl_sge_ssn : 24;
	__u32 rsv36 : 8;

	__u32 rpp_ini_rcv_messlen;

	__u32 rsv37 : 8;
	__u32 rpp_ini_unack_psn : 24;

	__u32 rsv38 : 4;
	__u32 rpp_ini_irrl_info_flag : 1;
	__u32 rpp_ini_qpsts_err_flag : 1;
	__u32 rpp_ini_read_retry_flag : 1;
	__u32 rpp_ini_write_retry_flag : 1;
	__u32 rpp_ini_cur_ssn : 24;

	__u32 rpp_tgt_sge_va_low;

	__u32 rpp_tgt_sge_va_high;

	__u32 rpp_tgt_sge_key;

	__u32 rpp_tgt_sge_len : 31;
	__u32 rpp_wqe_err : 1;

	__u32 rpp_tgt_read_ots_ptr : 8;
	__u32 rpp_tgt_rnr_flag : 1;
	__u32 rpp_tgt_nak_flag : 1;
	__u32 rpp_tgt_rtr_aeq_flag : 1;
	__u32 rsv39 : 13;
	__u32 rpp_tgt_sge_num : 5;
	__u32 rpp_tgt_page_pa_sel : 1;
	__u32 rpp_tgt_page_pa_vld : 2;

	__u32 rpp_tgt_page_pa_1_low;

	__u32 rpp_tgt_page_pa_1_high;

	__u32 rpp_tgt_rq_ud_len_err : 1;
	__u32 rpp_tgt_page_pa_l : 31;

	__u32 rpp_tgt_page_pa_h;

	__u32 rpp_tgt_qp_error : 1;
	__u32 rpp_wqe_vld : 1;
	__u32 rsv40 : 1;
	__u32 rpp_tgt_bth_opcode : 5;
	__u32 rpp_tgt_epsn : 24;

	__u32 rpp_tgt_rcv_messlen;

	__u32 rpp_tgt_sw_counter : 16;
	__u32 rpp_tgt_hw_counter : 16;

	__u32 rpp_ini_pkt_psn : 24;
	__u32 rsv41 : 8;

	__u32 rsv42;
	__u32 pf_id : 3;
	__u32 vf_relative_id : 5;
	__u32 vf_id : 8;
	__u32 vf_valid : 1;
	__u32 rsv43 : 5;
	__u32 sqpn_8_17 : 10;

	__u32 hw_cqn_snd : 19;
	__u32 rsv44 : 5;
	__u32 sqpn_0_7 : 8;

	__u32 hw_cqn_rcv : 19;
	__u32 rsv45 : 13;

	__u32 hw_srqn : 18;
	__u32 sw_cc_enable : 2;
	__u32 sw_cc_index : 12;
};

#define SXE2_RCMS_MAX_FPT_COUNT 4096
#define SXE2_RCMS_SPT_ENTRY_CNT 512

enum sxe2_rcms_fpt_entry_type {
	SXE2_RCMS_FPT_TYPE_FIRST  = 1,
	SXE2_RCMS_FPT_TYPE_SECOND = 2,
};

enum sxe2_rcms_rsrc_type {
	SXE2_RCMS_OBJ_QP	  = 0,
	SXE2_RCMS_OBJ_CQ	  = 1,
	SXE2_RCMS_OBJ_SRQ	  = 2,
	SXE2_RCMS_OBJ_MR	  = 3,
	SXE2_RCMS_OBJ_RESP	  = 4,
	SXE2_RCMS_OBJ_IRRL	  = 5,
	SXE2_RCMS_OBJ_SSNT	  = 6,
	SXE2_RCMS_OBJ_AH	  = 7,
	SXE2_RCMS_OBJ_ACK_TIMEOUT = 8,
	SXE2_RCMS_OBJ_PBLE	  = 9,
	SXE2_RCMS_OBJ_MAX,
};

struct sxe2_rcms_obj_info {
	u64 base;
	u32 max_cnt;
	u32 cnt;
	u32 size;
};

#pragma pack(1)
struct sxe2_rcms_query_fpm_value_wqe {
	u64 rsv0;
	u64 rsv1;
	u64 rcms_function_id : 6;
	u64 rsv2 : 58;
	u64 rsv4 : 32;
	u64 op : 6;
	u64 rsv5 : 4;
	u64 rsv6 : 21;
	u64 wqe_valid : 1;
	u64 rsv7 : 2;
	u64 query_buf_pa : 62;
	u64 rsv8;
	u64 rsv9;
	u64 rsv10;
};
#pragma pack(0)

#pragma pack(1)
struct sxe2_rcms_commit_fpm_value_wqe {
	u64 rsv0;
	u64 rsv1;
	u64 rcms_function_id : 6;
	u64 rsv2 : 58;
	u64 rsv3 : 32;
	u64 op : 6;
	u64 rsv4 : 4;
	u64 rsv5 : 21;
	u64 wqe_valid : 1;
	u64 rsv6 : 2;
	u64 commit_buf_pa : 62;
	u32 rsv7;
	u32 rsv8;
	u32 rsv9;
};
#pragma pack(0)

#pragma pack(1)
struct sxe2_rcms_manage_vf_pble_cp_wqe {
	u64 rsv0;
	u64 rsv1;
	u64 spte_cnt : 10;
	u64 rsv2 : 6;
	u64 first_spte_idx : 9;
	u64 rsv3 : 7;
	u64 fpte_idx : 13;
	u64 rsv4 : 19;
	u64 rsv5 : 32;
	u64 op : 6;
	u64 rsv6 : 4;
	u64 rsv7 : 20;
	u64 invalidate_spte : 1;
	u64 wqe_valid : 1;
	u64 rsv8 : 3;
	u64 spt_pagelist_buf_pa : 61;
	u64 rsv9;
	u64 rsv10;
	u64 rsv11;
};
#pragma pack(0)

#pragma pack(1)
struct qp_mq_wqe {
	__u64 modify_qp_type : 1;
	__u64 modify_qp_state : 1;
	__u64 rsvd0 : 29;
	__u64 modify_qp_mode : 1;
	__u64 rsvd1 : 32;

	__u64 rsvd2 : 32;
	__u64 rsvd3 : 32;

	__u64 qp_context_address;

	__u64 qpn : 18;
	__u64 rsvd4 : 14;
	__u64 op : 6;
	__u64 rsvd5 : 10;
	__u64 qp_type : 3;
	__u64 rsvd6 : 2;
	__u64 sw_cc_enable : 2;
	__u64 rsvd7 : 5;
	__u64 next_rdma_state : 3;
	__u64 wqe_valid : 1;

	__u64 rsvd8 : 32;
	__u64 rsvd9 : 32;

	__u64 rsvd10 : 32;
	__u64 rsvd11 : 32;

	__u64 rsvd12 : 32;
	__u64 rsvd13 : 32;

	__u64 rsvd14 : 32;
	__u64 rsvd15 : 32;
};
#pragma pack(0)

#pragma pack(1)
struct qp_mq_create_cc_qp_wqe {
	u64 timely_min_rtt_h : 12;
	u64 timely_alpha : 20;
	u64 timely_thigh_h : 12;
	u64 timely_tlow : 16;
	u64 timely_min_rtt_l : 4;
	u64 timely_pre_rtt_h : 8;
	u64 timely_beta : 20;
	u64 timely_thigh_l : 4;
	u64 rsv0 : 8;
	u64 timely_rtt_diff : 16;
	u64 timely_pre_rtt_l : 8;
	u64 qp_context_address;
	u64 qp_id : 18;
	u64 dcqcn_b_l : 14;
	u64 op : 6;
	u64 rsv1 : 1;
	u64 dcqcn_b_h : 11;
	u64 dcqcn_bc : 3;
	u64 sw_cc_enable : 2;
	u64 rsv2 : 8;
	u64 wqe_valid : 1;
	u64 dcqcn_t_interval_h : 12;
	u64 dcqcn_g : 20;
	u64 dcqcn_rhai_h : 8;
	u64 dcqcn_rai : 16;
	u64 dcqcn_f : 4;
	u64 dcqcn_t_interval_l : 4;
	u64 dcqcn_rreduce_mperiod_h : 8;
	u64 dcqcn_k : 16;
	u64 dcqcn_rhai_l : 8;
	u64 dcqcn_min_dec_factor : 8;
	u64 dcqcn_rreduce_next_node_info : 16;
	u64 dcqcn_rreduce_mperiod_l : 8;
	u64 dcqcn_rc_h : 4;
	u64 dcqcn_alpha : 20;
	u64 dcqcn_min_rate : 8;
	u64 dcqcn_rt_h : 16;
	u64 dcqcn_rc_l : 16;
	u64 dcqcn_func_id : 12;
	u64 dcqcn_t_next_node_info : 16;
	u64 dcqcn_rt_l : 4;
	u64 dcqcn_t_counter : 3;
	u64 dcqcn_byte_counter : 25;
	u64 dcqcn_decrease_rate_valid : 4;
};
#pragma pack(0)

#pragma pack(1)
struct sxe2_rcms_update_fpte_wqe {
	u64 fpte_cmd_0 : 32;
	u64 rsv0 : 32;
	u64 fpte_data_0;
	u64 rcms_fcn_id : 6;
	u64 rsv1 : 1;
	u64 fpt_buffer_address : 57;
	u64 fpt_entry_cnt : 6;
	u64 rsv2 : 1;
	u64 skip_fpt_entry_0 : 1;
	u64 rsv3 : 24;
	u64 op : 6;
	u64 rsv4 : 4;
	u64 rsv5 : 21;
	u64 wqe_valid : 1;
	u64 fpte_cmd_1 : 32;
	u64 rsv6 : 31;
	u64 fpt_entry_valid_1 : 1;
	u64 fpte_data_1;
	u64 fpte_cmd_2 : 32;
	u64 rsv7 : 31;
	u64 fpt_entry_valid_2 : 1;
	u64 fpte_data_2;
};
#pragma pack(0)

#define SXE2_SQ_RSVD 8
#define SXE2_RQ_RSVD 8

enum sxe2_mr_caps_const {
	SXE2_MAX_MR_SIZE	      = 0xffffffffffffffff,
};

enum sxe2_device_caps_const {
	SXE2_WQE_SIZE		      = 4,
	SXE2_MQ_WQE_SIZE	      = 8,
	SXE2_CQE_SIZE		      = 8,
	SXE2_EXTENDED_CQE_SIZE	      = 8,
	SXE2_AEQE_SIZE		      = 2,
	SXE2_CEQE_SIZE		      = 1,
	SXE2_MQ_CTX_SIZE	      = 8,
	SXE2_SHADOW_AREA_SIZE	      = 8,
	SXE2_GATHER_STATS_BUF_SIZE    = 900,
	SXE2_GATHER_STATS_BUF_VF_SIZE = 144,
	SXE2_MIN_IW_QP_ID	      = 0,
	SXE2_MIN_IW_SRQ_ID	      = 0,
	SXE2_QUERY_FPM_BUF_SIZE	      = 96,
	SXE2_COMMIT_FPM_BUF_SIZE      = 96,
	SXE2_MAX_IW_QP_ID	      = 262143,
	SXE2_MIN_CEQID		      = 0,
	SXE2_MAX_CEQID		      = 1023,
	SXE2_RDMA_CEQ_MAX_COUNT	      = SXE2_MAX_CEQID + 1,
	SXE2_MIN_CQID		      = 0,
	SXE2_MAX_CQID		      = 524287,
	SXE2_MIN_AEQ_ENTRIES	      = 4,
	SXE2_MAX_AEQ_ENTRIES	      = 262144,
	SXE2_MIN_CEQ_ENTRIES	      = 4,
	SXE2_MAX_CEQ_ENTRIES	      = 262144,
	SXE2_MIN_CQ_SIZE	      = 4,
	SXE2_MAX_CQ_SIZE	      = 2097152,
	SXE2_DB_ID_ZERO		      = 0,
	SXE2_MAX_PE_ENA_VF_COUNT      = 32,
	SXE2_MAX_VF_FPM_ID	      = 39,
	SXE2_MAX_SQ_PAYLOAD_SIZE      = 2145386496,
	SXE2_MAX_INLINE_DATA_SIZE     = 225,
	SXE2_MAX_WQ_ENTRIES	      = 32768,
	SXE2_MAX_OUTBOUND_MSG_SIZE    = 2147483647,
	SXE2_MAX_INBOUND_MSG_SIZE     = 2147483647,
	SXE2_Q2_BUF_SIZE	      = 256,
	SXE2_MAX_PDS		      = 262144,
	SXE2_QP_SW_MAX_WQ_QUANTA      = 32768,
	SXE2_QP_SW_MAX_SQ_QUANTA      = 32768,
	SXE2_QP_SW_MAX_RQ_QUANTA      = 32768,
	SXE2_SRQ_SW_MAX_SRQ_QUANTA = 65536,
	SXE2_MAX_SRQ_WRS = (SXE2_QP_SW_MAX_RQ_QUANTA - SXE2_RQ_RSVD),
	SXE2_DONE_COUNT		   = 100000,
	SXE2_SLEEP_COUNT	   = 10,
	SXE2_MQ_COMPL_WAIT_TIME_MS = 10,
	SXE2_MAX_PUSH_PAGE_COUNT   = 256,
	SXE2_MAX_WQ_FRAGMENT_COUNT = 13,
	SXE2_MAX_SGE_RD		   = 13,
	SXE2_MAX_RRA_SIZE = 64,
	SXE2_MAX_SRA_SIZE = 64,
	SXE2_MIN_WQ_SIZE       = 8,
	SXE2_MAX_QUANTA_PER_WR = 8,
	SXE2_MAX_BAR_REGS	       = 30,
	SXE2_VF_MAX_QSET_CNT	       = 8,
	SXE2_PF_MAX_QSET_CNT	       = 16,
	SXE2_PF_MAX_QSET_CNT_NO_LAG_AA = 8,
	SXE2_RDMA_DEFAULT_MAX_PUSH_LEN = 8192,
	SXE2_VCHNL_MAX_MSG_SIZE = 1024,
	SXE2_HCA_CORE_CLOCK_KHZ = 1000000UL,
};

#define SXE2_ACCESS_FLAGS_LOCALREAD   0x01
#define SXE2_ACCESS_FLAGS_LOCALWRITE  0x02
#define SXE2_ACCESS_FLAGS_REMOTEREAD  0x04
#define SXE2_ACCESS_FLAGS_REMOTEWRITE 0x08
#define SXE2_ACCESS_FLAGS_BIND_WINDOW 0x10
#define SXE2_ACCESS_FLAGS_ZERO_BASED  0x20

#define SXE2_MR_ACCESS_MODE_PA 0
#define SXE2_MR_ACCESS_MODE_VA 1

enum sxe2_pbl_mr_mode {
	MR_TABLE_FIRST_MODE  = 1,
	MR_TABLE_SECOND_MODE = 2,
	MR_TABLE_THIRD_MODE  = 3,
};

enum sxe2_pbl_cq_eq_mode {
	CQ_EQ_PA_FIRST_MODE	= 0,
	CQ_EQ_PA_SECOND_MODE	= 1,
	CQ_EQ_TABLE_SECOND_MODE = 2,
	CQ_EQ_TABLE_THIRD_MODE	= 3,
};

union sxe2_reg_mr_info {
	struct {
		u64 rsv1 : 7;
		u64 rsv2 : 1;
		u64 pbl_mode : 2;
		u64 access_right : 5;
		u64 va_based_flag : 1;
		u64 rsv3 : 1;
		u64 rsv4 : 7;
		u64 access_mode : 5;
		u64 mr_type : 1;
		u64 rsv5 : 1;
		u64 rsv6 : 1;
		u64 mr_key : 8;
		u64 rsv7 : 18;
		u64 rsv8 : 6;
		u64 ref_tag : 32;
		u64 pd : 18;
		u64 is_len64 : 1;
		u64 rsv12 : 13;
		u64 start_addr;
		u64 mr_idx : 22;
		u64 rsv14 : 10;
		u64 op : 6;
		u64 rsv15 : 25;
		u64 wqe_valid : 1;
		u64 rsv16;
		u64 len;
		u64 pbl_index;
		u64 log_entity_size : 5;
		u64 rsv17 : 27;
		u64 rsv18 : 32;
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

union sxe2_dereg_mr_info {
	struct {
		u64 rsv1;
		u64 rsv2 : 24;
		u64 rsv3 : 8;
		u64 pd : 18;
		u64 rsv4 : 1;
		u64 rsv5 : 1;
		u64 rsv6 : 12;
		u64 rsv7;
		u64 mr_idx : 22;
		u64 rsv8 : 10;
		u64 op : 6;
		u64 rsv9 : 25;
		u64 wqe_valid : 1;
		u64 rsv10;
		u64 rsv11;
		u64 rsv12;
		u64 rsv13;
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

union sxe2_query_mr_info {
	struct {
		u64 rsv1;
		u64 rsv2;
		u64 buf_addr;
		u64 mr_index : 22;
		u64 rsv3 : 10;
		u64 op : 6;
		u64 rsv4 : 25;
		u64 wqe_valid : 1;
		u64 rsv5;
		u64 rsv6;
		u64 rsv7;
		u64 rsv8;
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

union sxe2_hw_mrc {
	struct {
		u64 rsv1 : 8;
		u64 pbl_mode : 2;
		u64 access_rights : 5;
		u64 va_based_flag : 1;
		u64 mw_type : 1;
		u64 rsv2 : 7;
		u64 access_mode : 5;
		u64 mrct_type : 1;
		u64 free : 1;
		u64 rsv3 : 1;
		u64 mr_key : 8;
		u64 qpn : 18;
		u64 rsv4 : 6;
		u64 mw_bind_num : 24;
		u64 rsv5 : 8;
		u64 pd : 18;
		u64 is_len64 : 1;
		u64 rsv7 : 13;
		u64 start_addr;
		u64 len;
		u64 parent_mr_stag : 32;
		u64 ref_tag : 32;
		u64 dif_pbl_index : 33;
		u64 rsv9 : 1;
		u64 dif_offset : 30;
		u64 pbl_index : 34;
		u64 data_offset : 30;
		u64 log_entity_size : 5;
		u64 pfvf_id : 12;
		u64 rsv11 : 15;
		u64 app_tag : 16;
		u64 dif_mode : 4;
		u64 block_size : 1;
		u64 rsv6 : 1;
		u64 sge_type : 1;
		u64 rsv12 : 9;
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

#define SXE2_RDMA_DB_EQ_INFO_OFFSET (4)
#define SXE2_RDMA_DB_CQ_ARM_OFFSET  (8)
#define SXE2_RDMA_DB_CQ_INFO_OFFSET (12)

#define SXE2_QP_TYPE_ROCE_RC 3
#define SXE2_QP_TYPE_ROCE_UD 4

enum sxe2_major_opcode {
	SXE2_SUCCESS	     = 0,
	SXE2_LOCAL_LEN_ERR   = 0x1,
	SXE2_LOCAL_QP_OP_ERR = 0x2,
	SXE2_RSV1_ERR,
	SXE2_LOCAL_PROTECTION_ERR	= 0x4,
	SXE2_WR_FLUSH_ERR		= 0x5,
	SXE2_MW_BIND_ERR		= 0x6,
	SXE2_FAST_REGISTER_ERR		= 0x7,
	SXE2_INVALID_KEY_ERR		= 0x8,
	SXE2_BAD_RESPONSE_ERR		= 0x10,
	SXE2_LOCAL_ACCESS_ERR		= 0x11,
	SXE2_REMOTE_INVALID_REQUEST_ERR = 0x12,
	SXE2_REMOTE_ACCESS_ERR		= 0x13,
	SXE2_REMOTE_OPERATION_ERR	= 0x14,
	SXE2_TRANS_RETRY_CNT_EXCEED_ERR = 0x15,
	SXE2_RNR_RETRY_CNT_EXCEED_ERR	= 0x16,
	SXE2_ABORT_ERR			= 0x22,
	SXE2_DIF_CHECK_ERR		= 0x23,
	SXE2_SQ_FAKE_ERR		= 0x24,
};

#pragma pack(1)
struct drv_rdma_soft_eqc {
	u64 oi : 1;
	u64 vsi_index : 10;
	u64 rsv1 : 16;
	u64 sw_owner_bit : 1;
	u64 sw_status : 4;
	u64 uar_page : 24;
	u64 log_eq_size : 5;
	u64 pbl_mode : 2;
	u64 rsv2 : 1;

	u64 rsv3 : 12;
	u64 TPH_en : 1;
	u64 TPH_value : 8;
	u64 rsv4 : 11;
	u64 rsv5 : 11;
	u64 page_offset : 13;
	u64 log_page_size : 5;
	u64 rsv6 : 3;

	u64 pbl_index;

	u32 rsv7;
};

struct drv_rdma_hw_eqc {
	u32 hw_owner_bit : 1;
	u32 over_flag : 1;
	u32 rsv1 : 6;
	u32 hw_status : 1;
	u32 pfvf_id : 12;
	u32 rsv2 : 11;

	u32 rsv3;
	u32 rsv4;

	u32 consumer_counter : 24;
	u32 rsv5 : 8;

	u32 producer_counter : 24;
	u32 rsv6 : 8;

	u32 page_addr_odd_l;
	u32 page_addr_odd_h;

	u32 page_addr_even_l;
	u32 page_addr_even_h;
};

struct sxe2_rdma_eqc {
	struct drv_rdma_soft_eqc seqc;
	struct drv_rdma_hw_eqc heqc;
};
#pragma pack(0)

#define SXE2_AE_AMP_UNALLOCATED_STAG		       0x0102
#define SXE2_AE_AMP_INVALID_STAG		       0x0103
#define SXE2_AE_AMP_BAD_QP			       0x0104
#define SXE2_AE_AMP_BAD_PD			       0x0105
#define SXE2_AE_AMP_BAD_STAG_KEY		       0x0106
#define SXE2_AE_AMP_BAD_STAG_INDEX		       0x0107
#define SXE2_AE_AMP_BOUNDS_VIOLATION		       0x0108
#define SXE2_AE_AMP_RIGHTS_VIOLATION		       0x0109
#define SXE2_AE_AMP_FASTREG_VALID_STAG		       0x010c
#define SXE2_AE_AMP_FASTREG_MW_STAG		       0x010d
#define SXE2_AE_AMP_FASTREG_INVALID_RIGHTS	       0x010e
#define SXE2_AE_AMP_FASTREG_INVALID_LENGTH	       0x0110
#define SXE2_AE_AMP_REMOTE_INVALIDATE_MR_RD_ERR	       0x0111
#define SXE2_AE_AMP_INVALIDATE_NO_REMOTE_ACCESS_RIGHTS 0x0112
#define SXE2_AE_AMP_INVALIDATE_MR_WITH_BOUND_WINDOWS   0x0113
#define SXE2_AE_AMP_MWBIND_VALID_STAG		       0x0114
#define SXE2_AE_AMP_MWBIND_OF_MR_STAG		       0x0115
#define SXE2_AE_AMP_MWBIND_TO_ZERO_BASED_STAG	       0x0116
#define SXE2_AE_AMP_MWBIND_TO_MW_STAG		       0x0117
#define SXE2_AE_AMP_MWBIND_INVALID_RIGHTS	       0x0118
#define SXE2_AE_AMP_MWBIND_INVALID_BOUNDS	       0x0119
#define SXE2_AE_AMP_MWBIND_TO_INVALID_PARENT	       0x011a
#define SXE2_AE_AMP_MWBIND_BIND_DISABLED	       0x011b
#define SXE2_AE_AMP_INVALIDATE_TYPE1_MW		       0x011d
#define SXE2_AE_AMP_MWBIND_ZERO_BASED_TYPE1_MW	       0x011e
#define SXE2_AE_AMP_MWBIND_WRONG_TYPE		       0x0120
#define SXE2_AE_AMP_FASTREG_PBLE_MISMATCH	       0x0121
#define SXE2_AE_CQ_OPERATION_ERROR		       0x0203
#define SXE2_AE_LLP_TOO_MANY_RETRIES		       0x050a
#define SXE2_AE_QP_SUSPEND_COMPLETE		       0x0900

#define SXE2_AE_LLWQE_ERR	     0x0a00
#define SXE2_AE_DOORBELL_ERR	     0x0a01
#define SXE2_AE_LLWQE_8B_INVALID     0x0a02
#define SXE2_AE_DOORBELL_QSET_ERR    0x0a06
#define SXE2_AE_DOORBELL_QPN_ERR     0x0a08
#define SXE2_AE_DOORBELL_EQN_ERR     0x0a09
#define SXE2_AE_DOORBELL_CQN_ERR     0x0a0a
#define SXE2_AE_DOORBELL_QPN_NUM_ERR 0x0a0b

#define SXE2_AE_WQE_LOAD_QPC_PBL_ERR 0x0b00
#define SXE2_AE_WQE_LOAD_QPC_DMA_ERR 0x0b01
#define SXE2_AE_WQE_QPC_CFG_ERR	     0x0b03
#define SXE2_AE_WQE_RD_DMA_ERR	     0x0b04
#define SXE2_AE_WQE_CFG_ERR	     0x0b05
#define SXE2_AE_WQE_OPCODE_ERR	     0x0b06
#define SXE2_AE_WQE_LENGTH_ERR	     0x0b07
#define SXE2_AE_WQE_LLWQE_ERR	     0x0b08
#define SXE2_AE_WQE_RD_RESP_DMA_ERR  0x0b09
#define SXE2_AE_WQE_RD_AH_ERR	     0x0b0a
#define SXE2_AE_WQE_AH_CFG_ERR	     0x0b0b

#define SXE2_AE_WQE_PBL_DMA_ERR 0x0b0c

#define SXE2_AE_RXENG_RXT_OPCODE_ERR		    0x0c01
#define SXE2_AE_RXENG_RXT_LENGTH_ERR		    0x0c02
#define SXE2_AE_RXENG_RXT_RDMA_READ_OUTSTANDING_ERR 0x0c03
#define SXE2_AE_RXENG_RXI_BAD_RESPONSE		    0x0c04
#define SXE2_AE_RXENG_RXI_LENGTH_ERR		    0x0c05
#define SXE2_AE_RXENG_RXI_IRRL_DMA_ERR		    0x0c06
#define SXE2_AE_RXENG_RXT_RESP_WR_PADDR_ERR	    0x0c07
#define SXE2_AE_RXENG_RXT_RESP_RD_DMA_ERR	    0x0c08
#define SXE2_AE_RXENG_RXI_SSNT_OVERSIZE_ERR	    0x0c09
#define SXE2_AE_RXENG_RXI_SSNT_DMA_ERR		    0x0c0a
#define SXE2_AE_RXENG_RXT_RQE_LIMIT		    0x0c0b
#define SXE2_AE_RXENG_RX_LOAD_QPC_DMA_ERR	    0x0c0c
#define SXE2_AE_RXENG_RX_LOAD_QPC_PA_ERR	    0x0c0d
#define SXE2_AE_RXENG_RX_LOAD_SRQC_DMA_ERR	    0x0c0e
#define SXE2_AE_RXENG_RX_LOAD_SRQC_PA_ERR	    0x0c0f
#define SXE2_AE_RXENG_RQ_PI_DMA_ERR		    0x0c10
#define SXE2_AE_RXENG_RQ_ADDR_ERR		    0x0c11
#define SXE2_AE_RXENG_RQ_DMA_ERR		    0x0c12
#define SXE2_AE_RXENG_RQ_WQE_VLD_ERR		    0x0c13
#define SXE2_AE_RXENG_SRQC_STS_ERR		    0x0c14
#define SXE2_AE_RXENG_SRQC_STS_RSV		    0x0c15
#define SXE2_AE_RXENG_SRQ_LAST_WQE		    0x0c16
#define SXE2_AE_RXENG_DBR_VALUE_ERR		    0x0c17
#define SXE2_AE_RXENG_RTR_FIRST_PKT		    0x0c18

#define SXE2_AE_SRQC_LOAD_SRQC_DMA_ERR	   0x0c19
#define SXE2_AE_SRQC_LOAD_SRQC_PA_ERR	   0x0c1a
#define SXE2_AE_SRQC_STS_ERR		   0x0c1b
#define SXE2_AE_RXENG_REMOTE_INVALID_ERROR 0x0c1c
#define SXE2_AE_RXENG_REMOTE_ACCESS_ERROR  0x0c1d
#define SXE2_AE_RXENG_REMOTE_QP_ERROR	   0x0c1e
#define SXE2_AE_RXENG_RXI_WQE_MISMATCH	   0x0c1f

#define SXE2_AE_TXENG_PAYLOAD_RD_DMA_ERR      0x0d00
#define SXE2_AE_TXENG_RD_PKEY_ERR	      0x0d01
#define SXE2_AE_TXENG_RD_SSNT_PBL_ERR	      0x0d02
#define SXE2_AE_TXENG_RD_IRRL_PBL_ERR	      0x0d03
#define SXE2_AE_TXENG_RESP_PAYLOAD_RD_DMA_ERR 0x0d10

#define SXE2_AE_TMO_WR_PA_ERR  0x0f00
#define SXE2_AE_TMO_RD_PA_ERR  0x0f01
#define SXE2_AE_TMO_RD_DMA_ERR 0x0f02
#define SXE2_AE_TMO_RD_QPC_ERR 0x0f03
#define SXE2_AE_CC_QP_RATE     0x0f10
#define SXE2_AE_CEQ_OVERFLOW   0x0f11
#define SXE2_AE_EQ_STATUS_ERR  0x0f12
#define SXE2_AE_CQ_STATUS_ERR  0x0f13
#define SXE2_AE_QP_CQ_OVERFLOW 0x0f14

#define SXE2_AE_SOURCE_RSVD 0x0
#define SXE2_AE_SOURCE_RQ 0x1
#define SXE2_AE_SOURCE_CQ 0x2
#define SXE2_AE_SOURCE_SQ 0x5
#define SXE2_AE_SOURCE_SRQ 0x7
#define SXE2_AE_SOURCE_DB_PROC 0x9
#define SXE2_AE_SOURCE_TMO 0xa
#define SXE2_AE_SOURCE_CC 0xb

#pragma pack(1)
struct sxe2_eq_wqe {
	u64 oi : 1;
	u64 vsi_index : 10;
	u64 rsv1 : 16;
	u64 sw_owner_bit : 1;
	u64 sw_status : 4;
	u64 uar_page : 24;
	u64 log_eq_size : 5;
	u64 pbl_mode : 2;
	u64 rsv2 : 1;

	u64 rsv3 : 12;
	u64 TPH_en : 1;
	u64 TPH_value : 8;
	u64 rsv4 : 11;
	u64 rsv5 : 11;
	u64 page_offset : 13;
	u64 log_page_size : 5;
	u64 rsv6 : 3;

	u64 pbl_index;

	u64 rsv7 : 32;
	u64 op : 6;
	u64 eqn : 10;
	u64 pfvf_id : 12;
	u64 rsv8 : 3;
	u64 WQE_Valid : 1;

	u64 rsv9 : 8;
	u64 physical_buffer_address : 56;

	u64 rsv10;
	u64 rsv11;

	u64 rsv12;
};
#pragma pack(0)

struct drv_rdma_soft_srqc {
	u64 pd : 18;
	u64 rsv0 : 2;
	u64 log_srq_size : 4;
	u64 state : 8;
	u64 rsv1 : 25;
	u64 srq_access_mode : 1;
	u64 log_page_size : 5;
	u64 rsv2 : 1;
	u64 dbr_addr;
	u64 SRQ_Completion_Context;
	u64 srq_pbl_pointer;
	u64 lwm : 16;
	u64 rsv3 : 1;
	u64 log_rq_stride : 2;
	u64 page_offset : 13;
};

struct drv_rdma_hw_srqc {
	u64 state_err_aeq_flag : 1;
	u64 rsv4 : 31;
	u64 sw_srq_counter : 16;
	u64 hw_srq_counter : 16;
	u64 srq_page_pa_sel : 1;
	u64 srq_page_pa_vld : 2;
	u64 srq_wqe_vld : 1;
	u64 rsv5 : 28;
	u64 srq_page_pa0;
	u64 srq_page_pa1;
};

#pragma pack(1)
struct sxe2_rdma_srqc {
	struct drv_rdma_soft_srqc ssrqc;
	struct drv_rdma_hw_srqc hsrqc;
};
#pragma pack(0)

#pragma pack(1)
struct mq_wqe_of_srq {
	u64 pd : 18;
	u64 rsv0 : 2;
	u64 log_srq_size : 4;
	u64 state : 8;
	u64 rsv1 : 25;
	u64 srq_access_mode : 1;
	u64 log_page_size : 6;
	u64 dbr_addr;
	u64 SRQ_Completion_Context;
	u64 srqn : 18;
	u64 rsv2 : 14;
	u64 op : 6;
	u64 rsv3 : 25;
	u64 wqe_valid : 1;
	u64 rsv4 : 8;
	u64 Physical_Buffer_Address : 56;
	u64 srq_pbl_pointer;
	u64 lwm : 16;
	u64 rsv5 : 1;
	u64 log_rq_stride : 2;
	u64 page_offset : 13;
	u64 rsv6 : 32;
	u64 rsv7;
};
#pragma pack(0)

#endif
