// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_qp_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_qp_debugfs.h"

enum qpc_e {
	ACK_TIMEOUT = 0,
	RETRY_MODE,
	CREDIT_EN,
	COMM_EST,
	RQE_LWM,
	RETRY_RESP_OP_SEL,
	LOG_RTM,
	QP_STATE,
	DQPN,
	QP_TYPE,
	LLWQE_PAGE_INDEX,
	LLWQE_MODE_ENABLE,
	LOG_MSG_MAX,
	PMTU,
	QP_PAGE_OFFSET,
	LOG_RQ_SIZE,
	LOG_SQ_SIZE,
	CQN_SND,
	LOG_RQ_STRIDE,
	LOG_PAGE_SIZE,
	CQN_RCV,
	MIN_RNR_NAK,
	FL,
	SRQN,
	BUCKET_TYPE,
	STAT_RATE,
	RQ_TYPE,
	IPV4,
	PD,
	LOG_RRA_MAX,
	LOG_SRA_MAX,
	SEND_START_PSN,
	TMO_RETRY,
	UDPRIV_CQENABLE,
	RNR_RETRY,
	RCV_START_PSN,
	ACK_MODE,
	PKEY_INDEX,
	SQ_FLUSH_FLAG,
	RQ_FLUSH_FLAG,
	LOG_ACK_REQ_FREQ,
	HOP_LIMIT,
	Q_KEY,
	SMAC_LOW,
	SMAC_HIGH,
	SRC_PORT_NUM,
	RMAC_LOW,
	RMAC_HIGH,
	DEST_PORT_NUM,
	QP_CTX,
	SQ_TPH_VAL,
	RQ_TPH_VAL,
	SQ_TPH_EN,
	RQ_TPH_EN,
	XMIT_TPH_EN,
	RCV_TPH_EN,
	CNP_DSCP,
	CNP_ECN,
	FLOW_LABEL,
	DSCP,
	ECN,
	DEST_IP3,
	DEST_IP2,
	DEST_IP1,
	DEST_IP0,
	LOCAL_IP3,
	LOCAL_IP2,
	LOCAL_IP1,
	LOCAL_IP0,
	DBR_ADDR,
	PBL_POINTER,
	TPID_IDX,
	WQ_ACCESS_MODE,
	USE_STATS,
	STATS_INDEX,
	INSERT_VLAN_TAG,
	VLAN_TAG,
	SRC_VSI,
	DISPATCH_MIN_UNIT,
	DISPATCH_MODE,
};

#ifdef SXE2_CFG_DEBUG
static char *g_qp_fields[] = {
	[ACK_TIMEOUT]	    = "ack_timeout",
	[RETRY_MODE]	    = "retry_mode",
	[CREDIT_EN]	    = "credit_en",
	[COMM_EST]	    = "comm_est",
	[RQE_LWM]	    = "rqe_lwm",
	[QP_STATE]	    = "qp_state",
	[DQPN]		    = "dqpn",
	[QP_TYPE]	    = "qp_type",
	[LLWQE_PAGE_INDEX]  = "llwqe_page_index",
	[LLWQE_MODE_ENABLE] = "llwqe_mode_enable",
	[RETRY_RESP_OP_SEL] = "retry_resp_op_sel",
	[LOG_RTM]	    = "log_rtm",
	[LOG_MSG_MAX]	    = "log_msg_max",
	[PMTU]		    = "pmtu",
	[QP_PAGE_OFFSET]    = "page_offset",
	[LOG_RQ_SIZE]	    = "log_rq_size",
	[LOG_SQ_SIZE]	    = "log_sq_size",
	[CQN_SND]	    = "cqn_snd",
	[LOG_RQ_STRIDE]	    = "log_rq_stride",
	[LOG_PAGE_SIZE]	    = "log_page_size",
	[CQN_RCV]	    = "cqn_rcv",
	[MIN_RNR_NAK]	    = "min_rnr_nak",
	[FL]		    = "fl",
	[SRQN]		    = "srqn",
	[BUCKET_TYPE]	    = "bucket_type",
	[STAT_RATE]	    = "stat_rate",
	[RQ_TYPE]	    = "rq_type",
	[IPV4]		    = "ipv4",
	[PD]		    = "pd",
	[LOG_RRA_MAX]	    = "log_rra_max",
	[LOG_SRA_MAX]	    = "log_sra_max",
	[SEND_START_PSN]    = "send_start_psn",
	[TMO_RETRY]	    = "tmo_retry",
	[UDPRIV_CQENABLE]   = "udpriv_cqenable",
	[RNR_RETRY]	    = "rnr_retry",
	[RCV_START_PSN]	    = "rcv_start_psn",
	[ACK_MODE]	    = "ack_mode",
	[PKEY_INDEX]	    = "pkey_index",
	[SQ_FLUSH_FLAG]	    = "sq_flush_flag",
	[RQ_FLUSH_FLAG]	    = "rq_flush_flag",
	[LOG_ACK_REQ_FREQ]  = "log_ack_req_freq",
	[HOP_LIMIT]	    = "hop_limit",
	[Q_KEY]		    = "q_key",
	[SMAC_LOW]	    = "smac_low",
	[SMAC_HIGH]	    = "smac_high",
	[SRC_PORT_NUM]	    = "src_port_num",
	[RMAC_LOW]	    = "rmac_low",
	[RMAC_HIGH]	    = "rmac_high",
	[DEST_PORT_NUM]	    = "dest_port_num",
	[QP_CTX]	    = "qp_completion_context",
	[SQ_TPH_VAL]	    = "sq_tph_value",
	[RQ_TPH_VAL]	    = "rq_tph_value",
	[SQ_TPH_EN]	    = "sq_tph_en",
	[RQ_TPH_EN]	    = "rq_tph_en",
	[XMIT_TPH_EN]	    = "xmit_tph_en",
	[RCV_TPH_EN]	    = "rcv_tph_en",
	[CNP_DSCP]	    = "cnp_dscp",
	[CNP_ECN]	    = "cnp_ecn",
	[FLOW_LABEL]	    = "flow_label",
	[DSCP]		    = "dscp",
	[ECN]		    = "ecn",
	[DEST_IP3]	    = "dest_ip_addr_3",
	[DEST_IP2]	    = "dest_ip_addr_2",
	[DEST_IP1]	    = "dest_ip_addr_1",
	[DEST_IP0]	    = "dest_ip_addr_0",
	[LOCAL_IP3]	    = "local_ip_addr_3",
	[LOCAL_IP2]	    = "local_ip_addr_2",
	[LOCAL_IP1]	    = "local_ip_addr_1",
	[DBR_ADDR]	    = "dbr_addr",
	[PBL_POINTER]	    = "pbl_pointer",
	[TPID_IDX]	    = "tpid_index",
	[WQ_ACCESS_MODE]    = "wq_access_mode",
	[USE_STATS]	    = "use_statistics_instance",
	[STATS_INDEX]	    = "statistics_instance_index",
	[INSERT_VLAN_TAG]   = "insert_vlan_tag",
	[VLAN_TAG]	    = "vlan_tag",
	[SRC_VSI]	    = "src_vsi",
	[DISPATCH_MIN_UNIT] = "dispatch_min_unit",
	[DISPATCH_MODE]	    = "dispatch_mode",
};
#endif

void drv_rdma_qp_read_field_seg0(char *buf, size_t *len, struct sxe2_qpc *qpc)
{
	*len += dbg_vsnprintf(buf, *len, "SEG0(SW_CFG)\n");
	*len += dbg_vsnprintf(buf, *len,
			      "ack_timeout:			  %llu\n",
			      qpc->ack_timeout);
	*len += dbg_vsnprintf(buf, *len,
			      "retry_mode:			  %llu\n",
			      qpc->retry_mode);
	*len += dbg_vsnprintf(buf, *len,
			      "credit_en:			  %llu\n",
			      qpc->credit_en);
	*len += dbg_vsnprintf(buf, *len,
			      "comm_est:			  %llu\n",
			      qpc->comm_est);
	*len += dbg_vsnprintf(buf, *len,
			      "rqe_lwm:			  %llu\n",
			      qpc->rqe_lwm);
	*len += dbg_vsnprintf(buf, *len,
			      "qp_state:			  %llu\n",
			      qpc->qp_state);
	*len += dbg_vsnprintf(buf, *len, "dqpn:			  %llu\n",
			      qpc->dqpn);
	*len += dbg_vsnprintf(buf, *len,
			      "qp_type:			  %llu\n",
			      qpc->qp_type);
	*len += dbg_vsnprintf(buf, *len,
			      "llwqe_page_index:			  %llu\n",
			      qpc->llwqe_page_index);
	*len += dbg_vsnprintf(buf, *len,
			      "llwqe_mode_enable:			  %llu\n",
			      qpc->llwqe_mode_enable);
	*len += dbg_vsnprintf(buf, *len,
			      "retry_resp_op_sel:			  %llu\n",
			      qpc->retry_resp_op_sel);
	*len += dbg_vsnprintf(buf, *len,
			      "log_rtm:			  %llu\n",
			      qpc->log_rtm);
	*len += dbg_vsnprintf(buf, *len,
			      "log_msg_max:			  %llu\n",
			      qpc->log_msg_max);
	*len += dbg_vsnprintf(buf, *len, "pmtu:			  %llu\n",
			      qpc->pmtu);
	*len += dbg_vsnprintf(buf, *len,
			      "page_offset:			  %llu\n",
			      qpc->page_offset);
	*len += dbg_vsnprintf(buf, *len,
			      "log_rq_size:			  %llu\n",
			      qpc->log_rq_size);
	*len += dbg_vsnprintf(buf, *len,
			      "log_sq_size:			  %llu\n",
			      qpc->log_sq_size);
	*len += dbg_vsnprintf(buf, *len,
			      "cqn_snd:			  %llu\n",
			      qpc->cqn_snd);
	*len += dbg_vsnprintf(buf, *len,
			      "log_rq_stride:			  %llu\n",
			      qpc->log_rq_stride);
	*len += dbg_vsnprintf(buf, *len,
			      "log_page_size:			  %llu\n",
			      qpc->log_page_size);
	*len += dbg_vsnprintf(buf, *len,
			      "cqn_rcv:			  %llu\n",
			      qpc->cqn_rcv);
	*len += dbg_vsnprintf(buf, *len,
			      "min_rnr_nak:			  %llu\n",
			      qpc->min_rnr_nak);
	*len += dbg_vsnprintf(buf, *len, "fl:			  %llu\n",
			      qpc->fl);
	*len += dbg_vsnprintf(buf, *len, "srqn:			  %llu\n",
			      qpc->srqn);
	*len += dbg_vsnprintf(buf, *len,
			      "bucket_type:			  %llu\n",
			      qpc->bucket_type);
	*len += dbg_vsnprintf(buf, *len,
			      "stat_rate:			  %llu\n",
			      qpc->stat_rate);
	*len += dbg_vsnprintf(buf, *len,
			      "rq_type:			  %llu\n",
			      qpc->rq_type);
	*len += dbg_vsnprintf(buf, *len, "ipv4:			  %llu\n",
			      qpc->ipv4);
	*len += dbg_vsnprintf(buf, *len, "pd:			  %llu\n",
			      qpc->pd);
	*len += dbg_vsnprintf(buf, *len,
			      "log_rra_max:			  %llu\n",
			      qpc->log_rra_max);
	*len += dbg_vsnprintf(buf, *len,
			      "log_sra_max:			  %llu\n",
			      qpc->log_sra_max);
	*len += dbg_vsnprintf(buf, *len,
			      "send_start_psn:			  %llu\n",
			      qpc->send_start_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "tmo_retry:			  %llu\n",
			      qpc->tmo_retry);
	*len += dbg_vsnprintf(buf, *len,
			      "udpriv_cqenable:			  %llu\n",
			      qpc->udpriv_cqenable);
	*len += dbg_vsnprintf(buf, *len,
			      "rnr_retry:			  %llu\n",
			      qpc->rnr_retry);
	*len += dbg_vsnprintf(buf, *len,
			      "rcv_start_psn:			  %llu\n",
			      qpc->rcv_start_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "ack_mode:			  %llu\n",
			      qpc->ack_mode);
	*len += dbg_vsnprintf(buf, *len,
			      "pkey_index:			  %llu\n",
			      qpc->pkey_index);
	*len += dbg_vsnprintf(buf, *len,
			      "rq_flush_flag:			  %llu\n",
			      qpc->rq_flush_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "sq_flush_flag:			  %llu\n",
			      qpc->sq_flush_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "log_ack_req_freq:			  %llu\n",
			      qpc->log_ack_req_freq);
	*len += dbg_vsnprintf(buf, *len,
			      "hop_limit:			  %llu\n",
			      qpc->hop_limit);
	*len += dbg_vsnprintf(buf, *len,
			      "q_key:			  %llu\n",
			      qpc->q_key);
	*len += dbg_vsnprintf(buf, *len,
			      "smac_low:			  %llu\n",
			      qpc->smac_low);
	*len += dbg_vsnprintf(buf, *len,
			      "smac_high:			  %llu\n",
			      qpc->smac_high);
	*len += dbg_vsnprintf(buf, *len,
			      "src_port_num:			  %llu\n",
			      qpc->src_port_num);
	*len += dbg_vsnprintf(buf, *len,
			      "rmac_low:			  %llu\n",
			      qpc->rmac_low);
	*len += dbg_vsnprintf(buf, *len,
			      "rmac_high:			  %llu\n",
			      qpc->rmac_high);
	*len += dbg_vsnprintf(buf, *len,
			      "dest_port_num:			  %llu\n",
			      qpc->dest_port_num);
}

void drv_rdma_qp_read_field_seg1(char *buf, size_t *len, struct sxe2_qpc *qpc)
{
	*len += dbg_vsnprintf(buf, *len, "SEG1(SW_CFG)\n");
	*len += dbg_vsnprintf(
		buf, *len,
		"qp_completion_context:			  %llu\n",
		qpc->qp_completion_contex);
	*len += dbg_vsnprintf(buf, *len,
			      "sq_tph_value:			  %llu\n",
			      qpc->sq_tph_value);
	*len += dbg_vsnprintf(buf, *len,
			      "rq_tph_value:			  %llu\n",
			      qpc->rq_tph_value);
	*len += dbg_vsnprintf(buf, *len,
			      "sq_tph_en:			  %llu\n",
			      qpc->sq_tph_en);
	*len += dbg_vsnprintf(buf, *len,
			      "rq_tph_en:			  %llu\n",
			      qpc->rq_tph_en);
	*len += dbg_vsnprintf(buf, *len,
			      "xmit_tph_en:			  %llu\n",
			      qpc->xmit_tph_en);
	*len += dbg_vsnprintf(buf, *len,
			      "rcv_tph_en:			  %llu\n",
			      qpc->rcv_tph_en);
	*len += dbg_vsnprintf(buf, *len,
			      "cnp_dscp:			  %llu\n",
			      qpc->cnp_dscp);
	*len += dbg_vsnprintf(buf, *len,
			      "cnp_ecn:			  %llu\n",
			      qpc->cnp_ecn);
	*len += dbg_vsnprintf(buf, *len,
			      "flow_label:			  %llu\n",
			      qpc->flow_label);
	*len += dbg_vsnprintf(buf, *len, "dscp:			  %llu\n",
			      qpc->dscp);
	*len += dbg_vsnprintf(buf, *len, "ecn:			  %llu\n",
			      qpc->ecn);
	*len += dbg_vsnprintf(buf, *len,
			      "dest_ip_addr_3:			  %llu\n",
			      qpc->dest_ipaddr3);
	*len += dbg_vsnprintf(buf, *len,
			      "dest_ip_addr_2:			  %llu\n",
			      qpc->dest_ipaddr2);
	*len += dbg_vsnprintf(buf, *len,
			      "dest_ip_addr_1:			  %llu\n",
			      qpc->dest_ipaddr1);
	*len += dbg_vsnprintf(buf, *len,
			      "dest_ip_addr_0:			  %llu\n",
			      qpc->dest_ipaddr0);
	*len += dbg_vsnprintf(buf, *len,
			      "local_ip_addr_3:			  %llu\n",
			      qpc->local_ipaddr_3);
	*len += dbg_vsnprintf(buf, *len,
			      "local_ip_addr_2:			  %llu\n",
			      qpc->local_ipaddr_2);
	*len += dbg_vsnprintf(buf, *len,
			      "local_ip_addr_1:			  %llu\n",
			      qpc->local_ipaddr_1);
	*len += dbg_vsnprintf(buf, *len,
			      "local_ip_addr_0:			  %llu\n",
			      qpc->local_ipaddr_0);
	*len += dbg_vsnprintf(buf, *len,
			      "dbr_addr:			  %llu\n",
			      qpc->dbr_addr);
	*len += dbg_vsnprintf(buf, *len,
			      "pbl_pointer:			  %llu\n",
			      qpc->pbl_pointer);
	*len += dbg_vsnprintf(buf, *len,
			      "tpid_index:			  %llu\n",
			      qpc->tpid_index);
	*len += dbg_vsnprintf(buf, *len,
			      "wq_access_mode:			  %llu\n",
			      qpc->wq_acces_mode);
	*len += dbg_vsnprintf(
		buf, *len,
		"use_statistics_instance:			  %llu\n",
		qpc->use_statistics_intance);
	*len += dbg_vsnprintf(
		buf, *len,
		"statistics_instance_index:			  %llu\n",
		qpc->statistics_instance_index);
	*len += dbg_vsnprintf(buf, *len,
			      "insert_vlan_tag:			  %llu\n",
			      qpc->insert_vlan_tag);
	*len += dbg_vsnprintf(buf, *len,
			      "vlan_tag:			  %llu\n",
			      qpc->vlan_tag);
	*len += dbg_vsnprintf(buf, *len,
			      "src_vsi:			  %llu\n",
			      qpc->src_vsi);
	*len += dbg_vsnprintf(buf, *len,
			      "dispatch_min_unit:			  %llu\n",
			      qpc->dispatch_min_unit);
	*len += dbg_vsnprintf(buf, *len,
			      "dispatch_mode:			  %llu\n",
			      qpc->dispatch_mode);
}

void drv_rdma_qp_read_field_seg2(char *buf, size_t *len, struct sxe2_qpc *qpc)
{
	*len += dbg_vsnprintf(buf, *len, "SEG2(WQE_PROC)\n");
	*len += dbg_vsnprintf(buf, *len,
			      "hw_sq_wqebb_counter:			  %llu\n",
			      qpc->hw_sq_wqebb_counter);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_sq_retry_end_ptr:			  %llu\n",
			      qpc->txw_sq_retry_end_ptr);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_sq_retry_end_psn:			  %llu\n",
			      qpc->txw_sq_retry_end_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_page_pa1_low:			  %llu\n",
			      qpc->wqe_page_pa1_low);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_page_pa1_high:			  %llu\n",
			      qpc->wqe_page_pa1_high);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_page_pa2_low:			  %llu\n",
			      qpc->wqe_page_pa2_low);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_page_pa2_high:			  %llu\n",
			      qpc->wqe_page_pa2_high);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_page_pa_vld:			  %llu\n",
			      qpc->wqe_page_pa_vld);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_page_pa_sel:			  %llu\n",
			      qpc->wqe_page_pa_sel);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_resp_retry_flag:			  %llu\n",
			      qpc->txw_resp_retry_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_send_bk_vld:			  %llu\n",
			      qpc->wqe_send_bk_vld);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_send_sge_addr:			  %llu\n",
			      qpc->wqe_send_sge_addr);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_resp_occupty:			  %llu\n",
			      qpc->txw_resp_occupty);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_polarity:			  %llu\n",
			      qpc->wqe_polarity);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_rx_sqretry:			  %llu\n",
			      qpc->wqe_rx_sqretry);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_sq_occupty:			  %llu\n",
			      qpc->txw_sq_occupty);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_resp_break_all:			  %llu\n",
			      qpc->txw_resp_break_all);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_ll_type:			  %llu\n",
			      qpc->txw_ll_type);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_resp_go_back_n:			  %llu\n",
			      qpc->txw_resp_go_back_n);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_rx_ack_retry:			  %llu\n",
			      qpc->wqe_rx_ack_retry);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_tx_eng_retry:			  %llu\n",
			      qpc->wqe_tx_eng_retry);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_resp_bk_valid:			  %llu\n",
			      qpc->wqe_resp_bk_valid);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_sq_retry_flag:			  %llu\n",
			      qpc->txw_sq_retry_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_nxt_need_irrl_num:			  %llu\n",
		qpc->txw_nxt_need_irrl_num);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_ll_wqe_drop:			  %llu\n",
			      qpc->txw_ll_wqe_drop);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_sq_retry_type:			  %llu\n",
			      qpc->txw_sq_retry_type);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_sq_retry_start_psn_low:			  %llu\n",
		qpc->txw_sq_retry_start_psn_low);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_sq_retry_start_psn:			  %llu\n",
		qpc->txw_sq_retry_start_psn);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_resp_retry_finish_flag:			  %llu\n",
		qpc->txw_resp_retry_finish_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_send_try_flag:			  %llu\n",
			      qpc->txw_send_try_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_proc_qp_state:			  %llu\n",
			      qpc->wqe_proc_qp_state);
	*len += dbg_vsnprintf(
		buf, *len,
		"stat_rate_already_init:			  %llu\n",
		qpc->stat_rate_already_init);
	*len += dbg_vsnprintf(
		buf, *len,
		"last_wqe_already_sent:			  %llu\n",
		qpc->last_wqe_already_sent);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_nak_retry_cnt:			  %llu\n",
			      qpc->wqe_nak_retry_cnt);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_rnr_retry_cnt:			  %llu\n",
			      qpc->wqe_rnr_retry_cnt);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_send_offest:			  %llu\n",
			      qpc->wqe_send_offest);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_resp_retry_cnt:			  %llu\n",
			      qpc->txw_resp_retry_cnt);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_resp_retry_end_ptr:			  %llu\n",
		qpc->txw_resp_retry_end_ptr);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_resp_retry_finish_back_ptr:			  %llu\n",
		qpc->txw_resp_retry_finish_back_ptr);
	*len += dbg_vsnprintf(
		buf, *len,
		"txw_resp_retry_exit_ptr:			  %llu\n",
		qpc->txw_resp_retry_exit_ptr);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_ssn_send:			  %llu\n",
			      qpc->wqe_ssn_send);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_ssn_nocredit_cnt_low:			  %llu\n",
		qpc->wqe_ssn_nocredit_cnt_low);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_ssn_nocredit_cnt_high:			  %llu\n",
		qpc->wqe_ssn_nocredit_cnt_high);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_next_send_psn_low:			  %llu\n",
		qpc->wqe_next_send_psn_low);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_next_send_psn_high:			  %llu\n",
		qpc->wqe_next_send_psn_high);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_msn:			  %llu\n",
			      qpc->respcache_msn);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_credit:			  %llu\n",
			      qpc->respcache_credit);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_credit_check_en:			  %llu\n",
			      qpc->wqe_credit_check_en);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_outsdanding_check_en:			  %llu\n",
		qpc->wqe_outsdanding_check_en);
	*len += dbg_vsnprintf(buf, *len,
			      "sq_stop:			  %llu\n",
			      qpc->sq_stop);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_psn:			  %llu\n",
			      qpc->respcache_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_r_va_low:			  %llu\n",
			      qpc->respcache_r_va_low);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_r_va_high:			  %llu\n",
			      qpc->respcache_r_va_high);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_r_key:			  %llu\n",
			      qpc->respcache_r_key);
	*len += dbg_vsnprintf(buf, *len,
			      "respcache_dma_len:			  %llu\n",
			      qpc->respcache_dma_len);
	*len += dbg_vsnprintf(buf, *len,
			      "mcrt_busy:			  %llu\n",
			      qpc->mcrt_busy);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_rtr2rts_flag:			  %llu\n",
			      qpc->txw_rtr2rts_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_resp_first_rd_flag:			  %llu\n",
		qpc->wqe_resp_first_rd_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_resp_rd_ptr_out:			  %llu\n",
			      qpc->wqe_resp_rd_ptr_out);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_resp_rd_ptr_sel:			  %llu\n",
			      qpc->wqe_resp_rd_ptr_sel);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_resp_rd_ptr_in:			  %llu\n",
			      qpc->wqe_resp_rd_ptr_in);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_wqe_irrl_wptr:			  %llu\n",
			      qpc->txw_wqe_irrl_wptr);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_psn_check_en:			  %llu\n",
			      qpc->wqe_psn_check_en);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_nop_check_en:			  %llu\n",
			      qpc->wqe_nop_check_en);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_read_fence_check_en:			  %llu\n",
		qpc->wqe_read_fence_check_en);
	*len += dbg_vsnprintf(buf, *len,
			      "resp_newest_psn:			  %llu\n",
			      qpc->resp_newest_psn);
	*len += dbg_vsnprintf(
		buf, *len,
		"wqe_local_fence_check_en:			  %llu\n",
		qpc->wqe_local_fence_check_en);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_chx_st:			  %llu\n",
			      qpc->txw_chx_st);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_resp_err:			  %llu\n",
			      qpc->txw_resp_err);
	*len += dbg_vsnprintf(buf, *len,
			      "wqe_proc_cnp_flag:			  %llu\n",
			      qpc->wqe_proc_cnp_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "mcrt_wqe_idx:			  %llu\n",
			      qpc->mcrt_wqe_idx);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_rate_bucket_low:			  %llu\n",
			      qpc->txw_rate_bucket_low);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_nxt_wqe_psn:			  %llu\n",
			      qpc->txw_nxt_wqe_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_rate_bucket_high:			  %llu\n",
			      qpc->txw_rate_bucket_high);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_nak_flag:			  %llu\n",
			      qpc->txw_nak_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_token_num:			  %llu\n",
			      qpc->txw_token_num);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_token_num:			  %llu\n",
			      qpc->txw_sq_retry_end_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_rate_timestamp:			  %llu\n",
			      qpc->txw_rate_timestamp);
	*len += dbg_vsnprintf(buf, *len,
			      "txw_wqe_start_psn:			  %llu\n",
			      qpc->txw_wqe_start_psn);
}

void drv_rdma_qp_read_field_seg3(char *buf, size_t *len, struct sxe2_qpc *qpc)
{
	*len += dbg_vsnprintf(buf, *len, "SEG3(TX_ENG)\n");
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_qpc_rtr2rts_flag:			  %llu\n",
		qpc->txeng_qpc_rtr2rts_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_req_err_flag:			  %llu\n",
			      qpc->txeng_req_err_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_resp_err_flag:			  %llu\n",
			      qpc->txeng_resp_err_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_flush_err_retry_flag:			  %llu\n",
		qpc->txeng_flush_err_retry_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_flush_err_retry_wqe_idx:			  %llu\n",
		qpc->txeng_flush_err_retry_wqe_idx);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_wqe_start_flag:			  %llu\n",
			      qpc->txeng_wqe_start_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_qp_state:			  %llu\n",
			      qpc->txeng_qp_state);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_ok_req_ssn:			  %llu\n",
			      qpc->txeng_ok_req_ssn);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_sq_err_syndrom:			  %llu\n",
			      qpc->txeng_sq_err_syndrom);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_tx2rx_retry_end_psn:			  %llu\n",
		qpc->txeng_tx2rx_retry_end_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_resp_err_psn_l:			  %llu\n",
			      qpc->txeng_resp_err_psn_l);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_resp_wait_nak_flag:			  %llu\n",
		qpc->txeng_resp_wait_nak_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_syn_sch2rxi_retry_phase_tag:			  %llu\n",
		qpc->txeng_syn_sch2rxi_retry_phase_tag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_tx2rx_retry_flag:			  %llu\n",
		qpc->txeng_sq_flush_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_send_req_next_ssn:			  %llu\n",
		qpc->txeng_send_req_next_ssn);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_token_num_l:			  %llu\n",
			      qpc->txeng_token_num_l);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_npsn:			  %llu\n",
			      qpc->txeng_npsn);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_ssnt_tx_wr_totptr:			  %llu\n",
		qpc->txeng_ssnt_tx_wr_totptr);

	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_tx_first_wr_flag:      %llu\n",
			      qpc->txeng_irrl_tx_first_wr_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_tx_first_wr_sel:       %llu\n",
			      qpc->txeng_irrl_tx_first_wr_sel);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_tx_first_wr_inptr:     %llu\n",
			      qpc->txeng_irrl_tx_first_wr_inptr);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_tx_wr_sel:             %llu\n",
			      qpc->txeng_irrl_tx_wr_sel);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_tx_wr_inptr:           %llu\n",
			      qpc->txeng_irrl_tx_wr_inptr);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_tx_wr_outptr:          %llu\n",
			      qpc->txeng_irrl_tx_wr_outptr);

	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_ssnt_tx_first_wr_in_flag:			  %llu\n",
		qpc->txeng_ssnt_tx_first_wr_in_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_ssnt_tx_first_wr_inptr:			  %llu\n",
		qpc->txeng_ssnt_tx_first_wr_inptr);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_ssnt_tx_rd2wr_flag:			  %llu\n",
		qpc->txeng_ssnt_tx_rd2wr_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_ssnt_tx_wr_inptr:			  %llu\n",
		qpc->txeng_ssnt_tx_wr_inptr);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_ssnt_tx_wr_outptr:			  %llu\n",
		qpc->txeng_ssnt_tx_wr_outptr);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_0_31:			  %llu\n",
			      qpc->txeng_irrl_pa_0_31);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_32_63:			  %llu\n",
			      qpc->txeng_irrl_pa_32_63);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_64_95:			  %llu\n",
			      qpc->txeng_irrl_pa_64_95);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_96_127:			  %llu\n",
			      qpc->txeng_irrl_pa_96_127);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_96_127:			  %llu\n",
			      qpc->txeng_ssnt_pa_0_31);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_96_127:			  %llu\n",
			      qpc->txeng_ssnt_pa_32_63);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_96_127:			  %llu\n",
			      qpc->txeng_ssnt_pa_64_95);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_irrl_pa_96_127:			  %llu\n",
			      qpc->txeng_ssnt_pa_96_127);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_resp_err_psn_h:			  %llu\n",
			      qpc->txeng_resp_err_psn_h);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_newest_ack_req_psn:			  %llu\n",
		qpc->txeng_newest_ack_req_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_token_num_m:			  %llu\n",
			      qpc->txeng_token_num_m);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_newest_unack_psn:			  %llu\n",
		qpc->txeng_newest_unack_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_token_num_h:			  %llu\n",
			      qpc->txeng_token_num_h);
	*len += dbg_vsnprintf(
		buf, *len,
		"txeng_oldest_unack_psn:			  %llu\n",
		qpc->txeng_oldest_unack_psn);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_tmo_log_rtm:			  %llu\n",
			      qpc->txeng_tmo_log_rtm);
	*len += dbg_vsnprintf(buf, *len,
			      "txeng_tmo_stamp_h:			  %llu\n",
			      qpc->txeng_tmo_stamp_h);
}

void drv_rdma_qp_read_field_seg4(char *buf, size_t *len, struct sxe2_qpc *qpc)
{
	*len += dbg_vsnprintf(buf, *len, "SEG4(RX_INI)\n");
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_newest_unack_psn:			  %llu\n",
			      qpc->rxi_newest_unack_psn);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_qp_error_cqe_syndrome:			  %llu\n",
		qpc->rxi_qp_error_cqe_syndrome);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_qp_state:			  %llu\n",
			      qpc->rxi_qp_state);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_req_rnr_retry_flag:			  %llu\n",
		qpc->rxi_req_rnr_retry_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_resp_rnr_nak_tmr:			  %llu\n",
			      qpc->rxi_resp_rnr_nak_tmr);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_retring_flag:			  %llu\n",
			      qpc->rxi_retring_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_retry_phase_tag:			  %llu\n",
			      qpc->rxi_retry_phase_tag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_wqe_sge_ce:			  %llu\n",
			      qpc->rxi_ssnt_wqe_sge_ce);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_in_wr_ptr_from_rx:			  %llu\n",
		qpc->rxi_ssnt_in_wr_ptr_from_rx);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_out_rd_ptr:			  %llu\n",
			      qpc->rxi_ssnt_out_rd_ptr);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_ll_wqe_drop:			  %llu\n",
			      qpc->rxi_ssnt_ll_wqe_drop);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_wqe_data_length:			  %llu\n",
		qpc->rxi_ssnt_wqe_data_length);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_wqe_start_psn:			  %llu\n",
		qpc->rxi_ssnt_wqe_start_psn);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_rx_rd2wr_flag:			  %llu\n",
		qpc->rxi_ssnt_rx_rd2wr_flag);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_rx_first_rd_flag:			  %llu\n",
		qpc->rxi_ssnt_rx_first_rd_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_info_flag:			  %llu\n",
			      qpc->rxi_ssnt_info_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_credit:			  %llu\n",
			      qpc->rxi_credit);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_unack_wqe_ssn:			  %llu\n",
		qpc->rxi_ssnt_unack_wqe_ssn);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxi_ssnt_total_rd_ptr:			  %llu\n",
		qpc->rxi_ssnt_total_rd_ptr);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_wqe_wrid:			  %llu\n",
			      qpc->rxi_ssnt_wqe_wrid);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_in_rd_ptr:			  %llu\n",
			      qpc->rxi_ssnt_in_rd_ptr);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ssnt_opcode:			  %llu\n",
			      qpc->rxi_ssnt_opcode);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_resp_msn:			  %llu\n",
			      qpc->rxi_resp_msn);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_irrl_wr_outptr:			  %llu\n",
			      qpc->rxi_irrl_wr_outptr);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ack_time_stamp:			  %llu\n",
			      qpc->rxi_ack_time_stamp);
	*len += dbg_vsnprintf(buf, *len,
			      "rxi_ae_code:			  %llu\n",
			      qpc->rxi_ae_code);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxeng_dif_breack_point:			  %llu\n",
		qpc->rxeng_dif_breack_point);
	*len += dbg_vsnprintf(buf, *len,
			      "rx_dif_flag:			  %llu\n",
			      qpc->rx_dif_flag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxeng_dif_ref_tag:			  %llu\n",
			      qpc->rxeng_dif_ref_tag);
	*len += dbg_vsnprintf(buf, *len,
			      "rxeng_dif_crc_seed:			  %llu\n",
			      qpc->rxeng_dif_crc_seed);
	*len += dbg_vsnprintf(
		buf, *len,
		"rxeng_dif_check_speed:			  %llu\n",
		qpc->rxeng_dif_check_speed);
	*len += dbg_vsnprintf(buf, *len,
			      "sw_cc_enable:			  %llu\n",
			      qpc->sw_cc_enable);
	*len += dbg_vsnprintf(buf, *len,
			      "sw_cc_index:			  %llu\n",
			      qpc->sw_cc_index);
}

void drv_rdma_qp_read_field_seg5(struct sxe2_rdma_device *rdma_dev, int qpn,
				 struct sxe2_qpc *qpc)
{
	DRV_RDMA_LOG_DEV_DEBUG("qp:%#x qpc SEG5(RX_TGT)\n", qpn);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_qp_state:			 %u\n",
			       qpc->rxt_qp_state);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_pa_type:			  %u\n",
			       qpc->rxt_resp_pa_type);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_newest_credit:			  %u\n",
			       qpc->rxt_newest_credit);
	DRV_RDMA_LOG_DEV_DEBUG("rx_cnp_flag:			  %u\n",
			       qpc->rx_cnp_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_retry_wr_cnt:			  %u\n",
			       qpc->rxt_resp_retry_wr_cnt);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_ack_type:			  %u\n",
			       qpc->rxt_ack_type);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_nak_flag:			  %u\n",
			       qpc->rxt_nak_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_ack_retry_flag:			  %u\n",
			       qpc->rxt_ack_retry_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_ack_syndrome:			  %u\n",
			       qpc->rxt_ack_syndrome);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_ack_msn:			  %u\n",
			       qpc->rxt_ack_msn);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_paddr_96_127:			  %u\n",
			       qpc->rxt_resp_paddr_96_127);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_paddr_64_95:			  %u\n",
			       qpc->rxt_resp_paddr_64_95);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_paddr_32_63:			  %u\n",
			       qpc->rxt_resp_paddr_32_63);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_paddr_0_31:			  %u\n",
			       qpc->rxt_resp_paddr_0_31);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_rd_flag:			  %u\n",
			       qpc->rxt_resp_rd_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_boundary_done:			  %u\n",
			       qpc->rxt_resp_boundary_done);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rxt_resp_first_wr_ptr_in:			  %u\n",
		qpc->rxt_resp_first_wr_ptr_in);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rxt_resp_first_wr_ptr_sel:			  %u\n",
		qpc->rxt_resp_first_wr_ptr_sel);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_first_wr_flag:			  %u\n",
			       qpc->rxt_resp_first_wr_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_wr_ptr_in:			  %u\n",
			       qpc->rxt_resp_wr_ptr_in);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_wr_ptr_out:			  %u\n",
			       qpc->rxt_resp_wr_ptr_out);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_wr_ptr_sel:			  %u\n",
			       qpc->rxt_resp_wr_ptr_sel);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_pa_vld:			  %u\n",
			       qpc->rxt_resp_pa_vld);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_newest_psn:			  %u\n",
			       qpc->rxt_resp_newest_psn);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rxt_resp_retry_start_ptr:			  %u\n",
		qpc->rxt_resp_retry_start_ptr);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_rmsm:			  %u\n",
			       qpc->rxt_rmsm);
	DRV_RDMA_LOG_DEV_DEBUG("rxt_resp_retry_end_ptr:			  %u\n",
			       qpc->rxt_resp_retry_end_ptr);
	DRV_RDMA_LOG_DEV_DEBUG("rx_cnp_disp_timing:			  %u\n",
			       qpc->rx_cnp_disp_timing);
}

void drv_rdma_qp_read_field_seg6(struct sxe2_rdma_device *rdma_dev, int qpn,
				 struct sxe2_qpc *qpc)
{
	DRV_RDMA_LOG_DEV_DEBUG("qp:%#x qpc SEG6(RX_PKT_PROC)\n", qpn);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_rd_ptr_in:			  %u\n",
			       qpc->rpp_ini_irrl_rd_ptr_in);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_rd_ptr_out:			  %u\n",
		qpc->rpp_ini_irrl_rd_ptr_out);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_rd_ptr_sel:			  %u\n",
		qpc->rpp_ini_irrl_rd_ptr_sel);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_first_rd_flag:			  %u\n",
		qpc->rpp_ini_irrl_first_rd_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_delete_en:			  %u\n",
			       qpc->rpp_ini_irrl_delete_en);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_delete_done:			  %u\n",
		qpc->rpp_ini_irrl_delete_done);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_sge_va_low:			  %u\n",
		qpc->rpp_ini_irrl_sge_va_low);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_sge_va_high:			  %u\n",
		qpc->rpp_ini_irrl_sge_va_high);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_sge_lkey:			  %u\n",
			       qpc->rpp_ini_irrl_sge_lkey);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_sge_len:			  %u\n",
			       qpc->rpp_ini_irrl_sge_len);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_irrl_sge_totallen:			  %u\n",
		qpc->rpp_ini_irrl_sge_totallen);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_sge_spsn:			  %u\n",
			       qpc->rpp_ini_irrl_sge_spsn);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_sge_ssn:			  %u\n",
			       qpc->rpp_ini_irrl_sge_ssn);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_rcv_messlen:			  %u\n",
			       qpc->rpp_ini_rcv_messlen);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_unack_psn:			  %u\n",
			       qpc->rpp_ini_unack_psn);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_irrl_info_flag:			  %u\n",
			       qpc->rpp_ini_irrl_info_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_qpsts_err_flag:			  %u\n",
			       qpc->rpp_ini_qpsts_err_flag);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_read_retry_flag:			  %u\n",
		qpc->rpp_ini_read_retry_flag);
	DRV_RDMA_LOG_DEV_DEBUG(
		"rpp_ini_write_retry_flag:			  %u\n",
		qpc->rpp_ini_write_retry_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_cur_ssn:			  %u\n",
			       qpc->rpp_ini_cur_ssn);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sge_va_low:			  %u\n",
			       qpc->rpp_tgt_sge_va_low);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sge_va_high:			  %u\n",
			       qpc->rpp_tgt_sge_va_high);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sge_key:			  %u\n",
			       qpc->rpp_tgt_sge_key);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sge_len:			  %u\n",
			       qpc->rpp_tgt_sge_len);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sge_len:			  %u\n",
			       qpc->rpp_wqe_err);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_read_ots_ptr:			  %u\n",
			       qpc->rpp_tgt_read_ots_ptr);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_rnr_flag:			  %u\n",
			       qpc->rpp_tgt_rnr_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_nak_flag:			  %u\n",
			       qpc->rpp_tgt_nak_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_nak_flag:			  %u\n",
			       qpc->rpp_tgt_rtr_aeq_flag);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sge_num:			  %u\n",
			       qpc->rpp_tgt_sge_num);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_page_pa_sel:			  %u\n",
			       qpc->rpp_tgt_page_pa_sel);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_page_pa_vld:			  %u\n",
			       qpc->rpp_tgt_page_pa_vld);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_page_pa_1_low:			  %u\n",
			       qpc->rpp_tgt_page_pa_1_low);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_page_pa_1_high:			  %u\n",
			       qpc->rpp_tgt_page_pa_1_high);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_rq_ud_len_err:			  %u\n",
			       qpc->rpp_tgt_rq_ud_len_err);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_page_pa_l:			  %u\n",
			       qpc->rpp_tgt_page_pa_l);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_page_pa_h:			  %u\n",
			       qpc->rpp_tgt_page_pa_h);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_qp_error:			  %u\n",
			       qpc->rpp_tgt_qp_error);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_wqe_vld:			  %u\n",
			       qpc->rpp_wqe_vld);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_bth_opcode:			  %u\n",
			       qpc->rpp_tgt_bth_opcode);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_epsn:			  %u\n",
			       qpc->rpp_tgt_epsn);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_rcv_messlen:			  %u\n",
			       qpc->rpp_tgt_rcv_messlen);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_sw_counter:			  %u\n",
			       qpc->rpp_tgt_sw_counter);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_tgt_hw_counter:			  %u\n",
			       qpc->rpp_tgt_hw_counter);
	DRV_RDMA_LOG_DEV_DEBUG("rpp_ini_pkt_psn:			  %u\n",
			       qpc->rpp_ini_pkt_psn);
}

void drv_rdma_qp_read_field_seg7(struct sxe2_rdma_device *rdma_dev, int qpn,
				 struct sxe2_qpc *qpc)
{
	DRV_RDMA_LOG_DEV_DEBUG("qp:%#x qpc SEG7(HW_ID)\n", qpn);
	DRV_RDMA_LOG_DEV_DEBUG("pf_id:			  %u\n", qpc->pf_id);
	DRV_RDMA_LOG_DEV_DEBUG("vf_relative_id:			  %u\n",
			       qpc->vf_relative_id);
	DRV_RDMA_LOG_DEV_DEBUG("vf_id:			  %u\n", qpc->vf_id);
	DRV_RDMA_LOG_DEV_DEBUG("vf_valid:			  %u\n",
			       qpc->vf_valid);
	DRV_RDMA_LOG_DEV_DEBUG("sqpn_8_17:			  %u\n",
			       qpc->sqpn_8_17);
	DRV_RDMA_LOG_DEV_DEBUG("hw_cqn_snd:			  %u\n",
			       qpc->hw_cqn_snd);
	DRV_RDMA_LOG_DEV_DEBUG("sqpn_0_7:			  %u\n",
			       qpc->sqpn_0_7);
	DRV_RDMA_LOG_DEV_DEBUG("hw_cqn_rcv:			  %u\n",
			       qpc->hw_cqn_rcv);
	DRV_RDMA_LOG_DEV_DEBUG("hw_srqn:			  %u\n",
			       qpc->hw_srqn);
	DRV_RDMA_LOG_DEV_DEBUG("sw_cc_enable:			  %u\n",
			       qpc->sw_cc_enable);
	DRV_RDMA_LOG_DEV_DEBUG("sw_cc_index:			  %u\n",
			       qpc->sw_cc_index);
}

u64 drv_rdma_qp_read_field(struct sxe2_rdma_device *rdma_dev, void *data,
			   enum drv_rdma_dbg_rsc_type type, char *buf)
{
	struct sxe2_rdma_qp *qp;
	struct sxe2_rdma_ctx_qp *qp_ctx;
	int qpn;
	int ret = 0;
	struct sxe2_qpc *qpc;
	size_t len = 0;

	qp	   = (struct sxe2_rdma_qp *)data;
	qpn	   = qp->ibqp.qp_num;
	qp_ctx	   = &qp->qp_ctx;

	ret = sxe2_mq_query_qp_cmd(qp);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("sxe2_mq_query_qp_cmd failed , ret(%d)\n",
				     ret);
		goto end;
	}

	qpc = (struct sxe2_qpc *)qp->host_ctx.va;

	len += dbg_vsnprintf(buf, len, "qp:%#x context:\n\n", qpn);
	drv_rdma_qp_read_field_seg0(buf, &len, qpc);

	drv_rdma_qp_read_field_seg1(buf, &len, qpc);

	drv_rdma_qp_read_field_seg2(buf, &len, qpc);

	drv_rdma_qp_read_field_seg3(buf, &len, qpc);

	drv_rdma_qp_read_field_seg4(buf, &len, qpc);

	drv_rdma_qp_read_field_seg5(rdma_dev, qpn, qpc);

	drv_rdma_qp_read_field_seg6(rdma_dev, qpn, qpc);

	drv_rdma_qp_read_field_seg7(rdma_dev, qpn, qpc);

end:
	return len;
}
static int drv_rdma_qp_write_field(struct sxe2_rdma_device *rdma_dev,
				   void *data, enum drv_rdma_dbg_rsc_type type,
				   char *buf)
{
#ifdef SXE2_CFG_DEBUG
	u32 i;
	int ret;
	u64 temp_value;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_qp *qp;
	struct sxe2_qpc *qpc;

	qp  = (struct sxe2_rdma_qp *)data;
	qpc = (struct sxe2_qpc *)qp->host_ctx.va;

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(buf, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(g_qp_fields); i++) {
		if (!strncmp(argv[0], g_qp_fields[i], strlen(g_qp_fields[i])) &&
		    (strlen(g_qp_fields[i]) == strlen(argv[0]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%d)\n", ret);
		goto end;
	}

	DRV_RDMA_LOG_DEV_INFO("query qp i:%d, temp_value:%llx\n", i,
			      temp_value);

	switch (i) {
	case ACK_TIMEOUT:
		qpc->ack_timeout = temp_value;
		break;
	case RETRY_MODE:
		qpc->retry_mode = temp_value;
		break;
	case CREDIT_EN:
		qpc->credit_en = temp_value;
		break;
	case COMM_EST:
		qpc->comm_est = temp_value;
		break;
	case RQE_LWM:
		qpc->rqe_lwm = temp_value;
		break;
	case QP_STATE:
		qpc->qp_state = temp_value;
		break;
	case DQPN:
		qpc->dqpn = temp_value;
		break;
	case QP_TYPE:
		qpc->qp_type = temp_value;
		break;
	case LLWQE_PAGE_INDEX:
		qpc->llwqe_page_index = temp_value;
		break;
	case LLWQE_MODE_ENABLE:
		qpc->llwqe_mode_enable = temp_value;
		break;
	case RETRY_RESP_OP_SEL:
		qpc->retry_resp_op_sel = temp_value;
		break;
	case LOG_RTM:
		qpc->log_rtm = temp_value;
		break;
	case LOG_MSG_MAX:
		qpc->log_msg_max = temp_value;
		break;
	case PMTU:
		qpc->pmtu = temp_value;
		break;
	case QP_PAGE_OFFSET:
		qpc->page_offset = temp_value;
		break;
	case LOG_RQ_SIZE:
		qpc->log_rq_size = temp_value;
		break;
	case LOG_SQ_SIZE:
		qpc->log_sq_size = temp_value;
		break;
	case CQN_SND:
		qpc->cqn_snd = temp_value;
		break;
	case LOG_RQ_STRIDE:
		qpc->log_rq_stride = temp_value;
		break;
	case LOG_PAGE_SIZE:
		qpc->log_page_size = temp_value;
		break;
	case CQN_RCV:
		qpc->cqn_rcv = temp_value;
		break;
	case MIN_RNR_NAK:
		qpc->min_rnr_nak = temp_value;
		break;
	case FL:
		qpc->fl = temp_value;
		break;
	case SRQN:
		qpc->srqn = temp_value;
		break;
	case BUCKET_TYPE:
		qpc->bucket_type = temp_value;
		break;
	case STAT_RATE:
		qpc->stat_rate = temp_value;
		break;
	case RQ_TYPE:
		qpc->rq_type = temp_value;
		break;
	case IPV4:
		qpc->ipv4 = temp_value;
		break;
	case PD:
		qpc->pd = temp_value;
		break;
	case LOG_RRA_MAX:
		qpc->log_rra_max = temp_value;
		break;
	case LOG_SRA_MAX:
		qpc->log_sra_max = temp_value;
		break;
	case SEND_START_PSN:
		qpc->send_start_psn = temp_value;
		break;
	case TMO_RETRY:
		qpc->tmo_retry = temp_value;
		break;
	case UDPRIV_CQENABLE:
		qpc->udpriv_cqenable = temp_value;
		break;
	case RNR_RETRY:
		qpc->rnr_retry = temp_value;
		break;
	case RCV_START_PSN:
		qpc->rcv_start_psn = temp_value;
		break;
	case ACK_MODE:
		qpc->ack_mode = temp_value;
		break;
	case PKEY_INDEX:
		qpc->pkey_index = temp_value;
		break;
	case SQ_FLUSH_FLAG:
		qpc->sq_flush_flag = temp_value;
		break;
	case RQ_FLUSH_FLAG:
		qpc->rq_flush_flag = temp_value;
		break;
	case LOG_ACK_REQ_FREQ:
		qpc->log_ack_req_freq = temp_value;
		break;
	case HOP_LIMIT:
		qpc->hop_limit = temp_value;
		break;
	case Q_KEY:
		qpc->q_key = temp_value;
		break;
	case SMAC_LOW:
		qpc->smac_low = temp_value;
		break;
	case SMAC_HIGH:
		qpc->smac_high = temp_value;
		break;
	case SRC_PORT_NUM:
		qpc->src_port_num = temp_value;
		break;
	case RMAC_LOW:
		qpc->rmac_low = temp_value;
		break;
	case RMAC_HIGH:
		qpc->rmac_high = temp_value;
		break;
	case DEST_PORT_NUM:
		qpc->dest_port_num = temp_value;
		break;
	case QP_CTX:
		qpc->qp_completion_contex = temp_value;
		break;
	case SQ_TPH_VAL:
		qpc->sq_tph_value = temp_value;
		break;
	case RQ_TPH_VAL:
		qpc->rq_tph_value = temp_value;
		break;
	case SQ_TPH_EN:
		qpc->sq_tph_en = temp_value;
		break;
	case RQ_TPH_EN:
		qpc->rq_tph_en = temp_value;
		break;
	case XMIT_TPH_EN:
		qpc->xmit_tph_en = temp_value;
		break;
	case RCV_TPH_EN:
		qpc->rcv_tph_en = temp_value;
		break;
	case CNP_DSCP:
		qpc->cnp_dscp = temp_value;
		break;
	case CNP_ECN:
		qpc->cnp_ecn = temp_value;
		break;
	case FLOW_LABEL:
		qpc->flow_label = temp_value;
		break;
	case DSCP:
		qpc->dscp = temp_value;
		break;
	case ECN:
		qpc->ecn = temp_value;
		break;
	case DEST_IP3:
		qpc->dest_ipaddr3 = temp_value;
		break;
	case DEST_IP2:
		qpc->dest_ipaddr2 = temp_value;
		break;
	case DEST_IP1:
		qpc->dest_ipaddr1 = temp_value;
		break;
	case DEST_IP0:
		qpc->dest_ipaddr0 = temp_value;
		break;
	case LOCAL_IP3:
		qpc->local_ipaddr_3 = temp_value;
		break;
	case LOCAL_IP2:
		qpc->local_ipaddr_2 = temp_value;
		break;
	case LOCAL_IP1:
		qpc->local_ipaddr_1 = temp_value;
		break;
	case LOCAL_IP0:
		qpc->local_ipaddr_0 = temp_value;
		break;
	case DBR_ADDR:
		qpc->dbr_addr = temp_value;
		break;
	case PBL_POINTER:
		qpc->pbl_pointer = temp_value;
		break;
	case TPID_IDX:
		qpc->tpid_index = temp_value;
		break;
	case WQ_ACCESS_MODE:
		qpc->wq_acces_mode = temp_value;
		break;
	case USE_STATS:
		qpc->use_statistics_intance = temp_value;
		break;
	case STATS_INDEX:
		qpc->statistics_instance_index = temp_value;
		break;
	case INSERT_VLAN_TAG:
		qpc->insert_vlan_tag = temp_value;
		break;
	case VLAN_TAG:
		qpc->vlan_tag = temp_value;
		break;
	case SRC_VSI:
		qpc->src_vsi = temp_value;
		break;
	case DISPATCH_MIN_UNIT:
		qpc->dispatch_min_unit = temp_value;
		break;
	case DISPATCH_MODE:
		qpc->dispatch_mode = temp_value;
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_WARN("invalid index %d, ret %d\n", i, ret);
		goto end;
	}

	ret = sxe2_mq_modify_qp_cmd(qp);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("modify qp ctx:%s failed, ret (%d)\n",
				     argv[0], ret);
	}
end:
	return ret;
#else
	return 0;
#endif
}
int drv_rdma_debug_qp_add(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_qp *qp)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->qp_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("qp debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	qp->dbg_node = drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_QP,
					     rdma_dev->hdl->qp_debugfs,
					     drv_rdma_qp_read_field,
					     drv_rdma_qp_write_field,
					     (int)qp->ibqp.qp_num, qp);
	if (!qp->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
	}

end:
	return ret;
}
void drv_rdma_debug_qp_remove(struct sxe2_rdma_device *rdma_dev,
			      struct sxe2_rdma_qp *qp)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->qp_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("qp debugfs dir not exist\n");
		goto end;
	}

	if (qp->dbg_node) {
		drv_rdma_rm_res_tree(qp->dbg_node);
		qp->dbg_node = NULL;
	}

end:
	return;
}
