/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_WQE_H
#define SPFC_WQE_H

#include "unf_type.h"
#include "unf_common.h"
#include "spfc_hw_wqe.h"
#include "spfc_parent_context.h"

/* TGT WQE type */
/* DRV->uCode via Parent SQ */
#define SPFC_SQE_FCP_TRD SPFC_TASK_T_TREAD
#define SPFC_SQE_FCP_TWR SPFC_TASK_T_TWRITE
#define SPFC_SQE_FCP_TRSP SPFC_TASK_T_TRESP
#define SPFC_SQE_FCP_TACK SPFC_TASK_T_TACK
#define SPFC_SQE_ELS_CMND SPFC_TASK_T_ELS
#define SPFC_SQE_ELS_RSP SPFC_TASK_T_ELS_RSP
#define SPFC_SQE_GS_CMND SPFC_TASK_T_GS
#define SPFC_SQE_BLS_CMND SPFC_TASK_T_ABTS
#define SPFC_SQE_FCP_IREAD SPFC_TASK_T_IREAD
#define SPFC_SQE_FCP_IWRITE SPFC_TASK_T_IWRITE
#define SPFC_SQE_FCP_ITMF SPFC_TASK_T_ITMF
#define SPFC_SQE_SESS_RST SPFC_TASK_T_SESS_RESET
#define SPFC_SQE_FCP_TMF_TRSP SPFC_TASK_T_TMF_RESP
#define SPFC_SQE_NOP SPFC_TASK_T_NOP
/* DRV->uCode Via CMDQ */
#define SPFC_CMDQE_ABTS_RSP SPFC_TASK_T_ABTS_RSP
#define SPFC_CMDQE_ABORT SPFC_TASK_T_ABORT
#define SPFC_CMDQE_SESS_DIS SPFC_TASK_T_SESS_DIS
#define SPFC_CMDQE_SESS_DEL SPFC_TASK_T_SESS_DEL

/* uCode->Drv Via CMD SCQ */
#define SPFC_SCQE_FCP_TCMND SPFC_TASK_T_RCV_TCMND
#define SPFC_SCQE_ELS_CMND SPFC_TASK_T_RCV_ELS_CMD
#define SPFC_SCQE_ABTS_CMD SPFC_TASK_T_RCV_ABTS_CMD
#define SPFC_SCQE_FCP_IRSP SPFC_TASK_T_IRESP
#define SPFC_SCQE_FCP_ITMF_RSP SPFC_TASK_T_ITMF_RESP

/* uCode->Drv Via STS SCQ */
#define SPFC_SCQE_FCP_TSTS SPFC_TASK_T_TSTS
#define SPFC_SCQE_GS_RSP SPFC_TASK_T_RCV_GS_RSP
#define SPFC_SCQE_ELS_RSP SPFC_TASK_T_RCV_ELS_RSP
#define SPFC_SCQE_ABTS_RSP SPFC_TASK_T_RCV_ABTS_RSP
#define SPFC_SCQE_ELS_RSP_STS SPFC_TASK_T_ELS_RSP_STS
#define SPFC_SCQE_ABORT_STS SPFC_TASK_T_ABORT_STS
#define SPFC_SCQE_SESS_EN_STS SPFC_TASK_T_SESS_EN_STS
#define SPFC_SCQE_SESS_DIS_STS SPFC_TASK_T_SESS_DIS_STS
#define SPFC_SCQE_SESS_DEL_STS SPFC_TASK_T_SESS_DEL_STS
#define SPFC_SCQE_SESS_RST_STS SPFC_TASK_T_SESS_RESET_STS
#define SPFC_SCQE_ITMF_MARKER_STS SPFC_TASK_T_ITMF_MARKER_STS
#define SPFC_SCQE_ABTS_MARKER_STS SPFC_TASK_T_ABTS_MARKER_STS
#define SPFC_SCQE_FLUSH_SQ_STS SPFC_TASK_T_FLUSH_SQ_STS
#define SPFC_SCQE_BUF_CLEAR_STS SPFC_TASK_T_BUFFER_CLEAR_STS
#define SPFC_SCQE_CLEAR_SRQ_STS SPFC_TASK_T_CLEAR_SRQ_STS
#define SPFC_SCQE_DIFX_RESULT_STS SPFC_TASK_T_DIFX_RESULT_STS
#define SPFC_SCQE_XID_FREE_ABORT_STS SPFC_TASK_T_EXCH_ID_FREE_ABORT_STS
#define SPFC_SCQE_EXCHID_TIMEOUT_STS SPFC_TASK_T_EXCHID_TIMEOUT_STS
#define SPFC_SQE_NOP_STS SPFC_TASK_T_NOP_STS

#define SPFC_LOW_32_BITS(__addr) ((u32)((u64)(__addr) & 0xffffffff))
#define SPFC_HIGH_32_BITS(__addr) ((u32)(((u64)(__addr) >> 32) & 0xffffffff))

/* Error Code from SCQ */
#define SPFC_COMPLETION_STATUS_SUCCESS FC_CQE_COMPLETED
#define SPFC_COMPLETION_STATUS_ABORTED_SETUP_FAIL FC_IMMI_CMDPKT_SETUP_FAIL

#define SPFC_COMPLETION_STATUS_TIMEOUT FC_ERROR_CODE_E_D_TIMER_EXPIRE
#define SPFC_COMPLETION_STATUS_DIF_ERROR FC_ERROR_CODE_DATA_DIFX_FAILED
#define SPFC_COMPLETION_STATUS_DATA_OOO FC_ERROR_CODE_DATA_OOO_RO
#define SPFC_COMPLETION_STATUS_DATA_OVERFLOW \
	FC_ERROR_CODE_DATA_EXCEEDS_DATA2TRNS

#define SPFC_SCQE_INVALID_CONN_ID (0xffff)
#define SPFC_GET_SCQE_TYPE(scqe) ((scqe)->common.ch.wd0.task_type)
#define SPFC_GET_SCQE_STATUS(scqe) ((scqe)->common.ch.wd0.err_code)
#define SPFC_GET_SCQE_REMAIN_CNT(scqe) ((scqe)->common.ch.wd0.cqe_remain_cnt)
#define SPFC_GET_SCQE_CONN_ID(scqe) ((scqe)->common.conn_id)
#define SPFC_GET_SCQE_SQN(scqe) ((scqe)->common.ch.wd0.sqn)
#define SPFC_GET_WQE_TYPE(wqe) ((wqe)->ts_sl.task_type)

#define SPFC_WQE_IS_IO(wqe)                               \
	((SPFC_GET_WQE_TYPE(wqe) != SPFC_SQE_SESS_RST) && \
	 (SPFC_GET_WQE_TYPE(wqe) != SPFC_SQE_NOP))
#define SPFC_SCQE_HAS_ERRCODE(scqe) \
	(SPFC_GET_SCQE_STATUS(scqe) != SPFC_COMPLETION_STATUS_SUCCESS)
#define SPFC_SCQE_ERR_TO_CM(scqe) \
	(SPFC_GET_SCQE_STATUS(scqe) != FC_ELS_GS_RSP_EXCH_CHECK_FAIL)
#define SPFC_SCQE_EXCH_ABORTED(scqe)        \
	((SPFC_GET_SCQE_STATUS(scqe) >=     \
	  FC_CQE_BUFFER_CLEAR_IO_COMPLETED) && \
	 (SPFC_GET_SCQE_STATUS(scqe) <= FC_CQE_WQE_FLUSH_IO_COMPLETED))
#define SPFC_SCQE_CONN_ID_VALID(scqe) \
	(SPFC_GET_SCQE_CONN_ID(scqe) != SPFC_SCQE_INVALID_CONN_ID)

/*
 * checksum error bitmap define
 */
#define NIC_RX_CSUM_HW_BYPASS_ERR (1)
#define NIC_RX_CSUM_IP_CSUM_ERR (1 << 1)
#define NIC_RX_CSUM_TCP_CSUM_ERR (1 << 2)
#define NIC_RX_CSUM_UDP_CSUM_ERR (1 << 3)
#define NIC_RX_CSUM_SCTP_CRC_ERR (1 << 4)

#define SPFC_WQE_SECTION_CHUNK_SIZE 8	   /* 8 bytes' chunk */
#define SPFC_T_RESP_WQE_CTR_TSL_SIZE 15	   /* 8 bytes' chunk */
#define SPFC_T_RD_WR_WQE_CTR_TSL_SIZE 9	   /* 8 bytes' chunk */
#define SPFC_T_RD_WR_WQE_CTR_BDSL_SIZE 4   /* 8 bytes' chunk */
#define SPFC_T_RD_WR_WQE_CTR_CTRLSL_SIZE 1 /* 8 bytes' chunk */

#define SPFC_WQE_MAX_ESGE_NUM 3	     /* 3 ESGE In Extended wqe */
#define SPFC_WQE_SGE_ENTRY_NUM 2     /* BD SGE and DIF SGE count */
#define SPFC_WQE_SGE_DIF_ENTRY_NUM 1 /* DIF SGE count */
#define SPFC_WQE_SGE_LAST_FLAG 1
#define SPFC_WQE_SGE_NOT_LAST_FLAG 0
#define SPFC_WQE_SGE_EXTEND_FLAG 1
#define SPFC_WQE_SGE_NOT_EXTEND_FLAG 0

#define SPFC_FCP_TMF_PORT_RESET (0)
#define SPFC_FCP_TMF_LUN_RESET (1)
#define SPFC_FCP_TMF_TGT_RESET (2)
#define SPFC_FCP_TMF_RSVD (3)

#define SPFC_ADJUST_DATA(old_va, new_va) \
	{                              \
		(old_va) = new_va;       \
	}

#define SPFC_GET_RESET_TYPE(tmf_flag, reset_flag)               \
	{                                                       \
		switch (tmf_flag) {                             \
		case UNF_FCP_TM_ABORT_TASK_SET:                 \
		case UNF_FCP_TM_LOGICAL_UNIT_RESET:             \
			(reset_flag) = SPFC_FCP_TMF_LUN_RESET;  \
			break;                                  \
		case UNF_FCP_TM_TARGET_RESET:                   \
			(reset_flag) = SPFC_FCP_TMF_TGT_RESET;  \
			break;                                  \
		case UNF_FCP_TM_CLEAR_TASK_SET:                 \
			(reset_flag) = SPFC_FCP_TMF_PORT_RESET; \
			break;                                  \
		default:                                        \
			(reset_flag) = SPFC_FCP_TMF_RSVD;       \
		}                                               \
	}

/* Link WQE structure */
struct spfc_linkwqe {
	union {
		struct {
			u32 rsv1 : 14;
			u32 wf : 1;
			u32 rsv2 : 14;
			u32 ctrlsl : 2;
			u32 o : 1;
		} wd0;

		u32 val_wd0;
	};

	union {
		struct {
			u32 msn : 16;
			u32 dump_msn : 15;
			u32 lp : 1; /* lp means whether O bit is overturn */
		} wd1;

		u32 val_wd1;
	};

	u32 next_page_addr_hi;
	u32 next_page_addr_lo;
};

/* Session Enable */
struct spfc_host_keys {
	struct {
		u32 smac1 : 8;
		u32 smac0 : 8;
		u32 rsv : 16;
	} wd0;

	u8 smac[ARRAY_INDEX_4];

	u8 dmac[ARRAY_INDEX_4];
	struct {
		u8 sid_1;
		u8 sid_2;
		u8 dmac_rvd[ARRAY_INDEX_2];
	} wd3;
	struct {
		u8 did_0;
		u8 did_1;
		u8 did_2;
		u8 sid_0;
	} wd4;

	struct {
		u32 port_id : 3;
		u32 host_id : 2;
		u32 rsvd : 27;
	} wd5;
	u32 rsvd;
};

/* Parent SQ WQE Related function */
void spfc_build_service_wqe_ctrl_section(struct spfc_wqe_ctrl *wqe_cs, u32 ts_size,
					 u32 bdsl);
void spfc_build_service_wqe_ts_common(struct spfc_sqe_ts *sqe_ts, u32 rport_index,
				      u16 local_xid, u16 remote_xid,
				      u16 data_len);
void spfc_build_els_gs_wqe_sge(struct spfc_sqe *sqe, void *buf_addr, u64 phy_addr,
			       u32 buf_len, u32 xid, void *handle);
void spfc_build_els_wqe_ts_req(struct spfc_sqe *sqe, void *info, u32 scqn,
			       void *frame_pld, struct unf_frame_pkg *pkg);
void spfc_build_els_wqe_ts_rsp(struct spfc_sqe *sqe, void *info,
			       struct unf_frame_pkg *pkg, void *frame_pld,
			       u16 type, u16 cmnd);
void spfc_build_bls_wqe_ts_req(struct spfc_sqe *sqe, struct unf_frame_pkg *pkg,
			       void *handle);
void spfc_build_trd_twr_wqe_ctrls(struct unf_frame_pkg *pkg, struct spfc_sqe *sqe);
void spfc_build_wqe_owner_pmsn(struct spfc_sqe *io_sqe, u16 owner, u16 pmsn);
void spfc_convert_parent_wqe_to_big_endian(struct spfc_sqe *sqe);
void spfc_build_icmnd_wqe_ctrls(struct unf_frame_pkg *pkg, struct spfc_sqe *sqe);
void spfc_build_icmnd_wqe_ts(void *handle, struct unf_frame_pkg *pkg,
			     struct spfc_sqe_ts *sqe_ts, union spfc_sqe_ts_ex *sqe_tsex);
void spfc_build_icmnd_wqe_ts_header(struct unf_frame_pkg *pkg, struct spfc_sqe *sqe,
				    u8 task_type, u16 exi_base, u8 port_idx);

void spfc_build_cmdqe_common(union spfc_cmdqe *cmd_qe, enum spfc_task_type task_type,
			     u16 rxid);
void spfc_build_srq_wqe_ctrls(struct spfc_rqe *rqe, u16 owner, u16 pmsn);
void spfc_build_common_wqe_ctrls(struct spfc_wqe_ctrl *ctrl_sl, u8 task_len);
void spfc_build_tmf_rsp_wqe_ts_header(struct unf_frame_pkg *pkg,
				      struct spfc_sqe_tmf_rsp *sqe, u16 exi_base,
				      u32 scqn);

#endif
