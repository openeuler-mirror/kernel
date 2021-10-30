// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_wqe.h"
#include "spfc_module.h"
#include "spfc_service.h"

void spfc_build_tmf_rsp_wqe_ts_header(struct unf_frame_pkg *pkg,
				      struct spfc_sqe_tmf_rsp *sqe, u16 exi_base,
				      u32 scqn)
{
	sqe->ts_sl.task_type = SPFC_SQE_FCP_TMF_TRSP;
	sqe->ts_sl.wd0.conn_id =
	    (u16)(pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX]);

	if (UNF_GET_RXID(pkg) == INVALID_VALUE16)
		sqe->ts_sl.local_xid = INVALID_VALUE16;
	else
		sqe->ts_sl.local_xid = UNF_GET_RXID(pkg) + exi_base;

	sqe->ts_sl.tmf_rsp.wd0.scqn = scqn;
	sqe->ts_sl.magic_num = UNF_GETXCHGALLOCTIME(pkg);
}

void spfc_build_common_wqe_ctrls(struct spfc_wqe_ctrl *ctrl_sl, u8 task_len)
{
	/* "BDSL" field of CtrlS - defines the size of BDS, which varies from 0
	 * to 2040 bytes (8 bits of 8 bytes' chunk)
	 */
	ctrl_sl->ch.wd0.bdsl = 0;

	/* "DrvSL" field of CtrlS - defines the size of DrvS, which varies from
	 * 0 to 24 bytes
	 */
	ctrl_sl->ch.wd0.drv_sl = 0;

	/* a.
	 * b1 - linking WQE, which will be only used in linked page architecture
	 * instead of ring, it's a special control WQE which does not contain
	 * any buffer or inline data information, and will only be consumed by
	 * hardware. The size is aligned to WQEBB/WQE b0 - normal WQE, either
	 * normal SEG WQE or inline data WQE
	 */
	ctrl_sl->ch.wd0.wf = 0;

	/*
	 * "CF" field of CtrlS - Completion Format - defines the format of CS.
	 * a.	b0 - Status information is embedded inside of Completion Section
	 * b.	b1 - Completion Section keeps SGL, where Status information
	 * should be written. (For the definition of SGLs see ?4.1
	 * .)
	 */
	ctrl_sl->ch.wd0.cf = 0;

	/* "TSL" field of CtrlS - defines the size of TS, which varies from 0 to
	 * 248 bytes
	 */
	ctrl_sl->ch.wd0.tsl = task_len;

	/*
	 * Variable length SGE (vSGE). The size of SGE is 16 bytes. The vSGE
	 * format is of two types, which are defined by "VA " field of CtrlS.
	 * "VA" stands for Virtual Address: o   b0. SGE comprises 64-bits
	 * buffer's pointer and 31-bits Length, each SGE can only support up to
	 * 2G-1B, it can guarantee each single SGE length can not exceed 2GB by
	 * nature, A byte count value of zero means a 0byte data transfer. o b1.
	 * SGE comprises 64-bits buffer's pointer, 31-bits Length and 30-bits
	 * Key of the Translation table , each SGE can only support up to 2G-1B,
	 * it can guarantee each single SGE length can not exceed 2GB by nature,
	 * A byte count value of zero means a 0byte data transfer
	 */
	ctrl_sl->ch.wd0.va = 0;

	/*
	 * "DF" field of CtrlS - Data Format - defines the format of BDS
	 * a.  b0 - BDS carries the list of SGEs (SGL)
	 * b.  b1 - BDS carries the inline data
	 */
	ctrl_sl->ch.wd0.df = 0;

	/* "CR" - Completion is Required - marks CQE generation request per WQE
	 */
	ctrl_sl->ch.wd0.cr = 1;

	/* "DIFSL" field of CtrlS - defines the size of DIFS, which varies from
	 * 0 to 56 bytes
	 */
	ctrl_sl->ch.wd0.dif_sl = 0;

	/* "CSL" field of CtrlS - defines the size of CS, which varies from 0 to
	 * 24 bytes
	 */
	ctrl_sl->ch.wd0.csl = 0;

	/* CtrlSL describes the size of CtrlS in 8 bytes chunks. The
	 * value Zero is not valid
	 */
	ctrl_sl->ch.wd0.ctrl_sl = 1;

	/* "O" - Owner - marks ownership of WQE */
	ctrl_sl->ch.wd0.owner = 0;
}

void spfc_build_trd_twr_wqe_ctrls(struct unf_frame_pkg *pkg, struct spfc_sqe *sqe)
{
	/* "BDSL" field of CtrlS - defines the size of BDS, which varies from 0
	 * to 2040 bytes (8 bits of 8 bytes' chunk)
	 */
	/* TrdWqe carry 2 SGE defaultly, 4DW per SGE, the value is 4 because
	 * unit is 2DW, in double SGL mode, bdsl is 2
	 */
	sqe->ctrl_sl.ch.wd0.bdsl = SPFC_T_RD_WR_WQE_CTR_BDSL_SIZE;

	/* "DrvSL" field of CtrlS - defines the size of DrvS, which varies from
	 * 0 to 24 bytes
	 */
	/* DrvSL = 0 */
	sqe->ctrl_sl.ch.wd0.drv_sl = 0;

	/* a.
	 * b1 - linking WQE, which will be only used in linked page architecture
	 * instead of ring, it's a special control WQE which does not contain
	 * any buffer or inline data information, and will only be consumed by
	 * hardware. The size is aligned to WQEBB/WQE b0 - normal WQE, either
	 * normal SEG WQE or inline data WQE
	 */
	/* normal wqe */
	sqe->ctrl_sl.ch.wd0.wf = 0;

	/*
	 * "CF" field of CtrlS - Completion Format - defines the format of CS.
	 * a. b0 - Status information is embedded inside of Completion Section
	 * b. b1 - Completion Section keeps SGL, where Status information
	 * should be written. (For the definition of SGLs see ?4.1)
	 */
	/* by SCQE mode, the value is ignored */
	sqe->ctrl_sl.ch.wd0.cf = 0;

	/* "TSL" field of CtrlS - defines the size of TS, which varies from 0 to
	 * 248 bytes
	 */
	/* TSL is configured by 56 bytes */
	sqe->ctrl_sl.ch.wd0.tsl =
	    sizeof(struct spfc_sqe_ts) / SPFC_WQE_SECTION_CHUNK_SIZE;

	/*
	 * Variable length SGE (vSGE). The size of SGE is 16 bytes. The vSGE
	 * format is of two types, which are defined by "VA " field of CtrlS.
	 * "VA" stands for Virtual Address: o b0. SGE comprises 64-bits buffer's
	 * pointer and 31-bits Length, each SGE can only support up to 2G-1B, it
	 * can guarantee each single SGE length can not exceed 2GB by nature, A
	 * byte count value of zero means a 0byte data transfer. o   b1. SGE
	 * comprises 64-bits buffer's pointer, 31-bits Length and 30-bits Key of
	 * the Translation table , each SGE can only support up to 2G-1B, it can
	 * guarantee each single SGE length can not exceed 2GB by nature, A byte
	 * count value of zero means a 0byte data transfer
	 */
	sqe->ctrl_sl.ch.wd0.va = 0;

	/*
	 * "DF" field of CtrlS - Data Format - defines the format of BDS
	 * a.  b0 - BDS carries the list of SGEs (SGL)
	 * b.  b1 - BDS carries the inline data
	 */
	sqe->ctrl_sl.ch.wd0.df = 0;

	/* "CR" - Completion is Required - marks CQE generation request per WQE
	 */
	/* by SCQE mode, this value is ignored */
	sqe->ctrl_sl.ch.wd0.cr = 1;

	/* "DIFSL" field of CtrlS - defines the size of DIFS, which varies from
	 * 0 to 56 bytes.
	 */
	sqe->ctrl_sl.ch.wd0.dif_sl = 0;

	/* "CSL" field of CtrlS - defines the size of CS, which varies from 0 to
	 * 24 bytes
	 */
	sqe->ctrl_sl.ch.wd0.csl = 0;

	/* CtrlSL describes the size of CtrlS in 8 bytes chunks. The
	 * value Zero is not valid.
	 */
	sqe->ctrl_sl.ch.wd0.ctrl_sl = SPFC_T_RD_WR_WQE_CTR_CTRLSL_SIZE;

	/* "O" - Owner - marks ownership of WQE */
	sqe->ctrl_sl.ch.wd0.owner = 0;
}

/* ****************************************************************************
 * Function Name        : spfc_build_service_wqe_ts_common
 * Function Description : Construct the DW1~DW3 field in the Parent SQ WQE
 * request of the ELS and ELS_RSP requests.
 * Input Parameters     : struct spfc_sqe_ts *sqe_ts u32 rport_index u16 local_xid
 * u16 remote_xid u16 data_len
 * Output Parameters  : N/A
 * Return Type        : void
 ****************************************************************************
 */
void spfc_build_service_wqe_ts_common(struct spfc_sqe_ts *sqe_ts, u32 rport_index,
				      u16 local_xid, u16 remote_xid, u16 data_len)
{
	sqe_ts->local_xid = local_xid;

	sqe_ts->wd0.conn_id = (u16)rport_index;
	sqe_ts->wd0.remote_xid = remote_xid;

	sqe_ts->cont.els_gs_elsrsp_comm.data_len = data_len;
}

/* ****************************************************************************
 * Function Name          : spfc_build_els_gs_wqe_sge
 * Function Description : Construct the SGE field of the ELS and ELS_RSP WQE.
 * The SGE and frame content have been converted to large ends in this
 * function.
 * Input Parameters: struct spfc_sqe *sqe void *buf_addr u32 buf_len u32 xid
 * Output Parameters  : N/A
 * Return Type        : void
 ****************************************************************************
 */
void spfc_build_els_gs_wqe_sge(struct spfc_sqe *sqe, void *buf_addr, u64 phy_addr,
			       u32 buf_len, u32 xid, void *handle)
{
	u64 els_rsp_phy_addr;
	struct spfc_variable_sge *sge = NULL;

	/* Fill in SGE and convert it to big-endian. */
	sge = &sqe->sge[ARRAY_INDEX_0];
	els_rsp_phy_addr = phy_addr;
	sge->buf_addr_hi = SPFC_HIGH_32_BITS(els_rsp_phy_addr);
	sge->buf_addr_lo = SPFC_LOW_32_BITS(els_rsp_phy_addr);
	sge->wd0.buf_len = buf_len;
	sge->wd0.r_flag = 0;
	sge->wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
	sge->wd1.buf_addr_gpa = SPFC_ZEROCOPY_PCIE_TEMPLATE_VALUE;
	sge->wd1.xid = 0;
	sge->wd1.last_flag = SPFC_WQE_SGE_LAST_FLAG;
	spfc_cpu_to_big32(sge, sizeof(*sge));

	/* Converts the payload of an FC frame into a big end. */
	if (buf_addr)
		spfc_cpu_to_big32(buf_addr, buf_len);
}

/* ****************************************************************************
 * Function Name          : spfc_build_els_wqe_ts_rsp
 * Function Description : Construct the DW2~DW6 field in the Parent SQ WQE
 * of the ELS_RSP request.
 * Input Parameters     : struct spfc_sqe *sqe void *sq_info void *frame_pld
 * u16 type u16 cmnd u32 scqn
 * Output Parameters: N/A
 * Return Type : void
 ****************************************************************************
 */
void spfc_build_els_wqe_ts_rsp(struct spfc_sqe *sqe, void *info,
			       struct unf_frame_pkg *pkg, void *frame_pld,
			       u16 type, u16 cmnd)
{
	struct unf_prli_payload *prli_acc_pld = NULL;
	struct spfc_sqe_els_rsp *els_rsp = NULL;
	struct spfc_sqe_ts *sqe_ts = NULL;
	struct spfc_parent_sq_info *sq_info = NULL;
	struct spfc_hba_info *hba = NULL;
	struct unf_fc_head *pkg_fc_hdr_info = NULL;
	struct spfc_parent_queue_info *prnt_q_info = (struct spfc_parent_queue_info *)info;

	FC_CHECK_RETURN_VOID(sqe);
	FC_CHECK_RETURN_VOID(frame_pld);

	sqe_ts = &sqe->ts_sl;
	els_rsp = &sqe_ts->cont.els_rsp;
	sqe_ts->task_type = SPFC_SQE_ELS_RSP;

	/* The default chip does not need to update parameters. */
	els_rsp->wd1.para_update = 0x0;

	sq_info = &prnt_q_info->parent_sq_info;
	hba = (struct spfc_hba_info *)sq_info->hba;

	pkg_fc_hdr_info = &pkg->frame_head;
	els_rsp->sid = pkg_fc_hdr_info->csctl_sid;
	els_rsp->did = pkg_fc_hdr_info->rctl_did;
	els_rsp->wd7.hotpooltag = UNF_GET_HOTPOOL_TAG(pkg) + hba->exi_base;
	els_rsp->wd2.class_mode = FC_PROTOCOL_CLASS_3;

	if (type == ELS_RJT)
		els_rsp->wd2.class_mode = pkg->class_mode;

	/* When the PLOGI request is sent, the microcode needs to be instructed
	 * to clear the I/O related to the link to avoid data inconsistency
	 * caused by the disorder of the IO.
	 */
	if ((cmnd == ELS_LOGO || cmnd == ELS_PLOGI)) {
		els_rsp->wd1.clr_io = 1;
		els_rsp->wd6.reset_exch_start = hba->exi_base;
		els_rsp->wd6.reset_exch_end =
		    hba->exi_base + (hba->exi_count - 1);
		els_rsp->wd7.scqn =
		    prnt_q_info->parent_sts_scq_info.cqm_queue_id;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "Port(0x%x) send cmd(0x%x) to RPort(0x%x),rport index(0x%x), notify clean io start 0x%x, end 0x%x, scqn 0x%x.",
			     sq_info->local_port_id, cmnd, sq_info->remote_port_id,
			     sq_info->rport_index, els_rsp->wd6.reset_exch_start,
			     els_rsp->wd6.reset_exch_end, els_rsp->wd7.scqn);

		return;
	}

	if (type == ELS_RJT)
		return;

	/* Enter WQE in the PrliAcc negotiation parameter, and fill in the
	 * Update flag in WQE.
	 */
	if (cmnd == ELS_PRLI) {
		/* The chip updates the PLOGI ACC negotiation parameters. */
		els_rsp->wd2.seq_cnt = sq_info->plogi_co_parms.seq_cnt;
		els_rsp->wd2.e_d_tov = sq_info->plogi_co_parms.ed_tov;
		els_rsp->wd2.tx_mfs = sq_info->plogi_co_parms.tx_mfs;
		els_rsp->e_d_tov_timer_val = sq_info->plogi_co_parms.ed_tov_time;

		/* The chip updates the PRLI ACC parameter. */
		prli_acc_pld = (struct unf_prli_payload *)frame_pld;
		els_rsp->wd4.xfer_dis = SPFC_GET_PRLI_PARAM_WXFER(prli_acc_pld->parms);
		els_rsp->wd4.conf = SPFC_GET_PRLI_PARAM_CONF(prli_acc_pld->parms);
		els_rsp->wd4.rec = SPFC_GET_PRLI_PARAM_REC(prli_acc_pld->parms);

		els_rsp->wd1.para_update = 0x03;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "Port(0x%x) save rport index(0x%x) login parms,seqcnt:0x%x,e_d_tov:0x%x,txmfs:0x%x,e_d_tovtimerval:0x%x, xfer_dis:0x%x,conf:0x%x,rec:0x%x.",
			     sq_info->local_port_id, sq_info->rport_index,
			     els_rsp->wd2.seq_cnt, els_rsp->wd2.e_d_tov,
			     els_rsp->wd2.tx_mfs, els_rsp->e_d_tov_timer_val,
			     els_rsp->wd4.xfer_dis, els_rsp->wd4.conf, els_rsp->wd4.rec);
	}
}

/* ****************************************************************************
 * Function Name       : spfc_build_els_wqe_ts_req
 * Function Description: Construct the DW2~DW4 field in the Parent SQ WQE
 * of the ELS request.
 * Input Parameters: struct spfc_sqe *sqe void *sq_info u16 cmnd u32 scqn
 * Output Parameters: N/A
 * Return Type: void
 ****************************************************************************
 */
void spfc_build_els_wqe_ts_req(struct spfc_sqe *sqe, void *info, u32 scqn,
			       void *frame_pld, struct unf_frame_pkg *pkg)
{
	struct spfc_sqe_ts *sqe_ts = NULL;
	struct spfc_sqe_t_els_gs *els_req = NULL;
	struct spfc_parent_sq_info *sq_info = NULL;
	struct spfc_hba_info *hba = NULL;
	struct unf_fc_head *pkg_fc_hdr_info = NULL;
	u16 cmnd;

	cmnd = SPFC_GET_LS_GS_CMND_CODE(pkg->cmnd);

	sqe_ts = &sqe->ts_sl;
	if (pkg->type == UNF_PKG_GS_REQ)
		sqe_ts->task_type = SPFC_SQE_GS_CMND;
	else
		sqe_ts->task_type = SPFC_SQE_ELS_CMND;

	sqe_ts->magic_num = UNF_GETXCHGALLOCTIME(pkg);

	els_req = &sqe_ts->cont.t_els_gs;
	pkg_fc_hdr_info = &pkg->frame_head;

	sq_info = (struct spfc_parent_sq_info *)info;
	hba = (struct spfc_hba_info *)sq_info->hba;
	els_req->sid = pkg_fc_hdr_info->csctl_sid;
	els_req->did = pkg_fc_hdr_info->rctl_did;

	/* When the PLOGI request is sent, the microcode needs to be instructed
	 * to clear the I/O related to the link to avoid data inconsistency
	 * caused by the disorder of the IO.
	 */
	if ((cmnd == ELS_LOGO || cmnd == ELS_PLOGI) && hba) {
		els_req->wd4.clr_io = 1;
		els_req->wd6.reset_exch_start = hba->exi_base;
		els_req->wd6.reset_exch_end = hba->exi_base + (hba->exi_count - 1);
		els_req->wd7.scqn = scqn;
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "Port(0x%x) Rport(0x%x) SID(0x%x) send %s to DID(0x%x), notify clean io start 0x%x, end 0x%x, scqn 0x%x.",
			     hba->port_cfg.port_id, sq_info->rport_index,
			     sq_info->local_port_id, (cmnd == ELS_PLOGI) ? "PLOGI" : "LOGO",
			     sq_info->remote_port_id, els_req->wd6.reset_exch_start,
			     els_req->wd6.reset_exch_end, scqn);

		return;
	}

	/* The chip updates the PLOGI ACC negotiation parameters. */
	if (cmnd == ELS_PRLI) {
		els_req->wd5.seq_cnt = sq_info->plogi_co_parms.seq_cnt;
		els_req->wd5.e_d_tov = sq_info->plogi_co_parms.ed_tov;
		els_req->wd5.tx_mfs = sq_info->plogi_co_parms.tx_mfs;
		els_req->e_d_tov_timer_val = sq_info->plogi_co_parms.ed_tov_time;

		els_req->wd4.rec_support = hba->port_cfg.tape_support ? 1 : 0;
		els_req->wd4.para_update = 0x01;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_INFO,
			     "Port(0x%x) save rport index(0x%x) login parms,seqcnt:0x%x,e_d_tov:0x%x,txmfs:0x%x,e_d_tovtimerval:0x%x.",
			     sq_info->local_port_id, sq_info->rport_index,
			     els_req->wd5.seq_cnt, els_req->wd5.e_d_tov,
			     els_req->wd5.tx_mfs, els_req->e_d_tov_timer_val);
	}

	if (cmnd == ELS_ECHO)
		els_req->echo_flag = true;

	if (cmnd == ELS_REC) {
		els_req->wd4.rec_flag = 1;
		els_req->wd4.origin_hottag = pkg->origin_hottag + hba->exi_base;
		els_req->origin_magicnum = pkg->origin_magicnum;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "Port(0x%x) Rport(0x%x) SID(0x%x) send Rec to DID(0x%x), origin_hottag 0x%x",
			     hba->port_cfg.port_id, sq_info->rport_index,
			     sq_info->local_port_id, sq_info->remote_port_id,
			     els_req->wd4.origin_hottag);
	}
}

/* ****************************************************************************
 * Function Name          : spfc_build_bls_wqe_ts_req
 * Function Description: Construct the DW2 field in the Parent SQ WQE of
 * the ELS request, that is, ABTS parameter.
 * Input Parameters:struct unf_frame_pkg *pkg void *hba
 * Output Parameters: N/A
 * Return Type: void
 ****************************************************************************
 */
void spfc_build_bls_wqe_ts_req(struct spfc_sqe *sqe, struct unf_frame_pkg *pkg, void *handle)
{
	struct spfc_sqe_abts *abts;

	sqe->ts_sl.task_type = SPFC_SQE_BLS_CMND;
	sqe->ts_sl.magic_num = UNF_GETXCHGALLOCTIME(pkg);

	abts = &sqe->ts_sl.cont.abts;
	abts->fh_parm_abts = pkg->frame_head.parameter;
	abts->hotpooltag = UNF_GET_HOTPOOL_TAG(pkg) +
			   ((struct spfc_hba_info *)handle)->exi_base;
	abts->release_timer = UNF_GET_XID_RELEASE_TIMER(pkg);
}

/* ****************************************************************************
 * Function Name          : spfc_build_service_wqe_ctrl_section
 * Function Description: fill Parent SQ WQE and Root SQ WQE's Control Section
 * Input Parameters    : struct spfc_wqe_ctrl *wqe_cs u32 ts_size u32 bdsl
 * Output Parameters   : N/A
 * Return Type         : void
 ****************************************************************************
 */
void spfc_build_service_wqe_ctrl_section(struct spfc_wqe_ctrl *wqe_cs, u32 ts_size,
					 u32 bdsl)
{
	wqe_cs->ch.wd0.bdsl = bdsl;
	wqe_cs->ch.wd0.drv_sl = 0;
	wqe_cs->ch.wd0.rsvd0 = 0;
	wqe_cs->ch.wd0.wf = 0;
	wqe_cs->ch.wd0.cf = 0;
	wqe_cs->ch.wd0.tsl = ts_size;
	wqe_cs->ch.wd0.va = 0;
	wqe_cs->ch.wd0.df = 0;
	wqe_cs->ch.wd0.cr = 1;
	wqe_cs->ch.wd0.dif_sl = 0;
	wqe_cs->ch.wd0.csl = 0;
	wqe_cs->ch.wd0.ctrl_sl = SPFC_BYTES_TO_QW_NUM(sizeof(*wqe_cs)); /* divided by 8 */
	wqe_cs->ch.wd0.owner = 0;
}

/* ****************************************************************************
 * Function Name          : spfc_build_wqe_owner_pmsn
 * Function Description: This field is filled using the value of Control
 * Section of Parent SQ WQE.
 * Input Parameters: struct spfc_wqe_ctrl *wqe_cs u16 owner u16 pmsn
 * Output Parameters  : N/A
 * Return Type: void
 ****************************************************************************
 */
void spfc_build_wqe_owner_pmsn(struct spfc_sqe *io_sqe, u16 owner, u16 pmsn)
{
	struct spfc_wqe_ctrl *wqe_cs = &io_sqe->ctrl_sl;
	struct spfc_wqe_ctrl *wqee_cs = &io_sqe->ectrl_sl;

	wqe_cs->qsf.wqe_sn = pmsn;
	wqe_cs->qsf.dump_wqe_sn = wqe_cs->qsf.wqe_sn;
	wqe_cs->ch.wd0.owner = (u32)owner;
	wqee_cs->ch.ctrl_ch_val = wqe_cs->ch.ctrl_ch_val;
	wqee_cs->qsf.wqe_sn = wqe_cs->qsf.wqe_sn;
	wqee_cs->qsf.dump_wqe_sn = wqe_cs->qsf.dump_wqe_sn;
}

/* ****************************************************************************
 * Function Name          : spfc_convert_parent_wqe_to_big_endian
 * Function Description: Set the Done field of Parent SQ WQE and convert
 * Control Section and Task Section to big-endian.
 * Input Parameters:struct spfc_sqe *sqe
 * Output Parameters  : N/A
 * Return Type        : void
 ****************************************************************************
 */
void spfc_convert_parent_wqe_to_big_endian(struct spfc_sqe *sqe)
{
	if (likely(sqe->ts_sl.task_type != SPFC_TASK_T_TRESP &&
		   sqe->ts_sl.task_type != SPFC_TASK_T_TMF_RESP)) {
		/* Convert Control Secton and Task Section to big-endian. Before
		 * the SGE enters the queue, the upper-layer driver converts the
		 * SGE and Task Section to the big-endian mode.
		 */
		spfc_cpu_to_big32(&sqe->ctrl_sl, sizeof(sqe->ctrl_sl));
		spfc_cpu_to_big32(&sqe->ts_sl, sizeof(sqe->ts_sl));
		spfc_cpu_to_big32(&sqe->ectrl_sl, sizeof(sqe->ectrl_sl));
		spfc_cpu_to_big32(&sqe->sid, sizeof(sqe->sid));
		spfc_cpu_to_big32(&sqe->did, sizeof(sqe->did));
		spfc_cpu_to_big32(&sqe->wqe_gpa, sizeof(sqe->wqe_gpa));
		spfc_cpu_to_big32(&sqe->db_val, sizeof(sqe->db_val));
	} else {
		/* The SPFC_TASK_T_TRESP may use the SGE as the Task Section to
		 * convert the entire SQE into a large end.
		 */
		spfc_cpu_to_big32(sqe, sizeof(struct spfc_sqe_tresp));
	}
}

/* ****************************************************************************
 * Function Name        : spfc_build_cmdqe_common
 * Function Description : Assemble the Cmdqe Common part.
 * Input Parameters: union spfc_cmdqe *cmd_qe enum spfc_task_type task_type u16 rxid
 * Output Parameters  : N/A
 * Return Type: void
 ****************************************************************************
 */
void spfc_build_cmdqe_common(union spfc_cmdqe *cmd_qe, enum spfc_task_type task_type,
			     u16 rxid)
{
	cmd_qe->common.wd0.task_type = task_type;
	cmd_qe->common.wd0.rx_id = rxid;
	cmd_qe->common.wd0.rsvd0 = 0;
}

#define SPFC_STANDARD_SIRT_ENABLE (1)
#define SPFC_STANDARD_SIRT_DISABLE (0)
#define SPFC_UNKNOWN_ID (0xFFFF)

void spfc_build_icmnd_wqe_ts_header(struct unf_frame_pkg *pkg, struct spfc_sqe *sqe,
				    u8 task_type, u16 exi_base, u8 port_idx)
{
	sqe->ts_sl.local_xid = (u16)UNF_GET_HOTPOOL_TAG(pkg) + exi_base;
	sqe->ts_sl.task_type = task_type;
	sqe->ts_sl.wd0.conn_id =
	    (u16)(pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX]);

	sqe->ts_sl.wd0.remote_xid = SPFC_UNKNOWN_ID;
	sqe->ts_sl.magic_num = UNF_GETXCHGALLOCTIME(pkg);
}

/* ****************************************************************************
 * Function Name          : spfc_build_icmnd_wqe_ts
 * Function Description : Constructing the TS Domain of the ICmnd
 * Input Parameters: void *hba struct unf_frame_pkg *pkg
 * struct spfc_sqe_ts *sqe_ts
 * Output Parameters  :N/A
 * Return Type : void
 ****************************************************************************
 */
void spfc_build_icmnd_wqe_ts(void *handle, struct unf_frame_pkg *pkg,
			     struct spfc_sqe_ts *sqe_ts, union spfc_sqe_ts_ex *sqe_tsex)
{
	struct spfc_sqe_icmnd *icmnd = &sqe_ts->cont.icmnd;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;

	sqe_ts->cdb_type = 0;
	memcpy(icmnd->fcp_cmnd_iu, pkg->fcp_cmnd, sizeof(struct unf_fcp_cmnd));

	if (sqe_ts->task_type == SPFC_SQE_FCP_ITMF) {
		icmnd->info.tmf.w0.bs.reset_exch_start = hba->exi_base;
		icmnd->info.tmf.w0.bs.reset_exch_end = hba->exi_base + hba->exi_count - 1;

		icmnd->info.tmf.w1.bs.reset_did = UNF_GET_DID(pkg);
		/* delivers the marker status flag to the microcode. */
		icmnd->info.tmf.w1.bs.marker_sts = 1;
		SPFC_GET_RESET_TYPE(UNF_GET_TASK_MGMT_FLAGS(pkg->fcp_cmnd->control),
				    icmnd->info.tmf.w1.bs.reset_type);

		icmnd->info.tmf.w2.bs.reset_sid = UNF_GET_SID(pkg);

		memcpy(icmnd->info.tmf.reset_lun, pkg->fcp_cmnd->lun,
		       sizeof(icmnd->info.tmf.reset_lun));
	}
}

/* ****************************************************************************
 * Function Name          : spfc_build_icmnd_wqe_ctrls
 * Function Description : The CtrlS domain of the ICmnd is constructed. The
 * analysis result is the same as that of the TWTR.
 * Input Parameters: struct unf_frame_pkg *pkg struct spfc_sqe *sqe
 * Output Parameters: N/A
 * Return Type: void
 ****************************************************************************
 */
void spfc_build_icmnd_wqe_ctrls(struct unf_frame_pkg *pkg, struct spfc_sqe *sqe)
{
	spfc_build_trd_twr_wqe_ctrls(pkg, sqe);
}

/* ****************************************************************************
 * Function Name          : spfc_build_srq_wqe_ctrls
 * Function Description : Construct the CtrlS domain of the ICmnd. The analysis
 * result is the same as that of the TWTR.
 * Input Parameters : struct spfc_rqe *rqe u16 owner u16 pmsn
 * Output Parameters  : N/A
 * Return Type        : void
 ****************************************************************************
 */
void spfc_build_srq_wqe_ctrls(struct spfc_rqe *rqe, u16 owner, u16 pmsn)
{
	struct spfc_wqe_ctrl_ch *wqe_ctrls = NULL;

	wqe_ctrls = &rqe->ctrl_sl.ch;
	wqe_ctrls->wd0.owner = owner;
	wqe_ctrls->wd0.ctrl_sl = sizeof(struct spfc_wqe_ctrl) >> UNF_SHIFT_3;
	wqe_ctrls->wd0.csl = 1;
	wqe_ctrls->wd0.dif_sl = 0;
	wqe_ctrls->wd0.cr = 1;
	wqe_ctrls->wd0.df = 0;
	wqe_ctrls->wd0.va = 0;
	wqe_ctrls->wd0.tsl = 0;
	wqe_ctrls->wd0.cf = 0;
	wqe_ctrls->wd0.wf = 0;
	wqe_ctrls->wd0.drv_sl = sizeof(struct spfc_rqe_drv) >> UNF_SHIFT_3;
	wqe_ctrls->wd0.bdsl = sizeof(struct spfc_constant_sge) >> UNF_SHIFT_3;

	rqe->ctrl_sl.wd0.wqe_msn = pmsn;
	rqe->ctrl_sl.wd0.dump_wqe_msn = rqe->ctrl_sl.wd0.wqe_msn;
}
