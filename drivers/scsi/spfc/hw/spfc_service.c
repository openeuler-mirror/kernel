// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_service.h"
#include "unf_log.h"
#include "spfc_io.h"
#include "spfc_chipitf.h"

#define SPFC_ELS_SRQ_BUF_NUM (0x9)
#define SPFC_LS_GS_USERID_LEN ((FC_LS_GS_USERID_CNT_MAX + 1) / 2)

struct unf_scqe_handle_table {
	u32 scqe_type; /* ELS type */
	bool reclaim_sq_wpg;
	u32 (*scqe_handle_func)(struct spfc_hba_info *hba, union spfc_scqe *scqe);
};

static u32 spfc_get_els_rsp_pld_len(u16 els_type, u16 els_cmnd,
				    u32 *els_acc_pld_len)
{
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(els_acc_pld_len, UNF_RETURN_ERROR);

	/* RJT */
	if (els_type == ELS_RJT) {
		*els_acc_pld_len = UNF_ELS_ACC_RJT_LEN;
		return RETURN_OK;
	}

	/* ACC */
	switch (els_cmnd) {
	/* uses the same PAYLOAD length as PLOGI. */
	case ELS_FLOGI:
	case ELS_PDISC:
	case ELS_PLOGI:
		*els_acc_pld_len = UNF_PLOGI_ACC_PAYLOAD_LEN;
		break;

	case ELS_PRLI:
		/* If sirt is enabled, The PRLI ACC payload extends 12 bytes */
		*els_acc_pld_len = (UNF_PRLI_ACC_PAYLOAD_LEN - UNF_PRLI_SIRT_EXTRA_SIZE);

		break;

	case ELS_LOGO:
		*els_acc_pld_len = UNF_LOGO_ACC_PAYLOAD_LEN;
		break;

	case ELS_PRLO:
		*els_acc_pld_len = UNF_PRLO_ACC_PAYLOAD_LEN;
		break;

	case ELS_RSCN:
		*els_acc_pld_len = UNF_RSCN_ACC_PAYLOAD_LEN;
		break;

	case ELS_ADISC:
		*els_acc_pld_len = UNF_ADISC_ACC_PAYLOAD_LEN;
		break;

	case ELS_RRQ:
		*els_acc_pld_len = UNF_RRQ_ACC_PAYLOAD_LEN;
		break;

	case ELS_SCR:
		*els_acc_pld_len = UNF_SCR_RSP_PAYLOAD_LEN;
		break;

	case ELS_ECHO:
		*els_acc_pld_len = UNF_ECHO_ACC_PAYLOAD_LEN;
		break;

	case ELS_REC:
		*els_acc_pld_len = UNF_REC_ACC_PAYLOAD_LEN;
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Unknown ELS command(0x%x)",
			     els_cmnd);
		ret = UNF_RETURN_ERROR;
		break;
	}

	return ret;
}

struct unf_els_cmd_paylod_table {
	u16 els_cmnd; /* ELS type */
	u32 els_req_pld_len;
	u32 els_rsp_pld_len;
};

static const struct unf_els_cmd_paylod_table els_pld_table_map[] = {
	{ELS_FDISC, UNF_FDISC_PAYLOAD_LEN, UNF_FDISC_ACC_PAYLOAD_LEN},
	{ELS_FLOGI, UNF_FLOGI_PAYLOAD_LEN, UNF_FLOGI_ACC_PAYLOAD_LEN},
	{ELS_PLOGI, UNF_PLOGI_PAYLOAD_LEN, UNF_PLOGI_ACC_PAYLOAD_LEN},
	{ELS_SCR, UNF_SCR_PAYLOAD_LEN, UNF_SCR_RSP_PAYLOAD_LEN},
	{ELS_PDISC, UNF_PDISC_PAYLOAD_LEN, UNF_PDISC_ACC_PAYLOAD_LEN},
	{ELS_LOGO, UNF_LOGO_PAYLOAD_LEN, UNF_LOGO_ACC_PAYLOAD_LEN},
	{ELS_PRLO, UNF_PRLO_PAYLOAD_LEN, UNF_PRLO_ACC_PAYLOAD_LEN},
	{ELS_ADISC, UNF_ADISC_PAYLOAD_LEN, UNF_ADISC_ACC_PAYLOAD_LEN},
	{ELS_RRQ, UNF_RRQ_PAYLOAD_LEN, UNF_RRQ_ACC_PAYLOAD_LEN},
	{ELS_RSCN, 0, UNF_RSCN_ACC_PAYLOAD_LEN},
	{ELS_ECHO, UNF_ECHO_PAYLOAD_LEN, UNF_ECHO_ACC_PAYLOAD_LEN},
	{ELS_REC, UNF_REC_PAYLOAD_LEN, UNF_REC_ACC_PAYLOAD_LEN}
};

static u32 spfc_get_els_req_acc_pld_len(u16 els_cmnd, u32 *req_pld_len, u32 *rsp_pld_len)
{
	u32 ret = RETURN_OK;
	u32 i;

	FC_CHECK_RETURN_VALUE(req_pld_len, UNF_RETURN_ERROR);

	for (i = 0; i < (sizeof(els_pld_table_map) /
			 sizeof(struct unf_els_cmd_paylod_table));
	     i++) {
		if (els_pld_table_map[i].els_cmnd == els_cmnd) {
			*req_pld_len = els_pld_table_map[i].els_req_pld_len;
			*rsp_pld_len = els_pld_table_map[i].els_rsp_pld_len;
			return ret;
		}
	}

	switch (els_cmnd) {
	case ELS_PRLI:
		/* If sirt is enabled, The PRLI ACC payload extends 12 bytes */
		*req_pld_len = SPFC_GET_PRLI_PAYLOAD_LEN;
		*rsp_pld_len = SPFC_GET_PRLI_PAYLOAD_LEN;

		break;

	default:
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Unknown ELS_CMD(0x%x)", els_cmnd);
		ret = UNF_RETURN_ERROR;
		break;
	}

	return ret;
}

static u32 spfc_check_parent_qinfo_valid(struct spfc_hba_info *hba, struct unf_frame_pkg *pkg,
					 struct spfc_parent_queue_info **prt_qinfo)
{
	if (!*prt_qinfo) {
		if (pkg->type == UNF_PKG_ELS_REQ || pkg->type == UNF_PKG_ELS_REPLY) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) send LS SID(0x%x) DID(0x%x) with null prtqinfo",
				     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
				     pkg->frame_head.rctl_did);
			pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = SPFC_DEFAULT_RPORT_INDEX;
			*prt_qinfo = spfc_find_parent_queue_info_by_pkg(hba, pkg);
			if (!*prt_qinfo)
				return UNF_RETURN_ERROR;
		} else {
			return UNF_RETURN_ERROR;
		}
	}

	if (pkg->type == UNF_PKG_GS_REQ && SPFC_RPORT_NOT_OFFLOADED(*prt_qinfo)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) send GS SID(0x%x) DID(0x%x), send GS Request before PLOGI",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);
		return UNF_RETURN_ERROR;
	}
	return RETURN_OK;
}

static void spfc_get_pkt_cmnd_type_code(struct unf_frame_pkg *pkg,
					u16 *ls_gs_cmnd_code,
					u16 *ls_gs_cmnd_type)
{
	*ls_gs_cmnd_type = SPFC_GET_LS_GS_CMND_CODE(pkg->cmnd);
	if (SPFC_PKG_IS_ELS_RSP(*ls_gs_cmnd_type)) {
		*ls_gs_cmnd_code = SPFC_GET_ELS_RSP_CODE(pkg->cmnd);
	} else if (pkg->type == UNF_PKG_GS_REQ) {
		*ls_gs_cmnd_code = *ls_gs_cmnd_type;
	} else {
		*ls_gs_cmnd_code = *ls_gs_cmnd_type;
		*ls_gs_cmnd_type = ELS_CMND;
	}
}

static u32 spfc_get_gs_req_rsp_pld_len(u16 cmnd_code, u32 *gs_pld_len, u32 *gs_rsp_pld_len)
{
	FC_CHECK_RETURN_VALUE(gs_pld_len, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(gs_rsp_pld_len, UNF_RETURN_ERROR);

	switch (cmnd_code) {
	case NS_GPN_ID:
		*gs_pld_len = UNF_GPNID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_GPNID_RSP_PAYLOAD_LEN;
		break;

	case NS_GNN_ID:
		*gs_pld_len = UNF_GNNID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_GNNID_RSP_PAYLOAD_LEN;
		break;

	case NS_GFF_ID:
		*gs_pld_len = UNF_GFFID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_GFFID_RSP_PAYLOAD_LEN;
		break;

	case NS_GID_FT:
	case NS_GID_PT:
		*gs_pld_len = UNF_GID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_GID_ACC_PAYLOAD_LEN;
		break;

	case NS_RFT_ID:
		*gs_pld_len = UNF_RFTID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_RFTID_RSP_PAYLOAD_LEN;
		break;

	case NS_RFF_ID:
		*gs_pld_len = UNF_RFFID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_RFFID_RSP_PAYLOAD_LEN;
		break;
	case NS_GA_NXT:
		*gs_pld_len = UNF_GID_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_GID_ACC_PAYLOAD_LEN;
		break;

	case NS_GIEL:
		*gs_pld_len = UNF_RFTID_RSP_PAYLOAD_LEN;
		*gs_rsp_pld_len = UNF_GID_ACC_PAYLOAD_LEN;
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Unknown GS commond type(0x%x)", cmnd_code);
		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static void *spfc_get_els_frame_addr(struct spfc_hba_info *hba,
				     struct unf_frame_pkg *pkg,
				     u16 els_cmnd_code, u16 els_cmnd_type,
				     u64 *phy_addr)
{
	void *frame_pld_addr = NULL;
	dma_addr_t els_frame_addr = 0;

	if (els_cmnd_code == ELS_ECHO) {
		frame_pld_addr = (void *)UNF_GET_ECHO_PAYLOAD(pkg);
		els_frame_addr = UNF_GET_ECHO_PAYLOAD_PHYADDR(pkg);
	} else if (els_cmnd_code == ELS_RSCN) {
		if (els_cmnd_type == ELS_CMND) {
			/* Not Support */
			frame_pld_addr = NULL;
			els_frame_addr = 0;
		} else {
			frame_pld_addr = (void *)UNF_GET_RSCN_ACC_PAYLOAD(pkg);
			els_frame_addr = pkg->unf_cmnd_pload_bl.buf_dma_addr +
					 sizeof(struct unf_fc_head);
		}
	} else {
		frame_pld_addr = (void *)SPFC_GET_CMND_PAYLOAD_ADDR(pkg);
		els_frame_addr = pkg->unf_cmnd_pload_bl.buf_dma_addr +
				 sizeof(struct unf_fc_head);
	}
	*phy_addr = els_frame_addr;
	return frame_pld_addr;
}

static u32 spfc_get_frame_info(struct spfc_hba_info *hba,
			       struct unf_frame_pkg *pkg, void **frame_pld_addr,
			       u32 *frame_pld_len, u64 *frame_phy_addr,
			       u32 *acc_pld_len)
{
	u32 ret = RETURN_OK;
	u16 ls_gs_cmnd_code = SPFC_ZERO;
	u16 ls_gs_cmnd_type = SPFC_ZERO;

	spfc_get_pkt_cmnd_type_code(pkg, &ls_gs_cmnd_code, &ls_gs_cmnd_type);

	if (pkg->type == UNF_PKG_GS_REQ) {
		ret = spfc_get_gs_req_rsp_pld_len(ls_gs_cmnd_code,
						  frame_pld_len, acc_pld_len);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Port(0x%x) send GS SID(0x%x) DID(0x%x), get error GS request and response payload length",
				     hba->port_cfg.port_id,
				     pkg->frame_head.csctl_sid,
				     pkg->frame_head.rctl_did);

			return ret;
		}
		*frame_pld_addr = (void *)(SPFC_GET_CMND_PAYLOAD_ADDR(pkg));
		*frame_phy_addr = pkg->unf_cmnd_pload_bl.buf_dma_addr + sizeof(struct unf_fc_head);
		if (ls_gs_cmnd_code == NS_GID_FT || ls_gs_cmnd_code == NS_GID_PT)
			*frame_pld_addr = (void *)(UNF_GET_GID_PAYLOAD(pkg));
	} else {
		*frame_pld_addr = spfc_get_els_frame_addr(hba, pkg, ls_gs_cmnd_code,
							  ls_gs_cmnd_type, frame_phy_addr);
		if (SPFC_PKG_IS_ELS_RSP(ls_gs_cmnd_type)) {
			ret = spfc_get_els_rsp_pld_len(ls_gs_cmnd_type, ls_gs_cmnd_code,
						       frame_pld_len);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
					     "[info]Port(0x%x) get els cmd (0x%x) rsp len failed.",
					     hba->port_cfg.port_id,
					     ls_gs_cmnd_code);
				return ret;
			}
		} else {
			ret = spfc_get_els_req_acc_pld_len(ls_gs_cmnd_code, frame_pld_len,
							   acc_pld_len);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
					     "[info]Port(0x%x) get els cmd (0x%x) req and acc len failed.",
					     hba->port_cfg.port_id,
					     ls_gs_cmnd_code);
				return ret;
			}
		}
	}
	return ret;
}

static u32
spfc_send_ls_gs_via_parent(struct spfc_hba_info *hba, struct unf_frame_pkg *pkg,
			   struct spfc_parent_queue_info *prt_queue_info)
{
	u32 ret = UNF_RETURN_ERROR;
	u16 ls_gs_cmnd_code = SPFC_ZERO;
	u16 ls_gs_cmnd_type = SPFC_ZERO;
	u16 remote_exid = 0;
	u16 hot_tag = 0;
	struct spfc_parent_sq_info *parent_sq_info = NULL;
	struct spfc_sqe tmp_sqe;
	struct spfc_sqe *sqe = NULL;
	void *frame_pld_addr = NULL;
	u32 frame_pld_len = 0;
	u32 acc_pld_len = 0;
	u64 frame_pa = 0;
	ulong flags = 0;
	u16 ssqn = 0;
	spinlock_t *prtq_state_lock = NULL;

	ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	sqe = &tmp_sqe;
	memset(sqe, 0, sizeof(struct spfc_sqe));

	parent_sq_info = &prt_queue_info->parent_sq_info;
	hot_tag = (u16)UNF_GET_HOTPOOL_TAG(pkg) + hba->exi_base;

	spfc_get_pkt_cmnd_type_code(pkg, &ls_gs_cmnd_code, &ls_gs_cmnd_type);

	ret = spfc_get_frame_info(hba, pkg, &frame_pld_addr, &frame_pld_len,
				  &frame_pa, &acc_pld_len);
	if (ret != RETURN_OK)
		return ret;

	if (SPFC_PKG_IS_ELS_RSP(ls_gs_cmnd_type)) {
		remote_exid = UNF_GET_OXID(pkg);
		spfc_build_els_wqe_ts_rsp(sqe, prt_queue_info, pkg,
					  frame_pld_addr, ls_gs_cmnd_type,
					  ls_gs_cmnd_code);

		/* Assemble the SQE Task Section Els Common part */
		spfc_build_service_wqe_ts_common(&sqe->ts_sl, parent_sq_info->rport_index,
						 UNF_GET_RXID(pkg), remote_exid,
						 SPFC_LSW(frame_pld_len));
	} else {
		remote_exid = UNF_GET_RXID(pkg);
		/* send els req ,only use local_xid for hotpooltag */
		spfc_build_els_wqe_ts_req(sqe, parent_sq_info,
					  prt_queue_info->parent_sts_scq_info.cqm_queue_id,
					  frame_pld_addr, pkg);
		spfc_build_service_wqe_ts_common(&sqe->ts_sl, parent_sq_info->rport_index, hot_tag,
						 remote_exid, SPFC_LSW(frame_pld_len));
	}
	/* Assemble the SQE Control Section part */
	spfc_build_service_wqe_ctrl_section(&sqe->ctrl_sl, SPFC_BYTES_TO_QW_NUM(SPFC_SQE_TS_SIZE),
					    SPFC_BYTES_TO_QW_NUM(sizeof(struct spfc_variable_sge)));

	/* Build SGE */
	spfc_build_els_gs_wqe_sge(sqe, frame_pld_addr, frame_pa, frame_pld_len,
				  parent_sq_info->context_id, hba);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) RPort(0x%x) send ELS/GS Type(0x%x) Code(0x%x) HotTag(0x%x)",
		     hba->port_cfg.port_id, parent_sq_info->rport_index, ls_gs_cmnd_type,
		     ls_gs_cmnd_code, hot_tag);
	if (ls_gs_cmnd_code == ELS_PLOGI || ls_gs_cmnd_code == ELS_LOGO) {
		ret = spfc_suspend_sqe_and_send_nop(hba, prt_queue_info, sqe, pkg);
		return ret;
	}
	prtq_state_lock = &prt_queue_info->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flags);
	if (SPFC_RPORT_NOT_OFFLOADED(prt_queue_info)) {
		spin_unlock_irqrestore(prtq_state_lock, flags);
		/* Send PLOGI or PLOGI ACC or SCR if session not offload */
		ret = spfc_send_els_via_default_session(hba, sqe, pkg, prt_queue_info);
	} else {
		spin_unlock_irqrestore(prtq_state_lock, flags);
		ret = spfc_parent_sq_enqueue(parent_sq_info, sqe, ssqn);
	}

	return ret;
}

u32 spfc_send_ls_gs_cmnd(void *handle, struct unf_frame_pkg *pkg)
{
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_hba_info *hba = NULL;
	struct spfc_parent_queue_info *prt_qinfo = NULL;
	u16 ls_gs_cmnd_code = SPFC_ZERO;
	union unf_sfs_u *sfs_entry = NULL;
	struct unf_rrq *rrq_pld = NULL;
	u16 ox_id = 0;
	u16 rx_id = 0;

	/* Check Parameters */
	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(UNF_GET_SFS_ENTRY(pkg), UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(SPFC_GET_CMND_PAYLOAD_ADDR(pkg), UNF_RETURN_ERROR);

	SPFC_CHECK_PKG_ALLOCTIME(pkg);
	hba = (struct spfc_hba_info *)handle;
	ls_gs_cmnd_code = SPFC_GET_LS_GS_CMND_CODE(pkg->cmnd);

	/* If RRQ Req, Special processing */
	if (ls_gs_cmnd_code == ELS_RRQ) {
		sfs_entry = UNF_GET_SFS_ENTRY(pkg);
		rrq_pld = &sfs_entry->rrq;
		ox_id = (u16)(rrq_pld->oxid_rxid >> UNF_SHIFT_16);
		rx_id = (u16)(rrq_pld->oxid_rxid & SPFC_RXID_MASK);
		rrq_pld->oxid_rxid = (u32)ox_id << UNF_SHIFT_16 | rx_id;
	}

	prt_qinfo = spfc_find_parent_queue_info_by_pkg(hba, pkg);
	ret = spfc_check_parent_qinfo_valid(hba, pkg, &prt_qinfo);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[error]Port(0x%x) send ELS/GS SID(0x%x) DID(0x%x) check qinfo invalid",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);
		return UNF_RETURN_ERROR;
	}

	ret = spfc_send_ls_gs_via_parent(hba, pkg, prt_qinfo);

	return ret;
}

void spfc_save_login_parms_in_sq_info(struct spfc_hba_info *hba,
				      struct unf_port_login_parms *login_params)
{
	u32 rport_index = login_params->rport_index;
	struct spfc_parent_sq_info *parent_sq_info = NULL;

	if (rport_index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) save login parms,but uplevel alloc invalid rport index: 0x%x",
			     hba->port_cfg.port_id, rport_index);

		return;
	}

	parent_sq_info = &hba->parent_queue_mgr->parent_queue[rport_index].parent_sq_info;

	parent_sq_info->plogi_co_parms.seq_cnt = login_params->seq_cnt;
	parent_sq_info->plogi_co_parms.ed_tov = login_params->ed_tov;
	parent_sq_info->plogi_co_parms.tx_mfs = (login_params->tx_mfs <
						 SPFC_DEFAULT_TX_MAX_FREAM_SIZE) ?
						 SPFC_DEFAULT_TX_MAX_FREAM_SIZE :
						 login_params->tx_mfs;
	parent_sq_info->plogi_co_parms.ed_tov_time = login_params->ed_tov_timer_val;
}

static void
spfc_recover_offloading_state(struct spfc_parent_queue_info *prt_queue_info,
			      enum spfc_parent_queue_state offload_state)
{
	ulong flags = 0;

	spin_lock_irqsave(&prt_queue_info->parent_queue_state_lock, flags);

	if (prt_queue_info->offload_state == SPFC_QUEUE_STATE_OFFLOADING)
		prt_queue_info->offload_state = offload_state;

	spin_unlock_irqrestore(&prt_queue_info->parent_queue_state_lock, flags);
}

static bool spfc_check_need_delay_offload(void *hba, struct unf_frame_pkg *pkg, u32 rport_index,
					  struct spfc_parent_queue_info *cur_prt_queue_info,
					  struct spfc_parent_queue_info **offload_prt_queue_info)
{
	ulong flags = 0;
	struct spfc_parent_queue_info *prt_queue_info = NULL;
	spinlock_t *prtq_state_lock = NULL;

	prtq_state_lock = &cur_prt_queue_info->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flags);

	if (cur_prt_queue_info->offload_state == SPFC_QUEUE_STATE_OFFLOADING) {
		spin_unlock_irqrestore(prtq_state_lock, flags);

		prt_queue_info = spfc_find_offload_parent_queue(hba, pkg->frame_head.csctl_sid &
								UNF_NPORTID_MASK,
								pkg->frame_head.rctl_did &
								UNF_NPORTID_MASK, rport_index);
		if (prt_queue_info) {
			*offload_prt_queue_info = prt_queue_info;
			return true;
		}
	} else {
		spin_unlock_irqrestore(prtq_state_lock, flags);
	}

	return false;
}

static u16 spfc_build_wqe_with_offload(struct spfc_hba_info *hba, struct spfc_sqe *sqe,
				       struct spfc_parent_queue_info *prt_queue_info,
				       struct unf_frame_pkg *pkg,
				       enum spfc_parent_queue_state last_offload_state)
{
	u32 tx_mfs = 2048;
	u32 edtov_timer = 2000;
	dma_addr_t ctx_pa = 0;
	u16 els_cmnd_type = SPFC_ZERO;
	u16 els_cmnd_code = SPFC_ZERO;
	void *ctx_va = NULL;
	struct spfc_parent_context *parent_ctx_info = NULL;
	struct spfc_sw_section *sw_setction = NULL;
	struct spfc_parent_sq_info *parent_sq_info = &prt_queue_info->parent_sq_info;
	u16 offload_flag = 0;

	els_cmnd_type = SPFC_GET_ELS_RSP_TYPE(pkg->cmnd);
	if (SPFC_PKG_IS_ELS_RSP(els_cmnd_type)) {
		els_cmnd_code = SPFC_GET_ELS_RSP_CODE(pkg->cmnd);
	} else {
		els_cmnd_code = els_cmnd_type;
		els_cmnd_type = ELS_CMND;
	}

	offload_flag = SPFC_CHECK_NEED_OFFLOAD(els_cmnd_code, els_cmnd_type, last_offload_state);

	parent_ctx_info = (struct spfc_parent_context *)(prt_queue_info->parent_ctx.parent_ctx);
	sw_setction = &parent_ctx_info->sw_section;

	sw_setction->tx_mfs = cpu_to_be16((u16)(tx_mfs));
	sw_setction->e_d_tov_timer_val = cpu_to_be32(edtov_timer);

	spfc_big_to_cpu32(&sw_setction->sw_ctxt_misc.pctxt_val0,
			  sizeof(sw_setction->sw_ctxt_misc.pctxt_val0));
	sw_setction->sw_ctxt_misc.dw.port_id = SPFC_GET_NETWORK_PORT_ID(hba);
	spfc_cpu_to_big32(&sw_setction->sw_ctxt_misc.pctxt_val0,
			  sizeof(sw_setction->sw_ctxt_misc.pctxt_val0));

	spfc_big_to_cpu32(&sw_setction->sw_ctxt_config.pctxt_val1,
			  sizeof(sw_setction->sw_ctxt_config.pctxt_val1));
	spfc_cpu_to_big32(&sw_setction->sw_ctxt_config.pctxt_val1,
			  sizeof(sw_setction->sw_ctxt_config.pctxt_val1));

	/* Fill in contex to the chip */
	ctx_pa = prt_queue_info->parent_ctx.cqm_parent_ctx_obj->paddr;
	ctx_va = prt_queue_info->parent_ctx.cqm_parent_ctx_obj->vaddr;

	/* No need write key and no need do BIG TO CPU32 */
	memcpy(ctx_va, prt_queue_info->parent_ctx.parent_ctx, sizeof(struct spfc_parent_context));

	if (SPFC_PKG_IS_ELS_RSP(els_cmnd_type)) {
		sqe->ts_sl.cont.els_rsp.context_gpa_hi = SPFC_HIGH_32_BITS(ctx_pa);
		sqe->ts_sl.cont.els_rsp.context_gpa_lo = SPFC_LOW_32_BITS(ctx_pa);
		sqe->ts_sl.cont.els_rsp.wd1.offload_flag = offload_flag;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]sid 0x%x, did 0x%x, GPA HIGH 0x%x,GPA LOW 0x%x, scq 0x%x,offload flag 0x%x",
			     parent_sq_info->local_port_id,
			     parent_sq_info->remote_port_id,
			     sqe->ts_sl.cont.els_rsp.context_gpa_hi,
			     sqe->ts_sl.cont.els_rsp.context_gpa_lo,
			     prt_queue_info->parent_sts_scq_info.cqm_queue_id,
			     offload_flag);
	} else {
		sqe->ts_sl.cont.t_els_gs.context_gpa_hi = SPFC_HIGH_32_BITS(ctx_pa);
		sqe->ts_sl.cont.t_els_gs.context_gpa_lo =  SPFC_LOW_32_BITS(ctx_pa);
		sqe->ts_sl.cont.t_els_gs.wd4.offload_flag = offload_flag;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]sid 0x%x, did 0x%x, GPA HIGH 0x%x,GPA LOW 0x%x, scq 0x%x,offload flag 0x%x",
			     parent_sq_info->local_port_id,
			     parent_sq_info->remote_port_id,
			     sqe->ts_sl.cont.t_els_gs.context_gpa_hi,
			     sqe->ts_sl.cont.t_els_gs.context_gpa_lo,
			     prt_queue_info->parent_sts_scq_info.cqm_queue_id,
			     offload_flag);
	}

	if (offload_flag) {
		prt_queue_info->offload_state = SPFC_QUEUE_STATE_OFFLOADING;
		parent_sq_info->need_offloaded = SPFC_NEED_DO_OFFLOAD;
	}

	return offload_flag;
}

u32 spfc_send_els_via_default_session(struct spfc_hba_info *hba, struct spfc_sqe *io_sqe,
				      struct unf_frame_pkg *pkg,
				      struct spfc_parent_queue_info *prt_queue_info)
{
	ulong flags = 0;
	bool sqe_delay = false;
	u32 ret = UNF_RETURN_ERROR;
	u16 els_cmnd_code = SPFC_ZERO;
	u16 els_cmnd_type = SPFC_ZERO;
	u16 ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	u32 rport_index = pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX];
	struct spfc_sqe *sqe = io_sqe;
	struct spfc_parent_queue_info *default_prt_queue_info = NULL;
	struct spfc_parent_sq_info *parent_sq_info = &prt_queue_info->parent_sq_info;
	struct spfc_parent_queue_info *offload_queue_info = NULL;
	enum spfc_parent_queue_state last_offload_state = SPFC_QUEUE_STATE_INITIALIZED;
	struct spfc_delay_destroy_ctrl_info delay_ctl_info;
	u16 offload_flag = 0;
	u32 default_index = SPFC_DEFAULT_RPORT_INDEX;

	memset(&delay_ctl_info, 0, sizeof(struct spfc_delay_destroy_ctrl_info));
	/* Determine the ELS type in pkg */
	els_cmnd_type = SPFC_GET_LS_GS_CMND_CODE(pkg->cmnd);

	if (SPFC_PKG_IS_ELS_RSP(els_cmnd_type)) {
		els_cmnd_code = SPFC_GET_ELS_RSP_CODE(pkg->cmnd);
	} else {
		els_cmnd_code = els_cmnd_type;
		els_cmnd_type = ELS_CMND;
	}

	spin_lock_irqsave(&prt_queue_info->parent_queue_state_lock, flags);

	last_offload_state = prt_queue_info->offload_state;

	offload_flag = spfc_build_wqe_with_offload(hba, sqe, prt_queue_info,
						   pkg, last_offload_state);

	spin_unlock_irqrestore(&prt_queue_info->parent_queue_state_lock, flags);

	if (!offload_flag) {
		default_prt_queue_info = &hba->parent_queue_mgr->parent_queue[default_index];
		if (!default_prt_queue_info) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[ERR]cmd(0x%x), type(0x%x) send fail, default session null",
				     els_cmnd_code, els_cmnd_type);
			return UNF_RETURN_ERROR;
		}
		parent_sq_info = &default_prt_queue_info->parent_sq_info;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]cmd(0x%x), type(0x%x) send via default session",
			     els_cmnd_code, els_cmnd_type);
	} else {
		/* Need this xid to judge delay offload, when Sqe Enqueue will
		 * write again
		 */
		sqe->ts_sl.xid = parent_sq_info->context_id;
		sqe_delay = spfc_check_need_delay_offload(hba, pkg, rport_index, prt_queue_info,
							  &offload_queue_info);

		if (sqe_delay) {
			ret = spfc_push_delay_sqe(hba, offload_queue_info, sqe, pkg);
			if (ret == RETURN_OK) {
				spfc_recover_offloading_state(prt_queue_info, last_offload_state);
				return ret;
			}
		}
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]cmd(0x%x), type(0x%x) do secretly offload",
			     els_cmnd_code, els_cmnd_type);
	}

	ret = spfc_parent_sq_enqueue(parent_sq_info, sqe, ssqn);

	if (ret != RETURN_OK) {
		spfc_recover_offloading_state(prt_queue_info, last_offload_state);

		spin_lock_irqsave(&prt_queue_info->parent_queue_state_lock,
				  flags);

		if (prt_queue_info->parent_sq_info.destroy_sqe.valid) {
			memcpy(&delay_ctl_info, &prt_queue_info->parent_sq_info.destroy_sqe,
			       sizeof(struct spfc_delay_destroy_ctrl_info));

			prt_queue_info->parent_sq_info.destroy_sqe.valid = false;
		}

		spin_unlock_irqrestore(&prt_queue_info->parent_queue_state_lock, flags);

		spfc_pop_destroy_parent_queue_sqe((void *)hba, &delay_ctl_info);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) send ELS Type(0x%x) Code(0x%x) fail,recover offloadstatus(%u)",
			     hba->port_cfg.port_id, rport_index, els_cmnd_type,
			     els_cmnd_code, prt_queue_info->offload_state);
	}

	return ret;
}

static u32 spfc_rcv_ls_gs_rsp_payload(struct spfc_hba_info *hba,
				      struct unf_frame_pkg *pkg, u32 hot_tag,
				      u8 *els_pld_buf, u32 pld_len)
{
	u32 ret = UNF_RETURN_ERROR;

	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;
	if (pkg->type == UNF_PKG_GS_REQ_DONE)
		spfc_big_to_cpu32(els_pld_buf, pld_len);
	else
		pkg->byte_orders |= SPFC_BIT_2;

	pkg->unf_cmnd_pload_bl.buffer_ptr = els_pld_buf;
	pkg->unf_cmnd_pload_bl.length = pld_len;

	pkg->last_pkg_flag = UNF_PKG_NOT_LAST_RESPONSE;

	UNF_LOWLEVEL_RECEIVE_LS_GS_PKG(ret, hba->lport, pkg);

	return ret;
}

u32 spfc_scq_recv_abts_rsp(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	/* Default path, which is sent from SCQ to the driver */
	u8 status = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 ox_id = INVALID_VALUE32;
	u32 hot_tag = INVALID_VALUE32;
	struct unf_frame_pkg pkg = {0};
	struct spfc_scqe_rcv_abts_rsp *abts_rsp = NULL;

	abts_rsp = &scqe->rcv_abts_rsp;
	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = abts_rsp->magic_num;

	ox_id = (u32)(abts_rsp->wd0.ox_id);

	hot_tag = abts_rsp->wd1.hotpooltag & UNF_ORIGIN_HOTTAG_MASK;
	if (unlikely(hot_tag < (u32)hba->exi_base ||
		     hot_tag >= (u32)(hba->exi_base + hba->exi_count))) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) has bad HotTag(0x%x) for bls_rsp",
			     hba->port_cfg.port_id, hot_tag);

		status = UNF_IO_FAILED;
		hot_tag = INVALID_VALUE32;
	} else {
		hot_tag -= hba->exi_base;
		if (unlikely(SPFC_SCQE_HAS_ERRCODE(scqe))) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) BLS response has error code(0x%x) tag(0x%x)",
				     hba->port_cfg.port_id,
				     SPFC_GET_SCQE_STATUS(scqe), (u32)hot_tag);

			status = UNF_IO_FAILED;
		} else {
			pkg.frame_head.rctl_did = abts_rsp->wd3.did;
			pkg.frame_head.csctl_sid = abts_rsp->wd4.sid;
			pkg.frame_head.oxid_rxid = (u32)(abts_rsp->wd0.rx_id) | ox_id <<
						    UNF_SHIFT_16;

			/* BLS_ACC/BLS_RJT: IO_succeed */
			if (abts_rsp->wd2.fh_rctrl == SPFC_RCTL_BLS_ACC) {
				status = UNF_IO_SUCCESS;
			} else if (abts_rsp->wd2.fh_rctrl == SPFC_RCTL_BLS_RJT) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
					     "[info]Port(0x%x) ABTS RJT: %08x-%08x-%08x",
					     hba->port_cfg.port_id,
					     abts_rsp->payload[ARRAY_INDEX_0],
					     abts_rsp->payload[ARRAY_INDEX_1],
					     abts_rsp->payload[ARRAY_INDEX_2]);

				status = UNF_IO_SUCCESS;
			} else {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
					     "[err]Port(0x%x) BLS response RCTL is error",
					     hba->port_cfg.port_id);
				SPFC_ERR_IO_STAT(hba, SPFC_SCQE_ABTS_RSP);
				status = UNF_IO_FAILED;
			}
		}
	}

	/* Set PKG/exchange status & Process BLS_RSP */
	pkg.status = status;
	ret = spfc_rcv_bls_rsp(hba, &pkg, hot_tag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) recv ABTS rsp OX_ID(0x%x) RX_ID(0x%x) HotTag(0x%x) SID(0x%x) DID(0x%x) %s",
		     hba->port_cfg.port_id, ox_id, abts_rsp->wd0.rx_id, hot_tag,
		     abts_rsp->wd4.sid, abts_rsp->wd3.did,
		     (ret == RETURN_OK) ? "OK" : "ERROR");

	return ret;
}

u32 spfc_recv_els_cmnd(const struct spfc_hba_info *hba,
		       struct unf_frame_pkg *pkg, u8 *els_pld, u32 pld_len,
		       bool first)
{
	u32 ret = UNF_RETURN_ERROR;

	/* Convert Payload to small endian */
	spfc_big_to_cpu32(els_pld, pld_len);

	pkg->type = UNF_PKG_ELS_REQ;

	pkg->unf_cmnd_pload_bl.buffer_ptr = els_pld;

	/* Payload length */
	pkg->unf_cmnd_pload_bl.length = pld_len;

	/* Obtain the Cmnd type from the Paylaod. The Cmnd is in small endian */
	if (first)
		pkg->cmnd = UNF_GET_FC_PAYLOAD_ELS_CMND(pkg->unf_cmnd_pload_bl.buffer_ptr);

	/* Errors have been processed in SPFC_RecvElsError */
	pkg->status = UNF_IO_SUCCESS;

	/* Send PKG to the CM layer */
	UNF_LOWLEVEL_RECEIVE_LS_GS_PKG(ret, hba->lport, pkg);

	if (ret != RETURN_OK) {
		pkg->rx_or_ox_id = UNF_PKG_FREE_RXID;
		pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = INVALID_VALUE32;
		pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = INVALID_VALUE32;
		ret = spfc_free_xid((void *)hba, pkg);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) recv %s ox_id(0x%x) RXID(0x%x) PldLen(0x%x) failed, Free xid %s",
			     hba->port_cfg.port_id,
			     UNF_GET_FC_HEADER_RCTL(&pkg->frame_head) == SPFC_FC_RCTL_ELS_REQ ?
			     "ELS REQ" : "ELS RSP",
			     UNF_GET_OXID(pkg), UNF_GET_RXID(pkg), pld_len,
			     (ret == RETURN_OK) ? "OK" : "ERROR");
	}

	return ret;
}

u32 spfc_rcv_ls_gs_rsp(const struct spfc_hba_info *hba,
		       struct unf_frame_pkg *pkg, u32 hot_tag)
{
	u32 ret = UNF_RETURN_ERROR;

	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;
	if (pkg->type == UNF_PKG_ELS_REQ_DONE)
		pkg->byte_orders |= SPFC_BIT_2;

	pkg->last_pkg_flag = UNF_PKG_LAST_RESPONSE;

	UNF_LOWLEVEL_RECEIVE_LS_GS_PKG(ret, hba->lport, pkg);

	return ret;
}

u32 spfc_rcv_els_rsp_sts(const struct spfc_hba_info *hba,
			 struct unf_frame_pkg *pkg, u32 hot_tag)
{
	u32 ret = UNF_RETURN_ERROR;

	pkg->type = UNF_PKG_ELS_REPLY_DONE;
	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;

	UNF_LOWLEVEL_SEND_ELS_DONE(ret, hba->lport, pkg);

	return ret;
}

u32 spfc_rcv_bls_rsp(const struct spfc_hba_info *hba, struct unf_frame_pkg *pkg,
		     u32 hot_tag)
{
	/*
	 * 1. SCQ (normal)
	 * 2. from Root RQ (parent no existence)
	 * *
	 * single frame, single sequence
	 */
	u32 ret = UNF_RETURN_ERROR;

	pkg->type = UNF_PKG_BLS_REQ_DONE;
	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;
	pkg->last_pkg_flag = UNF_PKG_LAST_RESPONSE;

	UNF_LOWLEVEL_RECEIVE_BLS_PKG(ret, hba->lport, pkg);

	return ret;
}

u32 spfc_rsv_bls_rsp_sts(const struct spfc_hba_info *hba,
			 struct unf_frame_pkg *pkg, u32 rx_id)
{
	u32 ret = UNF_RETURN_ERROR;

	pkg->type = UNF_PKG_BLS_REPLY_DONE;
	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = rx_id;

	UNF_LOWLEVEL_RECEIVE_BLS_PKG(ret, hba->lport, pkg);

	return ret;
}

u32 spfc_rcv_tmf_marker_sts(const struct spfc_hba_info *hba,
			    struct unf_frame_pkg *pkg, u32 hot_tag)
{
	u32 ret = UNF_RETURN_ERROR;

	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;

	/* Send PKG info to COM */
	UNF_LOWLEVEL_RECEIVE_MARKER_STS(ret, hba->lport, pkg);

	return ret;
}

u32 spfc_rcv_abts_marker_sts(const struct spfc_hba_info *hba,
			     struct unf_frame_pkg *pkg, u32 hot_tag)
{
	u32 ret = UNF_RETURN_ERROR;

	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;

	UNF_LOWLEVEL_RECEIVE_ABTS_MARKER_STS(ret, hba->lport, pkg);

	return ret;
}

static void spfc_scqe_error_pre_proc(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	/* Currently, only printing and statistics collection are performed */
	SPFC_ERR_IO_STAT(hba, SPFC_GET_SCQE_TYPE(scqe));
	SPFC_SCQ_ERR_TYPE_STAT(hba, SPFC_GET_SCQE_STATUS(scqe));

	FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_WARN,
		     "[warn]Port(0x%x)-Task_type(%u) SCQE contain error code(%u),additional info(0x%x)",
		     hba->port_cfg.port_id, scqe->common.ch.wd0.task_type,
		     scqe->common.ch.wd0.err_code, scqe->common.conn_id);
}

void *spfc_get_els_buf_by_user_id(struct spfc_hba_info *hba, u16 user_id)
{
	struct spfc_drq_buff_entry *srq_buf_entry = NULL;
	struct spfc_srq_info *srq_info = NULL;

	FC_CHECK_RETURN_VALUE(hba, NULL);

	srq_info = &hba->els_srq_info;
	FC_CHECK_RETURN_VALUE(user_id < srq_info->valid_wqe_num, NULL);

	srq_buf_entry = &srq_info->els_buff_entry_head[user_id];

	return srq_buf_entry->buff_addr;
}

static u32 spfc_check_srq_buf_valid(struct spfc_hba_info *hba,
				    u16 *buf_id_array, u32 buf_num)
{
	u32 index = 0;
	u32 buf_id = 0;
	void *srq_buf = NULL;

	for (index = 0; index < buf_num; index++) {
		buf_id = buf_id_array[index];

		if (buf_id < hba->els_srq_info.valid_wqe_num)
			srq_buf = spfc_get_els_buf_by_user_id(hba, (u16)buf_id);
		else
			srq_buf = NULL;

		if (!srq_buf) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) get srq buffer user id(0x%x) is null",
				     hba->port_cfg.port_id, buf_id);

			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

static void spfc_reclaim_srq_buf(struct spfc_hba_info *hba, u16 *buf_id_array,
				 u32 buf_num)
{
	u32 index = 0;
	u32 buf_id = 0;
	void *srq_buf = NULL;

	for (index = 0; index < buf_num; index++) {
		buf_id = buf_id_array[index];
		if (buf_id < hba->els_srq_info.valid_wqe_num)
			srq_buf = spfc_get_els_buf_by_user_id(hba, (u16)buf_id);
		else
			srq_buf = NULL;

		/* If the value of buffer is NULL, it indicates that the value
		 * of buffer is invalid. In this case, exit directly.
		 */
		if (!srq_buf)
			break;

		spfc_post_els_srq_wqe(&hba->els_srq_info, (u16)buf_id);
	}
}

static u32 spfc_check_ls_gs_valid(struct spfc_hba_info *hba, union spfc_scqe *scqe,
				  struct unf_frame_pkg *pkg, u16 *buf_id_array,
				  u32 buf_num, u32 frame_len)
{
	u32 hot_tag;

	hot_tag = UNF_GET_HOTPOOL_TAG(pkg);

	/* The ELS CMD returns an error code and discards it directly */
	if ((sizeof(struct spfc_fc_frame_header) > frame_len) ||
	    (SPFC_SCQE_HAS_ERRCODE(scqe)) || buf_num > SPFC_ELS_SRQ_BUF_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) get scqe type(0x%x) payload len(0x%x),scq status(0x%x),user id num(0x%x) abnormal",
			     hba->port_cfg.port_id, SPFC_GET_SCQE_TYPE(scqe), frame_len,
			     SPFC_GET_SCQE_STATUS(scqe), buf_num);

		/* ELS RSP Special Processing */
		if (SPFC_GET_SCQE_TYPE(scqe) == SPFC_SCQE_ELS_RSP ||
		    SPFC_GET_SCQE_TYPE(scqe) == SPFC_SCQE_GS_RSP) {
			if (SPFC_SCQE_ERR_TO_CM(scqe)) {
				pkg->status = UNF_IO_FAILED;
				(void)spfc_rcv_ls_gs_rsp(hba, pkg, hot_tag);
			} else {
				if (SPFC_GET_SCQE_TYPE(scqe) == SPFC_SCQE_ELS_RSP)
					SPFC_HBA_STAT(hba, SPFC_STAT_ELS_RSP_EXCH_REUSE);
				else
					SPFC_HBA_STAT(hba, SPFC_STAT_GS_RSP_EXCH_REUSE);
			}
		}

		/* Reclaim srq */
		if (buf_num <= SPFC_ELS_SRQ_BUF_NUM)
			spfc_reclaim_srq_buf(hba, buf_id_array, buf_num);

		return UNF_RETURN_ERROR;
	}

	/* ELS CMD Check the validity of the buffer sent by the ucode */
	if (SPFC_GET_SCQE_TYPE(scqe) == SPFC_SCQE_ELS_CMND) {
		if (spfc_check_srq_buf_valid(hba, buf_id_array, buf_num) != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) get els cmnd scqe user id num(0x%x) abnormal, as some srq buff is null",
				     hba->port_cfg.port_id, buf_num);

			spfc_reclaim_srq_buf(hba, buf_id_array, buf_num);

			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

u32 spfc_scq_recv_els_cmnd(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 ret = RETURN_OK;
	u32 pld_len = 0;
	u32 header_len = 0;
	u32 frame_len = 0;
	u32 rcv_data_len = 0;
	u32 max_buf_num = 0;
	u16 buf_id = 0;
	u32 index = 0;
	u8 *pld_addr = NULL;
	struct unf_frame_pkg pkg = {0};
	struct spfc_scqe_rcv_els_cmd *els_cmd = NULL;
	struct spfc_fc_frame_header *els_frame = NULL;
	struct spfc_fc_frame_header tmp_frame = {0};
	void *els_buf = NULL;
	bool first = false;

	els_cmd = &scqe->rcv_els_cmd;
	frame_len = els_cmd->wd3.data_len;
	max_buf_num = els_cmd->wd3.user_id_num;
	spfc_swap_16_in_32((u32 *)els_cmd->user_id, SPFC_LS_GS_USERID_LEN);

	pkg.xchg_contex = NULL;
	pkg.status = UNF_IO_SUCCESS;

	/* Check the validity of error codes and buff. If an exception occurs,
	 * discard the error code
	 */
	ret = spfc_check_ls_gs_valid(hba, scqe, &pkg, els_cmd->user_id,
				     max_buf_num, frame_len);
	if (ret != RETURN_OK) {
		pkg.rx_or_ox_id = UNF_PKG_FREE_RXID;
		pkg.frame_head.oxid_rxid =
		    (u32)(els_cmd->wd2.rx_id) | (u32)(els_cmd->wd2.ox_id) << UNF_SHIFT_16;
		pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = INVALID_VALUE32;
		pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = INVALID_VALUE32;
		pkg.frame_head.csctl_sid = els_cmd->wd1.sid;
		pkg.frame_head.rctl_did = els_cmd->wd0.did;
		spfc_free_xid((void *)hba, &pkg);
		return RETURN_OK;
	}

	/* Send data to COM cyclically */
	for (index = 0; index < max_buf_num; index++) {
		/* Exception record, which is not processed currently */
		if (rcv_data_len >= frame_len) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) get els cmd date len(0x%x) is bigger than fream len(0x%x)",
				     hba->port_cfg.port_id, rcv_data_len, frame_len);
		}

		buf_id = (u16)els_cmd->user_id[index];
		els_buf = spfc_get_els_buf_by_user_id(hba, buf_id);

		/* Obtain playload address */
		pld_addr = (u8 *)(els_buf);
		header_len = 0;
		first = false;
		if (index == 0) {
			els_frame = (struct spfc_fc_frame_header *)els_buf;
			pld_addr = (u8 *)(els_frame + 1);

			header_len = sizeof(struct spfc_fc_frame_header);
			first = true;

			memcpy(&tmp_frame, els_frame, sizeof(struct spfc_fc_frame_header));
			spfc_big_to_cpu32(&tmp_frame, sizeof(struct spfc_fc_frame_header));
			memcpy(&pkg.frame_head, &tmp_frame, sizeof(pkg.frame_head));
			pkg.frame_head.oxid_rxid = (u32)((pkg.frame_head.oxid_rxid &
							 SPFC_OXID_MASK) | (els_cmd->wd2.rx_id));
		}

		/* Calculate the playload length */
		pkg.last_pkg_flag = 0;
		pld_len = SPFC_SRQ_ELS_SGE_LEN;

		if ((rcv_data_len + SPFC_SRQ_ELS_SGE_LEN) >= frame_len) {
			pkg.last_pkg_flag = 1;
			pld_len = frame_len - rcv_data_len;
		}

		pkg.class_mode = els_cmd->wd0.class_mode;

		/* Push data to COM */
		if (ret == RETURN_OK) {
			ret = spfc_recv_els_cmnd(hba, &pkg, pld_addr,
						 (pld_len - header_len), first);
		}

		/* Reclaim srq buffer */
		spfc_post_els_srq_wqe(&hba->els_srq_info, buf_id);

		rcv_data_len += pld_len;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) recv ELS Type(0x%x) Cmnd(0x%x) ox_id(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) %u",
		     hba->port_cfg.port_id, pkg.type, pkg.cmnd, els_cmd->wd2.ox_id,
		     els_cmd->wd2.rx_id, els_cmd->wd1.sid, els_cmd->wd0.did, ret);

	return ret;
}

static u32 spfc_get_ls_gs_pld_len(struct spfc_hba_info *hba, u32 rcv_data_len, u32 frame_len)
{
	u32 pld_len;

	/* Exception record, which is not processed currently */
	if (rcv_data_len >= frame_len) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) get els rsp data len(0x%x) is bigger than fream len(0x%x)",
			     hba->port_cfg.port_id, rcv_data_len, frame_len);
	}

	pld_len = SPFC_SRQ_ELS_SGE_LEN;
	if ((rcv_data_len + SPFC_SRQ_ELS_SGE_LEN) >= frame_len)
		pld_len = frame_len - rcv_data_len;

	return pld_len;
}

u32 spfc_scq_recv_ls_gs_rsp(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 ret = RETURN_OK;
	u32 pld_len = 0;
	u32 header_len = 0;
	u32 frame_len = 0;
	u32 rcv_data_len = 0;
	u32 max_buf_num = 0;
	u16 buf_id = 0;
	u32 hot_tag = INVALID_VALUE32;
	u32 index = 0;
	u32 ox_id = (~0);
	struct unf_frame_pkg pkg = {0};
	struct spfc_scqe_rcv_els_gs_rsp *ls_gs_rsp_scqe = NULL;
	struct spfc_fc_frame_header *els_frame = NULL;
	void *ls_gs_buf = NULL;
	u8 *pld_addr = NULL;
	u8 task_type;

	ls_gs_rsp_scqe = &scqe->rcv_els_gs_rsp;
	frame_len = ls_gs_rsp_scqe->wd2.data_len;
	max_buf_num = ls_gs_rsp_scqe->wd4.user_id_num;
	spfc_swap_16_in_32((u32 *)ls_gs_rsp_scqe->user_id, SPFC_LS_GS_USERID_LEN);

	ox_id = ls_gs_rsp_scqe->wd1.ox_id;
	hot_tag = ((u16)(ls_gs_rsp_scqe->wd5.hotpooltag) & UNF_ORIGIN_HOTTAG_MASK) - hba->exi_base;
	pkg.frame_head.oxid_rxid = (u32)(ls_gs_rsp_scqe->wd1.rx_id) | ox_id << UNF_SHIFT_16;
	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = ls_gs_rsp_scqe->magic_num;
	pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = hot_tag;
	pkg.frame_head.csctl_sid = ls_gs_rsp_scqe->wd4.sid;
	pkg.frame_head.rctl_did = ls_gs_rsp_scqe->wd3.did;
	pkg.status = UNF_IO_SUCCESS;
	pkg.type = UNF_PKG_ELS_REQ_DONE;

	task_type = SPFC_GET_SCQE_TYPE(scqe);
	if (task_type == SPFC_SCQE_GS_RSP) {
		if (ls_gs_rsp_scqe->wd3.end_rsp)
			SPFC_HBA_STAT(hba, SPFC_STAT_LAST_GS_SCQE);
		pkg.type = UNF_PKG_GS_REQ_DONE;
	}

	/* Handle the exception first. The LS/GS RSP returns the error code.
	 * Only the ox_id can submit the error code to the CM layer.
	 */
	ret = spfc_check_ls_gs_valid(hba, scqe, &pkg, ls_gs_rsp_scqe->user_id,
				     max_buf_num, frame_len);
	if (ret != RETURN_OK)
		return RETURN_OK;

	if (ls_gs_rsp_scqe->wd3.echo_rsp) {
		pkg.private_data[PKG_PRIVATE_ECHO_CMD_RCV_TIME] =
		    ls_gs_rsp_scqe->user_id[ARRAY_INDEX_5];
		pkg.private_data[PKG_PRIVATE_ECHO_RSP_SND_TIME] =
		    ls_gs_rsp_scqe->user_id[ARRAY_INDEX_6];
		pkg.private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME] =
		    ls_gs_rsp_scqe->user_id[ARRAY_INDEX_7];
		pkg.private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME] =
		    ls_gs_rsp_scqe->user_id[ARRAY_INDEX_8];
	}

	/* Send data to COM cyclically */
	for (index = 0; index < max_buf_num; index++) {
		/* Obtain buffer address */
		ls_gs_buf = NULL;
		buf_id = (u16)ls_gs_rsp_scqe->user_id[index];
		ls_gs_buf = spfc_get_els_buf_by_user_id(hba, buf_id);

		if (unlikely(!ls_gs_buf)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) ox_id(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) Index(0x%x) get els rsp buff user id(0x%x) abnormal",
				     hba->port_cfg.port_id, ox_id,
				     ls_gs_rsp_scqe->wd1.rx_id, ls_gs_rsp_scqe->wd4.sid,
				     ls_gs_rsp_scqe->wd3.did, index, buf_id);

			if (index == 0) {
				pkg.status = UNF_IO_FAILED;
				ret = spfc_rcv_ls_gs_rsp(hba, &pkg, hot_tag);
			}

			return ret;
		}

		header_len = 0;
		pld_addr = (u8 *)(ls_gs_buf);
		if (index == 0) {
			header_len = sizeof(struct spfc_fc_frame_header);
			els_frame = (struct spfc_fc_frame_header *)ls_gs_buf;
			pld_addr = (u8 *)(els_frame + 1);
		}

		/* Calculate the playload length */
		pld_len = spfc_get_ls_gs_pld_len(hba, rcv_data_len, frame_len);

		/* Push data to COM */
		if (ret == RETURN_OK) {
			ret = spfc_rcv_ls_gs_rsp_payload(hba, &pkg, hot_tag, pld_addr,
							 (pld_len - header_len));
		}

		/* Reclaim srq buffer */
		spfc_post_els_srq_wqe(&hba->els_srq_info, buf_id);

		rcv_data_len += pld_len;
	}

	if (ls_gs_rsp_scqe->wd3.end_rsp && ret == RETURN_OK)
		ret = spfc_rcv_ls_gs_rsp(hba, &pkg, hot_tag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) receive LS/GS RSP ox_id(0x%x) RXID(0x%x) SID(0x%x) DID(0x%x) end_rsp(0x%x) user_num(0x%x)",
		     hba->port_cfg.port_id, ox_id, ls_gs_rsp_scqe->wd1.rx_id,
		     ls_gs_rsp_scqe->wd4.sid, ls_gs_rsp_scqe->wd3.did,
		     ls_gs_rsp_scqe->wd3.end_rsp,
		     ls_gs_rsp_scqe->wd4.user_id_num);

	return ret;
}

u32 spfc_scq_recv_els_rsp_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 rx_id = INVALID_VALUE32;
	u32 hot_tag = INVALID_VALUE32;
	struct unf_frame_pkg pkg = {0};
	struct spfc_scqe_comm_rsp_sts *els_rsp_sts_scqe = NULL;

	els_rsp_sts_scqe = &scqe->comm_sts;
	rx_id = (u32)els_rsp_sts_scqe->wd0.rx_id;

	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    els_rsp_sts_scqe->magic_num;
	pkg.frame_head.oxid_rxid = rx_id | (u32)(els_rsp_sts_scqe->wd0.ox_id) << UNF_SHIFT_16;
	hot_tag = (u32)((els_rsp_sts_scqe->wd1.hotpooltag & UNF_ORIGIN_HOTTAG_MASK) -
		  hba->exi_base);

	if (unlikely(SPFC_SCQE_HAS_ERRCODE(scqe)))
		pkg.status = UNF_IO_FAILED;
	else
		pkg.status = UNF_IO_SUCCESS;

	ret = spfc_rcv_els_rsp_sts(hba, &pkg, hot_tag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) recv ELS RSP STS ox_id(0x%x) RXID(0x%x) HotTag(0x%x) %s",
		     hba->port_cfg.port_id, els_rsp_sts_scqe->wd0.ox_id, rx_id,
		     hot_tag, (ret == RETURN_OK) ? "OK" : "ERROR");

	return ret;
}

static u32 spfc_check_rport_valid(const struct spfc_parent_queue_info *prt_queue_info, u32 scqe_xid)
{
	if (prt_queue_info->parent_ctx.cqm_parent_ctx_obj) {
		if ((prt_queue_info->parent_sq_info.context_id & SPFC_CQM_XID_MASK) ==
		    (scqe_xid & SPFC_CQM_XID_MASK)) {
			return RETURN_OK;
		}
	}

	return UNF_RETURN_ERROR;
}

u32 spfc_scq_recv_offload_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 valid = UNF_RETURN_ERROR;
	u32 rport_index = 0;
	u32 cid = 0;
	u32 xid = 0;
	ulong flags = 0;
	struct spfc_parent_queue_info *prt_qinfo = NULL;
	struct spfc_parent_sq_info *parent_sq_info = NULL;
	struct spfc_scqe_sess_sts *offload_sts_scqe = NULL;
	struct spfc_delay_destroy_ctrl_info delay_ctl_info;

	memset(&delay_ctl_info, 0, sizeof(struct spfc_delay_destroy_ctrl_info));
	offload_sts_scqe = &scqe->sess_sts;
	rport_index = offload_sts_scqe->wd1.conn_id;
	cid = offload_sts_scqe->wd2.cid;
	xid = offload_sts_scqe->wd0.xid_qpn;

	if (rport_index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive an error offload status: rport(0x%x) is invalid, cacheid(0x%x)",
			     hba->port_cfg.port_id, rport_index, cid);

		return UNF_RETURN_ERROR;
	}

	if (rport_index == SPFC_DEFAULT_RPORT_INDEX &&
	    hba->default_sq_info.default_sq_flag == 0xF) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) default session timeout: rport(0x%x) cacheid(0x%x)",
			     hba->port_cfg.port_id, rport_index, cid);
		return UNF_RETURN_ERROR;
	}

	prt_qinfo = &hba->parent_queue_mgr->parent_queue[rport_index];
	parent_sq_info = &prt_qinfo->parent_sq_info;

	valid = spfc_check_rport_valid(prt_qinfo, xid);
	if (valid != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive an error offload status: rport(0x%x), context id(0x%x) is invalid",
			     hba->port_cfg.port_id, rport_index, xid);

		return UNF_RETURN_ERROR;
	}

	/* Offload failed */
	if (SPFC_GET_SCQE_STATUS(scqe) != SPFC_COMPLETION_STATUS_SUCCESS) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x), rport(0x%x), context id(0x%x), cache id(0x%x), offload failed",
			     hba->port_cfg.port_id, rport_index, xid, cid);

		spin_lock_irqsave(&prt_qinfo->parent_queue_state_lock, flags);
		if (prt_qinfo->offload_state != SPFC_QUEUE_STATE_OFFLOADED) {
			prt_qinfo->offload_state = SPFC_QUEUE_STATE_INITIALIZED;
			parent_sq_info->need_offloaded = INVALID_VALUE8;
		}
		spin_unlock_irqrestore(&prt_qinfo->parent_queue_state_lock,
				       flags);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&prt_qinfo->parent_queue_state_lock, flags);
	prt_qinfo->parent_sq_info.cache_id = cid;
	prt_qinfo->offload_state = SPFC_QUEUE_STATE_OFFLOADED;
	parent_sq_info->need_offloaded = SPFC_HAVE_OFFLOAD;
	atomic_set(&prt_qinfo->parent_sq_info.sq_cached, true);

	if (prt_qinfo->parent_sq_info.destroy_sqe.valid) {
		delay_ctl_info.valid = prt_qinfo->parent_sq_info.destroy_sqe.valid;
		delay_ctl_info.rport_index = prt_qinfo->parent_sq_info.destroy_sqe.rport_index;
		delay_ctl_info.time_out = prt_qinfo->parent_sq_info.destroy_sqe.time_out;
		delay_ctl_info.start_jiff = prt_qinfo->parent_sq_info.destroy_sqe.start_jiff;
		delay_ctl_info.rport_info.nport_id =
		    prt_qinfo->parent_sq_info.destroy_sqe.rport_info.nport_id;
		delay_ctl_info.rport_info.rport_index =
		    prt_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index;
		delay_ctl_info.rport_info.port_name =
		    prt_qinfo->parent_sq_info.destroy_sqe.rport_info.port_name;
		prt_qinfo->parent_sq_info.destroy_sqe.valid = false;
	}
	spin_unlock_irqrestore(&prt_qinfo->parent_queue_state_lock, flags);

	if (rport_index == SPFC_DEFAULT_RPORT_INDEX) {
		hba->default_sq_info.sq_cid = cid;
		hba->default_sq_info.sq_xid = xid;
		hba->default_sq_info.default_sq_flag = 1;
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_MAJOR, "[info]Receive default Session info");
	}

	spfc_pop_destroy_parent_queue_sqe((void *)hba, &delay_ctl_info);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) offload success: rport index(0x%x),rport nportid(0x%x),context id(0x%x),cache id(0x%x).",
		     hba->port_cfg.port_id, rport_index,
		     prt_qinfo->parent_sq_info.remote_port_id, xid, cid);

	return RETURN_OK;
}

static u32 spfc_send_bls_via_parent(struct spfc_hba_info *hba, struct unf_frame_pkg *pkg)
{
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = INVALID_VALUE16;
	u16 rx_id = INVALID_VALUE16;
	struct spfc_sqe tmp_sqe;
	struct spfc_sqe *sqe = NULL;
	struct spfc_parent_sq_info *parent_sq_info = NULL;
	struct spfc_parent_queue_info *prt_qinfo = NULL;
	u16 ssqn;

	FC_CHECK_RETURN_VALUE((pkg->type == UNF_PKG_BLS_REQ), UNF_RETURN_ERROR);

	sqe = &tmp_sqe;
	memset(sqe, 0, sizeof(struct spfc_sqe));

	prt_qinfo = spfc_find_parent_queue_info_by_pkg(hba, pkg);
	if (!prt_qinfo) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send BLS SID_DID(0x%x_0x%x) with null parent queue information",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);

		return ret;
	}

	parent_sq_info = spfc_find_parent_sq_by_pkg(hba, pkg);
	if (!parent_sq_info) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send ABTS SID_DID(0x%x_0x%x) with null parent queue information",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);

		return ret;
	}

	rx_id = UNF_GET_RXID(pkg);
	ox_id = UNF_GET_OXID(pkg);

	/* Assemble the SQE Control Section part. The ABTS does not have
	 * Payload. bdsl=0
	 */
	spfc_build_service_wqe_ctrl_section(&sqe->ctrl_sl, SPFC_BYTES_TO_QW_NUM(SPFC_SQE_TS_SIZE),
					    0);

	/* Assemble the SQE Task Section BLS Common part. The value of DW2 of
	 * BLS WQE is Rsvd, and the value of DW2 is 0
	 */
	spfc_build_service_wqe_ts_common(&sqe->ts_sl, parent_sq_info->rport_index, ox_id, rx_id, 0);

	/* Assemble the special part of the ABTS */
	spfc_build_bls_wqe_ts_req(sqe, pkg, hba);
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) RPort(0x%x) send ABTS_REQ ox_id(0x%x) RXID(0x%x), HotTag(0x%x)",
		     hba->port_cfg.port_id, parent_sq_info->rport_index, ox_id,
		     rx_id, (u16)(UNF_GET_HOTPOOL_TAG(pkg) + hba->exi_base));

	ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	ret = spfc_parent_sq_enqueue(parent_sq_info, sqe, ssqn);

	return ret;
}

u32 spfc_send_bls_cmnd(void *handle, struct unf_frame_pkg *pkg)
{
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_hba_info *hba = NULL;
	ulong flags = 0;
	struct spfc_parent_queue_info *prt_qinfo = NULL;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg->type == UNF_PKG_BLS_REQ || pkg->type == UNF_PKG_BLS_REPLY,
			      UNF_RETURN_ERROR);

	SPFC_CHECK_PKG_ALLOCTIME(pkg);
	hba = (struct spfc_hba_info *)handle;

	prt_qinfo = spfc_find_parent_queue_info_by_pkg(hba, pkg);
	if (!prt_qinfo) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send BLS SID_DID(0x%x_0x%x) with null parent queue information",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);

		return ret;
	}

	spin_lock_irqsave(&prt_qinfo->parent_queue_state_lock, flags);

	if (SPFC_RPORT_OFFLOADED(prt_qinfo)) {
		spin_unlock_irqrestore(&prt_qinfo->parent_queue_state_lock, flags);
		ret = spfc_send_bls_via_parent(hba, pkg);
	} else {
		spin_unlock_irqrestore(&prt_qinfo->parent_queue_state_lock, flags);
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[error]Port(0x%x) send BLS SID_DID(0x%x_0x%x) with no offloaded, do noting",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);
	}

	return ret;
}

static u32 spfc_scq_rcv_flush_sq_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	/*
	 * RCVD sq flush sts
	 * --->>> continue flush or clear done
	 */
	u32 ret = UNF_RETURN_ERROR;

	if (scqe->flush_sts.wd0.port_id != hba->port_index) {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_CRITICAL,
			     "[err]Port(0x%x) clear_sts_port_idx(0x%x) not match hba_port_idx(0x%x), stage(0x%x)",
			     hba->port_cfg.port_id, scqe->clear_sts.wd0.port_id,
			     hba->port_index, hba->queue_set_stage);

		return UNF_RETURN_ERROR;
	}

	if (scqe->flush_sts.wd0.last_flush) {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_INFO,
			     "[info]Port(0x%x) flush sq(0x%x) done, stage(0x%x)",
			     hba->port_cfg.port_id, hba->next_clear_sq, hba->queue_set_stage);

		/* If the Flush STS is last one, send cmd done */
		ret = spfc_clear_sq_wqe_done(hba);
	} else {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
			     "[info]Port(0x%x) continue flush sq(0x%x), stage(0x%x)",
			     hba->port_cfg.port_id, hba->next_clear_sq, hba->queue_set_stage);

		ret = spfc_clear_pending_sq_wqe(hba);
	}

	return ret;
}

static u32 spfc_scq_rcv_buf_clear_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	/*
	 * clear: fetched sq wqe
	 * ---to--->>> pending sq wqe
	 */
	u32 ret = UNF_RETURN_ERROR;

	if (scqe->clear_sts.wd0.port_id != hba->port_index) {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_CRITICAL,
			     "[err]Port(0x%x) clear_sts_port_idx(0x%x) not match hba_port_idx(0x%x), stage(0x%x)",
			     hba->port_cfg.port_id, scqe->clear_sts.wd0.port_id,
			     hba->port_index, hba->queue_set_stage);

		return UNF_RETURN_ERROR;
	}

	/* set port with I/O cleared state */
	spfc_set_hba_clear_state(hba, true);

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_KEVENT,
		     "[info]Port(0x%x) cleared all fetched wqe, start clear sq pending wqe, stage (0x%x)",
		     hba->port_cfg.port_id, hba->queue_set_stage);

	hba->queue_set_stage = SPFC_QUEUE_SET_STAGE_FLUSHING;
	ret = spfc_clear_pending_sq_wqe(hba);

	return ret;
}

u32 spfc_scq_recv_sess_rst_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 rport_index = INVALID_VALUE32;
	ulong flags = 0;
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	struct spfc_scqe_sess_sts *sess_sts_scqe = (struct spfc_scqe_sess_sts *)(void *)scqe;
	u32 flush_done;
	u32 *ctx_array = NULL;
	int ret;
	spinlock_t *prtq_state_lock = NULL;

	rport_index = sess_sts_scqe->wd1.conn_id;
	if (rport_index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive reset session cmd sts failed, invlaid rport(0x%x) status_code(0x%x) remain_cnt(0x%x)",
			     hba->port_cfg.port_id, rport_index,
			     sess_sts_scqe->ch.wd0.err_code,
			     sess_sts_scqe->ch.wd0.cqe_remain_cnt);

		return UNF_RETURN_ERROR;
	}

	parent_queue_info = &hba->parent_queue_mgr->parent_queue[rport_index];
	prtq_state_lock = &parent_queue_info->parent_queue_state_lock;
	/*
	 * If only session reset is used, the offload status of sq remains
	 * unchanged. If a link is deleted, the offload status is set to
	 * destroying and is irreversible.
	 */
	spin_lock_irqsave(prtq_state_lock, flags);

	/*
	 * According to the fault tolerance principle, even if the connection
	 * deletion times out and the sts returns to delete the connection, one
	 * indicates that the cancel timer is successful, and 0 indicates that
	 * the timer is being processed.
	 */
	if (!cancel_delayed_work(&parent_queue_info->parent_sq_info.del_work)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) rport_index(0x%x) delete rport timer maybe timeout",
			     hba->port_cfg.port_id, rport_index);
	}

	/*
	 * If the SessRstSts is returned too late and the Parent Queue Info
	 * resource is released, OK is returned.
	 */
	if (parent_queue_info->offload_state != SPFC_QUEUE_STATE_DESTROYING) {
		spin_unlock_irqrestore(prtq_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[info]Port(0x%x) reset session cmd complete, no need to free parent qinfo, rport(0x%x) status_code(0x%x) remain_cnt(0x%x)",
			     hba->port_cfg.port_id, rport_index,
			     sess_sts_scqe->ch.wd0.err_code,
			     sess_sts_scqe->ch.wd0.cqe_remain_cnt);

		return RETURN_OK;
	}

	if (parent_queue_info->parent_ctx.cqm_parent_ctx_obj) {
		ctx_array = (u32 *)((void *)(parent_queue_info->parent_ctx
						 .cqm_parent_ctx_obj->vaddr));
		flush_done = ctx_array[SPFC_CTXT_FLUSH_DONE_DW_POS] & SPFC_CTXT_FLUSH_DONE_MASK_BE;
		mb();
		if (flush_done == 0) {
			spin_unlock_irqrestore(prtq_state_lock, flags);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) rport(0x%x) flushdone is not set, delay to free parent session",
				     hba->port_cfg.port_id, rport_index);

			/* If flushdone bit is not set,delay free Sq info */
			ret = queue_delayed_work(hba->work_queue,
						 &(parent_queue_info->parent_sq_info
						 .flush_done_timeout_work),
						 (ulong)msecs_to_jiffies((u32)
						 SPFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_MS));
			if (!ret) {
				SPFC_HBA_STAT(hba, SPFC_STAT_PARENT_SQ_QUEUE_DELAYED_WORK);
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
					     "[err]Port(0x%x) rport(0x%x) queue delayed work failed ret:%d",
					     hba->port_cfg.port_id, rport_index,
					     ret);
			}

			return RETURN_OK;
		}
	}

	spin_unlock_irqrestore(prtq_state_lock, flags);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) begin to free parent session with rport(0x%x)",
		     hba->port_cfg.port_id, rport_index);

	spfc_free_parent_queue_info(hba, parent_queue_info);

	return RETURN_OK;
}

static u32 spfc_scq_rcv_clear_srq_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	/*
	 * clear ELS/Immi SRQ
	 * ---then--->>> Destroy SRQ
	 */
	struct spfc_srq_info *srq_info = NULL;

	if (SPFC_GET_SCQE_STATUS(scqe) != 0) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) clear srq failed, status(0x%x)",
			     hba->port_cfg.port_id, SPFC_GET_SCQE_STATUS(scqe));

		return RETURN_OK;
	}

	srq_info = &hba->els_srq_info;

	/*
	 * 1: cancel timer succeed
	 * 0: the timer is being processed, the SQ is released when the timer
	 * times out
	 */
	if (cancel_delayed_work(&srq_info->del_work))
		queue_work(hba->work_queue, &hba->els_srq_clear_work);

	return RETURN_OK;
}

u32 spfc_scq_recv_marker_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 ox_id = INVALID_VALUE32;
	u32 rx_id = INVALID_VALUE32;
	u32 hot_tag = INVALID_VALUE32;
	struct unf_frame_pkg pkg = {0};
	struct spfc_scqe_itmf_marker_sts *tmf_marker_sts_scqe = NULL;

	tmf_marker_sts_scqe = &scqe->itmf_marker_sts;
	ox_id = (u32)tmf_marker_sts_scqe->wd1.ox_id;
	rx_id = (u32)tmf_marker_sts_scqe->wd1.rx_id;
	hot_tag = (tmf_marker_sts_scqe->wd4.hotpooltag & UNF_ORIGIN_HOTTAG_MASK) - hba->exi_base;
	pkg.frame_head.oxid_rxid = rx_id | (u32)(ox_id) << UNF_SHIFT_16;
	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = tmf_marker_sts_scqe->magic_num;
	pkg.frame_head.csctl_sid = tmf_marker_sts_scqe->wd3.sid;
	pkg.frame_head.rctl_did = tmf_marker_sts_scqe->wd2.did;

	/* 1. set pkg status */
	if (unlikely(SPFC_SCQE_HAS_ERRCODE(scqe)))
		pkg.status = UNF_IO_FAILED;
	else
		pkg.status = UNF_IO_SUCCESS;

	/* 2 .process rcvd marker STS: set exchange state */
	ret = spfc_rcv_tmf_marker_sts(hba, &pkg, hot_tag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[event]Port(0x%x) recv marker STS OX_ID(0x%x) RX_ID(0x%x) HotTag(0x%x) result %s",
		      hba->port_cfg.port_id, ox_id, rx_id, hot_tag,
		      (ret == RETURN_OK) ? "succeed" : "failed");

	return ret;
}

u32 spfc_scq_recv_abts_marker_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 ox_id = INVALID_VALUE32;
	u32 rx_id = INVALID_VALUE32;
	u32 hot_tag = INVALID_VALUE32;
	struct unf_frame_pkg pkg = {0};
	struct spfc_scqe_abts_marker_sts *abts_marker_sts_scqe = NULL;

	abts_marker_sts_scqe = &scqe->abts_marker_sts;
	if (!abts_marker_sts_scqe) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]ABTS marker STS is NULL");
		return ret;
	}

	ox_id = (u32)abts_marker_sts_scqe->wd1.ox_id;
	rx_id = (u32)abts_marker_sts_scqe->wd1.rx_id;
	hot_tag = (abts_marker_sts_scqe->wd4.hotpooltag & UNF_ORIGIN_HOTTAG_MASK) - hba->exi_base;
	pkg.frame_head.oxid_rxid = rx_id | (u32)(ox_id) << UNF_SHIFT_16;
	pkg.frame_head.csctl_sid = abts_marker_sts_scqe->wd3.sid;
	pkg.frame_head.rctl_did = abts_marker_sts_scqe->wd2.did;
	pkg.abts_maker_status = (u32)abts_marker_sts_scqe->wd3.io_state;
	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = abts_marker_sts_scqe->magic_num;

	if (unlikely(SPFC_SCQE_HAS_ERRCODE(scqe)))
		pkg.status = UNF_IO_FAILED;
	else
		pkg.status = UNF_IO_SUCCESS;

	ret = spfc_rcv_abts_marker_sts(hba, &pkg, hot_tag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) recv abts marker STS ox_id(0x%x) RXID(0x%x) HotTag(0x%x) %s",
		     hba->port_cfg.port_id, ox_id, rx_id, hot_tag,
		     (ret == RETURN_OK) ? "SUCCEED" : "FAILED");

	return ret;
}

u32 spfc_handle_aeq_off_load_err(struct spfc_hba_info *hba, struct spfc_aqe_data *aeq_msg)
{
	u32 ret = RETURN_OK;
	u32 rport_index = 0;
	u32 xid = 0;
	struct spfc_parent_queue_info *prt_qinfo = NULL;
	struct spfc_delay_destroy_ctrl_info delay_ctl_info;
	ulong flags = 0;

	memset(&delay_ctl_info, 0, sizeof(struct spfc_delay_destroy_ctrl_info));

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
		     "[err]Port(0x%x) receive Offload Err Event, EvtCode(0x%x) Conn_id(0x%x) Xid(0x%x)",
		     hba->port_cfg.port_id, aeq_msg->wd0.evt_code,
		     aeq_msg->wd0.conn_id, aeq_msg->wd1.xid);

	/* Currently, only the offload failure caused by insufficient scqe is
	 * processed. Other errors are not processed temporarily.
	 */
	if (unlikely(aeq_msg->wd0.evt_code != FC_ERROR_OFFLOAD_LACKOF_SCQE_FAIL)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive an unsupported error code of AEQ Event,EvtCode(0x%x) Conn_id(0x%x)",
			     hba->port_cfg.port_id, aeq_msg->wd0.evt_code,
			     aeq_msg->wd0.conn_id);

		return UNF_RETURN_ERROR;
	}
	SPFC_SCQ_ERR_TYPE_STAT(hba, FC_ERROR_OFFLOAD_LACKOF_SCQE_FAIL);

	rport_index = aeq_msg->wd0.conn_id;
	xid = aeq_msg->wd1.xid;

	if (rport_index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive an error offload status: rport(0x%x) is invalid, Xid(0x%x)",
			     hba->port_cfg.port_id, rport_index, aeq_msg->wd1.xid);

		return UNF_RETURN_ERROR;
	}

	prt_qinfo = &hba->parent_queue_mgr->parent_queue[rport_index];
	if (spfc_check_rport_valid(prt_qinfo, xid) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive an error offload status: rport(0x%x), context id(0x%x) is invalid",
			     hba->port_cfg.port_id, rport_index, xid);

		return UNF_RETURN_ERROR;
	}

	/* The offload status is restored only when the offload status is offloading */
	spin_lock_irqsave(&prt_qinfo->parent_queue_state_lock, flags);
	if (prt_qinfo->offload_state == SPFC_QUEUE_STATE_OFFLOADING)
		prt_qinfo->offload_state = SPFC_QUEUE_STATE_INITIALIZED;
	spin_unlock_irqrestore(&prt_qinfo->parent_queue_state_lock, flags);

	if (prt_qinfo->parent_sq_info.destroy_sqe.valid) {
		delay_ctl_info.valid = prt_qinfo->parent_sq_info.destroy_sqe.valid;
		delay_ctl_info.rport_index = prt_qinfo->parent_sq_info.destroy_sqe.rport_index;
		delay_ctl_info.time_out = prt_qinfo->parent_sq_info.destroy_sqe.time_out;
		delay_ctl_info.start_jiff = prt_qinfo->parent_sq_info.destroy_sqe.start_jiff;
		delay_ctl_info.rport_info.nport_id =
		    prt_qinfo->parent_sq_info.destroy_sqe.rport_info.nport_id;
		delay_ctl_info.rport_info.rport_index =
		    prt_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index;
		delay_ctl_info.rport_info.port_name =
		    prt_qinfo->parent_sq_info.destroy_sqe.rport_info.port_name;
		prt_qinfo->parent_sq_info.destroy_sqe.valid = false;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,  UNF_MAJOR,
			     "[info]Port(0x%x) pop up delay sqe, start:0x%llx, timeout:0x%x, rport:0x%x, offload state:0x%x",
			     hba->port_cfg.port_id, delay_ctl_info.start_jiff,
			     delay_ctl_info.time_out,
			     prt_qinfo->parent_sq_info.destroy_sqe.rport_info.rport_index,
			     SPFC_QUEUE_STATE_INITIALIZED);

		ret = spfc_free_parent_resource(hba, &delay_ctl_info.rport_info);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) pop delay destroy parent sq failed, rport(0x%x), rport nport id 0x%x",
				     hba->port_cfg.port_id,
				     delay_ctl_info.rport_info.rport_index,
				     delay_ctl_info.rport_info.nport_id);
		}
	}

	return ret;
}

u32 spfc_free_xid(void *handle, struct unf_frame_pkg *pkg)
{
	u32 ret = RETURN_ERROR;
	u16 rx_id = INVALID_VALUE16;
	u16 ox_id = INVALID_VALUE16;
	u16 hot_tag = INVALID_VALUE16;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)handle;
	union spfc_cmdqe tmp_cmd_wqe;
	union spfc_cmdqe *cmd_wqe = NULL;

	FC_CHECK_RETURN_VALUE(hba, RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, RETURN_ERROR);
	SPFC_CHECK_PKG_ALLOCTIME(pkg);

	cmd_wqe = &tmp_cmd_wqe;
	memset(cmd_wqe, 0, sizeof(union spfc_cmdqe));

	rx_id = UNF_GET_RXID(pkg);
	ox_id = UNF_GET_OXID(pkg);
	if (UNF_GET_HOTPOOL_TAG(pkg) != INVALID_VALUE32)
		hot_tag = (u16)UNF_GET_HOTPOOL_TAG(pkg) + hba->exi_base;

	spfc_build_cmdqe_common(cmd_wqe, SPFC_TASK_T_EXCH_ID_FREE, rx_id);
	cmd_wqe->xid_free.wd2.hotpool_tag = hot_tag;
	cmd_wqe->xid_free.magic_num = UNF_GETXCHGALLOCTIME(pkg);
	cmd_wqe->xid_free.sid = pkg->frame_head.csctl_sid;
	cmd_wqe->xid_free.did = pkg->frame_head.rctl_did;
	cmd_wqe->xid_free.type = pkg->type;

	if (pkg->rx_or_ox_id == UNF_PKG_FREE_OXID)
		cmd_wqe->xid_free.wd0.task_id = ox_id;
	else
		cmd_wqe->xid_free.wd0.task_id = rx_id;

	cmd_wqe->xid_free.wd0.port_id = hba->port_index;
	cmd_wqe->xid_free.wd2.scqn = hba->default_scqn;
	ret = spfc_root_cmdq_enqueue(hba, cmd_wqe, sizeof(cmd_wqe->xid_free));

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_INFO,
		     "[info]Port(0x%x) ox_id(0x%x) RXID(0x%x) hottag(0x%x) magic_num(0x%x) Sid(0x%x) Did(0x%x), send free xid %s",
		     hba->port_cfg.port_id, ox_id, rx_id, hot_tag,
		     cmd_wqe->xid_free.magic_num, cmd_wqe->xid_free.sid,
		     cmd_wqe->xid_free.did,
		     (ret == RETURN_OK) ? "OK" : "ERROR");

	return ret;
}

u32 spfc_scq_free_xid_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 hot_tag = INVALID_VALUE32;
	u32 magic_num = INVALID_VALUE32;
	u32 ox_id = INVALID_VALUE32;
	u32 rx_id = INVALID_VALUE32;
	struct spfc_scqe_comm_rsp_sts *free_xid_sts_scqe = NULL;

	free_xid_sts_scqe = &scqe->comm_sts;
	magic_num = free_xid_sts_scqe->magic_num;
	ox_id = (u32)free_xid_sts_scqe->wd0.ox_id;
	rx_id = (u32)free_xid_sts_scqe->wd0.rx_id;

	if (free_xid_sts_scqe->wd1.hotpooltag != INVALID_VALUE16) {
		hot_tag = (free_xid_sts_scqe->wd1.hotpooltag &
			   UNF_ORIGIN_HOTTAG_MASK) - hba->exi_base;
	}

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_INFO,
		     "Port(0x%x) hottag(0x%x) magicnum(0x%x) ox_id(0x%x) rxid(0x%x) sts(%d)",
		     hba->port_cfg.port_id, hot_tag, magic_num, ox_id, rx_id,
		     SPFC_GET_SCQE_STATUS(scqe));

	return RETURN_OK;
}

u32 spfc_scq_exchg_timeout_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	u32 hot_tag = INVALID_VALUE32;
	u32 magic_num = INVALID_VALUE32;
	u32 ox_id = INVALID_VALUE32;
	u32 rx_id = INVALID_VALUE32;
	struct spfc_scqe_comm_rsp_sts *time_out_scqe = NULL;

	time_out_scqe = &scqe->comm_sts;
	magic_num = time_out_scqe->magic_num;
	ox_id = (u32)time_out_scqe->wd0.ox_id;
	rx_id = (u32)time_out_scqe->wd0.rx_id;

	if (time_out_scqe->wd1.hotpooltag != INVALID_VALUE16)
		hot_tag = (time_out_scqe->wd1.hotpooltag & UNF_ORIGIN_HOTTAG_MASK) - hba->exi_base;

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_INFO,
		     "Port(0x%x) recv timer time out sts hotpooltag(0x%x) magicnum(0x%x) ox_id(0x%x) rxid(0x%x) sts(%d)",
		     hba->port_cfg.port_id, hot_tag, magic_num, ox_id, rx_id,
		     SPFC_GET_SCQE_STATUS(scqe));

	return RETURN_OK;
}

u32 spfc_scq_rcv_sq_nop_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe)
{
	struct spfc_scqe_sq_nop_sts *sq_nop_scqe = NULL;
	struct spfc_parent_queue_info *prt_qinfo = NULL;
	struct spfc_parent_sq_info *parent_sq_info = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct spfc_suspend_sqe_info *suspend_sqe = NULL;
	struct spfc_suspend_sqe_info *sqe = NULL;
	u32 rport_index = 0;
	u32 magic_num;
	u16 sqn;
	u32 sqn_base;
	u32 sqn_max;
	u32 ret = RETURN_OK;
	ulong flags = 0;

	sq_nop_scqe = &scqe->sq_nop_sts;
	rport_index = sq_nop_scqe->wd1.conn_id;
	magic_num = sq_nop_scqe->magic_num;
	sqn = sq_nop_scqe->wd0.sqn;
	prt_qinfo = &hba->parent_queue_mgr->parent_queue[rport_index];
	parent_sq_info = &prt_qinfo->parent_sq_info;
	sqn_base = parent_sq_info->sqn_base;
	sqn_max = sqn_base + UNF_SQ_NUM_PER_SESSION - 1;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) rport(0x%x), magic_num(0x%x) receive nop sq sts form sq(0x%x)",
		     hba->port_cfg.port_id, rport_index, magic_num, sqn);

	spin_lock_irqsave(&prt_qinfo->parent_queue_state_lock, flags);
	list_for_each_safe(node, next_node, &parent_sq_info->suspend_sqe_list) {
		sqe = list_entry(node, struct spfc_suspend_sqe_info, list_sqe_entry);
		if (sqe->magic_num != magic_num)
			continue;
		suspend_sqe = sqe;
		if (sqn == sqn_max)
			list_del(node);
		break;
	}
	spin_unlock_irqrestore(&prt_qinfo->parent_queue_state_lock, flags);

	if (suspend_sqe) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) rport_index(0x%x) find suspend sqe.",
			     hba->port_cfg.port_id, rport_index);
		if (sqn < sqn_max) {
			ret = spfc_send_nop_cmd(hba, parent_sq_info, magic_num, sqn + 1);
		} else if (sqn == sqn_max) {
			if (!cancel_delayed_work(&suspend_sqe->timeout_work)) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
					     "[warn]Port(0x%x) rport(0x%x) reset worker timer maybe timeout",
					     hba->port_cfg.port_id, rport_index);
			}
			parent_sq_info->need_offloaded = suspend_sqe->old_offload_sts;
			ret = spfc_pop_suspend_sqe(hba, prt_qinfo, suspend_sqe);
			kfree(suspend_sqe);
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) rport(0x%x) magicnum(0x%x)can't find suspend sqe",
			     hba->port_cfg.port_id, rport_index, magic_num);
	}
	return ret;
}

static const struct unf_scqe_handle_table scqe_handle_table[] = {
	{/* INI rcvd FCP RSP */
	 SPFC_SCQE_FCP_IRSP, true, spfc_scq_recv_iresp},
	{/* INI/TGT rcvd ELS_CMND */
	 SPFC_SCQE_ELS_CMND, false, spfc_scq_recv_els_cmnd},
	{/* INI/TGT rcvd ELS_RSP */
	 SPFC_SCQE_ELS_RSP, true, spfc_scq_recv_ls_gs_rsp},
	{/* INI/TGT rcvd GS_RSP */
	 SPFC_SCQE_GS_RSP, true, spfc_scq_recv_ls_gs_rsp},
	{/* INI rcvd BLS_RSP */
	 SPFC_SCQE_ABTS_RSP, true, spfc_scq_recv_abts_rsp},
	{/* INI/TGT rcvd ELS_RSP STS(Done) */
	 SPFC_SCQE_ELS_RSP_STS, true, spfc_scq_recv_els_rsp_sts},
	{/* INI or TGT rcvd Session enable STS */
	 SPFC_SCQE_SESS_EN_STS, false, spfc_scq_recv_offload_sts},
	{/* INI or TGT rcvd flush (pending) SQ STS */
	 SPFC_SCQE_FLUSH_SQ_STS, false, spfc_scq_rcv_flush_sq_sts},
	{/* INI or TGT rcvd Buffer clear STS */
	 SPFC_SCQE_BUF_CLEAR_STS, false, spfc_scq_rcv_buf_clear_sts},
	{/* INI or TGT rcvd session reset STS */
	 SPFC_SCQE_SESS_RST_STS, false, spfc_scq_recv_sess_rst_sts},
	{/* ELS/IMMI SRQ */
	 SPFC_SCQE_CLEAR_SRQ_STS, false, spfc_scq_rcv_clear_srq_sts},
	{/* INI rcvd TMF RSP */
	 SPFC_SCQE_FCP_ITMF_RSP, true, spfc_scq_recv_iresp},
	{/* INI rcvd TMF Marker STS */
	 SPFC_SCQE_ITMF_MARKER_STS, false, spfc_scq_recv_marker_sts},
	{/* INI rcvd ABTS Marker STS */
	 SPFC_SCQE_ABTS_MARKER_STS, false, spfc_scq_recv_abts_marker_sts},
	{SPFC_SCQE_XID_FREE_ABORT_STS, false, spfc_scq_free_xid_sts},
	{SPFC_SCQE_EXCHID_TIMEOUT_STS, false, spfc_scq_exchg_timeout_sts},
	{SPFC_SQE_NOP_STS, true, spfc_scq_rcv_sq_nop_sts},

};

u32 spfc_rcv_scq_entry_from_scq(struct spfc_hba_info *hba, union spfc_scqe *scqe, u32 scqn)
{
	u32 ret = UNF_RETURN_ERROR;
	bool reclaim = false;
	u32 index = 0;
	u32 total = 0;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(scqe, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(scqn < SPFC_TOTAL_SCQ_NUM, UNF_RETURN_ERROR);

	SPFC_IO_STAT(hba, SPFC_GET_SCQE_TYPE(scqe));

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) receive scqe type %d from SCQ[%u]",
		     hba->port_cfg.port_id, SPFC_GET_SCQE_TYPE(scqe), scqn);

	/* 1. error code cheking */
	if (unlikely(SPFC_SCQE_HAS_ERRCODE(scqe))) {
		/* So far, just print & counter */
		spfc_scqe_error_pre_proc(hba, scqe);
	}

	/* 2. Process SCQE by corresponding  processer */
	total = sizeof(scqe_handle_table) / sizeof(struct unf_scqe_handle_table);
	while (index < total) {
		if (SPFC_GET_SCQE_TYPE(scqe) == scqe_handle_table[index].scqe_type) {
			ret = scqe_handle_table[index].scqe_handle_func(hba, scqe);
			reclaim = scqe_handle_table[index].reclaim_sq_wpg;

			break;
		}

		index++;
	}

	/* 3. SCQE type check */
	if (unlikely(total == index)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Unknown SCQE type %d",
			     SPFC_GET_SCQE_TYPE(scqe));

		UNF_PRINT_SFS_LIMIT(UNF_ERR, hba->port_cfg.port_id, scqe, sizeof(union spfc_scqe));
	}

	/* 4. If SCQE is for SQ-WQE then recovery Link List SQ free page */
	if (reclaim) {
		if (SPFC_GET_SCQE_SQN(scqe) < SPFC_MAX_SSQ_NUM) {
			ret = spfc_reclaim_sq_wqe_page(hba, scqe);
		} else {
			/* NOTE: for buffer clear, the SCQE conn_id is 0xFFFF,count with HBA */
			SPFC_HBA_STAT((struct spfc_hba_info *)hba, SPFC_STAT_SQ_IO_BUFFER_CLEARED);
		}
	}

	return ret;
}
