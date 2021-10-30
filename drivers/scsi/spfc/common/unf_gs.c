// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_gs.h"
#include "unf_log.h"
#include "unf_exchg.h"
#include "unf_rport.h"
#include "unf_service.h"
#include "unf_portman.h"
#include "unf_ls.h"

static void unf_gpn_id_callback(void *lport, void *sns_port, void *xchg);
static void unf_gpn_id_ob_callback(struct unf_xchg *xchg);
static void unf_gnn_id_ob_callback(struct unf_xchg *xchg);
static void unf_scr_callback(void *lport, void *rport, void *xchg);
static void unf_scr_ob_callback(struct unf_xchg *xchg);
static void unf_gff_id_ob_callback(struct unf_xchg *xchg);
static void unf_gff_id_callback(void *lport, void *sns_port, void *xchg);
static void unf_gnn_id_callback(void *lport, void *sns_port, void *xchg);
static void unf_gid_ft_ob_callback(struct unf_xchg *xchg);
static void unf_gid_ft_callback(void *lport, void *rport, void *xchg);
static void unf_gid_pt_ob_callback(struct unf_xchg *xchg);
static void unf_gid_pt_callback(void *lport, void *rport, void *xchg);
static void unf_rft_id_ob_callback(struct unf_xchg *xchg);
static void unf_rft_id_callback(void *lport, void *rport, void *xchg);
static void unf_rff_id_callback(void *lport, void *rport, void *xchg);
static void unf_rff_id_ob_callback(struct unf_xchg *xchg);

#define UNF_GET_DOMAIN_ID(x) (((x) & 0xFF0000) >> 16)
#define UNF_GET_AREA_ID(x) (((x) & 0x00FF00) >> 8)

#define UNF_GID_LAST_PORT_ID 0x80
#define UNF_GID_CONTROL(nport_id) ((nport_id) >> 24)
#define UNF_GET_PORT_OPTIONS(fc_4feature) ((fc_4feature) >> 20)

#define UNF_SERVICE_GET_NPORTID_FORM_GID_PAGE(port_id_page) \
	(((u32)(port_id_page)->port_id_domain << 16) |      \
	 ((u32)(port_id_page)->port_id_area << 8) |         \
	 ((u32)(port_id_page)->port_id_port))

#define UNF_GNN_GFF_ID_RJT_REASON(rjt_reason)       \
	((UNF_CTIU_RJT_UNABLE_PERFORM ==                \
	  ((rjt_reason) & UNF_CTIU_RJT_MASK)) &&        \
	 ((UNF_CTIU_RJT_EXP_PORTID_NO_REG ==            \
	   ((rjt_reason) & UNF_CTIU_RJT_EXP_MASK)) ||   \
	  (UNF_CTIU_RJT_EXP_PORTNAME_NO_REG ==          \
	   ((rjt_reason) & UNF_CTIU_RJT_EXP_MASK)) ||   \
	  (UNF_CTIU_RJT_EXP_NODENAME_NO_REG ==          \
	   ((rjt_reason) & UNF_CTIU_RJT_EXP_MASK))))

u32 unf_send_scr(struct unf_lport *lport, struct unf_rport *rport)
{
	/* after RCVD RFF_ID ACC */
	struct unf_scr *scr = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, NULL, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for SCR",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_SCR;

	xchg->callback = unf_scr_callback;
	xchg->ob_callback = unf_scr_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	scr = &fc_entry->scr;
	memset(scr, 0, sizeof(struct unf_scr));
	scr->payload[ARRAY_INDEX_0] = (UNF_GS_CMND_SCR); /* SCR is 0x62 */
	scr->payload[ARRAY_INDEX_1] = (UNF_FABRIC_FULL_REG); /* Full registration */
	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: SCR send %s. Port(0x%x_0x%x)--->RPort(0x%x) with hottag(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     lport->nport_id, rport->nport_id, xchg->hotpooltag);

	return ret;
}

static void unf_fill_gff_id_pld(struct unf_gffid *gff_id, u32 nport_id)
{
	FC_CHECK_RETURN_VOID(gff_id);

	gff_id->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	gff_id->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	gff_id->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GFF_ID);
	gff_id->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;
	gff_id->nport_id = nport_id;
}

static void unf_ctpass_thru_callback(void *lport, void *rport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_gid_acc_pld *gid_acc_pld = NULL;
	struct unf_xchg *unf_xchg = NULL;
	union unf_sfs_u *sfs = NULL;
	u32 cmnd_rsp_size = 0;

	struct send_com_trans_out *out_send = NULL;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)xchg;
	sfs = unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;

	gid_acc_pld = sfs->get_id.gid_rsp.gid_acc_pld;
	if (!gid_acc_pld) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) CT PassThru response payload is NULL",
			     unf_lport->port_id);

		return;
	}

	out_send = (struct send_com_trans_out *)unf_xchg->upper_ct;

	cmnd_rsp_size = (gid_acc_pld->ctiu_pream.cmnd_rsp_size);
	if (UNF_CT_IU_ACCEPT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		out_send->hba_status = 0; /* HBA_STATUS_OK 0 */
		out_send->total_resp_buffer_cnt = unf_xchg->fcp_sfs_union.sfs_entry.cur_offset;
		out_send->actual_resp_buffer_cnt = unf_xchg->fcp_sfs_union.sfs_entry.cur_offset;
		unf_cpu_to_big_end(out_send->resp_buffer, (u32)out_send->total_resp_buffer_cnt);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Port(0x%x_0x%x) CT PassThru was receive len is(0x%0x)",
			     unf_lport->port_id, unf_lport->nport_id,
			     out_send->total_resp_buffer_cnt);
	} else if (UNF_CT_IU_REJECT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		out_send->hba_status = 13; /* HBA_STATUS_ERROR_ELS_REJECT 13 */

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) CT PassThru was rejected",
			     unf_lport->port_id, unf_lport->nport_id);
	} else {
		out_send->hba_status = 1; /* HBA_STATUS_ERROR 1 */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) CT PassThru was UNKNOWN",
			     unf_lport->port_id, unf_lport->nport_id);
	}

	up(&unf_lport->wmi_task_sema);
}

u32 unf_send_ctpass_thru(struct unf_lport *lport, void *buffer, u32 bufflen)
{
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_rport *sns_port = NULL;
	struct send_com_trans_in *in_send = (struct send_com_trans_in *)buffer;
	struct send_com_trans_out *out_send =
	    (struct send_com_trans_out *)buffer;
	struct unf_ctiu_prem *ctiu_pream = NULL;
	struct unf_gid *gs_pld = NULL;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buffer, UNF_RETURN_ERROR);

	ctiu_pream = (struct unf_ctiu_prem *)in_send->req_buffer;
	unf_cpu_to_big_end(ctiu_pream, sizeof(struct unf_gid));

	if (ctiu_pream->cmnd_rsp_size >> UNF_SHIFT_16 == NS_GIEL) {
		sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_MGMT_SERV);
		if (!sns_port) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) can't find SNS port",
				     lport->port_id);

			return UNF_RETURN_ERROR;
		}
	} else if (ctiu_pream->cmnd_rsp_size >> UNF_SHIFT_16 == NS_GA_NXT) {
		sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
		if (!sns_port) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) can't find SNS port",
				     lport->port_id);

			return UNF_RETURN_ERROR;
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[info]%s cmnd(0x%x) is error:", __func__,
			     ctiu_pream->cmnd_rsp_size >> UNF_SHIFT_16);

		return UNF_RETURN_ERROR;
	}

	xchg = unf_get_sfs_free_xchg_and_init(lport, sns_port->nport_id, sns_port, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for GFF_ID",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	xchg->cmnd_code = ctiu_pream->cmnd_rsp_size >> UNF_SHIFT_16;
	xchg->upper_ct = buffer;
	xchg->ob_callback = NULL;
	xchg->callback = unf_ctpass_thru_callback;
	xchg->oxid = xchg->hotpooltag;
	unf_fill_package(&pkg, xchg, sns_port);
	pkg.type = UNF_PKG_GS_REQ;
	xchg->fcp_sfs_union.sfs_entry.sfs_buff_len = bufflen;
	gs_pld = &fc_entry->get_id.gid_req; /* GID req payload */
	memset(gs_pld, 0, sizeof(struct unf_gid));
	memcpy(gs_pld, (struct unf_gid *)in_send->req_buffer, sizeof(struct unf_gid));
	fc_entry->get_id.gid_rsp.gid_acc_pld = (struct unf_gid_acc_pld *)out_send->resp_buffer;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);

	return ret;
}

u32 unf_send_gff_id(struct unf_lport *lport, struct unf_rport *sns_port,
		    u32 nport_id)
{
	struct unf_gffid *gff_id = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;

	struct unf_frame_pkg pkg;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);

	if (unf_is_lport_valid(lport) != RETURN_OK)
		/* Lport is invalid, no retry or handle required, return ok */
		return RETURN_OK;

	unf_lport = (struct unf_lport *)lport->root_lport;

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, sns_port->nport_id, sns_port, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for GFF_ID",
			     lport->port_id);

		return unf_get_and_post_disc_event(lport, sns_port, nport_id, UNF_DISC_GET_FEATURE);
	}

	xchg->cmnd_code = NS_GFF_ID;
	xchg->disc_portid = nport_id;

	xchg->ob_callback = unf_gff_id_ob_callback;
	xchg->callback = unf_gff_id_callback;

	unf_fill_package(&pkg, xchg, sns_port);
	pkg.type = UNF_PKG_GS_REQ;

	gff_id = &fc_entry->gff_id;
	memset(gff_id, 0, sizeof(struct unf_gffid));
	unf_fill_gff_id_pld(gff_id, nport_id);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);
	else
		atomic_dec(&unf_lport->disc.disc_thread_info.disc_contrl_size);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: GFF_ID send %s. Port(0x%x)--->RPort(0x%x). Inquire RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     sns_port->nport_id, nport_id);

	return ret;
}

static void unf_fill_gnnid_pld(struct unf_gnnid *gnnid_pld, u32 nport_id)
{
	/* Inquiry R_Port node name from SW */
	FC_CHECK_RETURN_VOID(gnnid_pld);

	gnnid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	gnnid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	gnnid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GNN_ID);
	gnnid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	gnnid_pld->nport_id = nport_id;
}

u32 unf_send_gnn_id(struct unf_lport *lport, struct unf_rport *sns_port,
		    u32 nport_id)
{
	/* from DISC stop/re-login */
	struct unf_gnnid *unf_gnnid = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "Port(0x%x_0x%x) send gnnid to 0x%x.", lport->port_id,
		     lport->nport_id, nport_id);

	if (unf_is_lport_valid(lport) != RETURN_OK)
		/* Lport is invalid, no retry or handle required, return ok */
		return RETURN_OK;

	unf_lport = (struct unf_lport *)lport->root_lport;

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, sns_port->nport_id,
					      sns_port, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) exchange can't be NULL for GNN_ID",
			     lport->port_id);

		return unf_get_and_post_disc_event(lport, sns_port, nport_id,
						   UNF_DISC_GET_NODE_NAME);
	}

	xchg->cmnd_code = NS_GNN_ID;
	xchg->disc_portid = nport_id;

	xchg->ob_callback = unf_gnn_id_ob_callback;
	xchg->callback = unf_gnn_id_callback;

	unf_fill_package(&pkg, xchg, sns_port);
	pkg.type = UNF_PKG_GS_REQ;

	unf_gnnid = &fc_entry->gnn_id; /* GNNID payload */
	memset(unf_gnnid, 0, sizeof(struct unf_gnnid));
	unf_fill_gnnid_pld(unf_gnnid, nport_id);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);
	else
		atomic_dec(&unf_lport->disc.disc_thread_info.disc_contrl_size);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: GNN_ID send %s. Port(0x%x_0x%x)--->RPort(0x%x) inquire Nportid(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     lport->nport_id, sns_port->nport_id, nport_id);

	return ret;
}

static void unf_fill_gpnid_pld(struct unf_gpnid *gpnid_pld, u32 nport_id)
{
	FC_CHECK_RETURN_VOID(gpnid_pld);

	gpnid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	gpnid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	gpnid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GPN_ID);
	gpnid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	/* Inquiry WWN from SW */
	gpnid_pld->nport_id = nport_id;
}

u32 unf_send_gpn_id(struct unf_lport *lport, struct unf_rport *sns_port,
		    u32 nport_id)
{
	struct unf_gpnid *gpnid_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);

	if (unf_is_lport_valid(lport) != RETURN_OK)
		/* Lport is invalid, no retry or handle required, return ok */
		return RETURN_OK;

	unf_lport = (struct unf_lport *)lport->root_lport;

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, sns_port->nport_id,
					      sns_port, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for GPN_ID",
			     lport->port_id);

		return unf_get_and_post_disc_event(lport, sns_port, nport_id,
						   UNF_DISC_GET_PORT_NAME);
	}

	xchg->cmnd_code = NS_GPN_ID;
	xchg->disc_portid = nport_id;

	xchg->callback = unf_gpn_id_callback;
	xchg->ob_callback = unf_gpn_id_ob_callback;

	unf_fill_package(&pkg, xchg, sns_port);
	pkg.type = UNF_PKG_GS_REQ;

	gpnid_pld = &fc_entry->gpn_id;
	memset(gpnid_pld, 0, sizeof(struct unf_gpnid));
	unf_fill_gpnid_pld(gpnid_pld, nport_id);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);
	else
		atomic_dec(&unf_lport->disc.disc_thread_info.disc_contrl_size);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: GPN_ID send %s. Port(0x%x)--->RPort(0x%x). Inquire RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     sns_port->nport_id, nport_id);

	return ret;
}

static void unf_fill_gid_ft_pld(struct unf_gid *gid_pld)
{
	FC_CHECK_RETURN_VOID(gid_pld);

	gid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	gid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	gid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GID_FT);
	gid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	gid_pld->scope_type = (UNF_GID_FT_TYPE);
}

u32 unf_send_gid_ft(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_gid *gid_pld = NULL;
	struct unf_gid_rsp *gid_rsp = NULL;
	struct unf_gid_acc_pld *gid_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id,
					      rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for GID_FT",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_GID_FT;

	xchg->ob_callback = unf_gid_ft_ob_callback;
	xchg->callback = unf_gid_ft_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_GS_REQ;

	gid_pld = &fc_entry->get_id.gid_req; /* GID req payload */
	unf_fill_gid_ft_pld(gid_pld);
	gid_rsp = &fc_entry->get_id.gid_rsp; /* GID rsp payload */

	gid_acc_pld = (struct unf_gid_acc_pld *)unf_get_one_big_sfs_buf(xchg);
	if (!gid_acc_pld) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate GID_FT response buffer failed",
			     lport->port_id);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}
	memset(gid_acc_pld, 0, sizeof(struct unf_gid_acc_pld));
	gid_rsp->gid_acc_pld = gid_acc_pld;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: GID_FT send %s. Port(0x%x)--->RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id);

	return ret;
}

static void unf_fill_gid_pt_pld(struct unf_gid *gid_pld,
				struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(gid_pld);
	FC_CHECK_RETURN_VOID(lport);

	gid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	gid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	gid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_GID_PT);
	gid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;

	/* 0x7F000000 means NX_Port */
	gid_pld->scope_type = (UNF_GID_PT_TYPE);
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, gid_pld,
			    sizeof(struct unf_gid));
}

u32 unf_send_gid_pt(struct unf_lport *lport, struct unf_rport *rport)
{
	/* from DISC start */
	struct unf_gid *gid_pld = NULL;
	struct unf_gid_rsp *gid_rsp = NULL;
	struct unf_gid_acc_pld *gid_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id,
					      rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for GID_PT",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_GID_PT;

	xchg->ob_callback = unf_gid_pt_ob_callback;
	xchg->callback = unf_gid_pt_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_GS_REQ;

	gid_pld = &fc_entry->get_id.gid_req; /* GID req payload */
	unf_fill_gid_pt_pld(gid_pld, lport);
	gid_rsp = &fc_entry->get_id.gid_rsp; /* GID rsp payload */

	gid_acc_pld = (struct unf_gid_acc_pld *)unf_get_one_big_sfs_buf(xchg);
	if (!gid_acc_pld) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%0x) Allocate GID_PT response buffer failed",
			     lport->port_id);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}
	memset(gid_acc_pld, 0, sizeof(struct unf_gid_acc_pld));
	gid_rsp->gid_acc_pld = gid_acc_pld;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: GID_PT send %s. Port(0x%x_0x%x)--->RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     lport->nport_id, rport->nport_id);

	return ret;
}

static void unf_fill_rft_id_pld(struct unf_rftid *rftid_pld,
				struct unf_lport *lport)
{
	u32 index = 1;

	FC_CHECK_RETURN_VOID(rftid_pld);
	FC_CHECK_RETURN_VOID(lport);

	rftid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	rftid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	rftid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_RFT_ID);
	rftid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;
	rftid_pld->nport_id = (lport->nport_id);
	rftid_pld->fc4_types[ARRAY_INDEX_0] = (UNF_FC4_SCSI_BIT8);

	for (index = ARRAY_INDEX_2; index < UNF_FC4TYPE_CNT; index++)
		rftid_pld->fc4_types[index] = 0;
}

u32 unf_send_rft_id(struct unf_lport *lport, struct unf_rport *rport)
{
	/* After PLOGI process */
	struct unf_rftid *rft_id = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id,
					      rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for RFT_ID",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_RFT_ID;

	xchg->callback = unf_rft_id_callback;
	xchg->ob_callback = unf_rft_id_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_GS_REQ;

	rft_id = &fc_entry->rft_id;
	memset(rft_id, 0, sizeof(struct unf_rftid));
	unf_fill_rft_id_pld(rft_id, lport);
	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: RFT_ID send %s. Port(0x%x_0x%x)--->RPort(0x%x). rport(0x%p) wwpn(0x%llx) ",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     lport->nport_id, rport->nport_id, rport, rport->port_name);

	return ret;
}

static void unf_fill_rff_id_pld(struct unf_rffid *rffid_pld,
				struct unf_lport *lport, u32 fc4_type)
{
	FC_CHECK_RETURN_VOID(rffid_pld);
	FC_CHECK_RETURN_VOID(lport);

	rffid_pld->ctiu_pream.rev_inid = (UNF_REV_NPORTID_INIT);
	rffid_pld->ctiu_pream.gstype_gssub_options = (UNF_FSTYPE_OPT_INIT);
	rffid_pld->ctiu_pream.cmnd_rsp_size = (UNF_FSTYPE_RFF_ID);
	rffid_pld->ctiu_pream.frag_reason_exp_vend = UNF_FRAG_REASON_VENDOR;
	rffid_pld->nport_id = (lport->nport_id);
	rffid_pld->fc4_feature = (fc4_type | (lport->options << UNF_SHIFT_4));
}

u32 unf_send_rff_id(struct unf_lport *lport, struct unf_rport *rport,
		    u32 fc4_type)
{
	/* from RFT_ID, then Send SCR */
	struct unf_rffid *rff_id = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
		     UNF_INFO, "%s Enter", __func__);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id,
					      rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for RFF_ID",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = NS_RFF_ID;

	xchg->callback = unf_rff_id_callback;
	xchg->ob_callback = unf_rff_id_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_GS_REQ;

	rff_id = &fc_entry->rff_id;
	memset(rff_id, 0, sizeof(struct unf_rffid));
	unf_fill_rff_id_pld(rff_id, lport, fc4_type);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: RFF_ID feature 0x%x(10:TGT,20:INI,30:COM) send %s. Port(0x%x_0x%x)--->RPortid(0x%x) rport(0x%p)",
		     lport->options, (ret != RETURN_OK) ? "failed" : "succeed",
		     lport->port_id, lport->nport_id, rport->nport_id, rport);

	return ret;
}

void unf_handle_init_gid_acc(struct unf_gid_acc_pld *gid_acc_pld,
			     struct unf_lport *lport)
{
	/*
	 * from SCR ACC callback
	 * NOTE: inquiry disc R_Port used for NPIV
	 */
	struct unf_disc_rport *disc_rport = NULL;
	struct unf_disc *disc = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 gid_port_id = 0;
	u32 nport_id = 0;
	u32 index = 0;
	u8 control = 0;

	FC_CHECK_RETURN_VOID(gid_acc_pld);
	FC_CHECK_RETURN_VOID(lport);

	/*
	 * 1. Find & Check & Get (new) R_Port from list_disc_rports_pool
	 * then, Add to R_Port Disc_busy_list
	 */
	while (index < UNF_GID_PORT_CNT) {
		gid_port_id = (gid_acc_pld->gid_port_id[index]);
		nport_id = UNF_NPORTID_MASK & gid_port_id;
		control = UNF_GID_CONTROL(gid_port_id);

		/* for each N_Port_ID from GID_ACC payload */
		if (lport->nport_id != nport_id && nport_id != 0 &&
		    (!unf_lookup_lport_by_nportid(lport, nport_id))) {
			/* for New Port, not L_Port */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x_0x%x) get nportid(0x%x) from GID_ACC",
				     lport->port_id, lport->nport_id, nport_id);

			/* Get R_Port from list of RPort Disc Pool */
			disc_rport = unf_rport_get_free_and_init(lport,
								 UNF_PORT_TYPE_DISC, nport_id);
			if (!disc_rport) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x_0x%x) can't allocate new rport(0x%x) from disc pool",
					     lport->port_id, lport->nport_id,
					     nport_id);

				index++;
				continue;
			}
		}

		if (UNF_GID_LAST_PORT_ID == (UNF_GID_LAST_PORT_ID & control))
			break;

		index++;
	}

	/*
	 * 2. Do port disc stop operation:
	 * NOTE: Do DISC & release R_Port from busy_list back to
	 * list_disc_rports_pool
	 */
	disc = &lport->disc;
	if (!disc->disc_temp.unf_disc_stop) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) disc stop function is NULL",
			     lport->port_id, lport->nport_id);

		return;
	}

	ret = disc->disc_temp.unf_disc_stop(lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) do disc stop failed",
			     lport->port_id, lport->nport_id);
	}
}

u32 unf_rport_relogin(struct unf_lport *lport, u32 nport_id)
{
	/* Send GNN_ID */
	struct unf_rport *sns_port = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* Get SNS R_Port */
	sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't find fabric Port", lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	/* Send GNN_ID now to SW */
	ret = unf_get_and_post_disc_event(lport, sns_port, nport_id,
					  UNF_DISC_GET_NODE_NAME);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			     lport->nport_id, UNF_DISC_GET_NODE_NAME, nport_id);

		/* NOTE: Continue to next stage */
		unf_rcv_gnn_id_rsp_unknown(lport, sns_port, nport_id);
	}

	return ret;
}

u32 unf_rport_check_wwn(struct unf_lport *lport, struct unf_rport *rport)
{
	/* Send GPN_ID */
	struct unf_rport *sns_port = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	/* Get SNS R_Port */
	sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't find fabric Port", lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	/* Send GPN_ID to SW */
	ret = unf_get_and_post_disc_event(lport, sns_port, rport->nport_id,
					  UNF_DISC_GET_PORT_NAME);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			     lport->nport_id, UNF_DISC_GET_PORT_NAME,
			     rport->nport_id);

		unf_rcv_gpn_id_rsp_unknown(lport, rport->nport_id);
	}

	return ret;
}

u32 unf_handle_rscn_port_not_indisc(struct unf_lport *lport, u32 rscn_nport_id)
{
	/* RSCN Port_ID not in GID_ACC payload table: Link Down */
	struct unf_rport *unf_rport = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* from R_Port busy list by N_Port_ID */
	unf_rport = unf_get_rport_by_nport_id(lport, rscn_nport_id);
	if (unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[info]Port(0x%x) RPort(0x%x) wwpn(0x%llx) has been removed and link down it",
			     lport->port_id, rscn_nport_id, unf_rport->port_name);

		unf_rport_linkdown(lport, unf_rport);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) has no RPort(0x%x) and do nothing",
			     lport->nport_id, rscn_nport_id);
	}

	return ret;
}

u32 unf_handle_rscn_port_indisc(struct unf_lport *lport, u32 rscn_nport_id)
{
	/* Send GPN_ID or re-login(GNN_ID) */
	struct unf_rport *unf_rport = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* from R_Port busy list by N_Port_ID */
	unf_rport = unf_get_rport_by_nport_id(lport, rscn_nport_id);
	if (unf_rport) {
		/* R_Port exist: send GPN_ID */
		ret = unf_rport_check_wwn(lport, unf_rport);
	} else {
		if (UNF_PORT_MODE_INI == (lport->options & UNF_PORT_MODE_INI))
			/* Re-LOGIN with INI mode: Send GNN_ID */
			ret = unf_rport_relogin(lport, rscn_nport_id);
		else
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) with no INI feature. Do nothing",
				     lport->nport_id);
	}

	return ret;
}

static u32 unf_handle_rscn_port_addr(struct unf_port_id_page *portid_page,
				     struct unf_gid_acc_pld *gid_acc_pld,
				     struct unf_lport *lport)
{
	/*
	 * Input parameters:
	 * 1. Port_ID_page: saved from RSCN payload
	 * 2. GID_ACC_payload: back from GID_ACC (GID_PT or GID_FT)
	 * *
	 * Do work: check whether RSCN Port_ID within GID_ACC payload or not
	 * then, re-login or link down rport
	 */
	u32 rscn_nport_id = 0;
	u32 gid_port_id = 0;
	u32 nport_id = 0;
	u32 index = 0;
	u8 control = 0;
	u32 ret = RETURN_OK;
	bool have_same_id = false;

	FC_CHECK_RETURN_VALUE(portid_page, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(gid_acc_pld, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* 1. get RSCN_NPort_ID from (L_Port->Disc->RSCN_Mgr)->RSCN_Port_ID_Page
	 */
	rscn_nport_id = UNF_SERVICE_GET_NPORTID_FORM_GID_PAGE(portid_page);

	/*
	 * 2. for RSCN_NPort_ID
	 * check whether RSCN_NPort_ID within GID_ACC_Payload or not
	 */
	while (index < UNF_GID_PORT_CNT) {
		gid_port_id = (gid_acc_pld->gid_port_id[index]);
		nport_id = UNF_NPORTID_MASK & gid_port_id;
		control = UNF_GID_CONTROL(gid_port_id);

		if (lport->nport_id != nport_id && nport_id != 0) {
			/* is not L_Port */
			if (nport_id == rscn_nport_id) {
				/* RSCN Port_ID within GID_ACC payload */
				have_same_id = true;
				break;
			}
		}

		if (UNF_GID_LAST_PORT_ID == (UNF_GID_LAST_PORT_ID & control))
			break;

		index++;
	}

	/* 3. RSCN_Port_ID not within GID_ACC payload table */
	if (!have_same_id) {
		/* rport has been removed */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[warn]Port(0x%x_0x%x) find RSCN N_Port_ID(0x%x) in GID_ACC table failed",
			     lport->port_id, lport->nport_id, rscn_nport_id);

		/* Link down rport */
		ret = unf_handle_rscn_port_not_indisc(lport, rscn_nport_id);

	} else { /* 4. RSCN_Port_ID within GID_ACC payload table */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x_0x%x) find RSCN N_Port_ID(0x%x) in GID_ACC table succeed",
			     lport->port_id, lport->nport_id, rscn_nport_id);

		/* Re-login with INI mode */
		ret = unf_handle_rscn_port_indisc(lport, rscn_nport_id);
	}

	return ret;
}

void unf_check_rport_rscn_process(struct unf_rport *rport,
				  struct unf_port_id_page *portid_page)
{
	struct unf_rport *unf_rport = rport;
	struct unf_port_id_page *unf_portid_page = portid_page;
	u8 addr_format = unf_portid_page->addr_format;

	switch (addr_format) {
	/* domain+area */
	case UNF_RSCN_AREA_ADDR_GROUP:
		if (UNF_GET_DOMAIN_ID(unf_rport->nport_id) == unf_portid_page->port_id_domain &&
		    UNF_GET_AREA_ID(unf_rport->nport_id) == unf_portid_page->port_id_area)
			unf_rport->rscn_position = UNF_RPORT_NEED_PROCESS;

		break;
	/* domain */
	case UNF_RSCN_DOMAIN_ADDR_GROUP:
		if (UNF_GET_DOMAIN_ID(unf_rport->nport_id) == unf_portid_page->port_id_domain)
			unf_rport->rscn_position = UNF_RPORT_NEED_PROCESS;

		break;
	/* all */
	case UNF_RSCN_FABRIC_ADDR_GROUP:
		unf_rport->rscn_position = UNF_RPORT_NEED_PROCESS;
		break;
	default:
		break;
	}
}

static void unf_set_rport_rscn_position(struct unf_lport *lport,
					struct unf_port_id_page *portid_page)
{
	struct unf_rport *unf_rport = NULL;
	struct list_head *list_node = NULL;
	struct list_head *list_nextnode = NULL;
	struct unf_disc *disc = NULL;
	ulong disc_flag = 0;
	ulong rport_flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	disc = &lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	list_for_each_safe(list_node, list_nextnode, &disc->list_busy_rports) {
		unf_rport = list_entry(list_node, struct unf_rport, entry_rport);
		spin_lock_irqsave(&unf_rport->rport_state_lock, rport_flag);

		if (unf_rport->nport_id < UNF_FC_FID_DOM_MGR) {
			if (unf_rport->rscn_position == UNF_RPORT_NOT_NEED_PROCESS)
				unf_check_rport_rscn_process(unf_rport, portid_page);
		} else {
			unf_rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		}

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, rport_flag);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);
}

static void unf_set_rport_rscn_position_local(struct unf_lport *lport)
{
	struct unf_rport *unf_rport = NULL;
	struct list_head *list_node = NULL;
	struct list_head *list_nextnode = NULL;
	struct unf_disc *disc = NULL;
	ulong disc_flag = 0;
	ulong rport_flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	disc = &lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	list_for_each_safe(list_node, list_nextnode, &disc->list_busy_rports) {
		unf_rport = list_entry(list_node, struct unf_rport, entry_rport);
		spin_lock_irqsave(&unf_rport->rport_state_lock, rport_flag);

		if (unf_rport->nport_id < UNF_FC_FID_DOM_MGR) {
			if (unf_rport->rscn_position == UNF_RPORT_NEED_PROCESS)
				unf_rport->rscn_position = UNF_RPORT_ONLY_IN_LOCAL_PROCESS;
		} else {
			unf_rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		}

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, rport_flag);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);
}

static void unf_reset_rport_rscn_setting(struct unf_lport *lport)
{
	struct unf_rport *rport = NULL;
	struct list_head *list_node = NULL;
	struct list_head *list_nextnode = NULL;
	struct unf_disc *disc = NULL;
	ulong rport_flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	disc = &lport->disc;

	list_for_each_safe(list_node, list_nextnode, &disc->list_busy_rports) {
		rport = list_entry(list_node, struct unf_rport, entry_rport);
		spin_lock_irqsave(&rport->rport_state_lock, rport_flag);
		rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}
}

void unf_compare_nport_id_with_rport_list(struct unf_lport *lport, u32 nport_id,
					  struct unf_port_id_page *portid_page)
{
	struct unf_rport *rport = NULL;
	ulong rport_flag = 0;
	u8 addr_format = portid_page->addr_format;

	FC_CHECK_RETURN_VOID(lport);

	switch (addr_format) {
	/* domain+area */
	case UNF_RSCN_AREA_ADDR_GROUP:
		if ((UNF_GET_DOMAIN_ID(nport_id) != portid_page->port_id_domain) ||
		    (UNF_GET_AREA_ID(nport_id) != portid_page->port_id_area))
			return;

		break;
	/* domain */
	case UNF_RSCN_DOMAIN_ADDR_GROUP:
		if (UNF_GET_DOMAIN_ID(nport_id) != portid_page->port_id_domain)
			return;

		break;
	/* all */
	case UNF_RSCN_FABRIC_ADDR_GROUP:
		break;
	/* can't enter this branch guarantee by outer */
	default:
		break;
	}

	rport = unf_get_rport_by_nport_id(lport, nport_id);

	if (!rport) {
		if (UNF_PORT_MODE_INI == (lport->options & UNF_PORT_MODE_INI)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
				     "[event]Port(0x%x) Find Rport(0x%x) by RSCN",
				     lport->nport_id, nport_id);
			unf_rport_relogin(lport, nport_id);
		}
	} else {
		spin_lock_irqsave(&rport->rport_state_lock, rport_flag);
		if (rport->rscn_position == UNF_RPORT_NEED_PROCESS)
			rport->rscn_position = UNF_RPORT_IN_DISC_AND_LOCAL_PROCESS;

		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}
}

static void unf_compare_disc_with_local_rport(struct unf_lport *lport,
					      struct unf_gid_acc_pld *pld,
					      struct unf_port_id_page *page)
{
	u32 gid_port_id = 0;
	u32 nport_id = 0;
	u32 index = 0;
	u8 control = 0;

	FC_CHECK_RETURN_VOID(pld);
	FC_CHECK_RETURN_VOID(lport);

	while (index < UNF_GID_PORT_CNT) {
		gid_port_id = (pld->gid_port_id[index]);
		nport_id = UNF_NPORTID_MASK & gid_port_id;
		control = UNF_GID_CONTROL(gid_port_id);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_INFO, "[info]Port(0x%x) DISC N_Port_ID(0x%x)",
			     lport->nport_id, nport_id);

		if (nport_id != 0 &&
		    (!unf_lookup_lport_by_nportid(lport, nport_id)))
			unf_compare_nport_id_with_rport_list(lport, nport_id, page);

		if (UNF_GID_LAST_PORT_ID == (UNF_GID_LAST_PORT_ID & control))
			break;

		index++;
	}

	unf_set_rport_rscn_position_local(lport);
}

static u32 unf_process_each_rport_after_rscn(struct unf_lport *lport,
					     struct unf_rport *sns_port,
					     struct unf_rport *rport)
{
	ulong rport_flag = 0;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);

	spin_lock_irqsave(&rport->rport_state_lock, rport_flag);

	if (rport->rscn_position == UNF_RPORT_IN_DISC_AND_LOCAL_PROCESS) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[info]Port(0x%x_0x%x) RPort(0x%x) rescan position(0x%x), check wwpn",
			     lport->port_id, lport->nport_id, rport->nport_id,
			     rport->rscn_position);
		rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
		ret = unf_rport_check_wwn(lport, rport);
	} else if (rport->rscn_position == UNF_RPORT_ONLY_IN_LOCAL_PROCESS) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[event]Port(0x%x_0x%x) RPort(0x%x) rescan position(0x%x), linkdown it",
			     lport->port_id, lport->nport_id, rport->nport_id,
			     rport->rscn_position);
		rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
		unf_rport_linkdown(lport, rport);
	} else {
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);
	}

	return ret;
}

static u32 unf_process_local_rport_after_rscn(struct unf_lport *lport,
					      struct unf_rport *sns_port)
{
	struct unf_rport *unf_rport = NULL;
	struct list_head *list_node = NULL;
	struct unf_disc *disc = NULL;
	ulong disc_flag = 0;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);
	disc = &lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	if (list_empty(&disc->list_busy_rports)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

		return UNF_RETURN_ERROR;
	}

	list_node = UNF_OS_LIST_NEXT(&disc->list_busy_rports);

	do {
		unf_rport = list_entry(list_node, struct unf_rport, entry_rport);

		if (unf_rport->rscn_position == UNF_RPORT_NOT_NEED_PROCESS) {
			list_node = UNF_OS_LIST_NEXT(list_node);
			continue;
		} else {
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);
			ret = unf_process_each_rport_after_rscn(lport, sns_port, unf_rport);
			spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
			list_node = UNF_OS_LIST_NEXT(&disc->list_busy_rports);
		}
	} while (list_node != &disc->list_busy_rports);

	unf_reset_rport_rscn_setting(lport);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

	return ret;
}

static u32 unf_handle_rscn_group_addr(struct unf_port_id_page *portid_page,
				      struct unf_gid_acc_pld *gid_acc_pld,
				      struct unf_lport *lport)
{
	struct unf_rport *sns_port = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(portid_page, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(gid_acc_pld, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	sns_port = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find fabric port failed", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	unf_set_rport_rscn_position(lport, portid_page);
	unf_compare_disc_with_local_rport(lport, gid_acc_pld, portid_page);

	ret = unf_process_local_rport_after_rscn(lport, sns_port);

	return ret;
}

static void unf_handle_rscn_gid_acc(struct unf_gid_acc_pld *gid_acc_pid,
				    struct unf_lport *lport)
{
	/* for N_Port_ID table return from RSCN */
	struct unf_port_id_page *port_id_page = NULL;
	struct unf_rscn_mgr *rscn_mgr = NULL;
	struct list_head *list_node = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(gid_acc_pid);
	FC_CHECK_RETURN_VOID(lport);
	rscn_mgr = &lport->disc.rscn_mgr;

	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	while (!list_empty(&rscn_mgr->list_using_rscn_page)) {
		/*
		 * for each RSCN_Using_Page(NPortID)
		 * for each
		 * L_Port->Disc->RSCN_Mgr->RSCN_Using_Page(Port_ID_Page)
		 * * NOTE:
		 * check using_page_port_id whether within GID_ACC payload or
		 * not
		 */
		list_node = UNF_OS_LIST_NEXT(&rscn_mgr->list_using_rscn_page);
		port_id_page = list_entry(list_node, struct unf_port_id_page, list_node_rscn);
		list_del(list_node); /* NOTE: here delete node (from RSCN using Page) */
		spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);

		switch (port_id_page->addr_format) {
		/* each page of RSNC corresponding one of N_Port_ID */
		case UNF_RSCN_PORT_ADDR:
			(void)unf_handle_rscn_port_addr(port_id_page, gid_acc_pid, lport);
			break;

		/* each page of RSNC corresponding address group */
		case UNF_RSCN_AREA_ADDR_GROUP:
		case UNF_RSCN_DOMAIN_ADDR_GROUP:
		case UNF_RSCN_FABRIC_ADDR_GROUP:
			(void)unf_handle_rscn_group_addr(port_id_page, gid_acc_pid, lport);
			break;

		default:
			break;
		}

		/* NOTE: release this RSCN_Node */
		rscn_mgr->unf_release_rscn_node(rscn_mgr, port_id_page);

		/* go to next */
		spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	}

	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);
}

static void unf_gid_acc_handle(struct unf_gid_acc_pld *gid_acc_pid,
			       struct unf_lport *lport)
{
#define UNF_NONE_DISC 0X0 /* before enter DISC */
	struct unf_disc *disc = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(gid_acc_pid);
	FC_CHECK_RETURN_VOID(lport);
	disc = &lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	switch (disc->disc_option) {
	case UNF_INIT_DISC: /* from SCR callback with INI mode */
		disc->disc_option = UNF_NONE_DISC;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		unf_handle_init_gid_acc(gid_acc_pid, lport); /* R_Port from Disc_list */
		break;

	case UNF_RSCN_DISC: /* from RSCN payload parse(analysis) */
		disc->disc_option = UNF_NONE_DISC;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		unf_handle_rscn_gid_acc(gid_acc_pid, lport); /* R_Port from busy_list */
		break;

	default:
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x)'s disc option(0x%x) is abnormal",
			     lport->port_id, lport->nport_id, disc->disc_option);
		break;
	}
}

static void unf_gid_ft_ob_callback(struct unf_xchg *xchg)
{
	/* Do recovery */
	struct unf_lport *lport = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	struct unf_disc *disc = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	sfs_ptr = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!sfs_ptr)
		return;

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
	if (!lport)
		return;

	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	/* Do DISC recovery operation */
	unf_disc_error_recovery(lport);
}

static void unf_gid_ft_callback(void *lport, void *rport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_gid_acc_pld *gid_acc_pld = NULL;
	struct unf_xchg *unf_xchg = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	u32 cmnd_rsp_size = 0;
	u32 rjt_reason = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)xchg;
	disc = &unf_lport->disc;

	sfs_ptr = unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	gid_acc_pld = sfs_ptr->get_id.gid_rsp.gid_acc_pld;
	if (!gid_acc_pld) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) GID_FT response payload is NULL",
			     unf_lport->port_id);

		return;
	}

	cmnd_rsp_size = gid_acc_pld->ctiu_pream.cmnd_rsp_size;
	if (UNF_CT_IU_ACCEPT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_SUCCESS);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Process GID_FT ACC */
		unf_gid_acc_handle(gid_acc_pld, unf_lport);
	} else if (UNF_CT_IU_REJECT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		rjt_reason = (gid_acc_pld->ctiu_pream.frag_reason_exp_vend);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) GID_FT was rejected with reason code(0x%x)",
			     unf_lport->port_id, rjt_reason);

		if (UNF_CTIU_RJT_EXP_FC4TYPE_NO_REG ==
		    (rjt_reason & UNF_CTIU_RJT_EXP_MASK)) {
			spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
			unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_SUCCESS);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

			unf_gid_acc_handle(gid_acc_pld, unf_lport);
		} else {
			spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
			unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_SUCCESS);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
		}
	} else {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_FAILED);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Do DISC recovery operation */
		unf_disc_error_recovery(unf_lport);
	}
}

static void unf_gid_pt_ob_callback(struct unf_xchg *xchg)
{
	/* Do recovery */
	struct unf_lport *lport = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	struct unf_disc *disc = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	sfs_ptr = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!sfs_ptr)
		return;

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
	if (!lport)
		return;

	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	unf_disc_state_ma(lport, UNF_EVENT_DISC_FAILED);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	/* Do DISC recovery operation */
	unf_disc_error_recovery(lport);
}

static void unf_gid_pt_callback(void *lport, void *rport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_gid_acc_pld *gid_acc_pld = NULL;
	struct unf_xchg *unf_xchg = NULL;
	union unf_sfs_u *sfs_ptr = NULL;
	u32 cmnd_rsp_size = 0;
	u32 rjt_reason = 0;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_rport = (struct unf_rport *)rport;
	disc = &unf_lport->disc;
	unf_xchg = (struct unf_xchg *)xchg;
	sfs_ptr = unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;

	gid_acc_pld = sfs_ptr->get_id.gid_rsp.gid_acc_pld;
	if (!gid_acc_pld) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) GID_PT response payload is NULL",
			     unf_lport->port_id);
		return;
	}

	cmnd_rsp_size = (gid_acc_pld->ctiu_pream.cmnd_rsp_size);
	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_SUCCESS);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		unf_gid_acc_handle(gid_acc_pld, unf_lport);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		rjt_reason = (gid_acc_pld->ctiu_pream.frag_reason_exp_vend);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) GID_PT was rejected with reason code(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, rjt_reason);

		if ((rjt_reason & UNF_CTIU_RJT_EXP_MASK) ==
		    UNF_CTIU_RJT_EXP_PORTTYPE_NO_REG) {
			spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
			unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_SUCCESS);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

			unf_gid_acc_handle(gid_acc_pld, unf_lport);
		} else {
			ret = unf_send_gid_ft(unf_lport, unf_rport);
			if (ret != RETURN_OK)
				goto SEND_GID_PT_FT_FAILED;
		}
	} else {
		goto SEND_GID_PT_FT_FAILED;
	}

	return;
SEND_GID_PT_FT_FAILED:
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_FAILED);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	unf_disc_error_recovery(unf_lport);
}

static void unf_gnn_id_ob_callback(struct unf_xchg *xchg)
{
	/* Send GFF_ID */
	struct unf_lport *lport = NULL;
	struct unf_rport *sns_port = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 nport_id = 0;
	struct unf_lport *root_lport = NULL;

	FC_CHECK_RETURN_VOID(xchg);
	lport = xchg->lport;
	FC_CHECK_RETURN_VOID(lport);
	sns_port = xchg->rport;
	FC_CHECK_RETURN_VOID(sns_port);
	nport_id = xchg->disc_portid;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x) send GNN_ID failed to inquire RPort(0x%x)",
		     lport->port_id, nport_id);

	root_lport = (struct unf_lport *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.thread);

	/* NOTE: continue next stage */
	ret = unf_get_and_post_disc_event(lport, sns_port, nport_id, UNF_DISC_GET_FEATURE);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			     lport->port_id, UNF_DISC_GET_FEATURE, nport_id);

		unf_rcv_gff_id_rsp_unknown(lport, nport_id);
	}
}

static void unf_rcv_gnn_id_acc(struct unf_lport *lport,
			       struct unf_rport *sns_port,
			       struct unf_gnnid_rsp *gnnid_rsp_pld,
			       u32 nport_id)
{
	/* Send GFF_ID or Link down immediately */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_sns_port = sns_port;
	struct unf_gnnid_rsp *unf_gnnid_rsp_pld = gnnid_rsp_pld;
	struct unf_rport *rport = NULL;
	u64 node_name = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(sns_port);
	FC_CHECK_RETURN_VOID(gnnid_rsp_pld);

	node_name = ((u64)(unf_gnnid_rsp_pld->node_name[ARRAY_INDEX_0]) << UNF_SHIFT_32) |
		((u64)(unf_gnnid_rsp_pld->node_name[ARRAY_INDEX_1]));

	if (unf_lport->node_name == node_name) {
		/* R_Port & L_Port with same Node Name */
		rport = unf_get_rport_by_nport_id(unf_lport, nport_id);
		if (rport) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
				     "[info]Port(0x%x) has the same node name(0x%llx) with RPort(0x%x), linkdown it",
				     unf_lport->port_id, node_name, nport_id);

			/* Destroy immediately */
			unf_rport_immediate_link_down(unf_lport, rport);
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Port(0x%x) got RPort(0x%x) with node name(0x%llx) by GNN_ID",
			     unf_lport->port_id, nport_id, node_name);

		/* Start to Send GFF_ID */
		ret = unf_get_and_post_disc_event(unf_lport, unf_sns_port,
						  nport_id, UNF_DISC_GET_FEATURE);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
				     unf_lport->port_id, UNF_DISC_GET_FEATURE, nport_id);

			unf_rcv_gff_id_rsp_unknown(unf_lport, nport_id);
		}
	}
}

static void unf_rcv_gnn_id_rjt(struct unf_lport *lport,
			       struct unf_rport *sns_port,
			       struct unf_gnnid_rsp *gnnid_rsp_pld,
			       u32 nport_id)
{
	/* Send GFF_ID */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_sns_port = sns_port;
	struct unf_gnnid_rsp *unf_gnnid_rsp_pld = gnnid_rsp_pld;
	u32 rjt_reason = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(sns_port);
	FC_CHECK_RETURN_VOID(gnnid_rsp_pld);

	rjt_reason = (unf_gnnid_rsp_pld->ctiu_pream.frag_reason_exp_vend);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x_0x%x) GNN_ID was rejected with reason code(0x%x)",
		     unf_lport->port_id, unf_lport->nport_id, rjt_reason);

	if (!UNF_GNN_GFF_ID_RJT_REASON(rjt_reason)) {
		/* Node existence: Continue next stage */
		ret = unf_get_and_post_disc_event(unf_lport, unf_sns_port,
						  nport_id, UNF_DISC_GET_FEATURE);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
				     unf_lport->port_id, UNF_DISC_GET_FEATURE, nport_id);

			unf_rcv_gff_id_rsp_unknown(unf_lport, nport_id);
		}
	}
}

void unf_rcv_gnn_id_rsp_unknown(struct unf_lport *lport,
				struct unf_rport *sns_port, u32 nport_id)
{
	/* Send GFF_ID */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_sns_port = sns_port;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(sns_port);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x_0x%x) Rportid(0x%x) GNN_ID response is unknown. Sending GFF_ID",
		     unf_lport->port_id, unf_lport->nport_id, nport_id);

	ret = unf_get_and_post_disc_event(unf_lport, unf_sns_port, nport_id, UNF_DISC_GET_FEATURE);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			     unf_lport->port_id, UNF_DISC_GET_FEATURE,
			     nport_id);

		/* NOTE: go to next stage */
		unf_rcv_gff_id_rsp_unknown(unf_lport, nport_id);
	}
}

static void unf_gnn_id_callback(void *lport, void *sns_port, void *xchg)
{
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_rport *unf_sns_port = (struct unf_rport *)sns_port;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_gnnid_rsp *gnnid_rsp_pld = NULL;
	u32 cmnd_rsp_size = 0;
	u32 nport_id = 0;
	struct unf_lport *root_lport = NULL;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(sns_port);
	FC_CHECK_RETURN_VOID(xchg);

	nport_id = unf_xchg->disc_portid;
	gnnid_rsp_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->gnn_id_rsp;
	cmnd_rsp_size = gnnid_rsp_pld->ctiu_pream.cmnd_rsp_size;

	root_lport = (struct unf_lport *)unf_lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.thread);

	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		/* Case ACC: send GFF_ID or Link down immediately */
		unf_rcv_gnn_id_acc(unf_lport, unf_sns_port, gnnid_rsp_pld, nport_id);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		/* Case RJT: send GFF_ID */
		unf_rcv_gnn_id_rjt(unf_lport, unf_sns_port, gnnid_rsp_pld, nport_id);
	} else { /* NOTE: continue next stage */
		/* Case unknown: send GFF_ID */
		unf_rcv_gnn_id_rsp_unknown(unf_lport, unf_sns_port, nport_id);
	}
}

static void unf_gff_id_ob_callback(struct unf_xchg *xchg)
{
	/* Send PLOGI */
	struct unf_lport *lport = NULL;
	struct unf_lport *root_lport = NULL;
	struct unf_rport *rport = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 nport_id = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	nport_id = xchg->disc_portid;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_CHECK_RETURN_VOID(lport);

	root_lport = (struct unf_lport *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.thread);

	/* Get (safe) R_Port */
	rport = unf_get_rport_by_nport_id(lport, nport_id);
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY, nport_id);
	if (!rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't allocate new RPort(0x%x)",
			     lport->port_id, nport_id);
		return;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x_0x%x) send GFF_ID(0x%x_0x%x) to RPort(0x%x_0x%x) abnormal",
		     lport->port_id, lport->nport_id, xchg->oxid, xchg->rxid,
		     rport->rport_index, rport->nport_id);

	/* Update R_Port state: PLOGI_WAIT */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = nport_id;
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* NOTE: Start to send PLOGI */
	ret = unf_send_plogi(lport, rport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send PLOGI failed, enter recovry",
			     lport->port_id);

		/* Do R_Port recovery */
		unf_rport_error_recovery(rport);
	}
}

void unf_rcv_gff_id_acc(struct unf_lport *lport,
			struct unf_gffid_rsp *gffid_rsp_pld, u32 nport_id)
{
	/* Delay to LOGIN */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *rport = NULL;
	struct unf_gffid_rsp *unf_gffid_rsp_pld = gffid_rsp_pld;
	u32 fc_4feacture = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(gffid_rsp_pld);

	fc_4feacture = unf_gffid_rsp_pld->fc4_feature[ARRAY_INDEX_1];
	if ((UNF_GFF_ACC_MASK & fc_4feacture) == 0)
		fc_4feacture = be32_to_cpu(unf_gffid_rsp_pld->fc4_feature[ARRAY_INDEX_1]);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x_0x%x) RPort(0x%x) received GFF_ID ACC. FC4 feature is 0x%x(1:TGT,2:INI,3:COM)",
		     unf_lport->port_id, unf_lport->nport_id, nport_id, fc_4feacture);

	/* Check (& Get new) R_Port */
	rport = unf_get_rport_by_nport_id(unf_lport, nport_id);
	if (rport)
		rport = unf_find_rport(unf_lport, nport_id, rport->port_name);

	if (rport || (UNF_GET_PORT_OPTIONS(fc_4feacture) != UNF_PORT_MODE_INI)) {
		rport = unf_get_safe_rport(unf_lport, rport, UNF_RPORT_REUSE_ONLY, nport_id);
		FC_CHECK_RETURN_VOID(rport);
	} else {
		return;
	}

	if ((fc_4feacture & UNF_GFF_ACC_MASK) != 0) {
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->options = UNF_GET_PORT_OPTIONS(fc_4feacture);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	} else if (rport->port_name != INVALID_WWPN) {
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->options = unf_get_port_feature(rport->port_name);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}

	/* NOTE: Send PLOGI if necessary */
	unf_check_rport_need_delay_plogi(unf_lport, rport, rport->options);
}

void unf_rcv_gff_id_rjt(struct unf_lport *lport,
			struct unf_gffid_rsp *gffid_rsp_pld, u32 nport_id)
{
	/* Delay LOGIN or LOGO */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *rport = NULL;
	struct unf_gffid_rsp *unf_gffid_rsp_pld = gffid_rsp_pld;
	u32 rjt_reason = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(gffid_rsp_pld);

	/* Check (& Get new) R_Port */
	rport = unf_get_rport_by_nport_id(unf_lport, nport_id);
	if (rport)
		rport = unf_find_rport(unf_lport, nport_id, rport->port_name);

	if (!rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) get RPort by N_Port_ID(0x%x) failed and alloc new",
			     unf_lport->port_id, nport_id);

		rport = unf_rport_get_free_and_init(unf_lport, UNF_PORT_TYPE_FC, nport_id);
		FC_CHECK_RETURN_VOID(rport);

		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = nport_id;
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}

	rjt_reason = unf_gffid_rsp_pld->ctiu_pream.frag_reason_exp_vend;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x) send GFF_ID for RPort(0x%x) but was rejected. Reason code(0x%x)",
		     unf_lport->port_id, nport_id, rjt_reason);

	if (!UNF_GNN_GFF_ID_RJT_REASON(rjt_reason)) {
		rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_ONLY, nport_id);
		FC_CHECK_RETURN_VOID(rport);

		/* Update R_Port state: PLOGI_WAIT */
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = nport_id;
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Delay to send PLOGI */
		unf_rport_delay_login(rport);
	} else {
		spin_lock_irqsave(&rport->rport_state_lock, flag);
		if (rport->rp_state == UNF_RPORT_ST_INIT) {
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);

			/* Enter closing state */
			unf_rport_enter_logo(unf_lport, rport);
		} else {
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);
		}
	}
}

void unf_rcv_gff_id_rsp_unknown(struct unf_lport *lport, u32 nport_id)
{
	/* Send PLOGI */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *rport = NULL;
	ulong flag = 0;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x) send GFF_ID for RPort(0x%x) but response is unknown",
		     unf_lport->port_id, nport_id);

	/* Get (Safe) R_Port & Set State */
	rport = unf_get_rport_by_nport_id(unf_lport, nport_id);
	if (rport)
		rport = unf_find_rport(unf_lport, nport_id, rport->port_name);

	if (!rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) can't get RPort by NPort ID(0x%x), allocate new RPort",
			     unf_lport->port_id, unf_lport->nport_id, nport_id);

		rport = unf_rport_get_free_and_init(unf_lport, UNF_PORT_TYPE_FC, nport_id);
		FC_CHECK_RETURN_VOID(rport);

		spin_lock_irqsave(&rport->rport_state_lock, flag);
		rport->nport_id = nport_id;
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}

	rport = unf_get_safe_rport(unf_lport, rport, UNF_RPORT_REUSE_ONLY, nport_id);
	FC_CHECK_RETURN_VOID(rport);

	/* Update R_Port state: PLOGI_WAIT */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->nport_id = nport_id;
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* Start to send PLOGI */
	ret = unf_send_plogi(unf_lport, rport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) can not send PLOGI for RPort(0x%x), enter recovery",
			     unf_lport->port_id, nport_id);

		unf_rport_error_recovery(rport);
	}
}

static void unf_gff_id_callback(void *lport, void *sns_port, void *xchg)
{
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_lport *root_lport = NULL;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_gffid_rsp *gffid_rsp_pld = NULL;
	u32 cmnd_rsp_size = 0;
	u32 nport_id = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(sns_port);
	FC_CHECK_RETURN_VOID(xchg);

	nport_id = unf_xchg->disc_portid;

	gffid_rsp_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->gff_id_rsp;
	cmnd_rsp_size = (gffid_rsp_pld->ctiu_pream.cmnd_rsp_size);

	root_lport = (struct unf_lport *)unf_lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.thread);

	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		/* Case for GFF_ID ACC: (Delay)PLOGI */
		unf_rcv_gff_id_acc(unf_lport, gffid_rsp_pld, nport_id);
	} else if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_REJECT) {
		/* Case for GFF_ID RJT: Delay PLOGI or LOGO directly */
		unf_rcv_gff_id_rjt(unf_lport, gffid_rsp_pld, nport_id);
	} else {
		/* Send PLOGI */
		unf_rcv_gff_id_rsp_unknown(unf_lport, nport_id);
	}
}

static void unf_rcv_gpn_id_acc(struct unf_lport *lport,
			       u32 nport_id, u64 port_name)
{
	/* then PLOGI or re-login */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *rport = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	rport = unf_find_valid_rport(unf_lport, port_name, nport_id);
	if (rport) {
		/* R_Port with TGT mode & L_Port with INI mode:
		 * send PLOGI with INIT state
		 */
		if ((rport->options & UNF_PORT_MODE_TGT) == UNF_PORT_MODE_TGT) {
			rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_INIT, nport_id);
			FC_CHECK_RETURN_VOID(rport);

			/* Update R_Port state: PLOGI_WAIT */
			spin_lock_irqsave(&rport->rport_state_lock, flag);
			rport->nport_id = nport_id;
			unf_rport_state_ma(rport, UNF_EVENT_RPORT_ENTER_PLOGI);
			spin_unlock_irqrestore(&rport->rport_state_lock, flag);

			/* Start to send PLOGI */
			ret = unf_send_plogi(unf_lport, rport);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI failed for 0x%x, enter recovry",
					     unf_lport->port_id, unf_lport->nport_id, nport_id);

				unf_rport_error_recovery(rport);
			}
		} else {
			spin_lock_irqsave(&rport->rport_state_lock, flag);
			if (rport->rp_state != UNF_RPORT_ST_PLOGI_WAIT &&
			    rport->rp_state != UNF_RPORT_ST_PRLI_WAIT &&
			    rport->rp_state != UNF_RPORT_ST_READY) {
				unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
				spin_unlock_irqrestore(&rport->rport_state_lock, flag);

				/* Do LOGO operation */
				unf_rport_enter_logo(unf_lport, rport);
			} else {
				spin_unlock_irqrestore(&rport->rport_state_lock, flag);
			}
		}
	} else {
		/* Send GNN_ID */
		(void)unf_rport_relogin(unf_lport, nport_id);
	}
}

static void unf_rcv_gpn_id_rjt(struct unf_lport *lport, u32 nport_id)
{
	struct unf_lport *unf_lport = lport;
	struct unf_rport *rport = NULL;

	FC_CHECK_RETURN_VOID(lport);

	rport = unf_get_rport_by_nport_id(unf_lport, nport_id);
	if (rport)
		/* Do R_Port Link down */
		unf_rport_linkdown(unf_lport, rport);
}

void unf_rcv_gpn_id_rsp_unknown(struct unf_lport *lport, u32 nport_id)
{
	struct unf_lport *unf_lport = lport;

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x) wrong response of GPN_ID with RPort(0x%x)",
		     unf_lport->port_id, nport_id);

	/* NOTE: go to next stage */
	(void)unf_rport_relogin(unf_lport, nport_id);
}

static void unf_gpn_id_ob_callback(struct unf_xchg *xchg)
{
	struct unf_lport *lport = NULL;
	u32 nport_id = 0;
	struct unf_lport *root_lport = NULL;

	FC_CHECK_RETURN_VOID(xchg);

	lport = xchg->lport;
	nport_id = xchg->disc_portid;
	FC_CHECK_RETURN_VOID(lport);

	root_lport = (struct unf_lport *)lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.thread);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x) send GPN_ID failed to inquire RPort(0x%x)",
		     lport->port_id, nport_id);

	/* NOTE: go to next stage */
	(void)unf_rport_relogin(lport, nport_id);
}

static void unf_gpn_id_callback(void *lport, void *sns_port, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_gpnid_rsp *gpnid_rsp_pld = NULL;
	u64 port_name = 0;
	u32 cmnd_rsp_size = 0;
	u32 nport_id = 0;
	struct unf_lport *root_lport = NULL;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(sns_port);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)xchg;
	nport_id = unf_xchg->disc_portid;

	root_lport = (struct unf_lport *)unf_lport->root_lport;
	atomic_inc(&root_lport->disc.disc_thread_info.disc_contrl_size);
	wake_up_process(root_lport->disc.disc_thread_info.thread);

	gpnid_rsp_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->gpn_id_rsp;
	cmnd_rsp_size = gpnid_rsp_pld->ctiu_pream.cmnd_rsp_size;
	if (UNF_CT_IU_ACCEPT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		/* GPN_ID ACC */
		port_name = ((u64)(gpnid_rsp_pld->port_name[ARRAY_INDEX_0])
			     << UNF_SHIFT_32) |
			    ((u64)(gpnid_rsp_pld->port_name[ARRAY_INDEX_1]));

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Port(0x%x) GPN_ID ACC with WWN(0x%llx) RPort NPort ID(0x%x)",
			     unf_lport->port_id, port_name, nport_id);

		/* Send PLOGI or LOGO or GNN_ID */
		unf_rcv_gpn_id_acc(unf_lport, nport_id, port_name);
	} else if (UNF_CT_IU_REJECT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		/* GPN_ID RJT: Link Down */
		unf_rcv_gpn_id_rjt(unf_lport, nport_id);
	} else {
		/* GPN_ID response type unknown: Send GNN_ID */
		unf_rcv_gpn_id_rsp_unknown(unf_lport, nport_id);
	}
}

static void unf_rff_id_ob_callback(struct unf_xchg *xchg)
{
	/* Do recovery */
	struct unf_lport *lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x_0x%x) send RFF_ID failed",
		     lport->port_id, lport->nport_id);

	unf_lport_error_recovery(lport);
}

static void unf_rff_id_callback(void *lport, void *rport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_ctiu_prem *ctiu_prem = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 cmnd_rsp_size = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)xchg;
	if (unlikely(!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr))
		return;

	unf_rport = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_FCTRL);
	unf_rport = unf_get_safe_rport(unf_lport, unf_rport,
				       UNF_RPORT_REUSE_ONLY, UNF_FC_FID_FCTRL);
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't allocate RPort(0x%x)",
			     unf_lport->port_id, UNF_FC_FID_FCTRL);
		return;
	}

	unf_rport->nport_id = UNF_FC_FID_FCTRL;
	ctiu_prem = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rff_id_rsp.ctiu_pream;
	cmnd_rsp_size = ctiu_prem->cmnd_rsp_size;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]LOGIN: Port(0x%x_0x%x) RFF_ID rsp is (0x%x)",
		     unf_lport->port_id, unf_lport->nport_id,
		     (cmnd_rsp_size & UNF_CT_IU_RSP_MASK));

	/* RSP Type check: some SW not support RFF_ID, go to next stage also */
	if ((cmnd_rsp_size & UNF_CT_IU_RSP_MASK) == UNF_CT_IU_ACCEPT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Port(0x%x_0x%x) receive RFF ACC(0x%x) in state(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id,
			     (cmnd_rsp_size & UNF_CT_IU_RSP_MASK), unf_lport->states);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) receive RFF RJT(0x%x) in state(0x%x) with RJT reason code(0x%x) explanation(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id,
			     (cmnd_rsp_size & UNF_CT_IU_RSP_MASK), unf_lport->states,
			     (ctiu_prem->frag_reason_exp_vend) & UNF_CT_IU_REASON_MASK,
			     (ctiu_prem->frag_reason_exp_vend) & UNF_CT_IU_EXPLAN_MASK);
	}

	/* L_Port state check */
	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	if (unf_lport->states != UNF_LPORT_ST_RFF_ID_WAIT) {
		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) receive RFF reply in state(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, unf_lport->states);

		return;
	}
	/* LPort: RFF_ID_WAIT --> SCR_WAIT */
	unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_REMOTE_ACC);
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	ret = unf_send_scr(unf_lport, unf_rport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) send SCR failed",
			     unf_lport->port_id, unf_lport->nport_id);
		unf_lport_error_recovery(unf_lport);
	}
}

static void unf_rft_id_ob_callback(struct unf_xchg *xchg)
{
	struct unf_lport *lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x_0x%x) send RFT_ID failed",
		     lport->port_id, lport->nport_id);
	unf_lport_error_recovery(lport);
}

static void unf_rft_id_callback(void *lport, void *rport, void *xchg)
{
	/* RFT_ID --->>> RFF_ID */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_ctiu_prem *ctiu_prem = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 cmnd_rsp_size = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_rport = (struct unf_rport *)rport;
	unf_xchg = (struct unf_xchg *)xchg;

	if (!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) SFS entry is NULL with state(0x%x)",
			     unf_lport->port_id, unf_lport->states);
		return;
	}

	ctiu_prem = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr
		->rft_id_rsp.ctiu_pream;
	cmnd_rsp_size = (ctiu_prem->cmnd_rsp_size);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x_0x%x) RFT_ID response is (0x%x)",
		     (cmnd_rsp_size & UNF_CT_IU_RSP_MASK), unf_lport->port_id,
		     unf_lport->nport_id);

	if (UNF_CT_IU_ACCEPT == (cmnd_rsp_size & UNF_CT_IU_RSP_MASK)) {
		/* Case for RFT_ID ACC: send RFF_ID */
		spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
		if (unf_lport->states != UNF_LPORT_ST_RFT_ID_WAIT) {
			spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x_0x%x) receive RFT_ID ACC in state(0x%x)",
				     unf_lport->port_id, unf_lport->nport_id,
				     unf_lport->states);

			return;
		}

		/* LPort: RFT_ID_WAIT --> RFF_ID_WAIT */
		unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_REMOTE_ACC);
		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

		/* Start to send RFF_ID GS command */
		ret = unf_send_rff_id(unf_lport, unf_rport, UNF_FC4_FCP_TYPE);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x_0x%x) send RFF_ID failed",
				     unf_lport->port_id, unf_lport->nport_id);
			unf_lport_error_recovery(unf_lport);
		}
	} else {
		/* Case for RFT_ID RJT: do recovery */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) receive RFT_ID RJT with reason_code(0x%x) explanation(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id,
			     (ctiu_prem->frag_reason_exp_vend) & UNF_CT_IU_REASON_MASK,
			     (ctiu_prem->frag_reason_exp_vend) & UNF_CT_IU_EXPLAN_MASK);

		/* Do L_Port recovery */
		unf_lport_error_recovery(unf_lport);
	}
}

static void unf_scr_ob_callback(struct unf_xchg *xchg)
{
	/* Callback fucnion for exception: Do L_Port error recovery */
	struct unf_lport *lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) send SCR failed and do port recovery",
		     lport->port_id);

	unf_lport_error_recovery(lport);
}

static void unf_scr_callback(void *lport, void *rport, void *xchg)
{
	/* Callback function for SCR response: Send GID_PT with INI mode */
	struct unf_lport *unf_lport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_els_acc *els_acc = NULL;
	u32 ret = UNF_RETURN_ERROR;
	ulong port_flag = 0;
	ulong disc_flag = 0;
	u32 cmnd = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)xchg;
	disc = &unf_lport->disc;

	if (!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr)
		return;

	els_acc = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->els_acc;
	if (unf_xchg->byte_orders & UNF_BIT_2)
		cmnd = be32_to_cpu(els_acc->cmnd);
	else
		cmnd = (els_acc->cmnd);

	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		spin_lock_irqsave(&unf_lport->lport_state_lock, port_flag);
		if (unf_lport->states != UNF_LPORT_ST_SCR_WAIT) {
			spin_unlock_irqrestore(&unf_lport->lport_state_lock,
					       port_flag);
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) receive SCR ACC with error state(0x%x)",
				     unf_lport->port_id, unf_lport->nport_id,
				     unf_lport->states);
			return;
		}

		/* LPort: SCR_WAIT --> READY */
		unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_REMOTE_ACC);
		if (unf_lport->states == UNF_LPORT_ST_READY) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]LOGIN: Port(0x%x_0x%x) enter READY state when received SCR response",
				     unf_lport->port_id, unf_lport->nport_id);
		}

		/* Start to Discovery with INI mode: GID_PT */
		if ((unf_lport->options & UNF_PORT_MODE_INI) ==
		    UNF_PORT_MODE_INI) {
			spin_unlock_irqrestore(&unf_lport->lport_state_lock,
					       port_flag);

			if (unf_lport->disc.disc_temp.unf_disc_start) {
				spin_lock_irqsave(&disc->rport_busy_pool_lock,
						  disc_flag);
				unf_lport->disc.disc_option = UNF_INIT_DISC;
				disc->last_disc_jiff = jiffies;
				spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

				ret = unf_lport->disc.disc_temp.unf_disc_start(unf_lport);
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
					     "[info]LOGIN: Port(0x%x) DISC %s with INI mode",
					     unf_lport->port_id,
					     (ret != RETURN_OK) ? "failed" : "succeed");
			}
			return;
		}

		spin_unlock_irqrestore(&unf_lport->lport_state_lock, port_flag);
		/* NOTE: set state with UNF_DISC_ST_END used for
		 * RSCN process
		 */
		spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
		unf_lport->disc.states = UNF_DISC_ST_END;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) is TGT mode, no need to discovery",
			     unf_lport->port_id);

		return;
	}
	unf_lport_error_recovery(unf_lport);
}

void unf_check_rport_need_delay_plogi(struct unf_lport *lport,
				      struct unf_rport *rport, u32 port_feature)
{
	/*
	 * Called by:
	 * 1. Private loop
	 * 2. RCVD GFF_ID ACC
	 */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	ulong flag = 0;
	u32 nport_id = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	nport_id = unf_rport->nport_id;

	/*
	 * Send GFF_ID means L_Port has INI attribute
	 * *
	 * When to send PLOGI:
	 * 1. R_Port has TGT mode (COM or TGT), send PLOGI immediately
	 * 2. R_Port only with INI, send LOGO immediately
	 * 3. R_Port with unknown attribute, delay to send PLOGI
	 */
	if ((UNF_PORT_MODE_TGT & port_feature) ||
	    (UNF_LPORT_ENHANCED_FEATURE_ENHANCED_GFF &
	     unf_lport->enhanced_features)) {
		/* R_Port has TGT mode: send PLOGI immediately */
		unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY, nport_id);
		FC_CHECK_RETURN_VOID(unf_rport);

		/* Update R_Port state: PLOGI_WAIT */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport->nport_id = nport_id;
		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		/* Start to send PLOGI */
		ret = unf_send_plogi(unf_lport, unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI to RPort(0x%x) failed",
				     unf_lport->port_id, unf_lport->nport_id,
				     nport_id);

			unf_rport_error_recovery(unf_rport);
		}
	} else if (port_feature == UNF_PORT_MODE_INI) {
		/* R_Port only with INI mode: can't send PLOGI
		 * --->>> LOGO/nothing
		 */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		if (unf_rport->rp_state == UNF_RPORT_ST_INIT) {
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x_0x%x) send LOGO to RPort(0x%x) which only with INI mode",
				     unf_lport->port_id, unf_lport->nport_id, nport_id);

			/* Enter Closing state */
			unf_rport_enter_logo(unf_lport, unf_rport);
		} else {
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);
		}
	} else {
		/* Unknown R_Port attribute: Delay to send PLOGI */
		unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY, nport_id);
		FC_CHECK_RETURN_VOID(unf_rport);

		/* Update R_Port state: PLOGI_WAIT */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport->nport_id = nport_id;
		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		unf_rport_delay_login(unf_rport);
	}
}
