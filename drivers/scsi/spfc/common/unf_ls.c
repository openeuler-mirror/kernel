// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_ls.h"
#include "unf_log.h"
#include "unf_service.h"
#include "unf_portman.h"
#include "unf_gs.h"
#include "unf_npiv.h"

static void unf_flogi_acc_ob_callback(struct unf_xchg *xchg);
static void unf_plogi_acc_ob_callback(struct unf_xchg *xchg);
static void unf_prli_acc_ob_callback(struct unf_xchg *xchg);
static void unf_rscn_acc_ob_callback(struct unf_xchg *xchg);
static void unf_pdisc_acc_ob_callback(struct unf_xchg *xchg);
static void unf_adisc_acc_ob_callback(struct unf_xchg *xchg);
static void unf_logo_acc_ob_callback(struct unf_xchg *xchg);
static void unf_logo_ob_callback(struct unf_xchg *xchg);
static void unf_logo_callback(void *lport, void *rport, void *xchg);
static void unf_rrq_callback(void *lport, void *rport, void *xchg);
static void unf_rrq_ob_callback(struct unf_xchg *xchg);
static void unf_lport_update_nport_id(struct unf_lport *lport, u32 nport_id);
static void
unf_lport_update_time_params(struct unf_lport *lport,
			     struct unf_flogi_fdisc_payload *flogi_payload);

static void unf_login_with_rport_in_n2n(struct unf_lport *lport,
					u64 remote_port_name,
					u64 remote_node_name);
#define UNF_LOWLEVEL_BBCREDIT 0x6
#define UNF_DEFAULT_BB_SC_N 0

#define UNF_ECHO_REQ_SIZE 0
#define UNF_ECHO_WAIT_SEM_TIMEOUT(lport) (2 * (ulong)(lport)->ra_tov)

#define UNF_SERVICE_COLLECT(service_collect, item)               \
	do {                                                        \
		if ((item) < UNF_SERVICE_BUTT) {                  \
			(service_collect).service_cnt[(item)]++; \
		}                                                   \
	} while (0)

static void unf_check_rport_need_delay_prli(struct unf_lport *lport,
					    struct unf_rport *rport,
					    u32 port_feature)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	port_feature &= UNF_PORT_MODE_BOTH;

	/* Used for: L_Port has INI mode & R_Port is not SW */
	if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
		/*
		 * 1. immediately: R_Port only with TGT, or
		 * L_Port only with INI & R_Port has TGT mode, send PRLI
		 * immediately
		 */
		if ((port_feature == UNF_PORT_MODE_TGT ||
		     lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) ||
		    (UNF_PORT_MODE_TGT == (port_feature & UNF_PORT_MODE_TGT))) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
				     UNF_MAJOR,
				     "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) send PRLI",
				     lport->port_id, lport->nport_id,
				     rport->nport_id, port_feature);
			ret = unf_send_prli(lport, rport, ELS_PRLI);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) send PRLI failed",
					     lport->port_id, lport->nport_id,
					     rport->nport_id, port_feature);

				unf_rport_error_recovery(rport);
			}
		}
		/* 2. R_Port has BOTH mode or unknown, Delay to send PRLI */
		else if (port_feature != UNF_PORT_MODE_INI) {
			/* Prevent: PRLI done before PLOGI */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) delay to send PRLI",
				     lport->port_id, lport->nport_id,
				     rport->nport_id, port_feature);

			/* Delay to send PRLI to R_Port */
			unf_rport_delay_login(rport);
		} else {
			/* 3. R_Port only with INI mode: wait for R_Port's PRLI:
			 * Do not care
			 */
			/* Cancel recovery(timer) work */
			if (delayed_work_pending(&rport->recovery_work)) {
				if (cancel_delayed_work(&rport->recovery_work)) {
					FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
						     "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) is pure INI",
						     lport->port_id,
						     lport->nport_id,
						     rport->nport_id,
						     port_feature);

					unf_rport_ref_dec(rport);
				}
			}

			/* Server: R_Port only support INI, do not care this
			 * case
			 */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]LOGIN: Port(0x%x_0x%x) Rport(0x%x) with feature(0x%x) wait for PRLI",
				     lport->port_id, lport->nport_id,
				     rport->nport_id, port_feature);
		}
	}
}

static u32 unf_low_level_bb_credit(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 bb_credit = UNF_LOWLEVEL_BBCREDIT;

	if (unlikely(!lport))
		return bb_credit;

	unf_lport = lport;

	if (unlikely(!unf_lport->low_level_func.port_mgr_op.ll_port_config_get))
		return bb_credit;

	ret = unf_lport->low_level_func.port_mgr_op.ll_port_config_get((void *)unf_lport->fc_port,
	    UNF_PORT_CFG_GET_WORKBALE_BBCREDIT,
	    (void *)&bb_credit);
	if (unlikely(ret != RETURN_OK)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[warn]Port(0x%x) get BB_Credit failed, use default value(%d)",
			     unf_lport->port_id, UNF_LOWLEVEL_BBCREDIT);

		bb_credit = UNF_LOWLEVEL_BBCREDIT;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) with BB_Credit(%u)", unf_lport->port_id,
		     bb_credit);

	return bb_credit;
}

u32 unf_low_level_bb_scn(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_low_level_port_mgr_op *port_mgr = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 bb_scn = UNF_DEFAULT_BB_SC_N;

	if (unlikely(!lport))
		return bb_scn;

	unf_lport = lport;
	port_mgr = &unf_lport->low_level_func.port_mgr_op;

	if (unlikely(!port_mgr->ll_port_config_get))
		return bb_scn;

	ret = port_mgr->ll_port_config_get((void *)unf_lport->fc_port,
					   UNF_PORT_CFG_GET_WORKBALE_BBSCN,
					   (void *)&bb_scn);
	if (unlikely(ret != RETURN_OK)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[warn]Port(0x%x) get bbscn failed, use default value(%d)",
			     unf_lport->port_id, UNF_DEFAULT_BB_SC_N);

		bb_scn = UNF_DEFAULT_BB_SC_N;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x)'s bbscn(%d)", unf_lport->port_id, bb_scn);

	return bb_scn;
}

static void unf_fill_rec_pld(struct unf_rec_pld *rec_pld, u32 sid)
{
	FC_CHECK_RETURN_VOID(rec_pld);

	rec_pld->rec_cmnd = (UNF_ELS_CMND_REC);
	rec_pld->xchg_org_sid = sid;
	rec_pld->ox_id = INVALID_VALUE16;
	rec_pld->rx_id = INVALID_VALUE16;
}

u32 unf_send_rec(struct unf_lport *lport, struct unf_rport *rport,
		 struct unf_xchg *io_xchg)
{
	struct unf_rec_pld *rec_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(io_xchg, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for PLOGI",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_REC;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;
	pkg.origin_hottag = io_xchg->hotpooltag;
	pkg.origin_magicnum = io_xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];
	rec_pld = &fc_entry->rec.rec_pld;
	memset(rec_pld, 0, sizeof(struct unf_rec_pld));

	unf_fill_rec_pld(rec_pld, lport->nport_id);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[info]LOGIN: Send REC %s. Port(0x%x_0x%x_0x%llx)--->RPort(0x%x_0x%llx) with hottag(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     lport->nport_id, lport->port_name, rport->nport_id,
		     rport->port_name, xchg->hotpooltag);

	return ret;
}

static void unf_fill_flogi_pld(struct unf_flogi_fdisc_payload *flogi_pld,
			       struct unf_lport *lport)
{
	struct unf_fabric_parm *fabric_parms = NULL;

	FC_CHECK_RETURN_VOID(flogi_pld);
	FC_CHECK_RETURN_VOID(lport);

	fabric_parms = &flogi_pld->fabric_parms;
	if (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT ||
	    lport->act_topo == UNF_TOP_P2P_MASK) {
		/* Fabric or P2P or FCoE VN2VN topology */
		fabric_parms->co_parms.bb_credit = unf_low_level_bb_credit(lport);
		fabric_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
		fabric_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
		fabric_parms->co_parms.bb_receive_data_field_size = (lport->max_frame_size);
		fabric_parms->co_parms.bbscn = unf_low_level_bb_scn(lport);
	} else {
		/* Loop topology here */
		fabric_parms->co_parms.clean_address = UNF_CLEAN_ADDRESS_DEFAULT;
		fabric_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		fabric_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
		fabric_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
		fabric_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_LPORT;
		fabric_parms->co_parms.bb_receive_data_field_size = (lport->max_frame_size);
	}

	if (lport->low_level_func.support_max_npiv_num != 0)
		/* support NPIV */
		fabric_parms->co_parms.clean_address = 1;

	fabric_parms->cl_parms[ARRAY_INDEX_2].valid = UNF_CLASS_VALID;

	/* according the user value to set the priority */
	if (lport->qos_cs_ctrl)
		fabric_parms->cl_parms[ARRAY_INDEX_2].priority = UNF_PRIORITY_ENABLE;
	else
		fabric_parms->cl_parms[ARRAY_INDEX_2].priority = UNF_PRIORITY_DISABLE;

	fabric_parms->cl_parms[ARRAY_INDEX_2].sequential_delivery = UNF_SEQUEN_DELIVERY_REQ;
	fabric_parms->cl_parms[ARRAY_INDEX_2].received_data_field_size = (lport->max_frame_size);

	fabric_parms->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	fabric_parms->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	fabric_parms->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	fabric_parms->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);
}

u32 unf_send_flogi(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_xchg *xchg = NULL;
	struct unf_flogi_fdisc_payload *flogi_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for FLOGI",
			     lport->port_id);

		return ret;
	}

	/* FLOGI */
	xchg->cmnd_code = ELS_FLOGI;

	/* for rcvd flogi acc/rjt processer */
	xchg->callback = unf_flogi_callback;
	/* for send flogi failed processer */
	xchg->ob_callback = unf_flogi_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	flogi_pld = &fc_entry->flogi.flogi_payload;
	memset(flogi_pld, 0, sizeof(struct unf_flogi_fdisc_payload));
	unf_fill_flogi_pld(flogi_pld, lport);
	flogi_pld->cmnd = (UNF_ELS_CMND_FLOGI);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Begin to send FLOGI. Port(0x%x)--->RPort(0x%x) with hottag(0x%x)",
		     lport->port_id, rport->nport_id, xchg->hotpooltag);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, flogi_pld,
			    sizeof(struct unf_flogi_fdisc_payload));
	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]LOGIN: Send FLOGI failed. Port(0x%x)--->RPort(0x%x)",
			     lport->port_id, rport->nport_id);

		unf_cm_free_xchg((void *)lport, (void *)xchg);
	}

	return ret;
}

u32 unf_send_fdisc(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_xchg *exch = NULL;
	struct unf_flogi_fdisc_payload *fdisc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	exch = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!exch) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for FDISC",
			     lport->port_id);

		return ret;
	}

	exch->cmnd_code = ELS_FDISC;

	exch->callback = unf_fdisc_callback;
	exch->ob_callback = unf_fdisc_ob_callback;

	unf_fill_package(&pkg, exch, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	fdisc_pld = &fc_entry->fdisc.fdisc_payload;
	memset(fdisc_pld, 0, sizeof(struct unf_flogi_fdisc_payload));
	unf_fill_flogi_pld(fdisc_pld, lport);
	fdisc_pld->cmnd = UNF_ELS_CMND_FDISC;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, exch);

	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)exch);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: FDISC send %s. Port(0x%x)--->RPort(0x%x) with hottag(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, exch->hotpooltag);

	return ret;
}

static void unf_fill_plogi_pld(struct unf_plogi_payload *plogi_pld,
			       struct unf_lport *lport)
{
	struct unf_lgn_parm *login_parms = NULL;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(plogi_pld);
	FC_CHECK_RETURN_VOID(lport);

	unf_lport = lport->root_lport;
	plogi_pld->cmnd = (UNF_ELS_CMND_PLOGI);
	login_parms = &plogi_pld->stparms;

	if (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		/* P2P or Fabric mode or FCoE VN2VN */
		login_parms->co_parms.bb_credit = (unf_low_level_bb_credit(lport));
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_NFPORT;
		login_parms->co_parms.bbscn =
		    (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC)
			? 0
			: unf_low_level_bb_scn(lport);
	} else {
		/* Public loop & Private loop mode */
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_LPORT;
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing = UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size = (lport->max_frame_size);
	login_parms->co_parms.nport_total_concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->co_parms.relative_offset = (UNF_PLOGI_RO_CATEGORY);
	login_parms->co_parms.e_d_tov = UNF_DEFAULT_EDTOV;
	if (unf_lport->priority == UNF_PRIORITY_ENABLE) {
		login_parms->cl_parms[ARRAY_INDEX_2].priority =
		    UNF_PRIORITY_ENABLE;
	} else {
		login_parms->cl_parms[ARRAY_INDEX_2].priority =
		    UNF_PRIORITY_DISABLE;
	}

	/* for class_3 */
	login_parms->cl_parms[ARRAY_INDEX_2].valid = UNF_CLASS_VALID;
	login_parms->cl_parms[ARRAY_INDEX_2].received_data_field_size = (lport->max_frame_size);
	login_parms->cl_parms[ARRAY_INDEX_2].concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->cl_parms[ARRAY_INDEX_2].open_sequence_per_exchange = (UNF_PLOGI_SEQ_PER_XCHG);

	login_parms->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	login_parms->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	login_parms->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	login_parms->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, plogi_pld, sizeof(struct unf_plogi_payload));
}

u32 unf_send_plogi(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_plogi_payload *plogi_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for PLOGI",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_PLOGI;

	xchg->callback = unf_plogi_callback;
	xchg->ob_callback = unf_plogi_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;
	unf_cm_xchg_mgr_abort_io_by_id(lport, rport, xchg->sid, xchg->did, 0);

	plogi_pld = &fc_entry->plogi.payload;
	memset(plogi_pld, 0, sizeof(struct unf_plogi_payload));
	unf_fill_plogi_pld(plogi_pld, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Send PLOGI %s. Port(0x%x_0x%x_0x%llx)--->RPort(0x%x_0x%llx) with hottag(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     lport->nport_id, lport->port_name, rport->nport_id,
		     rport->port_name, xchg->hotpooltag);

	return ret;
}

static void unf_fill_logo_pld(struct unf_logo_payload *logo_pld,
			      struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(logo_pld);
	FC_CHECK_RETURN_VOID(lport);

	logo_pld->cmnd = (UNF_ELS_CMND_LOGO);
	logo_pld->nport_id = (lport->nport_id);
	logo_pld->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	logo_pld->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, logo_pld, sizeof(struct unf_logo_payload));
}

u32 unf_send_logo(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_logo_payload *logo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	struct unf_frame_pkg pkg = {0};
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for LOGO",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_LOGO;
	/* retry or link down immediately */
	xchg->callback = unf_logo_callback;
	/* do nothing */
	xchg->ob_callback = unf_logo_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	logo_pld = &fc_entry->logo.payload;
	memset(logo_pld, 0, sizeof(struct unf_logo_payload));
	unf_fill_logo_pld(logo_pld, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	rport->logo_retries++;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[info]LOGIN: LOGO send %s. Port(0x%x)--->RPort(0x%x) hottag(0x%x) Retries(%d)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, xchg->hotpooltag, rport->logo_retries);

	return ret;
}

u32 unf_send_logo_by_did(struct unf_lport *lport, u32 did)
{
	struct unf_logo_payload *logo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	struct unf_frame_pkg pkg = {0};
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, did, NULL, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for LOGO",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_LOGO;

	unf_fill_package(&pkg, xchg, NULL);
	pkg.type = UNF_PKG_ELS_REQ;

	logo_pld = &fc_entry->logo.payload;
	memset(logo_pld, 0, sizeof(struct unf_logo_payload));
	unf_fill_logo_pld(logo_pld, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: LOGO send %s. Port(0x%x)--->RPort(0x%x) with hottag(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     did, xchg->hotpooltag);

	return ret;
}

static void unf_echo_callback(void *lport, void *rport, void *xchg)
{
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_rport *unf_rport = (struct unf_rport *)rport;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_echo_payload *echo_rsp_pld = NULL;
	u32 cmnd = 0;
	u32 mag_ver_local = 0;
	u32 mag_ver_remote = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_xchg = (struct unf_xchg *)xchg;
	if (!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr)
		return;

	echo_rsp_pld = unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.echo_pld;
	FC_CHECK_RETURN_VOID(echo_rsp_pld);

	if (unf_xchg->byte_orders & UNF_BIT_2) {
		unf_big_end_to_cpu((u8 *)echo_rsp_pld, sizeof(struct unf_echo_payload));
		cmnd = echo_rsp_pld->cmnd;
	} else {
		cmnd = echo_rsp_pld->cmnd;
	}

	mag_ver_local = echo_rsp_pld->data[ARRAY_INDEX_0];
	mag_ver_remote = echo_rsp_pld->data[ARRAY_INDEX_1];

	if (UNF_ELS_CMND_ACC == (cmnd & UNF_ELS_CMND_HIGH_MASK)) {
		if (mag_ver_local == ECHO_MG_VERSION_LOCAL &&
		    mag_ver_remote == ECHO_MG_VERSION_REMOTE) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "LPort(0x%x) send ECHO to RPort(0x%x), received ACC. local snd echo:(0x%x), remote rcv echo:(0x%x), remote snd echo acc:(0x%x), local rcv echo acc:(0x%x)",
				     unf_lport->port_id, unf_rport->nport_id,
				     unf_xchg->private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME],
				     unf_xchg->private_data[PKG_PRIVATE_ECHO_CMD_RCV_TIME],
				     unf_xchg->private_data[PKG_PRIVATE_ECHO_RSP_SND_TIME],
				     unf_xchg->private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME]);
		} else if ((mag_ver_local == ECHO_MG_VERSION_LOCAL) &&
			   (mag_ver_remote != ECHO_MG_VERSION_REMOTE)) {
			/* the peer don't supprt smartping, only local snd and
			 * rcv rsp time stamp
			 */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "LPort(0x%x) send ECHO to RPort(0x%x), received ACC. local snd echo:(0x%x), local rcv echo acc:(0x%x)",
				     unf_lport->port_id, unf_rport->nport_id,
				     unf_xchg->private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME],
				     unf_xchg->private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME]);
		} else if ((mag_ver_local != ECHO_MG_VERSION_LOCAL) &&
			   (mag_ver_remote != ECHO_MG_VERSION_REMOTE)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
				     UNF_MAJOR,
				     "LPort(0x%x) send ECHO to RPort(0x%x), received ACC. local and remote is not FC HBA",
				     unf_lport->port_id, unf_rport->nport_id);
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send ECHO to RPort(0x%x) and received RJT",
			     unf_lport->port_id, unf_rport->nport_id);
	}

	unf_xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_OK;
	unf_xchg->echo_info.response_time = jiffies - unf_xchg->echo_info.response_time;

	/* wake up semaphore */
	up(&unf_xchg->echo_info.echo_sync_sema);
}

static void unf_echo_ob_callback(struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;

	FC_CHECK_RETURN_VOID(xchg);
	unf_lport = xchg->lport;
	FC_CHECK_RETURN_VOID(unf_lport);
	unf_rport = xchg->rport;
	FC_CHECK_RETURN_VOID(unf_rport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) send ECHO to RPort(0x%x) but timeout",
		     unf_lport->port_id, unf_rport->nport_id);

	xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_FAIL;

	/* wake up semaphore */
	up(&xchg->echo_info.echo_sync_sema);
}

u32 unf_send_echo(struct unf_lport *lport, struct unf_rport *rport, u32 *time)
{
	struct unf_echo_payload *echo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	struct unf_frame_pkg pkg = {0};
	u32 ret = UNF_RETURN_ERROR;
	ulong delay = 0;
	dma_addr_t phy_echo_addr;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(time, UNF_RETURN_ERROR);

	delay = UNF_ECHO_WAIT_SEM_TIMEOUT(lport);
	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for ECHO",
			     lport->port_id);

		return ret;
	}

	/* ECHO */
	xchg->cmnd_code = ELS_ECHO;
	xchg->fcp_sfs_union.sfs_entry.cur_offset = UNF_ECHO_REQ_SIZE;

	/* Set callback function, wake up semaphore */
	xchg->callback = unf_echo_callback;
	/* wake up semaphore */
	xchg->ob_callback = unf_echo_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	echo_pld = (struct unf_echo_payload *)unf_get_one_big_sfs_buf(xchg);
	if (!echo_pld) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't allocate buffer for ECHO",
			     lport->port_id);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	fc_entry->echo.echo_pld = echo_pld;
	phy_echo_addr = pci_map_single(lport->low_level_func.dev, echo_pld,
				       UNF_ECHO_PAYLOAD_LEN,
				       DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(lport->low_level_func.dev, phy_echo_addr)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) pci map err", lport->port_id);
		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}
	fc_entry->echo.phy_echo_addr = phy_echo_addr;
	memset(echo_pld, 0, sizeof(struct unf_echo_payload));
	echo_pld->cmnd = (UNF_ELS_CMND_ECHO);
	echo_pld->data[ARRAY_INDEX_0] = ECHO_MG_VERSION_LOCAL;

	ret = unf_xchg_ref_inc(xchg, SEND_ELS);
	FC_CHECK_RETURN_VALUE((ret == RETURN_OK), UNF_RETURN_ERROR);

	xchg->echo_info.response_time = jiffies;
	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK) {
		unf_cm_free_xchg((void *)lport, (void *)xchg);
	} else {
		if (down_timeout(&xchg->echo_info.echo_sync_sema,
				 (long)msecs_to_jiffies((u32)delay))) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]ECHO send %s. Port(0x%x)--->RPort(0x%x) but response timeout ",
				     (ret != RETURN_OK) ? "failed" : "succeed",
				     lport->port_id, rport->nport_id);

			xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_FAIL;
		}

		if (xchg->echo_info.echo_result == UNF_ELS_ECHO_RESULT_FAIL) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
				     UNF_MAJOR, "Echo send fail or timeout");

			ret = UNF_RETURN_ERROR;
		} else {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "echo acc rsp,echo_cmd_snd(0x%xus)-->echo_cmd_rcv(0x%xus)-->echo_acc_ snd(0x%xus)-->echo_acc_rcv(0x%xus).",
				     xchg->private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME],
				     xchg->private_data[PKG_PRIVATE_ECHO_CMD_RCV_TIME],
				     xchg->private_data[PKG_PRIVATE_ECHO_RSP_SND_TIME],
				     xchg->private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME]);

			*time =
			    (xchg->private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME] -
			     xchg->private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME]) -
			    (xchg->private_data[PKG_PRIVATE_ECHO_RSP_SND_TIME] -
			     xchg->private_data[PKG_PRIVATE_ECHO_CMD_RCV_TIME]);
		}
	}

	pci_unmap_single(lport->low_level_func.dev, phy_echo_addr,
			 UNF_ECHO_PAYLOAD_LEN, DMA_BIDIRECTIONAL);
	fc_entry->echo.phy_echo_addr = 0;
	unf_xchg_ref_dec(xchg, SEND_ELS);

	return ret;
}

static void unf_fill_prli_pld(struct unf_prli_payload *prli_pld,
			      struct unf_lport *lport)
{
	u32 pld_len = 0;

	FC_CHECK_RETURN_VOID(prli_pld);
	FC_CHECK_RETURN_VOID(lport);

	pld_len = sizeof(struct unf_prli_payload) - UNF_PRLI_SIRT_EXTRA_SIZE;
	prli_pld->cmnd =
	    (UNF_ELS_CMND_PRLI |
	     ((u32)UNF_FC4_FRAME_PAGE_SIZE << UNF_FC4_FRAME_PAGE_SIZE_SHIFT) |
	     ((u32)pld_len));

	prli_pld->parms[ARRAY_INDEX_0] = (UNF_FC4_FRAME_PARM_0_FCP | UNF_FC4_FRAME_PARM_0_I_PAIR);
	prli_pld->parms[ARRAY_INDEX_1] = UNF_NOT_MEANINGFUL;
	prli_pld->parms[ARRAY_INDEX_2] = UNF_NOT_MEANINGFUL;

	/* About Read Xfer_rdy disable */
	prli_pld->parms[ARRAY_INDEX_3] = (UNF_FC4_FRAME_PARM_3_R_XFER_DIS | lport->options);

	/* About FCP confirm */
	if (lport->low_level_func.lport_cfg_items.fcp_conf)
		prli_pld->parms[ARRAY_INDEX_3] |= UNF_FC4_FRAME_PARM_3_CONF_ALLOW;

	/* About Tape support */
	if (lport->low_level_func.lport_cfg_items.tape_support)
		prli_pld->parms[ARRAY_INDEX_3] |=
		    (UNF_FC4_FRAME_PARM_3_REC_SUPPORT |
		     UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT |
		     UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT |
		     UNF_FC4_FRAME_PARM_3_CONF_ALLOW);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x)'s PRLI payload: options(0x%x) parameter-3(0x%x)",
		     lport->port_id, lport->options,
		     prli_pld->parms[ARRAY_INDEX_3]);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, prli_pld, sizeof(struct unf_prli_payload));
}

u32 unf_send_prli(struct unf_lport *lport, struct unf_rport *rport,
		  u32 cmnd_code)
{
	struct unf_prli_payload *prli_pal = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for PRLI",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = cmnd_code;

	/* for rcvd prli acc/rjt processer */
	xchg->callback = unf_prli_callback;
	/* for send prli failed processer */
	xchg->ob_callback = unf_prli_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	prli_pal = &fc_entry->prli.payload;
	memset(prli_pal, 0, sizeof(struct unf_prli_payload));
	unf_fill_prli_pld(prli_pal, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: PRLI send %s. Port(0x%x)--->RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id);

	return ret;
}

static void unf_fill_prlo_pld(struct unf_prli_payload *prlo_pld,
			      struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(prlo_pld);
	FC_CHECK_RETURN_VOID(lport);

	prlo_pld->cmnd = (UNF_ELS_CMND_PRLO);
	prlo_pld->parms[ARRAY_INDEX_0] = (UNF_FC4_FRAME_PARM_0_FCP);
	prlo_pld->parms[ARRAY_INDEX_1] = UNF_NOT_MEANINGFUL;
	prlo_pld->parms[ARRAY_INDEX_2] = UNF_NOT_MEANINGFUL;
	prlo_pld->parms[ARRAY_INDEX_3] = UNF_NO_SERVICE_PARAMS;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, prlo_pld, sizeof(struct unf_prli_payload));
}

u32 unf_send_prlo(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_prli_payload *prlo_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for PRLO", lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_PRLO;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	prlo_pld = &fc_entry->prlo.payload;
	memset(prlo_pld, 0, sizeof(struct unf_prli_payload));
	unf_fill_prlo_pld(prlo_pld, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: PRLO send %s. Port(0x%x)--->RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id);

	return ret;
}

static void unf_fill_pdisc_pld(struct unf_plogi_payload *pdisc_pld,
			       struct unf_lport *lport)
{
	struct unf_lgn_parm *login_parms = NULL;

	FC_CHECK_RETURN_VOID(pdisc_pld);
	FC_CHECK_RETURN_VOID(lport);

	pdisc_pld->cmnd = (UNF_ELS_CMND_PDISC);
	login_parms = &pdisc_pld->stparms;

	if (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		/* P2P & Fabric */
		login_parms->co_parms.bb_credit = (unf_low_level_bb_credit(lport));
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_NFPORT;
		login_parms->co_parms.bbscn =
		    (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC)
			? 0
			: unf_low_level_bb_scn(lport);
	} else {
		/* Public loop & Private loop */
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		/* :1 */
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_LPORT;
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing = UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size = (lport->max_frame_size);
	login_parms->co_parms.nport_total_concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->co_parms.relative_offset = (UNF_PLOGI_RO_CATEGORY);
	login_parms->co_parms.e_d_tov = (lport->ed_tov);

	login_parms->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	login_parms->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	login_parms->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	login_parms->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);

	/* class-3 */
	login_parms->cl_parms[ARRAY_INDEX_2].valid = UNF_CLASS_VALID;
	login_parms->cl_parms[ARRAY_INDEX_2].received_data_field_size = (lport->max_frame_size);
	login_parms->cl_parms[ARRAY_INDEX_2].concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->cl_parms[ARRAY_INDEX_2].open_sequence_per_exchange = (UNF_PLOGI_SEQ_PER_XCHG);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, pdisc_pld, sizeof(struct unf_plogi_payload));
}

u32 unf_send_pdisc(struct unf_lport *lport, struct unf_rport *rport)
{
	/* PLOGI/PDISC with same payload */
	struct unf_plogi_payload *pdisc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for PDISC",
			     lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_PDISC;
	xchg->callback = NULL;
	xchg->ob_callback = NULL;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	pdisc_pld = &fc_entry->pdisc.payload;
	memset(pdisc_pld, 0, sizeof(struct unf_plogi_payload));
	unf_fill_pdisc_pld(pdisc_pld, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: PDISC send %s. Port(0x%x)--->RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id, rport->nport_id);

	return ret;
}

static void unf_fill_adisc_pld(struct unf_adisc_payload *adisc_pld,
			       struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(adisc_pld);
	FC_CHECK_RETURN_VOID(lport);

	adisc_pld->cmnd = (UNF_ELS_CMND_ADISC);
	adisc_pld->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	adisc_pld->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	adisc_pld->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	adisc_pld->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, adisc_pld, sizeof(struct unf_adisc_payload));
}

u32 unf_send_adisc(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_adisc_payload *adisc_pal = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for ADISC", lport->port_id);

		return ret;
	}

	xchg->cmnd_code = ELS_ADISC;

	xchg->callback = NULL;
	xchg->ob_callback = NULL;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;

	adisc_pal = &fc_entry->adisc.adisc_payl;
	memset(adisc_pal, 0, sizeof(struct unf_adisc_payload));
	unf_fill_adisc_pld(adisc_pal, lport);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: ADISC send %s. Port(0x%x)--->RPort(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id);

	return ret;
}

static void unf_fill_rrq_pld(struct unf_rrq *rrq_pld, struct unf_xchg *xchg)
{
	FC_CHECK_RETURN_VOID(rrq_pld);
	FC_CHECK_RETURN_VOID(xchg);

	rrq_pld->cmnd = UNF_ELS_CMND_RRQ;
	rrq_pld->sid = xchg->sid;
	rrq_pld->oxid_rxid = ((u32)xchg->oxid << UNF_SHIFT_16 | xchg->rxid);
}

u32 unf_send_rrq(struct unf_lport *lport, struct unf_rport *rport,
		 struct unf_xchg *xchg)
{
	/* after ABTS Done */
	struct unf_rrq *rrq_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_frame_pkg pkg = {0};
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	unf_xchg = unf_get_sfs_free_xchg_and_init(lport, rport->nport_id, rport, &fc_entry);
	if (!unf_xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for RRQ",
			     lport->port_id);

		return ret;
	}

	unf_xchg->cmnd_code = ELS_RRQ; /* RRQ */

	unf_xchg->callback = unf_rrq_callback; /* release I/O exchange context */
	unf_xchg->ob_callback = unf_rrq_ob_callback;  /* release I/O exchange context */
	unf_xchg->io_xchg = xchg; /* pointer to IO XCHG */

	unf_fill_package(&pkg, unf_xchg, rport);
	pkg.type = UNF_PKG_ELS_REQ;
	rrq_pld = &fc_entry->rrq;
	memset(rrq_pld, 0, sizeof(struct unf_rrq));
	unf_fill_rrq_pld(rrq_pld, xchg);

	ret = unf_ls_gs_cmnd_send(lport, &pkg, unf_xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)unf_xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]RRQ send %s. Port(0x%x)--->RPort(0x%x) free old exchange(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, xchg->hotpooltag);

	return ret;
}

u32 unf_send_flogi_acc(struct unf_lport *lport, struct unf_rport *rport,
		       struct unf_xchg *xchg)
{
	struct unf_flogi_fdisc_payload *flogi_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};
	u16 ox_id = 0;
	u16 rx_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_FLOGI);

	xchg->did = 0;	      /* D_ID must be 0 */
	xchg->sid = UNF_FC_FID_FLOGI; /* S_ID must be 0xfffffe */
	xchg->oid = xchg->sid;
	xchg->callback = NULL;
	xchg->lport = lport;
	xchg->rport = rport;
	xchg->ob_callback = unf_flogi_acc_ob_callback; /* call back for sending
							* FLOGI response
							*/

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	flogi_acc_pld = &fc_entry->flogi_acc.flogi_payload;
	flogi_acc_pld->cmnd = (UNF_ELS_CMND_ACC);
	unf_fill_flogi_pld(flogi_acc_pld, lport);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]LOGIN: FLOGI ACC send %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, ox_id, rx_id);
	return ret;
}

static void unf_fill_plogi_acc_pld(struct unf_plogi_payload *plogi_acc_pld,
				   struct unf_lport *lport)
{
	struct unf_lgn_parm *login_parms = NULL;

	FC_CHECK_RETURN_VOID(plogi_acc_pld);
	FC_CHECK_RETURN_VOID(lport);

	plogi_acc_pld->cmnd = (UNF_ELS_CMND_ACC);
	login_parms = &plogi_acc_pld->stparms;

	if (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		login_parms->co_parms.bb_credit = (unf_low_level_bb_credit(lport));
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_NFPORT; /* 0 */
		login_parms->co_parms.bbscn =
		    (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC)
			? 0
			: unf_low_level_bb_scn(lport);
	} else {
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_LPORT; /* 1 */
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing = UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size = (lport->max_frame_size);
	login_parms->co_parms.nport_total_concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->co_parms.relative_offset = (UNF_PLOGI_RO_CATEGORY);
	login_parms->co_parms.e_d_tov = (lport->ed_tov);
	login_parms->cl_parms[ARRAY_INDEX_2].valid = UNF_CLASS_VALID; /* class-3 */
	login_parms->cl_parms[ARRAY_INDEX_2].received_data_field_size = (lport->max_frame_size);
	login_parms->cl_parms[ARRAY_INDEX_2].concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->cl_parms[ARRAY_INDEX_2].open_sequence_per_exchange = (UNF_PLOGI_SEQ_PER_XCHG);
	login_parms->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	login_parms->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	login_parms->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	login_parms->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, plogi_acc_pld,
			    sizeof(struct unf_plogi_payload));
}

u32 unf_send_plogi_acc(struct unf_lport *lport, struct unf_rport *rport,
		       struct unf_xchg *xchg)
{
	struct unf_plogi_payload *plogi_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};
	u16 ox_id = 0;
	u16 rx_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PLOGI);

	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->callback = NULL;
	xchg->lport = lport;
	xchg->rport = rport;

	xchg->ob_callback = unf_plogi_acc_ob_callback; /* call back for sending PLOGI ACC */

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	plogi_acc_pld = &fc_entry->plogi_acc.payload;
	unf_fill_plogi_acc_pld(plogi_acc_pld, lport);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	if (rport->nport_id < UNF_FC_FID_DOM_MGR ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: PLOGI ACC send %s. Port(0x%x_0x%x_0x%llx)--->RPort(0x%x_0x%llx) with OX_ID(0x%x) RX_ID(0x%x)",
			     (ret != RETURN_OK) ? "failed" : "succeed",
			     lport->port_id, lport->nport_id, lport->port_name,
			     rport->nport_id, rport->port_name, ox_id, rx_id);
	}

	return ret;
}

static void unf_fill_prli_acc_pld(struct unf_prli_payload *prli_acc_pld,
				  struct unf_lport *lport,
				  struct unf_rport *rport)
{
	u32 port_mode = UNF_FC4_FRAME_PARM_3_TGT;

	FC_CHECK_RETURN_VOID(prli_acc_pld);
	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	prli_acc_pld->cmnd =
	    (UNF_ELS_CMND_ACC |
	     ((u32)UNF_FC4_FRAME_PAGE_SIZE << UNF_FC4_FRAME_PAGE_SIZE_SHIFT) |
	     ((u32)(sizeof(struct unf_prli_payload) - UNF_PRLI_SIRT_EXTRA_SIZE)));

	prli_acc_pld->parms[ARRAY_INDEX_0] =
	    (UNF_FC4_FRAME_PARM_0_FCP | UNF_FC4_FRAME_PARM_0_I_PAIR |
	     UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE);
	prli_acc_pld->parms[ARRAY_INDEX_1] = UNF_NOT_MEANINGFUL;
	prli_acc_pld->parms[ARRAY_INDEX_2] = UNF_NOT_MEANINGFUL;

	/* About INI/TGT mode */
	if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
		/* return INI (0x20): R_Port has TGT mode, L_Port has INI mode
		 */
		port_mode = UNF_FC4_FRAME_PARM_3_INI;
	} else {
		port_mode = lport->options;
	}

	/* About Read xfer_rdy disable */
	prli_acc_pld->parms[ARRAY_INDEX_3] =
	    (UNF_FC4_FRAME_PARM_3_R_XFER_DIS | port_mode); /* 0x2 */

	/* About Tape support */
	if (rport->tape_support_needed) {
		prli_acc_pld->parms[ARRAY_INDEX_3] |=
		    (UNF_FC4_FRAME_PARM_3_REC_SUPPORT |
		     UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT |
		     UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT |
		     UNF_FC4_FRAME_PARM_3_CONF_ALLOW);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "PRLI ACC tape support");
	}

	/* About confirm */
	if (lport->low_level_func.lport_cfg_items.fcp_conf)
		prli_acc_pld->parms[ARRAY_INDEX_3] |=
		    UNF_FC4_FRAME_PARM_3_CONF_ALLOW; /* 0x80 */

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, prli_acc_pld,
			    sizeof(struct unf_prli_payload));
}

u32 unf_send_prli_acc(struct unf_lport *lport, struct unf_rport *rport,
		      struct unf_xchg *xchg)
{
	struct unf_prli_payload *prli_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};
	u16 ox_id = 0;
	u16 rx_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PRLI);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;

	xchg->callback = NULL;
	xchg->ob_callback =
	    unf_prli_acc_ob_callback; /* callback when send succeed */

	unf_fill_package(&pkg, xchg, rport);

	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	prli_acc_pld = &fc_entry->prli_acc.payload;
	unf_fill_prli_acc_pld(prli_acc_pld, lport, rport);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	if (rport->nport_id < UNF_FC_FID_DOM_MGR ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: PRLI ACC send %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
			     (ret != RETURN_OK) ? "failed" : "succeed",
			     lport->port_id, rport->nport_id, ox_id, rx_id);
	}

	return ret;
}

u32 unf_send_rec_acc(struct unf_lport *lport, struct unf_rport *rport,
		     struct unf_xchg *xchg)
{
	/* Reserved */
	unf_cm_free_xchg((void *)lport, (void *)xchg);

	return RETURN_OK;
}

static void unf_rrq_acc_ob_callback(struct unf_xchg *xchg)
{
	FC_CHECK_RETURN_VOID(xchg);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[info]RRQ ACC Xchg(0x%p) tag(0x%x)", xchg,
		     xchg->hotpooltag);
}

static void unf_fill_els_acc_pld(struct unf_els_acc *els_acc_pld)
{
	FC_CHECK_RETURN_VOID(els_acc_pld);

	els_acc_pld->cmnd = (UNF_ELS_CMND_ACC);
}

u32 unf_send_rscn_acc(struct unf_lport *lport, struct unf_rport *rport,
		      struct unf_xchg *xchg)
{
	struct unf_els_acc *rscn_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));
	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_RSCN);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;

	xchg->callback = NULL;
	xchg->ob_callback = unf_rscn_acc_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	rscn_acc = &fc_entry->els_acc;
	unf_fill_els_acc_pld(rscn_acc);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: RSCN ACC send %s. Port(0x%x)--->RPort(0x%x) with OXID(0x%x) RXID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, ox_id, rx_id);

	return ret;
}

u32 unf_send_logo_acc(struct unf_lport *lport, struct unf_rport *rport,
		      struct unf_xchg *xchg)
{
	struct unf_els_acc *logo_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_LOGO);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;
	xchg->callback = NULL;
	xchg->ob_callback = unf_logo_acc_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	logo_acc = &fc_entry->els_acc;
	unf_fill_els_acc_pld(logo_acc);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: LOGO ACC send %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
			     (ret != RETURN_OK) ? "failed" : "succeed",
			     lport->port_id, rport->nport_id, ox_id, rx_id);
	}

	return ret;
}

static u32 unf_send_rrq_acc(struct unf_lport *lport, struct unf_rport *rport,
			    struct unf_xchg *xchg)
{
	struct unf_els_acc *rrq_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;
	xchg->callback = NULL; /* do noting */

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	rrq_acc = &fc_entry->els_acc;
	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_RRQ);
	xchg->ob_callback = unf_rrq_acc_ob_callback; /* do noting */
	unf_fill_els_acc_pld(rrq_acc);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]RRQ ACC send %s. Port(0x%x)--->RPort(0x%x) with Xchg(0x%p) OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, xchg, ox_id, rx_id);

	return ret;
}

static void unf_fill_pdisc_acc_pld(struct unf_plogi_payload *pdisc_acc_pld,
				   struct unf_lport *lport)
{
	struct unf_lgn_parm *login_parms = NULL;

	FC_CHECK_RETURN_VOID(pdisc_acc_pld);
	FC_CHECK_RETURN_VOID(lport);

	pdisc_acc_pld->cmnd = (UNF_ELS_CMND_ACC);
	login_parms = &pdisc_acc_pld->stparms;

	if (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		login_parms->co_parms.bb_credit = (unf_low_level_bb_credit(lport));
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_NFPORT;
		login_parms->co_parms.bbscn =
		    (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC)
			? 0
			: unf_low_level_bb_scn(lport);
	} else {
		login_parms->co_parms.bb_credit = UNF_BBCREDIT_LPORT;
		login_parms->co_parms.alternate_bb_credit_mgmt = UNF_BBCREDIT_MANAGE_LPORT;
	}

	login_parms->co_parms.lowest_version = UNF_PLOGI_VERSION_LOWER;
	login_parms->co_parms.highest_version = UNF_PLOGI_VERSION_UPPER;
	login_parms->co_parms.continuously_increasing = UNF_CONTIN_INCREASE_SUPPORT;
	login_parms->co_parms.bb_receive_data_field_size = (lport->max_frame_size);
	login_parms->co_parms.nport_total_concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->co_parms.relative_offset = (UNF_PLOGI_RO_CATEGORY);
	login_parms->co_parms.e_d_tov = (lport->ed_tov);

	login_parms->cl_parms[ARRAY_INDEX_2].valid = UNF_CLASS_VALID; /* class-3 */
	login_parms->cl_parms[ARRAY_INDEX_2].received_data_field_size = (lport->max_frame_size);
	login_parms->cl_parms[ARRAY_INDEX_2].concurrent_sequences = (UNF_PLOGI_CONCURRENT_SEQ);
	login_parms->cl_parms[ARRAY_INDEX_2].open_sequence_per_exchange = (UNF_PLOGI_SEQ_PER_XCHG);

	login_parms->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	login_parms->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	login_parms->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	login_parms->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, pdisc_acc_pld,
			    sizeof(struct unf_plogi_payload));
}

u32 unf_send_pdisc_acc(struct unf_lport *lport, struct unf_rport *rport,
		       struct unf_xchg *xchg)
{
	struct unf_plogi_payload *pdisc_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PDISC);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;

	xchg->callback = NULL;
	xchg->ob_callback = unf_pdisc_acc_ob_callback;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	pdisc_acc_pld = &fc_entry->pdisc_acc.payload;
	unf_fill_pdisc_acc_pld(pdisc_acc_pld, lport);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Send PDISC ACC %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, ox_id, rx_id);

	return ret;
}

static void unf_fill_adisc_acc_pld(struct unf_adisc_payload *adisc_acc_pld,
				   struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(adisc_acc_pld);
	FC_CHECK_RETURN_VOID(lport);

	adisc_acc_pld->cmnd = (UNF_ELS_CMND_ACC);

	adisc_acc_pld->hard_address = (lport->nport_id & UNF_ALPA_MASK);
	adisc_acc_pld->high_node_name = UNF_GET_NAME_HIGH_WORD(lport->node_name);
	adisc_acc_pld->low_node_name = UNF_GET_NAME_LOW_WORD(lport->node_name);
	adisc_acc_pld->high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	adisc_acc_pld->low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);
	adisc_acc_pld->nport_id = lport->nport_id;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, adisc_acc_pld,
			    sizeof(struct unf_adisc_payload));
}

u32 unf_send_adisc_acc(struct unf_lport *lport, struct unf_rport *rport,
		       struct unf_xchg *xchg)
{
	struct unf_adisc_payload *adisc_acc_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};
	u16 ox_id = 0;
	u16 rx_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_ADISC);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;

	xchg->callback = NULL;
	xchg->ob_callback = unf_adisc_acc_ob_callback;
	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	adisc_acc_pld = &fc_entry->adisc_acc.adisc_payl;
	unf_fill_adisc_acc_pld(adisc_acc_pld, lport);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Send ADISC ACC %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, ox_id, rx_id);

	return ret;
}

static void unf_fill_prlo_acc_pld(struct unf_prli_prlo *prlo_acc,
				  struct unf_lport *lport)
{
	struct unf_prli_payload *prlo_acc_pld = NULL;

	FC_CHECK_RETURN_VOID(prlo_acc);

	prlo_acc_pld = &prlo_acc->payload;
	prlo_acc_pld->cmnd =
	    (UNF_ELS_CMND_ACC |
	     ((u32)UNF_FC4_FRAME_PAGE_SIZE << UNF_FC4_FRAME_PAGE_SIZE_SHIFT) |
	     ((u32)sizeof(struct unf_prli_payload)));
	prlo_acc_pld->parms[ARRAY_INDEX_0] =
	    (UNF_FC4_FRAME_PARM_0_FCP | UNF_FC4_FRAME_PARM_0_GOOD_RSP_CODE);
	prlo_acc_pld->parms[ARRAY_INDEX_1] = 0;
	prlo_acc_pld->parms[ARRAY_INDEX_2] = 0;
	prlo_acc_pld->parms[ARRAY_INDEX_3] = 0;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, prlo_acc_pld,
			    sizeof(struct unf_prli_payload));
}

u32 unf_send_prlo_acc(struct unf_lport *lport, struct unf_rport *rport,
		      struct unf_xchg *xchg)
{
	struct unf_prli_prlo *prlo_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_PRLO);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;

	xchg->callback = NULL;
	xchg->ob_callback = NULL;

	unf_fill_package(&pkg, xchg, rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	memset(fc_entry, 0, sizeof(union unf_sfs_u));
	prlo_acc = &fc_entry->prlo_acc;
	unf_fill_prlo_acc_pld(prlo_acc, lport);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Send PRLO ACC %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, ox_id, rx_id);

	return ret;
}

static void unf_prli_acc_ob_callback(struct unf_xchg *xchg)
{
	/* Report R_Port scsi Link Up */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;
	enum unf_rport_login_state rport_state = UNF_RPORT_ST_INIT;

	FC_CHECK_RETURN_VOID(xchg);
	unf_lport = xchg->lport;
	unf_rport = xchg->rport;
	FC_CHECK_RETURN_VOID(unf_lport);
	FC_CHECK_RETURN_VOID(unf_rport);

	/* Update & Report Link Up */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_READY);
	rport_state = unf_rport->rp_state;
	if (unf_rport->nport_id < UNF_FC_FID_DOM_MGR) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[event]LOGIN: Port(0x%x) RPort(0x%x) state(0x%x) WWN(0x%llx) prliacc",
			     unf_lport->port_id, unf_rport->nport_id,
			     unf_rport->rp_state, unf_rport->port_name);
	}
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	if (rport_state == UNF_RPORT_ST_READY) {
		unf_rport->logo_retries = 0;
		unf_update_lport_state_by_linkup_event(unf_lport, unf_rport,
						       unf_rport->options);
	}
}

static void unf_schedule_open_work(struct unf_lport *lport,
				   struct unf_rport *rport)
{
	/* Used for L_Port port only with TGT, or R_Port only with INI */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	ulong delay = 0;
	ulong flag = 0;
	u32 ret = 0;
	u32 port_feature = INVALID_VALUE32;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	delay = (ulong)unf_lport->ed_tov;
	port_feature = unf_rport->options & UNF_PORT_MODE_BOTH;

	if (unf_lport->options == UNF_PORT_MODE_TGT ||
	    port_feature == UNF_PORT_MODE_INI) {
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);

		ret = unf_rport_ref_inc(unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) RPort(0x%x) abnormal, no need open",
				     unf_lport->port_id, unf_lport->nport_id, unf_rport->nport_id);

			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);
			return;
		}

		/* Delay work pending check */
		if (delayed_work_pending(&unf_rport->open_work)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) RPort(0x%x) open work is running, no need re-open",
				     unf_lport->port_id, unf_lport->nport_id,
				     unf_rport->nport_id);

			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);
			unf_rport_ref_dec(unf_rport);
			return;
		}

		/* start open work */
		if (queue_delayed_work(unf_wq, &unf_rport->open_work,
				       (ulong)msecs_to_jiffies((u32)delay))) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x_0x%x) RPort(0x%x) start open work",
				     unf_lport->port_id, unf_lport->nport_id, unf_rport->nport_id);

			(void)unf_rport_ref_inc(unf_rport);
		}
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		unf_rport_ref_dec(unf_rport);
	}
}

static void unf_plogi_acc_ob_callback(struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	unf_lport = xchg->lport;
	unf_rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	FC_CHECK_RETURN_VOID(unf_lport);
	FC_CHECK_RETURN_VOID(unf_rport);

	/*
	 * 1. According to FC-LS 4.2.7.1:
	 * after RCVD PLOGI or sending PLOGI ACC, need to termitate open EXCH
	 */
	unf_cm_xchg_mgr_abort_io_by_id(unf_lport, unf_rport,
				       unf_rport->nport_id, unf_lport->nport_id, 0);

	/* 2. Send PLOGI ACC fail */
	if (xchg->ob_callback_sts != UNF_IO_SUCCESS) {
		/* Do R_Port recovery */
		unf_rport_error_recovery(unf_rport);

		/* Do not care: Just used for L_Port only is TGT mode or R_Port
		 * only is INI mode
		 */
		unf_schedule_open_work(unf_lport, unf_rport);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x_0x%x) send PLOGI ACC failed(0x%x) with RPort(0x%x) feature(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id,
			     unf_lport->options, xchg->ob_callback_sts,
			     unf_rport->nport_id, unf_rport->options);

		return;
	}

	/* 3. Private Loop: check whether or not need to send PRLI */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	if (unf_lport->act_topo == UNF_ACT_TOP_PRIVATE_LOOP &&
	    (unf_rport->rp_state == UNF_RPORT_ST_PRLI_WAIT ||
	     unf_rport->rp_state == UNF_RPORT_ST_READY)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) RPort(0x%x) with State(0x%x) return directly",
			     unf_lport->port_id, unf_lport->nport_id,
			     unf_rport->nport_id, unf_rport->rp_state);

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);
		return;
	}
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PRLI);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	/* 4. Set Port Feature with BOTH: cancel */
	if (unf_rport->options == UNF_PORT_MODE_UNKNOWN && unf_rport->port_name != INVALID_WWPN)
		unf_rport->options = unf_get_port_feature(unf_rport->port_name);

	/*
	 * 5. Check whether need to send PRLI delay
	 * Call by: RCVD PLOGI ACC or callback for sending PLOGI ACC succeed
	 */
	unf_check_rport_need_delay_prli(unf_lport, unf_rport, unf_rport->options);

	/* 6. Do not care: Just used for L_Port only is TGT mode or R_Port only
	 * is INI mode
	 */
	unf_schedule_open_work(unf_lport, unf_rport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x_0x%x_0x%x) send PLOGI ACC succeed with RPort(0x%x) feature(0x%x)",
		     unf_lport->port_id, unf_lport->nport_id, unf_lport->options,
		     unf_rport->nport_id, unf_rport->options);
}

static void unf_flogi_acc_ob_callback(struct unf_xchg *xchg)
{
	/* Callback for Sending FLOGI ACC succeed */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;
	u64 rport_port_name = 0;
	u64 rport_node_name = 0;

	FC_CHECK_RETURN_VOID(xchg);
	FC_CHECK_RETURN_VOID(xchg->lport);
	FC_CHECK_RETURN_VOID(xchg->rport);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	unf_lport = xchg->lport;
	unf_rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	if (unf_rport->port_name == 0 && unf_rport->node_name == 0) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Port(0x%x_0x%x_0x%x) already send Plogi with RPort(0x%x) feature(0x%x).",
			     unf_lport->port_id, unf_lport->nport_id, unf_lport->options,
			     unf_rport->nport_id, unf_rport->options);

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);
		return;
	}

	rport_port_name = unf_rport->port_name;
	rport_node_name = unf_rport->node_name;

	/* Swap case: Set WWPN & WWNN with zero */
	unf_rport->port_name = 0;
	unf_rport->node_name = 0;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	/* Enter PLOGI stage: after send FLOGI ACC succeed */
	unf_login_with_rport_in_n2n(unf_lport, rport_port_name, rport_node_name);
}

static void unf_rscn_acc_ob_callback(struct unf_xchg *xchg)
{
}

static void unf_logo_acc_ob_callback(struct unf_xchg *xchg)
{
}

static void unf_adisc_acc_ob_callback(struct unf_xchg *xchg)
{
}

static void unf_pdisc_acc_ob_callback(struct unf_xchg *xchg)
{
}

static inline u8 unf_determin_bbscn(u8 local_bbscn, u8 remote_bbscn)
{
	if (remote_bbscn == 0 || local_bbscn == 0)
		local_bbscn = 0;
	else
		local_bbscn = local_bbscn > remote_bbscn ? local_bbscn : remote_bbscn;

	return local_bbscn;
}

static void unf_cfg_lowlevel_fabric_params(struct unf_lport *lport,
					   struct unf_rport *rport,
					   struct unf_fabric_parm *login_parms)
{
	struct unf_port_login_parms login_co_parms = {0};
	u32 remote_edtov = 0;
	u32 ret = 0;
	u8 remote_edtov_resolution = 0; /* 0:ms; 1:ns */

	if (!lport->low_level_func.port_mgr_op.ll_port_config_set)
		return;

	login_co_parms.remote_rttov_tag = (u8)UNF_GET_RT_TOV_FROM_PARAMS(login_parms);
	login_co_parms.remote_edtov_tag = 0;
	login_co_parms.remote_bb_credit = (u16)UNF_GET_BB_CREDIT_FROM_PARAMS(login_parms);
	login_co_parms.compared_bbscn =
	    (u32)unf_determin_bbscn((u8)lport->low_level_func.lport_cfg_items.bbscn,
				    (u8)UNF_GET_BB_SC_N_FROM_PARAMS(login_parms));

	remote_edtov_resolution = (u8)UNF_GET_E_D_TOV_RESOLUTION_FROM_PARAMS(login_parms);
	remote_edtov = UNF_GET_E_D_TOV_FROM_PARAMS(login_parms);
	login_co_parms.compared_edtov_val =
	    remote_edtov_resolution ? (remote_edtov / UNF_OS_MS_TO_NS)
				    : remote_edtov;

	login_co_parms.compared_ratov_val = UNF_GET_RA_TOV_FROM_PARAMS(login_parms);
	login_co_parms.els_cmnd_code = ELS_FLOGI;

	if (UNF_TOP_P2P_MASK & (u32)lport->act_topo) {
		login_co_parms.act_topo = (login_parms->co_parms.nport == UNF_F_PORT)
			? UNF_ACT_TOP_P2P_FABRIC
			: UNF_ACT_TOP_P2P_DIRECT;
	} else {
		login_co_parms.act_topo = lport->act_topo;
	}

	ret = lport->low_level_func.port_mgr_op.ll_port_config_set((void *)lport->fc_port,
	    UNF_PORT_CFG_UPDATE_FABRIC_PARAM, (void *)&login_co_parms);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Lowlevel unsupport fabric config");
	}
}

u32 unf_check_flogi_params(struct unf_lport *lport, struct unf_rport *rport,
			   struct unf_fabric_parm *fabric_parms)
{
	u32 ret = RETURN_OK;
	u32 high_port_name;
	u32 low_port_name;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(fabric_parms, UNF_RETURN_ERROR);

	if (fabric_parms->cl_parms[ARRAY_INDEX_2].valid == UNF_CLASS_INVALID) {
		/* Discard directly */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) NPort_ID(0x%x) FLOGI not support class3",
			     lport->port_id, rport->nport_id);

		return UNF_RETURN_ERROR;
	}

	high_port_name = UNF_GET_NAME_HIGH_WORD(lport->port_name);
	low_port_name = UNF_GET_NAME_LOW_WORD(lport->port_name);
	if (fabric_parms->high_port_name == high_port_name &&
	    fabric_parms->low_port_name == low_port_name) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]The wwpn(0x%x%x) of lport(0x%x) is same as the wwpn of rport(0x%x)",
			     high_port_name, low_port_name, lport->port_id, rport->nport_id);
		return UNF_RETURN_ERROR;
	}

	return ret;
}

static void unf_save_fabric_params(struct unf_lport *lport,
				   struct unf_rport *rport,
				   struct unf_fabric_parm *fabric_parms)
{
	u64 fabric_node_name = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(fabric_parms);

	fabric_node_name = (u64)(((u64)(fabric_parms->high_node_name) << UNF_SHIFT_32) |
			   ((u64)(fabric_parms->low_node_name)));

	/* R_Port for 0xfffffe is used for FLOGI, not need to save WWN */
	if (fabric_parms->co_parms.bb_receive_data_field_size > UNF_MAX_FRAME_SIZE)
		rport->max_frame_size = UNF_MAX_FRAME_SIZE; /* 2112 */
	else
		rport->max_frame_size = fabric_parms->co_parms.bb_receive_data_field_size;

	/* with Fabric attribute */
	if (fabric_parms->co_parms.nport == UNF_F_PORT) {
		rport->ed_tov = fabric_parms->co_parms.e_d_tov;
		rport->ra_tov = fabric_parms->co_parms.r_a_tov;
		lport->ed_tov = fabric_parms->co_parms.e_d_tov;
		lport->ra_tov = fabric_parms->co_parms.r_a_tov;
		lport->fabric_node_name = fabric_node_name;
	}

	/* Configure info from FLOGI to chip */
	unf_cfg_lowlevel_fabric_params(lport, rport, fabric_parms);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) Rport(0x%x) login parameter: E_D_TOV = %u. LPort E_D_TOV = %u. fabric nodename: 0x%x%x",
		     lport->port_id, rport->nport_id, (fabric_parms->co_parms.e_d_tov),
		     lport->ed_tov, fabric_parms->high_node_name, fabric_parms->low_node_name);
}

u32 unf_flogi_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_flogi_fdisc_acc *flogi_frame = NULL;
	struct unf_fabric_parm *fabric_login_parms = NULL;
	u32 ret = UNF_RETURN_ERROR;
	ulong flag = 0;
	u64 wwpn = 0;
	u64 wwnn = 0;
	enum unf_act_topo unf_active_topo;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x)<---RPort(0x%x) Receive FLOGI with OX_ID(0x%x)",
		     lport->port_id, sid, xchg->oxid);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_FLOGI);

	/* Check L_Port state: Offline */
	if (lport->states >= UNF_LPORT_ST_OFFLINE) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) with state(0x%x) not need to handle FLOGI",
			     lport->port_id, lport->states);

		unf_cm_free_xchg(lport, xchg);
		return ret;
	}

	flogi_frame = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->flogi;
	fabric_login_parms = &flogi_frame->flogi_payload.fabric_parms;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, &flogi_frame->flogi_payload,
			    sizeof(struct unf_flogi_fdisc_payload));
	wwpn = (u64)(((u64)(fabric_login_parms->high_port_name) << UNF_SHIFT_32) |
		  ((u64)fabric_login_parms->low_port_name));
	wwnn = (u64)(((u64)(fabric_login_parms->high_node_name) << UNF_SHIFT_32) |
		  ((u64)fabric_login_parms->low_node_name));

	/* Get (new) R_Port: reuse only */
	unf_rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_FLOGI);
	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY, UNF_FC_FID_FLOGI);
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) has no RPort. do nothing", lport->port_id);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	/* Update R_Port info */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->port_name = wwpn;
	unf_rport->node_name = wwnn;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	/* Check RCVD FLOGI parameters: only for class-3 */
	ret = unf_check_flogi_params(lport, unf_rport, fabric_login_parms);
	if (ret != RETURN_OK) {
		/* Discard directly */
		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	/* Save fabric parameters */
	unf_save_fabric_params(lport, unf_rport, fabric_login_parms);

	if ((u32)lport->act_topo & UNF_TOP_P2P_MASK) {
		unf_active_topo =
		    (fabric_login_parms->co_parms.nport == UNF_F_PORT)
			? UNF_ACT_TOP_P2P_FABRIC
			: UNF_ACT_TOP_P2P_DIRECT;
		unf_lport_update_topo(lport, unf_active_topo);
	}
	/* Send ACC for FLOGI */
	ret = unf_send_flogi_acc(lport, unf_rport, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) send FLOGI ACC failed and do recover",
			     lport->port_id);

		/* Do L_Port recovery */
		unf_lport_error_recovery(lport);
	}

	return ret;
}

static void unf_cfg_lowlevel_port_params(struct unf_lport *lport,
					 struct unf_rport *rport,
					 struct unf_lgn_parm *login_parms,
					 u32 cmd_type)
{
	struct unf_port_login_parms login_co_parms = {0};
	u32 ret = 0;

	if (!lport->low_level_func.port_mgr_op.ll_port_config_set)
		return;

	login_co_parms.rport_index = rport->rport_index;
	login_co_parms.seq_cnt = 0;
	login_co_parms.ed_tov = 0; /* ms */
	login_co_parms.ed_tov_timer_val = lport->ed_tov;
	login_co_parms.tx_mfs = rport->max_frame_size;

	login_co_parms.remote_rttov_tag = (u8)UNF_GET_RT_TOV_FROM_PARAMS(login_parms);
	login_co_parms.remote_edtov_tag = 0;
	login_co_parms.remote_bb_credit = (u16)UNF_GET_BB_CREDIT_FROM_PARAMS(login_parms);
	login_co_parms.els_cmnd_code = cmd_type;

	if (lport->act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		login_co_parms.compared_bbscn = 0;
	} else {
		login_co_parms.compared_bbscn =
		    (u32)unf_determin_bbscn((u8)lport->low_level_func.lport_cfg_items.bbscn,
					    (u8)UNF_GET_BB_SC_N_FROM_PARAMS(login_parms));
	}

	login_co_parms.compared_edtov_val = lport->ed_tov;
	login_co_parms.compared_ratov_val = lport->ra_tov;

	ret = lport->low_level_func.port_mgr_op.ll_port_config_set((void *)lport->fc_port,
	    UNF_PORT_CFG_UPDATE_PLOGI_PARAM, (void *)&login_co_parms);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) Lowlevel unsupport port config", lport->port_id);
	}
}

u32 unf_check_plogi_params(struct unf_lport *lport, struct unf_rport *rport,
			   struct unf_lgn_parm *login_parms)
{
	u32 ret = RETURN_OK;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(login_parms, UNF_RETURN_ERROR);

	/* Parameters check: Class-type */
	if (login_parms->cl_parms[ARRAY_INDEX_2].valid == UNF_CLASS_INVALID ||
	    login_parms->co_parms.bb_receive_data_field_size == 0) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort N_Port_ID(0x%x) with PLOGI parameters invalid: class3(%u), BBReceiveDataFieldSize(0x%x), send LOGO",
			     lport->port_id, rport->nport_id,
			     login_parms->cl_parms[ARRAY_INDEX_2].valid,
			     login_parms->co_parms.bb_receive_data_field_size);

		spin_lock_irqsave(&rport->rport_state_lock, flag);
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO); /* --->>> LOGO */
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* Enter LOGO stage */
		unf_rport_enter_logo(lport, rport);
		return UNF_RETURN_ERROR;
	}

	/* 16G FC Brocade SW, Domain Controller's PLOGI both support CLASS-1 &
	 * CLASS-2
	 */
	if (login_parms->cl_parms[ARRAY_INDEX_0].valid == UNF_CLASS_VALID ||
	    login_parms->cl_parms[ARRAY_INDEX_1].valid == UNF_CLASS_VALID) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) get PLOGI class1(%u) class2(%u) from N_Port_ID(0x%x)",
			     lport->port_id, login_parms->cl_parms[ARRAY_INDEX_0].valid,
			     login_parms->cl_parms[ARRAY_INDEX_1].valid, rport->nport_id);
	}

	return ret;
}

static void unf_save_plogi_params(struct unf_lport *lport,
				  struct unf_rport *rport,
				  struct unf_lgn_parm *login_parms,
				  u32 cmd_code)
{
#define UNF_DELAY_TIME 100 /* WWPN smaller delay to send PRLI with COM mode */

	u64 wwpn = INVALID_VALUE64;
	u64 wwnn = INVALID_VALUE64;
	u32 ed_tov = 0;
	u32 remote_edtov = 0;

	if (login_parms->co_parms.bb_receive_data_field_size > UNF_MAX_FRAME_SIZE)
		rport->max_frame_size = UNF_MAX_FRAME_SIZE; /* 2112 */
	else
		rport->max_frame_size = login_parms->co_parms.bb_receive_data_field_size;

	wwnn = (u64)(((u64)(login_parms->high_node_name) << UNF_SHIFT_32) |
		     ((u64)login_parms->low_node_name));
	wwpn = (u64)(((u64)(login_parms->high_port_name) << UNF_SHIFT_32) |
		     ((u64)login_parms->low_port_name));

	remote_edtov = login_parms->co_parms.e_d_tov;
	ed_tov = login_parms->co_parms.e_d_tov_resolution
		     ? (remote_edtov / UNF_OS_MS_TO_NS)
		     : remote_edtov;

	rport->port_name = wwpn;
	rport->node_name = wwnn;
	rport->local_nport_id = lport->nport_id;

	if (lport->act_topo == UNF_ACT_TOP_P2P_DIRECT ||
	    lport->act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		/* P2P or Private Loop or FCoE VN2VN */
		lport->ed_tov = (lport->ed_tov > ed_tov) ? lport->ed_tov : ed_tov;
		lport->ra_tov = 2 * lport->ed_tov; /* 2 * E_D_TOV */

		if (ed_tov != 0)
			rport->ed_tov = ed_tov;
		else
			rport->ed_tov = UNF_DEFAULT_EDTOV;
	} else {
		/* SAN: E_D_TOV updated by FLOGI */
		rport->ed_tov = lport->ed_tov;
	}

	/* WWPN smaller: delay to send PRLI */
	if (rport->port_name > lport->port_name)
		rport->ed_tov += UNF_DELAY_TIME; /* 100ms */

	/* Configure port parameters to low level (chip) */
	unf_cfg_lowlevel_port_params(lport, rport, login_parms, cmd_code);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) RPort(0x%x) with WWPN(0x%llx) WWNN(0x%llx) login: ED_TOV(%u) Port: ED_TOV(%u)",
		     lport->port_id, rport->nport_id, rport->port_name, rport->node_name,
		     ed_tov, lport->ed_tov);
}

static bool unf_check_bbscn_is_enabled(u8 local_bbscn, u8 remote_bbscn)
{
	return unf_determin_bbscn(local_bbscn, remote_bbscn) ? true : false;
}

static u32 unf_irq_process_switch2thread(void *lport, struct unf_xchg *xchg,
					 unf_event_task evt_task)
{
	struct unf_cm_event_report *event = NULL;
	struct unf_xchg *unf_xchg = NULL;
	u32 ret = 0;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	unf_lport = lport;
	unf_xchg = xchg;

	if (unlikely(!unf_lport->event_mgr.unf_get_free_event_func ||
		     !unf_lport->event_mgr.unf_post_event_func ||
		     !unf_lport->event_mgr.unf_release_event)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) event function is NULL",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	ret = unf_xchg_ref_inc(unf_xchg, SFS_RESPONSE);
	FC_CHECK_RETURN_VALUE((ret == RETURN_OK), UNF_RETURN_ERROR);

	event = unf_lport->event_mgr.unf_get_free_event_func((void *)lport);
	FC_CHECK_RETURN_VALUE(event, UNF_RETURN_ERROR);

	event->lport = unf_lport;
	event->event_asy_flag = UNF_EVENT_ASYN;
	event->unf_event_task = evt_task;
	event->para_in = xchg;
	unf_lport->event_mgr.unf_post_event_func(unf_lport, event);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) start to switch thread process now",
		     unf_lport->port_id);

	return ret;
}

u32 unf_plogi_handler_com_process(struct unf_xchg *xchg)
{
	struct unf_xchg *unf_xchg = xchg;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_plogi_pdisc *plogi_frame = NULL;
	struct unf_lgn_parm *login_parms = NULL;
	u32 ret = UNF_RETURN_ERROR;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(unf_xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(unf_xchg->lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(unf_xchg->rport, UNF_RETURN_ERROR);

	unf_lport = unf_xchg->lport;
	unf_rport = unf_xchg->rport;
	plogi_frame = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi;
	login_parms = &plogi_frame->payload.stparms;

	unf_save_plogi_params(unf_lport, unf_rport, login_parms, ELS_PLOGI);

	/* Update state: PLOGI_WAIT */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = unf_xchg->sid;
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	/* Send PLOGI ACC to remote port */
	ret = unf_send_plogi_acc(unf_lport, unf_rport, unf_xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) send PLOGI ACC failed",
			     unf_lport->port_id);

		/* NOTE: exchange has been freed inner(before) */
		unf_rport_error_recovery(unf_rport);
		return ret;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]LOGIN: Port(0x%x) send PLOGI ACC to Port(0x%x) succeed",
		     unf_lport->port_id, unf_rport->nport_id);

	return ret;
}

int unf_plogi_async_handle(void *argc_in, void *argc_out)
{
	struct unf_xchg *xchg = (struct unf_xchg *)argc_in;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	ret = unf_plogi_handler_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return (int)ret;
}

u32 unf_plogi_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_xchg *unf_xchg = xchg;
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = NULL;
	struct unf_plogi_pdisc *plogi_frame = NULL;
	struct unf_lgn_parm *login_parms = NULL;
	struct unf_rjt_info rjt_info = {0};
	u64 wwpn = INVALID_VALUE64;
	u32 ret = UNF_RETURN_ERROR;
	bool bbscn_enabled = false;
	bool switch2thread = false;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	/* 1. Maybe: PLOGI is sent by Name server */
	if (sid < UNF_FC_FID_DOM_MGR ||
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Receive PLOGI. Port(0x%x_0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			     lport->port_id, lport->nport_id, sid, xchg->oxid);
	}

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_PLOGI);

	/* 2. State check: Offline */
	if (unf_lport->states >= UNF_LPORT_ST_OFFLINE) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) received PLOGI with state(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, unf_lport->states);

		unf_cm_free_xchg(unf_lport, unf_xchg);
		return UNF_RETURN_ERROR;
	}

	/* Get R_Port by WWpn */
	plogi_frame = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi;
	login_parms = &plogi_frame->payload.stparms;

	UNF_PRINT_SFS_LIMIT(UNF_INFO, unf_lport->port_id, &plogi_frame->payload,
			    sizeof(struct unf_plogi_payload));

	wwpn = (u64)(((u64)(login_parms->high_port_name) << UNF_SHIFT_32) |
		     ((u64)login_parms->low_port_name));

	/* 3. Get (new) R_Port (by wwpn) */
	unf_rport = unf_find_rport(unf_lport, sid, wwpn);
	unf_rport = unf_get_safe_rport(unf_lport, unf_rport, UNF_RPORT_REUSE_ONLY, sid);
	if (!unf_rport) {
		memset(&rjt_info, 0, sizeof(struct unf_rjt_info));
		rjt_info.els_cmnd_code = ELS_PLOGI;
		rjt_info.reason_code = UNF_LS_RJT_BUSY;
		rjt_info.reason_explanation = UNF_LS_RJT_INSUFFICIENT_RESOURCES;

		/* R_Port is NULL: Send ELS RJT for PLOGI */
		(void)unf_send_els_rjt_by_did(unf_lport, unf_xchg, sid, &rjt_info);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) has no RPort and send PLOGI reject",
			     unf_lport->port_id);
		return RETURN_OK;
	}

	/*
	 * 4. According to FC-LS 4.2.7.1:
	 * After RCVD PLogi or send Plogi ACC, need to termitate open EXCH
	 */
	unf_cm_xchg_mgr_abort_io_by_id(unf_lport, unf_rport, sid, unf_lport->nport_id, 0);

	/* 5. Cancel recovery timer work after RCVD PLOGI */
	if (cancel_delayed_work(&unf_rport->recovery_work))
		atomic_dec(&unf_rport->rport_ref_cnt);

	/*
	 * 6. Plogi parameters check
	 * Call by: (RCVD) PLOGI handler & callback function for RCVD PLOGI_ACC
	 */
	ret = unf_check_plogi_params(unf_lport, unf_rport, login_parms);
	if (ret != RETURN_OK) {
		unf_cm_free_xchg(unf_lport, unf_xchg);
		return UNF_RETURN_ERROR;
	}

	unf_xchg->lport = lport;
	unf_xchg->rport = unf_rport;
	unf_xchg->sid = sid;

	/* 7. About bbscn for context change */
	bbscn_enabled =
	    unf_check_bbscn_is_enabled((u8)unf_lport->low_level_func.lport_cfg_items.bbscn,
				       (u8)UNF_GET_BB_SC_N_FROM_PARAMS(login_parms));
	if (unf_lport->act_topo == UNF_ACT_TOP_P2P_DIRECT && bbscn_enabled) {
		switch2thread = true;
		unf_lport->bbscn_support = true;
	}

	/* 8. Process PLOGI Frame: switch to thread if necessary */
	if (switch2thread && unf_lport->root_lport == unf_lport) {
		/* Wait for LR complete sync */
		ret = unf_irq_process_switch2thread(unf_lport, unf_xchg, unf_plogi_async_handle);
	} else {
		ret = unf_plogi_handler_com_process(unf_xchg);
	}

	return ret;
}

static void unf_obtain_tape_capacity(struct unf_lport *lport,
				     struct unf_rport *rport, u32 tape_parm)
{
	u32 rec_support = 0;
	u32 task_retry_support = 0;
	u32 retry_support = 0;

	rec_support = tape_parm & UNF_FC4_FRAME_PARM_3_REC_SUPPORT;
	task_retry_support =
	    tape_parm & UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT;
	retry_support = tape_parm & UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT;

	if (lport->low_level_func.lport_cfg_items.tape_support &&
	    rec_support && task_retry_support && retry_support) {
		rport->tape_support_needed = true;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) FC_tape is needed for RPort(0x%x)",
			     lport->port_id, lport->nport_id, rport->nport_id);
	}

	if ((tape_parm & UNF_FC4_FRAME_PARM_3_CONF_ALLOW) &&
	    lport->low_level_func.lport_cfg_items.fcp_conf) {
		rport->fcp_conf_needed = true;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) FCP confirm is needed for RPort(0x%x)",
			     lport->port_id, lport->nport_id, rport->nport_id);
	}
}

static u32 unf_prli_handler_com_process(struct unf_xchg *xchg)
{
	struct unf_prli_prlo *prli = NULL;
	u32 ret = UNF_RETURN_ERROR;
	ulong flags = 0;
	u32 sid = 0;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;

	unf_xchg = xchg;
	FC_CHECK_RETURN_VALUE(unf_xchg->lport, UNF_RETURN_ERROR);
	unf_lport = unf_xchg->lport;
	sid = xchg->sid;

	UNF_SERVICE_COLLECT(unf_lport->link_service_info, UNF_SERVICE_ITEM_PRLI);

	/* 1. Get R_Port: for each R_Port from rport_busy_list */
	unf_rport = unf_get_rport_by_nport_id(unf_lport, sid);
	if (!unf_rport) {
		/* non session (R_Port) existence */
		(void)unf_send_logo_by_did(unf_lport, sid);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) received PRLI but no RPort SID(0x%x) OX_ID(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, sid, xchg->oxid);

		unf_cm_free_xchg(unf_lport, xchg);
		return ret;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]LOGIN: Receive PRLI. Port(0x%x)<---RPort(0x%x) with S_ID(0x%x)",
		     unf_lport->port_id, unf_rport->nport_id, sid);

	/* 2. Get PRLI info */
	prli = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->prli;
	if (sid < UNF_FC_FID_DOM_MGR || unf_lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Receive PRLI. Port(0x%x_0x%x)<---RPort(0x%x) parameter-3(0x%x) OX_ID(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, sid,
			     prli->payload.parms[ARRAY_INDEX_3], xchg->oxid);
	}

	UNF_PRINT_SFS_LIMIT(UNF_INFO, unf_lport->port_id, &prli->payload,
			    sizeof(struct unf_prli_payload));

	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);

	/* 3. Increase R_Port ref_cnt */
	ret = unf_rport_ref_inc(unf_rport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x_0x%p) is removing and do nothing",
			     unf_lport->port_id, unf_rport->nport_id, unf_rport);

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

		unf_cm_free_xchg(unf_lport, xchg);
		return RETURN_ERROR;
	}

	/* 4. Cancel R_Port Open work */
	if (cancel_delayed_work(&unf_rport->open_work)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) RPort(0x%x) cancel open work succeed",
			     unf_lport->port_id, unf_lport->nport_id, unf_rport->nport_id);

		/* This is not the last counter */
		atomic_dec(&unf_rport->rport_ref_cnt);
	}

	/* 5. Check R_Port state */
	if (unf_rport->rp_state != UNF_RPORT_ST_PRLI_WAIT &&
	    unf_rport->rp_state != UNF_RPORT_ST_READY) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) RPort(0x%x) with state(0x%x) when received PRLI, send LOGO",
			     unf_lport->port_id, unf_lport->nport_id,
			     unf_rport->nport_id, unf_rport->rp_state);

		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

		/* NOTE: Start to send LOGO */
		unf_rport_enter_logo(unf_lport, unf_rport);

		unf_cm_free_xchg(unf_lport, xchg);
		unf_rport_ref_dec(unf_rport);

		return RETURN_ERROR;
	}

	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	/* 6. Update R_Port options(INI/TGT/BOTH) */
	unf_rport->options =
	    prli->payload.parms[ARRAY_INDEX_3] &
	    (UNF_FC4_FRAME_PARM_3_TGT | UNF_FC4_FRAME_PARM_3_INI);

	unf_update_port_feature(unf_rport->port_name, unf_rport->options);

	/* for Confirm */
	unf_rport->fcp_conf_needed = false;

	unf_obtain_tape_capacity(unf_lport, unf_rport, prli->payload.parms[ARRAY_INDEX_3]);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x_0x%x) RPort(0x%x) parameter-3(0x%x) options(0x%x)",
		     unf_lport->port_id, unf_lport->nport_id, unf_rport->nport_id,
		     prli->payload.parms[ARRAY_INDEX_3], unf_rport->options);

	/* 7. Send PRLI ACC */
	ret = unf_send_prli_acc(unf_lport, unf_rport, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) RPort(0x%x) send PRLI ACC failed",
			     unf_lport->port_id, unf_lport->nport_id, unf_rport->nport_id);

		/* NOTE: exchange has been freed inner(before) */
		unf_rport_error_recovery(unf_rport);
	}

	/* 8. Decrease R_Port ref_cnt */
	unf_rport_ref_dec(unf_rport);

	return ret;
}

int unf_prli_async_handle(void *argc_in, void *argc_out)
{
	struct unf_xchg *xchg = (struct unf_xchg *)argc_in;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	ret = unf_prli_handler_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return (int)ret;
}

u32 unf_prli_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	u32 ret = UNF_RETURN_ERROR;
	bool switch2thread = false;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->sid = sid;
	xchg->lport = lport;
	unf_lport = lport;

	if (lport->bbscn_support &&
	    lport->act_topo == UNF_ACT_TOP_P2P_DIRECT)
		switch2thread = true;

	if (switch2thread && unf_lport->root_lport == unf_lport) {
		/* Wait for LR done sync */
		ret = unf_irq_process_switch2thread(lport, xchg, unf_prli_async_handle);
	} else {
		ret = unf_prli_handler_com_process(xchg);
	}

	return ret;
}

static void unf_save_rscn_port_id(struct unf_rscn_mgr *rscn_mg,
				  struct unf_rscn_port_id_page *rscn_port_id)
{
	struct unf_port_id_page *exit_port_id_page = NULL;
	struct unf_port_id_page *new_port_id_page = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	bool is_repeat = false;

	FC_CHECK_RETURN_VOID(rscn_mg);
	FC_CHECK_RETURN_VOID(rscn_port_id);

	/* 1. check new RSCN Port_ID (RSNC_Page) whether within RSCN_Mgr or not
	 */
	spin_lock_irqsave(&rscn_mg->rscn_id_list_lock, flag);
	if (list_empty(&rscn_mg->list_using_rscn_page)) {
		is_repeat = false;
	} else {
		/* Check repeat: for each exist RSCN page form RSCN_Mgr Page
		 * list
		 */
		list_for_each_safe(node, next_node, &rscn_mg->list_using_rscn_page) {
			exit_port_id_page = list_entry(node, struct unf_port_id_page,
						       list_node_rscn);
			if (exit_port_id_page->port_id_port == rscn_port_id->port_id_port &&
			    exit_port_id_page->port_id_area == rscn_port_id->port_id_area &&
			    exit_port_id_page->port_id_domain == rscn_port_id->port_id_domain) {
				is_repeat = true;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&rscn_mg->rscn_id_list_lock, flag);

	FC_CHECK_RETURN_VOID(rscn_mg->unf_get_free_rscn_node);

	/* 2. Get & add free RSNC Node --->>> RSCN_Mgr */
	if (!is_repeat) {
		new_port_id_page = rscn_mg->unf_get_free_rscn_node(rscn_mg);
		if (!new_port_id_page) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
				     UNF_ERR, "[err]Get free RSCN node failed");

			return;
		}

		new_port_id_page->addr_format = rscn_port_id->addr_format;
		new_port_id_page->event_qualifier = rscn_port_id->event_qualifier;
		new_port_id_page->reserved = rscn_port_id->reserved;
		new_port_id_page->port_id_domain = rscn_port_id->port_id_domain;
		new_port_id_page->port_id_area = rscn_port_id->port_id_area;
		new_port_id_page->port_id_port = rscn_port_id->port_id_port;

		/* Add entry to list: using_rscn_page */
		spin_lock_irqsave(&rscn_mg->rscn_id_list_lock, flag);
		list_add_tail(&new_port_id_page->list_node_rscn, &rscn_mg->list_using_rscn_page);
		spin_unlock_irqrestore(&rscn_mg->rscn_id_list_lock, flag);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) has repeat RSCN node with domain(0x%x) area(0x%x)",
			     rscn_port_id->port_id_domain, rscn_port_id->port_id_area,
			     rscn_port_id->port_id_port);
	}
}

static u32 unf_analysis_rscn_payload(struct unf_lport *lport,
				     struct unf_rscn_pld *rscn_pld)
{
#define UNF_OS_DISC_REDISC_TIME 10000

	struct unf_rscn_port_id_page *rscn_port_id = NULL;
	struct unf_disc *disc = NULL;
	struct unf_rscn_mgr *rscn_mgr = NULL;
	u32 index = 0;
	u32 pld_len = 0;
	u32 port_id_page_cnt = 0;
	u32 ret = RETURN_OK;
	ulong flag = 0;
	bool eb_need_disc_flag = false;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rscn_pld, UNF_RETURN_ERROR);

	/* This field is the length in bytes of the entire Payload, inclusive of
	 * the word 0
	 */
	pld_len = UNF_GET_RSCN_PLD_LEN(rscn_pld->cmnd);
	pld_len -= sizeof(rscn_pld->cmnd);
	port_id_page_cnt = pld_len / UNF_RSCN_PAGE_LEN;

	/* Pages within payload is nor more than 255 */
	if (port_id_page_cnt > UNF_RSCN_PAGE_SUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x_0x%x) page num(0x%x) exceed 255 in RSCN",
			     lport->port_id, lport->nport_id, port_id_page_cnt);

		return UNF_RETURN_ERROR;
	}

	/* L_Port-->Disc-->Rscn_Mgr */
	disc = &lport->disc;
	rscn_mgr = &disc->rscn_mgr;

	/* for each ID from RSCN_Page: check whether need to Disc or not */
	while (index < port_id_page_cnt) {
		rscn_port_id = &rscn_pld->port_id_page[index];
		if (unf_lookup_lport_by_nportid(lport, *(u32 *)rscn_port_id)) {
			/* Prevent to create session with L_Port which have the
			 * same N_Port_ID
			 */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
				     "[info]Port(0x%x) find local N_Port_ID(0x%x) within RSCN payload",
				     ((struct unf_lport *)(lport->root_lport))->nport_id,
				     *(u32 *)rscn_port_id);
		} else {
			/* New RSCN_Page ID find, save it to RSCN_Mgr */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
				     "[info]Port(0x%x_0x%x) save RSCN N_Port_ID(0x%x)",
				     lport->port_id, lport->nport_id,
				     *(u32 *)rscn_port_id);

			/* 1. new RSCN_Page ID find, save it to RSCN_Mgr */
			unf_save_rscn_port_id(rscn_mgr, rscn_port_id);
			eb_need_disc_flag = true;
		}
		index++;
	}

	if (!eb_need_disc_flag) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
			     "[info]Port(0x%x) find all N_Port_ID and do not need to disc",
			     ((struct unf_lport *)(lport->root_lport))->nport_id);

		return RETURN_OK;
	}

	/* 2. Do/Start Disc: Check & do Disc (GID_PT) process */
	if (!disc->disc_temp.unf_disc_start) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) DISC start function is NULL",
			     lport->nport_id, lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if (disc->states == UNF_DISC_ST_END ||
	    ((jiffies - disc->last_disc_jiff) > msecs_to_jiffies(UNF_OS_DISC_REDISC_TIME))) {
		disc->disc_option = UNF_RSCN_DISC;
		disc->last_disc_jiff = jiffies;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		ret = disc->disc_temp.unf_disc_start(lport);
	} else {
		FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_INFO,
			     "[info]Port(0x%x_0x%x) DISC state(0x%x) with last time(%llu) and don't do DISC",
			     lport->port_id, lport->nport_id, disc->states,
			     disc->last_disc_jiff);

		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	}

	return ret;
}

u32 unf_rscn_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	/*
	 * A RSCN ELS shall be sent to registered Nx_Ports
	 * when an event occurs that may have affected the state of
	 * one or more Nx_Ports, or the ULP state within the Nx_Port.
	 * *
	 * The Payload of a RSCN Request includes a list
	 * containing the addresses of the affected Nx_Ports.
	 * *
	 * Each affected Port_ID page contains the ID of the Nx_Port,
	 * Fabric Controller, E_Port, domain, or area for which the event was
	 * detected.
	 */
	struct unf_rscn_pld *rscn_pld = NULL;
	struct unf_rport *unf_rport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 pld_len = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Receive RSCN Port(0x%x_0x%x)<---RPort(0x%x) OX_ID(0x%x)",
		     lport->port_id, lport->nport_id, sid, xchg->oxid);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_RSCN);

	/* 1. Get R_Port by S_ID */
	unf_rport = unf_get_rport_by_nport_id(lport, sid); /* rport busy_list */
	if (!unf_rport) {
		unf_rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC, sid);
		if (!unf_rport) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) received RSCN but has no RPort(0x%x) with OX_ID(0x%x)",
				     lport->port_id, lport->nport_id, sid, xchg->oxid);

			unf_cm_free_xchg(lport, xchg);
			return UNF_RETURN_ERROR;
		}

		unf_rport->nport_id = sid;
	}

	rscn_pld = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld;
	FC_CHECK_RETURN_VALUE(rscn_pld, UNF_RETURN_ERROR);
	pld_len = UNF_GET_RSCN_PLD_LEN(rscn_pld->cmnd);
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, rscn_pld, pld_len);

	/* 2. NOTE: Analysis RSCN payload(save & disc if necessary) */
	ret = unf_analysis_rscn_payload(lport, rscn_pld);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) analysis RSCN failed",
			     lport->port_id, lport->nport_id);
	}

	/* 3. send rscn_acc after analysis payload */
	ret = unf_send_rscn_acc(lport, unf_rport, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) send RSCN response failed",
			     lport->port_id, lport->nport_id);
	}

	return ret;
}

static void unf_analysis_pdisc_pld(struct unf_lport *lport,
				   struct unf_rport *rport,
				   struct unf_plogi_pdisc *pdisc)
{
	struct unf_lgn_parm *pdisc_params = NULL;
	u64 wwpn = INVALID_VALUE64;
	u64 wwnn = INVALID_VALUE64;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(pdisc);

	pdisc_params = &pdisc->payload.stparms;
	if (pdisc_params->co_parms.bb_receive_data_field_size > UNF_MAX_FRAME_SIZE)
		rport->max_frame_size = UNF_MAX_FRAME_SIZE;
	else
		rport->max_frame_size = pdisc_params->co_parms.bb_receive_data_field_size;

	wwnn = (u64)(((u64)(pdisc_params->high_node_name) << UNF_SHIFT_32) |
		     ((u64)pdisc_params->low_node_name));
	wwpn = (u64)(((u64)(pdisc_params->high_port_name) << UNF_SHIFT_32) |
		     ((u64)pdisc_params->low_port_name));

	rport->port_name = wwpn;
	rport->node_name = wwnn;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) save PDISC parameters to Rport(0x%x) WWPN(0x%llx) WWNN(0x%llx)",
		     lport->port_id, rport->nport_id, rport->port_name,
		     rport->node_name);
}

u32 unf_send_pdisc_rjt(struct unf_lport *lport, struct unf_rport *rport, struct unf_xchg *xchg)
{
	u32 ret = UNF_RETURN_ERROR;
	struct unf_rjt_info rjt_info;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	memset(&rjt_info, 0, sizeof(struct unf_rjt_info));
	rjt_info.els_cmnd_code = ELS_PDISC;
	rjt_info.reason_code = UNF_LS_RJT_LOGICAL_ERROR;
	rjt_info.reason_explanation = UNF_LS_RJT_NO_ADDITIONAL_INFO;

	ret = unf_send_els_rjt_by_rport(lport, xchg, rport, &rjt_info);

	return ret;
}

u32 unf_pdisc_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_plogi_pdisc *pdisc = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;
	u32 ret = RETURN_OK;
	u64 wwpn = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Receive PDISC. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		     lport->port_id, sid, xchg->oxid);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_PDISC);
	pdisc = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->pdisc;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, &pdisc->payload,
			    sizeof(struct unf_plogi_payload));
	wwpn = (u64)(((u64)(pdisc->payload.stparms.high_port_name) << UNF_SHIFT_32) |
		     ((u64)pdisc->payload.stparms.low_port_name));

	unf_rport = unf_find_rport(lport, sid, wwpn);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't find RPort by NPort ID(0x%x). Free exchange and send LOGO",
			     lport->port_id, sid);

		unf_cm_free_xchg(lport, xchg);
		(void)unf_send_logo_by_did(lport, sid);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MINOR,
			     "[info]Port(0x%x) get exist RPort(0x%x) when receive PDISC with S_Id(0x%x)",
			     lport->port_id, unf_rport->nport_id, sid);

		if (sid >= UNF_FC_FID_DOM_MGR)
			return unf_send_pdisc_rjt(lport, unf_rport, xchg);

		unf_analysis_pdisc_pld(lport, unf_rport, pdisc);

		/* State: READY */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
		if (unf_rport->rp_state == UNF_RPORT_ST_READY) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) find RPort(0x%x) state is READY when receiving PDISC",
				     lport->port_id, sid);

			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

			ret = unf_send_pdisc_acc(lport, unf_rport, xchg);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x) handle PDISC failed",
					     lport->port_id);

				return ret;
			}

			/* Report Down/Up event to scsi */
			unf_update_lport_state_by_linkup_event(lport,
							       unf_rport, unf_rport->options);
		} else if ((unf_rport->rp_state == UNF_RPORT_ST_CLOSING) &&
			 (unf_rport->session)) {
			/* State: Closing */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving PDISC",
				     lport->port_id, sid, unf_rport->rp_state);

			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

			unf_cm_free_xchg(lport, xchg);
			(void)unf_send_logo_by_did(lport, sid);
		} else if (unf_rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) {
			/* State: PRLI_WAIT */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving PDISC",
				     lport->port_id, sid, unf_rport->rp_state);

			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

			ret = unf_send_pdisc_acc(lport, unf_rport, xchg);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x) handle PDISC failed",
					     lport->port_id);

				return ret;
			}
		} else {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving PDISC, send LOGO",
				     lport->port_id, sid, unf_rport->rp_state);

			unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

			unf_rport_enter_logo(lport, unf_rport);
			unf_cm_free_xchg(lport, xchg);
		}
	}

	return ret;
}

static void unf_analysis_adisc_pld(struct unf_lport *lport,
				   struct unf_rport *rport,
				   struct unf_adisc_payload *adisc_pld)
{
	u64 wwpn = INVALID_VALUE64;
	u64 wwnn = INVALID_VALUE64;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(adisc_pld);

	wwnn = (u64)(((u64)(adisc_pld->high_node_name) << UNF_SHIFT_32) |
		     ((u64)adisc_pld->low_node_name));
	wwpn = (u64)(((u64)(adisc_pld->high_port_name) << UNF_SHIFT_32) |
		     ((u64)adisc_pld->low_port_name));

	rport->port_name = wwpn;
	rport->node_name = wwnn;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) save ADISC parameters to RPort(0x%x), WWPN(0x%llx) WWNN(0x%llx) NPort ID(0x%x)",
		     lport->port_id, rport->nport_id, rport->port_name,
		     rport->node_name, adisc_pld->nport_id);
}

u32 unf_adisc_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_adisc_payload *adisc_pld = NULL;
	ulong flags = 0;
	u64 wwpn = 0;
	u32 ret = RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Receive ADISC. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		     lport->port_id, sid, xchg->oxid);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_ADISC);
	adisc_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->adisc.adisc_payl;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, adisc_pld, sizeof(struct unf_adisc_payload));
	wwpn = (u64)(((u64)(adisc_pld->high_port_name) << UNF_SHIFT_32) |
		     ((u64)adisc_pld->low_port_name));

	unf_rport = unf_find_rport(lport, sid, wwpn);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't find RPort by NPort ID(0x%x). Free exchange and send LOGO",
			     lport->port_id, sid);

		unf_cm_free_xchg(lport, xchg);
		(void)unf_send_logo_by_did(lport, sid);

		return ret;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MINOR,
		     "[info]Port(0x%x) get exist RPort(0x%x) when receive ADISC with S_ID(0x%x)",
		     lport->port_id, unf_rport->nport_id, sid);

	unf_analysis_adisc_pld(lport, unf_rport, adisc_pld);

	/* State: READY */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	if (unf_rport->rp_state == UNF_RPORT_ST_READY) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) find RPort(0x%x) state is READY when receiving ADISC",
			     lport->port_id, sid);

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

		/* Return ACC directly */
		ret = unf_send_adisc_acc(lport, unf_rport, xchg);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) send ADISC ACC failed", lport->port_id);

			return ret;
		}

		/* Report Down/Up event to SCSI */
		unf_update_lport_state_by_linkup_event(lport, unf_rport, unf_rport->options);
	}
	/* State: Closing */
	else if ((unf_rport->rp_state == UNF_RPORT_ST_CLOSING) &&
		 (unf_rport->session)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving ADISC",
			     lport->port_id, sid, unf_rport->rp_state);

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

		unf_rport = unf_get_safe_rport(lport, unf_rport,
					       UNF_RPORT_REUSE_RECOVER,
					       unf_rport->nport_id);
		if (unf_rport) {
			spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
			unf_rport->nport_id = sid;
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

			ret = unf_send_adisc_acc(lport, unf_rport, xchg);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x) send ADISC ACC failed",
					     lport->port_id);

				return ret;
			}

			unf_update_lport_state_by_linkup_event(lport,
							       unf_rport, unf_rport->options);
		} else {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) can't find RPort by NPort_ID(0x%x). Free exchange and send LOGO",
				     lport->port_id, sid);

			unf_cm_free_xchg(lport, xchg);
			(void)unf_send_logo_by_did(lport, sid);
		}
	} else if (unf_rport->rp_state == UNF_RPORT_ST_PRLI_WAIT) {
		/* State: PRLI_WAIT */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving ADISC",
			     lport->port_id, sid, unf_rport->rp_state);

		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

		ret = unf_send_adisc_acc(lport, unf_rport, xchg);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) send ADISC ACC failed", lport->port_id);

			return ret;
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find RPort(0x%x) state is 0x%x when receiving ADISC, send LOGO",
			     lport->port_id, sid, unf_rport->rp_state);

		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

		unf_rport_enter_logo(lport, unf_rport);
		unf_cm_free_xchg(lport, xchg);
	}

	return ret;
}

u32 unf_rec_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x) receive REC", lport->port_id);

	/* Send rec acc */
	ret = unf_send_rec_acc(lport, unf_rport, xchg); /* discard directly */

	return ret;
}

u32 unf_rrq_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_rrq *rrq = NULL;
	struct unf_xchg *xchg_reused = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	u32 unf_sid = 0;
	ulong flags = 0;
	struct unf_rjt_info rjt_info = {0};
	struct unf_xchg_hot_pool *hot_pool = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_RRQ);
	rrq = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rrq;
	ox_id = (u16)(rrq->oxid_rxid >> UNF_SHIFT_16);
	rx_id = (u16)(rrq->oxid_rxid);
	unf_sid = rrq->sid & UNF_NPORTID_MASK;

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_KEVENT,
		     "[warn]Receive RRQ. Port(0x%x)<---RPort(0x%x) sfsXchg(0x%p) OX_ID(0x%x,0x%x) RX_ID(0x%x)",
		     lport->port_id, sid, xchg, ox_id, xchg->oxid, rx_id);

	/* Get R_Port */
	unf_rport = unf_get_rport_by_nport_id(lport, sid);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) receive RRQ but has no RPort(0x%x)",
			     lport->port_id, sid);

		/* NOTE: send LOGO */
		unf_send_logo_by_did(lport, unf_sid);

		unf_cm_free_xchg(lport, xchg);
		return ret;
	}

	/* Get Target (Abort I/O) exchange context */
	xchg_reused = unf_cm_lookup_xchg_by_id(lport, ox_id, unf_sid); /* unf_find_xchg_by_ox_id */
	if (!xchg_reused) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) cannot find exchange with OX_ID(0x%x) RX_ID(0x%x) S_ID(0x%x)",
			     lport->port_id, ox_id, rx_id, unf_sid);

		rjt_info.els_cmnd_code = ELS_RRQ;
		rjt_info.reason_code = FCXLS_BA_RJT_LOGICAL_ERROR | FCXLS_LS_RJT_INVALID_OXID_RXID;

		/* NOTE: send ELS RJT */
		if (unf_send_els_rjt_by_rport(lport, xchg, unf_rport, &rjt_info) != RETURN_OK) {
			unf_cm_free_xchg(lport, xchg);
			return UNF_RETURN_ERROR;
		}

		return RETURN_OK;
	}

	hot_pool = xchg_reused->hot_pool;
	if (unlikely(!hot_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Port(0x%x) OxId(0x%x) Rxid(0x%x) Sid(0x%x) Hot Pool is NULL.",
			     lport->port_id, ox_id, rx_id, unf_sid);

		return ret;
	}

	spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
	xchg_reused->oxid = INVALID_VALUE16;
	xchg_reused->rxid = INVALID_VALUE16;
	spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

	/* NOTE: release I/O exchange context */
	unf_xchg_ref_dec(xchg_reused, SFS_RESPONSE);

	/* Send RRQ ACC */
	ret = unf_send_rrq_acc(lport, unf_rport, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can not send RRQ rsp. Xchg(0x%p) Ioxchg(0x%p) OX_RX_ID(0x%x 0x%x) S_ID(0x%x)",
			     lport->port_id, xchg, xchg_reused, ox_id, rx_id, unf_sid);

		unf_cm_free_xchg(lport, xchg);
	}

	return ret;
}

u32 unf_logo_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_rport *logo_rport = NULL;
	struct unf_logo *logo = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 nport_id = 0;
	struct unf_rjt_info rjt_info = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_LOGO);
	logo = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->logo;
	nport_id = logo->payload.nport_id & UNF_NPORTID_MASK;

	if (sid < UNF_FC_FID_DOM_MGR) {
		/* R_Port is not fabric port */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[info]LOGIN: Receive LOGO. Port(0x%x)<---RPort(0x%x) NPort_ID(0x%x) OXID(0x%x)",
			     lport->port_id, sid, nport_id, xchg->oxid);
	}

	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, &logo->payload,
			    sizeof(struct unf_logo_payload));

	/*
	 * 1. S_ID unequal to NPort_ID:
	 * link down Rport find by NPort_ID immediately
	 */
	if (sid != nport_id) {
		logo_rport = unf_get_rport_by_nport_id(lport, nport_id);
		if (logo_rport)
			unf_rport_immediate_link_down(lport, logo_rport);
	}

	/* 2. Get R_Port by S_ID (frame header) */
	unf_rport = unf_get_rport_by_nport_id(lport, sid);
	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_INIT, sid); /* INIT */
	if (!unf_rport) {
		memset(&rjt_info, 0, sizeof(struct unf_rjt_info));
		rjt_info.els_cmnd_code = ELS_LOGO;
		rjt_info.reason_code = UNF_LS_RJT_LOGICAL_ERROR;
		rjt_info.reason_explanation = UNF_LS_RJT_NO_ADDITIONAL_INFO;
		ret = unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) receive LOGO but has no RPort(0x%x)",
			     lport->port_id, sid);

		return ret;
	}

	/*
	 * 3. I/O resource release: set ABORT tag
	 * *
	 * Call by: R_Port remove; RCVD LOGO; RCVD PLOGI; send PLOGI ACC
	 */
	unf_cm_xchg_mgr_abort_io_by_id(lport, unf_rport, sid, lport->nport_id, INI_IO_STATE_LOGO);

	/* 4. Send LOGO ACC */
	ret = unf_send_logo_acc(lport, unf_rport, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) send LOGO failed", lport->port_id);
	}
	/*
	 * 5. Do same operations with RCVD LOGO/PRLO & Send LOGO:
	 * retry (LOGIN or LOGO) or link down immediately
	 */
	unf_process_rport_after_logo(lport, unf_rport);

	return ret;
}

u32 unf_prlo_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_prli_prlo *prlo = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Receive PRLO. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		     lport->port_id, sid, xchg->oxid);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_LOGO);

	/* Get (new) R_Port */
	unf_rport = unf_get_rport_by_nport_id(lport, sid);
	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_INIT, sid); /* INIT */
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) receive PRLO but has no RPort",
			     lport->port_id);

		/* Discard directly */
		unf_cm_free_xchg(lport, xchg);
		return ret;
	}

	prlo = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->prlo;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, &prlo->payload,
			    sizeof(struct unf_prli_payload));

	/* Send PRLO ACC to remote */
	ret = unf_send_prlo_acc(lport, unf_rport, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send PRLO ACC failed", lport->port_id);
	}

	/* Enter Enhanced action after LOGO (retry LOGIN or LOGO) */
	unf_process_rport_after_logo(lport, unf_rport);

	return ret;
}

static void unf_fill_echo_acc_pld(struct unf_echo *echo_acc)
{
	struct unf_echo_payload *echo_acc_pld = NULL;

	FC_CHECK_RETURN_VOID(echo_acc);

	echo_acc_pld = echo_acc->echo_pld;
	FC_CHECK_RETURN_VOID(echo_acc_pld);

	echo_acc_pld->cmnd = UNF_ELS_CMND_ACC;
}

static void unf_echo_acc_callback(struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = xchg->lport;

	FC_CHECK_RETURN_VOID(unf_lport);
	if (xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.phy_echo_addr) {
		pci_unmap_single(unf_lport->low_level_func.dev,
				 xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc
				 .phy_echo_addr,
				 UNF_ECHO_PAYLOAD_LEN, DMA_BIDIRECTIONAL);
		xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo_acc.phy_echo_addr = 0;
	}
}

static u32 unf_send_echo_acc(struct unf_lport *lport, u32 did,
			     struct unf_xchg *xchg)
{
	struct unf_echo *echo_acc = NULL;
	union unf_sfs_u *fc_entry = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;
	struct unf_frame_pkg pkg;
	dma_addr_t phy_echo_acc_addr;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));
	xchg->cmnd_code = UNF_SET_ELS_ACC_TYPE(ELS_ECHO);
	xchg->did = did;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;

	xchg->callback = NULL;
	xchg->ob_callback = unf_echo_acc_callback;

	unf_fill_package(&pkg, xchg, xchg->rport);
	pkg.type = UNF_PKG_ELS_REPLY;
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	echo_acc = &fc_entry->echo_acc;
	unf_fill_echo_acc_pld(echo_acc);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;
	phy_echo_acc_addr = pci_map_single(lport->low_level_func.dev,
					   echo_acc->echo_pld,
					   UNF_ECHO_PAYLOAD_LEN,
					   DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(lport->low_level_func.dev, phy_echo_acc_addr)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) pci map err",
			     lport->port_id);
		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}
	echo_acc->phy_echo_addr = phy_echo_acc_addr;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK) {
		unf_cm_free_xchg((void *)lport, (void *)xchg);
		pci_unmap_single(lport->low_level_func.dev,
				 phy_echo_acc_addr, UNF_ECHO_PAYLOAD_LEN,
				 DMA_BIDIRECTIONAL);
		echo_acc->phy_echo_addr = 0;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]ECHO ACC send %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     did, ox_id, rx_id);

	return ret;
}

u32 unf_echo_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg)
{
	struct unf_echo_payload *echo_pld = NULL;
	struct unf_rport *unf_rport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 data_len = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	data_len = xchg->fcp_sfs_union.sfs_entry.cur_offset;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Receive ECHO. Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x))",
		     lport->port_id, sid, xchg->oxid);

	UNF_SERVICE_COLLECT(lport->link_service_info, UNF_SERVICE_ITEM_ECHO);
	echo_pld = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld;
	UNF_PRINT_SFS_LIMIT(UNF_INFO, lport->port_id, echo_pld, data_len);
	unf_rport = unf_get_rport_by_nport_id(lport, sid);
	xchg->rport = unf_rport;

	ret = unf_send_echo_acc(lport, sid, xchg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) send ECHO ACC failed", lport->port_id);
	}

	return ret;
}

static void unf_login_with_rport_in_n2n(struct unf_lport *lport,
					u64 remote_port_name,
					u64 remote_node_name)
{
	/*
	 * Call by (P2P):
	 * 1. RCVD FLOGI ACC
	 * 2. Send FLOGI ACC succeed
	 * *
	 * Compare WWN, larger is master, then send PLOGI
	 */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = NULL;
	ulong lport_flag = 0;
	ulong rport_flag = 0;
	u64 port_name = 0;
	u64 node_name = 0;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VOID(lport);

	spin_lock_irqsave(&unf_lport->lport_state_lock, lport_flag);
	unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_READY); /* LPort: FLOGI_WAIT --> READY */
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, lport_flag);

	port_name = remote_port_name;
	node_name = remote_node_name;

	if (unf_lport->port_name > port_name) {
		/* Master case: send PLOGI */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x)'s WWN(0x%llx) is larger than rport(0x%llx), should be master",
			     unf_lport->port_id, unf_lport->port_name, port_name);

		/* Update N_Port_ID now: 0xEF */
		unf_lport->nport_id = UNF_P2P_LOCAL_NPORT_ID;

		unf_rport = unf_find_valid_rport(lport, port_name, UNF_P2P_REMOTE_NPORT_ID);
		unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY,
					       UNF_P2P_REMOTE_NPORT_ID);
		if (unf_rport) {
			unf_rport->node_name = node_name;
			unf_rport->port_name = port_name;
			unf_rport->nport_id = UNF_P2P_REMOTE_NPORT_ID; /* 0xD6 */
			unf_rport->local_nport_id = UNF_P2P_LOCAL_NPORT_ID; /* 0xEF */

			spin_lock_irqsave(&unf_rport->rport_state_lock, rport_flag);
			if (unf_rport->rp_state == UNF_RPORT_ST_PLOGI_WAIT ||
			    unf_rport->rp_state == UNF_RPORT_ST_PRLI_WAIT ||
			    unf_rport->rp_state == UNF_RPORT_ST_READY) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
					     "[info]LOGIN: Port(0x%x) Rport(0x%x) have sent PLOGI or PRLI with state(0x%x)",
					     unf_lport->port_id,
					     unf_rport->nport_id,
					     unf_rport->rp_state);

				spin_unlock_irqrestore(&unf_rport->rport_state_lock,
						       rport_flag);
				return;
			}
			/* Update L_Port State: PLOGI_WAIT */
			unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, rport_flag);

			/* P2P with master: Start to Send PLOGI */
			ret = unf_send_plogi(unf_lport, unf_rport);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]LOGIN: Port(0x%x) with WWN(0x%llx) send PLOGI to(0x%llx) failed",
					     unf_lport->port_id,
					     unf_lport->port_name, port_name);

				unf_rport_error_recovery(unf_rport);
			}
		} else {
			/* Get/Alloc R_Port failed */
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) with WWN(0x%llx) allocate RPort(ID:0x%x,WWPN:0x%llx) failed",
				     unf_lport->port_id, unf_lport->port_name,
				     UNF_P2P_REMOTE_NPORT_ID, port_name);
		}
	} else {
		/* Slave case: L_Port's Port Name is smaller than R_Port */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) with WWN(0x%llx) is smaller than rport(0x%llx), do nothing",
			     unf_lport->port_id, unf_lport->port_name, port_name);
	}
}

void unf_lport_enter_mns_plogi(struct unf_lport *lport)
{
	/* Fabric or Public Loop Mode: Login with Name server */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_plogi_payload *plogi_pld = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_xchg *xchg = NULL;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VOID(lport);

	/* Get (safe) R_Port */
	unf_rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC, UNF_FC_FID_MGMT_SERV);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate RPort failed", lport->port_id);
		return;
	}

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = UNF_FC_FID_MGMT_SERV; /* 0xfffffa */
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));

	/* Get & Set new free exchange */
	xchg = unf_cm_get_free_xchg(lport, UNF_XCHG_TYPE_SFS);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange can't be NULL for PLOGI", lport->port_id);

		return;
	}

	xchg->cmnd_code = ELS_PLOGI; /* PLOGI */
	xchg->did = unf_rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = unf_lport;
	xchg->rport = unf_rport;

	/* Set callback function */
	xchg->callback = NULL;	  /* for rcvd plogi acc/rjt processer */
	xchg->ob_callback = NULL; /* for send plogi failed processer */

	unf_fill_package(&pkg, xchg, unf_rport);
	pkg.type = UNF_PKG_ELS_REQ;
	/* Fill PLOGI payload */
	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return;
	}

	plogi_pld = &fc_entry->plogi.payload;
	memset(plogi_pld, 0, sizeof(struct unf_plogi_payload));
	unf_fill_plogi_pld(plogi_pld, lport);

	/* Start to Send PLOGI command */
	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);
}

static void unf_register_to_switch(struct unf_lport *lport)
{
	/* Register to Fabric, used for: FABRIC & PUBLI LOOP */
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_lport_state_ma(lport, UNF_EVENT_LPORT_REMOTE_ACC);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* Login with Name server: PLOGI */
	unf_lport_enter_sns_plogi(lport);

	unf_lport_enter_mns_plogi(lport);

	/* Physical Port */
	if (lport->root_lport == lport &&
	    lport->act_topo == UNF_ACT_TOP_P2P_FABRIC) {
		unf_linkup_all_vports(lport);
	}
}

void unf_fdisc_ob_callback(struct unf_xchg *xchg)
{
	/* Do recovery */
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	unf_lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: FDISC send failed");

	FC_CHECK_RETURN_VOID(unf_lport);

	/* Do L_Port error recovery */
	unf_lport_error_recovery(unf_lport);
}

void unf_fdisc_callback(void *lport, void *rport, void *exch)
{
	/* Register to Name Server or Do recovery */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *xchg = NULL;
	struct unf_flogi_fdisc_payload *fdisc_pld = NULL;
	ulong flag = 0;
	u32 cmd = 0;

	unf_lport = (struct unf_lport *)lport;
	unf_rport = (struct unf_rport *)rport;
	xchg = (struct unf_xchg *)exch;
	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(exch);
	FC_CHECK_RETURN_VOID(xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr);
	fdisc_pld = &xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->fdisc_acc.fdisc_payload;
	if (xchg->byte_orders & UNF_BIT_2)
		unf_big_end_to_cpu((u8 *)fdisc_pld, sizeof(struct unf_flogi_fdisc_payload));

	cmd = fdisc_pld->cmnd;
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: FDISC response is (0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		     cmd, unf_lport->port_id, unf_rport->nport_id, xchg->oxid);
	unf_rport = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_FLOGI);
	unf_rport = unf_get_safe_rport(unf_lport, unf_rport,
				       UNF_RPORT_REUSE_ONLY, UNF_FC_FID_FLOGI);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) has no Rport", unf_lport->port_id);
		return;
	}

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = UNF_FC_FID_FLOGI;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	if ((cmd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		/* Case for ACC */
		spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
		if (unf_lport->states != UNF_LPORT_ST_FLOGI_WAIT) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) receive Flogi/Fdisc ACC in state(0x%x)",
				     unf_lport->port_id, unf_lport->nport_id, unf_lport->states);

			spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);
			return;
		}
		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

		unf_lport_update_nport_id(unf_lport, xchg->sid);
		unf_lport_update_time_params(unf_lport, fdisc_pld);
		unf_register_to_switch(unf_lport);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: FDISC response is (0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			     cmd, unf_lport->port_id, unf_rport->nport_id, xchg->oxid);

		/* Case for RJT: Do L_Port recovery */
		unf_lport_error_recovery(unf_lport);
	}
}

void unf_flogi_ob_callback(struct unf_xchg *xchg)
{
	/* Send FLOGI failed & Do L_Port recovery */
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	/* Get L_port from exchange context */
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	unf_lport = xchg->lport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
	FC_CHECK_RETURN_VOID(unf_lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x) send FLOGI failed",
		     unf_lport->port_id);

	/* Check L_Port state */
	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	if (unf_lport->states != UNF_LPORT_ST_FLOGI_WAIT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x_0x%x) send FLOGI failed with state(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, unf_lport->states);

		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);
		return;
	}
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	/* Do L_Port error recovery */
	unf_lport_error_recovery(unf_lport);
}

static void unf_lport_update_nport_id(struct unf_lport *lport, u32 nport_id)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	lport->nport_id = nport_id;
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);
}

static void
unf_lport_update_time_params(struct unf_lport *lport,
			     struct unf_flogi_fdisc_payload *flogi_payload)
{
	ulong flag = 0;
	u32 ed_tov = 0;
	u32 ra_tov = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(flogi_payload);

	ed_tov = flogi_payload->fabric_parms.co_parms.e_d_tov;
	ra_tov = flogi_payload->fabric_parms.co_parms.r_a_tov;

	spin_lock_irqsave(&lport->lport_state_lock, flag);

	/* FC-FS-3: 21.3.4, 21.3.5 */
	if (lport->act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    lport->act_topo == UNF_ACT_TOP_PUBLIC_LOOP) {
		lport->ed_tov = ed_tov;
		lport->ra_tov = ra_tov;
	} else {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) with topo(0x%x) no need to save time parameters",
			     lport->port_id, lport->nport_id, lport->act_topo);
	}

	spin_unlock_irqrestore(&lport->lport_state_lock, flag);
}

static void unf_rcv_flogi_acc(struct unf_lport *lport, struct unf_rport *rport,
			      struct unf_flogi_fdisc_payload *flogi_pld,
			      u32 nport_id, struct unf_xchg *xchg)
{
	/* PLOGI to Name server or remote port */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	struct unf_flogi_fdisc_payload *unf_flogi_pld = flogi_pld;
	struct unf_fabric_parm *fabric_params = NULL;
	u64 port_name = 0;
	u64 node_name = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(flogi_pld);

	/* Check L_Port state: FLOGI_WAIT */
	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	if (unf_lport->states != UNF_LPORT_ST_FLOGI_WAIT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[info]Port(0x%x_0x%x) receive FLOGI ACC with state(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, unf_lport->states);

		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);
		return;
	}
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	fabric_params = &unf_flogi_pld->fabric_parms;
	node_name =
	    (u64)(((u64)(fabric_params->high_node_name) << UNF_SHIFT_32) |
		  ((u64)(fabric_params->low_node_name)));
	port_name =
	    (u64)(((u64)(fabric_params->high_port_name) << UNF_SHIFT_32) |
		  ((u64)(fabric_params->low_port_name)));

	/* flogi acc pyload class 3 service priority value */
	if (unf_lport->root_lport == unf_lport && unf_lport->qos_cs_ctrl &&
	    fabric_params->cl_parms[ARRAY_INDEX_2].priority == UNF_PRIORITY_ENABLE)
		unf_lport->priority = (bool)UNF_PRIORITY_ENABLE;
	else
		unf_lport->priority = (bool)UNF_PRIORITY_DISABLE;

	/* Save Flogi parameters */
	unf_save_fabric_params(unf_lport, unf_rport, fabric_params);

	if (UNF_CHECK_NPORT_FPORT_BIT(unf_flogi_pld) == UNF_N_PORT) {
		/* P2P Mode */
		unf_lport_update_topo(unf_lport, UNF_ACT_TOP_P2P_DIRECT);
		unf_login_with_rport_in_n2n(unf_lport, port_name, node_name);
	} else {
		/* for:
		 * UNF_ACT_TOP_PUBLIC_LOOP/UNF_ACT_TOP_P2P_FABRIC
		 * /UNF_TOP_P2P_MASK
		 */
		if (unf_lport->act_topo != UNF_ACT_TOP_PUBLIC_LOOP)
			unf_lport_update_topo(unf_lport, UNF_ACT_TOP_P2P_FABRIC);

		unf_lport_update_nport_id(unf_lport, nport_id);
		unf_lport_update_time_params(unf_lport, unf_flogi_pld);

		/* Save process both for Public loop & Fabric */
		unf_register_to_switch(unf_lport);
	}
}

static void unf_flogi_acc_com_process(struct unf_xchg *xchg)
{
	/* Maybe within interrupt or thread context */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_flogi_fdisc_payload *flogi_pld = NULL;
	u32 nport_id = 0;
	u32 cmnd = 0;
	ulong flags = 0;
	struct unf_xchg *unf_xchg = xchg;

	FC_CHECK_RETURN_VOID(unf_xchg);
	FC_CHECK_RETURN_VOID(unf_xchg->lport);

	unf_lport = unf_xchg->lport;
	unf_rport = unf_xchg->rport;
	flogi_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->flogi_acc.flogi_payload;
	cmnd = flogi_pld->cmnd;

	/* Get N_Port_ID & R_Port */
	/* Others: 0xFFFFFE */
	unf_rport = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_FLOGI);
	nport_id = UNF_FC_FID_FLOGI;

	/* Get Safe R_Port: reuse only */
	unf_rport = unf_get_safe_rport(unf_lport, unf_rport, UNF_RPORT_REUSE_ONLY, nport_id);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can not allocate new Rport", unf_lport->port_id);

		return;
	}

	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	unf_rport->nport_id = UNF_FC_FID_FLOGI;

	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	/* Process FLOGI ACC or RJT */
	if ((cmnd & UNF_ELS_CMND_HIGH_MASK) == UNF_ELS_CMND_ACC) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: FLOGI response is(0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			     cmnd, unf_lport->port_id, unf_rport->nport_id, unf_xchg->oxid);

		/* Case for ACC */
		unf_rcv_flogi_acc(unf_lport, unf_rport, flogi_pld, unf_xchg->sid, unf_xchg);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: FLOGI response is(0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
			     cmnd, unf_lport->port_id, unf_rport->nport_id,
			     unf_xchg->oxid);

		/* Case for RJT: do L_Port error recovery */
		unf_lport_error_recovery(unf_lport);
	}
}

static int unf_rcv_flogi_acc_async_callback(void *argc_in, void *argc_out)
{
	struct unf_xchg *xchg = (struct unf_xchg *)argc_in;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	unf_flogi_acc_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return RETURN_OK;
}

void unf_flogi_callback(void *lport, void *rport, void *xchg)
{
	/* Callback function for FLOGI ACC or RJT */
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_flogi_fdisc_payload *flogi_pld = NULL;
	bool bbscn_enabled = false;
	enum unf_act_topo act_topo = UNF_ACT_TOP_UNKNOWN;
	bool switch2thread = false;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);
	FC_CHECK_RETURN_VOID(unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr);

	unf_xchg->lport = lport;
	flogi_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->flogi_acc.flogi_payload;

	if (unf_xchg->byte_orders & UNF_BIT_2)
		unf_big_end_to_cpu((u8 *)flogi_pld, sizeof(struct unf_flogi_fdisc_payload));

	if (unf_lport->act_topo != UNF_ACT_TOP_PUBLIC_LOOP &&
	    (UNF_CHECK_NPORT_FPORT_BIT(flogi_pld) == UNF_F_PORT))
		/* Get Top Mode (P2P_F) --->>> used for BBSCN */
		act_topo = UNF_ACT_TOP_P2P_FABRIC;

	bbscn_enabled =
	    unf_check_bbscn_is_enabled((u8)unf_lport->low_level_func.lport_cfg_items.bbscn,
				       (u8)UNF_GET_BB_SC_N_FROM_PARAMS(&flogi_pld->fabric_parms));
	if (act_topo == UNF_ACT_TOP_P2P_FABRIC && bbscn_enabled) {
		/* BBSCN Enable or not --->>> used for Context change */
		unf_lport->bbscn_support = true;
		switch2thread = true;
	}

	if (switch2thread && unf_lport->root_lport == unf_lport) {
		/* Wait for LR done sync: for Root Port */
		(void)unf_irq_process_switch2thread(unf_lport, unf_xchg,
		    unf_rcv_flogi_acc_async_callback);
	} else {
		/* Process FLOGI response directly */
		unf_flogi_acc_com_process(unf_xchg);
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ALL,
		     "[info]Port(0x%x) process FLOGI response: switch(%d) to thread done",
		     unf_lport->port_id, switch2thread);
}

void unf_plogi_ob_callback(struct unf_xchg *xchg)
{
	/* Do L_Port or R_Port recovery */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	unf_lport = xchg->lport;
	unf_rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_CHECK_RETURN_VOID(unf_lport);
	FC_CHECK_RETURN_VOID(unf_rport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI(0x%x_0x%x) to RPort(%p:0x%x_0x%x) failed",
		     unf_lport->port_id, unf_lport->nport_id, xchg->oxid,
		     xchg->rxid, unf_rport, unf_rport->rport_index,
		     unf_rport->nport_id);

	/* Start to recovery */
	if (unf_rport->nport_id > UNF_FC_FID_DOM_MGR) {
		/* with Name server: R_Port is fabric --->>> L_Port error
		 * recovery
		 */
		unf_lport_error_recovery(unf_lport);
	} else {
		/* R_Port is not fabric --->>> R_Port error recovery */
		unf_rport_error_recovery(unf_rport);
	}
}

void unf_rcv_plogi_acc(struct unf_lport *lport, struct unf_rport *rport,
		       struct unf_lgn_parm *login_parms)
{
	/* PLOGI ACC: PRLI(non fabric) or RFT_ID(fabric) */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	struct unf_lgn_parm *unf_login_parms = login_parms;
	u64 node_name = 0;
	u64 port_name = 0;
	ulong flag = 0;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(login_parms);

	node_name = (u64)(((u64)(unf_login_parms->high_node_name) << UNF_SHIFT_32) |
		    ((u64)(unf_login_parms->low_node_name)));
	port_name = (u64)(((u64)(unf_login_parms->high_port_name) << UNF_SHIFT_32) |
		    ((u64)(unf_login_parms->low_port_name)));

	/* ACC & Case for: R_Port is fabric (RFT_ID) */
	if (unf_rport->nport_id >= UNF_FC_FID_DOM_MGR) {
		/* Check L_Port state */
		spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
		if (unf_lport->states != UNF_LPORT_ST_PLOGI_WAIT) {
			spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) receive PLOGI ACC with error state(0x%x)",
				     lport->port_id, unf_lport->states);

			return;
		}
		unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_REMOTE_ACC);
		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

		/* PLOGI parameters save */
		unf_save_plogi_params(unf_lport, unf_rport, unf_login_parms, ELS_ACC);

		/* Update R_Port WWPN & WWNN */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport->node_name = node_name;
		unf_rport->port_name = port_name;
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		/* Start to Send RFT_ID */
		ret = unf_send_rft_id(unf_lport, unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x) send RFT_ID failed",
				     lport->port_id);

			unf_lport_error_recovery(unf_lport);
		}
	} else {
		/* ACC & Case for: R_Port is not fabric */
		if (unf_rport->options == UNF_PORT_MODE_UNKNOWN &&
		    unf_rport->port_name != INVALID_WWPN)
			unf_rport->options = unf_get_port_feature(port_name);

		/* Set Port Feature with BOTH: cancel */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport->node_name = node_name;
		unf_rport->port_name = port_name;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]LOGIN: Port(0x%x)<---LS_ACC(DID:0x%x SID:0x%x) for PLOGI ACC with RPort state(0x%x) NodeName(0x%llx) E_D_TOV(%u)",
			     unf_lport->port_id, unf_lport->nport_id,
			     unf_rport->nport_id, unf_rport->rp_state,
			     unf_rport->node_name, unf_rport->ed_tov);

		if (unf_lport->act_topo == UNF_ACT_TOP_PRIVATE_LOOP &&
		    (unf_rport->rp_state == UNF_RPORT_ST_PRLI_WAIT ||
		     unf_rport->rp_state == UNF_RPORT_ST_READY)) {
			/* Do nothing, return directly */
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);
			return;
		}

		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PRLI);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		/* PLOGI parameters save */
		unf_save_plogi_params(unf_lport, unf_rport, unf_login_parms, ELS_ACC);

		/*
		 * Need Delay to Send PRLI or not
		 * Used for: L_Port with INI mode & R_Port is not Fabric
		 */
		unf_check_rport_need_delay_prli(unf_lport, unf_rport, unf_rport->options);

		/* Do not care: Just used for L_Port only is TGT mode or R_Port
		 * only is INI mode
		 */
		unf_schedule_open_work(unf_lport, unf_rport);
	}
}

void unf_plogi_acc_com_process(struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_plogi_payload *plogi_pld = NULL;
	struct unf_lgn_parm *login_parms = NULL;
	ulong flag = 0;
	u64 port_name = 0;
	u32 rport_nport_id = 0;
	u32 cmnd = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(unf_xchg);
	FC_CHECK_RETURN_VOID(unf_xchg->lport);
	FC_CHECK_RETURN_VOID(unf_xchg->rport);

	unf_lport = unf_xchg->lport;
	unf_rport = unf_xchg->rport;
	rport_nport_id = unf_rport->nport_id;
	plogi_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi_acc.payload;
	login_parms = &plogi_pld->stparms;
	cmnd = (plogi_pld->cmnd);

	if (UNF_ELS_CMND_ACC == (cmnd & UNF_ELS_CMND_HIGH_MASK)) {
		/* Case for PLOGI ACC: Go to next stage */
		port_name =
		    (u64)(((u64)(login_parms->high_port_name) << UNF_SHIFT_32) |
			  ((u64)(login_parms->low_port_name)));

		/* Get (new) R_Port: 0xfffffc has same WWN with 0xfffcxx */
		unf_rport = unf_find_rport(unf_lport, rport_nport_id, port_name);
		unf_rport = unf_get_safe_rport(unf_lport, unf_rport,
					       UNF_RPORT_REUSE_ONLY, rport_nport_id);
		if (unlikely(!unf_rport)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) alloc new RPort with wwpn(0x%llx) failed",
				     unf_lport->port_id, unf_lport->nport_id, port_name);
			return;
		}

		/* PLOGI parameters check */
		ret = unf_check_plogi_params(unf_lport, unf_rport, login_parms);
		if (ret != RETURN_OK)
			return;

		/* Update R_Port state */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport->nport_id = rport_nport_id;
		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		/* Start to process PLOGI ACC */
		unf_rcv_plogi_acc(unf_lport, unf_rport, login_parms);
	} else {
		/* Case for PLOGI RJT: L_Port or R_Port recovery */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x)<---RPort(0x%p) with LS_RJT(DID:0x%x SID:0x%x) for PLOGI",
			     unf_lport->port_id, unf_rport, unf_lport->nport_id,
			     unf_rport->nport_id);

		if (unf_rport->nport_id >= UNF_FC_FID_DOM_MGR)
			unf_lport_error_recovery(unf_lport);
		else
			unf_rport_error_recovery(unf_rport);
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: PLOGI response(0x%x). Port(0x%x_0x%x)<---RPort(0x%x_0x%p) wwpn(0x%llx) OX_ID(0x%x)",
		     cmnd, unf_lport->port_id, unf_lport->nport_id, unf_rport->nport_id,
		     unf_rport, port_name, unf_xchg->oxid);
}

static int unf_rcv_plogi_acc_async_callback(void *argc_in, void *argc_out)
{
	struct unf_xchg *xchg = (struct unf_xchg *)argc_in;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	unf_plogi_acc_com_process(xchg);

	unf_xchg_ref_dec(xchg, SFS_RESPONSE);

	return RETURN_OK;
}

void unf_plogi_callback(void *lport, void *rport, void *xchg)
{
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_plogi_payload *plogi_pld = NULL;
	struct unf_lgn_parm *login_parms = NULL;
	bool bbscn_enabled = false;
	bool switch2thread = false;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);
	FC_CHECK_RETURN_VOID(unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr);

	plogi_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->plogi_acc.payload;
	login_parms = &plogi_pld->stparms;
	unf_xchg->lport = lport;

	if (unf_xchg->byte_orders & UNF_BIT_2)
		unf_big_end_to_cpu((u8 *)plogi_pld, sizeof(struct unf_plogi_payload));

	bbscn_enabled =
	    unf_check_bbscn_is_enabled((u8)unf_lport->low_level_func.lport_cfg_items.bbscn,
				       (u8)UNF_GET_BB_SC_N_FROM_PARAMS(login_parms));
	if ((bbscn_enabled) &&
	    unf_lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		switch2thread = true;
		unf_lport->bbscn_support = true;
	}

	if (switch2thread && unf_lport->root_lport == unf_lport) {
		/* Wait for LR done sync: just for ROOT Port */
		(void)unf_irq_process_switch2thread(unf_lport, unf_xchg,
		    unf_rcv_plogi_acc_async_callback);
	} else {
		unf_plogi_acc_com_process(unf_xchg);
	}
}

static void unf_logo_ob_callback(struct unf_xchg *xchg)
{
	struct unf_lport *lport = NULL;
	struct unf_rport *rport = NULL;
	struct unf_rport *old_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	u32 nport_id = 0;
	u32 logo_retry = 0;
	u32 max_frame_size = 0;
	u64 port_name = 0;

	FC_CHECK_RETURN_VOID(xchg);
	unf_xchg = xchg;
	old_rport = unf_xchg->rport;
	logo_retry = old_rport->logo_retries;
	max_frame_size = old_rport->max_frame_size;
	port_name = old_rport->port_name;
	unf_rport_enter_closing(old_rport);

	lport = unf_xchg->lport;
	if (unf_is_lport_valid(lport) != RETURN_OK)
		return;

	/* Get R_Port by exchange info: Init state */
	nport_id = unf_xchg->did;
	rport = unf_get_rport_by_nport_id(lport, nport_id);
	rport = unf_get_safe_rport(lport, rport, UNF_RPORT_REUSE_INIT, nport_id);
	if (!rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) cannot allocate RPort", lport->port_id);
		return;
	}

	rport->logo_retries = logo_retry;
	rport->max_frame_size = max_frame_size;
	rport->port_name = port_name;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[info]LOGIN: Port(0x%x) received LOGO RSP timeout topo(0x%x) retries(%u)",
		     lport->port_id, lport->act_topo, rport->logo_retries);

	/* RCVD LOGO/PRLO & SEND LOGO: the same process */
	if (rport->logo_retries < UNF_MAX_RETRY_COUNT) {
		/* <: retry (LOGIN or LOGO) if necessary */
		unf_process_rport_after_logo(lport, rport);
	} else {
		/* >=: Link down */
		unf_rport_immediate_link_down(lport, rport);
	}
}

static void unf_logo_callback(void *lport, void *rport, void *xchg)
{
	/* RCVD LOGO ACC/RJT: retry(LOGIN/LOGO) or link down immediately */
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_rport *unf_rport = NULL;
	struct unf_rport *old_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_els_rjt *els_acc_rjt = NULL;
	u32 cmnd = 0;
	u32 nport_id = 0;
	u32 logo_retry = 0;
	u32 max_frame_size = 0;
	u64 port_name = 0;

	FC_CHECK_RETURN_VOID(xchg);

	unf_xchg = (struct unf_xchg *)xchg;
	old_rport = unf_xchg->rport;

	logo_retry = old_rport->logo_retries;
	max_frame_size = old_rport->max_frame_size;
	port_name = old_rport->port_name;
	unf_rport_enter_closing(old_rport);

	if (unf_is_lport_valid(lport) != RETURN_OK)
		return;

	if (!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr)
		return;

	/* Get R_Port by exchange info: Init state */
	els_acc_rjt = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->els_rjt;
	nport_id = unf_xchg->did;
	unf_rport = unf_get_rport_by_nport_id(unf_lport, nport_id);
	unf_rport = unf_get_safe_rport(unf_lport, unf_rport, UNF_RPORT_REUSE_INIT, nport_id);

	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) cannot allocate RPort",
			     unf_lport->port_id);
		return;
	}

	unf_rport->logo_retries = logo_retry;
	unf_rport->max_frame_size = max_frame_size;
	unf_rport->port_name = port_name;
	cmnd = be32_to_cpu(els_acc_rjt->cmnd);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x) received LOGO RSP(0x%x),topo(0x%x) Port options(0x%x) RPort options(0x%x) retries(%u)",
		     unf_lport->port_id, (cmnd & UNF_ELS_CMND_HIGH_MASK),
		     unf_lport->act_topo, unf_lport->options, unf_rport->options,
		     unf_rport->logo_retries);

	/* RCVD LOGO/PRLO & SEND LOGO: the same process */
	if (unf_rport->logo_retries < UNF_MAX_RETRY_COUNT) {
		/* <: retry (LOGIN or LOGO) if necessary */
		unf_process_rport_after_logo(unf_lport, unf_rport);
	} else {
		/* >=: Link down */
		unf_rport_immediate_link_down(unf_lport, unf_rport);
	}
}

void unf_prli_ob_callback(struct unf_xchg *xchg)
{
	/* Do R_Port recovery */
	struct unf_lport *lport = NULL;
	struct unf_rport *rport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	lport = xchg->lport;
	rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]LOGIN: Port(0x%x_0x%x) RPort(0x%x) send PRLI failed and do recovery",
		     lport->port_id, lport->nport_id, rport->nport_id);

	/* Start to do R_Port error recovery */
	unf_rport_error_recovery(rport);
}

void unf_prli_callback(void *lport, void *rport, void *xchg)
{
	/* RCVD PRLI RSP: ACC or RJT --->>> SCSI Link Up */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_prli_payload *prli_acc_pld = NULL;
	ulong flag = 0;
	u32 cmnd = 0;
	u32 options = 0;
	u32 fcp_conf = 0;
	u32 rec_support = 0;
	u32 task_retry_support = 0;
	u32 retry_support = 0;
	u32 tape_support = 0;
	u32 fc4_type = 0;
	enum unf_rport_login_state rport_state = UNF_RPORT_ST_INIT;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);
	unf_lport = (struct unf_lport *)lport;
	unf_rport = (struct unf_rport *)rport;
	unf_xchg = (struct unf_xchg *)xchg;

	if (!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) exchange(%p) entry is NULL",
			     unf_lport->port_id, unf_xchg);
		return;
	}

	/* Get PRLI ACC payload */
	prli_acc_pld = &unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->prli_acc.payload;
	if (unf_xchg->byte_orders & UNF_BIT_2) {
		/* Change to little End, About INI/TGT mode & confirm info */
		options = be32_to_cpu(prli_acc_pld->parms[ARRAY_INDEX_3]) &
		    (UNF_FC4_FRAME_PARM_3_TGT | UNF_FC4_FRAME_PARM_3_INI);

		cmnd = be32_to_cpu(prli_acc_pld->cmnd);
		fcp_conf = be32_to_cpu(prli_acc_pld->parms[ARRAY_INDEX_3]) &
		    UNF_FC4_FRAME_PARM_3_CONF_ALLOW;
		rec_support = be32_to_cpu(prli_acc_pld->parms[ARRAY_INDEX_3]) &
		    UNF_FC4_FRAME_PARM_3_REC_SUPPORT;
		task_retry_support = be32_to_cpu(prli_acc_pld->parms[ARRAY_INDEX_3]) &
		    UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT;
		retry_support = be32_to_cpu(prli_acc_pld->parms[ARRAY_INDEX_3]) &
		    UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT;
		fc4_type = be32_to_cpu(prli_acc_pld->parms[ARRAY_INDEX_0]) >>
			UNF_FC4_TYPE_SHIFT & UNF_FC4_TYPE_MASK;
	} else {
		options = (prli_acc_pld->parms[ARRAY_INDEX_3]) &
			  (UNF_FC4_FRAME_PARM_3_TGT | UNF_FC4_FRAME_PARM_3_INI);

		cmnd = (prli_acc_pld->cmnd);
		fcp_conf = prli_acc_pld->parms[ARRAY_INDEX_3] & UNF_FC4_FRAME_PARM_3_CONF_ALLOW;
		rec_support = prli_acc_pld->parms[ARRAY_INDEX_3] & UNF_FC4_FRAME_PARM_3_REC_SUPPORT;
		task_retry_support = prli_acc_pld->parms[ARRAY_INDEX_3] &
				     UNF_FC4_FRAME_PARM_3_TASK_RETRY_ID_SUPPORT;
		retry_support = prli_acc_pld->parms[ARRAY_INDEX_3] &
				UNF_FC4_FRAME_PARM_3_RETRY_SUPPORT;
		fc4_type = prli_acc_pld->parms[ARRAY_INDEX_0] >> UNF_FC4_TYPE_SHIFT;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: PRLI RSP: RPort(0x%x) parameter-3(0x%x) option(0x%x) cmd(0x%x) uiRecSupport:%u",
		     unf_rport->nport_id, prli_acc_pld->parms[ARRAY_INDEX_3],
		     options, cmnd, rec_support);

	/* PRLI ACC: R_Port READY & Report R_Port Link Up */
	if (UNF_ELS_CMND_ACC == (cmnd & UNF_ELS_CMND_HIGH_MASK)) {
		/* Update R_Port options(INI/TGT/BOTH) */
		unf_rport->options = options;

		unf_update_port_feature(unf_rport->port_name, unf_rport->options);

		/* NOTE: R_Port only with INI mode, send LOGO */
		if (unf_rport->options == UNF_PORT_MODE_INI) {
			/* Update R_Port state: LOGO */
			spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
			unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
			spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

			/* NOTE: Start to Send LOGO */
			unf_rport_enter_logo(unf_lport, unf_rport);
			return;
		}

		/* About confirm */
		if (fcp_conf && unf_lport->low_level_func.lport_cfg_items.fcp_conf) {
			unf_rport->fcp_conf_needed = true;

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x_0x%x) FCP config is need for RPort(0x%x)",
				     unf_lport->port_id, unf_lport->nport_id,
				     unf_rport->nport_id);
		}

		tape_support = (rec_support && task_retry_support && retry_support);
		if (tape_support && unf_lport->low_level_func.lport_cfg_items.tape_support) {
			unf_rport->tape_support_needed = true;

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
				     "[info]Port(0x%x_0x%x) Rec is enabled for RPort(0x%x)",
				     unf_lport->port_id, unf_lport->nport_id,
				     unf_rport->nport_id);
		}

		/* Update R_Port state: READY */
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_READY);
		rport_state = unf_rport->rp_state;
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		/* Report R_Port online (Link Up) event to SCSI */
		if (rport_state == UNF_RPORT_ST_READY) {
			unf_rport->logo_retries = 0;
			unf_update_lport_state_by_linkup_event(unf_lport, unf_rport,
							       unf_rport->options);
		}
	} else {
		/* PRLI RJT: Do R_Port error recovery */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]LOGIN: Port(0x%x)<---LS_RJT(DID:0x%x SID:0x%x) for PRLI. RPort(0x%p) OX_ID(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id,
			     unf_rport->nport_id, unf_rport, unf_xchg->oxid);

		unf_rport_error_recovery(unf_rport);
	}
}

static void unf_rrq_callback(void *lport, void *rport, void *xchg)
{
	/* Release I/O */
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_xchg *io_xchg = NULL;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(xchg);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)xchg;

	if (!unf_xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) exchange(0x%p) SfsEntryPtr is NULL",
			     unf_lport->port_id, unf_xchg);
		return;
	}

	io_xchg = (struct unf_xchg *)unf_xchg->io_xchg;
	if (!io_xchg) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) IO exchange is NULL. RRQ cb sfs xchg(0x%p) tag(0x%x)",
			     unf_lport->port_id, unf_xchg, unf_xchg->hotpooltag);
		return;
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) release IO exch(0x%p) tag(0x%x). RRQ cb sfs xchg(0x%p) tag(0x%x)",
		     unf_lport->port_id, unf_xchg->io_xchg, io_xchg->hotpooltag,
		     unf_xchg, unf_xchg->hotpooltag);

	/* After RRQ Success, Free xid */
	unf_notify_chip_free_xid(io_xchg);

	/* NOTE: release I/O exchange resource */
	unf_xchg_ref_dec(io_xchg, XCHG_ALLOC);
}

static void unf_rrq_ob_callback(struct unf_xchg *xchg)
{
	/* Release I/O */
	struct unf_xchg *unf_xchg = NULL;
	struct unf_xchg *io_xchg = NULL;

	unf_xchg = (struct unf_xchg *)xchg;
	if (!unf_xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Exchange can't be NULL");
		return;
	}

	io_xchg = (struct unf_xchg *)unf_xchg->io_xchg;
	if (!io_xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]IO exchange can't be NULL with Sfs exch(0x%p) tag(0x%x)",
			     unf_xchg, unf_xchg->hotpooltag);
		return;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[info]send RRQ failed: SFS exch(0x%p) tag(0x%x) exch(0x%p) tag(0x%x) OXID_RXID(0x%x_0x%x) SID_DID(0x%x_0x%x)",
		     unf_xchg, unf_xchg->hotpooltag, io_xchg, io_xchg->hotpooltag,
		     io_xchg->oxid, io_xchg->rxid, io_xchg->sid, io_xchg->did);

	/* If RRQ failure or timepout, Free xid. */
	unf_notify_chip_free_xid(io_xchg);

	/* NOTE: Free I/O exchange resource */
	unf_xchg_ref_dec(io_xchg, XCHG_ALLOC);
}
