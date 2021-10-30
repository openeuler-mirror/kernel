// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_service.h"
#include "unf_log.h"
#include "unf_rport.h"
#include "unf_ls.h"
#include "unf_gs.h"

struct unf_els_handle_table els_handle_table[] = {
	{ELS_PLOGI, unf_plogi_handler}, {ELS_FLOGI, unf_flogi_handler},
	{ELS_LOGO, unf_logo_handler},   {ELS_ECHO, unf_echo_handler},
	{ELS_RRQ, unf_rrq_handler},	    {ELS_REC, unf_rec_handler},
	{ELS_PRLI, unf_prli_handler},   {ELS_PRLO, unf_prlo_handler},
	{ELS_PDISC, unf_pdisc_handler}, {ELS_ADISC, unf_adisc_handler},
	{ELS_RSCN, unf_rscn_handler} };

u32 max_frame_size = UNF_DEFAULT_FRAME_SIZE;

#define UNF_NEED_BIG_RESPONSE_BUFF(cmnd_code)                       \
	(((cmnd_code) == ELS_ECHO) || ((cmnd_code) == NS_GID_PT) || \
	 ((cmnd_code) == NS_GID_FT))

#define NEED_REFRESH_NPORTID(pkg)                                     \
	((((pkg)->cmnd == ELS_PLOGI) || ((pkg)->cmnd == ELS_PDISC) || \
	  ((pkg)->cmnd == ELS_ADISC)))

void unf_select_sq(struct unf_xchg *xchg, struct unf_frame_pkg *pkg)
{
	u32 ssq_index = 0;
	struct unf_rport *unf_rport = NULL;

	if (likely(xchg)) {
		unf_rport = xchg->rport;

		if (unf_rport) {
			ssq_index = (xchg->hotpooltag % UNF_SQ_NUM_PER_SESSION) +
			    unf_rport->sqn_base;
		}
	}

	pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX] = ssq_index;
}

u32 unf_ls_gs_cmnd_send(struct unf_lport *lport, struct unf_frame_pkg *pkg,
			struct unf_xchg *xchg)
{
	u32 ret = UNF_RETURN_ERROR;
	ulong time_out = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	if (unlikely(!lport->low_level_func.service_op.unf_ls_gs_send)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) LS/GS send function is NULL",
			     lport->port_id);

		return ret;
	}

	if (pkg->type == UNF_PKG_GS_REQ)
		time_out = UNF_GET_GS_SFS_XCHG_TIMER(lport);
	else
		time_out = UNF_GET_ELS_SFS_XCHG_TIMER(lport);

	if (xchg->cmnd_code == ELS_RRQ) {
		time_out = ((ulong)UNF_GET_ELS_SFS_XCHG_TIMER(lport) > UNF_RRQ_MIN_TIMEOUT_INTERVAL)
			       ? (ulong)UNF_GET_ELS_SFS_XCHG_TIMER(lport)
			       : UNF_RRQ_MIN_TIMEOUT_INTERVAL;
	} else if (xchg->cmnd_code == ELS_LOGO) {
		time_out = UNF_LOGO_TIMEOUT_INTERVAL;
	}

	pkg->private_data[PKG_PRIVATE_XCHG_TIMEER] = (u32)time_out;
	lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg, time_out, UNF_TIMER_TYPE_SFS);

	unf_select_sq(xchg, pkg);

	ret = lport->low_level_func.service_op.unf_ls_gs_send(lport->fc_port, pkg);
	if (unlikely(ret != RETURN_OK))
		lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

	return ret;
}

static u32 unf_bls_cmnd_send(struct unf_lport *lport, struct unf_frame_pkg *pkg,
			     struct unf_xchg *xchg)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	pkg->private_data[PKG_PRIVATE_XCHG_TIMEER] = (u32)UNF_GET_BLS_SFS_XCHG_TIMER(lport);
	pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];

	unf_select_sq(xchg, pkg);

	return lport->low_level_func.service_op.unf_bls_send(lport->fc_port, pkg);
}

void unf_fill_package(struct unf_frame_pkg *pkg, struct unf_xchg *xchg,
		      struct unf_rport *rport)
{
	/* v_pstRport maybe NULL */
	FC_CHECK_RETURN_VOID(pkg);
	FC_CHECK_RETURN_VOID(xchg);

	pkg->cmnd = xchg->cmnd_code;
	pkg->fcp_cmnd = &xchg->fcp_cmnd;
	pkg->frame_head.csctl_sid = xchg->sid;
	pkg->frame_head.rctl_did = xchg->did;
	pkg->frame_head.oxid_rxid = ((u32)xchg->oxid << UNF_SHIFT_16 | xchg->rxid);
	pkg->xchg_contex = xchg;

	FC_CHECK_RETURN_VOID(xchg->lport);
	pkg->private_data[PKG_PRIVATE_XCHG_VP_INDEX] = xchg->lport->vp_index;

	if (!rport) {
		pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = UNF_RPORT_INVALID_INDEX;
		pkg->private_data[PKG_PRIVATE_RPORT_RX_SIZE] = INVALID_VALUE32;
	} else {
		if (likely(rport->nport_id != UNF_FC_FID_FLOGI))
			pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = rport->rport_index;
		else
			pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = SPFC_DEFAULT_RPORT_INDEX;

		pkg->private_data[PKG_PRIVATE_RPORT_RX_SIZE] = rport->max_frame_size;
	}

	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = xchg->hotpooltag | UNF_HOTTAG_FLAG;
	pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];
	pkg->private_data[PKG_PRIVATE_LOWLEVEL_XCHG_ADD] =
	    xchg->private_data[PKG_PRIVATE_LOWLEVEL_XCHG_ADD];
	pkg->unf_cmnd_pload_bl.buffer_ptr =
		(u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	pkg->unf_cmnd_pload_bl.buf_dma_addr =
		xchg->fcp_sfs_union.sfs_entry.sfs_buff_phy_addr;

	/* Low level need to know payload length if send ECHO response */
	pkg->unf_cmnd_pload_bl.length = xchg->fcp_sfs_union.sfs_entry.cur_offset;
}

struct unf_xchg *unf_get_sfs_free_xchg_and_init(struct unf_lport *lport, u32 did,
						struct unf_rport *rport,
						union unf_sfs_u **fc_entry)
{
	struct unf_xchg *xchg = NULL;
	union unf_sfs_u *sfs_fc_entry = NULL;

	xchg = unf_cm_get_free_xchg(lport, UNF_XCHG_TYPE_SFS);
	if (!xchg)
		return NULL;

	xchg->did = did;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;
	xchg->disc_rport = NULL;
	xchg->callback = NULL;
	xchg->ob_callback = NULL;

	sfs_fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!sfs_fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return NULL;
	}

	*fc_entry = sfs_fc_entry;

	return xchg;
}

void *unf_get_one_big_sfs_buf(struct unf_xchg *xchg)
{
	struct unf_big_sfs *big_sfs = NULL;
	struct list_head *list_head = NULL;
	struct unf_xchg_mgr *xchg_mgr = NULL;
	ulong flag = 0;
	spinlock_t *big_sfs_pool_lock = NULL;

	FC_CHECK_RETURN_VALUE(xchg, NULL);
	xchg_mgr = xchg->xchg_mgr;
	FC_CHECK_RETURN_VALUE(xchg_mgr, NULL);
	big_sfs_pool_lock = &xchg_mgr->big_sfs_pool.big_sfs_pool_lock;

	spin_lock_irqsave(big_sfs_pool_lock, flag);
	if (!list_empty(&xchg_mgr->big_sfs_pool.list_freepool)) {
		/* from free to busy */
		list_head = UNF_OS_LIST_NEXT(&xchg_mgr->big_sfs_pool.list_freepool);
		list_del(list_head);
		xchg_mgr->big_sfs_pool.free_count--;
		list_add_tail(list_head, &xchg_mgr->big_sfs_pool.list_busypool);
		big_sfs = list_entry(list_head, struct unf_big_sfs, entry_bigsfs);
	} else {
		spin_unlock_irqrestore(big_sfs_pool_lock, flag);
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Allocate big sfs buf failed, count(0x%x) exchange(0x%p) command(0x%x)",
			     xchg_mgr->big_sfs_pool.free_count, xchg, xchg->cmnd_code);

		return NULL;
	}
	spin_unlock_irqrestore(big_sfs_pool_lock, flag);

	xchg->big_sfs_buf = big_sfs;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Allocate one big sfs buffer(0x%p), remaining count(0x%x) exchange(0x%p) command(0x%x)",
		     big_sfs->addr, xchg_mgr->big_sfs_pool.free_count, xchg,
		     xchg->cmnd_code);

	return big_sfs->addr;
}

static void unf_fill_rjt_pld(struct unf_els_rjt *els_rjt, u32 reason_code,
			     u32 reason_explanation)
{
	FC_CHECK_RETURN_VOID(els_rjt);

	els_rjt->cmnd = UNF_ELS_CMND_RJT;
	els_rjt->reason_code = (reason_code | reason_explanation);
}

u32 unf_send_abts(struct unf_lport *lport, struct unf_xchg *xchg)
{
	struct unf_rport *unf_rport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_frame_pkg pkg;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	unf_rport = xchg->rport;
	FC_CHECK_RETURN_VALUE(unf_rport, UNF_RETURN_ERROR);

	/* set pkg info */
	memset(&pkg, 0, sizeof(struct unf_frame_pkg));
	pkg.type = UNF_PKG_BLS_REQ;
	pkg.frame_head.csctl_sid = xchg->sid;
	pkg.frame_head.rctl_did = xchg->did;
	pkg.frame_head.oxid_rxid = ((u32)xchg->oxid << UNF_SHIFT_16 | xchg->rxid);
	pkg.xchg_contex = xchg;
	pkg.unf_cmnd_pload_bl.buffer_ptr = (u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;

	pkg.unf_cmnd_pload_bl.buf_dma_addr = xchg->fcp_sfs_union.sfs_entry.sfs_buff_phy_addr;
	pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = xchg->hotpooltag | UNF_HOTTAG_FLAG;

	UNF_SET_XCHG_ALLOC_TIME(&pkg, xchg);
	UNF_SET_ABORT_INFO_IOTYPE(&pkg, xchg);

	pkg.private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] =
	    xchg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX];

	/* Send ABTS frame to target */
	ret = unf_bls_cmnd_send(lport, &pkg, xchg);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[info]Port(0x%x_0x%x) send ABTS %s. Abort exch(0x%p) Cmdsn:0x%lx, tag(0x%x) iotype(0x%x)",
		     lport->port_id, lport->nport_id,
		     (ret == UNF_RETURN_ERROR) ? "failed" : "succeed", xchg,
		     (ulong)xchg->cmnd_sn, xchg->hotpooltag, xchg->data_direction);

	return ret;
}

u32 unf_send_els_rjt_by_rport(struct unf_lport *lport, struct unf_xchg *xchg,
			      struct unf_rport *rport, struct unf_rjt_info *rjt_info)
{
	struct unf_els_rjt *els_rjt = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_frame_pkg pkg = {0};
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_RJT_TYPE(rjt_info->els_cmnd_code);
	xchg->did = rport->nport_id;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = rport;
	xchg->disc_rport = NULL;

	xchg->callback = NULL;
	xchg->ob_callback = NULL;

	unf_fill_package(&pkg, xchg, rport);
	pkg.class_mode = UNF_FC_PROTOCOL_CLASS_3;
	pkg.type = UNF_PKG_ELS_REPLY;

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	els_rjt = &fc_entry->els_rjt;
	memset(els_rjt, 0, sizeof(struct unf_els_rjt));
	unf_fill_rjt_pld(els_rjt, rjt_info->reason_code, rjt_info->reason_explanation);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Send LS_RJT for 0x%x %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     rjt_info->els_cmnd_code,
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id,
		     rport->nport_id, ox_id, rx_id);

	return ret;
}

u32 unf_send_els_rjt_by_did(struct unf_lport *lport, struct unf_xchg *xchg,
			    u32 did, struct unf_rjt_info *rjt_info)
{
	struct unf_els_rjt *els_rjt = NULL;
	union unf_sfs_u *fc_entry = NULL;
	struct unf_frame_pkg pkg = {0};
	u32 ret = UNF_RETURN_ERROR;
	u16 ox_id = 0;
	u16 rx_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	xchg->cmnd_code = UNF_SET_ELS_RJT_TYPE(rjt_info->els_cmnd_code);
	xchg->did = did;
	xchg->sid = lport->nport_id;
	xchg->oid = xchg->sid;
	xchg->lport = lport;
	xchg->rport = NULL;
	xchg->disc_rport = NULL;

	xchg->callback = NULL;
	xchg->ob_callback = NULL;

	unf_fill_package(&pkg, xchg, NULL);
	pkg.class_mode = UNF_FC_PROTOCOL_CLASS_3;
	pkg.type = UNF_PKG_ELS_REPLY;

	if (rjt_info->reason_code == UNF_LS_RJT_CLASS_ERROR &&
	    rjt_info->class_mode != UNF_FC_PROTOCOL_CLASS_3) {
		pkg.class_mode = rjt_info->class_mode;
	}

	fc_entry = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr;
	if (!fc_entry) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) entry can't be NULL with tag(0x%x)",
			     lport->port_id, xchg->hotpooltag);

		unf_cm_free_xchg(lport, xchg);
		return UNF_RETURN_ERROR;
	}

	els_rjt = &fc_entry->els_rjt;
	memset(els_rjt, 0, sizeof(struct unf_els_rjt));
	unf_fill_rjt_pld(els_rjt, rjt_info->reason_code, rjt_info->reason_explanation);
	ox_id = xchg->oxid;
	rx_id = xchg->rxid;

	ret = unf_ls_gs_cmnd_send(lport, &pkg, xchg);
	if (ret != RETURN_OK)
		unf_cm_free_xchg((void *)lport, (void *)xchg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Send LS_RJT %s. Port(0x%x)--->RPort(0x%x) with OX_ID(0x%x) RX_ID(0x%x)",
		     (ret != RETURN_OK) ? "failed" : "succeed", lport->port_id, did, ox_id, rx_id);

	return ret;
}

static u32 unf_els_cmnd_default_handler(struct unf_lport *lport, struct unf_xchg *xchg, u32 sid,
					u32 els_cmnd_code)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_rjt_info rjt_info = {0};
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_KEVENT,
		     "[info]Receive Unknown ELS command(0x%x). Port(0x%x)<---RPort(0x%x) with OX_ID(0x%x)",
		     els_cmnd_code, lport->port_id, sid, xchg->oxid);

	memset(&rjt_info, 0, sizeof(struct unf_rjt_info));
	rjt_info.els_cmnd_code = els_cmnd_code;
	rjt_info.reason_code = UNF_LS_RJT_NOT_SUPPORTED;

	unf_rport = unf_get_rport_by_nport_id(lport, sid);
	if (unf_rport) {
		if (unf_rport->rport_index !=
		    xchg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX]) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x_0x%x) NPort handle(0x%x) from low level is not equal to RPort index(0x%x)",
				     lport->port_id, lport->nport_id,
				     xchg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX],
				     unf_rport->rport_index);
		}
		ret = unf_send_els_rjt_by_rport(lport, xchg, unf_rport, &rjt_info);
	} else {
		ret = unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);
	}

	return ret;
}

static struct unf_xchg *unf_alloc_xchg_for_rcv_cmnd(struct unf_lport *lport,
						    struct unf_frame_pkg *pkg)
{
	struct unf_xchg *xchg = NULL;
	ulong flags = 0;
	u32 i = 0;
	u32 offset = 0;
	u8 *cmnd_pld = NULL;
	u32 first_dword = 0;
	u32 alloc_time = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(pkg, NULL);

	if (!pkg->xchg_contex) {
		xchg = unf_cm_get_free_xchg(lport, UNF_XCHG_TYPE_SFS);
		if (!xchg) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[warn]Port(0x%x) get new exchange failed",
				     lport->port_id);

			return NULL;
		}

		offset = (xchg->fcp_sfs_union.sfs_entry.cur_offset);
		cmnd_pld = (u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld;
		first_dword = xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr
				  ->sfs_common.frame_head.rctl_did;

		if (cmnd_pld || first_dword != 0 || offset != 0) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) exchange(0x%p) abnormal, maybe data overrun, start(%llu) command(0x%x)",
				     lport->port_id, xchg, xchg->alloc_jif, pkg->cmnd);

			UNF_PRINT_SFS(UNF_INFO, lport->port_id,
				      xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr,
				      sizeof(union unf_sfs_u));
		}

		memset(xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr, 0, sizeof(union unf_sfs_u));

		pkg->xchg_contex = (void *)xchg;

		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		xchg->fcp_sfs_union.sfs_entry.cur_offset = 0;
		alloc_time = xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];
		for (i = 0; i < PKG_MAX_PRIVATE_DATA_SIZE; i++)
			xchg->private_data[i] = pkg->private_data[i];

		xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = alloc_time;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	} else {
		xchg = (struct unf_xchg *)pkg->xchg_contex;
	}

	if (!xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
		unf_cm_free_xchg((void *)lport, (void *)xchg);

		return NULL;
	}

	return xchg;
}

static u8 *unf_calc_big_cmnd_pld_buffer(struct unf_xchg *xchg, u32 cmnd_code)
{
	u8 *cmnd_pld = NULL;
	void *buf = NULL;
	u8 *dest = NULL;

	FC_CHECK_RETURN_VALUE(xchg, NULL);

	if (cmnd_code == ELS_RSCN)
		cmnd_pld = (u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld;
	else
		cmnd_pld = (u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld;

	if (!cmnd_pld) {
		buf = unf_get_one_big_sfs_buf(xchg);
		if (!buf)
			return NULL;

		if (cmnd_code == ELS_RSCN) {
			memset(buf, 0, sizeof(struct unf_rscn_pld));
			xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->rscn.rscn_pld = buf;
		} else {
			memset(buf, 0, sizeof(struct unf_echo_payload));
			xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld = buf;
		}

		dest = (u8 *)buf;
	} else {
		dest = (u8 *)(cmnd_pld + xchg->fcp_sfs_union.sfs_entry.cur_offset);
	}

	return dest;
}

static u8 *unf_calc_other_pld_buffer(struct unf_xchg *xchg)
{
	u8 *dest = NULL;
	u32 offset = 0;

	FC_CHECK_RETURN_VALUE(xchg, NULL);

	offset = (sizeof(struct unf_fc_head)) + (xchg->fcp_sfs_union.sfs_entry.cur_offset);
	dest = (u8 *)((u8 *)(xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) + offset);

	return dest;
}

struct unf_xchg *unf_mv_data_2_xchg(struct unf_lport *lport, struct unf_frame_pkg *pkg)
{
	struct unf_xchg *xchg = NULL;
	u8 *dest = NULL;
	u32 length = 0;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(pkg, NULL);

	xchg = unf_alloc_xchg_for_rcv_cmnd(lport, pkg);
	if (!xchg)
		return NULL;

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);

	memcpy(&xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->sfs_common.frame_head,
	       &pkg->frame_head, sizeof(pkg->frame_head));

	if (pkg->cmnd == ELS_RSCN || pkg->cmnd == ELS_ECHO)
		dest = unf_calc_big_cmnd_pld_buffer(xchg, pkg->cmnd);
	else
		dest = unf_calc_other_pld_buffer(xchg);

	if (!dest) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_cm_free_xchg((void *)lport, (void *)xchg);

		return NULL;
	}

	if (((xchg->fcp_sfs_union.sfs_entry.cur_offset +
	      pkg->unf_cmnd_pload_bl.length) > (u32)sizeof(union unf_sfs_u)) &&
	    pkg->cmnd != ELS_RSCN && pkg->cmnd != ELS_ECHO) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) excange(0x%p) command(0x%x,0x%x) copy payload overrun(0x%x:0x%x:0x%x)",
			     lport->port_id, xchg, pkg->cmnd, xchg->hotpooltag,
			     xchg->fcp_sfs_union.sfs_entry.cur_offset,
			     pkg->unf_cmnd_pload_bl.length, (u32)sizeof(union unf_sfs_u));

		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_cm_free_xchg((void *)lport, (void *)xchg);

		return NULL;
	}

	length = pkg->unf_cmnd_pload_bl.length;
	if (length > 0)
		memcpy(dest, pkg->unf_cmnd_pload_bl.buffer_ptr, length);

	xchg->fcp_sfs_union.sfs_entry.cur_offset += length;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return xchg;
}

static u32 unf_check_els_cmnd_valid(struct unf_lport *lport, struct unf_frame_pkg *pkg,
				    struct unf_xchg *xchg)
{
	struct unf_rjt_info rjt_info = {0};
	struct unf_lport *vport = NULL;
	u32 sid = 0;
	u32 did = 0;

	sid = (pkg->frame_head.csctl_sid) & UNF_NPORTID_MASK;
	did = (pkg->frame_head.rctl_did) & UNF_NPORTID_MASK;

	memset(&rjt_info, 0, sizeof(struct unf_rjt_info));

	if (pkg->class_mode != UNF_FC_PROTOCOL_CLASS_3) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) unsupport class 0x%x cmd 0x%x and send RJT",
			     lport->port_id, pkg->class_mode, pkg->cmnd);

		rjt_info.reason_code = UNF_LS_RJT_CLASS_ERROR;
		rjt_info.els_cmnd_code = pkg->cmnd;
		rjt_info.class_mode = pkg->class_mode;
		(void)unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);

		return UNF_RETURN_ERROR;
	}

	rjt_info.reason_code = UNF_LS_RJT_NOT_SUPPORTED;

	if (pkg->cmnd == ELS_FLOGI && lport->act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) receive FLOGI in top (0x%x) and send LS_RJT",
			     lport->port_id, lport->act_topo);

		rjt_info.els_cmnd_code = ELS_FLOGI;
		(void)unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);

		return UNF_RETURN_ERROR;
	}

	if (pkg->cmnd == ELS_PLOGI && did >= UNF_FC_FID_DOM_MGR) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x)receive PLOGI with wellknown address(0x%x) and Send LS_RJT",
			     lport->port_id, did);

		rjt_info.els_cmnd_code = ELS_PLOGI;
		(void)unf_send_els_rjt_by_did(lport, xchg, sid, &rjt_info);

		return UNF_RETURN_ERROR;
	}

	if ((lport->nport_id == 0 || lport->nport_id == INVALID_VALUE32) &&
	    (NEED_REFRESH_NPORTID(pkg))) {
		lport->nport_id = did;
	} else if ((lport->nport_id != did) && (pkg->cmnd != ELS_FLOGI)) {
		vport = unf_cm_lookup_vport_by_did(lport, did);
		if (!vport) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) receive ELS cmd(0x%x) with abnormal D_ID(0x%x)",
				     lport->nport_id, pkg->cmnd, did);

			unf_cm_free_xchg(lport, xchg);
			return UNF_RETURN_ERROR;
		}
	}

	return RETURN_OK;
}

static u32 unf_rcv_els_cmnd_req(struct unf_lport *lport, struct unf_frame_pkg *pkg)
{
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 i = 0;
	u32 sid = 0;
	u32 did = 0;
	struct unf_lport *vport = NULL;
	u32 (*els_cmnd_handler)(struct unf_lport *, u32, struct unf_xchg *) = NULL;

	sid = (pkg->frame_head.csctl_sid) & UNF_NPORTID_MASK;
	did = (pkg->frame_head.rctl_did) & UNF_NPORTID_MASK;

	xchg = unf_mv_data_2_xchg(lport, pkg);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) receive ElsCmnd(0x%x), exchange is NULL",
			     lport->port_id, pkg->cmnd);
		return UNF_RETURN_ERROR;
	}

	if (!pkg->last_pkg_flag) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Exchange(%u) waiting for last WQE",
			     xchg->hotpooltag);
		return RETURN_OK;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Exchange(%u) get last WQE", xchg->hotpooltag);

	xchg->oxid = UNF_GET_OXID(pkg);
	xchg->abort_oxid = xchg->oxid;
	xchg->rxid = UNF_GET_RXID(pkg);
	xchg->cmnd_code = pkg->cmnd;

	ret = unf_check_els_cmnd_valid(lport, pkg, xchg);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	if (lport->nport_id != did && pkg->cmnd != ELS_FLOGI) {
		vport = unf_cm_lookup_vport_by_did(lport, did);
		if (!vport) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) received unknown ELS command with S_ID(0x%x) D_ID(0x%x))",
				     lport->port_id, sid, did);
			return UNF_RETURN_ERROR;
		}
		lport = vport;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]VPort(0x%x) received ELS command with S_ID(0x%x) D_ID(0x%x)",
			     lport->port_id, sid, did);
	}

	do {
		if (pkg->cmnd == els_handle_table[i].cmnd) {
			els_cmnd_handler = els_handle_table[i].els_cmnd_handler;
			break;
		}
		i++;
	} while (i < (sizeof(els_handle_table) / sizeof(struct unf_els_handle_table)));

	if (els_cmnd_handler) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) receive ELS(0x%x) from RPort(0x%x) and process it",
			     lport->port_id, pkg->cmnd, sid);
		ret = els_cmnd_handler(lport, sid, xchg);
	} else {
		ret = unf_els_cmnd_default_handler(lport, xchg, sid, pkg->cmnd);
	}
	return ret;
}

u32 unf_send_els_rsp_succ(struct unf_lport *lport, struct unf_frame_pkg *pkg)
{
	struct unf_xchg *xchg = NULL;
	u32 ret = RETURN_OK;
	u16 hot_pool_tag = 0;
	ulong flags = 0;
	void (*ob_callback)(struct unf_xchg *) = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	if (!lport->xchg_mgr_temp.unf_look_up_xchg_by_tag) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) lookup exchange by tag function is NULL",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (u16)(pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg *)(lport->xchg_mgr_temp.unf_look_up_xchg_by_tag((void *)lport,
					    hot_pool_tag));
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) find exhange by tag(0x%x) failed",
			     lport->port_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (xchg->ob_callback &&
	    (!(xchg->io_state & TGT_IO_STATE_ABORT))) {
		ob_callback = xchg->ob_callback;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) with exchange(0x%p) tag(0x%x) do callback",
			     lport->port_id, xchg, hot_pool_tag);

		ob_callback(xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)lport, (void *)xchg);
	return ret;
}

static u8 *unf_calc_big_resp_pld_buffer(struct unf_xchg *xchg, u32 cmnd_code)
{
	u8 *resp_pld = NULL;
	u8 *dest = NULL;

	FC_CHECK_RETURN_VALUE(xchg, NULL);

	if (cmnd_code == ELS_ECHO) {
		resp_pld = (u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr->echo.echo_pld;
	} else {
		resp_pld = (u8 *)xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr
			       ->get_id.gid_rsp.gid_acc_pld;
	}

	if (resp_pld)
		dest = (u8 *)(resp_pld + xchg->fcp_sfs_union.sfs_entry.cur_offset);

	return dest;
}

static u8 *unf_calc_other_resp_pld_buffer(struct unf_xchg *xchg)
{
	u8 *dest = NULL;
	u32 offset = 0;

	FC_CHECK_RETURN_VALUE(xchg, NULL);

	offset = xchg->fcp_sfs_union.sfs_entry.cur_offset;
	dest = (u8 *)((u8 *)(xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) + offset);

	return dest;
}

u32 unf_mv_resp_2_xchg(struct unf_xchg *xchg, struct unf_frame_pkg *pkg)
{
	u8 *dest = NULL;
	u32 length = 0;
	u32 offset = 0;
	u32 max_frame_len = 0;
	ulong flags = 0;

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);

	if (UNF_NEED_BIG_RESPONSE_BUFF(xchg->cmnd_code)) {
		dest = unf_calc_big_resp_pld_buffer(xchg, xchg->cmnd_code);
		offset = 0;
		max_frame_len = sizeof(struct unf_gid_acc_pld);
	} else if (NS_GA_NXT == xchg->cmnd_code || NS_GIEL == xchg->cmnd_code) {
		dest = unf_calc_big_resp_pld_buffer(xchg, xchg->cmnd_code);
		offset = 0;
		max_frame_len = xchg->fcp_sfs_union.sfs_entry.sfs_buff_len;
	} else {
		dest = unf_calc_other_resp_pld_buffer(xchg);
		offset = sizeof(struct unf_fc_head);
		max_frame_len = sizeof(union unf_sfs_u);
	}

	if (!dest) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		return UNF_RETURN_ERROR;
	}

	if (xchg->fcp_sfs_union.sfs_entry.cur_offset == 0) {
		xchg->fcp_sfs_union.sfs_entry.cur_offset += offset;
		dest = dest + offset;
	}

	length = pkg->unf_cmnd_pload_bl.length;

	if ((xchg->fcp_sfs_union.sfs_entry.cur_offset + length) >
	    max_frame_len) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Exchange(0x%p) command(0x%x) hotpooltag(0x%x) OX_RX_ID(0x%x) S_ID(0x%x) D_ID(0x%x) copy payload overrun(0x%x:0x%x:0x%x)",
			     xchg, xchg->cmnd_code, xchg->hotpooltag, pkg->frame_head.oxid_rxid,
			     pkg->frame_head.csctl_sid & UNF_NPORTID_MASK,
			     pkg->frame_head.rctl_did & UNF_NPORTID_MASK,
			     xchg->fcp_sfs_union.sfs_entry.cur_offset,
			     pkg->unf_cmnd_pload_bl.length, max_frame_len);

		length = max_frame_len - xchg->fcp_sfs_union.sfs_entry.cur_offset;
	}

	if (length > 0)
		memcpy(dest, pkg->unf_cmnd_pload_bl.buffer_ptr, length);

	xchg->fcp_sfs_union.sfs_entry.cur_offset += length;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return RETURN_OK;
}

static void unf_ls_gs_do_callback(struct unf_xchg *xchg,
				  struct unf_frame_pkg *pkg)
{
	ulong flags = 0;
	void (*callback)(void *, void *, void *) = NULL;

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (xchg->callback &&
	    (xchg->cmnd_code == ELS_RRQ ||
	     xchg->cmnd_code == ELS_LOGO ||
	     !(xchg->io_state & TGT_IO_STATE_ABORT))) {
		callback = xchg->callback;

		if (xchg->cmnd_code == ELS_FLOGI || xchg->cmnd_code == ELS_FDISC)
			xchg->sid = pkg->frame_head.rctl_did & UNF_NPORTID_MASK;

		if (xchg->cmnd_code == ELS_ECHO) {
			xchg->private_data[PKG_PRIVATE_ECHO_CMD_RCV_TIME] =
			    pkg->private_data[PKG_PRIVATE_ECHO_CMD_RCV_TIME];
			xchg->private_data[PKG_PRIVATE_ECHO_RSP_SND_TIME] =
			    pkg->private_data[PKG_PRIVATE_ECHO_RSP_SND_TIME];
			xchg->private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME] =
			    pkg->private_data[PKG_PRIVATE_ECHO_CMD_SND_TIME];
			xchg->private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME] =
			    pkg->private_data[PKG_PRIVATE_ECHO_ACC_RCV_TIME];
		}
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		callback(xchg->lport, xchg->rport, xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}
}

u32 unf_send_ls_gs_cmnd_succ(struct unf_lport *lport, struct unf_frame_pkg *pkg)
{
	struct unf_xchg *xchg = NULL;
	u32 ret = RETURN_OK;
	u16 hot_pool_tag = 0;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	unf_lport = lport;

	if (!unf_lport->xchg_mgr_temp.unf_look_up_xchg_by_tag) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) lookup exchange by tag function can't be NULL",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (u16)(pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg *)(unf_lport->xchg_mgr_temp
				     .unf_look_up_xchg_by_tag((void *)unf_lport, hot_pool_tag));
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) find exchange by tag(0x%x) failed",
			     unf_lport->port_id, unf_lport->nport_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(unf_lport, hot_pool_tag, xchg,
				  pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME],
				  xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	if ((pkg->frame_head.csctl_sid & UNF_NPORTID_MASK) != xchg->did) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find exhange invalid, package S_ID(0x%x) exchange S_ID(0x%x) D_ID(0x%x)",
			     unf_lport->port_id, pkg->frame_head.csctl_sid, xchg->sid, xchg->did);

		return UNF_RETURN_ERROR;
	}

	if (pkg->last_pkg_flag == UNF_PKG_NOT_LAST_RESPONSE) {
		ret = unf_mv_resp_2_xchg(xchg, pkg);
		return ret;
	}

	xchg->byte_orders = pkg->byte_orders;
	unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);
	unf_ls_gs_do_callback(xchg, pkg);
	unf_cm_free_xchg((void *)unf_lport, (void *)xchg);
	return ret;
}

u32 unf_send_ls_gs_cmnd_failed(struct unf_lport *lport,
			       struct unf_frame_pkg *pkg)
{
	struct unf_xchg *xchg = NULL;
	u32 ret = RETURN_OK;
	u16 hot_pool_tag = 0;
	ulong flags = 0;
	void (*ob_callback)(struct unf_xchg *) = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	if (!lport->xchg_mgr_temp.unf_look_up_xchg_by_tag) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) lookup exchange by tag function can't be NULL",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (u16)(pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);
	xchg = (struct unf_xchg *)(lport->xchg_mgr_temp.unf_look_up_xchg_by_tag((void *)lport,
					     hot_pool_tag));
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) find exhange by tag(0x%x) failed",
			     lport->port_id, lport->nport_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(lport, hot_pool_tag, xchg,
				  pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME],
				  xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (xchg->ob_callback &&
	    (xchg->cmnd_code == ELS_RRQ || xchg->cmnd_code == ELS_LOGO ||
	     (!(xchg->io_state & TGT_IO_STATE_ABORT)))) {
		ob_callback = xchg->ob_callback;
		xchg->ob_callback_sts = pkg->status;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		ob_callback(xchg);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) exchange(0x%p) tag(0x%x) do callback",
			     lport->port_id, xchg, hot_pool_tag);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_cm_free_xchg((void *)lport, (void *)xchg);
	return ret;
}

static u32 unf_rcv_ls_gs_cmnd_reply(struct unf_lport *lport,
				    struct unf_frame_pkg *pkg)
{
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	if (pkg->status == UNF_IO_SUCCESS || pkg->status == UNF_IO_UNDER_FLOW)
		ret = unf_send_ls_gs_cmnd_succ(lport, pkg);
	else
		ret = unf_send_ls_gs_cmnd_failed(lport, pkg);

	return ret;
}

u32 unf_receive_ls_gs_pkg(void *lport, struct unf_frame_pkg *pkg)
{
	struct unf_lport *unf_lport = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	unf_lport = (struct unf_lport *)lport;

	switch (pkg->type) {
	case UNF_PKG_ELS_REQ_DONE:
	case UNF_PKG_GS_REQ_DONE:
		ret = unf_rcv_ls_gs_cmnd_reply(unf_lport, pkg);
		break;

	case UNF_PKG_ELS_REQ:
		ret = unf_rcv_els_cmnd_req(unf_lport, pkg);
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) with exchange type(0x%x) abnormal",
			     unf_lport->port_id, unf_lport->nport_id, pkg->type);
		break;
	}

	return ret;
}

u32 unf_send_els_done(void *lport, struct unf_frame_pkg *pkg)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	if (pkg->type == UNF_PKG_ELS_REPLY_DONE) {
		if (pkg->status == UNF_IO_SUCCESS || pkg->status == UNF_IO_UNDER_FLOW)
			ret = unf_send_els_rsp_succ(lport, pkg);
		else
			ret = unf_send_ls_gs_cmnd_failed(lport, pkg);
	}

	return ret;
}

void unf_rport_immediate_link_down(struct unf_lport *lport, struct unf_rport *rport)
{
	/* Swap case: Report Link Down immediately & release R_Port */
	ulong flags = 0;
	struct unf_disc *disc = NULL;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&rport->rport_state_lock, flags);
	/* 1. Inc R_Port ref_cnt */
	if (unf_rport_ref_inc(rport) != RETURN_OK) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) Rport(0x%p,0x%x) is removing and no need process",
			     lport->port_id, rport, rport->nport_id);

		return;
	}

	/* 2. R_PORT state update: Link Down Event --->>> closing state */
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	/* 3. Put R_Port from busy to destroy list */
	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flags);
	list_del_init(&rport->entry_rport);
	list_add_tail(&rport->entry_rport, &disc->list_destroy_rports);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flags);

	/* 4. Schedule Closing work (Enqueuing workqueue) */
	unf_schedule_closing_work(lport, rport);

	unf_rport_ref_dec(rport);
}

struct unf_rport *unf_find_rport(struct unf_lport *lport, u32 rport_nport_id,
				 u64 lport_name)
{
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	if (rport_nport_id >= UNF_FC_FID_DOM_MGR) {
		/* R_Port is Fabric: by N_Port_ID */
		unf_rport = unf_get_rport_by_nport_id(unf_lport, rport_nport_id);
	} else {
		/* Others: by WWPN & N_Port_ID */
		unf_rport = unf_find_valid_rport(unf_lport, lport_name, rport_nport_id);
	}

	return unf_rport;
}

void unf_process_logo_in_pri_loop(struct unf_lport *lport, struct unf_rport *rport)
{
	/* Send PLOGI or LOGO */
	struct unf_rport *unf_rport = rport;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI); /* PLOGI WAIT */
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	/* Private Loop with INI mode, Avoid COM Mode problem */
	unf_rport_delay_login(unf_rport);
}

void unf_process_logo_in_n2n(struct unf_lport *lport, struct unf_rport *rport)
{
	/* Send PLOGI or LOGO */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);

	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	if (unf_lport->port_name > unf_rport->port_name) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x)'s WWN(0x%llx) is larger than(0x%llx), should be master",
			     unf_lport->port_id, unf_lport->port_name, unf_rport->port_name);

		ret = unf_send_plogi(unf_lport, unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x) send PLOGI failed, enter recovery",
				     lport->port_id);

			unf_rport_error_recovery(unf_rport);
		}
	} else {
		unf_rport_enter_logo(unf_lport, unf_rport);
	}
}

void unf_process_logo_in_fabric(struct unf_lport *lport,
				struct unf_rport *rport)
{
	/* Send GFF_ID or LOGO */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	struct unf_rport *sns_port = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	/* L_Port with INI Mode: Send GFF_ID */
	sns_port = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't find fabric port",
			     unf_lport->port_id);
		return;
	}

	ret = unf_get_and_post_disc_event(lport, sns_port, unf_rport->nport_id,
					  UNF_DISC_GET_FEATURE);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
			     unf_lport->port_id, UNF_DISC_GET_FEATURE,
			     unf_rport->nport_id);

		unf_rcv_gff_id_rsp_unknown(unf_lport, unf_rport->nport_id);
	}
}

void unf_process_rport_after_logo(struct unf_lport *lport, struct unf_rport *rport)
{
	/*
	 * 1. LOGO handler
	 * 2. RPLO handler
	 * 3. LOGO_CALL_BACK (send LOGO ACC) handler
	 */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	if (unf_rport->nport_id < UNF_FC_FID_DOM_MGR) {
		/* R_Port is not fabric port (retry LOGIN or LOGO) */
		if (unf_lport->act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
			/* Private Loop: PLOGI or LOGO */
			unf_process_logo_in_pri_loop(unf_lport, unf_rport);
		} else if (unf_lport->act_topo == UNF_ACT_TOP_P2P_DIRECT) {
			/* Point to Point: LOGIN or LOGO */
			unf_process_logo_in_n2n(unf_lport, unf_rport);
		} else {
			/* Fabric or Public Loop: GFF_ID or LOGO */
			unf_process_logo_in_fabric(unf_lport, unf_rport);
		}
	} else {
		/* Rport is fabric port: link down now */
		unf_rport_linkdown(unf_lport, unf_rport);
	}
}

static u32 unf_rcv_bls_req_done(struct unf_lport *lport, struct unf_frame_pkg *pkg)
{
	/*
	 * About I/O resource:
	 * 1. normal: Release I/O resource during RRQ processer
	 * 2. exception: Release I/O resource immediately
	 */
	struct unf_xchg *xchg = NULL;
	u16 hot_pool_tag = 0;
	ulong flags = 0;
	ulong time_ms = 0;
	u32 ret = RETURN_OK;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	unf_lport = lport;

	hot_pool_tag = (u16)pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX];
	xchg = (struct unf_xchg *)unf_cm_lookup_xchg_by_tag((void *)unf_lport, hot_pool_tag);
	if (!xchg) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) can't find exchange by tag(0x%x) when receiving ABTS response",
			     unf_lport->port_id, hot_pool_tag);
		return UNF_RETURN_ERROR;
	}

	UNF_CHECK_ALLOCTIME_VALID(lport, hot_pool_tag, xchg,
				  pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME],
				  xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	ret = unf_xchg_ref_inc(xchg, TGT_ABTS_DONE);
	FC_CHECK_RETURN_VALUE((ret == RETURN_OK), UNF_RETURN_ERROR);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->oxid = UNF_GET_OXID(pkg);
	xchg->rxid = UNF_GET_RXID(pkg);
	xchg->io_state |= INI_IO_STATE_DONE;
	xchg->abts_state |= ABTS_RESPONSE_RECEIVED;
	if (!(INI_IO_STATE_UPABORT & xchg->io_state)) {
		/* NOTE: I/O exchange has been released and used again */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) SID(0x%x) exch(0x%p) (0x%x:0x%x:0x%x:0x%x) state(0x%x) is abnormal with cnt(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, xchg->sid,
			     xchg, xchg->hotpooltag, xchg->oxid, xchg->rxid,
			     xchg->oid, xchg->io_state,
			     atomic_read(&xchg->ref_cnt));

		unf_xchg_ref_dec(xchg, TGT_ABTS_DONE);
		return UNF_RETURN_ERROR;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);
	/*
	 * Exchage I/O Status check: Succ-> Add RRQ Timer
	 * ***** pkg->status --- to --->>> scsi_cmnd->result *****
	 * *
	 * FAILED: ERR_Code or X_ID is err, or BA_RSP type is err
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (pkg->status == UNF_IO_SUCCESS) {
		/* Succeed: PKG status -->> EXCH status -->> scsi status */
		UNF_SET_SCSI_CMND_RESULT(xchg, UNF_IO_SUCCESS);
		xchg->io_state |= INI_IO_STATE_WAIT_RRQ;
		xchg->rxid = UNF_GET_RXID(pkg);
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* Add RRQ timer */
		time_ms = (ulong)(unf_lport->ra_tov);
		unf_lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg, time_ms,
			     UNF_TIMER_TYPE_INI_RRQ);
	} else {
		/* Failed: PKG status -->> EXCH status -->> scsi status */
		UNF_SET_SCSI_CMND_RESULT(xchg, UNF_IO_FAILED);
		if (MARKER_STS_RECEIVED & xchg->abts_state) {
			spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

			/* NOTE: release I/O resource immediately */
			unf_cm_free_xchg(unf_lport, xchg);
		} else {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) exch(0x%p) OX_RX(0x%x:0x%x) IOstate(0x%x) ABTSstate(0x%x) receive response abnormal ref(0x%x)",
				     unf_lport->port_id, xchg, xchg->oxid, xchg->rxid,
				     xchg->io_state, xchg->abts_state, atomic_read(&xchg->ref_cnt));
			spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		}
	}

	/*
	 * If abts response arrived before
	 * marker sts received just wake up abts marker sema
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (!(MARKER_STS_RECEIVED & xchg->abts_state)) {
		xchg->ucode_abts_state = pkg->status;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		up(&xchg->task_sema);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
	}

	unf_xchg_ref_dec(xchg, TGT_ABTS_DONE);
	return ret;
}

u32 unf_receive_bls_pkg(void *lport, struct unf_frame_pkg *pkg)
{
	struct unf_lport *unf_lport = NULL;
	u32 ret = UNF_RETURN_ERROR;

	unf_lport = (struct unf_lport *)lport;
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	if (pkg->type == UNF_PKG_BLS_REQ_DONE) {
		/* INI: RCVD BLS Req Done */
		ret = unf_rcv_bls_req_done(lport, pkg);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) received BLS packet type(%xh) is error",
			     unf_lport->port_id, pkg->type);

		return UNF_RETURN_ERROR;
	}

	return ret;
}

static void unf_fill_free_xid_pkg(struct unf_xchg *xchg, struct unf_frame_pkg *pkg)
{
	pkg->frame_head.csctl_sid = xchg->sid;
	pkg->frame_head.rctl_did = xchg->did;
	pkg->frame_head.oxid_rxid = (u32)(((u32)xchg->oxid << UNF_SHIFT_16) | xchg->rxid);
	pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = xchg->hotpooltag | UNF_HOTTAG_FLAG;
	UNF_SET_XCHG_ALLOC_TIME(pkg, xchg);

	if (xchg->xchg_type == UNF_XCHG_TYPE_SFS) {
		if (UNF_XCHG_IS_ELS_REPLY(xchg)) {
			pkg->type = UNF_PKG_ELS_REPLY;
			pkg->rx_or_ox_id = UNF_PKG_FREE_RXID;
			pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = INVALID_VALUE32;
			pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = INVALID_VALUE32;
		} else {
			pkg->type = UNF_PKG_ELS_REQ;
			pkg->rx_or_ox_id = UNF_PKG_FREE_OXID;
		}
	} else if (xchg->xchg_type == UNF_XCHG_TYPE_INI) {
		pkg->type = UNF_PKG_INI_IO;
		pkg->rx_or_ox_id = UNF_PKG_FREE_OXID;
	}
}

void unf_notify_chip_free_xid(struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = NULL;
	u32 ret = RETURN_ERROR;
	struct unf_frame_pkg pkg = {0};

	FC_CHECK_RETURN_VOID(xchg);
	unf_lport = xchg->lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	unf_fill_free_xid_pkg(xchg, &pkg);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Sid_Did(0x%x)(0x%x) Xchg(0x%p) RXorOX(0x%x) tag(0x%x) xid(0x%x) magic(0x%x) Stat(0x%x)type(0x%x) wait timeout.",
		     xchg->sid, xchg->did, xchg, pkg.rx_or_ox_id,
		     pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX], pkg.frame_head.oxid_rxid,
		     pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME], xchg->io_state, pkg.type);

	ret = unf_lport->low_level_func.service_op.ll_release_xid(unf_lport->fc_port, &pkg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Free xid abnormal:Sid_Did(0x%x 0x%x) Xchg(0x%p) RXorOX(0x%x) xid(0x%x) Stat(0x%x) tag(0x%x) magic(0x%x) type(0x%x).",
			     xchg->sid, xchg->did, xchg, pkg.rx_or_ox_id,
			     pkg.frame_head.oxid_rxid, xchg->io_state,
			     pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX],
			     pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME],
			     pkg.type);
	}
}
