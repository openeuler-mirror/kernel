// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_io_abnormal.h"
#include "unf_log.h"
#include "unf_scsi_common.h"
#include "unf_rport.h"
#include "unf_io.h"
#include "unf_portman.h"
#include "unf_service.h"

static int unf_send_abts_success(struct unf_lport *lport, struct unf_xchg *xchg,
				 struct unf_scsi_cmnd *scsi_cmnd,
				 u32 time_out_value)
{
	bool need_wait_marker = true;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	u32 scsi_id = 0;
	u32 return_value = 0;
	ulong xchg_flag = 0;

	spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
	need_wait_marker = (xchg->abts_state & MARKER_STS_RECEIVED) ? false : true;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

	if (need_wait_marker) {
		if (down_timeout(&xchg->task_sema, (s64)msecs_to_jiffies(time_out_value))) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) recv abts marker timeout,Exch(0x%p) OX_ID(0x%x 0x%x) RX_ID(0x%x)",
				     lport->port_id, xchg, xchg->oxid,
				     xchg->hotpooltag, xchg->rxid);

			/* Cancel abts rsp timer when sema timeout */
			lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

			/* Cnacel the flag of INI_IO_STATE_UPABORT and process
			 * the io in TMF
			 */
			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
			xchg->io_state &= ~INI_IO_STATE_UPABORT;
			xchg->io_state |= INI_IO_STATE_TMF_ABORT;
			spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

			return UNF_SCSI_ABORT_FAIL;
		}
	} else {
		xchg->ucode_abts_state = UNF_IO_SUCCESS;
	}

	scsi_image_table = &lport->rport_scsi_table;
	scsi_id = scsi_cmnd->scsi_id;

	spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
	if (xchg->ucode_abts_state == UNF_IO_SUCCESS ||
	    xchg->scsi_cmnd_info.result == UNF_IO_ABORT_PORT_REMOVING) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) Send ABTS succeed and recv marker Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) marker status(0x%x)",
			     lport->port_id, xchg, xchg->oxid, xchg->rxid, xchg->ucode_abts_state);
		return_value = DID_RESET;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, return_value);
		unf_complete_cmnd(scsi_cmnd, DID_RESET << UNF_SHIFT_16);
		return UNF_SCSI_ABORT_SUCCESS;
	}

	xchg->io_state &= ~INI_IO_STATE_UPABORT;
	xchg->io_state |= INI_IO_STATE_TMF_ABORT;

	spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

	/* Cancel abts rsp timer when sema timeout */
	lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
		     "[warn]Port(0x%x) send ABTS failed. Exch(0x%p) oxid(0x%x) hot_tag(0x%x) ret(0x%x) xchg->io_state (0x%x)",
		     lport->port_id, xchg, xchg->oxid, xchg->hotpooltag,
		     xchg->scsi_cmnd_info.result, xchg->io_state);

	/* return fail and then enter TMF */
	return UNF_SCSI_ABORT_FAIL;
}

static int unf_ini_abort_cmnd(struct unf_lport *lport, struct unf_xchg *xchg,
			      struct unf_scsi_cmnd *scsi_cmnd)
{
	/*
	 * About INI_IO_STATE_UPABORT:
	 * *
	 * 1. Check: L_Port destroy
	 * 2. Check: I/O XCHG timeout
	 * 3. Set ABORT: send ABTS
	 * 4. Set ABORT: LUN reset
	 * 5. Set ABORT: Target reset
	 * 6. Check: Prevent to send I/O to target
	 * (unf_prefer_to_send_scsi_cmnd)
	 * 7. Check: Done INI XCHG --->>> do not call scsi_done, return directly
	 * 8. Check: INI SCSI Complete --->>> do not call scsi_done, return
	 * directly
	 */
#define UNF_RPORT_NOTREADY_WAIT_SEM_TIMEOUT (2000)

	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong rport_flag = 0;
	ulong xchg_flag = 0;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	u32 scsi_id = 0;
	u32 time_out_value = (u32)UNF_WAIT_SEM_TIMEOUT;
	u32 return_value = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_SCSI_ABORT_FAIL);
	unf_lport = lport;

	/* 1. Xchg State Set: INI_IO_STATE_UPABORT */
	spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
	xchg->io_state |= INI_IO_STATE_UPABORT;
	unf_rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

	/* 2. R_Port check */
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send ABTS but no RPort, OX_ID(0x%x) RX_ID(0x%x)",
			     unf_lport->port_id, xchg->oxid, xchg->rxid);

		return UNF_SCSI_ABORT_SUCCESS;
	}

	spin_lock_irqsave(&unf_rport->rport_state_lock, rport_flag);
	if (unlikely(unf_rport->rp_state != UNF_RPORT_ST_READY)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find RPort's state(0x%x) is not ready but send ABTS also, exchange(0x%p) tag(0x%x)",
			     unf_lport->port_id, unf_rport->rp_state, xchg, xchg->hotpooltag);

		/*
		 * Important: Send ABTS also & update timer
		 * Purpose: only used for release chip (uCode) resource,
		 * continue
		 */
		time_out_value = UNF_RPORT_NOTREADY_WAIT_SEM_TIMEOUT;
	}
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, rport_flag);

	/* 3. L_Port State check */
	if (unlikely(unf_lport->port_removing)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is removing", unf_lport->port_id);

		xchg->io_state &= ~INI_IO_STATE_UPABORT;

		return UNF_SCSI_ABORT_FAIL;
	}

	scsi_image_table = &unf_lport->rport_scsi_table;
	scsi_id = scsi_cmnd->scsi_id;

	/* If pcie linkdown, complete this io and flush all io */
	if (unlikely(unf_lport->pcie_link_down)) {
		return_value = DID_RESET;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, return_value);
		unf_complete_cmnd(scsi_cmnd, DID_RESET << UNF_SHIFT_16);
		unf_free_lport_all_xchg(lport);
		return UNF_SCSI_ABORT_SUCCESS;
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_KEVENT,
		     "[abort]Port(0x%x) Exchg(0x%p) delay(%llu) SID(0x%x) DID(0x%x) wwpn(0x%llx) hottag(0x%x) scsi_id(0x%x) lun_id(0x%x) cmdsn(0x%llx) Ini:%p",
		     unf_lport->port_id, xchg,
		     (u64)jiffies_to_msecs(jiffies) - (u64)jiffies_to_msecs(xchg->alloc_jif),
		     xchg->sid, xchg->did, unf_rport->port_name, xchg->hotpooltag,
		     scsi_cmnd->scsi_id, (u32)scsi_cmnd->raw_lun_id, scsi_cmnd->cmnd_sn,
		     scsi_cmnd->pinitiator);

	/* Init abts marker semaphore */
	sema_init(&xchg->task_sema, 0);

	if (xchg->scsi_cmnd_info.time_out != 0)
		unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer(xchg);

	lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg, (ulong)UNF_WAIT_ABTS_RSP_TIMEOUT,
	    UNF_TIMER_TYPE_INI_ABTS);

	/* 4. Send INI ABTS CMND */
	if (unf_send_abts(unf_lport, xchg) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) Send ABTS failed. Exch(0x%p) hottag(0x%x)",
			     unf_lport->port_id, xchg, xchg->hotpooltag);

		lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

		spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
		xchg->io_state &= ~INI_IO_STATE_UPABORT;
		xchg->io_state |= INI_IO_STATE_TMF_ABORT;

		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

		return UNF_SCSI_ABORT_FAIL;
	}

	return unf_send_abts_success(unf_lport, xchg, scsi_cmnd, time_out_value);
}

static void unf_flush_ini_resp_que(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	if (lport->low_level_func.service_op.unf_flush_ini_resp_que)
		(void)lport->low_level_func.service_op.unf_flush_ini_resp_que(lport->fc_port);
}

int unf_cm_eh_abort_handler(struct unf_scsi_cmnd *scsi_cmnd)
{
	/*
	 * SCSI ABORT Command --->>> FC ABTS Command
	 * If return ABORT_FAIL, then enter TMF process
	 */
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_lport *xchg_lport = NULL;
	int ret = UNF_SCSI_ABORT_SUCCESS;
	ulong flag = 0;

	/* 1. Get L_Port: Point to Scsi_host */
	unf_lport = unf_find_lport_by_scsi_cmd(scsi_cmnd);
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Can't find port by scsi host id(0x%x)",
			     UNF_GET_SCSI_HOST_ID_BY_CMND(scsi_cmnd));
		return UNF_SCSI_ABORT_FAIL;
	}

	/* 2. find target Xchg for INI Abort CMND */
	unf_xchg = unf_cm_lookup_xchg_by_cmnd_sn(unf_lport, scsi_cmnd->cmnd_sn,
						 scsi_cmnd->world_id,
						 scsi_cmnd->pinitiator);
	if (unlikely(!unf_xchg)) {
		FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_WARN,
			     "[warn]Port(0x%x) can't find exchange by Cmdsn(0x%lx),Ini:%p",
			     unf_lport->port_id, (ulong)scsi_cmnd->cmnd_sn,
			     scsi_cmnd->pinitiator);

		unf_flush_ini_resp_que(unf_lport);

		return UNF_SCSI_ABORT_SUCCESS;
	}

	/* 3. increase ref_cnt to protect exchange */
	ret = (int)unf_xchg_ref_inc(unf_xchg, INI_EH_ABORT);
	if (unlikely(ret != RETURN_OK)) {
		unf_flush_ini_resp_que(unf_lport);

		return UNF_SCSI_ABORT_SUCCESS;
	}

	scsi_cmnd->upper_cmnd = unf_xchg->scsi_cmnd_info.scsi_cmnd;
	unf_xchg->debug_hook = true;

	/* 4. Exchang L_Port/R_Port Get & check */
	spin_lock_irqsave(&unf_xchg->xchg_state_lock, flag);
	xchg_lport = unf_xchg->lport;
	unf_rport = unf_xchg->rport;
	spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flag);

	if (unlikely(!xchg_lport || !unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Exchange(0x%p)'s L_Port or R_Port is NULL, state(0x%x)",
			     unf_xchg, unf_xchg->io_state);

		unf_xchg_ref_dec(unf_xchg, INI_EH_ABORT);

		if (!xchg_lport)
			/* for L_Port */
			return UNF_SCSI_ABORT_FAIL;
		/* for R_Port */
		return UNF_SCSI_ABORT_SUCCESS;
	}

	/* 5. Send INI Abort Cmnd */
	ret = unf_ini_abort_cmnd(xchg_lport, unf_xchg, scsi_cmnd);

	/* 6. decrease exchange ref_cnt */
	unf_xchg_ref_dec(unf_xchg, INI_EH_ABORT);

	return ret;
}

u32 unf_tmf_timeout_recovery_default(void *rport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_rport *unf_rport = (struct unf_rport *)rport;

	unf_lport = unf_xchg->lport;
	FC_CHECK_RETURN_VALUE(unf_lport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	unf_rport_enter_logo(unf_lport, unf_rport);

	return RETURN_OK;
}

void unf_abts_timeout_recovery_default(void *rport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;
	ulong flags = 0;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_rport *unf_rport = (struct unf_rport *)rport;

	unf_lport = unf_xchg->lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	spin_lock_irqsave(&unf_xchg->xchg_state_lock, flags);
	if (INI_IO_STATE_DONE & unf_xchg->io_state) {
		spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flags);

		return;
	}
	spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flags);

	if (unf_xchg->rport_bind_jifs != unf_rport->rport_alloc_jifs)
		return;

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	unf_rport_enter_logo(unf_lport, unf_rport);
}

u32 unf_tmf_timeout_recovery_special(void *rport, void *xchg)
{
	/* Do port reset or R_Port LOGO */
	int ret = UNF_RETURN_ERROR;
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = (struct unf_xchg *)xchg;
	struct unf_rport *unf_rport = (struct unf_rport *)rport;

	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(unf_xchg->lport, UNF_RETURN_ERROR);

	unf_lport = unf_xchg->lport->root_lport;
	FC_CHECK_RETURN_VALUE(unf_lport, UNF_RETURN_ERROR);

	/* 1. TMF response timeout & Marker STS timeout */
	if (!(unf_xchg->tmf_state &
	      (MARKER_STS_RECEIVED | TMF_RESPONSE_RECEIVED))) {
		/* TMF timeout & marker timeout */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) receive marker status timeout and do recovery",
			     unf_lport->port_id);

		/* Do port reset */
		ret = unf_cm_reset_port(unf_lport->port_id);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) do reset failed",
				     unf_lport->port_id);

			return UNF_RETURN_ERROR;
		}

		return RETURN_OK;
	}

	/* 2. default case: Do LOGO process */
	unf_tmf_timeout_recovery_default(unf_rport, unf_xchg);

	return RETURN_OK;
}

void unf_tmf_abnormal_recovery(struct unf_lport *lport, struct unf_rport *rport,
			       struct unf_xchg *xchg)
{
	/*
	 * for device(lun)/target(session) reset:
	 * Do port reset or R_Port LOGO
	 */
	if (lport->unf_tmf_abnormal_recovery)
		lport->unf_tmf_abnormal_recovery((void *)rport, (void *)xchg);
}

int unf_cm_eh_device_reset_handler(struct unf_scsi_cmnd *scsi_cmnd)
{
	/* SCSI Device/LUN Reset Command --->>> FC LUN/Device Reset Command */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	u32 cmnd_result = 0;
	int ret = SUCCESS;

	FC_CHECK_RETURN_VALUE(scsi_cmnd, FAILED);
	FC_CHECK_RETURN_VALUE(scsi_cmnd->lun_id, FAILED);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[event]Enter device/LUN reset handler");

	/* 1. Get L_Port */
	unf_lport = unf_find_lport_by_scsi_cmd(scsi_cmnd);
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Can't find port by scsi_host_id(0x%x)",
			     UNF_GET_SCSI_HOST_ID_BY_CMND(scsi_cmnd));

		return FAILED;
	}

	/* 2. L_Port State checking */
	if (unlikely(unf_lport->port_removing)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%p) is removing", unf_lport);

		return FAILED;
	}

	/*
	 * 3. Get R_Port: no rport is found or rport is not ready,return ok
	 * from: L_Port -->> rport_scsi_table (image table) -->>
	 * rport_info_table
	 */
	unf_rport = unf_find_rport_by_scsi_id(unf_lport, scsi_cmnd->err_code_table,
					      scsi_cmnd->err_code_table_cout,
					      UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd), &cmnd_result);
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) Can't find rport by scsi_id(0x%x)",
			     unf_lport->port_id, UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd));

		return SUCCESS;
	}

	/*
	 * 4. Set the I/O of the corresponding LUN to abort.
	 * *
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	unf_cm_xchg_abort_by_lun(unf_lport, unf_rport, *((u64 *)scsi_cmnd->lun_id), NULL, false);

	/* 5. R_Port state check */
	if (unlikely(unf_rport->rp_state != UNF_RPORT_ST_READY)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) state(0x%x) SCSI Command(0x%p), rport is not ready",
			     unf_lport->port_id, unf_rport->nport_id,
			     unf_rport->rp_state, scsi_cmnd);

		return SUCCESS;
	}

	/* 6. Get & inc ref_cnt free Xchg for Device reset */
	unf_xchg = (struct unf_xchg *)unf_cm_get_free_xchg(unf_lport, UNF_XCHG_TYPE_INI);
	if (unlikely(!unf_xchg)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%p) can't get free exchange", unf_lport);

		return FAILED;
	}

	/* increase ref_cnt for protecting exchange */
	ret = (int)unf_xchg_ref_inc(unf_xchg, INI_EH_DEVICE_RESET);
	FC_CHECK_RETURN_VALUE((ret == RETURN_OK), FAILED);

	/* 7. Send Device/LUN Reset to Low level */
	ret = unf_send_scsi_mgmt_cmnd(unf_xchg, unf_lport, unf_rport, scsi_cmnd,
				      UNF_FCP_TM_LOGICAL_UNIT_RESET);
	if (unlikely(ret == FAILED)) {
		/*
		 * Do port reset or R_Port LOGO:
		 * 1. FAILED: send failed
		 * 2. FAILED: semaphore timeout
		 * 3. SUCCESS: rcvd rsp & semaphore has been waken up
		 */
		unf_tmf_abnormal_recovery(unf_lport, unf_rport, unf_xchg);
	}

	/*
	 * 8. Release resource immediately if necessary
	 * NOTE: here, semaphore timeout or rcvd rsp(semaphore has been waken
	 * up)
	 */
	if (likely(!unf_lport->port_removing || unf_lport->root_lport != unf_lport))
		unf_cm_free_xchg(unf_xchg->lport, unf_xchg);

	/* decrease ref_cnt */
	unf_xchg_ref_dec(unf_xchg, INI_EH_DEVICE_RESET);

	return SUCCESS;
}

int unf_cm_target_reset_handler(struct unf_scsi_cmnd *scsi_cmnd)
{
	/* SCSI Target Reset Command --->>> FC Session Reset/Delete Command */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	u32 cmnd_result = 0;
	int ret = SUCCESS;

	FC_CHECK_RETURN_VALUE(scsi_cmnd, FAILED);
	FC_CHECK_RETURN_VALUE(scsi_cmnd->lun_id, FAILED);

	/* 1. Get L_Port */
	unf_lport = unf_find_lport_by_scsi_cmd(scsi_cmnd);
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Can't find port by scsi_host_id(0x%x)",
			     UNF_GET_SCSI_HOST_ID_BY_CMND(scsi_cmnd));

		return FAILED;
	}

	/* 2. L_Port State check */
	if (unlikely(unf_lport->port_removing)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%p) is removing", unf_lport);

		return FAILED;
	}

	/*
	 * 3. Get R_Port: no rport is found or rport is not ready,return ok
	 * from: L_Port -->> rport_scsi_table (image table) -->>
	 * rport_info_table
	 */
	unf_rport = unf_find_rport_by_scsi_id(unf_lport, scsi_cmnd->err_code_table,
					      scsi_cmnd->err_code_table_cout,
					      UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd), &cmnd_result);
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Can't find rport by scsi_id(0x%x)",
			     UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd));

		return SUCCESS;
	}

	/*
	 * 4. set UP_ABORT on Target IO and Session IO
	 * *
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	unf_cm_xchg_abort_by_session(unf_lport, unf_rport);

	/* 5. R_Port state check */
	if (unlikely(unf_rport->rp_state != UNF_RPORT_ST_READY)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) state(0x%x) is not ready, SCSI Command(0x%p)",
			     unf_lport->port_id, unf_rport->nport_id,
			     unf_rport->rp_state, scsi_cmnd);

		return SUCCESS;
	}

	/* 6. Get free Xchg for Target Reset CMND */
	unf_xchg = (struct unf_xchg *)unf_cm_get_free_xchg(unf_lport, UNF_XCHG_TYPE_INI);
	if (unlikely(!unf_xchg)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%p) can't get free exchange", unf_lport);

		return FAILED;
	}

	/* increase ref_cnt to protect exchange */
	ret = (int)unf_xchg_ref_inc(unf_xchg, INI_EH_DEVICE_RESET);
	FC_CHECK_RETURN_VALUE((ret == RETURN_OK), FAILED);

	/* 7. Send Target Reset Cmnd to low-level */
	ret = unf_send_scsi_mgmt_cmnd(unf_xchg, unf_lport, unf_rport, scsi_cmnd,
				      UNF_FCP_TM_TARGET_RESET);
	if (unlikely(ret == FAILED)) {
		/*
		 * Do port reset or R_Port LOGO:
		 * 1. FAILED: send failed
		 * 2. FAILED: semaphore timeout
		 * 3. SUCCESS: rcvd rsp & semaphore has been waken up
		 */
		unf_tmf_abnormal_recovery(unf_lport, unf_rport, unf_xchg);
	}

	/*
	 * 8. Release resource immediately if necessary
	 * NOTE: here, semaphore timeout or rcvd rsp(semaphore has been waken
	 * up)
	 */
	if (likely(!unf_lport->port_removing || unf_lport->root_lport != unf_lport))
		unf_cm_free_xchg(unf_xchg->lport, unf_xchg);

	/* decrease exchange ref_cnt */
	unf_xchg_ref_dec(unf_xchg, INI_EH_DEVICE_RESET);

	return SUCCESS;
}

int unf_cm_bus_reset_handler(struct unf_scsi_cmnd *scsi_cmnd)
{
	/* SCSI BUS Reset Command --->>> FC Port Reset Command */
	struct unf_lport *unf_lport = NULL;
	int cmnd_result = 0;

	/* 1. Get L_Port */
	unf_lport = unf_find_lport_by_scsi_cmd(scsi_cmnd);
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Can't find port by scsi_host_id(0x%x)",
			     UNF_GET_SCSI_HOST_ID_BY_CMND(scsi_cmnd));

		return FAILED;
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_KEVENT,
		     "[event]Do port reset with scsi_bus_reset");

	cmnd_result = unf_cm_reset_port(unf_lport->port_id);
	if (unlikely(cmnd_result == UNF_RETURN_ERROR))
		return FAILED;
	else
		return SUCCESS;
}

void unf_process_scsi_mgmt_result(struct unf_frame_pkg *pkg,
				  struct unf_xchg *xchg)
{
	u8 *rsp_info = NULL;
	u8 rsp_code = 0;
	u32 code_index = 0;

	/*
	 * LLT found that:RSP_CODE is the third byte of
	 * FCP_RSP_INFO, on Little endian should be byte 0, For
	 * detail FCP_4 Table 26  FCP_RSP_INFO field format
	 * *
	 * 1. state setting
	 * 2. wake up semaphore
	 */
	FC_CHECK_RETURN_VOID(pkg);
	FC_CHECK_RETURN_VOID(xchg);

	xchg->tmf_state |= TMF_RESPONSE_RECEIVED;

	if (UNF_GET_LL_ERR(pkg) != UNF_IO_SUCCESS ||
	    pkg->unf_rsp_pload_bl.length > UNF_RESPONE_DATA_LEN) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Send scsi manage command failed with error code(0x%x) resp len(0x%x)",
			     UNF_GET_LL_ERR(pkg), pkg->unf_rsp_pload_bl.length);

		xchg->scsi_cmnd_info.result = UNF_IO_FAILED;

		/* wakeup semaphore & return */
		up(&xchg->task_sema);

		return;
	}

	rsp_info = pkg->unf_rsp_pload_bl.buffer_ptr;
	if (rsp_info && pkg->unf_rsp_pload_bl.length != 0) {
		/* change to little end if necessary */
		if (pkg->byte_orders & UNF_BIT_3)
			unf_big_end_to_cpu(rsp_info, pkg->unf_rsp_pload_bl.length);
	}

	if (!rsp_info) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]FCP response data pointer is NULL with Xchg TAG(0x%x)",
			     xchg->hotpooltag);

		xchg->scsi_cmnd_info.result = UNF_IO_SUCCESS;

		/* wakeup semaphore & return */
		up(&xchg->task_sema);

		return;
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[info]FCP response data length(0x%x), RSP_CODE(0x%x:%x:%x:%x:%x:%x:%x:%x)",
		     pkg->unf_rsp_pload_bl.length, rsp_info[ARRAY_INDEX_0],
		     rsp_info[ARRAY_INDEX_1], rsp_info[ARRAY_INDEX_2],
		     rsp_info[ARRAY_INDEX_3], rsp_info[ARRAY_INDEX_4],
		     rsp_info[ARRAY_INDEX_5], rsp_info[ARRAY_INDEX_6],
		     rsp_info[ARRAY_INDEX_7]);

	rsp_code = rsp_info[code_index];
	if (rsp_code == UNF_FCP_TM_RSP_COMPLETE || rsp_code == UNF_FCP_TM_RSP_SUCCEED)
		xchg->scsi_cmnd_info.result = UNF_IO_SUCCESS;
	else
		xchg->scsi_cmnd_info.result = UNF_IO_FAILED;

	/* wakeup semaphore & return */
	up(&xchg->task_sema);
}

static void unf_build_task_mgmt_fcp_cmnd(struct unf_fcp_cmnd *fcp_cmnd,
					 struct unf_scsi_cmnd *scsi_cmnd,
					 enum unf_task_mgmt_cmd task_mgmt)
{
	FC_CHECK_RETURN_VOID(fcp_cmnd);
	FC_CHECK_RETURN_VOID(scsi_cmnd);

	unf_big_end_to_cpu((void *)scsi_cmnd->lun_id, UNF_FCP_LUNID_LEN_8);
	(*(u64 *)(scsi_cmnd->lun_id)) >>= UNF_SHIFT_8;
	memcpy(fcp_cmnd->lun, scsi_cmnd->lun_id, sizeof(fcp_cmnd->lun));

	/*
	 * If the TASK MANAGEMENT FLAGS field is set to a nonzero value,
	 * the FCP_CDB field, the FCP_DL field, the TASK ATTRIBUTE field,
	 * the RDDATA bit, and the WRDATA bit shall be ignored and the
	 * FCP_BIDIRECTIONAL_READ_DL field shall not be included in the FCP_CMND
	 * IU payload
	 */
	fcp_cmnd->control = UNF_SET_TASK_MGMT_FLAGS((u32)(task_mgmt));

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "SCSI cmnd(0x%x) is task mgmt cmnd. ntrl Flag(LITTLE END) is 0x%x.",
		     task_mgmt, fcp_cmnd->control);
}

int unf_send_scsi_mgmt_cmnd(struct unf_xchg *xchg, struct unf_lport *lport,
			    struct unf_rport *rport,
			    struct unf_scsi_cmnd *scsi_cmnd,
			    enum unf_task_mgmt_cmd task_mgnt_cmd_type)
{
	/*
	 * 1. Device/LUN reset
	 * 2. Target/Session reset
	 */
	struct unf_xchg *unf_xchg = NULL;
	int ret = SUCCESS;
	struct unf_frame_pkg pkg = {0};
	ulong xchg_flag = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, FAILED);
	FC_CHECK_RETURN_VALUE(rport, FAILED);
	FC_CHECK_RETURN_VALUE(xchg, FAILED);
	FC_CHECK_RETURN_VALUE(scsi_cmnd, FAILED);
	FC_CHECK_RETURN_VALUE(task_mgnt_cmd_type <= UNF_FCP_TM_TERMINATE_TASK &&
			      task_mgnt_cmd_type >= UNF_FCP_TM_QUERY_TASK_SET, FAILED);

	unf_xchg = xchg;
	unf_xchg->lport = lport;
	unf_xchg->rport = rport;

	/* 1. State: Up_Task */
	spin_lock_irqsave(&unf_xchg->xchg_state_lock, xchg_flag);
	unf_xchg->io_state |= INI_IO_STATE_UPTASK;
	spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, xchg_flag);
	pkg.frame_head.oxid_rxid = ((u32)unf_xchg->oxid << (u32)UNF_SHIFT_16) | unf_xchg->rxid;

	/* 2. Set TASK MANAGEMENT FLAGS of FCP_CMND to the corresponding task
	 * management command
	 */
	unf_build_task_mgmt_fcp_cmnd(&unf_xchg->fcp_cmnd, scsi_cmnd, task_mgnt_cmd_type);

	pkg.xchg_contex = unf_xchg;
	pkg.private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = rport->rport_index;
	pkg.fcp_cmnd = &unf_xchg->fcp_cmnd;
	pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = unf_xchg->hotpooltag | UNF_HOTTAG_FLAG;
	pkg.frame_head.csctl_sid = lport->nport_id;
	pkg.frame_head.rctl_did = rport->nport_id;

	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];

	if (unlikely(lport->pcie_link_down)) {
		unf_free_lport_all_xchg(lport);
		return SUCCESS;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) Hottag(0x%x) lunid(0x%llx)",
		     lport->port_id, task_mgnt_cmd_type, rport->nport_id,
		     unf_xchg->hotpooltag, *((u64 *)scsi_cmnd->lun_id));

	/* 3. Init exchange task semaphore */
	sema_init(&unf_xchg->task_sema, 0);

	/* 4. Send Mgmt Task to low-level */
	if (unf_hardware_start_io(lport, &pkg) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) failed",
			     lport->port_id, task_mgnt_cmd_type, rport->nport_id);

		return FAILED;
	}

	/*
	 * semaphore timeout
	 **
	 * Code review: The second input parameter needs to be converted to
	 jiffies.
	 * set semaphore after the message is sent successfully.The semaphore is
	 returned when the semaphore times out or is woken up.
	 **
	 * 5. The semaphore is cleared and counted when the Mgmt Task message is
	 sent, and is Wake Up when the RSP message is received.
	 *  If the semaphore is not Wake Up, the semaphore is triggered after
	 timeout. That is, no RSP message is received within the timeout period.
	 */
	if (down_timeout(&unf_xchg->task_sema, (s64)msecs_to_jiffies((u32)UNF_WAIT_SEM_TIMEOUT))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) timeout scsi id(0x%x) lun id(0x%x)",
			     lport->nport_id, task_mgnt_cmd_type,
			     rport->nport_id, scsi_cmnd->scsi_id,
			     (u32)scsi_cmnd->raw_lun_id);
		unf_notify_chip_free_xid(unf_xchg);
		/* semaphore timeout */
		ret = FAILED;
		spin_lock_irqsave(&lport->lport_state_lock, flag);
		if (lport->states == UNF_LPORT_ST_RESET)
			ret = SUCCESS;
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		return ret;
	}

	/*
	 * 6. NOTE: no timeout (has been waken up)
	 * Do Scsi_Cmnd(Mgmt Task) result checking
	 * *
	 * FAILED: with error code or RSP is error
	 * SUCCESS: others
	 */
	if (unf_xchg->scsi_cmnd_info.result == UNF_IO_SUCCESS) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) and receive rsp succeed",
			     lport->nport_id, task_mgnt_cmd_type, rport->nport_id);

		ret = SUCCESS;
	} else {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send task_cmnd(0x%x) to RPort(0x%x) and receive rsp failed scsi id(0x%x) lun id(0x%x)",
			     lport->nport_id, task_mgnt_cmd_type, rport->nport_id,
			     scsi_cmnd->scsi_id, (u32)scsi_cmnd->raw_lun_id);

		ret = FAILED;
	}

	return ret;
}

u32 unf_recv_tmf_marker_status(void *lport, struct unf_frame_pkg *pkg)
{
	struct unf_lport *unf_lport = NULL;
	u32 uret = RETURN_OK;
	struct unf_xchg *unf_xchg = NULL;
	u16 hot_pool_tag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	unf_lport = (struct unf_lport *)lport;

	/* Find exchange which point to marker sts */
	if (!unf_lport->xchg_mgr_temp.unf_look_up_xchg_by_tag) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) tag function is NULL", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag =
	    (u16)(pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);

	unf_xchg =
	    (struct unf_xchg *)(unf_lport->xchg_mgr_temp
				    .unf_look_up_xchg_by_tag((void *)unf_lport, hot_pool_tag));
	if (!unf_xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) find exchange by tag(0x%x) failed",
			     unf_lport->port_id, unf_lport->nport_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	/*
	 * NOTE: set exchange TMF state with MARKER_STS_RECEIVED
	 * *
	 * About TMF state
	 * 1. STS received
	 * 2. Response received
	 * 3. Do check if necessary
	 */
	unf_xchg->tmf_state |= MARKER_STS_RECEIVED;

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[info]Marker STS: D_ID(0x%x) S_ID(0x%x) OX_ID(0x%x) RX_ID(0x%x), EXCH: D_ID(0x%x) S_ID(0x%x) OX_ID(0x%x) RX_ID(0x%x)",
		     pkg->frame_head.rctl_did & UNF_NPORTID_MASK,
		     pkg->frame_head.csctl_sid & UNF_NPORTID_MASK,
		     (u16)(pkg->frame_head.oxid_rxid >> UNF_SHIFT_16),
		     (u16)(pkg->frame_head.oxid_rxid), unf_xchg->did, unf_xchg->sid,
		     unf_xchg->oxid, unf_xchg->rxid);

	return uret;
}

u32 unf_recv_abts_marker_status(void *lport, struct unf_frame_pkg *pkg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	u16 hot_pool_tag = 0;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	unf_lport = (struct unf_lport *)lport;

	/* Find exchange by tag */
	if (!unf_lport->xchg_mgr_temp.unf_look_up_xchg_by_tag) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) tag function is NULL", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	hot_pool_tag = (u16)(pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX]);

	unf_xchg =
	(struct unf_xchg *)(unf_lport->xchg_mgr_temp.unf_look_up_xchg_by_tag((void *)unf_lport,
										 hot_pool_tag));
	if (!unf_xchg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) find exchange by tag(0x%x) failed",
			     unf_lport->port_id, unf_lport->nport_id, hot_pool_tag);

		return UNF_RETURN_ERROR;
	}

	/*
	 * NOTE: set exchange ABTS state with MARKER_STS_RECEIVED
	 * *
	 * About exchange ABTS state
	 * 1. STS received
	 * 2. Response received
	 * 3. Do check if necessary
	 * *
	 * About Exchange status get from low level
	 * 1. Set: when RCVD ABTS Marker
	 * 2. Set: when RCVD ABTS Req Done
	 * 3. value: set value with pkg->status
	 */
	spin_lock_irqsave(&unf_xchg->xchg_state_lock, flags);
	unf_xchg->ucode_abts_state = pkg->status;
	unf_xchg->abts_state |= MARKER_STS_RECEIVED;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[info]Port(0x%x) wake up SEMA for Abts marker exchange(0x%p) oxid(0x%x 0x%x) hottag(0x%x) status(0x%x)",
		     unf_lport->port_id, unf_xchg, unf_xchg->oxid, unf_xchg->rxid,
		     unf_xchg->hotpooltag, pkg->abts_maker_status);

	/*
	 * NOTE: Second time for ABTS marker received, or
	 * ABTS response have been received, no need to wake up sema
	 */
	if ((INI_IO_STATE_ABORT_TIMEOUT & unf_xchg->io_state) ||
	    (ABTS_RESPONSE_RECEIVED & unf_xchg->abts_state)) {
		spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[info]Port(0x%x) no need to wake up SEMA for Abts marker ABTS_STATE(0x%x) IO_STATE(0x%x)",
			     unf_lport->port_id, unf_xchg->abts_state, unf_xchg->io_state);

		return RETURN_OK;
	}

	if (unf_xchg->io_state & INI_IO_STATE_TMF_ABORT) {
		spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flags);
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[info]Port(0x%x) receive Abts marker, exchange(%p) state(0x%x) free it",
			     unf_lport->port_id, unf_xchg, unf_xchg->io_state);

		unf_cm_free_xchg(unf_lport, unf_xchg);
	} else {
		spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flags);
		up(&unf_xchg->task_sema);
	}

	return RETURN_OK;
}
