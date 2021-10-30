// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_exchg_abort.h"
#include "unf_log.h"
#include "unf_common.h"
#include "unf_rport.h"
#include "unf_service.h"
#include "unf_ls.h"
#include "unf_io.h"

void unf_cm_xchg_mgr_abort_io_by_id(struct unf_lport *lport, struct unf_rport *rport, u32 sid,
				    u32 did, u32 extra_io_state)
{
	/*
	 * for target session: set ABORT
	 * 1. R_Port remove
	 * 2. Send PLOGI_ACC callback
	 * 3. RCVD PLOGI
	 * 4. RCVD LOGO
	 */
	FC_CHECK_RETURN_VOID(lport);

	if (lport->xchg_mgr_temp.unf_xchg_mgr_io_xchg_abort) {
		/* The SID/DID of the Xchg is in reverse direction in different
		 * phases. Therefore, the reverse direction needs to be
		 * considered
		 */
		lport->xchg_mgr_temp.unf_xchg_mgr_io_xchg_abort(lport, rport, sid, did,
								    extra_io_state);
		lport->xchg_mgr_temp.unf_xchg_mgr_io_xchg_abort(lport, rport, did, sid,
								    extra_io_state);
	}
}

void unf_cm_xchg_mgr_abort_sfs_by_id(struct unf_lport *lport,
				     struct unf_rport *rport, u32 sid, u32 did)
{
	FC_CHECK_RETURN_VOID(lport);

	if (lport->xchg_mgr_temp.unf_xchg_mgr_sfs_xchg_abort) {
		/* The SID/DID of the Xchg is in reverse direction in different
		 * phases, therefore, the reverse direction needs to be
		 * considered
		 */
		lport->xchg_mgr_temp.unf_xchg_mgr_sfs_xchg_abort(lport, rport, sid, did);
		lport->xchg_mgr_temp.unf_xchg_mgr_sfs_xchg_abort(lport, rport, did, sid);
	}
}

void unf_cm_xchg_abort_by_lun(struct unf_lport *lport, struct unf_rport *rport,
			      u64 lun_id, void *xchg, bool abort_all_lun_flag)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	void (*unf_xchg_abort_by_lun)(void *, void *, u64, void *, bool) = NULL;

	FC_CHECK_RETURN_VOID(lport);

	unf_xchg_abort_by_lun = lport->xchg_mgr_temp.unf_xchg_abort_by_lun;
	if (unf_xchg_abort_by_lun)
		unf_xchg_abort_by_lun((void *)lport, (void *)rport, lun_id,
				      xchg, abort_all_lun_flag);
}

void unf_cm_xchg_abort_by_session(struct unf_lport *lport, struct unf_rport *rport)
{
	void (*unf_xchg_abort_by_session)(void *, void *) = NULL;

	FC_CHECK_RETURN_VOID(lport);

	unf_xchg_abort_by_session = lport->xchg_mgr_temp.unf_xchg_abort_by_session;
	if (unf_xchg_abort_by_session)
		unf_xchg_abort_by_session((void *)lport, (void *)rport);
}

static void unf_xchg_abort_all_sfs_xchg(struct unf_lport *lport, bool clean)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong pool_lock_falgs = 0;
	ulong xchg_lock_flags = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VOID(lport);
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT,
				     UNF_MAJOR, "Port(0x%x) Hot Pool is NULL.", lport->port_id);

			continue;
		}

		if (!clean) {
			spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);

			/* Clearing the SFS_Busy_list Exchange Resource */
			list_for_each_safe(xchg_node, next_xchg_node, &hot_pool->sfs_busylist) {
				xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);
				spin_lock_irqsave(&xchg->xchg_state_lock, xchg_lock_flags);
				if (atomic_read(&xchg->ref_cnt) > 0)
					xchg->io_state |= TGT_IO_STATE_ABORT;

				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_lock_flags);
			}

			spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);
		} else {
			continue;
		}
	}
}

static void unf_xchg_abort_ini_io_xchg(struct unf_lport *lport, bool clean)
{
	/* Clean L_Port/V_Port Link Down I/O: Abort */
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong pool_lock_falgs = 0;
	ulong xchg_lock_flags = 0;
	u32 io_state = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VOID(lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) hot pool is NULL",
				     lport->port_id);

			continue;
		}

		if (!clean) {
			spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);

			/* 1. Abort INI_Busy_List IO */
			list_for_each_safe(xchg_node, next_xchg_node, &hot_pool->ini_busylist) {
				xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);
				spin_lock_irqsave(&xchg->xchg_state_lock, xchg_lock_flags);
				if (atomic_read(&xchg->ref_cnt) > 0)
					xchg->io_state |= INI_IO_STATE_DRABORT | io_state;
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_lock_flags);
			}

			spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);
		} else {
			/* Do nothing, just return */
			continue;
		}
	}
}

void unf_xchg_abort_all_xchg(void *lport, u32 xchg_type, bool clean)
{
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(lport);
	unf_lport = (struct unf_lport *)lport;

	switch (xchg_type) {
	case UNF_XCHG_TYPE_SFS:
		unf_xchg_abort_all_sfs_xchg(unf_lport, clean);
		break;
	/* Clean L_Port/V_Port Link Down I/O: Abort */
	case UNF_XCHG_TYPE_INI:
		unf_xchg_abort_ini_io_xchg(unf_lport, clean);
		break;
	default:
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) unknown exch type(0x%x)",
			     unf_lport->port_id, xchg_type);
		break;
	}
}

static void unf_xchg_abort_ini_send_tm_cmd(void *lport, void *rport, u64 lun_id)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong flags = 0;
	ulong xchg_flag = 0;
	u32 i = 0;
	u64 raw_lun_id = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);
	unf_rport = (struct unf_rport *)rport;

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Port(0x%x) hot pool is NULL",
				     unf_lport->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);

		/* 1. for each exchange from busy list */
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);

			raw_lun_id = *(u64 *)(xchg->fcp_cmnd.lun) >> UNF_SHIFT_16 &
				     UNF_RAW_LUN_ID_MASK;
			if (lun_id == raw_lun_id && unf_rport == xchg->rport) {
				spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
				xchg->io_state |= INI_IO_STATE_TMF_ABORT;
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

				FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
					     "[info]Exchange(%p) state(0x%x) S_ID(0x%x) D_ID(0x%x) tag(0x%x) abort by TMF CMD",
					     xchg, xchg->io_state,
					     ((struct unf_lport *)lport)->nport_id,
					     unf_rport->nport_id, xchg->hotpooltag);
			}
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
	}
}

static void unf_xchg_abort_ini_tmf_target_reset(void *lport, void *rport)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong flags = 0;
	ulong xchg_flag = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);
	unf_rport = (struct unf_rport *)rport;

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Port(0x%x) hot pool is NULL",
				     unf_lport->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);

		/* 1. for each exchange from busy_list */
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);
			if (unf_rport == xchg->rport) {
				spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
				xchg->io_state |= INI_IO_STATE_TMF_ABORT;
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);

				FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
					     "[info]Exchange(%p) state(0x%x) S_ID(0x%x) D_ID(0x%x) tag(0x%x) abort by TMF CMD",
					     xchg, xchg->io_state, unf_lport->nport_id,
					     unf_rport->nport_id, xchg->hotpooltag);
			}
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
	}
}

void unf_xchg_abort_by_lun(void *lport, void *rport, u64 lun_id, void *xchg,
			   bool abort_all_lun_flag)
{
	/* ABORT: set UP_ABORT tag for target LUN I/O */
	struct unf_xchg *tm_xchg = (struct unf_xchg *)xchg;

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[event]Port(0x%x) LUN_ID(0x%llx) TM_EXCH(0x%p) flag(%d)",
		     ((struct unf_lport *)lport)->port_id, lun_id, xchg,
		     abort_all_lun_flag);

	/* for INI Mode */
	if (!tm_xchg) {
		/*
		 * LUN Reset: set UP_ABORT tag, with:
		 * INI_Busy_list, IO_Wait_list,
		 * IO_Delay_list, IO_Delay_transfer_list
		 */
		unf_xchg_abort_ini_send_tm_cmd(lport, rport, lun_id);

		return;
	}
}

void unf_xchg_abort_by_session(void *lport, void *rport)
{
	/*
	 * LUN Reset: set UP_ABORT tag, with:
	 * INI_Busy_list, IO_Wait_list,
	 * IO_Delay_list, IO_Delay_transfer_list
	 */
	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "[event]Port(0x%x) Rport(0x%x) start session reset with TMF",
		     ((struct unf_lport *)lport)->port_id, ((struct unf_rport *)rport)->nport_id);

	unf_xchg_abort_ini_tmf_target_reset(lport, rport);
}

void unf_xchg_up_abort_io_by_scsi_id(void *lport, u32 scsi_id)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong flags = 0;
	ulong xchg_flag = 0;
	u32 i;
	u32 io_abort_flag = INI_IO_STATE_UPABORT | INI_IO_STATE_UPSEND_ERR |
			    INI_IO_STATE_TMF_ABORT;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Port(0x%x) hot pool is NULL",
				     unf_lport->port_id);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);

		/* 1. for each exchange from busy_list */
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);
			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
			if (lport == xchg->lport && scsi_id == xchg->scsi_id &&
			    !(xchg->io_state & io_abort_flag)) {
				xchg->io_state |= INI_IO_STATE_UPABORT;
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);
				FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
					     "[info]Exchange(%p) scsi_cmd(0x%p) state(0x%x) scsi_id(0x%x) tag(0x%x) upabort by scsi id",
					     xchg, xchg->scsi_cmnd_info.scsi_cmnd,
					     xchg->io_state, scsi_id, xchg->hotpooltag);
			} else {
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);
			}
		}
		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
	}
}

static void unf_ini_busy_io_xchg_abort(void *xchg_hot_pool, void *rport,
				       u32 sid, u32 did, u32 extra_io_state)
{
	/*
	 * for target session: Set (DRV) ABORT
	 * 1. R_Port remove
	 * 2. Send PLOGI_ACC callback
	 * 3. RCVD PLOGI
	 * 4. RCVD LOGO
	 */
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct unf_xchg *xchg = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong xchg_lock_flags = 0;

	unf_rport = (struct unf_rport *)rport;
	hot_pool = (struct unf_xchg_hot_pool *)xchg_hot_pool;

	/* ABORT INI IO: INI_BUSY_LIST */
	list_for_each_safe(xchg_node, next_xchg_node, &hot_pool->ini_busylist) {
		xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);

		spin_lock_irqsave(&xchg->xchg_state_lock, xchg_lock_flags);
		if (did == xchg->did && sid == xchg->sid &&
		    unf_rport == xchg->rport &&
		    (atomic_read(&xchg->ref_cnt) > 0)) {
			xchg->scsi_cmnd_info.result = UNF_SCSI_HOST(DID_IMM_RETRY);
			xchg->io_state |= INI_IO_STATE_DRABORT;
			xchg->io_state |= extra_io_state;

			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[info]Abort INI:0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
				     xchg, (u32)xchg->hotpooltag, (u32)xchg->xchg_type,
				     (u32)xchg->oxid, (u32)xchg->rxid,
				     (u32)xchg->sid, (u32)xchg->did, (u32)xchg->io_state,
				     atomic_read(&xchg->ref_cnt), xchg->alloc_jif);
		}
		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_lock_flags);
	}
}

void unf_xchg_mgr_io_xchg_abort(void *lport, void *rport, u32 sid, u32 did, u32 extra_io_state)
{
	/*
	 * for target session: set ABORT
	 * 1. R_Port remove
	 * 2. Send PLOGI_ACC callback
	 * 3. RCVD PLOGI
	 * 4. RCVD LOGO
	 */
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong pool_lock_falgs = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VOID(lport);
	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) hot pool is NULL",
				     unf_lport->port_id);

			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);

		/* 1. Clear INI (session) IO: INI Mode */
		unf_ini_busy_io_xchg_abort(hot_pool, rport, sid, did, extra_io_state);

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);
	}
}

void unf_xchg_mgr_sfs_xchg_abort(void *lport, void *rport, u32 sid, u32 did)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	struct unf_xchg *xchg = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong pool_lock_falgs = 0;
	ulong xchg_lock_flags = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (!hot_pool) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT,
				     UNF_MAJOR, "Port(0x%x) Hot Pool is NULL.",
				     unf_lport->port_id);

			continue;
		}

		unf_rport = (struct unf_rport *)rport;

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);

		/* Clear the SFS exchange of the corresponding connection */
		list_for_each_safe(xchg_node, next_xchg_node, &hot_pool->sfs_busylist) {
			xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);

			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_lock_flags);
			if (did == xchg->did && sid == xchg->sid &&
			    unf_rport == xchg->rport && (atomic_read(&xchg->ref_cnt) > 0)) {
				xchg->io_state |= TGT_IO_STATE_ABORT;
				FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
					     "Abort SFS:0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
					     xchg, (u32)xchg->hotpooltag, (u32)xchg->xchg_type,
					     (u32)xchg->oxid, (u32)xchg->rxid, (u32)xchg->sid,
					     (u32)xchg->did, (u32)xchg->io_state,
					     atomic_read(&xchg->ref_cnt), xchg->alloc_jif);
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_lock_flags);
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_falgs);
	}
}

static void unf_fc_wait_abts_complete(struct unf_lport *lport, struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = lport;
	struct unf_scsi_cmnd scsi_cmnd = {0};
	ulong flag = 0;
	u32 time_out_value = 2000;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	u32 io_result;

	scsi_cmnd.scsi_id = xchg->scsi_cmnd_info.scsi_id;
	scsi_cmnd.upper_cmnd = xchg->scsi_cmnd_info.scsi_cmnd;
	scsi_cmnd.done = xchg->scsi_cmnd_info.done;
	scsi_image_table = &unf_lport->rport_scsi_table;

	if (down_timeout(&xchg->task_sema, (s64)msecs_to_jiffies(time_out_value))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) recv abts marker timeout,Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x)",
			     unf_lport->port_id, xchg, xchg->oxid, xchg->rxid);
		goto ABTS_FIAILED;
	}

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	if (xchg->ucode_abts_state == UNF_IO_SUCCESS ||
	    xchg->scsi_cmnd_info.result == UNF_IO_ABORT_PORT_REMOVING) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) Send ABTS succeed and recv marker Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) marker status(0x%x)",
			     unf_lport->port_id, xchg, xchg->oxid, xchg->rxid,
			     xchg->ucode_abts_state);
		io_result = DID_BUS_BUSY;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_cmnd.scsi_id, io_result);
		unf_complete_cmnd(&scsi_cmnd, io_result << UNF_SHIFT_16);
		return;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
		     "[warn]Port(0x%x) send ABTS failed. Exch(0x%p) hot_tag(0x%x) ret(0x%x) xchg->io_state (0x%x)",
		     unf_lport->port_id, xchg, xchg->hotpooltag,
		     xchg->scsi_cmnd_info.result, xchg->io_state);
	goto ABTS_FIAILED;

ABTS_FIAILED:
	unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);
	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	xchg->io_state &= ~INI_IO_STATE_UPABORT;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
}

void unf_fc_abort_time_out_cmnd(struct unf_lport *lport, struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = lport;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flag);
	if (xchg->io_state & INI_IO_STATE_UPABORT) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "LPort(0x%x) xchange(0x%p) OX_ID(0x%x), RX_ID(0x%x)  Cmdsn(0x%lx) has been aborted.",
			     unf_lport->port_id, xchg, xchg->oxid,
			     xchg->rxid, (ulong)xchg->cmnd_sn);
		return;
	}
	xchg->io_state |= INI_IO_STATE_UPABORT;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_KEVENT,
		     "LPort(0x%x) exchg(0x%p) OX_ID(0x%x) RX_ID(0x%x) Cmdsn(0x%lx) timeout abort it",
		     unf_lport->port_id, xchg, xchg->oxid, xchg->rxid, (ulong)xchg->cmnd_sn);

	unf_lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg,
			(ulong)UNF_WAIT_ABTS_RSP_TIMEOUT, UNF_TIMER_TYPE_INI_ABTS);

	sema_init(&xchg->task_sema, 0);

	if (unf_send_abts(unf_lport, xchg) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "LPort(0x%x) send ABTS, Send ABTS unsuccessful. Exchange OX_ID(0x%x), RX_ID(0x%x).",
			     unf_lport->port_id, xchg->oxid, xchg->rxid);
		unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);
		spin_lock_irqsave(&xchg->xchg_state_lock, flag);
		xchg->io_state &= ~INI_IO_STATE_UPABORT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flag);
		return;
	}
	unf_fc_wait_abts_complete(unf_lport, xchg);
}

static void unf_fc_ini_io_rec_wait_time_out(struct unf_lport *lport, struct unf_rport *rport,
					    struct unf_xchg *xchg)
{
	ulong time_out = 0;

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
		     "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) Rec timeout exchange OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
		     lport->port_id, rport->nport_id, xchg, xchg->oxid,
		     xchg->rxid, xchg->io_state);

	if (xchg->rport_bind_jifs == rport->rport_alloc_jifs) {
		unf_send_rec(lport, rport, xchg);

		if (xchg->scsi_cmnd_info.abort_time_out > 0) {
			time_out = (xchg->scsi_cmnd_info.abort_time_out > UNF_REC_TOV) ?
				   (xchg->scsi_cmnd_info.abort_time_out - UNF_REC_TOV) : 0;
			if (time_out > 0) {
				lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg, time_out,
				    UNF_TIMER_TYPE_REQ_IO);
			} else {
				unf_fc_abort_time_out_cmnd(lport, xchg);
			}
		}
	}
}

static void unf_fc_ini_send_abts_time_out(struct unf_lport *lport, struct unf_rport *rport,
					  struct unf_xchg *xchg)
{
	if (xchg->rport_bind_jifs == rport->rport_alloc_jifs &&
	    xchg->rport_bind_jifs != INVALID_VALUE64) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) first time to send abts timeout, retry again OX_ID(0x%x) RX_ID(0x%x) HotTag(0x%x) state(0x%x)",
			     lport->port_id, rport->nport_id, xchg, xchg->oxid,
			     xchg->rxid, xchg->hotpooltag, xchg->io_state);

		lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg,
				(ulong)UNF_WAIT_ABTS_RSP_TIMEOUT, UNF_TIMER_TYPE_INI_ABTS);

		if (unf_send_abts(lport, xchg) != RETURN_OK) {
			lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)xchg);

			unf_abts_timeout_recovery_default(rport, xchg);

			unf_cm_free_xchg(lport, xchg);
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) rport is invalid, exchg rport jiff(0x%llx 0x%llx), free exchange OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			     lport->port_id, rport->nport_id, xchg,
			     xchg->rport_bind_jifs, rport->rport_alloc_jifs,
			     xchg->oxid, xchg->rxid, xchg->io_state);

		unf_cm_free_xchg(lport, xchg);
	}
}

void unf_fc_ini_io_xchg_time_out(struct work_struct *work)
{
	struct unf_xchg *xchg = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 port_valid_flag = 0;

	xchg = container_of(work, struct unf_xchg, timeout_work.work);
	FC_CHECK_RETURN_VOID(xchg);

	ret = unf_xchg_ref_inc(xchg, INI_IO_TIMEOUT);
	FC_CHECK_RETURN_VOID(ret == RETURN_OK);

	unf_lport = xchg->lport;
	unf_rport = xchg->rport;

	port_valid_flag = (!unf_lport) || (!unf_rport);
	if (port_valid_flag) {
		unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);
		unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);
		return;
	}

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	/* 1. for Send RRQ failed Timer timeout */
	if (INI_IO_STATE_RRQSEND_ERR & xchg->io_state) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[info]LPort(0x%x) RPort(0x%x) Exch(0x%p) had wait enough time for RRQ send failed OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			     unf_lport->port_id, unf_rport->nport_id, xchg,
			     xchg->oxid, xchg->rxid, xchg->io_state);
		unf_notify_chip_free_xid(xchg);
		unf_cm_free_xchg(unf_lport, xchg);
	}
	/* Second ABTS timeout and enter LOGO process */
	else if ((INI_IO_STATE_ABORT_TIMEOUT & xchg->io_state) &&
		 (!(ABTS_RESPONSE_RECEIVED & xchg->abts_state))) {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) Exch(0x%p) had wait enough time for second abts send OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
			     unf_lport->port_id, unf_rport->nport_id, xchg,
			     xchg->oxid, xchg->rxid, xchg->io_state);
		unf_abts_timeout_recovery_default(unf_rport, xchg);
		unf_cm_free_xchg(unf_lport, xchg);
	}
	/* First time to send ABTS, timeout and retry to send ABTS again */
	else if ((INI_IO_STATE_UPABORT & xchg->io_state) &&
		 (!(ABTS_RESPONSE_RECEIVED & xchg->abts_state))) {
		xchg->io_state |= INI_IO_STATE_ABORT_TIMEOUT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_fc_ini_send_abts_time_out(unf_lport, unf_rport, xchg);
	}
	/* 3. IO_DONE */
	else if ((INI_IO_STATE_DONE & xchg->io_state) &&
		 (ABTS_RESPONSE_RECEIVED & xchg->abts_state)) {
		/*
		 * for IO_DONE:
		 * 1. INI ABTS first timer time out
		 * 2. INI RCVD ABTS Response
		 * 3. Normal case for I/O Done
		 */
		/* Send ABTS & RCVD RSP & no timeout */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		if (unf_send_rrq(unf_lport, unf_rport, xchg) == RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[info]LPort(0x%x) send RRQ succeed to RPort(0x%x) Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
				     unf_lport->port_id, unf_rport->nport_id, xchg,
				     xchg->oxid, xchg->rxid, xchg->io_state);
		} else {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]LPort(0x%x) can't send RRQ to RPort(0x%x) Exch(0x%p) OX_ID(0x%x) RX_ID(0x%x) state(0x%x)",
				     unf_lport->port_id, unf_rport->nport_id, xchg,
				      xchg->oxid, xchg->rxid, xchg->io_state);

			spin_lock_irqsave(&xchg->xchg_state_lock, flags);
			xchg->io_state |= INI_IO_STATE_RRQSEND_ERR;
			spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
			unf_lport->xchg_mgr_temp.unf_xchg_add_timer((void *)xchg,
				(ulong)UNF_WRITE_RRQ_SENDERR_INTERVAL, UNF_TIMER_TYPE_INI_IO);
		}
	} else if (INI_IO_STATE_REC_TIMEOUT_WAIT & xchg->io_state) {
		xchg->io_state &= ~INI_IO_STATE_REC_TIMEOUT_WAIT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_fc_ini_io_rec_wait_time_out(unf_lport, unf_rport, xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		unf_fc_abort_time_out_cmnd(unf_lport, xchg);
	}

	unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);
	unf_xchg_ref_dec(xchg, INI_IO_TIMEOUT);
}

void unf_sfs_xchg_time_out(struct work_struct *work)
{
	struct unf_xchg *xchg = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(work);
	xchg = container_of(work, struct unf_xchg, timeout_work.work);
	FC_CHECK_RETURN_VOID(xchg);

	ret = unf_xchg_ref_inc(xchg, SFS_TIMEOUT);
	FC_CHECK_RETURN_VOID(ret == RETURN_OK);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	unf_lport = xchg->lport;
	unf_rport = xchg->rport;
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	unf_xchg_ref_dec(xchg, SFS_TIMEOUT);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]SFS Exch(%p) Cmnd(0x%x) IO Exch(0x%p) Sid_Did(0x%x:0x%x) HotTag(0x%x) State(0x%x) Timeout.",
		     xchg, xchg->cmnd_code, xchg->io_xchg, xchg->sid, xchg->did,
		     xchg->hotpooltag, xchg->io_state);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if ((xchg->io_state & TGT_IO_STATE_ABORT) &&
	    xchg->cmnd_code != ELS_RRQ && xchg->cmnd_code != ELS_LOGO) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "SFS Exch(0x%p) Cmnd(0x%x) Hot Pool Tag(0x%x) timeout, but aborted, no need to handle.",
			     xchg, xchg->cmnd_code, xchg->hotpooltag);
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		unf_xchg_ref_dec(xchg, SFS_TIMEOUT);
		unf_xchg_ref_dec(xchg, SFS_TIMEOUT);

		return;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	/* The sfs times out. If the sfs is ELS reply,
	 * go to UNF_RPortErrorRecovery/unf_lport_error_recovery.
	 * Otherwise, go to the corresponding obCallback.
	 */
	if (UNF_XCHG_IS_ELS_REPLY(xchg) && unf_rport) {
		if (unf_rport->nport_id >= UNF_FC_FID_DOM_MGR)
			unf_lport_error_recovery(unf_lport);
		else
			unf_rport_error_recovery(unf_rport);

	} else if (xchg->ob_callback) {
		xchg->ob_callback(xchg);
	} else {
		/* Do nothing */
	}
	unf_notify_chip_free_xid(xchg);
	unf_xchg_ref_dec(xchg, SFS_TIMEOUT);
	unf_xchg_ref_dec(xchg, SFS_TIMEOUT);
}
