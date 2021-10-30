// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_rport.h"
#include "unf_log.h"
#include "unf_exchg.h"
#include "unf_ls.h"
#include "unf_service.h"
#include "unf_portman.h"

/* rport state:ready --->>> link_down --->>> closing --->>> timeout --->>> delete */
struct unf_rport_feature_pool *port_feature_pool;

void unf_sesion_loss_timeout(struct work_struct *work)
{
	struct unf_wwpn_rport_info *wwpn_rport_info = NULL;

	FC_CHECK_RETURN_VOID(work);

	wwpn_rport_info = container_of(work, struct unf_wwpn_rport_info, loss_tmo_work.work);
	if (unlikely(!wwpn_rport_info)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]wwpn_rport_info is NULL");
		return;
	}

	atomic_set(&wwpn_rport_info->scsi_state, UNF_SCSI_ST_DEAD);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[info]Port(0x%x) wwpn(0x%llx) set target(0x%x) scsi state to dead",
		     ((struct unf_lport *)(wwpn_rport_info->lport))->port_id,
		     wwpn_rport_info->wwpn, wwpn_rport_info->target_id);
}

u32 unf_alloc_scsi_id(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_rport_scsi_id_image *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info *wwn_rport_info = NULL;
	ulong flags = 0;
	u32 index = 0;
	u32 ret = UNF_RETURN_ERROR;
	spinlock_t *rport_scsi_tb_lock = NULL;

	rport_scsi_table = &lport->rport_scsi_table;
	rport_scsi_tb_lock = &rport_scsi_table->scsi_image_table_lock;
	spin_lock_irqsave(rport_scsi_tb_lock, flags);

	/* 1. At first, existence check */
	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[index];
		if (rport->port_name == wwn_rport_info->wwpn) {
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);
			UNF_DELAYED_WORK_SYNC(ret, (lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");

			/* Plug case: reuse again */
			spin_lock_irqsave(rport_scsi_tb_lock, flags);
			wwn_rport_info->rport = rport;
			wwn_rport_info->las_ten_scsi_state =
			    atomic_read(&wwn_rport_info->scsi_state);
			atomic_set(&wwn_rport_info->scsi_state, UNF_SCSI_ST_ONLINE);
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) find the same scsi_id(0x%x) by wwpn(0x%llx) RPort(%p) N_Port_ID(0x%x)",
				     lport->port_id, index, wwn_rport_info->wwpn, rport,
				     rport->nport_id);

			atomic_inc(&lport->resume_scsi_id);
			goto find;
		}
	}

	/* 2. Alloc new SCSI ID */
	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[index];
		if (wwn_rport_info->wwpn == INVALID_WWPN) {
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);
			UNF_DELAYED_WORK_SYNC(ret, (lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");
			/* Use the free space */
			spin_lock_irqsave(rport_scsi_tb_lock, flags);
			wwn_rport_info->rport = rport;
			wwn_rport_info->wwpn = rport->port_name;
			wwn_rport_info->las_ten_scsi_state =
			    atomic_read(&wwn_rport_info->scsi_state);
			atomic_set(&wwn_rport_info->scsi_state, UNF_SCSI_ST_ONLINE);
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) allco new scsi_id(0x%x) by wwpn(0x%llx) RPort(%p) N_Port_ID(0x%x)",
				     lport->port_id, index, wwn_rport_info->wwpn, rport,
				     rport->nport_id);

			atomic_inc(&lport->alloc_scsi_id);
			goto find;
		}
	}

	/* 3. Reuse space has been used */
	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[index];
		if (atomic_read(&wwn_rport_info->scsi_state) == UNF_SCSI_ST_DEAD) {
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);
			UNF_DELAYED_WORK_SYNC(ret, (lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");

			spin_lock_irqsave(rport_scsi_tb_lock, flags);
			if (wwn_rport_info->dfx_counter) {
				memset(wwn_rport_info->dfx_counter, 0,
				       sizeof(struct unf_wwpn_dfx_counter_info));
			}
			if (wwn_rport_info->lun_qos_level) {
				memset(wwn_rport_info->lun_qos_level, 0,
				       sizeof(u8) * UNF_MAX_LUN_PER_TARGET);
			}
			wwn_rport_info->rport = rport;
			wwn_rport_info->wwpn = rport->port_name;
			wwn_rport_info->las_ten_scsi_state =
			    atomic_read(&wwn_rport_info->scsi_state);
			atomic_set(&wwn_rport_info->scsi_state, UNF_SCSI_ST_ONLINE);
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[info]Port(0x%x) reuse a dead scsi_id(0x%x) by wwpn(0x%llx) RPort(%p) N_Port_ID(0x%x)",
				     lport->port_id, index, wwn_rport_info->wwpn, rport,
				     rport->nport_id);

			atomic_inc(&lport->reuse_scsi_id);
			goto find;
		}
	}

	spin_unlock_irqrestore(rport_scsi_tb_lock, flags);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) there is not enough scsi_id with max_value(0x%x)",
		     lport->port_id, index);

	return INVALID_VALUE32;

find:
	if (!wwn_rport_info->dfx_counter) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
			     "[info]Port(0x%x) allocate Rport(0x%x) DFX buffer",
			     lport->port_id, wwn_rport_info->rport->nport_id);
		wwn_rport_info->dfx_counter = vmalloc(sizeof(struct unf_wwpn_dfx_counter_info));
		if (!wwn_rport_info->dfx_counter) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "[err]Port(0x%x) allocate DFX buffer fail",
				     lport->port_id);

			return INVALID_VALUE32;
		}

		memset(wwn_rport_info->dfx_counter, 0, sizeof(struct unf_wwpn_dfx_counter_info));
	}

	return index;
}

u32 unf_get_scsi_id_by_wwpn(struct unf_lport *lport, u64 wwpn)
{
	struct unf_rport_scsi_id_image *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info *wwn_rport_info = NULL;
	ulong flags = 0;
	u32 index = 0;
	spinlock_t *rport_scsi_tb_lock = NULL;

	FC_CHECK_RETURN_VALUE(lport, INVALID_VALUE32);
	rport_scsi_table = &lport->rport_scsi_table;
	rport_scsi_tb_lock = &rport_scsi_table->scsi_image_table_lock;

	if (wwpn == 0)
		return INVALID_VALUE32;

	spin_lock_irqsave(rport_scsi_tb_lock, flags);

	for (index = 0; index < rport_scsi_table->max_scsi_id; index++) {
		wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[index];
		if (wwn_rport_info->wwpn == wwpn) {
			spin_unlock_irqrestore(rport_scsi_tb_lock, flags);
			return index;
		}
	}

	spin_unlock_irqrestore(rport_scsi_tb_lock, flags);

	return INVALID_VALUE32;
}

void unf_set_device_state(struct unf_lport *lport, u32 scsi_id, int scsi_state)
{
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	struct unf_wwpn_rport_info *wwpn_rport_info = NULL;

	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) RPort scsi_id(0x%x) is max than 0x%x",
			     lport->port_id, scsi_id, UNF_MAX_SCSI_ID);
		return;
	}

	scsi_image_table = &lport->rport_scsi_table;
	wwpn_rport_info = &scsi_image_table->wwn_rport_info_table[scsi_id];
	atomic_set(&wwpn_rport_info->scsi_state, scsi_state);
}

void unf_rport_linkdown(struct unf_lport *lport, struct unf_rport *rport)
{
	/*
	 * 1. port_logout
	 * 2. rcvd_rscn_port_not_in_disc
	 * 3. each_rport_after_rscn
	 * 4. rcvd_gpnid_rjt
	 * 5. rport_after_logout(rport is fabric port)
	 */
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	/* 1. Update R_Port state: Link Down Event --->>> closing state */
	spin_lock_irqsave(&rport->rport_state_lock, flag);
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	/* 3. Port enter closing (then enter to Delete) process */
	unf_rport_enter_closing(rport);
}

static struct unf_rport *unf_rport_is_changed(struct unf_lport *lport,
					      struct unf_rport *rport, u32 sid)
{
	if (rport) {
		/* S_ID or D_ID has been changed */
		if (rport->nport_id != sid || rport->local_nport_id != lport->nport_id) {
			/* 1. Swap case: (SID or DID changed): Report link down
			 * & delete immediately
			 */
			unf_rport_immediate_link_down(lport, rport);
			return NULL;
		}
	}

	return rport;
}

struct unf_rport *unf_rport_set_qualifier_key_reuse(struct unf_lport *lport,
						    struct unf_rport *rport_by_nport_id,
						    struct unf_rport *rport_by_wwpn,
						    u64 wwpn, u32 sid)
{
	/* Used for SPFC Chip */
	struct unf_rport *rport = NULL;
	struct unf_rport *rporta = NULL;
	struct unf_rport *rportb = NULL;
	bool wwpn_flag = false;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	/* About R_Port by N_Port_ID */
	rporta = unf_rport_is_changed(lport, rport_by_nport_id, sid);

	/* About R_Port by WWpn */
	rportb = unf_rport_is_changed(lport, rport_by_wwpn, sid);

	if (!rporta && !rportb) {
		return NULL;
	} else if (!rporta && rportb) {
		/* 3. Plug case: reuse again */
		rport = rportb;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) RPort(0x%p) WWPN(0x%llx) S_ID(0x%x) D_ID(0x%x) reused by wwpn",
			     lport->port_id, rport, rport->port_name,
			     rport->nport_id, rport->local_nport_id);

		return rport;
	} else if (rporta && !rportb) {
		wwpn_flag = (rporta->port_name != wwpn && rporta->port_name != 0 &&
			     rporta->port_name != INVALID_VALUE64);
		if (wwpn_flag) {
			/* 4. WWPN changed: Report link down & delete
			 * immediately
			 */
			unf_rport_immediate_link_down(lport, rporta);
			return NULL;
		}

		/* Updtae WWPN */
		rporta->port_name = wwpn;
		rport = rporta;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) RPort(0x%p) WWPN(0x%llx) S_ID(0x%x) D_ID(0x%x) reused by N_Port_ID",
			     lport->port_id, rport, rport->port_name,
			     rport->nport_id, rport->local_nport_id);

		return rport;
	}

	/* 5. Case for A == B && A != NULL && B != NULL */
	if (rportb == rporta) {
		rport = rporta;
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) find the same RPort(0x%p) WWPN(0x%llx) S_ID(0x%x) D_ID(0x%x)",
			     lport->port_id, rport, rport->port_name, rport->nport_id,
			     rport->local_nport_id);

		return rport;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) find two duplicate login. RPort(A:0x%p, WWPN:0x%llx, S_ID:0x%x, D_ID:0x%x) RPort(B:0x%p, WWPN:0x%llx, S_ID:0x%x, D_ID:0x%x)",
		     lport->port_id, rporta, rporta->port_name, rporta->nport_id,
		     rporta->local_nport_id, rportb, rportb->port_name, rportb->nport_id,
		     rportb->local_nport_id);

	/* 6. Case for A != B && A != NULL && B != NULL: Immediate
	 * Report && Deletion
	 */
	unf_rport_immediate_link_down(lport, rporta);
	unf_rport_immediate_link_down(lport, rportb);

	return NULL;
}

struct unf_rport *unf_find_valid_rport(struct unf_lport *lport, u64 wwpn, u32 sid)
{
	struct unf_rport *rport = NULL;
	struct unf_rport *rport_by_nport_id = NULL;
	struct unf_rport *rport_by_wwpn = NULL;
	ulong flags = 0;
	spinlock_t *rport_state_lock = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(lport->unf_qualify_rport, NULL);

	/* Get R_Port by WWN & N_Port_ID */
	rport_by_nport_id = unf_get_rport_by_nport_id(lport, sid);
	rport_by_wwpn = unf_get_rport_by_wwn(lport, wwpn);
	rport_state_lock = &rport_by_wwpn->rport_state_lock;

	/* R_Port check: by WWPN */
	if (rport_by_wwpn) {
		spin_lock_irqsave(rport_state_lock, flags);
		if (rport_by_wwpn->nport_id == UNF_FC_FID_FLOGI) {
			spin_unlock_irqrestore(rport_state_lock, flags);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
				     "[err]Port(0x%x) RPort(0x%p) find by WWPN(0x%llx) is invalid",
				     lport->port_id, rport_by_wwpn, wwpn);

			rport_by_wwpn = NULL;
		} else {
			spin_unlock_irqrestore(rport_state_lock, flags);
		}
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x_0x%x) RPort(0x%p) find by N_Port_ID(0x%x) and RPort(0x%p) by WWPN(0x%llx)",
		     lport->port_id, lport->nport_id, rport_by_nport_id, sid, rport_by_wwpn, wwpn);

	/* R_Port validity check: get by WWPN & N_Port_ID */
	rport = lport->unf_qualify_rport(lport, rport_by_nport_id,
					     rport_by_wwpn, wwpn, sid);

	return rport;
}

void unf_rport_delay_login(struct unf_rport *rport)
{
	FC_CHECK_RETURN_VOID(rport);

	/* Do R_Port recovery: PLOGI or PRLI or LOGO */
	unf_rport_error_recovery(rport);
}

void unf_rport_enter_logo(struct unf_lport *lport, struct unf_rport *rport)
{
	/*
	 * 1. TMF/ABTS timeout recovery                                     :Y
	 * 2. L_Port error recovery --->>> larger than retry_count          :Y
	 * 3. R_Port error recovery --->>> larger than retry_count          :Y
	 * 4. Check PLOGI parameter  --->>> parameter is error              :Y
	 * 5. PRLI handler          --->>> R_Port state is error            :Y
	 * 6. PDISC handler         --->>> R_Port state is not PRLI_WAIT    :Y
	 * 7. ADISC handler         --->>> R_Port state is not PRLI_WAIT    :Y
	 * 8. PLOGI wait timeout with R_PORT is INI mode                    :Y
	 * 9. RCVD GFFID_RJT        --->>> R_Port state is INIT             :Y
	 * 10. RCVD GPNID_ACC       --->>> R_Port state is error            :Y
	 * 11. Private Loop mode with LOGO case                             :Y
	 * 12. P2P          mode with LOGO case                             :Y
	 * 13. Fabric       mode with LOGO case                             :Y
	 * 14. RCVD PRLI_ACC with R_Port is INI                             :Y
	 * 15. TGT RCVD BLS_REQ with session is error                       :Y
	 */
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&rport->rport_state_lock, flags);

	if (rport->rp_state == UNF_RPORT_ST_CLOSING ||
	    rport->rp_state == UNF_RPORT_ST_DELETE) {
		/* 1. Already within Closing or Delete: Do nothing */
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		return;
	} else if (rport->rp_state == UNF_RPORT_ST_LOGO) {
		/* 2. Update R_Port state: Normal Enter Event --->>> closing
		 * state
		 */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_NORMAL_ENTER);
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		/* Send Logo if necessary */
		if (unf_send_logo(lport, rport) != RETURN_OK)
			unf_rport_enter_closing(rport);
	} else {
		/* 3. Update R_Port state: Link Down Event --->>> closing state
		 */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		unf_rport_enter_closing(rport);
	}
}

u32 unf_free_scsi_id(struct unf_lport *lport, u32 scsi_id)
{
	ulong flags = 0;
	struct unf_rport_scsi_id_image *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info *wwn_rport_info = NULL;
	spinlock_t *rport_scsi_tb_lock = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	if (unlikely(lport->port_removing)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) is removing and do nothing",
			     lport->port_id, lport->nport_id);

		return UNF_RETURN_ERROR;
	}

	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x_0x%x) scsi_id(0x%x) is bigger than %d",
			     lport->port_id, lport->nport_id, scsi_id, UNF_MAX_SCSI_ID);

		return UNF_RETURN_ERROR;
	}

	rport_scsi_table = &lport->rport_scsi_table;
	rport_scsi_tb_lock = &rport_scsi_table->scsi_image_table_lock;
	if (rport_scsi_table->wwn_rport_info_table) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[warn]Port(0x%x_0x%x) RPort(0x%p) free scsi_id(0x%x) wwpn(0x%llx) target_id(0x%x) succeed",
			     lport->port_id, lport->nport_id,
			     rport_scsi_table->wwn_rport_info_table[scsi_id].rport,
			     scsi_id, rport_scsi_table->wwn_rport_info_table[scsi_id].wwpn,
			     rport_scsi_table->wwn_rport_info_table[scsi_id].target_id);

		spin_lock_irqsave(rport_scsi_tb_lock, flags);
		wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[scsi_id];
		if (wwn_rport_info->rport) {
			wwn_rport_info->rport->rport = NULL;
			wwn_rport_info->rport = NULL;
		}
		wwn_rport_info->target_id = INVALID_VALUE32;
		atomic_set(&wwn_rport_info->scsi_state, UNF_SCSI_ST_DEAD);

		/* NOTE: remain WWPN/Port_Name unchanged(un-cleared) */
		spin_unlock_irqrestore(rport_scsi_tb_lock, flags);

		return RETURN_OK;
	}

	return UNF_RETURN_ERROR;
}

static void unf_report_ini_linkwown_event(struct unf_lport *lport, struct unf_rport *rport)
{
	u32 scsi_id = 0;
	struct fc_rport *unf_rport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	/*
	 * 1. set local device(rport/rport_info_table) state
	 * -------------------------------------------------OFF_LINE
	 * *
	 * about rport->scsi_id
	 * valid during rport link up to link down
	 */

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	scsi_id = rport->scsi_id;
	unf_set_device_state(lport, scsi_id, UNF_SCSI_ST_OFFLINE);

	/* 2. delete scsi's rport */
	unf_rport = (struct fc_rport *)rport->rport;
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	if (unf_rport) {
		fc_remote_port_delete(unf_rport);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[event]Port(0x%x_0x%x) delete RPort(0x%x) wwpn(0x%llx) scsi_id(0x%x) succeed",
			     lport->port_id, lport->nport_id, rport->nport_id,
			     rport->port_name, scsi_id);

		atomic_inc(&lport->scsi_session_del_success);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[warn]Port(0x%x_0x%x) delete RPort(0x%x_0x%p) failed",
			     lport->port_id, lport->nport_id, rport->nport_id, rport);
	}
}

static void unf_report_ini_linkup_event(struct unf_lport *lport, struct unf_rport *rport)
{
	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
		     "[event]Port(0x%x) RPort(0x%x_0x%p) put INI link up work(%p) to work_queue",
		     lport->port_id, rport->nport_id, rport, &rport->start_work);

	if (unlikely(!queue_work(lport->link_event_wq, &rport->start_work))) {
		atomic_inc(&lport->add_start_work_failed);

		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]Port(0x%x) RPort(0x%x_0x%p) put INI link up to work_queue failed",
			     lport->port_id, rport->nport_id, rport);
	}
}

void unf_update_lport_state_by_linkup_event(struct unf_lport *lport,
					    struct unf_rport *rport,
					    u32 rport_att)
{
	/* Report R_Port Link Up/Down Event */
	ulong flag = 0;
	enum unf_port_state lport_state = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&rport->rport_state_lock, flag);

	/* 1. R_Port does not has TGT mode any more */
	if (((rport_att & UNF_FC4_FRAME_PARM_3_TGT) == 0) &&
	    rport->lport_ini_state == UNF_PORT_STATE_LINKUP) {
		rport->last_lport_ini_state = rport->lport_ini_state;
		rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) does not have TGT attribute(0x%x) any more",
			     lport->port_id, rport->nport_id, rport_att);
	}

	/* 2. R_Port with TGT mode, L_Port with INI mode */
	if ((rport_att & UNF_FC4_FRAME_PARM_3_TGT) &&
	    (lport->options & UNF_FC4_FRAME_PARM_3_INI)) {
		rport->last_lport_ini_state = rport->lport_ini_state;
		rport->lport_ini_state = UNF_PORT_STATE_LINKUP;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[warn]Port(0x%x) update INI state with last(0x%x) and now(0x%x)",
			     lport->port_id, rport->last_lport_ini_state,
			     rport->lport_ini_state);
	}

	/* 3. Report L_Port INI/TGT Down/Up event to SCSI */
	if (rport->last_lport_ini_state == rport->lport_ini_state) {
		if (rport->nport_id < UNF_FC_FID_DOM_MGR) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) RPort(0x%x %p) INI state(0x%x) has not been changed",
				     lport->port_id, rport->nport_id, rport,
				     rport->lport_ini_state);
		}

		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		return;
	}

	lport_state = rport->lport_ini_state;

	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	switch (lport_state) {
	case UNF_PORT_STATE_LINKDOWN:
		unf_report_ini_linkwown_event(lport, rport);
		break;
	case UNF_PORT_STATE_LINKUP:
		unf_report_ini_linkup_event(lport, rport);
		break;
	default:
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) with unknown link status(0x%x)",
			     lport->port_id, rport->lport_ini_state);
		break;
	}
}

static void unf_rport_callback(void *rport, void *lport, u32 result)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(rport);
	FC_CHECK_RETURN_VOID(lport);
	unf_rport = (struct unf_rport *)rport;
	unf_lport = (struct unf_lport *)lport;

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->last_lport_ini_state = unf_rport->lport_ini_state;
	unf_rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	unf_rport->last_lport_tgt_state = unf_rport->lport_tgt_state;
	unf_rport->lport_tgt_state = UNF_PORT_STATE_LINKDOWN;

	/* Report R_Port Link Down Event to scsi */
	if (unf_rport->last_lport_ini_state == unf_rport->lport_ini_state) {
		if (unf_rport->nport_id < UNF_FC_FID_DOM_MGR) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) RPort(0x%x %p) INI state(0x%x) has not been changed",
				     unf_lport->port_id, unf_rport->nport_id,
				     unf_rport, unf_rport->lport_ini_state);
		}
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		return;
	}

	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	unf_report_ini_linkwown_event(unf_lport, unf_rport);
}

static void unf_rport_recovery_timeout(struct work_struct *work)
{
	struct unf_lport *lport = NULL;
	struct unf_rport *rport = NULL;
	u32 ret = RETURN_OK;
	ulong flag = 0;
	enum unf_rport_login_state rp_state = UNF_RPORT_ST_INIT;

	FC_CHECK_RETURN_VOID(work);

	rport = container_of(work, struct unf_rport, recovery_work.work);
	if (unlikely(!rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort is NULL");

		return;
	}

	lport = rport->lport;
	if (unlikely(!lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort(0x%x) Port is NULL", rport->nport_id);

		/* for timer */
		unf_rport_ref_dec(rport);
		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rp_state = rport->rp_state;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x_0x%x) RPort(0x%x) state(0x%x) recovery timer timeout",
		     lport->port_id, lport->nport_id, rport->nport_id, rp_state);
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	switch (rp_state) {
	case UNF_RPORT_ST_PLOGI_WAIT:
		if ((lport->act_topo == UNF_ACT_TOP_P2P_DIRECT &&
		     lport->port_name > rport->port_name) ||
		     lport->act_topo != UNF_ACT_TOP_P2P_DIRECT) {
			/* P2P: Name is master with P2P_D
			 * or has INI Mode
			 */
			ret = unf_send_plogi(rport->lport, rport);
		}
		break;
	case UNF_RPORT_ST_PRLI_WAIT:
		ret = unf_send_prli(rport->lport, rport, ELS_PRLI);
		if (ret != RETURN_OK)
			unf_rport_error_recovery(rport);
	fallthrough;
	default:
		break;
	}

	if (ret != RETURN_OK)
		unf_rport_error_recovery(rport);

	/* company with timer */
	unf_rport_ref_dec(rport);
}

void unf_schedule_closing_work(struct unf_lport *lport, struct unf_rport *rport)
{
	ulong flags = 0;
	struct unf_rport_scsi_id_image *rport_scsi_table = NULL;
	struct unf_wwpn_rport_info *wwn_rport_info = NULL;
	u32 scsi_id = 0;
	u32 ret = 0;
	u32 delay = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(rport);

	delay = (u32)(unf_get_link_lose_tmo(lport) * 1000);

	rport_scsi_table = &lport->rport_scsi_table;
	scsi_id = rport->scsi_id;
	spin_lock_irqsave(&rport->rport_state_lock, flags);

	/* 1. Cancel recovery_work */
	if (cancel_delayed_work(&rport->recovery_work)) {
		atomic_dec(&rport->rport_ref_cnt);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) RPort(0x%x_0x%p) cancel recovery work succeed",
			     lport->port_id, lport->nport_id, rport->nport_id, rport);
	}

	/* 2. Cancel Open_work */
	if (cancel_delayed_work(&rport->open_work)) {
		atomic_dec(&rport->rport_ref_cnt);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) RPort(0x%x_0x%p) cancel open work succeed",
			     lport->port_id, lport->nport_id, rport->nport_id, rport);
	}

	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	/* 3. Work in-queue (switch to thread context) */
	if (!queue_work(lport->link_event_wq, &rport->closing_work)) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[warn]Port(0x%x) RPort(0x%x_0x%p) add link down to work queue failed",
			     lport->port_id, rport->nport_id, rport);

		atomic_inc(&lport->add_closing_work_failed);
	} else {
		spin_lock_irqsave(&rport->rport_state_lock, flags);
		(void)unf_rport_ref_inc(rport);
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
			     "[info]Port(0x%x) RPort(0x%x_0x%p) add link down to work(%p) queue succeed",
			     lport->port_id, rport->nport_id, rport,
			     &rport->closing_work);
	}

	if (rport->nport_id > UNF_FC_FID_DOM_MGR)
		return;

	if (scsi_id >= UNF_MAX_SCSI_ID) {
		scsi_id = unf_get_scsi_id_by_wwpn(lport, rport->port_name);
		if (scsi_id >= UNF_MAX_SCSI_ID) {
			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
				     "[warn]Port(0x%x) RPort(0x%p) NPortId(0x%x) wwpn(0x%llx) option(0x%x) scsi_id(0x%x) is max than(0x%x)",
				     lport->port_id, rport, rport->nport_id,
				     rport->port_name, rport->options, scsi_id,
				     UNF_MAX_SCSI_ID);

			return;
		}
	}

	wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[scsi_id];
	ret = queue_delayed_work(unf_wq, &wwn_rport_info->loss_tmo_work,
				 (ulong)msecs_to_jiffies((u32)delay));
	if (!ret) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
			     "[info] Port(0x%x) add RPort(0x%p) NPortId(0x%x) scsi_id(0x%x) wwpn(0x%llx) loss timeout work failed",
			     lport->port_id, rport, rport->nport_id, scsi_id,
			     rport->port_name);
	}
}

static void unf_rport_closing_timeout(struct work_struct *work)
{
	/* closing --->>>(timeout)--->>> delete */
	struct unf_rport *rport = NULL;
	struct unf_lport *lport = NULL;
	struct unf_disc *disc = NULL;
	ulong rport_flag = 0;
	ulong disc_flag = 0;
	void (*unf_rport_callback)(void *, void *, u32) = NULL;
	enum unf_rport_login_state old_state;

	FC_CHECK_RETURN_VOID(work);

	/* Get R_Port & L_Port & Disc */
	rport = container_of(work, struct unf_rport, closing_work);
	if (unlikely(!rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort is NULL");
		return;
	}

	lport = rport->lport;
	if (unlikely(!lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort(0x%x_0x%p) Port is NULL",
			     rport->nport_id, rport);

		/* Release directly (for timer) */
		unf_rport_ref_dec(rport);
		return;
	}
	disc = &lport->disc;

	spin_lock_irqsave(&rport->rport_state_lock, rport_flag);

	old_state = rport->rp_state;
	/* 1. Update R_Port state: event_timeout --->>> state_delete */
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_CLS_TIMEOUT);

	/* Check R_Port state */
	if (rport->rp_state != UNF_RPORT_ST_DELETE) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x_0x%x) RPort(0x%x_0x%p) closing timeout with error state(0x%x->0x%x)",
			     lport->port_id, lport->nport_id, rport->nport_id,
			     rport, old_state, rport->rp_state);

		spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);

		/* Dec ref_cnt for timer */
		unf_rport_ref_dec(rport);
		return;
	}

	unf_rport_callback = rport->unf_rport_callback;
	spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);

	/* 2. Put R_Port to delete list */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_flag);
	list_del_init(&rport->entry_rport);
	list_add_tail(&rport->entry_rport, &disc->list_delete_rports);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_flag);

	/* 3. Report rport link down event to scsi */
	if (unf_rport_callback) {
		unf_rport_callback((void *)rport, (void *)rport->lport, RETURN_OK);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort(0x%x) callback is NULL",
			     rport->nport_id);
	}

	/* 4. Remove/delete R_Port */
	unf_rport_ref_dec(rport);
	unf_rport_ref_dec(rport);
}

static void unf_rport_linkup_to_scsi(struct work_struct *work)
{
	struct fc_rport_identifiers rport_ids;
	struct fc_rport *rport = NULL;
	ulong flags = RETURN_OK;
	struct unf_wwpn_rport_info *wwn_rport_info = NULL;
	struct unf_rport_scsi_id_image *rport_scsi_table = NULL;
	u32 scsi_id = 0;

	struct unf_lport *lport = NULL;
	struct unf_rport *unf_rport = NULL;

	FC_CHECK_RETURN_VOID(work);

	unf_rport = container_of(work, struct unf_rport, start_work);
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort is NULL for work(%p)", work);
		return;
	}

	lport = unf_rport->lport;
	if (unlikely(!lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]RPort(0x%x_0x%p) Port is NULL",
			     unf_rport->nport_id, unf_rport);
		return;
	}

	/* 1. Alloc R_Port SCSI_ID (image table) */
	unf_rport->scsi_id = unf_alloc_scsi_id(lport, unf_rport);
	if (unlikely(unf_rport->scsi_id == INVALID_VALUE32)) {
		atomic_inc(&lport->scsi_session_add_failed);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[err]Port(0x%x_0x%x) RPort(0x%x_0x%p) wwpn(0x%llx) scsi_id(0x%x) is invalid",
			     lport->port_id, lport->nport_id,
			     unf_rport->nport_id, unf_rport,
			     unf_rport->port_name, unf_rport->scsi_id);

		/* NOTE: return */
		return;
	}

	/* 2. Add rport to scsi */
	scsi_id = unf_rport->scsi_id;
	rport_ids.node_name = unf_rport->node_name;
	rport_ids.port_name = unf_rport->port_name;
	rport_ids.port_id = unf_rport->nport_id;
	rport_ids.roles = FC_RPORT_ROLE_UNKNOWN;
	rport = fc_remote_port_add(lport->host_info.host, 0, &rport_ids);
	if (unlikely(!rport)) {
		atomic_inc(&lport->scsi_session_add_failed);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x_0x%x) RPort(0x%x_0x%p) wwpn(0x%llx) report link up to scsi failed",
			     lport->port_id, lport->nport_id, unf_rport->nport_id, unf_rport,
			     unf_rport->port_name);

		unf_free_scsi_id(lport, scsi_id);
		return;
	}

	/* 3. Change rport role */
	*((u32 *)rport->dd_data) = scsi_id; /* save local SCSI_ID to scsi rport */
	rport->supported_classes = FC_COS_CLASS3;
	rport_ids.roles |= FC_PORT_ROLE_FCP_TARGET;
	rport->dev_loss_tmo = (u32)unf_get_link_lose_tmo(lport); /* default 30s */
	fc_remote_port_rolechg(rport, rport_ids.roles);

	/* 4. Save scsi rport info to local R_Port */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flags);
	unf_rport->rport = rport;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flags);

	rport_scsi_table = &lport->rport_scsi_table;
	spin_lock_irqsave(&rport_scsi_table->scsi_image_table_lock, flags);
	wwn_rport_info = &rport_scsi_table->wwn_rport_info_table[scsi_id];
	wwn_rport_info->target_id = rport->scsi_target_id;
	wwn_rport_info->rport = unf_rport;
	atomic_set(&wwn_rport_info->scsi_state, UNF_SCSI_ST_ONLINE);
	spin_unlock_irqrestore(&rport_scsi_table->scsi_image_table_lock, flags);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[event]Port(0x%x_0x%x) RPort(0x%x) wwpn(0x%llx) scsi_id(0x%x) link up to scsi succeed",
		     lport->port_id, lport->nport_id, unf_rport->nport_id,
		     unf_rport->port_name, scsi_id);

	atomic_inc(&lport->scsi_session_add_success);
}

static void unf_rport_open_timeout(struct work_struct *work)
{
	struct unf_rport *rport = NULL;
	struct unf_lport *lport = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(work);

	rport = container_of(work, struct unf_rport, open_work.work);
	if (!rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]RPort is NULL");

		return;
	}

	spin_lock_irqsave(&rport->rport_state_lock, flags);
	lport = rport->lport;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x_0x%x) RPort(0x%x) open work timeout with state(0x%x)",
		     lport->port_id, lport->nport_id, rport->nport_id,
		     rport->rp_state);

	/* NOTE: R_Port state check */
	if (rport->rp_state != UNF_RPORT_ST_PRLI_WAIT) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		/* Dec ref_cnt for timer case */
		unf_rport_ref_dec(rport);
		return;
	}

	/* Report R_Port Link Down event */
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	unf_rport_enter_closing(rport);
	/* Dec ref_cnt for timer case */
	unf_rport_ref_dec(rport);
}

static u32 unf_alloc_index_for_rport(struct unf_lport *lport, struct unf_rport *rport)
{
	ulong rport_flag = 0;
	ulong pool_flag = 0;
	u32 alloc_indx = 0;
	u32 max_rport = 0;
	struct unf_rport_pool *rport_pool = NULL;
	spinlock_t *rport_scsi_tb_lock = NULL;

	rport_pool = &lport->rport_pool;
	rport_scsi_tb_lock = &rport_pool->rport_free_pool_lock;
	max_rport = lport->low_level_func.lport_cfg_items.max_login;

	max_rport = max_rport > SPFC_DEFAULT_RPORT_INDEX ? SPFC_DEFAULT_RPORT_INDEX : max_rport;

	spin_lock_irqsave(rport_scsi_tb_lock, pool_flag);
	while (alloc_indx < max_rport) {
		if (!test_bit((int)alloc_indx, rport_pool->rpi_bitmap)) {
			/* Case for SPFC */
			if (unlikely(atomic_read(&lport->lport_no_operate_flag) == UNF_LPORT_NOP)) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x) is within NOP", lport->port_id);

				spin_unlock_irqrestore(rport_scsi_tb_lock, pool_flag);
				return UNF_RETURN_ERROR;
			}

			spin_lock_irqsave(&rport->rport_state_lock, rport_flag);
			rport->rport_index = alloc_indx;

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
				     "[info]Port(0x%x) RPort(0x%x) alloc index(0x%x) succeed",
				     lport->port_id, alloc_indx, rport->nport_id);

			spin_unlock_irqrestore(&rport->rport_state_lock, rport_flag);

			/* Set (index) bit */
			set_bit((int)alloc_indx, rport_pool->rpi_bitmap);

			/* Break here */
			break;
		}
		alloc_indx++;
	}
	spin_unlock_irqrestore(rport_scsi_tb_lock, pool_flag);

	if (max_rport == alloc_indx)
		return UNF_RETURN_ERROR;
	return RETURN_OK;
}

static void unf_check_rport_pool_status(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = lport;
	struct unf_rport_pool *rport_pool = NULL;
	ulong flags = 0;
	u32 max_rport = 0;

	FC_CHECK_RETURN_VOID(lport);
	rport_pool = &unf_lport->rport_pool;

	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flags);
	max_rport = unf_lport->low_level_func.lport_cfg_items.max_login;
	if (rport_pool->rport_pool_completion &&
	    rport_pool->rport_pool_count == max_rport) {
		complete(rport_pool->rport_pool_completion);
	}

	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flags);
}

static void unf_init_rport_sq_num(struct unf_rport *rport, struct unf_lport *lport)
{
	u32 session_order;
	u32 ssq_average_session_num;

	ssq_average_session_num = (lport->max_ssq_num - 1) / UNF_SQ_NUM_PER_SESSION;
	session_order = (rport->rport_index) % ssq_average_session_num;
	rport->sqn_base = (session_order * UNF_SQ_NUM_PER_SESSION);
}

void unf_init_rport_params(struct unf_rport *rport, struct unf_lport *lport)
{
	struct unf_rport *unf_rport = rport;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(unf_rport);
	FC_CHECK_RETURN_VOID(lport);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_set_rport_state(unf_rport, UNF_RPORT_ST_INIT);
	unf_rport->unf_rport_callback = unf_rport_callback;
	unf_rport->lport = lport;
	unf_rport->fcp_conf_needed = false;
	unf_rport->tape_support_needed = false;
	unf_rport->max_retries = UNF_MAX_RETRY_COUNT;
	unf_rport->logo_retries = 0;
	unf_rport->retries = 0;
	unf_rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
	unf_rport->last_lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	unf_rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	unf_rport->last_lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	unf_rport->lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	unf_rport->node_name = 0;
	unf_rport->port_name = INVALID_WWPN;
	unf_rport->disc_done = 0;
	unf_rport->scsi_id = INVALID_VALUE32;
	unf_rport->data_thread = NULL;
	sema_init(&unf_rport->task_sema, 0);
	atomic_set(&unf_rport->rport_ref_cnt, 0);
	atomic_set(&unf_rport->pending_io_cnt, 0);
	unf_rport->rport_alloc_jifs = jiffies;

	unf_rport->ed_tov = UNF_DEFAULT_EDTOV + 500;
	unf_rport->ra_tov = UNF_DEFAULT_RATOV;

	INIT_WORK(&unf_rport->closing_work, unf_rport_closing_timeout);
	INIT_WORK(&unf_rport->start_work, unf_rport_linkup_to_scsi);
	INIT_DELAYED_WORK(&unf_rport->recovery_work, unf_rport_recovery_timeout);
	INIT_DELAYED_WORK(&unf_rport->open_work, unf_rport_open_timeout);

	atomic_inc(&unf_rport->rport_ref_cnt);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);
}

static u32 unf_alloc_ll_rport_resource(struct unf_lport *lport,
				       struct unf_rport *rport, u32 nport_id)
{
	u32 ret = RETURN_OK;
	struct unf_port_info rport_info = {0};
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_qos_info *qos_info = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;

	unf_lport = lport->root_lport;

	if (unf_lport->low_level_func.service_op.unf_alloc_rport_res) {
		spin_lock_irqsave(&lport->qos_mgr_lock, flag);
		rport_info.qos_level = lport->qos_level;
		list_for_each_safe(node, next_node, &lport->list_qos_head) {
			qos_info = (struct unf_qos_info *)list_entry(node, struct unf_qos_info,
								     entry_qos_info);

			if (qos_info && qos_info->nport_id == nport_id) {
				rport_info.qos_level = qos_info->qos_level;
				break;
			}
		}

		spin_unlock_irqrestore(&lport->qos_mgr_lock, flag);

		unf_init_rport_sq_num(rport, unf_lport);

		rport->qos_level = rport_info.qos_level;
		rport_info.nport_id = nport_id;
		rport_info.rport_index = rport->rport_index;
		rport_info.local_nport_id = lport->nport_id;
		rport_info.port_name = 0;
		rport_info.cs_ctrl = UNF_CSCTRL_INVALID;
		rport_info.sqn_base = rport->sqn_base;

		if (unf_lport->priority == UNF_PRIORITY_ENABLE) {
			if (rport_info.qos_level == UNF_QOS_LEVEL_DEFAULT)
				rport_info.cs_ctrl = UNF_CSCTRL_LOW;
			else if (rport_info.qos_level == UNF_QOS_LEVEL_MIDDLE)
				rport_info.cs_ctrl = UNF_CSCTRL_MIDDLE;
			else if (rport_info.qos_level == UNF_QOS_LEVEL_HIGH)
				rport_info.cs_ctrl = UNF_CSCTRL_HIGH;
		}

		ret = unf_lport->low_level_func.service_op.unf_alloc_rport_res(unf_lport->fc_port,
									       &rport_info);
	} else {
		ret = RETURN_OK;
	}

	return ret;
}

static void *unf_add_rport_to_busy_list(struct unf_lport *lport,
					struct unf_rport *new_rport,
					u32 nport_id)
{
	struct unf_rport_pool *rport_pool = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_rport *unf_new_rport = new_rport;
	struct unf_rport *old_rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	spinlock_t *rport_free_lock = NULL;
	spinlock_t *rport_busy_lock = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(new_rport, NULL);

	unf_lport = lport->root_lport;
	disc = &lport->disc;
	FC_CHECK_RETURN_VALUE(unf_lport, NULL);
	rport_pool = &unf_lport->rport_pool;
	rport_free_lock = &rport_pool->rport_free_pool_lock;
	rport_busy_lock = &disc->rport_busy_pool_lock;

	spin_lock_irqsave(rport_busy_lock, flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		/* According to N_Port_ID */
		old_rport = list_entry(node, struct unf_rport, entry_rport);
		if (old_rport->nport_id == nport_id)
			break;
		old_rport = NULL;
	}

	if (old_rport) {
		spin_unlock_irqrestore(rport_busy_lock, flag);

		/* Use old R_Port & Add new R_Port back to R_Port Pool */
		spin_lock_irqsave(rport_free_lock, flag);
		clear_bit((int)unf_new_rport->rport_index, rport_pool->rpi_bitmap);
		list_add_tail(&unf_new_rport->entry_rport, &rport_pool->list_rports_pool);
		rport_pool->rport_pool_count++;
		spin_unlock_irqrestore(rport_free_lock, flag);

		unf_check_rport_pool_status(unf_lport);
		return (void *)old_rport;
	}
	spin_unlock_irqrestore(rport_busy_lock, flag);
	if (nport_id != UNF_FC_FID_FLOGI) {
		if (unf_alloc_ll_rport_resource(lport, unf_new_rport, nport_id) != RETURN_OK) {
			/* Add new R_Port back to R_Port Pool */
			spin_lock_irqsave(rport_free_lock, flag);
			clear_bit((int)unf_new_rport->rport_index, rport_pool->rpi_bitmap);
			list_add_tail(&unf_new_rport->entry_rport, &rport_pool->list_rports_pool);
			rport_pool->rport_pool_count++;
			spin_unlock_irqrestore(rport_free_lock, flag);
			unf_check_rport_pool_status(unf_lport);

			return NULL;
		}
	}

	spin_lock_irqsave(rport_busy_lock, flag);
	/* Add new R_Port to busy list */
	list_add_tail(&unf_new_rport->entry_rport, &disc->list_busy_rports);
	unf_new_rport->nport_id = nport_id;
	unf_new_rport->local_nport_id = lport->nport_id;
	spin_unlock_irqrestore(rport_busy_lock, flag);
	unf_init_rport_params(unf_new_rport, lport);

	return (void *)unf_new_rport;
}

void *unf_rport_get_free_and_init(void *lport, u32 port_type, u32 nport_id)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport_pool *rport_pool = NULL;
	struct unf_disc *disc = NULL;
	struct unf_disc *vport_disc = NULL;
	struct unf_rport *rport = NULL;
	struct list_head *list_head = NULL;
	ulong flag = 0;
	struct unf_disc_rport *disc_rport = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VALUE(unf_lport, NULL);

	/* Check L_Port state: NOP */
	if (unlikely(atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP))
		return NULL;

	rport_pool = &unf_lport->rport_pool;
	disc = &unf_lport->disc;

	/* 1. UNF_PORT_TYPE_DISC: Get from disc_rport_pool */
	if (port_type == UNF_PORT_TYPE_DISC) {
		vport_disc = &((struct unf_lport *)lport)->disc;
		/* NOTE: list_disc_rports_pool used with list_disc_rports_busy */
		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		if (!list_empty(&disc->disc_rport_mgr.list_disc_rports_pool)) {
			/* Get & delete from Disc R_Port Pool & Add it to Busy list */
			list_head = UNF_OS_LIST_NEXT(&disc->disc_rport_mgr.list_disc_rports_pool);
			list_del_init(list_head);
			disc_rport = list_entry(list_head, struct unf_disc_rport, entry_rport);
			disc_rport->nport_id = nport_id;
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

			/* Add to list_disc_rports_busy */
			spin_lock_irqsave(&vport_disc->rport_busy_pool_lock, flag);
			list_add_tail(list_head, &vport_disc->disc_rport_mgr.list_disc_rports_busy);
			spin_unlock_irqrestore(&vport_disc->rport_busy_pool_lock, flag);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
				     "Port(0x%x_0x%x) add nportid:0x%x to rportbusy list",
				     unf_lport->port_id, unf_lport->nport_id,
				     disc_rport->nport_id);
		} else {
			disc_rport = NULL;
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
		}

		/* NOTE: return */
		return disc_rport;
	}

	/* 2. UNF_PORT_TYPE_FC (rport_pool): Get from list_rports_pool */
	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	if (!list_empty(&rport_pool->list_rports_pool)) {
		/* Get & delete from R_Port free Pool */
		list_head = UNF_OS_LIST_NEXT(&rport_pool->list_rports_pool);
		list_del_init(list_head);
		rport_pool->rport_pool_count--;
		rport = list_entry(list_head, struct unf_rport, entry_rport);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) RPort pool is empty",
			     unf_lport->port_id, unf_lport->nport_id);

		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

		return NULL;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	/* 3. Alloc (& set bit) R_Port index */
	if (unf_alloc_index_for_rport(unf_lport, rport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate index for new RPort failed",
			     unf_lport->nport_id);

		/* Alloc failed: Add R_Port back to R_Port Pool */
		spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
		list_add_tail(&rport->entry_rport, &rport_pool->list_rports_pool);
		rport_pool->rport_pool_count++;
		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);
		unf_check_rport_pool_status(unf_lport);
		return NULL;
	}

	/* 4. Add R_Port to busy list */
	rport = unf_add_rport_to_busy_list(lport, rport, nport_id);

	return (void *)rport;
}

u32 unf_release_rport_res(struct unf_lport *lport, struct unf_rport *rport)
{
	u32 ret = UNF_RETURN_ERROR;
	struct unf_port_info rport_info;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	memset(&rport_info, 0, sizeof(struct unf_port_info));

	rport_info.rport_index = rport->rport_index;
	rport_info.nport_id = rport->nport_id;
	rport_info.port_name = rport->port_name;
	rport_info.sqn_base = rport->sqn_base;

	/* 2. release R_Port(parent context/Session) resource */
	if (!lport->low_level_func.service_op.unf_release_rport_res) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) release rport resource function can't be NULL",
			     lport->port_id);

		return ret;
	}

	ret = lport->low_level_func.service_op.unf_release_rport_res(lport->fc_port, &rport_info);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) rport_index(0x%x, %p) send release session CMND failed",
			     lport->port_id, rport_info.rport_index, rport);
	}

	return ret;
}

static void unf_reset_rport_attribute(struct unf_rport *rport)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	rport->unf_rport_callback = NULL;
	rport->lport = NULL;
	rport->node_name = INVALID_VALUE64;
	rport->port_name = INVALID_WWPN;
	rport->nport_id = INVALID_VALUE32;
	rport->local_nport_id = INVALID_VALUE32;
	rport->max_frame_size = UNF_MAX_FRAME_SIZE;
	rport->ed_tov = UNF_DEFAULT_EDTOV;
	rport->ra_tov = UNF_DEFAULT_RATOV;
	rport->rport_index = INVALID_VALUE32;
	rport->scsi_id = INVALID_VALUE32;
	rport->rport_alloc_jifs = INVALID_VALUE64;

	/* ini or tgt */
	rport->options = 0;

	/* fcp conf */
	rport->fcp_conf_needed = false;

	/* special req retry times */
	rport->retries = 0;
	rport->logo_retries = 0;

	/* special req retry times */
	rport->max_retries = UNF_MAX_RETRY_COUNT;

	/* for target mode */
	rport->session = NULL;
	rport->last_lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	rport->lport_ini_state = UNF_PORT_STATE_LINKDOWN;
	rport->rp_state = UNF_RPORT_ST_INIT;
	rport->last_lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	rport->lport_tgt_state = UNF_PORT_STATE_LINKDOWN;
	rport->rscn_position = UNF_RPORT_NOT_NEED_PROCESS;
	rport->disc_done = 0;
	rport->sqn_base = 0;

	/* for scsi */
	rport->data_thread = NULL;
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);
}

u32 unf_rport_remove(void *rport)
{
	struct unf_lport *lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_rport_pool *rport_pool = NULL;
	ulong flag = 0;
	u32 rport_index = 0;
	u32 nport_id = 0;

	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	unf_rport = (struct unf_rport *)rport;
	lport = unf_rport->lport;
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	rport_pool = &((struct unf_lport *)lport->root_lport)->rport_pool;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Remove RPort(0x%p) with remote_nport_id(0x%x) local_nport_id(0x%x)",
		     unf_rport, unf_rport->nport_id, unf_rport->local_nport_id);

	/* 1. Terminate open exchange before rport remove: set ABORT tag */
	unf_cm_xchg_mgr_abort_io_by_id(lport, unf_rport, unf_rport->nport_id, lport->nport_id, 0);

	/* 2. Abort sfp exchange before rport remove */
	unf_cm_xchg_mgr_abort_sfs_by_id(lport, unf_rport, unf_rport->nport_id, lport->nport_id);

	/* 3. Release R_Port resource: session reset/delete */
	if (likely(unf_rport->nport_id != UNF_FC_FID_FLOGI))
		(void)unf_release_rport_res(lport, unf_rport);

	nport_id = unf_rport->nport_id;

	/* 4.1 Delete R_Port from disc destroy/delete list */
	spin_lock_irqsave(&lport->disc.rport_busy_pool_lock, flag);
	list_del_init(&unf_rport->entry_rport);
	spin_unlock_irqrestore(&lport->disc.rport_busy_pool_lock, flag);

	rport_index = unf_rport->rport_index;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) release RPort(0x%x_%p) with index(0x%x)",
		     lport->port_id, unf_rport->nport_id, unf_rport,
		     unf_rport->rport_index);

	unf_reset_rport_attribute(unf_rport);

	/* 4.2 Add rport to --->>> rport_pool (free pool) & clear bitmap */
	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	if (unlikely(nport_id == UNF_FC_FID_FLOGI)) {
		if (test_bit((int)rport_index, rport_pool->rpi_bitmap))
			clear_bit((int)rport_index, rport_pool->rpi_bitmap);
	}

	list_add_tail(&unf_rport->entry_rport, &rport_pool->list_rports_pool);
	rport_pool->rport_pool_count++;
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	unf_check_rport_pool_status((struct unf_lport *)lport->root_lport);
	up(&unf_rport->task_sema);

	return RETURN_OK;
}

u32 unf_rport_ref_inc(struct unf_rport *rport)
{
	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	if (atomic_read(&rport->rport_ref_cnt) <= 0) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Rport(0x%x) reference count is wrong %d",
			     rport->nport_id,
			     atomic_read(&rport->rport_ref_cnt));
		return UNF_RETURN_ERROR;
	}

	atomic_inc(&rport->rport_ref_cnt);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Rport(0x%x) reference count is %d", rport->nport_id,
		     atomic_read(&rport->rport_ref_cnt));

	return RETURN_OK;
}

void unf_rport_ref_dec(struct unf_rport *rport)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(rport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Rport(0x%x) reference count is %d", rport->nport_id,
		     atomic_read(&rport->rport_ref_cnt));

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	if (atomic_dec_and_test(&rport->rport_ref_cnt)) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
		(void)unf_rport_remove(rport);
	} else {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	}
}

void unf_set_rport_state(struct unf_rport *rport,
			 enum unf_rport_login_state states)
{
	FC_CHECK_RETURN_VOID(rport);

	if (rport->rp_state != states) {
		/* Reset R_Port retry count */
		rport->retries = 0;
	}

	rport->rp_state = states;
}

static enum unf_rport_login_state
unf_rport_stat_init(enum unf_rport_login_state old_state,
		    enum unf_rport_event event)
{
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	switch (event) {
	case UNF_EVENT_RPORT_LOGO:
		next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_ENTER_PLOGI:
		next_state = UNF_RPORT_ST_PLOGI_WAIT;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:
		next_state = UNF_RPORT_ST_CLOSING;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_rport_login_state unf_rport_stat_plogi_wait(enum unf_rport_login_state old_state,
							    enum unf_rport_event event)
{
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	switch (event) {
	case UNF_EVENT_RPORT_ENTER_PRLI:
		next_state = UNF_RPORT_ST_PRLI_WAIT;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:
		next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_LOGO:
		next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_RECOVERY:
		next_state = UNF_RPORT_ST_READY;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_rport_login_state unf_rport_stat_prli_wait(enum unf_rport_login_state old_state,
							   enum unf_rport_event event)
{
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	switch (event) {
	case UNF_EVENT_RPORT_READY:
		next_state = UNF_RPORT_ST_READY;
		break;

	case UNF_EVENT_RPORT_LOGO:
		next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:
		next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_RECOVERY:
		next_state = UNF_RPORT_ST_READY;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_rport_login_state unf_rport_stat_ready(enum unf_rport_login_state old_state,
						       enum unf_rport_event event)
{
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	switch (event) {
	case UNF_EVENT_RPORT_LOGO:
		next_state = UNF_RPORT_ST_LOGO;
		break;

	case UNF_EVENT_RPORT_LINK_DOWN:
		next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_ENTER_PLOGI:
		next_state = UNF_RPORT_ST_PLOGI_WAIT;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_rport_login_state unf_rport_stat_closing(enum unf_rport_login_state old_state,
							 enum unf_rport_event event)
{
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	switch (event) {
	case UNF_EVENT_RPORT_CLS_TIMEOUT:
		next_state = UNF_RPORT_ST_DELETE;
		break;

	case UNF_EVENT_RPORT_RELOGIN:
		next_state = UNF_RPORT_ST_INIT;
		break;

	case UNF_EVENT_RPORT_RECOVERY:
		next_state = UNF_RPORT_ST_READY;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_rport_login_state unf_rport_stat_logo(enum unf_rport_login_state old_state,
						      enum unf_rport_event event)
{
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	switch (event) {
	case UNF_EVENT_RPORT_NORMAL_ENTER:
		next_state = UNF_RPORT_ST_CLOSING;
		break;

	case UNF_EVENT_RPORT_RECOVERY:
		next_state = UNF_RPORT_ST_READY;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

void unf_rport_state_ma(struct unf_rport *rport, enum unf_rport_event event)
{
	enum unf_rport_login_state old_state = UNF_RPORT_ST_INIT;
	enum unf_rport_login_state next_state = UNF_RPORT_ST_INIT;

	FC_CHECK_RETURN_VOID(rport);

	old_state = rport->rp_state;

	switch (rport->rp_state) {
	case UNF_RPORT_ST_INIT:
		next_state = unf_rport_stat_init(old_state, event);
		break;
	case UNF_RPORT_ST_PLOGI_WAIT:
		next_state = unf_rport_stat_plogi_wait(old_state, event);
		break;
	case UNF_RPORT_ST_PRLI_WAIT:
		next_state = unf_rport_stat_prli_wait(old_state, event);
		break;
	case UNF_RPORT_ST_LOGO:
		next_state = unf_rport_stat_logo(old_state, event);
		break;
	case UNF_RPORT_ST_CLOSING:
		next_state = unf_rport_stat_closing(old_state, event);
		break;
	case UNF_RPORT_ST_READY:
		next_state = unf_rport_stat_ready(old_state, event);
		break;
	case UNF_RPORT_ST_DELETE:
	default:
		next_state = UNF_RPORT_ST_INIT;
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_MAJOR, "[info]RPort(0x%x) hold state(0x%x)",
			     rport->nport_id, rport->rp_state);
		break;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MINOR,
		     "[info]RPort(0x%x) with oldstate(0x%x) event(0x%x) nextstate(0x%x)",
		     rport->nport_id, old_state, event, next_state);

	unf_set_rport_state(rport, next_state);
}

void unf_clean_linkdown_rport(struct unf_lport *lport)
{
	/* for L_Port's R_Port(s) */
	struct unf_disc *disc = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_rport *rport = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong disc_lock_flag = 0;
	ulong rport_lock_flag = 0;

	FC_CHECK_RETURN_VOID(lport);
	disc = &lport->disc;

	/* for each busy R_Port */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, disc_lock_flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport, entry_rport);

		/* 1. Prevent process Repeatly: Closing */
		spin_lock_irqsave(&rport->rport_state_lock, rport_lock_flag);
		if (rport->rp_state == UNF_RPORT_ST_CLOSING) {
			spin_unlock_irqrestore(&rport->rport_state_lock, rport_lock_flag);
			continue;
		}

		/* 2. Increase ref_cnt to protect R_Port */
		if (unf_rport_ref_inc(rport) != RETURN_OK) {
			spin_unlock_irqrestore(&rport->rport_state_lock, rport_lock_flag);
			continue;
		}

		/* 3. Update R_Port state: Link Down Event --->>> closing state
		 */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LINK_DOWN);

		/* 4. Put R_Port from busy to destroy list */
		list_del_init(&rport->entry_rport);
		list_add_tail(&rport->entry_rport, &disc->list_destroy_rports);

		unf_lport = rport->lport;
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_lock_flag);

		/* 5. Schedule Closing work (Enqueuing workqueue) */
		unf_schedule_closing_work(unf_lport, rport);

		/* 6. decrease R_Port ref_cnt (company with 2) */
		unf_rport_ref_dec(rport);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, disc_lock_flag);
}

void unf_rport_enter_closing(struct unf_rport *rport)
{
	/*
	 * call by
	 * 1. with RSCN processer
	 * 2. with LOGOUT processer
	 * *
	 * from
	 * 1. R_Port Link Down
	 * 2. R_Port enter LOGO
	 */
	ulong rport_lock_flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_lport *lport = NULL;
	struct unf_disc *disc = NULL;

	FC_CHECK_RETURN_VOID(rport);

	/* 1. Increase ref_cnt to protect R_Port */
	spin_lock_irqsave(&rport->rport_state_lock, rport_lock_flag);
	ret = unf_rport_ref_inc(rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&rport->rport_state_lock, rport_lock_flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) is removing and no need process",
			     rport->nport_id, rport);

		return;
	}

	/* NOTE: R_Port state has been set(with closing) */

	lport = rport->lport;
	spin_unlock_irqrestore(&rport->rport_state_lock, rport_lock_flag);

	/* 2. Put R_Port from busy to destroy list */
	disc = &lport->disc;
	spin_lock_irqsave(&disc->rport_busy_pool_lock, rport_lock_flag);
	list_del_init(&rport->entry_rport);
	list_add_tail(&rport->entry_rport, &disc->list_destroy_rports);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, rport_lock_flag);

	/* 3. Schedule Closing work (Enqueuing workqueue) */
	unf_schedule_closing_work(lport, rport);

	/* 4. dec R_Port ref_cnt */
	unf_rport_ref_dec(rport);
}

void unf_rport_error_recovery(struct unf_rport *rport)
{
	ulong delay = 0;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(rport);

	spin_lock_irqsave(&rport->rport_state_lock, flag);

	ret = unf_rport_ref_inc(rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) is removing and no need process",
			     rport->nport_id, rport);
		return;
	}

	/* Check R_Port state */
	if (rport->rp_state == UNF_RPORT_ST_CLOSING ||
	    rport->rp_state == UNF_RPORT_ST_DELETE) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]RPort(0x%x_0x%p) offline and no need process",
			     rport->nport_id, rport);

		unf_rport_ref_dec(rport);
		return;
	}

	/* Check repeatability with recovery work */
	if (delayed_work_pending(&rport->recovery_work)) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]RPort(0x%x_0x%p) recovery work is running and no need process",
			     rport->nport_id, rport);

		unf_rport_ref_dec(rport);
		return;
	}

	/* NOTE: Re-login or Logout directly (recovery work) */
	if (rport->retries < rport->max_retries) {
		rport->retries++;
		delay = UNF_DEFAULT_EDTOV / 4;

		if (queue_delayed_work(unf_wq, &rport->recovery_work,
				       (ulong)msecs_to_jiffies((u32)delay))) {
			/* Inc ref_cnt: corresponding to this work timer */
			(void)unf_rport_ref_inc(rport);
		}
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) state(0x%x) retry login failed",
			     rport->nport_id, rport, rport->rp_state);

		/* Update R_Port state: LOGO event --->>> ST_LOGO */
		unf_rport_state_ma(rport, UNF_EVENT_RPORT_LOGO);
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		unf_rport_enter_logo(rport->lport, rport);
	}

	unf_rport_ref_dec(rport);
}

static u32 unf_rport_reuse_only(struct unf_rport *rport)
{
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	ret = unf_rport_ref_inc(rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* R_Port with delete state */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) is removing and no need process",
			     rport->nport_id, rport);

		return UNF_RETURN_ERROR;
	}

	/* R_Port State check: delete */
	if (rport->rp_state == UNF_RPORT_ST_DELETE ||
	    rport->rp_state == UNF_RPORT_ST_CLOSING) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) state(0x%x) is delete or closing no need process",
			     rport->nport_id, rport, rport->rp_state);

		ret = UNF_RETURN_ERROR;
	}
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	unf_rport_ref_dec(rport);

	return ret;
}

static u32 unf_rport_reuse_recover(struct unf_rport *rport)
{
	ulong flags = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&rport->rport_state_lock, flags);
	ret = unf_rport_ref_inc(rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flags);

		/* R_Port with delete state */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) is removing and no need process",
			     rport->nport_id, rport);

		return UNF_RETURN_ERROR;
	}

	/* R_Port state check: delete */
	if (rport->rp_state == UNF_RPORT_ST_DELETE ||
	    rport->rp_state == UNF_RPORT_ST_CLOSING) {
		ret = UNF_RETURN_ERROR;
	}

	/* Update R_Port state: recovery --->>> ready */
	unf_rport_state_ma(rport, UNF_EVENT_RPORT_RECOVERY);
	spin_unlock_irqrestore(&rport->rport_state_lock, flags);

	unf_rport_ref_dec(rport);

	return ret;
}

static u32 unf_rport_reuse_init(struct unf_rport *rport)
{
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(rport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&rport->rport_state_lock, flag);
	ret = unf_rport_ref_inc(rport);
	if (ret != RETURN_OK) {
		spin_unlock_irqrestore(&rport->rport_state_lock, flag);

		/* R_Port with delete state */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]RPort(0x%x_0x%p) is removing and no need process",
			     rport->nport_id, rport);

		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]RPort(0x%x)'s state is 0x%x with use_init flag",
		     rport->nport_id, rport->rp_state);

	/* R_Port State check: delete */
	if (rport->rp_state == UNF_RPORT_ST_DELETE ||
	    rport->rp_state == UNF_RPORT_ST_CLOSING) {
		ret = UNF_RETURN_ERROR;
	} else {
		/* Update R_Port state: re-enter Init state */
		unf_set_rport_state(rport, UNF_RPORT_ST_INIT);
	}
	spin_unlock_irqrestore(&rport->rport_state_lock, flag);

	unf_rport_ref_dec(rport);

	return ret;
}

struct unf_rport *unf_get_rport_by_nport_id(struct unf_lport *lport,
					    u32 nport_id)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_rport *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	struct unf_rport *find_rport = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	unf_lport = (struct unf_lport *)lport;
	disc = &unf_lport->disc;

	/* for each r_port from rport_busy_list: compare N_Port_ID */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport, entry_rport);
		if (rport && rport->nport_id == nport_id) {
			find_rport = rport;
			break;
		}
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	return find_rport;
}

struct unf_rport *unf_get_rport_by_wwn(struct unf_lport *lport, u64 wwpn)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_rport *rport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	struct unf_rport *find_rport = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	unf_lport = (struct unf_lport *)lport;
	disc = &unf_lport->disc;

	/* for each r_port from busy_list: compare wwpn(port name) */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		rport = list_entry(node, struct unf_rport, entry_rport);
		if (rport && rport->port_name == wwpn) {
			find_rport = rport;
			break;
		}
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	return find_rport;
}

struct unf_rport *unf_get_safe_rport(struct unf_lport *lport,
				     struct unf_rport *rport,
				     enum unf_rport_reuse_flag reuse_flag,
				     u32 nport_id)
{
	/*
	 * New add or plug
	 * *
	 * retry_flogi          --->>> reuse_only
	 * name_server_register --->>> reuse_only
	 * SNS_plogi            --->>> reuse_only
	 * enter_flogi          --->>> reuse_only
	 * logout               --->>> reuse_only
	 * flogi_handler        --->>> reuse_only
	 * plogi_handler        --->>> reuse_only
	 * adisc_handler        --->>> reuse_recovery
	 * logout_handler       --->>> reuse_init
	 * prlo_handler         --->>> reuse_init
	 * login_with_loop      --->>> reuse_only
	 * gffid_callback       --->>> reuse_only
	 * delay_plogi          --->>> reuse_only
	 * gffid_rjt            --->>> reuse_only
	 * gffid_rsp_unknown    --->>> reuse_only
	 * gpnid_acc            --->>> reuse_init
	 * fdisc_callback       --->>> reuse_only
	 * flogi_acc            --->>> reuse_only
	 * plogi_acc            --->>> reuse_only
	 * logo_callback        --->>> reuse_init
	 * rffid_callback       --->>> reuse_only
	 */
#define UNF_AVOID_LINK_FLASH_TIME 3000

	struct unf_rport *unf_rport = rport;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	/* 1. Alloc New R_Port or Update R_Port Property */
	if (!unf_rport) {
		/* If NULL, get/Alloc new node (R_Port from R_Port pool)
		 * directly
		 */
		unf_rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC, nport_id);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_INFO,
			     "[info]Port(0x%x) get exist RPort(0x%x) with state(0x%x) and reuse_flag(0x%x)",
			     lport->port_id, unf_rport->nport_id,
			     unf_rport->rp_state, reuse_flag);

		switch (reuse_flag) {
		case UNF_RPORT_REUSE_ONLY:
			ret = unf_rport_reuse_only(unf_rport);
			if (ret != RETURN_OK) {
				/* R_Port within delete list: need get new */
				unf_rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC,
									nport_id);
			}
			break;

		case UNF_RPORT_REUSE_INIT:
			ret = unf_rport_reuse_init(unf_rport);
			if (ret != RETURN_OK) {
				/* R_Port within delete list: need get new */
				unf_rport = unf_rport_get_free_and_init(lport, UNF_PORT_TYPE_FC,
									nport_id);
			}
			break;

		case UNF_RPORT_REUSE_RECOVER:
			ret = unf_rport_reuse_recover(unf_rport);
			if (ret != RETURN_OK) {
				/* R_Port within delete list,
				 * NOTE: do nothing
				 */
				unf_rport = NULL;
			}
			break;

		default:
			break;
		}
	} // end else: R_Port != NULL

	return unf_rport;
}

u32 unf_get_port_feature(u64 wwpn)
{
	struct unf_rport_feature_recard *port_fea = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;
	struct list_head list_temp_node;
	struct list_head *list_busy_head = NULL;
	struct list_head *list_free_head = NULL;
	spinlock_t *feature_lock = NULL;

	list_busy_head = &port_feature_pool->list_busy_head;
	list_free_head = &port_feature_pool->list_free_head;
	feature_lock = &port_feature_pool->port_fea_pool_lock;
	spin_lock_irqsave(feature_lock, flags);
	list_for_each_safe(node, next_node, list_busy_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard, entry_feature);

		if (port_fea->wwpn == wwpn) {
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature, list_busy_head);
			spin_unlock_irqrestore(feature_lock, flags);

			return port_fea->port_feature;
		}
	}

	list_for_each_safe(node, next_node, list_free_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard, entry_feature);

		if (port_fea->wwpn == wwpn) {
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature, list_busy_head);
			spin_unlock_irqrestore(feature_lock, flags);

			return port_fea->port_feature;
		}
	}

	/* can't find wwpn */
	if (list_empty(list_free_head)) {
		/* free is empty, transport busy to free */
		list_temp_node = port_feature_pool->list_free_head;
		port_feature_pool->list_free_head = port_feature_pool->list_busy_head;
		port_feature_pool->list_busy_head = list_temp_node;
	}

	port_fea = list_entry(UNF_OS_LIST_PREV(list_free_head),
			      struct unf_rport_feature_recard,
			      entry_feature);
	list_del(&port_fea->entry_feature);
	list_add(&port_fea->entry_feature, list_busy_head);

	port_fea->wwpn = wwpn;
	port_fea->port_feature = UNF_PORT_MODE_UNKNOWN;

	spin_unlock_irqrestore(feature_lock, flags);
	return UNF_PORT_MODE_UNKNOWN;
}

void unf_update_port_feature(u64 wwpn, u32 port_feature)
{
	struct unf_rport_feature_recard *port_fea = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct list_head *busy_head = NULL;
	struct list_head *free_head = NULL;
	ulong flags = 0;
	spinlock_t *feature_lock = NULL;

	feature_lock = &port_feature_pool->port_fea_pool_lock;
	busy_head = &port_feature_pool->list_busy_head;
	free_head = &port_feature_pool->list_free_head;

	spin_lock_irqsave(feature_lock, flags);
	list_for_each_safe(node, next_node, busy_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard, entry_feature);

		if (port_fea->wwpn == wwpn) {
			port_fea->port_feature = port_feature;
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature, busy_head);
			spin_unlock_irqrestore(feature_lock, flags);

			return;
		}
	}

	list_for_each_safe(node, next_node, free_head) {
		port_fea = list_entry(node, struct unf_rport_feature_recard, entry_feature);

		if (port_fea->wwpn == wwpn) {
			port_fea->port_feature = port_feature;
			list_del(&port_fea->entry_feature);
			list_add(&port_fea->entry_feature, busy_head);

			spin_unlock_irqrestore(feature_lock, flags);

			return;
		}
	}

	spin_unlock_irqrestore(feature_lock, flags);
}
