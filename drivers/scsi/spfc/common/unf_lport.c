// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_lport.h"
#include "unf_log.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_service.h"
#include "unf_ls.h"
#include "unf_gs.h"
#include "unf_portman.h"

static void unf_lport_config(struct unf_lport *lport);
void unf_cm_mark_dirty_mem(struct unf_lport *lport, enum unf_lport_dirty_flag type)
{
	FC_CHECK_RETURN_VOID((lport));

	lport->dirty_flag |= (u32)type;
}

u32 unf_init_lport_route(struct unf_lport *lport)
{
	u32 ret = RETURN_OK;
	int ret_val = 0;

	FC_CHECK_RETURN_VALUE((lport), UNF_RETURN_ERROR);

	/* Init L_Port route work */
	INIT_DELAYED_WORK(&lport->route_timer_work, unf_lport_route_work);

	/* Delay route work */
	ret_val = queue_delayed_work(unf_wq, &lport->route_timer_work,
				     (ulong)msecs_to_jiffies(UNF_LPORT_POLL_TIMER));
	if (unlikely((!(bool)(ret_val)))) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_WARN,
			     "[warn]Port(0x%x) schedule route work failed",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	ret = unf_lport_ref_inc(lport);
	return ret;
}

void unf_destroy_lport_route(struct unf_lport *lport)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);

	/* Cancel (route timer) delay work */
	UNF_DELAYED_WORK_SYNC(ret, (lport->port_id), (&lport->route_timer_work),
			      "Route Timer work");
	if (ret == RETURN_OK)
		/* Corresponding to ADD operation */
		unf_lport_ref_dec(lport);

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_2_CLOSE_ROUTE;
}

void unf_init_port_parms(struct unf_lport *lport)
{
	INIT_LIST_HEAD(&lport->list_vports_head);
	INIT_LIST_HEAD(&lport->list_intergrad_vports);
	INIT_LIST_HEAD(&lport->list_destroy_vports);
	INIT_LIST_HEAD(&lport->entry_lport);
	INIT_LIST_HEAD(&lport->list_qos_head);

	spin_lock_init(&lport->qos_mgr_lock);
	spin_lock_init(&lport->lport_state_lock);

	lport->max_frame_size = max_frame_size;
	lport->ed_tov = UNF_DEFAULT_EDTOV;
	lport->ra_tov = UNF_DEFAULT_RATOV;
	lport->fabric_node_name = 0;
	lport->qos_level = UNF_QOS_LEVEL_DEFAULT;
	lport->qos_cs_ctrl = false;
	lport->priority = (bool)UNF_PRIORITY_DISABLE;
	lport->port_dirt_exchange = false;

	unf_lport_config(lport);

	unf_set_lport_state(lport, UNF_LPORT_ST_ONLINE);

	lport->link_up = UNF_PORT_LINK_DOWN;
	lport->port_removing = false;
	lport->lport_free_completion = NULL;
	lport->last_tx_fault_jif = 0;
	lport->enhanced_features = 0;
	lport->destroy_step = INVALID_VALUE32;
	lport->dirty_flag = 0;
	lport->switch_state = false;
	lport->bbscn_support = false;
	lport->loop_back_test_mode = false;
	lport->start_work_state = UNF_START_WORK_STOP;
	lport->sfp_power_fault_count = 0;
	lport->sfp_9545_fault_count = 0;

	atomic_set(&lport->lport_no_operate_flag, UNF_LPORT_NORMAL);
	atomic_set(&lport->port_ref_cnt, 0);
	atomic_set(&lport->scsi_session_add_success, 0);
	atomic_set(&lport->scsi_session_add_failed, 0);
	atomic_set(&lport->scsi_session_del_success, 0);
	atomic_set(&lport->scsi_session_del_failed, 0);
	atomic_set(&lport->add_start_work_failed, 0);
	atomic_set(&lport->add_closing_work_failed, 0);
	atomic_set(&lport->alloc_scsi_id, 0);
	atomic_set(&lport->resume_scsi_id, 0);
	atomic_set(&lport->reuse_scsi_id, 0);
	atomic_set(&lport->device_alloc, 0);
	atomic_set(&lport->device_destroy, 0);
	atomic_set(&lport->session_loss_tmo, 0);
	atomic_set(&lport->host_no, 0);
	atomic64_set(&lport->exchg_index, 0x1000);
	atomic_inc(&lport->port_ref_cnt);

	memset(&lport->port_dynamic_info, 0, sizeof(struct unf_port_dynamic_info));
	memset(&lport->link_service_info, 0, sizeof(struct unf_link_service_collect));
	memset(&lport->err_code_sum, 0, sizeof(struct unf_err_code));
}

void unf_reset_lport_params(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = lport;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport->link_up = UNF_PORT_LINK_DOWN;
	unf_lport->nport_id = 0;
	unf_lport->max_frame_size = max_frame_size;
	unf_lport->ed_tov = UNF_DEFAULT_EDTOV;
	unf_lport->ra_tov = UNF_DEFAULT_RATOV;
	unf_lport->fabric_node_name = 0;
}

static enum unf_lport_login_state
unf_lport_state_online(enum unf_lport_login_state old_state,
		       enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_LINK_UP:
		next_state = UNF_LPORT_ST_LINK_UP;
		break;

	case UNF_EVENT_LPORT_NORMAL_ENTER:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_initial(enum unf_lport_login_state old_state,
							  enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_LINK_UP:
		next_state = UNF_LPORT_ST_LINK_UP;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_linkup(enum unf_lport_login_state old_state,
							 enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_NORMAL_ENTER:
		next_state = UNF_LPORT_ST_FLOGI_WAIT;
		break;

	case UNF_EVENT_LPORT_READY:
		next_state = UNF_LPORT_ST_READY;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_flogi_wait(enum unf_lport_login_state old_state,
							     enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		next_state = UNF_LPORT_ST_PLOGI_WAIT;
		break;

	case UNF_EVENT_LPORT_READY:
		next_state = UNF_LPORT_ST_READY;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_plogi_wait(enum unf_lport_login_state old_state,
							     enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		next_state = UNF_LPORT_ST_RFT_ID_WAIT;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state
unf_lport_state_rftid_wait(enum unf_lport_login_state old_state,
			   enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		next_state = UNF_LPORT_ST_RFF_ID_WAIT;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_rffid_wait(enum unf_lport_login_state old_state,
							     enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		next_state = UNF_LPORT_ST_SCR_WAIT;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_scr_wait(enum unf_lport_login_state old_state,
							   enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_REMOTE_ACC:
		next_state = UNF_LPORT_ST_READY;
		break;

	case UNF_EVENT_LPORT_REMOTE_TIMEOUT:
		next_state = UNF_LPORT_ST_LOGO;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state
unf_lport_state_logo(enum unf_lport_login_state old_state,
		     enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_NORMAL_ENTER:
		next_state = UNF_LPORT_ST_OFFLINE;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_offline(enum unf_lport_login_state old_state,
							  enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_ONLINE:
		next_state = UNF_LPORT_ST_ONLINE;
		break;

	case UNF_EVENT_LPORT_RESET:
		next_state = UNF_LPORT_ST_RESET;
		break;

	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_reset(enum unf_lport_login_state old_state,
							enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_NORMAL_ENTER:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static enum unf_lport_login_state unf_lport_state_ready(enum unf_lport_login_state old_state,
							enum unf_lport_event lport_event)
{
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;

	switch (lport_event) {
	case UNF_EVENT_LPORT_LINK_DOWN:
		next_state = UNF_LPORT_ST_INITIAL;
		break;

	case UNF_EVENT_LPORT_RESET:
		next_state = UNF_LPORT_ST_RESET;
		break;

	case UNF_EVENT_LPORT_OFFLINE:
		next_state = UNF_LPORT_ST_LOGO;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

static struct unf_lport_state_ma lport_state[] = {
	{UNF_LPORT_ST_ONLINE, unf_lport_state_online},
	{UNF_LPORT_ST_INITIAL, unf_lport_state_initial},
	{UNF_LPORT_ST_LINK_UP, unf_lport_state_linkup},
	{UNF_LPORT_ST_FLOGI_WAIT, unf_lport_state_flogi_wait},
	{UNF_LPORT_ST_PLOGI_WAIT, unf_lport_state_plogi_wait},
	{UNF_LPORT_ST_RFT_ID_WAIT, unf_lport_state_rftid_wait},
	{UNF_LPORT_ST_RFF_ID_WAIT, unf_lport_state_rffid_wait},
	{UNF_LPORT_ST_SCR_WAIT, unf_lport_state_scr_wait},
	{UNF_LPORT_ST_LOGO, unf_lport_state_logo},
	{UNF_LPORT_ST_OFFLINE, unf_lport_state_offline},
	{UNF_LPORT_ST_RESET, unf_lport_state_reset},
	{UNF_LPORT_ST_READY, unf_lport_state_ready},
};

void unf_lport_state_ma(struct unf_lport *lport,
			enum unf_lport_event lport_event)
{
	enum unf_lport_login_state old_state = UNF_LPORT_ST_ONLINE;
	enum unf_lport_login_state next_state = UNF_LPORT_ST_ONLINE;
	u32 index = 0;

	FC_CHECK_RETURN_VOID(lport);

	old_state = lport->states;

	while (index < (sizeof(lport_state) / sizeof(struct unf_lport_state_ma))) {
		if (lport->states == lport_state[index].lport_state) {
			next_state = lport_state[index].lport_state_ma(old_state, lport_event);
			break;
		}
		index++;
	}

	if (index >= (sizeof(lport_state) / sizeof(struct unf_lport_state_ma))) {
		next_state = old_state;
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_MAJOR, "[info]Port(0x%x) hold state(0x%x)",
			     lport->port_id, lport->states);
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) with old state(0x%x) event(0x%x) next state(0x%x)",
		     lport->port_id, old_state, lport_event, next_state);

	unf_set_lport_state(lport, next_state);
}

u32 unf_lport_retry_flogi(struct unf_lport *lport)
{
	struct unf_rport *unf_rport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* Get (new) R_Port */
	unf_rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_FLOGI);
	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY, UNF_FC_FID_FLOGI);
	if (unlikely(!unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) allocate RPort failed",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Check L_Port state */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	if (lport->states != UNF_LPORT_ST_FLOGI_WAIT) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) no need to retry FLOGI with state(0x%x)",
			     lport->port_id, lport->states);

		spin_unlock_irqrestore(&lport->lport_state_lock, flag);
		return RETURN_OK;
	}
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = UNF_FC_FID_FLOGI;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	/* Send FLOGI or FDISC */
	if (lport->root_lport != lport) {
		ret = unf_send_fdisc(lport, unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x) send FDISC failed", lport->port_id);

			/* Do L_Port recovery */
			unf_lport_error_recovery(lport);
		}
	} else {
		ret = unf_send_flogi(lport, unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x) send FLOGI failed\n", lport->port_id);

			/* Do L_Port recovery */
			unf_lport_error_recovery(lport);
		}
	}

	return ret;
}

u32 unf_lport_name_server_register(struct unf_lport *lport,
				   enum unf_lport_login_state state)
{
	struct unf_rport *unf_rport = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 fabric_id = UNF_FC_FID_DIR_SERV;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	if (state == UNF_LPORT_ST_SCR_WAIT)
		fabric_id = UNF_FC_FID_FCTRL;

	/* Get (safe) R_Port */
	unf_rport =
	    unf_get_rport_by_nport_id(lport, fabric_id);
	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY,
				       fabric_id);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) allocate RPort failed",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Update R_Port & L_Port state */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = fabric_id;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_lport_state_ma(lport, UNF_EVENT_LPORT_NORMAL_ENTER);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	switch (state) {
	/* RFT_ID */
	case UNF_LPORT_ST_RFT_ID_WAIT:
		ret = unf_send_rft_id(lport, unf_rport);
		break;
	/* RFF_ID */
	case UNF_LPORT_ST_RFF_ID_WAIT:
		ret = unf_send_rff_id(lport, unf_rport, UNF_FC4_FCP_TYPE);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x) register SCSI FC4Type to fabric(0xfffffc) failed",
				     lport->nport_id);
			unf_lport_error_recovery(lport);
		}
		break;

	/* SCR */
	case UNF_LPORT_ST_SCR_WAIT:
		ret = unf_send_scr(lport, unf_rport);
		break;

	/* PLOGI */
	case UNF_LPORT_ST_PLOGI_WAIT:
	default:
		spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
		unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
		spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

		ret = unf_send_plogi(lport, unf_rport);
		break;
	}

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) register fabric(0xfffffc) failed",
			     lport->nport_id);

		/* Do L_Port recovery */
		unf_lport_error_recovery(lport);
	}

	return ret;
}

u32 unf_lport_enter_sns_logo(struct unf_lport *lport, struct unf_rport *rport)
{
	struct unf_rport *unf_rport = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	if (!rport)
		unf_rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_DIR_SERV);
	else
		unf_rport = rport;

	if (!unf_rport) {
		spin_lock_irqsave(&lport->lport_state_lock, flag);
		unf_lport_state_ma(lport, UNF_EVENT_LPORT_NORMAL_ENTER);
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		return RETURN_OK;
	}

	/* Update L_Port & R_Port state */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_lport_state_ma(lport, UNF_EVENT_LPORT_NORMAL_ENTER);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_LOGO);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	/* Do R_Port LOGO state */
	unf_rport_enter_logo(lport, unf_rport);

	return ret;
}

void unf_lport_enter_sns_plogi(struct unf_lport *lport)
{
	/* Fabric or Public Loop Mode: Login with Name server */
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);

	/* Get (safe) R_Port */
	unf_rport = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_DIR_SERV);
	if (unf_rport) {
		/* for port swap: Delete old R_Port if necessary */
		if (unf_rport->local_nport_id != lport->nport_id) {
			unf_rport_immediate_link_down(lport, unf_rport);
			unf_rport = NULL;
		}
	}

	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY,
				       UNF_FC_FID_DIR_SERV);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) allocate RPort failed",
			     lport->port_id);

		unf_lport_error_recovery(unf_lport);
		return;
	}

	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = UNF_FC_FID_DIR_SERV;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	/* Send PLOGI to Fabric(0xfffffc) */
	ret = unf_send_plogi(unf_lport, unf_rport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]LOGIN: Port(0x%x) send PLOGI to name server failed",
			     lport->port_id);

		unf_lport_error_recovery(unf_lport);
	}
}

int unf_get_port_params(void *arg_in, void *arg_out)
{
	struct unf_lport *unf_lport = (struct unf_lport *)arg_in;
	struct unf_low_level_port_mgr_op *port_mgr = NULL;
	struct unf_port_param port_params = {0};

	FC_CHECK_RETURN_VALUE(arg_in, UNF_RETURN_ERROR);

	port_mgr = &unf_lport->low_level_func.port_mgr_op;
	if (!port_mgr->ll_port_config_get) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_WARN,
			     "[warn]Port(0x%x) low level port_config_get function is NULL",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_INFO,
		     "[warn]Port(0x%x) get parameters with default:R_A_TOV(%d) E_D_TOV(%d)",
		     unf_lport->port_id, UNF_DEFAULT_FABRIC_RATOV,
		     UNF_DEFAULT_EDTOV);

	port_params.ra_tov = UNF_DEFAULT_FABRIC_RATOV;
	port_params.ed_tov = UNF_DEFAULT_EDTOV;

	/* Update parameters with Fabric mode */
	if (unf_lport->act_topo == UNF_ACT_TOP_PUBLIC_LOOP ||
	    unf_lport->act_topo == UNF_ACT_TOP_P2P_FABRIC) {
		unf_lport->ra_tov = port_params.ra_tov;
		unf_lport->ed_tov = port_params.ed_tov;
	}

	return RETURN_OK;
}

u32 unf_lport_enter_flogi(struct unf_lport *lport)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_cm_event_report *event = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 nport_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* Get (safe) R_Port */
	nport_id = UNF_FC_FID_FLOGI;
	unf_rport = unf_get_rport_by_nport_id(lport, UNF_FC_FID_FLOGI);

	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY, nport_id);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate RPort failed",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Updtae L_Port state */
	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_lport_state_ma(lport, UNF_EVENT_LPORT_NORMAL_ENTER);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* Update R_Port N_Port_ID */
	spin_lock_irqsave(&unf_rport->rport_state_lock, flag);
	unf_rport->nport_id = UNF_FC_FID_FLOGI;
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, flag);

	event = unf_get_one_event_node(lport);
	if (event) {
		event->lport = lport;
		event->event_asy_flag = UNF_EVENT_ASYN;
		event->unf_event_task = unf_get_port_params;
		event->para_in = (void *)lport;
		unf_post_one_event_node(lport, event);
	}

	if (lport->root_lport != lport) {
		/* for NPIV */
		ret = unf_send_fdisc(lport, unf_rport);
		if (ret != RETURN_OK)
			unf_lport_error_recovery(lport);
	} else {
		/* for Physical Port */
		ret = unf_send_flogi(lport, unf_rport);
		if (ret != RETURN_OK)
			unf_lport_error_recovery(lport);
	}

	return ret;
}

void unf_set_lport_state(struct unf_lport *lport, enum unf_lport_login_state state)
{
	FC_CHECK_RETURN_VOID(lport);
	if (lport->states != state)
		lport->retries = 0;

	lport->states = state;
}

static void unf_lport_timeout(struct work_struct *work)
{
	struct unf_lport *unf_lport = NULL;
	enum unf_lport_login_state state = UNF_LPORT_ST_READY;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(work);
	unf_lport = container_of(work, struct unf_lport, retry_work.work);
	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	state = unf_lport->states;
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) is timeout with state(0x%x)",
		     unf_lport->port_id, state);
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	switch (state) {
	/* FLOGI retry */
	case UNF_LPORT_ST_FLOGI_WAIT:
		(void)unf_lport_retry_flogi(unf_lport);
		break;

	case UNF_LPORT_ST_PLOGI_WAIT:
	case UNF_LPORT_ST_RFT_ID_WAIT:
	case UNF_LPORT_ST_RFF_ID_WAIT:
	case UNF_LPORT_ST_SCR_WAIT:
		(void)unf_lport_name_server_register(unf_lport, state);
		break;

	/* Send LOGO External */
	case UNF_LPORT_ST_LOGO:
		break;

	/* Do nothing */
	case UNF_LPORT_ST_OFFLINE:
	case UNF_LPORT_ST_READY:
	case UNF_LPORT_ST_RESET:
	case UNF_LPORT_ST_ONLINE:
	case UNF_LPORT_ST_INITIAL:
	case UNF_LPORT_ST_LINK_UP:

		unf_lport->retries = 0;
		break;
	default:
		break;
	}

	unf_lport_ref_dec_to_destroy(unf_lport);
}

static void unf_lport_config(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	INIT_DELAYED_WORK(&lport->retry_work, unf_lport_timeout);

	lport->max_retry_count = UNF_MAX_RETRY_COUNT;
	lport->retries = 0;
}

void unf_lport_error_recovery(struct unf_lport *lport)
{
	ulong delay = 0;
	ulong flag = 0;
	int ret_val = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);

	ret = unf_lport_ref_inc(lport);
	if (unlikely(ret != RETURN_OK)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is removing and no need process",
			     lport->port_id);
		return;
	}

	spin_lock_irqsave(&lport->lport_state_lock, flag);

	/* Port State: removing */
	if (lport->port_removing) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is removing and no need process",
			     lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);
		return;
	}

	/* Port State: offline */
	if (lport->states == UNF_LPORT_ST_OFFLINE) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is offline and no need process",
			     lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);
		return;
	}

	/* Queue work state check */
	if (delayed_work_pending(&lport->retry_work)) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		unf_lport_ref_dec_to_destroy(lport);
		return;
	}

	/* Do retry operation */
	if (lport->retries < lport->max_retry_count) {
		lport->retries++;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x_0x%x) enter recovery and retry %u times",
			     lport->port_id, lport->nport_id, lport->retries);

		delay = (ulong)lport->ed_tov;
		ret_val = queue_delayed_work(unf_wq, &lport->retry_work,
					     (ulong)msecs_to_jiffies((u32)delay));
		if (ret_val != 0) {
			atomic_inc(&lport->port_ref_cnt);
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) queue work success and reference count is %d",
				     lport->port_id,
				     atomic_read(&lport->port_ref_cnt));
		}
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);
	} else {
		unf_lport_state_ma(lport, UNF_EVENT_LPORT_REMOTE_TIMEOUT);
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) register operation timeout and do LOGO",
			     lport->port_id);

		(void)unf_lport_enter_sns_logo(lport, NULL);
	}

	unf_lport_ref_dec_to_destroy(lport);
}

struct unf_lport *unf_cm_lookup_vport_by_vp_index(struct unf_lport *lport, u16 vp_index)
{
	FC_CHECK_RETURN_VALUE(lport, NULL);

	if (vp_index == 0)
		return lport;

	if (!lport->lport_mgr_temp.unf_look_up_vport_by_index) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) function do look up vport by index is NULL",
			     lport->port_id);

		return NULL;
	}

	return lport->lport_mgr_temp.unf_look_up_vport_by_index(lport, vp_index);
}

struct unf_lport *unf_cm_lookup_vport_by_did(struct unf_lport *lport, u32 did)
{
	FC_CHECK_RETURN_VALUE(lport, NULL);

	if (!lport->lport_mgr_temp.unf_look_up_vport_by_did) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) function do look up vport by D_ID is NULL",
			     lport->port_id);

		return NULL;
	}

	return lport->lport_mgr_temp.unf_look_up_vport_by_did(lport, did);
}

struct unf_lport *unf_cm_lookup_vport_by_wwpn(struct unf_lport *lport, u64 wwpn)
{
	FC_CHECK_RETURN_VALUE(lport, NULL);

	if (!lport->lport_mgr_temp.unf_look_up_vport_by_wwpn) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) function do look up vport by WWPN is NULL",
			     lport->port_id);

		return NULL;
	}

	return lport->lport_mgr_temp.unf_look_up_vport_by_wwpn(lport, wwpn);
}

void unf_cm_vport_remove(struct unf_lport *vport)
{
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(vport);
	unf_lport = vport->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	if (!unf_lport->lport_mgr_temp.unf_vport_remove) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) function do vport remove is NULL",
			     unf_lport->port_id);
		return;
	}

	unf_lport->lport_mgr_temp.unf_vport_remove(vport);
}
