// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_npiv_portman.h"
#include "unf_log.h"
#include "unf_common.h"
#include "unf_rport.h"
#include "unf_npiv.h"
#include "unf_portman.h"

void *unf_lookup_vport_by_index(void *lport, u16 vp_index)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	unf_lport = (struct unf_lport *)lport;

	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) vport pool is NULL", unf_lport->port_id);

		return NULL;
	}

	if (vp_index == 0 || vp_index > vport_pool->slab_total_sum) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) input vport index(0x%x) is beyond the normal range(0x1~0x%x)",
			     unf_lport->port_id, vp_index, vport_pool->slab_total_sum);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	unf_vport = unf_get_vport_by_slab_index(vport_pool, vp_index - 1);
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	return (void *)unf_vport;
}

void *unf_lookup_vport_by_portid(void *lport, u32 port_id)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	unf_lport = (struct unf_lport *)lport;
	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) vport pool is NULL", unf_lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->port_id == port_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
			return unf_vport;
		}
	}

	list_for_each_safe(node, next_node, &unf_lport->list_intergrad_vports) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->port_id == port_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
			return unf_vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) has no vport ID(0x%x).",
		     unf_lport->port_id, port_id);
	return NULL;
}

void *unf_lookup_vport_by_did(void *lport, u32 did)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	unf_lport = (struct unf_lport *)lport;
	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) vport pool is NULL", unf_lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->nport_id == did) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

			return unf_vport;
		}
	}

	list_for_each_safe(node, next_node, &unf_lport->list_intergrad_vports) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->nport_id == did) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
			return unf_vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) has no vport Nport ID(0x%x)", unf_lport->port_id, did);
	return NULL;
}

void *unf_lookup_vport_by_wwpn(void *lport, u64 wwpn)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	unf_lport = (struct unf_lport *)lport;
	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) vport pool is NULL", unf_lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->port_name == wwpn) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

			return unf_vport;
		}
	}

	list_for_each_safe(node, next_node, &unf_lport->list_intergrad_vports) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->port_name == wwpn) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
			return unf_vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) has no vport WWPN(0x%llx)",
		     unf_lport->port_id, wwpn);

	return NULL;
}

void unf_linkdown_one_vport(struct unf_lport *vport)
{
	ulong flag = 0;
	struct unf_lport *root_lport = NULL;

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_KEVENT,
		     "[info]VPort(0x%x) linkdown", vport->port_id);

	spin_lock_irqsave(&vport->lport_state_lock, flag);
	vport->link_up = UNF_PORT_LINK_DOWN;
	vport->nport_id = 0; /* set nportid 0 before send fdisc again */
	unf_lport_state_ma(vport, UNF_EVENT_LPORT_LINK_DOWN);
	spin_unlock_irqrestore(&vport->lport_state_lock, flag);

	root_lport = (struct unf_lport *)vport->root_lport;

	unf_flush_disc_event(&root_lport->disc, vport);

	unf_clean_linkdown_rport(vport);
}

void unf_linkdown_all_vports(void *lport)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport = (struct unf_lport *)lport;
	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) VPort pool is NULL", unf_lport->port_id);

		return;
	}

	/* Transfer to the transition chain */
	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		list_del_init(&unf_vport->entry_vport);
		list_add_tail(&unf_vport->entry_vport, &unf_lport->list_intergrad_vports);
		(void)unf_lport_ref_inc(unf_vport);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	while (!list_empty(&unf_lport->list_intergrad_vports)) {
		node = UNF_OS_LIST_NEXT(&unf_lport->list_intergrad_vports);
		unf_vport = list_entry(node, struct unf_lport, entry_vport);

		list_del_init(&unf_vport->entry_vport);
		list_add_tail(&unf_vport->entry_vport, &unf_lport->list_vports_head);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

		unf_linkdown_one_vport(unf_vport);

		unf_vport_ref_dec(unf_vport);

		spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);
}

int unf_process_vports_linkup(void *arg_in, void *arg_out)
{
#define UNF_WAIT_VPORT_LOGIN_ONE_TIME_MS 100
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;
	int ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(arg_in, RETURN_ERROR);

	unf_lport = (struct unf_lport *)arg_in;

	if (atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is NOP don't continue", unf_lport->port_id);

		return RETURN_OK;
	}

	if (unf_lport->link_up != UNF_PORT_LINK_UP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is not linkup don't continue.",
			     unf_lport->port_id);

		return RETURN_OK;
	}

	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) VPort pool is NULL.", unf_lport->port_id);

		return RETURN_OK;
	}

	/* Transfer to the transition chain */
	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		list_del_init(&unf_vport->entry_vport);
		list_add_tail(&unf_vport->entry_vport, &unf_lport->list_intergrad_vports);
		(void)unf_lport_ref_inc(unf_vport);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	while (!list_empty(&unf_lport->list_intergrad_vports)) {
		node = UNF_OS_LIST_NEXT(&unf_lport->list_intergrad_vports);
		unf_vport = list_entry(node, struct unf_lport, entry_vport);

		list_del_init(&unf_vport->entry_vport);
		list_add_tail(&unf_vport->entry_vport, &unf_lport->list_vports_head);
		spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

		if (atomic_read(&unf_vport->lport_no_operate_flag) == UNF_LPORT_NOP) {
			unf_vport_ref_dec(unf_vport);
			spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
			continue;
		}

		if (unf_lport->link_up == UNF_PORT_LINK_UP &&
		    unf_lport->act_topo == UNF_ACT_TOP_P2P_FABRIC) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[info]Vport(0x%x) begin login", unf_vport->port_id);

			unf_vport->link_up = UNF_PORT_LINK_UP;
			(void)unf_lport_login(unf_vport, unf_lport->act_topo);

			msleep(UNF_WAIT_VPORT_LOGIN_ONE_TIME_MS);
		} else {
			unf_linkdown_one_vport(unf_vport);

			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Vport(0x%x) login failed because root port linkdown",
				     unf_vport->port_id);
		}

		unf_vport_ref_dec(unf_vport);
		spin_lock_irqsave(&vport_pool->vport_pool_lock, flags);
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flags);

	return ret;
}

void unf_linkup_all_vports(struct unf_lport *lport)
{
	struct unf_cm_event_report *event = NULL;

	FC_CHECK_RETURN_VOID(lport);

	if (unlikely(!lport->event_mgr.unf_get_free_event_func ||
		     !lport->event_mgr.unf_post_event_func ||
		     !lport->event_mgr.unf_release_event)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) Event fun is NULL",
			     lport->port_id);
		return;
	}

	event = lport->event_mgr.unf_get_free_event_func((void *)lport);
	FC_CHECK_RETURN_VOID(event);

	event->lport = lport;
	event->event_asy_flag = UNF_EVENT_ASYN;
	event->unf_event_task = unf_process_vports_linkup;
	event->para_in = (void *)lport;

	lport->event_mgr.unf_post_event_func(lport, event);
}
