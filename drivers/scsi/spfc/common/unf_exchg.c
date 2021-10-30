// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_exchg.h"
#include "unf_log.h"
#include "unf_common.h"
#include "unf_rport.h"
#include "unf_service.h"
#include "unf_io.h"
#include "unf_exchg_abort.h"

#define SPFC_XCHG_TYPE_MASK 0xFFFF
#define UNF_DEL_XCHG_TIMER_SAFE(xchg)                                          \
	do {                                                                   \
		if (cancel_delayed_work(&((xchg)->timeout_work))) {     \
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR, \
			    "Exchange(0x%p) is free, but timer is pending.",   \
			    xchg);                                             \
		} else {                                                       \
			FC_DRV_PRINT(UNF_LOG_IO_ATT,   \
			    UNF_CRITICAL,                                      \
			    "Exchange(0x%p) is free, but timer is running.",   \
			    xchg);                                             \
		}                                                              \
	} while (0)

static struct unf_io_flow_id io_stage_table[] = {
	    {"XCHG_ALLOC"},	 {"TGT_RECEIVE_ABTS"},
	    {"TGT_ABTS_DONE"},	 {"TGT_IO_SRR"},
	    {"SFS_RESPONSE"},	 {"SFS_TIMEOUT"},
	    {"INI_SEND_CMND"},	 {"INI_RESPONSE_DONE"},
	    {"INI_EH_ABORT"},	 {"INI_EH_DEVICE_RESET"},
	    {"INI_EH_BLS_DONE"}, {"INI_IO_TIMEOUT"},
	    {"INI_REQ_TIMEOUT"}, {"XCHG_CANCEL_TIMER"},
	    {"XCHG_FREE_XCHG"},	 {"SEND_ELS"},
	    {"IO_XCHG_WAIT"},
};

static void unf_init_xchg_attribute(struct unf_xchg *xchg);
static void unf_delay_work_del_syn(struct unf_xchg *xchg);
static void unf_free_lport_sfs_xchg(struct unf_xchg_mgr *xchg_mgr,
				    bool done_ini_flag);
static void unf_free_lport_destroy_xchg(struct unf_xchg_mgr *xchg_mgr);

void unf_wake_up_scsi_task_cmnd(struct unf_lport *lport)
{
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong hot_pool_lock_flags = 0;
	ulong xchg_flag = 0;
	struct unf_xchg_mgr *xchg_mgrs = NULL;
	u32 i;

	FC_CHECK_RETURN_VOID(lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgrs = unf_get_xchg_mgr_by_lport(lport, i);

		if (!xchg_mgrs) {
			FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MINOR,
				     "Can't find LPort(0x%x) MgrIdx %u exchange manager.",
				     lport->port_id, i);
			continue;
		}

		spin_lock_irqsave(&xchg_mgrs->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
		list_for_each_safe(node, next_node,
				   (&xchg_mgrs->hot_pool->ini_busylist)) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);

			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);
			if (INI_IO_STATE_UPTASK & xchg->io_state &&
			    (atomic_read(&xchg->ref_cnt) > 0)) {
				UNF_SET_SCSI_CMND_RESULT(xchg, UNF_IO_SUCCESS);
				up(&xchg->task_sema);
				FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MINOR,
					     "Wake up task command exchange(0x%p), Hot Pool Tag(0x%x).",
					     xchg, xchg->hotpooltag);
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);
		}

		spin_unlock_irqrestore(&xchg_mgrs->hot_pool->xchg_hotpool_lock,
				       hot_pool_lock_flags);
	}
}

void *unf_cm_get_free_xchg(void *lport, u32 xchg_type)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_cm_xchg_mgr_template *xchg_mgr_temp = NULL;

	FC_CHECK_RETURN_VALUE(unlikely(lport), NULL);

	unf_lport = (struct unf_lport *)lport;
	xchg_mgr_temp = &unf_lport->xchg_mgr_temp;

	/* Find the corresponding Lport Xchg management template. */
	FC_CHECK_RETURN_VALUE(unlikely(xchg_mgr_temp->unf_xchg_get_free_and_init), NULL);

	return xchg_mgr_temp->unf_xchg_get_free_and_init(unf_lport, xchg_type);
}

void unf_cm_free_xchg(void *lport, void *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_cm_xchg_mgr_template *xchg_mgr_temp = NULL;

	FC_CHECK_RETURN_VOID(unlikely(lport));
	FC_CHECK_RETURN_VOID(unlikely(xchg));

	unf_lport = (struct unf_lport *)lport;
	xchg_mgr_temp = &unf_lport->xchg_mgr_temp;
	FC_CHECK_RETURN_VOID(unlikely(xchg_mgr_temp->unf_xchg_release));

	/*
	 * unf_cm_free_xchg --->>> unf_free_xchg
	 * --->>> unf_xchg_ref_dec --->>> unf_free_fcp_xchg --->>>
	 * unf_done_ini_xchg
	 */
	xchg_mgr_temp->unf_xchg_release(lport, xchg);
}

void *unf_cm_lookup_xchg_by_tag(void *lport, u16 hot_pool_tag)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_cm_xchg_mgr_template *xchg_mgr_temp = NULL;

	FC_CHECK_RETURN_VALUE(unlikely(lport), NULL);

	/* Find the corresponding Lport Xchg management template */
	unf_lport = (struct unf_lport *)lport;
	xchg_mgr_temp = &unf_lport->xchg_mgr_temp;

	FC_CHECK_RETURN_VALUE(unlikely(xchg_mgr_temp->unf_look_up_xchg_by_tag), NULL);

	return xchg_mgr_temp->unf_look_up_xchg_by_tag(lport, hot_pool_tag);
}

void *unf_cm_lookup_xchg_by_id(void *lport, u16 ox_id, u32 oid)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_cm_xchg_mgr_template *xchg_mgr_temp = NULL;

	FC_CHECK_RETURN_VALUE(unlikely(lport), NULL);

	unf_lport = (struct unf_lport *)lport;
	xchg_mgr_temp = &unf_lport->xchg_mgr_temp;

	/* Find the corresponding Lport Xchg management template */
	FC_CHECK_RETURN_VALUE(unlikely(xchg_mgr_temp->unf_look_up_xchg_by_id), NULL);

	return xchg_mgr_temp->unf_look_up_xchg_by_id(lport, ox_id, oid);
}

struct unf_xchg *unf_cm_lookup_xchg_by_cmnd_sn(void *lport, u64 command_sn,
					       u32 world_id, void *pinitiator)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_cm_xchg_mgr_template *xchg_mgr_temp = NULL;
	struct unf_xchg *xchg = NULL;

	FC_CHECK_RETURN_VALUE(unlikely(lport), NULL);

	unf_lport = (struct unf_lport *)lport;
	xchg_mgr_temp = &unf_lport->xchg_mgr_temp;

	FC_CHECK_RETURN_VALUE(unlikely(xchg_mgr_temp->unf_look_up_xchg_by_cmnd_sn), NULL);

	xchg = (struct unf_xchg *)xchg_mgr_temp->unf_look_up_xchg_by_cmnd_sn(unf_lport,
										 command_sn,
										 world_id,
										 pinitiator);

	return xchg;
}

static u32 unf_init_xchg(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr,
			 u32 xchg_sum, u32 sfs_sum)
{
	struct unf_xchg *xchg_mem = NULL;
	union unf_sfs_u *sfs_mm_start = NULL;
	dma_addr_t sfs_dma_addr;
	struct unf_xchg *xchg = NULL;
	struct unf_xchg_free_pool *free_pool = NULL;
	ulong flags = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VALUE((sfs_sum <= xchg_sum), UNF_RETURN_ERROR);

	free_pool = &xchg_mgr->free_pool;
	xchg_mem = xchg_mgr->fcp_mm_start;
	xchg = xchg_mem;

	sfs_mm_start = (union unf_sfs_u *)xchg_mgr->sfs_mm_start;
	sfs_dma_addr = xchg_mgr->sfs_phy_addr;
	/* 1. Allocate the SFS UNION memory to each SFS XCHG
	 * and mount the SFS XCHG to the corresponding FREE linked list
	 */
	free_pool->total_sfs_xchg = 0;
	free_pool->sfs_xchg_sum = sfs_sum;
	for (i = 0; i < sfs_sum; i++) {
		INIT_LIST_HEAD(&xchg->list_xchg_entry);
		INIT_LIST_HEAD(&xchg->list_esgls);
		spin_lock_init(&xchg->xchg_state_lock);
		sema_init(&xchg->task_sema, 0);
		sema_init(&xchg->echo_info.echo_sync_sema, 0);

		spin_lock_irqsave(&free_pool->xchg_freepool_lock, flags);
		xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr = sfs_mm_start;
		xchg->fcp_sfs_union.sfs_entry.sfs_buff_phy_addr = sfs_dma_addr;
		xchg->fcp_sfs_union.sfs_entry.sfs_buff_len = sizeof(*sfs_mm_start);
		list_add_tail(&xchg->list_xchg_entry, &free_pool->list_sfs_xchg_list);
		free_pool->total_sfs_xchg++;
		spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);

		sfs_mm_start++;
		sfs_dma_addr = sfs_dma_addr + sizeof(union unf_sfs_u);
		xchg++;
	}

	free_pool->total_fcp_xchg = 0;

	for (i = 0; (i < xchg_sum - sfs_sum); i++) {
		INIT_LIST_HEAD(&xchg->list_xchg_entry);

		INIT_LIST_HEAD(&xchg->list_esgls);
		spin_lock_init(&xchg->xchg_state_lock);
		sema_init(&xchg->task_sema, 0);
		sema_init(&xchg->echo_info.echo_sync_sema, 0);

		/* alloc dma buffer for fcp_rsp_iu */
		spin_lock_irqsave(&free_pool->xchg_freepool_lock, flags);
		list_add_tail(&xchg->list_xchg_entry, &free_pool->list_free_xchg_list);
		free_pool->total_fcp_xchg++;
		spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);

		xchg++;
	}

	free_pool->fcp_xchg_sum = free_pool->total_fcp_xchg;

	return RETURN_OK;
}

static u32 unf_get_xchg_config_sum(struct unf_lport *lport, u32 *xchg_sum)
{
	struct unf_lport_cfg_item *lport_cfg_items = NULL;

	lport_cfg_items = &lport->low_level_func.lport_cfg_items;

	/* It has been checked at the bottom layer. Don't need to check it
	 * again.
	 */
	*xchg_sum = lport_cfg_items->max_sfs_xchg + lport_cfg_items->max_io;
	if ((*xchg_sum / UNF_EXCHG_MGR_NUM) == 0 ||
	    lport_cfg_items->max_sfs_xchg / UNF_EXCHG_MGR_NUM == 0) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) Xchgsum(%u) or SfsXchg(%u) is less than ExchangeMgrNum(%u).",
			     lport->port_id, *xchg_sum, lport_cfg_items->max_sfs_xchg,
			     UNF_EXCHG_MGR_NUM);
		return UNF_RETURN_ERROR;
	}

	if (*xchg_sum > (INVALID_VALUE16 - 1)) {
		/* If the format of ox_id/rx_id is exceeded, this function is
		 * not supported
		 */
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) Exchange num(0x%x) is Too Big.",
			     lport->port_id, *xchg_sum);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static void unf_xchg_cancel_timer(void *xchg)
{
	struct unf_xchg *tmp_xchg = NULL;
	bool need_dec_xchg_ref = false;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);
	tmp_xchg = (struct unf_xchg *)xchg;

	spin_lock_irqsave(&tmp_xchg->xchg_state_lock, flag);
	if (cancel_delayed_work(&tmp_xchg->timeout_work))
		need_dec_xchg_ref = true;

	spin_unlock_irqrestore(&tmp_xchg->xchg_state_lock, flag);

	if (need_dec_xchg_ref)
		unf_xchg_ref_dec(xchg, XCHG_CANCEL_TIMER);
}

void unf_show_all_xchg(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *xchg = NULL;
	struct list_head *xchg_node = NULL;
	struct list_head *next_xchg_node = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(xchg_mgr);

	unf_lport = lport;

	/* hot Xchg */
	spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, flags);

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN, "INI busy :");
	list_for_each_safe(xchg_node, next_xchg_node, &xchg_mgr->hot_pool->ini_busylist) {
		xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
			     "0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
			     xchg, (u32)xchg->hotpooltag, (u32)xchg->xchg_type,
			     (u32)xchg->oxid, (u32)xchg->rxid, (u32)xchg->sid, (u32)xchg->did,
			     atomic_read(&xchg->ref_cnt), (u32)xchg->io_state, xchg->alloc_jif);
	}

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN, "SFS :");
	list_for_each_safe(xchg_node, next_xchg_node, &xchg_mgr->hot_pool->sfs_busylist) {
		xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
			     "0x%p---0x%x---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
			     xchg, xchg->cmnd_code, (u32)xchg->hotpooltag,
			     (u32)xchg->xchg_type, (u32)xchg->oxid, (u32)xchg->rxid, (u32)xchg->sid,
			     (u32)xchg->did, atomic_read(&xchg->ref_cnt),
			     (u32)xchg->io_state, xchg->alloc_jif);
	}

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN, "Destroy list.");
	list_for_each_safe(xchg_node, next_xchg_node, &xchg_mgr->hot_pool->list_destroy_xchg) {
		xchg = list_entry(xchg_node, struct unf_xchg, list_xchg_entry);
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
			     "0x%p---0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----0x%x----%llu.",
			     xchg, (u32)xchg->hotpooltag, (u32)xchg->xchg_type,
			     (u32)xchg->oxid, (u32)xchg->rxid, (u32)xchg->sid, (u32)xchg->did,
			     atomic_read(&xchg->ref_cnt), (u32)xchg->io_state, xchg->alloc_jif);
	}
	spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock, flags);
}

static u32 unf_free_lport_xchg(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr)
{
#define UNF_OS_WAITIO_TIMEOUT (10 * 1000)

	ulong free_pool_lock_flags = 0;
	bool wait = false;
	u32 total_xchg = 0;
	u32 total_xchg_sum = 0;
	u32 ret = RETURN_OK;
	u64 time_out = 0;
	struct completion xchg_mgr_completion;

	init_completion(&xchg_mgr_completion);
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg_mgr, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg_mgr->hot_pool, UNF_RETURN_ERROR);

	unf_free_lport_sfs_xchg(xchg_mgr, false);

	/* free INI Mode exchanges belong to L_Port */
	unf_free_lport_ini_xchg(xchg_mgr, false);

	spin_lock_irqsave(&xchg_mgr->free_pool.xchg_freepool_lock, free_pool_lock_flags);
	total_xchg = xchg_mgr->free_pool.total_fcp_xchg + xchg_mgr->free_pool.total_sfs_xchg;
	total_xchg_sum = xchg_mgr->free_pool.fcp_xchg_sum + xchg_mgr->free_pool.sfs_xchg_sum;
	if (total_xchg != total_xchg_sum) {
		xchg_mgr->free_pool.xchg_mgr_completion = &xchg_mgr_completion;
		wait = true;
	}
	spin_unlock_irqrestore(&xchg_mgr->free_pool.xchg_freepool_lock, free_pool_lock_flags);

	if (wait) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) begin to wait for exchange manager completion (0x%x:0x%x)",
			     lport->port_id, total_xchg, total_xchg_sum);

		unf_show_all_xchg(lport, xchg_mgr);

		time_out = wait_for_completion_timeout(xchg_mgr->free_pool.xchg_mgr_completion,
						       msecs_to_jiffies(UNF_OS_WAITIO_TIMEOUT));
		if (time_out == 0)
			unf_free_lport_destroy_xchg(xchg_mgr);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) wait for exchange manager completion end",
			     lport->port_id);

		spin_lock_irqsave(&xchg_mgr->free_pool.xchg_freepool_lock, free_pool_lock_flags);
		xchg_mgr->free_pool.xchg_mgr_completion = NULL;
		spin_unlock_irqrestore(&xchg_mgr->free_pool.xchg_freepool_lock,
				       free_pool_lock_flags);
	}

	return ret;
}

void unf_free_lport_all_xchg(struct unf_lport *lport)
{
	struct unf_xchg_mgr *xchg_mgr = NULL;
	u32 i;

	FC_CHECK_RETURN_VOID(lport);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = unf_get_xchg_mgr_by_lport(lport, i);
		;
		if (unlikely(!xchg_mgr)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Port(0x%x) hot pool is NULL",
				     lport->port_id);

			continue;
		}
		unf_free_lport_sfs_xchg(xchg_mgr, false);

		/* free INI Mode exchanges belong to L_Port */
		unf_free_lport_ini_xchg(xchg_mgr, false);

		unf_free_lport_destroy_xchg(xchg_mgr);
	}
}

static void unf_delay_work_del_syn(struct unf_xchg *xchg)
{
	FC_CHECK_RETURN_VOID(xchg);

	/* synchronous release timer */
	if (!cancel_delayed_work_sync(&xchg->timeout_work)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Exchange(0x%p), State(0x%x) can't delete work timer, timer is running or no timer.",
			     xchg, xchg->io_state);
	} else {
		/* The reference count cannot be directly subtracted.
		 * This prevents the XCHG from being moved to the Free linked
		 * list when the card is unloaded.
		 */
		unf_cm_free_xchg(xchg->lport, xchg);
	}
}

static void unf_free_lport_sfs_xchg(struct unf_xchg_mgr *xchg_mgr, bool done_ini_flag)
{
	struct list_head *list = NULL;
	struct unf_xchg *xchg = NULL;
	ulong hot_pool_lock_flags = 0;

	FC_CHECK_RETURN_VOID(xchg_mgr);
	FC_CHECK_RETURN_VOID(xchg_mgr->hot_pool);

	spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
	while (!list_empty(&xchg_mgr->hot_pool->sfs_busylist)) {
		list = UNF_OS_LIST_NEXT(&xchg_mgr->hot_pool->sfs_busylist);
		list_del_init(list);

		/* Prevent the xchg of the sfs from being accessed repeatedly.
		 * The xchg is first mounted to the destroy linked list.
		 */
		list_add_tail(list, &xchg_mgr->hot_pool->list_destroy_xchg);

		xchg = list_entry(list, struct unf_xchg, list_xchg_entry);
		spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
		unf_delay_work_del_syn(xchg);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Free SFS Exchange(0x%p), State(0x%x), Reference count(%d), Start time(%llu).",
			     xchg, xchg->io_state, atomic_read(&xchg->ref_cnt), xchg->alloc_jif);

		unf_cm_free_xchg(xchg->lport, xchg);

		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
	}
	spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
}

void unf_free_lport_ini_xchg(struct unf_xchg_mgr *xchg_mgr, bool done_ini_flag)
{
	struct list_head *list = NULL;
	struct unf_xchg *xchg = NULL;
	ulong hot_pool_lock_flags = 0;
	u32 up_status = 0;

	FC_CHECK_RETURN_VOID(xchg_mgr);
	FC_CHECK_RETURN_VOID(xchg_mgr->hot_pool);

	spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
	while (!list_empty(&xchg_mgr->hot_pool->ini_busylist)) {
		/* for each INI busy_list (exchange) node */
		list = UNF_OS_LIST_NEXT(&xchg_mgr->hot_pool->ini_busylist);

		/* Put exchange node to destroy_list, prevent done repeatly */
		list_del_init(list);
		list_add_tail(list, &xchg_mgr->hot_pool->list_destroy_xchg);
		xchg = list_entry(list, struct unf_xchg, list_xchg_entry);
		if (atomic_read(&xchg->ref_cnt) <= 0)
			continue;

		spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock,
				       hot_pool_lock_flags);
		unf_delay_work_del_syn(xchg);

		/* In the case of INI done, the command should be set to fail to
		 * prevent data inconsistency caused by the return of OK
		 */
		up_status = unf_get_up_level_cmnd_errcode(xchg->scsi_cmnd_info.err_code_table,
							  xchg->scsi_cmnd_info.err_code_table_cout,
							  UNF_IO_PORT_LOGOUT);

		if (INI_IO_STATE_UPABORT & xchg->io_state) {
			/*
			 * About L_Port destroy:
			 * UP_ABORT ---to--->>> ABORT_Port_Removing
			 */
			up_status = UNF_IO_ABORT_PORT_REMOVING;
		}

		xchg->scsi_cmnd_info.result = up_status;
		up(&xchg->task_sema);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Free INI exchange(0x%p) state(0x%x) reference count(%d) start time(%llu)",
			     xchg, xchg->io_state, atomic_read(&xchg->ref_cnt), xchg->alloc_jif);

		unf_cm_free_xchg(xchg->lport, xchg);

		/* go to next INI busy_list (exchange) node */
		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
	}
	spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
}

static void unf_free_lport_destroy_xchg(struct unf_xchg_mgr *xchg_mgr)
{
#define UNF_WAIT_DESTROY_EMPTY_STEP_MS 1000
#define UNF_WAIT_IO_STATE_TGT_FRONT_MS (10 * 1000)

	struct unf_xchg *xchg = NULL;
	struct list_head *next_xchg_node = NULL;
	ulong hot_pool_lock_flags = 0;
	ulong xchg_flag = 0;

	FC_CHECK_RETURN_VOID(xchg_mgr);
	FC_CHECK_RETURN_VOID(xchg_mgr->hot_pool);

	/* In this case, the timer on the destroy linked list is deleted.
	 * You only need to check whether the timer is released at the end of
	 * the tgt.
	 */
	spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
	while (!list_empty(&xchg_mgr->hot_pool->list_destroy_xchg)) {
		next_xchg_node = UNF_OS_LIST_NEXT(&xchg_mgr->hot_pool->list_destroy_xchg);
		xchg = list_entry(next_xchg_node, struct unf_xchg, list_xchg_entry);

		spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flag);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Free Exchange(0x%p), Type(0x%x), State(0x%x), Reference count(%d), Start time(%llu)",
			     xchg, xchg->xchg_type, xchg->io_state,
			     atomic_read(&xchg->ref_cnt), xchg->alloc_jif);

		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flag);
		spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);

		/* This interface can be invoked to ensure that the timer is
		 * successfully canceled or wait until the timer execution is
		 * complete
		 */
		unf_delay_work_del_syn(xchg);

		/*
		 * If the timer is canceled successfully, delete Xchg
		 * If the timer has burst, the Xchg may have been released,In
		 * this case, deleting the Xchg will be failed
		 */
		unf_cm_free_xchg(xchg->lport, xchg);

		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
	};

	spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock, hot_pool_lock_flags);
}

static void unf_free_all_big_sfs(struct unf_xchg_mgr *xchg_mgr)
{
	struct unf_big_sfs *big_sfs = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	u32 i;

	FC_CHECK_RETURN_VOID(xchg_mgr);

	/* Release the free resources in the busy state */
	spin_lock_irqsave(&xchg_mgr->big_sfs_pool.big_sfs_pool_lock, flag);
	list_for_each_safe(node, next_node, &xchg_mgr->big_sfs_pool.list_busypool) {
		list_del(node);
		list_add_tail(node, &xchg_mgr->big_sfs_pool.list_freepool);
	}

	list_for_each_safe(node, next_node, &xchg_mgr->big_sfs_pool.list_freepool) {
		list_del(node);
		big_sfs = list_entry(node, struct unf_big_sfs, entry_bigsfs);
		if (big_sfs->addr)
			big_sfs->addr = NULL;
	}
	spin_unlock_irqrestore(&xchg_mgr->big_sfs_pool.big_sfs_pool_lock, flag);

	if (xchg_mgr->big_sfs_buf_list.buflist) {
		for (i = 0; i < xchg_mgr->big_sfs_buf_list.buf_num; i++) {
			kfree(xchg_mgr->big_sfs_buf_list.buflist[i].vaddr);
			xchg_mgr->big_sfs_buf_list.buflist[i].vaddr = NULL;
		}

		kfree(xchg_mgr->big_sfs_buf_list.buflist);
		xchg_mgr->big_sfs_buf_list.buflist = NULL;
	}
}

static void unf_free_big_sfs_pool(struct unf_xchg_mgr *xchg_mgr)
{
	FC_CHECK_RETURN_VOID(xchg_mgr);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Free Big SFS Pool, Count(0x%x).",
		     xchg_mgr->big_sfs_pool.free_count);

	unf_free_all_big_sfs(xchg_mgr);
	xchg_mgr->big_sfs_pool.free_count = 0;

	if (xchg_mgr->big_sfs_pool.big_sfs_pool) {
		vfree(xchg_mgr->big_sfs_pool.big_sfs_pool);
		xchg_mgr->big_sfs_pool.big_sfs_pool = NULL;
	}
}

static void unf_free_xchg_mgr_mem(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr)
{
	struct unf_xchg *xchg = NULL;
	u32 i = 0;
	u32 xchg_sum = 0;
	struct unf_xchg_free_pool *free_pool = NULL;

	FC_CHECK_RETURN_VOID(xchg_mgr);

	unf_free_big_sfs_pool(xchg_mgr);

	/* The sfs is released first, and the XchgMgr is allocated by the get
	 * free page. Therefore, the XchgMgr is compared with the '0'
	 */
	if (xchg_mgr->sfs_mm_start != 0) {
		dma_free_coherent(&lport->low_level_func.dev->dev, xchg_mgr->sfs_mem_size,
				  xchg_mgr->sfs_mm_start, xchg_mgr->sfs_phy_addr);
		xchg_mgr->sfs_mm_start = 0;
	}

	/* Release Xchg first */
	if (xchg_mgr->fcp_mm_start) {
		unf_get_xchg_config_sum(lport, &xchg_sum);
		xchg_sum = xchg_sum / UNF_EXCHG_MGR_NUM;

		xchg = xchg_mgr->fcp_mm_start;
		for (i = 0; i < xchg_sum; i++) {
			if (!xchg)
				break;
			xchg++;
		}

		vfree(xchg_mgr->fcp_mm_start);
		xchg_mgr->fcp_mm_start = NULL;
	}

	/* release the hot pool */
	if (xchg_mgr->hot_pool) {
		vfree(xchg_mgr->hot_pool);
		xchg_mgr->hot_pool = NULL;
	}

	free_pool = &xchg_mgr->free_pool;

	vfree(xchg_mgr);
}

static void unf_free_xchg_mgr(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr)
{
	ulong flags = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(xchg_mgr);

	/* 1. At first, free exchanges for this Exch_Mgr */
	ret = unf_free_lport_xchg(lport, xchg_mgr);

	/* 2. Delete this Exch_Mgr entry */
	spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
	list_del_init(&xchg_mgr->xchg_mgr_entry);
	spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

	/* 3. free Exch_Mgr memory if necessary */
	if (ret == RETURN_OK) {
		/* free memory directly */
		unf_free_xchg_mgr_mem(lport, xchg_mgr);
	} else {
		/* Add it to Dirty list */
		spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
		list_add_tail(&xchg_mgr->xchg_mgr_entry, &lport->list_drty_xchg_mgr_head);
		spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

		/* Mark dirty flag */
		unf_cm_mark_dirty_mem(lport, UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY);
	}
}

void unf_free_all_xchg_mgr(struct unf_lport *lport)
{
	struct unf_xchg_mgr *xchg_mgr = NULL;
	ulong flags = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VOID(lport);

	/* for each L_Port->Exch_Mgr_List */
	spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
	while (!list_empty(&lport->list_xchg_mgr_head)) {
		spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

		xchg_mgr = unf_get_xchg_mgr_by_lport(lport, i);
		unf_free_xchg_mgr(lport, xchg_mgr);
		if (i < UNF_EXCHG_MGR_NUM)
			lport->xchg_mgr[i] = NULL;

		i++;

		/* go to next */
		spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
	}
	spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_4_DESTROY_EXCH_MGR;
}

static u32 unf_init_xchg_mgr(struct unf_xchg_mgr *xchg_mgr)
{
	FC_CHECK_RETURN_VALUE(xchg_mgr, UNF_RETURN_ERROR);

	memset(xchg_mgr, 0, sizeof(struct unf_xchg_mgr));

	INIT_LIST_HEAD(&xchg_mgr->xchg_mgr_entry);
	xchg_mgr->fcp_mm_start = NULL;
	xchg_mgr->mem_szie = sizeof(struct unf_xchg_mgr);

	return RETURN_OK;
}

static u32 unf_init_xchg_mgr_free_pool(struct unf_xchg_mgr *xchg_mgr)
{
	struct unf_xchg_free_pool *free_pool = NULL;

	FC_CHECK_RETURN_VALUE(xchg_mgr, UNF_RETURN_ERROR);

	free_pool = &xchg_mgr->free_pool;
	INIT_LIST_HEAD(&free_pool->list_free_xchg_list);
	INIT_LIST_HEAD(&free_pool->list_sfs_xchg_list);
	spin_lock_init(&free_pool->xchg_freepool_lock);
	free_pool->fcp_xchg_sum = 0;
	free_pool->xchg_mgr_completion = NULL;

	return RETURN_OK;
}

static u32 unf_init_xchg_hot_pool(struct unf_lport *lport, struct unf_xchg_hot_pool *hot_pool,
				  u32 xchg_sum)
{
	FC_CHECK_RETURN_VALUE(hot_pool, UNF_RETURN_ERROR);

	INIT_LIST_HEAD(&hot_pool->sfs_busylist);
	INIT_LIST_HEAD(&hot_pool->ini_busylist);
	spin_lock_init(&hot_pool->xchg_hotpool_lock);
	INIT_LIST_HEAD(&hot_pool->list_destroy_xchg);
	hot_pool->total_xchges = 0;
	hot_pool->wait_state = false;
	hot_pool->lport = lport;

	/* Slab Pool Index */
	hot_pool->slab_next_index = 0;
	UNF_TOU16_CHECK(hot_pool->slab_total_sum, xchg_sum, return UNF_RETURN_ERROR);

	return RETURN_OK;
}

static u32 unf_alloc_and_init_big_sfs_pool(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr)
{
#define UNF_MAX_RESOURCE_RESERVED_FOR_RSCN 20
#define UNF_BIG_SFS_POOL_TYPES 6
	u32 i = 0;
	u32 size = 0;
	u32 align_size = 0;
	u32 npiv_cnt = 0;
	struct unf_big_sfs_pool *big_sfs_pool = NULL;
	struct unf_big_sfs *big_sfs_buff = NULL;
	u32 buf_total_size;
	u32 buf_num;
	u32 buf_cnt_per_huge_buf;
	u32 alloc_idx;
	u32 cur_buf_idx = 0;
	u32 cur_buf_offset = 0;

	FC_CHECK_RETURN_VALUE(xchg_mgr, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	big_sfs_pool = &xchg_mgr->big_sfs_pool;

	INIT_LIST_HEAD(&big_sfs_pool->list_freepool);
	INIT_LIST_HEAD(&big_sfs_pool->list_busypool);
	spin_lock_init(&big_sfs_pool->big_sfs_pool_lock);
	npiv_cnt = lport->low_level_func.support_max_npiv_num;

	/*
	 * The value*6 indicates GID_PT/GID_FT, RSCN, and ECHO
	 * Another command is received when a command is being responded
	 * A maximum of 20 resources are reserved for the RSCN. During the test,
	 * multiple rscn are found. As a result, the resources are insufficient
	 * and the disc fails.
	 */
	big_sfs_pool->free_count = (npiv_cnt + 1) * UNF_BIG_SFS_POOL_TYPES +
				   UNF_MAX_RESOURCE_RESERVED_FOR_RSCN;
	big_sfs_buff =
	    (struct unf_big_sfs *)vmalloc(big_sfs_pool->free_count * sizeof(struct unf_big_sfs));
	if (!big_sfs_buff) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Allocate Big SFS buf fail.");

		return UNF_RETURN_ERROR;
	}
	memset(big_sfs_buff, 0, big_sfs_pool->free_count * sizeof(struct unf_big_sfs));
	xchg_mgr->mem_szie += (u32)(big_sfs_pool->free_count * sizeof(struct unf_big_sfs));
	big_sfs_pool->big_sfs_pool = (void *)big_sfs_buff;

	/*
	 * Use the larger value of sizeof (struct unf_gid_acc_pld) and sizeof
	 * (struct unf_rscn_pld) to avoid the icp error.Therefore, the value is
	 * directly assigned instead of being compared.
	 */
	size = sizeof(struct unf_gid_acc_pld);
	align_size = ALIGN(size, PAGE_SIZE);

	buf_total_size = align_size * big_sfs_pool->free_count;
	xchg_mgr->big_sfs_buf_list.buf_size =
	    buf_total_size > BUF_LIST_PAGE_SIZE ? BUF_LIST_PAGE_SIZE
						: buf_total_size;

	buf_cnt_per_huge_buf = xchg_mgr->big_sfs_buf_list.buf_size / align_size;
	buf_num = big_sfs_pool->free_count % buf_cnt_per_huge_buf
		      ? big_sfs_pool->free_count / buf_cnt_per_huge_buf + 1
		      : big_sfs_pool->free_count / buf_cnt_per_huge_buf;

	xchg_mgr->big_sfs_buf_list.buflist = (struct buff_list *)kmalloc(buf_num *
						sizeof(struct buff_list), GFP_KERNEL);
	xchg_mgr->big_sfs_buf_list.buf_num = buf_num;

	if (!xchg_mgr->big_sfs_buf_list.buflist) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate BigSfs pool buf list failed out of memory");
		goto free_buff;
	}
	memset(xchg_mgr->big_sfs_buf_list.buflist, 0, buf_num * sizeof(struct buff_list));
	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		xchg_mgr->big_sfs_buf_list.buflist[alloc_idx].vaddr =
		    kmalloc(xchg_mgr->big_sfs_buf_list.buf_size, GFP_ATOMIC);
		if (xchg_mgr->big_sfs_buf_list.buflist[alloc_idx].vaddr ==
		    NULL) {
			goto free_buff;
		}
		memset(xchg_mgr->big_sfs_buf_list.buflist[alloc_idx].vaddr, 0,
		       xchg_mgr->big_sfs_buf_list.buf_size);
	}

	for (i = 0; i < big_sfs_pool->free_count; i++) {
		if (i != 0 && !(i % buf_cnt_per_huge_buf))
			cur_buf_idx++;

		cur_buf_offset = align_size * (i % buf_cnt_per_huge_buf);
		big_sfs_buff->addr = xchg_mgr->big_sfs_buf_list.buflist[cur_buf_idx].vaddr +
		    cur_buf_offset;
		big_sfs_buff->size = size;
		xchg_mgr->mem_szie += size;
		list_add_tail(&big_sfs_buff->entry_bigsfs, &big_sfs_pool->list_freepool);
		big_sfs_buff++;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[EVENT]Allocate BigSfs pool size:%d,align_size:%d,buf_num:%u,buf_size:%u",
		     size, align_size, xchg_mgr->big_sfs_buf_list.buf_num,
		     xchg_mgr->big_sfs_buf_list.buf_size);
	return RETURN_OK;
free_buff:
	unf_free_all_big_sfs(xchg_mgr);
	vfree(big_sfs_buff);
	big_sfs_pool->big_sfs_pool = NULL;
	return UNF_RETURN_ERROR;
}

static void unf_free_one_big_sfs(struct unf_xchg *xchg)
{
	ulong flag = 0;
	struct unf_xchg_mgr *xchg_mgr = NULL;

	FC_CHECK_RETURN_VOID(xchg);
	xchg_mgr = xchg->xchg_mgr;
	FC_CHECK_RETURN_VOID(xchg_mgr);
	if (!xchg->big_sfs_buf)
		return;

	if (xchg->cmnd_code != NS_GID_PT && xchg->cmnd_code != NS_GID_FT &&
	    xchg->cmnd_code != ELS_ECHO &&
	    xchg->cmnd_code != (UNF_SET_ELS_ACC_TYPE(ELS_ECHO)) && xchg->cmnd_code != ELS_RSCN &&
	    xchg->cmnd_code != (UNF_SET_ELS_ACC_TYPE(ELS_RSCN))) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "Exchange(0x%p), Command(0x%x) big SFS buf is not NULL.",
			     xchg, xchg->cmnd_code);
	}

	spin_lock_irqsave(&xchg_mgr->big_sfs_pool.big_sfs_pool_lock, flag);
	list_del(&xchg->big_sfs_buf->entry_bigsfs);
	list_add_tail(&xchg->big_sfs_buf->entry_bigsfs,
		      &xchg_mgr->big_sfs_pool.list_freepool);
	xchg_mgr->big_sfs_pool.free_count++;
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "Free one big SFS buf(0x%p), Count(0x%x), Exchange(0x%p), Command(0x%x).",
		     xchg->big_sfs_buf->addr, xchg_mgr->big_sfs_pool.free_count,
		     xchg, xchg->cmnd_code);
	spin_unlock_irqrestore(&xchg_mgr->big_sfs_pool.big_sfs_pool_lock, flag);
}

static void unf_free_exchg_mgr_info(struct unf_lport *lport)
{
	u32 i;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;
	struct unf_xchg_mgr *xchg_mgr = NULL;

	spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
	list_for_each_safe(node, next_node, &lport->list_xchg_mgr_head) {
		list_del(node);
		xchg_mgr = list_entry(node, struct unf_xchg_mgr, xchg_mgr_entry);
	}
	spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = lport->xchg_mgr[i];

		if (xchg_mgr) {
			unf_free_big_sfs_pool(xchg_mgr);

			if (xchg_mgr->sfs_mm_start) {
				dma_free_coherent(&lport->low_level_func.dev->dev,
						  xchg_mgr->sfs_mem_size, xchg_mgr->sfs_mm_start,
						  xchg_mgr->sfs_phy_addr);
				xchg_mgr->sfs_mm_start = 0;
			}

			if (xchg_mgr->fcp_mm_start) {
				vfree(xchg_mgr->fcp_mm_start);
				xchg_mgr->fcp_mm_start = NULL;
			}

			if (xchg_mgr->hot_pool) {
				vfree(xchg_mgr->hot_pool);
				xchg_mgr->hot_pool = NULL;
			}

			vfree(xchg_mgr);
			lport->xchg_mgr[i] = NULL;
		}
	}
}

static u32 unf_alloc_and_init_xchg_mgr(struct unf_lport *lport)
{
	struct unf_xchg_mgr *xchg_mgr = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct unf_xchg *xchg_mem = NULL;
	void *sfs_mm_start = 0;
	dma_addr_t sfs_phy_addr = 0;
	u32 xchg_sum = 0;
	u32 sfs_xchg_sum = 0;
	ulong flags = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 slab_num = 0;
	u32 i = 0;

	ret = unf_get_xchg_config_sum(lport, &xchg_sum);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) can't get Exchange.", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* SFS Exchange Sum */
	sfs_xchg_sum = lport->low_level_func.lport_cfg_items.max_sfs_xchg /
		       UNF_EXCHG_MGR_NUM;
	xchg_sum = xchg_sum / UNF_EXCHG_MGR_NUM;
	slab_num = lport->low_level_func.support_max_hot_tag_range / UNF_EXCHG_MGR_NUM;
	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		/* Alloc Exchange Manager */
		xchg_mgr = (struct unf_xchg_mgr *)vmalloc(sizeof(struct unf_xchg_mgr));
		if (!xchg_mgr) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "Port(0x%x) allocate Exchange Manager Memory Fail.",
				     lport->port_id);
			goto exit;
		}

		/* Init Exchange Manager */
		ret = unf_init_xchg_mgr(xchg_mgr);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
				     "Port(0x%x) initialization Exchange Manager  unsuccessful.",
				     lport->port_id);
			goto free_xchg_mgr;
		}

		/* Initialize the Exchange Free Pool resource */
		ret = unf_init_xchg_mgr_free_pool(xchg_mgr);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
				     "Port(0x%x) initialization Exchange Manager Free Pool  unsuccessful.",
				     lport->port_id);
			goto free_xchg_mgr;
		}

		/* Allocate memory for Hot Pool and Xchg slab */
		hot_pool = vmalloc(sizeof(struct unf_xchg_hot_pool) +
					  sizeof(struct unf_xchg *) * slab_num);
		if (!hot_pool) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "Port(0x%x) allocate Hot Pool Memory Fail.",
				     lport->port_id);
			goto free_xchg_mgr;
		}
		memset(hot_pool, 0,
		       sizeof(struct unf_xchg_hot_pool) + sizeof(struct unf_xchg *) * slab_num);

		xchg_mgr->mem_szie += (u32)(sizeof(struct unf_xchg_hot_pool) +
			  sizeof(struct unf_xchg *) * slab_num);
		/* Initialize the Exchange Hot Pool resource */
		ret = unf_init_xchg_hot_pool(lport, hot_pool, slab_num);
		if (ret != RETURN_OK)
			goto free_hot_pool;

		hot_pool->base += (u16)(i * slab_num);
		/* Allocate the memory of all Xchg (IO/SFS) */
		xchg_mem = vmalloc(sizeof(struct unf_xchg) * xchg_sum);
		if (!xchg_mem) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "Port(0x%x) allocate Exchange Memory Fail.",
				     lport->port_id);
			goto free_hot_pool;
		}
		memset(xchg_mem, 0, sizeof(struct unf_xchg) * xchg_sum);

		xchg_mgr->mem_szie += (u32)(sizeof(struct unf_xchg) * xchg_sum);
		xchg_mgr->hot_pool = hot_pool;
		xchg_mgr->fcp_mm_start = xchg_mem;
		/* Allocate the memory used by the SFS Xchg to carry the
		 * ELS/BLS/GS command and response
		 */
		xchg_mgr->sfs_mem_size = (u32)(sizeof(union unf_sfs_u) * sfs_xchg_sum);

		/* Apply for the DMA space for sending sfs frames.
		 * If the value of DMA32 is less than 4 GB, cross-4G problems
		 * will not occur
		 */
		sfs_mm_start = dma_alloc_coherent(&lport->low_level_func.dev->dev,
						  xchg_mgr->sfs_mem_size,
						  &sfs_phy_addr, GFP_KERNEL);
		if (!sfs_mm_start) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "Port(0x%x) Get Free Pagers Fail .",
				     lport->port_id);
			goto free_xchg_mem;
		}
		memset(sfs_mm_start, 0, sizeof(union unf_sfs_u) * sfs_xchg_sum);

		xchg_mgr->mem_szie += xchg_mgr->sfs_mem_size;
		xchg_mgr->sfs_mm_start = sfs_mm_start;
		xchg_mgr->sfs_phy_addr = sfs_phy_addr;
		/* The Xchg is initialized and mounted to the Free Pool */
		ret = unf_init_xchg(lport, xchg_mgr, xchg_sum, sfs_xchg_sum);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
				     "Port(0x%x) initialization Exchange unsuccessful, Exchange Number(%d), SFS Exchange number(%d).",
				     lport->port_id, xchg_sum, sfs_xchg_sum);
			dma_free_coherent(&lport->low_level_func.dev->dev, xchg_mgr->sfs_mem_size,
					  xchg_mgr->sfs_mm_start, xchg_mgr->sfs_phy_addr);
			xchg_mgr->sfs_mm_start = 0;
			goto free_xchg_mem;
		}

		/* Apply for the memory used by GID_PT, GID_FT, and RSCN */
		ret = unf_alloc_and_init_big_sfs_pool(lport, xchg_mgr);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "Port(0x%x) allocate big SFS fail", lport->port_id);
			dma_free_coherent(&lport->low_level_func.dev->dev, xchg_mgr->sfs_mem_size,
					  xchg_mgr->sfs_mm_start, xchg_mgr->sfs_phy_addr);
			xchg_mgr->sfs_mm_start = 0;
			goto free_xchg_mem;
		}

		spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
		lport->xchg_mgr[i] = (void *)xchg_mgr;
		list_add_tail(&xchg_mgr->xchg_mgr_entry, &lport->list_xchg_mgr_head);
		spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) ExchangeMgr:(0x%p),Base:(0x%x).",
			     lport->port_id, lport->xchg_mgr[i], hot_pool->base);
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) allocate Exchange Manager size(0x%x).",
		     lport->port_id, xchg_mgr->mem_szie);
	return RETURN_OK;
free_xchg_mem:
	vfree(xchg_mem);
free_hot_pool:
	vfree(hot_pool);
free_xchg_mgr:
	vfree(xchg_mgr);
exit:
	unf_free_exchg_mgr_info(lport);
	return UNF_RETURN_ERROR;
}

void unf_xchg_mgr_destroy(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	unf_free_all_xchg_mgr(lport);
}

u32 unf_alloc_xchg_resource(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	INIT_LIST_HEAD(&lport->list_drty_xchg_mgr_head);
	INIT_LIST_HEAD(&lport->list_xchg_mgr_head);
	spin_lock_init(&lport->xchg_mgr_lock);

	/* LPort Xchg Management Unit Alloc */
	if (unf_alloc_and_init_xchg_mgr(lport) != RETURN_OK)
		return UNF_RETURN_ERROR;

	return RETURN_OK;
}

void unf_destroy_dirty_xchg(struct unf_lport *lport, bool show_only)
{
	u32 dirty_xchg = 0;
	struct unf_xchg_mgr *xchg_mgr = NULL;
	ulong flags = 0;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;

	FC_CHECK_RETURN_VOID(lport);

	if (lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY) {
		spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
		list_for_each_safe(node, next_node, &lport->list_drty_xchg_mgr_head) {
			xchg_mgr = list_entry(node, struct unf_xchg_mgr, xchg_mgr_entry);
			spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);
			if (xchg_mgr) {
				dirty_xchg = (xchg_mgr->free_pool.total_fcp_xchg +
				     xchg_mgr->free_pool.total_sfs_xchg);

				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
					     "[info]Port(0x%x) has %u dirty exchange(s)",
					     lport->port_id, dirty_xchg);

				unf_show_all_xchg(lport, xchg_mgr);

				if (!show_only) {
					/* Delete Dirty Exchange Mgr entry */
					spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
					list_del_init(&xchg_mgr->xchg_mgr_entry);
					spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

					/* Free Dirty Exchange Mgr memory */
					unf_free_xchg_mgr_mem(lport, xchg_mgr);
				}
			}
			spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
		}
		spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);
	}
}

struct unf_xchg_mgr *unf_get_xchg_mgr_by_lport(struct unf_lport *lport, u32 idx)
{
	struct unf_xchg_mgr *xchg_mgr = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE((idx < UNF_EXCHG_MGR_NUM), NULL);

	spin_lock_irqsave(&lport->xchg_mgr_lock, flags);
	xchg_mgr = lport->xchg_mgr[idx];
	spin_unlock_irqrestore(&lport->xchg_mgr_lock, flags);

	return xchg_mgr;
}

struct unf_xchg_hot_pool *unf_get_hot_pool_by_lport(struct unf_lport *lport,
						    u32 mgr_idx)
{
	struct unf_xchg_mgr *xchg_mgr = NULL;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	unf_lport = (struct unf_lport *)(lport->root_lport);

	FC_CHECK_RETURN_VALUE(unf_lport, NULL);

	/* Get Xchg Manager */
	xchg_mgr = unf_get_xchg_mgr_by_lport(unf_lport, mgr_idx);
	if (!xchg_mgr) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Port(0x%x) Exchange Manager is NULL.",
			     unf_lport->port_id);

		return NULL;
	}

	/* Get Xchg Manager Hot Pool */
	return xchg_mgr->hot_pool;
}

static inline void unf_hot_pool_slab_set(struct unf_xchg_hot_pool *hot_pool,
					 u16 slab_index, struct unf_xchg *xchg)
{
	FC_CHECK_RETURN_VOID(hot_pool);

	hot_pool->xchg_slab[slab_index] = xchg;
}

static inline struct unf_xchg *unf_get_xchg_by_xchg_tag(struct unf_xchg_hot_pool *hot_pool,
							u16 slab_index)
{
	FC_CHECK_RETURN_VALUE(hot_pool, NULL);

	return hot_pool->xchg_slab[slab_index];
}

static void *unf_look_up_xchg_by_tag(void *lport, u16 hot_pool_tag)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct unf_xchg *xchg = NULL;
	ulong flags = 0;
	u32 exchg_mgr_idx = 0;
	struct unf_xchg_mgr *xchg_mgr = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	/* In the case of NPIV, lport is the Vport pointer,
	 * the share uses the ExchMgr of RootLport
	 */
	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VALUE(unf_lport, NULL);

	exchg_mgr_idx = (hot_pool_tag * UNF_EXCHG_MGR_NUM) /
			unf_lport->low_level_func.support_max_hot_tag_range;
	if (unlikely(exchg_mgr_idx >= UNF_EXCHG_MGR_NUM)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) Get ExchgMgr %u err",
			     unf_lport->port_id, exchg_mgr_idx);

		return NULL;
	}

	xchg_mgr = unf_lport->xchg_mgr[exchg_mgr_idx];

	if (unlikely(!xchg_mgr)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) ExchgMgr %u is null",
			     unf_lport->port_id, exchg_mgr_idx);

		return NULL;
	}

	hot_pool = xchg_mgr->hot_pool;

	if (unlikely(!hot_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Port(0x%x) Hot Pool is NULL.",
			     unf_lport->port_id);

		return NULL;
	}

	if (unlikely(hot_pool_tag >= (hot_pool->slab_total_sum + hot_pool->base))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]LPort(0x%x) can't Input Tag(0x%x), Max(0x%x).",
			     unf_lport->port_id, hot_pool_tag,
			     (hot_pool->slab_total_sum + hot_pool->base));

		return NULL;
	}

	spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
	xchg = unf_get_xchg_by_xchg_tag(hot_pool, hot_pool_tag - hot_pool->base);
	spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

	return (void *)xchg;
}

static void *unf_find_xchg_by_ox_id(void *lport, u16 ox_id, u32 oid)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct unf_xchg *xchg = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong flags = 0;
	ulong xchg_flags = 0;
	u32 i = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	/* In the case of NPIV, the lport is the Vport pointer,
	 * and the share uses the ExchMgr of the RootLport
	 */
	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VALUE(unf_lport, NULL);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "Port(0x%x) MgrIdex %u Hot Pool is NULL.",
				     unf_lport->port_id, i);
			continue;
		}

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);

		/* 1. Traverse sfs_busy list */
		list_for_each_safe(node, next_node, &hot_pool->sfs_busylist) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);
			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flags);
			if (unf_check_oxid_matched(ox_id, oid, xchg)) {
				atomic_inc(&xchg->ref_cnt);
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flags);
				spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
				return xchg;
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flags);
		}

		/* 2. Traverse INI_Busy List */
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);
			spin_lock_irqsave(&xchg->xchg_state_lock, xchg_flags);
			if (unf_check_oxid_matched(ox_id, oid, xchg)) {
				atomic_inc(&xchg->ref_cnt);
				spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_flags);
				spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
				return xchg;
			}
			spin_unlock_irqrestore(&xchg->xchg_state_lock,
					       xchg_flags);
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
	}

	return NULL;
}

static inline bool unf_check_xchg_matched(struct unf_xchg *xchg, u64 command_sn,
					  u32 world_id, void *pinitiator)
{
	bool matched = false;

	matched = (command_sn == xchg->cmnd_sn);
	if (matched && (atomic_read(&xchg->ref_cnt) > 0))
		return true;
	else
		return false;
}

static void *unf_look_up_xchg_by_cmnd_sn(void *lport, u64 command_sn,
					 u32 world_id, void *pinitiator)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_xchg *xchg = NULL;
	ulong flags = 0;
	u32 i;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	/* In NPIV, lport is a Vport pointer, and idle resources are shared by
	 * ExchMgr of RootLport. However, busy resources are mounted on each
	 * vport. Therefore, vport needs to be used.
	 */
	unf_lport = (struct unf_lport *)lport;
	FC_CHECK_RETURN_VALUE(unf_lport, NULL);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		hot_pool = unf_get_hot_pool_by_lport(unf_lport, i);
		if (unlikely(!hot_pool)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Port(0x%x) hot pool is NULL",
				     unf_lport->port_id);

			continue;
		}

		/* from busy_list */
		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
		list_for_each_safe(node, next_node, &hot_pool->ini_busylist) {
			xchg = list_entry(node, struct unf_xchg, list_xchg_entry);
			if (unf_check_xchg_matched(xchg, command_sn, world_id, pinitiator)) {
				spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

				return xchg;
			}
		}

		/* vport: from destroy_list */
		if (unf_lport != unf_lport->root_lport) {
			list_for_each_safe(node, next_node, &hot_pool->list_destroy_xchg) {
				xchg = list_entry(node, struct unf_xchg, list_xchg_entry);
				if (unf_check_xchg_matched(xchg, command_sn, world_id,
							   pinitiator)) {
					spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

					FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
						     "[info]Port(0x%x) lookup exchange from destroy list",
						     unf_lport->port_id);

					return xchg;
				}
			}
		}

		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
	}

	return NULL;
}

static inline u32 unf_alloc_hot_pool_slab(struct unf_xchg_hot_pool *hot_pool, struct unf_xchg *xchg)
{
	u16 slab_index = 0;

	FC_CHECK_RETURN_VALUE(hot_pool, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	/* Check whether the hotpool tag is in the specified range sirt.
	 * If yes, set up the management relationship. If no, handle the problem
	 * according to the normal IO. If the sirt digitmap is used but the tag
	 * is occupied, it indicates that the I/O is discarded.
	 */

	hot_pool->slab_next_index = (u16)hot_pool->slab_next_index;
	slab_index = hot_pool->slab_next_index;
	while (unf_get_xchg_by_xchg_tag(hot_pool, slab_index)) {
		slab_index++;
		slab_index = slab_index % hot_pool->slab_total_sum;

		/* Rewind occurs */
		if (slab_index == hot_pool->slab_next_index) {
			FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_MAJOR,
				     "There is No Slab At Hot Pool(0x%p) for xchg(0x%p).",
				     hot_pool, xchg);

			return UNF_RETURN_ERROR;
		}
	}

	unf_hot_pool_slab_set(hot_pool, slab_index, xchg);
	xchg->hotpooltag = slab_index + hot_pool->base;
	slab_index++;
	hot_pool->slab_next_index = slab_index % hot_pool->slab_total_sum;

	return RETURN_OK;
}

struct unf_esgl_page *
unf_get_and_add_one_free_esgl_page(struct unf_lport *lport, struct unf_xchg *xchg)
{
	struct unf_esgl *esgl = NULL;
	struct list_head *list_head = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(xchg, NULL);

	/* Obtain a new Esgl from the EsglPool and add it to the list_esgls of
	 * the Xchg
	 */
	spin_lock_irqsave(&lport->esgl_pool.esgl_pool_lock, flag);
	if (!list_empty(&lport->esgl_pool.list_esgl_pool)) {
		list_head = UNF_OS_LIST_NEXT(&lport->esgl_pool.list_esgl_pool);
		list_del(list_head);
		lport->esgl_pool.esgl_pool_count--;
		list_add_tail(list_head, &xchg->list_esgls);

		esgl = list_entry(list_head, struct unf_esgl, entry_esgl);
		atomic_inc(&xchg->esgl_cnt);
		spin_unlock_irqrestore(&lport->esgl_pool.esgl_pool_lock, flag);
	} else {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) esgl pool is empty",
			     lport->nport_id);

		spin_unlock_irqrestore(&lport->esgl_pool.esgl_pool_lock, flag);
		return NULL;
	}

	return &esgl->page;
}

void unf_release_esgls(struct unf_xchg *xchg)
{
	struct unf_lport *unf_lport = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(xchg);
	FC_CHECK_RETURN_VOID(xchg->lport);

	if (atomic_read(&xchg->esgl_cnt) <= 0)
		return;

	/* In the case of NPIV, the Vport pointer is saved in v_pstExch,
	 * and the EsglPool of RootLport is shared.
	 */
	unf_lport = (xchg->lport)->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	spin_lock_irqsave(&unf_lport->esgl_pool.esgl_pool_lock, flag);
	if (!list_empty(&xchg->list_esgls)) {
		list_for_each_safe(list, list_tmp, &xchg->list_esgls) {
			list_del(list);
			list_add_tail(list, &unf_lport->esgl_pool.list_esgl_pool);
			unf_lport->esgl_pool.esgl_pool_count++;
			atomic_dec(&xchg->esgl_cnt);
		}
	}
	spin_unlock_irqrestore(&unf_lport->esgl_pool.esgl_pool_lock, flag);
}

static void unf_add_back_to_fcp_list(struct unf_xchg_free_pool *free_pool, struct unf_xchg *xchg)
{
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(free_pool);
	FC_CHECK_RETURN_VOID(xchg);

	unf_init_xchg_attribute(xchg);

	/* The released I/O resources are added to the queue tail to facilitate
	 * fault locating
	 */
	spin_lock_irqsave(&free_pool->xchg_freepool_lock, flags);
	list_add_tail(&xchg->list_xchg_entry, &free_pool->list_free_xchg_list);
	free_pool->total_fcp_xchg++;
	spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);
}

static void unf_check_xchg_mgr_status(struct unf_xchg_mgr *xchg_mgr)
{
	ulong flags = 0;
	u32 total_xchg = 0;
	u32 total_xchg_sum = 0;

	FC_CHECK_RETURN_VOID(xchg_mgr);

	spin_lock_irqsave(&xchg_mgr->free_pool.xchg_freepool_lock, flags);

	total_xchg = xchg_mgr->free_pool.total_fcp_xchg + xchg_mgr->free_pool.total_sfs_xchg;
	total_xchg_sum = xchg_mgr->free_pool.fcp_xchg_sum + xchg_mgr->free_pool.sfs_xchg_sum;

	if (xchg_mgr->free_pool.xchg_mgr_completion && total_xchg == total_xchg_sum)
		complete(xchg_mgr->free_pool.xchg_mgr_completion);

	spin_unlock_irqrestore(&xchg_mgr->free_pool.xchg_freepool_lock, flags);
}

static void unf_free_fcp_xchg(struct unf_xchg *xchg)
{
	struct unf_xchg_free_pool *free_pool = NULL;
	struct unf_xchg_mgr *xchg_mgr = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;

	FC_CHECK_RETURN_VOID(xchg);

	/* Releasing a Specified INI I/O and Invoking the scsi_done Process */
	unf_done_ini_xchg(xchg);
	free_pool = xchg->free_pool;
	xchg_mgr = xchg->xchg_mgr;
	unf_lport = xchg->lport;
	unf_rport = xchg->rport;

	atomic_dec(&unf_rport->pending_io_cnt);
	/* Release the Esgls in the Xchg structure and return it to the EsglPool
	 * of the Lport
	 */
	unf_release_esgls(xchg);

	if (unlikely(xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu)) {
		kfree(xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu);
		xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu = NULL;
	}

	/* Mount I/O resources to the FCP Free linked list */
	unf_add_back_to_fcp_list(free_pool, xchg);

	/* The Xchg is released synchronously and then forcibly released to
	 * prevent the Xchg from accessing the Xchg in the normal I/O process
	 */
	if (unlikely(unf_lport->port_removing))
		unf_check_xchg_mgr_status(xchg_mgr);
}

static void unf_init_io_xchg_param(struct unf_xchg *xchg, struct unf_lport *lport,
				   struct unf_xchg_mgr *xchg_mgr)
{
	static atomic64_t exhd_id;

	xchg->start_jif = atomic64_inc_return(&exhd_id);
	xchg->xchg_mgr = xchg_mgr;
	xchg->free_pool = &xchg_mgr->free_pool;
	xchg->hot_pool = xchg_mgr->hot_pool;
	xchg->lport = lport;
	xchg->xchg_type = UNF_XCHG_TYPE_INI;
	xchg->free_xchg = unf_free_fcp_xchg;
	xchg->scsi_or_tgt_cmnd_func = NULL;
	xchg->io_state = UNF_IO_STATE_NEW;
	xchg->io_send_stage = TGT_IO_SEND_STAGE_NONE;
	xchg->io_send_result = TGT_IO_SEND_RESULT_INVALID;
	xchg->io_send_abort = false;
	xchg->io_abort_result = false;
	xchg->oxid = INVALID_VALUE16;
	xchg->abort_oxid = INVALID_VALUE16;
	xchg->rxid = INVALID_VALUE16;
	xchg->sid = INVALID_VALUE32;
	xchg->did = INVALID_VALUE32;
	xchg->oid = INVALID_VALUE32;
	xchg->seq_id = INVALID_VALUE8;
	xchg->cmnd_code = INVALID_VALUE32;
	xchg->data_len = 0;
	xchg->resid_len = 0;
	xchg->data_direction = DMA_NONE;
	xchg->may_consume_res_cnt = 0;
	xchg->fast_consume_res_cnt = 0;
	xchg->io_front_jif = 0;
	xchg->tmf_state = 0;
	xchg->ucode_abts_state = INVALID_VALUE32;
	xchg->abts_state = 0;
	xchg->rport_bind_jifs = INVALID_VALUE64;
	xchg->scsi_id = INVALID_VALUE32;
	xchg->qos_level = 0;
	xchg->world_id = INVALID_VALUE32;

	memset(&xchg->dif_control, 0, sizeof(struct unf_dif_control_info));
	memset(&xchg->req_sgl_info, 0, sizeof(struct unf_req_sgl_info));
	memset(&xchg->dif_sgl_info, 0, sizeof(struct unf_req_sgl_info));
	xchg->scsi_cmnd_info.result = 0;

	xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    (u32)atomic64_inc_return(&((struct unf_lport *)lport->root_lport)->exchg_index);

	if (xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] == INVALID_VALUE32) {
		xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		    (u32)atomic64_inc_return(&((struct unf_lport *)lport->root_lport)->exchg_index);
	}

	if (xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] == 0) {
		xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		    (u32)atomic64_inc_return(&((struct unf_lport *)lport->root_lport)->exchg_index);
	}

	atomic_set(&xchg->ref_cnt, 0);
	atomic_set(&xchg->delay_flag, 0);

	if (delayed_work_pending(&xchg->timeout_work))
		UNF_DEL_XCHG_TIMER_SAFE(xchg);

	INIT_DELAYED_WORK(&xchg->timeout_work, unf_fc_ini_io_xchg_time_out);
}

static struct unf_xchg *unf_alloc_io_xchg(struct unf_lport *lport,
					  struct unf_xchg_mgr *xchg_mgr)
{
	struct unf_xchg *xchg = NULL;
	struct list_head *list_node = NULL;
	struct unf_xchg_free_pool *free_pool = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(xchg_mgr, NULL);
	FC_CHECK_RETURN_VALUE(lport, NULL);

	free_pool = &xchg_mgr->free_pool;
	hot_pool = xchg_mgr->hot_pool;
	FC_CHECK_RETURN_VALUE(free_pool, NULL);
	FC_CHECK_RETURN_VALUE(hot_pool, NULL);

	/* 1. Free Pool */
	spin_lock_irqsave(&free_pool->xchg_freepool_lock, flags);
	if (unlikely(list_empty(&free_pool->list_free_xchg_list))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "Port(0x%x) have no Exchange anymore.",
			     lport->port_id);
		spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);
		return NULL;
	}

	/* Select an idle node from free pool */
	list_node = UNF_OS_LIST_NEXT(&free_pool->list_free_xchg_list);
	list_del(list_node);
	free_pool->total_fcp_xchg--;
	spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);

	xchg = list_entry(list_node, struct unf_xchg, list_xchg_entry);
	/*
	 * Hot Pool:
	 * When xchg is mounted to Hot Pool, the mount mode and release mode
	 * of Xchg must be specified and stored in the sfs linked list.
	 */
	flags = 0;
	spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
	if (unf_alloc_hot_pool_slab(hot_pool, xchg) != RETURN_OK) {
		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
		unf_add_back_to_fcp_list(free_pool, xchg);
		if (unlikely(lport->port_removing))
			unf_check_xchg_mgr_status(xchg_mgr);

		return NULL;
	}
	list_add_tail(&xchg->list_xchg_entry, &hot_pool->ini_busylist);
	spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

	/* 3. Exchange State */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	unf_init_io_xchg_param(xchg, lport, xchg_mgr);
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return xchg;
}

static void unf_add_back_to_sfs_list(struct unf_xchg_free_pool *free_pool,
				     struct unf_xchg *xchg)
{
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(free_pool);
	FC_CHECK_RETURN_VOID(xchg);

	unf_init_xchg_attribute(xchg);

	spin_lock_irqsave(&free_pool->xchg_freepool_lock, flags);

	list_add_tail(&xchg->list_xchg_entry, &free_pool->list_sfs_xchg_list);
	free_pool->total_sfs_xchg++;
	spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);
}

static void unf_free_sfs_xchg(struct unf_xchg *xchg)
{
	struct unf_xchg_free_pool *free_pool = NULL;
	struct unf_xchg_mgr *xchg_mgr = NULL;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(xchg);

	free_pool = xchg->free_pool;
	unf_lport = xchg->lport;
	xchg_mgr = xchg->xchg_mgr;

	/* The memory is applied for when the GID_PT/GID_FT is sent.
	 * If no response is received, the GID_PT/GID_FT needs to be forcibly
	 * released.
	 */

	unf_free_one_big_sfs(xchg);

	unf_add_back_to_sfs_list(free_pool, xchg);

	if (unlikely(unf_lport->port_removing))
		unf_check_xchg_mgr_status(xchg_mgr);
}

static void unf_fc_xchg_add_timer(void *xchg, ulong time_ms,
				  enum unf_timer_type time_type)
{
	ulong flag = 0;
	struct unf_xchg *unf_xchg = NULL;
	ulong times_ms = time_ms;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(xchg);
	unf_xchg = (struct unf_xchg *)xchg;
	unf_lport = unf_xchg->lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	/* update timeout */
	switch (time_type) {
	/* The processing of TGT RRQ timeout is the same as that of TGT IO
	 * timeout. The timeout period is different.
	 */
	case UNF_TIMER_TYPE_TGT_RRQ:
		times_ms = times_ms + UNF_TGT_RRQ_REDUNDANT_TIME;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "TGT RRQ Timer set.");
		break;

	case UNF_TIMER_TYPE_INI_RRQ:
		times_ms = times_ms - UNF_INI_RRQ_REDUNDANT_TIME;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "INI RRQ Timer set.");
		break;

	case UNF_TIMER_TYPE_SFS:
		times_ms = times_ms + UNF_INI_ELS_REDUNDANT_TIME;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "INI ELS Timer set.");
		break;
	default:
		break;
	}

	/* The xchg of the timer must be valid. If the reference count of xchg
	 * is 0, the timer must not be added
	 */
	if (atomic_read(&unf_xchg->ref_cnt) <= 0) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_KEVENT,
			     "[warn]Abnormal Exchange(0x%p), Reference count(0x%x), Can't add timer.",
			     unf_xchg, atomic_read(&unf_xchg->ref_cnt));
		return;
	}

	/* Delay Work: Hold for timer */
	spin_lock_irqsave(&unf_xchg->xchg_state_lock, flag);
	if (queue_delayed_work(unf_lport->xchg_wq, &unf_xchg->timeout_work,
			       (ulong)msecs_to_jiffies((u32)times_ms))) {
		/* hold for timer */
		atomic_inc(&unf_xchg->ref_cnt);
	}
	spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flag);
}

static void unf_init_sfs_xchg_param(struct unf_xchg *xchg,
				    struct unf_lport *lport,
				    struct unf_xchg_mgr *xchg_mgr)
{
	xchg->free_pool = &xchg_mgr->free_pool;
	xchg->hot_pool = xchg_mgr->hot_pool;
	xchg->lport = lport;
	xchg->xchg_mgr = xchg_mgr;
	xchg->free_xchg = unf_free_sfs_xchg;
	xchg->xchg_type = UNF_XCHG_TYPE_SFS;
	xchg->io_state = UNF_IO_STATE_NEW;
	xchg->scsi_cmnd_info.result = 0;
	xchg->ob_callback_sts = UNF_IO_SUCCESS;

	xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    (u32)atomic64_inc_return(&((struct unf_lport *)lport->root_lport)->exchg_index);

	if (xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] ==
	    INVALID_VALUE32) {
		xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		    (u32)atomic64_inc_return(&((struct unf_lport *)lport->root_lport)->exchg_index);
	}

	if (xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] == 0) {
		xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
		    (u32)atomic64_inc_return(&((struct unf_lport *)lport->root_lport)->exchg_index);
	}

	if (delayed_work_pending(&xchg->timeout_work))
		UNF_DEL_XCHG_TIMER_SAFE(xchg);

	INIT_DELAYED_WORK(&xchg->timeout_work, unf_sfs_xchg_time_out);
}

static struct unf_xchg *unf_alloc_sfs_xchg(struct unf_lport *lport,
					   struct unf_xchg_mgr *xchg_mgr)
{
	struct unf_xchg *xchg = NULL;
	struct list_head *list_node = NULL;
	struct unf_xchg_free_pool *free_pool = NULL;
	struct unf_xchg_hot_pool *hot_pool = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(xchg_mgr, NULL);
	free_pool = &xchg_mgr->free_pool;
	hot_pool = xchg_mgr->hot_pool;
	FC_CHECK_RETURN_VALUE(free_pool, NULL);
	FC_CHECK_RETURN_VALUE(hot_pool, NULL);

	/* Select an idle node from free pool */
	spin_lock_irqsave(&free_pool->xchg_freepool_lock, flags);
	if (list_empty(&free_pool->list_sfs_xchg_list)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Port(0x%x) have no Exchange anymore.",
			     lport->port_id);
		spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);
		return NULL;
	}

	list_node = UNF_OS_LIST_NEXT(&free_pool->list_sfs_xchg_list);
	list_del(list_node);
	free_pool->total_sfs_xchg--;
	spin_unlock_irqrestore(&free_pool->xchg_freepool_lock, flags);

	xchg = list_entry(list_node, struct unf_xchg, list_xchg_entry);
	/*
	 * The xchg is mounted to the Hot Pool.
	 * The mount mode and release mode of the xchg must be specified
	 * and stored in the sfs linked list.
	 */
	flags = 0;
	spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
	if (unf_alloc_hot_pool_slab(hot_pool, xchg) != RETURN_OK) {
		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);
		unf_add_back_to_sfs_list(free_pool, xchg);
		if (unlikely(lport->port_removing))
			unf_check_xchg_mgr_status(xchg_mgr);

		return NULL;
	}

	list_add_tail(&xchg->list_xchg_entry, &hot_pool->sfs_busylist);
	hot_pool->total_xchges++;
	spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	unf_init_sfs_xchg_param(xchg, lport, xchg_mgr);
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return xchg;
}

static void *unf_get_new_xchg(void *lport, u32 xchg_type)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg_mgr *xchg_mgr = NULL;
	struct unf_xchg *xchg = NULL;
	u32 exchg_type = 0;
	u16 xchg_mgr_type;
	u32 rtry_cnt = 0;
	u32 last_exchg_mgr_idx;

	xchg_mgr_type = (xchg_type >> UNF_SHIFT_16);
	exchg_type = xchg_type & SPFC_XCHG_TYPE_MASK;
	FC_CHECK_RETURN_VALUE(lport, NULL);

	/* In the case of NPIV, the lport is the Vport pointer,
	 * and the share uses the ExchMgr of the RootLport.
	 */
	unf_lport = ((struct unf_lport *)lport)->root_lport;
	FC_CHECK_RETURN_VALUE(unf_lport, NULL);

	if (unlikely((atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP) ||
		     (atomic_read(&((struct unf_lport *)lport)->lport_no_operate_flag) ==
		     UNF_LPORT_NOP))) {
		return NULL;
	}

	last_exchg_mgr_idx = (u32)atomic64_inc_return(&unf_lport->last_exchg_mgr_idx);
try_next_mgr:
	rtry_cnt++;
	if (unlikely(rtry_cnt > UNF_EXCHG_MGR_NUM))
		return NULL;

	/* If Fixed mode,only use XchgMgr 0 */
	if (unlikely(xchg_mgr_type == UNF_XCHG_MGR_TYPE_FIXED)) {
		xchg_mgr = (struct unf_xchg_mgr *)unf_lport->xchg_mgr[ARRAY_INDEX_0];
	} else {
		xchg_mgr = (struct unf_xchg_mgr *)unf_lport
			->xchg_mgr[last_exchg_mgr_idx % UNF_EXCHG_MGR_NUM];
	}
	if (unlikely(!xchg_mgr)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) get exchangemgr %u is null.",
			     unf_lport->port_id, last_exchg_mgr_idx % UNF_EXCHG_MGR_NUM);
		return NULL;
	}
	last_exchg_mgr_idx++;

	/* Allocate entries based on the Exchange type */
	switch (exchg_type) {
	case UNF_XCHG_TYPE_SFS:
		xchg = unf_alloc_sfs_xchg(lport, xchg_mgr);
		break;
	case UNF_XCHG_TYPE_INI:
		xchg = unf_alloc_io_xchg(lport, xchg_mgr);
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Port(0x%x) unwonted, Exchange type(0x%x).",
			     unf_lport->port_id, exchg_type);
		break;
	}

	if (likely(xchg)) {
		xchg->oxid = INVALID_VALUE16;
		xchg->abort_oxid = INVALID_VALUE16;
		xchg->rxid = INVALID_VALUE16;
		xchg->debug_hook = false;
		xchg->alloc_jif = jiffies;

		atomic_set(&xchg->ref_cnt, 1);
		atomic_set(&xchg->esgl_cnt, 0);
	} else {
		goto try_next_mgr;
	}

	return xchg;
}

static void unf_free_xchg(void *lport, void *xchg)
{
	struct unf_xchg *unf_xchg = NULL;

	FC_CHECK_RETURN_VOID(xchg);

	unf_xchg = (struct unf_xchg *)xchg;
	unf_xchg_ref_dec(unf_xchg, XCHG_FREE_XCHG);
}

u32 unf_init_xchg_mgr_temp(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	lport->xchg_mgr_temp.unf_xchg_get_free_and_init = unf_get_new_xchg;
	lport->xchg_mgr_temp.unf_xchg_release = unf_free_xchg;
	lport->xchg_mgr_temp.unf_look_up_xchg_by_tag = unf_look_up_xchg_by_tag;
	lport->xchg_mgr_temp.unf_look_up_xchg_by_id = unf_find_xchg_by_ox_id;
	lport->xchg_mgr_temp.unf_xchg_add_timer = unf_fc_xchg_add_timer;
	lport->xchg_mgr_temp.unf_xchg_cancel_timer = unf_xchg_cancel_timer;
	lport->xchg_mgr_temp.unf_xchg_abort_all_io = unf_xchg_abort_all_xchg;
	lport->xchg_mgr_temp.unf_look_up_xchg_by_cmnd_sn = unf_look_up_xchg_by_cmnd_sn;
	lport->xchg_mgr_temp.unf_xchg_abort_by_lun = unf_xchg_abort_by_lun;
	lport->xchg_mgr_temp.unf_xchg_abort_by_session =  unf_xchg_abort_by_session;
	lport->xchg_mgr_temp.unf_xchg_mgr_io_xchg_abort = unf_xchg_mgr_io_xchg_abort;
	lport->xchg_mgr_temp.unf_xchg_mgr_sfs_xchg_abort =  unf_xchg_mgr_sfs_xchg_abort;

	return RETURN_OK;
}

void unf_release_xchg_mgr_temp(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	if (lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) has dirty exchange, Don't release exchange manager template.",
			     lport->port_id);

		return;
	}

	memset(&lport->xchg_mgr_temp, 0, sizeof(struct unf_cm_xchg_mgr_template));

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_7_DESTROY_XCHG_MGR_TMP;
}

void unf_set_hot_pool_wait_state(struct unf_lport *lport, bool wait_state)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	ulong pool_lock_flags = 0;
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

		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, pool_lock_flags);
		hot_pool->wait_state = wait_state;
		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, pool_lock_flags);
	}
}

u32 unf_xchg_ref_inc(struct unf_xchg *xchg, enum unf_ioflow_id io_stage)
{
	struct unf_xchg_hot_pool *hot_pool = NULL;
	ulong flags = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);

	if (unlikely(xchg->debug_hook)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]Xchg(0x%p) State(0x%x) SID_DID(0x%x_0x%x) OX_ID_RX_ID(0x%x_0x%x) AllocJiff(%llu) Refcnt(%d) Stage(%s)",
			     xchg, xchg->io_state, xchg->sid, xchg->did,
			     xchg->oxid, xchg->rxid, xchg->alloc_jif,
			     atomic_read(&xchg->ref_cnt),
			     io_stage_table[io_stage].stage);
	}

	hot_pool = xchg->hot_pool;
	FC_CHECK_RETURN_VALUE(hot_pool, UNF_RETURN_ERROR);

	/* Exchange -> Hot Pool Tag check */
	if (unlikely((xchg->hotpooltag >= (hot_pool->slab_total_sum + hot_pool->base)) ||
		     xchg->hotpooltag < hot_pool->base)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Xchg(0x%p) S_ID(%xh) D_ID(0x%x) hot_pool_tag(0x%x) is bigger than slab total num(0x%x) base(0x%x)",
			     xchg, xchg->sid, xchg->did, xchg->hotpooltag,
			     hot_pool->slab_total_sum + hot_pool->base, hot_pool->base);

		return UNF_RETURN_ERROR;
	}

	/* atomic read & inc */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (unlikely(atomic_read(&xchg->ref_cnt) <= 0)) {
		ret = UNF_RETURN_ERROR;
	} else {
		if (unf_get_xchg_by_xchg_tag(hot_pool, xchg->hotpooltag - hot_pool->base) == xchg) {
			atomic_inc(&xchg->ref_cnt);
			ret = RETURN_OK;
		} else {
			ret = UNF_RETURN_ERROR;
		}
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	return ret;
}

void unf_xchg_ref_dec(struct unf_xchg *xchg, enum unf_ioflow_id io_stage)
{
	/* Atomic dec ref_cnt & test, free exchange if necessary (ref_cnt==0) */
	struct unf_xchg_hot_pool *hot_pool = NULL;
	void (*free_xchg)(struct unf_xchg *) = NULL;
	ulong flags = 0;
	ulong xchg_lock_falgs = 0;

	FC_CHECK_RETURN_VOID(xchg);

	if (xchg->debug_hook) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[info]Xchg(0x%p) State(0x%x) SID_DID(0x%x_0x%x) OXID_RXID(0x%x_0x%x) AllocJiff(%llu) Refcnt(%d) Statge %s",
			     xchg, xchg->io_state, xchg->sid, xchg->did, xchg->oxid,
			     xchg->rxid, xchg->alloc_jif,
			     atomic_read(&xchg->ref_cnt),
			     io_stage_table[io_stage].stage);
	}

	hot_pool = xchg->hot_pool;
	FC_CHECK_RETURN_VOID(hot_pool);
	FC_CHECK_RETURN_VOID((xchg->hotpooltag >= hot_pool->base));

	/*
	 * 1. Atomic dec & test
	 * 2. Free exchange if necessary (ref_cnt == 0)
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, xchg_lock_falgs);
	if (atomic_dec_and_test(&xchg->ref_cnt)) {
		free_xchg = xchg->free_xchg;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_lock_falgs);
		spin_lock_irqsave(&hot_pool->xchg_hotpool_lock, flags);
		unf_hot_pool_slab_set(hot_pool,
				      xchg->hotpooltag - hot_pool->base, NULL);
		/* Delete exchange list entry */
		list_del_init(&xchg->list_xchg_entry);
		hot_pool->total_xchges--;
		spin_unlock_irqrestore(&hot_pool->xchg_hotpool_lock, flags);

		/* unf_free_fcp_xchg --->>> unf_done_ini_xchg */
		if (free_xchg)
			free_xchg(xchg);
	} else {
		spin_unlock_irqrestore(&xchg->xchg_state_lock, xchg_lock_falgs);
	}
}

static void unf_init_xchg_attribute(struct unf_xchg *xchg)
{
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(xchg);

	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->xchg_mgr = NULL;
	xchg->free_pool = NULL;
	xchg->hot_pool = NULL;
	xchg->lport = NULL;
	xchg->rport = NULL;
	xchg->disc_rport = NULL;
	xchg->io_state = UNF_IO_STATE_NEW;
	xchg->io_send_stage = TGT_IO_SEND_STAGE_NONE;
	xchg->io_send_result = TGT_IO_SEND_RESULT_INVALID;
	xchg->io_send_abort = false;
	xchg->io_abort_result = false;
	xchg->abts_state = 0;
	xchg->oxid = INVALID_VALUE16;
	xchg->abort_oxid = INVALID_VALUE16;
	xchg->rxid = INVALID_VALUE16;
	xchg->sid = INVALID_VALUE32;
	xchg->did = INVALID_VALUE32;
	xchg->oid = INVALID_VALUE32;
	xchg->disc_portid = INVALID_VALUE32;
	xchg->seq_id = INVALID_VALUE8;
	xchg->cmnd_code = INVALID_VALUE32;
	xchg->cmnd_sn = INVALID_VALUE64;
	xchg->data_len = 0;
	xchg->resid_len = 0;
	xchg->data_direction = DMA_NONE;
	xchg->hotpooltag = INVALID_VALUE16;
	xchg->big_sfs_buf = NULL;
	xchg->may_consume_res_cnt = 0;
	xchg->fast_consume_res_cnt = 0;
	xchg->io_front_jif = INVALID_VALUE64;
	xchg->ob_callback_sts = UNF_IO_SUCCESS;
	xchg->start_jif = 0;
	xchg->rport_bind_jifs = INVALID_VALUE64;
	xchg->scsi_id = INVALID_VALUE32;
	xchg->qos_level = 0;
	xchg->world_id = INVALID_VALUE32;

	memset(&xchg->seq, 0, sizeof(struct unf_seq));
	memset(&xchg->fcp_cmnd, 0, sizeof(struct unf_fcp_cmnd));
	memset(&xchg->scsi_cmnd_info, 0, sizeof(struct unf_scsi_cmd_info));
	memset(&xchg->dif_info, 0, sizeof(struct dif_info));
	memset(xchg->private_data, 0, (PKG_MAX_PRIVATE_DATA_SIZE * sizeof(u32)));
	xchg->echo_info.echo_result = UNF_ELS_ECHO_RESULT_OK;
	xchg->echo_info.response_time = 0;

	if (xchg->xchg_type == UNF_XCHG_TYPE_SFS) {
		if (xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr) {
			memset(xchg->fcp_sfs_union.sfs_entry.fc_sfs_entry_ptr, 0,
			       sizeof(union unf_sfs_u));
			xchg->fcp_sfs_union.sfs_entry.cur_offset = 0;
		}
	} else if (xchg->xchg_type != UNF_XCHG_TYPE_INI) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Exchange Type(0x%x) SFS Union uninited.",
			     xchg->xchg_type);
	}
	xchg->xchg_type = UNF_XCHG_TYPE_INVALID;
	xchg->xfer_or_rsp_echo = NULL;
	xchg->scsi_or_tgt_cmnd_func = NULL;
	xchg->ob_callback = NULL;
	xchg->callback = NULL;
	xchg->free_xchg = NULL;

	atomic_set(&xchg->ref_cnt, 0);
	atomic_set(&xchg->esgl_cnt, 0);
	atomic_set(&xchg->delay_flag, 0);

	if (delayed_work_pending(&xchg->timeout_work))
		UNF_DEL_XCHG_TIMER_SAFE(xchg);

	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
}

bool unf_busy_io_completed(struct unf_lport *lport)
{
	struct unf_xchg_mgr *xchg_mgr = NULL;
	ulong pool_lock_flags = 0;
	u32 i;

	FC_CHECK_RETURN_VALUE(lport, true);

	for (i = 0; i < UNF_EXCHG_MGR_NUM; i++) {
		xchg_mgr = unf_get_xchg_mgr_by_lport(lport, i);
		if (unlikely(!xchg_mgr)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%x) Exchange Manager is NULL",
				     lport->port_id);
			continue;
		}

		spin_lock_irqsave(&xchg_mgr->hot_pool->xchg_hotpool_lock,
				  pool_lock_flags);
		if (!list_empty(&xchg_mgr->hot_pool->ini_busylist)) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
				     "[info]Port(0x%x) ini busylist is not empty.",
				     lport->port_id);
			spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock,
					       pool_lock_flags);
			return false;
		}
		spin_unlock_irqrestore(&xchg_mgr->hot_pool->xchg_hotpool_lock,
				       pool_lock_flags);
	}
	return true;
}
