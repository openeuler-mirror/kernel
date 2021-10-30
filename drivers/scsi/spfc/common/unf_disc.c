// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_disc.h"
#include "unf_log.h"
#include "unf_common.h"
#include "unf_event.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_exchg.h"
#include "unf_ls.h"
#include "unf_gs.h"
#include "unf_portman.h"

#define UNF_LIST_RSCN_PAGE_CNT 2560
#define UNF_MAX_PORTS_PRI_LOOP 2
#define UNF_MAX_GS_SEND_NUM 8
#define UNF_OS_REMOVE_CARD_TIMEOUT (60 * 1000)

static void unf_set_disc_state(struct unf_disc *disc,
			       enum unf_disc_state states)
{
	FC_CHECK_RETURN_VOID(disc);

	if (states != disc->states) {
		/* Reset disc retry count */
		disc->retry_count = 0;
	}

	disc->states = states;
}

static inline u32 unf_get_loop_map(struct unf_lport *lport, u8 loop_map[], u32 loop_map_size)
{
	struct unf_buf buf = {0};
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport->low_level_func.port_mgr_op.ll_port_config_get,
			      UNF_RETURN_ERROR);

	buf.buf = loop_map;
	buf.buf_len = loop_map_size;

	ret = lport->low_level_func.port_mgr_op.ll_port_config_get(lport->fc_port,
								   UNF_PORT_CFG_GET_LOOP_MAP,
								   (void *)&buf);
	return ret;
}

static void unf_login_with_loop_node(struct unf_lport *lport, u32 alpa)
{
	/* Only used for Private Loop LOGIN */
	struct unf_rport *unf_rport = NULL;
	ulong rport_flag = 0;
	u32 port_feature = 0;
	u32 ret;

	/* Check AL_PA validity */
	if (lport->nport_id == alpa) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) is the same as RPort with AL_PA(0x%x), do nothing",
			     lport->port_id, alpa);
		return;
	}

	if (alpa == 0) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) RPort(0x%x) is fabric, do nothing",
			     lport->port_id, alpa);
		return;
	}

	/* Get & set R_Port: reuse only */
	unf_rport = unf_get_rport_by_nport_id(lport, alpa);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]LOGIN: Port(0x%x_0x%x) RPort(0x%x_0x%p) login with private loop",
		     lport->port_id, lport->nport_id, alpa, unf_rport);

	unf_rport = unf_get_safe_rport(lport, unf_rport, UNF_RPORT_REUSE_ONLY, alpa);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) allocate new RPort(0x%x) failed",
			     lport->port_id, lport->nport_id, alpa);
		return;
	}

	/* Update R_Port state & N_Port_ID */
	spin_lock_irqsave(&unf_rport->rport_state_lock, rport_flag);
	unf_rport->nport_id = alpa;
	unf_rport_state_ma(unf_rport, UNF_EVENT_RPORT_ENTER_PLOGI);
	spin_unlock_irqrestore(&unf_rport->rport_state_lock, rport_flag);

	/* Private Loop: check whether need delay to send PLOGI or not */
	port_feature = unf_rport->options;

	/* check Rport and Lport feature */
	if (port_feature == UNF_PORT_MODE_UNKNOWN &&
	    lport->options == UNF_PORT_MODE_INI) {
		/* Start to send PLOGI */
		ret = unf_send_plogi(lport, unf_rport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]LOGIN: Port(0x%x_0x%x) send PLOGI to RPort(0x%x) failed",
				     lport->port_id, lport->nport_id, unf_rport->nport_id);

			unf_rport_error_recovery(unf_rport);
		}
	} else {
		unf_check_rport_need_delay_plogi(lport, unf_rport, port_feature);
	}
}

static int unf_discover_private_loop(void *arg_in, void *arg_out)
{
	struct unf_lport *unf_lport = (struct unf_lport *)arg_in;
	u32 ret = UNF_RETURN_ERROR;
	u32 i = 0;
	u8 loop_id = 0;
	u32 alpa_index = 0;
	u8 loop_map[UNF_LOOPMAP_COUNT];

	FC_CHECK_RETURN_VALUE(unf_lport, UNF_RETURN_ERROR);
	memset(loop_map, 0x0, UNF_LOOPMAP_COUNT);

	/* Get Port Loop Map */
	ret = unf_get_loop_map(unf_lport, loop_map, UNF_LOOPMAP_COUNT);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) get loop map failed", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Check Loop Map Ports Count */
	if (loop_map[ARRAY_INDEX_0] > UNF_MAX_PORTS_PRI_LOOP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) has more than %d ports(%u) in private loop",
			     unf_lport->port_id, UNF_MAX_PORTS_PRI_LOOP, loop_map[ARRAY_INDEX_0]);

		return UNF_RETURN_ERROR;
	}

	/* AL_PA = 0 means Public Loop */
	if (loop_map[ARRAY_INDEX_1] == UNF_FL_PORT_LOOP_ADDR ||
	    loop_map[ARRAY_INDEX_2] == UNF_FL_PORT_LOOP_ADDR) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) one or more AL_PA is 0x00, indicate it's FL_Port",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Discovery Private Loop Ports */
	for (i = 0; i < loop_map[ARRAY_INDEX_0]; i++) {
		alpa_index = i + 1;

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[info]Port(0x%x) start to disc(0x%x) with count(0x%x)",
			     unf_lport->port_id, loop_map[alpa_index], i);

		/* Check whether need delay to send PLOGI or not */
		loop_id = loop_map[alpa_index];
		unf_login_with_loop_node(unf_lport, (u32)loop_id);
	}

	return RETURN_OK;
}

u32 unf_disc_start(void *lport)
{
	/*
	 * Call by:
	 * 1. Enter Private Loop Login
	 * 2. Analysis RSCN payload
	 * 3. SCR callback
	 * *
	 * Doing:
	 * Fabric/Public Loop: Send GID_PT
	 * Private Loop: (delay to) send PLOGI or send LOGO immediately
	 * P2P: do nothing
	 */
	struct unf_lport *unf_lport = (struct unf_lport *)lport;
	struct unf_rport *unf_rport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_cm_event_report *event = NULL;
	u32 ret = RETURN_OK;
	ulong flag = 0;
	enum unf_act_topo act_topo = UNF_ACT_TOP_UNKNOWN;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	act_topo = unf_lport->act_topo;
	disc = &unf_lport->disc;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]LOGIN: Port(0x%x) with topo(0x%x) begin to discovery",
		     unf_lport->port_id, act_topo);

	if (act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    act_topo == UNF_ACT_TOP_PUBLIC_LOOP) {
		/* 1. Fabric or Public Loop Topology: for directory server */
		unf_rport = unf_get_rport_by_nport_id(unf_lport,
						      UNF_FC_FID_DIR_SERV); /* 0xfffffc */
		if (!unf_rport) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) unable to get SNS RPort(0xfffffc)",
				     unf_lport->port_id);

			unf_rport = unf_rport_get_free_and_init(unf_lport, UNF_PORT_TYPE_FC,
								UNF_FC_FID_DIR_SERV);
			if (!unf_rport)
				return UNF_RETURN_ERROR;

			unf_rport->nport_id = UNF_FC_FID_DIR_SERV;
		}

		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		unf_set_disc_state(disc, UNF_DISC_ST_START); /* disc start */
		unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_NORMAL_ENTER);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/*
		 * NOTE: Send GID_PT
		 * The Name Server shall, when it receives a GID_PT request,
		 * return all Port Identifiers having registered support for the
		 * specified Port Type. One or more Port Identifiers, having
		 * registered as the specified Port Type, are returned.
		 */
		ret = unf_send_gid_pt(unf_lport, unf_rport);
		if (ret != RETURN_OK)
			unf_disc_error_recovery(unf_lport);
	} else if (act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		/* Private Loop: to thread process */
		event = unf_get_one_event_node(unf_lport);
		FC_CHECK_RETURN_VALUE(event, UNF_RETURN_ERROR);

		event->lport = unf_lport;
		event->event_asy_flag = UNF_EVENT_ASYN;
		event->unf_event_task = unf_discover_private_loop;
		event->para_in = (void *)unf_lport;

		unf_post_one_event_node(unf_lport, event);
	} else {
		/* P2P toplogy mode: Do nothing */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) with topo(0x%x) need do nothing",
			     unf_lport->port_id, act_topo);
	}

	return ret;
}

static u32 unf_disc_stop(void *lport)
{
	/* Call by GID_ACC processer */
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *root_lport = NULL;
	struct unf_rport *sns_port = NULL;
	struct unf_disc_rport *disc_rport = NULL;
	struct unf_disc *disc = NULL;
	struct unf_disc *root_disc = NULL;
	struct list_head *node = NULL;
	ulong flag = 0;
	u32 ret = RETURN_OK;
	u32 nport_id = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	unf_lport = (struct unf_lport *)lport;
	disc = &unf_lport->disc;
	root_lport = (struct unf_lport *)unf_lport->root_lport;
	root_disc = &root_lport->disc;

	/* Get R_Port for Directory server */
	sns_port = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_DIR_SERV);
	if (!sns_port) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find fabric RPort(0xfffffc) failed",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* for R_Port from disc pool busy list */
	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if (list_empty(&disc->disc_rport_mgr.list_disc_rports_busy)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
		return RETURN_OK;
	}

	node = UNF_OS_LIST_NEXT(&disc->disc_rport_mgr.list_disc_rports_busy);
	do {
		/* Delete from Disc busy list */
		disc_rport = list_entry(node, struct unf_disc_rport, entry_rport);
		nport_id = disc_rport->nport_id;
		list_del_init(node);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		/* Add back to (free) Disc R_Port pool (list) */
		spin_lock_irqsave(&root_disc->rport_busy_pool_lock, flag);
		list_add_tail(node, &root_disc->disc_rport_mgr.list_disc_rports_pool);
		spin_unlock_irqrestore(&root_disc->rport_busy_pool_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "Port(0x%x_0x%x) remove nportid:0x%x from rportbusy list",
			     unf_lport->port_id, unf_lport->nport_id, disc_rport->nport_id);
		/* Send GNN_ID to Name Server */
		ret = unf_get_and_post_disc_event(unf_lport, sns_port, nport_id,
						  UNF_DISC_GET_NODE_NAME);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) add discovery event(0x%x) failed Rport(0x%x)",
				     unf_lport->nport_id, UNF_DISC_GET_NODE_NAME, nport_id);

			/* NOTE: go to next stage */
			unf_rcv_gnn_id_rsp_unknown(unf_lport, sns_port, nport_id);
		}

		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		node = UNF_OS_LIST_NEXT(&disc->disc_rport_mgr.list_disc_rports_busy);
	} while (node != &disc->disc_rport_mgr.list_disc_rports_busy);
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	return ret;
}

static u32 unf_init_rport_pool(struct unf_lport *lport)
{
	struct unf_rport_pool *rport_pool = NULL;
	struct unf_rport *unf_rport = NULL;
	u32 ret = RETURN_OK;
	u32 i = 0;
	u32 bitmap_cnt = 0;
	ulong flag = 0;
	u32 max_login = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* Init RPort Pool info */
	rport_pool = &lport->rport_pool;
	max_login = lport->low_level_func.lport_cfg_items.max_login;
	rport_pool->rport_pool_completion = NULL;
	rport_pool->rport_pool_count = max_login;
	spin_lock_init(&rport_pool->rport_free_pool_lock);
	INIT_LIST_HEAD(&rport_pool->list_rports_pool); /* free RPort pool */

	/* 1. Alloc RPort Pool buffer/resource (memory) */
	rport_pool->rport_pool_add = vmalloc((size_t)(max_login * sizeof(struct unf_rport)));
	if (!rport_pool->rport_pool_add) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) allocate RPort(s) resource failed", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(rport_pool->rport_pool_add, 0, (max_login * sizeof(struct unf_rport)));

	/* 2. Alloc R_Port Pool bitmap */
	bitmap_cnt = (lport->low_level_func.support_max_rport) / BITS_PER_LONG + 1;
	rport_pool->rpi_bitmap = vmalloc((size_t)(bitmap_cnt * sizeof(ulong)));
	if (!rport_pool->rpi_bitmap) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) allocate RPort Bitmap failed", lport->port_id);

		vfree(rport_pool->rport_pool_add);
		rport_pool->rport_pool_add = NULL;
		return UNF_RETURN_ERROR;
	}
	memset(rport_pool->rpi_bitmap, 0, (bitmap_cnt * sizeof(ulong)));

	/* 3. Rport resource Management: Add Rports (buffer) to Rport Pool List
	 */
	unf_rport = (struct unf_rport *)(rport_pool->rport_pool_add);
	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	for (i = 0; i < rport_pool->rport_pool_count; i++) {
		spin_lock_init(&unf_rport->rport_state_lock);
		list_add_tail(&unf_rport->entry_rport, &rport_pool->list_rports_pool);
		sema_init(&unf_rport->task_sema, 0);
		unf_rport++;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	return ret;
}

static void unf_free_rport_pool(struct unf_lport *lport)
{
	struct unf_rport_pool *rport_pool = NULL;
	bool wait = false;
	ulong flag = 0;
	u32 remain = 0;
	u64 timeout = 0;
	u32 max_login = 0;
	u32 i;
	struct unf_rport *unf_rport = NULL;
	struct completion rport_pool_completion;

	init_completion(&rport_pool_completion);
	FC_CHECK_RETURN_VOID(lport);

	rport_pool = &lport->rport_pool;
	max_login = lport->low_level_func.lport_cfg_items.max_login;

	spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
	if (rport_pool->rport_pool_count != max_login) {
		rport_pool->rport_pool_completion = &rport_pool_completion;
		remain = max_login - rport_pool->rport_pool_count;
		wait = true;
	}
	spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);

	if (wait) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) begin to wait for RPort pool completion, remain(0x%x)",
			     lport->port_id, remain);

		unf_show_all_rport(lport);

		timeout = wait_for_completion_timeout(rport_pool->rport_pool_completion,
						      msecs_to_jiffies(UNF_OS_REMOVE_CARD_TIMEOUT));
		if (timeout == 0)
			unf_cm_mark_dirty_mem(lport, UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) wait for RPort pool completion end",
			     lport->port_id);

		spin_lock_irqsave(&rport_pool->rport_free_pool_lock, flag);
		rport_pool->rport_pool_completion = NULL;
		spin_unlock_irqrestore(&rport_pool->rport_free_pool_lock, flag);
	}

	unf_rport = (struct unf_rport *)(rport_pool->rport_pool_add);
	for (i = 0; i < rport_pool->rport_pool_count; i++) {
		if (!unf_rport)
			break;
		unf_rport++;
	}

	if ((lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY) == 0) {
		vfree(rport_pool->rport_pool_add);
		rport_pool->rport_pool_add = NULL;
		vfree(rport_pool->rpi_bitmap);
		rport_pool->rpi_bitmap = NULL;
	}
}

static void unf_init_rscn_node(struct unf_port_id_page *port_id_page)
{
	FC_CHECK_RETURN_VOID(port_id_page);

	port_id_page->addr_format = 0;
	port_id_page->event_qualifier = 0;
	port_id_page->reserved = 0;
	port_id_page->port_id_area = 0;
	port_id_page->port_id_domain = 0;
	port_id_page->port_id_port = 0;
}

struct unf_port_id_page *unf_get_free_rscn_node(void *rscn_mg)
{
	/* Call by Save RSCN Port_ID */
	struct unf_rscn_mgr *rscn_mgr = NULL;
	struct unf_port_id_page *port_id_node = NULL;
	struct list_head *list_node = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(rscn_mg, NULL);
	rscn_mgr = (struct unf_rscn_mgr *)rscn_mg;

	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	if (list_empty(&rscn_mgr->list_free_rscn_page)) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_WARN,
			     "[warn]No RSCN node anymore");

		spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);
		return NULL;
	}

	/* Get from list_free_RSCN_page */
	list_node = UNF_OS_LIST_NEXT(&rscn_mgr->list_free_rscn_page);
	list_del(list_node);
	rscn_mgr->free_rscn_count--;
	port_id_node = list_entry(list_node, struct unf_port_id_page, list_node_rscn);
	unf_init_rscn_node(port_id_node);
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);

	return port_id_node;
}

static void unf_release_rscn_node(void *rscn_mg, void *port_id_node)
{
	/* Call by RSCN GID_ACC */
	struct unf_rscn_mgr *rscn_mgr = NULL;
	struct unf_port_id_page *port_id_page = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(rscn_mg);
	FC_CHECK_RETURN_VOID(port_id_node);
	rscn_mgr = (struct unf_rscn_mgr *)rscn_mg;
	port_id_page = (struct unf_port_id_page *)port_id_node;

	/* Back to list_free_RSCN_page */
	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	rscn_mgr->free_rscn_count++;
	unf_init_rscn_node(port_id_page);
	list_add_tail(&port_id_page->list_node_rscn, &rscn_mgr->list_free_rscn_page);
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);
}

static u32 unf_init_rscn_pool(struct unf_lport *lport)
{
	struct unf_rscn_mgr *rscn_mgr = NULL;
	struct unf_port_id_page *port_id_page = NULL;
	u32 ret = RETURN_OK;
	u32 i = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	rscn_mgr = &lport->disc.rscn_mgr;

	/* Get RSCN Pool buffer */
	rscn_mgr->rscn_pool_add = vmalloc(UNF_LIST_RSCN_PAGE_CNT * sizeof(struct unf_port_id_page));
	if (!rscn_mgr->rscn_pool_add) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate RSCN pool failed", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(rscn_mgr->rscn_pool_add, 0,
	       UNF_LIST_RSCN_PAGE_CNT * sizeof(struct unf_port_id_page));

	spin_lock_irqsave(&rscn_mgr->rscn_id_list_lock, flag);
	port_id_page = (struct unf_port_id_page *)(rscn_mgr->rscn_pool_add);
	for (i = 0; i < UNF_LIST_RSCN_PAGE_CNT; i++) {
		/* Add tail to list_free_RSCN_page */
		list_add_tail(&port_id_page->list_node_rscn, &rscn_mgr->list_free_rscn_page);

		rscn_mgr->free_rscn_count++;
		port_id_page++;
	}
	spin_unlock_irqrestore(&rscn_mgr->rscn_id_list_lock, flag);

	return ret;
}

static void unf_freerscn_pool(struct unf_lport *lport)
{
	struct unf_disc *disc = NULL;

	FC_CHECK_RETURN_VOID(lport);

	disc = &lport->disc;
	if (disc->rscn_mgr.rscn_pool_add) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_INFO, "[info]Port(0x%x) free RSCN pool", lport->nport_id);

		vfree(disc->rscn_mgr.rscn_pool_add);
		disc->rscn_mgr.rscn_pool_add = NULL;
	}
}

static u32 unf_init_rscn_mgr(struct unf_lport *lport)
{
	struct unf_rscn_mgr *rscn_mgr = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	rscn_mgr = &lport->disc.rscn_mgr;

	INIT_LIST_HEAD(&rscn_mgr->list_free_rscn_page); /* free RSCN page list */
	INIT_LIST_HEAD(&rscn_mgr->list_using_rscn_page); /* busy RSCN page list */
	spin_lock_init(&rscn_mgr->rscn_id_list_lock);
	rscn_mgr->free_rscn_count = 0;
	rscn_mgr->unf_get_free_rscn_node = unf_get_free_rscn_node;
	rscn_mgr->unf_release_rscn_node = unf_release_rscn_node;

	ret = unf_init_rscn_pool(lport);
	return ret;
}

static void unf_destroy_rscn_mngr(struct unf_lport *lport)
{
	struct unf_rscn_mgr *rscn_mgr = NULL;

	FC_CHECK_RETURN_VOID(lport);
	rscn_mgr = &lport->disc.rscn_mgr;

	rscn_mgr->free_rscn_count = 0;
	rscn_mgr->unf_get_free_rscn_node = NULL;
	rscn_mgr->unf_release_rscn_node = NULL;

	unf_freerscn_pool(lport);
}

static u32 unf_init_disc_rport_pool(struct unf_lport *lport)
{
	struct unf_disc_rport_mg *disc_mgr = NULL;
	struct unf_disc_rport *disc_rport = NULL;
	u32 i = 0;
	u32 max_log_in = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	max_log_in = lport->low_level_func.lport_cfg_items.max_login;
	disc_mgr = &lport->disc.disc_rport_mgr;

	/* Alloc R_Port Disc Pool buffer */
	disc_mgr->disc_pool_add =
	    vmalloc(max_log_in * sizeof(struct unf_disc_rport));
	if (!disc_mgr->disc_pool_add) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate disc RPort pool failed", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(disc_mgr->disc_pool_add, 0, (max_log_in * sizeof(struct unf_disc_rport)));

	/* Add R_Port to (free) DISC R_Port Pool */
	spin_lock_irqsave(&lport->disc.rport_busy_pool_lock, flag);
	disc_rport = (struct unf_disc_rport *)(disc_mgr->disc_pool_add);
	for (i = 0; i < max_log_in; i++) {
		/* Add tail to list_disc_Rport_pool */
		list_add_tail(&disc_rport->entry_rport, &disc_mgr->list_disc_rports_pool);

		disc_rport++;
	}
	spin_unlock_irqrestore(&lport->disc.rport_busy_pool_lock, flag);

	return RETURN_OK;
}

static void unf_free_disc_rport_pool(struct unf_lport *lport)
{
	struct unf_disc *disc = NULL;

	FC_CHECK_RETURN_VOID(lport);

	disc = &lport->disc;
	if (disc->disc_rport_mgr.disc_pool_add) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_INFO, "[info]Port(0x%x) free disc RPort pool", lport->port_id);

		vfree(disc->disc_rport_mgr.disc_pool_add);
		disc->disc_rport_mgr.disc_pool_add = NULL;
	}
}

int unf_discover_port_info(void *arg_in)
{
	struct unf_disc_gs_event_info *disc_gs_info = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;

	FC_CHECK_RETURN_VALUE(arg_in, UNF_RETURN_ERROR);

	disc_gs_info = (struct unf_disc_gs_event_info *)arg_in;
	unf_lport = (struct unf_lport *)disc_gs_info->lport;
	unf_rport = (struct unf_rport *)disc_gs_info->rport;

	switch (disc_gs_info->type) {
	case UNF_DISC_GET_PORT_NAME:
		ret = unf_send_gpn_id(unf_lport, unf_rport, disc_gs_info->rport_id);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) send GPN_ID failed RPort(0x%x)",
				     unf_lport->nport_id, disc_gs_info->rport_id);
			unf_rcv_gpn_id_rsp_unknown(unf_lport, disc_gs_info->rport_id);
		}
		break;
	case UNF_DISC_GET_FEATURE:
		ret = unf_send_gff_id(unf_lport, unf_rport, disc_gs_info->rport_id);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) send GFF_ID failed to get RPort(0x%x)'s feature",
				     unf_lport->port_id, disc_gs_info->rport_id);

			unf_rcv_gff_id_rsp_unknown(unf_lport, disc_gs_info->rport_id);
		}
		break;
	case UNF_DISC_GET_NODE_NAME:
		ret = unf_send_gnn_id(unf_lport, unf_rport, disc_gs_info->rport_id);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) GNN_ID send failed with NPort ID(0x%x)",
				     unf_lport->port_id, disc_gs_info->rport_id);

			/* NOTE: Continue to next stage */
			unf_rcv_gnn_id_rsp_unknown(unf_lport, unf_rport, disc_gs_info->rport_id);
		}
		break;
	default:
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]Send GS packet type(0x%x) is unknown", disc_gs_info->type);
	}

	kfree(disc_gs_info);

	return (int)ret;
}

u32 unf_get_and_post_disc_event(void *lport, void *sns_port, u32 nport_id,
				enum unf_disc_type type)
{
	struct unf_disc_gs_event_info *disc_gs_info = NULL;
	ulong flag = 0;
	struct unf_lport *root_lport = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_disc_manage_info *disc_info = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(sns_port, UNF_RETURN_ERROR);

	unf_lport = (struct unf_lport *)lport;

	if (unf_lport->link_up == UNF_PORT_LINK_DOWN)
		return RETURN_OK;

	root_lport = unf_lport->root_lport;
	disc_info = &root_lport->disc.disc_thread_info;

	if (disc_info->thread_exit)
		return RETURN_OK;

	disc_gs_info = kmalloc(sizeof(struct unf_disc_gs_event_info), GFP_ATOMIC);
	if (!disc_gs_info)
		return UNF_RETURN_ERROR;

	disc_gs_info->type = type;
	disc_gs_info->lport = unf_lport;
	disc_gs_info->rport = sns_port;
	disc_gs_info->rport_id = nport_id;

	INIT_LIST_HEAD(&disc_gs_info->list_entry);

	spin_lock_irqsave(&disc_info->disc_event_list_lock, flag);
	list_add_tail(&disc_gs_info->list_entry, &disc_info->list_head);
	spin_unlock_irqrestore(&disc_info->disc_event_list_lock, flag);
	wake_up_process(disc_info->thread);
	return RETURN_OK;
}

static int unf_disc_event_process(void *arg)
{
	struct list_head *node = NULL;
	struct unf_disc_gs_event_info *disc_gs_info = NULL;
	ulong flags = 0;
	struct unf_disc *disc = (struct unf_disc *)arg;
	struct unf_disc_manage_info *disc_info = &disc->disc_thread_info;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) enter discovery thread.", disc->lport->port_id);

	while (!kthread_should_stop()) {
		if (disc_info->thread_exit)
			break;

		spin_lock_irqsave(&disc_info->disc_event_list_lock, flags);
		if ((list_empty(&disc_info->list_head)) ||
		    (atomic_read(&disc_info->disc_contrl_size) == 0)) {
			spin_unlock_irqrestore(&disc_info->disc_event_list_lock, flags);

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((long)msecs_to_jiffies(UNF_S_TO_MS));
		} else {
			node = UNF_OS_LIST_NEXT(&disc_info->list_head);
			list_del_init(node);
			disc_gs_info = list_entry(node, struct unf_disc_gs_event_info, list_entry);
			spin_unlock_irqrestore(&disc_info->disc_event_list_lock, flags);
			unf_discover_port_info(disc_gs_info);
		}
	}
	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
		     "Port(0x%x) discovery thread over.", disc->lport->port_id);

	return RETURN_OK;
}

void unf_flush_disc_event(void *disc, void *vport)
{
	struct unf_disc *unf_disc = (struct unf_disc *)disc;
	struct unf_disc_manage_info *disc_info = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	struct unf_disc_gs_event_info *disc_gs_info = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(disc);

	disc_info = &unf_disc->disc_thread_info;

	spin_lock_irqsave(&disc_info->disc_event_list_lock, flag);
	list_for_each_safe(list, list_tmp, &disc_info->list_head) {
		disc_gs_info = list_entry(list, struct unf_disc_gs_event_info, list_entry);

		if (!vport || disc_gs_info->lport == vport) {
			list_del_init(&disc_gs_info->list_entry);
			kfree(disc_gs_info);
		}
	}

	if (!vport)
		atomic_set(&disc_info->disc_contrl_size, UNF_MAX_GS_SEND_NUM);
	spin_unlock_irqrestore(&disc_info->disc_event_list_lock, flag);
}

void unf_disc_ctrl_size_inc(void *lport, u32 cmnd)
{
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport = (struct unf_lport *)lport;
	unf_lport = unf_lport->root_lport;
	FC_CHECK_RETURN_VOID(unf_lport);

	if (atomic_read(&unf_lport->disc.disc_thread_info.disc_contrl_size) ==
	    UNF_MAX_GS_SEND_NUM)
		return;

	if (cmnd == NS_GPN_ID || cmnd == NS_GNN_ID || cmnd == NS_GFF_ID)
		atomic_inc(&unf_lport->disc.disc_thread_info.disc_contrl_size);
}

void unf_destroy_disc_thread(void *disc)
{
	struct unf_disc_manage_info *disc_info = NULL;
	struct unf_disc *unf_disc = (struct unf_disc *)disc;

	FC_CHECK_RETURN_VOID(unf_disc);

	disc_info = &unf_disc->disc_thread_info;

	disc_info->thread_exit = true;
	unf_flush_disc_event(unf_disc, NULL);

	wake_up_process(disc_info->thread);
	kthread_stop(disc_info->thread);
	disc_info->thread = NULL;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "Port(0x%x) destroy discovery thread succeed.",
		     unf_disc->lport->port_id);
}

u32 unf_crerate_disc_thread(void *disc)
{
	struct unf_disc_manage_info *disc_info = NULL;
	struct unf_disc *unf_disc = (struct unf_disc *)disc;

	FC_CHECK_RETURN_VALUE(unf_disc, UNF_RETURN_ERROR);

	/* If the thread cannot be found, apply for a new thread. */
	disc_info = &unf_disc->disc_thread_info;

	memset(disc_info, 0, sizeof(struct unf_disc_manage_info));

	INIT_LIST_HEAD(&disc_info->list_head);
	spin_lock_init(&disc_info->disc_event_list_lock);
	atomic_set(&disc_info->disc_contrl_size, UNF_MAX_GS_SEND_NUM);

	disc_info->thread_exit = false;
	disc_info->thread = kthread_create(unf_disc_event_process, unf_disc, "%x_DiscT",
					   unf_disc->lport->port_id);

	if (IS_ERR(disc_info->thread) || !disc_info->thread) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) creat discovery thread(0x%p) unsuccessful.",
			     unf_disc->lport->port_id, disc_info->thread);

		return UNF_RETURN_ERROR;
	}

	wake_up_process(disc_info->thread);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) creat discovery thread succeed.", unf_disc->lport->port_id);

	return RETURN_OK;
}

void unf_disc_ref_cnt_dec(struct unf_disc *disc)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(disc);

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if (atomic_dec_and_test(&disc->disc_ref_cnt)) {
		if (disc->disc_completion)
			complete(disc->disc_completion);
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
}

void unf_wait_disc_complete(struct unf_lport *lport)
{
	struct unf_disc *disc = NULL;
	bool wait = false;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	u64 time_out = 0;

	struct completion disc_completion;

	init_completion(&disc_completion);
	disc = &lport->disc;

	UNF_DELAYED_WORK_SYNC(ret, (lport->port_id), (&disc->disc_work),
			      "Disc_work");
	if (ret == RETURN_OK)
		unf_disc_ref_cnt_dec(disc);

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	if (atomic_read(&disc->disc_ref_cnt) != 0) {
		disc->disc_completion = &disc_completion;
		wait = true;
	}
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	if (wait) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) begin to wait for discover completion",
			     lport->port_id);

		time_out =
			wait_for_completion_timeout(disc->disc_completion,
						    msecs_to_jiffies(UNF_OS_REMOVE_CARD_TIMEOUT));
		if (time_out == 0)
			unf_cm_mark_dirty_mem(lport, UNF_LPORT_DIRTY_FLAG_DISC_DIRTY);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) wait for discover completion end", lport->port_id);

		spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
		disc->disc_completion = NULL;
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	}
}

void unf_disc_mgr_destroy(void *lport)
{
	struct unf_disc *disc = NULL;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(lport);
	unf_lport = (struct unf_lport *)lport;

	disc = &unf_lport->disc;
	disc->retry_count = 0;
	disc->disc_temp.unf_disc_start = NULL;
	disc->disc_temp.unf_disc_stop = NULL;
	disc->disc_temp.unf_disc_callback = NULL;

	unf_free_disc_rport_pool(unf_lport);
	unf_destroy_rscn_mngr(unf_lport);
	unf_wait_disc_complete(unf_lport);

	if (unf_lport->root_lport != unf_lport)
		return;

	unf_destroy_disc_thread(disc);
	unf_free_rport_pool(unf_lport);
	unf_lport->destroy_step = UNF_LPORT_DESTROY_STEP_6_DESTROY_DISC_MGR;
}

void unf_disc_error_recovery(void *lport)
{
	struct unf_rport *unf_rport = NULL;
	struct unf_disc *disc = NULL;
	ulong delay = 0;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport = (struct unf_lport *)lport;
	disc = &unf_lport->disc;

	unf_rport = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_DIR_SERV);
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Port(0x%x) find RPort failed", unf_lport->port_id);
		return;
	}

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);

	/* Delay work is pending */
	if (delayed_work_pending(&disc->disc_work)) {
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) disc_work is running and do nothing",
			     unf_lport->port_id);
		return;
	}

	/* Continue to retry */
	if (disc->retry_count < disc->max_retry_count) {
		disc->retry_count++;
		delay = (ulong)unf_lport->ed_tov;
		if (queue_delayed_work(unf_wq, &disc->disc_work,
				       (ulong)msecs_to_jiffies((u32)delay)))
			atomic_inc(&disc->disc_ref_cnt);
		spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
	} else {
		/* Go to next stage */
		if (disc->states == UNF_DISC_ST_GIDPT_WAIT) {
			/* GID_PT_WAIT --->>> Send GID_FT */
			unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_RETRY_TIMEOUT);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

			while ((ret != RETURN_OK) &&
			       (disc->retry_count < disc->max_retry_count)) {
				ret = unf_send_gid_ft(unf_lport, unf_rport);
				disc->retry_count++;
			}
		} else if (disc->states == UNF_DISC_ST_GIDFT_WAIT) {
			/* GID_FT_WAIT --->>> Send LOGO */
			unf_disc_state_ma(unf_lport, UNF_EVENT_DISC_RETRY_TIMEOUT);
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
		} else {
			spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
		}
	}
}

enum unf_disc_state unf_disc_stat_start(enum unf_disc_state old_state,
					enum unf_disc_event event)
{
	enum unf_disc_state next_state = UNF_DISC_ST_END;

	if (event == UNF_EVENT_DISC_NORMAL_ENTER)
		next_state = UNF_DISC_ST_GIDPT_WAIT;
	else
		next_state = old_state;

	return next_state;
}

enum unf_disc_state unf_disc_stat_gid_pt_wait(enum unf_disc_state old_state,
					      enum unf_disc_event event)
{
	enum unf_disc_state next_state = UNF_DISC_ST_END;

	switch (event) {
	case UNF_EVENT_DISC_FAILED:
		next_state = UNF_DISC_ST_GIDPT_WAIT;
		break;

	case UNF_EVENT_DISC_RETRY_TIMEOUT:
		next_state = UNF_DISC_ST_GIDFT_WAIT;
		break;

	case UNF_EVENT_DISC_SUCCESS:
		next_state = UNF_DISC_ST_END;
		break;

	case UNF_EVENT_DISC_LINKDOWN:
		next_state = UNF_DISC_ST_START;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

enum unf_disc_state unf_disc_stat_gid_ft_wait(enum unf_disc_state old_state,
					      enum unf_disc_event event)
{
	enum unf_disc_state next_state = UNF_DISC_ST_END;

	switch (event) {
	case UNF_EVENT_DISC_FAILED:
		next_state = UNF_DISC_ST_GIDFT_WAIT;
		break;

	case UNF_EVENT_DISC_RETRY_TIMEOUT:
		next_state = UNF_DISC_ST_END;
		break;

	case UNF_EVENT_DISC_LINKDOWN:
		next_state = UNF_DISC_ST_START;
		break;

	case UNF_EVENT_DISC_SUCCESS:
		next_state = UNF_DISC_ST_END;
		break;

	default:
		next_state = old_state;
		break;
	}

	return next_state;
}

enum unf_disc_state unf_disc_stat_end(enum unf_disc_state old_state, enum unf_disc_event event)
{
	enum unf_disc_state next_state = UNF_DISC_ST_END;

	if (event == UNF_EVENT_DISC_LINKDOWN)
		next_state = UNF_DISC_ST_START;
	else
		next_state = old_state;

	return next_state;
}

void unf_disc_state_ma(struct unf_lport *lport, enum unf_disc_event event)
{
	struct unf_disc *disc = NULL;
	enum unf_disc_state old_state = UNF_DISC_ST_START;
	enum unf_disc_state next_state = UNF_DISC_ST_START;

	FC_CHECK_RETURN_VOID(lport);

	disc = &lport->disc;
	old_state = disc->states;

	switch (disc->states) {
	case UNF_DISC_ST_START:
		next_state = unf_disc_stat_start(old_state, event);
		break;

	case UNF_DISC_ST_GIDPT_WAIT:
		next_state = unf_disc_stat_gid_pt_wait(old_state, event);
		break;

	case UNF_DISC_ST_GIDFT_WAIT:
		next_state = unf_disc_stat_gid_ft_wait(old_state, event);
		break;

	case UNF_DISC_ST_END:
		next_state = unf_disc_stat_end(old_state, event);
		break;

	default:
		next_state = old_state;
		break;
	}

	unf_set_disc_state(disc, next_state);
}

static void unf_lport_disc_timeout(struct work_struct *work)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_disc *disc = NULL;
	enum unf_disc_state state = UNF_DISC_ST_END;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(work);

	disc = container_of(work, struct unf_disc, disc_work.work);
	if (!disc) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_WARN, "[warn]Get discover pointer failed");

		return;
	}

	unf_lport = disc->lport;
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Find Port by discovery work failed");

		unf_disc_ref_cnt_dec(disc);
		return;
	}

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);
	state = disc->states;
	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);

	unf_rport = unf_get_rport_by_nport_id(unf_lport, UNF_FC_FID_DIR_SERV); /* 0xfffffc */
	if (!unf_rport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) find fabric RPort failed", unf_lport->port_id);

		unf_disc_ref_cnt_dec(disc);
		return;
	}

	switch (state) {
	case UNF_DISC_ST_START:
		break;

	case UNF_DISC_ST_GIDPT_WAIT:
		(void)unf_send_gid_pt(unf_lport, unf_rport);
		break;

	case UNF_DISC_ST_GIDFT_WAIT:
		(void)unf_send_gid_ft(unf_lport, unf_rport);
		break;

	case UNF_DISC_ST_END:
		break;

	default:
		break;
	}

	unf_disc_ref_cnt_dec(disc);
}

u32 unf_init_disc_mgr(struct unf_lport *lport)
{
	struct unf_disc *disc = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	disc = &lport->disc;
	disc->max_retry_count = UNF_DISC_RETRY_TIMES;
	disc->retry_count = 0;
	disc->disc_flag = UNF_DISC_NONE;
	INIT_LIST_HEAD(&disc->list_busy_rports);
	INIT_LIST_HEAD(&disc->list_delete_rports);
	INIT_LIST_HEAD(&disc->list_destroy_rports);
	spin_lock_init(&disc->rport_busy_pool_lock);

	disc->disc_rport_mgr.disc_pool_add = NULL;
	INIT_LIST_HEAD(&disc->disc_rport_mgr.list_disc_rports_pool);
	INIT_LIST_HEAD(&disc->disc_rport_mgr.list_disc_rports_busy);

	disc->disc_completion = NULL;
	disc->lport = lport;
	INIT_DELAYED_WORK(&disc->disc_work, unf_lport_disc_timeout);
	disc->disc_temp.unf_disc_start = unf_disc_start;
	disc->disc_temp.unf_disc_stop = unf_disc_stop;
	disc->disc_temp.unf_disc_callback = NULL;
	atomic_set(&disc->disc_ref_cnt, 0);

	/* Init RSCN Manager */
	ret = unf_init_rscn_mgr(lport);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	if (lport->root_lport != lport)
		return ret;

	ret = unf_crerate_disc_thread(disc);
	if (ret != RETURN_OK) {
		unf_destroy_rscn_mngr(lport);

		return UNF_RETURN_ERROR;
	}

	/* Init R_Port free Pool */
	ret = unf_init_rport_pool(lport);
	if (ret != RETURN_OK) {
		unf_destroy_disc_thread(disc);
		unf_destroy_rscn_mngr(lport);

		return UNF_RETURN_ERROR;
	}

	/* Init R_Port free disc Pool */
	ret = unf_init_disc_rport_pool(lport);
	if (ret != RETURN_OK) {
		unf_destroy_disc_thread(disc);
		unf_free_rport_pool(lport);
		unf_destroy_rscn_mngr(lport);

		return UNF_RETURN_ERROR;
	}

	return ret;
}
