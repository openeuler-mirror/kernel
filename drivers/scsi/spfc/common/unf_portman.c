// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_portman.h"
#include "unf_log.h"
#include "unf_exchg.h"
#include "unf_rport.h"
#include "unf_io.h"
#include "unf_npiv.h"
#include "unf_scsi_common.h"

#define UNF_LPORT_CHIP_ERROR(unf_lport) \
	((unf_lport)->pcie_error_cnt.pcie_error_count[UNF_PCIE_FATALERRORDETECTED])

struct unf_global_lport global_lport_mgr;

static int unf_port_switch(struct unf_lport *lport, bool switch_flag);
static u32 unf_build_lport_wwn(struct unf_lport *lport);
static int unf_lport_destroy(void *lport, void *arg_out);
static u32 unf_port_linkup(struct unf_lport *lport, void *input);
static u32 unf_port_linkdown(struct unf_lport *lport, void *input);
static u32 unf_port_abnormal_reset(struct unf_lport *lport, void *input);
static u32 unf_port_reset_start(struct unf_lport *lport, void *input);
static u32 unf_port_reset_end(struct unf_lport *lport, void *input);
static u32 unf_port_nop(struct unf_lport *lport, void *input);
static void unf_destroy_card_thread(struct unf_lport *lport);
static u32 unf_creat_card_thread(struct unf_lport *lport);
static u32 unf_find_card_thread(struct unf_lport *lport);
static u32 unf_port_begin_remove(struct unf_lport *lport, void *input);

static struct unf_port_action g_lport_action[] = {
	{UNF_PORT_LINK_UP, unf_port_linkup},
	{UNF_PORT_LINK_DOWN, unf_port_linkdown},
	{UNF_PORT_RESET_START, unf_port_reset_start},
	{UNF_PORT_RESET_END, unf_port_reset_end},
	{UNF_PORT_NOP, unf_port_nop},
	{UNF_PORT_BEGIN_REMOVE, unf_port_begin_remove},
	{UNF_PORT_RELEASE_RPORT_INDEX, unf_port_release_rport_index},
	{UNF_PORT_ABNORMAL_RESET, unf_port_abnormal_reset},
};

static void unf_destroy_dirty_rport(struct unf_lport *lport, bool show_only)
{
	u32 dirty_rport = 0;

	/* for whole L_Port */
	if (lport->dirty_flag & UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY) {
		dirty_rport = lport->rport_pool.rport_pool_count;

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) has %d dirty RPort(s)",
			     lport->port_id, dirty_rport);

		/* Show L_Port's R_Port(s) from busy_list & destroy_list */
		unf_show_all_rport(lport);

		/* free R_Port pool memory & bitmap */
		if (!show_only) {
			vfree(lport->rport_pool.rport_pool_add);
			lport->rport_pool.rport_pool_add = NULL;
			vfree(lport->rport_pool.rpi_bitmap);
			lport->rport_pool.rpi_bitmap = NULL;
		}
	}
}

void unf_show_dirty_port(bool show_only, u32 *dirty_port_num)
{
	struct list_head *node = NULL;
	struct list_head *node_next = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong flags = 0;
	u32 port_num = 0;

	FC_CHECK_RETURN_VOID(dirty_port_num);

	/* for each dirty L_Port from global L_Port list */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_for_each_safe(node, node_next, &global_lport_mgr.dirty_list_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) has dirty data(0x%x)",
			     unf_lport->port_id, unf_lport->dirty_flag);

		/* Destroy dirty L_Port's exchange(s) & R_Port(s) */
		unf_destroy_dirty_xchg(unf_lport, show_only);
		unf_destroy_dirty_rport(unf_lport, show_only);

		/* Delete (dirty L_Port) list entry if necessary */
		if (!show_only) {
			list_del_init(node);
			vfree(unf_lport);
		}

		port_num++;
	}
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	*dirty_port_num = port_num;
}

void unf_show_all_rport(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_disc *disc = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	u32 rport_cnt = 0;
	u32 target_cnt = 0;

	FC_CHECK_RETURN_VOID(lport);

	unf_lport = lport;
	disc = &unf_lport->disc;

	spin_lock_irqsave(&disc->rport_busy_pool_lock, flag);

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
		     "[info]Port(0x%x) disc state(0x%x)", unf_lport->port_id, disc->states);

	/* for each R_Port from busy_list */
	list_for_each_safe(node, next_node, &disc->list_busy_rports) {
		unf_rport = list_entry(node, struct unf_rport, entry_rport);
		rport_cnt++;

		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
			     "[info]Port(0x%x) busy RPorts(%u_%p) WWPN(0x%016llx) scsi_id(0x%x) local N_Port_ID(0x%x) N_Port_ID(0x%06x). State(0x%04x) options(0x%04x) index(0x%04x) ref(%d) pend:%d",
			     unf_lport->port_id, rport_cnt, unf_rport,
			     unf_rport->port_name, unf_rport->scsi_id,
			     unf_rport->local_nport_id, unf_rport->nport_id,
			     unf_rport->rp_state, unf_rport->options,
			     unf_rport->rport_index,
			     atomic_read(&unf_rport->rport_ref_cnt),
			     atomic_read(&unf_rport->pending_io_cnt));

		if (unf_rport->nport_id < UNF_FC_FID_DOM_MGR)
			target_cnt++;
	}

	unf_lport->target_cnt = target_cnt;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) targetnum=(%u)", unf_lport->port_id,
		     unf_lport->target_cnt);

	/* for each R_Port from destroy_list */
	list_for_each_safe(node, next_node, &disc->list_destroy_rports) {
		unf_rport = list_entry(node, struct unf_rport, entry_rport);
		rport_cnt++;

		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
			     "[info]Port(0x%x) destroy RPorts(%u) WWPN(0x%016llx) N_Port_ID(0x%06x) State(0x%04x) options(0x%04x) index(0x%04x) ref(%d)",
			     unf_lport->port_id, rport_cnt, unf_rport->port_name,
			     unf_rport->nport_id, unf_rport->rp_state,
			     unf_rport->options, unf_rport->rport_index,
			     atomic_read(&unf_rport->rport_ref_cnt));
	}

	spin_unlock_irqrestore(&disc->rport_busy_pool_lock, flag);
}

u32 unf_lport_ref_inc(struct unf_lport *lport)
{
	ulong lport_flags = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&lport->lport_state_lock, lport_flags);
	if (atomic_read(&lport->port_ref_cnt) <= 0) {
		spin_unlock_irqrestore(&lport->lport_state_lock, lport_flags);

		return UNF_RETURN_ERROR;
	}

	atomic_inc(&lport->port_ref_cnt);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%p) port_id(0x%x) reference count is %d",
		     lport, lport->port_id, atomic_read(&lport->port_ref_cnt));

	spin_unlock_irqrestore(&lport->lport_state_lock, lport_flags);

	return RETURN_OK;
}

void unf_lport_ref_dec(struct unf_lport *lport)
{
	ulong flags = 0;
	ulong lport_flags = 0;

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "LPort(0x%p), port ID(0x%x), reference count is %d.",
		     lport, lport->port_id, atomic_read(&lport->port_ref_cnt));

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	spin_lock_irqsave(&lport->lport_state_lock, lport_flags);
	if (atomic_dec_and_test(&lport->port_ref_cnt)) {
		spin_unlock_irqrestore(&lport->lport_state_lock, lport_flags);
		list_del(&lport->entry_lport);
		global_lport_mgr.lport_sum--;

		/* attaches the lport to the destroy linked list for dfx */
		list_add_tail(&lport->entry_lport, &global_lport_mgr.destroy_list_head);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

		(void)unf_lport_destroy(lport, NULL);
	} else {
		spin_unlock_irqrestore(&lport->lport_state_lock, lport_flags);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);
	}
}

void unf_lport_update_topo(struct unf_lport *lport,
			   enum unf_act_topo active_topo)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);

	if (active_topo > UNF_ACT_TOP_UNKNOWN || active_topo < UNF_ACT_TOP_PUBLIC_LOOP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) set invalid topology(0x%x) with current value(0x%x)",
			     lport->nport_id, active_topo, lport->act_topo);

		return;
	}

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	lport->act_topo = active_topo;
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);
}

void unf_set_lport_removing(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	lport->fc_port = NULL;
	lport->port_removing = true;
	lport->destroy_step = UNF_LPORT_DESTROY_STEP_0_SET_REMOVING;
}

u32 unf_release_local_port(void *lport)
{
	struct unf_lport *unf_lport = lport;
	struct completion lport_free_completion;

	init_completion(&lport_free_completion);
	FC_CHECK_RETURN_VALUE(unf_lport, UNF_RETURN_ERROR);

	unf_lport->lport_free_completion = &lport_free_completion;
	unf_set_lport_removing(unf_lport);
	unf_lport_ref_dec(unf_lport);
	wait_for_completion(unf_lport->lport_free_completion);
	/* for dirty case */
	if (unf_lport->dirty_flag == 0)
		vfree(unf_lport);

	return RETURN_OK;
}

static void unf_free_all_esgl_pages(struct unf_lport *lport)
{
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	u32 i;

	FC_CHECK_RETURN_VOID(lport);
	spin_lock_irqsave(&lport->esgl_pool.esgl_pool_lock, flag);
	list_for_each_safe(node, next_node, &lport->esgl_pool.list_esgl_pool) {
		list_del(node);
	}

	spin_unlock_irqrestore(&lport->esgl_pool.esgl_pool_lock, flag);
	if (lport->esgl_pool.esgl_buff_list.buflist) {
		for (i = 0; i < lport->esgl_pool.esgl_buff_list.buf_num; i++) {
			if (lport->esgl_pool.esgl_buff_list.buflist[i].vaddr) {
				dma_free_coherent(&lport->low_level_func.dev->dev,
						  lport->esgl_pool.esgl_buff_list.buf_size,
						  lport->esgl_pool.esgl_buff_list.buflist[i].vaddr,
						  lport->esgl_pool.esgl_buff_list.buflist[i].paddr);
				lport->esgl_pool.esgl_buff_list.buflist[i].vaddr = NULL;
			}
		}
		kfree(lport->esgl_pool.esgl_buff_list.buflist);
		lport->esgl_pool.esgl_buff_list.buflist = NULL;
	}
}

static u32 unf_init_esgl_pool(struct unf_lport *lport)
{
	struct unf_esgl *esgl = NULL;
	u32 ret = RETURN_OK;
	u32 index = 0;
	u32 buf_total_size;
	u32 buf_num;
	u32 alloc_idx;
	u32 curbuf_idx = 0;
	u32 curbuf_offset = 0;
	u32 buf_cnt_perhugebuf;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	lport->esgl_pool.esgl_pool_count = lport->low_level_func.lport_cfg_items.max_io;
	spin_lock_init(&lport->esgl_pool.esgl_pool_lock);
	INIT_LIST_HEAD(&lport->esgl_pool.list_esgl_pool);

	lport->esgl_pool.esgl_pool_addr =
	    vmalloc((size_t)((lport->esgl_pool.esgl_pool_count) * sizeof(struct unf_esgl)));
	if (!lport->esgl_pool.esgl_pool_addr) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "LPort(0x%x) cannot allocate ESGL Pool.", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	esgl = (struct unf_esgl *)lport->esgl_pool.esgl_pool_addr;
	memset(esgl, 0, ((lport->esgl_pool.esgl_pool_count) * sizeof(struct unf_esgl)));

	buf_total_size = (u32)(PAGE_SIZE * lport->esgl_pool.esgl_pool_count);

	lport->esgl_pool.esgl_buff_list.buf_size =
	    buf_total_size > BUF_LIST_PAGE_SIZE ? BUF_LIST_PAGE_SIZE : buf_total_size;
	buf_cnt_perhugebuf = lport->esgl_pool.esgl_buff_list.buf_size / PAGE_SIZE;
	buf_num = lport->esgl_pool.esgl_pool_count % buf_cnt_perhugebuf
		? lport->esgl_pool.esgl_pool_count / buf_cnt_perhugebuf + 1
		: lport->esgl_pool.esgl_pool_count / buf_cnt_perhugebuf;
	lport->esgl_pool.esgl_buff_list.buflist =
	    (struct buff_list *)kmalloc(buf_num * sizeof(struct buff_list), GFP_KERNEL);
	lport->esgl_pool.esgl_buff_list.buf_num = buf_num;

	if (!lport->esgl_pool.esgl_buff_list.buflist) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate Esgl pool buf list failed out of memory");
		goto free_buff;
	}
	memset(lport->esgl_pool.esgl_buff_list.buflist, 0, buf_num * sizeof(struct buff_list));

	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		lport->esgl_pool.esgl_buff_list.buflist[alloc_idx]
		    .vaddr = dma_alloc_coherent(&lport->low_level_func.dev->dev,
		    lport->esgl_pool.esgl_buff_list.buf_size,
		    &lport->esgl_pool.esgl_buff_list.buflist[alloc_idx].paddr, GFP_KERNEL);
		if (!lport->esgl_pool.esgl_buff_list.buflist[alloc_idx].vaddr)
			goto free_buff;
		memset(lport->esgl_pool.esgl_buff_list.buflist[alloc_idx].vaddr, 0,
		       lport->esgl_pool.esgl_buff_list.buf_size);
	}

	/* allocates the Esgl page, and the DMA uses the */
	for (index = 0; index < lport->esgl_pool.esgl_pool_count; index++) {
		if (index != 0 && !(index % buf_cnt_perhugebuf))
			curbuf_idx++;
		curbuf_offset = (u32)(PAGE_SIZE * (index % buf_cnt_perhugebuf));
		esgl->page.page_address =
		    (u64)lport->esgl_pool.esgl_buff_list.buflist[curbuf_idx].vaddr + curbuf_offset;
		esgl->page.page_size = PAGE_SIZE;
		esgl->page.esgl_phy_addr =
		    lport->esgl_pool.esgl_buff_list.buflist[curbuf_idx].paddr + curbuf_offset;
		list_add_tail(&esgl->entry_esgl, &lport->esgl_pool.list_esgl_pool);
		esgl++;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[EVENT]Allocate bufnum:%u,buf_total_size:%u", buf_num, buf_total_size);

	return ret;
free_buff:
	unf_free_all_esgl_pages(lport);
	vfree(lport->esgl_pool.esgl_pool_addr);

	return UNF_RETURN_ERROR;
}

static void unf_free_esgl_pool(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	unf_free_all_esgl_pages(lport);
	lport->esgl_pool.esgl_pool_count = 0;

	if (lport->esgl_pool.esgl_pool_addr) {
		vfree(lport->esgl_pool.esgl_pool_addr);
		lport->esgl_pool.esgl_pool_addr = NULL;
	}

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_5_DESTROY_ESGL_POOL;
}

struct unf_lport *unf_find_lport_by_port_id(u32 port_id)
{
	struct unf_lport *unf_lport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;
	u32 portid = port_id & (~PORTID_VPINDEX_MASK);
	u16 vport_index;
	spinlock_t *lport_list_lock = NULL;

	lport_list_lock = &global_lport_mgr.global_lport_list_lock;
	vport_index = (port_id & PORTID_VPINDEX_MASK) >> PORTID_VPINDEX_SHIT;
	spin_lock_irqsave(lport_list_lock, flags);

	list_for_each_safe(node, next_node, &global_lport_mgr.lport_list_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);
		if (unf_lport->port_id == portid && !unf_lport->port_removing) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return unf_cm_lookup_vport_by_vp_index(unf_lport, vport_index);
		}
	}

	list_for_each_safe(node, next_node, &global_lport_mgr.intergrad_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);
		if (unf_lport->port_id == portid && !unf_lport->port_removing) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return unf_cm_lookup_vport_by_vp_index(unf_lport, vport_index);
		}
	}

	spin_unlock_irqrestore(lport_list_lock, flags);

	return NULL;
}

u32 unf_is_vport_valid(struct unf_lport *lport, struct unf_lport *vport)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;
	spinlock_t *vport_pool_lock = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(vport, UNF_RETURN_ERROR);

	unf_lport = lport;
	vport_pool = unf_lport->vport_pool;
	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) vport pool is NULL", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	vport_pool_lock = &vport_pool->vport_pool_lock;
	spin_lock_irqsave(vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);

		if (unf_vport == vport && !unf_vport->port_removing) {
			spin_unlock_irqrestore(vport_pool_lock, flag);

			return RETURN_OK;
		}
	}

	list_for_each_safe(node, next_node, &unf_lport->list_intergrad_vports) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);

		if (unf_vport == vport && !unf_vport->port_removing) {
			spin_unlock_irqrestore(vport_pool_lock, flag);

			return RETURN_OK;
		}
	}
	spin_unlock_irqrestore(vport_pool_lock, flag);

	return UNF_RETURN_ERROR;
}

u32 unf_is_lport_valid(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flags = 0;
	spinlock_t *lport_list_lock = NULL;

	lport_list_lock = &global_lport_mgr.global_lport_list_lock;
	spin_lock_irqsave(lport_list_lock, flags);

	list_for_each_safe(node, next_node, &global_lport_mgr.lport_list_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);

		if (unf_lport == lport && !unf_lport->port_removing) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return RETURN_OK;
		}

		if (unf_is_vport_valid(unf_lport, lport) == RETURN_OK) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return RETURN_OK;
		}
	}

	list_for_each_safe(node, next_node, &global_lport_mgr.intergrad_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);

		if (unf_lport == lport && !unf_lport->port_removing) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return RETURN_OK;
		}

		if (unf_is_vport_valid(unf_lport, lport) == RETURN_OK) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return RETURN_OK;
		}
	}

	list_for_each_safe(node, next_node, &global_lport_mgr.destroy_list_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);

		if (unf_lport == lport && !unf_lport->port_removing) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return RETURN_OK;
		}

		if (unf_is_vport_valid(unf_lport, lport) == RETURN_OK) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return RETURN_OK;
		}
	}

	spin_unlock_irqrestore(lport_list_lock, flags);

	return UNF_RETURN_ERROR;
}

static void unf_clean_linkdown_io(struct unf_lport *lport, bool clean_flag)
{
	/* Clean L_Port/V_Port Link Down I/O: Set Abort Tag */
	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(lport->xchg_mgr_temp.unf_xchg_abort_all_io);

	lport->xchg_mgr_temp.unf_xchg_abort_all_io(lport, UNF_XCHG_TYPE_INI, clean_flag);
	lport->xchg_mgr_temp.unf_xchg_abort_all_io(lport, UNF_XCHG_TYPE_SFS, clean_flag);
}

u32 unf_fc_port_link_event(void *lport, u32 events, void *input)
{
	struct unf_lport *unf_lport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 index = 0;

	if (unlikely(!lport))
		return UNF_RETURN_ERROR;
	unf_lport = (struct unf_lport *)lport;

	ret = unf_lport_ref_inc(unf_lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) is removing and do nothing",
			     unf_lport->port_id);

		return RETURN_OK;
	}

	/* process port event */
	while (index < (sizeof(g_lport_action) / sizeof(struct unf_port_action))) {
		if (g_lport_action[index].action == events) {
			ret = g_lport_action[index].unf_action(unf_lport, input);

			unf_lport_ref_dec_to_destroy(unf_lport);

			return ret;
		}
		index++;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) receive unknown event(0x%x)",
		     unf_lport->port_id, events);

	unf_lport_ref_dec_to_destroy(unf_lport);

	return ret;
}

void unf_port_mgmt_init(void)
{
	memset(&global_lport_mgr, 0, sizeof(struct unf_global_lport));

	INIT_LIST_HEAD(&global_lport_mgr.lport_list_head);

	INIT_LIST_HEAD(&global_lport_mgr.intergrad_head);

	INIT_LIST_HEAD(&global_lport_mgr.destroy_list_head);

	INIT_LIST_HEAD(&global_lport_mgr.dirty_list_head);

	spin_lock_init(&global_lport_mgr.global_lport_list_lock);

	UNF_SET_NOMAL_MODE(global_lport_mgr.dft_mode);

	global_lport_mgr.start_work = true;
}

void unf_port_mgmt_deinit(void)
{
	if (global_lport_mgr.lport_sum != 0) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]There are %u port pool memory giveaway",
			     global_lport_mgr.lport_sum);
	}

	memset(&global_lport_mgr, 0, sizeof(struct unf_global_lport));

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Common port manager exit succeed");
}

static void unf_port_register(struct unf_lport *lport)
{
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Register LPort(0x%p), port ID(0x%x).", lport, lport->port_id);

	/* Add to the global management linked list header */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_add_tail(&lport->entry_lport, &global_lport_mgr.lport_list_head);
	global_lport_mgr.lport_sum++;
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);
}

static void unf_port_unregister(struct unf_lport *lport)
{
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Unregister LPort(0x%p), port ID(0x%x).", lport, lport->port_id);

	/* Remove from the global management linked list header */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_del(&lport->entry_lport);
	global_lport_mgr.lport_sum--;
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);
}

int unf_port_start_work(struct unf_lport *lport)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	if (lport->start_work_state != UNF_START_WORK_STOP) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		return RETURN_OK;
	}
	lport->start_work_state = UNF_START_WORK_COMPLETE;
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	/* switch sfp to start work */
	(void)unf_port_switch(lport, true);

	return RETURN_OK;
}

static u32
unf_lport_init_lw_funop(struct unf_lport *lport,
			struct unf_low_level_functioon_op *low_level_op)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(low_level_op, UNF_RETURN_ERROR);

	lport->port_id = low_level_op->lport_cfg_items.port_id;
	lport->port_name = low_level_op->sys_port_name;
	lport->node_name = low_level_op->sys_node_name;
	lport->options = low_level_op->lport_cfg_items.port_mode;
	lport->act_topo = UNF_ACT_TOP_UNKNOWN;
	lport->max_ssq_num = low_level_op->support_max_ssq_num;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) .", lport->port_id);

	memcpy(&lport->low_level_func, low_level_op, sizeof(struct unf_low_level_functioon_op));

	return RETURN_OK;
}

void unf_lport_release_lw_funop(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VOID(lport);

	memset(&lport->low_level_func, 0, sizeof(struct unf_low_level_functioon_op));

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_13_DESTROY_LW_INTERFACE;
}

struct unf_lport *unf_find_lport_by_scsi_hostid(u32 scsi_host_id)
{
	struct list_head *node = NULL, *next_node = NULL;
	struct list_head *vp_node = NULL, *next_vp_node = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_lport *unf_vport = NULL;
	ulong flags = 0;
	ulong pool_flags = 0;
	spinlock_t *vp_pool_lock = NULL;
	spinlock_t *lport_list_lock = &global_lport_mgr.global_lport_list_lock;

	spin_lock_irqsave(lport_list_lock, flags);
	list_for_each_safe(node, next_node, &global_lport_mgr.lport_list_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);
		vp_pool_lock = &unf_lport->vport_pool->vport_pool_lock;
		if (scsi_host_id == UNF_GET_SCSI_HOST_ID(unf_lport->host_info.host)) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return unf_lport;
		}

		/* support NPIV */
		if (unf_lport->vport_pool) {
			spin_lock_irqsave(vp_pool_lock, pool_flags);
			list_for_each_safe(vp_node, next_vp_node, &unf_lport->list_vports_head) {
				unf_vport = list_entry(vp_node, struct unf_lport, entry_vport);

				if (scsi_host_id ==
				    UNF_GET_SCSI_HOST_ID(unf_vport->host_info.host)) {
					spin_unlock_irqrestore(vp_pool_lock, pool_flags);
					spin_unlock_irqrestore(lport_list_lock, flags);

					return unf_vport;
				}
			}
			spin_unlock_irqrestore(vp_pool_lock, pool_flags);
		}
	}

	list_for_each_safe(node, next_node, &global_lport_mgr.intergrad_head) {
		unf_lport = list_entry(node, struct unf_lport, entry_lport);
		vp_pool_lock = &unf_lport->vport_pool->vport_pool_lock;
		if (scsi_host_id ==
		    UNF_GET_SCSI_HOST_ID(unf_lport->host_info.host)) {
			spin_unlock_irqrestore(lport_list_lock, flags);

			return unf_lport;
		}

		/* support NPIV */
		if (unf_lport->vport_pool) {
			spin_lock_irqsave(vp_pool_lock, pool_flags);
			list_for_each_safe(vp_node, next_vp_node, &unf_lport->list_vports_head) {
				unf_vport = list_entry(vp_node, struct unf_lport, entry_vport);

				if (scsi_host_id ==
				    UNF_GET_SCSI_HOST_ID(unf_vport->host_info.host)) {
					spin_unlock_irqrestore(vp_pool_lock, pool_flags);
					spin_unlock_irqrestore(lport_list_lock, flags);

					return unf_vport;
				}
			}
			spin_unlock_irqrestore(vp_pool_lock, pool_flags);
		}
	}
	spin_unlock_irqrestore(lport_list_lock, flags);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
		     "[warn]Can not find port by scsi_host_id(0x%x), may be removing",
		     scsi_host_id);

	return NULL;
}

u32 unf_init_scsi_id_table(struct unf_lport *lport)
{
	struct unf_rport_scsi_id_image *rport_scsi_id_image = NULL;
	struct unf_wwpn_rport_info *wwpn_port_info = NULL;
	u32 idx;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	rport_scsi_id_image = &lport->rport_scsi_table;
	rport_scsi_id_image->max_scsi_id = UNF_MAX_SCSI_ID;

	/* If the number of remote connections supported by the L_Port is 0, an
	 * exception occurs
	 */
	if (rport_scsi_id_image->max_scsi_id == 0) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x), supported maximum login is zero.", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	rport_scsi_id_image->wwn_rport_info_table =
	    vmalloc(rport_scsi_id_image->max_scsi_id * sizeof(struct unf_wwpn_rport_info));
	if (!rport_scsi_id_image->wwn_rport_info_table) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) can't allocate SCSI ID Table(0x%x).",
			     lport->port_id, rport_scsi_id_image->max_scsi_id);

		return UNF_RETURN_ERROR;
	}
	memset(rport_scsi_id_image->wwn_rport_info_table, 0,
	       rport_scsi_id_image->max_scsi_id * sizeof(struct unf_wwpn_rport_info));

	wwpn_port_info = rport_scsi_id_image->wwn_rport_info_table;

	for (idx = 0; idx < rport_scsi_id_image->max_scsi_id; idx++) {
		INIT_DELAYED_WORK(&wwpn_port_info->loss_tmo_work, unf_sesion_loss_timeout);
		INIT_LIST_HEAD(&wwpn_port_info->fc_lun_list);
		wwpn_port_info->lport = lport;
		wwpn_port_info->target_id = INVALID_VALUE32;
		wwpn_port_info++;
	}

	spin_lock_init(&rport_scsi_id_image->scsi_image_table_lock);
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Port(0x%x) supported maximum login is %u.",
		     lport->port_id, rport_scsi_id_image->max_scsi_id);

	return RETURN_OK;
}

void unf_destroy_scsi_id_table(struct unf_lport *lport)
{
	struct unf_rport_scsi_id_image *rport_scsi_id_image = NULL;
	struct unf_wwpn_rport_info *wwn_rport_info = NULL;
	u32 i = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);

	rport_scsi_id_image = &lport->rport_scsi_table;
	if (rport_scsi_id_image->wwn_rport_info_table) {
		for (i = 0; i < UNF_MAX_SCSI_ID; i++) {
			wwn_rport_info = &rport_scsi_id_image->wwn_rport_info_table[i];
			UNF_DELAYED_WORK_SYNC(ret, (lport->port_id),
					      (&wwn_rport_info->loss_tmo_work),
					      "loss tmo Timer work");
			if (wwn_rport_info->lun_qos_level) {
				vfree(wwn_rport_info->lun_qos_level);
				wwn_rport_info->lun_qos_level = NULL;
			}
		}

		if (ret) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
				     "Port(0x%x) cancel loss tmo work success", lport->port_id);
		}
		vfree(rport_scsi_id_image->wwn_rport_info_table);
		rport_scsi_id_image->wwn_rport_info_table = NULL;
	}

	rport_scsi_id_image->max_scsi_id = 0;
	lport->destroy_step = UNF_LPORT_DESTROY_STEP_10_DESTROY_SCSI_TABLE;
}

static u32 unf_lport_init(struct unf_lport *lport, void *private_data,
			  struct unf_low_level_functioon_op *low_level_op)
{
	u32 ret = RETURN_OK;
	char work_queue_name[13];

	unf_init_port_parms(lport);

	/* Associating  LPort with FCPort */
	lport->fc_port = private_data;

	/* VpIndx=0 is reserved for Lport, and rootLport points to its own */
	lport->vp_index = 0;
	lport->root_lport = lport;
	lport->chip_info = NULL;

	/* Initialize the units related to L_Port and lw func */
	ret = unf_lport_init_lw_funop(lport, low_level_op);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) initialize lowlevel function unsuccessful.",
			     lport->port_id);

		return ret;
	}

	/* Init Linkevent workqueue */
	snprintf(work_queue_name, sizeof(work_queue_name), "%x_lkq", lport->port_id);

	lport->link_event_wq = create_singlethread_workqueue(work_queue_name);
	if (!lport->link_event_wq) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]Port(0x%x) creat link event work queue failed", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	snprintf(work_queue_name, sizeof(work_queue_name), "%x_xchgwq", lport->port_id);
	lport->xchg_wq = create_workqueue(work_queue_name);
	if (!lport->xchg_wq) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]Port(0x%x) creat Exchg work queue failed",
			     lport->port_id);
		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;
		return UNF_RETURN_ERROR;
	}
	/* scsi table (R_Port) required for initializing INI
	 * Initialize the scsi id Table table to manage the mapping between SCSI
	 * ID, WWN, and Rport.
	 */

	ret = unf_init_scsi_id_table(lport);
	if (ret != RETURN_OK) {
		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;

		flush_workqueue(lport->xchg_wq);
		destroy_workqueue(lport->xchg_wq);
		lport->xchg_wq = NULL;
		return ret;
	}

	/* Initialize the EXCH resource */
	ret = unf_alloc_xchg_resource(lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) can't allocate exchange resource.", lport->port_id);

		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;

		flush_workqueue(lport->xchg_wq);
		destroy_workqueue(lport->xchg_wq);
		lport->xchg_wq = NULL;
		unf_destroy_scsi_id_table(lport);

		return ret;
	}

	/* Initialize the ESGL resource pool used by Lport */
	ret = unf_init_esgl_pool(lport);
	if (ret != RETURN_OK) {
		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;

		flush_workqueue(lport->xchg_wq);
		destroy_workqueue(lport->xchg_wq);
		lport->xchg_wq = NULL;
		unf_free_all_xchg_mgr(lport);
		unf_destroy_scsi_id_table(lport);

		return ret;
	}
	/* Initialize the disc manager under Lport */
	ret = unf_init_disc_mgr(lport);
	if (ret != RETURN_OK) {
		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;

		flush_workqueue(lport->xchg_wq);
		destroy_workqueue(lport->xchg_wq);
		lport->xchg_wq = NULL;
		unf_free_esgl_pool(lport);
		unf_free_all_xchg_mgr(lport);
		unf_destroy_scsi_id_table(lport);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) initialize discover manager unsuccessful.",
			     lport->port_id);

		return ret;
	}

	/* Initialize the LPort manager */
	ret = unf_init_vport_mgr_temp(lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) initialize RPort manager unsuccessful.", lport->port_id);

		goto RELEASE_LPORT;
	}

	/* Initialize the EXCH manager */
	ret = unf_init_xchg_mgr_temp(lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) initialize exchange manager unsuccessful.",
			     lport->port_id);
		goto RELEASE_LPORT;
	}
	/* Initialize the resources required by the event processing center */
	ret = unf_init_event_center(lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) initialize event center unsuccessful.", lport->port_id);
		goto RELEASE_LPORT;
	}
	/* Initialize the initialization status of Lport */
	unf_set_lport_state(lport, UNF_LPORT_ST_INITIAL);

	/* Initialize the Lport route test case */
	ret = unf_init_lport_route(lport);
	if (ret != RETURN_OK) {
		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;

		flush_workqueue(lport->xchg_wq);
		destroy_workqueue(lport->xchg_wq);
		lport->xchg_wq = NULL;
		(void)unf_event_center_destroy(lport);
		unf_disc_mgr_destroy(lport);
		unf_free_esgl_pool(lport);
		unf_free_all_xchg_mgr(lport);
		unf_destroy_scsi_id_table(lport);

		return ret;
	}
	/* Thesupports the initialization stepof the NPIV */
	ret = unf_init_vport_pool(lport);
	if (ret != RETURN_OK) {
		flush_workqueue(lport->link_event_wq);
		destroy_workqueue(lport->link_event_wq);
		lport->link_event_wq = NULL;

		flush_workqueue(lport->xchg_wq);
		destroy_workqueue(lport->xchg_wq);
		lport->xchg_wq = NULL;

		unf_destroy_lport_route(lport);
		(void)unf_event_center_destroy(lport);
		unf_disc_mgr_destroy(lport);
		unf_free_esgl_pool(lport);
		unf_free_all_xchg_mgr(lport);
		unf_destroy_scsi_id_table(lport);

		return ret;
	}

	/* qualifier rport callback */
	lport->unf_qualify_rport = unf_rport_set_qualifier_key_reuse;
	lport->unf_tmf_abnormal_recovery = unf_tmf_timeout_recovery_special;
	return RETURN_OK;
RELEASE_LPORT:
	flush_workqueue(lport->link_event_wq);
	destroy_workqueue(lport->link_event_wq);
	lport->link_event_wq = NULL;

	flush_workqueue(lport->xchg_wq);
	destroy_workqueue(lport->xchg_wq);
	lport->xchg_wq = NULL;

	unf_disc_mgr_destroy(lport);
	unf_free_esgl_pool(lport);
	unf_free_all_xchg_mgr(lport);
	unf_destroy_scsi_id_table(lport);

	return ret;
}

void unf_free_qos_info(struct unf_lport *lport)
{
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_qos_info *qos_info = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);

	spin_lock_irqsave(&lport->qos_mgr_lock, flag);
	list_for_each_safe(node, next_node, &lport->list_qos_head) {
		qos_info = (struct unf_qos_info *)list_entry(node,
		    struct unf_qos_info, entry_qos_info);
		list_del_init(&qos_info->entry_qos_info);
		kfree(qos_info);
	}

	spin_unlock_irqrestore(&lport->qos_mgr_lock, flag);
}

u32 unf_lport_deinit(struct unf_lport *lport)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	unf_free_qos_info(lport);

	unf_unregister_scsi_host(lport);

	/* If the card is unloaded normally, the thread is stopped once. The
	 * problem does not occur if you stop the thread again.
	 */
	unf_destroy_lport_route(lport);

	/* minus the reference count of the card event; the last port deletes
	 * the card thread
	 */
	unf_destroy_card_thread(lport);
	flush_workqueue(lport->link_event_wq);
	destroy_workqueue(lport->link_event_wq);
	lport->link_event_wq = NULL;

	(void)unf_event_center_destroy(lport);
	unf_free_vport_pool(lport);
	unf_xchg_mgr_destroy(lport);

	unf_free_esgl_pool(lport);

	/* reliability review :Disc should release after Xchg. Destroy the disc
	 * manager
	 */
	unf_disc_mgr_destroy(lport);

	unf_release_xchg_mgr_temp(lport);

	unf_release_vport_mgr_temp(lport);

	unf_destroy_scsi_id_table(lport);

	flush_workqueue(lport->xchg_wq);
	destroy_workqueue(lport->xchg_wq);
	lport->xchg_wq = NULL;

	/* Releasing the lw Interface Template */
	unf_lport_release_lw_funop(lport);
	lport->fc_port = NULL;

	return RETURN_OK;
}

static int unf_card_event_process(void *arg)
{
	struct list_head *node = NULL;
	struct unf_cm_event_report *event_node = NULL;
	ulong flags = 0;
	struct unf_chip_manage_info *chip_info = (struct unf_chip_manage_info *)arg;

	set_user_nice(current, UNF_OS_THRD_PRI_LOW);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Slot(%u) chip(0x%x) enter event thread.",
		     chip_info->slot_id, chip_info->chip_id);

	while (!kthread_should_stop()) {
		if (chip_info->thread_exit)
			break;

		spin_lock_irqsave(&chip_info->chip_event_list_lock, flags);
		if (list_empty(&chip_info->list_head)) {
			spin_unlock_irqrestore(&chip_info->chip_event_list_lock, flags);

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((long)msecs_to_jiffies(UNF_S_TO_MS));
		} else {
			node = UNF_OS_LIST_NEXT(&chip_info->list_head);
			list_del_init(node);
			chip_info->list_num--;
			event_node = list_entry(node, struct unf_cm_event_report, list_entry);
			spin_unlock_irqrestore(&chip_info->chip_event_list_lock, flags);
			unf_handle_event(event_node);
		}
	}
	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
		     "Slot(%u) chip(0x%x) exit event thread.",
		     chip_info->slot_id, chip_info->chip_id);

	return RETURN_OK;
}

static void unf_destroy_card_thread(struct unf_lport *lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_chip_manage_info *chip_info = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	struct unf_cm_event_report *event_node = NULL;
	ulong event_lock_flag = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(lport);

	/* If the thread cannot be found, apply for a new thread. */
	chip_info = lport->chip_info;
	if (!chip_info) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) has no event thread.", lport->port_id);
		return;
	}
	event_mgr = &lport->event_mgr;

	spin_lock_irqsave(&chip_info->chip_event_list_lock, flag);
	if (!list_empty(&chip_info->list_head)) {
		list_for_each_safe(list, list_tmp, &chip_info->list_head) {
			event_node = list_entry(list, struct unf_cm_event_report, list_entry);

			/* The LPort under the global event node is null. */
			if (event_node->lport == lport) {
				list_del_init(&event_node->list_entry);
				if (event_node->event_asy_flag == UNF_EVENT_SYN) {
					event_node->result = UNF_RETURN_ERROR;
					complete(&event_node->event_comp);
				}

				spin_lock_irqsave(&event_mgr->port_event_lock, event_lock_flag);
				event_mgr->free_event_count++;
				list_add_tail(&event_node->list_entry, &event_mgr->list_free_event);
				spin_unlock_irqrestore(&event_mgr->port_event_lock,
						       event_lock_flag);
			}
		}
	}
	spin_unlock_irqrestore(&chip_info->chip_event_list_lock, flag);

	/* If the number of events introduced by the event thread is 0,
	 * it indicates that no interface is used. In this case, thread
	 * resources need to be consumed
	 */
	if (atomic_dec_and_test(&chip_info->ref_cnt)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) destroy slot(%u) chip(0x%x) event thread succeed.",
			     lport->port_id, chip_info->slot_id, chip_info->chip_id);
		chip_info->thread_exit = true;
		wake_up_process(chip_info->thread);
		kthread_stop(chip_info->thread);
		chip_info->thread = NULL;

		spin_lock_irqsave(&card_thread_mgr.global_card_list_lock, flag);
		list_del_init(&chip_info->list_chip_thread_entry);
		card_thread_mgr.card_num--;
		spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock, flag);

		vfree(chip_info);
	}

	lport->chip_info = NULL;
}

static u32 unf_creat_card_thread(struct unf_lport *lport)
{
	ulong flag = 0;
	struct unf_chip_manage_info *chip_manage_info = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* If the thread cannot be found, apply for a new thread. */
	chip_manage_info = (struct unf_chip_manage_info *)
	    vmalloc(sizeof(struct unf_chip_manage_info));
	if (!chip_manage_info) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) cannot allocate thread memory.", lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(chip_manage_info, 0, sizeof(struct unf_chip_manage_info));

	memcpy(&chip_manage_info->chip_info, &lport->low_level_func.chip_info,
	       sizeof(struct unf_chip_info));
	chip_manage_info->slot_id = UNF_GET_BOARD_TYPE_AND_SLOT_ID_BY_PORTID(lport->port_id);
	chip_manage_info->chip_id = lport->low_level_func.chip_id;
	chip_manage_info->list_num = 0;
	chip_manage_info->sfp_9545_fault = false;
	chip_manage_info->sfp_power_fault = false;
	atomic_set(&chip_manage_info->ref_cnt, 1);
	atomic_set(&chip_manage_info->card_loop_test_flag, false);
	spin_lock_init(&chip_manage_info->card_loop_back_state_lock);
	INIT_LIST_HEAD(&chip_manage_info->list_head);
	spin_lock_init(&chip_manage_info->chip_event_list_lock);

	chip_manage_info->thread_exit = false;
	chip_manage_info->thread = kthread_create(unf_card_event_process,
						  chip_manage_info, "%x_et", lport->port_id);

	if (IS_ERR(chip_manage_info->thread) || !chip_manage_info->thread) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) creat event thread(0x%p) unsuccessful.",
			     lport->port_id, chip_manage_info->thread);

		vfree(chip_manage_info);

		return UNF_RETURN_ERROR;
	}

	lport->chip_info = chip_manage_info;
	wake_up_process(chip_manage_info->thread);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) creat slot(%u) chip(0x%x) event thread succeed.",
		     lport->port_id, chip_manage_info->slot_id,
		     chip_manage_info->chip_id);

	spin_lock_irqsave(&card_thread_mgr.global_card_list_lock, flag);
	list_add_tail(&chip_manage_info->list_chip_thread_entry, &card_thread_mgr.card_list_head);
	card_thread_mgr.card_num++;
	spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock, flag);

	return RETURN_OK;
}

static u32 unf_find_card_thread(struct unf_lport *lport)
{
	ulong flag = 0;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct unf_chip_manage_info *chip_info = NULL;
	u32 ret = UNF_RETURN_ERROR;

	spin_lock_irqsave(&card_thread_mgr.global_card_list_lock, flag);
	list_for_each_safe(node, next_node, &card_thread_mgr.card_list_head) {
		chip_info = list_entry(node, struct unf_chip_manage_info, list_chip_thread_entry);

		if (chip_info->chip_id == lport->low_level_func.chip_id &&
		    chip_info->slot_id ==
		     UNF_GET_BOARD_TYPE_AND_SLOT_ID_BY_PORTID(lport->port_id)) {
			atomic_inc(&chip_info->ref_cnt);
			lport->chip_info = chip_info;

			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
				     "Port(0x%x) find card(%u) chip(0x%x) event thread succeed.",
				     lport->port_id, chip_info->slot_id, chip_info->chip_id);

			spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock, flag);

			return RETURN_OK;
		}
	}
	spin_unlock_irqrestore(&card_thread_mgr.global_card_list_lock, flag);

	ret = unf_creat_card_thread(lport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) creat event thread unsuccessful. Destroy LPort.",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	} else {
		return RETURN_OK;
	}
}

void *unf_lport_create_and_init(void *private_data, struct unf_low_level_functioon_op *low_level_op)
{
	struct unf_lport *unf_lport = NULL;
	u32 ret = UNF_RETURN_ERROR;

	if (!private_data) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Private Data is NULL");

		return NULL;
	}
	if (!low_level_op) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LowLevel port(0x%p) function is NULL", private_data);

		return NULL;
	}

	/* 1. vmalloc & Memset L_Port */
	unf_lport = vmalloc(sizeof(struct unf_lport));
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Alloc LPort memory failed.");

		return NULL;
	}
	memset(unf_lport, 0, sizeof(struct unf_lport));

	/* 2. L_Port Init */
	if (unf_lport_init(unf_lport, private_data, low_level_op) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort initialize unsuccessful.");

		vfree(unf_lport);

		return NULL;
	}

	/* 4. Get or Create Chip Thread
	 * Chip_ID & Slot_ID
	 */
	ret = unf_find_card_thread(unf_lport);
	if (ret != RETURN_OK) {
		(void)unf_lport_deinit(unf_lport);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%x) Find Chip thread unsuccessful. Destroy LPort.",
			     unf_lport->port_id);

		vfree(unf_lport);
		return NULL;
	}

	/* 5. Registers with in the port management global linked list */
	unf_port_register(unf_lport);
	/* update WWN */
	if (unf_build_lport_wwn(unf_lport) != RETURN_OK) {
		unf_port_unregister(unf_lport);
		(void)unf_lport_deinit(unf_lport);
		vfree(unf_lport);
		return NULL;
	}

	// unf_init_link_lose_tmo(unf_lport);//TO DO

	/* initialize Scsi Host */
	if (unf_register_scsi_host(unf_lport) != RETURN_OK) {
		unf_port_unregister(unf_lport);
		(void)unf_lport_deinit(unf_lport);
		vfree(unf_lport);
		return NULL;
	}
	/* 7. Here, start work now */
	if (global_lport_mgr.start_work) {
		if (unf_port_start_work(unf_lport) != RETURN_OK) {
			unf_port_unregister(unf_lport);

			(void)unf_lport_deinit(unf_lport);

			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[warn]Port(0x%x) start work failed", unf_lport->port_id);
			vfree(unf_lport);
			return NULL;
		}
	}

	return unf_lport;
}

static int unf_lport_destroy(void *lport, void *arg_out)
{
	struct unf_lport *unf_lport = NULL;
	ulong flags = 0;

	if (!lport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR, "LPort is NULL.");

		return UNF_RETURN_ERROR;
	}

	unf_lport = (struct unf_lport *)lport;

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
		     "Destroy LPort(0x%p), ID(0x%x).", unf_lport, unf_lport->port_id);
	/* NPIV Ensure that all Vport are deleted */
	unf_destroy_all_vports(unf_lport);
	unf_lport->destroy_step = UNF_LPORT_DESTROY_STEP_1_REPORT_PORT_OUT;

	(void)unf_lport_deinit(lport);

	/* The port is removed from the destroy linked list. The next step is to
	 * release the memory
	 */
	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	list_del(&unf_lport->entry_lport);

	/* If the port has dirty memory, the port is mounted to the linked list
	 * of dirty ports
	 */
	if (unf_lport->dirty_flag)
		list_add_tail(&unf_lport->entry_lport, &global_lport_mgr.dirty_list_head);
	spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

	if (unf_lport->lport_free_completion) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Complete LPort(0x%p), port ID(0x%x)'s Free Completion.",
			     unf_lport, unf_lport->port_id);
		complete(unf_lport->lport_free_completion);
	} else {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "LPort(0x%p), port ID(0x%x)'s Free Completion is NULL.",
			     unf_lport, unf_lport->port_id);
		dump_stack();
	}

	return RETURN_OK;
}

static int unf_port_switch(struct unf_lport *lport, bool switch_flag)
{
	struct unf_lport *unf_lport = lport;
	int ret = UNF_RETURN_ERROR;
	bool flag = false;

	FC_CHECK_RETURN_VALUE(unf_lport, UNF_RETURN_ERROR);

	if (!unf_lport->low_level_func.port_mgr_op.ll_port_config_set) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_WARN,
			     "[warn]Port(0x%x)'s config(switch) function is NULL",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	flag = switch_flag ? true : false;

	ret = (int)unf_lport->low_level_func.port_mgr_op.ll_port_config_set(unf_lport->fc_port,
	    UNF_PORT_CFG_SET_PORT_SWITCH, (void *)&flag);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_WARN, "[warn]Port(0x%x) switch %s failed",
			     unf_lport->port_id, switch_flag ? "On" : "Off");

		return UNF_RETURN_ERROR;
	}

	unf_lport->switch_state = (bool)flag;

	return RETURN_OK;
}

static int unf_send_event(u32 port_id, u32 syn_flag, void *argc_in, void *argc_out,
			  int (*func)(void *argc_in, void *argc_out))
{
	struct unf_lport *lport = NULL;
	struct unf_cm_event_report *event = NULL;
	int ret = 0;

	lport = unf_find_lport_by_port_id(port_id);
	if (!lport) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_INFO, "Cannot find LPort(0x%x).", port_id);

		return UNF_RETURN_ERROR;
	}

	if (unf_lport_ref_inc(lport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "LPort(0x%x) is removing, no need process.",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}
	if (unlikely(!lport->event_mgr.unf_get_free_event_func ||
		     !lport->event_mgr.unf_post_event_func ||
		     !lport->event_mgr.unf_release_event)) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_MAJOR, "Event function is NULL.");

		unf_lport_ref_dec_to_destroy(lport);

		return UNF_RETURN_ERROR;
	}

	if (lport->port_removing) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "LPort(0x%x) is removing, no need process.",
			     lport->port_id);

		unf_lport_ref_dec_to_destroy(lport);

		return UNF_RETURN_ERROR;
	}

	event = lport->event_mgr.unf_get_free_event_func((void *)lport);
	if (!event) {
		unf_lport_ref_dec_to_destroy(lport);

		return UNF_RETURN_ERROR;
	}

	init_completion(&event->event_comp);
	event->lport = lport;
	event->event_asy_flag = syn_flag;
	event->unf_event_task = func;
	event->para_in = argc_in;
	event->para_out = argc_out;
	lport->event_mgr.unf_post_event_func(lport, event);

	if (event->event_asy_flag) {
		/* You must wait for the other party to return. Otherwise, the
		 * linked list may be in disorder.
		 */
		wait_for_completion(&event->event_comp);
		ret = (int)event->result;
		lport->event_mgr.unf_release_event(lport, event);
	} else {
		ret = RETURN_OK;
	}

	unf_lport_ref_dec_to_destroy(lport);
	return ret;
}

static int unf_reset_port(void *arg_in, void *arg_out)
{
	struct unf_reset_port_argin *input = (struct unf_reset_port_argin *)arg_in;
	struct unf_lport *lport = NULL;
	u32 ret = UNF_RETURN_ERROR;
	enum unf_port_config_state port_state = UNF_PORT_CONFIG_STATE_RESET;

	FC_CHECK_RETURN_VALUE(input, UNF_RETURN_ERROR);

	lport = unf_find_lport_by_port_id(input->port_id);
	if (!lport) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_MAJOR, "Not find LPort(0x%x).",
			     input->port_id);

		return UNF_RETURN_ERROR;
	}

	/* reset port */
	if (!lport->low_level_func.port_mgr_op.ll_port_config_set) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_MAJOR,
			     "Port(0x%x)'s corresponding function is NULL.", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	lport->act_topo = UNF_ACT_TOP_UNKNOWN;
	lport->speed = UNF_PORT_SPEED_UNKNOWN;
	lport->fabric_node_name = 0;

	ret = lport->low_level_func.port_mgr_op.ll_port_config_set(lport->fc_port,
								   UNF_PORT_CFG_SET_PORT_STATE,
								   (void *)&port_state);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_MAJOR, "Reset port(0x%x) unsuccessful.",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

int unf_cm_reset_port(u32 port_id)
{
	int ret = UNF_RETURN_ERROR;

	ret = unf_send_event(port_id, UNF_EVENT_SYN, (void *)&port_id,
			     (void *)NULL, unf_reset_port);
	return ret;
}

int unf_lport_reset_port(struct unf_lport *lport, u32 flag)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	return unf_send_event(lport->port_id, flag, (void *)&lport->port_id,
			      (void *)NULL, unf_reset_port);
}

static inline u32 unf_get_loop_alpa(struct unf_lport *lport, void *loop_alpa)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport->low_level_func.port_mgr_op.ll_port_config_get,
			      UNF_RETURN_ERROR);

	ret = lport->low_level_func.port_mgr_op.ll_port_config_get(lport->fc_port,
	    UNF_PORT_CFG_GET_LOOP_ALPA, loop_alpa);

	return ret;
}

static u32 unf_lport_enter_private_loop_login(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = lport;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_READY); /* LPort: LINK_UP --> READY */
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	unf_lport_update_topo(unf_lport, UNF_ACT_TOP_PRIVATE_LOOP);

	/* NOP: check L_Port state */
	if (atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_MAJOR, "[info]Port(0x%x) is NOP, do nothing",
			     unf_lport->port_id);

		return RETURN_OK;
	}

	/* INI: check L_Port mode */
	if (UNF_PORT_MODE_INI != (unf_lport->options & UNF_PORT_MODE_INI)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) has no INI feature(0x%x), do nothing",
			     unf_lport->port_id, unf_lport->options);

		return RETURN_OK;
	}

	if (unf_lport->disc.disc_temp.unf_disc_start) {
		ret = unf_lport->disc.disc_temp.unf_disc_start(unf_lport);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) with nportid(0x%x) start discovery failed",
				     unf_lport->port_id, unf_lport->nport_id);
		}
	}

	return ret;
}

u32 unf_lport_login(struct unf_lport *lport, enum unf_act_topo act_topo)
{
	u32 loop_alpa = 0;
	u32 ret = RETURN_OK;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* 1. Update (set) L_Port topo which get from low level */
	unf_lport_update_topo(lport, act_topo);

	spin_lock_irqsave(&lport->lport_state_lock, flag);

	/* 2. Link state check */
	if (lport->link_up != UNF_PORT_LINK_UP) {
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) with link_state(0x%x) port_state(0x%x) when login",
			     lport->port_id, lport->link_up, lport->states);

		return UNF_RETURN_ERROR;
	}

	/* 3. Update L_Port state */
	unf_lport_state_ma(lport, UNF_EVENT_LPORT_LINK_UP); /* LPort: INITIAL --> LINK UP */
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]LOGIN: Port(0x%x) start to login with topology(0x%x)",
		     lport->port_id, lport->act_topo);

	/* 4. Start logoin */
	if (act_topo == UNF_TOP_P2P_MASK ||
	    act_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    act_topo == UNF_ACT_TOP_P2P_DIRECT) {
		/* P2P or Fabric mode */
		ret = unf_lport_enter_flogi(lport);
	} else if (act_topo == UNF_ACT_TOP_PUBLIC_LOOP) {
		/* Public loop */
		(void)unf_get_loop_alpa(lport, &loop_alpa);

		/* Before FLOGI ALPA just low 8 bit, after FLOGI ACC, switch
		 * will assign complete addresses
		 */
		spin_lock_irqsave(&lport->lport_state_lock, flag);
		lport->nport_id = loop_alpa;
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		ret = unf_lport_enter_flogi(lport);
	} else if (act_topo == UNF_ACT_TOP_PRIVATE_LOOP) {
		/* Private loop */
		(void)unf_get_loop_alpa(lport, &loop_alpa);

		spin_lock_irqsave(&lport->lport_state_lock, flag);
		lport->nport_id = loop_alpa;
		spin_unlock_irqrestore(&lport->lport_state_lock, flag);

		ret = unf_lport_enter_private_loop_login(lport);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]LOGIN: Port(0x%x) login with unknown topology(0x%x)",
			     lport->port_id, lport->act_topo);
	}

	return ret;
}

static u32 unf_port_linkup(struct unf_lport *lport, void *input)
{
	struct unf_lport *unf_lport = lport;
	u32 ret = RETURN_OK;
	enum unf_act_topo act_topo = UNF_ACT_TOP_UNKNOWN;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	/* If NOP state, stop */
	if (atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Port(0x%x) is NOP and do nothing", unf_lport->port_id);

		return RETURN_OK;
	}

	/* Update port state */
	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	unf_lport->link_up = UNF_PORT_LINK_UP;
	unf_lport->speed = *((u32 *)input);
	unf_set_lport_state(lport, UNF_LPORT_ST_INITIAL); /* INITIAL state */
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	/* set hot pool wait state: so far, do not care */
	unf_set_hot_pool_wait_state(unf_lport, true);

	unf_lport->enhanced_features |= UNF_LPORT_ENHANCED_FEATURE_READ_SFP_ONCE;

	/* Get port active topopolgy (from low level) */
	if (!unf_lport->low_level_func.port_mgr_op.ll_port_config_get) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Port(0x%x) get topo function is NULL", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}
	ret = unf_lport->low_level_func.port_mgr_op.ll_port_config_get(unf_lport->fc_port,
	    UNF_PORT_CFG_GET_TOPO_ACT, (void *)&act_topo);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Port(0x%x) get topo from low level failed",
			     unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	/* Start Login process */
	ret = unf_lport_login(unf_lport, act_topo);

	return ret;
}

static u32 unf_port_linkdown(struct unf_lport *lport, void *input)
{
	ulong flag = 0;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	unf_lport = lport;

	/* To prevent repeated reporting linkdown */
	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	unf_lport->speed = UNF_PORT_SPEED_UNKNOWN;
	unf_lport->act_topo = UNF_ACT_TOP_UNKNOWN;
	if (unf_lport->link_up == UNF_PORT_LINK_DOWN) {
		spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

		return RETURN_OK;
	}
	unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_LINK_DOWN);
	unf_reset_lport_params(unf_lport);
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	unf_set_hot_pool_wait_state(unf_lport, false);

	/*
	 * clear I/O:
	 * 1. INI do ABORT only,
	 * 2. TGT need do source clear with Wait_IO
	 * *
	 * for INI: busy/delay/delay_transfer/wait
	 * Clean L_Port/V_Port Link Down I/O: only set ABORT tag
	 */
	unf_flush_disc_event(&unf_lport->disc, NULL);

	unf_clean_linkdown_io(unf_lport, false);

	/* for L_Port's R_Ports */
	unf_clean_linkdown_rport(unf_lport);
	/* for L_Port's all Vports */
	unf_linkdown_all_vports(lport);
	return RETURN_OK;
}

static u32 unf_port_abnormal_reset(struct unf_lport *lport, void *input)
{
	u32 ret = UNF_RETURN_ERROR;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	unf_lport = lport;

	ret = (u32)unf_lport_reset_port(unf_lport, UNF_EVENT_ASYN);

	return ret;
}

static u32 unf_port_reset_start(struct unf_lport *lport, void *input)
{
	u32 ret = RETURN_OK;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_set_lport_state(lport, UNF_LPORT_ST_RESET);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "Port(0x%x) begin to reset.", lport->port_id);

	return ret;
}

static u32 unf_port_reset_end(struct unf_lport *lport, void *input)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "Port(0x%x) reset end.", lport->port_id);

	/* Task management command returns success and avoid repair measures
	 * case offline device
	 */
	unf_wake_up_scsi_task_cmnd(lport);

	spin_lock_irqsave(&lport->lport_state_lock, flag);
	unf_set_lport_state(lport, UNF_LPORT_ST_INITIAL);
	spin_unlock_irqrestore(&lport->lport_state_lock, flag);

	return RETURN_OK;
}

static u32 unf_port_nop(struct unf_lport *lport, void *input)
{
	struct unf_lport *unf_lport = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	unf_lport = lport;

	atomic_set(&unf_lport->lport_no_operate_flag, UNF_LPORT_NOP);

	spin_lock_irqsave(&unf_lport->lport_state_lock, flag);
	unf_lport_state_ma(unf_lport, UNF_EVENT_LPORT_LINK_DOWN);
	unf_reset_lport_params(unf_lport);
	spin_unlock_irqrestore(&unf_lport->lport_state_lock, flag);

	/* Set Tag prevent pending I/O to wait_list when close sfp failed */
	unf_set_hot_pool_wait_state(unf_lport, false);

	unf_flush_disc_event(&unf_lport->disc, NULL);

	/* L_Port/V_Port's I/O(s): Clean Link Down I/O: Set Abort Tag */
	unf_clean_linkdown_io(unf_lport, false);

	/* L_Port/V_Port's R_Port(s): report link down event to scsi & clear
	 * resource
	 */
	unf_clean_linkdown_rport(unf_lport);
	unf_linkdown_all_vports(unf_lport);
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) report NOP event done", unf_lport->nport_id);

	return RETURN_OK;
}

static u32 unf_port_begin_remove(struct unf_lport *lport, void *input)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	/* Cancel route timer delay work */
	unf_destroy_lport_route(lport);

	return RETURN_OK;
}

static u32 unf_get_pcie_link_state(struct unf_lport *lport)
{
	struct unf_lport *unf_lport = lport;
	bool linkstate = true;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(unf_lport->low_level_func.port_mgr_op.ll_port_config_get,
			      UNF_RETURN_ERROR);

	ret = unf_lport->low_level_func.port_mgr_op.ll_port_config_get(unf_lport->fc_port,
	    UNF_PORT_CFG_GET_PCIE_LINK_STATE, (void *)&linkstate);
	if (ret != RETURN_OK || linkstate != true) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_KEVENT, "[err]Can't Get Pcie Link State");

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

void unf_root_lport_ref_dec(struct unf_lport *lport)
{
	ulong flags = 0;
	ulong lport_flags = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VOID(lport);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%p) port_id(0x%x) reference count is %d",
		     lport, lport->port_id, atomic_read(&lport->port_ref_cnt));

	spin_lock_irqsave(&global_lport_mgr.global_lport_list_lock, flags);
	spin_lock_irqsave(&lport->lport_state_lock, lport_flags);
	if (atomic_dec_and_test(&lport->port_ref_cnt)) {
		spin_unlock_irqrestore(&lport->lport_state_lock, lport_flags);

		list_del(&lport->entry_lport);
		global_lport_mgr.lport_sum--;

		/* Put L_Port to destroy list for debuging */
		list_add_tail(&lport->entry_lport, &global_lport_mgr.destroy_list_head);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);

		ret = unf_schedule_global_event((void *)lport, UNF_GLOBAL_EVENT_ASYN,
						unf_lport_destroy);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_EVENT, UNF_CRITICAL,
				     "[warn]Schedule global event faile. remain nodes(0x%x)",
				     global_event_queue.list_number);
		}
	} else {
		spin_unlock_irqrestore(&lport->lport_state_lock, lport_flags);
		spin_unlock_irqrestore(&global_lport_mgr.global_lport_list_lock, flags);
	}
}

void unf_lport_ref_dec_to_destroy(struct unf_lport *lport)
{
	if (lport->root_lport != lport)
		unf_vport_ref_dec(lport);
	else
		unf_root_lport_ref_dec(lport);
}

void unf_lport_route_work(struct work_struct *work)
{
#define UNF_MAX_PCIE_LINK_DOWN_TIMES 3
	struct unf_lport *unf_lport = NULL;
	int ret = 0;

	FC_CHECK_RETURN_VOID(work);

	unf_lport = container_of(work, struct unf_lport, route_timer_work.work);
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_KEVENT, "[err]LPort is NULL");

		return;
	}

	if (unlikely(unf_lport->port_removing)) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			     "[warn]LPort(0x%x) route work is closing.", unf_lport->port_id);

		unf_lport_ref_dec_to_destroy(unf_lport);

		return;
	}

	if (unlikely(unf_get_pcie_link_state(unf_lport)))
		unf_lport->pcie_link_down_cnt++;
	else
		unf_lport->pcie_link_down_cnt = 0;

	if (unf_lport->pcie_link_down_cnt >= UNF_MAX_PCIE_LINK_DOWN_TIMES) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			     "[warn]LPort(0x%x) detected pcie linkdown, closing route work",
			     unf_lport->port_id);
		unf_lport->pcie_link_down = true;
		unf_free_lport_all_xchg(unf_lport);
		unf_lport_ref_dec_to_destroy(unf_lport);
		return;
	}

	if (unlikely(UNF_LPORT_CHIP_ERROR(unf_lport))) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			     "[warn]LPort(0x%x) reported chip error, closing route work. ",
			     unf_lport->port_id);

		unf_lport_ref_dec_to_destroy(unf_lport);

		return;
	}

	if (unf_lport->enhanced_features &
	    UNF_LPORT_ENHANCED_FEATURE_CLOSE_FW_ROUTE) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			     "[warn]User close LPort(0x%x) route work. ", unf_lport->port_id);

		unf_lport_ref_dec_to_destroy(unf_lport);

		return;
	}

	/* Scheduling 1 second */
	ret = queue_delayed_work(unf_wq, &unf_lport->route_timer_work,
				 (ulong)msecs_to_jiffies(UNF_LPORT_POLL_TIMER));
	if (ret == 0) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_KEVENT,
			     "[warn]LPort(0x%x) schedule work unsuccessful.", unf_lport->port_id);

		unf_lport_ref_dec_to_destroy(unf_lport);
	}
}

static int unf_cm_get_mac_adr(void *argc_in, void *argc_out)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_get_chip_info_argout *chip_info = NULL;

	FC_CHECK_RETURN_VALUE(argc_in, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(argc_out, UNF_RETURN_ERROR);

	unf_lport = (struct unf_lport *)argc_in;
	chip_info = (struct unf_get_chip_info_argout *)argc_out;

	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT,
			     UNF_MAJOR, " LPort is null.");

		return UNF_RETURN_ERROR;
	}

	if (!unf_lport->low_level_func.port_mgr_op.ll_port_config_get) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x)'s corresponding function is NULL.", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	if (unf_lport->low_level_func.port_mgr_op.ll_port_config_get(unf_lport->fc_port,
								     UNF_PORT_CFG_GET_MAC_ADDR,
								     chip_info) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) get .", unf_lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

int unf_build_sys_wwn(u32 port_id, u64 *sys_port_name, u64 *sys_node_name)
{
	struct unf_get_chip_info_argout wwn = {0};
	u32 ret = UNF_RETURN_ERROR;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE((sys_port_name), UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE((sys_node_name), UNF_RETURN_ERROR);

	unf_lport = unf_find_lport_by_port_id(port_id);
	if (!unf_lport)
		return UNF_RETURN_ERROR;

	ret = (u32)unf_send_event(unf_lport->port_id, UNF_EVENT_SYN,
				  (void *)unf_lport, (void *)&wwn, unf_cm_get_mac_adr);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "send event(port get mac adr) fail.");
		return UNF_RETURN_ERROR;
	}

	/* save card mode: UNF_FC_SERVER_BOARD_32_G(6):32G;
	 * UNF_FC_SERVER_BOARD_16_G(7):16G MODE
	 */
	unf_lport->card_type = wwn.board_type;

	/* update port max speed */
	if (wwn.board_type == UNF_FC_SERVER_BOARD_32_G)
		unf_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_32_G;
	else if (wwn.board_type == UNF_FC_SERVER_BOARD_16_G)
		unf_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_16_G;
	else if (wwn.board_type == UNF_FC_SERVER_BOARD_8_G)
		unf_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_8_G;
	else
		unf_lport->low_level_func.fc_ser_max_speed = UNF_PORT_SPEED_32_G;

	*sys_port_name = wwn.wwpn;
	*sys_node_name = wwn.wwnn;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) Port Name(0x%llx), Node Name(0x%llx.)",
		     port_id, *sys_port_name, *sys_node_name);

	return RETURN_OK;
}

static u32 unf_update_port_wwn(struct unf_lport *lport,
			       struct unf_port_wwn *port_wwn)
{
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(port_wwn, UNF_RETURN_ERROR);

	/* Now notice lowlevel to update */
	if (!lport->low_level_func.port_mgr_op.ll_port_config_set) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x)'s corresponding function is NULL.",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	if (lport->low_level_func.port_mgr_op.ll_port_config_set(lport->fc_port,
								 UNF_PORT_CFG_UPDATE_WWN,
								 port_wwn) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) update WWN unsuccessful.",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "Port(0x%x) update WWN: previous(0x%llx, 0x%llx), now(0x%llx, 0x%llx).",
		     lport->port_id, lport->port_name, lport->node_name,
		     port_wwn->sys_port_wwn, port_wwn->sys_node_name);

	lport->port_name = port_wwn->sys_port_wwn;
	lport->node_name = port_wwn->sys_node_name;

	return RETURN_OK;
}

static u32 unf_build_lport_wwn(struct unf_lport *lport)
{
	struct unf_port_wwn port_wwn = {0};

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	if (unf_build_sys_wwn(lport->port_id, &port_wwn.sys_port_wwn,
			      &port_wwn.sys_node_name) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "Port(0x%x) build WWN unsuccessful.", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) build WWN succeed", lport->port_id);

	if (unf_update_port_wwn(lport, &port_wwn) != RETURN_OK)
		return UNF_RETURN_ERROR;

	return RETURN_OK;
}

u32 unf_port_release_rport_index(struct unf_lport *lport, void *input)
{
	u32 rport_index = INVALID_VALUE32;
	ulong flag = 0;
	struct unf_rport_pool *rport_pool = NULL;
	struct unf_lport *unf_lport = NULL;
	spinlock_t *rport_pool_lock = NULL;

	unf_lport = (struct unf_lport *)lport->root_lport;
	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	if (input) {
		rport_index = *(u32 *)input;
		if (rport_index < lport->low_level_func.support_max_rport) {
			rport_pool = &unf_lport->rport_pool;
			rport_pool_lock = &rport_pool->rport_free_pool_lock;
			spin_lock_irqsave(rport_pool_lock, flag);
			if (test_bit((int)rport_index, rport_pool->rpi_bitmap)) {
				clear_bit((int)rport_index, rport_pool->rpi_bitmap);
			} else {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x) try to release a free rport index(0x%x)",
					     lport->port_id, rport_index);
			}
			spin_unlock_irqrestore(rport_pool_lock, flag);
		} else {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) try to release a not exist rport index(0x%x)",
				     lport->port_id, rport_index);
		}
	}

	return RETURN_OK;
}

void *unf_lookup_lport_by_nportid(void *lport, u32 nport_id)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_vport_pool *vport_pool = NULL;
	struct unf_lport *unf_vport = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);

	unf_lport = (struct unf_lport *)lport;
	unf_lport = unf_lport->root_lport;
	vport_pool = unf_lport->vport_pool;

	if (unf_lport->nport_id == nport_id)
		return unf_lport;

	if (unlikely(!vport_pool)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) vport pool is NULL", unf_lport->port_id);

		return NULL;
	}

	spin_lock_irqsave(&vport_pool->vport_pool_lock, flag);
	list_for_each_safe(node, next_node, &unf_lport->list_vports_head) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->nport_id == nport_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
			return unf_vport;
		}
	}

	list_for_each_safe(node, next_node, &unf_lport->list_intergrad_vports) {
		unf_vport = list_entry(node, struct unf_lport, entry_vport);
		if (unf_vport->nport_id == nport_id) {
			spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);
			return unf_vport;
		}
	}
	spin_unlock_irqrestore(&vport_pool->vport_pool_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "Port(0x%x) has no vport Nport ID(0x%x)",
		     unf_lport->port_id, nport_id);

	return NULL;
}

int unf_get_link_lose_tmo(struct unf_lport *lport)
{
	u32 tmo_value = 0;

	if (!lport)
		return UNF_LOSE_TMO;

	tmo_value = atomic_read(&lport->link_lose_tmo);

	if (!tmo_value)
		tmo_value = UNF_LOSE_TMO;

	return (int)tmo_value;
}

u32 unf_register_scsi_host(struct unf_lport *lport)
{
	struct unf_host_param host_param = {0};

	struct Scsi_Host **scsi_host = NULL;
	struct unf_lport_cfg_item *lport_cfg_items = NULL;

	FC_CHECK_RETURN_VALUE((lport), UNF_RETURN_ERROR);

	/* Point to -->> L_port->Scsi_host */
	scsi_host = &lport->host_info.host;

	lport_cfg_items = &lport->low_level_func.lport_cfg_items;
	host_param.can_queue = (int)lport_cfg_items->max_queue_depth;

	/* Performance optimization */
	host_param.cmnd_per_lun = UNF_MAX_CMND_PER_LUN;

	host_param.sg_table_size = UNF_MAX_DMA_SEGS;
	host_param.max_id = UNF_MAX_TARGET_NUMBER;
	host_param.max_lun = UNF_DEFAULT_MAX_LUN;
	host_param.max_channel = UNF_MAX_BUS_CHANNEL;
	host_param.max_cmnd_len = UNF_MAX_SCSI_CMND_LEN; /* CDB-16 */
	host_param.dma_boundary = UNF_DMA_BOUNDARY;
	host_param.max_sectors = UNF_MAX_SECTORS;
	host_param.port_id = lport->port_id;
	host_param.lport = lport;
	host_param.pdev = &lport->low_level_func.dev->dev;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Port(0x%x) allocate scsi host: can queue(%u), command performance LUN(%u), max lun(%u)",
		     lport->port_id, host_param.can_queue, host_param.cmnd_per_lun,
		     host_param.max_lun);

	if (unf_alloc_scsi_host(scsi_host, &host_param) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) allocate scsi host failed", lport->port_id);

		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) allocate scsi host(0x%x) succeed",
		     lport->port_id, UNF_GET_SCSI_HOST_ID(*scsi_host));

	return RETURN_OK;
}

void unf_unregister_scsi_host(struct unf_lport *lport)
{
	struct Scsi_Host *scsi_host = NULL;
	u32 host_no = 0;

	FC_CHECK_RETURN_VOID(lport);

	scsi_host = lport->host_info.host;

	if (scsi_host) {
		host_no = UNF_GET_SCSI_HOST_ID(scsi_host);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[event]Port(0x%x) starting unregister scsi host(0x%x)",
			     lport->port_id, host_no);
		unf_free_scsi_host(scsi_host);
		/* can`t set scsi_host for NULL, since it does`t alloc by itself */
	} else {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
			     "[warn]Port(0x%x) unregister scsi host, invalid scsi_host ",
			     lport->port_id);
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[event]Port(0x%x) unregister scsi host(0x%x) succeed",
		     lport->port_id, host_no);

	lport->destroy_step = UNF_LPORT_DESTROY_STEP_12_UNREG_SCSI_HOST;
}
