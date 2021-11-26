// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_queue.h"
#include "unf_log.h"
#include "unf_lport.h"
#include "spfc_module.h"
#include "spfc_utils.h"
#include "spfc_service.h"
#include "spfc_chipitf.h"
#include "spfc_parent_context.h"
#include "sphw_hw.h"
#include "sphw_crm.h"

#define SPFC_UCODE_CMD_MODIFY_QUEUE_CONTEXT 0

#define SPFC_DONE_MASK (0x00000001)
#define SPFC_OWNER_MASK (0x80000000)

#define SPFC_SQ_LINK_PRE (1 << 2)

#define SPFC_SQ_HEADER_ADDR_ALIGN_SIZE (64)
#define SPFC_SQ_HEADER_ADDR_ALIGN_SIZE_MASK (SPFC_SQ_HEADER_ADDR_ALIGN_SIZE - 1)

#define SPFC_ADDR_64_ALIGN(addr)                            \
	(((addr) + (SPFC_SQ_HEADER_ADDR_ALIGN_SIZE_MASK)) & \
	 ~(SPFC_SQ_HEADER_ADDR_ALIGN_SIZE_MASK))

u32 spfc_get_parity_value(u64 *src_data, u32 row, u32 col)
{
	u32 i = 0;
	u32 j = 0;
	u32 offset = 0;
	u32 group = 0;
	u32 bit_offset = 0;
	u32 bit_val = 0;
	u32 tmp_val = 0;
	u32 dest_data = 0;

	for (i = 0; i < row; i++) {
		for (j = 0; j < col; j++) {
			offset = (row * j + i);
			group = offset / (sizeof(src_data[ARRAY_INDEX_0]) * UNF_BITS_PER_BYTE);
			bit_offset = offset % (sizeof(src_data[ARRAY_INDEX_0]) * UNF_BITS_PER_BYTE);
			tmp_val = (src_data[group] >> bit_offset) & SPFC_PARITY_MASK;

			if (j == 0) {
				bit_val = tmp_val;
				continue;
			}

			bit_val ^= tmp_val;
		}

		bit_val = (~bit_val) & SPFC_PARITY_MASK;

		dest_data |= (bit_val << i);
	}

	return dest_data;
}

static void spfc_update_producer_info(u16 q_depth, u16 *pus_pi, u16 *pus_owner)
{
	u16 current_pi = 0;
	u16 next_pi = 0;
	u16 owner = 0;

	current_pi = *pus_pi;
	next_pi = current_pi + 1;

	if (next_pi < q_depth) {
		*pus_pi = next_pi;
	} else {
		/* PI reversal */
		*pus_pi = 0;

		/* obit reversal */
		owner = *pus_owner;
		*pus_owner = !owner;
	}
}

static void spfc_update_consumer_info(u16 q_depth, u16 *pus_ci, u16 *pus_owner)
{
	u16 current_ci = 0;
	u16 next_ci = 0;
	u16 owner = 0;

	current_ci = *pus_ci;
	next_ci = current_ci + 1;

	if (next_ci < q_depth) {
		*pus_ci = next_ci;
	} else {
		/* CI reversal */
		*pus_ci = 0;

		/* obit reversal */
		owner = *pus_owner;
		*pus_owner = !owner;
	}
}

static inline void spfc_update_cq_header(struct ci_record *ci_record, u16 ci,
					 u16 owner)
{
	u32 size = 0;
	struct ci_record record = {0};

	size = sizeof(struct ci_record);
	memcpy(&record, ci_record, size);
	spfc_big_to_cpu64(&record, size);
	record.cmsn = ci + (u16)(owner << SPFC_CQ_HEADER_OWNER_SHIFT);
	record.dump_cmsn = record.cmsn;
	spfc_cpu_to_big64(&record, size);

	wmb();
	memcpy(ci_record, &record, size);
}

static void spfc_update_srq_header(struct db_record *pmsn_record, u16 pmsn)
{
	u32 size = 0;
	struct db_record record = {0};

	size = sizeof(struct db_record);
	memcpy(&record, pmsn_record, size);
	spfc_big_to_cpu64(&record, size);
	record.pmsn = pmsn;
	record.dump_pmsn = record.pmsn;
	spfc_cpu_to_big64(&record, sizeof(struct db_record));

	wmb();
	memcpy(pmsn_record, &record, size);
}

static void spfc_set_srq_wqe_owner_be(struct spfc_wqe_ctrl *sqe_ctrl_in_wp,
				      u32 owner)
{
	struct spfc_wqe_ctrl_ch wqe_ctrl_ch;

	mb();

	wqe_ctrl_ch.ctrl_ch_val = be32_to_cpu(sqe_ctrl_in_wp->ch.ctrl_ch_val);
	wqe_ctrl_ch.wd0.owner = owner;
	sqe_ctrl_in_wp->ch.ctrl_ch_val = cpu_to_be32(wqe_ctrl_ch.ctrl_ch_val);

	mb();
}

static inline void spfc_set_sq_wqe_owner_be(void *sqe)
{
	u32 *sqe_dw = (u32 *)sqe;
	u32 *e_sqe_dw = (u32 *)((u8 *)sqe + SPFC_EXTEND_WQE_OFFSET);

	/* Ensure that the write of WQE is complete */
	mb();
	e_sqe_dw[SPFC_SQE_SECOND_OBIT_DW_POS] |= SPFC_SQE_OBIT_SET_MASK_BE;
	e_sqe_dw[SPFC_SQE_FIRST_OBIT_DW_POS] |= SPFC_SQE_OBIT_SET_MASK_BE;
	sqe_dw[SPFC_SQE_SECOND_OBIT_DW_POS] |= SPFC_SQE_OBIT_SET_MASK_BE;
	sqe_dw[SPFC_SQE_FIRST_OBIT_DW_POS] |= SPFC_SQE_OBIT_SET_MASK_BE;
	mb();
}

void spfc_clear_sq_wqe_owner_be(struct spfc_sqe *sqe)
{
	u32 *sqe_dw = (u32 *)sqe;
	u32 *e_sqe_dw = (u32 *)((u8 *)sqe + SPFC_EXTEND_WQE_OFFSET);

	mb();
	sqe_dw[SPFC_SQE_SECOND_OBIT_DW_POS] &= SPFC_SQE_OBIT_CLEAR_MASK_BE;
	mb();
	sqe_dw[SPFC_SQE_FIRST_OBIT_DW_POS] &= SPFC_SQE_OBIT_CLEAR_MASK_BE;
	e_sqe_dw[SPFC_SQE_SECOND_OBIT_DW_POS] &= SPFC_SQE_OBIT_CLEAR_MASK_BE;
	e_sqe_dw[SPFC_SQE_FIRST_OBIT_DW_POS] &= SPFC_SQE_OBIT_CLEAR_MASK_BE;
}

static void spfc_set_direct_wqe_owner_be(void *sqe, u16 owner)
{
	if (owner)
		spfc_set_sq_wqe_owner_be(sqe);
	else
		spfc_clear_sq_wqe_owner_be(sqe);
}

static void spfc_set_srq_link_wqe_owner_be(struct spfc_linkwqe *link_wqe,
					   u32 owner, u16 pmsn)
{
	struct spfc_linkwqe local_lw;

	mb();
	local_lw.val_wd1 = be32_to_cpu(link_wqe->val_wd1);
	local_lw.wd1.msn = pmsn;
	local_lw.wd1.dump_msn = (local_lw.wd1.msn & SPFC_LOCAL_LW_WD1_DUMP_MSN_MASK);
	link_wqe->val_wd1 = cpu_to_be32(local_lw.val_wd1);

	local_lw.val_wd0 = be32_to_cpu(link_wqe->val_wd0);
	local_lw.wd0.o = owner;
	link_wqe->val_wd0 = cpu_to_be32(local_lw.val_wd0);
	mb();
}

static inline bool spfc_is_scq_link_wqe(struct spfc_scq_info *scq_info)
{
	u16 custom_scqe_num = 0;

	custom_scqe_num = scq_info->ci + 1;

	if ((custom_scqe_num % scq_info->wqe_num_per_buf == 0) ||
	    scq_info->valid_wqe_num == custom_scqe_num)
		return true;
	else
		return false;
}

static struct spfc_wqe_page *
spfc_add_tail_wqe_page(struct spfc_parent_ssq_info *ssq)
{
	struct spfc_hba_info *hba = NULL;
	struct spfc_wqe_page *esgl = NULL;
	struct list_head *free_list_head = NULL;
	ulong flag = 0;

	hba = (struct spfc_hba_info *)ssq->hba;

	spin_lock_irqsave(&hba->sq_wpg_pool.wpg_pool_lock, flag);

	/* Get a WqePage from hba->sq_wpg_pool.list_free_wpg_pool, and add to
	 * sq.list_SqTailWqePage
	 */
	if (!list_empty(&hba->sq_wpg_pool.list_free_wpg_pool)) {
		free_list_head = UNF_OS_LIST_NEXT(&hba->sq_wpg_pool.list_free_wpg_pool);
		list_del(free_list_head);
		list_add_tail(free_list_head, &ssq->list_linked_list_sq);
		esgl = list_entry(free_list_head, struct spfc_wqe_page, entry_wpg);

		/* WqePage Pool counter */
		atomic_inc(&hba->sq_wpg_pool.wpg_in_use);
	} else {
		esgl = NULL;
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]SQ pool is empty when SQ(0x%x) try to get wqe page",
			     ssq->sqn);
		SPFC_HBA_STAT(hba, SPFC_STAT_SQ_POOL_EMPTY);
	}

	spin_unlock_irqrestore(&hba->sq_wpg_pool.wpg_pool_lock, flag);

	return esgl;
}

static inline struct spfc_sqe *spfc_get_wqe_page_entry(struct spfc_wqe_page *wpg,
						       u32 wqe_offset)
{
	struct spfc_sqe *sqe_wpg = NULL;

	sqe_wpg = (struct spfc_sqe *)(wpg->wpg_addr);
	sqe_wpg += wqe_offset;

	return sqe_wpg;
}

static void spfc_free_head_wqe_page(struct spfc_parent_ssq_info *ssq)
{
	struct spfc_hba_info *hba = NULL;
	struct spfc_wqe_page *sq_wpg = NULL;
	struct list_head *entry_head_wqe_page = NULL;
	ulong flag = 0;

	atomic_dec(&ssq->wqe_page_cnt);

	hba = (struct spfc_hba_info *)ssq->hba;
	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "Port(0x%x) free wqe page nowpagecnt:%d",
		     hba->port_cfg.port_id,
		     atomic_read(&ssq->wqe_page_cnt));
	sq_wpg = SPFC_GET_SQ_HEAD(ssq);

	memset((void *)sq_wpg->wpg_addr, WQE_MARKER_0, hba->sq_wpg_pool.wpg_size);

	spin_lock_irqsave(&hba->sq_wpg_pool.wpg_pool_lock, flag);
	entry_head_wqe_page = &sq_wpg->entry_wpg;
	list_del(entry_head_wqe_page);
	list_add_tail(entry_head_wqe_page, &hba->sq_wpg_pool.list_free_wpg_pool);

	/* WqePage Pool counter */
	atomic_dec(&hba->sq_wpg_pool.wpg_in_use);
	spin_unlock_irqrestore(&hba->sq_wpg_pool.wpg_pool_lock, flag);
}

static void spfc_free_link_list_wpg(struct spfc_parent_ssq_info *ssq)
{
	ulong flag = 0;
	struct spfc_hba_info *hba = NULL;
	struct list_head *node = NULL;
	struct list_head *next_node = NULL;
	struct list_head *entry_head_wqe_page = NULL;
	struct spfc_wqe_page *sq_wpg = NULL;

	hba = (struct spfc_hba_info *)ssq->hba;

	list_for_each_safe(node, next_node, &ssq->list_linked_list_sq) {
		sq_wpg = list_entry(node, struct spfc_wqe_page, entry_wpg);
		memset((void *)sq_wpg->wpg_addr, WQE_MARKER_0, hba->sq_wpg_pool.wpg_size);

		spin_lock_irqsave(&hba->sq_wpg_pool.wpg_pool_lock, flag);
		entry_head_wqe_page = &sq_wpg->entry_wpg;
		list_del(entry_head_wqe_page);
		list_add_tail(entry_head_wqe_page, &hba->sq_wpg_pool.list_free_wpg_pool);

		/* WqePage Pool counter */
		atomic_dec(&ssq->wqe_page_cnt);
		atomic_dec(&hba->sq_wpg_pool.wpg_in_use);

		spin_unlock_irqrestore(&hba->sq_wpg_pool.wpg_pool_lock, flag);
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "[info]Port(0x%x) RPort(0x%x) Sq(0x%x) link list destroyed, Sq.WqePageCnt=0x%x, SqWpgPool.wpg_in_use=0x%x",
		     hba->port_cfg.port_id, ssq->sqn, ssq->context_id,
		     atomic_read(&ssq->wqe_page_cnt), atomic_read(&hba->sq_wpg_pool.wpg_in_use));
}

struct spfc_wqe_page *
spfc_add_one_wqe_page(struct spfc_parent_ssq_info *ssq)
{
	u32 wqe_inx = 0;
	struct spfc_wqe_page *wqe_page = NULL;
	struct spfc_sqe *sqe_in_wp = NULL;
	struct spfc_linkwqe *link_wqe_in_wpg = NULL;
	struct spfc_linkwqe link_wqe;

	/* Add a new Wqe Page */
	wqe_page = spfc_add_tail_wqe_page(ssq);

	if (!wqe_page)
		return NULL;

	for (wqe_inx = 0; wqe_inx <= ssq->wqe_num_per_buf; wqe_inx++) {
		sqe_in_wp = spfc_get_wqe_page_entry(wqe_page, wqe_inx);
		sqe_in_wp->ctrl_sl.ch.ctrl_ch_val = 0;
		sqe_in_wp->ectrl_sl.ch.ctrl_ch_val = 0;
	}

	/* Set last WqePage as linkwqe */
	link_wqe_in_wpg = (struct spfc_linkwqe *)spfc_get_wqe_page_entry(wqe_page,
									 ssq->wqe_num_per_buf);
	link_wqe.val_wd0 = 0;
	link_wqe.val_wd1 = 0;
	link_wqe.next_page_addr_hi = (ssq->queue_style == SPFC_QUEUE_RING_STYLE)
					 ? SPFC_MSD(wqe_page->wpg_phy_addr)
					 : 0;
	link_wqe.next_page_addr_lo = (ssq->queue_style == SPFC_QUEUE_RING_STYLE)
					 ? SPFC_LSD(wqe_page->wpg_phy_addr)
					 : 0;
	link_wqe.wd0.wf = CQM_WQE_WF_LINK;
	link_wqe.wd0.ctrlsl = CQM_LINK_WQE_CTRLSL_VALUE;
	link_wqe.wd0.o = !(ssq->last_pi_owner);
	link_wqe.wd1.lp = (ssq->queue_style == SPFC_QUEUE_RING_STYLE)
			      ? CQM_LINK_WQE_LP_VALID
			      : CQM_LINK_WQE_LP_INVALID;
	spfc_cpu_to_big32(&link_wqe, sizeof(struct spfc_linkwqe));
	memcpy(link_wqe_in_wpg, &link_wqe, sizeof(struct spfc_linkwqe));
	memcpy((u8 *)link_wqe_in_wpg + SPFC_EXTEND_WQE_OFFSET,
	       &link_wqe, sizeof(struct spfc_linkwqe));

	return wqe_page;
}

static inline struct spfc_scqe_type *
spfc_get_scq_entry(struct spfc_scq_info *scq_info)
{
	u32 buf_id = 0;
	u16 buf_offset = 0;
	u16 ci = 0;
	struct cqm_buf_list *buf = NULL;

	FC_CHECK_RETURN_VALUE(scq_info, NULL);

	ci = scq_info->ci;
	buf_id = ci / scq_info->wqe_num_per_buf;
	buf = &scq_info->cqm_scq_info->q_room_buf_1.buf_list[buf_id];
	buf_offset = (u16)(ci % scq_info->wqe_num_per_buf);

	return (struct spfc_scqe_type *)(buf->va) + buf_offset;
}

static inline bool spfc_is_cqe_done(u32 *done, u32 *owner, u16 driver_owner)
{
	return ((((u16)(!!(*done & SPFC_DONE_MASK)) == driver_owner) &&
		 ((u16)(!!(*owner & SPFC_OWNER_MASK)) == driver_owner)) ? true : false);
}

u32 spfc_process_scq_cqe_entity(ulong info, u32 proc_cnt)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 index = 0;
	struct wq_header *queue_header = NULL;
	struct spfc_scqe_type *scqe = NULL;
	struct spfc_scqe_type tmp_scqe;
	struct spfc_scq_info *scq_info = (struct spfc_scq_info *)info;

	FC_CHECK_RETURN_VALUE(scq_info, ret);
	SPFC_FUNCTION_ENTER;

	queue_header = (struct wq_header *)(void *)(scq_info->cqm_scq_info->q_header_vaddr);

	for (index = 0; index < proc_cnt;) {
		/* If linked wqe, then update CI */
		if (spfc_is_scq_link_wqe(scq_info)) {
			spfc_update_consumer_info(scq_info->valid_wqe_num,
						  &scq_info->ci,
						  &scq_info->ci_owner);
			spfc_update_cq_header(&queue_header->ci_record,
					      scq_info->ci, scq_info->ci_owner);

			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_INFO,
				     "[info]Current wqe is a linked wqe");
			continue;
		}

		/* Get SCQE and then check obit & donebit whether been set */
		scqe = spfc_get_scq_entry(scq_info);
		if (unlikely(!scqe)) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[warn]Scqe is NULL");
			break;
		}

		if (!spfc_is_cqe_done((u32 *)(void *)&scqe->wd0,
				      (u32 *)(void *)&scqe->ch.wd0,
				      scq_info->ci_owner)) {
			atomic_set(&scq_info->flush_stat, SPFC_QUEUE_FLUSH_DONE);

			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_INFO, "[info]Now has no valid scqe");
			break;
		}

		/* rmb & do memory copy */
		rmb();
		memcpy(&tmp_scqe, scqe, sizeof(struct spfc_scqe_type));
		/* process SCQ entry */
		ret = spfc_rcv_scq_entry_from_scq(scq_info->hba, (void *)&tmp_scqe,
						  scq_info->queue_id);
		if (unlikely(ret != RETURN_OK)) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]QueueId(0x%x) scqn(0x%x) scqe process error at CI(0x%x)",
				     scq_info->queue_id, scq_info->scqn, scq_info->ci);
		}

		/* Update Driver's CI & Obit */
		spfc_update_consumer_info(scq_info->valid_wqe_num,
					  &scq_info->ci, &scq_info->ci_owner);
		spfc_update_cq_header(&queue_header->ci_record, scq_info->ci,
				      scq_info->ci_owner);
		index++;
	}

	/* Re-schedule again if necessary */
	if (index == proc_cnt)
		tasklet_schedule(&scq_info->tasklet);

	SPFC_FUNCTION_RETURN;

	return index;
}

void spfc_set_scq_irg_cfg(struct spfc_hba_info *hba, u32 mode, u16 msix_index)
{
#define SPFC_POLLING_MODE_ITERRUPT_PENDING_CNT 5
#define SPFC_POLLING_MODE_ITERRUPT_COALESC_TIMER_CFG 10
	u8 pending_limt = 0;
	u8 coalesc_timer_cfg = 0;

	struct interrupt_info info = {0};

	if (mode != SPFC_SCQ_INTR_LOW_LATENCY_MODE) {
		pending_limt = SPFC_POLLING_MODE_ITERRUPT_PENDING_CNT;
		coalesc_timer_cfg =
		    SPFC_POLLING_MODE_ITERRUPT_COALESC_TIMER_CFG;
	}

	memset(&info, 0, sizeof(info));
	info.interrupt_coalesc_set = 1;
	info.lli_set = 0;
	info.pending_limt = pending_limt;
	info.coalesc_timer_cfg = coalesc_timer_cfg;
	info.resend_timer_cfg = 0;
	info.msix_index = msix_index;

	sphw_set_interrupt_cfg(hba->dev_handle, info, SPHW_CHANNEL_FC);
}

void spfc_process_scq_cqe(ulong info)
{
	struct spfc_scq_info *scq_info = (struct spfc_scq_info *)info;

	FC_CHECK_RETURN_VOID(scq_info);

	spfc_process_scq_cqe_entity(info, SPFC_CQE_MAX_PROCESS_NUM_PER_INTR);
}

irqreturn_t spfc_scq_irq(int irq, void *scq_info)
{
	SPFC_FUNCTION_ENTER;

	FC_CHECK_RETURN_VALUE(scq_info, IRQ_NONE);

	tasklet_schedule(&((struct spfc_scq_info *)scq_info)->tasklet);

	SPFC_FUNCTION_RETURN;

	return IRQ_HANDLED;
}

static u32 spfc_alloc_scq_int(struct spfc_scq_info *scq_info)
{
	int ret = UNF_RETURN_ERROR_S32;
	u16 act_num = 0;
	struct irq_info irq_info;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VALUE(scq_info, UNF_RETURN_ERROR);

	/* 1. Alloc & check SCQ IRQ */
	hba = (struct spfc_hba_info *)(scq_info->hba);
	ret = sphw_alloc_irqs(hba->dev_handle, SERVICE_T_FC, SPFC_INT_NUM_PER_QUEUE,
			      &irq_info, &act_num);
	if (ret != RETURN_OK || act_num != SPFC_INT_NUM_PER_QUEUE) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate scq irq failed, return %d", ret);
		return UNF_RETURN_ERROR;
	}

	if (irq_info.msix_entry_idx >= SPFC_SCQ_INT_ID_MAX) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SCQ irq id exceed %d, msix_entry_idx %d",
			     SPFC_SCQ_INT_ID_MAX, irq_info.msix_entry_idx);
		sphw_free_irq(hba->dev_handle, SERVICE_T_FC, irq_info.irq_id);
		return UNF_RETURN_ERROR;
	}

	scq_info->irq_id = (u32)(irq_info.irq_id);
	scq_info->msix_entry_idx = (u16)(irq_info.msix_entry_idx);

	snprintf(scq_info->irq_name, SPFC_IRQ_NAME_MAX, "fc_scq%u_%x_msix%u",
		 scq_info->queue_id, hba->port_cfg.port_id, scq_info->msix_entry_idx);

	/* 2. SCQ IRQ tasklet init */
	tasklet_init(&scq_info->tasklet, spfc_process_scq_cqe, (ulong)(uintptr_t)scq_info);

	/* 3. Request IRQ for SCQ */
	ret = request_irq(scq_info->irq_id, spfc_scq_irq, 0, scq_info->irq_name, scq_info);

	sphw_set_msix_state(hba->dev_handle, scq_info->msix_entry_idx, SPHW_MSIX_ENABLE);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Request SCQ irq failed, SCQ Index = %u, return %d",
			     scq_info->queue_id, ret);
		sphw_free_irq(hba->dev_handle, SERVICE_T_FC, scq_info->irq_id);
		memset(scq_info->irq_name, 0, SPFC_IRQ_NAME_MAX);
		scq_info->irq_id = 0;
		scq_info->msix_entry_idx = 0;
		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

static void spfc_free_scq_int(struct spfc_scq_info *scq_info)
{
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID(scq_info);

	hba = (struct spfc_hba_info *)(scq_info->hba);
	sphw_set_msix_state(hba->dev_handle, scq_info->msix_entry_idx, SPHW_MSIX_DISABLE);
	free_irq(scq_info->irq_id, scq_info);
	tasklet_kill(&scq_info->tasklet);
	sphw_free_irq(hba->dev_handle, SERVICE_T_FC, scq_info->irq_id);
	memset(scq_info->irq_name, 0, SPFC_IRQ_NAME_MAX);
	scq_info->irq_id = 0;
	scq_info->msix_entry_idx = 0;
}

static void spfc_init_scq_info(struct spfc_hba_info *hba, struct cqm_queue *cqm_scq,
			       u32 queue_id, struct spfc_scq_info **scq_info)
{
	FC_CHECK_RETURN_VOID(hba);
	FC_CHECK_RETURN_VOID(cqm_scq);
	FC_CHECK_RETURN_VOID(scq_info);

	*scq_info = &hba->scq_info[queue_id];
	(*scq_info)->queue_id = queue_id;
	(*scq_info)->scqn = cqm_scq->index;
	(*scq_info)->hba = (void *)hba;

	(*scq_info)->cqm_scq_info = cqm_scq;
	(*scq_info)->wqe_num_per_buf =
	    cqm_scq->q_room_buf_1.buf_size / SPFC_SCQE_SIZE;
	(*scq_info)->wqe_size = SPFC_SCQE_SIZE;
	(*scq_info)->valid_wqe_num = (SPFC_SCQ_IS_STS(queue_id) ? SPFC_STS_SCQ_DEPTH
				      : SPFC_CMD_SCQ_DEPTH);
	(*scq_info)->scqc_cq_depth = (SPFC_SCQ_IS_STS(queue_id) ? SPFC_STS_SCQC_CQ_DEPTH
				      : SPFC_CMD_SCQC_CQ_DEPTH);
	(*scq_info)->scqc_ci_type = SPFC_STS_SCQ_CI_TYPE;
	(*scq_info)->ci = 0;
	(*scq_info)->ci_owner = 1;
}

static void spfc_init_scq_header(struct wq_header *queue_header)
{
	FC_CHECK_RETURN_VOID(queue_header);

	memset(queue_header, 0, sizeof(struct wq_header));

	/* Obit default is 1 */
	queue_header->db_record.pmsn = 1 << UNF_SHIFT_15;
	queue_header->db_record.dump_pmsn = queue_header->db_record.pmsn;
	queue_header->ci_record.cmsn = 1 << UNF_SHIFT_15;
	queue_header->ci_record.dump_cmsn = queue_header->ci_record.cmsn;

	/* Big endian convert */
	spfc_cpu_to_big64((void *)queue_header, sizeof(struct wq_header));
}

static void spfc_cfg_scq_ctx(struct spfc_scq_info *scq_info,
			     struct spfc_cq_qinfo *scq_ctx)
{
	struct cqm_queue *cqm_scq_info = NULL;
	struct spfc_queue_info_bus queue_bus;
	u64 parity = 0;

	FC_CHECK_RETURN_VOID(scq_info);

	cqm_scq_info = scq_info->cqm_scq_info;

	scq_ctx->pcie_template_hi = 0;
	scq_ctx->cur_cqe_gpa = cqm_scq_info->q_room_buf_1.buf_list->pa >> SPFC_CQE_GPA_SHIFT;
	scq_ctx->pi = 0;
	scq_ctx->pi_o = 1;
	scq_ctx->ci = scq_info->ci;
	scq_ctx->ci_o = scq_info->ci_owner;
	scq_ctx->c_eqn_msi_x = scq_info->msix_entry_idx;
	scq_ctx->ci_type = scq_info->scqc_ci_type;
	scq_ctx->cq_depth = scq_info->scqc_cq_depth;
	scq_ctx->armq = SPFC_ARMQ_IDLE;
	scq_ctx->cur_cqe_cnt = 0;
	scq_ctx->cqe_max_cnt = 0;
	scq_ctx->cqe_dmaattr_idx = 0;
	scq_ctx->cq_so_ro = 0;
	scq_ctx->init_mode = SPFC_CQ_INT_MODE;
	scq_ctx->next_o = 1;
	scq_ctx->loop_o = 1;
	scq_ctx->next_cq_wqe_page_gpa = cqm_scq_info->q_room_buf_1.buf_list[ARRAY_INDEX_1].pa >>
					SPFC_NEXT_CQE_GPA_SHIFT;
	scq_ctx->pcie_template_lo = 0;

	scq_ctx->ci_gpa = (cqm_scq_info->q_header_paddr + offsetof(struct wq_header, ci_record)) >>
			   SPFC_CQE_GPA_SHIFT;

	memset(&queue_bus, 0, sizeof(struct spfc_queue_info_bus));
	queue_bus.bus[ARRAY_INDEX_0] |= ((u64)(scq_info->scqn & SPFC_SCQN_MASK)); /* bits 20 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(scq_ctx->pcie_template_lo)) << UNF_SHIFT_20);
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(scq_ctx->ci_gpa & SPFC_SCQ_CTX_CI_GPA_MASK)) <<
					UNF_SHIFT_23); /* bits 28 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(scq_ctx->cqe_dmaattr_idx)) << UNF_SHIFT_51);
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(scq_ctx->cq_so_ro)) << UNF_SHIFT_57); /* bits 2 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(scq_ctx->init_mode)) << UNF_SHIFT_59); /* bits 2 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(scq_ctx->c_eqn_msi_x &
					 SPFC_SCQ_CTX_C_EQN_MSI_X_MASK)) << UNF_SHIFT_61);
	queue_bus.bus[ARRAY_INDEX_1] |= ((u64)(scq_ctx->c_eqn_msi_x >> UNF_SHIFT_3)); /* bits 7 */
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(scq_ctx->ci_type)) << UNF_SHIFT_7); /* bits 1 */
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(scq_ctx->cq_depth)) << UNF_SHIFT_8); /* bits 3 */
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(scq_ctx->cqe_max_cnt)) << UNF_SHIFT_11);
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(scq_ctx->pcie_template_hi)) << UNF_SHIFT_19);

	parity = spfc_get_parity_value(queue_bus.bus, SPFC_SCQC_BUS_ROW, SPFC_SCQC_BUS_COL);
	scq_ctx->parity_0 = parity & SPFC_PARITY_MASK;
	scq_ctx->parity_1 = (parity >> UNF_SHIFT_1) & SPFC_PARITY_MASK;
	scq_ctx->parity_2 = (parity >> UNF_SHIFT_2) & SPFC_PARITY_MASK;

	spfc_cpu_to_big64((void *)scq_ctx, sizeof(struct spfc_cq_qinfo));
}

static u32 spfc_creat_scqc_via_cmdq_sync(struct spfc_hba_info *hba,
					 struct spfc_cq_qinfo *scqc, u32 scqn)
{
#define SPFC_INIT_SCQC_TIMEOUT 3000
	int ret;
	u32 covrt_size;
	struct spfc_cmdqe_creat_scqc init_scqc_cmd;
	struct sphw_cmd_buf *cmdq_in_buf;

	cmdq_in_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmdq_in_buf) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]cmdq in_cmd_buf alloc failed");

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_INIT_SCQC);
		return UNF_RETURN_ERROR;
	}

	memset(&init_scqc_cmd, 0, sizeof(init_scqc_cmd));
	init_scqc_cmd.wd0.task_type = SPFC_TASK_T_INIT_SCQC;
	init_scqc_cmd.wd1.scqn = SPFC_LSW(scqn);
	covrt_size = sizeof(init_scqc_cmd) - sizeof(init_scqc_cmd.scqc);
	spfc_cpu_to_big32(&init_scqc_cmd, covrt_size);

	/* scqc is already big endian */
	memcpy(init_scqc_cmd.scqc, scqc, sizeof(*scqc));
	memcpy(cmdq_in_buf->buf, &init_scqc_cmd, sizeof(init_scqc_cmd));
	cmdq_in_buf->size = sizeof(init_scqc_cmd);

	ret = sphw_cmdq_detail_resp(hba->dev_handle, COMM_MOD_FC, 0,
				    cmdq_in_buf, NULL, NULL,
				    SPFC_INIT_SCQC_TIMEOUT, SPHW_CHANNEL_FC);
	sphw_free_cmd_buf(hba->dev_handle, cmdq_in_buf);
	if (ret) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Send creat scqc via cmdq failed, ret=%d",
			     ret);

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_INIT_SCQC);
		return UNF_RETURN_ERROR;
	}

	SPFC_IO_STAT(hba, SPFC_TASK_T_INIT_SCQC);

	return RETURN_OK;
}

static u32 spfc_delete_ssqc_via_cmdq_sync(struct spfc_hba_info *hba, u32 xid,
					  u64 context_gpa, u32 entry_count)
{
#define SPFC_DELETE_SSQC_TIMEOUT 3000
	int ret = RETURN_OK;
	struct spfc_cmdqe_delete_ssqc delete_ssqc_cmd;
	struct sphw_cmd_buf *cmdq_in_buf = NULL;

	cmdq_in_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmdq_in_buf) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]cmdq in_cmd_buf alloc failed");
		return UNF_RETURN_ERROR;
	}

	memset(&delete_ssqc_cmd, 0, sizeof(delete_ssqc_cmd));
	delete_ssqc_cmd.wd0.task_type = SPFC_TASK_T_CLEAR_SSQ_CONTEXT;
	delete_ssqc_cmd.wd0.xid = xid;
	delete_ssqc_cmd.wd0.entry_count = entry_count;
	delete_ssqc_cmd.wd1.scqn = SPFC_LSW(0);
	delete_ssqc_cmd.context_gpa_hi = SPFC_HIGH_32_BITS(context_gpa);
	delete_ssqc_cmd.context_gpa_lo = SPFC_LOW_32_BITS(context_gpa);
	spfc_cpu_to_big32(&delete_ssqc_cmd, sizeof(delete_ssqc_cmd));
	memcpy(cmdq_in_buf->buf, &delete_ssqc_cmd, sizeof(delete_ssqc_cmd));
	cmdq_in_buf->size = sizeof(delete_ssqc_cmd);

	ret = sphw_cmdq_detail_resp(hba->dev_handle, COMM_MOD_FC, 0,
				    cmdq_in_buf, NULL, NULL,
				    SPFC_DELETE_SSQC_TIMEOUT,
				    SPHW_CHANNEL_FC);

	sphw_free_cmd_buf(hba->dev_handle, cmdq_in_buf);

	return ret;
}

static void spfc_free_ssq_qpc(struct spfc_hba_info *hba, u32 free_sq_num)
{
	u32 global_sq_index = 0;
	u32 qid = 0;
	struct spfc_parent_shared_queue_info *ssq_info = NULL;

	SPFC_FUNCTION_ENTER;
	for (global_sq_index = 0; global_sq_index < free_sq_num;) {
		for (qid = 1; qid <= SPFC_SQ_NUM_PER_QPC; qid++) {
			ssq_info = &hba->parent_queue_mgr->shared_queue[global_sq_index];
			if (qid == SPFC_SQ_NUM_PER_QPC ||
			    global_sq_index == free_sq_num - 1) {
				if (ssq_info->parent_ctx.cqm_parent_ctx_obj) {
					FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
						     "[INFO]qid 0x%x, global_sq_index 0x%x, free_sq_num 0x%x",
						     qid, global_sq_index, free_sq_num);
					cqm3_object_delete(&ssq_info->parent_ctx
							   .cqm_parent_ctx_obj->object);
					ssq_info->parent_ctx.cqm_parent_ctx_obj = NULL;
				}
			}
			global_sq_index++;
			if (global_sq_index >= free_sq_num)
				break;
		}
	}
}

void spfc_free_ssq(void *handle, u32 free_sq_num)
{
#define SPFC_FREE_SSQ_WAIT_MS 1000
	u32 global_sq_index = 0;
	u32 qid = 0;
	struct spfc_parent_shared_queue_info *ssq_info = NULL;
	struct spfc_parent_ssq_info *sq_ctrl = NULL;
	struct cqm_qpc_mpt *prnt_ctx = NULL;
	u32 ret = UNF_RETURN_ERROR;
	u32 entry_count = 0;
	struct spfc_hba_info *hba = NULL;

	SPFC_FUNCTION_ENTER;

	hba = (struct spfc_hba_info *)handle;
	for (global_sq_index = 0; global_sq_index < free_sq_num;) {
		for (qid = 1; qid <= SPFC_SQ_NUM_PER_QPC; qid++) {
			ssq_info = &hba->parent_queue_mgr->shared_queue[global_sq_index];
			sq_ctrl = &ssq_info->parent_ssq_info;
			/* Free data cos */
			spfc_free_link_list_wpg(sq_ctrl);
			if (sq_ctrl->queue_head_original) {
				pci_unmap_single(hba->pci_dev,
						 sq_ctrl->queue_hdr_phy_addr_original,
						 sizeof(struct spfc_queue_header) +
						 SPFC_SQ_HEADER_ADDR_ALIGN_SIZE,
						 DMA_BIDIRECTIONAL);
				kfree(sq_ctrl->queue_head_original);
				sq_ctrl->queue_head_original = NULL;
			}
			if (qid == SPFC_SQ_NUM_PER_QPC || global_sq_index == free_sq_num - 1) {
				if (ssq_info->parent_ctx.cqm_parent_ctx_obj) {
					prnt_ctx = ssq_info->parent_ctx.cqm_parent_ctx_obj;
					entry_count = (qid == SPFC_SQ_NUM_PER_QPC ?
							SPFC_SQ_NUM_PER_QPC :
							free_sq_num - global_sq_index);
					ret = spfc_delete_ssqc_via_cmdq_sync(hba, prnt_ctx->xid,
									     prnt_ctx->paddr,
									     entry_count);
					if (ret != RETURN_OK) {
						FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
							     "[err]ucode delete ssq fail, glbindex 0x%x, qid 0x%x, glsqindex 0x%x",
							     global_sq_index, qid, free_sq_num);
					}
				}
			}
			global_sq_index++;
			if (global_sq_index >= free_sq_num)
				break;
		}
	}

	msleep(SPFC_FREE_SSQ_WAIT_MS);

	spfc_free_ssq_qpc(hba, free_sq_num);
}

u32 spfc_creat_ssqc_via_cmdq_sync(struct spfc_hba_info *hba,
				  struct spfc_ssq_parent_context *ssqc,
				  u32 xid, u64 context_gpa)
{
#define SPFC_INIT_SSQC_TIMEOUT 3000
	int ret;
	u32 covrt_size;
	struct spfc_cmdqe_creat_ssqc create_ssqc_cmd;
	struct sphw_cmd_buf *cmdq_in_buf = NULL;

	cmdq_in_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmdq_in_buf) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]cmdq in_cmd_buf alloc failed");
		return UNF_RETURN_ERROR;
	}

	memset(&create_ssqc_cmd, 0, sizeof(create_ssqc_cmd));
	create_ssqc_cmd.wd0.task_type = SPFC_TASK_T_CREATE_SSQ_CONTEXT;
	create_ssqc_cmd.wd0.xid = xid;
	create_ssqc_cmd.wd1.scqn = SPFC_LSW(0);
	create_ssqc_cmd.context_gpa_hi = SPFC_HIGH_32_BITS(context_gpa);
	create_ssqc_cmd.context_gpa_lo = SPFC_LOW_32_BITS(context_gpa);
	covrt_size = sizeof(create_ssqc_cmd) - sizeof(create_ssqc_cmd.ssqc);
	spfc_cpu_to_big32(&create_ssqc_cmd, covrt_size);

	/* scqc is already big endian */
	memcpy(create_ssqc_cmd.ssqc, ssqc, sizeof(*ssqc));
	memcpy(cmdq_in_buf->buf, &create_ssqc_cmd, sizeof(create_ssqc_cmd));
	cmdq_in_buf->size = sizeof(create_ssqc_cmd);
	ret = sphw_cmdq_detail_resp(hba->dev_handle, COMM_MOD_FC, 0,
				    cmdq_in_buf, NULL, NULL,
				    SPFC_INIT_SSQC_TIMEOUT, SPHW_CHANNEL_FC);
	sphw_free_cmd_buf(hba->dev_handle, cmdq_in_buf);
	if (ret)
		return UNF_RETURN_ERROR;
	return RETURN_OK;
}

void spfc_init_sq_prnt_ctxt_sq_qinfo(struct spfc_sq_qinfo *sq_info,
				     struct spfc_parent_ssq_info *ssq)
{
	struct spfc_wqe_page *head_wqe_page = NULL;
	struct spfc_sq_qinfo *prnt_sq_ctx = NULL;
	struct spfc_queue_info_bus queue_bus;

	SPFC_FUNCTION_ENTER;

	/* Obtains the Parent Context address */
	head_wqe_page = SPFC_GET_SQ_HEAD(ssq);

	prnt_sq_ctx = sq_info;

	/* The PMSN is updated by the host driver */
	prnt_sq_ctx->pmsn_type = SPFC_PMSN_CI_TYPE_FROM_HOST;

	/* Indicates the value of O of the valid SQE in the current round of SQ.
	 * * The value of Linked List SQ is always one, and the value of 0 is
	 * invalid.
	 */
	prnt_sq_ctx->loop_o =
	    SPFC_OWNER_DRIVER_PRODUCT; /* current valid o-bit */

	/* should be opposite from loop_o */
	prnt_sq_ctx->cur_wqe_o = ~(prnt_sq_ctx->loop_o);

	/* the first sqe's gpa */
	prnt_sq_ctx->cur_sqe_gpa = head_wqe_page->wpg_phy_addr;

	/* Indicates the GPA of the Queue header that is initialized to the SQ
	 * in * the Host memory. The value must be 16-byte aligned.
	 */
	prnt_sq_ctx->pmsn_gpa = ssq->queue_hdr_phy_addr;
	if (wqe_pre_load != 0)
		prnt_sq_ctx->pmsn_gpa |= SPFC_SQ_LINK_PRE;

	/* This field is used to fill in the dmaattr_idx field of the ComboDMA.
	 * The default value is 0
	 */
	prnt_sq_ctx->sqe_dmaattr_idx = SPFC_DMA_ATTR_OFST;

	/* This field is filled using the value of RO_SO in the SGL0 of the
	 * ComboDMA
	 */
	prnt_sq_ctx->sq_so_ro = SPFC_PCIE_RELAXED_ORDERING;

	prnt_sq_ctx->ring = ssq->queue_style;

	/* This field is used to set the SGL0 field of the Child solicDMA */
	prnt_sq_ctx->zerocopy_dmaattr_idx = SPFC_DMA_ATTR_OFST;

	prnt_sq_ctx->zerocopy_so_ro = SPFC_PCIE_RELAXED_ORDERING;
	prnt_sq_ctx->enable_256 = SPFC_256BWQE_ENABLE;

	/* PCIe attribute information */
	prnt_sq_ctx->pcie_template = SPFC_PCIE_TEMPLATE;

	memset(&queue_bus, 0, sizeof(struct spfc_queue_info_bus));
	queue_bus.bus[ARRAY_INDEX_0] |= ((u64)(ssq->context_id & SPFC_SSQ_CTX_MASK)); /* bits 20 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->sqe_dmaattr_idx)) << UNF_SHIFT_20);
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->sq_so_ro)) << UNF_SHIFT_26);
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->ring)) << UNF_SHIFT_28); /* bits 1 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->zerocopy_dmaattr_idx))
					 << UNF_SHIFT_29); /* bits 6 */
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->zerocopy_so_ro)) << UNF_SHIFT_35);
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->pcie_template)) << UNF_SHIFT_37);
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(prnt_sq_ctx->pmsn_gpa >> UNF_SHIFT_4))
					 << UNF_SHIFT_43); /* bits 21 */
	queue_bus.bus[ARRAY_INDEX_1] |= ((u64)(prnt_sq_ctx->pmsn_gpa >> UNF_SHIFT_25));
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(prnt_sq_ctx->pmsn_type)) << UNF_SHIFT_39);
	prnt_sq_ctx->parity = spfc_get_parity_value(queue_bus.bus, SPFC_SQC_BUS_ROW,
						    SPFC_SQC_BUS_COL);
	spfc_cpu_to_big64(prnt_sq_ctx, sizeof(struct spfc_sq_qinfo));

	SPFC_FUNCTION_RETURN;
}

u32 spfc_create_ssq(void *handle)
{
	u32 ret = RETURN_OK;
	u32 global_sq_index = 0;
	u32 qid = 0;
	struct cqm_qpc_mpt *prnt_ctx = NULL;
	struct spfc_parent_shared_queue_info *ssq_info = NULL;
	struct spfc_parent_ssq_info *sq_ctrl = NULL;
	u32 queue_header_alloc_size = 0;
	struct spfc_wqe_page *head_wpg = NULL;
	struct spfc_ssq_parent_context prnt_ctx_info;
	struct spfc_sq_qinfo *sq_info = NULL;
	struct spfc_scq_qinfo *psq_pretchinfo = NULL;
	struct spfc_queue_info_bus queue_bus;
	struct spfc_fc_key_section *keysection = NULL;
	struct spfc_hba_info *hba = NULL;
	dma_addr_t origin_addr;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	hba = (struct spfc_hba_info *)handle;
	for (global_sq_index = 0; global_sq_index < SPFC_MAX_SSQ_NUM;) {
		qid = 0;
		prnt_ctx = cqm3_object_qpc_mpt_create(hba->dev_handle, SERVICE_T_FC,
						      CQM_OBJECT_SERVICE_CTX,
						      SPFC_CNTX_SIZE_256B, NULL,
						      CQM_INDEX_INVALID);
		if (!prnt_ctx) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "[err]Create ssq context failed, CQM_INDEX is 0x%x",
				     CQM_INDEX_INVALID);
			goto ssq_ctx_create_fail;
		}
		memset(&prnt_ctx_info, 0, sizeof(prnt_ctx_info));
		keysection = (struct spfc_fc_key_section *)&prnt_ctx_info;
		keysection->xid_h = (prnt_ctx->xid >> UNF_SHIFT_16) & SPFC_KEYSECTION_XID_H_MASK;
		keysection->xid_l = prnt_ctx->xid & SPFC_KEYSECTION_XID_L_MASK;
		spfc_cpu_to_big32(keysection, sizeof(struct spfc_fc_key_section));
		for (qid = 0; qid < SPFC_SQ_NUM_PER_QPC; qid++) {
			sq_info = (struct spfc_sq_qinfo *)((u8 *)(&prnt_ctx_info) + ((qid + 1) *
				   SPFC_SQ_SPACE_OFFSET));
			ssq_info = &hba->parent_queue_mgr->shared_queue[global_sq_index];
			ssq_info->parent_ctx.cqm_parent_ctx_obj = prnt_ctx;
			/* Initialize struct spfc_parent_sq_info */
			sq_ctrl = &ssq_info->parent_ssq_info;
			sq_ctrl->hba = (void *)hba;
			sq_ctrl->context_id = prnt_ctx->xid;
			sq_ctrl->sq_queue_id = qid + SPFC_SQ_QID_START_PER_QPC;
			sq_ctrl->cache_id = FC_CALC_CID(prnt_ctx->xid);
			sq_ctrl->sqn = global_sq_index;
			sq_ctrl->max_sqe_num = hba->exi_count;
			/* Reduce one Link Wqe */
			sq_ctrl->wqe_num_per_buf = hba->sq_wpg_pool.wqe_per_wpg - 1;
			sq_ctrl->wqe_size = SPFC_SQE_SIZE;
			sq_ctrl->wqe_offset = 0;
			sq_ctrl->head_start_cmsn = 0;
			sq_ctrl->head_end_cmsn = SPFC_GET_WP_END_CMSN(0, sq_ctrl->wqe_num_per_buf);
			sq_ctrl->last_pmsn = 0;
			 /* Linked List SQ Owner Bit 1 valid,0 invalid */
			sq_ctrl->last_pi_owner = 1;
			atomic_set(&sq_ctrl->sq_valid, true);
			sq_ctrl->accum_wqe_cnt = 0;
			sq_ctrl->service_type = SPFC_SERVICE_TYPE_FC_SQ;
			sq_ctrl->queue_style = (global_sq_index == SPFC_DIRECTWQE_SQ_INDEX) ?
						SPFC_QUEUE_RING_STYLE : SPFC_QUEUE_LINK_STYLE;
			INIT_LIST_HEAD(&sq_ctrl->list_linked_list_sq);
			atomic_set(&sq_ctrl->wqe_page_cnt, 0);
			atomic_set(&sq_ctrl->sq_db_cnt, 0);
			atomic_set(&sq_ctrl->sqe_minus_cqe_cnt, 1);
			atomic_set(&sq_ctrl->sq_wqe_cnt, 0);
			atomic_set(&sq_ctrl->sq_cqe_cnt, 0);
			spin_lock_init(&sq_ctrl->parent_sq_enqueue_lock);
			memset(sq_ctrl->io_stat, 0, sizeof(sq_ctrl->io_stat));

			/* Allocate and initialize the Queue Header space. 64B
			 * alignment is required. * Additional 64B is applied
			 * for alignment
			 */
			queue_header_alloc_size = sizeof(struct spfc_queue_header) +
						  SPFC_SQ_HEADER_ADDR_ALIGN_SIZE;
			sq_ctrl->queue_head_original = kmalloc(queue_header_alloc_size, GFP_ATOMIC);
			if (!sq_ctrl->queue_head_original) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
					     "[err]SQ(0x%x) create SQ queue header failed",
					     global_sq_index);
				goto ssq_qheader_create_fail;
			}

			memset((u8 *)sq_ctrl->queue_head_original, 0, queue_header_alloc_size);

			sq_ctrl->queue_hdr_phy_addr_original =
				pci_map_single(hba->pci_dev, sq_ctrl->queue_head_original,
					       queue_header_alloc_size, DMA_BIDIRECTIONAL);
			origin_addr = sq_ctrl->queue_hdr_phy_addr_original;
			if (pci_dma_mapping_error(hba->pci_dev, origin_addr)) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
					     "[err]SQ(0x%x) SQ queue header DMA mapping failed",
					     global_sq_index);
				goto ssq_qheader_dma_map_fail;
			}

			/* Obtains the 64B alignment address */
			sq_ctrl->queue_header = (struct spfc_queue_header *)(uintptr_t)
			SPFC_ADDR_64_ALIGN((u64)((uintptr_t)(sq_ctrl->queue_head_original)));
			sq_ctrl->queue_hdr_phy_addr = SPFC_ADDR_64_ALIGN(origin_addr);

			/* Each SQ is allocated with a Wqe Page by default. The
			 * WqePageCnt is incremented by one
			 */
			head_wpg = spfc_add_one_wqe_page(sq_ctrl);
			if (!head_wpg) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
					     "[err]SQ(0x%x) create SQ first wqe page failed",
					     global_sq_index);
				goto ssq_headwpg_create_fail;
			}

			atomic_inc(&sq_ctrl->wqe_page_cnt);
			spfc_init_sq_prnt_ctxt_sq_qinfo(sq_info, sq_ctrl);
			global_sq_index++;
			if (global_sq_index == SPFC_MAX_SSQ_NUM)
				break;
		}
		psq_pretchinfo = &prnt_ctx_info.sq_pretchinfo;
		psq_pretchinfo->hw_scqc_config.info.rq_th2_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.rq_th1_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.rq_th0_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.rq_min_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.sq_th2_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.sq_th1_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.sq_th0_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.sq_min_preld_cache_num = wqe_pre_load;
		psq_pretchinfo->hw_scqc_config.info.scq_n = (u64)0;
		psq_pretchinfo->hw_scqc_config.info.parity = 0;

		memset(&queue_bus, 0, sizeof(struct spfc_queue_info_bus));
		queue_bus.bus[ARRAY_INDEX_0] = psq_pretchinfo->hw_scqc_config.pctxt_val1;
		psq_pretchinfo->hw_scqc_config.info.parity =
		    spfc_get_parity_value(queue_bus.bus, SPFC_HW_SCQC_BUS_ROW,
					  SPFC_HW_SCQC_BUS_COL);
		spfc_cpu_to_big64(psq_pretchinfo, sizeof(struct spfc_scq_qinfo));
		ret = spfc_creat_ssqc_via_cmdq_sync(hba, &prnt_ctx_info,
						    prnt_ctx->xid, prnt_ctx->paddr);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[err]SQ(0x%x) create ssqc failed.",
				     global_sq_index);
			goto ssq_cmdqsync_fail;
		}
	}

	return RETURN_OK;

ssq_headwpg_create_fail:
	pci_unmap_single(hba->pci_dev, sq_ctrl->queue_hdr_phy_addr_original,
			 queue_header_alloc_size, DMA_BIDIRECTIONAL);

ssq_qheader_dma_map_fail:
	kfree(sq_ctrl->queue_head_original);
	sq_ctrl->queue_head_original = NULL;

ssq_qheader_create_fail:
	cqm3_object_delete(&prnt_ctx->object);
	ssq_info->parent_ctx.cqm_parent_ctx_obj = NULL;
	if (qid > 0) {
		while (qid--) {
			ssq_info = &hba->parent_queue_mgr->shared_queue[global_sq_index - qid];
			ssq_info->parent_ctx.cqm_parent_ctx_obj = NULL;
		}
	}

ssq_ctx_create_fail:
ssq_cmdqsync_fail:
	if (global_sq_index > 0)
		spfc_free_ssq(hba, global_sq_index);

	return UNF_RETURN_ERROR;
}

static u32 spfc_create_scq(struct spfc_hba_info *hba)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 scq_index = 0;
	u32 scq_cfg_num = 0;
	struct cqm_queue *cqm_scq = NULL;
	void *handle = NULL;
	struct spfc_scq_info *scq_info = NULL;
	struct spfc_cq_qinfo cq_qinfo;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	handle = hba->dev_handle;
	/* Create SCQ by CQM interface */
	for (scq_index = 0; scq_index < SPFC_TOTAL_SCQ_NUM; scq_index++) {
		/*
		 * 1. Create/Allocate SCQ
		 * *
		 * Notice: SCQ[0, 2, 4 ...]--->CMD SCQ,
		 * SCQ[1, 3, 5 ...]--->STS SCQ,
		 * SCQ[SPFC_TOTAL_SCQ_NUM-1]--->Defaul SCQ
		 */
		cqm_scq = cqm3_object_nonrdma_queue_create(handle, SERVICE_T_FC,
							   CQM_OBJECT_NONRDMA_SCQ,
							   SPFC_SCQ_IS_STS(scq_index) ?
							   SPFC_STS_SCQ_DEPTH :
							   SPFC_CMD_SCQ_DEPTH,
							   SPFC_SCQE_SIZE, hba);
		if (!cqm_scq) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_WARN, "[err]Create scq failed");

			goto free_scq;
		}

		/* 2. Initialize SCQ (info) */
		spfc_init_scq_info(hba, cqm_scq, scq_index, &scq_info);

		/* 3. Allocate & Initialize SCQ interrupt */
		ret = spfc_alloc_scq_int(scq_info);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[err]Allocate scq interrupt failed");

			cqm3_object_delete(&cqm_scq->object);
			memset(scq_info, 0, sizeof(struct spfc_scq_info));
			goto free_scq;
		}

		/* 4. Initialize SCQ queue header */
		spfc_init_scq_header((struct wq_header *)(void *)cqm_scq->q_header_vaddr);

		/* 5. Initialize & Create SCQ CTX */
		memset(&cq_qinfo, 0, sizeof(cq_qinfo));
		spfc_cfg_scq_ctx(scq_info, &cq_qinfo);
		ret = spfc_creat_scqc_via_cmdq_sync(hba, &cq_qinfo, scq_info->scqn);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[err]Create scq context failed");

			cqm3_object_delete(&cqm_scq->object);
			memset(scq_info, 0, sizeof(struct spfc_scq_info));
			goto free_scq;
		}

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
			     "[info]Create SCQ[%u] Scqn=%u WqeNum=%u WqeSize=%u WqePerBuf=%u CqDepth=%u CiType=%u irq=%u msix=%u",
			     scq_info->queue_id, scq_info->scqn,
			     scq_info->valid_wqe_num, scq_info->wqe_size,
			     scq_info->wqe_num_per_buf, scq_info->scqc_cq_depth,
			     scq_info->scqc_ci_type, scq_info->irq_id,
			     scq_info->msix_entry_idx);
	}

	/* Last SCQ is used to handle SCQE delivery access when clearing buffer
	 */
	hba->default_scqn = scq_info->scqn;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Default Scqn=%u CqmScqIndex=%u", hba->default_scqn,
		     cqm_scq->index);

	return RETURN_OK;

free_scq:
	spfc_flush_scq_ctx(hba);

	scq_cfg_num = scq_index;
	for (scq_index = 0; scq_index < scq_cfg_num; scq_index++) {
		scq_info = &hba->scq_info[scq_index];
		spfc_free_scq_int(scq_info);
		cqm_scq = scq_info->cqm_scq_info;
		cqm3_object_delete(&cqm_scq->object);
		memset(scq_info, 0, sizeof(struct spfc_scq_info));
	}

	return UNF_RETURN_ERROR;
}

static void spfc_destroy_scq(struct spfc_hba_info *hba)
{
	u32 scq_index = 0;
	struct cqm_queue *cqm_scq = NULL;
	struct spfc_scq_info *scq_info = NULL;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Start destroy total %d SCQ", SPFC_TOTAL_SCQ_NUM);

	FC_CHECK_RETURN_VOID(hba);

	/* Use CQM to delete SCQ */
	for (scq_index = 0; scq_index < SPFC_TOTAL_SCQ_NUM; scq_index++) {
		scq_info = &hba->scq_info[scq_index];

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ALL,
			     "[info]Destroy SCQ%u, Scqn=%u, Irq=%u, msix=%u, name=%s",
			     scq_index, scq_info->scqn, scq_info->irq_id,
			     scq_info->msix_entry_idx, scq_info->irq_name);

		spfc_free_scq_int(scq_info);
		cqm_scq = scq_info->cqm_scq_info;
		cqm3_object_delete(&cqm_scq->object);
		memset(scq_info, 0, sizeof(struct spfc_scq_info));
	}
}

static void spfc_init_srq_info(struct spfc_hba_info *hba, struct cqm_queue *cqm_srq,
			       struct spfc_srq_info *srq_info)
{
	FC_CHECK_RETURN_VOID(hba);
	FC_CHECK_RETURN_VOID(cqm_srq);
	FC_CHECK_RETURN_VOID(srq_info);

	srq_info->hba = (void *)hba;

	srq_info->cqm_srq_info = cqm_srq;
	srq_info->wqe_num_per_buf = cqm_srq->q_room_buf_1.buf_size / SPFC_SRQE_SIZE - 1;
	srq_info->wqe_size = SPFC_SRQE_SIZE;
	srq_info->valid_wqe_num = cqm_srq->valid_wqe_num;
	srq_info->pi = 0;
	srq_info->pi_owner = SPFC_SRQ_INIT_LOOP_O;
	srq_info->pmsn = 0;
	srq_info->srqn = cqm_srq->index;
	srq_info->first_rqe_recv_dma = 0;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Init srq info(srq index 0x%x) valid wqe num 0x%x, buffer size 0x%x, wqe num per buf 0x%x",
		     cqm_srq->index, srq_info->valid_wqe_num,
		     cqm_srq->q_room_buf_1.buf_size, srq_info->wqe_num_per_buf);
}

static void spfc_init_srq_header(struct wq_header *queue_header)
{
	FC_CHECK_RETURN_VOID(queue_header);

	memset(queue_header, 0, sizeof(struct wq_header));
}

/*
 *Function Name       : spfc_get_srq_entry
 *Function Description: Obtain RQE in SRQ via PI.
 *Input Parameters    : *srq_info,
 *					   **linked_rqe,
 *					   position
 *Output Parameters   : N/A
 *Return Type         : struct spfc_rqe*
 */
static struct spfc_rqe *spfc_get_srq_entry(struct spfc_srq_info *srq_info,
					   struct spfc_rqe **linked_rqe, u16 position)
{
	u32 buf_id = 0;
	u32 wqe_num_per_buf = 0;
	u16 buf_offset = 0;
	struct cqm_buf_list *buf = NULL;

	FC_CHECK_RETURN_VALUE(srq_info, NULL);

	wqe_num_per_buf = srq_info->wqe_num_per_buf;

	buf_id = position / wqe_num_per_buf;
	buf = &srq_info->cqm_srq_info->q_room_buf_1.buf_list[buf_id];
	buf_offset = position % ((u16)wqe_num_per_buf);

	if (buf_offset + 1 == wqe_num_per_buf)
		*linked_rqe = (struct spfc_rqe *)(buf->va) + wqe_num_per_buf;
	else
		*linked_rqe = NULL;

	return (struct spfc_rqe *)(buf->va) + buf_offset;
}

void spfc_post_els_srq_wqe(struct spfc_srq_info *srq_info, u16 buf_id)
{
	struct spfc_rqe *rqe = NULL;
	struct spfc_rqe tmp_rqe;
	struct spfc_rqe *linked_rqe = NULL;
	struct wq_header *wq_header = NULL;
	struct spfc_drq_buff_entry *buff_entry = NULL;

	FC_CHECK_RETURN_VOID(srq_info);
	FC_CHECK_RETURN_VOID(buf_id < srq_info->valid_wqe_num);

	buff_entry = srq_info->els_buff_entry_head + buf_id;

	spin_lock(&srq_info->srq_spin_lock);

	/* Obtain RQE, not include link wqe */
	rqe = spfc_get_srq_entry(srq_info, &linked_rqe, srq_info->pi);
	if (!rqe) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]post els srq,get srqe failed, valid wqe num 0x%x, pi 0x%x, pmsn 0x%x",
			     srq_info->valid_wqe_num, srq_info->pi,
			     srq_info->pmsn);

		spin_unlock(&srq_info->srq_spin_lock);
		return;
	}

	/* Initialize RQE */
	/* cs section is not used */
	memset(&tmp_rqe, 0, sizeof(struct spfc_rqe));

	/* default Obit is invalid, and set valid finally */
	spfc_build_srq_wqe_ctrls(&tmp_rqe, !srq_info->pi_owner, srq_info->pmsn + 1);

	tmp_rqe.bds_sl.buf_addr_hi = SPFC_HIGH_32_BITS(buff_entry->buff_dma);
	tmp_rqe.bds_sl.buf_addr_lo = SPFC_LOW_32_BITS(buff_entry->buff_dma);
	tmp_rqe.drv_sl.wd0.user_id = buf_id;

	/* convert to big endian */
	spfc_cpu_to_big32(&tmp_rqe, sizeof(struct spfc_rqe));

	memcpy(rqe, &tmp_rqe, sizeof(struct spfc_rqe));

	/* reset Obit */
	spfc_set_srq_wqe_owner_be((struct spfc_wqe_ctrl *)(void *)(&rqe->ctrl_sl),
				  srq_info->pi_owner);

	if (linked_rqe) {
		/* Update Obit in linked WQE */
		spfc_set_srq_link_wqe_owner_be((struct spfc_linkwqe *)(void *)linked_rqe,
					       srq_info->pi_owner, srq_info->pmsn + 1);
	}

	/* Update PI and PMSN */
	spfc_update_producer_info((u16)(srq_info->valid_wqe_num),
				  &srq_info->pi, &srq_info->pi_owner);

	/* pmsn is 16bit. The value is added to the maximum value and is
	 * automatically reversed
	 */
	srq_info->pmsn++;

	/* Update pmsn in queue header */
	wq_header = (struct wq_header *)(void *)srq_info->cqm_srq_info->q_header_vaddr;
	spfc_update_srq_header(&wq_header->db_record, srq_info->pmsn);

	spin_unlock(&srq_info->srq_spin_lock);
}

/*
 *Function Name       : spfc_cfg_srq_ctx
 *Function Description: Initialize the CTX of the SRQ that receives the
 *					   immediate data. The RQE of the SRQ
 *					   needs to be
 *initialized when the RQE is filled. Input Parameters    : *srq_info, *srq_ctx,
 *					   sge_size,
 *					   rqe_gpa
 *Output Parameters   : N/A
 *Return Type         : void
 */
static void spfc_cfg_srq_ctx(struct spfc_srq_info *srq_info,
			     struct spfc_srq_ctx *ctx, u32 sge_size,
			     u64 rqe_gpa)
{
	struct spfc_srq_ctx *srq_ctx = NULL;
	struct cqm_queue *cqm_srq_info = NULL;
	struct spfc_queue_info_bus queue_bus;

	FC_CHECK_RETURN_VOID(srq_info);
	FC_CHECK_RETURN_VOID(ctx);

	cqm_srq_info = srq_info->cqm_srq_info;
	srq_ctx = ctx;
	srq_ctx->last_rq_pmsn = 0;
	srq_ctx->cur_rqe_msn = 0;
	srq_ctx->pcie_template = 0;
	/* The value of CTX needs to be updated
	 *when RQE is configured
	 */
	srq_ctx->cur_rqe_gpa = rqe_gpa;
	srq_ctx->cur_sge_v = 0;
	srq_ctx->cur_sge_l = 0;
	/* The information received by the SRQ is reported through the
	 *SCQ. The interrupt and ArmCQ are disabled.
	 */
	srq_ctx->int_mode = 0;
	srq_ctx->ceqn_msix = 0;
	srq_ctx->cur_sge_remain_len = 0;
	srq_ctx->cur_sge_id = 0;
	srq_ctx->consant_sge_len = sge_size;
	srq_ctx->cur_wqe_o = 0;
	srq_ctx->pmsn_type = SPFC_PMSN_CI_TYPE_FROM_HOST;
	srq_ctx->bdsl = 0;
	srq_ctx->cr = 0;
	srq_ctx->csl = 0;
	srq_ctx->cf = 0;
	srq_ctx->ctrl_sl = 0;
	srq_ctx->cur_sge_gpa = 0;
	srq_ctx->cur_pmsn_gpa = cqm_srq_info->q_header_paddr;
	srq_ctx->prefetch_max_masn = 0;
	srq_ctx->cqe_max_cnt = 0;
	srq_ctx->cur_cqe_cnt = 0;
	srq_ctx->arm_q = 0;
	srq_ctx->cq_so_ro = 0;
	srq_ctx->cqe_dma_attr_idx = 0;
	srq_ctx->rq_so_ro = 0;
	srq_ctx->rqe_dma_attr_idx = 0;
	srq_ctx->loop_o = SPFC_SRQ_INIT_LOOP_O;
	srq_ctx->ring = SPFC_QUEUE_RING;

	memset(&queue_bus, 0, sizeof(struct spfc_queue_info_bus));
	queue_bus.bus[ARRAY_INDEX_0] |= ((u64)(cqm_srq_info->q_ctx_paddr >> UNF_SHIFT_4));
	queue_bus.bus[ARRAY_INDEX_0] |= (((u64)(srq_ctx->rqe_dma_attr_idx &
						SPFC_SRQ_CTX_rqe_dma_attr_idx_MASK))
						<< UNF_SHIFT_60); /* bits 4 */

	queue_bus.bus[ARRAY_INDEX_1] |= ((u64)(srq_ctx->rqe_dma_attr_idx >> UNF_SHIFT_4));
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(srq_ctx->rq_so_ro)) << UNF_SHIFT_2); /* bits 2 */
	queue_bus.bus[ARRAY_INDEX_1] |= (((u64)(srq_ctx->cur_pmsn_gpa >> UNF_SHIFT_4))
					 << UNF_SHIFT_4); /* bits 60 */

	queue_bus.bus[ARRAY_INDEX_2] |= ((u64)(srq_ctx->consant_sge_len)); /* bits 17 */
	queue_bus.bus[ARRAY_INDEX_2] |= (((u64)(srq_ctx->pcie_template)) << UNF_SHIFT_17);

	srq_ctx->parity = spfc_get_parity_value((void *)queue_bus.bus, SPFC_SRQC_BUS_ROW,
						SPFC_SRQC_BUS_COL);

	spfc_cpu_to_big64((void *)srq_ctx, sizeof(struct spfc_srq_ctx));
}

static u32 spfc_creat_srqc_via_cmdq_sync(struct spfc_hba_info *hba,
					 struct spfc_srq_ctx *srqc,
					 u64 ctx_gpa)
{
#define SPFC_INIT_SRQC_TIMEOUT 3000

	int ret;
	u32 covrt_size;
	struct spfc_cmdqe_creat_srqc init_srq_cmd;
	struct sphw_cmd_buf *cmdq_in_buf;

	cmdq_in_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmdq_in_buf) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]cmdq in_cmd_buf alloc failed");

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_INIT_SRQC);
		return UNF_RETURN_ERROR;
	}

	memset(&init_srq_cmd, 0, sizeof(init_srq_cmd));
	init_srq_cmd.wd0.task_type = SPFC_TASK_T_INIT_SRQC;
	init_srq_cmd.srqc_gpa_h = SPFC_HIGH_32_BITS(ctx_gpa);
	init_srq_cmd.srqc_gpa_l = SPFC_LOW_32_BITS(ctx_gpa);
	covrt_size = sizeof(init_srq_cmd) - sizeof(init_srq_cmd.srqc);
	spfc_cpu_to_big32(&init_srq_cmd, covrt_size);

	/* srqc is already big-endian */
	memcpy(init_srq_cmd.srqc, srqc, sizeof(*srqc));
	memcpy(cmdq_in_buf->buf, &init_srq_cmd, sizeof(init_srq_cmd));
	cmdq_in_buf->size = sizeof(init_srq_cmd);

	ret = sphw_cmdq_detail_resp(hba->dev_handle, COMM_MOD_FC, 0,
				    cmdq_in_buf, NULL, NULL,
				    SPFC_INIT_SRQC_TIMEOUT, SPHW_CHANNEL_FC);

	sphw_free_cmd_buf(hba->dev_handle, cmdq_in_buf);

	if (ret) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Send creat srqc via cmdq failed, ret=%d",
			     ret);

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_INIT_SRQC);
		return UNF_RETURN_ERROR;
	}

	SPFC_IO_STAT(hba, SPFC_TASK_T_INIT_SRQC);

	return RETURN_OK;
}

static void spfc_init_els_srq_wqe(struct spfc_srq_info *srq_info)
{
	u32 rqe_index = 0;
	struct spfc_drq_buff_entry *buf_entry = NULL;

	FC_CHECK_RETURN_VOID(srq_info);

	for (rqe_index = 0; rqe_index < srq_info->valid_wqe_num - 1; rqe_index++) {
		buf_entry = srq_info->els_buff_entry_head + rqe_index;
		spfc_post_els_srq_wqe(srq_info, buf_entry->buff_id);
	}
}

static void spfc_free_els_srq_buff(struct spfc_hba_info *hba, u32 srq_valid_wqe)
{
	u32 buff_index = 0;
	struct spfc_srq_info *srq_info = NULL;
	struct spfc_drq_buff_entry *buff_entry = NULL;

	FC_CHECK_RETURN_VOID(hba);

	srq_info = &hba->els_srq_info;

	if (!srq_info->els_buff_entry_head)
		return;

	for (buff_index = 0; buff_index < srq_valid_wqe; buff_index++) {
		buff_entry = &srq_info->els_buff_entry_head[buff_index];
		buff_entry->buff_addr = NULL;
	}

	if (srq_info->buf_list.buflist) {
		for (buff_index = 0; buff_index < srq_info->buf_list.buf_num;
		     buff_index++) {
			if (srq_info->buf_list.buflist[buff_index].paddr != 0) {
				pci_unmap_single(hba->pci_dev,
						 srq_info->buf_list.buflist[buff_index].paddr,
						 srq_info->buf_list.buf_size,
						 DMA_FROM_DEVICE);
				srq_info->buf_list.buflist[buff_index].paddr = 0;
			}
			kfree(srq_info->buf_list.buflist[buff_index].vaddr);
			srq_info->buf_list.buflist[buff_index].vaddr = NULL;
		}

		kfree(srq_info->buf_list.buflist);
		srq_info->buf_list.buflist = NULL;
	}

	kfree(srq_info->els_buff_entry_head);
	srq_info->els_buff_entry_head = NULL;
}

static u32 spfc_alloc_els_srq_buff(struct spfc_hba_info *hba, u32 srq_valid_wqe)
{
	u32 req_buff_size = 0;
	u32 buff_index = 0;
	struct spfc_srq_info *srq_info = NULL;
	struct spfc_drq_buff_entry *buff_entry = NULL;
	u32 buf_total_size;
	u32 buf_num;
	u32 alloc_idx;
	u32 cur_buf_idx = 0;
	u32 cur_buf_offset = 0;
	u32 buf_cnt_perhugebuf;

	srq_info = &hba->els_srq_info;

	/* Apply for entry buffer */
	req_buff_size = (u32)(srq_valid_wqe * sizeof(struct spfc_drq_buff_entry));
	srq_info->els_buff_entry_head = (struct spfc_drq_buff_entry *)kmalloc(req_buff_size,
									      GFP_KERNEL);
	if (!srq_info->els_buff_entry_head) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate ELS Srq receive buffer entries failed");

		return UNF_RETURN_ERROR;
	}
	memset(srq_info->els_buff_entry_head, 0, req_buff_size);

	buf_total_size = SPFC_SRQ_ELS_SGE_LEN * srq_valid_wqe;

	srq_info->buf_list.buf_size = buf_total_size > BUF_LIST_PAGE_SIZE
					  ? BUF_LIST_PAGE_SIZE
					  : buf_total_size;
	buf_cnt_perhugebuf = srq_info->buf_list.buf_size / SPFC_SRQ_ELS_SGE_LEN;
	buf_num = srq_valid_wqe % buf_cnt_perhugebuf ?
			srq_valid_wqe / buf_cnt_perhugebuf + 1 :
			srq_valid_wqe / buf_cnt_perhugebuf;
	srq_info->buf_list.buflist = (struct buff_list *)kmalloc(buf_num * sizeof(struct buff_list),
								 GFP_KERNEL);
	srq_info->buf_list.buf_num = buf_num;

	if (!srq_info->buf_list.buflist) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate ELS buf list failed out of memory");
		goto free_buff;
	}
	memset(srq_info->buf_list.buflist, 0, buf_num * sizeof(struct buff_list));

	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		srq_info->buf_list.buflist[alloc_idx].vaddr = kmalloc(srq_info->buf_list.buf_size,
								      GFP_KERNEL);
		if (!srq_info->buf_list.buflist[alloc_idx].vaddr)
			goto free_buff;

		memset(srq_info->buf_list.buflist[alloc_idx].vaddr, 0, srq_info->buf_list.buf_size);

		srq_info->buf_list.buflist[alloc_idx].paddr =
		    pci_map_single(hba->pci_dev, srq_info->buf_list.buflist[alloc_idx].vaddr,
				   srq_info->buf_list.buf_size, DMA_FROM_DEVICE);
		if (pci_dma_mapping_error(hba->pci_dev,
					  srq_info->buf_list.buflist[alloc_idx].paddr)) {
			srq_info->buf_list.buflist[alloc_idx].paddr = 0;
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[err]Map els srq buffer failed");

			goto free_buff;
		}
	}

	/* Apply for receiving buffer and attach it to the free linked list */
	for (buff_index = 0; buff_index < srq_valid_wqe; buff_index++) {
		buff_entry = &srq_info->els_buff_entry_head[buff_index];
		cur_buf_idx = buff_index / buf_cnt_perhugebuf;
		cur_buf_offset = SPFC_SRQ_ELS_SGE_LEN * (buff_index % buf_cnt_perhugebuf);
		buff_entry->buff_addr = srq_info->buf_list.buflist[cur_buf_idx].vaddr +
					cur_buf_offset;
		buff_entry->buff_dma = srq_info->buf_list.buflist[cur_buf_idx].paddr +
					cur_buf_offset;
		buff_entry->buff_id = (u16)buff_index;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[EVENT]Allocate bufnum:%u,buf_total_size:%u", buf_num,
		     buf_total_size);

	return RETURN_OK;

free_buff:
	spfc_free_els_srq_buff(hba, srq_valid_wqe);
	return UNF_RETURN_ERROR;
}

void spfc_send_clear_srq_cmd(struct spfc_hba_info *hba,
			     struct spfc_srq_info *srq_info)
{
	union spfc_cmdqe cmdqe;
	struct cqm_queue *cqm_fcp_srq = NULL;
	ulong flag = 0;

	memset(&cmdqe, 0, sizeof(union spfc_cmdqe));

	spin_lock_irqsave(&srq_info->srq_spin_lock, flag);
	cqm_fcp_srq = srq_info->cqm_srq_info;
	if (!cqm_fcp_srq) {
		srq_info->state = SPFC_CLEAN_DONE;
		spin_unlock_irqrestore(&srq_info->srq_spin_lock, flag);
		return;
	}

	cmdqe.clear_srq.wd0.task_type = SPFC_TASK_T_CLEAR_SRQ;
	cmdqe.clear_srq.wd1.scqn = SPFC_LSW(hba->default_scqn);
	cmdqe.clear_srq.wd1.srq_type = srq_info->srq_type;
	cmdqe.clear_srq.srqc_gpa_h = SPFC_HIGH_32_BITS(cqm_fcp_srq->q_ctx_paddr);
	cmdqe.clear_srq.srqc_gpa_l = SPFC_LOW_32_BITS(cqm_fcp_srq->q_ctx_paddr);

	(void)queue_delayed_work(hba->work_queue, &srq_info->del_work,
					 (ulong)msecs_to_jiffies(SPFC_SRQ_DEL_STAGE_TIMEOUT_MS));
	spin_unlock_irqrestore(&srq_info->srq_spin_lock, flag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port 0x%x begin to clear srq 0x%x(0x%x,0x%llx)",
		     hba->port_cfg.port_id, srq_info->srq_type,
		     SPFC_LSW(hba->default_scqn),
		     (u64)cqm_fcp_srq->q_ctx_paddr);

	/* Run the ROOT CMDQ command to issue the clear srq command. If the
	 * command fails to be delivered, retry upon timeout.
	 */
	(void)spfc_root_cmdq_enqueue(hba, &cmdqe, sizeof(cmdqe.clear_srq));
}

/*
 *Function Name       : spfc_srq_clr_timeout
 *Function Description: Delete srq when timeout.
 *Input Parameters    : *work
 *Output Parameters   : N/A
 *Return Type         : void
 */
static void spfc_srq_clr_timeout(struct work_struct *work)
{
#define SPFC_MAX_DEL_SRQ_RETRY_TIMES 2
	struct spfc_srq_info *srq = NULL;
	struct spfc_hba_info *hba = NULL;
	struct cqm_queue *cqm_fcp_imm_srq = NULL;
	ulong flag = 0;

	srq = container_of(work, struct spfc_srq_info, del_work.work);

	spin_lock_irqsave(&srq->srq_spin_lock, flag);
	hba = srq->hba;
	cqm_fcp_imm_srq = srq->cqm_srq_info;
	spin_unlock_irqrestore(&srq->srq_spin_lock, flag);

	if (hba && cqm_fcp_imm_srq) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port 0x%x clear srq 0x%x stat 0x%x timeout",
			     hba->port_cfg.port_id, srq->srq_type, srq->state);

		/* If the delivery fails or the execution times out after the
		 * delivery, try again once
		 */
		srq->del_retry_time++;
		if (srq->del_retry_time < SPFC_MAX_DEL_SRQ_RETRY_TIMES)
			spfc_send_clear_srq_cmd(hba, srq);
		else
			srq->del_retry_time = 0;
	}
}

static u32 spfc_create_els_srq(struct spfc_hba_info *hba)
{
	u32 ret = UNF_RETURN_ERROR;
	struct cqm_queue *cqm_srq = NULL;
	struct wq_header *wq_header = NULL;
	struct spfc_srq_info *srq_info = NULL;
	struct spfc_srq_ctx srq_ctx = {0};

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	cqm_srq = cqm3_object_fc_srq_create(hba->dev_handle, SERVICE_T_FC,
					    CQM_OBJECT_NONRDMA_SRQ, SPFC_SRQ_ELS_DATA_DEPTH,
					    SPFC_SRQE_SIZE, hba);
	if (!cqm_srq) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Create Els Srq failed");

		return UNF_RETURN_ERROR;
	}

	/* Initialize SRQ */
	srq_info = &hba->els_srq_info;
	spfc_init_srq_info(hba, cqm_srq, srq_info);
	srq_info->srq_type = SPFC_SRQ_ELS;
	srq_info->enable = true;
	srq_info->state = SPFC_CLEAN_DONE;
	srq_info->del_retry_time = 0;

	/* The srq lock is initialized and can be created repeatedly */
	spin_lock_init(&srq_info->srq_spin_lock);
	srq_info->spin_lock_init = true;

	/* Initialize queue header */
	wq_header = (struct wq_header *)(void *)cqm_srq->q_header_vaddr;
	spfc_init_srq_header(wq_header);
	INIT_DELAYED_WORK(&srq_info->del_work, spfc_srq_clr_timeout);

	/* Apply for RQ buffer */
	ret = spfc_alloc_els_srq_buff(hba, srq_info->valid_wqe_num);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate Els Srq buffer failed");

		cqm3_object_delete(&cqm_srq->object);
		memset(srq_info, 0, sizeof(struct spfc_srq_info));
		return UNF_RETURN_ERROR;
	}

	/* Fill RQE, update queue header */
	spfc_init_els_srq_wqe(srq_info);

	/* Fill SRQ CTX */
	memset(&srq_ctx, 0, sizeof(srq_ctx));
	spfc_cfg_srq_ctx(srq_info, &srq_ctx, SPFC_SRQ_ELS_SGE_LEN,
			 srq_info->cqm_srq_info->q_room_buf_1.buf_list->pa);

	ret = spfc_creat_srqc_via_cmdq_sync(hba, &srq_ctx, srq_info->cqm_srq_info->q_ctx_paddr);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Creat Els Srqc failed");

		spfc_free_els_srq_buff(hba, srq_info->valid_wqe_num);
		cqm3_object_delete(&cqm_srq->object);
		memset(srq_info, 0, sizeof(struct spfc_srq_info));

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

void spfc_wq_destroy_els_srq(struct work_struct *work)
{
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID(work);
	hba =
	    container_of(work, struct spfc_hba_info, els_srq_clear_work);
	spfc_destroy_els_srq(hba);
}

void spfc_destroy_els_srq(void *handle)
{
	/*
	 * Receive clear els srq sts
	 * ---then--->>> destroy els srq
	 */
	struct spfc_srq_info *srq_info = NULL;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID(handle);

	hba = (struct spfc_hba_info *)handle;
	srq_info = &hba->els_srq_info;

	/* release receive buffer */
	spfc_free_els_srq_buff(hba, srq_info->valid_wqe_num);

	/* release srq info */
	if (srq_info->cqm_srq_info) {
		cqm3_object_delete(&srq_info->cqm_srq_info->object);
		srq_info->cqm_srq_info = NULL;
	}
	if (srq_info->spin_lock_init)
		srq_info->spin_lock_init = false;
	srq_info->hba = NULL;
	srq_info->enable = false;
	srq_info->state = SPFC_CLEAN_DONE;
}

/*
 *Function Name       : spfc_create_srq
 *Function Description: Create SRQ, which contains four SRQ for receiving
 *					   instant data and a SRQ for receiving
 *					   ELS data.
 *Input Parameters    : *hba Output Parameters   : N/A Return Type :u32
 */
static u32 spfc_create_srq(struct spfc_hba_info *hba)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	/* Create ELS SRQ */
	ret = spfc_create_els_srq(hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Create Els Srq failed");
		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

/*
 *Function Name       : spfc_destroy_srq
 *Function Description: Release the SRQ resource, including the SRQ for
 *					   receiving the immediate data and the
 *					   SRQ forreceiving the ELS data.
 *Input Parameters    : *hba Output Parameters   : N/A
 *Return Type         : void
 */
static void spfc_destroy_srq(struct spfc_hba_info *hba)
{
	FC_CHECK_RETURN_VOID(hba);

	spfc_destroy_els_srq(hba);
}

u32 spfc_create_common_share_queues(void *handle)
{
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	hba = (struct spfc_hba_info *)handle;
	/* Create & Init 8 pairs SCQ */
	ret = spfc_create_scq(hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Create scq failed");

		return UNF_RETURN_ERROR;
	}

	/* Alloc SRQ resource for SIRT & ELS */
	ret = spfc_create_srq(hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Create srq failed");

		spfc_flush_scq_ctx(hba);
		spfc_destroy_scq(hba);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

void spfc_destroy_common_share_queues(void *hba)
{
	FC_CHECK_RETURN_VOID(hba);

	spfc_destroy_scq((struct spfc_hba_info *)hba);
	spfc_destroy_srq((struct spfc_hba_info *)hba);
}

static u8 spfc_map_fcp_data_cos(struct spfc_hba_info *hba)
{
	u8 i = 0;
	u8 min_cnt_index = SPFC_PACKET_COS_FC_DATA;
	bool get_init_index = false;

	for (i = 0; i < SPFC_MAX_COS_NUM; i++) {
		/* Check whether the CoS is valid for the FC and cannot be
		 * occupied by the CMD
		 */
		if ((!(hba->cos_bitmap & ((u32)1 << i))) || i == SPFC_PACKET_COS_FC_CMD)
			continue;

		if (!get_init_index) {
			min_cnt_index = i;
			get_init_index = true;
			continue;
		}

		if (atomic_read(&hba->cos_rport_cnt[i]) <
		    atomic_read(&hba->cos_rport_cnt[min_cnt_index]))
			min_cnt_index = i;
	}

	atomic_inc(&hba->cos_rport_cnt[min_cnt_index]);

	return min_cnt_index;
}

static void spfc_update_cos_rport_cnt(struct spfc_hba_info *hba, u8 cos_index)
{
	if (cos_index >= SPFC_MAX_COS_NUM ||
	    cos_index == SPFC_PACKET_COS_FC_CMD ||
	    (!(hba->cos_bitmap & ((u32)1 << cos_index))) ||
	    (atomic_read(&hba->cos_rport_cnt[cos_index]) == 0))
		return;

	atomic_dec(&hba->cos_rport_cnt[cos_index]);
}

void spfc_invalid_parent_sq(struct spfc_parent_sq_info *sq_info)
{
	sq_info->rport_index = INVALID_VALUE32;
	sq_info->context_id = INVALID_VALUE32;
	sq_info->sq_queue_id = INVALID_VALUE32;
	sq_info->cache_id = INVALID_VALUE32;
	sq_info->local_port_id = INVALID_VALUE32;
	sq_info->remote_port_id = INVALID_VALUE32;
	sq_info->hba = NULL;
	sq_info->del_start_jiff = INVALID_VALUE64;
	sq_info->port_in_flush = false;
	sq_info->sq_in_sess_rst = false;
	sq_info->oqid_rd = INVALID_VALUE16;
	sq_info->oqid_wr = INVALID_VALUE16;
	sq_info->srq_ctx_addr = 0;
	sq_info->sqn_base = 0;
	atomic_set(&sq_info->sq_cached, false);
	sq_info->vport_id = 0;
	sq_info->sirt_dif_control.protect_opcode = UNF_DIF_ACTION_NONE;
	sq_info->need_offloaded = INVALID_VALUE8;
	atomic_set(&sq_info->sq_valid, false);
	atomic_set(&sq_info->flush_done_wait_cnt, 0);
	memset(&sq_info->delay_sqe, 0, sizeof(struct spfc_delay_sqe_ctrl_info));
	memset(sq_info->io_stat, 0, sizeof(sq_info->io_stat));
}

static void spfc_parent_sq_opreate_timeout(struct work_struct *work)
{
	ulong flag = 0;
	struct spfc_parent_sq_info *parent_sq = NULL;
	struct spfc_parent_queue_info *parent_queue = NULL;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID(work);

	parent_sq = container_of(work, struct spfc_parent_sq_info, del_work.work);
	parent_queue = container_of(parent_sq, struct spfc_parent_queue_info, parent_sq_info);
	hba = (struct spfc_hba_info *)parent_sq->hba;
	FC_CHECK_RETURN_VOID(hba);

	spin_lock_irqsave(&parent_queue->parent_queue_state_lock, flag);
	if (parent_queue->offload_state == SPFC_QUEUE_STATE_DESTROYING) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "Port(0x%x) sq rport index(0x%x) local nportid(0x%x),remote nportid(0x%x) reset timeout.",
			     hba->port_cfg.port_id, parent_sq->rport_index,
			     parent_sq->local_port_id,
			     parent_sq->remote_port_id);
	}
	spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock, flag);
}

static void spfc_parent_sq_wait_flush_done_timeout(struct work_struct *work)
{
	ulong flag = 0;
	struct spfc_parent_sq_info *parent_sq = NULL;
	struct spfc_parent_queue_info *parent_queue = NULL;
	struct spfc_hba_info *hba = NULL;
	u32 ctx_flush_done;
	u32 *ctx_dw = NULL;
	int ret;
	int sq_state = SPFC_STAT_PARENT_SQ_QUEUE_DELAYED_WORK;
	spinlock_t *prtq_state_lock = NULL;

	FC_CHECK_RETURN_VOID(work);

	parent_sq = container_of(work, struct spfc_parent_sq_info, flush_done_timeout_work.work);

	FC_CHECK_RETURN_VOID(parent_sq);

	parent_queue = container_of(parent_sq, struct spfc_parent_queue_info, parent_sq_info);
	prtq_state_lock = &parent_queue->parent_queue_state_lock;
	hba = (struct spfc_hba_info *)parent_sq->hba;
	FC_CHECK_RETURN_VOID(hba);
	FC_CHECK_RETURN_VOID(parent_queue);

	spin_lock_irqsave(prtq_state_lock, flag);
	if (parent_queue->offload_state != SPFC_QUEUE_STATE_DESTROYING) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) sq rport index(0x%x) is not destroying status,offloadsts is %d",
			     hba->port_cfg.port_id, parent_sq->rport_index,
			     parent_queue->offload_state);
		spin_unlock_irqrestore(prtq_state_lock, flag);
		return;
	}

	if (parent_queue->parent_ctx.cqm_parent_ctx_obj) {
		ctx_dw = (u32 *)((void *)(parent_queue->parent_ctx.cqm_parent_ctx_obj->vaddr));
		ctx_flush_done = ctx_dw[SPFC_CTXT_FLUSH_DONE_DW_POS] & SPFC_CTXT_FLUSH_DONE_MASK_BE;
		if (ctx_flush_done == 0) {
			spin_unlock_irqrestore(prtq_state_lock, flag);

			if (atomic_read(&parent_queue->parent_sq_info.flush_done_wait_cnt) <
			    SPFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_CNT) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[info]Port(0x%x) sq rport index(0x%x) wait flush done timeout %d times",
					     hba->port_cfg.port_id, parent_sq->rport_index,
					     atomic_read(&(parent_queue->parent_sq_info
							.flush_done_wait_cnt)));

				atomic_inc(&parent_queue->parent_sq_info.flush_done_wait_cnt);

				/* Delay Free Sq info */
				ret = queue_delayed_work(hba->work_queue,
							 &(parent_queue->parent_sq_info
							 .flush_done_timeout_work),
							 (ulong)msecs_to_jiffies((u32)
							 SPFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_MS));
				if (!ret) {
					FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
						     "[err]Port(0x%x) rport(0x%x) queue delayed work failed ret:%d",
						     hba->port_cfg.port_id,
						     parent_sq->rport_index, ret);
					SPFC_HBA_STAT(hba, sq_state);
				}

				return;
			}
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) sq rport index(0x%x) has wait flush done %d times,do not free sq",
				     hba->port_cfg.port_id,
				     parent_sq->rport_index,
				     atomic_read(&(parent_queue->parent_sq_info
						.flush_done_wait_cnt)));

			SPFC_HBA_STAT(hba, SPFC_STAT_CTXT_FLUSH_DONE);
			return;
		}
	}

	spin_unlock_irqrestore(prtq_state_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) sq rport index(0x%x) flush done bit is ok,free sq now",
		     hba->port_cfg.port_id, parent_sq->rport_index);

	spfc_free_parent_queue_info(hba, parent_queue);
}

static void spfc_free_parent_sq(struct spfc_hba_info *hba,
				struct spfc_parent_queue_info *parq_info)
{
#define SPFC_WAIT_PRT_CTX_FUSH_DONE_LOOP_TIMES 100
	u32 ctx_flush_done = 0;
	u32 *ctx_dw = NULL;
	struct spfc_parent_sq_info *sq_info = NULL;
	u32 uidelaycnt = 0;
	struct list_head *list = NULL;
	struct spfc_suspend_sqe_info *suspend_sqe = NULL;
	ulong flag = 0;

	sq_info = &parq_info->parent_sq_info;

	spin_lock_irqsave(&parq_info->parent_queue_state_lock, flag);
	while (!list_empty(&sq_info->suspend_sqe_list)) {
		list = UNF_OS_LIST_NEXT(&sq_info->suspend_sqe_list);
		list_del(list);
		suspend_sqe = list_entry(list, struct spfc_suspend_sqe_info, list_sqe_entry);
		if (suspend_sqe) {
			if (!cancel_delayed_work(&suspend_sqe->timeout_work)) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
					     "[warn]reset worker timer maybe timeout");
			}

			kfree(suspend_sqe);
		}
	}
	spin_unlock_irqrestore(&parq_info->parent_queue_state_lock, flag);

	/* Free data cos */
	spfc_update_cos_rport_cnt(hba, parq_info->queue_data_cos);

	if (parq_info->parent_ctx.cqm_parent_ctx_obj) {
		ctx_dw = (u32 *)((void *)(parq_info->parent_ctx.cqm_parent_ctx_obj->vaddr));
		ctx_flush_done = ctx_dw[SPFC_CTXT_FLUSH_DONE_DW_POS] & SPFC_CTXT_FLUSH_DONE_MASK_BE;
		mb();
		if (parq_info->offload_state == SPFC_QUEUE_STATE_DESTROYING &&
		    ctx_flush_done == 0) {
			do {
				ctx_flush_done = ctx_dw[SPFC_CTXT_FLUSH_DONE_DW_POS] &
						 SPFC_CTXT_FLUSH_DONE_MASK_BE;
				mb();
				if (ctx_flush_done != 0)
					break;
				uidelaycnt++;
			} while (uidelaycnt < SPFC_WAIT_PRT_CTX_FUSH_DONE_LOOP_TIMES);

			if (ctx_flush_done == 0) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
					     "[warn]Port(0x%x) Rport(0x%x) flush done is not set",
					     hba->port_cfg.port_id,
					     sq_info->rport_index);
			}
		}

		cqm3_object_delete(&parq_info->parent_ctx.cqm_parent_ctx_obj->object);
		parq_info->parent_ctx.cqm_parent_ctx_obj = NULL;
	}

	spfc_invalid_parent_sq(sq_info);
}

u32 spfc_alloc_parent_sq(struct spfc_hba_info *hba,
			 struct spfc_parent_queue_info *parq_info,
			 struct unf_port_info *rport_info)
{
	struct spfc_parent_sq_info *sq_ctrl = NULL;
	struct cqm_qpc_mpt *prnt_ctx = NULL;
	ulong flag = 0;

	/* Craete parent context via CQM */
	prnt_ctx = cqm3_object_qpc_mpt_create(hba->dev_handle, SERVICE_T_FC,
					      CQM_OBJECT_SERVICE_CTX, SPFC_CNTX_SIZE_256B,
					      parq_info, CQM_INDEX_INVALID);
	if (!prnt_ctx) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Create parent context failed, CQM_INDEX is 0x%x",
			     CQM_INDEX_INVALID);
		goto parent_create_fail;
	}

	parq_info->parent_ctx.cqm_parent_ctx_obj = prnt_ctx;
	/* Initialize struct spfc_parent_sq_info */
	sq_ctrl = &parq_info->parent_sq_info;
	sq_ctrl->hba = (void *)hba;
	sq_ctrl->rport_index = rport_info->rport_index;
	sq_ctrl->sqn_base = rport_info->sqn_base;
	sq_ctrl->context_id = prnt_ctx->xid;
	sq_ctrl->sq_queue_id = SPFC_QID_SQ;
	sq_ctrl->cache_id = INVALID_VALUE32;
	sq_ctrl->local_port_id = INVALID_VALUE32;
	sq_ctrl->remote_port_id = INVALID_VALUE32;
	sq_ctrl->sq_in_sess_rst = false;
	atomic_set(&sq_ctrl->sq_valid, true);
	sq_ctrl->del_start_jiff = INVALID_VALUE64;
	sq_ctrl->service_type = SPFC_SERVICE_TYPE_FC;
	sq_ctrl->vport_id = (u8)rport_info->qos_level;
	sq_ctrl->cs_ctrl = (u8)rport_info->cs_ctrl;
	sq_ctrl->sirt_dif_control.protect_opcode = UNF_DIF_ACTION_NONE;
	sq_ctrl->need_offloaded = INVALID_VALUE8;
	atomic_set(&sq_ctrl->flush_done_wait_cnt, 0);

	/* Check whether the HBA is in the Linkdown state. Note that
	 * offload_state must be in the non-FREE state.
	 */
	spin_lock_irqsave(&hba->flush_state_lock, flag);
	sq_ctrl->port_in_flush = hba->in_flushing;
	spin_unlock_irqrestore(&hba->flush_state_lock, flag);
	memset(sq_ctrl->io_stat, 0, sizeof(sq_ctrl->io_stat));

	INIT_DELAYED_WORK(&sq_ctrl->del_work, spfc_parent_sq_opreate_timeout);
	INIT_DELAYED_WORK(&sq_ctrl->flush_done_timeout_work,
			  spfc_parent_sq_wait_flush_done_timeout);
	INIT_LIST_HEAD(&sq_ctrl->suspend_sqe_list);

	memset(&sq_ctrl->delay_sqe, 0, sizeof(struct spfc_delay_sqe_ctrl_info));

	return RETURN_OK;

parent_create_fail:
	parq_info->parent_ctx.cqm_parent_ctx_obj = NULL;

	return UNF_RETURN_ERROR;
}

static void
spfc_init_prnt_ctxt_scq_qinfo(void *hba,
			      struct spfc_parent_queue_info *prnt_qinfo)
{
	u32 resp_scqn = 0;
	struct spfc_parent_context *ctx = NULL;
	struct spfc_scq_qinfo *resp_prnt_scq_ctxt = NULL;
	struct spfc_queue_info_bus queue_bus;

	/* Obtains the queue id of the scq returned by the CQM when the SCQ is
	 * created
	 */
	resp_scqn = prnt_qinfo->parent_sts_scq_info.cqm_queue_id;

	/* Obtains the Parent Context address */
	ctx = (struct spfc_parent_context *)(prnt_qinfo->parent_ctx.parent_ctx);

	resp_prnt_scq_ctxt = &ctx->resp_scq_qinfo;
	resp_prnt_scq_ctxt->hw_scqc_config.info.rq_th2_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.rq_th1_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.rq_th0_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.rq_min_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.sq_th2_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.sq_th1_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.sq_th0_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.sq_min_preld_cache_num = wqe_pre_load;
	resp_prnt_scq_ctxt->hw_scqc_config.info.scq_n = (u64)resp_scqn;
	resp_prnt_scq_ctxt->hw_scqc_config.info.parity = 0;

	memset(&queue_bus, 0, sizeof(struct spfc_queue_info_bus));
	queue_bus.bus[ARRAY_INDEX_0] = resp_prnt_scq_ctxt->hw_scqc_config.pctxt_val1;
	resp_prnt_scq_ctxt->hw_scqc_config.info.parity = spfc_get_parity_value(queue_bus.bus,
									       SPFC_HW_SCQC_BUS_ROW,
									       SPFC_HW_SCQC_BUS_COL
									       );
	spfc_cpu_to_big64(resp_prnt_scq_ctxt, sizeof(struct spfc_scq_qinfo));
}

static void
spfc_init_prnt_ctxt_srq_qinfo(void *handle, struct spfc_parent_queue_info *prnt_qinfo)
{
	struct spfc_parent_context *ctx = NULL;
	struct cqm_queue *cqm_els_srq = NULL;
	struct spfc_parent_sq_info *sq = NULL;
	struct spfc_queue_info_bus queue_bus;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	/* Obtains the SQ address */
	sq = &prnt_qinfo->parent_sq_info;

	/* Obtains the Parent Context address */
	ctx = (struct spfc_parent_context *)(prnt_qinfo->parent_ctx.parent_ctx);

	cqm_els_srq = hba->els_srq_info.cqm_srq_info;

	/* Initialize the Parent SRQ INFO used when the ELS is received */
	ctx->els_srq_info.srqc_gpa = cqm_els_srq->q_ctx_paddr >> UNF_SHIFT_4;

	memset(&queue_bus, 0, sizeof(struct spfc_queue_info_bus));
	queue_bus.bus[ARRAY_INDEX_0] = ctx->els_srq_info.srqc_gpa;
	ctx->els_srq_info.parity = spfc_get_parity_value(queue_bus.bus, SPFC_HW_SRQC_BUS_ROW,
							 SPFC_HW_SRQC_BUS_COL);
	spfc_cpu_to_big64(&ctx->els_srq_info, sizeof(struct spfc_srq_qinfo));

	ctx->imm_srq_info.srqc_gpa = 0;
	sq->srq_ctx_addr = 0;
}

static u16 spfc_get_max_sequence_id(void)
{
	return SPFC_HRQI_SEQ_ID_MAX;
}

static void spfc_init_prnt_rsvd_qinfo(struct spfc_parent_queue_info *prnt_qinfo)
{
	struct spfc_parent_context *ctx = NULL;
	struct spfc_hw_rsvd_queue *hw_rsvd_qinfo = NULL;
	u16 max_seq = 0;
	u32 each = 0, seq_index = 0;

	/* Obtains the Parent Context address */
	ctx = (struct spfc_parent_context *)(prnt_qinfo->parent_ctx.parent_ctx);
	hw_rsvd_qinfo = (struct spfc_hw_rsvd_queue *)&ctx->hw_rsvdq;
	memset(hw_rsvd_qinfo->seq_id_bitmap, 0, sizeof(hw_rsvd_qinfo->seq_id_bitmap));

	max_seq = spfc_get_max_sequence_id();

	/* special set for sequence id 0, which is always kept by ucode for
	 * sending fcp-cmd
	 */
	hw_rsvd_qinfo->seq_id_bitmap[SPFC_HRQI_SEQ_SEPCIAL_ID] = 1;
	seq_index = SPFC_HRQI_SEQ_SEPCIAL_ID - (max_seq >> SPFC_HRQI_SEQ_INDEX_SHIFT);

	/* Set the unavailable mask to start from max + 1 */
	for (each = (max_seq % SPFC_HRQI_SEQ_INDEX_MAX) + 1;
	     each < SPFC_HRQI_SEQ_INDEX_MAX; each++) {
		hw_rsvd_qinfo->seq_id_bitmap[seq_index] |= ((u64)0x1) << each;
	}

	hw_rsvd_qinfo->seq_id_bitmap[seq_index] =
				cpu_to_be64(hw_rsvd_qinfo->seq_id_bitmap[seq_index]);

	/* sepcial set for sequence id 0 */
	if (seq_index != SPFC_HRQI_SEQ_SEPCIAL_ID)
		hw_rsvd_qinfo->seq_id_bitmap[SPFC_HRQI_SEQ_SEPCIAL_ID] =
		    cpu_to_be64(hw_rsvd_qinfo->seq_id_bitmap[SPFC_HRQI_SEQ_SEPCIAL_ID]);

	for (each = 0; each < seq_index; each++)
		hw_rsvd_qinfo->seq_id_bitmap[each] = SPFC_HRQI_SEQ_INVALID_ID;

	/* no matter what the range of seq id, last_req_seq_id is fixed value
	 * 0xff
	 */
	hw_rsvd_qinfo->wd0.last_req_seq_id = SPFC_HRQI_SEQ_ID_MAX;
	hw_rsvd_qinfo->wd0.xid = prnt_qinfo->parent_sq_info.context_id;

	*(u64 *)&hw_rsvd_qinfo->wd0 =
	    cpu_to_be64(*(u64 *)&hw_rsvd_qinfo->wd0);
}

/*
 *Function Name       : spfc_init_prnt_sw_section_info
 *Function Description: Initialize the SW Section area that can be accessed by
 *					   the Parent Context uCode.
 *Input Parameters    : *hba,
 *		       *prnt_qinfo
 *Output Parameters   : N/A
 *Return Type         : void
 */
static void spfc_init_prnt_sw_section_info(struct spfc_hba_info *hba,
					   struct spfc_parent_queue_info *prnt_qinfo)
{
#define SPFC_VLAN_ENABLE (1)
#define SPFC_MB_PER_KB 1024
	u16 rport_index;
	struct spfc_parent_context *ctx = NULL;
	struct spfc_sw_section *sw_setion = NULL;
	u16 total_scq_num = SPFC_TOTAL_SCQ_NUM;
	u32 queue_id;
	dma_addr_t queue_hdr_paddr;

	/* Obtains the Parent Context address */
	ctx = (struct spfc_parent_context *)(prnt_qinfo->parent_ctx.parent_ctx);
	sw_setion = &ctx->sw_section;

	/* xid+vPortId */
	sw_setion->sw_ctxt_vport_xid.xid = prnt_qinfo->parent_sq_info.context_id;
	spfc_cpu_to_big32(&sw_setion->sw_ctxt_vport_xid, sizeof(sw_setion->sw_ctxt_vport_xid));

	/* conn_id */
	rport_index = SPFC_LSW(prnt_qinfo->parent_sq_info.rport_index);
	sw_setion->conn_id = cpu_to_be16(rport_index);

	/* Immediate parameters */
	sw_setion->immi_rq_page_size = 0;

	/* Parent SCQ INFO used for sending packets to the Cmnd */
	sw_setion->scq_num_rcv_cmd = cpu_to_be16((u16)prnt_qinfo->parent_cmd_scq_info.cqm_queue_id);
	sw_setion->scq_num_max_scqn = cpu_to_be16(total_scq_num);

	/* sw_ctxt_misc */
	sw_setion->sw_ctxt_misc.dw.srv_type = prnt_qinfo->parent_sq_info.service_type;
	sw_setion->sw_ctxt_misc.dw.port_id = hba->port_index;

	/* only the VN2VF mode is supported */
	sw_setion->sw_ctxt_misc.dw.vlan_id = 0;
	spfc_cpu_to_big32(&sw_setion->sw_ctxt_misc.pctxt_val0,
			  sizeof(sw_setion->sw_ctxt_misc.pctxt_val0));

	/* Configuring the combo length */
	sw_setion->per_xmit_data_size = cpu_to_be32(combo_length * SPFC_MB_PER_KB);
	sw_setion->sw_ctxt_config.dw.work_mode = SPFC_PORT_MODE_INI;
	sw_setion->sw_ctxt_config.dw.status = FC_PARENT_STATUS_INVALID;
	sw_setion->sw_ctxt_config.dw.cos = 0;
	sw_setion->sw_ctxt_config.dw.oq_cos_cmd = SPFC_PACKET_COS_FC_CMD;
	sw_setion->sw_ctxt_config.dw.oq_cos_data = prnt_qinfo->queue_data_cos;
	sw_setion->sw_ctxt_config.dw.priority = 0;
	sw_setion->sw_ctxt_config.dw.vlan_enable = SPFC_VLAN_ENABLE;
	sw_setion->sw_ctxt_config.dw.sgl_num = dif_sgl_mode;
	spfc_cpu_to_big32(&sw_setion->sw_ctxt_config.pctxt_val1,
			  sizeof(sw_setion->sw_ctxt_config.pctxt_val1));
	spfc_cpu_to_big32(&sw_setion->immi_dif_info, sizeof(sw_setion->immi_dif_info));

	queue_id = prnt_qinfo->parent_cmd_scq_info.local_queue_id;
	queue_hdr_paddr = hba->scq_info[queue_id].cqm_scq_info->q_header_paddr;
	sw_setion->cmd_scq_gpa_h = SPFC_HIGH_32_BITS(queue_hdr_paddr);
	sw_setion->cmd_scq_gpa_l = SPFC_LOW_32_BITS(queue_hdr_paddr);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Port(0x%x) RPort(0x%x) CmdLocalScqn(0x%x) QheaderGpaH(0x%x) QheaderGpaL(0x%x)",
		     hba->port_cfg.port_id, prnt_qinfo->parent_sq_info.rport_index, queue_id,
		     sw_setion->cmd_scq_gpa_h, sw_setion->cmd_scq_gpa_l);

	spfc_cpu_to_big32(&sw_setion->cmd_scq_gpa_h, sizeof(sw_setion->cmd_scq_gpa_h));
	spfc_cpu_to_big32(&sw_setion->cmd_scq_gpa_l, sizeof(sw_setion->cmd_scq_gpa_l));
}

static void spfc_init_parent_context(void *hba, struct spfc_parent_queue_info *prnt_qinfo)
{
	struct spfc_parent_context *ctx = NULL;

	ctx = (struct spfc_parent_context *)(prnt_qinfo->parent_ctx.parent_ctx);

	/* Initialize Parent Context */
	memset(ctx, 0, SPFC_CNTX_SIZE_256B);

	/* Initialize the Queue Info hardware area */
	spfc_init_prnt_ctxt_scq_qinfo(hba, prnt_qinfo);
	spfc_init_prnt_ctxt_srq_qinfo(hba, prnt_qinfo);
	spfc_init_prnt_rsvd_qinfo(prnt_qinfo);

	/* Initialize Software Section */
	spfc_init_prnt_sw_section_info(hba, prnt_qinfo);
}

void spfc_map_shared_queue_qid(struct spfc_hba_info *hba,
			       struct spfc_parent_queue_info *parent_queue_info,
			       u32 rport_index)
{
	u32 cmd_scqn_local = 0;
	u32 sts_scqn_local = 0;

	/* The SCQ is used for each connection based on the balanced *
	 * distribution of commands and responses
	 */
	cmd_scqn_local = SPFC_RPORTID_TO_CMD_SCQN(rport_index);
	sts_scqn_local = SPFC_RPORTID_TO_STS_SCQN(rport_index);
	parent_queue_info->parent_cmd_scq_info.local_queue_id = cmd_scqn_local;
	parent_queue_info->parent_sts_scq_info.local_queue_id = sts_scqn_local;
	parent_queue_info->parent_cmd_scq_info.cqm_queue_id =
	    hba->scq_info[cmd_scqn_local].scqn;
	parent_queue_info->parent_sts_scq_info.cqm_queue_id =
	    hba->scq_info[sts_scqn_local].scqn;

	/* Each session share with immediate SRQ and ElsSRQ */
	parent_queue_info->parent_els_srq_info.local_queue_id = 0;
	parent_queue_info->parent_els_srq_info.cqm_queue_id = hba->els_srq_info.srqn;

	/* Allocate fcp data cos value */
	parent_queue_info->queue_data_cos = spfc_map_fcp_data_cos(hba);

	/* Allocate Parent SQ vPort */
	parent_queue_info->parent_sq_info.vport_id += parent_queue_info->queue_vport_id;
}

u32 spfc_send_session_enable(struct spfc_hba_info *hba, struct unf_port_info *rport_info)
{
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	dma_addr_t ctx_phy_addr = 0;
	void *ctx_addr = NULL;
	union spfc_cmdqe session_enable;
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_parent_context *ctx = NULL;
	struct spfc_sw_section *sw_setion = NULL;
	struct spfc_host_keys key;
	u32 tx_mfs = 2048;
	u32 edtov_timer = 2000;
	ulong flag = 0;
	spinlock_t *prtq_state_lock = NULL;
	u32 index;

	memset(&session_enable, 0, sizeof(union spfc_cmdqe));
	memset(&key, 0, sizeof(struct spfc_host_keys));
	index = rport_info->rport_index;
	parent_queue_info = &hba->parent_queue_mgr->parent_queue[index];
	prtq_state_lock = &parent_queue_info->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flag);

	ctx = (struct spfc_parent_context *)(parent_queue_info->parent_ctx.parent_ctx);
	sw_setion = &ctx->sw_section;

	sw_setion->tx_mfs = cpu_to_be16((u16)(tx_mfs));
	sw_setion->e_d_tov_timer_val = cpu_to_be32(edtov_timer);

	spfc_big_to_cpu32(&sw_setion->sw_ctxt_misc.pctxt_val0,
			  sizeof(sw_setion->sw_ctxt_misc.pctxt_val0));
	sw_setion->sw_ctxt_misc.dw.port_id = SPFC_GET_NETWORK_PORT_ID(hba);
	spfc_cpu_to_big32(&sw_setion->sw_ctxt_misc.pctxt_val0,
			  sizeof(sw_setion->sw_ctxt_misc.pctxt_val0));

	spfc_big_to_cpu32(&sw_setion->sw_ctxt_config.pctxt_val1,
			  sizeof(sw_setion->sw_ctxt_config.pctxt_val1));
	spfc_cpu_to_big32(&sw_setion->sw_ctxt_config.pctxt_val1,
			  sizeof(sw_setion->sw_ctxt_config.pctxt_val1));

	parent_queue_info->parent_sq_info.rport_index = rport_info->rport_index;
	parent_queue_info->parent_sq_info.local_port_id = rport_info->local_nport_id;
	parent_queue_info->parent_sq_info.remote_port_id = rport_info->nport_id;
	parent_queue_info->parent_sq_info.context_id =
	    parent_queue_info->parent_ctx.cqm_parent_ctx_obj->xid;

	/* Fill in contex to the chip */
	ctx_phy_addr = parent_queue_info->parent_ctx.cqm_parent_ctx_obj->paddr;
	ctx_addr = parent_queue_info->parent_ctx.cqm_parent_ctx_obj->vaddr;
	memcpy(ctx_addr, parent_queue_info->parent_ctx.parent_ctx,
	       sizeof(struct spfc_parent_context));
	session_enable.session_enable.wd0.task_type = SPFC_TASK_T_SESS_EN;
	session_enable.session_enable.wd2.conn_id = rport_info->rport_index;
	session_enable.session_enable.wd2.scqn = hba->default_scqn;
	session_enable.session_enable.wd3.xid_p =
	    parent_queue_info->parent_ctx.cqm_parent_ctx_obj->xid;
	session_enable.session_enable.context_gpa_hi = SPFC_HIGH_32_BITS(ctx_phy_addr);
	session_enable.session_enable.context_gpa_lo = SPFC_LOW_32_BITS(ctx_phy_addr);

	spin_unlock_irqrestore(prtq_state_lock, flag);

	key.wd3.sid_2 = (rport_info->local_nport_id & SPFC_KEY_WD3_SID_2_MASK) >>  UNF_SHIFT_16;
	key.wd3.sid_1 = (rport_info->local_nport_id & SPFC_KEY_WD3_SID_1_MASK) >> UNF_SHIFT_8;
	key.wd4.sid_0 = rport_info->local_nport_id & SPFC_KEY_WD3_SID_0_MASK;
	key.wd4.did_0 = rport_info->nport_id & SPFC_KEY_WD4_DID_0_MASK;
	key.wd4.did_1 = (rport_info->nport_id & SPFC_KEY_WD4_DID_1_MASK) >> UNF_SHIFT_8;
	key.wd4.did_2 = (rport_info->nport_id & SPFC_KEY_WD4_DID_2_MASK) >> UNF_SHIFT_16;
	key.wd5.host_id = 0;
	key.wd5.port_id = hba->port_index;

	memcpy(&session_enable.session_enable.keys, &key, sizeof(struct spfc_host_keys));

	memcpy((void *)(uintptr_t)session_enable.session_enable.context,
	       parent_queue_info->parent_ctx.parent_ctx,
	       sizeof(struct spfc_parent_context));
	spfc_big_to_cpu32((void *)(uintptr_t)session_enable.session_enable.context,
			  sizeof(struct spfc_parent_context));

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,
		     "[info] xid:0x%x, sid:0x%x,did:0x%x parentcontext:",
		     parent_queue_info->parent_ctx.cqm_parent_ctx_obj->xid,
		     rport_info->local_nport_id, rport_info->nport_id);

	ret = spfc_root_cmdq_enqueue(hba, &session_enable, sizeof(session_enable.session_enable));
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]RootCMDQEnqueue Error, free default session parent resource");
		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) send default session enable success,rport index(0x%x),context id(0x%x) SID=(0x%x), DID=(0x%x)",
		     hba->port_cfg.port_id, rport_info->rport_index,
		     parent_queue_info->parent_sq_info.context_id,
		     rport_info->local_nport_id, rport_info->nport_id);

	return RETURN_OK;
}

u32 spfc_alloc_parent_resource(void *handle, struct unf_port_info *rport_info)
{
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_hba_info *hba = NULL;
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	ulong flag = 0;
	spinlock_t *prtq_state_lock = NULL;
	u32 index;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport_info, UNF_RETURN_ERROR);

	hba = (struct spfc_hba_info *)handle;
	if (!hba->parent_queue_mgr) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) cannot find parent queue pool",
			     hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	index = rport_info->rport_index;
	if (index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) allocate parent resource failed, invlaid rport index(0x%x),rport nportid(0x%x)",
			     hba->port_cfg.port_id, index,
			     rport_info->nport_id);

		return UNF_RETURN_ERROR;
	}

	parent_queue_info = &hba->parent_queue_mgr->parent_queue[index];
	prtq_state_lock = &parent_queue_info->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flag);

	if (parent_queue_info->offload_state != SPFC_QUEUE_STATE_FREE) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) allocate parent resource failed, invlaid rport index(0x%x),rport nportid(0x%x), offload state(0x%x)",
			     hba->port_cfg.port_id, index, rport_info->nport_id,
			     parent_queue_info->offload_state);

		spin_unlock_irqrestore(prtq_state_lock, flag);
		return UNF_RETURN_ERROR;
	}

	parent_queue_info->offload_state = SPFC_QUEUE_STATE_INITIALIZED;
	/* Create Parent Context and Link List SQ */
	ret = spfc_alloc_parent_sq(hba, parent_queue_info, rport_info);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "Port(0x%x) alloc session resoure failed.rport index(0x%x),rport nportid(0x%x).",
			     hba->port_cfg.port_id, index,
			     rport_info->nport_id);

		parent_queue_info->offload_state = SPFC_QUEUE_STATE_FREE;
		spfc_invalid_parent_sq(&parent_queue_info->parent_sq_info);
		spin_unlock_irqrestore(prtq_state_lock, flag);

		return UNF_RETURN_ERROR;
	}

	/* Allocate the corresponding queue xid to each parent */
	spfc_map_shared_queue_qid(hba, parent_queue_info, rport_info->rport_index);

	/* Initialize Parent Context, including hardware area and ucode area */
	spfc_init_parent_context(hba, parent_queue_info);

	spin_unlock_irqrestore(prtq_state_lock, flag);

	/* Only default enable session obviously, other will enable secertly */
	if (unlikely(rport_info->rport_index == SPFC_DEFAULT_RPORT_INDEX))
		return spfc_send_session_enable(handle, rport_info);

	parent_queue_info->parent_sq_info.local_port_id = rport_info->local_nport_id;
	parent_queue_info->parent_sq_info.remote_port_id = rport_info->nport_id;
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) allocate parent sq success,rport index(0x%x),rport nportid(0x%x),context id(0x%x)",
		     hba->port_cfg.port_id, rport_info->rport_index,
		     rport_info->nport_id,
		     parent_queue_info->parent_sq_info.context_id);

	return ret;
}

u32 spfc_free_parent_resource(void *handle, struct unf_port_info *rport_info)
{
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	ulong flag = 0;
	ulong rst_flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	enum spfc_session_reset_mode mode = SPFC_SESS_RST_DELETE_IO_CONN_BOTH;
	struct spfc_hba_info *hba = NULL;
	spinlock_t *prtq_state_lock = NULL;
	spinlock_t *sq_enq_lock = NULL;
	u32 index;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(rport_info, UNF_RETURN_ERROR);

	hba = (struct spfc_hba_info *)handle;
	if (!hba->parent_queue_mgr) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Port(0x%x) cannot find parent queue pool",
			     hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	/* get parent queue info (by rport index) */
	if (rport_info->rport_index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Port(0x%x) free parent resource failed, invlaid rport_index(%u) rport_nport_id(0x%x)",
			     hba->port_cfg.port_id, rport_info->rport_index, rport_info->nport_id);

		return UNF_RETURN_ERROR;
	}

	index = rport_info->rport_index;
	parent_queue_info = &hba->parent_queue_mgr->parent_queue[index];
	prtq_state_lock = &parent_queue_info->parent_queue_state_lock;
	sq_enq_lock = &parent_queue_info->parent_sq_info.parent_sq_enqueue_lock;

	spin_lock_irqsave(prtq_state_lock, flag);
	/* 1. for has been offload */
	if (parent_queue_info->offload_state == SPFC_QUEUE_STATE_OFFLOADED) {
		parent_queue_info->offload_state = SPFC_QUEUE_STATE_DESTROYING;
		spin_unlock_irqrestore(prtq_state_lock, flag);

		/* set reset state, in order to prevent I/O in_SQ */
		spin_lock_irqsave(sq_enq_lock, rst_flag);
		parent_queue_info->parent_sq_info.sq_in_sess_rst = true;
		spin_unlock_irqrestore(sq_enq_lock, rst_flag);

		/* check pcie device state */
		if (!hba->dev_present) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port(0x%x) hba is not present, free  directly. rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
				     hba->port_cfg.port_id, rport_info->rport_index,
				     parent_queue_info->parent_sq_info.rport_index,
				     parent_queue_info->parent_sq_info.local_port_id,
				     rport_info->nport_id,
				     parent_queue_info->parent_sq_info.remote_port_id);

			spfc_free_parent_queue_info(hba, parent_queue_info);
			return RETURN_OK;
		}

		parent_queue_info->parent_sq_info.del_start_jiff = jiffies;
		(void)queue_delayed_work(hba->work_queue,
						 &parent_queue_info->parent_sq_info.del_work,
						 (ulong)msecs_to_jiffies((u32)
						 SPFC_SQ_DEL_STAGE_TIMEOUT_MS));

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) begin to reset parent session, rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			     hba->port_cfg.port_id, rport_info->rport_index,
			     parent_queue_info->parent_sq_info.rport_index,
			     parent_queue_info->parent_sq_info.local_port_id,
			     rport_info->nport_id,
			     parent_queue_info->parent_sq_info.remote_port_id);
		/* Forcibly set both mode */
		mode = SPFC_SESS_RST_DELETE_IO_CONN_BOTH;
		ret = spfc_send_session_rst_cmd(hba, parent_queue_info, mode);

		return ret;
	} else if (parent_queue_info->offload_state == SPFC_QUEUE_STATE_INITIALIZED) {
		/* 2. for resource has been alloc, but not offload */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) parent sq is not offloaded, free directly. rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			     hba->port_cfg.port_id, rport_info->rport_index,
			     parent_queue_info->parent_sq_info.rport_index,
			     parent_queue_info->parent_sq_info.local_port_id,
			     rport_info->nport_id,
			     parent_queue_info->parent_sq_info.remote_port_id);

		spin_unlock_irqrestore(prtq_state_lock, flag);
		spfc_free_parent_queue_info(hba, parent_queue_info);

		return RETURN_OK;
	} else if (parent_queue_info->offload_state ==
		   SPFC_QUEUE_STATE_OFFLOADING) {
		/* 3. for driver has offloading CMND to uCode */
		spfc_push_destroy_parent_queue_sqe(hba, parent_queue_info, rport_info);
		spin_unlock_irqrestore(prtq_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) parent sq is offloading, push to delay free. rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
			     hba->port_cfg.port_id, rport_info->rport_index,
			     parent_queue_info->parent_sq_info.rport_index,
			     parent_queue_info->parent_sq_info.local_port_id,
			     rport_info->nport_id,
			     parent_queue_info->parent_sq_info.remote_port_id);

		return RETURN_OK;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
		     "[warn]Port(0x%x) parent sq is not created, do not need free state(0x%x) rport_index(0x%x:0x%x) local_nportid(0x%x) remote_nportid(0x%x:0x%x)",
		     hba->port_cfg.port_id, parent_queue_info->offload_state,
		     rport_info->rport_index,
		     parent_queue_info->parent_sq_info.rport_index,
		     parent_queue_info->parent_sq_info.local_port_id,
		     rport_info->nport_id,
		     parent_queue_info->parent_sq_info.remote_port_id);

	spin_unlock_irqrestore(prtq_state_lock, flag);

	return RETURN_OK;
}

void spfc_free_parent_queue_mgr(void *handle)
{
	u32 index = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID(handle);

	hba = (struct spfc_hba_info *)handle;
	if (!hba->parent_queue_mgr)
		return;
	parent_queue_mgr = hba->parent_queue_mgr;

	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		if (parent_queue_mgr->parent_queue[index].parent_ctx.parent_ctx)
			parent_queue_mgr->parent_queue[index].parent_ctx.parent_ctx = NULL;
	}

	if (parent_queue_mgr->parent_sq_buf_list.buflist) {
		for (index = 0; index < parent_queue_mgr->parent_sq_buf_list.buf_num; index++) {
			if (parent_queue_mgr->parent_sq_buf_list.buflist[index].paddr != 0) {
				pci_unmap_single(hba->pci_dev,
						 parent_queue_mgr->parent_sq_buf_list
						 .buflist[index].paddr,
						 parent_queue_mgr->parent_sq_buf_list.buf_size,
						 DMA_BIDIRECTIONAL);
				parent_queue_mgr->parent_sq_buf_list.buflist[index].paddr = 0;
			}
			kfree(parent_queue_mgr->parent_sq_buf_list.buflist[index].vaddr);
			parent_queue_mgr->parent_sq_buf_list.buflist[index].vaddr = NULL;
		}

		kfree(parent_queue_mgr->parent_sq_buf_list.buflist);
		parent_queue_mgr->parent_sq_buf_list.buflist = NULL;
	}

	vfree(parent_queue_mgr);
	hba->parent_queue_mgr = NULL;
}

void spfc_free_parent_queues(void *handle)
{
	u32 index = 0;
	ulong flag = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	struct spfc_hba_info *hba = NULL;
	spinlock_t *prtq_state_lock = NULL;

	FC_CHECK_RETURN_VOID(handle);

	hba = (struct spfc_hba_info *)handle;
	parent_queue_mgr = hba->parent_queue_mgr;

	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		prtq_state_lock = &parent_queue_mgr->parent_queue[index].parent_queue_state_lock;
		spin_lock_irqsave(prtq_state_lock, flag);

		if (SPFC_QUEUE_STATE_DESTROYING ==
		    parent_queue_mgr->parent_queue[index].offload_state) {
			spin_unlock_irqrestore(prtq_state_lock, flag);

			(void)cancel_delayed_work_sync(&parent_queue_mgr->parent_queue[index]
							.parent_sq_info.del_work);
			(void)cancel_delayed_work_sync(&parent_queue_mgr->parent_queue[index]
							.parent_sq_info.flush_done_timeout_work);

			/* free parent queue */
			spfc_free_parent_queue_info(hba, &parent_queue_mgr->parent_queue[index]);
			continue;
		}

		spin_unlock_irqrestore(prtq_state_lock, flag);
	}
}

/*
 *Function Name       : spfc_alloc_parent_queue_mgr
 *Function Description: Allocate and initialize parent queue manager.
 *Input Parameters    : *handle
 *Output Parameters   : N/A
 *Return Type         : void
 */
u32 spfc_alloc_parent_queue_mgr(void *handle)
{
	u32 index = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	u32 buf_total_size;
	u32 buf_num;
	u32 alloc_idx;
	u32 cur_buf_idx = 0;
	u32 cur_buf_offset = 0;
	u32 prt_ctx_size = sizeof(struct spfc_parent_context);
	u32 buf_cnt_perhugebuf;
	struct spfc_hba_info *hba = NULL;
	u32 init_val = INVALID_VALUE32;
	dma_addr_t paddr;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);

	hba = (struct spfc_hba_info *)handle;
	parent_queue_mgr = (struct spfc_parent_queue_mgr *)vmalloc(sizeof
								   (struct spfc_parent_queue_mgr));
	if (!parent_queue_mgr) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) cannot allocate queue manager",
			     hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	hba->parent_queue_mgr = parent_queue_mgr;
	memset(parent_queue_mgr, 0, sizeof(struct spfc_parent_queue_mgr));

	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		spin_lock_init(&parent_queue_mgr->parent_queue[index].parent_queue_state_lock);
		parent_queue_mgr->parent_queue[index].offload_state = SPFC_QUEUE_STATE_FREE;
		spin_lock_init(&(parent_queue_mgr->parent_queue[index]
			       .parent_sq_info.parent_sq_enqueue_lock));
		parent_queue_mgr->parent_queue[index].parent_cmd_scq_info.cqm_queue_id = init_val;
		parent_queue_mgr->parent_queue[index].parent_sts_scq_info.cqm_queue_id = init_val;
		parent_queue_mgr->parent_queue[index].parent_els_srq_info.cqm_queue_id = init_val;
		parent_queue_mgr->parent_queue[index].parent_sq_info.del_start_jiff = init_val;
		parent_queue_mgr->parent_queue[index].queue_vport_id = hba->vpid_start;
	}

	buf_total_size = prt_ctx_size * UNF_SPFC_MAXRPORT_NUM;
	parent_queue_mgr->parent_sq_buf_list.buf_size = buf_total_size > BUF_LIST_PAGE_SIZE ?
							BUF_LIST_PAGE_SIZE : buf_total_size;
	buf_cnt_perhugebuf = parent_queue_mgr->parent_sq_buf_list.buf_size / prt_ctx_size;
	buf_num = UNF_SPFC_MAXRPORT_NUM % buf_cnt_perhugebuf ?
		  UNF_SPFC_MAXRPORT_NUM / buf_cnt_perhugebuf + 1 :
		  UNF_SPFC_MAXRPORT_NUM / buf_cnt_perhugebuf;
	parent_queue_mgr->parent_sq_buf_list.buflist =
	    (struct buff_list *)kmalloc(buf_num * sizeof(struct buff_list), GFP_KERNEL);
	parent_queue_mgr->parent_sq_buf_list.buf_num = buf_num;

	if (!parent_queue_mgr->parent_sq_buf_list.buflist) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Allocate QueuMgr buf list failed out of memory");
		goto free_parent_queue;
	}
	memset(parent_queue_mgr->parent_sq_buf_list.buflist, 0, buf_num * sizeof(struct buff_list));

	for (alloc_idx = 0; alloc_idx < buf_num; alloc_idx++) {
		parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr =
			kmalloc(parent_queue_mgr->parent_sq_buf_list.buf_size, GFP_KERNEL);
		if (!parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr)
			goto free_parent_queue;

		memset(parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr, 0,
		       parent_queue_mgr->parent_sq_buf_list.buf_size);

		parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].paddr =
		    pci_map_single(hba->pci_dev,
				   parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].vaddr,
				   parent_queue_mgr->parent_sq_buf_list.buf_size,
				   DMA_BIDIRECTIONAL);
		paddr = parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].paddr;
		if (pci_dma_mapping_error(hba->pci_dev, paddr)) {
			parent_queue_mgr->parent_sq_buf_list.buflist[alloc_idx].paddr = 0;
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[err]Map QueuMgr address failed");

			goto free_parent_queue;
		}
	}

	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		cur_buf_idx = index / buf_cnt_perhugebuf;
		cur_buf_offset = prt_ctx_size * (index % buf_cnt_perhugebuf);

		parent_queue_mgr->parent_queue[index].parent_ctx.parent_ctx =
		    parent_queue_mgr->parent_sq_buf_list.buflist[cur_buf_idx].vaddr +
		    cur_buf_offset;
		parent_queue_mgr->parent_queue[index].parent_ctx.parent_ctx_addr =
		    parent_queue_mgr->parent_sq_buf_list.buflist[cur_buf_idx].paddr +
		    cur_buf_offset;
	}
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[EVENT]Allocate bufnum:%u,buf_total_size:%u", buf_num, buf_total_size);

	return RETURN_OK;

free_parent_queue:
	spfc_free_parent_queue_mgr(hba);
	return UNF_RETURN_ERROR;
}

static void spfc_rlease_all_wqe_pages(struct spfc_hba_info *hba)
{
	u32 index;
	struct spfc_wqe_page *wpg = NULL;

	FC_CHECK_RETURN_VOID((hba));

	wpg = hba->sq_wpg_pool.wpg_pool_addr;

	for (index = 0; index < hba->sq_wpg_pool.wpg_cnt; index++) {
		if (wpg->wpg_addr) {
			dma_pool_free(hba->sq_wpg_pool.wpg_dma_pool,
				      wpg->wpg_addr, wpg->wpg_phy_addr);
			wpg->wpg_addr = NULL;
			wpg->wpg_phy_addr = 0;
		}

		wpg++;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port[%u] free total %u wqepages", hba->port_index,
		     index);
}

u32 spfc_alloc_parent_sq_wqe_page_pool(void *handle)
{
	u32 index = 0;
	struct spfc_sq_wqepage_pool *wpg_pool = NULL;
	struct spfc_wqe_page *wpg = NULL;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	wpg_pool = &hba->sq_wpg_pool;

	INIT_LIST_HEAD(&wpg_pool->list_free_wpg_pool);
	spin_lock_init(&wpg_pool->wpg_pool_lock);
	atomic_set(&wpg_pool->wpg_in_use, 0);

	/* Calculate the number of Wqe Page required in the pool */
	wpg_pool->wpg_size = wqe_page_size;
	wpg_pool->wpg_cnt = SPFC_MIN_WP_NUM * SPFC_MAX_SSQ_NUM +
			    ((hba->exi_count * SPFC_SQE_SIZE) / wpg_pool->wpg_size);
	wpg_pool->wqe_per_wpg = wpg_pool->wpg_size / SPFC_SQE_SIZE;

	/* Craete DMA POOL */
	wpg_pool->wpg_dma_pool = dma_pool_create("spfc_wpg_pool",
						 &hba->pci_dev->dev,
						 wpg_pool->wpg_size,
						 SPFC_SQE_SIZE, 0);
	if (!wpg_pool->wpg_dma_pool) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Cannot allocate SQ WqePage DMA pool");

		goto out_create_dma_pool_err;
	}

	/* Allocate arrays to record all WqePage addresses */
	wpg_pool->wpg_pool_addr = (struct spfc_wqe_page *)vmalloc(wpg_pool->wpg_cnt *
								  sizeof(struct spfc_wqe_page));
	if (!wpg_pool->wpg_pool_addr) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Allocate SQ WqePageAddr array failed");

		goto out_alloc_wpg_array_err;
	}
	wpg = wpg_pool->wpg_pool_addr;
	memset(wpg, 0, wpg_pool->wpg_cnt * sizeof(struct spfc_wqe_page));

	for (index = 0; index < wpg_pool->wpg_cnt; index++) {
		wpg->wpg_addr = dma_pool_alloc(wpg_pool->wpg_dma_pool, GFP_KERNEL,
					       (u64 *)&wpg->wpg_phy_addr);
		if (!wpg->wpg_addr) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_ERR, "[err]Dma pool allocated failed");
			break;
		}

		/* To ensure security, clear the memory */
		memset(wpg->wpg_addr, 0, wpg_pool->wpg_size);

		/* Add to the idle linked list */
		INIT_LIST_HEAD(&wpg->entry_wpg);
		list_add_tail(&wpg->entry_wpg, &wpg_pool->list_free_wpg_pool);

		wpg++;
	}
	/* ALL allocated successfully */
	if (wpg_pool->wpg_cnt == index)
		return RETURN_OK;

	spfc_rlease_all_wqe_pages(hba);
	vfree(wpg_pool->wpg_pool_addr);
	wpg_pool->wpg_pool_addr = NULL;

out_alloc_wpg_array_err:
	dma_pool_destroy(wpg_pool->wpg_dma_pool);
	wpg_pool->wpg_dma_pool = NULL;

out_create_dma_pool_err:
	return UNF_RETURN_ERROR;
}

void spfc_free_parent_sq_wqe_page_pool(void *handle)
{
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID((handle));
	hba = (struct spfc_hba_info *)handle;
	spfc_rlease_all_wqe_pages(hba);
	hba->sq_wpg_pool.wpg_cnt = 0;

	if (hba->sq_wpg_pool.wpg_pool_addr) {
		vfree(hba->sq_wpg_pool.wpg_pool_addr);
		hba->sq_wpg_pool.wpg_pool_addr = NULL;
	}

	dma_pool_destroy(hba->sq_wpg_pool.wpg_dma_pool);
	hba->sq_wpg_pool.wpg_dma_pool = NULL;
}

static u32 spfc_parent_sq_ring_direct_wqe_doorbell(struct spfc_parent_ssq_info *sq, u8 *direct_wqe)
{
	u32 ret = RETURN_OK;
	int ravl;
	u16 pmsn;
	u64 queue_hdr_db_val;
	struct spfc_hba_info *hba;

	hba = (struct spfc_hba_info *)sq->hba;
	pmsn = sq->last_pmsn;

	if (sq->cache_id == INVALID_VALUE32) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]SQ(0x%x) invalid cid", sq->context_id);
		return RETURN_ERROR;
	}
	/* Fill Doorbell Record */
	queue_hdr_db_val = sq->queue_header->door_bell_record;
	queue_hdr_db_val &= (u64)(~(0xFFFFFFFF));
	queue_hdr_db_val |= (u64)((u64)pmsn << UNF_SHIFT_16 | pmsn);
	sq->queue_header->door_bell_record =
	    cpu_to_be64(queue_hdr_db_val);

	ravl = cqm_ring_direct_wqe_db_fc(hba->dev_handle, SERVICE_T_FC, direct_wqe);
	if (unlikely(ravl != CQM_SUCCESS)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]SQ(0x%x) send DB failed", sq->context_id);

		ret = RETURN_ERROR;
	}

	atomic_inc(&sq->sq_db_cnt);

	return ret;
}

u32 spfc_parent_sq_ring_doorbell(struct spfc_parent_ssq_info *sq, u8 qos_level, u32 c)
{
	u32 ret = RETURN_OK;
	int ravl;
	u16 pmsn;
	u8 pmsn_lo;
	u8 pmsn_hi;
	u64 db_val_qw;
	struct spfc_hba_info *hba;
	struct spfc_parent_sq_db door_bell;

	hba = (struct spfc_hba_info *)sq->hba;
	pmsn = sq->last_pmsn;
	/* Obtain the low 8 Bit of PMSN */
	pmsn_lo = (u8)(pmsn & SPFC_PMSN_MASK);
	/* Obtain the high 8 Bit of PMSN */
	pmsn_hi = (u8)((pmsn >> UNF_SHIFT_8) & SPFC_PMSN_MASK);
	door_bell.wd0.service_type = SPFC_LSW(sq->service_type);
	door_bell.wd0.cos = 0;
	/* c = 0 data type, c = 1 control type, two type are different in mqm */
	door_bell.wd0.c = c;
	door_bell.wd0.arm = SPFC_DB_ARM_DISABLE;
	door_bell.wd0.cntx_size = SPFC_CNTX_SIZE_T_256B;
	door_bell.wd0.xid = sq->context_id;
	door_bell.wd1.sm_data = sq->cache_id;
	door_bell.wd1.qid = sq->sq_queue_id;
	door_bell.wd1.pi_hi = (u32)pmsn_hi;

	if (sq->cache_id == INVALID_VALUE32) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]SQ(0x%x) invalid cid", sq->context_id);
		return UNF_RETURN_ERROR;
	}
	/* Fill Doorbell Record */
	db_val_qw = sq->queue_header->door_bell_record;
	db_val_qw &= (u64)(~(SPFC_DB_VAL_MASK));
	db_val_qw |= (u64)((u64)pmsn << UNF_SHIFT_16 | pmsn);
	sq->queue_header->door_bell_record = cpu_to_be64(db_val_qw);

	/* ring doorbell */
	db_val_qw = *(u64 *)&door_bell;
	ravl = cqm3_ring_hardware_db_fc(hba->dev_handle, SERVICE_T_FC, pmsn_lo,
					(qos_level & SPFC_QOS_LEVEL_MASK),
					db_val_qw);
	if (unlikely(ravl != CQM_SUCCESS)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]SQ(0x%x) send DB(0x%llx) failed",
			     sq->context_id, db_val_qw);

		ret = UNF_RETURN_ERROR;
	}

	/* Doorbell success counter */
	atomic_inc(&sq->sq_db_cnt);

	return ret;
}

u32 spfc_direct_sq_enqueue(struct spfc_parent_ssq_info *ssq, struct spfc_sqe *io_sqe, u8 wqe_type)
{
	u32 ret = RETURN_OK;
	u32 msn_wd = INVALID_VALUE32;
	u16 link_wqe_msn = 0;
	ulong flag = 0;
	struct spfc_wqe_page *tail_wpg = NULL;
	struct spfc_sqe *sqe_in_wp = NULL;
	struct spfc_linkwqe *link_wqe = NULL;
	struct spfc_linkwqe *link_wqe_last_part = NULL;
	u64 wqe_gpa;
	struct spfc_direct_wqe_db dre_door_bell;

	spin_lock_irqsave(&ssq->parent_sq_enqueue_lock, flag);
	tail_wpg = SPFC_GET_SQ_TAIL(ssq);
	if (ssq->wqe_offset == ssq->wqe_num_per_buf) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_INFO,
			     "[info]Ssq(0x%x), xid(0x%x) qid(0x%x) add wqepage at Pmsn(0x%x), sqe_minus_cqe_cnt(0x%x)",
			     ssq->sqn, ssq->context_id, ssq->sq_queue_id,
			     ssq->last_pmsn,
			     atomic_read(&ssq->sqe_minus_cqe_cnt));

		link_wqe_msn = SPFC_MSN_DEC(ssq->last_pmsn);
		link_wqe = (struct spfc_linkwqe *)spfc_get_wqe_page_entry(tail_wpg,
									  ssq->wqe_offset);
		msn_wd = be32_to_cpu(link_wqe->val_wd1);
		msn_wd |= ((u32)(link_wqe_msn & SPFC_MSNWD_L_MASK));
		msn_wd |= (((u32)(link_wqe_msn & SPFC_MSNWD_H_MASK)) << UNF_SHIFT_16);
		link_wqe->val_wd1 = cpu_to_be32(msn_wd);
		link_wqe_last_part = (struct spfc_linkwqe *)((u8 *)link_wqe +
				     SPFC_EXTEND_WQE_OFFSET);
		link_wqe_last_part->val_wd1 = link_wqe->val_wd1;
		spfc_set_direct_wqe_owner_be(link_wqe, ssq->last_pi_owner);
		ssq->wqe_offset = 0;
		ssq->last_pi_owner = !ssq->last_pi_owner;
	}
	sqe_in_wp =
	    (struct spfc_sqe *)spfc_get_wqe_page_entry(tail_wpg, ssq->wqe_offset);
	spfc_build_wqe_owner_pmsn(io_sqe, (ssq->last_pi_owner), ssq->last_pmsn);
	SPFC_IO_STAT((struct spfc_hba_info *)ssq->hba, wqe_type);

	wqe_gpa = tail_wpg->wpg_phy_addr + (ssq->wqe_offset * sizeof(struct spfc_sqe));
	io_sqe->wqe_gpa = (wqe_gpa >> UNF_SHIFT_6);

	dre_door_bell.wd0.ddb = IWARP_FC_DDB_TYPE;
	dre_door_bell.wd0.cos = 0;
	dre_door_bell.wd0.c = 0;
	dre_door_bell.wd0.pi_hi =
	    (u32)(ssq->last_pmsn >> UNF_SHIFT_12) & SPFC_DB_WD0_PI_H_MASK;
	dre_door_bell.wd0.cntx_size = SPFC_CNTX_SIZE_T_256B;
	dre_door_bell.wd0.xid = ssq->context_id;
	dre_door_bell.wd1.sm_data = ssq->cache_id;
	dre_door_bell.wd1.pi_lo = (u32)(ssq->last_pmsn & SPFC_DB_WD0_PI_L_MASK);
	io_sqe->db_val = *(u64 *)&dre_door_bell;

	spfc_convert_parent_wqe_to_big_endian(io_sqe);
	memcpy(sqe_in_wp, io_sqe, sizeof(struct spfc_sqe));
	spfc_set_direct_wqe_owner_be(sqe_in_wp, ssq->last_pi_owner);

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_INFO,
		     "[INFO]Ssq(0x%x) xid:0x%x,qid:0x%x wqegpa:0x%llx,o:0x%x,outstandind:0x%x,pmsn:0x%x,cmsn:0x%x",
		     ssq->sqn, ssq->context_id, ssq->sq_queue_id, wqe_gpa,
		     ssq->last_pi_owner, atomic_read(&ssq->sqe_minus_cqe_cnt),
		     ssq->last_pmsn, SPFC_GET_QUEUE_CMSN(ssq));

	ssq->accum_wqe_cnt++;
	if (ssq->accum_wqe_cnt == accum_db_num) {
		ret = spfc_parent_sq_ring_direct_wqe_doorbell(ssq, (void *)sqe_in_wp);
		if (unlikely(ret != RETURN_OK))
			SPFC_ERR_IO_STAT((struct spfc_hba_info *)ssq->hba, wqe_type);
		ssq->accum_wqe_cnt = 0;
	}

	ssq->wqe_offset += 1;
	ssq->last_pmsn = SPFC_MSN_INC(ssq->last_pmsn);
	atomic_inc(&ssq->sq_wqe_cnt);
	atomic_inc(&ssq->sqe_minus_cqe_cnt);
	SPFC_SQ_IO_STAT(ssq, wqe_type);
	spin_unlock_irqrestore(&ssq->parent_sq_enqueue_lock, flag);
	return ret;
}

u32 spfc_parent_ssq_enqueue(struct spfc_parent_ssq_info *ssq, struct spfc_sqe *io_sqe, u8 wqe_type)
{
	u32 ret = RETURN_OK;
	u32 addr_wd = INVALID_VALUE32;
	u32 msn_wd = INVALID_VALUE32;
	u16 link_wqe_msn = 0;
	ulong flag = 0;
	struct spfc_wqe_page *new_wqe_page = NULL;
	struct spfc_wqe_page *tail_wpg = NULL;
	struct spfc_sqe *sqe_in_wp = NULL;
	struct spfc_linkwqe *link_wqe = NULL;
	struct spfc_linkwqe *link_wqe_last_part = NULL;
	u32 cur_cmsn = 0;
	u8 qos_level = (u8)io_sqe->ts_sl.cont.icmnd.info.dif_info.wd1.vpid;
	u32 c = SPFC_DB_C_BIT_CONTROL_TYPE;

	if (ssq->queue_style == SPFC_QUEUE_RING_STYLE)
		return spfc_direct_sq_enqueue(ssq, io_sqe, wqe_type);

	spin_lock_irqsave(&ssq->parent_sq_enqueue_lock, flag);
	tail_wpg = SPFC_GET_SQ_TAIL(ssq);
	if (ssq->wqe_offset == ssq->wqe_num_per_buf) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_INFO,
			     "[info]Ssq(0x%x), xid(0x%x) qid(0x%x) add wqepage at Pmsn(0x%x), WpgCnt(0x%x)",
			     ssq->sqn, ssq->context_id, ssq->sq_queue_id,
			     ssq->last_pmsn,
			     atomic_read(&ssq->wqe_page_cnt));
		cur_cmsn = SPFC_GET_QUEUE_CMSN(ssq);
		spfc_free_sq_wqe_page(ssq, cur_cmsn);
		new_wqe_page = spfc_add_one_wqe_page(ssq);
		if (unlikely(!new_wqe_page)) {
			SPFC_ERR_IO_STAT((struct spfc_hba_info *)ssq->hba, wqe_type);
			spin_unlock_irqrestore(&ssq->parent_sq_enqueue_lock, flag);
			return UNF_RETURN_ERROR;
		}
		link_wqe = (struct spfc_linkwqe *)spfc_get_wqe_page_entry(tail_wpg,
									  ssq->wqe_offset);
		addr_wd = SPFC_MSD(new_wqe_page->wpg_phy_addr);
		link_wqe->next_page_addr_hi = cpu_to_be32(addr_wd);
		addr_wd = SPFC_LSD(new_wqe_page->wpg_phy_addr);
		link_wqe->next_page_addr_lo = cpu_to_be32(addr_wd);
		link_wqe_msn = SPFC_MSN_DEC(ssq->last_pmsn);
		msn_wd = be32_to_cpu(link_wqe->val_wd1);
		msn_wd |= ((u32)(link_wqe_msn & SPFC_MSNWD_L_MASK));
		msn_wd |= (((u32)(link_wqe_msn & SPFC_MSNWD_H_MASK)) << UNF_SHIFT_16);
		link_wqe->val_wd1 = cpu_to_be32(msn_wd);
		link_wqe_last_part = (struct spfc_linkwqe *)((u8 *)link_wqe +
				      SPFC_EXTEND_WQE_OFFSET);
		link_wqe_last_part->next_page_addr_hi = link_wqe->next_page_addr_hi;
		link_wqe_last_part->next_page_addr_lo = link_wqe->next_page_addr_lo;
		link_wqe_last_part->val_wd1 = link_wqe->val_wd1;
		spfc_set_sq_wqe_owner_be(link_wqe);
		ssq->wqe_offset = 0;
		tail_wpg = SPFC_GET_SQ_TAIL(ssq);
		atomic_inc(&ssq->wqe_page_cnt);
	}

	spfc_build_wqe_owner_pmsn(io_sqe, !(ssq->last_pi_owner), ssq->last_pmsn);
	SPFC_IO_STAT((struct spfc_hba_info *)ssq->hba, wqe_type);
	spfc_convert_parent_wqe_to_big_endian(io_sqe);
	sqe_in_wp = (struct spfc_sqe *)spfc_get_wqe_page_entry(tail_wpg, ssq->wqe_offset);
	memcpy(sqe_in_wp, io_sqe, sizeof(struct spfc_sqe));
	spfc_set_sq_wqe_owner_be(sqe_in_wp);

	FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_INFO,
		     "[INFO]Ssq(0x%x) xid:0x%x,qid:0x%x wqegpa:0x%llx, qos_level:0x%x, c:0x%x",
		     ssq->sqn, ssq->context_id, ssq->sq_queue_id,
		     virt_to_phys(sqe_in_wp), qos_level, c);

	ssq->accum_wqe_cnt++;
	if (ssq->accum_wqe_cnt == accum_db_num) {
		ret = spfc_parent_sq_ring_doorbell(ssq, qos_level, c);
		if (unlikely(ret != RETURN_OK))
			SPFC_ERR_IO_STAT((struct spfc_hba_info *)ssq->hba, wqe_type);
		ssq->accum_wqe_cnt = 0;
	}
	ssq->wqe_offset += 1;
	ssq->last_pmsn = SPFC_MSN_INC(ssq->last_pmsn);
	atomic_inc(&ssq->sq_wqe_cnt);
	atomic_inc(&ssq->sqe_minus_cqe_cnt);
	SPFC_SQ_IO_STAT(ssq, wqe_type);
	spin_unlock_irqrestore(&ssq->parent_sq_enqueue_lock, flag);
	return ret;
}

u32 spfc_parent_sq_enqueue(struct spfc_parent_sq_info *sq, struct spfc_sqe *io_sqe, u16 ssqn)
{
	u8 wqe_type = 0;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)sq->hba;
	struct spfc_parent_ssq_info *ssq = NULL;

	if (unlikely(ssqn >= SPFC_MAX_SSQ_NUM)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Ssqn 0x%x is invalid.", ssqn);

		return UNF_RETURN_ERROR;
	}

	wqe_type = (u8)SPFC_GET_WQE_TYPE(io_sqe);

	/* Serial enqueue */
	io_sqe->ts_sl.xid = sq->context_id;
	io_sqe->ts_sl.cid = sq->cache_id;
	io_sqe->ts_sl.sqn = ssqn;

	/* Choose SSQ */
	ssq = &hba->parent_queue_mgr->shared_queue[ssqn].parent_ssq_info;

	/* If the SQ is invalid, the wqe is discarded */
	if (unlikely(!atomic_read(&sq->sq_valid))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]SQ is invalid, reject wqe(0x%x)", wqe_type);

		return UNF_RETURN_ERROR;
	}

	/* The heartbeat detection status is 0, which allows control sessions
	 * enqueuing
	 */
	if (unlikely(!hba->heart_status && SPFC_WQE_IS_IO(io_sqe))) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[err]Heart status is false");

		return UNF_RETURN_ERROR;
	}

	if (sq->need_offloaded != SPFC_NEED_DO_OFFLOAD) {
		/* Ensure to be offloaded */
		if (unlikely(!atomic_read(&sq->sq_cached))) {
			SPFC_ERR_IO_STAT((struct spfc_hba_info *)sq->hba, wqe_type);
			SPFC_HBA_STAT((struct spfc_hba_info *)sq->hba,
				      SPFC_STAT_PARENT_SQ_NOT_OFFLOADED);

			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
				     "[err]RPort(0x%x) Session(0x%x) is not offloaded, reject wqe(0x%x)",
				     sq->rport_index, sq->context_id, wqe_type);

			return UNF_RETURN_ERROR;
		}
	}

	/* Whether the SQ is in the flush state. Temporarily allow the control
	 * sessions to enqueue.
	 */
	if (unlikely(sq->port_in_flush && SPFC_WQE_IS_IO(io_sqe))) {
		SPFC_ERR_IO_STAT((struct spfc_hba_info *)sq->hba, wqe_type);
		SPFC_HBA_STAT((struct spfc_hba_info *)sq->hba, SPFC_STAT_PARENT_IO_FLUSHED);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Session(0x%x) in flush, Sqn(0x%x) cmsn(0x%x), reject wqe(0x%x)",
			     sq->context_id, ssqn, SPFC_GET_QUEUE_CMSN(ssq),
			     wqe_type);

		return UNF_RETURN_ERROR;
	}

	/* If the SQ is in the Seesion deletion state and is the WQE of the I/O
	 * path, * the I/O failure is directly returned
	 */
	if (unlikely(sq->sq_in_sess_rst && SPFC_WQE_IS_IO(io_sqe))) {
		SPFC_ERR_IO_STAT((struct spfc_hba_info *)sq->hba, wqe_type);
		SPFC_HBA_STAT((struct spfc_hba_info *)sq->hba, SPFC_STAT_PARENT_IO_FLUSHED);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Session(0x%x) in session reset, reject wqe(0x%x)",
			     sq->context_id, wqe_type);

		return UNF_RETURN_ERROR;
	}

	return spfc_parent_ssq_enqueue(ssq, io_sqe, wqe_type);
}

static bool spfc_msn_in_wqe_page(u32 start_msn, u32 end_msn, u32 cur_cmsn)
{
	bool ret = true;

	if (end_msn >= start_msn) {
		if (cur_cmsn < start_msn || cur_cmsn > end_msn)
			ret = false;
		else
			ret = true;
	} else {
		if (cur_cmsn > end_msn && cur_cmsn < start_msn)
			ret = false;
		else
			ret = true;
	}

	return ret;
}

void spfc_free_sq_wqe_page(struct spfc_parent_ssq_info *ssq, u32 cur_cmsn)
{
	u16 wpg_start_cmsn = 0;
	u16 wpg_end_cmsn = 0;
	bool wqe_page_in_use = false;

	/* If there is only zero or one Wqe Page, no release is required */
	if (atomic_read(&ssq->wqe_page_cnt) <= SPFC_MIN_WP_NUM)
		return;

	/* Check whether the current MSN is within the MSN range covered by the
	 * WqePage
	 */
	wpg_start_cmsn = ssq->head_start_cmsn;
	wpg_end_cmsn = ssq->head_end_cmsn;
	wqe_page_in_use = spfc_msn_in_wqe_page(wpg_start_cmsn, wpg_end_cmsn, cur_cmsn);

	/* If the value of CMSN is within the current Wqe Page, no release is
	 * required
	 */
	if (wqe_page_in_use)
		return;

	/* If the next WqePage is available and the CMSN is not in the current
	 * WqePage, * the current WqePage is released
	 */
	while (!wqe_page_in_use &&
	       (atomic_read(&ssq->wqe_page_cnt) > SPFC_MIN_WP_NUM)) {
		/* Free WqePage */
		spfc_free_head_wqe_page(ssq);

		/* Obtain the start MSN of the next WqePage */
		wpg_start_cmsn = SPFC_MSN_INC(wpg_end_cmsn);

		/* obtain the end MSN of the next WqePage */
		wpg_end_cmsn =
		    SPFC_GET_WP_END_CMSN(wpg_start_cmsn, ssq->wqe_num_per_buf);

		/* Set new MSN range */
		ssq->head_start_cmsn = wpg_start_cmsn;
		ssq->head_end_cmsn = wpg_end_cmsn;
		cur_cmsn = SPFC_GET_QUEUE_CMSN(ssq);
		/* Check whether the current MSN is within the MSN range covered
		 * by the WqePage
		 */
		wqe_page_in_use = spfc_msn_in_wqe_page(wpg_start_cmsn, wpg_end_cmsn, cur_cmsn);
	}
}

/*
 *Function Name       : SPFC_UpdateSqCompletionStat
 *Function Description: Update the calculation statistics of the CQE
 *corresponding to the WQE on the connection SQ.
 *Input Parameters    : *sq, *scqe
 *Output Parameters   : N/A
 *Return Type         : void
 */
static void spfc_update_sq_wqe_completion_stat(struct spfc_parent_ssq_info *ssq,
					       union spfc_scqe *scqe)
{
	struct spfc_scqe_rcv_els_gs_rsp *els_gs_rsp = NULL;

	els_gs_rsp = (struct spfc_scqe_rcv_els_gs_rsp *)scqe;

	/* For the ELS/GS RSP intermediate frame and the CQE that is more than
	 * the  ELS_GS_RSP_EXCH_CHECK_FAIL, no statistics are required
	 */
	if (unlikely(SPFC_GET_SCQE_TYPE(scqe) == SPFC_SCQE_ELS_RSP) ||
	    (SPFC_GET_SCQE_TYPE(scqe) == SPFC_SCQE_GS_RSP)) {
		if (!els_gs_rsp->wd3.end_rsp || !SPFC_SCQE_ERR_TO_CM(scqe))
			return;
	}

	/* When the SQ statistics are updated, the PlogiAcc or PlogiAccSts that
	 * is * implicitly unloaded will enter here, and one more CQE count is
	 * added
	 */
	atomic_inc(&ssq->sq_cqe_cnt);
	atomic_dec(&ssq->sqe_minus_cqe_cnt);
	SPFC_SQ_IO_STAT(ssq, SPFC_GET_SCQE_TYPE(scqe));
}

/*
 *Function Name       : spfc_reclaim_sq_wqe_page
 *Function Description: Reclaim the Wqe Pgae that has been used up in the Linked
 *					   List SQ.
 *Input Parameters    : *handle,
 *					   *scqe
 *Output Parameters   : N/A
 *Return Type         : u32
 */
u32 spfc_reclaim_sq_wqe_page(void *handle, union spfc_scqe *scqe)
{
	u32 ret = RETURN_OK;
	u32 cur_cmsn = 0;
	u32 sqn = INVALID_VALUE32;
	struct spfc_parent_ssq_info *ssq = NULL;
	struct spfc_parent_shared_queue_info *parent_queue_info = NULL;
	struct spfc_hba_info *hba = NULL;
	ulong flag = 0;

	hba = (struct spfc_hba_info *)handle;
	sqn = SPFC_GET_SCQE_SQN(scqe);
	if (sqn >= SPFC_MAX_SSQ_NUM) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) do not have sqn: 0x%x",
			     hba->port_cfg.port_id, sqn);

		return UNF_RETURN_ERROR;
	}

	parent_queue_info = &hba->parent_queue_mgr->shared_queue[sqn];
	ssq = &parent_queue_info->parent_ssq_info;
	/* If there is only zero or one Wqe Page, no release is required */
	if (atomic_read(&ssq->wqe_page_cnt) <= SPFC_MIN_WP_NUM) {
		spfc_update_sq_wqe_completion_stat(ssq, scqe);
		return RETURN_OK;
	}

	spin_lock_irqsave(&ssq->parent_sq_enqueue_lock, flag);
	cur_cmsn = SPFC_GET_QUEUE_CMSN(ssq);
	spfc_free_sq_wqe_page(ssq, cur_cmsn);
	spin_unlock_irqrestore(&ssq->parent_sq_enqueue_lock, flag);

	spfc_update_sq_wqe_completion_stat(ssq, scqe);

	return ret;
}

u32 spfc_root_cmdq_enqueue(void *handle, union spfc_cmdqe *cmdqe, u16 cmd_len)
{
#define SPFC_ROOTCMDQ_TIMEOUT_MS 3000
	u8 wqe_type = 0;
	int cmq_ret = 0;
	struct sphw_cmd_buf *cmd_buf = NULL;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	wqe_type = (u8)cmdqe->common.wd0.task_type;
	SPFC_IO_STAT(hba, wqe_type);

	cmd_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmd_buf) {
		SPFC_ERR_IO_STAT(hba, wqe_type);
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) CqmHandle(0x%p) allocate cmdq buffer failed",
			     hba->port_cfg.port_id, hba->dev_handle);

		return UNF_RETURN_ERROR;
	}

	memcpy(cmd_buf->buf, cmdqe, cmd_len);
	spfc_cpu_to_big32(cmd_buf->buf, cmd_len);
	cmd_buf->size = cmd_len;

	cmq_ret = sphw_cmdq_async(hba->dev_handle, COMM_MOD_FC, 0, cmd_buf, SPHW_CHANNEL_FC);

	if (cmq_ret != RETURN_OK) {
		sphw_free_cmd_buf(hba->dev_handle, cmd_buf);
		SPFC_ERR_IO_STAT(hba, wqe_type);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) CqmHandle(0x%p) send buff clear cmnd failed(0x%x)",
			     hba->port_cfg.port_id, hba->dev_handle, cmq_ret);
		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

struct spfc_parent_queue_info *
spfc_find_parent_queue_info_by_pkg(void *handle, struct unf_frame_pkg *pkg)
{
	u32 rport_index = 0;
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	rport_index = pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX];

	if (unlikely(rport_index >= UNF_SPFC_MAXRPORT_NUM)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[warn]Port(0x%x) send pkg sid_did(0x%x_0x%x), but uplevel allocate invalid rport index: 0x%x",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did, rport_index);

		return NULL;
	}

	/* parent -->> session */
	parent_queue_info = &hba->parent_queue_mgr->parent_queue[rport_index];

	return parent_queue_info;
}

struct spfc_parent_queue_info *spfc_find_parent_queue_info_by_id(struct spfc_hba_info *hba,
								 u32 local_id, u32 remote_id)
{
	u32 index = 0;
	ulong flag = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	spinlock_t *prtq_state_lock = NULL;
	u32 lport_id;
	u32 rport_id;

	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr)
		return NULL;

	/* rport_number -->> parent_number -->> session_number */
	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		prtq_state_lock = &parent_queue_mgr->parent_queue[index].parent_queue_state_lock;
		lport_id = parent_queue_mgr->parent_queue[index].parent_sq_info.local_port_id;
		rport_id = parent_queue_mgr->parent_queue[index].parent_sq_info.remote_port_id;
		spin_lock_irqsave(prtq_state_lock, flag);

		/* local_id & remote_id & offload */
		if (local_id == lport_id && remote_id == rport_id &&
		    parent_queue_mgr->parent_queue[index].offload_state ==
		     SPFC_QUEUE_STATE_OFFLOADED) {
			parent_queue_info = &parent_queue_mgr->parent_queue[index];
			spin_unlock_irqrestore(prtq_state_lock, flag);

			return parent_queue_info;
		}

		spin_unlock_irqrestore(prtq_state_lock, flag);
	}

	return NULL;
}

struct spfc_parent_queue_info *spfc_find_offload_parent_queue(void *handle, u32 local_id,
							      u32 remote_id, u32 rport_index)
{
	u32 index = 0;
	ulong flag = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	struct spfc_hba_info *hba = NULL;
	spinlock_t *prtq_state_lock = NULL;

	hba = (struct spfc_hba_info *)handle;
	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr)
		return NULL;

	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		if (rport_index == index)
			continue;
		prtq_state_lock = &parent_queue_mgr->parent_queue[index].parent_queue_state_lock;
		spin_lock_irqsave(prtq_state_lock, flag);

		if (local_id == parent_queue_mgr->parent_queue[index]
				     .parent_sq_info.local_port_id &&
		    remote_id == parent_queue_mgr->parent_queue[index]
				      .parent_sq_info.remote_port_id &&
		    parent_queue_mgr->parent_queue[index].offload_state !=
		     SPFC_QUEUE_STATE_FREE &&
		    parent_queue_mgr->parent_queue[index].offload_state !=
		     SPFC_QUEUE_STATE_INITIALIZED) {
			parent_queue_info = &parent_queue_mgr->parent_queue[index];
			spin_unlock_irqrestore(prtq_state_lock, flag);

			return parent_queue_info;
		}

		spin_unlock_irqrestore(prtq_state_lock, flag);
	}

	return NULL;
}

struct spfc_parent_sq_info *spfc_find_parent_sq_by_pkg(void *handle, struct unf_frame_pkg *pkg)
{
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	struct cqm_qpc_mpt *cqm_parent_ctxt_obj = NULL;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	parent_queue_info = spfc_find_parent_queue_info_by_pkg(hba, pkg);
	if (unlikely(!parent_queue_info)) {
		parent_queue_info = spfc_find_parent_queue_info_by_id(hba,
								      pkg->frame_head.csctl_sid &
								      UNF_NPORTID_MASK,
								      pkg->frame_head.rctl_did &
								      UNF_NPORTID_MASK);
		if (!parent_queue_info) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x), get a null parent queue information",
				     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
				     pkg->frame_head.rctl_did);

			return NULL;
		}
	}

	cqm_parent_ctxt_obj = (parent_queue_info->parent_ctx.cqm_parent_ctx_obj);
	if (unlikely(!cqm_parent_ctxt_obj)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[err]Port(0x%x) send pkg sid_did(0x%x_0x%x) with this rport has not alloc parent sq information",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did);

		return NULL;
	}

	return &parent_queue_info->parent_sq_info;
}

u32 spfc_check_all_parent_queue_free(struct spfc_hba_info *hba)
{
	u32 index = 0;
	ulong flag = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	spinlock_t *prtq_state_lock = NULL;

	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[err]Port(0x%x) get a null parent queue mgr",
			     hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}

	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		prtq_state_lock = &parent_queue_mgr->parent_queue[index].parent_queue_state_lock;
		spin_lock_irqsave(prtq_state_lock, flag);

		if (parent_queue_mgr->parent_queue[index].offload_state != SPFC_QUEUE_STATE_FREE) {
			spin_unlock_irqrestore(prtq_state_lock, flag);
			return UNF_RETURN_ERROR;
		}

		spin_unlock_irqrestore(prtq_state_lock, flag);
	}

	return RETURN_OK;
}

void spfc_flush_specific_scq(struct spfc_hba_info *hba, u32 index)
{
	/* The software interrupt is scheduled and processed during the second
	 * timeout period
	 */
	struct spfc_scq_info *scq_info = NULL;
	u32 flush_done_time = 0;

	scq_info = &hba->scq_info[index];
	atomic_set(&scq_info->flush_stat, SPFC_QUEUE_FLUSH_DOING);
	tasklet_schedule(&scq_info->tasklet);

	/* Wait for a maximum of 2 seconds. If the SCQ soft interrupt is not
	 * scheduled * within 2 seconds, only timeout is returned
	 */
	while ((atomic_read(&scq_info->flush_stat) != SPFC_QUEUE_FLUSH_DONE) &&
	       (flush_done_time < SPFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS)) {
		msleep(SPFC_QUEUE_FLUSH_WAIT_MS);
		flush_done_time += SPFC_QUEUE_FLUSH_WAIT_MS;
		tasklet_schedule(&scq_info->tasklet);
	}

	if (atomic_read(&scq_info->flush_stat) != SPFC_QUEUE_FLUSH_DONE) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
			     "[warn]Port(0x%x) special scq(0x%x) flush timeout",
			     hba->port_cfg.port_id, index);
	}
}

static void spfc_flush_cmd_scq(struct spfc_hba_info *hba)
{
	u32 index = 0;

	for (index = SPFC_CMD_SCQN_START; index < SPFC_SESSION_SCQ_NUM;
	     index += SPFC_SCQS_PER_SESSION) {
		spfc_flush_specific_scq(hba, index);
	}
}

static void spfc_flush_sts_scq(struct spfc_hba_info *hba)
{
	u32 index = 0;

	/* for each STS SCQ */
	for (index = SPFC_STS_SCQN_START; index < SPFC_SESSION_SCQ_NUM;
	     index += SPFC_SCQS_PER_SESSION) {
		spfc_flush_specific_scq(hba, index);
	}
}

static void spfc_flush_all_scq(struct spfc_hba_info *hba)
{
	spfc_flush_cmd_scq(hba);
	spfc_flush_sts_scq(hba);
	/* Flush Default SCQ */
	spfc_flush_specific_scq(hba, SPFC_SESSION_SCQ_NUM);
}

void spfc_wait_all_queues_empty(struct spfc_hba_info *hba)
{
	spfc_flush_all_scq(hba);
}

void spfc_set_rport_flush_state(void *handle, bool in_flush)
{
	u32 index = 0;
	ulong flag = 0;
	struct spfc_parent_queue_mgr *parent_queue_mgr = NULL;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	parent_queue_mgr = hba->parent_queue_mgr;
	if (!parent_queue_mgr) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) parent queue manager is empty",
			     hba->port_cfg.port_id);
		return;
	}

	/*
	 * for each HBA's R_Port(SQ),
	 * set state with been flushing or flush done
	 */
	for (index = 0; index < UNF_SPFC_MAXRPORT_NUM; index++) {
		spin_lock_irqsave(&parent_queue_mgr->parent_queue[index]
				  .parent_sq_info.parent_sq_enqueue_lock, flag);
		if (parent_queue_mgr->parent_queue[index].offload_state != SPFC_QUEUE_STATE_FREE) {
			parent_queue_mgr->parent_queue[index]
			    .parent_sq_info.port_in_flush = in_flush;
		}
		spin_unlock_irqrestore(&parent_queue_mgr->parent_queue[index]
				       .parent_sq_info.parent_sq_enqueue_lock, flag);
	}
}

u32 spfc_clear_fetched_sq_wqe(void *handle)
{
	u32 ret = UNF_RETURN_ERROR;
	union spfc_cmdqe cmdqe;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);

	hba = (struct spfc_hba_info *)handle;
	/*
	 * The ROOT SQ cannot control the WQE in the empty queue of the ROOT SQ.
	 * Therefore, the ROOT SQ does not enqueue the WQE after the hardware
	 * obtains the. Link down after the wait mode is used. Therefore, the
	 * WQE of the hardware driver needs to enter the WQE of the queue after
	 * the Link down of the Link down is reported.
	 */
	memset(&cmdqe, 0, sizeof(union spfc_cmdqe));
	spfc_build_cmdqe_common(&cmdqe, SPFC_TASK_T_BUFFER_CLEAR, 0);
	cmdqe.buffer_clear.wd1.rx_id_start = hba->exi_base;
	cmdqe.buffer_clear.wd1.rx_id_end = hba->exi_base + hba->exi_count - 1;
	cmdqe.buffer_clear.scqn = hba->default_scqn;

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
		     "[info]Port(0x%x) start clear all fetched wqe in start(0x%x) - end(0x%x) scqn(0x%x) stage(0x%x)",
		     hba->port_cfg.port_id, cmdqe.buffer_clear.wd1.rx_id_start,
		     cmdqe.buffer_clear.wd1.rx_id_end, cmdqe.buffer_clear.scqn,
		     hba->queue_set_stage);

	/* Send BUFFER_CLEAR command via ROOT CMDQ */
	ret = spfc_root_cmdq_enqueue(hba, &cmdqe, sizeof(cmdqe.buffer_clear));

	return ret;
}

u32 spfc_clear_pending_sq_wqe(void *handle)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 cmdqe_len = 0;
	ulong flag = 0;
	struct spfc_parent_ssq_info *ssq_info = NULL;
	union spfc_cmdqe cmdqe;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	memset(&cmdqe, 0, sizeof(union spfc_cmdqe));
	spfc_build_cmdqe_common(&cmdqe, SPFC_TASK_T_FLUSH_SQ, 0);
	cmdqe.flush_sq.wd0.wqe_type = SPFC_TASK_T_FLUSH_SQ;
	cmdqe.flush_sq.wd1.scqn = SPFC_LSW(hba->default_scqn);
	cmdqe.flush_sq.wd1.port_id = hba->port_index;

	ssq_info = &hba->parent_queue_mgr->shared_queue[ARRAY_INDEX_0].parent_ssq_info;

	spin_lock_irqsave(&ssq_info->parent_sq_enqueue_lock, flag);
	cmdqe.flush_sq.wd3.first_sq_xid = ssq_info->context_id;
	spin_unlock_irqrestore(&ssq_info->parent_sq_enqueue_lock, flag);
	cmdqe.flush_sq.wd0.entry_count = SPFC_MAX_SSQ_NUM;
	cmdqe.flush_sq.wd3.sqqid_start_per_session = SPFC_SQ_QID_START_PER_QPC;
	cmdqe.flush_sq.wd3.sqcnt_per_session = SPFC_SQ_NUM_PER_QPC;
	cmdqe.flush_sq.wd1.last_wqe = 1;

	/* Clear pending Queue */
	cmdqe_len = (u32)(sizeof(cmdqe.flush_sq));
	ret = spfc_root_cmdq_enqueue(hba, &cmdqe, (u16)cmdqe_len);

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
		     "[info]Port(0x%x) clear total 0x%x SQ in this CMDQE(last=%u), stage (0x%x)",
		     hba->port_cfg.port_id, SPFC_MAX_SSQ_NUM,
		     cmdqe.flush_sq.wd1.last_wqe, hba->queue_set_stage);

	return ret;
}

u32 spfc_wait_queue_set_flush_done(struct spfc_hba_info *hba)
{
	u32 flush_done_time = 0;
	u32 ret = RETURN_OK;

	while ((hba->queue_set_stage != SPFC_QUEUE_SET_STAGE_FLUSHDONE) &&
	       (flush_done_time < SPFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS)) {
		msleep(SPFC_QUEUE_FLUSH_WAIT_MS);
		flush_done_time += SPFC_QUEUE_FLUSH_WAIT_MS;
	}

	if (hba->queue_set_stage != SPFC_QUEUE_SET_STAGE_FLUSHDONE) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
			     "[warn]Port(0x%x) queue sets flush timeout with stage(0x%x)",
			     hba->port_cfg.port_id, hba->queue_set_stage);

		ret = UNF_RETURN_ERROR;
	}

	return ret;
}

void spfc_disable_all_scq_schedule(struct spfc_hba_info *hba)
{
	struct spfc_scq_info *scq_info = NULL;
	u32 index = 0;

	for (index = 0; index < SPFC_TOTAL_SCQ_NUM; index++) {
		scq_info = &hba->scq_info[index];
		tasklet_disable(&scq_info->tasklet);
	}
}

void spfc_disable_queues_dispatch(struct spfc_hba_info *hba)
{
	spfc_disable_all_scq_schedule(hba);
}

void spfc_enable_all_scq_schedule(struct spfc_hba_info *hba)
{
	struct spfc_scq_info *scq_info = NULL;
	u32 index = 0;

	for (index = 0; index < SPFC_TOTAL_SCQ_NUM; index++) {
		scq_info = &hba->scq_info[index];
		tasklet_enable(&scq_info->tasklet);
	}
}

void spfc_enalbe_queues_dispatch(void *handle)
{
	spfc_enable_all_scq_schedule((struct spfc_hba_info *)handle);
}

/*
 *Function Name       : spfc_clear_els_srq
 *Function Description: When the port is used as the remove, the resources
 *related to the els srq are deleted.
 *Input Parameters    : *hba Output Parameters
 *Return Type         : void
 */
void spfc_clear_els_srq(struct spfc_hba_info *hba)
{
#define SPFC_WAIT_CLR_SRQ_CTX_MS 500
#define SPFC_WAIT_CLR_SRQ_CTX_LOOP_TIMES 60

	u32 index = 0;
	ulong flag = 0;
	struct spfc_srq_info *srq_info = NULL;

	srq_info = &hba->els_srq_info;

	spin_lock_irqsave(&srq_info->srq_spin_lock, flag);
	if (!srq_info->enable || srq_info->state == SPFC_CLEAN_DOING) {
		spin_unlock_irqrestore(&srq_info->srq_spin_lock, flag);

		return;
	}
	srq_info->enable = false;
	srq_info->state = SPFC_CLEAN_DOING;
	spin_unlock_irqrestore(&srq_info->srq_spin_lock, flag);

	spfc_send_clear_srq_cmd(hba, &hba->els_srq_info);

	/* wait for uCode to clear SRQ context, the timer is 30S */
	while ((srq_info->state != SPFC_CLEAN_DONE) &&
	       (index < SPFC_WAIT_CLR_SRQ_CTX_LOOP_TIMES)) {
		msleep(SPFC_WAIT_CLR_SRQ_CTX_MS);
		index++;
	}

	if (srq_info->state != SPFC_CLEAN_DONE) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
			     "[warn]SPFC Port(0x%x) clear els srq timeout",
			     hba->port_cfg.port_id);
	}
}

u32 spfc_wait_all_parent_queue_free(struct spfc_hba_info *hba)
{
#define SPFC_MAX_LOOP_TIMES 6000
#define SPFC_WAIT_ONE_TIME_MS 5
	u32 index = 0;
	u32 ret = UNF_RETURN_ERROR;

	do {
		ret = spfc_check_all_parent_queue_free(hba);
		if (ret == RETURN_OK)
			break;

		index++;
		msleep(SPFC_WAIT_ONE_TIME_MS);
	} while (index < SPFC_MAX_LOOP_TIMES);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,
			     "[warn]Port(0x%x) wait all parent queue state free timeout",
			     hba->port_cfg.port_id);
	}

	return ret;
}

/*
 *Function Name       : spfc_queue_pre_process
 *Function Description: When the port functions as the remove, the queue needs
 *					   to be preprocessed.
 *Input Parameters    : *handle,
 *					   clean
 *Output Parameters   : N/A
 *Return Type         : void
 */
void spfc_queue_pre_process(void *handle, bool clean)
{
#define SPFC_WAIT_LINKDOWN_EVENT_MS 500
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	/* From port reset & port remove */
	/* 1. Wait for 2s and wait for QUEUE to be FLUSH Done. */
	if (spfc_wait_queue_set_flush_done(hba) != RETURN_OK) {
		/*
		 * During the process of removing the card, if the port is
		 * disabled and the flush done is not available, the chip is
		 * powered off or the pcie link is disconnected. In this case,
		 * you can proceed with the next step.
		 */
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]SPFC Port(0x%x) clean queue sets timeout",
			     hba->port_cfg.port_id);
	}

	/*
	 * 2. Port remove:
	 * 2.1 free parent queue
	 * 2.2 clear & destroy ELS/SIRT SRQ
	 */
	if (clean) {
		if (spfc_wait_all_parent_queue_free(hba) != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_WARN,
				     "[warn]SPFC Port(0x%x) free all parent queue timeout",
				     hba->port_cfg.port_id);
		}

		/* clear & than destroy ELS/SIRT SRQ */
		spfc_clear_els_srq(hba);
	}

	msleep(SPFC_WAIT_LINKDOWN_EVENT_MS);

	/*
	 * 3. The internal resources of the port chip are flush done. However,
	 * there may be residual scqe or rq in the queue. The scheduling is
	 * forcibly refreshed once.
	 */
	spfc_wait_all_queues_empty(hba);

	/* 4. Disable tasklet scheduling for upstream queues on the software
	 * layer
	 */
	spfc_disable_queues_dispatch(hba);
}

void spfc_queue_post_process(void *hba)
{
	spfc_enalbe_queues_dispatch((struct spfc_hba_info *)hba);
}

/*
 *Function Name       : spfc_push_delay_sqe
 *Function Description: Check whether there is a sq that is being deleted.
 *					   If yes, add the sq to the sq.
 *Input Parameters    : *hba,
 *					   *offload_parent_queue,
 *					   *sqe,
 *					   *pkg
 *Output Parameters   : N/A
 *Return Type         : u32
 */
u32 spfc_push_delay_sqe(void *hba,
			struct spfc_parent_queue_info *offload_parent_queue,
			struct spfc_sqe *sqe, struct unf_frame_pkg *pkg)
{
	ulong flag = 0;
	spinlock_t *prtq_state_lock = NULL;

	prtq_state_lock = &offload_parent_queue->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flag);

	if (offload_parent_queue->offload_state != SPFC_QUEUE_STATE_INITIALIZED &&
	    offload_parent_queue->offload_state != SPFC_QUEUE_STATE_FREE) {
		memcpy(&offload_parent_queue->parent_sq_info.delay_sqe.sqe,
		       sqe, sizeof(struct spfc_sqe));
		offload_parent_queue->parent_sq_info.delay_sqe.start_jiff = jiffies;
		offload_parent_queue->parent_sq_info.delay_sqe.time_out =
		    pkg->private_data[PKG_PRIVATE_XCHG_TIMEER];
		offload_parent_queue->parent_sq_info.delay_sqe.valid = true;
		offload_parent_queue->parent_sq_info.delay_sqe.rport_index =
		    pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX];
		offload_parent_queue->parent_sq_info.delay_sqe.sid =
		    pkg->frame_head.csctl_sid & UNF_NPORTID_MASK;
		offload_parent_queue->parent_sq_info.delay_sqe.did =
		    pkg->frame_head.rctl_did & UNF_NPORTID_MASK;
		offload_parent_queue->parent_sq_info.delay_sqe.xid =
		    sqe->ts_sl.xid;
		offload_parent_queue->parent_sq_info.delay_sqe.ssqn =
		    (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];

		spin_unlock_irqrestore(prtq_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) RPort(0x%x) delay send ELS, OXID(0x%x), RXID(0x%x)",
			     ((struct spfc_hba_info *)hba)->port_cfg.port_id,
			     pkg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX],
			     UNF_GET_OXID(pkg), UNF_GET_RXID(pkg));

		return RETURN_OK;
	}

	spin_unlock_irqrestore(prtq_state_lock, flag);

	return UNF_RETURN_ERROR;
}

static u32 spfc_pop_session_valid_check(struct spfc_hba_info *hba,
					struct spfc_delay_sqe_ctrl_info *sqe_info, u32 rport_index)
{
	if (!sqe_info->valid)
		return UNF_RETURN_ERROR;

	if (jiffies_to_msecs(jiffies - sqe_info->start_jiff) >= sqe_info->time_out) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) pop delay enable session failed, start time 0x%llx, timeout value 0x%x",
			     hba->port_cfg.port_id, sqe_info->start_jiff,
			     sqe_info->time_out);

		return UNF_RETURN_ERROR;
	}

	if (rport_index >= UNF_SPFC_MAXRPORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) pop delay enable session failed, rport index(0x%x) is invalid",
			     hba->port_cfg.port_id, rport_index);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}

/*
 *Function Name       : spfc_pop_delay_sqe
 *Function Description: The sqe that is delayed due to the deletion of the old
 *					 connection is sent to the root sq for
 *processing. Input Parameters    : *hba, *sqe_info Output Parameters   : N/A
 *Return Type         : void
 */
static void spfc_pop_delay_sqe(struct spfc_hba_info *hba,
			       struct spfc_delay_sqe_ctrl_info *sqe_info)
{
	ulong flag;
	u32 delay_rport_index = INVALID_VALUE32;
	struct spfc_parent_queue_info *parent_queue = NULL;
	enum spfc_parent_queue_state offload_state =
	    SPFC_QUEUE_STATE_DESTROYING;
	struct spfc_delay_destroy_ctrl_info destroy_sqe_info;
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_parent_sq_info *sq_info = NULL;
	spinlock_t *prtq_state_lock = NULL;

	memset(&destroy_sqe_info, 0, sizeof(struct spfc_delay_destroy_ctrl_info));
	delay_rport_index = sqe_info->rport_index;

	/* According to the sequence, the rport index id is reported and then
	 * the sqe of the new link setup request is delivered.
	 */
	ret = spfc_pop_session_valid_check(hba, sqe_info, delay_rport_index);

	if (ret != RETURN_OK)
		return;

	parent_queue = &hba->parent_queue_mgr->parent_queue[delay_rport_index];
	sq_info = &parent_queue->parent_sq_info;
	prtq_state_lock = &parent_queue->parent_queue_state_lock;
	/* Before the root sq is delivered, check the status again to
	 * ensure that the initialization status is not uninstalled. Other
	 * states are not processed and are discarded directly.
	 */
	spin_lock_irqsave(prtq_state_lock, flag);
	offload_state = parent_queue->offload_state;

	/* Before re-enqueuing the rootsq, check whether the offload status and
	 * connection information is consistent to prevent the old request from
	 * being sent after the connection status is changed.
	 */
	if (offload_state == SPFC_QUEUE_STATE_INITIALIZED &&
	    parent_queue->parent_sq_info.local_port_id == sqe_info->sid &&
	    parent_queue->parent_sq_info.remote_port_id == sqe_info->did &&
	    SPFC_CHECK_XID_MATCHED(parent_queue->parent_sq_info.context_id,
				   sqe_info->sqe.ts_sl.xid)) {
		parent_queue->offload_state = SPFC_QUEUE_STATE_OFFLOADING;
		spin_unlock_irqrestore(prtq_state_lock, flag);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) pop up delay session enable, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
			     hba->port_cfg.port_id, sqe_info->start_jiff,
			     sqe_info->time_out, delay_rport_index, offload_state);

		if (spfc_parent_sq_enqueue(sq_info, &sqe_info->sqe, sqe_info->ssqn) != RETURN_OK) {
			spin_lock_irqsave(prtq_state_lock, flag);

			if (parent_queue->offload_state == SPFC_QUEUE_STATE_OFFLOADING)
				parent_queue->offload_state = offload_state;

			if (parent_queue->parent_sq_info.destroy_sqe.valid) {
				memcpy(&destroy_sqe_info,
				       &parent_queue->parent_sq_info.destroy_sqe,
				       sizeof(struct spfc_delay_destroy_ctrl_info));

				parent_queue->parent_sq_info.destroy_sqe.valid = false;
			}

			spin_unlock_irqrestore(prtq_state_lock, flag);

			spfc_pop_destroy_parent_queue_sqe((void *)hba, &destroy_sqe_info);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]Port(0x%x) pop up delay session enable fail, recover offload state 0x%x",
				     hba->port_cfg.port_id, parent_queue->offload_state);
			return;
		}
	} else {
		spin_unlock_irqrestore(prtq_state_lock, flag);
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port 0x%x pop delay session enable failed, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
			     hba->port_cfg.port_id, sqe_info->start_jiff,
			     sqe_info->time_out, delay_rport_index,
			     offload_state);
	}
}

void spfc_push_destroy_parent_queue_sqe(void *hba,
					struct spfc_parent_queue_info *offloading_parent_queue,
					struct unf_port_info *rport_info)
{
	offloading_parent_queue->parent_sq_info.destroy_sqe.valid = true;
	offloading_parent_queue->parent_sq_info.destroy_sqe.rport_index = rport_info->rport_index;
	offloading_parent_queue->parent_sq_info.destroy_sqe.time_out =
	    SPFC_SQ_DEL_STAGE_TIMEOUT_MS;
	offloading_parent_queue->parent_sq_info.destroy_sqe.start_jiff = jiffies;
	offloading_parent_queue->parent_sq_info.destroy_sqe.rport_info.nport_id =
	    rport_info->nport_id;
	offloading_parent_queue->parent_sq_info.destroy_sqe.rport_info.rport_index =
	    rport_info->rport_index;
	offloading_parent_queue->parent_sq_info.destroy_sqe.rport_info.port_name =
	    rport_info->port_name;
}

/*
 *Function Name       : spfc_pop_destroy_parent_queue_sqe
 *Function Description: The deletion connection sqe that is delayed due to
 *					   connection uninstallation is sent to
 *the parent sq for processing. Input Parameters    : *handle, *destroy_sqe_info
 *Output Parameters   : N/A
 *Return Type         : void
 */
void spfc_pop_destroy_parent_queue_sqe(void *handle,
				       struct spfc_delay_destroy_ctrl_info *destroy_sqe_info)
{
	u32 ret = UNF_RETURN_ERROR;
	ulong flag;
	u32 index = INVALID_VALUE32;
	struct spfc_parent_queue_info *parent_queue = NULL;
	enum spfc_parent_queue_state offload_state =
	    SPFC_QUEUE_STATE_DESTROYING;
	struct spfc_hba_info *hba = NULL;
	spinlock_t *prtq_state_lock = NULL;

	hba = (struct spfc_hba_info *)handle;
	if (!destroy_sqe_info->valid)
		return;

	if (jiffies_to_msecs(jiffies - destroy_sqe_info->start_jiff) < destroy_sqe_info->time_out) {
		index = destroy_sqe_info->rport_index;
		parent_queue = &hba->parent_queue_mgr->parent_queue[index];
		prtq_state_lock = &parent_queue->parent_queue_state_lock;
		/* Before delivery, check the status again to ensure that the
		 * initialization status is not uninstalled. Other states are
		 * not processed and are discarded directly.
		 */
		spin_lock_irqsave(prtq_state_lock, flag);

		offload_state = parent_queue->offload_state;
		if (offload_state == SPFC_QUEUE_STATE_OFFLOADED ||
		    offload_state == SPFC_QUEUE_STATE_INITIALIZED) {
			spin_unlock_irqrestore(prtq_state_lock, flag);

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
				     "[info]Port 0x%x pop up delay destroy parent sq, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, offload state 0x%x",
				     hba->port_cfg.port_id,
				     destroy_sqe_info->start_jiff,
				     destroy_sqe_info->time_out,
				     index, offload_state);
			ret = spfc_free_parent_resource(hba, &destroy_sqe_info->rport_info);
		} else {
			ret = UNF_RETURN_ERROR;
			spin_unlock_irqrestore(prtq_state_lock, flag);
		}
	}

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port 0x%x pop delay destroy parent sq failed, sqe start time 0x%llx, timeout value 0x%x, rport index 0x%x, rport nport id 0x%x,offload state 0x%x",
			     hba->port_cfg.port_id, destroy_sqe_info->start_jiff,
			     destroy_sqe_info->time_out, index,
			     destroy_sqe_info->rport_info.nport_id, offload_state);
	}
}

void spfc_free_parent_queue_info(void *handle, struct spfc_parent_queue_info *parent_queue_info)
{
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 rport_index = INVALID_VALUE32;
	struct spfc_hba_info *hba = NULL;
	struct spfc_delay_sqe_ctrl_info sqe_info;
	spinlock_t *prtq_state_lock = NULL;

	memset(&sqe_info, 0, sizeof(struct spfc_delay_sqe_ctrl_info));
	hba = (struct spfc_hba_info *)handle;
	prtq_state_lock = &parent_queue_info->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) begin to free parent sq, rport_index(0x%x)",
		     hba->port_cfg.port_id, parent_queue_info->parent_sq_info.rport_index);

	if (parent_queue_info->offload_state == SPFC_QUEUE_STATE_FREE) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[info]Port(0x%x) duplicate free parent sq, rport_index(0x%x)",
			     hba->port_cfg.port_id,
			     parent_queue_info->parent_sq_info.rport_index);

		spin_unlock_irqrestore(prtq_state_lock, flag);
		return;
	}

	if (parent_queue_info->parent_sq_info.delay_sqe.valid) {
		memcpy(&sqe_info, &parent_queue_info->parent_sq_info.delay_sqe,
		       sizeof(struct spfc_delay_sqe_ctrl_info));
	}

	rport_index = parent_queue_info->parent_sq_info.rport_index;

	/* The Parent Contexe and SQ information is released. After
	 * initialization, the Parent Contexe and SQ information is associated
	 * with the sq in the queue of the parent
	 */

	spin_unlock_irqrestore(prtq_state_lock, flag);
	spfc_free_parent_sq(hba, parent_queue_info);
	spin_lock_irqsave(prtq_state_lock, flag);

	/* The initialization of all queue id is invalid */
	parent_queue_info->parent_cmd_scq_info.cqm_queue_id = INVALID_VALUE32;
	parent_queue_info->parent_sts_scq_info.cqm_queue_id = INVALID_VALUE32;
	parent_queue_info->parent_els_srq_info.cqm_queue_id = INVALID_VALUE32;
	parent_queue_info->offload_state = SPFC_QUEUE_STATE_FREE;

	spin_unlock_irqrestore(prtq_state_lock, flag);

	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_RELEASE_RPORT_INDEX,
				(void *)&rport_index);

	spfc_pop_delay_sqe(hba, &sqe_info);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[warn]Port(0x%x) free parent sq with rport_index(0x%x) failed",
			     hba->port_cfg.port_id, rport_index);
	}
}

static void spfc_do_port_reset(struct work_struct *work)
{
	struct spfc_suspend_sqe_info *suspend_sqe = NULL;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VOID(work);

	suspend_sqe = container_of(work, struct spfc_suspend_sqe_info,
				   timeout_work.work);
	hba = (struct spfc_hba_info *)suspend_sqe->hba;
	FC_CHECK_RETURN_VOID(hba);
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) magic num (0x%x)do port reset.",
		     hba->port_cfg.port_id, suspend_sqe->magic_num);

	spfc_port_reset(hba);
}

static void
spfc_push_sqe_suspend(void *hba, struct spfc_parent_queue_info *parent_queue,
		      struct spfc_sqe *sqe, struct unf_frame_pkg *pkg, u32 magic_num)
{
#define SPFC_SQ_NOP_TIMEOUT_MS 1000
	ulong flag = 0;
	u32 sqn_base;
	struct spfc_parent_sq_info *sq = NULL;
	struct spfc_suspend_sqe_info *suspend_sqe = NULL;

	sq = &parent_queue->parent_sq_info;
	suspend_sqe =
	    kmalloc(sizeof(struct spfc_suspend_sqe_info), GFP_ATOMIC);
	if (!suspend_sqe) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[err]alloc suspend sqe memory failed");
		return;
	}
	memset(suspend_sqe, 0, sizeof(struct spfc_suspend_sqe_info));
	memcpy(&suspend_sqe->sqe, sqe, sizeof(struct spfc_sqe));
	suspend_sqe->magic_num = magic_num;
	suspend_sqe->old_offload_sts = sq->need_offloaded;
	suspend_sqe->hba = sq->hba;

	if (pkg) {
		memcpy(&suspend_sqe->pkg, pkg, sizeof(struct unf_frame_pkg));
	} else {
		sqn_base = sq->sqn_base;
		suspend_sqe->pkg.private_data[PKG_PRIVATE_XCHG_SSQ_INDEX] =
		    sqn_base;
	}

	INIT_DELAYED_WORK(&suspend_sqe->timeout_work, spfc_do_port_reset);
	INIT_LIST_HEAD(&suspend_sqe->list_sqe_entry);

	spin_lock_irqsave(&parent_queue->parent_queue_state_lock, flag);
	list_add_tail(&suspend_sqe->list_sqe_entry, &sq->suspend_sqe_list);
	spin_unlock_irqrestore(&parent_queue->parent_queue_state_lock, flag);

	(void)queue_delayed_work(((struct spfc_hba_info *)hba)->work_queue,
					 &suspend_sqe->timeout_work,
					 (ulong)msecs_to_jiffies((u32)SPFC_SQ_NOP_TIMEOUT_MS));

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) magic num(0x%x)suspend sqe",
		     ((struct spfc_hba_info *)hba)->port_cfg.port_id, magic_num);
}

u32 spfc_pop_suspend_sqe(void *handle, struct spfc_parent_queue_info *parent_queue,
			 struct spfc_suspend_sqe_info *suspen_sqe)
{
	ulong flag;
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_parent_sq_info *sq = NULL;
	u16 ssqn;
	struct unf_frame_pkg *pkg = NULL;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)handle;
	u8 task_type;
	spinlock_t *prtq_state_lock = NULL;

	sq = &parent_queue->parent_sq_info;
	task_type = suspen_sqe->sqe.ts_sl.task_type;
	pkg = &suspen_sqe->pkg;
	if (!pkg) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT,
			     UNF_MAJOR, "[error]pkt is null.");
		return UNF_RETURN_ERROR;
	}

	ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) pop up suspend wqe sqn (0x%x) TaskType(0x%x)",
		     hba->port_cfg.port_id, ssqn, task_type);

	prtq_state_lock = &parent_queue->parent_queue_state_lock;
	spin_lock_irqsave(prtq_state_lock, flag);
	if (SPFC_RPORT_NOT_OFFLOADED(parent_queue) &&
	    (task_type == SPFC_SQE_ELS_RSP ||
	     task_type == SPFC_TASK_T_ELS)) {
		spin_unlock_irqrestore(prtq_state_lock, flag);
		/* Send PLOGI or PLOGI ACC or SCR if session not offload */
		ret = spfc_send_els_via_default_session(hba, &suspen_sqe->sqe, pkg, parent_queue);
	} else {
		spin_unlock_irqrestore(prtq_state_lock, flag);
		ret = spfc_parent_sq_enqueue(sq, &suspen_sqe->sqe, ssqn);
	}
	return ret;
}

static void spfc_build_nop_sqe(struct spfc_hba_info *hba, struct spfc_parent_sq_info *sq,
			       struct spfc_sqe *sqe, u32 magic_num, u32 scqn)
{
	sqe->ts_sl.task_type = SPFC_SQE_NOP;
	sqe->ts_sl.wd0.conn_id = (u16)(sq->rport_index);
	sqe->ts_sl.cont.nop_sq.wd0.scqn = scqn;
	sqe->ts_sl.cont.nop_sq.magic_num = magic_num;
	spfc_build_common_wqe_ctrls(&sqe->ctrl_sl,
				    sizeof(struct spfc_sqe_ts) / SPFC_WQE_SECTION_CHUNK_SIZE);
}

u32 spfc_send_nop_cmd(void *handle, struct spfc_parent_sq_info *parent_sq_info,
		      u32 magic_num, u16 sqn)
{
	struct spfc_sqe empty_sq_sqe;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)handle;
	u32 ret;

	memset(&empty_sq_sqe, 0, sizeof(struct spfc_sqe));

	spfc_build_nop_sqe(hba, parent_sq_info, &empty_sq_sqe, magic_num, hba->default_scqn);
	ret = spfc_parent_sq_enqueue(parent_sq_info, &empty_sq_sqe, sqn);
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]send nop cmd scqn(0x%x) sq(0x%x).",
		     hba->default_scqn, sqn);
	return ret;
}

u32 spfc_suspend_sqe_and_send_nop(void *handle,
				  struct spfc_parent_queue_info *parent_queue,
				  struct spfc_sqe *sqe, struct unf_frame_pkg *pkg)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 magic_num;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)handle;
	struct spfc_parent_sq_info *parent_sq = &parent_queue->parent_sq_info;
	struct unf_lport *lport = (struct unf_lport *)hba->lport;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);

	if (pkg) {
		magic_num = pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];
	} else {
		magic_num = (u32)atomic64_inc_return(&((struct unf_lport *)
						     lport->root_lport)->exchg_index);
	}

	spfc_push_sqe_suspend(hba, parent_queue, sqe, pkg, magic_num);
	if (SPFC_RPORT_NOT_OFFLOADED(parent_queue))
		parent_sq->need_offloaded = SPFC_NEED_DO_OFFLOAD;

	ret = spfc_send_nop_cmd(hba, parent_sq, magic_num,
				(u16)parent_sq->sqn_base);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[err]Port(0x%x) rport_index(0x%x)send sq empty failed.",
			     hba->port_cfg.port_id, parent_sq->rport_index);
	}
	return ret;
}

void spfc_build_session_rst_wqe(void *handle, struct spfc_parent_sq_info *sq,
				struct spfc_sqe *sqe, enum spfc_session_reset_mode mode, u32 scqn)
{
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	/* The reset session command does not occupy xid. Therefore,
	 * 0xffff can be used to align with the microcode.
	 */
	sqe->ts_sl.task_type = SPFC_SQE_SESS_RST;
	sqe->ts_sl.local_xid = 0xffff;
	sqe->ts_sl.wd0.conn_id = (u16)(sq->rport_index);
	sqe->ts_sl.wd0.remote_xid = 0xffff;
	sqe->ts_sl.cont.reset_session.wd0.reset_exch_start = hba->exi_base;
	sqe->ts_sl.cont.reset_session.wd0.reset_exch_end = hba->exi_base + (hba->exi_count - 1);
	sqe->ts_sl.cont.reset_session.wd1.reset_did = sq->remote_port_id;
	sqe->ts_sl.cont.reset_session.wd1.mode = mode;
	sqe->ts_sl.cont.reset_session.wd2.reset_sid = sq->local_port_id;
	sqe->ts_sl.cont.reset_session.wd3.scqn = scqn;

	spfc_build_common_wqe_ctrls(&sqe->ctrl_sl,
				    sizeof(struct spfc_sqe_ts) / SPFC_WQE_SECTION_CHUNK_SIZE);
}

u32 spfc_send_session_rst_cmd(void *handle,
			      struct spfc_parent_queue_info *parent_queue_info,
			      enum spfc_session_reset_mode mode)
{
	struct spfc_parent_sq_info *sq = NULL;
	struct spfc_sqe rst_sess_sqe;
	u32 ret = UNF_RETURN_ERROR;
	u32 sts_scqn = 0;
	struct spfc_hba_info *hba = NULL;

	hba = (struct spfc_hba_info *)handle;
	memset(&rst_sess_sqe, 0, sizeof(struct spfc_sqe));
	sq = &parent_queue_info->parent_sq_info;
	sts_scqn = hba->default_scqn;

	spfc_build_session_rst_wqe(hba, sq, &rst_sess_sqe, mode, sts_scqn);
	ret = spfc_suspend_sqe_and_send_nop(hba, parent_queue_info, &rst_sess_sqe, NULL);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]RPort(0x%x) send SESS_RST(%d) start_exch_id(0x%x) end_exch_id(0x%x), scqn(0x%x) ctx_id(0x%x) cid(0x%x)",
		     sq->rport_index, mode,
		     rst_sess_sqe.ts_sl.cont.reset_session.wd0.reset_exch_start,
		     rst_sess_sqe.ts_sl.cont.reset_session.wd0.reset_exch_end,
		     rst_sess_sqe.ts_sl.cont.reset_session.wd3.scqn,
		     sq->context_id, sq->cache_id);
	return ret;
}

void spfc_rcvd_els_from_srq_timeout(struct work_struct *work)
{
	struct spfc_hba_info *hba = NULL;

	hba = container_of(work, struct spfc_hba_info, srq_delay_info.del_work.work);

	/* If the frame is not processed, the frame is pushed to the CM layer:
	 * The frame may have been processed when the root rq receives data.
	 */
	if (hba->srq_delay_info.srq_delay_flag) {
		spfc_recv_els_cmnd(hba, &hba->srq_delay_info.frame_pkg,
				   hba->srq_delay_info.frame_pkg.unf_cmnd_pload_bl.buffer_ptr,
				   0, false);
		hba->srq_delay_info.srq_delay_flag = 0;

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) srq delay work timeout, send saved plgoi to CM",
			     hba->port_cfg.port_id);
	}
}

u32 spfc_flush_ini_resp_queue(void *handle)
{
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VALUE(handle, UNF_RETURN_ERROR);
	hba = (struct spfc_hba_info *)handle;

	spfc_flush_sts_scq(hba);

	return RETURN_OK;
}

static void spfc_handle_aeq_queue_error(struct spfc_hba_info *hba,
					struct spfc_aqe_data *aeq_msg)
{
	u32 sts_scqn_local = 0;
	u32 full_ci = INVALID_VALUE32;
	u32 full_ci_owner = INVALID_VALUE32;
	struct spfc_scq_info *scq_info = NULL;

	sts_scqn_local = SPFC_RPORTID_TO_STS_SCQN(aeq_msg->wd0.conn_id);
	scq_info = &hba->scq_info[sts_scqn_local];
	full_ci = scq_info->ci;
	full_ci_owner = scq_info->ci_owner;

	/* Currently, Flush is forcibly set to StsScq. No matter whether scq is
	 * processed, AEQE is returned
	 */
	tasklet_schedule(&scq_info->tasklet);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) RPort(0x%x) LocalScqn(0x%x) CqmScqn(0x%x) is full, force flush CI from (%u|0x%x) to (%u|0x%x)",
		     hba->port_cfg.port_id, aeq_msg->wd0.conn_id,
		     sts_scqn_local, scq_info->scqn, full_ci_owner, full_ci,
		     scq_info->ci_owner, scq_info->ci);
}

void spfc_process_aeqe(void *handle, u8 event_type, u8 *val)
{
	u32 ret = RETURN_OK;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)handle;
	struct spfc_aqe_data aeq_msg;
	u8 event_code = INVALID_VALUE8;
	u64 event_val = *((u64 *)val);

	FC_CHECK_RETURN_VOID(hba);

	memcpy(&aeq_msg, (struct spfc_aqe_data *)&event_val, sizeof(struct spfc_aqe_data));
	event_code = (u8)aeq_msg.wd0.evt_code;

	switch (event_type) {
	case FC_AEQ_EVENT_QUEUE_ERROR:
		spfc_handle_aeq_queue_error(hba, &aeq_msg);
		break;

	case FC_AEQ_EVENT_WQE_FATAL_ERROR:
		UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport,
					UNF_PORT_ABNORMAL_RESET, NULL);
		break;

	case FC_AEQ_EVENT_CTX_FATAL_ERROR:
		break;

	case FC_AEQ_EVENT_OFFLOAD_ERROR:
		ret = spfc_handle_aeq_off_load_err(hba, &aeq_msg);
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[warn]Port(0x%x) receive a unsupported AEQ EventType(0x%x) EventVal(0x%llx).",
			     hba->port_cfg.port_id, event_type, (u64)event_val);
		return;
	}

	if (event_code < FC_AEQ_EVT_ERR_CODE_BUTT)
		SPFC_AEQ_ERR_TYPE_STAT(hba, aeq_msg.wd0.evt_code);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[info]Port(0x%x) receive AEQ EventType(0x%x) EventVal(0x%llx) EvtCode(0x%x) Conn_id(0x%x) Xid(0x%x) %s",
		     hba->port_cfg.port_id, event_type, (u64)event_val, event_code,
		     aeq_msg.wd0.conn_id, aeq_msg.wd1.xid,
		     (ret == UNF_RETURN_ERROR) ? "ERROR" : "OK");
}

void spfc_sess_resource_free_sync(void *handle,
				  struct unf_port_info *rport_info)
{
	struct spfc_parent_queue_info *parent_queue_info = NULL;
	ulong flag = 0;
	u32 wait_sq_cnt = 0;
	struct spfc_hba_info *hba = NULL;
	spinlock_t *prtq_state_lock = NULL;
	u32 index = SPFC_DEFAULT_RPORT_INDEX;

	FC_CHECK_RETURN_VOID(handle);
	FC_CHECK_RETURN_VOID(rport_info);

	hba = (struct spfc_hba_info *)handle;
	parent_queue_info = &hba->parent_queue_mgr->parent_queue[index];
	prtq_state_lock = &parent_queue_info->parent_queue_state_lock;
	(void)spfc_free_parent_resource((void *)hba, rport_info);

	for (;;) {
		spin_lock_irqsave(prtq_state_lock, flag);
		if (parent_queue_info->offload_state == SPFC_QUEUE_STATE_FREE) {
			spin_unlock_irqrestore(prtq_state_lock, flag);
			break;
		}
		spin_unlock_irqrestore(prtq_state_lock, flag);
		msleep(SPFC_WAIT_SESS_FREE_ONE_TIME_MS);
		wait_sq_cnt++;
		if (wait_sq_cnt >= SPFC_MAX_WAIT_LOOP_TIMES)
			break;
	}
}
