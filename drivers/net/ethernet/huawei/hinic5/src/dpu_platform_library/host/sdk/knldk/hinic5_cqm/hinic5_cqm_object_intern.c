/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_object_intern.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"

#include "hinic5_cqm_object.h"
#include "hinic5_cqm_bitmap_table.h"
#include "hinic5_cqm_bat_cla.h"
#include "hinic5_cqm_main.h"
#include "hinic5_cqm_object_intern.h"

#define srq_obj_intern_if_section

/**
 * Prototype    : hinic5_cqm_container_free
 * Description  : Only the container buffer is released. The buffer in the WQE
 *		  and fast link tables are not involved.
 *		  Containers can be released from head to tail, including head
 *		  and tail. This function does not modify the start and
 *		  end pointers of qinfo records.
 * Input        : u8 *srq_head_container
 *		  u8 *srq_tail_container: If it is NULL, it means to release
 *					  container from head to tail.
 *		  struct tag_hinic5_cqm_queue *common
 * Output       : None
 * Return Value : void
 * 1.Date         : 2016/2/1
 *   Modification : Created function
 */
void hinic5_cqm_container_free(u8 *srq_head_container, u8 *srq_tail_container,
			struct tag_hinic5_cqm_queue *common)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(common->object.hinic5_cqm_handle);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	u32 link_wqe_offset = qinfo->wqe_per_buf * qinfo->wqe_size;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_srq_linkwqe *srq_link_wqe = NULL;
	u32 container_size = qinfo->container_size;
	struct device *dev = hinic5_cqm_handle->dev;
	u64 addr;
	u8 *srqhead_container = srq_head_container;
	u8 *srqtail_container = srq_tail_container;

	if (unlikely(srqhead_container == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(srqhead_container));
		return;
	}

	/* 1. The range is released cyclically from the head to the tail, i.e.
	 * [head:tail]. If the tail is null, the range is [head:null]. Oterwise,
	 * [head:tail->next).
	 */
	if (srqtail_container) {
		/* [head:tail->next): Update srqtail_container to the next
		 * container va.
		 */
		srq_link_wqe = (struct tag_hinic5_cqm_srq_linkwqe *)(srqtail_container +
							      link_wqe_offset);
		/* Only the link wqe part needs to be converted. */
		hinic5_cqm_swab32((u8 *)(srq_link_wqe), sizeof(struct tag_hinic5_cqm_linkwqe) >> HINIC5_CQM_DW_SHIFT);
		srqtail_container = (u8 *)(uintptr_t)HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->fixed_next_buffer_addr_h,
							    srq_link_wqe->fixed_next_buffer_addr_l);
	}

	do {
		/* 2. Obtain the link wqe of the current container */
		srq_link_wqe = (struct tag_hinic5_cqm_srq_linkwqe *)(srqhead_container +
							      link_wqe_offset);
		/* Only the link wqe part needs to be converted. */
		hinic5_cqm_swab32((u8 *)(srq_link_wqe), sizeof(struct tag_hinic5_cqm_linkwqe) >> HINIC5_CQM_DW_SHIFT);
		/* Obtain the va of the next container using the link wqe. */
		srqhead_container = (u8 *)(uintptr_t)HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->fixed_next_buffer_addr_h,
							    srq_link_wqe->fixed_next_buffer_addr_l);

		/* 3. Obtain the current container pa from the link wqe,
		 * and cancel the mapping
		 */
		addr = HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_gpa_h,
					srq_link_wqe->current_buffer_gpa_l);
		if (addr == 0) {
			hinic5_cqm_err(handle->dev_hdl, "Container free: buffer physical addr is null\n");
			return;
		}
		dma_unmap_single(dev, (dma_addr_t)addr, container_size,
				 DMA_BIDIRECTIONAL);

		/* 4. Obtain the container va through linkwqe and release the
		 * container va.
		 */
		addr = HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_addr_h,
					srq_link_wqe->current_buffer_addr_l);
		if (addr == 0) {
			hinic5_cqm_err(handle->dev_hdl, "Container free: buffer virtual addr is null\n");
			return;
		}
		kfree((void *)(uintptr_t)addr);
	} while (srqhead_container != srqtail_container);
}

static void hinic5_cqm_update_srq_link_wqe(u32 link_wqe_offset, u8 *new_container,
					   dma_addr_t new_container_pa)
{
	struct tag_hinic5_cqm_srq_linkwqe *srq_link_wqe =
		(struct tag_hinic5_cqm_srq_linkwqe *)((uintptr_t)new_container + link_wqe_offset);
	struct tag_hinic5_cqm_linkwqe *link_wqe = &srq_link_wqe->linkwqe;

	link_wqe->o = HINIC5_CQM_LINK_WQE_OWNER_INVALID;
	link_wqe->ctrlsl = HINIC5_CQM_LINK_WQE_CTRLSL_VALUE;
	link_wqe->lp = HINIC5_CQM_LINK_WQE_LP_INVALID;
	link_wqe->wf = HINIC5_CQM_WQE_WF_LINK;
	srq_link_wqe->current_buffer_gpa_h = HINIC5_CQM_ADDR_HI(new_container_pa);
	srq_link_wqe->current_buffer_gpa_l = HINIC5_CQM_ADDR_LW(new_container_pa);
	srq_link_wqe->current_buffer_addr_h = HINIC5_CQM_ADDR_HI((uintptr_t)new_container);
	srq_link_wqe->current_buffer_addr_l = HINIC5_CQM_ADDR_LW((uintptr_t)new_container);

	/* Convert only the area accessed by the chip to the network sequence */
	hinic5_cqm_swab32((u8 *)link_wqe, sizeof(struct tag_hinic5_cqm_linkwqe) >> HINIC5_CQM_DW_SHIFT);
}

/**
 * Prototype    : hinic5_cqm_container_create
 * Description  : Create a container for the RQ or SRQ, link it to the tail of
 *		  the queue, and update the tail container pointer of the queue.
 * Input        : struct tag_hinic5_cqm_object *object
 *		  u8 **container_addr
 *		  bool link
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/2/16
 *   Modification : Created function
 */
s32 hinic5_cqm_container_create(struct tag_hinic5_cqm_object *object, u8 **container_addr, bool link)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(object->hinic5_cqm_handle);
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo, common);
	u32 link_wqe_offset = qinfo->wqe_per_buf * qinfo->wqe_size;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_srq_linkwqe *srq_link_wqe = NULL;
	struct tag_hinic5_cqm_linkwqe *link_wqe = NULL;
	dma_addr_t new_container_pa;
	u8 *new_container = NULL;

	/* 1. Applying for Container Space and Initializing Invalid/Normal WQE
	 * of the Container.
	 */
	new_container = kzalloc(qinfo->container_size, GFP_ATOMIC);
	if (!new_container) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(new_container));
		return HINIC5_CQM_FAIL;
	}

	/* Container PCI mapping */
	new_container_pa = dma_map_single(hinic5_cqm_handle->dev, new_container, qinfo->container_size, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(hinic5_cqm_handle->dev, new_container_pa) != 0) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(new_container_pa));
		kfree(new_container);
		return HINIC5_CQM_FAIL;
	}

	/* 2. The container is linked to the SRQ, and the link wqe of
	 * tail_container and new_container is updated.
	 */
	/* If the SRQ is not empty, update the linkwqe of the tail container. */
	if (link) {
		if (common->tail_container) {
			srq_link_wqe = (struct tag_hinic5_cqm_srq_linkwqe *)(common->tail_container + link_wqe_offset);
			link_wqe = &srq_link_wqe->linkwqe;
			link_wqe->next_page_gpa_h = __swab32((u32)HINIC5_CQM_ADDR_HI(new_container_pa));
			link_wqe->next_page_gpa_l = __swab32((u32)HINIC5_CQM_ADDR_LW(new_container_pa));
			link_wqe->next_buffer_addr_h = __swab32((u32)HINIC5_CQM_ADDR_HI((uintptr_t)new_container));
			link_wqe->next_buffer_addr_l = __swab32((u32)HINIC5_CQM_ADDR_LW((uintptr_t)new_container));
			/* make sure next page gpa and next buffer addr of
			 * link wqe update first
			 */
			wmb();
			/* The SRQ tail container may be accessed by the chip.
			 * Therefore, obit must be set to 1 at last.
			 */
			(*(u32 *)(void *)link_wqe) |= 0x80;
			/* make sure obit set ahead of fixed next buffer addr
			 * updating of srq link wqe
			 */
			wmb();
			srq_link_wqe->fixed_next_buffer_addr_h = (u32)HINIC5_CQM_ADDR_HI((uintptr_t)new_container);
			srq_link_wqe->fixed_next_buffer_addr_l = (u32)HINIC5_CQM_ADDR_LW((uintptr_t)new_container);
		}
	}

	/* Update the Invalid WQE of a New Container */
	clear_bit(0x1F, (ulong *)new_container);
	/* Update the link wqe of the new container. */
	hinic5_cqm_update_srq_link_wqe(link_wqe_offset, new_container, new_container_pa);
	if (link)
		/* Update the tail pointer of a queue. */
		common->tail_container = new_container;
	else
		*container_addr = new_container;

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_srq_container_init
 * Description  : Initialize the SRQ to create all containers and link them.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/2/3
 *   Modification : Created function
 */
static s32 hinic5_cqm_srq_container_init(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 container_num = object->object_size;
	s32 ret;
	u32 i;

	if (common->head_container || common->tail_container) {
		hinic5_cqm_err(handle->dev_hdl, "Srq container init: srq tail/head container not null\n");
		return HINIC5_CQM_FAIL;
	}

	/* Applying for a Container
	 * During initialization, the head/tail pointer is null.
	 * After the first application is successful, head=tail.
	 */
	ret = hinic5_cqm_container_create(&qinfo->common.object, NULL, true);
	if (ret == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl, "Srq container init: hinic5_cqm_srq_container_add fail\n");
		return HINIC5_CQM_FAIL;
	}
	common->head_container = common->tail_container;

	/* The container is dynamically created and the tail pointer is updated.
	 * If the container fails to be created, release the containers from
	 * head to null.
	 */
	for (i = 1; i < container_num; i++) {
		ret = hinic5_cqm_container_create(&qinfo->common.object, NULL, true);
		if (ret == HINIC5_CQM_FAIL) {
			hinic5_cqm_container_free(common->head_container, NULL,
					   &qinfo->common);
			return HINIC5_CQM_FAIL;
		}
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_share_recv_queue_create
 * Description  : Create SRQ(share receive queue)
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2016/1/27
 *   Modification : Created function
 */
s32 hinic5_cqm_share_recv_queue_create(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_toe_private_capability *toe_own_cap = &hinic5_cqm_handle->toe_own_capability;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	u32 step;
	s32 ret;

	/* 1. Create srq container, including initializing  the link wqe. */
	ret = hinic5_cqm_srq_container_init(object);
	if (ret == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_srq_container_init));
		return HINIC5_CQM_FAIL;
	}

	/* 2. Create srq ctx: SRQ CTX is directly delivered by the driver to the
	 * chip memory area through the cmdq channel, and no CLA table
	 * management is required. Therefore, the HINIC5_CQM applies for only one empty
	 * buffer for the driver.
	 */
	/* bitmap applies for index */
	bitmap = &toe_own_cap->srqc_bitmap;
	qinfo->index_count = (ALIGN(qinfo->q_ctx_size,
				    toe_own_cap->toe_srqc_basic_size)) /
			     toe_own_cap->toe_srqc_basic_size;
	/* align with 2 as the upper bound */
	step = ALIGN(toe_own_cap->toe_srqc_number, 2);
	qinfo->common.index = hinic5_cqm_bitmap_alloc(bitmap, step, qinfo->index_count,
					       func_cap->xid_alloc_mode);
	if (qinfo->common.index >= bitmap->max_num) {
		hinic5_cqm_err(handle->dev_hdl, "Srq create: queue index %u exceeds max_num %u\n",
			qinfo->common.index, bitmap->max_num);
		goto err1;
	}
	qinfo->common.index += toe_own_cap->toe_srqc_start_id;

	/* apply for buffer for SRQC */
	common->q_ctx_vaddr = kzalloc(qinfo->q_ctx_size, GFP_KERNEL);
	if (!common->q_ctx_vaddr) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(q_ctx_vaddr));
		goto err2;
	}
	return HINIC5_CQM_SUCCESS;

err2:
	hinic5_cqm_bitmap_free(bitmap,
			qinfo->common.index - toe_own_cap->toe_srqc_start_id,
			qinfo->index_count);
err1:
	hinic5_cqm_container_free(common->head_container, common->tail_container,
			   &qinfo->common);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_srq_used_rq_delete
 * Description  : Delete RQ in TOE SRQ mode.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2016/5/19
 *   Modification : Created function
 */
static void hinic5_cqm_srq_used_rq_delete(const struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(common->object.hinic5_cqm_handle);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	u32 link_wqe_offset = qinfo->wqe_per_buf * qinfo->wqe_size;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_srq_linkwqe *srq_link_wqe = NULL;
	dma_addr_t addr;

	/* Currently, the SRQ solution does not support RQ initialization
	 * without mounting container.
	 * As a result, RQ resources are released incorrectly.
	 * Temporary workaround: Only one container is mounted during RQ
	 * initialization and only one container is released
	 * during resource release.
	 */
	if (unlikely(common->head_container == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR("Rq del: rq has no contianer to release\n");
		return;
	}

	/* 1. Obtain current container pa from the link wqe table and
	 * cancel the mapping.
	 */
	srq_link_wqe = (struct tag_hinic5_cqm_srq_linkwqe *)(common->head_container + link_wqe_offset);
	/* Only the link wqe part needs to be converted. */
	hinic5_cqm_swab32((u8 *)(srq_link_wqe), sizeof(struct tag_hinic5_cqm_linkwqe) >> HINIC5_CQM_DW_SHIFT);

	addr = HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_gpa_h,
				srq_link_wqe->current_buffer_gpa_l);
	if (addr == 0) {
		hinic5_cqm_err(handle->dev_hdl, "Rq del: buffer physical addr is null\n");
		return;
	}
	dma_unmap_single(hinic5_cqm_handle->dev, addr, qinfo->container_size,
			 DMA_BIDIRECTIONAL);

	/* 2. Obtain the container va through the linkwqe and release. */
	addr = HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_addr_h,
				srq_link_wqe->current_buffer_addr_l);
	if (addr == 0) {
		hinic5_cqm_err(handle->dev_hdl, "Rq del: buffer virtual addr is null\n");
		return;
	}
	kfree((void *)(uintptr_t)addr);
}

/**
 * Prototype    : hinic5_cqm_share_recv_queue_delete
 * Description  : The SRQ object is deleted. Delete only containers that are not
 *		  used by SRQ, that is, containers from the head to the tail.
 *		  The RQ releases containers that have been used by the RQ.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2016/2/2
 *   Modification : Created function
 */
void hinic5_cqm_share_recv_queue_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_bitmap *bitmap = &hinic5_cqm_handle->toe_own_capability.srqc_bitmap;
	u32 index = common->index - hinic5_cqm_handle->toe_own_capability.toe_srqc_start_id;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	/* 1. Wait for completion and ensure that all references to the QPC
	 * are complete.
	 */
	if (atomic_dec_and_test(&object->refcount) != 0)
		complete(&object->free);
	else
		hinic5_cqm_err(handle->dev_hdl, "Srq del: object is referred by others, has to wait for completion\n");

	wait_for_completion(&object->free);
	destroy_completion(&object->free);
	/* 2. The corresponding index in the bitmap is cleared. */
	hinic5_cqm_bitmap_free(bitmap, index, qinfo->index_count);

	/* 3. SRQC resource release */
	if (unlikely(common->q_ctx_vaddr == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR("Srq del: srqc kfree, context virtual addr is null\n");
		return;
	}
	kfree(common->q_ctx_vaddr);

	/* 4. The SRQ queue is released. */
	hinic5_cqm_container_free(common->head_container, NULL, &qinfo->common);
}

#define obj_intern_if_section

/* include dynamic and static applications. */
static u32 hinic5_cqm_general_bitmap_alloc(struct tag_hinic5_cqm_object *object,
				    struct tag_hinic5_cqm_cla_table *cla_table,
				    struct tag_hinic5_cqm_bitmap_range *bp_range,
				    u32 xid, u32 count)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_bitmap *bitmap = &cla_table->bitmap;
	u32 index;

	if (HINIC5_CQM_DYNAMIC_XID_ALLOC_MODE(xid)) {
		if (HINIC5_CQM_DYNAMIC_XID_LB_MODE(xid) != HINIC5_CQM_XID_LOW_BIT_NONE ||
		    HINIC5_CQM_DYNAMIC_XID_SEARCH_MODE(xid) != HINIC5_CQM_XID_SEARCH_ALL) {
			if (count > 1) {
				hinic5_cqm_warn(handle->dev_hdl, "Not support alloc multiple bits.\n");
				return HINIC5_CQM_INDEX_INVALID;
			}
			index = hinic5_cqm_bitmap_alloc_lowbits_align(bitmap, bp_range, hinic5_cqm_handle,
							       xid, func_cap->xid_alloc_mode);
		} else {
			/* apply for an index normally */
			index = hinic5_cqm_bitmap_alloc(bitmap, 1U << (cla_table->z + 1),
						 count, func_cap->xid_alloc_mode);
		}

		if (index >= bitmap->max_num - bitmap->reserved_back) {
			hinic5_cqm_warn(handle->dev_hdl,
					"cqm bitmap alloc, index is err. index:0x%x, max_num:0x%x, reserved_back:0x%x\n",
					index, bitmap->max_num, bitmap->reserved_back);
			return HINIC5_CQM_INDEX_INVALID;
		}
	} else {
		if ((IS_MASTER_HOST(handle)) && (hinic5_func_type((void *)handle) != TYPE_PPF) &&
			(hinic5_support_vroce((void *)handle, NULL))) {
			/* If PF is vroce control function, apply for index by xid */
			index = hinic5_cqm_bitmap_alloc_by_xid(bitmap, count, xid);
		} else {
			/* apply for index to be reserved */
			index = hinic5_cqm_bitmap_alloc_reserved(bitmap, count, xid);
		}
		if (index != xid) {
			hinic5_cqm_warn(handle->dev_hdl,
					"cqm bitmap alloc, index(0x%x) != xid(0x%x).\n",
					index, xid);
			return HINIC5_CQM_INDEX_INVALID;
		}
	}

	return index;
}

/**
 * Prototype    : hinic5_cqm_qpc_mpt_bitmap_alloc
 * Description  : Apply for index from the bitmap when creating QPC or MPT.
 * Input        : struct tag_hinic5_cqm_object *object
 *                struct tag_hinic5_cqm_cla_table *cla_table
 *                struct tag_hinic5_cqm_bitmap_range *bp_range
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
static s32 hinic5_cqm_qpc_mpt_bitmap_alloc(struct tag_hinic5_cqm_object *object,
				    struct tag_hinic5_cqm_cla_table *cla_table,
				    struct tag_hinic5_cqm_bitmap_range *bp_range)
{
	struct tag_hinic5_cqm_qpc_mpt *common = container_of(object, struct tag_hinic5_cqm_qpc_mpt, object);
	struct tag_hinic5_cqm_qpc_mpt_info *qpc_mpt_info = container_of(common,
								 struct tag_hinic5_cqm_qpc_mpt_info,
								 common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 xid = qpc_mpt_info->common.xid;

	qpc_mpt_info->index_count =
		(ALIGN(object->object_size, cla_table->obj_size)) / cla_table->obj_size;
	qpc_mpt_info->common.xid = hinic5_cqm_general_bitmap_alloc(object, cla_table, bp_range,
							    xid, qpc_mpt_info->index_count);
	if (qpc_mpt_info->common.xid == HINIC5_CQM_INDEX_INVALID) {
		hinic5_cqm_warn(handle->dev_hdl,
			HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_general_bitmap_alloc));
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_qpc_mpt_create
 * Description  : Create QPC or MPT
 * Input        : struct tag_hinic5_cqm_object *object
 *                struct tag_hinic5_cqm_bitmap_range *bp_range
 * Output       : None
 * Return Value : s32
 * 1.Date   : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_qpc_mpt_create(struct tag_hinic5_cqm_object *object, struct tag_hinic5_cqm_bitmap_range *bp_range)
{
	struct tag_hinic5_cqm_qpc_mpt *common = container_of(object, struct tag_hinic5_cqm_qpc_mpt, object);
	struct tag_hinic5_cqm_qpc_mpt_info *qpc_mpt_info = container_of(common, struct tag_hinic5_cqm_qpc_mpt_info, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	bool is_lock_bh;
	u32 index, count;

	/* find the corresponding cla table */
	if (object->object_type == HINIC5_CQM_OBJECT_SERVICE_CTX) {
		cla_table = hinic5_cqm_cla_table_get(&hinic5_cqm_handle->bat_table, HINIC5_CQM_BAT_ENTRY_T_QPC);
	} else if (object->object_type == HINIC5_CQM_OBJECT_MPT) {
		cla_table = hinic5_cqm_cla_table_get(&hinic5_cqm_handle->bat_table, HINIC5_CQM_BAT_ENTRY_T_MPT);
	} else {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object->object_type));
		return HINIC5_CQM_FAIL;
	}

	if (unlikely(cla_table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_table_get));
		return HINIC5_CQM_FAIL;
	}

	/* Bitmap applies for index. */
	if (hinic5_cqm_qpc_mpt_bitmap_alloc(object, cla_table, bp_range) == HINIC5_CQM_FAIL) {
		hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_qpc_mpt_bitmap_alloc));
		return HINIC5_CQM_FAIL;
	}

	bitmap = &cla_table->bitmap;
	index = qpc_mpt_info->common.xid;
	count = qpc_mpt_info->index_count;

	/* Find the trunk page from the BAT/CLA and allocate the buffer.
	 * Ensure that the released buffer has been cleared.
	 */
	if (!HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle)) {
		/* The CLA memory of the Fake VF are holded by the parent
		 * function, so the Fake VF can't get the memory. */
		qpc_mpt_info->common.vaddr = hinic5_cqm_cla_get(hinic5_cqm_handle, cla_table,
							 index, count, &common->paddr);

		if (!qpc_mpt_info->common.vaddr) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_get));
			hinic5_cqm_err(handle->dev_hdl,
				"Qpc mpt init: qpc mpt vaddr is null, alloc_static=%d\n",
				cla_table->alloc_static);
			goto err1;
		}
	}

	/* Indexes are associated with objects, and FC is executed
	 * in the interrupt context.
	 */
	object_table = &cla_table->obj_table;
	is_lock_bh = (object->service_type != HINIC5_CQM_SERVICE_T_FC);
	if (hinic5_cqm_object_table_insert(hinic5_cqm_handle, object_table, index, object, is_lock_bh) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_table_insert));
		goto err2;
	}

	return HINIC5_CQM_SUCCESS;

err2:
	hinic5_cqm_cla_put(hinic5_cqm_handle, cla_table, index, count);
err1:
	hinic5_cqm_bitmap_free(bitmap, index, count);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_qpc_mpt_delete
 * Description  : Delete QPC or MPT.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_qpc_mpt_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_qpc_mpt *common = container_of(object, struct tag_hinic5_cqm_qpc_mpt, object);
	struct tag_hinic5_cqm_qpc_mpt_info *qpc_mpt_info = container_of(common,
								 struct tag_hinic5_cqm_qpc_mpt_info,
								 common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	u32 count = qpc_mpt_info->index_count;
	u32 index = qpc_mpt_info->common.xid;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_qpc_mpt_delete_cnt);

	/* find the corresponding cla table */
	if (object->object_type == HINIC5_CQM_OBJECT_SERVICE_CTX) {
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_QPC);
	} else if (object->object_type == HINIC5_CQM_OBJECT_MPT) {
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_MPT);
	} else {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object->object_type));
		return;
	}

	if (unlikely(cla_table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_table_get_qpc));
		return;
	}

	/* disassociate index and object */
	object_table = &cla_table->obj_table;
	if (object->service_type == HINIC5_CQM_SERVICE_T_FC)
		hinic5_cqm_object_table_remove(hinic5_cqm_handle, object_table, index, object,
					false);
	else
		hinic5_cqm_object_table_remove(hinic5_cqm_handle, object_table, index, object,
					true);

	/* wait for completion to ensure that all references to
	 * the QPC are complete
	 */
	if (atomic_dec_and_test(&object->refcount) != 0)
		complete(&object->free);
	else
		hinic5_cqm_err(handle->dev_hdl, "Qpc mpt del: object is referred by others, has to wait for completion\n");

	/* Static QPC allocation must be non-blocking.
	 * Services ensure that the QPC is referenced
	 * when the QPC is deleted. Roce and UB service
	 * should depend on completion to avoid race condition.
	 */
	if (!cla_table->alloc_static || object->service_type == HINIC5_CQM_SERVICE_T_ROCE ||
	    object->service_type == HINIC5_CQM_SERVICE_T_UB)
		wait_for_completion(&object->free);

	/* VMware  FC need explicitly deinit spin_lock in completion */
	destroy_completion(&object->free);

	/* release qpc buffer */
	hinic5_cqm_cla_put(hinic5_cqm_handle, cla_table, index, count);

	/* release the index to the bitmap */
	bitmap = &cla_table->bitmap;
	hinic5_cqm_bitmap_free(bitmap, index, count);
}

/**
 * Prototype    : hinic5_cqm_linkwqe_fill
 * Description  : Used to organize the queue buffer of non-RDMA services and
 *		  fill the link wqe.
 * Input        : wqe_per_buf: Linkwqe is not included.
 *		  wqe_number: Linkwqe is not included.
 *		  tail: true - The linkwqe must be at the end of the page;
 *			false - The linkwqe can be not at the end of the page.
 * Output       : None
 * Return Value : void
 * 1.Date   : 2015/6/15
 *   Modification : Created function
 */
static void hinic5_cqm_linkwqe_fill(struct tag_hinic5_cqm_buf *buf, u32 wqe_per_buf, u32 wqe_size,
			     u32 wqe_number, bool tail, u8 link_mode)
{
	struct tag_hinic5_cqm_linkwqe_128B *linkwqe = NULL;
	struct tag_hinic5_cqm_linkwqe *wqe = NULL;
	dma_addr_t addr;
	u8 *tmp = NULL;
	u8 *va = NULL;
	u32 i;

	/* The linkwqe of other buffer except the last buffer
	 * is directly filled to the tail.
	 */
	for (i = 0; i < buf->buf_number; i++) {
		va = (u8 *)(buf->buf_list[i].va);

		if (i != (buf->buf_number - 1)) {
			wqe = (struct tag_hinic5_cqm_linkwqe *)(va + (u32)(wqe_size * wqe_per_buf));
			wqe->wf = HINIC5_CQM_WQE_WF_LINK;
			wqe->ctrlsl = HINIC5_CQM_LINK_WQE_CTRLSL_VALUE;
			wqe->lp = HINIC5_CQM_LINK_WQE_LP_INVALID;
			/* The valid value of link wqe needs to be set to 1.
			 * Each service ensures that o-bit=1 indicates that
			 * link wqe is valid and o-bit=0 indicates that
			 * link wqe is invalid.
			 */
			wqe->o = HINIC5_CQM_LINK_WQE_OWNER_VALID;
			addr = buf->buf_list[(u32)(i + 1)].pa;
			wqe->next_page_gpa_h = HINIC5_CQM_ADDR_HI(addr);
			wqe->next_page_gpa_l = HINIC5_CQM_ADDR_LW(addr);
		} else { /* linkwqe special padding of the last buffer */
			if (tail) {
				/* must be filled at the end of the page */
				tmp = va + (u32)(wqe_size * wqe_per_buf);
				wqe = (struct tag_hinic5_cqm_linkwqe *)tmp;
			} else {
				/* The last linkwqe is filled
				 * following the last wqe.
				 */
				tmp = va + (u32)(wqe_size * (wqe_number - wqe_per_buf *
							     (buf->buf_number - 1)));
				wqe = (struct tag_hinic5_cqm_linkwqe *)tmp;
			}
			wqe->wf = HINIC5_CQM_WQE_WF_LINK;
			wqe->ctrlsl = HINIC5_CQM_LINK_WQE_CTRLSL_VALUE;

			/* In link mode, the last link WQE is invalid;
			 * In ring mode, the last link wqe is valid, pointing to
			 * the home page, and the lp is set.
			 */
			if (link_mode == HINIC5_CQM_QUEUE_LINK_MODE) {
				wqe->o = HINIC5_CQM_LINK_WQE_OWNER_INVALID;
			} else {
				/* The lp field of the last link_wqe is set to
				 * 1, indicating that the meaning of the o-bit
				 * is reversed.
				 */
				wqe->lp = HINIC5_CQM_LINK_WQE_LP_VALID;
				wqe->o = HINIC5_CQM_LINK_WQE_OWNER_VALID;
				addr = buf->buf_list[0].pa;
				wqe->next_page_gpa_h = HINIC5_CQM_ADDR_HI(addr);
				wqe->next_page_gpa_l = HINIC5_CQM_ADDR_LW(addr);
			}
		}

		if (wqe_size == HINIC5_CQM_LINKWQE_128B) {
			/* After the B800 version, the WQE obit scheme is
			 * changed. The 64B bits before and after the 128B WQE
			 * need to be assigned a value:
			 * ifoe the 63rd bit from the end of the last 64B is
			 * obit;
			 * toe  the 157th bit from the end of the last 64B is
			 * obit.
			 */
			linkwqe = (struct tag_hinic5_cqm_linkwqe_128B *)(void *)wqe;
			linkwqe->second64B.third_16B.bs.toe_o = HINIC5_CQM_LINK_WQE_OWNER_VALID;
			linkwqe->second64B.forth_16B.bs.ifoe_o = HINIC5_CQM_LINK_WQE_OWNER_VALID;

			/* shift 2 bits by right to get length of dw(4B) */
			hinic5_cqm_swab32((u8 *)wqe, sizeof(struct tag_hinic5_cqm_linkwqe_128B) >> 2);
		} else {
			/* shift 2 bits by right to get length of dw(4B) */
			hinic5_cqm_swab32((u8 *)wqe, sizeof(struct tag_hinic5_cqm_linkwqe) >> 2);
		}
	}
}

static int hinic5_cqm_nonrdma_queue_ctx_create_scq(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	bool bh = false;

	/* find the corresponding cla table */
	cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SCQC);
	if (!cla_table) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(nonrdma_hinic5_cqm_cla_table_get));
		return HINIC5_CQM_FAIL;
	}

	/* bitmap applies for index */
	bitmap = &cla_table->bitmap;
	qinfo->index_count = (ALIGN(qinfo->q_ctx_size, cla_table->obj_size)) / cla_table->obj_size;
	qinfo->common.index = hinic5_cqm_bitmap_alloc(bitmap, 1U << (cla_table->z + 1),
					       qinfo->index_count,
					       hinic5_cqm_handle->func_capability.xid_alloc_mode);
	if (qinfo->common.index >= bitmap->max_num) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(nonrdma_hinic5_cqm_bitmap_alloc));
		return HINIC5_CQM_FAIL;
	}

	/* find the trunk page from BAT/CLA and allocate the buffer */
	common->q_ctx_vaddr = hinic5_cqm_cla_get(hinic5_cqm_handle, cla_table, qinfo->common.index,
					  qinfo->index_count, &common->q_ctx_paddr);
	if (!common->q_ctx_vaddr) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(nonrdma_hinic5_cqm_cla_get_lock));
		hinic5_cqm_bitmap_free(bitmap, qinfo->common.index, qinfo->index_count);
		return HINIC5_CQM_FAIL;
	}

	/* index and object association */
	object_table = &cla_table->obj_table;
	bh = (object->service_type == HINIC5_CQM_SERVICE_T_FC) ? false : true;
	if (hinic5_cqm_object_table_insert(hinic5_cqm_handle, object_table, qinfo->common.index, object,
				    bh) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(nonrdma_hinic5_cqm_object_table_insert));
		hinic5_cqm_cla_put(hinic5_cqm_handle, cla_table, qinfo->common.index, qinfo->index_count);
		hinic5_cqm_bitmap_free(bitmap, qinfo->common.index, qinfo->index_count);

		return HINIC5_CQM_FAIL;
	}

	return 0;
}

static s32 hinic5_cqm_nonrdma_queue_ctx_create(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo,
							   common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 shift;
	int ret;

	if (object->object_type == HINIC5_CQM_OBJECT_NONRDMA_SRQ) {
		shift = hinic5_cqm_shift(qinfo->q_ctx_size);
		common->q_ctx_vaddr = hinic5_cqm_kmalloc_align(qinfo->q_ctx_size,
							GFP_KERNEL | __GFP_ZERO,
							(u16)shift);
		if (!common->q_ctx_vaddr) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(q_ctx_vaddr));
			return HINIC5_CQM_FAIL;
		}

		common->q_ctx_paddr = dma_map_single(hinic5_cqm_handle->dev, common->q_ctx_vaddr,
						     qinfo->q_ctx_size, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(hinic5_cqm_handle->dev, common->q_ctx_paddr) != 0) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(q_ctx_vaddr));
			hinic5_cqm_kfree_align(common->q_ctx_vaddr);
			common->q_ctx_vaddr = NULL;
			return HINIC5_CQM_FAIL;
		}
	} else if (object->object_type == HINIC5_CQM_OBJECT_NONRDMA_SCQ) {
		ret = hinic5_cqm_nonrdma_queue_ctx_create_scq(object);
		if (ret != 0)
			return ret;
	}

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_free_queue_header(struct tag_hinic5_cqm_queue *common, struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
	struct hinic5_hwdev *handle)
{
	dma_unmap_single(hinic5_cqm_handle->dev, common->q_header_paddr, sizeof(struct tag_hinic5_cqm_queue_header),
		DMA_BIDIRECTIONAL);

	hinic5_cqm_kfree_align(common->q_header_vaddr);
	common->q_header_vaddr = NULL;
}

static s32 hinic5_cqm_alloc_queue_header(struct tag_hinic5_cqm_queue *common, struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
	struct hinic5_hwdev *handle)
{
	common->q_header_vaddr = hinic5_cqm_kmalloc_align(sizeof(struct tag_hinic5_cqm_queue_header),
		GFP_KERNEL | __GFP_ZERO, HINIC5_CQM_QHEAD_ALIGN_ORDER);
	if (!common->q_header_vaddr) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(q_header_vaddr));
		return HINIC5_CQM_FAIL;
	}

	common->q_header_paddr = dma_map_single(hinic5_cqm_handle->dev, common->q_header_vaddr,
		sizeof(struct tag_hinic5_cqm_queue_header), DMA_BIDIRECTIONAL);
	if (dma_mapping_error(hinic5_cqm_handle->dev, common->q_header_paddr) != 0) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(q_header_vaddr));
		hinic5_cqm_kfree_align(common->q_header_vaddr);
		common->q_header_vaddr = NULL;
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}
/**
 * Prototype    : hinic5_cqm_nonrdma_queue_create
 * Description  : Create a queue for non-RDMA services.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_nonrdma_queue_create(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_buf *q_room_buf = &common->q_room_buf_1;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 wqe_number = qinfo->common.object.object_size;
	u32 wqe_size = qinfo->wqe_size;
	u32 order = hinic5_cqm_handle->service[object->service_type].buf_order;
	u32 buf_number, buf_size;
	bool tail = false; /* determine whether the linkwqe is at the end of the page */

	/* When creating a CQ/SCQ queue, the page size is 4 KB,
	 * the linkwqe must be at the end of the page.
	 */
	if (object->object_type == HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_CQ || object->object_type == HINIC5_CQM_OBJECT_NONRDMA_SCQ) {
		/* depth: 2^n-aligned; depth range: 256-32 K */
		if (wqe_number < HINIC5_CQM_CQ_DEPTH_MIN || wqe_number > HINIC5_CQM_CQ_DEPTH_MAX) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(wqe_number));
			return HINIC5_CQM_FAIL;
		}
		if (!hinic5_cqm_check_align(wqe_number)) {
			hinic5_cqm_err(handle->dev_hdl, "Nonrdma queue alloc: wqe_number is not align on 2^n\n");
			return HINIC5_CQM_FAIL;
		}

		order = HINIC5_CQM_4K_PAGE_ORDER; /* wqe page 4k */
		tail = true; /* The linkwqe must be at the end of the page. */
		buf_size = HINIC5_CQM_4K_PAGE_SIZE;
	} else {
		buf_size = (u32)(PAGE_SIZE << order);
	}

	/* Calculate the total number of buffers required,
	 * -1 indicates that the link wqe in a buffer is deducted.
	 */
	qinfo->wqe_per_buf = (buf_size / wqe_size) - 1;
	/* number of linkwqes that are included in the depth transferred
	 * by the service
	 */
	buf_number = ALIGN((wqe_size * wqe_number), buf_size) / buf_size;

	/* apply for buffer */
	q_room_buf->buf_number = buf_number;
	q_room_buf->buf_size = buf_size;
	q_room_buf->page_number = buf_number << order;
	if (hinic5_cqm_buf_alloc(hinic5_cqm_handle, q_room_buf, false) == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_buf_alloc));
		return HINIC5_CQM_FAIL;
	}
	/* fill link wqe, wqe_number - buf_number is the number of wqe without
	 * link wqe
	 */
	hinic5_cqm_linkwqe_fill(q_room_buf, qinfo->wqe_per_buf, wqe_size, wqe_number - buf_number, tail, common->queue_link_mode);

	/* create queue header */
	if (hinic5_cqm_alloc_queue_header(common, hinic5_cqm_handle, handle) != HINIC5_CQM_SUCCESS) {
		goto err1;
	}

	/* create queue ctx */
	if (hinic5_cqm_nonrdma_queue_ctx_create(object) == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_nonrdma_queue_ctx_create));
		goto err2;
	}

	return HINIC5_CQM_SUCCESS;

err2:
	hinic5_cqm_free_queue_header(common, hinic5_cqm_handle, handle);
err1:
	hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_nonrdma_queue_delete
 * Description  : Delete the queues of non-RDMA services.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_nonrdma_queue_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct tag_hinic5_cqm_buf *q_room_buf = &common->q_room_buf_1;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	u32 index = qinfo->common.index;
	u32 count = qinfo->index_count;

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_nonrdma_queue_delete_cnt);

	/* The SCQ has an independent SCQN association. */
	if (object->object_type == HINIC5_CQM_OBJECT_NONRDMA_SCQ) {
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SCQC);
		if (unlikely(cla_table == NULL)) {
			HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_table_get_queue));
			return;
		}

		/* disassociate index and object */
		object_table = &cla_table->obj_table;
		hinic5_cqm_object_table_remove(hinic5_cqm_handle, object_table, index, object, object->service_type != HINIC5_CQM_SERVICE_T_FC);
	}

	/* wait for completion to ensure that all references to
	 * the QPC are complete
	 */
	if (atomic_dec_and_test(&object->refcount) != 0)
		complete(&object->free);
	else
		hinic5_cqm_err(handle->dev_hdl, "Nonrdma queue del: object is referred by others, has to wait for completion\n");

	wait_for_completion(&object->free);
	destroy_completion(&object->free);

	/* If the q header exists, release. */
	if (qinfo->common.q_header_vaddr) {
		dma_unmap_single(hinic5_cqm_handle->dev, common->q_header_paddr, sizeof(struct tag_hinic5_cqm_queue_header),
			DMA_BIDIRECTIONAL);

		hinic5_cqm_kfree_align(qinfo->common.q_header_vaddr);
		qinfo->common.q_header_vaddr = NULL;
	}

	/* RQ deletion in TOE SRQ mode */
	if (common->queue_link_mode == HINIC5_CQM_QUEUE_TOE_SRQ_LINK_MODE)
		hinic5_cqm_srq_used_rq_delete(&common->object);
	else
		/* If q room exists, release. */
		hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);
	/* SRQ and SCQ have independent CTXs and release. */
	if (object->object_type == HINIC5_CQM_OBJECT_NONRDMA_SRQ) {
		/* The CTX of the SRQ of the nordma is
		 * applied for independently.
		 */
		if (common->q_ctx_vaddr) {
			dma_unmap_single(hinic5_cqm_handle->dev, common->q_ctx_paddr, qinfo->q_ctx_size, DMA_BIDIRECTIONAL);

			hinic5_cqm_kfree_align(common->q_ctx_vaddr);
			common->q_ctx_vaddr = NULL;
		}
	} else if (object->object_type == HINIC5_CQM_OBJECT_NONRDMA_SCQ) {
		/* The CTX of the SCQ of the nordma is managed by BAT/CLA. */
		hinic5_cqm_cla_put(hinic5_cqm_handle, cla_table, index, count);

		/* release the index to the bitmap */
		bitmap = &cla_table->bitmap;
		hinic5_cqm_bitmap_free(bitmap, index, count);
	}
}

static s32 hinic5_cqm_rdma_queue_ctx_create(struct tag_hinic5_cqm_object *object, struct tag_hinic5_cqm_bitmap_range *bp_range)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_rdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_rdma_qinfo, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;

	if (object->object_type == HINIC5_CQM_OBJECT_RDMA_SRQ || object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ) {
		if (object->object_type == HINIC5_CQM_OBJECT_RDMA_SRQ)
			cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SRQC);
		else
			cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SCQC);

		if (!cla_table) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(rdma_hinic5_cqm_cla_table_get));
			return HINIC5_CQM_FAIL;
		}

		qinfo->index_count = (ALIGN(qinfo->q_ctx_size, cla_table->obj_size)) / cla_table->obj_size;
		qinfo->common.index = hinic5_cqm_general_bitmap_alloc(object, cla_table, bp_range, qinfo->common.index,
			qinfo->index_count);
		if (qinfo->common.index == HINIC5_CQM_INDEX_INVALID) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_general_bitmap_alloc));
			return HINIC5_CQM_FAIL;
		}

		/* bitmap applies for index */
		bitmap = &cla_table->bitmap;

		/* find the trunk page from BAT/CLA and allocate the buffer */
		if (!HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle)) {
			/* The CLA memory of the Fake VF are holded by the parent
			 * function, so the Fake VF can't get the memory. */
			qinfo->common.q_ctx_vaddr =
				hinic5_cqm_cla_get(hinic5_cqm_handle, cla_table, qinfo->common.index,
					    qinfo->index_count, &qinfo->common.q_ctx_paddr);
			if (!qinfo->common.q_ctx_vaddr) {
				hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(rdma_hinic5_cqm_cla_get_lock));
				hinic5_cqm_bitmap_free(bitmap, qinfo->common.index, qinfo->index_count);
				return HINIC5_CQM_FAIL;
			}
		}

		/* associate index and object */
		object_table = &cla_table->obj_table;
		if (hinic5_cqm_object_table_insert(hinic5_cqm_handle, object_table, qinfo->common.index, object, true) != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(rdma_hinic5_cqm_object_table_insert));
			hinic5_cqm_cla_put(hinic5_cqm_handle, cla_table, qinfo->common.index, qinfo->index_count);
			hinic5_cqm_bitmap_free(bitmap, qinfo->common.index, qinfo->index_count);
			return HINIC5_CQM_FAIL;
		}
	}

	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_qinfo_judgment(struct tag_hinic5_cqm_rdma_qinfo *qinfo, struct tag_hinic5_cqm_buf *q_room_buf,
			      struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct hinic5_hwdev *handle)
{
		if (hinic5_cqm_buf_alloc(hinic5_cqm_handle, q_room_buf, true) == HINIC5_CQM_FAIL) {
			hinic5_cqm_err(handle->dev_hdl,
				HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_buf_alloc));
			return HINIC5_CQM_FAIL;
		}

		/* queue header */
		qinfo->common.q_header_vaddr =
		    hinic5_cqm_kmalloc_align(sizeof(struct tag_hinic5_cqm_queue_header),
				      GFP_KERNEL | __GFP_ZERO,
				      HINIC5_CQM_QHEAD_ALIGN_ORDER);
		if (!qinfo->common.q_header_vaddr) {
			hinic5_cqm_err(handle->dev_hdl,
				HINIC5_CQM_ALLOC_FAIL(q_header_vaddr));

			if (qinfo->room_header_alloc)
				hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);

			return HINIC5_CQM_FAIL;
		}

		qinfo->common.q_header_paddr =
		    dma_map_single(hinic5_cqm_handle->dev,
				   qinfo->common.q_header_vaddr,
				   sizeof(struct tag_hinic5_cqm_queue_header),
				   DMA_BIDIRECTIONAL);
		if (dma_mapping_error(hinic5_cqm_handle->dev,
					  qinfo->common.q_header_paddr) != 0) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(q_header_vaddr));

			if (qinfo->room_header_alloc) {
				hinic5_cqm_kfree_align(qinfo->common.q_header_vaddr);
				qinfo->common.q_header_vaddr = NULL;
			}

			if (qinfo->room_header_alloc)
				hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);

			return HINIC5_CQM_FAIL;
		}

		return 0;
}

/**
 * Prototype    : hinic5_cqm_rdma_queue_create
 * Description  : Create rdma queue.
 * Input        : struct tag_hinic5_cqm_object *object
 *              : struct tag_hinic5_cqm_bitmap_range *bp_range
 * Output       : None
 * Return Value : s32
 * 1.Date          : 2015/4/15
 *    Modification : Created function
 */
s32 hinic5_cqm_rdma_queue_create(struct tag_hinic5_cqm_object *object, struct tag_hinic5_cqm_bitmap_range *bp_range)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_rdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_rdma_qinfo,
							common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_service *service = hinic5_cqm_handle->service + object->service_type;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *q_room_buf = NULL;
	u32 order = service->buf_order;
	u32 buf_size = (u32)(PAGE_SIZE << order);

	if (qinfo->room_header_alloc) {
		/* apply for queue room buffer */
		if (qinfo->common.current_q_room == HINIC5_CQM_RDMA_Q_ROOM_1)
			q_room_buf = &qinfo->common.q_room_buf_1;
		else
			q_room_buf = &qinfo->common.q_room_buf_2;

		q_room_buf->buf_number = ALIGN(object->object_size, buf_size) /
					 buf_size;
		q_room_buf->page_number = (q_room_buf->buf_number << order);
		q_room_buf->buf_size = buf_size;

		if (hinic5_cqm_qinfo_judgment(qinfo, q_room_buf, hinic5_cqm_handle, handle) == HINIC5_CQM_FAIL) {
			return HINIC5_CQM_FAIL;
		}
	}

	/* queue ctx */
	if (hinic5_cqm_rdma_queue_ctx_create(object, bp_range) == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_rdma_queue_ctx_create));

		if (qinfo->room_header_alloc) {
			dma_unmap_single(hinic5_cqm_handle->dev, qinfo->common.q_header_paddr,
					 sizeof(struct tag_hinic5_cqm_queue_header),
					 DMA_BIDIRECTIONAL);
		}

		if (qinfo->room_header_alloc) {
			hinic5_cqm_kfree_align(qinfo->common.q_header_vaddr);
			qinfo->common.q_header_vaddr = NULL;
		}

		if (qinfo->room_header_alloc) {
			hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);
		}

		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_rdma_queue_delete
 * Description  : Create rdma queue.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_rdma_queue_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_queue *common = container_of(object, struct tag_hinic5_cqm_queue, object);
	struct tag_hinic5_cqm_rdma_qinfo *qinfo = container_of(common, struct tag_hinic5_cqm_rdma_qinfo, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct tag_hinic5_cqm_bat_table *bat_table = &hinic5_cqm_handle->bat_table;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_buf *q_room_buf = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	u32 index = qinfo->common.index;
	u32 count = qinfo->index_count;

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_rdma_queue_delete_cnt);

	q_room_buf = (qinfo->common.current_q_room == HINIC5_CQM_RDMA_Q_ROOM_1) ?
		&qinfo->common.q_room_buf_1 : &qinfo->common.q_room_buf_2;

	/* SCQ and SRQ are associated with independent SCQN and SRQN. */
	if (object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ || object->object_type == HINIC5_CQM_OBJECT_RDMA_SRQ) {
		if (object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ) {
			cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SCQC);
		} else if (object->object_type == HINIC5_CQM_OBJECT_RDMA_SRQ) {
			cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SRQC);
		}
		if (unlikely(!cla_table)) {
			HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_FUNCTION_FAIL
						 (hinic5_cqm_cla_table_get));
			return;
		}
		/* disassociate index and object */
		object_table = &cla_table->obj_table;
		hinic5_cqm_object_table_remove(hinic5_cqm_handle, object_table,
					       index, object, true);
	}

	/* wait for completion to make sure all references are complete */
	if (atomic_dec_and_test(&object->refcount) != 0)
		complete(&object->free);
	else
		hinic5_cqm_err(handle->dev_hdl, "Rdma queue del: object is referred by others, has to wait for completion\n");

	wait_for_completion(&object->free);
	destroy_completion(&object->free);

	/* If the q header exists, release. */
	if (qinfo->room_header_alloc && qinfo->common.q_header_vaddr) {
		dma_unmap_single(hinic5_cqm_handle->dev, qinfo->common.q_header_paddr,
				 sizeof(struct tag_hinic5_cqm_queue_header), DMA_BIDIRECTIONAL);

		hinic5_cqm_kfree_align(qinfo->common.q_header_vaddr);
		qinfo->common.q_header_vaddr = NULL;
	}

	/* If q room exists, release. */
	hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);

	/* SRQ and SCQ have independent CTX, released. */
	if (object->object_type == HINIC5_CQM_OBJECT_RDMA_SRQ ||
	    object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ) {
		hinic5_cqm_cla_put(hinic5_cqm_handle, cla_table, index, count);

		/* release the index to the bitmap */
		bitmap = &cla_table->bitmap;
		hinic5_cqm_bitmap_free(bitmap, index, count);
	}
}

/**
 * Prototype    : hinic5_cqm_rdma_table_create
 * Description  : Create RDMA-related entries.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_rdma_table_create(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_mtt_rdmarc *common =
		container_of(object, struct tag_hinic5_cqm_mtt_rdmarc, object);
	struct tag_hinic5_cqm_rdma_table *rdma_table =
		container_of(common, struct tag_hinic5_cqm_rdma_table, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle =
		(struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *buf = &rdma_table->buf;

	/* Less than one page is allocated by actual size.
	 * RDMARC also requires physical continuity.
	 */
	if (object->object_size <= PAGE_SIZE ||
	    object->object_type == HINIC5_CQM_OBJECT_RDMARC) {
		buf->buf_number = 1;
		buf->page_number = buf->buf_number;
		buf->buf_size = object->object_size;
		buf->direct.va = dma_alloc_coherent(hinic5_cqm_handle->dev, buf->buf_size,
						    &buf->direct.pa, GFP_ATOMIC);
		if (unlikely(!buf->direct.va)) {
			HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(direct));
			return HINIC5_CQM_FAIL;
		}
	} else { /* page-by-page alignment greater than one page */
		buf->buf_number = ALIGN(object->object_size, PAGE_SIZE) /
				  PAGE_SIZE;
		buf->page_number = buf->buf_number;
		buf->buf_size = PAGE_SIZE;
		if (hinic5_cqm_buf_alloc(hinic5_cqm_handle, buf, true) == HINIC5_CQM_FAIL) {
			hinic5_cqm_err(handle->dev_hdl,
				       HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_buf_alloc));
			return HINIC5_CQM_FAIL;
		}
	}

	rdma_table->common.vaddr = (u8 *)(buf->direct.va);

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_rdma_table_delete
 * Description  : Delete RDMA-related Entries.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_rdma_table_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_mtt_rdmarc *common =
		container_of(object, struct tag_hinic5_cqm_mtt_rdmarc, object);
	struct tag_hinic5_cqm_rdma_table *rdma_table =
		container_of(common, struct tag_hinic5_cqm_rdma_table, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle =
		(struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *buf = &rdma_table->buf;

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_rdma_table_delete_cnt);

	if (buf->buf_number == 1) {
		if (buf->direct.va) {
			dma_free_coherent(hinic5_cqm_handle->dev, buf->buf_size,
					  buf->direct.va, buf->direct.pa);
			buf->direct.va = NULL;
		}
	} else {
		hinic5_cqm_buf_free(buf, hinic5_cqm_handle->dev);
	}
}

/**
 * Prototype    : hinic5_cqm_rdma_table_offset_addr
 * Description  : Obtain the address of the RDMA entry based on the offset.
 *		  The offset is the index.
 * Input        : struct tag_hinic5_cqm_object *object
 *		  u32 offset
 *		  dma_addr_t *paddr
 * Output       : None
 * Return Value : u8 *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
u8 *hinic5_cqm_rdma_table_offset_addr(struct tag_hinic5_cqm_object *object, u32 offset, dma_addr_t *paddr)
{
	struct tag_hinic5_cqm_mtt_rdmarc *common =
		container_of(object, struct tag_hinic5_cqm_mtt_rdmarc, object);
	struct tag_hinic5_cqm_rdma_table *rdma_table =
		container_of(common, struct tag_hinic5_cqm_rdma_table, common);
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle =
		(struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_buf *buf = &rdma_table->buf;
	struct tag_hinic5_cqm_buf_list *buf_node = NULL;
	u32 buf_id, buf_offset;

	if (offset < rdma_table->common.index_base ||
	    ((offset - rdma_table->common.index_base) >=
	     rdma_table->common.index_number)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(offset));
		return NULL;
	}

	if (buf->buf_number == 1) {
		buf_offset = (u32)((offset - rdma_table->common.index_base) *
				   (sizeof(dma_addr_t)));

		*paddr = buf->direct.pa + buf_offset;
		return ((u8 *)(buf->direct.va)) + buf_offset;
	}

	buf_id = (offset - rdma_table->common.index_base) /
		 (PAGE_SIZE / sizeof(dma_addr_t));
	buf_offset = (u32)((offset - rdma_table->common.index_base) -
			   (buf_id * (PAGE_SIZE / sizeof(dma_addr_t))));
	buf_offset = (u32)(buf_offset * sizeof(dma_addr_t));

	if (buf_id >= buf->buf_number) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(buf_id));
		return NULL;
	}
	buf_node = buf->buf_list + buf_id;
	*paddr = buf_node->pa + buf_offset;

	return ((u8 *)(buf->direct.va)) +
	       (offset - rdma_table->common.index_base) * (sizeof(dma_addr_t));
}
