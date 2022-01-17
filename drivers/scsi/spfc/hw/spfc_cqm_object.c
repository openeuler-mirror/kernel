// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_hwdev.h"
#include "sphw_hwif.h"

#include "spfc_cqm_object.h"
#include "spfc_cqm_bitmap_table.h"
#include "spfc_cqm_bat_cla.h"
#include "spfc_cqm_main.h"

s32 cqm_qpc_mpt_bitmap_alloc(struct cqm_object *object, struct cqm_cla_table *cla_table)
{
	struct cqm_qpc_mpt *common = container_of(object, struct cqm_qpc_mpt, object);
	struct cqm_qpc_mpt_info *qpc_mpt_info = container_of(common,
								 struct cqm_qpc_mpt_info,
								 common);
	struct cqm_handle *cqm_handle = (struct cqm_handle *)object->cqm_handle;
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_bitmap *bitmap = &cla_table->bitmap;
	u32 index, count;

	count = (ALIGN(object->object_size, cla_table->obj_size)) / cla_table->obj_size;
	qpc_mpt_info->index_count = count;

	if (qpc_mpt_info->common.xid == CQM_INDEX_INVALID) {
		/* apply for an index normally */
		index = cqm_bitmap_alloc(bitmap, 1U << (cla_table->z + 1),
					 count, func_cap->xid_alloc_mode);
		if (index < bitmap->max_num) {
			qpc_mpt_info->common.xid = index;
		} else {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_bitmap_alloc));
			return CQM_FAIL;
		}
	} else {
		/* apply for index to be reserved */
		index = cqm_bitmap_alloc_reserved(bitmap, count,
						  qpc_mpt_info->common.xid);
		if (index != qpc_mpt_info->common.xid) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_bitmap_alloc_reserved));
			return CQM_FAIL;
		}
	}

	return CQM_SUCCESS;
}

s32 cqm_qpc_mpt_create(struct cqm_object *object)
{
	struct cqm_qpc_mpt *common = container_of(object, struct cqm_qpc_mpt, object);
	struct cqm_qpc_mpt_info *qpc_mpt_info = container_of(common,
								 struct cqm_qpc_mpt_info,
								 common);
	struct cqm_handle *cqm_handle = (struct cqm_handle *)object->cqm_handle;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_object_table *object_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	struct cqm_bitmap *bitmap = NULL;
	u32 index, count;

	/* find the corresponding cla table */
	if (object->object_type == CQM_OBJECT_SERVICE_CTX) {
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_QPC);
	} else {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
		return CQM_FAIL;
	}

	CQM_PTR_CHECK_RET(cla_table, CQM_FAIL,
			  CQM_FUNCTION_FAIL(cqm_cla_table_get));

	/* Bitmap applies for index. */
	if (cqm_qpc_mpt_bitmap_alloc(object, cla_table) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_qpc_mpt_bitmap_alloc));
		return CQM_FAIL;
	}

	bitmap = &cla_table->bitmap;
	index = qpc_mpt_info->common.xid;
	count = qpc_mpt_info->index_count;

	/* Find the trunk page from the BAT/CLA and allocate the buffer.
	 * Ensure that the released buffer has been cleared.
	 */
	if (cla_table->alloc_static)
		qpc_mpt_info->common.vaddr = cqm_cla_get_unlock(cqm_handle,
								cla_table,
								index, count,
								&common->paddr);
	else
		qpc_mpt_info->common.vaddr = cqm_cla_get_lock(cqm_handle,
							      cla_table, index,
							      count,
							      &common->paddr);

	if (!qpc_mpt_info->common.vaddr) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_get_lock));
		cqm_err(handle->dev_hdl, "Qpc mpt init: qpc mpt vaddr is null, cla_table->alloc_static=%d\n",
			cla_table->alloc_static);
		goto err1;
	}

	/* Indexes are associated with objects, and FC is executed
	 * in the interrupt context.
	 */
	object_table = &cla_table->obj_table;
	if (object->service_type == CQM_SERVICE_T_FC) {
		if (cqm_object_table_insert(cqm_handle, object_table, index,
					    object, false) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_object_table_insert));
			goto err2;
		}
	} else {
		if (cqm_object_table_insert(cqm_handle, object_table, index,
					    object, true) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(cqm_object_table_insert));
			goto err2;
		}
	}

	return CQM_SUCCESS;

err2:
	cqm_cla_put(cqm_handle, cla_table, index, count);
err1:
	cqm_bitmap_free(bitmap, index, count);
	return CQM_FAIL;
}

struct cqm_qpc_mpt *cqm3_object_qpc_mpt_create(void *ex_handle, u32 service_type,
					       enum cqm_object_type object_type,
					       u32 object_size, void *object_priv,
					       u32 index)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_qpc_mpt_info *qpc_mpt_info = NULL;
	struct cqm_handle *cqm_handle = NULL;
	s32 ret = CQM_FAIL;

	CQM_PTR_CHECK_RET(ex_handle, NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_qpc_mpt_create_cnt);

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, NULL, CQM_PTR_NULL(cqm_handle));

	if (service_type >= CQM_SERVICE_T_MAX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return NULL;
	}
	/* exception of service registrion check */
	if (!cqm_handle->service[service_type].has_register) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return NULL;
	}

	if (object_type != CQM_OBJECT_SERVICE_CTX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	qpc_mpt_info = kmalloc(sizeof(*qpc_mpt_info), GFP_ATOMIC | __GFP_ZERO);
	CQM_PTR_CHECK_RET(qpc_mpt_info, NULL, CQM_ALLOC_FAIL(qpc_mpt_info));

	qpc_mpt_info->common.object.service_type = service_type;
	qpc_mpt_info->common.object.object_type = object_type;
	qpc_mpt_info->common.object.object_size = object_size;
	atomic_set(&qpc_mpt_info->common.object.refcount, 1);
	init_completion(&qpc_mpt_info->common.object.free);
	qpc_mpt_info->common.object.cqm_handle = cqm_handle;
	qpc_mpt_info->common.xid = index;

	qpc_mpt_info->common.priv = object_priv;

	ret = cqm_qpc_mpt_create(&qpc_mpt_info->common.object);
	if (ret == CQM_SUCCESS)
		return &qpc_mpt_info->common;

	cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_qpc_mpt_create));
	kfree(qpc_mpt_info);
	return NULL;
}

void cqm_linkwqe_fill(struct cqm_buf *buf, u32 wqe_per_buf, u32 wqe_size,
		      u32 wqe_number, bool tail, u8 link_mode)
{
	struct cqm_linkwqe_128B *linkwqe = NULL;
	struct cqm_linkwqe *wqe = NULL;
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
			wqe = (struct cqm_linkwqe *)(va + (u32)(wqe_size * wqe_per_buf));
			wqe->wf = CQM_WQE_WF_LINK;
			wqe->ctrlsl = CQM_LINK_WQE_CTRLSL_VALUE;
			wqe->lp = CQM_LINK_WQE_LP_INVALID;
			/* The valid value of link wqe needs to be set to 1.
			 * Each service ensures that o-bit=1 indicates that
			 * link wqe is valid and o-bit=0 indicates that
			 * link wqe is invalid.
			 */
			wqe->o = CQM_LINK_WQE_OWNER_VALID;
			addr = buf->buf_list[(u32)(i + 1)].pa;
			wqe->next_page_gpa_h = CQM_ADDR_HI(addr);
			wqe->next_page_gpa_l = CQM_ADDR_LW(addr);
		} else { /* linkwqe special padding of the last buffer */
			if (tail) {
				/* must be filled at the end of the page */
				tmp = va + (u32)(wqe_size * wqe_per_buf);
				wqe = (struct cqm_linkwqe *)tmp;
			} else {
				/* The last linkwqe is filled
				 * following the last wqe.
				 */
				tmp = va + (u32)(wqe_size * (wqe_number -
							     wqe_per_buf *
							     (buf->buf_number -
							      1)));
				wqe = (struct cqm_linkwqe *)tmp;
			}
			wqe->wf = CQM_WQE_WF_LINK;
			wqe->ctrlsl = CQM_LINK_WQE_CTRLSL_VALUE;

			/* In link mode, the last link WQE is invalid;
			 * In ring mode, the last link wqe is valid, pointing to
			 * the home page, and the lp is set.
			 */
			if (link_mode == CQM_QUEUE_LINK_MODE) {
				wqe->o = CQM_LINK_WQE_OWNER_INVALID;
			} else {
				/* The lp field of the last link_wqe is set to
				 * 1, indicating that the meaning of the o-bit
				 * is reversed.
				 */
				wqe->lp = CQM_LINK_WQE_LP_VALID;
				wqe->o = CQM_LINK_WQE_OWNER_VALID;
				addr = buf->buf_list[0].pa;
				wqe->next_page_gpa_h = CQM_ADDR_HI(addr);
				wqe->next_page_gpa_l = CQM_ADDR_LW(addr);
			}
		}

		if (wqe_size == CQM_LINKWQE_128B) {
			/* After the B800 version, the WQE obit scheme is
			 * changed. The 64B bits before and after the 128B WQE
			 * need to be assigned a value:
			 * ifoe the 63rd bit from the end of the last 64B is
			 * obit;
			 * toe  the 157th bit from the end of the last 64B is
			 * obit.
			 */
			linkwqe = (struct cqm_linkwqe_128B *)wqe;
			linkwqe->second64B.forth_16B.bs.ifoe_o = CQM_LINK_WQE_OWNER_VALID;

			/* shift 2 bits by right to get length of dw(4B) */
			cqm_swab32((u8 *)wqe, sizeof(struct cqm_linkwqe_128B) >> 2);
		} else {
			/* shift 2 bits by right to get length of dw(4B) */
			cqm_swab32((u8 *)wqe, sizeof(struct cqm_linkwqe) >> 2);
		}
	}
}

s32 cqm_nonrdma_queue_ctx_create(struct cqm_object *object)
{
	struct cqm_queue *common = container_of(object, struct cqm_queue, object);
	struct cqm_nonrdma_qinfo *qinfo = container_of(common, struct cqm_nonrdma_qinfo,
							   common);
	struct cqm_handle *cqm_handle = (struct cqm_handle *)object->cqm_handle;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_object_table *object_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	struct cqm_bitmap *bitmap = NULL;
	s32 shift;

	if (object->object_type == CQM_OBJECT_NONRDMA_SRQ) {
		shift = cqm_shift(qinfo->q_ctx_size);
		common->q_ctx_vaddr = cqm_kmalloc_align(qinfo->q_ctx_size,
							GFP_KERNEL | __GFP_ZERO,
							(u16)shift);
		if (!common->q_ctx_vaddr) {
			cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(q_ctx_vaddr));
			return CQM_FAIL;
		}

		common->q_ctx_paddr = pci_map_single(cqm_handle->dev,
						     common->q_ctx_vaddr,
						     qinfo->q_ctx_size,
						     PCI_DMA_BIDIRECTIONAL);
		if (pci_dma_mapping_error(cqm_handle->dev,
					  common->q_ctx_paddr)) {
			cqm_err(handle->dev_hdl, CQM_MAP_FAIL(q_ctx_vaddr));
			cqm_kfree_align(common->q_ctx_vaddr);
			common->q_ctx_vaddr = NULL;
			return CQM_FAIL;
		}
	} else if (object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		/* find the corresponding cla table */
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_SCQC);
		if (!cla_table) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(nonrdma_cqm_cla_table_get));
			return CQM_FAIL;
		}

		/* bitmap applies for index */
		bitmap = &cla_table->bitmap;
		qinfo->index_count =
		    (ALIGN(qinfo->q_ctx_size, cla_table->obj_size)) /
		    cla_table->obj_size;
		qinfo->common.index = cqm_bitmap_alloc(bitmap, 1U << (cla_table->z + 1),
						       qinfo->index_count,
						       cqm_handle->func_capability.xid_alloc_mode);
		if (qinfo->common.index >= bitmap->max_num) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(nonrdma_cqm_bitmap_alloc));
			return CQM_FAIL;
		}

		/* find the trunk page from BAT/CLA and allocate the buffer */
		common->q_ctx_vaddr = cqm_cla_get_lock(cqm_handle, cla_table,
						       qinfo->common.index,
						       qinfo->index_count,
						       &common->q_ctx_paddr);
		if (!common->q_ctx_vaddr) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(nonrdma_cqm_cla_get_lock));
			cqm_bitmap_free(bitmap, qinfo->common.index,
					qinfo->index_count);
			return CQM_FAIL;
		}

		/* index and object association */
		object_table = &cla_table->obj_table;
		if (object->service_type == CQM_SERVICE_T_FC) {
			if (cqm_object_table_insert(cqm_handle, object_table,
						    qinfo->common.index, object,
						    false) != CQM_SUCCESS) {
				cqm_err(handle->dev_hdl,
					CQM_FUNCTION_FAIL(nonrdma_cqm_object_table_insert));
				cqm_cla_put(cqm_handle, cla_table,
					    qinfo->common.index,
					    qinfo->index_count);
				cqm_bitmap_free(bitmap, qinfo->common.index,
						qinfo->index_count);
				return CQM_FAIL;
			}
		} else {
			if (cqm_object_table_insert(cqm_handle, object_table,
						    qinfo->common.index, object,
						    true) != CQM_SUCCESS) {
				cqm_err(handle->dev_hdl,
					CQM_FUNCTION_FAIL(nonrdma_cqm_object_table_insert));
				cqm_cla_put(cqm_handle, cla_table,
					    qinfo->common.index,
					    qinfo->index_count);
				cqm_bitmap_free(bitmap, qinfo->common.index,
						qinfo->index_count);
				return CQM_FAIL;
			}
		}
	}

	return CQM_SUCCESS;
}

s32 cqm_nonrdma_queue_create(struct cqm_object *object)
{
	struct cqm_queue *common = container_of(object, struct cqm_queue, object);
	struct cqm_nonrdma_qinfo *qinfo = container_of(common, struct cqm_nonrdma_qinfo,
							   common);
	struct cqm_handle *cqm_handle = (struct cqm_handle *)object->cqm_handle;
	struct cqm_service *service = cqm_handle->service + object->service_type;
	struct cqm_buf *q_room_buf = &common->q_room_buf_1;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 wqe_number = qinfo->common.object.object_size;
	u32 wqe_size = qinfo->wqe_size;
	u32 order = service->buf_order;
	u32 buf_number, buf_size;
	bool tail = false; /* determine whether the linkwqe is at the end of the page */

	/* When creating a CQ/SCQ queue, the page size is 4 KB,
	 * the linkwqe must be at the end of the page.
	 */
	if (object->object_type == CQM_OBJECT_NONRDMA_EMBEDDED_CQ ||
	    object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		/* depth: 2^n-aligned; depth range: 256-32 K */
		if (wqe_number < CQM_CQ_DEPTH_MIN ||
		    wqe_number > CQM_CQ_DEPTH_MAX) {
			cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(wqe_number));
			return CQM_FAIL;
		}
		if (!cqm_check_align(wqe_number)) {
			cqm_err(handle->dev_hdl, "Nonrdma queue alloc: wqe_number is not align on 2^n\n");
			return CQM_FAIL;
		}

		order = CQM_4K_PAGE_ORDER; /* wqe page 4k */
		tail = true; /* The linkwqe must be at the end of the page. */
		buf_size = CQM_4K_PAGE_SIZE;
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
	if (cqm_buf_alloc(cqm_handle, q_room_buf, false) == CQM_FAIL) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_buf_alloc));
		return CQM_FAIL;
	}
	/* fill link wqe, wqe_number - buf_number is the number of wqe without
	 * link wqe
	 */
	cqm_linkwqe_fill(q_room_buf, qinfo->wqe_per_buf, wqe_size,
			 wqe_number - buf_number, tail,
			 common->queue_link_mode);

	/* create queue header */
	qinfo->common.q_header_vaddr = cqm_kmalloc_align(sizeof(struct cqm_queue_header),
							 GFP_KERNEL | __GFP_ZERO,
							 CQM_QHEAD_ALIGN_ORDER);
	if (!qinfo->common.q_header_vaddr) {
		cqm_err(handle->dev_hdl, CQM_ALLOC_FAIL(q_header_vaddr));
		goto err1;
	}

	common->q_header_paddr = pci_map_single(cqm_handle->dev,
						qinfo->common.q_header_vaddr,
						sizeof(struct cqm_queue_header),
						PCI_DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(cqm_handle->dev, common->q_header_paddr)) {
		cqm_err(handle->dev_hdl, CQM_MAP_FAIL(q_header_vaddr));
		goto err2;
	}

	/* create queue ctx */
	if (cqm_nonrdma_queue_ctx_create(object) == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_nonrdma_queue_ctx_create));
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	pci_unmap_single(cqm_handle->dev, common->q_header_paddr,
			 sizeof(struct cqm_queue_header), PCI_DMA_BIDIRECTIONAL);
err2:
	cqm_kfree_align(qinfo->common.q_header_vaddr);
	qinfo->common.q_header_vaddr = NULL;
err1:
	cqm_buf_free(q_room_buf, cqm_handle->dev);
	return CQM_FAIL;
}

struct cqm_queue *cqm3_object_fc_srq_create(void *ex_handle, u32 service_type,
					    enum cqm_object_type object_type,
					    u32 wqe_number, u32 wqe_size,
					    void *object_priv)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_nonrdma_qinfo *nonrdma_qinfo = NULL;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	u32 valid_wqe_per_buffer;
	u32 wqe_sum; /* include linkwqe, normal wqe */
	u32 buf_size;
	u32 buf_num;
	s32 ret;

	CQM_PTR_CHECK_RET(ex_handle, NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_fc_srq_create_cnt);

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, NULL, CQM_PTR_NULL(cqm_handle));

	/* service_type must be fc */
	if (service_type != CQM_SERVICE_T_FC) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return NULL;
	}

	/* exception of service unregistered check */
	if (!cqm_handle->service[service_type].has_register) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return NULL;
	}

	/* wqe_size cannot exceed PAGE_SIZE and must be 2^n aligned. */
	if (wqe_size >= PAGE_SIZE || (!cqm_check_align(wqe_size))) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(wqe_size));
		return NULL;
	}

	/* FC RQ is SRQ. (Different from the SRQ concept of TOE, FC indicates
	 * that packets received by all flows are placed on the same RQ.
	 * The SRQ of TOE is similar to the RQ resource pool.)
	 */
	if (object_type != CQM_OBJECT_NONRDMA_SRQ) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	service = &cqm_handle->service[service_type];
	buf_size = (u32)(PAGE_SIZE << (service->buf_order));
	/* subtract 1 link wqe */
	valid_wqe_per_buffer = buf_size / wqe_size - 1;
	buf_num = wqe_number / valid_wqe_per_buffer;
	if (wqe_number % valid_wqe_per_buffer != 0)
		buf_num++;

	/* calculate the total number of WQEs */
	wqe_sum = buf_num * (valid_wqe_per_buffer + 1);
	nonrdma_qinfo = kmalloc(sizeof(*nonrdma_qinfo), GFP_KERNEL | __GFP_ZERO);
	CQM_PTR_CHECK_RET(nonrdma_qinfo, NULL, CQM_ALLOC_FAIL(nonrdma_qinfo));

	/* initialize object member */
	nonrdma_qinfo->common.object.service_type = service_type;
	nonrdma_qinfo->common.object.object_type = object_type;
	/* total number of WQEs */
	nonrdma_qinfo->common.object.object_size = wqe_sum;
	atomic_set(&nonrdma_qinfo->common.object.refcount, 1);
	init_completion(&nonrdma_qinfo->common.object.free);
	nonrdma_qinfo->common.object.cqm_handle = cqm_handle;

	/* Initialize the doorbell used by the current queue.
	 * The default doorbell is the hardware doorbell.
	 */
	nonrdma_qinfo->common.current_q_doorbell = CQM_HARDWARE_DOORBELL;
	/* Currently, the connection mode is fixed. In the future,
	 * the service needs to transfer the connection mode.
	 */
	nonrdma_qinfo->common.queue_link_mode = CQM_QUEUE_RING_MODE;

	/* initialize public members */
	nonrdma_qinfo->common.priv = object_priv;
	nonrdma_qinfo->common.valid_wqe_num = wqe_sum - buf_num;

	/* initialize internal private members */
	nonrdma_qinfo->wqe_size = wqe_size;
	/* RQ (also called SRQ of FC) created by FC services,
	 * CTX needs to be created.
	 */
	nonrdma_qinfo->q_ctx_size = service->service_template.srq_ctx_size;

	ret = cqm_nonrdma_queue_create(&nonrdma_qinfo->common.object);
	if (ret == CQM_SUCCESS)
		return &nonrdma_qinfo->common;

	cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_fc_queue_create));
	kfree(nonrdma_qinfo);
	return NULL;
}

struct cqm_queue *cqm3_object_nonrdma_queue_create(void *ex_handle, u32 service_type,
						   enum cqm_object_type object_type,
						   u32 wqe_number, u32 wqe_size,
						   void *object_priv)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_nonrdma_qinfo *nonrdma_qinfo = NULL;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	s32 ret;

	CQM_PTR_CHECK_RET(ex_handle, NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_nonrdma_queue_create_cnt);

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, NULL, CQM_PTR_NULL(cqm_handle));

	/* exception of service registrion check */
	if (!cqm_handle->service[service_type].has_register) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return NULL;
	}
	/* wqe_size can't be more than PAGE_SIZE, can't be zero, must be power
	 * of 2 the function of cqm_check_align is to check above
	 */
	if (wqe_size >= PAGE_SIZE || (!cqm_check_align(wqe_size))) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(wqe_size));
		return NULL;
	}

	/* nonrdma supports: RQ, SQ, SRQ, CQ, SCQ */
	if (object_type < CQM_OBJECT_NONRDMA_EMBEDDED_RQ ||
	    object_type > CQM_OBJECT_NONRDMA_SCQ) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	nonrdma_qinfo = kmalloc(sizeof(*nonrdma_qinfo), GFP_KERNEL | __GFP_ZERO);
	CQM_PTR_CHECK_RET(nonrdma_qinfo, NULL, CQM_ALLOC_FAIL(nonrdma_qinfo));

	nonrdma_qinfo->common.object.service_type = service_type;
	nonrdma_qinfo->common.object.object_type = object_type;
	nonrdma_qinfo->common.object.object_size = wqe_number;
	atomic_set(&nonrdma_qinfo->common.object.refcount, 1);
	init_completion(&nonrdma_qinfo->common.object.free);
	nonrdma_qinfo->common.object.cqm_handle = cqm_handle;

	/* Initialize the doorbell used by the current queue.
	 * The default value is hardware doorbell
	 */
	nonrdma_qinfo->common.current_q_doorbell = CQM_HARDWARE_DOORBELL;
	/* Currently, the link mode is hardcoded and needs to be transferred by
	 * the service side.
	 */
	nonrdma_qinfo->common.queue_link_mode = CQM_QUEUE_RING_MODE;

	nonrdma_qinfo->common.priv = object_priv;

	/* Initialize internal private members */
	nonrdma_qinfo->wqe_size = wqe_size;
	service = &cqm_handle->service[service_type];
	switch (object_type) {
	case CQM_OBJECT_NONRDMA_SCQ:
		nonrdma_qinfo->q_ctx_size =
		    service->service_template.scq_ctx_size;
		break;
	case CQM_OBJECT_NONRDMA_SRQ:
		/* Currently, the SRQ of the service is created through a
		 * dedicated interface.
		 */
		nonrdma_qinfo->q_ctx_size =
		    service->service_template.srq_ctx_size;
		break;
	default:
		break;
	}

	ret = cqm_nonrdma_queue_create(&nonrdma_qinfo->common.object);
	if (ret == CQM_SUCCESS)
		return &nonrdma_qinfo->common;

	cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_nonrdma_queue_create));
	kfree(nonrdma_qinfo);
	return NULL;
}

void cqm_qpc_mpt_delete(struct cqm_object *object)
{
	struct cqm_qpc_mpt *common = container_of(object, struct cqm_qpc_mpt, object);
	struct cqm_qpc_mpt_info *qpc_mpt_info = container_of(common,
								 struct cqm_qpc_mpt_info,
								 common);
	struct cqm_handle *cqm_handle = (struct cqm_handle *)object->cqm_handle;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_object_table *object_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	u32 count = qpc_mpt_info->index_count;
	u32 index = qpc_mpt_info->common.xid;
	struct cqm_bitmap *bitmap = NULL;

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_qpc_mpt_delete_cnt);

	/* find the corresponding cla table */
	if (object->object_type == CQM_OBJECT_SERVICE_CTX) {
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_QPC);
	} else {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
		return;
	}

	CQM_PTR_CHECK_NO_RET(cla_table,
			     CQM_FUNCTION_FAIL(cqm_cla_table_get_qpc));

	/* disassociate index and object */
	object_table = &cla_table->obj_table;
	if (object->service_type == CQM_SERVICE_T_FC)
		cqm_object_table_remove(cqm_handle, object_table, index, object,
					false);
	else
		cqm_object_table_remove(cqm_handle, object_table, index, object,
					true);

	/* wait for completion to ensure that all references to
	 * the QPC are complete
	 */
	if (atomic_dec_and_test(&object->refcount))
		complete(&object->free);
	else
		cqm_err(handle->dev_hdl, "Qpc mpt del: object is referred by others, has to wait for completion\n");

	/* Static QPC allocation must be non-blocking.
	 * Services ensure that the QPC is referenced
	 * when the QPC is deleted.
	 */
	if (!cla_table->alloc_static)
		wait_for_completion(&object->free);

	/* release qpc buffer */
	cqm_cla_put(cqm_handle, cla_table, index, count);

	/* release the index to the bitmap */
	bitmap = &cla_table->bitmap;
	cqm_bitmap_free(bitmap, index, count);
}

s32 cqm_qpc_mpt_delete_ret(struct cqm_object *object)
{
	u32 object_type;

	object_type = object->object_type;
	switch (object_type) {
	case CQM_OBJECT_SERVICE_CTX:
		cqm_qpc_mpt_delete(object);
		return CQM_SUCCESS;
	default:
		return CQM_FAIL;
	}
}

void cqm_nonrdma_queue_delete(struct cqm_object *object)
{
	struct cqm_queue *common = container_of(object, struct cqm_queue, object);
	struct cqm_nonrdma_qinfo *qinfo = container_of(common, struct cqm_nonrdma_qinfo,
							   common);
	struct cqm_handle *cqm_handle = (struct cqm_handle *)object->cqm_handle;
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_buf *q_room_buf = &common->q_room_buf_1;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	struct cqm_object_table *object_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	struct cqm_bitmap *bitmap = NULL;
	u32 index = qinfo->common.index;
	u32 count = qinfo->index_count;

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_nonrdma_queue_delete_cnt);

	/* The SCQ has an independent SCQN association. */
	if (object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_SCQC);
		CQM_PTR_CHECK_NO_RET(cla_table, CQM_FUNCTION_FAIL(cqm_cla_table_get_queue));

		/* disassociate index and object */
		object_table = &cla_table->obj_table;
		if (object->service_type == CQM_SERVICE_T_FC)
			cqm_object_table_remove(cqm_handle, object_table, index,
						object, false);
		else
			cqm_object_table_remove(cqm_handle, object_table, index,
						object, true);
	}

	/* wait for completion to ensure that all references to
	 * the QPC are complete
	 */
	if (atomic_dec_and_test(&object->refcount))
		complete(&object->free);
	else
		cqm_err(handle->dev_hdl, "Nonrdma queue del: object is referred by others, has to wait for completion\n");

	wait_for_completion(&object->free);

	/* If the q header exists, release. */
	if (qinfo->common.q_header_vaddr) {
		pci_unmap_single(cqm_handle->dev, common->q_header_paddr,
				 sizeof(struct cqm_queue_header),
				 PCI_DMA_BIDIRECTIONAL);

		cqm_kfree_align(qinfo->common.q_header_vaddr);
		qinfo->common.q_header_vaddr = NULL;
	}

	cqm_buf_free(q_room_buf, cqm_handle->dev);
	/* SRQ and SCQ have independent CTXs and release. */
	if (object->object_type == CQM_OBJECT_NONRDMA_SRQ) {
		/* The CTX of the SRQ of the nordma is
		 * applied for independently.
		 */
		if (common->q_ctx_vaddr) {
			pci_unmap_single(cqm_handle->dev, common->q_ctx_paddr,
					 qinfo->q_ctx_size,
					 PCI_DMA_BIDIRECTIONAL);

			cqm_kfree_align(common->q_ctx_vaddr);
			common->q_ctx_vaddr = NULL;
		}
	} else if (object->object_type == CQM_OBJECT_NONRDMA_SCQ) {
		/* The CTX of the SCQ of the nordma is managed by BAT/CLA. */
		cqm_cla_put(cqm_handle, cla_table, index, count);

		/* release the index to the bitmap */
		bitmap = &cla_table->bitmap;
		cqm_bitmap_free(bitmap, index, count);
	}
}

s32 cqm_nonrdma_queue_delete_ret(struct cqm_object *object)
{
	u32 object_type;

	object_type = object->object_type;
	switch (object_type) {
	case CQM_OBJECT_NONRDMA_EMBEDDED_RQ:
	case CQM_OBJECT_NONRDMA_EMBEDDED_SQ:
	case CQM_OBJECT_NONRDMA_EMBEDDED_CQ:
	case CQM_OBJECT_NONRDMA_SCQ:
		cqm_nonrdma_queue_delete(object);
		return CQM_SUCCESS;
	case CQM_OBJECT_NONRDMA_SRQ:
		cqm_nonrdma_queue_delete(object);
		return CQM_SUCCESS;
	default:
		return CQM_FAIL;
	}
}

void cqm3_object_delete(struct cqm_object *object)
{
	struct cqm_handle *cqm_handle = NULL;
	struct sphw_hwdev *handle = NULL;

	CQM_PTR_CHECK_NO_RET(object, CQM_PTR_NULL(object));
	if (!object->cqm_handle) {
		pr_err("[CQM]object del: cqm_handle is null, service type %u, refcount %d\n",
		       object->service_type, (int)object->refcount.counter);
		kfree(object);
		return;
	}

	cqm_handle = (struct cqm_handle *)object->cqm_handle;

	if (!cqm_handle->ex_handle) {
		pr_err("[CQM]object del: ex_handle is null, service type %u, refcount %d\n",
		       object->service_type, (int)object->refcount.counter);
		kfree(object);
		return;
	}

	handle = cqm_handle->ex_handle;

	if (object->service_type >= CQM_SERVICE_T_MAX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->service_type));
		kfree(object);
		return;
	}

	if (cqm_qpc_mpt_delete_ret(object) == CQM_SUCCESS) {
		kfree(object);
		return;
	}

	if (cqm_nonrdma_queue_delete_ret(object) == CQM_SUCCESS) {
		kfree(object);
		return;
	}

	cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(object->object_type));
	kfree(object);
}

struct cqm_object *cqm3_object_get(void *ex_handle, enum cqm_object_type object_type,
				   u32 index, bool bh)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	struct cqm_bat_table *bat_table = &cqm_handle->bat_table;
	struct cqm_object_table *object_table = NULL;
	struct cqm_cla_table *cla_table = NULL;
	struct cqm_object *object = NULL;

	/* The data flow path takes performance into consideration and
	 * does not check input parameters.
	 */
	switch (object_type) {
	case CQM_OBJECT_SERVICE_CTX:
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_QPC);
		break;
	case CQM_OBJECT_NONRDMA_SCQ:
		cla_table = cqm_cla_table_get(bat_table, CQM_BAT_ENTRY_T_SCQC);
		break;
	default:
		return NULL;
	}

	if (!cla_table) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_table_get));
		return NULL;
	}

	object_table = &cla_table->obj_table;
	object = cqm_object_table_get(cqm_handle, object_table, index, bh);
	return object;
}

void cqm3_object_put(struct cqm_object *object)
{
	/* The data flow path takes performance into consideration and
	 * does not check input parameters.
	 */
	if (atomic_dec_and_test(&object->refcount))
		complete(&object->free);
}
