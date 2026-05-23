/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_object.c
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
#include "hinic5_typedef_inner.h"

#include "hinic5_cqm_bitmap_table.h"
#include "hinic5_cqm_bat_cla.h"
#include "hinic5_cqm_object_intern.h"
#include "hinic5_cqm_main.h"
#include "hinic5_cqm_object.h"

static inline void hinic5_cqm_object_init(struct tag_hinic5_cqm_object *object, u32 service_type,
					  enum hinic5_cqm_object_type object_type, u32 object_size,
					  void *hinic5_cqm_handle)
{
	object->service_type = service_type;
	object->object_type = object_type;
	object->object_size = object_size;
	atomic_set(&object->refcount, 1);
	init_completion(&object->free);
	object->hinic5_cqm_handle = hinic5_cqm_handle;
}

static s32 hinic5_cqm_object_create_check(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 service_type)
{
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return HINIC5_CQM_FAIL;
	}

	if (unlikely(service_type >= HINIC5_CQM_SERVICE_T_MAX)) {
		hinic5_cqm_err(hinic5_cqm_handle->dev, "invalid service %u\n", service_type);
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(!hinic5_cqm_handle->service[service_type].has_register)) {
		hinic5_cqm_err(hinic5_cqm_handle->dev, "service %u has not registered\n", service_type);
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

/**
 * Prototype    : hinic5_cqm_object_qpc_mpt_create
 * Description  : create QPC/MPT
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type: must be mpt or ctx.
 *		  u32 object_size: unit is Byte
 *		  void *object_priv: private structure of the service layer,
 *				     it can be NULL.
 *		  u32 index: apply for the reserved qpn 0~(1M-1) based on this value;
 *			     if automatic allocation is required,
 *			     index[20:0]  : fixed to 0x1fffff
 *			     index[23:21] : specified xid_lowbits[2:0]
 *			     index[26:24] : xid[2:0] match mode, see HINIC5_CQM_DYNAMIC_XID_MOD
 *			     index[27] : search mode,
 *					 0---specify the XID range,
 *					 1---search for the entire dynamic area
 *			     index[31:28]  : rsvd
 *			     notes: when index is HINIC5_CQM_INDEX_INVALID, means match all available xid
 *		  u32 bitmap_start: start index of dynamic xid search range,
 *				    valid when index[25]=0 && index[20:0]=0x1fffff
 *		  u32 bitmap_end: end index of dynamic xid search range,
 *				  valid when index[25]=0 && index[20:0]=0x1fffff
 *				  when search forward(bitmap_start<bitmap_end),
 *				    search range is [bitmap_start, bitmap_end)
 *				  when search reverse(bitmap_start>bitmap_end),
 *				    search range is (bitmap_end, bitmap_start].
 *				  bitmap_start=bitmap_end is illegal in range search mode
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_qpc_mpt *
 * 1.Date         : 2016/2/16
 *   Modification : Created function
 */
struct tag_hinic5_cqm_qpc_mpt *hinic5_cqm_object_qpc_mpt_create(void *ex_handle, u32 service_type,
						  enum hinic5_cqm_object_type object_type,
						  u32 object_size, void *object_priv, u32 index,
						  u32 bitmap_start, u32 bitmap_end)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_qpc_mpt_info *qpc_mpt_info = NULL;
	struct tag_hinic5_cqm_bitmap_range bp_range;
	s32 ret = HINIC5_CQM_FAIL;
	u32 relative_index;
	u32 fake_func_id;
	u32 index_num = index;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_qpc_mpt_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	if (object_type != HINIC5_CQM_OBJECT_SERVICE_CTX && object_type != HINIC5_CQM_OBJECT_MPT) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	/* fake vf adaption, switch to corresponding VF. */
	if (HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle) &&
	    !hinic5_cqm_handle->func_capability.use_fake_parent_cla) {
		struct tag_hinic5_cqm_fake_cfg *fake_cfg = &hinic5_cqm_handle->func_capability.fake_cfg;
		if (fake_cfg->fake_vf_max_pctx == 0) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(fake_cfg->fake_vf_max_pctx));
			return NULL;
		}

		fake_func_id   = index_num / fake_cfg->fake_vf_max_pctx;
		relative_index = index_num % fake_cfg->fake_vf_max_pctx;

		if (fake_func_id >= hinic5_cqm_get_child_func_number(hinic5_cqm_handle)) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(fake_func_id));
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(index));
			return NULL;
		}

		index_num = relative_index;
		hinic5_cqm_handle = hinic5_cqm_handle->fake_hinic5_cqm_handle[fake_func_id];
	}

	qpc_mpt_info = kzalloc(sizeof(*qpc_mpt_info), GFP_ATOMIC);
	if (unlikely(qpc_mpt_info == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(qpc_mpt_info));
		return NULL;
	}

	hinic5_cqm_object_init(&qpc_mpt_info->common.object, service_type, object_type,
			object_size, hinic5_cqm_handle);
	qpc_mpt_info->common.xid = index_num;
	bp_range.start = bitmap_start;
	bp_range.end = bitmap_end;

	qpc_mpt_info->common.priv = object_priv;

	ret = hinic5_cqm_qpc_mpt_create(&qpc_mpt_info->common.object, &bp_range);
	if (ret == HINIC5_CQM_SUCCESS)
		return &qpc_mpt_info->common;

	hinic5_cqm_warn(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_qpc_mpt_create));
	kfree(qpc_mpt_info);
	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_qpc_mpt_create);

static struct tag_hinic5_cqm_queue *hinic5_cqm_create_rqs(struct tag_hinic5_cqm_nonrdma_qinfo *rq_qinfo, struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
	struct hinic5_hwdev *handle, u32 init_rq_num)
{
	u32 i;
	/* 3. create queue header */
	rq_qinfo->common.q_header_vaddr = hinic5_cqm_kmalloc_align(sizeof(struct tag_hinic5_cqm_queue_header),
		GFP_KERNEL | __GFP_ZERO, HINIC5_CQM_QHEAD_ALIGN_ORDER);
	if (!rq_qinfo->common.q_header_vaddr) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_ALLOC_FAIL(q_header_vaddr));
		return NULL;
	}

	rq_qinfo->common.q_header_paddr = dma_map_single(hinic5_cqm_handle->dev, rq_qinfo->common.q_header_vaddr,
			   sizeof(struct tag_hinic5_cqm_queue_header), DMA_BIDIRECTIONAL);
	if (dma_mapping_error(hinic5_cqm_handle->dev, rq_qinfo->common.q_header_paddr) != 0) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_MAP_FAIL(q_header_vaddr));
		goto err1;
	}

	/* 4. create rq */
	for (i = 0; i < init_rq_num; i++) {
		if (hinic5_cqm_container_create(&rq_qinfo->common.object, NULL, true) != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_container_create));
			goto err2;
		}
		if (!rq_qinfo->common.head_container)
			rq_qinfo->common.head_container = rq_qinfo->common.tail_container;
	}

	return &rq_qinfo->common;

err2:
	hinic5_cqm_container_free(rq_qinfo->common.head_container, NULL,
			   &rq_qinfo->common);
err1:
	hinic5_cqm_kfree_align(rq_qinfo->common.q_header_vaddr);
	rq_qinfo->common.q_header_vaddr = NULL;
	return NULL;
}

/**
 * Prototype    : hinic5_cqm_object_recv_queue_create
 * Description  : when srq is used, create rq.
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type
 *		  u32 init_rq_num
 *		  u32 container_size
 *		  u32 wqe_size
 *		  void *object_priv
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_queue *
 * 1.Date         : 2016/2/16
 *   Modification : Created function
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_recv_queue_create(void *ex_handle, u32 service_type,
						   enum hinic5_cqm_object_type object_type,
						   u32 init_rq_num, u32 container_size,
						   u32 wqe_size, void *object_priv)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_nonrdma_qinfo *rq_qinfo = NULL;
	struct tag_hinic5_cqm_queue *ret = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_rq_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	if (object_type != HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_RQ) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	if (service_type != HINIC5_CQM_SERVICE_T_TOE) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(service_type));
		return NULL;
	}

	/* 1. create rq qinfo */
	rq_qinfo = kzalloc(sizeof(*rq_qinfo), GFP_KERNEL);
	if (unlikely(rq_qinfo == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(rq_qinfo));
		return NULL;
	}

	/* 2. init rq qinfo */
	rq_qinfo->container_size = container_size;
	rq_qinfo->wqe_size = wqe_size;
	rq_qinfo->wqe_per_buf = container_size / wqe_size - 1;

	rq_qinfo->common.queue_link_mode = HINIC5_CQM_QUEUE_TOE_SRQ_LINK_MODE;
	rq_qinfo->common.priv = object_priv;
	hinic5_cqm_object_init(&rq_qinfo->common.object, service_type, object_type,
			init_rq_num, hinic5_cqm_handle);

	/* 3. create rq */
	ret = hinic5_cqm_create_rqs(rq_qinfo, hinic5_cqm_handle, handle, init_rq_num);
	if (ret == NULL)
		kfree(rq_qinfo);

	return ret;
}
EXPORT_SYMBOL(hinic5_cqm_object_recv_queue_create);

/**
 * Prototype    : hinic5_cqm_object_share_recv_queue_add_container
 * Description  : allocate new container for srq
 * Input        : struct tag_hinic5_cqm_queue *common
 * Output       : None
 * Return Value : tail_container address
 * 1.Date         : 2016/2/14
 *   Modification : Created function
 */
s32 hinic5_cqm_object_share_recv_queue_add_container(struct tag_hinic5_cqm_queue *common)
{
	if (unlikely(common == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(common));
		return HINIC5_CQM_FAIL;
	}

	return hinic5_cqm_container_create(&common->object, NULL, true);
}
EXPORT_SYMBOL(hinic5_cqm_object_share_recv_queue_add_container);

s32 hinic5_cqm_object_srq_add_container_free(struct tag_hinic5_cqm_queue *common, u8 **container_addr)
{
	if (unlikely(common == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(common));
		return HINIC5_CQM_FAIL;
	}

	return hinic5_cqm_container_create(&common->object, container_addr, false);
}
EXPORT_SYMBOL(hinic5_cqm_object_srq_add_container_free);

static bool hinic5_cqm_object_share_recv_queue_param_check(struct hinic5_hwdev *handle, u32 service_type,
						    enum hinic5_cqm_object_type object_type,
						    u32 container_size, u32 wqe_size)
{
	/* service_type must be HINIC5_CQM_SERVICE_T_TOE */
	if (service_type != HINIC5_CQM_SERVICE_T_TOE) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(service_type));
		return false;
	}

	/* container size2^N aligning */
	if (!hinic5_cqm_check_align(container_size)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(container_size));
		return false;
	}

	/* external parameter check: object_type must be
	 * HINIC5_CQM_OBJECT_NONRDMA_SRQ
	 */
	if (object_type != HINIC5_CQM_OBJECT_NONRDMA_SRQ) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return false;
	}

	/* wqe_size, the divisor, cannot be 0 */
	if (wqe_size == 0) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(wqe_size));
		return false;
	}

	return true;
}

/**
 * Prototype    : hinic5_cqm_object_share_recv_queue_create
 * Description  : create srq
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type
 *		  u32 container_number
 *		  u32 container_size
 *		  u32 wqe_size
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_queue *
 * 1.Date         : 2016/2/1
 *   Modification : Created function
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_share_recv_queue_create(void *ex_handle, u32 service_type,
							 enum hinic5_cqm_object_type object_type,
							 u32 container_number, u32 container_size,
							 u32 wqe_size)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_nonrdma_qinfo *srq_qinfo = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_srq_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	if (!hinic5_cqm_object_share_recv_queue_param_check(handle, service_type, object_type,
						     container_size, wqe_size))
		return NULL;

	/* 2. create and initialize srq info */
	srq_qinfo = kzalloc(sizeof(*srq_qinfo), GFP_KERNEL);
	if (unlikely(srq_qinfo == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(srq_qinfo));
		return NULL;
	}

	hinic5_cqm_object_init(&srq_qinfo->common.object, service_type, object_type,
			container_number, hinic5_cqm_handle);

	srq_qinfo->common.queue_link_mode = HINIC5_CQM_QUEUE_TOE_SRQ_LINK_MODE;
	srq_qinfo->common.priv = NULL;
	srq_qinfo->wqe_per_buf = container_size / wqe_size - 1;
	srq_qinfo->wqe_size = wqe_size;
	srq_qinfo->container_size = container_size;
	service = &hinic5_cqm_handle->service[service_type];
	srq_qinfo->q_ctx_size = service->service_template.srq_ctx_size;

	/* 3. create srq and srq ctx */
	ret = hinic5_cqm_share_recv_queue_create(&srq_qinfo->common.object);
	if (ret == HINIC5_CQM_SUCCESS)
		return &srq_qinfo->common;

	hinic5_cqm_err(handle->dev_hdl,
		HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_share_recv_queue_create));
	kfree(srq_qinfo);
	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_share_recv_queue_create);

/* FC RQ is SRQ. (Different from the SRQ concept of TOE, FC indicates
 * that packets received by all flows are placed on the same RQ.
 * The SRQ of TOE is similar to the RQ resource pool.)
 */
static bool hinic5_cqm_object_fc_srq_param_check(struct hinic5_hwdev *handle, u32 service_type,
					  enum hinic5_cqm_object_type object_type, u32 wqe_size)
{
	/* service_type must be HINIC5_CQM_SERVICE_T_FC */
	if (service_type != HINIC5_CQM_SERVICE_T_FC) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(service_type));
		return false;
	}

	/* object_type must be HINIC5_CQM_OBJECT_NONRDMA_SRQ */
	if (object_type != HINIC5_CQM_OBJECT_NONRDMA_SRQ) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return false;
	}

	if (wqe_size >= PAGE_SIZE || !hinic5_cqm_check_align(wqe_size)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(wqe_size));
		return false;
	}

	return true;
}

/**
 * Prototype    : hinic5_cqm_object_fc_rq_create
 * Description  : RQ creation temporarily provided for the FC service.
 *		  Special requirement: The number of valid WQEs in the queue
 *		  must meet the number of transferred WQEs. Linkwqe can only be
 *		  filled at the end of the page. The actual valid number exceeds
 *		  the requirement. In this case, the service needs to be
 *		  informed of the additional number to be created.
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type
 *		  u32 wqe_number: Number of valid WQEs
 *		  u32 wqe_size
 *		  void *object_priv
 * Output       : None
 * 1.Date         : 2016/3/1
 *   Modification : Created function
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_fc_srq_create(void *ex_handle, u32 service_type,
					       enum hinic5_cqm_object_type object_type,
					       u32 wqe_number, u32 wqe_size,
					       void *object_priv)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_nonrdma_qinfo *nonrdma_qinfo = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	u32 valid_wqe_per_buffer, buf_size, buf_num;
	u32 wqe_sum; /* include linkwqe, normal wqe */
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_fc_srq_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	if (!hinic5_cqm_object_fc_srq_param_check(handle, service_type, object_type, wqe_size))
		return NULL;

	service = &hinic5_cqm_handle->service[service_type];
	buf_size = (u32)(PAGE_SIZE << (service->buf_order));
	/* subtract 1 link wqe */
	valid_wqe_per_buffer = buf_size / wqe_size - 1;
	buf_num = wqe_number / valid_wqe_per_buffer;
	if (wqe_number % valid_wqe_per_buffer != 0)
		buf_num++;

	/* calculate the total number of WQEs */
	wqe_sum = buf_num * (valid_wqe_per_buffer + 1);
	nonrdma_qinfo = kzalloc(sizeof(*nonrdma_qinfo), GFP_KERNEL);
	if (unlikely(nonrdma_qinfo == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(nonrdma_qinfo));
		return NULL;
	}

	hinic5_cqm_object_init(&nonrdma_qinfo->common.object, service_type, object_type,
			wqe_sum, hinic5_cqm_handle);

	/* Initialize the doorbell used by the current queue.
	 * The default doorbell is the hardware doorbell.
	 */
	nonrdma_qinfo->common.current_q_doorbell = HINIC5_CQM_HARDWARE_DOORBELL;
	/* Currently, the connection mode is fixed. In the future,
	 * the service needs to transfer the connection mode.
	 */
	nonrdma_qinfo->common.queue_link_mode = HINIC5_CQM_QUEUE_RING_MODE;

	/* initialize public members */
	nonrdma_qinfo->common.priv = object_priv;
	nonrdma_qinfo->common.valid_wqe_num = wqe_sum - buf_num;

	/* initialize internal private members */
	nonrdma_qinfo->wqe_size = wqe_size;
	/* RQ (also called SRQ of FC) created by FC services,
	 * CTX needs to be created.
	 */
	nonrdma_qinfo->q_ctx_size = service->service_template.srq_ctx_size;

	ret = hinic5_cqm_nonrdma_queue_create(&nonrdma_qinfo->common.object);
	if (ret == HINIC5_CQM_SUCCESS)
		return &nonrdma_qinfo->common;

	hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_fc_queue_create));
	kfree(nonrdma_qinfo);
	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_fc_srq_create);

static bool hinic5_cqm_object_nonrdma_queue_param_check(struct hinic5_hwdev *handle,
						 enum hinic5_cqm_object_type object_type, u32 wqe_size)
{
	/* wqe_size can't be more than PAGE_SIZE, can't be zero, must be power
	 * of 2 the function of hinic5_cqm_check_align is to check above
	 */
	if (wqe_size >= PAGE_SIZE || (!hinic5_cqm_check_align(wqe_size))) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(wqe_size));
		return false;
	}

	/* nonrdma supports: RQ, SQ, SRQ, CQ, SCQ */
	if (object_type < HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_RQ ||
	    object_type > HINIC5_CQM_OBJECT_NONRDMA_SCQ) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return false;
	}

	return true;
}

/**
 * Prototype    : hinic5_cqm_object_nonrdma_queue_create
 * Description  : create nonrdma queue
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type: can be embedded RQ/SQ/CQ and
 *						    SRQ/SCQ.
 *		  u32 wqe_number: include link wqe
 *		  u32 wqe_size: fixed length, must be power of 2
 *		  void *object_priv: private structure of the service layer,
 *				     it can be NULL.
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_queue *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_nonrdma_queue_create(void *ex_handle, u32 service_type,
						      enum hinic5_cqm_object_type object_type,
						      u32 wqe_number, u32 wqe_size,
						      void *object_priv)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_nonrdma_qinfo *nonrdma_qinfo = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_nonrdma_queue_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	if (!hinic5_cqm_object_nonrdma_queue_param_check(handle, object_type, wqe_size))
		return NULL;

	nonrdma_qinfo = kzalloc(sizeof(*nonrdma_qinfo), GFP_KERNEL);
	if (unlikely(nonrdma_qinfo == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(nonrdma_qinfo));
		return NULL;
	}

	hinic5_cqm_object_init(&nonrdma_qinfo->common.object, service_type, object_type,
			wqe_number, hinic5_cqm_handle);

	/* Initialize the doorbell used by the current queue.
	 * The default value is hardware doorbell
	 */
	nonrdma_qinfo->common.current_q_doorbell = HINIC5_CQM_HARDWARE_DOORBELL;
	/* Currently, the link mode is hardcoded and needs to be transferred by
	 * the service side.
	 */
	nonrdma_qinfo->common.queue_link_mode = HINIC5_CQM_QUEUE_RING_MODE;

	nonrdma_qinfo->common.priv = object_priv;

	/* Initialize internal private members */
	nonrdma_qinfo->wqe_size = wqe_size;
	service = &hinic5_cqm_handle->service[service_type];
	if (object_type == HINIC5_CQM_OBJECT_NONRDMA_SCQ) {
		nonrdma_qinfo->q_ctx_size = service->service_template.scq_ctx_size;
	} else if (object_type == HINIC5_CQM_OBJECT_NONRDMA_SRQ) {
		/* Currently, the SRQ of the service is created through a
		 * dedicated interface.
		 */
		nonrdma_qinfo->q_ctx_size = service->service_template.srq_ctx_size;
	}

	ret = hinic5_cqm_nonrdma_queue_create(&nonrdma_qinfo->common.object);
	if (ret == HINIC5_CQM_SUCCESS)
		return &nonrdma_qinfo->common;

	hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_nonrdma_queue_create));
	kfree(nonrdma_qinfo);
	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_nonrdma_queue_create);

static bool hinic5_cqm_object_rdma_queue_param_check(struct hinic5_hwdev *handle, u32 service_type,
					      enum hinic5_cqm_object_type object_type)
{
	/* service_type must be HINIC5_CQM_SERVICE_T_ROCE or HINIC5_CQM_SERVICE_T_UB */
	if (service_type != HINIC5_CQM_SERVICE_T_ROCE && service_type != HINIC5_CQM_SERVICE_T_UB && service_type != HINIC5_CQM_SERVICE_T_VBS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(service_type));
		return false;
	}

	/* rdma supports: QP, SRQ, SCQ */
	if (object_type > HINIC5_CQM_OBJECT_RDMA_SCQ || object_type < HINIC5_CQM_OBJECT_RDMA_QP) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return false;
	}

	return true;
}

/**
 * Prototype    : hinic5_cqm_object_rdma_queue_create
 * Description  : create rdma queue
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type: can be QP and SRQ/SCQ.
 *		  u32 object_size
 *		  void *object_priv: private structure of the service layer,
 *				     it can be NULL.
 *		  bool room_header_alloc: Whether to apply for queue room and
 *					  header space
 *		  u32 xid: apply for the reserved qpn 0~(1M-1) based on this value;
 *			   if automatic allocation is required,
 *			   xid[20:0]  : fixed to 0x1fffff
 *			   xid[23:21] : specified xid_lowbits[2:0]
 *			   xid[26:24] : xid[2:0] match mode, see HINIC5_CQM_DYNAMIC_XID_MOD
 *			   xid[27]    : search mode,
 *					0---specify the XID range,
 *					1---search for the entire dynamic area
 *			   xid[31:28] : rsvd
 *			   notes: when index is HINIC5_CQM_INDEX_INVALID, means match all available xid
 *		  u32 bitmap_start: start index of dynamic xid search range,
 *				    valid when index[25]=0 && index[20:0]=0x1fffff
 *		  u32 bitmap_end: end index of dynamic xid search range,
 *				  valid when index[25]=0 && index[20:0]=0x1fffff
 *				  when search forward(bitmap_start<bitmap_end),
 *				    search range is [bitmap_start, bitmap_end)
 *				  when search reverse(bitmap_start>bitmap_end),
 *				    search range is (bitmap_end, bitmap_start].
 *				  bitmap_start=bitmap_end is illegal in range search mode
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_queue *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_rdma_queue_create(void *ex_handle, u32 service_type,
						   enum hinic5_cqm_object_type object_type,
						   u32 object_size, void *object_priv,
						   bool room_header_alloc, u32 xid,
						   u32 bitmap_start, u32 bitmap_end)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_rdma_qinfo *rdma_qinfo = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	struct tag_hinic5_cqm_bitmap_range bp_range;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_rdma_queue_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	if (!hinic5_cqm_object_rdma_queue_param_check(handle, service_type, object_type))
		return NULL;

	rdma_qinfo = kzalloc(sizeof(*rdma_qinfo), GFP_KERNEL);
	if (unlikely(rdma_qinfo == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(rdma_qinfo));
		return NULL;
	}

	hinic5_cqm_object_init(&rdma_qinfo->common.object, service_type, object_type,
			object_size, hinic5_cqm_handle);
	rdma_qinfo->common.queue_link_mode = HINIC5_CQM_QUEUE_RDMA_QUEUE_MODE;
	rdma_qinfo->common.priv = object_priv;
	rdma_qinfo->common.current_q_room = HINIC5_CQM_RDMA_Q_ROOM_1;
	rdma_qinfo->room_header_alloc = room_header_alloc;
	rdma_qinfo->common.index = xid;
	bp_range.start = bitmap_start;
	bp_range.end = bitmap_end;

	/* Initializes the doorbell used by the current queue.
	 * The default value is hardware doorbell
	 */
	rdma_qinfo->common.current_q_doorbell = HINIC5_CQM_HARDWARE_DOORBELL;

	service = &hinic5_cqm_handle->service[service_type];
	if (object_type == HINIC5_CQM_OBJECT_RDMA_SCQ)
		rdma_qinfo->q_ctx_size = service->service_template.scq_ctx_size;
	else if (object_type == HINIC5_CQM_OBJECT_RDMA_SRQ)
		rdma_qinfo->q_ctx_size = service->service_template.srq_ctx_size;

	ret = hinic5_cqm_rdma_queue_create(&rdma_qinfo->common.object, &bp_range);
	if (ret == HINIC5_CQM_SUCCESS)
		return &rdma_qinfo->common;

	hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_rdma_queue_create));
	kfree(rdma_qinfo);
	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_rdma_queue_create);

/**
 * Prototype    : hinic5_cqm_object_rdma_table_get
 * Description  : create mtt and rdmarc of the rdma service
 * Input        : void *ex_handle
 *		  u32 service_type
 *		  enum hinic5_cqm_object_type object_type
 *		  u32 index_base: start of index
 *		  u32 index_number
 * Output       : None
 * Return Value : struct tag_hinic5_cqm_mtt_rdmarc *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
struct tag_hinic5_cqm_mtt_rdmarc *hinic5_cqm_object_rdma_table_get(void *ex_handle, u32 service_type,
						     enum hinic5_cqm_object_type object_type,
						     u32 index_base, u32 index_number)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_rdma_table *rdma_table = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_rdma_table_create_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (hinic5_cqm_object_create_check(hinic5_cqm_handle, service_type) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_create_check));
		return NULL;
	}

	/* service_type must be HINIC5_CQM_SERVICE_T_ROCE or HINIC5_CQM_SERVICE_T_UB */
	if (service_type != HINIC5_CQM_SERVICE_T_ROCE && service_type != HINIC5_CQM_SERVICE_T_UB) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(service_type));
		return NULL;
	}

	if (object_type != HINIC5_CQM_OBJECT_MTT &&
	    object_type != HINIC5_CQM_OBJECT_RDMARC) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object_type));
		return NULL;
	}

	rdma_table = kzalloc(sizeof(*rdma_table), GFP_KERNEL);
	if (unlikely(rdma_table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(rdma_table));
		return NULL;
	}

	hinic5_cqm_object_init(&rdma_table->common.object, service_type, object_type,
			(u32)(index_number * sizeof(dma_addr_t)), hinic5_cqm_handle);
	rdma_table->common.index_base = index_base;
	rdma_table->common.index_number = index_number;

	ret = hinic5_cqm_rdma_table_create(&rdma_table->common.object);
	if (ret == HINIC5_CQM_SUCCESS)
		return &rdma_table->common;

	hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_rdma_table_create));
	kfree(rdma_table);
	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_rdma_table_get);

static inline void hinic5_cqm_object_do_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = object->hinic5_cqm_handle;
	const u32 object_type = object->object_type;

	switch (object_type) {
	case HINIC5_CQM_OBJECT_SERVICE_CTX:
	case HINIC5_CQM_OBJECT_MPT:
		hinic5_cqm_qpc_mpt_delete(object);
		return;
	case HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_RQ:
	case HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_SQ:
	case HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_CQ:
	case HINIC5_CQM_OBJECT_NONRDMA_SCQ:
		hinic5_cqm_nonrdma_queue_delete(object);
		return;
	case HINIC5_CQM_OBJECT_NONRDMA_SRQ:
		if (object->service_type == HINIC5_CQM_SERVICE_T_TOE)
			hinic5_cqm_share_recv_queue_delete(object);
		else
			hinic5_cqm_nonrdma_queue_delete(object);
		return;
	case HINIC5_CQM_OBJECT_RDMA_QP:
	case HINIC5_CQM_OBJECT_RDMA_SRQ:
	case HINIC5_CQM_OBJECT_RDMA_SCQ:
		hinic5_cqm_rdma_queue_delete(object);
		return;
	case HINIC5_CQM_OBJECT_MTT:
	case HINIC5_CQM_OBJECT_RDMARC:
		hinic5_cqm_rdma_table_delete(object);
		return;
	default:
		hinic5_cqm_err(hinic5_cqm_handle->dev, HINIC5_CQM_WRONG_VALUE(object_type));
		return;
	}
}

/**
 * Prototype    : hinic5_cqm_object_delete
 * Description  : Deletes a created object. This function may be sleep and wait
 *		  for all operations on this object to be performed.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_object_delete(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct hinic5_hwdev *handle = NULL;

	if (unlikely(object == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(object));
		return;
	}
	if (!object->hinic5_cqm_handle) {
		pr_err("[HINIC5_CQM]object del: hinic5_cqm_handle is null, service type %u, refcount %d\n",
		       object->service_type, (int)object->refcount.counter);
		kfree(object);
		return;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;

	if (!hinic5_cqm_handle->ex_handle) {
		pr_err("[HINIC5_CQM]object del: ex_handle is null, service type %u, refcount %d\n",
		       object->service_type, (int)object->refcount.counter);
		kfree(object);
		return;
	}

	handle = hinic5_cqm_handle->ex_handle;

	if (object->service_type >= HINIC5_CQM_SERVICE_T_MAX) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(object->service_type));
		kfree(object);
		return;
	}

	hinic5_cqm_object_do_delete(object);
	kfree(object);
}
EXPORT_SYMBOL(hinic5_cqm_object_delete);

/**
 * Prototype    : hinic5_cqm_object_offset_addr
 * Description  : Only the rdma table can be searched to obtain the PA and VA
 *		  at the specified offset of the object buffer.
 * Input        : struct tag_hinic5_cqm_object *object
 *		  u32 offset: For a rdma table, the offset is the absolute index
 *			      number.
 *		  dma_addr_t *paddr: PA(physical address)
 * Output       : None
 * Return Value : u8 *
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
u8 *hinic5_cqm_object_offset_addr(struct tag_hinic5_cqm_object *object, u32 offset, dma_addr_t *paddr)
{
	u32 object_type;

	if (!object)
		return NULL;

	object_type = object->object_type;

	/* The data flow path takes performance into consideration and
	 * does not check input parameters.
	 */
	switch (object_type) {
	case HINIC5_CQM_OBJECT_MTT:
	case HINIC5_CQM_OBJECT_RDMARC:
		return hinic5_cqm_rdma_table_offset_addr(object, offset, paddr);
	default:
		break;
	}

	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_object_offset_addr);

/**
 * Prototype    : hinic5_cqm_object_get
 * Description  : Obtain an object based on the index.
 * Input        : void *ex_handle
 *		  enum hinic5_cqm_object_type object_type
 *		  u32 index: support qpn,mptn,scqn,srqn (n->number)
 *		  bool bh
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
struct tag_hinic5_cqm_object *hinic5_cqm_object_get(void *ex_handle, enum hinic5_cqm_object_type object_type,
				      u32 index, bool bh)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_bat_table *bat_table = NULL;
	struct tag_hinic5_cqm_object_table *object_table = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_object *object = NULL;

	if (!ex_handle)
		return NULL;

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (!hinic5_cqm_handle)
		return NULL;

	bat_table = &hinic5_cqm_handle->bat_table;

	/* The data flow path takes performance into consideration and
	 * does not check input parameters.
	 */
	switch (object_type) {
	case HINIC5_CQM_OBJECT_SERVICE_CTX:
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_QPC);
		break;
	case HINIC5_CQM_OBJECT_MPT:
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_MPT);
		break;
	case HINIC5_CQM_OBJECT_RDMA_SRQ:
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SRQC);
		break;
	case HINIC5_CQM_OBJECT_RDMA_SCQ:
	case HINIC5_CQM_OBJECT_NONRDMA_SCQ:
		cla_table = hinic5_cqm_cla_table_get(bat_table, HINIC5_CQM_BAT_ENTRY_T_SCQC);
		break;
	default:
		return NULL;
	}

	if (!cla_table) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_table_get));
		return NULL;
	}

	object_table = &cla_table->obj_table;
	object = hinic5_cqm_object_table_get(hinic5_cqm_handle, object_table, index, bh);
	return object;
}
EXPORT_SYMBOL(hinic5_cqm_object_get);

/**
 * Prototype    : hinic5_cqm_object_put
 * Description  : This function must be called after the hinic5_cqm_object_get
 *		  function. Otherwise, the object cannot be released.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_object_put(struct tag_hinic5_cqm_object *object)
{
	/* The data flow path takes performance into consideration and
	 * does not check input parameters.
	 */
	if (!object)
		return;

	if (atomic_dec_and_test(&object->refcount) != 0)
		complete(&object->free);
}
EXPORT_SYMBOL(hinic5_cqm_object_put);

/**
 * Prototype    : hinic5_cqm_object_funcid
 * Description  : Obtain the ID of the function to which the object belongs.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : If successful, the ID of the function will be returned.
 *		  If fail HINIC5_CQM_FAIL(-1) will be returned.
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_object_funcid(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;

	if (unlikely(object == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(object));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(object->hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;

	return hinic5_cqm_handle->func_attribute.func_global_idx;
}
EXPORT_SYMBOL(hinic5_cqm_object_funcid);

/**
 * Prototype    : hinic5_cqm_object_resize_alloc_new
 * Description  : Currently this function is only used for RoCE.
 *		  The CQ buffer is ajusted, but the cqn and cqc remain
 *		  unchanged. This function allocates new buffer, but do not
 *		  release old buffer. The valid buffer is still old buffer.
 * Input        : struct tag_hinic5_cqm_object *object
 *		  u32 object_size
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
s32 hinic5_cqm_object_resize_alloc_new(struct tag_hinic5_cqm_object *object, u32 object_size)
{
	struct tag_hinic5_cqm_rdma_qinfo *qinfo = (struct tag_hinic5_cqm_rdma_qinfo *)(void *)object;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	struct tag_hinic5_cqm_buf *q_room_buf = NULL;
	struct hinic5_hwdev *handle = NULL;
	u32 order, buf_size;

	if (unlikely(object == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(object));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(object->hinic5_cqm_handle));
		return HINIC5_CQM_FAIL;
	}
	handle = hinic5_cqm_handle->ex_handle;

	/* This interface is used only for the CQ of RoCE service. */
	if (object->service_type == HINIC5_CQM_SERVICE_T_ROCE &&
	    object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ) {
		service = hinic5_cqm_handle->service + object->service_type;
		order = service->buf_order;
		buf_size = (u32)(PAGE_SIZE << order);

		if (qinfo->common.current_q_room == HINIC5_CQM_RDMA_Q_ROOM_1)
			q_room_buf = &qinfo->common.q_room_buf_2;
		else
			q_room_buf = &qinfo->common.q_room_buf_1;

		if (qinfo->room_header_alloc) {
			q_room_buf->buf_number = ALIGN(object_size, buf_size) /
						 buf_size;
			q_room_buf->page_number = q_room_buf->buf_number <<
						  order;
			q_room_buf->buf_size = buf_size;
			if (hinic5_cqm_buf_alloc(hinic5_cqm_handle, q_room_buf, true) ==
			    HINIC5_CQM_FAIL) {
				hinic5_cqm_err(handle->dev_hdl,
					HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_buf_alloc));
				return HINIC5_CQM_FAIL;
			}

			qinfo->new_object_size = object_size;
			return HINIC5_CQM_SUCCESS;
		}

		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_WRONG_VALUE(qinfo->room_header_alloc));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_err(handle->dev_hdl, "Cq resize alloc: service_type %u object_type %u do not support resize\n",
		object->service_type, object->object_type);
	return HINIC5_CQM_FAIL;
}
EXPORT_SYMBOL(hinic5_cqm_object_resize_alloc_new);

/**
 * Prototype    : hinic5_cqm_object_resize_free_new
 * Description  : Currently this function is only used for RoCE.
 *		  The CQ buffer is ajusted, but the cqn and cqc remain
 *		  unchanged. This function frees new buffer, and is used to deal
 *		  with exceptions.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_object_resize_free_new(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_rdma_qinfo *qinfo = (struct tag_hinic5_cqm_rdma_qinfo *)(void *)object;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_buf *q_room_buf = NULL;
	struct hinic5_hwdev *handle = NULL;

	if (unlikely(object == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(object));
		return;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}
	handle = hinic5_cqm_handle->ex_handle;

	/* This interface is used only for the CQ of RoCE service. */
	if (object->service_type == HINIC5_CQM_SERVICE_T_ROCE &&
	    object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ) {
		if (qinfo->common.current_q_room == HINIC5_CQM_RDMA_Q_ROOM_1)
			q_room_buf = &qinfo->common.q_room_buf_2;
		else
			q_room_buf = &qinfo->common.q_room_buf_1;

		qinfo->new_object_size = 0;

		hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);
	} else {
		hinic5_cqm_err(handle->dev_hdl, "Cq resize free: service_type %u object_type %u do not support resize\n",
			object->service_type, object->object_type);
	}
}
EXPORT_SYMBOL(hinic5_cqm_object_resize_free_new);

/**
 * Prototype    : hinic5_cqm_object_resize_free_old
 * Description  : Currently this function is only used for RoCE.
 *		  The CQ buffer is ajusted, but the cqn and cqc remain
 *		  unchanged. This function frees old buffer and switches the
 *		  valid buffer to new buffer.
 * Input        : struct tag_hinic5_cqm_object *object
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_object_resize_free_old(struct tag_hinic5_cqm_object *object)
{
	struct tag_hinic5_cqm_rdma_qinfo *qinfo = (struct tag_hinic5_cqm_rdma_qinfo *)(void *)object;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_buf *q_room_buf = NULL;

	if (unlikely(object == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(object));
		return;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)object->hinic5_cqm_handle;
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}

	/* This interface is used only for the CQ of RoCE service. */
	if (object->service_type == HINIC5_CQM_SERVICE_T_ROCE &&
	    object->object_type == HINIC5_CQM_OBJECT_RDMA_SCQ) {
		if (qinfo->common.current_q_room == HINIC5_CQM_RDMA_Q_ROOM_1) {
			q_room_buf = &qinfo->common.q_room_buf_1;
			qinfo->common.current_q_room = HINIC5_CQM_RDMA_Q_ROOM_2;
		} else {
			q_room_buf = &qinfo->common.q_room_buf_2;
			qinfo->common.current_q_room = HINIC5_CQM_RDMA_Q_ROOM_1;
		}

		object->object_size = qinfo->new_object_size;

		hinic5_cqm_buf_free(q_room_buf, hinic5_cqm_handle->dev);
	}
}
EXPORT_SYMBOL(hinic5_cqm_object_resize_free_old);

/**
 * Prototype    : hinic5_cqm_gid_base
 * Description  : Obtain the base virtual address of the gid table for FT
 *		  debug.
 * Input        : void *ex_handle
 * Output       : None
 * 1.Date       : 2015/9/8
 * Modification : Created function
 */
void *hinic5_cqm_gid_base(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bat_table *bat_table = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_buf *cla_z_buf = NULL;
	u32 entry_type, i;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return NULL;
	}

	bat_table = &hinic5_cqm_handle->bat_table;
	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		entry_type = bat_table->bat_entry_type[i];
		if (entry_type == HINIC5_CQM_BAT_ENTRY_T_GID) {
			cla_table = &bat_table->entry[i];
			cla_z_buf = &cla_table->cla_z_buf;
			if (cla_z_buf->buf_list)
				return cla_z_buf->buf_list->va;
		}
	}

	return NULL;
}

/**
 * Prototype    : hinic5_cqm_timer_base
 * Description  : Obtain the base virtual address of the timer for live
 *		  migration.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2020/5/21
 *   Modification : Created function
 */
void *hinic5_cqm_timer_base(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_bat_table *bat_table = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_buf *cla_z_buf = NULL;
	u32 entry_type, i;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return NULL;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return NULL;
	}

	/* Timer resource is configured on PPF. */
	if (!HINIC5_CQM_IS_PPF(hinic5_cqm_handle)) {
		hinic5_cqm_err(handle->dev_hdl, "%s: wrong function type:%d\n",
			__func__, handle->hwif->attr.func_type);
		return NULL;
	}

	bat_table = &hinic5_cqm_handle->bat_table;

	for (i = 0; i < HINIC5_CQM_BAT_ENTRY_MAX; i++) {
		entry_type = bat_table->bat_entry_type[i];
		if (entry_type != HINIC5_CQM_BAT_ENTRY_T_TIMER)
			continue;

		cla_table = &bat_table->entry[i];
		cla_z_buf = &cla_table->cla_z_buf;

		if (!cla_z_buf->direct.va) {
			if (hinic5_cqm_buf_alloc_direct(hinic5_cqm_handle, cla_z_buf, true) ==
			    HINIC5_CQM_FAIL) {
				hinic5_cqm_err(handle->dev_hdl,
					HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_buf_alloc_direct));
				return NULL;
			}
		}

		return cla_z_buf->direct.va;
	}

	return NULL;
}
EXPORT_SYMBOL(hinic5_cqm_timer_base);

static inline bool val_in_range(u32 val, u32 start, u32 num)
{
	return val >= start && val - start < num;
}

/* Convert func id to func offset used in timer buffers. */
STATIC s32 hinic5_cqm_timer_get_func_offset(struct hinic5_hwdev *ex_handle,
				     u32 func_id, u32 *func_offset)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = ex_handle->hinic5_cqm_hdl;
	struct tag_hinic5_cqm_func_capability *cap = &hinic5_cqm_handle->func_capability;
	u32 vf_offset;
	int i;

	/* PF */
	if (val_in_range(func_id, cap->timer_pf_id_start, cap->timer_pf_num)) {
		*func_offset = func_id - cap->timer_pf_id_start;
		return HINIC5_CQM_SUCCESS;
	}

	if (!val_in_range(func_id, cap->timer_vf_id_start, cap->timer_vf_num))
		goto fail;

	if (!cap->timer_vf_deploy_with_segs) {
		vf_offset = func_id - cap->timer_vf_id_start;
		*func_offset = cap->timer_pf_num + vf_offset;
		return HINIC5_CQM_SUCCESS;
	}

	/* Timer buffer segmentation deployment */
	vf_offset = 0;
	for (i = 0; i < ARRAY_SIZE(cap->timer_vf_segs); i++) {
		struct timer_vf_info_seg *seg = &cap->timer_vf_segs[i];
		if (seg->start == 0)
			break;
		if (val_in_range(func_id, seg->start, seg->num)) {
			vf_offset += func_id - seg->start;
			*func_offset = cap->timer_pf_num + vf_offset;
			return HINIC5_CQM_SUCCESS;
		}
		vf_offset += seg->num;
	}

fail:
	hinic5_cqm_err(ex_handle->dev_hdl,
		"Timer clear: wrong func id %u\n", func_id);
	return HINIC5_CQM_FAIL;
}

STATIC void hinic5_cqm_clear_timer(struct hinic5_hwdev *handle, u32 func_id,
			    struct tag_hinic5_cqm_cla_table *cla_table)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = handle->hinic5_cqm_hdl;
	struct tag_hinic5_cqm_func_capability *cap = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_buf *cla_buf = &cla_table->cla_z_buf;
	u32 func_timer_size = HINIC5_CQM_TIMER_ALIGN_SCALE_NUM * cap->timer_basic_size;
	u32 func_buf_num = 0, func_offset = 0;
	u32 i, func_buf_start, func_buf_end;
	s32 ret;

	ret = hinic5_cqm_timer_get_func_offset(handle, func_id, &func_offset);
	if (ret == HINIC5_CQM_FAIL) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_timer_get_func_offset));
		return;
	}

	if (cla_buf->buf_size == 0)
		goto fail;
	func_buf_num = func_timer_size / cla_buf->buf_size;
	if (func_buf_num == 0) {
		/* Func timer size smaller than CLA buffer? Not yet implemented */
		goto fail;
	}

	func_buf_start = func_offset * func_buf_num;
	func_buf_end   = func_buf_start + func_buf_num;
	if (func_buf_end > cla_buf->buf_number) {
		hinic5_cqm_err(handle->dev_hdl,
			"Timer clear: func buffer end %u overflow, limit %u.\n",
			func_buf_end, cla_buf->buf_number);
		goto fail;
	}

	hinic5_cqm_dbg(handle->dev_hdl,
		"Timer clear: func id %u, offset %u. cla lvl %u.\n",
		func_id, func_offset, cla_table->cla_lvl);

	for (i = func_buf_start; i < func_buf_end; i++) {
		hinic5_cqm_dbg_on(hinic5_cqm_verbose, handle->dev_hdl,
			"Timer clear: buf %4u, pa 0x%lx, va 0x%lx\n",
			i, (uintptr_t)cla_buf->buf_list[i].pa,
			(uintptr_t)cla_buf->buf_list[i].va);
		memset(cla_buf->buf_list[i].va, 0, cla_buf->buf_size);
	}
	return;

fail:
	hinic5_cqm_err(handle->dev_hdl,
		"Timer clear: failed. timer cla lvl %u, buf size %u, buf num 0x%x\n",
		cla_table->cla_lvl, cla_buf->buf_size, cla_buf->buf_number);
	hinic5_cqm_err(handle->dev_hdl,
		"Timer clear: func id %u, offset %u. func timer size 0x%x, func buf num %u\n",
		func_id, func_offset, func_timer_size, func_buf_num);
}

/**
 * Prototype    : hinic5_cqm_function_timer_clear
 * Description  : Clear the timer buffer based on the function ID.
 *		  The function ID starts from 0 and the timer buffer is arranged
 *		  in sequence by function ID.
 * Input        : void *ex_handle
 *		  u32 functionid
 * Output       : None
 * Return Value : void
 * 1.Date         : 2016/12/19
 *   Modification : Created function
 */
void hinic5_cqm_function_timer_clear(void *ex_handle, u32 function_id)
{
	/* The timer buffer of one function is 32B*8wheel*2048spoke=128*4k */
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	u32 loop, i;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_func_timer_clear_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}

	if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle)) {
		cla_table = &hinic5_cqm_handle->bat_table.timer_entry[0];
		loop = hinic5_cqm_handle->func_capability.smf_max_num;
	} else {
		cla_table = hinic5_cqm_cla_table_get(&hinic5_cqm_handle->bat_table, HINIC5_CQM_BAT_ENTRY_T_TIMER);
		loop = 1;
	}

	if (unlikely(cla_table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(cla_table));
		return;
	}
	for (i = 0; i < loop; i++) {
		hinic5_cqm_clear_timer(handle, function_id, cla_table);
		cla_table++;
	}
}
EXPORT_SYMBOL(hinic5_cqm_function_timer_clear);

/**
 * Prototype    : hinic5_cqm_function_hash_buf_clear
 * Description  : clear hash buffer based on global function_id
 * Input        : void *ex_handle
 *		  s32 global_funcid
 * Output       : None
 * Return Value : None
 * 1.Date         : 2017/11/27
 *   Modification : Created function
 * 2.Date         : 2021/02/23
 *   Modification : Add para func_id; clear hash buf by func_id
 */
void hinic5_cqm_function_hash_buf_clear(void *ex_handle, s32 global_funcid)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_func_capability *func_cap = NULL;
	struct tag_hinic5_cqm_cla_table *cla_table = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_buf *cla_z_buf = NULL;
	s32 fake_funcid;
	u32 loop;
	u32 i;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_func_hash_buf_clear_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}
	func_cap = &hinic5_cqm_handle->func_capability;

	/* fake vf adaption, switch to corresponding VF. */
	if (HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle)) {
		fake_funcid = global_funcid -
			      (s32)(func_cap->fake_cfg.child_func_start);
		hinic5_cqm_info(handle->dev_hdl, "fake_funcid =%d\n", fake_funcid);
		if (fake_funcid < 0 || fake_funcid >= HINIC5_CQM_FAKE_FUNC_MAX) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(fake_funcid));
			return;
		}

		hinic5_cqm_handle = hinic5_cqm_handle->fake_hinic5_cqm_handle[fake_funcid];
	}

	if (HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle)) {
		cla_table = &hinic5_cqm_handle->bat_table.hash_entry[0];
		loop = hinic5_cqm_handle->func_capability.smf_max_num;
	} else {
		cla_table = hinic5_cqm_cla_table_get(&hinic5_cqm_handle->bat_table, HINIC5_CQM_BAT_ENTRY_T_HASH);
		loop = 1;
	}

	if (unlikely(cla_table == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(cla_table));
		return;
	}

	while (loop > 0) {
		cla_z_buf = &cla_table->cla_z_buf;

		for (i = 0; i < cla_z_buf->buf_number; i++)
			memset(cla_z_buf->buf_list[i].va, 0, cla_z_buf->buf_size);

		cla_table++;
		loop--;
	}
}
EXPORT_SYMBOL(hinic5_cqm_function_hash_buf_clear);

void hinic5_cqm_srq_used_rq_container_delete(struct tag_hinic5_cqm_object *object, u8 *container)
{
	struct tag_hinic5_cqm_queue *common = NULL;
	struct tag_hinic5_cqm_nonrdma_qinfo *qinfo = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_srq_linkwqe *srq_link_wqe = NULL;
	struct hinic5_hwdev *handle = NULL;
	dma_addr_t addr;
	u32 link_wqe_offset;

	if (!object || !container) {
		pr_err("object or container is null\n");
		return;
	}

	common = container_of(object, struct tag_hinic5_cqm_queue, object);
	qinfo = container_of(common, struct tag_hinic5_cqm_nonrdma_qinfo, common);
	link_wqe_offset = qinfo->wqe_per_buf * qinfo->wqe_size;
	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(common->object.hinic5_cqm_handle);
	handle = hinic5_cqm_handle->ex_handle;

	/* 1. Obtain the current container pa through link wqe table,
	 * unmap pa
	 */
	srq_link_wqe = (struct tag_hinic5_cqm_srq_linkwqe *)((uintptr_t)container + link_wqe_offset);
	/* shift right by 2 bits to get the length of dw(4B) */
	hinic5_cqm_swab32((u8 *)(srq_link_wqe), sizeof(struct tag_hinic5_cqm_linkwqe) >> 2);

	addr = HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_gpa_h,
				srq_link_wqe->current_buffer_gpa_l);
	if (addr == 0) {
		hinic5_cqm_err(handle->dev_hdl, "Rq container del: buffer physical addr is null\n");
		return;
	}
	dma_unmap_single(hinic5_cqm_handle->dev, addr, qinfo->container_size,
			 DMA_BIDIRECTIONAL);

	/* 2. Obtain the current container va through link wqe table, free va */
	addr = HINIC5_CQM_ADDR_COMBINE(srq_link_wqe->current_buffer_addr_h,
				srq_link_wqe->current_buffer_addr_l);
	if (addr == 0) {
		hinic5_cqm_err(handle->dev_hdl, "Rq container del: buffer virtual addr is null\n");
		return;
	}
	kfree((void *)(uintptr_t)addr);
}
EXPORT_SYMBOL(hinic5_cqm_srq_used_rq_container_delete);

s32 hinic5_cqm_dtoe_share_recv_queue_create(void *ex_handle, u32 contex_size,
				     u32 *index_count, u32 *index)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_toe_private_capability *tow_own_cap = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;
	u32 step;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(index_count == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(index_count));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(index == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(index));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return HINIC5_CQM_FAIL;
	}

	tow_own_cap = &hinic5_cqm_handle->toe_own_capability;

	bitmap = &tow_own_cap->srqc_bitmap;
	*index_count = (ALIGN(contex_size, tow_own_cap->toe_srqc_basic_size)) /
		       tow_own_cap->toe_srqc_basic_size;
	/* toe srqc number must align of 2 */
	step = ALIGN(tow_own_cap->toe_srqc_number, 2);
	*index = hinic5_cqm_bitmap_alloc(bitmap, step, *index_count,
				  hinic5_cqm_handle->func_capability.xid_alloc_mode);
	if (*index >= bitmap->max_num) {
		hinic5_cqm_err(handle->dev_hdl, "Srq create: queue index %u exceeds max_num %u\n",
			*index, bitmap->max_num);
		return HINIC5_CQM_FAIL;
	}
	*index += tow_own_cap->toe_srqc_start_id;

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_srq_create_cnt);

	return HINIC5_CQM_SUCCESS;
}
EXPORT_SYMBOL(hinic5_cqm_dtoe_share_recv_queue_create);

void hinic5_cqm_dtoe_free_srq_bitmap_index(void *ex_handle, u32 index_count, u32 index)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_bitmap *bitmap = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}

	bitmap = &hinic5_cqm_handle->toe_own_capability.srqc_bitmap;
	if ((index + index_count) > bitmap->max_num || (index + index_count) <= index) { // Avoid wrap-around
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_WRONG_VALUE(index + index_count));
		return;
	}

	hinic5_cqm_bitmap_free(bitmap, index, index_count);
}
EXPORT_SYMBOL(hinic5_cqm_dtoe_free_srq_bitmap_index);
