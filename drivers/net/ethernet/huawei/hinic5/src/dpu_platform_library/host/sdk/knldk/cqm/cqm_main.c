/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_main.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM main module implementation
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_mt.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_vram_api.h"
#include "hinic5_typedef_inner.h"

#include "vram_common.h"

#include "cqm_object.h"
#include "cqm_bitmap_table.h"
#include "cqm_bat_cla.h"
#include "cqm_bloomfilter.h"
#include "cqm_db.h"
#include "cqm_cmdq.h"
#include "cqm_main.h"

static s32 cqm_set_fake_vf_child_timer(struct tag_cqm_handle *cqm_handle,
	struct tag_cqm_handle *fake_cqm_handle, bool en)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)cqm_handle->ex_handle;
	u16 func_global_idx;
	s32 ret;

	if (fake_cqm_handle->func_capability.timer_enable == 0) {
		return CQM_SUCCESS;
	}

	func_global_idx = fake_cqm_handle->func_attribute.func_global_idx;
	ret = hinic5_func_tmr_bitmap_set(cqm_handle->ex_handle, func_global_idx, en);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, "func_id %u Timer %s timer bitmap failed\n",
			func_global_idx, en ? "enable" : "disable");
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

static void cqm_unset_fake_vf_timer(struct tag_cqm_handle *cqm_handle)
{
	u32 i, child_func_number = cqm_get_child_func_number(cqm_handle);

	for (i = 0; i < child_func_number; i++)
		(void)cqm_set_fake_vf_child_timer(cqm_handle, cqm_handle->fake_cqm_handle[i], false);
}

static s32 cqm_set_fake_vf_timer(struct tag_cqm_handle *cqm_handle)
{
	u32 i, child_func_number = cqm_get_child_func_number(cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		s32 ret = cqm_set_fake_vf_child_timer(cqm_handle, cqm_handle->fake_cqm_handle[i], true);
		if (ret != CQM_SUCCESS)
			goto err;
	}

	return CQM_SUCCESS;

err:
	cqm_unset_fake_vf_timer(cqm_handle);
	return CQM_FAIL;
}

static s32 cqm_set_timer_enable(void *ex_handle)
{
	struct hinic5_hwdev *handle = ex_handle;
	struct tag_cqm_handle *cqm_handle = handle->cqm_hdl;
	u16 func_id = hinic5_global_func_id(ex_handle);
	int is_in_kexec;

	is_in_kexec = vram5_get_kexec_flag();
	if (is_in_kexec != 0) {
		cqm_info(handle->dev_hdl, "Skip starting cqm timer during kexec\n");
		return CQM_SUCCESS;
	}

	/* Enable children */
	if (CQM_IS_FAKE_PARENT(cqm_handle) &&
	    cqm_set_fake_vf_timer(cqm_handle) != CQM_SUCCESS)
		return CQM_FAIL;

	/* Enable self */
	if (hinic5_func_tmr_bitmap_set(ex_handle, func_id, true) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, "Timer start: enable timer bitmap failed\n");
		goto err;
	}

	return CQM_SUCCESS;

err:
	if (CQM_IS_FAKE_PARENT(cqm_handle))
		cqm_unset_fake_vf_timer(cqm_handle);
	return CQM_FAIL;
}

static void cqm_set_timer_disable(void *ex_handle)
{
	struct hinic5_hwdev *handle = ex_handle;
	struct tag_cqm_handle *cqm_handle = handle->cqm_hdl;

	/* Disable self */
	if (hinic5_func_tmr_bitmap_set(ex_handle, hinic5_global_func_id(ex_handle),
				       false) != CQM_SUCCESS)
		cqm_err(handle->dev_hdl, "func_id %u Timer stop: disable timer bitmap failed\n",
			hinic5_global_func_id(ex_handle));

	/* Disable children */
	if (CQM_IS_FAKE_PARENT(cqm_handle))
		cqm_unset_fake_vf_timer(cqm_handle);
}

static u32 cqm_set_vio_enable(void *ex_handle, bool enable)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	int err;

	if (!ex_handle)
		return CQM_FAIL;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (!cqm_handle->service[CQM_SERVICE_T_VIRTIO].valid)
		return CQM_SUCCESS;

	err = hinic5_func_vio_en(ex_handle, enable);
	if (err != 0) {
		cqm_err(handle->dev_hdl, "VIO %s failed, err %d\n",
			(enable ? "enable" : "disable"), err);
		return CQM_FAIL;
	}

	cqm_info(handle->dev_hdl, "VIO %s success\n",
		 (enable ? "enable" : "disable"));
	return CQM_SUCCESS;
}

static s32 cqm5_initialize_recource(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	/* Initialize memory entries such as BAT, CLA, and bitmap. */
	if (cqm_mem_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_mem_init));
		return CQM_FAIL;
	}

	/* Event callback initialization */
	if (cqm_event_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_event_init));
		goto err1;
	}

	/* Doorbell initiation */
	if (cqm_db_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_db_init));
		goto err2;
	}

	/* Initialize the bloom filter. */
	if (cqm_bloomfilter_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bloomfilter_init));
		goto err3;
	}

	if (cqm_set_timer_enable(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_set_timer_enable));
		goto err4;
	}

	if (cqm_set_vio_enable(ex_handle, true) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_set_vio_enable));
		goto err5;
	}

	return CQM_SUCCESS;

err5:
	cqm_set_timer_disable(ex_handle);
err4:
	cqm_bloomfilter_uninit(ex_handle);
err3:
	cqm_db_uninit(ex_handle);
err2:
	cqm_event_uninit(ex_handle);
err1:
	cqm_mem_uninit(ex_handle);
	return CQM_FAIL;
}

static struct tag_cqm_handle *cqm_handle_create(void)
{
	struct tag_cqm_handle *cqm_handle = NULL;

	cqm_handle = kzalloc(sizeof(*cqm_handle), GFP_KERNEL);
	if (unlikely(!cqm_handle)) {
		CQM_PTR_CHECK_ERR(CQM_ALLOC_FAIL(cqm_handle));
		return NULL;
	}

	/* Clear the memory to prevent other systems from
	 * not clearing the memory.
	 */
	(void)memset(cqm_handle, 0,
		     sizeof(struct tag_cqm_handle));

	atomic_set(&cqm_handle->handle_state, CQM_HANDLE_STATE_INIT);

	return cqm_handle;
}

static struct tag_cqm_handle *cqm_handle_fork(struct tag_cqm_handle *parent_handle)
{
	struct tag_cqm_handle *child_handle = NULL;

	child_handle = kzalloc(sizeof(*child_handle), GFP_KERNEL);
	if (unlikely(!child_handle)) {
		CQM_PTR_CHECK_ERR(CQM_ALLOC_FAIL(child_handle));
		return NULL;
	}

	/* Copy the attributes of the parent CQM handle to the child CQM
	 * handle and modify the values of function.
	 */
	(void)memcpy(child_handle, parent_handle,
		     sizeof(struct tag_cqm_handle));

	/* Clear state & unlink some references */
	atomic_set(&child_handle->handle_state, CQM_HANDLE_STATE_INIT);
	(void)memset(child_handle->fake_cqm_handle, 0,
			sizeof(child_handle->fake_cqm_handle));

	return child_handle;
}

/**
 * Prototype    : cqm5_init
 * Description  : Complete CQM initialization.
 *		  If the function is a parent fake function, copy the fake.
 *		  If it is a child fake function (in the fake copy function,
 *		  not in this function), set fake_en in the BAT/CLA table.
 *		  cqm5_init->cqm_mem_init->cqm_fake_init(copy)
 *		  If the child fake conflict occurs, resources are not
 *		  initialized, but the timer must be enabled.
 *		  If the function is of the normal type,
 *		  follow the normal process.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/4/15
 * Modification   : Created function
 */
s32 cqm5_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}

	cqm_handle = cqm_handle_create();
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_FUNCTION_FAIL(cqm_handle_create));
		return CQM_FAIL;
	}

	cqm_handle->ex_handle = handle;
	cqm_handle->dev = handle->dev_hdl;
	handle->cqm_hdl = (void *)cqm_handle;

	/* 187x ops or 182x ops */
	cqm_cmdq_adapt_init(cqm_handle);
	/* Clearing Statistics */
	(void)memset(&handle->hw_stats.cqm_stats, 0, sizeof(struct cqm_stats));

	/* Reads VF/PF information. */
	cqm_handle->func_attribute = handle->hwif->attr;
	cqm_info(handle->dev_hdl, "Func init: function[%u] type %d(0:PF,1:VF,2:PPF)\n",
		cqm_handle->func_attribute.func_global_idx, cqm_handle->func_attribute.func_type);

	/* Read capability from configuration management module */
	ret = cqm_capability_init(ex_handle);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_capability_init));
		goto err1;
	}

	/* memory doorbell event bloomfilter timer init */
	if (cqm5_initialize_recource(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm5_initialize_recource));
		goto err1;
	}

	atomic_set(&cqm_handle->handle_state, CQM_HANDLE_STATE_READY);
	return CQM_SUCCESS;

err1:
	kfree(handle->cqm_hdl);
	handle->cqm_hdl = NULL;
	return CQM_FAIL;
}

/**
 * Prototype    : cqm5_uninit
 * Description  : Deinitializes the CQM module. This function is called once
 *		  each time a function is removed.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void cqm5_uninit(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return;
	}

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return;
	}

	atomic_set(&cqm_handle->handle_state, CQM_HANDLE_STATE_REMOVE);

	cqm_set_vio_enable(ex_handle, false);

	cqm_set_timer_disable(ex_handle);

	/* After the TMR timer stops, the system releases resources
	 * after a delay of one or two milliseconds.
	 */
	if (CQM_IS_PPF(cqm_handle)) {
		if (cqm_handle->func_capability.timer_enable ==
		    CQM_TIMER_ENABLE) {
			cqm_info(handle->dev_hdl, "PPF timer stop\n");
			ret = hinic5_ppf_tmr_stop(handle);
			if (ret != CQM_SUCCESS)
				/* The timer fails to be stopped,
				 * and the resource release is not affected.
				 */
				cqm_info(handle->dev_hdl, "PPF timer stop, ret=%d\n", ret);
		}

		usleep_range(0x384, 0x3E8); /* Somebody requires a delay of 1 ms,
					     * which is inaccurate.
					     */
	}

	/* Release Bloom Filter Table */
	cqm_bloomfilter_uninit(ex_handle);

	/* Release hardware doorbell */
	cqm_db_uninit(ex_handle);

	/* Cancel the callback of the event */
	cqm_event_uninit(ex_handle);

	/* Release various memory tables and require the service
	 * to release all objects.
	 */
	cqm_mem_uninit(ex_handle);

	/* Release cqm_handle */
	handle->cqm_hdl = NULL;
	kfree(cqm_handle);
}

static void cqm_test_mode_init(struct tag_cqm_handle *cqm_handle,
			       struct service_cap *service_capability)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	if (service_capability->test_mode == 0)
		return;

	cqm_info(handle->dev_hdl, "Enter CQM test mode\n");

	func_cap->qpc_number = service_capability->test_qpc_num;
	func_cap->qpc_reserved =
	    GET_MAX(func_cap->qpc_reserved,
		    service_capability->test_qpc_resvd_num);
	func_cap->xid_alloc_mode = service_capability->test_xid_alloc_mode;
	func_cap->gpa_check_enable = service_capability->test_gpa_check_enable;
	func_cap->pagesize_reorder = service_capability->test_page_size_reorder;
	func_cap->qpc_alloc_static =
	    (bool)(service_capability->test_qpc_alloc_mode);
	func_cap->scqc_alloc_static =
	    (bool)(service_capability->test_scqc_alloc_mode);
	func_cap->flow_table_based_conn_number =
	    service_capability->test_max_conn_num;
	func_cap->flow_table_based_conn_cache_number =
	    service_capability->test_max_cache_conn_num;
	func_cap->scqc_number = service_capability->test_scqc_num;
	func_cap->mpt_number = service_capability->test_mpt_num;
	func_cap->mpt_reserved = service_capability->test_mpt_recvd_num;
	func_cap->reorder_number = service_capability->test_reorder_num;
	/* 256K buckets, 256K*64B = 16MB */
	func_cap->hash_number = service_capability->test_hash_num;
}

static void cqm_service_capability_update(struct tag_cqm_handle *cqm_handle)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;

	func_cap->qpc_number = GET_MIN(CQM_MAX_QPC_NUM, func_cap->qpc_number);
	func_cap->scqc_number = GET_MIN(CQM_MAX_SCQC_NUM,
					func_cap->scqc_number);
	func_cap->srqc_number = GET_MIN(CQM_MAX_SRQC_NUM,
					func_cap->srqc_number);
	func_cap->childc_number = GET_MIN(CQM_MAX_CHILDC_NUM,
					  func_cap->childc_number);
}

static void cqm_service_valid_init(struct tag_cqm_handle *cqm_handle,
				   const struct service_cap *service_capability)
{
	u32 type = service_capability->chip_svc_type;
	struct tag_cqm_service *svc = cqm_handle->service;

	svc[CQM_SERVICE_T_NIC].valid    = (type & CFG_SERVICE_MASK_NIC) != 0;
	svc[CQM_SERVICE_T_OVS].valid    = (type & CFG_SERVICE_MASK_OVS) != 0;
	svc[CQM_SERVICE_T_ROCE].valid   = (type & CFG_SERVICE_MASK_ROCE) != 0;
	svc[CQM_SERVICE_T_TOE].valid    = (type & CFG_SERVICE_MASK_TOE) != 0;
	svc[CQM_SERVICE_T_FC].valid     = (type & CFG_SERVICE_MASK_FC) != 0;
	svc[CQM_SERVICE_T_IPSEC].valid  = (type & CFG_SERVICE_MASK_IPSEC) != 0;
	svc[CQM_SERVICE_T_VBS].valid    = (type & CFG_SERVICE_MASK_VBS) != 0;
	svc[CQM_SERVICE_T_VIRTIO].valid = (type & CFG_SERVICE_MASK_VIRTIO) != 0;
	svc[CQM_SERVICE_T_IOE].valid    = false;
	svc[CQM_SERVICE_T_PPA].valid    = (type & CFG_SERVICE_MASK_PPA) != 0;
	svc[CQM_SERVICE_T_UB].valid     = (type & CFG_SERVICE_MASK_UB) != 0;
	svc[CQM_SERVICE_T_JBOF].valid   = (type & CFG_SERVICE_MASK_JBOF) != 0;
	svc[CQM_SERVICE_T_VROCE].valid  = (type & CFG_SERVICE_MASK_VROCE) != 0;
	svc[CQM_SERVICE_T_DMMU].valid   = (type & CFG_SERVICE_MASK_DMMU) != 0;
	svc[CQM_SERVICE_T_CFM].valid    = (type & CFG_SERVICE_MASK_CFM) != 0;
}

static void cqm_service_capability_init_nic(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: nic is valid, but nic need not be init by cqm\n");
}

static void cqm_service_capability_init_ovs(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ovs_service_cap *ovs_cap = &service_capability->ovs_cap;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: ovs is valid\n");
	cqm_info(handle->dev_hdl, "Cap init: ovs qpc 0x%x\n",
		 ovs_cap->dev_ovs_cap.max_pctxs);
	func_cap->hash_number += ovs_cap->dev_ovs_cap.max_pctxs;
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
	func_cap->qpc_number += ovs_cap->dev_ovs_cap.max_pctxs;
	func_cap->qpc_basic_size = GET_MAX(ovs_cap->pctx_sz,
					   func_cap->qpc_basic_size);
	func_cap->qpc_reserved += ovs_cap->dev_ovs_cap.max_pctxs;
	func_cap->qpc_alloc_static = true;
	func_cap->pagesize_reorder = CQM_OVS_PAGESIZE_ORDER;
}

static void cqm_service_capability_roce_cap_print(struct hinic5_hwdev *handle,
	const struct hinic5_board_info *board_info, const struct dev_roce_svc_own_cap *roce_own_cap)
{
	cqm_info(handle->dev_hdl, "Cap init: roce is valid\n");
	cqm_info(handle->dev_hdl, "Cap init: roce qpc 0x%x, scqc 0x%x, srqc 0x%x, drc_qp 0x%x\n",
		 roce_own_cap->max_qps, roce_own_cap->max_cqs,
		 roce_own_cap->max_srqs, roce_own_cap->max_drc_qps);
	cqm_info(handle->dev_hdl, "Cap init: board_type 0x%x, scenes_id:0x%x, srv_bmp:0x%x\n",
		 board_info->board_type, board_info->scenes_id, board_info->service_en_bitmap);
	cqm_info(handle->dev_hdl, "Cap init: reserved_qps:0x%x, reserved_qps_back:0x%x, "
							  "reserved_cqs:0x%x, reserved_cqs_back:0x%x\n",
		 roce_own_cap->reserved_qps, roce_own_cap->reserved_qps_back,
		 roce_own_cap->reserved_cqs, roce_own_cap->reserved_cqs_back);
	cqm_info(handle->dev_hdl, "Cap init: reserved_srqs:0x%x, reserved_srqs_back:0x%x, "
							  "max_pd:0x%x, max_xrcd:0x%x, max_gid:0x%x\n",
		 roce_own_cap->reserved_srqs, roce_own_cap->reserved_srqs_back,
		 roce_own_cap->max_pd, roce_own_cap->max_xrcd, roce_own_cap->max_gid);
}

static void cqm_service_capability_init_roce(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct rdma_service_cap *rdma_cap = &service_capability->rdma_cap;
	struct dev_roce_svc_own_cap *roce_own_cap = &rdma_cap->dev_rdma_cap.roce_own_cap;

	cqm_service_capability_roce_cap_print(handle, &handle->board_info, roce_own_cap);

	func_cap->use_fake_parent_cla = true;

	if (COMM_SUPPORT_EXTEND_CAPBILITY(handle)) {
		func_cap->qpc_reserved += roce_own_cap->reserved_qps;
		func_cap->qpc_reserved_back += roce_own_cap->reserved_qps_back;
		func_cap->scq_reserved += roce_own_cap->reserved_cqs;
		func_cap->srq_reserved += roce_own_cap->reserved_srqs;
	} else {
		func_cap->qpc_reserved += CQM_QPC_ROCE_RSVD;
		func_cap->scq_reserved += CQM_CQ_ROCE_RSVD;
		func_cap->srq_reserved += CQM_SRQ_ROCE_RSVD;
	}

	func_cap->xid_alloc_mode = false; /* xid fast reuse */
	func_cap->qpc_number += roce_own_cap->max_qps;
	func_cap->qpc_basic_size = GET_MAX(roce_own_cap->qpc_entry_sz, func_cap->qpc_basic_size);
	func_cap->qpc_alloc_static = true;
	func_cap->scqc_alloc_static = true;
	func_cap->srqc_alloc_static = true;
	func_cap->scqc_number += roce_own_cap->max_cqs;
	func_cap->scqc_basic_size = GET_MAX(rdma_cap->cqc_entry_sz, func_cap->scqc_basic_size);
	func_cap->srqc_number += roce_own_cap->max_srqs;
	func_cap->srqc_basic_size = GET_MAX(roce_own_cap->srqc_entry_sz, func_cap->srqc_basic_size);
	func_cap->mpt_number += roce_own_cap->max_mpts;
	func_cap->mpt_reserved += rdma_cap->reserved_mrws;
	func_cap->mpt_basic_size = GET_MAX(rdma_cap->mpt_entry_sz, func_cap->mpt_basic_size);
	if (COMM_SUPPORT_EXTEND_CAPBILITY(handle))
		func_cap->gid_number = roce_own_cap->max_gid;
	else
		func_cap->gid_number = CQM_GID_RDMA_NUM;

	func_cap->gid_basic_size = CQM_GID_SIZE_32;
	func_cap->childc_number += roce_own_cap->max_child_ctx_num;
	func_cap->childc_basic_size = GET_MAX(CQM_CHILDC_SIZE_256, func_cap->childc_basic_size);
}

static void cqm_service_capability_init_vroce(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct rdma_service_cap *rdma_cap = &service_capability->rdma_cap;
	struct dev_roce_svc_own_cap *roce_own_cap = &rdma_cap->dev_rdma_cap.roce_own_cap;

	if (IS_MASTER_HOST(handle)) {
		func_cap->hash_number = roce_own_cap->max_qps;
		func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
		cqm_info(handle->dev_hdl, "Cap init: vroce is valid\n");
		cqm_info(handle->dev_hdl, "Cap init: hash_number 0x%x hash_basic_size 0x%x\n", func_cap->hash_number,
			func_cap->hash_basic_size);
	}
}

static void cqm_service_capability_init_toe(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_toe_private_capability *toe_own_cap = &cqm_handle->toe_own_capability;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct rdma_service_cap *rdma_cap = &service_capability->rdma_cap;
	struct toe_service_cap *toe_cap = &service_capability->toe_cap;
	struct dev_toe_svc_cap *dev_toe_cap = &toe_cap->dev_toe_cap;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: toe is valid\n");
	cqm_info(handle->dev_hdl, "Cap init: toe qpc 0x%x, scqc 0x%x, srqc 0x%x\n",
		 dev_toe_cap->max_pctxs, dev_toe_cap->max_cqs,
		 dev_toe_cap->max_srqs);
	func_cap->hash_number += dev_toe_cap->max_pctxs;
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
	func_cap->qpc_number += dev_toe_cap->max_pctxs;
	func_cap->qpc_basic_size = GET_MAX(toe_cap->pctx_sz,
					   func_cap->qpc_basic_size);
	func_cap->qpc_alloc_static = true;
	func_cap->scqc_number += dev_toe_cap->max_cqs;
	func_cap->scqc_basic_size = GET_MAX(toe_cap->scqc_sz,
					    func_cap->scqc_basic_size);
	func_cap->scqc_alloc_static = true;

	toe_own_cap->toe_srqc_number = dev_toe_cap->max_srqs;
	toe_own_cap->toe_srqc_start_id = dev_toe_cap->srq_id_start;
	toe_own_cap->toe_srqc_basic_size = CQM_SRQC_SIZE_64;
	func_cap->childc_number += dev_toe_cap->max_cctxt;
	func_cap->childc_basic_size = GET_MAX(CQM_CHILDC_SIZE_256,
					      func_cap->childc_basic_size);
	func_cap->mpt_number += dev_toe_cap->max_mpts;
	func_cap->mpt_reserved = 0;
	func_cap->mpt_basic_size = GET_MAX(rdma_cap->mpt_entry_sz,
					   func_cap->mpt_basic_size);
}

static void cqm_service_capability_init_ioe(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: ioe is valid\n");
}

static void cqm_service_capability_init_fc(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct fc_service_cap *fc_cap = &service_capability->fc_cap;
	struct dev_fc_svc_cap *dev_fc_cap = &fc_cap->dev_fc_cap;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: fc is valid\n");
	cqm_info(handle->dev_hdl, "Cap init: fc qpc 0x%x, scqc 0x%x, srqc 0x%x\n",
		 dev_fc_cap->max_parent_qpc_num, dev_fc_cap->scq_num,
		 dev_fc_cap->srq_num);
	func_cap->hash_number += dev_fc_cap->max_parent_qpc_num;
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
	func_cap->qpc_number += dev_fc_cap->max_parent_qpc_num;
	func_cap->qpc_basic_size = GET_MAX(fc_cap->parent_qpc_size,
					   func_cap->qpc_basic_size);
	func_cap->qpc_alloc_static = true;
	func_cap->scqc_number += dev_fc_cap->scq_num;
	func_cap->scqc_basic_size = GET_MAX(fc_cap->scqc_size,
					    func_cap->scqc_basic_size);
	func_cap->srqc_number += dev_fc_cap->srq_num;
	func_cap->srqc_basic_size = GET_MAX(fc_cap->srqc_size,
					    func_cap->srqc_basic_size);
	func_cap->lun_number = CQM_LUN_FC_NUM;
	func_cap->lun_basic_size = CQM_LUN_SIZE_8;
	func_cap->taskmap_number = CQM_TASKMAP_FC_NUM;
	func_cap->taskmap_basic_size = PAGE_SIZE;
	func_cap->childc_number += dev_fc_cap->max_child_qpc_num;
	func_cap->childc_basic_size = GET_MAX(fc_cap->child_qpc_size,
					      func_cap->childc_basic_size);
	func_cap->pagesize_reorder = CQM_FC_PAGESIZE_ORDER;
}

static void cqm_service_capability_init_vbs(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	cqm_info(handle->dev_hdl, "Cap init: vbs is valid\n");

	/* If the entry size is greater than the cache line (256 bytes),
	 * align the entries by cache line.
	 */
	func_cap->qpc_basic_size = GET_MAX(CQM_VBS_QPC_SIZE,
					   func_cap->qpc_basic_size);
	func_cap->qpc_alloc_static = true;
	func_cap->scqc_basic_size = CQM_VBS_SCQC_SIZE;
	func_cap->scqc_alloc_static = false;
	func_cap->scq_reserved += service_capability->vbs_cap.vbs_max_volq;
	func_cap->childc_number += service_capability->vbs_cap.vbs_child_ctx_num;
	func_cap->childc_basic_size = GET_MAX(CQM_CHILDC_SIZE_256, func_cap->childc_basic_size);
	func_cap->xid_alloc_mode = false;
	func_cap->hash_number += service_capability->vbs_cap.vbs_hash_bucket_num;
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;

	func_cap->qpc_number += service_capability->vbs_cap.vbs_max_volq;
	func_cap->scqc_number += service_capability->vbs_cap.vbs_max_volq;
}

static void cqm_service_capability_init_jbof(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct jbof_service_cap *jbof_cap = &service_capability->jbof_cap;

	cqm_info(handle->dev_hdl, "Cap init: jbof is valid\n");
	func_cap->qpc_alloc_static = true;
	func_cap->qpc_number += jbof_cap->max_parent_qpc_num;
	func_cap->qpc_basic_size = GET_MAX(jbof_cap->parent_qpc_size,
				func_cap->qpc_basic_size);
	func_cap->childc_number += jbof_cap->max_child_qpc_num;
	func_cap->childc_basic_size = GET_MAX(CQM_CHILDC_SIZE_256,
					      func_cap->childc_basic_size);
	func_cap->hash_number += jbof_cap->hash_bucket_num;
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
}

static void cqm_service_capability_init_ipsec(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ipsec_service_cap *ipsec_cap = &service_capability->ipsec_cap;
	struct dev_ipsec_svc_cap *ipsec_srvcap = &ipsec_cap->dev_ipsec_cap;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;

	func_cap->childc_number += (ipsec_srvcap->max_sactxs + ipsec_srvcap->max_spctxs);
	func_cap->childc_basic_size = GET_MAX(CQM_CHILDC_SIZE_256,
					      func_cap->childc_basic_size);
	func_cap->scqc_number += ipsec_srvcap->max_cqs;
	func_cap->scqc_basic_size = GET_MAX(CQM_SCQC_SIZE_64,
					    func_cap->scqc_basic_size);
	func_cap->scqc_alloc_static = true;
	func_cap->hash_number += CQM_CRYPT_HASH_BUCKET_NUM(ipsec_srvcap->sa_hash_bucket_num + ipsec_srvcap->sp_hash_bucket_num);
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
	cqm_info(handle->dev_hdl, "Cap init: ipsec is valid\n");
	cqm_info(handle->dev_hdl, "Cap init: max_sactxs: 0x%x, max_spctxs: 0x%x, childc_bsize %u\n",
		ipsec_srvcap->max_sactxs, ipsec_srvcap->max_spctxs, func_cap->childc_basic_size);
	cqm_info(handle->dev_hdl, "scqc_num 0x%x, scqc_bsize %u\n", ipsec_srvcap->max_cqs, func_cap->scqc_basic_size);
	cqm_info(handle->dev_hdl,
		"Cap init: ipsec sa_hash_bucket_num: 0x%x, sp_hash_bucket_num: 0x%x, hash_basic_size %u\n",
		ipsec_srvcap->sa_hash_bucket_num, ipsec_srvcap->sp_hash_bucket_num, func_cap->hash_basic_size);
}

static void cqm_service_capability_init_virtio(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *svc_cap = (struct service_cap *)pra;
	u32 vq_num, vq_size, xid2cid_size;

	cqm_info(handle->dev_hdl, "Cap init: virtio is valid\n");

	vq_num = svc_cap->virtio_vq_num != 0 ? svc_cap->virtio_vq_num : CQM_VIRTIO_VQ_NUM_DEFAULT;
	vq_num += svc_cap->nvme_qp_num;
	vq_size = vq_num * svc_cap->virtio_vq_size;
	cqm_info(handle->dev_hdl, "Cap init: vq_num 0x%x, vq_size 0x%x\n", vq_num, vq_size);

	if (COMM_SUPPORT_VIRTIO_FC_CACHE(handle)) {
		/* In VirtIO function context cache mode,
		 * the VQs are divided and stored in all enabled SMFs. */
		xid2cid_size = vq_size / func_cap->smf_enabled_num;
		xid2cid_size += svc_cap->vio_func_num * CQM_VIRTIO_FC_SIZE;
		cqm_info(handle->dev_hdl, "Cap init: vio_func_num 0x%x\n", svc_cap->vio_func_num);
	} else {
		xid2cid_size = vq_size;
	}

	func_cap->xid2cid_number += xid2cid_size / CQM_CHIP_CACHELINE;
	func_cap->xid2cid_basic_size = CQM_CHIP_CACHELINE;

	cqm_info(handle->dev_hdl, "Cap init: xid2cid_size 0x%x, xid2cid_number 0x%x\n",
		 xid2cid_size, func_cap->xid2cid_number);
}

static void cqm_service_capability_init_ppa(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ppa_service_cap *ppa_cap = &service_capability->ppa_cap;

	cqm_info(handle->dev_hdl, "Cap init: ppa is valid\n");
	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;
	func_cap->qpc_alloc_static = true;
	func_cap->pagesize_reorder = CQM_PPA_PAGESIZE_ORDER;
	func_cap->qpc_basic_size = GET_MAX(ppa_cap->pctx_sz,
					   func_cap->qpc_basic_size);
}

static void cqm_service_capability_init_ub(struct tag_cqm_handle *cqm_handle, void *pra)
{
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ub_dev_cap_sdk_res *ub_sdk_res = &service_capability->ub_cap.sdk_res;

	cqm_info(handle->dev_hdl, "Cap init: ub is valid\n");

	func_cap->use_fake_parent_cla = true;

	func_cap->scqc_alloc_static = true;
	func_cap->scqc_basic_size = GET_MAX(func_cap->scqc_basic_size, ub_sdk_res->cqc_entry_sz);
	func_cap->scqc_number += ub_sdk_res->max_tp;
	func_cap->scqc_number += ub_sdk_res->max_jfc;
	func_cap->scqc_number += ub_sdk_res->max_jetty_grp;
	func_cap->scqc_number += ub_sdk_res->max_vtp;
	func_cap->scqc_number += ub_sdk_res->max_utp;
	func_cap->scqc_number += ub_sdk_res->max_tpg;

	func_cap->scq_reserved += ub_sdk_res->max_tp;
	func_cap->scq_reserved += ub_sdk_res->max_jfrc;

	func_cap->srqc_number += ub_sdk_res->max_jfr;
	func_cap->srqc_basic_size = ub_sdk_res->srqc_entry_sz;
	func_cap->srqc_alloc_static = true;

	func_cap->mpt_basic_size = GET_MAX(ub_sdk_res->mpt_entry_sz, func_cap->mpt_basic_size);
	func_cap->mpt_number += ub_sdk_res->max_mpts;

	func_cap->qpc_alloc_static = true;
	func_cap->qpc_number += ub_sdk_res->max_jetty;
	func_cap->qpc_number += ub_sdk_res->max_tp;
	func_cap->qpc_basic_size = GET_MAX(func_cap->qpc_basic_size, ub_sdk_res->qpc_entry_sz);
	func_cap->gid_number += ub_sdk_res->max_gid;
	func_cap->gid_basic_size = CQM_GID_SIZE_32;
	func_cap->childc_number += ub_sdk_res->max_tpg + (ub_sdk_res->max_tp >> 1);
	func_cap->childc_basic_size = GET_MAX(CQM_CHILDC_SIZE_256, func_cap->childc_basic_size);
}

struct cqm_srv_cap_init serv_cap_init_list[] = {
	{CQM_SERVICE_T_NIC,     cqm_service_capability_init_nic},
	{CQM_SERVICE_T_OVS,     cqm_service_capability_init_ovs},
	{CQM_SERVICE_T_ROCE,    cqm_service_capability_init_roce},
	{CQM_SERVICE_T_TOE,     cqm_service_capability_init_toe},
	{CQM_SERVICE_T_IOE,     cqm_service_capability_init_ioe},
	{CQM_SERVICE_T_FC,      cqm_service_capability_init_fc},
	{CQM_SERVICE_T_VBS,     cqm_service_capability_init_vbs},
	{CQM_SERVICE_T_IPSEC,   cqm_service_capability_init_ipsec},
	{CQM_SERVICE_T_VIRTIO,  cqm_service_capability_init_virtio},
	{CQM_SERVICE_T_PPA,     cqm_service_capability_init_ppa},
	{CQM_SERVICE_T_UB,      cqm_service_capability_init_ub},
	{CQM_SERVICE_T_JBOF,    cqm_service_capability_init_jbof},
	{CQM_SERVICE_T_VROCE,   cqm_service_capability_init_vroce},
};

static void cqm_service_capability_init(struct tag_cqm_handle *cqm_handle,
					struct service_cap *service_capability)
{
	u32 list_size = ARRAY_SIZE(serv_cap_init_list);
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	u32 i;

	for (i = 0; i < CQM_SERVICE_T_MAX; i++) {
		cqm_handle->service[i].valid = false;
		cqm_handle->service[i].has_register = false;
		cqm_handle->service[i].buf_order = 0;
	}

	cqm_service_valid_init(cqm_handle, service_capability);

	cqm_info(handle->dev_hdl, "Cap init: service type %d\n",
		 service_capability->chip_svc_type);

	for (i = 0; i < list_size; i++) {
		if (cqm_handle->service[serv_cap_init_list[i].service_type].valid &&
		    serv_cap_init_list[i].serv_cap_proc) {
			serv_cap_init_list[i].serv_cap_proc(cqm_handle, (void *)service_capability);
		}
	}
}

static u32 get_fake_func_type(struct tag_cqm_fake_cfg *fake_cfg, u16 func_id)
{
	if (func_id == fake_cfg->parent_func)
		return CQM_FAKE_FUNC_PARENT;

	if (func_id >= fake_cfg->child_func_start &&
	    func_id < (fake_cfg->child_func_start + fake_cfg->child_func_number))
		return CQM_FAKE_FUNC_CHILD;

	return CQM_FAKE_FUNC_UNUSED;
}

/* Set func_type in fake_cqm_handle to ppf, pf, or vf. */
static void cqm_set_func_type(struct tag_cqm_handle *cqm_handle)
{
	u32 idx = cqm_handle->func_attribute.func_global_idx;

	if (idx == 0)
		cqm_handle->func_attribute.func_type = CQM_PPF;
	else if (idx < CQM_MAX_PF_NUM)
		cqm_handle->func_attribute.func_type = CQM_PF;
	else
		cqm_handle->func_attribute.func_type = CQM_VF;
}

static int cqm_capability_init_smf(struct hinic5_hwdev *handle, struct service_cap *svc_cap)
{
	struct tag_cqm_handle *cqm_handle = handle->cqm_hdl;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;

	func_cap->lb_mode = svc_cap->lb_mode;

	if (svc_cap->smf_enabled_num == 0) {
		cqm_err(handle->dev_hdl, "SMF not enabled.\n");
		return -EINVAL;
	}

	/* Initializing the LB Mode */
	if (func_cap->lb_mode == CQM_LB_MODE_NORMAL)
		func_cap->smf_pg = 0;
	else
		func_cap->smf_pg = svc_cap->smf_pg;
	func_cap->smf_max_num = svc_cap->smf_max_num;
	func_cap->smf_enabled_num = svc_cap->smf_enabled_num;
	func_cap->bat_cid_index_bit_width = svc_cap->bat_cid_index_bit_width;

	cqm_info(handle->dev_hdl,
		 "Cap init: lb_mode %u, smf_pg %u, smf_max_num %u\n",
		 func_cap->lb_mode, func_cap->smf_pg, func_cap->smf_max_num);
	return 0;
}

static void cqm_capability_init_fake_vf(struct hinic5_hwdev *handle, struct service_cap *svc_cap)
{
	struct tag_cqm_handle *cqm_handle = handle->cqm_hdl;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct tag_cqm_fake_cfg *cfg = &func_cap->fake_cfg;

	func_cap->fake_func_type = CQM_FAKE_FUNC_UNUSED;
	(void)memset(cfg, 0, sizeof(*cfg));

	if (svc_cap->fake_vf_num != 0) {
		u32 parent_func_id = svc_cap->fake_vf_parent_func_id;
		if (parent_func_id == 0)
			parent_func_id = cqm_handle->func_attribute.port_to_port_idx;

		cfg->parent_func = parent_func_id;
		cfg->child_func_start = svc_cap->fake_vf_start_id;
		cfg->child_func_number = svc_cap->fake_vf_num_cfg;

		cfg->fake_vf_lazy_init = svc_cap->fake_vf_lazy_init;

		cfg->fake_vf_max_pctx       = svc_cap->fake_vf_max_pctx;
		cfg->fake_vf_max_scqc_ctx   = svc_cap->fake_vf_max_scqc_ctx;
		cfg->fake_vf_max_srqc_ctx   = svc_cap->fake_vf_max_srqc_ctx;
		cfg->fake_vf_max_gid_ctx    = svc_cap->fake_vf_max_gid_ctx;
		cfg->fake_vf_max_mpt_ctx    = svc_cap->fake_vf_max_mpt_ctx;
		cfg->fake_vf_max_childc_ctx = svc_cap->fake_vf_max_childc_ctx;

		if (svc_cap->fake_vf_qpc_ctx_size_en)
			cfg->fake_vf_qpc_basic_size = 0x1 << svc_cap->fake_vf_qpc_ctx_size_order;

		cfg->fake_vf_bfilter_start_addr = svc_cap->fake_vf_bfilter_start_addr;
		cfg->fake_vf_bfilter_len = svc_cap->fake_vf_bfilter_len;

		if (cfg->child_func_number > CQM_FAKE_FUNC_MAX) {
			cfg->child_func_number = CQM_FAKE_FUNC_MAX;
			cqm_warn(handle->dev_hdl, "child_func_number exceeds max supported, use %d default\n", CQM_FAKE_FUNC_MAX);
		}
		func_cap->fake_func_type = get_fake_func_type(cfg, hinic5_global_func_id(handle));
	}

	cqm_info(handle->dev_hdl,
		 "Cap init: fake_func_type %u, parent %u, child start %u num %u, lazy init %d\n",
		 func_cap->fake_func_type, cfg->parent_func,
		 cfg->child_func_start, cfg->child_func_number,
		 cfg->fake_vf_lazy_init);
}

static int cqm_capability_init_bloomfilter(struct hinic5_hwdev *handle)
{
	struct tag_cqm_handle *cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;

	func_cap->bloomfilter_enable = service_capability->bloomfilter_en;
	cqm_info(handle->dev_hdl, "Cap init: bloomfilter_enable %u (1: enable; 0: disable)\n",
		 func_cap->bloomfilter_enable);

	if (func_cap->bloomfilter_enable != 0) {
		func_cap->bloomfilter_length = service_capability->bfilter_len;
		func_cap->bloomfilter_addr = service_capability->bfilter_start_addr;
		if (func_cap->bloomfilter_length != 0 &&
		    !cqm_check_align(func_cap->bloomfilter_length)) {
			cqm_err(handle->dev_hdl, "Cap init: bloomfilter_length %u is not the power of 2\n",
				func_cap->bloomfilter_length);

			return CQM_FAIL;
		}
	}

	cqm_info(handle->dev_hdl, "Cap init: bloomfilter_length 0x%x, bloomfilter_addr 0x%x\n",
		 func_cap->bloomfilter_length, func_cap->bloomfilter_addr);

	return 0;
}

static void cqm_capability_init_part_cap(struct hinic5_hwdev *handle)
{
	struct tag_cqm_handle *cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;

	func_cap->flow_table_based_conn_number = service_capability->max_connect_num;
	func_cap->flow_table_based_conn_cache_number = service_capability->max_stick2cache_num;
	cqm_info(handle->dev_hdl, "Cap init: cfg max_conn_num 0x%x, max_cache_conn_num 0x%x\n",
		 func_cap->flow_table_based_conn_number,
		 func_cap->flow_table_based_conn_cache_number);

	func_cap->hash_basic_size = CQM_HASH_BUCKET_SIZE_64;

	func_cap->qpc_reserved = 0;
	func_cap->qpc_reserved_back = 0;
	func_cap->mpt_reserved = 0;
	func_cap->mpt_reserved_back = 0;
	func_cap->scq_reserved = 0;
	func_cap->scq_reserved_back = 0;
	func_cap->srq_reserved = 0;
	func_cap->srq_reserved_back = 0;
	func_cap->qpc_alloc_static = false;
	func_cap->scqc_alloc_static = false;
	func_cap->srqc_alloc_static = false;

	func_cap->l3i_number = 0;
	func_cap->l3i_basic_size = CQM_L3I_SIZE_8;

	func_cap->xid_alloc_mode = true; /* xid alloc do not reuse */
	func_cap->gpa_check_enable = true;
}

STATIC int cqm_get_ppf_timer_cfg(struct hinic5_hwdev *handle)
{
	struct tag_cqm_handle *cqm_handle = handle->cqm_hdl;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct timer_vf_info_seg *vf_segs = func_cap->timer_vf_segs;
	struct service_cap *svc_cap = &handle->cfg_mgmt->svc_cap;
	u16 vf_actual = 0;
	int i, err;

	err = hinic5_get_ppf_timer_cfg(handle);
	if (err != 0)
		return err;

	func_cap->timer_pf_id_start = svc_cap->timer_pf_id_start;
	func_cap->timer_pf_num      = svc_cap->timer_pf_num;
	func_cap->timer_vf_id_start = svc_cap->timer_vf_id_start;
	func_cap->timer_vf_num      = svc_cap->timer_vf_num;

	memcpy(func_cap->timer_vf_segs,
	       svc_cap->timer_vf_segs, sizeof(svc_cap->timer_vf_segs));

	for (i = 0; i < TIMER_VF_SEGS_NUM; i++) {
		if (vf_segs[i].start == 0)
			break;
		vf_actual += vf_segs[i].num;
	}

	func_cap->timer_vf_num_actual = vf_actual;
	if (vf_actual == 0)
		func_cap->timer_vf_num_actual = func_cap->timer_vf_num;

	cqm_info(handle->dev_hdl,
		 "host timer cfg: pf start %u, num %u. vf start %u, num %u, actual %u, seg deploy %d\n",
		 func_cap->timer_pf_id_start, func_cap->timer_pf_num,
		 func_cap->timer_vf_id_start, func_cap->timer_vf_num,
		 func_cap->timer_vf_num_actual,
		 func_cap->timer_vf_deploy_with_segs);

	cqm_info(handle->dev_hdl,
		 "vf timer segs: %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u\n",
		 vf_segs[0x0].start, vf_segs[0x0].start + vf_segs[0x0].num,
		 vf_segs[0x1].start, vf_segs[0x1].start + vf_segs[0x1].num,
		 vf_segs[0x2].start, vf_segs[0x2].start + vf_segs[0x2].num,
		 vf_segs[0x3].start, vf_segs[0x3].start + vf_segs[0x3].num,
		 vf_segs[0x4].start, vf_segs[0x4].start + vf_segs[0x4].num,
		 vf_segs[0x5].start, vf_segs[0x5].start + vf_segs[0x5].num,
		 vf_segs[0x6].start, vf_segs[0x6].start + vf_segs[0x6].num);
	return 0;
}

static int cqm_capability_init_timer(struct hinic5_hwdev *handle)
{
	struct tag_cqm_handle *cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	u32 total_timer_num = 0;
	int err;

	/* Initializes the PPF capabilities: include timer, pf, vf. */
	if (CQM_IS_PPF(cqm_handle) && (service_capability->timer_en != 0)) {
		func_cap->pf_num = service_capability->pf_num;
		func_cap->pf_id_start = service_capability->pf_id_start;
		func_cap->vf_num = service_capability->vf_num;
		func_cap->vf_id_start = service_capability->vf_id_start;
		cqm_info(handle->dev_hdl, "Cap init: total function num 0x%x\n",
			 service_capability->host_total_function);
		cqm_info(handle->dev_hdl, "Cap init: pf_num 0x%x, pf_id_start 0x%x, vf_num 0x%x, vf_id_start 0x%x\n",
			 func_cap->pf_num, func_cap->pf_id_start,
			 func_cap->vf_num, func_cap->vf_id_start);

		err = cqm_get_ppf_timer_cfg(handle);
		if (err != 0)
			return err;

		total_timer_num = func_cap->timer_pf_num + func_cap->timer_vf_num;
	}

	func_cap->timer_enable = service_capability->timer_en;
	cqm_info(handle->dev_hdl, "Cap init: timer_enable %u (1: enable; 0: disable)\n",
		 func_cap->timer_enable);

	func_cap->timer_number = CQM_TIMER_ALIGN_SCALE_NUM * total_timer_num;
	func_cap->timer_basic_size = CQM_TIMER_SIZE_32;

	return 0;
}

static void print_bat_cap(struct hinic5_hwdev *hwdev, const char *prefix_in,
			  struct tag_cqm_func_capability *cap)
{
	const char *prefix = prefix_in ? prefix_in : "";

	cqm_info(hwdev->dev_hdl, "%sCap init: hash number 0x%x\n",
		 prefix, cap->hash_number);
	cqm_info(hwdev->dev_hdl, "%sCap init: qpc number 0x%x, reserved 0x%x, basic size 0x%x, alloc static %d\n",
		 prefix, cap->qpc_number, cap->qpc_reserved, cap->qpc_basic_size,
		 cap->qpc_alloc_static);
	cqm_info(hwdev->dev_hdl, "%sCap init: scqc number 0x%x, reserved 0x%x, basic size 0x%x, alloc static %d\n",
		 prefix, cap->scqc_number, cap->scq_reserved, cap->scqc_basic_size,
		 cap->scqc_alloc_static);
	cqm_info(hwdev->dev_hdl, "%sCap init: srqc number 0x%x, reserved 0x%x, basic size 0x%x, alloc static %d\n",
		 prefix, cap->srqc_number, cap->srq_reserved, cap->srqc_basic_size,
		 cap->srqc_alloc_static);
	cqm_info(hwdev->dev_hdl, "%sCap init: mpt number 0x%x, reserved 0x%x\n",
		 prefix, cap->mpt_number, cap->mpt_reserved);
	cqm_info(hwdev->dev_hdl, "%sCap init: gid number 0x%x, lun number 0x%x\n",
		 prefix, cap->gid_number, cap->lun_number);
	cqm_info(hwdev->dev_hdl, "%sCap init: taskmap number 0x%x, l3i number 0x%x\n",
		 prefix, cap->taskmap_number, cap->l3i_number);
	cqm_info(hwdev->dev_hdl, "%sCap init: childc number 0x%x, basic size 0x%x\n",
		 prefix, cap->childc_number, cap->childc_basic_size);
	cqm_info(hwdev->dev_hdl, "%sCap init: timer number 0x%x\n",
		 prefix, cap->timer_number);
	cqm_info(hwdev->dev_hdl, "%sCap init: xid2cid number 0x%x, alloc static %d\n",
		 prefix, cap->xid2cid_number, cap->xid_alloc_mode);
	cqm_info(hwdev->dev_hdl, "%sCap init: reorder number 0x%x\n",
		 prefix, cap->reorder_number);
}

static void cqm_capability_init_cap_print(struct hinic5_hwdev *handle)
{
	struct tag_cqm_handle *cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;

	func_cap->ft_enable = service_capability->sf_svc_attr.ft_en;
	func_cap->rdma_enable = service_capability->sf_svc_attr.rdma_en;
	func_cap->gpa_spu_en = service_capability->func_gpa_spu_en;

	cqm_info(handle->dev_hdl, "Cap init: pagesize_reorder %u\n", func_cap->pagesize_reorder);
	cqm_info(handle->dev_hdl, "Cap init: acs_spu_en %u, gpa_check_enable %d\n",
		 func_cap->gpa_spu_en, func_cap->gpa_check_enable);
	cqm_info(handle->dev_hdl, "Cap init: ft_enable %d, rdma_enable %d\n",
		 func_cap->ft_enable, func_cap->rdma_enable);

	print_bat_cap(handle, NULL, func_cap);
}

/**
 * Prototype    : cqm_capability_init
 * Description  : Initializes the function and service capabilities of the CQM.
 *		  Information needs to be read from the configuration management
 *		  module.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/12/9
 *   Modification : Created function
 */
s32 cqm_capability_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct tag_cqm_func_capability *func_cap = &cqm_handle->func_capability;
	int err = 0;

	err = cqm_capability_init_timer(handle);
	if (err != 0)
		goto out;

	err = cqm_capability_init_bloomfilter(handle);
	if (err != 0)
		goto out;

	cqm_capability_init_part_cap(handle);

	err = cqm_capability_init_smf(handle, service_capability);
	if (err != 0)
		goto out;

	cqm_capability_init_fake_vf(handle, service_capability);

	cqm_service_capability_init(cqm_handle, service_capability);

	cqm_test_mode_init(cqm_handle, service_capability);

	cqm_service_capability_update(cqm_handle);

	cqm_capability_init_cap_print(handle);

	return CQM_SUCCESS;

out:
	if (CQM_IS_PPF(cqm_handle))
		func_cap->timer_enable = 0;

	return err;
}

static void cqm_fake_uninit(struct tag_cqm_handle *cqm_handle)
{
	u32 i;

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return;

	for (i = 0; i < CQM_FAKE_FUNC_MAX; i++) {
		kfree(cqm_handle->fake_cqm_handle[i]);
		cqm_handle->fake_cqm_handle[i] = NULL;
	}
}

static void set_fake_cqm_attr(struct hinic5_hwdev *handle, struct tag_cqm_handle *fake_cqm_handle,
			      u32 child_func_start, u32 i)
{
	struct hinic5_func_attr *func_attr = &fake_cqm_handle->func_attribute;
	struct tag_cqm_func_capability *func_cap = &fake_cqm_handle->func_capability;
	struct tag_cqm_fake_cfg *cfg = &func_cap->fake_cfg;

	func_attr->func_global_idx = (u16)(child_func_start + i);
	cqm_set_func_type(fake_cqm_handle);

	func_cap->fake_func_type = CQM_FAKE_FUNC_CHILD_AGENT;

	func_cap->qpc_number    = cfg->fake_vf_max_pctx;
	func_cap->scqc_number   = cfg->fake_vf_max_scqc_ctx;
	func_cap->srqc_number   = cfg->fake_vf_max_srqc_ctx;
	func_cap->gid_number    = cfg->fake_vf_max_gid_ctx;
	func_cap->mpt_number    = cfg->fake_vf_max_mpt_ctx;
	func_cap->childc_number = cfg->fake_vf_max_childc_ctx;
	func_cap->hash_number   = cfg->fake_vf_max_pctx;
	func_cap->qpc_reserved  = cfg->fake_vf_max_pctx;

	if (cfg->fake_vf_qpc_basic_size != 0)
		func_cap->qpc_basic_size = cfg->fake_vf_qpc_basic_size;

	if (cfg->fake_vf_bfilter_len != 0) {
		func_cap->bloomfilter_enable = true;
		func_cap->bloomfilter_addr = cfg->fake_vf_bfilter_start_addr +
			cfg->fake_vf_bfilter_len * i;
		func_cap->bloomfilter_length = cfg->fake_vf_bfilter_len;
	}

	cqm_service_capability_update(fake_cqm_handle);
}

static void print_fake_cqm_attr(struct hinic5_hwdev *hwdev, struct tag_cqm_handle *fake_cqm_handle)
{
	cqm_func_capability_s *fake_func_cap = &fake_cqm_handle->func_capability;
	struct hinic5_func_attr *fake_func_attr = &fake_cqm_handle->func_attribute;
	const u16 fake_func_id = fake_func_attr->func_global_idx;
	char prefix[0x20] = { 0 };
	cqm_info(hwdev->dev_hdl, "[Fake %u] global_func_idx %u, func_type %d, parent_func_idx %u\n",
		 fake_func_id, fake_func_id, fake_func_attr->func_type, hinic5_global_func_id(hwdev));

	if (sprintf(prefix, "[Fake %u] ", fake_func_id) < 0)
		print_bat_cap(hwdev, "[Fake]", fake_func_cap);
	else
		print_bat_cap(hwdev, prefix, fake_func_cap);
}

/**
 * Prototype    : cqm_fake_init
 * Description  : When the fake VF mode is supported, the CQM handles of
 *		  the fake VFs need to be copied.
 * Input        : struct tag_cqm_handle *cqm_handle: Parent CQM handle of the current PF
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2020/4/15
 *   Modification : Created function
 */
static s32 cqm_fake_init(struct tag_cqm_handle *cqm_handle)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct tag_cqm_handle *fake_cqm_handle = NULL;
	u32 child_func_start, child_func_number, i;

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return CQM_SUCCESS;

	child_func_start = cqm_get_child_func_start(cqm_handle);
	child_func_number = cqm_get_child_func_number(cqm_handle);
	if (child_func_number == 0) {
		cqm_warn(handle->dev_hdl, "no child func, skip fake init\n");
		return CQM_SUCCESS;
	}

	for (i = 0; i < child_func_number; i++) {
		fake_cqm_handle = cqm_handle_fork(cqm_handle);
		if (!fake_cqm_handle) {
			cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_handle_fork));
			goto err;
		}

		set_fake_cqm_attr(handle, fake_cqm_handle, (u32)child_func_start, i);
		print_fake_cqm_attr(handle, fake_cqm_handle);

		fake_cqm_handle->parent_cqm_handle = cqm_handle;
		cqm_handle->fake_cqm_handle[i] = fake_cqm_handle;
	}

	return CQM_SUCCESS;

err:
	cqm_fake_uninit(cqm_handle);
	return CQM_FAIL;
}

static void cqm_fake_mem_uninit(struct tag_cqm_handle *cqm_handle)
{
	struct tag_cqm_handle *fake_cqm_handle = NULL;
	u32 child_func_number, i;

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return;

	child_func_number = cqm_get_child_func_number(cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_cqm_handle = cqm_handle->fake_cqm_handle[i];
		atomic_set(&fake_cqm_handle->handle_state, CQM_HANDLE_STATE_REMOVE);

		cqm_object_table_uninit(fake_cqm_handle);
		cqm_bitmap_uninit(fake_cqm_handle);
		cqm_cla_uninit(fake_cqm_handle, CQM_BAT_ENTRY_MAX);
		cqm_bat_uninit(fake_cqm_handle);
	}
}

static s32 fake_cqm_handle_mem_init(struct tag_cqm_handle *fake_cqm_handle)
{
	struct hinic5_hwdev *handle = fake_cqm_handle->ex_handle;

	if (!CQM_IS_FAKE_CHILD_AGENT(fake_cqm_handle))
		return CQM_FAIL;

	if (atomic_cmpxchg(&fake_cqm_handle->handle_state,
			   CQM_HANDLE_STATE_INIT, CQM_HANDLE_STATE_READY
			   ) != CQM_HANDLE_STATE_INIT) {
		cqm_warn(handle->dev_hdl, "[Fake %u] mem already inited\n",
			 fake_cqm_handle->func_attribute.func_global_idx);
		return CQM_FAIL;
	}

	if (cqm_bat_init(fake_cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_init));
		goto err1;
	}

	if (cqm_cla_init(fake_cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_init));
		goto err2;
	}

	if (cqm_bitmap_init(fake_cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bitmap_init));
		goto err3;
	}

	if (cqm_object_table_init(fake_cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_object_table_init));
		goto err4;
	}

	cqm_info(handle->dev_hdl, "[Fake %u] mem inited\n",
		 fake_cqm_handle->func_attribute.func_global_idx);

	return CQM_SUCCESS;

err4:
	cqm_bitmap_uninit(fake_cqm_handle);
err3:
	cqm_cla_uninit(fake_cqm_handle, CQM_BAT_ENTRY_MAX);
err2:
	cqm_bat_uninit(fake_cqm_handle);
err1:
	cqm_fake_mem_uninit(fake_cqm_handle);
	return CQM_FAIL;
}

/**
 * Prototype    : cqm_fake_mem_init
 * Description  : Initialize resources of the extended fake function.
 * Input        : struct tag_cqm_handle *cqm_handle: Parent CQM handle of the current PF
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2020/4/15
 *   Modification : Created function
 */
static s32 cqm_fake_mem_init(struct tag_cqm_handle *cqm_handle)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct tag_cqm_handle *fake_cqm_handle = NULL;
	u32 child_func_number, i;
	int ret;

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return CQM_SUCCESS;

	child_func_number = cqm_get_child_func_number(cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_cqm_handle = cqm_handle->fake_cqm_handle[i];
		ret = snprintf(fake_cqm_handle->name, VRAM_NAME_MAX_LEN,
				 "%s%s%02u", cqm_handle->name, VRAM_CQM_FAKE_MEM_BASE, i);
		if (ret < 0) {
			cqm_err(handle->dev_hdl, "fake cqm handle vram name snprintf failed");
			return CQM_FAIL;
		}

		/* Fake VF lazy init support */
		if (cqm_is_fake_vf_lazy_init(cqm_handle)) {
			cqm_info(handle->dev_hdl, "[Fake %u] init delayed\n",
				fake_cqm_handle->func_attribute.func_global_idx);
			continue;
		}

		ret = fake_cqm_handle_mem_init(fake_cqm_handle);
		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				CQM_FUNCTION_FAIL(fake_cqm_handle_mem_init));
			goto err;
		}
	}

	return CQM_SUCCESS;

err:
	cqm_fake_mem_uninit(cqm_handle);
	return CQM_FAIL;
}

/**
 * Prototype    : cqm_mem_init
 * Description  : Initialize CQM memory, including tables at different levels.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
s32 cqm_mem_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	int ret;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	ret = snprintf(cqm_handle->name, VRAM_NAME_MAX_LEN,
			 "%s%02u", VRAM_CQM_GLB_FUNC_BASE, hinic5_global_func_id(handle));
	if (ret < 0) {
		cqm_err(handle->dev_hdl, "cqm handle vram name snprintf failed");
		return CQM_FAIL;
	}
	if (cqm_fake_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_fake_init));
		return CQM_FAIL;
	}

	if (cqm_fake_mem_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_fake_mem_init));
		goto err1;
	}

	if (cqm_bat_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_init));
		goto err2;
	}

	if (cqm_cla_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_init));
		goto err3;
	}

	if (cqm_bitmap_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bitmap_init));
		goto err4;
	}

	if (cqm_object_table_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_object_table_init));
		goto err5;
	}

	return CQM_SUCCESS;

err5:
	cqm_bitmap_uninit(cqm_handle);
err4:
	cqm_cla_uninit(cqm_handle, CQM_BAT_ENTRY_MAX);
err3:
	cqm_bat_uninit(cqm_handle);
err2:
	cqm_fake_mem_uninit(cqm_handle);
err1:
	cqm_fake_uninit(cqm_handle);
	return CQM_FAIL;
}

int cqm5_init_fake_vf(void *ex_handle, u32 vf_id)
{
	struct hinic5_hwdev *handle = ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_handle *fake_cqm_handle = NULL;
	u32 child_func_start, child_func_number;
	int err;

	if (unlikely(!ex_handle)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return -EINVAL;
	}

	cqm_handle = handle->cqm_hdl;
	if (unlikely(!cqm_handle)) {
		cqm_err(handle->dev_hdl, "Stateful not init\n");
		return -EINVAL;
	}

	if (unlikely(atomic_read(&cqm_handle->handle_state) != CQM_HANDLE_STATE_READY)) {
		cqm_err(handle->dev_hdl, "Stateful not ready\n");
		return -EAGAIN;
	}

	if (!CQM_IS_FAKE_PARENT(cqm_handle)) {
		cqm_err(handle->dev_hdl, "Not a Fake VF group parent\n");
		return -EPERM;
	}

	child_func_start  = cqm_get_child_func_start(cqm_handle);
	child_func_number = cqm_get_child_func_number(cqm_handle);
	if (vf_id < child_func_start || vf_id >= child_func_start + child_func_number) {
		cqm_err(handle->dev_hdl,
			"VF %u is not in the Fake VF group\n", vf_id);
		return -EINVAL;
	}

	fake_cqm_handle = cqm_handle->fake_cqm_handle[vf_id - child_func_start];
	err = fake_cqm_handle_mem_init(fake_cqm_handle);
	if (err != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(fake_cqm_handle_mem_init));
		return -EFAULT;
	}

	return 0;
}
EXPORT_SYMBOL(cqm5_init_fake_vf);

void cqm_cla_fake_vf_cache_invalid(struct tag_cqm_handle *cqm_handle, u32 reset_flag)
{
	struct hinic5_hwdev *handle = cqm_handle->ex_handle;
	struct tag_cqm_handle *fake_cqm_handle = NULL;
	u32 child_func_number, i;
	u16 func_global_idx;
	int err;

	if (!CQM_IS_FAKE_PARENT(cqm_handle))
		return;

	child_func_number = cqm_get_child_func_number(cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_cqm_handle = cqm_handle->fake_cqm_handle[i];
		func_global_idx = fake_cqm_handle->func_attribute.func_global_idx;

		err = hinic5_func_reset(handle, func_global_idx,
					BIT(reset_flag), HINIC5_CHANNEL_COMM);
		if (err != 0)
			cqm_err(handle->dev_hdl, "cqm fake vf cla cache invalid err, func_id 0x%x\n", func_global_idx);
	}
}

void cqm_cla_func_cache_invalid(struct tag_cqm_handle *cqm_handle, u32 reset_flag)
{
	int err;
	u16 func_id;
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)cqm_handle->ex_handle;

	func_id = hinic5_global_func_id(handle);
	err = hinic5_func_reset(handle, func_id, BIT(reset_flag), HINIC5_CHANNEL_COMM);
	if (err != 0)
		cqm_err(handle->dev_hdl, "cqm cla cache invalid err, func_index = 0x%x\n", func_id);
}

/**
 * Prototype    : cqm_mem_uninit
 * Description  : Deinitialize CQM memory, including tables at different levels.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
void cqm_mem_uninit(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);

	cqm_object_table_uninit(cqm_handle);
	cqm_bitmap_uninit(cqm_handle);

	if (COMM_SUPPORT_SMF_CACHE_INVALID(handle)) {
		cqm_cla_fake_vf_cache_invalid(cqm_handle, RES_TYPE_SMF);
		cqm_cla_func_cache_invalid(cqm_handle, RES_TYPE_SMF);
	}

	cqm_cla_uninit(cqm_handle, CQM_BAT_ENTRY_MAX);
	cqm_bat_uninit(cqm_handle);
	cqm_fake_mem_uninit(cqm_handle);

	if (COMM_SUPPORT_SMF_CACHE_INVALID(handle)) {
		cqm_cla_fake_vf_cache_invalid(cqm_handle, RES_TYPE_SMF_CACHE_INVALID);
		cqm_cla_func_cache_invalid(cqm_handle, RES_TYPE_SMF_CACHE_INVALID);
	}

	cqm_fake_uninit(cqm_handle);
}

/**
 * Prototype    : cqm_event_init
 * Description  : Initialize CQM event callback.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
s32 cqm_event_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	/* Registers the CEQ and AEQ callback functions. */
	if (hinic5_ceq_register_cb(ex_handle, ex_handle, HINIC5_NON_L2NIC_SCQ,
				   cqm_scq_callback) != CHIPIF_SUCCESS) {
		cqm_err(handle->dev_hdl, "Event: fail to register scq callback\n");
		return CQM_FAIL;
	}

	if (hinic5_ceq_register_cb(ex_handle, ex_handle, HINIC5_NON_L2NIC_ECQ,
				   cqm_ecq_callback) != CHIPIF_SUCCESS) {
		cqm_err(handle->dev_hdl, "Event: fail to register ecq callback\n");
		goto err1;
	}

	if (hinic5_ceq_register_cb(ex_handle, ex_handle, HINIC5_NON_L2NIC_NO_CQ_EQ,
				   cqm_nocq_callback) != CHIPIF_SUCCESS) {
		cqm_err(handle->dev_hdl, "Event: fail to register nocq callback\n");
		goto err2;
	}

	if (hinic5_aeq_register_swe_cb(ex_handle, ex_handle, HINIC5_STATEFUL_EVENT,
				       cqm_aeq_callback) != CHIPIF_SUCCESS) {
		cqm_err(handle->dev_hdl, "Event: fail to register aeq callback\n");
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_NO_CQ_EQ);
err2:
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_ECQ);
err1:
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_SCQ);
	return CQM_FAIL;
}

/**
 * Prototype    : cqm_event_uninit
 * Description  : Deinitialize CQM event callback.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
void cqm_event_uninit(void *ex_handle)
{
	hinic5_aeq_unregister_swe_cb(ex_handle, HINIC5_STATEFUL_EVENT);
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_NO_CQ_EQ);
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_ECQ);
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_SCQ);
}

/**
 * Prototype    : cqm_scq_callback
 * Description  : CQM module callback processing for the ceq,
 *		  which processes NON_L2NIC_SCQ.
 * Input        : void *ex_handle
 *		  u32 ceqe_data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void cqm_scq_callback(void *ex_handle, u32 ceqe_data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct tag_cqm_queue *cqm_queue = NULL;
	struct tag_cqm_object *obj = NULL;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(scq_callback_ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_scq_callback_cnt);

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(scq_callback_cqm_handle));
		return;
	}

	cqm_dbg_on(cqm_verbose, handle->dev_hdl,
		"Event: %s, ceqe_data=0x%x\n", __func__, ceqe_data);
	obj = cqm5_object_get(ex_handle, CQM_OBJECT_NONRDMA_SCQ,
			     CQM_CQN_FROM_CEQE(ceqe_data), true);
	if (unlikely(obj == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(scq_callback_obj));
		return;
	}

	if (unlikely(obj->service_type >= CQM_SERVICE_T_MAX)) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(obj->service_type));
		cqm5_object_put(obj);
		return;
	}

	service = &cqm_handle->service[obj->service_type];
	service_template = &service->service_template;
	if (service_template->shared_cq_ceq_callback) {
		cqm_queue = (struct tag_cqm_queue *)(void *)obj;
		service_template->shared_cq_ceq_callback(service_template->service_handle,
							 CQM_CQN_FROM_CEQE(ceqe_data),
							 cqm_queue->priv);
	} else {
		cqm_err(handle->dev_hdl, CQM_PTR_NULL(shared_cq_ceq_callback));
	}

	cqm5_object_put(obj);
}

/**
 * Prototype    : cqm_ecq_callback
 * Description  : CQM module callback processing for the ceq,
 *		  which processes NON_L2NIC_ECQ.
 * Input        : void *ex_handle
 *		  u32 ceqe_data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void cqm_ecq_callback(void *ex_handle, u32 ceqe_data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct tag_cqm_qpc_mpt *qpc = NULL;
	struct tag_cqm_object *obj = NULL;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ecq_callback_ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_ecq_callback_cnt);

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ecq_callback_cqm_handle));
		return;
	}

	obj = cqm5_object_get(ex_handle, CQM_OBJECT_SERVICE_CTX,
			     CQM_XID_FROM_CEQE(ceqe_data), true);
	if (unlikely(obj == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ecq_callback_obj));
		return;
	}

	if (unlikely(obj->service_type >= CQM_SERVICE_T_MAX)) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(obj->service_type));
		cqm5_object_put(obj);
		return;
	}

	service = &cqm_handle->service[obj->service_type];
	service_template = &service->service_template;
	if (service_template->embedded_cq_ceq_callback) {
		qpc = (struct tag_cqm_qpc_mpt *)(void *)obj;
		service_template->embedded_cq_ceq_callback(service_template->service_handle,
							   CQM_XID_FROM_CEQE(ceqe_data), qpc->priv);
	} else {
		cqm_err(handle->dev_hdl,
			CQM_PTR_NULL(embedded_cq_ceq_callback));
	}

	cqm5_object_put(obj);
}

/**
 * Prototype    : cqm_nocq_callback
 * Description  : CQM module callback processing for the ceq,
 *		  which processes NON_L2NIC_NO_CQ_EQ.
 * Input        : void *ex_handle
 *		  u32 ceqe_data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void cqm_nocq_callback(void *ex_handle, u32 ceqe_data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	struct tag_cqm_qpc_mpt *qpc = NULL;
	struct tag_cqm_object *obj = NULL;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(nocq_callback_ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_nocq_callback_cnt);

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(nocq_callback_cqm_handle));
		return;
	}

	obj = cqm5_object_get(ex_handle, CQM_OBJECT_SERVICE_CTX,
			     CQM_XID_FROM_CEQE(ceqe_data), true);
	if (unlikely(obj == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(nocq_callback_obj));
		return;
	}

	if (unlikely(obj->service_type >= CQM_SERVICE_T_MAX)) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(obj->service_type));
		cqm5_object_put(obj);
		return;
	}

	service = &cqm_handle->service[obj->service_type];
	service_template = &service->service_template;
	if (service_template->no_cq_ceq_callback) {
		qpc = (struct tag_cqm_qpc_mpt *)(void *)obj;
		service_template->no_cq_ceq_callback(service_template->service_handle,
						     CQM_XID_FROM_CEQE(ceqe_data),
						     CQM_QID_FROM_CEQE(ceqe_data),
						     qpc->priv);
	} else {
		cqm_err(handle->dev_hdl, CQM_PTR_NULL(no_cq_ceq_callback));
	}

	cqm5_object_put(obj);
}

/* Distributes events to different service modules
 * based on the event type.
 */
static u32 cqm_aeq_event2type(u8 event)
{
	if (event < CQM_AEQ_BASE_T_DMMU)
		return CQM_SERVICE_T_NIC;
	if (event < CQM_AEQ_BASE_T_ROCE)
		return CQM_SERVICE_T_DMMU;
	if (event < CQM_AEQ_BASE_T_FC)
		return CQM_SERVICE_T_ROCE;
	if (event < CQM_AEQ_BASE_T_IOE)
		return CQM_SERVICE_T_FC;
	if (event < CQM_AEQ_BASE_T_TOE)
		return CQM_SERVICE_T_IOE;
	if (event < CQM_AEQ_BASE_T_UB)
		return CQM_SERVICE_T_TOE;
	if (event < CQM_AEQ_BASE_T_VBS)
		return CQM_SERVICE_T_UB;
	if (event < CQM_AEQ_BASE_T_IPSEC)
		return CQM_SERVICE_T_VBS;
	if (event < CQM_AEQ_BASE_T_MAX)
		return CQM_SERVICE_T_IPSEC;
	return CQM_SERVICE_T_MAX;
}

/**
 * Prototype    : cqm_aeq_callback
 * Description  : CQM module callback processing for the aeq.
 * Input        : void *ex_handle
 *		  u8 event
 *		  u64 data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
u8 cqm_aeq_callback(void *ex_handle, u8 event, u8 *data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;
	u8 event_level = FAULT_LEVEL_MAX;
	u32 service_type;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(aeq_callback_ex_handle));
		return event_level;
	}

	if (event >= CQM_AEQ_CALLBACK_CNT_MAX) {
		cqm_err(handle->dev_hdl, "cqm aeq event invalid %u\n", event);
		return event_level;
	}

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_aeq_callback_cnt[event]);

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(aeq_callback_cqm_handle));
		return event_level;
	}

	/* Distributes events to different service modules
	 * based on the event type.
	 */
	service_type = cqm_aeq_event2type(event);
	if (service_type == CQM_SERVICE_T_MAX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(event));
		return event_level;
	}

	service = &cqm_handle->service[service_type];
	service_template = &service->service_template;

	if (!service_template->aeq_level_callback)
		cqm_err(handle->dev_hdl, "Event: service_type %u aeq_level_callback unregistered, event %u\n",
			service_type, event);
	else
		event_level = service_template->aeq_level_callback(service_template->service_handle,
								   event, data);

	if (!service_template->aeq_callback)
		cqm_err(handle->dev_hdl, "Event: service_type %u aeq_callback unregistered\n",
			service_type);
	else
		service_template->aeq_callback(service_template->service_handle,
					       event, data);

	return event_level;
}

/**
 * Prototype    : cqm5_service_register
 * Description  : Callback template for the service driver
 *		  to register with the CQM.
 * Input        : void *ex_handle
 *		  struct tag_service_register_template *service_template
 * Output       : None
 * Return Value : s32
 * 1.Date	  : 2015/4/5
 * Modification	  : Created function
 */
s32 cqm5_service_register(void *ex_handle, struct tag_service_register_template *service_template)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return CQM_FAIL;
	}

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return CQM_FAIL;
	}
	if (unlikely(service_template == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(service_template));
		return CQM_FAIL;
	}

	if (service_template->service_type >= CQM_SERVICE_T_MAX) {
		cqm_err(handle->dev_hdl,
			CQM_WRONG_VALUE(service_template->service_type));
		return CQM_FAIL;
	}
	service = &cqm_handle->service[service_template->service_type];
	if (!service->valid) {
		cqm_err(handle->dev_hdl, "Service register: service_type %u is invalid\n",
			service_template->service_type);
		return CQM_FAIL;
	}

	if (service->has_register) {
		cqm_err(handle->dev_hdl, "Service register: service_type %u has registered\n",
			service_template->service_type);
		return CQM_FAIL;
	}

	service->has_register = true;
	(void)memcpy((void *)(&service->service_template),
		     (void *)service_template,
		     sizeof(struct tag_service_register_template));

	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_service_register);

/**
 * Prototype    : cqm5_service_unregister
 * Description  : The service driver deregisters the callback function
 *		  from the CQM.
 * Input        : void *ex_handle
 *		  u32 service_type
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/5
 * Modification	  : Created function
 */
void cqm5_service_unregister(void *ex_handle, u32 service_type)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_cqm_handle *cqm_handle = NULL;
	struct tag_cqm_service *service = NULL;

	if (unlikely(ex_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(ex_handle));
		return;
	}

	cqm_handle = (struct tag_cqm_handle *)(handle->cqm_hdl);
	if (unlikely(cqm_handle == NULL)) {
		CQM_PTR_CHECK_ERR(CQM_PTR_NULL(cqm_handle));
		return;
	}

	if (service_type >= CQM_SERVICE_T_MAX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return;
	}

	service = &cqm_handle->service[service_type];
	if (!service->valid)
		cqm_err(handle->dev_hdl, "Service unregister: service_type %u is disable\n",
			service_type);

	service->has_register = false;
	(void)memset(&service->service_template, 0,
		sizeof(struct tag_service_register_template));
}
EXPORT_SYMBOL(cqm5_service_unregister);

s32 cqm5_fake_vf_num_set(void *ex_handle, u16 fake_vf_num_cfg)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct service_cap *svc_cap = NULL;

	if (!ex_handle || !handle->cfg_mgmt)
		return CQM_FAIL;

	svc_cap = &handle->cfg_mgmt->svc_cap;

	if (fake_vf_num_cfg > svc_cap->fake_vf_num) {
		cqm_err(handle->dev_hdl, "fake_vf_num_cfg is invlaid, fw fake_vf_num is %u\n",
			svc_cap->fake_vf_num);
		return CQM_FAIL;
	}

	/* fake_vf_num_cfg is valid when func type is CQM_FAKE_FUNC_PARENT */
	svc_cap->fake_vf_num_cfg = fake_vf_num_cfg;
	cqm_info(handle->dev_hdl, "fake_vf_num_cfg set to %u\n", fake_vf_num_cfg);

	return CQM_SUCCESS;
}
EXPORT_SYMBOL(cqm5_fake_vf_num_set);
