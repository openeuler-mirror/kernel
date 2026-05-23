/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_main.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
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
#include "hinic5_hinic5_vram_api.h"
#include "hinic5_typedef_inner.h"

#include "hinic5_vram_common.h"

#include "hinic5_cqm_object.h"
#include "hinic5_cqm_bitmap_table.h"
#include "hinic5_cqm_bat_cla.h"
#include "hinic5_cqm_bloomfilter.h"
#include "hinic5_cqm_db.h"
#include "hinic5_cqm_cmdq.h"
#include "hinic5_cqm_main.h"

static s32 hinic5_cqm_set_fake_vf_child_timer(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle, bool en)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)hinic5_cqm_handle->ex_handle;
	u16 func_global_idx;
	s32 ret;

	if (fake_hinic5_cqm_handle->func_capability.timer_enable == 0) {
		return HINIC5_CQM_SUCCESS;
	}

	func_global_idx = fake_hinic5_cqm_handle->func_attribute.func_global_idx;
	ret = hinic5_func_tmr_bitmap_set(hinic5_cqm_handle->ex_handle, func_global_idx, en);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "func_id %u Timer %s timer bitmap failed\n",
			func_global_idx, en ? "enable" : "disable");
		return HINIC5_CQM_FAIL;
	}

	return HINIC5_CQM_SUCCESS;
}

static void hinic5_cqm_unset_fake_vf_timer(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	u32 i, child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);

	for (i = 0; i < child_func_number; i++)
		(void)hinic5_cqm_set_fake_vf_child_timer(hinic5_cqm_handle, hinic5_cqm_handle->fake_hinic5_cqm_handle[i], false);
}

static s32 hinic5_cqm_set_fake_vf_timer(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	u32 i, child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		s32 ret = hinic5_cqm_set_fake_vf_child_timer(hinic5_cqm_handle, hinic5_cqm_handle->fake_hinic5_cqm_handle[i], true);
		if (ret != HINIC5_CQM_SUCCESS)
			goto err;
	}

	return HINIC5_CQM_SUCCESS;

err:
	hinic5_cqm_unset_fake_vf_timer(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

static s32 hinic5_cqm_set_timer_enable(void *ex_handle)
{
	struct hinic5_hwdev *handle = ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = handle->hinic5_cqm_hdl;
	u16 func_id = hinic5_global_func_id(ex_handle);
	int is_in_kexec;

	is_in_kexec = hinic5_vram_get_kexec_flag();
	if (is_in_kexec != 0) {
		hinic5_cqm_info(handle->dev_hdl, "Skip starting hinic5_cqm timer during kexec\n");
		return HINIC5_CQM_SUCCESS;
	}

	/* Enable children */
	if (HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle) &&
	    hinic5_cqm_set_fake_vf_timer(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS)
		return HINIC5_CQM_FAIL;

	/* Enable self */
	if (hinic5_func_tmr_bitmap_set(ex_handle, func_id, true) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "Timer start: enable timer bitmap failed\n");
		goto err;
	}

	return HINIC5_CQM_SUCCESS;

err:
	if (HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		hinic5_cqm_unset_fake_vf_timer(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

static void hinic5_cqm_set_timer_disable(void *ex_handle)
{
	struct hinic5_hwdev *handle = ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = handle->hinic5_cqm_hdl;

	/* Disable self */
	if (hinic5_func_tmr_bitmap_set(ex_handle, hinic5_global_func_id(ex_handle),
				       false) != HINIC5_CQM_SUCCESS)
		hinic5_cqm_err(handle->dev_hdl, "func_id %u Timer stop: disable timer bitmap failed\n",
			hinic5_global_func_id(ex_handle));

	/* Disable children */
	if (HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		hinic5_cqm_unset_fake_vf_timer(hinic5_cqm_handle);
}

static u32 hinic5_cqm_set_vio_enable(void *ex_handle, bool enable)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	int err;

	if (!ex_handle)
		return HINIC5_CQM_FAIL;

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (!hinic5_cqm_handle->service[HINIC5_CQM_SERVICE_T_VIRTIO].valid)
		return HINIC5_CQM_SUCCESS;

	err = hinic5_func_vio_en(ex_handle, enable);
	if (err != 0) {
		hinic5_cqm_err(handle->dev_hdl, "VIO %s failed, err %d\n",
			(enable ? "enable" : "disable"), err);
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_info(handle->dev_hdl, "VIO %s success\n",
		 (enable ? "enable" : "disable"));
	return HINIC5_CQM_SUCCESS;
}

static s32 hinic5_cqm_initialize_recource(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	/* Initialize memory entries such as BAT, CLA, and bitmap. */
	if (hinic5_cqm_mem_init(ex_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_mem_init));
		return HINIC5_CQM_FAIL;
	}

	/* Event callback initialization */
	if (hinic5_cqm_event_init(ex_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_event_init));
		goto err1;
	}

	/* Doorbell initiation */
	if (hinic5_cqm_db_init(ex_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_db_init));
		goto err2;
	}

	/* Initialize the bloom filter. */
	if (hinic5_cqm_bloomfilter_init(ex_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bloomfilter_init));
		goto err3;
	}

	if (hinic5_cqm_set_timer_enable(ex_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_set_timer_enable));
		goto err4;
	}

	if (hinic5_cqm_set_vio_enable(ex_handle, true) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_set_vio_enable));
		goto err5;
	}

	return HINIC5_CQM_SUCCESS;

err5:
	hinic5_cqm_set_timer_disable(ex_handle);
err4:
	hinic5_cqm_bloomfilter_uninit(ex_handle);
err3:
	hinic5_cqm_db_uninit(ex_handle);
err2:
	hinic5_cqm_event_uninit(ex_handle);
err1:
	hinic5_cqm_mem_uninit(ex_handle);
	return HINIC5_CQM_FAIL;
}

static struct tag_hinic5_cqm_handle *hinic5_cqm_handle_create(void)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;

	hinic5_cqm_handle = kzalloc(sizeof(*hinic5_cqm_handle), GFP_KERNEL);
	if (unlikely(!hinic5_cqm_handle)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(hinic5_cqm_handle));
		return NULL;
	}

	/* Clear the memory to prevent other systems from
	 * not clearing the memory.
	 */
	memset(hinic5_cqm_handle, 0, sizeof(struct tag_hinic5_cqm_handle));

	atomic_set(&hinic5_cqm_handle->handle_state, HINIC5_CQM_HANDLE_STATE_INIT);

	return hinic5_cqm_handle;
}

static struct tag_hinic5_cqm_handle *hinic5_cqm_handle_fork(struct tag_hinic5_cqm_handle *parent_handle)
{
	struct tag_hinic5_cqm_handle *child_handle = NULL;

	child_handle = kzalloc(sizeof(*child_handle), GFP_KERNEL);
	if (unlikely(!child_handle)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_ALLOC_FAIL(child_handle));
		return NULL;
	}

	/* Copy the attributes of the parent HINIC5_CQM handle to the child HINIC5_CQM
	 * handle and modify the values of function.
	 */
	memcpy(child_handle,
	       parent_handle, sizeof(struct tag_hinic5_cqm_handle));

	/* Clear state & unlink some references */
	atomic_set(&child_handle->handle_state, HINIC5_CQM_HANDLE_STATE_INIT);
	memset(child_handle->fake_hinic5_cqm_handle,
	       0, sizeof(child_handle->fake_hinic5_cqm_handle));

	return child_handle;
}

/**
 * Prototype    : hinic5_cqm_init
 * Description  : Complete HINIC5_CQM initialization.
 *		  If the function is a parent fake function, copy the fake.
 *		  If it is a child fake function (in the fake copy function,
 *		  not in this function), set fake_en in the BAT/CLA table.
 *		  hinic5_cqm_init->hinic5_cqm_mem_init->hinic5_cqm_fake_init(copy)
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
s32 hinic5_cqm_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_handle = hinic5_cqm_handle_create();
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_handle_create));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_handle->ex_handle = handle;
	hinic5_cqm_handle->dev = handle->dev_hdl;
	handle->hinic5_cqm_hdl = (void *)hinic5_cqm_handle;

	/* 187x ops or 182x ops */
	hinic5_cqm_cmdq_adapt_init(hinic5_cqm_handle);
	/* Clearing Statistics */
	memset(&handle->hw_stats.hinic5_cqm_stats, 0, sizeof(struct hinic5_cqm_stats));

	/* Reads VF/PF information. */
	hinic5_cqm_handle->func_attribute = handle->hwif->attr;
	hinic5_cqm_info(handle->dev_hdl, "Func init: function[%u] type %d(0:PF,1:VF,2:PPF)\n",
		hinic5_cqm_handle->func_attribute.func_global_idx, hinic5_cqm_handle->func_attribute.func_type);

	/* Read capability from configuration management module */
	ret = hinic5_cqm_capability_init(ex_handle);
	if (ret != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_capability_init));
		goto err1;
	}

	/* memory doorbell event bloomfilter timer init */
	if (hinic5_cqm_initialize_recource(ex_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_initialize_recource));
		goto err1;
	}

	atomic_set(&hinic5_cqm_handle->handle_state, HINIC5_CQM_HANDLE_STATE_READY);
	return HINIC5_CQM_SUCCESS;

err1:
	kfree(handle->hinic5_cqm_hdl);
	handle->hinic5_cqm_hdl = NULL;
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_uninit
 * Description  : Deinitializes the HINIC5_CQM module. This function is called once
 *		  each time a function is removed.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/15
 *   Modification : Created function
 */
void hinic5_cqm_uninit(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	s32 ret;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}

	atomic_set(&hinic5_cqm_handle->handle_state, HINIC5_CQM_HANDLE_STATE_REMOVE);

	hinic5_cqm_set_vio_enable(ex_handle, false);

	hinic5_cqm_set_timer_disable(ex_handle);

	/* After the TMR timer stops, the system releases resources
	 * after a delay of one or two milliseconds.
	 */
	if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle)) {
		if (hinic5_cqm_handle->func_capability.timer_enable ==
		    HINIC5_CQM_TIMER_ENABLE) {
			hinic5_cqm_info(handle->dev_hdl, "PPF timer stop\n");
			ret = hinic5_ppf_tmr_stop(handle);
			if (ret != HINIC5_CQM_SUCCESS)
				/* The timer fails to be stopped,
				 * and the resource release is not affected.
				 */
				hinic5_cqm_info(handle->dev_hdl, "PPF timer stop, ret=%d\n", ret);
		}

		usleep_range(0x384, 0x3E8); /* Somebody requires a delay of 1 ms,
					     * which is inaccurate.
					     */
	}

	/* Release Bloom Filter Table */
	hinic5_cqm_bloomfilter_uninit(ex_handle);

	/* Release hardware doorbell */
	hinic5_cqm_db_uninit(ex_handle);

	/* Cancel the callback of the event */
	hinic5_cqm_event_uninit(ex_handle);

	/* Release various memory tables and require the service
	 * to release all objects.
	 */
	hinic5_cqm_mem_uninit(ex_handle);

	/* Release hinic5_cqm_handle */
	handle->hinic5_cqm_hdl = NULL;
	kfree(hinic5_cqm_handle);
}

static void hinic5_cqm_test_mode_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			       struct service_cap *service_capability)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	if (service_capability->test_mode == 0)
		return;

	hinic5_cqm_info(handle->dev_hdl, "Enter HINIC5_CQM test mode\n");

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

static void hinic5_cqm_service_capability_update(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;

	func_cap->qpc_number = GET_MIN(HINIC5_CQM_MAX_QPC_NUM, func_cap->qpc_number);
	func_cap->scqc_number = GET_MIN(HINIC5_CQM_MAX_SCQC_NUM,
					func_cap->scqc_number);
	func_cap->srqc_number = GET_MIN(HINIC5_CQM_MAX_SRQC_NUM,
					func_cap->srqc_number);
	func_cap->childc_number = GET_MIN(HINIC5_CQM_MAX_CHILDC_NUM,
					  func_cap->childc_number);
}

static void hinic5_cqm_service_valid_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   const struct service_cap *service_capability)
{
	u32 type = service_capability->chip_svc_type;
	struct tag_hinic5_cqm_service *svc = hinic5_cqm_handle->service;

	svc[HINIC5_CQM_SERVICE_T_NIC].valid    = (type & CFG_SERVICE_MASK_NIC) != 0;
	svc[HINIC5_CQM_SERVICE_T_OVS].valid    = (type & CFG_SERVICE_MASK_OVS) != 0;
	svc[HINIC5_CQM_SERVICE_T_ROCE].valid   = (type & CFG_SERVICE_MASK_ROCE) != 0;
	svc[HINIC5_CQM_SERVICE_T_TOE].valid    = (type & CFG_SERVICE_MASK_TOE) != 0;
	svc[HINIC5_CQM_SERVICE_T_FC].valid     = (type & CFG_SERVICE_MASK_FC) != 0;
	svc[HINIC5_CQM_SERVICE_T_IPSEC].valid  = (type & CFG_SERVICE_MASK_IPSEC) != 0;
	svc[HINIC5_CQM_SERVICE_T_VBS].valid    = (type & CFG_SERVICE_MASK_VBS) != 0;
	svc[HINIC5_CQM_SERVICE_T_VIRTIO].valid = (type & CFG_SERVICE_MASK_VIRTIO) != 0;
	svc[HINIC5_CQM_SERVICE_T_IOE].valid    = false;
	svc[HINIC5_CQM_SERVICE_T_PPA].valid    = (type & CFG_SERVICE_MASK_PPA) != 0;
	svc[HINIC5_CQM_SERVICE_T_UB].valid     = (type & CFG_SERVICE_MASK_UB) != 0;
	svc[HINIC5_CQM_SERVICE_T_JBOF].valid   = (type & CFG_SERVICE_MASK_JBOF) != 0;
	svc[HINIC5_CQM_SERVICE_T_VROCE].valid  = (type & CFG_SERVICE_MASK_VROCE) != 0;
	svc[HINIC5_CQM_SERVICE_T_DMMU].valid   = (type & CFG_SERVICE_MASK_DMMU) != 0;
	svc[HINIC5_CQM_SERVICE_T_CFM].valid    = (type & CFG_SERVICE_MASK_CFM) != 0;
}

static void hinic5_cqm_service_capability_init_nic(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: nic is valid, but nic need not be init by hinic5_cqm\n");
}

static void hinic5_cqm_service_capability_init_ovs(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ovs_service_cap *ovs_cap = &service_capability->ovs_cap;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: ovs is valid\n");
	hinic5_cqm_info(handle->dev_hdl, "Cap init: ovs qpc 0x%x\n",
		 ovs_cap->dev_ovs_cap.max_pctxs);
	func_cap->hash_number += ovs_cap->dev_ovs_cap.max_pctxs;
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
	func_cap->qpc_number += ovs_cap->dev_ovs_cap.max_pctxs;
	func_cap->qpc_basic_size = GET_MAX(ovs_cap->pctx_sz,
					   func_cap->qpc_basic_size);
	func_cap->qpc_reserved += ovs_cap->dev_ovs_cap.max_pctxs;
	func_cap->qpc_alloc_static = true;
	func_cap->pagesize_reorder = HINIC5_CQM_OVS_PAGESIZE_ORDER;
}

static void hinic5_cqm_service_capability_roce_cap_print(struct hinic5_hwdev *handle,
	const struct hinic5_board_info *board_info, const struct dev_roce_svc_own_cap *roce_own_cap)
{
	hinic5_cqm_info(handle->dev_hdl, "Cap init: roce is valid\n");
	hinic5_cqm_info(handle->dev_hdl, "Cap init: roce qpc 0x%x, scqc 0x%x, srqc 0x%x, drc_qp 0x%x\n",
		 roce_own_cap->max_qps, roce_own_cap->max_cqs,
		 roce_own_cap->max_srqs, roce_own_cap->max_drc_qps);
	hinic5_cqm_info(handle->dev_hdl, "Cap init: board_type 0x%x, scenes_id:0x%x, srv_bmp:0x%x\n",
		 board_info->board_type, board_info->scenes_id, board_info->service_en_bitmap);
	hinic5_cqm_info(handle->dev_hdl, "Cap init: reserved_qps:0x%x, reserved_qps_back:0x%x, "
							  "reserved_cqs:0x%x, reserved_cqs_back:0x%x\n",
		 roce_own_cap->reserved_qps, roce_own_cap->reserved_qps_back,
		 roce_own_cap->reserved_cqs, roce_own_cap->reserved_cqs_back);
	hinic5_cqm_info(handle->dev_hdl, "Cap init: reserved_srqs:0x%x, reserved_srqs_back:0x%x, "
							  "max_pd:0x%x, max_xrcd:0x%x, max_gid:0x%x\n",
		 roce_own_cap->reserved_srqs, roce_own_cap->reserved_srqs_back,
		 roce_own_cap->max_pd, roce_own_cap->max_xrcd, roce_own_cap->max_gid);
}

static void hinic5_cqm_service_capability_init_roce(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct rdma_service_cap *rdma_cap = &service_capability->rdma_cap;
	struct dev_roce_svc_own_cap *roce_own_cap = &rdma_cap->dev_rdma_cap.roce_own_cap;

	hinic5_cqm_service_capability_roce_cap_print(handle, &handle->board_info, roce_own_cap);

	func_cap->use_fake_parent_cla = true;

	if (COMM_SUPPORT_EXTEND_CAPBILITY(handle)) {
		func_cap->qpc_reserved += roce_own_cap->reserved_qps;
		func_cap->qpc_reserved_back += roce_own_cap->reserved_qps_back;
		func_cap->scq_reserved += roce_own_cap->reserved_cqs;
		func_cap->srq_reserved += roce_own_cap->reserved_srqs;
	} else {
		func_cap->qpc_reserved += HINIC5_CQM_QPC_ROCE_RSVD;
		func_cap->scq_reserved += HINIC5_CQM_CQ_ROCE_RSVD;
		func_cap->srq_reserved += HINIC5_CQM_SRQ_ROCE_RSVD;
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
		func_cap->gid_number = HINIC5_CQM_GID_RDMA_NUM;

	func_cap->gid_basic_size = HINIC5_CQM_GID_SIZE_32;
	func_cap->childc_number += roce_own_cap->max_child_ctx_num;
	func_cap->childc_basic_size = GET_MAX(HINIC5_CQM_CHILDC_SIZE_256, func_cap->childc_basic_size);
}

static void hinic5_cqm_service_capability_init_vroce(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct rdma_service_cap *rdma_cap = &service_capability->rdma_cap;
	struct dev_roce_svc_own_cap *roce_own_cap = &rdma_cap->dev_rdma_cap.roce_own_cap;

	if (IS_MASTER_HOST(handle)) {
		func_cap->hash_number = roce_own_cap->max_qps;
		func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
		hinic5_cqm_info(handle->dev_hdl, "Cap init: vroce is valid\n");
		hinic5_cqm_info(handle->dev_hdl, "Cap init: hash_number 0x%x hash_basic_size 0x%x\n", func_cap->hash_number,
			func_cap->hash_basic_size);
	}
}

static void hinic5_cqm_service_capability_init_toe(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_toe_private_capability *toe_own_cap = &hinic5_cqm_handle->toe_own_capability;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct rdma_service_cap *rdma_cap = &service_capability->rdma_cap;
	struct toe_service_cap *toe_cap = &service_capability->toe_cap;
	struct dev_toe_svc_cap *dev_toe_cap = &toe_cap->dev_toe_cap;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: toe is valid\n");
	hinic5_cqm_info(handle->dev_hdl, "Cap init: toe qpc 0x%x, scqc 0x%x, srqc 0x%x\n",
		 dev_toe_cap->max_pctxs, dev_toe_cap->max_cqs,
		 dev_toe_cap->max_srqs);
	func_cap->hash_number += dev_toe_cap->max_pctxs;
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
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
	toe_own_cap->toe_srqc_basic_size = HINIC5_CQM_SRQC_SIZE_64;
	func_cap->childc_number += dev_toe_cap->max_cctxt;
	func_cap->childc_basic_size = GET_MAX(HINIC5_CQM_CHILDC_SIZE_256,
					      func_cap->childc_basic_size);
	func_cap->mpt_number += dev_toe_cap->max_mpts;
	func_cap->mpt_reserved = 0;
	func_cap->mpt_basic_size = GET_MAX(rdma_cap->mpt_entry_sz,
					   func_cap->mpt_basic_size);
}

static void hinic5_cqm_service_capability_init_ioe(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: ioe is valid\n");
}

static void hinic5_cqm_service_capability_init_fc(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct fc_service_cap *fc_cap = &service_capability->fc_cap;
	struct dev_fc_svc_cap *dev_fc_cap = &fc_cap->dev_fc_cap;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: fc is valid\n");
	hinic5_cqm_info(handle->dev_hdl, "Cap init: fc qpc 0x%x, scqc 0x%x, srqc 0x%x\n",
		 dev_fc_cap->max_parent_qpc_num, dev_fc_cap->scq_num,
		 dev_fc_cap->srq_num);
	func_cap->hash_number += dev_fc_cap->max_parent_qpc_num;
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
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
	func_cap->lun_number = HINIC5_CQM_LUN_FC_NUM;
	func_cap->lun_basic_size = HINIC5_CQM_LUN_SIZE_8;
	func_cap->taskmap_number = HINIC5_CQM_TASKMAP_FC_NUM;
	func_cap->taskmap_basic_size = PAGE_SIZE;
	func_cap->childc_number += dev_fc_cap->max_child_qpc_num;
	func_cap->childc_basic_size = GET_MAX(fc_cap->child_qpc_size,
					      func_cap->childc_basic_size);
	func_cap->pagesize_reorder = HINIC5_CQM_FC_PAGESIZE_ORDER;
}

static void hinic5_cqm_service_capability_init_vbs(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: vbs is valid\n");

	/* If the entry size is greater than the cache line (256 bytes),
	 * align the entries by cache line.
	 */
	func_cap->qpc_basic_size = GET_MAX(HINIC5_CQM_VBS_QPC_SIZE,
					   func_cap->qpc_basic_size);
	func_cap->qpc_alloc_static = true;
	func_cap->scqc_basic_size = HINIC5_CQM_VBS_SCQC_SIZE;
	func_cap->scqc_alloc_static = false;
	func_cap->scq_reserved += service_capability->vbs_cap.vbs_max_volq;
	func_cap->childc_number += service_capability->vbs_cap.vbs_child_ctx_num;
	func_cap->childc_basic_size = GET_MAX(HINIC5_CQM_CHILDC_SIZE_256, func_cap->childc_basic_size);
	func_cap->xid_alloc_mode = false;
	func_cap->hash_number += service_capability->vbs_cap.vbs_hash_bucket_num;
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;

	func_cap->qpc_number += service_capability->vbs_cap.vbs_max_volq;
	func_cap->scqc_number += service_capability->vbs_cap.vbs_max_volq;
}

static void hinic5_cqm_service_capability_init_jbof(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct jbof_service_cap *jbof_cap = &service_capability->jbof_cap;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: jbof is valid\n");
	func_cap->qpc_alloc_static = true;
	func_cap->qpc_number += jbof_cap->max_parent_qpc_num;
	func_cap->qpc_basic_size = GET_MAX(jbof_cap->parent_qpc_size,
				func_cap->qpc_basic_size);
	func_cap->childc_number += jbof_cap->max_child_qpc_num;
	func_cap->childc_basic_size = GET_MAX(HINIC5_CQM_CHILDC_SIZE_256,
					      func_cap->childc_basic_size);
	func_cap->hash_number += jbof_cap->hash_bucket_num;
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
}

static void hinic5_cqm_service_capability_init_ipsec(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ipsec_service_cap *ipsec_cap = &service_capability->ipsec_cap;
	struct dev_ipsec_svc_cap *ipsec_srvcap = &ipsec_cap->dev_ipsec_cap;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;

	func_cap->childc_number += (ipsec_srvcap->max_sactxs + ipsec_srvcap->max_spctxs);
	func_cap->childc_basic_size = GET_MAX(HINIC5_CQM_CHILDC_SIZE_256,
					      func_cap->childc_basic_size);
	func_cap->scqc_number += ipsec_srvcap->max_cqs;
	func_cap->scqc_basic_size = GET_MAX(HINIC5_CQM_SCQC_SIZE_64,
					    func_cap->scqc_basic_size);
	func_cap->scqc_alloc_static = true;
	func_cap->hash_number += HINIC5_CQM_CRYPT_HASH_BUCKET_NUM(ipsec_srvcap->sa_hash_bucket_num + ipsec_srvcap->sp_hash_bucket_num);
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
	hinic5_cqm_info(handle->dev_hdl, "Cap init: ipsec is valid\n");
	hinic5_cqm_info(handle->dev_hdl, "Cap init: max_sactxs: 0x%x, max_spctxs: 0x%x, childc_bsize %u\n",
		ipsec_srvcap->max_sactxs, ipsec_srvcap->max_spctxs, func_cap->childc_basic_size);
	hinic5_cqm_info(handle->dev_hdl, "scqc_num 0x%x, scqc_bsize %u\n", ipsec_srvcap->max_cqs, func_cap->scqc_basic_size);
	hinic5_cqm_info(handle->dev_hdl,
		"Cap init: ipsec sa_hash_bucket_num: 0x%x, sp_hash_bucket_num: 0x%x, hash_basic_size %u\n",
		ipsec_srvcap->sa_hash_bucket_num, ipsec_srvcap->sp_hash_bucket_num, func_cap->hash_basic_size);
}

static void hinic5_cqm_service_capability_init_virtio(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *svc_cap = (struct service_cap *)pra;
	u32 vq_num, vq_size, xid2cid_size;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: virtio is valid\n");

	vq_num = svc_cap->virtio_vq_num != 0 ? svc_cap->virtio_vq_num : HINIC5_CQM_VIRTIO_VQ_NUM_DEFAULT;
	vq_num += svc_cap->nvme_qp_num;
	vq_size = vq_num * svc_cap->virtio_vq_size;
	hinic5_cqm_info(handle->dev_hdl, "Cap init: vq_num 0x%x, vq_size 0x%x\n", vq_num, vq_size);

	if (COMM_SUPPORT_VIRTIO_FC_CACHE(handle)) {
		/* In VirtIO function context cache mode,
		 * the VQs are divided and stored in all enabled SMFs. */
		xid2cid_size = vq_size / func_cap->smf_enabled_num;
		xid2cid_size += svc_cap->vio_func_num * HINIC5_CQM_VIRTIO_FC_SIZE;
		hinic5_cqm_info(handle->dev_hdl, "Cap init: vio_func_num 0x%x\n", svc_cap->vio_func_num);
	} else {
		xid2cid_size = vq_size;
	}

	func_cap->xid2cid_number += xid2cid_size / HINIC5_CQM_CHIP_CACHELINE;
	func_cap->xid2cid_basic_size = HINIC5_CQM_CHIP_CACHELINE;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: xid2cid_size 0x%x, xid2cid_number 0x%x\n",
		 xid2cid_size, func_cap->xid2cid_number);
}

static void hinic5_cqm_service_capability_init_ppa(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ppa_service_cap *ppa_cap = &service_capability->ppa_cap;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: ppa is valid\n");
	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;
	func_cap->qpc_alloc_static = true;
	func_cap->pagesize_reorder = HINIC5_CQM_PPA_PAGESIZE_ORDER;
	func_cap->qpc_basic_size = GET_MAX(ppa_cap->pctx_sz,
					   func_cap->qpc_basic_size);
}

static void hinic5_cqm_service_capability_init_ub(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, void *pra)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct ub_dev_cap_sdk_res *ub_sdk_res = &service_capability->ub_cap.sdk_res;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: ub is valid\n");

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
	func_cap->gid_basic_size = HINIC5_CQM_GID_SIZE_32;
	func_cap->childc_number += ub_sdk_res->max_tpg + (ub_sdk_res->max_tp >> 1);
	func_cap->childc_basic_size = GET_MAX(HINIC5_CQM_CHILDC_SIZE_256, func_cap->childc_basic_size);
}

struct hinic5_cqm_srv_cap_init hinic5_serv_cap_init_list[] = {
	{HINIC5_CQM_SERVICE_T_NIC,     hinic5_cqm_service_capability_init_nic},
	{HINIC5_CQM_SERVICE_T_OVS,     hinic5_cqm_service_capability_init_ovs},
	{HINIC5_CQM_SERVICE_T_ROCE,    hinic5_cqm_service_capability_init_roce},
	{HINIC5_CQM_SERVICE_T_TOE,     hinic5_cqm_service_capability_init_toe},
	{HINIC5_CQM_SERVICE_T_IOE,     hinic5_cqm_service_capability_init_ioe},
	{HINIC5_CQM_SERVICE_T_FC,      hinic5_cqm_service_capability_init_fc},
	{HINIC5_CQM_SERVICE_T_VBS,     hinic5_cqm_service_capability_init_vbs},
	{HINIC5_CQM_SERVICE_T_IPSEC,   hinic5_cqm_service_capability_init_ipsec},
	{HINIC5_CQM_SERVICE_T_VIRTIO,  hinic5_cqm_service_capability_init_virtio},
	{HINIC5_CQM_SERVICE_T_PPA,     hinic5_cqm_service_capability_init_ppa},
	{HINIC5_CQM_SERVICE_T_UB,      hinic5_cqm_service_capability_init_ub},
	{HINIC5_CQM_SERVICE_T_JBOF,    hinic5_cqm_service_capability_init_jbof},
	{HINIC5_CQM_SERVICE_T_VROCE,   hinic5_cqm_service_capability_init_vroce},
};

static void hinic5_cqm_service_capability_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					struct service_cap *service_capability)
{
	u32 list_size = ARRAY_SIZE(hinic5_serv_cap_init_list);
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	u32 i;

	for (i = 0; i < HINIC5_CQM_SERVICE_T_MAX; i++) {
		hinic5_cqm_handle->service[i].valid = false;
		hinic5_cqm_handle->service[i].has_register = false;
		hinic5_cqm_handle->service[i].buf_order = 0;
	}

	hinic5_cqm_service_valid_init(hinic5_cqm_handle, service_capability);

	hinic5_cqm_info(handle->dev_hdl, "Cap init: service type %d\n",
		 service_capability->chip_svc_type);

	for (i = 0; i < list_size; i++) {
		if (hinic5_cqm_handle->service[hinic5_serv_cap_init_list[i].service_type].valid &&
		    hinic5_serv_cap_init_list[i].serv_cap_proc) {
			hinic5_serv_cap_init_list[i].serv_cap_proc(hinic5_cqm_handle, (void *)service_capability);
		}
	}
}

static u32 get_fake_func_type(struct tag_hinic5_cqm_fake_cfg *fake_cfg, u16 func_id)
{
	if (func_id == fake_cfg->parent_func)
		return HINIC5_CQM_FAKE_FUNC_PARENT;

	if (func_id >= fake_cfg->child_func_start &&
	    func_id < (fake_cfg->child_func_start + fake_cfg->child_func_number))
		return HINIC5_CQM_FAKE_FUNC_CHILD;

	return HINIC5_CQM_FAKE_FUNC_UNUSED;
}

/* Set func_type in fake_hinic5_cqm_handle to ppf, pf, or vf. */
static void hinic5_cqm_set_func_type(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	u32 idx = hinic5_cqm_handle->func_attribute.func_global_idx;

	if (idx == 0)
		hinic5_cqm_handle->func_attribute.func_type = HINIC5_CQM_PPF;
	else if (idx < HINIC5_CQM_MAX_PF_NUM)
		hinic5_cqm_handle->func_attribute.func_type = HINIC5_CQM_PF;
	else
		hinic5_cqm_handle->func_attribute.func_type = HINIC5_CQM_VF;
}

static void hinic5_cqm_capability_init_smf(struct hinic5_hwdev *handle, struct service_cap *svc_cap)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = handle->hinic5_cqm_hdl;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;

	func_cap->lb_mode = svc_cap->lb_mode;

	/* Initializing the LB Mode */
	if (func_cap->lb_mode == HINIC5_CQM_LB_MODE_NORMAL)
		func_cap->smf_pg = 0;
	else
		func_cap->smf_pg = svc_cap->smf_pg;
	func_cap->smf_max_num = svc_cap->smf_max_num;
	func_cap->smf_enabled_num = svc_cap->smf_enabled_num;
	func_cap->bat_cid_index_bit_width = svc_cap->bat_cid_index_bit_width;

	hinic5_cqm_info(handle->dev_hdl,
		 "Cap init: lb_mode %u, smf_pg %u, smf_max_num %u\n",
		 func_cap->lb_mode, func_cap->smf_pg, func_cap->smf_max_num);
}

static void hinic5_cqm_capability_init_fake_vf(struct hinic5_hwdev *handle, struct service_cap *svc_cap)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = handle->hinic5_cqm_hdl;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_fake_cfg *cfg = &func_cap->fake_cfg;

	func_cap->fake_func_type = HINIC5_CQM_FAKE_FUNC_UNUSED;
	memset(cfg, 0, sizeof(*cfg));

	if (svc_cap->fake_vf_num != 0) {
		u32 parent_func_id = svc_cap->fake_vf_parent_func_id;
		if (parent_func_id == 0)
			parent_func_id = hinic5_cqm_handle->func_attribute.port_to_port_idx;

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

		func_cap->fake_func_type = get_fake_func_type(cfg, hinic5_global_func_id(handle));
	}

	hinic5_cqm_info(handle->dev_hdl,
		 "Cap init: fake_func_type %u, parent %u, child start %u num %u, lazy init %d\n",
		 func_cap->fake_func_type, cfg->parent_func,
		 cfg->child_func_start, cfg->child_func_number,
		 cfg->fake_vf_lazy_init);
}

static int hinic5_cqm_capability_init_bloomfilter(struct hinic5_hwdev *handle)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;

	func_cap->bloomfilter_enable = service_capability->bloomfilter_en;
	hinic5_cqm_info(handle->dev_hdl, "Cap init: bloomfilter_enable %u (1: enable; 0: disable)\n",
		 func_cap->bloomfilter_enable);

	if (func_cap->bloomfilter_enable != 0) {
		func_cap->bloomfilter_length = service_capability->bfilter_len;
		func_cap->bloomfilter_addr = service_capability->bfilter_start_addr;
		if (func_cap->bloomfilter_length != 0 &&
		    !hinic5_cqm_check_align(func_cap->bloomfilter_length)) {
			hinic5_cqm_err(handle->dev_hdl, "Cap init: bloomfilter_length %u is not the power of 2\n",
				func_cap->bloomfilter_length);

			return HINIC5_CQM_FAIL;
		}
	}

	hinic5_cqm_info(handle->dev_hdl, "Cap init: bloomfilter_length 0x%x, bloomfilter_addr 0x%x\n",
		 func_cap->bloomfilter_length, func_cap->bloomfilter_addr);

	return 0;
}

static void hinic5_cqm_capability_init_part_cap(struct hinic5_hwdev *handle)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;

	func_cap->flow_table_based_conn_number = service_capability->max_connect_num;
	func_cap->flow_table_based_conn_cache_number = service_capability->max_stick2cache_num;
	hinic5_cqm_info(handle->dev_hdl, "Cap init: cfg max_conn_num 0x%x, max_cache_conn_num 0x%x\n",
		 func_cap->flow_table_based_conn_number,
		 func_cap->flow_table_based_conn_cache_number);

	func_cap->hash_basic_size = HINIC5_CQM_HASH_BUCKET_SIZE_64;

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
	func_cap->l3i_basic_size = HINIC5_CQM_L3I_SIZE_8;

	func_cap->xid_alloc_mode = true; /* xid alloc do not reuse */
	func_cap->gpa_check_enable = true;
}

STATIC int hinic5_cqm_get_ppf_timer_cfg(struct hinic5_hwdev *handle)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = handle->hinic5_cqm_hdl;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
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

	hinic5_cqm_info(handle->dev_hdl,
		 "host timer cfg: pf start %u, num %u. vf start %u, num %u, actual %u, seg deploy %d\n",
		 func_cap->timer_pf_id_start, func_cap->timer_pf_num,
		 func_cap->timer_vf_id_start, func_cap->timer_vf_num,
		 func_cap->timer_vf_num_actual,
		 func_cap->timer_vf_deploy_with_segs);

	hinic5_cqm_info(handle->dev_hdl,
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

static int hinic5_cqm_capability_init_timer(struct hinic5_hwdev *handle)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	u32 total_timer_num = 0;
	int err;

	/* Initializes the PPF capabilities: include timer, pf, vf. */
	if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle) && (service_capability->timer_en != 0)) {
		func_cap->pf_num = service_capability->pf_num;
		func_cap->pf_id_start = service_capability->pf_id_start;
		func_cap->vf_num = service_capability->vf_num;
		func_cap->vf_id_start = service_capability->vf_id_start;
		hinic5_cqm_info(handle->dev_hdl, "Cap init: total function num 0x%x\n",
			 service_capability->host_total_function);
		hinic5_cqm_info(handle->dev_hdl, "Cap init: pf_num 0x%x, pf_id_start 0x%x, vf_num 0x%x, vf_id_start 0x%x\n",
			 func_cap->pf_num, func_cap->pf_id_start,
			 func_cap->vf_num, func_cap->vf_id_start);

		err = hinic5_cqm_get_ppf_timer_cfg(handle);
		if (err != 0)
			return err;

		total_timer_num = func_cap->timer_pf_num + func_cap->timer_vf_num;
	}

	func_cap->timer_enable = service_capability->timer_en;
	hinic5_cqm_info(handle->dev_hdl, "Cap init: timer_enable %u (1: enable; 0: disable)\n",
		 func_cap->timer_enable);

	func_cap->timer_number = HINIC5_CQM_TIMER_ALIGN_SCALE_NUM * total_timer_num;
	func_cap->timer_basic_size = HINIC5_CQM_TIMER_SIZE_32;

	return 0;
}

static void print_bat_cap(struct hinic5_hwdev *hwdev, const char *prefix_in,
			  struct tag_hinic5_cqm_func_capability *cap)
{
	const char *prefix = prefix_in ? prefix_in : "";

	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: hash number 0x%x\n",
		 prefix, cap->hash_number);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: qpc number 0x%x, reserved 0x%x, basic size 0x%x, alloc static %d\n",
		 prefix, cap->qpc_number, cap->qpc_reserved, cap->qpc_basic_size,
		 cap->qpc_alloc_static);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: scqc number 0x%x, reserved 0x%x, basic size 0x%x, alloc static %d\n",
		 prefix, cap->scqc_number, cap->scq_reserved, cap->scqc_basic_size,
		 cap->scqc_alloc_static);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: srqc number 0x%x, reserved 0x%x, basic size 0x%x, alloc static %d\n",
		 prefix, cap->srqc_number, cap->srq_reserved, cap->srqc_basic_size,
		 cap->srqc_alloc_static);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: mpt number 0x%x, reserved 0x%x\n",
		 prefix, cap->mpt_number, cap->mpt_reserved);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: gid number 0x%x, lun number 0x%x\n",
		 prefix, cap->gid_number, cap->lun_number);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: taskmap number 0x%x, l3i number 0x%x\n",
		 prefix, cap->taskmap_number, cap->l3i_number);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: childc number 0x%x, basic size 0x%x\n",
		 prefix, cap->childc_number, cap->childc_basic_size);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: timer number 0x%x\n",
		 prefix, cap->timer_number);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: xid2cid number 0x%x, alloc static %d\n",
		 prefix, cap->xid2cid_number, cap->xid_alloc_mode);
	hinic5_cqm_info(hwdev->dev_hdl, "%sCap init: reorder number 0x%x\n",
		 prefix, cap->reorder_number);
}

static void hinic5_cqm_capability_init_cap_print(struct hinic5_hwdev *handle)
{
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;

	func_cap->ft_enable = service_capability->sf_svc_attr.ft_en;
	func_cap->rdma_enable = service_capability->sf_svc_attr.rdma_en;
	func_cap->gpa_spu_en = service_capability->func_gpa_spu_en;

	hinic5_cqm_info(handle->dev_hdl, "Cap init: pagesize_reorder %u\n", func_cap->pagesize_reorder);
	hinic5_cqm_info(handle->dev_hdl, "Cap init: acs_spu_en %u, gpa_check_enable %d\n",
		 func_cap->gpa_spu_en, func_cap->gpa_check_enable);
	hinic5_cqm_info(handle->dev_hdl, "Cap init: ft_enable %d, rdma_enable %d\n",
		 func_cap->ft_enable, func_cap->rdma_enable);

	print_bat_cap(handle, NULL, func_cap);
}

/**
 * Prototype    : hinic5_cqm_capability_init
 * Description  : Initializes the function and service capabilities of the HINIC5_CQM.
 *		  Information needs to be read from the configuration management
 *		  module.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/12/9
 *   Modification : Created function
 */
s32 hinic5_cqm_capability_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	int err = 0;

	err = hinic5_cqm_capability_init_timer(handle);
	if (err != 0)
		goto out;

	err = hinic5_cqm_capability_init_bloomfilter(handle);
	if (err != 0)
		goto out;

	hinic5_cqm_capability_init_part_cap(handle);

	hinic5_cqm_capability_init_smf(handle, service_capability);

	hinic5_cqm_capability_init_fake_vf(handle, service_capability);

	hinic5_cqm_service_capability_init(hinic5_cqm_handle, service_capability);

	hinic5_cqm_test_mode_init(hinic5_cqm_handle, service_capability);

	hinic5_cqm_service_capability_update(hinic5_cqm_handle);

	hinic5_cqm_capability_init_cap_print(handle);

	return HINIC5_CQM_SUCCESS;

out:
	if (HINIC5_CQM_IS_PPF(hinic5_cqm_handle))
		func_cap->timer_enable = 0;

	return err;
}

static void hinic5_cqm_fake_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	u32 i;

	if (!HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		return;

	for (i = 0; i < HINIC5_CQM_FAKE_FUNC_MAX; i++) {
		kfree(hinic5_cqm_handle->fake_hinic5_cqm_handle[i]);
		hinic5_cqm_handle->fake_hinic5_cqm_handle[i] = NULL;
	}
}

static void set_fake_hinic5_cqm_attr(struct hinic5_hwdev *handle, struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle,
			      u32 child_func_start, u32 i)
{
	struct hinic5_func_attr *func_attr = &fake_hinic5_cqm_handle->func_attribute;
	struct tag_hinic5_cqm_func_capability *func_cap = &fake_hinic5_cqm_handle->func_capability;
	struct tag_hinic5_cqm_fake_cfg *cfg = &func_cap->fake_cfg;

	func_attr->func_global_idx = (u16)(child_func_start + i);
	hinic5_cqm_set_func_type(fake_hinic5_cqm_handle);

	func_cap->fake_func_type = HINIC5_CQM_FAKE_FUNC_CHILD_AGENT;

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

	hinic5_cqm_service_capability_update(fake_hinic5_cqm_handle);
}

static void print_fake_hinic5_cqm_attr(struct hinic5_hwdev *hwdev, struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle)
{
	hinic5_cqm_func_capability_s *fake_func_cap = &fake_hinic5_cqm_handle->func_capability;
	struct hinic5_func_attr *fake_func_attr = &fake_hinic5_cqm_handle->func_attribute;
	const u16 fake_func_id = fake_func_attr->func_global_idx;
	char prefix[0x20] = { 0 };
	hinic5_cqm_info(hwdev->dev_hdl, "[Fake %u] global_func_idx %u, func_type %d, parent_func_idx %u\n",
		 fake_func_id, fake_func_id, fake_func_attr->func_type, hinic5_global_func_id(hwdev));

	sprintf(prefix, "[Fake %u] ", fake_func_id);
	print_bat_cap(hwdev, prefix, fake_func_cap);
}

/**
 * Prototype    : hinic5_cqm_fake_init
 * Description  : When the fake VF mode is supported, the HINIC5_CQM handles of
 *		  the fake VFs need to be copied.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle: Parent HINIC5_CQM handle of the current PF
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2020/4/15
 *   Modification : Created function
 */
static s32 hinic5_cqm_fake_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle = NULL;
	u32 child_func_start, child_func_number, i;

	if (!HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		return HINIC5_CQM_SUCCESS;

	child_func_start = hinic5_cqm_get_child_func_start(hinic5_cqm_handle);
	child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);
	if (child_func_number == 0) {
		hinic5_cqm_warn(handle->dev_hdl, "no child func, skip fake init\n");
		return HINIC5_CQM_SUCCESS;
	}

	for (i = 0; i < child_func_number; i++) {
		fake_hinic5_cqm_handle = hinic5_cqm_handle_fork(hinic5_cqm_handle);
		if (!fake_hinic5_cqm_handle) {
			hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_handle_fork));
			goto err;
		}

		set_fake_hinic5_cqm_attr(handle, fake_hinic5_cqm_handle, (u32)child_func_start, i);
		print_fake_hinic5_cqm_attr(handle, fake_hinic5_cqm_handle);

		fake_hinic5_cqm_handle->parent_hinic5_cqm_handle = hinic5_cqm_handle;
		hinic5_cqm_handle->fake_hinic5_cqm_handle[i] = fake_hinic5_cqm_handle;
	}

	return HINIC5_CQM_SUCCESS;

err:
	hinic5_cqm_fake_uninit(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

static void hinic5_cqm_fake_mem_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle = NULL;
	u32 child_func_number, i;

	if (!HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		return;

	child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_hinic5_cqm_handle = hinic5_cqm_handle->fake_hinic5_cqm_handle[i];
		atomic_set(&fake_hinic5_cqm_handle->handle_state, HINIC5_CQM_HANDLE_STATE_REMOVE);

		hinic5_cqm_object_table_uninit(fake_hinic5_cqm_handle);
		hinic5_cqm_bitmap_uninit(fake_hinic5_cqm_handle);
		hinic5_cqm_cla_uninit(fake_hinic5_cqm_handle, HINIC5_CQM_BAT_ENTRY_MAX);
		hinic5_cqm_bat_uninit(fake_hinic5_cqm_handle);
	}
}

static s32 fake_hinic5_cqm_handle_mem_init(struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle)
{
	struct hinic5_hwdev *handle = fake_hinic5_cqm_handle->ex_handle;

	if (!HINIC5_CQM_IS_FAKE_CHILD_AGENT(fake_hinic5_cqm_handle))
		return HINIC5_CQM_FAIL;

	if (atomic_cmpxchg(&fake_hinic5_cqm_handle->handle_state,
			   HINIC5_CQM_HANDLE_STATE_INIT, HINIC5_CQM_HANDLE_STATE_READY
			   ) != HINIC5_CQM_HANDLE_STATE_INIT) {
		hinic5_cqm_warn(handle->dev_hdl, "[Fake %u] mem already inited\n",
			 fake_hinic5_cqm_handle->func_attribute.func_global_idx);
		return HINIC5_CQM_FAIL;
	}

	if (hinic5_cqm_bat_init(fake_hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bat_init));
		goto err1;
	}

	if (hinic5_cqm_cla_init(fake_hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_init));
		goto err2;
	}

	if (hinic5_cqm_bitmap_init(fake_hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bitmap_init));
		goto err3;
	}

	if (hinic5_cqm_object_table_init(fake_hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_table_init));
		goto err4;
	}

	hinic5_cqm_info(handle->dev_hdl, "[Fake %u] mem inited\n",
		 fake_hinic5_cqm_handle->func_attribute.func_global_idx);

	return HINIC5_CQM_SUCCESS;

err4:
	hinic5_cqm_bitmap_uninit(fake_hinic5_cqm_handle);
err3:
	hinic5_cqm_cla_uninit(fake_hinic5_cqm_handle, HINIC5_CQM_BAT_ENTRY_MAX);
err2:
	hinic5_cqm_bat_uninit(fake_hinic5_cqm_handle);
err1:
	hinic5_cqm_fake_mem_uninit(fake_hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_fake_mem_init
 * Description  : Initialize resources of the extended fake function.
 * Input        : struct tag_hinic5_cqm_handle *hinic5_cqm_handle: Parent HINIC5_CQM handle of the current PF
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2020/4/15
 *   Modification : Created function
 */
static s32 hinic5_cqm_fake_mem_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle = NULL;
	u32 child_func_number, i;
	int ret;

	if (!HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		return HINIC5_CQM_SUCCESS;

	child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_hinic5_cqm_handle = hinic5_cqm_handle->fake_hinic5_cqm_handle[i];
		ret = snprintf(fake_hinic5_cqm_handle->name, HINIC5_VRAM_NAME_MAX_LEN,
			       "%s%s%02u", hinic5_cqm_handle->name, HINIC5_VRAM_HINIC5_CQM_FAKE_MEM_BASE, i);
		if (ret < 0) {
			hinic5_cqm_err(handle->dev_hdl, "fake hinic5_cqm handle hinic5_vram name snprintf_s failed");
			return HINIC5_CQM_FAIL;
		}

		/* Fake VF lazy init support */
		if (hinic5_cqm_is_fake_vf_lazy_init(hinic5_cqm_handle)) {
			hinic5_cqm_info(handle->dev_hdl, "[Fake %u] init delayed\n",
				fake_hinic5_cqm_handle->func_attribute.func_global_idx);
			continue;
		}

		ret = fake_hinic5_cqm_handle_mem_init(fake_hinic5_cqm_handle);
		if (ret != HINIC5_CQM_SUCCESS) {
			hinic5_cqm_err(handle->dev_hdl,
				HINIC5_CQM_FUNCTION_FAIL(fake_hinic5_cqm_handle_mem_init));
			goto err;
		}
	}

	return HINIC5_CQM_SUCCESS;

err:
	hinic5_cqm_fake_mem_uninit(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_mem_init
 * Description  : Initialize HINIC5_CQM memory, including tables at different levels.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
s32 hinic5_cqm_mem_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	int ret;

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	ret = snprintf(hinic5_cqm_handle->name, HINIC5_VRAM_NAME_MAX_LEN,
		       "%s%02u", HINIC5_VRAM_HINIC5_CQM_GLB_FUNC_BASE, hinic5_global_func_id(handle));
	if (ret < 0) {
		hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm handle hinic5_vram name snprintf_s failed");
		return HINIC5_CQM_FAIL;
	}
	if (hinic5_cqm_fake_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_fake_init));
		return HINIC5_CQM_FAIL;
	}

	if (hinic5_cqm_fake_mem_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_fake_mem_init));
		goto err1;
	}

	if (hinic5_cqm_bat_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bat_init));
		goto err2;
	}

	if (hinic5_cqm_cla_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_cla_init));
		goto err3;
	}

	if (hinic5_cqm_bitmap_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_bitmap_init));
		goto err4;
	}

	if (hinic5_cqm_object_table_init(hinic5_cqm_handle) != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_FUNCTION_FAIL(hinic5_cqm_object_table_init));
		goto err5;
	}

	return HINIC5_CQM_SUCCESS;

err5:
	hinic5_cqm_bitmap_uninit(hinic5_cqm_handle);
err4:
	hinic5_cqm_cla_uninit(hinic5_cqm_handle, HINIC5_CQM_BAT_ENTRY_MAX);
err3:
	hinic5_cqm_bat_uninit(hinic5_cqm_handle);
err2:
	hinic5_cqm_fake_mem_uninit(hinic5_cqm_handle);
err1:
	hinic5_cqm_fake_uninit(hinic5_cqm_handle);
	return HINIC5_CQM_FAIL;
}

int hinic5_cqm_init_fake_vf(void *ex_handle, u32 vf_id)
{
	struct hinic5_hwdev *handle = ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle = NULL;
	u32 child_func_start, child_func_number;
	int err;

	if (unlikely(!ex_handle)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return -EINVAL;
	}

	hinic5_cqm_handle = handle->hinic5_cqm_hdl;
	if (unlikely(!hinic5_cqm_handle)) {
		hinic5_cqm_err(handle->dev_hdl, "Stateful not init\n");
		return -EINVAL;
	}

	if (unlikely(atomic_read(&hinic5_cqm_handle->handle_state) != HINIC5_CQM_HANDLE_STATE_READY)) {
		hinic5_cqm_err(handle->dev_hdl, "Stateful not ready\n");
		return -EAGAIN;
	}

	if (!HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle)) {
		hinic5_cqm_err(handle->dev_hdl, "Not a Fake VF group parent\n");
		return -EPERM;
	}

	child_func_start  = hinic5_cqm_get_child_func_start(hinic5_cqm_handle);
	child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);
	if (vf_id < child_func_start || vf_id >= child_func_start + child_func_number) {
		hinic5_cqm_err(handle->dev_hdl,
			"VF %u is not in the Fake VF group\n", vf_id);
		return -EINVAL;
	}

	fake_hinic5_cqm_handle = hinic5_cqm_handle->fake_hinic5_cqm_handle[vf_id - child_func_start];
	err = fake_hinic5_cqm_handle_mem_init(fake_hinic5_cqm_handle);
	if (err != HINIC5_CQM_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_FUNCTION_FAIL(fake_hinic5_cqm_handle_mem_init));
		return -EFAULT;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_cqm_init_fake_vf);

void hinic5_cqm_cla_fake_vf_cache_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 reset_flag)
{
	struct hinic5_hwdev *handle = hinic5_cqm_handle->ex_handle;
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle = NULL;
	u32 child_func_number, i;
	u16 func_global_idx;
	int err;

	if (!HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle))
		return;

	child_func_number = hinic5_cqm_get_child_func_number(hinic5_cqm_handle);

	for (i = 0; i < child_func_number; i++) {
		fake_hinic5_cqm_handle = hinic5_cqm_handle->fake_hinic5_cqm_handle[i];
		func_global_idx = fake_hinic5_cqm_handle->func_attribute.func_global_idx;

		err = hinic5_func_reset(handle, func_global_idx,
					BIT(reset_flag), HINIC5_CHANNEL_COMM);
		if (err != 0)
			hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm fake vf cla cache invalid err, func_id 0x%x\n", func_global_idx);
	}
}

void hinic5_cqm_cla_func_cache_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, u32 reset_flag)
{
	int err;
	u16 func_id;
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)hinic5_cqm_handle->ex_handle;

	func_id = hinic5_global_func_id(handle);
	err = hinic5_func_reset(handle, func_id, BIT(reset_flag), HINIC5_CHANNEL_COMM);
	if (err != 0)
		hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm cla cache invalid err, func_index = 0x%x\n", func_id);
}

/**
 * Prototype    : hinic5_cqm_mem_uninit
 * Description  : Deinitialize HINIC5_CQM memory, including tables at different levels.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
void hinic5_cqm_mem_uninit(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);

	hinic5_cqm_object_table_uninit(hinic5_cqm_handle);
	hinic5_cqm_bitmap_uninit(hinic5_cqm_handle);

	if (COMM_SUPPORT_SMF_CACHE_INVALID(handle)) {
		hinic5_cqm_cla_fake_vf_cache_invalid(hinic5_cqm_handle, RES_TYPE_SMF);
		hinic5_cqm_cla_func_cache_invalid(hinic5_cqm_handle, RES_TYPE_SMF);
	}

	hinic5_cqm_cla_uninit(hinic5_cqm_handle, HINIC5_CQM_BAT_ENTRY_MAX);
	hinic5_cqm_bat_uninit(hinic5_cqm_handle);
	hinic5_cqm_fake_mem_uninit(hinic5_cqm_handle);

	if (COMM_SUPPORT_SMF_CACHE_INVALID(handle)) {
		hinic5_cqm_cla_fake_vf_cache_invalid(hinic5_cqm_handle, RES_TYPE_SMF_CACHE_INVALID);
		hinic5_cqm_cla_func_cache_invalid(hinic5_cqm_handle, RES_TYPE_SMF_CACHE_INVALID);
	}

	hinic5_cqm_fake_uninit(hinic5_cqm_handle);
}

/**
 * Prototype    : hinic5_cqm_event_init
 * Description  : Initialize HINIC5_CQM event callback.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : s32
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
s32 hinic5_cqm_event_init(void *ex_handle)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;

	/* Registers the CEQ and AEQ callback functions. */
	if (hinic5_ceq_register_cb(ex_handle, ex_handle, HINIC5_NON_L2NIC_SCQ,
				   hinic5_cqm_scq_callback) != CHIPIF_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "Event: fail to register scq callback\n");
		return HINIC5_CQM_FAIL;
	}

	if (hinic5_ceq_register_cb(ex_handle, ex_handle, HINIC5_NON_L2NIC_ECQ,
				   hinic5_cqm_ecq_callback) != CHIPIF_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "Event: fail to register ecq callback\n");
		goto err1;
	}

	if (hinic5_ceq_register_cb(ex_handle, ex_handle, HINIC5_NON_L2NIC_NO_CQ_EQ,
				   hinic5_cqm_nocq_callback) != CHIPIF_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "Event: fail to register nocq callback\n");
		goto err2;
	}

	if (hinic5_aeq_register_swe_cb(ex_handle, ex_handle, HINIC5_STATEFUL_EVENT,
				       hinic5_cqm_aeq_callback) != CHIPIF_SUCCESS) {
		hinic5_cqm_err(handle->dev_hdl, "Event: fail to register aeq callback\n");
		goto err3;
	}

	return HINIC5_CQM_SUCCESS;

err3:
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_NO_CQ_EQ);
err2:
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_ECQ);
err1:
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_SCQ);
	return HINIC5_CQM_FAIL;
}

/**
 * Prototype    : hinic5_cqm_event_uninit
 * Description  : Deinitialize HINIC5_CQM event callback.
 * Input        : void *ex_handle
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/7/6
 *   Modification : Created function
 */
void hinic5_cqm_event_uninit(void *ex_handle)
{
	hinic5_aeq_unregister_swe_cb(ex_handle, HINIC5_STATEFUL_EVENT);
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_NO_CQ_EQ);
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_ECQ);
	hinic5_ceq_unregister_cb(ex_handle, HINIC5_NON_L2NIC_SCQ);
}

/**
 * Prototype    : hinic5_cqm_scq_callback
 * Description  : HINIC5_CQM module callback processing for the ceq,
 *		  which processes NON_L2NIC_SCQ.
 * Input        : void *ex_handle
 *		  u32 ceqe_data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void hinic5_cqm_scq_callback(void *ex_handle, u32 ceqe_data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	struct tag_hinic5_cqm_queue *hinic5_cqm_queue = NULL;
	struct tag_hinic5_cqm_object *obj = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(scq_callback_ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_scq_callback_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(scq_callback_hinic5_cqm_handle));
		return;
	}

	hinic5_cqm_dbg_on(hinic5_cqm_verbose, handle->dev_hdl,
		"Event: %s, ceqe_data=0x%x\n", __func__, ceqe_data);
	obj = hinic5_cqm_object_get(ex_handle, HINIC5_CQM_OBJECT_NONRDMA_SCQ,
			     HINIC5_CQM_CQN_FROM_CEQE(ceqe_data), true);
	if (unlikely(obj == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(scq_callback_obj));
		return;
	}

	if (unlikely(obj->service_type >= HINIC5_CQM_SERVICE_T_MAX)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(obj->service_type));
		hinic5_cqm_object_put(obj);
		return;
	}

	service = &hinic5_cqm_handle->service[obj->service_type];
	service_template = &service->service_template;
	if (service_template->shared_cq_ceq_callback) {
		hinic5_cqm_queue = (struct tag_hinic5_cqm_queue *)(void *)obj;
		service_template->shared_cq_ceq_callback(service_template->service_handle,
							 HINIC5_CQM_CQN_FROM_CEQE(ceqe_data),
							 hinic5_cqm_queue->priv);
	} else {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_PTR_NULL(shared_cq_ceq_callback));
	}

	hinic5_cqm_object_put(obj);
}

/**
 * Prototype    : hinic5_cqm_ecq_callback
 * Description  : HINIC5_CQM module callback processing for the ceq,
 *		  which processes NON_L2NIC_ECQ.
 * Input        : void *ex_handle
 *		  u32 ceqe_data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void hinic5_cqm_ecq_callback(void *ex_handle, u32 ceqe_data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	struct tag_hinic5_cqm_qpc_mpt *qpc = NULL;
	struct tag_hinic5_cqm_object *obj = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ecq_callback_ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_ecq_callback_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ecq_callback_hinic5_cqm_handle));
		return;
	}

	obj = hinic5_cqm_object_get(ex_handle, HINIC5_CQM_OBJECT_SERVICE_CTX,
			     HINIC5_CQM_XID_FROM_CEQE(ceqe_data), true);
	if (unlikely(obj == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ecq_callback_obj));
		return;
	}

	if (unlikely(obj->service_type >= HINIC5_CQM_SERVICE_T_MAX)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(obj->service_type));
		hinic5_cqm_object_put(obj);
		return;
	}

	service = &hinic5_cqm_handle->service[obj->service_type];
	service_template = &service->service_template;
	if (service_template->embedded_cq_ceq_callback) {
		qpc = (struct tag_hinic5_cqm_qpc_mpt *)(void *)obj;
		service_template->embedded_cq_ceq_callback(service_template->service_handle,
							   HINIC5_CQM_XID_FROM_CEQE(ceqe_data), qpc->priv);
	} else {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_PTR_NULL(embedded_cq_ceq_callback));
	}

	hinic5_cqm_object_put(obj);
}

/**
 * Prototype    : hinic5_cqm_nocq_callback
 * Description  : HINIC5_CQM module callback processing for the ceq,
 *		  which processes NON_L2NIC_NO_CQ_EQ.
 * Input        : void *ex_handle
 *		  u32 ceqe_data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
void hinic5_cqm_nocq_callback(void *ex_handle, u32 ceqe_data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	struct tag_hinic5_cqm_qpc_mpt *qpc = NULL;
	struct tag_hinic5_cqm_object *obj = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(nocq_callback_ex_handle));
		return;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_nocq_callback_cnt);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(nocq_callback_hinic5_cqm_handle));
		return;
	}

	obj = hinic5_cqm_object_get(ex_handle, HINIC5_CQM_OBJECT_SERVICE_CTX,
			     HINIC5_CQM_XID_FROM_CEQE(ceqe_data), true);
	if (unlikely(obj == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(nocq_callback_obj));
		return;
	}

	if (unlikely(obj->service_type >= HINIC5_CQM_SERVICE_T_MAX)) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(obj->service_type));
		hinic5_cqm_object_put(obj);
		return;
	}

	service = &hinic5_cqm_handle->service[obj->service_type];
	service_template = &service->service_template;
	if (service_template->no_cq_ceq_callback) {
		qpc = (struct tag_hinic5_cqm_qpc_mpt *)(void *)obj;
		service_template->no_cq_ceq_callback(service_template->service_handle,
						     HINIC5_CQM_XID_FROM_CEQE(ceqe_data),
						     HINIC5_CQM_QID_FROM_CEQE(ceqe_data),
						     qpc->priv);
	} else {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_PTR_NULL(no_cq_ceq_callback));
	}

	hinic5_cqm_object_put(obj);
}

/* Distributes events to different service modules
 * based on the event type.
 */
static u32 hinic5_cqm_aeq_event2type(u8 event)
{
	if (event < HINIC5_CQM_AEQ_BASE_T_DMMU)
		return HINIC5_CQM_SERVICE_T_NIC;
	if (event < HINIC5_CQM_AEQ_BASE_T_ROCE)
		return HINIC5_CQM_SERVICE_T_DMMU;
	if (event < HINIC5_CQM_AEQ_BASE_T_FC)
		return HINIC5_CQM_SERVICE_T_ROCE;
	if (event < HINIC5_CQM_AEQ_BASE_T_IOE)
		return HINIC5_CQM_SERVICE_T_FC;
	if (event < HINIC5_CQM_AEQ_BASE_T_TOE)
		return HINIC5_CQM_SERVICE_T_IOE;
	if (event < HINIC5_CQM_AEQ_BASE_T_UB)
		return HINIC5_CQM_SERVICE_T_TOE;
	if (event < HINIC5_CQM_AEQ_BASE_T_VBS)
		return HINIC5_CQM_SERVICE_T_UB;
	if (event < HINIC5_CQM_AEQ_BASE_T_IPSEC)
		return HINIC5_CQM_SERVICE_T_VBS;
	if (event < HINIC5_CQM_AEQ_BASE_T_MAX)
		return HINIC5_CQM_SERVICE_T_IPSEC;
	return HINIC5_CQM_SERVICE_T_MAX;
}

/**
 * Prototype    : hinic5_cqm_aeq_callback
 * Description  : HINIC5_CQM module callback processing for the aeq.
 * Input        : void *ex_handle
 *		  u8 event
 *		  u64 data
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/5/5
 *   Modification : Created function
 */
u8 hinic5_cqm_aeq_callback(void *ex_handle, u8 event, u8 *data)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_service_register_template *service_template = NULL;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;
	u8 event_level = FAULT_LEVEL_MAX;
	u32 service_type;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(aeq_callback_ex_handle));
		return event_level;
	}

	if (event >= HINIC5_CQM_AEQ_CALLBACK_CNT_MAX) {
		hinic5_cqm_err(handle->dev_hdl, "hinic5_cqm aeq event invalid %u\n", event);
		return event_level;
	}

	atomic_inc(&handle->hw_stats.hinic5_cqm_stats.hinic5_cqm_aeq_callback_cnt[event]);

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(aeq_callback_hinic5_cqm_handle));
		return event_level;
	}

	/* Distributes events to different service modules
	 * based on the event type.
	 */
	service_type = hinic5_cqm_aeq_event2type(event);
	if (service_type == HINIC5_CQM_SERVICE_T_MAX) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(event));
		return event_level;
	}

	service = &hinic5_cqm_handle->service[service_type];
	service_template = &service->service_template;

	if (!service_template->aeq_level_callback)
		hinic5_cqm_err(handle->dev_hdl, "Event: service_type %u aeq_level_callback unregistered, event %u\n",
			service_type, event);
	else
		event_level = service_template->aeq_level_callback(service_template->service_handle,
								   event, data);

	if (!service_template->aeq_callback)
		hinic5_cqm_err(handle->dev_hdl, "Event: service_type %u aeq_callback unregistered\n",
			service_type);
	else
		service_template->aeq_callback(service_template->service_handle,
					       event, data);

	return event_level;
}

/**
 * Prototype    : hinic5_cqm_service_register
 * Description  : Callback template for the service driver
 *		  to register with the HINIC5_CQM.
 * Input        : void *ex_handle
 *		  struct tag_service_register_template *service_template
 * Output       : None
 * Return Value : s32
 * 1.Date	  : 2015/4/5
 * Modification	  : Created function
 */
s32 hinic5_cqm_service_register(void *ex_handle, struct tag_service_register_template *service_template)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return HINIC5_CQM_FAIL;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return HINIC5_CQM_FAIL;
	}
	if (unlikely(service_template == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(service_template));
		return HINIC5_CQM_FAIL;
	}

	if (service_template->service_type >= HINIC5_CQM_SERVICE_T_MAX) {
		hinic5_cqm_err(handle->dev_hdl,
			HINIC5_CQM_WRONG_VALUE(service_template->service_type));
		return HINIC5_CQM_FAIL;
	}
	service = &hinic5_cqm_handle->service[service_template->service_type];
	if (!service->valid) {
		hinic5_cqm_err(handle->dev_hdl, "Service register: service_type %u is invalid\n",
			service_template->service_type);
		return HINIC5_CQM_FAIL;
	}

	if (service->has_register) {
		hinic5_cqm_err(handle->dev_hdl, "Service register: service_type %u has registered\n",
			service_template->service_type);
		return HINIC5_CQM_FAIL;
	}

	service->has_register = true;
	memcpy((void *)(&service->service_template),
	       (void *)service_template,
	       sizeof(struct tag_service_register_template));

	return HINIC5_CQM_SUCCESS;
}
EXPORT_SYMBOL(hinic5_cqm_service_register);

/**
 * Prototype    : hinic5_cqm_service_unregister
 * Description  : The service driver deregisters the callback function
 *		  from the HINIC5_CQM.
 * Input        : void *ex_handle
 *		  u32 service_type
 * Output       : None
 * Return Value : void
 * 1.Date         : 2015/4/5
 * Modification	  : Created function
 */
void hinic5_cqm_service_unregister(void *ex_handle, u32 service_type)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct tag_hinic5_cqm_handle *hinic5_cqm_handle = NULL;
	struct tag_hinic5_cqm_service *service = NULL;

	if (unlikely(ex_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(ex_handle));
		return;
	}

	hinic5_cqm_handle = (struct tag_hinic5_cqm_handle *)(handle->hinic5_cqm_hdl);
	if (unlikely(hinic5_cqm_handle == NULL)) {
		HINIC5_CQM_PTR_CHECK_ERR(HINIC5_CQM_PTR_NULL(hinic5_cqm_handle));
		return;
	}

	if (service_type >= HINIC5_CQM_SERVICE_T_MAX) {
		hinic5_cqm_err(handle->dev_hdl, HINIC5_CQM_WRONG_VALUE(service_type));
		return;
	}

	service = &hinic5_cqm_handle->service[service_type];
	if (!service->valid)
		hinic5_cqm_err(handle->dev_hdl, "Service unregister: service_type %u is disable\n",
			service_type);

	service->has_register = false;
	memset(&service->service_template, 0,
	       sizeof(struct tag_service_register_template));
}
EXPORT_SYMBOL(hinic5_cqm_service_unregister);

s32 hinic5_cqm_fake_vf_num_set(void *ex_handle, u16 fake_vf_num_cfg)
{
	struct hinic5_hwdev *handle = (struct hinic5_hwdev *)ex_handle;
	struct service_cap *svc_cap = NULL;

	if (!ex_handle || !handle->cfg_mgmt)
		return HINIC5_CQM_FAIL;

	svc_cap = &handle->cfg_mgmt->svc_cap;

	if (fake_vf_num_cfg > svc_cap->fake_vf_num) {
		hinic5_cqm_err(handle->dev_hdl, "fake_vf_num_cfg is invlaid, fw fake_vf_num is %u\n",
			svc_cap->fake_vf_num);
		return HINIC5_CQM_FAIL;
	}

	/* fake_vf_num_cfg is valid when func type is HINIC5_CQM_FAKE_FUNC_PARENT */
	svc_cap->fake_vf_num_cfg = fake_vf_num_cfg;
	hinic5_cqm_info(handle->dev_hdl, "fake_vf_num_cfg set to %u\n", fake_vf_num_cfg);

	return HINIC5_CQM_SUCCESS;
}
EXPORT_SYMBOL(hinic5_cqm_fake_vf_num_set);
