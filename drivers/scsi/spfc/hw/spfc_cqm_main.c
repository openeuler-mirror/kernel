// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "sphw_hw_cfg.h"
#include "spfc_cqm_main.h"

s32 cqm3_init(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;
	s32 ret;

	CQM_PTR_CHECK_RET(ex_handle, CQM_FAIL, CQM_PTR_NULL(ex_handle));

	cqm_handle = kmalloc(sizeof(*cqm_handle), GFP_KERNEL | __GFP_ZERO);
	CQM_PTR_CHECK_RET(cqm_handle, CQM_FAIL, CQM_ALLOC_FAIL(cqm_handle));

	/* Clear the memory to prevent other systems from
	 * not clearing the memory.
	 */
	memset(cqm_handle, 0, sizeof(struct cqm_handle));

	cqm_handle->ex_handle = handle;
	cqm_handle->dev = (struct pci_dev *)(handle->pcidev_hdl);
	handle->cqm_hdl = (void *)cqm_handle;

	/* Clearing Statistics */
	memset(&handle->hw_stats.cqm_stats, 0, sizeof(struct cqm_stats));

	/* Reads VF/PF information. */
	cqm_handle->func_attribute = handle->hwif->attr;
	cqm_info(handle->dev_hdl, "Func init: function[%u] type %d(0:PF,1:VF,2:PPF)\n",
		 cqm_handle->func_attribute.func_global_idx,
		 cqm_handle->func_attribute.func_type);

	/* Read capability from configuration management module */
	ret = cqm_capability_init(ex_handle);
	if (ret == CQM_FAIL) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_capability_init));
		goto err1;
	}

	/* Initialize memory entries such as BAT, CLA, and bitmap. */
	if (cqm_mem_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_mem_init));
		goto err1;
	}

	/* Event callback initialization */
	if (cqm_event_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_event_init));
		goto err2;
	}

	/* Doorbell initiation */
	if (cqm_db_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_db_init));
		goto err3;
	}

	/* Initialize the bloom filter. */
	if (cqm_bloomfilter_init(ex_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_bloomfilter_init));
		goto err4;
	}

	/* The timer bitmap is set directly at the beginning of the CQM.
	 * The ifconfig up/down command is not used to set or clear the bitmap.
	 */
	if (sphw_func_tmr_bitmap_set(ex_handle, true) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, "Timer start: enable timer bitmap failed\n");
		goto err5;
	}

	return CQM_SUCCESS;

err5:
	cqm_bloomfilter_uninit(ex_handle);
err4:
	cqm_db_uninit(ex_handle);
err3:
	cqm_event_uninit(ex_handle);
err2:
	cqm_mem_uninit(ex_handle);
err1:
	handle->cqm_hdl = NULL;
	kfree(cqm_handle);
	return CQM_FAIL;
}

void cqm3_uninit(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;
	s32 ret;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle));

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_NO_RET(cqm_handle, CQM_PTR_NULL(cqm_handle));

	/* The timer bitmap is set directly at the beginning of the CQM.
	 * The ifconfig up/down command is not used to set or clear the bitmap.
	 */
	cqm_info(handle->dev_hdl, "Timer stop: disable timer\n");
	if (sphw_func_tmr_bitmap_set(ex_handle, false) != CQM_SUCCESS)
		cqm_err(handle->dev_hdl, "Timer stop: disable timer bitmap failed\n");

	/* After the TMR timer stops, the system releases resources
	 * after a delay of one or two milliseconds.
	 */
	if (cqm_handle->func_attribute.func_type == CQM_PPF &&
	    cqm_handle->func_capability.timer_enable == CQM_TIMER_ENABLE) {
		cqm_info(handle->dev_hdl, "Timer stop: spfc ppf timer stop\n");
		ret = sphw_ppf_tmr_stop(handle);
		if (ret != CQM_SUCCESS)
			/* The timer fails to be stopped,
			 * and the resource release is not affected.
			 */
			cqm_info(handle->dev_hdl, "Timer stop: spfc ppf timer stop, ret=%d\n",
				 ret);
		/* Somebody requires a delay of 1 ms, which is inaccurate. */
		usleep_range(900, 1000);
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

void cqm_test_mode_init(struct cqm_handle *cqm_handle,
			struct service_cap *service_capability)
{
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;

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

void cqm_service_capability_update(struct cqm_handle *cqm_handle)
{
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;

	func_cap->qpc_number = GET_MIN(CQM_MAX_QPC_NUM, func_cap->qpc_number);
	func_cap->scqc_number = GET_MIN(CQM_MAX_SCQC_NUM, func_cap->scqc_number);
	func_cap->srqc_number = GET_MIN(CQM_MAX_SRQC_NUM, func_cap->srqc_number);
	func_cap->childc_number = GET_MIN(CQM_MAX_CHILDC_NUM, func_cap->childc_number);
}

void cqm_service_valid_init(struct cqm_handle *cqm_handle,
			    struct service_cap *service_capability)
{
	enum cfg_svc_type_en type = service_capability->chip_svc_type;
	struct cqm_service *svc = cqm_handle->service;

	svc[CQM_SERVICE_T_FC].valid = ((u32)type & CFG_SVC_FC_BIT5) ? true : false;
}

void cqm_service_capability_init_fc(struct cqm_handle *cqm_handle, void *pra)
{
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;
	struct service_cap *service_capability = (struct service_cap *)pra;
	struct fc_service_cap *fc_cap = &service_capability->fc_cap;
	struct dev_fc_svc_cap *dev_fc_cap = &fc_cap->dev_fc_cap;
	struct sphw_hwdev *handle = cqm_handle->ex_handle;

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

void cqm_service_capability_init(struct cqm_handle *cqm_handle,
				 struct service_cap *service_capability)
{
	struct sphw_hwdev *handle = cqm_handle->ex_handle;
	u32 i;

	for (i = 0; i < CQM_SERVICE_T_MAX; i++) {
		cqm_handle->service[i].valid = false;
		cqm_handle->service[i].has_register = false;
		cqm_handle->service[i].buf_order = 0;
	}

	cqm_service_valid_init(cqm_handle, service_capability);

	cqm_info(handle->dev_hdl, "Cap init: service type %d\n",
		 service_capability->chip_svc_type);

	if (cqm_handle->service[CQM_SERVICE_T_FC].valid)
		cqm_service_capability_init_fc(cqm_handle, (void *)service_capability);
}

/* Set func_type in fake_cqm_handle to ppf, pf, or vf. */
void cqm_set_func_type(struct cqm_handle *cqm_handle)
{
	u32 idx = cqm_handle->func_attribute.func_global_idx;

	if (idx == 0)
		cqm_handle->func_attribute.func_type = CQM_PPF;
	else if (idx < CQM_MAX_PF_NUM)
		cqm_handle->func_attribute.func_type = CQM_PF;
	else
		cqm_handle->func_attribute.func_type = CQM_VF;
}

void cqm_lb_fake_mode_init(struct cqm_handle *cqm_handle, struct service_cap *svc_cap)
{
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;

	func_cap->lb_mode = svc_cap->lb_mode;

	/* Initializing the LB Mode */
	if (func_cap->lb_mode == CQM_LB_MODE_NORMAL)
		func_cap->smf_pg = 0;
	else
		func_cap->smf_pg = svc_cap->smf_pg;

	func_cap->fake_cfg_number = 0;
	func_cap->fake_func_type = CQM_FAKE_FUNC_NORMAL;
}

s32 cqm_capability_init(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	struct service_cap *service_capability = &handle->cfg_mgmt->svc_cap;
	struct sphw_func_attr *func_attr = &cqm_handle->func_attribute;
	struct cqm_func_capability *func_cap = &cqm_handle->func_capability;
	u32 total_function_num = 0;
	int err = 0;

	/* Initializes the PPF capabilities: include timer, pf, vf. */
	if (func_attr->func_type == CQM_PPF) {
		total_function_num = service_capability->host_total_function;
		func_cap->timer_enable = service_capability->timer_en;
		func_cap->pf_num = service_capability->pf_num;
		func_cap->pf_id_start = service_capability->pf_id_start;
		func_cap->vf_num = service_capability->vf_num;
		func_cap->vf_id_start = service_capability->vf_id_start;

		cqm_info(handle->dev_hdl, "Cap init: total function num 0x%x\n",
			 total_function_num);
		cqm_info(handle->dev_hdl, "Cap init: pf_num 0x%x, pf_id_start 0x%x, vf_num 0x%x, vf_id_start 0x%x\n",
			 func_cap->pf_num, func_cap->pf_id_start,
			 func_cap->vf_num, func_cap->vf_id_start);
		cqm_info(handle->dev_hdl, "Cap init: timer_enable %u (1: enable; 0: disable)\n",
			 func_cap->timer_enable);
	}

	func_cap->flow_table_based_conn_number = service_capability->max_connect_num;
	func_cap->flow_table_based_conn_cache_number = service_capability->max_stick2cache_num;
	cqm_info(handle->dev_hdl, "Cap init: cfg max_conn_num 0x%x, max_cache_conn_num 0x%x\n",
		 func_cap->flow_table_based_conn_number,
		 func_cap->flow_table_based_conn_cache_number);

	func_cap->bloomfilter_enable = service_capability->bloomfilter_en;
	cqm_info(handle->dev_hdl, "Cap init: bloomfilter_enable %u (1: enable; 0: disable)\n",
		 func_cap->bloomfilter_enable);

	if (func_cap->bloomfilter_enable) {
		func_cap->bloomfilter_length = service_capability->bfilter_len;
		func_cap->bloomfilter_addr =
		    service_capability->bfilter_start_addr;
		if (func_cap->bloomfilter_length != 0 &&
		    !cqm_check_align(func_cap->bloomfilter_length)) {
			cqm_err(handle->dev_hdl, "Cap init: bloomfilter_length %u is not the power of 2\n",
				func_cap->bloomfilter_length);

			err = CQM_FAIL;
			goto out;
		}
	}

	cqm_info(handle->dev_hdl, "Cap init: bloomfilter_length 0x%x, bloomfilter_addr 0x%x\n",
		 func_cap->bloomfilter_length, func_cap->bloomfilter_addr);

	func_cap->qpc_reserved = 0;
	func_cap->mpt_reserved = 0;
	func_cap->scq_reserved = 0;
	func_cap->srq_reserved = 0;
	func_cap->qpc_alloc_static = false;
	func_cap->scqc_alloc_static = false;

	func_cap->l3i_number = CQM_L3I_COMM_NUM;
	func_cap->l3i_basic_size = CQM_L3I_SIZE_8;

	func_cap->timer_number = CQM_TIMER_ALIGN_SCALE_NUM * total_function_num;
	func_cap->timer_basic_size = CQM_TIMER_SIZE_32;

	func_cap->gpa_check_enable = true;

	cqm_lb_fake_mode_init(cqm_handle, service_capability);
	cqm_info(handle->dev_hdl, "Cap init: lb_mode=%u\n", func_cap->lb_mode);
	cqm_info(handle->dev_hdl, "Cap init: smf_pg=%u\n", func_cap->smf_pg);
	cqm_info(handle->dev_hdl, "Cap init: fake_func_type=%u\n", func_cap->fake_func_type);
	cqm_info(handle->dev_hdl, "Cap init: fake_cfg_number=%u\n", func_cap->fake_cfg_number);

	cqm_service_capability_init(cqm_handle, service_capability);

	cqm_test_mode_init(cqm_handle, service_capability);

	cqm_service_capability_update(cqm_handle);

	func_cap->ft_enable = service_capability->sf_svc_attr.ft_en;
	func_cap->rdma_enable = service_capability->sf_svc_attr.rdma_en;

	cqm_info(handle->dev_hdl, "Cap init: pagesize_reorder %u\n", func_cap->pagesize_reorder);
	cqm_info(handle->dev_hdl, "Cap init: xid_alloc_mode %d, gpa_check_enable %d\n",
		 func_cap->xid_alloc_mode, func_cap->gpa_check_enable);
	cqm_info(handle->dev_hdl, "Cap init: qpc_alloc_mode %d, scqc_alloc_mode %d\n",
		 func_cap->qpc_alloc_static, func_cap->scqc_alloc_static);
	cqm_info(handle->dev_hdl, "Cap init: hash_number 0x%x\n", func_cap->hash_number);
	cqm_info(handle->dev_hdl, "Cap init: qpc_number 0x%x, qpc_reserved 0x%x, qpc_basic_size 0x%x\n",
		 func_cap->qpc_number, func_cap->qpc_reserved, func_cap->qpc_basic_size);
	cqm_info(handle->dev_hdl, "Cap init: scqc_number 0x%x scqc_reserved 0x%x, scqc_basic_size 0x%x\n",
		 func_cap->scqc_number, func_cap->scq_reserved, func_cap->scqc_basic_size);
	cqm_info(handle->dev_hdl, "Cap init: srqc_number 0x%x, srqc_basic_size 0x%x\n",
		 func_cap->srqc_number, func_cap->srqc_basic_size);
	cqm_info(handle->dev_hdl, "Cap init: mpt_number 0x%x, mpt_reserved 0x%x\n",
		 func_cap->mpt_number, func_cap->mpt_reserved);
	cqm_info(handle->dev_hdl, "Cap init: gid_number 0x%x, lun_number 0x%x\n",
		 func_cap->gid_number, func_cap->lun_number);
	cqm_info(handle->dev_hdl, "Cap init: taskmap_number 0x%x, l3i_number 0x%x\n",
		 func_cap->taskmap_number, func_cap->l3i_number);
	cqm_info(handle->dev_hdl, "Cap init: timer_number 0x%x, childc_number 0x%x\n",
		 func_cap->timer_number, func_cap->childc_number);
	cqm_info(handle->dev_hdl, "Cap init: childc_basic_size 0x%x\n",
		 func_cap->childc_basic_size);
	cqm_info(handle->dev_hdl, "Cap init: xid2cid_number 0x%x, reorder_number 0x%x\n",
		 func_cap->xid2cid_number, func_cap->reorder_number);
	cqm_info(handle->dev_hdl, "Cap init: ft_enable %d, rdma_enable %d\n",
		 func_cap->ft_enable, func_cap->rdma_enable);

	return CQM_SUCCESS;

out:
	if (func_attr->func_type == CQM_PPF)
		func_cap->timer_enable = 0;

	return err;
}

s32 cqm_mem_init(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);

	if (cqm_bat_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bat_init));
		return CQM_FAIL;
	}

	if (cqm_cla_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_cla_init));
		goto err1;
	}

	if (cqm_bitmap_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_bitmap_init));
		goto err2;
	}

	if (cqm_object_table_init(cqm_handle) != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl,
			CQM_FUNCTION_FAIL(cqm_object_table_init));
		goto err3;
	}

	return CQM_SUCCESS;

err3:
	cqm_bitmap_uninit(cqm_handle);
err2:
	cqm_cla_uninit(cqm_handle, CQM_BAT_ENTRY_MAX);
err1:
	cqm_bat_uninit(cqm_handle);
	return CQM_FAIL;
}

void cqm_mem_uninit(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);

	cqm_object_table_uninit(cqm_handle);
	cqm_bitmap_uninit(cqm_handle);
	cqm_cla_uninit(cqm_handle, CQM_BAT_ENTRY_MAX);
	cqm_bat_uninit(cqm_handle);
}

s32 cqm_event_init(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;

	if (sphw_aeq_register_swe_cb(ex_handle, SPHW_STATEFULL_EVENT,
				     cqm_aeq_callback) != CHIPIF_SUCCESS) {
		cqm_err(handle->dev_hdl, "Event: fail to register aeq callback\n");
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

void cqm_event_uninit(void *ex_handle)
{
	sphw_aeq_unregister_swe_cb(ex_handle, SPHW_STATEFULL_EVENT);
}

u32 cqm_aeq_event2type(u8 event)
{
	u32 service_type;

	/* Distributes events to different service modules
	 * based on the event type.
	 */
	if (event >= CQM_AEQ_BASE_T_FC && event < CQM_AEQ_MAX_T_FC)
		service_type = CQM_SERVICE_T_FC;
	else
		service_type = CQM_SERVICE_T_MAX;

	return service_type;
}

u8 cqm_aeq_callback(void *ex_handle, u8 event, u8 *data)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct service_register_template *service_template = NULL;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	u8 event_level = FAULT_LEVEL_MAX;
	u32 service_type;

	CQM_PTR_CHECK_RET(ex_handle, event_level,
			  CQM_PTR_NULL(aeq_callback_ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_aeq_callback_cnt[event]);

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, event_level,
			  CQM_PTR_NULL(aeq_callback_cqm_handle));

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
		cqm_err(handle->dev_hdl, "Event: service_type %u aeq_level_callback unregistered\n",
			service_type);
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

s32 cqm3_service_register(void *ex_handle, struct service_register_template *service_template)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;

	CQM_PTR_CHECK_RET(ex_handle, CQM_FAIL, CQM_PTR_NULL(ex_handle));

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_RET(cqm_handle, CQM_FAIL, CQM_PTR_NULL(cqm_handle));
	CQM_PTR_CHECK_RET(service_template, CQM_FAIL,
			  CQM_PTR_NULL(service_template));

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
		     sizeof(struct service_register_template));

	return CQM_SUCCESS;
}

void cqm3_service_unregister(void *ex_handle, u32 service_type)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle));

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	CQM_PTR_CHECK_NO_RET(cqm_handle, CQM_PTR_NULL(cqm_handle));

	if (service_type >= CQM_SERVICE_T_MAX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(service_type));
		return;
	}

	service = &cqm_handle->service[service_type];
	if (!service->valid)
		cqm_err(handle->dev_hdl, "Service unregister: service_type %u is disable\n",
			service_type);

	service->has_register = false;
	memset(&service->service_template, 0, sizeof(struct service_register_template));
}

struct cqm_cmd_buf *cqm3_cmd_alloc(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;

	CQM_PTR_CHECK_RET(ex_handle, NULL, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_cmd_alloc_cnt);

	return (struct cqm_cmd_buf *)sphw_alloc_cmd_buf(ex_handle);
}

void cqm3_cmd_free(void *ex_handle, struct cqm_cmd_buf *cmd_buf)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle));
	CQM_PTR_CHECK_NO_RET(cmd_buf, CQM_PTR_NULL(cmd_buf));
	CQM_PTR_CHECK_NO_RET(cmd_buf->buf, CQM_PTR_NULL(buf));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_cmd_free_cnt);

	sphw_free_cmd_buf(ex_handle, (struct sphw_cmd_buf *)cmd_buf);
}

s32 cqm3_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, struct cqm_cmd_buf *buf_in,
		      struct cqm_cmd_buf *buf_out, u64 *out_param, u32 timeout,
		      u16 channel)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;

	CQM_PTR_CHECK_RET(ex_handle, CQM_FAIL, CQM_PTR_NULL(ex_handle));
	CQM_PTR_CHECK_RET(buf_in, CQM_FAIL, CQM_PTR_NULL(buf_in));
	CQM_PTR_CHECK_RET(buf_in->buf, CQM_FAIL, CQM_PTR_NULL(buf));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_send_cmd_box_cnt);

	return sphw_cmdq_detail_resp(ex_handle, mod, cmd,
				       (struct sphw_cmd_buf *)buf_in,
				       (struct sphw_cmd_buf *)buf_out,
				       out_param, timeout, channel);
}

int cqm_alloc_fc_db_addr(void *hwdev, void __iomem **db_base,
			 void __iomem **dwqe_base)
{
	struct sphw_hwif *hwif = NULL;
	u32 idx = 0;
#define SPFC_DB_ADDR_RSVD 12
#define SPFC_DB_MASK 128
	u64 db_base_phy_fc;

	if (!hwdev || !db_base)
		return -EINVAL;

	hwif = ((struct sphw_hwdev *)hwdev)->hwif;

	db_base_phy_fc = hwif->db_base_phy >> SPFC_DB_ADDR_RSVD;

	if (db_base_phy_fc & (SPFC_DB_MASK - 1))
		idx = SPFC_DB_MASK - (db_base_phy_fc && (SPFC_DB_MASK - 1));

	*db_base = hwif->db_base + idx * SPHW_DB_PAGE_SIZE;

	if (!dwqe_base)
		return 0;

	*dwqe_base = (u8 *)*db_base + SPHW_DWQE_OFFSET;

	return 0;
}

s32 cqm3_db_addr_alloc(void *ex_handle, void __iomem **db_addr,
		       void __iomem **dwqe_addr)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;

	CQM_PTR_CHECK_RET(ex_handle, CQM_FAIL, CQM_PTR_NULL(ex_handle));
	CQM_PTR_CHECK_RET(db_addr, CQM_FAIL, CQM_PTR_NULL(db_addr));
	CQM_PTR_CHECK_RET(dwqe_addr, CQM_FAIL, CQM_PTR_NULL(dwqe_addr));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_db_addr_alloc_cnt);

	return cqm_alloc_fc_db_addr(ex_handle, db_addr, dwqe_addr);
}

s32 cqm_db_phy_addr_alloc(void *ex_handle, u64 *db_paddr, u64 *dwqe_addr)
{
	return sphw_alloc_db_phy_addr(ex_handle, db_paddr, dwqe_addr);
}

void cqm3_db_addr_free(void *ex_handle, const void __iomem *db_addr,
		       void __iomem *dwqe_addr)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;

	CQM_PTR_CHECK_NO_RET(ex_handle, CQM_PTR_NULL(ex_handle));

	atomic_inc(&handle->hw_stats.cqm_stats.cqm_db_addr_free_cnt);

	sphw_free_db_addr(ex_handle, db_addr, dwqe_addr);
}

void cqm_db_phy_addr_free(void *ex_handle, u64 *db_paddr, u64 *dwqe_addr)
{
	sphw_free_db_phy_addr(ex_handle, *db_paddr, *dwqe_addr);
}

s32 cqm_db_init(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	s32 i;

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);

	/* Allocate hardware doorbells to services. */
	for (i = 0; i < CQM_SERVICE_T_MAX; i++) {
		service = &cqm_handle->service[i];
		if (!service->valid)
			continue;

		if (cqm3_db_addr_alloc(ex_handle, &service->hardware_db_vaddr,
				       &service->dwqe_vaddr) != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm3_db_addr_alloc));
			break;
		}

		if (cqm_db_phy_addr_alloc(handle, &service->hardware_db_paddr,
					  &service->dwqe_paddr) != CQM_SUCCESS) {
			cqm3_db_addr_free(ex_handle, service->hardware_db_vaddr,
					  service->dwqe_vaddr);
			cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm_db_phy_addr_alloc));
			break;
		}
	}

	if (i != CQM_SERVICE_T_MAX) {
		i--;
		for (; i >= 0; i--) {
			service = &cqm_handle->service[i];
			if (!service->valid)
				continue;

			cqm3_db_addr_free(ex_handle, service->hardware_db_vaddr,
					  service->dwqe_vaddr);
			cqm_db_phy_addr_free(ex_handle,
					     &service->hardware_db_paddr,
					     &service->dwqe_paddr);
		}
		return CQM_FAIL;
	}

	return CQM_SUCCESS;
}

void cqm_db_uninit(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	s32 i;

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);

	/* Release hardware doorbell. */
	for (i = 0; i < CQM_SERVICE_T_MAX; i++) {
		service = &cqm_handle->service[i];
		if (service->valid)
			cqm3_db_addr_free(ex_handle, service->hardware_db_vaddr,
					  service->dwqe_vaddr);
	}
}

s32 cqm3_ring_hardware_db_fc(void *ex_handle, u32 service_type, u8 db_count,
			     u8 pagenum, u64 db)
{
#define SPFC_DB_FAKE_VF_OFFSET 32
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	struct sphw_hwdev *handle = NULL;
	void *dbaddr = NULL;

	handle = (struct sphw_hwdev *)ex_handle;
	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	service = &cqm_handle->service[service_type];
	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	dbaddr = (u8 *)service->hardware_db_vaddr +
		 ((pagenum + SPFC_DB_FAKE_VF_OFFSET) * SPHW_DB_PAGE_SIZE);
	*((u64 *)dbaddr + db_count) = db;
	return CQM_SUCCESS;
}

s32 cqm_ring_direct_wqe_db_fc(void *ex_handle, u32 service_type,
			      void *direct_wqe)
{
	struct cqm_handle *cqm_handle = NULL;
	struct cqm_service *service = NULL;
	struct sphw_hwdev *handle = NULL;
	u64 *tmp = (u64 *)direct_wqe;
	int i;

	handle = (struct sphw_hwdev *)ex_handle;
	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	service = &cqm_handle->service[service_type];

	/* Considering the performance of ringing hardware db,
	 * the parameter is not checked.
	 */
	wmb();
	*((u64 *)service->dwqe_vaddr + 0) = tmp[2];
	*((u64 *)service->dwqe_vaddr + 1) = tmp[3];
	*((u64 *)service->dwqe_vaddr + 2) = tmp[0];
	*((u64 *)service->dwqe_vaddr + 3) = tmp[1];
	tmp += 4;

	/* The FC use 256B WQE. The directwqe is written at block0,
	 * and the length is 256B
	 */
	for (i = 4; i < 32; i++)
		*((u64 *)service->dwqe_vaddr + i) = *tmp++;

	return CQM_SUCCESS;
}

static s32 bloomfilter_init_cmd(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_handle *cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	struct cqm_func_capability *capability = &cqm_handle->func_capability;
	struct cqm_bloomfilter_init_cmd *cmd = NULL;
	struct cqm_cmd_buf *buf_in = NULL;
	s32 ret;

	buf_in = cqm3_cmd_alloc((void *)(cqm_handle->ex_handle));
	CQM_PTR_CHECK_RET(buf_in, CQM_FAIL, CQM_ALLOC_FAIL(buf_in));

	/* Fill the command format and convert it to big-endian. */
	buf_in->size = sizeof(struct cqm_bloomfilter_init_cmd);
	cmd = (struct cqm_bloomfilter_init_cmd *)(buf_in->buf);
	cmd->bloom_filter_addr = capability->bloomfilter_addr;
	cmd->bloom_filter_len = capability->bloomfilter_length;

	cqm_swab32((u8 *)cmd, (sizeof(struct cqm_bloomfilter_init_cmd) >> CQM_DW_SHIFT));

	ret = cqm3_send_cmd_box((void *)(cqm_handle->ex_handle),
				CQM_MOD_CQM, CQM_CMD_T_BLOOMFILTER_INIT, buf_in,
				NULL, NULL, CQM_CMD_TIMEOUT,
				SPHW_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm3_send_cmd_box));
		cqm_err(handle->dev_hdl, "Bloomfilter: %s ret=%d\n", __func__,
			ret);
		cqm_err(handle->dev_hdl, "Bloomfilter: %s: 0x%x 0x%x\n",
			__func__, cmd->bloom_filter_addr,
			cmd->bloom_filter_len);
		cqm3_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
		return CQM_FAIL;
	}
	cqm3_cmd_free((void *)(cqm_handle->ex_handle), buf_in);
	return CQM_SUCCESS;
}

s32 cqm_bloomfilter_init(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_bloomfilter_table *bloomfilter_table = NULL;
	struct cqm_func_capability *capability = NULL;
	struct cqm_handle *cqm_handle = NULL;
	u32 array_size;
	s32 ret;

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	bloomfilter_table = &cqm_handle->bloomfilter_table;
	capability = &cqm_handle->func_capability;

	if (capability->bloomfilter_length == 0) {
		cqm_info(handle->dev_hdl,
			 "Bloomfilter: bf_length=0, don't need to init bloomfilter\n");
		return CQM_SUCCESS;
	}

	/* The unit of bloomfilter_length is 64B(512bits). Each bit is a table
	 * node. Therefore the value must be shift 9 bits to the left.
	 */
	bloomfilter_table->table_size = capability->bloomfilter_length <<
					CQM_BF_LENGTH_UNIT;
	/* The unit of bloomfilter_length is 64B. The unit of array entryis 32B.
	 */
	array_size = capability->bloomfilter_length << 1;
	if (array_size == 0 || array_size > CQM_BF_BITARRAY_MAX) {
		cqm_err(handle->dev_hdl, CQM_WRONG_VALUE(array_size));
		return CQM_FAIL;
	}

	bloomfilter_table->array_mask = array_size - 1;
	/* This table is not a bitmap, it is the counter of corresponding bit.
	 */
	bloomfilter_table->table = vmalloc(bloomfilter_table->table_size * (sizeof(u32)));
	CQM_PTR_CHECK_RET(bloomfilter_table->table, CQM_FAIL, CQM_ALLOC_FAIL(table));

	memset(bloomfilter_table->table, 0,
	       (bloomfilter_table->table_size * sizeof(u32)));

	/* The the bloomfilter must be initialized to 0 by ucode,
	 * because the bloomfilter is mem mode
	 */
	if (cqm_handle->func_capability.bloomfilter_enable) {
		ret = bloomfilter_init_cmd(ex_handle);
		if (ret != CQM_SUCCESS) {
			cqm_err(handle->dev_hdl,
				"Bloomfilter: bloomfilter_init_cmd  ret=%d\n",
				ret);
			vfree(bloomfilter_table->table);
			bloomfilter_table->table = NULL;
			return CQM_FAIL;
		}
	}

	mutex_init(&bloomfilter_table->lock);
	return CQM_SUCCESS;
}

void cqm_bloomfilter_uninit(void *ex_handle)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_bloomfilter_table *bloomfilter_table = NULL;
	struct cqm_handle *cqm_handle = NULL;

	cqm_handle = (struct cqm_handle *)(handle->cqm_hdl);
	bloomfilter_table = &cqm_handle->bloomfilter_table;

	if (bloomfilter_table->table) {
		vfree(bloomfilter_table->table);
		bloomfilter_table->table = NULL;
	}
}

s32 cqm_bloomfilter_cmd(void *ex_handle, u32 op, u32 k_flag, u64 id)
{
	struct sphw_hwdev *handle = (struct sphw_hwdev *)ex_handle;
	struct cqm_cmd_buf *buf_in = NULL;
	struct cqm_bloomfilter_cmd *cmd = NULL;
	s32 ret;

	buf_in = cqm3_cmd_alloc(ex_handle);
	CQM_PTR_CHECK_RET(buf_in, CQM_FAIL, CQM_ALLOC_FAIL(buf_in));

	/* Fill the command format and convert it to big-endian. */
	buf_in->size = sizeof(struct cqm_bloomfilter_cmd);
	cmd = (struct cqm_bloomfilter_cmd *)(buf_in->buf);
	memset((void *)cmd, 0, sizeof(struct cqm_bloomfilter_cmd));
	cmd->k_en = k_flag;
	cmd->index_h = (u32)(id >> CQM_DW_OFFSET);
	cmd->index_l = (u32)(id & CQM_DW_MASK);

	cqm_swab32((u8 *)cmd, (sizeof(struct cqm_bloomfilter_cmd) >> CQM_DW_SHIFT));

	ret = cqm3_send_cmd_box(ex_handle, CQM_MOD_CQM, (u8)op, buf_in, NULL,
				NULL, CQM_CMD_TIMEOUT, SPHW_CHANNEL_DEFAULT);
	if (ret != CQM_SUCCESS) {
		cqm_err(handle->dev_hdl, CQM_FUNCTION_FAIL(cqm3_send_cmd_box));
		cqm_err(handle->dev_hdl, "Bloomfilter: bloomfilter_cmd ret=%d\n", ret);
		cqm_err(handle->dev_hdl, "Bloomfilter: op=0x%x, cmd: 0x%x 0x%x 0x%x 0x%x\n",
			op, *((u32 *)cmd), *(((u32 *)cmd) + CQM_DW_INDEX1),
			*(((u32 *)cmd) + CQM_DW_INDEX2),
			*(((u32 *)cmd) + CQM_DW_INDEX3));
		cqm3_cmd_free(ex_handle, buf_in);
		return CQM_FAIL;
	}

	cqm3_cmd_free(ex_handle, buf_in);

	return CQM_SUCCESS;
}
