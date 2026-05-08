// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_srq_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_srq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"

#define SXE2_DRV_SRQ_DEBUGFS_HEX (16)

enum {
	SRQ_PD,
	SRQ_LOG_SRQ_SIZE,
	SRQ_STATE,
	SRQ_ACCESS_MODE,
	SRQ_LOG_PAGE_SIZE,
	SRQ_DBR_ADDR,
	SRQ_CPML_CTX,
	SRQ_PBL_POINTER,
	SRQ_LWM,
	SRQ_LOG_RQ_STRIDE,
	SRQ_PAGE_OFFSET,
};

#ifdef SXE2_CFG_DEBUG
static char *srq_fields[] = {
	[SRQ_PD]	    = "pd",
	[SRQ_LOG_SRQ_SIZE]  = "log_srq_size",
	[SRQ_STATE]	    = "state",
	[SRQ_ACCESS_MODE]   = "srq_access_mode",
	[SRQ_LOG_PAGE_SIZE] = "log_page_size",
	[SRQ_DBR_ADDR]	    = "dbr_addr",
	[SRQ_CPML_CTX]	    = "srq_completion_context",
	[SRQ_PBL_POINTER]   = "srq_pbl_pointer",
	[SRQ_LWM]	    = "srq_lwm",
	[SRQ_LOG_RQ_STRIDE] = "log_rq_stride",
	[SRQ_PAGE_OFFSET]   = "page_offset",
};

static int drv_rdma_srq_opcode_switch(size_t i, u64 temp_value,
				      struct sxe2_rdma_srqc *srqc)
{
	int ret = 0;

	switch (i) {
	case SRQ_PD:
		srqc->ssrqc.pd = (u32)temp_value;
		break;
	case SRQ_LOG_SRQ_SIZE:
		srqc->ssrqc.log_srq_size = (u32)temp_value;
		break;
	case SRQ_STATE:
		srqc->ssrqc.state = (u32)temp_value;
		break;
	case SRQ_ACCESS_MODE:
		srqc->ssrqc.srq_access_mode = (u32)temp_value;
		break;
	case SRQ_LOG_PAGE_SIZE:
		srqc->ssrqc.log_page_size = (u32)temp_value;
		break;
	case SRQ_DBR_ADDR:
		srqc->ssrqc.dbr_addr = temp_value;
		break;
	case SRQ_CPML_CTX:
		srqc->ssrqc.SRQ_Completion_Context = temp_value;
		break;
	case SRQ_PBL_POINTER:
		srqc->ssrqc.srq_pbl_pointer = temp_value;
		break;
	case SRQ_LWM:
		srqc->ssrqc.lwm = (u32)temp_value;
		break;
	case SRQ_LOG_RQ_STRIDE:
		srqc->ssrqc.log_rq_stride = (u32)temp_value;
		break;
	case SRQ_PAGE_OFFSET:
		srqc->ssrqc.page_offset = (u32)temp_value;
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_WARN("invalid index %zu, ret %d\n", i, ret);
	}

	return ret;
}
#endif

static u64 drv_rdma_srq_read_field(struct sxe2_rdma_device *rdma_dev,
				   void *data, enum drv_rdma_dbg_rsc_type type,
				   char *buf)
{
	int ret = 0;
	struct sxe2_rdma_srqc *srqc;
	struct sxe2_rdma_srq *srq;
	struct sxe2_rdma_dma_mem query_srq = {};
	struct sxe2_rdma_ctx_dev *dev_ctx;
	size_t len = 0;

	if (!rdma_dev || !data) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"SRQ DEBUGFS:RDMA Dev/Data is NULL, ret %d\n", ret);
		goto end;
	}

	if (type == SXE2_DBG_RSC_SRQ) {
		srq = (struct sxe2_rdma_srq *)data;
	} else {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:RSC %d err, expected %d, ret %d\n", type,
			SXE2_DBG_RSC_SRQ, ret);
		goto end;
	}

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);

	query_srq.size = sizeof(struct sxe2_rdma_srqc);
	query_srq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_srq.size,
						&query_srq.pa, GFP_KERNEL);
	if (!query_srq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:query srq ctx alloc failed. ret %d\n",
			ret);
		goto end;
	}
	memset(query_srq.va, 0, query_srq.size);

	ret = sxe2_kquery_srq_mq_cmd(rdma_dev->rdma_func, &srq->srq_ctx,
					 (u64)query_srq.pa);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:Query SRQ --mq cmd failed, ret %d\n", ret);
		goto free_srqc;
	}

	srqc = (struct sxe2_rdma_srqc *)query_srq.va;

	len += dbg_vsnprintf(buf, len, "SRQ:%d Context:\n\n", srq->srq_id);
	len += dbg_vsnprintf(buf, len, "Soft Context\n");
	len += dbg_vsnprintf(buf, len,
				 "pd:					%#x\n",
				 srqc->ssrqc.pd);
	len += dbg_vsnprintf(buf, len, "log_srq_size:		%#x\n",
				 srqc->ssrqc.log_srq_size);
	len += dbg_vsnprintf(buf, len, "state:				%#x\n",
				 srqc->ssrqc.state);
	len += dbg_vsnprintf(buf, len, "srq_access_mode:	%#x\n",
				 srqc->ssrqc.srq_access_mode);
	len += dbg_vsnprintf(buf, len, "log_page_size:		%#x\n",
				 srqc->ssrqc.log_page_size);
	len += dbg_vsnprintf(buf, len,
				 "dbr_addr:		%#llx\n",
				 srqc->ssrqc.dbr_addr);
	len += dbg_vsnprintf(buf, len, "SRQ_Completion_Context: %#llx\n",
				 srqc->ssrqc.SRQ_Completion_Context);
	len += dbg_vsnprintf(buf, len,
				 "dbr_addr:		%#llx\n",
				 srqc->ssrqc.srq_pbl_pointer);
	len += dbg_vsnprintf(buf, len, "lwm:				%#x\n",
				 srqc->ssrqc.lwm);
	len += dbg_vsnprintf(buf, len, "log_rq_stride:		%#x\n",
				 srqc->ssrqc.log_rq_stride);
	len += dbg_vsnprintf(buf, len, "page_offset:		%#x\n",
				 srqc->ssrqc.page_offset);

	len += dbg_vsnprintf(buf, len, "Hardware Context\n");
	len += dbg_vsnprintf(buf, len, "state_err_aeq_flag: %#x\n",
				 srqc->hsrqc.state_err_aeq_flag);
	len += dbg_vsnprintf(buf, len, "sw_srq_counter:		%#x\n",
				 srqc->hsrqc.sw_srq_counter);
	len += dbg_vsnprintf(buf, len, "hw_srq_counter:		%#x\n",
				 srqc->hsrqc.hw_srq_counter);
	len += dbg_vsnprintf(buf, len, "srq_page_pa_sel:	%#x\n",
				 srqc->hsrqc.srq_page_pa_sel);
	len += dbg_vsnprintf(buf, len, "srq_page_pa_vld:	%#x\n",
				 srqc->hsrqc.srq_page_pa_vld);
	len += dbg_vsnprintf(buf, len, "srq_wqe_vld:		%#x\n",
				 srqc->hsrqc.srq_wqe_vld);
	len += dbg_vsnprintf(buf, len, "srq_page_pa0:		%#x\n",
				 srqc->hsrqc.srq_page_pa0);
	len += dbg_vsnprintf(buf, len, "srq_page_pa1:		%#x\n",
				 srqc->hsrqc.srq_page_pa1);

free_srqc:
	dma_free_coherent(dev_ctx->hw->device, query_srq.size, query_srq.va,
			  query_srq.pa);
	query_srq.va = NULL;
end:
	return len;
}

static int drv_rdma_srq_write_field(struct sxe2_rdma_device *rdma_dev,
				    void *data, enum drv_rdma_dbg_rsc_type type,
				    char *buf)
{
#ifdef SXE2_CFG_DEBUG
	size_t i;
	int ret = 0;
	u64 temp_value;
	struct sxe2_rdma_srqc *srqc;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_srq *srq;
	struct sxe2_rdma_dma_mem query_srq = {};
	struct sxe2_rdma_ctx_dev *dev_ctx;

	if (!rdma_dev || !data) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"SRQ DEBUGFS:RDMA Dev/Data is NULL, ret %d\n", ret);
		goto end;
	}

	if (type == SXE2_DBG_RSC_SRQ) {
		srq = (struct sxe2_rdma_srq *)data;
	} else {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:RSC %d err, expected %d, ret %d\n", type,
			SXE2_DBG_RSC_SRQ, ret);
		goto end;
	}

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);

	query_srq.size = sizeof(struct sxe2_rdma_srqc);
	query_srq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_srq.size,
					    &query_srq.pa, GFP_KERNEL);
	if (!query_srq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:query srq ctx alloc failed. ret:%d\n",
			ret);
		goto end;
	}
	memset(query_srq.va, 0, query_srq.size);

	ret = sxe2_kquery_srq_mq_cmd(rdma_dev->rdma_func, &srq->srq_ctx,
				     (u64)query_srq.pa);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:Query SRQ --mq cmd failed, ret %d\n", ret);
		goto free_srqc;
	}

	srqc = (struct sxe2_rdma_srqc *)query_srq.va;

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(buf, &argc, argv);
	if (ret)
		goto free_srqc;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("SRQ DEBUGFS:invalid param nums\n");
		goto free_srqc;
	}

	for (i = 0; i < ARRAY_SIZE(srq_fields); i++) {
		if (!strncmp(argv[0], srq_fields[i], strlen(srq_fields[i])) &&
		    (strlen(srq_fields[i]) == strlen(argv[0]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], SXE2_DRV_SRQ_DEBUGFS_HEX, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:get param value failed, ret (%d)\n", ret);
		goto free_srqc;
	}

	DRV_RDMA_LOG_DEV_INFO("SRQ DEBUGFS:query srq i:%zu, temp_value:%llx\n",
			      i, temp_value);

	ret = drv_rdma_srq_opcode_switch(i, temp_value, srqc);
	if (ret)
		goto free_srqc;

	ret = sxe2_kmodify_srq_mq_cmd(rdma_dev->rdma_func, &srq->srq_ctx, srqc);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:Modify SRQ --mq cmd failed, ret %d\n",
			ret);
	}

free_srqc:
	dma_free_coherent(dev_ctx->hw->device, query_srq.size, query_srq.va,
			  query_srq.pa);
	query_srq.va = NULL;
end:
	return ret;
#else
	return 0;
#endif
}

int drv_rdma_debug_srq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_srq *srq)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:debugfs root dir not exist, ret (%d)\n",
			ret);
		goto end;
	}

	if (!rdma_dev->hdl->srq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:srq debugfs dir not exist, ret (%d)\n",
			ret);
		goto end;
	}

	srq->dbg_node = drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_SRQ,
					      rdma_dev->hdl->srq_debugfs,
					      drv_rdma_srq_read_field,
					      drv_rdma_srq_write_field,
					      (int)srq->srq_id, srq);
	if (!srq->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:srq debug res tree add failed ret (%d)\n",
			ret);
	}

end:
	return ret;
}

void drv_rdma_debug_srq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_srq *srq)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR(
			"SRQ DEBUGFS:debugfs root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->srq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("SRQ DEBUGFS:srq debugfs dir not exist\n");
		goto end;
	}

	if (srq->dbg_node) {
		drv_rdma_rm_res_tree(srq->dbg_node);
		srq->dbg_node = NULL;
	}

end:
	return;
}
