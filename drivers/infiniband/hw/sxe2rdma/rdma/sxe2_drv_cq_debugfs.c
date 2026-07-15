// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cq_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_cq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_cq_debugfs.h"

enum {
	CQ_EQ_NUM,
	CQ_LOG_DBR_SIZE,
	CQ_LOG_CQ_SIZE,
	CQ_BRK_MODERATION_EN,
	CQ_OI,
	CQ_OWNER_BIT,
	CQ_STATUS,
	CQ_LOG_PG_SZ,
	CQ_PAGE_OFFSET,
	CQ_PBL_MODE,
	CQ_TPH_VALUE,
	CQ_MAX_CNT,
	CQ_PERIOD,
	CQ_TPH_EN,
	CQ_VSI_INDEX,
	CQ_DBR_ADDR,
	CQ_PBL_INDEX,
};

#ifdef SXE2_CFG_DEBUG
static char *cq_fields[] = {
	[CQ_EQ_NUM]	       = "c_eqn",
	[CQ_LOG_DBR_SIZE]      = "log_doorbell_size",
	[CQ_LOG_CQ_SIZE]       = "log_cq_size",
	[CQ_BRK_MODERATION_EN] = "sceq_break_moderation_en",
	[CQ_OI]		       = "oi",
	[CQ_OWNER_BIT]	       = "owner_bit",
	[CQ_STATUS]	       = "sw_status",
	[CQ_LOG_PG_SZ]	       = "log_page_size",
	[CQ_PAGE_OFFSET]       = "page_offset",
	[CQ_PBL_MODE]	       = "pbl_mode",
	[CQ_TPH_VALUE]	       = "TPH_value",
	[CQ_MAX_CNT]	       = "cq_max_count",
	[CQ_PERIOD]	       = "cq_period",
	[CQ_TPH_EN]	       = "TPH_en",
	[CQ_VSI_INDEX]	       = "vsi_index",
	[CQ_DBR_ADDR]	       = "doorbell_addr",
	[CQ_PBL_INDEX]	       = "pbl_index",
};
#endif
u64 drv_rdma_cq_read_field(struct sxe2_rdma_device *rdma_dev, void *data,
			   enum drv_rdma_dbg_rsc_type type, char *buf)
{
	int ret;
	struct sxe2_rdma_cqc *ctx;
	struct sxe2_rdma_mcq *mcq;
	struct sxe2_rdma_cq *cq;
	size_t len			= 0;
	u32 cq_num			= 0;
	struct sxe2_rdma_ctx_cq *cq_ctx = NULL;
	struct sxe2_rdma_dma_mem query_cq;
	struct sxe2_rdma_ctx_dev *dev_ctx;

	if (type == SXE2_DBG_RSC_MCQ) {
		mcq    = (struct sxe2_rdma_mcq *)data;
		cq_num = 0;
		cq_ctx = &mcq->ctx_cq;
	} else if (type == SXE2_DBG_RSC_CQ) {
		cq     = (struct sxe2_rdma_cq *)data;
		cq_num = cq->cq_num;
		cq_ctx = &cq->cq_ctx;
	}

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);

	memset(&query_cq, 0, sizeof(query_cq));
	query_cq.size = sizeof(struct sxe2_rdma_cqc);
	query_cq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_cq.size,
					   &query_cq.pa, GFP_KERNEL);
	if (!query_cq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query cq ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}
	memset(query_cq.va, 0, query_cq.size);

	ret = sxe2_drv_cq_query_op(rdma_dev, cq_ctx, query_cq.pa);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query cq failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	ctx = (struct sxe2_rdma_cqc *)query_cq.va;

	len += dbg_vsnprintf(buf, len, "cq:%d context:\n\n", cq_num);
	len += dbg_vsnprintf(buf, len, "soft context\n");
	len += dbg_vsnprintf(buf, len, "eqn:                      %lld\n",
			     ctx->scqc.eqn);
	len += dbg_vsnprintf(buf, len, "log_doorbell_size:        %lld\n",
			     ctx->scqc.log_dbr_size);
	len += dbg_vsnprintf(buf, len, "log_cq_size:              %lld\n",
			     ctx->scqc.log_cq_size);
	len += dbg_vsnprintf(buf, len, "scqe_break_moderation_en: %lld\n",
			     ctx->scqc.scqe_break_moderation_en);
	len += dbg_vsnprintf(buf, len, "oi:                       %lld\n",
			     ctx->scqc.oi);
	len += dbg_vsnprintf(buf, len, "sw_owner_bit:             %d\n",
			     ctx->scqc.sw_owner_bit);
	len += dbg_vsnprintf(buf, len, "sw_status:                %d\n",
			     ctx->scqc.sw_status);
	len += dbg_vsnprintf(buf, len, "log_page_size:            %d\n",
			     ctx->scqc.log_page_size);
	len += dbg_vsnprintf(buf, len, "page_offset:              %d\n",
			     ctx->scqc.page_offset);
	len += dbg_vsnprintf(buf, len, "pbl_mode:                 %d\n",
			     ctx->scqc.pbl_mode);
	len += dbg_vsnprintf(buf, len, "TPH_value:                %d\n",
			     ctx->scqc.TPH_value);
	len += dbg_vsnprintf(buf, len, "cq_max_count:             %d\n",
			     ctx->scqc.cq_max_count);
	len += dbg_vsnprintf(buf, len, "cq_period:                %d\n",
			     ctx->scqc.cq_period);
	len += dbg_vsnprintf(buf, len, "TPH_en:                   %d\n",
			     ctx->scqc.TPH_en);
	len += dbg_vsnprintf(buf, len, "vsi_index:                %d\n",
			     ctx->scqc.vsi_index);
	len += dbg_vsnprintf(buf, len, "doorbell_addr:            %llx\n",
			     ctx->scqc.dbr_addr);
	len += dbg_vsnprintf(buf, len, "pbl_index:                %llx\n\n",
			     ctx->scqc.pbl_index);

	len += dbg_vsnprintf(buf, len, "hw context\n");
	len += dbg_vsnprintf(buf, len, "hw_owner_bit:             %d\n",
			     ctx->hcqc.hw_owner_bit);
	len += dbg_vsnprintf(buf, len, "st:                       %d\n",
			     ctx->hcqc.st);
	len += dbg_vsnprintf(buf, len, "cmd:                      %d\n",
			     ctx->hcqc.cmd);
	len += dbg_vsnprintf(buf, len, "cmd_sn:                   %d\n",
			     ctx->hcqc.cmd_sn);
	len += dbg_vsnprintf(buf, len, "hw_status:                %d\n",
			     ctx->hcqc.hw_status);
	len += dbg_vsnprintf(buf, len, "last_sol_index_en:        %d\n",
			     ctx->hcqc.last_sol_index_en);
	len += dbg_vsnprintf(buf, len, "fid:                      %d\n",
			     ctx->hcqc.fid);
	len += dbg_vsnprintf(buf, len, "hw_eqn:                   %d\n",
			     ctx->hcqc.hw_eqn);
	len += dbg_vsnprintf(buf, len, "last_notified_index:      %d\n",
			     ctx->hcqc.last_notified_index);
	len += dbg_vsnprintf(buf, len, "last_solicited_index_l:   %d\n",
			     ctx->hcqc.last_solicited_index_l);
	len += dbg_vsnprintf(buf, len, "last_solicited_index_h:   %d\n",
			     ctx->hcqc.last_solicited_index_h);
	len += dbg_vsnprintf(buf, len, "consumer_counter_l:       %d\n",
			     ctx->hcqc.consumer_counter_l);
	len += dbg_vsnprintf(buf, len, "consumer_counter_h:       %d\n",
			     ctx->hcqc.consumer_counter_h);
	len += dbg_vsnprintf(buf, len, "producer_counter:         %d\n",
			     ctx->hcqc.producer_counter);
	len += dbg_vsnprintf(buf, len, "page_addr_odd_l:          %#x\n",
			     ctx->hcqc.page_addr_odd_l);
	len += dbg_vsnprintf(buf, len, "page_addr_odd_h:          %#x\n",
			     ctx->hcqc.page_addr_odd_h);
	len += dbg_vsnprintf(buf, len, "page_addr_even_l:         %#x\n",
			     ctx->hcqc.page_addr_even_l);
	len += dbg_vsnprintf(buf, len, "page_addr_even_h:         %#x\n",
			     ctx->hcqc.page_addr_even_h);
free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_cq.size, query_cq.va,
			  query_cq.pa);
	query_cq.va = NULL;

end:
	return len;
}

#ifdef SXE2_CFG_DEBUG
static int drv_rdma_cq_ctx_modify(struct sxe2_rdma_cqc *ctx, size_t field,
				  u64 value)
{
	int ret = 0;

	switch (field) {
	case CQ_EQ_NUM:
		ctx->scqc.eqn = value;
		break;
	case CQ_LOG_DBR_SIZE:
		ctx->scqc.log_dbr_size = value;
		break;
	case CQ_LOG_CQ_SIZE:
		ctx->scqc.log_cq_size = value;
		break;
	case CQ_BRK_MODERATION_EN:
		ctx->scqc.scqe_break_moderation_en = value;
		break;
	case CQ_OI:
		ctx->scqc.oi = value;
		break;
	case CQ_OWNER_BIT:
		ctx->scqc.sw_owner_bit = value;
		break;
	case CQ_STATUS:
		ctx->scqc.sw_status = value;
		break;
	case CQ_LOG_PG_SZ:
		ctx->scqc.log_page_size = value;
		break;
	case CQ_PAGE_OFFSET:
		ctx->scqc.page_offset = value;
		break;
	case CQ_PBL_MODE:
		ctx->scqc.pbl_mode = value;
		break;
	case CQ_TPH_VALUE:
		ctx->scqc.TPH_value = value;
		break;
	case CQ_MAX_CNT:
		ctx->scqc.cq_max_count = value;
		break;
	case CQ_PERIOD:
		ctx->scqc.cq_period = value;
		break;
	case CQ_TPH_EN:
		ctx->scqc.TPH_en = value;
		break;
	case CQ_VSI_INDEX:
		ctx->scqc.vsi_index = value;
		break;
	case CQ_DBR_ADDR:
		ctx->scqc.dbr_addr = value;
		break;
	case CQ_PBL_INDEX:
		ctx->scqc.pbl_index = value;
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_WARN("invalid index %d, ret %ld\n", field, ret);
	}

	return ret;
}
#endif
int drv_rdma_cq_write_field(struct sxe2_rdma_device *rdma_dev, void *data,
			    enum drv_rdma_dbg_rsc_type type, char *buf)
{
#ifdef SXE2_CFG_DEBUG
	size_t i;
	int ret;
	u64 temp_value;
	struct sxe2_rdma_cqc *ctx;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_mcq *mcq;
	struct sxe2_rdma_cq *cq;
	struct sxe2_rdma_ctx_cq *cq_ctx = NULL;
	struct sxe2_rdma_dma_mem query_cq;
	struct sxe2_rdma_ctx_dev *dev_ctx;

	if (type == SXE2_DBG_RSC_MCQ) {
		mcq    = (struct sxe2_rdma_mcq *)data;
		cq_ctx = &mcq->ctx_cq;
	} else if (type == SXE2_DBG_RSC_CQ) {
		cq     = (struct sxe2_rdma_cq *)data;
		cq_ctx = &cq->cq_ctx;
	}

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);
	memset(&query_cq, 0, sizeof(query_cq));
	query_cq.size = sizeof(struct sxe2_rdma_cqc);
	query_cq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_cq.size,
					   &query_cq.pa, GFP_KERNEL);
	if (!query_cq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query cq ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}
	memset(query_cq.va, 0, query_cq.size);

	ret = sxe2_drv_cq_query_op(rdma_dev, cq_ctx, query_cq.pa);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query cq failed, ret (%d)\n", ret);
		goto free_ctx;
	}
	ctx = (struct sxe2_rdma_cqc *)query_cq.va;

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(buf, &argc, argv);
	if (ret)
		goto free_ctx;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param nums\n");
		goto free_ctx;
	}

	for (i = 0; i < ARRAY_SIZE(cq_fields); i++) {
		if (!strncmp(argv[0], cq_fields[i], strlen(cq_fields[i])) &&
		    (strlen(cq_fields[i]) == strlen(argv[0])))
			break;
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	DRV_RDMA_LOG_DEV_INFO("query cq i:%ld, temp_value:%llx\n", i,
			      temp_value);

	ret = drv_rdma_cq_ctx_modify(ctx, i, temp_value);
	if (ret)
		goto free_ctx;

	ret = sxe2_drv_cq_modify_op(rdma_dev, cq_ctx, ctx);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("modify cq ctx:%s failed, ret (%d)\n",
				     argv[0], ret);

free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_cq.size, query_cq.va,
			  query_cq.pa);
	query_cq.va = NULL;

end:
	return ret;
#else
	return 0;
#endif
}

int drv_rdma_debug_cq_add(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_cq *cq)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->cq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("cq debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	cq->dbg_node =
		drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_CQ,
				      rdma_dev->hdl->cq_debugfs,
				      drv_rdma_cq_read_field,
				      drv_rdma_cq_write_field, cq->cq_num, cq);
	if (!cq->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
	}

end:
	return ret;
}

void drv_rdma_debug_cq_remove(struct sxe2_rdma_device *rdma_dev,
			      struct sxe2_rdma_cq *cq)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->cq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("cq debugfs dir not exist\n");
		goto end;
	}

	if (cq->dbg_node) {
		drv_rdma_rm_res_tree(cq->dbg_node);
		cq->dbg_node = NULL;
	}

end:
	return;
}

int drv_rdma_debug_mcq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_mcq *mcq)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->cq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("mcq debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	mcq->dbg_node = drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_MCQ,
					      rdma_dev->hdl->cq_debugfs,
					      drv_rdma_cq_read_field,
					      drv_rdma_cq_write_field, 0, mcq);
	if (!mcq->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
	}

end:
	return ret;
}

void drv_rdma_debug_mcq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_mcq *mcq)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->cq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("cq debugfs dir not exist\n");
		goto end;
	}

	if (mcq->dbg_node) {
		drv_rdma_rm_res_tree(mcq->dbg_node);
		mcq->dbg_node = NULL;
	}

end:
	return;
}

