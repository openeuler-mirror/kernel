// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mr_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rcms_debugfs.h"
#include "sxe2_drv_mr_debugfs.h"

enum { MR_KEY, MR_PD, MR_ACCESS_RIGHT };

#ifdef SXE2_CFG_DEBUG
static char *mr_fields[] = {
	[MR_KEY]	  = "mr_key",
	[MR_PD]		  = "pd",
	[MR_ACCESS_RIGHT] = "access_right"
};
#endif
static int sxe2_drv_mr_query_op(struct sxe2_rdma_device *rdma_dev, u32 mr_index,
				dma_addr_t pa)
{
	int ret;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("get mq_request failed, ret (%d)\n", ret);
		goto end;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_query",
		     &rdma_dev->rdma_func->mq.err_cqe_val, &mr_index);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_query");
#endif

	mq_info					   = &mq_request->info;
	mq_info->mq_cmd				   = MQ_OP_QUERY_MR;
	mq_info->post_mq			   = 1;
	mq_info->in.u.query_mr.ctx_dev		   = &rdma_func->ctx_dev;
	mq_info->in.u.query_mr.scratch		   = (uintptr_t)mq_request;
	mq_info->in.u.query_mr.info.field.buf_addr = pa;
	mq_info->in.u.query_mr.info.field.mr_index = mr_index;

	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);
	if (ret != 0)
		DRV_RDMA_LOG_DEV_ERR("handle query mr failed, ret (%d)\n", ret);

end:
	return ret;
}

static u64 sxe2_debugfs_mr_read(struct sxe2_rdma_device *rdma_dev, void *data,
				enum drv_rdma_dbg_rsc_type type, char *buf)
{
	int ret;
	int i;
	union sxe2_hw_mrc *mr_ctx;
	struct sxe2_mr *vendor_mr;
	size_t len = 0;
	u32 mr_index;
	struct sxe2_rdma_dma_mem query_mr;
	struct sxe2_rdma_ctx_dev *dev_ctx;

	vendor_mr = (struct sxe2_mr *)data;
	mr_index  = vendor_mr->stag >> SXE2_CQPSQ_STAG_IDX_S;

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);

	memset(&query_mr, 0, sizeof(query_mr));
	query_mr.size = sizeof(union sxe2_hw_mrc);
	query_mr.va   = dma_alloc_coherent(dev_ctx->hw->device, query_mr.size,
					   &query_mr.pa, GFP_KERNEL);
	if (!query_mr.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query mr ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}

	ret = sxe2_drv_mr_query_op(rdma_dev, mr_index, query_mr.pa);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query mr failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	mr_ctx = (union sxe2_hw_mrc *)query_mr.va;
	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++)
		mr_ctx->buf[i] = le64_to_cpu(mr_ctx->buf[i]);

	len += dbg_vsnprintf(buf, len, "MRINFO:%u\n", mr_index);
	len += dbg_vsnprintf(buf, len,
			     "----------------------------------------\n");
	len += dbg_vsnprintf(buf, len, "pbl_mode:           %d\n",
			     mr_ctx->field.pbl_mode);
	len += dbg_vsnprintf(buf, len, "access_rights:      %d\n",
			     mr_ctx->field.access_rights);
	len += dbg_vsnprintf(buf, len, "va_based_flag:      %d\n",
			     mr_ctx->field.va_based_flag);
	len += dbg_vsnprintf(buf, len, "mw_type:            %d\n",
			     mr_ctx->field.mw_type);
	len += dbg_vsnprintf(buf, len, "access_mode:        %d\n",
			     mr_ctx->field.access_mode);
	len += dbg_vsnprintf(buf, len, "mrct_type:          %d\n",
			     mr_ctx->field.mrct_type);
	len += dbg_vsnprintf(buf, len, "free:               %d\n",
			     mr_ctx->field.free);
	len += dbg_vsnprintf(buf, len, "mr_key:             %d\n",
			     mr_ctx->field.mr_key);
	len += dbg_vsnprintf(buf, len, "qpn:                %d\n",
			     mr_ctx->field.qpn);
	len += dbg_vsnprintf(buf, len, "mw_bind_num:        %d\n",
			     mr_ctx->field.mw_bind_num);
	len += dbg_vsnprintf(buf, len, "pd:                 %d\n",
			     mr_ctx->field.pd);
	len += dbg_vsnprintf(buf, len, "is_len64:           %d\n",
			     mr_ctx->field.is_len64);
	len += dbg_vsnprintf(buf, len, "start_addr:         %#llx\n",
			     mr_ctx->field.start_addr);
	len += dbg_vsnprintf(buf, len, "len:                %llu\n",
			     mr_ctx->field.len);
	len += dbg_vsnprintf(buf, len, "parent_mr_stag:     %u\n",
			     mr_ctx->field.parent_mr_stag);
	len += dbg_vsnprintf(buf, len, "ref_tag:            %u\n",
			     mr_ctx->field.ref_tag);
	len += dbg_vsnprintf(buf, len, "dif_pbl_index:      %#llx\n",
			     (u64)mr_ctx->field.dif_pbl_index);
	len += dbg_vsnprintf(buf, len, "dif_offset:         %u\n",
			     mr_ctx->field.dif_offset);
	len += dbg_vsnprintf(buf, len, "data_offset:        %u\n",
			     mr_ctx->field.data_offset);
	len += dbg_vsnprintf(buf, len, "sge_type:           %d\n",
			     mr_ctx->field.sge_type);
	len += dbg_vsnprintf(buf, len, "pbl_index:          %#llx\n",
			     (u64)mr_ctx->field.pbl_index);
	len += dbg_vsnprintf(buf, len, "log_entity_size:    %d\n",
			     mr_ctx->field.log_entity_size);
	len += dbg_vsnprintf(buf, len, "pfvf_id:            %d\n",
			     mr_ctx->field.pfvf_id);
	len += dbg_vsnprintf(buf, len, "app_tag:            %d\n",
			     mr_ctx->field.app_tag);
	len += dbg_vsnprintf(buf, len, "dif_mode:           %d\n",
			     mr_ctx->field.dif_mode);
	len += dbg_vsnprintf(buf, len, "block_size:         %d\n",
			     mr_ctx->field.block_size);
	len += dbg_vsnprintf(buf, len,
			     "----------------------------------------\n");

free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_mr.size, query_mr.va,
			  query_mr.pa);
	query_mr.va = NULL;

end:
	return len;
}

#ifdef SXE2_CFG_DEBUG

static int sxe2_mr_ctx_modify(union sxe2_hw_mrc *mr_ctx, int field, u64 value)
{
	int ret = 0;

	switch (field) {
	case MR_KEY:
		mr_ctx->field.mr_key = value;
		break;
	case MR_PD:
		mr_ctx->field.pd = value;
		break;
	case MR_ACCESS_RIGHT:
		mr_ctx->field.access_rights = value;
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_WARN("invalid index %d, ret %d\n", field, ret);
	}

	return ret;
}
#endif
static int sxe2_debugfs_mr_write(struct sxe2_rdma_device *rdma_dev, void *data,
				 enum drv_rdma_dbg_rsc_type type, char *buf)
{
#ifdef SXE2_CFG_DEBUG
	u32 i;
	int ret;
	int argc;
	u64 new_value;
	u32 mr_index;
	union sxe2_hw_mrc *mr_ctx;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_mr *vendor_mr	 = (struct sxe2_mr *)data;
	struct sxe2_rdma_dma_mem query_mr;
	struct sxe2_rdma_ctx_dev *dev_ctx;
	void *va_addr;
	bool find_field = false;

	mr_index = vendor_mr->stag >> SXE2_CQPSQ_STAG_IDX_S;
	dev_ctx	 = &(rdma_dev->rdma_func->ctx_dev);
	memset(&query_mr, 0, sizeof(query_mr));
	query_mr.size = sizeof(union sxe2_hw_mrc);
	query_mr.va   = dma_alloc_coherent(dev_ctx->hw->device, query_mr.size,
					   &query_mr.pa, GFP_KERNEL);
	if (!query_mr.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query mr ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}

	ret = sxe2_drv_mr_query_op(rdma_dev, mr_index, query_mr.pa);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query mr failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	mr_ctx = (union sxe2_hw_mrc *)query_mr.va;
	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++)
		mr_ctx->buf[i] = le64_to_cpu(mr_ctx->buf[i]);

	argc = 0;
	memset(argv, 0, sizeof(*argv) * DEBUG_ARGV_COUNT_MAX);
	ret = split_command(buf, &argc, argv);
	if (ret)
		goto free_ctx;

	DRV_RDMA_LOG_DEV_DEBUG("argv:%s\n", argv[0]);

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param nums\n");
		goto free_ctx;
	}

	for (i = 0; i < ARRAY_SIZE(mr_fields); i++) {
		if (!strncmp(argv[0], mr_fields[i], strlen(mr_fields[i])) &&
		    (strlen(mr_fields[i]) == strlen(argv[0]))) {
			find_field = true;
			break;
		}
	}
	if (!find_field) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("unsupport change mr field %s\n", argv[0]);
		goto free_ctx;
	}

	ret = kstrtoull(argv[1], 10, &new_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	DRV_RDMA_LOG_DEV_INFO("modify mr field %s new value %llx\n",
			      mr_fields[i], new_value);

	if (sxe2_mr_ctx_modify(mr_ctx, i, new_value))
		goto free_ctx;

	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++)
		mr_ctx->buf[i] = cpu_to_le64(mr_ctx->buf[i]);

	ret = sxe2_rcms_num_to_ctx_va_pointer(rdma_dev, SXE2_RCMS_OBJ_MR,
					      mr_index, &va_addr);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("query mr va addr failed, ret (%d)\n",
				     ret);
		goto end;
	}
	memcpy(va_addr, mr_ctx, sizeof(*mr_ctx));

free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_mr.size, query_mr.va,
			  query_mr.pa);
	query_mr.va = NULL;
end:
	return ret;
#else
	return 0;
#endif
}

int sxe2_debbugfs_mr_add(struct sxe2_rdma_device *rdma_dev,
			 struct sxe2_mr *vendor_mr)
{
	int ret = 0;
	u32 mr_idx;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->mr_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("mr debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	mr_idx = vendor_mr->stag >> SXE2_CQPSQ_STAG_IDX_S;

	vendor_mr->dbg_node = drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_MR,
						    rdma_dev->hdl->mr_debugfs,
						    sxe2_debugfs_mr_read,
						    sxe2_debugfs_mr_write,
						    (int)mr_idx, vendor_mr);
	if (!vendor_mr->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
	}

end:
	return ret;
}

void sxe2_debugfs_mr_remove(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_mr *vendor_mr)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->mr_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("mr debugfs dir not exist\n");
		goto end;
	}

	if (vendor_mr->dbg_node) {
		drv_rdma_rm_res_tree(vendor_mr->dbg_node);
		vendor_mr->dbg_node = NULL;
	}

end:
	return;
}

