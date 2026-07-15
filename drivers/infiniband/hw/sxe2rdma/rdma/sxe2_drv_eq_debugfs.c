// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_eq_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include "sxe2_compat.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_drv_eq.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_eq_debugfs.h"

#define INJECT_CMD_LEN		 32
#define IN_CMD_LEN		     64
#define ALIVE                0x7fffffff
enum {
	EQ_OI,
	EQ_VSI_INDEX,
	EQ_OWNER_BIT,
	EQ_STATUS,
	EQ_UAR_PAGE,
	EQ_LOG_EQ_SIZE,
	EQ_PBL_MODE,
	EQ_TPH_EN,
	EQ_TPH_VALUE,
	EQ_PAGE_OFFSET,
	EQ_LOG_PG_SZ,
	EQ_PBL_INDEX,
};

#ifdef SXE2_CFG_DEBUG
static char *eq_fields[] = {
	[EQ_OI]		 = "oi",
	[EQ_VSI_INDEX]	 = "vsi_index",
	[EQ_OWNER_BIT]	 = "owner_bit",
	[EQ_STATUS]	 = "sw_status",
	[EQ_UAR_PAGE]	 = "uar_page",
	[EQ_LOG_EQ_SIZE] = "log_eq_size",
	[EQ_PBL_MODE]	 = "pbl_mode",
	[EQ_TPH_EN]	 = "TPH_en",
	[EQ_TPH_VALUE]	 = "TPH_value",
	[EQ_PAGE_OFFSET] = "page_offset",
	[EQ_LOG_PG_SZ]	 = "log_page_size",
	[EQ_PBL_INDEX]	 = "pbl_index",
};
#endif
u64 drv_rdma_eq_read_field(struct sxe2_rdma_device *rdma_dev, void *data,
			   enum drv_rdma_dbg_rsc_type type, char *buf)
{
	int ret;
	struct sxe2_rdma_eqc *ctx;
	struct sxe2_rdma_ceq *ceq;
	struct sxe2_rdma_aeq *aeq;
	size_t len = 0;
	struct sxe2_rdma_dma_mem query_eq;
	struct sxe2_rdma_ctx_dev *dev_ctx;

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);

	query_eq.size = sizeof(struct sxe2_rdma_eqc);
	query_eq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_eq.size,
					   &query_eq.pa, GFP_KERNEL);
	if (!query_eq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query eq ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}
	memset(query_eq.va, 0, query_eq.size);

	if (type == SXE2_DBG_RSC_CEQ) {
		ceq = (struct sxe2_rdma_ceq *)data;

		ret = sxe2_drv_ceq_query_op(rdma_dev, &ceq->ctx_ceq,
					    query_eq.pa);
		if (ret != 0) {
			DRV_RDMA_LOG_DEV_ERR("query ceq failed, ret (%d)\n",
					     ret);
			goto free_ctx;
		}

		len += dbg_vsnprintf(buf, len, "ceq:%d context:\n\n",
				     ceq->ctx_ceq.ceq_id);
		len += dbg_vsnprintf(buf, len, "irq_num:  %d\n", ceq->irq);
		len += dbg_vsnprintf(buf, len, "msix_idx: %d\n\n",
				     ceq->msix_idx);
	} else if (type == SXE2_DBG_RSC_AEQ) {
		aeq = (struct sxe2_rdma_aeq *)data;

		ret = sxe2_drv_aeq_query_op(rdma_dev, &aeq->ctx_aeq,
					    query_eq.pa);
		if (ret != 0) {
			DRV_RDMA_LOG_DEV_ERR("query aeq failed, ret (%d)\n",
					     ret);
			goto free_ctx;
		}

		len += dbg_vsnprintf(buf, len, "aeq context:\n\n");
		len += dbg_vsnprintf(buf, len, "irq_num:  %d\n",
				     aeq->ctx_aeq.irq);
		len += dbg_vsnprintf(buf, len, "msix_idx: %d\n\n",
				     aeq->ctx_aeq.msix_idx);
	}

	ctx = (struct sxe2_rdma_eqc *)query_eq.va;

	len += dbg_vsnprintf(buf, len, "soft context\n");
	len += dbg_vsnprintf(buf, len, "oi:                       %lld\n",
			     ctx->seqc.oi);
	len += dbg_vsnprintf(buf, len, "vsi_index:                %d\n",
			     ctx->seqc.vsi_index);
	len += dbg_vsnprintf(buf, len, "sw_owner_bit:             %d\n",
			     ctx->seqc.sw_owner_bit);
	len += dbg_vsnprintf(buf, len, "sw_status:                %d\n",
			     ctx->seqc.sw_status);
	len += dbg_vsnprintf(buf, len, "uar_page:                 %d\n",
			     ctx->seqc.uar_page);
	len += dbg_vsnprintf(buf, len, "log_eq_size:              %lld\n",
			     ctx->seqc.log_eq_size);
	len += dbg_vsnprintf(buf, len, "pbl_mode:                 %d\n",
			     ctx->seqc.pbl_mode);
	len += dbg_vsnprintf(buf, len, "TPH_en:                   %d\n",
			     ctx->seqc.TPH_en);
	len += dbg_vsnprintf(buf, len, "TPH_value:                %d\n",
			     ctx->seqc.TPH_value);
	len += dbg_vsnprintf(buf, len, "page_offset:              %d\n",
			     ctx->seqc.page_offset);
	len += dbg_vsnprintf(buf, len, "log_page_size:            %d\n",
			     ctx->seqc.log_page_size);
	len += dbg_vsnprintf(buf, len, "pbl_index:                %llx\n\n",
			     ctx->seqc.pbl_index);

	len += dbg_vsnprintf(buf, len, "hw context\n");
	len += dbg_vsnprintf(buf, len, "hw_owner_bit:             %d\n",
			     ctx->heqc.hw_owner_bit);
	len += dbg_vsnprintf(buf, len, "over_flag:                %d\n",
			     ctx->heqc.over_flag);
	len += dbg_vsnprintf(buf, len, "hw_status:                %d\n",
			     ctx->heqc.hw_status);
	len += dbg_vsnprintf(buf, len, "pfvf_id:                  %d\n",
			     ctx->heqc.pfvf_id);
	len += dbg_vsnprintf(buf, len, "consumer_counter:         %d\n",
			     ctx->heqc.consumer_counter);
	len += dbg_vsnprintf(buf, len, "producer_counter:         %d\n",
			     ctx->heqc.producer_counter);
	len += dbg_vsnprintf(buf, len, "page_addr_odd_l:          %d\n",
			     ctx->heqc.page_addr_odd_l);
	len += dbg_vsnprintf(buf, len, "page_addr_odd_h:          %d\n",
			     ctx->heqc.page_addr_odd_h);
	len += dbg_vsnprintf(buf, len, "page_addr_even_l:         %d\n",
			     ctx->heqc.page_addr_even_l);
	len += dbg_vsnprintf(buf, len, "page_addr_even_h:         %d\n",
			     ctx->heqc.page_addr_even_h);

free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_eq.size, query_eq.va,
			  query_eq.pa);
	query_eq.va = NULL;

end:
	return len;
}

#ifdef SXE2_CFG_DEBUG
static int drv_rdma_eq_ctx_modify(struct sxe2_rdma_eqc *ctx, int field,
				  u64 value)
{
	int ret = 0;

	switch (field) {
	case EQ_OI:
		ctx->seqc.oi = value;
		break;
	case EQ_VSI_INDEX:
		ctx->seqc.vsi_index = value;
		break;
	case EQ_OWNER_BIT:
		ctx->seqc.sw_owner_bit = value;
		break;
	case EQ_STATUS:
		ctx->seqc.sw_status = value;
		break;
	case EQ_UAR_PAGE:
		ctx->seqc.uar_page = value;
		break;
	case EQ_LOG_EQ_SIZE:
		ctx->seqc.log_eq_size = value;
		break;
	case EQ_PBL_MODE:
		ctx->seqc.pbl_mode = value;
		break;
	case EQ_TPH_EN:
		ctx->seqc.TPH_en = value;
		break;
	case EQ_TPH_VALUE:
		ctx->seqc.TPH_value = value;
		break;
	case EQ_PAGE_OFFSET:
		ctx->seqc.page_offset = value;
		break;
	case EQ_LOG_PG_SZ:
		ctx->seqc.log_page_size = value;
		break;
	case EQ_PBL_INDEX:
		ctx->seqc.pbl_index = value;
		break;
	default:
		ret = -EINVAL;
		DRV_RDMA_LOG_WARN("invalid index %d, ret %d\n", field, ret);
	}

	return ret;
}

static int drv_rdma_query_eq(struct sxe2_rdma_device *rdma_dev, void *data,
			     enum drv_rdma_dbg_rsc_type type,
			     struct sxe2_rdma_dma_mem query_eq)
{
	int ret			  = 0;
	struct sxe2_rdma_ceq *ceq = NULL;
	struct sxe2_rdma_aeq *aeq = NULL;

	if (type == SXE2_DBG_RSC_CEQ) {
		ceq = (struct sxe2_rdma_ceq *)data;

		ret = sxe2_drv_ceq_query_op(rdma_dev, &ceq->ctx_ceq,
					    query_eq.pa);
		if (ret != 0) {
			DRV_RDMA_LOG_ERROR_BDF("query ceq failed, ret (%d)\n",
					       ret);
			goto end;
		}

	} else if (type == SXE2_DBG_RSC_AEQ) {
		aeq = (struct sxe2_rdma_aeq *)data;

		ret = sxe2_drv_aeq_query_op(rdma_dev, &aeq->ctx_aeq,
					    query_eq.pa);
		if (ret != 0) {
			DRV_RDMA_LOG_ERROR_BDF("query aeq failed, ret (%d)\n",
					       ret);
			goto end;
		}
	}

end:
	return ret;
}
#endif

int drv_rdma_eq_write_field(struct sxe2_rdma_device *rdma_dev, void *data,
			    enum drv_rdma_dbg_rsc_type type, char *buf)
{
#ifdef SXE2_CFG_DEBUG
	u32 i;
	int ret;
	u64 temp_value;
	struct sxe2_rdma_eqc *ctx;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_ceq *ceq	 = NULL;
	struct sxe2_rdma_aeq *aeq	 = NULL;
	struct sxe2_rdma_dma_mem query_eq;
	struct sxe2_rdma_ctx_dev *dev_ctx;

	dev_ctx = &(rdma_dev->rdma_func->ctx_dev);

	query_eq.size = sizeof(struct sxe2_rdma_eqc);
	query_eq.va   = dma_alloc_coherent(dev_ctx->hw->device, query_eq.size,
					   &query_eq.pa, GFP_KERNEL);
	if (!query_eq.va) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("query eq ctx alloc failed. ret:%d\n",
				     ret);
		goto end;
	}
	memset(query_eq.va, 0, query_eq.size);

	ret = drv_rdma_query_eq(rdma_dev, data, type, query_eq);
	if (ret)
		goto free_ctx;

	ctx = (struct sxe2_rdma_eqc *)query_eq.va;

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

	for (i = 0; i < ARRAY_SIZE(eq_fields); i++) {
		if (!strncmp(argv[0], eq_fields[i], strlen(eq_fields[i])) &&
		    (strlen(eq_fields[i]) == strlen(argv[0]))) {
			break;
		}
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%d)\n", ret);
		goto free_ctx;
	}

	DRV_RDMA_LOG_DEV_INFO("query eq i:%d, temp_value:%llx\n", i,
			      temp_value);

	ret = drv_rdma_eq_ctx_modify(ctx, i, temp_value);
	if (ret)
		goto free_ctx;

	if (type == SXE2_DBG_RSC_CEQ) {
		ret = sxe2_drv_ceq_modify_op(rdma_dev, &ceq->ctx_ceq, ctx);
		if (ret != 0)
			DRV_RDMA_LOG_DEV_ERR(
				"modify ceq ctx:%s failed, ret (%d)\n", argv[0],
				ret);
	} else if (type == SXE2_DBG_RSC_AEQ) {
		ret = sxe2_drv_aeq_modify_op(rdma_dev, &aeq->ctx_aeq, ctx);
		if (ret != 0)
			DRV_RDMA_LOG_DEV_ERR(
				"modify aeq ctx:%s failed, ret (%d)\n", argv[0],
				ret);
	}

free_ctx:
	dma_free_coherent(dev_ctx->hw->device, query_eq.size, query_eq.va,
			  query_eq.pa);
	query_eq.va = NULL;

end:
	return ret;
#else
	return 0;
#endif
}

static ssize_t drv_rdma_ae_codes_info_read(struct file *filp, char __user *buf,
					   size_t count, loff_t *off)
{
	ssize_t ret	 = 0;
	size_t len_total = 0;
	char *rsp	 = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	int i = 0;
	struct sxe2_ae_desc *ae_desc_debug;
	int ae_list_count;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"MQ DEBUGFS:find dev struct from private_data failed, ret %zu\n",
			ret);
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zu\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "ae codes info:\n");
	len_total += dbg_vsnprintf(rsp_end, len_total,
				   "---value---count---name---\n");

	ae_desc_debug = sxe2_get_ae_desc_list();
	ae_list_count = sxe2_get_ae_desc_list_size();
	for (i = 0; i < ae_list_count; i++) {
		len_total += dbg_vsnprintf(rsp_end, len_total,
					   "%#llx   %#llx   %s\n",
					   ae_desc_debug[i].id,
					   ae_desc_debug[i].count,
					   ae_desc_debug[i].name);
	}

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_ae_codes_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_ae_codes_info_read,
};

int drv_rdma_debug_aeq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_aeq *aeq)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->aeq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("aeq debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	aeq->dbg_node = drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_AEQ,
					      rdma_dev->hdl->aeq_debugfs,
					      drv_rdma_eq_read_field,
					      drv_rdma_eq_write_field, 0, aeq);
	if (!aeq->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
		goto end;
	}

	debugfs_create_file("ae_codes_info", SXE2_DEBUG_FILE_ONLY_READ,
			    rdma_dev->hdl->aeq_debugfs, rdma_dev,
			    &sxe2_rdma_ae_codes_fops);

end:
	return ret;
}

void drv_rdma_debug_aeq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_aeq *aeq)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->aeq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("aeq debugfs dir not exist\n");
		goto end;
	}

	kfree(aeq->dbg_node);
	aeq->dbg_node = NULL;

end:
	return;
}

int drv_rdma_debug_ceq_add(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ceq *ceq)
{
	int ret = 0;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->ceq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("eq debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	ceq->dbg_node = drv_rdma_add_res_tree(rdma_dev, SXE2_DBG_RSC_CEQ,
					      rdma_dev->hdl->ceq_debugfs,
					      drv_rdma_eq_read_field,
					      drv_rdma_eq_write_field,
					      (int)ceq->ctx_ceq.ceq_id, ceq);
	if (!ceq->dbg_node) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("debug res tree add failed ret (%d)\n",
				     ret);
	}

end:
	return ret;
}

void drv_rdma_debug_ceq_remove(struct sxe2_rdma_device *rdma_dev,
			       struct sxe2_rdma_ceq *ceq)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->ceq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("ceq debugfs dir not exist\n");
		goto end;
	}

	if (ceq->dbg_node) {
		drv_rdma_rm_res_tree(ceq->dbg_node);
		ceq->dbg_node = NULL;
	}

end:
	return;
}

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)

enum { AEQ_INJECT_CQ_SWSTATUS_ERR,
		AEQ_INJECT_CEQ_SWSTATUS_ERR,
		AEQ_INJECT_DB_CEQN_ERR,
		AEQ_INJECT_CEQ_CI_NOUDPATE_ERR,
		AEQ_INJECT_AEQ_CI_NOUDPATE_ERR,
		AEQ_INJECT_TMO_FPTE_VALID_ERR,
		AEQ_INJECT_CQ_DB_NO_UPDATE_ERR,
		AEQ_INJECT_SRQ_LIMIT_ERR,
		AEQ_INJECT_LLWQE_ERR,
};

static char *inject_flag_fields[] = {
	[AEQ_INJECT_CQ_SWSTATUS_ERR]	 = "cq_sw_status_err",
	[AEQ_INJECT_CEQ_SWSTATUS_ERR]	 = "ceq_sw_status_err",
	[AEQ_INJECT_DB_CEQN_ERR]	 = "db_ceqn_err",
	[AEQ_INJECT_CEQ_CI_NOUDPATE_ERR] = "ceq_ci_noupdate",
	[AEQ_INJECT_AEQ_CI_NOUDPATE_ERR] = "aeq_ci_noupdate",
	[AEQ_INJECT_TMO_FPTE_VALID_ERR]	 = "tmo_fpte_valid_0",
	[AEQ_INJECT_CQ_DB_NO_UPDATE_ERR] = "cq_db_no_update",
	[AEQ_INJECT_SRQ_LIMIT_ERR]	 = "srq_limit",
	[AEQ_INJECT_LLWQE_ERR]		 = "llwqe_err",
};

STATIC ssize_t drv_aeq_codes_inject_flag_read(struct file *filp,
					      char __user *buf, size_t count,
					      loff_t *pos)
{
	ssize_t ret;
	char *rsp = NULL;
	char *rsp_end;
	size_t len = 0;
	struct sxe2_rdma_device *rdma_dev;

	rdma_dev = filp->private_data;

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"MQ DEBUGFS:mq status rsp kmalloc failed, ret %zd\n",
			ret);
		goto end;
	}
	rsp_end = rsp;

	len += dbg_vsnprintf(rsp_end, len, "aeq codes inject flag\n");
	len += dbg_vsnprintf(rsp_end, len,
			     "echo xxx 1 > inject_flag; inject err\n");
	len += dbg_vsnprintf(rsp_end, len, "cq_sw_status_err:    %d\n",
			     rdma_dev->rdma_func->inject_aeq.cq_sw_status_err);
	len += dbg_vsnprintf(rsp_end, len, "ceq_sw_status_err:   %d\n",
			     rdma_dev->rdma_func->inject_aeq.ceq_sw_status_err);
	len += dbg_vsnprintf(rsp_end, len, "db_ceqn_err:         %d\n",
			     rdma_dev->rdma_func->inject_aeq.db_ceqn_err);
	len += dbg_vsnprintf(rsp_end, len, "ceq_ci_noupdate:     %d\n",
			     rdma_dev->rdma_func->inject_aeq.ceq_ci_noupdate);
	len += dbg_vsnprintf(rsp_end, len, "aeq_ci_noupdate:     %d\n",
			     rdma_dev->rdma_func->inject_aeq.aeq_ci_noupdate);
	len += dbg_vsnprintf(rsp_end, len, "tmo_fpte_valid_0:    %d\n",
			     rdma_dev->rdma_func->inject_aeq.tmo_fpte_valid_0);
	len += dbg_vsnprintf(rsp_end, len, "cq_db_no_update:     %d\n",
			     rdma_dev->rdma_func->inject_aeq.cq_db_no_update);
	len += dbg_vsnprintf(rsp_end, len, "srq_limit_flag:     %d\n",
			     rdma_dev->rdma_func->inject_aeq.srq_limit_flag);
	len += dbg_vsnprintf(rsp_end, len, "llwqe_flag:     %d\n",
			     rdma_dev->rdma_func->inject_aeq.llwqe_flag);

	ret = simple_read_from_buffer(buf, count, pos, rsp, (ssize_t)len);
	if (ret < 0)
		DRV_RDMA_LOG_DEV_ERR("MQ DEBUGFS:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

STATIC ssize_t drv_aeq_codes_inject_flag_write(struct file *filp,
					       const char __user *buf,
					       size_t count, loff_t *pos)
{
	int ret;
	char in_buf[IN_CMD_LEN] = { 0 };
	u32 i;
	u64 temp_value;
	int argc;
	char *argv[DEBUG_ARGV_COUNT_MAX] = { 0 };
	struct sxe2_rdma_device *rdma_dev;
	char cmd_buf[INJECT_CMD_LEN] = {0};
	u64 alive = ALIVE;

	rdma_dev = filp->private_data;

	if ((count >= IN_CMD_LEN) ||  copy_from_user(in_buf, buf, count)) {
		ret = -EFAULT;
		goto end;
	}

	argc = 0;

	ret = split_command(in_buf, &argc, argv);
	if (ret)
		goto end;

	if (argc != DEBUG_PARA_CONT2) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("invalid param nums\n");
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(inject_flag_fields); i++) {
		if (!strncmp(argv[0], inject_flag_fields[i],
			     strlen(inject_flag_fields[i])))
			break;
	}

	ret = kstrtoull(argv[1], 10, &temp_value);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("get param value failed, ret (%d)\n", ret);
		goto end;
	}

	DRV_RDMA_LOG_DEV_INFO("inject flag i:%d, to temp_value:%llx\n", i,
			      temp_value);
	snprintf(cmd_buf, sizeof(cmd_buf), "-u %llx -a  %llx", temp_value, alive);

	switch (i) {
	case AEQ_INJECT_CQ_SWSTATUS_ERR:
		rdma_dev->rdma_func->inject_aeq.cq_sw_status_err =
			(u8)temp_value;
		INJECT_ACTIVE(rdma_dev->rdma_func, "cq_sw_status_err", cmd_buf);
		break;
	case AEQ_INJECT_CEQ_SWSTATUS_ERR:
		rdma_dev->rdma_func->inject_aeq.ceq_sw_status_err =
			(u8)temp_value;
		INJECT_ACTIVE(rdma_dev->rdma_func, "ceq_sw_status_err", cmd_buf);
		break;
	case AEQ_INJECT_DB_CEQN_ERR:
		rdma_dev->rdma_func->inject_aeq.db_ceqn_err = (u8)temp_value;
		break;
	case AEQ_INJECT_CEQ_CI_NOUDPATE_ERR:
		rdma_dev->rdma_func->inject_aeq.ceq_ci_noupdate =
			(u8)temp_value;
		INJECT_ACTIVE(rdma_dev->rdma_func, "ceq_ci_noupdate", cmd_buf);
		break;
	case AEQ_INJECT_AEQ_CI_NOUDPATE_ERR:
		rdma_dev->rdma_func->inject_aeq.aeq_ci_noupdate =
			(u8)temp_value;
		INJECT_ACTIVE(rdma_dev->rdma_func, "aeq_ci_noupdate", cmd_buf);
		break;
	case AEQ_INJECT_TMO_FPTE_VALID_ERR:
		rdma_dev->rdma_func->inject_aeq.tmo_fpte_valid_0 =
			(u8)temp_value;
		break;
	case AEQ_INJECT_CQ_DB_NO_UPDATE_ERR:
		rdma_dev->rdma_func->inject_aeq.cq_db_no_update =
			(u8)temp_value;
		break;
	case AEQ_INJECT_SRQ_LIMIT_ERR:
		rdma_dev->rdma_func->inject_aeq.srq_limit_flag = (u8)temp_value;
		INJECT_ACTIVE(rdma_dev->rdma_func, "srq_limit_flag", cmd_buf);
		break;
	case AEQ_INJECT_LLWQE_ERR:
		rdma_dev->rdma_func->inject_aeq.llwqe_flag = (u8)temp_value;
		INJECT_ACTIVE(rdma_dev->rdma_func, "llwqe_flag", cmd_buf);
		break;
	default:
		DRV_RDMA_LOG_DEV_WARN("invalid index %d\n", i);
		ret = -EINVAL;
		goto end;
	}

	*pos = (loff_t)count;
	ret  = (int)count;

end:
	return ret;
}

static const struct file_operations aeq_codes_inject_flag_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_aeq_codes_inject_flag_read,
	.write = drv_aeq_codes_inject_flag_write,
};

int sxe2_rdma_aeq_codes_inject_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret			      = 0;
	struct sxe2_rdma_handler *hdl = rdma_dev->hdl;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("root dir not exist, ret (%d)\n", ret);
		goto end;
	}

	if (!rdma_dev->hdl->aeq_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("aeq debugfs dir not exist, ret (%d)\n",
				     ret);
		goto end;
	}

	hdl->aeq_codes_err_debugfs =
		debugfs_create_dir("aeq_codes_inject", hdl->aeq_debugfs);
	if (!hdl->aeq_codes_err_debugfs) {
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs create aeq_codes_inject dir failed.\n");
		ret = -ENOMEM;
		goto end;
	}

	debugfs_create_file("inject_flag", SXE2_DEBUG_FILE_READ_WRITE,
			    hdl->aeq_codes_err_debugfs, rdma_dev,
			    &aeq_codes_inject_flag_fops);

end:
	return ret;
}

void drv_rdma_aeq_codes_inject_del(struct sxe2_rdma_device *rdma_dev)
{
	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		DRV_RDMA_LOG_DEV_ERR("root dir not exist\n");
		goto end;
	}

	if (!rdma_dev->hdl->aeq_debugfs) {
		DRV_RDMA_LOG_DEV_ERR("aeq debugfs dir not exist\n");
		goto end;
	}

	debugfs_remove_recursive(rdma_dev->hdl->aeq_codes_err_debugfs);
	rdma_dev->hdl->aeq_codes_err_debugfs = NULL;

end:
	return;
}

#endif

