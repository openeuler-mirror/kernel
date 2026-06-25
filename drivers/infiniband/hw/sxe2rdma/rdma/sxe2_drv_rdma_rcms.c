// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_rcms.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_rdma_qos.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_rcms_debugfs.h"
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/printk.h>

extern struct mutex func_lock;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
u32 g_inject_fpte_err;
#endif

struct sxe2_rcms_rsrc_limits g_rsrc_limits_table[] = {
	[0] = {
		.qp_limit = 0x80,
	},
	[1] = {
		.qp_limit = 0x400,
	},
	[2] = {
		.qp_limit = 0x800,
	},
	[3] = {
		.qp_limit = 0x1000,
	},
	[4] = {
		.qp_limit = 0x4000,
	},
	[5] = {
		.qp_limit = 0x10000,
	},
	[6] = {
		.qp_limit = 0x20000,
	},
	[7] = {
		.qp_limit = 0x40000,
	},
};

int sxe2_rcms_query_fpm_val_cmd(struct sxe2_mq_ctx *mq, u64 scratch,
				u16 rcms_fn_id,
				struct sxe2_rdma_dma_mem *query_fpm_mem,
				bool post_sq, u8 wait_type)
{
	int ret = SXE2_OK;
	__le64 *wqe;

	struct sxe2_rcms_query_fpm_value_wqe *query_fpm_wqe;
	struct sxe2_rdma_ctx_dev *dev	  = mq->dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 tail, val, error;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_QUERY_FPM_VAL]) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       MQ_OP_QUERY_FPM_VAL);
		ret = -EBUSY;
		goto end;
	}
#endif

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		DRV_RDMA_LOG_DEV_ERR("RCMS: query fpm kget next mq wqe err\n");
		ret = -ENOMEM;
		goto end;
	}

	query_fpm_wqe = (struct sxe2_rcms_query_fpm_value_wqe *)wqe;
	query_fpm_wqe->rcms_function_id = rcms_fn_id;
	query_fpm_wqe->query_buf_pa =
		query_fpm_mem->pa >>
		SXE2_RCMS_QUERY_BUF_PA_SHIFT;
	query_fpm_wqe->op = SXE2_MQ_OP_QUERY_FPM_VAL;
	dma_wmb();
	query_fpm_wqe->wqe_valid = mq->polarity;
	DRV_RDMA_LOG_DEV_DEBUG("RCMS: query buf pa=%#llx\n", query_fpm_mem->pa);
	sxe2_kget_mq_reg_info(mq, &val, &tail, &error);

	if (post_sq) {
		sxe2_kpost_mq(mq);
		if (wait_type == SXE2_MQ_WAIT_POLL_REGS) {
			ret = sxe2_kpoll_mq_registers(
				mq, tail, mq->dev->hw_attrs.max_done_count);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS: query fpm kpoll mq reg err ret=%d\n",
					ret);
			}
		} else if (wait_type == SXE2_MQ_WAIT_POLL_CQ) {
			ret = sxe2_kpoll_mcq(mq, SXE2_MQ_OP_QUERY_FPM_VAL,
					     NULL);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS: query fpm kpoll mcq reg err ret=%d\n",
					ret);
			}
		}
	}

end:
	return ret;
}

static int
sxe2_rcms_query_fpm_val_cmd_complete(struct sxe2_rdma_ctx_dev *dev,
				     struct sxe2_rdma_dma_mem *query_fpm_mem,
				     u16 rcms_fn_id)
{
	int ret = SXE2_OK;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!query_fpm_mem) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:query fpm complete buffer pointer is null\n");
		ret = -EINVAL;
		goto end;
	}

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		ret = -ENOMEM;
		goto end;
	}

	mq_info				       = &mq_request->info;
	mq_request->param		       = NULL;
	mq_info->in.u.query_fpm_val.mq	       = dev->mq;
	mq_info->in.u.query_fpm_val.fpm_val_pa = query_fpm_mem->pa;
	mq_info->in.u.query_fpm_val.fpm_val_va = query_fpm_mem->va;
	mq_info->in.u.query_fpm_val.rcms_fn_id = rcms_fn_id;
	mq_info->mq_cmd			       = MQ_OP_QUERY_FPM_VAL;
	mq_info->post_mq		       = 1;
	mq_info->in.u.query_fpm_val.scratch    = (uintptr_t)mq_request;

	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return ret;
}

static void sxe2_rcms_parse_fpm_query_buf(struct sxe2_rdma_ctx_dev *dev,
					  __le32 *query_buf,
					  struct sxe2_rcms_info *rcms_info)
{
	struct sxe2_rcms_obj_info *obj_info;
	u32 i;
	u32 temp;
	u32 start_byte			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!query_buf || !rcms_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:func id %u parse fpm query pointer is null buf add=%p rcms_info=%p\n",
			rcms_info->rcms_fn_id, query_buf, rcms_info);
		goto end;
	}

	obj_info = rcms_info->rcms_obj;
	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		get_32bit_val(query_buf, start_byte, &temp);
		if (i == SXE2_RCMS_OBJ_ACK_TIMEOUT) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"RCMS:func id %u AMO entry size=%u\n",
				rcms_info->rcms_fn_id, temp);
			temp = SXE2_RCMS_AMO_PAGE_SIZE;
		}
		obj_info[i].size = 1 << temp;
		start_byte += SXE2_RCMS_PARSE_QUERY_BUF_SHIFT;
		get_32bit_val(query_buf, start_byte, &obj_info[i].max_cnt);
		start_byte += SXE2_RCMS_PARSE_QUERY_BUF_SHIFT;
		DRV_RDMA_LOG_DEV_DEBUG(
			"RCMS:func id %u obj %d size=%u max_cnt=%u\n",
			rcms_info->rcms_fn_id, i, obj_info[i].size,
			obj_info[i].max_cnt);
	}
	get_32bit_val(query_buf, SXE2_RCMS_MAX_FPTE_CNT_BUF_OFFSET, &temp);
	rcms_info->max_fpte_cnt = temp & SXE2_RCMS_MAX_FPTE_CNT_MASK;
	rcms_info->max_cc_qp_cnt =
		FIELD_GET(SXE2_RCMS_MAX_CC_QP_CNT_MASK, temp);
	get_32bit_val(query_buf, SXE2_RCMS_FIRST_FPTE_IDX_BUF_OFFSET, &temp);
	rcms_info->first_fpte_index = temp & SXE2_RCMS_FIRST_FPTE_IDX_MASK;
	rcms_info->irrl_ost_num = FIELD_GET(SXE2_RCMS_IRRL_OST_NUM_MASK, temp);
	rcms_info->ssnt_ost_num = FIELD_GET(SXE2_RCMS_SSNT_OST_NUM_MASK, temp);
	rcms_info->resp_ost_num = FIELD_GET(SXE2_RCMS_RESP_OST_NUM_MASK, temp);
	get_32bit_val(query_buf, SXE2_RCMS_CEQS_DB_BUF_OFFSET, &temp);
	rcms_info->max_ceqs = temp & SXE2_RCMS_MAX_CEQS_MASK;
	rcms_info->max_db_page_num =
		FIELD_GET(SXE2_RCMS_MAX_DB_PAGE_NUM_MASK, temp);
	get_32bit_val(query_buf, SXE2_RCMS_DB_BAR_ADDR_BUF_OFFSET,
		      &rcms_info->db_bar_addr);
	DRV_RDMA_LOG_DEV_DEBUG(
		"RCMS:func id %u max fpte cnt=%u,\n"
		"\tfirst fpte idx=%u ceqs = %u db page=%u db addr=0x%x\n",
		rcms_info->rcms_fn_id, rcms_info->max_fpte_cnt,
		rcms_info->first_fpte_index, rcms_info->max_ceqs,
		rcms_info->max_db_page_num, rcms_info->db_bar_addr);
	DRV_RDMA_LOG_DEV_DEBUG(
		"RCMS:func id %u max_cc_qp_cnt=%u, irrl_ost_num=%u\n"
		"\tssnt_ost_num = %u resp_ost_num=%u\n",
		rcms_info->rcms_fn_id, rcms_info->max_cc_qp_cnt,
		rcms_info->irrl_ost_num, rcms_info->ssnt_ost_num,
		rcms_info->resp_ost_num);
end:
	return;
}

static int sxe2_rcms_pf_query_fpm_val(struct sxe2_rdma_ctx_dev *dev)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_rdma_dma_mem query_fpm_mem;
	u8 wait_type;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!dev->rcms_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: pf query fpm val rcms info pointer is err\n");
		ret = -EINVAL;
		goto end;
	}
	rcms_info = dev->rcms_info;

	if (rcms_info->rcms_fn_id >= dev->hw_attrs.first_hw_vf_fpm_id) {
		DRV_RDMA_LOG_DEV_ERR("RCMS: input function id err func id=%u\n",
				     rcms_info->rcms_fn_id);
		ret = -EINVAL;
		goto end;
	}

	query_fpm_mem.pa = dev->fpm_query_buf_pa;
	query_fpm_mem.va = dev->fpm_query_buf;
	wait_type	 = SXE2_MQ_WAIT_POLL_REGS;

	ret = sxe2_rcms_query_fpm_val_cmd(dev->mq, SXE2_RCMS_MQ_CMD_NO_SCRATCH,
					  rcms_info->rcms_fn_id, &query_fpm_mem,
					  true, wait_type);
	if (ret != SXE2_OK)
		goto end;

	sxe2_rcms_parse_fpm_query_buf(dev, (__le32 *)query_fpm_mem.va,
				      rcms_info);
end:
	return ret;
}

static u32 sxe2_rcms_est_fpt_entry_cnt(struct sxe2_rcms_info *rcms_info)
{
	u64 size = 0;
	u32 fpte_cnt;
	u32 i;

	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		if (i != SXE2_RCMS_OBJ_PBLE) {
			size += round_up(rcms_info->rcms_obj[i].cnt *
						 rcms_info->rcms_obj[i].size,
					 rcms_info->rcms_obj[i + 1].size);
		} else {
			size += rcms_info->rcms_obj[i].cnt *
				rcms_info->rcms_obj[i].size;
		}
	}

	if (size & SXE2_FPTE_RCMS_2MB_MASK)
		fpte_cnt = (u32)(FPT_INDEX_GET(size) + 1);
	else
		fpte_cnt = (u32)FPT_INDEX_GET(size);

	if (fpte_cnt > SXE2_MAX_FPTE_CNT)
		fpte_cnt = SXE2_MAX_FPTE_CNT;

	return fpte_cnt;
}

static int sxe2_rcms_loop_modify_fpm_val(struct sxe2_rdma_device *rdma_dev,
					 struct sxe2_rcms_info *rcms_info,
					 u32 qp_limit_count, u8 rcms_profile)
{
	u32 max_fpte;
	u32 qp_wanted = 0;
	u32 mr_wanted, pble_wanted;
	u32 powerof2;
	u32 fpte_needed;
	u32 fpte_diff;
	u32 loop_count			    = 0;
	struct sxe2_rcms_obj_info *rcms_obj = rcms_info->rcms_obj;
	int ret				    = SXE2_OK;

	max_fpte = rcms_info->max_fpte_cnt;
	fpte_needed = sxe2_rcms_est_fpt_entry_cnt(rcms_info);
	qp_wanted   = min(qp_limit_count, rcms_obj[SXE2_RCMS_OBJ_QP].max_cnt);
	mr_wanted   = rcms_obj[SXE2_RCMS_OBJ_MR].max_cnt;
	pble_wanted = rcms_obj[SXE2_RCMS_OBJ_PBLE].max_cnt;

	do {
		++loop_count;
		rcms_obj[SXE2_RCMS_OBJ_QP].cnt = qp_wanted;
		rcms_obj[SXE2_RCMS_OBJ_ACK_TIMEOUT].cnt =
			min(qp_wanted, rcms_obj[SXE2_RCMS_OBJ_ACK_TIMEOUT].cnt);
		rcms_obj[SXE2_RCMS_OBJ_IRRL].cnt =
			min(qp_wanted, rcms_obj[SXE2_RCMS_OBJ_IRRL].cnt);
		rcms_obj[SXE2_RCMS_OBJ_SSNT].cnt =
			min(qp_wanted, rcms_obj[SXE2_RCMS_OBJ_SSNT].cnt);
		rcms_obj[SXE2_RCMS_OBJ_CQ].cnt =
			min(2 * qp_wanted, rcms_obj[SXE2_RCMS_OBJ_CQ].cnt);
		rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt =
			min(qp_wanted / 2, rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt);
		rcms_obj[SXE2_RCMS_OBJ_MR].cnt	 = mr_wanted;
		rcms_obj[SXE2_RCMS_OBJ_PBLE].cnt = pble_wanted;
		fpte_needed = sxe2_rcms_est_fpt_entry_cnt(rcms_info);
		if (fpte_needed <= max_fpte)
			break;

		fpte_diff = fpte_needed - max_fpte;
		if (fpte_diff > 128) {
			if (!(loop_count % 2) && qp_wanted > 128) {
				qp_wanted /= 2;
			} else {
				pble_wanted /= 2;
				mr_wanted /= 2;
			}
			continue;
		}
		if (rcms_profile != SXE2_RCMS_PROFILE_FAVOR_VF &&
		    pble_wanted >
			    (512 * SXE2_RCMS_FPM_MULTIPLIER * fpte_diff)) {
			pble_wanted -=
				256 * SXE2_RCMS_FPM_MULTIPLIER * fpte_diff;
			continue;
		} else if (pble_wanted > 100 * SXE2_RCMS_FPM_MULTIPLIER) {
			pble_wanted -= 10 * SXE2_RCMS_FPM_MULTIPLIER;
		} else if (pble_wanted > 16 * SXE2_RCMS_FPM_MULTIPLIER) {
			pble_wanted -= SXE2_RCMS_FPM_MULTIPLIER;
		}

		if (mr_wanted > SXE2_RCMS_FPM_MULTIPLIER)
			mr_wanted -= SXE2_RCMS_FPM_MULTIPLIER;
		if (!(loop_count % 10) && qp_wanted > 128)
			qp_wanted /= 2;

	} while (loop_count < 40);
	if (fpte_needed > max_fpte) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:func id %u modify fpm val err fpte needed=%u max fpte cnt=%u\n",
			rcms_info->rcms_fn_id, fpte_needed, max_fpte);
		ret = -EINVAL;
		goto end;
	}

	if (loop_count > 2 && fpte_needed < max_fpte) {
		pble_wanted += (max_fpte - fpte_needed) * 256 *
			       SXE2_RCMS_FPM_MULTIPLIER;
		rcms_obj[SXE2_RCMS_OBJ_PBLE].cnt =
			min(pble_wanted, rcms_obj[SXE2_RCMS_OBJ_PBLE].max_cnt);
		powerof2 = 1;
		while (powerof2 <= rcms_obj[SXE2_RCMS_OBJ_PBLE].cnt)
			powerof2 *= 2;

		powerof2 /= 2;
		rcms_obj[SXE2_RCMS_OBJ_PBLE].cnt = powerof2;
	}

end:
	return ret;
}

int sxe2_rcms_modify_fpm_val(struct sxe2_rdma_ctx_dev *dev,
			     struct sxe2_rcms_info *rcms_info,
			     u32 qp_limit_count)
{
	int ret = SXE2_OK;
	u32 i;
	u32 fpte_needed;
#ifdef SXE2_CFG_DEBUG
	u32 loop_count			    = 0;
#endif
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(dev);
	struct sxe2_rcms_obj_info *rcms_obj = rcms_info->rcms_obj;

	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++)
		rcms_obj[i].cnt = rcms_obj[i].max_cnt;

	ret = sxe2_rcms_loop_modify_fpm_val(rdma_dev, rcms_info, qp_limit_count,
					    dev->mq->rcms_profile);
	if (ret != SXE2_OK)
		goto end;

	fpte_needed = sxe2_rcms_est_fpt_entry_cnt(rcms_info);
	DRV_RDMA_LOG_DEBUG_BDF("RCMS:func id %u loop cnt=%u fpte needed=%u\n",
			       rcms_info->rcms_fn_id, loop_count, fpte_needed);
	DRV_RDMA_LOG_DEBUG_BDF(
		"RCMS:func id %u qp cnt=%u cq cnt=%u srq cnt=%u mr cnt=%u ah cnt=%u pble cnt=%u\n",
		rcms_info->rcms_fn_id, rcms_obj[SXE2_RCMS_OBJ_QP].cnt,
		rcms_obj[SXE2_RCMS_OBJ_CQ].cnt, rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt,
		rcms_obj[SXE2_RCMS_OBJ_MR].cnt, rcms_obj[SXE2_RCMS_OBJ_AH].cnt,
		rcms_obj[SXE2_RCMS_OBJ_PBLE].cnt);
	DRV_RDMA_LOG_DEBUG_BDF(
		"RCMS:func id %u RESP cnt=%u IRRL cnt=%u SSNT cnt=%u ATMO cnt=%u\n",
		rcms_info->rcms_fn_id, rcms_obj[SXE2_RCMS_OBJ_RESP].cnt,
		rcms_obj[SXE2_RCMS_OBJ_IRRL].cnt,
		rcms_obj[SXE2_RCMS_OBJ_SSNT].cnt,
		rcms_obj[SXE2_RCMS_OBJ_ACK_TIMEOUT].cnt);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "rcms_commit_err_qp",
		     &rdma_dev->rdma_func->mq.err_cqe_val, rcms_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_commit_err_qp");

	INJECT_START(rdma_dev->rdma_func, "rcms_commit_err_cq",
		     &rdma_dev->rdma_func->mq.err_cqe_val, rcms_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_commit_err_cq");

	INJECT_START(rdma_dev->rdma_func, "rcms_commit_err_srq",
		     &rdma_dev->rdma_func->mq.err_cqe_val, rcms_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_commit_err_srq");

	INJECT_START(rdma_dev->rdma_func, "rcms_commit_err_mr",
		     &rdma_dev->rdma_func->mq.err_cqe_val, rcms_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_commit_err_mr");

	INJECT_START(rdma_dev->rdma_func, "rcms_commit_err_ah",
		     &rdma_dev->rdma_func->mq.err_cqe_val, rcms_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_commit_err_ah");
#endif

end:
	return ret;
}

static void sxe2_rcms_get_obj_liner_base(struct sxe2_rdma_ctx_dev *dev,
					 struct sxe2_rcms_info *rcms_info)
{
	u64 liner_base;
	u64 first_fpte_index;
	u32 fpte_needed;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!rcms_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:func id %u get obj liner base rcms info pointer is null\n",
			rcms_info->rcms_fn_id);
		goto end;
	}

	first_fpte_index = (u64)rcms_info->first_fpte_index;
	liner_base = first_fpte_index * SXE2_RCMS_FPTE_SIZE +
		     SXE2_RCMS_LINER_ADDR_BASE;
	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		if ((i == SXE2_RCMS_OBJ_PBLE) &&
		    (liner_base & SXE2_FPTE_RCMS_2MB_MASK)) {
			liner_base = (FPT_INDEX_GET(liner_base) + 1) *
					     SXE2_RCMS_FPTE_SIZE +
				     SXE2_RCMS_LINER_ADDR_BASE;
		}

		rcms_info->rcms_obj[i].base =
			round_up(liner_base, rcms_info->rcms_obj[i].size);
		liner_base = rcms_info->rcms_obj[i].base +
			     rcms_info->rcms_obj[i].cnt *
				     rcms_info->rcms_obj[i].size;
	}

	rcms_info->max_fpte_index = (u32)FPT_INDEX_GET(liner_base);
	fpte_needed =
		rcms_info->max_fpte_index - rcms_info->first_fpte_index + 1;
	rcms_info->fpte_needed = fpte_needed;
	rcms_info->first_page_fpte =
		rcms_info->max_fpte_cnt - rcms_info->fpte_needed;
	rcms_info->fpt.fpte_cnt = fpte_needed;
end:
	return;
}

int sxe2_rcms_commit_fpm_val_cmd(struct sxe2_mq_ctx *mq, u64 scratch,
				 u16 rcms_fn_id,
				 struct sxe2_rdma_dma_mem *commit_fpm_mem,
				 bool post_sq, u8 wait_type)
{
	int ret = SXE2_OK;
	__le64 *wqe;
	struct sxe2_rcms_commit_fpm_value_wqe *commit_fpm_wqe;
	u32 tail, val, error;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	u64 *wqe_start;
	int i;

	if (!mq || !commit_fpm_mem) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:commit fpm cmd mq or commit buffer pointer is null\n");
		ret = -EINVAL;
		goto end;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_COMMIT_FPM_VAL]) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       MQ_OP_COMMIT_FPM_VAL);
		ret = -EBUSY;
		goto end;
	}
#endif

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:get wq err ret=%d\n", ret);
		ret = -ENOMEM;
		goto end;
	}
	commit_fpm_wqe = (struct sxe2_rcms_commit_fpm_value_wqe *)wqe;
	commit_fpm_wqe->rcms_function_id = rcms_fn_id;
	commit_fpm_wqe->commit_buf_pa = commit_fpm_mem->pa >> 2;
	commit_fpm_wqe->op	      = SXE2_MQ_OP_COMMIT_FPM_VAL;
	dma_wmb();
	commit_fpm_wqe->wqe_valid = mq->polarity;
	DRV_RDMA_LOG_DEV_DEBUG(
		"RCMS: commit fpm wqe func id=%u buf pa=%#llx op=%u wqe valid=%u\n",
		commit_fpm_wqe->rcms_function_id,
		(u64)commit_fpm_wqe->commit_buf_pa, commit_fpm_wqe->op,
		commit_fpm_wqe->wqe_valid);
	wqe_start = (u64 *)wqe;
	for (i = 0; i < SXE2_RCMS_MQ_WQE_LEN; i++) {
		DRV_RDMA_LOG_DEV_DEBUG("RCMS:commit fpm wqe 64bit[%u]=%#llx\n",
				       i, wqe_start[i]);
	}

	sxe2_kget_mq_reg_info(mq, &val, &tail, &error);

	if (post_sq) {
		sxe2_kpost_mq(mq);
		if (wait_type == SXE2_MQ_WAIT_POLL_REGS)
			ret = sxe2_kpoll_mq_registers(
				mq, tail, mq->dev->hw_attrs.max_done_count);
		else if (wait_type == SXE2_MQ_WAIT_POLL_CQ)
			ret = sxe2_kpoll_mcq(mq, SXE2_MQ_OP_COMMIT_FPM_VAL,
					     NULL);
	}
end:
	return ret;
}

static int
sxe2_rcms_commit_fpm_val_cmd_complete(struct sxe2_rdma_ctx_dev *dev,
				      struct sxe2_rdma_dma_mem *commit_fpm_mem,
				      u16 rcms_fn_id)
{
	int ret = SXE2_OK;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:get mq request err\n");
		ret = -ENOMEM;
		goto end;
	}

	mq_info					= &mq_request->info;
	mq_request->param			= NULL;
	mq_info->in.u.commit_fpm_val.mq		= dev->mq;
	mq_info->in.u.commit_fpm_val.fpm_val_pa = commit_fpm_mem->pa;
	mq_info->in.u.commit_fpm_val.fpm_val_va = commit_fpm_mem->va;
	mq_info->in.u.commit_fpm_val.rcms_fn_id = rcms_fn_id;
	mq_info->mq_cmd				= MQ_OP_COMMIT_FPM_VAL;
	mq_info->post_mq			= 1;
	mq_info->in.u.commit_fpm_val.scratch	= (uintptr_t)mq_request;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return ret;
}

static int sxe2_rcms_pf_commit_fpm_val(struct sxe2_rdma_ctx_dev *dev)
{
	int ret = SXE2_OK;
	__le32 *buf;
	struct sxe2_rcms_obj_info *obj_info;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_rdma_dma_mem commit_fpm_mem;
	u8 wait_type;
	u32 i;
	u32 start_byte = 0;
	u64 base_val;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!dev->rcms_info) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:rcms info is null err\n");
		ret = -EFAULT;
		goto end;
	}
	rcms_info = dev->rcms_info;

	if (rcms_info->rcms_fn_id >= dev->hw_attrs.first_hw_vf_fpm_id) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:pf func id err func id=%d\n",
				     rcms_info->rcms_fn_id);
		ret = -EINVAL;
		goto end;
	}

	if (!rcms_info->rcms_obj) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:rcms obj is null err\n");
		ret = -EFAULT;
		goto end;
	}
	obj_info = rcms_info->rcms_obj;

	buf = dev->fpm_commit_buf;
	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		base_val = obj_info[i].base >> SXE2_RCMS_OBJ_LINER_BASE_SHIFT;
		set_32bit_val(buf, start_byte, (u32)base_val);
		start_byte += SXE2_RCMS_COMMIT_BUF_SHIFT;
		set_32bit_val(buf, start_byte, (u32)obj_info[i].cnt);
		start_byte += SXE2_RCMS_COMMIT_BUF_SHIFT;
	}

	set_32bit_val(buf, SXE2_RCMS_MAX_FPTE_CNT_BUF_OFFSET,
		      (u32)rcms_info->max_fpte_cnt);
	set_32bit_val(buf, SXE2_RCMS_CEQS_DB_BUF_OFFSET,
		      (u32)rcms_info->max_ceqs);
	commit_fpm_mem.pa = dev->fpm_commit_buf_pa;
	commit_fpm_mem.va = (void *)buf;
	wait_type	  = SXE2_MQ_WAIT_POLL_REGS;
	ret = sxe2_rcms_commit_fpm_val_cmd(dev->mq, SXE2_RCMS_MQ_CMD_NO_SCRATCH,
					   rcms_info->rcms_fn_id,
					   &commit_fpm_mem, true, wait_type);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:commit fpt val cmd err ret=%d\n",
				     ret);
	}

end:
	return ret;
}

static int sxe2_rcms_alloc_fpt_entry_mem(struct sxe2_rdma_ctx_dev *dev,
					 struct sxe2_rcms_info *rcms_info)
{
	int ret = SXE2_OK;
	struct sxe2_rdma_virt_mem virt_mem;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 mem_size;

	if (!rcms_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:alloc fpte rcms info pointer is null\n");
		ret = -EINVAL;
		goto end;
	}
	mem_size =
		(u32)(sizeof(struct sxe2_rcms_fpt_entry) *
		      (rcms_info->fpt.fpte_cnt + rcms_info->first_fpte_index));
	virt_mem.size = mem_size;
	virt_mem.va = kzalloc(virt_mem.size, GFP_KERNEL);
	if (!virt_mem.va) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:alloc fpte struct mem err\n");
		ret = -ENOMEM;
		goto end;
	}
	rcms_info->fpt.fpte = virt_mem.va;
end:
	return ret;
}

int sxe2_rcms_pf_config_fpm_val(struct sxe2_rdma_ctx_dev *dev,
				u32 qp_limit_count)
{
	int ret				  = SXE2_OK;
	struct sxe2_rcms_info *rcms_info  = dev->rcms_info;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	ret = sxe2_rcms_pf_query_fpm_val(dev);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("RCMS: pf query fpm val err ret=%d\n",
				     ret);
		goto end;
	}
	ret = sxe2_rcms_modify_fpm_val(dev, rcms_info, qp_limit_count);
	if (ret != SXE2_OK)
		goto end;

	sxe2_rcms_get_obj_liner_base(dev, rcms_info);
	ret = sxe2_rcms_pf_commit_fpm_val(dev);
	if (ret != SXE2_OK)
		goto end;

	ret = sxe2_rcms_alloc_fpt_entry_mem(dev, rcms_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("RCMS: alloc fpt entry mem err ret=%d\n",
				     ret);
	}

end:
	return ret;
}

void sxe2_rcms_get_obj_fpte_range(struct sxe2_rcms_info *rcms_info,
				  u32 obj_type, u32 start_idx, u32 obj_cnt,
				  u32 *fpte_idx, u32 *fpte_limit)
{
	u64 liner_addr;
	u64 liner_addr_limit;

	liner_addr = rcms_info->rcms_obj[obj_type].base +
		     rcms_info->rcms_obj[obj_type].size * start_idx;
	liner_addr_limit =
		liner_addr + rcms_info->rcms_obj[obj_type].size * obj_cnt;
	*fpte_idx   = (u32)FPT_INDEX_GET(liner_addr);
	*fpte_limit = (u32)FPT_INDEX_GET((liner_addr_limit - 1));
	*fpte_limit += 1;
}

void sxe2_rcms_get_obj_spte_range(struct sxe2_rcms_info *rcms_info,
				  u32 obj_type, u32 start_idx, u32 obj_cnt,
				  u32 *spte_idx, u32 *spte_limit)
{
	u64 liner_addr;
	u64 liner_addr_limit;

	liner_addr = rcms_info->rcms_obj[obj_type].base +
		     rcms_info->rcms_obj[obj_type].size * start_idx;
	liner_addr_limit =
		liner_addr + rcms_info->rcms_obj[obj_type].size * obj_cnt;
	*spte_idx   = (u32)SPT_INDEX_GET(liner_addr);
	*spte_limit = (u32)SPT_INDEX_GET((liner_addr_limit - 1));
	*spte_limit += 1;
}

int sxe2_rcms_add_fpt_entry(struct sxe2_rdma_ctx_dev *dev,
			    struct sxe2_rcms_info *rcms_info, u32 fpte_index,
			    enum sxe2_rcms_fpt_entry_type fpte_type)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rdma_dma_mem page_mem = { 0 };
	struct sxe2_rdma_virt_mem *vmem;
	u64 page_len			  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!rcms_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:add fpte rcms info pointer is null\n");
		ret = -EINVAL;
		goto end;
	}
	fpte = &rcms_info->fpt.fpte[fpte_index];
	if (!fpte->valid) {
		if (fpte_type == SXE2_RCMS_FPT_TYPE_FIRST)
			page_len = SXE2_RCMS_FIRST_CP_SIZE;
		else if (fpte_type == SXE2_RCMS_FPT_TYPE_SECOND)
			page_len = SXE2_RCMS_SPT_PAGE_SIZE;

		page_mem.size =
			(u32)ALIGN(page_len, SXE2_RCMS_FPT_SPT_BUF_ALIGNMENT);
		page_mem.va = dma_alloc_coherent(dev->hw->device, page_mem.size,
						 &page_mem.pa, GFP_KERNEL);
		if (!page_mem.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:The current environment cannot allocate contiguous memory.\n"
				"\tplease use rcms_mode=2 or release the used memory\n"
				"\tin the environment\n");
			DRV_RDMA_LOG_DEV_ERR("RCMS:alloc fpte %u mem err\n",
					     fpte_index);
			ret = -ENOMEM;
			return ret;
		}
		memset(page_mem.va, 0, page_mem.size);

		if (fpte_type == SXE2_RCMS_FPT_TYPE_FIRST) {
			memcpy(&fpte->u.cp.page_addr, &page_mem,
			       sizeof(fpte->u.cp.page_addr));
			fpte->u.cp.fpt_spt_index = fpte_index;
		} else if (fpte_type == SXE2_RCMS_FPT_TYPE_SECOND) {
			vmem = &fpte->u.spt.spte_virt_mem;
			vmem->size = sizeof(struct sxe2_rcms_spt_entry) *
				     SXE2_RCMS_SPT_ENTRY_CNT;
			vmem->va = kzalloc(vmem->size, GFP_KERNEL);
			if (!vmem->va) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS:alloc fpte %u spte struct mem err\n",
					fpte_index);
				ret = -ENOMEM;
				goto spte_mem_err;
			}
			fpte->u.spt.spte = vmem->va;
			memset(page_mem.va, SXE2_RCMS_SPT_INVALID_VAL,
			       page_len);
			memcpy(&fpte->u.spt.spt_page_addr, &page_mem,
			       sizeof(fpte->u.spt.spt_page_addr));
			fpte->u.spt.use_cnt = 0;
		}
		rcms_info->fpt.fpte[fpte_index].entry_type = fpte_type;
		rcms_info->fpt.use_cnt++;
	}
	if (fpte_type == SXE2_RCMS_FPT_TYPE_FIRST)
		fpte->u.cp.use_cnt++;

	goto end;
spte_mem_err:
	dma_free_coherent(dev->hw->device, page_mem.size, page_mem.va,
			  page_mem.pa);
	page_mem.va = NULL;
end:
	return ret;
}

int sxe2_rcms_invalidate_spt_cache(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
				   u32 spte_idx)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 pull			  = SXE2_RCMS_SPT_INVALID_REG_PULL;
	u32 bar_reg_val;
	u32 idx_val;

	mutex_lock(&func_lock);
	bar_reg_val =
		WRITE_BIT(SXE2_RCMS_SPT_INVALID_MASK_REG_VAL,
			  SPT_CACHE_INVALID_MASK_M, SPT_CACHE_INVALID_MASK_S);
	SXE2_BAR_WRITE_32(bar_reg_val,
			  dev->hw_regs[RCMS_SPT_CACHE_FAST_INVALID_MASK]);
	idx_val	    = (fpte_idx << 9) | spte_idx;
	bar_reg_val = WRITE_BIT(idx_val, SPT_CACHE_INVALID_IDX_SPT_IDX_M,
				SPT_CACHE_INVALID_IDX_SPT_IDX_S) |
		      WRITE_BIT(1, SPT_CACHE_INVALID_IDX_EN_M,
				SPT_CACHE_INVALID_IDX_EN_S);
	SXE2_BAR_WRITE_32(bar_reg_val,
			  dev->hw_regs[RCMS_SPT_CACHE_FAST_INVALID_IDX]);
	do {
		bar_reg_val = SXE2_BAR_READ_32(
			dev->hw_regs[RCMS_SPT_CACHE_FAST_INVALID_IDX]);
		if (READ_BIT(bar_reg_val, SPT_CACHE_INVALID_IDX_DONE_M,
			     SPT_CACHE_INVALID_IDX_DONE_S)) {
			break;
		}
		cond_resched();
	} while (--pull);

	if (!pull) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:invalid spt cache err fpte idx=%u spte idx=%u\n",
			fpte_idx, spte_idx);
		ret = -EINVAL;
	} else {
		bar_reg_val = WRITE_BIT(0, SPT_CACHE_INVALID_IDX_DONE_M,
					SPT_CACHE_INVALID_IDX_DONE_S);
		SXE2_BAR_WRITE_32(
			bar_reg_val,
			dev->hw_regs[RCMS_SPT_CACHE_FAST_INVALID_IDX]);
	}
	mutex_unlock(&func_lock);
	return ret;
}

int sxe2_rcms_add_spt_entry(struct sxe2_rdma_ctx_dev *dev,
			    struct sxe2_rcms_info *rcms_info, u32 spte_index)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_spt *spt;
	struct sxe2_rcms_spt_entry *spte;
	struct sxe2_rdma_dma_mem page_mem = { 0 };
	u64 *spt_page_addr;
	u64 page_pa = 0;
	u32 rel_spt_index;
	u32 fpte_index;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!rcms_info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:add spte rcms info pointer is null\n");
		ret = -EINVAL;
		goto end;
	}
	fpte_index = spte_index / SXE2_RCMS_SPT_ENTRY_CNT;
	if (fpte_index > rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:fpte index %u out of bounds  max fpte index=%u\n",
			fpte_index, rcms_info->fpt.fpte_cnt);
		ret = -EINVAL;
		goto end;
	}
	if (rcms_info->fpt.fpte[fpte_index].entry_type !=
	    SXE2_RCMS_FPT_TYPE_SECOND) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:fpte %u type is not second type = %u\n",
			fpte_index, rcms_info->fpt.fpte[fpte_index].entry_type);
		ret = -EINVAL;
		goto end;
	}
	rel_spt_index = REL_SPTE_INDEX_GET(spte_index);
	spt	      = &rcms_info->fpt.fpte[fpte_index].u.spt;
	spte = &rcms_info->fpt.fpte[fpte_index].u.spt.spte[rel_spt_index];
	if (!spte->valid) {
		page_mem.size = ALIGN(SXE2_RCMS_SECOND_CP_SIEZ,
				      SXE2_RCMS_FPT_SPT_BUF_ALIGNMENT);
		page_mem.va = dma_alloc_coherent(dev->hw->device, page_mem.size,
						 &page_mem.pa, GFP_KERNEL);
		if (!page_mem.va) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:fpte index %u rel spte index %u alloc cp err\n",
				fpte_index, rel_spt_index);
			ret = -ENOMEM;
			return ret;
		}
		memset(page_mem.va, 0, page_mem.size);
		memcpy(&spte->cp.page_addr, &page_mem,
		       sizeof(spte->cp.page_addr));
		spte->cp.fpt_spt_index = spte_index;
		spte->cp.entry_type    = SXE2_RCMS_FPT_TYPE_SECOND;
		page_pa		       = page_mem.pa;
		spt_page_addr	       = spt->spt_page_addr.va;
		spt_page_addr += rel_spt_index;
		memcpy(spt_page_addr, &page_pa, sizeof(*spt_page_addr));
		spte->fpt_index = fpte_index;
		spte->valid	= true;
		spt->use_cnt++;
		;
		ret = sxe2_rcms_invalidate_spt_cache(dev, fpte_index,
						     rel_spt_index);
		if (ret != SXE2_OK)
			goto invalid_spt_err;
	}

	spte->cp.use_cnt++;
	goto end;
invalid_spt_err:
	spt->use_cnt--;
	spte->valid = false;
	dma_free_coherent(dev->hw->device, page_mem.size, page_mem.va,
			  page_mem.pa);
	page_mem.va = NULL;

end:
	return ret;
}

static void sxe2_rcms_set_fpte(u64 pa, u16 fpte_index,
			       enum sxe2_rcms_fpt_entry_type fpte_type,
			       struct sxe2_rcms_update_fpt_entry *entry)
{
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	u32 valid = 1;

	DRV_RDMA_LOG_DEBUG("inject mq debugfs rcms_ctx_err\n");
	if (g_inject_fpte_err == 1) {
		valid = 0;
	} else if (g_inject_fpte_err == 2) {
		entry->data = 0;
		entry->cmd  = fpte_index;
		return;
	} else if (g_inject_fpte_err == 3) {
		pa = 0xFFFFFFFFFFFFF000;
	} else if (g_inject_fpte_err == 4) {
		fpte_index = 0xffff;
	}
	entry->data =
		pa |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_CP_COUNT,
			   (s64)SXE2_RCMS_SPT_ENTRY_CNT) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_TYPE,
			   (fpte_type == SXE2_RCMS_FPT_TYPE_SECOND ? 0 : 1)) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_VALID, valid);
	entry->cmd = fpte_index;
	return;
#else
	entry->data =
		pa |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_CP_COUNT,
			   (s64)SXE2_RCMS_SPT_ENTRY_CNT) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_TYPE,
			   (s64)(fpte_type == SXE2_RCMS_FPT_TYPE_SECOND ? 0 :
									  1)) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_VALID, (s64)1);

	entry->cmd = fpte_index;
#endif
}

static void sxe2_rcms_clr_fpte(u16 fpte_index,
			       enum sxe2_rcms_fpt_entry_type fpte_type,
			       struct sxe2_rcms_update_fpt_entry *entry)
{
	entry->data = (u64)(
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_CP_COUNT,
			   (s64)SXE2_RCMS_SPT_ENTRY_CNT) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_TYPE,
			   (s64)(fpte_type == SXE2_RCMS_FPT_TYPE_SECOND ? 0 :
									  1)) |
		FIELD_PREP((s64)SXE2_RCMS_FPT_DATALOW_VALID, (s64)0));

	entry->cmd = fpte_index;
}

int sxe2_rcms_update_fpte_wqe_fill(struct sxe2_mq_ctx *mq,
				   struct sxe2_rcms_update_fptes_info *info,
				   u64 scratch)
{
	int ret = SXE2_OK;
	u64 data;
	__le64 *wqe;
	u32 mem_entries, wqe_entries;
	struct sxe2_rdma_dma_mem *fpte_buf;
	struct sxe2_rcms_update_fpte_wqe *update_fpte_wqe;
	u64 offset = 0;
	u32 wqe_idx;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	u64 *wqe_start;
	int i;

	if (!mq || !info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:update fpte wqe fill mq or info pointer is null\n");
		ret = -EINVAL;
		goto end;
	}
	fpte_buf = &mq->fptebuf;
	wqe	 = sxe2_kget_next_mq_wqe_idx(mq, scratch, &wqe_idx);
	if (!wqe) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:mq get wqe err ret=%d\n", ret);
		ret = -ENOMEM;
		goto end;
	}
	update_fpte_wqe = (struct sxe2_rcms_update_fpte_wqe *)wqe;
	wqe_entries	= (info->cnt > SXE2_UPDATE_FPTE_WQE_INCLUDE_ENTRY_CNT) ?
			      SXE2_UPDATE_FPTE_WQE_INCLUDE_ENTRY_CNT :
			      info->cnt;
	mem_entries = info->cnt - wqe_entries;

	if (mem_entries) {
		offset = wqe_idx * SXE2_RCMS_UPDATE_FPTE_BUF_SIZE;
		memcpy(((char *)fpte_buf->va + offset), &info->entry[3],
		       (size_t)(mem_entries
				<< SXE2_RCMS_FPTE_BUF_ENTRIES_SIZE_SHIFT));
		data = (u64)fpte_buf->pa + offset;
	} else {
		data = 0;
	}

	update_fpte_wqe->rcms_fcn_id	    = info->rcms_fn_id;
	update_fpte_wqe->fpt_buffer_address = data >> SXE2_RCMS_FPTE_BUF_SHIFT;
	if (wqe_entries >= 1 && wqe_entries <= 3) {
		update_fpte_wqe->fpte_cmd_0  = info->entry[0].cmd;
		update_fpte_wqe->fpte_data_0 = info->entry[0].data;
	}
	if (wqe_entries == 2 || wqe_entries == 3) {
		update_fpte_wqe->fpte_cmd_1	   = info->entry[1].cmd;
		update_fpte_wqe->fpt_entry_valid_1 = 1;
		update_fpte_wqe->fpte_data_1	   = info->entry[1].data;
	}
	if (wqe_entries == 3) {
		update_fpte_wqe->fpte_cmd_2	   = info->entry[2].cmd;
		update_fpte_wqe->fpt_entry_valid_2 = 1;
		update_fpte_wqe->fpte_data_2	   = info->entry[2].data;
	}
	update_fpte_wqe->fpt_entry_cnt = (u64)mem_entries;
	update_fpte_wqe->op	       = SXE2_MQ_OP_UPDATE_FPT;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_fpte",
		     &rdma_dev->rdma_func->mq.err_cqe_val, update_fpte_wqe);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_fpte");
#endif

	dma_wmb();
	update_fpte_wqe->wqe_valid = mq->polarity;
	wqe_start		   = (u64 *)wqe;
	for (i = 0; i < SXE2_RCMS_MQ_WQE_LEN; i++) {
		DRV_RDMA_LOG_DEV_DEBUG("RCMS:update fpte wqe 64bit[%u]=%#llx\n",
				       i, wqe_start[i]);
	}

end:
	return ret;
}

int sxe2_rcms_update_fptes_cmd(struct sxe2_rdma_ctx_dev *dev,
			       struct sxe2_rcms_update_fptes_info *info)
{
	int ret = SXE2_OK;
	u32 error;
	u32 val				  = 0;
	u32 tail			  = 0;
	struct sxe2_mq_ctx *mq		  = dev->mq;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:update fpte cmd info pointer is null\n");
		ret = -EINVAL;
		goto end;
	}

	ret = sxe2_rcms_update_fpte_wqe_fill(mq, info,
					     SXE2_RCMS_MQ_CMD_NO_SCRATCH);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:update fpte wqe fill err ret=%d\n",
				     ret);
		goto end;
	}

	sxe2_kget_mq_reg_info(mq, &val, &tail, &error);
	sxe2_kpost_mq(mq);
	ret = sxe2_kpoll_mq_registers(mq, tail,
				      mq->dev->hw_attrs.max_done_count);
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	if (rdma_dev->rdma_func->mq.ops_failed[MQ_OP_UPDATE_FPT] && !ret) {
		DRV_RDMA_LOG_DEV_DEBUG("MQ:opcode %u inject op failed tri\n",
				       MQ_OP_UPDATE_FPT);
		ret = -EBUSY;
	}
#endif

	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:update fpte kpoll mq registers err ret=%d\n",
			ret);
	}

end:
	return ret;
}

int sxe2_rcms_update_pe_fptes(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rcms_update_fptes_info *info,
			      u64 scratch)
{
	int ret				  = SXE2_OK;
	struct sxe2_mq_ctx *mq		  = dev->mq;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!info) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:update pe fptes info pointer is null\n");
		ret = -EINVAL;
		goto end;
	}

	ret = sxe2_rcms_update_fpte_wqe_fill(mq, info, scratch);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:update pe fpte wqe fill err ret=%d\n", ret);
		goto end;
	}
	sxe2_kpost_mq(mq);
end:
	return ret;
}

int sxe2_rcms_update_fptes_cmd_complete(
	struct sxe2_rdma_ctx_dev *dev, struct sxe2_rcms_update_fptes_info *info)
{
	int ret = SXE2_OK;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	mq_request = sxe2_kalloc_and_get_mq_request(&rdma_func->mq, true);
	if (!mq_request) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:get mq request err\n");
		ret = -ENOMEM;
		goto end;
	}

	mq_info = &mq_request->info;
	memcpy(&mq_info->in.u.update_pe_fptes.info, info,
	       sizeof(mq_info->in.u.update_pe_fptes.info));
	mq_info->mq_cmd			      = MQ_OP_UPDATE_FPT;
	mq_info->post_mq		      = 1;
	mq_info->in.u.update_pe_fptes.dev     = dev;
	mq_info->in.u.update_pe_fptes.scratch = (uintptr_t)mq_request;
	ret = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:update fptes khandle mq cmd err ret=%d\n", ret);
	}
	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return ret;
}

int sxe2_rcms_update_fptes(struct sxe2_rdma_ctx_dev *dev,
			   struct sxe2_rcms_info *rcms_info,
			   u16 *fpte_index_addr, u32 fpte_cnt, bool seted)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_update_fptes_info *update_fpte_info;
	u16 fpte_index;
	u64 fpte_pa;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	update_fpte_info = kzalloc(
		sizeof(*update_fpte_info), GFP_KERNEL);
	if (!update_fpte_info) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:alloc update fpte info err\n");
		ret = -ENOMEM;
		goto end;
	}
	update_fpte_info->cnt	     = 0;
	update_fpte_info->rcms_fn_id = rcms_info->rcms_fn_id;
	for (i = 0; i < fpte_cnt; i++) {
		fpte_index = fpte_index_addr[i];
		fpte	   = &rcms_info->fpt.fpte[fpte_index];
		if (!fpte || (!fpte->valid && seted) ||
		    (fpte->valid && !seted)) {
			continue;
		}
		if (seted) {
			fpte_pa = (fpte->entry_type ==
				   SXE2_RCMS_FPT_TYPE_SECOND) ?
					  fpte->u.spt.spt_page_addr.pa :
					  fpte->u.cp.page_addr.pa;
			sxe2_rcms_set_fpte(
				fpte_pa, fpte_index, fpte->entry_type,
				&update_fpte_info->entry[update_fpte_info->cnt]);
		} else {
			sxe2_rcms_clr_fpte(
				fpte_index, fpte->entry_type,
				&update_fpte_info->entry[update_fpte_info->cnt]);
		}
		update_fpte_info->cnt++;
		if (update_fpte_info->cnt ==
		    SXE2_RCMS_MAX_UPDATE_FPTE_ENTRIES) {
			ret = dev->mq->process_mq_fpt(dev, update_fpte_info);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS:mq update fpte err ret=%d\n",
					ret);
				goto free_update_info;
			}
			update_fpte_info->cnt = 0;
		}
	}
	if (update_fpte_info->cnt) {
		ret = dev->mq->process_mq_fpt(dev, update_fpte_info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR("RCMS:mq update fpte err ret=%d\n",
					     ret);
		}
	}
free_update_info:
	kfree(update_fpte_info);
end:
	return ret;
}

int sxe2_rcms_vf_update_fptes(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rcms_info *rcms_info,
			      u16 *fpte_index_addr, u32 fpte_cnt, bool seted)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rcms_vf_update_fptes_info *update_vf_fpte_info;
	u16 fpte_index;
	u64 fpte_pa;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	update_vf_fpte_info = kzalloc(sizeof(*update_vf_fpte_info), GFP_KERNEL);
	if (!update_vf_fpte_info) {
		DRV_RDMA_LOG_ERROR_BDF(
					"RCMS:alloc update vf fpte info err\n");
		ret = -ENOMEM;
		goto end;
	}

	update_vf_fpte_info->set = seted;

	for (i = 0; i < fpte_cnt; i++) {
		fpte_index = fpte_index_addr[i];
		fpte	   = &rcms_info->fpt.fpte[fpte_index];
		if (!fpte || (!fpte->valid && seted) ||
		    (fpte->valid && !seted)) {
			continue;
		}
		if (seted) {
			fpte_pa = (fpte->entry_type ==
				   SXE2_RCMS_FPT_TYPE_SECOND) ?
					  fpte->u.spt.spt_page_addr.pa :
					  fpte->u.cp.page_addr.pa;
			sxe2_rcms_set_fpte(
				fpte_pa, fpte_index, fpte->entry_type,
				&(update_vf_fpte_info
					 ->entry[update_vf_fpte_info->cnt]));
		} else {
			sxe2_rcms_clr_fpte(
				fpte_index, fpte->entry_type,
				&(update_vf_fpte_info
					 ->entry[update_vf_fpte_info->cnt]));
		};
		update_vf_fpte_info->cnt++;
		if (update_vf_fpte_info->cnt ==
			SXE2_RCMS_VF_MAX_UPDATE_FPTE_ENTRIES) {
			ret = sxe2_vchnl_req_update_fpte(dev,
							 update_vf_fpte_info);
			if (ret != SXE2_OK)
				goto free_info;
			memset(update_vf_fpte_info, 0,
			       sizeof(*update_vf_fpte_info));
			update_vf_fpte_info->set = seted;
		}
	}
	if (update_vf_fpte_info->cnt)
		ret = sxe2_vchnl_req_update_fpte(dev, update_vf_fpte_info);

free_info:
	kfree(update_vf_fpte_info);
end:
	return ret;
}

static int sxe2_rcms_finish_add_fpte_reg(struct sxe2_rdma_ctx_dev *dev,
					 struct sxe2_rcms_create_obj_info *info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!info->add_fpte_cnt)
		goto end;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "rcms_ctx_err_qp", info,
		     &rdma_dev->rdma_func->mq.err_cqe_val);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_ctx_err_qp");

	INJECT_START(rdma_dev->rdma_func, "rcms_ctx_err_ssnt", info,
		     &rdma_dev->rdma_func->mq.err_cqe_val);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "rcms_ctx_err_ssnt");
#endif

	if (dev->privileged) {
		ret = sxe2_rcms_update_fptes(dev, info->rcms_info,
					     &info->rcms_info->fpte_indexes[0],
					     info->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEBUG_BDF("update pf fpte err ret=%d\n",
					       ret);
		}
	} else {
		ret = sxe2_rcms_vf_update_fptes(
			dev, info->rcms_info, &info->rcms_info->fpte_indexes[0],
			info->add_fpte_cnt, true);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEBUG_BDF("update vf fpte err ret=%d\n",
					       ret);
		}
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	g_inject_fpte_err = 0;
#endif

end:
	return ret;
}

int sxe2_rcms_remove_spt_entry(struct sxe2_rdma_ctx_dev *dev,
			       struct sxe2_rcms_info *rcms_info, u32 spte_index)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_spt_entry *spte;
	struct sxe2_rcms_spt *spt;
	struct sxe2_rcms_fpt_entry *fpte;
	u32 fpte_index;
	u32 rel_spt_idx;
	u64 *spt_page_addr;
	struct sxe2_rdma_dma_mem *page_mem;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	fpte_index = spte_index / SXE2_RCMS_SPT_ENTRY_CNT;
	rel_spt_idx = REL_SPTE_INDEX_GET(spte_index);
	if (fpte_index > rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:remove spte input fpte index out of bounds fpte index=%u max fpte index=%u\n",
			fpte_index, rcms_info->max_fpte_index);
		ret = -EINVAL;
		goto end;
	}
	fpte = &rcms_info->fpt.fpte[fpte_index];
	if (fpte->entry_type != SXE2_RCMS_FPT_TYPE_SECOND) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:remove spte fpte %u type is not second type = %u\n",
			fpte_index, rcms_info->fpt.fpte[fpte_index].entry_type);
		ret = -EINVAL;
		goto end;
	}

	spt  = &fpte->u.spt;
	spte = &spt->spte[rel_spt_idx];
	if (--spte->cp.use_cnt)
		goto end;

	spte->valid = false;
	spt->use_cnt--;
	spt_page_addr = spt->spt_page_addr.va;
	spt_page_addr += rel_spt_idx;
	memset(spt_page_addr, SXE2_RCMS_SPTE_INVALID_VAL, sizeof(u64));
	sxe2_rcms_invalidate_spt_cache(dev, fpte_index, rel_spt_idx);
	page_mem = &spte->cp.page_addr;
	if (!page_mem || !page_mem->va) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:cp page mem err\n");
		ret = -EINVAL;
		goto end;
	}
	dma_free_coherent(dev->hw->device, page_mem->size, page_mem->va,
			  page_mem->pa);
	page_mem->va = NULL;
	if (!spt->use_cnt) {
		if (spt->spte_virt_mem.va != NULL) {
			kfree(spt->spte_virt_mem.va);
			spt->spte_virt_mem.va = NULL;
		}
	}

end:
	return ret;
}

void sxe2_rcms_remove_fpt_entry(struct sxe2_rdma_ctx_dev *dev,
				struct sxe2_rcms_info *rcms_info,
				u32 fpte_index,
				enum sxe2_rcms_fpt_entry_type fpte_type)
{
	struct sxe2_rcms_fpt_entry *fpte = &rcms_info->fpt.fpte[fpte_index];

	if (fpte->valid) {
		fpte->valid = false;
		rcms_info->fpt.use_cnt--;
	}

	if (fpte_type == SXE2_RCMS_FPT_TYPE_FIRST) {
		if (!fpte->u.cp.use_cnt && fpte->u.cp.page_addr.va) {
			dma_free_coherent(dev->hw->device,
					  fpte->u.cp.page_addr.size,
					  fpte->u.cp.page_addr.va,
					  fpte->u.cp.page_addr.pa);
			fpte->u.cp.page_addr.va = NULL;
		}
	} else if (fpte_type == SXE2_RCMS_FPT_TYPE_SECOND) {
		if (!fpte->u.spt.use_cnt && fpte->u.spt.spt_page_addr.va) {
			dma_free_coherent(dev->hw->device,
					  fpte->u.spt.spt_page_addr.size,
					  fpte->u.spt.spt_page_addr.va,
					  fpte->u.spt.spt_page_addr.pa);
			fpte->u.spt.spt_page_addr.va = NULL;
		}
		if (!fpte->u.spt.use_cnt && fpte->u.spt.spte_virt_mem.va) {
			kfree(fpte->u.spt.spte_virt_mem.va);
			fpte->u.spt.spte_virt_mem.va = NULL;
		}
	}
}

static int sxe2_rcms_prep_remove_fpte_cp(struct sxe2_rcms_info *rcms_info,
					 u32 fpte_index)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;

	fpte = &rcms_info->fpt.fpte[fpte_index];
	if (--fpte->u.cp.use_cnt) {
		ret = -EBUSY;
		goto end;
	}
	fpte->valid = false;
	rcms_info->fpt.use_cnt--;
end:
	return ret;
}

static int sxe2_rcms_prep_remove_fpte_spt(struct sxe2_rcms_info *rcms_info,
					  u32 fpte_index)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;

	fpte = &rcms_info->fpt.fpte[fpte_index];
	if (fpte->u.spt.use_cnt) {
		ret = -EBUSY;
		goto end;
	}
	fpte->valid = false;
	rcms_info->fpt.use_cnt--;
end:
	return ret;
}

int sxe2_rcms_build_first_type_table(struct sxe2_rdma_ctx_dev *dev,
				     struct sxe2_rcms_create_obj_info *obj_info)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;
	u32 fpte_idx;
	u32 fpte_lmt;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	sxe2_rcms_get_obj_fpte_range(obj_info->rcms_info, obj_info->rsrc_type,
				     obj_info->start_idx, obj_info->obj_cnt,
				     &fpte_idx, &fpte_lmt);
	DRV_RDMA_LOG_DEV_DEBUG(
		"RCMS:obj %u min fpte index=%u lmt fpte index=%u\n",
		obj_info->rsrc_type, fpte_idx, fpte_lmt);
	if (fpte_idx > obj_info->rcms_info->max_fpte_index ||
	    (fpte_lmt - 1) > obj_info->rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:obj %u fpte idx range err fpte idx=%u fpte lmt=%u fpte cnt=%u\n",
			obj_info->rsrc_type, fpte_idx, fpte_lmt,
			obj_info->rcms_info->fpt.fpte_cnt);
		ret = -EINVAL;
		goto end;
	}

	for (i = fpte_idx; i < fpte_lmt; i++) {
		ret = sxe2_rcms_add_fpt_entry(dev, obj_info->rcms_info, i,
					      obj_info->entry_type);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:obj %u add fpte %u err ret=%d\n",
				obj_info->rsrc_type, i, ret);
			goto fpte_err;
		}
		fpte = &obj_info->rcms_info->fpt.fpte[i];
		if (fpte->valid)
			continue;

		fpte->valid = true;

		obj_info->rcms_info->fpte_indexes[obj_info->add_fpte_cnt] =
			(u16)i;
		obj_info->add_fpte_cnt++;
	}
	goto end;

fpte_err:
	while (i && (i > fpte_idx)) {
		i--;
		fpte = &obj_info->rcms_info->fpt.fpte[i];
		fpte->u.cp.use_cnt--;
	}
	while (obj_info->add_fpte_cnt) {
		obj_info->add_fpte_cnt--;
		sxe2_rcms_remove_fpt_entry(
			dev, obj_info->rcms_info,
			obj_info->rcms_info
				->fpte_indexes[obj_info->add_fpte_cnt],
			obj_info->entry_type);
	}

end:
	return ret;
}

static int sxe2_rcms_finish_clr_fpte_reg(struct sxe2_rdma_ctx_dev *dev,
					 struct sxe2_rcms_del_obj_info *info,
					 bool reset, bool mq_update)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;
	struct sxe2_rdma_dma_mem *mem;
	u16 fpte_idx;
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!info->del_fpte_cnt)
		goto end;

	if (dev->privileged && !reset && mq_update) {
		ret = sxe2_rcms_update_fptes(dev, info->rcms_info,
					     &info->rcms_info->fpte_indexes[0],
					     info->del_fpte_cnt, false);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:pf finish clr fpte error ret=%d\n", ret);
		}
	} else if (!dev->privileged && !reset && mq_update) {
		ret = sxe2_rcms_vf_update_fptes(
			dev, info->rcms_info, &info->rcms_info->fpte_indexes[0],
			info->del_fpte_cnt, false);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_ERROR_BDF(
				"RCMS:vf finish clr fpte error ret=%d\n", ret);
		}
	}

	for (i = 0; i < info->del_fpte_cnt; i++) {
		fpte_idx = info->rcms_info->fpte_indexes[i];
		fpte	 = &info->rcms_info->fpt.fpte[fpte_idx];
		mem	 = (fpte->entry_type == SXE2_RCMS_FPT_TYPE_SECOND) ?
			      &fpte->u.spt.spt_page_addr :
			      &fpte->u.cp.page_addr;
		if (!mem || !mem->va) {
			DRV_RDMA_LOG_DEV_ERR("RCMS:fpte %u mem err\n",
					       fpte_idx);
		} else {
			DRV_RDMA_LOG_DEV_DEBUG(
				"RCMS:free fpte %u mem pa=0x%llx\n", fpte_idx,
				mem->pa);
			dma_free_coherent(dev->hw->device, mem->size, mem->va,
					  mem->pa);
			mem->va = NULL;
		}
	}
end:
	return ret;
}

int sxe2_rcms_build_second_type_table(struct sxe2_rdma_ctx_dev *dev,
				      struct sxe2_rcms_create_obj_info *obj_info)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_fpt_entry *fpte;
	u32 fpte_idx, fpte_lmt;
	u32 spte_idx, spte_lmt;
	u32 spte_idx_range		  = 0;
	u32 spte_lmt_range		  = 0;
	u32 i				  = 0;
	u32 j				  = 0;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	sxe2_rcms_get_obj_fpte_range(obj_info->rcms_info, obj_info->rsrc_type,
				     obj_info->start_idx, obj_info->obj_cnt,
				     &fpte_idx, &fpte_lmt);
	if (fpte_idx > obj_info->rcms_info->max_fpte_index ||
	    (fpte_lmt - 1) > obj_info->rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:obj %u fpte idx range err fpte idx=%u fpte lmt=%u fpte cnt=%u\n",
			obj_info->rsrc_type, fpte_idx, fpte_lmt,
			obj_info->rcms_info->fpt.fpte_cnt);
		ret = -EINVAL;
		goto end;
	}
	sxe2_rcms_get_obj_spte_range(obj_info->rcms_info, obj_info->rsrc_type,
				     obj_info->start_idx, obj_info->obj_cnt,
				     &spte_idx, &spte_lmt);
	DRV_RDMA_LOG_DEV_DEBUG(
		"RCMS:obj %u min spte index=%u lmt spte index=%u\n",
		obj_info->rsrc_type, spte_idx, spte_lmt);

	for (i = fpte_idx; i < fpte_lmt; i++) {
		ret = sxe2_rcms_add_fpt_entry(dev, obj_info->rcms_info, i,
					      obj_info->entry_type);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:obj %u second mode add fpte %u err ret=%d\n",
				obj_info->rsrc_type, i, ret);
			goto fpte_err;
		}
		fpte = &obj_info->rcms_info->fpt.fpte[i];
		spte_idx_range = max(spte_idx, i * SXE2_RCMS_SPT_ENTRY_CNT);
		spte_lmt_range =
			min(spte_lmt, (i + 1) * SXE2_RCMS_SPT_ENTRY_CNT);
		for (j = spte_idx_range; j < spte_lmt_range; j++) {
			if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_SECOND &&
			    (dev->rcms_info == obj_info->rcms_info &&
			     obj_info->rsrc_type != SXE2_RCMS_OBJ_PBLE)) {
				ret = sxe2_rcms_add_spt_entry(
					dev, obj_info->rcms_info, j);
				if (ret != SXE2_OK) {
					DRV_RDMA_LOG_DEV_ERR(
						"RCMS:obj %u second mode add spte %u err ret=%d\n",
						obj_info->rsrc_type, j, ret);
					goto spte_err;
				}
			}
		}
		if (fpte->valid)
			continue;

		obj_info->rcms_info->fpte_indexes[obj_info->add_fpte_cnt] =
			(u16)i;
		obj_info->add_fpte_cnt++;
		fpte->valid = true;
	}
	goto end;
spte_err:
	while (j && (j > spte_idx_range)) {
		j--;
		sxe2_rcms_remove_spt_entry(dev, obj_info->rcms_info, j);
	}

	if (fpte->valid == false) {
		sxe2_rcms_remove_fpt_entry(dev, obj_info->rcms_info, i,
					   obj_info->entry_type);
	} else {
		fpte->u.cp.use_cnt--;
	}
fpte_err:
	while (i && (i > fpte_idx)) {
		i--;
		spte_idx_range = max(spte_idx, i * SXE2_RCMS_SPT_ENTRY_CNT);
		spte_lmt_range =
			min(spte_lmt, (i + 1) * SXE2_RCMS_SPT_ENTRY_CNT);
		j = spte_lmt_range;
		while (j > spte_idx_range) {
			j--;
			sxe2_rcms_remove_spt_entry(dev, obj_info->rcms_info, j);
		}
	}
	while (obj_info->add_fpte_cnt) {
		obj_info->add_fpte_cnt--;
		sxe2_rcms_remove_fpt_entry(
			dev, obj_info->rcms_info,
			obj_info->rcms_info
				->fpte_indexes[obj_info->add_fpte_cnt],
			obj_info->entry_type);
	}
end:
	return ret;
}

int sxe2_rcms_del_obj(struct sxe2_rdma_ctx_dev *dev,
		      struct sxe2_rcms_del_obj_info *info, bool reset,
		      bool mq_update)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_spt *spt;
	struct sxe2_rcms_fpt_entry *fpte;
	u32 fpte_idx, fpte_lmt;
	u32 spte_idx, spte_lmt, rel_spte_idx;
	u32 i, j;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (info->start_idx > info->rcms_info->rcms_obj[info->rsrc_type].cnt ||
	    (info->start_idx + info->obj_cnt) >
		    info->rcms_info->rcms_obj[info->rsrc_type].cnt) {
		DRV_RDMA_LOG_ERROR_BDF(
			"RCMS:idx err start idx=%u obj type=%u max cnt=%u\n",
			info->start_idx, info->rsrc_type,
			info->rcms_info->rcms_obj[info->rsrc_type].cnt);
		ret = -EINVAL;
		goto end;
	}
	sxe2_rcms_get_obj_spte_range(info->rcms_info, info->rsrc_type,
				     info->start_idx, info->obj_cnt, &spte_idx,
				     &spte_lmt);
	DRV_RDMA_LOG_DEV_DEBUG("RCMS:del obj %u spte idx=%u spte lmt =%u\n",
			       info->rsrc_type, spte_idx, spte_lmt);
	for (i = spte_idx; i < spte_lmt; i++) {
		fpte_idx = SPT_IDX_TO_FPT_IDX(i);
		if (fpte_idx > info->rcms_info->max_fpte_index) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:del obj %u invalid fpte idx fpte idx=%u max_idx = %u\n",
				info->rsrc_type, fpte_idx,
				info->rcms_info->max_fpte_index);
			ret = -EINVAL;
			goto end;
		}
		if (!info->rcms_info->fpt.fpte[fpte_idx].valid)
			continue;

		if (info->rcms_info->fpt.fpte[fpte_idx].entry_type !=
		    SXE2_RCMS_FPT_TYPE_SECOND) {
			continue;
		}
		rel_spte_idx = REL_SPTE_INDEX_GET(i);
		spt	     = &info->rcms_info->fpt.fpte[fpte_idx].u.spt;
		if (spt->spte && spt->spte[rel_spte_idx].valid) {
			ret = sxe2_rcms_remove_spt_entry(dev, info->rcms_info,
							 i);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS:del obj remove spte %u err ret=%d\n",
					i, ret);
				goto end;
			}
		}
	}
	sxe2_rcms_get_obj_fpte_range(info->rcms_info, info->rsrc_type,
				     info->start_idx, info->obj_cnt, &fpte_idx,
				     &fpte_lmt);
	if (fpte_idx > info->rcms_info->max_fpte_index ||
	    (fpte_lmt - 1) > info->rcms_info->max_fpte_index) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: del obj %u invalid fpte idx fpte idx=%u fpte_lmt=%u max_idx = %u\n",
			info->rsrc_type, fpte_idx, fpte_lmt,
			info->rcms_info->max_fpte_index);
		ret = -EINVAL;
		goto end;
	}
	for (j = fpte_idx; j < fpte_lmt; j++) {
		fpte = &info->rcms_info->fpt.fpte[j];
		if (!info->rcms_info->fpt.fpte[j].valid)
			continue;

		if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_FIRST) {
			ret = sxe2_rcms_prep_remove_fpte_cp(info->rcms_info, j);
		} else if (fpte->entry_type == SXE2_RCMS_FPT_TYPE_SECOND) {
			ret = sxe2_rcms_prep_remove_fpte_spt(info->rcms_info,
							     j);
			if (dev->rcms_info != info->rcms_info &&
			    info->rsrc_type == SXE2_RCMS_OBJ_PBLE &&
			    fpte->u.spt.spte) {
				kfree(fpte->u.spt.spte_virt_mem.va);
				fpte->u.spt.spte_virt_mem.va = NULL;
				fpte->u.spt.spte	     = NULL;
			}
		}
		if (ret == SXE2_OK) {
			info->rcms_info->fpte_indexes[info->del_fpte_cnt] =
				(u16)j;
			info->del_fpte_cnt++;
		} else {
			ret = SXE2_OK;
		}
	}
	ret = sxe2_rcms_finish_clr_fpte_reg(dev, info, reset, mq_update);
end:
	return ret;
}

static int sxe2_rcms_del_obj_type(struct sxe2_rdma_ctx_dev *dev,
				  enum sxe2_rcms_rsrc_type obj_type,
				  struct sxe2_rcms_info *rcms_info,
				  bool privileged, bool reset, bool mq_update)
{
	int ret				   = SXE2_OK;
	struct sxe2_rcms_del_obj_info info = {};
	struct sxe2_rdma_device *rdma_dev  = to_rdmadev(dev);

	info.rcms_info	  = rcms_info;
	info.rsrc_type	  = obj_type;
	info.privileged	  = privileged;
	info.del_fpte_cnt = 0;
	info.start_idx	  = 0;
	info.obj_cnt	  = rcms_info->rcms_obj[obj_type].cnt;
	ret = sxe2_rcms_del_obj(dev, &info, reset, mq_update);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF("RCMS:del obj %u err ret=%d\n", obj_type,
				     ret);
	}

	return ret;
}

void sxe2_rcms_del_objs(struct sxe2_rdma_ctx_dev *dev,
			struct sxe2_rcms_info *rcms_info, bool privileged,
			bool reset, bool mq_update)
{
	u32 i;

	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		if (dev->rcms_info->rcms_obj[i].cnt) {
			sxe2_rcms_del_obj_type(dev, i, rcms_info, privileged,
					       reset, mq_update);
		}
	}
}

int sxe2_rcms_create_obj(struct sxe2_rdma_ctx_dev *dev,
			 struct sxe2_rcms_create_obj_info *obj_info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	if (obj_info->start_idx >=
		    obj_info->rcms_info->rcms_obj[obj_info->rsrc_type].cnt ||
	    (obj_info->start_idx + obj_info->obj_cnt) >
		    obj_info->rcms_info->rcms_obj[obj_info->rsrc_type].cnt) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: invalid hmc obj type %u, start = %u, req cnt %u, cnt = %u\n",
			obj_info->rsrc_type, obj_info->start_idx,
			obj_info->obj_cnt,
			obj_info->rcms_info->rcms_obj[obj_info->rsrc_type].cnt);
		ret = -EINVAL;
		goto end;
	}

	if (obj_info->init_mode == FIRST_PAGE_TABLE) {
		ret = sxe2_rcms_build_first_type_table(dev, obj_info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:obj %u build first type table err ret=%d\n",
				obj_info->rsrc_type, ret);
			goto end;
		}
	} else {
		ret = sxe2_rcms_build_second_type_table(dev, obj_info);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"RCMS:obj %u build second type table err ret=%d\n",
				obj_info->rsrc_type, ret);
			goto end;
		}
	}

	ret = sxe2_rcms_finish_add_fpte_reg(dev, obj_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:obj %u update fpte err ret=%d\n",
				     obj_info->rsrc_type, ret);
		goto update_fpte_err;
	}
	goto end;
update_fpte_err:
	sxe2_rcms_del_obj_type(dev, obj_info->rsrc_type, dev->rcms_info,
			       obj_info->privileged, rdma_func->reset, false);
end:
	return ret;
}

static int sxe2_rcms_pf_create_objs(struct sxe2_rdma_pci_f *rdma_func,
				    bool privileged)
{
	int ret				      = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	      = &rdma_func->ctx_dev;
	struct sxe2_rcms_create_obj_info info = {};
	u32 i;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	info.rcms_info	= dev->rcms_info;
	info.privileged = privileged;
	info.init_mode	= dev->rcms_info->create_mode;
	info.entry_type = info.init_mode == FIRST_PAGE_TABLE ?
				  SXE2_RCMS_FPT_TYPE_FIRST :
				  SXE2_RCMS_FPT_TYPE_SECOND;
	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		if (i == SXE2_RCMS_OBJ_PBLE)
			continue;
		if (dev->rcms_info->rcms_obj[i].cnt) {
			info.rsrc_type = i;
			info.add_fpte_cnt = 0;
			info.start_idx	  = 0;
			info.obj_cnt	  = dev->rcms_info->rcms_obj[i].cnt;
			ret = sxe2_rcms_create_obj(dev, &info);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS:create rcms obj %u err ret=%d\n",
					i, ret);
				goto close_obj;
			}
		}
	}
	goto end;

close_obj:
	while (i) {
		i--;
		if (dev->rcms_info->rcms_obj[i].cnt) {
			sxe2_rcms_del_obj_type(dev, i, dev->rcms_info,
					       privileged, false, true);
		}
	}
end:
	return ret;
}

static int sxe2_rcms_alloc_vf_query_fpm_buf(struct sxe2_rdma_ctx_dev *dev,
					    struct sxe2_rdma_dma_mem *mem)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	ret = sxe2_kget_aligned_mem(rdma_func, mem, SXE2_QUERY_FPM_BUF_SIZE,
				    SXE2_FPM_QUERY_BUF_ALIGNMENT_M);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("rcms:alloc vf query fpm buf err ret=%d\n",
				     ret);
	}
	return ret;
}

static int
sxe2_rcms_pf_query_vf_fpm_val(struct sxe2_rdma_vchnl_dev *vc_dev, u8 vf_pmf_idx,
			      struct sxe2_rdma_dma_mem *query_fpm_mem)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);

	ret = sxe2_rcms_query_fpm_val_cmd_complete(vc_dev->pf_dev,
						   query_fpm_mem, vf_pmf_idx);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: vf %u pmf id %u mq query vf fpm val err ret=%d\n",
			vc_dev->vf_id, vf_pmf_idx, ret);
		goto end;
	}
	sxe2_rcms_parse_fpm_query_buf(vc_dev->pf_dev, query_fpm_mem->va,
				      &vc_dev->rcms_info);
end:
	return ret;
}

static int
sxe2_rcms_pf_commit_vf_fpm_val(struct sxe2_rdma_ctx_dev *dev, u8 vf_pmf_idx,
			       struct sxe2_rdma_dma_mem *commit_fpm_mem,
			       struct sxe2_rcms_info *rcms_info)
{
	int ret = SXE2_OK;
	__le32 *buf;
	struct sxe2_rcms_obj_info *obj_info;
	u32 i;
	u32 start_byte = 0;
	u32 base_val;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	buf	 = (__le32 *)(commit_fpm_mem->va);
	obj_info = rcms_info->rcms_obj;
	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		base_val = (u32)(
			(obj_info[i].base >> SXE2_RCMS_OBJ_LINER_BASE_SHIFT) &
			SXE2_RCMS_OBJ_BASE_MASK);
		set_32bit_val(buf, start_byte, base_val);
		start_byte += SXE2_RCMS_COMMIT_BUF_SHIFT;
		set_32bit_val(buf, start_byte, obj_info[i].cnt);
		start_byte += SXE2_RCMS_COMMIT_BUF_SHIFT;
	}
	set_32bit_val(buf, SXE2_RCMS_MAX_FPTE_CNT_BUF_OFFSET,
		      rcms_info->max_fpte_cnt);
	set_32bit_val(buf, SXE2_RCMS_CEQS_DB_BUF_OFFSET, rcms_info->max_ceqs);
	ret = sxe2_rcms_commit_fpm_val_cmd_complete(dev, commit_fpm_mem,
						    vf_pmf_idx);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:func id %u commit vf fpm val cmd err ret=%d\n",
			vf_pmf_idx, ret);
	}
	return ret;
}

static int sxe2_rcms_pf_query_commit_vf_fpm_val(
	struct sxe2_rdma_vchnl_dev *vc_dev, u8 vf_pmf_idx,
	struct sxe2_rdma_dma_mem *fpm_mem, struct sxe2_rcms_info *rcms_info)
{
	int ret = SXE2_OK;
	u32 qp_limit_cnt;
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(vc_dev->pf_dev);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(vc_dev->pf_dev);

	qp_limit_cnt = g_rsrc_limits_table[rdma_func->limits_sel].qp_limit;
	ret = sxe2_rcms_pf_query_vf_fpm_val(vc_dev, vf_pmf_idx, fpm_mem);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: vmf id %u mq query vf fpm val err ret=%d\n",
			vf_pmf_idx, ret);
		goto end;
	}
	ret = sxe2_rcms_modify_fpm_val(vc_dev->pf_dev, rcms_info, qp_limit_cnt);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: vmf id %u modify vf fpm val err ret=%d\n",
			vf_pmf_idx, ret);
		goto end;
	}
	sxe2_rcms_get_obj_liner_base(vc_dev->pf_dev, rcms_info);
	ret = sxe2_rcms_pf_commit_vf_fpm_val(vc_dev->pf_dev, vf_pmf_idx,
					     fpm_mem, rcms_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: vmf id %u mq commit vf fpm val err ret=%d\n",
			vf_pmf_idx, ret);
		goto end;
	}
	rcms_info->fpt.fpte = NULL;

end:
	return ret;
}

int sxe2_rcms_pf_config_vf_fpm_val(struct sxe2_rdma_vchnl_dev *vc_dev)
{
	int ret = SXE2_OK;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_rdma_dma_mem query_fpm_mem;
	u16 vf_idx;
	struct sxe2_rdma_ctx_dev *dev	  = vc_dev->pf_dev;
	u8 vf_pmf_idx			  = (u8)(vc_dev->pmf_index);
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if ((!dev->privileged) ||
	    (vf_pmf_idx > dev->hw_attrs.max_hw_vf_fpm_id ||
	     vf_pmf_idx < dev->hw_attrs.first_hw_vf_fpm_id)) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:dev if pf err or vf pmf id err dev privileged=%u id=%u\n",
			dev->privileged, vf_pmf_idx);
		ret = -EINVAL;
		goto end;
	}

	rcms_info = &vc_dev->rcms_info;
	vf_idx	  = vc_dev->vf_idx;
	if (!vc_dev->fpm_query_buf) {
		if (!dev->vf_fpm_query_buf[vf_idx].va) {
			ret = sxe2_rcms_alloc_vf_query_fpm_buf(
				dev, &dev->vf_fpm_query_buf[vf_idx]);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS: alloc vf query fpm buf err ret=%d\n",
					ret);
				goto end;
			}
		}
		vc_dev->fpm_query_buf	 = dev->vf_fpm_query_buf[vf_idx].va;
		vc_dev->fpm_query_buf_pa = dev->vf_fpm_query_buf[vf_idx].pa;
	}
	query_fpm_mem.pa      = vc_dev->fpm_query_buf_pa;
	query_fpm_mem.va      = vc_dev->fpm_query_buf;
	rcms_info->rcms_fn_id = vf_pmf_idx;

	ret = sxe2_rcms_pf_query_commit_vf_fpm_val(vc_dev, vf_pmf_idx,
						   &query_fpm_mem, rcms_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS:vf %u pmf id %u query commit vf fpm val err ret=%d\n",
			vc_dev->vf_id, vf_pmf_idx, ret);
		ret = -EINVAL;
		goto end;
	}
end:
	return ret;
}

static int sxe2_rcms_vf_create_objs(struct sxe2_rdma_pci_f *rdma_func)
{
	int ret			      = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev = &rdma_func->ctx_dev;
	u32 i;
	struct sxe2_rdma_device *rdma_dev     = to_rdmadev(dev);
	struct sxe2_rcms_create_obj_info info = {};

	info.rcms_info	= dev->rcms_info;
	info.privileged = false;
	info.init_mode	= FIRST_PAGE_TABLE;
	info.entry_type = SXE2_RCMS_FPT_TYPE_FIRST;

	for (i = SXE2_RCMS_OBJ_QP; i < SXE2_RCMS_OBJ_MAX; i++) {
		if (i == SXE2_RCMS_OBJ_PBLE)
			continue;
		if (dev->rcms_info->rcms_obj[i].cnt) {
			info.rsrc_type	  = i;
			info.add_fpte_cnt = 0;
			info.start_idx	  = 0;
			info.obj_cnt	  = dev->rcms_info->rcms_obj[i].cnt;
			ret = sxe2_rcms_create_obj(dev, &info);
			if (ret != SXE2_OK) {
				DRV_RDMA_LOG_DEV_ERR(
					"RCMS:vf create rcms obj %u err ret=%d\n",
					i, ret);
				goto close_obj;
			}
		}
	}
	goto end;

close_obj:
	while (i) {
		i--;
		if (dev->rcms_info->rcms_obj[i].cnt) {
			sxe2_rcms_del_obj_type(dev, i, dev->rcms_info,
					       dev->privileged, false, true);
		}
	}
end:
	return ret;
}

static int sxe2_rcms_setup_vf(struct sxe2_rdma_pci_f *rdma_func)
{
	int ret = SXE2_OK;
	int i;
	struct sxe2_vchnl_init_vf_rcms_resp init_rcms_resp;
	struct sxe2_vchnl_vf_obj_resp vf_obj_resp;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_func->ctx_dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (dev->privileged) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: setup vf privileged err privileged=%u\n",
			dev->privileged);
		ret = -EINVAL;
		goto end;
	}

	if (!dev->rcms_info || !dev->rcms_info->rcms_obj) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: vf rcms info or obj pointer is null\n");
		ret = -ENOMEM;
		goto end;
	}

	ret = sxe2_vchnl_req_init_vf_rcms(dev, &init_rcms_resp);
	if (ret != SXE2_OK)
		goto end;

	rcms_info		    = dev->rcms_info;
	rcms_info->first_fpte_index = init_rcms_resp.first_fpte_index;
	rcms_info->max_fpte_index   = init_rcms_resp.max_fpte_index;
	rcms_info->max_fpte_cnt	    = init_rcms_resp.max_fpte_cnt;
	rcms_info->fpte_needed	    = init_rcms_resp.fpte_needed;
	rcms_info->max_ceqs	    = init_rcms_resp.max_ceqs;
	rcms_info->max_db_page_num  = init_rcms_resp.max_db_page_num;
	rcms_info->db_bar_addr	    = init_rcms_resp.db_bar_addr;
	rcms_info->first_page_fpte =
		rcms_info->max_fpte_cnt - rcms_info->fpte_needed;
	rcms_info->max_cc_qp_cnt = init_rcms_resp.max_cc_qp_cnt;

	for (i = 0; i < SXE2_RCMS_OBJ_MAX; i++)
		rcms_info->rcms_obj[i].cnt = init_rcms_resp.obj_max_cnt[i];

	rcms_info->fpt.fpte_cnt = rcms_info->fpte_needed;

	ret = sxe2_vchnl_req_get_vf_obj_info(dev, &vf_obj_resp);
	if (ret != SXE2_OK)
		goto end;

	for (i = 0; i < SXE2_RCMS_OBJ_MAX; i++) {
		rcms_info->rcms_obj[i].size = vf_obj_resp.obj_info[i].size;
		rcms_info->rcms_obj[i].base = vf_obj_resp.obj_info[i].base;
		DRV_RDMA_LOG_DEV_DEBUG(
			"RCMS:vf obj %u max cnt=%u size=%u base=%#llx\n", i,
			rcms_info->rcms_obj[i].cnt, rcms_info->rcms_obj[i].size,
			rcms_info->rcms_obj[i].base);
	}

	rcms_info->pmf_index   = init_rcms_resp.pmf_index;
	rcms_info->pf_max_ceqs = init_rcms_resp.pf_max_ceqs;
	DRV_RDMA_LOG_DEV_DEBUG(
		"RCMS VF Capability Val:\n"
		"\tvf pmf_index %#x pf_max_ceqs=%#x\n"
		"\tvf fpte needed=%u fpte first idx=%u max fpte idx=%u\n"
		"\tmax fpte cnt=%u first pgae fpte=%u\n"
		"\tvf max ceqs=%u max db page=%u db addr=%#x\n",
		rcms_info->pmf_index, rcms_info->pf_max_ceqs,
		rcms_info->fpte_needed, rcms_info->first_fpte_index,
		rcms_info->max_fpte_index, rcms_info->max_fpte_cnt,
		rcms_info->first_page_fpte, rcms_info->max_ceqs,
		rcms_info->max_db_page_num, rcms_info->db_bar_addr);

	ret = sxe2_rcms_alloc_fpt_entry_mem(dev, rcms_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: vf alloc fpt entry mem err ret=%d\n", ret);
		goto end;
	}
	ret = sxe2_rcms_vf_create_objs(rdma_func);
	if (ret != SXE2_OK)
		goto free_fpte_mem;

	goto end;

free_fpte_mem:
	kfree(rcms_info->fpt.fpte);
	rcms_info->fpt.fpte = NULL;
end:
	return ret;
}

static int sxe2_rcms_setup_pf(struct sxe2_rdma_pci_f *rdma_func)
{
	int ret = SXE2_OK;
	u32 qp_limit_cnt;
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_func->ctx_dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	if (!dev->rcms_info || !dev->rcms_info->rcms_obj) {
		DRV_RDMA_LOG_DEV_ERR(
			"RCMS: rcms info or obj pointer is null\n");
		ret = -ENOMEM;
		goto end;
	}
	if (rdma_func->rcms_mode.ctx_mode >= SXE2_RCMS_INIT_MODE_MAX) {
		DRV_RDMA_LOG_DEV_ERR("RCMS:rcms init mode err init mode=%u\n",
				     rdma_func->rcms_mode.ctx_mode);
		ret = -EINVAL;
		goto end;
	}
	if (rdma_func->rcms_mode.ctx_mode == SXE2_RCMS_FIRST_INIT_MODE)
		dev->rcms_info->create_mode = FIRST_PAGE_TABLE;
	else
		dev->rcms_info->create_mode = SECOND_PAGE_TABLE;

	qp_limit_cnt = g_rsrc_limits_table[rdma_func->limits_sel].qp_limit;
	dev->rcms_info->rcms_fn_id = dev->rcms_fn_id;
	ret = sxe2_rcms_pf_config_fpm_val(dev, qp_limit_cnt);
	if (ret != SXE2_OK)
		goto end;

	ret = sxe2_rcms_pf_create_objs(rdma_func, dev->privileged);
	if (ret != SXE2_OK)
		goto create_objs_err;

	goto end;
create_objs_err:
	if (dev->rcms_info->fpt.fpte != NULL) {
		kfree(dev->rcms_info->fpt.fpte);
		dev->rcms_info->fpt.fpte = NULL;
	}
end:
	return ret;
}

int sxe2_rcms_setup(struct sxe2_rdma_device *rdma_dev)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	DRV_RDMA_LOG_DEV_DEBUG("RCMS: setup rcms start\n");
	ret = drv_rdma_debug_rcms_add(rdma_dev, rdma_func->ctx_dev.rcms_info);
	if (ret != SXE2_OK)
		goto end;

	if (rdma_func->ftype == SXE2_RDMA_PF)
		ret = sxe2_rcms_setup_pf(rdma_func);
	else
		ret = sxe2_rcms_setup_vf(rdma_func);

	if (ret != SXE2_OK)
		goto end;

	DRV_RDMA_LOG_DEV_DEBUG("RCMS: setup rcms finish\n");
end:
	return ret;
}

void sxe2_rcms_exit(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_func->ctx_dev;

	DRV_RDMA_LOG_DEV_DEBUG("RCMS:exit rcms start privileged=%u\n",
			       dev->privileged);

	sxe2_rcms_del_objs(dev, dev->rcms_info, dev->privileged,
			   rdma_func->reset, true);
	if (dev->rcms_info->fpt.fpte != NULL) {
		kfree(dev->rcms_info->fpt.fpte);
		dev->rcms_info->fpt.fpte = NULL;
	}
	DRV_RDMA_LOG_DEV_DEBUG("RCMS:exit rcms finish privileged=%u\n",
			       dev->privileged);
}
