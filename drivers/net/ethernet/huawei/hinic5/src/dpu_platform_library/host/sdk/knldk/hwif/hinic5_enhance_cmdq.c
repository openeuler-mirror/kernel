/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_enhance_cmdq.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "ossl_knl.h"
#include "npu_cmdq_base_defs.h"
#include "comm_defs.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hw_api.h"
#include "hinic5_hwdev.h"
#include "hinic5_eqs.h"
#include "hinic5_common.h"
#include "hinic5_wq.h"
#include "hinic5_hw_comm.h"
#include "hinic5_cmdq.h"

void hinic5_enhanced_cmdq_init_queue_ctxt(struct hinic5_cmdqs *cmdqs, struct hinic5_cmdq *cmdq)
{
	struct enhance_cmdq_ctxt_info *ctxt_info = &cmdq->cmdq_enhance_ctxt;
	struct hinic5_wq *wq = &cmdq->wq;
	u64 cmdq_first_block_paddr, pfn;
	u16 start_ci = (u16)wq->cons_idx;
	u32 start_pi = (u16)wq->prod_idx;

	pfn = CMDQ_PFN(hinic5_wq_get_first_wqe_page_addr(wq));

	/* first part 16B */
	if (cmdq->cmdqs->poll) {
		ctxt_info->eq_cfg =
			ENHANCED_CMDQ_SET(pfn, CTXT0_CI_WQE_ADDR) |
			ENHANCED_CMDQ_SET(HINIC5_CEQ_ID_CMDQ, CTXT0_EQ) |
			ENHANCED_CMDQ_SET(0, CTXT0_CEQ_ARM) |
			ENHANCED_CMDQ_SET(0, CTXT0_CEQ_EN) |
			ENHANCED_CMDQ_SET(1, CTXT0_HW_BUSY_BIT);
	} else {
		ctxt_info->eq_cfg =
			ENHANCED_CMDQ_SET(pfn, CTXT0_CI_WQE_ADDR) |
			ENHANCED_CMDQ_SET(HINIC5_CEQ_ID_CMDQ, CTXT0_EQ) |
			ENHANCED_CMDQ_SET(1, CTXT0_CEQ_ARM) |
			ENHANCED_CMDQ_SET(1, CTXT0_CEQ_EN) |
			ENHANCED_CMDQ_SET(1, CTXT0_HW_BUSY_BIT);
	}

	ctxt_info->dfx_pi_ci =
		ENHANCED_CMDQ_SET(0, CTXT1_Q_DIS) |
		ENHANCED_CMDQ_SET(0, CTXT1_ERR_CODE) |
		ENHANCED_CMDQ_SET(start_pi, CTXT1_PI) |
		ENHANCED_CMDQ_SET(start_ci, CTXT1_CI);

	/* second part 16B */
	ctxt_info->pft_thd =
		ENHANCED_CMDQ_SET(CI_HIGN_IDX(start_ci), CTXT2_PFT_CI) |
		ENHANCED_CMDQ_SET(1, CTXT2_O_BIT) |
		ENHANCED_CMDQ_SET(WQ_PREFETCH_MIN, CTXT2_PFT_MIN) |
		ENHANCED_CMDQ_SET(WQ_PREFETCH_MAX, CTXT2_PFT_MAX) |
		ENHANCED_CMDQ_SET(WQ_PREFETCH_THRESHOLD, CTXT2_PFT_THD);
	ctxt_info->pft_ci =
		ENHANCED_CMDQ_SET(pfn, CTXT3_PFT_CI_ADDR) |
		ENHANCED_CMDQ_SET(start_ci, CTXT3_PFT_CI);

	/* third part 16B */
	cmdq_first_block_paddr = cmdqs->wq_block_paddr;
	pfn = WQ_BLOCK_PFN(cmdq_first_block_paddr);

	ctxt_info->ci_cla_addr = ENHANCED_CMDQ_SET(pfn, CTXT4_CI_CLA_ADDR);
}

static void enhance_cmdq_set_completion(union hinic5_cmdq_enhance_completion *completion,
					const struct hinic5_cmd_buf *buf_out)
{
	completion->sge_resp_hi_addr = upper_32_bits(buf_out->dma_addr);
	completion->sge_resp_lo_addr = lower_32_bits(buf_out->dma_addr);
	completion->sge_resp_len = buf_out->size;
}

static void cmdq_set_wqe_buf_desc(struct hinic5_enhanced_cmdq_wqe *enhanced_wqe,
				  const struct hinic5_cmdq_cmd_param *cmd_buf, u32 len)
{
	enhanced_wqe->buf_desc[0].sge_send_hi_addr = upper_32_bits(cmd_buf->buf_in->dma_addr + len);
	enhanced_wqe->buf_desc[0].sge_send_lo_addr = lower_32_bits(cmd_buf->buf_in->dma_addr + len);
	enhanced_wqe->buf_desc[0].len = len;

	enhanced_wqe->buf_desc[1].sge_send_hi_addr =
		upper_32_bits(cmd_buf->buf_in->dma_addr + (len << 1));
	enhanced_wqe->buf_desc[1].sge_send_lo_addr =
		lower_32_bits(cmd_buf->buf_in->dma_addr + (len << 1));
	enhanced_wqe->buf_desc[1].len = cmd_buf->buf_in->size - (len << 1); /* remain data len */
}

void hinic5_enhanced_cmdq_set_wqe(struct hinic5_cmdq_wqe *wqe, enum hinic5_cmdq_cmd_type cmd_type,
			   const struct hinic5_cmdq_cmd_param *cmd_buf, int wrapped)
{
	struct hinic5_enhanced_cmdq_wqe *enhanced_wqe = NULL;
	u32 len = 0;

	if (!wqe || !cmd_buf || !cmd_buf->buf_in) {
		pr_err("wqe or buf_in is null\n");
		return;
	}

	enhanced_wqe = &wqe->enhanced_cmdq_wqe;
	/* Wqe should be 64B aligned, so we fill 3 sges
	 * split data len as three parts carried with ctrl sec and two bdsl
	 */
	len = cmd_buf->buf_in->size / 3;

	if (cmd_type != HINIC5_CMD_TYPE_INLINE_DATA) {
		enhanced_wqe->ctrl_sec.header = ENHANCE_CMDQ_WQE_HEADER_SET(len, SEND_SGE_LEN) |
			ENHANCE_CMDQ_WQE_HEADER_SET(BUFDESC_ENHANCE_CMD_LEN, BDSL) |
			ENHANCE_CMDQ_WQE_HEADER_SET(DATA_SGE, DF) |
			ENHANCE_CMDQ_WQE_HEADER_SET(NORMAL_WQE_TYPE, DN) |
			ENHANCE_CMDQ_WQE_HEADER_SET(COMPACT_WQE_TYPE, EC) |
			ENHANCE_CMDQ_WQE_HEADER_SET((u32)wrapped, HW_BUSY_BIT);

		enhanced_wqe->ctrl_sec.sge_send_hi_addr = upper_32_bits(cmd_buf->buf_in->dma_addr);
		enhanced_wqe->ctrl_sec.sge_send_lo_addr = lower_32_bits(cmd_buf->buf_in->dma_addr);

		cmdq_set_wqe_buf_desc(enhanced_wqe, cmd_buf, len);
	} else {
		enhanced_wqe->ctrl_sec.header =
			ENHANCE_CMDQ_WQE_HEADER_SET(cmd_buf->buf_in->size, BDSL) | /* 64B ALIGNED */
			ENHANCE_CMDQ_WQE_HEADER_SET(DATA_DIRECT, DF) |
			ENHANCE_CMDQ_WQE_HEADER_SET(NORMAL_WQE_TYPE, DN) |
			ENHANCE_CMDQ_WQE_HEADER_SET(COMPACT_WQE_TYPE, EC) |
			ENHANCE_CMDQ_WQE_HEADER_SET((u32)wrapped, HW_BUSY_BIT);
	}

	enhanced_wqe->completion.cs_format = ENHANCE_CMDQ_WQE_CS_SET(cmd_buf->cmd, CMD) |
		ENHANCE_CMDQ_WQE_CS_SET(HINIC5_ACK_TYPE_CMDQ, ACK_TYPE) |
		ENHANCE_CMDQ_WQE_CS_SET((cmd_buf->mod == HINIC5_MOD_ROCE), RN) |
		ENHANCE_CMDQ_WQE_CS_SET((cmd_buf->mod == HINIC5_MOD_HIHTR), RN) |
		ENHANCE_CMDQ_WQE_CS_SET(cmd_buf->mod, MOD);

	switch (cmd_type) {
	case HINIC5_CMD_TYPE_DIRECT_RESP:
		enhanced_wqe->completion.cs_format |= ENHANCE_CMDQ_WQE_CS_SET(INLINE_DATA, CF);
		break;
	case HINIC5_CMD_TYPE_SGE_RESP:
		if (cmd_buf->buf_out) {
			enhanced_wqe->completion.cs_format |=
				ENHANCE_CMDQ_WQE_CS_SET(SGE_RESPONSE, CF);
			enhance_cmdq_set_completion(&enhanced_wqe->completion, cmd_buf->buf_out);
		}
		break;
	case HINIC5_CMD_TYPE_ASYNC:
		break;
	case HINIC5_CMD_TYPE_INLINE_DATA:
		enhance_cmdq_set_completion(&enhanced_wqe->completion, cmd_buf->buf_out);
		memcpy(enhanced_wqe->inline_data, cmd_buf->buf_in->buf, cmd_buf->buf_in->size);
		break;
	default:
		break;
	}
}

static inline u32 enhanced_cmdq_completion_get_error_code
			(union hinic5_cmdq_enhance_completion *completion)
{
	u32 cs_dw0 = hinic5_hw_cpu32(completion->dw[0]);

	return ENHANCE_CMDQ_WQE_CS_GET(cs_dw0, ERR_CODE);
}

static inline u32 enhanced_cmdq_completion_get_error_status
			(union hinic5_cmdq_enhance_completion *completion)
{
	u32 cs_dw0, cs_dw3, error_status;

	cs_dw0 = hinic5_hw_cpu32(completion->dw[0]);
	cs_dw3 = hinic5_hw_cpu32(completion->dw[0x3]);

	error_status = ENHANCE_CMDQ_WQE_CS_GET(cs_dw0, ERR_STATUS_28_18) <<
		       ENHANCE_CMDQ_WQE_CS_ERR_STATUS_28_18_OFFSET;
	error_status |= ENHANCE_CMDQ_WQE_CS_GET(cs_dw3, ERR_STATUS_17_0);

	return error_status;
}

static inline u64 enhanced_cmdq_completion_get_udata
			(union hinic5_cmdq_enhance_completion *completion,
			struct hinic5_cmdq *cmdq)
{
	u64 udata_l, udata_h;

	/* HTN has no udata */
	if (COMM_SUPPORT_HTN_CMD(cmdq->hwdev))
		return 0;

	udata_l = hinic5_hw_cpu32(completion->dw[0x1]);
	udata_h = hinic5_hw_cpu32(completion->dw[0x2]);
	return (udata_h << BIT_32) | udata_l;
}

void enhanced_cmdq_update_cmd_status(struct hinic5_cmdq *cmdq,
				     struct hinic5_cmdq_cmd_info *cmd_info,
				     struct hinic5_enhanced_cmdq_wqe *wqe)
{
	union hinic5_cmdq_enhance_completion *completion = &wqe->completion;
	u32 errcode, error_status = 0;

	errcode = enhanced_cmdq_completion_get_error_code(completion);
	if (errcode != 0) {
		error_status = enhanced_cmdq_completion_get_error_status(completion);
		sdk_err(cmdq->hwdev->dev_hdl, "Cmdq error code 0x%x, error status 0x%x\n",
			errcode, error_status);
	}

	if (COMM_SUPPORT_HTN_CMD(cmdq->hwdev)) {
		*cmd_info->errcode = (int)errcode;
		if (cmd_info->direct_resp)
			*cmd_info->direct_resp = error_status;
	} else {
		/* Non-HTN enhanced CMDQ errcode try to align with normal CMDQ.
		 * [30:29] is errcode from completion, which actually has only 1 bit,
		 * [28:0] is error_status from completion
		 */
		errcode = (errcode & HINIC5_CMDQ_CQE_DW0_ERR_CODE_MASK) <<
			  HINIC5_CMDQ_CQE_DW0_ERR_CODE_SHIFT;
		errcode |= error_status & HINIC5_CMDQ_CQE_DW0_ERR_STATUS_MASK;

		*cmd_info->errcode = (int)errcode;
		if (cmd_info->direct_resp)
			*cmd_info->direct_resp =
				enhanced_cmdq_completion_get_udata(completion, cmdq);
	}
}
