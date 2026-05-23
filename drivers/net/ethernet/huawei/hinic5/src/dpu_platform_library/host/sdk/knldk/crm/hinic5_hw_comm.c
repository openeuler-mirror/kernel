/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw_comm.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/kernel.h>
#include <linux/msi.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>

#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_common.h"
#include "hinic5_csr_inner.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_mgmt.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_cmdq.h"
#include "mpu_inband_cmd_defs.h"
#include "mpu_inband_cmd.h"
#include "hinic5_vram_common.h"
#include "hinic5_hinic5_vram_api.h"
#include "hinic5_hw_comm.h"

unsigned char lowpower_mode;
module_param(lowpower_mode, byte, 0644);
MODULE_PARM_DESC(lowpower_mode, "Set lowpower test mode, 0-sml rd loop, 1-writeback ddr, 2-off");

/* 1872 FT B505 temporary modification, to be removed after MQM fixes CMQ constraint */
static unsigned char cmdq_cos_offset;
module_param(cmdq_cos_offset, byte, 0444);
MODULE_PARM_DESC(cmdq_cos_offset, "Set cmdq cos start offset");

#define	HINIC5_MSIX_CNT_LLI_TIMER_SHIFT			0
#define	HINIC5_MSIX_CNT_LLI_CREDIT_SHIFT		8
#define	HINIC5_MSIX_CNT_COALESC_TIMER_SHIFT		8
#define	HINIC5_MSIX_CNT_PENDING_SHIFT			8
#define	HINIC5_MSIX_CNT_RESEND_TIMER_SHIFT		29

#define	HINIC5_MSIX_CNT_LLI_TIMER_MASK			0xFFU
#define	HINIC5_MSIX_CNT_LLI_CREDIT_MASK			0xFFU
#define	HINIC5_MSIX_CNT_COALESC_TIMER_MASK		0xFFU
#define	HINIC5_MSIX_CNT_PENDING_MASK			0x1FU
#define	HINIC5_MSIX_CNT_RESEND_TIMER_MASK		0x7U

#define HINIC5_MSIX_CNT_SET(val, member)		\
		(((val) & HINIC5_MSIX_CNT_##member##_MASK) << \
		HINIC5_MSIX_CNT_##member##_SHIFT)

#define DEFAULT_RX_BUF_SIZE	((u16)0xB)
#define HINIC5_HT_GPA_PAGE_LEN 1024

enum hinic5_rx_buf_size {
	HINIC5_RX_BUF_SIZE_32B = 0x20,
	HINIC5_RX_BUF_SIZE_64B = 0x40,
	HINIC5_RX_BUF_SIZE_96B = 0x60,
	HINIC5_RX_BUF_SIZE_128B = 0x80,
	HINIC5_RX_BUF_SIZE_192B = 0xC0,
	HINIC5_RX_BUF_SIZE_256B = 0x100,
	HINIC5_RX_BUF_SIZE_384B = 0x180,
	HINIC5_RX_BUF_SIZE_512B = 0x200,
	HINIC5_RX_BUF_SIZE_768B = 0x300,
	HINIC5_RX_BUF_SIZE_1K = 0x400,
	HINIC5_RX_BUF_SIZE_1_5K = 0x600,
	HINIC5_RX_BUF_SIZE_2K = 0x800,
	HINIC5_RX_BUF_SIZE_3K = 0xC00,
	HINIC5_RX_BUF_SIZE_4K = 0x1000,
	HINIC5_RX_BUF_SIZE_8K = 0x2000,
	HINIC5_RX_BUF_SIZE_16K = 0x4000,
};

static inline int comm_msg_to_mgmt_sync(struct hinic5_hwdev *hwdev, u16 cmd, void *buf_in,
					u16 in_size, void *buf_out, u16 *out_size)
{
	return hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, cmd, buf_in,
				       in_size, buf_out, out_size, 0,
				       HINIC5_CHANNEL_COMM);
}

static inline int comm_msg_to_mgmt_sync_ch(struct hinic5_hwdev *hwdev, u16 cmd, void *buf_in,
					   u16 in_size, void *buf_out, u16 *out_size, u16 channel)
{
	return hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, cmd, buf_in,
				       in_size, buf_out, out_size, 0, channel);
}

int hinic5_get_interrupt_cfg(void *dev, struct interrupt_info *info,
			     u16 channel)
{
	struct hinic5_hwdev *hwdev = dev;
	struct comm_cmd_msix_config msix_cfg;
	u16 out_size = sizeof(msix_cfg);
	int err;

	if (!hwdev || !info)
		return -EINVAL;

	memset(&msix_cfg, 0, sizeof(msix_cfg));
	msix_cfg.func_id = hinic5_global_func_id(hwdev);
	msix_cfg.msix_index = info->msix_index;
	msix_cfg.opcode = MGMT_MSG_CMD_OP_GET;

	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_CFG_MSIX_CTRL_REG,
				       &msix_cfg, sizeof(msix_cfg), &msix_cfg,
				       &out_size, channel);
	if (err != 0 || out_size == 0 || msix_cfg.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to get interrupt config, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, msix_cfg.head.status, out_size, channel);
		return -EINVAL;
	}

	info->lli_credit_limit = msix_cfg.lli_credit_cnt;
	info->lli_timer_cfg = msix_cfg.lli_timer_cnt;
	info->pending_limt = msix_cfg.pending_cnt;
	info->coalesc_timer_cfg = msix_cfg.coalesce_timer_cnt;
	info->resend_timer_cfg = msix_cfg.resend_timer_cnt;

	return 0;
}

int hinic5_set_interrupt_cfg_direct(void *hwdev, struct interrupt_info *info,
				    u16 channel)
{
	struct comm_cmd_msix_config msix_cfg;
	u16 out_size = sizeof(msix_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&msix_cfg, 0, sizeof(msix_cfg));
	msix_cfg.func_id = hinic5_global_func_id(hwdev);
	msix_cfg.msix_index = info->msix_index;
	msix_cfg.opcode = MGMT_MSG_CMD_OP_SET;

	msix_cfg.lli_credit_cnt = info->lli_credit_limit;
	msix_cfg.lli_timer_cnt = info->lli_timer_cfg;
	msix_cfg.pending_cnt = info->pending_limt;
	msix_cfg.coalesce_timer_cnt = info->coalesc_timer_cfg;
	msix_cfg.resend_timer_cnt = info->resend_timer_cfg;

	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_CFG_MSIX_CTRL_REG,
				       &msix_cfg, sizeof(msix_cfg), &msix_cfg,
				       &out_size, channel);
	if (err != 0 || out_size == 0 || msix_cfg.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set interrupt config, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, msix_cfg.head.status, out_size, channel);
		return -EINVAL;
	}

	return 0;
}

int hinic5_set_interrupt_cfg(void *dev, struct interrupt_info info, u16 channel)
{
	struct interrupt_info temp_info;
	struct hinic5_hwdev *hwdev = dev;
	int err;

	if (!hwdev)
		return -EINVAL;

	temp_info.msix_index = info.msix_index;

	err = hinic5_get_interrupt_cfg(hwdev, &temp_info, channel);
	if (err != 0)
		return -EINVAL;

	if (info.lli_set == 0) {
		info.lli_credit_limit = temp_info.lli_credit_limit;
		info.lli_timer_cfg = temp_info.lli_timer_cfg;
	}

	if (info.interrupt_coalesc_set == 0) {
		info.pending_limt = temp_info.pending_limt;
		info.coalesc_timer_cfg = temp_info.coalesc_timer_cfg;
		info.resend_timer_cfg = temp_info.resend_timer_cfg;
	}

	return hinic5_set_interrupt_cfg_direct(hwdev, &info, channel);
}
EXPORT_SYMBOL(hinic5_set_interrupt_cfg);

void hinic5_misx_intr_clear_resend_bit(void *hwdev, u16 msix_idx,
				       u8 clear_resend_en)
{
	struct hinic5_hwif *hwif = NULL;
	u32 msix_ctrl = 0, addr;

	if (!hwdev)
		return;

	hwif = ((struct hinic5_hwdev *)hwdev)->hwif;

	msix_ctrl = HINIC5_MSI_CLR_INDIR_SET(msix_idx, SIMPLE_INDIR_IDX) |
		    HINIC5_MSI_CLR_INDIR_SET(clear_resend_en, RESEND_TIMER_CLR);

	addr = HINIC5_CSR_FUNC_MSI_CLR_WR_ADDR;
	hinic5_hwif_write_reg(hwif, addr, msix_ctrl);
}
EXPORT_SYMBOL(hinic5_misx_intr_clear_resend_bit);

int hinic5_set_wq_page_size(void *hwdev, u16 func_idx, u32 page_size,
			    u16 channel)
{
	struct comm_cmd_wq_page_size page_size_info;
	u16 out_size = sizeof(page_size_info);
	int err;

	memset(&page_size_info, 0, sizeof(page_size_info));
	page_size_info.func_id = func_idx;
	page_size_info.page_size = HINIC5_PAGE_SIZE_HW(page_size);
	page_size_info.opcode = MGMT_MSG_CMD_OP_SET;

	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_CFG_PAGESIZE,
				       &page_size_info, sizeof(page_size_info),
				       &page_size_info, &out_size, channel);
	if (err != 0 || out_size == 0 || page_size_info.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set wq page size, err: %d, status: 0x%x, out_size: 0x%x, channel: 0x%x\n",
			err, page_size_info.head.status, out_size, channel);
		return -EFAULT;
	}

	return 0;
}

int hinic5_func_reset(void *dev, u16 func_id, u64 reset_flag, u16 channel)
{
	struct comm_cmd_func_reset func_reset;
	struct hinic5_hwdev *hwdev = dev;
	u16 out_size = sizeof(func_reset);
	int err = 0;
	int is_in_kexec;

	if (!dev) {
		pr_err("Invalid para: dev is null.\n");
		return -EINVAL;
	}

	is_in_kexec = hinic5_vram_get_kexec_flag();
	if (is_in_kexec != 0) {
		sdk_info(hwdev->dev_hdl, "Skip function reset!\n");
		return 0;
	}

	sdk_info(hwdev->dev_hdl, "Function is reset, flag: 0x%llx, channel:0x%x\n",
		 reset_flag, channel);

	memset(&func_reset, 0, sizeof(func_reset));
	func_reset.func_id = func_id;
	func_reset.reset_flag = reset_flag;
	/* During func reset, chip may have OUTBOUND_FLUSH_DISABLED, skip abnormality check */
	atomic_inc(&hwdev->check_ob_flush_bypass_ref_cnt);
	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_FUNC_RESET,
				       &func_reset, sizeof(func_reset),
				       &func_reset, &out_size, channel);
	if (err != 0 || out_size == 0 || func_reset.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to reset func resources, reset_flag 0x%llx, err: %d, " \
			"status: 0x%x, out_size: 0x%x\n",
			reset_flag, err, func_reset.head.status, out_size);
		err = -EIO;
	}

	atomic_dec(&hwdev->check_ob_flush_bypass_ref_cnt);
	return err;
}
EXPORT_SYMBOL(hinic5_func_reset);

static u16 get_hw_rx_buf_size(const void *hwdev, u16 rx_buf_sz)
{
	const int hinic5_hw_rx_buf_size[] = {
		HINIC5_RX_BUF_SIZE_32B,
		HINIC5_RX_BUF_SIZE_64B,
		HINIC5_RX_BUF_SIZE_96B,
		HINIC5_RX_BUF_SIZE_128B,
		HINIC5_RX_BUF_SIZE_192B,
		HINIC5_RX_BUF_SIZE_256B,
		HINIC5_RX_BUF_SIZE_384B,
		HINIC5_RX_BUF_SIZE_512B,
		HINIC5_RX_BUF_SIZE_768B,
		HINIC5_RX_BUF_SIZE_1K,
		HINIC5_RX_BUF_SIZE_1_5K,
		HINIC5_RX_BUF_SIZE_2K,
		HINIC5_RX_BUF_SIZE_3K,
		HINIC5_RX_BUF_SIZE_4K,
		HINIC5_RX_BUF_SIZE_8K,
		HINIC5_RX_BUF_SIZE_16K,
	};
	u16 num_hw_types;
	u16 i;

	if (COMM_IS_USE_REAL_RX_BUF_SIZE((struct hinic5_hwdev *)hwdev))
		return rx_buf_sz;

	num_hw_types = ARRAY_SIZE(hinic5_hw_rx_buf_size);
	for (i = 0; i < num_hw_types; i++) {
		if (hinic5_hw_rx_buf_size[i] == rx_buf_sz)
			return i;
	}

	pr_err("Chip can't support rx buf size of %d\n", rx_buf_sz);

	return DEFAULT_RX_BUF_SIZE; /* default 2K */
}

int hinic5_set_root_ctxt(void *hwdev, u32 rq_depth, u32 sq_depth, u16 rx_buf_sz,
			 u16 channel)
{
	struct comm_cmd_root_ctxt root_ctxt;
	u16 out_size = sizeof(root_ctxt);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&root_ctxt, 0, sizeof(root_ctxt));
	root_ctxt.func_id = hinic5_global_func_id(hwdev);

	root_ctxt.set_cmdq_depth = 0;
	root_ctxt.cmdq_depth = 0;

	root_ctxt.lro_en = 1;

	root_ctxt.rq_depth  = (u16)ilog2(rq_depth);
	root_ctxt.rx_buf_sz = get_hw_rx_buf_size(hwdev, rx_buf_sz);
	root_ctxt.sq_depth  = (u16)ilog2(sq_depth);

	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_SET_VAT,
				       &root_ctxt, sizeof(root_ctxt),
				       &root_ctxt, &out_size, channel);
	if (err != 0 || out_size == 0 || root_ctxt.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set root context, err: %d, status: 0x%x, out_size: 0x%x, channel: 0x%x\n",
			err, root_ctxt.head.status, out_size, channel);
		return -EFAULT;
	}
	return 0;
}
EXPORT_SYMBOL(hinic5_set_root_ctxt);

int hinic5_clean_root_ctxt(void *hwdev, u16 channel)
{
	struct comm_cmd_root_ctxt root_ctxt;
	u16 out_size = sizeof(root_ctxt);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&root_ctxt, 0, sizeof(root_ctxt));
	root_ctxt.func_id = hinic5_global_func_id(hwdev);

	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_SET_VAT,
				       &root_ctxt, sizeof(root_ctxt),
				       &root_ctxt, &out_size, channel);
	if (err != 0 || out_size == 0 || root_ctxt.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set root context, err: %d, status: 0x%x, out_size: 0x%x, channel: 0x%x\n",
			err, root_ctxt.head.status, out_size, channel);
		return -EFAULT;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_clean_root_ctxt);

int hinic5_set_cmdq_depth(void *hwdev, u16 cmdq_depth)
{
	struct comm_cmd_root_ctxt root_ctxt;
	u16 out_size = sizeof(root_ctxt);
	int err;

	memset(&root_ctxt, 0, sizeof(root_ctxt));
	root_ctxt.func_id = hinic5_global_func_id(hwdev);

	root_ctxt.set_cmdq_depth = 1;
	root_ctxt.cmdq_depth = (u8)ilog2(cmdq_depth);
	root_ctxt.cmdq_mode = ((struct hinic5_hwdev *)hwdev)->cmdq_mode;

	if (((struct hinic5_hwdev *)hwdev)->cmdq_mode == HINIC5_ENHANCE_CMDQ)
		root_ctxt.cmdq_depth--;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_VAT, &root_ctxt,
				    sizeof(root_ctxt), &root_ctxt, &out_size);
	if (err != 0 || out_size == 0 || root_ctxt.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set cmdq depth, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, root_ctxt.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_set_enhance_cmdq_ctxt(struct hinic5_hwdev *hwdev, u8 cmdq_id,
				 struct enhance_cmdq_ctxt_info *ctxt)
{
	struct comm_cmd_enhance_cmdq_ctxt cmdq_ctxt;
	u16 out_size = sizeof(cmdq_ctxt);
	int err;

	memset(&cmdq_ctxt, 0, sizeof(cmdq_ctxt));
	memcpy(&cmdq_ctxt.ctxt, ctxt, sizeof(*ctxt));
	cmdq_ctxt.func_id = hinic5_global_func_id(hwdev);
	cmdq_ctxt.cmdq_id = cmdq_id | cmdq_cos_offset;
	hwdev->cmdq_cos_offset = cmdq_cos_offset;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_ENHANCE_CMDQ_CTXT,
				    &cmdq_ctxt, sizeof(cmdq_ctxt),
				    &cmdq_ctxt, &out_size);
	if (err != 0 || out_size == 0 || cmdq_ctxt.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set enhanced cmdq ctxt, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, cmdq_ctxt.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_set_cmdq_ctxt(struct hinic5_hwdev *hwdev, u8 cmdq_id,
			 struct cmdq_ctxt_info *ctxt)
{
	struct comm_cmd_cmdq_ctxt cmdq_ctxt;
	u16 out_size = sizeof(cmdq_ctxt);
	int err;

	memset(&cmdq_ctxt, 0, sizeof(cmdq_ctxt));
	memcpy(&cmdq_ctxt.ctxt, ctxt, sizeof(*ctxt));
	cmdq_ctxt.func_id = hinic5_global_func_id(hwdev);
	cmdq_ctxt.cmdq_id = cmdq_id;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_CMDQ_CTXT,
				    &cmdq_ctxt, sizeof(cmdq_ctxt),
				    &cmdq_ctxt, &out_size);
	if (err != 0 || out_size == 0 || cmdq_ctxt.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set cmdq ctxt, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, cmdq_ctxt.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_set_ceq_ctrl_reg(struct hinic5_hwdev *hwdev, u16 q_id,
			    u32 ctrl0, u32 ctrl1)
{
	struct comm_cmd_ceq_ctrl_reg ceq_ctrl;
	u16 out_size = sizeof(ceq_ctrl);
	int err;

	memset(&ceq_ctrl, 0, sizeof(ceq_ctrl));
	ceq_ctrl.func_id = hinic5_global_func_id(hwdev);
	ceq_ctrl.q_id = q_id;
	ceq_ctrl.ctrl0 = ctrl0;
	ceq_ctrl.ctrl1 = ctrl1;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_CEQ_CTRL_REG,
				    &ceq_ctrl, sizeof(ceq_ctrl),
				    &ceq_ctrl, &out_size);
	if (err != 0 || out_size == 0 || ceq_ctrl.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set ceq %u ctrl reg, err: %d status: 0x%x, out_size: 0x%x\n",
			q_id, err, ceq_ctrl.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_set_dma_attr_tbl(struct hinic5_hwdev *hwdev, u8 entry_idx, u8 st, u8 at, u8 ph,
			    u8 no_snooping, u8 tph_en)
{
	struct comm_cmd_dma_attr_config dma_attr;
	u16 out_size = sizeof(dma_attr);
	int err;

	memset(&dma_attr, 0, sizeof(dma_attr));
	dma_attr.func_id = hinic5_global_func_id(hwdev);
	dma_attr.entry_idx = entry_idx;
	dma_attr.st = st;
	dma_attr.at = at;
	dma_attr.ph = ph;
	dma_attr.no_snooping = no_snooping;
	dma_attr.tph_en = tph_en;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_DMA_ATTR, &dma_attr, sizeof(dma_attr),
				    &dma_attr, &out_size);
	if (err != 0 || out_size == 0 || dma_attr.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set dma attr, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, dma_attr.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_set_bdf_ctxt(void *hwdev, u8 bus, u8 device, u8 function)
{
	struct comm_cmd_bdf_info bdf_info;
	u16 out_size = sizeof(bdf_info);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&bdf_info, 0, sizeof(bdf_info));
	bdf_info.function_idx = hinic5_global_func_id(hwdev);
	bdf_info.bus = bus;
	bdf_info.device = device;
	bdf_info.function = function;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SEND_BDF_INFO,
				    &bdf_info, sizeof(bdf_info),
				    &bdf_info, &out_size);
	if (err != 0 || out_size == 0 || bdf_info.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set bdf info to MPU, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, bdf_info.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_sync_time(void *hwdev, u64 time)
{
	struct comm_cmd_sync_time time_info;
	u16 out_size = sizeof(time_info);
	int err;

	memset(&time_info, 0, sizeof(time_info));
	time_info.mstime = time;
	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SYNC_TIME, &time_info,
				    sizeof(time_info), &time_info, &out_size);
	if (err != 0 || time_info.head.status != 0 || out_size == 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to sync time to mgmt, err: %d, status: 0x%x, out size: 0x%x\n",
			err, time_info.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_set_ppf_flr_type(void *hwdev, enum hinic5_ppf_flr_type flr_type)
{
	struct comm_cmd_ppf_flr_type_set flr_type_set;
	u16 out_size = sizeof(struct comm_cmd_ppf_flr_type_set);
	struct hinic5_hwdev *dev = hwdev;
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&flr_type_set, 0, sizeof(flr_type_set));
	flr_type_set.func_id = hinic5_global_func_id(hwdev);
	flr_type_set.ppf_flr_type = flr_type;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_PPF_FLR_TYPE,
				    &flr_type_set, sizeof(flr_type_set),
				    &flr_type_set, &out_size);
	if (err != 0 || out_size == 0 || flr_type_set.head.status != 0) {
		sdk_err(dev->dev_hdl, "Failed to set ppf flr type, err: %d, status: 0x%x, out size: 0x%x\n",
			err, flr_type_set.head.status, out_size);
		return -EIO;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_set_ppf_flr_type);

int hinic5_set_ppf_tbl_hotreplace_flag(void *hwdev, u8 flag)
{
	struct comm_cmd_ppf_tbl_htrp_config htr_info;
	u16 out_size = sizeof(struct comm_cmd_ppf_tbl_htrp_config);
	struct hinic5_hwdev *dev = hwdev;
	int ret;

	if (!hwdev) {
		pr_err("Sdk set ppf table hotreplace flag para is null");
		return -EINVAL;
	}

	memset(&htr_info, 0, sizeof(htr_info));

	htr_info.hotreplace_flag = flag;
	ret = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_PPF_TBL_HTR_FLG,
				    &htr_info, sizeof(htr_info), &htr_info, &out_size);
	if (ret != 0 || htr_info.head.status != 0) {
		sdk_err(dev->dev_hdl, "Send mbox to mpu failed in sdk, ret:%d, status:%u",
			ret, htr_info.head.status);
		return -EIO;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_set_ppf_tbl_hotreplace_flag);

static int hinic5_get_fw_ver(struct hinic5_hwdev *hwdev, enum hinic5_fw_ver_type type,
			     u8 *mgmt_ver, u8 version_size, u16 channel)
{
	struct comm_cmd_get_fw_version fw_ver;
	u16 out_size = sizeof(fw_ver);
	int err;

	if (!hwdev || !mgmt_ver)
		return -EINVAL;

	memset(&fw_ver, 0, sizeof(fw_ver));
	fw_ver.fw_type = type;
	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_GET_FW_VERSION,
				       &fw_ver, sizeof(fw_ver), &fw_ver,
				       &out_size, channel);
	if (err != 0 || out_size == 0 || fw_ver.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to get fw version, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, fw_ver.head.status, out_size, channel);
		return -EIO;
	}

	if (version_size > HINIC5_MGMT_VERSION_MAX_LEN) {
		sdk_err(hwdev->dev_hdl, "memcpy fw_ver.ver over range\n");
		return -ERANGE;
	}

	memcpy(mgmt_ver, fw_ver.ver, version_size);
	return 0;
}

int hinic5_get_mgmt_version(void *hwdev, u8 *mgmt_ver, u8 version_size,
			    u16 channel)
{
	return hinic5_get_fw_ver(hwdev, HINIC5_FW_VER_TYPE_MPU, mgmt_ver,
				 version_size, channel);
}
EXPORT_SYMBOL(hinic5_get_mgmt_version);

int hinic5_get_fw_version(void *hwdev, struct hinic5_fw_version *fw_ver,
			  u16 channel)
{
	int err;

	if (!hwdev || !fw_ver)
		return -EINVAL;

	err = hinic5_get_fw_ver(hwdev, HINIC5_FW_VER_TYPE_MPU,
				fw_ver->mgmt_ver, sizeof(fw_ver->mgmt_ver),
				channel);
	if (err != 0)
		return err;

	err = hinic5_get_fw_ver(hwdev, HINIC5_FW_VER_TYPE_NPU,
				fw_ver->microcode_ver,
				sizeof(fw_ver->microcode_ver), channel);
	if (err != 0)
		return err;

	return hinic5_get_fw_ver(hwdev, HINIC5_FW_VER_TYPE_BOOT,
				 fw_ver->boot_ver, sizeof(fw_ver->boot_ver),
				 channel);
}
EXPORT_SYMBOL(hinic5_get_fw_version);

static int hinic5_comm_features_nego(void *hwdev, u8 opcode, u64 *s_feature,
				     u16 size)
{
	struct comm_cmd_feature_nego feature_nego;
	u16 out_size = sizeof(feature_nego);
	struct hinic5_hwdev *dev = hwdev;
	int err;

	if (!hwdev || !s_feature || size > COMM_MAX_FEATURE_QWORD)
		return -EINVAL;

	memset(&feature_nego, 0, sizeof(feature_nego));
	feature_nego.func_id = hinic5_global_func_id(hwdev);
	feature_nego.opcode = opcode;
	if (opcode == MGMT_MSG_CMD_OP_SET)
		memcpy(feature_nego.s_feature, s_feature, (size * sizeof(u64)));

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_FEATURE_NEGO,
				    &feature_nego, sizeof(feature_nego),
				    &feature_nego, &out_size);
	if (err != 0 || out_size == 0 || feature_nego.head.status != 0) {
		sdk_err(dev->dev_hdl, "Failed to negotiate feature, err: %d, status: 0x%x, out size: 0x%x\n",
			err, feature_nego.head.status, out_size);
		return -EINVAL;
	}

	if (opcode == MGMT_MSG_CMD_OP_GET)
		memcpy(s_feature, feature_nego.s_feature, (COMM_MAX_FEATURE_QWORD * sizeof(u64)));

	return 0;
}

int hinic5_get_comm_features(void *hwdev, u64 *s_feature, u16 size)
{
	return hinic5_comm_features_nego(hwdev, MGMT_MSG_CMD_OP_GET, s_feature,
					 size);
}

int hinic5_set_comm_features(void *hwdev, u64 *s_feature, u16 size)
{
	return hinic5_comm_features_nego(hwdev, MGMT_MSG_CMD_OP_SET, s_feature,
					 size);
}

int hinic5_comm_channel_detect(struct hinic5_hwdev *hwdev)
{
	struct comm_cmd_channel_detect channel_detect_info;
	u16 out_size = sizeof(channel_detect_info);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&channel_detect_info, 0, sizeof(channel_detect_info));
	channel_detect_info.func_id = hinic5_global_func_id(hwdev);

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_CHANNEL_DETECT,
				    &channel_detect_info, sizeof(channel_detect_info),
				    &channel_detect_info, &out_size);
	if ((channel_detect_info.head.status != HINIC5_MGMT_CMD_UNSUPPORTED &&
	    channel_detect_info.head.status != 0) || err != 0 || out_size == 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to send channel detect, err: %d, status: 0x%x, out size: 0x%x\n",
			err, channel_detect_info.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hinic5_func_tmr_bitmap_set(void *hwdev, u16 func_id, bool en)
{
#ifdef __UEFI__
	return 0;
#endif
	struct comm_cmd_func_tmr_bitmap_op bitmap_op;
	u16 out_size = sizeof(bitmap_op);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&bitmap_op, 0, sizeof(bitmap_op));
	bitmap_op.func_id = func_id;
	bitmap_op.opcode = en ? FUNC_TMR_BITMAP_ENABLE : FUNC_TMR_BITMAP_DISABLE;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_FUNC_TMR_BITMAT,
				    &bitmap_op, sizeof(bitmap_op),
				    &bitmap_op, &out_size);
	if (err != 0 || out_size == 0 || bitmap_op.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set timer bitmap, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, bitmap_op.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_func_vio_en(void *hwdev, bool en)
{
	struct hinic5_hwdev *dev = (struct hinic5_hwdev *)hwdev;
	struct comm_cmd_virtio_en cmd;
	u16 out_size = sizeof(cmd);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));
	cmd.msien_snap_2_virtio_en = en ? 0x1 : 0x0;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_VIO_EN,
				    &cmd, sizeof(cmd), &cmd, &out_size);
	if (cmd.head.status == HINIC5_MGMT_CMD_UNSUPPORTED) {
		sdk_warn(dev->dev_hdl, "not support vio en");
		return 0;
	}
	if (err != 0 || out_size == 0 || cmd.head.status != 0) {
		sdk_err(dev->dev_hdl,
			"Failed to set vio %s, err: %d, status: 0x%x, out_size: 0x%x\n",
			(en ? "enable" : "disable"),
			err, cmd.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static int alloc_bank_buf(struct hinic5_hwdev *hwdev, struct hinic5_page_addr *pg0,
			  struct hinic5_page_addr *pg1, struct comm_cmd_ht_gpa *ht_gpa_set)
{
	size_t page_len = HINIC5_HT_GPA_PAGE_SIZE * HINIC5_HT_GPA_PAGE_LEN;

	if (lowpower_mode != 0) {
		pg0->virt_addr = dma_zalloc_coherent(hwdev->dev_hdl, page_len,
						     &pg0->phys_addr, GFP_KERNEL);
		ht_gpa_set->rsvd0[0] = lowpower_mode;
		sdk_info(hwdev->dev_hdl, "Alloc pg0 page addr len: 0x%lx, lowpower_mode=%u\n",
			 page_len, lowpower_mode);
	} else {
		pg0->virt_addr = dma_zalloc_coherent(hwdev->dev_hdl, HINIC5_HT_GPA_PAGE_SIZE,
						     &pg0->phys_addr, GFP_KERNEL);
	}

	if (!pg0->virt_addr) {
		sdk_err(hwdev->dev_hdl, "Alloc pg0 page addr failed\n");
		return -EFAULT;
	}

	pg1->virt_addr = dma_zalloc_coherent(hwdev->dev_hdl,
					     HINIC5_HT_GPA_PAGE_SIZE,
					     &pg1->phys_addr, GFP_KERNEL);
	if (!pg1->virt_addr) {
		sdk_err(hwdev->dev_hdl, "Alloc pg1 page addr failed\n");
		return -EFAULT;
	}

	return 0;
}

static int ht_gpa_set(struct hinic5_hwdev *hwdev, struct hinic5_page_addr *pg0,
		      struct hinic5_page_addr *pg1)
{
	struct comm_cmd_ht_gpa ht_gpa_set;
	u16 out_size = sizeof(ht_gpa_set);
	int ret;

	memset(&ht_gpa_set, 0, sizeof(ht_gpa_set));
	ret = alloc_bank_buf(hwdev, pg0, pg1, &ht_gpa_set);
	if (ret != 0)
		return -EFAULT;

	ht_gpa_set.host_id = hinic5_host_id(hwdev);
	ht_gpa_set.opcode = HT_GPA_SET;
	ht_gpa_set.page_pa0 = pg0->phys_addr;
	ht_gpa_set.page_pa1 = pg1->phys_addr;
#ifndef __VMWARE__
	sdk_info(hwdev->dev_hdl, "ht gpa set: page_addr0.pa=0x%llx, page_addr1.pa=0x%llx\n",
		 pg0->phys_addr, pg1->phys_addr);
#else
	sdk_info(hwdev->dev_hdl, "ht gpa set: page_addr0.pa=0x%lx, page_addr1.pa=0x%lx\n",
		 pg0->phys_addr, pg1->phys_addr);
#endif
	ret = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_HT_GPA,
				    &ht_gpa_set, sizeof(ht_gpa_set),
				    &ht_gpa_set, &out_size);
	if (ret != 0 || out_size == 0 || ht_gpa_set.head.status != 0) {
		sdk_warn(hwdev->dev_hdl, "ht gpa set failed, ret: %d, status: 0x%x, out_size: 0x%x\n",
			 ret, ht_gpa_set.head.status, out_size);
		return -EFAULT;
	}

	hwdev->page_pa0.phys_addr = pg0->phys_addr;
	hwdev->page_pa0.virt_addr = pg0->virt_addr;

	hwdev->page_pa1.phys_addr = pg1->phys_addr;
	hwdev->page_pa1.virt_addr = pg1->virt_addr;

	return 0;
}

int hinic5_ht_gpa_init(struct hinic5_hwdev *hwdev)
{
	struct hinic5_page_addr page_addr0[HINIC5_HT_GPA_SET_RETRY_TIMES] = { 0 };
	struct hinic5_page_addr page_addr1[HINIC5_HT_GPA_SET_RETRY_TIMES] = { 0 };
	int ret, i, j;

	if (!hwdev) {
		pr_err("hwdev is null.\n");
		return -EINVAL;
	}

	if (hwdev->page_pa0.phys_addr != 0 || hwdev->page_pa1.phys_addr != 0) {
		sdk_err(hwdev->dev_hdl, "ht gpa have be inited.\n");
		return 0;
	}

	for (i = 0; i < HINIC5_HT_GPA_SET_RETRY_TIMES; i++) {
		ret = ht_gpa_set(hwdev, &page_addr0[i], &page_addr1[i]);
		if (ret == 0)
			break;
	}

	for (j = 0; j < i; j++) {
		if (page_addr0[j].virt_addr) {
			dma_free_coherent(hwdev->dev_hdl,
					  HINIC5_HT_GPA_PAGE_SIZE,
					  page_addr0[j].virt_addr,
					  (dma_addr_t)page_addr0[j].phys_addr);
			page_addr0[j].virt_addr = NULL;
		}
		if (page_addr1[j].virt_addr) {
			dma_free_coherent(hwdev->dev_hdl,
					  HINIC5_HT_GPA_PAGE_SIZE,
					  page_addr1[j].virt_addr,
					  (dma_addr_t)page_addr1[j].phys_addr);
			page_addr1[j].virt_addr = NULL;
		}
	}

	if (i >= HINIC5_HT_GPA_SET_RETRY_TIMES) {
		sdk_err(hwdev->dev_hdl, "ht gpa init failed, retry times: %d\n",
			i);
		return -EFAULT;
	}

	return 0;
}

static void ht_gpa_clear(struct hinic5_hwdev *hwdev)
{
	struct comm_cmd_ht_gpa ht_gpa_set;
	u16 out_size = sizeof(ht_gpa_set);
	int ret;

	memset(&ht_gpa_set, 0, sizeof(ht_gpa_set));

	ht_gpa_set.host_id = hinic5_host_id(hwdev);
	ht_gpa_set.opcode = HT_GPA_CLEAR;

	sdk_info(hwdev->dev_hdl, "ht gpa clear");

	ret = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_HT_GPA,
				    &ht_gpa_set, sizeof(ht_gpa_set),
				    &ht_gpa_set, &out_size);
	if (ret != 0 || out_size == 0 || ht_gpa_set.head.status != 0) {
		sdk_warn(hwdev->dev_hdl, "ht gpa set failed, ret: %d, status: 0x%x, out_size: 0x%x\n",
			 ret, ht_gpa_set.head.status, out_size);
	}
}

void hinic5_ht_gpa_deinit(struct hinic5_hwdev *hwdev)
{
	if (!hwdev) {
		pr_err("hwdev is null.\n");
		return;
	}

	ht_gpa_clear(hwdev);

	if (hwdev->page_pa0.virt_addr && hwdev->page_pa0.phys_addr != 0) {
		dma_free_coherent(hwdev->dev_hdl, HINIC5_HT_GPA_PAGE_SIZE,
				  hwdev->page_pa0.virt_addr,
				  (dma_addr_t)(hwdev->page_pa0.phys_addr));
		hwdev->page_pa0.virt_addr = NULL;
		hwdev->page_pa0.phys_addr = 0;
	}

	if (hwdev->page_pa1.virt_addr && hwdev->page_pa1.phys_addr != 0) {
		dma_free_coherent(hwdev->dev_hdl, HINIC5_HT_GPA_PAGE_SIZE,
				  hwdev->page_pa1.virt_addr,
				  (dma_addr_t)hwdev->page_pa1.phys_addr);
		hwdev->page_pa1.virt_addr = NULL;
		hwdev->page_pa1.phys_addr = 0;
	}
}

static int set_ppf_tmr_status(struct hinic5_hwdev *hwdev,
			      enum ppf_tmr_status status)
{
	struct comm_cmd_ppf_tmr_op op;
	u16 out_size = sizeof(op);
	int err = 0;

	if (!hwdev)
		return -EINVAL;

	memset(&op, 0, sizeof(op));

	if (hinic5_func_type(hwdev) != TYPE_PPF)
		return -EFAULT;

	op.opcode = status;
	op.ppf_id = hinic5_ppf_idx(hwdev);

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_PPF_TMR, &op,
				    sizeof(op), &op, &out_size);
	if (err != 0 || out_size == 0 || op.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set ppf timer, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, op.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_ppf_tmr_start(void *hwdev)
{
	int is_in_kexec;

	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for starting ppf timer\n");
		return -EINVAL;
	}

	is_in_kexec = hinic5_vram_get_kexec_flag();
	if (is_in_kexec != 0) {
		pr_info("Skip starting ppt timer during kexec");
		return 0;
	}

	return set_ppf_tmr_status(hwdev, HINIC_PPF_TMR_FLAG_START);
}
EXPORT_SYMBOL(hinic5_ppf_tmr_start);

int hinic5_ppf_tmr_stop(void *hwdev)
{
	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for stop ppf timer\n");
		return -EINVAL;
	}

	return set_ppf_tmr_status(hwdev, HINIC_PPF_TMR_FLAG_STOP);
}
EXPORT_SYMBOL(hinic5_ppf_tmr_stop);

static int hinic5_hinic5_vram_kalloc_align(struct hinic5_hwdev *hwdev, char *name, u32 page_size,
					   u32 page_num, struct hinic5_dma_addr_align *mem_align)
{
	void *vaddr = NULL, *align_vaddr = NULL;
	dma_addr_t paddr, align_paddr;
	u64 real_size = page_size;
	u64 align = page_size;

	vaddr = (void *)hinic5_hinic5_vram_kalloc(name, real_size);
	if (!vaddr) {
		sdk_err(hwdev->dev_hdl, "hinic5_vram kalloc failed, name:%s.\n", name);
		return -ENOMEM;
	}

	paddr = (dma_addr_t)virt_to_phys(vaddr);
	align_paddr = ALIGN(paddr, align);
	/* align */
	if (align_paddr == paddr) {
		align_vaddr = vaddr;
		goto out;
	}

	hinic5_hinic5_vram_kfree((void *)vaddr, name, real_size);

	/* realloc memory for align */
	real_size = page_size + align;
	vaddr = (void *)hinic5_hinic5_vram_kalloc(name, real_size);
	if (!vaddr) {
		sdk_err(hwdev->dev_hdl, "hinic5_vram kalloc align failed, name:%s.\n", name);
		return -ENOMEM;
	}

	paddr = (dma_addr_t)virt_to_phys(vaddr);
	align_paddr = ALIGN(paddr, align);
	align_vaddr = (void *)(uintptr_t)((u64)(uintptr_t)vaddr + (align_paddr - paddr));

out:
	mem_align->real_size = (u32)real_size;
	mem_align->ori_vaddr = vaddr;
	mem_align->ori_paddr = paddr;
	mem_align->align_vaddr = align_vaddr;
	mem_align->align_paddr = align_paddr;

	return 0;
}

static void mqm_eqm_free_page_mem(struct hinic5_hwdev *hwdev)
{
	struct hinic5_dma_addr_align *page_addr = NULL;
	u32 i;
	int is_use_hinic5_vram = get_use_hinic5_vram_flag();
	struct mqm_eqm_hinic5_vram_name_s *mqm_eqm_vram_name = hwdev->mqm_eqm_hinic5_vram_name;

	page_addr = hwdev->mqm_att.brm_srch_page_addr;

	for (i = 0; i < hwdev->mqm_att.page_num; i++) {
		if (is_use_hinic5_vram != 0) {
			hinic5_hinic5_vram_kfree(page_addr->ori_vaddr,
						 mqm_eqm_vram_name[i].hinic5_vram_name,
						 page_addr->real_size);
		} else {
			hinic5_dma_free_coherent_align(hwdev->dev_hdl, page_addr);
		}
		page_addr++;
	}
	kfree(mqm_eqm_vram_name);
	hwdev->mqm_eqm_hinic5_vram_name = NULL;
}

static int mqm_eqm_try_alloc_mem(struct hinic5_hwdev *hwdev, u32 page_size,
				 u32 page_num)
{
	struct hinic5_dma_addr_align *page_addr = hwdev->mqm_att.brm_srch_page_addr;
	int is_use_hinic5_vram = get_use_hinic5_vram_flag();
	struct mqm_eqm_hinic5_vram_name_s *mqm_eqm_hinic5_vram_name = NULL;
	u32 valid_num = 0;
	u32 flag = 1;
	u32 i = 0;
	int err;
	u16 func_id;

	mqm_eqm_hinic5_vram_name = kzalloc(sizeof(struct mqm_eqm_hinic5_vram_name_s) * page_num, GFP_KERNEL);
	if (!mqm_eqm_hinic5_vram_name)
		return -ENOMEM;

	hwdev->mqm_eqm_hinic5_vram_name = mqm_eqm_hinic5_vram_name;
	func_id = hinic5_global_func_id(hwdev);

	for (i = 0; i < page_num; i++) {
		if (is_use_hinic5_vram != 0) {
			err = snprintf(mqm_eqm_hinic5_vram_name[i].hinic5_vram_name,
				       HINIC5_VRAM_NAME_MAX_LEN, "%s%hu%s%u",
				       HINIC5_VRAM_NIC_FUNC_BASE, func_id,
				       HINIC5_VRAM_NIC_MQM, i);
			if (err < 0) {
				sdk_err(hwdev->dev_hdl,
					"mqm eqm snprintf name fail, err:%d, index:%u\n", err, i);
				flag = 0;
				break;
			}
			err = hinic5_hinic5_vram_kalloc_align(hwdev,
							      mqm_eqm_hinic5_vram_name[i].hinic5_vram_name,
							      page_size, page_num, page_addr);
		} else {
			err = hinic5_dma_zalloc_coherent_align(hwdev->dev_hdl, page_size,
							       page_size, GFP_KERNEL, page_addr);
		}
		if (err != 0) {
			flag = 0;
			break;
		}
		valid_num++;
		page_addr++;
	}

	hwdev->mqm_att.page_num = valid_num;
	if (flag == 1) {
		hwdev->mqm_att.page_size = page_size;
	} else {
		mqm_eqm_free_page_mem(hwdev);
		return -EFAULT;
	}

	return 0;
}

static int mqm_eqm_alloc_page_mem(struct hinic5_hwdev *hwdev)
{
	int ret = 0;
	u32 page_num;

	/* apply for 2M page, page number is chunk_num/1024 */
	page_num = (hwdev->mqm_att.chunk_num + 0x3ff) >> 0xa;
	ret = mqm_eqm_try_alloc_mem(hwdev, 0x2 * 0x400 * 0x400, page_num);
	if (ret == 0) {
		sdk_info(hwdev->dev_hdl, "[mqm_eqm_init] Alloc page_size 2M OK\n");
		return 0;
	}

	/* apply for 64KB page, page number is chunk_num/32 */
	page_num = (hwdev->mqm_att.chunk_num + 0x1f) >> 0x5;
	ret = mqm_eqm_try_alloc_mem(hwdev, 0x40 * 0x400, page_num);
	if (ret == 0) {
		sdk_info(hwdev->dev_hdl, "[mqm_eqm_init] Alloc page_size 64K OK\n");
		return 0;
	}

	/* apply for 4KB page, page number is chunk_num/2 */
	page_num = (hwdev->mqm_att.chunk_num + 1) >> 1;
	ret = mqm_eqm_try_alloc_mem(hwdev, 0x4 * 0x400, page_num);
	if (ret == 0) {
		sdk_info(hwdev->dev_hdl, "[mqm_eqm_init] Alloc page_size 4K OK\n");
		return 0;
	}

	return ret;
}

static int mqm_eqm_set_cfg_2_hw(struct hinic5_hwdev *hwdev, u8 valid)
{
	struct comm_cmd_eqm_cfg info_eqm_cfg;
	u16 out_size = sizeof(info_eqm_cfg);
	int err;

	memset(&info_eqm_cfg, 0, sizeof(info_eqm_cfg));

	info_eqm_cfg.host_id = hinic5_host_id(hwdev);
	info_eqm_cfg.page_size = hwdev->mqm_att.page_size;
	info_eqm_cfg.valid = valid;
	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_SET_MQM_CFG_INFO,
				    &info_eqm_cfg, sizeof(info_eqm_cfg),
				    &info_eqm_cfg, &out_size);
	if (err != 0 || out_size == 0 || info_eqm_cfg.head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to init func table, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, info_eqm_cfg.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

#define EQM_DATA_BUF_SIZE	1024
#define MQM_ATT_PAGE_NUM	128

static int mqm_eqm_set_page_2_hw(struct hinic5_hwdev *hwdev)
{
	struct comm_cmd_eqm_search_gpa *info = NULL;
	struct hinic5_dma_addr_align *page_addr = NULL;
	void *send_buf = NULL;
	u16 send_buf_size, out_size;
	u64 *gpa_hi52 = NULL;
	u64 gpa;
	u32 num, start_idx, i;
	int err = 0;
	u8  cmd;

	send_buf_size = sizeof(struct comm_cmd_eqm_search_gpa) +
			EQM_DATA_BUF_SIZE;
	send_buf = kzalloc(send_buf_size, GFP_KERNEL);
	if (!send_buf) {
		sdk_err(hwdev->dev_hdl, "Alloc virtual mem failed\r\n");
		return -EFAULT;
	}

	page_addr = hwdev->mqm_att.brm_srch_page_addr;
	info = (struct comm_cmd_eqm_search_gpa *)send_buf;

	gpa_hi52 = info->gpa_hi52;
	num = 0;
	start_idx = 0;
	cmd = COMM_MGMT_CMD_SET_MQM_SRCH_GPA;
	for (i = 0; i < hwdev->mqm_att.page_num; i++) {
		/* gpa align to 4K, save gpa[31:12] */
		gpa = page_addr->align_paddr >> 12;
		gpa_hi52[num] = gpa;
		num++;
		if (num == MQM_ATT_PAGE_NUM) {
			info->num = num;
			info->start_idx = start_idx;
			info->host_id = hinic5_host_id(hwdev);
			out_size = send_buf_size;
			err = comm_msg_to_mgmt_sync(hwdev, cmd, info, (u16)send_buf_size,
						    info, &out_size);
			if (MSG_TO_MGMT_SYNC_RETURN_ERR(err, out_size, info->head.status)) {
				sdk_err(hwdev->dev_hdl, "Set mqm srch gpa fail, err: %d, status: 0x%x, out_size: 0x%x\n",
					err, info->head.status, out_size);
				err = -EFAULT;
				goto set_page_2_hw_end;
			}

			gpa_hi52 = info->gpa_hi52;
			num = 0;
			start_idx = i + 1;
		}
		page_addr++;
	}

	if (num != 0) {
		info->num = num;
		info->start_idx = start_idx;
		info->host_id = hinic5_host_id(hwdev);
		out_size = send_buf_size;
		err = comm_msg_to_mgmt_sync(hwdev, cmd, info, (u16)send_buf_size, info, &out_size);
		if (MSG_TO_MGMT_SYNC_RETURN_ERR(err, out_size, info->head.status)) {
			sdk_err(hwdev->dev_hdl, "Set mqm srch gpa fail, err: %d, status: 0x%x, out_size: 0x%x\n",
				err, info->head.status, out_size);
			err = -EFAULT;
			goto set_page_2_hw_end;
		}
	}

set_page_2_hw_end:
	kfree(send_buf);
	return err;
}

static int get_eqm_num(struct hinic5_hwdev *hwdev, struct comm_cmd_get_eqm_num *info_eqm_fix)
{
	int ret;
	u16 len = sizeof(*info_eqm_fix);

	memset(info_eqm_fix, 0, sizeof(*info_eqm_fix));

	ret = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_GET_MQM_FIX_INFO,
				    info_eqm_fix, sizeof(*info_eqm_fix), info_eqm_fix, &len);
	if (ret != 0 || len == 0 || info_eqm_fix->head.status != 0) {
		sdk_err(hwdev->dev_hdl, "Get mqm fix info fail,err: %d, status: 0x%x, out_size: 0x%x\n",
			ret, info_eqm_fix->head.status, len);
		return -EFAULT;
	}

	sdk_info(hwdev->dev_hdl, "get chunk_num: 0x%x, search_gpa_num: 0x%08x\n",
		 info_eqm_fix->chunk_num, info_eqm_fix->search_gpa_num);

	return 0;
}

static int mqm_eqm_init(struct hinic5_hwdev *hwdev)
{
	struct comm_cmd_get_eqm_num info_eqm_fix;
	int ret;

	if (hwdev->hwif->attr.func_type != TYPE_PPF)
		return 0;

	ret = get_eqm_num(hwdev, &info_eqm_fix);
	if (ret != 0)
		return ret;

	if (info_eqm_fix.chunk_num == 0)
		return 0;

	hwdev->mqm_att.chunk_num = info_eqm_fix.chunk_num;
	hwdev->mqm_att.search_gpa_num = info_eqm_fix.search_gpa_num;
	hwdev->mqm_att.page_size = 0;
	hwdev->mqm_att.page_num  = 0;

	hwdev->mqm_att.brm_srch_page_addr =
		kcalloc(hwdev->mqm_att.chunk_num, sizeof(struct hinic5_dma_addr_align), GFP_KERNEL);
	if (!(hwdev->mqm_att.brm_srch_page_addr)) {
		sdk_err(hwdev->dev_hdl, "Alloc virtual mem failed\r\n");
		return -EFAULT;
	}

	ret = mqm_eqm_alloc_page_mem(hwdev);
	if (ret != 0) {
		sdk_err(hwdev->dev_hdl, "Alloc eqm page mem failed\r\n");
		goto err_page;
	}

	ret = mqm_eqm_set_page_2_hw(hwdev);
	if (ret != 0) {
		sdk_err(hwdev->dev_hdl, "Set page to hw failed\r\n");
		goto err_ecmd;
	}

	ret = mqm_eqm_set_cfg_2_hw(hwdev, 1);
	if (ret != 0) {
		sdk_err(hwdev->dev_hdl, "Set page to hw failed\r\n");
		goto err_ecmd;
	}

	sdk_info(hwdev->dev_hdl, "ppf_ext_db_init ok\r\n");

	return 0;

err_ecmd:
	mqm_eqm_free_page_mem(hwdev);

err_page:
	kfree(hwdev->mqm_att.brm_srch_page_addr);

	return ret;
}

static void mqm_eqm_deinit(struct hinic5_hwdev *hwdev)
{
	int ret;

	if (hwdev->hwif->attr.func_type != TYPE_PPF)
		return;

	if (hwdev->mqm_att.chunk_num == 0)
		return;

	mqm_eqm_free_page_mem(hwdev);
	kfree(hwdev->mqm_att.brm_srch_page_addr);

	ret = mqm_eqm_set_cfg_2_hw(hwdev, 0);
	if (ret != 0) {
		sdk_err(hwdev->dev_hdl, "Set mqm eqm cfg to chip fail! err: %d\n",
			ret);
		return;
	}

	hwdev->mqm_att.chunk_num = 0;
	hwdev->mqm_att.search_gpa_num = 0;
	hwdev->mqm_att.page_num = 0;
	hwdev->mqm_att.page_size = 0;
}

int hinic5_ppf_ext_db_init(struct hinic5_hwdev *hwdev)
{
	int ret;

	ret = mqm_eqm_init(hwdev);
	if (ret != 0) {
		sdk_err(hwdev->dev_hdl, "MQM eqm init fail!\n");
		return -EFAULT;
	}

	return 0;
}

int hinic5_ppf_ext_db_deinit(struct hinic5_hwdev *hwdev)
{
	if (!hwdev)
		return -EINVAL;

	mqm_eqm_deinit(hwdev);

	return 0;
}

static enum hinic5_wait_return check_flr_finish_handler(void *priv_data)
{
	struct hinic5_hwif *hwif = priv_data;
	enum hinic5_pf_status status;

	status = hinic5_get_pf_status(hwif);
	if (status == HINIC5_PF_STATUS_FLR_FINISH_FLAG) {
#if defined(__UEFI__) && !defined(__HIFC__)
		hinic5_set_pf_status(hwif, HINIC5_PF_STATUS_INIT);
#else
		hinic5_set_pf_status(hwif, HINIC5_PF_STATUS_ACTIVE_FLAG);
#endif
		return WAIT_PROCESS_CPL;
	}

	return WAIT_PROCESS_WAITING;
}

#define HINIC5_FLR_TIMEOUT		40000

static int wait_for_flr_finish(struct hinic5_hwif *hwif, u32 flr_timeout_ms)
{
	u32 flr_timeout = (flr_timeout_ms == 0) ? HINIC5_FLR_TIMEOUT : flr_timeout_ms;

	return hinic5_wait_for_timeout(hwif, check_flr_finish_handler,
				       flr_timeout, 0xa * USEC_PER_MSEC);
}

#define HINIC5_WAIT_CMDQ_IDLE_TIMEOUT		5000

static enum hinic5_wait_return check_cmdq_stop_handler(void *priv_data)
{
	struct hinic5_hwdev *hwdev = priv_data;
	struct hinic5_cmdqs *cmdqs = hwdev->cmdqs;
	u32 cmdq_type;

	/* Stop waiting when card unpresent */
	if (!hinic5_is_chip_present(hwdev))
		return WAIT_PROCESS_CPL;

	cmdq_type = (u32)HINIC5_CMDQ_SYNC;
	for (; cmdq_type < cmdqs->cmdq_num; cmdq_type++) {
		if (!hinic5_cmdq_idle(&cmdqs->cmdq[cmdq_type]))
			return WAIT_PROCESS_WAITING;
	}

	return WAIT_PROCESS_CPL;
}

static int wait_cmdq_stop(struct hinic5_hwdev *hwdev)
{
	u32 cmdq_type;
	struct hinic5_cmdqs *cmdqs = hwdev->cmdqs;
	int err;

	if ((cmdqs->status & HINIC5_CMDQ_ENABLE) == 0)
		return 0;

	cmdqs->status &= ~HINIC5_CMDQ_ENABLE;

	err = hinic5_wait_for_timeout(hwdev, check_cmdq_stop_handler,
				      HINIC5_WAIT_CMDQ_IDLE_TIMEOUT,
				      USEC_PER_MSEC);
	if (err == 0)
		return 0;

	cmdq_type = (u32)HINIC5_CMDQ_SYNC;
	for (; cmdq_type < cmdqs->cmdq_num; cmdq_type++) {
		if (!hinic5_cmdq_idle(&cmdqs->cmdq[cmdq_type]))
			sdk_err(hwdev->dev_hdl, "Cmdq %u is busy\n", cmdq_type);
	}

	cmdqs->status |= HINIC5_CMDQ_ENABLE;

	return err;
}

static int hinic5_rx_tx_flush(struct hinic5_hwdev *hwdev, u16 channel, bool wait_io,
			      u32 flr_timeout_ms)
{
	struct hinic5_hwif *hwif = hwdev->hwif;
	struct comm_cmd_clear_doorbell clear_db;
	struct comm_cmd_clear_resource clr_res;
	u16 out_size;
	int err;

	if (HINIC5_FUNC_TYPE(hwdev) != TYPE_VF && wait_io == true)
		msleep(100); /* wait ucode 100 ms stop I/O */

	err = wait_cmdq_stop(hwdev);
	if (err != 0)
		sdk_warn(hwdev->dev_hdl, "CMDQ is still working, please check CMDQ timeout value is reasonable\n");

	hinic5_disable_doorbell(hwif);

	out_size = sizeof(clear_db);
	memset(&clear_db, 0, sizeof(clear_db));
	clear_db.func_id = HINIC5_HWIF_GLOBAL_IDX(hwif);

	err = comm_msg_to_mgmt_sync_ch(hwdev,  COMM_MGMT_CMD_FLUSH_DOORBELL, &clear_db,
				       sizeof(clear_db), &clear_db, &out_size, channel);
	if (err != 0 || out_size == 0 || clear_db.head.status != 0) {
		sdk_warn(hwdev->dev_hdl, "Failed to flush doorbell, err: %d, status: 0x%x, out_size: 0x%x, channel: 0x%x\n",
			 err, clear_db.head.status, out_size, channel);
	}

	hinic5_set_pf_status(hwif, HINIC5_PF_STATUS_FLR_START_FLAG);

	memset(&clr_res, 0, sizeof(clr_res));
	clr_res.func_id = HINIC5_HWIF_GLOBAL_IDX(hwif);

	err = hinic5_msg_to_mgmt_no_ack(hwdev, HINIC5_MOD_COMM, COMM_MGMT_CMD_START_FLUSH, &clr_res,
					sizeof(clr_res), channel);
	if (err != 0)
		sdk_warn(hwdev->dev_hdl, "Failed to notice flush message, err: %d, channel: 0x%x\n",
			 err, channel);

	if (HINIC5_FUNC_TYPE(hwdev) != TYPE_VF) {
		err = wait_for_flr_finish(hwif, flr_timeout_ms);
		if (err != 0)
			sdk_warn(hwdev->dev_hdl, "Wait firmware FLR timeout\n");
	}

	hinic5_enable_doorbell(hwif);

	err = hinic5_reinit_cmdq_ctxts(hwdev);
	if (err != 0)
		sdk_warn(hwdev->dev_hdl, "Failed to reinit cmdq\n");

	return err;
}

int hinic5_func_rx_tx_flush(void *hwdev, u16 channel, bool wait_io, u32 flr_timeout_ms)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return -EINVAL;

	if (!hinic5_is_chip_present(dev))
		return 0;

	return hinic5_rx_tx_flush(dev, channel, wait_io, flr_timeout_ms);
}
EXPORT_SYMBOL(hinic5_func_rx_tx_flush);

int hinic5_get_board_info(void *hwdev, struct hinic5_board_info *info,
			  u16 channel)
{
	struct comm_cmd_board_info board_info;
	u16 out_size = sizeof(board_info);
	int err;

	if (!hwdev || !info)
		return -EINVAL;

	memset(&board_info, 0, sizeof(board_info));
	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_GET_BOARD_INFO,
				       &board_info, sizeof(board_info),
				       &board_info, &out_size, channel);
	if (err != 0 || out_size == 0 || board_info.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to get board info, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, board_info.head.status, out_size, channel);
		return -EIO;
	}

	memcpy(info, &board_info.info, sizeof(*info));

	return 0;
}
EXPORT_SYMBOL(hinic5_get_board_info);

int hinic5_get_hw_pf_infos(void *hwdev, struct hinic5_hw_pf_infos *infos,
			   u16 channel)
{
	struct comm_cmd_hw_pf_infos *pf_infos = NULL;
	u16 out_size = sizeof(*pf_infos);
	int err = 0;

	if (!hwdev || !infos)
		return -EINVAL;

	pf_infos = kzalloc(sizeof(*pf_infos), GFP_KERNEL);
	if (!pf_infos)
		return -ENOMEM;

	err = comm_msg_to_mgmt_sync_ch(hwdev, COMM_MGMT_CMD_GET_HW_PF_INFOS,
				       pf_infos, sizeof(*pf_infos),
				       pf_infos, &out_size, channel);
	if (err != 0 || out_size == 0 || pf_infos->head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to get hw pf information, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, pf_infos->head.status, out_size, channel);
		err = -EIO;
		goto free_buf;
	}

	memcpy(infos, &pf_infos->infos, sizeof(struct hinic5_hw_pf_infos));

free_buf:
	kfree(pf_infos);
	return err;
}
EXPORT_SYMBOL(hinic5_get_hw_pf_infos);

int hinic5_get_global_attr(void *hwdev, struct comm_global_attr *attr)
{
	struct comm_cmd_get_glb_attr get_attr = { 0 };
	u16 out_size = sizeof(get_attr);
	int err = 0;

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_GET_GLOBAL_ATTR,
				    &get_attr, sizeof(get_attr), &get_attr,
				    &out_size);
	if (err != 0 || out_size == 0 || get_attr.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to get global attribute, err: %d, status: 0x%x, out size: 0x%x\n",
			err, get_attr.head.status, out_size);
		return -EIO;
	}

	memcpy(attr, &get_attr.attr, sizeof(struct comm_global_attr));

	return 0;
}

int hinic5_set_func_svc_used_state(void *hwdev, u16 svc_type, u8 state,
				   u16 channel)
{
	struct comm_cmd_func_svc_used_state used_state;
	u16 out_size = sizeof(used_state);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&used_state, 0, sizeof(used_state));
	used_state.func_id = hinic5_global_func_id(hwdev);
	used_state.svc_type = svc_type;
	used_state.used_state = state;

	err = comm_msg_to_mgmt_sync_ch(hwdev,
				       COMM_MGMT_CMD_SET_FUNC_SVC_USED_STATE,
				       &used_state, sizeof(used_state),
				       &used_state, &out_size, channel);
	if (err != 0 || out_size == 0 || used_state.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set func service used state, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n\n",
			err, used_state.head.status, out_size, channel);
		return -EIO;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_set_func_svc_used_state);

int hinic5_get_sml_table_info(void *hwdev, u32 tbl_id, u8 *node_id, u8 *instance_id)
{
	struct sml_table_id_info sml_table = {0};
	struct comm_cmd_get_sml_tbl_data sml_tbl = {0};
	u16 out_size = sizeof(sml_tbl);
	int err;

	if (!hwdev)
		return -EINVAL;

	if (tbl_id != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl, "sml table index is not 0");
		return -EINVAL;
	}

	err = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_GET_SML_TABLE_INFO,
				    &sml_tbl, sizeof(sml_tbl), &sml_tbl, &out_size);
	if (err != 0 || out_size == 0 || sml_tbl.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to get sml table information, err: %d, status: 0x%x, out size: 0x%x\n",
			err, sml_tbl.head.status, out_size);
		return -EIO;
	}

	memcpy(&sml_table, sml_tbl.tbl_data, sizeof(sml_table));

	*node_id = sml_table.node_id;
	*instance_id = sml_table.instance_id;

	return 0;
}

int hinic5_activate_firmware(void *hwdev, u8 cfg_index)
{
	struct hinic5_cmd_activate_firmware activate_msg;
	u16 out_size = sizeof(activate_msg);
	int err;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) == TYPE_VF)
		return -EOPNOTSUPP;

	memset(&activate_msg, 0, sizeof(activate_msg));
	activate_msg.index = cfg_index;

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, COMM_MGMT_CMD_ACTIVE_FW,
				      &activate_msg, sizeof(activate_msg),
				      &activate_msg, &out_size, FW_UPDATE_MGMT_TIMEOUT, 0);
	if (err != 0 || out_size == 0 || activate_msg.msg_head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to activate firmware, err: %d, status: 0x%x, out size: 0x%x\n",
			err, activate_msg.msg_head.status, out_size);
		err = (activate_msg.msg_head.status != 0) ? activate_msg.msg_head.status : -EIO;
		return err;
	} else {
		return 0;
	}
}

int hinic5_switch_config(void *hwdev, u8 cfg_index)
{
	struct hinic5_cmd_switch_config switch_cfg;
	u16 out_size = sizeof(switch_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) != TYPE_PF)
		return -EOPNOTSUPP;

	if (!COMM_SUPPORT_API_CHAIN((struct hinic5_hwdev *)hwdev))
		return -EPERM;

	memset(&switch_cfg, 0, sizeof(switch_cfg));
	switch_cfg.index = cfg_index;

	err = hinic5_pf_to_mgmt_sync(hwdev, HINIC5_MOD_COMM, COMM_MGMT_CMD_SWITCH_CFG,
				     &switch_cfg, sizeof(switch_cfg),
				     &switch_cfg, &out_size, FW_UPDATE_MGMT_TIMEOUT);
	if (err != 0 || out_size == 0 || switch_cfg.msg_head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to switch cfg, err: %d, status: 0x%x, out size: 0x%x\n",
			err, switch_cfg.msg_head.status, out_size);
		err = (switch_cfg.msg_head.status != 0) ? switch_cfg.msg_head.status : -EIO;
		return err;
	}

	return 0;
}

int hinic5_get_secure_mem_cfg(struct hinic5_hwdev *hwdev, dma_addr_t *gpa, u32 *len)
{
	struct hinic5_cqm_cmd_func_secure_mem mem_info;
	u16 out_size = sizeof(mem_info);
	int ret;

	if (!hwdev || !gpa || !len)
		return -EPERM;

	memset(&mem_info, 0, sizeof(mem_info));
	mem_info.func_id = hinic5_global_func_id((void *)hwdev);

	ret = comm_msg_to_mgmt_sync(hwdev, COMM_MGMT_CMD_GET_FUNC_SECURE_MEM,
				    &mem_info, sizeof(mem_info),
				    &mem_info, &out_size);
	if (mem_info.head.status == HINIC5_MGMT_CMD_UNSUPPORTED)
		return -EPERM;

	if (ret != 0 || out_size == 0 || mem_info.head.status != 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to get memsec info, ret: %d, status: 0x%x, out size: 0x%x\n",
			ret, mem_info.head.status, out_size);
		return -EINVAL;
	}

	if (mem_info.valid == 0)
		return -EPERM;

	*len = mem_info.len;
	*gpa = (dma_addr_t)MAKE_64BITS(mem_info.gpa_hi, mem_info.gpa_lo);

	return 0;
}

#define PLUG_SRV_GET 1
#define PLUG_SRV_SET 0

int hisdk5_set_plug_srv_bitmap(void *hwdev, u8 srv_type, u16 func_id, u8 attach_en)
{
	struct comm_cmd_plug_srv plug_srv;
	u16 out_size = sizeof(plug_srv);
	int ret;

	if (!hwdev)
		return -EPERM;

	memset(&plug_srv, 0, sizeof(plug_srv));
	plug_srv.func_id = func_id;
	plug_srv.srv_type = srv_type;
	plug_srv.attach_en = attach_en;

	ret = comm_msg_to_mgmt_sync((struct hinic5_hwdev *)hwdev, COMM_MGMT_CMD_SET_FUNC_PLUG_SRV,
				    &plug_srv, sizeof(plug_srv),
				    &plug_srv, &out_size);
	if (ret != 0 || out_size == 0 || plug_srv.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to set plug srv_bitmap, ret: %d, status: 0x%x, out size: 0x%x\n",
			ret, plug_srv.head.status, out_size);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(hisdk5_set_plug_srv_bitmap);

int hisdk5_get_plug_srv_bitmap(void *hwdev, u8 srv_type, u16 func_id, u8 *attach_en)
{
	struct comm_cmd_plug_srv plug_srv;
	u16 out_size = sizeof(plug_srv);
	int ret;

	if (!hwdev)
		return -EPERM;

	memset(&plug_srv, 0, sizeof(plug_srv));
	plug_srv.func_id = func_id;
	plug_srv.srv_type = srv_type;

	ret = comm_msg_to_mgmt_sync((struct hinic5_hwdev *)hwdev, COMM_MGMT_CMD_GET_FUNC_PLUG_SRV,
				    &plug_srv, sizeof(plug_srv),
				    &plug_srv, &out_size);
	if (ret != 0 || out_size == 0 || plug_srv.head.status != 0) {
		sdk_err(((struct hinic5_hwdev *)hwdev)->dev_hdl,
			"Failed to get plug srv_bitmap, ret: %d, status: 0x%x, out size: 0x%x\n",
			ret, plug_srv.head.status, out_size);
		return -EINVAL;
	}

	*attach_en = plug_srv.attach_en;

	return 0;
}
EXPORT_SYMBOL(hisdk5_get_plug_srv_bitmap);
