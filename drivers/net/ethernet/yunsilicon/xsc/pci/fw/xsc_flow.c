// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"

#include "xsc_flow.h"

static DECLARE_COMPLETION(dma_read_done);

static inline int xsc_dma_wr_isbusy(struct xsc_core_device *xdev)
{
	u32 busy = 0;

	do {
		busy = REG_RD32(xdev, HIF_TBL_TBL_DL_BUSY_REG_ADDR);
	} while (busy != 0x0);

	return busy;
}

static inline int xsc_dma_rd_isbusy(struct xsc_core_device *xdev)
{
	u32 busy = 0;

	do {
		busy = REG_RD32(xdev, CLSF_DMA_DMA_UL_BUSY_REG_ADDR);
	} while (busy != 0x0);

	return busy;
}

static inline int xsc_dma_done(struct xsc_core_device *xdev)
{
	u32 done = 0;

	do {
		done = REG_RD32(xdev, CLSF_DMA_DMA_DL_DONE_REG_ADDR);
	} while ((done & 0x1) != 0x1);

	return done;
}

static inline void xsc_dma_wr_success_get(struct xsc_core_device *xdev, u32 *success, u32 size)
{
	u32 *ptr = NULL;

	ptr = success;
	IA_READ(xdev, CLSF_DMA_DMA_DL_SUCCESS_REG_ADDR, ptr, (size / sizeof(u32)));
}

int xsc_flow_table_dma_write_add(struct xsc_core_device *xdev,
				 const struct tdi_dma_write_key_bits *key,
				 const struct tdi_dma_write_action_bits *action)
{
	u32 i = 0;
	u32 busy = 0;
	u32 dma_wr_num = 0;
	u32 value = 0;
	u32 done = 0;
	u64 success[2];
	u32 data_len = 0;
	u64 dma_wr_addr = 0;

	if (!xdev || !key || !action)
		return -1;

	if (!action->entry_num)
		return -1;

	dma_wr_num = ((action->entry_num + (XSC_DMA_WR_MAX - 1)) / XSC_DMA_WR_MAX);

	for (i = 0; i < dma_wr_num; i++) {
		if ((action->entry_num % XSC_DMA_WR_MAX) && (i == (dma_wr_num - 1)))
			data_len = ((action->entry_num % XSC_DMA_WR_MAX) * XSC_DMA_LEN);
		else
			data_len = (XSC_DMA_WR_MAX * XSC_DMA_LEN);

		busy = xsc_dma_wr_isbusy(xdev);
		if (busy)
			return -1;

		REG_WR32(xdev, CLSF_DMA_ERR_CODE_CLR_REG_ADDR, 1);

		value = ((data_len << HIF_TBL_TBL_DL_REQ_REG_TBL_DL_LEN_SHIFT) |
			(key->host_id << HIF_TBL_TBL_DL_REQ_REG_TBL_DL_HOST_ID_SHIFT) |
			key->func_id);

		REG_WR32(xdev, HIF_TBL_TBL_DL_REQ_REG_ADDR, value);

		dma_wr_addr = (action->data_addr + ((i * XSC_DMA_WR_MAX) * XSC_DMA_LEN));
		value = (dma_wr_addr & HIF_TBL_TBL_DL_ADDR_L_REG_TBL_DL_ADDR_L_MASK);
		REG_WR32(xdev, HIF_TBL_TBL_DL_ADDR_L_REG_ADDR, value);

		value = ((dma_wr_addr >> 32) & HIF_TBL_TBL_DL_ADDR_H_REG_TBL_DL_ADDR_H_MASK);
		REG_WR32(xdev, HIF_TBL_TBL_DL_ADDR_H_REG_ADDR, value);

		REG_WR32(xdev, HIF_TBL_TBL_DL_START_REG_ADDR, 1);

		done = xsc_dma_done(xdev);
		if (done != XSC_DMA_WR_SUCCESS) {
			memset(success, 0, sizeof(success));
			xsc_dma_wr_success_get(xdev, (u32 *)&success, sizeof(success));
			xsc_core_err(xdev, "DMA write time %d status 0x%lx%lx fail.\n", i,
				     (unsigned long)success[1], (unsigned long)success[0]);
			return -1;
		}
	}

	return 0;
}

void xsc_dma_read_done_complete(void)
{
	complete(&dma_read_done);
}

int xsc_flow_table_dma_read_add(struct xsc_core_device *xdev,
				const struct tdi_dma_read_key_bits *key,
				const struct tdi_dma_read_action_bits *action)
{
	u32 busy = 0;
	u32 value = 0;

	if (!xdev || !key || !action)
		return -1;

	if (!action->burst_num)
		return -1;

	busy = xsc_dma_rd_isbusy(xdev);
	if (busy)
		return -1;

	value = ((key->host_id << HIF_TBL_TBL_UL_REQ_REG_TBL_UL_HOST_ID_SHIFT) |
		key->func_id);

	REG_WR32(xdev, HIF_TBL_TBL_UL_REQ_REG_ADDR, value);

	value = (action->data_addr & HIF_TBL_TBL_UL_ADDR_L_REG_TBL_UL_ADDR_L_MASK);
	REG_WR32(xdev, HIF_TBL_TBL_UL_ADDR_L_REG_ADDR, value);

	value = ((action->data_addr >> 32) & HIF_TBL_TBL_UL_ADDR_H_REG_TBL_UL_ADDR_H_MASK);
	REG_WR32(xdev, HIF_TBL_TBL_UL_ADDR_H_REG_ADDR, value);

	REG_WR32(xdev, HIF_TBL_TBL_UL_START_REG_ADDR, 1);

	value = (key->tbl_id & CLSF_DMA_DMA_RD_TABLE_ID_REG_DMA_RD_TBL_ID_MASK);
	REG_WR32(xdev, CLSF_DMA_DMA_RD_TABLE_ID_REG_ADDR, value);

	value = ((action->burst_num << CLSF_DMA_DMA_RD_ADDR_REG_DMA_RD_BURST_NUM_SHIFT) |
		key->tbl_start_addr);
	REG_WR32(xdev, CLSF_DMA_DMA_RD_ADDR_REG_ADDR, value);

	REG_WR32(xdev, CLSF_DMA_INDRW_RD_START_REG_ADDR, 1);

	/*wait msix interrupt */
	if (!wait_for_completion_timeout(&dma_read_done, msecs_to_jiffies(5000))) {
		xsc_core_err(xdev, "wait for dma read done completion timeout.\n");
		return -ETIMEDOUT;
	}

	REG_WR32(xdev, HIF_TBL_MSG_RDY_REG_ADDR, 1);

	return 0;
}

int xsc_flow_add(struct xsc_core_device *xdev,
		 int table, int length, void *data)
{
	int ret = -EINVAL;
	struct xsc_flow_dma_write_add *dma_wr;
	struct xsc_flow_dma_read_add *dma_rd;

	switch (table) {
	case XSC_FLOW_DMA_WR:
		if (length == sizeof(struct xsc_flow_dma_write_add)) {
			dma_wr = (struct xsc_flow_dma_write_add *)data;
			ret = xsc_flow_table_dma_write_add(xdev, &dma_wr->key, &dma_wr->action);
		}
		break;
	case XSC_FLOW_DMA_RD:
		if (length == sizeof(struct xsc_flow_dma_read_add)) {
			dma_rd = (struct xsc_flow_dma_read_add *)data;
			ret = xsc_flow_table_dma_read_add(xdev, &dma_rd->key, &dma_rd->action);
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

