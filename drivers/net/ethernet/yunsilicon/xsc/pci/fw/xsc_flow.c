// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"

#include "xsc_flow.h"

static DECLARE_COMPLETION(dma_read_done);

static int xsc_flow_table_dma_write_add(struct xsc_core_device *xdev,
					const struct tdi_dma_write_key_bits *key,
					const struct tdi_dma_write_action_bits *action)
{
	u32 i = 0;
	u32 dma_wr_num = 0;
	u32 data_len = 0;
	u64 dma_wr_addr = 0;
	u64 success[2];
	int ret;

	if (!xdev || !key || !action)
		return -1;

	if (!action->entry_num)
		return -1;

	dma_wr_num = ((action->entry_num + (XSC_DMA_WR_MAX - 1)) / XSC_DMA_WR_MAX);

	for (i = 0; i < dma_wr_num; i++) {
		dma_wr_addr = (action->data_addr + ((i * XSC_DMA_WR_MAX) * XSC_DMA_LEN));
		if ((action->entry_num % XSC_DMA_WR_MAX) && (i == (dma_wr_num - 1)))
			data_len = ((action->entry_num % XSC_DMA_WR_MAX) * XSC_DMA_LEN);
		else
			data_len = (XSC_DMA_WR_MAX * XSC_DMA_LEN);
		memset(success, 0, sizeof(success));
		ret = xsc_dma_write_tbl_once(xdev, data_len, dma_wr_addr, key->host_id,
					     key->func_id, success, sizeof(success));
		if (ret) {
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

static int xsc_flow_table_dma_read_add(struct xsc_core_device *xdev,
				       const struct tdi_dma_read_key_bits *key,
				       const struct tdi_dma_read_action_bits *action)
{
	if (!xdev || !key || !action)
		return -1;

	if (!action->burst_num)
		return -1;

	xsc_dma_read_tbl(xdev, key->host_id, key->func_id, action->data_addr,
			 key->tbl_id, action->burst_num, key->tbl_start_addr);
	/*wait msix interrupt */
	if (!wait_for_completion_timeout(&dma_read_done, msecs_to_jiffies(5000))) {
		xsc_core_err(xdev, "wait for dma read done completion timeout.\n");
		return -ETIMEDOUT;
	}

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

