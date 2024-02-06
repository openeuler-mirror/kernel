// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/driver.h"
#include "common/device.h"
#include "common/xsc_core.h"
#include "wq.h"

u32 xsc_wq_cyc_get_size(struct xsc_wq_cyc *wq)
{
	return (u32)wq->fbc.sz_m1 + 1;
}
EXPORT_SYMBOL_GPL(xsc_wq_cyc_get_size);

static u32 wq_get_byte_sz(u8 log_sz, u8 log_stride)
{
	return ((u32)1 << log_sz) << log_stride;
}

int xsc_eth_cqwq_create(struct xsc_core_device *xdev, struct xsc_wq_param *param,
			u8 q_log_size, u8 ele_log_size, struct xsc_cqwq *wq,
			struct xsc_wq_ctrl *wq_ctrl)
{
	u8 log_wq_stride = ele_log_size;
	u8 log_wq_sz     = q_log_size;
	int err;

	err = xsc_db_alloc_node(xdev, &wq_ctrl->db, param->db_numa_node);
	if (err) {
		xsc_core_warn(xdev, "xsc_db_alloc_node() failed, %d\n", err);
		return err;
	}

	err = xsc_frag_buf_alloc_node(xdev, wq_get_byte_sz(log_wq_sz, log_wq_stride),
				      &wq_ctrl->buf,
				      param->buf_numa_node);
	if (err) {
		xsc_core_warn(xdev, "xsc_frag_buf_alloc_node() failed, %d\n", err);
		goto err_db_free;
	}

	xsc_init_fbc(wq_ctrl->buf.frags, log_wq_stride, log_wq_sz, &wq->fbc);

	wq_ctrl->xdev = xdev;

	return 0;

err_db_free:
	xsc_db_free(xdev, &wq_ctrl->db);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_eth_cqwq_create);

int xsc_eth_wq_cyc_create(struct xsc_core_device *xdev, struct xsc_wq_param *param,
			  u8 q_log_size, u8 ele_log_size, struct xsc_wq_cyc *wq,
			  struct xsc_wq_ctrl *wq_ctrl)
{
	u8 log_wq_stride = ele_log_size;
	u8 log_wq_sz     = q_log_size;
	struct xsc_frag_buf_ctrl *fbc = &wq->fbc;
	int err;

	err = xsc_db_alloc_node(xdev, &wq_ctrl->db, param->db_numa_node);
	if (err) {
		xsc_core_warn(xdev, "xsc_db_alloc_node() failed, %d\n", err);
		return err;
	}

	err = xsc_frag_buf_alloc_node(xdev, wq_get_byte_sz(log_wq_sz, log_wq_stride),
				      &wq_ctrl->buf, param->buf_numa_node);
	if (err) {
		xsc_core_warn(xdev, "xsc_frag_buf_alloc_node() failed, %d\n", err);
		goto err_db_free;
	}

	xsc_init_fbc(wq_ctrl->buf.frags, log_wq_stride, log_wq_sz, fbc);
	wq->sz = xsc_wq_cyc_get_size(wq);

	wq_ctrl->xdev = xdev;

	return 0;

err_db_free:
	xsc_db_free(xdev, &wq_ctrl->db);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_eth_wq_cyc_create);

void xsc_eth_wq_destroy(struct xsc_wq_ctrl *wq_ctrl)
{
	xsc_frag_buf_free(wq_ctrl->xdev, &wq_ctrl->buf);
	xsc_db_free(wq_ctrl->xdev, &wq_ctrl->db);
}
EXPORT_SYMBOL_GPL(xsc_eth_wq_destroy);

