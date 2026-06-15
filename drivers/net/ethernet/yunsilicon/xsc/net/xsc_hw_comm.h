/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_HW_COMMON_H
#define XSC_HW_COMMON_H

#include "xsc_eth.h"

int xsc_hw_kernel_call(struct xsc_core_device *xdev, u16 opcode, void *req, void *rsp);
int xsc_cmd_destroy_cq(struct xsc_core_device *dev, struct xsc_core_cq *xcq);
int xsc_eth_create_cq(struct xsc_core_device *xdev, struct xsc_core_cq *xcq,
		      struct xsc_create_cq_ex_mbox_in *in, int insize);
int xsc_eth_modify_qp_status(struct xsc_core_device *xdev,
			     u32 qpn, u16 status);
int xsc_eth_create_qp_sq(struct xsc_core_device *xdev, struct xsc_sq *psq,
			 struct xsc_create_qp_mbox_in *in, int insize);
int xsc_eth_modify_qp_sq(struct xsc_core_device *xdev, struct xsc_modify_raw_qp_mbox_in *in);
int xsc_eth_destroy_qp_sq(struct xsc_core_device *xdev, struct xsc_sq *psq);
int xsc_eth_create_rss_qp_rqs(struct xsc_core_device *xdev,
			      struct xsc_create_multiqp_mbox_in *in,
			      int insize,
			      int *prqn_base);
int xsc_eth_destroy_qp_rq(struct xsc_core_device *xdev, struct xsc_rq *prq);

#endif
