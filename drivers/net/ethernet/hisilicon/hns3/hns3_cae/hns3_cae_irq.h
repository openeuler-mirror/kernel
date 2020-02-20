/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_IRQ_H__
#define __HNS3_CAE_IRQ_H__

int hns3_irq_lli_cfg(const struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out,
		     u32 out_size);
#endif
