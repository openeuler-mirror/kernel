/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_QINFO_H__
#define __HNS3_CAE_QINFO_H__

#include "hclge_main.h"
#include "hclge_cmd.h"
#include "hns3_enet.h"

#define HNS3_RING_RX_RING_EBDNUM_REG		0x00024
#ifndef HNS3_RING_TX_RING_EBDNUM_REG
#define HNS3_RING_TX_RING_EBDNUM_REG		0x00068
#endif

struct qinfo_param {
	int qid;
	int tx_head;
	int tx_tail;
	int tx_ebd;
	int tx_fbd;
	int rx_head;
	int rx_tail;
	int rx_ebd;
	int rx_fbd;
};

int hns3_cae_qinfo_cfg(const struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size,
		       void *buf_out, u32 out_size);

#endif
