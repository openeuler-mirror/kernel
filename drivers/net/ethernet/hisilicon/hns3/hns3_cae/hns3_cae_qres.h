/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_QRES_H__
#define __HNS3_CAE_QRES_H__

#include "hclge_main.h"
#include "hclge_cmd.h"
#include "hns3_enet.h"

#define HNS3_RING_RX_RING_EBDNUM_REG_ADRR		0x00008
#define HNS3_RING_TX_RING_EBDNUM_REG_ADRR		0x00068

struct qres_param {
	int qid;
	int tx_head;
	int tx_tail;
	int tx_ebd;
	int tx_fbd;
	int tx_software_head;	/* next_to_use */
	int tx_software_tail;	/* next_to_clean */
	int rx_head;
	int rx_tail;
	int rx_ebd;
	int rx_fbd;
	int rx_software_head;
	int rx_software_tail;
	int num_tqps;
	int num_bd;
	struct hns3_desc desc;	/* dma map address space */
};

enum param_type {
	TX_HEAD_TYPE,
	TX_TAIL_TYPE,
	TX_EBD_TYPE,
	TX_FBD_TYPE,
	TX_SOFTWARE_TAIL_TYPE,
	TX_SOFTWARE_HEAD_TYPE,
	RX_HEAD_TYPE,
	RX_TAIL_TYPE,
	RX_EBD_TYPE,
	RX_FBD_TYPE,
	RX_SOFTWARE_TAIL_TYPE,
	RX_SOFTWARE_HEAD_TYPE,
};

struct qres_bufin_param {
	int BD_id;
	int queue_type;
	int mtype;
	int queue_id;
};

enum qres_main_type {
	MTYPE_NULL,
	MTYPE_BD_INFO,
	MTYPE_QUEUE_INFO,
};

enum qres_queue_type {
	TYPE_NULL,
	TYPE_RX,
	TYPE_TX,
};

int hns3_cae_qres_cfg(const struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size,
		      void *buf_out, u32 out_size);

#endif
