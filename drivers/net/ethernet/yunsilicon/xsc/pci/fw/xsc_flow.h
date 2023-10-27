/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FLOW_H
#define XSC_FLOW_H

#include "osdep.h"

#define XSC_DMA_LEN     64
#define XSC_DMA_WR_MAX  128
#define XSC_DMA_WR_SUCCESS  0x3

/* key */
struct tdi_dma_write_key_bits {
	u8 host_id:1;
	u16 func_id:11;
} __packed;

struct tdi_dma_read_key_bits {
	u16 tbl_start_addr:16;
	u8 tbl_id:7;
	u8 host_id:1;
	u16 func_id:11;
} __packed;

/* action */
struct tdi_dma_write_action_bits {
	u32 entry_num:32;
	u64 data_addr:64;
} __packed;

struct tdi_dma_read_action_bits {
	u16 burst_num:16;
	u64 data_addr:64;
} __packed;

/* ioctl data - add */
struct xsc_flow_dma_write_add {
	struct tdi_dma_write_key_bits key;
	struct tdi_dma_write_action_bits action;
};

struct xsc_flow_dma_read_add {
	struct tdi_dma_read_key_bits key;
	struct tdi_dma_read_action_bits action;
};

struct xsc_logic_in_port_cfg_reg {
	u32 phy_port_offset:11;
	u32 resv0:5;
	u32 func_id_offset:11;
	u32 resv1:5;
	u32 aps_port_offset:11;
	u32 resv2:1;
	u32 aps_port_rec_flg:1;
	u32 resv3:19;
};

int xsc_flow_add(struct xsc_core_device *xdev,
	int table, int length, void *data);

void xsc_dma_read_done_complete(void);

#endif
