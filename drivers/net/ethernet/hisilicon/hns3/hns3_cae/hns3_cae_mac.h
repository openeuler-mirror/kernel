/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_MAC_H__
#define __HNS3_CAE_MAC_H__

#define SERDES_SERIAL_INNER_LOOP_B		0x0
#define SERDES_PARALLEL_OUTER_LOOP_B		0x1
#define SERDES_PARALLEL_INNER_LOOP_B		0x2

#define MAINTAIN_LOOP_MODE	0x2

struct hns3_cae_loop_param {
	u8 tx2rx_loop_en;	/* 0: off, 1:on, >=2: not set. */
	u8 rx2tx_loop_en;	/* 0: off, 1:on, >=2: not set. */
	u8 serial_tx2rx_loop_en;	/* 0: off, 1:on, >=2: not set. */
	u8 parallel_rx2tx_loop_en;	/* 0: off, 1:on, >=2: not set. */
	u8 parallel_tx2rx_loop_en;	/* 0: off, 1:on, >=2: not set. */
	u8 is_read;
};

struct hns3_cae_cfg_mac_mode_cmd {
	u32 txrx_pad_fcs_loop_en;
	u8 rsv[20];
};

struct hns3_cae_cfg_serdes_mode_cmd {
	u8 loop_valid;
	u8 loop_en;
	u8 loop_status;
	u8 rsv[21];
};

int hns3_cae_mac_loop_cfg(const struct hns3_nic_priv *net_priv,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size);

#endif
