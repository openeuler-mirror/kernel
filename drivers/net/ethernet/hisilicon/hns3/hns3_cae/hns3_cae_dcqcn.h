/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_DCQCN_H__
#define __HNS3_CAE_DCQCN_H__

enum {
	DCQCN_MASK_AI = 0x0,
	DCQCN_MASK_F,
	DCQCN_MASK_TKP,
	DCQCN_MASK_TMP,
	DCQCN_MASK_ALP,
	DCQCN_MASK_G,
	DCQCN_MASK_AL,
	DCQCN_MASK_MAX_SPEED,
	DCQCN_MASK_CNP_TIME,
	DCQCN_MASK_ALP_SHIFT,
};

enum DEVMEM_RW_TYPE {
	DEVMEM_CFG_WRITE = 0,
	DEVMEM_CFG_READ,
};

struct cfg_dcqcn_param {
	u16 ai;
	u8 f;
	u8 tkp;
	u16 tmp;
	u16 alp;
	u32 max_speed;
	u8 g;
	u8 al;
	u8 cnp_time;
	u8 alp_shift;
	u16 dcqcn_parm_opcode;
	u16 is_get;
	u32 device_number;
};

struct dcqcn_statistic_param {
	u32 dcqcn_rx_cnt;
	u32 dcqcn_tx_cnt;
	u32 dcqcn_db_cnt;
	u32 dcqcn_statistic_enable;
};

#define SCC_TEMP_LOW_ADDR	0x31000000
#define SCC_TEMP_HIGH_ADDR	0x1

#define HIARM_DCQCN_READ_CFG_MODE	30
#define HIARM_DCQCN_WRITE_CFG_MODE	31

int hns3_nic_dcqcn(struct hns3_nic_priv *net_priv,
		   void *buf_in, u32 in_size, void *buf_out, u32 out_size);
int hns3_dcqcn_get_msg_cnt(struct hns3_nic_priv *net_priv,
			   void *buf_in, u32 in_size,
			   void *buf_out, u32 out_size);
#endif
