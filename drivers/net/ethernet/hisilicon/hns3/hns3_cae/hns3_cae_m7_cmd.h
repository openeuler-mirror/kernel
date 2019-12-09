/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_M7_CMD_H__
#define __HNS3_CAE_M7_CMD_H__

#include "hclge_main.h"
#include "hclge_cmd.h"
#include "hns3_enet.h"

struct m7_cmd_para {
	u32 bd_count;
	u32 bd_type;
	void *bd_data;
};

int hns3_m7_cmd_handle(struct hns3_nic_priv *nic_dev, void *buf_in, u32 in_size,
		       void *buf_out, u32 out_size);
#endif
