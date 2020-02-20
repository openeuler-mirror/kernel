/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#include "hns3_cae_cmd.h"
#include "hns3_enet.h"

enum opc_dup {
	SET_PFC_STORM_PARA = 14,
	GET_PFC_STORM_PARA,
};

struct cmd_pfc_storm_param {
	u32 op_code;
	u32 judge_class;
	union {
		struct hns3_pfc_storm_param_mkii {
			u32 dir;
			u32 enable;
			u32 period_ms;
			u32 times;
			u32 recovery_period_ms;
		} pfc_storm_param_mkii;
		u8 buf[1024];
	};
};

int hns3_cae_pfc_storm_cfg(const struct hns3_nic_priv *net_priv,
			   void *buf_in, u32 in_size, void *buf_out,
			   u32 out_size);
