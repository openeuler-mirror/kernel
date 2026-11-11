/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_FW_CONF_H
#define _NSE_FW_CONF_H

#include <linux/kernel.h>
#include <linux/types.h>

enum nse_fw_fea_flags {
	NSE_FW_FEA_SUPPORT_DDP,

	NSE_FW_FEA_SUPPORT_NSCI,

	NSE_FW_FEA_SUPPORT_LLDP,

	NSE_FW_FEA_FLAGS_NBITS	/* must be last */
};

struct nse_fw_conf {
	DECLARE_BITMAP(fw_fea, NSE_FW_FEA_FLAGS_NBITS);
};

#endif

