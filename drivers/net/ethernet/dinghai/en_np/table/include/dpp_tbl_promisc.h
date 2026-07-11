/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_PROMISC_H
#define DPP_TBL_PROMISC_H

#include "zxic_common.h"
#include "dpp_type_api.h"

#define PROMISC_GROUP_NUM (4)
#define PROMISC_MEMBER_NUM_IN_GROUP (64)

struct dpp_vport_promisc_info_t {
	u32 pf_enable;
	u64 bitmap[PROMISC_GROUP_NUM];
};

struct dpp_vport_uc_promisc_table_t {
	struct dpp_vport_promisc_info_t promisc_info;
};

#endif
