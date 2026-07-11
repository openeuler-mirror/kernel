/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_MC_H
#define DPP_TBL_MC_H

#include "zxic_common.h"
#include "dpp_type_api.h"

#define MC_TABLE_SIZE (1028)
#define MC_GROUP_NUM (4)
#define MC_MEMBER_NUM_IN_GROUP (64)

struct dpp_vport_mc_info_t {
	u32 is_valid;
	u8 mac[6];
	u32 mc_pf_enable;
	u64 mc_bitmap[MC_GROUP_NUM];
};

struct dpp_vport_mc_table_t {
	struct dpp_vport_mc_info_t *mc_info;
};

#endif
