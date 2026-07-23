/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_BC_H
#define DPP_TBL_BC_H

#include "zxic_common.h"
#include "dpp_type_api.h"

#define BC_GROUP_NUM (4)
#define BC_MEMBER_NUM_IN_GROUP (64)

struct dpp_vport_bc_info_t {
	u64 bc_bitmap[BC_GROUP_NUM];
};

struct dpp_vport_bc_table_t {
	struct dpp_vport_bc_info_t bc_info;
};

#endif
