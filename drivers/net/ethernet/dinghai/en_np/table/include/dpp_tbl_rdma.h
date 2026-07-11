/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_MAC_H
#define DPP_TBL_MAC_H

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_dev.h"

u32 dpp_add_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac, const u16 vhcaId);
u32 dpp_del_rdma_trans_item(struct dpp_pf_info_t *pf_info, const void *mac);

#endif
