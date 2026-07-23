/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_PLCR_H
#define DPP_TBL_PLCR_H

#include "dpp_dev.h"
#include "dpp_tbl_comm.h"

u32 dpp_vport_egress_meter_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_ingress_meter_en_set(struct dpp_pf_info_t *pf_info, u8 enable);
u32 dpp_vport_egress_meter_mode_set(struct dpp_pf_info_t *pf_info, u8 mode);
u32 dpp_vport_ingress_meter_mode_set(struct dpp_pf_info_t *pf_info, u8 mode);
u32 dpp_vport_egress_meter_en_get(struct dpp_pf_info_t *pf_info, u32 *enable);
u32 dpp_vport_ingress_meter_en_get(struct dpp_pf_info_t *pf_info, u32 *enable);
u32 dpp_vport_egress_meter_mode_get(struct dpp_pf_info_t *pf_info, u32 *mode);
u32 dpp_vport_ingress_meter_mode_get(struct dpp_pf_info_t *pf_info, u32 *mode);

#endif
