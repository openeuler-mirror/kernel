/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_TM_H
#define DPP_TBL_TM_H

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_dev.h"

#define TM_BASE_QUEUE_VALID (0x1000)
#define TRUST_MODE_VALID (0x10)
#define UP_VALID (0x10)
#define TC_VALID (0x10)
#define TM_SWITCH_ON (1)
#define TM_SWITCH_OFF (0)

u32 dpp_tm_flowid_pport_table_set(struct dpp_pf_info_t *pf_info, u8 port, u32 flow_id);
u32 dpp_tm_flowid_pport_table_del(struct dpp_pf_info_t *pf_info, u8 port);
u32 dpp_tm_pport_trust_mode_table_set(struct dpp_pf_info_t *pf_info, u32 port, u32 mode);
u32 dpp_tm_pport_trust_mode_table_del(struct dpp_pf_info_t *pf_info, u32 port);
u32 dpp_tm_pport_dscp_map_table_set(struct dpp_pf_info_t *pf_info, u32 port, u32 dscp_id,
				    u32 up_id);
u32 dpp_tm_pport_dscp_map_table_del(struct dpp_pf_info_t *pf_info, u32 port, u32 dscp_id);
u32 dpp_tm_pport_up_map_table_set(struct dpp_pf_info_t *pf_info, u32 port, u32 up_id, u32 tc_id);
u32 dpp_tm_pport_up_map_table_del(struct dpp_pf_info_t *pf_info, u32 port, u32 up_id);
u32 dpp_tm_pport_mcode_switch_set(struct dpp_pf_info_t *pf_info, u32 port, u32 mode);
u32 dpp_tm_pport_mcode_switch_del(struct dpp_pf_info_t *pf_info, u32 port);

#endif
