/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DRV_FC_H_
#define _DPP_DRV_FC_H_

#include "zxic_common.h"
#include "dpp_pbu.h"
#include "dpp_pbu_api.h"
#include "dpp_drv_qos.h"
DPP_STATUS dpp_port_th_set(struct dpp_pf_info_t *pf_info, u32 port_id,
			   struct dpp_pbu_port_th_para_t *p_para);
DPP_STATUS dpp_port_th_get(struct dpp_pf_info_t *pf_info, u32 port_id,
			   struct dpp_pbu_port_th_para_t *p_para);
DPP_STATUS dpp_port_cos_th_set(struct dpp_pf_info_t *pf_info, u32 port_id,
			       struct dpp_pbu_port_cos_th_para_t *p_para);
DPP_STATUS dpp_port_cos_th_get(struct dpp_pf_info_t *pf_info, u32 port_id,
			       struct dpp_pbu_port_cos_th_para_t *p_para);
DPP_STATUS dpp_pfc_delay_time_set(struct dpp_pf_info_t *pf_info, u64 delayTime);
DPP_STATUS dpp_pfc_delay_time_get(struct dpp_pf_info_t *pf_info, u64 *delayTime);

#endif
