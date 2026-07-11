/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PBU_API_H_
#define _DPP_PBU_API_H_

#include "dpp_module.h"

#if ZXIC_REAL("data struct define")
struct dpp_pbu_mc_cos_para_t {
	u32 mc_cos_th[8];
	u32 mc_cos_mode[8];
};

struct dpp_pbu_port_th_para_t {
	u32 lif_th;
	u32 lif_prv;
	u32 idma_prv;
	u32 idma_th_cos0;
	u32 idma_th_cos1;
	u32 idma_th_cos2;
	u32 idma_th_cos3;
	u32 idma_th_cos4;
	u32 idma_th_cos5;
	u32 idma_th_cos6;
	u32 idma_th_cos7;
};

struct dpp_pbu_port_cos_th_para_t {
	u32 cos_th[8];
};

struct dpp_pbu_global_th_t {
	u32 idma_public_th;
	u32 lif_public_th;
	u32 idma_total_th;
	u32 lif_total_th;
	u32 mc_total_th;
};

#endif //struct

#if ZXIC_REAL("function declaration")

DPP_STATUS dpp_pbu_port_th_set(struct dpp_dev_t *dev, u32 port_id,
			       struct dpp_pbu_port_th_para_t *p_para);

DPP_STATUS dpp_pbu_port_cos_th_set(struct dpp_dev_t *dev, u32 port_id,
				   struct dpp_pbu_port_cos_th_para_t *p_para);

#endif //function
#endif
