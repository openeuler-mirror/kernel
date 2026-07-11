/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_STAT4K_REG_H_
#define _DPP_STAT4K_REG_H_
struct dpp_stat4k_etcam_block0_7_port_id_cfg_t {
	u32 block7_port_id;
	u32 block6_port_id;
	u32 block5_port_id;
	u32 block4_port_id;
	u32 block3_port_id;
	u32 block2_port_id;
	u32 block1_port_id;
	u32 block0_port_id;
};

struct dpp_stat4k_etcam_block0_3_base_addr_cfg_t {
	u32 block3_base_addr_cfg;
	u32 block2_base_addr_cfg;
	u32 block1_base_addr_cfg;
	u32 block0_base_addr_cfg;
};

struct dpp_stat4k_etcam_block4_7_base_addr_cfg_t {
	u32 block7_base_addr_cfg;
	u32 block6_base_addr_cfg;
	u32 block5_base_addr_cfg;
	u32 block4_base_addr_cfg;
};

#endif
