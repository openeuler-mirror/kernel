/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DTB4K_REG_H_
#define _DPP_DTB4K_REG_H_
struct dpp_dtb4k_dtb_enq_cfg_queue_dtb_addr_h_0_127_t {
	u32 cfg_queue_dtb_addr_h;
};

struct dpp_dtb4k_dtb_enq_cfg_queue_dtb_addr_l_0_127_t {
	u32 cfg_queue_dtb_addr_l;
};

struct dpp_dtb4k_dtb_enq_cfg_queue_dtb_len_0_127_t {
	u32 cfg_dtb_cmd_type;
	u32 cfg_dtb_cmd_int_en;
	u32 cfg_queue_dtb_len;
};

struct dpp_dtb4k_dtb_enq_info_queue_buf_space_left_0_127_t {
	u32 info_queue_buf_space_left;
};

struct dpp_dtb4k_dtb_enq_cfg_epid_v_func_num_0_127_t {
	u32 dbi_en;
	u32 queue_en;
	u32 cfg_epid;
	u32 cfg_vfunc_num;
	u32 cfg_vector;
	u32 cfg_func_num;
	u32 cfg_vfunc_active;
};

#endif
