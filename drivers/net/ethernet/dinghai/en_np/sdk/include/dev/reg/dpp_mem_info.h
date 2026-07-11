/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_MEM_H_
#define _DPP_MEM_H_
enum dpp_mem_no_e {
	PKTRX_PHYPORT_UDF_ATTRIm = 0,
	PKTRX_PHYPORT_HDW_ATTRIm = 1,
	PKTRX_PHYPORT_FLOW_PCm = 2,
	PKTRX_ICU_TCAMm = 3,
	PKTRX_FLOWNUM_TCAMm = 4,
};

struct dpp_mem_field_t {
	s8 *p_name;
	u32 flags;
	u16 msb_pos;
	u16 len;
};

#define DPP_MEM_FLAG_TCAM (1 << 0)
struct dpp_mem_info_t {
	u32 mem_no;
	u32 module_no;
	u32 flags;
	u32 mem_id;
	u32 index_min;
	u32 index_max;
	u32 width;

	struct dpp_mem_field_t *p_fileds;
};

#endif
