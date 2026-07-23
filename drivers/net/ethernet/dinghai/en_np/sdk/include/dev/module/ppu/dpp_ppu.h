/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PPU_H_
#define _DPP_PPU_H_
#include "dpp_module.h"
#include "dpp_ppu_api.h"
#include "dpp_ppu_reg.h"
#include "zxic_comm_thread.h"

#define PPU_CLS_ME_NUM (8)
#define PPU_INSTR_MEM_NUM (3)
#define PPU_INSTR_REG_NUM (4)
#define PPU_INSTR_NUM_MAX (32 * 1024) /* xjw mod at 18.6.2 from 16k to 32k */
#define PPU_SDT_IDX_MIN (0)
#define PPU_SDT_IDX_MAX (255)
#define PPU_DUP_IDX_MIN (0)
#define PPU_DUP_IDX_MAX (63)
#define PPU_INSTR_COL_MAX (4)

#define PPU_ME0_INT_BT_START (0)
#define PPU_ME0_INT_BT_LEN (1)
#define PPU_ME1_INT_BT_START (1)
#define PPU_ME1_INT_BT_LEN (1)
#define PPU_ME2_INT_BT_START (2)
#define PPU_ME2_INT_BT_LEN (1)
#define PPU_ME3_INT_BT_START (3)
#define PPU_ME3_INT_BT_LEN (1)
#define PPU_ME4_INT_BT_START (4)
#define PPU_ME4_INT_BT_LEN (1)
#define PPU_ME5_INT_BT_START (5)
#define PPU_ME5_INT_BT_LEN (1)
#define PPU_ME6_INT_BT_START (6)
#define PPU_ME6_INT_BT_LEN (1)
#define PPU_ME7_INT_BT_START (7)
#define PPU_ME7_INT_BT_LEN (1)

#define DPP_FPGA_MAX_FLOWTCAM_NUM (32)
#define DPP_PPU_CLS_0_BIT_MAP (1 << 0)
#define DPP_PPU_CLS_1_BIT_MAP (1 << 1)
#define DPP_PPU_CLS_2_BIT_MAP (1 << 2)
#define DPP_PPU_CLS_3_BIT_MAP (1 << 3)
#define DPP_PPU_CLS_4_BIT_MAP (1 << 4)
#define DPP_PPU_CLS_5_BIT_MAP (1 << 5)

#define DPP_PPU_CLS_ALL_START (0x3F)

struct dpp_ppu_cls_bitmap_t {
	u32 cls_use[DPP_PPU_CLUSTER_NUM];
	u32 instr_mem[PPU_INSTR_MEM_NUM];
};

struct dpp_ppu_ppu_cop_thash_rsk_t {
	u32 rsk_319_288;
	u32 rsk_287_256;
	u32 rsk_255_224;
	u32 rsk_223_192;
	u32 rsk_191_160;
	u32 rsk_159_128;
	u32 rsk_127_096;
	u32 rsk_095_064;
	u32 rsk_063_032;
	u32 rsk_031_000;
};

u32 dpp_ppu_cls_use_set(u32 dev_id, u32 cluster_id, u32 flag);
u32 dpp_ppu_cls_use_get(u32 dev_id, u32 cluster_id);
u32 dpp_ppu_instr_mem_set(u32 dev_id, u32 mem_id, u32 flag);
u32 dpp_ppu_parse_cls_bitmap(u32 dev_id, u32 bitmap);

DPP_STATUS dpp_ppu_ppu_cop_thash_rsk_set(struct dpp_dev_t *dev,
					 struct dpp_ppu_ppu_cop_thash_rsk_t *p_para);
DPP_STATUS
dpp_ppu_ppu_cop_thash_rsk_get(struct dpp_dev_t *dev,
			      struct dpp_ppu_ppu_cop_thash_rsk_t *p_ppu_cop_thash_rsk);
#endif
