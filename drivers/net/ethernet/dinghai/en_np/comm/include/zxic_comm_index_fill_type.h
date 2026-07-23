/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * DEPARTMENT       : ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 *****************************************************************************
 */

#ifndef _ZXIC_COMM_INDEX_FILL_TYPE_H
#define _ZXIC_COMM_INDEX_FILL_TYPE_H

typedef u32 (*INDEXFILL_TYPE_SWAP_FUNC)(u32 old_index, u32 new_index, void *p_cfg);

struct INDEX_FILL_TYPE_INDEX_STATUS {
	u32 is_used;
	u32 prio;
};

struct INDEX_FILL_TYPE_PRIO_NODE {
	struct _rb_tn prio_rb_node;
	struct _rb_cfg idx_rb_cfg;
	u32 prio;
};

struct SSP4_INDEX_FILL_TYPE_PRIO_RB_KEY {
	u32 prio;
};

struct INDEX_FILL_TYPE_MNG_CFG {
	struct _rb_cfg prio_rb;
	struct _d_head mv_list_head;
	void *p_cfg;
};

struct INDEX_FILL_TYPE_INDEX_POOL_CFG {
	u32 index_num;
	u32 total_used;
	u32 prio_max;
	u32 global_max_num;
	struct INDEX_FILL_TYPE_INDEX_STATUS *p_idx_status;
	INDEXFILL_TYPE_SWAP_FUNC swap_fun;
};

u32 zxic_comm_indexfill_type_idx_status_get(struct INDEX_FILL_TYPE_INDEX_STATUS *index_status,
					    u32 index, u32 *used_status_flag,
					    u32 *used_status_prio);

u32 zxic_comm_indexfill_type_idx_status_set(struct INDEX_FILL_TYPE_INDEX_STATUS *index_status,
					    u32 index, u32 prio, u32 used_flag);

u32 zxic_comm_indexfill_type_init(struct INDEX_FILL_TYPE_INDEX_POOL_CFG *p_fill_type_index_pool_cfg,
				  u32 index_num, u32 prio_max, u32 global_max_num,
				  INDEXFILL_TYPE_SWAP_FUNC p_swap_fun);

u32 zxic_comm_indexfill_type_rb_init(struct INDEX_FILL_TYPE_MNG_CFG *p_fill_type_mng_cfg);

u32 zxic_comm_indexfill_type_alloc(
			struct INDEX_FILL_TYPE_INDEX_POOL_CFG *p_fill_type_index_pool_cfg,
			struct INDEX_FILL_TYPE_MNG_CFG *p_fill_type_mng_cfg, u32 prio,
			u32 *out_index);

u32 zxic_comm_indexfill_type_free(struct INDEX_FILL_TYPE_INDEX_POOL_CFG *p_fill_type_index_pool_cfg,
				  struct INDEX_FILL_TYPE_MNG_CFG *p_fill_type_mng_cfg,
				  u32 free_index, u32 *out_index);

u32 zxic_comm_indexfill_type_show_all_position(
	struct INDEX_FILL_TYPE_INDEX_POOL_CFG *p_fill_type_index_pool_cfg,
	struct INDEX_FILL_TYPE_MNG_CFG *p_fill_type_mng_cfg);

#endif
