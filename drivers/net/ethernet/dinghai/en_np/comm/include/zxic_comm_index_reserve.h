/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * DEPARTMENT       : ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 *****************************************************************************
 */
#ifndef _ZXIC_COMM_INDEX_RESERVE_H
#define _ZXIC_COMM_INDEX_RESERVE_H

#define CMP_MODE_LOW (0)
#define CMP_MODE_HIGH (1)
typedef u32 (*SWAP_FUNC)(u32 old_index, u32 new_index);
typedef u32 (*LOCAL_SWAP_FUNC)(void *p_cfg, u32 old_index, u32 new_index);

struct INDEX_CURR {
	u32 head_curr;
	u32 tail_curr;
};

struct INR_SWAP_NODE {
	u32 old_handle;
	u32 new_handle;
};

struct _index_res_cfg {
	u32 total_num;
	u32 space_num;
	u32 *index_prop;
	struct _rb_cfg *index_usedrb;
	struct _rb_cfg *index_freerb;
	struct _rb_tn *index_node;
	SWAP_FUNC swap_fun;
	LOCAL_SWAP_FUNC local_fun;
	struct INDEX_CURR *index_curr;
	struct _d_head swap_list;
	u32 total_used;
	u32 is_init;
	u32 indexres_id;
};
void zxic_comm_rb_tn_relation_clear(struct _rb_tn *rb_tn_node);

u32 zxic_comm_indexres_init(struct _index_res_cfg *p_indexres_cfg, u32 arg_total_num,
			    u32 arg_space_num, u32 *arg_index_prop, SWAP_FUNC p_swap_fun,
			    LOCAL_SWAP_FUNC local_fun);

u32 zxic_comm_indexres_alloc(struct _index_res_cfg *p_indexres_cfg, u32 space_val, u32 *out_index);

u32 zxic_comm_indexres_free(struct _index_res_cfg *p_indexres_cfg, u32 space_val, u32 free_index);

u32 zxic_comm_indexres_destory(struct _index_res_cfg *p_indexres_cfg);

u32 zxic_comm_indexres_reset(struct _index_res_cfg *p_indexres_cfg);

u32 zxic_comm_indexres_showinfo(struct _index_res_cfg *p_indexres_cfg);

#endif
