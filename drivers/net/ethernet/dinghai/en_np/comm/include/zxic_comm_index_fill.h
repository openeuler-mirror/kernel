/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * DEPARTMENT       : ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 *****************************************************************************
 */

#ifndef _ZXIC_COMM_INDEX_FILL_H
#define _ZXIC_COMM_INDEX_FILL_H

typedef u32 (*INDEXFILL_SWAP_FUNC)(u32 old_index, u32 new_index, void *p_cfg);

struct INDEX_FILL_NODE {
	struct _rb_tn rb_node;
	u32 position;
	u32 usednum;
};

struct INDEX_FILL_CFG {
	struct _rb_cfg fill_rb;
	u32 index_num;
	struct INDEX_FILL_NODE *fill_node;
	INDEXFILL_SWAP_FUNC swap_fun;
	u32 total_used;
};

u32 ic_comm_node_data_free(void *p_data);

u32 zxic_comm_indexfill_init(struct INDEX_FILL_CFG *p_fill_cfg, u32 index_num,
			     ZXIC_KEY_CMP_FUNC p_cmp_fun, INDEXFILL_SWAP_FUNC p_swap_fun,
			     u32 key_len);

u32 zxic_comm_indexfill_free(struct INDEX_FILL_CFG *p_fill_cfg, u32 free_index, void *p_rb_key,
			     u32 *out_index);

u32 zxic_comm_indexfill_destroy(struct INDEX_FILL_CFG *p_fill_cfg);

u32 zxic_comm_indexfill_store(struct INDEX_FILL_CFG *p_fill_cfg, u32 *p_size, u8 **p_data_buff);

u32 zxic_comm_indexfill_show_all_position(struct INDEX_FILL_CFG *p_fill_cfg);
u32 zxic_comm_indexfill_clear(struct INDEX_FILL_CFG *p_fill_cfg);

#define ICMINF_GET_NODE_LASTPOS(p_inf_node) ((p_inf_node)->position + (p_inf_node)->usednum - 1)

#define ICMINF_GET_NODE_FSTPOS(p_inf_node) ((p_inf_node)->position)

#endif
