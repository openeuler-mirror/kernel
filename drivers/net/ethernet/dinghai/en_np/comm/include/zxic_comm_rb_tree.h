/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*****************************************************************************
 * DEPARTMENT       : ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 *****************************************************************************
 */

#ifndef _ZXIC_COMM_RB_TREE_H
#define _ZXIC_COMM_RB_TREE_H

#include "zxic_comm_double_link.h"
#include "zxic_comm_liststack.h"

#define ZXIC_RBT_RED (0x1)
#define ZXIC_RBT_BLACK (0x2)
#define ZXIC_RBT_MAX_DEPTH (96)

typedef s32 (*ZXIC_RB_CMPFUN)(void *p_new, void *p_old, u32 keysize);

struct _rb_tn {
	void *p_key;
	u32 color_lsv; /*last 2 bits indicate color, bit2-31 if dynamic=0 indicate list val*/
	struct _rb_tn *p_left;
	struct _rb_tn *p_right;
	struct _rb_tn *p_parent;
	struct _d_node tn_ln;
};

struct _rb_cfg {
	u32 key_size;
	u32 is_dynamic; /* 1 - customer manage memory;0 - alloc all memory*/
	struct _rb_tn *p_root; /* rb tree root node */
	struct _d_head tn_list;
	ZXIC_RB_CMPFUN p_cmpfun;
	struct _s_List_Stack_Manager *p_lsm; /* list stack manage*/
	u8 *p_keybase;
	struct _rb_tn *p_tnbase;
	u32 is_init;
};

#define GET_TN_COLOR(p_tn) ((!p_tn) ? ZXIC_RBT_BLACK : (p_tn)->color_lsv & 0x3)

#define SET_TN_COLOR(p_tn, color)                   \
	do {                                        \
		(p_tn)->color_lsv &= 0xfffffffc;    \
		(p_tn)->color_lsv |= (color & 0x3); \
	} while (0)

#define GET_TN_LSV(p_tn) ((p_tn)->color_lsv >> 2)

#define SET_TN_LSV(p_tn, list_val)                      \
	do {                                            \
		(p_tn)->color_lsv &= 0x3;               \
		(p_tn)->color_lsv |= ((list_val) << 2); \
	} while (0)

/*init the rb node ,be careful init_color is red*/
#define INIT_RBT_TN(p_tn, p_newkey)                    \
	do {                                           \
		(p_tn)->p_key = p_newkey;              \
		(p_tn)->color_lsv = 0;                 \
		(p_tn)->p_left = NULL;                 \
		(p_tn)->p_right = NULL;                \
		(p_tn)->p_parent = NULL;               \
		INIT_D_NODE(&((p_tn)->tn_ln), (p_tn)); \
	} while (0)

u32 zxic_comm_rb_init(struct _rb_cfg *p_rb_cfg, u32 total_num, u32 key_size, ZXIC_RB_CMPFUN cmpfun);

u32 zxic_comm_rb_insert(struct _rb_cfg *p_rb_cfg, void *p_key, void *out_val);

u32 zxic_comm_rb_delete(struct _rb_cfg *p_rb_cfg, void *p_key, void *out_val);

u32 zxic_comm_rb_search(struct _rb_cfg *p_rb_cfg, void *p_key, void *out_val);

u32 zxic_comm_rb_destroy(struct _rb_cfg *p_rb_cfg);

struct _rb_tn *zxic_comm_rb_get_1st_tn(struct _rb_cfg *p_rb_cfg);

struct _rb_tn *zxic_comm_rb_get_last_tn(struct _rb_cfg *p_rb_cfg);

u32 zxic_comm_rb_get_1st_key(struct _rb_cfg *p_rb_cfg, void *p_key_out);

u32 zxic_comm_rb_get_last_key(struct _rb_cfg *p_rb_cfg, void *p_key_out);

u32 zxic_comm_rb_insert_spec_index(struct _rb_cfg *p_rb_cfg, void *p_key, u32 in_idx);

#define ZXIC_RBT_RC_BASE (0x1000)

#define ZXIC_RBT_RC_UPDATE (ZXIC_RBT_RC_BASE | 0x1)
#define ZXIC_RBT_RC_SRHFAIL (ZXIC_RBT_RC_BASE | 0x2)
#define ZXIC_RBT_RC_FULL (ZXIC_RBT_RC_BASE | 0x3)
#define ZXIC_RBT_ISEMPTY_ERR (ZXIC_RBT_RC_BASE | 0x4)
#define ZXIC_RBT_PARA_INVALID (ZXIC_RBT_RC_BASE | 0x5)

#endif
