/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXIC_COMM_AVL_TREE_H__
#define __ZXIC_COMM_AVL_TREE_H__

/* Since the trees are balanced, their heignse will never be large. */
#define avl_maxheight 41 /* why this? a small exercise */
#define heightoftree(tree) ((tree) == NULL ? 0 : (tree)->avl_height)

struct _ZXIC_AVL_CFG;
struct _ZXIC_AVL_NODE;

#define ZXIC_LIST_ENTRY(ptr, type, member) \
	((type *)((u8 *)(ptr) - (((unsigned long)(&((type *)64)->member)) - 64)))

#define ZXIC_GET_AVL_KEY_ADDR(p_avl_cfg, key_index) \
	((p_avl_cfg->p_key_base) + (p_avl_cfg->key_len * (key_index)))

typedef s32 (*ZXIC_KEY_CMP_FUNC)(void *p_new_key, void *p_old_key, u32 key_len);

struct _ZXIC_AVL_NODE {
	void *p_key;
	//void *p_owner; /*the owner of this node*/
	u32 result;
	s32 avl_height;
	struct _ZXIC_AVL_NODE *p_avl_left;
	struct _ZXIC_AVL_NODE *p_avl_right;
	struct _d_node avl_node_list; /*the data is owner*/
};

struct _ZXIC_AVL_CFG {
	struct _ZXIC_AVL_NODE *p_root;
	u32 avl_node_num;
	struct _d_head avl_node_list_head;
	u32 key_len;
	u32 item_num;
	ZXIC_KEY_CMP_FUNC avl_cmp_func;
	u8 *p_key_base;
	struct _ZXIC_AVL_NODE *p_avl_node_base;
	struct _s_List_Stack_Manager *p_avl_node_liststack;

	u32 is_dynamic;
	u32 is_init;
};

u32 zxic_comm_avl_init(struct _ZXIC_AVL_CFG *p_avl_cfg, u32 item_num, u32 key_length,
		       ZXIC_KEY_CMP_FUNC avl_cmp_func);

u32 zxic_comm_avl_insert(struct _ZXIC_AVL_CFG *p_avl_cfg, void *p_new_key, u32 *p_index);

u32 zxic_comm_avl_remove(struct _ZXIC_AVL_CFG *p_avl_cfg, void *p_delete_key, void *p_out);

u32 zxic_comm_avl_find(struct _ZXIC_AVL_CFG *p_avl_cfg, void *p_find_key, void *p_out);

u32 zxic_comm_avl_destroy(struct _ZXIC_AVL_CFG *p_avl_cfg);

u32 ic_comm_avl_get_node_num(struct _ZXIC_AVL_CFG *p_avl_cfg);
u32 ic_comm_avl_is_none(struct _ZXIC_AVL_CFG *p_avl_cfg);
u32 ic_comm_avl_get_1st_key(struct _ZXIC_AVL_CFG *p_avl_cfg, void *p_key_out);
u32 ic_comm_avl_get_last_key(struct _ZXIC_AVL_CFG *p_avl_cfg, void *p_key_out);
u32 ic_comm_avl_get_1st_node(struct _ZXIC_AVL_CFG *p_avl_cfg, struct _ZXIC_AVL_NODE **p_node_out);
u32 ic_comm_avl_get_last_node(struct _ZXIC_AVL_CFG *p_avl_cfg, struct _ZXIC_AVL_NODE **p_node_out);

u32 zxic_comm_avl_show_info(struct _ZXIC_AVL_CFG *p_avl_cfg);

#endif /*__ZXIC_AVL_TREE_H__*/
