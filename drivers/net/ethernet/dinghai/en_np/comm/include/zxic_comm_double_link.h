/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXIC_COMM_DOUBLE_LINK_H
#define _ZXIC_COMM_DOUBLE_LINK_H
#define TEST_NUMBER (255)

struct _d_node {
	void *data;
	struct _d_node *prev;
	struct _d_node *next;
};

struct _d_head {
	u32 used;
	u32 maxnum;
	struct _d_node *p_next;
	struct _d_node *p_prev;
};

typedef s32 (*CMP_FUNC)(struct _d_node *data1, struct _d_node *data2, void *);

typedef u32 (*fun_free)(void *);

u32 zxic_comm_double_link_insert_1st(struct _d_node *newnode, struct _d_head *head);
u32 zxic_comm_double_link_insert_aft(struct _d_node *newnode, struct _d_node *oldnode,
				     struct _d_head *head);
u32 zxic_comm_double_link_insert_pre(struct _d_node *newnode, struct _d_node *oldnode,
				     struct _d_head *head);
u32 zxic_comm_double_link_insert_last(struct _d_node *newnode, struct _d_head *head);
u32 zxic_comm_double_link_merge_list(struct _d_head *d_list, struct _d_head *s_list);

u32 zxic_comm_double_link_insert_sort(struct _d_node *newnode, struct _d_head *head, CMP_FUNC fuc,
				      void *cmp_data);

u32 zxic_comm_double_link_search(struct _d_node *data, struct _d_head *head);
u32 zxic_comm_double_link_del(struct _d_node *data, struct _d_head *head);
u32 zxic_comm_double_link_init(u32 elmemtnum, struct _d_head *head);
u32 zxic_comm_double_link_insert_merge(struct _d_node *p_newnode, struct _d_head *p_head,
				       u32 is_head);

u32 zxic_comm_dlink_release(struct _d_head *p_head, fun_free fun);
s32 zxic_comm_double_link_default_cmp_fuc(struct _d_node *p_data1, struct _d_node *p_data2,
					  void *p_data);

u32 zxic_comm_double_link_del_pos(struct _d_head *p_head, void *cmp_data, fun_free fun);
u32 zxic_comm_double_link_insert_cmp(struct _d_head *p_head, void *cmp_data, u32 *is_same);

#define INIT_D_NODE(ptr, pdata)      \
	do {                         \
		(ptr)->data = pdata; \
		(ptr)->prev = NULL;  \
		(ptr)->next = NULL;  \
	} while (0)

#define MEM_OFF(type, member) (ZXIC_COMM_PTR_TO_VAL(&(((type *)0)->member)))

#define STRUCT_ENTRY_POINT(ptr, type, member) \
	((type *)(ZXIC_COMM_PTR_TO_VAL(ptr) - MEM_OFF(type, member)))

#define MEM_OFF_NOT_NULL(type, member) \
	(ZXIC_COMM_PTR_TO_VAL(&(((type *)4)->member)) - ZXIC_COMM_PTR_TO_VAL(((type *)4)))

#define GET_STRUCT_ENTRY_POINT(ptr, type, member) \
	((type *)(ZXIC_COMM_PTR_TO_VAL(ptr) - MEM_OFF_NOT_NULL(type, member)))

#define DLINK_IS_FULL(p_dlink) ((p_dlink)->used == (p_dlink)->maxnum)

u32 zxic_comm_double_link_sort(struct _d_head *p_head, CMP_FUNC cmp_fuc);
u32 zxic_comm_double_link_swap(struct _d_node *p_pre, struct _d_node *p_next);
u32 zxic_comm_double_link_test(void);
u32 zxic_comm_double_link_print(struct _d_head *p_head);
u32 zxic_comm_double_link_del_by_data(struct _d_head *p_head, void *cmp_data, fun_free fun);
u32 zxic_comm_double_link_del_by_info(struct _d_head *p_head, void *cmp_data, CMP_FUNC cmp_fuc,
				      u32 *p_deled_num);

#endif
