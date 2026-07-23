/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXIC_COMM_LIST_STACK_H__
#define __ZXIC_COMM_LIST_STACK_H__

#define LISTSTACK_MAX_ELEMENT ((u32)(0x0ffffffe))
#define LISTSTACK_INVALID_INDEX (0)
#define ALLOC_NUMBER (0x3)

struct _s_freelink {
	u32 index;
	u32 next;
};

struct _s_List_Stack_Manager {
	struct _s_freelink *p_array;

	u32 capacity;

	u32 p_head;

	u32 free_num;
	u32 used_num;
};

u32 zxic_comm_liststack_creat(u32 element_num, struct _s_List_Stack_Manager **p_list);

u32 zxic_comm_liststack_alloc(struct _s_List_Stack_Manager *p_list, u32 *index);
u32 zxic_comm_liststack_free(struct _s_List_Stack_Manager *p_list, u32 index);
u32 zxic_comm_liststack_destroy(struct _s_List_Stack_Manager *p_list);
u32 zxic_comm_liststack_alloc_spec_index(struct _s_List_Stack_Manager *p_list, u32 index);

u32 zxic_comm_liststack_show_used(struct _s_List_Stack_Manager *p_list, u32 line_number);
u32 zxic_comm_liststack_show_free(struct _s_List_Stack_Manager *p_list, u32 line_number);

#endif /* end "_FTMCOMM_LIST_STACK_H" */
