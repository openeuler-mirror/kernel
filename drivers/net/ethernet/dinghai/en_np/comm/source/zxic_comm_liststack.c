// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"

u32 zxic_comm_liststack_creat(u32 element_num, struct _s_List_Stack_Manager **p_list)
{
	struct _s_List_Stack_Manager *p_local_list = NULL;
	u32 dw_list_size = 0;
	u32 dw_manage_size = 0;
	u32 dw_actual_element_num = 0;
	u32 i = 0;

	if (!p_list) {
		ZXIC_COMM_PRINT("\n p_list is NULL!\n");
		return ZXIC_LIST_STACK_POINT_NULL;
	}
	if (element_num <= 0) {
		*p_list = NULL;
		ZXIC_COMM_PRINT("\n FtmComm_ListStackCreat_dwElementNum <=0");
		return ZXIC_LIST_STACK_ELEMENT_NUM_ERR;
	}

	if (element_num > LISTSTACK_MAX_ELEMENT - 1)
		dw_actual_element_num = LISTSTACK_MAX_ELEMENT;
	else
		dw_actual_element_num = element_num + 1; /*10124041 index from 0*/

	dw_list_size = (dw_actual_element_num * ZXIC_SIZEOF(struct _s_freelink)) & 0xffffffff;
	dw_manage_size = (ZXIC_SIZEOF(struct _s_List_Stack_Manager) + dw_list_size) & 0xffffffff;

	p_local_list = (struct _s_List_Stack_Manager *)ZXIC_COMM_MALLOC(dw_manage_size);

	if (!p_local_list) {
		*p_list = NULL;
		ZXIC_COMM_PRINT("\n zxic comm_liststack_creat Fail\n");
		return ZXIC_LIST_STACK_ALLOC_MEMORY_FAIL;
	}

	ZXIC_COMM_MEMSET(p_local_list, 0, dw_manage_size);

	p_local_list->p_array = (struct _s_freelink *)((u8 *)p_local_list +
						       ZXIC_SIZEOF(struct _s_List_Stack_Manager));

	p_local_list->capacity = dw_actual_element_num;
	p_local_list->free_num = dw_actual_element_num - 1; /* for index = 0 is reserved */
	p_local_list->used_num = 0;

	for (i = 1; i < (dw_actual_element_num - 1); i++) {
		p_local_list->p_array[i].index = i;
		p_local_list->p_array[i].next = i + 1;
	}

	p_local_list->p_array[0].index = 0;
	p_local_list->p_array[0].next = 0;

	p_local_list->p_array[dw_actual_element_num - 1].index = dw_actual_element_num - 1;
	p_local_list->p_array[dw_actual_element_num - 1].next = 0xffffffff;

	p_local_list->p_head = p_local_list->p_array[1].index;

	*p_list = p_local_list;

	return ZXIC_OK;
}

u32 zxic_comm_liststack_alloc(struct _s_List_Stack_Manager *p_list, u32 *p_index)
{
	u32 dw_alloc_index = 0;
	u32 dw_next_free = 0;

	if (!p_list) {
		*p_index = LISTSTACK_INVALID_INDEX;
		ZXIC_COMM_PRINT("\n zxic comm_liststack_alloc! ERROR LINE:%d\n ", __LINE__);
		return ZXIC_LIST_STACK_POINT_NULL;
	}

	if ((p_list->p_head) == LISTSTACK_INVALID_INDEX) {
		*p_index = LISTSTACK_INVALID_INDEX;

		/*ZXIC_COMM_PRINT("\n zxic_comm_liststack_alloc is full!  LINE:%d\n ",__LINE__);*/
		return ZXIC_LIST_STACK_ISEMPTY_ERR;
	}

	dw_alloc_index = p_list->p_head;

	dw_next_free = p_list->p_array[dw_alloc_index].next;
	p_list->p_array[dw_alloc_index].next = LISTSTACK_INVALID_INDEX;

	if (dw_next_free != 0xffffffff)
		p_list->p_head = p_list->p_array[dw_next_free].index;
	else
		p_list->p_head = LISTSTACK_INVALID_INDEX;

	*p_index = dw_alloc_index - 1;

	p_list->free_num--;
	p_list->used_num++;

	if ((p_list->free_num == 0) || (p_list->used_num == (p_list->capacity - 1))) {
		/*ZXIC_COMM_PRINT("\n zxic_comm_liststack_alloc! ERROR LINE:%d\n ",__LINE__);*/
		p_list->p_head = LISTSTACK_INVALID_INDEX;
	}

	return ZXIC_OK;
}

u32 zxic_comm_liststack_free(struct _s_List_Stack_Manager *p_list, u32 index)
{
	u32 dw_free_index = 0;
	u32 dw_prev_free = 0;
	u32 dw_index = 0;

	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(index, 1);
	dw_index = index + 1;

	if (!p_list) {
		ZXIC_COMM_PRINT("\n zxic comm_liststack_free is null! LINE:%d\n ", __LINE__);
		return ZXIC_LIST_STACK_POINT_NULL;
	}

	if (dw_index >= p_list->capacity) {
		ZXIC_COMM_PRINT("\n zxic comm_liststack_free is null! LINE:%d\n ", __LINE__);
		return ZXIC_LIST_STACK_FREE_INDEX_INVALID;
	}

	if (p_list->p_array[dw_index].next != LISTSTACK_INVALID_INDEX)
		return ZXIC_OK;

	dw_free_index = dw_index;
	dw_prev_free = p_list->p_head;

	if (dw_prev_free != 0)
		p_list->p_array[dw_free_index].next = p_list->p_array[dw_prev_free].index;
	else
		p_list->p_array[dw_free_index].next = 0xffffffff;

	p_list->p_head = p_list->p_array[dw_free_index].index;

	p_list->free_num++;
	p_list->used_num--;

	return ZXIC_OK;
}

u32 zxic_comm_liststack_alloc_spec_index(struct _s_List_Stack_Manager *p_list, u32 index)
{
	u32 dw_free_index = 0;
	u32 dw_index = 0;

	ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(index, 1);
	dw_index = index + 1;
	if (!p_list) {
		ZXIC_COMM_PRINT(
			"\n zxic comm_liststack_alloc_spec_index: address is full! ERROR LINE:%d\n ",
			__LINE__);
		return ZXIC_LIST_STACK_POINT_NULL;
	}

	if ((p_list->p_head) == LISTSTACK_INVALID_INDEX) {
		//ZXIC_COMM_PRINT("\n zxic_comm_liststack_alloc is full!  LINE:%d\n ",__LINE__);
		return ZXIC_LIST_STACK_ISEMPTY_ERR;
	}

	if (dw_index >= p_list->capacity) {
		ZXIC_COMM_PRINT(
			"\n zxic comm_liststack_alloc_spec_index: input invalid index! LINE:%d\n ",
			__LINE__);
		return ZXIC_LIST_STACK_ALLOC_INDEX_INVALID;
	}

	if (p_list->p_array[dw_index].next == LISTSTACK_INVALID_INDEX) {
		ZXIC_COMM_PRINT(
			"\n zxic comm_liststack_alloc_spec_index: index is used, not alloc again! LINE:%d\n ",
			__LINE__);
		return ZXIC_LIST_STACK_ALLOC_INDEX_USED;
	}
	if (p_list->p_head == dw_index) {
		if (p_list->p_array[dw_index].next != 0xffffffff)
			p_list->p_head = p_list->p_array[dw_index].next;
		else
			p_list->p_head = LISTSTACK_INVALID_INDEX;
	} else {
		dw_free_index = p_list->p_head;
		while (p_list->p_array[dw_free_index].next != 0xffffffff) {
			if (p_list->p_array[dw_free_index].next == dw_index) {
				p_list->p_array[dw_free_index].next =
					p_list->p_array[dw_index].next;
				break;
			}
			dw_free_index = p_list->p_array[dw_free_index].next;
		}
	}

	p_list->p_array[dw_index].next = LISTSTACK_INVALID_INDEX;
	p_list->free_num--;
	p_list->used_num++;

	if ((p_list->free_num == 0) || (p_list->used_num == (p_list->capacity - 1))) {
		//ZXIC_COMM_PRINT("\n zxic_comm_liststack_alloc! ERROR LINE:%d\n ",__LINE__);
		p_list->p_head = LISTSTACK_INVALID_INDEX;
	}

	return ZXIC_OK;
}

u32 zxic_comm_liststack_destroy(struct _s_List_Stack_Manager *p_list)
{
	if (!p_list) {
		ZXIC_COMM_PRINT("\n zxic comm_liststack_destroy! LINE:%d\n ", __LINE__);
		return ZXIC_LIST_STACK_POINT_NULL;
	}
	ZXIC_COMM_FREE(p_list);

	return ZXIC_OK;
}

u32 zxic_comm_liststack_showlist_info(struct _s_List_Stack_Manager *p_list)
{
	ZXIC_COMM_PRINT("\n\t List:     0x%p", (void *)p_list);
	ZXIC_COMM_PRINT("\n\t Array:    0x%p", (void *)p_list->p_array);
	ZXIC_COMM_PRINT("\n\t capacity: 0x%x", p_list->capacity);
	ZXIC_COMM_PRINT("\n\t p_head:   0x%x", p_list->p_head);
	ZXIC_COMM_PRINT("\n\t free_num: 0x%x", p_list->free_num);
	ZXIC_COMM_PRINT("\n\t used_num: 0x%x\n", p_list->used_num);

	return 0;
}

u32 zxic_comm_liststack_show_used(struct _s_List_Stack_Manager *p_list, u32 line_number)
{
	u32 rc = 0;
	u32 i = 0;
	u32 used_number = 0;
	u32 dw_index = 0;
	u32 dw_last_free_idx = 0;

	if (!p_list) {
		ZXIC_COMM_PRINT("\n Please Input Param!");
		return 0;
	}

	if (line_number == 0)
		line_number = 32;

	rc = zxic_comm_liststack_showlist_info(p_list);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_liststack_showlist_info");
	ZXIC_COMM_PRINT("\n");

	/*611002175032 zj068187 begin*/
	if (p_list->p_head == LISTSTACK_INVALID_INDEX)
		ZXIC_COMM_PRINT("\n The index are all used!\n");

	dw_index = p_list->p_head;
	ZXIC_COMM_CHECK_INDEX_UPPER(dw_index, (p_list->capacity - 1));
	while (p_list->p_array[dw_index].next != LISTSTACK_INVALID_INDEX) {
		dw_index = p_list->p_array[dw_index].next;
		ZXIC_COMM_CHECK_INDEX_UPPER(dw_index, (p_list->capacity - 1));
	}

	dw_last_free_idx = p_list->p_array[dw_index].index;
	/*611002175032 zj068187 end*/

	for (i = 1; i < p_list->capacity; i++) {
		/*611002175032 zj068187 modify*/
		if ((p_list->p_array[i].next == LISTSTACK_INVALID_INDEX) &&
		    (dw_last_free_idx != p_list->p_array[i].index)) {
			ZXIC_COMM_PRINT(" 0x%x", i);
			used_number++;

			if ((used_number % line_number) == 0)
				ZXIC_COMM_PRINT("\n");
		}
	}

	ZXIC_COMM_PRINT("\n used_number: 0x%x", used_number);

	return ZXIC_OK;
}

u32 zxic_comm_liststack_show_free(struct _s_List_Stack_Manager *p_list, u32 line_number)
{
	u32 rc = 0;
	u32 i = 0;
	u32 index = 0;
	u32 free_number = 0;

	if (!p_list) {
		ZXIC_COMM_PRINT("\n Please Input Param!");
		return 0;
	}

	if (line_number == 0)
		line_number = 32;

	rc = zxic_comm_liststack_showlist_info(p_list);
	ZXIC_COMM_CHECK_RC(rc, "zxic_comm_liststack_showlist_info");
	ZXIC_COMM_PRINT("\n");

	index = p_list->p_head;

	for (i = p_list->capacity - 1; i != 0; i--) {
		if (index != LISTSTACK_INVALID_INDEX) {
			ZXIC_COMM_PRINT(" 0x%x", index);
			free_number++;

			index = p_list->p_array[index].next;

			if ((free_number % line_number) == 0)
				ZXIC_COMM_PRINT("\n");
		} else {
			break;
		}
	}

	ZXIC_COMM_PRINT("\n free_number: 0x%x", free_number);

	return ZXIC_OK;
}
