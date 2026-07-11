// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "zxic_comm_double_link.h"

u32 zxic_comm_double_link_insert_1st(struct _d_node *p_newnode, struct _d_head *p_head)
{
	ZXIC_COMM_CHECK_POINT(p_newnode);
	ZXIC_COMM_CHECK_POINT(p_head);

	ZXIC_COMM_CHECK_INDEX((p_head->used + 1), 1, p_head->maxnum);

	ZXIC_COMM_ASSERT(!(!p_head->p_next && p_head->p_prev));
	ZXIC_COMM_ASSERT(!(p_head->p_next && !p_head->p_prev));

	p_newnode->next = p_head->p_next;
	p_newnode->prev = NULL;

	if (p_head->p_next)
		p_head->p_next->prev = p_newnode;
	else
		p_head->p_prev = p_newnode;

	p_head->p_next = p_newnode;
	p_head->used++;

	return ZXIC_OK;
}

u32 zxic_comm_double_link_insert_cmp(struct _d_head *p_head, void *cmp_data, u32 *is_same)
{
	struct _d_node *p_dn = 0;

	*is_same = 0;

	p_dn = p_head->p_next;

	while (p_dn) {
		if (*(u32 *)cmp_data == *(u32 *)p_dn->data) {
			*is_same = 1;

			break;
		}

		p_dn = p_dn->next;
	}

	return ZXIC_OK;
}

u32 zxic_comm_double_link_insert_merge(struct _d_node *p_newnode, struct _d_head *p_head,
				       u32 is_head)
{
	struct _d_node *p_dn = 0;
	u32 is_same = 0;

	p_dn = p_head->p_next;

	while (p_dn) {
		if (p_dn->data == p_newnode->data) {
			is_same = 1;
			break;
		}

		p_dn = p_dn->next;
	}

	if (!is_same) {
		if (is_head)
			return zxic_comm_double_link_insert_1st(p_newnode, p_head);
		else
			return zxic_comm_double_link_insert_last(p_newnode, p_head);
	}

	return ZXIC_OK;
}

u32 zxic_comm_double_link_insert_aft(struct _d_node *p_newnode, struct _d_node *p_oldnode,
				     struct _d_head *p_head)
{
	ZXIC_COMM_CHECK_POINT(p_newnode);
	ZXIC_COMM_CHECK_POINT(p_oldnode);
	ZXIC_COMM_CHECK_POINT(p_head);

	ZXIC_COMM_CHECK_INDEX((p_head->used + 1), 1, p_head->maxnum);

	ZXIC_COMM_ASSERT(!(!p_head->p_next && p_head->p_prev));
	ZXIC_COMM_ASSERT(!(p_head->p_next && !p_head->p_prev));

	p_newnode->next = p_oldnode->next;
	p_newnode->prev = p_oldnode;

	if (p_oldnode->next)
		p_oldnode->next->prev = p_newnode;
	else
		p_head->p_prev = p_newnode;

	p_oldnode->next = p_newnode;
	p_head->used++;

	return ZXIC_OK;
}

u32 zxic_comm_double_link_insert_pre(struct _d_node *p_newnode, struct _d_node *p_oldnode,
				     struct _d_head *p_head)
{
	ZXIC_COMM_CHECK_POINT(p_newnode);
	ZXIC_COMM_CHECK_POINT(p_oldnode);
	ZXIC_COMM_CHECK_POINT(p_head);

	ZXIC_COMM_CHECK_INDEX((p_head->used + 1), 1, p_head->maxnum);

	ZXIC_COMM_ASSERT(!(!p_head->p_next && p_head->p_prev));
	ZXIC_COMM_ASSERT(!(p_head->p_next && !p_head->p_prev));

	p_newnode->next = p_oldnode;
	p_newnode->prev = p_oldnode->prev;

	if (p_oldnode->prev)
		p_oldnode->prev->next = p_newnode;
	else
		p_head->p_next = p_newnode;

	p_oldnode->prev = p_newnode;
	p_head->used++;

	return ZXIC_OK;
}
u32 zxic_comm_double_link_insert_last(struct _d_node *p_newnode, struct _d_head *p_head)
{
	struct _d_node *p_dnode = NULL;

	ZXIC_COMM_CHECK_POINT(p_newnode);
	ZXIC_COMM_CHECK_POINT(p_head);

	ZXIC_COMM_CHECK_INDEX((p_head->used + 1), 1, p_head->maxnum);

	ZXIC_COMM_ASSERT(!(!p_head->p_next && p_head->p_prev));
	ZXIC_COMM_ASSERT(!(p_head->p_next && !p_head->p_prev));

	p_dnode = p_head->p_prev;

	if (!p_dnode) {
		p_head->p_next = p_newnode;
		p_head->p_prev = p_newnode;
		p_newnode->next = NULL;
		p_newnode->prev = NULL;
	} else {
		p_newnode->prev = p_dnode;
		p_newnode->next = NULL;
		p_head->p_prev = p_newnode;
		p_dnode->next = p_newnode;
	}

	p_head->used++;

	return ZXIC_OK;
}
u32 zxic_comm_double_link_del(struct _d_node *delnode, struct _d_head *p_head)
{
	struct _d_node *next = NULL;
	struct _d_node *pre = NULL;

	ZXIC_COMM_CHECK_POINT(delnode);
	ZXIC_COMM_CHECK_POINT(p_head);

	ZXIC_COMM_CHECK_INDEX(p_head->used, 1, p_head->maxnum);

	next = delnode->next;
	pre = delnode->prev;

	if (next)
		next->prev = delnode->prev;
	else
		p_head->p_prev = delnode->prev;

	if (pre)
		pre->next = delnode->next;
	else
		p_head->p_next = delnode->next;

	p_head->used--;
	delnode->next = NULL;
	delnode->prev = NULL;
	return ZXIC_OK;
}

u32 zxic_comm_double_link_init(u32 elmemtnum, struct _d_head *p_head)
{
	u32 err_code = 0;

	ZXIC_COMM_CHECK_POINT(p_head);

	if (elmemtnum == 0) {
		err_code = ZXIC_DOUBLE_LINK_INIT_ELEMENT_NUM_ERR;
		ZXIC_COMM_TRACE_ERROR("\nError:[0x%x] zxic_doule_link_init Element Num Err !",
				      err_code);
		return err_code;
	}

	p_head->maxnum = elmemtnum;
	p_head->used = 0;
	p_head->p_next = NULL;
	p_head->p_prev = NULL;

	return ZXIC_OK;
}

u32 zxic_comm_dlink_release(struct _d_head *p_head, fun_free fun)
{
	u32 rc = 0;
	struct _d_node *p_node = NULL;

	ZXIC_COMM_CHECK_POINT(p_head);

	while (p_head->used) {
		p_node = p_head->p_next;

		if (fun) {
			rc = fun(p_node->data);
			ZXIC_COMM_CHECK_RC(rc, "fun");
		}

		rc = zxic_comm_double_link_del(p_node, p_head);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_double_link_del");

		ZXIC_COMM_FREE(p_node);
	}

	return ZXIC_OK;
}
/*connetc the s_list to d_list */

u32 zxic_comm_double_link_merge_list(struct _d_head *d_list, struct _d_head *s_list)
{
	if (d_list->p_prev) {
		d_list->p_prev->next = s_list->p_next;
	} else {
		ZXIC_COMM_ASSERT(!d_list->p_next);
		d_list->p_next = s_list->p_next;
	}

	if (s_list->p_next) {
		ZXIC_COMM_ASSERT(s_list->p_prev);
		s_list->p_next->prev = d_list->p_prev;
		d_list->p_prev = s_list->p_prev;
	}

	d_list->used += s_list->used;

	return ZXIC_OK;
}

u32 zxic_comm_double_link_insert_sort(struct _d_node *p_newnode, struct _d_head *p_head,
				      CMP_FUNC cmp_fuc, void *cmp_data)
{
	struct _d_node *pre_node = NULL;

	ZXIC_COMM_CHECK_POINT(p_head);
	ZXIC_COMM_CHECK_POINT(p_newnode);

	if (!cmp_fuc)
		cmp_fuc = zxic_comm_double_link_default_cmp_fuc;

	ZXIC_COMM_CHECK_INDEX((p_head->used + 1), 1, p_head->maxnum);

	if (p_head->used == 0)
		return zxic_comm_double_link_insert_1st(p_newnode, p_head);

	pre_node = p_head->p_next;

	while (pre_node) {
		if (cmp_fuc(p_newnode, pre_node, cmp_data) <= 0)
			return zxic_comm_double_link_insert_pre(p_newnode, pre_node, p_head);
		pre_node = pre_node->next;
	}

	return zxic_comm_double_link_insert_last(p_newnode, p_head);
}

u32 zxic_comm_double_link_del_by_info(struct _d_head *p_head, void *cmp_data, CMP_FUNC cmp_fuc,
				      u32 *p_deled_num)
{
	u32 rc = 0;
	u32 is_same = 0;

	struct _d_node *p;
	struct _d_node *p_cur_node = ZXIC_NULL;

	if (!cmp_fuc)
		cmp_fuc = zxic_comm_double_link_default_cmp_fuc;

	p = p_head->p_next;

	while (p) {
		if (cmp_fuc(cmp_data, p, cmp_data) == 0) {
			rc = zxic_comm_double_link_del(p, p_head);
			ZXIC_COMM_CHECK_RC(rc, "zxic_comm_double_link_del");

			p_cur_node = p;
			p = p->next;

			ZXIC_COMM_FREE(p_cur_node);
			is_same++;
			continue;
		}

		p = p->next;
	}

	if (is_same == 0)
		return ZXIC_ERR;

	*p_deled_num = is_same;

	ZXIC_COMM_TRACE_DEBUG(" DOUBLE LINK DEL NUM %d\n", is_same);

	return ZXIC_OK;
}

u32 zxic_comm_double_link_del_pos(struct _d_head *p_head, void *cmp_data, fun_free fun)
{
	u32 rc = 0;
	u32 is_same = 0;

	struct _d_node *p;

	p = p_head->p_next;

	while (p) {
		if (*(u32 *)cmp_data == *(u32 *)p->data) {
			is_same = 1;

			break;
		}

		p = p->next;
	}

	if (is_same) {
		rc = zxic_comm_double_link_del(p, p_head);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_double_link_del");

		if (fun) {
			rc = fun(p->data);
			ZXIC_COMM_CHECK_RC(rc, "fun");
		}

		ZXIC_COMM_FREE(p);
	}

	return ZXIC_OK;
}

u32 zxic_comm_double_link_print(struct _d_head *p_head)
{
	struct _d_node *p_pre = NULL;
	struct _d_node *p_next = NULL;

	ZXIC_COMM_CHECK_POINT(p_head);

	p_next = p_head->p_next;
	ZXIC_COMM_PRINT("*************sequ order***********\n");

	while (p_next) {
		ZXIC_COMM_PRINT("==>%d", *(u32 *)(p_next->data));
		p_next = p_next->next;
	}

	ZXIC_COMM_PRINT("\n\n*************reverve order***********\n");
	p_pre = p_head->p_prev;

	while (p_pre) {
		ZXIC_COMM_PRINT("==>%d", *(u32 *)(p_pre->data));
		p_pre = p_pre->prev;
	}

	return ZXIC_OK;
}

s32 zxic_comm_double_link_default_cmp_fuc(struct _d_node *p_data1, struct _d_node *p_data2,
					  void *p_data)
{
	u32 data1 = *(u32 *)p_data1->data;
	u32 data2 = *(u32 *)p_data2->data;

	if (data1 > data2)
		return 1;
	else if (data1 == data2)
		return 0;
	else
		return -1;
}

u32 zxic_comm_double_link_del_by_data(struct _d_head *p_head, void *cmp_data, fun_free fun)
{
	u32 rc = 0;
	u32 is_same = 0;

	struct _d_node *p;

	p = p_head->p_next;

	while (p) {
		if (cmp_data == p->data) {
			is_same = 1;

			break;
		}
		p = p->next;
	}

	if (is_same) {
		rc = zxic_comm_double_link_del(p, p_head);
		ZXIC_COMM_CHECK_RC(rc, "zxic_comm_double_link_del");
		if (fun) {
			rc = fun(p->data);
			ZXIC_COMM_CHECK_RC(rc, "fun");
		}

		ZXIC_COMM_FREE(p);
	} else {
		ZXIC_COMM_TRACE_ERROR("\nError:data not exist. FUNCTION : %s!\n", __func__);
	}

	return ZXIC_OK;
}
