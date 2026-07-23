/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXIC_COMM_DOUBLELINK_INDEX_H__
#define __ZXIC_COMM_DOUBLELINK_INDEX_H__

/**************************  include head files  *****************************/

/**************************  type define  *****************************/
#define DOUBLELINK_CHECKSUM ((u32)(0xAABBBAAB))

/**************************  const variables  **************************/
#define DOUBLELINK_INVALID_PREVIOUS (0x0)
#define DOUBLELINK_INVALID_NEXT (0x0)
#define DOUBLELINK_USED_FLAG ((u32)(0xffffffff))
#define DOUBLELINK_LASTEST_ELEMENT ((u32)(0x0ffffffe))

/**
 * NAME: DLINK_NODE
 *
 * DESCRIPTION: Structure Node the information of the doublelink.
 */
struct DLINK_NODE {
	u32 dw_next_node;
	u32 dw_pre_node;
	u32 dw_self_node;
};

/**
 * NAME: FTMCOMM_DOUBLELINK_MANGER
 *
 * DESCRIPTION: Structure containing the information required by the
 * implementation of the doublelink.
 */

struct _FtmComm_DoubleLink_Manager {
	/* p_array is a pointer to the array of elements used to track which
	 * indexes have been allocated.
	 */
	struct DLINK_NODE *p_array;

	/* numElements is the number of indexes managed by this instance of the
	 * index_pool.
	 */
	u32 capacity;

	/* currFreeElement stores a free element for where to alloc next free element.
	 * This helps prevent looping over a large sections of the array each time
	 * a new index is allocated.
	 */
	u32 free_num;

	u32 used_num;

	u32 first_used;

	u32 last_used;

	u32 first_free;

	u32 last_free;
	/* offset is an adjustment value, allowing the caller to prevent certain
	 * indexes from being allocated.  This value is only meaningful to the
	 * client, and does not affect how the indexes are managed within the
	 * doublelink.
	 */
	u32 offset;

	u32 check_sum;
};

u32 zxic_comm_dlink_manage_create(u32 dw_element_num, u32 dw_offset,
				  struct _FtmComm_DoubleLink_Manager **p_dlink);

u32 zxic_comm_dlink_alloc(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 *index);

u32 zxic_comm_dlink_free(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 index);

u32 zxic_comm_dlink_get_next(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 dw_index,
			     u32 *p_next_index);

u32 zxic_comm_dlink_manage_clear(struct _FtmComm_DoubleLink_Manager *p_dlink);

u32 zxic_comm_dlink_get_previous(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 dw_index,
				 u32 *p_pre_index);

u32 zxic_comm_dlink_is_used(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 dw_index,
			    u8 *p_is_used);

u32 zxic_comm_dlink_first_free(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 *p_index);

u32 zxic_comm_dlink_first_used(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 *p_index);

u32 zxic_comm_dlink_manage_reset(struct _FtmComm_DoubleLink_Manager *p_dlink);

u32 zxic_comm_dlink_get_curr_info(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 *p_free_num,
				  u32 *p_curr_free_index);

u32 zxic_comm_dlink_last_used(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 *p_index);

u32 zxic_comm_dlink_used_num(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 *p_num);

u32 zxic_comm_dlink_show_node_info(struct _FtmComm_DoubleLink_Manager *p_dlink, u32 dw_node_index);

u32 zxic_comm_dlink_show_current_status(struct _FtmComm_DoubleLink_Manager *p_dlink);

u32 zxic_comm_dlink_self_test(void);

#endif
