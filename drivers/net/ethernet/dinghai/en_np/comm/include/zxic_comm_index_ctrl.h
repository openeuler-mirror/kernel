/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

/*********************************************************************
 * DEPARTMENT: ASIC_FPGA_R&D_Dept
 * MANUAL_PERCENT   : 100%
 ********************************************************************
 */
#ifndef _ZXIC_COMM_INDEX_CONTROLLER_H_
#define _ZXIC_COMM_INDEX_CONTROLLER_H_

//#include "zxic_common.h"
//#include "zxic_comm_rb_tree.h"
//#include "zxic_comm_double_link.h"

#define ZXIC_INDEX_EXPAND_MAX_NUM (900)
#define INDEX_KEY_LENGTH (4)
struct zxic_index_ctrl_cfg {
	u32 index_cursor_current;
	u32 index_cursor_last;
	u32 index_cursor_max_cur;
	u32 index_ctrl_is_init;
	u32 *p_index_buf;

	struct _rb_cfg index_ctrl_rb_tree;
	struct _rb_cfg rcd_ctrl_rb_tree;

	struct _d_head *p_index_ctrl_link;
};

struct _zxic_index_api_params {
	u32 zxic_expand_num; /*the expand num of this item  */
	u32 zxic_opera_mode; /*0:add;1:del;2:sch            */
	u32 zxic_rsp_isexit; /*the rsp of whether is exit   */
	u32 *p_zxic_out_index; /*the address of response      */
	void *p_zxic_data; /*the data of inserting in tcam*/
};

enum functionNo {
	INDEX_CTRL_ADD,
	INDEX_CTRL_ADD_FROM_LAST,
	INDEX_CTRL_DEL,
	INDEX_CTRL_SEARCH,
	INDEX_CTRL_UNDEFINED
};

u32 zxic_comm_indexctrl_get_free_index(struct zxic_index_ctrl_cfg *p_table_info, u32 func_type,
				       u32 *p_free_index_num);
u32 zxic_comm_indexctrl_add_from_last(struct zxic_index_ctrl_cfg *p_table_info, void *data,
				      u32 expand_num, u32 *out_index);
u32 zxic_comm_indexctrl_sch(struct zxic_index_ctrl_cfg *p_table_info, void *data, u32 *p_is_exit,
			    u32 *out_index);
u32 zxic_comm_indexctrl_extcommand(struct _zxic_index_api_params *p_zxic_api_params,
				   struct zxic_index_ctrl_cfg *p_table_info);
u32 zxic_comm_indexctrl_add(struct zxic_index_ctrl_cfg *p_table_info, void *data, u32 expand_num,
			    u32 *out_index);
u32 zxic_comm_indexctrl_init(struct zxic_index_ctrl_cfg *p_table_info, u32 index_max_num,
			     u32 table_key_len);
u32 zxic_comm_indexctrl_getindex_from_last(struct zxic_index_ctrl_cfg *p_table_info,
					   u32 *p_index_out);
u32 zxic_comm_indexctrl_del(struct zxic_index_ctrl_cfg *p_table_info, void *data, u32 *out_index);
u32 zxic_comm_indexctrl_getindex(struct zxic_index_ctrl_cfg *p_table_info, u32 *p_index_out);
s32 zxic_comm_indexctrl_cmp_key(void *new_key, void *old_key, u32 key_len);

#endif
