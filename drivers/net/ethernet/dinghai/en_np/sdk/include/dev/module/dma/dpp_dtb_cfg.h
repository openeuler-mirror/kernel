/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_DTB_CFG_H_
#define _DPP_DTB_CFG_H_
#include "dpp_dev.h"

#define DPP_DEV_SLOT_MAX (DPP_PCIE_SLOT_MAX)
#define DPP_DTB_QUEUE_NUM_MAX (128)
#define DPP_DTB_TRAF_CTRL_RAM_SIZE (256)
#define DPP_DTB_TRAF_CTRL_RAM_5_SIZE (64)
#define DPP_DTB_DUMP_PD_RAM_SIZE (2048)
#define DPP_DTB_RD_CTRL_RAM_SIZE (4096)
#define DPP_DTB_RD_TABLE_RAM_SIZE (8192)
#define DPP_DTB_CMD_MAN_RAM_SIZE (16384)

/* vport
 * 15 |14 13 12 |     11    |10  9  8|7 6 5 4 3 2 1 0|
 * rsv| ep_id   |func_active|func_num|    vfunc_num  |
 */
#define VPORT_EPID_BT_START (12)
#define VPORT_EPID_BT_LEN (3)
#define VPORT_FUNC_ACTIVE_BT_START (11)
#define VPORT_FUNC_ACTIVE_BT_LEN (1)
#define VPORT_FUNC_NUM_BT_START (8)
#define VPORT_FUNC_NUM_BT_LEN (3)
#define VPORT_VFUNC_NUM_BT_START (0)
#define VPORT_VFUNC_NUM_BT_LEN (8)

struct dpp_dtb_queue_item_info_t {
	u32 cmd_vld;
	u32 cmd_type;
	u32 int_en;
	u32 data_len;
	u32 data_laddr;
	u32 data_hddr;
};

struct dpp_dtb_queue_vm_info_t {
	u32 dbi_en;
	u32 queue_en;
	u32 epid;
	u32 vfunc_num;
	u32 vector;
	u32 func_num;
	u32 vfunc_active;
};

#if ZXIC_REAL("DTB_CFG")
u32 dpp_dtb_queue_item_info_set(struct dpp_dev_t *dev, u32 queue_id,
				struct dpp_dtb_queue_item_info_t *p_item_info);
u32 dpp_dtb_queue_unused_item_num_get(struct dpp_dev_t *dev, u32 queue_id, u32 *p_item_num);
u32 dpp_dtb_queue_vm_info_set(struct dpp_dev_t *dev, u32 queue_id,
			      struct dpp_dtb_queue_vm_info_t *p_vm_info);
u32 dpp_dtb_queue_vm_info_get(struct dpp_dev_t *dev, u32 queue_id,
			      struct dpp_dtb_queue_vm_info_t *p_vm_info);
u32 dpp_dtb_queue_enable_set(struct dpp_dev_t *dev, u32 queue_id, u32 enable);
u32 dpp_dtb_queue_enable_get(struct dpp_dev_t *dev, u32 queue_id, u32 *enable);
u32 dpp_dtb_finish_interrupt_event_state_set(struct dpp_dev_t *dev, u32 queue_id, u32 state);
u32 dpp_dtb_finish_interrupt_event_state_clr(struct dpp_dev_t *dev, u32 queue_id);

u32 dpp_dtb_debug_mode_get(struct dpp_dev_t *dev, u32 *p_debug_mode);

u32 dpp_dtb_mode_is_debug(struct dpp_dev_t *dev);
u32 dpp_dtb_axi_last_rd_table_info_get(struct dpp_dev_t *dev, u32 *p_last_rd_table_addr_h,
				       u32 *p_last_rd_table_addr_l, u32 *p_last_rd_table_len,
				       u32 *p_last_rd_table_user, u32 *p_last_rd_table_onload_cnt);
u32 dpp_dtb_axi_rd_table_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_rd_table_resp_err_cnt);
u32 dpp_dtb_axi_last_rd_pd_info_get(struct dpp_dev_t *dev, u32 *p_last_rd_pd_addr_h,
				    u32 *p_last_rd_pd_addr_l, u32 *p_last_rd_pd_len,
				    u32 *p_last_rd_pd_user, u32 *p_last_rd_pd_onload_cnt);
u32 dpp_dtb_axi_rd_pd_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_rd_pd_resp_err_cnt);
u32 dpp_dtb_axi_last_wr_ctrl_info_get(struct dpp_dev_t *dev, u32 *p_last_wr_ctrl_addr_h,
				      u32 *p_last_wr_ctrl_addr_l, u32 *p_last_wr_ctrl_len,
				      u32 *p_last_wr_ctrl_user, u32 *p_last_wr_ctrl_onload_cnt);
u32 dpp_dtb_axi_wr_ctrl_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_wr_ctrl_resp_err_cnt);
u32 dpp_dtb_axi_last_wr_ddr_info_get(struct dpp_dev_t *dev, u32 *p_last_wr_ddr_addr_h,
				     u32 *p_last_wr_ddr_addr_l, u32 *p_last_wr_ddr_len,
				     u32 *p_last_wr_ddr_user, u32 *p_last_wr_ddr_onload_cnt);
u32 dpp_dtb_axi_wr_ddr_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_wr_ddr_resp_err_cnt);
u32 dpp_dtb_axi_last_wr_fin_info_get(struct dpp_dev_t *dev, u32 *p_last_wr_fin_addr_h,
				     u32 *p_last_wr_fin_addr_l, u32 *p_last_wr_fin_len,
				     u32 *p_last_wr_fin_user, u32 *p_last_wr_fin_onload_cnt);
u32 dpp_dtb_axi_wr_fin_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_wr_fin_resp_err_cnt);
u32 dpp_dtb_state_info_get(struct dpp_dev_t *dev, u32 *p_wr_ctrl_state_info,
			   u32 *p_rd_table_state_info, u32 *p_rd_pd_state_info,
			   u32 *p_wr_ddr_state_info, u32 *p_dump_cmd_state_info);
u32 diag_dpp_dtb_channels_axi_resp_err_cnt_prt(struct dpp_dev_t *dev);
u32 diag_dpp_dtb_axi_last_operate_info_prt(struct dpp_dev_t *dev);
u32 diag_dpp_dtb_channels_state_info_prt(struct dpp_dev_t *dev);

#endif

#endif
