// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_cfg_reg.h"
#include "dpp_dev.h"
#include "dpp_dtb.h"
#include "dpp_reg.h"
#include "dpp_reg_info.h"
#include "dpp_dtb_cfg.h"
#include "dpp_dtb4k_reg.h"
#include "dpp_dtb_reg.h"

#define DTB_DEBUG_VALUE (0x5A)
#define DPP_DTB_SPACE_LEFT_MASK (0x3F)

#if ZXIC_REAL("DTB_CFG")
u32 dpp_dtb_queue_item_info_set(struct dpp_dev_t *dev, u32 queue_id,
				struct dpp_dtb_queue_item_info_t *p_item_info)
{
	u32 rc = 0;
	struct dpp_dtb4k_dtb_enq_cfg_queue_dtb_len_0_127_t dtb_len = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_item_info);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_item_info->cmd_vld, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_item_info->cmd_type, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_item_info->int_en, 0, 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), p_item_info->data_len, DPP_DTB_LEN_MIN,
				  DPP_DTB_DOWN_LEN);

	rc = dpp_reg_write(dev, DTB4K_DTB_ENQ_CFG_QUEUE_DTB_ADDR_H_0_127r, 0, queue_id,
			   &(p_item_info->data_hddr));
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	rc = dpp_reg_write(dev, DTB4K_DTB_ENQ_CFG_QUEUE_DTB_ADDR_L_0_127r, 0, queue_id,
			   &(p_item_info->data_laddr));
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	dtb_len.cfg_dtb_cmd_type = p_item_info->cmd_type;
	dtb_len.cfg_dtb_cmd_int_en = p_item_info->int_en;
	dtb_len.cfg_queue_dtb_len = p_item_info->data_len;

	rc = dpp_reg_write(dev, DTB4K_DTB_ENQ_CFG_QUEUE_DTB_LEN_0_127r, 0, queue_id, &dtb_len);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
u32 dpp_dtb_queue_unused_item_num_get(struct dpp_dev_t *dev, u32 queue_id, u32 *p_item_num)
{
	u32 rc = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_item_num);

	rc = dpp_reg_read(dev, DTB4K_DTB_ENQ_INFO_QUEUE_BUF_SPACE_LEFT_0_127r, 0, queue_id,
			  p_item_num);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	if ((*p_item_num & DPP_DTB_SPACE_LEFT_MASK) == DPP_DTB_SPACE_LEFT_MASK) {
		ZXIC_COMM_TRACE_ERROR("pcie bar abnormal, get dtb space left false.\n");
		return ZXIC_PAR_CHK_BAR_ABNORMAL;
	}

	return DPP_OK;
}
u32 dpp_dtb_queue_vm_info_set(struct dpp_dev_t *dev, u32 queue_id,
			      struct dpp_dtb_queue_vm_info_t *p_vm_info)
{
	u32 rc = 0;
	struct dpp_dtb4k_dtb_enq_cfg_epid_v_func_num_0_127_t vm_info = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_vm_info);

	vm_info.dbi_en = p_vm_info->dbi_en;
	vm_info.queue_en = p_vm_info->queue_en;
	vm_info.cfg_epid = p_vm_info->epid;
	vm_info.cfg_vector = p_vm_info->vector;
	vm_info.cfg_vfunc_num = p_vm_info->vfunc_num;
	vm_info.cfg_func_num = p_vm_info->func_num;
	vm_info.cfg_vfunc_active = p_vm_info->vfunc_active;

	rc = dpp_reg_write(dev, DTB4K_DTB_ENQ_CFG_EPID_V_FUNC_NUM_0_127r, 0, queue_id, &vm_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
u32 dpp_dtb_queue_vm_info_get(struct dpp_dev_t *dev, u32 queue_id,
			      struct dpp_dtb_queue_vm_info_t *p_vm_info)
{
	u32 rc = 0;
	struct dpp_dtb4k_dtb_enq_cfg_epid_v_func_num_0_127_t vm_info = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_vm_info);

	rc = dpp_reg_read(dev, DTB4K_DTB_ENQ_CFG_EPID_V_FUNC_NUM_0_127r, 0, queue_id, &vm_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	p_vm_info->dbi_en = vm_info.dbi_en;
	p_vm_info->queue_en = vm_info.queue_en;
	p_vm_info->epid = vm_info.cfg_epid;
	p_vm_info->vector = vm_info.cfg_vector;
	p_vm_info->vfunc_num = vm_info.cfg_vfunc_num;
	p_vm_info->func_num = vm_info.cfg_func_num;
	p_vm_info->vfunc_active = vm_info.cfg_vfunc_active;

	return DPP_OK;
}
u32 dpp_dtb_queue_enable_set(struct dpp_dev_t *dev, u32 queue_id, u32 enable)
{
	u32 rc = DPP_OK;
	struct dpp_dtb_queue_vm_info_t vm_info = { 0 };

	rc = dpp_dtb_queue_vm_info_get(dev, queue_id, &vm_info);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_queue_vm_info_get");

	vm_info.queue_en = enable;
	rc = dpp_dtb_queue_vm_info_set(dev, queue_id, &vm_info);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_queue_vm_info_set");

	ZXIC_COMM_TRACE_INFO("dtb queue [%d] enable_set [%d] success.\n", queue_id, enable);

	return rc;
}
u32 dpp_dtb_queue_enable_get(struct dpp_dev_t *dev, u32 queue_id, u32 *enable)
{
	u32 rc = DPP_OK;
	struct dpp_dtb_queue_vm_info_t vm_info = { 0 };

	rc = dpp_dtb_queue_vm_info_get(dev, queue_id, &vm_info);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_queue_vm_info_get");

	*enable = vm_info.queue_en;

	ZXIC_COMM_TRACE_INFO("dpp dtb_queue_enable_get queue %d enable: %d success.\n", queue_id,
			     *enable);

	return rc;
}
u32 dpp_dtb_finish_interrupt_event_state_set(struct dpp_dev_t *dev, u32 queue_id, u32 state)
{
	u32 rc = 0;
	u32 bit_shift = 0;
	u32 reg_shift = 0;
	u32 rd_value = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX(DEV_ID(dev), state, 0, 1);

	reg_shift = queue_id / 32;
	bit_shift = queue_id % 32;

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CFG_FINISH_INT_EVENT0r + reg_shift, 0, 0, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	ZXIC_COMM_UINT32_WRITE_BITS(rd_value, state, bit_shift, 1);

	rc = dpp_reg_write(dev, DTB_DTB_CFG_CFG_FINISH_INT_EVENT0r + reg_shift, 0, 0, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_write");

	return DPP_OK;
}
u32 dpp_dtb_finish_interrupt_event_state_clr(struct dpp_dev_t *dev, u32 queue_id)
{
	u32 rc = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(DEV_ID(dev), queue_id, 0, DPP_DTB_QUEUE_NUM_MAX - 1);

	rc = dpp_dtb_finish_interrupt_event_state_set(dev, queue_id, 1);
	ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, "dpp_dtb_finish_interrupt_event_state_set");

	return rc;
}
u32 dpp_dtb_debug_mode_get(struct dpp_dev_t *dev, u32 *p_debug_mode)
{
	u32 rc = 0;
	struct dpp_dtb_dtb_cfg_cfg_dtb_debug_mode_en_t dtb_debug_mode = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_debug_mode);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CFG_DTB_DEBUG_MODE_ENr, 0, 0, &dtb_debug_mode);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_debug_mode = dtb_debug_mode.cfg_dtb_debug_mode_en;

	return DPP_OK;
}
u32 dpp_dtb_mode_is_debug(struct dpp_dev_t *dev)
{
	u32 rc = 0;
	u32 dtb_mode = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	rc = dpp_dtb_debug_mode_get(dev, &dtb_mode);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_debug_mode_get");

	if (dtb_mode == DTB_DEBUG_VALUE)
		return 1;

	return 0;
}

#if ZXIC_REAL("AXIM_READ_TABLE_DEBUG")
u32 dpp_dtb_axi_last_rd_table_info_get(struct dpp_dev_t *dev, u32 *p_last_rd_table_addr_h,
				       u32 *p_last_rd_table_addr_l, u32 *p_last_rd_table_len,
				       u32 *p_last_rd_table_user, u32 *p_last_rd_table_onload_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_addr_high_t rd_table_addr_high = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_addr_low_t rd_table_addr_low = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_len_t rd_table_len = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t rd_table_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_onload_cnt_t rd_table_onload_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_table_addr_h);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_table_addr_l);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_table_len);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_table_user);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_table_onload_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_TABLE_ADDR_HIGHr, 0, 0,
			  &rd_table_addr_high);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_TABLE_ADDR_LOWr, 0, 0,
			  &rd_table_addr_low);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_TABLE_LENr, 0, 0, &rd_table_len);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_TABLE_USERr, 0, 0, &rd_table_user);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_TABLE_ONLOAD_CNTr, 0, 0,
			  &rd_table_onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_last_rd_table_addr_h = rd_table_addr_high.info_axi_last_rd_table_addr_high;
	*p_last_rd_table_addr_l = rd_table_addr_low.info_axi_last_rd_table_addr_low;
	*p_last_rd_table_len = rd_table_len.info_axi_last_rd_table_len;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t *)p_last_rd_table_user))
		.info_rd_table_user_en = rd_table_user.info_rd_table_user_en;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t *)p_last_rd_table_user))
		.info_rd_table_epid = rd_table_user.info_rd_table_epid;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t *)p_last_rd_table_user))
		.info_rd_table_vfunc_num = rd_table_user.info_rd_table_vfunc_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t *)p_last_rd_table_user))
		.info_rd_table_func_num = rd_table_user.info_rd_table_func_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t *)p_last_rd_table_user))
		.info_rd_table_vfunc_active = rd_table_user.info_rd_table_vfunc_active;
	*p_last_rd_table_onload_cnt = rd_table_onload_cnt.info_axi_last_rd_table_onload_cnt;

	return DPP_OK;
}
u32 dpp_dtb_axi_rd_table_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_rd_table_resp_err_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_cnt_axi_rd_table_resp_err_t rd_table_resp_err_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_axi_rd_table_resp_err_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CNT_AXI_RD_TABLE_RESP_ERRr, 0, 0,
			  &rd_table_resp_err_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_axi_rd_table_resp_err_cnt = rd_table_resp_err_cnt.cnt_axi_rd_table_resp_err;

	return DPP_OK;
}
#endif

#if ZXIC_REAL("AXIM_READ_PD_DEBUG")
u32 dpp_dtb_axi_last_rd_pd_info_get(struct dpp_dev_t *dev, u32 *p_last_rd_pd_addr_h,
				    u32 *p_last_rd_pd_addr_l, u32 *p_last_rd_pd_len,
				    u32 *p_last_rd_pd_user, u32 *p_last_rd_pd_onload_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_addr_high_t rd_pd_addr_high = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_addr_low_t rd_pd_addr_low = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_len_t rd_pd_len = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t rd_pd_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_onload_cnt_t rd_pd_onload_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_pd_addr_h);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_pd_addr_l);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_pd_len);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_pd_user);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_rd_pd_onload_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_PD_ADDR_HIGHr, 0, 0, &rd_pd_addr_high);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_PD_ADDR_LOWr, 0, 0, &rd_pd_addr_low);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_PD_LENr, 0, 0, &rd_pd_len);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_PD_USERr, 0, 0, &rd_pd_user);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_RD_PD_ONLOAD_CNTr, 0, 0,
			  &rd_pd_onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_last_rd_pd_addr_h = rd_pd_addr_high.info_axi_last_rd_pd_addr_high;
	*p_last_rd_pd_addr_l = rd_pd_addr_low.info_axi_last_rd_pd_addr_low;
	*p_last_rd_pd_len = rd_pd_len.info_axi_last_rd_pd_len;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t *)p_last_rd_pd_user))
		.info_rd_pd_user_en = rd_pd_user.info_rd_pd_user_en;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t *)p_last_rd_pd_user))
		.info_rd_pd_epid = rd_pd_user.info_rd_pd_epid;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t *)p_last_rd_pd_user))
		.info_rd_pd_vfunc_num = rd_pd_user.info_rd_pd_vfunc_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t *)p_last_rd_pd_user))
		.info_rd_pd_func_num = rd_pd_user.info_rd_pd_func_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t *)p_last_rd_pd_user))
		.info_rd_pd_vfunc_active = rd_pd_user.info_rd_pd_vfunc_active;
	*p_last_rd_pd_onload_cnt = rd_pd_onload_cnt.info_axi_last_rd_pd_onload_cnt;

	return DPP_OK;
}
u32 dpp_dtb_axi_rd_pd_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_rd_pd_resp_err_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_cnt_axi_rd_pd_resp_err_t rd_pd_resp_err_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_axi_rd_pd_resp_err_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CNT_AXI_RD_PD_RESP_ERRr, 0, 0, &rd_pd_resp_err_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_axi_rd_pd_resp_err_cnt = rd_pd_resp_err_cnt.cnt_axi_rd_pd_resp_err;

	return DPP_OK;
}

#endif

#if ZXIC_REAL("AXI_WRITE_CTRL_DEBUG")
u32 dpp_dtb_axi_last_wr_ctrl_info_get(struct dpp_dev_t *dev, u32 *p_last_wr_ctrl_addr_h,
				      u32 *p_last_wr_ctrl_addr_l, u32 *p_last_wr_ctrl_len,
				      u32 *p_last_wr_ctrl_user, u32 *p_last_wr_ctrl_onload_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_addr_high_t wr_ctrl_addr_high = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_addr_low_t wr_ctrl_addr_low = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_len_t wr_ctrl_len = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t wr_ctrl_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_onload_cnt_t wr_ctrl_onload_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ctrl_addr_h);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ctrl_addr_l);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ctrl_len);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ctrl_user);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ctrl_onload_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_CTRL_ADDR_HIGHr, 0, 0,
			  &wr_ctrl_addr_high);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_CTRL_ADDR_LOWr, 0, 0,
			  &wr_ctrl_addr_low);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_CTRL_LENr, 0, 0, &wr_ctrl_len);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_CTRL_USERr, 0, 0, &wr_ctrl_user);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_CTRL_ONLOAD_CNTr, 0, 0,
			  &wr_ctrl_onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_last_wr_ctrl_addr_h = wr_ctrl_addr_high.info_axi_last_wr_ctrl_addr_high;
	*p_last_wr_ctrl_addr_l = wr_ctrl_addr_low.info_axi_last_wr_ctrl_addr_low;
	*p_last_wr_ctrl_len = wr_ctrl_len.info_axi_last_wr_ctrl_len;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t *)p_last_wr_ctrl_user))
		.info_wr_ctrl_user_en = wr_ctrl_user.info_wr_ctrl_user_en;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t *)p_last_wr_ctrl_user))
		.info_wr_ctrl_epid = wr_ctrl_user.info_wr_ctrl_epid;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t *)p_last_wr_ctrl_user))
		.info_wr_ctrl_vfunc_num = wr_ctrl_user.info_wr_ctrl_vfunc_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t *)p_last_wr_ctrl_user))
		.info_wr_ctrl_func_num = wr_ctrl_user.info_wr_ctrl_func_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t *)p_last_wr_ctrl_user))
		.info_wr_ctrl_vfunc_active = wr_ctrl_user.info_wr_ctrl_vfunc_active;
	*p_last_wr_ctrl_onload_cnt = wr_ctrl_onload_cnt.info_axi_last_wr_ctrl_onload_cnt;

	return DPP_OK;
}
u32 dpp_dtb_axi_wr_ctrl_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_wr_ctrl_resp_err_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_cnt_axi_wr_ctrl_resp_err_t wr_ctrl_resp_err_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_axi_wr_ctrl_resp_err_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CNT_AXI_WR_CTRL_RESP_ERRr, 0, 0, &wr_ctrl_resp_err_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_axi_wr_ctrl_resp_err_cnt = wr_ctrl_resp_err_cnt.cnt_axi_wr_ctrl_resp_err;

	return DPP_OK;
}

#endif

#if ZXIC_REAL("AXI_WRITE_DDR_DEBUG")
u32 dpp_dtb_axi_last_wr_ddr_info_get(struct dpp_dev_t *dev, u32 *p_last_wr_ddr_addr_h,
				     u32 *p_last_wr_ddr_addr_l, u32 *p_last_wr_ddr_len,
				     u32 *p_last_wr_ddr_user, u32 *p_last_wr_ddr_onload_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_addr_high_t wr_ddr_addr_high = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_addr_low_t wr_ddr_addr_low = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_len_t wr_ddr_len = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t wr_ddr_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_onload_cnt_t wr_ddr_onload_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ddr_addr_h);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ddr_addr_l);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ddr_len);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ddr_user);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_ddr_onload_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_DDR_ADDR_HIGHr, 0, 0,
			  &wr_ddr_addr_high);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_DDR_ADDR_LOWr, 0, 0, &wr_ddr_addr_low);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_DDR_LENr, 0, 0, &wr_ddr_len);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_DDR_USERr, 0, 0, &wr_ddr_user);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_DDR_ONLOAD_CNTr, 0, 0,
			  &wr_ddr_onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_last_wr_ddr_addr_h = wr_ddr_addr_high.info_axi_last_wr_ddr_addr_high;
	*p_last_wr_ddr_addr_l = wr_ddr_addr_low.info_axi_last_wr_ddr_addr_low;
	*p_last_wr_ddr_len = wr_ddr_len.info_axi_last_wr_ddr_len;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t *)p_last_wr_ddr_user))
		.info_wr_ddr_user_en = wr_ddr_user.info_wr_ddr_user_en;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t *)p_last_wr_ddr_user))
		.info_wr_ddr_epid = wr_ddr_user.info_wr_ddr_epid;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t *)p_last_wr_ddr_user))
		.info_wr_ddr_vfunc_num = wr_ddr_user.info_wr_ddr_vfunc_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t *)p_last_wr_ddr_user))
		.info_wr_ddr_func_num = wr_ddr_user.info_wr_ddr_func_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t *)p_last_wr_ddr_user))
		.info_wr_ddr_vfunc_active = wr_ddr_user.info_wr_ddr_vfunc_active;
	*p_last_wr_ddr_onload_cnt = wr_ddr_onload_cnt.info_axi_last_wr_ddr_onload_cnt;

	return DPP_OK;
}
u32 dpp_dtb_axi_wr_ddr_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_wr_ddr_resp_err_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_cnt_axi_wr_ddr_resp_err_t wr_ddr_resp_err_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_axi_wr_ddr_resp_err_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CNT_AXI_WR_DDR_RESP_ERRr, 0, 0, &wr_ddr_resp_err_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_axi_wr_ddr_resp_err_cnt = wr_ddr_resp_err_cnt.cnt_axi_wr_ddr_resp_err;

	return DPP_OK;
}

#endif

#if ZXIC_REAL("AXIM_WRITE_FINISH_DEBUG")
u32 dpp_dtb_axi_last_wr_fin_info_get(struct dpp_dev_t *dev, u32 *p_last_wr_fin_addr_h,
				     u32 *p_last_wr_fin_addr_l, u32 *p_last_wr_fin_len,
				     u32 *p_last_wr_fin_user, u32 *p_last_wr_fin_onload_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_addr_high_t wr_fin_addr_high = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_addr_low_t wr_fin_addr_low = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_len_t wr_fin_len = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t wr_fin_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_onload_cnt_t wr_fin_onload_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_fin_addr_h);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_fin_addr_l);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_fin_len);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_fin_user);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_last_wr_fin_onload_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_FIN_ADDR_HIGHr, 0, 0,
			  &wr_fin_addr_high);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_FIN_ADDR_LOWr, 0, 0, &wr_fin_addr_low);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_FIN_LENr, 0, 0, &wr_fin_len);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_FIN_USERr, 0, 0, &wr_fin_user);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_AXI_LAST_WR_FIN_ONLOAD_CNTr, 0, 0,
			  &wr_fin_onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_last_wr_fin_addr_h = wr_fin_addr_high.info_axi_last_wr_fin_addr_high;
	*p_last_wr_fin_addr_l = wr_fin_addr_low.info_axi_last_wr_fin_addr_low;
	*p_last_wr_fin_len = wr_fin_len.info_axi_last_wr_fin_len;

	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t *)p_last_wr_fin_user))
		.info_wr_fin_user_en = wr_fin_user.info_wr_fin_user_en;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t *)p_last_wr_fin_user))
		.info_wr_fin_epid = wr_fin_user.info_wr_fin_epid;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t *)p_last_wr_fin_user))
		.info_wr_fin_vfunc_num = wr_fin_user.info_wr_fin_vfunc_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t *)p_last_wr_fin_user))
		.info_wr_fin_func_num = wr_fin_user.info_wr_fin_func_num;
	(*((struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t *)p_last_wr_fin_user))
		.info_wr_fin_vfunc_active = wr_fin_user.info_wr_fin_vfunc_active;
	*p_last_wr_fin_onload_cnt = wr_fin_onload_cnt.info_axi_last_wr_fin_onload_cnt;

	return DPP_OK;
}
u32 dpp_dtb_axi_wr_fin_resp_err_cnt_get(struct dpp_dev_t *dev, u32 *p_axi_wr_fin_resp_err_cnt)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_cnt_axi_wr_fin_resp_err_t wr_fin_resp_err_cnt = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_axi_wr_fin_resp_err_cnt);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_CNT_AXI_WR_FIN_RESP_ERRr, 0, 0, &wr_fin_resp_err_cnt);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_axi_wr_fin_resp_err_cnt = wr_fin_resp_err_cnt.cnt_axi_wr_fin_resp_err;

	return DPP_OK;
}

#endif

#if ZXIC_REAL("DTB_STATE")
u32 dpp_dtb_state_info_get(struct dpp_dev_t *dev, u32 *p_wr_ctrl_state_info,
			   u32 *p_rd_table_state_info, u32 *p_rd_pd_state_info,
			   u32 *p_wr_ddr_state_info, u32 *p_dump_cmd_state_info)
{
	u32 rc = 0;

	struct dpp_dtb_dtb_cfg_info_wr_ctrl_state_t wr_ctrl_state = { 0 };
	struct dpp_dtb_dtb_cfg_info_rd_table_state_t rd_table_state = { 0 };
	struct dpp_dtb_dtb_cfg_info_rd_pd_state_t rd_pd_state = { 0 };
	struct dpp_dtb_dtb_cfg_info_wr_ddr_state_t wr_ddr_state = { 0 };
	struct dpp_dtb_dtb_cfg_info_dump_cmd_state_t dump_cmd_state = { 0 };

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_INDEX(DEV_ID(dev), 0, DPP_DEV_CHANNEL_MAX - 1);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_wr_ctrl_state_info);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_rd_table_state_info);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_rd_pd_state_info);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_wr_ddr_state_info);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), p_dump_cmd_state_info);

	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_WR_CTRL_STATEr, 0, 0, &wr_ctrl_state);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_RD_TABLE_STATEr, 0, 0, &rd_table_state);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_RD_PD_STATEr, 0, 0, &rd_pd_state);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_WR_DDR_STATEr, 0, 0, &wr_ddr_state);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");
	rc = dpp_reg_read(dev, DTB_DTB_CFG_INFO_DUMP_CMD_STATEr, 0, 0, &dump_cmd_state);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_reg_read");

	*p_wr_ctrl_state_info = wr_ctrl_state.info_wr_ctrl_state;
	*p_rd_table_state_info = rd_table_state.info_rd_table_state;
	*p_rd_pd_state_info = rd_pd_state.info_rd_pd_state;
	*p_wr_ddr_state_info = wr_ddr_state.info_wr_ddr_state;
	*p_dump_cmd_state_info = dump_cmd_state.info_dump_cmd_state;

	return DPP_OK;
}

#endif
u32 diag_dpp_dtb_channels_axi_resp_err_cnt_prt(struct dpp_dev_t *dev)
{
	u32 rc = 0;
	u32 rd_value = 0;

	ZXIC_COMM_PRINT("\n --------------- DTB CHANNEL ERR STAT INFO ---------------\n");

	ZXIC_COMM_PRINT("********** dtb down table err cnt **********\n");

	rc = dpp_dtb_axi_rd_table_resp_err_cnt_get(dev, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_rd_table_resp_err_cnt_get");

	ZXIC_COMM_DBGCNT32_PRINT("cnt_axi_rd_table_resp_err", rd_value);

	rc = dpp_dtb_axi_wr_ctrl_resp_err_cnt_get(dev, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_wr_ctrl_resp_err_cnt_get");

	ZXIC_COMM_DBGCNT32_PRINT("cnt_axi_wr_ctrl_resp_err", rd_value);

	ZXIC_COMM_PRINT("********** dtb dump table err cnt **********\n");

	rc = dpp_dtb_axi_rd_pd_resp_err_cnt_get(dev, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_rd_pd_resp_err_cnt_get");

	ZXIC_COMM_DBGCNT32_PRINT("cnt_axi_rd_pd_resp_err", rd_value);

	rc = dpp_dtb_axi_wr_ddr_resp_err_cnt_get(dev, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_wr_ddr_resp_err_cnt_get");

	ZXIC_COMM_DBGCNT32_PRINT("cnt_axi_wr_ddr_resp_err", rd_value);

	rc = dpp_dtb_axi_wr_fin_resp_err_cnt_get(dev, &rd_value);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_wr_fin_resp_err_cnt_get");

	ZXIC_COMM_DBGCNT32_PRINT("cnt_axi_wr_fin_resp_err", rd_value);

	return DPP_OK;
}
u32 diag_dpp_dtb_axi_last_operate_info_prt(struct dpp_dev_t *dev)
{
	u32 rc = 0;
	u32 addr_high = 0;
	u32 addr_low = 0;
	u32 len = 0;
	u32 onload_cnt = 0;

	struct dpp_dtb_dtb_cfg_info_axi_last_rd_table_user_t rd_table_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_rd_pd_user_t rd_pd_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ctrl_user_t wr_ctrl_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_ddr_user_t wr_ddr_user = { 0 };
	struct dpp_dtb_dtb_cfg_info_axi_last_wr_fin_user_t wr_fin_user = { 0 };

	ZXIC_COMM_PRINT("\n------------------ DTB DOWN TABLE LAST INFO ------------------\n");
	rc = dpp_dtb_axi_last_rd_table_info_get(dev, &addr_high, &addr_low, &len,
						(u32 *)&rd_table_user, &onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_last_rd_table_info_get");
	ZXIC_COMM_PRINT("**********axim last read table info***********\n");
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_addr_high", addr_high);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_addr_low", addr_low);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_len", len);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_user_en",
				 rd_table_user.info_rd_table_user_en);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_epid", rd_table_user.info_rd_table_epid);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_vfunc_num",
				 rd_table_user.info_rd_table_vfunc_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_func_num",
				 rd_table_user.info_rd_table_func_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_vfunc_active",
				 rd_table_user.info_rd_table_vfunc_active);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_table_onload_cnt", onload_cnt);

	rc = dpp_dtb_axi_last_wr_ctrl_info_get(dev, &addr_high, &addr_low, &len,
					       (u32 *)&wr_ctrl_user, &onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_last_wr_ctrl_info_get");
	ZXIC_COMM_PRINT("**********axim last write ctrl info***********\n");
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_addr_high", addr_high);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_addr_low", addr_low);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_len", len);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_user_en",
				 wr_ctrl_user.info_wr_ctrl_user_en);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_epid", wr_ctrl_user.info_wr_ctrl_epid);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_vfunc_num",
				 wr_ctrl_user.info_wr_ctrl_vfunc_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_func_num",
				 wr_ctrl_user.info_wr_ctrl_func_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_vfunc_active",
				 wr_ctrl_user.info_wr_ctrl_vfunc_active);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ctrl_onload_cnt", onload_cnt);

	ZXIC_COMM_PRINT("\n------------------ DTB DUMP TABLE LAST INFO ------------------\n");
	rc = dpp_dtb_axi_last_rd_pd_info_get(dev, &addr_high, &addr_low, &len, (u32 *)&rd_pd_user,
					     &onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_last_rd_pd_info_get");
	ZXIC_COMM_PRINT("**********axim last read pd info***********\n");
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_addr_high", addr_high);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_addr_low", addr_low);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_len", len);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_user_en", rd_pd_user.info_rd_pd_user_en);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_epid", rd_pd_user.info_rd_pd_epid);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_vfunc_num", rd_pd_user.info_rd_pd_vfunc_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_func_num", rd_pd_user.info_rd_pd_func_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_vfunc_active",
				 rd_pd_user.info_rd_pd_vfunc_active);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_rd_pd_onload_cnt", onload_cnt);

	rc = dpp_dtb_axi_last_wr_ddr_info_get(dev, &addr_high, &addr_low, &len, (u32 *)&wr_ddr_user,
					      &onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_last_wr_ddr_info_get");
	ZXIC_COMM_PRINT("**********axim last write ddr info***********\n");
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_addr_high", addr_high);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_addr_low", addr_low);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_len", len);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_user_en", wr_ddr_user.info_wr_ddr_user_en);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_epid", wr_ddr_user.info_wr_ddr_epid);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_vfunc_num",
				 wr_ddr_user.info_wr_ddr_vfunc_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_func_num", wr_ddr_user.info_wr_ddr_func_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_vfunc_active",
				 wr_ddr_user.info_wr_ddr_vfunc_active);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_ddr_onload_cnt", onload_cnt);

	rc = dpp_dtb_axi_last_wr_fin_info_get(dev, &addr_high, &addr_low, &len, (u32 *)&wr_fin_user,
					      &onload_cnt);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_axi_wr_fin_resp_err_cnt_get");
	ZXIC_COMM_PRINT("**********axim last write final info***********\n");
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_addr_high", addr_high);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_addr_low", addr_low);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_len", len);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_user_en", wr_fin_user.info_wr_fin_user_en);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_epid", wr_fin_user.info_wr_fin_epid);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_vfunc_num",
				 wr_fin_user.info_wr_fin_vfunc_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_func_num", wr_fin_user.info_wr_fin_func_num);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_vfunc_active",
				 wr_fin_user.info_wr_fin_vfunc_active);
	ZXIC_COMM_DBGCNT32_PRINT("info_axi_last_wr_fin_onload_cnt", onload_cnt);

	return DPP_OK;
}
u32 diag_dpp_dtb_channels_state_info_prt(struct dpp_dev_t *dev)
{
	u32 rc = 0;

	u32 wr_ctrl_state = 0;
	u32 rd_table_state = 0;
	u32 rd_pd_state = 0;
	u32 wr_ddr_state = 0;
	u32 dump_cmd_state = 0;

	rc = dpp_dtb_state_info_get(dev, &wr_ctrl_state, &rd_table_state, &rd_pd_state,
				    &wr_ddr_state, &dump_cmd_state);
	ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(DEV_ID(dev), rc, "dpp_dtb_stat_info_get");

	ZXIC_COMM_PRINT("\n-------------- DTB CHANNEL STATE INFO  -----------------\n");
	ZXIC_COMM_PRINT("----- REG ------------------- CURRENT  ------- CORRECT -----\n");
	ZXIC_COMM_PRINT("info_wr_ctrl_state           0x%08x       0x00000005\n", wr_ctrl_state);
	ZXIC_COMM_PRINT("info_rd_table_state          0x%08x       0x00080004\n", rd_table_state);
	ZXIC_COMM_PRINT("info_rd_pd_state             0x%08x       0x00020020\n", rd_pd_state);
	ZXIC_COMM_PRINT("info_wr_ddr_state            0x%08x       0x00000001\n", wr_ddr_state);
	ZXIC_COMM_PRINT("info_dump_cmd_state          0x%08x       0x0000002a\n", dump_cmd_state);

	return DPP_OK;
}

#endif
