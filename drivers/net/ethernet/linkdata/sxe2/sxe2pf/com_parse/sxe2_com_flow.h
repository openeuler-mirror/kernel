/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_flow.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_FLOW_H__
#define __SXE2_COM_FLOW_H__

s32 sxe2_com_flow_filter_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			     struct sxe2_drv_cmd_params *cmd_buf);
s32 sxe2_com_flow_filter_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			     struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_flow_fnav_stat_alloc(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				  struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_flow_fnav_stat_free(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				 struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_flow_fnav_stat_query(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				  struct sxe2_drv_cmd_params *cmd_buf);

#endif
