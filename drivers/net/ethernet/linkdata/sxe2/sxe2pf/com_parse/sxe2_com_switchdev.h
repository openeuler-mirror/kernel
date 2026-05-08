/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_switchdev.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_SWITCHDEV_H__
#define __SXE2_COM_SWITCHDEV_H__

#include "sxe2.h"
s32 sxe2_com_switch_uplink(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			   struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_switch_repr(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_switch_mode(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_switch_cp_vsi(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			   struct sxe2_drv_cmd_params *cmd_buf);

#endif
