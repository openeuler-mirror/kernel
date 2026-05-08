/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_vlan.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_VLAN_H__
#define __SXE2_COM_VLAN_H__

#include "sxe2.h"

s32 sxe2_com_vlan_offload_cfg(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_port_vlan_cfg(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			   struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_vlan_cfg_query(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_user_vlan_destroy(struct sxe2_vsi *vsi);

s32 sxe2_user_vlan_offload_strip_paramcheck(struct sxe2_user_vlan_offload_cfg *vlan_cfg,
					    bool port_vlan_exist);

#endif
