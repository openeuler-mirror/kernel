/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_com_l2_filter.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2VF_COM_L2_FILTER_H__
#define __SXE2VF_COM_L2_FILTER_H__

#include "sxe2vf.h"
s32 sxe2vf_com_switch_filter_uc(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
				struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2vf_com_switch_filter_mc(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
				struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2vf_com_switch_filter_vlan_control(struct sxe2vf_adapter *adapter,
					  struct sxe2_obj *obj,
					  struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2vf_com_switch_filter_vlan_rule(struct sxe2vf_adapter *adapter,
				       struct sxe2_obj *obj,
				       struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2vf_com_switch_filter_promisc(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
				     struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2vf_com_switch_filter_allmulti(struct sxe2vf_adapter *adapter,
				      struct sxe2_obj *obj,
				      struct sxe2_drv_cmd_params *cmd_buf);

#endif
