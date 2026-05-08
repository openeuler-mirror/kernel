/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_com_stats.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_STATS_H__
#define __SXE2_COM_STATS_H__

#include "sxe2vf.h"

s32 sxe2vf_com_vsi_stat_get(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2vf_com_vsi_stat_clear(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf);

#endif
