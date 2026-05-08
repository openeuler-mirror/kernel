/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_rss.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_RSS_H__
#define __SXE2_COM_RSS_H__

#include "sxe2.h"

s32 sxe2_com_rss_key_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_rss_lut_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_rss_func_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			  struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_rss_hf_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_rss_hf_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_com_rss_hf_clear(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			  struct sxe2_drv_cmd_params *cmd_buf);
#endif
