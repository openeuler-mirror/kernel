/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_ipsec.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_ADAPTER_IPSEC_H__
#define __SXE2_ADAPTER_IPSEC_H__

#include "sxe2_drv_cmd.h"
#include "sxe2_cmd.h"

s32 sxe2_ipsec_cap_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
		       struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_ipsec_resource_clear(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_ipsec_txsa_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_ipsec_txsa_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_ipsec_rxsa_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf);

s32 sxe2_ipsec_rxsa_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf);

#endif
