/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dcb_nl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DCB_NL_H__
#define __SXE2_DCB_NL_H__

#include "sxe2_dcb.h"

void sxe2_dcbnl_set_all(struct sxe2_vsi *vsi);

void sxe2_dcbnl_setup(struct sxe2_vsi *vsi);

void sxe2_dcbnl_flush_apps(struct sxe2_adapter *adapter,
			   struct sxe2_dcbx_cfg *old_cfg,
			   struct sxe2_dcbx_cfg *new_cfg);

#endif

