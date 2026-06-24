/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_POSTPROCESS_H__
#define __VS_DC_POSTPROCESS_H__

#include "vs_egt_drm.h"
#include "vs_type.h"
#include "vs_dc_property.h"

bool vs_egt_dc_register_postprocess_states(struct vs_dc_property_state_group *states,
					   const struct vs_display_info *display_info);

#endif
