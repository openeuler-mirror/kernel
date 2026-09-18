/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hisdk5_lld.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   :
 */

#ifndef HISDK5_LLD_H
#define HISDK5_LLD_H

#include "hinic5_crm.h"
#include "hinic5_lld.h"

#include "hinic5_dev_mgmt.h"

/**
 * @brief Get the full ULD name array
 *
 * @return Returns a pointer to the ULD name array
 */
const char **hinic5_get_uld_names(void);

/**
 * @brief hinic5_get_uld_info_by_type - get udl info by service type
 * @param type: service type
 *
 * @return uld_info
 **/
const struct hinic5_uld_info *hinic5_get_uld_info_by_type(enum hinic5_service_type type);

void send_uld_dev_event(struct hinic5_adev *adev,
			struct hinic5_event_info *event);

#endif