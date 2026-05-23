/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_lld_inner.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef __HINIC5_LLD_INNER_H
#define __HINIC5_LLD_INNER_H

#include "hinic5_crm.h"
#include "hinic5_lld.h"

/**
 * @brief Get all ULD name array
 *
 * @return Return ULD name array pointer
 */
const char **hinic5_get_uld_names(void);

/**
 * @brief hinic5_get_uld_info_by_type - get udl info by service type
 * @param type: service type
 *
 * @return uld_info
 **/
const struct hinic5_uld_info *hinic5_get_uld_info_by_type(enum hinic5_service_type type);

#endif
