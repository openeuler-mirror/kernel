/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_lld_private.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_LLD_PRIVATE_H
#define HINIC5_LLD_PRIVATE_H
#include <linux/types.h>

#include "hinic5_dev_mgmt.h"

/* Module parameters */
bool hinic5_is_disable_vf_load(void);

bool hinic5_get_vf_service_load(struct hinic5_adev *adev, u16 service);
void wait_sriov_cfg_complete(struct hinic5_adev *adev);
void hinic5_func_deinit(struct hinic5_adev *adev);
int hinic5_func_init(struct hinic5_adev *adev);
int probe_func_param_init(struct hinic5_adev *adev);
#endif
