/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_RESET_H__
#define __UNIC_RESET_H__

#include <ub/ubase/ubase_comm_dev.h>

int unic_reset_handler(struct auxiliary_device *adev, enum ubase_reset_stage stage);

#endif /* __UNIC_RESET_H__ */
