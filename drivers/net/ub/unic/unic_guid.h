/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_GUID_H__
#define __UNIC_GUID_H__

#if IS_ENABLED(CONFIG_UB_UNIC_UBL)
#include <net/ub/ubl.h>
#endif

#include "unic_dev.h"

#ifndef UBL_ALEN
#define UBL_ALEN 16
#endif

int unic_init_guid(struct unic_dev *unic_dev);

#endif /* __UNIC_GUID_H__ */
