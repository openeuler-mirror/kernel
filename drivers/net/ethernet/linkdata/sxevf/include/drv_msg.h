/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: drv_msg.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __DRV_MSG_H__
#define __DRV_MSG_H__

#ifdef SXE_HOST_DRIVER
#include <linux/types.h>
#endif

#define SXE_VERSION_LEN 32

struct sxe_version_resp {
	u8 fw_version[SXE_VERSION_LEN];
};

#endif
