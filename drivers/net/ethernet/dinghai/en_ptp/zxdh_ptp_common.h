/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZX_PTP_COMMON_H
#define _ZX_PTP_COMMON_H

#include <linux/dinghai/log.h>

#define PTP_LOG_ERR(fmt, arg...) DH_LOG_ERR(MODULE_PTP, fmt, ##arg)
#define PTP_LOG_INFO(fmt, arg...) DH_LOG_INFO(MODULE_PTP, fmt, ##arg)
#define PTP_LOG_DEBUG(fmt, arg...) DH_LOG_DEBUG(MODULE_PTP, fmt, ##arg)
#define PTP_LOG_WARN(fmt, arg...) DH_LOG_WARNING(MODULE_PTP, fmt, ##arg)

#endif
