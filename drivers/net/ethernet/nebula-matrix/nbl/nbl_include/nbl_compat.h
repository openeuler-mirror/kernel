/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */
#ifndef _NBL_COMPAT_H_
#define _NBL_COMPAT_H_

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ipv6.h>

#ifndef HAVE_DEVLINK_FLASH_UPDATE
#define HAVE_DEVLINK_FLASH_UPDATE
#endif

#endif
