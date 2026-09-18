/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hiudk_lld.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : Intelligent Network Unified Driver low-level driver entry.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [UDK]" fmt

#include <linux/module.h>
#include <linux/moduleparam.h>

#include "hinic5_crm.h"

#define HIUDK_DRV_DESC "Intelligent Network Unified Driver"

static __init int hiudk5_init(void)
{
	pr_info("%s - version %s\n", HIUDK_DRV_DESC, HINIC5_DRV_VERSION);

	return 0;
}

static __exit void hiudk5_exit(void)
{
	return;
}

MODULE_LICENSE("GPL");
module_init(hiudk5_init);
module_exit(hiudk5_exit);
