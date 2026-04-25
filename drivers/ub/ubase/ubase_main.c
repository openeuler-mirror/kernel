// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/module.h>

#include "debugfs/ubase_debugfs.h"

static int __init ubase_init(void)
{
	int ret;

	ret = ubase_dbg_register_debugfs();
	if (ret)
		return ret;

	ret = ubase_ubus_register_driver();
	if (ret)
		ubase_dbg_unregister_debugfs();

	return ret;
}

static void __exit ubase_exit(void)
{
	ubase_ubus_unregister_driver();
	ubase_dbg_unregister_debugfs();
}

module_init(ubase_init);
module_exit(ubase_exit);

MODULE_DESCRIPTION("UBASE: Hisilicon Network Driver");
MODULE_IMPORT_NS(UB_UBFI);
MODULE_IMPORT_NS(UB_UBUS);
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: ummu");
MODULE_VERSION(UBASE_MOD_VERSION);
