// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2022 Hisilicon Limited.

#include <linux/init.h>
#include <linux/module.h>

#include "core.h"

static int __init roh_init(void)
{
	int ret;

	ret = roh_core_init();
	if (ret) {
		pr_err("roh_core: roh core init failed, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit roh_cleanup(void)
{
	roh_core_cleanup();
}

module_init(roh_init);
module_exit(roh_cleanup);
