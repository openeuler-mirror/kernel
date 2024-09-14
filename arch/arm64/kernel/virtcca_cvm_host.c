// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/virtcca_cvm_host.h>

DEFINE_STATIC_KEY_FALSE(virtcca_cvm_is_enable);

/* please use 'virtcca_cvm_host=1' to enable cvm host feature */
static int __init setup_virtcca_cvm_host(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cvm_guest.\n");
	} else {
		if (val)
			static_branch_enable(&virtcca_cvm_is_enable);
	}
	return ret;
}
early_param("virtcca_cvm_host", setup_virtcca_cvm_host);

bool is_virtcca_cvm_enable(void)
{
	if (static_branch_unlikely(&virtcca_cvm_is_enable))
		return true;
	return false;
}
EXPORT_SYMBOL_GPL(is_virtcca_cvm_enable);
