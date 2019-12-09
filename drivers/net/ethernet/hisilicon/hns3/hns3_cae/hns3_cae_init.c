// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>

#include "hnae3.h"
#include "hns3_enet.h"

#ifdef CONFIG_HNS3_TEST
#include "hns3_cae_lib.h"
#endif

static int __init hns3_cae_init(void)
{
#ifdef CONFIG_HNS3_TEST
	int ret;

	pr_err("%s enter!\n", __func__);

	ret = hns3_cae_k_init();
	if (ret)
		return ret;
#endif
	return 0;
}

static void __exit hns3_cae_exit(void)
{
#ifdef CONFIG_HNS3_TEST
	pr_err("%s exit!\n", __func__);
	hns3_cae_k_uninit();
#endif
}

module_init(hns3_cae_init);
module_exit(hns3_cae_exit);
MODULE_LICENSE("GPL");
