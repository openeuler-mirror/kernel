// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/module.h>

#include "hns_roce_device.h"
#include "hns_roce_test.h"

unsigned int int_mr_access = 7;
module_param(int_mr_access, uint, 0644);
MODULE_PARM_DESC(int_mr_access, "Mr access for ft test");

void test_set_mr_access(struct hns_roce_mr *mr)
{
	if (mr->key > 0)
		mr->access = int_mr_access;
}

