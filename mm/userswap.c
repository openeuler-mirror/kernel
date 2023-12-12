// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * userswap core file
 */

#include "internal.h"

DEFINE_STATIC_KEY_FALSE(userswap_enabled);

static int __init enable_userswap_setup(char *str)
{
	static_branch_enable(&userswap_enabled);
	return 1;
}
__setup("enable_userswap", enable_userswap_setup);
