/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 */

#ifndef _HISI_INTERNAL_H
#define _HISI_INTERNAL_H

enum {
	STATE_ONLINE,
	STATE_OFFLINE,
};

static const char *const online_type_to_str[] = {
	[STATE_ONLINE] = "online",
	[STATE_OFFLINE] = "offline",
};

static inline int online_type_from_str(const char *str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(online_type_to_str); i++) {
		if (sysfs_streq(str, online_type_to_str[i]))
			return i;
	}

	return -EINVAL;
}

#endif
