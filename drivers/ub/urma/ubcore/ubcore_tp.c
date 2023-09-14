// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore tp implementation
 * Author: Yan Fangfang
 * Create: 2022-08-25
 * Note:
 * History: 2022-08-25: Create file
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <urma/ubcore_api.h>
#include <urma/ubcore_uapi.h>

#define UB_PROTOCOL_HEAD_BYTES 313
#define UB_MTU_BITS_BASE_SHIFT 7

static inline int ubcore_mtu_enum_to_int(enum ubcore_mtu mtu)
{
	return 1 << ((int)mtu + UB_MTU_BITS_BASE_SHIFT);
}

enum ubcore_mtu ubcore_get_mtu(int mtu)
{
	mtu = mtu - UB_PROTOCOL_HEAD_BYTES;

	if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_2048))
		return UBCORE_MTU_2048;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_512))
		return UBCORE_MTU_512;
	else if (mtu >= ubcore_mtu_enum_to_int(UBCORE_MTU_256))
		return UBCORE_MTU_256;
	else
		return 0;
}
EXPORT_SYMBOL(ubcore_get_mtu);

struct ubcore_tp *ubcore_create_vtp(struct ubcore_device *dev, const union ubcore_eid *remote_eid,
				    enum ubcore_transport_mode trans_mode,
				    struct ubcore_udata *udata)
{
	return NULL;
}
EXPORT_SYMBOL(ubcore_create_vtp);

int ubcore_destroy_vtp(struct ubcore_tp *vtp)
{
	return -1;
}
EXPORT_SYMBOL(ubcore_destroy_vtp);
