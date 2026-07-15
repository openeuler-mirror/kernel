/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_ver_compat.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_COM_VER_COMPAT_H__
#define __SXE2_COM_VER_COMPAT_H__

#include "sxe2_ioctl_chnl.h"

struct sxe2_com_cmd_arg_sz {
	struct sxe2_com_ver_arg_sz *ver_arg_sz;
};

struct sxe2_com_ver_arg_sz {
	u32 ver;
	u32 arg_size;
};

s32 sxe2_com_get_arg_sz(u32 ver, u32 cmd);

#endif
