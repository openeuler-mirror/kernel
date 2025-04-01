/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe_ioctl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef _SXE_IOCTL_H_
#define _SXE_IOCTL_H_

#ifdef SXE_HOST_DRIVER
#include <linux/types.h>
#endif

struct sxeioctlsynccmd {
	u64 traceid;
	void *indata;
	u32 inlen;
	void *outdata;
	u32 outlen;
};

#define SXE_CMD_IOCTL_SYNC_CMD _IOWR('M', 1, struct sxeioctlsynccmd)

#endif
