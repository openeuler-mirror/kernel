/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe_hdc.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE_HDC_H__
#define __SXE_HDC_H__

#ifdef SXE_HOST_DRIVER
#include <linux/types.h>
#endif

#define HDC_CACHE_TOTAL_LEN (16 * 1024)
#define ONE_PACKET_LEN_MAX (1024)
#define DWORD_NUM (256)
#define HDC_TRANS_RETRY_COUNT (3)

enum sxehdcerrnocode {
	PKG_OK = 0,
	PKG_ERR_REQ_LEN,
	PKG_ERR_RESP_LEN,
	PKG_ERR_PKG_SKIP,
	PKG_ERR_NODATA,
	PKG_ERR_PF_LK,
	PKG_ERR_OTHER,
};

union hdcheader {
	struct {
		u8 pid : 4;
		u8 errcode : 4;
		u8 len;
		u16 startpkg : 1;
		u16 endpkg : 1;
		u16 isrd : 1;
		u16 msi : 1;
		u16 totallen : 12;
	} head;
	u32 dw0;
};

#endif

