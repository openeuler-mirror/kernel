/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : ossl_knl.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef OSSL_KNL_H
#define OSSL_KNL_H

#ifdef __LINUX__
#include "ossl_knl_linux.h"
#endif
#ifdef __WIN__
#include "ossl_knl_win.h"
#ifdef __HIFC__
#include "ossl_knl_fc_win.h"
#else
#include "ossl_knl_nic_win.h"
#endif
#endif

#ifdef __VMWARE__
#include "ossl_knl_vmware.h"
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN    0x4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN    0x1234
#endif

#ifdef BYTE_ORDER
#undef BYTE_ORDER
#endif
/* X86 */
#define BYTE_ORDER    LITTLE_ENDIAN
#define USEC_PER_MSEC	1000L
#define MSEC_PER_SEC	1000L

#ifndef UINT16_MAX
#define UINT16_MAX ((u16)(~((u16)0))) /* 0xFFFF */
#endif /* UINT16_MAX */

#ifndef __LINUX__
#ifndef MAX_ORDER
#define MAX_ORDER 10
#endif
#endif

#endif /* OSSL_KNL_H */
