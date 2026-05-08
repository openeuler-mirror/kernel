/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_msglevel.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_MSGLEVEL_H__
#define __SXE2_MSGLEVEL_H__

#define SXE2_DFLT_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)
#define SXE2_DBG_USER	  BIT_ULL(31)

struct sxe2_msglevel_context {
	u32 msg_enable;
	u64 debug_mask;
};

#endif
