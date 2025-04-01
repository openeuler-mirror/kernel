/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe_compat.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE_COMPAT_H__
#define __SXE_COMPAT_H__

#include "sxe_compat_gcc.h"
#include <linux/filter.h>
#include <linux/version.h>

#define HAVE_ETHTOOL_COALESCE_EXTACK
#define HAVE_ETHTOOL_EXTENDED_RINGPARAMS

#define HAVE_XDP_SUPPORT
#define HAVE_AF_XDP_ZERO_COPY
#define HAVE_MEM_TYPE_XSK_BUFF_POOL
#define HAVE_XDP_BUFF_DATA_META
#define HAVE_XDP_BUFF_FRAME_SIZE
#define XDP_RXQ_INFO_REQ_API_NEED_3_PARAMS
#define XDP_XMIT_FRAME_FAILED_NEED_FREE
#define HAVE_NETDEV_BPF_XSK_BUFF_POOL

#define HAVE_SKB_XMIT_MORE
#define HAVE_TIMEOUT_TXQUEUE_IDX

#define HAVE_NETDEV_NESTED_PRIV
#define HAVE_NET_PREFETCH_API
#define HAVE_NDO_FDB_ADD_EXTACK
#define HAVE_NDO_BRIDGE_SETLINK_EXTACK
#define HAVE_NDO_SET_VF_LINK_STATE
#define HAVE_NDO_XSK_WAKEUP
#define HAVE_MACVLAN_OFFLOAD_SUPPORT

#define HAVE_PTP_CLOCK_INFO_ADJFINE

#define SXE_LOG_OLD_FS
#define SXE_LOG_FS_NOTIFY

#endif
