/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ntuple.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NTUPLE_H
#define HINIC5_NTUPLE_H

#include <linux/types.h>
#include <linux/ethtool.h>

#define MAX_NUM_OF_ETHTOOL_NTUPLE_RULES BIT(10)
struct hinic5_ethtool_rx_flow_rule {
	struct list_head            list;
	struct ethtool_rx_flow_spec flow_spec;
};

#define UINT1_MAX          0x1
#define UINT2_MAX          0x3
#define UINT3_MAX          0x7
#define UINT4_MAX          0xf
#define UINT5_WIDTH        0x5
#define UINT5_MAX          0x1f
#define UINT15_MAX         0x7fff

#endif
