/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_TBM_H
#define XSC_TBM_H

#include "common/xsc_core.h"

#define XSC_LAG_NUM_MAX		0x30

enum {
	XSC_VLAN_MODE_NONE = 0,
	XSC_VLAN_MODE_TRUNK,
	XSC_VLAN_MODE_ACCESS,
	XSC_VLAN_MODE_TUNNEL,
	XSC_VLAN_MODE_NATIVE_TAGGED,
	XSC_VLAN_MODE_NATIVE_UNTAGGED,
};

struct xsc_vlan_config {
	u32	mode;
	u32	pvid;
	u32	proto;
	u32	prio;
	u32	vid_allow_base;
	u32	vid_allow_num;
	u32	smac_filter_en;
};

enum {
	XSC_HASH_FIELD_SEL_SRC_IP	= 1 << 0,
	XSC_HASH_FIELD_SEL_PROTO	= 1 << 1,
	XSC_HASH_FIELD_SEL_DST_IP	= 1 << 2,
	XSC_HASH_FIELD_SEL_SPORT	= 1 << 3,
	XSC_HASH_FIELD_SEL_DPORT	= 1 << 4,
	XSC_HASH_FIELD_SEL_SRC_IPV6	= 1 << 5,
	XSC_HASH_FIELD_SEL_DST_IPV6	= 1 << 6,
	XSC_HASH_FIELD_SEL_SPORT_V6	= 1 << 7,
	XSC_HASH_FIELD_SEL_DPORT_V6	= 1 << 8,
};

#define XSC_HASH_IP		(XSC_HASH_FIELD_SEL_SRC_IP	|\
				XSC_HASH_FIELD_SEL_DST_IP	|\
				XSC_HASH_FIELD_SEL_PROTO)
#define XSC_HASH_IP_PORTS	(XSC_HASH_FIELD_SEL_SRC_IP	|\
				XSC_HASH_FIELD_SEL_DST_IP	|\
				XSC_HASH_FIELD_SEL_SPORT	|\
				XSC_HASH_FIELD_SEL_DPORT	|\
				XSC_HASH_FIELD_SEL_PROTO)
#define XSC_HASH_IP6		(XSC_HASH_FIELD_SEL_SRC_IPV6	|\
				XSC_HASH_FIELD_SEL_DST_IPV6	|\
				XSC_HASH_FIELD_SEL_PROTO)
#define XSC_HASH_IP6_PORTS	(XSC_HASH_FIELD_SEL_SRC_IPV6	|\
				XSC_HASH_FIELD_SEL_DST_IPV6	|\
				XSC_HASH_FIELD_SEL_SPORT_V6	|\
				XSC_HASH_FIELD_SEL_DPORT_V6	|\
				XSC_HASH_FIELD_SEL_PROTO)

int xsc_tbm_vlan_config(struct xsc_core_device *dev,
			struct xsc_logic_port_info *info,
			struct xsc_vlan_config *config);

#endif /* XSC_TBM_H */

