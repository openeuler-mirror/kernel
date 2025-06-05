/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ESWITCH_H
#define XSC_ESWITCH_H

enum {
	XSC_ESWITCH_NONE,
	XSC_ESWITCH_LEGACY,
	XSC_ESWITCH_OFFLOADS
};

enum {
	REP_ETH,
	REP_IB,
	NUM_REP_TYPES,
};

enum {
	REP_UNREGISTERED,
	REP_REGISTERED,
	REP_LOADED,
};

enum xsc_switchdev_event {
	XSC_SWITCHDEV_EVENT_PAIR,
	XSC_SWITCHDEV_EVENT_UNPAIR,
};

enum {
	SET_VLAN_STRIP = BIT(0),
	SET_VLAN_INSERT = BIT(1),
	CLR_VLAN_STRIP = BIT(2),
	CLR_VLAN_INSERT = BIT(3),
};

#endif /* XSC_ESWITCH_H */

