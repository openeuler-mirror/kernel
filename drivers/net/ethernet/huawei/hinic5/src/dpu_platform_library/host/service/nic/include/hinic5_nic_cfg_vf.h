/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_cfg_vf.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_CFG_VF_H
#define HINIC5_NIC_CFG_VF_H

/* In order to adapt different linux version */
enum {
	HINIC5_IFLA_VF_LINK_STATE_AUTO, /* link state of the uplink */
	HINIC5_IFLA_VF_LINK_STATE_ENABLE, /* link always up */
	HINIC5_IFLA_VF_LINK_STATE_DISABLE, /* link always down */
};

#define NIC_CVLAN_INSERT_ENABLE 0x1
#define NIC_QINQ_INSERT_ENABLE  0x3
#define NIC_VF_TRUST_UNSUPPORT  0xFF

#endif
