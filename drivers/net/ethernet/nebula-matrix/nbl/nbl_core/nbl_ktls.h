/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 nebula-matrix Limited.
 * Author: Rocky Xie <rocky.xie@nebula-matrix.com>
 */

#ifndef _NBL_KTLS_H
#define _NBL_KTLS_H

#include "nbl_service.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/if_vlan.h>
#if IS_ENABLED(CONFIG_TLS_DEVICE)
#include <net/tls.h>

#define NBL_KTLS_AES_GCM_128			0
#define NBL_KTLS_AES_GCM_256			1
#define NBL_KTLS_SM4_GCM			2
#define NBL_KTLS_FLOW_TYPE_OFF			0
#define NBL_KTLS_FLOW_SIP_OFF			1
#define NBL_KTLS_FLOW_DIP_OFF			5
#define NBL_KTLS_FLOW_DPORT_OFF			9
#define NBL_KTLS_FLOW_SPORT_OFF			10
#define NBL_KTLS_FLOW_IP_LEN			4
#define NBL_KTLS_FLOW_TOTAL_LEN			12

#endif /* end ifdef CONFIG_TLS_DEVICE*/

void nbl_serv_setup_ktls_ops(struct nbl_service_ops *serv_ops_tbl);

#endif /*_NBL_KTLS_H*/
