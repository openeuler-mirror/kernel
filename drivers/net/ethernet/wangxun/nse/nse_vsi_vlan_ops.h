/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VSI_VLAN_OPS_H_
#define _NSE_VSI_VLAN_OPS_H_

#include "nse_type.h"
#include "nse_vsi_vlan_lib.h"

struct nse_vsi;

struct nse_vsi_vlan_ops {
	int (*add_vlan)(struct nse_vsi *vsi, struct nse_vlan *vlan);
	int (*del_vlan)(struct nse_vsi *vsi, struct nse_vlan *vlan);
	int (*ena_stripping)(struct nse_vsi *vsi, const u16 tpid);
	int (*dis_stripping)(struct nse_vsi *vsi);
	int (*ena_insertion)(struct nse_vsi *vsi, const u16 tpid);
	int (*dis_insertion)(struct nse_vsi *vsi);
	int (*ena_rx_filtering)(struct nse_vsi *vsi);
	int (*dis_rx_filtering)(struct nse_vsi *vsi);
	int (*ena_tx_filtering)(struct nse_vsi *vsi);
	int (*dis_tx_filtering)(struct nse_vsi *vsi);
	int (*set_port_vlan)(struct nse_vsi *vsi, struct nse_vlan *vlan);
};

void nse_vsi_init_vlan_ops(struct nse_vsi *vsi);
struct nse_vsi_vlan_ops *nse_get_compat_vsi_vlan_ops(struct nse_vsi *vsi);

#endif /* _NSE_VSI_VLAN_OPS_H_ */

