/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VSI_VLAN_LIB_H_
#define _NSE_VSI_VLAN_LIB_H_

#include <linux/types.h>
#include "nse_vlan.h"

struct nse_vsi;

int nse_vsi_add_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan);
int nse_vsi_del_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan);

int nse_vsi_ena_inner_stripping(struct nse_vsi *vsi, u16 tpid);
int nse_vsi_dis_inner_stripping(struct nse_vsi *vsi);
int nse_vsi_ena_inner_insertion(struct nse_vsi *vsi, u16 tpid);
int nse_vsi_dis_inner_insertion(struct nse_vsi *vsi);
int nse_vsi_set_inner_port_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan);

int nse_vsi_ena_rx_vlan_filtering(struct nse_vsi *vsi);
int nse_vsi_dis_rx_vlan_filtering(struct nse_vsi *vsi);
int nse_vsi_ena_tx_vlan_filtering(struct nse_vsi *vsi);
int nse_vsi_dis_tx_vlan_filtering(struct nse_vsi *vsi);

int nse_vsi_ena_outer_stripping(struct nse_vsi *vsi, u16 tpid);
int nse_vsi_dis_outer_stripping(struct nse_vsi *vsi);
int nse_vsi_ena_outer_insertion(struct nse_vsi *vsi, u16 tpid);
int nse_vsi_dis_outer_insertion(struct nse_vsi *vsi);
int nse_vsi_set_outer_port_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan);
int __nse_vsi_set_outer_port_vlan(struct nse_vsi *vsi, u16 vlan_info, u16 tpid);

#endif /* _NSE_VSI_VLAN_LIB_H_ */
