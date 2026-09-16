// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_vsi_vlan_ops.h"
#include "nse_vsi_vlan_lib.h"
#include "nse.h"
#include "nse_pf_vsi_vlan_ops.h"

void nse_pf_vsi_init_vlan_ops(struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops;

	/* PF VSI always use outer_vlan_ops */
	vlan_ops = &vsi->outer_vlan_ops;

	vlan_ops->add_vlan = nse_vsi_add_vlan;
	vlan_ops->del_vlan = nse_vsi_del_vlan;
	vlan_ops->ena_stripping = nse_vsi_ena_outer_stripping;
	vlan_ops->dis_stripping = nse_vsi_dis_outer_stripping;
	vlan_ops->ena_insertion = nse_vsi_ena_outer_insertion;
	vlan_ops->dis_insertion = nse_vsi_dis_outer_insertion;
	vlan_ops->ena_rx_filtering = nse_vsi_ena_rx_vlan_filtering;
	vlan_ops->dis_rx_filtering = nse_vsi_dis_rx_vlan_filtering;
}

