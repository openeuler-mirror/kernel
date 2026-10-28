// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_vsi_vlan_ops.h"
#include "nse_vsi_vlan_lib.h"
#include "nse.h"
#include "nse_vf_vsi_vlan_ops.h"
#include "nse_sriov.h"
#include "nse_lib.h"

static int
noop_vlan_arg(struct nse_vsi __always_unused *vsi,
	      struct nse_vlan __always_unused *vlan)
{
	return 0;
}

static int
noop_vlan(struct nse_vsi __always_unused *vsi)
{
	return 0;
}

/**
 * nse_vf_vsi_init_vlan_ops - Initialize default VSI VLAN ops for VF VSI
 * @vsi: VF's VSI being configured
 *
 * If Double VLAN Mode (DVM) is enabled, assume that the VF supports the new
 * VIRTCHNL_VF_VLAN_OFFLOAD_V2 capability and set up the VLAN ops accordingly.
 * If SVM is enabled maintain the same level of VLAN support previous to
 * VIRTCHNL_VF_VLAN_OFFLOAD_V2.
 */
void nse_vf_vsi_init_vlan_ops(struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops;
	struct nse_pf *pf = vsi->back;
	struct nse_vf *vf = vsi->vf;

	if (WARN_ON(!vf))
		return;

	vlan_ops = &vsi->outer_vlan_ops;

	/* outer VLAN ops regardless of port VLAN config */
	vlan_ops->add_vlan = nse_vsi_add_vlan;
	vlan_ops->ena_tx_filtering = nse_vsi_ena_tx_vlan_filtering;
	vlan_ops->dis_tx_filtering = nse_vsi_dis_tx_vlan_filtering;

	if (nse_vf_is_port_vlan_ena(vf)) {
		/* setup outer VLAN ops */
		vlan_ops->set_port_vlan = nse_vsi_set_outer_port_vlan;
		/* all Rx traffic should be in the domain of the
		 * assigned port VLAN, so prevent disabling Rx VLAN
		 * filtering
		 */
		vlan_ops->dis_rx_filtering = noop_vlan;
		vlan_ops->ena_rx_filtering =
			nse_vsi_ena_rx_vlan_filtering;

		/* setup inner VLAN ops */
		vlan_ops = &vsi->inner_vlan_ops;
		vlan_ops->add_vlan = noop_vlan_arg;
		vlan_ops->del_vlan = noop_vlan_arg;
		vlan_ops->ena_stripping = nse_vsi_ena_inner_stripping;
		vlan_ops->dis_stripping = nse_vsi_dis_inner_stripping;
		vlan_ops->ena_insertion = nse_vsi_ena_inner_insertion;
		vlan_ops->dis_insertion = nse_vsi_dis_inner_insertion;
	} else {
		vlan_ops->dis_rx_filtering =
			nse_vsi_dis_rx_vlan_filtering;

		if (!test_bit(NSE_FLAG_VF_VLAN_PRUNING, pf->flags))
			vlan_ops->ena_rx_filtering = noop_vlan;
		else
			vlan_ops->ena_rx_filtering =
				nse_vsi_ena_rx_vlan_filtering;

		vlan_ops->del_vlan = nse_vsi_del_vlan;
		vlan_ops->ena_stripping = nse_vsi_ena_outer_stripping;
		vlan_ops->dis_stripping = nse_vsi_dis_outer_stripping;
		vlan_ops->ena_insertion = nse_vsi_ena_outer_insertion;
		vlan_ops->dis_insertion = nse_vsi_dis_outer_insertion;

		/* setup inner VLAN ops */
		vlan_ops = &vsi->inner_vlan_ops;

		vlan_ops->ena_stripping = nse_vsi_ena_inner_stripping;
		vlan_ops->dis_stripping = nse_vsi_dis_inner_stripping;
		vlan_ops->ena_insertion = nse_vsi_ena_inner_insertion;
		vlan_ops->dis_insertion = nse_vsi_dis_inner_insertion;
	}
}

