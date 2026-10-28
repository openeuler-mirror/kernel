// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_pf_vsi_vlan_ops.h"
#include "nse_vf_vsi_vlan_ops.h"
#include "nse_lib.h"
#include "nse.h"

static int
op_unsupported_vlan_arg(struct nse_vsi * __always_unused vsi,
			struct nse_vlan * __always_unused vlan)
{
	return -EOPNOTSUPP;
}

static int
op_unsupported_tpid_arg(struct nse_vsi *__always_unused vsi,
			u16 __always_unused tpid)
{
	return -EOPNOTSUPP;
}

static int op_unsupported(struct nse_vsi *__always_unused vsi)
{
	return -EOPNOTSUPP;
}

/* If any new ops are added to the VSI VLAN ops interface then an unsupported
 * implementation should be set here.
 */
static struct nse_vsi_vlan_ops ops_unsupported = {
	.add_vlan = op_unsupported_vlan_arg,
	.del_vlan = op_unsupported_vlan_arg,
	.ena_stripping = op_unsupported_tpid_arg,
	.dis_stripping = op_unsupported,
	.ena_insertion = op_unsupported_tpid_arg,
	.dis_insertion = op_unsupported,
	.ena_rx_filtering = op_unsupported,
	.dis_rx_filtering = op_unsupported,
	.ena_tx_filtering = op_unsupported,
	.dis_tx_filtering = op_unsupported,
	.set_port_vlan = op_unsupported_vlan_arg,
};

/**
 * nse_vsi_init_unsupported_vlan_ops - init all VSI VLAN ops to unsupported
 * @vsi: VSI to initialize VSI VLAN ops to unsupported for
 *
 * By default all inner and outer VSI VLAN ops return -EOPNOTSUPP. This was done
 * as oppsed to leaving the ops null to prevent unexpected crashes. Instead if
 * an unsupported VSI VLAN op is called it will just return -EOPNOTSUPP.
 *
 */
static void nse_vsi_init_unsupported_vlan_ops(struct nse_vsi *vsi)
{
	vsi->outer_vlan_ops = ops_unsupported;
	vsi->inner_vlan_ops = ops_unsupported;
}

/**
 * nse_vsi_init_vlan_ops - initialize type specific VSI VLAN ops
 * @vsi: VSI to initialize ops for
 *
 * If any VSI types are added and/or require different ops than the PF or VF VSI
 * then they will have to add a case here to handle that. Also, VSI type
 * specific files should be added in the same manner that was done for PF VSI.
 */
void nse_vsi_init_vlan_ops(struct nse_vsi *vsi)
{
	/* Initialize all VSI types to have unsupported VSI VLAN ops */
	nse_vsi_init_unsupported_vlan_ops(vsi);

	switch (vsi->type) {
	case NSE_VSI_PF:
	case NSE_VSI_SWITCHDEV_CTRL:
		nse_pf_vsi_init_vlan_ops(vsi);
		break;
	case NSE_VSI_ADI:
	case NSE_VSI_VF:
		nse_vf_vsi_init_vlan_ops(vsi);
		break;
	default:
		dev_dbg(nse_pf_to_dev(vsi->back), "%s does not support VLAN operations\n",
			nse_vsi_type_str(vsi->type));
		break;
	}
}

struct nse_vsi_vlan_ops *nse_get_compat_vsi_vlan_ops(struct nse_vsi *vsi)
{
	return &vsi->outer_vlan_ops;
}

