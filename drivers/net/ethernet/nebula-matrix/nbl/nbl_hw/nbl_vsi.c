// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_vsi.h"

static int nbl_res_set_promisc_mode(void *priv, u16 vsi_id, u16 mode)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);
	u16 eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, vsi_id);

	if (pf_id >= NBL_RES_MGT_TO_PF_NUM(res_mgt))
		return -EINVAL;

	phy_ops->set_promisc_mode(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, eth_id, mode);

	return 0;
}

static int nbl_res_set_spoof_check_addr(void *priv, u16 vsi_id, u8 *mac)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->set_spoof_check_addr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vsi_id, mac);
}

static int nbl_res_set_vf_spoof_check(void *priv, u16 vsi_id, int vfid, u8 enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int pfid = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);
	u16 vf_vsi = vfid == -1 ? vsi_id : nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid,
				NBL_VSI_DATA);

	return phy_ops->set_spoof_check_enable(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vf_vsi, enable);
}

static u16 nbl_res_get_vf_function_id(void *priv, u16 vsi_id, int vfid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_sriov_info *sriov_info;
	u16 vf_vsi;
	int pfid = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);

	sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[pfid];

	if (vfid >= sriov_info->active_vf_num)
		return U16_MAX;

	vf_vsi = vfid == -1 ? vsi_id : nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid, NBL_VSI_DATA);

	return nbl_res_vsi_id_to_func_id(res_mgt, vf_vsi);
}

static int nbl_res_vsi_init_chip_module(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt;
	struct nbl_phy_ops *phy_ops;
	int ret = 0;

	if (!res_mgt)
		return -EINVAL;

	queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	ret = phy_ops->init_chip_module(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					res_mgt->resource_info->board_info.eth_speed,
					res_mgt->resource_info->board_info.eth_num);

	return ret;
}

static int nbl_res_vsi_init(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_vsi_mgt *vsi_mgt;
	struct nbl_phy_ops *phy_ops;
	int ret = 0;

	if (!res_mgt)
		return -EINVAL;

	vsi_mgt = NBL_RES_MGT_TO_VSI_MGT(res_mgt);
	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	/* TODO: unnecessary? */

	return ret;
}

static void nbl_res_get_phy_caps(void *priv, u8 eth_id, struct nbl_phy_caps *phy_caps)
{
	/*TODO need to get it through adminq*/
	phy_caps->speed = 0xFF;
	phy_caps->fec_ability = BIT(ETHTOOL_FEC_RS_BIT) | BIT(ETHTOOL_FEC_BASER_BIT);
	phy_caps->pause_param = 0x3;
}

static void nbl_res_get_phy_state(void *priv, u8 eth_id, struct nbl_phy_state *phy_state)
{
	/*TODO need to get it through adminq*/
	phy_state->current_speed = SPEED_10000;
	phy_state->fec_mode = ETHTOOL_FEC_OFF;
	phy_state->fc.tx_pause = 1;
	phy_state->fc.rx_pause = 1;
}

/* NBL_vsi_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_VSI_OPS_TBL								\
do {										\
	NBL_VSI_SET_OPS(init_chip_module, nbl_res_vsi_init_chip_module);	\
	NBL_VSI_SET_OPS(vsi_init, nbl_res_vsi_init);				\
	NBL_VSI_SET_OPS(set_promisc_mode, nbl_res_set_promisc_mode);		\
	NBL_VSI_SET_OPS(set_spoof_check_addr, nbl_res_set_spoof_check_addr);	\
	NBL_VSI_SET_OPS(set_vf_spoof_check, nbl_res_set_vf_spoof_check);	\
	NBL_VSI_SET_OPS(get_phy_caps, nbl_res_get_phy_caps);			\
	NBL_VSI_SET_OPS(get_phy_state, nbl_res_get_phy_state);			\
	NBL_VSI_SET_OPS(get_vf_function_id, nbl_res_get_vf_function_id);	\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_vsi_setup_mgt(struct device *dev, struct nbl_vsi_mgt **vsi_mgt)
{
	*vsi_mgt = devm_kzalloc(dev, sizeof(struct nbl_vsi_mgt), GFP_KERNEL);
	if (!*vsi_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_vsi_remove_mgt(struct device *dev, struct nbl_vsi_mgt **vsi_mgt)
{
	devm_kfree(dev, *vsi_mgt);
	*vsi_mgt = NULL;
}

int nbl_vsi_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_vsi_mgt **vsi_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	vsi_mgt = &NBL_RES_MGT_TO_VSI_MGT(res_mgt);

	return nbl_vsi_setup_mgt(dev, vsi_mgt);
}

void nbl_vsi_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev;
	struct nbl_vsi_mgt **vsi_mgt;

	dev = NBL_RES_MGT_TO_DEV(res_mgt);
	vsi_mgt = &NBL_RES_MGT_TO_VSI_MGT(res_mgt);

	if (!(*vsi_mgt))
		return;

	nbl_vsi_remove_mgt(dev, vsi_mgt);
}

int nbl_vsi_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_VSI_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_VSI_OPS_TBL;
#undef  NBL_VSI_SET_OPS

	return 0;
}

void nbl_vsi_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_VSI_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_VSI_OPS_TBL;
#undef  NBL_VSI_SET_OPS
}
