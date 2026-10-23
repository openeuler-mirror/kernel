// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_vsi.h"

static int nbl_res_set_promisc_mode(void *priv, struct nbl_ch_prm_set_promisc_mode *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, param->vsi_id);
	u16 eth_id = nbl_res_vsi_id_to_eth_id(res_mgt, param->vsi_id);

	if (pf_id >= NBL_RES_MGT_TO_PF_NUM(res_mgt))
		return -EINVAL;

	phy_ops->set_promisc_mode(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->vsi_id, eth_id,
				  param->mode);

	return 0;
}

static int nbl_res_set_spoof_check_addr(void *priv,
					struct nbl_ch_prm_set_spoof_check_addr *param)
{
	u16 func_id;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->vsi_id);
	/* if pf has cfg vf-mac, and the vf has active. it can change spoof mac. */
	if (!is_zero_ether_addr(vsi_info->mac_info[func_id].mac) &&
	    nbl_res_check_func_active_by_queue(res_mgt, func_id)) {
		return 0;
	}

	return phy_ops->set_spoof_check_addr(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->vsi_id,
					     param->mac);
}

static int nbl_res_set_vf_spoof_check(void *priv,
				      struct nbl_ch_prm_set_vf_spoof_check *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->vsi_id);
	u16 pfid = 0;
	u16 vf_vsi_id = 0;

	/* when ip link set eth0 vf <num> spoofchk */
	if (func_id < NBL_MAX_PF) {
		pfid = nbl_res_vsi_id_to_pf_id(res_mgt, param->vsi_id);
		vf_vsi_id = nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, param->vf_id, NBL_VSI_DATA);
	} else {
		vf_vsi_id = param->vsi_id;
	}

	return phy_ops->set_spoof_check_enable(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), vf_vsi_id,
					       param->enable);
}

static u16 nbl_res_get_vf_function_id(void *priv, u16 vsi_id, int vfid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 vf_vsi;
	int pfid = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);

	vf_vsi = vfid == -1 ? vsi_id : nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid, NBL_VSI_DATA);

	return nbl_res_vsi_id_to_func_id(res_mgt, vf_vsi);
}

static u16 nbl_res_get_vf_vsi_id(void *priv, u16 vsi_id, int vfid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 vf_vsi;
	int pfid = nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id);

	vf_vsi = vfid == -1 ? vsi_id : nbl_res_pfvfid_to_vsi_id(res_mgt, pfid, vfid, NBL_VSI_DATA);
	return vf_vsi;
}

static void nbl_res_vsi_set_driver_status(void *priv, bool active)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops;

	phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	NBL_OPS_CALL(phy_ops->set_driver_status, (NBL_RES_MGT_TO_PHY_PRIV(res_mgt), active));
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

static int nbl_res_init_vsi(void *priv)
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

static int nbl_res_get_phy_caps(void *priv, u8 *eth_id, struct nbl_phy_caps *phy_caps)
{
	/*TODO need to get it through adminq*/
	phy_caps->speed = 0xFF;
	phy_caps->fec_ability = BIT(ETHTOOL_FEC_RS_BIT) | BIT(ETHTOOL_FEC_BASER_BIT);
	phy_caps->pause_param = 0x3;

	return 0;
}

static void nbl_res_register_func_mac(void *priv, u8 *mac, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);

	if (func_id >= NBL_MAX_FUNC)
		return;

	ether_addr_copy(vsi_info->mac_info[func_id].mac, mac);
}

static int nbl_res_register_func_link_forced(void *priv, u16 func_id, u8 link_forced,
					     bool *should_notify)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);

	if (func_id >= NBL_MAX_FUNC)
		return -EINVAL;

	resource_info->link_forced_info[func_id] = link_forced;
	*should_notify = test_bit(func_id, resource_info->func_bitmap);

	return 0;
}

static int nbl_res_get_link_forced(void *priv, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, vsi_id);

	return resource_info->link_forced_info[func_id];
}

static int nbl_res_register_func_trust(void *priv, u16 func_id,
				       bool trusted, bool *should_notify)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);

	if (func_id >= NBL_MAX_FUNC)
		return -EINVAL;

	vsi_info->mac_info[func_id].trusted = trusted;
	*should_notify = test_bit(func_id, resource_info->func_bitmap);

	return 0;
}

static int nbl_res_register_func_vlan(void *priv, u16 func_id,
				      u16 vlan_tci, u16 vlan_proto, bool *should_notify)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);

	if (func_id >= NBL_MAX_FUNC)
		return -EINVAL;

	vsi_info->mac_info[func_id].vlan_proto = vlan_proto;
	vsi_info->mac_info[func_id].vlan_tci = vlan_tci;
	*should_notify = test_bit(func_id, resource_info->func_bitmap);

	return 0;
}

static int nbl_res_register_rate(void *priv, u16 func_id, int rate)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);

	if (func_id >= NBL_MAX_FUNC)
		return -EINVAL;

	vsi_info->mac_info[func_id].rate = rate;

	return 0;
}

/* NBL_vsi_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_VSI_OPS_TBL								\
do {										\
	NBL_VSI_SET_OPS(init_chip_module, nbl_res_vsi_init_chip_module);	\
	NBL_VSI_SET_OPS(set_driver_status, nbl_res_vsi_set_driver_status);	\
	NBL_VSI_SET_OPS(init_vsi, nbl_res_init_vsi);				\
	NBL_VSI_SET_OPS(set_promisc_mode, nbl_res_set_promisc_mode);		\
	NBL_VSI_SET_OPS(set_spoof_check_addr, nbl_res_set_spoof_check_addr);	\
	NBL_VSI_SET_OPS(set_vf_spoof_check, nbl_res_set_vf_spoof_check);	\
	NBL_VSI_SET_OPS(get_phy_caps, nbl_res_get_phy_caps);			\
	NBL_VSI_SET_OPS(get_vf_function_id, nbl_res_get_vf_function_id);	\
	NBL_VSI_SET_OPS(get_vf_vsi_id, nbl_res_get_vf_vsi_id);			\
	NBL_VSI_SET_OPS(register_func_mac, nbl_res_register_func_mac);		\
	NBL_VSI_SET_OPS(register_func_link_forced, nbl_res_register_func_link_forced);	\
	NBL_VSI_SET_OPS(register_func_vlan, nbl_res_register_func_vlan);	\
	NBL_VSI_SET_OPS(get_link_forced, nbl_res_get_link_forced);		\
	NBL_VSI_SET_OPS(register_func_rate, nbl_res_register_rate);		\
	NBL_VSI_SET_OPS(register_func_trust, nbl_res_register_func_trust);	\
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
