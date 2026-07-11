// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <linux/netdevice.h>
#include <linux/kref.h>
#include <linux/dinghai/lag.h>
#include <net/bonding.h>
#include "zxdh_lag.h"
#include "rdma_ops.h"
#include <linux/ethtool.h>
#include <linux/mutex.h>

static LIST_HEAD(zxdh_bond_list);
static LIST_HEAD(zxdh_aux_netdev_list);
static DEFINE_IDA(zxdh_bond_group_ids);
static struct mutex mlock;
#define RDMA_PHY_PORT_0_bit 17
#define RDMA_PHY_PORT_1_bit 16

static s32 zxdh_changeupper_event_handler(struct zxdh_bond_device *bond_dev,
					  struct event_node *node);

void zxdh_lag_lock_init(void)
{
	mutex_init(&mlock);
	init_bond_dev_hooks();
}

void zxdh_lag_lock_deinit(void)
{
	destroy_bond_dev_hooks();
	mutex_destroy(&mlock);
}

static bool netif_is_zxdh_aux(struct net_device *dev)
{
	return dev && (dev->netdev_ops == &zxdh_netdev_ops);
}

static u16 zxdh_convert_pcie_id_2_vfid(u16 pcie_id)
{
	u16 pf_id = 0;
	u16 ep_id = 0;

	pf_id = (pcie_id >> 8) & 0x7;
	ep_id = (pcie_id >> 12) & 0x7;

	return ZXDH_PF_VFID(ep_id, pf_id);
}

static u16 zxdh_covert_netdev_2_vfid(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;

	return zxdh_convert_pcie_id_2_vfid(en_dev->pcie_id);
}

static u32 zxdh_covert_hash_type(u32 hash_type)
{
	u32 np_hash_type = 0;

	switch (hash_type) {
	case NETDEV_LAG_HASH_L2: {
		np_hash_type = ZXDH_NETDEV_LAG_HASH_L2;
		break;
	}
	case NETDEV_LAG_HASH_L23: {
		np_hash_type = ZXDH_NETDEV_LAG_HASH_L23;
		break;
	}
	case NETDEV_LAG_HASH_L34: {
		np_hash_type = ZXDH_NETDEV_LAG_HASH_L34;
		break;
	}
	default: {
		np_hash_type = ZXDH_NETDEV_LAG_HASH_NONE;
		break;
	}
	}

	return np_hash_type;
}

static u32 zxdh_covert_bond_tx_type(u32 tx_type)
{
	u32 np_tx_type = 0;

	switch (tx_type) {
	case NETDEV_LAG_TX_TYPE_ACTIVEBACKUP: {
		np_tx_type = ZXDH_NETDEV_LAG_TX_TYPE_ACTIVEBACKUP;
		break;
	}
	case NETDEV_LAG_TX_TYPE_HASH: {
		np_tx_type = ZXDH_NETDEV_LAG_TX_TYPE_HASH;
		break;
	}
	default: {
		np_tx_type = ZXDH_NETDEV_LAG_TX_TYPE_UNKNOWN;
		break;
	}
	}

	return np_tx_type;
}

static s32 zxdh_hardware_bond_link(struct zxdh_bond_device *bond_dev,
				   struct netdev_lag_upper_info *lag_upper_info)
{
	struct zxdh_bond_group *group = bond_dev->group;

	if (!group) {
		LOG_ERR("%s fail\n", __func__);
		return -1;
	}

	group->lag_tx_type = (u8)zxdh_covert_bond_tx_type((u32)lag_upper_info->tx_type);
	group->hash_policy = (u8)zxdh_covert_hash_type((u32)lag_upper_info->hash_type);

	return 0;
}

static struct zxdh_bond_group *zxdh_find_hardware_bond_group(struct net_device *upper)
{
	struct zxdh_bond_group *tmp_group, *bond_group = NULL;

	list_for_each_entry(tmp_group, &zxdh_bond_list, node) {
		if (strcmp(dev_name(&upper->dev), zxdh_bond_group_name(tmp_group)) == 0) {
			bond_group = tmp_group;
			break;
		}
	}

	return bond_group;
}

static void *zxdh_create_hardware_bond_group(struct net_device *upper, bool is_special_bond)
{
	struct zxdh_bond_group *bond_group = NULL;

	if (!upper)
		return ERR_PTR(-EINVAL);

	bond_group = zxdh_find_hardware_bond_group(upper);
	if (bond_group)
		goto out;

	bond_group = kzalloc(sizeof(*bond_group), GFP_KERNEL);
	if (!bond_group)
		return ERR_PTR(-ENOMEM);

	/* create bond group id, range [0, 7] */
	if (is_special_bond)
		bond_group->group_ida = ZXDH_SPECIAL_LGA_ID;
	else
		bond_group->group_ida = ida_alloc_range(&zxdh_bond_group_ids, 1, 7, GFP_KERNEL);

	if (bond_group->group_ida < 0)
		goto err;

	strscpy(bond_group->name, dev_name(&upper->dev), IFNAMSIZ);
	list_add_tail(&bond_group->node, &zxdh_bond_list);

out:
	return bond_group;
err:
	kfree(bond_group);
	return ERR_PTR(-EINVAL);
}

static s32 zxdh_hardware_bond_group_init(struct zxdh_bond_device *bond_dev,
					 struct net_device *upper)
{
	struct zxdh_bond_group *bond_group = NULL;

	bond_group = zxdh_create_hardware_bond_group(upper, bond_dev->is_special_bond_dev);
	if (IS_ERR(bond_group))
		return -1;

	bond_dev->group = bond_group;
	bond_dev->upper_netdev = upper;

	return 0;
}

static bool zxdh_is_lower_state_change(struct zxdh_bond_device *bond_dev,
				       struct netdev_lag_lower_state_info *lag_lower_info)
{
	bool flag = true;

	if (bond_dev->link_up == lag_lower_info->link_up &&
	    bond_dev->tx_enabled == lag_lower_info->tx_enabled) {
		flag = false;
	}

	return flag;
}

static u32 zxdh_hardware_bond_set_mac_to_primary(struct zxdh_bond_device *bond_dev,
						 struct net_device *temp_netdev,
						 struct net_device *primary_netdev)
{
	struct zxdh_en_priv *primary_en_priv, *temp_en_priv;
	struct zxdh_en_device *primary_en_dev, *temp_en_dev;
	struct dpp_pf_info_t dpp_pf_info;
	s32 ret = 0;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	u16 current_vport = 0;
	struct netdev_hw_addr *ha = NULL;
	bool delete_flag = true;
	bool add_flag = true;

	if (!netif_is_zxdh_aux(temp_netdev) && !netif_is_zxdh_aux(primary_netdev)) {
		LOG_INFO("that is not zxdh aux netdev\n");
		return -1;
	}

	if (!bond_dev->group) {
		LOG_INFO("bond_dev->group is NULL\n");
		return -1;
	}

	if (bond_dev->group->lag_tx_type != ZXDH_NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
		LOG_DEBUG(
			"bond_dev->group->lag_tx_type is not ZXDH_NETDEV_LAG_TX_TYPE_ACTIVEBACKUP\n");
		return 0;
	}

	temp_en_priv = netdev_priv(temp_netdev);
	temp_en_dev = &temp_en_priv->edev;
	if (temp_en_dev->hardware_bond->primary) {
		LOG_DEBUG("primary pf %s don't need update mac for self\n", temp_netdev->name);
		return 0;
	}

	if ((!bond_dev->primary) && (bond_dev->netdev != temp_netdev)) {
		LOG_DEBUG("no-primary pf %s can't update mac for other pf %s\n",
			  bond_dev->netdev->name, temp_netdev->name);
		return 0;
	}

	primary_en_priv = netdev_priv(primary_netdev);
	primary_en_dev = &primary_en_priv->edev;

	dpp_pf_info.slot = primary_en_dev->slot_id;
	dpp_pf_info.vport = primary_en_dev->vport;

	if (!memcmp(primary_netdev->dev_addr, temp_netdev->dev_addr, temp_netdev->addr_len)) {
		LOG_INFO(
			"primary pf %s netdev mac %pM is same with temp pf %s netdev mac %pM, can't add\n",
			primary_netdev->name, primary_netdev->dev_addr, temp_netdev->name,
			temp_netdev->dev_addr);
		goto err;
	}
	if (!memcmp(primary_netdev->dev_addr, temp_en_dev->hardware_bond->last_mac_addr.sa_data,
		    temp_netdev->addr_len)) {
		LOG_INFO(
			"primary pf %s netdev mac %pM is same with temp pf %s last add mac %pM, can't del\n",
			primary_netdev->name, primary_netdev->dev_addr, temp_netdev->name,
			temp_en_dev->hardware_bond->last_mac_addr.sa_data);
		goto err;
	}

	list_for_each_entry(ha, &primary_netdev->uc.list, list) {
		if (!memcmp(ha->addr, temp_en_dev->hardware_bond->last_mac_addr.sa_data,
			    temp_netdev->addr_len)) {
			delete_flag = false;
			LOG_INFO("%pM is used by uc.list of primary pf %s, can't del\n",
				 temp_en_dev->hardware_bond->last_mac_addr.sa_data,
				 primary_netdev->name);
			goto err;
		}
		if (!memcmp(ha->addr, temp_netdev->dev_addr, temp_netdev->addr_len)) {
			add_flag = false;
			LOG_INFO("%pM is used by uc.list of primary pf %s, can't add\n",
				 temp_netdev->dev_addr, primary_netdev->name);
			goto err;
		}
	}
	if (delete_flag) {
		ret = dpp_unicast_mac_search(&dpp_pf_info,
					     temp_en_dev->hardware_bond->last_mac_addr.sa_data,
					     sriov_vlan_tpid, sriov_vlan_id, &current_vport);
		if ((!ret) && (dpp_pf_info.vport == current_vport)) {
			ret = dpp_del_mac(&dpp_pf_info,
					  temp_en_dev->hardware_bond->last_mac_addr.sa_data,
					  sriov_vlan_tpid, sriov_vlan_id);
			if (ret != 0) {
				LOG_ERR("pf del mac failed, retval: %d\n", ret);
				goto err;
			}
		} else if ((!ret) && (dpp_pf_info.vport != current_vport)) {
			LOG_INFO("%pM is used by primary pf(%s)-vf 0x%x, can't del\n",
				 temp_en_dev->hardware_bond->last_mac_addr.sa_data,
				 primary_netdev->name, current_vport);
			goto err;
		} else if (ret == DPP_HASH_RC_SRH_FAIL) {
			LOG_DEBUG("don't find %pM in primary pf(%s), don't need del\n",
				  temp_netdev->dev_addr, primary_netdev->name);
		} else {
			LOG_ERR("dpp_unicast_mac_search err ,ret%d\n", ret);
			goto err;
		}
	}

	if (add_flag) {
		ret = dpp_unicast_mac_search(&dpp_pf_info, temp_netdev->dev_addr, sriov_vlan_tpid,
					     sriov_vlan_id, &current_vport);
		if ((!ret) && (dpp_pf_info.vport == current_vport)) {
			LOG_DEBUG("%pM is used by primary pf(%s), don't need add\n",
				  temp_netdev->dev_addr, primary_netdev->name);
		}

		if ((!ret) && (dpp_pf_info.vport != current_vport)) {
			LOG_ERR("%pM is used by primary pf(%s) vport %d, can't add\n",
				temp_netdev->dev_addr, primary_netdev->name, current_vport);
			goto err;
		} else if (ret == DPP_HASH_RC_SRH_FAIL) {
			ret = dpp_add_mac(&dpp_pf_info, temp_netdev->dev_addr, sriov_vlan_tpid,
					  sriov_vlan_id);
			if (ret != 0) {
				LOG_ERR("pf add mac failed, retval: %d\n", ret);
				goto err;
			}
		} else {
			LOG_ERR("dpp_unicast_mac_search err ,ret%d\n", ret);
			goto err;
		}
	}
	ether_addr_copy(temp_en_dev->hardware_bond->last_mac_addr.sa_data, temp_netdev->dev_addr);
	ether_addr_copy(primary_en_dev->hardware_bond->last_mac_addr.sa_data,
			temp_netdev->dev_addr);
	return 0;
err:
	return -1;
}

static u32 zxdh_hardware_bond_set_primary_vfid(struct zxdh_bond_device *bond_dev,
					       struct net_device *temp_netdev, u16 primary_vfid)
{
	struct zxdh_en_priv *en_priv;
	struct zxdh_en_device *en_dev;
	struct dpp_pf_info_t dpp_pf_info;

	if (!netif_is_zxdh_aux(temp_netdev)) {
		LOG_ERR("that is not zxdh aux netdev\n");
		return -1;
	}

	if ((!bond_dev->primary) && (bond_dev->netdev != temp_netdev)) {
		LOG_DEBUG("no-primary pf %s can't update primary_vfid %d to other pf %s\n",
			  bond_dev->netdev->name, primary_vfid, temp_netdev->name);
		return 0;
	}

	en_priv = netdev_priv(temp_netdev);
	en_dev = &en_priv->edev;

	dpp_pf_info.slot = en_dev->slot_id;
	dpp_pf_info.vport = en_dev->vport;

	dpp_uplink_phy_attr_set(&dpp_pf_info, en_dev->phy_port, UPLINK_PHY_PORT_PRIMARY_PF_VQM_VFID,
				primary_vfid);
	LOG_INFO("%s set primary pf vqm vfid %hu, phyport %hu\n", temp_netdev->name, primary_vfid,
		 en_dev->phy_port);

	return 0;
}

static s32 zxdh_hardware_bond_get_primary_netdev(struct zxdh_bond_device *bond_dev,
						 struct net_device **primary_netdev)
{
	struct net_device *ndev_tmp;
	struct zxdh_en_priv *en_priv;
	struct zxdh_en_device *en_dev;
	u32 primary_port_cnt = 0;

	if (!bond_dev->upper_netdev)
		return -1;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(bond_dev->upper_netdev, ndev_tmp) {
		if (!netif_is_zxdh_aux(ndev_tmp))
			continue;

		en_priv = netdev_priv(ndev_tmp);
		en_dev = &en_priv->edev;

		if (en_dev->is_primary_port) {
			primary_port_cnt++;
			*primary_netdev = ndev_tmp;
		}
	}
	rcu_read_unlock();

	LOG_DEBUG("%s primary port num %u\n", bond_dev->netdev->name, primary_port_cnt);

	/* if no primary port */
	if ((primary_port_cnt == 0) || (*primary_netdev) || (primary_port_cnt > 1))
		return -1;

	return 0;
}

static s32 zxdh_hardware_bond_prepare_for_vf(struct zxdh_bond_device *bond_dev)
{
	struct net_device *ndev_tmp, *primary_netdev = NULL;
	u16 vfid = 0;
	s32 ret = 0;

	ret = zxdh_hardware_bond_get_primary_netdev(bond_dev, &primary_netdev);
	if (ret != 0) {
		LOG_INFO("%s get primary netdev failed\n", bond_dev->netdev->name);
		return -1;
	}

	vfid = zxdh_covert_netdev_2_vfid(primary_netdev);

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(bond_dev->upper_netdev, ndev_tmp) {
		zxdh_hardware_bond_set_primary_vfid(bond_dev, ndev_tmp, vfid);
		zxdh_hardware_bond_set_mac_to_primary(bond_dev, ndev_tmp, primary_netdev);
	}
	rcu_read_unlock();

	return 0;
}

static s32 zxdh_bond_set_dpp_member_port(struct zxdh_bond_device *bond_dev, bool enable,
					 struct event_node *node)
{
	u32 lagid = 0;
	u8 phy_port = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	u32 actual_enable_bit = bond_dev->phy_port == 0 ? RDMA_PHY_PORT_0_bit : RDMA_PHY_PORT_1_bit;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(bond_dev->netdev);
	en_dev = &en_priv->edev;
	if (!bond_dev->group)
		return -1;

	lagid = bond_dev->group->group_ida;

	phy_port = bond_dev->phy_port;
	pf_info.slot = bond_dev->slot;
	pf_info.vport = bond_dev->vport;

	if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR) {
		if (enable)
			dpp_lag_group_member_add(&pf_info, lagid, phy_port);
		else
			dpp_lag_group_member_del(&pf_info, lagid, phy_port);

		/* set panel attribute: BOND_LINK_UP */
		dpp_uplink_phy_attr_set(&pf_info, phy_port, UPLINK_PHY_PORT_BOND_LINK_UP, !!enable);
	}

	dpp_pktrx_mcode_glb_cfg_write(&pf_info, actual_enable_bit, actual_enable_bit, !!enable);

	LOG_INFO("%s node %d set members: lagid %hhu, phyport %hhu  bond_link_up %s\n",
		 netdev_name(bond_dev->netdev), node->idx, lagid, phy_port,
		 enable ? "true" : "false");

	return 0;
}

static void zxdh_print_hardware_bond_info(struct zxdh_bond_device *bond_dev,
					  struct event_node *node)
{
	struct zxdh_bond_group *group = bond_dev->group;

	LOG_INFO(
		"%s node %d event_type %ld bonded: %s txq %hu rxq %hu slot %hu vport 0x%x vfid %hu phyport %hhu linkup %hhu txenable %hhu\n",
		bond_dev->netdev->name, node->idx, node->event, bond_dev->bonded ? "true" : "false",
		bond_dev->txq, bond_dev->rxq, bond_dev->slot, bond_dev->vport, bond_dev->vfid,
		bond_dev->phy_port, node->link_up, node->tx_enabled);

	if (group) {
		LOG_INFO(
			"%s node %d event_type %ld master %s: group id %d tx_type %hhu hash_policy %hhu configured %s num_slaves %hu\n",
			bond_dev->netdev->name, node->idx, node->event, group->name,
			group->group_ida, group->lag_tx_type, group->hash_policy,
			group->configured ? "true" : "false", group->num_slaves);
	}
}

void del_slave_mac(struct zxdh_bond_device *bond_dev)
{
	struct dpp_pf_info_t dpp_pf_info;
	u16 sriov_vlan_tpid = 0;
	u16 sriov_vlan_id = 0;
	s32 ret = 0;

	dpp_pf_info.slot = bond_dev->slot;
	dpp_pf_info.vport = bond_dev->vport;

	if (!is_valid_ether_addr(bond_dev->last_mac_addr.sa_data))
		return;

	ret = dpp_del_mac(&dpp_pf_info, bond_dev->last_mac_addr.sa_data, sriov_vlan_tpid,
			  sriov_vlan_id);
	if (ret != 0) {
		LOG_ERR("pf del mac failed, retval: %d\n", ret);
	} else {
		LOG_INFO("del MAC %pM\n", bond_dev->last_mac_addr.sa_data);
		memset(bond_dev->last_mac_addr.sa_data, 0, ETH_ALEN);
	}
}

static s32 zxdh_update_hardware_bond_group(struct zxdh_bond_device *bond_dev,
					   struct event_node *node)
{
	s32 group_ida = 0;
	s32 ret = 0;
	struct zxdh_bond_group *group = bond_dev->group;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = bond_dev->slot,
		.vport = bond_dev->vport,
	};
	en_priv = netdev_priv(bond_dev->netdev);
	en_dev = &en_priv->edev;
	LOG_INFO("%s node %d linking %d, event %ld\n", netdev_name(bond_dev->netdev), node->idx,
		 node->linking, node->event);
	if (!node->linking && node->event == NETDEV_CHANGEUPPER) {
		bond_dev->group = NULL;
		bond_dev->bonded = false;
		if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR) {
			/* vport attr: LAG ID, LAG DISABLE */
			ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_LAG_ID, 0);
			if (ret != 0) {
				LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_LAG_ID 0 failed\n");
				return ret;
			}
			ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_LAG_EN_OFF, 0);
			if (ret != 0) {
				LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_LAG_EN_OFF 0 failed\n");
				return ret;
			}
			/* lag bond attr: disable member */
			dpp_uplink_phy_attr_set(&dpp_pf_info, bond_dev->phy_port,
						UPLINK_PHY_PORT_SRIOV_HD_BOND_EN, 0);
			dpp_uplink_phy_attr_set(&dpp_pf_info, bond_dev->phy_port,
						UPLINK_PHY_PORT_PRIMARY_PF_VQM_VFID, 0);
			/* panel attr: HARDWARE_BOND_ENABLE */
			dpp_uplink_phy_hardware_bond_set(&dpp_pf_info, bond_dev->phy_port, 0);
			if (bond_dev->primary)
				del_slave_mac(bond_dev);
		}
		zxdh_bond_set_dpp_member_port(bond_dev, false, node);
		if (bond_dev->primary) {
			zxdh_set_rdma_hwbond_master(bond_dev->netdev, bond_dev->upper_netdev,
						    false);
			zxdh_set_rdma_hwbond_speed(bond_dev->netdev, en_dev->speed);
		}
		bond_dev->upper_netdev = NULL;
		LOG_INFO("%s hardware bond set slave's group null\n",
			 netdev_name(bond_dev->netdev));
		ret = -1;
	}
	/* if no slaves, we need to free bond group */
	if (node->group_slave_num == 0 && node->event == NETDEV_CHANGEUPPER && !node->linking) {
		/* free bond group */
		list_del(&group->node);
		ida_free(&zxdh_bond_group_ids, group->group_ida);
		kfree(group);
		group = NULL;
		LOG_INFO("%s hardware bond group disabled\n", netdev_name(bond_dev->netdev));
		ret = -1;
	}
	if (ret == -1)
		return ret;

	/* if slaves, we check that configured */
	if (!group->configured) {
		group_ida = group->group_ida;
		dpp_lag_group_create(&dpp_pf_info, group_ida);
		dpp_lag_mode_set(&dpp_pf_info, group_ida, group->lag_tx_type);
		dpp_lag_group_hash_factor_set(&dpp_pf_info, group_ida, group->hash_policy);
		group->configured = true;
	}

	return 0;
}

static s32 zxdh_update_hardware_bond_slave(struct zxdh_bond_device *bond_dev)
{
	s32 ret = 0;
	struct zxdh_bond_group *group = bond_dev->group;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = bond_dev->slot,
		.vport = bond_dev->vport,
	};
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(bond_dev->netdev);
	en_dev = &en_priv->edev;

	if (bond_dev->bonded)
		return 0;

	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return 0;

	/* vport attr: LAG ID，LAG ENABLE */
	ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_LAG_EN_OFF, 1);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_LAG_EN_OFF 1 failed\n");
		return ret;
	}
	ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_LAG_ID, group->group_ida);
	if (ret != 0) {
		LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_LAG_ID %d failed\n", group->group_ida);
		return ret;
	}
	dpp_uplink_phy_attr_set(&dpp_pf_info, bond_dev->phy_port, UPLINK_PHY_PORT_SRIOV_HD_BOND_EN,
				1);
	dpp_uplink_phy_hardware_bond_set(&dpp_pf_info, bond_dev->phy_port, 1);

	if (bond_dev->primary)
		zxdh_set_rdma_hwbond_master(bond_dev->netdev, bond_dev->upper_netdev, true);

	zxdh_hardware_bond_prepare_for_vf(bond_dev);

	bond_dev->bonded = true;
	LOG_INFO("bond slave %s enabled\n", netdev_name(bond_dev->netdev));

	return 0;
}

static s32 zxdh_bond_cofig_rdma(struct zxdh_bond_device *bond_dev)
{
	struct net_device *ndev_tmp, *primary_netdev = NULL;
	struct zxdh_en_priv *en_priv;
	struct zxdh_en_device *en_dev;
	u32 primary_port_cnt = 0;
	struct ethtool_link_ksettings ks = { 0 };

	if (!bond_dev->upper_netdev)
		return 0;

	rtnl_lock();
	if (bond_dev->upper_netdev->ethtool_ops) {
		bond_dev->upper_netdev->ethtool_ops->get_link_ksettings(bond_dev->upper_netdev,
									&ks);
	}
	rtnl_unlock();

	rcu_read_lock();

	for_each_netdev_in_bond_rcu(bond_dev->upper_netdev, ndev_tmp) {
		if (!netif_is_zxdh_aux(ndev_tmp))
			continue;
		en_priv = netdev_priv(ndev_tmp);
		en_dev = &en_priv->edev;
		if (en_dev->is_primary_port) {
			primary_port_cnt++;
			primary_netdev = ndev_tmp;
		}
	}
	rcu_read_unlock();

	/* if no primary port */
	if ((primary_port_cnt == 0) || (!primary_netdev)) {
		return 0;
	} else if (primary_port_cnt > 1) {
		LOG_ERR("no primary port\n");
		return -1;
	}

	zxdh_set_rdma_hwbond_speed(bond_dev->upper_netdev, ks.base.speed);

	return 0;
}

/* bond_state*/
struct bond_port_info {
	u8 slave1_state;
	u8 slave1_port;
	u8 slave2_state;
	u8 slave2_port;
	u32 slave1_fid;
	u32 slave2_fid;
};

typedef int (*bond_dev_create_notify_hook_t)(char *ifname, struct bond_port_info *bond_info,
					     u8 mode);
typedef int (*bond_dev_update_notify_hook_t)(char *ifname, struct bond_port_info *bond_info);

struct bond_dev_hooks {
	bond_dev_create_notify_hook_t bond_dev_create_hook;
	bond_dev_update_notify_hook_t bond_dev_update_hook;
	struct mutex create_hook_lock;
	struct mutex update_hook_lock;
};

static struct bond_dev_hooks bond_hooks = {
	.bond_dev_create_hook = NULL,
	.bond_dev_update_hook = NULL,
	.create_hook_lock = __MUTEX_INITIALIZER(bond_hooks.create_hook_lock),
	.update_hook_lock = __MUTEX_INITIALIZER(bond_hooks.update_hook_lock),
};

void init_bond_dev_hooks(void)
{
	mutex_init(&bond_hooks.create_hook_lock);
	mutex_init(&bond_hooks.update_hook_lock);
	bond_hooks.bond_dev_create_hook = NULL;
	bond_hooks.bond_dev_update_hook = NULL;
	LOG_DEBUG("Bond hooks initialized successfully.\n");
}

void destroy_bond_dev_hooks(void)
{
	mutex_lock(&bond_hooks.create_hook_lock);
	if (bond_hooks.bond_dev_create_hook) {
		bond_hooks.bond_dev_create_hook = NULL;
		LOG_DEBUG("bond_dev_create_hook destroyed successfully.\n");
	}
	mutex_unlock(&bond_hooks.create_hook_lock);

	mutex_lock(&bond_hooks.update_hook_lock);
	if (bond_hooks.bond_dev_update_hook) {
		bond_hooks.bond_dev_update_hook = NULL;
		LOG_DEBUG("bond_dev_update_hook destroyed successfully.\n");
	}
	mutex_unlock(&bond_hooks.update_hook_lock);
}

int zxdh_register_bond_dev_create_hook(bond_dev_create_notify_hook_t hook)
{
	int ret = 0;

	mutex_lock(&bond_hooks.create_hook_lock);
	if (bond_hooks.bond_dev_create_hook && hook) {
		LOG_DEBUG(KERN_ERR "Repeat register bond_dev_create_notify_hook_t.\n");
		ret = -1;
	} else {
		bond_hooks.bond_dev_create_hook = hook;
	}
	mutex_unlock(&bond_hooks.create_hook_lock);

	return ret;
}
EXPORT_SYMBOL(zxdh_register_bond_dev_create_hook);

int zxdh_register_bond_dev_update_hook(bond_dev_update_notify_hook_t hook)
{
	int ret = 0;

	mutex_lock(&bond_hooks.update_hook_lock);
	if (bond_hooks.bond_dev_update_hook && hook) {
		LOG_DEBUG(KERN_ERR "Repeat register bond_dev_update_notify_hook_t.\n");
		ret = -1;
	} else {
		bond_hooks.bond_dev_update_hook = hook;
	}
	mutex_unlock(&bond_hooks.update_hook_lock);

	return ret;
}
EXPORT_SYMBOL(zxdh_register_bond_dev_update_hook);

void zxdh_bond_dev_create_hook_call(char *ifname, struct bond_port_info *bond_info, u8 mode)
{
	int ret = 0;

	mutex_lock(&bond_hooks.create_hook_lock);

	if (bond_hooks.bond_dev_create_hook) {
		ret = bond_hooks.bond_dev_create_hook(ifname, bond_info, mode);
		if (ret != 0) {
			LOG_DEBUG("zxdh bond_dev_create_hook_call\n");
			LOG_DEBUG("Error in bond dev create hook: %d\n", ret);
		} else {
			LOG_DEBUG("zxdh bond_dev_create_hook_call\n");
			LOG_DEBUG("bond dev create hook called successfully for %s.\n", ifname);
		}
	} else {
		LOG_DEBUG("bond dev create hook is not registered.\n");
	}
	mutex_unlock(&bond_hooks.create_hook_lock);
}

void zxdh_bond_dev_update_hook_call(char *ifname, struct bond_port_info *bond_info)
{
	int ret = 0;

	mutex_lock(&bond_hooks.update_hook_lock);

	if (bond_hooks.bond_dev_update_hook) {
		ret = bond_hooks.bond_dev_update_hook(ifname, bond_info);
		if (ret != 0) {
			LOG_DEBUG("zxdh bond_dev_update_hook_call\n");
			LOG_DEBUG("Error in bond dev update hook: %d\n", ret);
		} else {
			LOG_DEBUG("zxdh bond_dev_update_hook_call\n");
			LOG_DEBUG("bond dev update hook called successfully for %s.\n", ifname);
		}
	} else {
		LOG_DEBUG("bond dev update hook is not registered.\n");
	}
	mutex_unlock(&bond_hooks.update_hook_lock);
}

static bool zxdh_bond_dev_is_support_dualtor(struct zxdh_bond_device *hw_bond_dev)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	u64 dual_tor_addr = 0;

	if (!hw_bond_dev)
		return FALSE;
	en_priv = netdev_priv(hw_bond_dev->netdev);
	en_dev = &en_priv->edev;
	dual_tor_addr =
		en_dev->ops->get_bar_virt_addr(en_dev->parent, 0) + ZXDH_DUALTOR_LABEL_OFFSET;
	if (*(u32 *)dual_tor_addr != ZXDH_BAR_DUALTOR_LABEL_ON) {
		LOG_DEBUG("nic did not support dual tor!.\n");
		return FALSE;
	}
	return TRUE;
}

static s32 zxdh_get_hw_bond_panel_state(struct zxdh_bond_device *bond_dev)
{
	struct net_device *ndev_tmp = NULL;
	struct zxdh_en_priv *en_priv;
	struct zxdh_en_device *en_dev;
	struct bond_port_info bond_info = { 0 };

	if (!zxdh_bond_dev_is_support_dualtor(bond_dev))
		return 0;

	if (!bond_dev->upper_netdev)
		return 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(bond_dev->upper_netdev, ndev_tmp) {
		if (!netif_is_zxdh_aux(ndev_tmp))
			continue;
		en_priv = netdev_priv(ndev_tmp);
		en_dev = &en_priv->edev;

		if (en_dev->panel_id == 0) {
			bond_info.slave1_state = en_dev->hardware_bond->link_up ? 1 : 0;
			bond_info.slave1_port = en_dev->phy_port;
			LOG_DEBUG("slave1 %s states: %u, is_pri: %u, np_port: %u\n", ndev_tmp->name,
				  bond_info.slave1_state, en_dev->is_primary_port,
				  bond_info.slave1_port);
		} else if (en_dev->panel_id == 1) {
			bond_info.slave2_state = en_dev->hardware_bond->link_up ? 1 : 0;
			bond_info.slave2_port = en_dev->phy_port;
			LOG_DEBUG("slave2 %s states: %u, is_pri: %u, np_port: %u\n", ndev_tmp->name,
				  bond_info.slave2_state, en_dev->is_primary_port,
				  bond_info.slave2_port);
		}
	}
	rcu_read_unlock();
	zxdh_bond_dev_update_hook_call(bond_dev->upper_netdev->name, &bond_info);

	return 0;
}

int fid_gen_from_en_dev(struct zxdh_en_device *en_dev, u32 *fid_out)
{
	u32 fid = 0;

	if (!en_dev) {
		LOG_ERR("err ptr, null ptr en_dev.\n");
		return -1;
	}

	fid = ((en_dev->slot_id & 0x0000ffff) << 16);
	fid |= en_dev->pcie_id;

	*fid_out = fid;
	return 0;
}

static s32 zxdh_create_hw_bond_panel(struct zxdh_bond_device *bond_dev, struct event_node *node)
{
	struct net_device *ndev_tmp = NULL;
	struct zxdh_en_priv *en_priv;
	struct zxdh_en_device *en_dev;
	struct net_device *primary_dev = NULL;
	struct bond_port_info bond_info = { 0 };

	if (!bond_dev->upper_netdev) {
		LOG_DEBUG("do not exist uppder_dev.\n");
		return 0;
	}

	if (bond_dev->group->num_slaves != 2) {
		LOG_DEBUG("do not have 2 slaves yet.\n");
		return 0;
	}
	LOG_DEBUG("notify create hook.\n");

	rcu_read_lock();

	for_each_netdev_in_bond_rcu(bond_dev->upper_netdev, ndev_tmp) {
		if (!netif_is_zxdh_aux(ndev_tmp))
			continue;
		en_priv = netdev_priv(ndev_tmp);
		en_dev = &en_priv->edev;
		if (en_dev->is_primary_port)
			primary_dev = ndev_tmp;

		if (en_dev->panel_id == 0) {
			bond_info.slave1_state = node->link_up ? 1 : 0;
			bond_info.slave1_port = en_dev->phy_port;
			fid_gen_from_en_dev(en_dev, &bond_info.slave1_fid);
			LOG_DEBUG("slave1 fid 0x%x states: %u, is_pri: %u, np_port: %u\n",
				  bond_info.slave1_fid, bond_info.slave1_state,
				  en_dev->is_primary_port, bond_info.slave1_port);
		} else if (en_dev->panel_id == 1) {
			bond_info.slave2_state = node->link_up ? 1 : 0;
			bond_info.slave2_port = en_dev->phy_port;
			fid_gen_from_en_dev(en_dev, &bond_info.slave2_fid);
			LOG_DEBUG("slave2 fid 0x%x states: %u, is_pri: %u, np_port: %u\n",
				  bond_info.slave2_fid, bond_info.slave2_state,
				  en_dev->is_primary_port, bond_info.slave2_port);
		}
	}
	rcu_read_unlock();

	zxdh_bond_dev_create_hook_call(bond_dev->upper_netdev->name, &bond_info, 1);
	LOG_DEBUG("add primary dev:%s, slave1_state: %u, port1: %u, slave2_state: %u, port2: %u.\n",
		  primary_dev->name, bond_info.slave1_state, bond_info.slave1_port,
		  bond_info.slave2_state, bond_info.slave2_port);
	return 0;
}

static s32 zxdh_del_hw_bond_panel(struct zxdh_bond_device *bond_dev)
{
	struct bond_port_info bond_info = { 0 };

	if (!bond_dev->upper_netdev)
		return 0;

	if (bond_dev->group->num_slaves != 0) {
		LOG_DEBUG("not delete all slaves.\n");
		return 0;
	}

	zxdh_bond_dev_create_hook_call(bond_dev->upper_netdev->name, &bond_info, 0);
	LOG_DEBUG("del bond_dev : %s.\n", bond_dev->upper_netdev->name);

	return 0;
}

static void zxdh_do_hardware_bond(struct zxdh_bond_device *bond_dev, struct event_node *node)
{
	s32 ret = 0;
	bool lagstat = false;

	zxdh_print_hardware_bond_info(bond_dev, node);
	if (!bond_dev->group)
		goto out;
	ret = zxdh_update_hardware_bond_group(bond_dev, node);
	if (ret != 0)
		goto out;
	ret = zxdh_update_hardware_bond_slave(bond_dev);
	if (ret != 0)
		LOG_INFO("zxdh_update_hardware_bond_group fail\n");

	/* update: lag bond members、panel link */
	lagstat = node->link_up && node->tx_enabled;
	zxdh_bond_set_dpp_member_port(bond_dev, lagstat, node);

	LOG_DEBUG("link_up: %u, tx_enable: %u.\n", node->link_up, node->tx_enabled);
	if (node->link_up == node->tx_enabled) {
		/* (link_up = 0, tx_enable = 0) or (link_up = 1, tx_enable = 1) */
		zxdh_get_hw_bond_panel_state(bond_dev);
	}

	zxdh_bond_cofig_rdma(bond_dev);
out:
	return;
}

static s32 zxdh_update_special_bond_slave(struct zxdh_bond_device *bond_dev)
{
	s32 ret = 0;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = bond_dev->slot,
		.vport = bond_dev->vport,
	};
	struct zxdh_en_priv *en_priv = netdev_priv(bond_dev->netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	u16 ovs_vfid = en_dev->ops->get_ovs_pf_vfid(en_dev->parent);

	if (bond_dev->bonded || en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return 0;

	ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_HW_BOND_EN_OFF, 1);
	if (ret != 0) {
		LOG_ERR("%s dpp_vport_attr_set SRIOV_VPORT_HW_BOND_EN_OFF fail,ret: %d\n", __func__,
			ret);
		return ret;
	}
	dpp_uplink_phy_hardware_bond_set(&dpp_pf_info, bond_dev->phy_port, 1);
	dpp_uplink_phy_attr_set(&dpp_pf_info, en_dev->phy_port, UPLINK_PHY_PORT_PF_VQM_VFID,
				ovs_vfid);
	bond_dev->bonded = true;
	LOG_INFO("bond slave %s enabled\n", netdev_name(bond_dev->netdev));

	return 0;
}

static s32 zxdh_bond_set_special_bond_member_port(struct zxdh_bond_device *bond_dev, bool enable,
						  struct event_node *node)
{
	u32 lagid = 0;
	u8 phy_port = 0;
	struct dpp_pf_info_t pf_info = { 0 };
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	en_priv = netdev_priv(bond_dev->netdev);
	en_dev = &en_priv->edev;

	if (!bond_dev->group)
		return -1;
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR)
		return 0;
	lagid = bond_dev->group->group_ida;

	phy_port = bond_dev->phy_port;
	pf_info.slot = bond_dev->slot;
	pf_info.vport = bond_dev->vport;

	if (enable)
		dpp_lag_group_member_add(&pf_info, lagid, phy_port);
	else
		dpp_lag_group_member_del(&pf_info, lagid, phy_port);

	/* set panel attribute: BOND_LINK_UP */
	dpp_uplink_phy_attr_set(&pf_info, phy_port, UPLINK_PHY_PORT_BOND_LINK_UP, !!enable);

	LOG_INFO("%s node %d set members: lagid %hhu, phyport %hhu  bond_link_up %s\n",
		 netdev_name(bond_dev->netdev), node->idx, lagid, phy_port,
		 enable ? "true" : "false");

	return 0;
}

static s32 zxdh_update_special_bond_group(struct zxdh_bond_device *bond_dev,
					  struct event_node *node)
{
	s32 ret = 0;
	struct zxdh_bond_group *group = bond_dev->group;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = bond_dev->slot,
		.vport = bond_dev->vport,
	};
	en_priv = netdev_priv(bond_dev->netdev);
	en_dev = &en_priv->edev;
	LOG_INFO("%s node %d linking %d, event %ld\n", netdev_name(bond_dev->netdev), node->idx,
		 node->linking, node->event);

	if (!node->linking && node->event == NETDEV_CHANGEUPPER) {
		bond_dev->group = NULL;
		bond_dev->bonded = false;
		if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR) {
			zxdh_bond_set_special_bond_member_port(bond_dev, false, node);
			ret = dpp_vport_attr_set(&dpp_pf_info, SRIOV_VPORT_HW_BOND_EN_OFF, 0);
			if (ret != 0) {
				LOG_ERR("%s dpp_vport_attr_set SRIOV_BOND_EN_OFF fail,ret: %d\n",
					__func__, ret);
				return ret;
			}
			dpp_uplink_phy_hardware_bond_set(&dpp_pf_info, bond_dev->phy_port, 0);
			dpp_uplink_phy_attr_set(&dpp_pf_info, en_dev->phy_port,
						UPLINK_PHY_PORT_PF_VQM_VFID,
						zxdh_convert_pcie_id_2_vfid(en_dev->pcie_id));
		}
		bond_dev->upper_netdev = NULL;
		LOG_INFO("%s hardware bond set slave's group null\n",
			 netdev_name(bond_dev->netdev));
		ret = -1;
	}
	/* if no slaves, we need to free bond group */
	if (node->group_slave_num == 0 && node->event == NETDEV_CHANGEUPPER && !node->linking) {
		/* free bond group */
		list_del(&group->node);
		kfree(group);
		group = NULL;
		LOG_INFO("%s hardware bond group disabled\n", netdev_name(bond_dev->netdev));
		ret = -1;
	}
	if (ret == -1)
		return ret;

	/* if slaves, we check that configured */
	if (!group->configured) {
		dpp_lag_group_create(&dpp_pf_info, group->group_ida);
		if (group->lag_tx_type == ZXDH_NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
			dpp_lag_mode_set(&dpp_pf_info, group->group_ida, group->lag_tx_type);
		} else if (group->lag_tx_type == ZXDH_NETDEV_LAG_TX_TYPE_HASH) {
			dpp_lag_mode_set(&dpp_pf_info, group->group_ida, group->lag_tx_type);
			dpp_lag_group_hash_factor_set(&dpp_pf_info, group->group_ida,
						      ZXDH_NETDEV_LAG_HASH_L34);
		}
		group->configured = true;
	}

	return 0;
}

static void zxdh_do_special_bond(struct zxdh_bond_device *bond_dev, struct event_node *node)
{
	s32 ret = 0;
	bool lagstat = false;

	zxdh_print_hardware_bond_info(bond_dev, node);
	if (!bond_dev->group)
		goto out;
	ret = zxdh_update_special_bond_group(bond_dev, node);
	if (ret != 0)
		goto out;
	ret = zxdh_update_special_bond_slave(bond_dev);
	if (ret != 0)
		LOG_INFO("zxdh_update_hardware_bond_group fail\n");

	/* update: lag bond members、panel link */
	lagstat = node->link_up && node->tx_enabled;
	zxdh_bond_set_special_bond_member_port(bond_dev, lagstat, node);
out:
	return;
}

void zxdh_changeupper_dualtor_handler(struct zxdh_bond_device *hw_bond_dev,
				      struct event_node *node);
static void zxdh_do_hardware_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct event_ctx *ctx = container_of(delayed_work, struct event_ctx, bond_work);
	struct zxdh_bond_device *bond_dev = container_of(ctx, struct zxdh_bond_device, ctx);
	struct event_node *node, *tmp;
	s32 changed = 1;
	LIST_HEAD(local_list);

	spin_lock(&ctx->lock);
	list_splice_init(&ctx->event_list, &local_list);
	spin_unlock(&ctx->lock);
	LOG_INFO("%s enter %s\n", bond_dev->netdev->name, __func__);
	mutex_lock(&mlock);
	LOG_INFO("%s success get mlock\n", bond_dev->netdev->name);

	list_for_each_entry_safe(node, tmp, &local_list, list) {
		list_del(&node->list);
		LOG_INFO(
			"%s node %d addr %p get from list, event %ld linking %d link_up %d tx_enabled %d node_slave_num %d\n",
			bond_dev->netdev->name, node->idx, (void *)node, node->event, node->linking,
			node->link_up, node->tx_enabled, node->group_slave_num);
		if (node->event == NETDEV_CHANGEUPPER) {
			changed = zxdh_changeupper_event_handler(bond_dev, node);
			if (changed)
				zxdh_changeupper_dualtor_handler(bond_dev, node);
		}
		if (changed) {
			if (bond_dev->is_special_bond_dev)
				zxdh_do_special_bond(bond_dev, node);
			else
				zxdh_do_hardware_bond(bond_dev, node);
		}
		LOG_INFO("%s node %d addr %p has been processed\n", bond_dev->netdev->name,
			 node->idx, (void *)node);
		kfree(node);
	}
	mutex_unlock(&mlock);
	LOG_INFO("%s release mlock\n", bond_dev->netdev->name);
}

static void zxdh_queue_hardware_bond_work(struct zxdh_bond_device *bond_dev, struct event_ctx *ctx,
					  unsigned long delay)
{
	queue_delayed_work(bond_dev->wq, &ctx->bond_work, delay);
}

static s32 zxdh_get_hardware_bond_slaves_count(struct net_device *upper)
{
	struct net_device *ndev_tmp;
	s32 num_slaves = 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
		if (!netif_is_zxdh_aux(ndev_tmp)) {
			LOG_ERR("%s is not zxdh aux\n", dev_name(&ndev_tmp->dev));
			continue;
		}

		num_slaves++;
	}
	rcu_read_unlock();

	LOG_INFO("%s slaves num %d\n", upper->name, num_slaves);

	return num_slaves;
}

static s32 zxdh_update_bond_slaves(struct zxdh_bond_device *bond_dev, struct net_device *upper)
{
	if (!bond_dev->group) {
		LOG_ERR("!bond_dev->group\n");
		return -1;
	}

	bond_dev->group->num_slaves = zxdh_get_hardware_bond_slaves_count(upper);
	return 0;
}

static s32 zxdh_changeupper_event_pre_handler(struct zxdh_bond_device *bond_dev,
					      struct net_device *netdev, void *ptr)
{
	struct netdev_notifier_changeupper_info *info =
		(struct netdev_notifier_changeupper_info *)ptr;

	if (!netif_is_lag_master(info->upper_dev))
		return 0;
	bond_dev->upper_info.upper_dev = info->upper_dev;

	LOG_INFO("%s bonding %s\n", netdev->name, info->linking ? "LINK" : "UNLINK");
	bond_dev->linking = info->linking;
	if (info->linking) {
		bond_dev->upper_info.lag_upper_info.tx_type =
			((struct netdev_lag_upper_info *)info->upper_info)->tx_type;
		bond_dev->upper_info.lag_upper_info.hash_type =
			((struct netdev_lag_upper_info *)info->upper_info)->hash_type;
	}
	return 1;
}

static s32 zxdh_changeupper_event_handler(struct zxdh_bond_device *bond_dev,
					  struct event_node *node)
{
	s32 ret = 0;

	ret = zxdh_hardware_bond_group_init(bond_dev, bond_dev->upper_info.upper_dev);
	if (ret != 0) {
		LOG_ERR("zxdh init hardware bond group fail\n");
		return 0;
	}

	if (node->linking)
		zxdh_hardware_bond_link(bond_dev, &node->upper_info.lag_upper_info);

	zxdh_update_bond_slaves(bond_dev, bond_dev->upper_info.upper_dev);
	return 1;
}

static s32 zxdh_changelowerstate_event_handler(struct zxdh_bond_device *bond_dev,
					       struct net_device *netdev, void *ptr)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	struct netdev_notifier_changelowerstate_info *info;
	s32 change = 0;

	if (!netif_is_lag_port(netdev))
		return 0;

	info = (struct netdev_notifier_changelowerstate_info *)ptr;
	lag_lower_info = info->lower_state_info;
	if (!lag_lower_info)
		return 0;

	/* check if lower device state changed */
	if (zxdh_is_lower_state_change(bond_dev, lag_lower_info))
		change = 1;

	LOG_INFO("%s change: %d, link up: %hhu - %hhu, tx enable %hhu - %hhu\n", netdev->name,
		 change, lag_lower_info->link_up, bond_dev->link_up, lag_lower_info->tx_enabled,
		 bond_dev->tx_enabled);

	bond_dev->link_up = lag_lower_info->link_up;
	bond_dev->tx_enabled = lag_lower_info->tx_enabled;

	return change;
}

static s32 zxdh_bonding_info_event_handler(struct zxdh_bond_device *bond_dev,
					   struct net_device *netdev, void *ptr)
{
	return 0;
}

static s32 zxdh_changeaddr_event_handler(struct zxdh_bond_device *bond_dev,
					 struct net_device *netdev)
{
	s32 ret = 0;
	struct net_device *primary_netdev = NULL;

	if (!netif_is_lag_port(netdev)) {
		LOG_DEBUG("%s failed when netdev %s isn't bond slave\n", __func__, netdev->name);
		return 0;
	}

	if (bond_dev->is_special_bond_dev) {
		LOG_DEBUG("don't neet exec %s when netdev %s is special_bond\n", netdev->name,
			  __func__);
		return 0;
	}

	ret = zxdh_hardware_bond_get_primary_netdev(bond_dev, &primary_netdev);
	if (ret != 0) {
		LOG_DEBUG("%s get primary netdev failed\n", bond_dev->netdev->name);
		return -1;
	}

	zxdh_hardware_bond_set_mac_to_primary(bond_dev, bond_dev->netdev, primary_netdev);

	return 0;
}

void zxdh_changeupper_dualtor_handler(struct zxdh_bond_device *hw_bond_dev, struct event_node *node)
{
	if (node->linking != 0) {
		LOG_DEBUG("create bond detected.\n");
		zxdh_create_hw_bond_panel(hw_bond_dev, node);
	}

	else {
		LOG_DEBUG("del bond detected.\n");
		zxdh_del_hw_bond_panel(hw_bond_dev);
	}
}

void zxdh_bond_update_ctx_node(struct event_node *node, struct zxdh_bond_device *bond_dev)
{
	// node->upper_info.upper_dev = bond_dev->upper_info.upper_dev
	node->linking = bond_dev->linking;
	node->link_up = bond_dev->link_up;
	node->tx_enabled = bond_dev->tx_enabled;
	node->group_slave_num = 0;
	if (node->event == NETDEV_CHANGEUPPER) {
		node->group_slave_num =
			zxdh_get_hardware_bond_slaves_count(bond_dev->upper_info.upper_dev);
		if (node->linking) {
			node->upper_info.lag_upper_info.tx_type =
				bond_dev->upper_info.lag_upper_info.tx_type;
			node->upper_info.lag_upper_info.hash_type =
				bond_dev->upper_info.lag_upper_info.hash_type;
		}
	}
}

static int zxdh_hardware_bond_event_handler(struct notifier_block *notif_blk, unsigned long event,
					    void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct zxdh_bond_device *hw_bond_dev;
	s32 changed = 0;
	struct event_ctx *ctx = NULL;
	struct event_node *node = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;

	hw_bond_dev = container_of(notif_blk, struct zxdh_bond_device, notif_block);

	if (!hw_bond_dev->netdev)
		return NOTIFY_DONE;

	/* Check that the netdev is in the working namespace */
	if (!net_eq(dev_net(netdev), &init_net))
		return NOTIFY_DONE;

	if (netdev != hw_bond_dev->netdev)
		return NOTIFY_DONE;

	/* check that the netdev is hardware bond mode */
	if ((!zxdh_netdev_is_hwbond(netdev)) && (!hw_bond_dev->is_special_bond_dev))
		return NOTIFY_DONE;

	en_priv = netdev_priv(hw_bond_dev->netdev);
	en_dev = &en_priv->edev;
	switch (event) {
	case NETDEV_CHANGEUPPER: {
		changed = zxdh_changeupper_event_pre_handler(hw_bond_dev, netdev, ptr);
		LOG_INFO("%s node %d NETDEV_CHANGEUPPER, linking:%u\n", netdev->name,
			 hw_bond_dev->ctx.idx, hw_bond_dev->linking);
		break;
	}
	case NETDEV_CHANGELOWERSTATE: {
		LOG_INFO("%s node %d NETDEV_CHANGELOWERSTATE\n", netdev->name,
			 hw_bond_dev->ctx.idx);
		changed = zxdh_changelowerstate_event_handler(hw_bond_dev, netdev, ptr);
		break;
	}
	case NETDEV_BONDING_INFO: {
		changed = zxdh_bonding_info_event_handler(hw_bond_dev, netdev, ptr);
		break;
	}
	case NETDEV_CHANGEADDR: {
		LOG_INFO("%s NETDEV_CHANGEADDR\n", netdev->name);
		if (en_dev->device_state != ZXDH_DEVICE_STATE_INTERNAL_ERROR)
			zxdh_changeaddr_event_handler(hw_bond_dev, netdev);
		break;
	}
	}

	if (changed) {
		ctx = &hw_bond_dev->ctx;
		node = kmalloc(sizeof(*node), GFP_ATOMIC);
		if (!node) {
			LOG_ERR("Failed to allocate event node!\n");
			return NOTIFY_OK;
		}
		node->idx = ctx->idx;
		node->event = event;
		ctx->idx++;
		zxdh_bond_update_ctx_node(node, hw_bond_dev);

		spin_lock(&ctx->lock);
		list_add_tail(&node->list, &ctx->event_list);
		LOG_INFO(
			"%s node %d addr %p add to list, event %ld linking %d link_up %d tx_enabled %d\n",
			netdev->name, node->idx, (void *)node, node->event, node->linking,
			node->link_up, node->tx_enabled);
		spin_unlock(&ctx->lock);
		zxdh_queue_hardware_bond_work(hw_bond_dev, ctx, 0);
	}

	return NOTIFY_DONE;
}

static s32 zxdh_hardware_bond_device_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_bond_device *bond_dev;
	struct notifier_block *notif_blk;
	char queue_name[32];

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;

	/* rmda auxiliary device plug default */
	bond_dev = en_dev->hardware_bond;

	bond_dev->netdev = netdev;
	bond_dev->pf_core_dev = en_dev->parent->parent;
	bond_dev->bonded = false;
	bond_dev->upper_netdev = NULL;
	bond_dev->group = NULL;
	bond_dev->tx_enabled = false;
	bond_dev->link_up = false;

	bond_dev->primary = en_dev->is_primary_port;

	bond_dev->rxq = en_dev->phy_index[0];
	bond_dev->txq = en_dev->phy_index[1];

	bond_dev->vport = en_dev->vport;
	bond_dev->slot = en_dev->slot_id;
	bond_dev->vfid = zxdh_convert_pcie_id_2_vfid(en_dev->pcie_id);
	bond_dev->phy_port = en_dev->phy_port;
	bond_dev->is_special_bond_dev = en_dev->ops->is_special_bond(en_dev->parent);
	if (!bond_dev->primary)
		ether_addr_copy(bond_dev->last_mac_addr.sa_data, en_dev->netdev->dev_addr);
	else
		memset(bond_dev->last_mac_addr.sa_data, 0, ETH_ALEN);

	notif_blk = &bond_dev->notif_block;
	notif_blk->notifier_call = zxdh_hardware_bond_event_handler;
	if (register_netdevice_notifier(notif_blk)) {
		LOG_ERR("FAIL register bdf %x hardware bond event handler!\n", en_dev->ep_bdf);
		notif_blk->notifier_call = NULL;
		return -EINVAL;
	}

	LOG_DEBUG("bdf %x hardware bond event handler registered\n", en_dev->ep_bdf);

	snprintf(queue_name, sizeof(queue_name), "bond_work_%x", en_dev->ep_bdf);
	bond_dev->wq = create_singlethread_workqueue(queue_name);
	if (!bond_dev->wq) {
		LOG_ERR("FAIL register bdf %x hardware bond workqueue!\n", en_dev->ep_bdf);
		unregister_netdevice_notifier(notif_blk);
		notif_blk->notifier_call = NULL;
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&bond_dev->ctx.event_list);
	INIT_DELAYED_WORK(&bond_dev->ctx.bond_work, zxdh_do_hardware_bond_work);

	return 0;
}

s32 zxdh_rdma_bond_dpp_init(struct zxdh_bond_device *bond_dev)
{
	u8 phy_port = bond_dev->phy_port;
	s32 ret = 0;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = bond_dev->slot,
		.vport = bond_dev->vport,
	};

	ret = dpp_uplink_phy_lacp_pf_memport_qid_set(&dpp_pf_info, phy_port, bond_dev->rxq);
	if (ret != 0) {
		LOG_ERR("dpp_uplink_phy_lacp_pf_memport_qid_set failed: %d\n", ret);
		goto out;
	}
	ret = dpp_uplink_phy_lacp_pf_vqm_vfid_set(&dpp_pf_info, phy_port, bond_dev->vfid);
	if (ret != 0) {
		LOG_ERR("dpp_uplink_phy_lacp_pf_vqm_vfid_set failed: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

s32 zxdh_special_bond_dpp_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = en_dev->slot_id,
		.vport = en_dev->vport,
	};

	ret = dpp_uplink_phy_bond_vport(&dpp_pf_info, en_dev->phy_port);
	if (ret != 0) {
		LOG_ERR("dpp_uplink_phy_bond_vport failed: %d\n", ret);
		goto out;
	}
	ret = dpp_uplink_phy_lacp_pf_vqm_vfid_set(&dpp_pf_info, en_dev->phy_port,
						  en_dev->hardware_bond->vfid);
	if (ret != 0) {
		LOG_ERR("dpp_uplink_phy_lacp_pf_vqm_vfid_set failed: %d\n", ret);
		goto out;
	}
	ret = dpp_uplink_phy_lacp_pf_memport_qid_set(&dpp_pf_info, en_dev->phy_port,
						     en_dev->hardware_bond->rxq);
	if (ret != 0) {
		LOG_ERR("dpp_uplink_phy_lacp_pf_memport_qid_set failed: %d\n", ret);
		goto out;
	}

out:
	return ret;
}

s32 zxdh_hardware_bond_dpp_init(struct zxdh_en_device *en_dev)
{
	s32 ret = 0;

	en_dev->hardware_bond->rxq = en_dev->phy_index[0];
	en_dev->hardware_bond->txq = en_dev->phy_index[1];
	if (en_dev->hardware_bond->is_special_bond_dev)
		ret = zxdh_special_bond_dpp_init(en_dev);
	else
		ret = zxdh_rdma_bond_dpp_init(en_dev->hardware_bond);

	return ret;
}

s32 zxdh_hardware_bond_init(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	s32 ret = 0;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;

	/* do nothing if vf */
	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return 0;
	}

	/* create hardware bond device  */
	en_dev->hardware_bond = kzalloc(sizeof(struct zxdh_bond_device), GFP_KERNEL);
	if (!en_dev->hardware_bond) {
		LOG_ERR("zxdh hardware bond device kzalloc fail\n");
		return -ENOMEM;
	}

	ret = zxdh_hardware_bond_device_init(netdev);
	if (ret != 0) {
		LOG_ERR("zxdh hardware bond device init fail\n");
		goto err_bond_dev_init;
	}

	ret = zxdh_hardware_bond_dpp_init(en_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_hardware_bond_dpp_init fail\n");
		goto err_bond_dpp_init;
	}

	list_add_tail(&en_dev->hardware_bond->node, &zxdh_aux_netdev_list);

	LOG_INFO("bdf 0x%x success\n", en_dev->ep_bdf);

	return 0;

err_bond_dpp_init:
	unregister_netdevice_notifier(&en_dev->hardware_bond->notif_block);
	en_dev->hardware_bond->notif_block.notifier_call = NULL;
	cancel_delayed_work_sync(&en_dev->hardware_bond->ctx.bond_work);
	destroy_workqueue(en_dev->hardware_bond->wq);
err_bond_dev_init:
	kfree(en_dev->hardware_bond);
	en_dev->hardware_bond = NULL;
	return ret;
}

void zxdh_hardware_bond_uninit(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;
	struct zxdh_bond_device *hardware_bond;
	struct event_node *node, *tmp;

	en_priv = netdev_priv(netdev);
	en_dev = &en_priv->edev;

	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev))) {
		return;
	}

	if (en_dev->hardware_bond) {
		list_del(&en_dev->hardware_bond->node);

		hardware_bond = en_dev->hardware_bond;
		if (hardware_bond->notif_block.notifier_call) {
			unregister_netdevice_notifier(&hardware_bond->notif_block);
			hardware_bond->notif_block.notifier_call = NULL;
		}

		cancel_delayed_work_sync(&hardware_bond->ctx.bond_work);
		destroy_workqueue(hardware_bond->wq);

		spin_lock(&hardware_bond->ctx.lock);
		list_for_each_entry_safe(node, tmp, &hardware_bond->ctx.event_list, list) {
			list_del(&node->list);
			LOG_INFO(
				"%s node %d addr %p del from list, event %ld linking %d link_up %d tx_enabled %d\n",
				netdev->name, node->idx, (void *)node, node->event, node->linking,
				node->link_up, node->tx_enabled);
			kfree(node);
		}
		spin_unlock(&hardware_bond->ctx.lock);

		if (en_dev->hardware_bond->group)
			en_dev->hardware_bond->group->configured = false;

		kfree(en_dev->hardware_bond);
		en_dev->hardware_bond = NULL;
	}
}

s32 zxdh_recover_hwbond_in_reload(struct net_device *netdev)
{
	struct zxdh_en_priv *en_priv = netdev_priv(netdev);
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct zxdh_bond_device *hardware_bond;
	s32 ret = 0;
	u8 hit_flag = 0;
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = en_dev->slot_id,
		.vport = en_dev->vport,
	};

	if ((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) ||
	    (!zxdh_en_is_panel_port(en_dev)) || (en_dev->ops->is_bond(en_dev->parent))) {
		return 0;
	}

	if (en_dev->hardware_bond) {
		ret = zxdh_hardware_bond_dpp_init(en_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_hardware_bond_dpp_init failed: %d\n", ret);
			goto out;
		}
		hardware_bond = en_dev->hardware_bond;
		if (en_dev->hardware_bond->group) {
			dpp_lag_hit_flag_get(&dpp_pf_info, en_dev->hardware_bond->group->group_ida,
					     &hit_flag);
			LOG_INFO("%s check lag_bond %d hist_flag %d\n", netdev->name,
				 en_dev->hardware_bond->group->group_ida, hit_flag);
			en_dev->hardware_bond->group->configured = hit_flag == 0 ? false : true;
		}
		en_dev->hardware_bond->bonded = false;
		if (!en_dev->hardware_bond->is_special_bond_dev)
			en_dev->ops->optim_hardware_bond_time(en_dev->parent, en_dev->is_hwbond);
	}
out:
	return ret;
}

void zxdh_update_rdma_hwbond_master(void)
{
	struct zxdh_bond_device *bond_dev;
	struct net_device *netdev;
	struct net_device *uplink_upper;
	struct net_device *primary_netdev;
	s32 ret = 0;

	list_for_each_entry(bond_dev, &zxdh_aux_netdev_list, node) {
		netdev = bond_dev->netdev;
		if (!netdev)
			continue;

		/* if netdev not hwbond */
		if (!zxdh_netdev_is_hwbond(netdev))
			continue;

		rcu_read_lock();
		uplink_upper = netdev_master_upper_dev_get_rcu(netdev);
		rcu_read_unlock();
		if (uplink_upper && netif_is_lag_master(uplink_upper)) {
			ret = zxdh_hardware_bond_get_primary_netdev(bond_dev, &primary_netdev);
			if (!ret) {
				/* set rdma dev bind netdev and port speed */
				zxdh_set_rdma_hwbond_master(primary_netdev, uplink_upper, true);
				zxdh_bond_cofig_rdma(bond_dev);
				continue;
			}

			LOG_INFO("%s get primary netdev failed\n", netdev_name(netdev));
		}
	}
}
