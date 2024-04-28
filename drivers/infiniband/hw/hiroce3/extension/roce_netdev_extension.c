// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_netdev_extension.h"
#include "roce_mpu_common.h"

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

#ifndef PANGEA_NOF
int roce3_add_real_device_mac(struct roce3_device *rdev, struct net_device *netdev)
{
	int ret;
	u32 vlan_id = 0;

	/*
	 * no need to configure IPSURX vf table for vroce here,
	 * this action has been done in vroce driver
	 */
	roce3_add_ipsu_tbl_mac_entry(rdev->hwdev, (u8 *)netdev->dev_addr, vlan_id,
		rdev->glb_func_id, hinic3_er_id(rdev->hwdev));

#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		ret = roce3_add_bond_real_slave_mac(rdev, (u8 *)netdev->dev_addr);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to add bond ipsu mac, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, (u8 *)netdev->dev_addr, 0,
				rdev->glb_func_id, hinic3_er_id(rdev->hwdev));
			return ret;
		}
	}
#endif

	memcpy(rdev->mac, netdev->dev_addr, sizeof(rdev->mac));

	return 0;
}

int roce3_add_vlan_device_mac(struct roce3_device *rdev, struct net_device *netdev)
{
	int ret = 0;
	u32 vlan_id = 0;

	vlan_id = ROCE_GID_SET_VLAN_32BIT_VLAID(((u32)rdma_vlan_dev_vlan_id(netdev)));
	dev_info(rdev->hwdev_hdl, "[ROCE] %s: enter add vlan, vlan_id(0x%x), func_id(%d)\n",
		__func__, vlan_id, rdev->glb_func_id);
	ret = roce3_add_mac_tbl_mac_entry(rdev->hwdev, (u8 *)netdev->dev_addr,
		vlan_id, rdev->glb_func_id, rdev->glb_func_id);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to set vlan mac, vlan_id(0x%x), func_id(%d)\n",
			__func__, vlan_id, rdev->glb_func_id);
		return ret;
	}

	roce3_add_ipsu_tbl_mac_entry(rdev->hwdev, (u8 *)netdev->dev_addr, vlan_id,
		rdev->glb_func_id, hinic3_er_id(rdev->hwdev));

#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		ret = roce3_add_bond_vlan_slave_mac(rdev, (u8 *)netdev->dev_addr, (u16)vlan_id);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to set bond, vlan_id(0x%x), func_id(%d)\n",
				__func__, vlan_id, rdev->glb_func_id);
			goto err_add_bond_vlan_slave_mac;
		}
	}
#endif

	return ret;

#ifdef ROCE_BONDING_EN
err_add_bond_vlan_slave_mac:
	roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, (u8 *)netdev->dev_addr,
		vlan_id, rdev->glb_func_id, hinic3_er_id(rdev->hwdev));

	(void)hinic3_del_mac(rdev->hwdev, (u8 *)netdev->dev_addr, (u16)vlan_id,
		rdev->glb_func_id, HINIC3_CHANNEL_ROCE);

	return ret;
#endif
}

void roce3_del_real_device_mac(struct roce3_device *rdev)
{
	u32 vlan_id = 0;
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev))
		roce3_del_bond_real_slave_mac(rdev);
#endif

	roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, rdev->mac, vlan_id,
		rdev->glb_func_id, hinic3_er_id(rdev->hwdev));
}

void roce3_del_vlan_device_mac(struct roce3_device *rdev, struct roce3_vlan_dev_list *old_list)
{
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev))
		roce3_del_bond_vlan_slave_mac(rdev, old_list->mac, (u16)old_list->vlan_id);
#endif

	roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, old_list->mac, old_list->vlan_id,
		rdev->glb_func_id, hinic3_er_id(rdev->hwdev));

	(void)roce3_del_mac_tbl_mac_entry(rdev->hwdev, old_list->mac, old_list->vlan_id,
		rdev->glb_func_id, rdev->glb_func_id);
}

void roce3_event_up_extend(struct roce3_device *rdev)
{
	if (test_and_set_bit(ROCE3_PORT_EVENT, &rdev->status) == 0)
		roce3_ifconfig_up_down_event_report(rdev, IB_EVENT_PORT_ACTIVE);
}

#endif /* PANGEA_NOF */
