// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025-2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <linux/etherdevice.h>
#include <ub/ubase/ubase_comm_cmd.h>

#include "unic.h"
#include "unic_comm_addr.h"
#include "unic_cmd.h"
#include "unic_mac.h"

static int unic_add_mac_addr_common(struct unic_vport *vport, u8 *mac_addr,
				    enum unic_mac_addr_type mac_type,
				    u8 is_pfc)
{
	struct unic_mac_promisc {
		const char *type_str;
		u8 promisc_mode;
	} promisc[] = {
		[UNIC_MAC_ADDR_UC] = {"unicast", UNIC_OVERFLOW_UP_MAC},
		[UNIC_MAC_ADDR_MC] = {"multicast", UNIC_OVERFLOW_MP_MAC},
	};

	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct unic_mac_tbl_entry_cmd resp = {0};
	struct unic_mac_tbl_entry_cmd req = {0};
	u8 format_mac[UNIC_FORMAT_MAC_LEN];
	struct ubase_cmd_buf in, out;
	int ret;

	req.mac_type = mac_type;
	req.is_pfc = is_pfc;
	ether_addr_copy(req.mac_addr, mac_addr);
	unic_comm_format_mac_addr(format_mac, mac_addr);
	ubase_fill_inout_buf(&in, UBASE_OPC_ADD_MAC_TBL, false, sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_ADD_MAC_TBL, true, sizeof(resp), &resp);
	ret = ubase_cmd_send_inout(adev, &in, &out);
	ret = ret ? ret : -resp.resp_code;
	if (!ret) {
		return 0;
	} else if (ret == -EEXIST && mac_type == UNIC_MAC_ADDR_UC) {
		unic_info(unic_dev, "mac addr(%s) exists.\n", format_mac);
		return -EEXIST;
	} else if (ret != -ENOSPC) {
		unic_err(unic_dev,
			 "failed to add mac addr(%s), ret = %d.\n", format_mac,
			 ret);
		return ret;
	}

	if (!(vport->overflow_promisc_flags & promisc[mac_type].promisc_mode))
		unic_warn(unic_dev, "%s mac table is full.\n",
			  promisc[mac_type].type_str);

	return ret;
}

static int unic_del_mac_addr_common(struct unic_vport *vport, u8 *mac_addr,
				    enum unic_mac_addr_type mac_type,
				    u8 is_pfc, bool need_retry)
{
	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_mac_tbl_entry_cmd resp = {0};
	struct unic_mac_tbl_entry_cmd req = {0};
	u8 format_mac[UNIC_FORMAT_MAC_LEN];
	struct ubase_cmd_buf in, out;
	u32 time_out;
	int ret;

	req.mac_type = mac_type;
	req.is_pfc = is_pfc;
	ether_addr_copy(req.mac_addr, mac_addr);
	ubase_fill_inout_buf(&in, UBASE_OPC_DEL_MAC_TBL, false, sizeof(req), &req);
	ubase_fill_inout_buf(&out, UBASE_OPC_DEL_MAC_TBL, true, sizeof(resp), &resp);
	time_out = unic_cmd_timeout(vport->back);
	ret = need_retry ? ubase_cmd_send_inout_ex(adev, &in, &out, time_out) :
			   ubase_cmd_send_inout(adev, &in, &out);
	ret = ret ? ret : -resp.resp_code;
	if (ret) {
		unic_comm_format_mac_addr(format_mac, mac_addr);
		dev_err(adev->dev.parent, "failed to rm mac addr(%s), ret = %d.\n",
			format_mac, ret);
	}

	return ret;
}

int unic_cfg_mac_address(struct unic_dev *unic_dev, u8 *mac_addr)
{
	struct unic_comm_addr_node *new_node, *old_node;
	struct unic_vport *vport = &unic_dev->vport;
	u8 *old_mac = unic_dev->hw.mac.mac_addr;
	u8 unic_addr[UNIC_ADDR_LEN] = {0};
	struct list_head *list;
	int ret;

	list = &vport->addr_tbl.uc_mac_list;
	spin_lock_bh(&vport->addr_tbl.mac_list_lock);
	new_node = unic_comm_find_addr_node(list, mac_addr,
					    UNIC_COMM_ADDR_NO_MASK);
	if (new_node) {
		if (new_node->state != UNIC_COMM_ADDR_TO_ADD) {
			ret = unic_del_mac_addr_common(vport, mac_addr,
						       UNIC_MAC_ADDR_UC, 0,
						       false);
			if (ret) {
				spin_unlock_bh(&vport->addr_tbl.mac_list_lock);
				return ret;
			}
		}

		/* make sure the new addr is in the list head, avoid dev
		 * addr may be not re-added into mac table for the umv space
		 * limitation after reset.
		 */
		new_node->is_pfc = 1;
		new_node->state = UNIC_COMM_ADDR_TO_ADD;
		list_move(&new_node->node, list);
	} else {
		new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
		if (!new_node) {
			spin_unlock_bh(&vport->addr_tbl.mac_list_lock);
			return -ENOMEM;
		}

		new_node->state = UNIC_COMM_ADDR_TO_ADD;
		new_node->is_pfc = 1;
		ether_addr_copy(new_node->mac_addr, mac_addr);
		list_add(&new_node->node, list);
	}

	ether_addr_copy(unic_addr, old_mac);
	old_node = unic_comm_find_addr_node(list, unic_addr,
					    UNIC_COMM_ADDR_NO_MASK);
	if (old_node) {
		if (old_node->state == UNIC_COMM_ADDR_TO_ADD) {
			list_del(&old_node->node);
			kfree(old_node);
		} else {
			old_node->state = UNIC_COMM_ADDR_TO_DEL;
			old_node->is_pfc = 0;
		}
	}

	set_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);
	ether_addr_copy(unic_dev->hw.mac.mac_addr, mac_addr);
	spin_unlock_bh(&vport->addr_tbl.mac_list_lock);

	return 0;
}

static void unic_sync_mac_list(struct unic_vport *vport, struct list_head *list,
			       enum unic_mac_addr_type mac_type)
{
	struct unic_comm_addr_node *mac_node;
	int ret;

	list_for_each_entry(mac_node, list, node) {
		ret = unic_add_mac_addr_common(vport, mac_node->mac_addr, mac_type,
					       mac_node->is_pfc);
		if (!ret) {
			mac_node->state = UNIC_COMM_ADDR_ACTIVE;
		} else {
			set_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);

			/* UC MAC addition: -EEXIST indicates the address already
			 * exists in hardware. This entry cannot be added, but we
			 * can continue to try adding the next UC MAC in the list
			 * without breaking the loop.
			 * MC MAC addition: -ENOSPC indicates the hardware table
			 * is full for new entries. However, we can still continue
			 * to process MC MACs that may already exist in hardware
			 * without breaking.
			 */
			if ((mac_type == UNIC_MAC_ADDR_UC && ret != -EEXIST) ||
			    (mac_type == UNIC_MAC_ADDR_MC && ret != -ENOSPC))
				break;
		}
	}
}

static void unic_unsync_mac_list(struct unic_vport *vport,
				 struct list_head *list,
				 enum unic_mac_addr_type mac_type)
{
	struct unic_comm_addr_node *mac_node, *tmp;
	int ret;

	list_for_each_entry_safe(mac_node, tmp, list, node) {
		ret = unic_del_mac_addr_common(vport, mac_node->mac_addr, mac_type,
					       mac_node->is_pfc, true);
		if (!ret) {
			list_del(&mac_node->node);
			kfree(mac_node);
		} else {
			set_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);
			continue;
		}
	}
}

static void unic_sync_uc_mac_list(struct unic_vport *vport,
				  struct list_head *list)
{
	unic_sync_mac_list(vport, list, UNIC_MAC_ADDR_UC);
}

static void unic_sync_mc_mac_list(struct unic_vport *vport,
				  struct list_head *list)
{
	unic_sync_mac_list(vport, list, UNIC_MAC_ADDR_MC);
}

static void unic_unsync_uc_mac_list(struct unic_vport *vport,
				    struct list_head *list)
{
	unic_unsync_mac_list(vport, list, UNIC_MAC_ADDR_UC);
}

static void unic_unsync_mc_mac_list(struct unic_vport *vport,
				    struct list_head *list)
{
	unic_unsync_mac_list(vport, list, UNIC_MAC_ADDR_MC);
}

static void unic_sync_mac_table_common(struct unic_vport *vport,
				       enum unic_mac_addr_type mac_type)
{
	void (*unsync)(struct unic_vport *vport, struct list_head *list);
	void (*sync)(struct unic_vport *vport, struct list_head *list);
	struct list_head *mac_list;
	bool all_added;

	if (mac_type == UNIC_MAC_ADDR_UC) {
		mac_list = &vport->addr_tbl.uc_mac_list;
		sync = unic_sync_uc_mac_list;
		unsync = unic_unsync_uc_mac_list;
	} else {
		mac_list = &vport->addr_tbl.mc_mac_list;
		sync = unic_sync_mc_mac_list;
		unsync = unic_unsync_mc_mac_list;
	}

	all_added = unic_comm_sync_addr_table(vport, mac_list,
					      &vport->addr_tbl.mac_list_lock,
					      sync, unsync);
	if (mac_type == UNIC_MAC_ADDR_UC) {
		if (all_added)
			vport->overflow_promisc_flags &= ~UNIC_OVERFLOW_UP_MAC;
		else
			vport->overflow_promisc_flags |= UNIC_OVERFLOW_UP_MAC;
	} else {
		if (all_added)
			vport->overflow_promisc_flags &= ~UNIC_OVERFLOW_MP_MAC;
		else
			vport->overflow_promisc_flags |= UNIC_OVERFLOW_MP_MAC;
	}
}

void unic_sync_mac_table(struct unic_dev *unic_dev)
{
	struct unic_act_info *act_info = &unic_dev->act_info;
	struct unic_vport *vport = &unic_dev->vport;

	if (!mutex_trylock(&act_info->mutex))
		return;

	if (act_info->deactivate)
		goto out;

	if (!test_and_clear_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state))
		goto out;

	unic_sync_mac_table_common(vport, UNIC_MAC_ADDR_UC);
	unic_sync_mac_table_common(vport, UNIC_MAC_ADDR_MC);

out:
	mutex_unlock(&act_info->mutex);
}

static int unic_update_mac_list(struct net_device *netdev,
				enum UNIC_COMM_ADDR_STATE state,
				enum unic_mac_addr_type mac_type,
				const u8 *mac_addr)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_vport *vport = &unic_dev->vport;
	char format_mac[UNIC_FORMAT_MAC_LEN];
	u8 unic_addr[UNIC_ADDR_LEN] = {0};
	struct list_head *list;
	bool valid;
	int ret;

	if (!unic_dev_cfg_mac_supported(unic_dev))
		return -EOPNOTSUPP;

	if (mac_type == UNIC_MAC_ADDR_UC) {
		list = &vport->addr_tbl.uc_mac_list;
		valid = is_valid_ether_addr(mac_addr);
	} else {
		list = &vport->addr_tbl.mc_mac_list;
		valid = is_multicast_ether_addr(mac_addr);
	}

	unic_comm_format_mac_addr(format_mac, mac_addr);
	if (!valid) {
		unic_err(unic_dev, "failed to %s %s mac addr(%s).\n",
			 state == UNIC_COMM_ADDR_TO_ADD ? "add" : "del",
			 mac_type == UNIC_MAC_ADDR_UC ? "uc" : "mc", format_mac);
		return -EINVAL;
	}

	ether_addr_copy(unic_addr, mac_addr);
	ret = unic_comm_update_addr_list(list, &vport->addr_tbl.mac_list_lock,
					 state, unic_addr);
	if (ret) {
		unic_err(unic_dev,
			 "failed to update mac addr(%s). mac_type = %s.\n",
			 format_mac, mac_type == UNIC_MAC_ADDR_UC ? "uc" : "mc");
		return ret;
	}

	set_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);

	return ret;
}

int unic_add_uc_mac(struct net_device *netdev, const u8 *mac_addr)
{
	return unic_update_mac_list(netdev, UNIC_COMM_ADDR_TO_ADD,
				    UNIC_MAC_ADDR_UC, mac_addr);
}

int unic_del_uc_mac(struct net_device *netdev, const u8 *mac_addr)
{
	if (ether_addr_equal(mac_addr, netdev->dev_addr))
		return 0;

	return unic_update_mac_list(netdev, UNIC_COMM_ADDR_TO_DEL,
				    UNIC_MAC_ADDR_UC, mac_addr);
}

int unic_add_mc_mac(struct net_device *netdev, const u8 *mac_addr)
{
	return unic_update_mac_list(netdev, UNIC_COMM_ADDR_TO_ADD,
				    UNIC_MAC_ADDR_MC, mac_addr);
}

int unic_del_mc_mac(struct net_device *netdev, const u8 *mac_addr)
{
	return unic_update_mac_list(netdev, UNIC_COMM_ADDR_TO_DEL,
				    UNIC_MAC_ADDR_MC, mac_addr);
}

static int unic_get_mac_addr(struct unic_dev *unic_dev, u8 *p)
{
	struct unic_query_mac_addr_resp resp = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_MAC, true, 0, NULL);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_MAC, false, ETH_ALEN,
			     &resp);
	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret) {
		dev_err(unic_dev->comdev.adev->dev.parent,
			"failed to get mac address, ret = %d.\n", ret);
		return ret;
	}

	ether_addr_copy(p, resp.mac);

	return 0;
}

int unic_init_mac_addr(struct unic_dev *unic_dev)
{
	struct net_device *netdev = unic_dev->comdev.netdev;
	char format_mac[UNIC_FORMAT_MAC_LEN];
	u8 unic_addr[UNIC_ADDR_LEN] = {0};
	int ret;

	ret = unic_get_mac_addr(unic_dev, unic_addr);
	if (ret)
		return ret;

	/* Check if the MAC address is valid, if not get a random one */
	if (!is_valid_ether_addr(unic_addr)) {
		eth_hw_addr_random(netdev);
		ether_addr_copy(unic_addr, netdev->dev_addr);
		unic_comm_format_mac_addr(format_mac, unic_addr);
		dev_warn(unic_dev->comdev.adev->dev.parent,
			 "using random MAC address %s.\n", format_mac);
	} else {
		dev_addr_set(netdev, unic_addr);
		ether_addr_copy(netdev->perm_addr, unic_addr);
	}

	if (!unic_dev_cfg_mac_supported(unic_dev)) {
		ether_addr_copy(unic_dev->hw.mac.mac_addr, unic_addr);
		return 0;
	}

	ret = unic_cfg_mac_address(unic_dev, unic_addr);
	if (ret) {
		dev_err(unic_dev->comdev.adev->dev.parent,
			"failed to cfg MAC address, ret = %d!\n", ret);
		return ret;
	}

	ubase_set_dev_mac(unic_dev->comdev.adev, netdev->dev_addr,
			  netdev->addr_len);

	return 0;
}

void unic_uninit_mac_addr(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;
	struct unic_comm_addr_node *mac_node;
	u8 unic_addr[UNIC_ADDR_LEN] = {0};

	spin_lock_bh(&vport->addr_tbl.mac_list_lock);
	ether_addr_copy(unic_addr, unic_dev->comdev.netdev->dev_addr);
	mac_node = unic_comm_find_addr_node(&vport->addr_tbl.uc_mac_list,
					    unic_addr, UNIC_COMM_ADDR_NO_MASK);
	if (mac_node) {
		if (mac_node->state == UNIC_COMM_ADDR_TO_ADD) {
			list_del(&mac_node->node);
			kfree(mac_node);
		} else {
			mac_node->state = UNIC_COMM_ADDR_TO_DEL;
		}
	}

	set_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);
	spin_unlock_bh(&vport->addr_tbl.mac_list_lock);
}

static void unic_uninit_mac_table_common(struct unic_dev *unic_dev,
					 enum unic_mac_addr_type mac_type)
{
	struct unic_vport *vport = &unic_dev->vport;
	struct unic_comm_addr_node *mac_node, *tmp;
	struct list_head tmp_del_list, *list;

	INIT_LIST_HEAD(&tmp_del_list);

	list = (mac_type == UNIC_MAC_ADDR_UC) ?
	       &vport->addr_tbl.uc_mac_list : &vport->addr_tbl.mc_mac_list;

	spin_lock_bh(&vport->addr_tbl.mac_list_lock);

	list_for_each_entry_safe(mac_node, tmp, list, node) {
		switch (mac_node->state) {
		case UNIC_COMM_ADDR_TO_DEL:
		case UNIC_COMM_ADDR_ACTIVE:
			list_move_tail(&mac_node->node, &tmp_del_list);
			break;
		case UNIC_COMM_ADDR_TO_ADD:
			list_del(&mac_node->node);
			kfree(mac_node);
			break;
		default:
			break;
		}
	}

	spin_unlock_bh(&vport->addr_tbl.mac_list_lock);

	unic_unsync_mac_list(vport, &tmp_del_list, mac_type);

	if (!list_empty(&tmp_del_list))
		dev_warn(unic_dev->comdev.adev->dev.parent,
			 "uninit mac list not completely.\n");

	list_for_each_entry_safe(mac_node, tmp, &tmp_del_list, node) {
		list_del(&mac_node->node);
		kfree(mac_node);
	}
}

void unic_uninit_mac_table(struct unic_dev *unic_dev)
{
	unic_uninit_mac_table_common(unic_dev, UNIC_MAC_ADDR_UC);
	unic_uninit_mac_table_common(unic_dev, UNIC_MAC_ADDR_MC);
}

static void unic_deactivate_unsync_mac_list(struct unic_vport *vport,
					    struct list_head *list,
					    enum unic_mac_addr_type mac_type)
{
	struct unic_comm_addr_node *mac_node, *tmp;
	int ret;

	list_for_each_entry_safe(mac_node, tmp, list, node) {
		ret = unic_del_mac_addr_common(vport, mac_node->mac_addr,
					       mac_type, mac_node->is_pfc,
					       true);
		if (ret)
			break;

		if (mac_node->state == UNIC_COMM_ADDR_ACTIVE) {
			mac_node->state = UNIC_COMM_ADDR_TO_ADD;
		} else if (mac_node->state == UNIC_COMM_ADDR_TO_DEL) {
			list_del(&mac_node->node);
			kfree(mac_node);
		}
	}
}

static void unic_deactivate_update_mac_state(struct unic_comm_addr_node *mac_node,
					     enum UNIC_COMM_ADDR_STATE state)
{
	switch (state) {
	case UNIC_COMM_ADDR_TO_ADD:
		if (mac_node->state == UNIC_COMM_ADDR_TO_DEL) {
			list_del(&mac_node->node);
			kfree(mac_node);
		} else if (mac_node->state == UNIC_COMM_ADDR_ACTIVE) {
			mac_node->state = UNIC_COMM_ADDR_TO_ADD;
		}
		break;
	case UNIC_COMM_ADDR_TO_DEL:
		mac_node->state = UNIC_COMM_ADDR_ACTIVE;
		break;
	default:
		break;
	}
}

static void unic_deactivate_sync_from_del_list(struct list_head *del_list,
					       struct list_head *mac_list)
{
	struct unic_comm_addr_node *mac_node, *tmp, *new_node;

	list_for_each_entry_safe(mac_node, tmp, del_list, node) {
		new_node = unic_comm_find_addr_node(mac_list,
						    mac_node->unic_addr,
						    UNIC_COMM_ADDR_NO_MASK);
		if (new_node) {
			unic_deactivate_update_mac_state(new_node,
							 mac_node->state);
			list_del(&mac_node->node);
			kfree(mac_node);
		} else {
			list_move_tail(&mac_node->node, mac_list);
		}
	}
}

static void unic_deactivate_sync_mac_table(struct unic_vport *vport,
					   enum unic_mac_addr_type mac_type)
{
	struct unic_comm_addr_node *mac_node, *tmp, *new_node;
	struct list_head *mac_list, tmp_list;

	INIT_LIST_HEAD(&tmp_list);

	if (mac_type == UNIC_MAC_ADDR_UC)
		mac_list = &vport->addr_tbl.uc_mac_list;
	else
		mac_list = &vport->addr_tbl.mc_mac_list;

	spin_lock_bh(&vport->addr_tbl.mac_list_lock);

	list_for_each_entry_safe(mac_node, tmp, mac_list, node) {
		switch (mac_node->state) {
		case UNIC_COMM_ADDR_TO_DEL:
			list_move_tail(&mac_node->node, &tmp_list);
			break;
		case UNIC_COMM_ADDR_ACTIVE:
			new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
			if (!new_node)
				goto stop_traverse;
			memcpy(new_node->unic_addr, mac_node->unic_addr,
			       UNIC_ADDR_LEN);
			new_node->state = mac_node->state;
			new_node->is_pfc = mac_node->is_pfc;
			list_add_tail(&new_node->node, &tmp_list);
			break;
		default:
			break;
		}
	}

stop_traverse:
	spin_unlock_bh(&vport->addr_tbl.mac_list_lock);
	unic_deactivate_unsync_mac_list(vport, &tmp_list, mac_type);

	spin_lock_bh(&vport->addr_tbl.mac_list_lock);
	unic_deactivate_sync_from_del_list(&tmp_list, mac_list);
	spin_unlock_bh(&vport->addr_tbl.mac_list_lock);
}

void unic_deactivate_mac_table(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;

	unic_deactivate_sync_mac_table(vport, UNIC_MAC_ADDR_UC);
	unic_deactivate_sync_mac_table(vport, UNIC_MAC_ADDR_MC);
	set_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);
}

void unic_activate_mac_table(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;

	clear_bit(UNIC_VPORT_STATE_MAC_TBL_CHANGE, &vport->state);
	unic_sync_mac_table_common(vport, UNIC_MAC_ADDR_UC);
	unic_sync_mac_table_common(vport, UNIC_MAC_ADDR_MC);
}
