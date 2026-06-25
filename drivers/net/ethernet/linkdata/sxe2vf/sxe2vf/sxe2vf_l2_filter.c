// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_l2_filter.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/wait.h>
#include <linux/if_ether.h>

#include "sxe2vf.h"
#include "sxe2vf_rx.h"
#include "sxe2_log.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2vf_netdev.h"

static inline void
sxe2vf_switch_mac_node_del_and_free(struct sxe2vf_addr_node *mac_node)
{
	if (mac_node) {
		list_del(&mac_node->list);
		kfree(mac_node);
	}
}

struct sxe2vf_addr_node *sxe2vf_addr_find(struct sxe2vf_adapter *adapter,
					  const u8 *macaddr)
{
	struct sxe2vf_addr_node *f;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;

	list_for_each_entry(f, &filter->mac_addr_list, list) {
		if (ether_addr_equal(macaddr, f->mac.macaddr))
			return f;
	}
	return NULL;
}

static struct sxe2vf_addr_node *sxe2vf_addr_node_add(struct sxe2vf_adapter *adapter,
						     const u8 *macaddr)
{
	struct sxe2vf_addr_node *f = NULL;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;

	f = sxe2vf_addr_find(adapter, macaddr);
	if (!f) {
		f = kzalloc(sizeof(*f), GFP_KERNEL);
		if (!f) {
			LOG_ERROR_BDF("create list node for macaddr:%pM failed.\n",
				      macaddr);
			return f;
		}

		list_add_tail(&f->list, &filter->mac_addr_list);

		ether_addr_copy(f->mac.macaddr, macaddr);
	}

	f->mac.attr.is_vf_mac = (u8)ether_addr_equal(macaddr, filter->cur_mac_addr);

	LOG_INFO_BDF("mac list node addr:%pM attr:0x%x.\n", f->mac.macaddr,
		     *(u8 *)&f->mac.attr);

	return f;
}

s32 sxe2vf_addr_node_del(struct sxe2vf_adapter *adapter, const u8 *macaddr)
{
	s32 ret = 0;
	struct sxe2vf_addr_node *f;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;

	f = sxe2vf_addr_find(adapter, macaddr);
	if (!f) {
		LOG_ERROR_BDF("mac addr:%pM not exist\n", macaddr);
		ret = -EINVAL;
		goto l_out;
	}

	f->mac.attr.is_vf_mac = (u8)ether_addr_equal(macaddr, filter->cur_mac_addr);
	sxe2vf_switch_mac_node_del_and_free(f);

l_out:
	return ret;
}

static void sxe2vf_addr_list_clear(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	struct sxe2vf_addr_node *f;
	struct sxe2vf_addr_node *ftmp;

	list_for_each_entry_safe(f, ftmp, &filter->mac_addr_list, list) {
		sxe2vf_switch_mac_node_del_and_free(f);
		f = NULL;
	}
}

static void sxe2vf_vlan_list_clear(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	struct sxe2vf_vlan_node *vlan_node;
	struct sxe2vf_vlan_node *vlan_node_tmp;

	list_for_each_entry_safe(vlan_node, vlan_node_tmp, &vlan_info->vlan_list,
				 list) {
		list_del(&vlan_node->list);
		kfree(vlan_node);
		vlan_node = NULL;
	}
}

STATIC struct sxe2vf_addr_node *
sxe2vf_user_addr_find_unlock(struct sxe2vf_adapter *adapter, const u8 *macaddr)
{
	struct sxe2vf_addr_node *f;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.user_fltr_ctxt.mac_filter;

	list_for_each_entry(f, &filter->mac_addr_list, list) {
		if (ether_addr_equal(macaddr, f->mac.macaddr))
			return f;
	}
	return NULL;
}

int sxe2vf_mac_addr_add(struct sxe2vf_adapter *adapter, const u8 *addr,
			enum sxe2vf_mac_owner owner)
{
	s32 ret = 0;
	struct sxe2vf_addr_node *f;
	u16 vsi_id;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	lockdep_assert_held(&switch_ctxt->mac_addr_lock);

	f = sxe2vf_addr_node_add(adapter, addr);
	if (!f) {
		LOG_ERROR_BDF("add user mac addr:%pM node failed.\n", addr);
		return -ENOMEM;
	}

	if (is_multicast_ether_addr(addr) ||
	    !sxe2vf_user_addr_find_unlock(adapter, addr)) {
		vsi_id = adapter->vsi_ctxt.vf_vsi->vsi_id;
		if (f->usage == 0) {
			ret = sxe2vf_mac_msg_send(adapter, &f->mac, true, false,
						  vsi_id);
			if (ret) {
				LOG_ERROR_BDF("add mac %pM failed %d\n", addr, ret);
				(void)sxe2vf_addr_node_del(adapter, addr);
				return ret;
			}
		} else if (owner == SXE2VF_MAC_OWNER_NETDEV) {
			(void)sxe2vf_mac_msg_send(adapter, &f->mac, true, false,
						  vsi_id);
		}
	}

	set_bit((int)owner, &f->usage);

	LOG_INFO_BDF("add mac %pM done\n", addr);

	return ret;
}

int sxe2vf_mac_addr_del(struct sxe2vf_adapter *adapter, const u8 *addr,
			enum sxe2vf_mac_owner owner)
{
	s32 ret = 0;
	struct sxe2vf_addr_node *f;
	u16 vsi_id;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	lockdep_assert_held(&switch_ctxt->mac_addr_lock);

	f = sxe2vf_addr_find(adapter, addr);
	if (!f) {
		LOG_ERROR_BDF("mac addr:%pM not exist\n", addr);
		return -ENOENT;
	}

	clear_bit((int)owner, &f->usage);

	if (is_multicast_ether_addr(addr) ||
	    !sxe2vf_user_addr_find_unlock(adapter, addr)) {
		if (f->usage == 0) {
			vsi_id = adapter->vsi_ctxt.vf_vsi->vsi_id;
			ret = sxe2vf_mac_msg_send(adapter, &f->mac, false, false,
						  vsi_id);
			if (ret) {
				LOG_ERROR_BDF("del mac %pM failed err:%d\n", addr,
					      ret);
				set_bit((int)owner, &f->usage);
				goto l_out;
			} else {
				(void)sxe2vf_addr_node_del(adapter, addr);
			}
			LOG_INFO_BDF("del mac %pM done\n", addr);
		} else {
			LOG_INFO_BDF("Do not need to del mac %pM, because it is in \t"
				     "using\n",
				     addr);
		}
	} else {
		(void)sxe2vf_addr_node_del(adapter, addr);
	}

l_out:
	return ret;
}

#ifdef SXE2VF_MAC_VLAN_CLEAR

static int sxe2vf_mac_addr_clear(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	mutex_lock(&switch_ctxt->mac_addr_lock);
	ret = sxe2vf_mac_clear_msg_send(adapter);
	if (ret)
		LOG_INFO_BDF("clear mac list failed\n");

	sxe2vf_addr_list_clear(adapter);
	mutex_unlock(&switch_ctxt->mac_addr_lock);

	LOG_INFO_BDF("mac list clear.\n");

	return ret;
}

static int sxe2vf_vlan_clear(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	s32 ret = 0;

	mutex_lock(&vlan_info->vlan_lock);
	ret = sxe2vf_vlan_clear_msg_send(adapter);
	if (ret)
		LOG_INFO_BDF("clear vlan list failed\n");

	sxe2vf_vlan_list_clear(adapter);
	mutex_unlock(&vlan_info->vlan_lock);

	LOG_INFO_BDF("vlan list clear.\n");

	return ret;
}
#endif
s32 sxe2vf_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_sync_addr_node *f;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	s32 ret = 0;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f) {
		LOG_ERROR_BDF("create sync list node for macaddr:%pM failed.\n",
			      addr);
		ret = -ENOMEM;
		goto l_out;
	}

	list_add_tail(&f->list, &filter->tmp_sync_list);

	ether_addr_copy(f->macaddr, addr);

	LOG_INFO_BDF("mac list node sync addr:%pM.\n", f->macaddr);

l_out:
	return ret;
}

s32 sxe2vf_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_sync_addr_node *f;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	s32 ret = 0;

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f) {
		LOG_ERROR_BDF("create unsync list node for macaddr:%pM failed.\n",
			      addr);
		ret = -ENOMEM;
		goto l_out;
	}

	list_add_tail(&f->list, &filter->tmp_unsync_list);

	ether_addr_copy(f->macaddr, addr);

	LOG_INFO_BDF("mac list node unsync addr:%pM.\n", f->macaddr);

l_out:
	return ret;
}

int sxe2vf_set_mac_address(struct net_device *netdev, void *p)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	struct sxe2vf_addr_node *f;
	struct sockaddr *addr = p;
	u8 old[ETH_ALEN] = {0};
	s32 ret = 0;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	if (!is_valid_ether_addr(addr->sa_data)) {
		LOG_ERROR_BDF("invalid user mac addr:%pM\n", addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(netdev->dev_addr, addr->sa_data)) {
		LOG_ERROR_BDF("user mac addr:%pM equal cur mac addr, skip set\n",
			      addr->sa_data);
		return ret;
	}

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, adapter->vsi_ctxt.vf_vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		(void)mutex_unlock(&adapter->vsi_ctxt.lock);
		return -EBUSY;
	}

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	f = sxe2vf_addr_find(adapter, filter->cur_mac_addr);
	if (f) {
		ether_addr_copy(old, f->mac.macaddr);

		ret = sxe2vf_mac_addr_del(adapter, old, SXE2VF_MAC_OWNER_NETDEV);
		if (ret)
			LOG_ERROR_BDF("del mac addr:%pM failed.\n", old);
	}

	ether_addr_copy(filter->cur_mac_addr, addr->sa_data);

	ret = sxe2vf_mac_addr_add(adapter, addr->sa_data, SXE2VF_MAC_OWNER_NETDEV);
	if (ret) {
		LOG_ERROR_BDF("add mac addr:%pM failed.\n", addr->sa_data);
		goto l_rollback;
	} else {
		if (!ether_addr_equal(netdev->dev_addr, filter->cur_mac_addr)) {
			eth_hw_addr_set(netdev, filter->cur_mac_addr);
			LOG_INFO_BDF("vf mac change to %pM.\n",
				     filter->cur_mac_addr);
		}
	}
	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);

	(void)mutex_unlock(&adapter->vsi_ctxt.lock);

	LOG_INFO_BDF("set mac %pM ret:%d.\n", addr->sa_data, ret);

	return ret;

l_rollback:

	if (sxe2vf_mac_addr_add(adapter, old, SXE2VF_MAC_OWNER_NETDEV))
		LOG_ERROR_BDF("rollback add old mac addr:%pM failed.\n", old);

	f = sxe2vf_addr_find(adapter, old);
	if (f)
		f->mac.attr.is_vf_mac = 1;

	f = sxe2vf_addr_find(adapter, addr->sa_data);
	if (f)
		f->mac.attr.is_vf_mac = 0;

	ether_addr_copy(filter->cur_mac_addr, old);

	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);

	(void)mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

bool sxe2vf_promisc_mode_changed(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	(void)netdev;
	return (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags ^ netdev->flags) &
	       (IFF_PROMISC | IFF_ALLMULTI);
}

void sxe2vf_set_rx_mode(struct net_device *netdev)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	set_bit(SXE2VF_FLAG_FLTR_SYNC, adapter->flags);

	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);
}

#define SET_ENABLE_FLAG_BY_VLAN_TAG(member, NET_FLAG)                               \
	do {                                                                        \
		typeof(NET_FLAG) _NET_FLAG = (NET_FLAG);                            \
		typeof(member) *_member = &(member);                                \
		LOG_INFO_BDF("feature request %llx dev %llx\n",                     \
			     request & (_NET_FLAG), *dev_features & (_NET_FLAG));   \
		if ((request & (_NET_FLAG)) ^ (*dev_features & (_NET_FLAG))) {     \
			*_member = false;                                           \
			if (request & (_NET_FLAG))                                  \
				*_member = true;                                    \
			LOG_INFO_BDF("dev_request  %llx\n", *dev_features);         \
		}                                                                   \
	} while (0)
s32 sxe2vf_vlan_filter_cfg(struct net_device *netdev, netdev_features_t request)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vlan_filter *filter_offload =
			&adapter->switch_ctxt.filter_ctxt.vlan_info.filter_offload;
	netdev_features_t *dev_features =
			&adapter->switch_ctxt.filter_ctxt.vlan_info.dev_features;
	if (adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist)
		request &= ~SXE2VF_VLAN_FILTER_FEATURES;

	(void)memset(filter_offload, SXE2_VF_VLAN_STATUS_INVALID,
		     sizeof(*filter_offload));

	SET_ENABLE_FLAG_BY_VLAN_TAG(filter_offload->ctag_filter_enable,
				    NETIF_F_HW_VLAN_CTAG_FILTER);
	SET_ENABLE_FLAG_BY_VLAN_TAG(filter_offload->stag_filter_enable,
				    NETIF_F_HW_VLAN_STAG_FILTER);

	if (filter_offload->ctag_filter_enable != SXE2_VF_VLAN_STATUS_INVALID) {
		ret = sxe2vf_vlan_filter_msg_send(adapter, false);
		if (!ret) {
			*dev_features &= ~(NETIF_F_HW_VLAN_CTAG_FILTER |
					   NETIF_F_HW_VLAN_STAG_FILTER);
			*dev_features |= (request & (NETIF_F_HW_VLAN_CTAG_FILTER |
						     NETIF_F_HW_VLAN_STAG_FILTER));
		}
	}
	LOG_INFO_BDF("ctag_filter_enable:%u stag_filter_enable:%u.\n",
		     filter_offload->ctag_filter_enable,
		     filter_offload->stag_filter_enable);
	return ret;
}

#ifdef SXE2VF_MAC_VLAN_CLEAR
void sxe2vf_l2_filter_clear(struct sxe2vf_adapter *adapter)
{
	sxe2vf_mac_addr_clear(adapter);

	sxe2vf_vlan_clear(adapter);
}
#endif

void sxe2vf_filter_list_destroy(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);
	sxe2vf_addr_list_clear(adapter);
	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);

	(void)mutex_lock(&vlan_info->vlan_lock);
	sxe2vf_vlan_list_clear(adapter);
	(void)mutex_unlock(&vlan_info->vlan_lock);
}

void sxe2vf_vlan_feature_update(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	u8 port_vlan_exist = vlan_info->port_vlan_exist;
	u8 is_switchdev = vlan_info->is_switchdev;

	if (port_vlan_exist) {
		netdev->features &=
				~(SXE2VF_VLAN_FILTER_FEATURES |
				  NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX);
		netdev->hw_features &=
				~(SXE2VF_VLAN_FILTER_FEATURES |
				  NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX);
	}

	if (is_switchdev) {
		netdev->features &=
				~(SXE2VF_VLAN_FILTER_FEATURES |
				  NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX |
				  NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);
		netdev->hw_features &=
				~(SXE2VF_VLAN_FILTER_FEATURES |
				  NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX |
				  NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);
	}

	LOG_INFO_BDF("feature:0x%llx hw_feature:0x%llx.\n", netdev->features,
		     netdev->hw_features);
}

s32 sxe2vf_vlan_offload_cfg(struct net_device *netdev, netdev_features_t request)
{
	s32 ret = 0;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	struct sxe2vf_vlan_offload *vlan_offload = &vlan_info->vlan_offload;
	netdev_features_t *dev_features = &vlan_info->dev_features;

	if (vlan_info->port_vlan_exist) {
		LOG_INFO_BDF("port vlan exist, disable stag offload.\n");
		request &= ~(NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX);
	}

	(void)memset(vlan_offload, SXE2_VF_VLAN_STATUS_INVALID,
		     sizeof(*vlan_offload));

	SET_ENABLE_FLAG_BY_VLAN_TAG(vlan_offload->stag_strip_enable,
				    NETIF_F_HW_VLAN_STAG_RX);
	SET_ENABLE_FLAG_BY_VLAN_TAG(vlan_offload->stag_insert_enable,
				    NETIF_F_HW_VLAN_STAG_TX);
	SET_ENABLE_FLAG_BY_VLAN_TAG(vlan_offload->ctag_strip_enable,
				    NETIF_F_HW_VLAN_CTAG_RX);
	SET_ENABLE_FLAG_BY_VLAN_TAG(vlan_offload->ctag_insert_enable,
				    NETIF_F_HW_VLAN_CTAG_TX);

	ret = sxe2vf_vlan_offload_msg_send(adapter);
	if (!ret) {
		*dev_features &=
				~(NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX |
				  NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX);
		*dev_features |= (request & (NETIF_F_HW_VLAN_STAG_RX |
					     NETIF_F_HW_VLAN_STAG_TX |
					     NETIF_F_HW_VLAN_CTAG_RX |
					     NETIF_F_HW_VLAN_CTAG_TX));
	}

	LOG_INFO_BDF("ctag_strip:%u stag_strip:%u\t"
		     " ctag_insert:%u stag_insert:%u.\n",
		     vlan_offload->ctag_strip_enable,
		     vlan_offload->stag_strip_enable,
		     vlan_offload->ctag_insert_enable,
		     vlan_offload->stag_insert_enable);
	return ret;
}

s32 sxe2vf_vlan_cfg(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	netdev_features_t req;

	sxe2vf_vlan_feature_update(adapter);
	req = adapter->netdev->features;
	(void)req;
	ret = sxe2vf_vlan_filter_cfg(adapter->netdev, req);
	if (ret)
		return ret;

	ret = sxe2vf_vlan_offload_cfg(adapter->netdev, req);
	return ret;
}

s32 sxe2vf_vlan_cfg_rebuild(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	if (!adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist &&
	    !adapter->switch_ctxt.filter_ctxt.vlan_info.is_switchdev) {
		adapter->netdev->hw_features |=
				NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX;
		adapter->netdev->features |= SXE2VF_VLAN_FILTER_FEATURES;
	} else {
		adapter->netdev->features &= ~SXE2VF_VLAN_FILTER_FEATURES;
	}

	ret = sxe2vf_vlan_filter_cfg(adapter->netdev, adapter->netdev->features);
	if (ret)
		return ret;

	ret = sxe2vf_vlan_offload_cfg(adapter->netdev, adapter->netdev->features);
	return ret;
}

static struct sxe2vf_vlan_node *sxe2vf_vlan_find(struct sxe2vf_adapter *adapter,
						 struct sxe2vf_vlan vlan)
{
	struct sxe2vf_vlan_node *f;
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;

	list_for_each_entry(f, &vlan_info->vlan_list, list) {
		if (f->vlan.vid == vlan.vid && f->vlan.tpid == vlan.tpid)
			return f;
	}

	return NULL;
}

bool sxe2vf_vlan_cnt_is_valid(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;

	return vlan_info->cnt < vlan_info->max_cnt;
}

STATIC int sxe2vf_vlan_process(struct sxe2vf_adapter *adapter,
			       struct sxe2vf_vlan vlan, bool add)
{
	int ret = 0;
	struct sxe2vf_vlan_node *f = NULL;
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;

	(void)mutex_lock(&vlan_info->vlan_lock);

	if (add) {
		f = sxe2vf_vlan_find(adapter, vlan);
		if (f)
			goto l_unlock;

		if (!sxe2vf_vlan_cnt_is_valid(adapter)) {
			LOG_DEV_ERR("vlan cnt:%u exceed max support cnt:%u, try to \t"
				    "delete\t"
				    "or disable exists vlans.\n",
				    vlan_info->cnt, vlan_info->max_cnt);
			ret = -EPERM;
			goto l_unlock;
		}

		f = kzalloc(sizeof(*f), GFP_KERNEL);
		if (!f) {
			LOG_ERROR_BDF("vlan tpid:%u vid:%u prio:%u alloc failed.\n",
				      vlan.tpid, vlan.vid, vlan.prio);
			ret = -ENOMEM;
			goto l_unlock;
		}

		ret = sxe2vf_vlan_msg_send(adapter, &vlan, true);
		if (ret == -EEXIST) {
			ret = 0;
		} else if (ret) {
			LOG_ERROR_BDF("add vlan mbx msg send failed ret %d.\n", ret);
			kfree(f);
			goto l_unlock;
		}

		f->vlan = vlan;
		list_add_tail(&f->list, &vlan_info->vlan_list);
		vlan_info->cnt++;
	} else {
		f = sxe2vf_vlan_find(adapter, vlan);
		if (!f)
			goto l_unlock;

		ret = sxe2vf_vlan_msg_send(adapter, &vlan, false);
		if (ret == -ENOENT) {
			ret = 0;
		} else if (ret) {
			LOG_ERROR_BDF("add vlan mbx msg send failed ret %d.\n", ret);
			goto l_unlock;
		}

		list_del(&f->list);
		kfree(f);
		vlan_info->cnt--;
	}

l_unlock:
	(void)mutex_unlock(&vlan_info->vlan_lock);
	return ret;
}

int sxe2vf_vlan_rx_add_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vlan vlan;
	u16 proto_u16;
	int ret = 0;

	if (!vid && be16_to_cpu(proto) == ETH_P_8021Q)
		return 0;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);

	if (test_bit(SXE2VF_VSI_DISABLE, adapter->vsi_ctxt.vf_vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		ret = -EBUSY;
		goto l_unlock;
	}
	proto_u16 = be16_to_cpu(proto);
	vlan = SXE2VF_VLAN(proto_u16, vid, 0);

	ret = sxe2vf_vlan_process(adapter, vlan, true);
	if (ret) {
		LOG_ERROR_BDF("add vlan failed ret:%d.\n", ret);
		goto l_unlock;
	}

	LOG_INFO_BDF("vlan tpid:0x%x vid:%u prio:%u add request.\n", vlan.tpid,
		     vlan.vid, vlan.prio);

l_unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

int sxe2vf_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_vlan vlan;
	u16 proto_u16;
	int ret = 0;

	if (!vid && be16_to_cpu(proto) == ETH_P_8021Q)
		return 0;

	(void)mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_VSI_DISABLE, adapter->vsi_ctxt.vf_vsi->state)) {
		LOG_INFO_BDF("vsi disabled, try later\n");
		ret = -EBUSY;
		goto l_unlock;
	}
	proto_u16 = be16_to_cpu(proto);
	vlan = SXE2VF_VLAN(proto_u16, vid, 0);

	ret = sxe2vf_vlan_process(adapter, vlan, false);
	if (ret) {
		LOG_ERROR_BDF("del vlan failed ret:%d.\n", ret);
		goto l_unlock;
	}

	LOG_INFO_BDF("vlan tag:0x%x delete request.\n", *(u16 *)&vlan);

l_unlock:
	(void)mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}

s32 sxe2vf_l2_filter_cfg_sync(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	struct sxe2vf_sync_addr_node *list_itr = NULL;
	struct sxe2vf_sync_addr_node *tmp = NULL;
	s32 ret = 0;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	if (!test_bit(SXE2VF_FLAG_FLTR_SYNC, adapter->flags))
		return 0;

	clear_bit(SXE2VF_FLAG_FLTR_SYNC, adapter->flags);

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	INIT_LIST_HEAD(&filter->tmp_sync_list);
	INIT_LIST_HEAD(&filter->tmp_unsync_list);

	netif_addr_lock_bh(netdev);
	(void)__dev_uc_sync(netdev, sxe2vf_addr_sync, sxe2vf_addr_unsync);
	(void)__dev_mc_sync(netdev, sxe2vf_addr_sync, sxe2vf_addr_unsync);
	netif_addr_unlock_bh(netdev);

	list_for_each_entry_safe(list_itr, tmp, &filter->tmp_sync_list, list) {
		ret = sxe2vf_mac_addr_add(adapter, list_itr->macaddr,
					  SXE2VF_MAC_OWNER_UC_MC);
		if (ret == -EEXIST) {
			LOG_WARN_BDF("mac filter exist, addr %pM\n",
				     list_itr->macaddr);
		} else if (ret) {
			LOG_DEV_ERR("add mac filter failed, addr %pM, ret %d\n",
				    list_itr->macaddr, ret);
		}
		list_del(&list_itr->list);
		kfree(list_itr);
		list_itr = NULL;
	}

	list_for_each_entry_safe(list_itr, tmp, &filter->tmp_unsync_list, list) {
		ret = sxe2vf_mac_addr_del(adapter, list_itr->macaddr,
					  SXE2VF_MAC_OWNER_UC_MC);
		if (ret == -ENOENT) {
			LOG_WARN_BDF("mac filter not exist, addr %pM\n",
				     list_itr->macaddr);
		} else if (ret) {
			LOG_DEV_ERR("delete mac filter failed, addr %pM, ret %d\n",
				    list_itr->macaddr, ret);
		}
		list_del(&list_itr->list);
		kfree(list_itr);
		list_itr = NULL;
	}

	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);

	rtnl_lock();
	ret = sxe2vf_promisc_set_msg_send(adapter);
	rtnl_unlock();
	if (ret)
		LOG_ERROR_BDF("promisc set mbx msg send failed ret %d.\n", ret);

	return ret;
}

s32 sxe2vf_dev_mac_add(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	s32 ret;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);
	ret = sxe2vf_mac_addr_add(adapter, filter->cur_mac_addr,
				  SXE2VF_MAC_OWNER_NETDEV);
	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);

	if (ret) {
		LOG_ERROR_BDF("vf dev mac:%pM add failed.\n", filter->cur_mac_addr);
		return ret;
	}

	if (is_valid_ether_addr(filter->cur_mac_addr) &&
	    !ether_addr_equal(adapter->netdev->dev_addr, filter->cur_mac_addr)) {
		LOG_WARN_BDF("change vf dev mac from %pM to %pM.\n",
			     adapter->netdev->dev_addr, filter->cur_mac_addr);
		eth_hw_addr_set(adapter->netdev, filter->cur_mac_addr);
	}

	return ret;
}

static void sxe2vf_vlan_rules_restore(struct sxe2vf_adapter *adapter)
{
	s32 ret;
	struct sxe2vf_vlan_node *f;
	struct sxe2vf_vlan_node *tmp = NULL;
	struct sxe2vf_vlan_info *vlan_info =
			&adapter->switch_ctxt.filter_ctxt.vlan_info;
	struct sxe2vf_vlan vlan;

	(void)mutex_lock(&vlan_info->vlan_lock);

	list_for_each_entry_safe(f, tmp, &vlan_info->vlan_list, list) {
		vlan = SXE2VF_VLAN(f->vlan.tpid, f->vlan.vid, f->vlan.prio);
		ret = sxe2vf_vlan_msg_send(adapter, &vlan, true);
		if (ret && (ret != -EEXIST)) {
			LOG_DEV_ERR("add vlan filter tpid:0x%x vid:%u prio:%u \t"
				    "failed ret %d\n",
				    vlan.tpid, vlan.vid, vlan.prio, ret);
			list_del(&f->list);
			kfree(f);
			vlan_info->cnt--;
		}
	}

	(void)mutex_unlock(&vlan_info->vlan_lock);
}

static void sxe2vf_mac_rules_restore(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mac_filter *filter =
			&adapter->switch_ctxt.filter_ctxt.mac_filter;
	struct sxe2vf_addr_node *f;
	struct sxe2vf_addr_node *tmp = NULL;
	u16 vsi_id = adapter->vsi_ctxt.vf_vsi->vsi_id;
	s32 ret;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	list_for_each_entry_safe(f, tmp, &filter->mac_addr_list, list) {
		if (ether_addr_equal(filter->cur_mac_addr, f->mac.macaddr))
			continue;
		ret = sxe2vf_mac_msg_send(adapter, &f->mac, true, false, vsi_id);
		if (ret && (ret != -EEXIST)) {
			LOG_ERROR_BDF("restore mac %pM, usage %lx failed %d\n",
				      f->mac.macaddr, f->usage, ret);
			sxe2vf_switch_mac_node_del_and_free(f);
		}
	}

	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);
}

static void sxe2vf_promisc_rules_restore(struct sxe2vf_adapter *adapter)
{
	struct sxe2_vf_promisc_msg msg = {0};
	u32 promisc_flags = 0;
	s32 ret = 0;

	if (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_ALLMULTI)
		promisc_flags |= SXE2_VF_PROMISC_MULTICAST;
	if (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC)
		promisc_flags |= SXE2_VF_PROMISC | SXE2_VF_PROMISC_MULTICAST;

	if (adapter->netdev->features & NETIF_F_HW_VLAN_CTAG_FILTER)
		promisc_flags |= SXE2_VF_VLAN_FILTER;

	msg.vsi_id = cpu_to_le16(adapter->vsi_ctxt.vf_vsi->vsi_id);
	msg.flags = cpu_to_le32(promisc_flags);

	ret = sxe2vf_mbx_common_msg_send(adapter, SXE2_VF_PROMISC_CFG, (u8 *)&msg,
					 sizeof(msg));
	if (ret)
		LOG_ERROR_BDF("set promisc msg handle result:%d.\n", ret);
}

void sxe2vf_l2_filter_rules_restore(struct sxe2vf_adapter *adapter)
{
	if (sxe2vf_dev_mac_add(adapter))
		return;

	sxe2vf_mac_rules_restore(adapter);

	if (!adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist &&
	    !adapter->switch_ctxt.filter_ctxt.vlan_info.is_switchdev) {
		sxe2vf_vlan_rules_restore(adapter);
	}

	sxe2vf_promisc_rules_restore(adapter);
}

STATIC s32 sxe2vf_ucmd_com_mode_unicast_mac_add(struct sxe2vf_adapter *adapter,
						u16 vsi_id, const u8 *addr)
{
	s32 ret = 0;
	struct sxe2vf_mac_filter *user_mac_fltr;
	struct sxe2vf_addr_node *eth_mac_node;
	struct sxe2vf_addr_node *user_mac_node;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u add unicast mac %pM\n", vsi_id, addr);

	user_mac_fltr = &adapter->switch_ctxt.user_fltr_ctxt.mac_filter;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2vf_user_addr_find_unlock(adapter, addr);
	if (user_mac_node) {
		LOG_ERROR_BDF("mac:%pM has been in user mac list.\n", addr);
		ret = -EEXIST;
		goto l_end;
	}

	user_mac_node = kzalloc(sizeof(*user_mac_node), GFP_KERNEL);
	if (!user_mac_node) {
		LOG_ERROR_BDF("create list node for macaddr:%pM failed.\n", addr);
		ret = -ENOMEM;
		goto l_end;
	}

	ether_addr_copy(user_mac_node->mac.macaddr, addr);

	eth_mac_node = sxe2vf_addr_find(adapter, addr);
	if (eth_mac_node) {
		ret = sxe2vf_mac_update_msg_send(adapter, addr, true);
		if (ret) {
			LOG_ERROR_BDF("mac %pM rule update to user failed %d\n",
				      addr, ret);
			kfree(user_mac_node);
			goto l_end;
		}
	} else {
		ret = sxe2vf_mac_msg_send(adapter, &user_mac_node->mac, true, true,
					  vsi_id);
		if (ret) {
			LOG_ERROR_BDF("user add mac %pM failed %d\n", addr, ret);
			kfree(user_mac_node);
			goto l_end;
		}
	}

	list_add_tail(&user_mac_node->list, &user_mac_fltr->mac_addr_list);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

STATIC s32 sxe2vf_ucmd_user_mode_unicast_mac_add(struct sxe2vf_adapter *adapter,
						 u16 vsi_id, const u8 *addr)
{
	s32 ret = 0;
	struct sxe2vf_mac_filter *user_mac_fltr;
	struct sxe2vf_addr_node *user_mac_node;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u add unicast mac %pM\n", vsi_id, addr);

	user_mac_fltr = &adapter->switch_ctxt.user_fltr_ctxt.mac_filter;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2vf_user_addr_find_unlock(adapter, addr);
	if (user_mac_node) {
		LOG_ERROR_BDF("mac:%pM has been in user mac list.\n", addr);
		ret = -EEXIST;
		goto l_end;
	}

	user_mac_node = kzalloc(sizeof(*user_mac_node), GFP_KERNEL);
	if (!user_mac_node) {
		LOG_ERROR_BDF("create list node for macaddr:%pM failed.\n", addr);
		ret = -ENOMEM;
		goto l_end;
	}

	ether_addr_copy(user_mac_node->mac.macaddr, addr);

	ret = sxe2vf_mac_msg_send(adapter, &user_mac_node->mac, true, true, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user add mac %pM failed %d\n", addr, ret);
		kfree(user_mac_node);
		goto l_end;
	}

	list_add_tail(&user_mac_node->list, &user_mac_fltr->mac_addr_list);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

s32 sxe2vf_ucmd_unicast_mac_add(struct sxe2vf_adapter *adapter, u16 vsi_id,
				const u8 *addr)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2vf_ucmd_user_mode_unicast_mac_add(adapter, vsi_id, addr);
	else
		ret = sxe2vf_ucmd_com_mode_unicast_mac_add(adapter, vsi_id, addr);

	return ret;
}

STATIC s32 sxe2vf_ucmd_com_mode_unicast_mac_del(struct sxe2vf_adapter *adapter,
						u16 vsi_id, const u8 *addr)
{
	s32 ret = 0;
	struct sxe2vf_addr_node *eth_mac_node;
	struct sxe2vf_addr_node *user_mac_node;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u del unicast mac %pM\n", vsi_id, addr);

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2vf_user_addr_find_unlock(adapter, addr);
	if (!user_mac_node) {
		LOG_WARN_BDF("mac:%pM is not in user mac list.\n", addr);
		goto l_end;
	}

	eth_mac_node = sxe2vf_addr_find(adapter, addr);
	if (eth_mac_node) {
		ret = sxe2vf_mac_update_msg_send(adapter, addr, false);
		if (ret) {
			LOG_ERROR_BDF("mac %pM rule update to kernel failed %d\n",
				      addr, ret);
			goto l_end;
		}
	} else {
		ret = sxe2vf_mac_msg_send(adapter, &user_mac_node->mac, false, true,
					  vsi_id);
		if (ret) {
			LOG_ERROR_BDF("user del mac %pM failed %d\n", addr, ret);
			goto l_end;
		}
	}

	sxe2vf_switch_mac_node_del_and_free(user_mac_node);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

STATIC s32 sxe2vf_ucmd_user_mode_unicast_mac_del(struct sxe2vf_adapter *adapter,
						 u16 vsi_id, const u8 *addr)
{
	s32 ret = 0;
	struct sxe2vf_addr_node *user_mac_node;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u del unicast mac %pM\n", vsi_id, addr);

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2vf_user_addr_find_unlock(adapter, addr);
	if (!user_mac_node) {
		LOG_WARN_BDF("mac:%pM is not in user mac list.\n", addr);
		goto l_end;
	}

	ret = sxe2vf_mac_msg_send(adapter, &user_mac_node->mac, false, true, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user del mac %pM failed %d\n", addr, ret);
		goto l_end;
	}

	sxe2vf_switch_mac_node_del_and_free(user_mac_node);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

s32 sxe2vf_ucmd_unicast_mac_del(struct sxe2vf_adapter *adapter, u16 vsi_id,
				const u8 *addr)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2vf_ucmd_user_mode_unicast_mac_del(adapter, vsi_id, addr);
	else
		ret = sxe2vf_ucmd_com_mode_unicast_mac_del(adapter, vsi_id, addr);

	return ret;
}

int sxe2vf_ucmd_multi_broad_mac_add(struct sxe2vf_adapter *adapter, u16 vsi_id,
				    const u8 *addr)
{
	s32 ret = 0;
	struct sxe2vf_mac_filter *user_mac_fltr;
	struct sxe2vf_addr_node *user_mac_node;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u add multi broad mac %pM\n", vsi_id, addr);

	user_mac_fltr = &adapter->switch_ctxt.user_fltr_ctxt.mac_filter;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2vf_user_addr_find_unlock(adapter, addr);
	if (user_mac_node) {
		LOG_ERROR_BDF("mac:%pM has been in user mac list.\n", addr);
		ret = -EEXIST;
		goto l_end;
	}

	user_mac_node = kzalloc(sizeof(*user_mac_node), GFP_KERNEL);
	if (!user_mac_node) {
		LOG_ERROR_BDF("create list node for macaddr:%pM failed.\n", addr);
		ret = -ENOMEM;
		goto l_end;
	}

	ether_addr_copy(user_mac_node->mac.macaddr, addr);

	ret = sxe2vf_mac_msg_send(adapter, &user_mac_node->mac, true, true, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user add mac %pM failed %d\n", addr, ret);
		kfree(user_mac_node);
		goto l_end;
	}

	list_add_tail(&user_mac_node->list, &user_mac_fltr->mac_addr_list);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

int sxe2vf_ucmd_multi_broad_mac_del(struct sxe2vf_adapter *adapter, u16 vsi_id,
				    const u8 *addr)
{
	s32 ret = 0;
	struct sxe2vf_addr_node *user_mac_node;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u del multi broad mac %pM\n", vsi_id, addr);

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	user_mac_node = sxe2vf_user_addr_find_unlock(adapter, addr);
	if (!user_mac_node) {
		LOG_WARN_BDF("mac:%pM is not in user mac list.\n", addr);
		goto l_end;
	}

	ret = sxe2vf_mac_msg_send(adapter, &user_mac_node->mac, false, true, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user del mac %pM failed %d\n", addr, ret);
		goto l_end;
	}

	sxe2vf_switch_mac_node_del_and_free(user_mac_node);

l_end:
	mutex_unlock(&switch_ctxt->mac_addr_lock);
	return ret;
}

STATIC int sxe2vf_ucmd_com_mode_promisc_rule_add(struct sxe2vf_adapter *adapter,
						 u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u add promisc rule\n", vsi_id);

	mutex_lock(&adapter->switch_ctxt.flag_lock);
	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_PROMISC) {
		LOG_ERROR_BDF("user vf has been set promisc\n");
		ret = -EEXIST;
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |= IFF_PROMISC;
	if (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC) {
		ret = sxe2vf_user_promisc_update_msg_send(adapter, vsi_id, true,
							  true);
		if (ret) {
			LOG_ERROR_BDF("promisc rule update to user failed %d\n",
				      ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
					(~IFF_PROMISC);
		}
	} else {
		ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
		if (ret) {
			LOG_ERROR_BDF("user set promisc failed %d\n", ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
					(~IFF_PROMISC);
		}
	}

l_end:
	mutex_unlock(&adapter->switch_ctxt.flag_lock);
	return ret;
}

STATIC int sxe2vf_ucmd_user_mode_promisc_rule_add(struct sxe2vf_adapter *adapter,
						  u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u add promisc rule\n", vsi_id);

	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_PROMISC) {
		LOG_ERROR_BDF("user vf has been set promisc\n");
		ret = -EEXIST;
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |= IFF_PROMISC;
	ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user set promisc failed %d\n", ret);
		adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
				(~IFF_PROMISC);
	}

l_end:
	return ret;
}

int sxe2vf_ucmd_promisc_rule_add(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2vf_ucmd_user_mode_promisc_rule_add(adapter, vsi_id);
	else
		ret = sxe2vf_ucmd_com_mode_promisc_rule_add(adapter, vsi_id);

	return ret;
}

STATIC int sxe2vf_ucmd_com_mode_promisc_rule_del(struct sxe2vf_adapter *adapter,
						 u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u del promisc rule\n", vsi_id);

	mutex_lock(&adapter->switch_ctxt.flag_lock);
	if (!(adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_PROMISC)) {
		LOG_WARN_BDF("user vf has not been set promisc\n");
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &= (~IFF_PROMISC);
	if (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC) {
		ret = sxe2vf_user_promisc_update_msg_send(adapter, vsi_id, false,
							  true);
		if (ret) {
			LOG_ERROR_BDF("promisc rule update to kernel failed %d\n",
				      ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |=
					IFF_PROMISC;
		}
	} else {
		ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
		if (ret) {
			LOG_ERROR_BDF("user set promisc failed %d\n", ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |=
					IFF_PROMISC;
		}
	}

l_end:
	mutex_unlock(&adapter->switch_ctxt.flag_lock);
	return ret;
}

STATIC int sxe2vf_ucmd_user_mode_promisc_rule_del(struct sxe2vf_adapter *adapter,
						  u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u del promisc rule\n", vsi_id);

	if (!(adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_PROMISC)) {
		LOG_WARN_BDF("user vf has not been set promisc\n");
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &= (~IFF_PROMISC);
	ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user set promisc failed %d\n", ret);
		adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |= IFF_PROMISC;
	}

l_end:
	return ret;
}

int sxe2vf_ucmd_promisc_rule_del(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2vf_ucmd_user_mode_promisc_rule_del(adapter, vsi_id);
	else
		ret = sxe2vf_ucmd_com_mode_promisc_rule_del(adapter, vsi_id);

	return ret;
}

STATIC int sxe2vf_ucmd_com_mode_allmulti_rule_add(struct sxe2vf_adapter *adapter,
						  u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u add allmulti rule\n", vsi_id);

	mutex_lock(&adapter->switch_ctxt.flag_lock);
	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_ALLMULTI) {
		LOG_ERROR_BDF("user vf has been set promisc\n");
		ret = -EEXIST;
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |= IFF_ALLMULTI;
	if ((adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_ALLMULTI) ||
	    (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC)) {
		ret = sxe2vf_user_promisc_update_msg_send(adapter, vsi_id, true,
							  false);
		if (ret) {
			LOG_ERROR_BDF("allmulti rule update to user failed %d\n",
				      ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
					(~IFF_ALLMULTI);
		}
	} else {
		ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
		if (ret) {
			LOG_ERROR_BDF("user set promisc failed %d\n", ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
					(~IFF_ALLMULTI);
		}
	}

l_end:
	mutex_unlock(&adapter->switch_ctxt.flag_lock);
	return ret;
}

STATIC int sxe2vf_ucmd_user_mode_allmulti_rule_add(struct sxe2vf_adapter *adapter,
						   u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u add allmulti rule\n", vsi_id);

	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_ALLMULTI) {
		LOG_ERROR_BDF("user vf has been set promisc\n");
		ret = -EEXIST;
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |= IFF_ALLMULTI;
	ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user set promisc failed %d\n", ret);
		adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
				(~IFF_ALLMULTI);
	}

l_end:
	return ret;
}

int sxe2vf_ucmd_allmulti_rule_add(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2vf_ucmd_user_mode_allmulti_rule_add(adapter, vsi_id);
	else
		ret = sxe2vf_ucmd_com_mode_allmulti_rule_add(adapter, vsi_id);

	return ret;
}

STATIC int sxe2vf_ucmd_com_mode_allmulti_rule_del(struct sxe2vf_adapter *adapter,
						  u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u del allmulti rule\n", vsi_id);

	mutex_lock(&adapter->switch_ctxt.flag_lock);
	if (!(adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &
	      IFF_ALLMULTI)) {
		LOG_WARN_BDF("user vf has not been set allmulti\n");
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &= (~IFF_ALLMULTI);
	if ((adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_ALLMULTI) ||
	    (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC)) {
		ret = sxe2vf_user_promisc_update_msg_send(adapter, vsi_id, false,
							  false);
		if (ret) {
			LOG_ERROR_BDF("allmulti rule update to kernel failed %d\n",
				      ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |=
					IFF_ALLMULTI;
		}
	} else {
		ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
		if (ret) {
			LOG_ERROR_BDF("user set allmulti failed %d\n", ret);
			adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |=
					IFF_PROMISC;
		}
	}

l_end:
	mutex_unlock(&adapter->switch_ctxt.flag_lock);
	return ret;
}

STATIC int sxe2vf_ucmd_user_mode_allmulti_rule_del(struct sxe2vf_adapter *adapter,
						   u16 vsi_id)
{
	s32 ret = 0;

	LOG_INFO_BDF("User vf vsi:%u del allmulti rule\n", vsi_id);

	if (!(adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &
	      IFF_ALLMULTI)) {
		LOG_WARN_BDF("user vf has not been set allmulti\n");
		goto l_end;
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &= (~IFF_ALLMULTI);
	ret = sxe2vf_user_promisc_set_msg_send(adapter, vsi_id);
	if (ret) {
		LOG_ERROR_BDF("user set allmulti failed %d\n", ret);
		adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags |=
				IFF_ALLMULTI;
	}

l_end:
	return ret;
}

int sxe2vf_ucmd_allmulti_rule_del(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		ret = sxe2vf_ucmd_user_mode_allmulti_rule_del(adapter, vsi_id);
	else
		ret = sxe2vf_ucmd_com_mode_allmulti_rule_del(adapter, vsi_id);

	return ret;
}

s32 sxe2vf_ucmd_vlan_filter_cfg(struct sxe2vf_adapter *adapter, u16 vsi_id,
				bool is_open)
{
	s32 ret = 0;
	struct sxe2vf_vlan_filter *filter_offload =
			&adapter->switch_ctxt.user_fltr_ctxt.vlan_info
					 .filter_offload;

	LOG_INFO_BDF("User vf vsi:%u %s vlan filter\n", vsi_id,
		     is_open ? "open" : "close");

	if (is_open && adapter->switch_ctxt.filter_ctxt.vlan_info.port_vlan_exist) {
		LOG_WARN_BDF("can not open vlan filter, when port vlan exist.\n");
		goto l_end;
	}

	if (is_open) {
		filter_offload->ctag_filter_enable = 1;
		filter_offload->stag_filter_enable = 1;
	} else {
		filter_offload->ctag_filter_enable = 0;
		filter_offload->stag_filter_enable = 0;
	}

	ret = sxe2vf_vlan_filter_msg_send(adapter, true);
	if (ret) {
		if (is_open) {
			filter_offload->ctag_filter_enable = 0;
			filter_offload->stag_filter_enable = 0;
		} else {
			filter_offload->ctag_filter_enable = 1;
			filter_offload->stag_filter_enable = 1;
		}
	}

	LOG_INFO_BDF("ctag_filter_enable:%u stag_filter_enable:%u.\n",
		     filter_offload->ctag_filter_enable,
		     filter_offload->stag_filter_enable);

l_end:
	return ret;
}

int sxe2vf_ucmd_vlan_rule_process(struct sxe2vf_adapter *adapter, u16 vsi_id,
				  struct sxe2vf_vlan *vlan, bool is_add)
{
	LOG_INFO_BDF("User vf vsi:%u %s vlan rule, vid:%u, tpid:%u\n", vsi_id,
		     is_add ? "add" : "del", vlan->vid, vlan->tpid);

	return sxe2vf_user_vlan_msg_send(adapter, vsi_id, vlan, is_add);
}

static void sxe2vf_user_unicast_mac_rest(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2vf_mac_filter *user_mac_fltr;
	struct sxe2vf_mac_filter *eth_mac_fltr;
	struct sxe2vf_addr_node *eth_node;
	struct sxe2vf_addr_node *user_node;
	struct sxe2vf_addr_node *tmp_1;
	struct sxe2vf_addr_node *tmp_2;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	eth_mac_fltr = &adapter->switch_ctxt.filter_ctxt.mac_filter;
	user_mac_fltr = &adapter->switch_ctxt.user_fltr_ctxt.mac_filter;

	(void)mutex_lock(&switch_ctxt->mac_addr_lock);

	list_for_each_entry_safe(user_node, tmp_1, &user_mac_fltr->mac_addr_list,
				 list) {
		if (is_unicast_ether_addr(user_node->mac.macaddr)) {
			list_for_each_entry_safe(eth_node, tmp_2,
						 &eth_mac_fltr->mac_addr_list, list) {
				if (!memcmp(user_node->mac.macaddr,
					    eth_node->mac.macaddr,
					    sizeof(user_node->mac.macaddr))) {
					ret = sxe2vf_mac_update_msg_send(adapter,
									 user_node->mac.macaddr,
									 false);
					if (ret) {
						LOG_ERROR_BDF("user vsi %u mac %pM, \t"
							      "update to\t"
							      "eth vf failed.\n",
							      vsi_id,
							      user_node->mac.macaddr);
					}
					break;
				}
			}
		}
		sxe2vf_switch_mac_node_del_and_free(user_node);
	}

	(void)mutex_unlock(&switch_ctxt->mac_addr_lock);
}

static void sxe2vf_user_promisc_allmulti_rest(struct sxe2vf_adapter *adapter,
					      u16 vsi_id)
{
	s32 ret = 0;

	mutex_lock(&adapter->switch_ctxt.flag_lock);

	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_ALLMULTI &&
	    (adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_ALLMULTI ||
	     adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC)) {
		ret = sxe2vf_user_promisc_update_msg_send(adapter, vsi_id, false,
							  false);
		if (ret)
			LOG_ERROR_BDF("user vf vsi_id :%u allmulti rule update\t"
				      "to eth failed %d\n",
				      vsi_id, ret);
	}

	if (adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags & IFF_PROMISC &&
	    adapter->switch_ctxt.filter_ctxt.cur_promisc_flags & IFF_PROMISC) {
		ret = sxe2vf_user_promisc_update_msg_send(adapter, vsi_id, false,
							  true);
		if (ret)
			LOG_ERROR_BDF("user vf vsi_id :%u promisc rule update\t"
				      " to eth failed %d\n",
				      vsi_id, ret);
	}

	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &= (~IFF_ALLMULTI);
	adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &= (~IFF_PROMISC);

	mutex_unlock(&adapter->switch_ctxt.flag_lock);
}

s32 sxe2vf_user_l2_feature_clean(struct sxe2vf_adapter *adapter, u16 vsi_id)
{
	s32 ret = 0;
	struct sxe2vf_mac_filter *user_mac_fltr;
	struct sxe2vf_addr_node *user_node;
	struct sxe2vf_addr_node *tmp;
	struct sxe2vf_switch_context *switch_ctxt = &adapter->switch_ctxt;

	LOG_INFO_BDF("User vf vsi:%u clean l2 feature.\n", vsi_id);

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK) {
		user_mac_fltr = &adapter->switch_ctxt.user_fltr_ctxt.mac_filter;
		(void)mutex_lock(&switch_ctxt->mac_addr_lock);
		list_for_each_entry_safe(user_node, tmp,
					 &user_mac_fltr->mac_addr_list, list) {
			sxe2vf_switch_mac_node_del_and_free(user_node);
		}
		(void)mutex_unlock(&switch_ctxt->mac_addr_lock);

		adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
				(~IFF_ALLMULTI);
		adapter->switch_ctxt.user_fltr_ctxt.cur_promisc_flags &=
				(~IFF_PROMISC);
	} else {
		sxe2vf_user_unicast_mac_rest(adapter, vsi_id);
		sxe2vf_user_promisc_allmulti_rest(adapter, vsi_id);
	}

	return ret;
}
