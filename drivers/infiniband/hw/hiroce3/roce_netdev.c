// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_netdev.h"
#include "roce_netdev_extension.h"
#include "roce_main_extension.h"
#include "roce_pub_cmd.h"
#include "hinic3_rdma.h"
#include "roce.h"

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

/*
 ****************************************************************************
 Prototype	: roce3_fill_gid_type
 Description  : fill gid type
 Input		: struct rdma_gid_entry *gid_entry
 Output	   : None

  1.Date		 : 2016/5/27
	Modification : Created function

****************************************************************************
*/
static void roce3_fill_gid_type(struct rdma_gid_entry *gid_entry, enum roce3_gid_type new_gid_type)
{
	static u32 index_roce3_gid_mapping[32][4] = {
		{0x120E1436, 3452, 224529784, 0x180E252A},
		{0x120E004A, 3472, 224660876, 0x6C0E403E},
		{0x120E0042, 3464, 224660836, 0x840E4036},
		{0x120E0042, 3464, 224398688, 0xC00E0036},
		{0x1212143A, 3456, 224791932, 0x1812252E},
		{0x1212004E, 3476, 224923024, 0x6C124042},
		{0x12120046, 3468, 224922984, 0x8412403A},
		{0x12120046, 3468, 224660836, 0xC012003A},
		{0x1216143E, 3460, 225054080, 0x18162532},
		{0x12160052, 3480, 225185172, 0x6C164046},
		{0x1216004A, 3472, 225185132, 0x8416403E},
		{0x1216004A, 3472, 224922984, 0xC016003E},
		{0x10301458, 3484, 226626968, 0x1830254C},
		{0x1030006C, 3504, 226758060, 0x6C304060},
		{0x10300064, 3496, 226758020, 0x84304058},
		{0x10300064, 3496, 226495872, 0xC0300058},
		{0x10401468, 838864300, 227675560, 0x1840255C},
		{0x1040007C, 1174408640, 227806652, 0x6C404070},
		{0x10400074, 1040190904, 227806612, 0x84404068},
		{0x10400074, 1040190904, 227544464, 0xC0400068},
		{0x1044146C, 905973168, 227937708, 0x18442560},
		{0x10440080, 1241517508, 228068800, 0x6C444074},
		{0x10440078, 1107299772, 228068760, 0x8444406C},
		{0x10440078, 1107299772, 227806612, 0xC044006C},
		{0x10481470, 973082036, 228199856, 0x18482564},
		{0x10480084, 1308626376, 228330948, 0x6C484078},
		{0x1048007C, 1174408640, 228330908, 0x84484070},
		{0x1048007C, 1174408640, 228068760, 0xC0480070},
		{0x1262148A, 1040190928, 230034892, 0x1862257E},
		{0x1262009E, 1375735268, 230165984, 0x6C624092},
		{0x12620096, 1241517532, 230165944, 0x8462408A},
		{0x12620096, 1241517532, 229903796, 0xC062008A},
	};
	u8 i = 0;

	gid_entry->dw6_h.bs.gid_type = new_gid_type;
	gid_entry->dw6_h.bs.gid_update = (new_gid_type == ROCE_IPv4_ROCEv2_GID);

	i = ROCE_GID_MAP_TBL_IDX_GET(gid_entry->dw6_h.bs.tunnel, gid_entry->dw6_h.bs.tag,
		(u16)new_gid_type);
	gid_entry->hdr_len_value = index_roce3_gid_mapping[i][0];
	if (new_gid_type == ROCE_IPv4_ROCEv2_GID) {
		*((u32 *)(void *)gid_entry + 1) = cpu_to_be32(index_roce3_gid_mapping[i][1]);
		*((u32 *)(void *)gid_entry + ROCE_GID_MAP_TBL_IDX2) =
			cpu_to_be32(index_roce3_gid_mapping[i][ROCE_GID_MAP_TBL_IDX2]);
	}
}

static void roce3_fill_gid_smac(struct net_device *net_dev, struct rdma_gid_entry *gid_entry)
{
	memcpy((void *)gid_entry->smac, (void *)net_dev->dev_addr, sizeof(gid_entry->smac));
}

static void roce3_fill_gid_vlan(struct roce3_device *rdev, struct net_device *net_dev,
	struct rdma_gid_entry *gid_entry)
{
	gid_entry->dw6_h.bs.tunnel = ROCE_GID_TUNNEL_INVALID;
	if (rdma_vlan_dev_vlan_id(net_dev) != 0xffff) {
		gid_entry->dw4.bs.cvlan = rdma_vlan_dev_vlan_id(net_dev) & 0xfff;
		gid_entry->dw6_h.bs.tag = ROCE_GID_VLAN_VALID;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_dispatch_event
 Description  : roce3_dispatch_event
 Input		: struct roce3_device *rdev
				int port_num
				enum ib_event_type type
 Output	   : None

  1.Date		 : 2016/3/29
	Modification : Created function

****************************************************************************
*/
static void roce3_dispatch_event(struct roce3_device *rdev, int port_num, enum ib_event_type type)
{
	struct ib_event event;

	if (rdev == NULL) {
		pr_err("[ROCE, ERR] %s: Rdev is null\n", __func__);
		return;
	}

	memset(&event, 0, sizeof(event));

	event.device = &rdev->ib_dev;
	event.element.port_num = (u8)port_num;
	event.event = type;

	ib_dispatch_event(&event);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
struct sin6_list {
	struct list_head list;
	struct sockaddr_in6 sin6;
};

static int roce3_gid_fill(struct roce3_device *rdev, struct rdma_gid_entry *gid_entry,
	struct net_device *event_netdev, struct sin6_list *sin6_iter)
{
	int ret = 0;

	if (cpu_to_be64(gid_entry->global.subnet_prefix) == ROCE_DEFAULT_GID_SUBNET_PREFIX)
		return ret;

	roce3_fill_gid_vlan(rdev, event_netdev, gid_entry);
	roce3_fill_gid_smac(event_netdev, gid_entry);

	/* RoCE V2 */
	if (rdma_protocol_roce_udp_encap(&rdev->ib_dev, ROCE_DEFAULT_PORT_NUM)) {
		roce3_fill_gid_type(gid_entry, ROCE_IPv6_ROCEv2_GID);
		ret = roce3_rdma_update_gid_mac(rdev->hwdev, 0, gid_entry);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to update V2 gid(IPv6), func_id(%d)\n",
				__func__, rdev->glb_func_id);
			list_del(&sin6_iter->list);
			kfree(sin6_iter);
			return ret;
		}
	}

	roce3_dispatch_event(rdev, ROCE_DEFAULT_PORT_NUM, IB_EVENT_GID_CHANGE);

	return ret;
}

static int roce3_netdev_event_ipv6_dev_scan(struct roce3_device *rdev,
	struct net_device *event_netdev, struct rdma_gid_entry *gid_entry)
{
	struct sin6_list *sin6_temp = NULL;
	struct sin6_list *sin6_iter = NULL;
	struct inet6_dev *in6_dev = NULL;
	struct inet6_ifaddr *ifp = NULL;
	struct sin6_list *entry = NULL;
	int ret;

	LIST_HEAD(sin6_init_list);

	in6_dev = in6_dev_get(event_netdev);
	if (in6_dev == NULL)
		return 0;

	read_lock_bh(&in6_dev->lock);
	list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (entry == NULL)
			continue;

		entry->sin6.sin6_family = AF_INET6;
		entry->sin6.sin6_addr = ifp->addr;
		list_add_tail(&entry->list, &sin6_init_list);
	}

	read_unlock_bh(&in6_dev->lock);
	in6_dev_put(in6_dev);

	list_for_each_entry_safe(sin6_iter, sin6_temp, &sin6_init_list, list) {
		memcpy((void *)gid_entry->raw, (void *)&sin6_iter->sin6.sin6_addr,
			sizeof(union ib_gid));

		ret = roce3_gid_fill(rdev, gid_entry, event_netdev, sin6_iter);
		if (ret != 0)
			goto err_free;

		list_del(&sin6_iter->list);
		kfree(sin6_iter);
	}

	return 0;

err_free:
	list_for_each_entry_safe(sin6_iter, sin6_temp, &sin6_init_list, list) {
		list_del(&sin6_iter->list);
		kfree(sin6_iter);
	}
	return ret;
}
#endif

static int roce3_netdev_event_ip_dev_scan(struct roce3_device *rdev,
	struct net_device *event_netdev)
{
	struct rdma_gid_entry gid_entry;
	int ret;

	memset(&gid_entry, 0, sizeof(gid_entry));

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	ret = roce3_netdev_event_ipv6_dev_scan(rdev, event_netdev, &gid_entry);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to scan IPv6, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}
#endif

	return 0;
}

static struct roce3_vlan_dev_list *roce3_find_vlan_device_list(const struct list_head *mac_list,
	const struct net_device *netdev)
{
	struct roce3_vlan_dev_list *vlan_dev_list = NULL;

	list_for_each_entry(vlan_dev_list, mac_list, list) {
		if (vlan_dev_list->net_dev == netdev)
			return vlan_dev_list;
	}

	return NULL;
}

static int roce3_add_vlan_device(struct roce3_device *rdev, struct net_device *netdev)
{
	struct roce3_vlan_dev_list *new_list;

	new_list = kzalloc(sizeof(*new_list), GFP_KERNEL);
	if (new_list == NULL)
		return -ENOMEM;

	new_list->ref_cnt = 1;
	new_list->net_dev = netdev;
	new_list->vlan_id = ROCE_GID_SET_VLAN_32BIT_VLAID(((u32)rdma_vlan_dev_vlan_id(netdev)));
	memcpy(new_list->mac, netdev->dev_addr, ROCE_MAC_ADDR_LEN);
	INIT_LIST_HEAD(&new_list->list);
	list_add_tail(&new_list->list, &rdev->mac_vlan_list_head);

	return 0;
}

static void roce3_del_vlan_device(struct roce3_device *rdev, struct roce3_vlan_dev_list *old_list)
{
	list_del(&old_list->list);
	kfree(old_list);
}

static int roce3_update_vlan_device_mac(struct roce3_device *rdev, struct net_device *netdev)
{
	struct roce3_vlan_dev_list *old_list = NULL;
	int ret;

	mutex_lock(&rdev->mac_vlan_mutex);
	old_list = roce3_find_vlan_device_list(&rdev->mac_vlan_list_head, netdev);
	if (old_list == NULL) {
		mutex_unlock(&rdev->mac_vlan_mutex);
		return 0;
	}

	if (ROCE_MEMCMP(old_list->mac, netdev->dev_addr, ROCE_MAC_ADDR_LEN) != 0) {
		roce3_del_vlan_device_mac(rdev, old_list);

		ret = roce3_add_vlan_device_mac(rdev, netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to add mac_vlan, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			mutex_unlock(&rdev->mac_vlan_mutex);
			return ret;
		}

		memcpy(old_list->mac, netdev->dev_addr, ROCE_MAC_ADDR_LEN);
	}

	mutex_unlock(&rdev->mac_vlan_mutex);

	return 0;
}

static int roce3_update_real_device_mac(struct roce3_device *rdev, struct net_device *netdev)
{
	int ret;

	roce3_del_real_device_mac(rdev);

	ret = roce3_add_real_device_mac(rdev, netdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to add real device ipsu mac, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	return 0;
}

void roce3_clean_vlan_device_mac(struct roce3_device *rdev)
{
	struct roce3_vlan_dev_list *pos = NULL;
	struct roce3_vlan_dev_list *tmp = NULL;

	mutex_lock(&rdev->mac_vlan_mutex);
	list_for_each_entry_safe(pos, tmp, &rdev->mac_vlan_list_head, list) {
#ifdef ROCE_BONDING_EN
		if (roce3_bond_is_active(rdev))
			(void)roce3_del_bond_vlan_slave_mac(rdev, pos->mac, (u16)pos->vlan_id);
#endif
		roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, pos->mac, pos->vlan_id,
			rdev->glb_func_id, hinic3_er_id(rdev->hwdev));

		(void)roce3_del_mac_tbl_mac_entry(rdev->hwdev, pos->mac, pos->vlan_id,
			rdev->glb_func_id, rdev->glb_func_id);

		list_del(&pos->list);
		kfree(pos);
	}
	mutex_unlock(&rdev->mac_vlan_mutex);
}

void roce3_clean_real_device_mac(struct roce3_device *rdev)
{
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev))
		(void)roce3_del_bond_real_slave_mac(rdev);
#endif

	roce3_del_ipsu_tbl_mac_entry(rdev->hwdev, rdev->mac, 0, rdev->glb_func_id,
		hinic3_er_id(rdev->hwdev));
}

static bool roce3_rdma_is_upper_dev_rcu(struct net_device *dev, struct net_device *upper)
{
	struct net_device *rdev_upper = NULL;
	struct net_device *master = NULL;
	bool ret = false;

	if ((upper == NULL) || (dev == NULL)) {
		ret = false;
	} else {
		rdev_upper = rdma_vlan_dev_real_dev(upper);
		master = netdev_master_upper_dev_get_rcu(dev);
		ret = ((upper == master) || (rdev_upper && (rdev_upper == master)) ||
			(rdev_upper == dev));
	}

	return ret;
}

/* check bonding device */
int roce3_is_eth_port_of_netdev(struct net_device *rdma_ndev, struct net_device *cookie)
{
	struct net_device *real_dev = NULL;
	int res;

	if (rdma_ndev == NULL)
		return 0;

	rcu_read_lock();
	real_dev = rdma_vlan_dev_real_dev(cookie);
	if (real_dev == NULL)
		real_dev = cookie;

	res = (roce3_rdma_is_upper_dev_rcu(rdma_ndev, cookie) || (real_dev == rdma_ndev));
	rcu_read_unlock();
	return res;
}

int roce3_ifconfig_up_down_event_report(struct roce3_device *rdev, u8 net_event)
{
	struct ib_event event = { 0 };

	if ((net_event == IB_EVENT_PORT_ACTIVE) &&
		(test_and_set_bit(ROCE3_PORT_EVENT, &rdev->status) != 0))
		return -1;

	if ((net_event == IB_EVENT_PORT_ERR) &&
		(test_and_clear_bit(ROCE3_PORT_EVENT, &rdev->status) == 0))
		return -1;

	event.device = &rdev->ib_dev;
	event.event = net_event;
	event.element.port_num = ROCE_DEFAULT_PORT_NUM;

	ib_dispatch_event(&event);
	return 0;
}

static int roce3_netdev_event_raw_dev(unsigned long event, struct roce3_device *rdev,
	struct net_device *event_netdev)
{
	int ret;

	if (event == NETDEV_REGISTER) {
		ret = roce3_add_real_device_mac(rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to add real device mac, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

	if (event == NETDEV_CHANGEADDR) {
		ret = roce3_update_real_device_mac(rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to update readl device mac, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}

		ret = roce3_netdev_event_ip_dev_scan(rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to scan ip_dev, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		if ((event == NETDEV_DOWN) || (event == NETDEV_UP))
			roce3_handle_bonded_port_state_event(rdev);
	} else {
		if (event == NETDEV_DOWN)
			roce3_ifconfig_up_down_event_report(rdev, IB_EVENT_PORT_ERR);
		if (event == NETDEV_UP)
			roce3_event_up_extend(rdev);
	}
#else
	if (event == NETDEV_DOWN)
		roce3_ifconfig_up_down_event_report(rdev, IB_EVENT_PORT_ERR);
	if (event == NETDEV_UP)
		roce3_event_up_extend(rdev);
#endif
	return 0;
}

static int roce3_netdev_event_vlan_dev(unsigned long event, struct roce3_device *rdev,
	struct net_device *event_netdev)
{
	int ret;

	if (event == NETDEV_CHANGEADDR) {
		ret = roce3_update_vlan_device_mac(rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to update vlan device mac, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}

		ret = roce3_netdev_event_ip_dev_scan(rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to scan vlan device ip list, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return ret;
		}
	}

	return 0;
}

static bool roce3_is_port_of_net_dev(struct roce3_device *rdev, struct net_device *event_netdev)
{
#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		if (roce3_bond_is_eth_port_of_netdev(rdev, event_netdev) == 0)
			return false;
	} else
#endif
	{
		if (roce3_is_eth_port_of_netdev(rdev->ndev, event_netdev) == 0)
			return false;
	}
	return true;
}

static int roce3_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *event_netdev;
	struct roce3_device *rdev = NULL;
	struct roce3_notifier *notifier = NULL;
	struct net_device *real_dev = NULL;
	int ret;

	if (nb == NULL || ptr == NULL)
		goto err_out;

	event_netdev = netdev_notifier_info_to_dev(ptr);
	if (event_netdev->type != ARPHRD_ETHER)
		goto err_out;

	notifier = container_of(nb, struct roce3_notifier, nb);
	rdev = container_of(notifier, struct roce3_device, notifier);

	if (roce3_hca_is_present(rdev) == 0)
		goto err_out;

	if (!roce3_is_port_of_net_dev(rdev, (void *)event_netdev))
		goto err_out;

	/* get raw netdev from event_netdev */
	real_dev = (rdma_vlan_dev_real_dev(event_netdev) != 0) ?
		rdma_vlan_dev_real_dev(event_netdev) : event_netdev;
	if (real_dev == event_netdev) {
		ret = roce3_netdev_event_raw_dev(event, rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to deal with raw device, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			goto err_out;
		}
	} else {
		ret = roce3_netdev_event_vlan_dev(event, rdev, event_netdev);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to deal with vlan device, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			goto err_out;
		}
	}

err_out:
	return NOTIFY_DONE;
}

/*
 ****************************************************************************
 Prototype	: roce3_unregister_netdev_event
 Description  : unregister netdev event related function
 Input		: struct roce3_device *rdev
 Output	   : None

  1.Date		 : 2015/6/18
	Modification : Created function

****************************************************************************
*/
void roce3_unregister_netdev_event(struct roce3_device *rdev)
{
	int ret = 0;
	struct roce3_notifier *notifier = &rdev->notifier;

	if (notifier->nb.notifier_call) {
		ret = unregister_netdevice_notifier(&notifier->nb);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to unregister netdev notifier, func_id(%d)\n",
				__func__, rdev->glb_func_id);
		}

		notifier->nb.notifier_call = NULL;
	}
}

/*
 ****************************************************************************
 Prototype	: roce3_register_netdev_event
 Description  : register netdev event related function
 Input		: struct roce3_device *rdev
 Output	   : None

  1.Date		 : 2015/6/18
	Modification : Created function

****************************************************************************
*/
int roce3_register_netdev_event(struct roce3_device *rdev)
{
	struct roce3_notifier *notifier = &rdev->notifier;
	int ret;

	notifier->nb.notifier_call = roce3_netdev_event;
	ret = register_netdevice_notifier(&notifier->nb);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to register netdev notifier, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		notifier->nb.notifier_call = NULL;
		return ret;
	}

	return 0;
}

static int roce3_set_gid_entry(struct roce3_device *rdev, struct rdma_gid_entry *gid_entry,
	const struct ib_gid_attr *attr, const union ib_gid *gid)
{
	static enum roce3_gid_type gid_type_map[ROCE_NETWORK_GID_TYPE_MAX] = {0};
	enum rdma_network_type network_type;
	enum roce3_gid_type roce_gid_type;

	gid_type_map[RDMA_NETWORK_IPV4] = ROCE_IPv4_ROCEv2_GID;
	gid_type_map[RDMA_NETWORK_IPV6] = ROCE_IPv6_ROCEv2_GID;

	memset(gid_entry, 0, sizeof(*gid_entry));
	network_type = rdma_gid_attr_network_type(attr);
	memcpy((void *)gid_entry->raw, (void *)(&attr->gid), sizeof(union ib_gid));
	if ((network_type == RDMA_NETWORK_IB) || (network_type == RDMA_NETWORK_ROCE_V1)) {
		pr_err("[ROCE, ERR] %s: IB or RoCE v1 is no longer supported, network_type(%d)\n",
			__func__, network_type);
		return (-EINVAL);
	}

	roce_gid_type = gid_type_map[network_type];
	roce3_fill_gid_vlan(rdev, attr->ndev, gid_entry);
	roce3_fill_gid_type(gid_entry, roce_gid_type);
	roce3_fill_gid_smac(attr->ndev, gid_entry);

	return 0;
}

static int roce3_check_and_set_gid_entry(const struct ib_gid_attr *attr, const union ib_gid *gid,
	struct rdma_gid_entry *gid_entry, struct roce3_device *rdev, unsigned int index)
{
	if ((cpu_to_be64(gid->global.subnet_prefix) == ROCE_DEFAULT_GID_SUBNET_PREFIX) &&
		(index > 1))
		return -EINVAL;

	memset(gid_entry, 0, sizeof(struct rdma_gid_entry));
	if (roce3_set_gid_entry(rdev, gid_entry, attr, gid) != 0) {
		pr_err("[ROCE, ERR] %s: Failed to set gid entry.\n", __func__);
		return (-EINVAL);
	}

	return 0;
}

/* add vlan_mac list or ref_cnt + 1
 * add mac_vlan when new list add
 */
static int roce3_notify_vlan(struct roce3_device *rdev, const struct ib_gid_attr *attr)
{
	int ret;
	struct roce3_vlan_dev_list *old_list = NULL;

	mutex_lock(&rdev->mac_vlan_mutex);
	pr_info("[ROCE] ADD vlan: Func_id:%d, Netdev:%s\n",
		rdev->glb_func_id, attr->ndev->name);
	old_list = roce3_find_vlan_device_list(&rdev->mac_vlan_list_head, attr->ndev);
	if (old_list != NULL) {
		old_list->ref_cnt++;
		mutex_unlock(&rdev->mac_vlan_mutex);
		return 0;
	}

	ret = roce3_add_vlan_device(rdev, attr->ndev);
	if (ret != 0) {
		mutex_unlock(&rdev->mac_vlan_mutex);
		return ret;
	}

	ret = roce3_add_vlan_device_mac(rdev, attr->ndev);
	if (ret != 0) {
		old_list = roce3_find_vlan_device_list(&rdev->mac_vlan_list_head, attr->ndev);
		if (old_list)
			roce3_del_vlan_device(rdev, old_list);

		mutex_unlock(&rdev->mac_vlan_mutex);
		return ret;
	}
	mutex_unlock(&rdev->mac_vlan_mutex);

	return 0;
}

int roce3_ib_add_gid(const struct ib_gid_attr *attr, __always_unused void **context)
{
	int ret;
	struct rdma_gid_entry gid_entry;
	struct roce3_device *rdev = to_roce3_dev(attr->device); /*lint !e78 !e530*/
	unsigned int index = attr->index;					   /*lint !e530*/

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}
	/*lint !e40*/
	ret = roce3_check_and_set_gid_entry(attr, &(attr->gid), &gid_entry, rdev, index);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: set gid err, func_id(%u)\n", __func__,
			rdev->glb_func_id);
		return ret;
	}

	// 添加第一个gid时，设置ipsu mac
	if (index == 0) {
		ret = roce3_update_real_device_mac(rdev, attr->ndev);
		if (ret != 0)
			return ret;
	}

	ret = roce3_rdma_update_gid(rdev->hwdev, 0, index, &gid_entry);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to update gid. ret(%d),func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);
		return ret;
	}

	rdev->gid_dev[index] = attr->ndev;

	if (rdma_vlan_dev_real_dev(attr->ndev)) {
		ret = roce3_notify_vlan(rdev, attr);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to nofify vlan, func_id(%d), ret(%d)\n",
				__func__, rdev->glb_func_id, ret);
			return ret;
		}
	}

	return 0;
}

int roce3_ib_del_gid(const struct ib_gid_attr *attr, __always_unused void **context)
{
	struct roce3_vlan_dev_list *old_list = NULL;
	struct roce3_device *rdev = NULL;
	u32 index = 0;

	if ((attr == NULL) || (attr->device == NULL)) { /*lint !e55 !e58 !e78*/
		pr_err("[ROCE] %s: Attr or attr->device is null\n", __func__);
		return (-EINVAL);
	}

	rdev = to_roce3_dev(attr->device); /*lint !e78*/
	index = attr->index;
	if (index >= rdev->rdma_cap.max_gid_per_port) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: Invalid gid index(%u), func_id(%d)\n",
			__func__, index, rdev->glb_func_id);
		return (-EINVAL);
	}

	/* del vlan_mac list or ref_cnt - 1 */
	/* del mac_vlan when ref_cnt = 0 */
	if (rdev->ndev != rdev->gid_dev[index]) {
		mutex_lock(&rdev->mac_vlan_mutex);
		old_list = roce3_find_vlan_device_list(&rdev->mac_vlan_list_head,
			rdev->gid_dev[index]);
		if (old_list) {
			old_list->ref_cnt--;
			if (old_list->ref_cnt == 0) {
				roce3_del_vlan_device_mac(rdev, old_list);

				roce3_del_vlan_device(rdev, old_list);
			}
		}
		mutex_unlock(&rdev->mac_vlan_mutex);
	}
	/*
	 * delete gid no longer send cmd to ucode which write 0s to target entry,
	 * preventing PPE from building malformed packets.
	 */
	return 0;
}
