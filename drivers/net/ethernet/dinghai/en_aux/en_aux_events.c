// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/dinghai/events.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include "en_aux_events.h"
#include "en_aux_eq.h"
#include "en_aux_cmd.h"
#include "../msg_common.h"
#include "../en_np/table/include/dpp_tbl_api.h"
#include "../zxdh_tools/zxdh_tools_netlink.h"
#include "../zxdh_tools/zxdh_tools_ioctl.h"
#include "dcbnl/en_dcbnl_api.h"
#include "zxic_common.h"
#include <linux/timer.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <net/addrconf.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <net/bonding.h>
#include <linux/umh.h>
#include "../en_ethtool/ethtool.h"

static struct mutex rdma_lock;
static const char *const cfg_argv[] = { "/etc/zxdh_cfg/smart_nic_cfg_proc.sh", "c", NULL };
static const char *const cfg_envp[] = { "HOME=/", "TERM=linux",
					"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/bin", NULL };
static s32 pf2vf_notifier(struct notifier_block *, unsigned long, void *);
static s32 riscv2aux_notifier(struct notifier_block *, unsigned long, void *);
static s32 aux_unload_notifier(struct notifier_block *, unsigned long, void *);
static s32 aux_load_notifier(struct notifier_block *, unsigned long, void *);
static s32 aux_state_notifier(struct notifier_block *, unsigned long, void *);

static struct dh_nb aux_events[] = {
	{ .nb.notifier_call = pf2vf_notifier, .event_type = DH_EVENT_TYPE_NOTIFY_PF_TO_VF },
	{ .nb.notifier_call = aux_unload_notifier, .event_type = DH_EVENT_TYPE_AUX_UNLOAD },
	{ .nb.notifier_call = aux_load_notifier, .event_type = DH_EVENT_TYPE_AUX_LOAD },
	{ .nb.notifier_call = aux_state_notifier, .event_type = DH_EVENT_TYPE_AUX_STATE },
	{ .nb.notifier_call = riscv2aux_notifier, .event_type = DH_EVENT_TYPE_NOTIFY_RISCV_TO_AUX },
};

static s32 do_pf_vf_inet6_update_mac_to_np(struct zxdh_en_device *en_dev,
					   const struct in6_addr *ipv6_addr, unsigned long action)
{
	s32 ret = 0;
	struct in6_addr sol_addr = { 0 };
	u8 mcast_mac[ETH_ALEN];

	DH_LOG_DEBUG(MODULE_PF, "IPv6 address changed on interface %s, %s address: %pI6c\n",
		     en_dev->netdev->name,
		     (action == 1) ? "add" :
		     (action == 2) ? "del" :
					   "unknown action with",
		     ipv6_addr);
	// Calculate the multicast MAC address from the IPv6 address
	addrconf_addr_solict_mult(ipv6_addr, &sol_addr);
	ipv6_eth_mc_map(&sol_addr, mcast_mac);
	DH_LOG_DEBUG(MODULE_PF, "Multicast MAC Address: %pM\n", mcast_mac);

	switch (action) {
	case NETDEV_UP: {
		ret = zxdh_ip6mac_add_safe(en_dev, ipv6_addr->s6_addr32, mcast_mac);
		if (ret != 0)
			LOG_ERR("zxdh_ip6mac_add_safe failed");
		break;
	}
	case NETDEV_DOWN: {
		ret = zxdh_ip6mac_del_safe(en_dev, ipv6_addr->s6_addr32, mcast_mac);
		if (ret != 0)
			LOG_ERR("zxdh_ip6mac_del_safe failed");
		break;
	}
	default:
		break;
	}
	return ret;
}

static s32 do_pf_vf_vxlan_update_mac_to_np(struct zxdh_en_device *en_dev, u8 *mcast_mac,
					   unsigned long action)
{
	s32 ret = 0;

	switch (action) {
	case NETDEV_UP: {
		ret = zxdh_ip4mac_add(en_dev, mcast_mac, action);
		if (ret != 0) {
			LOG_ERR("zxdh_ip4mac_add failed\n");
			return ret;
		}
		break;
	}
	case NETDEV_DOWN: {
		ret = zxdh_ip4mac_del(en_dev, mcast_mac, action);
		if (ret != 0) {
			LOG_ERR("zxdh_ip6mac_del failed\n");
			return ret;
		}
		break;
	}
	default:
		break;
	}
	return ret;
}

static s32 do_bond_master_inet6_update_mac_to_np(struct net_device *notifier_dev,
						 const struct in6_addr *ipv6_addr,
						 struct zxdh_en_device *en_dev,
						 unsigned long action)
{
	s32 ret = 0;
	struct list_head *iter = NULL;
	struct slave *slave_dev = NULL;
	struct bonding *bond = netdev_priv(notifier_dev);

	if (!bond_has_slaves(bond)) {
		DH_LOG_DEBUG(MODULE_PF, "Bond device %s don't have slave\n", notifier_dev->name);
		return 0;
	}

	bond_for_each_slave(bond, slave_dev, iter) {
		if (strcmp(en_dev->netdev->name, slave_dev->dev->name) != 0)
			continue;
		DH_LOG_DEBUG(MODULE_PF, "Bond device %s have slave device: %s\n",
			     notifier_dev->name, slave_dev->dev->name);
		ret = do_pf_vf_inet6_update_mac_to_np(en_dev, ipv6_addr, action);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static s32 inet6_addr_change_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct inet6_ifaddr *ifa = NULL;
	struct net_device *notifier_dev = NULL;
	struct zxdh_en_device *en_dev = container_of(nb, struct zxdh_en_device, ipv6_notifier);

	if (!data) {
		LOG_ERR("data is NULL");
		return NOTIFY_OK;
	}

	ifa = (struct inet6_ifaddr *)data;
	notifier_dev = ifa->idev->dev;

	if (!notifier_dev) {
		LOG_ERR("notifier_dev is NULL");
		return NOTIFY_OK;
	}

	if (is_vlan_dev(notifier_dev))
		notifier_dev = vlan_dev_real_dev(notifier_dev);

	if (netif_is_bond_master(notifier_dev))
		return do_bond_master_inet6_update_mac_to_np(notifier_dev, &ifa->addr, en_dev,
							     action);

	if (strcmp(en_dev->netdev->name, notifier_dev->name) == 0)
		return do_pf_vf_inet6_update_mac_to_np(en_dev, &ifa->addr, action);

	return NOTIFY_OK;
}

static void multicast_ipv4_to_mac(struct in_addr ipv4_addr, u8 *mac_addr)
{
	u32 ip = ntohl(ipv4_addr.s_addr);

	mac_addr[0] = MULTI_FLAG;
	mac_addr[1] = IPV4_TYPE_FLAG;
	mac_addr[2] = GLOBAL_FLAG;
	mac_addr[3] = (ip >> BIT16) & BIT_23_L; /* Take bits 16-23 from the IP address*/
	mac_addr[4] = (ip >> BIT8) & BIT_15_L; /* Take bits 8-15 from the IP address */
	mac_addr[5] = ip & BIT_7_L; /* Take bits 0-7 from the IP address */
}

static s32 vxlan_netdev_change_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct vxlan_dev *vxlan = NULL;
	struct net_device *notifier_dev = netdev_notifier_info_to_dev(data);
	struct zxdh_en_device *en_dev = container_of(nb, struct zxdh_en_device, vxlan_notifier);
	struct vxlan_config *cfg = NULL;
	u32 ipv4_addr = 0;
	struct in6_addr *ipv6_addr = NULL;
	u8 mac_addr[6] = { 0 };

	s32 ret = 0;

	if (!notifier_dev) {
		LOG_ERR("notifier_dev is NULL\n");
		return NOTIFY_BAD;
	}

	if (!en_dev) {
		LOG_ERR("en_dev is NULL\n");
		return NOTIFY_BAD;
	}

	if (!(notifier_dev->rtnl_link_ops &&
	      strcmp(notifier_dev->rtnl_link_ops->kind, "vxlan") == 0)) {
		return NOTIFY_DONE;
	}

	en_dev = container_of(nb, struct zxdh_en_device, vxlan_notifier);
	if (!en_dev) {
		LOG_ERR("en_dev is NULL\n");
		return NOTIFY_BAD;
	}

	vxlan = netdev_priv(notifier_dev);
	cfg = &vxlan->cfg;

	if (cfg->remote_ip.sa.sa_family == AF_INET) {
		ipv4_addr = cfg->remote_ip.sin.sin_addr.s_addr;
		if ((ipv4_addr & htonl(0xF0000000)) != htonl(0xE0000000))
			return NOTIFY_DONE;

		multicast_ipv4_to_mac(cfg->remote_ip.sin.sin_addr, mac_addr);
		LOG_DEBUG("VXLAN device %s IPv4 address %pI4 to multi mac %pM\n",
			  notifier_dev->name, &cfg->remote_ip.sin.sin_addr, mac_addr);
	} else if (cfg->remote_ip.sa.sa_family == AF_INET6) {
		ipv6_addr = &cfg->remote_ip.sin6.sin6_addr;
		if (ipv6_addr->s6_addr[0] != 0xFF)
			return NOTIFY_DONE;

		ipv6_eth_mc_map(ipv6_addr, mac_addr);
		LOG_DEBUG("VXLAN device %s IPv6 address %pI6c to multi mac %pM\n",
			  notifier_dev->name, ipv6_addr, mac_addr);
	} else {
		LOG_INFO("Unsupported address family\n");
	}

	ret = do_pf_vf_vxlan_update_mac_to_np(en_dev, mac_addr, action);
	if (ret != 0) {
		LOG_ERR("do_pf_vf_vxlan_update_mac_to_np failed\n");
		return NOTIFY_BAD;
	}
	return NOTIFY_OK;
}

static void vf_link_info_update_handler(struct work_struct *_work)
{
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, vf_link_info_update_work);
	union zxdh_msg *msg = NULL;
	struct zxdh_vf_item *vf_item = NULL;
	s32 err = 0;
	u16 vf_idx = 0;
	struct pci_dev *pdev = NULL;
	u16 num_vfs = 0;
	bool pf_link_up = false;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	pf_link_up = en_dev->ops->get_pf_link_up(en_dev->parent);
	pdev = en_dev->ops->get_pdev(en_dev->parent);
	num_vfs = pci_num_vf(pdev);

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}
	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		msg->payload.hdr_vf.op_code = ZXDH_SET_VF_LINK_STATE;
		msg->payload.link_state_msg.is_link_force_set = FALSE;
		msg->payload.link_state_msg.link_up = pf_link_up;
		msg->payload.link_state_msg.speed = en_dev->speed;
		msg->payload.link_state_msg.autoneg_enable = en_dev->autoneg_enable;
		msg->payload.link_state_msg.supported_speed_modes = en_dev->supported_speed_modes;
		msg->payload.link_state_msg.advertising_speed_modes =
			en_dev->advertising_speed_modes;
		msg->payload.hdr_vf.dst_pcie_id = FIND_VF_PCIE_ID(en_dev->pcie_id, vf_idx);
		vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
		if (vf_item->is_probed) {
			msg->payload.link_state_msg.link_forced = vf_item->link_forced;
			err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_PF_BAR_MSG_TO_VF,
							msg, msg, &para);
			if (err != 0)
				LOG_ERR("failed to update VF[%d]\n", vf_idx);
		}
	}
	kfree(msg);
}

static void link_info_irq_update_vf_handler(struct work_struct *_work)
{
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, link_info_irq_update_vf_work);
	struct zxdh_vf_item *vf_item = NULL;
	s32 err = 0;
	u16 vf_idx = 0;
	struct pci_dev *pdev = NULL;
	u16 num_vfs = 0;
	bool pf_link_up = en_dev->ops->get_pf_link_up(en_dev->parent);
	u16 func_no = 0;
	u16 pf_no = FIND_PF_ID(en_dev->pcie_id);
	union zxdh_msg *msg = NULL;
	u8 link_info = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	if (en_dev->ops->is_upf(en_dev->parent)) {
		link_info = (en_dev->phy_port & 0x0F) << 4 | (en_dev->link_up & 0x0F);
		LOG_DEBUG("upf update vf link_info: %u\n", link_info);
	} else {
		link_info = pf_link_up ? 1 : 0;
	}

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_DEV_STATUS_NOTIFY;
	msg->payload.hdr_to_agt.pcie_id = en_dev->pcie_id;

	pdev = en_dev->ops->get_pdev(en_dev->parent);
	num_vfs = pci_num_vf(pdev);
	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_item = en_dev->ops->get_vf_item(en_dev->parent, vf_idx);
		LOG_INFO("vf_idx:%d, vf_item->link_forced %d, is_probed %d\n", vf_idx,
			 vf_item->link_forced, vf_item->is_probed);
		if (vf_item->link_forced == FALSE) {
			en_dev->ops->set_vf_link_info(en_dev->parent, vf_idx, link_info);
			if (vf_item->is_probed) {
				func_no = GET_FUNC_NO(pf_no, vf_idx);
				msg->payload.pcie_msix_msg
					.func_no[msg->payload.pcie_msix_msg.num++] = func_no;
			}
		}
	}
	if (msg->payload.pcie_msix_msg.num > 0) {
		LOG_INFO("%s update %d vf link info\n", en_dev->netdev->name,
			 msg->payload.pcie_msix_msg.num);
		err = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
		if (err != 0)
			LOG_ERR("failed to update VF link info\n");
	}

	kfree(msg);
}

static void link_info_irq_process_handler(struct work_struct *_work)
{
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, link_info_irq_process_work);
	s32 ret = 0;
	struct link_info_struct link_info_val = { 0 };
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;

	if (!zxdh_en_is_panel_port(en_dev))
		return;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg) {
		LOG_ERR("kzalloc(%lu, GFP_KERNEL) failed !", sizeof(union zxdh_msg));
		return;
	}

	msg->payload.hdr_to_agt.op_code = AGENT_MAC_LINK_INFO_GET;
	msg->payload.hdr_to_agt.phyport = en_dev->phy_port;
	ret = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_MAC, msg, msg, &para);
	if (ret != 0) {
		LOG_ERR("get speed and duplex from agent failed: %d\n", ret);
		kfree(msg);
		return;
	}
	en_dev->speed = msg->reps.mac_set_msg.speed;
	en_dev->curr_speed_modes = msg->reps.mac_set_msg.speed_modes;
	en_dev->duplex = msg->reps.mac_set_msg.duplex;
	LOG_INFO("netdev:%s, phy_port:0x%x, speed:%d, duplex:0x%x\n", en_dev->netdev->name,
		 en_dev->phy_port, en_dev->speed, en_dev->duplex);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		link_info_val.speed = en_dev->speed;
		link_info_val.autoneg_enable = en_dev->autoneg_enable;
		link_info_val.supported_speed_modes = en_dev->supported_speed_modes;
		link_info_val.advertising_speed_modes = en_dev->advertising_speed_modes;
		link_info_val.duplex = en_dev->duplex;

		en_dev->ops->update_pf_link_info(en_dev->parent, &link_info_val);
	}

	if (en_dev->speed != SPEED_UNKNOWN)
		netif_carrier_on(en_dev->netdev);

	kfree(msg);
}

static void link_info_irq_update_np_work_handler(struct work_struct *_work)
{
	s32 ret = 0;
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, link_info_irq_update_np_work);
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	if (!en_dev->ops->is_bond(en_dev->parent)) {
		if (!netif_running(en_dev->netdev))
			return;
		if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF) {
			zxdh_vf_egr_port_attr_set(en_dev, SRIOV_VPORT_IS_UP, en_dev->link_up, 0);
		} else {
			ret = dpp_vport_attr_set(&pf_info, SRIOV_VPORT_IS_UP, en_dev->link_up);
			if (ret != 0) {
				LOG_ERR("dpp_vport_attr_set SRIOV_VPORT_IS_UP %d failed, ret:%d\n",
					en_dev->link_up, ret);
				return;
			}
			if (en_dev->is_hwbond || en_dev->ops->is_special_bond(en_dev->parent)) {
				dpp_uplink_phy_attr_set(&pf_info, en_dev->phy_port,
							UPLINK_PHY_PORT_IS_UP, en_dev->link_up);
			}
		}
		return;
	}

	if (!en_dev->link_up) {
		zxdh_uplink_phy_attr_set(&pf_info, en_dev->phy_port, UPLINK_PHY_PORT_IS_UP, 0);
	} else {
		if (en_dev->netdev->flags & IFF_UP) {
			zxdh_uplink_phy_attr_set(&pf_info, en_dev->phy_port, UPLINK_PHY_PORT_IS_UP,
						 1);
		}
	}
}

static void en_aux_spoof_check(struct zxdh_en_device *en_dev)
{
	u64 prev_ssvpc_num = 0;
	u16 en_aux_pf_id = 0;
	u32 ret = 0;
	u16 num_vfs = 0;
	u64 ssvpc_incr = 0;
	struct pci_dev *pdev = NULL;
	struct dh_core_dev *dh_dev = NULL;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	dh_dev = en_dev->parent;
	pdev = en_dev->ops->get_pdev(dh_dev);
	num_vfs = pci_num_vf(pdev);

	if (!IS_PF(en_dev->vport))
		return;
	if (num_vfs == 0)
		return;
	prev_ssvpc_num = en_dev->last_tx_vport_ssvpc_packets;
	en_aux_pf_id = DH_AUX_PF_ID_OFFSET(en_dev->vport);
	// spoof static register not clear to 0 after read
	ret = dpp_stat_spoof_packet_drop_cnt_get(&pf_info, en_aux_pf_id, NP_GET_PKT_CNT,
						 &(en_dev->last_tx_vport_ssvpc_packets));
	if (ret != 0) {
		LOG_ERR("Failed to get spoof check dropped packets number.\n");
		return;
	}
	ssvpc_incr = en_dev->last_tx_vport_ssvpc_packets - prev_ssvpc_num;
	if (!ssvpc_incr)
		return;
	LOG_DEBUG("%llu Spoofed packets detected in EP%d, PF%d\n", ssvpc_incr, EPID(en_dev->vport),
		  FUNC_NUM(en_dev->vport));
}

static void en_aux_service_task(struct work_struct *_work)
{
	struct zxdh_en_device *en_dev = container_of(_work, struct zxdh_en_device, service_task);

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	en_aux_spoof_check(en_dev);
}

static bool en_aux_all_vfs_spoof_check_off(struct zxdh_en_device *en_dev)
{
	u16 vf_idx = 0;
	s32 num_vfs = 0;
	struct pci_dev *pdev = NULL;
	struct zxdh_pf_device *pf_dev = NULL;
	struct dh_core_dev *dh_dev = NULL;

	dh_dev = en_dev->parent;
	pdev = en_dev->ops->get_pdev(dh_dev);
	pf_dev = dh_core_priv(dh_dev->parent);

	num_vfs = pci_num_vf(pdev);
	if (num_vfs == 0)
		return true;

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		if (pf_dev->vf_item[vf_idx].spoofchk == true)
			return false;
	}
	return true;
}

static void en_aux_service_timer(struct timer_list *t)
{
	unsigned long next_event_offset = HZ * 2;
	struct zxdh_en_device *en_dev = from_timer(en_dev, t, service_timer);
	struct zxdh_en_priv *en_priv = container_of(en_dev, struct zxdh_en_priv, edev);
	bool all_vfs_spoof_check_off_flag = en_aux_all_vfs_spoof_check_off(en_dev);

	/* Reset the timer */
	mod_timer(&en_dev->service_timer, next_event_offset + jiffies);
	if (!all_vfs_spoof_check_off_flag)
		queue_work(en_priv->events->wq, &en_dev->service_task);
}

static void en_aux_service_riscv_task(struct work_struct *_work)
{
	s32 retval = 0;
	time64_t time64;
	struct rtc_time tm;
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, service_riscv_task);
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (!msg)
		return;

	if (!IS_PF(en_dev->vport)) {
		kfree(msg);
		return;
	}

	msg->payload.hdr_to_cmn.pcie_id = en_dev->pcie_id;
	;
	msg->payload.hdr_to_cmn.write_bytes = 9;
	msg->payload.hdr_to_cmn.type = RISC_SERVER_TIME;
	msg->payload.hdr_to_cmn.field = 0;

	time64 = ktime_get_real_seconds();
	time64 += 28800;
	rtc_time64_to_tm(time64, &tm);

	msg->payload.time_cfg_msg.tmmng_type = 0xF0;
	msg->payload.time_cfg_msg.dir = 0x2;
	msg->payload.time_cfg_msg.year = tm.tm_year + 1900;
	msg->payload.time_cfg_msg.month = tm.tm_mon + 1;
	msg->payload.time_cfg_msg.day = tm.tm_mday;
	msg->payload.time_cfg_msg.hour = tm.tm_hour;
	msg->payload.time_cfg_msg.min = tm.tm_min;
	msg->payload.time_cfg_msg.sec = tm.tm_sec;

	retval = en_dev->ops->msg_send_cmd(en_dev->parent, MODULE_PF_TIMER_TO_RISC_MSG, msg, msg,
					   &para);
	if (retval != 0) {
		LOG_ERR("zxdh_send_command_to_riscv failed: %d\n", retval);
		en_dev->time_sync_done = false;
	} else {
		LOG_DEBUG("send msg timer to riscv:%d-%d-%d %d:%d:%d\n",
			  msg->payload.time_cfg_msg.year, msg->payload.time_cfg_msg.month,
			  msg->payload.time_cfg_msg.day, msg->payload.time_cfg_msg.hour,
			  msg->payload.time_cfg_msg.min, msg->payload.time_cfg_msg.sec);
		en_dev->time_sync_done = true;
	}

	kfree(msg);
}

static void en_aux_service_riscv_timer(struct timer_list *t)
{
	unsigned long next_event_offset;
	struct zxdh_en_device *en_dev = from_timer(en_dev, t, service_riscv_timer);
	struct zxdh_en_priv *en_priv = container_of(en_dev, struct zxdh_en_priv, edev);

	if (en_dev->time_sync_done)
		next_event_offset = HZ * 259200;
	else
		next_event_offset = HZ * 60;

	/* Reset the timer */
	mod_timer(&en_dev->service_riscv_timer, next_event_offset + jiffies);
	queue_work(en_priv->events->wq, &en_dev->service_riscv_task);
}

static void pf2vf_msg_proc_work_handler(struct work_struct *_work)
{
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, pf2vf_msg_proc_work);
	u64 virt_addr = 0;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	virt_addr = en_dev->ops->get_bar_virt_addr(en_dev->parent, 0) + ZXDH_BAR_MSG_OFFSET +
		    ZXDH_BAR_PFVF_MSG_OFFSET;
	zxdh_bar_irq_recv(MSG_CHAN_END_PF, MSG_CHAN_END_VF, virt_addr, en_dev);
}

static s32 pf2vf_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct zxdh_en_priv *en_priv = (struct zxdh_en_priv *)event_nb->ctx;

	queue_work(en_priv->events->wq, &en_priv->edev.pf2vf_msg_proc_work);

	return NOTIFY_OK;
}

static void riscv2aux_msg_proc_work_handler(struct work_struct *_work)
{
	struct zxdh_en_device *en_dev =
		container_of(_work, struct zxdh_en_device, riscv2aux_msg_proc_work);
	u64 virt_addr = 0;
	u16 src = MSG_CHAN_END_RISC;
	u16 dst = MSG_CHAN_END_PF;

	if (en_dev->init_comp_flag != AUX_INIT_COMPLETED)
		return;
	virt_addr = en_dev->ops->get_bar_virt_addr(en_dev->parent, 0) + ZXDH_BAR_MSG_OFFSET;
	zxdh_bar_irq_recv(src, dst, virt_addr, en_dev);
}

static s32 riscv2aux_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct zxdh_en_priv *en_priv = (struct zxdh_en_priv *)event_nb->ctx;

	LOG_DEBUG("is called\n");
	queue_work(en_priv->events->wq, &en_priv->edev.riscv2aux_msg_proc_work);
	return NOTIFY_OK;
}

typedef s32 (*zxdh_rdma_event_handler)(struct net_device *netdev, u8 event_type, void *data);
static zxdh_rdma_event_handler zxdh_rdma_events_handler;
void zxdh_rdma_events_register(zxdh_rdma_event_handler callback)
{
	if (!zxdh_rdma_events_handler)
		zxdh_rdma_events_handler = callback;
}
EXPORT_SYMBOL(zxdh_rdma_events_register);

void zxdh_rdma_events_unregister(void)
{
	zxdh_rdma_events_handler = NULL;
}
EXPORT_SYMBOL(zxdh_rdma_events_unregister);

s32 zxdh_rdma_events_call(struct net_device *netdev, u8 event_type, void *data)
{
	if (zxdh_rdma_events_handler)
		return zxdh_rdma_events_handler(netdev, event_type, data);

	return 0;
}

static s32 aux_unload_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct zxdh_en_priv *en_priv = (struct zxdh_en_priv *)event_nb->ctx;
	struct zxdh_en_device *en_dev = &en_priv->edev;

	HEAL_INFO("%s is called\n", en_dev->netdev->name);
	zxdh_rdma_events_call(en_dev->netdev, ZXDH_RDMA_HEALTH_EVENT, NULL);
	zxdh_aux_unload(en_priv);
	return NOTIFY_OK;
}

static s32 aux_load_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct zxdh_en_priv *en_priv = (struct zxdh_en_priv *)event_nb->ctx;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 err = 0;

	HEAL_INFO("%s is called\n", en_dev->netdev->name);
	err = zxdh_aux_load(en_priv);
	if (err != 0) {
		*((s32 *)data) = err;
		return NOTIFY_OK;
	}

	if (en_dev->is_rdma_aux_plug) {
		mutex_lock(&rdma_lock);
		en_dev->ops->unplug_adev(en_dev->parent, RDMA_AUX_DEVICE);
		en_dev->ops->plug_adev(en_dev->parent, RDMA_AUX_DEVICE);
		mutex_unlock(&rdma_lock);
	}

	return NOTIFY_OK;
}

static s32 aux_state_notifier(struct notifier_block *nb, unsigned long type, void *data)
{
	struct dh_event_nb *event_nb = dh_nb_cof(nb, struct dh_event_nb, nb);
	struct zxdh_en_priv *en_priv = (struct zxdh_en_priv *)event_nb->ctx;
	struct zxdh_en_device *en_dev = &en_priv->edev;

	if (en_dev->device_state == *((u8 *)data))
		return NOTIFY_OK;

	HEAL_INFO("%s device_state update: %d\n", en_dev->netdev->name, *((u8 *)data));
	en_dev->device_state = *((u8 *)data);
	if (en_dev->device_state == ZXDH_DEVICE_STATE_INTERNAL_ERROR) {
		netif_tx_stop_all_queues(en_dev->netdev);
		netif_carrier_off(en_dev->netdev);
		en_dev->link_up = false;
	} else if (en_dev->device_state == ZXDH_DEVICE_STATE_UP) {
		netif_tx_wake_all_queues(en_dev->netdev);
		if (en_dev->ops->is_bond(en_dev->parent))
			dh_bond_pf_link_info_get(en_priv);
		else
			dh_eq_async_link_info_int_process(en_priv);
	}

	return NOTIFY_OK;
}

void plug_adev_work_handler(struct work_struct *work)
{
	struct zxdh_en_device *en_dev = container_of(work, struct zxdh_en_device, plug_adev_work);

	en_dev->ops->plug_adev(en_dev->parent, RDMA_AUX_DEVICE);
	en_dev->is_rdma_aux_plug = true;
	en_dev->ops->is_rdma_aux_plug(en_dev->parent, en_dev->is_rdma_aux_plug, TRUE);
}

void unplug_adev_work_handler(struct work_struct *work)
{
	struct zxdh_en_device *en_dev = container_of(work, struct zxdh_en_device, unplug_adev_work);

	en_dev->ops->unplug_adev(en_dev->parent, RDMA_AUX_DEVICE);
	en_dev->is_rdma_aux_plug = false;
	en_dev->ops->is_rdma_aux_plug(en_dev->parent, en_dev->is_rdma_aux_plug, TRUE);
}

typedef u32 (*zxdh_pf_msg_func)(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct zxdh_en_device *en_dev);

struct zxdh_pf_msg_proc {
	enum zxdh_msg_op_code op_code;
	u8 proc_name[64];
	zxdh_pf_msg_func msg_proc;
};

static u32 zxdh_set_vf_link_state(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				  struct zxdh_en_device *en_dev)
{
	u32 ret = 0;
	u16 vf_idx = msg->hdr_vf.dst_pcie_id & (0xff);

	if (!msg->link_state_msg.is_link_force_set) {
		en_dev->speed = msg->link_state_msg.speed;
		en_dev->autoneg_enable = msg->link_state_msg.autoneg_enable;
		en_dev->supported_speed_modes = msg->link_state_msg.supported_speed_modes;
		en_dev->advertising_speed_modes = msg->link_state_msg.advertising_speed_modes;
		if (msg->link_state_msg.link_forced)
			return 0;
	}

	en_dev->ops->set_pf_link_up(en_dev->parent, msg->link_state_msg.link_up);
	if (en_dev->ops->get_pf_link_up(en_dev->parent))
		netif_carrier_on(en_dev->netdev);
	else
		netif_carrier_off(en_dev->netdev);

	LOG_DEBUG("[VF GET MSG FROM PF]--VF[%d] link_state[%s] update success!\n", vf_idx,
		  en_dev->ops->get_pf_link_up(en_dev->parent) ? "TRUE" : "FALSE");
	return ret;
}

static u32 zxdh_set_vf_reset(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			     struct zxdh_en_device *en_dev)
{
	return 0;
}

static u32 zxdh_set_vf_vlan(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
			    struct zxdh_en_device *edev)
{
	u32 ret = 0;
	/* update local var*/
	edev->vlan_dev.vlan_id = msg->vf_vlan_msg.vlan_id;
	edev->vlan_dev.qos = msg->vf_vlan_msg.qos;
	edev->vlan_dev.protocol = msg->vf_vlan_msg.protocl;

	return ret;
}

static u32 zxdh_pf_get_vf_queue(struct zxdh_msg_info *msg, struct zxdh_reps_info *reps,
				struct zxdh_en_device *edev)
{
	u32 ret = 0;
	u32 vir_queue_start;
	u32 vir_queue_num;
	u32 queue_index;
	u32 queue_num;
	u32 max_queue_num = edev->curr_queue_pairs;

	PLCR_LOG_INFO("vf's edev->vport     = 0x%x\n", edev->vport);
	PLCR_LOG_INFO("vf's max_queue_num(pairs) = 0x%x\n", max_queue_num);
	PLCR_LOG_INFO("edev->device_id = %x\n", edev->device_id);
	PLCR_LOG_INFO("edev->rq[0].vq->phy_index = %x\n", edev->rq[0].vq->phy_index);
	PLCR_LOG_INFO("edev->sq[0].vq->phy_index = %x\n", edev->sq[0].vq->phy_index);

	vir_queue_start = msg->plcr_pf_get_vf_queue_info_msg.vir_queue_start;
	vir_queue_num = msg->plcr_pf_get_vf_queue_info_msg.vir_queue_num;

	PLCR_LOG_INFO("vir_queue_start = 0x%x\n", vir_queue_start);
	PLCR_LOG_INFO("vir_queue_num   = 0x%x\n", vir_queue_num);

	if (max_queue_num > (vir_queue_num + vir_queue_num))
		max_queue_num = vir_queue_num + vir_queue_num;

	for (queue_index = vir_queue_start, queue_num = 0; queue_index < max_queue_num;
	     queue_index++, queue_num++) {
		//get rx&tx queue info
		reps->plcr_pf_get_vf_queue_info_rsp.phy_rxq[queue_num] =
			edev->rq[queue_num].vq->phy_index;
		reps->plcr_pf_get_vf_queue_info_rsp.phy_txq[queue_num] =
			edev->sq[queue_num].vq->phy_index;
	}

	reps->plcr_pf_get_vf_queue_info_rsp.phy_queue_num = queue_num;

	PLCR_LOG_INFO("queue_num   = 0x%x\n", queue_num);

	return ret;
}

struct zxdh_pf_msg_proc pf_msg_proc[] = {
	{ ZXDH_SET_VF_LINK_STATE, "set_vf_link_state", zxdh_set_vf_link_state },
	{ ZXDH_SET_VF_RESET, "set_vf_reset", zxdh_set_vf_reset },
	{ ZXDH_PF_SET_VF_VLAN, "pf_set_vf_vlan", zxdh_set_vf_vlan },
	{ ZXDH_PF_GET_VF_QUEUE_INFO, "pf_get_vf_queue_info", zxdh_pf_get_vf_queue },
};

s32 zxdh_vf_msg_recv_func(void *pay_load, u16 len, void *reps_buffer, u16 *reps_len, void *dev)
{
	struct zxdh_msg_info *msg = (struct zxdh_msg_info *)pay_load;
	struct zxdh_reps_info *reps = (struct zxdh_reps_info *)reps_buffer;
	struct zxdh_en_device *en_dev = (struct zxdh_en_device *)dev;
	s32 ret = 0;
	s32 i = 0;
	s32 num = 0;

	LOG_DEBUG("is called\n");
	if (len != sizeof(union zxdh_msg)) {
		LOG_ERR("invalid data_len\n");
		return -1;
	}

	if (!en_dev) {
		LOG_ERR("dev is NULL\n");
		return -1;
	}

	num = sizeof(pf_msg_proc) / sizeof(struct zxdh_pf_msg_proc);

	for (i = 0; i < num; i++) {
		*reps_len = sizeof(union zxdh_msg);
		if (pf_msg_proc[i].op_code == msg->hdr_vf.op_code) {
			LOG_DEBUG("%s is called", pf_msg_proc[i].proc_name);
			ret = pf_msg_proc[i].msg_proc(msg, reps, en_dev);
			if (ret != 0) {
				reps->flag = ZXDH_REPS_FAIL;
				LOG_ERR("%s failed, ret: %d\n", pf_msg_proc[i].proc_name, ret);
				return -1;
			}
			reps->flag = ZXDH_REPS_SUCC;
			return 0;
		}
	}

	LOG_ERR("invalid op_code: [%u]\n", msg->hdr_vf.op_code);
	reps->flag = ZXDH_INVALID_OP_CODE;
	return -2;
}

s32 dh_ip_mac_init(struct zxdh_en_priv *en_priv)
{
	s32 err = 0;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dpp_pf_info_t pf_info = { 0 };
	u8 ip4_mac[6] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 };
	u8 ip6_mac[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };

	pf_info.slot = en_dev->slot_id;
	pf_info.vport = en_dev->vport;

	if (en_dev->curr_multicast_num >= DEV_MULTICAST_MAX_NUM) {
		LOG_ERR("curr_multicast_num is beyond maximum\n");
		return -ENOSPC;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		err = dpp_multi_mac_add_member(&pf_info, ip4_mac);
		if (err != 0) {
			LOG_ERR("dpp_multi_mac_add_member mac:%pM failed, err:%d\n", ip4_mac, err);
			return err;
		}
		en_dev->curr_multicast_num++;
		err = dpp_multi_mac_add_member(&pf_info, ip6_mac);
		if (err != 0) {
			LOG_ERR("dpp_multi_mac_add_member mac:%pM failed, err:%d\n", ip6_mac, err);
			return err;
		}
		en_dev->curr_multicast_num++;
		LOG_INFO("current multicast num: %d", en_dev->curr_multicast_num);
	} else {
		err = zxdh_vf_dpp_add_ipv6_mac(en_dev, ip4_mac);
		if (err != 0) {
			LOG_ERR("zxdh_vf_ip_mac_init mac:%pM failed, err:%d\n", ip4_mac, err);
			return err;
		}
		en_dev->curr_multicast_num++;

		err = zxdh_vf_dpp_add_ipv6_mac(en_dev, ip6_mac);
		if (err != 0) {
			LOG_ERR("zxdh_vf_ip_mac_init mac:%pM failed, err:%d\n", ip6_mac, err);
			return err;
		}
		en_dev->curr_multicast_num++;
		LOG_INFO("current multicast num is %d", en_dev->curr_multicast_num);
	}

	LOG_DEBUG("config exist mac to np\n");
	return 0;
}

s32 dh_aux_ipv6_notifier_init(struct zxdh_en_priv *en_priv)
{
	s32 ret = 0;
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->ipv6_notifier.notifier_call = inet6_addr_change_notifier;
	en_dev->ipv6_notifier.priority = 0;
	ret = dh_inet6_addr_change_notifier_register(&(en_dev->ipv6_notifier));
	if (ret) {
		LOG_ERR("Failed to register inet6addr_notifier, ret:%d\n", ret);
		return ret;
	}
	LOG_INFO("netdev:%s ipv6_notifier_init success\n", en_dev->netdev->name);
	return ret;
}

s32 dh_aux_vxlan_netdev_notifier_init(struct zxdh_en_priv *en_priv)
{
	s32 ret = 0;
	struct zxdh_en_device *en_dev = &en_priv->edev;

	en_dev->vxlan_notifier.notifier_call = vxlan_netdev_change_notifier;
	en_dev->vxlan_notifier.priority = 0;
	ret = dh_vxlan_netdev_change_notifier_register(&(en_dev->vxlan_notifier));
	if (ret) {
		LOG_ERR("Failed to register vxlan_notifier, ret:%d\n", ret);
		return ret;
	}
	LOG_DEBUG("netdev:%s vxlan_notifier_init success\n", en_dev->netdev->name);
	return ret;
}

static void run_cfg_shell_script(struct work_struct *work)
{
	s32 ret = 0;

	ret = call_usermodehelper("/etc/zxdh_cfg/smart_nic_cfg_proc.sh", (char **)cfg_argv,
				  (char **)cfg_envp, UMH_WAIT_PROC);
	if (ret < 0) {
		LOG_DEBUG("run cfg_shell_script\n");
		LOG_DEBUG("Failed to execute shell script(err:%d)\n", ret);
	} else {
		LOG_DEBUG("run cfg_shell_script\n");
		LOG_DEBUG("Shell script executed successfully,ret:%d\n", ret);
	}
}

void zxdh_cap_pkt_uninit(struct zxdh_en_device *en_dev, bool offload_mode)
{
	u32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	if (en_dev->pkt_dev_flag == 1) {
		pf_info.slot = en_dev->slot_id;
		pf_info.vport = en_dev->vport;
		if (en_dev->pkt_wq) {
			destroy_workqueue(en_dev->pkt_wq);
			en_dev->pkt_wq = NULL;
		}

		if (offload_mode) {
			ret = dpp_pkt_capture_disable_all(&pf_info);
			if (ret != 0)
				LOG_ERR("dpp_pkt_capture_disable_all failed, ret:%d!!!\n", ret);

			ret = dpp_pkt_capture_table_flush(&pf_info);
			if (ret != 0)
				LOG_ERR("dpp_pkt_capture_table_flush failed, ret:%d!!!\n", ret);

			ret = dpp_pkt_capture_speed_set(&pf_info, ZXDH_PKT_INIT_SPEED);
			if (ret != 0)
				LOG_ERR("dpp_pkt_capture_speed_set failed, ret:%d!!!\n", ret);
		}

		en_dev->pkt_cap_switch = 1;
		en_dev->pkt_save_file_flag = 0;
		en_dev->pkt_file_num = 0;
		en_dev->pkt_save_file.enable_pkt_num_mode = 0;
		en_dev->pkt_save_file.pkt_file_size = 0;
		en_dev->pkt_save_file.pkt_set_count = 0;
		en_dev->pkt_save_file.pkt_cur_num = 0;
		en_dev->pkt_addr_marked = 0;
		en_dev->pkt_dev_speed = ZXDH_PKT_INIT_SPEED;
		en_dev->pkt_save_file.file_pos = 0;

		while (en_dev->pkt_save_file.ubuf_idx != en_dev->pkt_save_file.pkt_rbuf_idx) {
			if (en_dev->pkt_file_info &&
			    en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx]
				    .pkt_addr_array) {
				SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file.ubuf_idx]
						   .pkt_addr_array);
			}

			en_dev->pkt_save_file.ubuf_idx++;
			if (en_dev->pkt_save_file.ubuf_idx >=
			    (ZXDH_MQ_PAIRS_NUM * ZXDH_PF_MIN_DESC_NUM)) {
				en_dev->pkt_save_file.ubuf_idx = 0;
			}
		}

		if (en_dev->pkt_file_info) {
			if (en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx]
				    .pkt_addr_array) {
				SAFE_KFREE(en_dev->pkt_file_info[en_dev->pkt_save_file.pkt_rbuf_idx]
						   .pkt_addr_array);
			}

			kfree(en_dev->pkt_file_info);
			en_dev->pkt_file_info = NULL;
		}

		if (en_dev->pkt_save_file.log_file) {
			close_log_file(en_dev->pkt_save_file.log_file);
			en_dev->pkt_save_file.log_file = NULL;
		}

		en_dev->pkt_save_file.ubuf_idx = 0;
		en_dev->pkt_save_file.pkt_rbuf_idx = 0;
		en_dev->pkt_dev_flag = 0;
	}
}

s32 dh_aux_events_init(struct zxdh_en_priv *en_priv)
{
	struct dh_events *events = NULL;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;
	s32 ret = 0;
	u32 evt_num = ARRAY_SIZE(aux_events);

	if (!en_dev->ops->if_init(en_dev->parent))
		evt_num -= 1;

	events = kzalloc((sizeof(*events) + evt_num * sizeof(struct dh_event_nb)), GFP_KERNEL);
	if (unlikely(!events)) {
		LOG_ERR("events kzalloc failed: %p\n", events);
		ret = -ENOMEM;
		goto err_events_kzalloc;
	}

	events->evt_num = evt_num;
	events->dev = NULL;
	en_priv->events = events;
	events->wq = create_singlethread_workqueue("dh_aux_events");
	if (!events->wq) {
		LOG_ERR("events->wq create_singlethread_workqueue failed: %p\n", events->wq);
		ret = -ENOMEM;
		goto err_create_wq;
	}

	INIT_WORK(&en_dev->vf_link_info_update_work, vf_link_info_update_handler);
	INIT_WORK(&en_dev->link_info_irq_update_vf_work, link_info_irq_update_vf_handler);
	INIT_WORK(&en_dev->link_info_irq_process_work, link_info_irq_process_handler);
	INIT_WORK(&en_dev->link_info_irq_update_np_work, link_info_irq_update_np_work_handler);
	INIT_WORK(&en_dev->rx_mode_set_work, rx_mode_set_handler);
	INIT_WORK(&en_dev->pf2vf_msg_proc_work, pf2vf_msg_proc_work_handler);
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		INIT_WORK(&en_dev->service_task, en_aux_service_task);
		INIT_WORK(&en_dev->service_riscv_task, en_aux_service_riscv_task);
	}

	INIT_WORK(&en_dev->riscv2aux_msg_proc_work, riscv2aux_msg_proc_work_handler);
	INIT_WORK(&en_dev->plug_adev_work, plug_adev_work_handler);
	INIT_WORK(&en_dev->unplug_adev_work, unplug_adev_work_handler);

	INIT_WORK(&en_dev->smart_nic_copy_work, run_cfg_shell_script);
	queue_work(events->wq, &en_dev->smart_nic_copy_work);

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		timer_setup(&en_dev->service_timer, en_aux_service_timer, 0);
		ret = mod_timer(&en_dev->service_timer, jiffies);
		if (ret) {
			LOG_ERR("timer add failed\n");
			goto err_mod_timer;
		}

		timer_setup(&en_dev->service_riscv_timer, en_aux_service_riscv_timer, 0);
		ret = mod_timer(&en_dev->service_riscv_timer, jiffies);
		if (ret) {
			LOG_ERR("timer add failed\n");
			goto err_riscv_timer;
		}
	}

	for (i = 0; i < evt_num; i++) {
		events->notifiers[i].nb = aux_events[i];
		events->notifiers[i].ctx = en_priv;
		en_dev->ops->aux_nh_attach(en_dev->parent, &events->notifiers[i].nb, true);
	}

	return ret;

err_riscv_timer:
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		del_timer_sync(&en_dev->service_riscv_timer);
err_mod_timer:
	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF)
		del_timer_sync(&en_dev->service_timer);
	destroy_workqueue(events->wq);
err_create_wq:
	kfree(events);
err_events_kzalloc:
	return ret;
}

void dh_aux_events_uninit(struct zxdh_en_priv *en_priv)
{
	struct dh_events *events = en_priv->events;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	s32 i = 0;

	for (i = events->evt_num - 1; i >= 0; i--) {
		// dh_eq_notifier_unregister(&en_priv->eq_table, &events->notifiers[i].nb);
		en_dev->ops->aux_nh_attach(en_dev->parent, &events->notifiers[i].nb, false);
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) {
		del_timer_sync(&en_dev->service_timer);
		del_timer_sync(&en_dev->service_riscv_timer);
		zxdh_cap_pkt_uninit(en_dev, true);
	}

	destroy_workqueue(en_priv->events->wq);
	kfree(en_priv->events);
}

static s32 mgr_test_cnt(void *data, u16 len, void *reps, u16 *reps_len, void *dev)
{
	u8 *pay_load = (u8 *)data;
	u8 *reps_buffer = (u8 *)reps;
	u16 idx = 0;
	u16 sum = 0;

	if (!reps_buffer)
		return 0;

	for (idx = 0; idx < len; idx++)
		sum += pay_load[idx];

	reps_buffer[0] = (u8)sum;
	reps_buffer[1] = (u8)(sum >> 8);
	*reps_len = 2;
	return 0;
}

static s32 msgq_test_func(void *data, u16 len, void *reps, u16 *reps_len, void *dev)
{
	if (!reps)
		return 0;

	*reps_len = len;
	return 0;
}

typedef u32 (*zxdh_vqmb_msg_func)(struct vqmb_to_host_msg *msg, struct zxdh_reps_info *reps,
				  struct zxdh_en_device *en_dev);

struct zxdh_vqmb_msg_proc {
	u8 proc_name[64];
	zxdh_vqmb_msg_func msg_proc;
};

enum {
	MSG_BIT_VQMB_CTRL_NP = 1,
	VQMB_MSG_TYPE_MAX = 63,
};

static u32 vqmb_port_ctrl_func(struct vqmb_to_host_msg *msg, struct zxdh_reps_info *reps,
			       struct zxdh_en_device *en_dev)
{
	u32 err = 0;
	bool port_enable = msg->vqmb_port_ctrl_msg.port_enable;

	if (port_enable) {
		en_dev->vqmb_port_ctl = !port_enable;
		if (netif_running(en_dev->netdev))
			err = zxdh_port_enable(en_dev, port_enable);
	} else {
		if (netif_running(en_dev->netdev))
			err = zxdh_port_enable(en_dev, port_enable);
		en_dev->vqmb_port_ctl = !port_enable;
	}
	LOG_INFO("port_enable: %d, vfid: %d\n", port_enable, msg->vqmb_hdr.vfid);
	return err;
}

struct zxdh_vqmb_msg_proc vqmb_msg_proc[] = {
	{ "invalid", NULL },
	{ "vqmb_port_ctrl_func", vqmb_port_ctrl_func },
};

s32 zxdh_vqmb_msg_recv_func(void *pay_load, u16 len, void *reps_buffer, u16 *reps_len, void *dev)
{
	struct vqmb_to_host_msg *msg = (struct vqmb_to_host_msg *)pay_load;
	struct zxdh_reps_info *reps = (struct zxdh_reps_info *)reps_buffer;
	struct zxdh_en_device *en_dev = (struct zxdh_en_device *)dev;
	s32 ret = 0;
	u32 num = 0;
	u32 i = 0;

	if (!en_dev) {
		LOG_ERR("dev is NULL\n");
		return -1;
	}

	*reps_len = sizeof(reps->flag);
	num = ARRAY_SIZE(vqmb_msg_proc);
	for (i = MSG_BIT_VQMB_CTRL_NP; i < VQMB_MSG_TYPE_MAX; i++) {
		if (i >= num)
			break;
		if (((msg->vqmb_hdr.bits & (1 << i)) == 0))
			continue;
		LOG_DEBUG("%s is called", vqmb_msg_proc[i].proc_name);
		if (!vqmb_msg_proc[i].msg_proc)
			continue;
		ret = vqmb_msg_proc[i].msg_proc(msg, reps, en_dev);
		if (ret != 0) {
			reps->flag = ZXDH_REPS_FAIL;
			LOG_ERR("%s failed, ret: %d\n", vqmb_msg_proc[i].proc_name, ret);
			return -1;
		}
	}

	reps->flag = ZXDH_REPS_SUCC;
	LOG_DEBUG("reps->flag: 0x%x, reps_len: %d\n", reps->flag, *reps_len);
	return 0;
}

s32 dh_aux_msg_recv_func_register(void)
{
	s32 ret = 0;

	mutex_init(&rdma_lock);
	ret = zxdh_bar_chan_msg_recv_register(MODULE_PF_BAR_MSG_TO_VF, zxdh_vf_msg_recv_func);
	if (ret != 0) {
		LOG_ERR("event_id[%d] register failed: %d\n", MODULE_PF_BAR_MSG_TO_VF, ret);
		return ret;
	}

	ret = zxdh_bar_chan_msg_recv_register(MODULE_DHTOOL, zxdh_tools_sendto_user_netlink);
	if (ret != 0) {
		LOG_ERR("event_id[%d] register failed: %d\n", MODULE_DHTOOL, ret);
		goto unregister_pf_to_vf;
	}

	ret = zxdh_bar_chan_msg_recv_register(MODULE_DEMO, mgr_test_cnt);
	if (ret != 0) {
		LOG_ERR("event_id[%d] register failed: %d\n", MODULE_DEMO, ret);
		goto unregister_dhtool;
	}

	ret = zxdh_bar_chan_msg_recv_register(MODULE_MSGQ, msgq_test_func);
	if (ret != 0) {
		LOG_ERR("event_id[%d] register failed: %d\n", MODULE_MSGQ, ret);
		goto unregister_demo;
	}

	ret = zxdh_bar_chan_msg_recv_register(MODULE_VQMB, zxdh_vqmb_msg_recv_func);
	if (ret != 0) {
		LOG_ERR("event_id[%d] register failed: %d\n", MODULE_VQMB, ret);
		goto unregister_msgq;
	}

	return ret;
unregister_msgq:
	zxdh_bar_chan_msg_recv_unregister(MODULE_MSGQ);
unregister_demo:
	zxdh_bar_chan_msg_recv_unregister(MODULE_DEMO);
unregister_dhtool:
	zxdh_bar_chan_msg_recv_unregister(MODULE_DHTOOL);
unregister_pf_to_vf:
	zxdh_bar_chan_msg_recv_unregister(MODULE_PF_BAR_MSG_TO_VF);
	return ret;
}

void dh_aux_msg_recv_func_unregister(void)
{
	mutex_destroy(&rdma_lock);
	zxdh_bar_chan_msg_recv_unregister(MODULE_VQMB);
	zxdh_bar_chan_msg_recv_unregister(MODULE_MSGQ);
	zxdh_bar_chan_msg_recv_unregister(MODULE_DEMO);
	zxdh_bar_chan_msg_recv_unregister(MODULE_DHTOOL);
	zxdh_bar_chan_msg_recv_unregister(MODULE_PF_BAR_MSG_TO_VF);
}
