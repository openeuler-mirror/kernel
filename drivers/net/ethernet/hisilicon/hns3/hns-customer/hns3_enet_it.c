// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "../hnae3.h"
#include "hns3_enet_it.h"
#include "hns3pf/hclge_main_it.h"
#include "../hns3_enet.h"

extern const char hns3_driver_string[];
extern const char hns3_copyright[];

#ifdef CONFIG_IT_VALIDATION

#define HNAE_DRIVER_VERSION		"B075"
#define HNAE_DRIVER_VERSION_MAX_LEN	8

#ifdef CONFIG_HNS3_X86
#define HNAE3_DEV_ID_X86_25_GE			0xA125
#endif

extern struct ethtool_ops hns3vf_ethtool_ops;
extern struct ethtool_ops hns3_ethtool_ops;
extern struct net_device_ops hns3_nic_netdev_ops;
extern const struct hnae3_client_ops client_ops;
extern struct hnae3_client client;
extern struct pci_driver hns3_driver;
extern const char hns3_driver_name[];
extern struct pci_error_handlers hns3_err_handler;

extern int hns3_set_link_ksettings_it(struct net_device *netdev,
				      const struct ethtool_link_ksettings *cmd);

/* hns3_pci_tbl - PCI Device ID Table
 *
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
const struct pci_device_id hns3_pci_tbl_it[] = {
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_GE), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_25GE), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_25GE_RDMA),
	 HNAE3_DEV_SUPPORT_ROCE_DCB_BITS},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_25GE_RDMA_MACSEC),
	 HNAE3_DEV_SUPPORT_ROCE_DCB_BITS},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_50GE_RDMA),
	 HNAE3_DEV_SUPPORT_ROCE_DCB_BITS},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_50GE_RDMA_MACSEC),
	 HNAE3_DEV_SUPPORT_ROCE_DCB_BITS},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_100G_RDMA_MACSEC),
	 HNAE3_DEV_SUPPORT_ROCE_DCB_BITS},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_100G_VF), 0},
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_100G_RDMA_DCB_PFC_VF),
	 HNAE3_DEV_SUPPORT_ROCE_DCB_BITS},
#ifdef CONFIG_HNS3_X86
	{PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_X86_25_GE), 0},
#endif
	/* required last entry */
	{0, }
};
MODULE_DEVICE_TABLE(pci, hns3_pci_tbl_it);

#ifdef CONFIG_EXT_TEST
void hns3_nic_net_timeout_it(struct net_device *ndev)
{
	if (!hns3_get_tx_timeo_queue_info(ndev))
		return;

	nic_call_event(ndev, HNAE3_FUNC_RESET_CUSTOM);
}
#endif

int hns3_nic_do_ioctl_it(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case (SIOCDEVPRIVATE + 4):
		if (hns3_ioctl)
			return hns3_ioctl(netdev, ifr->ifr_data);
		pr_err("open nic_test failed");
		return -EINVAL;
	default:
		return -EINVAL;
	}
}

#if (KERNEL_VERSION(4, 19, 0) > LINUX_VERSION_CODE)
u16 hns3_nic_select_queue_it(struct net_device *ndev, struct sk_buff *skb,
			     void *accel_priv,
			     select_queue_fallback_t fallback)
#else
u16 hns3_nic_select_queue_it(struct net_device *ndev, struct sk_buff *skb,
			     struct net_device *accel_priv,
			     select_queue_fallback_t fallback)
#endif
{
#define HNS3_VLAN_PRIO_SHIFT	13
	if (!accel_priv)
		if (skb->vlan_tci && !skb->priority)
			skb->priority = skb->vlan_tci >> HNS3_VLAN_PRIO_SHIFT;

#if (KERNEL_VERSION(4, 19, 0) > LINUX_VERSION_CODE)
	return fallback(ndev, skb);
#else
	return fallback(ndev, skb, accel_priv);
#endif
}

static int __init hns3_init_module_it(void)
{
	struct ethtool_ops *loc_ethtool_ops;
	struct net_device_ops *ndev_ops;
	int ret;

#ifdef CONFIG_EXT_TEST
	struct pci_error_handlers *err_handlers;

	err_handlers = (struct pci_error_handlers *)&hns3_err_handler;
	err_handlers->slot_reset = NULL;
#endif

	pr_info("%s: %s - version\n", hns3_driver_name, hns3_driver_string);
	pr_info("%s: %s\n", hns3_driver_name, hns3_copyright);

	strncpy(hns3_driver_version, HNAE_DRIVER_VERSION,
		HNAE_DRIVER_VERSION_MAX_LEN);

	loc_ethtool_ops = (struct ethtool_ops *)&hns3_ethtool_ops;
	loc_ethtool_ops->set_link_ksettings = hns3_set_link_ksettings_it;
	client.type = HNAE3_CLIENT_KNIC;
	snprintf(client.name, HNAE3_CLIENT_NAME_LENGTH - 1, "%s",
		 hns3_driver_name);

	client.ops = &client_ops;
	ndev_ops = (struct net_device_ops *)&hns3_nic_netdev_ops;
	ndev_ops->ndo_do_ioctl = hns3_nic_do_ioctl_it;
#ifdef CONFIG_EXT_TEST
	ndev_ops->ndo_tx_timeout = hns3_nic_net_timeout_it;
#endif
	ndev_ops->ndo_select_queue = hns3_nic_select_queue_it;

	INIT_LIST_HEAD(&client.node);
	hns3_dbg_register_debugfs(hns3_driver_name);

	ret = hnae3_register_client(&client);
	if (ret)
		goto err_reg_client;

	hns3_driver.id_table = hns3_pci_tbl_it;
	ret = pci_register_driver(&hns3_driver);
	if (ret)
		goto err_reg_driver;

	return ret;

err_reg_driver:
	hnae3_unregister_client(&client);
err_reg_client:
	hns3_dbg_unregister_debugfs();
	return ret;
}
module_init(hns3_init_module_it);
#endif
