// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "hnae3.h"
#include "hns3_enet_it.h"
#include "hns3_enet.h"

extern const char hns3_driver_string[];
extern const char hns3_copyright[];

#ifdef CONFIG_IT_VALIDATION

#define HNAE_DRIVER_VERSION		"1.9.20.2"

extern struct net_device_ops hns3_nic_netdev_ops;
extern const struct hnae3_client_ops client_ops;
extern struct hnae3_client client;
extern struct pci_driver hns3_driver;
extern const char hns3_driver_name[];

#if (KERNEL_VERSION(4, 19, 0) > LINUX_VERSION_CODE)
u16 hns3_nic_select_queue_it(struct net_device *ndev, struct sk_buff *skb,
			     void *accel_priv, select_queue_fallback_t fallback)
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
	struct net_device_ops *ndev_ops;
	int ret;

	pr_info("%s: %s - version\n", hns3_driver_name, hns3_driver_string);
	pr_info("%s: %s\n", hns3_driver_name, hns3_copyright);

	strncpy(hns3_driver_version, HNAE_DRIVER_VERSION,
		strlen(hns3_driver_version));

	client.type = HNAE3_CLIENT_KNIC;
	snprintf(client.name, HNAE3_CLIENT_NAME_LENGTH - 1, "%s",
		 hns3_driver_name);

	client.ops = &client_ops;
	ndev_ops = (struct net_device_ops *)&hns3_nic_netdev_ops;
	ndev_ops->ndo_select_queue = hns3_nic_select_queue_it;

	INIT_LIST_HEAD(&client.node);
	hns3_dbg_register_debugfs(hns3_driver_name);

	ret = hnae3_register_client(&client);
	if (ret)
		goto err_reg_client;

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
