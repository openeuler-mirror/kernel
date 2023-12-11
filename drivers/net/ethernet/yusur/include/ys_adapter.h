/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_ADPTER_H_
#define __YS_ADPTER_H_

#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/pci.h>

struct hw_adapter_ops {
	int (*hw_adp_init)(struct net_device *ndev);
	void (*hw_adp_uninit)(struct net_device *ndev);
	int (*hw_adp_start)(struct net_device *ndev);
	void (*hw_adp_stop)(struct net_device *ndev);
	void (*hw_adp_update_stat)(struct net_device *ndev);
	int (*hw_adp_send)(struct sk_buff *skb, struct net_device *ndev);
	int (*hw_adp_running)(struct net_device *ndev);
	int (*hw_adp_get_init_irq_sub)(struct pci_dev *pdev, int index,
				       void *irq_sub);
	int (*hw_adp_irq_pre_init)(struct pci_dev *pdev);
	void (*hw_adp_set_mac)(struct net_device *ndev);
	int (*hw_adp_detect_sysfs_attrs)(struct device_attribute **attrs);
	int (*hw_adp_i2c_init)(struct pci_dev *pdev);
};

#endif /* __YS_ADPTER_H_ */
