/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_NDEV_OPS_H_
#define __YS_NDEV_OPS_H_

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#define YS_MAX_MTU 9600

extern const struct net_device_ops ys_ndev_ops;

struct ys_ndev_hw_ops {
	void (*ys_init_hw_features)(struct net_device *ndev);
	int (*ys_ndev_change_mtu)(struct net_device *ndev, int new_mtu);
	int (*ys_update_cfg)(struct net_device *ndev, u16 vf_num);
	int (*ys_delete_cfg)(struct net_device *ndev, u16 vf_num);
	int (*ys_features_set)(struct net_device *ndev,
			       netdev_features_t features);
	int (*ys_set_rx_flags)(struct net_device *ndev);
	int (*ys_set_mc_mac)(struct net_device *ndev, const u8 *mac,
			     bool enable);
	int (*ys_set_port_vf_vlan)(struct net_device *ndev, u16 vf, u16 vlan,
				   u8 qos, bool enable);
	void (*ys_set_trunk_vid)(struct net_device *netdev, u16 vlan_id,
				 u8 enable);
};

int ys_ndev_hw_init(struct net_device *ndev);
int ys_ndev_hw_uninit(struct net_device *ndev);

#endif /* __YS_NDEV_OPS_H_ */
