/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXDH_HARDWARE_BOND_H_
#define _ZXDH_HARDWARE_BOND_H_

#include "../en_aux.h"

struct zxdh_bond_group;
extern const struct net_device_ops zxdh_netdev_ops;

#define ZXDH_SPECIAL_LGA_ID 0

struct upper_info_struct {
	struct net_device *upper_dev;
	struct netdev_lag_upper_info lag_upper_info;
};

struct event_node {
	struct list_head list;
	unsigned long event;
	struct upper_info_struct upper_info;
	bool linking;
	u8 link_up;
	u8 tx_enabled;
	u32 idx;
	s32 group_slave_num;
};

struct event_ctx {
	struct delayed_work bond_work;
	spinlock_t lock;
	struct list_head event_list;
	u32 idx;
};

struct zxdh_bond_device {
	struct dh_core_dev *pf_core_dev; /* backlink to PF core dev struct */
	struct net_device *netdev; /* this PF's netdev */
	struct net_device *upper_netdev; /* upper bonding netdev */
	struct notifier_block notif_block;

	struct event_ctx ctx;
	struct workqueue_struct *wq;

	u8 bonded : 1; /* currently bonded */
	u8 tx_enabled : 1;
	u8 link_up : 1;

	bool primary; /* this is a primary port */
	bool is_special_bond_dev;

	u16 rxq;
	u16 txq;

	u16 slot;
	u16 vport;

	u16 vfid;
	u16 ovs_pf_vfid;
	u8 phy_port;
	// u16 primary_vfid;
	bool linking;
	struct list_head node;

	struct upper_info_struct upper_info;
	struct zxdh_bond_group *group;
	struct sockaddr last_mac_addr;
};

struct zxdh_bond_group {
	char name[IFNAMSIZ];

	s32 group_ida;

	u8 lag_tx_type; /* enum zxdh_netdev_lag_tx_type */
	u8 hash_policy;
	u8 num_slaves;

	bool configured;

	struct list_head node;
};

static inline bool zxdh_netdev_is_hwbond(const struct net_device *netdev)
{
	return (&((struct zxdh_en_priv *)netdev_priv(netdev))->edev)->is_hwbond;
}

static inline u16 zxdh_bond_device_get_vport(const struct zxdh_bond_device *bond_dev)
{
	return bond_dev->vport;
}

static inline const char *zxdh_bond_group_name(const struct zxdh_bond_group *group)
{
	return group->name;
}

void init_bond_dev_hooks(void);
void destroy_bond_dev_hooks(void);
void zxdh_lag_lock_init(void);
void zxdh_lag_lock_deinit(void);

#endif /* END _ZXDH_HARDWARE_BOND_H_ */
