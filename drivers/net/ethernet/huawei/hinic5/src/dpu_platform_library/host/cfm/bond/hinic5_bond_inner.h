/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_bond_inner.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_BOND_INNER_H
#define HINIC5_BOND_INNER_H

#include <net/bonding.h>
#include <linux/list.h>
#include <linux/srcu.h>
#include "hinic5_bond.h"

extern struct srcu_struct bdev_srcu;

#define bond_slave_info(bond_dev, slave_dev, fmt, ...) \
	netdev_info(bond_dev, "[BOND] (slave %s): " fmt, (slave_dev)->name, ##__VA_ARGS__)
#define bond_slave_warn(bond_dev, slave_dev, fmt, ...) \
	netdev_warn(bond_dev, "[BOND] (slave %s): " fmt, (slave_dev)->name, ##__VA_ARGS__)
#define bond_slave_dbg(bond_dev, slave_dev, fmt, ...) \
	netdev_dbg(bond_dev, "[BOND] (slave %s): " fmt, (slave_dev)->name, ##__VA_ARGS__)
#define bond_slave_err(bond_dev, slave_dev, fmt, ...) \
	netdev_err(bond_dev, "[BOND] (slave %s): " fmt, (slave_dev)->name, ##__VA_ARGS__)

#define bond_master_info(bond_dev, fmt, ...) \
	netdev_info(bond_dev, "[BOND]" fmt, ##__VA_ARGS__)
#define bond_master_warn(bond_dev, fmt, ...) \
	netdev_warn(bond_dev, "[BOND]" fmt, ##__VA_ARGS__)
#define bond_master_dbg(bond_dev, fmt, ...) \
	netdev_dbg(bond_dev, "[BOND]" fmt, ##__VA_ARGS__)
#define bond_master_err(bond_dev, fmt, ...) \
	netdev_err(bond_dev, "[BOND]" fmt, ##__VA_ARGS__)

#define PORT_INVALID_ID		0xFF

#define BITMAP_SET(bm, bit)		((bm) |= (typeof(bm))(1U << (bit)))
#define BITMAP_CLR(bm, bit)		((bm) &= ~((typeof(bm))(1U << (bit))))
#define BITMAP_JUDGE(bm, bit)	((bm) & (typeof(bm))(1U << (bit)))

enum bond_dev_status {
	BOND_DEV_STATUS_IDLE,
	BOND_DEV_STATUS_ACTIVATED,
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16UL
#endif
#define HINIC5_BOND_START_ID	1
#define HINIC5_MAX_BODN_ID_NUM 64 /* MAX BOND ID for driver */
#define HINIC5_INVALID_BOND_ID 0xFF

#define HINIC5_BOND_ID_IS_VALID(_id)   (((_id) >= HINIC5_BOND_START_ID) && ((_id) < HINIC5_MAX_BODN_ID_NUM))
#define HINIC5_BOND_ID_IS_INVALID(_id)	(!(HINIC5_BOND_ID_IS_VALID(_id)))

struct hinic5_bond_dev {
	char name[BOND_NAME_MAX_LEN];
	char chip_name[IFNAMSIZ];
	struct bond_attr bond_attr;
	struct bond_attr new_attr;
	struct bonding *bond;
	struct kref ref;
	enum bond_dev_status status;
	u8 slot_used[HINIC5_BOND_USER_NUM];
	struct workqueue_struct *wq;
	struct delayed_work bond_work;
	struct bond_tracker tracker;
	spinlock_t lock; /* lock for change status */
	u32 service_en_bitmap;
	u32 chip_bond_id;
	bool dead; /* check bdev liveness under SRCU */
};

#define HINIC5_MAX_BOND_ID_PER_CARD 5 /* MAX BOND ID for per chip */
struct hinic5_bond_chip {
	u8 chip_bond_id[HINIC5_MAX_BOND_ID_PER_CARD];
	char chip_name[IFNAMSIZ];
	struct list_head node;
	u32 bond_num;
};

void bond_disable_netdev_event(void);
int bond_enable_netdev_event(void);

struct socket **hinic5_get_bond_mngr_sock_addr(void);
struct socket *hinic5_get_bond_mngr_sock(void);

int hinic5_bond_event_attach(struct bonding *bond, enum hinic5_bond_user user);
bool bond_call_srv_attach_func(enum hinic5_bond_user user, struct bonding *bond);
void bond_handle_rtnl_event(struct net_device *ndev);
u8 bond_dev_track_port(struct hinic5_bond_dev *bdev, struct net_device *ndev);
struct hinic5_bond_dev *bond_get_bdev(const struct bonding *bond);
bool hinic5_bond_slave_is_match(struct bonding *bond);
void bond_dev_free_chip_bond_id(struct hinic5_bond_dev *bdev);

#endif