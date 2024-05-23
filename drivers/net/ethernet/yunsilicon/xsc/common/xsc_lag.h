/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_LAG_H
#define XSC_LAG_H

#include <net/ip_fib.h>

#define XSC_LAG_PORT_START	15
#define XSC_LAG_NUM_MAX		0x30

struct lag_func {
	struct xsc_core_device	*xdev;
	struct net_device		*netdev;
};

/* Used for collection of netdev event info. */
struct lag_tracker {
	enum   netdev_lag_hash		hash_type;
	enum   netdev_lag_hash		old_hash_type;
	enum   netdev_lag_tx_type	tx_type;
	struct netdev_lag_lower_state_info	netdev_state[XSC_MAX_PORTS];
	struct net_device *ndev[XSC_MAX_PORTS];
	unsigned int is_hw_bonded:1;
	unsigned int is_kernel_bonded:1;
	unsigned int lag_disable:1;
	u8 gw_dmac0[6];
	u8 gw_dmac1[6];
};

/* used in tracking fib events */
struct lag_mp {
	struct notifier_block		fib_nb;
	struct fib_info			*mfi;
	struct workqueue_struct		*wq;
};

struct xsc_lag {
	u8				flags;
	struct kref			ref;
	u8				v2p_map[XSC_MAX_PORTS];
	struct lag_func			pf[XSC_MAX_PORTS];
	struct lag_tracker		tracker;
	struct workqueue_struct		*wq;
	struct delayed_work		bond_work;
	struct notifier_block		nb;
	struct lag_mp			lag_mp;
	u16				lag_id;
	u16				lag_cnt;
};

struct xsc_fib_event_work {
	struct work_struct	work;
	struct xsc_lag		*ldev;
	unsigned long		event;
	union {
		struct fib_entry_notifier_info fen_info;
		struct fib_nh_notifier_info fnh_info;
	};
};

enum {
	XSC_LAG_FLAG_ROCE	= 1 << 0,
	XSC_LAG_FLAG_SRIOV	= 1 << 1,
	XSC_LAG_FLAG_MULTIPATH	= 1 << 2,
};

enum {
	XSC_BOND_FLAG_KERNEL	= 1 << 3,
};

enum xsc_lag_hash {
	XSC_LAG_HASH_L23,
	XSC_LAG_HASH_L34,
	XSC_LAG_HASH_E23,
	XSC_LAG_HASH_E34
};

#define MAC_SHIFT			1
#define MAC_0_1_LOGIC		0
#define MAC_0_LOGIC			(0 + MAC_SHIFT)
#define MAC_1_LOGIC			(1 + MAC_SHIFT)
#define MAC_INVALID			0xff

#define XSC_LAG_MODE_FLAGS (XSC_LAG_FLAG_ROCE | XSC_LAG_FLAG_SRIOV |\
				XSC_LAG_FLAG_MULTIPATH)

#define GET_LAG_MEMBER_BITMAP(remap_port1, remap_port2)		\
	((((remap_port1) != MAC_INVALID) ? BIT((remap_port1) - MAC_SHIFT) : 0) |		\
	(((remap_port2) != MAC_INVALID) ? BIT((remap_port2) - MAC_SHIFT) : 0))

static inline bool __xsc_bond_is_active(struct xsc_lag *ldev)
{
	return !!(ldev->flags & XSC_BOND_FLAG_KERNEL);
}

static inline bool __xsc_lag_is_active(struct xsc_lag *ldev)
{
	return !!(ldev->flags & XSC_LAG_MODE_FLAGS);
}

static bool __maybe_unused __xsc_lag_is_multipath(struct xsc_lag *ldev)
{
	return !!(ldev->flags & XSC_LAG_FLAG_MULTIPATH);
}

static bool __maybe_unused __xsc_lag_is_roce(struct xsc_lag *ldev)
{
	return !!(ldev->flags & XSC_LAG_FLAG_ROCE);
}

static inline struct xsc_lag *xsc_lag_dev_get(struct xsc_core_device *xdev)
{
	return xdev->priv.lag;
}

void xsc_lag_add(struct xsc_core_device *xdev, struct net_device *netdev);
void xsc_lag_remove(struct xsc_core_device *xdev);
void xsc_lag_add_xdev(struct xsc_core_device *xdev);
void xsc_lag_remove_xdev(struct xsc_core_device *xdev);
void xsc_lag_enable(struct xsc_core_device *xdev);
void xsc_lag_disable(struct xsc_core_device *xdev);

#endif /* XSC_LAG_H */
