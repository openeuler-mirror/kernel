/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_LAG_H
#define XSC_LAG_H

#define XSC_BOARD_LAG_MAX    XSC_MAX_PORTS

enum lag_event_type {
	XSC_LAG_CREATE,
	XSC_LAG_ADD_MEMBER,
	XSC_LAG_REMOVE_MEMBER,
	XSC_LAG_UPDATE_MEMBER_STATUS,
	XSC_LAG_UPDATE_HASH_TYPE,
	XSC_LAG_DESTROY,
	XSC_LAG_EVENT_MAX
};

enum lag_slave_status {
	XSC_LAG_SLAVE_INACTIVE,
	XSC_LAG_SLAVE_ACTIVE,
	XSC_LAG_SLAVE_STATUS_MAX,
};

enum {
	XSC_SLEEP,
	XSC_WAKEUP,
	XSC_EXIT,
};

enum {
	XSC_LAG_FLAG_ROCE	= 1 << 0,
	XSC_LAG_FLAG_SRIOV	= 1 << 1,
	XSC_LAG_FLAG_KERNEL	= 1 << 2,
};

enum xsc_lag_hash {
	XSC_LAG_HASH_L23,
	XSC_LAG_HASH_L34,
	XSC_LAG_HASH_E23,
	XSC_LAG_HASH_E34,
};

enum {
	QOS_LAG_OP_CREATE	= 0,
	QOS_LAG_OP_ADD_MEMBER	= 1,
	QOS_LAG_OP_DEL_MEMBER	= 2,
	QOS_LAG_OP_DESTROY	= 3,
};

#define BOND_ID_INVALID		U8_MAX
#define	BOARD_ID_INVALID	U32_MAX
#define LAG_ID_INVALID		U16_MAX

#define XSC_LAG_MODE_FLAGS (XSC_LAG_FLAG_ROCE | XSC_LAG_FLAG_SRIOV | XSC_LAG_FLAG_KERNEL)

struct xsc_lag {
	struct net_device *bond_dev;
	u8	   bond_mode;
	enum   netdev_lag_tx_type	tx_type;
	enum   netdev_lag_hash		hash_type;
	u8			lag_type;
	u16			lag_id;
	atomic_t		qp_cnt[XSC_MAX_PORTS];
	struct list_head	slave_list;
	u8		xsc_member_cnt;
	u32		board_id;
	int		mode_changes_in_progress;
	u8		not_roce_lag_xdev_mask;
};

struct xsc_lag_event {
	struct list_head	node;
	enum   lag_event_type event_type;
	struct xsc_core_device	*xdev;
	struct xsc_core_device	*roce_lag_xdev;
	u8		bond_mode;
	u8		lag_type;
	u8		hash_type;
	u8		lag_sel_mode;
	u16		lag_id;
	enum	lag_slave_status slave_status;
	u8		is_roce_lag_xdev;
	u8		not_roce_lag_xdev_mask;
};

struct lag_event_list {
	struct list_head	head;
	spinlock_t		lock;	/* protect lag_event_list */
	struct task_struct	*bond_poll_task;
	wait_queue_head_t	wq;
	int			wait_flag;
	u8	event_type;
};

struct xsc_board_lag {
	struct xsc_lag xsc_lag[XSC_BOARD_LAG_MAX];
	u32 board_id;
	struct kref	ref;
	u8	bond_valid_mask;
	struct lag_event_list	lag_event_list;
	struct notifier_block	nb;
	struct mutex	lock;	/* protects board_lag */
};

void xsc_lag_add_xdev(struct xsc_core_device *xdev);
void xsc_lag_remove_xdev(struct xsc_core_device *xdev);
void xsc_lag_add_netdev(struct net_device *ndev);
void xsc_lag_remove_netdev(struct net_device *ndev);
void xsc_lag_disable(struct xsc_core_device *xdev);
void xsc_lag_enable(struct xsc_core_device *xdev);
bool xsc_lag_is_roce(struct xsc_core_device *xdev);
struct xsc_lag *xsc_get_lag(struct xsc_core_device *xdev);
struct xsc_core_device *xsc_get_roce_lag_xdev(struct xsc_core_device *xdev);
u16 xsc_get_lag_id(struct xsc_core_device *xdev);
struct xsc_board_lag *xsc_board_lag_get(struct xsc_core_device *xdev);

static inline void xsc_board_lag_lock(struct xsc_core_device *xdev)
{
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (xsc_core_is_pf(xdev))
		mutex_lock(&board_lag->lock);
}

static inline void xsc_board_lag_unlock(struct xsc_core_device *xdev)
{
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (xsc_core_is_pf(xdev))
		mutex_unlock(&board_lag->lock);
}

#endif /* XSC_LAG_H */
