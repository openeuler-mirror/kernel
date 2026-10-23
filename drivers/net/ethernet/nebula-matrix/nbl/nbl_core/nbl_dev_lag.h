/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEV_LAG_H_
#define _NBL_DEV_LAG_H_

#include "nbl_dev.h"

void nbl_lag_devcomm_lock(struct nbl_dev_mgt *dev_mgt);
void nbl_lag_devcomm_unlock(struct nbl_dev_mgt *dev_mgt);

#include <linux/xarray.h>
enum nbl_lag_mode {
	NBL_LAG_MODE_NONE,
	NBL_LAG_MODE_EN, /* support rdma lag and ovs offload */
};

enum nbl_lag_mbr_fwd {
	NBL_LAG_MEM_FWD_DROP,
	NBL_LAG_MEM_FWD_NORMAL,
};

enum {
	NBL_LAG_FLAG_NDEVS_READY,
};

/* XArray mark for the LAG master device(PF0).
 * Note: XA_MARK_0 is reserved by XA_FLAGS_ALLOC for free-slot tracking.
 */
#define NBL_LAG_XA_MARK_MASTER XA_MARK_1
/* XArray mark for port-level entries */
#define NBL_LAG_XA_MARK_PORT   XA_MARK_2

struct nbl_lag_func {
	struct nbl_dev_mgt *pdev;
	struct net_device *netdev;
	int idx; /* xarray index assigned by LAG */
};

struct nbl_lag_tracker {
	enum   netdev_lag_tx_type		tx_type;
	struct netdev_lag_lower_state_info      netdev_state[NBL_MAX_PF];
	bool netdev_updown[NBL_MAX_PF];
	int is_bonded:1;
	int has_inactive:1;
	enum netdev_lag_hash hash_type;
};

struct nbl_lag_dev {
	enum nbl_lag_mode	  mode;
	unsigned long		  mode_flags;
	unsigned long		  state_flags;
	int			  ports;
	int			  mode_changes_in_progress;
	struct kref               ref;
	struct xarray             pfs;
	struct nbl_lag_tracker	  new_tracker;
	struct nbl_lag_tracker	  old_tracker;
	struct workqueue_struct   *wq;
	struct delayed_work       bond_work;
	struct notifier_block     nb;
	/* Protect lag fields/state changes */
	struct mutex		  lock;
};

static inline struct nbl_lag_dev *
nbl_lag_dev(struct nbl_dev_mgt *dev_mgt)
{
	return dev_mgt->lag_dev;
}

static inline struct nbl_lag_func *
nbl_lag_pf(struct nbl_lag_dev *ldev, unsigned int idx)
{
	return xa_load(&ldev->pfs, idx);
}

static inline bool
nbl_lag_is_ready(struct nbl_lag_dev *ldev)
{
	return test_bit(NBL_LAG_FLAG_NDEVS_READY, &ldev->state_flags);
}

static inline bool
__nbl_lag_is_active(struct nbl_lag_dev *ldev)
{
	return ldev->mode != NBL_LAG_MODE_NONE;
}

static inline bool nbl_lag_mbr_is_active(struct nbl_lag_tracker *trk, int idx)
{
	return trk->netdev_state[idx].link_up &&
		trk->netdev_state[idx].tx_enabled &&
		trk->netdev_updown[idx];
}

#define NBL_LAG_FILTER_PORTS 0        /* iterate ports only (XA_MARK_PORT) */
#define NBL_LAG_FILTER_ALL   U32_MAX  /* iterate ALL devices */

#define nbl_lag_for_each(i, start_index, ldev, filter) \
	for (_tmp = start_index; \
	     _tmp = nbl_lag_get_next_func(ldev, _tmp, filter), \
	     i = _tmp, _tmp < NBL_MAX_PF; _tmp++)

#define nbl_ldev_for_each(i, start_index, ldev) \
	nbl_lag_for_each(i, start_index, ldev, NBL_LAG_FILTER_PORTS)

int nbl_lag_get_next_func(struct nbl_lag_dev *ldev, int start_idx, u32 filter);
int nbl_lag_get_pf_num(struct nbl_lag_dev *ldev);
int nbl_lag_get_netdev_num(struct nbl_lag_dev *ldev);
int nbl_lag_get_dev_index_by_seq(struct nbl_lag_dev *ldev, int seq);

#endif
