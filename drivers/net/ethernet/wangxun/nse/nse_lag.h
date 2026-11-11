/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_LAG_H_
#define _NSE_LAG_H_

#include <linux/netdevice.h>
#include "nse.h"

#define NSE_SUPPORT_HW_LAG

#define NSE_LAG_MIN_PORT 2
#define NSE_LAG_MAX_PORT 4
#define NSE_LAG_HASH_MAX_ENTRY 32
#define NSE_LAG_HASH_MAX_BUCKET (NSE_LAG_HASH_MAX_ENTRY/NSE_LAG_MAX_PORT)
#define NSE_LAG_HASH_MIN_BUCKET (NSE_LAG_HASH_MAX_ENTRY/NSE_LAG_MIN_PORT)

enum nse_lag_mode {
	NSE_LAG_MODE_NONE,
	NSE_LAG_MODE_SRIOV,
	NSE_LAG_MODE_ROCE,
};

struct nse_pf;

struct lag_func {
	struct nse_pf *pf;
	struct net_device    *netdev;
	bool has_drop;
	bool has_unplug; /*aux dev is unplug when hw bond*/
};

/*dynamic real-time valid bond information based on OS event*/
struct lag_tracker {
	enum   netdev_lag_tx_type           tx_type;
	struct netdev_lag_lower_state_info  netdev_state[NSE_LAG_MAX_PORT];
	unsigned int is_bonded:1;
	unsigned int has_inactive:1;
	enum netdev_lag_hash hash_type;
	unsigned long slave_bitmap; /*valid slave lan port bitmap*/
	u8 vld_ports; /*valid port num*/
	u8 buckets;
};

/* LAG dev information struct */
struct nse_lag {
	/* active or inactive, sriov lag or roce lag means active */
	enum nse_lag_mode		  mode;
	unsigned long		      flags;
#define	NSE_LAG_FLAG_NDEVS_READY 0  /*bit0: ready or non-ready, ready means all pf init done*/

	/* supported max lan port, but not valid port num */
	u8						  ports;
	u8					  v2p_map[NSE_LAG_HASH_MAX_ENTRY];
	u8                        old_hash_type;
	/* current dynamic real-time valid bond information */
	struct lag_tracker		  tracker;
	/* next dynamic real-time valid bond information */
	struct lag_tracker		  next_tracker;
	spinlock_t  next_tracker_lock; /* protects next_tracker */
	struct kref			  ref;
	struct lag_func			  lag_func[NSE_LAG_MAX_PORT];
	struct nse_pf			  *first_pf; /*first pf, is set in active hw lag*/
	/* it should be first pf's lan id */
	u8						   hw_lag_id;
	struct workqueue_struct   *wq;
	struct delayed_work	  bond_work;
	struct notifier_block	  nb;
	struct mutex		      lock;
};

int nse_init_lag(struct nse_pf *pf);
void nse_deinit_lag(struct nse_pf *pf);

enum nse_status
nse_aq_hw_lag(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_misc_subcodes opc,
		struct nse_sq_cd *cd);

bool
nse_lag_is_active(struct nse_lag *ldev);

bool
nse_is_pf_in_active_lag(struct nse_pf *pf);

#endif /* _NSE_LAG_H_ */
