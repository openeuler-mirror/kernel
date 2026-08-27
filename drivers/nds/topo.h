/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_TOPO_H_
#define P2P_TOPO_H_

#include <linux/blkdev.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "compat.h"
#include <linux/nds_p2p.h>

struct topo;

struct topo_bdev {
	dev_t id;
	u32 nsid;
	u64 size_sector;
	u64 start_sector;
	p2p_bdev_handle *handle;
};

union topo_priv {
	u32 chunk_sectors_shift;
};

struct topo_ops {
	int (*map_sector)(struct topo *topo, u64 from_sector,
			  u32 in_nr_sectors, struct topo_bdev **to_bdev,
			  u64 *to_sector, u32 *out_nr_sectors);
};

struct topo {
	char name[P2P_TOPO_NAME_LEN];
	const struct topo_ops *ops;
	dev_t top_dev;
	u64 size_sector;
	u32 nr_bdevs;
	struct topo_bdev *bdevs;
	p2p_bdev_handle *top_handle;
	union topo_priv priv;

	struct kref refcnt;
	struct kref pin_refcnt;
	struct rcu_work rcu_work;
};

struct shared_topo {
	struct topo *topo;
	struct list_head list;
};

struct shared_topo_list {
	spinlock_t lock;
	struct list_head head;
};

int topo_init(void);
void topo_exit(void);
int topo_add(const struct topo_user_cfg *cfg, struct shared_topo_list *list);
void topo_del(struct topo *topo);
struct topo *topo_get(struct block_device *top_bdev);
void topo_put(struct topo *topo);

#endif
