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

struct topo_extent {
	u32 dev_index;
	u32 flags;
	u64 logical_start;
	u64 size_sector;
	u64 start_sector;
	/*
	 * Sectors written since registration, relative to logical_start.
	 * NULL means the whole unwritten extent still reads as zeros.
	 * Published with cmpxchg; ranges themselves stay immutable.
	 */
	unsigned long *written;
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
	u8 kind;
	dev_t top_dev;
	u64 size_sector;
	u32 nr_bdevs;
	struct topo_bdev *bdevs;
	u32 nr_extents;
	struct topo_extent *extents;
	p2p_bdev_handle *top_handle;
	union topo_priv priv;
	/* Loop extents are RAID0 logical sectors; priv holds the chunk shift. */
	bool loop_stripe;
	/* Extent index for logical_sector >> loop_index_shift. Immutable. */
	u32 *loop_index;
	u32 loop_index_slots;
	u32 loop_index_shift;

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

/*
 * Leading run of a loop read. zero_nr sectors read as zeros; otherwise the
 * next disk_nr sectors are real. Non-loop topologies set disk_nr to nr.
 */
int topo_loop_read_span(const struct topo *topo, u64 sector, u32 nr,
			u32 *disk_nr, u32 *zero_nr);
/* Allocate the written bitmap before a write into an unwritten extent. */
int topo_loop_prepare_write(struct topo *topo, u64 sector, u32 nr);
/* Record a write that has been queued to the backing device. */
void topo_loop_mark_written(struct topo *topo, u64 sector, u32 nr);

#endif
