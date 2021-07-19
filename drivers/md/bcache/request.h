/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_
#include "btree.h"
#include "acache.h"

struct data_insert_op {
	struct closure		cl;
	struct cache_set	*c;
	struct bio		*bio;
	struct workqueue_struct *wq;

	unsigned int		inode;
	uint16_t		write_point;
	uint16_t		write_prio;
	blk_status_t		status;

	union {
		uint16_t	flags;

	struct {
		unsigned int	bypass:1;
		unsigned int	writeback:1;
		unsigned int	flush_journal:1;
		unsigned int	csum:1;

		unsigned int	replace:1;
		unsigned int	replace_collision:1;

		unsigned int	insert_data_done:1;
	};
	};

	struct keylist		insert_keys;
	BKEY_PADDED(replace_key);
};

unsigned int bch_get_congested(struct cache_set *c);
void bch_data_insert(struct closure *cl);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_flash_dev_request_init(struct bcache_device *d);

void bch_traffic_policy_init(struct cached_dev *dc);

extern struct kmem_cache *bch_search_cache, *bch_passthrough_cache;

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct bbio		bio;
	struct bio		*orig_bio;
	struct bio		*cache_miss;
	struct bcache_device	*d;

	unsigned int		insert_bio_sectors;
	unsigned int		recoverable:1;
	unsigned int		write:1;
	unsigned int		read_dirty_data:1;
	unsigned int		cache_missed:1;

	unsigned long		start_time;
	/* for prefetch, we do not need copy data to bio */
	bool			prefetch;
	/*
	 * The function bch_data_insert() is invoked asynchronously as the bio
	 * subbmited to backend block device, therefore there may be a read
	 * request subbmited after the bch_data_insert() done and ended before
	 * the backend bio is end. This read request will read data from the
	 * backend block device, and insert dirty data to cache device. However
	 * by writearound cache mode, bcache will not invalidate data again,
	 * so that read request after will read dirty data from the cache,
	 * causing a data corruption.
	 * So that we should put off this invalidation. This switch is for
	 */
	bool			write_inval_data_putoff;
	struct list_head	list_node;
	wait_queue_head_t	wqh;
	struct acache_info		smp;

	struct btree_op		op;
	struct data_insert_op	iop;
};

void search_free(struct closure *cl);
struct search *search_alloc(struct bio *bio, struct bcache_device *d, bool prefetch);
void cached_dev_read(struct cached_dev *dc, struct search *s);
#endif /* _BCACHE_REQUEST_H_ */
