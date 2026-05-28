// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/rbtree.h>
#include "common/xsc_core.h"
#include "common/xsc_eswitch.h"
#include "common/fs_core.h"
#include "common/fs_cmd.h"

#define XSC_FC_STATS_PERIOD msecs_to_jiffies(1000)
#define XSC_FC_BULK_QUERY_ALLOC_PERIOD msecs_to_jiffies(180 * 1000)
/* Max number of counters to query in bulk read is 32K */
#define XSC_SW_MAX_COUNTERS_BULK 64
#define XSC_INIT_COUNTERS_BULK 64
#define XSC_FC_POOL_MAX_THRESHOLD BIT(15)
#define XSC_FC_POOL_USED_BUFF_RATIO 10

static void xsc_fc_pool_init(struct xsc_fc_pool *fc_pool, struct xsc_core_device *dev);
static void xsc_fc_pool_cleanup(struct xsc_fc_pool *fc_pool);
static struct xsc_fc *xsc_fc_pool_acquire_counter(struct xsc_fc_pool *fc_pool);
static void xsc_fc_pool_release_counter(struct xsc_fc_pool *fc_pool, struct xsc_fc *fc);

/* locking scheme:
 *
 * It is the responsibility of the user to prevent concurrent calls or bad
 * ordering to xsc_fc_create(), xsc_fc_destroy() and accessing a reference
 * to struct xsc_fc.
 * e.g en_tc.c is protected by RTNL lock of its caller, and will never call a
 * dump (access to struct xsc_fc) after a counter is destroyed.
 *
 * access to counter list:
 * - create (user context)
 *   - xsc_fc_create() only adds to an addlist to be used by
 *     xsc_fc_stats_work(). addlist is a lockless single linked list
 *     that doesn't require any additional synchronization when adding single
 *     node.
 *   - spawn thread to do the actual destroy
 *
 * - destroy (user context)
 *   - add a counter to lockless dellist
 *   - spawn thread to do the actual del
 *
 * - dump (user context)
 *   user should not call dump after destroy
 *
 * - query (single thread workqueue context)
 *   destroy/dump - no conflict (see destroy)
 *   query/dump - packets and bytes might be inconsistent (since update is not
 *                atomic)
 *   query/create - no conflict (see create)
 *   since every create/destroy spawn the work, only after necessary time has
 *   elapsed, the thread will actually query the hardware.
 */

static struct list_head *xsc_fc_counters_lookup_next(struct xsc_core_device *dev,
						     u32 id)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	struct xsc_fc *counter;
#ifdef idr_for_each_entry_continue_uli
	unsigned long next_id = (unsigned long)id + 1;
	unsigned long tmp;

	rcu_read_lock();
	/* skip counters that are in idr, but not yet in counters list */
	idr_for_each_entry_continue_ul(&fc_stats->counters_idr,
				       counter, tmp, next_id) {
		if (!list_empty(&counter->list))
			break;
	}
	rcu_read_unlock();

	return counter ? &counter->list : &fc_stats->counters;
#else
	rcu_read_lock();
	list_for_each_entry(counter, &fc_stats->counters, list)
		if (counter->id > id) {
			rcu_read_unlock();
			return &counter->list;
		}

	rcu_read_unlock();

	return &fc_stats->counters;
#endif
}

static void xsc_fc_stats_insert(struct xsc_core_device *dev, struct xsc_fc *counter)
{
	struct list_head *next = xsc_fc_counters_lookup_next(dev, counter->id);

	list_add_tail(&counter->list, next);
}

static void xsc_fc_stats_remove(struct xsc_core_device *dev, struct xsc_fc *counter)
{
	list_del(&counter->list);
}

static int get_init_bulk_query_len(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;

	return min_t(int, XSC_INIT_COUNTERS_BULK,
		     (1 << esw->esw_caps.log_max_flow_counter_bulk));
}

static int get_max_bulk_query_len(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;

	return min_t(int, XSC_SW_MAX_COUNTERS_BULK,
		     (1 << esw->esw_caps.log_max_flow_counter_bulk));
}

static void update_counter_cache(int index, u32 *bulk_raw_data,
				 struct xsc_fc_cache *cache)
{
	void *stats = XSC_ADDR_OF(query_flow_counter_mbox_out, bulk_raw_data,
				  flow_stats[index]);
	u64 packets = XSC_GET64(traffic_counter, stats, packets);
	u64 bytes = XSC_GET64(traffic_counter, stats, bytes);

	if (cache->packets == packets)
		return;

	cache->packets = packets;
	cache->bytes = bytes;
	cache->lastuse = jiffies;
}

static void xsc_fc_stats_query_counter_range(struct xsc_core_device *dev,
					     struct xsc_fc *first, u32 last_id)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	bool query_more_counters = (first->id <= last_id);
	int cur_bulk_len = fc_stats->bulk_query_len;
	u32 *data = fc_stats->bulk_query_out;
	struct xsc_fc *counter = first;
	u32 bulk_base_id;
	u32 bulk_len;
	int err;

	while (query_more_counters) {
		/* first id must be aligned to 4 when using bulk query */
		bulk_base_id = counter->id & ~0x3;

		/* number of counters to query inc. the last counter */
		bulk_len = min_t(int, cur_bulk_len,
				 ALIGN(last_id - bulk_base_id + 1, 4));

		err = xsc_flow_fc_bulk_query(dev, bulk_base_id, bulk_len, data);
		if (err) {
			xsc_core_err(dev, "Error doing bulk query: %d\n", err);
			return;
		}
		query_more_counters = false;

		list_for_each_entry_from(counter, &fc_stats->counters, list) {
			int counter_index = counter->id - bulk_base_id;
			struct xsc_fc_cache *cache = &counter->cache;

			if (counter->id >= bulk_base_id + bulk_len) {
				query_more_counters = true;
				break;
			}

			update_counter_cache(counter_index, data, cache);
		}
	}
}

static void xsc_fc_free(struct xsc_core_device *dev, struct xsc_fc *counter, u32 bulk_len)
{
	xsc_flow_fc_free(dev, counter->id, bulk_len);
	kfree(counter);
}

static void xsc_fc_release(struct xsc_core_device *dev, struct xsc_fc *counter)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;

	if (counter->bulk)
		xsc_fc_pool_release_counter(&fc_stats->fc_pool, counter);
	else
		xsc_fc_free(dev, counter, 1);
}

static void xsc_fc_stats_bulk_query_size_increase(struct xsc_core_device *dev)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	int max_bulk_len = get_max_bulk_query_len(dev);
	unsigned long now = jiffies;
	u32 *bulk_query_out_tmp;
	int max_out_len;

	if (fc_stats->bulk_query_alloc_failed &&
	    time_before(now, fc_stats->next_bulk_query_alloc))
		return;

	max_out_len = xsc_flow_fc_get_bulk_query_out_len(max_bulk_len);
	bulk_query_out_tmp = kzalloc(max_out_len, GFP_KERNEL);
	if (!bulk_query_out_tmp) {
		xsc_core_warn(dev,
			      "Failed to add flow counters bulk buf size(%d), no memory\n",
			      max_bulk_len);
		fc_stats->bulk_query_alloc_failed = true;
		fc_stats->next_bulk_query_alloc =
			now + XSC_FC_BULK_QUERY_ALLOC_PERIOD;
		return;
	}

	kfree(fc_stats->bulk_query_out);
	fc_stats->bulk_query_out = bulk_query_out_tmp;
	fc_stats->bulk_query_len = max_bulk_len;
	if (fc_stats->bulk_query_alloc_failed) {
		xsc_core_info(dev,
			      "Flow counters bulk query buffer size increased, bulk_size(%d)\n",
			      max_bulk_len);
		fc_stats->bulk_query_alloc_failed = false;
	}
}

static void xsc_fc_stats_work(struct work_struct *work)
{
	struct xsc_core_device *dev = container_of(work, struct xsc_core_device,
						   priv.fc_stats.work.work);
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	/* Take dellist first to ensure that counters cannot be deleted before
	 * they are inserted.
	 */
	struct llist_node *dellist = llist_del_all(&fc_stats->dellist);
	struct llist_node *addlist = llist_del_all(&fc_stats->addlist);
	struct xsc_fc *counter = NULL, *last = NULL, *tmp;
	unsigned long now = jiffies;

	if (addlist || !list_empty(&fc_stats->counters))
		queue_delayed_work(fc_stats->wq, &fc_stats->work,
				   fc_stats->sampling_interval);

	llist_for_each_entry(counter, addlist, addlist) {
		xsc_fc_stats_insert(dev, counter);
		fc_stats->num_counters++;
	}

	llist_for_each_entry_safe(counter, tmp, dellist, dellist) {
		xsc_fc_stats_remove(dev, counter);

		xsc_fc_release(dev, counter);
		fc_stats->num_counters--;
	}

	if (fc_stats->bulk_query_len < get_max_bulk_query_len(dev) &&
	    fc_stats->num_counters > get_init_bulk_query_len(dev))
		xsc_fc_stats_bulk_query_size_increase(dev);

	if (time_before(now, fc_stats->next_query) ||
	    list_empty(&fc_stats->counters))
		return;

	last = list_last_entry(&fc_stats->counters, struct xsc_fc, list);

	counter = list_first_entry(&fc_stats->counters, struct xsc_fc, list);
	if (counter)
		xsc_fc_stats_query_counter_range(dev, counter, last->id);

	fc_stats->next_query = now + fc_stats->sampling_interval;
}

static struct xsc_fc *xsc_fc_single_alloc(struct xsc_core_device *dev)
{
	struct xsc_fc *counter;
	int err;

	counter = kzalloc(sizeof(*counter), GFP_KERNEL);
	if (!counter)
		return ERR_PTR(-ENOMEM);

	err = xsc_flow_fc_alloc(dev, &counter->id);
	if (err) {
		kfree(counter);
		return ERR_PTR(err);
	}

	return counter;
}

static struct xsc_fc *xsc_fc_acquire(struct xsc_core_device *dev, bool aging)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	struct xsc_fc *counter;

	if (aging && esw->esw_caps.flow_counter_bulk_alloc != 0) {
		counter = xsc_fc_pool_acquire_counter(&fc_stats->fc_pool);
		if (!IS_ERR(counter))
			return counter;
	}

	return xsc_fc_single_alloc(dev);
}

static struct xsc_fc *xsc_fc_create_ex(struct xsc_core_device *dev, bool aging)
{
	struct xsc_fc *counter = xsc_fc_acquire(dev, aging);
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;

	if (IS_ERR(counter))
		return counter;

	counter->aging = aging;

	if (aging) {
		counter->cache.lastuse = jiffies;
		counter->lastbytes = counter->cache.bytes;
		counter->lastpackets = counter->cache.packets;

		llist_add(&counter->addlist, &fc_stats->addlist);
	}

	return counter;
}

struct xsc_fc *xsc_fc_create(struct xsc_core_device *dev, bool aging)
{
	struct xsc_fc *counter = xsc_fc_create_ex(dev, aging);
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;

	if (aging)
		mod_delayed_work(fc_stats->wq, &fc_stats->work, 0);
	return counter;
}
EXPORT_SYMBOL(xsc_fc_create);

u32 xsc_fc_id(struct xsc_fc *counter)
{
	return counter->id;
}
EXPORT_SYMBOL(xsc_fc_id);

void xsc_fc_destroy(struct xsc_core_device *dev, struct xsc_fc *counter)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;

	if (!counter)
		return;

	if (counter->aging) {
		llist_add(&counter->dellist, &fc_stats->dellist);
		mod_delayed_work(fc_stats->wq, &fc_stats->work, 0);
		return;
	}

	xsc_fc_release(dev, counter);
}
EXPORT_SYMBOL(xsc_fc_destroy);

int xsc_init_fc_stats(struct xsc_core_device *dev)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	int init_bulk_len;
	int init_out_len;

	spin_lock_init(&fc_stats->counters_idr_lock);
	idr_init(&fc_stats->counters_idr);
	INIT_LIST_HEAD(&fc_stats->counters);
	init_llist_head(&fc_stats->addlist);
	init_llist_head(&fc_stats->dellist);

	init_bulk_len = get_init_bulk_query_len(dev);
	init_out_len = xsc_flow_fc_get_bulk_query_out_len(init_bulk_len);
	fc_stats->bulk_query_out = kzalloc(init_out_len, GFP_KERNEL);
	if (!fc_stats->bulk_query_out)
		return -ENOMEM;
	fc_stats->bulk_query_len = init_bulk_len;

	fc_stats->wq = create_singlethread_workqueue("xsc_fc");
	if (!fc_stats->wq)
		goto err_wq_create;

	fc_stats->sampling_interval = XSC_FC_STATS_PERIOD;
	INIT_DELAYED_WORK(&fc_stats->work, xsc_fc_stats_work);

	xsc_fc_pool_init(&fc_stats->fc_pool, dev);
	return 0;

err_wq_create:
	kfree(fc_stats->bulk_query_out);
	return -ENOMEM;
}

void xsc_cleanup_fc_stats(struct xsc_core_device *dev)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;
	struct llist_node *tmplist;
	struct xsc_fc *counter;
	struct xsc_fc *tmp;

	cancel_delayed_work_sync(&dev->priv.fc_stats.work);
	destroy_workqueue(dev->priv.fc_stats.wq);
	dev->priv.fc_stats.wq = NULL;

	tmplist = llist_del_all(&fc_stats->addlist);
	llist_for_each_entry_safe(counter, tmp, tmplist, addlist)
		xsc_fc_release(dev, counter);

	list_for_each_entry_safe(counter, tmp, &fc_stats->counters, list)
		xsc_fc_release(dev, counter);

	xsc_fc_pool_cleanup(&fc_stats->fc_pool);
	idr_destroy(&fc_stats->counters_idr);
	kfree(fc_stats->bulk_query_out);
}

int xsc_fc_query(struct xsc_core_device *dev, struct xsc_fc *counter,
		 u64 *packets, u64 *bytes)
{
	return xsc_flow_fc_query(dev, counter->id, packets, bytes, false);
}
EXPORT_SYMBOL(xsc_fc_query);

int xsc_fc_query_and_clear(struct xsc_core_device *dev, struct xsc_fc *counter,
			   u64 *packets, u64 *bytes)
{
	return xsc_flow_fc_query(dev, counter->id, packets, bytes, true);
}

u64 xsc_fc_query_lastuse(struct xsc_fc *counter)
{
	return counter->cache.lastuse;
}

void xsc_fc_query_cached(struct xsc_fc *counter,
			 u64 *bytes, u64 *packets, u64 *lastuse)
{
	struct xsc_fc_cache c;

	c = counter->cache;

	*bytes = c.bytes - counter->lastbytes;
	*packets = c.packets - counter->lastpackets;
	*lastuse = c.lastuse;

	counter->lastbytes = c.bytes;
	counter->lastpackets = c.packets;
}
EXPORT_SYMBOL(xsc_fc_query_cached);

void xsc_fc_query_cached_raw(struct xsc_fc *counter,
			     u64 *bytes, u64 *packets, u64 *lastuse)
{
	struct xsc_fc_cache c = counter->cache;

	*bytes = c.bytes;
	*packets = c.packets;
	*lastuse = c.lastuse;
}

void xsc_fc_queue_stats_work(struct xsc_core_device *dev,
			     struct delayed_work *dwork,
			     unsigned long delay)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;

	queue_delayed_work(fc_stats->wq, dwork, delay);
}

void xsc_fc_update_sampling_interval(struct xsc_core_device *dev,
				     unsigned long interval)
{
	struct xsc_fc_stats *fc_stats = &dev->priv.fc_stats;

	fc_stats->sampling_interval = min_t(unsigned long, interval,
					    fc_stats->sampling_interval);
}

static void xsc_fc_init(struct xsc_fc *counter, struct xsc_fc_bulk *bulk, u32 id)
{
	counter->bulk = bulk;
	counter->id = id;
}

static int xsc_fc_bulk_get_free_fcs_amount(struct xsc_fc_bulk *bulk)
{
	return bitmap_weight(bulk->bitmask, bulk->bulk_len);
}

static struct xsc_fc_bulk *xsc_fc_bulk_create(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;
	enum xsc_fc_bulk_alloc_bitmask alloc_bitmask;
	struct xsc_fc_bulk *bulk;
	int err = -ENOMEM;
	u32 bulk_len, bulk_sz;
	u32 base_id;
	int i;

	alloc_bitmask = esw->esw_caps.flow_counter_bulk_alloc;
	bulk_len = alloc_bitmask > 0 ? XSC_FC_BULK_NUM_FCS(alloc_bitmask) : 1;

	bulk_sz = sizeof(struct xsc_fc_bulk) + sizeof(struct xsc_fc) * bulk_len;
	bulk = kvzalloc(bulk_sz, GFP_KERNEL);
	if (!bulk)
		goto err_alloc_bulk;

	bulk->bitmask = kvcalloc(BITS_TO_LONGS(bulk_len), sizeof(unsigned long),
				 GFP_KERNEL);
	if (!bulk->bitmask)
		goto err_alloc_bitmask;

	err = xsc_flow_fc_bulk_alloc(dev, alloc_bitmask, &base_id);
	if (err)
		goto err_xsc_cmd_bulk_alloc;

	bulk->base_id = base_id;
	bulk->bulk_len = bulk_len;
	for (i = 0; i < bulk_len; i++) {
		xsc_fc_init(&bulk->fcs[i], bulk, base_id + i);
		set_bit(i, bulk->bitmask);
	}

	return bulk;

err_xsc_cmd_bulk_alloc:
	kvfree(bulk->bitmask);
err_alloc_bitmask:
	kvfree(bulk);
err_alloc_bulk:
	return ERR_PTR(err);
}

static int xsc_fc_bulk_destroy(struct xsc_core_device *dev, struct xsc_fc_bulk *bulk)
{
	if (xsc_fc_bulk_get_free_fcs_amount(bulk) < bulk->bulk_len) {
		xsc_core_err(dev, "Freeing bulk before all counters were released\n");
		return -EBUSY;
	}

	xsc_flow_fc_free(dev, bulk->base_id, bulk->bulk_len);
	kvfree(bulk->bitmask);
	kvfree(bulk);

	return 0;
}

static struct xsc_fc *xsc_fc_bulk_acquire_fc(struct xsc_fc_bulk *bulk)
{
	int free_fc_index = find_first_bit(bulk->bitmask, bulk->bulk_len);

	if (free_fc_index >= bulk->bulk_len)
		return ERR_PTR(-ENOSPC);

	clear_bit(free_fc_index, bulk->bitmask);
	return &bulk->fcs[free_fc_index];
}

static int xsc_fc_bulk_release_fc(struct xsc_fc_bulk *bulk, struct xsc_fc *fc)
{
	int fc_index = fc->id - bulk->base_id;

	if (test_bit(fc_index, bulk->bitmask))
		return -EINVAL;

	set_bit(fc_index, bulk->bitmask);
	return 0;
}

/* Flow counters pool API */
static void xsc_fc_pool_init(struct xsc_fc_pool *fc_pool, struct xsc_core_device *dev)
{
	fc_pool->dev = dev;
	mutex_init(&fc_pool->pool_lock);
	INIT_LIST_HEAD(&fc_pool->fully_used);
	INIT_LIST_HEAD(&fc_pool->partially_used);
	INIT_LIST_HEAD(&fc_pool->unused);
	fc_pool->available_fcs = 0;
	fc_pool->used_fcs = 0;
	fc_pool->threshold = 0;
}

static void xsc_fc_pool_cleanup(struct xsc_fc_pool *fc_pool)
{
	struct xsc_core_device *dev = fc_pool->dev;
	struct xsc_fc_bulk *bulk;
	struct xsc_fc_bulk *tmp;

	list_for_each_entry_safe(bulk, tmp, &fc_pool->fully_used, pool_list)
		xsc_fc_bulk_destroy(dev, bulk);
	list_for_each_entry_safe(bulk, tmp, &fc_pool->partially_used, pool_list)
		xsc_fc_bulk_destroy(dev, bulk);
	list_for_each_entry_safe(bulk, tmp, &fc_pool->unused, pool_list)
		xsc_fc_bulk_destroy(dev, bulk);
}

static void xsc_fc_pool_update_threshold(struct xsc_fc_pool *fc_pool)
{
	fc_pool->threshold = min_t(int, XSC_FC_POOL_MAX_THRESHOLD,
				   fc_pool->used_fcs / XSC_FC_POOL_USED_BUFF_RATIO);
}

static struct xsc_fc_bulk *xsc_fc_pool_alloc_new_bulk(struct xsc_fc_pool *fc_pool)
{
	struct xsc_core_device *dev = fc_pool->dev;
	struct xsc_fc_bulk *new_bulk;

	new_bulk = xsc_fc_bulk_create(dev);
	if (!IS_ERR(new_bulk))
		fc_pool->available_fcs += new_bulk->bulk_len;
	xsc_fc_pool_update_threshold(fc_pool);

	return new_bulk;
}

static void xsc_fc_pool_free_bulk(struct xsc_fc_pool *fc_pool, struct xsc_fc_bulk *bulk)
{
	struct xsc_core_device *dev = fc_pool->dev;

	fc_pool->available_fcs -= bulk->bulk_len;
	xsc_fc_bulk_destroy(dev, bulk);
	xsc_fc_pool_update_threshold(fc_pool);
}

static struct xsc_fc *xsc_fc_pool_acquire_from_list(struct list_head *src_list,
						    struct list_head *next_list,
						    bool move_non_full_bulk)
{
	struct xsc_fc_bulk *bulk;
	struct xsc_fc *fc;

	if (list_empty(src_list))
		return ERR_PTR(-ENODATA);

	bulk = list_first_entry(src_list, struct xsc_fc_bulk, pool_list);
	fc = xsc_fc_bulk_acquire_fc(bulk);
	if (move_non_full_bulk || xsc_fc_bulk_get_free_fcs_amount(bulk) == 0)
		list_move(&bulk->pool_list, next_list);

	return fc;
}

static struct xsc_fc *xsc_fc_pool_acquire_counter(struct xsc_fc_pool *fc_pool)
{
	struct xsc_fc_bulk *new_bulk;
	struct xsc_fc *fc;

	mutex_lock(&fc_pool->pool_lock);

	fc = xsc_fc_pool_acquire_from_list(&fc_pool->partially_used,
					   &fc_pool->fully_used, false);
	if (IS_ERR(fc))
		fc = xsc_fc_pool_acquire_from_list(&fc_pool->unused,
						   &fc_pool->partially_used, true);
	if (IS_ERR(fc)) {
		new_bulk = xsc_fc_pool_alloc_new_bulk(fc_pool);
		if (IS_ERR(new_bulk)) {
			fc = ERR_CAST(new_bulk);
			goto out;
		}
		fc = xsc_fc_bulk_acquire_fc(new_bulk);
		list_add(&new_bulk->pool_list, &fc_pool->partially_used);
	}
	if (!fc)
		goto out;

	fc_pool->available_fcs--;
	fc_pool->used_fcs++;
	fc->lastpackets = 0;
	fc->lastbytes = 0;
	memset(&fc->cache, 0, sizeof(fc->cache));

out:
	mutex_unlock(&fc_pool->pool_lock);
	return fc;
}

static void xsc_fc_pool_release_counter(struct xsc_fc_pool *fc_pool, struct xsc_fc *fc)
{
	struct xsc_core_device *dev = fc_pool->dev;
	struct xsc_fc_bulk *bulk = fc->bulk;
	int bulk_free_fcs_amount;

	mutex_lock(&fc_pool->pool_lock);

	if (xsc_fc_bulk_release_fc(bulk, fc)) {
		xsc_core_warn(dev, "Attempted to release a counter which is not acquired\n");
		goto unlock;
	}

	fc_pool->available_fcs++;
	fc_pool->used_fcs--;

	bulk_free_fcs_amount = xsc_fc_bulk_get_free_fcs_amount(bulk);
	if (bulk_free_fcs_amount == 1)
		list_move_tail(&bulk->pool_list, &fc_pool->partially_used);
	if (bulk_free_fcs_amount == bulk->bulk_len) {
		list_del(&bulk->pool_list);
		if (fc_pool->available_fcs > fc_pool->threshold)
			xsc_fc_pool_free_bulk(fc_pool, bulk);
		else
			list_add(&bulk->pool_list, &fc_pool->unused);
	}

unlock:
	mutex_unlock(&fc_pool->pool_lock);
}
