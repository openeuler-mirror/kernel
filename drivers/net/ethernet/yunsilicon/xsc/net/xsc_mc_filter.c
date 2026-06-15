// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
#include "xsc_eth.h"
#include <linux/crc32.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include <linux/limits.h>

static u32 xsc_mc_hashfn(const void *data, u32 len, u32 seed)
{
	return crc32_le(~0, data, len);
}

static int xsc_mc_obj_cmp(struct rhashtable_compare_arg *arg,
			  const void *obj)
{
	const u8 *key = arg->key;
	const struct xsc_mc_node *n = obj;

	return !ether_addr_equal(n->addr, key);
}

static const struct rhashtable_params xsc_mc_ht_params = {
	.nelem_hint  = 1024,
	.key_len     = ETH_ALEN,
	.key_offset  = offsetof(struct xsc_mc_node, addr),
	.head_offset = offsetof(struct xsc_mc_node, node),
	.hashfn      = xsc_mc_hashfn,
	.obj_cmpfn   = xsc_mc_obj_cmp,
	.automatic_shrinking = true,
	.min_size    = 2 * 1024,
	.max_size    = 16 * 1024,
};

int xsc_mc_hash_init(struct xsc_mc_hash *table)
{
	return rhashtable_init(&table->ht, &xsc_mc_ht_params);
}

void xsc_mc_hash_destroy(struct xsc_mc_hash *table)
{
	rhashtable_destroy(&table->ht);
}

int xsc_mc_hash_add(struct xsc_mc_hash *table, const u8 *addr)
{
	struct xsc_mc_node *node, *old;
	int err;

	rcu_read_lock();
	old = rhashtable_lookup(&table->ht, addr, xsc_mc_ht_params);
	if (old) {
		atomic_inc(&old->refcnt);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	ether_addr_copy(node->addr, addr);
	atomic_set(&node->refcnt, 1);

	err = rhashtable_insert_fast(&table->ht, &node->node,
				     xsc_mc_ht_params);
	if (err)
		kfree(node);

	return err;
}

int xsc_mc_hash_del(struct xsc_mc_hash *table, const u8 *addr)
{
	struct xsc_mc_node *node;
	int err;

	rcu_read_lock();
	node = rhashtable_lookup(&table->ht, addr, xsc_mc_ht_params);
	if (!node || !atomic_dec_and_test(&node->refcnt)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	err = rhashtable_remove_fast(&table->ht, &node->node,
				     xsc_mc_ht_params);

	kfree_rcu(node, rcu);
	return err;
}

static inline bool xsc_mc_trace_match(struct xsc_mc_hash *table, const u8 *dmac)
{
	if (table->trace.enabled  == 0)
		return false;

	return ether_addr_equal(table->trace.mac, dmac);
}

static void xsc_mc_trace_show(struct xsc_mc_hash *table, struct seq_file *m)
{
	if (table->trace.enabled == 0)
		return;

	seq_printf(m, "trace mac %02x:%02x:%02x:%02x:%02x:%02x pkts %d\n",
		   table->trace.mac[0], table->trace.mac[1], table->trace.mac[2],
		   table->trace.mac[3], table->trace.mac[4], table->trace.mac[5],
		   atomic_read(&table->trace.cnt));
}

static inline void safe_atomic_inc(atomic_t *v)
{
	int val = atomic_read(v);

	if (val >= INT_MAX - 1)
		atomic_set(v, 0);
	else
		atomic_inc(v);
}

u8 xsc_mc_hash_lookup(struct xsc_mc_hash *table, const u8 *addr)
{
	struct xsc_mc_node *node;
	u8 found = 0;

	rcu_read_lock();
	node = rhashtable_lookup(&table->ht, addr, xsc_mc_ht_params);
	if (node)
		found = 1;
	else if (xsc_mc_trace_match(table, addr))
		safe_atomic_inc(&table->trace.cnt);

	rcu_read_unlock();
	return found;
}

static void xsc_mc_seq_cb(const u8 *mac, u16 bucket, struct seq_file *m)
{
	static u16 last_bucket = ~0;

	if (bucket != last_bucket)
		seq_printf(m, "\nbuckets[%5u]", bucket);
	seq_printf(m, "  ->  %02x:%02x:%02x:%02x:%02x:%02x",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	last_bucket = bucket;
}

static int xsc_hash_dump_show(struct seq_file *m, void *v)
{
	struct xsc_mc_hash *table = m->private;
	struct rhashtable_iter iter;
	struct xsc_mc_node *node;
	u32 hash;
	u16 bucket;

	rhashtable_walk_enter(&table->ht, &iter);
	rhashtable_walk_start(&iter);
	while ((node = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(node))
			continue;

		hash = xsc_mc_hashfn(node->addr, ETH_ALEN, 0);
		bucket = hash & (table->ht.tbl->size - 1);
		xsc_mc_seq_cb(node->addr, bucket, m);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	seq_printf(m, "\ntbl_size=%u elems=%u\n",
		   table->ht.tbl->size, atomic_read(&table->ht.nelems));

	xsc_mc_trace_show(table, m);
	return 0;
}

static int xsc_hash_dump_open(struct inode *inode, struct file *file)
{
	return single_open(file, xsc_hash_dump_show, inode->i_private);
}

static const struct file_operations hash_dump_fops = {
	.open           = xsc_hash_dump_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static ssize_t xsc_mc_trace_write(struct file *file, const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct xsc_mc_hash *table = file->private_data;
	char buf[32];
	char *ptr;
	int ret;

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	buf[count] = '\0';

	ptr = strim(buf);

	if (strcmp(ptr, "0") == 0) {
		memset(table->trace.mac, 0, ETH_ALEN);
		atomic_set(&table->trace.cnt, 0);
		table->trace.enabled = 0;
		pr_info("mc trace disabled\n");
		return count;
	}

	ret = sscanf(ptr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		     &table->trace.mac[0], &table->trace.mac[1],
		     &table->trace.mac[2], &table->trace.mac[3],
		     &table->trace.mac[4], &table->trace.mac[5]);

	if (ret != ETH_ALEN) {
		pr_err("Invalid MAC format, expected xx:xx:xx:xx:xx:xx or 0\n");
		return -EINVAL;
	}

	table->trace.enabled = 1;
	atomic_set(&table->trace.cnt, 0);
	pr_info("mc trace enabled for %pM\n", table->trace.mac);

	return count;
}

static ssize_t xsc_mc_trace_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	struct xsc_mc_hash *table = file->private_data;
	char buf[64];
	int len;

	if (table->trace.enabled == 1)
		len = scnprintf(buf, sizeof(buf), "%pM\n", table->trace.mac);
	else
		len = scnprintf(buf, sizeof(buf), "0\n");

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations mc_trace_fops = {
	.owner = THIS_MODULE,
	.read = xsc_mc_trace_read,
	.write = xsc_mc_trace_write,
	.open = simple_open,
	.llseek = default_llseek,
};

static void xsc_hash_debug_add_port(struct xsc_mc_hash *table,
				    struct xsc_core_device *xdev)
{
	if (!xdev->dev_res || !xdev->dev_res->dbg_root) {
		xsc_core_err(xdev, "dbg_root err\n");
		return;
	}

	table->debug_dir = debugfs_create_dir("mc_hash", xdev->dev_res->dbg_root);
	if (!table->debug_dir) {
		xsc_core_err(xdev, "create dir err\n");
		return;
	}

	table->debug_dump = debugfs_create_file("dump", 0444,
						table->debug_dir, table, &hash_dump_fops);
	if (!table->debug_dump) {
		xsc_core_err(xdev, "create dump file err\n");
		return;
	}

	memset(&table->trace, 0, sizeof(table->trace));

	table->debug_trace = debugfs_create_file("trace", 0644,
						 table->debug_dir, table, &mc_trace_fops);
	if (!table->debug_trace) {
		xsc_core_err(xdev, "create trace file err\n");
		return;
	}
}

static void xsc_hash_debug_del_port(struct xsc_mc_hash *table)
{
	debugfs_remove(table->debug_trace);
	debugfs_remove(table->debug_dump);
	debugfs_remove(table->debug_dir);
}

static int xsc_mc_hash_alloc(struct xsc_adapter *adapter)
{
	int err;

	adapter->mc_hash_tbl = kzalloc(sizeof(*adapter->mc_hash_tbl), GFP_KERNEL);
	if (!adapter->mc_hash_tbl)
		return -ENOMEM;

	err = xsc_mc_hash_init(adapter->mc_hash_tbl);
	if (err) {
		kfree(adapter->mc_hash_tbl);
		adapter->mc_hash_tbl = NULL;
		return err;
	}

	return 0;
}

static void xsc_mc_hash_free(struct xsc_adapter *adapter)
{
	if (!adapter->mc_hash_tbl)
		return;

	xsc_mc_hash_destroy(adapter->mc_hash_tbl);
	kfree(adapter->mc_hash_tbl);
	adapter->mc_hash_tbl = NULL;
}

int xsc_mc_filter_setup(struct xsc_adapter *adapter)
{
	int err;

	err = xsc_mc_hash_alloc(adapter);
	if (err)
		return err;

	xsc_hash_debug_add_port(adapter->mc_hash_tbl, adapter->xdev);

	return 0;
}

void xsc_mc_filter_cleanup(struct xsc_adapter *adapter)
{
	xsc_hash_debug_del_port(adapter->mc_hash_tbl);
	xsc_mc_hash_free(adapter);
}

