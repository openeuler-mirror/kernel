// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024  Huawei Technologies Co., Ltd.
 * Author: Liu Shixin <liushixin2@huawei.com>
 */

#define pr_fmt(fmt) "NUMA remote: " fmt

#include <linux/device.h>
#include <linux/hugetlb.h>
#include <linux/page-isolation.h>
#include <linux/memory.h>
#include <linux/numa_remote.h>
#include "../../mm/hugetlb_vmemmap.h"
#include "../../mm/internal.h"

/* The default distance between local node and remote node */
#define REMOTE_TO_LOCAL_DISTANCE	100
/* The default distance between two remote node */
#define REMOTE_TO_REMOTE_DISTANCE	255

bool numa_remote_enabled __ro_after_init;
static bool numa_remote_nofallback_mode __ro_after_init;
static bool numa_remote_preonline_mode __ro_after_init;
static bool numa_remote_hugetlb_nowatermark_mode __ro_after_init;
static int numa_remote_max_nodes __ro_after_init = MAX_NUMNODES;

static nodemask_t numa_nodes_remote;

struct undo_fake_online_control {
	u64 start;
	u64 size;
	int nid;
	struct llist_node llist;
};

static LLIST_HEAD(undo_fake_online_list);

static atomic_long_t undo_fake_online_pages_node[MAX_NUMNODES];
static atomic_long_t pre_online_pages_node[MAX_NUMNODES];
static atomic_long_t pre_online_pages;

static DEFINE_MUTEX(numa_remote_lock);
static DECLARE_RWSEM(numa_remote_state_lock);

bool numa_is_remote_node(int nid)
{
	return !!node_isset(nid, numa_nodes_remote);
}
EXPORT_SYMBOL_GPL(numa_is_remote_node);

bool numa_remote_nofallback(int nid)
{
	return numa_remote_nofallback_mode && numa_is_remote_node(nid);
}

bool numa_remote_preonline(int nid)
{
	return numa_remote_preonline_mode && numa_is_remote_node(nid);
}

bool numa_remote_hugetlb_nowatermark(int nid)
{
	return numa_remote_hugetlb_nowatermark_mode && numa_is_remote_node(nid);
}

static void numa_remote_reset_distance(int nid)
{
	int i;

	for (i = 0; i < MAX_NUMNODES; i++) {
		if (i == nid)
			continue;
		if (!numa_is_remote_node(i)) {
			numa_set_distance(i, nid, REMOTE_TO_LOCAL_DISTANCE);
			numa_set_distance(nid, i, REMOTE_TO_LOCAL_DISTANCE);
		} else {
			numa_set_distance(i, nid, REMOTE_TO_REMOTE_DISTANCE);
			numa_set_distance(nid, i, REMOTE_TO_REMOTE_DISTANCE);
		}
	}
}

void __init numa_register_remote_nodes(void)
{
	int i, count = 0;

	if (!numa_remote_enabled)
		return;

	for (i = 0; i < MAX_NUMNODES; i++) {
		if (!node_test_and_set(i, numa_nodes_parsed)) {
			node_set(i, numa_nodes_remote);
			count++;
			if (count >= numa_remote_max_nodes)
				break;
		}
	}

	for (i = 0; i < MAX_NUMNODES; i++) {
		if (numa_is_remote_node(i))
			numa_remote_reset_distance(i);
	}

	pr_info("%d nodes", nodes_weight(numa_nodes_remote));
}

/*
 * Parse a series of numa_remote options.
 *
 * 'nofallback': skip remote node from zonelists.
 * 'preonline': support to online remote memory before it is ready.
 */
static int __init numa_parse_remote_nodes(char *buf)
{
	char *sep;
	int val;

	numa_remote_enabled = true;

	if (!buf)
		return 0;

	while (*buf) {
		sep = strchr(buf, ',');
		if (sep)
			*sep = 0;
		if (!strcmp(buf, "nofallback"))
			numa_remote_nofallback_mode = true;
		else if (!strcmp(buf, "preonline"))
			numa_remote_preonline_mode = true;
#ifdef CONFIG_HUGETLB_PAGE
		else if (!strcmp(buf, "hugetlb_nowatermark"))
			numa_remote_hugetlb_nowatermark_mode = true;
#endif
		else if (!kstrtoint(buf, 0, &val)) {
			if (val > 0)
				numa_remote_max_nodes = val;
		}
		if (!sep)
			break;
		buf = sep + 1;
	}

	return 0;
}
early_param("numa_remote", numa_parse_remote_nodes);

static void numa_remote_optimize_vmemmap(unsigned long start_pfn,
					 unsigned long end_pfn)
{
	unsigned long pfn;
	struct page *page;

	for (pfn = start_pfn; pfn < end_pfn; pfn += MAX_ORDER_NR_PAGES) {
		page = pfn_to_page(pfn);
		if (!page)
			continue;

		fake_online_pages_vmemmap_optimize(page, MAX_ORDER_NR_PAGES);
	}
}

static int numa_remote_restore_vmemmap(unsigned long start_pfn,
				       unsigned long end_pfn)
{
	unsigned long pfn;
	struct page *page;
	int ret;

	for (pfn = start_pfn; pfn < end_pfn; pfn += MAX_ORDER_NR_PAGES) {
		page = pfn_to_page(pfn);
		if (!page)
			continue;

		ret = fake_online_pages_vmemmap_restore(page, MAX_ORDER_NR_PAGES);
		if (ret) {
			numa_remote_optimize_vmemmap(start_pfn, pfn);
			return ret;
		}
	}

	return 0;
}

static void numa_remote_preonline_going_offline(unsigned long pfn,
						  unsigned long nr_pages)
{
	struct page *page;
	unsigned long i;

	adjust_managed_page_count(pfn_to_page(pfn), nr_pages);
	for (i = 0; i < nr_pages; i++) {
		page = pfn_to_page(pfn + i);
		if (WARN_ON(!page_ref_dec_and_test(page)))
			dump_page(page, "preonline page referenced");
	}
}

static void numa_remote_preonline_cancel_offline(unsigned long pfn,
						  unsigned long nr_pages)
{
	unsigned long i;

	adjust_managed_page_count(pfn_to_page(pfn), -nr_pages);
	for (i = 0; i < nr_pages; i++)
		page_ref_inc(pfn_to_page(pfn + i));
}

static int numa_remote_memory_notifier_cb(struct notifier_block *nb,
					 unsigned long action, void *arg)
{
	struct memory_notify *mhp = arg;
	const unsigned long start = PFN_PHYS(mhp->start_pfn);
	const unsigned long size = PFN_PHYS(mhp->nr_pages);
	int nid = pfn_to_nid(mhp->start_pfn);

	if (!check_memory_block_pre_online(start, size, true))
		return NOTIFY_DONE;

	switch (action) {
	case MEM_GOING_OFFLINE:
		numa_remote_preonline_going_offline(mhp->start_pfn, mhp->nr_pages);
		break;
	case MEM_CANCEL_OFFLINE:
		numa_remote_preonline_cancel_offline(mhp->start_pfn, mhp->nr_pages);
		break;
	case MEM_OFFLINE:
		atomic_long_add(-mhp->nr_pages, &pre_online_pages_node[nid]);
		atomic_long_add(-mhp->nr_pages, &pre_online_pages);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

struct notifier_block numa_remote_memory_notifier = {
	.notifier_call = numa_remote_memory_notifier_cb,
};

static void numa_remote_online_pages_cb(struct page *page, unsigned int order)
{
	unsigned long start_pfn, end_pfn, pfn, nr_pages;
	int nid = page_to_nid(page);
	struct page *p;

	start_pfn = page_to_pfn(page);
	nr_pages = 1 << order;
	end_pfn = start_pfn + nr_pages;

	if (!check_memory_block_pre_online(PFN_PHYS(start_pfn), nr_pages * PAGE_SIZE, true)) {
		generic_online_page(page, order);
		return;
	}

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		p = pfn_to_page(pfn);
		__SetPageOffline(p);
		ClearPageReserved(p);
	}
	numa_remote_optimize_vmemmap(start_pfn, end_pfn);
	atomic_long_add(nr_pages, &pre_online_pages_node[nid]);
	atomic_long_add(nr_pages, &pre_online_pages);
}

static void numa_remote_online_pages(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long nr_pages = end_pfn - start_pfn;
	unsigned long pfn, i;
	struct page *page;

	for (i = 0; i < nr_pages; ++i) {
		page = pfn_to_page(start_pfn + i);
		__ClearPageOffline(page);
	}

	for (pfn = start_pfn; pfn < end_pfn; pfn += (1UL << MAX_ORDER))
		generic_online_page(pfn_to_page(pfn), MAX_ORDER);
}

/*
 * Undo fake-online a remote node. Have to be called in preonline mode then
 * the memory on the node can be allocated.
 */
static int __ref numa_remote_undo_fake_online(u64 start, u64 size, int nid)
{
	unsigned long start_pfn = PFN_DOWN(start);
	unsigned long end_pfn = PFN_DOWN(start + size);
	unsigned long nr_pages = end_pfn - start_pfn;
	int ret = 0;

	mem_hotplug_begin();
	if (!check_memory_block_pre_online(start, size, true)) {
		ret = -EINVAL;
		goto out;
	}

	if (!check_memory_block_online(start, size)) {
		ret = -EINVAL;
		goto out;
	}

	if (!check_memory_block_nid(start, size, nid)) {
		ret = -EINVAL;
		goto out;
	}

	ret = numa_remote_restore_vmemmap(start_pfn, end_pfn);
	if (ret) {
		pr_err_ratelimited("restore vmemmap failed\n");
		goto out;
	}

	set_memory_block_pre_online(start, size, false);
	atomic_long_add(-nr_pages, &pre_online_pages_node[nid]);
	atomic_long_add(-nr_pages, &pre_online_pages);
	numa_remote_online_pages(start_pfn, end_pfn);

	init_per_zone_wmark_min();
	writeback_set_ratelimit();

out:
	atomic_long_add(-nr_pages, &undo_fake_online_pages_node[nid]);
	mem_hotplug_done();
	if (unlikely(ret))
		pr_warn("online memory [%llx, %llx) failed: %d\n", start, start + size, ret);
	return ret;
}

static int __ref numa_remote_restore_isolation(u64 start, u64 size)
{
	unsigned long start_pfn = PFN_DOWN(start);
	unsigned long end_pfn = PFN_DOWN(start + size);
	int ret = 0;

	mem_hotplug_begin();

	ret = numa_remote_restore_vmemmap(start_pfn, end_pfn);
	if (ret) {
		pr_err_ratelimited("restore vmemmap failed\n");
		goto out;
	}

out:
	mem_hotplug_done();
	return ret;
}

static void undo_fake_online_work_fn(struct work_struct *work)
{
	struct undo_fake_online_control *uic;
	struct llist_node *node;

	node = llist_del_all(&undo_fake_online_list);

	while (node) {
		uic = container_of(node, struct undo_fake_online_control, llist);
		node = node->next;

		mutex_lock(&numa_remote_lock);
		numa_remote_undo_fake_online(uic->start, uic->size, uic->nid);
		mutex_unlock(&numa_remote_lock);
		kfree(uic);
	}
}

static DECLARE_WORK(undo_fake_online_work, undo_fake_online_work_fn);

static void numa_remote_wait_undo_fake_online(void)
{
	flush_work(&undo_fake_online_work);
}

bool numa_remote_try_wait_undo_fake_online(int nid)
{
	int ret = false;

	if (!numa_remote_preonline(nid))
		return ret;

	if (!atomic_long_read(&undo_fake_online_pages_node[nid]))
		return ret;

	/*
	 * Avoid circular locking lockdep warnings. Preonline and
	 * offline require numa_remote_lock and vma lock. undo_fake_online_work
	 * requires numa_remote_lock. handle_mm_fault() may flush undo_fake_online_work
	 * with vma lock held. This forms circular locking dependency. However,
	 * numa_remote_state_lock guarantees when preonline or offline is doing,
	 * handle_mm_fault() won't flush undo_fake_online_work. False positive.
	 */
	lockdep_off();
	if (!down_read_trylock(&numa_remote_state_lock))
		goto out;

	numa_remote_wait_undo_fake_online();
	up_read(&numa_remote_state_lock);
	ret = true;
out:
	lockdep_on();
	return ret;
}

static int find_unused_remote_node(void)
{
	int nid;

	for_each_node_mask(nid, numa_nodes_remote) {
		if (!node_online(nid))
			return nid;
	}

	return NUMA_NO_NODE;
}

/*
 * Add remote memory to the system as system RAM from CXL or UB.
 * The resource_name (visible via /proc/iomem) has to have the format
 * "System RAM (Remote)".
 *
 * @nid:	which node to online
 * @start:	start address of memory range
 * @size:	size of memory range
 * @flags:	memory hotplug flags
 *
 * Returns:
 *	node in case add memory succeed.
 *	NUMA_NO_NODE in case add memory failed.
 */
int add_memory_remote(int nid, u64 start, u64 size, int flags)
{
	int real_nid = NUMA_NO_NODE;
	mhp_t mhp_flags = MHP_MERGE_RESOURCE;

	if (!numa_remote_enabled)
		return NUMA_NO_NODE;

	if (nid < NUMA_NO_NODE || nid >= MAX_NUMNODES)
		return NUMA_NO_NODE;

	if (nid != NUMA_NO_NODE && !numa_is_remote_node(nid))
		return NUMA_NO_NODE;

	if (!numa_remote_preonline_mode && !(flags & MEMORY_DIRECT_ONLINE))
		return NUMA_NO_NODE;

	if (flags & ~(MEMORY_KEEP_ISOLATED | MEMORY_DIRECT_ONLINE))
		return NUMA_NO_NODE;

	if (flags == (MEMORY_KEEP_ISOLATED | MEMORY_DIRECT_ONLINE))
		return NUMA_NO_NODE;

	/* Online pre-onlined memory. To avoid grabbing numa_rmeote
	 * lock and leading to unstable performance, don't check if
	 * [start, start + size) is pre-onelined, check it in the
	 * async work.
	 */
	if (!flags) {
		struct undo_fake_online_control *uic;

		if (check_hotplug_memory_range(start, size))
			return NUMA_NO_NODE;

		if (nid == NUMA_NO_NODE)
			return NUMA_NO_NODE;

		uic = kzalloc(sizeof(struct undo_fake_online_control),
					GFP_KERNEL);
		if (!uic)
			return NUMA_NO_NODE;

		atomic_long_add(size / PAGE_SIZE, &undo_fake_online_pages_node[nid]);
		uic->start = start;
		uic->size = size;
		uic->nid = nid;
		if (llist_add(&uic->llist, &undo_fake_online_list))
			schedule_work(&undo_fake_online_work);
		return nid;
	}

	numa_remote_wait_undo_fake_online();
	down_write(&numa_remote_state_lock);
	mutex_lock(&numa_remote_lock);
	lock_device_hotplug();

	real_nid = (nid == NUMA_NO_NODE) ? find_unused_remote_node() : nid;
	if (real_nid == NUMA_NO_NODE)
		goto unlock;

	if (flags & MEMORY_KEEP_ISOLATED)
		mhp_flags |= MHP_PREONLINE;

	if (__add_memory(real_nid, start, size, mhp_flags))
		real_nid = NUMA_NO_NODE;

unlock:
	unlock_device_hotplug();
	mutex_unlock(&numa_remote_lock);
	up_write(&numa_remote_state_lock);
	return real_nid;
}
EXPORT_SYMBOL_GPL(add_memory_remote);

/*
 * Remove remote memory.
 *
 * Returns:
 *	0 in case of memory hotremove succeed.
 *	-errno in case of memory hotremove failed.
 */
int remove_memory_remote(int nid, u64 start, u64 size)
{
	int ret = -EINVAL;

	if (!numa_remote_enabled)
		return -EINVAL;

	if (nid <= NUMA_NO_NODE || nid >= MAX_NUMNODES)
		return -EINVAL;

	if (!numa_is_remote_node(nid) || !node_online(nid))
		return -EINVAL;

	numa_remote_wait_undo_fake_online();

	down_write(&numa_remote_state_lock);
	mutex_lock(&numa_remote_lock);
	if (!check_memory_block_nid(start, size, nid))
		goto out;

	/*
	 * If all memory block are already online, do nothing here.
	 * If all memory block are pre-online, restore the isolation
	 * and count. If mixed, don't allow to offline.
	 */
	if (numa_remote_preonline(nid) &&
	    !check_memory_block_pre_online(start, size, false)) {
		if (!check_memory_block_pre_online(start, size, true))
			goto out;
		if (numa_remote_restore_isolation(start, size))
			goto out;
	}

	ret = offline_and_remove_memory(start, size);
	if (ret)
		goto out;

	if (!node_online(nid))
		numa_remote_reset_distance(nid);

out:
	mutex_unlock(&numa_remote_lock);
	up_write(&numa_remote_state_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(remove_memory_remote);

int numa_remote_set_distance(int target, int *node_ids, int *node_distances,
			     int count)
{
	int i;

	if (!numa_remote_enabled)
		return -EINVAL;

	if (target <= NUMA_NO_NODE || target >= MAX_NUMNODES)
		return -EINVAL;

	if (!numa_is_remote_node(target))
		return -EINVAL;

	for (i = 0; i < count; i++) {
		if (numa_is_remote_node(node_ids[i]))
			return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		numa_set_distance(target, node_ids[i], node_distances[i]);
		numa_set_distance(node_ids[i], target, node_distances[i]);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(numa_remote_set_distance);

static ssize_t remote_show(struct device *dev,
			   struct device_attribute *dev_attr, char *buf)
{
	return sprintf(buf, "%d\n", numa_is_remote_node(dev->id));
}
static DEVICE_ATTR_RO(remote);

static ssize_t critical_err_show(struct device *dev,
				 struct device_attribute *dev_attr, char *buf)
{
	return sprintf(buf, "%d\n", node_is_critical_err(dev->id) ? 1 : 0);
}

static ssize_t critical_err_store(struct device *dev,
				  struct device_attribute *dev_attr,
				  const char *buf, size_t count)
{
	int nid = dev->id;
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	if (val > 1)
		return -EINVAL;

	if (val == 0)
		clear_node_critical_err(nid);
	else
		set_node_critical_err(nid);

	return count;
}
static DEVICE_ATTR_RW(critical_err);

void numa_remote_register_node(struct node *node)
{
	if (!numa_remote_enabled)
		return;

	device_create_file(&node->dev, &dev_attr_remote);
	if (IS_ENABLED(CONFIG_ACPI_APEI_RAS_CRITICAL) &&
	    numa_is_remote_node(node->dev.id))
		device_create_file(&node->dev, &dev_attr_critical_err);
}

void numa_remote_unregister_node(struct node *node)
{
	if (!numa_remote_enabled)
		return;

	device_remove_file(&node->dev, &dev_attr_remote);
	if (IS_ENABLED(CONFIG_ACPI_APEI_RAS_CRITICAL) &&
	    numa_is_remote_node(node->dev.id))
		device_remove_file(&node->dev, &dev_attr_critical_err);
}

void numa_remote_report_meminfo(struct seq_file *m)
{
	pg_data_t *pgdat;
	struct zone *zone;
	unsigned long total_pages = 0;
	unsigned long free_pages = 0;

	if (!numa_remote_enabled)
		return;

	for_each_online_pgdat(pgdat) {
		zone = &pgdat->node_zones[ZONE_EXTMEM];
		if (populated_zone(zone)) {
			total_pages += zone_managed_pages(zone);
			free_pages += zone_page_state(zone, NR_FREE_PAGES);
		}
	}

	seq_printf(m, "RemoteMemTotal: %8lu kB\n"
			"RemoteMemFree:  %8lu kB\n"
			"RemoteMemPreonline: %4lu kB\n",
			K(total_pages), K(free_pages),
			K(atomic_long_read(&pre_online_pages)));
}

int numa_remote_report_node_meminfo(char *buf, int len, int nid)
{
	if (!numa_remote_enabled)
		return 0;

	return sysfs_emit_at(buf, len,
			     "Node %d RemoteMemPreonline: %4lu kB\n",
			     nid, K(atomic_long_read(&pre_online_pages_node[nid])));
}

static int __init numa_remote_init(void)
{
	int ret;

	if (!numa_remote_enabled)
		return 0;

	sysctl_oom_kill_cpuless_numa_allocating_task = 1;

	if (!numa_remote_preonline_mode)
		return 0;

	ret = set_online_page_callback(&numa_remote_online_pages_cb);
	if (ret)
		goto err_online_callback;

	ret = register_memory_notifier(&numa_remote_memory_notifier);
	if (ret)
		goto err_register_notifier;

	return 0;

err_register_notifier:
	restore_online_page_callback(&numa_remote_online_pages_cb);
err_online_callback:
	numa_remote_preonline_mode = false;
	pr_err("fail to enanble preonline mode\n");
	return ret;
}
late_initcall(numa_remote_init);
