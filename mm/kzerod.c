// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel zero pages daemon for anonymous memory
 */
#include <uapi/linux/sched/types.h>
#include <linux/suspend.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/kfifo.h>
#include <linux/llist.h>
#include <stdatomic.h>
#include <linux/mmzone.h>

#define KZEROD_CPUID_SIZE 16
#define GFP_MASK                                                               \
	((GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) | __GFP_NORETRY | __GFP_NOWARN)
#define GFP_THP_MASK (GFP_TRANSHUGE_LIGHT | __GFP_NORETRY)
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define KZEROD_POOL_SIZE 2
/* Default thp water mark. */
static unsigned short thp_wmark_per_numa = 20;
#else
#define KZEROD_POOL_SIZE 1
#endif
DECLARE_WAIT_QUEUE_HEAD(kzerod_wait);
DEFINE_SPINLOCK(kfifo_lock);
static unsigned short wmark_per_numa = 5;
static unsigned int kzerod_order_map;
static bool kzerod_enabled;
static struct task_struct *task_kzerod;
struct kfifo task_queue;
static struct kzerod_node **kzerod_pool;
static struct kzerod_numa_node **kzerod_per_numa;
struct kzerod_node {
	unsigned int wmark_high;
	unsigned int wmark_low;
	spinlock_t lock;
	atomic_t cur_nr;
	bool processing;
	unsigned short cpuid;
	struct llist_head zerod_pages;
};

struct kzerod_numa_node {
	unsigned short cpu_nr;
	atomic_t cur;
	struct kzerod_node **per_cpu_node;
};

static inline unsigned int kzerod_get_idx(unsigned int order)
{
	switch (order) {
	case 0:
		return 0;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	case HPAGE_PMD_ORDER:
		return 1;
#endif
	}
	return -1;
}

static inline unsigned int kzerod_get_order(unsigned int idx)
{
	switch (idx) {
	case 0:
		return 0;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	case 1:
		return HPAGE_PMD_ORDER;
#endif
	}
	return -1;
}

static inline struct kzerod_node *kzerod_get_node(unsigned int order,
						  unsigned int cpuid)
{
	unsigned int idx;
	struct kzerod_numa_node *node =
		&kzerod_per_numa[kzerod_get_idx(order)][cpu_to_node(cpuid)];

	idx = ((unsigned int)atomic_inc_return(&node->cur)) % node->cpu_nr;
	return node->per_cpu_node[idx];
}

void kzerod_enable_order(unsigned int order)
{
	kzerod_order_map |= 1U << order;
}

static inline void kzerod_disable_order(unsigned int order)
{
	kzerod_order_map &= ~(1U << order);
}

static inline bool kzerod_check_order(unsigned int order)
{
	return (kzerod_order_map & (1U << order)) != 0;
}

/* Get kzerod size by order. */
unsigned long kzerod_get_zeroed_size(unsigned int order)
{
	int cpuid;
	unsigned long ret = 0;
	unsigned int idx = kzerod_get_idx(order);
	unsigned int nr = 1 << order;

	if (!kzerod_enabled)
		return 0;
	for (cpuid = 0; cpuid < nr_cpu_ids; cpuid++)
		ret += atomic_read(&kzerod_pool[idx][cpuid].cur_nr) * nr;
	return ret;
}

/* Update water mark for a kerod node. */
static inline void kzerod_update_wmark(unsigned int order, unsigned int cpuid)
{
	int idx = kzerod_get_idx(order);
	int node = cpu_to_node(cpuid);
	struct kzerod_node *zn = &kzerod_pool[idx][cpuid];
	unsigned long long free_pages = NODE_DATA(node)->node_present_pages;
	/* `cpus_nr` means online cpu number in this numa node. */
	unsigned int cpus_nr = cpumask_weight(cpumask_of_node(node));

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (order == HPAGE_PMD_ORDER)
		zn->wmark_high = free_pages / (1 << order) *
				 thp_wmark_per_numa / cpus_nr / 100;
	else
		zn->wmark_high = free_pages * wmark_per_numa / cpus_nr / 100;
#else
	zn->wmark_high = free_pages * wmark_per_numa / cpus_nr / 100;
#endif

	zn->wmark_low = zn->wmark_high >> 2;
	pr_debug(
		"%s: Update wmark for cpu: %d, order: %d, cur node free pages nr(4K): %llu, %d < %d",
		__FILE__, cpuid, order, free_pages, zn->wmark_low,
		zn->wmark_high);
}

/* Alloc a prezeroed page by order and cpuid. */
struct page *alloc_prezeroed_page(unsigned int order, unsigned int cpuid)
{
	int ret;
	unsigned int task = 0;
	unsigned long _flag;
	struct page *page = NULL;
	struct kzerod_node *zn;
	struct llist_node *lnode;

	if (unlikely(!kzerod_enabled))
		return NULL;
	zn = kzerod_get_node(order, cpuid);
	/* Fast fail if get lock failed. */
	spin_lock_irqsave(&zn->lock, _flag);
	if (!llist_empty(&zn->zerod_pages)) {
		lnode = llist_del_first(&zn->zerod_pages);
		spin_unlock_irqrestore(&zn->lock, _flag);
		page = llist_entry(lnode, struct page, kzerod_node);
		atomic_dec(&zn->cur_nr);
	} else
		spin_unlock_irqrestore(&zn->lock, _flag);

	if (atomic_read(&zn->cur_nr) < zn->wmark_low && !zn->processing &&
	    kzerod_check_order(order)) {
		zn->processing = true;
		task = (order << KZEROD_CPUID_SIZE) | zn->cpuid;
		ret = kfifo_in_spinlocked(&task_queue, &task, sizeof(task),
					  &kfifo_lock);
		if (unlikely(ret != sizeof(task))) {
			pr_err("%s: Write data failed: %d\n", __FILE__, task);
			return NULL;
		}
		wake_up(&kzerod_wait);
	}

	return page;
}

/* Drain zero page for a order, also disable this order. */
void drain_zerod_page(unsigned int order)
{
	unsigned int id;
	unsigned long prev_zero;
	struct page *page;
	struct kzerod_node *zn;
	struct llist_node *head;
	struct page *last_page;
	struct pglist_data *node;

	kzerod_disable_order(order);
	for (id = 0; id < nr_cpu_ids; id++) {
		zn = &kzerod_pool[kzerod_get_idx(order)][id];
		if (zn == NULL)
			continue;
		prev_zero = atomic_read(&zn->cur_nr);
		spin_lock(&zn->lock);
		head = llist_del_all(&zn->zerod_pages);
		spin_unlock(&zn->lock);
		page = llist_entry(head, struct page, kzerod_node);
		if (!member_address_is_nonnull(page, kzerod_node))
			continue;
		node = NODE_DATA(cpu_to_node(id));
		do {
			last_page = llist_entry(&page->kzerod_node, struct page,
						kzerod_node);
			page = llist_entry(last_page->kzerod_node.next, struct page, kzerod_node);
			__free_pages(last_page, order);
			atomic_dec(&zn->cur_nr);
		} while (member_address_is_nonnull(page, kzerod_node));
	}
	pr_debug("%s: drained %lu pages for order %d\n", __FILE__,
		     prev_zero, order);
}

/* Drain all zero page in all zerod list. */
static void drain_all_zerod_page(void)
{
	unsigned int i, order;

	for (i = 0; i < KZEROD_POOL_SIZE; i++) {
		order = kzerod_get_order(i);
		kzerod_disable_order(order);
		drain_zerod_page(order);
	}
}

/* Used to clear page, support non-temporal instruction on x86_64 arch. */
static inline void kzerod_clear_page(struct page *page,
				     unsigned int pages_per_huge_page)
{
	int i;
	void *addr;

	for (i = 0; i < pages_per_huge_page; i++) {
		addr = kmap_atomic(page);
		clear_page_nocache(addr);
		kunmap_atomic(addr);
	}
}

/* Zeroing for one cpu by order. */
static int kzerod_zeroing(unsigned int order, unsigned int cpuid, gfp_t gfp)
{
	long nr = 0;
	int ret = 0;
	struct page *page;
	struct kzerod_node *zn;
	unsigned int nodeid = cpu_to_node(cpuid);

	if (!kzerod_enabled)
		return -ENODEV;
	zn = &kzerod_pool[kzerod_get_idx(order)][cpuid];
	while (atomic_read(&zn->cur_nr) < zn->wmark_high) {
		page = alloc_pages_node(nodeid, gfp, order);
		if (!page) {
			ret = -ENOMEM;
			goto out;
		}
		kzerod_clear_page(page, 1 << order);
		nr += 1 << order;
		/* No one will touch page->lnode so we don't need lock_page(). */
		llist_add(&page->kzerod_node, &zn->zerod_pages);
		atomic_inc(&zn->cur_nr);
	}
out:
	zn->processing = false;
	return ret;
}

/* Kernel zero page daemon function. */
static int kzerod(void *p)
{
	int ret;
	unsigned int task = 0;
	static unsigned long prev_jiffies;
	unsigned int prev_zero, cur_zero, cpuid, order;
	struct kzerod_node *zn;

	while (true) {
		/* Freeze until kfifo not empty. */
		wait_event_freezable(kzerod_wait, !kfifo_is_empty(&task_queue));
		/* Process all kzerod tasks in kfifo. */
		while (!kfifo_is_empty(&task_queue)) {
			ret = kfifo_out(&task_queue, &task, sizeof(task));
			if (unlikely(ret != sizeof(task))) {
				pr_err("%s: Read data failed: %d\n", __FILE__,
				       task);
				return -ENODEV;
			}
			cpuid = task & 0xFFFF;
			order = task >> KZEROD_CPUID_SIZE & 0xFFFF;
			if (unlikely(!kzerod_check_order(order)))
				continue;
			zn = &kzerod_pool[kzerod_get_idx(order)][cpuid];
			prev_zero = atomic_read(&zn->cur_nr);
			pr_debug("%s: zeroing for cpu %d, order %d\n",
				     __FILE__, cpuid, order);
			prev_jiffies = jiffies;
			ret = kzerod_zeroing(order, cpuid,
					     order == HPAGE_PMD_ORDER ?
							   GFP_THP_MASK :
							   GFP_MASK);
			cur_zero = atomic_read(&zn->cur_nr);
			pr_debug(
				"%s: ret from cpu %d order %d: %s(%d) zeroed:%d->%d pages %ums\n",
				__FILE__, cpuid, order,
				ret ? "failed" : "finished", ret, prev_zero,
				cur_zero,
				jiffies_to_msecs(jiffies - prev_jiffies));
			switch (ret) {
			case 0:
				continue;
			case -ENOMEM:
				pr_debug("%s: No mem left for node %d\n",
					     __FILE__, cpu_to_node(cpuid));
				continue;
			case -ENODEV:
				return -ENODEV;
			}
		}
	}
	return 0;
}

/* Free all memory alloced by kmalloc. */
static void __kzerod_free(void)
{
	unsigned int idx, nid;

	if (kfifo_initialized(&task_queue))
		kfifo_free(&task_queue);

	for (idx = 0; idx < KZEROD_POOL_SIZE; idx++) {
		kfree(kzerod_pool[idx]);
		for (nid = 0; nid < nr_online_nodes; nid++)
			kfree(kzerod_per_numa[idx][nid].per_cpu_node);
		kfree(kzerod_per_numa[idx]);
	}

	kfree(kzerod_pool);
	kfree(kzerod_per_numa);
}

/* Exit kzerod module. */
static void __kzerod_exit(void)
{
	kzerod_enabled = false;
	kzerod_order_map = 0;

	if (task_kzerod)
		kthread_stop(task_kzerod);

	if (kzerod_enabled)
		drain_all_zerod_page();

	__kzerod_free();
}

static void __exit kzerod_exit(void)
{
	__kzerod_exit();
}

static int kzerod_struct_init(void)
{
	int ret;
	unsigned int idx, nid;

	kzerod_pool =
		kmalloc_array(KZEROD_POOL_SIZE, sizeof(void *), GFP_KERNEL);
	if (!kzerod_pool)
		return -ENOMEM;

	kzerod_per_numa =
		kmalloc_array(KZEROD_POOL_SIZE, sizeof(void *), GFP_KERNEL);

	if (!kzerod_per_numa) {
		kfree(kzerod_pool);
		return -ENOMEM;
	}

	for (idx = 0; idx < KZEROD_POOL_SIZE; idx++) {
		/* Alloc kzerod pool, we alloc `nr_cpu_ids` node since some cpus maybe offline. */
		kzerod_pool[idx] = kmalloc_array(nr_cpu_ids, sizeof(struct kzerod_node),
		 GFP_KERNEL);
		if (!kzerod_pool[idx]) {
			ret = -ENOMEM;
			goto kzerod_init_failed;
		}
		memset(kzerod_pool[idx], 0,
		       nr_cpu_ids * sizeof(struct kzerod_node));

		kzerod_per_numa[idx] = kmalloc_array(nr_online_nodes,
				      sizeof(struct kzerod_numa_node), GFP_KERNEL);
		if (!kzerod_per_numa[idx]) {
			ret = -ENOMEM;
			goto kzerod_init_failed;
		}
		memset(kzerod_per_numa[idx], 0,
		       nr_online_nodes * sizeof(struct kzerod_numa_node));

		for (nid = 0; nid < nr_online_nodes; nid++) {
			kzerod_per_numa[idx][nid].per_cpu_node = kmalloc_array(
					nr_cpu_ids, sizeof(void *), GFP_KERNEL);
			if (!kzerod_per_numa[idx][nid].per_cpu_node) {
				ret = -ENOMEM;
				goto kzerod_init_failed;
			}
			memset(kzerod_per_numa[idx][nid].per_cpu_node, 0,
		       nr_cpu_ids * sizeof(void *));
		}
	}

	ret = kfifo_alloc(&task_queue,
			  nr_cpu_ids * KZEROD_POOL_SIZE * sizeof(unsigned int),
			  GFP_KERNEL);
	if (ret) {
		ret = -ENOMEM;
		goto kzerod_init_failed;
	}

	return 0;

kzerod_init_failed:
	pr_err("%s: Failed to alloc memory for kzerod\n", __FILE__);
	__kzerod_free();
	return ret;
}

static void kzerod_struct_set(void)
{
	unsigned int idx, cpuid, order;
	struct kzerod_node *node;
	struct kzerod_numa_node *numa_node;

	for (idx = 0; idx < KZEROD_POOL_SIZE; idx++) {
		/* Enable current order. */
		order = kzerod_get_order(idx);
		kzerod_enable_order(order);
		for (cpuid = 0; cpuid < nr_cpu_ids; cpuid++) {
			node = &kzerod_pool[idx][cpuid];
			node->cpuid = cpuid;
			numa_node = &kzerod_per_numa[idx][cpu_to_node(cpuid)];
			kzerod_update_wmark(order, cpuid);
			init_llist_head(&node->zerod_pages);
			spin_lock_init(&node->lock);
			/* CPU hot-plug is not currently supported. */
			numa_node->per_cpu_node[numa_node->cpu_nr] = node;
			numa_node->cpu_nr++;
		}
	}
}

static int kzerod_thread_init(void)
{
	int ret;
	struct sched_param param = { .sched_priority = 0 };

	task_kzerod = kthread_run(kzerod, NULL, "kzerod");
	if (IS_ERR(task_kzerod)) {
		task_kzerod = NULL;
		pr_err("%s: Failed to start kzerod\n", __FILE__);
		return -ENODEV;
	}

	kzerod_enabled = true;
	ret = sched_setscheduler(task_kzerod, SCHED_NORMAL, &param);
	return ret;
}

/* Init kzerod module. */
static int __init kzerod_init(void)
{
	int ret;

	ret = kzerod_struct_init();
	if (ret)
		return ret;

	kzerod_struct_set();

	ret = kzerod_thread_init();
	if (ret) {
		__kzerod_exit();
		return ret;
	}

	return 0;
}

/* Enable or disable kzerod param.*/
static int kzerod_set_enabled_param(const char *val,
				    const struct kernel_param *kp)
{
	int error;
	bool prev;
	unsigned int i, order;

	if (!task_kzerod) {
		pr_err("%s: Can't enable, task_kzerod is not ready\n",
		       __FILE__);
		return -ENODEV;
	}

	prev = kzerod_enabled;
	error = param_set_bool(val, kp);
	if (error)
		return error;
	if (!prev && kzerod_enabled) {
		for (i = 0; i < KZEROD_POOL_SIZE; i++) {
			order = kzerod_get_order(i);
			kzerod_enable_order(order);
		}
		pr_info("%s: enabled\n", __FILE__);
	} else if (prev && !kzerod_enabled) {
		drain_all_zerod_page();
		pr_info("%s: disabled\n", __FILE__);
	}
	return error;
}

static struct kernel_param_ops kzerod_enabled_param_ops = {
	.set = kzerod_set_enabled_param,
	.get = param_get_bool,
};
module_param_cb(enabled, &kzerod_enabled_param_ops, &kzerod_enabled, 0644);

/* Set water mark for common pages, all cpu in a numa node share these pages. */
static int kzerod_set_wmark_param(const char *val,
				  const struct kernel_param *kp)
{
	int error;
	unsigned short result;
	unsigned int id;

	if (!kzerod_enabled) {
		pr_err("%s: Can't set, enable kzerod first\n", __FILE__);
		return -ENODEV;
	}
	error = kstrtou16(val, 10, &result);
	if (error < 0 || result > 90 || (result + wmark_per_numa) > 90) {
		pr_err("Invalid input: %d\n", result);
		return error;
	}

	error = param_set_ushort(val, kp);

	for (id = 0; id < nr_cpu_ids; id++)
		kzerod_update_wmark(0, id);
	return error;
}

static struct kernel_param_ops kzerod_wmark_param_ops = {
	.set = kzerod_set_wmark_param,
	.get = param_get_ushort,
};
module_param_cb(per_numa_water_mark, &kzerod_wmark_param_ops, &wmark_per_numa,
		0644);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* Set water mark for transparent pages, all cpu in a numa node share these pages. */
static int kzerod_set_thp_wmark_param(const char *val,
				      const struct kernel_param *kp)
{
	int error;
	unsigned short result;
	unsigned int id;

	if (!kzerod_enabled) {
		pr_err("%s: Can't set, enable kzerod first\n", __FILE__);
		return -ENODEV;
	}
	error = kstrtou16(val, 10, &result);
	if (error < 0 || result > 90 || (result + thp_wmark_per_numa) > 90) {
		pr_err("Invalid input: %d\n", result);
		return error;
	}

	error = param_set_ushort(val, kp);

	for (id = 0; id < nr_cpu_ids; id++)
		kzerod_update_wmark(HPAGE_PMD_ORDER, id);
	return error;
}

static struct kernel_param_ops kzerod_thp_wmark_param_ops = {
	.set = kzerod_set_thp_wmark_param,
	.get = param_get_ushort,
};
module_param_cb(thp_per_numa_water_mark, &kzerod_thp_wmark_param_ops,
		&thp_wmark_per_numa, 0644);
#endif

module_init(kzerod_init);
module_exit(kzerod_exit);
