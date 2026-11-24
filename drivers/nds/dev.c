// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "p2p: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/vmalloc.h>
#include <linux/notifier.h>
#include <linux/tracepoint.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <linux/mutex.h>
#include <linux/percpu-refcount.h>
#include <linux/pid.h>
#include <linux/ratelimit.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/sort.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#ifdef CALC_CRC32
#include <linux/crc32.h>
#endif

#include <linux/nvme.h>
#include <linux/blk_types.h>
#include <linux/file.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include <trace/events/block.h>

#include <linux/nds_p2p.h>
#include "mem.h"
#include "compat.h"
#include "debugfs.h"
#include "dev.h"
#include "topo.h"

/* Shared error budget for user-triggered memory registration failures. */
static DEFINE_RATELIMIT_STATE(p2p_mem_ratelimit, 5 * HZ, 30);

#define p2p_pr_err_rl(fmt, ...) \
	do { \
		if (__ratelimit(&p2p_mem_ratelimit)) \
			pr_err(fmt, ##__VA_ARGS__); \
	} while (0)

#define P2P_NVME_MAX_RW_SECTORS ((1U << 20) >> SECTOR_SHIFT)
#define P2P_MAX_IOV 65536U
#define P2P_MAX_EXTENTS 1048576U
#define P2P_MAX_IOV_SIZE (2U << 30)
#define P2P_MAX_EXTENT_SIZE ((u64)U32_MAX << SECTOR_SHIFT)
#define P2P_MIN_PAGE_SIZE (4U << 10)
#define P2P_MEM_MAX_TOTAL_RANGES 65536U
/* Power-of-two CQ; caps outstanding I/Os per batch (in-flight + unharvested). */
#define P2P_CQ_SIZE P2P_MAX_IO_NR
#define P2P_CQ_MASK (P2P_CQ_SIZE - 1)

struct p2p_pa_iov {
	u64 addr;
	u64 len;
};

struct p2p_iov_iter {
	const struct p2p_pa_iov *iov;
	unsigned int nr_segs;
	u64 iov_offset;
	u64 count;
};

struct p2p_iov_map {
	u64 aligned_addr;
	u64 aligned_size;
	struct p2p_page_table *page_table;
	u32 page_size;
	u32 pa_num;
};

struct p2p_pinned_pa {
	struct p2p_iov_map *maps;
	unsigned int pinned_map_nr;
};

struct p2p_batch;

/* One independently pinned HBM VA range owned by a p2p_batch (mem_fd). */
struct p2p_mem_region {
	u64 addr;                       /* registered VA start */
	u64 size;                       /* registered byte length */
	u64 end;                        /* addr + size */
	u64 aligned_addr;               /* page_size-aligned VA start */
	struct p2p_page_table *page_table; /* CANN handle; pages_info[] used directly */
	u32 page_size;
	u32 pa_num;
	u32 page_shift;                 /* ilog2(page_size) */

	atomic_t table_refs;            /* live p2p_mem_tables referencing this region */
	struct completion unused;       /* signaled when table_refs drops to 0 */
	struct list_head node;          /* sorted by addr in batch->mem_regions */
};

/*
 * Immutable per-fd VA->PA lookup table snapshot.
 * Completely self-contained (no back-pointer to p2p_batch) so deferred teardown
 * cannot race with p2p_release().
 */
struct p2p_mem_table {
	unsigned int nr_regions;
	u32 min_page_shift;             /* min(page_shift) across all regions */
	pid_t owner_pid;                /* TGID reported in debugfs */
	u64 *reg_starts;                /* sorted VA starts, nr_regions entries */
	struct p2p_mem_region **regions;/* pinned regions in sorted VA order */

	struct percpu_ref io_refs;      /* active I/Os (and debugfs readers) */
	struct list_head debugfs_node;  /* RCU list for lockless debugfs enumeration */
	struct work_struct release_work;/* drops region->table_refs & kvfree()s arrays */
	struct rcu_head rcu;            /* percpu_ref_exit() + kfree() after grace period */
};

struct p2p_pinned_io_mem {
	bool pinned;
	bool reg_mem;
	union {
		struct p2p_pinned_pa *pinned_pa;
		struct p2p_mem_table *mem_table;
	};
};

struct p2p_io_context;

struct p2p_batch {
	/*
	 * Accepted CQ slots not yet retired; limited to P2P_CQ_SIZE.
	 */
	atomic_t io_cnt;

	/*
	 * AIO-style completion ring (fs/aio.c shape): the producer publishes
	 * slots and advances cq_tail under completion_lock only; the consumer
	 * reads slots and advances cq_head under the ring_lock mutex only.
	 * Neither side takes the other's lock on the hot path.
	 */
	struct p2p_io_context **cq;
	unsigned int cq_head;
	unsigned int cq_tail;
	/* Completed I/Os published to the CQ but not yet harvested. */
	atomic_t ready_events;
	/* Accepted I/Os not yet harvested, including ready_events. */
	atomic_t outstanding_events;
	spinlock_t completion_lock;
	/* Consumer side: getevents harvest, serialized against drain. */
	struct mutex ring_lock;

	wait_queue_head_t wait;
	struct shared_topo_list shared_topos;

	/* Per-fd registered memory VA table */
	struct mutex mem_lock;                  /* serializes register / unregister / release */
	struct pid *mem_owner_tgid;             /* TGID that opened this fd */
	struct list_head mem_regions;           /* p2p_mem_region sorted by addr */
	unsigned int mem_region_nr;
	struct p2p_mem_table __rcu *mem_table;  /* NULL when mem_region_nr == 0 or released */
};

struct p2p_io_context {
	u32 op;
	struct file *file;
	struct p2p_pa_iov *pa_iov;
	unsigned int pa_iov_nr;
	struct p2p_pinned_io_mem pinned_mem;
	u64 data_size;
	u64 user_data;
	struct completion io_done;
	atomic_t io_ref;
	int io_err;
	int issue_err;
	struct p2p_batch *batch;
#if defined(CALC_CRC32) || defined(DUMP_CONTENT)
	struct work_struct finalize_work;
#endif
};


static dev_t dev;
static struct class *dev_class;
static struct cdev p2p_cdev;

static struct tracepoint *p2p_tp;
static DEFINE_MUTEX(p2p_tp_lock);
static struct module *p2p_tp_mod;

static struct workqueue_struct *p2p_mem_wq;
static DEFINE_SPINLOCK(p2p_mem_table_list_lock);
static LIST_HEAD(p2p_mem_table_list);

static int p2p_open(struct inode *inode, struct file *file);
static int p2p_release(struct inode *inode, struct file *file);
static long p2p_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int p2p_drain_io(struct p2p_batch *batch);
static void p2p_tp_hook_exit(void);
static void p2p_revoke_mem_table(struct p2p_batch *batch,
				 struct list_head *revoked);
static void p2p_destroy_mem_region_list(struct list_head *revoked);
static void p2p_io_ctx_put(struct p2p_io_context *io_ctx);
static void p2p_publish_io_done(struct p2p_io_context *io_ctx);
#if defined(CALC_CRC32) || defined(DUMP_CONTENT)
static void p2p_finalize_io_work(struct work_struct *work);
#endif

static const struct file_operations dev_p2p_fops = {
	.owner = THIS_MODULE,
	.open = p2p_open,
	.release = p2p_release,
	.unlocked_ioctl = p2p_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

int p2p_debugfs_memory_show(struct seq_file *seq, void *unused)
{
	struct p2p_mem_table *tbl;

	rcu_read_lock();
	list_for_each_entry_rcu(tbl, &p2p_mem_table_list, debugfs_node) {
		unsigned int i;

		if (!percpu_ref_tryget_live(&tbl->io_refs))
			continue;

		seq_printf(seq, "pid=%d ranges=%u span=0x%llx-0x%llx\n",
			   tbl->owner_pid, tbl->nr_regions,
			   tbl->reg_starts[0],
			   tbl->regions[tbl->nr_regions - 1]->end);
		for (i = 0; i < tbl->nr_regions; i++) {
			const struct p2p_mem_region *reg = tbl->regions[i];

			seq_printf(seq, "  segment %u: va [0x%llx, 0x%llx) aligned 0x%llx page_size 0x%x\n",
				   i, reg->addr, reg->end,
				   reg->aligned_addr, reg->page_size);
		}
		percpu_ref_put(&tbl->io_refs);
	}
	rcu_read_unlock();

	return 0;
}

static int p2p_open(struct inode *inode, struct file *file)
{
	struct p2p_batch *batch;

	batch = kzalloc(sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return -ENOMEM;

	batch->cq = kcalloc(P2P_CQ_SIZE, sizeof(*batch->cq), GFP_KERNEL);
	if (!batch->cq) {
		kfree(batch);
		return -ENOMEM;
	}

	spin_lock_init(&batch->completion_lock);
	mutex_init(&batch->ring_lock);
	init_waitqueue_head(&batch->wait);
	spin_lock_init(&batch->shared_topos.lock);
	INIT_LIST_HEAD(&batch->shared_topos.head);
	mutex_init(&batch->mem_lock);
	batch->mem_owner_tgid = get_task_pid(current, PIDTYPE_TGID);
	INIT_LIST_HEAD(&batch->mem_regions);
	batch->mem_region_nr = 0;
	RCU_INIT_POINTER(batch->mem_table, NULL);
	atomic_set(&batch->io_cnt, 0);
	batch->cq_head = 0;
	batch->cq_tail = 0;
	atomic_set(&batch->ready_events, 0);
	atomic_set(&batch->outstanding_events, 0);

	file->private_data = batch;

	return 0;
}

static int p2p_release(struct inode *inode, struct file *file)
{
	struct p2p_batch *batch = file->private_data;
	struct shared_topo *shared, *next;
	LIST_HEAD(topos);
	LIST_HEAD(revoked_regions);

	/* 1. Stop new submissions from acquiring this fd's VA table. */
	p2p_revoke_mem_table(batch, &revoked_regions);

	/* 2. Drain this fd's own in-flight I/Os (handles mem_fd == io_fd). */
	if (atomic_read(&batch->io_cnt) > 0)
		p2p_drain_io(batch);

	/* 3. Wait for any other fd's/process's in-flight I/Os, then unpin. */
	p2p_destroy_mem_region_list(&revoked_regions);

	/* 4. Tear down topologies, CQ, and batch. */
	spin_lock(&batch->shared_topos.lock);
	list_splice_init(&batch->shared_topos.head, &topos);
	spin_unlock(&batch->shared_topos.lock);
	list_for_each_entry_safe(shared, next, &topos, list) {
		list_del(&shared->list);
		topo_del(shared->topo);
		kfree(shared);
	}

	put_pid(batch->mem_owner_tgid);
	kfree(batch->cq);
	kfree(batch);

	file->private_data = NULL;

	return 0;
}

static void p2p_mem_free_callback(void *data)
{
	(void)data;
}

static int p2p_pin_va_range(u64 addr, u64 size, struct p2p_iov_map *map)
{
	struct p2p_page_table *page_table = NULL;
	u64 aligned_addr;
	u64 aligned_end;
	u64 end;
	u64 get_addr;
	u64 get_end;
	u64 get_size;
	u64 page_num;
	int err;

	if (!size)
		return -EINVAL;
	if (check_add_overflow(addr, size, &end))
		return -EOVERFLOW;
	get_addr = round_down(addr, (u64)PAGE_SIZE);
	if (check_add_overflow(end, (u64)PAGE_SIZE - 1, &get_end))
		return -EOVERFLOW;
	get_end = round_down(get_end, (u64)PAGE_SIZE);
	get_size = get_end - get_addr;

	err = p2p_mem_get_pages(get_addr, get_size, p2p_mem_free_callback, NULL, &page_table);
	if (err) {
		pr_err("get page table addr 0x%llx size 0x%llx err %d\n", get_addr, get_size, err);
		return err;
	}

	if (!page_table || page_table->version != P2P_GET_PAGE_VERSION || !page_table->pages_info ||
	    page_table->page_size < P2P_MIN_PAGE_SIZE || page_table->page_size > U32_MAX ||
	    !is_power_of_2(page_table->page_size)) {
		pr_err("invalid page table version %u page_size 0x%llx\n",
		       page_table ? page_table->version : 0,
		       page_table ? page_table->page_size : 0);
		err = -EINVAL;
		goto put_pages;
	}

	aligned_addr = round_down(addr, page_table->page_size);
	if (check_add_overflow(end, page_table->page_size - 1, &aligned_end)) {
		err = -EOVERFLOW;
		goto put_pages;
	}
	aligned_end = round_down(aligned_end, page_table->page_size);
	page_num = (aligned_end - aligned_addr) / page_table->page_size;
	if (!page_num || page_num > U32_MAX || page_table->page_num != page_num) {
		pr_err("invalid page table page_num %llu expected %llu\n",
		       page_table->page_num, page_num);
		err = -EINVAL;
		goto put_pages;
	}

	pr_debug("pinned VA 0x%llx+0x%llx ver %u page_num %llu page_size 0x%llx\n",
		 addr, size, page_table->version, page_num, page_table->page_size);

	map->aligned_addr = aligned_addr;
	map->aligned_size = aligned_end - aligned_addr;
	map->page_table = page_table;
	map->page_size = (u32)page_table->page_size;
	map->pa_num = (u32)page_num;
	return 0;

put_pages:
	if (page_table)
		p2p_mem_put_pages(page_table);
	return err;
}

static void p2p_put_pinned_pa(struct p2p_pinned_pa *pinned_pa)
{
	unsigned int i;

	for (i = 0; i < pinned_pa->pinned_map_nr; i++) {
		struct p2p_iov_map *map = &pinned_pa->maps[i];
		int err;

		err = p2p_mem_put_pages(map->page_table);
		if (err)
			pr_err("put page table %u err %d\n", i, err);
	}

	kvfree(pinned_pa->maps);
	kfree(pinned_pa);
}

static void p2p_mem_table_free_rcu(struct rcu_head *rcu)
{
	struct p2p_mem_table *tbl;

	tbl = container_of(rcu, struct p2p_mem_table, rcu);
	percpu_ref_exit(&tbl->io_refs);
	kfree(tbl);
}

static void p2p_mem_table_release_work(struct work_struct *work)
{
	struct p2p_mem_table *tbl;
	unsigned int i;

	tbl = container_of(work, struct p2p_mem_table, release_work);
	for (i = 0; i < tbl->nr_regions; i++) {
		struct p2p_mem_region *reg = tbl->regions[i];

		if (atomic_dec_and_test(&reg->table_refs)) {
			pr_debug("memory region addr 0x%llx size 0x%llx unused\n",
				 reg->addr, reg->size);
			complete(&reg->unused);
		}
	}
	/*
	 * Safe to free here: io_refs is already 0, so no submitter or debugfs
	 * reader can pass percpu_ref_tryget_live() to dereference these arrays.
	 */
	kvfree(tbl->regions);
	kvfree(tbl->reg_starts);
	call_rcu(&tbl->rcu, p2p_mem_table_free_rcu);
}

static void p2p_mem_table_release(struct percpu_ref *ref)
{
	struct p2p_mem_table *tbl;

	tbl = container_of(ref, struct p2p_mem_table, io_refs);
	queue_work(p2p_mem_wq, &tbl->release_work);
}

static struct p2p_mem_table *p2p_mem_table_alloc(struct list_head *regions,
						 unsigned int nr_regions,
						 pid_t owner_pid)
{
	struct p2p_mem_table *tbl;
	struct p2p_mem_region *reg;
	u32 min_shift = U32_MAX;
	unsigned int i = 0;
	int err;

	tbl = kzalloc(sizeof(*tbl), GFP_KERNEL);
	if (!tbl)
		return ERR_PTR(-ENOMEM);

	tbl->reg_starts = kvmalloc_array(nr_regions, sizeof(*tbl->reg_starts), GFP_KERNEL);
	tbl->regions = kvmalloc_array(nr_regions, sizeof(*tbl->regions), GFP_KERNEL);
	if (!tbl->reg_starts || !tbl->regions) {
		err = -ENOMEM;
		goto free_arrays;
	}

	INIT_LIST_HEAD(&tbl->debugfs_node);
	INIT_WORK(&tbl->release_work, p2p_mem_table_release_work);
	err = percpu_ref_init(&tbl->io_refs, p2p_mem_table_release, 0, GFP_KERNEL);
	if (err)
		goto free_arrays;

	list_for_each_entry(reg, regions, node) {
		tbl->reg_starts[i] = reg->addr;
		tbl->regions[i] = reg;
		if (reg->page_shift < min_shift)
			min_shift = reg->page_shift;
		atomic_inc(&reg->table_refs);
		i++;
	}
	WARN_ON_ONCE(i != nr_regions);
	tbl->nr_regions = nr_regions;
	tbl->min_page_shift = min_shift;
	tbl->owner_pid = owner_pid;
	return tbl;

free_arrays:
	kvfree(tbl->regions);
	kvfree(tbl->reg_starts);
	kfree(tbl);
	return ERR_PTR(err);
}

static int p2p_pin_mem_region(u64 addr, u64 size, struct p2p_mem_region **reg_out)
{
	struct p2p_mem_region *reg;
	struct p2p_iov_map map;
	u32 i;
	int err;

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (!reg)
		return -ENOMEM;

	err = p2p_pin_va_range(addr, size, &map);
	if (err)
		goto free_reg;

	for (i = 0; i < map.pa_num; i++) {
		if (map.page_table->pages_info[i].pa & (SECTOR_SIZE - 1)) {
			pr_err("unaligned PA 0x%llx at page %u for addr 0x%llx\n",
			       map.page_table->pages_info[i].pa, i, addr);
			err = -EINVAL;
			goto put_pages;
		}
	}

	reg->addr = addr;
	reg->size = size;
	reg->end = addr + size;
	reg->aligned_addr = map.aligned_addr;
	reg->page_table = map.page_table;
	reg->page_size = map.page_size;
	reg->pa_num = map.pa_num;
	reg->page_shift = ilog2(reg->page_size);
	atomic_set(&reg->table_refs, 0);
	init_completion(&reg->unused);
	INIT_LIST_HEAD(&reg->node);
	*reg_out = reg;
	return 0;

put_pages:
	p2p_mem_put_pages(map.page_table);
free_reg:
	kfree(reg);
	return err;
}

static void p2p_unpin_mem_region(struct p2p_mem_region *reg)
{
	int err;

	err = p2p_mem_put_pages(reg->page_table);
	if (err)
		pr_err("put page table addr 0x%llx err %d\n", reg->addr, err);
	kfree(reg);
}

static struct p2p_mem_table *p2p_swap_mem_table(struct p2p_batch *batch,
						struct p2p_mem_table *new_tbl)
{
	struct p2p_mem_table *old_tbl;

	old_tbl = rcu_dereference_protected(batch->mem_table,
					    lockdep_is_held(&batch->mem_lock));
	spin_lock(&p2p_mem_table_list_lock);
	if (old_tbl)
		list_del_rcu(&old_tbl->debugfs_node);
	if (new_tbl)
		list_add_tail_rcu(&new_tbl->debugfs_node, &p2p_mem_table_list);
	spin_unlock(&p2p_mem_table_list_lock);
	rcu_assign_pointer(batch->mem_table, new_tbl);
	return old_tbl;
}

static void p2p_revoke_mem_table(struct p2p_batch *batch,
				 struct list_head *revoked)
{
	struct p2p_mem_table *old_tbl;

	mutex_lock(&batch->mem_lock);
	old_tbl = p2p_swap_mem_table(batch, NULL);
	list_splice_init(&batch->mem_regions, revoked);
	batch->mem_region_nr = 0;
	mutex_unlock(&batch->mem_lock);

	if (old_tbl)
		percpu_ref_kill(&old_tbl->io_refs);
}

static void p2p_destroy_mem_region_list(struct list_head *revoked)
{
	struct p2p_mem_region *reg, *next;

	list_for_each_entry_safe(reg, next, revoked, node) {
		list_del_init(&reg->node);
		pr_debug("waiting for memory region addr 0x%llx size 0x%llx\n",
			 reg->addr, reg->size);
		wait_for_completion(&reg->unused);
		pr_debug("memory region addr 0x%llx size 0x%llx drained\n",
			 reg->addr, reg->size);
		p2p_unpin_mem_region(reg);
	}
}

static int p2p_mem_range_cmp(const void *a, const void *b)
{
	const struct p2p_mem_range *ra = a;
	const struct p2p_mem_range *rb = b;

	if (ra->addr < rb->addr)
		return -1;
	return ra->addr > rb->addr;
}

/* Sort ranges by VA and reject empty, overflowing, or overlapping ones. */
static int p2p_sort_mem_ranges(struct p2p_mem_range *ranges, unsigned int nr)
{
	unsigned int i;
	u64 end;

	for (i = 0; i < nr; i++) {
		if (!ranges[i].size)
			return -EINVAL;
		if (check_add_overflow(ranges[i].addr, ranges[i].size, &end))
			return -EOVERFLOW;
	}

	sort(ranges, nr, sizeof(*ranges), p2p_mem_range_cmp, NULL);
	for (i = 1; i < nr; i++) {
		if (ranges[i].addr < ranges[i - 1].addr + ranges[i - 1].size) {
			p2p_pr_err_rl("registered range 0x%llx+0x%llx overlaps 0x%llx+0x%llx\n",
				      ranges[i].addr, ranges[i].size,
				      ranges[i - 1].addr, ranges[i - 1].size);
			return -EINVAL;
		}
	}
	return 0;
}

static int p2p_check_mem_overlap(const struct list_head *existing,
				 const struct p2p_mem_range *ranges,
				 unsigned int nr)
{
	const struct p2p_mem_region *reg;
	struct list_head *pos = existing->next;
	unsigned int i = 0;

	while (pos != existing && i < nr) {
		u64 r_start = ranges[i].addr;
		u64 r_end = r_start + ranges[i].size;

		reg = list_entry(pos, struct p2p_mem_region, node);
		if (reg->end <= r_start) {
			pos = pos->next;
		} else if (r_end <= reg->addr) {
			i++;
		} else {
			p2p_pr_err_rl("register range 0x%llx+0x%llx overlaps 0x%llx+0x%llx\n",
				      r_start, ranges[i].size, reg->addr, reg->size);
			return -EEXIST;
		}
	}
	return 0;
}

/* Merge sorted @new_regs[0..nr-1] into sorted @existing list. */
static void p2p_merge_mem_regions(struct list_head *existing,
				  struct p2p_mem_region **new_regs,
				  unsigned int nr)
{
	struct list_head *pos = existing->next;
	unsigned int i;

	for (i = 0; i < nr; i++) {
		while (pos != existing &&
		       list_entry(pos, struct p2p_mem_region, node)->addr < new_regs[i]->addr)
			pos = pos->next;
		list_add_tail(&new_regs[i]->node, pos);
	}
}

static int p2p_register_mem(struct p2p_batch *batch, void __user *arg)
{
	struct p2p_mem_register_param param;
	struct p2p_mem_range *ranges;
	struct p2p_mem_region **new_regs = NULL;
	struct p2p_mem_table *new_tbl;
	struct p2p_mem_table *old_tbl;
	unsigned int pinned = 0;
	unsigned int i;
	int err;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	if (param.flags || param.reserved[0] || param.reserved[1] ||
	    param.reserved[2] || param.reserved[3] || !param.ranges ||
	    !param.nr || param.nr > P2P_MEM_MAX_RANGES)
		return -EINVAL;

	ranges = kvmalloc_array(param.nr, sizeof(*ranges), GFP_KERNEL);
	if (!ranges)
		return -ENOMEM;
	if (copy_from_user(ranges, u64_to_user_ptr(param.ranges),
			   array_size(param.nr, sizeof(*ranges)))) {
		err = -EFAULT;
		goto free_ranges;
	}

	err = p2p_sort_mem_ranges(ranges, param.nr);
	if (err)
		goto free_ranges;

	new_regs = kvcalloc(param.nr, sizeof(*new_regs), GFP_KERNEL);
	if (!new_regs) {
		err = -ENOMEM;
		goto free_ranges;
	}

	mutex_lock(&batch->mem_lock);
	if (batch->mem_owner_tgid != task_tgid(current)) {
		err = -EPERM;
		goto unlock;
	}
	if (batch->mem_region_nr > P2P_MEM_MAX_TOTAL_RANGES - param.nr) {
		err = -E2BIG;
		goto unlock;
	}
	err = p2p_check_mem_overlap(&batch->mem_regions, ranges, param.nr);
	if (err)
		goto unlock;

	for (i = 0; i < param.nr; i++) {
		err = p2p_pin_mem_region(ranges[i].addr, ranges[i].size, &new_regs[i]);
		if (err)
			goto unpin_new;
		pinned++;
	}

	p2p_merge_mem_regions(&batch->mem_regions, new_regs, param.nr);
	new_tbl = p2p_mem_table_alloc(&batch->mem_regions,
				      batch->mem_region_nr + param.nr,
				      pid_vnr(batch->mem_owner_tgid));
	if (IS_ERR(new_tbl)) {
		err = PTR_ERR(new_tbl);
		for (i = 0; i < param.nr; i++)
			list_del_init(&new_regs[i]->node);
		goto unpin_new;
	}

	batch->mem_region_nr += param.nr;
	old_tbl = p2p_swap_mem_table(batch, new_tbl);
	if (old_tbl)
		percpu_ref_kill(&old_tbl->io_refs);
	mutex_unlock(&batch->mem_lock);

	kvfree(new_regs);
	kvfree(ranges);
	return 0;

unpin_new:
	for (i = 0; i < pinned; i++)
		p2p_unpin_mem_region(new_regs[i]);
unlock:
	mutex_unlock(&batch->mem_lock);
	kvfree(new_regs);
free_ranges:
	kvfree(ranges);
	return err;
}

static int p2p_unregister_mem(struct p2p_batch *batch, void __user *arg)
{
	struct p2p_mem_unregister_param param;
	struct p2p_mem_range *ranges;
	struct p2p_mem_region **removed = NULL;
	struct p2p_mem_table *new_tbl = NULL;
	struct p2p_mem_table *old_tbl;
	struct list_head *pos;
	LIST_HEAD(removed_list);
	unsigned int i;
	int err;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	if (param.flags || param.reserved[0] || param.reserved[1] ||
	    param.reserved[2] || param.reserved[3] || !param.ranges ||
	    !param.nr || param.nr > P2P_MEM_MAX_RANGES)
		return -EINVAL;

	ranges = kvmalloc_array(param.nr, sizeof(*ranges), GFP_KERNEL);
	if (!ranges)
		return -ENOMEM;
	if (copy_from_user(ranges, u64_to_user_ptr(param.ranges),
			   array_size(param.nr, sizeof(*ranges)))) {
		err = -EFAULT;
		goto free_ranges;
	}

	err = p2p_sort_mem_ranges(ranges, param.nr);
	if (err)
		goto free_ranges;

	removed = kvcalloc(param.nr, sizeof(*removed), GFP_KERNEL);
	if (!removed) {
		err = -ENOMEM;
		goto free_ranges;
	}

	mutex_lock(&batch->mem_lock);
	if (batch->mem_owner_tgid != task_tgid(current)) {
		err = -EPERM;
		goto unlock;
	}

	pos = batch->mem_regions.next;
	for (i = 0; i < param.nr; i++) {
		struct p2p_mem_region *reg;

		while (pos != &batch->mem_regions &&
		       list_entry(pos, struct p2p_mem_region, node)->addr < ranges[i].addr)
			pos = pos->next;
		if (pos == &batch->mem_regions) {
			err = -ENOENT;
			goto unlock;
		}
		reg = list_entry(pos, struct p2p_mem_region, node);
		if (reg->addr != ranges[i].addr) {
			err = -ENOENT;
			goto unlock;
		}
		if (reg->size != ranges[i].size) {
			err = -EINVAL;
			goto unlock;
		}
		removed[i] = reg;
		pos = pos->next;
	}

	for (i = 0; i < param.nr; i++)
		list_del_init(&removed[i]->node);

	if (batch->mem_region_nr > param.nr) {
		new_tbl = p2p_mem_table_alloc(&batch->mem_regions,
					      batch->mem_region_nr - param.nr,
					      pid_vnr(batch->mem_owner_tgid));
		if (IS_ERR(new_tbl)) {
			err = PTR_ERR(new_tbl);
			p2p_merge_mem_regions(&batch->mem_regions, removed, param.nr);
			goto unlock;
		}
	}

	batch->mem_region_nr -= param.nr;
	old_tbl = p2p_swap_mem_table(batch, new_tbl);
	mutex_unlock(&batch->mem_lock);

	if (old_tbl)
		percpu_ref_kill(&old_tbl->io_refs);
	for (i = 0; i < param.nr; i++)
		list_add_tail(&removed[i]->node, &removed_list);
	p2p_destroy_mem_region_list(&removed_list);
	err = 0;
	goto free_removed;

unlock:
	mutex_unlock(&batch->mem_lock);
free_removed:
	kvfree(removed);
free_ranges:
	kvfree(ranges);
	return err;
}

#ifdef DUMP_CONTENT
static void dump_pa_content(u64 pa, u64 size)
{
	unsigned int data_len = min_t(u64, size, 16U << 10);
	char prefix[64];
	void *addr;

	addr = ioremap(pa, data_len);
	if (!addr) {
		return;
	}

	scnprintf(prefix, sizeof(prefix), "p2p: PA 0x%llx content: ", pa);
	print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_ADDRESS, 16, 1, addr, data_len, false);

	iounmap(addr);
}
#else
static inline void dump_pa_content(u64 pa, u64 size)
{
}
#endif

static void p2p_iov_iter_init(struct p2p_iov_iter *iter,
			      const struct p2p_pa_iov *iov,
			      unsigned int nr_segs, u64 count)
{
	*iter = (struct p2p_iov_iter) {
		.iov = iov,
		.nr_segs = nr_segs,
		.count = count,
	};
}

static inline u64 p2p_iov_iter_count(const struct p2p_iov_iter *iter)
{
	return iter->count;
}

static inline u64 p2p_iov_iter_addr(const struct p2p_iov_iter *iter)
{
	return iter->iov->addr + iter->iov_offset;
}

static u32 p2p_iov_iter_single_seg_sectors(const struct p2p_iov_iter *iter)
{
	if (!iter->count)
		return 0;
	if (WARN_ON_ONCE(iter->iov_offset >= iter->iov->len))
		return 0;
	return (iter->iov->len - iter->iov_offset) >> SECTOR_SHIFT;
}

static void p2p_iov_iter_advance(struct p2p_iov_iter *iter, u64 bytes)
{
	if (WARN_ON_ONCE(bytes > iter->count)) {
		iter->count = 0;
		return;
	}

	iter->count -= bytes;
	iter->iov_offset += bytes;

	if (iter->iov_offset < iter->iov->len)
		return;

	iter->iov++;
	iter->nr_segs--;
	iter->iov_offset = 0;
}

static int get_pa_iov(const struct p2p_iov *iov, unsigned int iov_nr,
		      struct p2p_pa_iov **pa_iov, unsigned int *pa_iov_nr,
		      struct p2p_pinned_io_mem *pinned_mem)
{
	struct p2p_pinned_pa *pinned_pa;
	struct p2p_pa_iov *new_pa_iov;
	struct p2p_pa_iov *cur_pa_iov;
	struct p2p_iov_map *maps;
	unsigned int new_pa_iov_nr;
	unsigned int i;
	int err;

	pinned_pa = kzalloc(sizeof(*pinned_pa), GFP_KERNEL);
	if (!pinned_pa)
		return -ENOMEM;
	pinned_pa->maps = kvcalloc(iov_nr, sizeof(*pinned_pa->maps), GFP_KERNEL);
	if (!pinned_pa->maps) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}
	maps = pinned_pa->maps;

	new_pa_iov_nr = 0;
	for (i = 0; i < iov_nr; i++) {
		err = p2p_pin_va_range(iov[i].addr, iov[i].size, &maps[i]);
		if (err) {
			pr_err("get page table addr 0x%llx size 0x%x iov %u err %d\n",
			       iov[i].addr, iov[i].size, i, err);
			goto put_pinned_pa;
		}
		pinned_pa->pinned_map_nr++;
		if (maps[i].pa_num > UINT_MAX - new_pa_iov_nr) {
			err = -E2BIG;
			goto put_pinned_pa;
		}
		new_pa_iov_nr += maps[i].pa_num;
	}

	new_pa_iov = kvmalloc_array(new_pa_iov_nr, sizeof(*new_pa_iov), GFP_KERNEL);
	if (!new_pa_iov) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}

	cur_pa_iov = new_pa_iov;
	for (i = 0; i < iov_nr; i++) {
		u64 next_pa = ULLONG_MAX;
		u32 remaining = iov[i].size;
		u32 offset = iov[i].addr - maps[i].aligned_addr;
		unsigned int j;

		for (j = 0; j < maps[i].pa_num; j++) {
			u32 len = min(remaining, maps[i].page_size - offset);
			u64 pa = maps[i].page_table->pages_info[j].pa + offset;

			if ((pa | len) & (SECTOR_SIZE - 1)) {
				pr_err("unaligned PA IOV addr 0x%llx, len 0x%x, iov %u\n",
				       pa, len, i);
				err = -EINVAL;
				break;
			}
			if (pa != next_pa) {
				cur_pa_iov->addr = pa;
				cur_pa_iov->len = len;
				cur_pa_iov++;
			} else {
				cur_pa_iov[-1].len += len;
			}
			next_pa = pa + len;
			remaining -= len;
			offset = 0;
		}

		if (err)
			goto free_pa_iov;
		if (remaining) {
			pr_err("PA list leaves 0x%x bytes for iov %u\n",
			       remaining, i);
			err = -EINVAL;
			goto free_pa_iov;
		}
	}

	*pa_iov = new_pa_iov;
	*pa_iov_nr = cur_pa_iov - new_pa_iov;
	*pinned_mem = (struct p2p_pinned_io_mem) {
		.pinned = true,
		.pinned_pa = pinned_pa,
	};
	return 0;

free_pa_iov:
	kvfree(new_pa_iov);
put_pinned_pa:
	p2p_put_pinned_pa(pinned_pa);
	return err;
}

static int p2p_get_mem_table(struct p2p_batch *mem_batch,
			     struct p2p_mem_table **tbl_out)
{
	struct p2p_mem_table *tbl;

	rcu_read_lock();
	for (;;) {
		tbl = rcu_dereference(mem_batch->mem_table);
		if (!tbl) {
			rcu_read_unlock();
			return -ENOENT;
		}
		if (likely(percpu_ref_tryget_live(&tbl->io_refs))) {
			rcu_read_unlock();
			*tbl_out = tbl;
			return 0;
		}
		/*
		 * A concurrent register/unregister published a newer table (or
		 * NULL) before calling percpu_ref_kill() on @tbl. Re-read so an
		 * unrelated register/unregister never causes spurious -ESTALE.
		 */
		cpu_relax();
	}
}

static int p2p_resolve_mem_fd(int mem_fd, struct p2p_mem_table **tbl_out)
{
	struct p2p_mem_table *tbl;
	struct fd f;
	int err;

	if (mem_fd < 0)
		return -EBADF;

	f = fdget(mem_fd);
	if (!f.file)
		return -EBADF;
	if (f.file->f_op != &dev_p2p_fops) {
		fdput(f);
		return -EINVAL;
	}
	err = p2p_get_mem_table(f.file->private_data, &tbl);
	fdput(f);
	if (err)
		return err;

	*tbl_out = tbl;
	return 0;
}

/*
 * Find the region containing @addr. Try the caller's cursor and its successor
 * before branchless binary search.
 */
static const struct p2p_mem_region *p2p_mem_find_region(const struct p2p_mem_table *tbl,
							u64 addr, unsigned int *cursor)
{
	unsigned int nr = tbl->nr_regions;
	unsigned int lo = *cursor;
	unsigned int len;

	if (lo < nr && addr >= tbl->reg_starts[lo]) {
		if (addr < tbl->regions[lo]->end)
			return tbl->regions[lo];
		lo++;
		if (lo < nr && addr >= tbl->reg_starts[lo] && addr < tbl->regions[lo]->end) {
			*cursor = lo;
			return tbl->regions[lo];
		}
	}

	/* Branchless binary search: find the last region starting at or below addr. */
	lo = 0;
	len = nr;
	while (len > 1) {
		unsigned int half = len >> 1;

		lo += (tbl->reg_starts[lo + half] <= addr) ? half : 0;
		len -= half;
	}
	if (addr < tbl->reg_starts[lo] || addr >= tbl->regions[lo]->end)
		return NULL;
	*cursor = lo;
	return tbl->regions[lo];
}

/* Translate one IOV (must fit in one region) and coalesce physically contiguous PAs. */
static int p2p_mem_map_iov(const struct p2p_mem_table *tbl, const struct p2p_iov *iov,
			   unsigned int *cursor, struct p2p_pa_iov *pa_iov,
			   unsigned int *pa_iov_nr, u64 *next_pa)
{
	const struct p2p_mem_region *reg;
	const struct p2p_page_info *pages_info;
	u64 seg_offset;
	u64 page_idx;
	u32 page_offset;
	u32 remaining = iov->size;

	reg = p2p_mem_find_region(tbl, iov->addr, cursor);
	if (!reg || remaining > reg->end - iov->addr) {
		pr_err_ratelimited("registered IOV 0x%llx+0x%x out of segment range\n",
				   iov->addr, remaining);
		return -ERANGE;
	}

	pages_info = reg->page_table->pages_info;
	seg_offset = iov->addr - reg->aligned_addr;
	page_idx = seg_offset >> reg->page_shift;
	page_offset = seg_offset & (reg->page_size - 1);

	while (remaining) {
		u32 len = min(remaining, reg->page_size - page_offset);
		u64 pa = pages_info[page_idx].pa + page_offset;

		if ((pa | len) & (SECTOR_SIZE - 1))
			return -EINVAL;
		if (!*pa_iov_nr || pa != *next_pa) {
			pa_iov[*pa_iov_nr].addr = pa;
			pa_iov[*pa_iov_nr].len = len;
			(*pa_iov_nr)++;
		} else {
			pa_iov[*pa_iov_nr - 1].len += len;
		}
		*next_pa = pa + len;
		remaining -= len;
		page_idx++;
		page_offset = 0;
	}
	return 0;
}

static int get_registered_pa_iov(int mem_fd, const struct p2p_iov *iov,
				 unsigned int iov_nr, u64 data_size,
				 struct p2p_pa_iov **pa_iov_out,
				 unsigned int *pa_iov_nr_out,
				 struct p2p_pinned_io_mem *pinned_mem)
{
	struct p2p_mem_table *tbl;
	struct p2p_pa_iov *pa_iov;
	u64 max_pa_iov;
	u64 next_pa = ULLONG_MAX;
	unsigned int cursor = 0;
	unsigned int pa_iov_nr = 0;
	unsigned int i;
	int err;

	err = p2p_resolve_mem_fd(mem_fd, &tbl);
	if (err)
		return err;

	max_pa_iov = (data_size >> tbl->min_page_shift) + 2ULL * iov_nr;
	if (max_pa_iov > UINT_MAX) {
		pr_err_ratelimited("registered PA IOV count %llu exceeds limit (data_size 0x%llx iov_nr %u)\n",
				   max_pa_iov, data_size, iov_nr);
		err = -E2BIG;
		goto put_tbl;
	}

	pa_iov = kvmalloc_array(max_pa_iov, sizeof(*pa_iov), GFP_KERNEL);
	if (!pa_iov) {
		err = -ENOMEM;
		goto put_tbl;
	}

	for (i = 0; i < iov_nr; i++) {
		err = p2p_mem_map_iov(tbl, &iov[i], &cursor, pa_iov, &pa_iov_nr, &next_pa);
		if (err)
			goto free_pa_iov;
	}

	*pa_iov_out = pa_iov;
	*pa_iov_nr_out = pa_iov_nr;
	*pinned_mem = (struct p2p_pinned_io_mem) {
		.pinned = true,
		.reg_mem = true,
		.mem_table = tbl,
	};
	return 0;

free_pa_iov:
	kvfree(pa_iov);
put_tbl:
	percpu_ref_put(&tbl->io_refs);
	return err;
}

static void p2p_unpin_io_mem(struct p2p_pinned_io_mem *pinned_mem)
{
	if (!pinned_mem->pinned)
		return;

	if (pinned_mem->reg_mem)
		percpu_ref_put(&pinned_mem->mem_table->io_refs);
	else
		p2p_put_pinned_pa(pinned_mem->pinned_pa);
	pinned_mem->pinned = false;
}

static void free_io_ctx(struct p2p_io_context *io_ctx)
{
	p2p_unpin_io_mem(&io_ctx->pinned_mem);
	kvfree(io_ctx->pa_iov);
	fput(io_ctx->file);
	kfree(io_ctx);
}

static inline unsigned int p2p_queue_max_sectors(struct block_device *bdev)
{
	unsigned int max_sectors;

	max_sectors = queue_max_sectors(bdev_get_queue(bdev));

	return min(max_sectors, P2P_NVME_MAX_RW_SECTORS);
}

static struct p2p_io_context *new_io_ctx(u32 op, struct file *file, struct p2p_pa_iov *pa_iov,
					 unsigned int pa_iov_nr,
					 struct p2p_pinned_io_mem *pinned_mem, u64 data_size,
					 u64 user_data)
{
	struct p2p_io_context *io_ctx;

	io_ctx = kzalloc(sizeof(*io_ctx), GFP_KERNEL);
	if (!io_ctx)
		return ERR_PTR(-ENOMEM);

	io_ctx->op = op;
	io_ctx->file = file;
	io_ctx->pa_iov = pa_iov;
	io_ctx->pa_iov_nr = pa_iov_nr;
	io_ctx->pinned_mem = *pinned_mem;
	io_ctx->data_size = data_size;
	io_ctx->user_data = user_data;

	atomic_set(&io_ctx->io_ref, 1);
	init_completion(&io_ctx->io_done);
#if defined(CALC_CRC32) || defined(DUMP_CONTENT)
	INIT_WORK(&io_ctx->finalize_work, p2p_finalize_io_work);
#endif

	pinned_mem->pinned = false;
	return io_ctx;
}

static void p2p_hook_nvme_setup_cmd(void *ignore, struct request *rq,
				    struct nvme_command *cmd)
{
	if (rq->end_io != p2p_end_io)
		return;

	cmd->rw.flags = NVME_CMD_SGL_METABUF;
}

static bool is_nvme_setup_cmd_tp(struct tracepoint *tp)
{
	return !strcmp(tp->name, "nvme_setup_cmd");
}

static int p2p_register_tp_hook(struct tracepoint *tp)
{
	int err;

	err = tracepoint_probe_register(tp, p2p_hook_nvme_setup_cmd, NULL);
	if (!err) {
		p2p_tp = tp;
		pr_info("registered nvme_setup_cmd tp hook\n");
		return 0;
	}

	pr_warn("register tp hook err %d\n", err);
	return err;
}

static void p2p_find_builtin_tp(struct tracepoint *tp, void *priv)
{
	struct tracepoint **found = priv;

	if (!*found && is_nvme_setup_cmd_tp(tp))
		*found = tp;
}

#ifdef CONFIG_MODULES
static void p2p_register_tp_from_module(struct tp_module *module_tp)
{
	struct module *mod = module_tp->mod;
	unsigned int i;
	int err;

	for (i = 0; i < mod->num_tracepoints; i++) {
		struct tracepoint *tp;

		tp = tracepoint_ptr_deref(&mod->tracepoints_ptrs[i]);
		if (!is_nvme_setup_cmd_tp(tp))
			continue;

		if (!try_module_get(mod)) {
			pr_warn("failed to pin module\n");
			return;
		}

		err = p2p_register_tp_hook(tp);
		if (!err) {
			p2p_tp_mod = mod;
			return;
		}
		module_put(mod);
		return;
	}
}
#endif

static int p2p_tp_module_notify(struct notifier_block *nb, unsigned long val,
				void *data)
{
#ifdef CONFIG_MODULES
	struct tp_module *tp_mod = data;

	mutex_lock(&p2p_tp_lock);
	switch (val) {
	case MODULE_STATE_COMING:
		if (!p2p_tp)
			p2p_register_tp_from_module(tp_mod);
		break;
	default:
		break;
	}
	mutex_unlock(&p2p_tp_lock);
#endif

	return NOTIFY_OK;
}

static struct notifier_block p2p_tp_module_nb = {
	.notifier_call = p2p_tp_module_notify,
};

static int p2p_tp_hook_init(void)
{
	struct tracepoint *tp = NULL;
	int err;

	for_each_kernel_tracepoint(p2p_find_builtin_tp, &tp);
	if (tp)
		return p2p_register_tp_hook(tp);

	err = register_tracepoint_module_notifier(&p2p_tp_module_nb);
	if (err) {
		pr_err("register tp module notifier err %d\n", err);
		return err;
	}

	mutex_lock(&p2p_tp_lock);
	err = p2p_tp ? 0 : -ENOENT;
	mutex_unlock(&p2p_tp_lock);

	unregister_tracepoint_module_notifier(&p2p_tp_module_nb);

	if (err) {
		pr_err("tp not found\n");
		/*
		 * Notifier registration can synchronously invoke COMING
		 * callbacks, so use the shared exit path to undo any hook or
		 * module pin installed before this validation failed.
		 */
		p2p_tp_hook_exit();
	}

	return err;
}

static void p2p_tp_hook_exit(void)
{
	int err;

	if (!p2p_tp)
		return;

	err = tracepoint_probe_unregister(p2p_tp, p2p_hook_nvme_setup_cmd, NULL);
	if (err)
		pr_warn("unregister tp hook err %d\n", err);

	tracepoint_synchronize_unregister();

	module_put(p2p_tp_mod);
}

static void p2p_wake_batch_waiters(struct p2p_batch *batch)
{
	/*
	 * Pair condition stores (ready_events / outstanding_events / cq_tail
	 * under completion_lock, then unlock) with waitqueue_active: without this
	 * full barrier a
	 * waiter can observe !active, then miss the published condition and
	 * sleep. wait_event* still re-checks after prepare_to_wait.
	 */
	smp_mb();
	if (waitqueue_active(&batch->wait))
		wake_up(&batch->wait);
}

static void p2p_publish_io_done(struct p2p_io_context *io_ctx)
{
	struct p2p_batch *batch = io_ctx->batch;
	unsigned long flags;

	/*
	 * Producer hot path: completion_lock only (AIO's ctx->completion_lock
	 * shape). Always publish — drain never suppresses completion; it waits
	 * for natural publish then harvests under ring_lock.
	 */
	spin_lock_irqsave(&batch->completion_lock, flags);
	WARN_ON_ONCE(batch->cq_tail - READ_ONCE(batch->cq_head) >= P2P_CQ_SIZE);
	batch->cq[batch->cq_tail & P2P_CQ_MASK] = io_ctx;
	/* Slot stores must be visible before cq_tail advances. */
	smp_wmb();
	WRITE_ONCE(batch->cq_tail, batch->cq_tail + 1);
	atomic_inc(&batch->ready_events);
	spin_unlock_irqrestore(&batch->completion_lock, flags);

	p2p_wake_batch_waiters(batch);
	/* Last touch of io_ctx: harvest/drain wait io_done before freeing. */
	complete(&io_ctx->io_done);
}

void p2p_complete_io(struct request *req, blk_status_t status)
{
	struct p2p_io_context *io_ctx = req->end_io_data;

	p2p_stats_io_complete(io_ctx->op, status);
	if (status)
		cmpxchg(&io_ctx->io_err, 0, status);

	p2p_io_ctx_put(io_ctx);
}

static const char *p2p_io_op_name(u32 op)
{
	return op == P2P_IO_WRITE ? "write" : "read";
}

static int p2p_zero_pa(u64 pa, u32 nr_sectors)
{
	/* Keep each mapping modest; one iov segment can be up to 2 GiB. */
	const u32 chunk = (1U << 20) >> SECTOR_SHIFT;

	while (nr_sectors) {
		u32 n = min(nr_sectors, chunk);
		size_t len = (size_t)n << SECTOR_SHIFT;
		void __iomem *addr;

		addr = ioremap(pa, len);
		if (!addr)
			return -ENOMEM;
		memset_io(addr, 0, len);
		iounmap(addr);
		pa += len;
		nr_sectors -= n;
	}
	return 0;
}

static int do_io(struct p2p_io_context *io_ctx, struct block_device *bdev, unsigned int nsid,
		 u64 sector, unsigned int sector_nr, u64 paddr)
{
	struct nvme_command cmd = { };
	struct gendisk *disk = bdev->bd_disk;
	struct request_queue *queue = disk->queue;
	struct request *req;

	pr_debug("%s bdev %u:%u nsid %u sector 0x%llx nr_sectors 0x%x pa 0x%llx\n",
		 p2p_io_op_name(io_ctx->op), MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), nsid, sector,
		 sector_nr, paddr);

	cmd.rw.opcode = io_ctx->op == P2P_IO_WRITE ? nvme_cmd_write : nvme_cmd_read;
	cmd.rw.nsid = cpu_to_le32(nsid);
	cmd.rw.slba = cpu_to_le64(sector);
	cmd.rw.length = cpu_to_le16(sector_nr - 1);
	cmd.rw.control = 0;
	cmd.rw.dsmgmt = 0;

	cmd.rw.dptr.sgl.addr = cpu_to_le64(paddr);
	cmd.rw.dptr.sgl.length = cpu_to_le32(sector_nr << SECTOR_SHIFT);
	cmd.rw.dptr.sgl.type = NVME_SGL_FMT_DATA_DESC << 4;

	req = p2p_alloc_nvme_request(queue, &cmd);
	if (IS_ERR(req)) {
		pr_err("%s failed to allocate request: %ld\n", p2p_io_op_name(io_ctx->op),
		       PTR_ERR(req));
		return PTR_ERR(req);
	}

	req->end_io_data = io_ctx;
	req->end_io = p2p_end_io;
	atomic_inc(&io_ctx->io_ref);
	p2p_stats_io_issued(io_ctx->op, (u64)sector_nr << SECTOR_SHIFT);

	p2p_execute_rq_nowait(req, disk);

	return 0;
}

static int do_ios(struct p2p_io_context *io_ctx, struct topo *topo,
		  struct fiemap_extent *extents, unsigned int nr)
{
	struct p2p_iov_iter iter;
	struct blk_plug plug;
	unsigned int i;
	int err = 0;

	p2p_iov_iter_init(&iter, io_ctx->pa_iov, io_ctx->pa_iov_nr, io_ctx->data_size);
	blk_start_plug(&plug);

	for (i = 0; i < nr && p2p_iov_iter_count(&iter); i++) {
		u64 sector = extents[i].fe_physical >> SECTOR_SHIFT;
		/* The current use case limits each extent to less than 2 TiB. */
		u32 left = extents[i].fe_length >> SECTOR_SHIFT;
		unsigned int to_submit;

		pr_debug("%s ext %u sec 0x%llx+0x%x cnt 0x%llx off 0x%llx cur 0x%llx+0x%llx nr %u\n",
			 p2p_io_op_name(io_ctx->op), i, sector, left, iter.count, iter.iov_offset,
			 iter.iov->addr, iter.iov->len, iter.nr_segs);

		while (left && p2p_iov_iter_count(&iter)) {
			struct topo_bdev *topo_bdev;
			struct block_device *to_bdev;
			u64 to_sector;
			u32 topo_limit = left;
			u32 disk_nr = left;
			u32 zero_nr = 0;

			if (io_ctx->op == P2P_IO_READ) {
				err = topo_loop_read_span(topo, sector, left,
							  &disk_nr, &zero_nr);
				if (err)
					goto out;
				if (zero_nr) {
					to_submit = min_t(u32, zero_nr,
							  p2p_iov_iter_single_seg_sectors(&iter));
					if (!to_submit) {
						pr_err("zero %s ext %u sectors 0x%x iov bytes 0x%llx\n",
						       p2p_io_op_name(io_ctx->op), i, left,
						       p2p_iov_iter_count(&iter));
						err = -EINVAL;
						goto out;
					}
					err = p2p_zero_pa(p2p_iov_iter_addr(&iter),
							  to_submit);
					if (err)
						goto out;
					sector += to_submit;
					left -= to_submit;
					p2p_iov_iter_advance(&iter,
							     (u64)to_submit << SECTOR_SHIFT);
					continue;
				}
				if (!disk_nr) {
					err = -EIO;
					goto out;
				}
				topo_limit = disk_nr;
			}

			err = topo->ops->map_sector(topo, sector, topo_limit,
						     &topo_bdev, &to_sector,
						     &topo_limit);
			if (err)
				goto out;
			to_bdev = p2p_handle_to_bdev(topo_bdev->handle);

			to_submit = min3(topo_limit, p2p_queue_max_sectors(to_bdev),
					 p2p_iov_iter_single_seg_sectors(&iter));
			if (!to_submit) {
				pr_err("zero %s ext %u sectors 0x%x iov bytes 0x%llx\n",
				       p2p_io_op_name(io_ctx->op), i, left,
				       p2p_iov_iter_count(&iter));
				err = -EINVAL;
				goto out;
			}
			if (io_ctx->op == P2P_IO_WRITE) {
				err = topo_loop_prepare_write(topo, sector, to_submit);
				if (err)
					goto out;
			}
			err = do_io(io_ctx, to_bdev, topo_bdev->nsid, to_sector, to_submit,
				    p2p_iov_iter_addr(&iter));
			if (err)
				goto out;
			if (io_ctx->op == P2P_IO_WRITE)
				topo_loop_mark_written(topo, sector, to_submit);
			sector += to_submit;
			left -= to_submit;

			p2p_iov_iter_advance(&iter, (u64)to_submit << SECTOR_SHIFT);
		}
	}
	if (p2p_iov_iter_count(&iter)) {
		pr_err("%s extents leave 0x%llx IOV bytes unprocessed\n",
		       p2p_io_op_name(io_ctx->op), p2p_iov_iter_count(&iter));
		err = -EINVAL;
	}

out:
	blk_finish_plug(&plug);
	return err;
}

#ifdef CALC_CRC32
static void dump_io_ctx_crc32(const struct p2p_io_context *io_ctx)
{
	u32 crc = ~0U;
	unsigned int i;
	void *buffer;

	/*
	 * Logical-I/O finalization observed every NVMe DMA completion before
	 * this helper. Order the following CPU reads after those completions.
	 */
	dma_rmb();

	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer)
		return;

	for (i = 0; i < io_ctx->pa_iov_nr; i++) {
		const struct p2p_pa_iov *iov = &io_ctx->pa_iov[i];
		void __iomem *addr;
		u64 offset = 0;

		addr = ioremap(iov->addr, iov->len);
		if (!addr) {
			pr_err("crc32 failed file=%pD length=0x%llx err=%d\n",
			       io_ctx->file, io_ctx->data_size, -ENOMEM);
			kfree(buffer);
			return;
		}

		while (offset < iov->len) {
			size_t chunk = min_t(u64, iov->len - offset, PAGE_SIZE);

			memcpy_fromio(buffer, addr + offset, chunk);
			crc = crc32_le(crc, buffer, chunk);
			offset += chunk;
		}
		iounmap(addr);
	}

	kfree(buffer);
	crc ^= ~0U;
	pr_info("crc32 file=%pD length=0x%llx crc32=0x%08x\n",
		io_ctx->file, io_ctx->data_size, crc);
}
#else
static inline void dump_io_ctx_crc32(const struct p2p_io_context *io_ctx)
{
}
#endif

#if defined(CALC_CRC32) || defined(DUMP_CONTENT)
static void p2p_finalize_io_work(struct work_struct *work)
{
	struct p2p_io_context *io_ctx =
		container_of(work, struct p2p_io_context, finalize_work);

	dump_io_ctx_crc32(io_ctx);
	dump_pa_content(io_ctx->pa_iov[0].addr,
			min_t(u64, io_ctx->data_size, io_ctx->pa_iov[0].len));
	/*
	 * Registered unpin here (process context). One-shot stays pinned until
	 * retire; pinned_mem itself is an embedded field and remains valid.
	 */
	if (io_ctx->pinned_mem.reg_mem)
		p2p_unpin_io_mem(&io_ctx->pinned_mem);
	p2p_publish_io_done(io_ctx);
}
#endif

static int p2p_io_ctx_errno(const struct p2p_io_context *io_ctx)
{
	int err = io_ctx->issue_err;
	int io_err = io_ctx->io_err;

	if (io_err && !err)
		err = blk_status_to_errno(io_err);
	return err;
}

static void p2p_io_ctx_put(struct p2p_io_context *io_ctx)
{
	if (!atomic_dec_and_test(&io_ctx->io_ref))
		return;

#if defined(CALC_CRC32) || defined(DUMP_CONTENT)
	if (io_ctx->op == P2P_IO_READ && !io_ctx->issue_err && !io_ctx->io_err) {
		schedule_work(&io_ctx->finalize_work);
		return;
	}
#endif

	/*
	 * Registered: drop the percpu_ref on the completion path (safe).
	 * One-shot: leave pinned until p2p_retire_cq_head so
	 * hal_kernel_p2p_put_pages never runs in softirq.
	 */
	if (io_ctx->pinned_mem.reg_mem)
		p2p_unpin_io_mem(&io_ctx->pinned_mem);

	/* Log once per io_ctx when NVMe completion carried a blk error. */
	if (io_ctx->io_err && !io_ctx->issue_err)
		pr_err("I/O error status %d errno %d\n", io_ctx->io_err,
		       blk_status_to_errno(io_ctx->io_err));

	p2p_publish_io_done(io_ctx);
}

static int validate_io_data(const struct p2p_iov *iov, unsigned int iov_nr,
			    const struct fiemap_extent *extents, unsigned int ext_nr,
			    u64 *data_size)
{
	u64 extent_size = 0;
	u64 iov_size = 0;
	unsigned int i;

	for (i = 0; i < iov_nr; i++) {
		u64 end;

		if (!iov[i].size || iov[i].size > P2P_MAX_IOV_SIZE || iov[i].reserved ||
		    ((iov[i].addr | iov[i].size) & (SECTOR_SIZE - 1)) ||
		    check_add_overflow((u64)iov[i].addr, (u64)iov[i].size, &end) ||
		    check_add_overflow(iov_size, (u64)iov[i].size, &iov_size))
			return -EINVAL;
	}

	for (i = 0; i < ext_nr; i++) {
		u64 end;

		if (!extents[i].fe_length || extents[i].fe_length > P2P_MAX_EXTENT_SIZE ||
		    ((extents[i].fe_physical | extents[i].fe_length) & (SECTOR_SIZE - 1)) ||
		    check_add_overflow(extents[i].fe_physical, extents[i].fe_length, &end) ||
		    check_add_overflow(extent_size, extents[i].fe_length, &extent_size))
			return -EINVAL;
	}

	if (extent_size < iov_size)
		return -E2BIG;
	*data_size = iov_size;
	return 0;
}

static struct block_device *p2p_bdev_from_file(struct file *file, u32 op)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb;

	if (op == P2P_IO_WRITE) {
		if (!S_ISBLK(inode->i_mode) && !S_ISREG(inode->i_mode))
			return ERR_PTR(-EINVAL);
		if (!(file->f_mode & FMODE_WRITE))
			return ERR_PTR(-EBADF);
	} else if (!(file->f_mode & FMODE_READ)) {
		return ERR_PTR(-EBADF);
	}

	if (S_ISBLK(inode->i_mode))
		return I_BDEV(file->f_mapping->host);

	if (!S_ISREG(inode->i_mode))
		return ERR_PTR(-EINVAL);

	sb = inode->i_sb;
	if (!sb || !sb->s_bdev)
		return ERR_PTR(-EOPNOTSUPP);

	return sb->s_bdev;
}

static int validate_io_param(const struct p2p_io_param *param)
{
	if (param->op != P2P_IO_READ && param->op != P2P_IO_WRITE)
		return -EINVAL;
	if (param->flags & ~P2P_IO_F_MASK)
		return -EOPNOTSUPP;
	if (!param->iov_nr || param->iov_nr > P2P_MAX_IOV ||
	    !param->ext_nr || param->ext_nr > P2P_MAX_EXTENTS)
		return -EINVAL;
	if (param->mem_reserved || param->reserved[0] || param->reserved[1] ||
	    param->reserved[2])
		return -EINVAL;
	if (param->flags & P2P_IO_F_REGISTERED_MEM) {
		if (param->host_pid)
			return -EINVAL;
		if (param->mem_fd < 0)
			return -EBADF;
	}

	return 0;
}

static int validate_io_extents(const struct p2p_io_param *param,
			       const struct fiemap_extent *extents, struct block_device *bdev,
			       struct file *file)
{
	u64 capacity_sectors;
	u64 next = extents[0].fe_logical;
	bool regular = S_ISREG(file_inode(file)->i_mode);
	unsigned int i;

	capacity_sectors = p2p_bdev_nr_sectors(bdev);
	for (i = 0; i < param->ext_nr; i++) {
		const struct fiemap_extent *extent = &extents[i];
		u64 start_sector = extent->fe_physical >> SECTOR_SHIFT;
		u64 length_sectors = extent->fe_length >> SECTOR_SHIFT;

		if ((extent->fe_flags & ~P2P_FIEMAP_SUPPORTED_FLAGS) ||
		    (param->op == P2P_IO_WRITE && (extent->fe_flags & FIEMAP_EXTENT_SHARED)))
			return -EOPNOTSUPP;
		if (regular &&
		    ((extent->fe_logical & (SECTOR_SIZE - 1)) || extent->fe_logical != next ||
		     check_add_overflow(next, extent->fe_length, &next) || next > S64_MAX))
			return -EINVAL;
		if (param->op == P2P_IO_WRITE && (start_sector > capacity_sectors ||
						  length_sectors > capacity_sectors - start_sector))
			return -EFBIG;
	}

	return 0;
}

static int p2p_copy_iov_extents(const struct p2p_io_param *param, struct p2p_iov **iov_out,
				struct fiemap_extent **extents_out)
{
	struct p2p_iov *iov;
	struct fiemap_extent *extents;
	int err = 0;

	if (!param->extents)
		return -EINVAL;

	iov = kvmalloc_array(param->iov_nr, sizeof(*iov), GFP_KERNEL);
	if (!iov)
		return -ENOMEM;
	if (copy_from_user(iov, u64_to_user_ptr(param->iov),
			   array_size(param->iov_nr, sizeof(*iov)))) {
		err = -EFAULT;
		goto free_iov;
	}

	extents = kvmalloc_array(param->ext_nr, sizeof(*extents), GFP_KERNEL);
	if (!extents) {
		err = -ENOMEM;
		goto free_iov;
	}
	if (copy_from_user(extents, u64_to_user_ptr(param->extents),
			   array_size(param->ext_nr, sizeof(*extents)))) {
		err = -EFAULT;
		goto free_extents;
	}

	*iov_out = iov;
	*extents_out = extents;
	return 0;

free_extents:
	kvfree(extents);
free_iov:
	kvfree(iov);
	return err;
}

static int p2p_submit_one(struct p2p_batch *batch, const struct p2p_io_param *param)
{
	struct p2p_pa_iov *pa_iov = NULL;
	struct fiemap_extent *extents = NULL;
	struct p2p_iov *iov = NULL;
	struct file *reg_file = NULL;
	struct block_device *bdev;
	struct p2p_io_context *io_ctx;
	struct p2p_pinned_io_mem pinned_mem;
	struct topo *topo = NULL;
	u64 data_size;
	unsigned int pa_iov_nr;
	int err;

	err = validate_io_param(param);
	if (err)
		return err;

	err = p2p_copy_iov_extents(param, &iov, &extents);
	if (err)
		return err;

	/* Validate payload before open/topo so rejection errno stays stable. */
	err = validate_io_data(iov, param->iov_nr, extents, param->ext_nr, &data_size);
	if (err)
		goto free_bufs;

	reg_file = fget(param->file_fd);
	if (!reg_file) {
		err = -EBADF;
		goto free_bufs;
	}
	bdev = p2p_bdev_from_file(reg_file, param->op);
	if (IS_ERR(bdev)) {
		err = PTR_ERR(bdev);
		goto put_reg_file;
	}
	err = validate_io_extents(param, extents, bdev, reg_file);
	if (err)
		goto put_reg_file;
	topo = topo_get(bdev);
	if (IS_ERR(topo)) {
		err = PTR_ERR(topo);
		goto put_reg_file;
	}
	if (!topo) {
		pr_err_ratelimited("topology for bdev %u:%u is not registered\n",
				   MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
		err = -ENODEV;
		goto put_reg_file;
	}

	if (param->flags & P2P_IO_F_REGISTERED_MEM)
		err = get_registered_pa_iov(param->mem_fd, iov, param->iov_nr, data_size,
					    &pa_iov, &pa_iov_nr, &pinned_mem);
	else
		err = get_pa_iov(iov, param->iov_nr, &pa_iov, &pa_iov_nr,
				 &pinned_mem);
	if (err)
		goto put_topo;

	io_ctx = new_io_ctx(param->op, reg_file, pa_iov, pa_iov_nr, &pinned_mem,
			    data_size, param->user_data);
	if (IS_ERR(io_ctx)) {
		err = PTR_ERR(io_ctx);
		goto free_pa_iov;
	}
	reg_file = NULL;
	pa_iov = NULL;

	io_ctx->batch = batch;
	if (atomic_inc_return(&batch->io_cnt) > P2P_CQ_SIZE) {
		if (atomic_dec_and_test(&batch->io_cnt))
			p2p_wake_batch_waiters(batch);
		free_io_ctx(io_ctx);
		err = -EAGAIN;
		goto free_pa_iov;
	}
	atomic_inc(&batch->outstanding_events);

	io_ctx->issue_err = do_ios(io_ctx, topo, extents, param->ext_nr);
	if (io_ctx->issue_err)
		p2p_stats_io_issue_failed(io_ctx->op);
	p2p_io_ctx_put(io_ctx);
	err = 0;

free_pa_iov:
	p2p_unpin_io_mem(&pinned_mem);
	kvfree(pa_iov);
put_topo:
	topo_put(topo);
put_reg_file:
	if (reg_file)
		fput(reg_file);
free_bufs:
	kvfree(extents);
	kvfree(iov);
	return err;
}

static int p2p_submit_io(struct p2p_batch *batch, void __user *arg)
{
	struct p2p_io_batch_param param;
	struct p2p_io_param *items;
	unsigned int accepted = 0;
	unsigned int i;
	int err;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	/* Every accepted item needs one slot in this fd's completion queue. */
	if (!param.nr || param.nr > P2P_MAX_IO_NR || param.reserved)
		return -EINVAL;

	items = kvmalloc_array(param.nr, sizeof(*items), GFP_KERNEL);
	if (!items)
		return -ENOMEM;
	if (copy_from_user(items, u64_to_user_ptr(param.items),
			   array_size(param.nr, sizeof(*items)))) {
		err = -EFAULT;
		goto out;
	}

	for (i = 0; i < param.nr; i++) {
		err = p2p_submit_one(batch, &items[i]);
		if (err)
			goto out;
		accepted++;
	}
	err = accepted;
out:
	kvfree(items);
	return accepted ? accepted : err;
}

/*
 * Pop the CQ head slot and free its io_ctx. Caller holds ring_lock and must
 * have finished delivering (or discarding) the slot's single logical event.
 * Counts for remaining events were already adjusted by the caller.
 */
static void p2p_retire_cq_head(struct p2p_batch *batch, int *first_err)
{
	struct p2p_io_context *io_ctx;
	int err;

	/* Pairs with the producer's smp_wmb() before cq_tail. */
	smp_rmb();
	io_ctx = batch->cq[batch->cq_head & P2P_CQ_MASK];
	WRITE_ONCE(batch->cq_head, batch->cq_head + 1);

	err = p2p_io_ctx_errno(io_ctx);
	if (first_err && err && !*first_err)
		*first_err = err;

	/* Publisher's complete() is its final field access before unpin. */
	wait_for_completion(&io_ctx->io_done);
	/* Publish cq_head before returning its CQ slot to submitters. */
	smp_mb__before_atomic();
	atomic_dec(&batch->io_cnt);
	free_io_ctx(io_ctx);
}

/*
 * Drain waits for every accepted I/O to publish naturally, then harvests the
 * CQ under ring_lock (same consumer lock as getevents). No on_batch / steal:
 * publish always lands on the ring.
 */
static int p2p_drain_io(struct p2p_batch *batch)
{
	int first_err = 0;

	mutex_lock(&batch->ring_lock);
	while (atomic_read(&batch->io_cnt)) {
		/*
		 * Sleep with ring_lock held so getevents cannot interleave.
		 * Publish only takes completion_lock, so it can still wake us.
		 */
		wait_event(batch->wait,
			   batch->cq_head != READ_ONCE(batch->cq_tail) ||
			   !atomic_read(&batch->io_cnt));

		while (batch->cq_head != READ_ONCE(batch->cq_tail)) {
			atomic_dec(&batch->ready_events);
			atomic_dec(&batch->outstanding_events);
			p2p_wake_batch_waiters(batch);
			p2p_retire_cq_head(batch, &first_err);
		}
	}
	mutex_unlock(&batch->ring_lock);

	return first_err;
}

static void p2p_fill_io_event(struct p2p_io_context *io_ctx, struct p2p_io_event *out)
{
	int err = p2p_io_ctx_errno(io_ctx);

	out->user_data = io_ctx->user_data;
	out->res = err ? err : 0;
	out->reserved[0] = 0;
	out->reserved[1] = 0;
	out->reserved[2] = 0;
	out->reserved[3] = 0;
}

static bool p2p_cq_ready(struct p2p_batch *batch, unsigned int min_nr)
{
	unsigned int ready = atomic_read(&batch->ready_events);
	unsigned int outstanding = atomic_read(&batch->outstanding_events);

	return ready >= min_nr || ready == outstanding;
}

/*
 * AIO-style getevents: wait on ready logical I/Os, harvest under the
 * ring_lock mutex only, copy one event at a time (no kvmalloc intermediate).
 * Each CQ slot is one logical I/O / one event. On copy_to_user fault the slot
 * stays at head for the next call.
 */
static int p2p_get_io_events(struct p2p_batch *batch, void __user *arg)
{
	struct p2p_getevents_param param;
	struct p2p_io_event __user *user_events;
	struct p2p_io_context *io_ctx;
	struct p2p_io_event event;
	unsigned int total = 0;
	int ret = 0;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	if (param.min_nr < 0 || param.max_nr <= 0 ||
	    param.min_nr > param.max_nr || !param.events)
		return -EINVAL;

	user_events = u64_to_user_ptr(param.events);

	if (param.timeout_ns) {
		ktime_t until = param.timeout_ns < 0 ? KTIME_MAX :
				    ns_to_ktime(param.timeout_ns);

		ret = wait_event_interruptible_hrtimeout(
			batch->wait, p2p_cq_ready(batch, param.min_nr), until);
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		else if (ret == -ETIME)
			ret = 0;
		/* Fall through and harvest whatever is already on the CQ. */
	}

	mutex_lock(&batch->ring_lock);
	while (total < (unsigned int)param.max_nr) {
		if (batch->cq_head == READ_ONCE(batch->cq_tail))
			break;
		/* Pairs with the producer's smp_wmb() before cq_tail. */
		smp_rmb();
		io_ctx = batch->cq[batch->cq_head & P2P_CQ_MASK];

		p2p_fill_io_event(io_ctx, &event);
		if (copy_to_user(&user_events[total], &event, sizeof(event))) {
			ret = -EFAULT;
			break;
		}
		total++;
		p2p_retire_cq_head(batch, NULL);
	}

	/*
	 * Single consumer under ring_lock: one atomic_sub for all successfully
	 * copied events instead of a per-event atomic_dec.
	 */
	if (total) {
		atomic_sub(total, &batch->ready_events);
		atomic_sub(total, &batch->outstanding_events);
		p2p_wake_batch_waiters(batch);
	}
	mutex_unlock(&batch->ring_lock);

	if (total)
		return (int)total;
	return ret;
}

static int p2p_add_topo(struct p2p_batch *batch, void __user *arg)
{
	struct topo_user_cfg header;
	struct topo_user_cfg *cfg;
	size_t extent_size = 0;
	size_t size;
	int err;

	if (copy_from_user(&header, arg, sizeof(header)))
		return -EFAULT;
	if (!header.nr_devs) {
		pr_info("add topo err 1\n");
		return -EINVAL;
	}
	if (header.nr_devs > P2P_TOPO_MAX_BDEVS)
		return -E2BIG;
	if (!memchr(header.name, '\0', sizeof(header.name))) {
		pr_info("add topo err 2\n");
		return -EINVAL;
	}
	if (!strcmp(header.name, "loop")) {
		if (!header.extra[0]) {
			pr_info("add topo err 3\n");
			return -EINVAL;
		}
		if (header.extra[0] > P2P_TOPO_MAX_EXTENTS)
			return -E2BIG;
		if (header.extra[1] > 32 ||
		    check_mul_overflow((size_t)header.extra[0],
				       sizeof(struct topo_user_extent),
				       &extent_size)) {
			pr_info("add topo err 4\n");
			return -EINVAL;
		}
	}
	size = sizeof(header) +
	       header.nr_devs * sizeof(header.bdevs[0]);
	if (check_add_overflow(size, extent_size, &size)) {
		pr_info("add topo err 5\n");
		return -EINVAL;
	}

	cfg = memdup_user(arg, size);
	if (IS_ERR(cfg)) {
		pr_info("add topo err 6\n");
		return PTR_ERR(cfg);
	}
	if (cfg->nr_devs != header.nr_devs ||
	    memcmp(cfg->name, header.name, sizeof(cfg->name)) ||
	    cfg->extra[0] != header.extra[0] ||
	    cfg->extra[1] != header.extra[1]) {
		kfree(cfg);
		pr_info("add topo err 7\n");
		return -EINVAL;
	}

	err = topo_add(cfg, &batch->shared_topos);
	if (err)
		pr_info("add topo err 8\n");
	kfree(cfg);
	return err;
}

static int p2p_del_topo(struct p2p_batch *batch, void __user *arg)
{
	struct topo_del_cfg param;
	struct shared_topo *shared;
	struct topo *topo = NULL;
	dev_t top_dev;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	if (param.reserved)
		return -EINVAL;

	top_dev = new_decode_dev(param.top_dev);
	spin_lock(&batch->shared_topos.lock);
	list_for_each_entry(shared, &batch->shared_topos.head, list) {
		if (shared->topo->top_dev != top_dev)
			continue;
		list_del(&shared->list);
		topo = shared->topo;
		break;
	}
	spin_unlock(&batch->shared_topos.lock);
	if (!topo)
		return -ENOENT;

	topo_del(topo);
	kfree(shared);
	return 0;
}

static int p2p_get_info(void __user *arg)
{
	const struct p2p_device_info info = { .version = P2P_UAPI_VERSION };

	return copy_to_user(arg, &info, sizeof(info)) ? -EFAULT : 0;
}

static long p2p_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct p2p_batch *batch = file->private_data;
	int err = 0;

	switch (cmd) {
	case IOCTL_GET_INFO:
		err = p2p_get_info((void __user *)arg);
		break;
	case IOCTL_SUBMIT_IO:
		err = p2p_submit_io(batch, (void __user *)arg);
		break;
	case IOCTL_DRAIN_IO:
		err = p2p_drain_io(batch);
		break;
	case IOCTL_ADD_TOPO:
		err = p2p_add_topo(batch, (void __user *)arg);
		break;
	case IOCTL_DEL_TOPO:
		err = p2p_del_topo(batch, (void __user *)arg);
		break;
	case IOCTL_REGISTER_MEM:
		err = p2p_register_mem(batch, (void __user *)arg);
		break;
	case IOCTL_UNREGISTER_MEM:
		err = p2p_unregister_mem(batch, (void __user *)arg);
		break;
	case IOCTL_GET_IO_EVENTS:
		err = p2p_get_io_events(batch, (void __user *)arg);
		break;
	default:
		pr_info("invalid ioctl command 0x%x\n", cmd);
		err = -EINVAL;
		break;
	}
	return err;
}

static int __init p2p_drv_init(void)
{
	struct device *device;
	int err;

	err = p2p_mem_init();
	if (err)
		return err;

	p2p_mem_wq = alloc_workqueue("p2p_mem", WQ_UNBOUND, 0);
	if (!p2p_mem_wq) {
		pr_err("initialize memory release workqueue failed\n");
		err = -ENOMEM;
		goto exit_mem;
	}

	err = topo_init();
	if (err) {
		pr_err("initialize topology release workqueue err %d\n", err);
		goto exit_mem_wq;
	}

	err = p2p_tp_hook_init();
	if (err) {
		pr_err("register tp hook err %d\n", err);
		goto exit_topo;
	}

	p2p_debugfs_init();

	err = alloc_chrdev_region(&dev, 0, 1, "p2p_device");
	if (err < 0) {
		pr_err("allocate major number err %d\n", err);
		goto exit_debugfs;
	}

	pr_info("major = %d minor = %d\n", MAJOR(dev), MINOR(dev));
	cdev_init(&p2p_cdev, &dev_p2p_fops);

	err = cdev_add(&p2p_cdev, dev, 1);
	if (err < 0) {
		pr_err("add the device to the system err %d\n", err);
		goto free_dev;
	}

	dev_class = p2p_class_create("p2p_class");
	if (IS_ERR(dev_class)) {
		err = PTR_ERR(dev_class);
		pr_err("create class err %d\n", err);
		goto del_cdev;
	}

	device = device_create(dev_class, NULL, dev, NULL, "p2p_device");
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		pr_err("create device err %d\n", err);
		goto del_cls;
	}

	pr_info("driver inserted done, uapi v%u.%u\n",
		P2P_UAPI_VERSION_MAJOR, P2P_UAPI_VERSION_MINOR);
	return 0;

del_cls:
	class_destroy(dev_class);
del_cdev:
	cdev_del(&p2p_cdev);
free_dev:
	unregister_chrdev_region(dev, 1);
exit_debugfs:
	p2p_debugfs_exit();
	p2p_tp_hook_exit();
exit_topo:
	topo_exit();
exit_mem_wq:
	destroy_workqueue(p2p_mem_wq);
exit_mem:
	p2p_mem_exit();
	return err;
}

static void __exit p2p_drv_exit(void)
{
	p2p_debugfs_exit();
	device_destroy(dev_class, dev);
	class_destroy(dev_class);
	cdev_del(&p2p_cdev);
	unregister_chrdev_region(dev, 1);
	p2p_tp_hook_exit();
	WARN_ON_ONCE(!list_empty(&p2p_mem_table_list));
	/*
	 * Drain percpu_ref_kill RCU callbacks (which queue release_work onto
	 * p2p_mem_wq) and topology RCU callbacks, then flush/destroy
	 * p2p_mem_wq, then drain call_rcu(&tbl->rcu) frees.
	 */
	rcu_barrier();
	destroy_workqueue(p2p_mem_wq);
	rcu_barrier();
	topo_exit();
	p2p_mem_exit();
	pr_info("driver removed done\n");
}

module_init(p2p_drv_init);
module_exit(p2p_drv_exit);
MODULE_DESCRIPTION("XDS NVMe peer-to-peer I/O driver");
MODULE_LICENSE("GPL");
