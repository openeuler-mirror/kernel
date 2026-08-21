// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "p2p: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
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
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
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

#define P2P_NVME_MAX_RW_SECTORS ((1U << 20) >> SECTOR_SHIFT)
#define P2P_MAX_IOV 65536U
#define P2P_MAX_EXTENTS 1048576U
#define P2P_MAX_IOV_SIZE (2U << 30)
#define P2P_MAX_EXTENT_SIZE ((u64)U32_MAX << SECTOR_SHIFT)
#define P2P_MIN_PAGE_SIZE (64U << 10)
#define P2P_MEM_COOKIE_SHIFT 48
#define P2P_MEM_ID_MASK GENMASK_ULL(P2P_MEM_COOKIE_SHIFT - 1, 0)
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
	u64 *pa_list;
	u32 page_size;
	u32 page_size_shift;
	u32 pa_num;
};

struct p2p_pinned_pa {
	struct devmm_svm_process_id process_id;
	struct p2p_iov_map *maps;
	unsigned int pinned_map_nr;
	u64 *pa_list;
};

struct p2p_batch;

struct p2p_registered_mem {
	u64 handle;
	u64 addr;
	u64 size;
	struct p2p_pinned_pa *pinned_pa;
	struct p2p_batch *owner;
	struct pid *owner_tgid;

	struct percpu_ref io_refs;
	struct completion io_zero;
	struct rcu_head rcu;
	struct list_head owner_node;
};

struct p2p_pinned_io_mem {
	bool pinned;
	bool reg_mem;
	union {
		struct p2p_pinned_pa *pinned_pa;
		struct p2p_registered_mem *registered_mem;
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
	struct list_head owned_mems;
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

static DEFINE_XARRAY(registered_mems);
static DEFINE_MUTEX(registered_mem_lock);
static atomic64_t registered_mem_id = ATOMIC64_INIT(0);

static int p2p_open(struct inode *inode, struct file *file);
static int p2p_release(struct inode *inode, struct file *file);
static long p2p_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int p2p_drain_io(struct p2p_batch *batch);
static void p2p_tp_hook_exit(void);
static void p2p_revoke_all_registered_mem(struct p2p_batch *batch,
					  struct list_head *revoked);
static void p2p_destroy_registered_mem_list(struct list_head *revoked);
static void p2p_io_ctx_put(struct p2p_io_context *io_ctx);
static void p2p_publish_io_done(struct p2p_io_context *io_ctx);
#if defined(CALC_CRC32) || defined(DUMP_CONTENT)
static void p2p_finalize_io_work(struct work_struct *work);
#endif

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = p2p_open,
	.release = p2p_release,
	.unlocked_ioctl = p2p_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

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
	INIT_LIST_HEAD(&batch->owned_mems);
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
	LIST_HEAD(revoked_mems);

	p2p_revoke_all_registered_mem(batch, &revoked_mems);

	if (atomic_read(&batch->io_cnt) > 0)
		p2p_drain_io(batch);

	p2p_destroy_registered_mem_list(&revoked_mems);

	spin_lock(&batch->shared_topos.lock);
	list_splice_init(&batch->shared_topos.head, &topos);
	spin_unlock(&batch->shared_topos.lock);
	list_for_each_entry_safe(shared, next, &topos, list) {
		list_del(&shared->list);
		topo_del(shared->topo);
		kfree(shared);
	}

	kfree(batch->cq);
	kfree(batch);

	file->private_data = NULL;

	return 0;
}

static void init_process_id(int host_pid, struct devmm_svm_process_id *process_id)
{
	rcu_read_lock();
	process_id->host_pid = pid_nr(find_vpid(host_pid));
	rcu_read_unlock();
}

static void init_current_process_id(struct devmm_svm_process_id *process_id)
{
	process_id->host_pid = task_tgid_nr(current);
}

static void p2p_put_pinned_pa(struct p2p_pinned_pa *pinned_pa)
{
	unsigned int i;

	for (i = 0; i < pinned_pa->pinned_map_nr; i++) {
		struct p2p_iov_map *map = &pinned_pa->maps[i];

		p2p_mem_put_pa_list(&pinned_pa->process_id, map->aligned_addr,
				     map->aligned_size, map->pa_list,
				     map->pa_num);
	}

	kvfree(pinned_pa->pa_list);
	kvfree(pinned_pa->maps);
	kfree(pinned_pa);
}

static void p2p_registered_mem_release(struct percpu_ref *ref)
{
	struct p2p_registered_mem *mem;

	mem = container_of(ref, struct p2p_registered_mem, io_refs);
	pr_debug("registered memory handle 0x%llx released\n", mem->handle);
	complete(&mem->io_zero);
}

static void p2p_free_registered_mem_rcu(struct rcu_head *rcu)
{
	struct p2p_registered_mem *mem;

	mem = container_of(rcu, struct p2p_registered_mem, rcu);
	percpu_ref_exit(&mem->io_refs);
	kfree(mem);
}

static void p2p_destroy_registered_mem(struct p2p_registered_mem *mem)
{
	wait_for_completion(&mem->io_zero);
	p2p_put_pinned_pa(mem->pinned_pa);
	put_pid(mem->owner_tgid);
	call_rcu(&mem->rcu, p2p_free_registered_mem_rcu);
}

static int p2p_pin_registered_pa(u64 addr, u64 size,
				 struct p2p_pinned_pa **pinned_pa_out)
{
	struct p2p_pinned_pa *pinned_pa;
	struct p2p_iov_map *map;
	u64 aligned_end;
	u64 end;
	u64 pa_num;
	int page_size;
	int err;

	if (!size)
		return -EINVAL;
	if (check_add_overflow(addr, size, &end))
		return -EOVERFLOW;

	pinned_pa = kzalloc(sizeof(*pinned_pa), GFP_KERNEL);
	if (!pinned_pa)
		return -ENOMEM;
	init_current_process_id(&pinned_pa->process_id);

	page_size = p2p_mem_get_page_size(&pinned_pa->process_id, addr, size);
	if (page_size < 0) {
		err = page_size;
		goto put_pinned_pa;
	}
	if (page_size < P2P_MIN_PAGE_SIZE || !is_power_of_2(page_size)) {
		pr_err("invalid page size %d for registered range 0x%llx+0x%llx\n",
		       page_size, addr, size);
		err = -EINVAL;
		goto put_pinned_pa;
	}

	if (check_add_overflow(end, (u64)page_size - 1, &aligned_end)) {
		err = -EOVERFLOW;
		goto put_pinned_pa;
	}
	aligned_end &= ~((u64)page_size - 1);

	pinned_pa->maps = kzalloc(sizeof(*pinned_pa->maps), GFP_KERNEL);
	if (!pinned_pa->maps) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}
	map = pinned_pa->maps;
	map->aligned_addr = addr & ~((u64)page_size - 1);
	map->aligned_size = aligned_end - map->aligned_addr;
	map->page_size = page_size;
	map->page_size_shift = ilog2(page_size);
	pa_num = map->aligned_size >> map->page_size_shift;
	if (!pa_num || pa_num > U32_MAX) {
		err = -E2BIG;
		goto put_pinned_pa;
	}
	map->pa_num = pa_num;

	pinned_pa->pa_list = kvmalloc_array(map->pa_num, sizeof(*pinned_pa->pa_list), GFP_KERNEL);
	if (!pinned_pa->pa_list) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}
	map->pa_list = pinned_pa->pa_list;

	err = p2p_mem_get_pa_list(&pinned_pa->process_id, map->aligned_addr,
				  map->aligned_size, map->pa_list, map->pa_num);
	if (err) {
		pr_err("registered PA list addr 0x%llx size 0x%llx num %u err %d\n",
		       map->aligned_addr, map->aligned_size, map->pa_num, err);
		goto put_pinned_pa;
	}
	pinned_pa->pinned_map_nr = 1;

	*pinned_pa_out = pinned_pa;
	return 0;

put_pinned_pa:
	p2p_put_pinned_pa(pinned_pa);
	return err;
}

static u64 p2p_new_registered_mem_handle(void)
{
	u64 id = atomic64_inc_return(&registered_mem_id) & P2P_MEM_ID_MASK;
	u64 cookie = get_random_u32() & U16_MAX;

	return cookie << P2P_MEM_COOKIE_SHIFT | id;
}

static int p2p_publish_registered_mem(struct p2p_batch *batch,
				      struct p2p_registered_mem *mem)
{
	int err;

	mutex_lock(&registered_mem_lock);
	mem->owner = batch;
	err = xa_insert(&registered_mems, mem->handle, mem, GFP_KERNEL);
	if (!err) {
		list_add_tail(&mem->owner_node, &batch->owned_mems);
		percpu_ref_reinit(&mem->io_refs);
	} else {
		pr_err("publish registered memory handle 0x%llx err %d\n", mem->handle, err);
	}
	mutex_unlock(&registered_mem_lock);

	return err;
}

static int p2p_unpublish_registered_mem(struct p2p_batch *batch, u64 handle,
					struct p2p_registered_mem **mem_out)
{
	struct p2p_registered_mem *mem;
	int err = 0;

	mutex_lock(&registered_mem_lock);
	rcu_read_lock();
	mem = xa_load(&registered_mems, handle);
	if (!mem) {
		err = -ENOENT;
		goto unlock_rcu;
	}
	if (mem->owner != batch) {
		pr_err("registered memory handle 0x%llx belongs to another p2p fd\n", handle);
		err = -EPERM;
		goto unlock_rcu;
	}
	if (mem->owner_tgid != task_tgid(current)) {
		pr_err("registered memory handle 0x%llx belongs to another process\n", handle);
		err = -EPERM;
		goto unlock_rcu;
	}
	rcu_read_unlock();

	xa_erase(&registered_mems, handle);
	list_del_init(&mem->owner_node);
	*mem_out = mem;
	mutex_unlock(&registered_mem_lock);
	return 0;

unlock_rcu:
	rcu_read_unlock();
	mutex_unlock(&registered_mem_lock);
	return err;
}

static void p2p_revoke_all_registered_mem(struct p2p_batch *batch,
					  struct list_head *revoked)
{
	struct p2p_registered_mem *mem, *next;

	if (list_empty(&batch->owned_mems))
		return;

	list_for_each_entry_safe(mem, next, &batch->owned_mems, owner_node) {
		xa_erase(&registered_mems, mem->handle);
		list_move_tail(&mem->owner_node, revoked);
		pr_info("unregister memory handle 0x%llx through p2p fd release\n",
			mem->handle);
	}

	list_for_each_entry(mem, revoked, owner_node)
		percpu_ref_kill(&mem->io_refs);
}

static void p2p_destroy_registered_mem_list(struct list_head *revoked)
{
	struct p2p_registered_mem *mem;
	struct p2p_registered_mem *next;

	list_for_each_entry_safe(mem, next, revoked, owner_node) {
		list_del_init(&mem->owner_node);
		p2p_destroy_registered_mem(mem);
	}
}

static int p2p_register_mem(struct p2p_batch *batch, void __user *arg)
{
	struct p2p_mem_register_param __user *user_param = arg;
	struct p2p_mem_register_param param;
	struct p2p_registered_mem *mem;
	int err;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	if (param.reserved)
		return -EINVAL;

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	mem->addr = param.addr;
	mem->size = param.size;
	mem->owner_tgid = get_task_pid(current, PIDTYPE_TGID);
	init_completion(&mem->io_zero);
	INIT_LIST_HEAD(&mem->owner_node);

	err = percpu_ref_init(&mem->io_refs, p2p_registered_mem_release,
			      PERCPU_REF_INIT_DEAD, GFP_KERNEL);
	if (err)
		goto put_owner_tgid;

	err = p2p_pin_registered_pa(mem->addr, mem->size, &mem->pinned_pa);
	if (err)
		goto exit_io_refs;

	mem->handle = p2p_new_registered_mem_handle();
	if (put_user(mem->handle, &user_param->mem_handle)) {
		err = -EFAULT;
		goto put_pinned_pa;
	}

	err = p2p_publish_registered_mem(batch, mem);
	if (err)
		goto put_pinned_pa;

	pr_info("registered memory handle 0x%llx addr 0x%llx size 0x%llx\n",
		mem->handle, mem->addr, mem->size);
	return 0;

put_pinned_pa:
	p2p_put_pinned_pa(mem->pinned_pa);
exit_io_refs:
	percpu_ref_exit(&mem->io_refs);
put_owner_tgid:
	put_pid(mem->owner_tgid);
	kfree(mem);
	return err;
}

static int p2p_unregister_mem(struct p2p_batch *batch, void __user *arg)
{
	struct p2p_mem_unregister_param param;
	struct p2p_registered_mem *mem;
	int err;

	if (copy_from_user(&param, arg, sizeof(param)))
		return -EFAULT;
	if (param.reserved || !param.mem_handle)
		return -EINVAL;

	err = p2p_unpublish_registered_mem(batch, param.mem_handle, &mem);
	if (err) {
		pr_err("unregister memory handle 0x%llx err %d\n", param.mem_handle, err);
		return err;
	}

	percpu_ref_kill(&mem->io_refs);
	p2p_destroy_registered_mem(mem);

	pr_info("unregistered memory handle 0x%llx\n", param.mem_handle);
	return 0;
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

static int get_pa_iov(int host_pid, const struct p2p_iov *iov, unsigned int iov_nr,
		      struct p2p_pa_iov **pa_iov, unsigned int *pa_iov_nr,
		      struct p2p_pinned_io_mem *pinned_mem)
{
	struct p2p_pinned_pa *pinned_pa;
	struct p2p_pa_iov *new_pa_iov;
	struct p2p_iov_map *maps;
	unsigned int new_pa_iov_nr;
	unsigned int new_pa_iov_idx;
	unsigned int i;
	int err;

	pinned_pa = kzalloc(sizeof(*pinned_pa), GFP_KERNEL);
	if (!pinned_pa)
		return -ENOMEM;
	init_process_id(host_pid, &pinned_pa->process_id);
	pinned_pa->maps = kvcalloc(iov_nr, sizeof(*pinned_pa->maps), GFP_KERNEL);
	if (!pinned_pa->maps) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}
	maps = pinned_pa->maps;

	new_pa_iov_nr = 0;
	for (i = 0; i < iov_nr; i++) {
		u32 range_size;
		u32 pa_num;
		u32 offset;
		int page_size;

		page_size = p2p_mem_get_page_size(&pinned_pa->process_id, iov[i].addr, iov[i].size);
		if (page_size < P2P_MIN_PAGE_SIZE || !is_power_of_2(page_size)) {
			pr_err("invalid page size %d for addr 0x%llx, iov %u\n",
			       page_size, iov[i].addr, i);
			err = -EINVAL;
			goto put_pinned_pa;
		}

		offset = iov[i].addr & (page_size - 1);
		range_size = offset + iov[i].size;
		pa_num = DIV_ROUND_UP(range_size, (u32)page_size);
		if (!pa_num || pa_num > UINT_MAX - new_pa_iov_nr) {
			err = -E2BIG;
			goto put_pinned_pa;
		}

		maps[i].aligned_addr = iov[i].addr - offset;
		maps[i].page_size = page_size;
		maps[i].page_size_shift = ilog2(page_size);
		maps[i].pa_num = pa_num;
		maps[i].aligned_size = (u64)pa_num * page_size;
		new_pa_iov_nr += maps[i].pa_num;
	}

	pinned_pa->pa_list = kvmalloc_array(new_pa_iov_nr, sizeof(*pinned_pa->pa_list), GFP_KERNEL);
	if (!pinned_pa->pa_list) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}

	new_pa_iov = kvmalloc_array(new_pa_iov_nr, sizeof(*new_pa_iov), GFP_KERNEL);
	if (!new_pa_iov) {
		err = -ENOMEM;
		goto put_pinned_pa;
	}

	new_pa_iov_idx = 0;
	for (i = 0; i < iov_nr; i++) {
		u32 remaining = iov[i].size;
		u32 offset = iov[i].addr - maps[i].aligned_addr;
		unsigned int j;

		maps[i].pa_list = pinned_pa->pa_list + new_pa_iov_idx;
		err = p2p_mem_get_pa_list(&pinned_pa->process_id,
					  maps[i].aligned_addr,
					  maps[i].aligned_size,
					  maps[i].pa_list, maps[i].pa_num);
		if (err) {
			pr_err("PA list addr 0x%llx size 0x%llx num %u iov %u err %d\n",
			       maps[i].aligned_addr, maps[i].aligned_size,
			       maps[i].pa_num, i, err);
			goto free_pa_iov;
		}
		pinned_pa->pinned_map_nr++;

		for (j = 0; j < maps[i].pa_num; j++) {
			u32 len = min(remaining, maps[i].page_size - offset);

			new_pa_iov[new_pa_iov_idx].addr = maps[i].pa_list[j] + offset;
			new_pa_iov[new_pa_iov_idx].len = len;
			if ((new_pa_iov[new_pa_iov_idx].addr | len) & (SECTOR_SIZE - 1)) {
				pr_err("unaligned PA IOV addr 0x%llx, len 0x%x, iov %u\n",
				       new_pa_iov[new_pa_iov_idx].addr, len, i);
				err = -EINVAL;
				break;
			}
			new_pa_iov_idx++;
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
	*pa_iov_nr = new_pa_iov_nr;
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

static int p2p_get_registered_mem(u64 handle, struct p2p_registered_mem **mem_out)
{
	struct p2p_registered_mem *mem;
	int err;

	rcu_read_lock();
	mem = xa_load(&registered_mems, handle);
	if (!mem) {
		err = -ENOENT;
		goto unlock;
	}
	if (!percpu_ref_tryget_live(&mem->io_refs)) {
		err = -ESTALE;
		goto unlock;
	}
	rcu_read_unlock();
	if (mem->owner_tgid != task_tgid(current)) {
		percpu_ref_put(&mem->io_refs);
		return -EPERM;
	}

	*mem_out = mem;
	return 0;

unlock:
	rcu_read_unlock();
	return err;
}

static int get_registered_pa_iov(u64 handle, const struct p2p_iov *iov, unsigned int iov_nr,
				 struct p2p_pa_iov **pa_iov_out, unsigned int *pa_iov_nr_out,
				 struct p2p_pinned_io_mem *pinned_mem)
{
	struct p2p_registered_mem *mem;
	const struct p2p_iov_map *map;
	struct p2p_pa_iov *pa_iov;
	unsigned int pa_iov_nr = 0;
	unsigned int pa_iov_idx = 0;
	unsigned int i;
	int err;

	err = p2p_get_registered_mem(handle, &mem);
	if (err)
		return err;
	map = &mem->pinned_pa->maps[0];

	for (i = 0; i < iov_nr; i++) {
		u64 map_offset;
		u64 first_page;
		u64 last_page;
		u64 iov_end;
		u64 nr_pages;

		if (iov[i].addr < mem->addr || iov[i].size > mem->size ||
		    iov[i].addr - mem->addr > mem->size - iov[i].size) {
			err = -ERANGE;
			goto put_mem;
		}
		map_offset = iov[i].addr - map->aligned_addr;
		iov_end = map_offset + iov[i].size - 1;
		first_page = map_offset >> map->page_size_shift;
		last_page = iov_end >> map->page_size_shift;
		nr_pages = last_page - first_page + 1;
		if (nr_pages > UINT_MAX - pa_iov_nr) {
			err = -E2BIG;
			goto put_mem;
		}
		pa_iov_nr += nr_pages;
	}

	pa_iov = kvmalloc_array(pa_iov_nr, sizeof(*pa_iov), GFP_KERNEL);
	if (!pa_iov) {
		err = -ENOMEM;
		goto put_mem;
	}

	for (i = 0; i < iov_nr; i++) {
		u64 map_offset = iov[i].addr - map->aligned_addr;
		u64 page_idx = map_offset >> map->page_size_shift;
		u32 page_offset = map_offset & (map->page_size - 1);
		u32 remaining = iov[i].size;

		while (remaining) {
			u32 len = min(remaining, map->page_size - page_offset);
			u64 pa = map->pa_list[page_idx] + page_offset;

			if ((pa | len) & (SECTOR_SIZE - 1)) {
				err = -EINVAL;
				goto free_pa_iov;
			}
			pa_iov[pa_iov_idx].addr = pa;
			pa_iov[pa_iov_idx].len = len;
			pa_iov_idx++;
			remaining -= len;
			page_idx++;
			page_offset = 0;
		}
	}

	*pa_iov_out = pa_iov;
	*pa_iov_nr_out = pa_iov_nr;
	*pinned_mem = (struct p2p_pinned_io_mem) {
		.pinned = true,
		.reg_mem = true,
		.registered_mem = mem,
	};
	return 0;

free_pa_iov:
	kvfree(pa_iov);
put_mem:
	percpu_ref_put(&mem->io_refs);
	return err;
}

static void p2p_unpin_io_mem(struct p2p_pinned_io_mem *pinned_mem)
{
	if (!pinned_mem->pinned)
		return;

	if (pinned_mem->reg_mem)
		percpu_ref_put(&pinned_mem->registered_mem->io_refs);
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
	 * Pair condition stores (ready_events / cq_tail under completion_lock,
	 * then unlock) with waitqueue_active: without this full barrier a
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

	p2p_stats_io_complete(status);
	if (status)
		cmpxchg(&io_ctx->io_err, 0, status);

	p2p_io_ctx_put(io_ctx);
}

static const char *p2p_io_op_name(u32 op)
{
	return op == P2P_IO_WRITE ? "write" : "read";
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
	p2p_stats_io_issued((u64)sector_nr << SECTOR_SHIFT);

	p2p_execute_rq_nowait(req, disk);

	return 0;
}

static int do_ios(struct p2p_io_context *io_ctx, struct topo *topo, struct fiemap_extent *extents,
		  unsigned int nr)
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
			err = do_io(io_ctx, to_bdev, topo_bdev->nsid, to_sector, to_submit,
				    p2p_iov_iter_addr(&iter));
			if (err)
				goto out;
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

	/*
	 * Logical-I/O finalization observed every NVMe DMA completion before
	 * this helper. Order the following CPU reads after those completions.
	 */
	dma_rmb();

	for (i = 0; i < io_ctx->pa_iov_nr; i++) {
		const struct p2p_pa_iov *iov = &io_ctx->pa_iov[i];
		void __iomem *addr;

		addr = ioremap(iov->addr, iov->len);
		if (!addr) {
			pr_err("crc32 failed file=%pD length=0x%llx err=%d\n",
			       io_ctx->file, io_ctx->data_size, -ENOMEM);
			return;
		}

		crc = crc32_le(crc, (__force const unsigned char *)addr,
			       iov->len);
		iounmap(addr);
	}

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
	 * devmm_put_mem_pa_list never runs in softirq.
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
		if (S_ISREG(inode->i_mode))
			return ERR_PTR(-EOPNOTSUPP);
		if (!S_ISBLK(inode->i_mode))
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
	if (param->reserved[0] || param->reserved[1] || param->reserved[2])
		return -EINVAL;
	if (param->flags & P2P_IO_F_REGISTERED_MEM)
		return !param->mem_handle || param->host_pid ? -EINVAL : 0;

	return param->host_pid <= 0 ? -EINVAL : 0;
}

static int validate_write_range(const struct p2p_io_param *param,
				const struct fiemap_extent *extents, struct block_device *bdev)
{
	const struct fiemap_extent *extent;
	u64 capacity_sectors;
	u64 length_sectors;
	u64 start_sector;

	if (param->op != P2P_IO_WRITE)
		return 0;
	if (param->ext_nr != 1)
		return -EINVAL;

	extent = &extents[0];
	start_sector = extent->fe_physical >> SECTOR_SHIFT;
	length_sectors = extent->fe_length >> SECTOR_SHIFT;
	capacity_sectors = p2p_bdev_nr_sectors(bdev);
	if (start_sector > capacity_sectors || length_sectors > capacity_sectors - start_sector)
		return -EFBIG;

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
	err = validate_write_range(param, extents, bdev);
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
		err = get_registered_pa_iov(param->mem_handle, iov, param->iov_nr, &pa_iov,
					    &pa_iov_nr, &pinned_mem);
	else
		err = get_pa_iov(param->host_pid, iov, param->iov_nr, &pa_iov, &pa_iov_nr,
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
		p2p_stats_io_issue_failed();
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
	size_t size;
	int err;

	if (copy_from_user(&header, arg, sizeof(header)))
		return -EFAULT;
	if (!header.nr_devs)
		return -EINVAL;
	if (header.nr_devs > P2P_TOPO_MAX_BDEVS)
		return -E2BIG;
	size = sizeof(header) +
	       header.nr_devs * sizeof(header.bdevs[0]);

	cfg = memdup_user(arg, size);
	if (IS_ERR(cfg))
		return PTR_ERR(cfg);
	if (cfg->nr_devs != header.nr_devs) {
		kfree(cfg);
		return -EINVAL;
	}

	err = topo_add(cfg, &batch->shared_topos);
	kfree(cfg);
	return err;
}

static long p2p_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct p2p_batch *batch = file->private_data;
	int err = 0;

	switch (cmd) {
	case IOCTL_SUBMIT_IO:
		err = p2p_submit_io(batch, (void __user *)arg);
		break;
	case IOCTL_DRAIN_IO:
		err = p2p_drain_io(batch);
		break;
	case IOCTL_ADD_TOPO:
		err = p2p_add_topo(batch, (void __user *)arg);
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

	err = topo_init();
	if (err) {
		pr_err("initialize topology release workqueue err %d\n", err);
		goto exit_mem;
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
	cdev_init(&p2p_cdev, &fops);

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

	pr_info("driver inserted done\n");
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
	WARN_ON_ONCE(!xa_empty(&registered_mems));
	xa_destroy(&registered_mems);
	/*
	 * Drain registered-memory RCU frees and queue all topology release work
	 * before topo_exit() flushes and destroys the topology workqueue.
	 */
	rcu_barrier();
	topo_exit();
	p2p_mem_exit();
	pr_info("driver removed done\n");
}

module_init(p2p_drv_init);
module_exit(p2p_drv_exit);
MODULE_DESCRIPTION("XDS NVMe peer-to-peer I/O driver");
MODULE_LICENSE("GPL");
