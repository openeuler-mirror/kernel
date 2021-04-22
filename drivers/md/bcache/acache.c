// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/circ_buf.h>
#include <linux/list.h>

#include "acache.h"
#include "request.h"

#include <trace/events/bcache.h>

#define DEV_NAME "acache"

int acache_dev_size = (1024 * 4096 + 4096);

module_param_named(acache_size, acache_dev_size, int, 0444);
MODULE_PARM_DESC(acache_size, "size of ring buffer for size in byte");

int acache_prefetch_workers = 1000;

module_param_named(prefetch_workers, acache_prefetch_workers, int, 0444);
MODULE_PARM_DESC(prefetch_workers, "num of workers for processing prefetch requests");

struct inflight_list_head {
	struct list_head entry;
	spinlock_t io_lock;
	bool initialized;
};

struct prefetch_worker {
	struct acache_info s;
	struct work_struct work;
	struct list_head list;
};

struct acache_device {
	bool initialized;

	dev_t devno;
	struct cdev cdev;
	struct class *class;
	struct mem_reg *mem_regionp;

	struct acache_info *readbuf;
	struct acache_info *writebuf;

	struct acache_circ *acache_info_circ;

	struct inflight_list_head inflight_list;

	struct workqueue_struct *wq;
	struct prefetch_worker *prefetch_workers;
	struct list_head prefetch_workers_free;
	spinlock_t prefetch_workers_free_list_lock;
} adev;

#define MAX_TRANSFER_SIZE (1024 * 1024)

static atomic_t acache_opened_dev = ATOMIC_INIT(0);
static struct acache_metadata metadata;


int acache_open(struct inode *inode, struct file *filp)
{
	struct mem_reg *dev;

	int minor = MINOR(inode->i_rdev);

	if (minor >= ACACHE_NR_DEVS)
		return -ENODEV;
	if (atomic_xchg(&acache_opened_dev, 1))
		return -EPERM;

	dev = &adev.mem_regionp[minor];

	filp->private_data = dev;

	return 0;
}

int acache_release(struct inode *inode, struct file *filp)
{
	atomic_dec(&acache_opened_dev);
	return 0;
}

ssize_t read_circ_slice(struct acache_circ *circ, struct acache_info *buf,
			size_t size)
{
	unsigned long first, todo, flags;

	spin_lock_irqsave(&circ->lock, flags);

	todo = CIRC_CNT(circ->head, circ->tail, circ->size);
	if (todo == 0) {
		spin_unlock_irqrestore(&circ->lock, flags);
		return 0;
	}
	if (todo > size / sizeof(struct acache_info))
		todo = size / sizeof(struct acache_info);

	first = CIRC_CNT_TO_END(circ->head, circ->tail, circ->size);
	if (first > todo)
		first = todo;

	memcpy(buf, circ->data + circ->tail, first * sizeof(struct acache_info));
	if (first < todo)
		memcpy(buf + first, circ->data,
		       (todo - first) * sizeof(struct acache_info));
	circ->tail = (circ->tail + todo) & (circ->size - 1);

	spin_unlock_irqrestore(&circ->lock, flags);
	return todo * sizeof(struct acache_info);
}

static ssize_t acache_read(struct file *filp, char __user *buf,
			   size_t size, loff_t *ppos)
{
	long ret, cut;

	if (metadata.conntype != ACACHE_READWRITE_CONN)
		return -EINVAL;

	if (size > MAX_TRANSFER_SIZE)
		size = MAX_TRANSFER_SIZE;

	ret = read_circ_slice(adev.acache_info_circ, adev.readbuf, size);
	if (ret <= 0)
		return ret;

	cut = copy_to_user(buf, adev.readbuf, size);
	return ret - cut;
}

int process_one_request(struct acache_info *item);
static void prefetch_worker_func(struct work_struct *work)
{
	struct prefetch_worker *sw =
	    container_of(work, struct prefetch_worker, work);

	process_one_request(&sw->s);
	spin_lock(&adev.prefetch_workers_free_list_lock);
	list_add_tail(&sw->list, &adev.prefetch_workers_free);
	spin_unlock(&adev.prefetch_workers_free_list_lock);
}

static int queue_prefetch_item(struct acache_info *s)
{
	struct prefetch_worker *sw;

	spin_lock(&adev.prefetch_workers_free_list_lock);
	sw = list_first_entry_or_null(&adev.prefetch_workers_free,
				      struct prefetch_worker, list);
	if (!sw) {
		spin_unlock(&adev.prefetch_workers_free_list_lock);
		return -1;
	}
	list_del_init(&sw->list);
	spin_unlock(&adev.prefetch_workers_free_list_lock);

	memcpy(&sw->s, s, sizeof(struct acache_info));
	INIT_WORK(&sw->work, prefetch_worker_func);
	queue_work(adev.wq, &sw->work);
	return 0;
}

static ssize_t acache_write(struct file *filp, const char __user *buf,
			    size_t size, loff_t *ppos)
{
	long cut;
	int i;

	if (metadata.conntype != ACACHE_READWRITE_CONN)
		return -EINVAL;

	if (size > MAX_TRANSFER_SIZE)
		size = MAX_TRANSFER_SIZE;

	cut = copy_from_user(adev.writebuf, buf, size);
	for (i = 0; i < (size - cut) / sizeof(struct acache_info); i++) {
		if (queue_prefetch_item(adev.writebuf + i))
			break;
	}
	return i * sizeof(struct acache_info);
}

static long acache_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ACACHE_GET_METADATA:
		return copy_to_user((struct acache_metadata __user *)arg,
				    &metadata, sizeof(struct acache_metadata));
	default:
		return -EINVAL;
	}
}

static const struct file_operations acache_fops = {
	.owner = THIS_MODULE,
	.read = acache_read,
	.write = acache_write,
	.open = acache_open,
	.release = acache_release,
	.unlocked_ioctl = acache_ioctl,
};

void save_circ_item(struct acache_info *data)
{
	unsigned long flags;
	struct acache_circ *circ = adev.acache_info_circ;

	spin_lock_irqsave(&circ->lock, flags);
	if (CIRC_SPACE(circ->head, circ->tail, circ->size) >= 1) {
		memcpy(&circ->data[circ->head], data, sizeof(struct acache_info));
		circ->head = (circ->head + 1) & (circ->size - 1);
	} else {
		pr_debug("ringbuffer is full; discard new request.");
	}
	spin_unlock_irqrestore(&circ->lock, flags);
}

void init_acache_circ(struct acache_circ **circ, void *startaddr)
{
	*circ = (struct acache_circ *)startaddr;
	(*circ)->head = 0;
	(*circ)->tail = 0;
	(*circ)->size = ACACHE_CIRC_SIZE;
	spin_lock_init(&(*circ)->lock);
}

static void acache_free_mem(void)
{
	int i;

	for (i = 0; i < ACACHE_NR_DEVS; i++)
		vfree(adev.mem_regionp[i].data);

	if (adev.readbuf) {
		vfree(adev.readbuf);
		adev.readbuf = NULL;
	}
	if (adev.writebuf) {
		vfree(adev.writebuf);
		adev.writebuf = NULL;
	}

	kfree(adev.prefetch_workers);
	adev.prefetch_workers = NULL;
}

int acache_prefetch_init(struct acache_device *adev)
{
	int i;

	if (acache_prefetch_workers <= 0) {
		pr_err("acache_dev_size should not be less than zero");
		return -1;
	}
	adev->prefetch_workers = kmalloc_array(acache_prefetch_workers,
					       sizeof(struct prefetch_worker),
					       GFP_KERNEL);
	if (!adev->prefetch_workers)
		goto fail_prefetch_workers_alloc;

	INIT_LIST_HEAD(&adev->prefetch_workers_free);
	spin_lock_init(&adev->prefetch_workers_free_list_lock);
	for (i = 0; i < acache_prefetch_workers; i++) {
		spin_lock(&adev->prefetch_workers_free_list_lock);
		list_add_tail(&adev->prefetch_workers[i].list,
			      &adev->prefetch_workers_free);
		spin_unlock(&adev->prefetch_workers_free_list_lock);
	}

	adev->wq = alloc_workqueue("acache_prefetch", WQ_MEM_RECLAIM, 0);
	if (!adev->wq)
		goto fail_workqueue_alloc;

	return 0;

fail_workqueue_alloc:
	kfree(adev->prefetch_workers);
	adev->prefetch_workers = NULL;
fail_prefetch_workers_alloc:
	if (adev->wq)
		destroy_workqueue(adev->wq);
	return -1;
}

int acache_dev_init(void)
{
	int ret;
	int i;
	int major;
	struct device *dev;

	inflight_list_ops.init();
	major = alloc_chrdev_region(&adev.devno, 0, ACACHE_NR_DEVS, DEV_NAME);
	if (major < 0) {
		pr_err("failed to allocate chrdev region: %d", major);
		return major;
		goto fail_allocdev;
	}

	adev.class = class_create(THIS_MODULE, DEV_NAME);
	if (IS_ERR(adev.class)) {
		pr_err("failed to create acache class");
		ret = -1;
		goto fail_class;
	}

	if (acache_dev_size < PAGE_SIZE) {
		pr_err("acache_dev_size should not be less than PAGE_SIZE");
		ret = -1;
		goto fail_dev_add;
	}
	metadata.devsize = acache_dev_size;
	metadata.magic = ACACHE_MAGIC;
	metadata.conntype = ACACHE_READWRITE_CONN;
	cdev_init(&adev.cdev, &acache_fops);
	adev.cdev.owner = THIS_MODULE;

	ret = cdev_add(&adev.cdev, adev.devno, ACACHE_NR_DEVS);
	if (ret < 0) {
		pr_err("failed to add cdev");
		goto fail_dev_add;
	}

	dev = device_create(adev.class, NULL, adev.devno, NULL, DEV_NAME);
	if (IS_ERR(dev)) {
		pr_err("Could not create device");
		ret = -1;
		goto fail_device;
	}

	adev.readbuf = vmalloc(MAX_TRANSFER_SIZE);
	adev.writebuf = vmalloc(MAX_TRANSFER_SIZE);
	if (!adev.readbuf || !adev.writebuf) {
		ret = -ENOMEM;
		goto fail_malloc;
	}

	adev.initialized = true;
	adev.mem_regionp =
	    kmalloc_array(ACACHE_NR_DEVS, sizeof(struct mem_reg), GFP_KERNEL);
	if (!adev.mem_regionp) {
		ret = -ENOMEM;
		goto fail_malloc;
	}
	memset(adev.mem_regionp, 0, sizeof(struct mem_reg) * ACACHE_NR_DEVS);

	for (i = 0; i < ACACHE_NR_DEVS; i++) {
		adev.mem_regionp[i].size = ACACHE_DEV_SIZE;
		adev.mem_regionp[i].data = vmalloc(ACACHE_DEV_SIZE);
		if (!adev.mem_regionp[i].data) {
			ret = -ENOMEM;
			goto fail_memregion_data_malloc;
		}
		memset(adev.mem_regionp[i].data, 0, ACACHE_DEV_SIZE);
	}

	init_acache_circ(&adev.acache_info_circ, adev.mem_regionp[0].data);
	if (acache_prefetch_init(&adev))
		goto fail_prefetch_init;

	return 0;

fail_prefetch_init:
fail_memregion_data_malloc:
	acache_free_mem();
fail_malloc:
	device_destroy(adev.class, adev.devno);
fail_device:
	cdev_del(&adev.cdev);
fail_dev_add:
	class_destroy(adev.class);
fail_class:
	unregister_chrdev_region(adev.devno, ACACHE_NR_DEVS);
fail_allocdev:
	inflight_list_ops.exit();
	return ret;
}

void acache_dev_exit(void)
{
	if (!adev.initialized)
		return;

	if (adev.wq) {
		flush_workqueue(adev.wq);
		destroy_workqueue(adev.wq);
	}
	device_destroy(adev.class, adev.devno);
	cdev_del(&adev.cdev);
	acache_free_mem();
	kfree(adev.mem_regionp);
	unregister_chrdev_region(adev.devno, ACACHE_NR_DEVS);
	class_destroy(adev.class);
	inflight_list_ops.exit();
	kfree(adev.prefetch_workers);
}

static struct search *__inflight_list_lookup_locked(struct search *s)
{
	struct search *iter;
	struct bio *bio, *sbio;

	if (!adev.inflight_list.initialized)
		return NULL;
	sbio = &s->bio.bio;
	list_for_each_entry(iter, &adev.inflight_list.entry, list_node) {
		bio = &iter->bio.bio;
		if (sbio->bi_disk == bio->bi_disk &&
		    sbio->bi_iter.bi_sector < bio_end_sector(bio) &&
		    bio_end_sector(sbio) > bio->bi_iter.bi_sector) {
			return iter;
		}
	}
	return NULL;
}

static void inflight_list_init(void)
{
	INIT_LIST_HEAD(&adev.inflight_list.entry);
	spin_lock_init(&adev.inflight_list.io_lock);
	adev.inflight_list.initialized = true;
}

static void inflight_list_exit(void)
{
	if (!list_empty(&adev.inflight_list.entry))
		pr_err("existing with inflight list not empty");
}

static int inflight_list_insert(struct search *s)
{
	if (!adev.inflight_list.initialized)
		return -1;

	init_waitqueue_head(&s->wqh);
	spin_lock(&adev.inflight_list.io_lock);
	list_add_tail(&s->list_node, &adev.inflight_list.entry);
	spin_unlock(&adev.inflight_list.io_lock);

	trace_bcache_inflight_list_insert(s->d, s->orig_bio);
	return 0;
}

static int inflight_list_remove(struct search *s)
{
	if (!adev.inflight_list.initialized)
		return -1;

	spin_lock(&adev.inflight_list.io_lock);
	list_del_init(&s->list_node);
	spin_unlock(&adev.inflight_list.io_lock);

	wake_up_interruptible_all(&s->wqh);

	trace_bcache_inflight_list_remove(s->d, s->orig_bio);
	return 0;
}

static bool inflight_list_wait(struct search *s)
{
	struct search *pfs = NULL;
	struct cached_dev *dc;
	DEFINE_WAIT(wqe);

	if (!adev.inflight_list.initialized)
		return false;

	spin_lock(&adev.inflight_list.io_lock);
	pfs = __inflight_list_lookup_locked(s);
	if (pfs == NULL) {
		spin_unlock(&adev.inflight_list.io_lock);
		return false;
	}

	dc = container_of(pfs->d, struct cached_dev, disk);
	if (!dc->inflight_block_enable) {
		spin_unlock(&adev.inflight_list.io_lock);
		return true;
	}

	prepare_to_wait(&pfs->wqh, &wqe, TASK_INTERRUPTIBLE);

	/* unlock here to ensure pfs not changed. */
	spin_unlock(&adev.inflight_list.io_lock);
	schedule();

	finish_wait(&pfs->wqh, &wqe);

	return true;
}

const struct inflight_queue_ops inflight_list_ops = {
	.init	= inflight_list_init,
	.exit	= inflight_list_exit,
	.insert	= inflight_list_insert,
	.remove	= inflight_list_remove,
	.wait	= inflight_list_wait,
};

struct cached_dev *get_cached_device_by_dev(dev_t dev)
{
	struct cache_set *c, *tc;
	struct cached_dev *dc, *t;

	list_for_each_entry_safe(c, tc, &bch_cache_sets, list)
		list_for_each_entry_safe(dc, t, &c->cached_devs, list)
			if (dc->bdev->bd_dev == dev && cached_dev_get(dc))
				return dc;

	return NULL;
}

struct bio *get_bio_by_item(struct cached_dev *dc, struct acache_info *item)
{
	struct bio *bio;
	uint64_t offset = item->offset + dc->sb.data_offset;

	if (get_capacity(dc->bdev->bd_disk) < offset + (item->length >> 9)) {
		pr_err("prefetch area exceeds the capacity of disk(%d:%d), end: %llx, capacity: %lx",
		    MAJOR(dc->bdev->bd_dev), MINOR(dc->bdev->bd_dev),
		    offset + (item->length >> 9),
		    get_capacity(dc->bdev->bd_disk));
		return NULL;
	}

	bio = bio_alloc_bioset(GFP_NOWAIT, DIV_ROUND_UP(item->length >> 9, PAGE_SECTORS), &dc->disk.bio_split);
	if (!bio) {
		bio = bio_alloc_bioset(GFP_NOWAIT, DIV_ROUND_UP(item->length >> 9, PAGE_SECTORS), NULL);
		if (!bio)
			return NULL;
	}

	bio_set_dev(bio, dc->bdev);
	bio->bi_iter.bi_sector = item->offset + dc->sb.data_offset;
	bio->bi_iter.bi_size = (item->length >> 9) << 9;

	bch_bio_map(bio, NULL);
	if (bch_bio_alloc_pages(bio, __GFP_NOWARN | GFP_NOIO))
		goto out_put;

	return bio;
out_put:
	bio_put(bio);
	return NULL;
}

int process_one_request(struct acache_info *item)
{
	struct cached_dev *dc;
	struct bio *cache_bio;
	struct search *s;

	dc = get_cached_device_by_dev(item->dev);
	if (dc == NULL)
		return -1;
	cache_bio = get_bio_by_item(dc, item);
	if (cache_bio == NULL) {
		pr_err("acache: failed to alloc bio for prefetch");
		goto put_dev;
	}

	s = search_alloc(cache_bio, &dc->disk, true);

	trace_bcache_prefetch_request(&dc->disk, cache_bio);
	generic_start_io_acct(cache_bio->bi_disk->queue,
			      bio_op(cache_bio),
			      bio_sectors(cache_bio),
			      &s->d->disk->part0);

	cached_dev_read(dc, s);
	return 0;

put_dev:
	cached_dev_put(dc);
	return -1;
}

