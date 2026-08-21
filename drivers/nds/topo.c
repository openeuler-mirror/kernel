// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "p2p: " fmt

#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/kdev_t.h>
#include <linux/math64.h>
#include <linux/namei.h>
#include <linux/nvme_ioctl.h>
#include <linux/overflow.h>
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "topo.h"

#define P2P_SYSFS_BDEV_PATH_MAX 48

static RADIX_TREE(topo_tree, GFP_ATOMIC);
static DEFINE_SPINLOCK(topo_lock);
static struct workqueue_struct *topo_release_wq;

static bool topo_sysfs_path_exists(dev_t devt, const char *suffix)
{
	char name[P2P_SYSFS_BDEV_PATH_MAX];
	struct path path;
	int len;
	int err;

	len = snprintf(name, sizeof(name), "/sys/dev/block/%u:%u/%s",
		       MAJOR(devt), MINOR(devt), suffix);
	if (WARN_ON_ONCE(len >= sizeof(name)))
		return false;

	err = kern_path(name, LOOKUP_FOLLOW, &path);
	if (err)
		return false;
	path_put(&path);
	return true;
}

static int topo_validate_nvme_bdev(struct block_device *bdev)
{
	dev_t devt = bdev->bd_dev;

	if (!topo_sysfs_path_exists(devt, "device/subsysnqn")) {
		pr_err("component %u:%u is not an NVMe namespace\n",
		       MAJOR(devt), MINOR(devt));
		return -EOPNOTSUPP;
	}
	if (topo_sysfs_path_exists(devt, "device/iopolicy")) {
		pr_err("NVMe multipath component %u:%u is unsupported\n",
		       MAJOR(devt), MINOR(devt));
		return -EOPNOTSUPP;
	}
	return 0;
}

static int topo_get_nsid(struct block_device *bdev, u32 *nsid)
{
	const struct block_device_operations *fops = bdev->bd_disk->fops;
	int ret;

	if (WARN_ON_ONCE(!fops || !fops->ioctl))
		return -EINVAL;

	ret = fops->ioctl(bdev, P2P_BDEV_READ_MODE, NVME_IOCTL_ID, 0);
	if (ret < 0) {
		pr_err("NVME_IOCTL_ID failed for component %u:%u: %d\n",
		       MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), ret);
		return ret;
	}
	if (!ret)
		return -EINVAL;

	*nsid = ret;
	return 0;
}

static int topo_open_component(struct topo_bdev *bdev,
			       const struct topo_user_bdev *cfg)
{
	p2p_bdev_handle *input_handle;
	struct block_device *input_bdev;
	u64 end_sector;
	int err;

	bdev->id = new_decode_dev(cfg->dev_id);
	bdev->size_sector = cfg->size_sector;
	bdev->start_sector = cfg->start_sector;
	input_handle = p2p_bdev_open_by_dev(bdev->id);
	if (IS_ERR(input_handle)) {
		err = PTR_ERR(input_handle);
		pr_err("failed to open component %u:%u: %d\n",
		       MAJOR(bdev->id), MINOR(bdev->id), err);
		return err;
	}
	input_bdev = p2p_handle_to_bdev(input_handle);

	if (check_add_overflow(bdev->start_sector, bdev->size_sector,
			       &end_sector) ||
	    end_sector > p2p_bdev_nr_sectors(input_bdev)) {
		err = -EINVAL;
		goto out;
	}

	if (bdev_is_partition(input_bdev)) {
		bdev->start_sector += get_start_sect(input_bdev);
		bdev->id = p2p_bdev_whole(input_bdev)->bd_dev;
		bdev->handle = p2p_bdev_open_by_dev(bdev->id);
		if (IS_ERR(bdev->handle)) {
			err = PTR_ERR(bdev->handle);
			pr_err("failed to open whole component %u:%u: %d\n",
			       MAJOR(bdev->id), MINOR(bdev->id), err);
			bdev->handle = NULL;
			goto out;
		}
	} else {
		bdev->handle = input_handle;
		input_handle = NULL;
	}

	err = topo_validate_nvme_bdev(p2p_handle_to_bdev(bdev->handle));
	if (err)
		goto out;
	err = topo_get_nsid(p2p_handle_to_bdev(bdev->handle), &bdev->nsid);
out:
	if (input_handle)
		p2p_bdev_release(input_handle);
	return err;
}

static int linear_map_sector(struct topo *topo, u64 from_sector,
			     u32 in_nr_sectors, struct topo_bdev **to_bdev,
			     u64 *to_sector, u32 *out_nr_sectors)
{
	u64 logical_start = 0;
	u64 offset;
	u64 available;
	u32 i;

	for (i = 0; i < topo->nr_bdevs; i++) {
		struct topo_bdev *bdev = &topo->bdevs[i];

		if (from_sector - logical_start >= bdev->size_sector) {
			logical_start += bdev->size_sector;
			continue;
		}

		offset = from_sector - logical_start;
		available = bdev->size_sector - offset;
		*to_bdev = bdev;
		*to_sector = bdev->start_sector + offset;
		*out_nr_sectors = min_t(u64, in_nr_sectors, available);
		pr_debug("linear from 0x%llx+0x%x to %u:%u nsid %u 0x%llx+0x%x\n",
			 from_sector, in_nr_sectors, MAJOR(bdev->id), MINOR(bdev->id),
			 bdev->nsid, *to_sector, *out_nr_sectors);
		return 0;
	}

	return -EINVAL;
}

static int nvme_map_sector(struct topo *topo, u64 from_sector,
			   u32 in_nr_sectors, struct topo_bdev **to_bdev,
			   u64 *to_sector, u32 *out_nr_sectors)
{
	*to_bdev = &topo->bdevs[0];
	*to_sector = topo->bdevs[0].start_sector + from_sector;
	*out_nr_sectors = in_nr_sectors;
	return 0;
}

static int raid0_map_sector(struct topo *topo, u64 from_sector,
			    u32 in_nr_sectors, struct topo_bdev **to_bdev,
			    u64 *to_sector, u32 *out_nr_sectors)
{
	u64 chunk_sectors = 1ULL << topo->priv.chunk_sectors_shift;
	u64 chunk_index;
	u64 offset_in_chunk;
	u64 member_chunk;
	u64 member_offset;
	u32 member_index;

	if (from_sector >= topo->size_sector)
		return -EINVAL;

	chunk_index = from_sector >> topo->priv.chunk_sectors_shift;
	offset_in_chunk = from_sector & (chunk_sectors - 1);
	/* Avoid u64 % / on ARM32 (would pull in __aeabi_uldivmod). */
	member_chunk = div_u64_rem(chunk_index, topo->nr_bdevs, &member_index);
	member_offset = member_chunk * chunk_sectors + offset_in_chunk;

	*to_bdev = &topo->bdevs[member_index];
	*to_sector = topo->bdevs[member_index].start_sector + member_offset;
	*out_nr_sectors = min_t(u64, in_nr_sectors,
				    chunk_sectors - offset_in_chunk);
	pr_debug("raid0 from 0x%llx+0x%x to %u:%u nsid %u 0x%llx+0x%x\n",
		 from_sector, in_nr_sectors, MAJOR((*to_bdev)->id), MINOR((*to_bdev)->id),
		 (*to_bdev)->nsid, *to_sector, *out_nr_sectors);
	return 0;
}

static const struct topo_ops linear_ops = {
	.map_sector = linear_map_sector,
};

static const struct topo_ops nvme_ops = {
	.map_sector = nvme_map_sector,
};

static const struct topo_ops raid0_ops = {
	.map_sector = raid0_map_sector,
};

static void topo_release_handles(struct topo *topo)
{
	u32 i;

	if (topo->bdevs) {
		for (i = 0; i < topo->nr_bdevs; i++) {
			if (topo->bdevs[i].handle)
				p2p_bdev_release(topo->bdevs[i].handle);
		}
	}
	if (topo->top_handle)
		p2p_bdev_release(topo->top_handle);
}

static void topo_destroy_sync(struct topo *topo)
{
	topo_release_handles(topo);
	kfree(topo->bdevs);
	kfree(topo);
}

static void topo_debug_log(const char *action, const struct topo *topo)
{
	u32 i;

	pr_debug("%s %s topology %u:%u with %u components\n",
		 action, topo->name, MAJOR(topo->top_dev), MINOR(topo->top_dev),
		 topo->nr_bdevs);
	for (i = 0; i < topo->nr_bdevs; i++) {
		const struct topo_bdev *bdev = &topo->bdevs[i];

		pr_debug("topology component %u is %u:%u nsid %u range 0x%llx+0x%llx\n",
			 i, MAJOR(bdev->id), MINOR(bdev->id), bdev->nsid,
			 bdev->start_sector, bdev->size_sector);
	}
}

static void topo_release_work(struct work_struct *work)
{
	struct rcu_work *rcu_work = to_rcu_work(work);
	struct topo *topo = container_of(rcu_work, struct topo, rcu_work);

	topo_destroy_sync(topo);
}

static void topo_ref_release(struct kref *ref)
{
	struct topo *topo = container_of(ref, struct topo, refcnt);

	if (WARN_ON_ONCE(!queue_rcu_work(topo_release_wq, &topo->rcu_work)))
		return;
}

void topo_put(struct topo *topo)
{
	kref_put(&topo->refcnt, topo_ref_release);
}

static int topo_validate_linear(struct topo *topo,
				const struct topo_user_cfg *cfg)
{
	u64 size = 0;
	u32 i;

	if (cfg->extra[0] || cfg->extra[1])
		return -EINVAL;

	for (i = 0; i < topo->nr_bdevs; i++) {
		if (check_add_overflow(size, topo->bdevs[i].size_sector, &size))
			return -EINVAL;
	}
	if (size != p2p_bdev_nr_sectors(p2p_handle_to_bdev(topo->top_handle)))
		return -EINVAL;

	topo->size_sector = size;
	topo->ops = &linear_ops;
	return 0;
}

static int topo_validate_nvme(struct topo *topo,
			      const struct topo_user_cfg *cfg)
{
	struct block_device *top_bdev = p2p_handle_to_bdev(topo->top_handle);
	struct topo_bdev *bdev = &topo->bdevs[0];
	struct block_device *component = p2p_handle_to_bdev(bdev->handle);
	u64 start = bdev_is_partition(top_bdev) ? get_start_sect(top_bdev) : 0;
	u64 size = p2p_bdev_nr_sectors(top_bdev);

	if (cfg->extra[0] || cfg->extra[1] ||
	    component != p2p_bdev_whole(top_bdev) ||
	    bdev->start_sector != start || bdev->size_sector != size)
		return -EINVAL;

	topo->size_sector = size;
	topo->ops = &nvme_ops;
	return 0;
}

static int topo_validate_raid0(struct topo *topo,
			       const struct topo_user_cfg *cfg)
{
	u64 chunk_sectors;
	u64 size;
	u32 i;

	if (topo->nr_bdevs < 2 || cfg->extra[1] || cfg->extra[0] >= 32)
		return -EINVAL;

	chunk_sectors = 1ULL << cfg->extra[0];
	/* Compare configured offsets before partition-start translation. */
	for (i = 0; i < topo->nr_bdevs; i++) {
		if (cfg->bdevs[i].start_sector != cfg->bdevs[0].start_sector ||
		    cfg->bdevs[i].size_sector != cfg->bdevs[0].size_sector ||
		    (topo->bdevs[i].size_sector & (chunk_sectors - 1)))
			return -EINVAL;
	}
	if (check_mul_overflow(topo->bdevs[0].size_sector,
			       (u64)topo->nr_bdevs, &size))
		return -EINVAL;
	if (size != p2p_bdev_nr_sectors(p2p_handle_to_bdev(topo->top_handle)))
		return -EINVAL;

	topo->size_sector = size;
	topo->priv.chunk_sectors_shift = cfg->extra[0];
	topo->ops = &raid0_ops;
	return 0;
}

static int topo_validate_cfg(const struct topo_user_cfg *cfg)
{
	bool nvme;
	u32 i;
	u32 j;

	if (!memchr(cfg->name, '\0', sizeof(cfg->name)) ||
	    (strcmp(cfg->name, "nvme") && strcmp(cfg->name, "linear") &&
	     strcmp(cfg->name, "raid0")))
		return -EINVAL;
	nvme = !strcmp(cfg->name, "nvme");
	if (!cfg->nr_devs || cfg->nr_devs > P2P_TOPO_MAX_BDEVS ||
	    (nvme && cfg->nr_devs != 1))
		return -EINVAL;

	for (i = 0; i < cfg->nr_devs; i++) {
		if (cfg->bdevs[i].reserved || !cfg->bdevs[i].size_sector ||
		    (!nvme && cfg->bdevs[i].dev_id == cfg->top_dev))
			return -EINVAL;
		for (j = 0; j < i; j++) {
			if (cfg->bdevs[i].dev_id == cfg->bdevs[j].dev_id)
				return -EINVAL;
		}
	}
	return 0;
}

static struct topo *topo_alloc_candidate(const struct topo_user_cfg *cfg)
{
	struct topo *topo;
	u32 i;
	int err;

	topo = kzalloc(sizeof(*topo), GFP_KERNEL);
	if (!topo)
		return ERR_PTR(-ENOMEM);

	topo->top_dev = new_decode_dev(cfg->top_dev);
	topo->nr_bdevs = cfg->nr_devs;
	err = topo_validate_cfg(cfg);
	if (err)
		goto free_topo;

	topo->bdevs = kcalloc(topo->nr_bdevs, sizeof(*topo->bdevs),
			      GFP_KERNEL);
	if (!topo->bdevs) {
		err = -ENOMEM;
		goto free_topo;
	}
	strscpy(topo->name, cfg->name, sizeof(topo->name));
	INIT_RCU_WORK(&topo->rcu_work, topo_release_work);

	topo->top_handle = p2p_bdev_open_by_dev(topo->top_dev);
	if (IS_ERR(topo->top_handle)) {
		err = PTR_ERR(topo->top_handle);
		pr_err("failed to open top bdev %u:%u: %d\n",
		       MAJOR(topo->top_dev), MINOR(topo->top_dev), err);
		topo->top_handle = NULL;
		goto free_topo;
	}
	if ((!strcmp(topo->name, "linear") &&
	     !topo_sysfs_path_exists(topo->top_dev, "dm")) ||
	    (!strcmp(topo->name, "raid0") &&
	     !topo_sysfs_path_exists(topo->top_dev, "md"))) {
		err = -EOPNOTSUPP;
		goto free_topo;
	}

	for (i = 0; i < topo->nr_bdevs; i++) {
		struct topo_bdev *bdev = &topo->bdevs[i];

		err = topo_open_component(bdev, &cfg->bdevs[i]);
		if (err)
			goto free_topo;
	}

	if (!strcmp(topo->name, "nvme"))
		err = topo_validate_nvme(topo, cfg);
	else if (!strcmp(topo->name, "linear"))
		err = topo_validate_linear(topo, cfg);
	else
		err = topo_validate_raid0(topo, cfg);
	if (err) {
		pr_err("invalid %s topology for %u:%u: %d\n", topo->name,
		       MAJOR(topo->top_dev), MINOR(topo->top_dev), err);
		goto free_topo;
	}

	kref_init(&topo->refcnt);
	kref_init(&topo->pin_refcnt);
	return topo;

free_topo:
	topo_destroy_sync(topo);
	return ERR_PTR(err);
}

int topo_add(const struct topo_user_cfg *cfg, struct shared_topo_list *list)
{
	struct shared_topo *shared;
	struct topo *candidate = NULL;
	struct topo *installed;
	dev_t top_dev;
	bool inserted = false;
	int err;

	top_dev = new_decode_dev(cfg->top_dev);
	shared = kzalloc(sizeof(*shared), GFP_KERNEL);
	if (!shared)
		return -ENOMEM;

	spin_lock(&topo_lock);
	installed = radix_tree_lookup(&topo_tree, top_dev);
	if (installed)
		kref_get(&installed->pin_refcnt);
	spin_unlock(&topo_lock);
	if (installed)
		goto link_shared;

	candidate = topo_alloc_candidate(cfg);
	if (IS_ERR(candidate)) {
		err = PTR_ERR(candidate);
		goto free_shared;
	}

	err = radix_tree_preload(GFP_KERNEL);
	if (err)
		goto free_candidate;

	spin_lock(&topo_lock);
	installed = radix_tree_lookup(&topo_tree, candidate->top_dev);
	if (installed) {
		kref_get(&installed->pin_refcnt);
	} else {
		err = radix_tree_insert(&topo_tree, candidate->top_dev, candidate);
		if (!err) {
			installed = candidate;
			inserted = true;
		}
	}
	spin_unlock(&topo_lock);
	radix_tree_preload_end();
	if (err)
		goto free_candidate;

link_shared:
	shared->topo = installed;
	spin_lock(&list->lock);
	list_add_tail(&shared->list, &list->head);
	spin_unlock(&list->lock);
	topo_debug_log(inserted ? "register" : "pin", installed);

	if (candidate && installed != candidate)
		topo_destroy_sync(candidate);
	return 0;

free_candidate:
	topo_destroy_sync(candidate);
free_shared:
	kfree(shared);
	return err;
}

struct topo *topo_get(struct block_device *top_bdev)
{
	struct topo *topo;

	rcu_read_lock();
	topo = radix_tree_lookup(&topo_tree, top_bdev->bd_dev);
	if (!topo)
		goto out;
	if (!kref_get_unless_zero(&topo->refcnt)) {
		topo = ERR_PTR(-ESTALE);
		goto out;
	}

out:
	rcu_read_unlock();
	return topo;
}

static void topo_pin_release(struct kref *ref)
{
	struct topo *topo = container_of(ref, struct topo, pin_refcnt);
	void *removed;

	removed = radix_tree_delete(&topo_tree, topo->top_dev);
	spin_unlock(&topo_lock);
	WARN_ON_ONCE(removed != topo);
	topo_put(topo);
}

void topo_del(struct topo *topo)
{
	kref_put_lock(&topo->pin_refcnt, topo_pin_release, &topo_lock);
}

int topo_init(void)
{
	topo_release_wq = alloc_workqueue("p2p_topo_release",
					  WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!topo_release_wq)
		return -ENOMEM;
	return 0;
}

void topo_exit(void)
{
	WARN_ON_ONCE(!radix_tree_empty(&topo_tree));
	destroy_workqueue(topo_release_wq);
}
