// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "p2p: " fmt

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/err.h>
#include <linux/kdev_t.h>
#include <linux/namei.h>
#include <linux/nvme_ioctl.h>
#include <linux/overflow.h>
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "debugfs.h"
#include "topo.h"

#define P2P_SYSFS_BDEV_PATH_MAX 48

#define P2P_TOPO_KIND_NVME 0U
#define P2P_TOPO_KIND_LINEAR 1U
#define P2P_TOPO_KIND_RAID0 2U
#define P2P_TOPO_KIND_LOOP 3U

/* 256K entries, 1 MiB. Coarsen the slot until the table fits. */
#define LOOP_INDEX_MAX_SLOTS (1U << 18)

static RADIX_TREE(topo_tree, GFP_ATOMIC);
static DEFINE_SPINLOCK(topo_lock);
static struct workqueue_struct *topo_release_wq;

static void topo_debugfs_show_one(struct seq_file *seq, const struct topo *topo)
{
	const struct topo_bdev *bdev;
	u32 i;

	seq_printf(seq,
		   "name: %s top_dev: %u:%u size_sector: 0x%llx nr_bdevs: %u pin_count: %u\n",
		   topo->name, MAJOR(topo->top_dev), MINOR(topo->top_dev), topo->size_sector,
		   topo->nr_bdevs, kref_read(&topo->pin_refcnt));
	if (!strcmp(topo->name, "raid0") ||
	    (!strcmp(topo->name, "loop") && topo->loop_stripe))
		seq_printf(seq, "  chunk_sectors: 0x%llx\n",
			   1ULL << topo->priv.chunk_sectors_shift);
	if (!strcmp(topo->name, "loop")) {
		u32 unwritten = 0;

		for (i = 0; i < topo->nr_extents; i++) {
			if (topo->extents[i].flags & P2P_TOPO_EXTENT_UNWRITTEN)
				unwritten++;
		}
		seq_printf(seq,
			   "  extents: %u unwritten: %u index_slots: %u index_shift: %u\n",
			   topo->nr_extents, unwritten, topo->loop_index_slots,
			   topo->loop_index_shift);
	}
	for (i = 0; i < topo->nr_bdevs; i++) {
		bdev = &topo->bdevs[i];
		seq_printf(seq,
			   "  bdev[%u]: dev: %u:%u nsid: %u start_sector: 0x%llx",
			   i, MAJOR(bdev->id), MINOR(bdev->id), bdev->nsid,
			   bdev->start_sector);
		seq_printf(seq, " size_sector: 0x%llx\n", bdev->size_sector);
	}
	seq_putc(seq, '\n');
}

int p2p_debugfs_topo_show(struct seq_file *seq, void *unused)
{
	struct radix_tree_iter iter;
	struct topo *topo;
	void __rcu **slot;

	rcu_read_lock();
	radix_tree_for_each_slot(slot, &topo_tree, &iter, 0) {
		topo = radix_tree_deref_slot(slot);
		if (!topo)
			continue;
		if (radix_tree_deref_retry(topo)) {
			slot = radix_tree_iter_retry(&iter);
			continue;
		}
		topo_debugfs_show_one(seq, topo);
	}
	rcu_read_unlock();

	return 0;
}

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
	if (ret <= 0) {
		pr_err("NVME_IOCTL_ID failed for component %u:%u: %d\n",
		       MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), ret);
		return ret ? ret : -EINVAL;
	}

	*nsid = ret;
	return 0;
}

static int topo_open_component(struct topo_bdev *bdev, const struct topo_user_bdev *cfg)
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
	if (check_add_overflow(bdev->start_sector, bdev->size_sector, &end_sector) ||
	    end_sector > p2p_bdev_nr_sectors(input_bdev)) {
		pr_err("component %u:%u range 0x%llx+0x%llx exceeds capacity 0x%llx sectors\n",
		       MAJOR(bdev->id), MINOR(bdev->id), bdev->start_sector,
		       bdev->size_sector, (u64)p2p_bdev_nr_sectors(input_bdev));
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

static int raid0_map_offset(const struct topo *topo, u64 raid_sector,
			    u32 in_nr_sectors, struct topo_bdev **to_bdev,
			    u64 *to_sector, u32 *out_nr_sectors)
{
	u64 chunk_sectors = 1ULL << topo->priv.chunk_sectors_shift;
	u64 chunk_index = raid_sector >> topo->priv.chunk_sectors_shift;
	u64 offset_in_chunk = raid_sector & (chunk_sectors - 1);
	u64 member_chunk;
	u64 member_offset;
	u32 member_index;
	u32 nr;
	struct topo_bdev *bdev;

	member_chunk = div_u64_rem(chunk_index, topo->nr_bdevs, &member_index);
	member_offset = member_chunk * chunk_sectors + offset_in_chunk;
	bdev = &topo->bdevs[member_index];
	nr = min_t(u64, in_nr_sectors, chunk_sectors - offset_in_chunk);
	if (member_offset >= bdev->size_sector ||
	    nr > bdev->size_sector - member_offset)
		return -EINVAL;

	*to_bdev = bdev;
	*to_sector = bdev->start_sector + member_offset;
	*out_nr_sectors = nr;
	return 0;
}

static int raid0_map_sector(struct topo *topo, u64 from_sector,
			    u32 in_nr_sectors, struct topo_bdev **to_bdev,
			    u64 *to_sector, u32 *out_nr_sectors)
{
	int err;

	if (from_sector >= topo->size_sector)
		return -EINVAL;

	err = raid0_map_offset(topo, from_sector, in_nr_sectors, to_bdev,
			       to_sector, out_nr_sectors);
	if (err)
		return err;
	pr_debug("raid0 from 0x%llx+0x%x to %u:%u nsid %u 0x%llx+0x%x\n",
		 from_sector, in_nr_sectors, MAJOR((*to_bdev)->id),
		 MINOR((*to_bdev)->id), (*to_bdev)->nsid, *to_sector,
		 *out_nr_sectors);
	return 0;
}

static bool loop_extent_contains(const struct topo_extent *extent, u64 sector)
{
	return sector >= extent->logical_start &&
	       sector - extent->logical_start < extent->size_sector;
}

static struct topo_extent *loop_find_extent(struct topo *topo, u64 from_sector)
{
	u64 slot = from_sector >> topo->loop_index_shift;
	u32 idx;

	if (!topo->loop_index || slot >= topo->loop_index_slots)
		return NULL;

	idx = topo->loop_index[slot];
	while (idx < topo->nr_extents) {
		struct topo_extent *extent = &topo->extents[idx];

		if (loop_extent_contains(extent, from_sector))
			return extent;
		if (extent->logical_start > from_sector)
			return NULL;
		idx++;
	}

	return NULL;
}

static unsigned long *topo_extent_bitmap(u64 nbits)
{
	size_t bytes;

	if (!nbits)
		return NULL;
	bytes = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	if (!bytes)
		return NULL;
	return kvzalloc(bytes, GFP_KERNEL);
}

static u32 loop_same_state_run(const struct topo_extent *extent, u64 offset,
			       u32 nr, bool written)
{
	unsigned long *bits = READ_ONCE(extent->written);
	unsigned long end;
	unsigned long pos;
	u64 remain;

	remain = extent->size_sector - offset;
	if (nr < remain)
		remain = nr;
	if (!bits)
		return written ? 0 : (u32)remain;
	end = offset + remain;
	if (written) {
		if (!test_bit(offset, bits))
			return 0;
		pos = find_next_zero_bit(bits, end, offset);
	} else {
		if (test_bit(offset, bits))
			return 0;
		pos = find_next_bit(bits, end, offset);
	}
	return (u32)(pos - offset);
}

int topo_loop_read_span(const struct topo *topo, u64 sector, u32 nr,
			u32 *disk_nr, u32 *zero_nr)
{
	struct topo_extent *extent;
	u64 offset;

	*disk_nr = nr;
	*zero_nr = 0;
	if (!topo || topo->kind != P2P_TOPO_KIND_LOOP || !nr)
		return 0;

	extent = loop_find_extent((struct topo *)topo, sector);
	if (!extent || !(extent->flags & P2P_TOPO_EXTENT_UNWRITTEN))
		return 0;

	offset = sector - extent->logical_start;
	*zero_nr = loop_same_state_run(extent, offset, nr, false);
	if (*zero_nr) {
		*disk_nr = 0;
		return 0;
	}
	*disk_nr = loop_same_state_run(extent, offset, nr, true);
	return 0;
}

static int topo_loop_ensure_written(struct topo_extent *extent)
{
	unsigned long *bits;
	unsigned long *old;

	bits = READ_ONCE(extent->written);
	if (bits)
		return 0;
	bits = topo_extent_bitmap(extent->size_sector);
	if (!bits)
		return -ENOMEM;
	old = cmpxchg(&extent->written, NULL, bits);
	if (old)
		kvfree(bits);
	return 0;
}

int topo_loop_prepare_write(struct topo *topo, u64 sector, u32 nr)
{
	struct topo_extent *extent;
	u64 offset;

	if (!topo || topo->kind != P2P_TOPO_KIND_LOOP || !nr)
		return 0;
	extent = loop_find_extent(topo, sector);
	if (!extent || !(extent->flags & P2P_TOPO_EXTENT_UNWRITTEN))
		return 0;
	offset = sector - extent->logical_start;
	if (nr > extent->size_sector - offset)
		return -EINVAL;
	return topo_loop_ensure_written(extent);
}

void topo_loop_mark_written(struct topo *topo, u64 sector, u32 nr)
{
	struct topo_extent *extent;
	unsigned long *bits;
	u64 offset;
	u32 i;

	if (!topo || topo->kind != P2P_TOPO_KIND_LOOP || !nr)
		return;
	extent = loop_find_extent(topo, sector);
	if (!extent || !(extent->flags & P2P_TOPO_EXTENT_UNWRITTEN))
		return;
	bits = READ_ONCE(extent->written);
	if (!bits)
		return;
	offset = sector - extent->logical_start;
	if (nr > extent->size_sector - offset)
		return;
	for (i = 0; i < nr; i++)
		set_bit(offset + i, bits);
}

static int loop_map_sector(struct topo *topo, u64 from_sector,
			   u32 in_nr_sectors, struct topo_bdev **to_bdev,
			   u64 *to_sector, u32 *out_nr_sectors)
{
	const struct topo_extent *extent;
	u64 offset;
	u64 target;
	u32 limit;
	int err;

	extent = loop_find_extent(topo, from_sector);
	if (!extent)
		return -EINVAL;

	offset = from_sector - extent->logical_start;
	limit = min_t(u64, in_nr_sectors, extent->size_sector - offset);
	if (check_add_overflow(extent->start_sector, offset, &target))
		return -EINVAL;

	if (topo->loop_stripe) {
		err = raid0_map_offset(topo, target, limit, to_bdev, to_sector,
				       out_nr_sectors);
		if (err)
			return err;
	} else {
		*to_bdev = &topo->bdevs[extent->dev_index];
		*to_sector = (*to_bdev)->start_sector + target;
		*out_nr_sectors = limit;
	}
	pr_debug("loop from 0x%llx+0x%x to %u:%u nsid %u 0x%llx+0x%x\n",
		 from_sector, in_nr_sectors, MAJOR((*to_bdev)->id),
		 MINOR((*to_bdev)->id), (*to_bdev)->nsid, *to_sector,
		 *out_nr_sectors);
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

static const struct topo_ops loop_ops = {
	.map_sector = loop_map_sector,
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
	if (topo->extents) {
		for (i = 0; i < topo->nr_extents; i++)
			kvfree(topo->extents[i].written);
	}
	kfree(topo->extents);
	kvfree(topo->loop_index);
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

static int topo_validate_linear(struct topo *topo, const struct topo_user_cfg *cfg)
{
	struct block_device *top_bdev;
	u64 size = 0;
	u32 i;

	if (cfg->extra[0] || cfg->extra[1]) {
		pr_err("linear topology extra fields must be zero: 0x%llx 0x%llx\n",
		       cfg->extra[0], cfg->extra[1]);
		return -EINVAL;
	}

	for (i = 0; i < topo->nr_bdevs; i++) {
		u64 sum;

		if (check_add_overflow(size, topo->bdevs[i].size_sector, &sum)) {
			pr_err("linear topology size overflows at component %u: 0x%llx + 0x%llx sectors\n",
			       i, size, topo->bdevs[i].size_sector);
			return -EINVAL;
		}
		size = sum;
	}
	top_bdev = p2p_handle_to_bdev(topo->top_handle);
	if (size != p2p_bdev_nr_sectors(top_bdev)) {
		pr_err("linear topology size 0x%llx differs from top device capacity 0x%llx sectors\n",
		       size, (u64)p2p_bdev_nr_sectors(top_bdev));
		return -EINVAL;
	}

	topo->size_sector = size;
	topo->kind = P2P_TOPO_KIND_LINEAR;
	topo->ops = &linear_ops;
	return 0;
}

static int topo_validate_nvme(struct topo *topo, const struct topo_user_cfg *cfg)
{
	struct block_device *top_bdev = p2p_handle_to_bdev(topo->top_handle);
	struct topo_bdev *bdev = &topo->bdevs[0];
	struct block_device *component = p2p_handle_to_bdev(bdev->handle);
	struct block_device *whole = p2p_bdev_whole(top_bdev);
	u64 start = bdev_is_partition(top_bdev) ? get_start_sect(top_bdev) : 0;
	u64 size = p2p_bdev_nr_sectors(top_bdev);

	if (cfg->extra[0] || cfg->extra[1] ||
	    component != whole ||
	    bdev->start_sector != start || bdev->size_sector != size) {
		pr_err("invalid NVMe topology: extra 0x%llx 0x%llx, component %u:%u expected %u:%u, range 0x%llx+0x%llx expected 0x%llx+0x%llx\n",
		       cfg->extra[0], cfg->extra[1], MAJOR(component->bd_dev),
		       MINOR(component->bd_dev), MAJOR(whole->bd_dev),
		       MINOR(whole->bd_dev), bdev->start_sector,
		       bdev->size_sector, start, size);
		return -EINVAL;
	}

	topo->size_sector = size;
	topo->kind = P2P_TOPO_KIND_NVME;
	topo->ops = &nvme_ops;
	return 0;
}

static int topo_raid0_logical_sectors(const struct topo *topo, u64 chunk_shift,
				      u64 *logical_sectors)
{
	u64 chunk_sectors;
	u64 size;
	u32 i;

	if (chunk_shift >= 32 || topo->nr_bdevs < 2) {
		pr_err("invalid raid0 topology: components %u, chunk shift %llu\n",
		       topo->nr_bdevs, chunk_shift);
		return -EINVAL;
	}

	chunk_sectors = 1ULL << chunk_shift;
	for (i = 0; i < topo->nr_bdevs; i++) {
		if (topo->bdevs[i].size_sector != topo->bdevs[0].size_sector ||
		    topo->bdevs[i].size_sector & (chunk_sectors - 1)) {
			pr_err("raid0 component %u size 0x%llx must match 0x%llx and align to chunk 0x%llx sectors\n",
			       i, topo->bdevs[i].size_sector,
			       topo->bdevs[0].size_sector, chunk_sectors);
			return -EINVAL;
		}
	}
	if (check_mul_overflow(topo->bdevs[0].size_sector,
			       (u64)topo->nr_bdevs, &size)) {
		pr_err("raid0 topology size overflows: %u components of 0x%llx sectors\n",
		       topo->nr_bdevs, topo->bdevs[0].size_sector);
		return -EINVAL;
	}

	*logical_sectors = size;
	return 0;
}

static int topo_validate_raid0(struct topo *topo,
			       const struct topo_user_cfg *cfg)
{
	struct block_device *top_bdev;
	u64 size;
	int err;

	if (cfg->extra[1] || cfg->extra[0] >= 32) {
		pr_err("invalid raid0 topology: components %u, chunk shift %llu, extra[1] 0x%llx\n",
		       topo->nr_bdevs, cfg->extra[0], cfg->extra[1]);
		return -EINVAL;
	}

	err = topo_raid0_logical_sectors(topo, cfg->extra[0], &size);
	if (err)
		return err;
	top_bdev = p2p_handle_to_bdev(topo->top_handle);
	if (size != p2p_bdev_nr_sectors(top_bdev)) {
		pr_err("raid0 topology size 0x%llx differs from top device capacity 0x%llx sectors\n",
		       size, (u64)p2p_bdev_nr_sectors(top_bdev));
		return -EINVAL;
	}

	topo->size_sector = size;
	topo->priv.chunk_sectors_shift = cfg->extra[0];
	topo->kind = P2P_TOPO_KIND_RAID0;
	topo->ops = &raid0_ops;
	return 0;
}

static int topo_build_loop_index(struct topo *topo)
{
	u64 slot_sectors;
	u64 slots64;
	u64 shift_size = topo->size_sector;
	u32 shift = 0;
	u32 slots;
	u32 *index;
	u32 ei = 0;
	u32 s;

	while (shift < 63 && (shift_size >> shift) > LOOP_INDEX_MAX_SLOTS)
		shift++;
	slot_sectors = 1ULL << shift;
	if (check_add_overflow(shift_size, slot_sectors - 1, &slots64))
		return -EINVAL;
	slots64 >>= shift;
	if (!slots64 || slots64 > UINT_MAX)
		return -EINVAL;
	slots = slots64;

	index = kvmalloc_array(slots, sizeof(*index), GFP_KERNEL);
	if (!index)
		return -ENOMEM;

	for (s = 0; s < slots; s++) {
		u64 sector = (u64)s << shift;

		while (ei + 1 < topo->nr_extents &&
		       topo->extents[ei].logical_start +
		       topo->extents[ei].size_sector <= sector)
			ei++;
		index[s] = ei;
	}

	topo->loop_index = index;
	topo->loop_index_slots = slots;
	topo->loop_index_shift = shift;
	return 0;
}

static int topo_validate_loop(struct topo *topo,
			      const struct topo_user_cfg *cfg)
{
	const struct topo_user_extent *extents =
		(const struct topo_user_extent *)&cfg->bdevs[cfg->nr_devs];
	u64 stripe_sectors = 0;
	u64 size = 0;
	u64 chunk_shift = 0;
	u32 i;
	bool stripe = cfg->extra[1] != 0;
	int err;

	if (!cfg->extra[0] || cfg->extra[0] > P2P_TOPO_MAX_EXTENTS ||
	    cfg->extra[1] > 32)
		return -EINVAL;
	if (stripe) {
		chunk_shift = cfg->extra[1] - 1;
		err = topo_raid0_logical_sectors(topo, chunk_shift,
						 &stripe_sectors);
		if (err)
			return err;
	}

	for (i = 0; i < topo->nr_extents; i++) {
		const struct topo_user_extent *extent = &extents[i];
		u64 end;

		if ((extent->reserved & ~P2P_TOPO_EXTENT_UNWRITTEN) ||
		    !extent->size_sector ||
		    check_add_overflow(extent->start_sector,
				       extent->size_sector, &end))
			return -EINVAL;
		if (stripe) {
			if (extent->dev_index || end > stripe_sectors)
				return -EINVAL;
		} else if (extent->dev_index >= topo->nr_bdevs ||
			   end > cfg->bdevs[extent->dev_index].size_sector) {
			return -EINVAL;
		}
		if (check_add_overflow(size, extent->size_sector, &size))
			return -EINVAL;

		topo->extents[i].dev_index = extent->dev_index;
		topo->extents[i].flags = extent->reserved;
		topo->extents[i].logical_start = size - extent->size_sector;
		topo->extents[i].size_sector = extent->size_sector;
		topo->extents[i].start_sector = extent->start_sector;
		topo->extents[i].written = NULL;
	}
	if (size != p2p_bdev_nr_sectors(p2p_handle_to_bdev(topo->top_handle)))
		return -EINVAL;

	topo->size_sector = size;
	topo->loop_stripe = stripe;
	if (stripe)
		topo->priv.chunk_sectors_shift = chunk_shift;
	err = topo_build_loop_index(topo);
	if (err)
		return err;
	topo->kind = P2P_TOPO_KIND_LOOP;
	topo->ops = &loop_ops;
	return 0;
}

static int topo_validate_cfg(const struct topo_user_cfg *cfg)
{
	bool loop;
	bool nvme;
	u32 i;
	u32 j;

	if (!memchr(cfg->name, '\0', sizeof(cfg->name)) ||
	    (strcmp(cfg->name, "nvme") && strcmp(cfg->name, "linear") &&
	     strcmp(cfg->name, "raid0") && strcmp(cfg->name, "loop")))
		return -EINVAL;
	nvme = !strcmp(cfg->name, "nvme");
	loop = !strcmp(cfg->name, "loop");
	if (!cfg->nr_devs || cfg->nr_devs > P2P_TOPO_MAX_BDEVS ||
	    (nvme && cfg->nr_devs != 1))
		return -EINVAL;

	for (i = 0; i < cfg->nr_devs; i++) {
		if (cfg->bdevs[i].reserved || !cfg->bdevs[i].size_sector ||
		    (!nvme && cfg->bdevs[i].dev_id == cfg->top_dev))
			return -EINVAL;
		for (j = 0; !loop && j < i; j++) {
			if (cfg->bdevs[i].dev_id == cfg->bdevs[j].dev_id)
				return -EINVAL;
		}
	}

	return 0;
}

static void topo_debug_cfg(const struct topo_user_cfg *cfg)
{
	u32 i;

	pr_debug("cfg name: %.*s top_dev: 0x%x nr_devs: %u extra: 0x%llx 0x%llx\n",
		 P2P_TOPO_NAME_LEN, cfg->name, cfg->top_dev, cfg->nr_devs,
		 cfg->extra[0], cfg->extra[1]);
	for (i = 0; i < cfg->nr_devs; i++) {
		const struct topo_user_bdev *bdev = &cfg->bdevs[i];

		pr_debug("cfg bdev[%u]: dev_id: 0x%x reserved: 0x%x size_sector: 0x%llx start_sector: 0x%llx\n",
			 i, bdev->dev_id, bdev->reserved, bdev->size_sector, bdev->start_sector);
	}
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
	if (!strcmp(cfg->name, "loop"))
		topo->nr_extents = cfg->extra[0];
	err = topo_validate_cfg(cfg);
	if (err) {
		pr_err("invalid topology configuration for %u:%u: %d\n",
		       MAJOR(topo->top_dev), MINOR(topo->top_dev), err);
		topo_debug_cfg(cfg);
		goto free_topo;
	}

	topo->bdevs = kcalloc(topo->nr_bdevs, sizeof(*topo->bdevs),
			      GFP_KERNEL);
	if (!topo->bdevs) {
		err = -ENOMEM;
		goto free_topo;
	}
	if (topo->nr_extents) {
		topo->extents = kcalloc(topo->nr_extents,
					 sizeof(*topo->extents), GFP_KERNEL);
		if (!topo->extents) {
			err = -ENOMEM;
			goto free_topo;
		}
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
	     !topo_sysfs_path_exists(topo->top_dev, "md")) ||
	    (!strcmp(topo->name, "loop") &&
	     !topo_sysfs_path_exists(topo->top_dev, "loop/backing_file"))) {
		err = -EOPNOTSUPP;
		pr_err("top device %u:%u does not support %s topology\n",
		       MAJOR(topo->top_dev), MINOR(topo->top_dev), topo->name);
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
	else if (!strcmp(topo->name, "raid0"))
		err = topo_validate_raid0(topo, cfg);
	else
		err = topo_validate_loop(topo, cfg);
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
	/*
	 * Log before publishing the new pin. Once the list node is visible,
	 * a concurrent DEL_TOPO on this fd may remove the pin and free @installed.
	 */
	topo_debug_log(inserted ? "register" : "pin", installed);
	spin_lock(&list->lock);
	list_add_tail(&shared->list, &list->head);
	spin_unlock(&list->lock);

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
	topo_debug_log("unpin", topo);
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
