// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: Handle IOCTL from Lib UMMU.
 */

#define pr_fmt(fmt) "[UMMU_CORE][IOCTL]: " fmt

#include <linux/miscdevice.h>
#include <linux/bitfield.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/property.h>

#include "ummu_core_priv.h"

#define MMAP_TYPE_MASK GENMASK(1, 0)
#define MMAP_BLOCK_INDEX_MASK GENMASK(11, 2)
#define MMAP_BLK_TID_MASK GENMASK(31, 12)
#define MMAP_QUE_TID_MASK GENMASK(21, 2)
#define KEY_TIME_REGIN GENMASK_ULL(47, 16)
#define KEY_OFFSET_SHIFT 32
#define GET_PROC_KEY(tgid, stime) ((((u64)(tgid)) << (KEY_OFFSET_SHIFT)) \
			| ((u64)(FIELD_GET(KEY_TIME_REGIN, stime))))

struct ktid_info {
	u8 pcmdq_order;
	u8 pcplq_order;
	size_t blk_exp_size;
	u32 tid;
	enum ummu_mapt_mode mode;
	struct iommu_sva *sva;
	struct device *dev;
	u64 hw_cap;
	atomic_t mmap_count;
};

struct mmap_info {
	int type;
	u32 block_index;
	int page_cnt;
	unsigned long vm_start;
	unsigned long *bitmap;
	struct kref ref;
	u32 tid;
};

struct proc_manager {
	struct xarray tid_xa;
	struct mutex proc_mtx;
};

static DEFINE_XARRAY(proc_info_xa);
static DEFINE_MUTEX(global_proc_mtx);

static int get_ummu_cnt(struct ktid_info *entry, u32 *cnt)
{
	struct resource_args cnt_args;
	int ret;

	cnt_args.type = UMMU_CNT;
	ret = ummu_core_get_resource(entry->sva,
				     entry->dev, &cnt_args);
	if (ret)
		return ret;

	*cnt = cnt_args.ummu_cnt;

	return 0;
}

static int get_tid_res(struct ktid_info *entry)
{
	struct resource_args args = {0};
	int ret;

	args.type = UMMU_TID_RES;
	ret = ummu_core_get_resource(entry->sva, entry->dev, &args);
	if (ret)
		return ret;

	entry->pcmdq_order = args.tid_res.pcmdq_order;
	entry->pcplq_order = args.tid_res.pcplq_order;
	entry->blk_exp_size = args.tid_res.blk_exp_size;

	return 0;
}

static int proc_manager_open(struct inode *inode, struct file *filp)
{
	struct proc_manager *manager;
	unsigned long key;
	int ret;

	mutex_lock(&global_proc_mtx);
	key = GET_PROC_KEY(current->tgid, current->start_time);
	manager = xa_load(&proc_info_xa, key);
	if (manager) {
		mutex_unlock(&global_proc_mtx);
		return -EEXIST;
	}

	manager = kzalloc(sizeof(struct proc_manager), GFP_KERNEL);
	if (!manager) {
		mutex_unlock(&global_proc_mtx);
		return -ENOMEM;
	}

	mutex_init(&manager->proc_mtx);
	mutex_lock(&manager->proc_mtx);
	ret = xa_err(xa_store(&proc_info_xa, key, manager, GFP_KERNEL));
	if (ret)
		goto mtx_unlock;

	mutex_unlock(&global_proc_mtx);

	xa_init(&manager->tid_xa);
	filp->private_data = (void *)(uintptr_t)key;
	mutex_unlock(&manager->proc_mtx);

	return 0;

mtx_unlock:
	mutex_unlock(&global_proc_mtx);
	mutex_unlock(&manager->proc_mtx);
	mutex_destroy(&manager->proc_mtx);
	kfree(manager);
	return ret;
}

static int enable_dev_feat(struct device *dev)
{
	int ret;

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_IOPF);
	if (ret)
		return ret;

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		(void)iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_IOPF);
		return ret;
	}

	return 0;
}

static void disable_dev_feat(struct device *dev)
{
	(void)iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_SVA);
	(void)iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_IOPF);
}

static void release_tid_resource(struct ktid_info *entry)
{
	if (entry->sva)
		iommu_sva_unbind_device_isolated(entry->sva);

	if (entry->dev) {
		disable_dev_feat(entry->dev);
		(void)ummu_core_free_tdev(entry->dev);
	}
	kfree(entry);
}

static int proc_manager_close(struct inode *inode, struct file *filp)
{
	unsigned long key = (unsigned long)(uintptr_t)filp->private_data;
	struct proc_manager *manager;
	struct ktid_info *entry;
	unsigned long idx = 0;

	mutex_lock(&global_proc_mtx);
	manager = xa_load(&proc_info_xa, key);
	if (!manager) {
		mutex_unlock(&global_proc_mtx);
		return -EINVAL;
	}

	WARN_ON(!xa_erase(&proc_info_xa, key));
	mutex_lock(&manager->proc_mtx);
	mutex_unlock(&global_proc_mtx);
	if (!xa_empty(&manager->tid_xa))
		xa_for_each(&manager->tid_xa, idx, entry) {
			release_tid_resource(entry);
			cond_resched();
		}

	xa_destroy(&manager->tid_xa);
	filp->private_data = NULL;
	mutex_unlock(&manager->proc_mtx);
	mutex_destroy(&manager->proc_mtx);
	kfree(manager);

	return 0;
}

static void tid_mmap(struct vm_area_struct *vma)
{
	struct mmap_info *map_info = (struct mmap_info *)vma->vm_private_data;

	kref_get(&map_info->ref);
}

static void release_tid_mmap_info(struct kref *ref)
{
	struct mmap_info *map_info = container_of(ref, struct mmap_info, ref);

	bitmap_free(map_info->bitmap);
	kfree(map_info);
}

static void tid_munmap(struct vm_area_struct *area)
{
	unsigned long key = (unsigned long)(uintptr_t)area->vm_file->private_data;
	struct resource_args release_args = {};
	struct proc_manager *manager;
	struct mmap_info *map_info;
	struct ktid_info *entry;
	int start, end, i;
	bool set;

	map_info = area->vm_private_data;
	if (!map_info)
		return;

	start = (area->vm_start - map_info->vm_start) / PAGE_SIZE;
	end = (area->vm_end - map_info->vm_start) / PAGE_SIZE;

	for (i = start; i < end; ++i) {
		set = test_and_clear_bit(i, map_info->bitmap);
		if (set)
			map_info->page_cnt--;
		else
			pr_warn("dup page unmap.\n");
	}

	area->vm_private_data = NULL;

	/*
	 * Release block/queue resources when all pages are unmapped.
	 */
	if (map_info->page_cnt <= 0) {
		WARN_ON(map_info->page_cnt < 0);

		if (map_info->type == MMAP_TYPE_BLOCK) {
			release_args.block_index = map_info->block_index;
			release_args.type = UMMU_BLOCK;
		} else {
			release_args.type = UMMU_QUEUE_LIST;
		}

		mutex_lock(&global_proc_mtx);
		manager = xa_load(&proc_info_xa, key);
		if (manager) {
			mutex_lock(&manager->proc_mtx);
			mutex_unlock(&global_proc_mtx);

			entry = xa_load(&manager->tid_xa, map_info->tid);
			if (entry && entry->tid == map_info->tid) {
				ummu_core_put_resource(entry->sva, entry->dev,
							&release_args);
				atomic_dec(&entry->mmap_count);
			}
			mutex_unlock(&manager->proc_mtx);
		} else {
			mutex_unlock(&global_proc_mtx);
		}
	}

	/*
	 * Always release mmap_info via kref_put.
	 * Each VMA close corresponds to one VMA open (during split),
	 * so kref_put must be called for every close to maintain balance.
	 */
	kref_put(&map_info->ref, release_tid_mmap_info);
}

static int tid_mremap(struct vm_area_struct *area)
{
	return -EINVAL;
}

static const struct vm_operations_struct ops_fn = {
	.open = tid_mmap,
	.close = tid_munmap,
	.mremap = tid_mremap,
};

static int check_map_resource(struct vm_area_struct *vma, unsigned long size)
{
	unsigned long cul_size;

	cul_size = vma->vm_end - vma->vm_start;
	if (cul_size != size) {
		pr_err("map size is err!:cul_size:0x%lx, map_size:0x%lx.\n",
		       cul_size, size);
		return -EINVAL;
	}
	return 0;
}

static int map_block_resource(struct vm_area_struct *vma, size_t blk_size,
			      unsigned long block_index, struct ktid_info *entry)
{
	unsigned long start_addr = vma->vm_start;
	struct resource_args args;
	phys_addr_t page_base;
	int i, ret;

	ret = check_map_resource(vma, blk_size);
	if (ret)
		return ret;

	args.block.index = block_index;
	args.block.block_size_order = get_order(blk_size);
	args.type = UMMU_BLOCK;
	ret = ummu_core_get_resource(entry->sva, entry->dev, &args);
	if (ret)
		return ret;

	page_base = args.block.out_addr;
	for (i = 0; i < (1 << args.block.block_size_order); i++) {
		ret = vm_insert_page(vma, start_addr, pfn_to_page(PFN_DOWN(page_base)));
		if (ret) {
			ummu_core_put_resource(entry->sva, entry->dev, &args);
			return ret;
		}
		page_base += PAGE_SIZE;
		start_addr += PAGE_SIZE;
	}

	return ret;
}

static int do_map_queues(struct ktid_info *entry, struct vm_area_struct *vma,
			 int cnt, const struct resource_args *queues_args)
{
	unsigned long start_addr = vma->vm_start;
	struct queue_args *queue;
	phys_addr_t page_base;
	int i, j, ret;

	for (i = 0; i < cnt; i++) {
		queue = &queues_args->queues[i];
		page_base = queue->pcmdq_base;

		for (j = 0; j < (1 << entry->pcmdq_order); j++) {
			ret = vm_insert_page(vma, start_addr,
					     pfn_to_page(PFN_DOWN(page_base)));
			if (ret)
				return ret;

			page_base += PAGE_SIZE;
			start_addr += PAGE_SIZE;
		}

		page_base = queue->pcplq_base;
		for (j = 0; j < (1 << entry->pcplq_order); j++) {
			ret = vm_insert_page(vma, start_addr,
					     pfn_to_page(PFN_DOWN(page_base)));
			if (ret)
				return ret;

			page_base += PAGE_SIZE;
			start_addr += PAGE_SIZE;
		}

		ret = remap_pfn_range(vma, start_addr,
				      PHYS_PFN(queue->ctrl_page), PAGE_SIZE,
				      pgprot_noncached(vma->vm_page_prot));
		if (ret)
			return ret;

		start_addr += PAGE_SIZE;
	}

	return 0;
}

static int map_mutiq_resource(struct vm_area_struct *vma,
			      struct ktid_info *entry)
{
	struct resource_args args;
	unsigned long map_size;
	u32 cnt;
	int ret;

	ret = get_ummu_cnt(entry, &cnt);
	if (ret)
		return ret;

	map_size = PAGE_SIZE * cnt *
		   (1 + (1 << entry->pcmdq_order) + (1 << entry->pcplq_order));
	ret = check_map_resource(vma, map_size);
	if (ret)
		return ret;

	args.type = UMMU_QUEUE_LIST;
	args.queues = kcalloc(cnt, sizeof(struct queue_args), GFP_KERNEL);
	if (!args.queues)
		return -ENOMEM;

	ret = ummu_core_get_resource(entry->sva, entry->dev, &args);
	if (ret)
		goto free;

	ret = do_map_queues(entry, vma, cnt, &args);
	if (ret)
		ummu_core_put_resource(entry->sva, entry->dev, &args);

free:
	kfree(args.queues);
	return ret;
}

static int map_mapt_block(struct vm_area_struct *vma, struct ktid_info *entry,
			  struct mmap_info *map_info, unsigned long offset)
{
	unsigned long block_index;
	size_t blk_size;
	int ret;

	if (entry->mode == MAPT_MODE_TABLE)
		blk_size = entry->blk_exp_size;
	else if (entry->mode == MAPT_MODE_ENTRY)
		blk_size = PAGE_SIZE;
	else
		return -EINVAL;

	block_index = FIELD_GET(MMAP_BLOCK_INDEX_MASK, offset);
	if (block_index >= BLOCK_MAX_INDEX) {
		pr_err("invalid index: %lu.\n", block_index);
		return -EINVAL;
	}

	ret = map_block_resource(vma, blk_size, block_index, entry);
	if (ret)
		return ret;

	map_info->block_index = block_index;

	return 0;
}

static struct mmap_info *init_map_info(struct vm_area_struct *vma,
				       int mmap_type)
{
	struct mmap_info *map_info;

	map_info = kzalloc(sizeof(*map_info), GFP_KERNEL);
	if (!map_info)
		return ERR_PTR(-ENOMEM);

	map_info->page_cnt = (int)((vma->vm_end - vma->vm_start) / PAGE_SIZE);
	map_info->vm_start = vma->vm_start;
	map_info->type = mmap_type;
	map_info->bitmap = bitmap_zalloc(map_info->page_cnt, GFP_KERNEL);
	if (!map_info->bitmap) {
		kfree(map_info);
		return ERR_PTR(-ENOMEM);
	}
	return map_info;
}

static void deinit_map_info(struct mmap_info *map_info)
{
	bitmap_free(map_info->bitmap);
	kfree(map_info);
}

static struct ktid_info *get_tid_src(struct proc_manager *manager,
				     unsigned long offset, int mmap_type)
{
	struct ktid_info *entry;
	u32 tid;

	switch (mmap_type) {
	case MMAP_TYPE_BLOCK:
		tid = FIELD_GET(MMAP_BLK_TID_MASK, offset);
		break;
	case MMAP_TYPE_MUTIQ:
		tid = FIELD_GET(MMAP_QUE_TID_MASK, offset);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	entry = xa_load(&manager->tid_xa, tid);
	if (!entry)
		return ERR_PTR(-EINVAL);

	return entry;
}

/*
 *|20bit|10bit|2bit|page_shift|
 *| tid |index|op  | rsv      |
 */
static int tid_map_resource(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long key = (unsigned long)(uintptr_t)filp->private_data;
	unsigned long offset = vma->vm_pgoff;
	struct proc_manager *manager;
	struct mmap_info *map_info;
	struct ktid_info *entry;
	int mmap_type;
	int ret;

	mmap_type = FIELD_GET(MMAP_TYPE_MASK, offset);
	map_info = init_map_info(vma, mmap_type);
	if (IS_ERR(map_info))
		return PTR_ERR(map_info);

	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_IO);

	mutex_lock(&global_proc_mtx);
	manager = xa_load(&proc_info_xa, key);
	if (!manager) {
		mutex_unlock(&global_proc_mtx);
		deinit_map_info(map_info);
		return -EINVAL;
	}

	mutex_lock(&manager->proc_mtx);
	mutex_unlock(&global_proc_mtx);

	entry = get_tid_src(manager, offset, mmap_type);
	if (IS_ERR(entry)) {
		ret = PTR_ERR(entry);
		goto free_map_info;
	}

	map_info->tid = entry->tid;
	switch (mmap_type) {
	case MMAP_TYPE_BLOCK:
		ret = map_mapt_block(vma, entry, map_info, offset);
		if (ret)
			goto free_map_info;
		break;
	case MMAP_TYPE_MUTIQ:
		ret = map_mutiq_resource(vma, entry);
		if (ret)
			goto free_map_info;
		break;
	default:
		ret = -EINVAL;
		goto free_map_info;
	}

	/*
	 * Increment mmap count to prevent FREE_TID while mmap is active.
	 * This must be done while holding proc_mtx to prevent race with
	 * FREE_TID checking the count.
	 */
	atomic_inc(&entry->mmap_count);
	mutex_unlock(&manager->proc_mtx);

	bitmap_fill(map_info->bitmap, map_info->page_cnt);
	vma->vm_private_data = map_info;
	vma->vm_ops = &ops_fn;
	kref_init(&map_info->ref);

	return 0;

free_map_info:
	mutex_unlock(&manager->proc_mtx);
	deinit_map_info(map_info);
	return ret;
}

static int user_mode_device_init(struct ktid_info *entry)
{
	struct ummu_param param;
	struct tdev_attr attr;
	struct tid_dev *tdev;
	int ret;

	tdev_attr_init(&attr);
	attr.dma_attr = DEV_DMA_NOT_SUPPORTED;
	entry->dev = ummu_alloc_tdev(&attr, &entry->tid);
	if (!entry->dev)
		return -ENODEV;

	ret = enable_dev_feat(entry->dev);
	if (ret)
		goto free_dev;

	param.mode = entry->mode;
	entry->sva = iommu_sva_bind_device_isolated(entry->dev, current->mm, &param);
	if (IS_ERR(entry->sva)) {
		ret = PTR_ERR(entry->sva);
		entry->sva = NULL;
		goto disable_feat;
	}

	ret = ummu_get_tid(entry->dev, entry->sva, &entry->tid);
	if (ret)
		goto unbind;

	ret = get_tid_res(entry);
	if (ret)
		goto unbind;

	tdev = to_tid_dev(entry->dev);
	tdev->sva = entry->sva;

	return 0;

unbind:
	iommu_sva_unbind_device_isolated(entry->sva);
	entry->sva = NULL;
disable_feat:
	disable_dev_feat(entry->dev);
free_dev:
	ummu_core_free_tdev(entry->dev);
	entry->dev = NULL;

	return ret;
}

static int get_hw_cap(u32 *mode, u64 *hw_cap)
{
	u32 cap;
	int ret;

	ret = ummu_core_get_hw_cap(NULL, &cap);
	if (ret < 0)
		return ret;

	if (cap & HW_CAP_IOPF)
		*mode = UMMU_SVA_SHARE_MODE;
	else if (IS_ENABLED(CONFIG_UB_UMMU_SVA_SEPARATED_PAGES))
		*mode = UMMU_SVA_SEPARATE_MODE;
	else
		*mode = UMMU_SVA_SHARE_MODE;

	*hw_cap = cap;

	return 0;
}

static int sva_separated_mode_dev_init(struct ktid_info *entry)
{
	struct tdev_attr attr = {0};
	int ret;

	tdev_attr_init(&attr);
	attr.mode = entry->mode;
	attr.usva = true;
	entry->dev = ummu_alloc_tdev(&attr, &entry->tid);
	if (!entry->dev)
		return -ENODEV;

	ret = enable_dev_feat(entry->dev);
	if (ret)
		goto free_dev;

	ret = ummu_get_tid(entry->dev, NULL, &entry->tid);
	if (ret)
		goto disable_feat;

	ret = get_tid_res(entry);
	if (ret)
		goto disable_feat;

	return 0;

disable_feat:
	disable_dev_feat(entry->dev);
free_dev:
	ummu_core_free_tdev(entry->dev);
	return ret;
}

static int sva_mode_alloc_tid(struct proc_manager *manager,
			      struct ummu_tid_info *tid_data,
			      struct ktid_info **entry_out)
{
	struct ktid_info *entry;
	int sva_mode;
	u32 cnt;
	int ret;

	if (tid_data->mode >= MAPT_MODE_END)
		return -EINVAL;

	entry = kzalloc(sizeof(struct ktid_info), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	atomic_set(&entry->mmap_count, 0);
	entry->mode = tid_data->mode;
	entry->tid = UMMU_INVALID_TID;

	ret = get_hw_cap(&sva_mode, &entry->hw_cap);
	if (ret) {
		kfree(entry);
		return ret;
	}

	if (sva_mode == UMMU_SVA_SHARE_MODE)
		ret = user_mode_device_init(entry);
	else
		ret = sva_separated_mode_dev_init(entry);
	if (ret) {
		kfree(entry);
		return ret;
	}

	ret = xa_err(xa_store(&manager->tid_xa, entry->tid, entry, GFP_KERNEL));
	if (ret)
		goto uninit_dev;

	ret = get_ummu_cnt(entry, &cnt);
	if (ret)
		goto xa_erase;

	tid_data->pcmdq_order = entry->pcmdq_order;
	tid_data->pcplq_order = entry->pcplq_order;
	tid_data->blk_exp_size = entry->blk_exp_size;
	tid_data->tid = entry->tid;
	tid_data->mode = entry->mode;
	tid_data->ummu_cnt = cnt;
	tid_data->hw_cap = entry->hw_cap;

	*entry_out = entry;

	return 0;

xa_erase:
	xa_erase(&manager->tid_xa, entry->tid);
uninit_dev:
	release_tid_resource(entry);

	return ret;
}

static int sva_mode_free_tid(struct proc_manager *manager,
			     struct ummu_tid_info *tid_data)
{
	struct ktid_info *entry;

	entry = xa_load(&manager->tid_xa, tid_data->tid);
	if (!entry)
		return -EINVAL;

	/*
	 * Prevent FREE_TID while there are active mmaps.
	 * This ensures sva and dev remain valid for munmap to release
	 * block/queue resources.
	 */
	if (atomic_read(&entry->mmap_count) > 0)
		return -EBUSY;

	xa_erase(&manager->tid_xa, entry->tid);
	release_tid_resource(entry);
	return 0;
}

static int sva_mode_plbi(struct proc_manager *manager,
			 struct ummu_tid_info *tid_data, u32 cmd)
{
	struct iommu_plb_gather plb_gather = {0};
	struct iommu_domain *domain;
	struct ktid_info *entry;

	entry = xa_load(&manager->tid_xa, tid_data->tid);
	if (!entry)
		return -EINVAL;

	domain = entry->sva ? entry->sva->handle.domain :
		iommu_get_domain_for_dev(entry->dev);

	if (cmd == UMMU_IOCPLBI_VA) {
		iommu_plb_gather_init(&plb_gather);
		plb_gather.va = (void *)(uintptr_t)tid_data->va;
		plb_gather.size = tid_data->size;
		iommu_plb_sync(domain, &plb_gather);
	} else if (cmd == UMMU_IOCPLBI_ALL) {
		iommu_plb_sync_all(domain);
	}

	return 0;
}

static int alloc_tid_response(struct ummu_tid_info *tid_data,
			      unsigned long key, struct ktid_info *entry,
			      unsigned long arg)
{
	struct proc_manager *manager;
	int ret = 0;
	u32 err;

	err = copy_to_user((struct ummu_tid_info __user *)arg, tid_data,
			    sizeof(struct ummu_tid_info));
	if (err) {
		ret = -EFAULT;
		goto xa_erase;
	}

	return ret;
xa_erase:
	mutex_lock(&global_proc_mtx);
	manager = xa_load(&proc_info_xa, key);
	if (!manager) {
		mutex_unlock(&global_proc_mtx);
		return ret;
	}

	mutex_lock(&manager->proc_mtx);
	mutex_unlock(&global_proc_mtx);
	xa_erase(&manager->tid_xa, entry->tid);
	release_tid_resource(entry);
	mutex_unlock(&manager->proc_mtx);

	return ret;
}

static long tid_ioctl(struct file *filp, u32 cmd, unsigned long arg)
{
	unsigned long key = (unsigned long)(uintptr_t)filp->private_data;
	struct ummu_tid_info tid_data = {0};
	struct proc_manager *manager;
	struct ktid_info *entry;
	int ret;
	u32 err;

	err = copy_from_user(&tid_data, (struct ummu_tid_info __user *)arg,
			     sizeof(struct ummu_tid_info));
	if (err)
		return -EFAULT;

	mutex_lock(&global_proc_mtx);
	manager = xa_load(&proc_info_xa, key);
	if (!manager) {
		mutex_unlock(&global_proc_mtx);
		return -EINVAL;
	}

	mutex_lock(&manager->proc_mtx);
	mutex_unlock(&global_proc_mtx);
	switch (cmd) {
	case UMMU_IOCALLOC_TID:
		ret = sva_mode_alloc_tid(manager, &tid_data, &entry);
		break;
	case UMMU_IOCFREE_TID:
		ret = sva_mode_free_tid(manager, &tid_data);
		break;
	case UMMU_IOCPLBI_ALL:
	case UMMU_IOCPLBI_VA:
		ret = sva_mode_plbi(manager, &tid_data, cmd);
		break;
	default:
		ret = -EINVAL;
	}
	mutex_unlock(&manager->proc_mtx);

	if ((ret == 0) && (cmd == UMMU_IOCALLOC_TID))
		ret = alloc_tid_response(&tid_data, key, entry, arg);

	return ret;
}

static const struct file_operations misc_fops = {
	.owner = THIS_MODULE,
	.open = proc_manager_open,
	.release = proc_manager_close,
	.mmap = tid_map_resource,
	.unlocked_ioctl = tid_ioctl,
};

static struct miscdevice tid_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = TID_MISC_NAME,
	.fops = &misc_fops,
	.mode = 0666,
};

int tid_misc_init(void)
{
	return misc_register(&tid_misc_device);
}

void tid_misc_exit(void)
{
	misc_deregister(&tid_misc_device);
}
