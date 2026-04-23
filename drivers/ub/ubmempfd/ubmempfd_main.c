// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description：UBM MAPPING CORE API
 */
#define pr_fmt(fmt) "UBMEMPFD: " fmt

#include <linux/module.h>
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
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <asm/page.h>
#include <linux/ummu_core.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/hisi_ummu.h>
#include <uapi/ub/ubmempfd/ubmempfd.h>

#define UBMEMPFD_MISC_NAME "ubmempfd"
#define UBMEMPFD_MAX_SIZE 0x80000000
#define UBMEMPFD_MAX_AREA_NUM 262144

struct ubmempfd_ctx {
	struct rw_semaphore mapping_wr_lock;
	struct device *dev;
	struct iommu_domain *domain;
	bool work_state;
};

static u64 ubmempfd_get_max_area_size(struct ubm_request *req)
{
	u64 max_area_size = 0;
	int i;

	for (i = 0; i < req->areas_num; i++) {
		if (req->areas[i].size > max_area_size)
			max_area_size = req->areas[i].size;
	}

	return max_area_size;
}

static int ubmempfd_get_pages(u64 start, u64 page_num, int flags, struct page **pages)
{
	int ret;

	ret = get_user_pages_fast(start, page_num, FOLL_GET, pages);
	if (ret < 0 || ret > page_num)
		return -EINVAL;

	if (ret != page_num) {
		pr_err("Failed to get all pages, get %d, expect %llu\n", ret, page_num);
		for (int i = 0; i < ret; i++)
			put_page(pages[i]);
		return -EBUSY;
	}

	return 0;
}

static int ubmempfd_map_single_area(struct iommu_domain *domain, phys_addr_t *last_hpa,
	u64 *map_size, u64 *uba_start, u64 page_num, struct page **pages)
{
	phys_addr_t hpa;
	int ret;

	for (int j = 0; j < page_num; j++) {
		hpa = page_to_phys(pages[j]);
		put_page(pages[j]);

		if (*last_hpa == 0) {
			*last_hpa = hpa;
			*map_size += PAGE_SIZE;
			continue;
		}

		if (*last_hpa + *map_size == hpa) {
			*map_size += PAGE_SIZE;
			continue;
		}

		ret = iommu_map(domain, *uba_start, *last_hpa, *map_size,
				IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
		if (ret != 0) {
			for (int i = j + 1; i < page_num; i++)
				put_page(pages[i]);

			return ret;
		}
		*uba_start += *map_size;
		*last_hpa = hpa;
		*map_size = PAGE_SIZE;
	}

	return 0;
}

static int ubmempfd_do_iommu_map(struct iommu_domain *domain, struct ubm_request *req)
{
	u64 max_area_size = 0, page_num = 0, map_size = 0, uba_start;
	phys_addr_t last_hpa = 0;
	struct page **pages;
	int ret = 0;
	u32 i;

	max_area_size = ubmempfd_get_max_area_size(req);

	pages = vmalloc(sizeof(struct page *) * max_area_size / PAGE_SIZE);
	if (!pages)
		return -ENOMEM;

	uba_start = req->uba;
	for (i = 0; i < req->areas_num; i++) {
		page_num = req->areas[i].size / PAGE_SIZE;
		ret = ubmempfd_get_pages(req->areas[i].hva & PAGE_MASK, page_num, FOLL_GET, pages);
		if (ret)
			goto err;

		ret = ubmempfd_map_single_area(domain, &last_hpa, &map_size,
					       &uba_start, page_num, pages);
		if (ret) {
			pr_err("Failed to do iommu map area_idx = %u, ret = %d\n", i, ret);
			goto err;
		}
	}

	ret = iommu_map(domain, uba_start, last_hpa, map_size,
			IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
	if (ret != 0) {
		pr_err("Failed to do tail iommu map, ret = %d\n", ret);
		goto err;
	}
	uba_start += map_size;

err:
	vfree(pages);
	if (uba_start - req->uba != req->size) {
		pr_err("iommu map size match failed expect size = %llu, mapped size = %llu, ret %d.\n",
		       req->size, uba_start - req->uba, ret);
		iommu_unmap(domain, uba_start, uba_start - req->uba);
	}

	return ret;
}

static int ubmempfd_do_iommu_unmap(struct iommu_domain *domain, struct ubm_request *req)
{
	size_t unmap_size;
	u64 uba_start;
	u32 i;

	uba_start = req->uba;
	for (i = 0; i < req->areas_num; i++) {
		unmap_size = iommu_unmap(domain, uba_start, req->areas[i].size);
		if (unmap_size != req->areas[i].size) {
			pr_err("Failed to do iommu unmap, unmap_size %zu, expect size %llu\n",
			       unmap_size, req->areas[i].size);
			return -EINVAL;
		}
		uba_start += req->areas[i].size;
	}

	return 0;
}

static int ubmempfd_info_check(struct ubmempfd_ctx *ctx, struct ubm_request *req)
{
	u64 req_uba_area_size = 0;
	u64 addr;
	u64 size;
	u32 i;

	for (i = 0; i < req->areas_num; i++) {
		addr = req->areas[i].hva;
		size = req->areas[i].size;
		if (!size || size > UBMEMPFD_MAX_SIZE) {
			pr_err("Invalid size.\n");
			return -EINVAL;
		}
		if (!(IS_ALIGNED(addr, PAGE_SIZE) && IS_ALIGNED(size, PAGE_SIZE))) {
			pr_err("Address or size not aligned to PAGE_SIZE\n");
			return -EINVAL;
		}
		req_uba_area_size += size;
	}

	if (req_uba_area_size != req->size) {
		pr_err("Failed to check map size, uba size %llu, areas size %llu\n",
		       req->size, req_uba_area_size);
		return -EINVAL;
	}

	return 0;
}

static int ubmempfd_do_map(struct ubmempfd_ctx *ctx, struct ubm_request *req)
{
	int ret;

	ret = ubmempfd_info_check(ctx, req);
	if (ret)
		return ret;

	ret = ubmempfd_do_iommu_map(ctx->domain, req);
	if (ret != 0) {
		pr_err("Failed to do iommu map, ret %d\n", ret);
		return ret;
	}

	return 0;
}

static int ubmempfd_do_unmap(struct ubmempfd_ctx *ctx, struct ubm_request *req)
{
	return ubmempfd_do_iommu_unmap(ctx->domain, req);
}

static int ubmempfd_alloc_tdev(struct ubmempfd_ctx *ctx, u32 tid)
{
	struct hisi_ummu_tdev_info info;
	struct iommu_domain *domain;
	struct tdev_attr attr;
	struct device *dev;

	attr.name = NULL;
	attr.dma_attr = DEV_DMA_COHERENT;
	attr.priv = (u8 *)&info;
	attr.priv_len = sizeof(info);
	attr.mode = MAPT_MODE_END;
	attr.usva = false;
	info.v2.on_chip = false;
	info.v2.tid = tid;

	if (ctx->dev) {
		pr_info("ummu dev exists, tid %u\n", tid);
		return 0;
	}

	dev = ummu_core_alloc_tdev(&attr, &tid);
	if (!dev) {
		pr_err("Failed to create UMMU device, tid %u\n", tid);
		return -EPERM;
	}

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		pr_err("Failed to get UMMU device domain, tid %u\n", tid);
		ummu_core_free_tdev(dev);
		return -EPERM;
	}

	ctx->dev = dev;
	ctx->domain = domain;
	return 0;
}

static int ubmempfd_open(struct inode *inode, struct file *filp)
{
	struct ubmempfd_ctx *ctx = kzalloc(sizeof(struct ubmempfd_ctx), GFP_KERNEL);

	if (!ctx)
		return -ENOMEM;

	init_rwsem(&ctx->mapping_wr_lock);
	ctx->dev = NULL;
	ctx->domain = NULL;
	ctx->work_state = true;
	filp->private_data = (void *)ctx;
	pr_info("ubmempfd open, pid %d, comm %s\n", current->pid, current->comm);
	return 0;
}

static int ubmempfd_check_req(const char __user *buf, size_t count)
{
	size_t req_len = sizeof(struct ubm_request);
	struct ubm_request req;

	if (count < req_len) {
		pr_err("Invalid count\n");

		return -EINVAL;
	}

	if (copy_from_user(&req, buf, req_len)) {
		pr_err("Failed to copy ubm request from user, size %zu\n", req_len);
		return -EFAULT;
	}

	if (req.areas_num > UBMEMPFD_MAX_AREA_NUM ||
	    sizeof(((struct ubm_request *)0)->areas[0]) * req.areas_num != count - req_len) {
		pr_err("Failed to check req size, req size %zu, areas num %llu\n",
		       count, req.areas_num);
		return -EINVAL;
	}

	return 0;
}

static ssize_t ubmempfd_write(struct file *filp, const char __user *buf,
			      size_t count, loff_t *f_pos)
{
	struct ubmempfd_ctx *ctx;
	struct ubm_request *req;
	int ret;

	ctx = (struct ubmempfd_ctx *)filp->private_data;
	if (!ctx) {
		pr_err("Invalid ctx\n");
		return -EINVAL;
	}

	ret = ubmempfd_check_req(buf, count);
	if (ret)
		return ret;

	req = vzalloc(count);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, buf, count)) {
		pr_err("Failed to copy ubm request from user, size %zu\n", count);
		ret = -EFAULT;
		goto free_req;
	}

	if (ctx->work_state && !ctx->dev) {
		down_write(&ctx->mapping_wr_lock);
		ret = ubmempfd_alloc_tdev(ctx, req->tid);
		up_write(&ctx->mapping_wr_lock);
		if (ret)
			goto free_req;
	}

	down_read(&ctx->mapping_wr_lock);
	switch (req->opcode) {
	case UBMEMPFD_OPCODE_MAP:
		ret = ubmempfd_do_map(ctx, req);
		break;
	case UBMEMPFD_OPCODE_UNMAP:
		ret = ubmempfd_do_unmap(ctx, req);
		break;
	default:
		pr_err("Failed to get right opcode, opcode %u\n", req->opcode);
		ret = -EINVAL;
	}
	up_read(&ctx->mapping_wr_lock);

free_req:
	vfree(req);

	return (ret == 0) ? count : ret;
}

static int ubmempfd_close(struct inode *inode, struct file *filp)
{
	struct ubmempfd_ctx *ctx;

	ctx = (struct ubmempfd_ctx *)filp->private_data;
	if (!ctx)
		return 0;

	down_write(&ctx->mapping_wr_lock);
	if (ctx->dev) {
		ummu_core_free_tdev(ctx->dev);
		ctx->dev = NULL;
		ctx->domain = NULL;
	}
	ctx->work_state = false;
	filp->private_data = NULL;
	up_write(&ctx->mapping_wr_lock);
	kfree(ctx);

	pr_info("ubmempfd close, pid %d, comm %s\n", current->pid, current->comm);
	return 0;
}

static const struct file_operations ubmempfd_misc_fops = {
	.owner = THIS_MODULE,
	.open = ubmempfd_open,
	.release = ubmempfd_close,
	.write = ubmempfd_write,
};

static struct miscdevice ubmempfd_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = UBMEMPFD_MISC_NAME,
	.fops = &ubmempfd_misc_fops,
	.mode = 0666,
};

static int __init ubmempfd_core_init(void)
{
	return misc_register(&ubmempfd_misc_device);
}

static void __exit ubmempfd_core_exit(void)
{
	misc_deregister(&ubmempfd_misc_device);
}

module_init(ubmempfd_core_init);
module_exit(ubmempfd_core_exit);

MODULE_DESCRIPTION("Hisilicon UB Memory Provider File Descriptor Driver For Qemu");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
