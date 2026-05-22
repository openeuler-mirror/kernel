// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UBMEM-VMMU Device's Implementation
 */
#define pr_fmt(fmt) "UBMEM_VMMU: " fmt

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/iopoll.h>
#include <linux/err.h>
#include <linux/xarray.h>
#include <linux/ummu_core.h>
#include <ub/ubfi/ubfi.h>
#include <linux/hash.h>
#include <linux/hisi_ummu.h>
#include "../logic_ummu/logic_ummu.h"

/* ubmem_vmmu driver version release no. */
#define UBMEM_VMMU_DRV_VER_NO "01"
#define UBMEM_VMMU_DRV_NAME "ubmem_vmmu"
#define UBMEM_VMMU_PAGE_SIZE_4K (1UL << 12) // 4K
#define UBMEM_VMMU_ONCE_MAX_MAP_AREA_NUM 262144 // 1G
#define HASH_BUCKETS  64
#define POLL_DELAY_TIME_US 100
#define MAX_POLL_TIME_US 100000000
#define MAX_COUNT_FOR_GET_SLOT 10000000
#define MIN_PASIDS 65
#define MAX_PASIDS ((1UL << 20) - 1)

enum ubmem_vmmu_opcode {
	UBMEM_VMMU_OPCODE_MAP = 0,
	UBMEM_VMMU_OPCODE_UNMAP = 1,
	UBMEM_VMMU_OPCODE_DEFAULT = 2
};

struct ubm_request {
	u32 opcode;
	u32 tid;
	u64 uba;
	u64 size;
	u64 areas_num;
	struct {
		u64 gpa;
		u64 size;
	} areas[];
};

struct response_slot {
	union {
		struct {
			int state;
			int res;
		} inner;
		u64 val;
	};
};

struct ubmem_vmmu_device {
	struct ummu_core_device core_dev;
	struct device *dev;
	void __iomem *doorbell;
	void __iomem *rsp_slot;
	void __iomem *ring;
	unsigned long *slot_bitmap;
	u64 slot_num;
	u64 ring_size;
	u64 max_req_area_num;
	u64 max_req_size;
	u64 map_info_size;
	spinlock_t slot_lock;
};

struct ubmem_vmmu_map_info {
	struct list_head link;
	u64 start_areas_idx;
	struct ubm_request req;
};

struct ubmem_vmmu_map_ctx {
	struct ubmem_vmmu_map_info *last_map_info;
	struct list_head info_head;
	struct list_head link;
	pid_t pid;
	u64 uba_start;
	u64 uba_end;
	u32 tid;
};

struct ubmem_vmmu_domain {
	struct ubmem_vmmu_device *mmu;
	struct ummu_base_domain base_domain;
	struct {
		spinlock_t lock;
		struct list_head ctx_head;
	} map_hash[HASH_BUCKETS];
};

struct ubmem_vmmu_master {
	struct ubmem_vmmu_device *ubmem_vmmu_dev;
};

static struct ubmem_vmmu_device *global_ubmem_vmmu_dev;

static inline u32 pid_hash(pid_t pid)
{
	return hash_ptr((void *)((unsigned long)pid), ilog2(HASH_BUCKETS)) % HASH_BUCKETS;
}

static inline struct ubmem_vmmu_domain *to_ubmem_vmmu_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_domain =
		container_of(dom, struct ummu_base_domain, domain);
	return container_of(base_domain, struct ubmem_vmmu_domain, base_domain);
}

static bool ubmem_vmmu_support_call_back(struct tdev_attr *attr, bool *select)
{
	*select = false;

	return true;
}

static bool ubmem_vmmu_tdev_support_attr(struct ummu_core_device *core_device,
					struct tdev_attr *attr)
{
	struct hisi_ummu_tdev_info *info;

	if (!attr->priv || !attr->priv_len)
		return false;

	if (attr->priv_len < sizeof(struct hisi_ummu_tdev_info)) {
		pr_err("ubmem vmmu: para len is invalid: priv_len %u\n", attr->priv_len);
		return false;
	}

	info = (struct hisi_ummu_tdev_info *)attr->priv;
	if (info->v2.tid && info->v2.tid < core_device->iommu.min_pasids) {
		pr_info("ubmem vmmu: match success\n");
		return true;
	}

	pr_info("ubmem vmmu: mismatch, tid %u\n", info->v2.tid);
	return false;
}

static int ubmem_vmmu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct ubmem_vmmu_device *mmu_device =
		((struct ubmem_vmmu_master *)dev_iommu_priv_get(dev))->ubmem_vmmu_dev;
	struct ubmem_vmmu_domain *mmu_domain = to_ubmem_vmmu_domain(domain);
	u32 tid;
	int ret;

	pr_info("ubmem vmmu attach device\n");
	if (mmu_domain->mmu) {
		dev_err(dev, "attach failed, the domain has been occupied.\n");
		return -EEXIST;
	}
	if (!mmu_device) {
		dev_err(dev, "attach failed, find no ubmem device.\n");
		return -ENODEV;
	}

	ret = device_property_read_u32(dev, "assign-pasid", &tid);
	if (ret) {
		dev_err(dev, "attach failed, find no tid.\n");
		return -EINVAL;
	}

	mmu_domain->base_domain.tid = tid;
	mmu_domain->mmu = mmu_device;
	pr_info("ubmem vmmu attach device base_domain tid %u\n", tid);
	return 0;
}

static int ubmem_vmmu_handle_req_vm(struct ubm_request *req, u64 req_buf_size)
{
	struct ubmem_vmmu_device *ubmem_vmmu_dev = global_ubmem_vmmu_dev;
	u32 slot_idx, max_cnt = MAX_COUNT_FOR_GET_SLOT;
	struct response_slot rsp_info;
	void __iomem *addr;
	int ret;

	while (max_cnt) {
		spin_lock(&ubmem_vmmu_dev->slot_lock);
		slot_idx = find_first_zero_bit(ubmem_vmmu_dev->slot_bitmap,
					       ubmem_vmmu_dev->slot_num);
		if (slot_idx >= ubmem_vmmu_dev->slot_num) {
			spin_unlock(&ubmem_vmmu_dev->slot_lock);
			usleep_range(1, 2);
			max_cnt--;
			continue;
		}
		set_bit(slot_idx, ubmem_vmmu_dev->slot_bitmap);
		memcpy_toio(ubmem_vmmu_dev->ring, req, req_buf_size);
		iowrite32(slot_idx, ubmem_vmmu_dev->doorbell);
		spin_unlock(&ubmem_vmmu_dev->slot_lock);
		break;
	}
	if (!max_cnt) {
		pr_err("couldn't get slot, timeout!\n");
		return -ETIMEDOUT;
	}

	addr = ubmem_vmmu_dev->rsp_slot + slot_idx * sizeof(struct response_slot);
	ret = readq_relaxed_poll_timeout(addr, rsp_info.val, rsp_info.inner.state != 0,
					 POLL_DELAY_TIME_US, MAX_POLL_TIME_US);
	if (ret) {
		pr_err("couldn't get response status from qemu, timeout, ret %d!\n", ret);
		ret = -ETIMEDOUT;
		goto release_slot;
	}

	ret = rsp_info.inner.res;

release_slot:
	spin_lock(&ubmem_vmmu_dev->slot_lock);
	clear_bit(slot_idx, ubmem_vmmu_dev->slot_bitmap);
	spin_unlock(&ubmem_vmmu_dev->slot_lock);

	return ret;
}

static struct ubmem_vmmu_map_info *
ubmem_vmmu_create_map_info(struct ubmem_vmmu_map_ctx *map_ctx, u64 uba)
{
	struct ubmem_vmmu_map_info *map_info;

	map_info = vzalloc(global_ubmem_vmmu_dev->map_info_size);
	if (!map_info)
		return NULL;

	INIT_LIST_HEAD(&map_info->link);
	list_add_tail(&map_info->link, &map_ctx->info_head);
	map_info->start_areas_idx = 0;
	map_info->req.opcode = UBMEM_VMMU_OPCODE_MAP;
	map_info->req.tid = map_ctx->tid;
	map_info->req.uba = uba;
	map_info->req.size = 0;
	map_info->req.areas_num = 0;
	map_ctx->last_map_info = map_info;

	return map_info;
}

static struct ubmem_vmmu_map_ctx *
ubmem_vmmu_get_map_ctx(struct ubmem_vmmu_domain *mdom, u64 uba)
{
	struct ubmem_vmmu_map_info *map_info;
	struct ubmem_vmmu_map_ctx *map_ctx;
	pid_t pid = current->pid;
	u32 hash_idx = pid_hash(pid);

	spin_lock(&mdom->map_hash[hash_idx].lock);
	list_for_each_entry(map_ctx, &mdom->map_hash[hash_idx].ctx_head, link) {
		if (map_ctx->pid == pid && map_ctx->uba_end == uba) {
			spin_unlock(&mdom->map_hash[hash_idx].lock);
			return map_ctx;
		}
	}
	spin_unlock(&mdom->map_hash[hash_idx].lock);

	map_ctx = kzalloc(sizeof(struct ubmem_vmmu_map_ctx), GFP_KERNEL);
	if (!map_ctx)
		return NULL;

	pr_debug("ubm mmu map ctx, pid %d, hash_idx %u\n", pid, hash_idx);
	map_ctx->tid = mdom->base_domain.tid;
	map_ctx->pid = current->pid;
	map_ctx->uba_start = uba;
	map_ctx->last_map_info = NULL;
	INIT_LIST_HEAD(&map_ctx->link);
	INIT_LIST_HEAD(&map_ctx->info_head);

	map_info = ubmem_vmmu_create_map_info(map_ctx, uba);
	if (!map_info) {
		kfree(map_ctx);
		return NULL;
	}

	spin_lock(&mdom->map_hash[hash_idx].lock);
	list_add_tail(&map_ctx->link, &mdom->map_hash[hash_idx].ctx_head);
	spin_unlock(&mdom->map_hash[hash_idx].lock);
	return map_ctx;
}

static u64 ubmem_vmmu_add_map_info(struct ubmem_vmmu_map_ctx *map_ctx, u64 uba,
				   u64 paddr, u64 need_map_size)
{
	struct ubmem_vmmu_map_info *map_info = map_ctx->last_map_info;
	u64 map_size_per_map_info = need_map_size;
	u64 release_map_size;
	u64 cur_map_size = 0;
	u64 map_size = 0;
	u32 area_idx;

	while (1) {
		release_map_size = global_ubmem_vmmu_dev->max_req_size - map_info->req.size;
		cur_map_size = (release_map_size > map_size_per_map_info) ?
			       map_size_per_map_info : release_map_size;
		if (cur_map_size != 0) {
			area_idx = map_info->req.areas_num;
			map_info->req.areas[area_idx].gpa = paddr;
			map_info->req.areas[area_idx].size = cur_map_size;
			map_info->req.size += cur_map_size;
			map_info->req.areas_num += 1;
			map_size_per_map_info =
				(cur_map_size > map_size_per_map_info) ?
				0 : (map_size_per_map_info - cur_map_size);
			map_size += cur_map_size;
			if (map_size_per_map_info == 0)
				break;

			paddr += cur_map_size;
			uba += cur_map_size;
		}

		map_info = ubmem_vmmu_create_map_info(map_ctx, uba);
		if (!map_info)
			return map_size;
	}

	return map_size;
}

static int ubmem_vmmu_map_pages(struct iommu_domain *domain, unsigned long iova,
				   phys_addr_t paddr, size_t pgsize, size_t pgcount,
				   int prot, gfp_t gfp, size_t *mapped)
{
	struct ubmem_vmmu_domain *mdom = to_ubmem_vmmu_domain(domain);
	struct ubmem_vmmu_map_info *map_info, *tmp_info;
	struct ubmem_vmmu_map_ctx *map_ctx;
	size_t expect_size = pgsize * pgcount;
	pid_t pid = current->pid;
	u32 hash_idx = pid_hash(pid);
	u64 map_size;

	map_ctx = ubmem_vmmu_get_map_ctx(mdom, iova);
	if (!map_ctx)
		return -ENOMEM;

	map_size = ubmem_vmmu_add_map_info(map_ctx, iova, paddr, expect_size);
	pr_debug("vmmu map pages, map_size 0x%llx, request map size 0x%zx\n",
		 map_size, expect_size);
	if (map_size != expect_size) {
		*mapped = 0;
		pr_err("failed to add map info, map_size 0x%llx, request map size 0x%zx\n",
		       map_size, expect_size);
		list_for_each_entry_safe(map_info, tmp_info, &map_ctx->info_head, link) {
			list_del_init(&map_info->link);
			vfree(map_info);
		}

		spin_lock(&mdom->map_hash[hash_idx].lock);
		list_del_init(&map_ctx->link);
		spin_unlock(&mdom->map_hash[hash_idx].lock);
		kfree(map_ctx);
		return -ENOMEM;
	}

	map_ctx->uba_end = iova + map_size;
	*mapped = map_size;
	return 0;
}

static size_t ubmem_vmmu_unmap_pages(struct iommu_domain *domain,
					unsigned long iova, size_t pgsize,
					size_t pgcount,
					struct iommu_iotlb_gather *gather)
{
	struct ubmem_vmmu_domain *mdom = to_ubmem_vmmu_domain(domain);
	size_t unmap_size = pgsize * pgcount;
	struct ubm_request *req;
	int ret;

	u64 req_buf_size = sizeof(struct ubm_request) + sizeof(((struct ubm_request *)0)->areas[0]);

	req = kzalloc(req_buf_size, GFP_KERNEL);
	if (!req)
		return 0;

	req->opcode = UBMEM_VMMU_OPCODE_UNMAP;
	req->tid = mdom->base_domain.tid;
	req->uba = iova;
	req->size = unmap_size;
	req->areas_num = 1;
	req->areas[0].gpa = 0;
	req->areas[0].size = req->size;

	ret = ubmem_vmmu_handle_req_vm(req, req_buf_size);
	if (ret) {
		pr_err("failed to handle ubm_request, ret %d, tid %u, opcode %u, size 0x%llx\n",
		       ret, req->tid, req->opcode, req->size);
		kfree(req);
		return 0;
	}

	kfree(req);
	return unmap_size;
}

static int ubmem_vmmu_iotlb_sync_map(struct iommu_domain *domain,
					unsigned long iova, size_t size)
{
	struct ubmem_vmmu_domain *mdom = to_ubmem_vmmu_domain(domain);
	struct ubmem_vmmu_map_info *map_info, *tmp_info;
	struct ubmem_vmmu_map_ctx *map_ctx, *tmp_ctx;
	pid_t pid = current->pid;
	u32 hash_idx = pid_hash(pid);
	u64 iova_end = iova + size;
	bool ctx_match = false;
	u64 req_buf_size;
	int ret;

	pr_debug("vmmu iotlb sync map, size 0x%zx, pid %d, hash_idx %u\n", size, pid, hash_idx);

	spin_lock(&mdom->map_hash[hash_idx].lock);
	list_for_each_entry_safe(map_ctx, tmp_ctx, &mdom->map_hash[hash_idx].ctx_head, link) {
		if (map_ctx->pid == pid && map_ctx->uba_start == iova &&
		    map_ctx->uba_end == iova_end) {
			list_del_init(&map_ctx->link);
			ctx_match = true;
			break;
		}
	}
	spin_unlock(&mdom->map_hash[hash_idx].lock);

	if (ctx_match) {
		ret = 0;
		list_for_each_entry_safe(map_info, tmp_info, &map_ctx->info_head, link) {
			if (ret == 0) {
				req_buf_size = sizeof(struct ubm_request) +
					       sizeof(((struct ubm_request *)0)->areas[0]) *
					       map_info->req.areas_num;
				ret = ubmem_vmmu_handle_req_vm(&map_info->req, req_buf_size);
				if (ret)
					pr_err("failed to handle ubm_request, ret %d, tid %u, opcode %u, size 0x%llx\n",
						ret, map_info->req.tid, map_info->req.opcode,
						map_info->req.size);
			}
			list_del_init(&map_info->link);
			vfree(map_info);
		}
		kfree(map_ctx);
	}

	return ret;
}

static void ubmem_vmmu_domain_free(struct iommu_domain *domain)
{
	struct ubmem_vmmu_domain *mmu_domain = to_ubmem_vmmu_domain(domain);

	kfree(mmu_domain);
}

static struct ubmem_vmmu_domain *ubmem_vmmu_domain_alloc_helper(unsigned int type)
{
	struct ubmem_vmmu_domain *ubmem_vmmu_dom;
	u32 i;

	ubmem_vmmu_dom = kzalloc(sizeof(struct ubmem_vmmu_domain), GFP_KERNEL);
	if (!ubmem_vmmu_dom)
		return NULL;

	for (i = 0; i < HASH_BUCKETS; i++) {
		spin_lock_init(&ubmem_vmmu_dom->map_hash[i].lock);
		INIT_LIST_HEAD(&ubmem_vmmu_dom->map_hash[i].ctx_head);
	}
	ubmem_vmmu_dom->base_domain.tid = UMMU_INVALID_TID;
	return ubmem_vmmu_dom;
}

static struct iommu_domain *ubmem_vmmu_domain_alloc(unsigned int type)
{
	struct ubmem_vmmu_domain *ubmem_vmmu_dom;

	switch (type) {
	case IOMMU_DOMAIN_DMA:
	case IOMMU_DOMAIN_DMA_FQ:
		ubmem_vmmu_dom = ubmem_vmmu_domain_alloc_helper(type);
		if (!ubmem_vmmu_dom) {
			pr_err("Failed to allocate ubmem vmmu domain\n");
			return (struct iommu_domain *)ERR_PTR(-ENOMEM);
		}
		break;
	default:
		return (struct iommu_domain *)ERR_PTR(-EINVAL);
	}

	return &ubmem_vmmu_dom->base_domain.domain;
}

static struct iommu_device *ubmem_vmmu_probe_device(struct device *dev)
{
	struct ubmem_vmmu_device *ubmem_vmmu_dev = global_ubmem_vmmu_dev;
	struct iommu_fwspec *dev_iommu_fwspec;
	struct fwnode_handle *iommu_fwnode;
	struct ubmem_vmmu_master *master;

	dev_iommu_fwspec = dev_iommu_fwspec_get(dev);
	if (!dev_iommu_fwspec)
		return (struct iommu_device *)ERR_PTR(-ENODEV);

	iommu_fwnode = dev_iommu_fwspec->iommu_fwnode;
	if (!iommu_fwnode) {
		pr_err("ubm mmu probe device iommu_fwnode not exist!\n");
		return (struct iommu_device *)ERR_PTR(-ENODEV);
	}

	if (ubmem_vmmu_dev->core_dev.iommu.fwnode != iommu_fwnode) {
		pr_err("ubm mmu probe device %s failed, fwnode is not match!\n", dev_name(dev));
		return (struct iommu_device *)ERR_PTR(-ENODEV);
	}

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return (struct iommu_device *)ERR_PTR(-ENOMEM);

	master->ubmem_vmmu_dev = ubmem_vmmu_dev;
	dev_iommu_priv_set(dev, master);
	pr_info("ubm mmu probe device %s successful!\n", dev_name(dev));
	return &ubmem_vmmu_dev->core_dev.iommu;
}

static void ubmem_vmmu_release_device(struct device *dev)
{
	struct ubmem_vmmu_master *master = (struct ubmem_vmmu_master *)dev_iommu_priv_get(dev);

	dev_iommu_priv_set(dev, NULL);
	kfree(master);
}

static struct iommu_group *ubmem_vmmu_device_group(struct device *dev)
{
	return generic_device_group(dev);
}

static struct ummu_core_ops ubmem_vmmu_core_ops = {
	.tdev_support_attr = ubmem_vmmu_tdev_support_attr,
};

const struct iommu_domain_ops ubmem_vmmu_domain_ops = {
	.attach_dev = ubmem_vmmu_attach_dev,
	.map_pages = ubmem_vmmu_map_pages,
	.unmap_pages = ubmem_vmmu_unmap_pages,
	.iotlb_sync_map = ubmem_vmmu_iotlb_sync_map,
	.iotlb_sync = NULL,
	.free = ubmem_vmmu_domain_free,
};

const struct iommu_ops ubmem_vmmu_iommu_ops = {
	.domain_alloc = ubmem_vmmu_domain_alloc,
	.probe_device = ubmem_vmmu_probe_device,
	.release_device = ubmem_vmmu_release_device,
	.device_group = ubmem_vmmu_device_group,
	.default_domain_ops = &ubmem_vmmu_domain_ops,
	.pgsize_bitmap = -1UL,
	.owner = THIS_MODULE,
};

static void ubmem_vmmu_device_ubrt_probe(struct ubmem_vmmu_device *ubmem_vmmu)
{
	ubmem_vmmu->core_dev.iommu.min_pasids = MIN_PASIDS;
	ubmem_vmmu->core_dev.iommu.max_pasids = MAX_PASIDS;
}

static int ubmem_vmmu_init_ummu_device(struct ubmem_vmmu_device *ubmem_vmmu,
				const struct iommu_ops *iommu_ops,
				const struct ummu_core_ops *core_ops)
{
	struct ummu_core_init_args args = { 0 };

	args.iommu_ops = iommu_ops;
	args.core_ops = core_ops;
	args.hwdev = ubmem_vmmu->dev;
	args.tid_args.tid_ops = NULL;

	return ummu_core_device_init(&ubmem_vmmu->core_dev, &args);
}

static int ubmem_vmmu_init_device_resource(struct platform_device *pdev,
					   struct ubmem_vmmu_device *ubmem_vmmu)
{
	u32 slot_size, bitmap_size, area_num;
	struct device *dev = &pdev->dev;
	struct resource *res;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (unlikely(res == NULL)) {
		dev_err(dev, "IO resource 0 is null\n");
		return -EINVAL;
	}

	ubmem_vmmu->doorbell = devm_ioremap_resource(ubmem_vmmu->dev, res);
	if (IS_ERR(ubmem_vmmu->doorbell)) {
		dev_err(dev, "IO resource doorbell ioremap error\n");
		return PTR_ERR(ubmem_vmmu->doorbell);
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (unlikely(res == NULL)) {
		dev_err(dev, "IO resource 1 is null\n");
		return -EINVAL;
	}

	ubmem_vmmu->rsp_slot = devm_ioremap_resource(ubmem_vmmu->dev, res);
	if (IS_ERR(ubmem_vmmu->rsp_slot)) {
		dev_err(dev, "IO resource rsp_slot ioremap error\n");
		return PTR_ERR(ubmem_vmmu->rsp_slot);
	}

	ubmem_vmmu->slot_num = ioread64(ubmem_vmmu->rsp_slot);
	ubmem_vmmu->rsp_slot += sizeof(u64);
	slot_size = sizeof(struct response_slot) * ubmem_vmmu->slot_num;
	ubmem_vmmu->ring = ubmem_vmmu->rsp_slot + slot_size;
	ubmem_vmmu->ring_size = (res->end - res->start) - (slot_size + sizeof(u64));
	area_num = (ubmem_vmmu->ring_size - sizeof(struct ubm_request)) /
		   sizeof(((struct ubm_request *)0)->areas[0]);
	ubmem_vmmu->max_req_area_num = (area_num > UBMEM_VMMU_ONCE_MAX_MAP_AREA_NUM) ?
				       UBMEM_VMMU_ONCE_MAX_MAP_AREA_NUM : area_num;
	ubmem_vmmu->max_req_size = ubmem_vmmu->max_req_area_num * UBMEM_VMMU_PAGE_SIZE_4K;
	ubmem_vmmu->map_info_size =
	sizeof(struct ubmem_vmmu_map_info) +
	sizeof(((struct ubm_request *)0)->areas[0]) * ubmem_vmmu->max_req_area_num;
	spin_lock_init(&ubmem_vmmu->slot_lock);

	pr_info("ubmem_vmmu_test max_req_area_num %llu, max_req_size %llu, slot_num %llu, ring_size %llu\n",
		ubmem_vmmu->max_req_area_num, ubmem_vmmu->max_req_size,
		ubmem_vmmu->slot_num, ubmem_vmmu->ring_size);

	bitmap_size = BITS_TO_COMPAT_LONGS(ubmem_vmmu->slot_num);
	ubmem_vmmu->slot_bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (ubmem_vmmu->slot_bitmap == NULL) {
		dev_err(dev, "Alloc bitmap failed, size %u\n", bitmap_size);
		return -ENOMEM;
	}

	return 0;
}

static int ubmem_vmmu_device_probe(struct platform_device *pdev)
{
	struct ubmem_vmmu_device *ubmem_vmmu;
	struct device *dev = &pdev->dev;
	int ret = 0;

	ubmem_vmmu = devm_kzalloc(dev, sizeof(*ubmem_vmmu), GFP_KERNEL);
	if (!ubmem_vmmu)
		return -ENOMEM;

	ubmem_vmmu->dev = dev;

	ubmem_vmmu_device_ubrt_probe(ubmem_vmmu);

	ret = ubmem_vmmu_init_device_resource(pdev, ubmem_vmmu);
	if (ret) {
		dev_err(dev, "io device resource is null\n");
		return ret;
	}

	platform_set_drvdata(pdev, ubmem_vmmu);

	ret = ubmem_vmmu_init_ummu_device(ubmem_vmmu, &ubmem_vmmu_iommu_ops, &ubmem_vmmu_core_ops);
	if (ret) {
		dev_err(dev, "setup ubmem_vmmu device failed, ret: %d.\n", ret);
		goto bitmap_free;
	}

	ret = iommu_device_sysfs_add(&ubmem_vmmu->core_dev.iommu, ubmem_vmmu->dev, NULL,
					"ubmem_vmmu_%s", dev_name(ubmem_vmmu->dev));
	if (ret) {
		dev_err(dev, "add sysfs failed, ret=%d\n", ret);
		goto deinit_ummu_core;
	}

	ret = ummu_core_device_register(&ubmem_vmmu->core_dev, REGISTER_TYPE_NORMAL);
	if (ret) {
		dev_err(dev, "register to ummu core failed, ret=%d\n", ret);
		goto remove_sysfs;
	}

	ret = logic_ummu_register_support_attr(ubmem_vmmu_support_call_back);
	if (ret) {
		dev_err(dev, "register support attr to logic ummu failed, ret=%d\n", ret);
		goto register_scb_err;
	}

	global_ubmem_vmmu_dev = ubmem_vmmu;
	dev_info(dev, "register ubmem_vmmu to ummu core success");
	return 0;

register_scb_err:
	ummu_core_device_unregister(&ubmem_vmmu->core_dev);
remove_sysfs:
	iommu_device_sysfs_remove(&ubmem_vmmu->core_dev.iommu);
deinit_ummu_core:
	ummu_core_device_deinit(&ubmem_vmmu->core_dev);
bitmap_free:
	kfree(ubmem_vmmu->slot_bitmap);

	return ret;
}

static int ubmem_vmmu_device_remove(struct platform_device *pdev)
{
	struct ubmem_vmmu_device *ubmem_vmmu = platform_get_drvdata(pdev);

	if (!ubmem_vmmu) {
		pr_err("device remove get invalid platform device!\n");
		return -ENODEV;
	}
	logic_ummu_unregister_support_attr(ubmem_vmmu_support_call_back);
	ummu_core_device_unregister(&ubmem_vmmu->core_dev);
	iommu_device_sysfs_remove(&ubmem_vmmu->core_dev.iommu);
	ummu_core_device_deinit(&ubmem_vmmu->core_dev);
	kfree(ubmem_vmmu->slot_bitmap);
	ubmem_vmmu->slot_bitmap = NULL;
	global_ubmem_vmmu_dev = NULL;
	dev_info(&pdev->dev, "remove ubmem vmmu successful!\n");
	return 0;
}

static const struct of_device_id hisi_ubmem_vmmu_of_match[] = {
	{ .compatible = "hisi,ubmem_vmmu", },
	{ },
};
MODULE_DEVICE_TABLE(of, hisi_ubmem_vmmu_of_match);

static const struct acpi_device_id hisi_ubmem_vmmu_acpi_match[] = {
	{"HISI0591", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_ubmem_vmmu_acpi_match);

struct platform_driver ubmem_vmmu_driver = {
	.driver = {
		.name = UBMEM_VMMU_DRV_NAME,
		.suppress_bind_attrs = true,
		.of_match_table = hisi_ubmem_vmmu_of_match,
		.acpi_match_table = hisi_ubmem_vmmu_acpi_match,
	},
	.probe = ubmem_vmmu_device_probe,
	.remove = ubmem_vmmu_device_remove,
};

static int __init ubmem_vmmu_driver_register(struct platform_driver *drv)
{
	return platform_driver_register(drv);
}

static void __exit ubmem_vmmu_driver_unregister(struct platform_driver *drv)
{
	platform_driver_unregister(drv);
}

module_driver(ubmem_vmmu_driver, ubmem_vmmu_driver_register, ubmem_vmmu_driver_unregister);

MODULE_IMPORT_NS(UMMU_CORE_DRIVER);
MODULE_IMPORT_NS(UMMU_INTERNAL);
MODULE_DESCRIPTION("Hisilicon ubmem vmmu driver");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" UBMEM_VMMU_DRV_NAME);
