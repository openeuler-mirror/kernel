// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/wait.h>
#include <linux/mmzone.h>

#include <uapi/linux/sched/types.h>

#include <uapi/ub/obmm.h>
#include <linux/ummu_core.h>

#include "conti_mem_allocator.h"
#include "ubmempool_allocator.h"
#include "obmm_core.h"
#include "obmm_cache.h"
#include "obmm_export.h"
#include "obmm_shm_dev.h"

int export_flags_to_region_flags(unsigned long *region_flags, unsigned long user_flags)
{
	*region_flags = 0;

	if (user_flags & (~OBMM_EXPORT_FLAG_MASK)) {
		pr_err("undefined flags specified in export flags parameter %#lx.\n", user_flags);
		return -EINVAL;
	}
	if (user_flags & OBMM_EXPORT_FLAG_ALLOW_MMAP)
		*region_flags |= OBMM_REGION_FLAG_ALLOW_MMAP;
	if (user_flags & OBMM_EXPORT_FLAG_FAST)
		*region_flags |= OBMM_REGION_FLAG_FAST_ALLOC;

	return 0;
}
static int fill_ummu_info(struct tdev_attr *attr, struct obmm_export_region *e_reg)
{
	tdev_attr_init(attr);
	attr->name = (char *)"OBMM_TDEV";
	if (e_reg->vendor_len > 0) {
		attr->priv = kmemdup(e_reg->vendor_info, e_reg->vendor_len, GFP_KERNEL);
		if (!attr->priv)
			return -ENOMEM;
	}
	attr->priv_len = e_reg->vendor_len;
	return 0;
}

static void drain_ummu_info(struct tdev_attr *attr)
{
	kfree(attr->priv);
}

static int setup_ummu(struct obmm_export_region *e_reg)
{
	struct tdev_attr attr;
	uint32_t tokenid = UMMU_INVALID_TID;
	int retval;

	retval = fill_ummu_info(&attr, e_reg);
	if (retval)
		return retval;

	/* register the memory region through UMMU */
	pr_debug("call ummu_core_alloc_tdev(), priv_len=%u, tid=%u\n", attr.priv_len, tokenid);
	e_reg->ummu_dev = ummu_core_alloc_tdev(&attr, &tokenid);
	if (e_reg->ummu_dev == NULL) {
		pr_err("Failed to create UMMU device\n");
		retval = -EPERM;
		goto out_drain_info;
	}
	e_reg->tokenid = tokenid;
	pr_debug("ummu_core_alloc_tdev() returned ummu_dev: tid=%u, name=%s\n", tokenid,
		 dev_name(e_reg->ummu_dev));

	/* DMA mapping */
	pr_debug("call dma_map_sgtable(..., dir=DMA_BIDIRECTIONAL, attrs=0)\n");
	retval = dma_map_sgtable(e_reg->ummu_dev, &e_reg->sgt, DMA_BIDIRECTIONAL, 0);
	if (retval) {
		pr_err("Failed to map sgtable on UMMU. ret=%pe\n", ERR_PTR(retval));
		goto out_free_device;
	}
	pr_debug("dma_map_sgtable returned 0\n");

	e_reg->uba = sg_dma_address(e_reg->sgt.sgl);
	drain_ummu_info(&attr);
	return 0;

out_free_device:
	if (ummu_core_free_tdev(e_reg->ummu_dev))
		pr_warn("Failed to create memory region but unable to cleanup allocated UMMU device\n");
out_drain_info:
	drain_ummu_info(&attr);
	return retval;
}

static int teardown_ummu(struct obmm_export_region *e_reg)
{
	int ret, rollback_ret;

	pr_debug("call external: dma_unmap_sgtable\n");
	dma_unmap_sgtable(e_reg->ummu_dev, &e_reg->sgt, DMA_BIDIRECTIONAL, 0);

	pr_debug("call external: ummu_core_free_tdev()\n");
	ret = ummu_core_free_tdev(e_reg->ummu_dev);
	if (ret) {
		pr_err("Failed to free UMMU tdev, ret=%pe.\n", ERR_PTR(ret));
		goto err_free_tdev;
	}

	return 0;

err_free_tdev:

	rollback_ret = dma_map_sgtable(e_reg->ummu_dev, &e_reg->sgt, DMA_BIDIRECTIONAL, 0);
	if (rollback_ret) {
		pr_err("Failed to map sgtable on UMMU. ret=%pe\n", ERR_PTR(rollback_ret));
		ret = -ENOTRECOVERABLE;
	}
	if (e_reg->uba != sg_dma_address(e_reg->sgt.sgl)) {
		pr_err("Tried remapping in UMMU on rollback but UBA changed.\n");
		ret = -ENOTRECOVERABLE;
		pr_debug("call external: dma_unmap_sgtable\n");
		dma_unmap_sgtable(e_reg->ummu_dev, &e_reg->sgt, DMA_BIDIRECTIONAL, 0);
	}
	return ret;
}

/* Make sure the memory to be exported is in properly allocated and ready to be mapped by UMMU.
 * The detailed information of the memory should be put in place in e_reg->sgt
 */
static int alloc_export_memory(struct obmm_export_region *e_reg)
{
	if (region_memory_from_user(&e_reg->region))
		return alloc_export_memory_pid(e_reg);
	else
		return alloc_export_memory_pool(e_reg);
}

static void free_export_memory_pool(struct obmm_export_region *e_reg)
{
	sg_free_table(&e_reg->sgt);
	free_memory_contiguous(&e_reg->mem_desc);
}

static void free_export_memory(struct obmm_export_region *e_reg)
{
	if (region_memory_from_user(&e_reg->region))
		free_export_memory_pid(e_reg);
	else
		free_export_memory_pool(e_reg);
}

/* Ensure all user inputs are properly converted and filled into the region. */
int obmm_export_common(struct obmm_export_region *e_reg)
{
	int ret;

	ret = alloc_export_memory(e_reg);
	if (ret)
		return ret;

	ret = setup_ummu(e_reg);
	if (ret)
		goto free_memory;

	return 0;

free_memory:
	free_export_memory(e_reg);

	return ret;
}

int obmm_unexport_common(struct obmm_export_region *e_reg)
{
	int ret;

	ret = teardown_ummu(e_reg);
	if (ret)
		return ret;
	free_export_memory(e_reg);

	return 0;
}

/* NOTE: the operation order is not precisely the reverse order of initialization for the ease of
 * error rollback. Please make careful evaluation on modifications.
 */
int obmm_unexport(const struct obmm_cmd_unexport *cmd_unexport)
{
	int ret;
	struct obmm_region *reg;
	struct obmm_export_region *e_reg;

	pr_debug("%s: mem_id=%llu, flags=%#llx.\n", __func__, cmd_unexport->mem_id,
		cmd_unexport->flags);
	if (!validate_obmm_mem_id(cmd_unexport->mem_id))
		return -ENOENT;
	if (cmd_unexport->flags & (~OBMM_UNEXPORT_FLAG_MASK)) {
		pr_err("%s: invalid flags %#llx.\n", __func__, cmd_unexport->flags);
		return -EINVAL;
	}

	reg = search_deactivate_obmm_region(cmd_unexport->mem_id);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	if (reg->type != OBMM_EXPORT_REGION) {
		pr_err("%s: mem_id=%llu region type mismatched.\n", __func__, cmd_unexport->mem_id);
		ret = -EINVAL;
		goto err_unexport_common;
	}

	e_reg = container_of(reg, struct obmm_export_region, region);
	ret = obmm_unexport_common(e_reg);
	if (ret)
		goto err_unexport_common;

	deregister_obmm_region(reg);
	uninit_obmm_region(reg);
	/* the region is freed by the device release callback */
	obmm_shm_dev_put(reg);

	pr_debug("%s: mem_id=%llu completed.\n", __func__, cmd_unexport->mem_id);
	return 0;

err_unexport_common:
	activate_obmm_region(reg);
	pr_err("%s: mem_id=%llu failed, %pe.\n", __func__, cmd_unexport->mem_id, ERR_PTR(ret));

	return ret;
}

int set_export_vendor(struct obmm_export_region *e_reg, const void __user *vendor_info,
		      unsigned int vendor_len)
{
	if (vendor_len == 0) {
		e_reg->vendor_info = NULL;
		e_reg->vendor_len = vendor_len;
		return 0;
	}
	if (vendor_len > OBMM_MAX_VENDOR_LEN) {
		pr_err("invalid vendor_len = 0x%x, should less than 0x%x\n", vendor_len,
		       OBMM_MAX_VENDOR_LEN);
		return -EINVAL;
	}
	e_reg->vendor_info = kmalloc(vendor_len, GFP_KERNEL);
	if (!e_reg->vendor_info)
		return -ENOMEM;

	if (copy_from_user(e_reg->vendor_info, vendor_info, vendor_len)) {
		kfree(e_reg->vendor_info);
		e_reg->vendor_info = NULL;
		pr_err("failed to save vendor data.\n");
		return -EFAULT;
	}
	e_reg->vendor_len = vendor_len;
	return 0;
}

/* Free an export region whose device was never initialized (early error paths). */
void free_export_region(struct obmm_export_region *e_reg)
{
	if (e_reg->vendor_len)
		kfree(e_reg->vendor_info);

	kfree(e_reg);
}
