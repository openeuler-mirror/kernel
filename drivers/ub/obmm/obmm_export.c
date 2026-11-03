// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: export-half glue (UMMU setup/teardown, vendor copy); UNEXPORT.
 */

#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <uapi/ub/obmm.h>
#include <linux/ummu_core.h>

#include "obmm_core.h"
#include "obmm_backend.h"
#include "obmm_export.h"
#include "obmm_switch.h"
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

	return 0;
}

static int fill_ummu_info(struct tdev_attr *attr, const struct obmm_export_common *exp)
{
	tdev_attr_init(attr);
	attr->name = (char *)"OBMM_TDEV";
	if (exp->vendor_len > 0) {
		attr->priv = kmemdup(exp->vendor_info, exp->vendor_len, GFP_KERNEL);
		if (!attr->priv)
			return -ENOMEM;
	}
	attr->priv_len = exp->vendor_len;
	return 0;
}

static void drain_ummu_info(struct tdev_attr *attr)
{
	kfree(attr->priv);
}

int setup_ummu(struct obmm_export_common *exp)
{
	struct tdev_attr attr;
	uint32_t tokenid = UMMU_INVALID_TID;
	int retval;

	retval = fill_ummu_info(&attr, exp);
	if (retval) {
		pr_err("Failed to fill UMMU info, ret=%pe\n", ERR_PTR(retval));
		return retval;
	}

	/* register the memory region through UMMU */
	pr_debug("call ummu_core_alloc_tdev(), priv_len=%u, tid=%u\n", attr.priv_len, tokenid);
	exp->ummu_dev = ummu_core_alloc_tdev(&attr, &tokenid);
	if (exp->ummu_dev == NULL) {
		pr_err("Failed to create UMMU device\n");
		retval = -EPERM;
		goto out_drain_info;
	}
	exp->tokenid = tokenid;
	pr_debug("ummu_core_alloc_tdev() returned ummu_dev: tid=%u, name=%s\n", tokenid,
		 dev_name(exp->ummu_dev));

	/* DMA mapping */
	pr_debug("call dma_map_sgtable(..., dir=DMA_BIDIRECTIONAL, attrs=0)\n");
	retval = dma_map_sgtable(exp->ummu_dev, &exp->sgt, DMA_BIDIRECTIONAL, 0);
	if (retval) {
		pr_err("Failed to map sgtable on UMMU. ret=%pe\n", ERR_PTR(retval));
		goto out_free_device;
	}
	pr_debug("dma_map_sgtable returned 0\n");

	exp->uba = sg_dma_address(exp->sgt.sgl);
	drain_ummu_info(&attr);
	return 0;

out_free_device:
	if (ummu_core_free_tdev(exp->ummu_dev))
		pr_warn("Failed to create memory region but unable to cleanup allocated UMMU device\n");
out_drain_info:
	drain_ummu_info(&attr);
	return retval;
}

/*
 * Undo setup_ummu; on ummu_core_free_tdev failure the sg_table is re-mapped
 * and the destroy caller aborts, leaving the backend's resources leaked.
 */
int teardown_ummu(struct obmm_export_common *exp)
{
	int ret, rollback_ret;

	pr_debug("call external: dma_unmap_sgtable\n");
	dma_unmap_sgtable(exp->ummu_dev, &exp->sgt, DMA_BIDIRECTIONAL, 0);

	pr_debug("call external: ummu_core_free_tdev()\n");
	ret = ummu_core_free_tdev(exp->ummu_dev);
	if (ret) {
		pr_err("Failed to free UMMU tdev, ret=%pe.\n", ERR_PTR(ret));
		goto err_rollback;
	}

	return 0;

err_rollback:

	rollback_ret = dma_map_sgtable(exp->ummu_dev, &exp->sgt, DMA_BIDIRECTIONAL, 0);
	if (rollback_ret) {
		pr_err("Failed to map sgtable on UMMU. ret=%pe\n", ERR_PTR(rollback_ret));
		ret = -ENOTRECOVERABLE;
	}
	if (exp->uba != sg_dma_address(exp->sgt.sgl)) {
		pr_err("Tried remapping in UMMU on rollback but UBA changed.\n");
		ret = -ENOTRECOVERABLE;
		pr_debug("call external: dma_unmap_sgtable\n");
		dma_unmap_sgtable(exp->ummu_dev, &exp->sgt, DMA_BIDIRECTIONAL, 0);
	}
	return ret;
}

void *dup_export_vendor(const void __user *vendor_info, unsigned int vendor_len)
{
	void *vendor;

	if (vendor_len == 0)
		return NULL;
	if (vendor_len > OBMM_MAX_VENDOR_LEN) {
		pr_err("invalid vendor_len = 0x%x, should less than 0x%x\n", vendor_len,
		       OBMM_MAX_VENDOR_LEN);
		return ERR_PTR(-EINVAL);
	}
	vendor = memdup_user(vendor_info, vendor_len);
	if (IS_ERR(vendor))
		pr_err("failed to save vendor data.\n");

	return vendor;
}

/* NOTE: the operation order is not precisely the reverse order of initialization for the ease of
 * error rollback. Please make careful evaluation on modifications.
 */
int obmm_unexport(const struct obmm_cmd_unexport *cmd_unexport)
{
	int ret;
	struct obmm_region *reg;

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

	if (!obmm_region_teardown_matches(reg, OBMM_EXPORT_REGION)) {
		pr_err("%s: mem_id=%llu not an export region.\n", __func__, cmd_unexport->mem_id);
		ret = -EINVAL;
		goto err_unexport;
	}

	ret = obmm_region_teardown(reg);
	if (ret)
		goto err_teardown_aborted;

	pr_debug("%s: mem_id=%llu completed.\n", __func__, cmd_unexport->mem_id);
	return 0;

err_teardown_aborted:
	pr_err("%s: mem_id=%llu failed, %pe.\n", __func__, cmd_unexport->mem_id, ERR_PTR(ret));
	return ret;
err_unexport:
	activate_obmm_region(reg);
	pr_err("%s: mem_id=%llu failed, %pe.\n", __func__, cmd_unexport->mem_id, ERR_PTR(ret));

	return ret;
}
