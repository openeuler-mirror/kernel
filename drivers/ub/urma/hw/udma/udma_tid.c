// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/ummu_core.h>
#include "udma_ctx.h"
#include "udma_tid.h"

static int udma_get_key_id_from_user(struct udma_dev *udma_dev,
				     struct ubcore_udata *udata,
				     struct udma_tid *udma_tid)
{
	unsigned long byte;
	uint32_t tid = 0;

	if (!udata->udrv_data || !udata->udrv_data->in_addr) {
		dev_err(udma_dev->dev, "user driver data or input address is null.\n");
		return -EINVAL;
	}

	byte = copy_from_user(&tid, (void *)(uintptr_t)udata->udrv_data->in_addr,
			      min(udata->udrv_data->in_len,
			      (uint32_t)sizeof(tid)));
	if (byte) {
		dev_err(udma_dev->dev, "get user data failed, byte = %lu.\n", byte);
		return -EFAULT;
	}

	udma_tid->core_key_id.token_id = tid;
	udma_tid->tid = tid >> UDMA_TID_SHIFT;

	return 0;
}

static int udma_alloc_k_tid(struct udma_dev *udma_dev,
			    struct udma_tid *udma_tid)
{
	struct ummu_param param = {.mode = MAPT_MODE_TABLE};
	struct iommu_sva *ksva;
	uint32_t tid;
	int ret;

	ksva = iommu_ksva_bind_device(udma_dev->dev, &param);
	if (IS_ERR(ksva)) {
		dev_err(udma_dev->dev, "ksva bind device failed.\n");
		return -ENOMEM;
	}

	ret = ummu_get_tid(udma_dev->dev, ksva, &tid);
	if (ret) {
		dev_err(udma_dev->dev, "get TID from UMMU failed, ret = %d.\n", ret);
		goto err_get_tid;
	}

	if (tid > UDMA_MAX_TID) {
		dev_err(udma_dev->dev, "tid is overflow.\n");
		ret = -EINVAL;
		goto err_get_tid;
	}

	mutex_lock(&udma_dev->ksva_mutex);
	ret = xa_err(__xa_store(&udma_dev->ksva_table, tid, ksva, GFP_KERNEL));
	mutex_unlock(&udma_dev->ksva_mutex);
	if (ret) {
		dev_err(udma_dev->dev, "save ksva failed, ret = %d.\n", ret);
		goto err_get_tid;
	}

	udma_tid->core_key_id.token_id = tid << UDMA_TID_SHIFT;
	udma_tid->tid = tid;
	udma_tid->kernel_mode = true;

	return ret;

err_get_tid:
	iommu_ksva_unbind_device(ksva);

	return ret;
}

struct ubcore_token_id *udma_alloc_tid(struct ubcore_device *ub_dev,
				       union ubcore_token_id_flag flag,
				       struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_tid *udma_tid;
	int ret;

	udma_tid = kzalloc(sizeof(*udma_tid), GFP_KERNEL);
	if (!udma_tid)
		return NULL;

	if (udata) {
		ret = udma_get_key_id_from_user(udma_dev, udata, udma_tid);
		if (ret) {
			dev_err(udma_dev->dev, "get user key id failed, ret = %d.\n", ret);
			goto err_get_key_id;
		}
		return &udma_tid->core_key_id;
	}

	if (udma_alloc_k_tid(udma_dev, udma_tid))
		goto err_get_key_id;

	return &udma_tid->core_key_id;

err_get_key_id:
	kfree(udma_tid);
	return NULL;
}

int udma_free_tid(struct ubcore_token_id *token_id)
{
	struct udma_dev *udma_dev = to_udma_dev(token_id->ub_dev);
	struct udma_tid *udma_tid = to_udma_tid(token_id);
	struct ummu_invalid_cfg_param inva_param = {};
	struct udma_context *ctx;
	struct iommu_sva *ksva;
	int ret = 0;

	if (!udma_tid->kernel_mode) {
		ctx = to_udma_context(token_id->uctx);
		if (!ctx) {
			dev_err(udma_dev->dev, "udma free TID failed, context is null.\n");
			goto out;
		}
		inva_param.tid = udma_tid->tid;
		inva_param.mm = ctx->mm;
		ret = ummu_core_invalidate_cfg(&inva_param);
		if (ret && ret != -ENOENT && ret != -ESRCH)
			dev_err_ratelimited(udma_dev->dev,
					    "invalidate cfg_table failed, ret=%d.\n", ret);

		goto out;
	}

	mutex_lock(&udma_dev->ksva_mutex);
	ksva = (struct iommu_sva *)xa_load(&udma_dev->ksva_table, udma_tid->tid);
	if (!ksva) {
		mutex_unlock(&udma_dev->ksva_mutex);
		dev_warn(udma_dev->dev,
			 "unable to get ksva while free tid, token maybe is free.\n");
		goto out;
	}
	iommu_ksva_unbind_device(ksva);
	__xa_erase(&udma_dev->ksva_table, udma_tid->tid);
	mutex_unlock(&udma_dev->ksva_mutex);

out:
	kfree(udma_tid);

	return 0;
}
