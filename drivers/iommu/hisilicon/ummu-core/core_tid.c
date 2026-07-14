// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: UMMU Tid Manager.
 */

#define pr_fmt(fmt) "[UMMU_CORE][TID]: " fmt
#define CREATE_TRACE_POINTS
#include "ummu_trace.h"
#include <linux/ummu_core.h>

#include "ummu_core_priv.h"

struct ummu_tid_data {
	struct device *device;
	enum ummu_mapt_mode mode;
	enum tid_alloc_mode alloc_mode;
	u32 domain_type;
	u32 reserved;
	struct mm_struct *mm;
};

static int default_tid_alloc(struct ummu_tid_manager *manager,
			   struct ummu_tid_param *param, u32 *tid)
{
	struct ummu_tid_data *tid_data;
	int ret;

	if (!param->device) {
		pr_err("invalid param.\n");
		return -EINVAL;
	}
	tid_data = kzalloc(sizeof(struct ummu_tid_data), GFP_KERNEL);
	if (!tid_data)
		return -ENOMEM;

	tid_data->device = param->device;
	get_device(tid_data->device);
	ret = xa_alloc(&manager->token_ids, tid, tid_data,
		       XA_LIMIT(manager->min_tid, manager->max_tid),
		       GFP_KERNEL);
	if (ret) {
		pr_err("alloc xarray tid failed.\n");
		put_device(tid_data->device);
		kfree(tid_data);
	}

	return ret;
}

static void default_tid_free(struct ummu_tid_manager *manager, u32 tid)
{
	struct ummu_tid_data *tid_data;

	tid_data = xa_erase(&manager->token_ids, tid);
	if (!tid_data) {
		pr_err("invalid tid.\n");
		return;
	}
	put_device(tid_data->device);
	kfree(tid_data);
}

struct ummu_tid_manager *
default_manager_alloc(struct ummu_core_device *core_device, u32 max_tid,
		      u32 min_tid)
{
	struct ummu_tid_manager *manager;

	manager = kzalloc(sizeof(struct ummu_tid_manager), GFP_KERNEL);
	if (!manager)
		return NULL;

	xa_init_flags(&manager->token_ids, XA_FLAGS_ALLOC);
	return manager;
}

void default_manager_free(struct ummu_tid_manager *manager)
{
	struct ummu_tid_data *data;
	unsigned long index;

	if (!manager) {
		pr_err("invalid param.\n");
		return;
	}
	/* all tid have to be released by the user */
	if (WARN_ON(!xa_empty(&manager->token_ids))) {
		pr_warn("tid resource was not released.\n");
		xa_for_each(&manager->token_ids, index, data)
			manager->ops->free_tid(manager, index);
	}
	xa_destroy(&manager->token_ids);
	kfree(manager);
}

const struct tid_ops ummu_default_ops = {
	.alloc_tid_manager = default_manager_alloc,
	.free_tid_manager = default_manager_free,
	.alloc_tid = default_tid_alloc,
	.free_tid = default_tid_free,
};

static int ummu_global_pasid_alloc(struct ummu_tid_manager *manager,
			  struct ummu_tid_param *param, u32 *tidp)
{
	struct ummu_tid_data *tid_data;
	ioasid_t tid;
	int ret;

	if (!param->device) {
		pr_err("invalid param.\n");
		return -EINVAL;
	}
	tid_data = kzalloc(sizeof(struct ummu_tid_data), GFP_KERNEL);
	if (!tid_data)
		return -ENOMEM;

	tid_data->device = param->device;
	tid_data->mode = param->mode;
	tid_data->alloc_mode = param->alloc_mode;
	tid_data->domain_type = param->domain_type;
	if (param->mm) {
		mmgrab(param->mm);
		tid_data->mm = param->mm;
	}

	switch (param->alloc_mode) {
	case TID_ALLOC_TRANSPARENT:
		tid = param->assign_tid;
		if (tid >= manager->max_tid || tid < manager->min_tid) {
			pr_err("alloc transparent tid failed.\n");
			ret = -EINVAL;
			goto out_release_data;
		}
		break;
	case TID_ALLOC_ASSIGNED:
		/* assign a tid */
		tid = param->assign_tid;
		if (tid < IOMMU_FIRST_GLOBAL_PASID || tid >= manager->min_tid) {
			pr_err("alloc assigned tid failed.\n");
			ret = -EINVAL;
			goto out_release_data;
		}
		break;
	case TID_ALLOC_NORMAL:
		tid = iommu_alloc_global_pasid(tid_data->device);
		if (tid >= manager->max_tid || tid < manager->min_tid) {
			pr_err("alloc normal tid failed.\n");
			ret = -EINVAL;
			goto out_release_data;
		}
		break;
	default:
		pr_err("invalid alloc mode.\n");
		ret = -EINVAL;
		goto out_release_data;
	}

	ret = xa_insert(&manager->token_ids, tid, tid_data, GFP_KERNEL);
	if (ret) {
		pr_err("insert tid_data failed, ret:%d.\n", ret);
		goto out_release_tid;
	}
	*tidp = tid;
	return 0;

out_release_tid:
	if (tid_data->alloc_mode == TID_ALLOC_NORMAL)
		iommu_free_global_pasid(tid);
out_release_data:
	if (tid_data->mm)
		mmdrop(tid_data->mm);
	kfree(tid_data);
	return ret;
}

static void ummu_global_pasid_free(struct ummu_tid_manager *manager, u32 tid)
{
	struct ummu_tid_data *tid_data;

	tid_data = xa_erase(&manager->token_ids, tid);
	if (!tid_data) {
		pr_err("invalid tid.\n");
		return;
	}

	if (tid_data->mm)
		mmdrop(tid_data->mm);

	if (tid_data->alloc_mode == TID_ALLOC_NORMAL)
		iommu_free_global_pasid(tid);
	kfree(tid_data);
}

const struct tid_ops ummu_global_pasid_ops = {
	.alloc_tid_manager = default_manager_alloc,
	.free_tid_manager = default_manager_free,
	.alloc_tid = ummu_global_pasid_alloc,
	.free_tid = ummu_global_pasid_free,
};

int ummu_core_alloc_tid(struct ummu_core_device *ummu_core,
			struct ummu_tid_param *param, u32 *tidp)
{
	int ret;

	if (!ummu_core || !ummu_core->tid_manager || !param || !tidp) {
		pr_err("invalid param.\n");
		return -EINVAL;
	}
	ret = ummu_core->tid_manager->ops->alloc_tid(ummu_core->tid_manager,
						     param, tidp);
	if (!ret)
		trace_ummu_core_alloc_tid(dev_name(ummu_core->iommu.dev),
					  dev_name(param->device), *tidp);
	else
		pr_err("allocate tid failed.\n");
	return ret;
}
EXPORT_SYMBOL_NS_GPL(ummu_core_alloc_tid, UMMU_CORE_DRIVER);

void ummu_core_free_tid(struct ummu_core_device *ummu_core, u32 tid)
{
	if (!ummu_core || !ummu_core->tid_manager) {
		pr_err("invalid param.\n");
		return;
	}
	ummu_core->tid_manager->ops->free_tid(ummu_core->tid_manager, tid);
	trace_ummu_core_free_tid(dev_name(ummu_core->iommu.dev), tid);
}
EXPORT_SYMBOL_NS_GPL(ummu_core_free_tid, UMMU_CORE_DRIVER);

enum ummu_mapt_mode ummu_core_get_mapt_mode(struct ummu_core_device *ummu_core,
					    u32 tid)
{
	struct ummu_tid_data *tid_data;
	enum ummu_mapt_mode mode;

	if (!ummu_core || !ummu_core->tid_manager) {
		pr_err("invalid ummu_core.\n");
		return MAPT_MODE_END;
	}
	xa_lock(&ummu_core->tid_manager->token_ids);
	tid_data = xa_load(&ummu_core->tid_manager->token_ids, tid);
	if (tid_data) {
		mode = tid_data->mode;
	} else {
		pr_err("cannot get data.\n");
		mode = MAPT_MODE_END;
	}
	xa_unlock(&ummu_core->tid_manager->token_ids);

	return mode;
}
EXPORT_SYMBOL_GPL(ummu_core_get_mapt_mode);

struct device *ummu_core_get_device(struct ummu_core_device *ummu_core,
				    u32 tid)
{
	struct ummu_tid_data *tid_data;

	if (!ummu_core || !ummu_core->tid_manager) {
		pr_err("invalid ummu_core.\n");
		return NULL;
	}
	xa_lock(&ummu_core->tid_manager->token_ids);
	tid_data = xa_load(&ummu_core->tid_manager->token_ids, tid);
	if (!tid_data || !tid_data->device) {
		xa_unlock(&ummu_core->tid_manager->token_ids);
		return NULL;
	}
	get_device(tid_data->device);
	xa_unlock(&ummu_core->tid_manager->token_ids);

	return tid_data->device;
}
EXPORT_SYMBOL_GPL(ummu_core_get_device);

void ummu_core_put_device(struct device *dev)
{
	put_device(dev);
}
EXPORT_SYMBOL_GPL(ummu_core_put_device);

int ummu_core_get_tid_type(struct ummu_core_device *ummu_core, u32 tid,
			   u32 *tid_type)
{
	struct ummu_tid_data *tid_data;
	int ret;

	if (!ummu_core || !ummu_core->tid_manager || tid >= UMMU_INVALID_TID ||
	    !tid_type)
		return -EINVAL;

	xa_lock(&ummu_core->tid_manager->token_ids);
	tid_data = xa_load(&ummu_core->tid_manager->token_ids, tid);
	if (tid_data) {
		*tid_type = tid_data->domain_type;
		ret = 0;
	} else {
		pr_err("cannot get tid_data.\n");
		ret = -ENOENT;
	}
	xa_unlock(&ummu_core->tid_manager->token_ids);

	return ret;
}
EXPORT_SYMBOL_GPL(ummu_core_get_tid_type);

struct mm_struct *ummu_core_get_mm(struct ummu_core_device *ummu_core, u32 tid)
{
	struct ummu_tid_data *tid_data;

	if (!ummu_core || !ummu_core->tid_manager) {
		pr_err("invalid ummu_core.\n");
		return NULL;
	}

	xa_lock(&ummu_core->tid_manager->token_ids);
	tid_data = xa_load(&ummu_core->tid_manager->token_ids, tid);
	if (!tid_data) {
		xa_unlock(&ummu_core->tid_manager->token_ids);
		return NULL;
	}
	xa_unlock(&ummu_core->tid_manager->token_ids);

	return tid_data->mm;
}

const struct tid_ops *ummu_core_tid_ops[] = {
	[PASID_OPS] = &ummu_global_pasid_ops,
	[DEFAULT_OPS] = &ummu_default_ops,
};
EXPORT_SYMBOL_GPL(ummu_core_tid_ops);

const struct tid_ops *ummu_core_get_tid_ops(enum default_tid_ops_types type)
{
	if (type >= TID_OPS_MAX || type < PASID_OPS)
		return NULL;

	return ummu_core_tid_ops[type];
}
EXPORT_SYMBOL_NS_GPL(ummu_core_get_tid_ops, UMMU_CORE_DRIVER);
