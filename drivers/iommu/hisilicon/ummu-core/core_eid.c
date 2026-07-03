// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., All rights reserved.
 * Description: eid related functions.
 */

#define pr_fmt(fmt) "[UMMU_CORE][EID]: " fmt

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ummu_core.h>

struct ummu_core_device *global_core_device;
EXPORT_SYMBOL_NS_GPL(global_core_device, UMMU_CORE_INTERNAL);

DEFINE_MUTEX(global_device_lock);
EXPORT_SYMBOL_NS_GPL(global_device_lock, UMMU_CORE_INTERNAL);

static DEFINE_SPINLOCK(eid_func_lock);
static LIST_HEAD(eid_pre_insmode);

struct eid_info {
	enum eid_type type;
	eid_t eid;
	guid_t guid;
	struct list_head list;
};

/* add cached eid to the core device */
void ummu_flush_cached_eid(struct ummu_core_device *core_device)
{
	struct eid_info *info, *next;

	spin_lock(&eid_func_lock);
	list_for_each_entry_safe(info, next, &eid_pre_insmode, list) {
		core_device->ops->add_eid(core_device, &info->guid, info->eid, info->type);
		list_del(&info->list);
		kfree(info);
	}
	spin_unlock(&eid_func_lock);
}
EXPORT_SYMBOL_NS_GPL(ummu_flush_cached_eid, UMMU_CORE_INTERNAL);

int ummu_core_add_eid(guid_t *guid, eid_t eid, enum eid_type type)
{
	struct eid_info *info;
	int ret = 0;

	if (type >= EID_TYPE_MAX)
		return -EINVAL;

	mutex_lock(&global_device_lock);
	if (global_core_device) {
		ret = global_core_device->ops->add_eid(global_core_device, guid, eid, type);
		goto out_unlock_mutex;
	}

	/* cached the eid */
	spin_lock(&eid_func_lock);
	list_for_each_entry(info, &eid_pre_insmode, list)
		if (info->eid == eid) {
			ret = -EEXIST;
			goto out_unlock_spin;
		}

	info = kzalloc(sizeof(*info), GFP_ATOMIC);
	if (!info) {
		ret = -ENOMEM;
		goto out_unlock_spin;
	}
	info->eid = eid;
	info->type = type;
	guid_copy(&info->guid, guid);
	list_add_tail(&info->list, &eid_pre_insmode);

out_unlock_spin:
	spin_unlock(&eid_func_lock);

out_unlock_mutex:
	mutex_unlock(&global_device_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ummu_core_add_eid);

void ummu_core_del_eid(guid_t *guid, eid_t eid, enum eid_type type)
{
	struct eid_info *info, *next;

	mutex_lock(&global_device_lock);
	if (global_core_device) {
		global_core_device->ops->del_eid(global_core_device, guid, eid, type);
		goto out_unlock_mutex;
	}

	/* uncache the eid */
	spin_lock(&eid_func_lock);
	list_for_each_entry_safe(info, next, &eid_pre_insmode, list)
		if (info->eid == eid) {
			list_del(&info->list);
			kfree(info);
		}
	spin_unlock(&eid_func_lock);

out_unlock_mutex:
	mutex_unlock(&global_device_lock);
}
EXPORT_SYMBOL_GPL(ummu_core_del_eid);
