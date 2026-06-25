// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg device helper implementation file
 */

#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include <ub/urma/ubcore_uapi.h>
#include "ubagg_ioctl.h"
#include "ubagg_log.h"

#include "ubagg_device.h"

static atomic_t g_ucontext_cnt = ATOMIC_INIT(0);
static LIST_HEAD(g_ubagg_dev_list);
static DEFINE_SPINLOCK(g_ubagg_dev_list_lock);

static void ubagg_dev_release(struct kref *kref)
{
	struct ubagg_device *dev = container_of(kref, struct ubagg_device, ref);

	ubagg_uninit_device_res(dev);
	kfree(dev);
}

void ubagg_get_device(struct ubagg_device *dev)
{
	kref_get(&dev->ref);
}

void ubagg_put_device(struct ubagg_device *dev)
{
	kref_put(&dev->ref, ubagg_dev_release);
}

struct ubcore_ucontext *ubagg_alloc_ucontext(struct ubcore_device *dev,
					     uint32_t eid_index,
					     struct ubcore_udrv_priv *udrv_data)
{
	struct ubcore_ucontext *uctx;

	uctx = kzalloc(sizeof(*uctx), GFP_KERNEL);
	if (uctx == NULL)
		return NULL;

	atomic_inc(&g_ucontext_cnt);
	return uctx;
}

int ubagg_free_ucontext(struct ubcore_ucontext *uctx)
{
	if (uctx == NULL)
		return 0;

	atomic_dec(&g_ucontext_cnt);
	kfree(uctx);
	return 0;
}

uint32_t ubagg_get_ucontext_count(void)
{
	return (uint32_t)atomic_read(&g_ucontext_cnt);
}

struct ubagg_device *ubagg_get_device_by_name(const char *dev_name)
{
	struct ubagg_device *dev;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry(dev, &g_ubagg_dev_list, list_node) {
		if (strncmp(dev_name, dev->master_dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0) {
			ubagg_get_device(dev);
			spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
			return dev;
		}
	}
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);

	return NULL;
}

struct ubagg_device *ubagg_get_device_by_eid(const union ubcore_eid *eid)
{
	struct ubagg_device *dev;
	unsigned long flags;

	if (eid == NULL)
		return NULL;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry(dev, &g_ubagg_dev_list, list_node) {
		if (memcmp(&dev->bonding_eid, eid, sizeof(*eid)) == 0) {
			ubagg_get_device(dev);
			spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
			return dev;
		}
	}
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);

	return NULL;
}

struct ubagg_device *ubagg_get_first_device(void)
{
	struct ubagg_device *dev;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	if (list_empty(&g_ubagg_dev_list)) {
		spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
		return NULL;
	}

	dev = list_first_entry(&g_ubagg_dev_list, struct ubagg_device,
			       list_node);
	ubagg_get_device(dev);
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);

	return dev;
}

int ubagg_add_dev_to_list(struct ubagg_device *ubagg_dev)
{
	struct ubagg_device *cur = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry(cur, &g_ubagg_dev_list, list_node) {
		if (strncmp(cur->ub_dev.dev_name, ubagg_dev->ub_dev.dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0) {
			spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
			return -EEXIST;
		}
	}
	list_add_tail(&ubagg_dev->list_node, &g_ubagg_dev_list);
	ubagg_get_device(ubagg_dev);
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
	return 0;
}

void ubagg_remove_dev_from_list(struct ubagg_device *ubagg_dev)
{
	struct ubagg_device *cur = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	list_for_each_entry(cur, &g_ubagg_dev_list, list_node) {
		if (strncmp(cur->ub_dev.dev_name, ubagg_dev->ub_dev.dev_name,
			    UBAGG_MAX_DEV_NAME_LEN) == 0) {
			list_del_init(&cur->list_node);
			ubagg_put_device(cur);
			spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
			ubagg_log_info("ubagg dev %s removed from list\n",
				       ubagg_dev->ub_dev.dev_name);
			return;
		}
	}
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
}

struct ubagg_device *ubagg_pop_device_from_list(void)
{
	struct ubagg_device *dev;
	unsigned long flags;

	spin_lock_irqsave(&g_ubagg_dev_list_lock, flags);
	if (list_empty(&g_ubagg_dev_list)) {
		spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);
		return NULL;
	}

	dev = list_first_entry(&g_ubagg_dev_list, struct ubagg_device,
			       list_node);
	ubagg_get_device(dev);
	list_del_init(&dev->list_node);
	ubagg_put_device(dev);
	spin_unlock_irqrestore(&g_ubagg_dev_list_lock, flags);

	return dev;
}
