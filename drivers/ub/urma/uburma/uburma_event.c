// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: uburma event implementation
 * Author: Yan Fangfang
 * Create: 2022-07-28
 * Note:
 * History: 2022-07-28: create file
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/poll.h>

#include <urma/ubcore_uapi.h>

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_cmd.h"
#include "uburma_uobj.h"
#include "uburma_event.h"

#define UBURMA_JFCE_DELETE_EVENT 0
struct uburma_jfe_event {
	struct list_head node;
	uint32_t event_type; /* support async event */
	uint64_t event_data;
	struct list_head obj_node;
	uint32_t *counter;
};

struct uburma_jfce_uobj *uburma_get_jfce_uobj(int fd, struct uburma_file *ufile)
{
	struct uburma_uobj *uobj;
	struct uburma_jfce_uobj *jfce;

	if (fd < 0)
		return ERR_PTR(-ENOENT);

	uobj = uobj_get_read(UOBJ_CLASS_JFCE, fd, ufile);
	if (IS_ERR(uobj)) {
		uburma_log_err("get jfce uobj fail with fd %d\n", fd);
		return (void *)uobj;
	}

	jfce = container_of(uobj, struct uburma_jfce_uobj, uobj);
	uobj_get(uobj); // To keep the event file until jfce destroy.
	uobj_put_read(uobj);
	return jfce;
}

void uburma_write_event(struct uburma_jfe *jfe, uint64_t event_data, uint32_t event_type,
			struct list_head *obj_event_list, uint32_t *counter)
{
	struct uburma_jfe_event *event;
	unsigned long flags;

	spin_lock_irqsave(&jfe->lock, flags);
	if (jfe->deleting) {
		spin_unlock_irqrestore(&jfe->lock, flags);
		return;
	}
	event = kmalloc(sizeof(struct uburma_jfe_event), GFP_ATOMIC);
	if (event == NULL) {
		spin_unlock_irqrestore(&jfe->lock, flags);
		return;
	}
	event->event_data = event_data;
	event->event_type = event_type;
	event->counter = counter;

	list_add_tail(&event->node, &jfe->event_list);
	if (obj_event_list)
		list_add_tail(&event->obj_node, obj_event_list);
	spin_unlock_irqrestore(&jfe->lock, flags);
	wake_up_interruptible(&jfe->poll_wait);
}

void uburma_jfce_handler(struct ubcore_jfc *jfc)
{
	struct uburma_jfc_uobj *jfc_uobj;
	struct uburma_jfce_uobj *jfce;

	if (jfc == NULL)
		return;

	rcu_read_lock();
	jfc_uobj = rcu_dereference(jfc->jfc_cfg.jfc_context);
	if (jfc_uobj != NULL && !IS_ERR(jfc_uobj) && !IS_ERR(jfc_uobj->jfce)) {
		jfce = container_of(jfc_uobj->jfce, struct uburma_jfce_uobj, uobj);
		uburma_write_event(&jfce->jfe, jfc->urma_jfc, 0, &jfc_uobj->comp_event_list,
				   &jfc_uobj->comp_events_reported);
	}

	rcu_read_unlock();
}

void uburma_uninit_jfe(struct uburma_jfe *jfe)
{
	struct list_head *p, *next;
	struct uburma_jfe_event *event;

	spin_lock_irq(&jfe->lock);
	list_for_each_safe(p, next, &jfe->event_list) {
		event = list_entry(p, struct uburma_jfe_event, node);
		if (event->counter)
			list_del(&event->obj_node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
}

const struct file_operations uburma_jfce_fops = {
};

void uburma_init_jfe(struct uburma_jfe *jfe)
{
	spin_lock_init(&jfe->lock);
	INIT_LIST_HEAD(&jfe->event_list);
	init_waitqueue_head(&jfe->poll_wait);
}

const struct file_operations uburma_jfae_fops = {
};

static void uburma_async_event_callback(struct ubcore_event *event,
					struct ubcore_event_handler *handler)
{
	struct uburma_jfae_uobj *jfae =
		container_of(handler, struct uburma_jfae_uobj, event_handler);

	if (WARN_ON(IS_ERR_OR_NULL(jfae)))
		return;

	uburma_write_event(&jfae->jfe, event->element.port_id, event->event_type, NULL, NULL);
}


static inline void uburma_init_jfae_handler(struct ubcore_event_handler *handler)
{
	INIT_LIST_HEAD(&handler->node);
	handler->event_callback = uburma_async_event_callback;
}


void uburma_init_jfae(struct uburma_jfae_uobj *jfae, struct ubcore_device *ubc_dev)
{
	uburma_init_jfe(&jfae->jfe);
	uburma_init_jfae_handler(&jfae->event_handler);
	ubcore_register_event_handler(ubc_dev, &jfae->event_handler);
	jfae->dev = ubc_dev;
}

void uburma_release_comp_event(struct uburma_jfce_uobj *jfce, struct list_head *event_list)
{
	struct uburma_jfe *jfe = &jfce->jfe;
	struct uburma_jfe_event *event, *tmp;

	spin_lock_irq(&jfe->lock);
	list_for_each_entry_safe(event, tmp, event_list, obj_node) {
		list_del(&event->node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
}

void uburma_release_async_event(struct uburma_file *ufile, struct list_head *event_list)
{
	struct uburma_jfae_uobj *jfae = ufile->ucontext->jfae;
	struct uburma_jfe *jfe = &jfae->jfe;
	struct uburma_jfe_event *event, *tmp;

	spin_lock_irq(&jfe->lock);
	list_for_each_entry_safe(event, tmp, event_list, obj_node) {
		list_del(&event->node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
	uburma_put_jfae(ufile);
}

int uburma_get_jfae(struct uburma_file *ufile)
{
	struct uburma_jfae_uobj *jfae;

	if (ufile->ucontext == NULL) {
		uburma_log_err("ucontext is NULL");
		return -ENODEV;
	}

	jfae = ufile->ucontext->jfae;
	if (IS_ERR_OR_NULL(jfae)) {
		uburma_log_err("Failed to get jfae");
		return -EINVAL;
	}

	uobj_get(&jfae->uobj);
	return 0;
}

void uburma_put_jfae(struct uburma_file *ufile)
{
	struct uburma_jfae_uobj *jfae;

	if (ufile->ucontext == NULL)
		return;

	jfae = ufile->ucontext->jfae;
	if (IS_ERR_OR_NULL(jfae))
		return;

	uobj_put(&jfae->uobj);
}
