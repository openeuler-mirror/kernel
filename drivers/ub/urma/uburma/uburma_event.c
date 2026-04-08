// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
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

#include "ub/urma/ubcore_uapi.h"

#include "uburma_log.h"
#include "uburma_types.h"
#include "uburma_cmd.h"
#include "uburma_uobj.h"
#include "uburma_cmd_tlv.h"
#include "uburma_file_ops.h"

#include "uburma_event.h"

#define UBURMA_JFCE_DELETE_EVENT 0

struct uburma_jfe_event {
	struct list_head node;
	uint32_t event_type; /* support async event */
	uint64_t event_data;
	struct list_head obj_node;
	uint32_t *counter;
	uburma_jfe_event_data_free_fn event_data_free_fn;
};

struct uburma_jfce_uobj *uburma_get_jfce_uobj(int fd, struct uburma_file *ufile)
{
	struct uburma_uobj *uobj;
	struct uburma_jfce_uobj *jfce;

	if (fd < 0)
		return ERR_PTR(-ENOENT);

	uobj = uobj_get_read(UOBJ_CLASS_JFCE, fd, ufile);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("get jfce uobj fail with fd %d\n", fd);
		return (void *)uobj;
	}

	jfce = container_of(uobj, struct uburma_jfce_uobj, uobj);
	uobj_get(uobj); // To keep the event file until jfce destroy.
	uobj_put_read(uobj);
	return jfce;
}

void uburma_write_event_with_free_fn(
	struct uburma_jfe *jfe, uint64_t event_data, uint32_t event_type,
	struct list_head *obj_event_list, uint32_t *counter,
	uburma_jfe_event_data_free_fn event_data_free_fn)
{
	struct uburma_jfe_event *event;
	unsigned long flags;

	spin_lock_irqsave(&jfe->lock, flags);
	if (jfe->deleting) {
		spin_unlock_irqrestore(&jfe->lock, flags);
		return;
	}
	event = kmalloc(sizeof(struct uburma_jfe_event), GFP_ATOMIC);
	if (!event) {
		spin_unlock_irqrestore(&jfe->lock, flags);
		return;
	}
	event->event_data = event_data;
	event->event_type = event_type;
	event->counter = counter;
	event->event_data_free_fn = event_data_free_fn;
	INIT_LIST_HEAD(&event->node);
	INIT_LIST_HEAD(&event->obj_node);

	list_add_tail(&event->node, &jfe->event_list);
	if (obj_event_list)
		list_add_tail(&event->obj_node, obj_event_list);
	if (jfe->async_queue)
		kill_fasync(&jfe->async_queue, SIGIO, POLL_IN);
	spin_unlock_irqrestore(&jfe->lock, flags);
	wake_up_interruptible(&jfe->poll_wait);
}

void uburma_write_event(struct uburma_jfe *jfe, uint64_t event_data,
			uint32_t event_type, struct list_head *obj_event_list,
			uint32_t *counter)
{
	uburma_write_event_with_free_fn(jfe, event_data, event_type,
					obj_event_list, counter, NULL);
}

static bool uburma_jfce_is_null(struct uburma_jfc_uobj *jfc_uobj)
{
	unsigned long flag;

	spin_lock_irqsave(&jfc_uobj->jfc_lock, flag);
	if (jfc_uobj->jfce == NULL) {
		spin_unlock_irqrestore(&jfc_uobj->jfc_lock, flag);
		return true;
	}
	spin_unlock_irqrestore(&jfc_uobj->jfc_lock, flag);
	return false;
}

void uburma_jfce_handler(struct ubcore_jfc *jfc)
{
	struct uburma_jfc_uobj *jfc_uobj;
	struct uburma_jfce_uobj *jfce;
	bool write_event = false;

	if (!jfc)
		return;

	rcu_read_lock();
	jfc_uobj = rcu_dereference(jfc->jfc_cfg.jfc_context);
	if (!IS_ERR_OR_NULL(jfc_uobj) && !IS_ERR(jfc_uobj->jfce) &&
		(uburma_jfce_is_null(jfc_uobj) == false)) {
		jfce = container_of(jfc_uobj->jfce, struct uburma_jfce_uobj,
				    uobj);
		uburma_write_event(&jfce->jfe, jfc->urma_jfc, 0,
				   &jfc_uobj->comp_event_list,
				   &jfc_uobj->comp_events_reported);
		write_event = true;
	}

	rcu_read_unlock();
	if (write_event)
		uburma_log_info("Finish to write jfc event, jfc_id: %u.\n", jfc->id);
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
		if (event->event_data_free_fn)
			(*(event->event_data_free_fn))(event->event_data);
		list_del(&event->node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
}

static int uburma_delete_jfce(struct inode *inode, struct file *filp)
{
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_file *ufile;

	if (!uobj || !uobj->ufile)
		return 0;

	ufile = uobj->ufile;
	down_write(&ufile->ucontext_rwsem);

	uobj_get(uobj);
	/* will call uburma_hot_unplug_jfce if clean up is not going on */
	uburma_close_uobj_fd(filp);
	uobj->ufile = NULL;
	uobj_put(uobj);
	up_write(&ufile->ucontext_rwsem);
	kref_put(&ufile->ref, uburma_release_file);

	return 0;
}

/* Read up to event_cnt events from jfe */
static uint32_t uburma_read_jfe_event(struct uburma_jfe *jfe,
				      uint32_t event_cnt,
				      struct list_head *event_list)
{
	struct list_head *p, *next;
	struct uburma_jfe_event *event;
	uint32_t cnt = 0;

	spin_lock_irq(&jfe->lock);

	list_for_each_safe(p, next, &jfe->event_list) {
		if (cnt == event_cnt)
			break;
		event = list_entry(p, struct uburma_jfe_event, node);
		if (event->counter) {
			++(*event->counter);
			list_del(&event->obj_node);
		}
		list_del(p);
		list_add_tail(p, event_list);
		cnt++;
	}
	spin_unlock_irq(&jfe->lock);
	return cnt;
}

static int uburma_wait_event_timeout(struct uburma_jfe *jfe,
				     unsigned long max_timeout,
				     uint32_t max_event_cnt,
				     uint32_t *event_cnt,
				     struct list_head *event_list)
{
	long timeout = (long)max_timeout;

	*event_cnt = 0;
	while (!jfe->deleting) {
		asm volatile("" : : : "memory");
		*event_cnt =
			uburma_read_jfe_event(jfe, max_event_cnt, event_list);
		/* Stop waiting once we have read at least one event */
		if (jfe->deleting)
			return -EIO;
		else if (*event_cnt > 0)
			break;
		/*
		 * 0 if the @condition evaluated to %false after the @timeout elapsed,
		 * 1 if the @condition evaluated to %true after the @timeout elapsed,
		 * the remaining jiffies (at least 1) if the @condition evaluated to true
		 * before the @timeout elapsed,
		 * or -%ERESTARTSYS if it was interrupted by a signal.
		 */
		timeout = wait_event_interruptible_timeout(
			jfe->poll_wait,
			(!list_empty(&jfe->event_list) || jfe->deleting),
			(timeout));
		if (timeout <= 0)
			return timeout;
	}

	return 0;
}

static int uburma_wait_event(struct uburma_jfe *jfe, bool nonblock,
			     uint32_t max_event_cnt, uint32_t *event_cnt,
			     struct list_head *event_list)
{
	int ret;

	*event_cnt = 0;
	spin_lock_irq(&jfe->lock);
	while (list_empty(&jfe->event_list)) {
		spin_unlock_irq(&jfe->lock);
		if (nonblock)
			return -EAGAIN;

		/* The function will return -ERESTARTSYS if it was interrupted by a
		 * signal and 0 if @condition evaluated to true.
		 */
		ret = wait_event_interruptible(jfe->poll_wait,
					       (!list_empty(&jfe->event_list) ||
						jfe->deleting));
		if (ret != 0)
			return ret;

		spin_lock_irq(&jfe->lock);
		if (list_empty(&jfe->event_list) && jfe->deleting) {
			spin_unlock_irq(&jfe->lock);
			return -EIO;
		}
	}
	spin_unlock_irq(&jfe->lock);
	*event_cnt = uburma_read_jfe_event(jfe, max_event_cnt, event_list);

	return 0;
}

static __poll_t uburma_jfe_poll(struct uburma_jfe *jfe, struct file *filp,
				struct poll_table_struct *wait)
{
	__poll_t flag = 0;

	poll_wait(filp, &jfe->poll_wait, wait);

	spin_lock_irq(&jfe->lock);
	if (!list_empty(&jfe->event_list))
		flag = EPOLLIN | EPOLLRDNORM;

	spin_unlock_irq(&jfe->lock);

	return flag;
}

static __poll_t uburma_jfce_poll(struct file *filp,
				 struct poll_table_struct *wait)
{
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfce_uobj *jfce =
		container_of(uobj, struct uburma_jfce_uobj, uobj);

	return uburma_jfe_poll(&jfce->jfe, filp, wait);
}

static int uburma_jfce_wait(struct uburma_jfce_uobj *jfce, struct file *filp,
			    struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_jfce_wait arg = { 0 };
	struct list_head event_list;
	struct uburma_jfe_event *event;
	uint32_t max_event_cnt;
	uint32_t i = 0;
	struct list_head *p, *next;
	int ret;

	ret = uburma_event_tlv_parse(hdr, &arg);
	if (ret != 0)
		return -EFAULT;

	/* urma lib ensures that max_event_cnt > 0 */
	max_event_cnt = (arg.in.max_event_cnt < MAX_JFCE_EVENT_CNT ?
				       arg.in.max_event_cnt :
				       MAX_JFCE_EVENT_CNT);
	INIT_LIST_HEAD(&event_list);
	if (arg.in.time_out <= 0) {
		ret = uburma_wait_event(
			&jfce->jfe,
			(filp->f_flags & O_NONBLOCK) | (arg.in.time_out == 0),
			max_event_cnt, &arg.out.event_cnt, &event_list);
	} else {
		ret = uburma_wait_event_timeout(
			&jfce->jfe, msecs_to_jiffies(arg.in.time_out),
			max_event_cnt, &arg.out.event_cnt, &event_list);
	}

	if (ret < 0) {
		uburma_log_err("Failed to wait jfce event, ret: %d.\n", ret);
		return ret;
	}

	list_for_each_safe(p, next, &event_list) {
		event = list_entry(p, struct uburma_jfe_event, node);
		arg.out.event_data[i++] = event->event_data;
		list_del(p);
		kfree(event);
	}

	if (arg.out.event_cnt > 0 && uburma_event_tlv_append(hdr, &arg) != 0)
		return -EFAULT;

	return 0;
}

static long uburma_jfce_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct uburma_cmd_hdr hdr;
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfce_uobj *jfce =
		container_of(uobj, struct uburma_jfce_uobj, uobj);
	int ret;

	if (cmd == UBURMA_CMD_WAIT_JFC) {
		ret = (int)copy_from_user(&hdr, (struct uburma_cmd_hdr *)arg,
					  sizeof(struct uburma_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBURMA_CMD_MAX_ARGS_SIZE) ||
		    (hdr.args_len == 0 || hdr.args_addr == 0 ||
		     hdr.command >= UBURMA_EVENT_CMD_MAX)) {
			ret = -EINVAL;
		} else {
			ret = uburma_jfce_wait(jfce, filp, &hdr);
		}
	} else {
		ret = -ENOIOCTLCMD;
	}
	return (long)ret;
}

static int uburma_jfce_fasync(int fd, struct file *filp, int on)
{
	int ret;
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfce_uobj *jfce =
		container_of(uobj, struct uburma_jfce_uobj, uobj);

	if (!uobj)
		return -EINVAL;
	spin_lock_irq(&jfce->jfe.lock);
	ret = fasync_helper(fd, filp, on, &jfce->jfe.async_queue);
	spin_unlock_irq(&jfce->jfe.lock);
	return ret;
}

const struct file_operations uburma_jfce_fops = {
	.owner = THIS_MODULE,
	.poll = uburma_jfce_poll,
	.release = uburma_delete_jfce,
	.unlocked_ioctl = uburma_jfce_ioctl,
	.fasync = uburma_jfce_fasync,
};

void uburma_init_jfe(struct uburma_jfe *jfe)
{
	spin_lock_init(&jfe->lock);
	INIT_LIST_HEAD(&jfe->event_list);
	init_waitqueue_head(&jfe->poll_wait);
	jfe->async_queue = NULL;
}

static int uburma_delete_jfae(struct inode *inode, struct file *filp)
{
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfae_uobj *jfae =
		container_of(uobj, struct uburma_jfae_uobj, uobj);
	struct uburma_file *ufile;

	if (!uobj || !jfae || !uobj->ufile || !uobj->ufile->ucontext)
		return 0;

	ufile = uobj->ufile;
	down_write(&ufile->ucontext_rwsem);
	if (!uobj->ufile || !uobj->ufile->ucontext) {
		uburma_log_err("jfae has been released.\n");
		up_write(&ufile->ucontext_rwsem);
		return 0;
	}
	uobj_get(uobj);
	/* call uburma_hot_unplug_jfae when cleanup is not going on */
	uburma_close_uobj_fd(filp);
	uburma_uninit_jfe(&jfae->jfe);
	uobj->ufile = NULL;
	uobj_put(uobj);
	up_write(&ufile->ucontext_rwsem);
	kref_put(&ufile->ref, uburma_release_file);

	return 0;
}

static __poll_t uburma_jfae_poll(struct file *filp,
				 struct poll_table_struct *wait)
{
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfae_uobj *jfae =
		container_of(uobj, struct uburma_jfae_uobj, uobj);

	return uburma_jfe_poll(&jfae->jfe, filp, wait);
}

static inline void
uburma_set_async_event(struct uburma_cmd_async_event *async_event,
		       const struct uburma_jfe_event *event)
{
	async_event->event_data = event->event_data;
	async_event->event_type = event->event_type;
}

static int uburma_get_async_event(struct uburma_jfae_uobj *jfae,
				  struct file *filp, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_async_event arg = { 0 };
	struct list_head event_list;
	struct uburma_jfe_event *event = NULL;
	uint32_t event_cnt;
	int ret;

	INIT_LIST_HEAD(&event_list);
	ret = uburma_wait_event(&jfae->jfe, filp->f_flags & O_NONBLOCK, 1,
				&event_cnt, &event_list);
	if (ret < 0)
		return ret;

	if (event_cnt == 0 || list_empty(&event_list))
		return -EIO;

	event = list_first_entry(&event_list, struct uburma_jfe_event, node);
	if (!event)
		return -EIO;

	uburma_set_async_event(&arg, event);
	list_del(&event->node);
	kfree(event);

	if (event_cnt > 0 && uburma_event_tlv_append(hdr, &arg) != 0)
		return -EFAULT;

	return 0;
}

static long uburma_jfae_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct uburma_cmd_hdr hdr;
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfae_uobj *jfae =
		container_of(uobj, struct uburma_jfae_uobj, uobj);
	int ret;

	if (cmd == UBURMA_CMD_GET_ASYNC_EVENT) {
		ret = (int)copy_from_user(&hdr, (struct uburma_cmd_hdr *)arg,
					  sizeof(struct uburma_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBURMA_CMD_MAX_ARGS_SIZE) ||
		    (hdr.args_len == 0 || hdr.args_addr == 0 ||
		     hdr.command >= UBURMA_EVENT_CMD_MAX)) {
			ret = -EINVAL;
		} else {
			ret = uburma_get_async_event(jfae, filp, &hdr);
		}
	} else {
		ret = -ENOIOCTLCMD;
	}

	return (long)ret;
}

static int uburma_jfae_fasync(int fd, struct file *filp, int on)
{
	int ret;
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_jfae_uobj *jfae =
		container_of(uobj, struct uburma_jfae_uobj, uobj);

	if (!uobj)
		return -EINVAL;
	spin_lock_irq(&jfae->jfe.lock);
	ret = fasync_helper(fd, filp, on, &jfae->jfe.async_queue);
	spin_unlock_irq(&jfae->jfe.lock);
	return ret;
}

const struct file_operations uburma_jfae_fops = {
	.owner = THIS_MODULE,
	.poll = uburma_jfae_poll,
	.release = uburma_delete_jfae,
	.unlocked_ioctl = uburma_jfae_ioctl,
	.fasync = uburma_jfae_fasync,
};

static void uburma_async_event_callback(struct ubcore_event *event,
					struct ubcore_event_handler *handler)
{
	struct uburma_jfae_uobj *jfae =
		container_of(handler, struct uburma_jfae_uobj, event_handler);

	if (WARN_ON(IS_ERR_OR_NULL(jfae)))
		return;

	uburma_write_event(&jfae->jfe, event->element.port_id,
			   event->event_type, NULL, NULL);
}

static inline void
uburma_init_jfae_handler(struct ubcore_event_handler *handler)
{
	INIT_LIST_HEAD(&handler->node);
	handler->event_callback = uburma_async_event_callback;
}

void uburma_init_jfae(struct uburma_jfae_uobj *jfae,
		      struct ubcore_device *ubc_dev)
{
	uburma_init_jfe(&jfae->jfe);
	uburma_init_jfae_handler(&jfae->event_handler);
	ubcore_register_event_handler(ubc_dev, &jfae->event_handler);
	jfae->dev = ubc_dev;
}

void uburma_release_comp_event(struct uburma_jfce_uobj *jfce,
			       struct list_head *event_list)
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

void uburma_release_async_event(struct uburma_file *ufile,
				struct list_head *event_list)
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

	if (!ufile->ucontext) {
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

	if (!ufile->ucontext)
		return;

	jfae = ufile->ucontext->jfae;
	if (IS_ERR_OR_NULL(jfae))
		return;

	uobj_put(&jfae->uobj);
}

static void uburma_flush_notifier(struct uburma_uobj *uobj,
				  struct uburma_file *file)
{
	struct uburma_notifier_uobj *notifier =
		container_of(uobj, struct uburma_notifier_uobj, uobj);
	int incomplete_cnt;
	uint32_t event_cnt;
	struct uburma_jfe_event *event = NULL;
	struct list_head event_list;
	struct list_head *p, *next;
	struct uburma_notify_event *notify;
	int ret;

	INIT_LIST_HEAD(&event_list);
	while ((incomplete_cnt = atomic_read(&notifier->incomplete_cnt)) > 0) {
		ret = uburma_wait_event(&notifier->jfe, false,
					(uint32_t)incomplete_cnt, &event_cnt,
					&event_list);
		if (notifier->jfe.deleting)
			break;
		if (ret < 0)
			continue;
		atomic_sub(event_cnt, &notifier->incomplete_cnt);
		list_for_each_safe(p, next, &event_list) {
			event = list_entry(p, struct uburma_jfe_event, node);
			notify = (struct uburma_notify_event *)(uintptr_t)
					 event->event_data;
			if (notify->notify.status == 0) {
				if (notify->notify.type ==
				    UBURMA_IMPORT_JETTY_NOTIFY)
					uburma_unimport_jetty(
						file, false,
						notify->tjetty_handle);
				else
					uburma_unbind_jetty(
						file, false,
						notify->jetty_handle,
						notify->tjetty_handle);
			}
			kfree((struct uburma_notify_event *)(uintptr_t)
				      event->event_data);
			list_del(p);
			kfree(event);
		}
	}
}

static int uburma_delete_notifier(struct inode *inode, struct file *filp)
{
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_file *ufile;

	if (!uobj || !uobj->ufile)
		return 0;

	uobj_get(uobj);
	ufile = uobj->ufile;
	uburma_flush_notifier(uobj, ufile);

	down_write(&ufile->ucontext_rwsem);
	/* call uburma_hot_unplug_notifier when cleanup is not going on */
	uburma_close_uobj_fd(filp);
	uobj->ufile = NULL;
	uobj_put(uobj);
	up_write(&ufile->ucontext_rwsem);
	kref_put(&ufile->ref, uburma_release_file);

	return 0;
}

static __poll_t uburma_notifier_poll(struct file *filp,
				     struct poll_table_struct *wait)
{
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_notifier_uobj *notifier =
		container_of(uobj, struct uburma_notifier_uobj, uobj);

	return uburma_jfe_poll(&notifier->jfe, filp, wait);
}

static int uburma_wait_notify(struct uburma_notifier_uobj *notifier,
			      struct file *filp, struct uburma_cmd_hdr *hdr)
{
	struct uburma_cmd_wait_notify arg = { 0 };
	struct list_head event_list;
	struct uburma_jfe_event *event = NULL;
	uint32_t event_cnt, max_event_cnt;
	uint32_t i = 0;
	struct list_head *p, *next;
	int ret;

	ret = uburma_event_tlv_parse(hdr, &arg);
	if (ret != 0)
		return -EFAULT;

	max_event_cnt =
		(arg.in.cnt < MAX_NOTIFY_CNT ? arg.in.cnt : MAX_NOTIFY_CNT);
	INIT_LIST_HEAD(&event_list);
	if (arg.in.timeout <= 0) {
		ret = uburma_wait_event(&notifier->jfe,
					(filp->f_flags & O_NONBLOCK) |
						(arg.in.timeout == 0),
					max_event_cnt, &event_cnt, &event_list);
	} else {
		ret = uburma_wait_event_timeout(
			&notifier->jfe, msecs_to_jiffies(arg.in.timeout),
			max_event_cnt, &event_cnt, &event_list);
	}

	if (ret < 0 && ret != -EAGAIN) {
		uburma_log_err("Failed to wait notify event");
		return ret;
	}

	arg.out.cnt = event_cnt;
	atomic_sub(event_cnt, &notifier->incomplete_cnt);
	list_for_each_safe(p, next, &event_list) {
		event = list_entry(p, struct uburma_jfe_event, node);
		arg.out.notify[i++] = ((struct uburma_notify_event *)(uintptr_t)
					       event->event_data)
					      ->notify;
		kfree((struct uburma_notify_event *)(uintptr_t)
			      event->event_data);
		list_del(p);
		kfree(event);
	}

	if (event_cnt > 0 && uburma_event_tlv_append(hdr, &arg) != 0)
		return -EFAULT;

	return 0;
}

static long uburma_notifier_ioctl(struct file *filp, unsigned int cmd,
				  unsigned long arg)
{
	struct uburma_cmd_hdr hdr;
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_notifier_uobj *notifier =
		container_of(uobj, struct uburma_notifier_uobj, uobj);
	int ret;

	if (cmd == UBURMA_CMD_WAIT_NOTIFY) {
		ret = (int)copy_from_user(&hdr, (struct uburma_cmd_hdr *)arg,
					  sizeof(struct uburma_cmd_hdr));
		if ((ret != 0) || (hdr.args_len > UBURMA_CMD_MAX_ARGS_SIZE) ||
		    (hdr.args_len == 0 || hdr.args_addr == 0 ||
		     hdr.command >= UBURMA_EVENT_CMD_MAX)) {
			ret = -EINVAL;
		} else {
			ret = uburma_wait_notify(notifier, filp, &hdr);
		}
	} else {
		ret = -ENOIOCTLCMD;
	}

	return (long)ret;
}

static int uburma_notifier_fasync(int fd, struct file *filp, int on)
{
	int ret;
	struct uburma_uobj *uobj = filp->private_data;
	struct uburma_notifier_uobj *notifier =
		container_of(uobj, struct uburma_notifier_uobj, uobj);

	if (!uobj)
		return -EINVAL;
	spin_lock_irq(&notifier->jfe.lock);
	ret = fasync_helper(fd, filp, on, &notifier->jfe.async_queue);
	spin_unlock_irq(&notifier->jfe.lock);
	return ret;
}

const struct file_operations uburma_notifier_fops = {
	.owner = THIS_MODULE,
	.poll = uburma_notifier_poll,
	.release = uburma_delete_notifier,
	.unlocked_ioctl = uburma_notifier_ioctl,
	.fasync = uburma_notifier_fasync,
};

struct uburma_notifier_uobj *uburma_get_notifier_uobj(int fd,
						      struct uburma_file *ufile)
{
	struct uburma_uobj *uobj;
	struct uburma_notifier_uobj *notifier;

	if (fd < 0)
		return ERR_PTR(-ENOENT);

	uobj = uobj_get_read(UOBJ_CLASS_NOTIFIER, fd, ufile);
	if (IS_ERR_OR_NULL(uobj)) {
		uburma_log_err("get notifier uobj fail with fd %d\n", fd);
		return (void *)uobj;
	}

	notifier = container_of(uobj, struct uburma_notifier_uobj, uobj);
	uobj_get(uobj); // To keep the event file until notifier destroy.
	uobj_put_read(uobj);
	return notifier;
}
