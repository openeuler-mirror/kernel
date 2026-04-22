// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define pr_fmt(fmt) "CDMA: " fmt
#define dev_fmt pr_fmt

#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/rcupdate.h>
#include <linux/ioctl.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/minmax.h>
#include <uapi/ub/cdma/cdma_abi.h>
#include "cdma_uobj.h"
#include "cdma_event.h"

static __poll_t cdma_jfe_poll(struct cdma_jfe *jfe, struct file *filp,
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

static u32 cdma_read_jfe_event(struct cdma_jfe *jfe, u32 max_event_cnt,
			       struct list_head *event_list)
{
	struct cdma_jfe_event *event;
	struct list_head *next;
	struct list_head *p;
	u32 cnt = 0;

	if (!max_event_cnt)
		return 0;

	spin_lock_irq(&jfe->lock);

	list_for_each_safe(p, next, &jfe->event_list) {
		event = list_entry(p, struct cdma_jfe_event, node);
		if (event->counter) {
			++(*event->counter);
			list_del(&event->obj_node);
		}
		list_del(p);
		if (jfe->event_list_count > 0)
			jfe->event_list_count--;
		list_add_tail(p, event_list);
		cnt++;
		if (cnt == max_event_cnt)
			break;
	}
	spin_unlock_irq(&jfe->lock);

	return cnt;
}

static int cdma_wait_event(struct cdma_jfe *jfe, bool nonblock,
			   u32 max_event_cnt, u32 *event_cnt,
			   struct list_head *event_list)
{
	int ret;

	*event_cnt = 0;
	spin_lock_irq(&jfe->lock);
	while (list_empty(&jfe->event_list)) {
		spin_unlock_irq(&jfe->lock);
		if (nonblock)
			return -EAGAIN;

		ret = wait_event_interruptible(jfe->poll_wait,
					       !list_empty(&jfe->event_list));
		if (ret)
			return ret;

		spin_lock_irq(&jfe->lock);
		if (list_empty(&jfe->event_list)) {
			spin_unlock_irq(&jfe->lock);
			return -EIO;
		}
	}
	spin_unlock_irq(&jfe->lock);
	*event_cnt = cdma_read_jfe_event(jfe, max_event_cnt, event_list);

	return 0;
}

static int cdma_wait_event_timeout(struct cdma_jfe *jfe,
				   unsigned long max_timeout,
				   u32 max_event_cnt,
				   u32 *event_cnt,
				   struct list_head *event_list)
{
	long timeout = (long)max_timeout;

	*event_cnt = 0;
	while (1) {
		asm volatile("" : : : "memory");
		*event_cnt = cdma_read_jfe_event(jfe, max_event_cnt, event_list);
		if (*event_cnt > 0)
			break;
		timeout = wait_event_interruptible_timeout(jfe->poll_wait,
			  !list_empty(&jfe->event_list), timeout);
		if (timeout <= 0)
			return timeout;
	}

	return 0;
}

static int cdma_jfce_wait(struct cdma_jfce *jfce, struct file *filp,
			  unsigned long arg)
{
	struct cdma_cmd_jfce_wait_args we = { 0 };
	struct cdma_jfe_event *event;
	struct list_head event_list;
	struct list_head *next;
	struct list_head *p;
	u32 max_event_cnt;
	u32 i = 0;
	int ret;

	if (copy_from_user(&we, (const void __user *)arg,
			   (u32)sizeof(we)) != 0)
		return -EFAULT;

	max_event_cnt = min_t(u32, we.in.max_event_cnt, (u32)CDMA_MAX_JFCE_EVENT_CNT);
	INIT_LIST_HEAD(&event_list);
	if (we.in.time_out <= 0) {
		ret = cdma_wait_event(
			&jfce->jfe,
			(filp->f_flags & O_NONBLOCK) | (!we.in.time_out),
			max_event_cnt, &we.out.event_cnt, &event_list);
	} else {
		ret = cdma_wait_event_timeout(&jfce->jfe,
					      msecs_to_jiffies(we.in.time_out),
					      max_event_cnt, &we.out.event_cnt,
					      &event_list);
	}
	if (ret < 0) {
		pr_err("wait jfce event failed, ret = %d\n", ret);
		return ret;
	}

	list_for_each_safe(p, next, &event_list) {
		event = list_entry(p, struct cdma_jfe_event, node);
		we.out.event_data[i++] = event->event_data;
		list_del(p);
		kfree(event);
	}

	if (we.out.event_cnt > 0 && copy_to_user((void *)arg, &we, sizeof(we))) {
		pr_err("copy to user failed.\n");
		return -EFAULT;
	}

	return 0;
}

static __poll_t cdma_jfce_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct cdma_jfce *jfce = (struct cdma_jfce *)filp->private_data;

	if (!jfce)
		return POLLERR;

	return cdma_jfe_poll(&jfce->jfe, filp, wait);
}

static long cdma_jfce_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct cdma_jfce *jfce = (struct cdma_jfce *)filp->private_data;
	unsigned int nr = (unsigned int)_IOC_NR(cmd);
	long ret = -ENOIOCTLCMD;

	if (!arg || !jfce) {
		pr_err("jfce ioctl invalid parameter.\n");
		return -EINVAL;
	}

	if (_IOC_TYPE(cmd) != CDMA_EVENT_CMD_MAGIC) {
		pr_err("jfce ioctl invalid cmd type, cmd = %u.\n", cmd);
		return ret;
	}

	switch (nr) {
	case JFCE_CMD_WAIT_EVENT:
		ret = cdma_jfce_wait(jfce, filp, arg);
		break;
	default:
		pr_err("jfce ioctl wrong nr = %u.\n", nr);
	}

	return ret;
}

static int cdma_delete_jfce(struct inode *inode, struct file *filp)
{
	struct cdma_file *cfile;
	struct cdma_jfce *jfce;

	if (!filp || !filp->private_data)
		return 0;

	jfce = (struct cdma_jfce *)filp->private_data;

	cfile = jfce->cfile;
	if (!cfile)
		return 0;

	if (!mutex_trylock(&cfile->ctx_mutex))
		return -ENOLCK;
	cdma_destroy_jfce(jfce);
	filp->private_data = NULL;
	mutex_unlock(&cfile->ctx_mutex);
	cdma_close_uobj_fd(cfile);

	pr_info("jfce is release.\n");
	return 0;
}

static int cdma_jfce_fasync(int fd, struct file *filp, int on)
{
	struct cdma_jfce *jfce = (struct cdma_jfce *)filp->private_data;
	int ret;

	if (!jfce)
		return -EINVAL;

	spin_lock_irq(&jfce->jfe.lock);
	ret = fasync_helper(fd, filp, on, &jfce->jfe.async_queue);
	spin_unlock_irq(&jfce->jfe.lock);

	return ret;
}

const struct file_operations cdma_jfce_fops = {
	.owner = THIS_MODULE,
	.poll = cdma_jfce_poll,
	.unlocked_ioctl = cdma_jfce_ioctl,
	.release = cdma_delete_jfce,
	.fasync = cdma_jfce_fasync,
};

static int cdma_jfce_id_alloc(struct cdma_dev *cdev, struct cdma_jfce *jfce)
{
	struct cdma_table *jfce_tbl = &cdev->jfce_table;
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&jfce_tbl->lock);
	id = idr_alloc(&jfce_tbl->idr_tbl.idr, jfce, jfce_tbl->idr_tbl.min,
		       jfce_tbl->idr_tbl.max, GFP_NOWAIT);
	if (id < 0)
		dev_err(cdev->dev, "alloc jfce id failed.\n");
	spin_unlock(&jfce_tbl->lock);
	idr_preload_end();

	return id;
}

static void cdma_jfce_id_free(struct cdma_dev *cdev, u32 jfce_id)
{
	struct cdma_table *jfce_tbl = &cdev->jfce_table;

	spin_lock(&jfce_tbl->lock);
	idr_remove(&jfce_tbl->idr_tbl.idr, jfce_id);
	spin_unlock(&jfce_tbl->lock);
}

static void cdma_write_event(struct cdma_jfe *jfe, u64 event_data,
			     u32 event_type, struct list_head *obj_event_list,
			     u32 *counter)
{
	struct cdma_jfe_event *event;
	unsigned long flags;

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (event == NULL)
		return;

	spin_lock_irqsave(&jfe->lock, flags);
	INIT_LIST_HEAD(&event->obj_node);
	event->event_type = event_type;
	event->event_data = event_data;
	event->counter = counter;
	list_add_tail(&event->node, &jfe->event_list);
	if (obj_event_list)
		list_add_tail(&event->obj_node, obj_event_list);
	if (jfe->async_queue)
		kill_fasync(&jfe->async_queue, SIGIO, POLL_IN);
	jfe->event_list_count++;
	spin_unlock_irqrestore(&jfe->lock, flags);
	wake_up_interruptible(&jfe->poll_wait);
}

static void cdma_init_jfe(struct cdma_jfe *jfe)
{
	spin_lock_init(&jfe->lock);
	INIT_LIST_HEAD(&jfe->event_list);
	init_waitqueue_head(&jfe->poll_wait);
	jfe->async_queue = NULL;
	jfe->event_list_count = 0;
}

static void cdma_uninit_jfe(struct cdma_jfe *jfe)
{
	struct cdma_jfe_event *event;
	struct list_head *p, *next;

	spin_lock_irq(&jfe->lock);
	list_for_each_safe(p, next, &jfe->event_list) {
		event = list_entry(p, struct cdma_jfe_event, node);
		if (event->counter)
			list_del(&event->obj_node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
}

struct cdma_jfce *cdma_get_jfce_from_id(struct cdma_dev *cdev, int jfce_id)
{
	struct cdma_table *jfce_table = &cdev->jfce_table;
	struct cdma_jfce *jfce;
	struct file *file;

	spin_lock(&jfce_table->lock);
	jfce = idr_find(&jfce_table->idr_tbl.idr, jfce_id);
	if (!jfce) {
		dev_err(cdev->dev, "find jfce failed, id = %d.\n", jfce_id);
	} else {
		file = fget(jfce->fd);
		if (!file) {
			jfce = NULL;
		} else {
			if (file->private_data != jfce) {
				fput(file);
				jfce = NULL;
			}
		}
	}
	spin_unlock(&jfce_table->lock);

	return jfce;
}

void cdma_jfc_comp_event_cb(struct cdma_base_jfc *jfc)
{
	struct cdma_jfc_event *jfc_event;
	struct cdma_jfce *jfce;

	if (!jfc)
		return;

	jfc_event = &jfc->jfc_event;
	if (!IS_ERR_OR_NULL(jfc_event->jfce)) {
		jfce = jfc_event->jfce;
		if (jfce->jfe.event_list_count >= MAX_EVENT_LIST_SIZE)
			return;

		cdma_write_event(&jfce->jfe, jfc->jfc_cfg.queue_id, 0,
				 &jfc_event->comp_event_list,
				 &jfc_event->comp_events_reported);
	}
}

struct cdma_jfce *cdma_alloc_jfce(struct cdma_file *cfile)
{
	struct cdma_jfce *jfce;
	struct file *file;
	int new_fd;
	int ret;

	if (!cfile)
		return ERR_PTR(-EINVAL);

	new_fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (new_fd < 0)
		return ERR_PTR(new_fd);

	jfce = kzalloc(sizeof(*jfce), GFP_KERNEL);
	if (!jfce) {
		ret = -ENOMEM;
		goto err_put_unused_fd;
	}

	ret = cdma_jfce_id_alloc(cfile->cdev, jfce);
	if (ret < 0)
		goto err_free_jfce;
	jfce->id = ret;

	file = anon_inode_getfile("[jfce]", &cdma_jfce_fops, jfce,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_free_id;
	}

	cdma_init_jfe(&jfce->jfe);
	jfce->cdev = cfile->cdev;
	jfce->fd = new_fd;
	jfce->file = file;
	jfce->cfile = cfile;
	kref_get(&cfile->ref);
	fd_install(new_fd, file);

	return jfce;

err_free_id:
	cdma_jfce_id_free(cfile->cdev, jfce->id);
err_free_jfce:
	kfree(jfce);
err_put_unused_fd:
	put_unused_fd(new_fd);

	return ERR_PTR(ret);
}

void cdma_free_jfce(struct cdma_jfce *jfce)
{
	struct cdma_dev *cdev;

	if (!jfce || !jfce->cdev)
		return;

	cdev = jfce->cdev;

	if (jfce->id >= cdev->caps.jfce.max_cnt + cdev->caps.jfce.start_idx ||
		jfce->id < cdev->caps.jfce.start_idx) {
		dev_err(cdev->dev,
			"jfce id invalid, id = %u, start_idx = %u, max_cnt = %u.\n",
			jfce->id, cdev->caps.jfce.start_idx,
			cdev->caps.jfce.max_cnt);
		return;
	}

	fput(jfce->file);
	put_unused_fd(jfce->fd);
}

void cdma_destroy_jfce(struct cdma_jfce *jfce)
{
	if (!jfce)
		return;

	cdma_uninit_jfe(&jfce->jfe);
	if (jfce->cfile && jfce->cfile->cdev)
		cdma_jfce_id_free(jfce->cdev, jfce->id);
	kfree(jfce);
}

static void cdma_write_async_event(struct cdma_context *ctx, u64 event_data,
				   u32 type, struct list_head *obj_event_list,
				   u32 *counter)
{
	struct cdma_jfae *jfae;

	rcu_read_lock();
	jfae = rcu_dereference(ctx->jfae);
	if (!jfae)
		goto err_free_rcu;

	if (jfae->jfe.event_list_count >= MAX_EVENT_LIST_SIZE) {
		pr_debug(
			"event list overflow, and this write will be discarded.\n");
		goto err_free_rcu;
	}

	cdma_write_event(&jfae->jfe, event_data, type, obj_event_list, counter);

err_free_rcu:
	rcu_read_unlock();
}

void cdma_jfs_async_event_cb(struct cdma_event *event, struct cdma_context *ctx)
{
	struct cdma_jfs_event *jfs_event;

	jfs_event = &event->element.jfs->jfs_event;
	cdma_write_async_event(ctx, event->element.jfs->cfg.queue_id,
			       event->event_type, &jfs_event->async_event_list,
			       &jfs_event->async_events_reported);
}

void cdma_jfc_async_event_cb(struct cdma_event *event, struct cdma_context *ctx)
{
	struct cdma_jfc_event *jfc_event;

	jfc_event = &event->element.jfc->jfc_event;
	cdma_write_async_event(ctx, event->element.jfc->jfc_cfg.queue_id,
			       event->event_type, &jfc_event->async_event_list,
			       &jfc_event->async_events_reported);
}

static inline void cdma_set_async_event(struct cdma_cmd_async_event *async_event,
					const struct cdma_jfe_event *event)
{
	async_event->event_data = event->event_data;
	async_event->event_type = event->event_type;
}

static int cdma_get_async_event(struct cdma_jfae *jfae, struct file *filp,
				unsigned long arg)
{
	struct cdma_cmd_async_event async_event = { 0 };
	struct cdma_jfe_event *event;
	struct list_head event_list;
	struct cdma_context *ctx;
	struct cdma_dev *cdev;
	u32 event_cnt;
	int ret;

	if (!arg) {
		pr_err("invalid jfae arg.\n");
		return -EINVAL;
	}

	ctx = jfae->ctx;
	cdev = jfae->cfile->cdev;

	if (!cdev || cdev->status == CDMA_INVALID || !ctx || ctx->invalid) {
		pr_info("wait dev invalid event success.\n");
		async_event.event_data = 0;
		async_event.event_type = CDMA_EVENT_DEV_INVALID;
		ret = (int)copy_to_user((void *)arg, &async_event,
					sizeof(async_event));
		if (ret) {
			pr_err("dev copy to user failed, ret = %d\n", ret);
			return -EFAULT;
		}
	} else {
		INIT_LIST_HEAD(&event_list);
		ret = cdma_wait_event(&jfae->jfe, filp->f_flags & O_NONBLOCK, 1,
				      &event_cnt, &event_list);
		if (ret < 0) {
			pr_err("wait event failed, ret = %d.\n", ret);
			return ret;
		}
		event = list_first_entry(&event_list, struct cdma_jfe_event, node);
		if (event == NULL)
			return -EIO;

		cdma_set_async_event(&async_event, event);
		list_del(&event->node);
		kfree(event);

		if (event_cnt > 0) {
			ret = (int)copy_to_user((void *)arg, &async_event,
						sizeof(async_event));
			if (ret) {
				pr_err("dev copy to user failed, ret = %d\n", ret);
				return -EFAULT;
			}
		}
	}

	return 0;
}

static __poll_t cdma_jfae_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct cdma_jfae *jfae = (struct cdma_jfae *)filp->private_data;
	struct cdma_context *ctx;
	struct cdma_dev *cdev;

	if (!jfae || !jfae->cfile)
		return POLLERR;

	ctx = jfae->ctx;
	cdev = jfae->cfile->cdev;

	if (!cdev || cdev->status == CDMA_INVALID || !ctx || ctx->invalid)
		return POLLIN | POLLRDNORM;

	return cdma_jfe_poll(&jfae->jfe, filp, wait);
}

static long cdma_jfae_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct cdma_jfae *jfae = (struct cdma_jfae *)filp->private_data;
	unsigned int nr = (unsigned int)_IOC_NR(cmd);
	long ret = -ENOIOCTLCMD;

	if (!jfae) {
		pr_err("jfae ioctl invalid parameter.\n");
		return -EINVAL;
	}

	if (_IOC_TYPE(cmd) != CDMA_EVENT_CMD_MAGIC) {
		pr_err("jfae ioctl invalid cmd type, cmd = %u.\n", cmd);
		return ret;
	}

	switch (nr) {
	case JFAE_CMD_GET_ASYNC_EVENT:
		ret = cdma_get_async_event(jfae, filp, arg);
		break;
	default:
		pr_err("jfae ioctl wrong nr = %u.\n", nr);
	}

	return ret;
}

static int cdma_delete_jfae(struct inode *inode, struct file *filp)
{
	struct cdma_file *cfile;
	struct cdma_jfae *jfae;

	if (!filp || !filp->private_data)
		return 0;

	jfae = (struct cdma_jfae *)filp->private_data;
	cfile = jfae->cfile;
	if (!cfile)
		return 0;

	if (!mutex_trylock(&cfile->ctx_mutex))
		return -ENOLCK;

	if (jfae->ctx)
		jfae->ctx->jfae = NULL;

	cdma_uninit_jfe(&jfae->jfe);
	kfree(jfae);
	filp->private_data = NULL;
	mutex_unlock(&cfile->ctx_mutex);
	cdma_close_uobj_fd(cfile);

	pr_debug("jfae is release.\n");
	return 0;
}

static int cdma_jfae_fasync(int fd, struct file *filp, int on)
{
	struct cdma_jfae *jfae = (struct cdma_jfae *)filp->private_data;
	int ret;

	if (!jfae)
		return -EINVAL;

	spin_lock_irq(&jfae->jfe.lock);
	ret = fasync_helper(fd, filp, on, &jfae->jfe.async_queue);
	spin_unlock_irq(&jfae->jfe.lock);

	return ret;
}

const struct file_operations cdma_jfae_fops = {
	.owner = THIS_MODULE,
	.poll = cdma_jfae_poll,
	.unlocked_ioctl = cdma_jfae_ioctl,
	.release = cdma_delete_jfae,
	.fasync = cdma_jfae_fasync,
};

struct cdma_jfae *cdma_alloc_jfae(struct cdma_file *cfile)
{
	struct cdma_jfae *jfae;
	struct file *file;
	int fd;

	if (!cfile)
		return NULL;

	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	jfae = kzalloc(sizeof(*jfae), GFP_KERNEL);
	if (!jfae)
		goto err_put_unused_fd;

	file = anon_inode_getfile("[jfae]", &cdma_jfae_fops, jfae,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(file))
		goto err_free_jfae;

	cdma_init_jfe(&jfae->jfe);
	jfae->fd = fd;
	jfae->file = file;
	jfae->cfile = cfile;
	fd_install(fd, file);
	kref_get(&cfile->ref);
	return jfae;

err_free_jfae:
	kfree(jfae);
err_put_unused_fd:
	put_unused_fd(fd);

	return NULL;
}

void cdma_free_jfae(struct cdma_jfae *jfae)
{
	if (!jfae)
		return;

	fput(jfae->file);
	put_unused_fd(jfae->fd);
}

int cdma_get_jfae(struct cdma_context *ctx)
{
	struct cdma_jfae *jfae;
	struct file *file;

	if (!ctx)
		return -EINVAL;

	jfae = ctx->jfae;
	if (!jfae)
		return -EINVAL;

	file = fget(jfae->fd);
	if (!file)
		return -ENOENT;

	if (file->private_data != jfae) {
		fput(file);
		return -EBADF;
	}

	return 0;
}

void cdma_init_jfc_event(struct cdma_jfc_event *event, struct cdma_base_jfc *jfc)
{
	event->comp_events_reported = 0;
	event->async_events_reported = 0;
	INIT_LIST_HEAD(&event->comp_event_list);
	INIT_LIST_HEAD(&event->async_event_list);
	event->jfc = jfc;
}

void cdma_release_comp_event(struct cdma_jfce *jfce, struct list_head *event_list)
{
	struct cdma_jfe_event *event, *tmp;
	struct cdma_jfe *jfe;

	if (!jfce)
		return;

	jfe = &jfce->jfe;
	spin_lock_irq(&jfe->lock);
	list_for_each_entry_safe(event, tmp, event_list, obj_node) {
		list_del(&event->node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
	fput(jfce->file);
}

void cdma_release_async_event(struct cdma_context *ctx, struct list_head *event_list)
{
	struct cdma_jfe_event *event, *tmp;
	struct cdma_jfae *jfae;
	struct cdma_jfe *jfe;

	if (!ctx || !ctx->jfae)
		return;

	jfae = ctx->jfae;
	jfe = &jfae->jfe;
	spin_lock_irq(&jfe->lock);
	list_for_each_entry_safe(event, tmp, event_list, obj_node) {
		list_del(&event->node);
		kfree(event);
	}
	spin_unlock_irq(&jfe->lock);
	fput(jfae->file);
}

void cdma_put_jfae(struct cdma_context *ctx)
{
	struct cdma_jfae *jfae;

	if (!ctx)
		return;

	jfae = ctx->jfae;
	if (!jfae)
		return;

	if (!jfae->file)
		return;

	fput(jfae->file);
}
