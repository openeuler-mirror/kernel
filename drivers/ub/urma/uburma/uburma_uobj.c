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
 * Description: uobj framework in uburma
 * Author: Chen yujie
 * Create: 2022-09-07
 * Note:
 * History: 2022-09-07: create file
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

#include <urma/ubcore_types.h>
#include <urma/ubcore_uapi.h>

#include "uburma_types.h"
#include "uburma_file_ops.h"
#include "uburma_log.h"
#include "uburma_event.h"
#include "uburma_uobj.h"

static bool g_is_zero_fd;

static void uobj_free(struct kref *ref)
{
	kfree_rcu(container_of(ref, struct uburma_uobj, ref), rcu);
}

struct uburma_uobj *uobj_alloc_begin(const struct uobj_type *type, struct uburma_file *ufile)
{
	struct uburma_uobj *uobj;

	/* Cleanup is running. Calling this should have been impossible */
	if (!down_read_trylock(&ufile->cleanup_rwsem)) {
		uburma_log_warn("uobj: cleanup is running while allocating an uobject\n");
		return ERR_PTR(-EIO);
	}
	uobj = type->type_class->alloc_begin(type, ufile);
	if (IS_ERR(uobj))
		up_read(&ufile->cleanup_rwsem);
	return uobj;
}

void uobj_alloc_commit(struct uburma_uobj *uobj)
{
	/* relase write lock */
	atomic_set(&uobj->rcnt, 0);

	/* add uobj to list */
	mutex_lock(&uobj->ufile->uobjects_lock);
	list_add(&uobj->list, &uobj->ufile->uobjects);
	mutex_unlock(&uobj->ufile->uobjects_lock);

	uobj->type->type_class->alloc_commit(uobj);

	up_read(&uobj->ufile->cleanup_rwsem);
}

void uobj_alloc_abort(struct uburma_uobj *uobj)
{
	uburma_log_info("%s.\n", __func__);
	uobj->type->type_class->alloc_abort(uobj);
	up_read(&uobj->ufile->cleanup_rwsem);
}

void uobj_get(struct uburma_uobj *uobj)
{
	kref_get(&uobj->ref);
}

void uobj_put(struct uburma_uobj *uobj)
{
	kref_put(&uobj->ref, uobj_free);
}

/* Alloc buffer and init params. */
static struct uburma_uobj *alloc_uobj(struct uburma_file *ufile, const struct uobj_type *type)
{
	struct ubcore_device *ubc_dev;
	struct uburma_uobj *uobj;

	/* block read and write uobj if we are removing device */
	ubc_dev = srcu_dereference(ufile->ubu_dev->ubc_dev, &ufile->ubu_dev->ubc_dev_srcu);
	if (!ubc_dev)
		return ERR_PTR(-EIO);

	uobj = kzalloc(type->obj_size, GFP_KERNEL);
	if (uobj == NULL)
		return ERR_PTR(-ENOMEM);

	uobj->ufile = ufile;
	uobj->type = type;

	atomic_set(&uobj->rcnt, -1);
	kref_init(&uobj->ref);

	return uobj;
}

static int uobj_alloc_idr(struct uburma_uobj *uobj)
{
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock(&uobj->ufile->idr_lock);

	/* Alloc idr pointing to NULL. Will replace it once we commit. */
	ret = idr_alloc(&uobj->ufile->idr, NULL, 1,
		min_t(unsigned long, U32_MAX - 1U, INT_MAX), GFP_NOWAIT);
	if (ret >= 0)
		uobj->id = ret;

	spin_unlock(&uobj->ufile->idr_lock);
	idr_preload_end();

	return ret < 0 ? ret : 0;
}

static void uobj_remove_idr(struct uburma_uobj *uobj)
{
	spin_lock(&uobj->ufile->idr_lock);
	idr_remove(&uobj->ufile->idr, uobj->id);
	spin_unlock(&uobj->ufile->idr_lock);
}

static int uobj_try_lock(struct uburma_uobj *uobj, bool exclusive)
{
	/*
	 * When a shared access is required, we use a positive counter. Each
	 * shared access request checks that the value != -1 and increment it.
	 * Exclusive access is required for operations like write or destroy.
	 * In exclusive access mode, we check that the counter is zero (nobody
	 * claimed this object) and we set it to -1. Releasing a shared access
	 * lock is done simply by decreasing the counter. As for exclusive
	 * access locks, since only a single one of them is allowed
	 * concurrently, setting the counter to zero is enough for releasing
	 * this lock.
	 */
	if (!exclusive)
		return atomic_add_unless(&uobj->rcnt, 1, -1) ? 0 : -EBUSY;

	/* lock is either WRITE or DESTROY - should be exclusive */
	return atomic_cmpxchg(&uobj->rcnt, 0, -1) == 0 ? 0 : -EBUSY;
}

static void uobj_unlock(struct uburma_uobj *uobj, bool exclusive)
{
	/*
	 * In order to unlock an object, either decrease its rcnt for
	 * read access or zero it in case of exclusive access. See
	 * uverbs_try_lock_object for locking schema information.
	 */
	if (!exclusive)
		atomic_dec(&uobj->rcnt);
	else
		atomic_set(&uobj->rcnt, 0);
}

static int __must_check uobj_remove_commit_internal(struct uburma_uobj *uobj,
						    enum uburma_remove_reason why)
{
	struct uburma_file *ufile = uobj->ufile;
	int ret;

	ret = uobj->type->type_class->remove_commit(uobj, why);
	if (ret && why == UBURMA_REMOVE_DESTROY) {
		/* We couldn't remove the object, so just unlock the uobject */
		atomic_set(&uobj->rcnt, 0);
		uobj->type->type_class->lookup_put(uobj, UOBJ_ACCESS_NOLOCK);
	} else if (!list_empty(&uobj->list)) {
		mutex_lock(&ufile->uobjects_lock);
		list_del_init(&uobj->list);
		mutex_unlock(&ufile->uobjects_lock);
		/* put the ref we took when we created the object */
		uobj_put(uobj);
	}

	return ret;
}

static int uobj_cg_try_charge(struct uburma_uobj *uobj)
{
	return ubcore_cgroup_try_charge(&uobj->cg_obj, uobj->ufile->ucontext->ub_dev,
									UBCORE_RESOURCE_HCA_OBJECT);
}

static void uboj_cg_uncharge(struct uburma_uobj *uobj)
{
	ubcore_cgroup_uncharge(&uobj->cg_obj, uobj->ufile->ucontext->ub_dev,
						   UBCORE_RESOURCE_HCA_OBJECT);
}

static struct uburma_uobj *uobj_idr_alloc_begin(const struct uobj_type *type,
						struct uburma_file *ufile)
{
	struct uburma_uobj *uobj;
	int ret;

	uobj = alloc_uobj(ufile, type);
	if (IS_ERR(uobj))
		return uobj;

	ret = uobj_alloc_idr(uobj);
	if (ret)
		goto put_obj;

	ret = uobj_cg_try_charge(uobj);
	if (ret != 0) {
		uburma_log_warn("cgroup charge failed");
		goto remove;
	}
	return uobj;

remove:
	uobj_remove_idr(uobj);
put_obj:
	uobj_put(uobj);
	return ERR_PTR(ret);
}

static void uobj_idr_alloc_commit(struct uburma_uobj *uobj)
{
	spin_lock(&uobj->ufile->idr_lock);
	WARN_ON(idr_replace(&uobj->ufile->idr, uobj, uobj->id));
	spin_unlock(&uobj->ufile->idr_lock);
}

static void uobj_idr_alloc_abort(struct uburma_uobj *uobj)
{
	uboj_cg_uncharge(uobj);
	uobj_remove_idr(uobj);
	uobj_put(uobj);
}

static struct uburma_uobj *uobj_idr_lookup_get(const struct uobj_type *type,
					       struct uburma_file *ufile, int id,
					       enum uobj_access flag)
{
	struct uburma_uobj *uobj = NULL;

	rcu_read_lock();
	/* Object won't be released as we're protected in rcu. */
	uobj = idr_find(&ufile->idr, id);
	if (uobj == NULL) {
		uobj = ERR_PTR(-ENOENT);
		goto free;
	}

	/* Object associated with uobj may have been released. */
	if (!kref_get_unless_zero(&uobj->ref))
		uobj = ERR_PTR(-ENOENT);

free:
	rcu_read_unlock();
	return uobj;
}

static void uobj_idr_lookup_put(struct uburma_uobj *uobj, enum uobj_access flag)
{
	/* Empty for now. */
}

static int __must_check uobj_idr_remove_commit(struct uburma_uobj *uobj,
					       enum uburma_remove_reason why)
{
	const struct uobj_idr_type *idr_type = container_of(uobj->type, struct uobj_idr_type, type);
	/* Call object destroy function. */
	int ret = idr_type->destroy_func(uobj, why);

	/* Only user req destroy may fail. */
	if (why == UBURMA_REMOVE_DESTROY && ret)
		return ret;

	uboj_cg_uncharge(uobj);
	uobj_remove_idr(uobj);
	return ret;
}

static struct uburma_uobj *uobj_fd_alloc_begin(const struct uobj_type *type,
					       struct uburma_file *ufile)
{
	const struct uobj_fd_type *fd_type = container_of(type, struct uobj_fd_type, type);
	struct uburma_uobj *uobj;
	struct file *filp;
	int new_fd;

	new_fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (new_fd < 0)
		return ERR_PTR(new_fd);

	if (new_fd == 0) {
		new_fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
		if (new_fd < 0)
			return ERR_PTR(new_fd);
		g_is_zero_fd = true;
	}

	uobj = alloc_uobj(ufile, type);
	if (IS_ERR(uobj)) {
		put_unused_fd(new_fd);
		return uobj;
	}

	filp = anon_inode_getfile(fd_type->name, fd_type->fops, uobj, fd_type->flags);
	if (IS_ERR(filp)) {
		put_unused_fd(new_fd);
		uobj_put(uobj);
		return (void *)filp;
	}

	uobj->id = new_fd;
	uobj->object = filp;

	kref_get(&ufile->ref);

	return uobj;
}

static void uobj_fd_alloc_commit(struct uburma_uobj *uobj)
{
	struct file *filp = (struct file *)uobj->object;

	fd_install(uobj->id, filp);

	/* Do not set uobj->id = 0 as it may be read when remove uobj */

	/* Get another reference as we export this to the fops */
	uobj_get(uobj);
}

static void uobj_fd_alloc_abort(struct uburma_uobj *uobj)
{
	struct file *filp = uobj->object;

	/* Unsuccessful NEW */
	fput(filp);
	put_unused_fd(uobj->id);
}

static struct uburma_uobj *uobj_fd_lookup_get(const struct uobj_type *type,
	struct uburma_file *ufile, int id, enum uobj_access flag)
{
	const struct uobj_fd_type *fd_type = container_of(type, struct uobj_fd_type, type);
	struct uburma_uobj *uobj;
	struct file *f;

	if (flag != UOBJ_ACCESS_READ)
		return ERR_PTR(-EOPNOTSUPP);

	f = fget(id);
	if (f == NULL)
		return ERR_PTR(-EBADF);

	uobj = f->private_data;
	/*
	 * fget(id) ensures we are not currently running close_fd,
	 * and the caller is expected to ensure that close_fd is never
	 * done while a call top lookup is possible.
	 */
	if (f->f_op != fd_type->fops) {
		fput(f);
		return ERR_PTR(-EBADF);
	}

	uobj_get(uobj);
	return uobj;
}

static void uobj_fd_lookup_put(struct uburma_uobj *uobj, enum uobj_access flag)
{
	struct file *filp = uobj->object;

	WARN_ON(flag != UOBJ_ACCESS_READ);
	/* This indirectly calls close_fd and free the object */
	fput(filp);
}

static int __must_check uobj_fd_remove_commit(struct uburma_uobj *uobj,
					      enum uburma_remove_reason why)
{
	const struct uobj_fd_type *fd_type = container_of(uobj->type, struct uobj_fd_type, type);
	/* Call user close function. */
	int ret = fd_type->context_closed(uobj, why);

	if (why == UBURMA_REMOVE_DESTROY && ret)
		return ret;

	if (why == UBURMA_REMOVE_DURING_CLEANUP) {
		uobj_fd_alloc_abort(uobj);
		return ret;
	}

	return ret;
}

struct uburma_uobj *uobj_lookup_get(const struct uobj_type *type,
	struct uburma_file *ufile, int id, enum uobj_access flag)
{
	struct ubcore_device *ubc_dev;
	struct uburma_uobj *uobj;
	int ret;

	uobj = type->type_class->lookup_get(type, ufile, id, flag);
	if (IS_ERR(uobj))
		return uobj;

	if (uobj->type != type) {
		ret = -EINVAL;
		goto free;
	}

	/* block read and write uobj if we are removing device */
	ubc_dev = srcu_dereference(ufile->ubu_dev->ubc_dev, &ufile->ubu_dev->ubc_dev_srcu);
	if (!ubc_dev) {
		ret = -EIO;
		goto free;
	}

	if (flag == UOBJ_ACCESS_NOLOCK)
		return uobj;

	ret = uobj_try_lock(uobj, flag == UOBJ_ACCESS_WRITE);
	if (ret) {
		WARN(ufile->cleanup_reason, "uburma: Trying to lookup_get while cleanup context\n");
		goto free;
	}

	return uobj;
free:
	uobj->type->type_class->lookup_put(uobj, flag);
	/* pair with uobj_get in uobj_fd_lookup_get */
	uobj_put(uobj);
	return ERR_PTR(ret);
}

void uobj_lookup_put(struct uburma_uobj *uobj, enum uobj_access flag)
{
	uobj->type->type_class->lookup_put(uobj, flag);

	if (flag != UOBJ_ACCESS_NOLOCK)
		uobj_unlock(uobj, flag == UOBJ_ACCESS_WRITE); /* match with uobj_try_lock */

	uobj_put(uobj);
}

int __must_check uobj_remove_commit(struct uburma_uobj *uobj)
{
	struct uburma_file *ufile = uobj->ufile;
	int ret;

	/* put the ref count we took at lookup_get */
	uobj_put(uobj);

	down_read(&ufile->cleanup_rwsem);
	/* try Lock uobj for write with cleanup_rwsem locked */
	ret = uobj_try_lock(uobj, true);
	if (ret) {
		/* Do not rollback uobj_put here */
		up_read(&ufile->cleanup_rwsem);
		uburma_log_warn("Failed to lock uobj\n");
		return ret;
	}

	ret = uobj_remove_commit_internal(uobj, UBURMA_REMOVE_DESTROY);

	up_read(&ufile->cleanup_rwsem);
	return ret;
}

void uburma_init_uobj_context(struct uburma_file *ufile)
{
	g_is_zero_fd = false;
	ufile->cleanup_reason = 0;
	idr_init(&ufile->idr);
	spin_lock_init(&ufile->idr_lock);
	INIT_LIST_HEAD(&ufile->uobjects);
	mutex_init(&ufile->uobjects_lock);
	init_rwsem(&ufile->cleanup_rwsem);
}

static inline void do_clean_uobj(struct uburma_uobj *obj, unsigned int cur_order,
	enum uburma_remove_reason why)
{
	int ret;
	/* if we hit this WARN_ON,
	 * that means we are racing with a lookup_get.
	 */
	WARN_ON(uobj_try_lock(obj, true));
	ret = obj->type->type_class->remove_commit(obj, why);
	if (ret)
		pr_warn("uburma: failed to remove uobject id %d order %u\n",
			obj->id, cur_order);

	list_del_init(&obj->list);

	/* uburma_close_uobj_fd will also try lock the uobj for write */
	if (uobj_type_is_fd(obj))
		uobj_unlock(obj, true); /* match with uobj_try_lock */

	/* put the ref we took when we created the object */
	uobj_put(obj);
}

void uburma_cleanup_uobjs(struct uburma_file *ufile, enum uburma_remove_reason why)
{
	unsigned int cur_order = 0;

	ufile->cleanup_reason = why;
	down_write(&ufile->cleanup_rwsem);

	while (!list_empty(&ufile->uobjects)) {
		struct uburma_uobj *obj, *next_obj;
		unsigned int next_order = UINT_MAX;

		mutex_lock(&ufile->uobjects_lock);
		list_for_each_entry_safe(obj, next_obj, &ufile->uobjects, list) {
			if (obj->type->destroy_order == cur_order)
				do_clean_uobj(obj, cur_order, why);
			else
				next_order = min(next_order, obj->type->destroy_order);
		}
		mutex_unlock(&ufile->uobjects_lock);
		cur_order = next_order;
	}
	if (g_is_zero_fd == true) {
		put_unused_fd(0);
		g_is_zero_fd = false;
	}
	up_write(&ufile->cleanup_rwsem);
}

static int uburma_free_token_id(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	return ubcore_free_token_id((struct ubcore_token_id *)uobj->object);
}

static int uburma_free_seg(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	return ubcore_unregister_seg((struct ubcore_target_seg *)uobj->object);
}

static int uburma_free_jfc(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jfc_uobj *jfc_uobj = container_of(uobj, struct uburma_jfc_uobj, uobj);
	struct ubcore_jfc *jfc = (struct ubcore_jfc *)uobj->object;
	struct uburma_jfce_uobj *jfce_uobj;
	int ret;

	ret = ubcore_delete_jfc(jfc);
	if (ret)
		return ret;

	if (!IS_ERR(jfc_uobj->jfce)) {
		jfce_uobj = container_of(jfc_uobj->jfce, struct uburma_jfce_uobj, uobj);
		uburma_release_comp_event(jfce_uobj, &jfc_uobj->comp_event_list);
		uobj_put(jfc_uobj->jfce);
	}

	uburma_release_async_event(uobj->ufile, &jfc_uobj->async_event_list);
	return ret;
}

static int uburma_free_jfs(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jfs_uobj *jfs_uobj = container_of(uobj, struct uburma_jfs_uobj, uobj);
	int ret;

	ret = ubcore_delete_jfs((struct ubcore_jfs *)uobj->object);
	if (ret)
		return ret;

	uburma_release_async_event(uobj->ufile, &jfs_uobj->async_event_list);
	return ret;
}

static int uburma_free_jfr(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jfr_uobj *jfr_uobj = container_of(uobj, struct uburma_jfr_uobj, uobj);
	int ret;

	ret = ubcore_delete_jfr((struct ubcore_jfr *)uobj->object);
	if (ret)
		return ret;

	uburma_release_async_event(uobj->ufile, &jfr_uobj->async_event_list);
	return ret;
}

static int uburma_free_jetty(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jetty_uobj *jetty_uobj = container_of(uobj, struct uburma_jetty_uobj, uobj);
	int ret;

	ret = ubcore_delete_jetty((struct ubcore_jetty *)uobj->object);
	if (ret)
		return ret;

	uburma_release_async_event(uobj->ufile, &jetty_uobj->async_event_list);
	return ret;
}

static int uburma_free_jetty_grp(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jetty_grp_uobj *jetty_grp_uobj =
		container_of(uobj, struct uburma_jetty_grp_uobj, uobj);
	int ret;

	ret = ubcore_delete_jetty_grp((struct ubcore_jetty_group *)uobj->object);
	if (ret)
		return ret;

	uburma_release_async_event(uobj->ufile, &jetty_grp_uobj->async_event_list);
	return ret;
}

static int uburma_free_tjfr(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	return ubcore_unimport_jfr((struct ubcore_tjetty *)uobj->object);
}

static void uburma_free_tjetty_refcnt(struct uburma_tjetty_uobj *uburma_tjetty)
{
	struct ubcore_jetty *jetty;

	jetty = (struct ubcore_jetty *)uburma_tjetty->jetty_uobj->uobj.object;
	if (jetty->remote_jetty != NULL) {
		atomic_set(&jetty->remote_jetty->use_cnt, 0);
		jetty->remote_jetty = NULL;
	}
}

static int uburma_free_tjetty(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_tjetty_uobj *uburma_tjetty;

	uburma_tjetty = (struct uburma_tjetty_uobj *)uobj;
	if (uburma_tjetty->jetty_uobj != NULL) {
		(void)ubcore_unbind_jetty(uburma_tjetty->jetty_uobj->uobj.object);
		/* When resetting the network card, socket messages cannot be sent.
		 * Unbind jetty cannot succeed. The tjetty reference needs to be released,
		 * otherwise unimport jetty cannot succeed.
		 */
		uburma_free_tjetty_refcnt(uburma_tjetty);
		uburma_tjetty->jetty_uobj = NULL;
		uburma_log_warn("unbind_jetty hasn't been done and it has been handled");
	}
	return ubcore_unimport_jetty((struct ubcore_tjetty *)uobj->object);
}

static int uburma_free_tseg(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	return ubcore_unimport_seg((struct ubcore_target_seg *)uobj->object);
}

void uburma_close_uobj_fd(struct file *f)
{
	struct uburma_uobj *uobj = f->private_data;
	struct uburma_file *ufile = uobj->ufile;
	int ret;

	if (down_read_trylock(&ufile->cleanup_rwsem)) {
		/*
		 * uobj_fd_lookup_get holds the kref on the struct file any
		 * time a FD uobj is locked, which prevents this release
		 * method from being invoked. Meaning we can always get the
		 * write lock here, or we have a kernel bug.
		 */
		WARN_ON(uobj_try_lock(uobj, true));
		ret = uobj_remove_commit_internal(uobj, UBURMA_REMOVE_CLOSE);
		up_read(&ufile->cleanup_rwsem);
		if (ret)
			pr_warn("uburma: unable to clean up uobj file.\n");
	}

	/* Matches the get in alloc_begin_fd_uobject */
	kref_put(&ufile->ref, uburma_release_file);

	/* Pairs with filp->private_data in alloc_begin_fd_uobject */
	uobj_put(uobj);
}

static int uburma_hot_unplug_jfce(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jfce_uobj *jfce = container_of(uobj, struct uburma_jfce_uobj, uobj);
	struct uburma_jfe *jfe = &jfce->jfe;

	spin_lock_irq(&jfe->lock);
	if (jfe->deleting == true) {
		spin_unlock_irq(&jfe->lock);
		return 0;
	}
	jfe->deleting = true;
	spin_unlock_irq(&jfe->lock);

	if (why == UBURMA_REMOVE_DRIVER_REMOVE)
		wake_up_interruptible(&jfe->poll_wait);

	uburma_uninit_jfe(jfe);
	return 0;
}

static int uburma_hot_unplug_jfae(struct uburma_uobj *uobj, enum uburma_remove_reason why)
{
	struct uburma_jfae_uobj *jfae = container_of(uobj, struct uburma_jfae_uobj, uobj);
	struct uburma_jfe *jfe = &jfae->jfe;

	spin_lock_irq(&jfe->lock);
	if (jfe->deleting == true) {
		spin_unlock_irq(&jfe->lock);
		return 0;
	}
	spin_unlock_irq(&jfe->lock);

	if (why == UBURMA_REMOVE_DRIVER_REMOVE)
		uburma_write_event(&jfae->jfe, 0, UBCORE_EVENT_DEV_FATAL, NULL, NULL);

	spin_lock_irq(&jfe->lock);
	jfe->deleting = true;
	ubcore_unregister_event_handler(jfae->dev, &jfae->event_handler);
	spin_unlock_irq(&jfe->lock);

	return 0;
}

const struct uobj_type_class uobj_idr_type_class = {
	.alloc_begin = uobj_idr_alloc_begin,
	.alloc_commit = uobj_idr_alloc_commit,
	.alloc_abort = uobj_idr_alloc_abort,
	.lookup_get = uobj_idr_lookup_get,
	.lookup_put = uobj_idr_lookup_put,
	.remove_commit = uobj_idr_remove_commit,
};

const struct uobj_type_class uobj_fd_type_class = {
	.alloc_begin = uobj_fd_alloc_begin,
	.alloc_commit = uobj_fd_alloc_commit,
	.alloc_abort = uobj_fd_alloc_abort,
	.lookup_get = uobj_fd_lookup_get,
	.lookup_put = uobj_fd_lookup_put,
	.remove_commit = uobj_fd_remove_commit,
};

/* The destroy process start from order 0. */
declare_uobj_class(UOBJ_CLASS_JFCE,
		   &uobj_type_alloc_fd(3, sizeof(struct uburma_jfce_uobj), uburma_hot_unplug_jfce,
				       &uburma_jfce_fops, "[jfce]", O_RDWR | O_CLOEXEC));

declare_uobj_class(UOBJ_CLASS_JFAE,
	&uobj_type_alloc_fd(3, sizeof(struct uburma_jfae_uobj), uburma_hot_unplug_jfae,
						&uburma_jfae_fops, "[jfae]", O_RDWR | O_CLOEXEC));

declare_uobj_class(UOBJ_CLASS_JFC, &uobj_type_alloc_idr(sizeof(struct uburma_jfc_uobj), 2,
	uburma_free_jfc));
declare_uobj_class(UOBJ_CLASS_TOKEN, &uobj_type_alloc_idr(sizeof(struct uburma_uobj), 1,
	uburma_free_token_id));
declare_uobj_class(UOBJ_CLASS_SEG, &uobj_type_alloc_idr(sizeof(struct uburma_uobj), 1,
	uburma_free_seg));
declare_uobj_class(UOBJ_CLASS_JFS, &uobj_type_alloc_idr(sizeof(struct uburma_jfs_uobj), 1,
	uburma_free_jfs));
declare_uobj_class(UOBJ_CLASS_JFR, &uobj_type_alloc_idr(sizeof(struct uburma_jfr_uobj), 1,
	uburma_free_jfr));
declare_uobj_class(UOBJ_CLASS_JETTY, &uobj_type_alloc_idr(sizeof(struct uburma_jetty_uobj), 1,
	uburma_free_jetty));
declare_uobj_class(UOBJ_CLASS_JETTY_GRP, &uobj_type_alloc_idr(
	sizeof(struct uburma_jetty_grp_uobj), 1, uburma_free_jetty_grp));
declare_uobj_class(UOBJ_CLASS_TARGET_JFR, &uobj_type_alloc_idr(sizeof(struct uburma_uobj), 0,
	uburma_free_tjfr));
declare_uobj_class(UOBJ_CLASS_TARGET_JETTY, &uobj_type_alloc_idr(sizeof(struct uburma_tjetty_uobj),
	0, uburma_free_tjetty));
declare_uobj_class(UOBJ_CLASS_TARGET_SEG, &uobj_type_alloc_idr(sizeof(struct uburma_uobj), 0,
	uburma_free_tseg));
