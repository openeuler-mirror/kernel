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
#include "uburma_uobj.h"

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

int uobj_alloc_commit(struct uburma_uobj *uobj)
{
	/* relase write lock */
	atomic_set(&uobj->rcnt, 0);

	/* add uobj to list */
	mutex_lock(&uobj->ufile->uobjects_lock);
	list_add(&uobj->list, &uobj->ufile->uobjects);
	mutex_unlock(&uobj->ufile->uobjects_lock);

	uobj->type->type_class->alloc_commit(uobj);

	up_read(&uobj->ufile->cleanup_rwsem);
	return 0;
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
		uobj->type->type_class->lookup_put(uobj, true);
	} else if (!list_empty(&uobj->list)) {
		mutex_lock(&ufile->uobjects_lock);
		list_del_init(&uobj->list);
		mutex_unlock(&ufile->uobjects_lock);
		/* put the ref we took when we created the object */
		uobj_put(uobj);
	}

	return ret;
}

struct uburma_uobj *uobj_lookup_get(const struct uobj_type *type, struct uburma_file *ufile, int id,
				    enum uobj_access flag)
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
