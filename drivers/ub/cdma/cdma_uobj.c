// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#include <linux/slab.h>
#include "cdma_mmap.h"
#include "cdma_uobj.h"
#include "cdma_chardev.h"

static int cdma_uobj_alloc_idr(struct cdma_uobj *uobj)
{
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock(&uobj->cfile->idr_lock);

	ret = idr_alloc(&uobj->cfile->idr, uobj, 0, U32_MAX, GFP_NOWAIT);
	if (ret >= 0)
		uobj->id = ret;

	spin_unlock(&uobj->cfile->idr_lock);
	idr_preload_end();

	return ret < 0 ? ret : 0;
}

static inline void cdma_uobj_remove_idr(struct cdma_uobj *uobj)
{
	spin_lock(&uobj->cfile->idr_lock);
	idr_remove(&uobj->cfile->idr, uobj->id);
	spin_unlock(&uobj->cfile->idr_lock);
}

static struct cdma_uobj *cdma_uobj_alloc(struct cdma_file *cfile,
					 enum cdma_uobj_type obj_type)
{
	struct cdma_uobj *uobj;

	uobj = kzalloc(sizeof(*uobj), GFP_KERNEL);
	if (uobj == NULL)
		return ERR_PTR(-ENOMEM);

	atomic_set(&uobj->rcnt, 0);
	uobj->cfile = cfile;
	uobj->type = obj_type;

	return uobj;
}

static inline void cdma_uobj_free(struct cdma_uobj *uobj)
{
	kfree(uobj);
}

static inline void cdma_uobj_remove(struct cdma_uobj *uobj)
{
	idr_remove(&uobj->cfile->idr, uobj->id);
	cdma_uobj_free(uobj);
}

void cdma_init_uobj_idr(struct cdma_file *cfile)
{
	idr_init(&cfile->idr);
	spin_lock_init(&cfile->idr_lock);
}

struct cdma_uobj *cdma_uobj_create(struct cdma_file *cfile,
				   enum cdma_uobj_type obj_type)
{
	struct cdma_uobj *uobj;
	int ret;

	uobj = cdma_uobj_alloc(cfile, obj_type);
	if (IS_ERR(uobj))
		return uobj;

	ret = cdma_uobj_alloc_idr(uobj);
	if (ret)
		goto err_free_uobj;

	return uobj;

err_free_uobj:
	cdma_uobj_free(uobj);

	return ERR_PTR(ret);
}

void cdma_uobj_delete(struct cdma_uobj *uobj)
{
	cdma_uobj_remove_idr(uobj);
	cdma_uobj_free(uobj);
}

struct cdma_uobj *cdma_uobj_get(struct cdma_file *cfile, int id,
				enum cdma_uobj_type obj_type)
{
	struct cdma_uobj *uobj;

	spin_lock(&cfile->idr_lock);
	uobj = idr_find(&cfile->idr, id);
	if (uobj == NULL || uobj->type != obj_type)
		uobj = ERR_PTR(-ENOENT);
	spin_unlock(&cfile->idr_lock);

	return uobj;
}

void cdma_cleanup_context_uobj(struct cdma_file *cfile, enum cdma_remove_reason why)
{
	struct cdma_uobj *uobj;
	int id;

	if (why == CDMA_REMOVE_DRIVER_REMOVE)
		cdma_unmap_vma_pages(cfile);

	spin_lock(&cfile->idr_lock);
	idr_for_each_entry(&cfile->idr, uobj, id)
		cdma_uobj_remove(uobj);
	spin_unlock(&cfile->idr_lock);
}

void cdma_close_uobj_fd(struct cdma_file *cfile)
{
	kref_put(&cfile->ref, cdma_release_file);
}
