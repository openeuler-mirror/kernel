// SPDX-License-Identifier: GPL-2.0-or-later
/* CacheFiles extended attribute management
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/slab.h>
#include "internal.h"

static const char cachefiles_xattr_cache[] =
	XATTR_USER_PREFIX "CacheFiles.cache";

#define CACHEFILES_COOKIE_TYPE_DATA 1
#define CACHEFILES_CONTENT_NO_DATA 0 /* No content stored */

struct cachefiles_obj_xattr {
	__be64	object_size;	/* Actual size of the object */
	__be64	zero_point;     /* always zero */
	__u8	type;           /* Type of object */
	__u8	content;        /* always zero */
	__u8	data[];         /* netfs coherency data, always NULL */
} __packed;

struct cachefiles_vol_xattr {
	__be32  reserved;	/* Reserved, should be 0 */
	__u8    data[];		/* netfs volume coherency data, NULL */
} __packed;

struct cachefiles_vol_xattr new_vol_xattr;

static int cachefiles_set_new_vol_xattr(struct cachefiles_object *object);
static int cachefiles_check_new_vol_xattr(struct cachefiles_object *object);
static int cachefiles_set_new_obj_xattr(struct cachefiles_object *object);
static int cachefiles_check_new_obj_xattr(struct cachefiles_object *object);

/*
 * check the type label on an object
 * - done using xattrs
 */
int cachefiles_check_object_type(struct cachefiles_object *object,
				 struct cachefiles_cache *cache)
{
	struct dentry *dentry = object->dentry;
	char type[3], xtype[3];
	int ret;

	ASSERT(dentry);
	ASSERT(d_backing_inode(dentry));

	if (!object->fscache.cookie)
		strcpy(type, "C3");
	else
		snprintf(type, 3, "%02x", object->fscache.cookie->def->type);

	_enter("%p{%s}", object, type);

	/* attempt to install a type label directly */
	ret = mnt_want_write(cache->mnt);
	if (ret == 0) {
		ret = vfs_setxattr(dentry, cachefiles_xattr_cache, type, 2,
				   XATTR_CREATE);
		mnt_drop_write(cache->mnt);
	}
	if (ret == 0) {
		_debug("SET"); /* we succeeded */
		goto error;
	}

	if (ret != -EEXIST) {
		pr_err("Can't set xattr on %pd [%lu] (err %d)\n",
		       dentry, d_backing_inode(dentry)->i_ino,
		       -ret);
		goto error;
	}

	/* read the current type label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cache, xtype, 3);
	if (ret < 0) {
		if (ret == -ERANGE)
			goto bad_type_length;

		pr_err("Can't read xattr on %pd [%lu] (err %d)\n",
		       dentry, d_backing_inode(dentry)->i_ino,
		       -ret);
		goto error;
	}

	/* check the type is what we're expecting */
	if (ret != 2)
		goto bad_type_length;

	if (xtype[0] != type[0] || xtype[1] != type[1])
		goto bad_type;

	ret = 0;

error:
	_leave(" = %d", ret);
	return ret;

bad_type_length:
	pr_err("Cache object %lu type xattr length incorrect\n",
	       d_backing_inode(dentry)->i_ino);
	ret = -EIO;
	goto error;

bad_type:
	xtype[2] = 0;
	pr_err("Cache object %pd [%lu] type %s not %s\n",
	       dentry, d_backing_inode(dentry)->i_ino,
	       xtype, type);
	ret = -EIO;
	goto error;
}

/*
 * set the state xattr on a cache file
 */
int cachefiles_set_object_xattr(struct cachefiles_object *object,
				struct cachefiles_xattr *auxdata)
{
	struct dentry *dentry = object->dentry;
	struct cachefiles_cache *cache;
	int ret;

	ASSERT(dentry);

	_enter("%p,#%d", object, auxdata->len);

	/* attempt to install the cache metadata directly */
	_debug("SET #%u", auxdata->len);

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	clear_bit(FSCACHE_COOKIE_AUX_UPDATED, &object->fscache.cookie->flags);
	ret = mnt_want_write(cache->mnt);
	if (ret == 0) {
		if (data_new_version(object->fscache.cookie))
			ret = cachefiles_set_new_obj_xattr(object);
		else if (volume_new_version(object->fscache.cookie))
			ret = cachefiles_set_new_vol_xattr(object);
		else
			ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
					   &auxdata->type, auxdata->len,
					   XATTR_CREATE);
		mnt_drop_write(cache->mnt);
	}
	if (ret < 0 && ret != -ENOMEM)
		cachefiles_io_error_obj(
			object,
			"Failed to set xattr with error %d", ret);

	_leave(" = %d", ret);
	return ret;
}

/*
 * update the state xattr on a cache file
 */
int cachefiles_update_object_xattr(struct cachefiles_object *object,
				   struct cachefiles_xattr *auxdata)
{
	struct dentry *dentry = object->dentry;
	struct cachefiles_cache *cache;
	int ret;

	if (!dentry)
		return -ESTALE;

	_enter("%p,#%d", object, auxdata->len);

	/* attempt to install the cache metadata directly */
	_debug("SET #%u", auxdata->len);

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	clear_bit(FSCACHE_COOKIE_AUX_UPDATED, &object->fscache.cookie->flags);
	ret = mnt_want_write(cache->mnt);
	if (ret == 0) {
		ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
				   &auxdata->type, auxdata->len,
				   XATTR_REPLACE);
		mnt_drop_write(cache->mnt);
	}
	if (ret < 0 && ret != -ENOMEM)
		cachefiles_io_error_obj(
			object,
			"Failed to update xattr with error %d", ret);

	_leave(" = %d", ret);
	return ret;
}

/*
 * check the consistency between the backing cache and the FS-Cache cookie
 */
int cachefiles_check_auxdata(struct cachefiles_object *object)
{
	struct cachefiles_xattr *auxbuf;
	enum fscache_checkaux validity;
	struct dentry *dentry = object->dentry;
	ssize_t xlen;
	int ret;

	ASSERT(dentry);
	ASSERT(d_backing_inode(dentry));
	ASSERT(object->fscache.cookie->def->check_aux);

	auxbuf = kmalloc(sizeof(struct cachefiles_xattr) + 512, GFP_KERNEL);
	if (!auxbuf)
		return -ENOMEM;

	xlen = vfs_getxattr(dentry, cachefiles_xattr_cache,
			    &auxbuf->type, 512 + 1);
	ret = -ESTALE;
	if (xlen < 1 ||
	    auxbuf->type != object->fscache.cookie->def->type)
		goto error;

	xlen--;
	validity = fscache_check_aux(&object->fscache, &auxbuf->data, xlen,
				     i_size_read(d_backing_inode(dentry)));
	if (validity != FSCACHE_CHECKAUX_OKAY)
		goto error;

	ret = 0;
error:
	kfree(auxbuf);
	return ret;
}

int cachefiles_check_old_object_xattr(struct cachefiles_object *object,
				      struct cachefiles_xattr *auxdata)
{
	struct cachefiles_xattr *auxbuf;
	struct cachefiles_cache *cache;
	unsigned int len = sizeof(struct cachefiles_xattr) + 512;
	struct dentry *dentry = object->dentry;
	int ret;

	auxbuf = kmalloc(len, cachefiles_gfp);
	if (!auxbuf)
		return -ENOMEM;

	/* read the current type label */
	ret = vfs_getxattr(dentry, cachefiles_xattr_cache,
			   &auxbuf->type, 512 + 1);
	if (ret < 0)
		goto error;

	/* check the on-disk object */
	if (ret < 1) {
		pr_err("Cache object %lu xattr length incorrect\n",
		       d_backing_inode(dentry)->i_ino);
		goto stale;
	}

	if (auxbuf->type != auxdata->type)
		goto stale;

	auxbuf->len = ret;

	/* consult the netfs */
	if (object->fscache.cookie->def->check_aux) {
		enum fscache_checkaux result;
		unsigned int dlen;

		dlen = auxbuf->len - 1;

		_debug("checkaux %s #%u",
		       object->fscache.cookie->def->name, dlen);

		result = fscache_check_aux(&object->fscache,
					   &auxbuf->data, dlen,
					   i_size_read(d_backing_inode(dentry)));

		switch (result) {
			/* entry okay as is */
		case FSCACHE_CHECKAUX_OKAY:
			goto okay;

			/* entry requires update */
		case FSCACHE_CHECKAUX_NEEDS_UPDATE:
			break;

			/* entry requires deletion */
		case FSCACHE_CHECKAUX_OBSOLETE:
			goto stale;

		default:
			BUG();
		}

		cache = container_of(object->fscache.cache,
				     struct cachefiles_cache, cache);

		/* update the current label */
		ret = mnt_want_write(cache->mnt);
		if (ret == 0) {
			ret = vfs_setxattr(dentry, cachefiles_xattr_cache,
					   &auxdata->type, auxdata->len,
					   XATTR_REPLACE);
			mnt_drop_write(cache->mnt);
		}
		if (ret < 0) {
			cachefiles_io_error_obj(object,
						"Can't update xattr on %lu"
						" (error %d)",
						d_backing_inode(dentry)->i_ino, -ret);
			goto error;
		}
	}

okay:
	ret = 0;

error:
	kfree(auxbuf);
	return ret;

stale:
	ret = -ESTALE;
	goto error;
}

/*
 * check the state xattr on a cache file
 * - return -ESTALE if the object should be deleted
 */
int cachefiles_check_object_xattr(struct cachefiles_object *object,
				  struct cachefiles_xattr *auxdata)
{
	int ret;
	struct dentry *dentry = object->dentry;

	_enter("%p,#%d", object, auxdata->len);

	ASSERT(dentry);
	ASSERT(d_backing_inode(dentry));

	if (data_new_version(object->fscache.cookie))
		ret = cachefiles_check_new_obj_xattr(object);
	else if (volume_new_version(object->fscache.cookie))
		ret = cachefiles_check_new_vol_xattr(object);
	else
		ret = cachefiles_check_old_object_xattr(object, auxdata);

	if (ret < 0) {
		if (ret == -ENOMEM || ret == -ESTALE)
			goto error;
		/* no attribute - power went off mid-cull? */
		if (ret == -ENODATA)
			goto stale;
		if (ret == -ERANGE)
			goto bad_type_length;

		cachefiles_io_error_obj(object,
					"Can't read xattr on %lu (err %d)",
					d_backing_inode(dentry)->i_ino, -ret);
		goto error;
	}
	ret = 0;
error:
	_leave(" = %d", ret);
	return ret;

bad_type_length:
	pr_err("Cache object %lu xattr length incorrect\n",
	       d_backing_inode(dentry)->i_ino);
	ret = -EIO;
	goto error;

stale:
	ret = -ESTALE;
	goto error;
}

/*
 * remove the object's xattr to mark it stale
 */
int cachefiles_remove_object_xattr(struct cachefiles_cache *cache,
				   struct dentry *dentry)
{
	int ret;

	ret = mnt_want_write(cache->mnt);
	if (ret == 0) {
		ret = vfs_removexattr(dentry, cachefiles_xattr_cache);
		mnt_drop_write(cache->mnt);
	}
	if (ret < 0) {
		if (ret == -ENOENT || ret == -ENODATA)
			ret = 0;
		else if (ret != -ENOMEM)
			cachefiles_io_error(cache,
					    "Can't remove xattr from %lu"
					    " (error %d)",
					    d_backing_inode(dentry)->i_ino, -ret);
	}

	_leave(" = %d", ret);
	return ret;
}

static int cachefiles_set_new_vol_xattr(struct cachefiles_object *object)
{
	unsigned int len = sizeof(struct cachefiles_vol_xattr);
	struct dentry *dentry = object->dentry;

	return vfs_setxattr(dentry, cachefiles_xattr_cache, &new_vol_xattr,
			    len, XATTR_CREATE);
}

static int cachefiles_check_new_vol_xattr(struct cachefiles_object *object)
{
	int ret;
	struct cachefiles_vol_xattr buf;
	unsigned int len = sizeof(struct cachefiles_vol_xattr);
	struct dentry *dentry = object->dentry;

	ret = vfs_getxattr(dentry, cachefiles_xattr_cache, &buf, len);
	if (ret < 0)
		return ret;

	if (ret != len || memcmp(&buf, &new_vol_xattr, len) != 0)
		ret = -ESTALE;

	return ret > 0 ? 0 : ret;
}

static int cachefiles_set_new_obj_xattr(struct cachefiles_object *object)
{
	unsigned int len = sizeof(struct cachefiles_obj_xattr);
	struct dentry *dentry = object->dentry;
	struct cachefiles_obj_xattr buf = {
		.object_size = cpu_to_be64(object->fscache.store_limit_l),
		.type	     = CACHEFILES_COOKIE_TYPE_DATA,
		.content     = CACHEFILES_CONTENT_NO_DATA,
	};

	return vfs_setxattr(dentry, cachefiles_xattr_cache, &buf, len,
			    XATTR_CREATE);
}

static int cachefiles_check_new_obj_xattr(struct cachefiles_object *object)
{
	int ret;
	struct cachefiles_obj_xattr buf;
	unsigned int len = sizeof(struct cachefiles_obj_xattr);
	struct dentry *dentry = object->dentry;

	ret = vfs_getxattr(dentry, cachefiles_xattr_cache, &buf, len);
	if (ret < 0)
		return ret;

	if (ret != len ||
	    buf.type != CACHEFILES_COOKIE_TYPE_DATA ||
	    buf.content != CACHEFILES_CONTENT_NO_DATA ||
	    buf.object_size != cpu_to_be64(object->fscache.store_limit_l))
		ret = -ESTALE;

	return ret > 0 ? 0 : ret;
}
