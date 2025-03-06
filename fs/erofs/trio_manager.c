// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (C) 2025 Huawei Inc.
 */

#include <linux/sysfs.h>
#include <linux/kstrtox.h>
#include <linux/hashtable.h>
#include <linux/crc32.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/pfn_t.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/string.h>

#include "internal.h"

#define PATH_IO_DELIMIT		"|"
#define PATH_PATH_DELIMIT	"@"
#define IO_IO_DELIMIT		"+"
#define VAR_DELIMIT		","

struct trace_object {
	uint64_t		ino;  /* inode number of this trace object */
	struct list_head	head;   /* record the all trace io */
	struct hlist_node	node;   /* link into hashtable */
};

struct trace_io {
	struct list_head	link;    /* link of this io */
	uint64_t		soff;    /* offset in source file, trace.data */
	uint64_t		len;     /* length of this io */
	uint64_t		doff;    /* offset in destination */
};

static struct kmem_cache *trio_iop;
static struct kmem_cache *trio_objp;

static struct trace_object *alloc_trace_object(uint64_t ino)
{
	struct trace_object *obj = kmem_cache_zalloc(trio_objp, GFP_KERNEL);

	if (!obj)
		return NULL;

	obj->ino = ino;
	INIT_LIST_HEAD(&obj->head);

	return obj;
}

static void free_trace_object(struct trace_object *obj)
{
	struct list_head *pos, *n;
	struct trace_io *io;

	if (IS_ERR_OR_NULL(obj))
		return;

	list_for_each_safe(pos, n, &obj->head) {
		io = list_entry(pos, struct  trace_io, link);
		list_del(&io->link);
		kmem_cache_free(trio_iop, io);
	}
	kmem_cache_free(trio_objp, obj);
}

static void hash_add_trace_object(struct hlist_head *trace_ht,
			struct trace_object *obj)
{
	hlist_add_head(&obj->node, &trace_ht[hash_min(obj->ino, TRIO_HT_BITS)]);
}

static const struct hlist_head *_find_by_hash(struct hlist_head *ht, uint64_t ino)
{
	struct hlist_head *h;

	h = &ht[hash_min(ino, TRIO_HT_BITS)];
	if (hlist_empty(h))
		return NULL;

	return h;
}

static struct trace_object *find_trace_object(struct inode *inode)
{
	struct erofs_sb_info *sbi = EROFS_SB(inode->i_sb);
	unsigned long ino  = inode->i_ino;
	const struct hlist_head *handlers;
	struct trace_object *obj;

	handlers = _find_by_hash(sbi->meta_ht, ino);
	if (!handlers)
		return NULL;

	hlist_for_each_entry(obj, handlers, node)
		if (obj->ino == ino)
			return obj;

	return NULL;
}

struct trace_io *get_io_from_object(struct trace_object *obj,
			loff_t off, size_t len, size_t *hit_len)
{
	struct list_head *tmp;
	struct trace_io *io = NULL;
	size_t can_read = 0;

	list_for_each(tmp, &obj->head) {
		io = list_entry(tmp, struct trace_io, link);
		/* next bigger one */
		if (io->doff + io->len <= off)
			continue;

		/* last unmatch one */
		if (off + len <= io->doff)
			break;

		/* io include the read range */
		if (io->doff <= off) {
			can_read = min_t(size_t, len, io->doff + io->len - off);
			break;
		}
	}

	*hit_len = can_read;
	return io;
}

static void *_read_data_inner(struct super_block *sb, const char *path,
				   uint64_t *rsize)
{
	struct file *filp = filp_open(path, O_RDONLY, 0644);
	loff_t size, off, pos = 0;
	ssize_t ret = 0;
	void *data;
	char *buf;

	if (IS_ERR(filp)) {
		erofs_err(sb, "open target file:%s failed", path);
		return NULL;
	}

	size = i_size_read(filp->f_inode);
	data = vmalloc(size + 1);
	if (!data) {
		erofs_err(sb, "alloc buffer for size:%lld failed", size);
		goto close_data;
	}

	off = 0;
	while ((ret = kernel_read(filp, data + pos, size - pos, &off)) > 0) {
		pos += ret;
		if (pos >= size)
			break;
	}

	if (ret < 0) {
		erofs_err(sb, "read failed size:%lld, read:%lld, ret:%zd",
			  size, pos, ret);
		vfree(data);
		data = NULL;
		goto close_data;
	}

	if (pos != size) {
		erofs_err(sb, "read incomplete size:%lld, read:%lld, ret:%zd",
			  size, pos, ret);
		vfree(data);
		data = NULL;
		goto close_data;
	}

	buf = (char *)data;
	buf[size] = '\0';
	*rsize = size;

close_data:
	filp_close(filp, NULL);
	return data;
}

void *erofs_get_trio_object(struct inode *inode)
{
	struct trace_object *obj;

	obj = find_trace_object(inode);
	return obj;
}

ssize_t erofs_read_from_trio(struct address_space *mapping,
			loff_t pos, size_t len)
{
	struct inode *inode = mapping->host;
	struct erofs_sb_info *sbi = EROFS_SB(inode->i_sb);
	struct trace_object *obj;
	struct trace_io *target_io;
	struct iov_iter iter;
	loff_t new_foff;
	size_t hit_len;
	ssize_t ret;

	if (!inode->i_private)
		return 0;

	obj = (struct trace_object *)inode->i_private;
	target_io = get_io_from_object(obj, pos, len, &hit_len);
	if (!target_io || !hit_len)
		return 0;

	iov_iter_xarray(&iter, ITER_DEST, &mapping->i_pages, pos, hit_len);
	new_foff = (pos - target_io->doff) + target_io->soff;
	ret = copy_to_iter(sbi->buffer + new_foff, hit_len, &iter);
	if (ret != hit_len)
		return -EFAULT;
	return ret;
}

int erofs_register_trio(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	char *item, *path, *ios, *io, *s_toff, *s_len, *s_foff;
	uint64_t ino, doff, soff, len, dsize, msize;
	char *meta_buffer, *tmp;
	struct trace_object *obj;
	struct trace_io *io_item;
	struct list_head *pos, *n;
	LIST_HEAD(head);
	int ret = -EINVAL;

	if (!sbi->trio_meta && !sbi->trio_data)
		return 0;

	if (!sbi->trio_meta || !sbi->trio_data) {
		erofs_err(sb, "trio_meta and trio_data must be set together");
		return ret;
	}

	sbi->buffer = _read_data_inner(sb, sbi->trio_data, &dsize);
	if (!sbi->buffer)
		return ret;

	meta_buffer = _read_data_inner(sb, sbi->trio_meta, &msize);
	if (!meta_buffer)
		goto free_obj;

	tmp = meta_buffer;
	while ((item = strsep(&tmp, PATH_PATH_DELIMIT)) != NULL) {
		path = strsep(&item, PATH_IO_DELIMIT);
		ios = item;
		ret = kstrtou64(path, 10, &ino);
		if (ret < 0) {
			erofs_err(sb, "parse inode failed ino:%s failed", path);
			goto free_obj;
		}

		while ((io = strsep(&ios, IO_IO_DELIMIT)) != NULL) {
			s_toff = strsep(&io, VAR_DELIMIT);
			s_len = strsep(&io, VAR_DELIMIT);
			s_foff = strsep(&io, VAR_DELIMIT);

			ret = kstrtou64(s_toff, 10, &doff);
			if (ret < 0) {
				erofs_err(sb, "set target_offset failed path:%s,io(%s,%s,%s)",
				       path, s_toff, s_len, s_foff);
				goto free_obj;
			}

			ret = kstrtou64(s_len, 10, &len);
			if (ret < 0) {
				erofs_err(sb, "set target_length failed path:%s,io(%s,%s,%s)",
				       path, s_toff, s_len, s_foff);
				goto free_obj;
			}

			ret = kstrtou64(s_foff, 10, &soff);
			if (ret < 0) {
				erofs_err(sb, "set source_offset failed path:%s,io(%s,%s,%s)",
				       path, s_toff, s_len, s_foff);
				goto free_obj;
			}
			DBG_BUGON(soff + round_up(len, PAGE_SIZE) > dsize);

			io_item = kmem_cache_zalloc(trio_iop, GFP_KERNEL);
			if (!io_item) {
				erofs_err(sb, "alloc for trace io failed");
				ret = -ENOMEM;
				goto free_obj;
			}
			INIT_LIST_HEAD(&io_item->link);
			io_item->len = len;
			io_item->doff = doff;
			io_item->soff = soff;

			list_add_tail(&io_item->link, &head);
		}

		obj = alloc_trace_object(ino);
		if (obj == NULL) {
			erofs_err(sb, "alloc trace object failed");
			ret = -ENOMEM;
			goto free_obj;
		}

		list_splice_init(&head, &obj->head);
		hash_add_trace_object(sbi->meta_ht, obj);
	}
	ret = 0;

free_meta:
	vfree(meta_buffer);
	return ret;
free_obj:
	list_for_each_safe(pos, n, &head) {
		io_item = list_entry(pos, struct trace_io, link);
		list_del(&io_item->link);
		kmem_cache_free(trio_iop, io_item);
	}
	vfree(sbi->buffer);
	sbi->buffer = NULL;
	goto free_meta;
}

void erofs_unregister_trio(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct hlist_node *tmp;
	struct trace_object *obj;
	int i;

	hash_for_each_safe(sbi->meta_ht, i, tmp, obj, node) {
		hlist_del(&obj->node);
		free_trace_object(obj);
	}
	vfree(sbi->buffer);
	sbi->buffer = NULL;
}

int trio_manager_init(void)
{
	trio_objp = kmem_cache_create("trio_obj_pool",
				     sizeof(struct trace_object), 0, 0, NULL);
	if (!trio_objp)
		return -ENOMEM;

	trio_iop = kmem_cache_create("trio_io_pool", sizeof(struct trace_io),
				     0, 0, NULL);
	if (!trio_iop) {
		kmem_cache_destroy(trio_objp);
		return -ENOMEM;
	}

	return 0;
}

void trio_manager_exit(void)
{
	kmem_cache_destroy(trio_iop);
	kmem_cache_destroy(trio_objp);
}
