// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */

#include "internal.h"

#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/completion.h>

#include <trace/events/mfs.h>

static struct mfs_file_info *mfs_file_info_alloc(struct file *lower, struct file *cache)
{
	struct mfs_file_info  *info = kzalloc(sizeof(struct mfs_file_info), GFP_KERNEL);

	if (unlikely(!info))
		return NULL;

	info->lower = lower;
	info->cache = cache;
	return info;
}

static void mfs_file_info_free(struct mfs_file_info *info)
{
	fput(info->cache);
	fput(info->lower);
	kfree(info);
}

static int mfs_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file_dentry(file);
	struct mfs_sb_info *sbi = MFS_SB(inode->i_sb);
	struct path lpath, cpath;
	struct file *lfile, *cfile;
	int flags = file->f_flags | MFS_OPEN_FLAGS;
	struct mfs_file_info *file_info;
	int err = 0;

	trace_mfs_open(inode, file);
	mfs_get_path(dentry, &lpath, &cpath);
	lfile = dentry_open(&lpath, flags, current_cred());
	if (IS_ERR(lfile)) {
		err = PTR_ERR(lfile);
		goto put_path;
	}

	cfile = dentry_open(&cpath, flags, current_cred());
	if (IS_ERR(cfile)) {
		err = PTR_ERR(cfile);
		goto lfput;
	}

	if (support_event(sbi))
		/* close the default readahead */
		cfile->f_mode |= FMODE_RANDOM;
	file_info = mfs_file_info_alloc(lfile, cfile);
	if (!file_info) {
		err = -ENOMEM;
		goto cfput;
	}

	file->private_data = file_info;
	goto put_path;
cfput:
	fput(cfile);
lfput:
	fput(lfile);
put_path:
	mfs_put_path(&lpath, &cpath);
	return err;
}

static int mfs_release(struct inode *inode, struct file *file)
{
	struct mfs_cache_object *object = inode->i_private;
	struct mfs_sb_info *sbi;

	if (!object)
		goto out;
	sbi = MFS_SB(object->mfs_inode->i_sb);
	if (!support_event(sbi) || !allow_ev_type(sbi, MFS_OP_CLOSE))
		goto out;
	if (!cache_is_ready(sbi))
		goto out;
	/* post close event to user-space daemon for closing fd handle */
	mfs_post_event_close(object);
out:
	trace_mfs_release(inode, file);
	mfs_file_info_free(file->private_data);
	return 0;
}

static loff_t mfs_llseek(struct file *file, loff_t offset, int whence)
{
	struct mfs_file_info *file_info = file->private_data;
	struct inode *inode = file_inode(file);
	struct file *lfile, *cfile;
	loff_t ret;

	if (offset == 0) {
		if (whence == SEEK_CUR)
			return file->f_pos;

		if (whence == SEEK_SET)
			return vfs_setpos(file, 0, 0);
	}

	lfile = file_info->lower;
	cfile = file_info->cache;

	mfs_inode_lock(inode);
	lfile->f_pos = file->f_pos;
	ret = vfs_llseek(lfile, offset, whence);
	if (ret < 0)
		goto out;

	cfile->f_pos = file->f_pos;
	ret = vfs_llseek(cfile, offset, whence);
	if (ret < 0)
		goto out;

	file->f_pos = lfile->f_pos;
out:
	mfs_inode_unlock(inode);
	return ret;
}

static int mfs_flush(struct file *file, fl_owner_t id)
{
	struct mfs_file_info *file_info = file->private_data;
	struct file *cfile;
	int err = 0;

	cfile = file_info->cache;
	if (cfile->f_op->flush)
		err = cfile->f_op->flush(cfile, id);

	return err;
}

static int mfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct file *lfile;
	struct mfs_file_info *file_info = file->private_data;

	lfile = file_info->lower;
	return iterate_dir(lfile, ctx);
}

enum range_status {
	RANGE_DATA,
	RANGE_HOLE,
	RANGE_INVAL,
};

/* Continuous range with same status */
struct range_t {
	struct file *file;
	loff_t off;
	size_t max;
	size_t len;
	int status;
};

typedef int (*range_check) (struct range_t *r);

struct range_ctx {
	bool sync;  /* handle the miss case in sync/async way */
	int op;
	loff_t off;
	size_t len;
	struct file *file;
	struct mfs_cache_object *object;
	range_check checker; /* check method for range */
};

static int range_check_disk(struct range_t *r)
{
	loff_t off, to, start = r->off, end = r->off + r->max;
	struct file *file = r->file;
	int err = 0;

	off  = vfs_llseek(file, start, SEEK_DATA);
	if (off < 0) {
		if (off == (loff_t)-ENXIO) {
			r->len = end - start;
			r->status = RANGE_HOLE;
			goto out;
		}
		err = (int)off;
		goto out;
	}
	if (off >= end) {
		r->len = end - start;
		r->status = RANGE_HOLE;
		goto out;
	}
	if (off > start) {
		r->len = end - off;
		r->status = RANGE_HOLE;
		goto out;
	}
	to = vfs_llseek(file, start, SEEK_HOLE);
	if (to < 0) {
		err = (int)to;
		goto out;
	}
	if (to < end) {
		r->len = to - start;
		r->status = RANGE_DATA;
		goto out;
	}
	r->len = end - start;
	r->status = RANGE_DATA;
out:
	return err;
}

static int range_check_mem(struct range_t *r)
{
	struct inode *inode = file_inode(r->file);
	struct address_space *mapping = inode->i_mapping;
	loff_t cur_off = r->off, end = r->off + r->max;
	struct folio *folio;

	/* check from the first folio */
	folio = filemap_get_folio(mapping, cur_off >> PAGE_SHIFT);
	if (IS_ERR(folio)) {
		r->status = RANGE_HOLE;
		cur_off += PAGE_SIZE;
	} else {
		r->status = RANGE_DATA;
		cur_off += folio_size(folio);
		folio_put(folio);
	}

	while (cur_off < end) {
		folio = filemap_get_folio(mapping, cur_off >> PAGE_SHIFT);
		if (IS_ERR(folio)) {
			if (r->status == RANGE_DATA)
				break;
			/* continuous hole */
			cur_off += PAGE_SIZE;
			continue;
		}
		if (r->status == RANGE_HOLE) {
			folio_put(folio);
			break;
		}
		cur_off += folio_size(folio);
		folio_put(folio);
	}

	r->len = cur_off - r->off;
	return 0;
}

static int mfs_check_range(struct range_ctx *ctx)
{
	struct mfs_sb_info *sbi = MFS_SB(ctx->object->mfs_inode->i_sb);
	loff_t start = ctx->off, end = ctx->off + ctx->len;
	struct file *file = ctx->file;
	struct range_t r = { .file = file };
	size_t len = ctx->len;
	struct mfs_syncer syncer;
	int err = 0, err2 = 0;

	if (!support_event(sbi) || !allow_ev_type(sbi, ctx->op))
		return 0;
	if (!cache_is_ready(sbi))
		return ctx->sync ? -EIO : 0;
	if (!ctx->len)
		return 0;

	atomic_set(&syncer.notback, 1);
	init_completion(&syncer.done);
	INIT_LIST_HEAD(&syncer.head);
	spin_lock_init(&syncer.list_lock);
	atomic_set(&syncer.res, 0);
	while (start < end) {
		r.off = round_down(start, PAGE_SIZE);
		r.max = len + (start - r.off);
		r.len = 0;
		r.status = RANGE_INVAL;
		err = ctx->checker(&r);
		if (err)
			goto err;
		switch (r.status) {
		case RANGE_DATA:
			start += r.len;
			len -= r.len;
			break;
		case RANGE_HOLE:
			start += r.len;
			len -= r.len;
			if (ctx->sync)
				mfs_post_event_read(ctx->object, r.off, r.len, &syncer, ctx->op);
			else
				mfs_post_event_read(ctx->object, r.off, r.len, NULL, ctx->op);
			break;
		default:
			pr_warn("invalid range status:%d\n", r.status);
			WARN_ON_ONCE(1);
			err = -EINVAL;
			goto err;
		}
	}

err:
	if (atomic_dec_return(&syncer.notback) > 0) {
		err2 = wait_for_completion_interruptible(&syncer.done);
		if (err2)
			mfs_cancel_syncer_events(ctx->object, &syncer);
		else
			err = atomic_read(&syncer.res);
	}
	return err ?: err2;
}

static ssize_t mfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *cfile, *file = iocb->ki_filp;
	struct mfs_file_info *fi = file->private_data;
	size_t isize = i_size_read(file_inode(file));
	struct range_ctx ctx;
	ssize_t rsize;
	int err;

	if (!iov_iter_count(to))
		return 0;

	cfile = fi->cache;
	if (!cfile->f_op->read_iter)
		return -EINVAL;

	(void)get_file(cfile);
	ctx.file = cfile;
	ctx.object = file_inode(file)->i_private;
	ctx.off = iocb->ki_pos;
	ctx.op = MFS_OP_READ;
	ctx.len = min_t(size_t, isize - ctx.off, iov_iter_count(to));
	ctx.sync = false;
	ctx.checker = range_check_mem;
	if (need_sync_event(file_inode(file)->i_sb)) {
		ctx.sync = true;
		ctx.checker = range_check_disk;
	}
	err = mfs_check_range(&ctx);
	if (err) {
		fput(cfile);
		return err;
	}

	iocb->ki_filp = cfile;
	rsize = cfile->f_op->read_iter(iocb, to);
	iocb->ki_filp = file;
	fput(cfile);
	return rsize;
}

static int mfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mfs_file_info *fi = file->private_data;
	struct file *cfile = fi->cache;
	int err;

	if (!cfile->f_op->mmap)
		return -ENODEV;

	(void)get_file(cfile);
	vma->vm_file = cfile;
	err = call_mmap(vma->vm_file, vma);
	vma->vm_file = file;
	fput(cfile);
	if (err)
		return err;

	fi->cache_vm_ops = vma->vm_ops;
	vma->vm_ops = &mfs_file_vm_ops;

	return 0;
}

static vm_fault_t mfs_filemap_fault(struct vm_fault *vmf)
{
	struct file *cfile, *file = vmf->vma->vm_file;
	struct mfs_file_info *fi = file->private_data;
	size_t isize = i_size_read(file_inode(file));
	const struct vm_operations_struct *cvm_ops;
	struct vm_area_struct cvma, *vma, **vma_;
	struct range_ctx ctx;
	vm_fault_t ret;
	int err;

	vma = vmf->vma;
	memcpy(&cvma, vma, sizeof(struct vm_area_struct));
	cfile = fi->cache;
	cvm_ops = fi->cache_vm_ops;
	cvma.vm_file = cfile;

	if (unlikely(!cvm_ops->fault))
		return VM_FAULT_SIGBUS;
	if ((vmf->pgoff << PAGE_SHIFT) >= isize)
		return VM_FAULT_SIGBUS;

	(void)get_file(cfile);
	ctx.file = cfile;
	ctx.object = file_inode(file)->i_private;
	ctx.off = vmf->pgoff << PAGE_SHIFT;
	ctx.len = min_t(size_t, isize - ctx.off, PAGE_SIZE);
	ctx.op = MFS_OP_FAULT;
	ctx.sync = false;
	ctx.checker = range_check_mem;
	if (need_sync_event(file_inode(file)->i_sb)) {
		ctx.sync = true;
		ctx.checker = range_check_disk;
	}
	err = mfs_check_range(&ctx);
	if (err) {
		fput(cfile);
		return VM_FAULT_SIGBUS;
	}

	/*
	 * Dealing fault in mfs will call cachefile's fault eventually,
	 * hence we will change vmf->vma->vm_file to cachefile.
	 * When faulting concurrently, changing vmf->vma->vm_file is
	 * visible to other threads. Hence we use cvma to narrow the
	 * visibility. vmf->vma is const, so we use **vma_ to change.
	 */
	vma_ = (struct vm_area_struct **)&vmf->vma;
	*vma_ = &cvma;
	ret = cvm_ops->fault(vmf);
	*vma_ = vma;
	fput(cfile);
	return ret;
}

static vm_fault_t mfs_filemap_map_pages(struct vm_fault *vmf,
					pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	struct file *cfile, *file = vmf->vma->vm_file;
	struct mfs_file_info *fi = file->private_data;
	const struct vm_operations_struct *cvm_ops;
	struct vm_area_struct cvma, *vma, **vma_;
	vm_fault_t ret;

	vma = vmf->vma;
	memcpy(&cvma, vma, sizeof(struct vm_area_struct));
	cfile = fi->cache;
	cvm_ops = fi->cache_vm_ops;
	cvma.vm_file = cfile;

	if (unlikely(!cvm_ops->map_pages))
		return 0;

	(void)get_file(cfile);
	vma_ = (struct vm_area_struct **)&vmf->vma;
	*vma_ = &cvma;
	ret = cvm_ops->map_pages(vmf, start_pgoff, end_pgoff);
	*vma_ = vma;
	fput(cfile);

	return ret;
}

static int mfs_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	struct inode *inode = file_inode(file);
	struct mfs_sb_info *sbi = MFS_SB(inode->i_sb);
	struct mfs_file_info *fi;
	struct file *cfile;
	int ret;

	/* avoid trigger readahead in event mode */
	if (support_event(sbi))
		return generic_fadvise(file, offset, len, advice);

	fi = file->private_data;
	cfile = fi->cache;
	(void)get_file(cfile);

	ret = vfs_fadvise(cfile, offset, len, advice);
	fput(cfile);

	return ret;
}

const struct file_operations mfs_dir_fops = {
	.open		= mfs_open,
	.iterate_shared	= mfs_readdir,
	.release	= mfs_release,
};

const struct file_operations mfs_file_fops = {
	.open		= mfs_open,
	.release	= mfs_release,
	.llseek		= mfs_llseek,
	.read_iter	= mfs_read_iter,
	.flush		= mfs_flush,
	.mmap		= mfs_file_mmap,
	.fadvise	= mfs_fadvise,
};

const struct vm_operations_struct mfs_file_vm_ops = {
	.fault		= mfs_filemap_fault,
	.map_pages	= mfs_filemap_map_pages,
};

const struct address_space_operations mfs_aops = {
	.direct_IO	= noop_direct_IO,
};
