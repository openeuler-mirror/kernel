// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "euler.h"
#include "dht.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif)&S_IFMT) >> 12)

static int dir_emitter(void *privdata, const struct nv_dict_entry *de)
{
	struct dir_scan_data *data = (struct dir_scan_data *)privdata;
	struct eufs_inode *pi;
	int namelen;
	const char *name;
	char *page;
	int r;

	pi = s2p(data->sb, de->inode);
	pi = EUFS_FRESH_PI(pi);
	name = de->name;
	namelen = HASHLEN_LEN(de->hv);

	eufs_dbg("!de=%px, de->pi=%px, de->nextname=%llx, namelen=%d\n", de,
		  pi, de->nextname, namelen);
	if (likely(namelen <= FIRST_LEN)) {
		eufs_dbg("%s found name: %*s len: %d inode: %px\n",
			  __func__, namelen, name, namelen, pi);

		r = dir_emit(data->ctx, name, namelen, le64_to_cpu(de->inode),
			     IF2DT(eufs_iread_mode(pi)));
		if (!r)
			return -EINVAL;
		return 0;
	}
	if (eufs_ptr_fast_check_b(de->nextname)) {
		eufs_info("!de=%px, de->pi=%px, de->nextname=%llx, namelen=%d\n",
			  de, pi, de->nextname, namelen);
		BUG();
	}
	page = eufs_alloc_name_copy(data->sb, name, namelen,
				     s2p(data->sb, de->nextname));
	eufs_dbg("%s found name: %*s len: %d inode: %px\n", __func__, namelen,
		  page, namelen, pi);

	r = dir_emit(data->ctx, page, namelen, le64_to_cpu(de->inode),
		     IF2DT(eufs_iread_mode(pi)));
	eufs_free_page(page);
	if (!r)
		return -EINVAL;
	return 0;
}

static int eufs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct eufs_inode *pi = EUFS_PI(inode);
	struct dir_scan_data data = { .sb = inode->i_sb, .ctx = ctx };

	if (ctx->pos == EUFS_DIR_EODIR)
		return 0;
	if (ctx->pos == 0) {
		if (!dir_emit(ctx, ".", 1, (u64)eufs_pi2ino(inode->i_sb, pi),
			      IF2DT(inode->i_mode))) {
			return -EINVAL;
		}
		ctx->pos = EUFS_DIR_DOT;
	}

	if (ctx->pos == EUFS_DIR_DOT) {
		struct eufs_inode *dotdot = o2p(
			inode->i_sb, eufs_iread_dotdot(EUFS_FRESH_PI(pi)));

		if (!dir_emit(ctx, "..", 2,
			      (u64)eufs_pi2ino(inode->i_sb, dotdot),
			      IF2DT(eufs_iread_mode(dotdot))))
			return -EINVAL;
		ctx->pos = EUFS_DIR_DOTDOT;
	}

	if (!inode->i_size) {
		ctx->pos = EUFS_DIR_EODIR;
		return 0;
	}
	eufs_dbg("In Readdir! ctx->pos=%llx  inode=%px, pi=%px\n", ctx->pos,
		  inode, pi);

	nv_dict_scan_via_ptr(inode, ctx->pos, dir_emitter, (void *)&data);

	eufs_dbg("Out Readdir! ctx->pos=%llx\n", ctx->pos);
	return 0;
}

static loff_t eufs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t retval;

	inode_lock(inode);
	switch (whence) {
	case SEEK_END:
		/* TODO */
		retval = -EINVAL;
		goto out;
	case SEEK_CUR:
		/* TODO */
		retval = -EINVAL;
		goto out;
	case SEEK_SET:
		break;
	}
	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}
	retval = offset;
out:
	inode_unlock(inode);
	return retval;
}

const struct file_operations eufs_dir_operations = {
	.llseek = eufs_dir_llseek,
	.read = generic_read_dir,
	.iterate = eufs_readdir,
	.fsync = eufs_fsync,
};
