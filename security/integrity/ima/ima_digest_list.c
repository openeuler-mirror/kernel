// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_digest_list.c
 *      Functions to manage digest lists.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/xattr.h>

#include "ima.h"
#include "ima_digest_list.h"

struct ima_h_table ima_digests_htable = {
	.len = ATOMIC_LONG_INIT(0),
	.queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT
};

/*************************
 * Get/add/del functions *
 *************************/
struct ima_digest *ima_lookup_digest(u8 *digest, enum hash_algo algo,
				     enum compact_types type)
{
	struct ima_digest *d = NULL;
	int digest_len = hash_digest_size[algo];
	unsigned int key = ima_hash_key(digest);

	rcu_read_lock();
	hlist_for_each_entry_rcu(d, &ima_digests_htable.queue[key], hnext)
		if (d->algo == algo && d->type == type &&
		    !memcmp(d->digest, digest, digest_len))
			break;

	rcu_read_unlock();
	return d;
}

static int ima_add_digest_data_entry(u8 *digest, enum hash_algo algo,
				     enum compact_types type, u16 modifiers)
{
	struct ima_digest *d;
	int digest_len = hash_digest_size[algo];
	unsigned int key = ima_hash_key(digest);

	d = ima_lookup_digest(digest, algo, type);
	if (d) {
		d->modifiers |= modifiers;
		if (d->count < (u16)(~((u16)0)))
			d->count++;
		return -EEXIST;
	}

	d = kmalloc(sizeof(*d) + digest_len, GFP_KERNEL);
	if (d == NULL)
		return -ENOMEM;

	d->algo = algo;
	d->type = type;
	d->modifiers = modifiers;
	d->count = 1;

	memcpy(d->digest, digest, digest_len);
	hlist_add_head_rcu(&d->hnext, &ima_digests_htable.queue[key]);
	atomic_long_inc(&ima_digests_htable.len);
	return 0;
}

static void ima_del_digest_data_entry(u8 *digest, enum hash_algo algo,
				     enum compact_types type)
{
	struct ima_digest *d;

	d = ima_lookup_digest(digest, algo, type);
	if (!d)
		return;

	if (--d->count > 0)
		return;

	hlist_del_rcu(&d->hnext);
	atomic_long_dec(&ima_digests_htable.len);
}

/***********************
 * Compact list parser *
 ***********************/
struct compact_list_hdr {
	u8 version;
	u8 _reserved;
	u16 type;
	u16 modifiers;
	u16 algo;
	u32 count;
	u32 datalen;
} __packed;

int ima_parse_compact_list(loff_t size, void *buf, int op)
{
	u8 *digest;
	void *bufp = buf, *bufendp = buf + size;
	struct compact_list_hdr *hdr;
	size_t digest_len;
	int ret = 0, i;

	if (!(ima_digest_list_actions & ima_policy_flag))
		return -EACCES;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}

		hdr = bufp;

		if (hdr->version != 1) {
			pr_err("compact list, unsupported version\n");
			return -EINVAL;
		}

		if (ima_canonical_fmt) {
			hdr->type = le16_to_cpu(hdr->type);
			hdr->modifiers = le16_to_cpu(hdr->modifiers);
			hdr->algo = le16_to_cpu(hdr->algo);
			hdr->count = le32_to_cpu(hdr->count);
			hdr->datalen = le32_to_cpu(hdr->datalen);
		}

		if (hdr->algo >= HASH_ALGO__LAST)
			return -EINVAL;

		digest_len = hash_digest_size[hdr->algo];

		if (hdr->type >= COMPACT__LAST) {
			pr_err("compact list, invalid type %d\n", hdr->type);
			return -EINVAL;
		}

		bufp += sizeof(*hdr);

		for (i = 0; i < hdr->count; i++) {
			if (bufp + digest_len > bufendp) {
				pr_err("compact list, invalid data\n");
				return -EINVAL;
			}

			digest = bufp;
			bufp += digest_len;

			if (op == DIGEST_LIST_OP_ADD)
				ret = ima_add_digest_data_entry(digest,
					hdr->algo, hdr->type, hdr->modifiers);
			else if (op == DIGEST_LIST_OP_DEL)
				ima_del_digest_data_entry(digest, hdr->algo,
					hdr->type);
			if (ret < 0 && ret != -EEXIST)
				return ret;
		}

		if (i != hdr->count ||
		    bufp != (void *)hdr + sizeof(*hdr) + hdr->datalen) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}
	}

	return bufp - buf;
}

/***************************
 * Digest list usage check *
 ***************************/
void ima_check_measured_appraised(struct file *file)
{
	struct integrity_iint_cache *iint;

	if (!ima_digest_list_actions)
		return;

	iint = integrity_iint_find(file_inode(file));
	if (!iint) {
		pr_err("%s not processed, disabling digest lists lookup\n",
		       file_dentry(file)->d_name.name);
		ima_digest_list_actions = 0;
		return;
	}

	mutex_lock(&iint->mutex);
	if ((ima_digest_list_actions & IMA_MEASURE) &&
	    !(iint->flags & IMA_MEASURED)) {
		pr_err("%s not measured, disabling digest lists lookup "
		       "for measurement\n", file_dentry(file)->d_name.name);
		ima_digest_list_actions &= ~IMA_MEASURE;
	}

	if ((ima_digest_list_actions & IMA_APPRAISE) &&
	    (!(iint->flags & IMA_APPRAISED) ||
	    !test_bit(IMA_DIGSIG, &iint->atomic_flags))) {
		pr_err("%s not appraised, disabling digest lists lookup "
		       "for appraisal\n", file_dentry(file)->d_name.name);
		ima_digest_list_actions &= ~IMA_APPRAISE;
	}

	mutex_unlock(&iint->mutex);
}

struct ima_digest *ima_digest_allow(struct ima_digest *digest, int action)
{
	if (!(ima_digest_list_actions & action))
		return NULL;

	return digest;
}

/**************************************
 * Digest list loading at kernel init *
 **************************************/
struct readdir_callback {
	struct dir_context ctx;
	struct path *path;
};

static int __init load_digest_list(struct dir_context *__ctx, const char *name,
				   int namelen, loff_t offset, u64 ino,
				   unsigned int d_type)
{
	struct readdir_callback *ctx = container_of(__ctx, typeof(*ctx), ctx);
	struct path *dir = ctx->path;
	struct dentry *dentry;
	struct file *file;
	u8 *xattr_value = NULL;
	void *datap = NULL;
	loff_t size;
	int ret;

	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return 0;

	dentry = lookup_one_len(name, dir->dentry, strlen(name));
	if (IS_ERR(dentry))
		return 0;

	size = vfs_getxattr(&nop_mnt_idmap, dentry, XATTR_NAME_EVM, NULL, 0);
	if (size < 0) {
		size = vfs_getxattr_alloc(&nop_mnt_idmap, dentry, XATTR_NAME_IMA,
					  (char **)&xattr_value, 0, GFP_NOFS);
		if (size < 0 || xattr_value[0] != EVM_IMA_XATTR_DIGSIG)
			goto out;
	}

	file = file_open_root(dir, name, O_RDONLY, 0);
	if (IS_ERR(file)) {
		pr_err("Unable to open file: %s (%ld)", name, PTR_ERR(file));
		goto out;
	}

	ret = kernel_read_file(file, 0, &datap, INT_MAX, NULL,
			       READING_DIGEST_LIST);
	if (ret < 0) {
		pr_err("Unable to read file: %s (%d)", name, ret);
		goto out_fput;
	}

	size = ret;

	ima_check_measured_appraised(file);

	ret = ima_parse_compact_list(size, datap, DIGEST_LIST_OP_ADD);
	if (ret < 0)
		pr_err("Unable to parse file: %s (%d)", name, ret);

	vfree(datap);
out_fput:
	fput(file);
out:
	kfree(xattr_value);
	return 0;
}

void __init ima_load_digest_lists(void)
{
	struct path path;
	struct file *file;
	int ret;
	struct readdir_callback buf = {
		.ctx.actor = load_digest_list,
	};

	if (!(ima_digest_list_actions & ima_policy_flag))
		return;

	ret = kern_path(CONFIG_IMA_DIGEST_LISTS_DIR, 0, &path);
	if (ret)
		return;

	file = dentry_open(&path, O_RDONLY, current_cred());
	if (IS_ERR(file))
		goto out;

	buf.path = &path;
	iterate_dir(file, &buf.ctx);
	fput(file);
out:
	path_put(&path);
}
