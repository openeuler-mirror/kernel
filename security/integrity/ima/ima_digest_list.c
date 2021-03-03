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
