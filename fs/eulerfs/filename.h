/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef EUFS_FILENAME_H
#define EUFS_FILENAME_H

#include "alloc_interface.h"

/* ========== filenames ========== */
static __always_inline void eufs_free_name(struct super_block *sb,
					    struct nv_dict_entry *de)
{
	size_t len = HASHLEN_LEN(de->hv);
	struct nv_name_ext *p;
	struct nv_name_ext *next;

	if (likely(len <= FIRST_LEN))
		return;
	p = s2p(sb, de->nextname);
	len -= FIRST_LEN;
	while (len > FOLLOW_LEN) {
		next = s2p(sb, p->nextname);
		nv_free(sb, p);
		len -= FOLLOW_LEN;
		p = next;
	}
	nv_free(sb, p);
}

/* precondition: ext != NULL */
/* Use with `eufs_free_page(page);` */
static __always_inline void *
eufs_alloc_name_copy(struct super_block *sb, const char *name, size_t namelen,
		      const struct nv_name_ext *ext)
{
	char *page;
	char *p;
	size_t len;

	NV_ASSERT(namelen > FIRST_LEN);
	NV_ASSERT(namelen <= EUFS_MAX_NAME_LEN);

	page = eufs_alloc_page();
	p = page;
	memcpy(p, name, FIRST_LEN);
	len = namelen - FIRST_LEN;
	p += FIRST_LEN;
	name = ext->name;
	while (len > FOLLOW_LEN) {
		memcpy(p, name, FOLLOW_LEN);
		ext = s2p(sb, ext->nextname);
		name = ext->name;
		p += FOLLOW_LEN;
		len -= FOLLOW_LEN;
	}
	memcpy(p, name, len);
	*(char *)(p + len) = 0;
	return page;
}
/* TODO: Handle allocation failure */
static __always_inline int copy_filename(struct super_block *sb,
					 struct nv_dict_entry *de, hashlen_t hv,
					 const char *name)
{
	void *ext_pages[6];
	int n_ext_pages;
	struct nv_name_ext *p;
	struct nv_name_ext *new_p;
	size_t len = HASHLEN_LEN(hv);

	BUILD_BUG_ON(FIRST_LEN + FOLLOW_LEN * 6 < EUFS_MAX_NAME_LEN);
	BUG_ON(len > EUFS_MAX_NAME_LEN);

	de->hv = hv;
	if (likely(len <= FIRST_LEN)) {
		memcpy(de->name, name, len);
		de->nextname = cpu_to_le64(EUFS_POISON_POINTER);
		return 0;
	}
	n_ext_pages = 0;
	memcpy(de->name, name, FIRST_LEN);
	p = eufs_malloc_name_ext(sb);
	de->nextname = p2s(sb, p);
	if (!p)
		goto NO_SPC;
	ext_pages[n_ext_pages++] = p;
	name += FIRST_LEN;
	len -= FIRST_LEN;

	while (len > FOLLOW_LEN) {
		memcpy(p->name, name, FOLLOW_LEN);
		name += FOLLOW_LEN;
		len -= FOLLOW_LEN;
		new_p = eufs_malloc_name_ext(sb);
		p->nextname = p2s(sb, new_p);
		p = new_p;
		if (!p)
			goto NO_SPC;
		ext_pages[n_ext_pages++] = p;
	}
	memcpy(p->name, name, len);
	p->nextname = cpu_to_le64(EUFS_POISON_POINTER);
	return 0;
NO_SPC:
	while (n_ext_pages)
		nv_free(sb, ext_pages[--n_ext_pages]);
	return -ENOSPC;
}

#endif /* EUFS_FILENAME_H */
