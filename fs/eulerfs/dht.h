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

#ifndef EUFS_DHT_H
#define EUFS_DHT_H

#include <linux/atomic.h>
#include "filename.h"

#define DICT_OK (0)
#define DICT_ERR (1)

#define INDEX(h) (h & (NV_DICT_CAPACITY - 1))

#define CURSOR_IDX(csr) ((csr >> 32) & 0xffffffff)
#define CURSOR_CNT(csr) (csr & 0xffffffff)
#define CURSOR(idx, cnt) (((idx) << 32) | (cnt))

/* End of dir */
#define EUFS_DIR_EODIR (CURSOR(NV_DICT_CAPACITY, 2))
/* Offset of . in a dir */
#define EUFS_DIR_DOT (CURSOR(NV_DICT_CAPACITY, 0))
/* Offset of .. in a dir */
#define EUFS_DIR_DOTDOT (CURSOR(NV_DICT_CAPACITY, 1))

#define EUFS_DENTRY_FLAG_NOT_PERSIST 1
#define EUFS_DENTRY_FLAGS_MASK (~1ULL)

/* The total size of the hash table (buckets) is 8B * 512 = 4KB */

struct v_dict {
	struct nv_dict_entry *table[NV_DICT_CAPACITY];
} __aligned(PAGE_SIZE);

struct nv_dict_entry *nv_dict_add(struct inode *dir, u64 **nv_header, u64 h,
				  const char *key, struct eufs_inode *pi);

struct nv_dict_entry *nv_dict_find(struct inode *dir, hashlen_t h,
				   const char *key);

struct nv_dict_entry *nv_dict_delete(struct inode *dir,
				     struct nv_dict_entry **prevde,
				     u64 **nv_header, hashlen_t h,
				     const char *key);

void nv_dict_scan_via_ptr(struct inode *dir, u64 pos,
			  int (*fn)(void *privdata,
				    const struct nv_dict_entry *de),
			  void *privdata);

#define EUFS_PRINT_PI(pi, msg)                                                \
	eufs_info(                                                            \
		msg                                                            \
		" pi=%px, pi->i_mode=%x, pi->i_nlink=%x, "                     \
		"pi->root=0x%llx, pi->i_size=0x%llx, pi->i_dotdot=0x%llx\n",   \
		pi, pi ? eufs_iread_mode(pi) : 0,                             \
		pi ? eufs_iread_nlink(pi) : 0, pi ? eufs_iread_root(pi) : 0, \
		pi ? eufs_iread_size(pi) : 0,                                 \
		pi ? eufs_iread_dotdot(pi) : 0)

#define EUFS_PRINT_PI_INODE(msg, pi, inode)                                   \
	eufs_info(msg " pi=%px inode=%px; "                                   \
		       "pi->i_mode=0%o inode->i_mode=0%o; "                    \
		       "pi->i_nlink=0x%x inode=i_nlink=0x%x; "                 \
		       "pi->root=0x%llx inode->root=%px; "                     \
		       "pi->i_size=0x%llx inode->i_size=0x%llx; "              \
		       "pi->i_dotdot=0x%llx\n",                                \
		   pi, inode, pi ? eufs_iread_mode(pi) : 0,                   \
		   inode ? inode->i_mode : 0, pi ? eufs_iread_nlink(pi) : 0,  \
		   inode ? inode->i_nlink : 0, pi ? eufs_iread_root(pi) : 0,  \
		   inode ? EUFS_I(inode)->i_volatile_root : 0,                \
		   pi ? eufs_iread_size(pi) : 0, inode ? inode->i_size : 0,   \
		   pi ? pi->i_dotdot : 0)

#define _PRINT_DENTRY(de, msg)                                                 \
	{                                                                      \
		char *page;                                                    \
		if (HASHLEN_LEN(de->hv) > FIRST_LEN) {                         \
			page = eufs_alloc_name_copy(                          \
				de->name, HASHLEN_LEN(de->hv), de->nextname);  \
			info(msg " de=%px, de->name=[%px]%*s, de->inode=%px, " \
				 "de->next=%px, de->volatile_next=%px\n",      \
			     de, de->name, (int)HASHLEN_LEN(de->hv), page,     \
			     de->inode, de->next, de->volatile_next);          \
			eufs_free_page(page);                                 \
		} else {                                                       \
			info(msg " de=%px, de->name=[%px]%*s, de->inode=%px, " \
				 "de->next=%px, de->volatile_next=%px\n",      \
			     de, de->name, (int)HASHLEN_LEN(de->hv), de->name, \
			     de->inode, de->next, de->volatile_next);          \
		}                                                              \
	}

#define _PRINT_PINODE(pi, msg) EUFS_PRINT_PI(pi, msg)

#define PRINT_DENTRY(de, msg)
#define PRINT_PINODE(pi, msg)

void *fix_table(struct super_block *sb, struct nv_dict *dict, u32 idx);

/* Rule for encoded pointers:
 * encoding: o2s(encode(p2o()))
 * decoding: o2p(decode(s2o()))
 */
#define COMPOSE_DICT_HEAD_le64(sb, head)                                       \
	((__le64)((void *)head == NULL ?                                       \
			  NULL_VAL :                                           \
			  (cpu_to_le64(                                        \
				  ((u64)(p2o(sb, head) & ((1UL << 56) - 1)) |  \
				   ((u64)EUFS_SB(sb)->s_crash_ver & 0xff)     \
					   << 56)))))

#define DICT_HEAD_REAL_OFF(head_off)                                           \
	((u64)((u64)(head_off) & ((1UL << 56) - 1)))

static inline __le64 eufs_dentry_vnext(const struct nv_dict_entry *entry)
{
	__le64 vnext = entry->volatile_next;

	if (vnext != EUFS_DIR_EOC)
		vnext = vnext & cpu_to_le64(EUFS_DENTRY_FLAGS_MASK);

	return vnext;
}

static inline bool
eufs_dentry_is_not_persist(const struct nv_dict_entry *entry)
{
	return (entry->volatile_next ==
		(entry->next | cpu_to_le64(EUFS_DENTRY_FLAG_NOT_PERSIST)));
}

static inline void
eufs_dentry_clr_not_persist_flag(struct nv_dict_entry *entry)
{
	entry->volatile_next &= cpu_to_le64(EUFS_DENTRY_FLAGS_MASK);
}

static inline void
eufs_dentry_set_not_persist_flag(struct nv_dict_entry *entry)
{
	entry->volatile_next =
		entry->next | cpu_to_le64(EUFS_DENTRY_FLAG_NOT_PERSIST);
}

#endif /* EUFS_DHT_H */
