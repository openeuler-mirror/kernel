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
#include "euler.h"
#include "kmem_cache.h"
#include "dep.h"

static struct kmem_cache *eufs_dep_node_cachep;
static struct kmem_cache *eufs_page_cachep;
static struct kmem_cache *eufs_inode_cachep;

static void init_once(void *foo)
{
	struct eufs_inode_info *vi = foo;

	inode_init_once(&vi->vfs_inode);
}

int __init init_page_cache(void)
{
	eufs_page_cachep = kmem_cache_create(
		"eufs_page_cache", PAGE_SIZE, 0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_HWCACHE_ALIGN),
		NULL);
	if (eufs_page_cachep == NULL)
		return -ENOMEM;
	return 0;
}

int __init init_dep_node_cache(void)
{
	eufs_dep_node_cachep = kmem_cache_create(
		"eufs_dep_node_cache", sizeof(struct dep_node), 0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_HWCACHE_ALIGN),
		NULL);
	if (eufs_dep_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

int __init init_inodecache(void)
{
	eufs_inode_cachep = kmem_cache_create(
		"eufs_inode_cache", sizeof(struct eufs_inode_info), 0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), init_once);
	if (eufs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void destroy_page_cache(void)
{
	kmem_cache_destroy(eufs_page_cachep);
}

void destroy_inodecache(void)
{
	rcu_barrier();
	kmem_cache_destroy(eufs_inode_cachep);
}

void destroy_dep_node_cache(void)
{
	kmem_cache_destroy(eufs_dep_node_cachep);
}

void *eufs_zalloc_page(void)
{
	return kmem_cache_zalloc(eufs_page_cachep, GFP_NOFS | __GFP_NOFAIL);
}
void *eufs_alloc_page(void)
{
	return kmem_cache_alloc(eufs_page_cachep, GFP_NOFS | __GFP_NOFAIL);
}
void eufs_free_page(void *page)
{
	kmem_cache_free(eufs_page_cachep, page);
}

struct dep_node *eufs_alloc_dep_node(void)
{
	return kmem_cache_alloc(eufs_dep_node_cachep, GFP_NOFS);
}
void eufs_free_dep_node(struct dep_node *dep)
{
	kmem_cache_free(eufs_dep_node_cachep, dep);
}

struct eufs_inode_info *eufs_alloc_vi(void)
{
	return kmem_cache_alloc(eufs_inode_cachep, GFP_NOFS);
}
void eufs_free_vi(struct eufs_inode_info *vi)
{
	kmem_cache_free(eufs_inode_cachep, vi);
}
