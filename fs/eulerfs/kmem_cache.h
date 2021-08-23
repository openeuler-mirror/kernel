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

#ifndef EUFS_KMEM_CACHE_H
#define EUFS_KMEM_CACHE_H

#include <linux/module.h>

extern int init_page_cache(void) __init;
extern int init_dep_node_cache(void) __init;
extern int init_inodecache(void) __init;

extern void destroy_page_cache(void);
extern void destroy_inodecache(void);
extern void destroy_dep_node_cache(void);

extern void *eufs_zalloc_page(void);
extern void *eufs_alloc_page(void);
extern void eufs_free_page(void *page);

extern struct dep_node *eufs_alloc_dep_node(void);
extern void eufs_free_dep_node(struct dep_node *dep);

extern struct eufs_inode_info *eufs_alloc_vi(void);
extern void eufs_free_vi(struct eufs_inode_info *vi);

#endif /* EUFS_KMEM_CACHE_H */
