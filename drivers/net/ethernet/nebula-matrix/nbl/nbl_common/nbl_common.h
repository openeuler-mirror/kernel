/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_COMMON_H_
#define _NBL_COMMON_H_

#include "nbl_core.h"

/**
 * the key_hash size is index_size/NBL_INDEX_HASH_DIVISOR. eg index_size is 1024,
 * the key_hash size is 1024/16 = 64
 */
#define NBL_INDEX_HASH_DIVISOR                  16

/* list only need one bucket size */
#define NBL_HASH_TBL_LIST_BUCKET_SIZE		1

struct nbl_index_mgt {
	struct nbl_index_tbl_key tbl_key;
	unsigned long *bitmap;
	struct hlist_head *key_hash;
	u32 free_index_num;
	u32 bucket_size;
	struct mutex lock;  /* support multi thread */
};

struct nbl_index_entry_key_node {
	struct hlist_node node;
	u32 index;      /* the index for key has alloc from index table */
	u8 data[];
};

struct nbl_hash_tbl_mgt {
	struct nbl_hash_tbl_key tbl_key;
	struct hlist_head *hash;
	struct mutex lock;  /* support multi thread */
	u16 node_num;
};

struct nbl_hash_xy_tbl_mgt {
	struct nbl_hash_xy_tbl_key tbl_key;
	struct hlist_head *hash;
	struct hlist_head *x_axis_hash;
	struct hlist_head *y_axis_hash;
	struct mutex lock;  /* support multi thread */
	u16 node_num;
};

/* it used for y_axis no necessay */
struct nbl_hash_entry_node {
	struct hlist_node node;
	void *key;
	void *data;
};

/* it used for y_axis no necessay */
struct nbl_hash_entry_xy_node {
	struct hlist_node node;
	struct hlist_node x_axis_node;
	struct hlist_node y_axis_node;
	void *x_axis_key;
	void *y_axis_key;
	void *data;
};

#endif
