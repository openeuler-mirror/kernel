/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_bitmap_table.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_BITMAP_TABLE_H
#define HINIC5_CQM_BITMAP_TABLE_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/spinlock.h>

#include "hinic5_hinic5_vram_api.h"
#include "hinic5_cqm_object.h"
#include "hinic5_vram_common.h"

/* hinic5_cqm_buf_alloc() failed due to buddy allocator page exhaustion. */
#define HINIC5_CQM_BUF_ALLOC_BUDDY_PAGES_FAIL	(HINIC5_CQM_CONTINUE + 1)

struct tag_hinic5_cqm_bitmap_range {
	u32 start;
	u32 end;
};

struct tag_hinic5_cqm_bitmap {
	ulong *table;
	u32 max_num;
	u32 last;
	u32 reserved_top; /* reserved index */
	u32 reserved_back;
	spinlock_t lock; /* lock for hinic5_cqm */
	struct hinic5_vram_buf_info bitmap_info;
};

struct tag_hinic5_cqm_object_table {
	/* Now is big array. Later will be optimized as a red-black tree. */
	struct tag_hinic5_cqm_object **table;
	u32 max_num;
	rwlock_t lock;
};

struct tag_hinic5_cqm_handle;

s32 hinic5_cqm_bitmap_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
void hinic5_cqm_bitmap_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
u32 hinic5_cqm_bitmap_alloc(struct tag_hinic5_cqm_bitmap *bitmap, u32 step, u32 count, bool update_last);
u32 hinic5_cqm_bitmap_alloc_lowbits_align(struct tag_hinic5_cqm_bitmap *bitmap,
				   struct tag_hinic5_cqm_bitmap_range *bp_range,
				   struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
				   u32 xid, bool update_last);
u32 hinic5_cqm_bitmap_alloc_reserved(struct tag_hinic5_cqm_bitmap *bitmap, u32 count, u32 index);
void hinic5_cqm_bitmap_free(struct tag_hinic5_cqm_bitmap *bitmap, u32 index, u32 count);
s32 hinic5_cqm_object_table_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
void hinic5_cqm_object_table_uninit(struct tag_hinic5_cqm_handle *hinic5_cqm_handle);
s32 hinic5_cqm_object_table_insert(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			    struct tag_hinic5_cqm_object_table *object_table,
			    u32 index, struct tag_hinic5_cqm_object *obj, bool bh);
void hinic5_cqm_object_table_remove(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
			     struct tag_hinic5_cqm_object_table *object_table,
			     u32 index, const struct tag_hinic5_cqm_object *obj, bool bh);
struct tag_hinic5_cqm_object *hinic5_cqm_object_table_get(struct tag_hinic5_cqm_handle *hinic5_cqm_handle,
					    struct tag_hinic5_cqm_object_table *object_table,
					    u32 index, bool bh);
u32 hinic5_cqm_bitmap_alloc_by_xid(struct tag_hinic5_cqm_bitmap *bitmap, u32 count, u32 index);
void hinic5_cqm_swab64(u8 *addr, u32 cnt);
void hinic5_cqm_swab32(u8 *addr, u32 cnt);
bool hinic5_cqm_check_align(u32 data);
u32 hinic5_cqm_shift(u32 data);
s32 hinic5_cqm_buf_list_alloc(struct tag_hinic5_cqm_buf *buf);
s32 hinic5_cqm_buf_alloc(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf, bool direct);
s32 hinic5_cqm_buf_alloc_direct(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf, bool direct);
void hinic5_cqm_buf_free(struct tag_hinic5_cqm_buf *buf, struct device *dev);
void hinic5_cqm_buf_free_cache_inv(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, struct tag_hinic5_cqm_buf *buf,
			    s32 *inv_flag);
s32 hinic5_cqm_cla_cache_invalid(struct tag_hinic5_cqm_handle *hinic5_cqm_handle, dma_addr_t pa,
			  u32 cache_size);
void *hinic5_cqm_kmalloc_align(size_t size, gfp_t flags, u16 align_order);
void hinic5_cqm_kfree_align(void *addr);

#endif /* HINIC5_CQM_BITMAP_TABLE_H */
