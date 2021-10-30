/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_CQM_BITMAP_TABLE_H
#define SPFC_CQM_BITMAP_TABLE_H

struct cqm_bitmap {
	ulong *table;
	u32 max_num;
	u32 last;
	u32 reserved_top; /* reserved index */
	spinlock_t lock;
};

struct cqm_object_table {
	/* Now is big array. Later will be optimized as a red-black tree. */
	struct cqm_object **table;
	u32 max_num;
	rwlock_t lock;
};

struct cqm_cla_cache_invalid_cmd {
	u32 gpa_h;
	u32 gpa_l;

	u32 cache_size; /* CLA cache size=4096B */

	u32 smf_id;
	u32 func_id;
};

struct cqm_handle;

s32 cqm_bitmap_init(struct cqm_handle *cqm_handle);
void cqm_bitmap_uninit(struct cqm_handle *cqm_handle);
u32 cqm_bitmap_alloc(struct cqm_bitmap *bitmap, u32 step, u32 count, bool update_last);
u32 cqm_bitmap_alloc_reserved(struct cqm_bitmap *bitmap, u32 count, u32 index);
void cqm_bitmap_free(struct cqm_bitmap *bitmap, u32 index, u32 count);
s32 cqm_object_table_init(struct cqm_handle *cqm_handle);
void cqm_object_table_uninit(struct cqm_handle *cqm_handle);
s32 cqm_object_table_insert(struct cqm_handle *cqm_handle,
			    struct cqm_object_table *object_table,
			    u32 index, struct cqm_object *obj, bool bh);
void cqm_object_table_remove(struct cqm_handle *cqm_handle,
			     struct cqm_object_table *object_table,
			     u32 index, const struct cqm_object *obj, bool bh);
struct cqm_object *cqm_object_table_get(struct cqm_handle *cqm_handle,
					struct cqm_object_table *object_table,
					u32 index, bool bh);

void cqm_swab64(u8 *addr, u32 cnt);
void cqm_swab32(u8 *addr, u32 cnt);
bool cqm_check_align(u32 data);
s32 cqm_shift(u32 data);
s32 cqm_buf_alloc(struct cqm_handle *cqm_handle, struct cqm_buf *buf, bool direct);
s32 cqm_buf_alloc_direct(struct cqm_handle *cqm_handle, struct cqm_buf *buf, bool direct);
void cqm_buf_free(struct cqm_buf *buf, struct pci_dev *dev);
void cqm_buf_free_cache_inv(struct cqm_handle *cqm_handle, struct cqm_buf *buf,
			    s32 *inv_flag);
s32 cqm_cla_cache_invalid(struct cqm_handle *cqm_handle, dma_addr_t gpa,
			  u32 cache_size);
void *cqm_kmalloc_align(size_t size, gfp_t flags, u16 align_order);
void cqm_kfree_align(void *addr);

#endif
