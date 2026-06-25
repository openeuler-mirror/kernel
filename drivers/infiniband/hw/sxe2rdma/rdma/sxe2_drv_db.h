/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_db.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_DB_H
#define SXE2_DRV_DB_H

#include <linux/kref.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include "sxe2_drv_rdma_common.h"

enum sxe2_drv_db_page_type {
	SXE2_DRV_DB_PAGE_TYPE_LLWQE    = 0x0,
	SXE2_DRV_DB_PAGE_TYPE_NO_LLWQE = 0x1,
};

enum sxe2_drv_db_mmap_type {
	SXE2_DRV_DB_MMAP_TYPE_WC = 1,
	SXE2_DRV_DB_MMAP_TYPE_NC = 2,
};

enum drv_db_alloc_attrs {
	SXE2_DRV_ATTR_DB_OBJ_ALLOC_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
	SXE2_DRV_ATTR_DB_OBJ_ALLOC_TYPE,
	SXE2_DRV_ATTR_DB_OBJ_ALLOC_MMAP_OFFSET,
	SXE2_DRV_ATTR_DB_OBJ_ALLOC_MMAP_LENGTH,
	SXE2_DRV_ATTR_DB_OBJ_ALLOC_PAGE_ID,
};

enum sxe2_drv_db_obj_destroy_attrs {
	SXE2_DRV_ATTR_DB_OBJ_DESTROY_HANDLE = (1U << UVERBS_ID_NS_SHIFT),
};

enum sxe2_drv_db_obj_methods {
	SXE2_DRV_METHOD_DB_OBJ_ALLOC = (1U << UVERBS_ID_NS_SHIFT),
	SXE2_DRV_METHOD_DB_OBJ_DESTROY,
};

enum sxe2_drv_objects {
	SXE2_DRV_OBJECT_DB = (1U << UVERBS_ID_NS_SHIFT),
};

struct sxe2_db_page {
	void __iomem *map;
	bool wc;
	u32 index;
	struct list_head list;
	u32 llwqe_num;
	u32 llwqe_avail;
	unsigned long *llwqe_bitmap;
	struct kref ref_count;
	struct sxe2_rdma_pci_f *rdma_func;
};

struct sxe2_db_ucontext {
	struct ib_ucontext *ibucontext;
	struct list_head db_pageid_list;
	struct list_head entry_list;
	struct list_head list;
};

struct sxe2_db_mmap_entry {
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	struct rdma_user_mmap_entry *mmap_entry;
#else
	struct sxe2_user_mmap_entry *mmap_entry;
#endif
	u32 page_idx;
	struct list_head list;
};

struct sxe2_db_page_idx {
	u32 db_page_idx;
	struct list_head list;
};

int sxe2_kmmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma);
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
void sxe2_kmmap_free(struct rdma_user_mmap_entry *entry);
#endif
int sxe2_kinit_doorbell(struct sxe2_rdma_device *rdma_dev);

void sxe2_kfree_doorbell(struct sxe2_rdma_device *rdma_dev);
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
struct rdma_user_mmap_entry *
sxe2_kinsert_user_mmap_entry(struct sxe2_rdma_kcontext *ctx,
			     enum sxe2_drv_db_mmap_type mmap_flag,
			     u64 *mmap_offset);
#else
struct sxe2_user_mmap_entry *
rdma_find_user_mmap_entry(struct sxe2_rdma_kcontext *kcontext,
			  struct vm_area_struct *vma);
bool find_key_in_mmap_tbl(struct sxe2_rdma_kcontext *ucontext, u64 key);
struct sxe2_user_mmap_entry *
rdma_user_mmap_entry_add_hash(struct sxe2_rdma_kcontext *ucontext,
			      enum sxe2_drv_db_mmap_type mmap_flag,
			      u64 *mmap_offset);
void rdma_user_mmap_entry_del_hash(struct sxe2_user_mmap_entry *entry);
#endif

int db_kfree_mmap_entry(struct ib_uobject *uobject, enum rdma_remove_reason why,
			struct uverbs_attr_bundle *attrs);

u32 get_db_page_multiplier(void);

bool uctx_db_page_has_alloced(struct sxe2_rdma_device *rdma_dev,
			struct ib_ucontext *uctx, u32 page_idx);

int db_kalloc_llwqe_mmap_entry(struct sxe2_rdma_device *rdma_dev,
			struct ib_udata *udata,
			struct sxe2_rdma_qp *qp,
			u32 *page_id, u32 *length,
			u64 *mmap_offset);

#ifdef SXE2_CFG_DEBUG
int drv_rdma_debug_db_add(struct sxe2_rdma_device *rdma_dev);
#endif

#ifdef UVERBS_UOBJ_CREATE_NOT_SUPPORT
struct uverbs_api_ioctl_method {
	int(__rcu *handler)(struct uverbs_attr_bundle *attrs);
	DECLARE_BITMAP(attr_mandatory, UVERBS_API_ATTR_BKEY_LEN);
	u16 bundle_size;
	u8 use_stack : 1;
	u8 driver_method : 1;
	u8 disabled : 1;
	u8 has_udata : 1;
	u8 key_bitmap_len;
	u8 destroy_bkey;
};

struct bundle_alloc_head {
	struct bundle_alloc_head *next;
	u8 data[];
};

struct bundle_priv {
	struct bundle_alloc_head alloc_head;
	struct bundle_alloc_head *allocated_mem;
	size_t internal_avail;
	size_t internal_used;

	struct radix_tree_root *radix;
	const struct uverbs_api_ioctl_method *method_elm;
	void __rcu **radix_slots;
	unsigned long radix_slots_len;
	u32 method_key;

	struct ib_uverbs_attr __user *user_attrs;
	struct ib_uverbs_attr *uattrs;

	DECLARE_BITMAP(uobj_finalize, UVERBS_API_ATTR_BKEY_LEN);
	DECLARE_BITMAP(spec_finalize, UVERBS_API_ATTR_BKEY_LEN);
	DECLARE_BITMAP(uobj_hw_obj_valid, UVERBS_API_ATTR_BKEY_LEN);

	struct uverbs_attr_bundle bundle;
	u64 internal_buffer[32];
};
#endif

#endif
