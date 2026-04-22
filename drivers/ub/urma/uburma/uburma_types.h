/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Types definition provided by uburma
 * Author: Qian Guoxin
 * Create: 2021-8-4
 * Note:
 * History: 2021-8-4: Create file
 */

#ifndef UBURMA_TYPES_H
#define UBURMA_TYPES_H

#include <linux/types.h>
#include <linux/srcu.h>
#include <linux/kref.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/mmu_notifier.h>
#include "ub/urma/ubcore_types.h"

enum uburma_remove_reason {
	/* Userspace requested uobject deletion. Call could fail */
	UBURMA_REMOVE_DESTROY,
	/* Context deletion. This call should delete the actual object itself */
	UBURMA_REMOVE_CLOSE,
	/* Driver is being hot-unplugged. This call should delete the actual object itself */
	UBURMA_REMOVE_DRIVER_REMOVE,
	/* Context is being cleaned-up, but commit was just completed */
	UBURMA_REMOVE_DURING_CLEANUP
};

struct uburma_mn {
	struct mmu_notifier mn;
	struct mm_struct *mm;
};

struct uburma_file {
	struct kref ref;
	struct rw_semaphore ucontext_rwsem;

	struct uburma_device *ubu_dev;
	struct ubcore_ucontext *ucontext;

	/* uobj */
	struct mutex uobjects_lock;
	struct list_head uobjects;
	struct idr idr;
	spinlock_t idr_lock;
	struct rw_semaphore cleanup_rwsem;
	enum uburma_remove_reason cleanup_reason;

	struct list_head list;
	struct mutex umap_mutex;
	struct list_head umaps_list;
	struct page *fault_page;
	struct uburma_mn ub_mn;
};

enum BATCH_DELETE_ID {
	BATCH_DELETE_JETTY,
	BATCH_DELETE_JFS,
	BATCH_DELETE_JFR,
	BATCH_DELETE_JFC,
	BATCH_DELETE_NUM
};

struct uburma_uobj_batch_attr {
	bool enable_batch_class[BATCH_DELETE_NUM];
	bool is_batch;
};

#define UBURMA_JFC_TABLE_SIZE (64 * 1024U)
struct uburma_device {
	atomic_t refcnt;
	struct completion comp; /* When refcnt becomes 0, it will wake up */
	atomic_t cmdcnt; /* number of unfinished ioctl and mmap cmds */
	struct completion
		cmddone; /* When cmdcnt becomes 0, cmddone will wake up */
	unsigned int devnum;
	struct cdev cdev;
	struct device *dev;
	struct ubcore_device *__rcu ubc_dev;
	struct srcu_struct ubc_dev_srcu; /* protect ubc_dev */
	struct kobject kobj; /* when equal to 0 , free uburma_device. */
	struct uburma_uobj_batch_attr batch_attr;
	struct mutex uburma_file_list_mutex; /* protect uburma_file_list */
	struct list_head uburma_file_list;
	uint64_t irq_thresh_count_table[UBURMA_JFC_TABLE_SIZE];
	uint64_t irq_total_count_table[UBURMA_JFC_TABLE_SIZE];
};

struct uburma_umap_priv {
	struct vm_area_struct *vma;
	struct list_head node;
};

#endif /* UBURMA_TYPES_H */
