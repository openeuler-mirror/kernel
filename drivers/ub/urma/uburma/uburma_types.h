/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
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

#include <urma/ubcore_types.h>

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

struct uburma_file {
	struct kref ref;
	struct mutex mutex;
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
	int is_closed;
};

struct uburma_device {
	atomic_t  refcnt;
	struct completion comp; /* When refcnt becomes 0, it will wake up */
	atomic_t cmdcnt; /* number of unfinished ioctl and mmap cmds */
	struct completion cmddone; /* When cmdcnt becomes 0, cmddone will wake up */
	unsigned int devnum;
	struct cdev cdev;
	struct device *dev;
	struct ubcore_device *__rcu ubc_dev;
	struct srcu_struct ubc_dev_srcu;    /* protect ubc_dev */
	struct kobject kobj;                /* when equal to 0 , free uburma_device. */
	struct mutex lists_mutex;           /* protect lists */
	struct list_head uburma_file_list;
};

#endif /* UBURMA_TYPES_H */
