/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ubdevshm struct defines and function prototypes
 */

#ifndef __UBDEVSHM_MAIN_H__
#define __UBDEVSHM_MAIN_H__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/idr.h>
#include <ub/ubdevshm/ubdevshm.h>

extern struct rw_semaphore ubdevshm_rw_semlock;
extern struct list_head provider_list;
extern struct list_head container_list;
extern struct idr shm_container_idr;
extern struct idr mem_provider_idr;

struct role_info {
	unsigned int tgid;
	u64 aux; // user start_time for check whether is the same process
	char name[16];
	bool lite;
};

struct mem_provider {
	struct list_head node;
	int handle_id;
	refcount_t refcnt;
	struct ubdevshm_mem_ops *ops;
};

struct shm_segment {
	u64 va;
	u64 size;
	struct mem_uba uba;
};

// protected by cntr->lock
struct shm_area {
	struct rb_node node;
	u64 va;
	u64 size;
	struct list_head ctx_list;
};

struct access_ctx_inner {
	struct list_head node; // link to ctx_list
	struct mem_provider *provider;
	struct role_info user;
	struct shm_area *sa;
	struct shm_segment seg;
	long id;
	refcount_t refcnt;
	refcount_t acquire_refcnt;
};

enum use_mode {
	/*
	 * USE_MODE_NOGRANT used when there is only one provider and only one user,
	 * who is the cntr owner.
	 */
	USE_MODE_NOGRANT = 0,
	USE_MODE_GRANT,
	USE_MODE_MAX,
};

struct shm_container {
	struct list_head node;
	int id;
	enum use_mode mode;
	struct role_info owner;
	struct rb_root shm_area_root;
	struct mutex lock;
	refcount_t refcnt;
};

#endif /*__UBDEVSHM_MAIN_H__*/
