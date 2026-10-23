/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEVSHR_H_
#define _NBL_DEVSHR_H_

#include "nbl_core.h"

/* max 4pf, and one for merge all pf's bitmap. support release by pf_id */
#define NBL_DEVSHR_MAX_FUNC			5
#define NBL_DEVSHR_REV_FUNC_ID			4
#define NBL_DEVSHR_MAX_DEV			NBL_DRIVER_DEV_MAX

struct nbl_devshr_index_pool {
	struct rw_semaphore sem;
	unsigned long *bitmap[NBL_DEVSHR_MAX_FUNC];
};

struct nbl_devshr_dev_index_pool {
	struct nbl_devshr_index_pool *pool[NBL_DEVSHR_INDEX_MAX];
};

struct nbl_devshr_index_pool_info {
	struct kref func_ref;
	struct nbl_devshr_dev_index_pool *pool;
};

#endif
