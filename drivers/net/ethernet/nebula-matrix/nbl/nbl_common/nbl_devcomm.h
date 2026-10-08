/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEVCOMM_H_
#define _NBL_DEVCOMM_H_

#include "nbl_core.h"

struct nbl_devcomm_comp_key {
	u32 flags;
	union nbl_devcomm_match_key key;
	possible_net_t net;
};

struct nbl_devcomm_comp {
	struct list_head comp_list;
	enum nbl_devcomm_comp_type id;
	struct list_head comp_dev_list_head;
	struct nbl_devcomm_comp_key key;
	int (*event_cb)(int event, void *priv_data, void *event_data);
	struct kref ref;
	struct rw_semaphore sem;
};

#endif
