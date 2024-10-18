/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_EVENT_H_
#define _NBL_EVENT_H_

#include "nbl_core.h"

struct nbl_event_notifier {
	struct list_head node;
	struct mutex callback_lock;		/* Protect callback */
	struct nbl_event_callback callback;
	u16 src_vsi_id;
	u16 board_id;
};

struct nbl_event_notifier_list {
	struct list_head list;
	struct mutex notifier_lock;		/* Protect list structure */
};

struct nbl_event_mgt {
	struct nbl_event_notifier_list notifier_list[NBL_EVENT_MAX];
};

#endif
