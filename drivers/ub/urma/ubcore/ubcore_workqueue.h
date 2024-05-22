/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: Ubcore workqueue
 * Author: Zhang Jiayu
 * Create: 2024-1-27
 * Note:
 * History: 2024-1-27: Create file
 */

#ifndef UBCORE_WORKQUEUE_H
#define UBCORE_WORKQUEUE_H

#include <linux/types.h>
#include <linux/mm.h>

#include "urma/ubcore_types.h"

#define UBCORE_QUEUE_NAME_LEN 20

enum ubcore_queue_type {
	UBCORE_DISPATCH_EVENT_WQ = 0,
	UBCORE_SIP_NOTIFY_WQ,
	UBCORE_BOND_EVENT_WQ,
	UBCORE_FRONT_BACK_WQ, /* For frontend and backend ubcore communication. */
	UBCORE_QUEUE_TYPE_NUM
};

struct ubcore_front_back_work {
	struct work_struct work;
	struct ubcore_device *dev;
	struct ubcore_req_host *req;
};

void ubcore_flush_workqueue(int queue_type);

int ubcore_queue_work(int queue_type, struct work_struct *work);

int ubcore_create_workqueues(void);

void ubcore_destroy_workqueues(void);

#endif
