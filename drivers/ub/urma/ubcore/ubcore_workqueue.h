/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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
#include <ub/urma/ubcore_types.h>

#define UBCORE_QUEUE_NAME_LEN 32

enum ubcore_queue_type {
	UBCORE_DISPATCH_EVENT_WQ = 0,
	UBCORE_SIP_NOTIFY_WQ,
	UBCORE_BOND_EVENT_WQ,
	UBCORE_FRONT_BACK_WQ, /* For frontend and backend ubcore communication. */
	UBCORE_NLMSG_WQ, /* For send nl msg from ubcore to uvs */
	UBCORE_VTP_TASK_WQ,
	UBCORE_CONNECT_VTP_ASYNC_WQ,
	UBCORE_DISCONNECT_VTP_ASYNC_WQ,
	UBCORE_DEACTIVE_SHARE_TP_WQ,
	UBCORE_QUEUE_TYPE_NUM
};

struct ubcore_front_back_work {
	struct work_struct work;
	struct ubcore_device *dev;
	struct ubcore_req_host *req;
};

void ubcore_flush_workqueue(int queue_type);

void ubcore_drain_workqueue(int queue_type);

int ubcore_queue_work(int queue_type, struct work_struct *work);

int ubcore_queue_delayed_work(int queue_type, struct delayed_work *work,
			      unsigned long timeout);

bool ubcore_modify_delay_work(int queue_type, struct delayed_work *work,
			      unsigned long timeout);

int ubcore_create_workqueues(void);

void ubcore_destroy_workqueues(void);

#endif
