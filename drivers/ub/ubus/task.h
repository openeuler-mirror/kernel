/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2026. All rights reserved.
 */

#ifndef __TASK_H__
#define __TASK_H__

enum ub_delay_task_type {
	TASK_TYPE_START = 0,
	TASK_TYPE_ATTACH = 1,
	TASK_TYPE_REINIT = 2,
	TASK_TYPE_LINKDOWN = 3,
	TASK_TYPE_DISABLE = 4
};

enum ub_task_src {
	TASK_SRC_SELF = 0,
	TASK_SRC_POOL = 1,
	TASK_SRC_COMMON_MAX = 7,
	/* 8~15 reserved for Vendor */
	TASK_SRC_RETRY = 16,
};

#define TASK_SRC_COMMON_MASK 0xff
#define TASK_SRC_VDM_MASK 0xff00

struct ub_delay_task {
	int task_type;
	struct ub_entity *uent;
	struct ub_port *port;
	struct work_struct work;
};

struct ub_retry_task {
	u32 eid;
	struct ub_guid guid;
	struct delayed_work work;
	struct list_head node;
	struct kref kref;
};

static inline void ub_entity_assign_task_src(struct ub_entity *uent, int bit,
					     bool flag)
{
	assign_bit(bit, (unsigned long *)&uent->task_src, flag);
}

static inline bool ub_entity_test_task_src(struct ub_entity *uent, int bit)
{
	return test_bit(bit, (unsigned long *)&uent->task_src);
}

int ub_delay_task_wq_init(void);
void ub_delay_task_wq_uninit(void);
struct workqueue_struct *ub_get_delay_task_wq(void);
struct ub_delay_task *
ub_delay_task_alloc_and_init(struct ub_entity *uent, struct ub_port *port,
			     int type);
void ub_delay_task_free(struct ub_delay_task *task);
int ub_add_delay_task(struct ub_entity *uent, struct ub_port *port, int type);
void ub_add_retry_task(struct ub_entity *uent);
void ub_cancel_retry_work_sync(void);
int ub_create_existed_entity_handler(struct ub_entity *uent);
int ub_destroy_existed_entity_handler(struct ub_entity *uent);

#endif /* __TASK_H__ */
