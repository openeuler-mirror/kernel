/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: fast IPC header
 * Author: yangyun
 * Create: 2024-05-31
 */
#ifndef __FAST_IPC_H_
#define __FAST_IPC_H_

struct fast_ipc_bind_info {
	unsigned int data_size;

	struct task_struct *client_task;
	struct task_struct *server_task;

	bool is_calling;
	bool no_reply;
	bool client_need_exit;
	bool server_need_exit;

	atomic_t nr_call;

	spinlock_t lock;
	struct list_head node;
};

void fast_ipc_wakeup_server_task(struct fast_ipc_bind_info *bind_info);

void *fast_ipc_bind(struct task_struct *server_task);

void fast_ipc_unbind(struct fast_ipc_bind_info *bind_info,
		struct task_struct *server_task);

ssize_t fast_ipc_do_call(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk);

long fast_ipc_ret_call(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk);

long fast_ipc_wait_call(struct fast_ipc_bind_info *bind_info,
		struct task_struct *tsk);

void fast_ipc_release(struct fast_ipc_bind_info *bind_info);

static inline void fast_ipc_set_call_no_reply(struct fast_ipc_bind_info *bind_info)
{
	bind_info->no_reply = true;
};

#endif
