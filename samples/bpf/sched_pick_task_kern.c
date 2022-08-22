// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <linux/version.h>
#include <linux/sched.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/libbpf_sched.h>

#define PICK_CURR 1
#define PICK_NOMAL 0
#define ERROR -1

enum task_type {
	TASK_TYPE_OFFLINE = -1,
	TASK_TYPE_ONLINE,
	TASK_TYPE_MAX
};

/*
 * Only implements the effect of the task selection strategy
 * and needs to be used in conjunction with preempt and
 * load balance. If quota is not configured, the priority
 * inversion leads to system crash.
 */
SEC("sched/cfs_tag_pick_next_entity")
int BPF_PROG(sched_cfs_tag_pick_next_entity, struct sched_entity *curr, struct sched_entity *next)
{
	int curr_type = 0;
	int next_type = 0;

	if (curr == NULL || next == NULL)
		return PICK_NOMAL;

	curr_type = libbpf_sched_se_tag_of(curr);
	next_type = libbpf_sched_se_tag_of(next);

	if (curr_type > next_type)
		return PICK_CURR;

	return PICK_NOMAL;
}

char _license[] SEC("license") = "GPL";

