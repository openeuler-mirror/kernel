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

unsigned long idea_runtime = 1000000UL;

enum task_type {
	TASK_TYPE_OFFLINE = -1,
	TASK_TYPE_NORMAL,
	TASK_TYPE_ONLINE,
};

#define getVal(P)								\
	({									\
		typeof(P) val = 0;						\
		bpf_probe_read_kernel(&val, sizeof(val), &(P));			\
		val;								\
	})

#define bprintk(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
					##__VA_ARGS__);			\
		})

SEC("sched/cfs_check_preempt_wakeup")
int BPF_PROG(sched_cfs_check_preempt_wakeup, struct task_struct *curr, struct task_struct *p)
{
	long curr_type, p_type;
	int ret = 0;

	curr_type = bpf_sched_task_tag_of(curr);
	p_type = bpf_sched_task_tag_of(p);

	if (curr_type == TASK_TYPE_ONLINE && p_type == TASK_TYPE_OFFLINE)
		ret = -1;

	if (curr_type == TASK_TYPE_OFFLINE && p_type == TASK_TYPE_ONLINE)
		ret = 1;

	bprintk("check_preempt_wakeup: curr id = %d, p id = %d, preempt result is %d\n",
		getVal(curr->pid), getVal(p->pid), ret);

	return ret;
}

SEC("sched/cfs_check_preempt_tick")
int BPF_PROG(sched_cfs_check_preempt_tick, struct sched_entity *curr, unsigned long delta_exec)
{
	long curr_type = TASK_TYPE_NORMAL;
	int ret = 0, id = 0;
	int entity_is_task = bpf_sched_entity_is_task(curr);

	if (entity_is_task) {
		struct task_struct *tsk = bpf_sched_entity_to_task(curr);

		if (tsk) {
			curr_type = bpf_sched_task_tag_of(tsk);
			id = getVal(tsk->pid);
		}
	} else {
		struct task_group *tg = bpf_sched_entity_to_tg(curr);

		if (tg) {
			curr_type = bpf_sched_tg_tag_of(tg);
			id = bpf_sched_entity_to_cgrpid(curr);
		}
	}

	if (curr_type == TASK_TYPE_ONLINE)
		ret = delta_exec >= idea_runtime ? 1 : -1;

	bprintk("check_preempt_tick: delta = %lu, entity id = %d, preempt result = %d\n",
		delta_exec, id, ret);
	return ret;
}

SEC("sched/cfs_wakeup_preempt_entity")
int BPF_PROG(sched_cfs_wakeup_preempt_entity, struct sched_entity *curr, struct sched_entity *se)
{
	long curr_type = TASK_TYPE_NORMAL;
	long p_type = TASK_TYPE_NORMAL;
	int curr_id = 0, p_id = 0;
	int curr_is_task = bpf_sched_entity_is_task(curr);
	int p_is_task = bpf_sched_entity_is_task(se);
	int ret = 0;

	if (curr_is_task) {
		struct task_struct *tsk = bpf_sched_entity_to_task(curr);

		if (tsk) {
			curr_type = bpf_sched_task_tag_of(tsk);
			curr_id = getVal(tsk->pid);
		}
	} else {
		struct task_group *tg = bpf_sched_entity_to_tg(curr);

		if (tg) {
			curr_type = bpf_sched_tg_tag_of(tg);
			curr_id = bpf_sched_entity_to_cgrpid(curr);
		}
	}

	if (p_is_task) {
		struct task_struct *p = bpf_sched_entity_to_task(se);

		if (p) {
			p_type = bpf_sched_task_tag_of(p);
			p_id = getVal(p->pid);
		}
	} else {
		struct task_group *tg1 = bpf_sched_entity_to_tg(se);

		if (tg1) {
			p_type = bpf_sched_tg_tag_of(tg1);
			p_id = bpf_sched_entity_to_cgrpid(se);
		}
	}

	if (curr_type == TASK_TYPE_ONLINE && p_type == TASK_TYPE_OFFLINE)
		ret = -1;

	if (curr_type == TASK_TYPE_OFFLINE && p_type == TASK_TYPE_ONLINE)
		ret = 1;

	bprintk("wakeup_preempt_entity: curr entity id = %d, se entity id = %d, result = %d\n",
		curr_id, p_id, ret);
	return ret;
}

char _license[] SEC("license") = "GPL";
