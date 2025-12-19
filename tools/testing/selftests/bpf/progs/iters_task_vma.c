// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

pid_t target_pid = 0;
unsigned int vmas_seen = 0;

struct {
	__u64 vm_start;
	__u64 vm_end;
} vm_ranges[1000];

SEC("raw_tp/sys_enter")
int iter_task_vma_for_each(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;
	unsigned int seen = 0;

	if (task->pid != target_pid)
		return 0;

	if (vmas_seen)
		return 0;

	bpf_for_each(task_vma, vma, task, 0) {
		/*
		 * Hack code here:
		 * the compiler will assign the variable 'seen'
		 * and the array index to different, unrelated
		 * registers. As a result, the verifier will
		 * reject the code due to potential out-of-bounds
		 * access to the vm_ranges array. However, by
		 * multiplying both sides of the inequality by 16,
		 * we can ensure the code passes the verification
		 * test.
		 */
		if (seen * 16 >= 16000)
			break;

		vm_ranges[seen].vm_start = vma->vm_start;
		vm_ranges[seen].vm_end = vma->vm_end;
		seen++;
	}

	vmas_seen = seen;
	return 0;
}

char _license[] SEC("license") = "GPL";
