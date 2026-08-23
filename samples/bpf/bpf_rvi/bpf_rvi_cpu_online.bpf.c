// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Huawei Technologies Co., Ltd */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

void bpf_task_release(struct task_struct *p) __ksym;
struct task_struct *bpf_current_level1_reaper(void) __ksym;
struct cpuset *bpf_cpuset_from_task(struct task_struct *p) __ksym;
unsigned int bpf_cpuset_cpumask_weight(struct cpumask *pmask) __ksym;

char _license[] SEC("license") = "GPL";


#define RET_OK    0
#define RET_FAIL  1
#define RET_SKIP -1

static int task_effective_cpus_num(struct task_struct *reaper)
{
	struct cpuset *cpuset;

	cpuset = bpf_cpuset_from_task(reaper);
	if (!cpuset)
		return -1;

	return bpf_cpuset_cpumask_weight(cpuset->effective_cpus);
}

SEC("iter/generic_single")
s64 dump_cpu_online(struct bpf_iter__generic_single *ctx)
{
	struct seq_file *m = ctx->meta->seq;
	struct task_struct *reaper;
	int ncpus;
	int ret = RET_OK;

	reaper = bpf_current_level1_reaper();
	if (!reaper)
		return RET_FAIL;
	ncpus = task_effective_cpus_num(reaper);
	if (ncpus == -1) {
		ret = RET_FAIL;
		goto err;
	}

	if (ncpus > 1)
		BPF_SEQ_PRINTF(m, "0-%u\n", ncpus - 1);
	else
		BPF_SEQ_PRINTF(m, "0\n");

err:
	bpf_task_release(reaper);
	return ret;
}
