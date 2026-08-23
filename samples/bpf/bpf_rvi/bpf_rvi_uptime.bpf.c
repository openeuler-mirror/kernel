// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Huawei Technologies Co., Ltd */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define NSEC_PER_SEC		1000000000L

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;
struct task_struct *bpf_current_level1_reaper(void) __ksym;
struct cpuset *bpf_cpuset_from_task(struct task_struct *p) __ksym;
void cgroup_rstat_flush_atomic(struct cgroup *cgrp) __ksym;
unsigned int bpf_cpuset_cpumask_weight(struct cpumask *pmask) __ksym;
u64 bpf_task_ca_cpuusage(struct task_struct *p) __ksym;

char _license[] SEC("license") = "GPL";

static int task_effective_cpus_num(struct task_struct *reaper)
{
	struct cpuset *cpuset;

	cpuset = bpf_cpuset_from_task(reaper);
	if (!cpuset)
		return -1;

	return bpf_cpuset_cpumask_weight(cpuset->effective_cpus);
}

/* cpuacct.usage of cgroup v1. See cpuusage_read(). */
static int cgroup_v1_get_cpuusage(struct task_struct *reaper, u64 *usage)
{
	*usage = bpf_task_ca_cpuusage(reaper);
	return 0;
}

/* "usage_usec" of cpu.stat of cgroup v2. See cgroup_base_stat_cputime_show(). */
static int cgroup_v2_get_cpuusage(struct task_struct *reaper, u64 *usage)
{
	struct cgroup *cgroup;

	cgroup = reaper->cgroups->dfl_cgrp;
	if (!cgroup)
		return -1;
	cgroup_rstat_flush_atomic(cgroup);
	*usage = cgroup->bstat.cputime.sum_exec_runtime;

	return 0;
}

/*
 * What LXCFS uses is cpuacct.usage, which, as LXCFS's code comment says, might overestimate the
 * container's busy time if the container doesn't have its own cpuacct cgroup.
 */
static int cgroup_get_cpuusage(struct task_struct *reaper, u64 *usage)
{
	int err;

	bpf_rcu_read_lock();
	if (reaper->cgroups->dfl_cgrp)
		err = cgroup_v2_get_cpuusage(reaper, usage);
	else
		err = cgroup_v1_get_cpuusage(reaper, usage);
	bpf_rcu_read_unlock();
	return err;
}

#define RET_OK    0
#define RET_FAIL  1

SEC("iter/generic_single")
s64 dump_uptime(struct bpf_iter__generic_single *ctx)
{
	struct seq_file *m = ctx->meta->seq;
	struct task_struct *reaper;
	u64 cur_timestamp;
	u64 runtime, totaltime, idletime = 0, cpuusage = 0;
	u64 run_sec, run_nsec, idle_sec, idle_nsec;
	unsigned int cpu_count;
	int err, ret = RET_FAIL;

	reaper = bpf_current_level1_reaper();
	if (!reaper)
		return RET_FAIL;
	err = cgroup_get_cpuusage(reaper, &cpuusage);
	if (err)
		goto err;
	cpu_count = task_effective_cpus_num(reaper);
	if (cpu_count == -1)
		goto err;

	cur_timestamp = bpf_ktime_get_boot_ns(); // "ns": nanosecond, not namespace
	/*
	 * LXCFS takes the 22nd column from /proc/<pid>/stat, which is task->start_boottime (with
	 * transforming unit and adding timens bias). See do_task_stat() for details.
	 */
	if (cur_timestamp < reaper->start_boottime)
		runtime = 0;
	else
		runtime = cur_timestamp - reaper->start_boottime;
	/*
	 * As implemented in uptime_proc_show(), idle time of the original /proc/uptime is the sum
	 * of each cpu's idle time. Here we calculate it the other way around: subtract the total
	 * amount of cpu time by cpu usage.
	 */
	totaltime = runtime * cpu_count;
	if (totaltime > cpuusage)
		idletime = totaltime - cpuusage;

	run_sec = runtime / NSEC_PER_SEC;
	run_nsec = runtime % NSEC_PER_SEC;
	idle_sec = idletime / NSEC_PER_SEC;
	idle_nsec = idletime % NSEC_PER_SEC;
	BPF_SEQ_PRINTF(m, "%llu.%02llu %llu.%02llu\n", run_sec, run_nsec / (NSEC_PER_SEC / 100),
						       idle_sec, idle_nsec / (NSEC_PER_SEC / 100));

	ret = RET_OK;
err:
	bpf_task_release(reaper);
	return ret;
}
