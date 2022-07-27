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

#include <test_progs.h>

#include "sched.skel.h"
#include "cgroup_helpers.h"

#define CHECK_TGIDPID_MODE(HOOKNAME, TGIDPID) \
	do { \
		if (skel->bss->HOOKNAME##_tgidpid_ret) { \
			CHECK(skel->bss->HOOKNAME##_tgidpid_ret != TGIDPID, \
				#HOOKNAME"_tgidpid", #HOOKNAME"_tgidpid_ret %lu\n", \
				skel->bss->HOOKNAME##_tgidpid_ret); \
		} \
	} while (0)

#define CHECK_CGID_MODE(HOOKNAME, PID, CGID) \
	do { \
		if (skel->bss->HOOKNAME##_cgid_ret) { \
			if (skel->bss->HOOKNAME##_cgid_ret) { \
				CHECK(skel->bss->HOOKNAME##_cgid_pid_ret != PID, \
					#HOOKNAME"_cgid_pid", #HOOKNAME"_cgid_pid_ret %u\n", \
					skel->bss->HOOKNAME##_cgid_pid_ret); \
			} \
			if (skel->bss->HOOKNAME##_cgid_se_to_cgid_ret) { \
				CHECK(skel->bss->HOOKNAME##_cgid_se_to_cgid_ret != CGID, \
					#HOOKNAME"_cgid_se_to_cgid", \
					#HOOKNAME"_cgid_se_to_cgid_ret %lu\n", \
					skel->bss->HOOKNAME##_cgid_se_to_cgid_ret); \
			} \
		} \
	} while (0)

static void work(void)
{
	int i;

	for (i = 0; i < 1000; i++)
		usleep(1000);
}

int create_prioritize_task(int *child_pid)
{
	int cpid;

	cpid = fork();
	if (cpid == -1) {
		return -ECHILD;
	} else if (cpid == 0) {
		work();
		exit(0);
	} else {
		*child_pid = cpid;
		return 0;
	}
	return -EINVAL;
}

void test_sched_tgidpid_mode(void)
{
	struct sched *skel = NULL;
	int err, duration = 0, child_pid = 0, tgid = 0, cgid = 0;
	int status = 0;

	skel = sched__open();
	if (CHECK(!skel, "open", "sched open failed\n"))
		goto close_prog;

	err = sched__load(skel);
	if (CHECK(err, "load", "sched load failed: %d\n", err))
		goto close_prog;

	err = sched__attach(skel);
	if (CHECK(err, "attach", "sched attach failed: %d\n", err))
		goto close_prog;

	err = create_prioritize_task(&child_pid);
	if (CHECK(err < 0, "create_prior_task", "err %d errno %d\n", err, errno))
		goto close_prog;

	tgid = child_pid;
	skel->bss->tgidpid = (unsigned long)tgid << 32 | child_pid;
	skel->bss->cgid = cgid;

	if (child_pid)
		err = waitpid(child_pid, &status, 0);
	if (CHECK(err == -1 && errno != ECHILD, "waitpid", "failed %d", errno))
		goto close_prog;

	CHECK_TGIDPID_MODE(tick, skel->bss->tgidpid);
	CHECK_TGIDPID_MODE(wakeup, skel->bss->tgidpid);
	CHECK_TGIDPID_MODE(entity, skel->bss->tgidpid);

close_prog:
	sched__destroy(skel);
}

#define TEST_CGROUP "/test-bpf-sched-cgid-mode/"

void test_sched_cgid_mode(void)
{
	struct sched *skel = NULL;
	int err, duration = 0, cgid = 0, cgroup_fd = 0, pid = 0;

	skel = sched__open();
	if (CHECK(!skel, "open", "sched open failed\n"))
		goto close_prog;

	err = sched__load(skel);
	if (CHECK(err, "load", "sched load failed: %d\n", err))
		goto close_prog;

	err = sched__attach(skel);
	if (CHECK(err, "attach", "sched attach failed: %d\n", err))
		goto close_prog;

	cgroup_fd = cgroup_setup_and_join(TEST_CGROUP);
	if (CHECK(cgroup_fd < 0, "cgroup_setup_and_join", "err %d errno %d\n", cgroup_fd, errno))
		goto cleanup_cgroup_env;

	cgid = get_cgroup_id(TEST_CGROUP);
	if (CHECK(!cgid, "get_cgroup_id", "err %d", cgid))
		goto cleanup_cgroup_env;

	skel->bss->tgidpid = 0;
	skel->bss->cgid = cgid;

	/* trigger sched hook */
	work();

	pid = getpid();

	CHECK_CGID_MODE(tick, pid, cgid);
	CHECK_CGID_MODE(wakeup, pid, cgid);
	CHECK_CGID_MODE(entity, pid, cgid);

cleanup_cgroup_env:
	cleanup_cgroup_environment();
close_prog:
	sched__destroy(skel);
}

void test_test_sched(int argc, char **argv)
{
	if (test__start_subtest("sched_tgidpid_mode"))
		test_sched_tgidpid_mode();
	if (test__start_subtest("sched_cgid_mode"))
		test_sched_cgid_mode();
}
