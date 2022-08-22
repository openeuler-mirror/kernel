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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#define MAX_PROGS	(3)
#define TRACE_DIR	"/sys/kernel/debug/tracing/"
#define BUF_SIZE	(4096)

int progindex[MAX_PROGS];

static void usage(void)
{
	printf("USAGE: sched_preempt [...]\n");
	printf("       -W    # Test sched preempt wakeup\n");
	printf("       -T    # Test sched preempt tick\n");
	printf("       -E    # Test wakeup preempt entity\n");
	printf("       -h    # Display this help\n");
}

/* read trace logs from debug fs */
static void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(TRACE_DIR "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[BUF_SIZE];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

static inline bool check_attach_prog(int index)
{
	return progindex[index] ? true : false;
}

int main(int argc, char **argv)
{
	int opt;
	int index;
	char filename[256];
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link[3] = {NULL};

	char prognames[MAX_PROGS][256] = {
		"sched_cfs_check_preempt_wakeup",
		"sched_cfs_check_preempt_tick",
		"sched_cfs_wakeup_preempt_entity",
	};

	while ((opt = getopt(argc, argv, "WTEh")) != -1) {
		switch (opt) {
		case 'W':
			progindex[0] = 1;
			break;
		case 'T':
			progindex[1] = 1;
			break;
		case 'E':
			progindex[2] = 1;
			break;
		case 'h':
		default:
			usage();
			goto out;
		}
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		goto out;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	for (index = 0; index < MAX_PROGS; ++index) {
		if (check_attach_prog(index)) {
			prog = bpf_object__find_program_by_name(obj, prognames[index]);
			if (libbpf_get_error(prog)) {
				fprintf(stderr, "ERROR: finding a prog:%s in obj file failed\n",
					prognames[index]);
				goto cleanup;
			}

			link[index] = bpf_program__attach(prog);
			if (libbpf_get_error(link[index])) {
				fprintf(stderr, "ERROR: bpf_program__attach failed\n");
				link[index] = NULL;
				goto cleanup;
			}
		}
	}

	printf("preempt BPF started, hit Ctrl+C to stop!\n");

	read_trace_pipe();

cleanup:
	for (index = MAX_PROGS - 1; index >= 0; index--)
		bpf_link__destroy(link[index]);
	bpf_object__close(obj);

out:
	return 0;
}
