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
 *
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

static void usage(void)
{
	printf("USAGE: test sched select core [...]\n");
	printf("	   -W wakeup affine   # Test sched wake wakeup\n");
	printf("	   -C select core     # Test sched select core\n");
	printf("	   -R select core range  # Test sched select core range\n");
	printf("	   -h		   # Display this help\n");
}

#define TRACE_DIR	"/sys/kernel/debug/tracing/"
#define BUF_SIZE	(4096)

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

int main(int argc, char **argv)
{
	int opt;
	char filename[256];
	char progname[4][256];
	struct bpf_object *obj;
	struct bpf_program *prog[4] = {NULL};
	struct bpf_link *link[4] = {NULL};
	int prog_num = 1;
	int i = 0;

	while ((opt = getopt(argc, argv, "C::R::W::E::")) != -1) {
		switch (opt) {
		case 'C':
			snprintf(progname[0], sizeof(progname[0]), "cfs_select_cpu");
			break;
		case 'R':
			snprintf(progname[0], sizeof(progname[0]), "cfs_select_cpu_range");
			snprintf(progname[1], sizeof(progname[1]), "cfs_select_cpu_range_exit");
			prog_num = 2;
			break;
		case 'W':
			snprintf(progname[0], sizeof(progname[0]), "cfs_wake_affine");
			break;
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

	for (i = 0; i < prog_num; i++) {
		prog[i] = bpf_object__find_program_by_name(obj, progname[i]);
		if (libbpf_get_error(prog[i])) {
			fprintf(stderr, "ERROR: finding a prog %d in obj file failed\n", i);
			goto cleanup;
		}

		link[i] = bpf_program__attach(prog[i]);
		if (libbpf_get_error(link[i])) {
			fprintf(stderr, "ERROR: bpf_program__attach %d failed\n", i);
			link[i] = NULL;
			goto cleanup;
		}
	}

	printf("select rq BPF started, hit Ctrl+C to stop!\n");

	read_trace_pipe();

cleanup:
	for (; i >= 0; i--)
		bpf_link__destroy(link[i]);
	bpf_object__close(obj);
out:
	return 0;
}
