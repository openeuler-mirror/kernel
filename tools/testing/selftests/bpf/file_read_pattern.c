// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"

#define READ_TP_NAME "fs_file_read"
#define RELEASE_TP_NAME "fs_file_release"

int main(int argc, char *argv[])
{
	const char *name = "./file_read_pattern_prog.o";
	struct bpf_object *obj;
	const char *prog_name;
	struct bpf_program *prog;
	int unused;
	int err;
	int read_fd;
	int release_fd;

	err = bpf_prog_load(name, BPF_PROG_TYPE_UNSPEC, &obj, &unused);
	if (err) {
		printf("Failed to load program\n");
		return err;
	}

	prog_name = "raw_tracepoint.w/" READ_TP_NAME;
	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (!prog) {
		printf("no prog %s\n", prog_name);
		err = -EINVAL;
		goto out;
	}

	read_fd = bpf_raw_tracepoint_open(READ_TP_NAME, bpf_program__fd(prog));
	if (read_fd < 0) {
		err = -errno;
		printf("Failed to attach raw tracepoint %s\n", READ_TP_NAME);
		goto out;
	}

	prog_name = "raw_tracepoint/" RELEASE_TP_NAME;
	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (!prog) {
		printf("no prog %s\n", prog_name);
		err = -EINVAL;
		goto out;
	}

	release_fd = bpf_raw_tracepoint_open(RELEASE_TP_NAME,
					     bpf_program__fd(prog));
	if (release_fd < 0) {
		err = -errno;
		printf("Failed to attach raw tracepoint %s\n", RELEASE_TP_NAME);
		goto out;
	}

	pause();

	close(release_fd);
	close(read_fd);
out:
	bpf_object__close(obj);
	return err;
}
