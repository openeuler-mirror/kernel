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

#define READ_TP_NAME "fs_file_read"
#define RELEASE_TP_NAME "fs_file_release"

int main(int argc, char *argv[])
{
	const char *name = "./file_read_pattern_prog.bpf.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err = 0;
	int read_fd;
	int release_fd;

	obj = bpf_object__open_file(name, NULL);
	if (!obj) {
		err = -errno;
		printf("Failed to open program: %s\n", name);
		return err;
	}

	err = bpf_object__load(obj);
	if (err) {
		printf("failed to load program: %s\n", name);
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, READ_TP_NAME);
	if (!prog) {
		err = -errno;
		printf("no prog %s\n", READ_TP_NAME);
		goto out;
	}

	read_fd = bpf_raw_tracepoint_open(READ_TP_NAME, bpf_program__fd(prog));
	if (read_fd < 0) {
		err = read_fd;
		printf("Failed to attach raw tracepoint %s\n", READ_TP_NAME);
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, RELEASE_TP_NAME);
	if (!prog) {
		err = -errno;
		printf("no prog %s\n", RELEASE_TP_NAME);
		close(read_fd);
		goto out;
	}

	release_fd = bpf_raw_tracepoint_open(RELEASE_TP_NAME,
					     bpf_program__fd(prog));
	if (release_fd < 0) {
		err = release_fd;
		printf("Failed to attach raw tracepoint %s\n", RELEASE_TP_NAME);
		close(read_fd);
		goto out;
	}

	pause();

	close(release_fd);
	close(read_fd);
out:
	bpf_object__close(obj);
	return err;
}
