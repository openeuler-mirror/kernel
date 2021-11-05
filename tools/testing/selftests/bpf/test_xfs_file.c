// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"

#define SLEEP_SECS	9999999

int main(int argc, char *argv[])
{
	const char *file = "./test_set_xfs_file.o";
	struct bpf_object *obj;
	int efd, err, prog_fd;
	int delay = SLEEP_SECS;
	char *endptr, *str;

	if (argc == 2) {
		str = argv[1];
		delay = strtol(str, &endptr, 10);
	}

	err = bpf_prog_load(file, BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, &obj,
			&prog_fd);
	if (err) {
		printf("Failed to load xfs program\n");
		goto out;
	}

	efd = bpf_raw_tracepoint_open("xfs_file_read", prog_fd);
	if (efd < 0) {
		printf("Fail to open tracepoint, efd %d\n", efd);
		goto out;
	}

	sleep(delay);

	printf("END\n");

out:
	return err;
}
