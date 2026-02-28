// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: End-to-End HiSock Redirect sample.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEF_BPF_PATH	"bpf.o"
#define PORT_LOCAL	1
#define PORT_REMOTE	2
#define MAX_IF_NUM	8

struct {
	__u32 ifindex[MAX_IF_NUM];
	int if_num;
	char *local_port;
	char *remote_port;
	char *cgrp_path;
	char *bpf_path;
	bool unload;
	bool help;
} hisock;

struct hisock_prog_info {
	const char *sec_name;
	enum bpf_prog_type prog_type;
	enum bpf_attach_type attach_type;
	bool is_dev_attach;
	int prog_fd;
};

static struct hisock_prog_info prog_infos[] = {
	{
		.sec_name	= "hisock_sockops",
		.prog_type	= BPF_PROG_TYPE_SOCK_OPS,
		.attach_type	= BPF_CGROUP_SOCK_OPS,
	},
	{
		.sec_name	= "hisock_ingress",
		.prog_type	= BPF_PROG_TYPE_HISOCK,
		.attach_type	= BPF_HISOCK_INGRESS,
		.is_dev_attach	= true,
	},
	{
		.sec_name	= "hisock_egress",
		.prog_type	= BPF_PROG_TYPE_HISOCK,
		.attach_type	= BPF_HISOCK_EGRESS,
	},
};

static int set_prog_type(struct bpf_object *obj)
{
	enum bpf_attach_type attach_type;
	enum bpf_prog_type prog_type;
	struct bpf_program *prog;
	const char *sec_name;
	int i;

	bpf_object__for_each_program(prog, obj) {
		sec_name = bpf_program__section_name(prog);
		for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
			if (!strcmp(prog_infos[i].sec_name, sec_name)) {
				prog_type = prog_infos[i].prog_type;
				attach_type = prog_infos[i].attach_type;
				break;
			}
		}

		if (i == ARRAY_SIZE(prog_infos))
			return -1;

		bpf_program__set_type(prog, prog_type);
		bpf_program__set_expected_attach_type(prog, attach_type);
	}

	return 0;
}

static int find_progs(struct bpf_object *obj)
{
	struct hisock_prog_info *info;
	struct bpf_program *prog;
	int i, prog_fd;

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		info = &prog_infos[i];
		prog = bpf_object__find_program_by_title(obj, info->sec_name);
		if (!prog) {
			fprintf(stderr, "ERROR: failed to find prog sec %s\n", info->sec_name);
			return -1;
		}

		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			fprintf(stderr, "ERROR: failed to get fd of prog %s\n", info->sec_name);
			return -1;
		}

		info->prog_fd = prog_fd;
	}

	return 0;
}

static int parse_port_range(const char *port_str, __u8 status, int map_fd)
{
	char *str = strdup(port_str);
	char *token, *rest = str;
	__u16 port;

	while ((token = strtok_r(rest, ",", &rest))) {
		char *dash = strchr(token, '-');

		if (dash) {
			*dash = '\0';
			__u16 start = atoi(token);
			__u16 end = atoi(dash + 1);

			if (start > end || start == 0 || end > 65535) {
				fprintf(stderr, "Invalid port range: %s\n", token);
				return -1;
			}

			for (port = start; port <= end; port++)
				bpf_map_update_elem(map_fd, &port, &status, BPF_ANY);

			printf("Speed port range %u-%u:%u\n", start, end, status);
		} else {
			port = atoi(token);
			if (port == 0 || port > 65535) {
				fprintf(stderr, "Invalid port: %s\n", token);
				return -1;
			}
			bpf_map_update_elem(map_fd, &port, &status, BPF_ANY);
			printf("Speed port %u:%u\n", port, status);
		}
	}

	free(str);
	return 0;
}

static int set_speed_port(struct bpf_object *obj)
{
	int map_fd;

	map_fd = bpf_object__find_map_fd_by_name(obj, "speed_port");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: failed to find map fd\n");
		return -1;
	}

	if (hisock.local_port &&
	    parse_port_range(hisock.local_port, PORT_LOCAL, map_fd)) {
		fprintf(stderr, "ERROR: failed to update local port\n");
		return -1;
	}

	if (hisock.remote_port &&
	    parse_port_range(hisock.remote_port, PORT_REMOTE, map_fd)) {
		fprintf(stderr, "ERROR: failed to update remote port\n");
		return -1;
	}

	return 0;
}

static int detach_progs(void)
{
	struct hisock_prog_info *info;
	int i, j, cgrp_fd;
	int err_cnt = 0;

	cgrp_fd = open(hisock.cgrp_path, O_DIRECTORY, O_RDONLY);
	if (cgrp_fd < 0) {
		fprintf(stderr, "ERROR: failed to open cgrp %s\n", hisock.cgrp_path);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		info = &prog_infos[i];
		if (info->is_dev_attach) {
			for (j = 0; j < hisock.if_num; j++) {
				if (bpf_prog_detach(hisock.ifindex[j], info->attach_type)) {
					fprintf(stderr,
						"ERROR: failed to detach prog %s\n",
						info->sec_name);
					err_cnt++;
				}
			}
			continue;
		}

		if (bpf_prog_detach(cgrp_fd, info->attach_type)) {
			fprintf(stderr, "ERROR: failed to detach prog %s\n", info->sec_name);
			err_cnt++;
		}
	}

	close(cgrp_fd);
	return -err_cnt;
}

static int attach_progs(void)
{
	struct hisock_prog_info *info;
	int i, j, cgrp_fd;

	cgrp_fd = open(hisock.cgrp_path, O_DIRECTORY, O_RDONLY);
	if (cgrp_fd < 0) {
		fprintf(stderr, "ERROR: failed to open cgrp %s\n", hisock.cgrp_path);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		info = &prog_infos[i];
		if (info->is_dev_attach) {
			for (j = 0; j < hisock.if_num; j++) {
				if (bpf_prog_attach(info->prog_fd, hisock.ifindex[j],
						    info->attach_type, 0))
					goto fail;
			}
			continue;
		}

		if (bpf_prog_attach(info->prog_fd, cgrp_fd, info->attach_type, 0))
			goto fail;
	}

	close(cgrp_fd);
	return 0;
fail:
	fprintf(stderr, "ERROR: failed to attach prog %s\n", info->sec_name);
	close(cgrp_fd);
	detach_progs();
	return -1;
}

static int do_hisock(void)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_object *obj;

	setrlimit(RLIMIT_MEMLOCK, &r);

	obj = bpf_object__open(hisock.bpf_path);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: failed to open bpf file\n");
		return -1;
	}

	if (set_prog_type(obj)) {
		fprintf(stderr, "ERROR: failed to set prog type\n");
		bpf_object__close(obj);
		return -1;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: failed to load bpf obj\n");
		bpf_object__close(obj);
		return -1;
	}

	if (find_progs(obj)) {
		fprintf(stderr, "ERROR: failed to find progs\n");
		bpf_object__close(obj);
		return -1;
	}

	if (set_speed_port(obj)) {
		fprintf(stderr, "ERROR: failed to set speed port\n");
		bpf_object__close(obj);
		return -1;
	}

	if (attach_progs()) {
		fprintf(stderr, "ERROR: failed to attach progs\n");
		bpf_object__close(obj);
		return -1;
	}

	bpf_object__close(obj);
	return 0;
}

static void do_help(void)
{
	fprintf(stderr,
		"Load:   hisock_cmd [-f BPF_FILE] [-c CGRP_PATH] "
		"[-p LOCAL_PORT] [-r REMOTE_PORT] [-i INTERFACE]\n"
		"Unload: hisock_cmd -u [-c CGRP_PATH] [-i INTERFACE]\n");
}

static int parse_args(int argc, char **argv)
{
	char *ifname;
	int opt;

	hisock.bpf_path = DEF_BPF_PATH;
	hisock.if_num = 0;

	while ((opt = getopt(argc, argv, "f:c:p:r:i:uh")) != -1) {
		switch (opt) {
		case 'f':
			hisock.bpf_path = optarg;
			break;
		case 'c':
			hisock.cgrp_path = optarg;
			break;
		case 'p':
			hisock.local_port = optarg;
			break;
		case 'r':
			hisock.remote_port = optarg;
			break;
		case 'i':
			ifname = optarg;
			hisock.ifindex[hisock.if_num] = if_nametoindex(ifname);
			hisock.if_num++;
			break;
		case 'u':
			hisock.unload = true;
			break;
		case 'h':
			hisock.help = true;
			break;
		default:
			fprintf(stderr, "ERROR: unknown option %c\n", opt);
			return -1;
		}
	}

	if (hisock.cgrp_path == NULL ||
	    hisock.if_num == 0 ||
	    (!hisock.unload &&
	     hisock.local_port == NULL &&
	     hisock.remote_port == NULL)) {
		do_help();
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv)) {
		fprintf(stderr, "ERROR: failed to parse args\n");
		return -1;
	}

	if (hisock.help) {
		do_help();
		return 0;
	}

	if (hisock.unload) {
		if (detach_progs()) {
			fprintf(stderr, "ERROR: failed to detach progs\n");
			return -1;
		}

		printf("Unload HiSock successfully\n");
		return 0;
	}

	if (do_hisock()) {
		fprintf(stderr, "ERROR: failed to do hisock\n");
		return -1;
	}

	printf("Load HiSock successfully\n");
	return 0;
}
