// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Huawei Technologies Co., Ltd
 */

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "redis_acc.skel.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define CG_PATH		"/sys/fs/cgroup/tunned-acc"
#define PIN_PATH	"/sys/fs/bpf/redis/"

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

struct net_acc_prog_info {
	const char *prog_name;
	const char *pin_path;
	void **prog;
	int *fd;
};

struct net_acc_map_info {
	const char *map_name;
	char *pin_path;
	void **map;
	int *fd;
};

struct {
	int redis_sockops_fd;
	int redis_redir_fd;
	int redissock_map_fd;
} net_acc_fds;

struct {
	void *redis_sockops_obj;
	void *redis_redir_obj;
	void *redissock_map_obj;
} net_acc_obj;

static struct net_acc_prog_info prog_infos[] = {
	{
		.prog_name = "redis_sockops",
		.pin_path = PIN_PATH"sockops",
		.prog = &net_acc_obj.redis_sockops_obj,
		.fd = &net_acc_fds.redis_sockops_fd,
	},
	{
		.prog_name = "redis_redir",
		.pin_path = PIN_PATH"sk_msg",
		.prog = &net_acc_obj.redis_redir_obj,
		.fd = &net_acc_fds.redis_redir_fd,
	}
};

static struct net_acc_map_info map_infos[] = {
	{
		.map_name = "redissock_map",
		.pin_path = PIN_PATH"redissock_map",
		.map = &net_acc_obj.redissock_map_obj,
		.fd = &net_acc_fds.redissock_map_fd,
	}
};

int cg_fd = -1;
struct redissockmap *skel;

int net_acc_enabled(void)
{
	int map_fd;

	map_fd = bpf_obj_get(map_infos[0].pin_path);
	if (map_fd < 0)
		return 0;

	close(map_fd);
	return 1;
}

int pin_prog_map(void)
{
	int i, mapj, progj;
	int err = 0;

	mapj = ARRAY_SIZE(map_infos);
	for (i = 0; i < mapj; i++) {
		if (*map_infos[i].map)
			err = bpf_map__pin(*map_infos[i].map, map_infos[i].pin_path);
		if (err) {
			mapj = i;
			goto err1;
		}
	}

	progj =  ARRAY_SIZE(prog_infos);
	for (i = 0; i < progj; i++) {
		if (*prog_infos[i].prog)
			err = bpf_program__pin(*prog_infos[i].prog, prog_infos[i].pin_path);
		if (err) {
			progj = i;
			goto err2;
		}
	}
	return 0;
err2:
	for (i = 0; i < progj; i++) {
		if (*prog_infos[i].prog)
			bpf_program__unpin(*prog_infos[i].prog, prog_infos[i].pin_path);
	}
err1:
	for (i = 0; i < mapj; i++) {
		if (*map_infos[i].map)
			bpf_map__unpin(*map_infos[i].map, map_infos[i].pin_path);
	}
	return 1;
}

int attach_manually(void)
{
	int err;

	err = bpf_prog_attach(bpf_program__fd(skel->progs.redis_sockops), cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		fprintf(stderr, "failed to attach sockops programs\n");
		return -1;
	}

	err = bpf_prog_attach(bpf_program__fd(skel->progs.redis_redir),
			      bpf_map__fd(skel->maps.redissock_map), BPF_SK_MSG_VERDICT, 0);
	if (err) {
		fprintf(stderr, "failed to attach msg_verdict programs\n");
		goto cleanup1;
	}

	net_acc_obj.redis_sockops_obj = skel->progs.redis_sockops;
	net_acc_obj.redis_redir_obj = skel->progs.redis_redir;
	net_acc_obj.redissock_map_obj = skel->maps.redissock_map;
	return 0;
cleanup1:
	bpf_prog_detach2(bpf_program__fd(skel->progs.redis_sockops), cg_fd, BPF_CGROUP_SOCK_OPS);
	return -1;
}

void detach_manually(void)
{
	bpf_prog_detach2(bpf_program__fd(skel->progs.redis_redir),
			      bpf_map__fd(skel->maps.redissock_map), BPF_SK_MSG_VERDICT);
	bpf_prog_detach2(bpf_program__fd(skel->progs.redis_sockops), cg_fd, BPF_CGROUP_SOCK_OPS);
}

int net_acc_enable(void)
{
	int err;

	if (net_acc_enabled())
		return 0;

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d", err);
		close(cg_fd);
		return 1;
	}

	skel = redissockmap__open();
	if (!skel) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = redissockmap__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = redissockmap__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	err = attach_manually();
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	err = pin_prog_map();
	if (err) {
		fprintf(stderr, "failed to pin BPF programs and maps\n");
		goto cleanup1;
	}

	return 0;

cleanup1:
	detach_manually();
cleanup:
	redissockmap__destroy(skel);
	close(cg_fd);

	return err != 0;
}


int net_acc_disable(void)
{
	int i;

	if (!net_acc_enabled())
		return 0;

	for (i = 0; i < ARRAY_SIZE(map_infos); i++) {
		if (map_infos[i].fd) {
			*map_infos[i].fd = bpf_obj_get(map_infos[i].pin_path);
			unlink(map_infos[i].pin_path);
		}
	}

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		if (prog_infos[i].fd) {
			*prog_infos[i].fd = bpf_obj_get(prog_infos[i].pin_path);
			unlink(prog_infos[i].pin_path);
		}
	}

	bpf_prog_detach2(net_acc_fds.redis_redir_fd,
			net_acc_fds.redissock_map_fd, BPF_SK_MSG_VERDICT);
	bpf_prog_detach2(net_acc_fds.redis_sockops_fd, cg_fd, BPF_CGROUP_SOCK_OPS);

	close(net_acc_fds.redis_redir_fd);
	close(net_acc_fds.redis_redir_fd);
	close(net_acc_fds.redis_redir_fd);
	rmdir(PIN_PATH);
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;

	if (argc != 2)
		return 1;

	cg_fd = open(CG_PATH, O_DIRECTORY, O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "ERROR: (%i) open cgroup2 path failed: %s\n", cg_fd, CG_PATH);
		return 1;
	}

	if (strncmp(argv[1], "enable", 6) == 0)
		ret = net_acc_enable();
	else if (strncmp(argv[1], "disable", 7) == 0)
		ret = net_acc_disable();

	close(cg_fd);
	return ret;
}
