// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <linux/if_link.h>

#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

#define DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define DEFAULT_REDIS_PORT  6379

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define IFINDEX_NUM 8

struct {
	char *cgroup_path;
	char *bpf_path;
	int cgroup_fd;
	int map_ports_fd;
	int map_storage_fd;
	int map_interface_fd;
	int map_stats_fd;
	int redis_xdp_main_prog_fd;
	uint16_t listen_port;
	unsigned int ifindex;
} bmc;

struct bmc_prog_info {
	const char *sec_name;
	enum bpf_prog_type prog_type;
	enum bpf_attach_type attach_type;
	int *p_prog_fd;
	int *p_attach_fd;
	unsigned int attach_flags;
	unsigned int is_xdp_main;
	const char *pin_path;
	struct bpf_program *prog;
};

struct bmc_map_info {
	const char *map_name;
	int *p_map_fd;
	char *pin_path;
	struct bpf_map *map;
	bool is_stat_map;
	bool is_interface_map;
};

static struct bmc_prog_info prog_infos[] = {
	{
		.sec_name = "bmc/main",
		.prog_type = BPF_PROG_TYPE_XDP,
		.p_prog_fd = &bmc.redis_xdp_main_prog_fd,
		.attach_flags = XDP_FLAGS_DRV_MODE, // XDP_FLAGS_SKB_MODE
		.is_xdp_main = 1,
		.pin_path = "/sys/fs/bpf/bmc/prog_xdp_main"
	}
};

static struct bmc_map_info map_infos[] = {
	{
		.map_name = "bmc_ports",
		.p_map_fd = &bmc.map_ports_fd,
		.pin_path = "/sys/fs/bpf/bmc/map_ports"
	},
	{
		.map_name = "bmc_storage",
		.p_map_fd = &bmc.map_storage_fd,
		.pin_path = "/sys/fs/bpf/bmc/map_storage"
	},
	{
		.map_name = "bmc_interface",
		.p_map_fd = &bmc.map_interface_fd,
		.pin_path = "/sys/fs/bpf/bmc/interface",
		.is_interface_map = true,
	},
	{
		.map_name = "bmc_stats",
		.p_map_fd = &bmc.map_stats_fd,
		.pin_path = "/sys/fs/bpf/bmc/stats",
		.is_stat_map = true,
	},
};

static int find_type_by_sec_name(const char *sec_name,
				 enum bpf_prog_type *p_prog_type,
				 enum bpf_attach_type *p_attach_type)
{
	int i;

	if (sec_name == NULL) {
		fprintf(stderr, "sec_name is NULL\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		if (!strcmp(prog_infos[i].sec_name, sec_name)) {
			*p_prog_type = prog_infos[i].prog_type;
			*p_attach_type = prog_infos[i].attach_type;
			return 0;
		}
	}

	fprintf(stderr, "unknown prog %s\n", sec_name);

	return -1;
}

static int set_prog_type(struct bpf_object *obj)
{
	const char *sec_name;
	struct bpf_program *prog;
	enum bpf_prog_type prog_type;
	enum bpf_attach_type attach_type;

	bpf_object__for_each_program(prog, obj) {
		sec_name = bpf_program__section_name(prog);
		if (find_type_by_sec_name(sec_name, &prog_type, &attach_type))
			return -1;
		bpf_program__set_type(prog, prog_type);
		if (prog_type != BPF_PROG_TYPE_XDP)
			bpf_program__set_expected_attach_type(prog, attach_type);
	}

	return 0;
}

static struct bpf_object *load_bpf_file(const char *bpf_file)
{
	int err;
	char err_buf[256];
	struct bpf_object *obj;

	obj = bpf_object__open(bpf_file);
	err = libbpf_get_error(obj);
	if (err) {
		libbpf_strerror(err, err_buf, sizeof(err_buf));
		fprintf(stderr, "unable to open bpf file %s : %s\n", bpf_file,
			err_buf);
		return NULL;
	}

	if (set_prog_type(obj)) {
		bpf_object__close(obj);
		return NULL;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load bpf object failed\n");
		bpf_object__close(obj);
		return NULL;
	}

	return obj;
}

static int find_prog(struct bpf_object *obj, const char *sec_name,
		     struct bpf_program **p_prog, int *p_prog_fd)
{
	int fd;
	struct bpf_program *prog;

	prog = bpf_object__find_program_by_title(obj, sec_name);
	if (!prog) {
		fprintf(stderr, "failed to find prog %s\n", sec_name);
		return -1;
	}

	fd = bpf_program__fd(prog);
	if (fd < 0) {
		fprintf(stderr, "failed to get fd of prog %s\n", sec_name);
		return -1;
	}

	*p_prog = prog;
	*p_prog_fd = fd;

	return 0;
}

static void unpin_progs(int n)
{
	int i;

	for (i = 0; i < n; i++)
		bpf_program__unpin(prog_infos[i].prog, prog_infos[i].pin_path);
}

static int find_progs(struct bpf_object *obj)
{
	int i;
	struct bmc_prog_info *info;

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		info = &prog_infos[i];

		if (find_prog(obj, info->sec_name, &info->prog, info->p_prog_fd))
			goto error_find_prog;

		if (bpf_program__pin(info->prog, info->pin_path))
			goto error_find_prog;
	}

	return 0;

error_find_prog:
	unpin_progs(i);
	return -1;
}

static int find_map(struct bpf_object *obj, const char *map_name,
		    struct bpf_map **p_map, int *p_map_fd)
{
	int fd;
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		fprintf(stderr, "failed to find map %s\n", map_name);
		return -1;
	}

	fd = bpf_map__fd(map);
	if (fd < 0) {
		fprintf(stderr, "failed to get fd of map %s\n", map_name);
		return -1;
	}


	*p_map = map;
	*p_map_fd = fd;

	return 0;
}

static void unpin_maps(int n)
{
	int i;

	for (i = 0; i < n; i++)
		bpf_map__unpin(map_infos[i].map, map_infos[i].pin_path);
}

static int find_maps(struct bpf_object *obj)
{
	int i;
	__u32 key;
	__u32 value;
	int fd;
	struct bmc_map_info *info;

	for (i = 0; i < ARRAY_SIZE(map_infos); i++) {
		info = &map_infos[i];

		if (find_map(obj, info->map_name, &info->map, info->p_map_fd))
			goto error_find_map;

		if (bpf_map__pin(info->map, info->pin_path)) {
			fprintf(stderr, "failed to pin map %s to path %s\n",
				info->map_name, info->pin_path);
			goto error_find_map;
		}

		if (info->is_interface_map) {
			key = 0;
			value = bmc.ifindex;
			fd = bpf_map__fd(info->map);
			bpf_map_update_elem(fd, &key, &value, 0);
		}
	}

	return 0;

error_find_map:
	unpin_maps(i);
	return -1;
}

static void detach_xdp_progs(unsigned int ifindex, __u32 flags)
{
	bpf_set_link_xdp_fd(ifindex, -1, flags);
}

static void detach_progs(int n)
{
	int i;
	struct bmc_prog_info *info;

	for (i = 0; i < n; i++) {
		info = &prog_infos[i];
		if (info->is_xdp_main)
			detach_xdp_progs(bmc.ifindex, info->attach_flags);
		else if (info->prog_type != BPF_PROG_TYPE_XDP)
			bpf_prog_detach(*info->p_prog_fd, info->attach_type);
	}
}

static int attach_xdp_prog(int prog_fd, __u32 flags)
{
	if (bmc.ifindex) {
		if (bpf_set_link_xdp_fd(bmc.ifindex, prog_fd, flags)) {
			fprintf(stderr, "failed to attach xdp prog\n");
			return  -1;
		}
	}
	return 0;
}

static int attach_progs(struct bpf_object *obj)
{
	int i;
	int err;
	int prog_fd;
	int attach_fd;
	unsigned int flags;
	enum bpf_attach_type type;
	struct bmc_prog_info *info;

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		info = &prog_infos[i];
		prog_fd = *info->p_prog_fd;
		flags = info->attach_flags;

		if (info->is_xdp_main)
			err = attach_xdp_prog(prog_fd, flags);
		else if (info->prog_type != BPF_PROG_TYPE_XDP &&
			 info->p_attach_fd != NULL) {
			attach_fd = *info->p_attach_fd;
			type = info->attach_type;
			err = bpf_prog_attach(prog_fd, attach_fd, type, flags);
		} else
			continue;

		if (err) {
			fprintf(stderr, "attach prog %s failed!\n",
				info->sec_name);
			goto error_attach_prog;
		}
	}

	return 0;

error_attach_prog:
	detach_progs(i);

	return -1;
}

static int add_bmc_port(void)
{
	int ret;
	int map_fd = bmc.map_ports_fd;
	uint16_t port = htons(bmc.listen_port);
	uint32_t key = (uint32_t)port;
	uint32_t value = 1;

	ret = bpf_map_update_elem(map_fd, &key, &value, 0);
	if (ret)
		fprintf(stderr, "failed to add port %u\n", port);

	return ret;
}

static int setup_bpf(void)
{
	struct bpf_object *obj;

	bmc.cgroup_fd = open(bmc.cgroup_path, O_DIRECTORY, O_RDONLY);
	if (bmc.cgroup_fd < 0) {
		fprintf(stderr, "failed to open cgroup %s: %s\n",
			bmc.cgroup_path, strerror(errno));
		return -1;
	}

	obj = load_bpf_file(bmc.bpf_path);
	if (!obj)
		goto error_load_object;

	if (find_progs(obj))
		goto error_load_object;

	if (find_maps(obj))
		goto error_find_maps;

	if (attach_progs(obj))
		goto error_attach_progs;

	if (add_bmc_port())
		goto error_add_port;

	return 0;

error_add_port:
	detach_progs(ARRAY_SIZE(prog_infos));
error_attach_progs:
	unpin_maps(ARRAY_SIZE(map_infos));
error_find_maps:
	unpin_progs(ARRAY_SIZE(prog_infos));
error_load_object:
	bpf_object__close(obj);
	close(bmc.cgroup_fd);
	return -1;
}

static int parse_load_args(int argc, char *argv[])
{
	int opt;
	int port;
	const char *ifname = NULL;

	bmc.cgroup_path = DEFAULT_CGROUP_PATH;
	bmc.listen_port = DEFAULT_REDIS_PORT;
	bmc.ifindex = 0;

	while ((opt = getopt(argc, argv, "c:p:i:")) != -1) {
		switch (opt) {
		case 'c':
			bmc.cgroup_path = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			if (port <= 0 || port >= USHRT_MAX) {
				fprintf(stderr, "invalid port: %s\n", optarg);
				return -1;
			}
			bmc.listen_port = port;
			break;
		case 'i':
			printf("interface: %s\n", optarg);
			ifname = optarg;
			bmc.ifindex = if_nametoindex(ifname);
			break;
		default:
			fprintf(stderr, "unknown option %c\n", opt);
			return -1;
		}
	}

	if (!bmc.ifindex) {
		fprintf(stderr, "no netwrok interface found\n");
		return -1;
	}

	if (optind >= argc) {
		fprintf(stderr, "no bpf prog file found\n");
		return -1;
	}

	bmc.bpf_path = argv[optind];

	printf("bpf file: %s\n", bmc.bpf_path);
	printf("cgroup path: %s\n", bmc.cgroup_path);
	printf("listen port: %d\n", bmc.listen_port);
	printf("interface: %s\n", ifname);

	return 0;
}

struct cmd {
	const char *name;
	int (*func)(int argc, char *argv[]);
};

static int do_prog(int argc, char *argv[]);
static int do_stat(int argc, char *argv[]);

static int do_prog_load(int argc, char *argv[]);
static int do_prog_unload(int argc, char *argv[]);

static struct cmd main_cmds[] = {
	{ "prog", do_prog },
	{ "stat", do_stat },
};

static struct cmd prog_cmds[] = {
	{ "load", do_prog_load },
	{ "unload", do_prog_unload },
};

static char *elf_name;

static int dispatch_cmd(struct cmd cmds[], int ncmd, int argc,
			char *argv[], void (*help)(void))
{
	int i;
	int ret;

	if (argc <= 0) {
		help();
		return -1;
	}

	for (i = 0; i < ncmd; i++) {
		if (!strcmp(argv[0], cmds[i].name)) {
			ret = cmds[i].func(argc - 1, argv + 1);
			if (ret == -2) {
				help();
				ret = -1;
			}
			return ret;
		}
	}

	help();

	return -1;
}

static int do_prog_load(int argc, char *argv[])
{
	if (parse_load_args(argc + 1, argv - 1) < 0)
		return -2;

	if (setup_bpf())
		return -1;

	return 0;
}

static int do_prog_unload(int argc, char *argv[])
{
	int i;
	int err;
	int prog_fd;
	int cgroup_fd;
	int map_fd;
	char *interface_map_path = NULL;
	char *cgroup_path = DEFAULT_CGROUP_PATH;
	__u32 ifindex;
	__u32 key;

	if (argc > 1)
		cgroup_path = argv[0];

	cgroup_fd = open(cgroup_path, O_DIRECTORY, O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "failed to open cgroup path: %s\n",
			cgroup_path);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(map_infos); i++) {
		if (map_infos[i].is_interface_map) {
			interface_map_path = map_infos[i].pin_path;
			break;
		}
	}

	if (!interface_map_path) {
		fprintf(stderr, "no interface map found\n");
		return -1;
	}

	map_fd = bpf_obj_get(interface_map_path);
	if (map_fd < 0) {
		fprintf(stderr, "failed to get map from %s\n",
			interface_map_path);
		return -1;
	}

	key = 0;
	err = bpf_map_lookup_elem(map_fd, &key, &ifindex);
	close(map_fd);
	if (err) {
		fprintf(stderr, "lookup interface failed\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(prog_infos); i++) {
		if (prog_infos[i].attach_type == BPF_CGROUP_SOCK_OPS) {
			prog_fd = bpf_obj_get(prog_infos[i].pin_path);
			if (prog_fd >= 0)
				bpf_prog_detach2(prog_fd, cgroup_fd,
						BPF_CGROUP_SOCK_OPS);
		}

		if (prog_infos[i].is_xdp_main)
			detach_xdp_progs(ifindex, prog_infos[i].attach_flags);

		unlink(prog_infos[i].pin_path);
	}

	for (i = 0; i < ARRAY_SIZE(map_infos); i++)
		unlink(map_infos[i].pin_path);

	return 0;
}

static void do_prog_help(void)
{
	fprintf(stderr,
		"Usage: %s prog load [-c CGROUP_PATH] [-p LISTEN_PORT]"
		" {-i INTERFACE} {BPF_FILE}\n"
		"       %s prog unload [CGROUP_PATH]\n",
		elf_name, elf_name);
}

static int do_prog(int argc, char *argv[])
{
	return dispatch_cmd(prog_cmds, ARRAY_SIZE(prog_cmds),
			    argc, argv, do_prog_help);
}

static int do_stat(int argc, char *argv[])
{
	int i;
	int fd;
	int err;
	int ncpu;
	bool found = false;
	struct bmc_map_info *info;
	struct bpf_map_info map = {};
	struct redis_bmc_stat *percpu_stat;
	struct redis_bmc_stat stat = {};
	__u32 len = sizeof(map);
	__u32 key;

	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 0) {
		fprintf(stderr, "sysconf failed: %s\n", strerror(errno));
		return -1;
	}

	percpu_stat = malloc(sizeof(struct redis_bmc_stat) * ncpu);
	if (!percpu_stat) {
		fprintf(stderr, "malloc percpu stat failed\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(map_infos); i++) {
		info = &map_infos[i];
		if (info->is_stat_map) {
			found = true;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "no stats map found\n");
		free(percpu_stat);
		return -1;
	}

	fd = bpf_obj_get(info->pin_path);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s\n",
			info->pin_path);
		free(percpu_stat);
		return -1;
	}

	err = bpf_obj_get_info_by_fd(fd, &map, &len);
	if (err) {
		fprintf(stderr, "failed to get map info\n");
		err = -1;
		goto out;
	}

	if (map.type != BPF_MAP_TYPE_PERCPU_ARRAY) {
		fprintf(stderr, "unexpected map type: %d\n", map.type);
		err = -1;
		goto out;
	}

	if (map.key_size != sizeof(__u32)) {
		fprintf(stderr, "unexpected map key_size: %u\n", map.key_size);
		err = -1;
		goto out;
	}

	if (map.value_size != sizeof(struct redis_bmc_stat)) {
		fprintf(stderr, "unexpected map key_size: %u\n", map.key_size);
		err = -1;
		goto out;
	}

	key = 0;
	err = bpf_map_lookup_elem(fd, &key, percpu_stat);
	if (err) {
		fprintf(stderr, "lookup cpu stat failed, cpu=%u\n", i);
		err = -1;
		goto out;
	}

	for (int i = 0; i < ncpu; i++) {
		stat.total_get_requests += percpu_stat[i].total_get_requests;
		stat.hit_get_requests += percpu_stat[i].hit_get_requests;
		stat.drop_get_requests += percpu_stat[i].drop_get_requests;
		stat.total_set_requests += percpu_stat[i].total_set_requests;
		stat.hit_set_requests += percpu_stat[i].hit_set_requests;
		stat.drop_set_requests += percpu_stat[i].drop_set_requests;
	}

	printf("Total GET Requests: %llu\n", stat.total_get_requests);
	printf("Hit GET Requests: %llu (%.2f%%)\n", stat.hit_get_requests,
		stat.total_get_requests == 0 ? 0 :
		(double)stat.hit_get_requests /
		(double)stat.total_get_requests *
		100);
	printf("Dropped GET Requests: %llu (%.2lf%%)\n", stat.drop_get_requests,
		stat.total_get_requests == 0 ? 0 :
		(double)stat.drop_get_requests /
		(double)stat.total_get_requests *
		100);

	printf("Total SET Requests: %llu\n", stat.total_set_requests);
	printf("Hit SET Requests: %llu (%.2f%%)\n", stat.hit_set_requests,
		stat.total_set_requests == 0 ? 0 :
		(double)stat.hit_set_requests /
		(double)stat.total_set_requests *
		100);
	printf("Dropped SET Requests: %llu (%.2lf%%)\n", stat.drop_set_requests,
		stat.total_set_requests == 0 ? 0 :
		(double)stat.drop_set_requests /
		(double)stat.total_set_requests *
		100);

out:
	close(fd);
	free(percpu_stat);

	return err;
}

static void do_main_help(void)
{
	fprintf(stderr,
		"Usage: %s OBJECT { COMMAND | help }\n"
		"       OBJECT := { prog | stat }\n",
		elf_name);
}

int main(int argc, char *argv[])
{
	elf_name = argv[0];

	return dispatch_cmd(main_cmds, ARRAY_SIZE(main_cmds),
			    argc - 1, argv + 1, do_main_help);
}
