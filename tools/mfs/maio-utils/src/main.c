// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "loader.h"
#include "log.h"
#include "maio.h"
#include "policy.h"
#include "req_parser.h"
#include "fs_client.h"
#include "mfs.h"
#include "securec.h"

#include <sys/ioctl.h>
#include <sys/statfs.h>

#define MAX_BUF_SIZE 1024
#define MFS_SUPER_MAGIC 0x85428370

static int read_req(int fd)
{
	char *buf;
	int ret;

	buf = calloc(MAX_BUF_SIZE, sizeof(char));
	if (!buf) {
		log_error("failed to alloc buf\n");
		return -1;
	}
	ret = read(fd, buf, MAX_BUF_SIZE);
	if (ret <= 0) {
		if (ret < 0)
			log_error("failed to read, ret:%d\n", ret);
		return -1;
	}
	return maio_parse_req(buf, ret);
}

static void dev_monitor(int dfd)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = dfd;
	pfd.events = POLLIN;
	while (1) {
		ret = poll(&pfd, 1, -1);
		if (ret < 0) {
			log_error("poll failed\n");
			return;
		}
		if (ret == 0 || !(pfd.revents & POLLIN)) {
			log_error("poll events error, ret:%d, revents:%x\n", ret, pfd.revents);
			continue;
		}
		while (!read_req(pfd.fd)) {}
	}
}

int main(int argc, char *argv[])
{
	const char *mntpoint = NULL, *strategylib = NULL;
	struct mfs_ioc_fsinfo fsinfo = {0};
	int dfd, ret, opt;
	struct statfs buf;
	char devname[10];

	while ((opt = getopt(argc, argv, "m:s:")) != -1) {
		switch (opt) {
		case 'm':
			mntpoint = optarg;
			break;
		case 's':
			strategylib = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s -m ${mnt} [-s ${strategylib}]\n", argv[0]);
			return -EINVAL;
		}
	}
	if (!mntpoint) {
		fprintf(stderr, "mount point should specify\n");
		fprintf(stderr, "Usage: %s -m ${mnt} [-s ${strategylib}]\n", argv[0]);
		return -1;
	}

	ret = statfs(mntpoint, &buf);
	if (ret) {
		log_error("statfs %s failed, errstr:%s\n", mntpoint, strerror(errno));
		return -1;
	}
	if (buf.f_type != MFS_SUPER_MAGIC) {
		log_error("fstype(%x) is invalid, please check the mountpoint", buf.f_type);
		return -1;
	}

	sprintf_s(devname, sizeof(devname), "/dev/mfs%ld", buf.f_spare[0]);
	/* Open with O_CLOEXEC to avoid potential fd leaks */
	dfd = open(devname, O_RDWR | O_CLOEXEC);
	if (dfd < 0) {
		log_error("open %s failed errstr:%s\n", devname, strerror(errno));
		return -1;
	}

	ret = ioctl(dfd, MFS_IOC_FSINFO, (unsigned long)&fsinfo);
	if (ret < 0) {
		log_error("ioctl get fsinfo failed, ret:%d\n", ret);
		goto close_fd;
	}
	if (fsinfo.mode != 1) {
		log_error("fs runing mode(%d) is not supported", fsinfo.mode);
		goto close_fd;
	}
	ret = loader_init();
	if (ret) {
		log_error("loader init failed");
		goto close_fd;
	}
	ret = fs_client_init(NULL);
	if (ret) {
		log_error("clients init failed");
		goto free_loader;
	}
	ret = parser_init(fsinfo.mode, mntpoint);
	if (ret) {
		log_error("parser init failed");
		goto free_client;
	}
	ret = policy_init();
	if (ret) {
		log_error("policy init failed");
		goto free_parser;
	}
	ret = policy_register(strategylib);
	if (ret) {
		log_info("register new policy failed, use default policy");
	}

	dev_monitor(dfd);
free_parser:
	parser_destory();
free_client:
	fs_client_exit();
free_loader:
	loader_exit();
close_fd:
	close(dfd);
	return ret;
}
