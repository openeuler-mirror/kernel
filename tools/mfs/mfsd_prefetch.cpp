// SPDX-License-Identifier: GPL-2.0
/*
 * User-space demo of mfs
 *
 * Example use:
 * ./mfsd [mfs_mountpoint]
 * mfsd.c demostrates how to poll mfs device, read the events,
 * parse the events, process the events according to user mode
 * and trigger the ioctls mfs supported.
 *
 * See Documentation/filesystems/mfs.rst
 */

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <poll.h>
#include <string.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>

#include <map>
#include <string>

#include "../../include/uapi/linux/mfs.h"
#include "../../include/uapi/linux/magic.h"

using namespace std;

#define pr_err(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

static int mfs_mode = -1;
static map<string, uint64_t> files;

struct thread_ctx {
	char *path;
	uint64_t off;
	uint64_t len;
};

static int get_files(const char *parent)
{
	DIR *dir;
	struct dirent *entry;
	string filepath;
	struct stat buf;

	if ((dir = opendir(parent)) == NULL) {
		perror("opening directory failed");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		filepath = string(parent) + "/" + string(entry->d_name);
		if (stat(filepath.c_str(), &buf) == -1) {
			pr_err("stat path:%s failed\n", filepath.c_str());
			continue;
		}
		if (S_ISDIR(buf.st_mode))
			continue;
		files.insert(pair<string, uint64_t>(filepath, buf.st_size));
	}

	return 0;
}

static void *fault(void *arg)
{
	struct thread_ctx *ctx = (struct thread_ctx *)arg;
	int fd = open(ctx->path, O_RDONLY);
	if (fd < 0) {
		pr_err("open file:%s failed\n", ctx->path);
		free(ctx);
		return NULL;
	}

	void *addr = mmap(NULL, ctx->len, PROT_READ, MAP_SHARED, fd, 0);
	uint64_t idx;
	char tmp, total, *buffer = (char *)addr;
	total = 'B';
	for (idx = 0; idx < ctx->len; idx += 4096) {
		tmp = buffer[idx];
		total += tmp;
	}
	munmap(addr, ctx->len);
	close(fd);
	free(ctx);
	return NULL;
}

static int process_local_read(struct mfs_msg *msg)
{
	map<string, uint64_t>::iterator it;
	struct thread_ctx *ctx;
	pthread_t t0;
	int ret;

	if (files.empty())
		return 0;

	for (it = files.begin(); it != files.end(); ++it) {
		ctx = (struct thread_ctx *)malloc(sizeof(struct thread_ctx));
		if (!ctx) {
			perror("malloc ctx failed");
			continue;
		}
		ctx->path = strdup(it->first.c_str());
		ctx->off = 0;
		ctx->len = it->second;
		ret = pthread_create(&t0, NULL, fault, ctx);
		if (ret == 0)
			pthread_detach(t0);
	}
	files.clear();
	return 0;
}

static int process_remote_read(struct mfs_msg *msg)
{
	struct mfs_ioc_rpath *rpath;
	struct mfs_ioc_done done;
	int fd = msg->fd;
	int ret;

	rpath = (struct mfs_ioc_rpath *)malloc(sizeof(struct mfs_ioc_rpath) + 1024);

	if (!rpath) {
		pr_err("malloc for path failed\n");
		return -1;
	}
	rpath->max = 1024;
	ret = ioctl(fd, MFS_IOC_RPATH, (unsigned long)rpath);
	if (ret) {
		free(rpath);
		perror("ioctl failed");
		return -1;
	}
	free(rpath);

	done.id = msg->id;
	done.ret = 0;
	ret = ioctl(fd, MFS_IOC_DONE, (unsigned long)&done);
	if (ret)
		perror("failed to ioctl MFS_IOC_DONE");

	return ret;
}

static int process_read(struct mfs_msg *msg)
{
	int ret;

	if (mfs_mode == MFS_MODE_REMOTE)
		ret = process_remote_read(msg);
	else if (mfs_mode == MFS_MODE_LOCAL)
		ret = process_local_read(msg);
	else
		ret = -EINVAL;
	return ret;
}

static int process_req(int fd)
{
	char buf[1024];
	struct mfs_msg *msg;
	int ret;

	memset(buf, 0, sizeof(buf));
	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		if (ret < 0)
			pr_err("read failed, ret:%d\n", ret);
		return -1;
	}

	msg = (struct mfs_msg *)buf;
	if (ret != msg->len) {
		pr_err("invalid message length, read:%d, need:%d\n", ret, msg->len);
		return -1;
	}
	if (msg->opcode == MFS_OP_READ || msg->opcode == MFS_OP_FAULT) {
		return process_read(msg);
	}
	pr_err("invalid opcode:%d\n", msg->opcode);
	return -1;
}

static void ioctl_mfs_mode(int fd)
{
	struct mfs_ioc_fsinfo fsinfo = {0};
	int ret;

	ret = ioctl(fd, MFS_IOC_FSINFO, (unsigned long)&fsinfo);
	if (ret < 0) {
		perror("failed to ioctl mfs_ioc_fsinfo");
		close(fd);
		exit(-1);
	}

	mfs_mode = fsinfo.mode;
}

int main(int argc, char *argv[])
{
	struct pollfd pfd;
	struct statfs buf;
	char *mountpoint;
	char *parent;
	char devname[10];
	int fd, ret;

	if (argc != 3) {
		printf("./mfsd ${mfs_mountpoint} {data_dir}\n");
		return -1;
	}
	mountpoint = argv[1];
	parent = argv[2];

	ret = statfs(mountpoint, &buf);
	if (ret) {
		pr_err("statfs %s failed\n", mountpoint);
		return -1;
	}
	if (buf.f_type != MFS_SUPER_MAGIC) {
		pr_err("fstype(%lx) is invalid, please check the mountpoint\n", buf.f_type);
		return -1;
	}

	sprintf(devname, "/dev/mfs%ld", buf.f_spare[0]);
	fd = open(devname, O_RDWR);
	if (fd < 0) {
		pr_err("open %s failed\n", devname);
		return -1;
	}

	ioctl_mfs_mode(fd);
	pfd.fd = fd;
	pfd.events = POLLIN;

	ret = get_files(parent);
	if (ret < 0)
		return -1;

	while (1) {
		ret = poll(&pfd, 1, -1);
		if (ret < 0) {
			pr_err("poll failed\n");
			return -1;
		}

		if (ret == 0 || !(pfd.revents & POLLIN)) {
			pr_err("poll event error, ret:%d, revents:%x\n", ret, pfd.revents);
			break;
		}

		if (process_req(fd) == -1)
			pr_err("process req failed, errcode:%d\n", errno);
	}
	return 0;
}
