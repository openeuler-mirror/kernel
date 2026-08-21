// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <limits.h>

#include <linux/fiemap.h>

#include <linux/nds_p2p.h>
#include "p2p_common.h"
#include "file_p2p_api.h"

int close_p2p_fd(int dev_fd)
{
	return close(dev_fd);
}

int new_p2p_fd(void)
{
	return p2p_open_dev();
}

int add_topo(int dev_fd, const char *dev)
{
	return p2p_add_topo(dev_fd, dev);
}

int register_mem(int dev_fd, struct p2p_mem_register_param *param)
{
	if (ioctl(dev_fd, IOCTL_REGISTER_MEM, param) < 0)
		return -errno;
	return 0;
}

int unregister_mem(int dev_fd, const struct p2p_mem_unregister_param *param)
{
	if (ioctl(dev_fd, IOCTL_UNREGISTER_MEM, param) < 0)
		return -errno;
	return 0;
}

int rw_file(int dev_fd, const struct io_parameter *param)
{
	struct p2p_io_batch_param batch;
	struct p2p_io_param *io;
	struct fiemap *exts = NULL;
	struct stat file_stat;
	unsigned long io_size;
	unsigned long long total_size = 0;
	unsigned int ext_num = 0;
	const char *name;
	int file_fd = -1;
	int err = 0;

	if (!param)
		return -EINVAL;
	if (param->op != P2P_IO_READ && param->op != P2P_IO_WRITE)
		return -EINVAL;
	if (param->flags & ~P2P_IO_F_MASK)
		return -EOPNOTSUPP;
	if (param->flags & P2P_IO_F_REGISTERED_MEM) {
		if (!param->mem_handle || param->host_pid)
			return -EINVAL;
	} else if (param->host_pid < 0) {
		return -EINVAL;
	}

	err = p2p_get_iov_size(param->iov, param->iov_nr, &io_size);
	if (err)
		return err;
	if (ULONG_MAX - param->file_offset < io_size)
		return -EOVERFLOW;

	name = param->file_name;
	file_fd = open(name, (param->op == P2P_IO_WRITE ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
	if (file_fd < 0) {
		err = -errno;
		fprintf(stderr, "open %s failed, errno: %d\n", name, err);
		goto close_fds_out;
	}

	err = fstat(file_fd, &file_stat);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "fstat %s failed, errno: %d\n", name, err);
		goto close_fds_out;
	}

	if (param->op == P2P_IO_WRITE && !S_ISBLK(file_stat.st_mode)) {
		err = S_ISREG(file_stat.st_mode) ? -EOPNOTSUPP : -EINVAL;
		goto close_fds_out;
	}

	err = p2p_prepare_io_extents(file_fd, &file_stat, param->file_offset, io_size, &exts, &ext_num,
				     &total_size);
	if (err) {
		fprintf(stderr, "prepare extents failed, errno: %d\n", err);
		goto close_fds_out;
	}

	if (!ext_num || total_size < io_size) {
		err = -ENODATA;
		fprintf(stderr, "extent size %llu < IOV size %lu\n", total_size, io_size);
		goto free_ext_out;
	}

	io = calloc(1, sizeof(*io));
	if (io == NULL) {
		err = -ENOMEM;
		fprintf(stderr, "calloc p2p_io_param failed, errno: %d\n", err);
		goto free_ext_out;
	}

	io->op = param->op;
	io->file_fd = file_fd;
	io->flags = param->flags;
	if (param->flags & P2P_IO_F_REGISTERED_MEM) {
		io->host_pid = 0;
		io->mem_handle = param->mem_handle;
	} else {
		io->host_pid = param->host_pid ? param->host_pid : getpid();
		io->mem_handle = 0;
	}
	io->iov = (uint64_t)(uintptr_t)param->iov;
	io->iov_nr = param->iov_nr;
	io->ext_nr = ext_num;
	io->extents = (uint64_t)(uintptr_t)exts->fm_extents;

	batch.nr = 1;
	batch.reserved = 0;
	batch.items = (uint64_t)(uintptr_t)io;
	err = ioctl(dev_fd, IOCTL_SUBMIT_IO, &batch);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "%s file ioctl failed, errno: %d\n",
			param->op == P2P_IO_WRITE ? "write" : "read", -err);
		goto free_io_out;
	}
	if (err != 1) {
		fprintf(stderr, "%s file ioctl accepted %d requests, expected 1\n",
			param->op == P2P_IO_WRITE ? "write" : "read", err);
		err = -EIO;
		goto free_io_out;
	}
	err = 0;

free_io_out:
	free(io);
free_ext_out:
	free(exts);
close_fds_out:
	if (file_fd >= 0)
		close(file_fd);
	return err;
}

int drain_io(int dev_fd)
{
	if (ioctl(dev_fd, IOCTL_DRAIN_IO) < 0)
		return -errno;
	return 0;
}
