/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024-2024, Huawei Tech. Co., Ltd.
 *
 * Author: Ridong Chen <chenridong@huawei.com>
 */

#include <linux/fdtable.h>
#include <linux/filescontrol.h>
#include <linux/legacy-filescontrol.h>

u64 file_cg_count_fds(struct files_struct *files)
{
	int i;
	struct fdtable *fdt;
	int retval = 0;

	fdt = files_fdtable(files);
	for (i = 0; i < DIV_ROUND_UP(fdt->max_fds, BITS_PER_LONG); i++)
		retval += hweight64((__u64)fdt->open_fds[i]);
	return retval;
}

int files_cg_alloc_fd(struct files_struct *files, u64 n)
{
	return files_cgroup_alloc_fd(files, n);
}

void files_cg_unalloc_fd(struct files_struct *files, u64 n)
{
	files_cgroup_unalloc_fd(files, n);
}

void files_cg_assign(struct files_struct *files)
{
	files_cgroup_assign(files);
}

void files_cg_remove(struct files_struct *files)
{
	files_cgroup_remove(files);
}

int files_cg_dup_fds(struct files_struct *newf)
{
	return files_cgroup_dup_fds(newf);
}

void files_cg_put_fd(struct files_struct *files, unsigned int fd)
{
	files_cgroup_put_fd(files, fd);
}
