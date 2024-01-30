/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024-2024, Huawei Tech. Co., Ltd.
 *
 * Author: Ridong Chen <chenridong@huawei.com>
 */

#include <linux/misc_cgroup.h>
#include <linux/fdtable.h>
#include <linux/filescontrol.h>
#include <linux/misc-filescontrol.h>

int misc_fd_alloc_fd(struct files_struct *files, u64 n)
{
	if (files != &init_files)
		return misc_cg_try_charge(MISC_CG_RES_FD, files->misc_cg, n);
	return 0;
}

void misc_fd_unalloc_fd(struct files_struct *files, u64 n)
{
	if (files != &init_files)
		misc_cg_uncharge(MISC_CG_RES_FD, files->misc_cg, n);
}

void misc_fd_assign(struct files_struct *files)
{
	if (files == NULL || files == &init_files)
		return;

	files->misc_cg = get_current_misc_cg();
}

void misc_fd_remove(struct files_struct *files)
{
	if (files == &init_files)
		return;

	spin_lock(&files->file_lock);
	put_misc_cg(files->misc_cg);
	files->misc_cg = NULL;
	spin_unlock(&files->file_lock);
}

int misc_fd_dup_fds(struct files_struct *newf)
{
	int err;

	if (newf == &init_files)
		return 0;

	spin_lock(&newf->file_lock);
	err = misc_fd_alloc_fd(newf, file_cg_count_fds(newf));
	spin_unlock(&newf->file_lock);
	return err;
}

void misc_fd_put_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);

	if (files == &init_files)
		return;

	if (test_bit(fd, fdt->open_fds))
		misc_fd_unalloc_fd(files, 1);
}
