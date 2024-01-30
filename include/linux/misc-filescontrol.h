/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024-2024, Huawei Tech. Co., Ltd.
 *
 * Author: Ridong Chen <chenridong@huawei.com>
 */

#ifndef __MISC_FILESCONTROL_H_
#define __MISC_FILESCONTROL_H_

#include <linux/fdtable.h>
int misc_fd_alloc_fd(struct files_struct *files, u64 n);
void misc_fd_unalloc_fd(struct files_struct *files, u64 n);

void misc_fd_assign(struct files_struct *files);
void misc_fd_remove(struct files_struct *files);

int misc_fd_dup_fds(struct files_struct *newf);
void misc_fd_put_fd(struct files_struct *files, unsigned int fd);

#endif
