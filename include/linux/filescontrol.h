/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024-2024, Huawei Tech. Co., Ltd.
 *
 * Author: Ridong Chen <chenridong@huawei.com>
 */

#ifndef _LINUX_FILESCONTROL_H
#define _LINUX_FILESCONTROL_H

#include <linux/fdtable.h>

u64 file_cg_count_fds(struct files_struct *files);

#ifdef CONFIG_CGROUP_FILES
int files_cg_alloc_fd(struct files_struct *files, u64 n);
void files_cg_unalloc_fd(struct files_struct *files, u64 n);

void files_cg_assign(struct files_struct *files);
void files_cg_remove(struct files_struct *files);
extern struct files_struct init_files;

int files_cg_dup_fds(struct files_struct *newf);
void files_cg_put_fd(struct files_struct *files, unsigned int fd);
#else
static inline int files_cg_alloc_fd(struct files_struct *files, u64 n) { return 0; };
static inline void files_cg_unalloc_fd(struct files_struct *files, u64 n) {};

static inline void files_cg_assign(struct files_struct *files) {};
static inline void files_cg_remove(struct files_struct *files) {};

static inline int files_cg_dup_fds(struct files_struct *newf) { return 0; };
static inline void files_cg_put_fd(struct files_struct *files, unsigned int fd) {};
#endif /* CONFIG_CGROUP_FILES */

#endif /* _LINUX_FILESCONTROL_H */
