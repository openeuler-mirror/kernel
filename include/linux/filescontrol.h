/* SPDX-License-Identifier: GPL-2.0 */
/* filescontrol.h - Files Controller
 *
 * Copyright 2014 Google Inc.
 * Author: Brian Makin <merimus@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _LINUX_FILESCONTROL_H
#define _LINUX_FILESCONTROL_H

#include <linux/fdtable.h>

#ifdef CONFIG_CGROUP_FILES
extern int files_cgroup_alloc_fd(struct files_struct *files, u64 n);
extern void files_cgroup_unalloc_fd(struct files_struct *files, u64 n);

extern struct files_struct init_files;
extern void files_cgroup_assign(struct files_struct *files);
extern void files_cgroup_remove(struct files_struct *files);

extern int files_cgroup_dup_fds(struct files_struct *newf);
extern void files_cgroup_put_fd(struct files_struct *files, unsigned int fd);
#else /* no CONFIG_CGROUP_FILES */
static inline int files_cgroup_alloc_fd(struct files_struct *files, u64 n) { return 0; };
static inline void files_cgroup_unalloc_fd(struct files_struct *files, u64 n) {};

static inline void files_cgroup_assign(struct files_struct *files) {};
static inline void files_cgroup_remove(struct files_struct *files) {};

static inline int files_cgroup_dup_fds(struct files_struct *newf) { return 0; };
static inline void files_cgroup_put_fd(struct files_struct *files, unsigned int fd) {};
#endif /* CONFIG_CGROUP_FILES */

#endif /* _LINUX_FILESCONTROL_H */
