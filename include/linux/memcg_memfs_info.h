/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_MEMCG_MEMFS_INFO_H
#define _LINUX_MEMCG_MEMFS_INFO_H

#include <linux/memcontrol.h>
#include <linux/seq_file.h>

#ifdef CONFIG_MEMCG_MEMFS_INFO
void mem_cgroup_print_memfs_info(struct mem_cgroup *memcg, char *pathbuf,
				 struct seq_file *m);
int mem_cgroup_memfs_files_show(struct seq_file *m, void *v);
void mem_cgroup_memfs_info_init(void);
#else
static inline void mem_cgroup_print_memfs_info(struct mem_cgroup *memcg,
					       char *pathbuf,
					       struct seq_file *m)
{
}
static inline void mem_cgroup_memfs_info_init(void)
{
}
#endif
#endif
