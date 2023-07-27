/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_SHARE_POOL_INTERFACE_H
#define LINUX_SHARE_POOL_INTERFACE_H

#include <linux/mman.h>
#include <linux/mm_types.h>
#include <linux/numa.h>
#include <linux/kabi.h>

#ifdef CONFIG_ASCEND_SHARE_POOL
extern int sp_node_id(struct vm_area_struct *vma);
#else
static inline int sp_node_id(struct vm_area_struct *vma)
{
	return numa_node_id();
}
#endif /* !CONFIG_ASCEND_SHARE_POOL */

#endif /* LINUX_SHARE_POOL_INTERFACE_H */
