/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_XCALL_H
#define __ASM_XCALL_H

#include <linux/jump_label.h>
#include <linux/sched.h>
#include <linux/types.h>

DECLARE_STATIC_KEY_FALSE(xcall_enable);

struct xcall_info {
	/* Must be first! */
	DECLARE_BITMAP(xcall_enable, __NR_syscalls);
};

#define TASK_XINFO(p)	((struct xcall_info *)p->xinfo)

int xcall_init_task(struct task_struct *p, struct task_struct *orig);
void xcall_task_free(struct task_struct *p);
#endif /*__ASM_XCALL_H*/
