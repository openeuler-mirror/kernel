// SPDX-License-Identifier: GPL-2.0
#include <linux/uaccess.h>
#include <linux/errno.h>

/* get user space to a kernel buffer */
noinline void get_user_func(long *p, const long __user *addr,
			    int size, int *err)
{
	asm volatile(".global get_user_sea_fallback\n"
		     "get_user_sea_fallback:\n");

	if (unlikely(current->flags & PF_UCE_KERNEL_RECOVERY)) {
		current->flags &= ~PF_UCE_KERNEL_RECOVERY;
		*err = -EFAULT;
		return;
	}

	__get_user_uce_check(*p, addr, size, *err);
}
EXPORT_SYMBOL(get_user_func);
