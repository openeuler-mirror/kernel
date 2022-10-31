// SPDX-License-Identifier: GPL-2.0

#include <linux/error-injection.h>
#include <linux/kprobes.h>

asmlinkage void just_return_func(void);

asm(
	".text\n"
	".type just_return_func, @function\n"
	".globl just_return_func\n"
	"just_return_func:\n"
	"	ret\n"
	".size just_return_func, .-just_return_func\n"
);

void override_function_with_return(struct pt_regs *regs)
{
	regs->ip = (unsigned long)&just_return_func;
}
NOKPROBE_SYMBOL(override_function_with_return);

int regs_set_register(struct pt_regs *regs, const char *regs_name,
		      unsigned long value)
{
	int offset = 0;
	offset = regs_query_register_offset(regs_name) >> 3;
	if (offset >= 0) {
		*((unsigned long *)((unsigned long *)regs + offset)) = value;
		return 0;
	}
	return -1;
}
NOKPROBE_SYMBOL(regs_set_register);