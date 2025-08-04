/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common place for both 32- and 64-bit entry routines.
 */

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/msr-index.h>
#include <asm/nospec-branch.h>

.pushsection .noinstr.text, "ax"

SYM_FUNC_START(entry_ibpb)
	movl	$MSR_IA32_PRED_CMD, %ecx
	movl	_ASM_RIP(x86_pred_cmd), %eax
	xorl	%edx, %edx
	wrmsr
	RET
SYM_FUNC_END(entry_ibpb)
/* For KVM */
EXPORT_SYMBOL_GPL(entry_ibpb);

.popsection
