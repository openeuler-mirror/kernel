/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/export.h>

/* Allow an exception for an insn; exit if we get one.  */
#define FIXUP_LDST(x, y)			\
	99: x, y;			\
	.section __ex_table, "a";	\
	.long 99b - .;			\
	ldi $31, $out-99b($31);		\
	.previous

	.globl __copy_user
	.ent __copy_user
__copy_user:
	.prologue 0
#include "deep-copy_template.S"
$out:
	bis	$31, $18, $0
	ret
	.end __copy_user
	EXPORT_SYMBOL(__copy_user)
