/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/regdef.h>

	.text
	.set noat
ENTRY(__fpstate_save)
	/* a0: prev task */
	ldi	a0, TASK_THREAD(a0)
	ldi	t0, THREAD_CTX_FP(a0)
	vstd	$f0, CTX_FP_F0(t0)
	vstd	$f1, CTX_FP_F1(t0)
	vstd	$f2, CTX_FP_F2(t0)
	vstd	$f3, CTX_FP_F3(t0)
	vstd	$f4, CTX_FP_F4(t0)
	vstd	$f5, CTX_FP_F5(t0)
	vstd	$f6, CTX_FP_F6(t0)
	vstd	$f7, CTX_FP_F7(t0)
	vstd	$f8, CTX_FP_F8(t0)
	vstd	$f9, CTX_FP_F9(t0)
	vstd	$f10, CTX_FP_F10(t0)
	vstd	$f11, CTX_FP_F11(t0)
	vstd	$f12, CTX_FP_F12(t0)
	vstd	$f13, CTX_FP_F13(t0)
	vstd	$f14, CTX_FP_F14(t0)
	vstd	$f15, CTX_FP_F15(t0)
	vstd	$f16, CTX_FP_F16(t0)
	vstd	$f17, CTX_FP_F17(t0)
	vstd	$f18, CTX_FP_F18(t0)
	vstd	$f19, CTX_FP_F19(t0)
	vstd	$f20, CTX_FP_F20(t0)
	vstd	$f21, CTX_FP_F21(t0)
	vstd	$f22, CTX_FP_F22(t0)
	vstd	$f23, CTX_FP_F23(t0)
	vstd	$f24, CTX_FP_F24(t0)
	vstd	$f25, CTX_FP_F25(t0)
	vstd	$f26, CTX_FP_F26(t0)
	vstd	$f27, CTX_FP_F27(t0)
	rfpcr	$f0
	vstd	$f28, CTX_FP_F28(t0)
	vstd	$f29, CTX_FP_F29(t0)
	vstd	$f30, CTX_FP_F30(t0)
	fstd	$f0, THREAD_FPCR(a0)
	vldd	$f0, CTX_FP_F0(t0)
	ret
END(__fpstate_save)

ENTRY(__fpstate_restore)
	/* a0: next task */
	ldi	a0, TASK_THREAD(a0)
	fldd	$f0, THREAD_FPCR(a0)
	wfpcr	$f0
	fimovd	$f0, t1
	and	t1, 0x3, t1
	beq	t1, $setfpec_0
	subl	t1, 0x1, t1
	beq	t1, $setfpec_1
	subl	t1, 0x1, t1
	beq	t1, $setfpec_2
	setfpec3
	br	$setfpec_over
$setfpec_0:
	setfpec0
	br	$setfpec_over
$setfpec_1:
	setfpec1
	br	$setfpec_over
$setfpec_2:
	setfpec2
$setfpec_over:
	ldi	t0, THREAD_CTX_FP(a0)
	vldd	$f0, CTX_FP_F0(t0)
	vldd	$f1, CTX_FP_F1(t0)
	vldd	$f2, CTX_FP_F2(t0)
	vldd	$f3, CTX_FP_F3(t0)
	vldd	$f4, CTX_FP_F4(t0)
	vldd	$f5, CTX_FP_F5(t0)
	vldd	$f6, CTX_FP_F6(t0)
	vldd	$f7, CTX_FP_F7(t0)
	vldd	$f8, CTX_FP_F8(t0)
	vldd	$f9, CTX_FP_F9(t0)
	vldd	$f10, CTX_FP_F10(t0)
	vldd	$f11, CTX_FP_F11(t0)
	vldd	$f12, CTX_FP_F12(t0)
	vldd	$f13, CTX_FP_F13(t0)
	vldd	$f14, CTX_FP_F14(t0)
	vldd	$f15, CTX_FP_F15(t0)
	vldd	$f16, CTX_FP_F16(t0)
	vldd	$f17, CTX_FP_F17(t0)
	vldd	$f18, CTX_FP_F18(t0)
	vldd	$f19, CTX_FP_F19(t0)
	vldd	$f20, CTX_FP_F20(t0)
	vldd	$f21, CTX_FP_F21(t0)
	vldd	$f22, CTX_FP_F22(t0)
	vldd	$f23, CTX_FP_F23(t0)
	vldd	$f24, CTX_FP_F24(t0)
	vldd	$f25, CTX_FP_F25(t0)
	vldd	$f26, CTX_FP_F26(t0)
	vldd	$f27, CTX_FP_F27(t0)
	vldd	$f28, CTX_FP_F28(t0)
	vldd	$f29, CTX_FP_F29(t0)
	vldd	$f30, CTX_FP_F30(t0)
	ret
END(__fpstate_restore)
