/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>

.text
.set noat
.type perf_regs_load,%function
SYM_FUNC_START(perf_regs_load)
	stl $0, 0x0($16);
	stl $1, 0x8($16);
	stl $2, 0x10($16);
	stl $3, 0x18($16);
	stl $4, 0x20($16);
	stl $5, 0x28($16);
	stl $6, 0x30($16);
	stl $7, 0x38($16);
	stl $8, 0x40($16);
	stl $19, 0x48($16);
	stl $20, 0x50($16);
	stl $21, 0x58($16);
	stl $22, 0x60($16);
	stl $23, 0x68($16);
	stl $24, 0x70($16);
	stl $25, 0x78($16);
	stl $26, 0x80($16);
	stl $27, 0x88($16);
	stl $28, 0x90($16);
	stl $30, 0x98($16);
	stl $20, 0xa0($16);
	stl $21, 0xa8($16);
	stl $22, 0xb0($16);
	stl $23, 0xb8($16);
	stl $26, 0xc0($16);
	stl $29, 0xc8($16);
	stl $16, 0xd0($16);
	stl $17, 0xd8($16);
	stl $18, 0xe0($16);
	ret
SYM_FUNC_END(perf_regs_load)
