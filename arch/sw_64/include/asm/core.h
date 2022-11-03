/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_CORE_H
#define _ASM_SW64_CORE_H

#define II_II0			0
#define II_II1			1
#define II_SLEEP		2
#define II_WAKE			3
#define II_NMII			6

#ifdef CONFIG_SW64_CHIP3
#define II_RESET		II_NMII
#define CORES_PER_NODE_SHIFT	5
#endif
#define CORES_PER_NODE		(1UL << CORES_PER_NODE_SHIFT)

/*
 * 0x00 ~ 0xff for hardware mm fault
 */

#define MMCSR__TNV		0x0
#define MMCSR__IACV		0x1
#define MMCSR__FOR		0x2
#define MMCSR__FOE		0x3
#define MMCSR__FOW		0x4

#define MMCSR__BAD_DVA		0x6
#define MMCSR__ACV1		0x7
#define MMCSR__ACV0		0xc
#define MMCSR__BAD_IVA		0xf

/* 0x100 ~ 0x1ff for match debug */
#define MMCSR__DA_MATCH		0x100
#define MMCSR__DV_MATCH		0x101
#define MMCSR__DAV_MATCH	0x102
#define MMCSR__IA_MATCH		0x103
#define MMCSR__IDA_MATCH	0x104

 /* entry.S */
extern void entArith(void);
extern void entIF(void);
extern void entInt(void);
extern void entMM(void);
extern void entSys(void);
extern void entUna(void);
/* head.S */
extern void __smp_callin(unsigned long);
#endif /* _ASM_SW64_CORE_H */
