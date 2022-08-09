/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SW64_KERNEL_PROTO_H
#define _SW64_KERNEL_PROTO_H

#include <linux/interrupt.h>
#include <linux/io.h>
#include <asm/pgtable.h>
#include <asm/sw64io.h>

/* traps.c */
extern void show_regs(struct pt_regs *regs);
extern void die(char *str, struct pt_regs *regs, long err);

/* timer.c */
extern void setup_timer(void);

extern void __init setup_sched_clock(void);
#ifdef CONFIG_GENERIC_SCHED_CLOCK
extern void __init sw64_sched_clock_init(void);
#endif

#endif /* _SW64_PROTO_H */
