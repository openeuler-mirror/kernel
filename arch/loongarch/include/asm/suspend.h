/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_LOONGARCH_SUSPEND_H
#define _ASM_LOONGARCH_SUSPEND_H

void arch_common_resume(void);
void arch_common_suspend(void);
extern void loongarch_suspend_enter(void);
extern void loongarch_wakeup_start(void);

#endif /* _ASM_LOONGARCH_SUSPEND_H */
