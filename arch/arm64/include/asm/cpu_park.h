/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_CPU_PARK_H
#define __ASM_CPU_PARK_H

#ifdef CONFIG_ARM64_CPU_PARK

/* CPU park state flag: "park" */
#define PARK_MAGIC 0x7061726b

#ifndef __ASSEMBLY__
extern void enter_cpu_park(unsigned long text, unsigned long exit);
extern void do_cpu_park(unsigned long exit);
extern void reserve_park_mem(void);
extern int write_park_exit(unsigned int cpu);
extern int uninstall_cpu_park(unsigned int cpu);
extern void cpu_park_stop(void);
extern int kexec_smp_send_park(void);
#endif /* ifndef __ASSEMBLY__ */

#else
static inline void reserve_park_mem(void) {}
static inline int write_park_exit(unsigned int cpu) { return -EINVAL; }
static inline int uninstall_cpu_park(unsigned int cpu) { return -EINVAL; }
static inline void cpu_park_stop(void) {}
static inline int kexec_smp_send_park(void) { return -EINVAL; }
#endif

#endif /* ifndef __ASM_CPU_PARK_H */
