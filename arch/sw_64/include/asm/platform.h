/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PLATFORM_H
#define _ASM_SW64_PLATFORM_H

struct sw64_platform_ops {
	void (*kill_arch)(int mode);
	void __iomem *(*ioportmap)(unsigned long);
	void (*register_platform_devices)(void);
	void (*ops_fixup)(void);
};


extern struct sw64_platform_ops *sw64_platform;

extern struct sw64_platform_ops xuelang_ops;

#endif /* _ASM_SW64_PLATFORM_H */
