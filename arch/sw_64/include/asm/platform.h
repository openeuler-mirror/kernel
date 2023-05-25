/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PLATFORM_H
#define _ASM_SW64_PLATFORM_H

#include <linux/types.h>
#include <asm/chip3_io.h>

struct sw64_platform_ops {
	void __iomem *(*ioportmap)(unsigned long);
	void (*register_platform_devices)(void);
	void (*ops_fixup)(void);
};

#ifdef CONFIG_EFI
#define BIOS_VERSION_GUID       EFI_GUID(0xc47a23c3, 0xcebb, 0x4cc9, 0xa5, 0xe2, 0xde, 0xd0, 0x8f, 0xe4, 0x20, 0xb5)

#define BIOS_SUPPORT_RESET_CLALLBACK(bios_version) ((bios_version) != NULL)

extern unsigned long bios_version;

#endif

extern struct sw64_platform_ops *sw64_platform;

extern struct sw64_platform_ops xuelang_ops;
extern struct boot_params *sunway_boot_params;

extern void sw64_halt(void);
extern void sw64_poweroff(void);
extern void sw64_restart(void);
extern void (*pm_restart)(void);
extern void (*pm_halt)(void);
extern int i2c_set_adapter(void);
extern void cpld_write(uint8_t slave_addr, uint8_t reg, uint8_t data);
extern void fix_jm585_reset(void);

#endif /* _ASM_SW64_PLATFORM_H */
