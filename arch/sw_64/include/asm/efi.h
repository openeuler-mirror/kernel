/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_SW64_EFI_H
#define _ASM_SW64_EFI_H

#include <asm/early_ioremap.h>

#ifdef CONFIG_EFI
extern void efi_init(void);
extern unsigned long entSuspend;

#define SLEEP_ENTRY_GUID        EFI_GUID(0x59cb76bb, 0x9c3a, 0x4c8f, 0xbd, 0x5c, 0xc0, 0x0f, 0x20, 0x61, 0x18, 0x4b)

#else
#define efi_init()
#define efi_idmap_init()
#endif

#define arch_efi_call_virt_setup()
#define arch_efi_call_virt_teardown()

#define arch_efi_call_virt(p, f, args...)				\
({									\
	efi_##f##_t * __f;						\
	__f = p->f;							\
	__f(args);							\
})

#define ARCH_EFI_IRQ_FLAGS_MASK		0x00000001

/* arch specific definitions used by the stub code */

#endif /* _ASM_SW64_EFI_H */
