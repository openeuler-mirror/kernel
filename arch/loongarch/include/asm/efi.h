/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_LOONGARCH_EFI_H
#define _ASM_LOONGARCH_EFI_H

#include <linux/efi.h>

void __init loongson_efi_init(void);
void __init efi_runtime_init(void);

#define ARCH_EFI_IRQ_FLAGS_MASK  0x00000004  /* Bit 2: CSR.CRMD.IE */

#define arch_efi_call_virt_setup()
#define arch_efi_call_virt_teardown()

#define EFI_ALLOC_ALIGN		SZ_64K
#define EFI_RT_VIRTUAL_OFFSET	CSR_DMW0_BASE

#define LINUX_EFI_INITRD_MEDIA_GUID		EFI_GUID(0x5568e427, 0x68fc, 0x4f3d,  0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68)
#define LINUX_EFI_NEW_MEMMAP_GUID		EFI_GUID(0x800f683f, 0xd08b, 0x423a,  0xa2, 0x93, 0x96, 0x5c, 0x3c, 0x6f, 0xe2, 0xb4)

struct linux_efi_initrd {
	unsigned long	base;
	unsigned long	size;
};

struct efi_new_memmap {
	unsigned long		map_size;
	unsigned long		desc_size;
	u32			desc_ver;
	unsigned long		map_key;
	unsigned long		buff_size;
	efi_memory_desc_t	map[];
};

static inline struct screen_info *alloc_screen_info(void)
{
	return &screen_info;
}

static inline void efifb_setup_from_dmi(struct screen_info *si, const char *opt)
{
}

static inline void free_screen_info(struct screen_info *si)
{
}

static inline unsigned long efi_get_max_fdt_addr(unsigned long image_addr)
{
	return ULONG_MAX;
}

static inline unsigned long efi_get_max_initrd_addr(unsigned long image_addr)
{
	return ULONG_MAX;
}
extern void *early_memremap_ro(resource_size_t phys_addr, unsigned long size);

#endif /* _ASM_LOONGARCH_EFI_H */
