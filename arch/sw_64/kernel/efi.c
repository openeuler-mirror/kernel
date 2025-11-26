// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/init.h>

#include <asm/efi.h>

static __init pgprot_t create_mapping_protection(efi_memory_desc_t *md)
{
	switch (md->type) {
	case EFI_RUNTIME_SERVICES_CODE:
	case EFI_PAL_CODE:
		return PAGE_KERNEL_READONLY_EXEC;
	case EFI_RESERVED_TYPE:
	case EFI_RUNTIME_SERVICES_DATA:
	case EFI_UNUSABLE_MEMORY:
	case EFI_ACPI_MEMORY_NVS:
	case EFI_MEMORY_MAPPED_IO:
	case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
	case EFI_MAX_MEMORY_TYPE:
		return PAGE_KERNEL_NOEXEC;
	default:
		break;
	}

	return PAGE_KERNEL;
}

static void * __init pgtable_alloc_late(void)
{
	return (void *)__get_free_page(GFP_KERNEL);
}

int __init efi_create_mapping(struct mm_struct *mm, efi_memory_desc_t *md)
{
	pgprot_t prot = create_mapping_protection(md);
	unsigned long start, size;

	start = (unsigned long)__va(md->phys_addr);
	size = (unsigned long)(md->num_pages << EFI_PAGE_SHIFT);
	create_pgd_mapping(mm->pgd, start, (unsigned long)md->phys_addr, size,
			   prot, pgtable_alloc_late);
	return 0;
}
