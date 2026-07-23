// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "cmdk_mmu600.h"
#include "common_define.h"

u8 smmu_print_module_id;
EXPORT_SYMBOL(smmu_print_module_id);

/**
 * uswap_32 - Swap bytes in 32-bit value
 * @v: Value to swap
 *
 * Return: Byte-swapped value
 */
u32 uswap_32(u32 v)
{
	return ((v & 0x000000ff) << 24) | ((v & 0x0000ff00) << 8) | ((v & 0x00ff0000) >> 8) |
	       ((v & 0xff000000) >> 24);
}
EXPORT_SYMBOL(uswap_32);

/**
 * uswap_64 - Swap bytes in 64-bit value
 * @v: Value to swap
 *
 * Return: Byte-swapped value
 */
u64 uswap_64(u64 v)
{
	return ((u64)uswap_32((u32)v) << 32) | uswap_32((u32)(v >> 32));
}
EXPORT_SYMBOL(uswap_64);

/**
 * memset_8byte - Set memory with 64-bit pattern
 * @p: Pointer to memory
 * @data: 64-bit pattern to set
 * @size: Size in bytes
 *
 * Return: 0 on success
 */
u32 memset_8byte(u64 *p, u64 data, u64 size)
{
	u64 count = size / 8;
	u64 i;

	for (i = 0; i < count; i++)
		p[i] = data;

	return 0;
}
EXPORT_SYMBOL(memset_8byte);

/**
 * zxdh_smmu_cmd_tlb_sync - Synchronize TLB
 *
 * Return: 0 on success
 */
u32 zxdh_smmu_cmd_tlb_sync(void)
{
	/* TODO: Implement TLB sync command */
	return 0;
}
EXPORT_SYMBOL(zxdh_smmu_cmd_tlb_sync);

/**
 * zxdh_smmu_set_print_level - Set SMMU print level
 * @print_level: Print level to set
 *
 * Return: 0 on success
 */
u32 zxdh_smmu_set_print_level(u32 print_level)
{
	smmu_print_module_id = print_level;
	return 0;
}
EXPORT_SYMBOL(zxdh_smmu_set_print_level);

/**
 * zxdh_smmu_get_print_level - Get current SMMU print level
 *
 * Return: Current print level
 */
u8 zxdh_smmu_get_print_level(void)
{
	return smmu_print_module_id;
}
EXPORT_SYMBOL(zxdh_smmu_get_print_level);

MODULE_AUTHOR("ZTE Corporation");
MODULE_LICENSE("GPL");
