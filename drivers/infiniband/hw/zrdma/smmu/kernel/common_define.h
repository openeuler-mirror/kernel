/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _SMMU_COMMON_DEFINE_H_
#define _SMMU_COMMON_DEFINE_H_

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include "cmdk.h"

/* Endianness detection */
#ifdef __BIG_ENDIAN
#define SMMU_BIG_ENDIAN
#endif

/* Debug print level control */
extern u8 smmu_print_module_id;

#define smmu_print(level, fmt, ...)                  \
	do {                                         \
		if ((level) >= smmu_print_module_id) \
			pr_info(fmt, ##__VA_ARGS__); \
	} while (0)

/* Byte swap functions */
u32 smmu_swap32(u32 val);
u64 smmu_swap64(u64 val);

#ifdef SMMU_BIG_ENDIAN
#define SMMU_CPU_TO_LE32(x) smmu_swap32(x)
#define SMMU_CPU_TO_LE64(x) smmu_swap64(x)
#define SMMU_LE32_TO_CPU(x) smmu_swap32(x)
#define SMMU_LE64_TO_CPU(x) smmu_swap64(x)
#else
#define SMMU_CPU_TO_LE32(x) (x)
#define SMMU_CPU_TO_LE64(x) (x)
#define SMMU_LE32_TO_CPU(x) (x)
#define SMMU_LE64_TO_CPU(x) (x)
#endif

#endif /* _SMMU_COMMON_DEFINE_H_ */
