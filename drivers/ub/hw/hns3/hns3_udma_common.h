/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_COMMON_H
#define _UDMA_COMMON_H
#include <linux/bitfield.h>
#include <linux/types.h>

#define ub_write(dev, reg, val)	writel((val), (dev)->reg_base + (reg))
#define ub_read(dev, reg)	readl((dev)->reg_base + (reg))

#define UDMA_UDP_DPORT		4791
#define DMA_WQE_SHIFT		3
#define DMA_DB_RECORD_SHIFT	1

/* The minimum page size is 4K for hardware */
#define UDMA_HW_PAGE_SHIFT			12
#define UDMA_PAGE_SIZE				(1 << UDMA_HW_PAGE_SHIFT)
#define UDMA_HW_PAGE_ALIGN(x)		ALIGN(x, 1 << UDMA_HW_PAGE_SHIFT)

static inline uint64_t umem_cal_npages(uint64_t va, uint64_t len)
{
	return (ALIGN(va + len, UDMA_PAGE_SIZE) - ALIGN_DOWN(va, UDMA_PAGE_SIZE)) /
	       UDMA_PAGE_SIZE;
}

#define udma_get_field(origin, mask, shift)                                    \
	((le32_to_cpu(origin) & (mask)) >> (uint32_t)(shift))
#define udma_get_field64(origin, mask, shift)                                  \
	((le64_to_cpu(origin) & (mask)) >> (uint32_t)(shift))
#define udma_get_bit(origin, shift) \
	udma_get_field((origin), (1ul << (shift)), (shift))

#define udma_set_field(origin, mask, shift, val)                               \
	do {                                                                   \
		(origin) &= ~cpu_to_le32(mask);                                \
		(origin) |= cpu_to_le32(((uint32_t)(val) <<                    \
			    (uint32_t)(shift)) & (mask));                      \
	} while (0)

#define udma_set_bit(origin, shift, val)                                       \
	udma_set_field((origin), (1ul << (shift)), (shift), (val))

#define _udma_reg_enable(ptr, field)                    \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                                  \
		*((uint32_t *)_ptr + ((field) >> 32) / 32) |= cpu_to_le32(           \
			BIT((((field) << 32) >> 32) % 32));            \
	})

#define udma_reg_enable(ptr, field) _udma_reg_enable(ptr, field)

#define _udma_reg_clear(ptr, field)                     \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                                  \
		BUILD_BUG_ON((((field) >> 32) / 32) != ((((field) << 32) >> 32) / 32));            \
		*((uint32_t *)_ptr + ((field) >> 32) / 32) &=                        \
			~cpu_to_le32(GENMASK(((field) >> 32) % 32, (((field) << 32) >> 32) % 32)); \
	})

#define udma_reg_clear(ptr, field) _udma_reg_clear(ptr, field)

#define _udma_reg_write(ptr, field, val)                \
	({                                                                     \
		uint32_t _val = val;                                           \
		_udma_reg_clear((ptr), field);          \
		*((uint32_t *)(ptr) + ((field) >> 32) / 32) |=                       \
			cpu_to_le32(FIELD_PREP(GENMASK(((field) >> 32) % 32,         \
				(((field) << 32) >> 32) % 32), _val &                \
				GENMASK((((field) >> 32) - (((field) << 32) >> 32)), 0))); \
	})

#define udma_reg_write(ptr, field, val) _udma_reg_write(ptr, field, val)

#define _udma_reg_read(ptr, field)                      \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                                  \
		BUILD_BUG_ON((((field) >> 32) / 32) != ((((field) << 32) >> 32) / 32));            \
		FIELD_GET(GENMASK(((field) >> 32) % 32, (((field) << 32) >> 32) % 32),             \
			  le32_to_cpu(*((uint32_t *)_ptr + ((field) >> 32) / 32)));  \
	})

#define udma_reg_read(ptr, field) _udma_reg_read(ptr, field)

#endif /* _UDMA_COMMON_H */
