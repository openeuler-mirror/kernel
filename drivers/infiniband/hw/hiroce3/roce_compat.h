/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_COMPAT_H
#define ROCE_COMPAT_H

#include <linux/delay.h>

#define ROCE_LIKELY(x) /*lint -e730*/ likely(x) /*lint +e730*/

#define ROCE_UNLIKELY(x) /*lint -e730*/ unlikely(x) /*lint +e730*/

#define ROCE_ILOG2(n) /*lint -e866*/ ilog2(n) /*lint +e866*/

#define ROCE_ROUNDUP_POW_OF_TWO(n) /*lint -e866*/ roundup_pow_of_two(n) /*lint +e866*/

/*lint -e506 -e160 -e522*/
#define ROCE_MDELAY(n) mdelay(n)
#define ROCE_UDELAY(n) udelay(n)

#define ROCE_ALIGN(a, b) ALIGN(a, b)
#define ROCE_MAX(a, b) max(a, b)
#define ROCE_MIN(a, b) min(a, b)
#define ROCE_DIV_ROUND_UP(a, b) DIV_ROUND_UP(a, b)
#define ROCE_FLS(n) fls(n)

#define ROCE_MEMCMP(a, b, count) memcmp(a, b, count)
#define ROCE_IO_MAPPING_MAP_WC(mapping, offset) io_mapping_map_wc(mapping, offset)
#define ROCE_IOREMAP(phys_addr, size) ioremap(phys_addr, size)
#define ROCE_IOUNMAP(addr) iounmap(addr)
#define ROCE_IO_MAPPING_UNMAP(vaddr) io_mapping_unmap(vaddr)

#ifndef wc_wmb

#if defined(__i386__)
static inline void wc_wmb(void)
{
	asm volatile("lock; addl $0,0(%%esp) " ::: "memory");
}
#elif defined(__x86_64__)
static inline void wc_wmb(void)
{
	asm volatile("sfence" ::: "memory");
}
#elif defined(__ia64__)
static inline void wc_wmb(void)
{
	asm volatile("fwb" ::: "memory");
}
#else
static inline void wc_wmb(void)
{
	/* Write memory barrier in aarch64 */
	wmb();
}
#endif

#endif

#endif // ROCE_COMPAT_H
