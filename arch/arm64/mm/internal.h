/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ARM64_MM_INTERNAL_H
#define __ARM64_MM_INTERNAL_H

#include <linux/types.h>

#define MAX_RES_REGIONS 32
extern struct memblock_region mbk_memmap_regions[MAX_RES_REGIONS];
extern int mbk_memmap_cnt;

#endif /* ifndef _ARM64_MM_INTERNAL_H */
