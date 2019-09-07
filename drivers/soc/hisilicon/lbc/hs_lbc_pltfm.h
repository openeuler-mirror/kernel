/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _HS_LBC_PLTFM_H_
#define _HS_LBC_PLTFM_H_
#include <linux/version.h>

/* RW data width */
#define LBC_RWDATA_WIDTH_8  (0)
#define LBC_RWDATA_WIDTH_16 (1)
#define LBC_RWDATA_WIDTH_32 (2)

/* cs width */
#define LBC_CS_WIDTH_8  (0)
#define LBC_CS_WIDTH_16 (1)
#define LBC_CS_WIDTH_32 (2)

/* cs address shift */
#define LBC_CS_ADDR_SHIFT_0  (0)
#define LBC_CS_ADDR_SHIFT_1  (1)
#define LBC_CS_ADDR_SHIFT_2  (2)

#define LBC_CS_MAX_NUM (4)

#define LBC_CS_MEM_SIZE_0	(0)
#define LBC_CS_MEM_SIZE_64K (64 * 1024)
#define LBC_CS_MEM_SIZE_128K (LBC_CS_MEM_SIZE_64K << 1)
#define LBC_CS_MEM_SIZE_256K (LBC_CS_MEM_SIZE_128K << 1)
#define LBC_CS_MEM_SIZE_512K (LBC_CS_MEM_SIZE_256K << 1)
#define LBC_CS_MEM_SIZE_1M (LBC_CS_MEM_SIZE_512K << 1)
#define LBC_CS_MEM_SIZE_2M (LBC_CS_MEM_SIZE_1M << 1)
#define LBC_CS_MEM_SIZE_4M (LBC_CS_MEM_SIZE_2M << 1)
#define LBC_CS_MEM_SIZE_8M (LBC_CS_MEM_SIZE_4M << 1)
#define LBC_CS_MEM_SIZE_16M (LBC_CS_MEM_SIZE_8M << 1)
#define LBC_CS_MEM_SIZE_32M (LBC_CS_MEM_SIZE_16M << 1)
#define LBC_CS_MEM_SIZE_64M (LBC_CS_MEM_SIZE_32M << 1)
#define LBC_CS_MEM_SIZE_128M (LBC_CS_MEM_SIZE_64M << 1)
#define LBC_CS_MEM_SIZE_256M (LBC_CS_MEM_SIZE_128M << 1)

#define LBC_CS_MEM_SIZE_REG_0	(0)
#define LBC_CS_MEM_SIZE_REG_64K (1)
#define LBC_CS_MEM_SIZE_REG_128K (2)
#define LBC_CS_MEM_SIZE_REG_256K (3)
#define LBC_CS_MEM_SIZE_REG_512K (4)
#define LBC_CS_MEM_SIZE_REG_1M (5)
#define LBC_CS_MEM_SIZE_REG_2M (6)
#define LBC_CS_MEM_SIZE_REG_4M (7)
#define LBC_CS_MEM_SIZE_REG_8M (8)
#define LBC_CS_MEM_SIZE_REG_16M (9)
#define LBC_CS_MEM_SIZE_REG_32M (10)
#define LBC_CS_MEM_SIZE_REG_64M (11)
#define LBC_CS_MEM_SIZE_REG_128M (12)
#define LBC_CS_MEM_SIZE_REG_256M (13)
#define LBC_CS_MEM_SIZE_REG_512M (14)
#define LBC_CS_MEM_SIZE_REG_1G (15)
#define LBC_CS_MEM_SIZE_REG_2G (16)
#define LBC_CS_MEM_SIZE_REG_4G (17)

typedef struct lbc_cs_ctrl {
	volatile unsigned int mem_size :  5;
	volatile unsigned int data_width :  2;
	volatile unsigned int data_order :  1;
	volatile unsigned int byte_order :  1;
	volatile unsigned int rdy_mode :  1;
	volatile unsigned int rdy_pol :  1;
	volatile unsigned int addr_offset :  1;
	volatile unsigned int lbctl_en :  1;
	volatile unsigned int page_en :  1;
	volatile unsigned int page_size :  2;
	volatile unsigned int rdy_tout_en :  1;
	volatile unsigned int rble :  1;
	volatile unsigned int reserved :  14;
} LBC_CS_CTRL;

#define LBC_REG_RSV_MAX_NUM 4
#define LBC_REG_CRE_MAX_NUM 4
typedef struct lbc_reg_region {
	volatile unsigned int cs_base[LBC_CS_MAX_NUM];
	volatile unsigned int cs_base_reserved[LBC_REG_RSV_MAX_NUM];
	volatile LBC_CS_CTRL cs_ctrl[LBC_CS_MAX_NUM];
	volatile LBC_CS_CTRL cs_ctrl_creserved[LBC_REG_CRE_MAX_NUM];
} LBC_REG_REGION;

struct hisi_lbc_cs {
	unsigned int index;
	spinlock_t lock;
	void __iomem *cs_base;
	unsigned int size;
	unsigned int width; /* width */
	unsigned int shift; /* address shift */
};

struct hisi_lbc_dev {
	unsigned char is_reg_remaped;
	struct device *dev;
	void __iomem *regs_base;	  /* localbus regs base addr */
	struct hisi_lbc_cs cs[LBC_CS_MAX_NUM];
};

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
#define __ACCESS_ONCE(x) ({ \
	__maybe_unused typeof(x) __var = (__force typeof(x)) 0; \
	(volatile typeof(x) *)&(x); })
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))
#endif

#endif
