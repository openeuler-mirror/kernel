/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_STAT_LAYOUT_H
#define NBL_STAT_LAYOUT_H

#define NBL_STAT_OP_INFO_OFF		0x0040
#define NBL_STAT_OP_DMA_ADDR_L_OFF	0x0044
#define NBL_STAT_OP_DMA_ADDR_H_OFF	0x0048
#define NBL_STAT_FUNC_ID_OFF		0x004c
#define NBL_STAT_OP_ERR_OPCODE_EN_OFF	0x0050

#define NBL_STAT_MOD_INDEX		25
#define NBL_STAT_MOD_REG_SIZE		(448 * 1024)

#define NBL_STAT_REG_ADDR(base, off)	((base) + (off))

#endif /* NBL_STAT_LAYOUT_H */
