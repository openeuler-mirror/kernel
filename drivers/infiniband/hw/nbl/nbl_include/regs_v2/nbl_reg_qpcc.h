/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_QPCC_LAYOUT_H
#define NBL_QPCC_LAYOUT_H

#define NBL_QPCC_IDLE_BLOCK_FIFO_THR_HIGH_OFF	0x0244
#define NBL_QPCC_IDLE_BLOCK_FIFO_THR_LOW_OFF	0x0248
#define NBL_QPCC_CLR_CAM_AFULL_THR_OFF		0x0258

#define NBL_QPCC_CACHE_DEPTH			128

#define NBL_QPCC_REG_ADDR(base, off)		((base) + (off))

#endif /* NBL_QPCC_LAYOUT_H */
