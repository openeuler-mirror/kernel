/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_TXMR_LAYOUT_H
#define NBL_TXMR_LAYOUT_H

#define NBL_TXMR_FMR_NOFENCE_OFF		0x00a8

#define NBL_TXMR_FMR_NOFENCE_MASK		0x1
#define NBL_TXMR_READ_RESP_NOCHECK_MASK		0x4

#define NBL_TXMR_REG_ADDR(base, off)		((base) + (off))

#endif /* NBL_TXMR_LAYOUT_H */
