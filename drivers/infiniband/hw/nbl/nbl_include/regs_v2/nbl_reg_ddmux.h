/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_DDMUX_LAYOUT_H
#define NBL_DDMUX_LAYOUT_H

/* Register offsets from base */
#define NBL_DDMUX_HOLB_OFF			0x0088

/* HOLB register values */
#define NBL_DDMUX_HOLB_ENABLE			0x3
#define NBL_DDMUX_HOLB_DISABLE			0x2

/* Register address macro */
#define NBL_DDMUX_REG_ADDR(base, off)		((base) + (off))

#endif /* NBL_DDMUX_LAYOUT_H */
