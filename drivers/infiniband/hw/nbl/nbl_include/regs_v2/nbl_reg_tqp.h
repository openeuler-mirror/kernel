/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_TQP_LAYOUT_H
#define NBL_TQP_LAYOUT_H

#define NBL_TQP_SRP_TLP_TIMER_UNIT_OFF		0x0904
#define NBL_TQP_FLUSH_CONF_OFF			0x0c44
#define NBL_TQP_FLUSH_DONE_OFF			0x0c48

#define NBL_TQP_SRP_TLP_TIMER_UNIT_DFT_RNIC400	0x0500
#define NBL_TQP_FLUSH_FUNCTION_ID_MASK		0x3
#define NBL_TQP_FLUSH_VALID_SHIFT		31

#define NBL_TQP_REG_ADDR(base, off)		((base) + (off))

#endif /* NBL_TQP_LAYOUT_H */
