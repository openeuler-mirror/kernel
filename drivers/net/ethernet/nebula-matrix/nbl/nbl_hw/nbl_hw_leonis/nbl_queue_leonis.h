/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_QUEUE_LEONIS_H_
#define _NBL_QUEUE_LEONIS_H_

#include "nbl_resource.h"

#define NBL_QID_MAP_NOTIFY_ADDR_SHIFT		(9)
#define NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN	(23)

#define NBL_ADAPT_DESC_GOTHER_LEVEL1_TH	(1000000) /* 1000k  */
#define NBL_ADAPT_DESC_GOTHER_LEVEL1_DOWNGRADE_TH	(700000) /* 700k */
#define NBL_ADAPT_DESC_GOTHER_LEVEL0		(0)
#define NBL_ADAPT_DESC_GOTHER_LEVEL1		(1)

#define NBL_ADAPT_DESC_GOTHER_LEVEL0_TIMEOUT	(0x12c)
#define NBL_ADAPT_DESC_GOTHER_LEVEL1_TIMEOUT	(0x960)

#endif
