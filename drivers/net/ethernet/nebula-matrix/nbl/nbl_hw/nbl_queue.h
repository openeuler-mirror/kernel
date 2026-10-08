/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_QUEUE_H_
#define _NBL_QUEUE_H_

#include "nbl_resource.h"

#define NBL_QID_MAP_NOTIFY_ADDR_SHIFT		(9)
#define NBL_QID_MAP_NOTIFY_ADDR_LOW_PART_LEN	(23)

#define NBL_RSS_RET_MAX_SIZE			(128)
#define NBL_RSS_KEY_NUM				(16)

#define NBL_QUEUE_MGT_TO_MAX_QUEUE(queue_mgt)		((queue_mgt)->max_queue)
#define NBL_QUEUE_MGT_TO_QUEUE_BASE_IDX(queue_mgt)	((queue_mgt)->queue_base_idx)

#define NBL_ADAPT_DESC_GOTHER_LEVEL1_TH	(1000000) /* 1000k  */
#define NBL_ADAPT_DESC_GOTHER_LEVEL1_DOWNGRADE_TH	(700000) /* 700k */
#define NBL_ADAPT_DESC_GOTHER_LEVEL0		(0)
#define NBL_ADAPT_DESC_GOTHER_LEVEL1		(1)

#define NBL_ADAPT_DESC_GOTHER_LEVEL0_TIMEOUT	(0x12c)
#define NBL_ADAPT_DESC_GOTHER_LEVEL1_TIMEOUT	(0x960)
#define NBL_ADAPT_DESC_GOTHER_LEVEL0_TIMEOUT_DRACO	(0xE1)
#define NBL_ADAPT_DESC_GOTHER_LEVEL1_TIMEOUT_DRACO	(0x708)

#define NBL_SHAPING_WGT_MAX			(255)

#endif
