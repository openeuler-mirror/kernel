/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_INTERRUPT_H_
#define _NBL_INTERRUPT_H_

#include "nbl_resource.h"

#define NBL_INTR_MGT_TO_MSIX_MAP_TABLE_MAX_ENTRIES(intr_mgt) \
	((intr_mgt)->msix_map_table_max_entries)
#define NBL_INTR_MGT_TO_MAX_NET_INTERRUPT(intr_mgt)	((intr_mgt)->max_net_interrupt)
#define NBL_INTR_MGT_TO_MAX_OTHER_INTERRUPT(intr_mgt)	((intr_mgt)->max_other_interrupt)
#define NBL_INTR_MGT_TO_MSIX_TABLE_RANGE_OFT(intr_mgt)	((intr_mgt)->msix_table_range_oft)

/* leonis */
#define NBL_MSIX_MAP_TABLE_MAX_ENTRIES_LEONIS	(1024)
#define NBL_MAX_NET_INTERRUPT_LEONIS		(1024)
#define NBL_MAX_OTHER_INTERRUPT_LEONIS		(4096)

/* draco */
#define NBL_MSIX_MAP_TABLE_MAX_ENTRIES_DRACO	(512)
/* pf 16 rdma, vf 3*128 rdma, pf and vf 129 mailbox, PF has 1 ipsec、1 macsec、1 abnormal irq,
 * PF2-PF7 24
 */
#define NBL_INTR_SUPPRESS_LEVEL1_THRESHOLD	(100000) /* 100k pps */
#define NBL_INTR_SUPPRESS_LEVEL1_DOWNGRADE_THRESHOLD	(60000) /* 60kpps */
#define NBL_INTR_SUPPRESS_LEVEL0		(0)
#define NBL_INTR_SUPPRESS_LEVEL1		(1)

#define NBL_INTR_SUPPRESS_LEVEL1_THRESHOLD	(100000) /* 100k pps */
#define NBL_INTR_SUPPRESS_LEVEL2_THRESHOLD	(4000000) /* 4M pps */
#define NBL_INTR_SUPPRESS_LEVEL1_DOWNGRADE_THRESHOLD	(60000) /* 60kpps */
#define NBL_INTR_SUPPRESS_LEVEL2_DOWNGRADE_THRESHOLD	(2400000) /* 2.4Mpps */
#define NBL_INTR_SUPPRESS_LEVEL0		(0)
#define NBL_INTR_SUPPRESS_LEVEL1		(1)
#define NBL_INTR_SUPPRESS_LEVEL2		(2)

#define NBL_INTR_SUPPRESS_LEVEL0_PNUM		(0)
#define NBL_INTR_SUPPRESS_LEVEL1_25G_PNUM	(8)
#define NBL_INTR_SUPPRESS_LEVEL1_100G_PNUM	(8)
#define NBL_INTR_SUPPRESS_LEVEL2_100G_PNUM	(24)
#define NBL_INTR_SUPPRESS_LEVEL0_RATE		(0)
#define NBL_INTR_SUPPRESS_LEVEL1_25G_RATE	(1)
#define NBL_INTR_SUPPRESS_LEVEL1_DRACO_25G_RATE	(5)
#define NBL_INTR_SUPPRESS_LEVEL1_DRACO_25G_PNUM	(16)
#define NBL_INTR_SUPPRESS_LEVEL1_100G_RATE	(1)
#define NBL_INTR_SUPPRESS_LEVEL2_100G_RATE	(3)

#endif
