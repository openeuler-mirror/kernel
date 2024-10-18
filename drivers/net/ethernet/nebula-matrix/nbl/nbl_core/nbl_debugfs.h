/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEBUGFS_H_
#define _NBL_DEBUGFS_H_

#include "nbl_core.h"

#define NBL_DEBUGFS_MGT_TO_COMMON(debugfs_mgt)		((debugfs_mgt)->common)
#define NBL_DEBUGFS_MGT_TO_DISP_OPS_TBL(debugfs_mgt)	((debugfs_mgt)->disp_ops_tbl)
#define NBL_DEBUGFS_MGT_TO_DISP_OPS(debugfs_mgt)					\
	(NBL_DEBUGFS_MGT_TO_DISP_OPS_TBL(debugfs_mgt)->ops)
#define NBL_DEBUGFS_MGT_TO_DISP_PRIV(debugfs_mgt)					\
	(NBL_DEBUGFS_MGT_TO_DISP_OPS_TBL(debugfs_mgt)->priv)
#define NBL_DEBUGFS_MGT_TO_CHAN_OPS_TBL(debugfs_mgt)	((debugfs_mgt)->chan_ops_tbl)
#define NBL_DEBUGFS_MGT_TO_CHAN_OPS(debugfs_mgt)					\
	(NBL_DEBUGFS_MGT_TO_CHAN_OPS_TBL(debugfs_mgt)->ops)
#define NBL_DEBUGFS_MGT_TO_CHAN_PRIV(debugfs_mgt)					\
	(NBL_DEBUGFS_MGT_TO_CHAN_OPS_TBL(debugfs_mgt)->priv)

struct nbl_debugfs_mgt {
	struct dentry *nbl_debugfs_root;
	struct nbl_dispatch_ops_tbl *disp_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_common_info *common;
	/* Ring fops related info */
	u16 ring_index;
	u16 ring_num;
	bool pmd_debug;
};

#endif
