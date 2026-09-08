/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_DEBUGFS_H__
#define __UBASEPROXY_DEBUGFS_H__

#include "ubaseproxy_dev.h"

#define ubaseproxy_get_ubase_root_dentry(adev) ubase_diag_debugfs_root(adev)

enum ubaseproxy_dbg_dentry_type {
	/* must be the last entry. */
	UBASEPROXY_DBG_DENTRY_ROOT = 0,
};

int ubaseproxy_dbg_init(struct auxiliary_device *adev);
void ubaseproxy_dbg_uninit(struct auxiliary_device *adev);

#endif  /* __UBASEPROXY_DEBUGFS_H__ */
