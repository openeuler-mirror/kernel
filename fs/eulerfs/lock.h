/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef EUFS_LOCK_H
#define EUFS_LOCK_H

#include "euler_def.h"

static inline void eufs_inode_mark_lock_transferable(struct inode *inode)
{
	struct eufs_inode_info *vi = EUFS_I(inode);

	vi->i_lock_transferred = I_TRANS_AVAIL;
}

static inline void eufs_inode_wait_lock_transfer_done(struct inode *inode)
{
	struct eufs_inode_info *vi = EUFS_I(inode);

	while (cmpxchg(&vi->i_lock_transferred, I_TRANS_AVAIL, I_TRANS_NONE) !=
	       I_TRANS_AVAIL)
		cond_resched();
}

/* return true on success, false on failure */
static inline bool eufs_inode_mark_lock_transferring(struct inode *inode)
{
	struct eufs_inode_info *vi = EUFS_I(inode);

	return (cmpxchg(&vi->i_lock_transferred, I_TRANS_AVAIL,
			I_TRANS_LOCKED) == I_TRANS_AVAIL);
}

static inline void eufs_inode_lock_transfer_done(struct inode *inode)
{
	eufs_inode_mark_lock_transferable(inode);
}

#endif /* EUFS_LOCK_H */
