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

#ifndef EUFS_INODE_H
#define EUFS_INODE_H

extern struct inode *eufs_iget(struct super_block *sb, struct eufs_inode *pi);

extern void eufs_put_inode(struct inode *inode);

extern void eufs_evict_inode(struct inode *inode);

extern int eufs_write_inode(struct inode *inode,
			     struct writeback_control *wbc);

extern int eufs_notify_change(struct dentry *dentry, struct iattr *attr);

extern int eufs_file_getattr(const struct path *path, struct kstat *stat,
			      u32 request_mask, unsigned int query_flags);

extern void eufs_set_inode_flags(struct inode *inode, unsigned int flags);

extern unsigned int eufs_get_inode_flags(struct inode *inode,
					  struct eufs_inode *pi);

extern void eufs_sync_pinode(struct inode *inode, struct eufs_inode *pi,
			      bool evict);

extern struct inode *pre_inodes_get(struct dentry *dentry, struct inode *dir,
				    umode_t mode, bool special, dev_t rdev);

extern void eufs_inode_size_write(struct inode *inode, loff_t new_size);

#endif /* EUFS_INODE_H */
