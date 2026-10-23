/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2022, nebula-matrix Limited */

#ifndef NBL_IB_PT_CFG_H
#define NBL_IB_PT_CFG_H

#include "main.h"

void nbl_try_init_net_tc_tbl_pt(struct nbl_device *dev, bool pt_en_changed,
				bool pt_nak_pri_changed, bool cc_oamack_changed,
				bool new_val);
int nbl_pt_debugfs_init(struct nbl_device *dev);
void nbl_pt_debugfs_cleanup(struct nbl_device *dev);
int __nbl_pt_debugfs_init(struct nbl_device *dev);
void __nbl_pt_debugfs_cleanup(struct nbl_device *dev);

#endif /* NBL_IB_PT_CFG_H */
