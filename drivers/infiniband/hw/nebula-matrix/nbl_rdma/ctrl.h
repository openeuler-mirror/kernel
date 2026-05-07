/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_IB_CTRL_H
#define NBL_IB_CTRL_H

#define NBL_CQPSQ_SD_TYPE GENMASK_ULL(47, 45)
#define NBL_CQPSQ_SD_NUM GENMASK_ULL(44, 38)
#define NBL_CQPSQ_SD_START GENMASK_ULL(37, 25)

enum nbl_status_code nbl_sc_dev_init(struct nbl_sc_dev *dev, struct nbl_device_init_info *info);

#endif /* NBL_IB_CTRL_H */
