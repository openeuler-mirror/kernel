/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2023, NEBULARMATRIX */

#ifndef NBL_LAG_H
#define NBL_LAG_H

#include "regs_v2/nbl_reg_ddmux.h"

#define NBL_MAX_LAG_ID 1
#define NBL_MAX_PORT_ID 3

#define NBL_ETH_DPORT 0x0

int nbl_init_lag(struct nbl_device *nbl_dev,
		struct nbl_core_export *core_info);
void nbl_deinit_lag(struct nbl_device *nbl_dev,
		struct nbl_core_export *core_info);
void nbl_set_rdma_mp_en(struct nbl_pci_f *rf, bool mp_en);

#endif /* NBL_LAG_H */
