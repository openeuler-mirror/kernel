/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_inject_reg.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef _SXE2_DRV_RDMA_INJECT_REG_H_
#define _SXE2_DRV_RDMA_INJECT_REG_H_

#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
s32 sxe2_drv_inject_reg(struct sxe2_rdma_pci_f *dev);

void sxe2_drv_inject_unreg(struct sxe2_rdma_pci_f *dev);
#endif
#endif
