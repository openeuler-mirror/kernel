/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_pd.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_RDMA_PD_H__
#define __SXE2_DRV_RDMA_PD_H__

#include "sxe2_compat.h"

#ifdef ALLOC_PD_V1
struct ib_pd *sxe2_kalloc_pd(struct ib_device *ibdev, struct ib_ucontext *ibucontext,
									struct ib_udata *udata);
#else
int sxe2_kalloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
#endif

#ifdef DEALLOC_PD_VER_3
void sxe2_kdealloc_pd(struct ib_pd *pd, struct ib_udata *udata);
#elif defined DEALLOC_PD_VER_4
int sxe2_kdealloc_pd(struct ib_pd *pd);
#else
int sxe2_kdealloc_pd(struct ib_pd *pd, struct ib_udata *udata);
#endif
#endif
