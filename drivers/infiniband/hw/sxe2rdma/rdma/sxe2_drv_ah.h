/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_ah.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_AH_H__
#define __SXE2_DRV_AH_H__

#define ECN_CODE_PT_MASK       3
#define ECN_CODE_PT_VAL	       2
#define CQP_COMPL_WAIT_TIME_MS 10
#define CQP_TIMEOUT_THRESHOLD  500

#ifdef CREATE_AH_VER_3
struct ib_ah *sxe2_kcreate_ah(struct ib_pd *ibpd, struct rdma_ah_attr *attr,
		    struct ib_udata *udata);
#elif defined CREATE_AH_VER_2
int sxe2_kcreate_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr, u32 flags,
		    struct ib_udata *udata);
#else
int sxe2_kcreate_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata);
#endif

#ifdef DESTROY_AH_VER_3
void sxe2_kdestroy_ah(struct ib_ah *ibah, u32 ah_flags);
#elif defined DESTROY_AH_VER_4
int sxe2_kdestroy_ah(struct ib_ah *ibah);
#else
int sxe2_kdestroy_ah(struct ib_ah *ibah, u32 ah_flags);
#endif
int sxe2_kquery_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr);
#endif
