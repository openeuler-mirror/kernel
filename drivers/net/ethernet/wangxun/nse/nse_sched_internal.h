/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_SCHED_INTERNAL_H_
#define _NSE_SCHED_INTERNAL_H_

#include <linux/types.h>

/* NSE_SCHED_FACTOR_TBL_LEN == NSE_SCH_NODE_PARAM_PIR_CIR_MAX_VAL, **MUST** sync change */
#define NSE_SCHED_FACTOR_TBL_LEN						4000

u16 nse_sched_factor_val_to_idx(struct nse_port_info *pi, u16 fint, u16 dfint, u16 dfdf);
void nse_sched_init_factor_tbl(struct nse_port_info *pi);

#endif

