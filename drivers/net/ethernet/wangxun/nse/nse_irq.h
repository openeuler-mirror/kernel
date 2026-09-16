/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_IRQ_H_
#define _NSE_IRQ_H_

int nse_init_interrupt_scheme(struct nse_pf *pf);
void nse_clear_interrupt_scheme(struct nse_pf *pf);

int nse_get_irq_num(struct nse_pf *pf, int idx);

int nse_set_itr_interval(struct nse_hw *hw, u16 irq, u32 interval_in_us);
int nse_set_intrl_interval(struct nse_hw *hw, u16 irq, u32 interval_in_us);

#define NSE_ITR_INTERVAL_MIN_USEC	2
#define NSE_ITR_INTERVAL_MAX_USEC	8190
#define NSE_ITR_INTERVAL_8K			124
#define NSE_ITR_INTERVAL_20K		50
#define NSE_ITR_INTERVAL_DEFAULT	NSE_ITR_INTERVAL_20K

#define NSE_INTRL_INTERVAL_NO_USEC	0
#define NSE_INTRL_INTERVAL_MIN_USEC	4
#define NSE_INTRL_INTERVAL_MAX_USEC	252

#endif
