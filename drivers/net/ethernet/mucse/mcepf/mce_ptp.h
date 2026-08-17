/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef __MCE_PTP_H__
#define __MCE_PTP_H__
#include <linux/ptp_clock_kernel.h>

int mce_ptp_get_ts_config(struct mce_pf *pf, struct ifreq *ifr);
int mce_ptp_set_ts_config(struct mce_pf *pf, struct ifreq *ifr);
int mce_ptp_register(struct mce_pf *pf);
int mce_ptp_restore(struct mce_pf *pf);
void mce_ptp_unregister(struct mce_pf *pf);
void mce_ptp_get_rx_hwstamp(struct mce_pf *pf, struct mce_rx_desc_up *desc,
			    struct sk_buff *skb);
void mce_tx_hwtstamp_work(struct work_struct *work);

/* hardware ts can't so fake ts from the software clock */
#define PTP_HWTX_TIME_VALUE_MASK GENMASK(31, 0)
#define MCE_RX_SEC_MASK GENMASK(30, 0)
#define MCE_RX_NSEC_MASK GENMASK(30, 0)

#endif
