/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ptp.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_PTP_H
#define HINIC5_PTP_H
#define PTP_DEBUG

#include "ossl_knl.h"
#include "hinic5_nic_dev.h"

union hinic5_hw_ts32 {
	struct {
		u32 time_ns : 30;
		u32 time_s : 2;
	};
	u32 val;
};

enum hinic5_ptp_flags {
	HINIC5_PTP_TX_BUSY,
};

#ifdef PTP_DEBUG
#define ptp_dbg(format, ...) pr_info("[PTP]" format, ##__VA_ARGS__)
#else
#define ptp_dbg(format, ...)
#endif

#define PTP_CLOCK_MAX_ADJ_TIME_VALUE 0x3FFFFFFF
#define PTP_SKB_HWTSTAMPS_LENGTH	0x4
#define PTP_WR_UP_EN_FLAG BIT(0)
#define PTP_RD_UP_EN_FLAG BIT(1)

int hinic5_ptp_tx_process(struct hinic5_nic_dev *nic_dev, struct sk_buff *skb);
void hinic5_ptp_rx_hwtstamp(struct hinic5_nic_dev *nic_dev, struct sk_buff *skb);
int hinic5_ptp_set_ts_config(struct hinic5_nic_dev *nic_dev, struct ifreq *ifr);
int hinic5_ptp_get_ts_config(struct hinic5_nic_dev *nic_dev, struct ifreq *ifr);
void hinic5_ptp_init(struct hinic5_nic_dev *nic_dev);
void hinic5_ptp_deinit(struct hinic5_nic_dev *nic_dev);
#endif
