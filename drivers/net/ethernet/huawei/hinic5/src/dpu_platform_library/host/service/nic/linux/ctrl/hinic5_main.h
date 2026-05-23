/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_main.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_MAIN_H
#define	HINIC5_MAIN_H

#define HINIC5_NIC_DEV_WQ_NAME		"hinic5_nic_dev_wq"

#define DEFAULT_MSG_ENABLE		(NETIF_MSG_DRV | NETIF_MSG_LINK)

#define QID_MASKED(q_id, nic_dev)	((q_id) & ((nic_dev)->num_qps - 1))
#define WATCHDOG_TIMEOUT	5

#define HINIC5_SQ_DEPTH			1024
#define HINIC5_RQ_DEPTH			1024

#define HW_DEFAULT_COS_IS_VALID(cos) ((cos) & BIT(3))
#define HW_DEFAULT_COS_VALID_BIT 0x7

enum hinic5_rx_buff_len {
	RX_BUFF_VALID_2KB		= 2,
	RX_BUFF_VALID_4KB		= 4,
	RX_BUFF_VALID_8KB		= 8,
};

#define CONVERT_UNIT			1024

#endif
