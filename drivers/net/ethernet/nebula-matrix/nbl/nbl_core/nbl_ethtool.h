/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_ETHTOOL_H_
#define _NBL_ETHTOOL_H_

#include "nbl_service.h"

#define NBL_SELF_TEST_TIME_GAP 5 /* 5 seconds */
#define NBL_SELF_TEST_BUFF_SIZE 128
#define NBL_SELF_TEST_PADDING_DATA_1 0xFF
#define NBL_SELF_TEST_PADDING_DATA_2 0xA5
#define NBL_SELF_TEST_POS_1 3
#define NBL_SELF_TEST_POS_2 10
#define NBL_SELF_TEST_POS_3 12
#define NBL_SELF_TEST_BYTE_1 0xBE
#define NBL_SELF_TEST_BYTE_2 0xAF
#define NBL_SELF_TEST_PKT_NUM 32

#define NBL_SELF_TEST_Q_NUM 1

enum nbl_eth_lb_enable {
	NBL_ETH_LB_OFF,
	NBL_ETH_LB_ON,
};

enum nbl_ethtool_lb_test_err_code {
	NBL_LB_ERR_NON = 0,
	NBL_LB_ERR_RING_SETUP,
	NBL_LB_ERR_LB_MODE_SETUP,
	NBL_LB_ERR_SKB_ALLOC,
	NBL_LB_ERR_TX_FAIL,
	NBL_LB_ERR_RX_FAIL
};

void nbl_serv_update_stats(struct nbl_service_mgt *serv_mgt, bool ethtool);
void nbl_serv_setup_ethtool_ops(struct nbl_service_ops *serv_ops_tbl);

#endif
