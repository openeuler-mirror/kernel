/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ethtool_port_stats.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_ETHTOOL_PORT_STATS_H
#define	HINIC5_ETHTOOL_PORT_STATS_H

#include <linux/kernel.h>
#include <linux/ethtool.h>
#include "ossl_knl_linux.h"
#include "hinic5_nic_dev.h"
#include "hinic5_rx.h"
#include "hinic5_tx.h"
#include "nic_cfg_comm.h"
#include "mag_mpu_cmd_defs.h"

#define FPGA_PORT_COUNTER 0
#define EVB_PORT_COUNTER  1

struct hinic5_stats {
	char name[ETH_GSTRING_LEN];
	u32 size;
	int offset;
};

struct hinic5_port_link_stats {
	u64 link_down_events_phy;
};

#define HINIC5_NIC_STAT(_stat_item) { \
	.name = #_stat_item, \
	.size = FIELD_SIZEOF(struct hinic5_nic_stats, _stat_item), \
	.offset = offsetof(struct hinic5_nic_stats, _stat_item) \
}

#define HINIC5_RXQ_STAT(_stat_item) { \
	.name = "rxq%d_"#_stat_item, \
	.size = FIELD_SIZEOF(struct hinic5_rxq_stats, _stat_item), \
	.offset = offsetof(struct hinic5_rxq_stats, _stat_item) \
}

#define HINIC5_TXQ_STAT(_stat_item) { \
	.name = "txq%d_"#_stat_item, \
	.size = FIELD_SIZEOF(struct hinic5_txq_stats, _stat_item), \
	.offset = offsetof(struct hinic5_txq_stats, _stat_item) \
}

#ifdef HAVE_XDP_SUPPORT
#define HINIC5_XDPTXQ_STAT(_stat_item) { \
	.name = "txq%d_"#_stat_item, \
	.size = FIELD_SIZEOF(struct hinic5_xdptxq_stats, _stat_item), \
	.offset = offsetof(struct hinic5_xdptxq_stats, _stat_item) \
}
#endif

#define HINIC5_FUNC_STAT(_stat_item) {	\
	.name = #_stat_item, \
	.size = FIELD_SIZEOF(struct hinic5_vport_stats, _stat_item), \
	.offset = offsetof(struct hinic5_vport_stats, _stat_item) \
}

#define HINIC5_PORT_STAT(_stat_item) { \
	.name = #_stat_item, \
	.size = FIELD_SIZEOF(struct mag_cmd_port_stats, _stat_item), \
	.offset = offsetof(struct mag_cmd_port_stats, _stat_item) \
}

#define HINIC5_PORT_LINK_STAT(_stat_item) { \
	.name = #_stat_item, \
	.size = FIELD_SIZEOF(struct hinic5_port_link_stats, _stat_item), \
	.offset = offsetof(struct hinic5_port_link_stats, _stat_item) \
}

#endif
