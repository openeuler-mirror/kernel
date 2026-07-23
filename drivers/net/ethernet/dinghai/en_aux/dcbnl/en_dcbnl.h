/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EN_DCBNL_H__
#define __ZXDH_EN_DCBNL_H__
#include <linux/device.h>

#define ZXDH_DCBNL_OPEN

/* CEE not support */
//#define ZXDH_DCBNL_CEE_SUPPORT

#define ZXDH_DCBNL_INIT_FLAG (0x5a5a5a5a)
#define ZXDH_DCBNL_NULL_ID (0xffffffff)

#define ZXDH_DCBNL_MAX_PRIORITY (8)
#define ZXDH_DCBNL_MAX_TRAFFIC_CLASS (8)

#define ZXDH_DCBNL_MAX_DSCP (64)

#define ZXDH_DCBNL_MAX_BW_ALLOC (100)
#define ZXDH_DCBNL_MAX_WEIGHT (512)

#define ZXDH_DCBNL_RATEUNIT_K (1000)
#define ZXDH_DCBNL_RATEUNIT_M (1000000)
#define ZXDH_DCBNL_RATEUNIT_G (1000000000)
#define ZXDH_DCBNL_MAXRATE_KBITPS (400 * 1000000)
#define ZXDH_DCBNL_MINRATE_KBITPS (64)

#define ZXDH_DCBNL_INITRATE_KBITPS (400 * 1000000)

#define ZXDH_DCBNL_FLOW_RATE_CIR (0)

#define ZXDH_DCBNL_FLOW_RATE_CBS (2000)
#define ZXDH_DCBNL_FLOW_RATE_EBS (4000)
#define ZXDH_DCBNL_PORT_RATE_CBS (4000)

#define ZXDH_DCBNL_FLOW_RATE_CBS_REFRESH (0)
#define ZXDH_DCBNL_FLOW_RATE_EBS_REFRESH (0)

#define ZXDH_DCBNL_FLOW_TDTH (200)
#define ZXDH_DCBNL_FLOW_TDTH_UPF (900)
#define ZXDH_DCBNL_FLOW_TDTH_OPT (500)
#define ZXDH_DCBNL_FLOW_TDTH_DEFAULT (100)

#define ZXDH_DCBNL_CEE_STATE_UP (1)

#define ZXDH_DCBNL_MAX_SE_NODE_NUM (12)
#define ZXDH_DCBNL_MAX_TREE_LEVEL (7)
#define ZXDH_DCBNL_ETS_TREE_ROOT_LEVEL (4)
#define ZXDH_DCBNL_ETS_TREE_FLOW_LEVEL (0)

#define ZXDH_DCBNL_GSCHID_ID_MASK (0xFFFF)
#define ZXDH_DCBNL_GSCHID_ID_SHIFT (0)

#define ZXDH_DCBNL_GET_GSCHID_MSG(val, mask, shift) ((val >> shift) & mask)

#define ZXDH_DCBNL_INVALID_PARA (0xffffffff)

#define MAX_RATE_LIMITED_NUM (8)
enum zxdh_dcbnl_ets_trust {
	ZXDH_DCBNL_ETS_TRUST_PCP = 0,
	ZXDH_DCBNL_ETS_TRUST_DSCP = 1,
};

enum zxdh_dcbnl_ets_tc_tsa {
	ZXDH_DCBNL_VENDOR_TC = 0,
	ZXDH_DCBNL_STRICT_TC = 1,
	ZXDH_DCBNL_ETS_TC = 2,
	ZXDH_DCBNL_ZEROBW_ETS_TC = 3,
};

enum zxdh_dcbnl_ets_node_link_point {
	ZXDH_DCBNL_ETS_NODE_NULL = 0,
	ZXDH_DCBNL_ETS_NODE_VENDOR_C = 1,
	ZXDH_DCBNL_ETS_NODE_STRICT_C = 2,
	ZXDH_DCBNL_ETS_NODE_ETS_C = 3,
	ZXDH_DCBNL_ETS_NODE_ZEROBW_ETS_C = 4,
	ZXDH_DCBNL_ETS_NODE_VENDOR_E = 5,
	ZXDH_DCBNL_ETS_NODE_STRICT_E = 6,
	ZXDH_DCBNL_ETS_NODE_ETS_E = 7,
	ZXDH_DCBNL_ETS_NODE_ZEROBW_ETS_E = 8,
};

enum zxdh_dcbnl_se_flow_node_type {
	ZXDH_DCBNL_ETS_NODE_FQ = 0,
	ZXDH_DCBNL_ETS_NODE_FQ2 = 1,
	ZXDH_DCBNL_ETS_NODE_FQ4 = 2,
	ZXDH_DCBNL_ETS_NODE_FQ8 = 3,
	ZXDH_DCBNL_ETS_NODE_SP = 4,
	ZXDH_DCBNL_ETS_NODE_WFQ = 5,
	ZXDH_DCBNL_ETS_NODE_WFQ2 = 6,
	ZXDH_DCBNL_ETS_NODE_WFQ4 = 7,
	ZXDH_DCBNL_ETS_NODE_WFQ8 = 8,
	ZXDH_DCBNL_ETS_NODE_FLOW = 9,
};

struct zxdh_dcbnl_ets_se_node {
	struct zxdh_dcbnl_ets_se_node *se_next;
	u64 gsch_id;
	u32 node_idx;
	u32 node_type;
	u32 se_id;
	u32 se_link_id;
	u32 se_link_weight;
	u32 se_link_sp;
	u32 link_point;
};

struct zxdh_dcbnl_ets_flow_node {
	struct zxdh_dcbnl_ets_flow_node *flow_next;
	u64 gsch_id;
	u32 flow_id;
	u32 tc_id;
	u32 tc_type;
	u32 tc_tx_bw;
	u32 td_th;
	u32 c_linkid;
	u32 c_weight;
	u32 c_sp;
	u32 c_rate;
	u32 mode;
	u32 e_linkid;
	u32 e_weight;
	u32 e_sp;
	u32 e_rate;
};

struct zxdh_dcbnl_ets_node_list_head {
	struct zxdh_dcbnl_ets_se_node *se_next;
	struct zxdh_dcbnl_ets_flow_node *flow_next;
	u32 node_num;
};

struct zxdh_dcbnl_ets_se_flow_resource {
	u32 numq;
	u32 level;
	u32 flags;
	u32 resource_id;
	u64 gsch_id;
};

struct zxdh_dcbnl_se_tree_config {
	u32 level;
	u32 idx;
	u32 type;
	u32 link_level;
	u32 link_idx;
	u32 link_weight;
	u32 link_sp;
	u32 link_point;
};

struct zxdh_dcbnl_tc_flow_config {
	u32 link_level;
	u32 tc_type;
	u32 tc_tx_bw;
	u32 c_rate;
	u32 e_rate;
	u32 td_th;
};

struct zxdh_dcbnl_tc_flow_shape_para {
	u32 cir;
	u32 cbs;
	u32 db_en;
	u32 eir;
	u32 ebs;
};

struct zxdh_dcbnl_ieee_ets {
	u8 willing;
	u8 ets_cap;
	u8 cbs;
	u8 tc_tx_bw[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u8 tc_tsa[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u8 prio_tc[ZXDH_DCBNL_MAX_PRIORITY];
};

struct zxdh_dcbnl_cee_ets {
	u8 tc_tx_bw[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u8 tc_tsa[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u8 prio_tc[ZXDH_DCBNL_MAX_PRIORITY];
};

struct zxdh_dcbnl_para {
	u32 init_flag;
	u32 trust;
	u32 dscp_app_num;
	u8 dscp2prio[ZXDH_DCBNL_MAX_DSCP];
	u64 tc_maxrate[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	struct zxdh_dcbnl_ieee_ets ets_cfg;
	struct zxdh_dcbnl_cee_ets cee_ets_cfg;
	struct zxdh_dcbnl_ets_node_list_head ets_node_list_head[ZXDH_DCBNL_MAX_TREE_LEVEL];
};

struct zxdh_dcbnl_ets_switch_info {
	u32 cur_ets;
	u32 tc_td_th[ZXDH_DCBNL_MAX_TRAFFIC_CLASS];
	u32 switch_flag;
};

u32 zxdh_dcbnl_initialize(struct net_device *netdev);
u32 zxdh_dcbnl_ets_uninit(struct net_device *netdev);
u32 zxdh_dcbnl_set_tm_pport_mcode_gate_open(struct net_device *netdev);
u32 zxdh_dcbnl_set_tm_pport_mcode_gate_close(struct net_device *netdev);

#endif
