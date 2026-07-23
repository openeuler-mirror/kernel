/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PKT_CAP_TBL_H_
#define _DPP_PKT_CAP_TBL_H_

#include "zxic_common.h"
#include "dpp_apt_se_api.h"
#include "dpp_drv_acl.h"

#define DH_PKT_CAP_POINT_IN_MF_GLOBAL_OFFSET (18U)
#define DH_PKT_CAP_POINT_IN_MF_GLOBAL_LENGTH (6U)

#define DH_PKT_CAP_POINT_NORMAL_RULE_NUM (10U)
#define DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM (2U)

#define DH_PKT_CAP_TCAM_ITEM_NUM                                   \
	(DH_PKT_CAP_POINT_MAX * DH_PKT_CAP_POINT_NORMAL_RULE_NUM + \
	 DH_PKT_CAP_POINT_RDMA_RX * DH_PKT_CAP_POINT_KEY_WORD_RULE_NUM)

#define DH_PKT_CAP_SPEED_MIN (0U)
#define DH_PKT_CAP_SPEED_MAX (300000U)
#define DH_PKT_CAP_SPEED_DEFAULT (10000U)

enum zxdh_pkt_cap_point {
	DH_PKT_CAP_POINT_PANEL_RX = 0,
	DH_PKT_CAP_POINT_PANEL_TX = 1,
	DH_PKT_CAP_POINT_VQM_RX = 2,
	DH_PKT_CAP_POINT_VQM_TX = 3,
	DH_PKT_CAP_POINT_RDMA_RX = 4,
	DH_PKT_CAP_POINT_RDMA_TX = 5,
	DH_PKT_CAP_POINT_MAX = 6,
};

enum zxdh_pkt_cap_mode {
	DH_PKT_CAP_MODE_NORMAL = 0,
	DH_PKT_CAP_MODE_KEY_WORD = 1,
	DH_PKT_CAP_MODE_MAX = 2,
};

struct zxdh_pkt_cap_enable_status {
	u8 panel_rx_enable_status;
	u8 panel_tx_enable_status;
	u8 vqm_rx_enable_status;
	u8 vqm_tx_enable_status;
	u8 rdma_rx_enable_status;
	u8 rdma_tx_enable_status;
};

struct zxdh_pkt_cap_normal_configure {
	u16 rsv : 6;
	u16 sourceid : 1;
	u16 dmac : 1;
	u16 smac : 1;
	u16 ethtype : 1;
	u16 sip : 1;
	u16 dip : 1;
	u16 sport : 1;
	u16 dport : 1;
	u16 protocol : 1;
	u16 qp : 1;
};

struct zxdh_pkt_cap_rule {
	u16 dst_vqm_vfid;
	struct zxdh_pkt_cap_normal_configure rule_config;
	u32 tcam_index;
	struct zxdh_pkt_cap_key pkt_cap_key;
};
u32 dpp_pkt_capture_init(struct dpp_pf_info_t *pf_info);
u32 dpp_pkt_capture_uninit(struct dpp_pf_info_t *pf_info);
u32 dpp_pkt_capture_enable(struct dpp_pf_info_t *pf_info, enum zxdh_pkt_cap_point capture_pkt_flag);
u32 dpp_pkt_capture_disable(struct dpp_pf_info_t *pf_info,
			    enum zxdh_pkt_cap_point capture_pkt_flag);
u32 dpp_pkt_capture_disable_all(struct dpp_pf_info_t *pf_info);
u32 dpp_pkt_capture_enable_status_get(struct dpp_pf_info_t *pf_info,
				      struct zxdh_pkt_cap_enable_status *enable_status);
u32 dpp_pkt_capture_rule_index_to_tcam_index(u32 rule_index, enum zxdh_pkt_cap_mode rule_mode,
					     enum zxdh_pkt_cap_point capture_pkt_flag,
					     u32 *tcam_index);
u32 dpp_pkt_capture_tcam_index_to_rule_index(u32 tcam_index, enum zxdh_pkt_cap_mode *rule_mode,
					     u32 *rule_index);
u32 dpp_pkt_capture_item_insert(struct dpp_pf_info_t *pf_info, struct zxdh_pkt_cap_rule *rule);
u32 dpp_pkt_capture_item_delete(struct dpp_pf_info_t *pf_info, u32 tcam_index);
u32 dpp_pkt_capture_table_dump(struct dpp_pf_info_t *pf_info, struct zxdh_pkt_cap_rule *rule_array,
			       u32 *entry_num);
u32 dpp_pkt_capture_table_flush(struct dpp_pf_info_t *pf_info);
u32 dpp_pkt_capture_speed_set(struct dpp_pf_info_t *pf_info, u32 speed_kbps);
u32 dpp_pkt_capture_speed_get(struct dpp_pf_info_t *pf_info, u32 *speed_kbps);

#endif // !_DPP_PKT_CAP_TBL_H_
