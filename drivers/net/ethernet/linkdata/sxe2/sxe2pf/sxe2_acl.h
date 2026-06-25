/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_acl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_ACL_H__
#define __SXE2_ACL_H__

#include <linux/types.h>
#include <linux/ethtool.h>

#include "sxe2_cmd.h"
#include "sxe2_mbx_public.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_flow.h"
#include "sxe2_fnav.h"
#include "sxe2_drv_cmd.h"

#define SXE2_FW_MAX_ACTION_MEMORIES 20

#define SXE2_FW_ACL_KEY_WIDTH		    40
#define SXE2_FW_ACL_KEY_WIDTH_BYTES	    5
#define SXE2_FW_ACL_TCAM_DEPTH		    512
#define SXE2_ACL_ENTRY_ALLOC_UNIT	    512
#define SXE2_FW_MAX_CONCURRENT_ACL_TBL	15
#define SXE2_FW_MAX_ACTION_MEMORIES	    20
#define SXE2_FW_MAX_ACTION_ENTRIES	    512
#define SXE2_FW_ACL_LUT_NUM		        16
#define SXE2_AQC_ALLOC_ID_LESS_THAN_4K	0x1000
#define SXE2_AQC_TBL_MAX_ACTION_PAIRS	4
#define SXE2_ACL_MAX_CASCADE_WIDTH      4

#define SXE2_FW_MAX_TCAM_ALLOC_UNITS (SXE2_FW_ACL_TCAM_DEPTH / SXE2_ACL_ENTRY_ALLOC_UNIT)

#define SXE2_FW_ACL_ALLOC_UNITS (SXE2_FW_ACL_LUT_NUM * SXE2_FW_MAX_TCAM_ALLOC_UNITS)

#define SXE2_FW_MAX_ACL_TCAM_ENTRY (SXE2_FW_ACL_TCAM_DEPTH * SXE2_FW_ACL_LUT_NUM)

#define SXE2_ACL_MAX_NUM_ENTRY				2048

#define SXE2_ACL_SCEN_PKT_DIR_IDX_IN_TCAM	0x2
#define SXE2_ACL_SCEN_PID_IDX_IN_TCAM		0x3
#define SXE2_ACL_SCEN_RNG_CHK_IDX_IN_TCAM	0x4

#define SXE2_FW_ACL_BYTE_SEL_BASE		    0x20
#define SXE2_FW_ACL_BYTE_SEL_BASE_PKT_DIR	0x20
#define SXE2_FW_ACL_BYTE_SEL_BASE_PID		0x3E
#define SXE2_FW_ACL_BYTE_SEL_BASE_RNG_CHK	0x3F

#define SXE2_ACL_INVALID_PF_SCEN_NUM        (0x3f)
#define SXE2_ACL_PROF_BYTE_SEL_ELEMS        (30)
#define SXE2_ACL_PROF_BYTE_SEL_START_IDX    (0)

#define SXE2_GEN_FILTER_ID(mark, id) (((u64)(mark) << 32) | ((u64)(id) & 0xFFFFFFFFULL))

struct sxe2_mbx_msg_info;

enum sxe2_acl_fw_action_mdid {
	SXE2_ACL_ACTION_MDID_FLOW_ID = 0,
	SXE2_ACL_ACTION_MDID_PKT_DROP,
	SXE2_ACL_ACTION_MDID_RX_DST_Q,
	SXE2_ACL_ACTION_MDID_RX_DST_Q_REGION,
	SXE2_ACL_ACTION_MDID_RX_DST_VSI,
	SXE2_ACL_ACTION_MDID_CNT_PKT,
	SXE2_ACL_ACTION_MDID_CNT_BYTE,
	SXE2_ACL_ACTION_MDID_CNT_PKT_BYTE,
	SXE2_ACL_ACTION_MDID_NOP,
	SXE2_ACL_ACTION_MDID_MAX,
};

enum sxe2_acl_act_type {
	SXE2_ACL_ACT_DROP,
	SXE2_ACL_ACT_QINDEX,
	SXE2_ACL_ACT_QGROUP,
	SXE2_ACL_ACT_VSI,
	SXE2_ACL_ACT_OTHER,
};

enum sxe2_acl_lut_entry_priority {
	SXE2_ACL_LUT_ENTRY_PRIO_LOW,
	SXE2_ACL_LUT_ENTRY_PRIO_NORMAL,
	SXE2_ACL_LUT_ENTRY_PRIO_HIGH,
	SXE2_ACL_LUT_ENTRY_PRIO_MAX,
};

struct sxe2_acl_tbl_params {
	u16 width;
	u16 depth;

	u8 entry_act_pairs;
};

struct sxe2_acl_act_mem {
	u8 act_mem;
	u8 member_of_tcam;
};

struct sxe2_acl_tbl_info {
	u8 first_tcam;
	u8 last_tcam;
	u16 first_entry;
	u16 last_entry;

	struct list_head scens;
	struct sxe2_acl_tbl_params table_info;
	struct sxe2_acl_act_mem act_mems[SXE2_FW_MAX_ACTION_MEMORIES];

	DECLARE_BITMAP(avail, SXE2_FW_ACL_ALLOC_UNITS);

	u16 id;
	u16 max_slot_cnt;
};

struct sxe2_acl_scen_info {
	struct list_head l_entry;

	DECLARE_BITMAP(acl_act_mem_bitmap, SXE2_FW_MAX_ACTION_MEMORIES);

	DECLARE_BITMAP(acl_entry_bitmap, SXE2_FW_MAX_ACL_TCAM_ENTRY);

	u16 entry_first_index[SXE2_ACL_LUT_ENTRY_PRIO_MAX];
	u16 entry_last_index[SXE2_ACL_LUT_ENTRY_PRIO_MAX];

	u16 scen_id;

	u16 start;
	u16 end;

	u16 width;
	u16 num_entry;
	u8 avail_width;

	u8 pid_idx;
	u8 rnage_chk_idx;
	u8 pkt_dir_idx;
};

struct sxe2_acl_flow_action {
	enum sxe2_acl_act_type type;
	union {
		struct sxe2_acl_act_entry_data acl_act;
		u32 dummy;
	} data;
};

struct sxe2_acl_flow_entry {
	struct list_head l_entry;
	struct sxe2_flow_info_node *flow;
	struct sxe2_acl_flow_action *action;

	void *entry;
	u16 entry_size;
	u16 scen_entry_idx;
};

struct sxe2_acl_flow_cfg {
	struct list_head l_node;
	struct sxe2_fnav_flow_seg *seg;
	u32 filter_cnt;
	enum sxe2_fnav_flow_type flow_type;
};

struct sxe2_acl_context {
	struct sxe2_acl_tbl_info *acl_tbl_info;
	DECLARE_BITMAP(slots, SXE2_ACL_MAX_NUM_ENTRY);
	/* in order to protect the data */
	struct mutex filter_lock;
	struct sxe2_ppp_common_ctxt ppp;
};

struct sxe2_acl_filter {
	struct list_head l_node;
	struct sxe2_fnav_filter_full_key full_key;
	enum sxe2_fnav_flow_type flow_type;
	struct sxe2_acl_flow_entry *flow_entry;
	u64 filter_id;
};

s32 sxe2_acl_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				struct sxe2_adapter *adapter);

s32 sxe2_acl_init(struct sxe2_adapter *adapter);

void sxe2_acl_deinit(struct sxe2_adapter *adapter);

s32 sxe2_fwc_acl_set_scen_prof(struct sxe2_adapter *adapter,
			       struct sxe2_fwc_acl_prof_sel_base_req *prof_sel_req);

s32 sxe2_acl_flow_cfg_add(struct sxe2_vsi *vsi, struct sxe2_acl_flow_cfg *flow_cfg,
			  struct sxe2_fnav_flow_seg *seg);

s32 sxe2_acl_del_filter_by_id(struct sxe2_vsi *vsi, u64 filter_id);

s32 sxe2_acl_lut_entry_add(struct sxe2_vsi *vsi, struct sxe2_acl_filter *filter,
			   struct sxe2_acl_flow_action *acts);

s32 sxe2_com_flow_acl_filter_del(struct sxe2_adapter *adapter, u16 rule_vsi_id,
				 struct sxe2_drv_flow_filter_req *req);

s32 sxe2_com_flow_acl_filter_add(struct sxe2_adapter *adapter, u16 rule_vsi_id,
				 struct sxe2_drv_flow_filter_req *req,
				 struct sxe2_drv_flow_filter_resp *resp);
s32 sxe2_fwc_acl_trace_trigger(struct sxe2_adapter *adapter);

s32 sxe2_fwc_acl_trace_recorder(struct sxe2_adapter *adapter);

s32 sxe2_fwc_acl_dfx_get(struct sxe2_adapter *adapter);

struct sxe2_acl_flow_cfg *
sxe2_acl_find_flow_cfg_by_flow_type(struct sxe2_vsi *vsi,
				    enum sxe2_fnav_flow_type flow_type);

s32 sxe2_acl_del_filter_by_vsi(struct sxe2_vsi *rule_vsi);

void sxe2_acl_flow_cfg_add_list(struct sxe2_vsi *vsi, struct sxe2_acl_flow_cfg *flow_cfg);

void sxe2_vsi_acl_init(struct sxe2_vsi *vsi);

void sxe2_vsi_acl_deinit(struct sxe2_vsi *vsi);

#endif
