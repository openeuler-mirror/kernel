/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_FLOW_TBL_MGR_H
#define XSC_FLOW_TBL_MGR_H

#include "common/xsc_core.h"

#define XSC_GROUP_DEFAULT_PRIORITY	64
#define XSC_GROUP_MAX_PRIORITY		65

enum xsc_flow_direction {
	FLOW_DIR_INGRESS = 0,
	FLOW_DIR_EGRESS,
	FLOW_DIR_MAX,
};

#define FLOW_GRP_MAX	128
#define FLOW_GRP_DEFAULT_MAX_ENTRIES	256
#define FLOW_GRP_DEFAULT_NODEPORT_NUM	64
#define FLOW_GRP_DEFAULT_ENTRIES_NUM	64

enum xsc_flow_resv_grp {
	FLOW_GRP_INGRESS_1 = 1,
	FLOW_GRP_INGRESS_2,
	FLOW_GRP_INGRESS_DEFAULT,
	FLOW_GRP_EGRESS_1,
	FLOW_GRP_EGRESS_2,
	FLOW_GRP_EGRESS_3,
	FLOW_GRP_EGRESS_4,
	FLOW_GRP_EGRESS_5,
	FLOW_GRP_EGRESS_6,
	FLOW_GRP_EGRESS_7,
	FLOW_GRP_EGRESS_8,
	FLOW_GRP_EGRESS_DEFAULT,
	FLOW_GRP_RESV_MAX,
};

#define TBL_BIT(tbl_type)	(1ULL << (tbl_type))

enum xsc_offload_tbl {
	XSC_OFLD_IPAT_TBL,
	XSC_OFLD_EPAT_TBL,
	XSC_OFLD_RSS_HASH_TBL,
	XSC_OFLD_IPLMT_TBL,
	XSC_OFLD_WCT_PF_TBL,
	XSC_OFLD_EM_PF_TBL,
	XSC_OFLD_PCT_TBL,
	XSC_OFLD_WCT_TBL,
	XSC_OFLD_WCT_CHAIN_TBL,
	XSC_OFLD_EM_TBL,
	XSC_OFLD_EM_FAT_TBL,
	XSC_OFLD_NONE_EM_FAT_TBL,
	XSC_OFLD_TNL_ENCAP_TBL,
	XSC_OFLD_ECP_TNL_HDR_TBL,
	XSC_OFLD_ECP_TNL_TP_TBL,
	XSC_OFLD_ECP_SIP_TBL,
	XSC_OFLD_ECP_DIP_TBL,
	XSC_OFLD_ECP_SMAC_TBL,
	XSC_OFLD_ECP_DMAC_TBL,
	XSC_OFLD_ECP_TPID_TBL,
	XSC_OFLD_ECP_DPORT_TBL,
	XSC_OFLD_CT_TBL,
	XSC_OFLD_MDF_SIP_TBL,
	XSC_OFLD_MDF_DIP_TBL,
	XSC_OFLD_MDF_SMAC_TBL,
	XSC_OFLD_MDF_DMAC_TBL,
	XSC_OFLD_MDF_TPID_TBL,
	XSC_OFLD_MIRROR_TBL,
	XSC_OFLD_ECP_MIR_HDR_TBL,
	XSC_OFLD_PRG_ACT_IDX_TBL,
	XSC_OFLD_PRG_ACT0_TBL,
	XSC_OFLD_PRG_ACT1_TBL,
	XSC_OFLD_PRG_ACT2_TBL,
	XSC_OFLD_IACL_TBL,
	XSC_OFLD_EACL_TBL,
	XSC_OFLD_EACL_CNT_TBL,
	XSC_OFLD_ECP_ERSPAN_TBL,
	XSC_OFLD_MAX_TBL_NUM,
};

enum xsc_res_mgr_tbl {
	XSC_RES_MGR_IPAT_TBL,
	XSC_RES_MGR_EPAT_TBL,
	XSC_RES_MGR_RSS_HASH_TBL,
	XSC_RES_MGR_IPLMT_TBL,
	XSC_RES_MGR_WCT_PF_TBL,
	XSC_RES_MGR_EM_PF_TBL,
	XSC_RES_MGR_PCT_TBL,
	XSC_RES_MGR_WCT_TBL,
	XSC_RES_MGR_WCT_CHAIN_TBL,
	XSC_RES_MGR_EM_TBL,
	XSC_RES_MGR_EM_FAT_TBL,
	XSC_RES_MGR_NONE_EM_FAT_TBL,
	XSC_RES_MGR_TNL_ENCAP_TBL,
	XSC_RES_MGR_ECP_TNL_HDR_TBL,
	XSC_RES_MGR_ECP_TNL_TP_TBL,
	XSC_RES_MGR_ECP_IP_TBL,
	XSC_RES_MGR_ECP_MAC_TBL,
	XSC_RES_MGR_ECP_TPID_TBL,
	XSC_RES_MGR_ECP_DPORT_TBL,
	XSC_RES_MGR_CT_TBL,
	XSC_RES_MGR_MDF_IP_TBL,
	XSC_RES_MGR_MDF_MAC_TBL,
	XSC_RES_MGR_MDF_TPID_TBL,
	XSC_RES_MGR_MIRROR_TBL,
	XSC_RES_MGR_ECP_MIR_HDR_TBL,
	XSC_RES_MGR_PRG_ACT_IDX_TBL,
	XSC_RES_MGR_PRG_ACT0_TBL,
	XSC_RES_MGR_PRG_ACT1_TBL,
	XSC_RES_MGR_PRG_ACT2_TBL,
	XSC_RES_MGR_IACL_TBL,
	XSC_RES_MGR_EACL_TBL,
	XSC_RES_MGR_EACL_CNT_TBL,
	XSC_RES_MGR_ECP_ERSPAN_TBL,
	XSC_RES_MGR_MAX_TBL_NUM,
};

enum xsc_tbl_index_mgr_type {
	XSC_TBL_INDEX_LOCAL_MGR = 0,
	XSC_TBL_INDEX_NONE_LOCAL_MGR,
};

struct xsc_flow_tbl_res_mgr {
	u32 base_idx;
	u32 max_entries;
};

struct xsc_flow_tbl_ofld {
	u8 res_mgr_tbl;
};

struct xsc_flow_tbl_res {
	unsigned long *bitmap;
	u32 base_idx;
	u32 max_entries;
	spinlock_t lock; /* protect flow table resource */
};

struct xsc_hw_tbl {
	enum xsc_res_mgr_tbl res_tbl_type;
	enum xsc_tbl_index_mgr_type idx_mgr_type;
	u32 idx;
	atomic_t refcnt;
	void *key;
	void *action_data;
	void *raw_data;		/* just for search */

	struct list_head list;
};

struct xsc_hw_tbl_head {
	struct list_head entry_list;
	spinlock_t lock; /* protect hw table head */
};

struct xsc_flow_tbl_mgr {
	struct xsc_flow_tbl_res res_tables[XSC_RES_MGR_MAX_TBL_NUM];
	struct xsc_flow_tbl_ofld ofld_tables[XSC_OFLD_MAX_TBL_NUM];
	struct xsc_hw_tbl_head *hw_tbl_list[XSC_RES_MGR_MAX_TBL_NUM];
};

struct xsc_flow_grp_idx_range {
	u32	max_entries;
	u32	start_idx;
	u32	end_idx;
};

struct xsc_flow_grp_res {
	unsigned long *bitmap;
	u32 base_idx;
	u32 max_entries;
	spinlock_t lock; /* protect flow group resource */
	bool initialized;
	atomic_t refcnt;
};

struct xsc_flow_grp_res_mgr {
	struct xsc_flow_grp_res grp_res[FLOW_GRP_RESV_MAX];
};

struct xsc_flow_tbl_mgr *xsc_flow_tbl_mgr_alloc(struct xsc_core_device *dev);
void xsc_flow_tbl_mgr_free(struct xsc_flow_tbl_mgr *tbl_mgr);
int xsc_hw_tbl_alloc_idx(struct xsc_core_device *dev, u8 ofld_tbl_id, u32 *index);
void xsc_hw_tbl_free_idx(struct xsc_core_device *dev, struct xsc_hw_tbl *hw_tbl, u8 ofld_tbl_id);
struct xsc_hw_tbl *xsc_hw_tbl_create(struct xsc_core_device *dev, u8 ofld_tbl_id,
				     const void *data, u16 data_len, u32 entry_idx,
				     enum xsc_tbl_index_mgr_type idx_mgr_type);
void xsc_hw_tbl_free(struct xsc_core_device *dev, struct xsc_hw_tbl *hw_tbl);
struct xsc_hw_tbl *xsc_hw_tbl_find(struct xsc_core_device *dev,
				   u8 ofld_tbl_id, const void *data, u16 data_len);
int xsc_hw_tbl_fill_em_key(struct xsc_core_device *dev,
			   struct xsc_hw_tbl *hw_tbl, void *data, u16 data_len);
int xsc_hw_tbl_fill_action_data(struct xsc_core_device *dev,
				struct xsc_hw_tbl *hw_tbl,
				void *data, u16 data_len);
struct xsc_hw_tbl *xsc_hw_tbl_find_with_idx(struct xsc_core_device *dev,
					    u8 ofld_tbl_id, u32 idx);

struct xsc_flow_grp_res_mgr *xsc_flow_grp_res_mgr_alloc(struct xsc_core_device *dev);
void xsc_flow_grp_res_mgr_free(struct xsc_flow_grp_res_mgr *grp_res_mgr);
int xsc_flow_grp_res_alloc(struct xsc_core_device *dev, u32 grp_id);
bool xsc_flow_grp_res_free(struct xsc_core_device *dev, u32 grp_id);
int xsc_flow_grp_res_alloc_idx(struct xsc_core_device *dev, u8 grp_id, u32 *index);
void xsc_flow_grp_res_free_idx(struct xsc_core_device *dev, u8 grp_id, u32 index);
int xsc_flow_grp_idx_range_init(struct xsc_core_device *dev,
				u32 pct_start, u32 pct_end);

int xsc_hw_tbl_bulk_alloc(struct xsc_core_device *dev, u8 ofld_tbl_id, u32 *base_id, u32 count);
int xsc_hw_tbl_bulk_free(struct xsc_core_device *dev, u8 ofld_tbl_id, u32 base_id, u32 count);
#endif

