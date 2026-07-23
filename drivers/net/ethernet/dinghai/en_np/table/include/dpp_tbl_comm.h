/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_COMM_H
#define DPP_TBL_COMM_H

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_tbl_mc.h"
#include "dpp_tbl_mac.h"
#include "dpp_tbl_qid.h"
#include "dpp_tbl_port.h"
#include "dpp_tbl_bc.h"
#include "dpp_tbl_promisc.h"

#define VF_ACTIVE(VPORT) ((VPORT & 0x0800) >> 11)
#define EPID(VPORT) ((VPORT & 0x7000) >> 12)
#define FUNC_NUM(VPORT) ((VPORT & 0x0700) >> 8)
#define VFUNC_NUM(VPORT) ((VPORT & 0x00FF))

#define PF_VQM_VFID_OFFSET (1152)
#define IS_PF(VPORT) (!VF_ACTIVE(VPORT))
#define VQM_VFID(VPORT)                                                              \
	(IS_PF(VPORT) ? (PF_VQM_VFID_OFFSET + (EPID(VPORT) * 8) + FUNC_NUM(VPORT)) : \
			      ((EPID(VPORT) * 256) + VFUNC_NUM(VPORT)))

#define OWNER_PF_VQM_VFID(VPORT) (PF_VQM_VFID_OFFSET + (EPID(VPORT) * 8) + FUNC_NUM(VPORT))
#define OWNER_PF_VPORT(VPORT) (((EPID(VPORT)) << 12) | ((FUNC_NUM(VPORT)) << 8))

#define VQM_VFID_MAX_NUM (2048)

struct dpp_vport_mgr_t {
	struct dpp_vport_bc_table_t bc_table;
	struct dpp_vport_mc_table_t mc_table;
	struct dpp_vport_uc_promisc_table_t uc_promisc_table;
	struct dpp_vport_uc_promisc_table_t mc_promisc_table;
	struct zxic_mutex_t *table_lock[DPP_DEV_SDT_ID_MAX];
};

struct MAC_VPORT_INFO {
	u8 addr[6];
	u16 vport;
	u16 sriov_vlan_tpid;
	u16 sriov_vlan_id;
};

struct MC_PF_FLAG_MGR {
	u8 mc_addr[6];
	u16 pf_flag;
};

u32 dpp_data_print(u8 *data, u32 len);
u32 dpp_vport_attr_value_show(void);
u32 dpp_vport_mgr_init(struct dpp_pf_info_t *pf_info);
u32 dpp_vport_mgr_release(struct dpp_pf_info_t *pf_info);
u32 dpp_vport_table_lock(struct dpp_pf_info_t *pf_info, u32 sdt_no,
			 struct zxic_mutex_t **table_lock);
u32 dpp_vport_table_unlock(struct dpp_pf_info_t *pf_info, u32 sdt_no);
u32 dpp_vport_bc_table_get(struct dpp_pf_info_t *pf_info, struct dpp_vport_bc_table_t **bc_table);
u32 dpp_vport_mc_table_get(struct dpp_pf_info_t *pf_info, struct dpp_vport_mc_table_t **mc_table);
u32 dpp_vport_uc_promisc_table_get(struct dpp_pf_info_t *pf_info,
				   struct dpp_vport_uc_promisc_table_t **promisc_table);
u32 dpp_vport_mc_promisc_table_get(struct dpp_pf_info_t *pf_info,
				   struct dpp_vport_uc_promisc_table_t **promisc_table);
u32 dpp_vport_get_by_vqm_vfid(u16 pf_vport, u32 vqm_vfid, u16 *vport);
u32 dpp_vport_get_by_mc_bitmap(u16 pf_vport, u32 group_id, u64 mc_bitmap, u16 vport[64],
			       u32 *vport_num);
BOOLEAN dpp_vport_in_mc_bitmap(u32 vport, u64 mc_bitmap);
#endif
