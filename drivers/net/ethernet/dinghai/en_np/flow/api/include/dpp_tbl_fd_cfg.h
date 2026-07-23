/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_TBL_FD_CFG_H
#define DPP_TBL_FD_CFG_H

#include "zxic_common.h"

struct zxdh_fd_cfg_key {
	u8 dmac[6];
	u8 smac[6];
	u32 ethtype;
	u16 cvlan_pri;
	u16 cvlanid;
	u8 sip[16];
	u8 dip[16];
	u8 rsv1;
	u8 tos;
	u8 proto;
	u8 fragment;
	u16 sport;
	u16 dport;
	u32 rsv2;
	u32 vxlan_vni;
	u16 vqm_vfid;
	u16 rsv3;
};

struct zxdh_fd_cfg_key;

struct zxdh_fd_cfg_as_rlt {
	u8 hit_flag;
	u8 action_index;
	u16 action_index2;
	u32 v_qid;
	u32 uplink_fd_id;
	u32 spec_port_vfid;
	u32 count_id;
	u16 hash_alg;
	u16 rss_hash_factor;
	u16 rsv3;
	u16 encap0_index;
};

struct zxdh_fd_cfg_t {
	struct zxdh_fd_cfg_key key;
	struct zxdh_fd_cfg_key mask;
	struct zxdh_fd_cfg_as_rlt as_rlt;
};

u32 dpp_tbl_fd_cfg_add(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle,
		       struct zxdh_fd_cfg_t *p_fd_cfg);
u32 dpp_tbl_fd_cfg_del(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle);
u32 dpp_tbl_fd_cfg_get(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle,
		       struct zxdh_fd_cfg_t *p_fd_cfg);
u32 dpp_tbl_fd_cfg_search(struct dpp_pf_info_t *pf_info, u32 sdt_no, u32 handle,
			  struct zxdh_fd_cfg_t *p_fd_cfg);

#endif
