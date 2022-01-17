/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_CFG_CMD_H
#define SPHW_CFG_CMD_H

#include "sphw_mgmt_msg_base.h"

enum cfg_cmd {
	CFG_CMD_GET_DEV_CAP = 0,
};

struct cfg_cmd_dev_cap {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1;

	/* Public resources */
	u8 host_id;
	u8 ep_id;
	u8 er_id;
	u8 port_id;

	u16 host_total_func;
	u8 host_pf_num;
	u8 pf_id_start;
	u16 host_vf_num;
	u16 vf_id_start;
	u8 host_oq_id_mask_val;
	u8 rsvd_host[3];

	u16 svc_cap_en;
	u16 max_vf;
	u8 flexq_en;
	u8 valid_cos_bitmap;
	/* Reserved for func_valid_cos_bitmap */
	u16 rsvd_func1;
	u32 rsvd_func2;

	u8 sf_svc_attr;
	u8 func_sf_en;
	u8 lb_mode;
	u8 smf_pg;

	u32 max_conn_num;
	u16 max_stick2cache_num;
	u16 max_bfilter_start_addr;
	u16 bfilter_len;
	u16 hash_bucket_num;

	/* shared resource */
	u8 host_sf_en;
	u8 rsvd2_sr[3];
	u32 host_pctx_num;
	u32 host_ccxt_num;
	u32 host_scq_num;
	u32 host_srq_num;
	u32 host_mpt_num;

	/* l2nic */
	u16 nic_max_sq_id;
	u16 nic_max_rq_id;
	u32 rsvd_nic[3];

	/* RoCE */
	u32 roce_max_qp;
	u32 roce_max_cq;
	u32 roce_max_srq;
	u32 roce_max_mpt;
	u32 roce_max_drc_qp;

	u32 roce_cmtt_cl_start;
	u32 roce_cmtt_cl_end;
	u32 roce_cmtt_cl_size;

	u32 roce_dmtt_cl_start;
	u32 roce_dmtt_cl_end;
	u32 roce_dmtt_cl_size;

	u32 roce_wqe_cl_start;
	u32 roce_wqe_cl_end;
	u32 roce_wqe_cl_size;
	u8 roce_srq_container_mode;
	u8 rsvd_roce1[3];
	u32 rsvd_roce2[5];

	/* IPsec */
	u32 ipsec_max_sactx;
	u32 rsvd_ipsec[3];

	/* OVS */
	u32 ovs_max_qpc;
	u16 fake_vf_start_id;
	u8 fake_vf_num;
	u8 rsvd_ovs1;
	u32 rsvd_ovs2[2];

	/* ToE */
	u32 toe_max_pctx;
	u32 toe_max_cq;
	u16 toe_max_srq;
	u16 toe_srq_id_start;
	u16 toe_max_mpt;
	u16 toe_max_cctxt;
	u32 rsvd_toe[2];

	/* FC */
	u32 fc_max_pctx;
	u32 fc_max_scq;
	u32 fc_max_srq;

	u32 fc_max_cctx;
	u32 fc_cctx_id_start;

	u8 fc_vp_id_start;
	u8 fc_vp_id_end;
	u8 rsvd_fc1[2];
	u32 rsvd_fc2[5];

	/* VBS */
	u32 rsvd_vbs[4];

	u32 rsvd_glb[11];
};

#endif
