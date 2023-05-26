/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2022. All rights reserved.
 * File name: Cfg_mgt_comm_pub.h
 * Version No.: Draft
 * Generation date: 2016 year 05 month 07 day
 * Latest modification:
 * Function description: Header file for communication between the: Host and FW
 * Function list:
 * Modification history:
 * 1. Date: 2016 May 07
 * Modify content: Create a file.
 */
#ifndef CFG_MGT_COMM_PUB_H
#define CFG_MGT_COMM_PUB_H

#include "mgmt_msg_base.h"

enum servic_bit_define {
	SERVICE_BIT_NIC       = 0,
	SERVICE_BIT_ROCE      = 1,
	SERVICE_BIT_VBS       = 2,
	SERVICE_BIT_TOE       = 3,
	SERVICE_BIT_IPSEC     = 4,
	SERVICE_BIT_FC        = 5,
	SERVICE_BIT_VIRTIO    = 6,
	SERVICE_BIT_OVS       = 7,
	SERVICE_BIT_NVME      = 8,
	SERVICE_BIT_ROCEAA    = 9,
	SERVICE_BIT_CURRENET  = 10,
	SERVICE_BIT_PPA       = 11,
	SERVICE_BIT_MIGRATE   = 12,
	SERVICE_BIT_MAX
};

#define CFG_SERVICE_MASK_NIC        (0x1 << SERVICE_BIT_NIC)
#define CFG_SERVICE_MASK_ROCE       (0x1 << SERVICE_BIT_ROCE)
#define CFG_SERVICE_MASK_VBS        (0x1 << SERVICE_BIT_VBS)
#define CFG_SERVICE_MASK_TOE        (0x1 << SERVICE_BIT_TOE)
#define CFG_SERVICE_MASK_IPSEC      (0x1 << SERVICE_BIT_IPSEC)
#define CFG_SERVICE_MASK_FC         (0x1 << SERVICE_BIT_FC)
#define CFG_SERVICE_MASK_VIRTIO     (0x1 << SERVICE_BIT_VIRTIO)
#define CFG_SERVICE_MASK_OVS        (0x1 << SERVICE_BIT_OVS)
#define CFG_SERVICE_MASK_NVME       (0x1 << SERVICE_BIT_NVME)
#define CFG_SERVICE_MASK_ROCEAA     (0x1 << SERVICE_BIT_ROCEAA)
#define CFG_SERVICE_MASK_CURRENET   (0x1 << SERVICE_BIT_CURRENET)
#define CFG_SERVICE_MASK_PPA        (0x1 << SERVICE_BIT_PPA)
#define CFG_SERVICE_MASK_MIGRATE    (0x1 << SERVICE_BIT_MIGRATE)

/* Definition of the scenario ID in the cfg_data, which is used for SML memory allocation. */
enum scenes_id_define {
	SCENES_ID_FPGA_ETH              = 0,
	SCENES_ID_FPGA_TIOE             = 1,  /* Discarded */
	SCENES_ID_STORAGE_ROCEAA_2x100  = 2,
	SCENES_ID_STORAGE_ROCEAA_4x25   = 3,
	SCENES_ID_CLOUD                 = 4,
	SCENES_ID_FC                    = 5,
	SCENES_ID_STORAGE_ROCE          = 6,
	SCENES_ID_COMPUTE_ROCE          = 7,
	SCENES_ID_STORAGE_TOE           = 8,
	SCENES_ID_MAX
};

/* struct cfg_cmd_dev_cap.sf_svc_attr */
enum {
	SF_SVC_FT_BIT = (1 << 0),
	SF_SVC_RDMA_BIT = (1 << 1),
};

enum cfg_cmd {
	CFG_CMD_GET_DEV_CAP = 0,
	CFG_CMD_GET_HOST_TIMER = 1,
};

struct cfg_cmd_host_timer {
	struct mgmt_msg_head head;

	u8 host_id;
	u8 rsvd1;

	u8 timer_pf_num;
	u8 timer_pf_id_start;
	u16 timer_vf_num;
	u16 timer_vf_id_start;
	u32 rsvd2[8];
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
	u8 timer_en;
	u8 host_valid_bitmap;
	u8 rsvd_host;

	u16 svc_cap_en;
	u16 max_vf;
	u8 flexq_en;
	u8 valid_cos_bitmap;
	/* Reserved for func_valid_cos_bitmap */
	u8 port_cos_valid_bitmap;
	u8 rsvd_func1;
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
	u8 master_host_id;
	u8 srv_multi_host_mode;
	u8 virtio_vq_size;

	u32 rsvd_func3[5];

	/* l2nic */
	u16 nic_max_sq_id;
	u16 nic_max_rq_id;
	u16 nic_default_num_queues;
	u16 rsvd1_nic;
	u32 rsvd2_nic[2];

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
	u16 ipsec_max_cq;
	u16 rsvd_ipsec1;
	u32 rsvd_ipsec[2];

	/* OVS */
	u32 ovs_max_qpc;
	u32 rsvd_ovs1[3];

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
	u16 vbs_max_volq;
	u16 rsvd0_vbs;
	u32 rsvd1_vbs[3];

	u16 fake_vf_start_id;
	u16 fake_vf_num;
	u32 fake_vf_max_pctx;
	u16 fake_vf_bfilter_start_addr;
	u16 fake_vf_bfilter_len;
	u32 rsvd_glb[8];
};

#endif
