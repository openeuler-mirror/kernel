/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cfg_mgmt_mpu_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef CFG_MGMT_MPU_CMD_DEFS_H
#define CFG_MGMT_MPU_CMD_DEFS_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#else
#include "base_type.h"
#endif
#include "mpu_cmd_base_defs.h"

typedef enum {
	SERVICE_BIT_NIC       = 0,
	SERVICE_BIT_ROCE      = 1,
	SERVICE_BIT_VBS       = 2,
	SERVICE_BIT_TOE       = 3,
	SERVICE_BIT_IPSEC     = 4,
	SERVICE_BIT_FC        = 5,
	SERVICE_BIT_VIRTIO    = 6,
	SERVICE_BIT_OVS       = 7,
	SERVICE_BIT_NVME      = 8,
	SERVICE_BIT_ROCEAA    = 9, // TBD to be replaced with SERVICE_BIT_ROCE_MIG
	SERVICE_BIT_CURRENET  = 10, // TBD to be replaced with SERVICE_BIT_VIRTIO_MIG
	SERVICE_BIT_PPA       = 11,
	SERVICE_BIT_MIGRATE   = 12,
	SERVICE_BIT_VROCE     = 13,
	SERVICE_BIT_DMMU      = 14,
	SERVICE_BIT_UB        = 15,
	SERVICE_BIT_ROCE_MIG  = 16,
	SERVICE_BIT_JBOF      = 17,
	SERVICE_BIT_RSV0      = 18,
	SERVICE_BIT_ADV_ROCE  = 19,
	SERVICE_BIT_MACSEC    = 20,
	SERVICE_BIT_PFE       = 21,
	SERVICE_BIT_UBCNET    = 22,
	SERVICE_BIT_CFM       = 23,
	SERVICE_BIT_BIFUR     = 24,
	SERVICE_BIT_HIHTR     = 25,
	SERVICE_BIT_MAX
} servic_bit_define_e;

typedef enum {
	/* 0~31: reserved for servic_bit_define_e */

	EXT_CAP_BEGIN         = 32,
	EXT_CAP_FAKE_VF       = 32,
	EXT_CAP_FW_UPDATE     = 33,
	EXT_CAP_COMM_INFO     = 34,
	EXT_CAP_MAX,
} extend_cap_type_e;

#define CFG_SERVICE_MASK_NIC        (0x1 << SERVICE_BIT_NIC)
#define CFG_SERVICE_MASK_ROCE       (0x1 << SERVICE_BIT_ROCE)
#define CFG_SERVICE_MASK_VBS        (0x1 << SERVICE_BIT_VBS)
#define CFG_SERVICE_MASK_TOE        (0x1 << SERVICE_BIT_TOE)
#define CFG_SERVICE_MASK_IPSEC      (0x1 << SERVICE_BIT_IPSEC)
#define CFG_SERVICE_MASK_FC         (0x1 << SERVICE_BIT_FC)
#define CFG_SERVICE_MASK_VIRTIO     (0x1 << SERVICE_BIT_VIRTIO)
#define CFG_SERVICE_MASK_OVS        (0x1 << SERVICE_BIT_OVS)
#define CFG_SERVICE_MASK_NVME       (0x1 << SERVICE_BIT_NVME)
#define CFG_SERVICE_MASK_ROCEAA     (0x1 << SERVICE_BIT_ROCEAA) // TBD to be replaced with SERVICE_BIT_ROCE_MIG
#define CFG_SERVICE_MASK_CURRENET   (0x1 << SERVICE_BIT_CURRENET) // TBD to be replaced with SERVICE_BIT_VIRTIO_MIG
#define CFG_SERVICE_MASK_PPA        (0x1 << SERVICE_BIT_PPA)
#define CFG_SERVICE_MASK_MIGRATE    (0x1 << SERVICE_BIT_MIGRATE)
#define CFG_SERVICE_MASK_VROCE      (0x1 << SERVICE_BIT_VROCE)
#define CFG_SERVICE_MASK_JBOF       (0x1 << SERVICE_BIT_JBOF)
#define CFG_SERVICE_MASK_DMMU       (0x1 << SERVICE_BIT_DMMU)
#define CFG_SERVICE_MASK_CFM        (0x1 << SERVICE_BIT_CFM)
#define CFG_SERVICE_MASK_UB         (0x1 << SERVICE_BIT_UB)
#define CFG_SERVICE_MASK_MACSEC     (0x1 << SERVICE_BIT_MACSEC)
#define CFG_SERVICE_MASK_BIFUR      (0x1 << SERVICE_BIT_BIFUR)
#define CFG_SERVICE_MASK_HIHTR      (0x1 << SERVICE_BIT_HIHTR)

#define FUNC_PARITY_GPA_SPU_EN 0
#define FUNC_GPA_SPU_DIS 1
#define FUNC_GPA_SPU_EN 2

typedef enum {
	PLATFORMS_ID_ASIC                   = 0,
	PLATFORMS_ID_FPGA                   = 1,
	PLATFORMS_ID_PG                     = 2,
	PLATFORMS_ID_STRG                   = 3,
	PLATFORMS_ID_MAX
} platform_id_e;

/* Definition of the scenario ID in the cfg_data, which is used for SML memory allocation. */
typedef enum {
	SCENES_ID_FPGA_ETH                  = 0,
	SCENES_ID_FPGA_TIOE                 = 1, /* Discarded */
	SCENES_ID_ASIC_STORAGE_ROCEAA_2X100 = 2,
	SCENES_ID_ASIC_STORAGE_ROCEAA_4X25  = 3,
	SCENES_ID_ASIC_CLOUD                = 4,
	SCENES_ID_ASIC_FC                   = 5,
	SCENES_ID_ASIC_STORAGE_ROCE         = 6,
	SCENES_ID_ASIC_COMPUTE_ROCE         = 7,
	SCENES_ID_ASIC_STORAGE_TOE          = 8,
	SCENES_ID_FPGA_UB                   = 9,
	SCENES_ID_FPGA_JBOF                 = 10,
	SCENES_ID_FPGA_CRYPT                = 11,
	SCENES_ID_FPGA_VBS                  = 12,
	SCENES_ID_FPGA_FC                   = 13,
	SCENES_ID_FPGA_TOE                  = 14,
	SCENES_ID_FPGA_NIC                  = 15,
	SCENES_ID_PG_CLOUD                  = 16,
	SCENES_ID_PG_AT_TEST                = 17,
	SCENES_ID_PG_JBOF                   = 18,
	SCENES_ID_ASIC_JBOF                 = 19,
	SCENES_ID_PG_TOE                    = 20,
	SCENES_ID_ASIC_SLT                  = 21,
	SCENES_ID_PG_FC                     = 22,
	SCENES_ID_STRG_NIC                  = 23,
	SCENES_ID_FPGA_OVS                  = 24,
	SCENES_ID_FPGA_ALL1                 = 25,
	SCENES_ID_FPGA_ALL2                 = 26,
	SCENES_ID_ASIC_ALL                  = 27,
	SCENES_ID_MAX
} scenes_id_define_e;

/* Definition of the scenario ID in the cfg_data of V100 */
typedef enum {
	SCENES_ID_V100_FPGA_ETH              = 0,
	SCENES_ID_V100_COMPUTE_STANDARD      = 1,
	SCENES_ID_V100_STORAGE_ROCEAA_2x100  = 2,
	SCENES_ID_V100_STORAGE_ROCEAA_4x25   = 3,
	SCENES_ID_V100_CLOUD                 = 4,
	SCENES_ID_V100_FC                    = 5,
	SCENES_ID_V100_STORAGE_ROCE          = 6,
	SCENES_ID_V100_COMPUTE_ROCE          = 7,
	SCENES_ID_V100_STORAGE_TOE           = 8,
	SCENES_ID_V100_MAX
} scenes_id_v100_define_e;

/* struct cfg_cmd_dev_cap.sf_svc_attr */
enum {
	SF_SVC_FT_BIT = (1 << 0),
	SF_SVC_RDMA_BIT = (1 << 1),
};

/*
 * Detailed information about VF timer.
 * This describes the Fake VF timer info.
 */
struct timer_vf_info_fake {
	u16 timer_normal_vf_num; /* Size from the first Non-Fake VF to the last Non-Fake VF */
	u16 timer_fake_vf_id_start;
	u16 timer_fake_vf_num;   /* Size from the first Fake VF to the last Fake VF */
	u16 rsvd1;

	u32 rsvd[5];
};

/*
 * Detailed information about VF timer.
 * This describes a VF timer segment.
 */
struct timer_vf_info_seg {
	u16 start;
	u16 num;
};

#define TIMER_VF_SEGS_NUM 7
#define TIMER_FAKE_VF_SEG 6

struct cfg_cmd_host_timer {
	struct mgmt_msg_head head;

	u8 host_id;
	u8 rsvd1 : 6;
	/*
	 * Detailed info type about VF timer.
	 * Only one can be set.
	 */
	u8 timer_vf_info_mode_segs : 1; /* VF timer segments */
	u8 timer_vf_info_mode_fake : 1; /* Fake VF timer info */

	u8 timer_pf_num;
	u8 timer_pf_id_start;

	u16 timer_vf_num; /* Total num of VF */
	u16 timer_vf_id_start;

	union {
		struct timer_vf_info_fake fake;
		struct timer_vf_info_seg  segs[TIMER_VF_SEGS_NUM];
	} timer_vf_info;

	u32 rsvd3;
};

struct cfg_cmd_dev_cap {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 svc_cap_en_h;

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

	u16 svc_cap_en; /* svc_cap_en lower 16 bit */
	u16 max_vf;
	u8 flexq_en;
	u8 valid_cos_bitmap;
	/* Reserved for func_valid_cos_bitmap */
	u8 port_cos_valid_bitmap;
	u8 func_gpa_spu_en;
	u8 dev_cos_valid_bitmap;
	u8 dev_default_cos;
	u8 cos_mask_mode;
	u8 rsvd_func2;

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
	u16 vio_func_num; /* virtio + nvme function num, sharing the same cache */
	u16 nvme_qp_num;
	u32 virtio_vq_num;
	u32 rsvd_func4[3];

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
	u8 hyper_qpc_entry_size_en;
	u8 rsvd_roce1[2];
	u32 roce_max_child_ctx_num;
	u32 rsvd_roce2[4];

	/* IPsec */
	u32 ipsec_max_sactxs;
	u16 ipsec_max_cq;
	u16 rsvd_ipsec1;
	u16 ipsec_max_spctxs;
	u16 ipsec_sp_hash_bucket_num;
	u32 ipsec_sa_hash_bucket_num;

	/* OVS */
	u32 ovs_max_qpc;
	u32 rsvd_ovs1[3];

	/* ToE */
	u32 toe_max_pctx;
	u32 toe_max_cq;
	u16 toe_max_srq;
	u16 toe_srq_id_start;
	u16 toe_max_mpt;
	u16 rsvd_toe_1;
	u32 toe_max_cctxt;
	u32 rsvd_toe[1];

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
	u8  vbs_main_pf_enable;
	u8  vbs_vsock_pf_enable;
	u8  vbs_fushion_queue_pf_enable;
	u8  rsvd0_vbs;
	u16 vbs_host_dma_data_cos : 3;
	u16 vbs_vmio_cpy_data_cos : 3;
	u16 vbs_volq_cos : 3;
	u16 rsvd1_vbs : 7;
	u32 vbs_child_ctx_num : 21;
	u32 rsvd2_vbs : 11;
	u32 vbs_hash_bucket_num : 18;
	u32 rsvd3_vbs : 14;

	/* FakeVF */
	u16 fake_vf_start_id;
	u16 fake_vf_num;
	u32 fake_vf_max_pctx;
	u16 fake_vf_bfilter_start_addr;
	u16 fake_vf_bfilter_len;

	/* JBOF */
	u32 rsvd_jbof;
	u32 jbof_hash_bucket_num;
	u32 jbof_max_pctx;
	u32 jbof_max_cctx;

	/* DMMU */
	u16 max_fake_pasid;
	u16 min_fake_pasid;
	u16 dmmu_cl_start;
	u16 dmmu_cl_end;

	/* Rsvd */
	u32 rsvd_glb[2];
};

#define MAX_CAP_LEN_QWORD 2000
struct cfg_cmd_ext_dev_cap {
	struct mgmt_msg_head head;

	u16 func_id;
	u16 rsvd1;

	u8 ext_cap[MAX_CAP_LEN_QWORD];
};

struct cfg_cmd_tlv_hdr {
	u16 type;
	u16 len;
};

struct ub_firmware_caps {
	u32 is_tpf;
	u32 vf_cnt;
	u32 max_jfc;
	u32 max_jfr;
	u32 max_jetty;
	u32 max_jetty_grp;
	u32 max_tp;
	u32 max_tpg;
	u32 max_vtp;
	u32 max_utp;
	u32 max_gid;
	u32 max_mpts;
	u32 max_mtu;
	u32 max_jfrc;
	u32 cqc_entry_sz;
	u32 srqc_entry_sz;
	u32 qpc_entry_sz;
};

struct cfg_roce_ext_caps {
	u32 rsvd_qp;
	u32 rsvd_qp_back;
	u32 rsvd_cq;
	u32 rsvd_cq_back;
	u32 rsvd_srq;
	u32 rsvd_srq_back;
	u32 max_pd;
	u32 max_xrcd;
	u32 max_gid;
};

struct cfg_jbof_ext_caps {
	u32 jbof_hash_bucket_num;
	u32 jbof_max_pctx;
	u32 jbof_max_cctx;
};

struct cfg_fake_vf_ext_caps {
	u32 scqc_fake_vf_ctx_num;
	u32 srqc_fake_vf_ctx_num;
	u32 gid_fake_vf_ctx_num;
	u32 mpt_fake_vf_ctx_num;
	u32 childc_fake_vf_ctx_num;

	u8 qpc_fake_vf_ctx_size_order;
	u8 qpc_fake_vf_ctx_size_order_en;
	u16 fake_vf_parent_func_id; /* Parent function id of the fake vf group */

	u8 fake_vf_lazy_init;
	u8 rsvd1[0x3];

	u32 rsvd[0x5];
};

struct comm_info_ext_cap {
	u8 max_smf_num;
	u8 bat_cid_index_bit_width;

	/* CFM - CCP */
	u16 ccp_child_ctx_sz;   /* 12 bits */
	u32 ccp_max_child_ctx;  /* 20 bits */

	/* SRIOV - ext cap */
	u32 vf_isolation    : 1;  /* The VF communicates directly with the Mgmt */
	u32 rsvd1           : 31;

	u32 rsvd3[0x8];
};

typedef struct mpu_ub_ext_cap {
	struct cfg_cmd_tlv_hdr ub_ext_cap_mgmt;
	struct ub_firmware_caps ub_ext_cap_content;
} mpu_ub_ext_cap_s;

typedef struct mpu_roce_ext_cap {
	struct cfg_cmd_tlv_hdr roce_ext_cap_mgmt;
	struct cfg_roce_ext_caps roce_ext_cap_content;
} mpu_roce_ext_cap_s;

typedef struct mpu_jbof_ext_cap {
	struct cfg_cmd_tlv_hdr jbof_ext_cap_mgmt;
	struct cfg_jbof_ext_caps jbof_ext_cap_content;
} mpu_jbof_ext_cap_s;

typedef struct mpu_fake_vf_ext_cap {
	struct cfg_cmd_tlv_hdr mgmt;
	struct cfg_fake_vf_ext_caps content;
} mpu_fake_vf_ext_cap_s;

typedef struct {
	u32 fw_img_hdr_size;
	u32 fw_tile_text_size;
	u32 rsvd[6];
} cfg_fw_update_ext_caps;

typedef struct mpu_fw_update_ext_cap {
	struct cfg_cmd_tlv_hdr mgmt;
	cfg_fw_update_ext_caps fw_update_caps;
} mpu_fw_update_ext_cap_s;


typedef struct mpu_dev_comm_info_ext_cap {
	struct cfg_cmd_tlv_hdr mgmt;
	struct comm_info_ext_cap comm_info;
} mpu_dev_comm_info_ext_cap_s;

#endif