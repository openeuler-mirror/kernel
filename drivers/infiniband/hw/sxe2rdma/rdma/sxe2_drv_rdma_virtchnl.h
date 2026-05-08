/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_virtchnl.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_RDMA_VIRTCHNL_H
#define SXE2_DRV_RDMA_VIRTCHNL_H

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_stats.h"
#include "sxe2_drv_aux.h"

#define SXE2_VCHNL_CHNL_VER_V1	1
#define SXE2_VCHNL_CHNL_VER_MIN SXE2_VCHNL_CHNL_VER_V1
#define SXE2_VCHNL_CHNL_VER_MAX SXE2_VCHNL_CHNL_VER_V1

#define SXE2_VCHNL_OP_GET_RDMA_CAPS_MIN_SIZE  1
#define SXE2_VCHNL_OP_GET_RCMS_FCN_V1	      1
#define SXE2_VCHNL_OP_PUT_RCMS_FCN_V1	      1
#define SXE2_VCHNL_OP_VLAN_PARSING_V1	      1
#define SXE2_VCHNL_OP_GET_RDMA_CAPS_V1	      1
#define SXE2_VCHNL_OP_INIT_VF_RCMS_V1	      1
#define SXE2_VCHNL_OP_GATHER_STATS_V1	      1
#define SXE2_VCHNL_OP_MANAGE_QSET_NODE_V1     1
#define SXE2_VCHNL_OP_PBL_SET_FPTE_V1	      1
#define SXE2_VCHNL_OP_PBL_CLEAR_FPTE_V1	      1
#define SXE2_VCHNL_OP_GET_VF_OBJ_INFO_V1      1
#define SXE2_VCHNL_OP_UPDATE_FPTE_V1	      1
#define SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED_V1 1
#define SXE2_VCHNL_INVALID_VF_IDX	     0xFFFF

#define SXE2_FPTE_PA_MASK	0xFFFFFFFFFFFFF000
#define SXE2_FPTE_PA_VALID_MASK 0x1

enum sxe2_vchnl_opcode {
	SXE2_VCHNL_OP_GET_VER =
		0,
	SXE2_VCHNL_OP_GET_RCMS_FCN =
		1,
	SXE2_VCHNL_OP_PUT_RCMS_FCN =
		2,
	SXE2_VCHNL_OP_INIT_VF_RCMS =
		3,
	SXE2_VCHNL_OP_VLAN_PARSING =
		4,
	SXE2_VCHNL_OP_GET_RDMA_CAPS =
		5,
	SXE2_VCHNL_OP_GATHER_STATS =
		6,
	SXE2_VCHNL_OP_MANAGE_QSET_NODE =
		7,
	SXE2_VCHNL_OP_PBL_SET_FPTE =
		8,
	SXE2_VCHNL_OP_PBL_CLEAR_FPTE =
		9,
	SXE2_VCHNL_OP_GET_VF_OBJ_INFO =
		10,
	SXE2_VCHNL_OP_UPDATE_FPTE =
		11,
	SXE2_VCHNL_OP_GET_PORT_ACTIVE_SPEED =
		12,
};

enum sxe2_rdma_stats_vf_txrx {
	SXE2_RDMA_STATS_VF_NONE = 0,
	SXE2_RDMA_STATS_VF_TX	= 1,
	SXE2_RDMA_STATS_VF_RX	= 2,
};

struct sxe2_vchnl_mq_compl_func_tab_ret {
	union {
		u32 val;
		struct {
			u32 rel_fid : 6;
			u32 valid : 1;
			u32 rsvd : 25;
		};
	};
};

struct sxe2_vchnl_work {
	struct work_struct work;
	u8 vf_msg_buf[SXE2_VCHNL_MAX_MSG_SIZE];
	struct sxe2_rdma_ctx_dev *dev;
	u16 vf_id;
	u16 len;
	u64 session_id;
};

struct sxe2_vsi_init_info {
	struct sxe2_rdma_ctx_dev *dev;
	void *back_vsi;
	struct sxe2_rdma_l2params *params;
	u16 exception_lan_q;
	u16 pf_data_vsi_num;
	enum sxe2_rdma_vm_vf_type vm_vf_type;
	int (*register_qset)(
		struct sxe2_rdma_ctx_vsi *vsi, struct sxe2_rdma_qset *qset1,
		struct sxe2_rdma_qset *qset2);
	void (*unregister_qset)(
		struct sxe2_rdma_ctx_vsi *vsi, struct sxe2_rdma_qset *qset1,
		struct sxe2_rdma_qset *qset2);
};

#pragma pack(push, 1)

struct sxe2_vchnl_manage_rcms_func_table_wqe {
	u64 rsv0;
	u64 rsv1;
	u64 rsv2;
	u64 vf_id : 8;
	u64 rsv3 : 24;
	u64 op : 6;
	u64 rsv4 : 24;
	u64 free_func_table : 1;
	u64 wqe_valid : 1;
	u64 rsv5;
	u64 rsv6;
	u64 rsv7;
	u64 rsv8;
};

struct sxe2_vchnl_op_buf {
	u16 op_code;
	u16 op_ver;
	u16 buf_len;
	u16 rsvd;
	u64 op_ctx;
	u8 buf[];
};

struct sxe2_vchnl_resp_buf {
	u64 op_ctx;
	u16 buf_len;
	s16 op_ret;
	u16 rsvd[2];
	u8 buf[];
};

struct sxe2_vchnl_pbl_set_fpte_info {
	u32 fpte_idx;
	u64 page_pa;
};

struct sxe2_vchnl_pbl_clear_fpte_info {
	u32 fpte_idx;
	u32 pble_cnt;
};

struct sxe2_vchnl_rdma_caps {
	u8 hw_rev;
	u16 mq_timeout_s;
	u16 mq_def_timeout_s;
	u16 mq_hw_push_len;
};

struct sxe2_vchnl_manage_qet_node_info {
	u16 qset_id;
	u8 user_pri;
	bool add;
};

struct sxe2_vchnl_init_info {
	struct workqueue_struct *vchnl_wq;
	struct sxe2_rdma_vchnl_if *vchnl_if;
	enum sxe2_rdma_vers hw_rev;
	bool privileged;
};

struct sxe2_vchnl_init_vf_rcms_resp {
	u32 first_fpte_index;
	u32 max_fpte_index;
	u32 max_fpte_cnt;
	u32 fpte_needed;
	u32 max_cc_qp_cnt;
	u32 max_ceqs;
	u32 max_db_page_num;
	u32 db_bar_addr;
	u32 obj_max_cnt[SXE2_RCMS_OBJ_MAX];
	u16 pmf_index;
	u32 pf_max_ceqs;
};

struct sxe2_vchnl_vf_obj_info {
	u32 size;
	u64 base;
};

struct sxe2_vchnl_vf_obj_resp {
	struct sxe2_vchnl_vf_obj_info
		obj_info[SXE2_RCMS_OBJ_MAX];
};

struct sxe2_vchnl_req {
	struct sxe2_vchnl_op_buf *vchnl_msg;
	void *parm;
	u32 vf_id;
	u16 parm_len;
	u16 resp_len;
};

struct sxe2_vchnl_req_init_info {
	void *req_parm;
	void *resp_parm;
	u16 req_parm_len;
	u16 resp_parm_len;
	u16 op_code;
	u16 op_ver;
};

#pragma pack(pop)

int sxe2_vchnl_ctx_init(struct sxe2_rdma_ctx_dev *dev,
			struct sxe2_vchnl_init_info *info);

int sxe2_vchnl_req_get_ver(struct sxe2_rdma_ctx_dev *dev,
			   struct aux_ver_info *ver_res);

int sxe2_vchnl_req_get_rcms_fcn(struct sxe2_rdma_ctx_dev *dev);

int sxe2_vchnl_req_put_rcms_fcn(struct sxe2_rdma_ctx_dev *dev);

int sxe2_vchnl_req_get_vlan_parsing_cfg(struct sxe2_rdma_ctx_dev *dev,
					u8 *vlan_parse_en);

int sxe2_vchnl_req_get_caps(struct sxe2_rdma_ctx_dev *dev);

int sxe2_vchnl_req_init_vf_rcms(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_vchnl_init_vf_rcms_resp *init_vf_rcms_resp);

int sxe2_vchnl_send_pf(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
		       u16 len, u64 session_id);

int sxe2_vchnl_recv_pf(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
		       u16 len, u64 session_id);

int sxe2_vchnl_recv_vf(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
		       u16 len, u64 session_id);

int sxe2_vchnl_receive(struct aux_core_dev_info *cdev_info, u32 vf_id, u8 *msg,
		       u16 len, u64 session_id);

int sxe2_vchnl_send_sync(struct sxe2_rdma_ctx_dev *dev, u8 *msg, u16 len,
			 u8 *recv_msg, u16 recv_len);

int sxe2_vchnl_manage_rcms_pm_func_table(struct sxe2_mq_ctx *mq,
					 struct sxe2_rcms_fcn_info *info,
					 u64 scratch, bool post_sq);

int sxe2_vchnl_req_gather_stats(struct sxe2_rdma_ctx_dev *dev,
				struct sxe2_rdma_gather_stats *gather_stats_req);

int sxe2_vchnl_req_manage_qet_node(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_vchnl_manage_qet_node_info *qset_info);
int sxe2_vchnl_req_set_pbl_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
				u64 page_pa);

int sxe2_vchnl_req_clear_pbl_fpte(struct sxe2_rdma_ctx_dev *dev, u32 fpte_idx,
				  u32 pble_cnt);

void sxe2_vchnl_pf_put_vf_rcms_fcn(struct sxe2_rdma_ctx_dev *dev,
				   struct sxe2_rdma_vchnl_dev **vc_dev);

void sxe2_vchnl_put_vf_dev(struct sxe2_rdma_vchnl_dev **vc_dev);

struct sxe2_rdma_vchnl_dev *
sxe2_vchnl_find_vc_dev(struct sxe2_rdma_ctx_dev *dev, u16 vf_id);

int sxe2_vchnl_req_get_vf_obj_info(struct sxe2_rdma_ctx_dev *dev,
				   struct sxe2_vchnl_vf_obj_resp *vf_obj_resp);
int sxe2_vchnl_req_update_fpte(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_rcms_vf_update_fptes_info *update_vf_fpte_info);

int sxe2_vchnl_req_get_port_active_speed(
	struct sxe2_rdma_ctx_dev *dev,
	u32 *port_active_speed);

int sxe2_vchnl_req_send_sync(struct sxe2_rdma_ctx_dev *dev,
			     struct sxe2_vchnl_req_init_info *info);

#endif
