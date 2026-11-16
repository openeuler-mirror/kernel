/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_VIRTCHNL_H
#define NSER_VIRTCHNL_H

#include "hmc.h"

#pragma pack(push, 1)

struct nser_virtchnl_op_buf {
	u16 op_code;
	u16 op_ver;
	u16 buf_len;
	u16 rsvd;
	u64 op_ctx;
	/* Member alignment MUST be maintained above this location */
	u8 buf[];
};

struct nser_virtchnl_resp_buf {
	u64 op_ctx;
	u16 buf_len;
	s16 op_ret_code;
	/* Member alignment MUST be maintained above this location */
	u16 rsvd[2];
	u8 buf[];
};

enum nser_virtchnl_ops {
	NSER_VCHNL_OP_GET_VER = 0,
	NSER_VCHNL_OP_GET_HMC_FCN = 1,
	NSER_VCHNL_OP_PUT_HMC_FCN = 2,
	NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE = 3,
	NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE = 4,
	NSER_VCHNL_OP_GET_STATS = 5,
	NSER_VCHNL_OP_MANAGE_STATS_INST = 6,
	NSER_VCHNL_OP_MCG = 7,
	NSER_VCHNL_OP_UP_MAP = 8,
	NSER_VCHNL_OP_MANAGE_WS_NODE = 9,
	NSER_VCHNL_OP_VLAN_PARSING = 12,
};

#define NSER_VCHNL_CHNL_VER_V0 0
#define NSER_VCHNL_CHNL_VER_V1 1

#define NSER_VCHNL_OP_GET_VER_V0 0
#define NSER_VCHNL_OP_GET_VER_V1 1

#define NSER_VCHNL_OP_GET_HMC_FCN_V0 0
#define NSER_VCHNL_OP_PUT_HMC_FCN_V0 0
#define NSER_VCHNL_OP_ADD_HMC_OBJ_RANGE_V0 0
#define NSER_VCHNL_OP_DEL_HMC_OBJ_RANGE_V0 0
#define NSER_VCHNL_OP_GET_STATS_V0 0
#define NSER_VCHNL_OP_MANAGE_WS_NODE_V0 0
#define NSER_VCHNL_OP_VLAN_PARSING_V0 0
#define NSER_VCHNL_INVALID_VF_IDX 0xFFFF

struct nser_virtchnl_hmc_obj_range {
	u16 obj_type;
	u16 rsvd;
	u32 start_index;
	u32 obj_count;
};

struct nser_virtchnl_manage_ws_node {
	u8 add;
	u8 user_pri;
};

int nser_vchnl_recv_pf(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
int nser_vchnl_recv_vf(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
struct nser_vfdev *nser_find_vf_dev(struct nser_sc_dev *dev, u16 vf_id);
void nser_put_vfdev(struct nser_sc_dev *dev, struct nser_vfdev *vf_dev);
void nser_remove_vf_dev(struct nser_sc_dev *dev, struct nser_vfdev *vf_dev);
struct nser_virtchnl_req {
	struct nser_virtchnl_op_buf *vchnl_msg;
	void *parm;
	u32 vf_id;
	u16 parm_len;
	u16 resp_len;
};

#pragma pack(pop)

int nser_vchnl_vf_get_ver(struct nser_sc_dev *dev, u32 *vchnl_ver);
int nser_vchnl_vf_get_hmc_fcn(struct nser_sc_dev *dev);
int nser_vchnl_vf_put_hmc_fcn(struct nser_sc_dev *dev);
int nser_vchnl_vf_add_hmc_objs(struct nser_sc_dev *dev,
				enum nser_hmc_rsrc_type rsrc_type,
				u32 start_index, u32 rsrc_count);
int nser_vchnl_vf_del_hmc_obj(struct nser_sc_dev *dev,
			       enum nser_hmc_rsrc_type rsrc_type,
			       u32 start_index, u32 rsrc_count);
int nser_vchnl_vf_manage_ws_node(struct nser_sc_dev *dev, bool add,
				  u8 user_pri, u16 *qs_handle);
int nser_vchnl_vf_get_vlan_parsing_cfg(struct nser_sc_dev *dev,
					u8 *vlan_parse_en);
void nser_pf_put_vf_hmc_fcn(struct nser_sc_dev *dev, struct nser_vfdev *vf_dev);
#endif
