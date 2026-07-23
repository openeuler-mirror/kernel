/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_AGENT_CHANNEL_H
#define DPP_AGENT_CHANNEL_H

#include "zxic_common.h"
#include "dpp_dev.h"
#include "dpp_type_api.h"
#include "dpp_stat_api.h"
#include "dpp_stat_car.h"
#include "dpp_ppu.h"
#include "dpp_agent_se_res.h"

#define BUFFER_LEN_MAX (256)
#define REG_REPS_LEN (8)
#define CHANNEL_REPS_LEN (4)
#define NP_AGENT_ID (16)
#define MSG_REP_OFFSET (4)
#define MSG_REP_VALID (0Xff)
#define MSG_REP_LEN_OFFSET (1)
#define SCHE_RSP_LEN (2)
#define SCHE_REQ_VALID (0Xffff)
#define PROFILEID_REQ_VALID (0Xffff)
#define EPID_LEVEL (4)
#define BAR_MSG_RETRY_MAX_TIME (10)

#pragma pack(1)

enum dpp_tm_level { Q_LEVEL = 0, P_LEVEL, S_LEVEL, MAX_LEVEL };
enum dpp_agent_msg_type {
	DPP_REG_MSG = 0,
	DPP_DTB_MSG,
	DPP_TM_MSG,
	DPP_PLCR_MSG,
	DPP_PKTRX_IND_REG_RW_MSG,
	DPP_PCIE_BAR_MSG,
	DPP_RESET_MSG,
	DPP_PXE_MSG,
	DPP_TM_FLOW_SHAPE,
	DPP_TM_TD,
	DPP_TM_SE_SHAPE,
	DPP_TM_PP_SHAPE,
	DPP_PLCR_CAR_RATE,
	DPP_PLCR_CAR_PKT_RATE,
	DPP_PPU_THASH_RSK,
	DPP_ACL_MSG,
	DPP_STAT_MSG,
	DPP_RES_MSG,
	DPP_PSN_CFG_MSG,
	DPP_MSG_MAX
};

enum dpp_agent_msg_oper { DPP_WR = 0, DPP_RD, DPP_WR_RD_MAX };
enum dpp_agent_msg_res { RES_STD_NIC_MSG = 0, RES_OFFLOAD_MSG, RES_MAX_MSG };

enum dpp_msg_dtb_oper {
	QUEUE_REQUEST = 0,
	QUEUE_RELEASE = 1,
	QUEUE_SYNC_CFG = 2,
};

enum dpp_msg_tm_oper { SEID_REQUEST = 0, SEID_RELEASE = 1, SEID_QUERY = 2 };

enum dpp_msg_plcr_oper {
	PROFILEID_REQUEST = 0,
	PROFILEID_RELEASE = 1,
};
enum dpp_cosq_sche_type {
	FQ_SCHE = 0,
	FQ2_SCHE = 1,
	FQ4_SCHE = 2,
	FQ8_SCHE = 3,
	SP_SCHE = 4,
	WFQ_SCHE = 5,
	WFQ2_SCHE = 6,
	WFQ4_SCHE = 7,
	WFQ8_SCHE = 8,
	FLOW_SCHE = 9,
	SCHE_TYPE = 10
};

enum dpp_agent_msg_csflag { DPP_CS_ADDR_FLAG = 0, DPP_CS_REGNO_FLAG, DPP_CS_FLAG_MAX };

enum dpp_ppu_thash_rsk_oper {
	DPP_PPU_THASH_RSK_RD = 0,
	DPP_PPU_THASH_RSK_WR,
	DPP_PPU_THASH_RSK_MAX
};

enum dpp_pktrx_ind_reg_rw_oper {
	DPP_PKTRX_IND_REG_RD = 0,
	DPP_PKTRX_IND_REG_WR,
	DPP_PKTRX_IND_REG_MAX
};

enum dpp_msg_acl_index_oper {
	ACL_INDEX_REQUEST = 0,
	ACL_INDEX_RELEASE = 1,
	ACL_INDEX_VPORT_REL = 2,
	ACL_INDEX_ALL_REL = 3,
	ACL_INDEX_STAT_CLR = 4,
	ACL_INDEX_MAX
};
enum dpp_se_res_oper {
	HASH_FUNC_BULK_REQ = 0,
	HASH_TBL_REQ = 1,
	ERAM_TBL_REQ = 2,
	ACL_TBL_REQ = 3,
	LPM_TBL_REQ = 4,
	DDR_TBL_REQ = 5,
	STAT_CFG_REQ = 6,
	RES_REQ_MAX
};

enum dpp_agent_pcie_bar { BAR_MSG_NUM_REQ = 0, PCIE_BAR_MAX };

enum dpp_psn_cfg_oper { PSN_CFG_L2D_WR = 0, PSN_CFG_L2D_RD = 1, PSN_CFG_OPR_MAX };

struct dpp_agent_channel_reg_msg {
	u8 devId;
	u8 type;
	u8 subtype;
	u8 oper;
	u32 reg_no;
	u32 addr;
	u32 val_len;
	u32 val[32];
};

struct dpp_agent_channel_dtb_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
	u8 name[32];
	u32 vport;
	u32 queue_id;
};
struct dpp_agent_channel_tm_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 num;
	u32 port;
	u32 vport;
	u32 sche_level;
	u32 sche_type;
	u32 se_id;
};
struct dpp_agent_channel_plcr_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
	u32 vport;
	u32 car_type;
	u32 profile_id;
};

struct dpp_agent_tm_flow_shape_msg {
	u8 devId;
	u8 type;
	u8 rsv;
	u8 rsv1;
	u32 flow_id;
	u32 cir;
	u32 cbs;
	u32 db_en;
	u32 eir;
	u32 ebs;
};

struct dpp_agent_tm_td_msg {
	u8 devId;
	u8 type;
	u8 rsv;
	u8 rsv1;
	u32 level;
	u32 id;
	u32 td_th;
};

struct dpp_agent_tm_se_shape_msg {
	u8 devId;
	u8 type;
	u8 rsv;
	u8 rsv1;
	u32 se_id;
	u32 pir;
	u32 pbs;
	u32 db_en;
	u32 cir;
	u32 cbs;
};

struct dpp_agent_tm_pp_shape_msg {
	u8 devId;
	u8 type;
	u8 rsv;
	u8 rsv1;
	u32 pp_port;
	u32 cir;
	u32 cbs;
	u32 c_en;
};

struct dpp_agent_car_pkt_profile_msg {
	u8 devId;
	u8 type;
	u8 rsv;
	u8 rsv1;
	u32 car_level;
	u32 profile_id;
	u32 pkt_sign;
	u32 cir;
	u32 cbs;
	u32 pri[DPP_CAR_PRI_MAX];
};

struct dpp_agent_car_profile_msg {
	u8 devId;
	u8 type;
	u8 rsv;
	u8 rsv1;
	u32 car_level;
	u32 profile_id;
	u32 pkt_sign;
	u32 cd;
	u32 cf;
	u32 cm;
	u32 cir;
	u32 cbs;
	u32 eir;
	u32 ebs;
	u32 random_disc_e;
	u32 random_disc_c;
	u32 c_pri[DPP_CAR_PRI_MAX];
	u32 e_green_pri[DPP_CAR_PRI_MAX];
	u32 e_yellow_pri[DPP_CAR_PRI_MAX];
};

struct dpp_agent_ppu_thash_rsk_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
	u32 rsk_319_288;
	u32 rsk_287_256;
	u32 rsk_255_224;
	u32 rsk_223_192;
	u32 rsk_191_160;
	u32 rsk_159_128;
	u32 rsk_127_096;
	u32 rsk_095_064;
	u32 rsk_063_032;
	u32 rsk_031_000;
};

struct dpp_agent_pktrx_ind_reg_rw_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
	u32 mem_addr;
	u32 mem_id;
	u32 len;
	u32 ind_data[8];
};

struct dpp_agent_channel_acl_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
	u32 sdt_no;
	u32 vport;
	u32 index;
	u32 counter_id;
	u32 rd_mode;
};

struct dpp_agent_channel_stat_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
	u32 counter_id;
	u32 rd_mode;
	u32 num;
};

struct dpp_agent_se_res_msg {
	u8 devId;
	u8 type;
	u8 sub_type;
	u8 oper;
};

struct dpp_agent_channel_pcie_bar_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 rsv;
};

struct dpp_agent_channel_psn_cfg_msg {
	u8 devId;
	u8 type;
	u8 oper;
	u8 psn;
};

struct dpp_agent_channel_msg {
	u32 msg_len;
	void *msg;
};

#pragma pack()

DPP_STATUS dpp_agent_channel_init(void);
DPP_STATUS dpp_agent_channel_exit(void);
DPP_STATUS dpp_agent_channel_sync_send(struct dpp_dev_t *dev, struct dpp_agent_channel_msg *pMsg,
				       u32 *pData, u32 rep_len);
DPP_STATUS dpp_agent_channel_reg_sync_send(struct dpp_dev_t *dev,
					   struct dpp_agent_channel_reg_msg *pMsg, u32 *pData,
					   u32 rep_len);
DPP_STATUS dpp_agent_channel_reg_write(struct dpp_dev_t *dev, u32 reg_type, u32 reg_no,
				       u32 reg_width, u32 addr, u32 *pData);
DPP_STATUS dpp_agent_channel_reg_read(struct dpp_dev_t *dev, u32 reg_type, u32 reg_no,
				      u32 reg_width, u32 addr, u32 *pData);
DPP_STATUS dpp_agent_channel_dtb_sync_send(struct dpp_dev_t *dev,
					   struct dpp_agent_channel_dtb_msg *pMsg, u32 *pData,
					   u32 rep_len);
DPP_STATUS dpp_agent_channel_dtb_queue_request(struct dpp_dev_t *dev, const u8 *p_name,
					       u32 vport_info, u32 *p_queue_id);
DPP_STATUS dpp_agent_channel_dtb_queue_release(struct dpp_dev_t *dev, const u8 *p_name,
					       u32 queue_id);
DPP_STATUS dpp_agent_channel_dtb_queue_sync_cfg(struct dpp_dev_t *dev, const u8 *p_name,
						u32 vport_info, u32 queue_id);

DPP_STATUS dpp_agent_channel_tm_sync_send(struct dpp_dev_t *dev,
					  struct dpp_agent_channel_tm_msg *pMsg, u32 *pData,
					  u32 rep_len);
DPP_STATUS dpp_agent_channel_tm_seid_request(struct dpp_dev_t *dev, u32 port, u32 vport,
					     u32 sche_level, u32 sche_type, u32 num, u32 *p_se_id);
DPP_STATUS dpp_agent_channel_tm_seid_release(struct dpp_dev_t *dev, u32 port, u32 vport,
					     u32 sche_level, u32 sche_type, u32 num, u32 se_id);

DPP_STATUS dpp_agent_channel_tm_base_node_get(struct dpp_dev_t *dev, u32 port, u32 vport,
					      u32 *p_se_id);

DPP_STATUS dpp_agent_channel_plcr_sync_send(struct dpp_dev_t *dev,
					    struct dpp_agent_channel_plcr_msg *pMsg, u32 *pData,
					    u32 rep_len);
DPP_STATUS dpp_agent_channel_plcr_profileid_request(struct dpp_dev_t *dev, u32 vport, u32 car_type,
						    u32 *p_profileid);
DPP_STATUS dpp_agent_channel_plcr_profileid_release(struct dpp_dev_t *dev, u32 vport, u32 car_type,
						    u32 profileid);

DPP_STATUS dpp_agent_channel_tm_flow_shape(struct dpp_dev_t *dev, u32 flow_id, u32 cir, u32 cbs,
					   u32 db_en, u32 eir, u32 ebs);
DPP_STATUS dpp_agent_channel_tm_td_set(struct dpp_dev_t *dev, u32 level, u32 id, u32 td_th);
DPP_STATUS dpp_agent_channel_tm_se_shape(struct dpp_dev_t *dev, u32 se_id, u32 pir, u32 pbs,
					 u32 db_en, u32 cir, u32 cbs);
DPP_STATUS dpp_agent_channel_tm_port_shape(struct dpp_dev_t *dev, u32 pp_port, u32 cir, u32 cbs,
					   u32 c_en);

DPP_STATUS dpp_agent_channel_plcr_car_rate(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign,
					   u32 profile_id, void *p_car_profile_cfg);
DPP_STATUS dpp_agent_channel_ppu_thash_rsk(struct dpp_dev_t *dev, enum dpp_ppu_thash_rsk_oper oper,
					   struct dpp_ppu_ppu_cop_thash_rsk_t *p_para);

DPP_STATUS dpp_agent_channel_acl_index_request(struct dpp_dev_t *dev, u32 sdt_no, u32 vport,
					       u32 *p_index);
DPP_STATUS dpp_agent_channel_acl_index_release(struct dpp_dev_t *dev, u32 rel_type, u32 sdt_no,
					       u32 vport, u32 index);
DPP_STATUS dpp_agent_channel_acl_stat_clr(struct dpp_dev_t *dev, u32 sdt_no, u32 vport,
					  u32 counter_id, u32 rd_mode);
DPP_STATUS dpp_agent_channel_stat_clr(struct dpp_dev_t *dev, u32 count_id, u32 rd_mode, u32 num);
DPP_STATUS dpp_agent_channel_se_res_get(struct dpp_dev_t *dev, u32 sub_type, u32 opr,
					u32 *p_rsp_buff, u32 buff_size);
DPP_STATUS dpp_agent_channel_pcie_bar_request(struct dpp_dev_t *dev, u32 *p_bar_msg_num);
DPP_STATUS dpp_agent_channel_pktrx_ind_reg_rw(struct dpp_dev_t *dev, u32 mem_addr, u32 mem_id,
					      u32 oper, u32 len, u32 *p_data);
DPP_STATUS dpp_agent_channel_psn_cfg_l2d_write(struct dpp_dev_t *dev, u8 psn_cfg);
DPP_STATUS dpp_agent_channel_psn_cfg_l2d_read(struct dpp_dev_t *dev, u32 *p_psn_cfg);
#endif
