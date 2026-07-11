/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_STAT_API_H_
#define _DPP_STAT_API_H_

#if ZXIC_REAL("header file")

#include "dpp_dev.h"

#endif

#if ZXIC_REAL("data struct define")

enum stat_tm_mode_e { STAT_TM_MODE_ETM = 0, STAT_TM_MODE_FTM = 1, STAT_TM_MODE_MAX };

enum stat_tm_port_mode_e {
	STAT_TM_PORT_MODE_0_1 = 0,
	STAT_TM_PORT_MODE_2_3 = 1,
	STAT_TM_PORT_MODE_MAX,
};

enum stat_tm_cnt_mode_e {
	STAT_TM_CNT_MODE_MIX = 0,
	STAT_TM_CNT_MODE_INNER = 1,
	STAT_TM_CNT_MODE_MAX
};

enum tm_stat_type_e {

	TM_STAT_ENQUE_PKT = 0,
	TM_STAT_ENQUE_VALID_PKT = 1,
	TM_STAT_ENQUE_DROP_PKT = 2,
	TM_STAT_ENQUE_TD_PKT = 3,
	TM_STAT_ENQUE_WRED_PKT = 4,
	TM_STAT_ENQUE_DP0_PKT = 5,
	TM_STAT_ENQUE_DP1_PKT = 6,
	TM_STAT_ENQUE_DP2_PKT = 7,
	TM_STAT_ENQUE_DP3_PKT = 8,
	TM_STAT_ENQUE_DP4_PKT = 9,
	TM_STAT_ENQUE_DP5_PKT = 10,
	TM_STAT_ENQUE_DP6_PKT = 11,
	TM_STAT_ENQUE_DP7_PKT = 12,
	TM_STAT_ENQUE_BLOCK_PKT = 13,
	TM_STAT_ENQUE_DISABLE_PKT = 14,
	TM_STAT_DEQUE_PKT = 15,
	TM_STAT_DEQUE_VALID_PKT = 16,
	TM_STAT_DEQUE_DISCARD_PKT = 17,
	TM_STAT_DEQUE_CLEAR_PKT = 18,
	TM_STAT_DEQUE_AGE_PKT = 19,
	TM_STAT_TYPE_UNEN = 20,
	TM_STAT_TYPE_MAX
};

enum stat_car_type_e { STAT_CAR_A_TYPE = 0, STAT_CAR_B_TYPE, STAT_CAR_C_TYPE, STAT_CAR_MAX_TYPE };

struct stat_car_queue_cfg_t {
	u32 queue_id;
	u32 plcr_en;
	u32 drop_flag;
	void *profile_cfg;
};

struct stat_count_cfg_t {
	u32 rd_mode;
	u32 overflow_mode;
};

struct dpp_stat_smmu1_cfg_t {
	u32 baddr;
};

struct dpp_stat_comm_cfg_t {
	struct dpp_stat_smmu1_cfg_t stat_smmu1_cfg[DPP_DEV_CHANNEL_MAX];
	u32 is_init[DPP_DEV_CHANNEL_MAX];
};

struct dpp_stat_tm_cfg_t {
	u32 tm_en;
	u32 mov_en;
	u32 eram_en;
	u32 ftm_pkt_en;
	u32 etm_pkt_en;
	u32 ftm_port_type[4];
	u32 etm_port_type[4];
	u32 etm_start_queue_id;
	u32 etm_queue_depth_mode;
	struct dpp_stat_smmu1_cfg_t ftm_smmu1_cfg;
	struct dpp_stat_smmu1_cfg_t etm_smmu1_cfg;
	u32 is_init[DPP_DEV_CHANNEL_MAX];
};

struct dpp_stat_tm_cnt_t {
	u32 tm_cnt_en;
	u32 tm_mode;
	u32 tm_flow_id;
	u32 tm_stat_type;
	u32 is_tm_byte_en;
	u32 is_eram_en;
	u64 tm_cnt;
};

struct dpp_stat_brief_int_t {
	u32 etcam_int;
	u32 stat_sch_int;
};

struct dpp_stat_sch_intr_t {
	u32 hardware_rsv;
	u32 oam0_ord_fifo_int;
	u32 oam2_ord_fifo_int;
	u32 oam3_ord_fifo_int;
	u32 ddr_sch_fifo_int;
	u32 plcr_sch_fifo_int;
	u32 stat_schd_fifo_int;
	u32 stat_rschd_fifo_int;
};

enum stat_cnt_mode_e {
	STAT_64_MODE = 0,
	STAT_128_MODE = 1,
	STAT_MAX_MODE,
};

enum stat_rd_clr_mode_e {
	STAT_RD_CLR_MODE_UNCLR = 0,
	STAT_RD_CLR_MODE_CLR = 1,
	STAT_RD_CLR_MODE_MAX,
};

enum dpp_car_priority_e {
	DPP_CAR_PRI0 = 0,
	DPP_CAR_PRI1 = 1,
	DPP_CAR_PRI2 = 2,
	DPP_CAR_PRI3 = 3,
	DPP_CAR_PRI4 = 4,
	DPP_CAR_PRI5 = 5,
	DPP_CAR_PRI6 = 6,
	DPP_CAR_PRI7 = 7,
	DPP_CAR_PRI_MAX
};

struct dpp_stat_car_profile_cfg_t {
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

enum dpp_car_smmu0_mono_mode_e {
	CAR_SMMU0_MONO_MODE_NONE = 0,
	CAR_SMMU0_MONO_MODE_1 = 1,
	CAR_SMMU0_MONO_MODE_2 = 2,
	CAR_SMMU0_MONO_MODE_MAX
};

enum stat_tm_clr_mode_e {
	STAT_TM_CLR_MODE_UNCLR = 0,
	STAT_TM_CLR_MODE_CLR = 1,
	STAT_TM_CLR_MODE_MAX,
};

struct dpp_stat_car_a_queue_cfg_t {
	u32 flow_id;
	u32 drop_flag;
	u32 plcr_en;
	u32 profile_id;
	u64 tq;
	u32 ted;
	u32 tcd;
	u32 tei;
	u32 tci;
};

#endif

#if ZXIC_REAL("macro function define")

#endif

#if ZXIC_REAL("function declaration")
DPP_STATUS dpp_stat_comm_init(u32 dev_id, struct dpp_stat_comm_cfg_t *p_dpp_stat_comm_cfg);
DPP_STATUS dpp_stat_ppu_eram_baddr_set(struct dpp_dev_t *dev, u32 ppu_eram_baddr);
DPP_STATUS dpp_stat_ppu_eram_depth_set(struct dpp_dev_t *dev, u32 ppu_eram_depth);
DPP_STATUS dpp_stat_ppu_ddr_baddr_set(u32 dev_id, u32 ppu_ddr_baddr);
DPP_STATUS dpp_stat_tm_init(u32 dev_id, struct dpp_stat_tm_cfg_t *p_stat_tm_cfg);
DPP_STATUS dpp_stat_etm_port_type_set(u32 dev_id, u32 etm_port0_type, u32 etm_port1_type,
				      u32 etm_port2_type, u32 etm_port3_type);
DPP_STATUS dpp_stat_ftm_port_type_set(u32 dev_id, u32 ftm_port0_type, u32 ftm_port1_type,
				      u32 ftm_port2_type, u32 ftm_port3_type);
DPP_STATUS dpp_stat_car_hardware_init(u32 dev_id, u32 car_type, u32 car_mono_mode);
DPP_STATUS dpp_stat_car_en_mode_set(struct dpp_dev_t *dev, u32 mode);
DPP_STATUS
dpp_stat_cara_profile_cfg_set(struct dpp_dev_t *dev, u32 profile_id,
			      struct dpp_stat_car_profile_cfg_t *p_cara_profile_cfg);
DPP_STATUS
dpp_stat_cara_queue_cfg_get(struct dpp_dev_t *dev, u32 flow_id,
			    struct dpp_stat_car_a_queue_cfg_t *p_cara_queue_cfg);
DPP_STATUS dpp_stat_cara_queue_cfg_set(struct dpp_dev_t *dev, u32 flow_id, u32 drop_flag,
				       u32 plcr_en, u32 profile_id);
DPP_STATUS dpp_stat_help(u32 dev_id);
DPP_STATUS dpp_stat_module_init(u32 dev_id);
DPP_STATUS dpp_stat_ppu_cnt_set(u32 dev_id, enum stat_cnt_mode_e rd_mode, u32 index, u32 *p_data);
DPP_STATUS dpp_stat_ppu_cnt_get(struct dpp_dev_t *dev, enum stat_cnt_mode_e rd_mode, u32 index,
				u32 clr_mode, u32 *p_data);
DPP_STATUS dpp_stat_tm_cnt_get(u32 dev_id, u32 tm_mode, u32 only_pkt_num_en, u32 port_mode,
			       u32 cnt_mode, u32 clr_mode, u32 index, u32 *p_data);
DPP_STATUS diag_dpp_stat_ppu_cfg_prt(u32 dev_id);

#endif
#endif /*dpp_stat_api.h*/
