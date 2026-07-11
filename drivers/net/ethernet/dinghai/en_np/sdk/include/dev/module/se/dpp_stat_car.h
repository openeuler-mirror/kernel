/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_STAT_CAR_H_
#define _DPP_STAT_CAR_H_
#include "dpp_dev.h"
#include "dpp_stat_api.h"

#define DPP_CAR_ID_MAX (1)

#define DPP_CAR_DEBUG_SWITCH (0)

#define DPP_CAR_A_FLOW_ID_MAX (0x7fff)
#define DPP_CAR_B_FLOW_ID_MAX (0xfff)
#define DPP_CAR_C_FLOW_ID_MAX (0x3ff)
#define DPP_CAR_A_FLOW_ID_NUM (0x8000)
#define DPP_CAR_B_FLOW_ID_NUM (0x1000)
#define DPP_CAR_C_FLOW_ID_NUM (0x400)

#define DPP_CAR_PROFILE_ID_TOTAL ((0x200 + 0x80 + 0x20) * DPP_CAR_ID_MAX)

#define DPP_CAR_PKT_PROFILE_ID_MAX (0x200) /* 512 */
#define DPP_CAR_A_PROFILE_ID_MAX (0x1ff)
#define DPP_CAR_B_PROFILE_ID_MAX (0x7f)
#define DPP_CAR_C_PROFILE_ID_MAX (0x1f)

#define DPP_CAR_B_PROFILE_ID_RANDOM_MAX (0x1f)
#define DPP_CAR_C_PROFILE_ID_RANDOM_MAX (0x7)
#define DPP_CAR_RANDOM_OFFSET_VAL (7)

#define DPP_CAR_MAX_CBS_VALUE ((1 << 27) - 1)
#define DPP_CAR_MAX_EBS_VALUE ((1 << 27) - 1)
#define DPP_CAR_MAX_CIR_VALUE ((1 << 23) - 1)
#define DPP_CAR_MAX_EIR_VALUE ((1 << 23) - 1)
#define DPP_CAR_MAX_PKT_CIR_VALUE ((1 << 29) - 1)
#define DPP_CAR_MAX_PKT_CBS_VALUE ((1 << 13) - 1)
#define DPP_CAR_MAX_PRI_VALUE ((1 << 5) - 1)

#define DPP_CAR_QUEUQ_CFG_TQ_LEN (64)
#define DPP_CAR_QUEUQ_CFG_TQ_HIGH_13BIT_POS (44)
#define DPP_CAR_QUEUQ_CFG_TQ_HIGH_13BIT_LEN (13)
#define DPP_CAR_QUEUQ_CFG_TQ_LOW_32BIT_POS (31)
#define DPP_CAR_QUEUQ_CFG_TQ_LOW_32BIT_LEN (32)

#define DPP_CAR_PROFILE_CFG_ZXIC_UINT8 (28)
#define DPP_CAR_PROFILE_CFG_ZXIC_UINT32 (DPP_CAR_PROFILE_CFG_ZXIC_UINT8 >> 2)
#define DPP_CAR_PROFILE_CFG_WIDTH (DPP_CAR_PROFILE_CFG_ZXIC_UINT8 << 3)

#define DPP_CAR_QUEUE_CFG_ZXIC_UINT8 (4)
#define DPP_CAR_QUEUE_CFG_WIDTH (DPP_CAR_QUEUE_CFG_ZXIC_UINT8 << 3)

#define DPP_CAR_PROFILE_CFG_CAR_TYPE_POS (1)
#define DPP_CAR_PROFILE_CFG_CAR_TYPE_LEN (2)
#define DPP_CAR_PROFILE_CFG_PKT_SIGN_POS (2)
#define DPP_CAR_PROFILE_CFG_PKT_SIGN_LEN (1)
#define DPP_CAR_PROFILE_CFG_CD_POS (4)
#define DPP_CAR_PROFILE_CFG_CD_LEN (2)
#define DPP_CAR_PROFILE_CFG_CF_POS (5)
#define DPP_CAR_PROFILE_CFG_CF_LEN (1)
#define DPP_CAR_PROFILE_CFG_CM_POS (6)
#define DPP_CAR_PROFILE_CFG_CM_LEN (1)
#define DPP_CAR_PROFILE_CFG_EIR_POS (28)
#define DPP_CAR_PROFILE_CFG_EIR_LEN (22)
#define DPP_CAR_PROFILE_CFG_CIR_POS (50)
#define DPP_CAR_PROFILE_CFG_CIR_LEN (22)
#define DPP_CAR_PROFILE_CFG_EBS_POS (77)
#define DPP_CAR_PROFILE_CFG_EBS_LEN (27)
#define DPP_CAR_PROFILE_CFG_CBS_POS (104)
#define DPP_CAR_PROFILE_CFG_CBS_LEN (27)
#define DPP_CAR_PROFILE_CFG_C_PRI1_POS (139)
#define DPP_CAR_PROFILE_CFG_C_PRI1_LEN (5)
#define DPP_CAR_PROFILE_CFG_E_G_PRI1_POS (174)
#define DPP_CAR_PROFILE_CFG_E_G_PRI1_LEN (5)
#define DPP_CAR_PROFILE_CFG_E_Y_PRI0_POS (214)
#define DPP_CAR_PROFILE_CFG_E_Y_PRI0_LEN (5)

#define DPP_CAR_PKT_PROFILE_CFG_CAR_TYPE_POS (1)
#define DPP_CAR_PKT_PROFILE_CFG_CAR_TYPE_LEN (2)
#define DPP_CAR_PKT_PROFILE_CFG_PKT_SIGN_POS (2)
#define DPP_CAR_PKT_PROFILE_CFG_PKT_SIGN_LEN (1)
#define DPP_CAR_PKT_PROFILE_CFG_CIR_POS (32)
#define DPP_CAR_PKT_PROFILE_CFG_CIR_LEN (30)
#define DPP_CAR_PKT_PROFILE_CFG_CBS_POS (46)
#define DPP_CAR_PKT_PROFILE_CFG_CBS_LEN (14)
#define DPP_CAR_PKT_PROFILE_CFG_C_PRI0_POS (86)
#define DPP_CAR_PKT_PROFILE_CFG_C_PRI0_LEN (5)

#define DPP_CAR_QUEUE_CFG_CAR_TYPE_POS (1)
#define DPP_CAR_QUEUE_CFG_CAR_TYPE_LEN (2)
#define DPP_CAR_QUEUE_CFG_PKT_SIGN_POS (2)
#define DPP_CAR_QUEUE_CFG_PKT_SIGN_LEN (1)
#define DPP_CAR_QUEUE_CFG_QUEUE_ID_POS (16)
#define DPP_CAR_QUEUE_CFG_QUEUE_ID_LEN (14)

enum dpp_car_cd_mode_e {
	CAR_CD_MODE_SRTCM = 0,
	CAR_CD_MODE_TRTCM,
	CAR_CD_MODE_MEF10_1,
	CAR_CD_MODE_INVALID
};

enum dpp_car_rd_mode_e {
	CAR_READ_NOT_CLEAR = 0,
	CAR_READ_AND_CLEAR = 1,
};

enum dpp_car_overflow_mode_e {
	CAR_KEEP_COUNT = 0,
	CAR_RE_COUNT = 1,
};

enum dpp_car_qvos_mode_e {
	CAR_QVOS_MODE_OVERFLOW_0 = 0,
	CAR_QVOS_MODE_OVERFLOW_1 = 1,
	CAR_QVOS_MODE_OVERFLOW_2 = 2,
	CAR_QVOS_MODE_OVERFLOW_MAX
};

enum dpp_car_en_mode_e {
	DPP_CAR_EN_MODE_BOTH_EN = 0,
	DPP_CAR_EN_MODE_A_EN = 1,
	DPP_CAR_EN_MODE_A_B_EN = 2,
	DPP_CAR_EN_MODE_INVALID
};

enum dpp_car_cfg_operate_mode_e {
	CAR_OPERATE_MODE_ADD = 0,
	CAR_OPERATE_MODE_DEL = 1,
	CAR_OPERATE_MODE_SRH = 2,
	CAR_OPERATE_MODE_GET = 3,
	CAR_OPERATE_MODE_MAX,
};

struct dpp_stat_car_dbg_cnt_t {
	u32 pkt_input_total_cnt;
	u32 pkt_input_green_cnt;
	u32 pkt_input_yellow_cnt;
	u32 pkt_input_red_cnt;
	u32 pkt_output_total_cnt;
	u32 pkt_output_green_cnt;
	u32 pkt_output_yellow_cnt;
	u32 pkt_output_red_cnt;
	u32 pkt_fc_dbg_cnt;
	u32 pkt_size_cnt;
};

struct dpp_stat_car_pkt_profile_cfg_t {
	u32 profile_id;
	u32 pkt_sign;
	u32 cir;
	u32 cbs;
	u32 pri[DPP_CAR_PRI_MAX];
};

struct dpp_stat_car_a_pkt_queue_cfg_t {
	u32 flow_id;
	u32 drop_flag;
	u32 plcr_en;
	u32 profile_id;
	u64 tq;
	u64 dc;
	u32 tc;
};

struct dpp_stat_car_b_queue_cfg_t {
	u32 flow_id;
	u32 drop_flag;
	u32 plcr_en;
	u32 profile_id;
	u64 tq;
	u32 tce_flag;
	u32 tce;
	u32 tc;
	u32 te;
};

struct dpp_stat_car_c_queue_cfg_t {
	u32 flow_id;
	u32 drop_flag;
	u32 plcr_en;
	u32 profile_id;
	u64 tq;
	u32 tce_flag;
	u32 tce;
	u32 tc;
	u32 te;
};

struct dpp_car_profile_rb_key_t {
	u32 profile_cfg[DPP_CAR_PROFILE_CFG_ZXIC_UINT32];
	u32 is_static;
	u32 use_count;
};

struct dpp_car_profile_id_rb_key_t {
	u32 profile_id;
	void *p_car_node;
	u32 is_used;
};

struct dpp_car_queue_rb_key_t {
	/** carqueue
	 * car_type[2]+pkt_sign[1]+queue_id[14]+15[0]
	 */
	u8 profile_cfg[DPP_CAR_QUEUE_CFG_ZXIC_UINT8];
	u32 is_used;
	u32 profile_id;
};

struct dpp_car_rb_mng_t {
	u32 init_en;
	u32 total_num;
	u32 key_size;
	ZXIC_RB_CMPFUN p_cmpfun;
	ZXIC_RB_CMPFUN p_id_cmpfun;
	struct _rb_cfg *p_plcr_rb;
	struct _rb_cfg *p_plcr_id_rb;
	struct _s_List_Stack_Manager *p_liststack_mng;
};

struct dpp_car_profile_mng_t {
	u32 is_init;
	struct dpp_car_rb_mng_t *p_car_a_rb_profile_mng;
	struct dpp_car_rb_mng_t *p_car_b_rb_profile_mng;
	struct dpp_car_rb_mng_t *p_car_c_rb_profile_mng;
};

struct dpp_car_queue_mng_t {
	u32 is_init;
	struct dpp_car_rb_mng_t *p_car_rb_queue_mng;
};

struct dpp_car_cfg_t {
	u32 is_init[DPP_DEV_CHANNEL_MAX];
	u32 car0_mono_mode[DPP_DEV_CHANNEL_MAX];
	struct dpp_car_queue_mng_t *p_car_queue_mng[DPP_DEV_CHANNEL_MAX];
	struct dpp_car_profile_mng_t *p_car_profile_mng[DPP_DEV_CHANNEL_MAX];
};

struct dpp_car_soft_reset_item_t {
	u32 flow_id;
	u32 profile_id;
};

struct dpp_car_soft_reset_data_t {
	u8 car_pkt_sign[DPP_CAR_PKT_PROFILE_ID_MAX]; /*  */

	u32 is_init;
	u32 car0_pkt_num; /*  */

	u32 cara_flow_num;
	u32 carb_flow_num;
	u32 carc_flow_num;

	struct dpp_car_soft_reset_item_t cara_item[DPP_CAR_A_FLOW_ID_NUM];
	struct dpp_car_soft_reset_item_t carb_item[DPP_CAR_B_FLOW_ID_NUM];
	struct dpp_car_soft_reset_item_t carc_item[DPP_CAR_C_FLOW_ID_NUM];
};

struct dpp_car_random_ram_t {
	u32 p1;
	u32 p2;
	u32 p3;
	u32 tc;
	u32 t1;
	u32 t2;
	u32 t3;
};

struct dpp_car_soft_reset_queue_t {
	u32 car_type;
	u32 flow_id;
	u32 drop_flag;
	u32 plcr_en;
	u32 profile_id;
};
DPP_STATUS
dpp_stat_cara_pkt_profile_cfg_set(struct dpp_dev_t *dev, u32 profile_id,
				  struct dpp_stat_car_pkt_profile_cfg_t *p_cara_profile_cfg);
DPP_STATUS dpp_stat_cara_pkt_queue_cfg_get(struct dpp_dev_t *dev, u32 flow_id,
					   struct dpp_stat_car_a_pkt_queue_cfg_t *p_cara_queue_cfg);
DPP_STATUS dpp_stat_carb_random_ram_set(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c);
DPP_STATUS dpp_stat_carb_random_ram_get(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c);
DPP_STATUS dpp_stat_carc_random_ram_set(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c);
DPP_STATUS dpp_stat_carc_random_ram_get(struct dpp_dev_t *dev, u32 profile_id,
					struct dpp_car_random_ram_t *p_random_ram_e,
					struct dpp_car_random_ram_t *p_random_ram_c);
DPP_STATUS dpp_stat_car_pkt_size_offset_get(struct dpp_dev_t *dev, u32 *p_pkt_size_off);
DPP_STATUS dpp_stat_cara_max_pkt_size_set(struct dpp_dev_t *dev, u32 max_pkt_size);
DPP_STATUS dpp_stat_cara_max_pkt_size_get(struct dpp_dev_t *dev, u32 *p_max_pkt_size);
DPP_STATUS dpp_stat_carb_max_pkt_size_set(struct dpp_dev_t *dev, u32 max_pkt_size);
DPP_STATUS dpp_stat_carb_max_pkt_size_get(struct dpp_dev_t *dev, u32 *p_max_pkt_size);
DPP_STATUS dpp_stat_carc_max_pkt_size_set(struct dpp_dev_t *dev, u32 max_pkt_size);
DPP_STATUS dpp_stat_carc_max_pkt_size_get(struct dpp_dev_t *dev, u32 *p_max_pkt_size);
DPP_STATUS dpp_stat_car_max_pkt_size_get(struct dpp_dev_t *dev, u32 car_type, u32 *p_max_pkt_len);
DPP_STATUS dpp_stat_car_pkt_size_offset_set(struct dpp_dev_t *dev, u32 pkt_size_off);
DPP_STATUS dpp_stat_car_max_pkt_size_set(struct dpp_dev_t *dev, u32 car_type, u32 max_pkt_size);
DPP_STATUS dpp_stat_car_queue_cfg_set(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 drop_flag, u32 plcr_en, u32 profile_id);
DPP_STATUS dpp_stat_car_profile_cfg_set(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign,
					u32 profile_id, void *p_car_profile_cfg);
DPP_STATUS dpp_stat_car_queue_map_set(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 map_flow_id, u32 map_sp);
DPP_STATUS dpp_stat_car_queue_get(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign, u32 flow_id,
				  void *p_data);
DPP_STATUS dpp_stat_car_queue_cfg_get(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 *p_drop_flag, u32 *p_plcr_en, u32 *p_profile_id);

DPP_STATUS dpp_stat_car_profile_cfg_get(struct dpp_dev_t *dev, u32 car_type, u32 pkt_sign,
					u32 profile_id, void *p_car_profile_cfg);
DPP_STATUS dpp_stat_car_random_ram_set(struct dpp_dev_t *dev, u32 car_type, u32 profile_id,
				       struct dpp_car_random_ram_t *p_random_ram_e,
				       struct dpp_car_random_ram_t *p_random_ram_c);
DPP_STATUS dpp_stat_car_random_ram_get(struct dpp_dev_t *dev, u32 car_type, u32 profile_id,
				       struct dpp_car_random_ram_t *p_random_ram_e,
				       struct dpp_car_random_ram_t *p_random_ram_c);
DPP_STATUS dpp_stat_car_queue_map_get(struct dpp_dev_t *dev, u32 car_type, u32 flow_id,
				      u32 *p_map_flow_id, u32 *p_map_sp);
DPP_STATUS dpp_stat_car_dbg_cnt_get(u32 dev_id, u32 car_type,
				    struct dpp_stat_car_dbg_cnt_t *p_car_dbg_cnt);
DPP_STATUS dpp_stat_car_dbg_cnt_mode_set(u32 dev_id, u32 car_type, u32 overflow_mode, u32 rd_mode);
DPP_STATUS dpp_stat_car_dbg_cnt_mode_get(u32 dev_id, u32 car_type, u32 *p_overflow_mode,
					 u32 *p_rd_mode);
DPP_STATUS dpp_stat_car_init(u32 dev_id, struct dpp_car_cfg_t *p_car_cfg);
DPP_STATUS dpp_stat_car_glb_size_get(struct dpp_dev_t *dev, u32 *p_size);
DPP_STATUS dpp_stat_car_glb_mgr_set(u32 dev_id, u32 size, u8 *p_data_buff);
DPP_STATUS dpp_stat_car_glb_mgr_get(u32 dev_id, u32 *p_flag, u32 *p_size, u8 **pp_data_buff);

DPP_STATUS dpp_stat_queue_rb_root_prt(struct _rb_cfg *p_rb_cfg);
DPP_STATUS dpp_stat_car_profile_id_rb_root_prt(u32 dev_id, struct _rb_cfg *p_rb_cfg);
DPP_STATUS dpp_stat_cara_queue_qvos_set(struct dpp_dev_t *dev, u32 flow_id, u32 qvos_mode);
DPP_STATUS dpp_stat_cara_queue_qvos_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_qvos_mode);
DPP_STATUS dpp_stat_cara_queue_appoint_mode_set(struct dpp_dev_t *dev, u32 global_en, u32 sp_en,
						u32 appoint_sp, u32 appoint_queue);
DPP_STATUS dpp_stat_cara_queue_appoint_mode_get(struct dpp_dev_t *dev, u32 *p_global_en,
						u32 *p_sp_en, u32 *p_appoint_sp,
						u32 *p_appoint_queue);
DPP_STATUS dpp_stat_carb_queue_qvos_set(struct dpp_dev_t *dev, u32 flow_id, u32 qvos_mode);
DPP_STATUS dpp_stat_carb_queue_qvos_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_qvos_mode);
DPP_STATUS dpp_stat_carb_queue_appoint_mode_set(u32 dev_id, u32 global_en, u32 sp_en,
						u32 appoint_sp, u32 appoint_queue);
DPP_STATUS dpp_stat_carb_queue_appoint_mode_get(u32 dev_id, u32 *p_global_en, u32 *p_sp_en,
						u32 *p_appoint_sp, u32 *p_appoint_queue);
DPP_STATUS dpp_stat_carc_queue_qvos_set(struct dpp_dev_t *dev, u32 flow_id, u32 qvos_mode);
DPP_STATUS dpp_stat_carc_queue_qvos_get(struct dpp_dev_t *dev, u32 flow_id, u32 *p_qvos_mode);
DPP_STATUS dpp_stat_carc_queue_appoint_mode_set(u32 dev_id, u32 global_en, u32 sp_en,
						u32 appoint_sp, u32 appoint_queue);
DPP_STATUS dpp_stat_carc_queue_appoint_mode_get(u32 dev_id, u32 *p_global_en, u32 *p_sp_en,
						u32 *p_appoint_sp, u32 *p_appoint_queue);
DPP_STATUS dpp_stat_car_en_mode_get(struct dpp_dev_t *dev, u32 *p_mode);

#endif
