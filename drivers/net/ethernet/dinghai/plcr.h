/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_QOS_H__
#define __ZXDH_QOS_H__

#include <linux/dinghai/driver.h>
#include <linux/dinghai/en_aux.h>
#include <linux/dinghai/eq.h>
#include <linux/compiler_types.h>
#include <linux/types.h>
#include "dpp_drv_qos.h"
#include "en_sf.h"

#define ZXDH_PLCR_OPEN
#define ZXDH_SRIOV_SYSFS_EN
#ifdef ZXDH_PLCR_OPEN
#define ZXDH_PLCR_DEBUG
#endif

#define DROP_ENABLE 1
#define DROP_DISABLE 0
#define PLCR_ENABLE 1
#define PLCR_DISABLE 0

#define PLCR_STEP_SIZE 1u
#define PLCR_MIN_RATE 1u
#define PLCR_MAX_RATE (400 * (1 << 20))
#define PLCR_MAX_PKT_RATE DPP_CAR_MAX_PKT_CIR_VALUE

#define USER_MAX_BYTE_RATE ((PLCR_MAX_RATE * PLCR_STEP_SIZE) >> 10)
#define USER_MAX_PKT_RATE PLCR_MAX_PKT_RATE

#define CRED_ID(vport, car_type, profile_id) \
	((((vport)&0xffff) << 20) | (((car_type)&0xf) << 16) | ((profile_id)&0x1FF))
#define PROFILE_ID(cred_id) ((cred_id)&0x1FF)
#define VQM_QUEUE_PAIRS_MAX_NUM 2048

#define PLCR_CAR_A_PROFILE_RES_NUM 512
#define PLCR_CAR_B_PROFILE_RES_NUM 128
#define PLCR_CAR_C_PROFILE_RES_NUM 32

#define PLCR_CAR_A_FLOWID_RES_NUM 10240
#define PLCR_CAR_B_FLOWID_RES_NUM 2368
#define PLCR_CAR_C_FLOWID_RES_NUM 1024
#define PLCR_CAR_B_PF_DEFAULT_FLOWID 2048

#define PLCR_CAR_C_FLOWIDS_PER_EP 256
#define PLCR_CAR_C_FLOWIDS_PER_PF 32

#define FLOWID_2_XARRAY(flowid) (((flowid) + 1) * 8)
#define XARRAY_2_FLOWID(flowid) (((flowid) / 8) - 1)

#define PLCR_INVALID_PARAM 0xffffffff
#define PLCR_CAR_A_DPDK_FLOWID_OFFSET 8192
#define PLCR_MAX_QUEUE_PAIRS 128
#define PLCR_DEBUG

#define PLCR_FUNC_DBG_ENTER() LOG_INFO("%s-%d:enter !\n", __func__, __LINE__)

#define PLCR_LOG_INFO(fmt, arg...) DH_LOG_INFO(MODULE_PF, fmt, ##arg)

#define PLCR_LOG_ERR(fmt, arg...) DH_LOG_ERR(MODULE_PF, fmt, ##arg)

enum E_PLCR_ERR_CODE {
	PLCR_DEV_ALL_QID_2_FLOWID_QUEUE_PAIRS_OVERFLOW = 1,
	PLCR_GET_REQ_TYPE_INVALID_ERR,
	PLCR_DUPLICATE_RATE,
	PLCR_REMOVE_RATE_LIMIT,

	PLCR_ERROR_NUM
};

enum E_PLCR_CAR_TYPE {
	E_PLCR_CAR_A = 0,
	E_PLCR_CAR_B = 1,
	E_PLCR_CAR_C = 2,
	E_PLCR_CAR_NUM = 3,
};

union zxdh_plcr_profile_cfg {
	struct dpp_stat_car_profile_cfg_t byte_profile_cfg;
	struct dpp_stat_car_pkt_profile_cfg_t pkt_profile_cfg;
};

enum E_RATE_LIMIT_MODE {
	E_RATE_LIMIT_MODE0 = 0,
	E_RATE_LIMIT_MODE1,
	E_RATE_LIMIT_MODE2,
	E_RATE_LIMIT_MODE3,
};

enum E_RATE_LIMIT_REQ_TYPE {
	E_RATE_LIMIT_REQ_QUEUE_BYTE = 0,
	E_RATE_LIMIT_REQ_VF_BYTE,
	E_RATE_LIMIT_REQ_VF_GROUP_BYTE,
	E_RATE_LIMIT_REQ_VF_PKT,
	E_RATE_LIMIT_REQ_MOVE_VF_GROUP,
	E_RATE_LIMIT_REQ_TYPE_NUM,
};

/* Define rate limit direction */
enum E_RATE_LIMIT_DIRECTION {
	E_RATE_LIMIT_RX = 0,
	E_RATE_LIMIT_TX,
};

/* Define rate limit type */
enum E_RATE_LIMIT_PKT_BYTE {
	E_RATE_LIMIT_BYTE = 0,
	E_RATE_LIMIT_PACKET,
};

struct zxdh_plcr_rate_limit_paras {
	enum E_RATE_LIMIT_REQ_TYPE req_type;
	enum E_RATE_LIMIT_DIRECTION direction;
	enum E_RATE_LIMIT_PKT_BYTE mode;
	u32 max_rate;
	u32 min_rate;
	u32 queue_id;
	u32 vf_idx;
	u32 vfid;
	u32 vport;
	u32 group_id;
};

struct zxdh_plcr_flowids {
	u16 queue_pairs;
	u16 flowids_A[2][PLCR_MAX_QUEUE_PAIRS];
	u16 flowid_A[2];
	u16 flowid_B[2];
	u16 flowid_C[2];
};

struct zxdh_plcr_profile {
	u16 ref_cnt;
	u16 profile_id;
	u16 vport;
	u32 max_rate;
	u32 min_rate;
	u64 cred_id;
	struct dpp_stat_car_profile_cfg_t profile_cfg;
};

struct zxdh_plcr_flow {
	u16 vport;
	u16 vf_id;
	u16 profile_id;
	u16 flowid;
	u16 map_flowid;
	u16 next_flowid;
	u32 max_rate;
	u32 min_rate;
};

struct dh_core_dev;
struct zxdh_pf_device;
struct zxdh_en_priv;

enum ZXDH_GROUP_DATA_TYPE {
	ZXDH_GROUP_RX_RATE = 0,
	ZXDH_GROUP_TX_RATE = 1,
};

struct zxdh_group_obj {
	struct zxdh_pf_device *pf_dev;
	struct kobject kobj;
	struct completion free_group_comp;

	struct list_head list;
	s32 group_id;
	s32 num_vfs;
	u32 max_tx_rate;
	u32 max_rx_rate;
};

struct zxdh_group_work {
	struct work_struct work;
	struct zxdh_group_obj *group_obj;
};

enum ZXDH_VF_METER_DATA_TYPE {
	ZXDH_VF_MIN_RATE = 0,
	ZXDH_VF_MAX_RATE = 1,
};

enum ZXDH_VF_METER_TYPE {
	VF_METER_RX_BPS = 0,
	VF_METER_RX_PPS = 1,
	VF_METER_TX_BPS = 2,
	VF_METER_TX_PPS = 3,
	VF_METER_TYPE_NUM,
};

#define IS_TX_METER(meter_type) ((meter_type) == VF_METER_TX_BPS || (meter_type) == VF_METER_TX_PPS)
#define IS_PPS_METER(meter_type) \
	((meter_type) == VF_METER_RX_PPS || (meter_type) == VF_METER_TX_PPS)

struct zxdh_vf_meter_obj {
	struct zxdh_pf_device *pf_dev;
	struct zxdh_vf_obj *vf_obj;
	struct kobject kobj;
	u32 meter_type;
	u32 min_rate;
	u32 max_rate;
};

struct zxdh_vf_meters {
	struct kobject *kobj;
	struct kobject *rx_obj;
	struct kobject *tx_obj;
	struct zxdh_vf_meter_obj xps[4];
};

struct zxdh_vf_file_stats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_broadcast;
	u64 rx_multicast;
	u64 tx_broadcast;
	u64 tx_multicast;
	u64 rx_dropped;
	u64 tx_error;
	u64 rx_error;
};

struct zxdh_vf_obj {
	struct zxdh_pf_device *pf_dev;
	struct kobject kobj;
	u16 vport;
	u16 vf_idx;
	struct zxdh_group_obj *group;
	struct zxdh_vf_meters *meters;
};

struct zxdh_sriov_sysfs {
	struct kobject *sriov_obj;
#ifdef ZXDH_PLCR_DEBUG
	struct kobj_attribute burst_attr;
	struct kobj_attribute profile_attr;
	struct kobj_attribute all_vf_stats_attr;
#endif
	struct kobject *groups_obj;
	struct zxdh_group_obj *group_0;
	struct list_head groups_head;
	struct zxdh_vf_obj *vfs;
};

struct zxdh_plcr_table {
	struct xarray plcr_profiles[E_PLCR_CAR_NUM];
	struct xarray plcr_flows[E_PLCR_CAR_NUM];
	struct xarray plcr_maps[E_PLCR_CAR_NUM];
	u32 burst_size;
	bool is_init;
};

struct zxdh_plcr_cbs {
	u32 min_rate;
	u32 max_rate;
	u32 cbs;
};

struct vqm_rate {
	u32 pack_rate; //pps
	u32 rate; //kbps
} __packed;

struct vqm_poll {
	u16 poll_mode; /* bit0:rx, bit1:tx, 1:poll, 0:kick */
	u16 poll_time; /* 0:not cfg, other:cfg, unit:ms */
} __packed;

struct vqm_global_feature {
	u16 version;
	u64 features;
} __packed;

struct zxdh_vqm_param {
	u16 vqm_vfid;
	u16 opcode;
	u16 cmd;
	union {
		u8 mac[6];
		u8 enable_flag;
		struct vqm_rate vqm_rate;
		struct vqm_poll vqm_poll;
		struct vqm_global_feature vqm_global_feature;
	};
} __packed;

extern const u32 gaudplcrcarxprofilenum[E_PLCR_CAR_NUM];
extern const u32 gaudplcrcarxflowidnum[E_PLCR_CAR_NUM];
int zxdh_plcr_remove_rate_limit(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				u32 flowid, u32 flag);
void zxdh_plcr_count_profiles(struct zxdh_pf_device *pf_dev);
int zxdh_plcr_set_rate_limit(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_PKT_BYTE is_pkt_mode,
			     enum E_PLCR_CAR_TYPE car_type, u16 vport, u32 flowid, u32 max_rate,
			     u32 min_rate);
s32 zxdh_plcr_get_next_map(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid,
			   u32 *map_flowid);
s32 zxdh_plcr_init(struct zxdh_en_priv *en_priv);
s32 zxdh_plcr_uninit(struct zxdh_en_priv *en_priv);
int zxdh_plcr_get_vport_vfid(struct zxdh_pf_device *pf_dev, u32 vf_idx, u32 *vport, u32 *vfid);
int zxdh_plcr_req_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			  u16 *profile_id_out);
int zxdh_plcr_release_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			      u16 profile_id, u32 flag);
int zxdh_plcr_count_up_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			       u16 profile_id);
int zxdh_plcr_count_down_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				 u16 profile_id);
int zxdh_plcr_cfg_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			  struct dpp_stat_car_profile_cfg_t *profile_cfg);
int zxdh_plcr_get_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			  u32 pkt_sign, u16 profile_id,
			  struct dpp_stat_car_profile_cfg_t *profile_cfg);
u32 zxdh_plcr_reg_maxrate_user(u32 reg_maxrate);
s32 zxdh_plcr_req_flow(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u16 flow_id,
		       struct zxdh_plcr_flow **flow);
s32 zxdh_plcr_release_flow(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			   u16 flow_id);
void zxdh_plcr_update_flow(struct zxdh_plcr_flow *flow, u16 vport, u32 max_rate, u32 min_rate);
int zxdh_plcr_store_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			    u32 user_max_rate, u32 user_min_rate,
			    struct dpp_stat_car_profile_cfg_t *profile_cfg);
s32 zxdh_plcr_stroe_map(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid,
			u32 map_flowid);
s32 zxdh_plcr_clear_map(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid);
int zxdh_pf_plcr_get_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE *p_mode);
int zxdh_pf_plcr_set_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE mode);
int zxdh_plcr_get_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE *mode);
int zxdh_plcr_set_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE mode);
int zxdh_plcr_unified_set_rate_limit(struct zxdh_pf_device *pf_dev,
				     struct zxdh_plcr_rate_limit_paras *rate_limit_paras);
s32 zxdh_plcr_recover_cfg(struct zxdh_vf_item *vf_item, struct zxdh_pf_device *pf_dev, s32 vf_idx);
int zxdh_vqm_vf_set_rate_limit(struct zxdh_pf_device *pf_dev, u16 vqm_vfid, u32 vf_rate);

int zxdh_vf_update_sysfs_group(struct zxdh_pf_device *pf_dev, struct zxdh_vf_obj *vf, s32 group_id);
int zxdh_create_vfs_sysfs(struct dh_core_dev *dev, s32 num_vfs);
void zxdh_destroy_vfs_sysfs(struct dh_core_dev *dev, s32 num_vfs);
int zxdh_sriov_sysfs_init(struct dh_core_dev *dev);
void zxdh_sriov_sysfs_exit(struct dh_core_dev *dev);

#endif
