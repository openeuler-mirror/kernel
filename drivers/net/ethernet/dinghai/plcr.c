// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/zxdh_auxiliary_bus.h>
#include <linux/dinghai/driver.h>
#include <net/devlink.h>
#include <net/udp_tunnel.h>
#include <linux/dinghai/devlink.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/netdevice.h>
#include "en_aux.h"
#include "en_ethtool/ethtool.h"
#include <linux/dinghai/en_sf.h>
#include <linux/etherdevice.h>
#include <linux/dinghai/helper.h>
#include "en_np/table/include/dpp_tbl_api.h"
#include "en_np/table/include/dpp_tbl_plcr.h"
#include "en_aux/en_aux_events.h"
#include "en_aux/en_aux_eq.h"
#include "en_aux/en_aux_cmd.h"
#include "msg_common.h"
#include "cmd/msg_chan_priv.h"
#include "en_pf.h"
#include <linux/dinghai/zxdh_compat.h>
#include "en_aux/en_aux_ioctl.h"
#ifdef TIME_STAMP_1588
#include "en_aux/en_1588_pkt_proc.h"
#endif

#define VQM_BAR_MSG 36

#define OPCODE_GET 0
#define OPCODE_SET 1

#define CMD_MAC 1
#define CMD_ENABLED_QP 4
#define CMD_FEATURES 5
#define CMD_DRIVER_STATUS 6
#define CMD_VF_STATS 7
#define CMD_VF_FLAG 8
#define CMD_VF_QOS 9
#define CMD_VF_POLL 10
#define CMD_GLOBAL_FEATURES 11

const u32 gaudplcrcarxprofilenum[E_PLCR_CAR_NUM] = {
	PLCR_CAR_A_PROFILE_RES_NUM,
	PLCR_CAR_B_PROFILE_RES_NUM,
	PLCR_CAR_C_PROFILE_RES_NUM,
};

const u32 gaudplcrcarxflowidnum[E_PLCR_CAR_NUM] = {
	PLCR_CAR_A_FLOWID_RES_NUM,
	PLCR_CAR_B_FLOWID_RES_NUM,
	PLCR_CAR_C_FLOWID_RES_NUM,
};

struct zxdh_plcr_cbs gat_cara_byte_rate_limit_cbs[] = {
	{ 0, 500, 4 * 1024 * 1024 },	     { 500, 800, 10 * 1024 * 1024 },
	{ 800, 1500, 12 * 1024 * 1024 },     { 1500, 3000, 15 * 1024 * 1024 },
	{ 3000, 12000, 20 * 1024 * 1024 },   { 12000, 20000, 30 * 1024 * 1024 },
	{ 20000, 500000, 50 * 1024 * 1024 },
};

struct zxdh_plcr_cbs gat_carb_byte_rate_limit_cbs[] = {
	{ 0, 4000, 8 * 1024 * 1024 },
	{ 4000, 8000, 16 * 1024 * 1024 },
	{ 8000, 16000, 64 * 1024 * 1024 },
	{ 16000, 500000, 128 * 1024 * 1024 - 1 },
};

static inline struct zxdh_en_device *pf_dev_get_edev(struct zxdh_pf_device *pf_dev)
{
	struct zxdh_auxiliary_device *adev = NULL;
	struct zxdh_en_sf_container *sf_con = NULL;
	struct zxdh_en_sf_device *en_sf_dev = NULL;
	struct zxdh_en_priv *en_priv = NULL;
	struct zxdh_en_device *en_dev = NULL;

	adev = pf_dev->adevs_table[0].adev; //sf adev
	sf_con = container_of(adev, struct zxdh_en_sf_container, adev);
	en_sf_dev = dh_core_priv(sf_con->cdev); //sf cdev
	en_priv = en_sf_dev->adev[0]->dev.driver_data; //en adev
	if (!en_priv)
		return ERR_PTR(-ENODEV);

	en_dev = &en_priv->edev;
	if (!en_dev && !en_dev->init_comp_flag) {
		LOG_ERR("en_device not initialized!\n");
		return ERR_PTR(-ENODEV);
	}

	return en_dev;
}

u32 zxdh_plcr_user_maxrate_2_reg(u32 user_max_rate)
{
	u64 reg_maxrate;

	PLCR_FUNC_DBG_ENTER();
	reg_maxrate = ((u64)user_max_rate << 10 / PLCR_STEP_SIZE);
	return (u32)reg_maxrate;
}

u32 zxdh_plcr_reg_maxrate_user(u32 reg_maxrate)
{
	u32 user_max_rate;

	PLCR_FUNC_DBG_ENTER();

	user_max_rate = reg_maxrate * PLCR_STEP_SIZE / 1024;

	return user_max_rate;
}

static s32 zxdh_plcr_match_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				   struct dpp_stat_car_profile_cfg_t *profile_cfg, u16 *profile_id)
{
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];
	struct zxdh_plcr_profile *profile;
	unsigned long index;
	struct dpp_stat_car_pkt_profile_cfg_t *pkt_profile_cfg =
		(struct dpp_stat_car_pkt_profile_cfg_t *)(profile_cfg);
	u32 profile_max_num = gaudplcrcarxprofilenum[car_type];

	PLCR_FUNC_DBG_ENTER();

	xa_for_each_range(xarray_profile, index, profile, 0, profile_max_num) {
		if (!profile->ref_cnt)
			continue;

		if (profile_cfg->pkt_sign == E_RATE_LIMIT_PACKET) {
			if ((pkt_profile_cfg->pkt_sign ==
			     (((struct dpp_stat_car_pkt_profile_cfg_t *)(&profile->profile_cfg))
				      ->pkt_sign)) &&
			    (pkt_profile_cfg->cir ==
			     (((struct dpp_stat_car_pkt_profile_cfg_t *)(&profile->profile_cfg))
				      ->cir)) &&
			    (pkt_profile_cfg->cbs ==
			     (((struct dpp_stat_car_pkt_profile_cfg_t *)(&profile->profile_cfg))
				      ->cbs))) {
				*profile_id = profile->profile_id;
				PLCR_LOG_INFO("profile_id = %d\n", *profile_id);

				return 0;
			}
		}

		else if (profile_cfg->pkt_sign == E_RATE_LIMIT_BYTE) {
			if ((profile->profile_cfg.pkt_sign == profile_cfg->pkt_sign) &&
			    (profile->profile_cfg.cd == profile_cfg->cd) &&
			    (profile->profile_cfg.cf == profile_cfg->cf) &&
			    (profile->profile_cfg.cm == profile_cfg->cm) &&
			    (profile->profile_cfg.cir == profile_cfg->cir) &&
			    (profile->profile_cfg.cbs == profile_cfg->cbs) &&
			    (profile->profile_cfg.eir == profile_cfg->eir) &&
			    (profile->profile_cfg.ebs == profile_cfg->ebs)) {
				*profile_id = profile->profile_id;
				PLCR_LOG_INFO("profile_id = %d\n", *profile_id);

				return 0;
			}
		}
	}

	return -ERANGE;
}

s32 zxdh_plcr_req_flow(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u16 flow_id,
		       struct zxdh_plcr_flow **flow)
{
	struct zxdh_plcr_flow *flow_old;
	struct xarray *xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];

	PLCR_FUNC_DBG_ENTER();

	*flow = kzalloc(sizeof(struct zxdh_plcr_flow), GFP_KERNEL);
	if (unlikely(*flow == NULL)) {
		PLCR_LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	flow_old = xa_store(xarray_flow, flow_id, *flow, GFP_KERNEL);

	kfree(flow_old);

	return 0;
}

s32 zxdh_plcr_release_flow(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			   u16 flow_id)
{
	struct zxdh_plcr_flow *flow;
	struct xarray *xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];

	PLCR_FUNC_DBG_ENTER();

	flow = xa_load(xarray_flow, flow_id);
	if (!flow) {
		PLCR_LOG_ERR("failed to release an invalid flow_id=%d\n", flow_id);
		return -EINVAL;
	}

	xa_erase(xarray_flow, flow_id);
	kfree(flow);
	return 0;
}

void zxdh_plcr_update_flow(struct zxdh_plcr_flow *flow, u16 vport, u32 max_rate, u32 min_rate)
{
	flow->vport = vport;
	flow->max_rate = max_rate;
	flow->min_rate = min_rate;
}

int zxdh_plcr_req_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			  u16 *profile_id_out)
{
	int rtn = 0;
	struct zxdh_plcr_profile *profile;
	struct zxdh_plcr_profile *profile_old;
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];
	u16 profile_id = 0;
	u64 cred_id = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	PLCR_FUNC_DBG_ENTER();

	rtn = dpp_car_profile_id_add(&pf_info, (u32)car_type, &cred_id);
	if (rtn) {
		PLCR_LOG_ERR("failed to request a new profile\n");
		return -EINVAL;
	}

	if (0 != ((cred_id >> 56) & 0xFF)) {
		PLCR_LOG_ERR("failed to request a new profile\n");
		return -EINVAL;
	}

	profile_id = PROFILE_ID(cred_id);
	*profile_id_out = profile_id;
	PLCR_LOG_INFO(
		"dpp_car_profile_id_add: pf_info.vport = 0x%x, car_type = %d, profile_id = %d, cred_id = 0x%llx\n",
		pf_info.vport, car_type, profile_id, cred_id);

	profile = kzalloc(sizeof(struct zxdh_plcr_profile), GFP_KERNEL);
	if (unlikely(!profile)) {
		dpp_car_profile_id_delete(&pf_info, (u32)car_type, cred_id);
		PLCR_LOG_ERR("failed to kzalloc profile\n");

		return -ENOMEM;
	}
	profile->ref_cnt = 0;
	profile->max_rate = 0;
	profile->min_rate = 0;
	profile->cred_id = cred_id;
	profile->profile_id = profile_id;
	profile->vport = pf_dev->vport;

	profile_old = xa_store(xarray_profile, profile_id, profile, GFP_KERNEL);
	if (profile_old) {
		PLCR_LOG_ERR("failed to unreachable branch\n");
		kfree(profile_old);
	}

	return rtn;
}

int zxdh_plcr_release_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			      u16 profile_id, u32 flag)
{
	int rtn = 0;
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];
	struct zxdh_plcr_profile *profile;
	struct dpp_pf_info_t pf_info = { 0 };

	PLCR_FUNC_DBG_ENTER();

	profile = xa_load(xarray_profile, profile_id);
	if (!profile) {
		PLCR_LOG_ERR("failed to release an invalid profile=%d\n", profile_id);
		return -EINVAL;
	}

	if (!profile->ref_cnt) {
		pf_info.slot = pf_dev->slot_id;
		pf_info.vport = profile->vport;
		PLCR_LOG_INFO(
			"dpp_car_profile_id_delete: pf_info.vport = 0x%x, car_type = %d, profile_id = %d, cred_id = 0x%llx\n",
			pf_info.vport, car_type, profile_id, profile->cred_id);

		if (!flag) {
			rtn = dpp_car_profile_id_delete(&pf_info, car_type, profile->cred_id);
			if (rtn) {
				PLCR_LOG_ERR(
					"failed to call dpp_car_profile_id_delete, car_type=%d,profile_id=%d)\n",
					car_type, profile_id);
				rtn = EINVAL;
			}
		}

		xa_erase(xarray_profile, profile_id);

		kfree(profile);
	}

	return rtn;
}

static int zxdh_plcr_gen_profile(struct zxdh_pf_device *pf_dev,
				 enum E_RATE_LIMIT_PKT_BYTE is_pkt_mode,
				 enum E_PLCR_CAR_TYPE car_type, u32 max_rate, u32 min_rate,
				 struct dpp_stat_car_profile_cfg_t *profile_cfg)
{
	int rtn = 0;
	int pri = 0;
	u32 cbs = 0;
	u32 ebs = 0;
	struct dpp_stat_car_pkt_profile_cfg_t *pkt_profile_cfg =
		(struct dpp_stat_car_pkt_profile_cfg_t *)(profile_cfg);

	PLCR_FUNC_DBG_ENTER();

	if (is_pkt_mode == E_RATE_LIMIT_PACKET && car_type != E_PLCR_CAR_A) {
		PLCR_LOG_ERR("failed and only CAR A supports packet rate limit\n");
		rtn = -EINVAL;
	}

	memset(profile_cfg, 0, sizeof(*profile_cfg));
	if (is_pkt_mode == E_RATE_LIMIT_BYTE) {
		if (max_rate > USER_MAX_BYTE_RATE) {
			PLCR_LOG_ERR("failed and rtn=%d\n", -EINVAL);
			return -EINVAL;
		}

		profile_cfg->pkt_sign = E_RATE_LIMIT_BYTE;
		profile_cfg->cf = 1;

		if (pf_dev->plcr_table.burst_size) {
			cbs = pf_dev->plcr_table.burst_size;
			ebs = pf_dev->plcr_table.burst_size;
		} else {
			cbs = DPP_CAR_MAX_CBS_VALUE;
			ebs = DPP_CAR_MAX_EBS_VALUE;
		}

		profile_cfg->cbs = cbs;
		profile_cfg->ebs = ebs;
		profile_cfg->random_disc_c = 0;
		profile_cfg->random_disc_e = 0;

		if (car_type == E_PLCR_CAR_A) {
			profile_cfg->cm = 0;
			profile_cfg->cd = 0;
			profile_cfg->cir = zxdh_plcr_user_maxrate_2_reg(max_rate);
			profile_cfg->eir = 0;
		} else if (car_type == E_PLCR_CAR_B) {
			profile_cfg->cm = 1;
			profile_cfg->cd = 1;
			profile_cfg->cir = zxdh_plcr_user_maxrate_2_reg(min_rate);
			profile_cfg->eir = zxdh_plcr_user_maxrate_2_reg(max_rate);
		} else if (car_type == E_PLCR_CAR_C) {
			profile_cfg->cm = 1;
			profile_cfg->cd = 0;
			profile_cfg->cir = zxdh_plcr_user_maxrate_2_reg(max_rate);
			profile_cfg->eir = 0;
		}

		for (pri = 0; pri < DPP_CAR_PRI_MAX; pri++) {
			profile_cfg->c_pri[pri] = 0;
			profile_cfg->e_green_pri[pri] = 0;
			profile_cfg->e_yellow_pri[pri] = 0;
		}

		PLCR_LOG_INFO("cir = 0x%x, eir = 0x%x, cbs = 0x%x, ebs = 0x%x\n", profile_cfg->cir,
			      profile_cfg->eir, profile_cfg->cbs, profile_cfg->ebs);
	} else {
		if (max_rate > USER_MAX_PKT_RATE) {
			PLCR_LOG_ERR("failed and rtn=%d\n", -EINVAL);
			return -EINVAL;
		}
		if (pf_dev->plcr_table.burst_size)
			cbs = pf_dev->plcr_table.burst_size;
		else
			cbs = DPP_CAR_MAX_PKT_CBS_VALUE;

		pkt_profile_cfg->pkt_sign = E_RATE_LIMIT_PACKET;
		pkt_profile_cfg->cbs = cbs;
		pkt_profile_cfg->cir = max_rate;

		PLCR_LOG_INFO("pkt_type = 0x%x, cir = 0x%x, cbs = 0x%x\n",
			      pkt_profile_cfg->pkt_sign, pkt_profile_cfg->cir,
			      pkt_profile_cfg->cbs);
	}

	return rtn;
}

static void zxdh_plcr_update_profile(struct dpp_stat_car_profile_cfg_t *profile_cfg,
				     u_int16_t profile_id)
{
	PLCR_FUNC_DBG_ENTER();

	profile_cfg->profile_id = profile_id;
}

int zxdh_plcr_store_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			    u32 user_max_rate, u32 user_min_rate,
			    struct dpp_stat_car_profile_cfg_t *profile_cfg)
{
	int rtn = 0;
	u16 profile_id;
	struct zxdh_plcr_profile *profile;
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];

	PLCR_FUNC_DBG_ENTER();

	profile_id = profile_cfg->profile_id;

	profile = xa_load(xarray_profile, profile_id);
	if (!profile) {
		PLCR_LOG_ERR("failed to an invalid profile, profile_id=%d\n", profile_id);
		return -EINVAL;
	}

	profile->max_rate = user_max_rate;
	profile->min_rate = user_min_rate;

	memcpy(&profile->profile_cfg, profile_cfg, sizeof(struct dpp_stat_car_profile_cfg_t));

	return rtn;
}

int zxdh_plcr_cfg_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			  struct dpp_stat_car_profile_cfg_t *profile_cfg)
{
	int rtn = 0;
	u16 profile_id = 0;
	u32 pkt_sign = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	PLCR_FUNC_DBG_ENTER();

	profile_id = profile_cfg->profile_id;

	pkt_sign = profile_cfg->pkt_sign;

	rtn = dpp_car_profile_cfg_set(&pf_info, (u32)car_type, pkt_sign, profile_id, profile_cfg);
	if (rtn) {
		PLCR_LOG_ERR(
			"failed to configure the profile registers, car_type=%d,profile_id=%d\n",
			car_type, profile_id);
		return -EINVAL;
	}
	PLCR_LOG_INFO(
		"dpp_car_profile_cfg_set: pf_info.vport = 0x%x, car_type = %d, profile_id = %d, pkt_sign = %d\n",
		pf_info.vport, car_type, profile_id, pkt_sign);

	return rtn;
}

int zxdh_plcr_get_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			  u32 pkt_sign, u16 profile_id,
			  struct dpp_stat_car_profile_cfg_t *profile_cfg)
{
	int rtn = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	PLCR_FUNC_DBG_ENTER();

	PLCR_LOG_INFO(
		"dpp_car_profile_cfg_get: pf_info.vport = 0x%x, car_type = %d, profile_id = %d, pkt_sign = %d\n",
		pf_info.vport, car_type, profile_id, pkt_sign);
	rtn = dpp_car_profile_cfg_get(&pf_info, car_type, pkt_sign, profile_id, profile_cfg);
	if (rtn) {
		PLCR_LOG_ERR(
			"failed to call dpp_car_profile_cfg_get(), car_type=%d,profile_id=%d\n",
			car_type, profile_id);
		return -EINVAL;
	}

	return rtn;
}

static int zxdh_plcr_bind_flow_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				       u32 flowid, u16 profile_id)
{
	int rtn = 0;
	struct zxdh_plcr_flow *plcr_flow;
	struct xarray *xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	PLCR_FUNC_DBG_ENTER();

	plcr_flow = xa_load(xarray_flow, flowid);
	if (!plcr_flow) {
		PLCR_LOG_ERR(
			"failed to xa_load an invalid element,car_type=%d,flowid=%d,profile_id=%d\n",
			car_type, flowid, profile_id);
		return -EINVAL;
	}

	PLCR_LOG_INFO(
		"dpp_car_queue_cfg_set: pf_info.vport = 0x%x, car_type = %d, flowid = %d, profile_id = %d\n",
		pf_info.vport, car_type, flowid, profile_id);
	rtn = dpp_car_queue_cfg_set(&pf_info, (u32)car_type, flowid, DROP_DISABLE, PLCR_ENABLE,
				    profile_id);
	if (rtn) {
		PLCR_LOG_ERR(
			"failed to call dpp_car_queue_cfg_set(),car_type=%d,flowid=%d,profile_id=%d\n",
			car_type, flowid, profile_id);
		return -EINVAL;
	}
	PLCR_LOG_INFO("Bind profile_%d to flow_%d complete\n", profile_id, flowid);

	plcr_flow->profile_id = profile_id;

	return rtn;
}

int zxdh_plcr_unbind_flow_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				  u32 flowid, u16 profile_id, u32 flag)
{
	int rtn = 0;
	struct zxdh_plcr_flow *plcr_flow;
	struct xarray *xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	PLCR_FUNC_DBG_ENTER();

	plcr_flow = xa_load(xarray_flow, flowid);
	if (!plcr_flow) {
		PLCR_LOG_ERR("xa_load an invalid element, flowid=%d,profile_id=%d\n", flowid,
			     profile_id);
		return -EINVAL;
	}
	if (profile_id != plcr_flow->profile_id) {
		PLCR_LOG_ERR("xa_load an invalid element, profile_id=%d,plcr_flow->profile_id=%d\n",
			     profile_id, plcr_flow->profile_id);
		return -EINVAL;
	}

	PLCR_LOG_INFO(
		"dpp_car_queue_cfg_set: pf_info.vport = 0x%x, car_type = %d, flowid = %d, profile_id = %d\n",
		pf_info.vport, car_type, flowid, profile_id);
	if (!flag) {
		rtn = dpp_car_queue_cfg_set(&pf_info, (u32)car_type, flowid, DROP_DISABLE,
					    PLCR_DISABLE, profile_id);
		if (rtn) {
			PLCR_LOG_ERR(
				"failed to call dpp_car_queue_cfg_set(),car_type=%d,flowid=%d,profile_id=%d\n",
				car_type, flowid, profile_id);
			return rtn;
		}
	}

	return rtn;
}

int zxdh_plcr_count_up_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
			       u16 profile_id)
{
	int rtn = 0;
	struct zxdh_plcr_profile *plcr_profile;
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];

	PLCR_FUNC_DBG_ENTER();

	plcr_profile = xa_load(xarray_profile, profile_id);
	if (!plcr_profile) {
		PLCR_LOG_ERR(
			"failed to load element form xarray_profile, car_type=%d,profile_id=%d\n",
			car_type, profile_id);
		return -EINVAL;
	}

	plcr_profile->ref_cnt++;

	return rtn;
}

int zxdh_plcr_count_down_profile(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				 u16 profile_id)
{
	int rtn = 0;
	struct zxdh_plcr_profile *plcr_profile;
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];

	PLCR_FUNC_DBG_ENTER();

	plcr_profile = xa_load(xarray_profile, profile_id);
	if (!plcr_profile) {
		PLCR_LOG_ERR(
			"failed to load element form xarray_profile, car_type=%d,profile_id=%d\n",
			car_type, profile_id);
		return -EINVAL;
	}

	if (!plcr_profile->ref_cnt) {
		PLCR_LOG_ERR("failed and plcr_profile->ref_cnt=0\n");
		return -EINVAL;
	}

	plcr_profile->ref_cnt--;

	return rtn;
}

static int zxdh_plcr_get_profile_by_flowid(struct zxdh_pf_device *pf_dev,
					   enum E_PLCR_CAR_TYPE car_type, u32 flowid,
					   struct zxdh_plcr_profile **pplcr_profile)
{
	int rtn = 0;
	u16 profile_id = 0;
	struct zxdh_plcr_profile *plcr_profile;
	struct zxdh_plcr_flow *plcr_flow;
	struct xarray *xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_type];
	struct xarray *xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];

	PLCR_FUNC_DBG_ENTER();

	plcr_flow = xa_load(xarray_flow, flowid);
	if (!plcr_flow) {
		PLCR_LOG_ERR("failed to load element form xarray_flow, car_type=%d,flowid=%d\n",
			     car_type, flowid);
		return -EINVAL;
	}
	profile_id = plcr_flow->profile_id;

	plcr_profile = xa_load(xarray_profile, profile_id);
	if (!plcr_profile) {
		PLCR_LOG_ERR(
			"failed to load element form xarray_profile,car_type=%d,profile_id=%d\n",
			car_type, profile_id);
		return -EINVAL;
	}

	*pplcr_profile = plcr_profile;

	return rtn;
}

s32 zxdh_plcr_stroe_map(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid,
			u32 map_flowid)
{
	s32 rtn = 0;
	struct xarray *xarray_map = &pf_dev->plcr_table.plcr_maps[car_type];

	if (car_type == E_PLCR_CAR_A || car_type == E_PLCR_CAR_B) {
		xa_store(xarray_map, flowid, (void *)(uintptr_t)(FLOWID_2_XARRAY(map_flowid)),
			 GFP_KERNEL);
	}

	return rtn;
}

s32 zxdh_plcr_clear_map(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid)
{
	s32 rtn = 0;
	void *xarray_element;
	struct xarray *xarray_map = &pf_dev->plcr_table.plcr_maps[car_type];

	if (car_type == E_PLCR_CAR_A || car_type == E_PLCR_CAR_B) {
		xarray_element = xa_load(xarray_map, flowid);
		if (xarray_element)
			xa_erase(xarray_map, flowid);
	}

	return rtn;
}

s32 zxdh_plcr_get_next_map(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid,
			   u32 *map_flowid)
{
	s32 rtn = 0;
	void *xarray_element;
	struct xarray *xarray_map = &pf_dev->plcr_table.plcr_maps[car_type];

	if (car_type == E_PLCR_CAR_A || car_type == E_PLCR_CAR_B) {
		xarray_element = xa_load(xarray_map, flowid);
		if (!xarray_element)
			rtn = -EINVAL;
		else
			*map_flowid = XARRAY_2_FLOWID((u32)(uintptr_t)xarray_element);
	} else {
		rtn = -ERANGE;
	}

	return rtn;
}

int zxdh_plcr_check_release_flow_chain(struct zxdh_pf_device *pf_dev,
				       enum E_PLCR_CAR_TYPE e_car_type, u16 vport)
{
	int rtn = 0;
	enum E_PLCR_CAR_TYPE car_type;
	u32 flag1 = 0;
	u32 flag2 = 0;
	unsigned long flow_index;
	u32 flowid_car_B;
	u32 flowid_car_C;
	struct zxdh_plcr_flow *flow;
	struct xarray *xarray_flow;

	PLCR_FUNC_DBG_ENTER();

	if (e_car_type == E_PLCR_CAR_C) {
		PLCR_LOG_INFO("It is not necessary to change mode for vf group limit!\n");
		return rtn;
	}

	for (car_type = E_PLCR_CAR_A, flag1 = 0; car_type < E_PLCR_CAR_C; car_type++) {
		xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];

		xa_for_each_range(xarray_flow, flow_index, flow, 0,
				  gaudplcrcarxflowidnum[car_type]) {
			if (vport == flow->vport) {
				flag1 = 1;
				break;
			}
		}
		if (flag1 == 1) {
			PLCR_LOG_INFO("flow->flowid = 0x%x, vport = 0x%x\n", flow->flowid, vport);
			break;
		}
	}

	if (flag1 == 0) {
		if (VF_ACTIVE(vport)) {
			flowid_car_B = VQM_VFID(vport) * 2;
			rtn = zxdh_plcr_get_next_map(pf_dev, E_PLCR_CAR_B, flowid_car_B,
						     &flowid_car_C);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
			PLCR_LOG_INFO("flowid_car_B = 0x%x\n", flowid_car_B);
			PLCR_LOG_INFO("flowid_car_C = 0x%x\n", flowid_car_C);

			if ((flowid_car_C % (PLCR_CAR_C_FLOWIDS_PER_PF)) == 0)
				flag2 = 1;
		} else {
			flag2 = 1;
		}
	}

	if (flag2 != 0) {
		PLCR_LOG_INFO("Change to mode0: e_car_type = 0x%x, vport = 0x%x,\n", e_car_type,
			      vport);
		zxdh_plcr_set_mode(pf_dev, vport, E_RATE_LIMIT_MODE0);
	}

	return rtn;
}

static int zxdh_plcr_create_rate_limit(struct zxdh_pf_device *pf_dev,
				       enum E_RATE_LIMIT_PKT_BYTE is_pkt_mode,
				       enum E_PLCR_CAR_TYPE car_type, u16 vport, u32 flowid,
				       u32 max_rate, u32 min_rate)
{
	int rtn = 0;
	u16 profile_id = 0;
	struct dpp_stat_car_profile_cfg_t profile_cfg;
	struct zxdh_plcr_flow *plcr_flow = NULL;

	PLCR_FUNC_DBG_ENTER();

	if (max_rate == 0 && min_rate == 0) {
		PLCR_LOG_INFO("duplicate max_rate=%d on flowid=%d\n", max_rate, flowid);
		return PLCR_DUPLICATE_RATE;
	}

	rtn = zxdh_plcr_req_flow(pf_dev, car_type, flowid, &plcr_flow);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	zxdh_plcr_update_flow(plcr_flow, vport, max_rate, min_rate);

	rtn = zxdh_plcr_gen_profile(pf_dev, is_pkt_mode, car_type, max_rate, min_rate,
				    &profile_cfg);
	if (rtn) {
		PLCR_LOG_ERR("failed to call zxdh_plcr_gen_profile()\n");
		goto err3;
	}

	rtn = zxdh_plcr_match_profile(pf_dev, car_type, &profile_cfg, &profile_id);
	if (rtn) {
		rtn = zxdh_plcr_req_profile(pf_dev, car_type, &profile_id);
		if (rtn) {
			PLCR_LOG_ERR("failed to call zxdh_plcr_req_profile()\n");
			goto err3;
		}

		zxdh_plcr_update_profile(&profile_cfg, profile_id);

		rtn = zxdh_plcr_cfg_profile(pf_dev, car_type, &profile_cfg);
		if (rtn) {
			PLCR_LOG_ERR("failed to call zxdh_plcr_cfg_profile()\n");
			goto err2;
		}

		rtn = zxdh_plcr_store_profile(pf_dev, car_type, max_rate, min_rate, &profile_cfg);
		if (rtn) {
			PLCR_LOG_ERR("failed to call zxdh_plcr_store_profile()\n");
			goto err2;
		}
	}

	rtn = zxdh_plcr_bind_flow_profile(pf_dev, car_type, flowid, profile_id);
	if (rtn) {
		PLCR_LOG_ERR("failed to call zxdh_plcr_bind_flow_profile()\n");
		goto err2;
	}

	rtn = zxdh_plcr_count_up_profile(pf_dev, car_type, profile_id);
	if (rtn) {
		PLCR_LOG_ERR("failed to call zxdh_plcr_count_up_profile()\n");
		goto err1;
	}

	return rtn;

err1:
	zxdh_plcr_unbind_flow_profile(pf_dev, car_type, flowid, profile_id, 0);
err2:
	zxdh_plcr_release_profile(pf_dev, car_type, profile_id, 0);
err3:
	zxdh_plcr_release_flow(pf_dev, car_type, flowid);

	return rtn;
}

static int zxdh_plcr_modify_rate_limit(struct zxdh_pf_device *pf_dev,
				       enum E_RATE_LIMIT_PKT_BYTE is_pkt_mode,
				       enum E_PLCR_CAR_TYPE car_type, u32 flowid, u32 max_rate,
				       u32 min_rate)
{
	int rtn = 0;
	u16 profile_id = 0;
	struct dpp_stat_car_profile_cfg_t profile_cfg;
	struct xarray *xarray_flowid = &pf_dev->plcr_table.plcr_flows[car_type];
	struct zxdh_plcr_flow *plcr_flow = xa_load(xarray_flowid, flowid);
	struct zxdh_plcr_profile *profile_old = NULL;

	PLCR_FUNC_DBG_ENTER();

	if ((car_type == E_PLCR_CAR_A) || (car_type == E_PLCR_CAR_C)) {
		if (plcr_flow->max_rate == max_rate) {
			PLCR_LOG_INFO("duplicate max_rate=%d on flowid=%d\n", max_rate, flowid);
			return PLCR_DUPLICATE_RATE;
		}
	} else if (car_type == E_PLCR_CAR_B) {
		if ((plcr_flow->max_rate == max_rate) && (plcr_flow->min_rate == min_rate)) {
			PLCR_LOG_INFO("duplicate max_rate=%d, min_rate=%d on flowid=%d\n", max_rate,
				      min_rate, flowid);
			return PLCR_DUPLICATE_RATE;
		}
	} else {
		return -EINVAL;
	}

	rtn = zxdh_plcr_gen_profile(pf_dev, is_pkt_mode, car_type, max_rate, min_rate,
				    &profile_cfg);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	rtn = zxdh_plcr_get_profile_by_flowid(pf_dev, car_type, flowid, &profile_old);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	rtn = zxdh_plcr_match_profile(pf_dev, car_type, &profile_cfg, &profile_id);
	if (rtn) {
		if (profile_old->ref_cnt == 1) {
			zxdh_plcr_update_profile(&profile_cfg, profile_old->profile_id);

			rtn = zxdh_plcr_cfg_profile(pf_dev, car_type, &profile_cfg);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}

			rtn = zxdh_plcr_store_profile(pf_dev, car_type, max_rate, min_rate,
						      &profile_cfg);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}

			zxdh_plcr_update_flow(plcr_flow, plcr_flow->vport, max_rate, min_rate);

			return rtn;
		}

		rtn = zxdh_plcr_req_profile(pf_dev, car_type, &profile_id);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		zxdh_plcr_update_profile(&profile_cfg, profile_id);

		rtn = zxdh_plcr_cfg_profile(pf_dev, car_type, &profile_cfg);
		if (rtn) {
			PLCR_LOG_ERR("failed to call zxdh_plcr_cfg_profile()\n");
			goto err4;
		}

		rtn = zxdh_plcr_store_profile(pf_dev, car_type, max_rate, min_rate, &profile_cfg);
		if (rtn) {
			PLCR_LOG_ERR("failed to call zxdh_plcr_store_profile()\n");
			goto err4;
		}
	}

	rtn = zxdh_plcr_bind_flow_profile(pf_dev, car_type, flowid, profile_id);
	if (rtn) {
		PLCR_LOG_ERR("failed to call zxdh_plcr_bind_flow_profile()\n");
		goto err4;
	}

	zxdh_plcr_update_flow(plcr_flow, plcr_flow->vport, max_rate, min_rate);

	rtn = zxdh_plcr_count_up_profile(pf_dev, car_type, profile_id);
	if (rtn) {
		PLCR_LOG_ERR("failed to call zxdh_plcr_count_up_profile()\n");
		goto err4;
	}

	rtn = zxdh_plcr_count_down_profile(pf_dev, car_type, profile_old->profile_id);
	if (rtn) {
		PLCR_LOG_ERR("failed to call zxdh_plcr_count_up_profile()\n");
		goto err4;
	}

	zxdh_plcr_release_profile(pf_dev, car_type, profile_old->profile_id, 0);

	return rtn;

err4:
	zxdh_plcr_release_profile(pf_dev, car_type, profile_id, 0);
	return rtn;
}

int zxdh_plcr_remove_rate_limit(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type,
				u32 flowid, u32 flag)
{
	int rtn = 0;
	struct zxdh_plcr_profile *profile_old = NULL;

	PLCR_FUNC_DBG_ENTER();

	PLCR_LOG_INFO("car_type=%d,flowid=%d\n", car_type, flowid);

	rtn = zxdh_plcr_get_profile_by_flowid(pf_dev, car_type, flowid, &profile_old);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	rtn = zxdh_plcr_unbind_flow_profile(pf_dev, car_type, flowid, profile_old->profile_id,
					    flag);

	rtn = zxdh_plcr_count_down_profile(pf_dev, car_type, profile_old->profile_id);

	rtn = zxdh_plcr_release_profile(pf_dev, car_type, profile_old->profile_id, flag);

	rtn = zxdh_plcr_release_flow(pf_dev, car_type, flowid);

	return rtn;
}

void zxdh_plcr_count_profiles(struct zxdh_pf_device *pf_dev)
{
	struct zxdh_plcr_profile *profile;
	unsigned long index;
	u32 count = 0;
	enum E_PLCR_CAR_TYPE car_type;

	PLCR_FUNC_DBG_ENTER();

	for (car_type = E_PLCR_CAR_A; car_type < E_PLCR_CAR_NUM; car_type++) {
		count = 0;
		xa_for_each_range(&pf_dev->plcr_table.plcr_profiles[car_type], index, profile, 0,
				  gaudplcrcarxprofilenum[car_type]) {
			count++;
		}
		PLCR_LOG_INFO("car_type = %d, profiles_num = %d\n", car_type, count);
	}
}

int zxdh_plcr_set_rate_limit(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_PKT_BYTE is_pkt_mode,
			     enum E_PLCR_CAR_TYPE car_type, u16 vport, u32 flowid, u32 max_rate,
			     u32 min_rate)
{
	int rtn = 0;
	struct xarray *xarray_flow = &pf_dev->plcr_table.plcr_flows[car_type];
	struct zxdh_plcr_flow *flow = NULL;

	PLCR_FUNC_DBG_ENTER();

	flow = xa_load(xarray_flow, flowid);
	if (!flow) {
		rtn = zxdh_plcr_create_rate_limit(pf_dev, is_pkt_mode, car_type, vport, flowid,
						  max_rate, min_rate);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else if ((max_rate != 0) || (min_rate != 0)) {
		rtn = zxdh_plcr_modify_rate_limit(pf_dev, is_pkt_mode, car_type, flowid, max_rate,
						  min_rate);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else {
		rtn = zxdh_plcr_remove_rate_limit(pf_dev, car_type, flowid, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		zxdh_plcr_check_release_flow_chain(pf_dev, car_type, vport);

		rtn = PLCR_REMOVE_RATE_LIMIT;
	}

	zxdh_plcr_count_profiles(pf_dev);

	return rtn;
}

int zxdh_pf_plcr_set_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE mode)
{
	int rtn = 0;
	u32 enable = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = vport;
	PLCR_LOG_INFO("slot: %d, vport: 0x%x, mode: 0x%x\n", pf_info.slot, pf_info.vport, mode);

	//Check if the vport attribute table exists.
	rtn = dpp_vport_egress_meter_en_get(&pf_info, &enable);
	if (rtn == ZXIC_PAR_CHK_INVALID_INDEX) {
		PLCR_LOG_INFO("Write vport attribute table which does not exist!\n");
		return 0;
	}
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	if (mode == E_RATE_LIMIT_MODE0) {
		rtn = dpp_vport_egress_meter_en_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_en_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else if (mode == E_RATE_LIMIT_MODE1) {
		rtn = dpp_vport_egress_meter_en_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_en_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = dpp_vport_egress_meter_mode_set(&pf_info, 1);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_mode_set(&pf_info, 1);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = dpp_vport_egress_meter_en_set(&pf_info, 1);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_en_set(&pf_info, 1);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else if (mode == E_RATE_LIMIT_MODE2) {
		rtn = dpp_vport_egress_meter_en_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_en_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = dpp_vport_egress_meter_mode_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_mode_set(&pf_info, 0);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = dpp_vport_egress_meter_en_set(&pf_info, 1);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		rtn = dpp_vport_ingress_meter_en_set(&pf_info, 1);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else {
		return -ERANGE;
	}

	return rtn;
}

int zxdh_pf_plcr_get_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE *p_mode)
{
	int rtn = 0;
	u32 enable = 0;
	u32 mode = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	PLCR_FUNC_DBG_ENTER();

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = vport;
	PLCR_LOG_INFO("pf_info.slot = %d, pf_info.vport = 0x%x\n", pf_info.slot, pf_info.vport);

	rtn = dpp_vport_egress_meter_en_get(&pf_info, &enable);
	if (rtn == ZXIC_PAR_CHK_INVALID_INDEX) {
		PLCR_LOG_INFO("Read vport attribute table which does not exist!\n");
		*p_mode = E_RATE_LIMIT_MODE3;
		return 0;
	}
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	if (enable == 0) {
		*p_mode = E_RATE_LIMIT_MODE0;
	} else {
		rtn = dpp_vport_egress_meter_mode_get(&pf_info, &mode);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		if (mode == 1)
			*p_mode = E_RATE_LIMIT_MODE1;
		else
			*p_mode = E_RATE_LIMIT_MODE2;
	}

	PLCR_LOG_INFO("mode = %d\n", *p_mode);

	return rtn;
}

int zxdh_plcr_set_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE mode)
{
	s32 rtn = 0;
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		rtn = zxdh_pf_plcr_set_mode(pf_dev, vport, mode);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else {
		msg = kzalloc(sizeof(*msg), GFP_KERNEL);
		if (unlikely(!msg)) {
			PLCR_LOG_ERR("failed to kzalloc\n");
			return -ENOMEM;
		}
		msg->payload.hdr.op_code = ZXDH_PLCR_SET_MODE;
		msg->payload.hdr.vport = pf_dev->vport;
		msg->payload.hdr.pcie_id = pf_dev->pcie_id;
		msg->payload.hdr.vf_id = pf_dev->pcie_id & (0xff);

		msg->payload.plcr_work_mode_msg.vport = vport;
		msg->payload.plcr_work_mode_msg.mode = mode;

		rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
		kfree(msg);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	}

	return rtn;
}
EXPORT_SYMBOL(zxdh_plcr_set_mode);

int zxdh_plcr_get_mode(struct zxdh_pf_device *pf_dev, u16 vport, enum E_RATE_LIMIT_MODE *mode)
{
	s32 rtn = 0;
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	union zxdh_msg *msg = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		rtn = zxdh_pf_plcr_get_mode(pf_dev, vport, mode);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	} else {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (unlikely(!msg)) {
			PLCR_LOG_ERR("failed to kzalloc\n");
			return -ENOMEM;
		}
		msg->payload.hdr.op_code = ZXDH_PLCR_GET_MODE;
		msg->payload.hdr.vport = pf_dev->vport;
		msg->payload.hdr.pcie_id = pf_dev->pcie_id;
		msg->payload.hdr.vf_id = pf_dev->pcie_id & (0xff);

		msg->payload.plcr_work_mode_msg.vport = vport;
		PLCR_LOG_INFO("msg->payload.hdr.vf_id %u\n", msg->payload.hdr.vf_id);
		rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			kfree(msg);
			return rtn;
		}

		*mode = msg->reps.plcr_work_mode_rsp.mode;
		kfree(msg);

		PLCR_LOG_INFO("mode = %d\n", *mode);
	}

	return rtn;
}

int zxdh_plcr_show_rate_limit_paras(struct zxdh_plcr_rate_limit_paras *rate_limit_paras)
{
	PLCR_LOG_INFO("rate_limit_paras->req_type   = 0x%x\n", rate_limit_paras->req_type);
	PLCR_LOG_INFO("rate_limit_paras->direction  = 0x%x\n", rate_limit_paras->direction);
	PLCR_LOG_INFO("rate_limit_paras->mode       = 0x%x\n", rate_limit_paras->mode);
	PLCR_LOG_INFO("rate_limit_paras->max_rate   = 0x%x\n", rate_limit_paras->max_rate);
	PLCR_LOG_INFO("rate_limit_paras->min_rate   = 0x%x\n", rate_limit_paras->min_rate);
	PLCR_LOG_INFO("rate_limit_paras->queue_id   = 0x%x\n", rate_limit_paras->queue_id);
	PLCR_LOG_INFO("rate_limit_paras->vf_idx     = 0x%x\n", rate_limit_paras->vf_idx);
	PLCR_LOG_INFO("rate_limit_paras->vfid       = 0x%x\n", rate_limit_paras->vfid);
	PLCR_LOG_INFO("rate_limit_paras->vport      = 0x%x\n", rate_limit_paras->vport);
	PLCR_LOG_INFO("rate_limit_paras->group_id   = 0x%x\n", rate_limit_paras->group_id);

	return 0;
}

int zxdh_plcr_check_req_type(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_MODE mode,
			     struct zxdh_plcr_rate_limit_paras *rate_limit_paras,
			     enum E_RATE_LIMIT_REQ_TYPE *req_type)
{
	PLCR_FUNC_DBG_ENTER();

	if ((rate_limit_paras->req_type == E_RATE_LIMIT_REQ_QUEUE_BYTE) &&
	    (rate_limit_paras->mode == E_RATE_LIMIT_BYTE) &&
	    ((rate_limit_paras->min_rate != PLCR_INVALID_PARAM) ||
	     (rate_limit_paras->max_rate != PLCR_INVALID_PARAM)) &&
	    (rate_limit_paras->direction == E_RATE_LIMIT_TX) &&
	    (rate_limit_paras->vf_idx == PLCR_INVALID_PARAM) &&
	    (rate_limit_paras->group_id == PLCR_INVALID_PARAM) &&
	    (rate_limit_paras->queue_id < PLCR_MAX_QUEUE_PAIRS)) {
		*req_type = E_RATE_LIMIT_REQ_QUEUE_BYTE;

		if (mode == E_RATE_LIMIT_MODE2) {
			PLCR_LOG_ERR(
				"E_RATE_LIMIT_REQ_QUEUE_BYTE is not supported under E_RATE_LIMIT_MODE2\n");
			return -EPERM;
		}

		rate_limit_paras->group_id = 0;

		return 0;
	}

	else if ((rate_limit_paras->req_type == E_RATE_LIMIT_REQ_VF_BYTE) &&
		 (rate_limit_paras->mode == E_RATE_LIMIT_BYTE) &&
		 ((rate_limit_paras->min_rate != PLCR_INVALID_PARAM) ||
		  (rate_limit_paras->max_rate != PLCR_INVALID_PARAM)) &&
		 ((rate_limit_paras->direction == E_RATE_LIMIT_RX) ||
		  (rate_limit_paras->direction == E_RATE_LIMIT_TX)) &&
		 (rate_limit_paras->group_id == PLCR_INVALID_PARAM) &&
		 (rate_limit_paras->vf_idx != PLCR_INVALID_PARAM)) {
		rate_limit_paras->group_id = 0;

		*req_type = E_RATE_LIMIT_REQ_VF_BYTE;
		return 0;
	}

	else if ((rate_limit_paras->req_type == E_RATE_LIMIT_REQ_VF_PKT) &&
		 (rate_limit_paras->mode == E_RATE_LIMIT_PACKET) &&
		 ((rate_limit_paras->min_rate != PLCR_INVALID_PARAM) ||
		  (rate_limit_paras->max_rate != PLCR_INVALID_PARAM)) &&
		 ((rate_limit_paras->direction == E_RATE_LIMIT_RX) ||
		  (rate_limit_paras->direction == E_RATE_LIMIT_TX)) &&
		 (rate_limit_paras->group_id == PLCR_INVALID_PARAM) &&
		 (rate_limit_paras->vf_idx != PLCR_INVALID_PARAM)) {
		*req_type = E_RATE_LIMIT_REQ_VF_PKT;

		if (mode == E_RATE_LIMIT_MODE1) {
			PLCR_LOG_ERR(
				"E_RATE_LIMIT_REQ_VF_PKT is not supported under E_RATE_LIMIT_MODE1\n");
			return -EPERM;
		}

		rate_limit_paras->group_id = 0;

		return 0;
	}

	else if ((rate_limit_paras->req_type == E_RATE_LIMIT_REQ_VF_GROUP_BYTE) &&
		 (rate_limit_paras->mode == E_RATE_LIMIT_BYTE) &&
		 ((rate_limit_paras->min_rate != PLCR_INVALID_PARAM) ||
		  (rate_limit_paras->max_rate != PLCR_INVALID_PARAM)) &&
		 ((rate_limit_paras->direction == E_RATE_LIMIT_RX) ||
		  (rate_limit_paras->direction == E_RATE_LIMIT_TX)) &&
		 (rate_limit_paras->vf_idx == PLCR_INVALID_PARAM) &&
		 (rate_limit_paras->group_id != PLCR_INVALID_PARAM)) {
		*req_type = E_RATE_LIMIT_REQ_VF_GROUP_BYTE;
		return 0;
	}

	else if ((rate_limit_paras->req_type == E_RATE_LIMIT_REQ_MOVE_VF_GROUP) &&
		 (rate_limit_paras->mode == PLCR_INVALID_PARAM) &&
		 ((rate_limit_paras->min_rate == PLCR_INVALID_PARAM) &&
		  (rate_limit_paras->max_rate == PLCR_INVALID_PARAM)) &&
		 ((rate_limit_paras->direction == E_RATE_LIMIT_RX) ||
		  (rate_limit_paras->direction == E_RATE_LIMIT_TX)) &&
		 (rate_limit_paras->vf_idx != PLCR_INVALID_PARAM) &&
		 (rate_limit_paras->group_id != PLCR_INVALID_PARAM)) {
		*req_type = E_RATE_LIMIT_REQ_MOVE_VF_GROUP;
		return 0;
	}
	zxdh_plcr_show_rate_limit_paras(rate_limit_paras);

	return PLCR_GET_REQ_TYPE_INVALID_ERR;
}

s32 zxdh_pf_get_vf_queue_info(struct zxdh_pf_device *pf_dev, s32 vf_idx, s32 *phy_queue_num,
			      s32 *phy_rx_queue, s32 *phy_tx_queue)
{
	s32 rtn = 0;
	s32 i;
	union zxdh_msg *msg = NULL;
	s32 queue_pair_index;
	s32 queue_num;
	s32 queue_pair = 0;
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_en_device *en_dev;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	PLCR_FUNC_DBG_ENTER();

	en_dev = pf_dev_get_edev(pf_dev);
	if (IS_ERR(en_dev))
		return PTR_ERR(en_dev);

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		PLCR_LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}
	msg->payload.hdr_vf.op_code = ZXDH_PF_GET_VF_QUEUE_INFO;
	msg->payload.hdr_vf.dst_pcie_id = FIND_VF_PCIE_ID(pf_dev->pcie_id, vf_idx);

	for (queue_pair_index = 0; queue_pair_index < PLCR_MAX_QUEUE_PAIRS;) {
		msg->payload.plcr_pf_get_vf_queue_info_msg.vir_queue_start = queue_pair_index;
		msg->payload.plcr_pf_get_vf_queue_info_msg.vir_queue_num = 16;

		//get rx&tx phy queue
		PLCR_LOG_INFO("vir_queue_start = 0x%x\n",
			      msg->payload.plcr_pf_get_vf_queue_info_msg.vir_queue_start);
		PLCR_LOG_INFO("vir_queue_num   = 0x%x\n",
			      msg->payload.plcr_pf_get_vf_queue_info_msg.vir_queue_num);
		rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_PF_BAR_MSG_TO_VF, msg, msg, &para);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			goto free_msg;
		}

		queue_num = msg->reps.plcr_pf_get_vf_queue_info_rsp.phy_queue_num;
		for (i = 0; i < queue_num; i++) {
			phy_rx_queue[queue_pair_index * 16 + i] =
				msg->reps.plcr_pf_get_vf_queue_info_rsp.phy_rxq[i];
			phy_tx_queue[queue_pair_index * 16 + i] =
				msg->reps.plcr_pf_get_vf_queue_info_rsp.phy_txq[i];

			PLCR_LOG_INFO("rxq: 0x%x  -  0x%x\n", queue_pair_index * 16 + i,
				      phy_rx_queue[queue_pair_index * 16 + i]);
			PLCR_LOG_INFO("txq: 0x%x  -  0x%x\n", queue_pair_index * 16 + i,
				      phy_tx_queue[queue_pair_index * 16 + i]);
		}

		queue_pair += queue_num;

		if (queue_num < 16) {
			*phy_queue_num = queue_pair;
			PLCR_LOG_INFO("phy_queue_num = 0x%x\n", *phy_queue_num);
			goto free_msg;
		} else {
			queue_pair_index += 16;
		}
	}

free_msg:
	kfree(msg);
	return rtn;
}

int zxdh_plcr_map_flowid(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid,
			 u32 map_flowid)
{
	int rtn = 0;
	u32 map_sp = 0; //priority
	union zxdh_msg *msg = NULL;
	struct dpp_pf_info_t pf_info = { 0 };
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	PLCR_FUNC_DBG_ENTER();
	PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n", car_type, flowid,
		      map_flowid);

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		PLCR_LOG_INFO("flowid=0x%x, map_flowid=0x%x\n", flowid, map_flowid);
		pf_info.slot = pf_dev->slot_id;
		pf_info.vport = pf_dev->vport;
		PLCR_LOG_INFO(
			"dpp_car_queue_map_set: pf_info.vport = 0x%x, car_type = %d, flowid = %d, map_flowid = %d\n",
			pf_info.vport, car_type, flowid, map_flowid);
		rtn = dpp_car_queue_map_set(&pf_info, car_type, flowid, map_flowid, map_sp);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = zxdh_plcr_stroe_map(pf_dev, car_type, flowid, map_flowid);
	} else {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (unlikely(!msg)) {
			PLCR_LOG_ERR("failed to kzalloc\n");
			return -ENOMEM;
		}
		msg->payload.hdr.op_code = ZXDH_MAP_PLCR_FLOWID;
		msg->payload.hdr.vport = pf_dev->vport;
		msg->payload.hdr.pcie_id = pf_dev->pcie_id;
		msg->payload.hdr.vf_id = pf_dev->pcie_id & (0xff);

		msg->payload.plcr_flowid_map_msg.car_type = car_type;
		msg->payload.plcr_flowid_map_msg.flowid = flowid;
		msg->payload.plcr_flowid_map_msg.map_flowid = map_flowid;
		msg->payload.plcr_flowid_map_msg.sp = map_sp;
		PLCR_LOG_INFO("flowid=0x%x, map_flowid=0x%x\n", flowid, map_flowid);

		rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
		kfree(msg);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	}

	return rtn;
}

int zxdh_plcr_mode_init(struct zxdh_pf_device *pf_dev)
{
	s32 rtn = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	rtn = zxdh_plcr_set_mode(pf_dev, pf_dev->vport, E_RATE_LIMIT_MODE0);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	return rtn;
}

s32 zxdh_plcr_recover_cfg(struct zxdh_vf_item *vf_item, struct zxdh_pf_device *pf_dev, s32 vf_idx)
{
	s32 rtn = 0;
	struct zxdh_plcr_rate_limit_paras rate_limit_paras;

	PLCR_LOG_INFO("%s  zxdh_vf_item %p\n", __func__, vf_item);
	if (!vf_item) {
		PLCR_LOG_INFO("plcr init  vfid %u   vfitem null\n", vf_idx);
		return 0;
	}
	PLCR_LOG_INFO("%s  vfid %u   maxrate %u\n", __func__, vf_idx, vf_item->max_tx_rate);
	if (vf_item->max_tx_rate != 0 || vf_item->min_tx_rate != 0) {
		rate_limit_paras.req_type = E_RATE_LIMIT_REQ_VF_BYTE;
		rate_limit_paras.direction = E_RATE_LIMIT_TX;
		rate_limit_paras.mode = E_RATE_LIMIT_BYTE;
		rate_limit_paras.max_rate = vf_item->max_tx_rate;
		rate_limit_paras.min_rate = vf_item->min_tx_rate;
		rate_limit_paras.queue_id = PLCR_INVALID_PARAM;
		rate_limit_paras.vf_idx = vf_idx;
		rate_limit_paras.vfid = PLCR_INVALID_PARAM;
		rate_limit_paras.group_id = PLCR_INVALID_PARAM;

		rtn = zxdh_plcr_unified_set_rate_limit(pf_dev, &rate_limit_paras);
	}

	return rtn;
}

s32 zxdh_plcr_init(struct zxdh_en_priv *en_priv)
{
	s32 rtn = 0;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		xa_init(&pf_dev->plcr_table.plcr_profiles[E_PLCR_CAR_A]);
		xa_init(&pf_dev->plcr_table.plcr_flows[E_PLCR_CAR_A]);
		xa_init(&pf_dev->plcr_table.plcr_maps[E_PLCR_CAR_A]);

		xa_init(&pf_dev->plcr_table.plcr_profiles[E_PLCR_CAR_B]);
		xa_init(&pf_dev->plcr_table.plcr_flows[E_PLCR_CAR_B]);
		xa_init(&pf_dev->plcr_table.plcr_maps[E_PLCR_CAR_B]);

		xa_init(&pf_dev->plcr_table.plcr_profiles[E_PLCR_CAR_C]);
		xa_init(&pf_dev->plcr_table.plcr_flows[E_PLCR_CAR_C]);

		pf_dev->plcr_table.burst_size = 0;
	}

	if (dh_dev->coredev_type != DH_COREDEV_VF) {
		rtn = zxdh_plcr_mode_init(pf_dev);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	}
	pf_dev->plcr_table.is_init = true;

	return rtn;
}
EXPORT_SYMBOL(zxdh_plcr_init);

s32 zxdh_plcr_uninit(struct zxdh_en_priv *en_priv)
{
	int rtn = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_en_device *en_dev = &en_priv->edev;
	struct dh_core_dev *dh_dev = en_dev->parent->parent;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	unsigned long flow_id;
	enum E_PLCR_CAR_TYPE car_index;
	struct xarray *xarray_flow;
	struct xarray *xarray_profile;
	struct zxdh_plcr_flow *flow = NULL;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	PLCR_FUNC_DBG_ENTER();

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		for (car_index = E_PLCR_CAR_A; car_index <= E_PLCR_CAR_C; car_index++) {
			xarray_flow = &pf_dev->plcr_table.plcr_flows[car_index];
			xarray_profile = &pf_dev->plcr_table.plcr_profiles[car_index];
			xa_for_each_range(xarray_flow, flow_id, flow, 0,
					  gaudplcrcarxflowidnum[car_index]) {
				zxdh_plcr_remove_rate_limit(pf_dev, car_index, flow_id,
							    en_dev->quick_remove);

				//clear all vport mappings between car B and car C.
				if (car_index == E_PLCR_CAR_B)
					zxdh_plcr_clear_map(pf_dev, car_index, flow_id);
			}
			xa_destroy(xarray_flow);
			xa_destroy(xarray_profile);
		}

		pf_dev->plcr_table.is_init = false;
	} else if (dh_dev->coredev_type == DH_COREDEV_VF) {
		if (!en_dev->quick_remove) {
			msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
			if (unlikely(!msg)) {
				PLCR_LOG_ERR("failed to kzalloc\n");
				return -ENOMEM;
			}
			msg->payload.hdr.op_code = ZXDH_PLCR_UNINIT;
			msg->payload.hdr.vport = pf_dev->vport;
			msg->payload.hdr.pcie_id = pf_dev->pcie_id;
			msg->payload.hdr.vf_id = pf_dev->pcie_id & (0xff);

			rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg,
						   &para);
			kfree(msg);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
		}
	}
	return rtn;
}
EXPORT_SYMBOL(zxdh_plcr_uninit);

int zxdh_plcr_get_car_a_flowid(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_MODE mode,
			       struct zxdh_plcr_rate_limit_paras *rate_limit_paras,
			       struct zxdh_plcr_flowids *flowids)
{
	int rtn = 0;
	u32 queue_pair_index;
	struct zxdh_en_device *en_dev;

	PLCR_FUNC_DBG_ENTER();

	PLCR_LOG_INFO("mode = %d, rate_limit_paras->req_type = %d\n", mode,
		      rate_limit_paras->req_type);

	en_dev = pf_dev_get_edev(pf_dev);
	if (IS_ERR(en_dev))
		return PTR_ERR(en_dev);

	if (en_dev->curr_queue_pairs > PLCR_MAX_QUEUE_PAIRS)
		return -PLCR_DEV_ALL_QID_2_FLOWID_QUEUE_PAIRS_OVERFLOW;

	PLCR_LOG_INFO("rate_limit_paras->req_type = 0x%x\n", rate_limit_paras->req_type);

	if (rate_limit_paras->req_type == E_RATE_LIMIT_REQ_VF_GROUP_BYTE) {
		PLCR_LOG_INFO("E_RATE_LIMIT_REQ_VF_GROUP_BYTE does not need car A flowid!\n");
		return 0;
	} else if ((mode == E_RATE_LIMIT_MODE0 || mode == E_RATE_LIMIT_MODE1) &&
		   rate_limit_paras->req_type == E_RATE_LIMIT_REQ_QUEUE_BYTE) {
		for (queue_pair_index = 0; queue_pair_index < en_dev->curr_queue_pairs;
		     queue_pair_index++) {
			flowids->flowids_A[0][queue_pair_index] =
				en_dev->rq[queue_pair_index].vq->phy_index;

			flowids->flowids_A[1][queue_pair_index] =
				en_dev->sq[queue_pair_index].vq->phy_index;

			PLCR_LOG_INFO("flowids->flowids_A[0][%d] = 0x%x\n", queue_pair_index,
				      flowids->flowids_A[0][queue_pair_index]);
			PLCR_LOG_INFO("flowids->flowids_A[1][%d] = 0x%x\n", queue_pair_index,
				      flowids->flowids_A[1][queue_pair_index]);
		}
		flowids->queue_pairs = en_dev->curr_queue_pairs;

		PLCR_LOG_INFO("flowids->queue_pairs = 0x%x\n", flowids->queue_pairs);
	} else if ((mode == E_RATE_LIMIT_MODE0 &&
		    rate_limit_paras->req_type != E_RATE_LIMIT_REQ_QUEUE_BYTE) ||
		   (mode == E_RATE_LIMIT_MODE2 &&
		    rate_limit_paras->req_type == E_RATE_LIMIT_REQ_VF_PKT)) {
		flowids->flowid_A[0] = rate_limit_paras->vfid * 2 + PLCR_CAR_A_DPDK_FLOWID_OFFSET;
		flowids->flowid_A[1] =
			rate_limit_paras->vfid * 2 + 1 + PLCR_CAR_A_DPDK_FLOWID_OFFSET;
		PLCR_LOG_INFO("flowids->flowid_A[0] = 0x%x\n", flowids->flowid_A[0]);
		PLCR_LOG_INFO("flowids->flowid_A[1] = 0x%x\n", flowids->flowid_A[1]);
	} else {
		PLCR_LOG_INFO("Car A's flowid is not needed!\n");
		return 0;
	}

	return rtn;
}

int zxdh_plcr_get_car_b_flowid(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_MODE mode,
			       struct zxdh_plcr_rate_limit_paras *rate_limit_paras,
			       struct zxdh_plcr_flowids *flowids)
{
	int rtn = 0;

	PLCR_FUNC_DBG_ENTER();

	flowids->flowid_B[0] = rate_limit_paras->vfid * 2;
	flowids->flowid_B[1] = rate_limit_paras->vfid * 2 + 1;

	PLCR_LOG_INFO("flowids->flowid_B[0] = 0x%x\n", flowids->flowid_B[0]);
	PLCR_LOG_INFO("flowids->flowid_B[1] = 0x%x\n", flowids->flowid_B[1]);

	return rtn;
}

int zxdh_plcr_get_car_c_flowid(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_MODE mode,
			       struct zxdh_plcr_rate_limit_paras *rate_limit_paras,
			       struct zxdh_plcr_flowids *flowids)
{
	u16 vport = 0;
	u32 epid = 0;
	u32 pf_num = 0;

	PLCR_FUNC_DBG_ENTER();

	vport = pf_dev->vport;
	PLCR_LOG_INFO("pf's info : vport = 0x%x\n0", vport);

	if (rate_limit_paras->group_id >= 16) {
		PLCR_LOG_ERR("group_id must be less than 16!\n");
		return -ERANGE;
	}

	epid = EPID(vport);
	pf_num = FUNC_NUM(vport);
	PLCR_LOG_INFO("pf's info : epid = 0x%x, pf_num = 0x%x\n", epid, pf_num);

	epid = epid == 4 ? 0 : epid;

	flowids->flowid_C[0] = epid * PLCR_CAR_C_FLOWIDS_PER_EP +
			       pf_num * PLCR_CAR_C_FLOWIDS_PER_PF + rate_limit_paras->group_id * 2;
	flowids->flowid_C[1] = epid * PLCR_CAR_C_FLOWIDS_PER_EP +
			       pf_num * PLCR_CAR_C_FLOWIDS_PER_PF + rate_limit_paras->group_id * 2 +
			       1;

	PLCR_LOG_INFO("flowids->flowid_C[0] = 0x%x\n", flowids->flowid_C[0]);
	PLCR_LOG_INFO("flowids->flowid_C[1] = 0x%x\n", flowids->flowid_C[1]);

	return 0;
}

int zxdh_plcr_get_vport_vfid(struct zxdh_pf_device *pf_dev, u32 vf_idx, u32 *vport, u32 *vfid)
{
	s32 rtn = 0;
	struct zxdh_vf_item *vf_item;
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);

	PLCR_FUNC_DBG_ENTER();

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		PLCR_LOG_INFO("pf: pf_dev->vport = 0x%x, pf_dev->pcie_id = 0x%x\n", pf_dev->vport,
			      pf_dev->pcie_id);

		if (vf_idx == PLCR_INVALID_PARAM) {
			*vport = pf_dev->vport;
			*vfid = VQM_VFID(pf_dev->vport);

			PLCR_LOG_INFO("vf_idx is not specified! vport = %x, vfid = %x\n",
				      pf_dev->vport, *vfid);
			return rtn;
		}
		vf_item = &pf_dev->vf_item[vf_idx];
		if (ERR_PTR(-EINVAL) == vf_item)
			return -EINVAL;

		*vport = vf_item->vport;
		*vfid = VQM_VFID(vf_item->vport);

		PLCR_LOG_INFO("vf_idx = 0x%x, vf_item->vport = 0x%x, vfid = 0x%x\n", vf_idx,
			      vf_item->vport, *vfid);
		PLCR_LOG_INFO("mac address = %x %x %x %x %x %x\n", vf_item->mac[0], vf_item->mac[1],
			      vf_item->mac[2], vf_item->mac[3], vf_item->mac[4], vf_item->mac[5]);

	} else {
		PLCR_LOG_INFO("vf: pf_dev->vport = 0x%x, pf_dev->pcie_id = 0x%x\n", pf_dev->vport,
			      pf_dev->pcie_id);

		*vport = pf_dev->vport;
		*vfid = VQM_VFID(pf_dev->vport);

		PLCR_LOG_INFO("vf_idx = 0x%x, pf_dev->vport = 0x%x, vfid = 0x%x\n", vf_idx,
			      pf_dev->vport, *vfid);
	}

	return rtn;
}

int zxdh_plcr_get_cars_flowid(struct zxdh_pf_device *pf_dev, enum E_RATE_LIMIT_MODE mode,
			      struct zxdh_plcr_rate_limit_paras *rate_limit_paras,
			      struct zxdh_plcr_flowids *flowids)
{
	int rtn = 0;

	PLCR_FUNC_DBG_ENTER();

	//init the pointer flowids with invalid value
	memset(flowids, 0xff, sizeof(struct zxdh_plcr_flowids));

	//get car A flowid
	rtn = zxdh_plcr_get_car_a_flowid(pf_dev, mode, rate_limit_paras, flowids);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	//get car B flowid
	rtn = zxdh_plcr_get_car_b_flowid(pf_dev, mode, rate_limit_paras, flowids);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	//get car C flowid
	rtn = zxdh_plcr_get_car_c_flowid(pf_dev, mode, rate_limit_paras, flowids);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	return rtn;
}

int zxdh_plcr_get_next_mode(struct zxdh_pf_device *pf_dev,
			    struct zxdh_plcr_rate_limit_paras *rate_limit_paras, u32 *next_mode)
{
	int rtn = 0;
	enum E_RATE_LIMIT_MODE cur_mode;

	//get vport current mode
	rtn = zxdh_plcr_get_mode(pf_dev, rate_limit_paras->vport, &cur_mode);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	if (cur_mode == E_RATE_LIMIT_MODE0) {
		if (rate_limit_paras->req_type == E_RATE_LIMIT_REQ_QUEUE_BYTE)
			*next_mode = E_RATE_LIMIT_MODE1;
		else
			*next_mode = E_RATE_LIMIT_MODE2;

		return 0;
	}

	return -EINVAL;
}

int zxdh_plcr_init_flow(struct zxdh_pf_device *pf_dev, enum E_PLCR_CAR_TYPE car_type, u32 flowid)
{
	int rtn = 0;
	u32 vf_idx;
	u32 vport;
	u32 flowid_offset;
	u32 vfid;
	u32 map_flowid;
	union zxdh_msg *msg = NULL;
	struct dpp_pf_info_t pf_info = { 0 };
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	PLCR_FUNC_DBG_ENTER();

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		vport = pf_dev->vport;
		flowid_offset = EPID(vport) * PLCR_CAR_C_FLOWIDS_PER_EP +
				FUNC_NUM(vport) * PLCR_CAR_C_FLOWIDS_PER_PF;

		if ((car_type == E_PLCR_CAR_C) && (flowid - flowid_offset > 1)) {
			for (vf_idx = 0; vf_idx < pf_dev->num_vfs; vf_idx++) {
				map_flowid = 0xffff;
				rtn = zxdh_plcr_get_vport_vfid(pf_dev, vf_idx, &vport, &vfid);
				if (rtn) {
					PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
					return rtn;
				}

				if ((flowid % 2) == 0) {
					rtn = zxdh_plcr_get_next_map(pf_dev, E_PLCR_CAR_B, vfid * 2,
								     &map_flowid);
				} else {
					rtn = zxdh_plcr_get_next_map(pf_dev, E_PLCR_CAR_B,
								     vfid * 2 + 1, &map_flowid);
				}
				if ((!rtn) && (flowid == map_flowid)) {
					PLCR_LOG_INFO(
						"Group is currently being used by at least one VF\n");
					return 0;
				}
			}
		}
		pf_info.slot = pf_dev->slot_id;
		pf_info.vport = pf_dev->vport;
		PLCR_LOG_INFO(
			"dpp_car_queue_cfg_set: vport = 0x%x, car_type = %d, flowid = %d, plcr_en = 0\n",
			pf_dev->vport, car_type, flowid);
		rtn = dpp_car_queue_cfg_set(&pf_info, (u32)car_type, flowid, DROP_DISABLE,
					    PLCR_DISABLE, 0);
		if (rtn)
			PLCR_LOG_ERR("failed to call dpp_car_queue_cfg_set()\n");
	} else {
		msg = kzalloc(sizeof(*msg), GFP_KERNEL);
		if (unlikely(!msg)) {
			PLCR_LOG_ERR("failed to kzalloc\n");
			return -ENOMEM;
		}
		msg->payload.hdr.op_code = ZXDH_PLCR_FLOW_INIT;
		msg->payload.hdr.vport = pf_dev->vport;
		msg->payload.hdr.pcie_id = pf_dev->pcie_id;
		msg->payload.hdr.vf_id = pf_dev->pcie_id & (0xff);

		msg->payload.plcr_flow_init_msg.car_type = car_type;
		msg->payload.plcr_flow_init_msg.flowid = flowid;

		rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
		kfree(msg);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
	}

	return rtn;
}

int zxdh_plcr_set_cars_map(struct zxdh_pf_device *pf_dev,
			   struct zxdh_plcr_rate_limit_paras *rate_limit_paras,
			   struct zxdh_plcr_flowids *flowids)
{
	int rtn = 0;
	u32 flowid;
	u32 map_flowid;
	enum E_RATE_LIMIT_MODE mode;
	enum E_RATE_LIMIT_REQ_TYPE req_type;
	int queue_pair_index;

	PLCR_FUNC_DBG_ENTER();

	//get vport and vfid
	rtn = zxdh_plcr_get_vport_vfid(pf_dev, rate_limit_paras->vf_idx, &rate_limit_paras->vport,
				       &rate_limit_paras->vfid);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	//get vport current mode
	rtn = zxdh_plcr_get_mode(pf_dev, rate_limit_paras->vport, &mode);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	//get rate limit type
	rtn = zxdh_plcr_check_req_type(pf_dev, mode, rate_limit_paras, &req_type);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	rtn = zxdh_plcr_get_cars_flowid(pf_dev, mode, rate_limit_paras, flowids);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	if (mode == E_RATE_LIMIT_MODE0 && req_type != E_RATE_LIMIT_REQ_VF_GROUP_BYTE) {
		if (req_type == E_RATE_LIMIT_REQ_QUEUE_BYTE) {
			for (queue_pair_index = 0; queue_pair_index < flowids->queue_pairs;
			     queue_pair_index++) {
				flowid = flowids->flowids_A[0][queue_pair_index];
				map_flowid = flowids->flowid_B[0];
				PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n",
					      E_PLCR_CAR_A, flowid, map_flowid);

				rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_A, flowid);
				if (rtn) {
					PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
					return rtn;
				}
				rtn = zxdh_plcr_map_flowid(pf_dev, E_PLCR_CAR_A, flowid,
							   map_flowid);
				if (rtn) {
					PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
					return rtn;
				}

				flowid = flowids->flowids_A[1][queue_pair_index];
				map_flowid = flowids->flowid_B[1];
				PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n",
					      E_PLCR_CAR_A, flowid, map_flowid);

				rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_A, flowid);
				if (rtn) {
					PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
					return rtn;
				}
				rtn = zxdh_plcr_map_flowid(pf_dev, E_PLCR_CAR_A, flowid,
							   map_flowid);
				if (rtn) {
					PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
					return rtn;
				}
			}
		} else if (req_type == E_RATE_LIMIT_REQ_VF_PKT ||
			   req_type == E_RATE_LIMIT_REQ_VF_BYTE ||
			   req_type == E_RATE_LIMIT_REQ_MOVE_VF_GROUP) {
			flowid = flowids->flowid_A[0];
			map_flowid = flowids->flowid_B[0];
			PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n",
				      E_PLCR_CAR_A, flowid, map_flowid);

			rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_A, flowid);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
			rtn = zxdh_plcr_map_flowid(pf_dev, E_PLCR_CAR_A, flowid, map_flowid);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}

			flowid = flowids->flowid_A[1];
			map_flowid = flowids->flowid_B[1];
			PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n",
				      E_PLCR_CAR_A, flowid, map_flowid);

			rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_A, flowid);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
			rtn = zxdh_plcr_map_flowid(pf_dev, E_PLCR_CAR_A, flowid, map_flowid);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
		}
	}

	if ((mode == E_RATE_LIMIT_MODE0 && req_type != E_RATE_LIMIT_REQ_VF_GROUP_BYTE) ||
	    (req_type == E_RATE_LIMIT_REQ_MOVE_VF_GROUP)) {
		//car B rx flowid is mapped to car C rx flowid
		flowid = flowids->flowid_B[0];
		map_flowid = flowids->flowid_C[0];
		PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n", E_PLCR_CAR_B,
			      flowid, map_flowid);

		if (mode == E_RATE_LIMIT_MODE0) {
			rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_B, flowid);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
		}
		rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_C, map_flowid);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = zxdh_plcr_map_flowid(pf_dev, E_PLCR_CAR_B, flowid, map_flowid);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		//car B tx flowid is mapped to car C tx flowid
		flowid = flowids->flowid_B[1];
		map_flowid = flowids->flowid_C[1];
		PLCR_LOG_INFO("car_type = 0x%x, flowid = 0x%x, map_flowid = 0x%x\n", E_PLCR_CAR_B,
			      flowid, map_flowid);

		if (mode == E_RATE_LIMIT_MODE0) {
			rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_B, flowid);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
		}
		rtn = zxdh_plcr_init_flow(pf_dev, E_PLCR_CAR_C, map_flowid);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}

		rtn = zxdh_plcr_map_flowid(pf_dev, E_PLCR_CAR_B, flowid, map_flowid);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			return rtn;
		}
		PLCR_LOG_INFO("Successful to map!\n");
	}

	return rtn;
}

int zxdh_plcr_unified_set_rate_limit(struct zxdh_pf_device *pf_dev,
				     struct zxdh_plcr_rate_limit_paras *rate_limit_paras)
{
	int rtn = 0;
	union zxdh_msg *msg = NULL;
	struct zxdh_plcr_flowids flowids;
	u32 next_mode;
	enum E_RATE_LIMIT_MODE cur_mode;
	enum E_RATE_LIMIT_REQ_TYPE req_type;
	//u32 vport     = 0;
	u32 flowid = 0;
	u32 car_type = 0;
	u32 is_packet = 0;
	u32 max_rate = 0;
	u32 min_rate = 0;
	struct dh_core_dev *dh_dev = container_of((void *)pf_dev, struct dh_core_dev, priv);
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	PLCR_FUNC_DBG_ENTER();

	rtn = zxdh_plcr_set_cars_map(pf_dev, rate_limit_paras, &flowids);
	if (rtn) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return rtn;
	}

	req_type = rate_limit_paras->req_type;

	if (req_type == E_RATE_LIMIT_REQ_MOVE_VF_GROUP) {
		rtn = zxdh_plcr_get_mode(pf_dev, rate_limit_paras->vport, &cur_mode);

		if (cur_mode == E_RATE_LIMIT_MODE0 && rate_limit_paras->group_id) {
			rtn = zxdh_plcr_set_mode(pf_dev, rate_limit_paras->vport,
						 E_RATE_LIMIT_MODE2);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
		}

		else if (cur_mode != E_RATE_LIMIT_MODE0 && rate_limit_paras->group_id == 0) {
			zxdh_plcr_check_release_flow_chain(pf_dev, E_PLCR_CAR_B,
							   rate_limit_paras->vport);
			;
		}

		return rtn;
	} else if (req_type == E_RATE_LIMIT_REQ_QUEUE_BYTE) {
		if (rate_limit_paras->direction == E_RATE_LIMIT_RX)
			flowid = flowids.flowids_A[0][rate_limit_paras->queue_id];
		else
			flowid = flowids.flowids_A[1][rate_limit_paras->queue_id];

		max_rate = rate_limit_paras->max_rate;
		min_rate = 0;
		car_type = E_PLCR_CAR_A;
		is_packet = E_RATE_LIMIT_BYTE;
	} else if (req_type == E_RATE_LIMIT_REQ_VF_BYTE) {
		if (rate_limit_paras->direction == E_RATE_LIMIT_RX)
			flowid = flowids.flowid_B[0];
		else
			flowid = flowids.flowid_B[1];

		max_rate = rate_limit_paras->max_rate;
		min_rate = rate_limit_paras->min_rate;
		car_type = E_PLCR_CAR_B;
		is_packet = E_RATE_LIMIT_BYTE;
	} else if (req_type == E_RATE_LIMIT_REQ_VF_PKT) {
		if (rate_limit_paras->direction == E_RATE_LIMIT_RX)
			flowid = flowids.flowid_A[0];
		else
			flowid = flowids.flowid_A[1];

		max_rate = rate_limit_paras->max_rate;
		min_rate = rate_limit_paras->min_rate;
		car_type = E_PLCR_CAR_A;
		is_packet = E_RATE_LIMIT_PACKET;
	} else if (req_type == E_RATE_LIMIT_REQ_VF_GROUP_BYTE) {
		if (rate_limit_paras->direction == E_RATE_LIMIT_RX)
			flowid = flowids.flowid_C[0];
		else
			flowid = flowids.flowid_C[1];

		max_rate = rate_limit_paras->max_rate;
		min_rate = 0;
		car_type = E_PLCR_CAR_C;
		is_packet = E_RATE_LIMIT_BYTE;
	} else {
		return -EINVAL;
	}

	PLCR_LOG_INFO("rate_limit_paras vport    = 0x%x\n", rate_limit_paras->vport);
	PLCR_LOG_INFO("rate_limit_paras vfid    = 0x%x\n", rate_limit_paras->vfid);
	PLCR_LOG_INFO("flowid    = 0x%x\n", flowid);
	PLCR_LOG_INFO("car_type  = 0x%x\n", car_type);
	PLCR_LOG_INFO("is_packet = 0x%x\n", is_packet);
	PLCR_LOG_INFO("max_rate  = 0x%x\n", max_rate);
	PLCR_LOG_INFO("min_rate  = 0x%x\n", min_rate);

	//set rate limit
	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		rtn = zxdh_plcr_set_rate_limit(pf_dev, is_packet, car_type, rate_limit_paras->vport,
					       flowid, max_rate, min_rate);
	} else if (dh_dev->coredev_type == DH_COREDEV_VF) {
		msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
		if (unlikely(!msg)) {
			PLCR_LOG_ERR("failed to kzalloc\n");
			return -ENOMEM;
		}
		msg->payload.hdr.op_code = ZXDH_VF_RATE_LIMIT_SET;
		msg->payload.hdr.vport = pf_dev->vport;
		msg->payload.hdr.pcie_id = pf_dev->pcie_id;
		msg->payload.hdr.vf_id = pf_dev->pcie_id & (0xff);

		msg->payload.rate_limit_set_msg.flowid = flowid;
		msg->payload.rate_limit_set_msg.car_type = car_type;
		msg->payload.rate_limit_set_msg.is_packet = is_packet;
		msg->payload.rate_limit_set_msg.max_rate = max_rate;
		msg->payload.rate_limit_set_msg.min_rate = min_rate;

		PLCR_LOG_INFO("rate_limit_set_msg.flowid    = 0x%x\n",
			      msg->payload.rate_limit_set_msg.flowid);
		PLCR_LOG_INFO("rate_limit_set_msg.car_type  = 0x%x\n",
			      msg->payload.rate_limit_set_msg.car_type);
		PLCR_LOG_INFO("rate_limit_set_msg.is_packet = 0x%x\n",
			      msg->payload.rate_limit_set_msg.is_packet);
		PLCR_LOG_INFO("rate_limit_set_msg.max_rate  = 0x%x\n",
			      msg->payload.rate_limit_set_msg.max_rate);
		PLCR_LOG_INFO("rate_limit_set_msg.min_rate  = 0x%x\n",
			      msg->payload.rate_limit_set_msg.min_rate);

		rtn = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
		if (rtn) {
			PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
			kfree(msg);
			return rtn;
		}

		rtn = msg->reps.rate_limit_set_rsp.err_code;
		kfree(msg);
	}

	if (rtn && rtn != PLCR_REMOVE_RATE_LIMIT) {
		PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
		return (rtn == PLCR_DUPLICATE_RATE) ? 0 : -EPERM;
	}

	if (!rtn && req_type != E_RATE_LIMIT_REQ_VF_GROUP_BYTE) {
		rtn = zxdh_plcr_get_next_mode(pf_dev, rate_limit_paras, &next_mode);
		if (!rtn) {
			rtn = zxdh_plcr_set_mode(pf_dev, rate_limit_paras->vport, next_mode);
			if (rtn) {
				PLCR_LOG_ERR("failed and rtn=%d\n", rtn);
				return rtn;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(zxdh_plcr_unified_set_rate_limit);

static int zxdh_vqm_send_rate_msg(struct zxdh_pf_device *pf_dev, u16 vqm_vfid, void *in_payload,
				  u16 in_len, struct bar_recv_msg *out)
{
	int rtn = 0;
	u16 pcie_id = 0;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };

	pcie_id = FIND_VF_PCIE_ID(pf_dev->pcie_id, vqm_vfid);

	in.virt_addr = (u64)ZXDH_BAR_MSG_BASE(pf_dev->pci_ioremap_addr[0]);
	in.payload_addr = in_payload;
	in.payload_len = in_len;
	in.emec = 0;
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = VQM_BAR_MSG;
	in.src_pcieid = pcie_id;
	in.dst_pcieid = 0,

	result.recv_buffer = (void *)out;
	result.buffer_len = sizeof(struct bar_recv_msg);
	rtn = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (rtn != BAR_MSG_OK)
		PLCR_LOG_ERR("%s failed\n", __func__);
	return BAR_MSG_OK;
}

int zxdh_vqm_vf_set_rate_limit(struct zxdh_pf_device *pf_dev, u16 vqm_vfid, u32 vf_rate)
{
	int rtn = 0;
	u32 index = 0;
	struct zxdh_vqm_param param = { 0 };
	struct bar_recv_msg *recv_msg = NULL;

	if (!pf_dev) {
		PLCR_LOG_ERR("pf_dev NULL ptr\n");
		return -1;
	}

	index = VQM_VFID(vqm_vfid);

	param.vqm_vfid = index, param.opcode = OPCODE_SET, param.cmd = CMD_VF_QOS,
	param.vqm_rate.pack_rate = 0,
	param.vqm_rate.rate = (u32)(((u64)1000 * vf_rate * 106) / 100);

	recv_msg = kzalloc(sizeof(struct bar_recv_msg), GFP_KERNEL);
	if (!recv_msg) {
		PLCR_LOG_ERR("recv_msg NULL ptr\n");
		return -1;
	}

	rtn = zxdh_vqm_send_rate_msg(pf_dev, vqm_vfid, &param, (u16)sizeof(param), recv_msg);
	if (rtn)
		PLCR_LOG_ERR("zxdh_vqm_send_rate_msg failed\n");

	PLCR_LOG_INFO(
		"The Rate of VF vqm_vfid:0x%x index: %d has been set to: Max Tx Rate: %dMbit/s\n",
		vqm_vfid, index, vf_rate);

	return 0;
}
EXPORT_SYMBOL(zxdh_vqm_vf_set_rate_limit);
