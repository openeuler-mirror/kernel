// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include "nse.h"
#include "nse_acl.h"
#include "nse_repr_meter.h"

/**
 * nse_acl_destrory_hw_repr_meter -
 *				destroy hw repr meter in ACL module.
 *
 * @vsi: pointer to vsi structure
 * @meter: pointer to repr meter structure
 *
 */
void
nse_acl_destrory_hw_repr_meter(struct nse_vsi *vsi,
			struct nse_rep_meter *meter)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_acl_fltr_info *fltr_info = NULL;

	if (!meter || !meter->fltr_info)
		return;

	fltr_info = meter->fltr_info;
	nse_acl_remove_fltr(hw, fltr_info);
	devm_kfree(nse_hw_to_dev(hw), fltr_info);
	meter->fltr_info = NULL;
}

/**
 * nse_acl_create_hw_repr_meter -
 *				create hw repr meter in ACL module.
 *
 * @vsi: pointer to vsi structure
 * @meter: pointer to software meter object.
 * @in_port: lan id for uplink repr, src vsi id for vf repr
 * @dst_hw_vsi: uplink vsi id for uplink repr, control vsi id for vf repr
 * @rate: meter rate value of current xps
 * @burst: meter burst value of current xps
 */
static int
nse_acl_create_hw_repr_meter(struct nse_vsi *vsi,
				struct nse_rep_meter *meter,
			    u16 in_port, u16 dst_hw_vsi, u64 rate, u64 burst)
{
	struct nse_acl_fltr_info *fltr_info = NULL;
	struct nse_hw *hw = &vsi->back->hw;
	int err = 0;

	fltr_info = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*fltr_info),
				 GFP_KERNEL);
	if (!fltr_info)
		return -ENOMEM;

	fltr_info->lkup_type = NSE_ACL_LKUP_OVS_MISS;
	fltr_info->src_hw_vsi = in_port;
	fltr_info->dst_hw_vsi = dst_hw_vsi;
	fltr_info->meter_param.mode = NSE_RATE_LIMIT_PPS;

	fltr_info->sw_id = vsi->port_info->sw_id;
	fltr_info->meter_param.rate = rate;
	fltr_info->meter_param.burst = burst;
	fltr_info->fltr_act = NSE_ACL_METER;

	err = nse_acl_add_fltr(hw, fltr_info);
	if (err) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to add fltr in acl\n",
			__func__, __LINE__);
		goto err;
	}

	meter->fltr_info = fltr_info;

	return 0;

err:
	devm_kfree(nse_hw_to_dev(hw), fltr_info);
	return err;
}

/**
 * nse_repr_meter_get_stats -
 *				get repr meter statistic from hw.
 *
 * @vsi: pointer to vsi structure
 * @meter: pointer to software meter object.
 * @in_port: lan id for uplink repr, src vsi id for vf repr
 * @dst_hw_vsi: uplink vsi id for uplink repr, control vsi id for vf repr
 * @rate: meter rate value of current xps
 * @burst: meter burst value of current xps
 */
static int
nse_repr_meter_get_stats(struct nse_vsi *vsi,
				struct nse_rep_meter *meter)
{
	struct nse_hw *hw = &vsi->back->hw;
	int err = 0;

	if (!meter || !meter->fltr_info)
		return 0;

	err = nse_acl_get_meter_stats(hw, meter->fltr_info);
	if (err) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to get acl meter stats, meter id = %d\n",
			__func__, __LINE__, meter->fltr_info->meter_id);
		meter->packets_dropped = 0;
		meter->bytes_dropped = 0;
		return err;
	}

	meter->packets_dropped = meter->fltr_info->packets_dropped;
	meter->bytes_dropped = meter->fltr_info->bytes_dropped;
	return 0;
}

/**
 * nse_rep_set_miss_meter -
 *				set hw repr ovs miss meter
 *
 * @pf: pointer to pf structure
 * @is_uplink: uplink repr or vf repr.
 * @repr: vf repr struct when is_uplink == false.
 * @rate: meter rate value of current xps
 * @burst: meter burst value of current xps
 */
int nse_rep_set_miss_meter(struct nse_pf *pf, bool  is_uplink,
			struct nse_repr *repr, u64 rate, u64 burst)
{
	struct nse_rep_meter *meter = NULL;
	struct nse_vsi *vsi = NULL;
	struct nse_hw *hw = NULL;
	u16 in_port, dst_hw_vsi;
	int err = 0;

	if (!pf)
		return -EINVAL;

	hw = &pf->hw;

	if (is_uplink) {
		meter = &pf->switchdev.uplink_meter;
		vsi = pf->switchdev.uplink_vsi;
		if (!vsi) {
			dev_err(nse_pf_to_dev(pf),
				"[%s, %d] uplink vsi is NULL when cfg uplink miss rate limit\n",
				__func__, __LINE__);
			err = -EINVAL;
			goto err;
		}
		in_port = hw->lan_id;
		in_port |= (NSE_IN_PORT_TYPE_LAN <<
				NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;
		dst_hw_vsi = vsi->vsi_abs_num;
	} else {
		if (!repr) {
			dev_err(nse_pf_to_dev(pf),
				"[%s, %d] repr is NULL when cfg repr miss rate limit\n",
				__func__, __LINE__);
			err = -EINVAL;
			goto err;
		}
		meter = &repr->rep_meter;
		vsi = repr->src_vsi;
		in_port = vsi->vsi_abs_num;
		in_port |= (NSE_IN_PORT_TYPE_HOST <<
				NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;
		dst_hw_vsi = pf->switchdev.control_vsi->vsi_abs_num;
	}

	if (rate == meter->rate && burst == meter->burst)
		return 0;

	if (rate == 0 || burst == 0) {
		nse_acl_destrory_hw_repr_meter(vsi, meter);
		goto update;
	}

	if (meter->fltr_info) {
		dev_warn(nse_pf_to_dev(pf),
			"Please delete existed repr meter first\n");
		goto err;
	} else {
		err = nse_acl_create_hw_repr_meter(vsi, meter,
						in_port, dst_hw_vsi, rate, burst);
		if (err) {
			dev_err(nse_pf_to_dev(pf),
				"Failed to create hw repr meter\n");
			goto err;
		}
	}

update:
	meter->rate = rate;
	meter->burst = burst;

	return 0;

err:
	return err;
}

/**
 * nse_rep_get_miss_meter_data -
 *				get hw repr ovs miss meter parameter or statistic
 *
 * @pf: pointer to pf structure
 * @is_uplink: uplink repr or vf repr.
 * @repr: vf repr struct when is_uplink == false.
 * @data_type:
 * @data:
 */
int nse_rep_get_miss_meter_data(struct nse_pf *pf, bool  is_uplink,
			struct nse_repr *repr, int data_type, u64 *data)
{
	struct nse_rep_meter *meter = NULL;
	struct nse_vsi *vsi = NULL;
	struct nse_hw *hw = NULL;
	int err = 0;

	if (!pf)
		return -EINVAL;

	hw = &pf->hw;

	if (is_uplink) {
		vsi = pf->switchdev.uplink_vsi;
		if (!vsi) {
			dev_err(nse_pf_to_dev(pf),
				"[%s, %d] uplink vsi is NULL when get uplink miss meter data\n",
				__func__, __LINE__);
			err = -EINVAL;
			goto err;
		}

		meter = &pf->switchdev.uplink_meter;
	} else {
		if (!repr) {
			dev_err(nse_pf_to_dev(pf),
				"[%s, %d] repr is NULL when get vf repr meter data\n",
				__func__, __LINE__);
			err = -EINVAL;
			goto err;
		}
		vsi = repr->src_vsi;
		meter = &repr->rep_meter;
	}

	switch (data_type) {
	case NSE_RATE_LIMIT_DATA_RATE:
		*data = meter->rate;
		break;
	case NSE_RATE_LIMIT_DATA_BURST:
		*data = meter->burst;
		break;
	case NSE_RATE_LIMIT_DATA_PACKETS_DROPPED:
		err = nse_repr_meter_get_stats(vsi, meter);
		if (err) {
			meter->packets_dropped = 0;
			dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to get repr meter statistic, vsi id = %d\n",
			__func__, __LINE__, vsi->vsi_abs_num);
		}
		*data = meter->packets_dropped;
		break;
	case NSE_RATE_LIMIT_DATA_BYTES_DROPPED:
		err = nse_repr_meter_get_stats(vsi, meter);
		if (err) {
			meter->bytes_dropped = 0;
			dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to get repr meter statistic, vsi id = %d\n",
			__func__, __LINE__, vsi->vsi_abs_num);
		}
		*data = meter->bytes_dropped;
		break;
	default:
		err = -EINVAL;
		break;
	}

err:
	return err;
}

