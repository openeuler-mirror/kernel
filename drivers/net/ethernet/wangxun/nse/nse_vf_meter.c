// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include "nse.h"
#include "nse_vf_meter.h"
#include "nse_vf_lib.h"
#include "nse_acl.h"

/**
 * nse_acl_get_meter -
 *				get vf meter software object.
 *
 * @vf: pointer to VF structure
 * @rx_tx: receive direction or transmit direction, 0 is rx, 1 is tx.
 *			NSE_VF_RATE_LIMIT_RX / NSE_VF_RATE_LIMIT_TX
 * @xps: pps or bbs, enum nse_vf_meter_mode
 *
 */
static struct nse_vf_meter_xps *
nse_acl_get_vf_meter(struct nse_vf *vf, int rx_tx, int xps)
{
	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		return vf->tx_vf_meter.meter_xps[xps];
	else
		return vf->rx_vf_meter.meter_xps[xps];
}

/**
 * nse_acl_destrory_hw_vf_meter -
 *				destroy hw vf meter in ACL module.
 *
 * @vsi: pointer to vsi structure
 * @fltr_info: pointer to acl filter info
 *
 */
void
nse_acl_destrory_hw_vf_meter(struct nse_vsi *vsi,
			struct nse_acl_fltr_info *fltr_info)
{
	struct nse_hw *hw = &vsi->back->hw;

	nse_acl_remove_fltr(hw, fltr_info);
	devm_kfree(nse_hw_to_dev(hw), fltr_info);
	fltr_info = NULL;
}

/**
 * nse_acl_create_hw_vf_meter -
 *				create hw vf meter in ACL module.
 *
 * @vsi: pointer to vsi structure
 * @meter: pointer to software meter object.
 * @rx_tx: receive direction or transmit direction, 0 is rx, 1 is tx.
 *			NSE_VF_RATE_LIMIT_RX / NSE_VF_RATE_LIMIT_TX
 * @xps: pps or bbs, enum nse_vf_meter_mode
 * @rate: meter rate value of current xps
 * @burst: meter burst value of current xps
 *
 */
int
nse_acl_create_hw_vf_meter(struct nse_vsi *vsi,
				struct nse_vf_meter_xps *meter,
			    int rx_tx, int xps, u64 rate, u64 burst)
{
	struct nse_acl_fltr_info *fltr_info = NULL;
	struct nse_hw *hw = &vsi->back->hw;
	int err = 0;

	fltr_info = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*fltr_info),
				 GFP_KERNEL);
	if (!fltr_info)
		return -ENOMEM;

	if (rx_tx == NSE_VF_RATE_LIMIT_TX) {
		fltr_info->lkup_type = NSE_ACL_LKUP_TX_SRC_VSI;
		fltr_info->src_hw_vsi = vsi->vsi_abs_num;
		fltr_info->src_hw_vsi |= (NSE_IN_PORT_TYPE_HOST <<
				NSE_IN_PORT_TYPE_S) & NSE_IN_PORT_TYPE_M;

	} else {
		fltr_info->lkup_type = NSE_ACL_LKUP_RX_DEST_VSI;
		fltr_info->dst_hw_vsi = vsi->vsi_abs_num;
	}

	if (xps == NSE_VF_RATE_LIMIT_PPS)
		fltr_info->meter_param.mode = NSE_RATE_LIMIT_PPS;
	else
		fltr_info->meter_param.mode = NSE_RATE_LIMIT_BPS;

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
 * nse_vf_meter_set_rate_limit -
 *				set vf meter parameter to hw.
 *
 * @vf: pointer to VF structure
 * @meter: pointer to software meter object.
 * @rx_tx: receive direction or transmit direction, 0 is rx, 1 is tx.
 *			NSE_VF_RATE_LIMIT_RX / NSE_VF_RATE_LIMIT_TX
 * @xps: pps or bbs, enum nse_vf_meter_mode
 * @rate: meter rate value of current xps
 * @burst: meter burst value of current xps
 *
 */
int
nse_vf_meter_set_rate_limit(struct nse_vf *vf, struct nse_vf_meter_xps *meter,
			    int rx_tx, int xps, u64 rate, u64 burst)
{
	struct nse_pf *pf;
	struct nse_vsi *vsi;
	struct nse_vf_meter *vf_meter = NULL;
	int err = 0;

	if (rate == meter->rate && burst == meter->burst)
		return 0;

	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		vf_meter = &vf->tx_vf_meter;
	else
		vf_meter = &vf->rx_vf_meter;

	pf = vf->pf;
	vsi = nse_find_vsi_by_abs_id(pf, vf->vf_vsi_abs_id);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf),
			"Failed to get vf vsi by abs id(%d)\n",
			vf->vf_vsi_abs_id);
		return -EINVAL;
	}

	if (rate == 0 || burst == 0) {
		if (meter->fltr_info) {
			nse_acl_destrory_hw_vf_meter(vsi, meter->fltr_info);
			meter->fltr_info = NULL;
			vf_meter->is_meter_en = false;
		}

		goto update;
	}

	if (vf_meter->is_meter_en || meter->fltr_info) {
		dev_warn(nse_pf_to_dev(pf),
			"Please delete existed vf bps/pps meter first\n");
		goto err;
	} else {
		err = nse_acl_create_hw_vf_meter(vsi, meter, rx_tx, xps, rate, burst);
		if (err) {
			dev_err(nse_pf_to_dev(pf),
				"Failed to create hw vf meter\n");
			goto err;
		}

		vf_meter->is_meter_en = true;
	}

update:
	meter->rate = rate;
	meter->burst = burst;

	return 0;

err:
	return err;
}

/**
 * nse_set_vf_meter_data -
 *					configurate vf meter parameter.
 *
 * @pf: pointer to PF structure
 * @vf_id: vf id which is configurate meter.
 * @data_type: enum nse_rate_limit_data_type (rate or burst)
 * @rx_tx: receive direction or transmit direction, 0 is rx, 1 is tx.
 *			NSE_VF_RATE_LIMIT_RX / NSE_VF_RATE_LIMIT_TX
 * @xps: pps or bbs, enum nse_vf_meter_mode
 * @data: meter parameter value of current data_type
 */
int
nse_set_vf_meter_data(struct nse_pf *pf,
		u16 vf_id, int data_type, int rx_tx, int xps, u64 data)
{
	struct nse_vf *vf;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf_meter_xps *meter = NULL;
	int err = 0;

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf) {
		dev_err(dev,
			"[%s, %d] Failed to get vf by id(%d)\n",
			__func__, __LINE__, vf_id);
		return -EINVAL;
	}

	meter = nse_acl_get_vf_meter(vf, rx_tx, xps);
	if (!meter) {
		dev_err(dev,
			"[%s, %d] Failed to get acl vf meter, vf_id = %d\n",
			__func__, __LINE__, vf_id);
		return -EOPNOTSUPP;
	}

	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		mutex_lock(&vf->tx_vf_meter.vf_meter_lock);
	else
		mutex_lock(&vf->rx_vf_meter.vf_meter_lock);

	switch (data_type) {
	case NSE_RATE_LIMIT_DATA_RATE:
		err = nse_vf_meter_set_rate_limit(vf, meter, rx_tx, xps,
						  data, meter->burst);
		break;
	case NSE_RATE_LIMIT_DATA_BURST:
		err = nse_vf_meter_set_rate_limit(vf, meter, rx_tx, xps,
						  meter->rate, data);
		break;
	default:
		err = -EINVAL;
	}

	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		mutex_unlock(&vf->tx_vf_meter.vf_meter_lock);
	else
		mutex_unlock(&vf->rx_vf_meter.vf_meter_lock);

	return err;
}

/**
 * nse_vf_meter_get_stats -
 *				get vf meter statistic from hw.
 *
 * @vf: pointer to VF structure
 * @meter: pointer to software meter object.
 */
int nse_vf_meter_get_stats(struct nse_vf *vf, struct nse_vf_meter_xps *meter)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int err = 0;

	if (!meter || !meter->fltr_info)
		return 0;

	err = nse_acl_get_meter_stats(hw, meter->fltr_info);
	if (err) {
		dev_err(dev,
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
 * nse_get_vf_meter_data -
 *					get vf meter parameter or drop statistic.
 *
 * @pf: pointer to PF structure
 * @vf_id: vf id which is configurate meter.
 * @data_type: enum nse_rate_limit_data_type (rate or burst)
 * @rx_tx: receive direction or transmit direction, 0 is rx, 1 is tx.
 *			NSE_VF_RATE_LIMIT_RX / NSE_VF_RATE_LIMIT_TX
 * @xps: pps or bbs, enum nse_vf_meter_mode
 * @data: meter parameter value of current data_type
 */
int
nse_get_vf_meter_data(struct nse_pf *pf,
		u16 vf_id, int data_type, int rx_tx, int xps, u64 *data)
{
	struct nse_vf *vf;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf_meter_xps *meter = NULL;
	int err = 0;

	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf) {
		dev_err(dev,
			"[%s, %d] Failed to get vf by id(%d)\n",
			__func__, __LINE__, vf_id);
		return -EINVAL;
	}

	meter = nse_acl_get_vf_meter(vf, rx_tx, xps);
	if (!meter) {
		dev_err(dev,
			"[%s, %d] Failed to get vf acl meter, vf_id = %d\n",
			__func__, __LINE__, vf_id);
		return -EOPNOTSUPP;
	}

	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		mutex_lock(&vf->tx_vf_meter.vf_meter_lock);
	else
		mutex_lock(&vf->rx_vf_meter.vf_meter_lock);

	switch (data_type) {
	case NSE_RATE_LIMIT_DATA_RATE:
		*data  = meter->rate;
		break;
	case NSE_RATE_LIMIT_DATA_BURST:
		*data  = meter->burst;
		break;
	case NSE_RATE_LIMIT_DATA_PACKETS_DROPPED:
		err = nse_vf_meter_get_stats(vf, meter);
		if (err) {
			meter->packets_dropped = 0;
			dev_err(dev,
			"[%s, %d] Failed to get vf meter statistic, vf_id = %d\n",
			__func__, __LINE__, vf_id);
		}
		*data = meter->packets_dropped;
		break;
	case NSE_RATE_LIMIT_DATA_BYTES_DROPPED:
		err = nse_vf_meter_get_stats(vf, meter);
		if (err) {
			meter->bytes_dropped = 0;
			dev_err(dev,
			"[%s, %d] Failed to get vf meter statistic, vf_id = %d\n",
			__func__, __LINE__, vf_id);
		}
		*data = meter->bytes_dropped;
		break;
	default:
		err = -EINVAL;
	}

	if (rx_tx == NSE_VF_RATE_LIMIT_TX)
		mutex_unlock(&vf->tx_vf_meter.vf_meter_lock);
	else
		mutex_unlock(&vf->rx_vf_meter.vf_meter_lock);

	return err;
}

/**
 * nse_vf_meter_destroy_meters - destroy vf meter software object only.
 *								including memory and mutex
 * @pf: pointer to PF structure
 */
static void
nse_vf_meter_destroy_meters(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;
	int j;

	nse_for_each_vf(pf, bkt, vf) {
		mutex_destroy(&vf->tx_vf_meter.vf_meter_lock);
		mutex_destroy(&vf->rx_vf_meter.vf_meter_lock);
		for (j = NSE_VF_RATE_LIMIT_BPS; j <= NSE_VF_RATE_LIMIT_PPS; j++) {
			kfree(vf->tx_vf_meter.meter_xps[j]);
			vf->tx_vf_meter.meter_xps[j] = NULL;

			kfree(vf->rx_vf_meter.meter_xps[j]);
			vf->rx_vf_meter.meter_xps[j] = NULL;
		}
	}
}

/**
 * nse_vf_meter_create_meters - create vf meter software object only.
 *								including memory and mutex
 * @pf: pointer to PF structure
 */
int
nse_vf_meter_create_meters(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;
	struct nse_vf_meter_xps *meter;
	int j;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		for (j = NSE_VF_RATE_LIMIT_BPS; j <= NSE_VF_RATE_LIMIT_PPS; j++) {
			meter = kzalloc(sizeof(*meter), GFP_KERNEL);
			if (!meter)
				goto err_out;
			vf->rx_vf_meter.meter_xps[j] = meter;
		}
		mutex_init(&vf->rx_vf_meter.vf_meter_lock);

		for (j = NSE_VF_RATE_LIMIT_BPS; j <= NSE_VF_RATE_LIMIT_PPS; j++) {
			meter = kzalloc(sizeof(*meter), GFP_KERNEL);
			if (!meter)
				goto err_out;
			vf->tx_vf_meter.meter_xps[j] = meter;
		}
		mutex_init(&vf->tx_vf_meter.vf_meter_lock);
	}
	return 0;

err_out:
	nse_vf_meter_destroy_meters(pf);

	return -ENOMEM;
}

/**
 * nse_vf_meter_destroy_all_hw_meters - destroy all hardware vf meters.
 *
 * @pf: pointer to PF structure
 */
void
nse_vf_meter_destroy_all_hw_meters(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;
	struct nse_vsi *vsi;
	struct nse_vf_meter_xps *meter = NULL;
	int j;

	if (!pf)
		return;

	nse_for_each_vf(pf, bkt, vf) {
		vsi = nse_find_vsi_by_abs_id(pf, vf->vf_vsi_abs_id);
		if (!vsi) {
			dev_err(nse_pf_to_dev(pf),
				"Failed to get vf vsi by abs id(%d)\n",
				vf->vf_vsi_abs_id);
			continue;
		}

		for (j = NSE_VF_RATE_LIMIT_BPS; j <= NSE_VF_RATE_LIMIT_PPS; j++) {
			mutex_lock(&vf->tx_vf_meter.vf_meter_lock);
			meter = vf->tx_vf_meter.meter_xps[j];
			if (meter->fltr_info) {
				nse_acl_destrory_hw_vf_meter(vsi, meter->fltr_info);
				meter->fltr_info = NULL;
			}
			vf->tx_vf_meter.is_meter_en = false;
			mutex_unlock(&vf->tx_vf_meter.vf_meter_lock);

			mutex_lock(&vf->rx_vf_meter.vf_meter_lock);
			meter = vf->rx_vf_meter.meter_xps[j];
			if (meter->fltr_info) {
				nse_acl_destrory_hw_vf_meter(vsi, meter->fltr_info);
				meter->fltr_info = NULL;
			}
			vf->rx_vf_meter.is_meter_en = false;
			mutex_unlock(&vf->rx_vf_meter.vf_meter_lock);
		}
	}
}

void
nse_vf_meter_destroy_all(struct nse_pf *pf)
{
	nse_vf_meter_destroy_all_hw_meters(pf);
	nse_vf_meter_destroy_meters(pf);
}

