// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>

#include "sphw_crm.h"
#include "spnic_lld.h"
#include "spnic_nic_cfg.h"
#include "spnic_nic_dev.h"
#include "spnic_dcb.h"

#define DCB_CFG_CHG_ETS		BIT(0)
#define DCB_CFG_CHG_PFC		BIT(1)
#define DCB_CFG_CHG_UP_COS	BIT(2)

#define MAX_BW_PERCENT		100

void spnic_set_prio_tc_map(struct spnic_nic_dev *nic_dev)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->hw_dcb_cfg;
	u8 valid_up_bitmap = spnic_get_valid_up_bitmap(dcb_cfg);
	u8 default_tc = dcb_cfg->max_cos - 1;
	u8 i, tc_id;

	/* use 0~max_cos-1 as tc for netdev */
	for (tc_id = 0, i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (dcb_cfg->valid_cos_bitmap & BIT(i)) {
			netdev_set_prio_tc_map(nic_dev->netdev,
					       dcb_cfg->cos_cfg[i].up, tc_id);
			tc_id++;
		}
	}

	/* set invalid up mapping to the default tc */
	for (i = 0; i < SPNIC_DCB_UP_MAX; i++) {
		if (!(valid_up_bitmap & BIT(i)))
			netdev_set_prio_tc_map(nic_dev->netdev, i, default_tc);
	}
}

void spnic_update_tx_db_cos(struct spnic_nic_dev *nic_dev)
{
	u8 i, valid_cos_bitmap, cos;
	u16 num_rss;

	if (!test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		spnic_set_txq_cos(nic_dev, 0, nic_dev->q_params.num_qps,
				  nic_dev->hw_dcb_cfg.default_cos);
		return;
	}

	num_rss = nic_dev->q_params.num_rss;
	valid_cos_bitmap = nic_dev->hw_dcb_cfg.valid_cos_bitmap;
	for (i = 0; i < nic_dev->q_params.num_tc; i++) {
		cos = (u8)(ffs(valid_cos_bitmap) - 1);
		spnic_set_txq_cos(nic_dev, (u16)(i * num_rss), num_rss, cos);
		valid_cos_bitmap &= (~BIT(cos));
	}
}

int spnic_set_tx_cos_state(struct spnic_nic_dev *nic_dev)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->hw_dcb_cfg;
	struct spnic_dcb_state dcb_state = {0};
	u8 default_cos, i;
	int err;

	if (SPNIC_FUNC_IS_VF(nic_dev->hwdev)) {
		err = spnic_get_pf_dcb_state(nic_dev->hwdev, &dcb_state);
		if (err) {
			spnic_err(nic_dev, drv, "Failed to get vf default cos\n");
			return err;
		}
		/* VF does not support DCB, use the default cos */
		dcb_cfg->default_cos = dcb_state.default_cos;

		return 0;
	}

	default_cos = dcb_cfg->default_cos;
	dcb_state.dcb_on = !!test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags);
	dcb_state.default_cos = default_cos;
	memset(dcb_state.up_cos, default_cos, sizeof(dcb_state.up_cos));
	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
			if (dcb_cfg->valid_cos_bitmap & BIT(i))
				dcb_state.up_cos[dcb_cfg->cos_cfg[i].up] = i;
		}
	}

	err = spnic_set_dcb_state(nic_dev->hwdev, &dcb_state);
	if (err)
		spnic_err(nic_dev, drv, "Failed to set dcb state\n");

	return err;
}

static void setup_tc_reopen_handler(struct spnic_nic_dev *nic_dev,
				    const void *priv_data)
{
	u8 tc = *((u8 *)priv_data);

	if (tc) {
		netdev_set_num_tc(nic_dev->netdev, tc);
		spnic_set_prio_tc_map(nic_dev);

		set_bit(SPNIC_DCB_ENABLE, &nic_dev->flags);
	} else {
		netdev_reset_tc(nic_dev->netdev);

		clear_bit(SPNIC_DCB_ENABLE, &nic_dev->flags);
	}

	spnic_set_tx_cos_state(nic_dev);
}

int spnic_setup_tc(struct net_device *netdev, u8 tc)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_dyna_txrxq_params q_params = {0};
	u8 cur_tc;
	int err;

	if (tc && test_bit(SPNIC_SAME_RXTX, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, netdev, "Failed to enable DCB while Symmetric RSS is enabled\n");
		return -EOPNOTSUPP;
	}

	if (tc > nic_dev->hw_dcb_cfg.max_cos) {
		nicif_err(nic_dev, drv, netdev, "Invalid num_tc: %u, max tc: %u\n",
			  tc, nic_dev->hw_dcb_cfg.max_cos);
		return -EINVAL;
	}

	if (tc & (tc - 1)) {
		nicif_err(nic_dev, drv, netdev,
			  "Invalid num_tc: %u, must be power of 2\n", tc);
		return -EINVAL;
	}

	if (netif_running(netdev)) {
		cur_tc = nic_dev->q_params.num_tc;
		q_params = nic_dev->q_params;
		q_params.num_tc = tc;
		q_params.txqs_res = NULL;
		q_params.rxqs_res = NULL;
		q_params.irq_cfg = NULL;

		nicif_info(nic_dev, drv, netdev, "Change num_tc to %u, restarting channel\n",
			   tc);
		err = spnic_change_channel_settings(nic_dev, &q_params, setup_tc_reopen_handler,
						    &tc);
		if (err) {
			if (cur_tc != nic_dev->q_params.num_tc) {
				nicif_err(nic_dev, drv, netdev,
					  "Restore num_tc to %u\n", cur_tc);
				/* In this case, the channel resource is
				 * invalid, so we can safely modify the number
				 * of tc in netdev.
				 */
				nic_dev->q_params.num_tc = cur_tc;
				setup_tc_reopen_handler(nic_dev, &cur_tc);
			}
			nicif_err(nic_dev, drv, netdev, "Failed to change channel settings\n");
			return err;
		}
	} else {
		setup_tc_reopen_handler(nic_dev, &tc);
		spnic_update_num_qps(netdev);
	}

	spnic_configure_dcb(netdev);

	return 0;
}

/* Ucode thread timeout is 210ms, must be lagger then 210ms */
#define SPNIC_WAIT_PORT_IO_STOP		250

static int spnic_stop_port_traffic_flow(struct spnic_nic_dev *nic_dev, bool wait)
{
	int err = 0;

	down(&nic_dev->dcb_sem);

	if (nic_dev->disable_port_cnt++ != 0)
		goto out;

	err = spnic_force_port_disable(nic_dev);
	if (err) {
		spnic_err(nic_dev, drv, "Failed to disable port\n");
		goto set_port_err;
	}

	err = spnic_set_port_funcs_state(nic_dev->hwdev, false);
	if (err) {
		spnic_err(nic_dev, drv, "Failed to disable all functions in port\n");
		goto set_port_funcs_err;
	}

	spnic_info(nic_dev, drv, "Stop port traffic flow\n");

	goto out;

set_port_funcs_err:
	spnic_force_set_port_state(nic_dev, !!netif_running(nic_dev->netdev));

set_port_err:
out:
	if (err)
		nic_dev->disable_port_cnt--;

	up(&nic_dev->dcb_sem);
	if (!err && wait && nic_dev->netdev->reg_state == NETREG_REGISTERED)
		msleep(SPNIC_WAIT_PORT_IO_STOP);

	return err;
}

static int spnic_start_port_traffic_flow(struct spnic_nic_dev *nic_dev)
{
	int err;

	down(&nic_dev->dcb_sem);

	nic_dev->disable_port_cnt--;
	if (nic_dev->disable_port_cnt > 0) {
		up(&nic_dev->dcb_sem);
		return 0;
	}

	nic_dev->disable_port_cnt = 0;
	up(&nic_dev->dcb_sem);

	err = spnic_force_set_port_state(nic_dev, !!netif_running(nic_dev->netdev));
	if (err)
		spnic_err(nic_dev, drv, "Failed to disable port\n");

	err = spnic_set_port_funcs_state(nic_dev->hwdev, true);
	if (err)
		spnic_err(nic_dev, drv, "Failed to disable all functions in port\n");

	spnic_info(nic_dev, drv, "Start port traffic flow\n");

	return err;
}

static u8 get_cos_settings(u8 hw_valid_cos_bitmap, u8 *dst_valid_cos_bitmap)
{
	u8 support_cos = 0;
	u8 num_cos, overflow;
	u8 i;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (hw_valid_cos_bitmap & BIT(i))
			support_cos++;
	}

	num_cos = (u8)(1U << (u8)ilog2(support_cos));
	if (num_cos != support_cos) {
		/* Remove unused cos id */
		overflow = support_cos - num_cos;
		i = SPNIC_DCB_COS_MAX - 1;
		while (overflow) {
			if (hw_valid_cos_bitmap & BIT(i)) {
				hw_valid_cos_bitmap &= (~BIT(i));
				overflow--;
			}

			i--;
		}
	}

	*dst_valid_cos_bitmap = hw_valid_cos_bitmap;

	return num_cos;
}

static int get_dft_valid_up_bitmap(struct spnic_nic_dev *nic_dev, u8 num_pri,
				   u8 *valid_up_bitmap)
{
	bool setted = false;
	u8 up_bitmap = 0;
	u8 up;
	int err;

	err = spnic_get_chip_up_bitmap(nic_dev->pdev, &setted, &up_bitmap);
	if (err) {
		spnic_err(nic_dev, drv, "Get chip cos_up map failed\n");
		return -EFAULT;
	}

	if (!setted) {
		/* Use (num_cos-1)~0 as default user priority */
		for (up = 0; up < num_pri; up++)
			up_bitmap |= (u8)BIT(up);
	}

	err = spnic_set_chip_up_bitmap(nic_dev->pdev, up_bitmap);
	if (err) {
		spnic_err(nic_dev, drv, "Set chip cos_up map failed\n");
		return -EFAULT;
	}

	*valid_up_bitmap = up_bitmap;

	return 0;
}

u8 spnic_get_valid_up_bitmap(struct spnic_dcb_config *dcb_cfg)
{
	u8 valid_up_bitmap = 0;
	u8 i;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (dcb_cfg->valid_cos_bitmap & BIT(i))
			valid_up_bitmap |= (u8)BIT(dcb_cfg->cos_cfg[i].up);
	}

	return valid_up_bitmap;
}

static void update_valid_up_bitmap(struct spnic_dcb_config *dcb_cfg,
				   u8 valid_up_bitmap)
{
	u8 i, up;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (!(dcb_cfg->valid_cos_bitmap & BIT(i))) {
			dcb_cfg->cos_cfg[i].up = 0;
			continue;
		}

		/* get the highest priority */
		up = (u8)fls(valid_up_bitmap) - 1;
		valid_up_bitmap &= (~BIT(up));

		dcb_cfg->cos_cfg[i].up = up;
	}
}

static int init_default_dcb_cfg(struct spnic_nic_dev *nic_dev,
				struct spnic_dcb_config *dcb_cfg)
{
	struct spnic_cos_cfg *cos_cfg = dcb_cfg->cos_cfg;
	struct spnic_tc_cfg *tc_cfg = dcb_cfg->tc_cfg;
	u8 valid_cos_bitmap, i;
	u8 valid_up_bitmap = 0;
	int err;

	valid_cos_bitmap = sphw_cos_valid_bitmap(nic_dev->hwdev);
	if (!valid_cos_bitmap) {
		spnic_err(nic_dev, drv, "None cos supported\n");
		return -EFAULT;
	}

	dcb_cfg->max_cos = get_cos_settings(valid_cos_bitmap,
					    &dcb_cfg->valid_cos_bitmap);
	dcb_cfg->default_cos = (u8)fls(dcb_cfg->valid_cos_bitmap) - 1;

	err = get_dft_valid_up_bitmap(nic_dev, dcb_cfg->max_cos,
				      &valid_up_bitmap);
	if (err)
		return err;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		/* set all cos with 100 percent bw in default */
		cos_cfg[i].bw_pct = MAX_BW_PERCENT;
		cos_cfg[i].prio_sp = 0; /* DWRR */
		cos_cfg[i].tc_id = 0; /* all cos mapping to tc0 */
		cos_cfg[i].up = 0;
	}

	update_valid_up_bitmap(dcb_cfg, valid_up_bitmap);

	for (i = 0; i < SPNIC_DCB_TC_MAX; i++) {
		/* tc0 with 100 percent bw in default */
		tc_cfg[i].bw_pct = (i == 0) ? MAX_BW_PERCENT : 0;
		tc_cfg[i].prio_sp = 0; /* DWRR */
	}

	/* disable pfc */
	dcb_cfg->pfc_state = 0;
	dcb_cfg->pfc_en_bitmap = 0;

	return 0;
}

int spnic_dcb_init(struct spnic_nic_dev *nic_dev)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	int err;

	if (SPNIC_FUNC_IS_VF(nic_dev->hwdev))
		return spnic_set_tx_cos_state(nic_dev);

	err = init_default_dcb_cfg(nic_dev, dcb_cfg);
	if (err) {
		spnic_err(nic_dev, drv, "Initialize dcb configuration failed\n");
		return err;
	}

	spnic_info(nic_dev, drv, "Support num cos %u, default cos %u\n",
		   dcb_cfg->max_cos, dcb_cfg->default_cos);

	nic_dev->dcb_changes = DCB_CFG_CHG_ETS | DCB_CFG_CHG_PFC |
			       DCB_CFG_CHG_UP_COS;

	memcpy(&nic_dev->hw_dcb_cfg, &nic_dev->wanted_dcb_cfg,
	       sizeof(nic_dev->hw_dcb_cfg));

	err = spnic_set_tx_cos_state(nic_dev);
	if (err) {
		spnic_err(nic_dev, drv, "Set tx cos state failed\n");
		return err;
	}

	sema_init(&nic_dev->dcb_sem, 1);

	return 0;
}

u32 spnic_sync_dcb_cfg(struct spnic_nic_dev *nic_dev, struct spnic_dcb_config *src_dcb_cfg)
{
	struct spnic_dcb_config *wanted_cfg = src_dcb_cfg;
	struct spnic_dcb_config *hw_cfg = &nic_dev->hw_dcb_cfg;
	u32 changes = 0;

	if (memcmp(hw_cfg->cos_cfg, wanted_cfg->cos_cfg,
		   sizeof(hw_cfg->cos_cfg))) {
		memcpy(hw_cfg->cos_cfg, wanted_cfg->cos_cfg,
		       sizeof(hw_cfg->cos_cfg));
		changes |= DCB_CFG_CHG_ETS;
	}

	if (memcmp(hw_cfg->tc_cfg, wanted_cfg->tc_cfg,
		   sizeof(hw_cfg->tc_cfg))) {
		memcpy(hw_cfg->tc_cfg, wanted_cfg->tc_cfg,
		       sizeof(hw_cfg->tc_cfg));
		changes |= DCB_CFG_CHG_ETS;
	}

	if (hw_cfg->pfc_state != wanted_cfg->pfc_state ||
	    (wanted_cfg->pfc_state &&
	     hw_cfg->pfc_en_bitmap != wanted_cfg->pfc_en_bitmap)) {
		hw_cfg->pfc_state = wanted_cfg->pfc_state;
		hw_cfg->pfc_en_bitmap = wanted_cfg->pfc_en_bitmap;
		changes |= DCB_CFG_CHG_PFC;
	}

	return changes;
}

static int dcbcfg_set_hw_cos_up_map(struct spnic_nic_dev *nic_dev,
				    struct spnic_dcb_config *dcb_cfg)
{
	u8 cos_up_map[SPNIC_DCB_COS_MAX] = {0};
	int err;
	u8 i;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (!(dcb_cfg->valid_cos_bitmap & BIT(i)))
			continue;

		cos_up_map[i] = dcb_cfg->cos_cfg[i].up;
	}

	err = spnic_dcb_set_cos_up_map(nic_dev->hwdev, dcb_cfg->valid_cos_bitmap,
				       cos_up_map, SPNIC_DCB_COS_MAX);
	if (err)
		spnic_err(nic_dev, drv, "Set cos_up map failed\n");

	return err;
}

/* The sum of the cos bandwidth mapped to the same TC is 100 */
static void adjust_cos_bw(u8 valid_cos_bitmap, u8 *cos_tc, u8 *cos_bw)
{
	u8 tc, cos, cos_num;
	u16 bw_all, bw_remain;

	for (tc = 0; tc < SPNIC_DCB_TC_MAX; tc++) {
		bw_all = 0;
		cos_num = 0;
		for (cos = 0; cos < SPNIC_DCB_COS_MAX; cos++) {
			if (!(valid_cos_bitmap & BIT(cos)) || cos_tc[cos] != tc)
				continue;
			bw_all += cos_bw[cos];
			cos_num++;
		}

		if (!bw_all || !cos_num)
			continue;

		bw_remain = MAX_BW_PERCENT % cos_num;
		for (cos = 0; cos < SPNIC_DCB_COS_MAX; cos++) {
			if (!(valid_cos_bitmap & BIT(cos)) || cos_tc[cos] != tc)
				continue;

			cos_bw[cos] =
				(u8)(MAX_BW_PERCENT * cos_bw[cos] / bw_all);

			if (bw_remain) {
				cos_bw[cos]++;
				bw_remain--;
			}
		}
	}
}

static void dcbcfg_dump_configuration(struct spnic_nic_dev *nic_dev,
				      u8 *cos_tc, u8 *cos_bw, u8 *cos_prio,
				      u8 *tc_bw, u8 *tc_prio)
{
	u8 i;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (!(nic_dev->hw_dcb_cfg.valid_cos_bitmap & BIT(i)))
			continue;

		spnic_info(nic_dev, drv, "cos: %u, up: %u, tc: %u, bw: %u, prio: %u\n",
			   i, nic_dev->hw_dcb_cfg.cos_cfg[i].up, cos_tc[i],
			   cos_bw[i], cos_prio[i]);
	}

	for (i = 0; i < nic_dev->hw_dcb_cfg.max_cos; i++)
		spnic_info(nic_dev, drv, "tc: %u, bw: %u, prio: %u\n",
			   i, tc_bw[i], tc_prio[i]);
}

static int dcbcfg_set_hw_ets(struct spnic_nic_dev *nic_dev,
			     struct spnic_dcb_config *dcb_cfg)
{
	u8 cos_tc[SPNIC_DCB_COS_MAX] = {0};
	u8 cos_bw[SPNIC_DCB_COS_MAX] = {0};
	u8 cos_prio[SPNIC_DCB_COS_MAX] = {0};
	u8 tc_bw[SPNIC_DCB_TC_MAX] = {0};
	u8 tc_prio[SPNIC_DCB_TC_MAX] = {0};
	int err;
	u8 i;

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (!(dcb_cfg->valid_cos_bitmap & BIT(i)))
			continue;

		cos_tc[i] = dcb_cfg->cos_cfg[i].tc_id;
		cos_bw[i] = dcb_cfg->cos_cfg[i].bw_pct;
		cos_prio[i] = dcb_cfg->cos_cfg[i].prio_sp;
	}

	for (i = 0; i < SPNIC_DCB_TC_MAX; i++) {
		tc_bw[i] = dcb_cfg->tc_cfg[i].bw_pct;
		tc_prio[i] = dcb_cfg->tc_cfg[i].prio_sp;
	}

	adjust_cos_bw(dcb_cfg->valid_cos_bitmap, cos_tc, cos_bw);

	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags))
		dcbcfg_dump_configuration(nic_dev, cos_tc, cos_bw, cos_prio, tc_bw, tc_prio);

	err = spnic_dcb_set_ets(nic_dev->hwdev, cos_tc, cos_bw, cos_prio, tc_bw, tc_prio);
	if (err) {
		spnic_err(nic_dev, drv, "Failed to set ets\n");
		return err;
	}

	return 0;
}

static int dcbcfg_set_hw_pfc(struct spnic_nic_dev *nic_dev,
			     struct spnic_dcb_config *dcb_cfg)
{
	u8 valid_up_bitmap = spnic_get_valid_up_bitmap(dcb_cfg);
	u8 outof_range_pfc = (~valid_up_bitmap) & dcb_cfg->pfc_en_bitmap;
	int err;

	if (dcb_cfg->pfc_state && outof_range_pfc)
		spnic_info(nic_dev, drv, "PFC setting out of range, 0x%x will be ignored\n",
			   outof_range_pfc);

	err = spnic_dcb_set_pfc(nic_dev->hwdev, dcb_cfg->pfc_state, dcb_cfg->pfc_en_bitmap);
	if (err) {
		spnic_err(nic_dev, drv, "Failed to %s PFC\n",
			  dcb_cfg->pfc_state ? "enable" : "disable");
		return err;
	}

	if (dcb_cfg->pfc_state)
		spnic_info(nic_dev, drv, "Set PFC: 0x%x to hw done\n",
			   dcb_cfg->pfc_en_bitmap & valid_up_bitmap);
	else
		spnic_info(nic_dev, drv, "Disable PFC, enable tx/rx pause\n");

	return 0;
}

int spnic_dcbcfg_setall_to_hw(struct spnic_nic_dev *nic_dev, struct spnic_dcb_config *src_dcb_cfg)
{
	bool stop_traffic = false;
	int err = 0;

	nic_dev->dcb_changes |= spnic_sync_dcb_cfg(nic_dev, src_dcb_cfg);
	if (!nic_dev->dcb_changes)
		return 0;

	/* hw does not support to change up cos mapping and cos tc mapping with
	 * traffic flow
	 */
	stop_traffic = !!(nic_dev->dcb_changes &
			  (DCB_CFG_CHG_ETS | DCB_CFG_CHG_UP_COS));
	if (stop_traffic) {
		err = spnic_stop_port_traffic_flow(nic_dev, true);
		if (err)
			return err;
	}

	if (nic_dev->dcb_changes & DCB_CFG_CHG_UP_COS) {
		err = dcbcfg_set_hw_cos_up_map(nic_dev, &nic_dev->hw_dcb_cfg);
		if (err)
			goto out;

		nic_dev->dcb_changes &= (~DCB_CFG_CHG_UP_COS);
	}

	if (nic_dev->dcb_changes & DCB_CFG_CHG_ETS) {
		err = dcbcfg_set_hw_ets(nic_dev, &nic_dev->hw_dcb_cfg);
		if (err)
			goto out;

		nic_dev->dcb_changes &= (~DCB_CFG_CHG_ETS);
	}

	if (nic_dev->dcb_changes & DCB_CFG_CHG_PFC) {
		err = dcbcfg_set_hw_pfc(nic_dev, &nic_dev->hw_dcb_cfg);
		if (err)
			goto out;

		nic_dev->dcb_changes &= (~DCB_CFG_CHG_PFC);
	}

out:
	if (stop_traffic)
		spnic_start_port_traffic_flow(nic_dev);

	return err;
}

int spnic_dcb_reset_hw_config(struct spnic_nic_dev *nic_dev)
{
	struct spnic_dcb_config dft_cfg = {0};
	int err;

	init_default_dcb_cfg(nic_dev, &dft_cfg);
	err = spnic_dcbcfg_setall_to_hw(nic_dev, &dft_cfg);
	if (err) {
		spnic_err(nic_dev, drv, "Failed to reset hw dcb configuration\n");
		return err;
	}

	spnic_info(nic_dev, drv, "Reset hardware DCB configuration done\n");

	return 0;
}

int spnic_configure_dcb(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags))
		return spnic_dcbcfg_setall_to_hw(nic_dev, &nic_dev->wanted_dcb_cfg);
	else
		return spnic_dcb_reset_hw_config(nic_dev);
}

void spnic_dcbcfg_set_pfc_state(struct spnic_nic_dev *nic_dev, u8 pfc_state)
{
	nic_dev->wanted_dcb_cfg.pfc_state = pfc_state;
}

u8 spnic_dcbcfg_get_pfc_state(struct spnic_nic_dev *nic_dev)
{
	return nic_dev->wanted_dcb_cfg.pfc_state;
}

void spnic_dcbcfg_set_pfc_pri_en(struct spnic_nic_dev *nic_dev, u8 pfc_en_bitmap)
{
	nic_dev->wanted_dcb_cfg.pfc_en_bitmap = pfc_en_bitmap;
}

u8 spnic_dcbcfg_get_pfc_pri_en(struct spnic_nic_dev *nic_dev)
{
	return nic_dev->wanted_dcb_cfg.pfc_en_bitmap;
}

int spnic_dcbcfg_set_ets_up_tc_map(struct spnic_nic_dev *nic_dev, const u8 *up_tc_map)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	u8 i;

	for (i = 0; i < SPNIC_DCB_UP_MAX; i++) {
		if (!(dcb_cfg->valid_cos_bitmap & BIT(i)))
			continue;

		/* TC id can't exceed max cos */
		if (up_tc_map[dcb_cfg->cos_cfg[i].up] >= dcb_cfg->max_cos)
			return -EINVAL;
	}

	for (i = 0; i < SPNIC_DCB_UP_MAX; i++) {
		if (!(dcb_cfg->valid_cos_bitmap & BIT(i)))
			continue;

		dcb_cfg->cos_cfg[i].tc_id = up_tc_map[dcb_cfg->cos_cfg[i].up];
	}

	return 0;
}

void spnic_dcbcfg_get_ets_up_tc_map(struct spnic_nic_dev *nic_dev, u8 *up_tc_map)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	struct spnic_cos_cfg *cos_cfg = dcb_cfg->cos_cfg;
	u8 i;

	/* set unused up mapping to default tc */
	memset(up_tc_map, cos_cfg[dcb_cfg->default_cos].tc_id,
	       SPNIC_DCB_UP_MAX);

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		if (!(dcb_cfg->valid_cos_bitmap & BIT(i)))
			continue;

		up_tc_map[cos_cfg[i].up] = cos_cfg[i].tc_id;
	}
}

int spnic_dcbcfg_set_ets_tc_bw(struct spnic_nic_dev *nic_dev, const u8 *tc_bw)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	u8 bw_sum = 0;
	u8 i;

	for (i = 0; i < SPNIC_DCB_TC_MAX; i++) {
		/* cannot set bandwidth for unused tc */
		if (i >= dcb_cfg->max_cos && tc_bw[i] > 0)
			return -EINVAL;

		bw_sum += tc_bw[i];
	}

	if (bw_sum != MAX_BW_PERCENT && bw_sum != 0) {
		spnic_err(nic_dev, drv, "Invalid total bw %u\n", bw_sum);
		return -EINVAL;
	}

	for (i = 0; i < dcb_cfg->max_cos; i++)
		dcb_cfg->tc_cfg[i].bw_pct = tc_bw[i];

	return 0;
}

void spnic_dcbcfg_get_ets_tc_bw(struct spnic_nic_dev *nic_dev, u8 *tc_bw)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	u8 i;

	for (i = 0; i < dcb_cfg->max_cos; i++)
		tc_bw[i] = dcb_cfg->tc_cfg[i].bw_pct;
}

void spnic_dcbcfg_set_ets_tc_prio_type(struct spnic_nic_dev *nic_dev, u8 tc_prio_bitmap)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	u8 i;

	for (i = 0; i < dcb_cfg->max_cos; i++)
		dcb_cfg->tc_cfg[i].prio_sp = !!(tc_prio_bitmap & BIT(i));
}

void spnic_dcbcfg_get_ets_tc_prio_type(struct spnic_nic_dev *nic_dev, u8 *tc_prio_bitmap)
{
	struct spnic_dcb_config *dcb_cfg = &nic_dev->wanted_dcb_cfg;
	u8 i;

	*tc_prio_bitmap = 0;
	for (i = 0; i < dcb_cfg->max_cos; i++) {
		if (dcb_cfg->tc_cfg[i].prio_sp)
			*tc_prio_bitmap |= (u8)BIT(i);
	}
}

/* TODO: send a command to MPU, and MPU close all port traffic */
static int stop_all_ports_flow(void *uld_array[], u32 num_dev)
{
	struct spnic_nic_dev *tmp_dev = NULL;
	u32 i, idx;
	int err;

	for (idx = 0; idx < num_dev; idx++) {
		tmp_dev = (struct spnic_nic_dev *)uld_array[idx];
		err = spnic_stop_port_traffic_flow(tmp_dev, false);
		if (err) {
			nicif_err(tmp_dev, drv, tmp_dev->netdev, "Stop port traffic flow failed\n");
			goto stop_port_err;
		}
	}

	/* wait all traffic flow stopped */
	msleep(SPNIC_WAIT_PORT_IO_STOP);

	return 0;

stop_port_err:
	for (i = 0; i < idx; i++) {
		tmp_dev = (struct spnic_nic_dev *)uld_array[i];
		spnic_start_port_traffic_flow(tmp_dev);
	}

	return err;
}

static void start_all_ports_flow(void *uld_array[], u32 num_dev)
{
	struct spnic_nic_dev *tmp_dev = NULL;
	u32 idx;

	for (idx = 0; idx < num_dev; idx++) {
		tmp_dev = (struct spnic_nic_dev *)uld_array[idx];
		spnic_start_port_traffic_flow(tmp_dev);
	}
}

int change_dev_cos_up_map(struct spnic_nic_dev *nic_dev, u8 valid_up_bitmap)
{
	struct net_device *netdev = nic_dev->netdev;
	int err = 0;

	if (test_and_set_bit(SPNIC_DCB_UP_COS_SETTING, &nic_dev->dcb_flags)) {
		nicif_warn(nic_dev, drv, netdev,
			   "Cos_up map setting in inprocess, please try again later\n");
		return -EFAULT;
	}

	if (spnic_get_valid_up_bitmap(&nic_dev->wanted_dcb_cfg) ==
	    valid_up_bitmap) {
		nicif_err(nic_dev, drv, netdev, "Same up bitmap, don't need to change anything\n");
		err = 0;
		goto out;
	}

	nicif_info(nic_dev, drv, netdev, "Set valid_up_bitmap: 0x%x\n",
		   valid_up_bitmap);

	update_valid_up_bitmap(&nic_dev->wanted_dcb_cfg, valid_up_bitmap);

	nic_dev->dcb_changes = DCB_CFG_CHG_ETS | DCB_CFG_CHG_PFC | DCB_CFG_CHG_UP_COS;

	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		err = spnic_dcbcfg_setall_to_hw(nic_dev, &nic_dev->wanted_dcb_cfg);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Reconfig dcb to hw failed\n");
			goto out;
		}

		/* Change up/tc map for netdev */
		spnic_set_prio_tc_map(nic_dev);
		spnic_update_tx_db_cos(nic_dev);
	}

	err = spnic_set_tx_cos_state(nic_dev);

out:
	clear_bit(SPNIC_DCB_UP_COS_SETTING, &nic_dev->dcb_flags);

	return err;
}

int spnic_dcbcfg_set_up_bitmap(struct spnic_nic_dev *nic_dev, u8 valid_up_bitmap)
{
	struct spnic_nic_dev *tmp_dev = NULL;
	void **uld_array = NULL;
	u32 i, idx, num_dev = 0;
	int err, rollback_err;
	bool up_setted = false;
	u8 old_valid_up_bitmap = 0;
	u8 max_pf;

	/* Save old valid up bitmap, in case of set failed */
	err = spnic_get_chip_up_bitmap(nic_dev->pdev, &up_setted, &old_valid_up_bitmap);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Get old chip valid up bitmap failed\n");
		return -EFAULT;
	}

	if (valid_up_bitmap == old_valid_up_bitmap) {
		nicif_info(nic_dev, drv, nic_dev->netdev, "Same valid up bitmap, don't need to change anything\n");
		return 0;
	}

	max_pf = sphw_max_pf_num(nic_dev->hwdev);
	if (!max_pf) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Invalid max pf number\n");
		return -EFAULT;
	}

	uld_array = kcalloc(max_pf, sizeof(void *), GFP_KERNEL);
	if (!uld_array) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc uld_array\n");
		return -ENOMEM;
	}

	/* Get all pf of this chip */
	err = spnic_get_pf_nic_uld_array(nic_dev->pdev, &num_dev, uld_array);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Get all pf private handle failed\n");
		err = -EFAULT;
		goto out;
	}

	err = stop_all_ports_flow(uld_array, num_dev);
	if (err)
		goto out;

	for (idx = 0; idx < num_dev; idx++) {
		tmp_dev = (struct spnic_nic_dev *)uld_array[idx];
		err = change_dev_cos_up_map(tmp_dev, valid_up_bitmap);
		if (err) {
			nicif_err(tmp_dev, drv, tmp_dev->netdev, "Set cos_up map to hw failed\n");
			goto set_err;
		}
	}

	start_all_ports_flow(uld_array, num_dev);

	spnic_set_chip_up_bitmap(nic_dev->pdev, valid_up_bitmap);
	kfree(uld_array);

	return 0;

set_err:
	/* undo all settings */
	for (i = 0; i <= idx; i++) {
		tmp_dev = (struct spnic_nic_dev *)uld_array[i];
		rollback_err = change_dev_cos_up_map(tmp_dev, old_valid_up_bitmap);
		if (rollback_err)
			nicif_err(tmp_dev, drv, tmp_dev->netdev, "Failed to rollback cos_up map to hw\n");
	}

	start_all_ports_flow(uld_array, num_dev);

out:
	kfree(uld_array);

	return err;
}
