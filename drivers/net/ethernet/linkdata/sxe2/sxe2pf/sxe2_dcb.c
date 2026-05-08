// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dcb.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_hw.h"
#include "sxe2_vsi.h"
#include "sxe2_log.h"
#include "sxe2_dcb.h"
#include "sxe2_event.h"
#include "sxe2_common.h"
#include "sxe2_dcb_nl.h"
#include "sxe2_lldp_tlv.h"
#include "sxe2_txsched.h"
#include "sxe2_aux_driver.h"
#include "sxe2_switch.h"
#include "sxe2_netdev.h"
#include <net/dcbnl.h>
#include <linux/if_bridge.h>

#define CEE_DCBX_MAX_PGS 8
#define CEE_DCBX_MAX_PRIO 8

#define SXE2_DCBX_WAIT_CNT 10
#define SXE2_DCBX_RESET_WAIT_MS 5

void sxe2_dcb_set_state(struct sxe2_adapter *adapter, enum sxe2_dcb_state state,
			bool need_lock)
{
	if (need_lock) {
		mutex_lock(&adapter->dcb_ctxt.tc_mutex);
		adapter->dcb_ctxt.state = state;
		mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	} else {
		adapter->dcb_ctxt.state = state;
	}
}

STATIC s32 sxe2_dcb_vsis_enable_unlock(struct sxe2_adapter *adapter)
{
	u32 i;
	s32 ret = 0;
	struct sxe2_vsi *vsi;

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;

		switch (vsi->type) {
		case SXE2_VSI_T_PF:
			ret = sxe2_main_vsi_open(vsi);
			break;

		case SXE2_VSI_T_ESW:
			ret = sxe2_vsi_open(vsi);
			break;

		default:
			break;
		}
	}

	return ret;
}

STATIC void sxe2_dcb_vsis_disable_unlock(struct sxe2_adapter *adapter)
{
	u32 i;
	struct sxe2_vsi *vsi;

	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi)
			continue;

		switch (vsi->type) {
		case SXE2_VSI_T_PF:
		case SXE2_VSI_T_ESW:
			(void)sxe2_vsi_close(vsi);
			break;

		default:
			break;
		}
	}
}

static u8 sxe2_dcb_mode_get(struct sxe2_adapter *adapter, bool host)
{
	u8 mode;

	if (host)
		mode = DCB_CAP_DCBX_HOST;
	else
		mode = DCB_CAP_DCBX_LLD_MANAGED;

	if (adapter->dcb_ctxt.local_dcbx_cfg.dcbx_mode & SXE2_DCBX_MODE_CEE)
		mode |= DCB_CAP_DCBX_VER_CEE;
	else
		mode |= DCB_CAP_DCBX_VER_IEEE;

	return mode;
}

s32 sxe2_dcb_lldp_mib_cfg(struct sxe2_adapter *adapter,
			  struct sxe2_fwc_local_mib_set *mib)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_MIB_SET, mib,
				  sizeof(struct sxe2_fwc_local_mib_set) + mib->mib_len, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("dcb mib set failed, ret=%d\n", ret);

	return ret;
}

STATIC s32 sxe2_dcb_cfg_download(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_dcbx_cfg *dcbcfg;
	struct sxe2_fwc_local_mib_set *lldpmib;

	dcbcfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	lldpmib = devm_kzalloc(SXE2_ADAPTER_TO_DEV(adapter),
			       (sizeof(struct sxe2_fwc_local_mib_set) + SXE2_LLDPDU_SIZE),
			       GFP_KERNEL);
	if (!lldpmib)
		return -ENOMEM;

	sxe2_dcb_cfg_to_lldp(lldpmib->mib_buffer, &lldpmib->mib_len, dcbcfg);

	ret = sxe2_dcb_lldp_mib_cfg(adapter, lldpmib);

	devm_kfree(SXE2_ADAPTER_TO_DEV(adapter), lldpmib);

	return ret;
}

u8 sxe2_dcb_tc_cnt_get(struct sxe2_dcbx_cfg *dcbcfg)
{
	u32 i;
	u8 tc_cnt = 0;
	u8 tc_bitmap = 0;

	sxe2_for_each_tc(i) tc_bitmap |= BIT(dcbcfg->ets.prio_tbl[i]);

	sxe2_for_each_tc(i)
	{
		if (tc_bitmap & BIT(i))
			tc_cnt++;
		else
			break;
	}

	if (!tc_cnt)
		tc_cnt = SXE2_DFLT_TC_NUM;

	return tc_cnt;
}

u8 sxe2_dcb_tc_bitmap_get(struct sxe2_dcbx_cfg *dcbcfg)
{
	u8 i, tc_cnt, tc_bitmap = 1;

	tc_cnt = sxe2_dcb_tc_cnt_get(dcbcfg);

	for (i = 0; i < tc_cnt; i++)
		tc_bitmap |= BIT(i);

	return tc_bitmap;
}

s32 sxe2_dcb_bw_chk(struct sxe2_adapter *adapter, struct sxe2_dcbx_cfg *dcbcfg)
{
	s32 i;
	u8 tc_cnt, total_bw = 0;
	u8 ets_tc_cnt = 0;
	struct sxe2_dcb_ets_cfg *etscfg = &dcbcfg->ets;

	tc_cnt = sxe2_dcb_tc_cnt_get(dcbcfg);

	if (tc_cnt == SXE2_DFLT_TC_NUM) {
		etscfg->tcbw_tbl[0] = SXE2_TC_MAX_BW;
		for (i = 1; i < IEEE_8021QAZ_MAX_TCS; i++) {
			if (etscfg->tsa_tbl[i] == IEEE_8021QAZ_TSA_ETS)
				etscfg->tcbw_tbl[i] = 0;
			else
				etscfg->tcbw_tbl[i] = SXE2_TC_MAX_BW;
		}
		LOG_DEV_WARN("One tc enabled, change tc 0 bandwidth to 100.\n");
		return 0;
	}

	for (i = 0; i < tc_cnt; i++) {
		if (etscfg->tsa_tbl[i] == IEEE_8021QAZ_TSA_ETS) {
			if (etscfg->tcbw_tbl[i] == 0) {
				LOG_DEV_ERR("TC %d is used but bw is 0.\n", i);
				return -EINVAL;
			}
			total_bw += etscfg->tcbw_tbl[i];
			ets_tc_cnt++;
		} else {
			etscfg->tcbw_tbl[i] = SXE2_TC_MAX_BW;
		}
	}

	if (total_bw != SXE2_TC_MAX_BW && ets_tc_cnt != 0) {
		LOG_DEV_ERR("invalid config, total bandwidth must equal 100, total_bw %d\n",
			    total_bw);
		return -EINVAL;
	}

	return 0;
}

void sxe2_vsi_netdev_tc_cfg(struct sxe2_vsi *vsi, u8 tc_bitmap)
{
	u8 i;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct net_device *netdev = vsi->netdev;

	if (!netdev)
		return;

	LOG_INFO_BDF("netdev tc cfg, tc_cnt=%d, tc_map=%x\n", vsi->tc.tc_cnt,
		     vsi->tc.tc_map);

	if (netdev_set_num_tc(netdev, vsi->tc.tc_cnt))
		return;

	sxe2_for_each_tc(i)
	{
		if (vsi->tc.tc_map & BIT(i)) {
			(void)netdev_set_tc_queue(netdev, i, vsi->tc.info[i].txq_cnt,
						  vsi->tc.info[i].txq_offset);
			LOG_INFO_BDF("netdev tc[%d] q cfg, txq_cnt=%d, txq_offset=%d\n",
				     i, vsi->tc.info[i].txq_cnt,
				     vsi->tc.info[i].txq_offset);
		}
	}
}

STATIC void sxe2_dcb_vsi_cfg(struct sxe2_vsi *vsi, u8 tc_bitmap)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_dcbx_cfg *dcbcfg;
	struct net_device *netdev = vsi->netdev;
	int i;
	u8 ets_tc;

	sxe2_vsi_tc_cfg(vsi);

	sxe2_vsi_queues_irqs_map(vsi);

	ret = sxe2_vsi_recfg(vsi);

	if (ret) {
		LOG_ERROR_BDF("vsi recfg failed: %d\n", ret);
		goto l_err;
	}

	sxe2_vsi_netdev_tc_cfg(vsi, tc_bitmap);

	dcbcfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		ets_tc = dcbcfg->ets.prio_tbl[i];

		(void)netdev_set_prio_tc_map(netdev, i, ets_tc);

		LOG_INFO_BDF("netdev map prio[%d] to tc[%d]\n", i, ets_tc);
	}
l_err:
	return;
}

static bool sxe2_dcb_tc_contig(u8 *prio_table)
{
	bool found_empty = false;
	u8 used_tc = 0;
	int i;

	for (i = 0; i < CEE_DCBX_MAX_PRIO; i++)
		used_tc |= BIT(prio_table[i]);

	for (i = 0; i < CEE_DCBX_MAX_PRIO; i++) {
		if (used_tc & BIT(i)) {
			if (found_empty)
				return false;
		} else {
			found_empty = true;
		}
	}

	return true;
}

void sxe2_setup_dcb_qos_info(struct sxe2_adapter *adapter,
			     struct aux_qos_params *qos_info)
{
	struct sxe2_dcbx_cfg *dcbx_cfg;
	unsigned int i;

	dcbx_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	qos_info->num_apps = dcbx_cfg->numapps;
	qos_info->num_tc = sxe2_dcb_tc_cnt_get(dcbx_cfg);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		qos_info->up2tc[i] = dcbx_cfg->ets.prio_tbl[i];

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		qos_info->tc_info[i].rel_bw = dcbx_cfg->ets.tcbw_tbl[i];

	for (i = 0; i < qos_info->num_apps; i++) {
		qos_info->apps[i].priority = dcbx_cfg->app[i].prio;
		qos_info->apps[i].prot_id = dcbx_cfg->app[i].prot_id;
		qos_info->apps[i].selector = dcbx_cfg->app[i].selector;
	}

	qos_info->pfc_mode = dcbx_cfg->qos_mode;
	for (i = 0; i < SXE2_DSCP_MAX_NUM; i++)
		qos_info->dscp_map[i] = dcbx_cfg->dscp_map[i];
}

STATIC bool sxe2_dcb_tc_qalloc_chk(struct sxe2_adapter *adapter,
				   struct sxe2_dcbx_cfg *new_cfg)
{
	u8 tc_cnt;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;

	tc_cnt = sxe2_dcb_tc_cnt_get(new_cfg);
	if (vsi->txqs.q_alloc < tc_cnt) {
		LOG_DEV_ERR("Trying to use more Traffic Classes (%u), \t"
			    "than tx queue allocated (%u)!\n",
			     tc_cnt, vsi->txqs.q_alloc);
		return false;
	}

	if (vsi->rxqs.q_alloc < tc_cnt) {
		LOG_DEV_ERR("Trying to use more Traffic Classes (%u), \t"
			    "than rx queue allocated (%u)!\n",
			    tc_cnt, vsi->txqs.q_alloc);
		return false;
	}

	return true;
}

s32 sxe2_fc_get(struct sxe2_adapter *adapter, u16 vsi_id, u8 *fc)
{
	s32 ret = 0;
	struct sxe2_vsi *vsi = NULL;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!vsi) {
		ret = -EINVAL;
		LOG_ERROR("find vf vsi by vsi_id %d failed.\n", vsi_id);
		goto l_unlock;
	}

	if (test_bit(SXE2_VSI_FLAG_FC_ON, vsi->flags)) {
		if (adapter->lfc_ctxt.rx_en || adapter->lfc_ctxt.tx_en)
			*fc = SXE2_FC_T_LFC;
		else
			*fc = SXE2_FC_T_PFC;
	} else {
		*fc = SXE2_FC_T_DIS;
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	return ret;
}

void sxe2_set_fc_flag(struct sxe2_vsi *vsi, bool on)
{
	if (on)
		set_bit(SXE2_VSI_FLAG_FC_ON, vsi->flags);
	else
		clear_bit(SXE2_VSI_FLAG_FC_ON, vsi->flags);
}

s32 sxe2_dcb_cfg(struct sxe2_adapter *adapter, struct sxe2_dcbx_cfg *new_cfg, bool locked)
{
	u8 tc_cnt;
	struct sxe2_vsi *pf_vsi;
	s32 ret = 0;
	struct sxe2_dcbx_cfg *old_cfg, *curr_cfg;
	struct sxe2_vsi *main_vsi;
	u8 tc_map;
	int i;

	curr_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	if (!sxe2_dcb_tc_contig(new_cfg->ets.prio_tbl)) {
		LOG_DEV_ERR("tc not contig\n");
		return -EINVAL;
	}

	if (!sxe2_dcb_tc_qalloc_chk(adapter, new_cfg))
		return -EINVAL;

	tc_cnt = sxe2_dcb_tc_cnt_get(new_cfg);
	if (tc_cnt == SXE2_DFLT_TC_NUM) {
		LOG_INFO_BDF("DCB tagging disabled (num TC = 1)\n");
		clear_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags);
	} else {
		LOG_INFO_BDF("DCB tagging enabled (num TC > 1)\n");
		set_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags);
	}

	if (!memcmp(new_cfg, curr_cfg, sizeof(*new_cfg))) {
		LOG_INFO_BDF("No change in DCB config required\n");
		return ret;
	}

	if (sxe2_dcb_bw_chk(adapter, new_cfg))
		return -EINVAL;

	old_cfg = kmemdup(curr_cfg, sizeof(*old_cfg), GFP_KERNEL);
	if (!old_cfg)
		return -ENOMEM;

	LOG_INFO_BDF("Commit DCB Configuration to the hardware\n");

	pf_vsi = adapter->vsi_ctxt.main_vsi;
	if (!pf_vsi) {
		LOG_ERROR_BDF("PF VSI doesn't exist\n");
		ret = -EINVAL;
		goto free_old_cfg;
	}

	main_vsi = adapter->vsi_ctxt.main_vsi;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (tc_cnt > SXE2_DFLT_TC_NUM &&
	    test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags)) {
		LOG_DEV_ERR("macvlan is enabled, can not set dcb\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	if (test_bit(SXE2_VSI_S_DISABLE, main_vsi->state))
		goto l_unlock;

	sxe2_dcb_vsis_disable_unlock(adapter);
	LOG_INFO_BDF("set dcb vsis disable\n");

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		(void)sxe2_txsched_tc_max_bw_lmt_cfg(adapter->vsi_ctxt.main_vsi,
						     (u8)i, SXE2_TXSCHED_DFLT_BW);
	LOG_INFO_BDF("disable tc maxrate.\n");

	(void)memcpy(curr_cfg, new_cfg, sizeof(*curr_cfg));

	ret = sxe2_dcb_cfg_download(adapter);
	if (ret) {
		LOG_ERROR_BDF("set dcb config failed, ret=%d\n", ret);
		ret = -EBUSY;
		(void)memcpy(curr_cfg, old_cfg, sizeof(*curr_cfg));
		goto out;
	}

	LOG_INFO_BDF("download dcb cfg\n");

	ret = sxe2_txsched_ets_update(adapter, tc_cnt);
	if (ret)
		goto out;

	tc_map = sxe2_dcb_tc_bitmap_get(curr_cfg);
	sxe2_dcb_vsi_cfg(adapter->vsi_ctxt.main_vsi, tc_map);

	if (adapter->dcb_ctxt.state == SXE2_DCB_STATE_READY) {
		mutex_unlock(&adapter->vsi_ctxt.lock);

		ret = sxe2_rdma_aux_send_tc_change_event(adapter);
		if (ret)
			LOG_ERROR_BDF("notify rdma aux failed ret:%d.\n", ret);

		ret = sxe2_netdev_q_cnt_set(main_vsi->netdev, main_vsi->txqs.q_cnt,
					    main_vsi->rxqs.q_cnt, locked);
		if (ret)
			LOG_INFO_BDF("pf netdev q cnt set failed ret:%d.\n", ret);
		mutex_lock(&adapter->vsi_ctxt.lock);
	}

	if (test_bit(SXE2_VSI_S_DISABLE, main_vsi->state))
		goto l_unlock;
out:
	(void)sxe2_dcb_vsis_enable_unlock(adapter);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

free_old_cfg:
	for (i = 0; i < tc_cnt; i++)
		(void)sxe2_txsched_tc_max_bw_lmt_cfg(adapter->vsi_ctxt.main_vsi,
						     (u8)i, curr_cfg->hw_bw_value[i]);
	LOG_INFO_BDF("rebuild tc maxrate.\n");

	kfree(old_cfg);
	return ret;
}

void sxe2_dcb_sw_safe_mode_cfg(struct sxe2_adapter *adapter)
{
	struct sxe2_dcbx_cfg *dcbcfg;
	int i;

	dcbcfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	(void)memset(&adapter->dcb_ctxt.local_dcbx_cfg, 0, sizeof(*dcbcfg));

	dcbcfg->ets.willing = 1;
	dcbcfg->ets.maxtcs = SXE2_TC_MAX_CNT;
	dcbcfg->ets.tcbw_tbl[0] = 100;
	dcbcfg->ets.tsa_tbl[0] = SXE2_IEEE_TSA_ETS;

	dcbcfg->pfc.willing = 1;
	dcbcfg->pfc.cap = SXE2_TC_MAX_CNT;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		dcbcfg->usr_bw_value[i] = 0;
		dcbcfg->hw_bw_value[i] = SXE2_TXSCHED_DFLT_BW;
	}
	(void)memcpy(&adapter->dcb_ctxt.desired_dcbx_cfg, dcbcfg, sizeof(*dcbcfg));
}

s32 sxe2_dcb_sw_dflt_cfg(struct sxe2_adapter *adapter, bool ets_willing, bool locked)
{
	int ret;
	struct sxe2_dcbx_cfg *dcbcfg;
	int i;

	dcbcfg = &adapter->dcb_ctxt.desired_dcbx_cfg;

	(void)memset(&adapter->dcb_ctxt.desired_dcbx_cfg, 0, sizeof(*dcbcfg));

	dcbcfg->ets.willing = ets_willing ? 1 : 0;
	dcbcfg->ets.maxtcs = SXE2_TC_MAX_CNT;
	dcbcfg->ets.tcbw_tbl[0] = 100;
	dcbcfg->ets.tsa_tbl[0] = SXE2_IEEE_TSA_ETS;

	dcbcfg->pfc.willing = 1;
	dcbcfg->pfc.cap = SXE2_TC_MAX_CNT;
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		dcbcfg->usr_bw_value[i] = 0;
		dcbcfg->hw_bw_value[i] = SXE2_TXSCHED_DFLT_BW;
	}

	ret = sxe2_dcb_cfg(adapter, dcbcfg, locked);
	if (ret)
		LOG_ERROR_BDF("Failed to set default dcb config %d\n", ret);

	return ret;
}

s32 sxe2_dcb_process_lldp_set_mib_change(struct sxe2_adapter *adapter, void *buf,
					 u32 buf_len)
{
	s32 ret;
	struct sxe2_dcbx_cfg *tmp_dcbx_cfg = NULL;
	struct sxe2_dcbx_cfg *new_dcbx_cfg = NULL;
	struct sxe2_dcbx_cfg *remote_dcbx_cfg = NULL;
	s32 i = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (!(test_bit(SXE2_FLAG_DCB_CAPABLE, adapter->flags))) {
		LOG_WARN_BDF("dcb disable, lldp mib change\n");
		return 0;
	}

	tmp_dcbx_cfg = devm_kcalloc(dev, sizeof(struct sxe2_dcbx_cfg), 1,
				    GFP_KERNEL);
	new_dcbx_cfg = devm_kcalloc(dev, sizeof(struct sxe2_dcbx_cfg), 1,
				    GFP_KERNEL);
	remote_dcbx_cfg = devm_kcalloc(dev, sizeof(struct sxe2_dcbx_cfg), 1,
				       GFP_KERNEL);
	if (!remote_dcbx_cfg ||
	    !tmp_dcbx_cfg ||
	    !remote_dcbx_cfg) {
		LOG_ERROR_BDF("no mem for remote dcbx_cfg.\n");
		ret = -ENOMEM;
		goto l_out;
	}

	memcpy(tmp_dcbx_cfg, &adapter->dcb_ctxt.local_dcbx_cfg,
	       sizeof(struct sxe2_dcbx_cfg));

	ret = sxe2_lldp_to_dcb_cfg(buf, remote_dcbx_cfg);
	if (ret) {
		LOG_ERROR_BDF("parse dcbx tlv failed: %d\n", ret);
		ret = -EIO;
		goto l_out;
	}

	(void)memcpy(&adapter->dcb_ctxt.remote_dcbx_cfg,
		     remote_dcbx_cfg, sizeof(struct sxe2_dcbx_cfg));

	(void)memcpy(&new_dcbx_cfg->ets, &remote_dcbx_cfg->etsrec,
		     sizeof(struct sxe2_dcb_ets_cfg));
	(void)memcpy(&new_dcbx_cfg->pfc, &remote_dcbx_cfg->pfc,
		     sizeof(struct sxe2_dcb_pfc_cfg));
	new_dcbx_cfg->ets.willing = 1;
	new_dcbx_cfg->pfc.willing = 1;

	if (!memcmp(new_dcbx_cfg, &adapter->dcb_ctxt.local_dcbx_cfg,
		    sizeof(struct sxe2_dcbx_cfg))) {
		LOG_INFO_BDF("no change detected in dcbx configuration.\n");
		goto l_out;
	}

	adapter->dcb_ctxt.dcbx_cap = sxe2_dcb_mode_get(adapter, false);
	sxe2_dcbnl_flush_apps(adapter, tmp_dcbx_cfg,
			      &adapter->dcb_ctxt.local_dcbx_cfg);

	for (i = 0; i < SXE2_DCBX_WAIT_CNT; i++) {
		rtnl_lock();
		mutex_lock(&adapter->dcb_ctxt.tc_mutex);
		if (adapter->dcb_ctxt.state == SXE2_DCB_STATE_READY)
			break;
		mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
		rtnl_unlock();
		msleep(SXE2_DCBX_RESET_WAIT_MS);
	}

	if (i == SXE2_DCBX_WAIT_CNT) {
		LOG_ERROR_BDF("wait reset done timeout.\n");
		ret = -ETIMEDOUT;
		goto l_out;
	}

	ret = sxe2_dcb_cfg(adapter, new_dcbx_cfg, true);
	if (ret)
		LOG_ERROR_BDF("dcb cfg in dcbx notify failed: %d.\n", ret);
	else
		memcpy(&adapter->dcb_ctxt.desired_dcbx_cfg,
		       &adapter->dcb_ctxt.local_dcbx_cfg,
		       sizeof(struct sxe2_dcbx_cfg));

	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	rtnl_unlock();

	LOG_ERROR_BDF("dcbx fw agent mib change process end.\n");

l_out:
	if (tmp_dcbx_cfg)
		devm_kfree(dev, tmp_dcbx_cfg);
	if (new_dcbx_cfg)
		devm_kfree(dev, new_dcbx_cfg);
	if (remote_dcbx_cfg)
		devm_kfree(dev, remote_dcbx_cfg);

	return ret;
}

void sxe2_lldp_sw_rule_change(struct sxe2_adapter *adapter, u8 stats)
{
	s32 ret;

	mutex_lock(&adapter->switch_ctxt.lldp_rule_lock);
	if (stats == SXE2_LLDP_FW_AGENT_ENABLE) {
		ret = sxe2_rx_etype_rule_del(adapter,
					     adapter->vsi_ctxt.main_vsi->idx_in_dev,
					     ETH_P_LLDP);
		if (ret)
			LOG_ERROR_BDF("fw lldp agent fail to change enable:%d\n",
				      ret);

		ret = sxe2_tx_etype_rule_add(adapter->vsi_ctxt.main_vsi, ETH_P_LLDP);
		if (ret)
			LOG_ERROR_BDF("fw lldp agent fail to change enable:%d\n",
				      ret);

		LOG_INFO_BDF("fw lldp agent change to enable\n");
	} else {
		ret = sxe2_rx_etype_rule_add(adapter->vsi_ctxt.main_vsi, ETH_P_LLDP);
		if (ret)
			LOG_ERROR_BDF("fw lldp agent fail to change disable:%d\n",
				      ret);

		ret = sxe2_tx_etype_rule_del(adapter,
					     adapter->vsi_ctxt.main_vsi->idx_in_dev,
					     ETH_P_LLDP);
		if (ret)
			LOG_ERROR_BDF("fw lldp agent fail to change disable:%d\n",
				      ret);

		LOG_INFO_BDF("fw lldp agent change to disable\n");
	}
	mutex_unlock(&adapter->switch_ctxt.lldp_rule_lock);
}

s32 sxe2_lldp_fw_agent_change(struct sxe2_adapter *adapter,
			      void *buf, u32 buf_len)

{
	struct sxe2_fwc_notify_lldp_fw_agent *lldp_st = buf;
	s32 ret = 0;

	if (buf_len < sizeof(struct sxe2_fwc_notify_lldp_fw_agent)) {
		LOG_WARN_BDF("lldp agent changed, receive bad msg.\n");
		ret = -EIO;
		goto out;
	}

	sxe2_lldp_sw_rule_change(adapter, lldp_st->stats);

	if (lldp_st->stats == SXE2_LLDP_FW_AGENT_DISABLE &&
	    test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		set_bit(SXE2_FLAG_FW_DCBX_DIS_PENDING, adapter->flags);
		sxe2_monitor_work_schedule(adapter);
		LOG_DEV_INFO("Recv Fw lldp agent disable action, disable Fw dcbx \t"
			     "agent.\n");
	}

out:
	return ret;
}

s32 sxe2_qos_mode_set(struct sxe2_adapter *adapter, enum sxe2QosMode mode)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_QOS_MODE_SET, &mode, sizeof(mode),
				  NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("add vsi failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_dcbx_agent_event_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_fwc_event event = {0};

	event.count = 1;
	event.code[0] = cpu_to_le16(SXE2_EVENT_CODE_MIB_NOTIFY);
	ret = sxe2_fwc_event_subscribe(adapter, &event);
	if (ret) {
		LOG_ERROR_BDF("dcbx agent event subscribe failed, ret=%d\n", ret);
	} else {
		(void)sxe2_set_event_status(adapter, SXE2_EVENT_CODE_MIB_NOTIFY,
					    SXE2_CMD_EVENT_STATUS_SUB);
	}

	return ret;
}

void sxe2_dcbx_agent_event_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_fwc_event event = {0};

	event.count = 1;
	event.code[0] = cpu_to_le16(SXE2_EVENT_CODE_MIB_NOTIFY);
	(void)sxe2_fwc_event_unsubscribe(adapter, &event);
	(void)sxe2_set_event_status(adapter, SXE2_EVENT_CODE_MIB_NOTIFY,
				    SXE2_CMD_EVENT_STATUS_UNSUB);
}

s32 sxe2_lldp_agent_event_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_fwc_event event = {0};

	event.count = 1;
	event.code[0] = cpu_to_le16(SXE2_EVENT_CODE_LLDP_AGENT_NOTIFY);
	ret = sxe2_fwc_event_subscribe(adapter, &event);
	if (ret)
		LOG_ERROR_BDF("dcbx agent event subscribe failed, ret=%d\n", ret);
	else
		(void)sxe2_set_event_status(adapter, SXE2_EVENT_CODE_LLDP_AGENT_NOTIFY,
					    SXE2_CMD_EVENT_STATUS_SUB);

	return ret;
}

void sxe2_lldp_agent_event_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_fwc_event event = {0};

	event.count = 1;
	event.code[0] = cpu_to_le16(SXE2_EVENT_CODE_MIB_NOTIFY);
	(void)sxe2_fwc_event_unsubscribe(adapter, &event);
	(void)sxe2_set_event_status(adapter, SXE2_EVENT_CODE_LLDP_AGENT_NOTIFY,
				    SXE2_CMD_EVENT_STATUS_UNSUB);
}

s32 sxe2_lldp_fw_agent_status_get(struct sxe2_adapter *adapter,
				  bool *enable, u8 *direction)
{
	s32 ret;
	struct sxe2_fwc_lldp_fw_agent agent = {0};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_FW_AGENT_GET,
				  NULL, 0, &agent, sizeof(agent));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get lldp fw agent status failed, ret=%d\n", ret);
		ret = -EIO;
	}

	*enable = (agent.status == sxe2_lldp_disabled) ? false : true;
	if (direction)
		*direction = agent.status;

	return ret;
}

s32 sxe2_dcbx_fw_agent_status_get(struct sxe2_adapter *adapter, bool *is_enable)
{
	s32 ret;
	struct sxe2_fwc_fw_agent agent = {0};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_DCBX_FW_AGENT_GET, NULL, 0,
				  &agent, sizeof(agent));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get lldp fw agent status failed, ret=%d\n", ret);
		ret = -EIO;
	}

	*is_enable = agent.enable;

	return ret;
}

s32 sxe2_dcbx_fw_agent_status_set(struct sxe2_adapter *adapter, bool is_enable)
{
	s32 ret;
	struct sxe2_fwc_fw_agent agent;
	struct sxe2_cmd_params cmd = {};

	agent.enable = (u8)is_enable;
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LLDP_DCBX_FW_AGENT_SET, &agent,
				  sizeof(agent), NULL, 0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get lldp fw agent status failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

void sxe2_dcb_stats_update(struct sxe2_adapter *adapter)
{
	struct sxe2_dcb_stats *dcb_stats = &adapter->pf_stats.dcb_stats;

	sxe2_hw_pause_stats_update(&adapter->hw,
				   adapter->port_idx, dcb_stats->prev_stat_loaded,
				   &dcb_stats->curr_pause_stats,
				   &dcb_stats->perv_pause_stats);
	dcb_stats->prev_stat_loaded = true;
}

s32 sxe2_dcb_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u8 tc_cnt;
	struct sxe2_dcbx_cfg *cfg = &adapter->dcb_ctxt.local_dcbx_cfg;

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);

	if (test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		ret = sxe2_dcbx_agent_event_init(adapter);
		if (ret) {
			LOG_ERROR_BDF("Listening dcbx agent change even failed %d\n",
				      ret);
			ret = -EIO;
			goto dcb_error;
		}

		ret = sxe2_fw_dcbx_agent_cfg_get(adapter, &adapter->dcb_ctxt.local_dcbx_cfg);
		if (ret)
			LOG_ERROR_BDF("get local dcb config %d use old cfg\n", ret);

		(void)memcpy(&adapter->dcb_ctxt.desired_dcbx_cfg,
			     &adapter->dcb_ctxt.local_dcbx_cfg,
			     sizeof(struct sxe2_dcbx_cfg));
	}

	ret = sxe2_dcb_cfg_download(adapter);
	if (ret) {
		LOG_ERROR_BDF("failed to set dcb config in rebuild\n");
		goto dcb_error;
	}

	LOG_INFO_BDF("DCB info restored\n");
	tc_cnt = sxe2_dcb_tc_cnt_get(cfg);
	ret = sxe2_txsched_ets_update(adapter, tc_cnt);
	if (ret) {
		LOG_ERROR_BDF("Query Port ets failed\n");
		goto dcb_error;
	}

dcb_error:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);

	return ret;
}

s32 sxe2_dcb_maxrate_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u8 tc_cnt;
	struct sxe2_dcbx_cfg *cfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	u8 i;

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	tc_cnt = sxe2_dcb_tc_cnt_get(cfg);
	for (i = 0; i < tc_cnt; i++) {
		ret = sxe2_txsched_tc_max_bw_lmt_cfg(adapter->vsi_ctxt.main_vsi, i,
						     (u32)cfg->hw_bw_value[i]);
		if (ret) {
			LOG_ERROR_BDF("dcb set tc %d maxrate %u failed %d.\n",
				      i, cfg->hw_bw_value[i], ret);
			goto l_end;
		}
		LOG_INFO_BDF("dcb rebuild tc_%d max_bw %u kbps\n",
			     i, cfg->hw_bw_value[i]);
	}

l_end:
	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);

	return ret;
}

static s32 sxe2_dcbx_change2host(struct sxe2_adapter *adapter, bool locked)
{
	s32 ret = 0;

	clear_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags);
	ret = sxe2_qos_mode_set(adapter, SXE2_QOS_MODE_VLAN);
	if (ret) {
		LOG_ERROR_BDF("failed to set vlan pfc mode\n");
		goto out;
	}

	ret = sxe2_dcb_sw_dflt_cfg(adapter, true, locked);
	if (ret) {
		LOG_ERROR_BDF("Failed to set local dcb config %d\n", ret);
		ret = -EIO;
		goto out;
	}

	adapter->dcb_ctxt.dcbx_cap = sxe2_dcb_mode_get(adapter, true);
out:
	return ret;
}

s32 sxe2_dcbx_agent_enable(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	bool lldp_enabled = false;
	u8 dir;

	if (adapter->dcb_ctxt.local_dcbx_cfg.qos_mode == SXE2_QOS_MODE_DSCP) {
		LOG_DEV_ERR("QOS in L3 DSCP mode, \t"
			    "FW Agent not allowed to start\n");
		ret = -EOPNOTSUPP;
		goto l_out;
	}

	ret = sxe2_lldp_fw_agent_status_get(adapter, &lldp_enabled, &dir);
	if (ret) {
		LOG_ERROR_BDF("dcbx lldp st get failed:%d\n", ret);
		goto l_out;
	} else if (!lldp_enabled || dir != sxe2_lldp_enabled_rx_tx) {
		LOG_DEV_ERR("Lldp agent is not enabled or \t"
			    "Fw Lldp Agent work mode is not TXRX.\n");
		ret = -EOPNOTSUPP;
		goto l_out;
	}

	ret = sxe2_dcbx_fw_agent_status_set(adapter, true);
	if (ret) {
		LOG_ERROR_BDF("start fw dcbx agent failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_out;
	}

	ret = sxe2_dcb_init(adapter, true);
	if (ret) {
		LOG_ERROR_BDF("start fw dcbx agent failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_out;
	}

l_out:
	return ret;
}

s32 sxe2_dcbx_agent_disable(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	sxe2_dcbx_agent_event_deinit(adapter);

	ret = sxe2_dcbx_fw_agent_status_set(adapter, false);
	if (ret) {
		LOG_ERROR_BDF("stop fw dcbx agent failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_out;
	}

	ret = sxe2_dcb_init(adapter, true);
	if (ret) {
		LOG_ERROR_BDF("start fw dcbx agent failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_out;
	}

l_out:

	return ret;
}

static s32 sxe2_dcbx_change2fw(struct sxe2_adapter *adapter, bool locked)
{
	s32 ret = 0;

	ret = sxe2_dcbx_agent_event_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("Listening dcbx agent \t"
			      "change even failed %d\n", ret);
		ret = -EIO;
		goto out;
	}

	ret = sxe2_fw_dcbx_agent_cfg_get(adapter, &adapter->dcb_ctxt.desired_dcbx_cfg);
	if (ret) {
		LOG_ERROR_BDF("get local dcb config %d\n", ret);
		ret = -EIO;
		goto out;
	}

	(void)sxe2_dcb_cfg(adapter,
			   &adapter->dcb_ctxt.desired_dcbx_cfg, locked);

	adapter->dcb_ctxt.dcbx_cap = sxe2_dcb_mode_get(adapter, false);

	set_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags);

out:
	return ret;
}

s32 sxe2_dcb_init(struct sxe2_adapter *adapter, bool locked)
{
	s32 ret = 0;
	bool dcbx_enable;

	mutex_lock(&adapter->dcb_ctxt.tc_mutex);
	if (adapter->dcb_ctxt.state == SXE2_DCB_STATE_RESET) {
		LOG_ERROR_BDF("dcb is reset state.\n");
		goto dcb_init_err;
	}

	ret = sxe2_dcbx_fw_agent_status_get(adapter, &dcbx_enable);
	if (ret) {
		LOG_ERROR_BDF("dcbx fw agent status get failed, ret=%d\n", ret);
		goto dcb_init_err;
	}

	if (!dcbx_enable)
		ret = sxe2_dcbx_change2host(adapter, locked);
	else
		ret = sxe2_dcbx_change2fw(adapter, locked);
	if (ret) {
		LOG_ERROR_BDF("dcbx init failed, ret=%d\n", ret);
		goto dcb_init_err;
	}

	if (adapter->dcb_ctxt.state == SXE2_DCB_STATE_UNINIT)
		adapter->dcb_ctxt.state = SXE2_DCB_STATE_READY;

	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	LOG_INFO_BDF("DCB init success\n");

	return 0;

dcb_init_err:

	mutex_unlock(&adapter->dcb_ctxt.tc_mutex);
	LOG_ERROR_BDF("DCB init failed\n");

	return ret;
}

void sxe2_dcb_deinit(struct sxe2_adapter *adapter, bool locked)
{
	rtnl_lock();
	(void)sxe2_dcbx_agent_disable(adapter);
	rtnl_unlock();

	adapter->dcb_ctxt.state = SXE2_DCB_STATE_UNINIT;

	LOG_INFO_BDF("DCB deinit success\n");
}
