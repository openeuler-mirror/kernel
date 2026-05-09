// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_macvlan.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/if_macvlan.h>
#include "sxe2_common.h"
#include "sxe2_macvlan.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_netdev.h"
#include "sxe2_xsk.h"

s32 sxe2_vsi_cfg_netdev_tc0(struct sxe2_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	struct sxe2_adapter *adapter = vsi->adapter;
	int ret;

	if (!netdev)
		return -EINVAL;

	ret = netdev_set_num_tc(netdev, 1);
	if (ret) {
		LOG_ERROR_BDF("Error setting num TC\n");
		return ret;
	}

	ret = netdev_set_tc_queue(netdev, 0, vsi->txqs.q_cnt, 0);
	if (ret) {
		LOG_ERROR_BDF("Error setting TC queue\n");
		goto set_tc_queue_err;
	}

	return 0;
set_tc_queue_err:
	WARN_ON_ONCE(netdev_set_num_tc(netdev, 0));
	return ret;
}

#ifdef HAVE_NETDEV_SB_DEV
STATIC s32 sxe2_netdev_sb_chnl_cfg(struct sxe2_vsi *vsi, struct sxe2_vsi *parent_vsi,
				   struct net_device *vdev, u16 macvlan_id)
{
	s32 ret;
	struct net_device *netdev = parent_vsi->netdev;
	u16 offset = parent_vsi->txqs.q_cnt + macvlan_id;
	struct sxe2_adapter *adapter = vsi->adapter;

	ret = netdev_set_sb_channel(vdev, macvlan_id + 1);
	if (ret) {
		LOG_DEV_ERR("Error setting netdev_set_sb_channel %d\n", ret);
		return ret;
	}

	ret = netdev_bind_sb_channel_queue(netdev, vdev, 0, vsi->txqs.q_cnt, offset);
	if (ret) {
		LOG_DEV_ERR("Error setting netdev_bind_sb_channel_queue %d\n", ret);
		WARN_ON_ONCE(netdev_set_sb_channel(vdev, 0));
	}

	return ret;
}
#endif

STATIC void sxe2_netdev_sb_chnl_uncfg(struct net_device *netdev,
				      struct net_device *vdev)
{
#ifdef HAVE_NETDEV_SB_DEV
	netdev_unbind_sb_channel(netdev, vdev);
	WARN_ON_ONCE(netdev_set_sb_channel(vdev, 0));
#endif
}

STATIC void sxe2_fwd_del_macvlan_unlock(struct net_device *netdev, void *accel_priv)
{
	struct sxe2_macvlan *mv = accel_priv;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *parent_vsi = np->vsi;
	struct sxe2_vsi *vsi = mv->vsi;
	struct sxe2_adapter *adapter = parent_vsi->adapter;
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;
	struct net_device *vdev = mv->vdev;
	s32 mv_id = mv->id;

	sxe2_netdev_sb_chnl_uncfg(netdev, vdev);

	macvlan->num_macvlan--;
	clear_bit(mv_id, macvlan->avail_macvlan);
	list_del(&mv->list);
	devm_kfree(&adapter->pdev->dev, mv);

	if (parent_vsi->txqs.q[parent_vsi->txqs.q_cnt + mv_id])
		parent_vsi->txqs.q[parent_vsi->txqs.q_cnt + mv_id] = NULL;

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		vsi->netdev = NULL;
		set_bit(SXE2_VSI_S_MACVLAN_DEL, vsi->state);
		sxe2_monitor_work_schedule(adapter);
	} else {
		sxe2_vsi_destroy_unlock(vsi);
	}

	LOG_DEV_INFO("Delete MACVLAN of %s.\n", vdev->name);
}

void sxe2_fwd_del_macvlan(struct net_device *netdev, void *accel_priv)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *parent_vsi = np->vsi;
	struct sxe2_adapter *adapter = parent_vsi->adapter;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_fwd_del_macvlan_unlock(netdev, accel_priv);
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

STATIC s32 sxe2_add_macvlan_check(struct sxe2_adapter *adapter,
				  struct net_device *vdev)
{
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("can not do MACVLAN offload. device is in Safe Mode\n");
		return -EOPNOTSUPP;
	}

	if (macvlan->num_macvlan == macvlan->max_num_macvlan) {
		LOG_DEV_ERR("MACVLAN offload limit reached\n");
		return -ENOSPC;
	}

	if (vdev->num_rx_queues != SXE2_DFLT_RXQ_VMDQ_VSI ||
	    vdev->num_tx_queues != SXE2_DFLT_TXQ_VMDQ_VSI) {
		LOG_DEV_ERR("can not do MACVLAN offload. %s has multiple queues\n",
			    vdev->name);
		return -EOPNOTSUPP;
	}

	if (sxe2_usable_txqs_cnt_get(adapter) < SXE2_DFLT_TXQ_VMDQ_VSI ||
	    sxe2_usable_rxqs_cnt_get(adapter) < SXE2_DFLT_RXQ_VMDQ_VSI) {
		LOG_DEV_ERR("can not do MACVLAN offload. Not enough queues\n");
		return -ENOSPC;
	}

	return 0;
}

STATIC void *sxe2_fwd_add_macvlan_unlock(struct net_device *netdev,
					 struct net_device *vdev)
{
	s32 ret;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *parent_vsi = np->vsi;
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_adapter *adapter = parent_vsi->adapter;
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;
	struct sxe2_macvlan *mv = NULL;
	s32 avail_id, offset, i;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u8 mac[ETH_ALEN];

	ret = sxe2_add_macvlan_check(adapter, vdev);
	if (ret)
		return ERR_PTR(ret);

	if (test_bit(SXE2_VSI_S_DISABLE, parent_vsi->state)) {
		LOG_DEV_ERR("pf vsi disabled, try later.\n");
		ret = -EBUSY;
		goto l_end;
	}

	avail_id = (s32)find_first_zero_bit(macvlan->avail_macvlan,
					    macvlan->max_num_macvlan);

	vsi = sxe2_macvlan_vsi_create(adapter);
	if (!vsi) {
		LOG_DEV_ERR("Failed to create MACVLAN offload (VMDQ) VSI\n");
		ret = -EIO;
		goto l_end;
	}

	macvlan->num_macvlan++;
	offset = parent_vsi->txqs.q_cnt + avail_id;
	vsi->netdev = vdev;

	sxe2_for_each_vsi_txq(vsi, i)
	{
		parent_vsi->txqs.q[offset + i] = vsi->txqs.q[i];
	}

	ret = sxe2_vsi_cfg_netdev_tc0(vsi);
	if (ret)
		goto l_vsi_destroy;

#ifdef HAVE_NETDEV_SB_DEV
	ret = sxe2_netdev_sb_chnl_cfg(vsi, parent_vsi, vdev, (u16)avail_id);
	if (ret)
		goto l_vsi_destroy;
#endif

	sxe2_napi_add(vsi);

	ret = sxe2_vsi_open(vsi);
	if (ret)
		goto l_sb_chnl_uncfg;

	ether_addr_copy(mac, vdev->dev_addr);
	ret = sxe2_mac_rule_add(vsi, mac);
	if (ret == -EEXIST) {
		LOG_DEV_INFO("can't add MAC filters %pM for VSI %d, error %d\n", mac,
			     vsi->idx_in_dev, ret);
	} else if (ret) {
		LOG_DEV_INFO("can't add MAC filters %pM for VSI %d, error %d\n", mac,
			     vsi->idx_in_dev, ret);
		ret = -ENOMEM;
		goto l_add_mac_err;
	}

	mv = devm_kzalloc(dev, sizeof(*mv), GFP_KERNEL);
	if (!mv) {
		ret = -ENOMEM;
		goto l_mv_init_err;
	}
	INIT_LIST_HEAD(&mv->list);
	mv->parent_vsi = parent_vsi;
	mv->vsi = vsi;
	mv->id = avail_id;
	mv->vdev = vdev;
	ether_addr_copy(mv->mac, mac);
	list_add(&mv->list, &macvlan->macvlan_list);

	set_bit(avail_id, macvlan->avail_macvlan);

	LOG_DEV_INFO("MACVLAN offloads for %s are on\n", vdev->name);

	return mv;

l_mv_init_err:
	sxe2_vsi_fltr_remove(adapter, vsi->idx_in_dev);
l_add_mac_err:
	WARN_ON_ONCE(sxe2_vsi_close(vsi));
	sxe2_napi_del(vsi);
	vsi->netdev = NULL;
l_sb_chnl_uncfg:
	sxe2_netdev_sb_chnl_uncfg(netdev, vdev);
l_vsi_destroy:
	macvlan->num_macvlan--;
	sxe2_vsi_destroy_unlock(vsi);
l_end:
	return ERR_PTR(ret);
}

void *sxe2_fwd_add_macvlan(struct net_device *netdev, struct net_device *vdev)
{
	void *mv;
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *parent_vsi = np->vsi;
	struct sxe2_adapter *adapter = parent_vsi->adapter;
	s32 ret;
	u16 old_txq_cnt = (u16)vdev->real_num_tx_queues;
	u16 old_rxq_cnt = (u16)vdev->real_num_rx_queues;

	ret = sxe2_netdev_q_cnt_set(vdev, SXE2_DFLT_TXQ_VMDQ_VSI,
				    SXE2_DFLT_RXQ_VMDQ_VSI, true);
	if (ret) {
		LOG_DEV_ERR("macvlan netdev real tx:%u rx:%u set failed:%d\n",
			    SXE2_DFLT_TXQ_VMDQ_VSI, SXE2_DFLT_RXQ_VMDQ_VSI, ret);
		return NULL;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	mv = sxe2_fwd_add_macvlan_unlock(netdev, vdev);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	if (!mv)
		WARN_ON_ONCE(sxe2_netdev_q_cnt_set(vdev, old_txq_cnt, old_rxq_cnt,
						   true));

	return mv;
}

STATIC s32 sxe2_macvlan_enable_check_without_lock(struct sxe2_vsi *vsi, bool init)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;

	if (init && test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto l_end;
	}

#ifdef HAVE_XDP_SUPPORT
	if (sxe2_xdp_is_enable(vsi)) {
		ret = -EPERM;
		LOG_DEV_ERR("MACVLAN offload cannot be supported - xdp enabled\n");
		goto l_end;
	}
#endif

	if (!test_bit(SXE2_FLAG_VMDQ_CAPABLE, adapter->flags)) {
		ret = -EPERM;
		LOG_DEV_ERR("MACVLAN offload cannot be supported - VMDQ is disabled\n");
		goto l_end;
	}

	if (test_bit(SXE2_FLAG_DCB_ENABLE, adapter->flags)) {
		ret = -EPERM;
		LOG_DEV_ERR("MACVLAN offload cannot be supported - dcb enabled\n");
		goto l_end;
	}

	if (sxe2_is_safe_mode(adapter)) {
		ret = -EOPNOTSUPP;
		LOG_DEV_ERR("MACVLAN offload cannot be configured - Device is in Safe Mode\n");
		goto l_end;
	}

	if (sxe2_eswitch_is_offload(adapter)) {
		ret = -EOPNOTSUPP;
		LOG_DEV_ERR("MACVLAN offload cannot be configured - switchdev is enabled\n");
	}

l_end:
	return ret;
}

STATIC struct sxe2_queue **sxe2_macvlan_q_alloc(struct sxe2_vsi *vsi)
{
	unsigned int total_q_cnt;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;
	struct sxe2_queue **temp_queues = NULL;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u16 txqs = sxe2_usable_txqs_cnt_get(adapter);
	u16 rxqs = sxe2_usable_rxqs_cnt_get(adapter);

	macvlan->max_num_macvlan = (u16)min3(txqs, rxqs, (u16)SXE2_MAX_MACVLANS);

	total_q_cnt = vsi->txqs.q_cnt + macvlan->max_num_macvlan;

	temp_queues = devm_kcalloc(dev, total_q_cnt, sizeof(*temp_queues),
				   GFP_KERNEL);
	if (!temp_queues)
		macvlan->max_num_macvlan = 0;

	return temp_queues;
}

s32 sxe2_macvlan_init(struct sxe2_vsi *vsi, bool init)
{
	s32 ret = 0;
	struct net_device *netdev = vsi->netdev;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;
	struct sxe2_queue **temp_queues;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 i;

	if (sxe2_eswitch_mode_read_lock(adapter)) {
		ret = -EBUSY;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);

	ret = sxe2_macvlan_enable_check_without_lock(vsi, init);
	if (ret) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		goto l_end;
	}

	temp_queues = sxe2_macvlan_q_alloc(vsi);
	if (!temp_queues) {
		ret = -ENOMEM;
		mutex_unlock(&adapter->vsi_ctxt.lock);
		goto l_end;
	}

	ret = sxe2_vsi_close(vsi);
	if (ret) {
		devm_kfree(dev, temp_queues);
		macvlan->max_num_macvlan = 0;
		if (netif_running(vsi->netdev))
			WARN_ON_ONCE(sxe2_vsi_open(vsi));

		mutex_unlock(&adapter->vsi_ctxt.lock);
		goto l_end;
	}

	set_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	ret = sxe2_netdev_q_cnt_set(netdev, vsi->txqs.q_cnt, vsi->rxqs.q_cnt, init);
	if (ret) {
		clear_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags);
		devm_kfree(dev, temp_queues);
		macvlan->max_num_macvlan = 0;
		if (netif_running(vsi->netdev)) {
			mutex_lock(&adapter->vsi_ctxt.lock);
			WARN_ON_ONCE(sxe2_vsi_open(vsi));
			mutex_unlock(&adapter->vsi_ctxt.lock);
		}
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (init && test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		goto dis_vsi_err;
	}
	sxe2_for_each_vsi_txq(vsi, i)
	{
		temp_queues[i] = vsi->txqs.q[i];
	}

	vsi->origin_txqs = vsi->txqs.q;
	vsi->txqs.q = temp_queues;

	if (!init) {
		LOG_WARN_BDF("macvlan rebuild no need enable vsi.\n");
		goto l_unlock;
	}

	ret = sxe2_vsi_cfg_netdev_tc0(vsi);
	if (ret)
		goto set_num_tc_err;

	INIT_LIST_HEAD(&macvlan->macvlan_list);

	goto ena_vsi;

set_num_tc_err:
	vsi->txqs.q = vsi->origin_txqs;
	vsi->origin_txqs = NULL;

dis_vsi_err:
	clear_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags);
	devm_kfree(dev, temp_queues);
	macvlan->max_num_macvlan = 0;

ena_vsi:
	if (netif_running(vsi->netdev))
		WARN_ON_ONCE(sxe2_vsi_open(vsi));

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

	if (ret) {
		WARN_ON_ONCE(sxe2_netdev_q_cnt_set(netdev, vsi->txqs.q_cnt,
						   vsi->rxqs.q_cnt, init));
	}

l_end:
	sxe2_eswitch_mode_read_unlock(adapter);
	return ret;
}

s32 sxe2_macvlan_deinit(struct sxe2_vsi *vsi, bool locked)
{
	struct sxe2_macvlan *mv, *mv_tmp;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;
	struct sxe2_queue **temp_queues = NULL;
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);

	if (locked && test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		ret = -EBUSY;
		LOG_ERROR_BDF("vsi disabled, try later.\n");
		goto l_unlock;
	}

	clear_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags);

	(void)sxe2_vsi_close(vsi);

	list_for_each_entry_safe(mv, mv_tmp, &macvlan->macvlan_list, list) {
		(void)sxe2_mac_rule_del(adapter, mv->vsi->idx_in_dev, mv->mac);
#ifdef HAVE_NETDEV_SB_DEV
		(void)macvlan_release_l2fw_offload(mv->vdev);
#endif
		sxe2_fwd_del_macvlan_unlock(mv->parent_vsi->netdev, mv);
	}

	ret = netdev_set_num_tc(vsi->netdev, 0);
	if (ret)
		LOG_ERROR_BDF("set num:0 tc NOK, ret:%d\n", ret);

	mutex_unlock(&adapter->vsi_ctxt.lock);
	ret = sxe2_netdev_q_cnt_set(vsi->netdev, vsi->txqs.q_cnt, vsi->rxqs.q_cnt,
				    locked);
	if (ret) {
		LOG_ERROR_BDF("netdev txq_cnt:%u rxq_cnt:%u set failed %d.\n",
			      vsi->txqs.q_cnt, vsi->rxqs.q_cnt, ret);
		goto l_end;
	}

	macvlan->max_num_macvlan = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	temp_queues = vsi->txqs.q;
	vsi->txqs.q = vsi->origin_txqs;
	vsi->origin_txqs = NULL;

	if (locked) {
		if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
			ret = -EBUSY;
			LOG_ERROR_BDF("vsi disabled, try later.\n");
			goto l_unlock;
		}

		if (netif_running(vsi->netdev) && sxe2_vsi_open(vsi))
			LOG_ERROR_BDF("main vsi enable failed %d.\n", ret);
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (temp_queues)
		devm_kfree(&adapter->pdev->dev, temp_queues);

l_end:
	return ret;
}

STATIC void sxe2_macvlan_replay(struct sxe2_adapter *adapter)
{
	struct sxe2_macvlan_context *macvlan = &adapter->macvlan_ctxt;
	struct sxe2_macvlan *mv, *mv_temp;
	struct sxe2_vsi *parent_vsi;
	s32 offset;
	u16 i;
#ifdef HAVE_NETDEV_SB_DEV
	s32 ret;
#endif

	mutex_lock(&adapter->vsi_ctxt.lock);

	list_for_each_entry_safe(mv, mv_temp, &macvlan->macvlan_list, list) {
		parent_vsi = mv->parent_vsi;
		offset = parent_vsi->txqs.q_cnt + mv->id;

		sxe2_for_each_vsi_txq(mv->vsi, i)
		{
			parent_vsi->txqs.q[offset + i] = mv->vsi->txqs.q[i];
		}

#ifdef HAVE_NETDEV_SB_DEV
		ret = sxe2_netdev_sb_chnl_cfg(mv->vsi, parent_vsi, mv->vdev,
					      (u16)mv->id);
		if (ret) {
			LOG_ERROR_BDF("sxe2_netdev_sb_chnl_cfg failed: %d.\n", ret);
			(void)sxe2_mac_rule_del(adapter, mv->vsi->idx_in_dev,
						mv->mac);
			(void)macvlan_release_l2fw_offload(mv->vdev);
			sxe2_fwd_del_macvlan_unlock(mv->parent_vsi->netdev, mv);
			continue;
		}
#endif
	}

	mutex_unlock(&adapter->vsi_ctxt.lock);
}

void sxe2_fwd_del_macvlan_deay(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;
	u16 i;

	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_for_each_vsi(&adapter->vsi_ctxt, i)
	{
		vsi = adapter->vsi_ctxt.vsi[i];
		if (!vsi || vsi->type != SXE2_VSI_T_MACVLAN)
			continue;

		if (!test_bit(SXE2_VSI_S_MACVLAN_DEL, vsi->state))
			continue;

		sxe2_vsi_destroy_unlock(vsi);
	}
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

s32 sxe2_macvlan_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_vsi *parent_vsi = adapter->vsi_ctxt.main_vsi;

	if (!test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags))
		return 0;

	ret = sxe2_vsi_rebuild_by_type(adapter, SXE2_VSI_T_MACVLAN, true);
	if (ret) {
		LOG_DEV_ERR("sxe2_vsi_rebuild_by_type failed ret:%d.\n", ret);
		goto l_end;
	}

	ret = sxe2_macvlan_init(parent_vsi, false);
	if (ret) {
		LOG_DEV_ERR("sxe2_macvlan_init failed ret:%d.\n", ret);
		goto l_err;
	}

	sxe2_macvlan_replay(adapter);

	rtnl_lock();
	ret = sxe2_vsi_enable_by_type(adapter, SXE2_VSI_T_MACVLAN);
	rtnl_unlock();
	if (!ret) {
		LOG_DEV_ERR("sxe2_vsi_enable_by_type failed ret:%d.\n", ret);
		goto l_end;
	}

l_err:
	WARN_ON_ONCE(sxe2_macvlan_deinit(parent_vsi, false));
l_end:
	return ret;
}

bool sxe2_macvlan_is_enabled(struct sxe2_adapter *adapter)
{
	return !!(test_bit(SXE2_FLAG_MACVLAN_ENABLE, adapter->flags));
}

#ifdef SXE2_MACVLAN_STATS
struct sxe2_macvlan *sxe2_get_macvlan(int id, struct sxe2_adapter *adapter)
{
	struct sxe2_macvlan *mv;

	if (!(test_bit(id, adapter->macvlan_ctxt.avail_macvlan)))
		return NULL;

	list_for_each_entry(mv, &adapter->macvlan_ctxt.macvlan_list, list) {
		if (id == mv->id)
			return mv;
	}
	return NULL;
}
#endif
