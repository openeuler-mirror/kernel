// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_monitor.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2.h"
#include "sxe2_tx.h"
#include "sxe2_monitor.h"
#include "sxe2_ethtool.h"
#include "sxe2_mbx_channel.h"
#include "sxe2_aux_driver.h"
#include "sxe2_ipsec.h"
#include "sxe2_arfs.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_lag.h"
#include "sxe2_cmd.h"
#include "sxe2_hw.h"

#define SXE2_TX_TIME_HANDLE_JIFFIES(last_jiffies) ((unsigned long)last_jiffies + 2 * HZ)

#define SXE2_BITS_PER_U64 (sizeof(u64) * BITS_PER_BYTE)

struct workqueue_struct *sxe2_workqueue;

#ifdef SXE2_CFG_DEBUG
extern int g_pf_switch_stats;
#endif

static void sxe2_monitor_work_complete(struct sxe2_adapter *adapter)
{
	BUG_ON(!test_bit(SXE2_MONITOR_WORK_SCHED, &adapter->monitor_ctxt.state));
	/* in order to force CPU ordering */
	smp_mb__before_atomic();
	clear_bit(SXE2_MONITOR_WORK_SCHED, &adapter->monitor_ctxt.state);
}

int sxe2_sync_mac_add(struct net_device *netdev, const u8 *addr)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_mac_sync_entry *mac_entry;

	mac_entry = kzalloc(sizeof(*mac_entry), GFP_ATOMIC);
	if (!mac_entry)
		return -ENOMEM;

	ether_addr_copy(mac_entry->mac_addr, addr);
	list_add(&mac_entry->list_entry, &vsi->mac_filter.tmp_sync_list);

	return 0;
}

int sxe2_unsync_mac_add(struct net_device *netdev, const u8 *addr)
{
	struct sxe2_netdev_priv *np = netdev_priv(netdev);
	struct sxe2_vsi *vsi = np->vsi;
	struct sxe2_mac_sync_entry *mac_entry;

	mac_entry = kzalloc(sizeof(*mac_entry), GFP_ATOMIC);
	if (!mac_entry)
		return -ENOMEM;

	ether_addr_copy(mac_entry->mac_addr, addr);
	list_add(&mac_entry->list_entry, &vsi->mac_filter.tmp_unsync_list);

	return 0;
}

STATIC s32 sxe2_vsi_promisc_sync_legacy(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct net_device *netdev = vsi->netdev;
	struct sxe2_adapter *adapter = vsi->adapter;

	mutex_lock(&adapter->user_pf_ctxt.flag_lock);

	if (!(netdev->flags & IFF_ALLMULTI) && !(netdev->flags & IFF_PROMISC)) {
		if (sxe2_allmulti_rule_in_use(vsi)) {
			ret = sxe2_allmulti_rule_del(adapter, vsi->idx_in_dev);
			if (ret) {
				LOG_DEV_ERR("delete allmulti filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}

		if (sxe2_promisc_rule_in_use(vsi)) {
			ret = sxe2_promisc_rule_del(adapter, vsi->idx_in_dev);
			if (ret) {
				LOG_DEV_ERR("delete promisc filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}

		if (netdev->features & NETIF_F_HW_VLAN_CTAG_FILTER) {
			ret = sxe2_vlan_filter_control(adapter, vsi->idx_in_dev,
						       true);
			if (ret) {
				LOG_DEV_ERR("turn on vlan filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}
	} else if ((netdev->flags & IFF_ALLMULTI) &&
		   !(netdev->flags & IFF_PROMISC)) {
		if (!sxe2_allmulti_rule_in_use(vsi) &&
		    !adapter->user_pf_ctxt.is_allmulti_set) {
			ret = sxe2_allmulti_rule_add(vsi);
			if (ret) {
				LOG_DEV_ERR("add allmulti filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}

		if (sxe2_promisc_rule_in_use(vsi)) {
			ret = sxe2_promisc_rule_del(adapter, vsi->idx_in_dev);
			if (ret) {
				LOG_DEV_ERR("delete promisc filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}

		if (netdev->features & NETIF_F_HW_VLAN_CTAG_FILTER) {
			ret = sxe2_vlan_filter_control(adapter, vsi->idx_in_dev,
						       true);
			if (ret) {
				LOG_DEV_ERR("turn on vlan filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}
	} else {
		if (!sxe2_allmulti_rule_in_use(vsi) &&
		    !adapter->user_pf_ctxt.is_allmulti_set) {
			ret = sxe2_allmulti_rule_add(vsi);
			if (ret) {
				LOG_DEV_ERR("add allmulti filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}

		if (!sxe2_promisc_rule_in_use(vsi) &&
		    !adapter->user_pf_ctxt.is_promisc_set) {
			ret = sxe2_promisc_rule_add(vsi);
			if (ret) {
				LOG_DEV_ERR("add promisc filter failed, ret %d\n",
					    ret);
				goto l_end;
			}
		}

		ret = sxe2_vlan_filter_control(adapter, vsi->idx_in_dev, false);
		if (ret) {
			LOG_DEV_ERR("turn off vlan filter failed, ret %d\n", ret);
			goto l_end;
		}
	}

l_end:
	mutex_unlock(&adapter->user_pf_ctxt.flag_lock);

	return ret;
}

STATIC s32 sxe2_vsi_l2_fltr_sync(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct net_device *netdev = vsi->netdev;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_mac_sync_entry *list_itr = NULL;
	struct sxe2_mac_sync_entry *tmp = NULL;
	struct sxe2_mac_filter *mac_filter = &vsi->mac_filter;

	if (!vsi->netdev)
		return 0;

	rtnl_lock();

	if (test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags)) {
		clear_bit(SXE2_VSI_S_MAC_FLTR_CHANGED, vsi->state);
		rtnl_unlock();
		return 0;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	mutex_lock(&mac_filter->sync_lock);

	INIT_LIST_HEAD(&mac_filter->tmp_sync_list);
	INIT_LIST_HEAD(&mac_filter->tmp_unsync_list);

	if (test_bit(SXE2_VSI_S_MAC_FLTR_CHANGED, vsi->state)) {
		clear_bit(SXE2_VSI_S_MAC_FLTR_CHANGED, vsi->state);
		netif_addr_lock_bh(netdev);
		(void)__dev_uc_sync(netdev, sxe2_sync_mac_add, sxe2_unsync_mac_add);
		(void)__dev_mc_sync(netdev, sxe2_sync_mac_add, sxe2_unsync_mac_add);
		netif_addr_unlock_bh(netdev);
	}

	list_for_each_entry_safe(list_itr, tmp, &mac_filter->tmp_sync_list,
				 list_entry) {
		ret = sxe2_mac_addr_add(vsi, list_itr->mac_addr,
					SXE2_MAC_OWNER_UC_MC);
		if (ret)
			LOG_DEV_ERR("add mac filter failed, addr %pM, ret %d\n",
				    list_itr->mac_addr, ret);
		list_del(&list_itr->list_entry);
		kfree(list_itr);
	}

	list_for_each_entry_safe(list_itr, tmp, &mac_filter->tmp_unsync_list,
				 list_entry) {
		ret = sxe2_mac_addr_del(vsi, list_itr->mac_addr,
					SXE2_MAC_OWNER_UC_MC);
		if (ret)
			LOG_DEV_ERR("delete mac filter failed, addr %pM, ret %d\n",
				    list_itr->mac_addr, ret);
		list_del(&list_itr->list_entry);
		kfree(list_itr);
	}
	mutex_unlock(&mac_filter->sync_lock);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	ret = sxe2_vsi_promisc_sync_legacy(vsi);

	rtnl_unlock();
	return ret;
}

STATIC void sxe2_l2_fltr_sync(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;

	if (!test_bit(SXE2_FLAG_FLTR_SYNC, adapter->flags))
		return;

	if (test_bit(SXE2_VSI_S_DISABLE, vsi->state)) {
		LOG_ERROR("can't sync l2 fltr. device not ready\n");
		return;
	}

	clear_bit(SXE2_FLAG_FLTR_SYNC, adapter->flags);

	if (test_bit(SXE2_VSI_S_MAC_FLTR_CHANGED, vsi->state))
		(void)sxe2_vsi_l2_fltr_sync(vsi);
}

static void sxe2_stats_update_work(struct sxe2_adapter *adapter)
{
	mutex_lock(&adapter->vsi_ctxt.lock);
	sxe2_stats_update(adapter);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	sxe2_repr_vf_vsis_stats_acculate_update(adapter);
}

STATIC void sxe2_mtu_changed_handler(struct sxe2_adapter *adapter)
{
	if (test_and_clear_bit(SXE2_FLAG_MTU_CHANGED, adapter->flags))
		(void)sxe2_rdma_aux_send_mtu_changed_event(adapter);
}

static void sxe2_mdd_req_fill(struct sxe2_adapter *adapter,
			      struct sxe2_fwc_mdd_req *req)
{
	struct sxe2_vf_node *vf_node;
	u16 idx;
	u16 i = 0;
	struct sxe2_mdd_vf_req *vf = req->vfs;

	sxe2_for_each_vf(adapter, idx)
	{
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);
		if (!vf_node) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
			continue;
		}

		vf->vf_idx = cpu_to_le16(vf_node->vf_idx);
		vf->q_mapping_mode = SXE2_MAPPING_CONTIG;
		vf++;
		i++;
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
	}

	req->vf_cnt = cpu_to_le16(i);
}

static void sxe2_mdd_req_v2_fill(struct sxe2_adapter *adapter,
				 struct sxe2_fwc_mdd_req_v2 *req)
{
	struct sxe2_vf_node *vf_node;
	u16 idx;
	u16 i = 0;
	struct sxe2_mdd_vf_req_v2 *vf = req->vfs;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct sxe2_queue_layout *q_layout = &adapter->q_ctxt.txq_layout;
	unsigned long *map = q_layout->txq_map;
	struct sxe2_vsi_queues *queues = &vsi->txqs;
	u16 offset = 0;

	offset = sxe2_vsi_qs_offset_get(vsi, q_layout, map,
					adapter->q_ctxt.max_txq_cnt,
					queues->q_alloc, SXE2_DATA_TQ);
	req->q_offset = cpu_to_le16(offset);
	sxe2_for_each_vf(adapter, idx)
	{
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);

		vf->vf_idx = cpu_to_le16(vf_node->vf_idx);
		vf->q_mapping_mode = SXE2_MAPPING_CONTIG;

		vf++;
		i++;
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
	}

	req->vf_cnt = cpu_to_le16(i);
}

STATIC s32 sxe2_fwc_vf_mdd_check(struct sxe2_adapter *adapter,
				 struct sxe2_fwc_mdd_req *req, u32 req_len,
				 struct sxe2_fwc_mdd_resp *resp, u32 resp_len)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_MDD_CHECK, req, req_len, resp,
				  resp_len);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi mdd check failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_fwc_vf_mdd_check_v2(struct sxe2_adapter *adapter,
				    struct sxe2_fwc_mdd_req_v2 *req, u32 req_len,
				    struct sxe2_fwc_mdd_resp_v2 *resp, u32 resp_len)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_VSI_MDD_CHECK_V2,
				  req, req_len, resp, resp_len);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi mdd check v2 failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_fwc_vf_mdd_check_compat(struct sxe2_adapter *adapter,
					u8 *req_buf, u32 req_len_v2,
					u8 *resp_buf_v2, u32 resp_len_v2,
					u8 *req_buf_v1, u32 req_len_v1,
					u8 *resp_buf_v1, u32 resp_len_v1,
					bool *used_v2)
{
	s32 ret;

	*used_v2 = false;

	ret = sxe2_fwc_vf_mdd_check_v2(adapter,
				       (struct sxe2_fwc_mdd_req_v2 *)req_buf,
				       req_len_v2,
				       (struct sxe2_fwc_mdd_resp_v2 *)resp_buf_v2,
				       resp_len_v2);
	if (ret == 0) {
		*used_v2 = true;
		return 0;
	}

	LOG_WARN_BDF("MDD_CHECK_V2 opcode failed (ret=%d), fallback to V1 opcode\n", ret);
	ret = sxe2_fwc_vf_mdd_check(adapter,
				    (struct sxe2_fwc_mdd_req *)req_buf_v1,
				    req_len_v1,
				    (struct sxe2_fwc_mdd_resp *)resp_buf_v1,
				    resp_len_v1);
	if (ret == 0)
		*used_v2 = false;

	return ret;
}

STATIC bool sxe2_mdd_rx_event_valid(u8 event)
{
	return event != SXE2_RX_MDD_EVENT_NONE &&
	       event != SXE2_RX_MDD_EVENT_INVALID;
}

static void sxe2_vf_mdd_reply_process(struct sxe2_adapter *adapter,
				      struct sxe2_fwc_mdd_resp *resp)
{
	u32 i;
	u16 vf_idx;
	u16 pf_idx = adapter->pf_idx;
	u32 mdd_tx_event;
	u8 mdd_rx_event;
	struct sxe2_mdd_vf_resp *mdd_vfs = resp->mdd_vfs;
	struct sxe2_vf_node *vf_node;

	mdd_tx_event = le32_to_cpu(resp->pf_mdd_tx_event);
	mdd_rx_event = resp->pf_mdd_rx_event;
	if (mdd_tx_event) {
		LOG_DEV_WARN("Malicious Driver Detection Tx event on PF# %d.\n",
			     pf_idx);
		LOG_DEV_WARN("pf mdd event 0x%04x detected.\n", mdd_tx_event);
	}

	if (sxe2_mdd_rx_event_valid(mdd_rx_event)) {
		LOG_DEV_WARN("Malicious Driver Detection Rx event on PF# %d.\n",
			     pf_idx);
		LOG_DEV_WARN("pf mdd rx event 0x%04x detected, enter FAULT state.\n", mdd_rx_event);
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_FAULT,
				   SXE2_RESET_INVAL);
		sxe2_dev_ctrl_work_schedule(adapter);
		return;
	}

	mdd_tx_event = le32_to_cpu(resp->vf_mdd_tx_event);
	mdd_rx_event = resp->vf_mdd_rx_event;
	if (mdd_tx_event || sxe2_mdd_rx_event_valid(mdd_rx_event)) {
		LOG_DEV_WARN("vf mdd tx event 0x%04x rx event 0x%04x detected.\n",
			     mdd_tx_event, mdd_rx_event);

		for (i = 0; i < resp->mdd_vf_cnt; i++) {
			vf_idx = le16_to_cpu(mdd_vfs[i].vf_idx);

			if (sxe2_vf_id_check(adapter, vf_idx)) {
				LOG_ERROR_BDF("invalid mdd vf_idx:%u.\n", vf_idx);
				continue;
			}

			mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			vf_node = sxe2_vf_node_get(adapter, vf_idx);
			if (!vf_node) {
				LOG_ERROR_BDF("vf %d node is null.\n", vf_idx);
				mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
				continue;
			}

			if (sxe2_check_vf_ready_for_cfg(vf_node)) {
				mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
				continue;
			}

			LOG_DEV_WARN("vf %d mdd tx event 0x%04x rx event 0x%04x mdd\t"
				     "%d detected.\n",
				     vf_idx, mdd_tx_event, mdd_rx_event,
				     mdd_vfs[i].mdd);
			if (mdd_vfs[i].mdd & SXE2_MDD_TYPE_TX) {
				LOG_DEV_WARN("Malicious Driver Detection Tx event\t"
					     "on PF# %d VF# %d Mac %pM.\t"
					     "mdd-auto-reset-vfs=%s\n",
					     pf_idx, vf_idx, vf_node->mac_addr.addr,
					     test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF,
						      adapter->flags)
							     ? "on"
							     : "off");
			}

			if (mdd_vfs[i].mdd & SXE2_MDD_TYPE_RX) {
				LOG_DEV_WARN("Malicious Driver Detection Rx event \t"
					     "on PF# %d VF# %d Mac %pM. \t"
					     "mdd-auto-reset-vfs=%s\n",
					     pf_idx, vf_idx, vf_node->mac_addr.addr,
					     test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF,
						      adapter->flags)
							     ? "on"
							     : "off");
			}

			if (test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF, adapter->flags)) {
				LOG_DEV_WARN("vf #%d detected mdd event reset vf now.\n",
					     vf_idx);
				(void)sxe2_reset_vf(adapter, vf_idx, 0);
			} else if (mdd_vfs[i].mdd & SXE2_MDD_TYPE_RX) {
				LOG_DEV_WARN("vf %d rx mdd detected, notify VF\t"
					     "enter FAULT state.\n", vf_idx);
				(void)sxe2_send_mdd_fault_notify_to_vf(adapter, vf_node);
			}

			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		}
	}
}

static void sxe2_vf_mdd_reply_process_v2(struct sxe2_adapter *adapter,
					 struct sxe2_fwc_mdd_resp_v2 *resp)
{
	u32 vf_mdd_tx_event = le32_to_cpu(resp->vf_mdd_tx_event);
	u32 pf_mdd_tx_event = le32_to_cpu(resp->pf_mdd_tx_event);
	u8 vf_mdd_rx_event = resp->vf_mdd_rx_event;
	u8 pf_mdd_rx_event = resp->pf_mdd_rx_event;
	u64 pf_tx_qmap = le64_to_cpu(resp->pf_tx_queues_bitmap);
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	u16 pf_idx = adapter->pf_idx;
	u16 max_txq = adapter->q_ctxt.max_txq_cnt;
	struct sxe2_vf_node *vf_node;
	struct sxe2_queue *txq;
	unsigned int q_idx;
	u8 vf_mdd_type;
	u64 vf_qmap;
	u16 vf_idx;
	u32 i;

	if (pf_mdd_tx_event || sxe2_mdd_rx_event_valid(pf_mdd_rx_event)) {
		if (pf_mdd_tx_event) {
			LOG_DEV_WARN("Malicious Driver Detection Tx event on PF# %d.\n",
				     pf_idx);
			LOG_DEV_WARN("pf mdd event 0x%04x detected.\n",
				     pf_mdd_tx_event);
		}

		if (sxe2_mdd_rx_event_valid(pf_mdd_rx_event)) {
			LOG_DEV_WARN("Malicious Driver Detection Rx event on PF# %d.\n",
				     pf_idx);
			LOG_DEV_WARN("pf mdd rx event 0x%04x detected, enter FAULT state.\n",
				     pf_mdd_rx_event);
			sxe2_dev_state_set(adapter, SXE2_DEVSTATE_FAULT,
					   SXE2_RESET_INVAL);
			sxe2_dev_ctrl_work_schedule(adapter);
			return;
		}
	}

	if (pf_tx_qmap) {
		LOG_WARN_BDF("PF MDD problem queues bitmap: 0x%016llx\n",
			     (unsigned long long)pf_tx_qmap);

		for_each_set_bit(q_idx,
				 (const unsigned long *)&pf_tx_qmap,
				 SXE2_BITS_PER_U64) {
			if (q_idx >= max_txq)
				break;
			txq = sxe2_tx_queue_get(vsi, (u16)q_idx);
			if (txq) {
				netif_tx_stop_queue(netdev_get_tx_queue(vsi->netdev, q_idx));
				(void)sxe2_txq_stop(vsi, txq);
				set_bit(SXE2_TXQ_MDD_DISABLED, &txq->flags);
				LOG_WARN_BDF("PF MDD problem queue %u stop\n", q_idx);
			}
		}
	}

	if (vf_mdd_tx_event || sxe2_mdd_rx_event_valid(vf_mdd_rx_event))
		LOG_DEV_WARN("vf mdd tx event 0x%04x rx event 0x%04x detected.\n",
			     vf_mdd_tx_event, vf_mdd_rx_event);
	else
		return;

	for (i = 0; i < le16_to_cpu(resp->mdd_vf_cnt); i++) {
		vf_idx = le16_to_cpu(resp->mdd_vfs[i].vf_idx);
		vf_qmap = le64_to_cpu(resp->mdd_vfs[i].tx_queues_bitmap);
		vf_mdd_type = resp->mdd_vfs[i].mdd;

		if (sxe2_vf_id_check(adapter, vf_idx))
			continue;

		mutex_lock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		vf_node = sxe2_vf_node_get(adapter, vf_idx);
		if (!vf_node) {
			LOG_ERROR_BDF("vf %d node is null.\n", vf_idx);
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			continue;
		}

		if (sxe2_check_vf_ready_for_cfg(vf_node)) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			continue;
		}

		LOG_DEV_WARN("vf %d mdd tx event 0x%04x rx event 0x%04x mdd\t"
			     "%d detected q bitmap %llu.\n",
			     vf_idx, vf_mdd_tx_event, vf_mdd_rx_event, vf_mdd_type, vf_qmap);

		if (vf_mdd_type & SXE2_MDD_TYPE_TX) {
			LOG_DEV_WARN("Malicious Driver Detection Tx event\t"
				     "on PF# %d VF# %d Mac %pM.\t"
				     "mdd-auto-reset-vfs=%s\n",
				     pf_idx, vf_idx, vf_node->mac_addr.addr,
				     test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF,
					      adapter->flags)
					     ? "on"
					     : "off");
		}

		if (vf_mdd_type & SXE2_MDD_TYPE_RX) {
			LOG_DEV_WARN("Malicious Driver Detection Rx event \t"
				     "on PF# %d VF# %d Mac %pM. \t"
				     "mdd-auto-reset-vfs=%s\n",
				     pf_idx, vf_idx, vf_node->mac_addr.addr,
				     test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF,
					      adapter->flags)
					     ? "on"
					     : "off");
		}

		if (!vf_node->vsi) {
			LOG_WARN_BDF("vf %u vsi is null, continue\n", vf_node->vf_idx);
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
			continue;
		}

		(void)sxe2_send_mdd_notify_to_vf(adapter, vf_node, vf_qmap);
		max_txq = vf_node->vsi->txqs.q_cnt;
		for_each_set_bit(q_idx,
				 (const unsigned long *)&vf_qmap,
				 SXE2_BITS_PER_U64) {
			if (q_idx >= max_txq)
				break;
			txq = sxe2_tx_queue_get(vf_node->vsi, (u16)q_idx);
			if (txq) {
				(void)sxe2_txq_stop(vf_node->vsi, txq);
				set_bit(SXE2_TXQ_MDD_DISABLED, &txq->flags);
				LOG_WARN_BDF("VF %u MDD problem queue %u stop\n", vf_idx, q_idx);
			}
		}

		if (test_bit(SXE2_FLAG_MDD_AUTO_RESET_VF, adapter->flags)) {
			LOG_DEV_WARN("vf #%d detected mdd event reset vf now.\n",
				     vf_idx);
			(void)sxe2_reset_vf(adapter, vf_idx, 0);
		} else if (vf_mdd_type & SXE2_MDD_TYPE_RX) {
			LOG_DEV_WARN("vf %d rx mdd detected, notify VF\t"
				     "enter FAULT state.\n", vf_idx);
			(void)sxe2_send_mdd_fault_notify_to_vf(adapter, vf_node);
		}

		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
	}
}

bool sxe2_get_pf_link_status(struct sxe2_adapter *adapter)
{
	bool link_status;

	u32 val = SXE2_REG_READ(&adapter->hw, SXE2_LINK_STATUS_BASE);

	if (val == SXE2_REG_INVALID_VALUE) {
		link_status = SXE2_LINK_DOWN;
		goto end;
	}

	switch (adapter->port_idx) {
	case SXE2_PORT0_CNT:
		if ((val >> SXE2_LINK_STATUS_PORT0_POS) & SXE2_LINK_STATUS_MASK)
			link_status = SXE2_LINK_UP;
		else
			link_status = SXE2_LINK_DOWN;
		break;
	case SXE2_PORT1_CNT:
		if ((val >> SXE2_LINK_STATUS_PORT1_POS) & SXE2_LINK_STATUS_MASK)
			link_status = SXE2_LINK_UP;
		else
			link_status = SXE2_LINK_DOWN;
		break;
	case SXE2_PORT2_CNT:
		if ((val >> SXE2_LINK_STATUS_PORT2_POS) & SXE2_LINK_STATUS_MASK)
			link_status = SXE2_LINK_UP;
		else
			link_status = SXE2_LINK_DOWN;
		break;
	case SXE2_PORT3_CNT:
		if ((val >> SXE2_LINK_STATUS_PORT3_POS) & SXE2_LINK_STATUS_MASK)
			link_status = SXE2_LINK_UP;
		else
			link_status = SXE2_LINK_DOWN;
		break;
	default:
		link_status = SXE2_LINK_DOWN;
		goto end;
	}

end:
	return link_status;
}

u32 sxe2_get_link_speed(struct sxe2_adapter *adapter)
{
	u32 link_speed, val, reg;

	reg = SXE2_REG_READ(&adapter->hw, SXE2_LINK_SPEED_BASE);
	if (reg == SXE2_REG_INVALID_VALUE) {
		link_speed = SXE2_LINK_SPEED_UNKNOWN;
		goto end;
	}
	switch (adapter->port_idx) {
	case SXE2_PORT0_CNT:
		val = (reg >> SXE2_LINK_SPEED_PORT0_POS) & SXE2_LINK_SPEED_MASK;
		if (val == SXE2_LINK_REG_GET_10G_VALUE)
			link_speed = SXE2_LINK_SPEED_10G;
		else if (val == SXE2_LINK_REG_GET_25G_VALUE)
			link_speed = SXE2_LINK_SPEED_25G;
		else if (val == SXE2_LINK_REG_GET_50G_VALUE)
			link_speed = SXE2_LINK_SPEED_50G;
		else if (val == SXE2_LINK_REG_GET_100G_VALUE)
			link_speed = SXE2_LINK_SPEED_100G;
		else
			link_speed = SXE2_LINK_SPEED_UNKNOWN;

		break;
	case SXE2_PORT1_CNT:
		val = (reg >> SXE2_LINK_SPEED_PORT1_POS) & SXE2_LINK_SPEED_MASK;
		if (val == SXE2_LINK_REG_GET_10G_VALUE)
			link_speed = SXE2_LINK_SPEED_10G;
		else if (val == SXE2_LINK_REG_GET_25G_VALUE)
			link_speed = SXE2_LINK_SPEED_25G;
		else
			link_speed = SXE2_LINK_SPEED_UNKNOWN;

		break;
	case SXE2_PORT2_CNT:
		val = (reg >> SXE2_LINK_SPEED_PORT2_POS) & SXE2_LINK_SPEED_MASK;
		if (val == SXE2_LINK_REG_GET_10G_VALUE)
			link_speed = SXE2_LINK_SPEED_10G;
		else if (val == SXE2_LINK_REG_GET_25G_VALUE)
			link_speed = SXE2_LINK_SPEED_25G;
		else if (val == SXE2_LINK_REG_GET_50G_VALUE)
			link_speed = SXE2_LINK_SPEED_50G;
		else
			link_speed = SXE2_LINK_SPEED_UNKNOWN;

		break;
	case SXE2_PORT3_CNT:
		val = (reg >> SXE2_LINK_SPEED_PORT3_POS) & SXE2_LINK_SPEED_MASK;
		if (val == SXE2_LINK_REG_GET_10G_VALUE)
			link_speed = SXE2_LINK_SPEED_10G;
		else if (val == SXE2_LINK_REG_GET_25G_VALUE)
			link_speed = SXE2_LINK_SPEED_25G;
		else
			link_speed = SXE2_LINK_SPEED_UNKNOWN;

		break;
	default:
		link_speed = SXE2_LINK_SPEED_UNKNOWN;
		goto end;
	}
end:
	return link_speed;
}

static bool sxe2_pf_carrier(struct sxe2_adapter *adapter)
{
	bool link_status;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct net_device *netdev = NULL;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (!vsi || !vsi->netdev) {
		link_status = false;
		goto l_end;
	}

	netdev = vsi->netdev;
	mutex_lock(&adapter->link_ctxt.link_status_lock);
	link_status = sxe2_get_pf_link_status(adapter);
	if (link_status) {
		if (netif_running(netdev) && !netif_carrier_ok(netdev) &&
		    !test_bit(SXE2_VSI_S_DOWN, vsi->state)) {
			netif_carrier_on(netdev);
			netif_tx_start_all_queues(netdev);
			LOG_DEV_INFO("nic link is up\n");
		}
	} else {
		netif_carrier_off(netdev);
		netif_tx_stop_all_queues(netdev);
		LOG_DEV_INFO("nic link is down\n");
	}
	mutex_unlock(&adapter->link_ctxt.link_status_lock);

l_end:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return link_status;
}

STATIC void sxe2_linkchk_notify_vfs(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_node *vf;
	u32 bkt;

	sxe2_for_each_vf(adapter, bkt)
	{
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, bkt));
		vf = sxe2_vf_node_get(adapter, (u16)bkt);
		if (!vf) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, bkt));
			continue;
		}

		if (sxe2_check_vf_ready_for_cfg(vf)) {
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, bkt));
			continue;
		}

		sxe2_notify_vf_link_state(vf);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, bkt));
	}
}

STATIC void sxe2_linkchk_handler(struct sxe2_adapter *adapter)
{
	if (test_and_clear_bit(SXE2_FLAG_LINK_CHECK, adapter->flags)) {
		LOG_INFO_BDF("process link check task.\n");
		(void)sxe2_pf_carrier(adapter);
		(void)sxe2_com_irq_notifier_call_chain(&adapter->com_ctxt,
						       SXE2_COM_EC_LINK_CHG);
		sxe2_linkchk_notify_vfs(adapter);
	}
}

STATIC void sxe2_mdd_work(struct sxe2_adapter *adapter)
{
	u8 *req_buf_v1 = NULL;
	u8 *resp_buf_v1 = NULL;
	u8 *req_buf_v2 = NULL;
	u8 *resp_buf_v2 = NULL;
	struct sxe2_fwc_mdd_req *req_v1;
	struct sxe2_fwc_mdd_resp *resp_v1;
	struct sxe2_fwc_mdd_req_v2 *req_v2;
	struct sxe2_fwc_mdd_resp_v2 *resp_v2;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 req_len_v1, resp_len_v1;
	u32 req_len_v2, resp_len_v2;
	u8 mdd_check = 0;
	bool used_v2 = false;

	if (test_and_clear_bit(SXE2_FLAG_MDD_TX_PENDING, adapter->flags))
		mdd_check |= SXE2_MDD_TYPE_TX;
	if (test_and_clear_bit(SXE2_FLAG_MDD_RX_PENDING, adapter->flags))
		mdd_check |= SXE2_MDD_TYPE_RX;

	if (mdd_check == 0)
		return;

	req_buf_v2 = devm_kzalloc(dev, SXE2_MAX_MDD_REQ_BUF_V2, GFP_KERNEL);
	if (!req_buf_v2)
		goto l_free;

	resp_buf_v2 = devm_kzalloc(dev, SXE2_MAX_MDD_RESP_BUF_V2, GFP_KERNEL);
	if (!resp_buf_v2)
		goto l_free;

	req_buf_v1 = devm_kzalloc(dev, SXE2_MAX_MDD_REQ_BUF, GFP_KERNEL);
	if (!req_buf_v1)
		goto l_free;

	resp_buf_v1 = devm_kzalloc(dev, SXE2_MAX_MDD_RESP_BUF, GFP_KERNEL);
	if (!resp_buf_v1)
		goto l_free;

	mutex_lock(&adapter->vf_ctxt.vfs_lock);
	req_v1 = (struct sxe2_fwc_mdd_req *)req_buf_v1;
	resp_v1 = (struct sxe2_fwc_mdd_resp *)resp_buf_v1;
	req_v2 = (struct sxe2_fwc_mdd_req_v2 *)req_buf_v2;
	resp_v2 = (struct sxe2_fwc_mdd_resp_v2 *)resp_buf_v2;

	req_v1->mdd_check = mdd_check;
	req_v2->mdd_check = mdd_check;

	sxe2_mdd_req_fill(adapter, req_v1);
	sxe2_mdd_req_v2_fill(adapter, req_v2);

	req_len_v1 = (u32)(sizeof(struct sxe2_fwc_mdd_req) +
			    pci_num_vf(adapter->pdev) * sizeof(struct sxe2_mdd_vf_req));
	resp_len_v1 = SXE2_MAX_MDD_RESP_BUF;

	req_len_v2 = (u32)(sizeof(struct sxe2_fwc_mdd_req_v2) +
			    pci_num_vf(adapter->pdev) * sizeof(struct sxe2_mdd_vf_req_v2));
	resp_len_v2 = SXE2_MAX_MDD_RESP_BUF_V2;

	if (sxe2_fwc_vf_mdd_check_compat(adapter,
					 req_buf_v2, req_len_v2,
					 resp_buf_v2, resp_len_v2,
					 req_buf_v1, req_len_v1,
					 resp_buf_v1, resp_len_v1,
					 &used_v2)) {
		LOG_ERROR_BDF("vsi mdd check (compat) failed.\n");
		goto l_unlock;
	}

	if (used_v2)
		sxe2_vf_mdd_reply_process_v2(adapter, resp_v2);
	else
		sxe2_vf_mdd_reply_process(adapter, resp_v1);

l_unlock:
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);

l_free:
	sxe2_hw_event_mdd_irq_switch(&adapter->hw, SXE2_MDD_OICR_MASK, true);

	if (req_buf_v1)
		devm_kfree(dev, req_buf_v1);
	if (resp_buf_v1)
		devm_kfree(dev, resp_buf_v1);
	if (req_buf_v2)
		devm_kfree(dev, req_buf_v2);
	if (resp_buf_v2)
		devm_kfree(dev, resp_buf_v2);
}

STATIC void sxe2_dcbx_agent_status_proc(struct sxe2_adapter *adapter)
{
	s32 ret;

	if (!test_bit(SXE2_FLAG_FW_DCBX_DIS_PENDING, adapter->flags))
		return;

	if (!test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		clear_bit(SXE2_FLAG_FW_DCBX_DIS_PENDING, adapter->flags);
		return;
	}

	rtnl_lock();
	ret = sxe2_dcbx_agent_disable(adapter);
	rtnl_unlock();

	if (ret && test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		LOG_ERROR_BDF("disable fw dcbx agent failed, retry later: %d\n", ret);
		return;
	}

	clear_bit(SXE2_FLAG_FW_DCBX_DIS_PENDING, adapter->flags);
}

STATIC bool sxe2_is_pfc_causing_hung_q(struct sxe2_adapter *adapter,
				       struct sxe2_queue *txq)
{
	bool pfc_cause = false;
	u8 num_tcs = 0, i, tc, up_in_tc = 0;
	struct sxe2_vsi *vsi	      = adapter->vsi_ctxt.main_vsi;
	struct sxe2_dcb_stats *stats  = &adapter->pf_stats.dcb_stats;
	struct sxe2_dcbx_cfg *dcb_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	struct sxe2_pause_stats *hung_stats  = &adapter->txtimeout_ctxt.pause_stats;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	if (!vsi)
		goto l_end;

	sxe2_for_each_tc(i)
		if (vsi->tc.tc_map & BIT(i))
			num_tcs++;

	for (tc = 0; tc < num_tcs - 1; tc++)
		if (sxe2_find_q_in_range(vsi->tc.info[tc].txq_offset,
					 vsi->tc.info[tc + 1].txq_offset,
					 txq->idx_in_vsi))
			break;

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++) {
		if (dcb_cfg->ets.prio_tbl[i] == tc)
			up_in_tc |= BIT(i);
	}

	for (i = 0; i < IEEE_8021Q_MAX_PRIORITIES; i++)
		if (up_in_tc & BIT(i))
			if (stats->curr_pause_stats.prio_xoff_rx[i] >
			    hung_stats->prio_xoff_rx[i])
				pfc_cause = true;

l_end:
	return pfc_cause;
}

STATIC bool sxe2_is_lfc_causing_hung_q(struct sxe2_adapter *adapter,
				       struct sxe2_queue *txq)
{
	bool lfc_cause = false;
	struct sxe2_vsi *vsi	      = adapter->vsi_ctxt.main_vsi;
	struct sxe2_dcb_stats *stats  = &adapter->pf_stats.dcb_stats;
	struct sxe2_pause_stats *hung_stats  = &adapter->txtimeout_ctxt.pause_stats;

	lockdep_assert_held(&adapter->vsi_ctxt.lock);

	if (!vsi)
		goto l_end;

	if (stats->curr_pause_stats.rx_pause > hung_stats->rx_pause)
		lfc_cause = true;

l_end:
	return lfc_cause;
}

STATIC bool sxe2_is_fc_causing_hung_q(struct sxe2_adapter *adapter,
				      struct sxe2_queue *txq)
{
	bool fc_case = false;

	if (adapter->lfc_ctxt.rx_en || adapter->lfc_ctxt.tx_en ||
	    adapter->lfc_ctxt.an == SXE2_LFC_AN_ON)
		fc_case = sxe2_is_lfc_causing_hung_q(adapter, txq);
	else if (adapter->dcb_ctxt.local_dcbx_cfg.pfc.enable)
		fc_case = sxe2_is_pfc_causing_hung_q(adapter, txq);

	return fc_case;
}

STATIC void sxe2_tx_hung_proc(struct sxe2_adapter *adapter)
{
	struct sxe2_txtimeout_ctxt *timeout_ctxt = &adapter->txtimeout_ctxt;
	struct sxe2_vsi *vsi = adapter->vsi_ctxt.main_vsi;
	struct sxe2_queue *txq = NULL;
	struct netdev_queue *ntxq = NULL;

	if (!test_bit(SXE2_FLAG_TX_TIMEOUT, adapter->flags))
		goto l_end;

	if (time_before(jiffies,
			SXE2_TX_TIME_HANDLE_JIFFIES(timeout_ctxt->last_hung_jiffies) +
						    SXE2_NORMAL_TIMER_PERIOD))
		goto l_end;

	mutex_lock(&adapter->vsi_ctxt.lock);

	txq = sxe2_tx_queue_get(vsi, timeout_ctxt->last_hung_txq);
	if (!txq) {
		LOG_DEV_ERR("get txq %u failed.\n", timeout_ctxt->last_hung_txq);
		sxe2_txtimeout_clean(adapter);
		goto l_unlock;
	}

	if (sxe2_is_fc_causing_hung_q(adapter, txq)) {
		LOG_DEV_INFO("fake Tx hang detected on queue %u, \t"
				"timeout caused by FC storm\n",
				timeout_ctxt->last_hung_txq);
		sxe2_txtimeout_clean(adapter);
		goto l_unlock;
	}

	ntxq = sxe2_netdev_txq_get(txq);
	if (ntxq->trans_start != timeout_ctxt->txq_last_trans &&
	    !netif_xmit_stopped(ntxq)) {
		LOG_DEV_INFO("Tx hang detected on queue %u at %llu, \t"
				"auto recovered at %llu\n",
				timeout_ctxt->last_hung_txq, timeout_ctxt->last_hung_jiffies,
				(unsigned long long)ntxq->trans_start);
		sxe2_txtimeout_clean(adapter);
		goto l_unlock;
	}

	sxe2_pf_reset_and_check(adapter);
	LOG_DEV_ERR("Tx hang detected on queue %u at %llu",
		    timeout_ctxt->last_hung_txq, timeout_ctxt->last_hung_jiffies);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	return;
}

void sxe2_work_cb(struct work_struct *work)
{
	struct sxe2_monitor_context *monitor =
			container_of(work, struct sxe2_monitor_context, work);
	struct sxe2_adapter *adapter =
			container_of(monitor, struct sxe2_adapter, monitor_ctxt);
	unsigned long start_time = jiffies;

	sxe2_fwd_del_macvlan_deay(adapter);

#ifdef SXE2_CFG_DEBUG
	if (g_pf_switch_stats)
		sxe2_stats_update_work(adapter);
#else
	sxe2_stats_update_work(adapter);
#endif

	sxe2_l2_fltr_sync(adapter);

	sxe2_mtu_changed_handler(adapter);

	sxe2_aux_aeq_overflow_handler(adapter);

	sxe2_mdd_work(adapter);

	sxe2_linkchk_handler(adapter);

	sxe2_tx_hang_check_subtask(adapter);

	sxe2_lag_proc(adapter);

	if (sxe2_is_safe_mode(adapter))
		goto l_complete;

	sxe2_arfs_filters_sync(adapter);

	sxe2_dcbx_agent_status_proc(adapter);

	sxe2_dcbx_pending_cfg_proc(adapter);

	sxe2_tx_hung_proc(adapter);

l_complete:
	sxe2_monitor_work_complete(adapter);

	if (time_after(jiffies, (start_time + adapter->monitor_ctxt.period)))
		mod_timer(&adapter->monitor_ctxt.timer, jiffies);
}

void sxe2_monitor_work_schedule(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->monitor_ctxt.lock, flags);
	if (!test_bit(SXE2_MONITOR_WORK_DISABLED, &adapter->monitor_ctxt.state) &&
	    !test_and_set_bit(SXE2_MONITOR_WORK_SCHED,
			      &adapter->monitor_ctxt.state)) {
		sxe2_queue_work(adapter, sxe2_workqueue,
				&adapter->monitor_ctxt.work);
	}
	spin_unlock_irqrestore(&adapter->monitor_ctxt.lock, flags);
}

STATIC void sxe2_timer_cb(struct timer_list *timer)
{
	struct sxe2_monitor_context *monitor =
			container_of(timer, struct sxe2_monitor_context, timer);
	struct sxe2_adapter *adapter =
			container_of(monitor, struct sxe2_adapter, monitor_ctxt);

	mod_timer(&adapter->monitor_ctxt.timer,
		  adapter->monitor_ctxt.period + jiffies);

	sxe2_monitor_work_schedule(adapter);
	(void)monitor;
}

void sxe2_monitor_init(struct sxe2_adapter *adapter)
{
	adapter->monitor_ctxt.period = SXE2_NORMAL_TIMER_PERIOD;

	set_bit(SXE2_MONITOR_WORK_DISABLED, &adapter->monitor_ctxt.state);

	INIT_WORK(&adapter->monitor_ctxt.work, sxe2_work_cb);

	timer_setup(&adapter->monitor_ctxt.timer, sxe2_timer_cb, 0);
}

void sxe2_monitor_stop(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->monitor_ctxt.lock, flags);
	set_bit(SXE2_MONITOR_WORK_DISABLED, &adapter->monitor_ctxt.state);
	spin_unlock_irqrestore(&adapter->monitor_ctxt.lock, flags);

	if (adapter->monitor_ctxt.timer.function)
		del_timer_sync(&adapter->monitor_ctxt.timer);
	if (adapter->monitor_ctxt.work.func)
		cancel_work_sync(&adapter->monitor_ctxt.work);

	clear_bit(SXE2_MONITOR_WORK_SCHED, &adapter->monitor_ctxt.state);
}

void sxe2_monitor_start(struct sxe2_adapter *adapter)
{
	set_bit(SXE2_FLAG_LINK_CHECK, adapter->flags);

	clear_bit(SXE2_MONITOR_WORK_DISABLED, &adapter->monitor_ctxt.state);
	sxe2_monitor_work_schedule(adapter);
	mod_timer(&adapter->monitor_ctxt.timer,
		  adapter->monitor_ctxt.period + jiffies);
}

s32 sxe2_monitor_create(void)
{
	s32 ret = 0;

	sxe2_workqueue = alloc_workqueue("%s", 0, 0, SXE2_DRV_NAME);
	if (!sxe2_workqueue) {
		LOG_PR_ERR("failed to create workqueue\n");
		ret = -ENOMEM;
	}

	return ret;
}

void sxe2_monitor_destroy(void)
{
	destroy_workqueue(sxe2_workqueue);
	sxe2_workqueue = NULL;
}
