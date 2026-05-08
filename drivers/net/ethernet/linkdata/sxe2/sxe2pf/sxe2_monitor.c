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

#define SXE2_MAX_MDD_REQ_BUF                                                        \
	(sizeof(struct sxe2_fwc_mdd_req) +                                          \
	 SXE2_VF_NUM * sizeof(struct sxe2_mdd_vf_req))

#define SXE2_MAX_MDD_RESP_BUF                                                       \
	(sizeof(struct sxe2_fwc_mdd_resp) +                                         \
	 SXE2_VF_NUM * sizeof(struct sxe2_mdd_vf_resp))

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

	ret = 0;
	if (!test_bit(SXE2_FLAG_SWITCHDEV_ENABLE, adapter->flags)) {
		rtnl_lock();
		ret = sxe2_vsi_promisc_sync_legacy(vsi);
		rtnl_unlock();
	}

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

		vf->vf_idx = cpu_to_le16(vf_node->vf_idx);

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

	if (mdd_rx_event) {
		LOG_DEV_WARN("Malicious Driver Detection Rx event on PF# %d.\n",
			     pf_idx);
		LOG_DEV_WARN("pf mdd rx event 0x%04x detected.\n", mdd_rx_event);
	}

	mdd_tx_event = le32_to_cpu(resp->vf_mdd_tx_event);
	mdd_rx_event = resp->vf_mdd_rx_event;
	if (mdd_tx_event || mdd_rx_event) {
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
			}

			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, vf_idx));
		}
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
	u8 *req_buf;
	u8 *resp_buf;
	struct sxe2_fwc_mdd_req *req;
	struct sxe2_fwc_mdd_resp *resp;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u32 req_len, resp_len;

	req_buf = devm_kzalloc(dev, SXE2_MAX_MDD_REQ_BUF, GFP_KERNEL);
	if (!req_buf)
		return;

	resp_buf = devm_kzalloc(dev, SXE2_MAX_MDD_RESP_BUF, GFP_KERNEL);
	if (!resp_buf) {
		devm_kfree(dev, req_buf);
		return;
	}

	mutex_lock(&adapter->vf_ctxt.vfs_lock);
	req = (struct sxe2_fwc_mdd_req *)req_buf;
	resp = (struct sxe2_fwc_mdd_resp *)resp_buf;

	if (test_and_clear_bit(SXE2_FLAG_MDD_TX_PENDING, adapter->flags))
		req->mdd_check = SXE2_MDD_TYPE_TX;

	if (test_and_clear_bit(SXE2_FLAG_MDD_RX_PENDING, adapter->flags))
		req->mdd_check = SXE2_MDD_TYPE_RX;

	if (req->mdd_check == 0)
		goto l_free;

	sxe2_mdd_req_fill(adapter, req);
	req_len = (u32)(sizeof(struct sxe2_fwc_mdd_req) +
			pci_num_vf(adapter->pdev) * sizeof(struct sxe2_mdd_vf_req));
	resp_len = SXE2_MAX_MDD_RESP_BUF;

	if (sxe2_fwc_vf_mdd_check(adapter, req, req_len, resp, resp_len)) {
		LOG_ERROR_BDF("vsi mdd check failed.\n");
		goto l_free;
	}

	sxe2_vf_mdd_reply_process(adapter, resp);

l_free:
	mutex_unlock(&adapter->vf_ctxt.vfs_lock);
	devm_kfree(dev, req_buf);
	devm_kfree(dev, resp_buf);
}

STATIC void sxe2_dcbx_agent_status_proc(struct sxe2_adapter *adapter)
{
	if (test_bit(SXE2_FLAG_FW_DCBX_DIS_PENDING, adapter->flags) &&
	    test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags)) {
		rtnl_lock();
		(void)sxe2_dcbx_agent_disable(adapter);
		rtnl_unlock();
		clear_bit(SXE2_FLAG_FW_DCBX_DIS_PENDING, adapter->flags);
	}
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
