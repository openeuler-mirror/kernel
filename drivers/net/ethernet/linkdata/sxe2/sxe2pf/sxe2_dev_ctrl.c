// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_dev_ctrl.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/sched.h>

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_dev_ctrl.h"
#include "sxe2_log.h"
#include "sxe2_hw.h"
#include "sxe2_common.h"
#include "sxe2_mbx_msg.h"
#include "sxe2_mbx_channel.h"
#include "sxe2_netdev.h"
#include "sxe2_macsec.h"
#include "sxe2_ipsec.h"
#include "sxe2_ddp.h"
#include "sxe2_eswitch.h"
#include "sxe2_ethtool.h"
#include "sxe2_lag.h"
#include "sxe2_com_cdev.h"
#include "sxe2_acl.h"

#ifdef SXE2_CFG_DEBUG
extern int switch_heart_check;
#endif

#ifndef secs_to_jiffies
#define secs_to_jiffies(_secs) msecs_to_jiffies((_secs) * 1000)
#endif

#define SXE2_HEARTBEAT_TIMEOUT_SECS (30)

#define SXE2_DEV_CTRL_TIMEOUT_SECS (2)
#define SXE2_DEV_CTRL_TIMER_PERIOD (secs_to_jiffies(SXE2_DEV_CTRL_TIMEOUT_SECS))

#ifndef SXE2_TEST
#define SXE2_WAIT_RESET_DONE_TIMEOUT (100000)
#else
#define SXE2_WAIT_RESET_DONE_TIMEOUT (200)
#endif

#ifndef SXE2_TEST
#define SXE2_WAIT_FW_INIT_TIMEOUT_MS (30000)
#else
#define SXE2_WAIT_FW_INIT_TIMEOUT_MS (200)
#endif

#define SXE2_STOP_DROP_TIMEOUT 1000
#define SXE2_STOP_DROP_DONE_INTERVAL 1
#define SXE2_RESET_WAIT_INTERVAL (5)
#define SXE2_RESET_WAIT_TIMES (200)

struct workqueue_struct *sxe2_dev_ctrl_workqueue;

void sxe2_vf_stop(struct sxe2_vf_node *vf_node)
{
	set_bit(SXE2_VF_STATE_DIS, vf_node->states);
	clear_bit(SXE2_VF_STATE_ACTIVE, vf_node->states);

	sxe2_vf_queues_stop(vf_node);
}

void sxe2_vfs_stop(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_context *vf_ctxt = &adapter->vf_ctxt;
	struct sxe2_vf_node *vf_node;
	u16 idx;

	mutex_lock(&vf_ctxt->vfs_lock);

	if (!test_and_set_bit(SXE2_FLAG_SRIOV_VFS_DISABLED, adapter->flags)) {
		sxe2_eswitch_stop(adapter);

		sxe2_for_each_vf(adapter, idx)
		{
			mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));

			vf_node = sxe2_vf_node_get(adapter, idx);

			sxe2_vf_stop(vf_node);

			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
		}
	}

	mutex_unlock(&vf_ctxt->vfs_lock);

	LOG_DEV_INFO("vf cnt:%u stops done.\n", adapter->vf_ctxt.num_vfs);
}

void sxe2_pf_stop(struct sxe2_adapter *adapter, u16 stop_flag)
{
	LOG_DEBUG_BDF("pf sw process stop start.\n");

	mutex_lock(&adapter->dev_ctrl_ctxt.pf_lock);
	if (test_and_set_bit(SXE2_PF_STOPPED, &adapter->dev_ctrl_ctxt.flag))
		goto l_end;

	if (stop_flag & SXE2_PF_STOP_CANCEL_CMD_QUEUE)
		sxe2_wait_task_cancel_all(adapter);

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_KERNEL)
		sxe2_com_disable(&adapter->com_ctxt);

	sxe2_dcb_set_state(adapter, SXE2_DCB_STATE_RESET, true);
	if (test_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags))
		sxe2_dcbx_agent_event_deinit(adapter);

	sxe2_lldp_agent_event_deinit(adapter);
	sxe2_log_export_deinit(adapter);
	sxe2_monitor_stop(adapter);

	sxe2_lag_stop(adapter);

	sxe2_ptp_stop(adapter);

	(void)sxe2_vsi_disable_all(adapter);

	adapter->pf_stats.stat_prev_loaded = false;
	adapter->pf_stats.dcb_stats.prev_stat_loaded = false;

	sxe2_vfs_stop(adapter);

	sxe2_ipsec_stop(adapter);

	if (stop_flag & SXE2_PF_STOP_RESET_NOTICE_RDMA)
		sxe2_rdma_aux_send_reset_event(adapter);

	sxe2_cmd_channels_disable(adapter);

	sxe2_event_irq_disable(adapter);

l_end:
	LOG_DEBUG_BDF("pf sw process stopped.\n");
	mutex_unlock(&adapter->dev_ctrl_ctxt.pf_lock);
}

STATIC void sxe2_pf_sw_cfg_clear(struct sxe2_adapter *adapter)
{
	sxe2_fnav_enter_reset(adapter, true);
	sxe2_fnav_flow_ctxt_clean(adapter);
	sxe2_arfs_clean(adapter);
	sxe2_rss_ppp_ctxt_clean(&adapter->rss_flow_ctxt);

	sxe2_txsched_tree_clean(adapter);
#ifdef HAVE_MACSEC_SUPPORT
	sxe2_macsec_enter_reset(adapter, true);
#endif
	sxe2_ipsec_sa_clean(adapter);
}

STATIC s32 sxe2_pf_hw_cfg_clear(struct sxe2_adapter *adapter)
{
	return sxe2_fwc_clear_pf_cfg(adapter);
}

STATIC s32 sxe2_pf_cfg_clear(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	sxe2_pf_sw_cfg_clear(adapter);

	ret = sxe2_pf_hw_cfg_clear(adapter);

	return ret;
}

static s32 sxe2_vfs_rebuild(struct sxe2_adapter *adapter)
{
	struct sxe2_vf_context *vf_ctxt = &adapter->vf_ctxt;
	struct sxe2_vf_node *vf_node;
	u16 idx;
	s32 ret = 0;

	mutex_lock(&vf_ctxt->vfs_lock);

	if (test_bit(SXE2_FLAG_SRIOV_VFS_DISABLED, adapter->flags)) {
		if (!adapter->vf_ctxt.num_vfs) {
			LOG_INFO_BDF("no enable vf do nothing.\n");
			goto l_clear_bit;
		}
		sxe2_vfs_repr_decfg(adapter);

		sxe2_for_each_vf(adapter, idx)
		{
			ret = sxe2_wait_vfr_done(adapter, idx);
			if (ret) {
				if (!pci_num_vf(adapter->pdev)) {
					LOG_DEV_ERR("vf:%u wait vfr done fail due\t"
						    "to vf pci dev removed.\n",
						    idx);
					ret = 0;
				}
				goto l_unlock;
			}

			mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
			vf_node = sxe2_vf_node_get(adapter, idx);
			ret = sxe2_vf_clean_and_rebuild(vf_node, false);
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
			if (ret) {
				LOG_DEV_ERR("vf:%u rebuild failed during function\t"
					    "level reset.\n",
					    idx);
				goto l_unlock;
			}
		}

		ret = sxe2_eswitch_rebuild(adapter);
		if (ret) {
			LOG_DEV_ERR("eswitch rebuild failed\n");
			goto l_unlock;
		}

		if (test_bit(SXE2_FLAG_FNAV_ENABLE, adapter->flags) &&
		    adapter->vsi_ctxt.main_vsi) {
			ret = sxe2_fnav_filter_replay(adapter->vsi_ctxt.main_vsi,
						      true);
			if (ret) {
				LOG_DEV_ERR("fnav filter action to vf rebuild\t"
					    "failed\n");
				goto l_unlock;
			}
		}

		sxe2_vfs_active(adapter);
	}

l_clear_bit:
	clear_bit(SXE2_FLAG_SRIOV_VFS_DISABLED, adapter->flags);
	LOG_INFO_BDF("vf cnt:%u rebuild done.\n", pci_num_vf(adapter->pdev));

l_unlock:
	mutex_unlock(&vf_ctxt->vfs_lock);
	return ret;
}

s32 sxe2_lfc_rebuild_set(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_fwc_lfc_info lfc = {0};
	struct sxe2_cmd_params cmd = {0};

	if (adapter->lfc_ctxt.rx_en || adapter->lfc_ctxt.tx_en) {
		lfc.fc_mode = SXE2_FC_MODE_LFC;
		lfc.rx_en = adapter->lfc_ctxt.rx_en;
		lfc.tx_en = adapter->lfc_ctxt.tx_en;
		sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_LINK_FLOW_CONTROL_SET, &lfc,
					  sizeof(lfc), NULL, 0);

		ret = sxe2_cmd_fw_exec(adapter, &cmd);
		if (ret) {
			LOG_DEV_ERR("fc set cmd fail, ret=%d\n", ret);
			goto end;
		}
	}

end:
	return ret;
}

STATIC s32 sxe2_pf_cmd_chnl_reactive(struct sxe2_adapter *adapter)
{
	s32 ret;

	pci_restore_msi_state(adapter->pdev);

	sxe2_event_irq_enable(adapter);

	ret = sxe2_cmd_channels_enable(adapter);
	if (ret)
		goto l_cmd_channels_enable_err;

	return 0;

l_cmd_channels_enable_err:
	sxe2_event_irq_disable(adapter);
	(void)sxe2_corer_check(adapter);
	return ret;
}

STATIC void sxe2_pf_cmd_chnl_deactive(struct sxe2_adapter *adapter)
{
	sxe2_cmd_channels_disable(adapter);
	sxe2_event_irq_disable(adapter);
}

STATIC s32 sxe2_pf_recfg(struct sxe2_adapter *adapter)
{
	s32 ret;
	u32 mtu;
	struct net_device *netdev = adapter->vsi_ctxt.main_vsi->netdev;
	struct sxe2_dcbx_cfg *curr_cfg;

	ret = sxe2_pf_cfg_clear(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_pf_cfg_clear rq failed, ret=%d\n", ret);
		goto l_end;
	}

	sxe2_fw_version_get(adapter);

	sxe2_hw_pf_stats_update(adapter);

	ret = sxe2_ddp_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("ddp pkg process failed, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_caps_get(adapter);
	if (ret) {
		LOG_DEV_ERR("get device and function caps failed, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_txsched_dflt_topo_init(adapter);
	if (ret) {
		LOG_DEV_ERR("txsched init failed, ret=%d\n", ret);
		goto l_end;
	}

	curr_cfg = &adapter->dcb_ctxt.local_dcbx_cfg;
	if (sxe2_is_safe_mode(adapter))
		sxe2_dcb_sw_safe_mode_cfg(adapter);

	ret = sxe2_dcb_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("dcb rebuild failed, ret=%d\n", ret);
		goto l_end;
	}

	if (!(curr_cfg->pfc.enable)) {
		ret = sxe2_lfc_rebuild_set(adapter);
		if (ret)
			LOG_DEV_ERR("lfc rebuild failed, ret=%d\n", ret);
	}

	mtu = netdev->mtu;
	ret = sxe2_set_mtu_cfg(adapter, mtu);
	if (ret)
		LOG_DEV_ERR("rebuild mtu:%d, ret: %d\n", mtu, ret);

l_end:
	return ret;
}

STATIC s32 sxe2_pf_vsi_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_vsi *main_vsi;

	rtnl_lock();
	ret = sxe2_vsi_rebuild_by_type(adapter, SXE2_VSI_T_PF, true);
	if (ret) {
		rtnl_unlock();
		goto l_end;
	}
	rtnl_unlock();

	main_vsi = adapter->vsi_ctxt.main_vsi;
	ret = sxe2_netdev_q_cnt_set(main_vsi->netdev, main_vsi->txqs.q_cnt,
				    main_vsi->rxqs.q_cnt, false);
	if (ret) {
		LOG_DEV_ERR("pf netdev q cnt set failed ret:%d.\n", ret);
		goto l_end;
	}

	ret = sxe2_macvlan_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_macvlan_rebuild failed ret:%d.\n", ret);
		goto l_end;
	}

	ret = sxe2_vsi_enable_by_type(adapter, SXE2_VSI_T_PF);
	if (ret) {
		LOG_DEV_ERR("pf enable failed ret:%d.\n", ret);
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_pf_feature_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret;

	ret = sxe2_dcb_maxrate_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("dcb max tc rate rebuild failed, ret:%d\n", ret);
		goto l_end;
	}

	ret = sxe2_pf_eth_fnav_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("ctrl vsi rebuild failed, ret:%d\n", ret);
		goto l_end;
	}
	sxe2_fnav_enter_reset(adapter, false);

	(void)sxe2_ptp_rebuild(adapter);

	ret = sxe2_rdma_aux_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_rdma_aux_rebuild failed. ret:%d\n", ret);
		goto l_end;
	}

	sxe2_lag_rebuild(adapter);

#ifdef HAVE_MACSEC_SUPPORT
	(void)sxe2_macsec_rebuild(adapter);
#endif

	(void)sxe2_ipsec_rebuild(adapter);

	ret = sxe2_log_export_init(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_log_export_init failed. ret:%d\n", ret);
		goto l_log_export_init_failed;
	}

	ret = sxe2_vfs_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("vfs rebuild failed. ret:%d\n", ret);
		goto l_vfs_rebuild_failed;
	}

	sxe2_dcb_set_state(adapter, SXE2_DCB_STATE_READY, true);

#ifdef HAVE_MACSEC_SUPPORT
	sxe2_macsec_enter_reset(adapter, false);
#endif

	return ret;

l_vfs_rebuild_failed:
	sxe2_log_export_deinit(adapter);
l_log_export_init_failed:
	sxe2_rdma_aux_delete(&adapter->aux_ctxt.cdev_info);

l_end:
	return ret;
}

s32 sxe2_pf_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret;

	mutex_lock(&adapter->dev_ctrl_ctxt.pf_lock);

	LOG_DEBUG_BDF("pf rebuild start.\n");

	if (adapter->dev_ctrl_ctxt.dev_state == SXE2_DEVSTATE_FAULT) {
		LOG_WARN_BDF("sxe2 nic fault.\n");
		ret = -EIO;
		goto l_end;
	}
	ret = sxe2_pf_cmd_chnl_reactive(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_pf_cmd_chnl_reactive failed, ret=%d\n", ret);
		goto l_end;
	}

	ret = sxe2_pf_recfg(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_pf_recfg failed, ret=%d\n", ret);
		goto l_pf_recfg_failed;
	}

	ret = sxe2_pf_vsi_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_pf_vsi_rebuild failed, ret=%d\n", ret);
		goto l_vsi_comm_roll_back;
	}

	if (sxe2_is_safe_mode(adapter))
		goto l_rebuild_safe_mode;

	ret = sxe2_pf_feature_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("sxe2_pf_feature_rebuild failed, ret=%d\n", ret);
		goto l_vsi_comm_roll_back;
	}

l_rebuild_safe_mode:
	if (sxe2_is_safe_mode(adapter))
		(void)sxe2_ipsec_rebuild(adapter);

	sxe2_monitor_start(adapter);

	sxe2_com_enable(&adapter->com_ctxt);

	clear_bit(SXE2_PF_STOPPED, &adapter->dev_ctrl_ctxt.flag);

	goto l_end;

l_vsi_comm_roll_back:
	(void)sxe2_vsi_disable_all(adapter);
	sxe2_txsched_tree_clean(adapter);
l_pf_recfg_failed:
	sxe2_pf_cmd_chnl_deactive(adapter);
	(void)sxe2_corer_check(adapter);
l_end:
	mutex_unlock(&adapter->dev_ctrl_ctxt.pf_lock);
	LOG_DEBUG_BDF("pf rebuild end.\n");

	return ret;
}

void sxe2_dev_state_set(struct sxe2_adapter *adapter,
			enum sxe2_dev_state new_dev_state,
			enum sxe2_reset_type new_reset_type)
{
	enum sxe2_dev_state old_state;
	enum sxe2_reset_type old_reset_type;
	unsigned long flags;

	spin_lock_irqsave(&adapter->dev_ctrl_ctxt.state_lock, flags);

	old_state = adapter->dev_ctrl_ctxt.dev_state;
	old_reset_type = adapter->dev_ctrl_ctxt.reset_type;

	if (old_state == SXE2_DEVSTATE_FAULT)
		goto l_unlock;

	switch (new_dev_state) {
	case SXE2_DEVSTATE_INITIAL:
		if (old_state == SXE2_DEVSTATE_RESETTING &&
		    old_reset_type == SXE2_RESET_CORER) {
			adapter->dev_ctrl_ctxt.dev_state = SXE2_DEVSTATE_INITIAL;
			adapter->dev_ctrl_ctxt.reset_type = SXE2_RESET_INVAL;
		}
		break;
	case SXE2_DEVSTATE_ACCESSIBLE:
		if (old_state == SXE2_DEVSTATE_INITIAL ||
		    old_state == SXE2_DEVSTATE_RUNNING ||
		    (old_state == SXE2_DEVSTATE_RESETTING &&
		     old_reset_type == SXE2_RESET_PFR)) {
			adapter->dev_ctrl_ctxt.dev_state = SXE2_DEVSTATE_ACCESSIBLE;
			adapter->dev_ctrl_ctxt.reset_type = SXE2_RESET_INVAL;
		}
		break;
	case SXE2_DEVSTATE_RUNNING:
		if (old_state == SXE2_DEVSTATE_ACCESSIBLE) {
			adapter->dev_ctrl_ctxt.dev_state = SXE2_DEVSTATE_RUNNING;
			adapter->dev_ctrl_ctxt.reset_type = SXE2_RESET_INVAL;
		}
		break;
	case SXE2_DEVSTATE_ABNORMAL:
		if (new_reset_type == SXE2_RESET_CORER) {
			if (old_state == SXE2_DEVSTATE_ACCESSIBLE ||
			    old_state == SXE2_DEVSTATE_RUNNING ||
			    (old_state == SXE2_DEVSTATE_ABNORMAL &&
			     old_reset_type == SXE2_RESET_PFR) ||
			    (old_state == SXE2_DEVSTATE_RESETTING &&
			     old_reset_type == SXE2_RESET_PFR)) {
				adapter->dev_ctrl_ctxt.dev_state =
						SXE2_DEVSTATE_ABNORMAL;
				adapter->dev_ctrl_ctxt.reset_type = new_reset_type;
			}
		}

		if (new_reset_type == SXE2_RESET_PFR) {
			if (old_state == SXE2_DEVSTATE_ACCESSIBLE ||
			    old_state == SXE2_DEVSTATE_RUNNING) {
				adapter->dev_ctrl_ctxt.dev_state =
						SXE2_DEVSTATE_ABNORMAL;
				adapter->dev_ctrl_ctxt.reset_type = new_reset_type;
			}
		}
		break;
	case SXE2_DEVSTATE_RESETTING:
		if (new_reset_type == SXE2_RESET_CORER) {
			if (old_state == SXE2_DEVSTATE_ACCESSIBLE ||
			    old_state == SXE2_DEVSTATE_RUNNING ||
			    old_state == SXE2_DEVSTATE_ABNORMAL ||
			    (old_state == SXE2_DEVSTATE_RESETTING &&
			     old_reset_type == SXE2_RESET_PFR))
				adapter->dev_ctrl_ctxt.dev_state =
						SXE2_DEVSTATE_RESETTING;
			adapter->dev_ctrl_ctxt.reset_type = new_reset_type;
		}

		if (new_reset_type == SXE2_RESET_PFR) {
			if (old_state == SXE2_DEVSTATE_ABNORMAL &&
			    old_reset_type == SXE2_RESET_PFR) {
				adapter->dev_ctrl_ctxt.dev_state =
						SXE2_DEVSTATE_RESETTING;
				adapter->dev_ctrl_ctxt.reset_type = new_reset_type;
			}
		}
		break;
	case SXE2_DEVSTATE_FAULT:
		adapter->dev_ctrl_ctxt.dev_state = SXE2_DEVSTATE_FAULT;
		break;
	default:
		SXE2_BUG();
		break;
	}

l_unlock:
	spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.state_lock, flags);
	LOG_DEBUG_BDF("device state changes from %d(state)-%d(reset_type) to\t"
		      "%d(state)-%d(reset_type), final state is\t"
		      "%d(state)-%d(reset_type)\n",
		      old_state, old_reset_type, new_dev_state, new_reset_type,
		      adapter->dev_ctrl_ctxt.dev_state,
		      adapter->dev_ctrl_ctxt.reset_type);
}

void sxe2_dev_state_get(struct sxe2_adapter *adapter, enum sxe2_dev_state *state,
			enum sxe2_reset_type *reset_type)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->dev_ctrl_ctxt.state_lock, flags);
	if (state)
		*state = adapter->dev_ctrl_ctxt.dev_state;
	if (reset_type)
		*reset_type = adapter->dev_ctrl_ctxt.reset_type;
	spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.state_lock, flags);
}

STATIC void sxe2_heartbeat_update(struct sxe2_adapter *adapter)
{
	u32 heartbeat_value;

	heartbeat_value = sxe2_hw_heartbeat_get(&adapter->hw);

	adapter->dev_ctrl_ctxt.last_heartbeat_value = heartbeat_value;
	adapter->dev_ctrl_ctxt.last_heartbeat_time = jiffies;
}

s32 sxe2_wait_fw_init(struct sxe2_adapter *adapter)
{
	unsigned long end = jiffies + msecs_to_jiffies(SXE2_WAIT_FW_INIT_TIMEOUT_MS);
	struct sxe2_hw *hw = &adapter->hw;
	u32 fw_state;
	s32 ret = 0;

	do {
		cond_resched();

		fw_state = sxe2_fw_state_get(hw) & SXE2_FW_STATE_MASK;
		if (fw_state == SXE2_FW_STATE_FINISH) {
			LOG_DEBUG_BDF("fw state is finished.\n");
			ret = 0;
			goto out;
		} else if (unlikely(fw_state == SXE2_FW_STATE_ABNORMAL)) {
			LOG_DEV_INFO("fw state is abnormal.\n");
			ret = -EBUSY;
			goto out;
		} else if (unlikely(fw_state == SXE2_FW_STATE_MASK)) {
			LOG_DEV_INFO("device offline.\n");
			ret = -ENODEV;
			goto out;
		}
	} while (!time_after(jiffies, end));

	ret = -ETIMEDOUT;
	LOG_DEV_INFO("wait Fw init timeout.\n");

out:
	LOG_DEBUG_BDF("fw state is 0x%x, ret is:%d.\n", fw_state, ret);
	return ret;
}

s32 sxe2_stop_drop(struct sxe2_adapter *adapter)
{
	u16 timeout = SXE2_STOP_DROP_TIMEOUT;
	struct sxe2_hw *hw = &adapter->hw;
	u16 cnt;

	if (sxe2_hw_stop_drop_done(hw))
		return 0;

	sxe2_hw_stop_drop(hw);

	for (cnt = 0; cnt < timeout; cnt++) {
		msleep(SXE2_STOP_DROP_DONE_INTERVAL);
		if (sxe2_hw_stop_drop_done(hw))
			break;
	}
	if (cnt == timeout) {
		LOG_DEV_ERR("stop PCIe drop timeout.\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static void sxe2_trigger_reset(struct sxe2_adapter *adapter,
			       enum sxe2_reset_type reset_type)
{
	struct sxe2_hw *hw = &adapter->hw;

	switch (reset_type) {
	case SXE2_RESET_PFR:
		adapter->dev_ctrl_ctxt.pfr_cnt++;
		sxe2_hw_trigger_pfr(hw);
		break;
	case SXE2_RESET_CORER:
		{
			if (hw->is_pop_type) {
				sxe2_dev_state_set(adapter, SXE2_DEVSTATE_FAULT,
						   SXE2_RESET_INVAL);
				LOG_INFO_BDF("device is pop mode, can not do core\t"
					     "reset.\n");
			} else {
				sxe2_hw_trigger_corer(hw);
			}
		}
		break;
	default:
		LOG_DEV_ERR("invalid reset type %d\n", reset_type);
		break;
	}
}

static s32 sxe2_reset_done(struct sxe2_adapter *adapter,
			   enum sxe2_reset_type reset_type)
{
	s32 ret = 0;
	struct sxe2_hw *hw = &adapter->hw;

	switch (reset_type) {
	case SXE2_RESET_PFR:
		ret = sxe2_hw_pfr_done(hw);
		break;
	case SXE2_RESET_CORER:
		ret = sxe2_hw_corer_done(hw);
		break;
	default:
		LOG_DEV_ERR("invalid reset type %d\n", reset_type);
		break;
	}

	return ret;
}

s32 sxe2_wait_reset_done(struct sxe2_adapter *adapter,
			 enum sxe2_reset_type reset_type)
{
	s32 ret;
	unsigned long end;
	u32 delay_ms = SXE2_WAIT_RESET_DONE_TIMEOUT;

	end = jiffies + msecs_to_jiffies(delay_ms);
	do {
		cond_resched();

		ret = sxe2_reset_done(adapter, reset_type);
		if (ret) {
			if (unlikely(ret == -EBUSY)) {
				LOG_WARN_BDF("wait pfr done. but core reset\t"
					     "occur.\n");
				goto out;
			} else {
				ret = 0;
				LOG_DEBUG_BDF("reset success. reset type:%u.\n",
					      reset_type);
				goto out;
			}
		}
	} while (!time_after(jiffies, end));

	ret = -ETIMEDOUT;
	LOG_DEV_ERR("wait reset done timeout. reset type:%u\n", reset_type);

out:
	return ret;
}

STATIC void sxe2_initial_proc(struct sxe2_adapter *adapter)
{
	if (sxe2_stop_drop(adapter)) {
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_FAULT, SXE2_RESET_INVAL);
	} else {
		sxe2_heartbeat_update(adapter);
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_ACCESSIBLE,
				   SXE2_RESET_INVAL);
	}
}

STATIC s32 sxe2_accessible_proc(struct sxe2_adapter *adapter)
{
	s32 ret;

	if (adapter->dev_ctrl_ctxt.rebuild_failed) {
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_FAULT, SXE2_RESET_INVAL);
		return 0;
	}

	ret = sxe2_pf_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("pf rebuild failed:%d.\n", ret);
		adapter->dev_ctrl_ctxt.rebuild_failed = true;
		return ret;
	}

	adapter->dev_ctrl_ctxt.rebuild_failed = false;

	sxe2_dev_state_set(adapter, SXE2_DEVSTATE_RUNNING, SXE2_RESET_INVAL);

	return 0;
}

STATIC void sxe2_abnormal_proc(struct sxe2_adapter *adapter,
			       enum sxe2_reset_type reset_type)
{
	adapter->dev_ctrl_ctxt.rebuild_failed = false;

	sxe2_trigger_reset(adapter, reset_type);

	sxe2_dev_state_set(adapter, SXE2_DEVSTATE_RESETTING, reset_type);
}

STATIC s32 sxe2_resetting_proc(struct sxe2_adapter *adapter,
			       enum sxe2_reset_type reset_type)
{
	s32 ret;

	adapter->dev_ctrl_ctxt.rebuild_failed = false;

	(void)sxe2_pf_stop(adapter, SXE2_PF_STOP_CANCEL_CMD_QUEUE |
						    SXE2_PF_STOP_RESET_NOTICE_RDMA);

	ret = sxe2_wait_reset_done(adapter, reset_type);
	if (ret == -ETIMEDOUT) {
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_FAULT, SXE2_RESET_INVAL);
		return ret;
	}

	sxe2_rdma_aux_delete(&adapter->aux_ctxt.cdev_info);

	if (reset_type == SXE2_RESET_CORER)
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_INITIAL, SXE2_RESET_INVAL);
	else if (reset_type == SXE2_RESET_PFR)
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_ACCESSIBLE,
				   SXE2_RESET_INVAL);
	else
		SXE2_BUG();

	return ret;
}

STATIC void sxe2_fault_proc(struct sxe2_adapter *adapter)
{
	u32 val;

	sxe2_pf_stop(adapter, SXE2_PF_STOP_RESET_NOTICE_RDMA);
	del_timer_sync(&adapter->dev_ctrl_ctxt.timer);

	(void)pci_read_config_dword(adapter->pdev, SXE2_PCIE_SYS_READY, &val);
	if (val == SXE2_REG_INVALID_VALUE) {
		LOG_DEV_ERR("configuration space inaccessible. please check the\t"
			    "device.\n");
	} else {
		val = sxe2_read_reg(&adapter->hw, SXE2_PFGEN_CTRL);

		if (val == SXE2_REG_INVALID_VALUE)
			LOG_DEV_ERR("bar0 inaccessible.\n");
	}

	LOG_DEV_ERR("sxe2 nic fault\n");
}

STATIC s32 sxe2_dev_state_proc(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	enum sxe2_dev_state dev_state;
	enum sxe2_reset_type reset_type;

	sxe2_dev_state_get(adapter, &dev_state, &reset_type);

	switch (dev_state) {
	case SXE2_DEVSTATE_INITIAL:
		sxe2_initial_proc(adapter);
		break;
	case SXE2_DEVSTATE_ACCESSIBLE:
		ret = sxe2_accessible_proc(adapter);
		break;
	case SXE2_DEVSTATE_ABNORMAL:
		sxe2_abnormal_proc(adapter, reset_type);
		break;
	case SXE2_DEVSTATE_RESETTING:
		ret = sxe2_resetting_proc(adapter, reset_type);
		break;
	case SXE2_DEVSTATE_RUNNING:
	case SXE2_DEVSTATE_FAULT:
	default:
		LOG_DEV_ERR("Invalid device state %d\n", dev_state);
		ret = -EINVAL;
		SXE2_BUG();
		break;
	}

	return ret;
}

STATIC void sxe2_reset_work(struct sxe2_adapter *adapter)
{
	while (adapter->dev_ctrl_ctxt.dev_state != SXE2_DEVSTATE_RUNNING &&
	       adapter->dev_ctrl_ctxt.dev_state != SXE2_DEVSTATE_FAULT) {
		(void)sxe2_dev_state_proc(adapter);
		cond_resched();
	}
}

STATIC s32 sxe2_fault_work(struct sxe2_adapter *adapter)
{
	enum sxe2_dev_state dev_state;
	enum sxe2_reset_type reset_type;

	sxe2_dev_state_get(adapter, &dev_state, &reset_type);
	(void)reset_type;

	if (dev_state != SXE2_DEVSTATE_FAULT)
		return 0;

	sxe2_fault_proc(adapter);

	return -EFAULT;
}

STATIC s32 sxe2_heartbeat_check(struct sxe2_adapter *adapter)
{
	u32 heartbeat_value;
	unsigned long expired_time = adapter->dev_ctrl_ctxt.last_heartbeat_time +
				     secs_to_jiffies(SXE2_HEARTBEAT_TIMEOUT_SECS);

	if (time_before(jiffies, expired_time))
		return 0;

	heartbeat_value = sxe2_hw_heartbeat_get(&adapter->hw);

	if (heartbeat_value == adapter->dev_ctrl_ctxt.last_heartbeat_value) {
		LOG_DEV_ERR("heartbeat check failed, lasttime: %u ms, nowtime: %u\t"
			    "ms.\n",
			    jiffies_to_msecs(adapter->dev_ctrl_ctxt
							     .last_heartbeat_time),
			    jiffies_to_msecs(jiffies));
		adapter->dev_ctrl_ctxt.last_heartbeat_time = jiffies;
		return -EFAULT;
	}

	sxe2_heartbeat_update(adapter);

	return 0;
}

STATIC void sxe2_heartbeat_work(struct sxe2_adapter *adapter)
{
	enum sxe2_dev_state dev_state;
	enum sxe2_reset_type reset_type;

#ifdef SXE2_CFG_DEBUG
	if (!adapter->dev_ctrl_ctxt.heart_beat_ena)
		return;
#endif

	sxe2_dev_state_get(adapter, &dev_state, &reset_type);

	if (dev_state != SXE2_DEVSTATE_ACCESSIBLE &&
	    dev_state != SXE2_DEVSTATE_RUNNING)
		return;

	if (sxe2_heartbeat_check(adapter))
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_ABNORMAL,
				   SXE2_RESET_CORER);
}

void sxe2_dev_ctrl_work_schedule(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->dev_ctrl_ctxt.wq_lock, flags);
	if (!test_bit(SXE2_DEV_CTRL_WORK_DISABLED,
		      &adapter->dev_ctrl_ctxt.work_state) &&
	    !test_and_set_bit(SXE2_DEV_CTRL_WORK_SCHED,
			      &adapter->dev_ctrl_ctxt.work_state))
		sxe2_queue_work(adapter, sxe2_dev_ctrl_workqueue,
				&adapter->dev_ctrl_ctxt.work);
	spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.wq_lock, flags);
}

STATIC void sxe2_dev_ctrl_work_complete(struct sxe2_adapter *adapter)
{
	BUG_ON(!test_bit(SXE2_DEV_CTRL_WORK_SCHED,
			 &adapter->dev_ctrl_ctxt.work_state));

	/* in order to force CPU ordering */
	smp_mb__before_atomic();
	clear_bit(SXE2_DEV_CTRL_WORK_SCHED, &adapter->dev_ctrl_ctxt.work_state);

	if (test_bit(SXE2_FLAG_VFLR_PENDING, adapter->flags))
		sxe2_dev_ctrl_work_schedule(adapter);
}

STATIC void sxe2_vflr_work(struct sxe2_adapter *adapter)
{
	u16 vf_id_in_dev = 0;
	u16 idx;
	struct sxe2_vf_node *vf_node;

	if (!test_and_clear_bit(SXE2_FLAG_VFLR_PENDING, adapter->flags))
		return;

	sxe2_for_each_vf(adapter, idx)
	{
		vf_id_in_dev = idx + adapter->vf_ctxt.vfid_base;
		if (sxe2_hw_vflr_cause_get(&adapter->hw, vf_id_in_dev)) {
			sxe2_hw_vflr_cause_clear(&adapter->hw, vf_id_in_dev);

			LOG_WARN_BDF("vf:%u vf_id_in_dev:%u vflr checked.\n", idx,
				     vf_id_in_dev);

			mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
			vf_node = sxe2_vf_node_get(adapter, idx);
			if (!vf_node) {
				mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
				continue;
			}

			if (sxe2_check_vf_ready_for_cfg(vf_node)) {
				mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
				continue;
			}
			(void)sxe2_reset_vf(adapter, idx, SXE2_VF_RESET_FLAG_NOTIFY);
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
		}
	}
}

STATIC void sxe2_interrupt_err_print(struct sxe2_adapter *adapter)
{
	u32 print_flag = adapter->dev_ctrl_ctxt.print_flag;

	if (likely(print_flag == 0))
		goto l_out;

	if (print_flag & SXE2_PRINT_CORE_RESET) {
		LOG_DEV_INFO("recv core reset irq cause.\n");
		print_flag &= ~SXE2_PRINT_CORE_RESET;
	}

	if (print_flag & SXE2_PRINT_ECC_ERROR) {
		LOG_ERROR_BDF("multi-bit ecc err occur!\n");
		print_flag &= ~SXE2_PRINT_ECC_ERROR;
	}

	if (print_flag & SXE2_PRINT_REG_CFG_ERR) {
		LOG_WARN_BDF("register config error!\n");
		print_flag &= ~SXE2_PRINT_REG_CFG_ERR;
	}

	if (print_flag & SXE2_PRINT_RAM_CONFLICT) {
		LOG_DEV_WARN("ram read write conflict!\n");
		print_flag &= ~SXE2_PRINT_RAM_CONFLICT;
	}

	adapter->dev_ctrl_ctxt.print_flag = print_flag;
l_out:
	return;
}

STATIC void sxe2_dev_ctrl_work_cb(struct work_struct *work)
{
	struct sxe2_dev_ctrl_context *dev_ctrl_ctxt =
			container_of(work, struct sxe2_dev_ctrl_context, work);
	struct sxe2_adapter *adapter =
			container_of(dev_ctrl_ctxt, struct sxe2_adapter, dev_ctrl_ctxt);

	sxe2_interrupt_err_print(adapter);

	if (sxe2_fault_work(adapter))
		goto l_end;

	sxe2_heartbeat_work(adapter);

	sxe2_reset_work(adapter);

	sxe2_vflr_work(adapter);

l_end:
	sxe2_dev_ctrl_work_complete(adapter);
}

STATIC void sxe2_dev_ctrl_timer_cb(struct timer_list *timer)
{
	struct sxe2_dev_ctrl_context *dev_ctrl =
			container_of(timer, struct sxe2_dev_ctrl_context, timer);
	struct sxe2_adapter *adapter =
			container_of(dev_ctrl, struct sxe2_adapter, dev_ctrl_ctxt);

	(void)dev_ctrl;
	mod_timer(&adapter->dev_ctrl_ctxt.timer,
		  adapter->dev_ctrl_ctxt.period + jiffies);

	sxe2_dev_ctrl_work_schedule(adapter);
}

STATIC void sxe2_dev_ctrl_work_init(struct sxe2_adapter *adapter)
{
	adapter->dev_ctrl_ctxt.period = SXE2_DEV_CTRL_TIMER_PERIOD;

	INIT_WORK(&adapter->dev_ctrl_ctxt.work, sxe2_dev_ctrl_work_cb);

	timer_setup(&adapter->dev_ctrl_ctxt.timer, sxe2_dev_ctrl_timer_cb, 0);
}

void sxe2_dev_ctrl_work_stop(struct sxe2_adapter *adapter)
{
	unsigned long flags;

	spin_lock_irqsave(&adapter->dev_ctrl_ctxt.wq_lock, flags);
	set_bit(SXE2_DEV_CTRL_WORK_DISABLED, &adapter->dev_ctrl_ctxt.work_state);
	spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.wq_lock, flags);

	if (adapter->dev_ctrl_ctxt.timer.function)
		del_timer_sync(&adapter->dev_ctrl_ctxt.timer);

	if (adapter->dev_ctrl_ctxt.work.func)
		cancel_work_sync(&adapter->dev_ctrl_ctxt.work);

	clear_bit(SXE2_DEV_CTRL_WORK_SCHED, &adapter->dev_ctrl_ctxt.work_state);
}

void sxe2_dev_ctrl_work_start(struct sxe2_adapter *adapter)
{
	sxe2_heartbeat_update(adapter);
	clear_bit(SXE2_DEV_CTRL_WORK_DISABLED, &adapter->dev_ctrl_ctxt.work_state);
	sxe2_dev_ctrl_work_schedule(adapter);
	mod_timer(&adapter->dev_ctrl_ctxt.timer,
		  adapter->dev_ctrl_ctxt.period + jiffies);
}

s32 sxe2_dev_ctrl_work_create(void)
{
	sxe2_dev_ctrl_workqueue =
			alloc_workqueue("%s-DEV-CTRL", 0, 0, SXE2_DRV_NAME);
	if (!sxe2_dev_ctrl_workqueue) {
		LOG_PR_ERR("failed to create dev ctrl workqueue\n");
		return -ENOMEM;
	}

	return 0;
}

void sxe2_dev_ctrl_work_destroy(void)
{
	destroy_workqueue(sxe2_dev_ctrl_workqueue);
	sxe2_dev_ctrl_workqueue = NULL;
}

void sxe2_dev_ctrl_init_once(struct sxe2_adapter *adapter)
{
	mutex_init(&adapter->dev_ctrl_ctxt.pf_lock);

	spin_lock_init(&adapter->dev_ctrl_ctxt.state_lock);
	spin_lock_init(&adapter->dev_ctrl_ctxt.wq_lock);
	spin_lock_init(&adapter->dev_ctrl_ctxt.cmd_list_lock);
}

void sxe2_dev_ctrl_deinit_once(struct sxe2_adapter *adapter)
{
	mutex_destroy(&adapter->dev_ctrl_ctxt.pf_lock);
}

void sxe2_dev_ctrl_init(struct sxe2_adapter *adapter)
{
	set_bit(SXE2_DEV_CTRL_WORK_DISABLED, &adapter->dev_ctrl_ctxt.work_state);
	sxe2_dev_ctrl_work_init(adapter);
#ifdef SXE2_CFG_DEBUG
	if (switch_heart_check)
		adapter->dev_ctrl_ctxt.heart_beat_ena = true;
	else
		adapter->dev_ctrl_ctxt.heart_beat_ena = false;
#endif
}

void sxe2_dev_ctrl_deinit(struct sxe2_adapter *adapter)
{
	sxe2_dev_ctrl_work_stop(adapter);
}

s32 sxe2_reset_async(struct sxe2_adapter *adapter, enum sxe2_reset_type reset_type)
{
	if (reset_type == SXE2_RESET_INVAL || reset_type >= SXE2_RESET_MAX)
		return -EINVAL;

	sxe2_dev_state_set(adapter, SXE2_DEVSTATE_ABNORMAL, reset_type);

	sxe2_dev_ctrl_work_schedule(adapter);

	return 0;
}

s32 sxe2_reset_sync(struct sxe2_adapter *adapter, enum sxe2_reset_type reset_type)
{
	if (reset_type == SXE2_RESET_INVAL)
		return -EINVAL;

	sxe2_trigger_reset(adapter, reset_type);

	return sxe2_wait_reset_done(adapter, reset_type);
}

STATIC void sxe2_core_reset_and_check(struct sxe2_adapter *adapter)
{
#ifndef SXE2_TEST
	u32 val;
	u16 wait_times = 0;
	struct sxe2_hw *hw = &adapter->hw;

	if (hw->is_pop_type) {
		LOG_INFO_BDF("device is pop mode, do not need reset proc.\n");
		return;
	}

	sxe2_trigger_reset(adapter, SXE2_RESET_CORER);

	do {
		val = sxe2_read_reg(hw, SXE2_PFGEN_CTRL);
		wait_times++;
		if (val == SXE2_REG_INVALID_VALUE)
			break;

		msleep(SXE2_RESET_WAIT_INTERVAL);
		if (wait_times > SXE2_RESET_WAIT_TIMES) {
			LOG_DEV_WARN("core reset trigger when err occur.\n");
			break;
		}
	} while (1);
#endif
}

s32 sxe2_fwc_clear_pf_cfg(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_PF_CFG_CLEAR, NULL, 0, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("clear pf cfg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

bool sxe2_corer_check(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;
	unsigned long flags;

	if (sxe2_hw_corer_irq_cause_get(hw)) {
		if (in_interrupt())
			adapter->dev_ctrl_ctxt.print_flag |= SXE2_PRINT_CORE_RESET;
		else
			LOG_DEV_INFO("recv core reset irq cause.\n");
		adapter->dev_ctrl_ctxt.corer_cnt++;
		spin_lock_irqsave(&adapter->dev_ctrl_ctxt.cmd_list_lock, flags);
		sxe2_dev_state_set(adapter, SXE2_DEVSTATE_RESETTING,
				   SXE2_RESET_CORER);
		sxe2_wait_task_cancel_all(adapter);
		spin_unlock_irqrestore(&adapter->dev_ctrl_ctxt.cmd_list_lock, flags);
		return true;
	}

	return false;
}

s32 sxe2_wait_vfr_done(struct sxe2_adapter *adapter, u16 vf_id)
{
	s32 ret;
	unsigned long end;
	u32 reset_status;
	unsigned int delay_ms = SXE2_WAIT_RESET_DONE_TIMEOUT;
	struct sxe2_hw *hw = &adapter->hw;

	end = jiffies + msecs_to_jiffies(delay_ms);
	do {
		cond_resched();

		reset_status = sxe2_hw_vfr_done(hw, vf_id);
		if (reset_status == SXE2_REG_UNACCESS) {
			ret = -EBUSY;
			LOG_DEBUG_BDF("core/pfr reset detected.\n");
			goto out;
		} else if (reset_status) {
			ret = 0;
			LOG_DEBUG_BDF("vf:%u reset success.\n", vf_id);
			goto out;
		}
	} while (!time_after(jiffies, end));

	ret = -ETIMEDOUT;

	LOG_DEV_ERR("vf:%u wait vfr done timeout\n", vf_id);

out:
	return ret;
}

s32 sxe2_reset_vf(struct sxe2_adapter *adapter, u16 vf_id, u32 flag)
{
	s32 ret = 0;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_vf_node *vf_node;

	vf_node = sxe2_vf_node_get(adapter, vf_id);
	if (!vf_node) {
		LOG_ERROR_BDF("invalid vf_id:%u reset failed.\n", vf_id);
		ret = -EINVAL;
		return ret;
	}

	if (flag & SXE2_VF_RESET_FLAG_NOTIFY)
		(void)sxe2_vf_reset_notify(adapter, vf_node);

	sxe2_vf_stop(vf_node);

	sxe2_hw_trigger_vfr(hw, vf_id);

	ret = sxe2_wait_vfr_done(adapter, vf_id);
	if (ret)
		goto l_end;

	(void)sxe2_rdma_aux_send_vf_reset_event(adapter, vf_node->vf_idx);

	ret = sxe2_vf_clean_and_rebuild(vf_node, true);
	if (ret) {
		LOG_ERROR_BDF("vf:%u vsi recreate failed during reset.\n",
			      vf_node->vf_idx);
		goto l_end;
	}

	clear_bit(SXE2_VF_STATE_DIS, vf_node->states);

	sxe2_hw_vf_active(hw, vf_node->vf_idx);

	LOG_DEV_INFO("vf:%u reset done.\n", vf_id);

l_end:
	return ret;
}

s32 sxe2_reset_all_vfs(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u16 idx;
	struct sxe2_vf_node *vf_node;

	for (idx = 0; idx < pci_num_vf(adapter->pdev); idx++) {
		mutex_lock(SXE2_VF_NODE_LOCK(adapter, idx));
		vf_node = sxe2_vf_node_get(adapter, idx);
		if (!vf_node) {
			LOG_ERROR_BDF("idx:%u invalid.\n", idx);
			mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
			continue;
		}
		ret = sxe2_reset_vf(adapter, idx, 0);
		if (ret)
			LOG_ERROR_BDF("vf:%u reset failed %d.\n", idx, ret);
		mutex_unlock(SXE2_VF_NODE_LOCK(adapter, idx));
	}

	LOG_DEV_INFO("reset all vfs:%u done.\n", idx);

	return ret;
}

STATIC bool sxe2_is_in_resetting(struct sxe2_adapter *adapter)
{
	bool ret;
	struct sxe2_hw *hw = &adapter->hw;

	ret = sxe2_corer_check(adapter);
	if (ret)
		goto l_end;

	if (!sxe2_hw_pfr_done(hw)) {
		ret = true;
		goto l_end;
	}

	if (!sxe2_hw_corer_done(hw)) {
		ret = true;
		goto l_end;
	}

	if (adapter->dev_ctrl_ctxt.dev_state == SXE2_DEVSTATE_RESETTING) {
		ret = true;
		goto l_end;
	}
	ret = false;

l_end:
	return ret;
}

void sxe2_trigger_and_wait_resetting(struct sxe2_adapter *adapter)
{
	if (sxe2_is_in_resetting(adapter))
		goto l_end;

	sxe2_core_reset_and_check(adapter);

l_end:
	LOG_INFO_BDF("device is in resetting.\n");
}
