// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_lag.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/idr.h>
#include <net/bonding.h>
#include "sxe2_lag.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_tc.h"
#include "sxe2_aux_driver.h"
#include "sxe2_common.h"

#define SXE2_LAG_BOND_MODE_UNSET -1
#define SXE2_LAG_ADAPTER_IDX_UNSET -1

#define SXE2_LAG_PRIMARY_ID 0
#define SXE2_LAG_REDUNDANT_ID 1

static DEFINE_IDA(sxe2_lag_ida);
static struct mutex sxe2_lag_list_mtx;
static struct sxe2_lag_list sxe2_lag_head;

int allow_repeat_sn;
module_param(allow_repeat_sn, int, 0644);

MODULE_PARM_DESC(allow_repeat_sn,
		 "Indicates device can be probed successfully or not when SN is repeat.");

void sxe2_lag_init_once(void)
{
	mutex_init(&sxe2_lag_list_mtx);
	INIT_LIST_HEAD(&sxe2_lag_head.node);
}

void sxe2_lag_deinit_once(void)
{
	mutex_destroy(&sxe2_lag_list_mtx);
}

STATIC void sxe2_lag_list_lock(void)
{
	mutex_lock(&sxe2_lag_list_mtx);
}

STATIC void sxe2_lag_list_unlock(void)
{
	mutex_unlock(&sxe2_lag_list_mtx);
}

STATIC struct sxe2_lag_context *sxe2_lag_alloc(void)
{
	size_t size;
	struct sxe2_lag_context *lag;

	size = sizeof(struct sxe2_lag_context);
	lag = kmalloc(size, GFP_ATOMIC);
	if (!lag) {
		LOG_ERROR("alloc lag ctxt failed.\n");
		goto l_end;
	}

	memset(lag, 0, sizeof(struct sxe2_lag_context));
l_end:

	return lag;
}

STATIC struct sxe2_lag_context *sxe2_lag_context_find(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = NULL;
	struct list_head *tmp;
	struct list_head *n;
	struct sxe2_lag_list *entry = NULL;

	list_for_each_safe(tmp, n, &sxe2_lag_head.node) {
		entry = list_entry(tmp, struct sxe2_lag_list, node);
		if (!entry->lag) {
			LOG_ERROR_BDF("lag is null.\n");
			continue;
		}

		if (memcmp(adapter->serial_num, entry->lag->serial_num,
			   SXE2_SERIAL_NUM_LEN) == 0) {
			lag = entry->lag;
			break;
		}
	}

	LOG_INFO_BDF("find lag %p.\n", lag);

	return lag;
}

static bool sxe2_lag_is_primary(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	bool ret = false;

	if (adapter == lag->adapters[SXE2_LAG_PRIMARY_ID])
		ret = true;

	return ret;
}

bool sxe2_lag_is_bonded(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	return lag->bonded;
}

struct sxe2_adapter *sxe2_lag_role_find(struct sxe2_lag_context *lag,
					int role)
{
	struct sxe2_adapter *adapter = NULL;

	switch (role) {
	case SXE2_LAG_ADAPTER_TYPE_PRIMARY:
		adapter = lag->adapters[SXE2_LAG_PRIMARY_ID];
		break;
	case SXE2_LAG_ADAPTER_TYPE_REDUNDANT:
		adapter = lag->adapters[SXE2_LAG_REDUNDANT_ID];
		break;
	case SXE2_LAG_ADAPTER_TYPE_ACTIVE:
		if (lag->active_id != SXE2_LAG_ADAPTER_IDX_UNSET)
			adapter = lag->adapters[lag->active_id];
		break;
	default:
		break;
	}

	return adapter;
}

static void sxe2_lag_active_set(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	int i;

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		if (adapter == lag->adapters[i]) {
			lag->active_id = i;
			break;
		}
	}

	LOG_INFO("set lag active idx %d.\n", lag->active_id);
}

static void sxe2_lag_info_display(struct sxe2_lag_context *lag)
{
	struct sxe2_adapter *adapter = lag->adapters[0];
	struct sxe2_adapter *bond_adapter = NULL;
	struct sxe2_adapter *active_adapter = NULL;
	struct net_device *netdev;
	struct net_device *upperdev;
	int i;
	const char *name;
	const char *upper;
	const char *primary;
	const char *active;
	const char *mode;

	active_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_ACTIVE);
	if (lag->bond_mode == BOND_MODE_ACTIVEBACKUP)
		mode = "act-back";
	else if (lag->bond_mode == SXE2_LAG_BOND_MODE_UNSET)
		mode = "unset";
	else
		mode = "act-act";

	LOG_INFO_BDF("lag display: current bond state %d mode %s\n", lag->bonded,
		     mode);
	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		bond_adapter = lag->adapters[i];
		netdev = bond_adapter->vsi_ctxt.main_vsi->netdev;
		rcu_read_lock();
		upperdev = netdev_master_upper_dev_get_rcu(netdev);
		upper = upperdev ? netdev_name(upperdev) : "unset";
		rcu_read_unlock();

		name = netdev ? netdev_name(netdev) : "unset";
		primary = sxe2_lag_is_primary(bond_adapter) ? "TRUE" : "FALSE";

		active = "unset";
		if (active_adapter)
			active = active_adapter->pf_idx == bond_adapter->pf_idx ? "TRUE" : "FALSE";

		LOG_INFO_BDF("lag display: %s , upper:%s, primary:%s active %s\n",
			     name, upper, primary, active);
	}
}

static struct sxe2_adapter *sxe2_lag_get_adapter(struct sxe2_lag_context *lag, u8 pf)
{
	return lag->adapters[pf];
}

STATIC void sxe2_lag_move_nodes(struct sxe2_lag_context *lag, u8 oldpf, u8 newpf,
				bool is_aa, u8 pf_idx)
{
	struct sxe2_adapter *adapter = lag->adapters[0];
	struct sxe2_adapter *old_adapter = sxe2_lag_get_adapter(lag, oldpf);
	struct sxe2_adapter *new_adapter = sxe2_lag_get_adapter(lag, newpf);
	struct aux_rdma_qset_params qset = {};
	int ret;
	u16 new_teid;
	u8 user_pri;
	u8 dest = SXE2_RDMA_PF0;

	if (!old_adapter || !new_adapter) {
		LOG_WARN_BDF("Could not locate resources to move node\n");
		return;
	}

	sxe2_for_each_user_prio(user_pri)
	{
		if (is_aa) {
			qset.teid = lag->rdma_qsets[user_pri].teid[pf_idx];
			qset.user_pri = user_pri;
			qset.qset_id = lag->rdma_qsets[user_pri].qset_id[pf_idx];
			memcpy(qset.tc, lag->rdma_qsets[user_pri].tc,
			       sizeof(qset.tc));
			if (!qset.teid)
				continue;

			ret = sxe2_txsched_qset_node_move(old_adapter, new_adapter,
							  &qset, &new_teid,
							  (u8)is_aa);
			if (ret) {
				LOG_ERROR_BDF("Lag aa move nodes error,ret=%d\n", ret);
				return;
			}

			if (newpf == SXE2_LAG_PF0)
				dest = SXE2_RDMA_PF0;
			else if (newpf == SXE2_LAG_PF1)
				dest = SXE2_RDMA_PF1;

			lag->rdma_qsets[user_pri].teid[pf_idx] = new_teid;
			lag->rdma_qsets[user_pri].qset_port[pf_idx] = dest;
		} else {
			qset.teid = lag->rdma_qset[user_pri].teid;
			qset.user_pri = user_pri;
			qset.qset_id = lag->rdma_qset[user_pri].qset_id;
			memcpy(qset.tc, lag->rdma_qset[user_pri].tc,
			       sizeof(qset.tc));
			if (!qset.teid)
				continue;

			ret = sxe2_txsched_qset_node_move(old_adapter, new_adapter,
							  &qset, &new_teid,
							  (u8)is_aa);
			if (ret) {
				LOG_ERROR_BDF("Lag move nodes error,ret=%d\n", ret);
				return;
			}

			if (newpf == SXE2_LAG_PF0)
				dest = SXE2_RDMA_PF0;
			else if (newpf == SXE2_LAG_PF1)
				dest = SXE2_RDMA_PF1;

			lag->rdma_qset[user_pri].teid = new_teid;
			lag->rdma_qset[user_pri].qset_port = dest;
		}
	}
}

STATIC int sxe2_lag_move_node(struct sxe2_lag_context *lag, u8 oldpf, u8 newpf,
			      u8 user_pri, bool is_aa, u8 pf_idx)
{
	struct sxe2_adapter *old_adapter = sxe2_lag_get_adapter(lag, oldpf);
	struct sxe2_adapter *new_adapter = sxe2_lag_get_adapter(lag, newpf);
	struct sxe2_adapter *adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_PRIMARY);
	struct aux_rdma_qset_params qset = {};
	u16 new_teid;
	int ret;
	u8 dest = SXE2_RDMA_PF0;

	if (!old_adapter || !new_adapter) {
		LOG_WARN_BDF("Could not locate resources to move node\n");
		ret = -EINVAL;
		goto l_end;
	}

	if (is_aa) {
		qset.user_pri = user_pri;
		qset.teid = lag->rdma_qsets[user_pri].teid[pf_idx];
		qset.qset_id = lag->rdma_qsets[user_pri].qset_id[pf_idx];
		memcpy(qset.tc, lag->rdma_qsets[user_pri].tc, sizeof(qset.tc));
		ret = sxe2_txsched_qset_node_move(old_adapter, new_adapter, &qset,
						  &new_teid, (u8)is_aa);
		if (ret) {
			LOG_ERROR_BDF("Lag aa move nodes error,ret=%d\n", ret);
			goto l_end;
		}

		if (newpf == SXE2_LAG_PF0)
			dest = SXE2_RDMA_PF0;
		else if (newpf == SXE2_LAG_PF1)
			dest = SXE2_RDMA_PF1;

		lag->rdma_qsets[user_pri].teid[pf_idx] = new_teid;
		lag->rdma_qsets[user_pri].qset_port[pf_idx] = dest;
	} else {
		qset.user_pri = user_pri;
		qset.teid = lag->rdma_qset[user_pri].teid;
		qset.qset_id = lag->rdma_qset[user_pri].qset_id;
		memcpy(qset.tc, lag->rdma_qsets[user_pri].tc, sizeof(qset.tc));
		ret = sxe2_txsched_qset_node_move(old_adapter, new_adapter, &qset,
						  &new_teid, (u8)is_aa);
		if (ret) {
			LOG_ERROR_BDF("Lag move nodes error,ret=%d\n", ret);
			goto l_end;
		}

		if (newpf == SXE2_LAG_PF0)
			dest = SXE2_RDMA_PF0;
		else if (newpf == SXE2_LAG_PF1)
			dest = SXE2_RDMA_PF1;

		lag->rdma_qset[user_pri].teid = new_teid;
		lag->rdma_qset[user_pri].qset_port = dest;
	}

l_end:
	return 0;
}

static void sxe2_lag_unlink(struct sxe2_adapter *adapter)
{
	struct aux_core_dev_info *cdev;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct sxe2_adapter *primary_adapter;

	if (sxe2_lag_is_primary(adapter)) {
		lag->active_id = SXE2_LAG_ADAPTER_IDX_UNSET;
		cdev = &adapter->aux_ctxt.cdev_info;
		if (cdev->adev)
			cdev->rdma_pf_bitmap &= ~SXE2_RDMA_PF0;
	} else {
		primary_adapter = sxe2_lag_role_find(lag,
						     SXE2_LAG_ADAPTER_TYPE_PRIMARY);
		if (primary_adapter) {
			cdev = &primary_adapter->aux_ctxt.cdev_info;
			if (cdev->adev)
				cdev->rdma_pf_bitmap &= ~SXE2_RDMA_PF1;
		}
	}
}

STATIC s32 sxe2_lag_del_prune_list(struct sxe2_adapter *primary_adapter,
				   struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *list_itr = NULL;
	u16 vsi_id;

	vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	list_head = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_VLAN].rule_head;
	list_for_each_entry(list_itr, list_head, list_entry) {
		if (test_bit(vsi_id, list_itr->vsi_list->vsi_map) &&
		    bitmap_weight(list_itr->vsi_list->vsi_map, SXE2_VSI_MAX_CNT) == 1 &&
		    list_itr->vsi_list->need_bond == 1) {
			ret = sxe2_vsi_list_update_bond(adapter,
							list_itr->vsi_list,
							primary_adapter, false);
			if (ret) {
				LOG_ERROR_BDF("Error adding VSI prune list\n");
				return ret;
			}
			list_itr->vsi_list->need_bond = 0;
			return ret;
		}
	}
	ret = -EEXIST;
	return ret;
}

STATIC s32 sxe2_lag_add_prune_list(struct sxe2_adapter *primary_adapter,
				   struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_switch_context *switch_ctxt = &adapter->switch_ctxt;
	struct list_head *list_head;
	struct sxe2_rule_info *list_itr = NULL;
	u16 vsi_id;

	vsi_id = adapter->vsi_ctxt.main_vsi->idx_in_dev;
	list_head = &switch_ctxt->recipe[SXE2_DEFAULT_RECIPE_VLAN].rule_head;
	list_for_each_entry(list_itr, list_head, list_entry) {
		if ((test_bit(vsi_id, list_itr->vsi_list->vsi_map)) &&
		    (bitmap_weight(list_itr->vsi_list->vsi_map, SXE2_VSI_MAX_CNT) ==
		     1)) {
			list_itr->vsi_list->need_bond = 1;
			ret = sxe2_vsi_list_update_bond(adapter, list_itr->vsi_list,
							primary_adapter, true);
			if (ret) {
				LOG_ERROR("Error adding VSI prune list\n");
				return ret;
			}
			return ret;
		}
	}
	ret = -EEXIST;
	return ret;
}

static s32 sxe2_lag_rdma_create_fltr(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	LOG_INFO_BDF("lag create rdma action start.\n");

	if (sxe2_lag_is_primary(adapter)) {
		struct sxe2_fwc_switch_large_action large_act;

		memset(&large_act, 0, sizeof(large_act));
		large_act.action[0].reg.rsv0	 = 0;
		large_act.action[0].reg.rsv1	 = 0;
		large_act.action[0].reg.list	 = 0;
		large_act.action[0].reg.fwd_vsi000 = 0;
		large_act.action[0].reg.rsv2	 = 0;
		large_act.action[0].reg.vsi_list = adapter->vsi_ctxt.main_vsi->idx_in_dev;
		large_act.action[0].reg.valid = 1;
		large_act.idx = 0;

		ret = sxe2_fwc_switch_large_action_cfg(adapter, &large_act,
						       SXE2_CMD_SWITCH_LARGE_ACTION_CFG);
		if (ret) {
			LOG_ERROR_BDF("large action add fail, ret=%d\n", ret);
			return ret;
		}
	} else {
		ret = sxe2_bond_single_rule_setup(adapter, true);
		if (ret) {
			LOG_ERROR_BDF("single action add fail, ret=%d\n", ret);
			return ret;
		}
	}

	LOG_INFO_BDF("lag create rdma action proc complete.\n");

	return ret;
}

static void sxe2_lag_rdma_del_action(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_fwc_switch_large_action lg_act;

	LOG_INFO_BDF("lag del rdma action start.\n");
	if (!sxe2_lag_is_primary(adapter)) {
		LOG_ERROR("adapter is not primary.\n");
		goto l_end;
	}

	memset(&lg_act, 0, sizeof(lg_act));
	lg_act.action[0].reg.rsv0	      = 0;
	lg_act.action[0].reg.rsv1	      = 0;
	lg_act.action[0].reg.list	      = 0;
	lg_act.action[0].reg.fwd_vsi000 = 0;
	lg_act.action[0].reg.rsv2	      = 0;
	lg_act.action[0].reg.vsi_list =
		adapter->vsi_ctxt.main_vsi->idx_in_dev;
	lg_act.action[0].reg.valid = 0;
	lg_act.idx = 0;

	ret = sxe2_fwc_switch_large_action_cfg(adapter, &lg_act,
					       SXE2_CMD_SWITCH_LARGE_ACTION_CFG);
	if (ret)
		LOG_ERROR_BDF("large action del fail, ret=%d\n", ret);

	LOG_INFO_BDF("lag del rdma action process complete.\n");

l_end:
	LOG_INFO_BDF("lag del rdma action end.\n");
}

static void sxe2_lag_reclaim_nodes(struct sxe2_lag_context *lag)
{
	struct sxe2_adapter *primary_adapter;
	struct sxe2_adapter *redundant_adapter;

	primary_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_PRIMARY);
	if (!primary_adapter) {
		LOG_ERROR("find primary failed.\n");
		goto l_end;
	}

	redundant_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_REDUNDANT);
	if (!redundant_adapter) {
		LOG_ERROR("find redundant failed.\n");
		goto l_end;
	}

	sxe2_lag_move_nodes(lag, redundant_adapter->pf_idx, primary_adapter->pf_idx,
			    false, 0);

l_end:
	return;
}

STATIC void sxe2_lag_aa_reclaim_nodes(struct sxe2_lag_context *lag,
				      struct aux_core_dev_info *cdev)
{
	sxe2_lag_move_nodes(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, true, SXE2_LAG_PF1);

	sxe2_lag_move_nodes(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, true, SXE2_LAG_PF0);
}

void sxe2_lag_aa_reclaim_node(struct sxe2_lag_context *lag,
			      struct aux_core_dev_info *cdev, u8 user_pri)
{
	(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, user_pri, true,
				 SXE2_LAG_PF1);

	(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, user_pri, true,
				 SXE2_LAG_PF0);
}

void sxe2_lag_ab_reclaim_node(struct sxe2_lag_context *lag,
			      struct aux_core_dev_info *cdev, u8 user_pri)
{
	(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, user_pri, false,
				 SXE2_LAG_PF1);
}

static bool sxe2_lag_monitor_act_back(struct sxe2_lag_context *lag)
{
	bool send = false;
	struct sxe2_adapter *adapter = lag->adapters[0];
	struct sxe2_adapter *primary_adapter;
	struct sxe2_adapter *redundant_adapter;
	struct sxe2_adapter *active_adapter;
	struct aux_core_dev_info *cdev = NULL;
	struct sxe2_lag_dev_info *info = NULL;
	u8 primary_pf = SXE2_RDMA_INVALID_PF;
	u8 redundant_pf = SXE2_RDMA_INVALID_PF;
	u8 active_pf = SXE2_RDMA_INVALID_PF;
	u8 old_pf = SXE2_RDMA_INVALID_PF;
	s32 i;

	LOG_INFO_BDF("lag mode act-back proc start.\n");
	primary_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_PRIMARY);
	redundant_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_REDUNDANT);
	cdev = &primary_adapter->aux_ctxt.cdev_info;

	primary_pf = primary_adapter->pf_idx;
	redundant_pf = redundant_adapter->pf_idx;

	if (cdev->rdma_pf_bitmap == SXE2_RDMA_INVALID_PF) {
		cdev->rdma_pf_bitmap = SXE2_RDMA_BOTH_PF;
		LOG_INFO_BDF("lag update cdev rdma pf_bitmap 0x3.\n");
	}

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		info = &lag->lag_wk.info[i];
		if (info->slave_state == BOND_STATE_ACTIVE)
			active_pf = lag->adapters[i]->pf_idx;
	}

	if (active_pf == SXE2_RDMA_INVALID_PF) {
		LOG_INFO_BDF("lag mode act-back: not found active func.\n");
		goto l_end;
	}

	active_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_ACTIVE);
	if (active_adapter && active_pf == active_adapter->pf_idx) {
		LOG_INFO_BDF("lag mode act-back: active pf already set.\n");
		goto l_end;
	}

	if (primary_pf == active_pf) {
		cdev->rdma_pf_bitmap |= SXE2_RDMA_PF0;
		cdev->rdma_pf_bitmap &= ~SXE2_RDMA_PF1;
		sxe2_lag_active_set(primary_adapter);
		old_pf = redundant_pf;

	} else {
		cdev->rdma_pf_bitmap |= SXE2_RDMA_PF1;
		cdev->rdma_pf_bitmap &= ~SXE2_RDMA_PF0;
		sxe2_lag_active_set(redundant_adapter);
		old_pf = primary_pf;
	}

	if (lag->lag_wk.event == SXE2_LAG_EVENT_BONDINFO) {
		sxe2_lag_move_nodes(lag, old_pf, active_pf, false, 0);
		send = true;
	}
	LOG_INFO_BDF("lag after send failover bitmap:%d\n", cdev->rdma_pf_bitmap);

l_end:

	LOG_INFO_BDF("lag mode act-back proc end.\n");
	return send;
}

void sxe2_lag_aa_failover(struct sxe2_lag_context *lag,
			  struct aux_core_dev_info *cdev, u8 dest)
{
	struct aux_rdma_multi_qset_params *qsets;
	u8 not_all = 0;
	u8 i;

	LOG_DEBUG("lag aa failover proc start.\n");

	if (!(cdev->rdma_pf_bitmap & dest))
		goto l_end;

	not_all = cdev->rdma_pf_bitmap ^ SXE2_RDMA_BOTH_PF;

	sxe2_for_each_user_prio(i)
	{
		qsets = lag->rdma_qsets;

		if (dest == SXE2_RDMA_PF0) {
			if (qsets[i].teid[SXE2_LAG_PF0] &&
			    qsets[i].qset_port[SXE2_LAG_PF0] != dest) {
				(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1,
							 SXE2_LAG_PF0, i, true,
							 SXE2_LAG_PF0);
				qsets[i].qset_port[SXE2_LAG_PF0] = dest;
			}

			if (not_all && qsets[i].teid[SXE2_LAG_PF1] &&
			    qsets[i].qset_port[SXE2_LAG_PF1] != dest) {
				(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1,
							 SXE2_LAG_PF0, i, true,
							 SXE2_LAG_PF1);
				qsets[i].qset_port[SXE2_LAG_PF1] = dest;
			}
		} else {
			if (qsets[i].teid[SXE2_LAG_PF1] &&
			    qsets[i].qset_port[SXE2_LAG_PF1] != dest) {
				(void)sxe2_lag_move_node(lag, SXE2_LAG_PF0,
							 SXE2_LAG_PF1, i, true,
							 SXE2_LAG_PF1);
				qsets[i].qset_port[SXE2_LAG_PF1] = dest;
			}

			if (not_all && qsets[i].teid[SXE2_LAG_PF0] &&
			    qsets[i].qset_port[SXE2_LAG_PF0] != dest) {
				(void)sxe2_lag_move_node(lag, SXE2_LAG_PF0,
							 SXE2_LAG_PF1, i, true,
							 SXE2_LAG_PF0);
				qsets[i].qset_port[SXE2_LAG_PF0] = dest;
			}
		}
	}

	LOG_INFO("lag after send failover bitmap:%d\n", cdev->rdma_pf_bitmap);

l_end:
	LOG_DEBUG("lag aa failover proc end.\n");
}

static u8 sxe2_lag_get_move_dest(u8 old_st, u8 new_st)
{
	u8 dest = SXE2_RDMA_INVALID_PF;

	if ((old_st & BIT(0)) != (new_st & BIT(0))) {
		if (new_st & BIT(0))
			dest = SXE2_RDMA_PF0;
		else
			dest = SXE2_RDMA_PF1;
	} else if ((old_st & BIT(1)) != (new_st & BIT(1))) {
		if (new_st & BIT(1))
			dest = SXE2_RDMA_PF1;
		else
			dest = SXE2_RDMA_PF0;
	}

	return dest;
}

static bool sxe2_lag_monitor_act_act(struct sxe2_lag_context *lag)
{
	bool send = false;
	struct sxe2_adapter *adapter = lag->adapters[0];
	struct sxe2_adapter *primary_adapter;
	struct aux_core_dev_info *cdev = NULL;
	struct sxe2_lag_dev_info *info = NULL;
	u8 primary_pf = SXE2_RDMA_INVALID_PF;
	u8 dest = SXE2_RDMA_INVALID_PF;
	u8 pf_bitmap = 0;
	s32 i;

	LOG_INFO_BDF("lag mode act-act: proc start.\n");

	primary_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_PRIMARY);
	primary_pf = primary_adapter->pf_idx;
	cdev = &primary_adapter->aux_ctxt.cdev_info;

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		info = &lag->lag_wk.info[i];
		if (info->slave_link == BOND_LINK_UP) {
			if (primary_pf == lag->adapters[i]->pf_idx) {
				pf_bitmap |= SXE2_RDMA_PF0;
				LOG_INFO_BDF("lag mode act-act: prim change to active.\n");
			} else {
				pf_bitmap |= SXE2_RDMA_PF1;
				LOG_INFO_BDF("lag mode act-act: redundant change to active.\n");
			}
		} else {
			if (primary_pf == lag->adapters[i]->pf_idx) {
				pf_bitmap &= ~SXE2_RDMA_PF0;
				LOG_INFO_BDF("lag mode act-act: prim change to down.\n");
			} else {
				pf_bitmap &= ~SXE2_RDMA_PF1;
				LOG_INFO_BDF("lag mode act-act: redundant change to down.\n");
			}
		}
	}

	dest = sxe2_lag_get_move_dest(cdev->rdma_pf_bitmap, pf_bitmap);
	if (dest == SXE2_RDMA_INVALID_PF) {
		LOG_WARN("lag get node move dest failed, old st %d new st %d.\n",
			 cdev->rdma_pf_bitmap, pf_bitmap);
		goto l_end;
	}

	cdev->rdma_pf_bitmap = pf_bitmap;

	if (lag->lag_wk.event == SXE2_LAG_EVENT_BONDINFO) {
		sxe2_lag_aa_failover(lag, cdev, dest);
		send = true;
	}

	LOG_INFO_BDF("lag mode act-act: primary %d redundant %d proc end.\n",
		     SXE2_LAG_PF0, SXE2_LAG_PF1);
l_end:
	return send;
}

static bool sxe2_lag_is_configurable(struct sxe2_adapter *adapter)
{
	bool ret = true;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	if (lag->state[SXE2_LAG_PF0] != SXE2_LAG_STATE_READY ||
	    lag->state[SXE2_LAG_PF1] != SXE2_LAG_STATE_READY)
		ret = false;

	LOG_DEBUG_BDF("pf state available(%d) for config lag.\n", ret);

	return ret;
}

static void sxe2_lag_del_devs(struct sxe2_lag_context *lag)
{
	struct sxe2_adapter *adapter = lag->adapters[0];
	struct sxe2_adapter *primary_adapter;
	struct sxe2_adapter *redundant_adapter;
	struct aux_core_dev_info *cdev_info;

	LOG_DEBUG_BDF("lag pf %d in bond, need del rdma aux dev.\n",
		      adapter->pf_idx);

	primary_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_PRIMARY);
	cdev_info = &primary_adapter->aux_ctxt.cdev_info;
	redundant_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_REDUNDANT);

	if (cdev_info->bond_mode == SXE2_LAG_MODE_ACTIVE_ACTIVE)
		sxe2_lag_aa_reclaim_nodes(lag, cdev_info);
	else
		sxe2_lag_reclaim_nodes(lag);

	(void)sxe2_lag_del_prune_list(primary_adapter, redundant_adapter);
	(void)sxe2_bond_single_rule_setup(redundant_adapter, false);
	sxe2_lag_unlink(redundant_adapter);

	sxe2_lag_rdma_del_action(primary_adapter);
	sxe2_lag_unlink(primary_adapter);

	if (lag->bond_id != -1) {
		ida_simple_remove(&sxe2_lag_ida, lag->bond_id);
		lag->bond_id = -1;
	}
}

static void sxe2_lag_add_devs(struct sxe2_lag_context *lag)
{
	struct sxe2_adapter *adapter = lag->adapters[0];
	struct sxe2_lag_work *work = &lag->lag_wk;
	struct sxe2_adapter *primary_adapter;
	struct sxe2_adapter *redundant_adapter;
	struct aux_core_dev_info *cdev_info;

	LOG_DEBUG_BDF("lag enter bond mode %d.\n", work->bond_mode);

	primary_adapter = lag->adapters[SXE2_LAG_PRIMARY_ID];
	lag->bond_id = ida_alloc(&sxe2_lag_ida, GFP_KERNEL);
	lag->bond_mode = work->bond_mode;

	sxe2_lag_active_set(primary_adapter);
	(void)sxe2_lag_rdma_create_fltr(primary_adapter);

	redundant_adapter = lag->adapters[SXE2_LAG_REDUNDANT_ID];
	(void)sxe2_lag_rdma_create_fltr(redundant_adapter);
	(void)sxe2_lag_add_prune_list(primary_adapter, redundant_adapter);

	cdev_info = &primary_adapter->aux_ctxt.cdev_info;
	if (lag->bond_mode == BOND_MODE_ACTIVEBACKUP) {
		cdev_info->bond_mode = SXE2_LAG_MODE_ACTIVE_BACKUP;
		(void)sxe2_lag_monitor_act_back(lag);
	} else {
		cdev_info->bond_mode = SXE2_LAG_MODE_ACTIVE_ACTIVE;
		(void)sxe2_lag_monitor_act_act(lag);
	}
}

STATIC void sxe2_lag_aa_alloced_node_move_original(struct sxe2_lag_context *lag,
						   u8 dest, u8 user_pri)
{
	(void)sxe2_lag_move_node(lag, SXE2_LAG_PF0, SXE2_LAG_PF1, user_pri, true,
				 SXE2_LAG_PF1);
}

STATIC void sxe2_lag_aa_alloced_move_node(struct sxe2_lag_context *lag, u8 dest,
					  u8 user_pri)
{
	if (dest == SXE2_RDMA_PF0)
		(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, user_pri,
					 true, SXE2_LAG_PF1);
	else if (dest == SXE2_RDMA_PF1)
		(void)sxe2_lag_move_node(lag, SXE2_LAG_PF0, SXE2_LAG_PF1, user_pri,
					 true, SXE2_LAG_PF0);
}

STATIC void sxe2_lag_ab_alloced_move_node(struct sxe2_lag_context *lag,
					  u8 dest, u8 user_pri)
{
	if (dest == SXE2_LAG_PF0)
		(void)sxe2_lag_move_node(lag, SXE2_LAG_PF1, SXE2_LAG_PF0, user_pri,
					 false, SXE2_LAG_PF1);
	else if (dest == SXE2_LAG_PF1)
		(void)sxe2_lag_move_node(lag, SXE2_LAG_PF0, SXE2_LAG_PF1, user_pri,
					 false, SXE2_LAG_PF0);
}

void sxe2_lag_alloced_node_move(struct aux_core_dev_info *cdev_info, u8 user_pri,
				bool is_aa)
{
	struct sxe2_adapter *adapter = cdev_info->adapter;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	u8 dest;
	u8 dflt_bitmap = SXE2_RDMA_BOTH_PF;
	u8 active_pf = SXE2_RDMA_INVALID_PF;

	if (is_aa) {
		sxe2_lag_aa_alloced_node_move_original(lag, SXE2_RDMA_PF1, user_pri);
		dest = sxe2_lag_get_move_dest(dflt_bitmap,
					      cdev_info->rdma_pf_bitmap);

		if (cdev_info->rdma_pf_bitmap == SXE2_RDMA_INVALID_PF)
			cdev_info->rdma_pf_bitmap = SXE2_RDMA_BOTH_PF;

		if (dest != SXE2_RDMA_INVALID_PF) {
			sxe2_lag_aa_alloced_move_node(lag, dest, user_pri);
			LOG_INFO("lag mode act-act: init st %d cdev st %d.\n",
				 dflt_bitmap, cdev_info->rdma_pf_bitmap);
		} else {
			LOG_INFO_BDF("lag mode act-act: no need move nodes.\n");
		}

	} else {
		if (lag->lag_wk.info[0].slave_state == BOND_STATE_ACTIVE)
			active_pf = lag->adapters[0]->pf_idx;
		else if (lag->lag_wk.info[1].slave_state == BOND_STATE_ACTIVE)
			active_pf = lag->adapters[1]->pf_idx;

		if (adapter->pf_idx == active_pf ||
		    active_pf == SXE2_RDMA_INVALID_PF) {
			LOG_INFO_BDF("lag mode act-back: no need move nodes.\n");
		} else {
			sxe2_lag_ab_alloced_move_node(lag, active_pf, user_pri);
			LOG_INFO_BDF("lag mode act-back: move nodes from %d to %d.\n",
				     adapter->pf_idx, active_pf);
		}
	}
}

static s32 sxe2_lag_changeupper_proc(struct sxe2_lag_work *work)
{
	s32 ret = 0;
	struct sxe2_lag_context *lag = work->lag;
	struct sxe2_adapter *adapter = NULL;
	struct sxe2_adapter *primary_adapter = NULL;
	struct sxe2_adapter *tmp_adapter = NULL;
	struct sxe2_adapter *bonded_adapters[SXE2_MAX_BOND_DEV_NUM] = {};
	struct aux_core_dev_info *cdev_info = NULL;
	s32 i;
	bool bonded;

	mutex_lock(&lag->lock);
	adapter = lag->adapters[0];

	LOG_INFO_BDF("lag changeupper_event_proc start.\n");

	if (!test_and_clear_bit(SXE2_LAG_FLAGS_WK_PENDING, &lag->flags)) {
		LOG_ERROR_BDF("lag: no work bit set.\n");
		mutex_unlock(&lag->lock);
		goto l_end;
	}

	set_bit(SXE2_LAG_FLAGS_WK_PROCESS, &lag->flags);

	bonded = lag->lag_wk.is_bonded;
	lag->bonded = bonded;
	if (bonded)
		sxe2_lag_add_devs(lag);
	else
		sxe2_lag_del_devs(lag);

	sxe2_lag_info_display(lag);

	work->state = SXE2_LAG_WK_ST_UNSET;
	work->event = SXE2_LAG_EVENT_UNSET;

	primary_adapter = sxe2_lag_role_find(lag, SXE2_LAG_ADAPTER_TYPE_PRIMARY);
	memcpy(bonded_adapters, lag->adapters,
	       sizeof(struct sxe2_adapter *) * SXE2_MAX_BOND_DEV_NUM);

	mutex_unlock(&lag->lock);

	if (bonded) {
		for (i = SXE2_MAX_BOND_DEV_NUM; i > 0; i--) {
			tmp_adapter = bonded_adapters[i - 1];
			cdev_info = &tmp_adapter->aux_ctxt.cdev_info;
			sxe2_rdma_aux_delete(cdev_info);
		}

		(void)sxe2_rdma_aux_add(primary_adapter);
	} else {
		cdev_info = &primary_adapter->aux_ctxt.cdev_info;
		sxe2_rdma_aux_delete(cdev_info);

		cdev_info->bond_mode = SXE2_LAG_MODE_NONE;
		for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
			tmp_adapter = bonded_adapters[i];
			(void)sxe2_rdma_aux_add(tmp_adapter);
		}
	}

l_end:
	mutex_lock(&lag->lock);
	clear_bit(SXE2_LAG_FLAGS_WK_PROCESS, &lag->flags);
	mutex_unlock(&lag->lock);
	LOG_INFO_BDF("lag changeupper_event_proc end.\n");

	return ret;
}

static s32 sxe2_lag_bondinfo_proc(struct sxe2_lag_work *work)
{
	s32 ret = 0;
	bool send = false;
	struct sxe2_lag_context *lag = work->lag;
	struct sxe2_adapter *adapter;
	unsigned int event;

	mutex_lock(&lag->lock);
	adapter = lag->adapters[0];

	LOG_INFO_BDF("lag bondinfo_event_proc start.\n");

	if (!test_and_clear_bit(SXE2_LAG_FLAGS_WK_PENDING, &lag->flags)) {
		LOG_ERROR_BDF("lag: no work bit set.\n");
		mutex_unlock(&lag->lock);
		goto l_end;
	}

	set_bit(SXE2_LAG_FLAGS_WK_PROCESS, &lag->flags);

	lag->bond_mode = work->bond_mode;
	if (lag->bond_mode == BOND_MODE_ACTIVEBACKUP)
		send = sxe2_lag_monitor_act_back(lag);
	else
		send = sxe2_lag_monitor_act_act(lag);

	sxe2_lag_info_display(lag);

	event = lag->lag_wk.event;
	work->state = SXE2_LAG_WK_ST_DONE;
	work->event = SXE2_LAG_EVENT_UNSET;

	mutex_unlock(&lag->lock);

	if (event == SXE2_LAG_EVENT_BONDINFO && send)
		(void)sxe2_rdma_aux_send_failover_event(adapter);

l_end:
	mutex_lock(&lag->lock);
	clear_bit(SXE2_LAG_FLAGS_WK_PROCESS, &lag->flags);
	mutex_unlock(&lag->lock);
	LOG_INFO_BDF("lag bondinfo_event_proc end.\n");

	return ret;
}

static void sxe2_lag_work_cb(struct work_struct *work)
{
	struct sxe2_lag_work *lag_work;
	s32 ret = 0;

	lag_work = container_of(work, struct sxe2_lag_work, task);
	LOG_INFO("lag work process event %d.\n", lag_work->event);

	if (lag_work->event == SXE2_LAG_EVENT_CHANGEUPPER)
		ret = sxe2_lag_changeupper_proc(lag_work);
	else if (lag_work->event == SXE2_LAG_EVENT_BONDINFO)
		ret = sxe2_lag_bondinfo_proc(lag_work);

	if (ret)
		LOG_WARN("lag work process failed, ret:%d.\n", ret);
}

STATIC int sxe2_lag_netdev_idx_get(struct sxe2_lag_context *lag,
				   struct net_device *dev)
{
	int i;
	int idx = -1;
	struct sxe2_adapter *adapter;

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		adapter = lag->adapters[i];
		if (adapter && adapter->vsi_ctxt.main_vsi->netdev == dev) {
			idx = i;
			LOG_DEBUG("find pf %d in bond.\n", adapter->pf_idx);
			break;
		}
	}

	return idx;
}

STATIC int
sxe2_lag_changeupper_event_fill(struct sxe2_adapter *adapter,
				struct netdev_notifier_changeupper_info *info)
{
	int changed = 0;
	struct net_device *upper = info->upper_dev;
	struct net_device *ndev_tmp;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct slave *slave;
	bool is_bonded;
	bool is_in_lag;
	bool mode_supported;
	int bond_status = 0;
	int num_slaves = 0;
	int bond_mode = -1;
	int idx = 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
		idx = sxe2_lag_netdev_idx_get(lag, ndev_tmp);
		if (idx >= 0) {
			slave = bond_slave_get_rcu(ndev_tmp);
			if (slave)
				bond_mode = BOND_MODE(slave->bond);
			bond_status |= (1 << idx);
		}

		num_slaves++;
	}
	rcu_read_unlock();

	if (!(bond_status & 0x3))
		goto l_end;

	is_in_lag = num_slaves == SXE2_MAX_BOND_DEV_NUM && bond_status == 0x3;

	if (bond_mode == BOND_MODE_ACTIVEBACKUP || bond_mode == BOND_MODE_XOR ||
	    bond_mode == BOND_MODE_8023AD) {
		lag->lag_wk.bond_mode = bond_mode;
		mode_supported = true;
		LOG_INFO_BDF("bond mode %d.\n", bond_mode);
	} else {
		mode_supported = false;
		LOG_ERROR_BDF("unsupport bond mode %d.\n", bond_mode);
	}

	is_bonded = is_in_lag && mode_supported;
	if (lag->lag_wk.is_bonded != is_bonded) {
		lag->lag_wk.is_bonded = is_bonded;
		changed = 1;
	}

l_end:
	if (changed) {
		lag->lag_wk.event = SXE2_LAG_EVENT_CHANGEUPPER;
		lag->lag_wk.state = SXE2_LAG_WK_ST_WAIT_PROC;
	}

	LOG_INFO_BDF("changeupper syn proc done: changed %d\n", changed);
	return changed;
}

static int sxe2_lag_bondinfo_event_fill(struct sxe2_adapter *adapter,
					struct netdev_notifier_bonding_info *info)
{
	int changed = 0;
	struct net_device *event_netdev = info->info.dev;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct sxe2_lag_dev_info *linfo = NULL;
	struct sxe2_lag_dev_info event_info = {};
	int idx = 0;

	idx = sxe2_lag_netdev_idx_get(lag, event_netdev);
	if (idx < 0)
		goto l_end;

	event_info.slave_state = info->bonding_info.slave.state;
	event_info.slave_link = info->bonding_info.slave.link;

	lag->lag_wk.bond_mode = info->bonding_info.master.bond_mode;
	linfo = &lag->lag_wk.info[idx];

	if (memcmp(&event_info, linfo, sizeof(struct sxe2_lag_dev_info) == 0))
		goto l_end;

	linfo->slave_state = info->bonding_info.slave.state;
	linfo->slave_link = info->bonding_info.slave.link;

	if (!lag->bonded)
		goto l_end;

	changed = 1;

l_end:
	if (changed && lag->lag_wk.state != SXE2_LAG_WK_ST_WAIT_PROC) {
		lag->lag_wk.event = SXE2_LAG_EVENT_BONDINFO;
		lag->lag_wk.state = SXE2_LAG_WK_ST_WAIT_PROC;
	}

	LOG_INFO_BDF("bondinfo syn proc done: changed %d\n", changed);

	return changed;
}

STATIC void sxe2_lag_work_sched(struct sxe2_lag_context *lag)
{
	int i;
	struct sxe2_adapter *adapter = NULL;

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		adapter = lag->adapters[i];
		if (adapter) {
			if (!sxe2_lag_is_configurable(adapter)) {
				LOG_INFO_BDF("lag work sched: pf %d is busy.\n",
					     adapter->pf_idx);
				return;
			}
		} else {
			LOG_DEBUG_BDF("lag work sched: find idx adapter null.\n");
			return;
		}
	}

	set_bit(SXE2_LAG_FLAGS_WK_PENDING, &lag->flags);
	if (test_bit(SXE2_LAG_FLAGS_WK_PROCESS, &lag->flags)) {
		LOG_INFO("lag: work is processing, queue work latter.\n");
		return;
	}
	(void)queue_work(lag->wkq, &lag->lag_wk.task);
}

static bool sxe2_lag_safe_mode_check(struct sxe2_lag_context *lag)
{
	bool in_safe_mode = false;
	int i;

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		if (lag->adapters[i] && sxe2_is_safe_mode(lag->adapters[i])) {
			in_safe_mode = true;
			LOG_ERROR("pf %d in safe mode.\n", lag->adapters[i]->pf_idx);
			break;
		}
	}

	return in_safe_mode;
}

static bool sxe2_lag_sriov_check(struct sxe2_lag_context *lag)
{
	struct sxe2_adapter *adapter;
	bool in_sriov = false;
	int i;

	for (i = 0; i < SXE2_MAX_BOND_DEV_NUM; i++) {
		adapter = lag->adapters[i];
		if (adapter) {
			mutex_lock(&adapter->vf_ctxt.vfs_lock);
			if (sxe2_vf_is_exist(adapter)) {
				in_sriov = true;
				LOG_DEV_ERR("pf %d in sriov.\n",
					    lag->adapters[i]->pf_idx);
			}
			mutex_unlock(&adapter->vf_ctxt.vfs_lock);

			if (in_sriov)
				break;
		}
	}

	return in_sriov;
}

static int sxe2_lag_event_process(struct sxe2_adapter *adapter, unsigned long event,
				  void *ptr)
{
	int ret = NOTIFY_DONE;
	int changed = 0;
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(netdev), &init_net))
		goto l_end;

	if (sxe2_lag_safe_mode_check(adapter->lag_ctxt))
		goto l_end;

	if (sxe2_lag_sriov_check(adapter->lag_ctxt))
		goto l_end;

	if (!test_bit(SXE2_FLAG_RDMA_LOADED, adapter->flags))
		goto l_end;

	if (event == NETDEV_CHANGEUPPER)
		changed = sxe2_lag_changeupper_event_fill(adapter, ptr);
	else
		changed = sxe2_lag_bondinfo_event_fill(adapter, ptr);

	if (changed)
		sxe2_lag_work_sched(adapter->lag_ctxt);

l_end:
	LOG_INFO_BDF("lag work sched : event %lu changed %d.\n", event, changed);

	return ret;
}

static bool sxe2_lag_event_check(struct sxe2_adapter *adapter, unsigned long event,
				 void *ptr)
{
	bool support = true;
#ifndef SXE2_CFG_RELEASE
	struct netdev_notifier_bonding_info *binfo = ptr;
#endif
	struct netdev_notifier_changeupper_info *cinfo = ptr;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		LOG_INFO_BDF("lag check: changeupper event_netdev %s upper %s\n",
			     netdev_name(cinfo->info.dev),
			     netdev_name(cinfo->upper_dev));
		if (!netif_is_lag_master(cinfo->upper_dev)) {
			support = false;
			LOG_ERROR_BDF("lag link: upper %s is not lag master.\n",
				      netdev_name(cinfo->upper_dev));
		}
		break;
	case NETDEV_BONDING_INFO:
		LOG_INFO_BDF("lag check: bondinfo event_netdev %s\n",
			     netdev_name(binfo->info.dev));
		break;
	default:
		LOG_INFO_BDF("lag check: ignore event %lu.\n", event);
		support = false;
	}

	return support;
}

STATIC int sxe2_lag_netdev_event_handler(struct notifier_block *notif_blk,
					 unsigned long event, void *ptr)
{
	s32 ret = NOTIFY_DONE;
	struct sxe2_lag_context *lag;
	struct sxe2_adapter *adapter;

	lag = container_of(notif_blk, struct sxe2_lag_context, notif_block);

	mutex_lock(&lag->lock);
	adapter = lag->adapters[0];

	if (!sxe2_lag_event_check(adapter, event, ptr))
		goto l_end;

	switch (event) {
	case NETDEV_CHANGEUPPER:
	case NETDEV_BONDING_INFO:
		(void)sxe2_lag_event_process(adapter, event, ptr);
		break;
	default:
		LOG_DEBUG_BDF("lag ignore netdev notifier event %ld.\n", event);
		break;
	}

l_end:
	LOG_DEBUG_BDF("lag netdev event handler end.\n");
	mutex_unlock(&lag->lock);
	return ret;
}

STATIC struct sxe2_lag_context *sxe2_lag_ctxt_init(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = NULL;
	struct sxe2_lag_list *entry;
	size_t size;

	lag = sxe2_lag_alloc();
	if (!lag) {
		LOG_ERROR_BDF("alloc lag failed.\n");
		goto l_end;
	}

	lag->wkq = alloc_ordered_workqueue("%s-LAG-%s", __WQ_LEGACY | WQ_MEM_RECLAIM,
					   SXE2_DRV_NAME, adapter->serial_num);
	if (!lag->wkq) {
		LOG_ERROR_BDF("Failed to create LAG workqueue.\n");
		goto l_free_lag;
	}

	mutex_init(&lag->lock);

	lag->bond_mode = SXE2_LAG_BOND_MODE_UNSET;
	lag->ref_num = 0;
	lag->bonded = false;
	memcpy(lag->serial_num, adapter->serial_num, SXE2_SERIAL_NUM_LEN);

	lag->lag_wk.lag = lag;
	lag->lag_wk.state = SXE2_LAG_WK_ST_UNSET;
	INIT_WORK(&lag->lag_wk.task, sxe2_lag_work_cb);

	size = sizeof(struct sxe2_lag_list);
	entry = kzalloc(size, GFP_KERNEL);
	if (!entry) {
		LOG_ERROR_BDF("alloc lag list node failed.\n");
		goto l_mutex_deinit;
	}

	entry->lag = lag;
	list_add(&entry->node, &sxe2_lag_head.node);

	LOG_INFO_BDF("lag init success lag 0x%p.\n", lag);
	return lag;

l_mutex_deinit:
	mutex_destroy(&lag->lock);
	destroy_workqueue(lag->wkq);

l_free_lag:
	kfree(lag);
	lag = NULL;

l_end:
	return lag;
}

STATIC void sxe2_lag_ctxt_deinit(struct sxe2_lag_context *lag)
{
	struct list_head *tmp;
	struct list_head *n;
	struct sxe2_lag_list *entry = NULL;

	cancel_work_sync(&lag->lag_wk.task);

	list_for_each_safe(tmp, n, &sxe2_lag_head.node) {
		entry = list_entry(tmp, struct sxe2_lag_list, node);
		if (entry->lag == lag) {
			list_del(&entry->node);
			LOG_DEBUG("del entry of lag %p.\n", lag);
			break;
		}

		entry = NULL;
	}

	if (!entry) {
		LOG_ERROR("find lag %p entry failed.\n", lag);
		goto l_end;
	}

	destroy_workqueue(lag->wkq);

	mutex_destroy(&lag->lock);

	kfree(lag);
	kfree(entry);

l_end:
	return;
}

bool sxe2_lag_support(struct sxe2_adapter *adapter)
{
	int pf_cnt = adapter->aux_ctxt.cdev_info.pf_cnt;
	bool supported = false;

	if (pf_cnt != SXE2_MAX_BOND_DEV_NUM || allow_repeat_sn)
		goto l_end;

	supported = true;
l_end:

	return supported;
}

int sxe2_lag_init(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = NULL;
	int ret = 0;

	LOG_INFO_BDF("lag init pf %d.\n", adapter->pf_idx);

	if (!sxe2_lag_support(adapter)) {
		LOG_DEV_INFO("unsupport lag.\n");
		goto l_end;
	}
	sxe2_lag_list_lock();
	lag = sxe2_lag_context_find(adapter);
	if (!lag) {
		lag = sxe2_lag_ctxt_init(adapter);
		if (!lag) {
			ret = -ENOMEM;
			LOG_DEV_ERR("lag init failed.\n");
			sxe2_lag_list_unlock();
			goto l_end;
		}
	}

	mutex_lock(&lag->lock);
	if (lag->ref_num >= SXE2_MAX_BOND_DEV_NUM) {
		LOG_DEV_ERR("netdev is arrive max %d.\n", SXE2_MAX_BOND_DEV_NUM);
		ret = -EMLINK;
		goto l_unlock;
	}

	adapter->lag_ctxt = lag;
	lag->adapters[adapter->pf_idx] = adapter;
	lag->ref_num++;

	lag->state[adapter->pf_idx] = SXE2_LAG_STATE_READY;

	LOG_INFO_BDF("lag init success use pf %d lag 0x%p serial_num %s.\n",
		     adapter->pf_idx, lag, lag->serial_num);
l_unlock:
	mutex_unlock(&lag->lock);
	sxe2_lag_list_unlock();

l_end:

	if (lag && lag->ref_num == SXE2_MAX_BOND_DEV_NUM) {
		if (ret == 0 && !lag->notif_block.notifier_call) {
			lag->notif_block.notifier_call =
					sxe2_lag_netdev_event_handler;
			ret = register_netdevice_notifier(&lag->notif_block);
			if (ret) {
				lag->notif_block.notifier_call = NULL;
				LOG_DEV_ERR("FAIL register netdev event handler!\n");
				return ret;
			}
			LOG_INFO_BDF("netdev event handler registered\n");
		} else {
			LOG_DEV_ERR("SN: %s netdev event has already register, \t"
				    "maybe Serial Num is repeat ret: %d.\n",
				    adapter->serial_num, ret);
		}
	}

	return ret;
}

void sxe2_lag_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct notifier_block *notif_blk;

	if (!sxe2_lag_support(adapter))
		goto l_end;

	if (!lag) {
		LOG_ERROR_BDF("adapter already unlinkd lag.\n");
		goto l_end;
	}

	sxe2_lag_list_lock();

	if (lag->ref_num == SXE2_MAX_BOND_DEV_NUM) {
		notif_blk = &lag->notif_block;
		if (notif_blk->notifier_call) {
			(void)unregister_netdevice_notifier(notif_blk);
			LOG_INFO("LAG event handler unregistered\n");
		}
	}

	mutex_lock(&lag->lock);
	adapter->lag_ctxt = NULL;
	lag->adapters[adapter->pf_idx] = NULL;
	lag->ref_num--;
	mutex_unlock(&lag->lock);

	if (lag->ref_num == 0) {
		sxe2_lag_ctxt_deinit(lag);
		LOG_INFO_BDF("lag ctxt deinit success.\n");
	}

	sxe2_lag_list_unlock();

	LOG_INFO_BDF("lag deinit success.\n");

l_end:
	return;
}

static void sxe2_lag_enter_reset(struct sxe2_adapter *adapter, bool to_reset)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	if (adapter->pf_idx > SXE2_MAX_PF_NUM)
		return;

	mutex_lock(&lag->lock);
	if (to_reset)
		lag->state[adapter->pf_idx] = SXE2_LAG_STATE_RESET;
	else
		lag->state[adapter->pf_idx] = SXE2_LAG_STATE_READY;

	LOG_INFO_BDF("lag pf %d stat enter %d\n",
		     adapter->pf_idx, lag->state[adapter->pf_idx]);
	mutex_unlock(&lag->lock);
}

static bool sxe2_lag_enter_ready(struct sxe2_adapter *adapter)
{
	bool ready = false;
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	mutex_lock(&lag->lock);
	if (lag->state[SXE2_LAG_PF0] == SXE2_LAG_STATE_READY &&
	    lag->state[SXE2_LAG_PF1] == SXE2_LAG_STATE_READY)
		ready = true;
	mutex_unlock(&lag->lock);

	return ready;
}

void sxe2_lag_stop(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_adapter *primary_adapter;

	if (!sxe2_lag_support(adapter))
		goto l_end;

	LOG_DEBUG_BDF("lag stop proc start.\n");

	cancel_work_sync(&lag->lag_wk.task);

	if (!sxe2_lag_enter_ready(adapter)) {
		LOG_DEBUG_BDF("lag stop proc: already in reset.\n");
		goto l_end;
	}

	sxe2_lag_enter_reset(adapter, true);

	mutex_lock(&lag->lock);
	if (!lag->bonded) {
		mutex_unlock(&lag->lock);
		goto l_end;
	}

	sxe2_lag_del_devs(lag);
	primary_adapter = sxe2_lag_role_find(lag, SXE2_LAG_PRIMARY_ID);
	mutex_unlock(&lag->lock);

	cdev_info = &primary_adapter->aux_ctxt.cdev_info;
	sxe2_rdma_aux_delete(cdev_info);

l_end:
	LOG_DEBUG_BDF("lag stop proc end.\n");
}

void sxe2_lag_rebuild(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	if (!sxe2_lag_support(adapter))
		goto l_end;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_WARN_BDF("running in safe mode, lag does not need rebuild.\n");
		goto l_end;
	}

	LOG_DEBUG_BDF("lag rebuild proc start.\n");

	sxe2_lag_enter_reset(adapter, false);

	mutex_lock(&lag->lock);
	if (!lag->bonded) {
		mutex_unlock(&lag->lock);
		goto l_end;
	}

	LOG_DEBUG_BDF("lag pf %d in bond, need rebuild rdma aux dev.\n",
		      adapter->pf_idx);

	lag->lag_wk.event = SXE2_LAG_EVENT_CHANGEUPPER;
	lag->lag_wk.state = SXE2_LAG_WK_ST_WAIT_PROC;

	sxe2_lag_work_sched(adapter->lag_ctxt);
	mutex_unlock(&lag->lock);

l_end:

	LOG_DEBUG_BDF("lag rebuild proc end.\n");
}

void sxe2_lag_proc(struct sxe2_adapter *adapter)
{
	struct sxe2_lag_context *lag = adapter->lag_ctxt;

	if (!sxe2_lag_support(adapter))
		goto l_end;

	mutex_lock(&lag->lock);
	if (!test_bit(SXE2_LAG_FLAGS_WK_PROCESS, &lag->flags) &&
	    test_bit(SXE2_LAG_FLAGS_WK_PENDING, &lag->flags)) {
		(void)queue_work(lag->wkq, &lag->lag_wk.task);
		LOG_INFO_BDF("lag: find pending event, queue work now.\n");
	}

	mutex_unlock(&lag->lock);

l_end:
	return;
}
