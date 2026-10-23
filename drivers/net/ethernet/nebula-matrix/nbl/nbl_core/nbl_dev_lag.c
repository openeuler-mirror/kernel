// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_dev_lag.h"

/* General purpose, use for short periods of time.
 * Beware of lock dependencies (preferably, no locks should be acquired
 * under it).
 */
static DEFINE_SPINLOCK(lag_lock);

static void nbl_do_bond_work(struct work_struct *work);
static int nbl_lag_netdev_event(struct notifier_block *this,
				unsigned long event, void *ptr);

static int nbl_lag_get_master_idx(struct nbl_lag_dev *ldev)
{
	unsigned long idx = 0;
	void *entry;

	if (!ldev)
		return -ENOENT;

	entry = xa_find(&ldev->pfs, &idx, U8_MAX, NBL_LAG_XA_MARK_MASTER);
	if (!entry)
		return -ENOENT;

	return (int)idx;
}

static u8 nbl_get_pdev_index(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);

	return NBL_COMMON_TO_MY_PF(common);
}

static int nbl_lag_dev_get_netdev_idx(struct nbl_lag_dev *ldev,
				      struct net_device *ndev)
{
	struct nbl_lag_func *pf;
	int i, _tmp;

	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		if (pf->netdev == ndev)
			return i;
	}

	return -ENOENT;
}

static void nbl_lag_mark_master(struct nbl_lag_dev *ldev)
{
	int lowest_dev_idx = INT_MAX;
	struct nbl_lag_func *pf;
	int master_xa_idx = -1;
	int dev_idx;
	int i, _tmp;

	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		/* mark min pf as master */
		dev_idx = nbl_get_pdev_index(pf->pdev);
		if (dev_idx < lowest_dev_idx) {
			lowest_dev_idx = dev_idx;
			master_xa_idx = i;
		}
	}

	if (master_xa_idx >= 0)
		xa_set_mark(&ldev->pfs, master_xa_idx, NBL_LAG_XA_MARK_MASTER);
}

static void nbl_lag_clear_master(struct nbl_lag_dev *ldev)
{
	unsigned long idx = 0;
	void *entry;

	entry = xa_find(&ldev->pfs, &idx, U8_MAX, NBL_LAG_XA_MARK_MASTER);
	if (!entry)
		return;

	xa_clear_mark(&ldev->pfs, idx, NBL_LAG_XA_MARK_MASTER);
}

int nbl_lag_get_dev_index_by_seq(struct nbl_lag_dev *ldev, int seq)
{
	int master_idx, i, _tmp, num = 0;

	if (!ldev)
		return -ENOENT;

	master_idx = nbl_lag_get_master_idx(ldev);

	/* If seq 0 is requested and there's a primary PF, return it */
	if (master_idx >= 0) {
		if (seq == 0)
			return master_idx;
		num++;
	}

	nbl_ldev_for_each(i, 0, ldev) {
		/* Skip the primary PF in the loop */
		if (i == master_idx)
			continue;

		if (num == seq)
			return i;
		num++;
	}
	return -ENOENT;
}

static int nbl_lag_comp_event_cb(int event, void *priv_data, void *event_data)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)priv_data;
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	int idx;

	mutex_lock(&ldev->lock);
	switch (event) {
	case NBL_DEVCOMM_LAG_MASTER_MASK_EVENT:
		idx = nbl_lag_get_master_idx(ldev);
		if (idx >= 0)
			break;

		if (nbl_lag_get_pf_num(ldev) == ldev->ports)
			nbl_lag_mark_master(ldev);
		break;
	case NBL_DEVCOMM_LAG_MASTER_UNMASK_EVENT:
		nbl_lag_clear_master(ldev);
		break;
	default:
		break;
	}
	mutex_unlock(&ldev->lock);

	return 0;
}

static int nbl_lag_register_devcomm_comp(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_devcomm_match_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.key.val = NBL_COMMON_TO_BOARD_ID(common);
	attr.net = &init_net;
	dev_mgt->pf_comp_dev = nbl_devcomm_register_component(NBL_DEVCOMM_LAG_DEV,
							      &attr,
							      nbl_lag_comp_event_cb,
							      dev_mgt);
	if (!dev_mgt->pf_comp_dev)
		return -ENOMEM;

	return 0;
}

/* The last nbl_dev_mgt to unregister will destroy the workqueue before removing the
 * devcomm component, and as all the nbl_dev_mgt use the same devcomm component we are
 * guaranteed that the devcomm is valid while the calling work is running.
 */
static
struct nbl_devcomm_comp_dev *nbl_lag_get_devcomm_comp(struct nbl_lag_dev *ldev)
{
	struct nbl_devcomm_comp_dev *devcomm = NULL;
	struct nbl_lag_func *pf;
	int i;

	mutex_lock(&ldev->lock);
	i = nbl_lag_get_next_func(ldev, 0, NBL_LAG_FILTER_PORTS);
	if (i < NBL_MAX_PF) {
		pf = nbl_lag_pf(ldev, i);
		devcomm = pf->pdev->pf_comp_dev;
	}
	mutex_unlock(&ldev->lock);
	return devcomm;
}

void nbl_lag_devcomm_lock(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	struct nbl_devcomm_comp_dev *devcomm;

	if (!ldev)
		return;

	devcomm = nbl_lag_get_devcomm_comp(ldev);
	if (!devcomm)
		return;

	nbl_devcomm_comp_lock(devcomm);
}

void nbl_lag_devcomm_unlock(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	struct nbl_devcomm_comp_dev *devcomm;

	if (!ldev)
		return;

	devcomm = nbl_lag_get_devcomm_comp(ldev);
	if (!devcomm)
		return;

	nbl_devcomm_comp_unlock(devcomm);
}

static void nbl_queue_bond_work(struct nbl_lag_dev *ldev, unsigned long delay)
{
	queue_delayed_work(ldev->wq, &ldev->bond_work, delay);
}

int nbl_lag_get_next_func(struct nbl_lag_dev *ldev, int start_idx, u32 filter)
{
	struct nbl_lag_func *pf;
	unsigned long idx;

	if (filter == NBL_LAG_FILTER_PORTS) {
		idx = start_idx;
		for (pf = xa_find(&ldev->pfs, &idx, ULONG_MAX, NBL_LAG_XA_MARK_PORT);
		     pf; pf = xa_find_after(&ldev->pfs, &idx, ULONG_MAX, NBL_LAG_XA_MARK_PORT))
			if (pf->pdev)
				return idx;

		return NBL_MAX_PF;
	}

	xa_for_each_start(&ldev->pfs, idx, pf, start_idx) {
		if (!pf->pdev)
			continue;
		if (filter == NBL_LAG_FILTER_ALL)
			return idx;
	}

	return NBL_MAX_PF;
}

int nbl_lag_get_pf_num(struct nbl_lag_dev *ldev)
{
	int i, _tmp, num = 0;

	if (!ldev)
		return 0;

	nbl_ldev_for_each(i, 0, ldev) {
		(void)i;
		num++;
	}

	return num;
}

int nbl_lag_get_netdev_num(struct nbl_lag_dev *ldev)
{
	struct nbl_lag_func *pf;
	int i, _tmp, num = 0;

	if (!ldev)
		return 0;

	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		if (pf->netdev)
			num++;
	}
	return num;
}

static void __nbl_ldev_add_netdev(struct nbl_lag_dev *ldev,
				  struct nbl_dev_mgt *dev_mgt,
				  struct net_device *netdev)
{
	struct nbl_lag_func *pf;
	unsigned long flags;
	int i, _tmp;

	spin_lock_irqsave(&lag_lock, flags);
	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		if (pf->pdev == dev_mgt) {
			pf->netdev = netdev;
			ldev->new_tracker.netdev_state[i].link_up = 0;
			ldev->new_tracker.netdev_state[i].tx_enabled = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&lag_lock, flags);
}

static void __nbl_ldev_remove_netdev(struct nbl_lag_dev *ldev,
				     struct net_device *netdev)
{
	struct nbl_lag_func *pf;
	unsigned long flags;
	int i, _tmp;

	spin_lock_irqsave(&lag_lock, flags);
	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		if (pf->netdev == netdev) {
			pf->netdev = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&lag_lock, flags);
}

void nbl_ldev_add_netdev(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev)
{
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	int num = 0;

	if (!ldev)
		return;

	mutex_lock(&ldev->lock);
	__nbl_ldev_add_netdev(ldev, dev_mgt, netdev);
	num = nbl_lag_get_pf_num(ldev);
	if (num >= ldev->ports)
		set_bit(NBL_LAG_FLAG_NDEVS_READY, &ldev->state_flags);
	mutex_unlock(&ldev->lock);
	nbl_queue_bond_work(ldev, 0);
}

void nbl_ldev_remove_netdev(struct nbl_dev_mgt *dev_mgt,
			    struct net_device *netdev)
{
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	bool lag_is_active;

	if (!ldev)
		return;

	mutex_lock(&ldev->lock);
	__nbl_ldev_remove_netdev(ldev, netdev);
	clear_bit(NBL_LAG_FLAG_NDEVS_READY, &ldev->state_flags);
	lag_is_active = __nbl_lag_is_active(ldev);
	mutex_unlock(&ldev->lock);

	if (lag_is_active)
		nbl_queue_bond_work(ldev, 0);
}

static void nbl_ldev_free(struct kref *ref)
{
	struct nbl_lag_dev *ldev = container_of(ref, struct nbl_lag_dev, ref);
	struct nbl_lag_func *pf;
	struct notifier_block *notif_blk = &ldev->nb;
	int i, _tmp;

	if (notif_blk->notifier_call)
		unregister_netdevice_notifier_net(&init_net, notif_blk);

	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_ALL) {
		pf = nbl_lag_pf(ldev, i);
		xa_erase(&ldev->pfs, i);
		kfree(pf);
	}

	xa_destroy(&ldev->pfs);
	cancel_delayed_work_sync(&ldev->bond_work);
	destroy_workqueue(ldev->wq);
	mutex_destroy(&ldev->lock);
	kfree(ldev);
}

static void nbl_ldev_put(struct nbl_lag_dev *ldev)
{
	kref_put(&ldev->ref, nbl_ldev_free);
}

static void nbl_ldev_get(struct nbl_lag_dev *ldev)
{
	kref_get(&ldev->ref);
}

static struct nbl_lag_dev *nbl_lag_dev_alloc(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dispatch_ops *disp_ops = NBL_DEV_MGT_TO_DISP_OPS(dev_mgt);
	struct nbl_lag_dev *ldev;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct notifier_block *notify_blk;

	/* Lenois can insure alloc by pf0 */
	if (!NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt))
		return NULL;

	ldev = kzalloc(sizeof(*ldev), GFP_KERNEL);
	if (!ldev)
		return NULL;

	ldev->wq = create_singlethread_workqueue("nbl_lag");
	if (!ldev->wq) {
		kfree(ldev);
		return NULL;
	}

	kref_init(&ldev->ref);
	mutex_init(&ldev->lock);
	xa_init_flags(&ldev->pfs, XA_FLAGS_ALLOC);
	INIT_DELAYED_WORK(&ldev->bond_work, nbl_do_bond_work);

	notify_blk = &ldev->nb;
	notify_blk->notifier_call = nbl_lag_netdev_event;
	if (register_netdevice_notifier_net(&init_net, notify_blk)) {
		notify_blk->notifier_call = NULL;
		nbl_err(common, NBL_DEBUG_MAIN,
			"Failed to register nbl lag netdev handler!\n");
	}

	ldev->mode = NBL_LAG_MODE_NONE;
	ldev->ports =
		disp_ops->get_lag_ports_max(NBL_DEV_MGT_TO_DISP_PRIV(dev_mgt));

	return ldev;
}

static int nbl_lag_dev_add_pfdev(struct nbl_lag_dev *ldev, struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_lag_func *pf;
	u32 idx;
	int err;

	pf = kzalloc(sizeof(*pf), GFP_KERNEL);
	if (!pf)
		return -ENOMEM;

	err = xa_alloc(&ldev->pfs, &idx, pf, XA_LIMIT(0, NBL_MAX_PF - 1),
		       GFP_KERNEL);
	if (err) {
		kfree(pf);
		return err;
	}

	pf->idx = idx;
	pf->pdev = dev_mgt;
	NBL_DEV_MGT_TO_LAG_DEV(dev_mgt) = ldev;

	xa_set_mark(&ldev->pfs, idx, NBL_LAG_XA_MARK_PORT);

	return 0;
}

static int nbl_lag_add_dev(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_devcomm_comp_dev *pos = NULL;
	struct nbl_lag_dev *ldev = NULL;
	struct nbl_dev_mgt *tmp_dev_mgt;
	int err;

	tmp_dev_mgt = nbl_devcomm_get_next_peer_data(dev_mgt->pf_comp_dev,
						     &pos);
	if (tmp_dev_mgt)
		ldev = NBL_DEV_MGT_TO_LAG_DEV(tmp_dev_mgt);

	if (!ldev) {
		ldev = nbl_lag_dev_alloc(dev_mgt);
		if (!ldev) {
			nbl_err(NBL_DEV_MGT_TO_COMMON(dev_mgt), NBL_DEBUG_MAIN,
				"Failed to alloc lag dev\n");
			err = -ENOMEM;
			goto alloc_ldev_failed;
		}

		err = nbl_lag_dev_add_pfdev(ldev, dev_mgt);
		if (err) {
			nbl_err(NBL_DEV_MGT_TO_COMMON(dev_mgt), NBL_DEBUG_MAIN,
				"Failed to add lag dev's pf\n");
			nbl_ldev_put(ldev);
			err = -ENOMEM;
			goto add_pfdev_failed;
		}

		return 0;
	}

	mutex_lock(&ldev->lock);
	if (ldev->mode_changes_in_progress) {
		mutex_unlock(&ldev->lock);
		return -EAGAIN;
	}

	nbl_ldev_get(ldev);
	err = nbl_lag_dev_add_pfdev(ldev, dev_mgt);
	if (err) {
		nbl_ldev_put(ldev);
		mutex_unlock(&ldev->lock);
		goto add_pfdev_failed;
	}
	mutex_unlock(&ldev->lock);

	return 0;

add_pfdev_failed:
alloc_ldev_failed:
	return err;
}

static void nbl_lag_remove_dev(struct nbl_lag_dev *ldev,
			       struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_lag_func *pf;
	int i, _tmp;

	if (!NBL_DEV_MGT_TO_LAG_DEV(dev_mgt))
		return;

	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_ALL) {
		pf = nbl_lag_pf(ldev, i);
		if (pf->pdev == dev_mgt)
			break;
	}
	if (i >= NBL_MAX_PF)
		return;

	pf->pdev = NULL;
	NBL_DEV_MGT_TO_LAG_DEV(dev_mgt) = NULL;
	xa_erase(&ldev->pfs, pf->idx);
	kfree(pf);
}

int nbl_dev_setup_lag_dev(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_DEV_MGT_TO_DISP_OPS(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	int ret;

	if (!param->caps.support_lag)
		return 0;

	if (NBL_COMMON_TO_ETH_MODE(common) < 2)
		return 0;

	if (disp_ops->check_lag_nosupport(NBL_DEV_MGT_TO_DISP_PRIV(dev_mgt)))
		return 0;

	ret = nbl_lag_register_devcomm_comp(dev_mgt);
	if (ret)
		return ret;
recheck:
	/**
	 * hold the dev_mgt->pf_comp_dev's lock, to avoid
	 * nbl_dev_remove_lag_dev free ldev. Because nbl_dev_remove_lag_dev
	 * will call nbl_devcomm_send_event before nbl_ldev_put. And
	 * nbl_devcomm_send_event also need dev_mgt->pf_comp_dev's lock.
	 */
	nbl_devcomm_comp_lock(dev_mgt->pf_comp_dev);
	ret = nbl_lag_add_dev(dev_mgt);
	nbl_devcomm_comp_unlock(dev_mgt->pf_comp_dev);

	if (ret == -EAGAIN) {
		msleep(100);
		goto recheck;
	}

	nbl_devcomm_send_event(dev_mgt->pf_comp_dev,
			       NBL_DEVCOMM_LAG_MASTER_MASK_EVENT,
			       NBL_DEVCOMM_LAG_MASTER_UNMASK_EVENT,
			       NULL);

	return 0;
}

void nbl_dev_remove_lag_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_lag_dev *ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);

	ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	if (!ldev)
		return;

recheck:
	mutex_lock(&ldev->lock);
	if (ldev->mode_changes_in_progress) {
		mutex_unlock(&ldev->lock);
		msleep(100);
		goto recheck;
	}

	nbl_lag_remove_dev(ldev, dev_mgt);
	mutex_unlock(&ldev->lock);
	nbl_devcomm_send_event(dev_mgt->pf_comp_dev,
			       NBL_DEVCOMM_LAG_MASTER_UNMASK_EVENT,
			       NBL_DEVCOMM_LAG_MASTER_UNMASK_EVENT, NULL);
	nbl_devcomm_unregister_component(dev_mgt->pf_comp_dev);
	dev_mgt->pf_comp_dev = NULL;
	nbl_ldev_put(ldev);
}

static bool nbl_lag_check_prereq(struct nbl_lag_dev *ldev)
{
	int master_idx = nbl_lag_get_dev_index_by_seq(ldev, 0);

	if (master_idx < 0 || nbl_lag_get_netdev_num(ldev) != ldev->ports)
		return false;

	return true;
}

static void __maybe_unused nbl_lag_drop_lock(struct nbl_lag_dev *ldev)
{
	ldev->mode_changes_in_progress++;
	mutex_unlock(&ldev->lock);
}

static void __maybe_unused nbl_lag_retake_lock(struct nbl_lag_dev *ldev)
{
	mutex_lock(&ldev->lock);
	ldev->mode_changes_in_progress--;
}

static void nbl_lag_remove_rdma_adevs(struct nbl_lag_dev *ldev)
{
	struct nbl_dev_rdma *rdma_dev;
	struct nbl_lag_func *pf;
	int i, _tmp;

	/**
	 * adev remove may take a while, increase mode_changes_in_progress,
	 * so other paths observe mode_changes_in_progress and retry.
	 */
	nbl_lag_drop_lock(ldev);
	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_PORTS) {
		pf = nbl_lag_pf(ldev, i);
		rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(pf->pdev);
		if (!rdma_dev || !rdma_dev->adev)
			continue;
		nbl_dev_destroy_rdma_aux_dev(rdma_dev, &rdma_dev->adev);
	}
	nbl_lag_retake_lock(ldev);
}

static void nbl_lag_add_rdma_adevs(struct nbl_lag_dev *ldev)
{
	struct nbl_dev_rdma *rdma_dev;
	struct nbl_lag_func *pf;
	int i, _tmp;

	/**
	 * adev add may take a while, increase mode_changes_in_progress,
	 * so other paths observe mode_changes_in_progress and retry.
	 */
	nbl_lag_drop_lock(ldev);
	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_PORTS) {
		pf = nbl_lag_pf(ldev, i);
		if (pf->pdev->adev_flag & NBL_DISABLE_ADEV)
			continue;

		rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(pf->pdev);
		if (!rdma_dev || rdma_dev->adev)
			continue;

		nbl_dev_create_rdma_aux_dev(pf->pdev, NBL_AUX_DEV_ROCE);
	}
	nbl_lag_retake_lock(ldev);
}

static void nbl_lag_add_rdma_bond_adev(struct nbl_lag_dev *ldev,
				       struct nbl_dev_mgt *dev_mgt)
{
	/**
	 * adev add adev may take a while, increase mode_changes_in_progress,
	 * so other paths observe mode_changes_in_progress and retry.
	 */
	nbl_lag_drop_lock(ldev);
	nbl_dev_create_rdma_aux_dev(dev_mgt, NBL_AUX_DEV_BOND);
	nbl_lag_retake_lock(ldev);
}

static void nbl_lag_remove_rdma_bond_adev(struct nbl_lag_dev *ldev,
					  struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_dev_rdma *rdma_dev = NBL_DEV_MGT_TO_RDMA_DEV(dev_mgt);

	if (!rdma_dev || dev_mgt->adev_flag & NBL_DISABLE_ADEV)
		return;
	/**
	 * adev add adev may take a while, increase mode_changes_in_progress,
	 * so other paths observe mode_changes_in_progress and retry.
	 */
	nbl_lag_drop_lock(ldev);
	if (rdma_dev->bond_adev)
		nbl_dev_destroy_rdma_aux_dev(rdma_dev, &rdma_dev->bond_adev);
	nbl_lag_retake_lock(ldev);
}

static bool nbl_lag_should_modify_lag(struct nbl_lag_dev *ldev, bool do_bond)
{
	return do_bond && __nbl_lag_is_active(ldev);
}

static bool nbl_lag_should_disable_lag(struct nbl_lag_dev *ldev, bool do_bond)
{
	return !do_bond && __nbl_lag_is_active(ldev);
}

static void nbl_lag_form_mem_info(struct nbl_lag_dev *ldev,
				  struct nbl_lag_tracker *trk,
				  struct nbl_lag_member_list_param *mbr_prm)
{
	struct nbl_dev_mgt *dev_tmp;
	struct nbl_common_info *common;
	struct nbl_lag_func *pf;
	int i, _tmp;
	u16 mbr_num = 0;

	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_PORTS) {
		pf = nbl_lag_pf(ldev, i);
		dev_tmp = pf->pdev;
		common = NBL_DEV_MGT_TO_COMMON(pf->pdev);
		mbr_prm->member_list[mbr_num].vsi_id =
			NBL_COMMON_TO_VSI_ID(common);
		mbr_prm->member_list[mbr_num].eth_id =
			NBL_COMMON_TO_ETH_ID(common);
		mbr_prm->member_list[mbr_num].active =
			nbl_lag_mbr_is_active(trk, i);
		mbr_num++;
	}

	mbr_prm->lag_num = mbr_num;
	mbr_prm->lag_id = 0;
	if (trk->tx_type == NETDEV_LAG_TX_TYPE_HASH)
		mbr_prm->duppkt_enable = true;
}

static void nbl_lag_active(struct nbl_lag_dev *ldev,
			   struct nbl_dev_mgt *dev_mst,
			   struct nbl_lag_tracker *trk)
{
	struct nbl_service_ops *serv_ops;
	struct nbl_dev_mgt *dev_tmp;
	struct nbl_common_info *common;
	struct nbl_lag_func *pf;
	void *serv_priv;
	struct nbl_lag_member_list_param mbr_prm;
	int i, _tmp;
	enum nbl_lag_mbr_fwd mbr_fwd;
	u8 eth_id;
	bool active;
	bool lag_en;
	struct nbl_ch_prm_enable_lag_protocol lag_prm;
	struct nbl_ch_prm_cfg_lag_hash_algorithm hash_prm;
	struct nbl_ch_prm_cfg_lag_member_fwd fwd_prm;
	struct nbl_ch_prm_cfg_lag_member_up_attr up_prm;

	memset(&mbr_prm, 0, sizeof(mbr_prm));
	nbl_lag_form_mem_info(ldev, trk, &mbr_prm);
	nbl_lag_drop_lock(ldev);
	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_PORTS) {
		pf = nbl_lag_pf(ldev, i);
		dev_tmp = pf->pdev;
		serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_tmp);
		common = NBL_DEV_MGT_TO_COMMON(dev_tmp);
		serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_tmp);
		eth_id = NBL_COMMON_TO_ETH_ID(common);
		lag_prm.eth_id = eth_id;
		lag_prm.lag_en = true;
		serv_ops->enable_lag_protocol(serv_priv, &lag_prm);
		serv_ops->set_sfp_state(serv_priv, eth_id,
					trk->netdev_updown[i], true);
		up_prm.eth_id = eth_id;
		up_prm.lag_id = 0;
		up_prm.enable = true;
		serv_ops->cfg_lag_member_up_attr(serv_priv, &up_prm);
		active = nbl_lag_mbr_is_active(trk, i);
		mbr_fwd = active ? NBL_LAG_MEM_FWD_NORMAL :
				NBL_LAG_MEM_FWD_DROP;
		fwd_prm.eth_id = eth_id;
		fwd_prm.lag_id = 0;
		fwd_prm.fwd = mbr_fwd;
		serv_ops->cfg_lag_member_fwd(serv_priv, &fwd_prm);
		serv_ops->cfg_lag_member_list(serv_priv, &mbr_prm);
		serv_ops->set_lag_info(serv_priv, 0, mbr_prm.lag_num);
	}
	nbl_lag_retake_lock(ldev);

	serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_mst);
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mst);
	hash_prm.eth_id = 0;
	hash_prm.lag_id = 0;
	hash_prm.hash_type = trk->hash_type;
	serv_ops->cfg_lag_hash_algorithm(serv_priv, &hash_prm);
	lag_en = true;
	serv_ops->set_lag_status(serv_priv, &lag_en);

	ldev->mode = NBL_LAG_MODE_EN;
}

static void nbl_lag_disable(struct nbl_lag_dev *ldev,
			    struct nbl_dev_mgt *dev_mst)
{
	struct nbl_service_ops *serv_ops;
	struct nbl_dev_mgt *dev_tmp;
	struct nbl_common_info *common;
	struct nbl_lag_func *pf;
	void *serv_priv;
	struct nbl_lag_member_list_param mbr_prm;
	int i, _tmp;
	u8 eth_id;
	bool lag_en;
	struct nbl_ch_prm_enable_lag_protocol lag_prm;
	struct nbl_ch_prm_cfg_lag_member_fwd fwd_prm;
	struct nbl_ch_prm_cfg_lag_member_up_attr up_prm;

	memset(&mbr_prm, 0, sizeof(mbr_prm));
	nbl_lag_drop_lock(ldev);
	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_PORTS) {
		pf = nbl_lag_pf(ldev, i);
		dev_tmp = pf->pdev;
		serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_tmp);
		common = NBL_DEV_MGT_TO_COMMON(dev_tmp);
		serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_tmp);
		eth_id = NBL_COMMON_TO_ETH_ID(common);
		lag_prm.eth_id = eth_id;
		lag_prm.lag_en = false;
		serv_ops->enable_lag_protocol(serv_priv, &lag_prm);
		up_prm.eth_id = eth_id;
		up_prm.lag_id = 0;
		up_prm.enable = false;
		serv_ops->cfg_lag_member_up_attr(serv_priv, &up_prm);
		fwd_prm.eth_id = eth_id;
		fwd_prm.lag_id = 0;
		fwd_prm.fwd = NBL_LAG_MEM_FWD_DROP;
		serv_ops->cfg_lag_member_fwd(serv_priv, &fwd_prm);
		serv_ops->cfg_lag_member_list(serv_priv, &mbr_prm);
		if (pf->netdev)
			serv_ops->unset_lag_info(serv_priv);
		serv_ops->set_sfp_state(serv_priv, eth_id, true, true);
	}
	nbl_lag_retake_lock(ldev);

	serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_mst);
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mst);
	lag_en = false;
	serv_ops->set_lag_status(serv_priv, &lag_en);

	ldev->mode = NBL_LAG_MODE_NONE;
}

static void nbl_lag_modify(struct nbl_lag_dev *ldev,
			   struct nbl_dev_mgt *dev_mst,
			   struct nbl_lag_tracker *new_trk,
			   struct nbl_lag_tracker *old_trk)
{
	struct nbl_service_ops *serv_ops;
	struct nbl_dev_mgt *dev_tmp;
	struct nbl_common_info *common;
	struct nbl_lag_func *pf;
	void *serv_priv;
	struct nbl_lag_member_list_param mbr_prm;
	int i, _tmp;
	enum nbl_lag_mbr_fwd mbr_fwd;
	u8 eth_id;
	bool old_active, new_active;
	bool old_up, new_up;
	struct nbl_ch_prm_cfg_lag_hash_algorithm hash_prm;
	struct nbl_ch_prm_cfg_lag_member_fwd fwd_prm;
	struct nbl_ch_prm_cfg_lag_member_up_attr up_prm;

	memset(&mbr_prm, 0, sizeof(mbr_prm));
	nbl_lag_form_mem_info(ldev, new_trk, &mbr_prm);
	nbl_lag_drop_lock(ldev);
	nbl_lag_for_each(i, 0, ldev, NBL_LAG_FILTER_PORTS) {
		pf = nbl_lag_pf(ldev, i);
		dev_tmp = pf->pdev;
		serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_tmp);
		common = NBL_DEV_MGT_TO_COMMON(dev_tmp);
		serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_tmp);
		eth_id = NBL_COMMON_TO_ETH_ID(common);
		new_active = nbl_lag_mbr_is_active(new_trk, i);
		old_active = nbl_lag_mbr_is_active(old_trk, i);
		if (new_active != old_active) {
			up_prm.eth_id = eth_id;
			up_prm.lag_id = 0;
			up_prm.enable = new_active;
			serv_ops->cfg_lag_member_up_attr(serv_priv, &up_prm);
			mbr_fwd = new_active ? NBL_LAG_MEM_FWD_NORMAL :
					NBL_LAG_MEM_FWD_DROP;
			fwd_prm.eth_id = eth_id;
			fwd_prm.lag_id = 0;
			fwd_prm.fwd = mbr_fwd;
			serv_ops->cfg_lag_member_fwd(serv_priv, &fwd_prm);
		}

		serv_ops->cfg_lag_member_list(serv_priv, &mbr_prm);
		new_up =  new_trk->netdev_updown[i];
		old_up =  old_trk->netdev_updown[i];
		if (new_up != old_up)
			serv_ops->set_sfp_state(serv_priv, eth_id, new_up,
						true);
	}
	nbl_lag_retake_lock(ldev);

	serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev_mst);
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mst);
	if (new_trk->hash_type != old_trk->hash_type) {
		hash_prm.eth_id = 0;
		hash_prm.lag_id = 0;
		hash_prm.hash_type = new_trk->hash_type;
		serv_ops->cfg_lag_hash_algorithm(serv_priv, &hash_prm);
	}
}

static void nbl_do_bond(struct nbl_lag_dev *ldev)
{
	int idx = nbl_lag_get_dev_index_by_seq(ldev, 0);
	struct nbl_lag_tracker new_trk;
	struct nbl_lag_tracker old_trk;
	struct nbl_dev_mgt *dev0;
	bool do_bond;

	if (idx < 0)
		return;

	dev0 = nbl_lag_pf(ldev, idx)->pdev;
	if (!nbl_lag_is_ready(ldev)) {
		do_bond = false;
	} else {
		new_trk = ldev->new_tracker;
		old_trk = ldev->old_tracker;
		do_bond = new_trk.is_bonded && nbl_lag_check_prereq(ldev);
	}

	if (do_bond && !__nbl_lag_is_active(ldev)) {
		nbl_lag_remove_rdma_adevs(ldev);
		nbl_lag_active(ldev, dev0, &new_trk);
		nbl_lag_add_rdma_bond_adev(ldev, dev0);
	} else if (nbl_lag_should_modify_lag(ldev, do_bond)) {
		nbl_lag_modify(ldev, dev0, &new_trk, &old_trk);
		nbl_dev_rdma_notify_bond_member(dev0);
	} else if (nbl_lag_should_disable_lag(ldev, do_bond)) {
		ldev->mode = NBL_LAG_MODE_NONE;
		nbl_lag_remove_rdma_bond_adev(ldev, dev0);
		nbl_lag_disable(ldev, dev0);
		nbl_lag_add_rdma_adevs(ldev);
	}

	/* copy from tmp new_trk, to avoid ldev->new_tracker change when nbl_lag_modify process */
	ldev->old_tracker = new_trk;
}

static void nbl_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct nbl_lag_dev *ldev = container_of(delayed_work, struct nbl_lag_dev,
						bond_work);
	struct nbl_devcomm_comp_dev *devcomm;
	int status;

	/**
	 * By calling nbl_lag_remove_dev first within nbl_dev_remove_lag_dev
	 * while holding ldev->lock, we ensure that the retrieved devcomm is
	 * not the PF currently being deleted. This prevents accessing a
	 * dangling pointer if the devcomm were to be freed after being
	 * obtained.
	 */

	devcomm = nbl_lag_get_devcomm_comp(ldev);
	if (!devcomm)
		return;

	status = nbl_devcomm_comp_trylock(devcomm);
	if (!status) {
		nbl_queue_bond_work(ldev, HZ);
		return;
	}

	mutex_lock(&ldev->lock);
	if (ldev->mode_changes_in_progress) {
		mutex_unlock(&ldev->lock);
		nbl_devcomm_comp_unlock(devcomm);
		nbl_queue_bond_work(ldev, HZ);
		return;
	}

	nbl_do_bond(ldev);
	mutex_unlock(&ldev->lock);
	nbl_devcomm_comp_unlock(devcomm);
}

/**
 * bond netdev don't know we need headroom, so it will lead we need two desc
 * one packet. now we update bond's headrom
 */
static void nbl_ldev_update_bond_headroom(struct nbl_lag_dev *ldev,
					  struct net_device *bond)
{
	u16 needed_headroom;
	int idx = nbl_lag_get_dev_index_by_seq(ldev, 0);
	struct nbl_dev_mgt *dev0;
	struct nbl_service_ops *serv_ops;
	void *serv_priv;

	if (idx < 0)
		return;

	dev0 = nbl_lag_pf(ldev, idx)->pdev;
	serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev0);
	serv_priv = NBL_DEV_MGT_TO_SERV_PRIV(dev0);
	needed_headroom = serv_ops->get_tx_headroom(serv_priv);
	if (bond->needed_headroom < needed_headroom)
		bond->needed_headroom += needed_headroom;
}

static int nbl_handle_changeupper_event(struct nbl_lag_dev *ldev,
					struct nbl_lag_tracker *tracker,
					struct netdev_notifier_changeupper_info *info)
{
	struct net_device *upper = info->upper_dev, *ndev_tmp;
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	bool is_bonded, is_in_lag, mode_supported;
	bool has_inactive = 0;
	struct nbl_lag_func *pf;
	struct slave *slave;
	int num_slaves = 0;
	int changed = 0;
	int i, _tmp;
	u8 bond_status = 0;

	if (!netif_is_lag_master(upper))
		return 0;

	if (info->linking)
		lag_upper_info = info->upper_info;

	/* The event may still be of interest if the slave does not belong to
	 * us, but is enslaved to a master which has one or more of our netdevs
	 * as slaves (e.g., if a new slave is added to a master that bonds two
	 * of our netdevs, we should unbond).
	 */
	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
		nbl_ldev_for_each(i, 0, ldev) {
			pf = nbl_lag_pf(ldev, i);
			if (pf->netdev == ndev_tmp) {
				bond_status |= (1 << pf->idx);
				break;
			}
		}

		if (i < NBL_MAX_PF) {
			slave = bond_slave_get_rcu(ndev_tmp);
			if (slave)
				has_inactive |= bond_is_slave_inactive(slave);
		}

		num_slaves++;
	}
	rcu_read_unlock();

	netdev_info(upper, "receive update event, bond_status:%x, slave_num:%d\n",
		    bond_status, num_slaves);

	/* None of this lagdev's netdevs are slaves of this master. */
	if (!(bond_status & GENMASK(ldev->ports - 1, 0)))
		return 0;

	if (lag_upper_info) {
		tracker->tx_type = lag_upper_info->tx_type;
		tracker->hash_type = lag_upper_info->hash_type;
	}

	tracker->has_inactive = has_inactive;
	/* Determine bonding status:
	 * A device is considered bonded if both its physical ports are slaves
	 * of the same lag master, and only them.
	 */
	is_in_lag = num_slaves == ldev->ports &&
		bond_status == GENMASK(ldev->ports - 1, 0);

	/* Lag mode must be activebackup or hash. */
	mode_supported = tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP ||
			 tracker->tx_type == NETDEV_LAG_TX_TYPE_HASH;

	is_bonded = is_in_lag && mode_supported;
	if (tracker->is_bonded != is_bonded) {
		tracker->is_bonded = is_bonded;
		changed = 1;
	}

	if (!is_in_lag)
		return changed;

	if (tracker->is_bonded)
		nbl_ldev_update_bond_headroom(ldev, upper);

	if (!nbl_lag_is_ready(ldev))
		netdev_info(upper, "lag dev is not ready\n");
	else if (!mode_supported)
		netdev_info(upper, "bond mode is not support hardware offload\n");

	return changed;
}

static int nbl_handle_changelowerstate_event(struct nbl_lag_dev *ldev,
					     struct nbl_lag_tracker *tracker,
					     struct net_device *ndev,
					     struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	int idx;

	if (!netif_is_lag_port(ndev))
		return 0;

	idx = nbl_lag_dev_get_netdev_idx(ldev, ndev);
	if (idx < 0)
		return 0;

	lag_lower_info = info->lower_state_info;
	if (!lag_lower_info)
		return 0;

	tracker->netdev_state[idx] = *lag_lower_info;
	netdev_info(ndev, "receive lower_state event, link_up:%d, tx_enable:%d\n",
		    lag_lower_info->link_up, lag_lower_info->tx_enabled);

	return 1;
}

/**
 * netdev add to bond, kernel will notify member up first(now has't
 * netif_lag_port) . so can't check netif_is_lag_port
 */
static int nbl_handle_ndev_up_event(struct nbl_lag_dev *ldev, bool up,
				    struct nbl_lag_tracker *tracker,
				    struct net_device *ndev)
{
	int idx;

	idx = nbl_lag_dev_get_netdev_idx(ldev, ndev);
	if (idx < 0)
		return 0;

	tracker->netdev_updown[idx] = up;
	netdev_info(ndev, "receive netdev %s event\n", up ? "up" : "down");

	return 1;
}

/**
 * netdev add to bond, must set down first. so it can check netif_is_lag_port
 */
static int nbl_handle_ndev_down_event(struct nbl_lag_dev *ldev, bool up,
				      struct nbl_lag_tracker *tracker,
				      struct net_device *ndev)
{
	int idx;

	if (!netif_is_lag_port(ndev))
		return 0;

	idx = nbl_lag_dev_get_netdev_idx(ldev, ndev);
	if (idx < 0)
		return 0;

	tracker->netdev_updown[idx] = up;
	netdev_info(ndev, "receive netdev %s event\n", up ? "up" : "down");

	return 1;
}

static int nbl_handle_changeinfodata_event(struct nbl_lag_dev *ldev,
					   struct nbl_lag_tracker *tracker,
					   struct net_device *ndev)
{
	struct net_device *ndev_tmp;
	struct slave *slave;
	bool has_inactive = 0;
	int idx;

	if (!netif_is_lag_master(ndev))
		return 0;

	rcu_read_lock();
	for_each_netdev_in_bond_rcu(ndev, ndev_tmp) {
		idx = nbl_lag_dev_get_netdev_idx(ldev, ndev_tmp);
		if (idx < 0)
			continue;

		slave = bond_slave_get_rcu(ndev_tmp);
		if (slave)
			has_inactive |= bond_is_slave_inactive(slave);
	}
	rcu_read_unlock();

	if (tracker->has_inactive == has_inactive)
		return 0;

	tracker->has_inactive = has_inactive;
	netdev_info(ndev, "receive info change event, inactive:%d\n", has_inactive);

	return 1;
}

static int nbl_lag_netdev_event(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct nbl_lag_tracker tracker;
	struct nbl_lag_dev *ldev;
	int changed = 0;

	if (event != NETDEV_CHANGEUPPER &&
	    event != NETDEV_CHANGELOWERSTATE &&
	    event != NETDEV_CHANGEINFODATA &&
	    event != NETDEV_DOWN &&
	    event != NETDEV_UP)
		return NOTIFY_DONE;

	ldev    = container_of(this, struct nbl_lag_dev, nb);
	tracker = ldev->new_tracker;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		changed = nbl_handle_changeupper_event(ldev, &tracker, ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		changed = nbl_handle_changelowerstate_event(ldev, &tracker,
							    ndev, ptr);
		break;
	case NETDEV_CHANGEINFODATA:
		changed = nbl_handle_changeinfodata_event(ldev, &tracker, ndev);
		break;
	case NETDEV_DOWN:
		changed = nbl_handle_ndev_down_event(ldev, false, &tracker,
						     ndev);
		break;
	case NETDEV_UP:
		changed = nbl_handle_ndev_up_event(ldev, true, &tracker, ndev);
		break;
	}

	ldev->new_tracker = tracker;
	if (changed)
		nbl_queue_bond_work(ldev, 0);

	return NOTIFY_DONE;
}

int nbl_dev_dump_ldev(void *p, struct seq_file *m)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)
					NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_lag_dev *ldev;
	struct nbl_lag_func *pf;
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_lag_tracker new_trk, old_trk;
	int i, _tmp;

	nbl_lag_devcomm_lock(dev_mgt);
	ldev = NBL_DEV_MGT_TO_LAG_DEV(dev_mgt);
	if (!ldev) {
		seq_puts(m, "ldev not support\n");
		goto out;
	}

	new_trk = ldev->new_tracker;
	old_trk = ldev->old_tracker;
	seq_printf(m, "ldev number: %d\n", nbl_lag_get_pf_num(ldev));
	nbl_ldev_for_each(i, 0, ldev) {
		pf = nbl_lag_pf(ldev, i);
		common = NBL_DEV_MGT_TO_COMMON(pf->pdev);
		seq_printf(m, "ldev idx: %d, pci: %s\n",
			   i, pci_name(NBL_COMMON_TO_PDEV(common)));
		seq_printf(m, "new link_up: %d, tx_enabled: %d, up: %d\n",
			   new_trk.netdev_state[i].link_up,
			   new_trk.netdev_state[i].tx_enabled,
			   new_trk.netdev_updown[i]);
		seq_printf(m, "old link_up: %d, tx_enabled: %d, up: %d\n",
			   old_trk.netdev_state[i].link_up,
			   old_trk.netdev_state[i].tx_enabled,
			   old_trk.netdev_updown[i]);
	}

	seq_printf(m, "new bond_mode: %d, hash_type: %d, bonded: %d\n",
		   new_trk.tx_type, new_trk.hash_type, new_trk.is_bonded);
	seq_printf(m, "old bond_mode: %d, hash_type: %d, bonded: %d\n",
		   old_trk.tx_type, old_trk.hash_type, old_trk.is_bonded);

out:
	nbl_lag_devcomm_unlock(dev_mgt);

	return 0;
}
