// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/etherdevice.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include "common/vport.h"
#include "eswitch.h"
#include "common/xsc_lag.h"
#include "devlink.h"
#include "eswitch_offloads.h"
#include "eswitch_legacy.h"

static int xsc_eswitch_check(const struct xsc_core_device *dev)
{
	if (!ESW_ALLOWED(dev->priv.eswitch))
		return -EPERM;
	if (!dev->priv.eswitch->num_vfs)
		return -EOPNOTSUPP;

	return 0;
}

/**
 * xsc_esw_hold() - Try to take a read lock on esw mode lock.
 * @xdev: xsc core device.
 *
 * Should be called by esw resources callers.
 *
 * Return: true on success or false.
 */
bool xsc_esw_hold(struct xsc_core_device *xdev)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	/* e.g. VF doesn't have eswitch so nothing to do */
	if (!ESW_ALLOWED(esw))
		return true;

	if (down_read_trylock(&esw->mode_lock) != 0) {
		if (esw->eswitch_operation_in_progress) {
			up_read(&esw->mode_lock);
			return false;
		}
		return true;
	}

	return false;
}
EXPORT_SYMBOL(xsc_esw_hold);

/**
 * xsc_esw_release() - Release a read lock on esw mode lock.
 * @xdev: xsc core device.
 */
void xsc_esw_release(struct xsc_core_device *xdev)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	if (ESW_ALLOWED(esw))
		up_read(&esw->mode_lock);
}
EXPORT_SYMBOL(xsc_esw_release);

/**
 * xsc_esw_get() - Increase esw user count.
 * @mdev: xsc core device.
 */
void xsc_esw_get(struct xsc_core_device *xdev)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	if (ESW_ALLOWED(esw))
		atomic64_inc(&esw->user_count);
}
EXPORT_SYMBOL(xsc_esw_get);

/**
 * xsc_esw_put() - Decrease esw user count.
 * @mdev: xsc core device.
 */
void xsc_esw_put(struct xsc_core_device *xdev)
{
	struct xsc_eswitch *esw = xdev->priv.eswitch;

	if (ESW_ALLOWED(esw))
		atomic64_dec_if_positive(&esw->user_count);
}
EXPORT_SYMBOL(xsc_esw_put);

/**
 * xsc_esw_try_lock() - Take a write lock on esw mode lock.
 * @esw: eswitch device.
 *
 * Should be called by esw mode change routine.
 *
 * Return:
 * * 0       - esw mode if successfully locked and refcount is 0.
 * * -EBUSY  - refcount is not 0.
 * * -EINVAL - In the middle of switching mode or lock is already held.
 */
int xsc_esw_try_lock(struct xsc_eswitch *esw)
{
	if (down_write_trylock(&esw->mode_lock) == 0)
		return -EINVAL;

	if (esw->eswitch_operation_in_progress ||
	    atomic64_read(&esw->user_count) > 0) {
		up_write(&esw->mode_lock);
		return -EBUSY;
	}

	return esw->mode;
}

int xsc_esw_lock(struct xsc_eswitch *esw)
{
	down_write(&esw->mode_lock);

	if (esw->eswitch_operation_in_progress) {
		up_write(&esw->mode_lock);
		return -EBUSY;
	}

	return 0;
}

/**
 * xsc_esw_unlock() - Release write lock on esw mode lock
 * @esw: eswitch device.
 */
void xsc_esw_unlock(struct xsc_eswitch *esw)
{
	up_write(&esw->mode_lock);
}

struct xsc_vport *__must_check
xsc_eswitch_get_vport(struct xsc_eswitch *esw, u16 vport_num)
{
	u16 idx;

	if (!esw || !xsc_core_is_vport_manager(esw->dev))
		return ERR_PTR(-EPERM);

	idx = xsc_eswitch_vport_num_to_index(esw, vport_num);
	if (idx > esw->total_vports - 1) {
		xsc_core_dbg(esw->dev, "vport out of range: num(0x%x), idx(0x%x)\n",
			     vport_num, idx);
		return ERR_PTR(-EINVAL);
	}

	return &esw->vports[idx];
}
EXPORT_SYMBOL(xsc_eswitch_get_vport);

static bool is_esw_manager_vport(const struct xsc_eswitch *esw, u16 vport_num)
{
	return esw->manager_vport == vport_num;
}

static int esw_mode_from_devlink(u16 mode, u16 *xsc_mode)
{
	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		*xsc_mode = XSC_ESWITCH_LEGACY;
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		*xsc_mode = XSC_ESWITCH_OFFLOADS;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int esw_mode_to_devlink(u16 xsc_mode, u16 *mode)
{
	switch (xsc_mode) {
	case XSC_ESWITCH_LEGACY:
		*mode = DEVLINK_ESWITCH_MODE_LEGACY;
		break;
	case XSC_ESWITCH_OFFLOADS:
		*mode = DEVLINK_ESWITCH_MODE_SWITCHDEV;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int xsc_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode
				  , struct netlink_ext_ack *extack
				)
{
	struct xsc_core_device *dev = devlink_priv(devlink);
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u16 cur_xsc_mode, xsc_mode = XSC_ESWITCH_NONE;
	int err = 0;

	err = xsc_eswitch_check(dev);
	if (err)
		return err;

	if (esw_mode_from_devlink(mode, &xsc_mode))
		return -EINVAL;

	err = xsc_esw_try_lock(esw);
	if (err < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Can't change mode, E-Switch is busy");
		return err;
	}

	cur_xsc_mode = err;
	if (xsc_mode == cur_xsc_mode)
		goto unlock;

	if (xsc_host_is_dpu_mode(dev) ||
	    (cur_xsc_mode != XSC_ESWITCH_LEGACY && xsc_mode == XSC_ESWITCH_OFFLOADS) ||
	    (cur_xsc_mode == XSC_ESWITCH_OFFLOADS && xsc_mode == XSC_ESWITCH_LEGACY)) {
		xsc_core_err(dev, "%s failed: do not set mode %d to mode %d\n",
			     __func__, cur_xsc_mode, xsc_mode);
		err = -EOPNOTSUPP;
		goto unlock;
	}

	if (xsc_mode == XSC_ESWITCH_OFFLOADS &&
	    esw->offloads.rep_mode == XSC_REP_MODE_KERNEL &&
	    !is_support_tc_offload(esw->dev)) {
		xsc_core_info(esw->dev, "kernel rep is not support!\n");
		err = -EOPNOTSUPP;
		goto unlock;
	}

	esw->eswitch_operation_in_progress = true;
	up_write(&esw->mode_lock);

	if (xsc_mode == XSC_ESWITCH_OFFLOADS) {
		xsc_lag_disable(dev);

		err = xsc_cmd_modify_hca(dev);
		if (err)
			goto err_modify_hca;

		if (esw->offloads.rep_mode == XSC_REP_MODE_KERNEL)
			esw_legacy_disable(esw);

		esw->mode = XSC_ESWITCH_OFFLOADS;

		if (esw->offloads.rep_mode == XSC_REP_MODE_KERNEL &&
		    !esw->offloads.rep_established)
			err = esw_offloads_start(esw);

err_modify_hca:
		if (err)
			esw->mode = cur_xsc_mode;

		xsc_lag_enable(dev);
	}

	down_write(&esw->mode_lock);
	esw->eswitch_operation_in_progress = false;
unlock:
	xsc_esw_unlock(esw);
	return err;
}

int xsc_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct xsc_core_device *dev = devlink_priv(devlink);
	struct xsc_eswitch *esw = dev->priv.eswitch;
	int err = 0;

	err = xsc_eswitch_check(dev);
	if (err)
		return err;

	xsc_esw_lock(esw);
	if (xsc_host_is_dpu_mode(dev))
		err = -EOPNOTSUPP;
	else
		err = esw_mode_to_devlink(esw->mode, mode);
	xsc_esw_unlock(esw);

	return err;
}

bool is_xdev_switchdev_mode(const struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw = dev->priv.eswitch;

	return (esw->mode == XSC_ESWITCH_OFFLOADS);
}
EXPORT_SYMBOL_GPL(is_xdev_switchdev_mode);

static void esw_vport_change_handle_locked(struct xsc_vport *vport)
{
	struct xsc_core_device *dev = vport->dev;
	u8 mac[ETH_ALEN];

	xsc_query_other_nic_vport_mac_address(dev, vport->vport, mac);
}

static void esw_vport_change_handler(struct work_struct *work)
{
	struct xsc_vport *vport =
		container_of(work, struct xsc_vport, vport_change_handler);
	struct xsc_eswitch *esw = vport->dev->priv.eswitch;

	mutex_lock(&esw->state_lock);
	esw_vport_change_handle_locked(vport);
	mutex_unlock(&esw->state_lock);
}

static void xsc_eswitch_enable_vport(struct xsc_eswitch *esw,
			      u16 vport_num,
			      enum xsc_eswitch_vport_event enabled_events)
{
	struct xsc_vport *vport = xsc_eswitch_get_vport(esw, vport_num);

	mutex_lock(&esw->state_lock);
	if (vport->enabled)
		goto unlock_out;

	if (!is_esw_manager_vport(esw, vport_num) &&
	    esw->mode == XSC_ESWITCH_LEGACY) {
		xsc_modify_vport_admin_state(esw->dev,
					     vport_num, 1,
					     vport->info.link_state);
	}

	bitmap_zero(vport->req_vlan_bitmap, VLAN_N_VID);
	bitmap_zero(vport->acl_vlan_8021q_bitmap, VLAN_N_VID);
	bitmap_zero(vport->info.vlan_trunk_8021q_bitmap, VLAN_N_VID);

	/* Sync with current vport context */
	vport->enabled_events = enabled_events;
	vport->enabled = true;

	esw->enabled_vports++;
unlock_out:
	mutex_unlock(&esw->state_lock);
}

static void xsc_eswitch_disable_vport(struct xsc_eswitch *esw, u16 vport_num)
{
	struct xsc_vport *vport = xsc_eswitch_get_vport(esw, vport_num);

	mutex_lock(&esw->state_lock);
	if (!vport->enabled)
		goto done;

	xsc_core_dbg(esw->dev, "Disabling vport(%d)\n", vport_num);
	/* Mark this vport as disabled to discard new events */
	vport->enabled = false;
	if (!is_esw_manager_vport(esw, vport_num) &&
	    esw->mode == XSC_ESWITCH_LEGACY) {
		xsc_modify_vport_admin_state(esw->dev,
					     vport_num, 1,
					     XSC_VPORT_ADMIN_STATE_DOWN);
	}
	esw->enabled_vports--;

done:
	mutex_unlock(&esw->state_lock);
}

static void xsc_eswitch_clear_vf_vports_info(struct xsc_eswitch *esw)
{
	struct xsc_vport *vport;
	int i;

	xsc_esw_for_each_vf_vport(esw, i, vport, esw->num_vfs) {
		memset(&vport->info, 0, sizeof(vport->info));
		vport->info.link_state = XSC_VPORT_ADMIN_STATE_AUTO;
		vport->info.vlan_proto = htons(ETH_P_8021Q);
		vport->info.roce = true;
	}
}

static int xsc_eswitch_load_vport(struct xsc_eswitch *esw, u16 vport_num,
				  enum xsc_eswitch_vport_event enabled_events)
{
	int err;

	xsc_eswitch_enable_vport(esw, vport_num, enabled_events);

	err = esw_offloads_rep_load(esw, vport_num);
	if (err)
		goto err_rep;

	return 0;

err_rep:
	xsc_eswitch_disable_vport(esw, vport_num);
	return err;
}

static void xsc_eswitch_unload_vport(struct xsc_eswitch *esw, u16 vport_num)
{
	esw_offloads_unload_rep(esw, vport_num);
	xsc_eswitch_disable_vport(esw, vport_num);
}

static void xsc_eswitch_unload_vf_vports(struct xsc_eswitch *esw, u16 num_vfs)
{
	struct xsc_vport *vport;
	unsigned long i;

	xsc_esw_for_each_vf_vport(esw, i, vport, num_vfs) {
		if (!vport->enabled)
			continue;
		xsc_eswitch_unload_vport(esw, vport->vport);
	}
}

static int xsc_eswitch_load_vf_vports(struct xsc_eswitch *esw, u16 num_vfs,
				      enum xsc_eswitch_vport_event enabled_events)
{
	struct xsc_vport *vport;
	unsigned long i;
	int err;

	xsc_esw_for_each_vf_vport(esw, i, vport, num_vfs) {
		err = xsc_eswitch_load_vport(esw, vport->vport, enabled_events);
		if (err)
			goto vf_err;
	}

	return 0;

vf_err:
	xsc_eswitch_unload_vf_vports(esw, num_vfs);
	return err;
}

int xsc_eswitch_enable_pf_vf_vports(struct xsc_eswitch *esw,
				    enum xsc_eswitch_vport_event enabled_events)
{
	int err = 0;

	if (esw->mode != XSC_ESWITCH_OFFLOADS) {
		err = xsc_eswitch_load_vport(esw, XSC_VPORT_PF, enabled_events);
		if (err)
			return err;
	}

	err = xsc_eswitch_load_vf_vports(esw, esw->num_vfs, enabled_events);
	if (err)
		goto vf_err;

	return 0;

vf_err:
	if (esw->mode != XSC_ESWITCH_OFFLOADS)
		xsc_eswitch_unload_vport(esw, XSC_VPORT_PF);

	return err;
}

void xsc_eswitch_disable_pf_vf_vports(struct xsc_eswitch *esw)
{
	xsc_eswitch_unload_vf_vports(esw, esw->num_vfs);
	xsc_eswitch_unload_vport(esw, XSC_VPORT_PF);
}

int xsc_eswitch_enable_locked(struct xsc_eswitch *esw, int num_vfs)
{
	int err;

	lockdep_assert_held(&esw->mode_lock);

	if (esw->mode == XSC_ESWITCH_LEGACY) {
		esw->num_vfs = num_vfs;
		err = esw_legacy_enable(esw);
	} else {
		err = esw_offloads_enable(esw);
	}

	xsc_core_info(esw->dev, "Enable: mode(%s), rep_mode(%s), nvfs(%d), active_vports(%d), err=%d\n",
		      esw->mode == XSC_ESWITCH_LEGACY ? "LEGACY" : "OFFLOADS",
		      esw->offloads.rep_mode == XSC_REP_MODE_KERNEL ? "kernel" : "dpdk",
		      num_vfs, esw->enabled_vports, err);

	return err;
}

int xsc_eswitch_enable(struct xsc_eswitch *esw, int num_vfs)
{
	int ret;

	down_write(&esw->mode_lock);
	ret = xsc_eswitch_enable_locked(esw, num_vfs);
	up_write(&esw->mode_lock);
	return ret;
}

void xsc_eswitch_disable_locked(struct xsc_eswitch *esw, bool clear_vf)
{
	int old_mode;

	lockdep_assert_held(&esw->mode_lock);

	if (esw->mode == XSC_ESWITCH_NONE)
		return;

	xsc_core_info(esw->dev, "Disable: mode(%s)\n",
		      esw->mode == XSC_ESWITCH_LEGACY ? "LEGACY" : "OFFLOADS");

	if (esw->mode == XSC_ESWITCH_LEGACY)
		esw_legacy_disable(esw);
	else if (esw->mode == XSC_ESWITCH_OFFLOADS)
		esw_offloads_disable(esw);

	old_mode = esw->mode;
	esw->mode = XSC_ESWITCH_NONE;

	if (clear_vf)
		xsc_eswitch_clear_vf_vports_info(esw);

	esw->num_vfs = 0;
}

void xsc_eswitch_disable(struct xsc_eswitch *esw, bool clear_vf)
{
	if (!ESW_ALLOWED(esw))
		return;

	down_write(&esw->mode_lock);
	xsc_eswitch_disable_locked(esw, clear_vf);
	up_write(&esw->mode_lock);
}

static int xsc_esw_vports_init(struct xsc_eswitch *esw)
{
	struct xsc_core_device *dev = esw->dev;
	struct xsc_vport *vport;
	int err = 0;
	int i;

	esw->vports = xsc_vzalloc(esw->total_vports * sizeof(struct xsc_vport));
	if (!esw->vports) {
		xsc_core_err(dev, "failed to alloc mem for eswitch vports\n");
		err = -ENOMEM;
		goto err_out;
	}

	xsc_esw_for_all_vports(esw, i, vport) {
		vport->dev = dev;
		vport->vport = xsc_eswitch_index_to_vport_num(esw, i);
		vport->info.link_state = XSC_VPORT_ADMIN_STATE_AUTO;
		vport->info.vlan_proto = htons(ETH_P_8021Q);
		vport->info.roce = true;

		INIT_WORK(&vport->vport_change_handler, esw_vport_change_handler);
	}

err_out:
	return err;
}

static void xsc_esw_vports_deinit(struct xsc_eswitch *esw)
{
	xsc_vfree(esw->vports);
}

static int xsc_esw_reps_init(struct xsc_eswitch *esw)
{
	struct xsc_core_device *dev = esw->dev;
	struct xsc_eswitch_rep *rep;
	u8 rep_type;
	int vport_index;
	int err = 0;

	mutex_init(&esw->offloads.uplink_netdev_lock);
	esw->offloads.rep_mode = XSC_REP_MODE_DPDK;
	esw->offloads.vport_reps = xsc_vzalloc(esw->total_vports * sizeof(struct xsc_eswitch_rep));
	if (!esw->offloads.vport_reps) {
		xsc_core_err(dev, "failed to alloc mem for eswitch vport_reps\n");
		err = -ENOMEM;
		goto err_out;
	}

	xsc_esw_for_all_reps(esw, vport_index, rep) {
		rep->vport = xsc_eswitch_index_to_vport_num(esw, vport_index);

		for (rep_type = 0; rep_type < NUM_REP_TYPES; rep_type++)
			atomic_set(&rep->rep_data[rep_type].state, REP_UNREGISTERED);
	}

err_out:
	return err;
}

static void xsc_esw_reps_deinit(struct xsc_eswitch *esw)
{
	mutex_destroy(&esw->offloads.uplink_netdev_lock);
	xsc_vfree(esw->offloads.vport_reps);
}

int xsc_eswitch_init(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw;
	int total_vports, err;

	if (!XSC_VPORT_MANAGER(dev)) {
		if (xsc_core_is_pf(dev))
			xsc_core_err(dev, "%s XSC_VPORT_MANAGER check fail\n", __func__);
		return 0;
	}

	total_vports = xsc_eswitch_get_total_vports(dev);

	xsc_core_info(dev, "Total vports %d\n", total_vports);

	esw = kzalloc(sizeof(*esw), GFP_KERNEL);
	if (!esw)
		return -ENOMEM;

	esw->dev = dev;
	esw->manager_vport = xsc_eswitch_manager_vport(dev);
	esw->first_host_vport = xsc_eswitch_first_host_vport_num(dev);
	esw->total_vports = total_vports;

	dev->priv.eswitch = esw;

	esw->work_queue = create_singlethread_workqueue("xsc_esw_wq");
	if (!esw->work_queue) {
		xsc_core_err(dev, "failed to create eswitch work queue\n");
		err = -ENOMEM;
		goto abort;
	}

	err = xsc_esw_vports_init(esw);
	if (err)
		goto err_vport;

	err = xsc_esw_reps_init(esw);
	if (err)
		goto err_offloads;

	mutex_init(&esw->state_lock);
	init_rwsem(&esw->mode_lock);

	esw->enabled_vports = 0;
	esw->mode = XSC_ESWITCH_NONE;

	return 0;

err_offloads:
	xsc_esw_vports_deinit(esw);
err_vport:
	if (esw->work_queue)
		destroy_workqueue(esw->work_queue);
	esw->total_vports = 0;
abort:
	dev->priv.eswitch = NULL;
	kfree(esw);
	return err;
}

void xsc_eswitch_cleanup(struct xsc_core_device *dev)
{
	if (!dev->priv.eswitch || !XSC_VPORT_MANAGER(dev))
		return;

	xsc_core_dbg(dev, "cleanup\n");

	destroy_workqueue(dev->priv.eswitch->work_queue);
	xsc_esw_vports_deinit(dev->priv.eswitch);
	xsc_esw_reps_deinit(dev->priv.eswitch);
}

#ifdef XSC_ESW_GUID_ENABLE
static void node_guid_gen_from_mac(u64 *node_guid, u8 mac[ETH_ALEN])
{
	((u8 *)node_guid)[7] = mac[0];
	((u8 *)node_guid)[6] = mac[1];
	((u8 *)node_guid)[5] = mac[2];
	((u8 *)node_guid)[4] = 0xff;
	((u8 *)node_guid)[3] = 0xfe;
	((u8 *)node_guid)[2] = mac[3];
	((u8 *)node_guid)[1] = mac[4];
	((u8 *)node_guid)[0] = mac[5];
}
#endif

int xsc_eswitch_set_vport_mac(struct xsc_eswitch *esw,
			      u16 vport, u8 mac[ETH_ALEN])
{
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);
	int err = 0;

#ifdef XSC_ESW_GUID_ENABLE
	u64 node_guid;
#endif

	if (IS_ERR(evport))
		return PTR_ERR(evport);

	if (is_multicast_ether_addr(mac))
		return -EINVAL;

	mutex_lock(&esw->state_lock);

	if (evport->info.spoofchk && !is_valid_ether_addr(mac))
		xsc_core_warn(esw->dev,
			      "Set invalid MAC while spoofchk is on, vport(%d)\n",
			      vport);

	err = xsc_modify_other_nic_vport_mac_address(esw->dev, vport, mac, false);
	if (err) {
		xsc_core_err(esw->dev,
			     "Failed to xsc_modify_nic_vport_mac vport(%d) err=(%d)\n",
			     vport, err);
		goto unlock;
	}

	ether_addr_copy(evport->info.mac, mac);

#ifdef XSC_ESW_GUID_ENABLE
	node_guid_gen_from_mac(&node_guid, mac);
	err = xsc_modify_other_nic_vport_node_guid(esw->dev, vport, node_guid);
	if (err)
		xsc_core_err(esw->dev,
			     "Failed to set vport %d node guid, err = %d. RDMA_CM will not function properly for this VF.\n",
			     vport, err);
	evport->info.node_guid = node_guid;
#endif

#ifdef XSC_ESW_FDB_ENABLE
	if (evport->enabled && esw->mode == XSC_ESWITCH_LEGACY)
		err = esw_vport_ingress_config(esw, evport);
#endif

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}
EXPORT_SYMBOL(xsc_eswitch_set_vport_mac);

int xsc_eswitch_get_vport_mac(struct xsc_eswitch *esw,
			      u16 vport, u8 *mac)
{
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);

	if (IS_ERR(evport))
		return PTR_ERR(evport);

	mutex_lock(&esw->state_lock);
	ether_addr_copy(mac, evport->info.mac);
	mutex_unlock(&esw->state_lock);
	return 0;
}

static int __xsc_eswitch_set_vport_vlan(struct xsc_eswitch *esw, int vport, u16 vlan,
					u8 qos, __be16 proto, u8 set_flags)
{
	struct xsc_modify_nic_vport_context_in *in;
	int err, in_sz;

	in_sz = sizeof(struct xsc_modify_nic_vport_context_in) + 2;

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select.addresses_list = 1;
	if ((set_flags & SET_VLAN_STRIP) || (set_flags & SET_VLAN_INSERT))
		in->nic_vport_ctx.vlan_allowed = 1;
	else
		in->nic_vport_ctx.vlan_allowed = 0;
	in->vport_number = cpu_to_be16(vport);
	in->other_vport = 1;
	in->nic_vport_ctx.allowed_list_type = XSC_NVPRT_LIST_TYPE_VLAN_OFFLOAD;
	in->nic_vport_ctx.vlan_proto = cpu_to_be16(ntohs(proto));
	in->nic_vport_ctx.qos = qos;
	in->nic_vport_ctx.vlan = cpu_to_be16(vlan);

	err = xsc_modify_nic_vport_context(esw->dev, in, in_sz);
	kfree(in);

	if (err == EBUSY) {
		xsc_core_err(esw->dev,
			     "Failed to set vport%d vlan vst mode because vlan strip exist.\n",
			     vport);
		xsc_core_err(esw->dev,
			     "<ethtool -K eth0 rxvlan off> to disable vlan strip and try again\n");
	}

	return err;
}

int xsc_eswitch_set_vport_vlan(struct xsc_eswitch *esw, int vport,
			       u16 vlan, u8 qos, __be16 vlan_proto)
{
	u8 set_flags = 0;
	int err = 0;

	if (!ESW_ALLOWED(esw))
		return -EPERM;

	if (vlan || qos)
		set_flags = SET_VLAN_STRIP | SET_VLAN_INSERT;
	else
		set_flags = CLR_VLAN_STRIP | CLR_VLAN_INSERT;

	mutex_lock(&esw->state_lock);
	if (esw->mode != XSC_ESWITCH_LEGACY) {
		if (!vlan)
			goto unlock;

		err = -EOPNOTSUPP;
		goto unlock;
	}

	err = __xsc_eswitch_set_vport_vlan(esw, vport, vlan, qos, vlan_proto, set_flags);

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_eswitch_set_vport_vlan);

static int xsc_vport_link2ifla(u8 esw_link)
{
	switch (esw_link) {
	case XSC_VPORT_ADMIN_STATE_DOWN:
		return IFLA_VF_LINK_STATE_DISABLE;
	case XSC_VPORT_ADMIN_STATE_UP:
		return IFLA_VF_LINK_STATE_ENABLE;
	}
	return IFLA_VF_LINK_STATE_AUTO;
}

static int xsc_ifla_link2vport(u8 ifla_link)
{
	switch (ifla_link) {
	case IFLA_VF_LINK_STATE_DISABLE:
		return XSC_VPORT_ADMIN_STATE_DOWN;
	case IFLA_VF_LINK_STATE_ENABLE:
		return XSC_VPORT_ADMIN_STATE_UP;
	}
	return XSC_VPORT_ADMIN_STATE_AUTO;
}

int xsc_eswitch_set_vport_state(struct xsc_eswitch *esw,
				u16 vport, int link_state)
{
	u8 xsc_link = xsc_ifla_link2vport((u8)link_state);
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);
	int err = 0;

	if (!ESW_ALLOWED(esw))
		return -EPERM;

	if (IS_ERR(evport))
		return PTR_ERR(evport);

	mutex_lock(&esw->state_lock);
	err = xsc_modify_vport_admin_state(esw->dev, vport, 1, xsc_link);
	if (err) {
		xsc_core_warn(esw->dev,
			      "Failed to set vport %d link state %d, err = %d",
			      vport, xsc_link, err);
		goto unlock;
	}

	evport->info.link_state = xsc_link;

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}
EXPORT_SYMBOL(xsc_eswitch_set_vport_state);

int xsc_eswitch_set_vport_spoofchk(struct xsc_eswitch *esw,
				   u16 vport, u8 spoofchk)
{
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);
	bool pschk;
	int err = 0;

	if (!ESW_ALLOWED(esw))
		return -EPERM;
	if (IS_ERR(evport))
		return PTR_ERR(evport);

	mutex_lock(&esw->state_lock);
	if (esw->mode != XSC_ESWITCH_LEGACY) {
		err = -EOPNOTSUPP;
		goto unlock;
	}

	pschk = evport->info.spoofchk;
	evport->info.spoofchk = spoofchk;
	if (spoofchk && !is_valid_ether_addr(evport->info.mac))
		xsc_core_warn(esw->dev, "Spoofchk in set while MAC is invalid, vport(%d)\n",
			      evport->vport);

	if (pschk != spoofchk) {
		err = xsc_modify_nic_vport_spoofchk(esw->dev, vport, spoofchk);
		if (err)
			evport->info.spoofchk = pschk;
	}

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}
EXPORT_SYMBOL(xsc_eswitch_set_vport_spoofchk);

static int xsc_eswitch_update_vport_trunk(struct xsc_eswitch *esw,
					  struct xsc_vport *evport,
					  unsigned long *old_trunk)
{
	DECLARE_BITMAP(diff_vlan_bm, VLAN_N_VID);
	int err = 0;

	bitmap_xor(diff_vlan_bm, old_trunk,
		   evport->info.vlan_trunk_8021q_bitmap, VLAN_N_VID);
	if (!bitmap_weight(diff_vlan_bm, VLAN_N_VID))
		return err;

	if (err)
		bitmap_copy(evport->info.vlan_trunk_8021q_bitmap, old_trunk, VLAN_N_VID);

	return err;
}

int xsc_eswitch_add_vport_trunk_range(struct xsc_eswitch *esw,
				      int vport, u16 start_vlan, u16 end_vlan)
{
	DECLARE_BITMAP(prev_vport_bitmap, VLAN_N_VID);
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);
	int err = 0;

	if (!ESW_ALLOWED(esw))
		return -EPERM;
	if (IS_ERR(evport))
		return PTR_ERR(evport);

	if (end_vlan > VLAN_N_VID || start_vlan > end_vlan)
		return -EINVAL;

	mutex_lock(&esw->state_lock);

	if (evport->info.vlan || evport->info.qos) {
		err = -EPERM;
		xsc_core_warn(esw->dev,
			      "VGT+ is not allowed when operating in VST mode vport(%d)\n",
			      vport);
		goto unlock;
	}

	bitmap_copy(prev_vport_bitmap, evport->info.vlan_trunk_8021q_bitmap,
		    VLAN_N_VID);
	bitmap_set(evport->info.vlan_trunk_8021q_bitmap, start_vlan,
		   end_vlan - start_vlan + 1);
	err = xsc_eswitch_update_vport_trunk(esw, evport, prev_vport_bitmap);

unlock:
	mutex_unlock(&esw->state_lock);

	return err;
}

int xsc_eswitch_del_vport_trunk_range(struct xsc_eswitch *esw,
				      int vport, u16 start_vlan, u16 end_vlan)
{
	DECLARE_BITMAP(prev_vport_bitmap, VLAN_N_VID);
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);
	int err = 0;

	if (!ESW_ALLOWED(esw))
		return -EPERM;
	if (IS_ERR(evport))
		return PTR_ERR(evport);

	if (end_vlan > VLAN_N_VID || start_vlan > end_vlan)
		return -EINVAL;

	mutex_lock(&esw->state_lock);
	bitmap_copy(prev_vport_bitmap, evport->info.vlan_trunk_8021q_bitmap,
		    VLAN_N_VID);
	bitmap_clear(evport->info.vlan_trunk_8021q_bitmap, start_vlan,
		     end_vlan - start_vlan + 1);
	err = xsc_eswitch_update_vport_trunk(esw, evport, prev_vport_bitmap);
	mutex_unlock(&esw->state_lock);

	return err;
}

int xsc_eswitch_set_vport_trust(struct xsc_eswitch *esw,
				u16 vport_num, bool setting)
{
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport_num);
	int err = 0;

	if (!ESW_ALLOWED(esw))
		return -EPERM;
	if (IS_ERR(evport))
		return PTR_ERR(evport);

	mutex_lock(&esw->state_lock);
	if (esw->mode != XSC_ESWITCH_LEGACY) {
		err = -EOPNOTSUPP;
		goto unlock;
	}
	if (setting != evport->info.trusted) {
		err = xsc_modify_nic_vport_trust(esw->dev, vport_num, setting);
		if (err)
			goto unlock;

		evport->info.trusted = setting;
	}

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}
EXPORT_SYMBOL(xsc_eswitch_set_vport_trust);

int xsc_eswitch_set_vport_rate(struct xsc_eswitch *esw, u16 vport,
			       u32 max_rate, u32 min_rate)
{
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);
	int err = 0;

	if (IS_ERR(evport))
		return PTR_ERR(evport);

	mutex_lock(&esw->state_lock);
	err = xsc_modify_vport_max_rate(evport->dev, vport, max_rate);
	if (!err) {
		evport->info.max_rate = max_rate;
		evport->info.min_rate = min_rate;
	}
	mutex_unlock(&esw->state_lock);

	return err;
}
EXPORT_SYMBOL(xsc_eswitch_set_vport_rate);


int xsc_eswitch_get_vport_config(struct xsc_eswitch *esw,
				 u16 vport, struct ifla_vf_info *ivi)
{
	struct xsc_vport *evport = xsc_eswitch_get_vport(esw, vport);

	if (IS_ERR(evport))
		return PTR_ERR(evport);

	memset(ivi, 0, sizeof(*ivi));
	ivi->vf = vport - 1;

	mutex_lock(&esw->state_lock);
	ether_addr_copy(ivi->mac, evport->info.mac);

	ivi->linkstate = xsc_vport_link2ifla(evport->info.link_state);
	ivi->spoofchk = evport->info.spoofchk;
	ivi->trusted = evport->info.trusted;
	ivi->min_tx_rate = evport->info.min_rate;
	ivi->max_tx_rate = evport->info.max_rate;
	ivi->vlan = evport->vlan_id;
	ivi->vlan_proto = evport->vlan_proto;

	mutex_unlock(&esw->state_lock);

	return 0;
}
EXPORT_SYMBOL(xsc_eswitch_get_vport_config);

int xsc_eswitch_vport_update_group(struct xsc_eswitch *esw, int vport_num,
				   u32 group_id)
{
	return 0;
}

int xsc_eswitch_set_vgroup_rate(struct xsc_eswitch *esw, int group_id,
				u32 max_rate)
{
	return 0;
}

int xsc_eswitch_set_vgroup_max_rate(struct xsc_eswitch *esw, int group_id,
				    u32 max_rate)
{
	return 0;
}

int xsc_eswitch_set_vgroup_min_rate(struct xsc_eswitch *esw, int group_id,
				    u32 min_rate)
{
	return 0;
}

int xsc_eswitch_modify_esw_vport_context(struct xsc_eswitch *esw, u16 vport,
					 bool other_vport, void *in, int inlen)
{
	return 0;
}

int xsc_eswitch_query_esw_vport_context(struct xsc_eswitch *esw, u16 vport,
					bool other_vport, void *out, int outlen)
{
	return 0;
}

int xsc_eswitch_get_vport_stats(struct xsc_eswitch *esw,
				u16 vport, struct ifla_vf_stats *vf_stats)
{
	return 0;
}

int xsc_eswitch_query_vport_drop_stats(struct xsc_core_device *dev,
				       struct xsc_vport *vport,
				       struct xsc_vport_drop_stats *stats)
{
	return 0;
}
