// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/etherdevice.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include "common/vport.h"
#include "fw/xsc_tbm.h"
#include "eswitch.h"
#include "common/xsc_lag.h"

static int xsc_eswitch_check(const struct xsc_core_device *dev)
{
	if (!ESW_ALLOWED(dev->priv.eswitch))
		return -EPERM;
	if (!dev->priv.eswitch->num_vfs)
		return -EOPNOTSUPP;

	return 0;
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

static int eswitch_devlink_pf_support_check(const struct xsc_eswitch *esw)
{
	return 0;
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

int xsc_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode, struct netlink_ext_ack *extack)
{
	struct xsc_core_device *dev = devlink_priv(devlink);
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u16 cur_xsc_mode, xsc_mode = 0;
	int err = 0;

	err = xsc_eswitch_check(dev);
	if (err)
		return err;

	if (esw_mode_from_devlink(mode, &xsc_mode))
		return -EINVAL;

	mutex_lock(&esw->mode_lock);
	err = eswitch_devlink_pf_support_check(esw);
	if (err)
		goto done;

	cur_xsc_mode = esw->mode;

	if (cur_xsc_mode == xsc_mode)
		goto done;

	if ((cur_xsc_mode != XSC_ESWITCH_LEGACY && xsc_mode == XSC_ESWITCH_OFFLOADS) ||
	    (cur_xsc_mode == XSC_ESWITCH_OFFLOADS && xsc_mode == XSC_ESWITCH_LEGACY)) {
		xsc_core_err(dev, "%s failed: do not set mode %d to mode %d\n",
			     __func__, cur_xsc_mode, xsc_mode);
		mutex_unlock(&esw->mode_lock);
		return -EOPNOTSUPP;
	}

	xsc_lag_disable(dev);
	esw->mode = xsc_mode;
	xsc_lag_enable(dev);

	if (esw->mode == XSC_ESWITCH_OFFLOADS)
		xsc_cmd_modify_hca(dev);

done:
	mutex_unlock(&esw->mode_lock);
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

	mutex_lock(&esw->mode_lock);
	err = esw_mode_to_devlink(esw->mode, mode);
	mutex_unlock(&esw->mode_lock);

	return err;
}

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

void xsc_eswitch_enable_vport(struct xsc_eswitch *esw,
			      struct xsc_vport *vport,
			      enum xsc_eswitch_vport_event enabled_events)
{
	mutex_lock(&esw->state_lock);
	if (vport->enabled)
		goto unlock_out;

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

void xsc_eswitch_disable_vport(struct xsc_eswitch *esw,
			       struct xsc_vport *vport)
{
	u16 vport_num = vport->vport;

	mutex_lock(&esw->state_lock);
	if (!vport->enabled)
		goto done;

	xsc_core_dbg(esw->dev, "Disabling vport(%d)\n", vport_num);
	/* Mark this vport as disabled to discard new events */
	vport->enabled = false;

	/* We don't assume VFs will cleanup after themselves.
	 * Calling vport change handler while vport is disabled will cleanup
	 * the vport resources.
	 */
	vport->enabled_events = 0;
	esw->enabled_vports--;
done:
	mutex_unlock(&esw->state_lock);
}

void xsc_eswitch_enable_pf_vf_vports(struct xsc_eswitch *esw,
				     enum xsc_eswitch_vport_event enabled_events)
{
	struct xsc_vport *vport;
	int i;

	vport = xsc_eswitch_get_vport(esw, XSC_VPORT_PF);
	xsc_eswitch_enable_vport(esw, vport, enabled_events);

	xsc_esw_for_each_vf_vport(esw, i, vport, esw->num_vfs)
		xsc_eswitch_enable_vport(esw, vport, enabled_events);
}

#define XSC_LEGACY_SRIOV_VPORT_EVENTS (XSC_VPORT_UC_ADDR_CHANGE | \
					XSC_VPORT_MC_ADDR_CHANGE | \
					XSC_VPORT_PROMISC_CHANGE | \
					XSC_VPORT_VLAN_CHANGE)

int esw_legacy_enable(struct xsc_eswitch *esw)
{
	struct xsc_vport *vport;
	unsigned long i;

	xsc_esw_for_each_vf_vport(esw, i, vport, esw->num_vfs) {
		vport->info.link_state = XSC_VPORT_ADMIN_STATE_AUTO;
	}
	xsc_eswitch_enable_pf_vf_vports(esw, XSC_LEGACY_SRIOV_VPORT_EVENTS);
	return 0;
}

int xsc_eswitch_enable_locked(struct xsc_eswitch *esw, int mode, int num_vfs)
{
	int err;

	lockdep_assert_held(&esw->mode_lock);

	esw->num_vfs = num_vfs;

	if (esw->mode == XSC_ESWITCH_NONE)
		err = esw_legacy_enable(esw);
	else
		err = -EOPNOTSUPP;

	if (err)
		goto ret;

	esw->mode = mode;

	xsc_core_info(esw->dev, "Enable: mode(%s), nvfs(%d), active vports(%d)\n",
		      mode == XSC_ESWITCH_LEGACY ? "LEGACY" : "OFFLOADS",
		      num_vfs, esw->enabled_vports);

	return 0;

ret:
	return err;
}

int xsc_eswitch_enable(struct xsc_eswitch *esw, int mode, int num_vfs)
{
	int ret;

	mutex_lock(&esw->mode_lock);
	ret = xsc_eswitch_enable_locked(esw, mode, num_vfs);
	mutex_unlock(&esw->mode_lock);
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

	old_mode = esw->mode;
	esw->mode = XSC_ESWITCH_NONE;

	esw->num_vfs = 0;
}

void xsc_eswitch_disable(struct xsc_eswitch *esw, bool clear_vf)
{
	if (!ESW_ALLOWED(esw))
		return;

	mutex_lock(&esw->mode_lock);
	xsc_eswitch_disable_locked(esw, clear_vf);
	mutex_unlock(&esw->mode_lock);
}

int xsc_eswitch_init(struct xsc_core_device *dev)
{
	struct xsc_eswitch *esw;
	struct xsc_vport *vport;
	int i, total_vports, err;

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
	esw->work_queue = create_singlethread_workqueue("xsc_esw_wq");
	if (!esw->work_queue) {
		err = -ENOMEM;
		goto abort;
	}
	esw->vports = kcalloc(total_vports, sizeof(struct xsc_vport),
			      GFP_KERNEL);
	if (!esw->vports) {
		err = -ENOMEM;
		goto abort;
	}
	esw->total_vports = total_vports;

	mutex_init(&esw->state_lock);
	mutex_init(&esw->mode_lock);

	xsc_esw_for_all_vports(esw, i, vport) {
		vport->vport = xsc_eswitch_index_to_vport_num(esw, i);
		vport->info.link_state = XSC_VPORT_ADMIN_STATE_AUTO;
		vport->info.vlan_proto = htons(ETH_P_8021Q);
		vport->info.roce = true;

		vport->dev = dev;
		INIT_WORK(&vport->vport_change_handler,
			  esw_vport_change_handler);
	}
	esw->enabled_vports = 0;
	esw->mode = XSC_ESWITCH_NONE;

	dev->priv.eswitch = esw;
	return 0;

abort:
	if (esw->work_queue)
		destroy_workqueue(esw->work_queue);
	kfree(esw->vports);
	kfree(esw);
	return 0;
}

void xsc_eswitch_cleanup(struct xsc_core_device *dev)
{
	if (!dev->priv.eswitch || !XSC_VPORT_MANAGER(dev))
		return;

	xsc_core_dbg(dev, "cleanup\n");

	destroy_workqueue(dev->priv.eswitch->work_queue);
	kfree(dev->priv.eswitch->vports);
	kfree(dev->priv.eswitch);
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

int __xsc_eswitch_set_vport_vlan(struct xsc_eswitch *esw, int vport, u16 vlan,
				 u8 qos, __be16 proto, u8 set_flags)
{
	return 0;
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
			goto unlock; /* compatibility with libvirt */

		err = -EOPNOTSUPP;
		goto unlock;
	}

	err = __xsc_eswitch_set_vport_vlan(esw, vport, vlan, qos, vlan_proto, set_flags);

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int xsc_eswitch_set_vport_state(struct xsc_eswitch *esw,
				u16 vport, int link_state)
{
	return 0;
}

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
	if (pschk && !is_valid_ether_addr(evport->info.mac))
		xsc_core_warn(esw->dev, "Spoofchk in set while MAC is invalid, vport(%d)\n",
			      evport->vport);

	if (err)
		evport->info.spoofchk = pschk;

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

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
	evport->info.trusted = setting;

unlock:
	mutex_unlock(&esw->state_lock);
	return err;
}

int xsc_eswitch_set_vport_rate(struct xsc_eswitch *esw, u16 vport,
			       u32 max_rate, u32 min_rate)
{
	return 0;
}

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
