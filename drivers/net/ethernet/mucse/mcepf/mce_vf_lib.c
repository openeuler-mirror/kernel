// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/bitops.h>
#include "mce.h"
#include "mce_type.h"
#include "mce_base.h"
#include "mce_lib.h"
#include "mce_sriov.h"
#include "mce_virtchnl.h"
#include "mce_vf_lib.h"

int _vfnum(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	int vfnum = 0;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		vfnum = (vfid == PFINFO_IDX) ? pf->max_vfs : vfid;

	return vfnum;
}

/**
 * mce_check_vf_mac_conflict - check if a MAC would conflict with other VFs in the same VLAN
 * @pf: PF structure
 * @vf_id: VF being configured
 * @mac: MAC address to check
 * @vlan_id: target VLAN ID to check against
 *
 * Returns: 0 on success, -EEXIST if conflict found.
 */
int mce_check_vf_mac_conflict(struct mce_pf *pf, int vf_id, u8 *mac,
			      u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	struct vf_info *tmp_vfinfo;
	int i;

	mce_for_each_pf_vf_id(pf, i) {
		if (i == vf_id)
			continue;
		tmp_vfinfo = &vf->vfinfo[i];
		if (tmp_vfinfo->pf_vlan != vlan_id)
			continue;
		if (ether_addr_equal(mac, tmp_vfinfo->vf_mac_addr)) {
			if (i == PFINFO_IDX)
				dev_err(mce_pf_to_dev(pf),
					"VF %d MAC %pM conflicts with PF in VLAN %d\n",
					vf_id, mac, vlan_id);
			else
				dev_err(&pf->pdev->dev,
					"VF %d MAC %pM conflicts with VF %d in VLAN %d\n",
					vf_id, mac, i, vlan_id);
			return -EEXIST;
		}
	}
	return 0;
}

int mce_vc_check_ipv4_conflict_with_vf(struct mce_pf *pf, int vfid,
				       __be32 ipv4_addr)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo, *tmp_vfinfo;
	int i;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -1;

	vfinfo = &vf->vfinfo[vfid];
	/* Check for IP address conflict within the same VLAN */
	mce_for_each_pf_vf_id(pf, i) {
		if (i == vfid)
			continue;
		tmp_vfinfo = &vf->vfinfo[i];
		/* Only check VFs in the same VLAN (or both without VLAN) */
		if (vfinfo->pf_vlan != tmp_vfinfo->pf_vlan)
			continue;
		/* Skip VFs without IP address configured */
		if (tmp_vfinfo->vf_ipv4_addr == 0)
			continue;
		if (ipv4_addr == tmp_vfinfo->vf_ipv4_addr)
			return i;
	}
	return -1;
}

bool mce_vf_check_any_trust_setuped(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int id;

	mce_for_each_vf_id(pf, id) {
		if (vf->vfinfo[id].trusted)
			return true;
	}
	return false;
}

int mce_vf_set_evb_vepa_mode(struct mce_hw *hw, bool on)
{
	struct mce_pf *pf = hw->back;
	struct mce_vf *vf;
	int id, cnt = 0;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	vf = mce_pf_to_vf(pf);
	if (on) {
		mce_for_each_vf_id(pf, id)
			if (!vf->vfinfo[id].spoofchk_enabled)
				cnt++;
	}

	if (cnt) {
		dev_warn(mce_pf_to_dev(pf),
			 "Cannot turn on veb vepa mode when some vf spoof checking disabled, cnt:%d.\n",
			cnt);
		return -EBUSY;
	}

	if (on) {
		if (!test_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags)) {
			set_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags);
			hw->vf.ops->set_vf_spoofchk_mac(hw, PFINFO_IDX, true,
							true);
			dev_info(mce_pf_to_dev(pf),
				 "Force turn on pf anti-spoof when in evb vepa mode\n");
		}
		hw->ops->set_evb_mode(hw, BRIDGE_MODE_VEPA);
	} else {
		clear_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags);
		hw->vf.ops->set_vf_spoofchk_mac(hw, PFINFO_IDX, false, true);
		dev_info(mce_pf_to_dev(pf),
			 "Force turn off pf anti-spoof when in evb veb mode\n");
		hw->ops->set_evb_mode(hw, BRIDGE_MODE_VEB);
		/* restore trust mode */
		if (mce_vf_check_any_trust_setuped(hw))
			hw->vf.ops->set_vf_trust_vport_en(hw, true);
		else
			hw->vf.ops->set_vf_trust_vport_en(hw, false);
	}
	pf->bridge_mode = on ? BRIDGE_MODE_VEPA : BRIDGE_MODE_VEB;
	return 0;
}

static int mce_vf_get_veb_rule_entry(struct mce_hw *hw, int vfid)
{
	int entry = 0;

	if (vfid == PFINFO_IDX)
		entry = hw->vf_uc_addr_offset - 1;
	else
		entry = hw->vf_uc_addr_offset + vfid;
	return entry;
}

int mce_get_vf_max_supported_queue(struct mce_hw *hw, int *pf0_max_vf_queues,
				   int *pf1_max_vf_queues)
{
	int ret;

	ret = hw->vf.ops->get_vf_max_supported_queue(hw, pf0_max_vf_queues,
						     pf1_max_vf_queues);
	return ret;
}

void mce_vf_cfg_txring_bw_lmt(struct mce_pf *pf, int vf_id, int max_tx_rate)
{
	struct mce_hw *hw = &pf->hw;

	hw->vf.ops->set_vf_cfg_txring_bw_lmt(hw, vf_id, max_tx_rate);
}

bool mce_check_vf_redir_filters_active(struct vf_info *vfinfo)
{
	if (vfinfo->fdir_active_fltr || vfinfo->tcpsync.valid)
		return true;
	return false;
}

int mce_check_vf_no_ready_for_cfg(struct vf_info *vfinfo)
{
	if (!vfinfo->init_done)
		return -EBUSY;
	return 0;
}

int mce_vf_del_all_vlan(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;
	int i;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	vfinfo = &vf->vfinfo[vfid];

	for (i = 0; i < MCE_MAX_VF_VLAN_WHITE_LISTS; i++) {
		if (vfinfo->vf_vlan[i].vid)
			mce_vf_del_flr_vlan(pf, vfid, vfinfo->vf_vlan[i].vid);
	}
	return 0;
}

int mce_vf_clear_all_vlan_and_restore_pf_vlan(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;
	/* clear all vf vlan */
	mce_vf_del_all_vlan(hw, vfid);
	/* restore pf_vlan */
	vfinfo = &vf->vfinfo[vfid];
	if (vfinfo->pf_vlan)
		mce_vf_setup_flr_vlan(pf, vfid, vfinfo->pf_vlan);
	return 0;
}

int mce_vf_handle_flr_intr(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	hw_logd(LOG_MISC_IRQ, "trigger vf:%d flr interrput\n", vfid);
	vfinfo = &vf->vfinfo[vfid];
	/* init_done is true when virtual machine force shutdown */
	if (!vfinfo->init_done)
		return 0;
	vfinfo->init_done = false;
	mce_vf_clear_all_vlan_and_restore_pf_vlan(hw, vfid);
	return 0;
}

int mce_vf_force_close_and_wait_done(struct mce_pf *pf)
{
	struct mce_mbx_info *vf_mbx;
	struct vf_info *vfinfo;
	u32 timeout_us;
	int vfid;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	mce_for_each_vf_id(pf, vfid) {
		vf_mbx = &pf->hw.vf_mbx[vfid];
		vfinfo = vf_mbx->vfinfo;
		if (mce_check_vf_no_ready_for_cfg(vfinfo))
			continue;

		mce_mbx_clear_vf_reset_done_stat(vf_mbx);
		mce_mbx_send_event(vf_mbx, EVT_PF_FORECE_VF_CLOESE, 1000);
	}

#define __MCE_TIMEOUT_STEP_1MS 1000
	/* 5000 ms */
	timeout_us = 5000 * __MCE_TIMEOUT_STEP_1MS;
	while (timeout_us) {
		usleep_range(__MCE_TIMEOUT_STEP_1MS,
			     2 * __MCE_TIMEOUT_STEP_1MS);
		mce_for_each_vf_id(pf, vfid) {
			vf_mbx = &pf->hw.vf_mbx[vfid];
			vfinfo = vf_mbx->vfinfo;
			if (mce_check_vf_no_ready_for_cfg(vfinfo))
				continue;

			/* if 1, force vf close ok, else again */
			if (mce_mbx_get_vf_stat(vf_mbx, VF_RESET_DONE) != 1)
				break;
		}
		if (vfid == pf->num_vfs)
			break;
		timeout_us -= __MCE_TIMEOUT_STEP_1MS;
	}

	if (timeout_us == 0)
		dev_info(mce_pf_to_dev(pf), "%s time out, the last vf id:%d\n",
			 __func__, vfid);

	return 0;
}

void mce_vf_force_open_and_no_wait(struct mce_pf *pf)
{
	struct mce_mbx_info *vf_mbx;
	struct vf_info *vfinfo;
	int vfid;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;

	mce_for_each_vf_id(pf, vfid) {
		vf_mbx = &pf->hw.vf_mbx[vfid];
		vfinfo = vf_mbx->vfinfo;
		if (mce_check_vf_no_ready_for_cfg(vfinfo))
			continue;

		mce_mbx_send_event(vf_mbx, EVT_PF_FORECE_VF_OPEN, 1000);
	}
}

struct mce_vsi *mce_get_vf_vsi(struct mce_pf *pf, int vf_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);

	if (vf->vfinfo[vf_id].lan_vsi_idx == MCE_NO_VSI)
		return NULL;

	return pf->vsi[vf->vfinfo[vf_id].lan_vsi_idx];
}

static int mce_vf_find_vlan_loc(struct mce_pf *pf, int vf_id,
				u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int i = 0;

	for (i = 0; i < MCE_MAX_VF_VLAN_WHITE_LISTS; i++) {
		if (vf->vfinfo[vf_id].vf_vlan[i].vid == vlan_id)
			return i;
	}
	return -1;
}

int mce_vf_setup_flr_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int loc, avail_id;

	loc = mce_vf_find_vlan_loc(pf, vf_id, vlan_id);
	if (loc >= 0) {
		/* if pf not use it, just set it */
		if (test_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags)) {
			if (!vf->vfinfo[vf_id].vf_vlan[loc].pf_used) {
				vf->vfinfo[vf_id].vf_vlan[loc].pf_used = true;
				return 0;
			}
		} else {
			if (!vf->vfinfo[vf_id].vf_vlan[loc].vf_used) {
				vf->vfinfo[vf_id].vf_vlan[loc].vf_used = true;
				return 0;
			}
		}
		/* maybe ctags stags */
		dev_info(mce_hw_to_dev(hw),
			 "%s vf:%d vlan id:%d had beed setuped, exit\n",
			 __func__, _vfnum(hw, vf_id), vlan_id);
		return -1;
	}

	avail_id = find_first_zero_bit(vf->vfinfo[vf_id].avail_vlan,
				       MCE_MAX_VF_VLAN_WHITE_LISTS);
	if (avail_id >= MCE_MAX_VF_VLAN_WHITE_LISTS) {
		dev_info(mce_hw_to_dev(hw),
			 "%s vf:%d the vlan nums exceeds maximum allowed:%d\n",
			 __func__, _vfnum(hw, vf_id),
			 MCE_MAX_VF_VLAN_WHITE_LISTS);
		return -ENOMEM;
	}
	set_bit(avail_id, vf->vfinfo[vf_id].avail_vlan);
	vf->vfinfo[vf_id].vf_vlan[avail_id].vid = vlan_id;
	if (test_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags))
		vf->vfinfo[vf_id].vf_vlan[avail_id].pf_used = true;
	else
		vf->vfinfo[vf_id].vf_vlan[avail_id].vf_used = true;
	vf->t_info.entry = avail_id;
	vf->t_info.vlanid = vlan_id;
	mce_vf_set_veb_misc_rule(hw, vf_id, VEB_POLICY_TYPE_UC_ADD_VLAN);

	return 0;
}

int mce_vf_del_flr_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int loc;

	loc = mce_vf_find_vlan_loc(pf, vf_id, vlan_id);
	if (loc < 0) {
		dev_info(mce_hw_to_dev(hw),
			 "%s vf:%d vlan id:%d not exist, exit!\n", __func__,
			 _vfnum(hw, vf_id), vlan_id);
		return -1;
	}

	if (test_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags))
		vf->vfinfo[vf_id].vf_vlan[loc].pf_used = false;
	else
		vf->vfinfo[vf_id].vf_vlan[loc].vf_used = false;

	/* only clear pf/vf not used */
	if (!vf->vfinfo[vf_id].vf_vlan[loc].pf_used &&
	    !vf->vfinfo[vf_id].vf_vlan[loc].vf_used) {
		clear_bit(loc, vf->vfinfo[vf_id].avail_vlan);
		vf->t_info.entry = loc;
		mce_vf_set_veb_misc_rule(hw, vf_id, VEB_POLICY_TYPE_UC_DEL_VLAN);
		vf->vfinfo[vf_id].vf_vlan[loc].vid = 0;
		vf->vfinfo[vf_id].vf_vlan[loc].qos = 0;
	}

	return 0;
}

int mce_vf_setup_veb_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;

	vf->t_info.vlanid = vlan_id;
	mce_vf_set_veb_misc_rule(hw, vf_id, VEB_POLICY_TYPE_VEB_ADD_VLAN);
	return 0;
}

int mce_vf_del_veb_vlan(struct mce_pf *pf, int vf_id, u16 vlan_id)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;

	vf->t_info.vlanid = vlan_id;
	mce_vf_set_veb_misc_rule(hw, vf_id, VEB_POLICY_TYPE_VEB_DEL_VLAN);
	return 0;
}

int mce_vf_setup_true_promisc(struct mce_pf *pf)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int i;

	/* turn on pf true promisc */
	hw->vf.ops->set_vf_true_promisc(hw, PFINFO_IDX, true);

	if (!vf || !vf->vfinfo)
		return 0;

	mce_for_each_vf_id(pf, i) {
		if (vf->vfinfo[i].trusted)
			hw->vf.ops->set_vf_true_promisc(hw, i, true);
		else
			hw->vf.ops->set_vf_true_promisc(hw, i, false);
	}

	return 0;
}

int mce_vf_del_true_promisc(struct mce_pf *pf)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int i;

	/* turn on pf true promisc */
	hw->vf.ops->set_vf_true_promisc(hw, PFINFO_IDX, false);

	if (!vf || !vf->vfinfo)
		return 0;

	mce_for_each_vf_id(pf, i)
		hw->vf.ops->set_vf_true_promisc(hw, i, false);

	return 0;
}

int mce_vf_setup_rqa_tcp_sync_en(struct mce_pf *pf, bool on)
{
	struct mce_hw *hw = &pf->hw;

	/* turn on tcp sync enable */
	hw->vf.ops->set_vf_rqa_tcp_sync_en(hw, on);
	return 0;
}

static int mce_vf_ena_spoofchk(struct mce_pf *pf, int vfid)
{
	struct mce_hw *hw = &pf->hw;

	hw->vf.ops->set_vf_spoofchk_mac(hw, vfid, true, false);

	return 0;
}

static int mce_vf_dis_spoofchk(struct mce_pf *pf, int vfid)
{
	struct mce_hw *hw = &pf->hw;

	hw->vf.ops->set_vf_spoofchk_mac(hw, vfid, false, false);
	return 0;
}

/**
 * mce_vf_apply_spoofchk - Apply Tx spoof checking setting
 * @pf: associated to the pf
 * @vfid: config vf number
 * @enable: whether to enable or disable the spoof checking
 * Returns: The result of the operation.
 */
int mce_vf_apply_spoofchk(struct mce_pf *pf, int vfid, bool enable)
{
	int err;

	if (enable)
		err = mce_vf_ena_spoofchk(pf, vfid);
	else
		err = mce_vf_dis_spoofchk(pf, vfid);
	return err;
}

/**
 * mce_vf_set_trusted - set vf trusted
 * @pf: associated to the pf
 * @vfid: config vf number
 * @enable: whether to enable or disable the spoof checking
 * Returns: The result of the operation.
 */
int mce_vf_set_trusted(struct mce_pf *pf, int vfid, bool enable)
{
	struct mce_hw *hw = &pf->hw;
	int err = 0;

	hw->vf.ops->set_vf_trusted(hw, vfid, enable);
	/* TODO: when trust on, the spoof mac/VLAN enable bit should clear */
	return err;
}

int mce_vf_resync_mc_list(struct mce_pf *pf, bool to_pfvf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;
	struct mce_hw *hw = &pf->hw;
	struct netdev_hw_addr *ha;

	if (netdev_mc_empty(netdev))
		return 0;

	if (to_pfvf) {
		/* clear pfvf multicast addr filter table */
		hw->vf.ops->set_vf_clear_mc_filter(hw, true);
		/* copy pf multicast filter table to pfvf */
		netdev_for_each_mc_addr(ha, netdev)
			hw->vf.ops->set_vf_add_mc_fliter(hw, ha->addr);
	} else {
		/* clear pf multicast filter table*/
		hw->ops->clr_mc_filter(hw);
		spin_lock_bh(&hw->mac_hash_lock);

		netdev_for_each_mc_addr(ha, netdev) {
			bool s_low = hw->uc_mc_hash_ctl.mc_s_low;
			u16 hash_v =
				mce_calc_mac_hash_val(hw, ha->addr, s_low);

			/* clear pfvf multicast filter table */
			hw->vf.ops->set_vf_del_mc_filter(hw, ha->addr);
			hw->ops->add_mc_filter(hw, hash_v);
		}
		spin_unlock_bh(&hw->mac_hash_lock);
	}
	return 0;
}

int mce_vf_resync_vlan_list(struct mce_pf *pf, bool to_pfvf)
{
	struct mce_vlan_list_entry *vlan_entry = NULL;
	struct mce_hw *hw = &pf->hw;
	u16 vid;

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		vid = vlan_entry->vid;
		if (to_pfvf) {
			/* del pf vlan and add pfvf vlan*/
			hw->ops->del_vlan_filter(hw, vid);
			mce_vf_setup_flr_vlan(pf, PFINFO_IDX, vid);
		} else {
			/* del vfpf vlan and add pf vlan */
			mce_vf_del_flr_vlan(pf, PFINFO_IDX, vid);
			hw->ops->add_vlan_filter(hw, vid);
		}
	}

	return 0;
}

static int mce_set_veb_vm_add_uc_macaddr_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = mce_vf_get_veb_rule_entry(hw, vfid);
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);

	return 0;
}

static int mce_set_veb_vm_add_uc_macaddr_with_act_rule(struct mce_hw *hw,
						       int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = mce_vf_get_veb_rule_entry(hw, vfid);
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, true,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int mce_set_veb_vm_add_macvlan_macaddr_with_act_rule(struct mce_hw *hw,
							    int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct tuple4_policy *policy;
	struct list_head *pos;
	int entry = -1;

	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (policy->free) {
			policy->free = false;
			policy->vf = vfid;
			memcpy(policy->mac, vf->t_info.macaddr, ETH_ALEN);
			entry = policy->entry;
			break;
		}
	}

	if (entry == -1) {
		dev_err(mce_pf_to_dev(pf), "no memory for new mac-vlan\n");
		return -ENOMEM;
	}
	/* find a free entry */
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, true,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int mce_set_veb_vm_add_bcmc_macaddr_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	memset(vf->t_info.macaddr, 0xff, ETH_ALEN);
	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);

	return 0;
}

static int mce_set_veb_vm_add_bcmc_macaddr_with_act_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	memset(vf->t_info.macaddr, 0xff, ETH_ALEN);
	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     true);
	hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_BCMC, entry, true,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int mce_set_veb_vm_del_uc_macaddr_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = mce_vf_get_veb_rule_entry(hw, vfid);
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	return 0;
}

static int mce_set_veb_vm_del_uc_macaddr_with_act_rule(struct mce_hw *hw,
						       int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = mce_vf_get_veb_rule_entry(hw, vfid);
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, false,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int mce_set_veb_vm_del_macvlan_macaddr_with_act_rule(struct mce_hw *hw,
							    int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct tuple4_policy *policy;
	struct list_head *pos;
	int entry = -1;

	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (!policy->free && policy->vf == vfid) {
			if (!memcmp(policy->mac, vf->t_info.macaddr, ETH_ALEN)) {
				policy->free = true;
				policy->vf = -1;
				entry = policy->entry;
				break;
			}
		}
	}
	if (entry == -1) {
		dev_err(mce_pf_to_dev(pf), "del not exist mac-vlan?\n");
		return -EINVAL;
	}
	hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	hw->vf.ops->set_vf_set_veb_act(hw, vfid, entry, false,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int mce_set_veb_vm_del_bcmc_macaddr_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	return 0;
}

static int mce_set_veb_vm_del_bcmc_macaddr_with_act_rule(struct mce_hw *hw)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry;

	entry = hw->vf_bcmc_addr_offset;
	hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
					     false);
	hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_BCMC, entry, false,
				       vf->t_info.bcmc_bitmap);
	return 0;
}

static int mce_set_veb_vm_add_uc_vlan_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry = vf->t_info.entry;

	hw->vf.ops->set_vf_add_flr_vlan(hw, vfid, entry);
	return 0;
}

static int mce_set_veb_vm_del_uc_vlan_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry = vf->t_info.entry;

	hw->vf.ops->set_vf_del_flr_vlan(hw, vfid, entry);
	return 0;
}

static int mce_set_veb_vm_add_veb_vlan_rule(struct mce_hw *hw, int vfid)
{
	int entry;

	entry = mce_vf_get_veb_rule_entry(hw, vfid);
	hw->vf.ops->set_vf_add_veb_vlan(hw, vfid, entry);
	return 0;
}

static int mce_set_veb_vm_del_veb_vlan_rule(struct mce_hw *hw, int vfid)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int entry = vf->t_info.entry;

	entry = mce_vf_get_veb_rule_entry(hw, vfid);
	hw->vf.ops->set_vf_del_veb_vlan(hw, vfid, entry);
	return 0;
}

int mce_vf_set_veb_misc_rule(struct mce_hw *hw, int vfid,
			     enum veb_policy_type ptype)
{
	int err = 0;

	if (ptype == VEB_POLICY_TYPE_NONE || ptype >= VEB_POLICY_TYPE_MAX)
		return 0;

	switch (ptype) {
	case VEB_POLICY_TYPE_UC_ADD_MACADDR:
		mce_set_veb_vm_add_uc_macaddr_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT:
		mce_set_veb_vm_add_uc_macaddr_with_act_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_MACVLAN_ADD_MACADDR_WITH_ACT:
		err = mce_set_veb_vm_add_macvlan_macaddr_with_act_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_UC_DEL_MACADDR:
		mce_set_veb_vm_del_uc_macaddr_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_UC_DEL_MACADDR_WITH_ACT:
		mce_set_veb_vm_del_uc_macaddr_with_act_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_MACVLAN_DEL_MACADDR_WITH_ACT:
		mce_set_veb_vm_del_macvlan_macaddr_with_act_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_BCMC_ADD_MACADDR:
		mce_set_veb_vm_add_bcmc_macaddr_rule(hw);
		break;
	case VEB_POLICY_TYPE_BCMC_ADD_MACADDR_WITH_ACT:
		mce_set_veb_vm_add_bcmc_macaddr_with_act_rule(hw);
		break;
	case VEB_POLICY_TYPE_BCMC_DEL_MACADDR:
		mce_set_veb_vm_del_bcmc_macaddr_rule(hw);
		break;
	case VEB_POLICY_TYPE_BCMC_DEL_MACADDR_WITH_ACT:
		mce_set_veb_vm_del_bcmc_macaddr_with_act_rule(hw);
		break;
	case VEB_POLICY_TYPE_UC_ADD_VLAN:
		mce_set_veb_vm_add_uc_vlan_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_UC_DEL_VLAN:
		mce_set_veb_vm_del_uc_vlan_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_VEB_ADD_VLAN:
		mce_set_veb_vm_add_veb_vlan_rule(hw, vfid);
		break;
	case VEB_POLICY_TYPE_VEB_DEL_VLAN:
		mce_set_veb_vm_del_veb_vlan_rule(hw, vfid);
		break;
	default:
		break;
	}

	return err;
}

/**
 * mce_add_pf_macvlan_fltr - Add a PF MACVLAN filter to the VEB table
 * @hw: hardware structure
 * @mac: MAC address to add (addrB in macvtap scenario)
 * @ifindex: network interface index associated with the MACVLAN entry
 *
 * Adds a secondary MAC address for the PF to the VEB table using the
 * dynamic MACVLAN entry pool. This is needed when the PF is passed to
 * a VM via macvtap with a different MAC address than the physical PF.
 *
 * Return: 0 on success, negative on error
 */
int mce_add_pf_macvlan_fltr(struct mce_hw *hw, const u8 *mac, int ifindex)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct tuple4_policy *policy;
	struct list_head *pos;
	bool sriov_ena;
	int entry = -1;

	if (!is_valid_ether_addr(mac)) {
		dev_err(mce_hw_to_dev(hw),
			"PF macvlan: invalid mac addr %pM\n", mac);
		return -EINVAL;
	}

	/* Check for duplicate: skip if MAC already exists for PFINFO_IDX */
	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (!policy->free &&
		    policy->vf == PF_MACVLAN_VF_MARKER &&
		    ether_addr_equal(policy->mac, mac)) {
			dev_info(mce_hw_to_dev(hw),
				 "PF macvlan: mac %pM already in VEB table, skip duplicate add\n",
				 mac);
			return 0;
		}
	}

	/* Find a free tuple4_policy entry and save MAC (always, even if
	 * SR-IOV is off, so it can be programmed later when SR-IOV enables).
	 */
	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (policy->free) {
			policy->free = false;
			policy->vf = PF_MACVLAN_VF_MARKER;
				policy->owner_ifindex = ifindex;
			memcpy(policy->mac, mac, ETH_ALEN);
			entry = policy->entry;
			break;
		}
	}

	if (entry == -1) {
		dev_err(mce_hw_to_dev(hw),
			"PF macvlan: no free VEB entry for mac %pM\n", mac);
		return -ENOMEM;
	}

	sriov_ena = test_bit(MCE_FLAG_SRIOV_ENA, pf->flags);

	if (!sriov_ena) {
		/* SR-IOV not enabled yet: save MAC in software only.
		 * _vfnum() returns 0 when SRIOV is off, which would program
		 * the wrong vport bitmap. The entry will be programmed to
		 * hardware when SR-IOV is enabled via mce_restore_pf_macvlan_fltr().
		 */
		dev_info(mce_hw_to_dev(hw),
			 "PF macvlan: mac %pM saved (SR-IOV off, defer HW program)\n",
			mac);
		return 0;
	}

	/* SR-IOV is enabled: program hardware now with correct vfnum */
	ether_addr_copy(vf->t_info.macaddr, mac);
	vf->t_info.bcmc_bitmap = MCE_F_HOLD;

	hw->ops->update_fltr_macaddr(hw, (u8 *)mac, entry, true);
	hw->vf.ops->set_vf_update_vm_macaddr(hw, (u8 *)mac, entry, true);
	hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_IDX, entry, true, MCE_F_HOLD);

	dev_info(mce_hw_to_dev(hw),
		 "PF macvlan: added mac %pM to VEB table (entry %d)\n", mac,
		 entry);

	return 0;
}

/**
 * mce_del_pf_macvlan_fltr - Delete a PF MACVLAN filter from the VEB table
 * @hw: hardware structure
 * @mac: MAC address to remove
 *
 * Removes a previously added PF MACVLAN entry from the VEB table.
 *
 * Return: 0 on success, negative on error
 */
int mce_del_pf_macvlan_fltr(struct mce_hw *hw, const u8 *mac)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct tuple4_policy *policy;
	struct list_head *pos;
	int entry = -1;

	if (!is_valid_ether_addr(mac)) {
		dev_err(mce_hw_to_dev(hw),
			"PF macvlan: invalid mac addr %pM\n", mac);
		return -EINVAL;
	}

	/* Find the PF MACVLAN entry and free it */
	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (!policy->free &&
		    policy->vf == PF_MACVLAN_VF_MARKER &&
		    ether_addr_equal(policy->mac, mac)) {
			entry = policy->entry;
			/* Save MAC to t_info before memset:
			 * caller may pass policy->mac which
			 * is zeroed below.
			 */
			ether_addr_copy(vf->t_info.macaddr, mac);
			policy->free = true;
			policy->vf = -1;
			memset(policy->mac, 0, ETH_ALEN);
			break;
		}
	}
	if (entry == -1) {
		dev_info(mce_hw_to_dev(hw),
			 "PF macvlan: mac %pM not in VEB table, skip delete\n",
			 mac);
		return 0;
	}

	/* Clear hardware if SR-IOV is enabled (HW was programmed).
	 * Use t_info scratch buffer: update_fltr_macaddr(..., false)
	 * zeros the passed-in buffer; must not corrupt caller's mac.
	 */
	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		hw->ops->update_fltr_macaddr(hw, vf->t_info.macaddr, entry, false);
		hw->vf.ops->set_vf_update_vm_macaddr(hw, vf->t_info.macaddr, entry,
						     false);
		hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_IDX, entry, false,
					       MCE_F_HOLD);
	}

	dev_info(mce_hw_to_dev(hw),
		 "PF macvlan: deleted mac %pM from VEB table (entry %d)\n",
		 mac, entry);

	return 0;
}

/**
 * mce_del_pf_macvlan_by_ifindex - Delete PF MACVLAN entry by owner ifindex
 * @hw: hardware structure
 * @ifindex: netdev ifindex of the owning macvtap device
 *
 * Used when a macvtap changes its MAC address (NETDEV_CHANGEADDR).
 * Finds and removes the stale tuple4_policy entry belonging to the
 * macvtap identified by @ifindex.
 */
void mce_del_pf_macvlan_by_ifindex(struct mce_hw *hw, int ifindex)
{
	struct tuple4_policy *policy;
	struct list_head *pos;

	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (!policy->free &&
		    policy->vf == PF_MACVLAN_VF_MARKER &&
		    policy->owner_ifindex == ifindex) {
			mce_del_pf_macvlan_fltr(hw, policy->mac);
			break;
		}
	}
}

/**
 * mce_restore_pf_macvlan_fltr - Restore all PF MACVLAN filters after HW reset
 * @hw: hardware structure
 *
 * After a hardware reset, all VEB entries are cleared. This function
 * re-programs all PF MACVLAN entries from the tuple4_policy software state.
 */
void mce_restore_pf_macvlan_fltr(struct mce_hw *hw)
{
	struct tuple4_policy *policy;
	struct list_head *pos;

	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (!policy->free && policy->vf == PF_MACVLAN_VF_MARKER) {
			hw->ops->update_fltr_macaddr(hw, policy->mac,
						     policy->entry, true);
			hw->vf.ops->set_vf_update_vm_macaddr(hw, policy->mac,
							     policy->entry, true);
			hw->vf.ops->set_vf_set_veb_act(hw, PFINFO_IDX,
						       policy->entry, true,
						       MCE_F_HOLD);
		}
	}
}

/**
 * mce_cleanup_pf_macvlan_fltr - Clean up all PF MACVLAN filters (SW state only)
 * @hw: hardware structure
 *
 * Frees all PF MACVLAN entries from the tuple4_policy list. Hardware
 * state is assumed to already be cleared (e.g. by mce_reset_hw).
 * Called during SR-IOV disable.
 */
void mce_cleanup_pf_macvlan_fltr(struct mce_hw *hw)
{
	struct tuple4_policy *policy;
	struct list_head *pos;

	list_for_each(pos, &hw->tuple4_policy.l) {
		policy = list_entry(pos, struct tuple4_policy, l);
		if (!policy->free && policy->vf == PF_MACVLAN_VF_MARKER) {
			policy->free = true;
			policy->vf = -1;
			memset(policy->mac, 0, ETH_ALEN);
		}
	}
}
