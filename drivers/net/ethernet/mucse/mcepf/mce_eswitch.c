// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include "mce.h"
#include "mce_fdir.h"
#include "mce_lib.h"
#include "mce_eswitch.h"
#include "mce_fltr.h"
#include "mce_devlink.h"
#include "mce_vf_lib.h"
#include "mce_npu.h"

/**
 * mce_eswitch_mode_get - get current eswitch mode
 * @devlink: pointer to devlink structure
 * @mode: output parameter for current eswitch mode
 * Returns: The result of the operation.
 */
int mce_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct mce_pf *pf = devlink_priv(devlink);

	*mode = pf->eswitch_mode;
	return 0;
}

static int mce_eswitch_setup_reprs(struct mce_pf __always_unused *pf)
{
	return -ENODEV;
}

static void mce_eswitch_release_reprs(struct mce_pf __always_unused *pf)
{
}

/**
 * mce_eswitch_setup_env - configure switchdev HW filters
 * @pf: pointer to PF struct
 *
 * This function clears uplink unicast and multicast sync state used for
 * switchdev mode.
 * Returns: The result of the operation.
 */
static int __maybe_unused mce_eswitch_setup_env(struct mce_pf *pf)
{
	struct mce_vsi *uplink_vsi = pf->switchdev.uplink_vsi;
	struct net_device *uplink_netdev = uplink_vsi->netdev;

	netif_addr_lock_bh(uplink_netdev);
	__dev_uc_unsync(uplink_netdev, NULL);
	__dev_mc_unsync(uplink_netdev, NULL);
	netif_addr_unlock_bh(uplink_netdev);
	return 0;
}

/**
 * mce_eswitch_napi_enable - enable NAPI for all port representors
 * @pf: pointer to PF structure
 */
static void mce_eswitch_napi_enable(struct mce_pf *pf)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;
	int i = 0;

	mce_for_each_vf_id(pf, i) {
		vfinfo = &vf->vfinfo[i];
		napi_enable(&vfinfo->repr->q_vector->napi);
	}
}

static void mce_eswitch_remove_fltr(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int i = 0;

	mce_for_each_pf_vf_id(pf, i) {
		mce_vf_apply_spoofchk(pf, i, false);
	}

	/* remove pf dmac flr */
	ether_addr_copy(vf->t_info.macaddr, vsi->port_info->addr);
	mce_vf_set_veb_misc_rule(hw, PFINFO_IDX,
				 VEB_POLICY_TYPE_UC_DEL_MACADDR_WITH_ACT);
}

static void mce_eswitch_restore_fltr(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int i = 0;

	mce_for_each_pf_vf_id(pf, i) {
		mce_vf_apply_spoofchk(pf, i, true);
	}

	/* restore pf dmac flr */
	ether_addr_copy(vf->t_info.macaddr, vsi->port_info->addr);
	mce_vf_set_veb_misc_rule(hw, PFINFO_IDX,
				 VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
}

/**
 * mce_eswitch_napi_disable - disable NAPI for all port representors
 * @pf: pointer to PF structure
 */
static void mce_eswitch_napi_disable(struct mce_pf *pf)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;
	int i = 0;

	mce_for_each_vf_id(pf, i) {
		vfinfo = &vf->vfinfo[i];
		napi_disable(&vfinfo->repr->q_vector->napi);
	}
}

static void mce_eswitch_setup_dft_rules(struct mce_pf *pf, bool add)
{
	struct mce_hw *hw = &pf->hw;

	if (add) {
		/* post all in to rx */
		hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1,
						  false,
						  MCE_VF_POST_CTRL_ALLIN_TO_RX,
						  true);
	} else {
		/* post filter hit rules to rx */
		hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, false,
			MCE_VF_POST_CTRL_FILTER_TX_TO_RX, true);
	}
}

/**
 * mce_eswitch_enable_switchdev - configure eswitch in switchdev mode
 * @pf: pointer to PF structure
 * Returns: The result of the operation.
 */
static int mce_eswitch_enable_switchdev(struct mce_pf *pf)
{
	pf->switchdev.uplink_vsi = mce_get_main_vsi(pf);
	pf->switchdev.uplink_vsi->vport_id = pf->max_vfs;
	if (mce_repr_add_for_all_vfs(pf))
		goto err_repr_add;
	if (mce_eswitch_setup_reprs(pf))
		goto err_setup_reprs;
	if (pf->npu_en)
		mce_npu_download_firmware(&pf->hw);
	mce_eswitch_napi_enable(pf);
	mce_eswitch_remove_fltr(pf);
	mce_eswitch_setup_dft_rules(pf, true);
	return 0;
err_setup_reprs:
	mce_repr_rem_from_all_vfs(pf);
err_repr_add:
	return -ENODEV;
}

/**
 * mce_eswitch_disable_switchdev - disable switchdev resources
 * @pf: pointer to PF structure
 */
static void mce_eswitch_disable_switchdev(struct mce_pf *pf)
{
	mce_eswitch_napi_disable(pf);
	mce_eswitch_release_reprs(pf);
	mce_repr_rem_from_all_vfs(pf);
	mce_eswitch_restore_fltr(pf);
	mce_eswitch_setup_dft_rules(pf, false);
}

bool mce_is_support_eswitch(struct mce_pf *pf)
{
	return true;
}

int mce_eswitch_alloc_vfs(struct mce_pf *pf)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_vsi *vsi = NULL;
	int i = 0;

	mce_for_each_vf_id(pf, i) {
		vsi = mce_vsi_alloc(pf, MCE_VSI_SWITCHDEV_VF);
		if (!vsi) {
			dev_err(mce_pf_to_dev(pf),
				"Failed to create VF:%d VSI\n", i);
			return -1;
		}
		vf->vfinfo[i].lan_vsi_idx = vsi->idx;
		vsi->vport_id = i;
	}

	return 0;
}

int mce_eswitch_free_vfs(struct mce_pf *pf)
{
	struct mce_vsi *vsi = NULL;
	int i = 0;

	mce_for_each_vsi(pf, i) {
		/* vsi 0 is pf */
		if (i == 0 || !pf->vsi[i])
			continue;
		vsi = pf->vsi[i];
		mce_vsi_free_stats(vsi);
		mce_vsi_clear(vsi);
	}

	return 0;
}

bool mce_is_eswitch_mode_switchdev(struct mce_pf *pf)
{
	return false;
}

/**
 * mce_eswitch_release - cleanup eswitch
 * @pf: pointer to PF structure
 */
void mce_eswitch_release(struct mce_pf *pf)
{
	mce_eswitch_disable_switchdev(pf);
	pf->switchdev.is_running = false;
}

/**
 * mce_eswitch_configure - configure eswitch
 * @pf: pointer to PF structure
 * Returns: The result of the operation.
 */
int mce_eswitch_configure(struct mce_pf *pf)
{
	int status;

	if (!mce_is_support_eswitch(pf))
		return 0;

	status = mce_eswitch_enable_switchdev(pf);
	if (status)
		return status;

	pf->switchdev.is_running = true;
	return 0;
}

#endif /* CONFIG_NET_DEVLINK */
