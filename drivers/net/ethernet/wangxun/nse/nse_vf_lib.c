// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#include <linux/pci.h>

#include "nse_vf_lib_private.h"
#include "nse.h"
#include "nse_base.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_vf_vsi_vlan_ops.h"
#include "nse_virtchnl_allowlist.h"

/**
 * nse_get_vf_by_id - Get pointer to VF by ID
 * @pf: the PF private structure
 * @vf_id: the VF ID to locate
 *
 * Locate and return a pointer to the VF structure associated with a given ID.
 * Returns NULL if the ID does not have a valid VF structure associated with
 * it.
 *
 * Note that valid vf_id values cannot exceed U16_MAX. However, some code
 * flows receive, store, and report VF IDs using a u32 field. This is done so
 * that those flows can use the upper bits for special values such as the
 * broadcast VF ID. The u32 parameter prevents implicit truncation which would
 * cause the driver to misinterpret these special values.
 *
 * This function takes a reference on the VF which must be released by calling
 * nse_put_vf() when the caller has finished accessing the VF structure.
 */
struct nse_vf *nse_get_vf_by_id(struct nse_pf *pf, u32 vf_id)
{
	struct nse_vf *vf;

	/* All valid VF IDs are 16 bits */
	if (vf_id > U16_MAX) {
		dev_err(nse_pf_to_dev(pf), "Out of range VF ID: %u\n",
			vf_id);
		return NULL;
	}

	rcu_read_lock();
	hash_for_each_possible_rcu(pf->vfs.table, vf, entry, vf_id) {
		if (vf->vf_id == vf_id) {
			struct nse_vf *found;

			if (kref_get_unless_zero(&vf->refcnt))
				found = vf;
			else
				found = NULL;

			rcu_read_unlock();
			return found;
		}
	}

	rcu_read_unlock();
	return NULL;
}

struct nse_vf *nse_get_vf_by_vsi_abs_id(struct nse_pf *pf, u16 vsi_abs_id)
{
	struct nse_vf *vf;
	struct nse_vfs *vfs = &pf->vfs;
	u16 vf_vsi_abs_base = vfs->vf_vsialloc_firstvsi + pf->vsi_space_start;
	unsigned int bkt;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vf *found = NULL;

	if (vsi_abs_id >= NSE_MAX_VSI) {
		dev_err(dev, "Out of range VF-VSI absolute ID: %u\n",
			vsi_abs_id);
		return NULL;
	}

	if (!pf->sriov_res_planned) {
		dev_err(dev, "SRIOV not enabled, sriov_res_planned = false\n");
		return NULL;
	}

	if (vsi_abs_id < vf_vsi_abs_base ||
		vsi_abs_id >= (pf->vsi_space_start + pf->vsi_space_size)) {
		dev_err(dev, "vsi_abs_id: %u, NOT in the VF VSI range of this PF: [%u, %u)\n",
					vsi_abs_id, vf_vsi_abs_base, (pf->vsi_space_start +
								      pf->vsi_space_size));
		return NULL;
	}

	mutex_lock(&pf->vfs.table_lock);
	rcu_read_lock();

	nse_for_each_vf(pf, bkt, vf) {
		if (vf->vf_vsi_abs_id == vsi_abs_id) {
			if (kref_get_unless_zero(&vf->refcnt))
				found = vf;
			else
				found = NULL;

			goto out;
		}
	}

out:
	rcu_read_unlock();
	mutex_unlock(&pf->vfs.table_lock);

	return found;
}

/**
 * nse_release_vf - Release VF associated with a refcount
 * @ref: the kref decremented to zero
 *
 * Callback function for kref_put to release a VF once its reference count has
 * hit zero.
 */
static void nse_release_vf(struct kref *ref)
{
	struct nse_vf *vf = container_of(ref, struct nse_vf, refcnt);

	vf->vf_ops->free(vf);
}

/**
 * nse_put_vf - Release a reference to a VF
 * @vf: the VF structure to decrease reference count on
 *
 * Decrease the reference count for a VF, and free the entry if it is no
 * longer in use.
 *
 * This must be called after nse_get_vf_by_id() once the reference to the VF
 * structure is no longer used. Otherwise, the VF structure will never be
 * freed.
 */
void nse_put_vf(struct nse_vf *vf)
{
	kref_put(&vf->refcnt, nse_release_vf);
}

/**
 * nse_is_valid_vf_id - helper to check if VF ID is valid
 * @pf: pointer to the PF structure
 * @vf_id: the ID of the VF to check
 *
 * Note that valid vf_id values cannot exceed U16_MAX. However, some code
 * flows receive, store, and report VF IDs using a u32. This function takes
 * a u32 in order to prevent implicit truncation of such values to a u16.
 *
 * Note that this function only guarantees that the VF ID is valid at the
 * point of calling it. It does not guarantee the VF ID will remain valid
 * after it exits. It is possible that the VF will be released at any time
 * after this function exits.
 */
bool nse_is_valid_vf_id(struct nse_pf *pf, u32 vf_id)
{
	struct nse_vf *vf;

	/* VF IDs are not necessarily contiguous. Validate that the VF ID
	 * exists in the VF hash table.
	 */
	vf = nse_get_vf_by_id(pf, vf_id);
	if (!vf) {
		dev_err(nse_pf_to_dev(pf), "Invalid VF ID: %u\n", vf_id);
		return false;
	}

	nse_put_vf(vf);
	return true;
}

/**
 * nse_has_vfs - Return true if the PF has any associated VFs
 * @pf: the PF private structure
 *
 * Return whether or not the PF has any allocated VFs.
 *
 * Note that this function only guarantees that there are no VFs at the point
 * of calling it. It does not guarantee that no more VFs will be added.
 */
bool nse_has_vfs(struct nse_pf *pf)
{
	/* A simple check that the hash table is not empty does not require
	 * the mutex or rcu_read_lock.
	 */
	return !hash_empty(pf->vfs.table);
}

/**
 * nse_get_num_vfs - Get number of allocated VFs
 * @pf: the PF private structure
 *
 * Return the total number of allocated VFs. NOTE: VF IDs are not guaranteed
 * to be contiguous. Do not assume that a VF ID is guaranteed to be less than
 * the output of this function.
 */
u16 nse_get_num_vfs(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;
	u16 num_vfs = 0;

	rcu_read_lock();
	nse_for_each_vf_rcu(pf, bkt, vf)
		num_vfs++;
	rcu_read_unlock();

	return num_vfs;
}

/**
 * nse_get_vf_vsi - get VF's VSI based on the stored index
 * @vf: VF used to get VSI
 */
struct nse_vsi *nse_get_vf_vsi(struct nse_vf *vf)
{
	if (vf->lan_vsi_idx == NSE_NO_VSI)
		return NULL;

	return vf->pf->vsi[vf->lan_vsi_idx];
}

/**
 * nse_is_vf_disabled
 * @vf: pointer to the VF info
 *
 * If the PF has been disabled, there is no need resetting VF until PF is
 * active again. Similarly, if the VF has been disabled, this means something
 * else is resetting the VF, so we shouldn't continue.
 *
 * Returns true if the caller should consider the VF as disabled whether
 * because that single VF is explicitly disabled or because the PF is
 * currently disabled.
 */
bool nse_is_vf_disabled(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;

	return (test_bit(NSE_VF_DIS, pf->state) ||
		test_bit(NSE_VF_STATE_DIS, vf->vf_states));
}

/**
 * nse_wait_on_vf_reset - poll to make sure a given VF is ready after reset
 * @vf: The VF being resseting
 *
 * The max poll time is about ~800ms, which is about the maximum time it takes
 * for a VF to be reset and/or a VF driver to be removed.
 */
static void nse_wait_on_vf_reset(struct nse_vf *vf)
{
	int i;

	for (i = 0; i < NSE_MAX_VF_RESET_TRIES; i++) {
		if (test_bit(NSE_VF_STATE_INIT, vf->vf_states))
			break;
		msleep(NSE_MAX_VF_RESET_SLEEP_MS);
	}
}

/**
 * nse_check_vf_ready_for_cfg - check if VF is ready to be configured/queried
 * @vf: VF to check if it's ready to be configured/queried
 *
 * The purpose of this function is to make sure the VF is not in reset, not
 * disabled, and initialized so it can be configured and/or queried by a host
 * administrator.
 */
int nse_check_vf_ready_for_cfg(struct nse_vf *vf)
{
	nse_wait_on_vf_reset(vf);

	if (nse_is_vf_disabled(vf))
		return -EINVAL;

	if (nse_check_vf_init(vf))
		return -EBUSY;

	return 0;
}

/**
 * nse_trigger_vf_reset - Reset a VF on HW
 * @vf: pointer to the VF structure
 * @is_vflr: true if VFLR was issued, false if not
 * @is_pfr: true if the reset was triggered due to a previous PFR
 *
 * Trigger hardware to start a reset for a particular VF. Expects the caller
 * to wait the proper amount of time to allow hardware to reset the VF before
 * it cleans up and restores VF functionality.
 */
void nse_trigger_vf_reset(struct nse_vf *vf, bool is_vflr, bool is_pfr)
{
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] is_vflr=%d, is_pfr=%d\n",
								__func__, is_vflr, is_pfr);

	/* Inform VF that it is no longer active, as a warning */
	clear_bit(NSE_VF_STATE_ACTIVE, vf->vf_states);

	/* Disable VF's configuration API during reset. The flag is re-enabled
	 * when it's safe again to access VF's VSI.
	 */
	clear_bit(NSE_VF_STATE_INIT, vf->vf_states);

	if (!is_pfr && !is_vflr)
		vf->vf_ops->trigger_reset_register(vf);

	if (vf->use_pv_msgbox)
		wr32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_rel_num), NSE_REG_VALUE_RESET_MAGIC_1);
}

static void nse_vf_clear_counters(struct nse_vf *vf)
{
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	if (vsi)
		vsi->num_vlan = 0;

	vf->num_mac = 0;
}

/**
 * nse_vf_pre_vsi_rebuild - tasks to be done prior to VSI rebuild
 * @vf: VF to perform pre VSI rebuild tasks
 *
 * These tasks are items that don't need to be amortized since they are most
 * likely called in a for loop with all VF(s) in the reset_all_vfs() case.
 */
void nse_vf_pre_vsi_rebuild(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);

	/* Close any IRQ mapping now */
	if (vf->vf_ops->irq_close)
		vf->vf_ops->irq_close(vf);

	nse_vf_clear_counters(vf);
}

/**
 * nse_vf_recreate_vsi - Release and re-create the VF's VSI
 * @vf: VF to recreate the VSI for
 *
 * This is only called when a single VF is being reset (i.e. VVF, VFLR, host
 * VF configuration change, etc)
 *
 * It releases and then re-creates a new VSI.
 */
int nse_vf_reinit_vsi(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	u16 max_txqs[NSE_MAX_TRAFFIC_CLASS] = { 0 };
	int i;
	enum nse_status status;
	int err = 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);

	nse_vsi_dis_irq(vsi);

	nse_fltr_remove_all(vsi);

	nse_vsi_clear_q_irqll_status(vsi);

	err = vf->vf_ops->reinit_vsi(vf);
	if (err) {
		dev_err(dev, "[%s] FAIL: reinit the VF-%u VSI, err=%d\n",
						__func__, vf->vf_id, err);
		return err;
	}

	for (i = 0; i < vsi->tc_cfg.numtc; i++)
		max_txqs[i] = vsi->alloc_txq;

	status = nse_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc, max_txqs);
	if (status) {
		dev_err(dev, "[%s] FAIL: cfg_vsi_lan() for VF-%u VSI, status=%d\n",
						__func__, vf->vf_id, status);
		err = -EIO;
	}

	return err;
}

/**
 * nse_vf_post_vsi_rebuild - Reset tasks that occur after VSI rebuild
 * @vf: the VF being reset
 *
 * Perform reset tasks which must occur after the VSI has been re-created or
 * rebuilt during a VF reset.
 */
void nse_vf_post_vsi_rebuild(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vf_vsi = nse_get_vf_vsi(vf);

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);

	/* cfg rss when VF is in reset (VF reset, PF reset, or global reset */
	(void)nse_vsi_cfg_rss(vf_vsi);

	nse_fdir_vf_vsi_init(hw, vf_vsi, vf);

	nse_vf_rebuild_host_cfg(vf);
	nse_vf_set_initialized(vf);

	vf->vf_ops->post_vsi_rebuild(vf);

	vf->vf_ops->clear_reset_trigger(vf);
}

/**
 * nse_is_any_vf_in_unicast_promisc - check if any VF(s)
 * are in unicast promiscuous mode
 * @pf: PF structure for accessing VF(s)
 *
 * Return false if no VF(s) are in unicast promiscuous mode,
 * else return true
 */
bool nse_is_any_vf_in_unicast_promisc(struct nse_pf *pf)
{
	bool is_vf_promisc = false;
	struct nse_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	nse_for_each_vf_rcu(pf, bkt, vf) {
		/* found a VF that has promiscuous mode configured */
		if (test_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states)) {
			is_vf_promisc = true;
			break;
		}
	}
	rcu_read_unlock();

	return is_vf_promisc;
}

/**
 * nse_vf_get_promisc_masks - Calculate masks for promiscuous modes
 * @vf: the VF pointer
 * @vsi: the VSI to configure
 * @ucast_m: promiscuous mask to apply to unicast
 * @mcast_m: promiscuous mask to apply to multicast
 *
 * Decide which mask should be used for unicast and multicast filter,
 * based on presence of VLANs
 */
void nse_vf_get_promisc_masks(struct nse_vf *vf, struct nse_vsi *vsi,
			      u8 *ucast_m, u8 *mcast_m)
{
	if (nse_vf_is_port_vlan_ena(vf) ||
	    nse_vsi_has_non_zero_vlans(vsi)) {
		*mcast_m = NSE_MCAST_VLAN_PROMISC_BITS;
		*ucast_m = NSE_VF_UCAST_VLAN_PROMISC_BITS;
	} else {
		*mcast_m = NSE_MCAST_PROMISC_BITS;
		*ucast_m = NSE_VF_UCAST_PROMISC_BITS;
	}
}

/**
 * nse_vf_clear_all_promisc_modes - Clear promisc/allmulticast on VF VSI
 * @vf: the VF pointer
 * @vsi: the VSI to configure
 *
 * Clear all promiscuous/allmulticast filters for a VF
 */
static int nse_vf_clear_all_promisc_modes(struct nse_vf *vf,
					  struct nse_vsi *vsi)
{
	struct nse_pf *pf = vf->pf;
	u8 ucast_m, mcast_m;
	int ret = 0;

	nse_vf_get_promisc_masks(vf, vsi, &ucast_m, &mcast_m);
	if (test_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states)) {
		if (!test_bit(NSE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags)) {
			if (nse_is_vsi_dflt_vsi(vsi))
				ret = nse_clear_dflt_vsi(vsi);
		} else {
			ret = nse_vf_clear_vsi_promisc(vf, vsi, ucast_m);
		}

		if (ret) {
			dev_err(nse_pf_to_dev(vf->pf), "Disabling promiscuous mode failed\n");
		} else {
			clear_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states);
			dev_info(nse_pf_to_dev(vf->pf), "Disabling promiscuous mode succeeded\n");
		}
	}

	if (test_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states)) {
		ret = nse_vf_clear_vsi_promisc(vf, vsi, mcast_m);
		if (ret) {
			dev_err(nse_pf_to_dev(vf->pf), "Disabling allmulticast mode failed\n");
		} else {
			clear_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states);
			dev_info(nse_pf_to_dev(vf->pf), "Disabling allmulticast mode succeeded\n");
		}
	}
	return ret;
}

/**
 * nse_vf_set_vsi_promisc - Enable promiscuous traffic for a VF VSI
 * @vf: the VF pointer
 * @vsi: the VSI to configure
 * @promisc_m: the promiscuous mask to apply
 *
 * Enable promiscuous traffic to the VF VSI for the provided traffic types in
 * the promisc_m mask.
 */
int
nse_vf_set_vsi_promisc(struct nse_vf *vf, struct nse_vsi *vsi, u8 promisc_m)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status;

	if (nse_vf_is_port_vlan_ena(vf))
		status = nse_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m,
						  nse_vf_get_port_vlan_id(vf));
	else if (nse_vsi_has_non_zero_vlans(vsi))
		status = nse_fltr_set_vlan_vsi_promisc(hw, vsi, promisc_m);
	else
		status = nse_fltr_set_vsi_promisc(hw, vsi->idx, promisc_m, 0);

	if (status && status != NSE_ERR_ALREADY_EXISTS) {
		dev_err(nse_pf_to_dev(vsi->back), "enable Tx/Rx filter promiscuous mode on VF-%u failed, error: %s\n",
			vf->vf_id, nse_stat_str(status));
		return nse_status_to_errno(status);
	}

	return 0;
}

/**
 * nse_vf_clear_vsi_promisc - Disable promiscuous traffic for a VF VSI
 * @vf: the VF pointer
 * @vsi: the VSI to configure
 * @promisc_m: the promiscuous mask to apply
 *
 * Disable promiscuous traffic to the VF VSI for the provided traffic types in
 * the promisc_m mask.
 */
int
nse_vf_clear_vsi_promisc(struct nse_vf *vf, struct nse_vsi *vsi, u8 promisc_m)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status;

	if (nse_vf_is_port_vlan_ena(vf))
		status = nse_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m,
						    nse_vf_get_port_vlan_id(vf));
	else if (nse_vsi_has_non_zero_vlans(vsi))
		status = nse_fltr_clear_vlan_vsi_promisc(hw, vsi, promisc_m);
	else
		status = nse_fltr_clear_vsi_promisc(hw, vsi->idx, promisc_m, 0);

	if (status && status != NSE_ERR_DOES_NOT_EXIST) {
		dev_err(nse_pf_to_dev(vsi->back), "disable Tx/Rx filter promiscuous mode on VF-%u failed, error: %s\n",
			vf->vf_id, nse_stat_str(status));
		return nse_status_to_errno(status);
	}

	return 0;
}

/**
 * nse_notify_vf_reset - Notify VF of a reset event
 * @vf: pointer to the VF structure
 */
void nse_notify_vf_reset(struct nse_vf *vf)
{
	struct nse_hw *hw = &vf->pf->hw;
	struct virtchnl_pf_event pfe;

	/* Bail out if VF is in disabled state, neither initialized, nor active
	 * state - otherwise proceed with notifications
	 */
	if ((!test_bit(NSE_VF_STATE_INIT, vf->vf_states) &&
	     !test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) ||
	    test_bit(NSE_VF_STATE_DIS, vf->vf_states)) {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] skip send vch-event(RESET_IMPENDING) to VF\n",
									__func__, __LINE__);
		return;
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s, %d] send vch-event(RESET_IMPENDING) to VF\n",
									__func__, __LINE__);

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	pfe.event_data.reset_event.reset_type = 0;
	(void)nse_aq_send_msg_to_vf(hw, vf->vf_vsi_abs_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe, sizeof(pfe),
			      NULL);
}

/**
 * nse_reset_vf - Reset a particular VF
 * @vf: pointer to the VF structure
 * @flags: flags controlling behavior of the reset
 *
 * Flags: enum nse_vf_reset_flags
 *   NSE_VF_RESET_VFLR - Indicates a reset is due to VFLR event
 *   NSE_VF_RESET_NOTIFY - Send VF a notification prior to reset
 *   NSE_VF_RESET_LOCK - Acquire VF cfg_lock before resetting
 *
 * Returns 0 if the VF is currently in reset, if resets are disabled, or if
 * the VF resets successfully. Returns an error code if the VF fails to
 * rebuild.
 */
int nse_reset_vf(struct nse_vf *vf, u32 flags)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	int err = 0;
	bool rsd = true;

	nse_debug(hw, NSE_DBG_SYS, "[%s] VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d), flags=0x%X, force_reset_vf=%d\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id,
								flags, pf->force_reset_vf);

	/* may move this notify later ? */
	if (flags & NSE_VF_RESET_NOTIFY)
		nse_notify_vf_reset(vf);

	if (pf->force_reset_vf) {
		/* don't use nse_is_vf_disabled() here */

		if (test_bit(NSE_VF_STATE_DIS, vf->vf_states)) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] (vf->vf_stats & VF_STATE_DIS) = true, return early even force_reset_vf=true\n",
										__func__,
											__LINE__);
			return 0;
		}

		if (test_bit(NSE_VF_RESETS_DISABLED, pf->state) ||
		    test_bit(NSE_VF_DIS, pf->state)) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] (pf->state & VF_RESETS_DISABLED) = %d, (pf->state & NSE_VF_DIS) = %d, --- but continue because force_reset_vf=true\n",
										__func__,
											__LINE__,
				  test_bit(NSE_VF_RESETS_DISABLED, pf->state),
					  test_bit(NSE_VF_DIS, pf->state));
		}
	} else {
		if (test_bit(NSE_VF_RESETS_DISABLED, pf->state)) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] (pf->state & VF_RESETS_DISABLED) = true, when trying to reset VF %d, return early\n",
										__func__,
											__LINE__,
											vf->vf_id);
			return 0;
		}

		if (nse_is_vf_disabled(vf)) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] is_vf_disabled(vf->vf_id = %d) = true, return early\n",
										__func__,
											__LINE__,
											vf->vf_id);
			return 0;
		}
	}

	vf->vf_reset_count++;
	if (flags & NSE_VF_RESET_VFLR)
		vf->vflr_count++;
	else
		vf->vfr_count++;

	if (flags & NSE_VF_RESET_LOCK)
		mutex_lock(&vf->cfg_lock);
	else
		lockdep_assert_held(&vf->cfg_lock);

	/* Set VF disable bit state here, before triggering reset */
	set_bit(NSE_VF_STATE_DIS, vf->vf_states);

	nse_send_vf_reset_to_aux(pf, nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID),
				 nse_abs_vf_id(hw, vf->vf_id));

	nse_trigger_vf_reset(vf, flags & NSE_VF_RESET_VFLR, false);

	vsi = nse_get_vf_vsi(vf);
	if (WARN_ON(!vsi)) {
		err = -EIO;
		goto out_unlock;
	}

	nse_vsi_clear_q_irqll_status(vsi);

	if (vf->driver_caps & VIRTCHNL_VF_CAP_RDMA)
		vf->vf_ops->clear_rdma_irq_map(vf);

	/* poll reg to make sure that underlying-cleanup is complete
	 */
	if (!(flags & NSE_VF_RESET_VFLR))
		rsd = vf->vf_ops->poll_reset_status(vf);

	/* Display a warning if VF didn't manage to reset in time, but need to
	 * continue on with the operation.
	 */
	if (!rsd)
		dev_warn(dev, "VF reset check timeout on VF %d\n", vf->vf_id);

	nse_dis_vf_qs(vf, true);

	vf->driver_caps = 0;
	nse_vc_set_default_allowlist(vf);

	/* disable promiscuous modes in case they were enabled
	 * ignore any error if disabling process failed
	 */
	nse_vf_clear_all_promisc_modes(vf, vsi);

	nse_vf_pre_vsi_rebuild(vf);

	if (nse_vf_reinit_vsi(vf)) {
		dev_err(dev, "[%s] FAIL: vf_reinit_vsi(VF-%u's VSI)\n",
						__func__, vf->vf_id);
		err = -EFAULT;
		goto out_unlock;
	}

	nse_vf_post_vsi_rebuild(vf);

	vsi = nse_get_vf_vsi(vf);
	if (WARN_ON(!vsi)) {
		err = -EINVAL;
		goto out_unlock;
	}

	nse_eswitch_update_repr(vsi);

	err = 0;

out_unlock:
	if (flags & NSE_VF_RESET_LOCK)
		mutex_unlock(&vf->cfg_lock);

	nse_debug(hw, NSE_DBG_SYS, "[%s] out, err=%d\n",
								__func__, err);

	return err;
}

enum nse_status
nse_reenable_sriov(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;

	if (!nse_has_vfs(pf))
		return 0;

	status = nse_aq_set_sriov_res(&pf->hw);

	if (status)
		dev_err(dev, "[%s] FAIL: aq_set_sriov_res(), status=%d(%s)\n",
			__func__, status, nse_stat_str(status));

	return status;
}

/**
 * ice_reset_all_vfs - reset all allocated VFs in one go
 * @pf: pointer to the PF structure
 *
 * Reset all VFs at once, in response to a PF or other device reset.
 *
 * First, tell the hardware to reset each VF, then do all the waiting in one
 * chunk, and finally finish restoring each VF after the wait. This is useful
 * during PF routines which need to reset all VFs, as otherwise it must perform
 * these resets in a serialized fashion.
 */
void nse_reset_all_vfs(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_vf *vf;
	struct nse_vsi *vsi;
	unsigned int bkt;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	/* If we don't have any VFs, then there is nothing to reset */
	if (!nse_has_vfs(pf)) {
		nse_debug(hw, NSE_DBG_SYS,
			  "[%s] return early because VF not enabled on this PF\n", __func__);
		return;
	}

	if (nse_is_high_reset_type(reset_type)) {
		nse_debug(hw, NSE_DBG_SYS,
			  "[%s, %d] high_reset rebuild need to call aq_set_sriov_res()\n",
			__func__, __LINE__);

		status = nse_aq_set_sriov_res(hw);
		if (status) {
			dev_err(dev, "[%s, %d] FAIL: aq_set_sriov_res() status=%d, SRIOV may not usable after high_reset\n",
						__func__, __LINE__, status);
			set_bit(NSE_VF_DIS, pf->state);
			return;
		}
	}

	mutex_lock(&pf->vfs.table_lock);

	/* If VFs have been disabled, there is no need to reset */
	if (test_and_set_bit(NSE_VF_DIS, pf->state)) {
		mutex_unlock(&pf->vfs.table_lock);
		return;
	}

	nse_for_each_vf(pf, bkt, vf) {
		vsi = nse_get_vf_vsi(vf);

		mutex_lock(&vf->cfg_lock);

		/* Inform VF that it is no longer active, as a warning */
		clear_bit(NSE_VF_STATE_ACTIVE, vf->vf_states);

		/* Disable VF's configuration API during reset. The flag is re-enabled
		 * when it's safe again to access VF's VSI.
		 */
		clear_bit(NSE_VF_STATE_INIT, vf->vf_states);

		if (vf->use_pv_msgbox)
			wr32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_rel_num),
			     NSE_REG_VALUE_RESET_MAGIC_1);

		vf->driver_caps = 0;
		nse_vc_set_default_allowlist(vf);

		nse_vf_pre_vsi_rebuild(vf);

		if (nse_vf_reinit_vsi(vf))
			dev_warn(dev, "[%s] WARN: fail to reinit the VF-%u's VSI\n",
							__func__, vf->vf_id);

		nse_vf_post_vsi_rebuild(vf);

		mutex_unlock(&vf->cfg_lock);
	}

	if (nse_is_eswitch_mode_switchdev(pf))
		if (nse_eswitch_rebuild(pf, reset_type))
			dev_warn(dev, "[%s] WARN: eswitch rebuild failed\n", __func__);

	nse_flush(hw);

	clear_bit(NSE_VF_DIS, pf->state);

	mutex_unlock(&pf->vfs.table_lock);

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d, DONE\n", __func__, reset_type);
}

/**
 * nse_set_vf_state_qs_dis - Set VF queues state to disabled
 * @vf: pointer to the VF structure
 */
void nse_set_vf_state_qs_dis(struct nse_vf *vf)
{
	/* Clear Rx/Tx enabled queues flag */
	bitmap_zero(vf->txq_ena, NSE_MAX_QS_PER_VF);
	bitmap_zero(vf->rxq_ena, NSE_MAX_QS_PER_VF);
	clear_bit(NSE_VF_STATE_QS_ENA, vf->vf_states);
}

/**
 * nse_initialize_vf_entry - Initialize a VF entry
 * @vf: pointer to the VF structure
 *
 * Returns 0 on success or an integer error code on failure.
 */
int nse_initialize_vf_entry(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_vfs *vfs;

	vfs = &pf->vfs;

	/* assign default capabilities */
	vf->spoofchk = true;
	vf->num_vf_qs = vfs->num_qps_per;
	nse_vc_set_default_allowlist(vf);
	nse_virtchnl_set_dflt_ops(vf);

	mutex_init(&vf->cfg_lock);

	return 0;
}

/**
 * nse_err_to_virt_err - translate errors for VF return code
 * @nse_err: error return code
 */
enum virtchnl_status_code nse_err_to_virt_err(enum nse_status nse_err)
{
	switch (nse_err) {
	case NSE_SUCCESS:
		return VIRTCHNL_STATUS_SUCCESS;
	case NSE_ERR_BAD_PTR:
	case NSE_ERR_INVAL_SIZE:
	case NSE_ERR_DEVICE_NOT_SUPPORTED:
	case NSE_ERR_PARAM:
	case NSE_ERR_CFG:
		return VIRTCHNL_STATUS_ERR_PARAM;
	case NSE_ERR_NO_MEMORY:
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;
	case NSE_ERR_NOT_READY:
	case NSE_ERR_RESET_FAILED:
	case NSE_ERR_FW_API_VER:
	case NSE_ERR_AQ_ERROR:
	case NSE_ERR_AQ_TIMEOUT:
	case NSE_ERR_AQ_FULL:
	case NSE_ERR_AQ_NO_WORK:
	case NSE_ERR_AQ_EMPTY:
		return VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
	default:
		return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
	}
}

/**
 * nse_check_vf_init - helper to check if VF init complete
 * @vf: the pointer to the VF to check
 */
int nse_check_vf_init(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;

	if (!test_bit(NSE_VF_STATE_INIT, vf->vf_states)) {
		dev_err(nse_pf_to_dev(pf), "VF ID: %u in reset. Try again.\n",
			vf->vf_id);
		return -EBUSY;
	}
	return 0;
}

/**
 * nse_vf_set_host_trust_cfg - set trust setting based on pre-reset value
 * @vf: VF to configure trust setting for
 */
static void nse_vf_set_host_trust_cfg(struct nse_vf *vf)
{
	if (vf->trusted)
		set_bit(NSE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
	else
		clear_bit(NSE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
}

/**
 * nse_vf_rebuild_host_mac_cfg - add broadcast and the VF's perm_addr/LAA
 * @vf: VF to add MAC filters for
 *
 * Called after a VF VSI has been re-added/rebuilt during reset. The PF driver
 * always re-adds a broadcast filter and the VF's perm_addr/LAA after reset.
 */
static int nse_vf_rebuild_host_mac_cfg(struct nse_vf *vf)
{
	struct device *dev = nse_pf_to_dev(vf->pf);
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	enum nse_status status;
	u8 broadcast[ETH_ALEN];

	if (WARN_ON(!vsi))
		return -EINVAL;

	if (nse_is_eswitch_mode_switchdev(vf->pf))
		return 0;

	eth_broadcast_addr(broadcast);
	status = nse_fltr_add_mac(vsi, broadcast, NSE_FWD_TO_VSI);
	if (status) {
		dev_err(dev, "failed to add broadcast MAC filter for VF %u, error %s\n",
			vf->vf_id, nse_stat_str(status));
		return nse_status_to_errno(status);
	}

	vf->num_mac++;

	if (is_valid_ether_addr(vf->hw_lan_addr.addr)) {
		status = nse_fltr_add_mac(vsi, vf->hw_lan_addr.addr,
					  NSE_FWD_TO_VSI);
		if (status) {
			dev_err(dev, "failed to add default unicast MAC filter %pM for VF %u, error %s\n",
				&vf->hw_lan_addr.addr[0], vf->vf_id,
				nse_stat_str(status));
			return nse_status_to_errno(status);
		}
		vf->num_mac++;

		ether_addr_copy(vf->dev_lan_addr.addr, vf->hw_lan_addr.addr);
	}

	return 0;
}

/**
 * nse_vf_rebuild_host_vlan_cfg - add VLAN 0 filter or rebuild the Port VLAN
 * @vf: VF to add MAC filters for
 * @vsi: Pointer to VSI
 *
 * Called after a VF VSI has been re-added/rebuilt during reset. The PF driver
 * always re-adds either a VLAN 0 or port VLAN based filter after reset.
 */
int nse_vf_rebuild_host_vlan_cfg(struct nse_vf *vf, struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vf_is_port_vlan_ena(vf_rel_id=%u)=%d\n",
		  __func__, vf->vf_id, nse_vf_is_port_vlan_ena(vf));

	if (nse_vf_is_port_vlan_ena(vf)) {
		err = vlan_ops->set_port_vlan(vsi, &vf->port_vlan_info);
		if (err) {
			dev_err(dev, "[%s] FAIL: vlan_ops->set_port_vlan() to configure port VLAN via VSI parameters for VF %u, err=%d\n",
							__func__, vf->vf_id, err);
			return err;
		}

		err = vlan_ops->add_vlan(vsi, &vf->port_vlan_info);
	} else {
		err = nse_vsi_add_vlan_zero(vsi);
	}

	if (err) {
		dev_err(dev, "[%s] FAIL: add VLAN %u filter for VF %u during VF rebuild, err=%d\n",
						__func__, nse_vf_is_port_vlan_ena(vf) ?
							nse_vf_get_port_vlan_id(vf) :
							0, vf->vf_id, err);
		return err;
	}

	err = vlan_ops->ena_rx_filtering(vsi);
	if (err) {
		dev_err(dev, "[%s] FAIL: enable Rx VLAN filtering for VF %d VSI %d during VF rebuild, err=%d\n",
						__func__, vf->vf_id, vsi->idx, err);
	}

	return 0;
}

/**
 * nse_vf_rebuild_host_tx_rate_cfg - re-apply the Tx rate limiting configuration
 * @vf: VF to re-apply the configuration for
 *
 * Called after a VF VSI has been re-added/rebuild during reset. The PF driver
 * needs to re-apply the host configured Tx rate limiting configuration.
 */
static int nse_vf_rebuild_host_tx_rate_cfg(struct nse_vf *vf)
{
	struct device *dev = nse_pf_to_dev(vf->pf);
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);
	int err;

	if (WARN_ON(!vsi))
		return -EINVAL;

	if (vf->min_tx_rate) {
		err = nse_set_min_bw_limit(vsi, vf->min_tx_rate * 1000);
		if (err) {
			nse_dev_err_errno(dev, err,
					  "failed to set min Tx rate to %d Mbps for VF %u",
					  vf->min_tx_rate, vf->vf_id);
			return err;
		}
	}

	if (vf->max_tx_rate) {
		err = nse_set_max_bw_limit(vsi, vf->max_tx_rate * 1000);
		if (err) {
			nse_dev_err_errno(dev, err,
					  "failed to set max Tx rate to %d Mbps for VF %u",
					  vf->max_tx_rate, vf->vf_id);
			return err;
		}
	}

	return 0;
}

/**
 * nse_vf_rebuild_host_cfg - host admin configuration is persistent across reset
 * @vf: VF to rebuild host configuration on
 */
void nse_vf_rebuild_host_cfg(struct nse_vf *vf)
{
	struct device *dev = nse_pf_to_dev(vf->pf);
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	if (WARN_ON(!vsi))
		return;

	nse_vf_set_host_trust_cfg(vf);

	/* need before nse_vf_rebuild_host_vlan_cfg() if VF port-based VLAN status changed */
	nse_vsi_init_vlan_ops(vsi);

	if (nse_vf_rebuild_host_mac_cfg(vf))
		dev_err(dev, "[%s] FAIL: vf_rebuild_host_mac_cfg() to rebuild default MAC configuration for VF %d\n",
						__func__, vf->vf_id);

	if (nse_vf_rebuild_host_vlan_cfg(vf, vsi))
		dev_err(dev, "[%s] FAIL: vf_rebuild_host_vlan_cfg() to rebuild VLAN configuration for VF %u\n",
						__func__, vf->vf_id);

	if (nse_vf_rebuild_host_tx_rate_cfg(vf))
		dev_err(dev, "[%s] FAIL: vf_rebuild_host_tx_rate_cfg() to rebuild Tx rate limiting configuration for VF %u\n",
						__func__, vf->vf_id);

	if (nse_vsi_apply_spoofchk(vsi, vf->spoofchk))
		dev_err(dev, "[%s] FAIL: vsi_apply_spoofchk() to rebuild spoofchk configuration for VF %d\n",
						__func__, vf->vf_id);
}

/**
 * nse_vf_init_host_cfg - Initialize host admin configuration
 * @vf: VF to initialize
 * @vsi: the VSI created at initialization
 *
 * Initialize the VF host configuration. Called during VF creation to setup
 * VLAN 0, add the VF VSI broadcast filter, and setup spoof checking. It
 * should only be called during VF creation.
 */
int nse_vf_init_host_cfg(struct nse_vf *vf, struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops;
	struct nse_pf *pf = vf->pf;
	u8 broadcast[ETH_ALEN];
	enum nse_status status;
	struct device *dev;
	int err;

	dev = nse_pf_to_dev(pf);

	err = nse_vsi_add_vlan_zero(vsi);
	if (err) {
		dev_warn(dev, "Failed to add VLAN 0 filter for VF %d\n",
			 vf->vf_id);
		return err;
	}

	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	err = vlan_ops->ena_rx_filtering(vsi);
	if (err) {
		dev_warn(dev, "Failed to enable Rx VLAN filtering for VF %d\n",
			 vf->vf_id);
		return err;
	}

	eth_broadcast_addr(broadcast);
	status = nse_fltr_add_mac(vsi, broadcast, NSE_FWD_TO_VSI);
	if (status) {
		dev_err(dev, "Failed to add broadcast MAC filter for VF %d, status %s\n",
			vf->vf_id, nse_stat_str(status));
		err = nse_status_to_errno(status);
		return err;
	}

	vf->num_mac = 1;

	err = nse_vsi_apply_spoofchk(vsi, vf->spoofchk);
	if (err) {
		dev_warn(dev, "Failed to initialize spoofchk setting for VF %d\n",
			 vf->vf_id);
		return err;
	}

	return 0;
}

/**
 * nse_vf_invalidate_vsi - invalidate vsi_idx/vsi_num to remove VSI access
 * @vf: VF to remove access to VSI for
 */
void nse_vf_invalidate_vsi(struct nse_vf *vf)
{
	vf->lan_vsi_idx = NSE_NO_VSI;
	vf->vf_vsi_abs_id = NSE_NO_VSI;
	vf->vf_vsi_rel_id = NSE_NO_VSI;
}

/**
 * nse_vf_vsi_release - Release the VF VSI and invalidate indexes
 * @vf: pointer to the VF structure
 *
 * Release the VF associated with this VSI and then invalidate the VSI
 * indexes.
 */
void nse_vf_vsi_release(struct nse_vf *vf)
{
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	if (WARN_ON(!vsi))
		return;

	nse_vsi_release(vsi);
	nse_vf_invalidate_vsi(vf);

	nse_debugfs_vf_exit(vf);
}

/**
 * nse_vf_set_initialized - VF is ready for VIRTCHNL communication
 * @vf: VF to set in initialized state
 *
 * After this function the VF will be ready to receive/handle the
 * VIRTCHNL_OP_GET_VF_RESOURCES message
 */
void nse_vf_set_initialized(struct nse_vf *vf)
{
	nse_set_vf_state_qs_dis(vf);
	clear_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states);
	clear_bit(NSE_VF_STATE_DIS, vf->vf_states);
	set_bit(NSE_VF_STATE_INIT, vf->vf_states);
	memset(&vf->vlan_v2_caps, 0, sizeof(vf->vlan_v2_caps));
}

/**
 * nse_vf_get_port_info - Get the VF's port info structure
 * @vf: VF used to get the port info structure for
 */
struct nse_port_info *nse_vf_get_port_info(struct nse_vf *vf)
{
	return vf->pf->hw.port_info;
}

static int nse_cfg_mac_antispoof(struct nse_vsi *vsi, bool enable)
{
	if (nse_bypass_switch)
		return 0;

	if (!vsi)
		return -EINVAL;

	if (nse_is_hw_static_fea_set(&vsi->back->hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return 0;

	if (enable)
		return nse_vsi_update_switch(vsi, nse_vsi_ctx_set_mac_antispoof);
	else
		return nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_mac_antispoof);
}

/**
 * nse_vsi_ena_spoofchk - enable Tx spoof checking for this VSI
 * @vsi: VSI to enable Tx spoof checking for
 *
 * This also enables Tx filtering of the VLANs for this VSI.
 */
static int nse_vsi_ena_spoofchk(struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops;
	int err;

	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);

	err = vlan_ops->ena_tx_filtering(vsi);
	if (err)
		return err;

	return nse_cfg_mac_antispoof(vsi, true);
}

/**
 * nse_vsi_dis_spoofchk - disable Tx spoof checking for this VSI
 * @vsi: VSI to disable Tx spoof checking for
 *
 * This also disables Tx filtering of the VLANs for this VSI
 */
static int nse_vsi_dis_spoofchk(struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops;
	int err;

	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);

	err = vlan_ops->dis_tx_filtering(vsi);
	if (err)
		return err;

	return nse_cfg_mac_antispoof(vsi, false);
}

/**
 * nse_vsi_apply_spoofchk - Apply Tx spoof checking setting to a VSI
 * @vsi: VSI associated to the VF
 * @enable: whether to enable or disable the spoof checking
 */
int nse_vsi_apply_spoofchk(struct nse_vsi *vsi, bool enable)
{
	int err;

	if (enable)
		err = nse_vsi_ena_spoofchk(vsi);
	else
		err = nse_vsi_dis_spoofchk(vsi);

	return err;
}

/**
 * nse_is_vf_trusted
 * @vf: pointer to the VF info
 */
bool nse_is_vf_trusted(struct nse_vf *vf)
{
	return test_bit(NSE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
}

/**
 * nse_vf_has_no_qs_ena - check if the VF has any Rx or Tx queues enabled
 * @vf: the VF to check
 *
 * Returns true if the VF has no Rx and no Tx queues enabled and returns false
 * otherwise
 */
bool nse_vf_has_no_qs_ena(struct nse_vf *vf)
{
	return (!bitmap_weight(vf->rxq_ena, NSE_MAX_QS_PER_VF) &&
		!bitmap_weight(vf->txq_ena, NSE_MAX_QS_PER_VF));
}

/**
 * nse_is_vf_link_up - check if the VF's link is up
 * @vf: VF to check if link is up
 */
bool nse_is_vf_link_up(struct nse_vf *vf)
{
	struct nse_port_info *pi = nse_vf_get_port_info(vf);

	if (nse_check_vf_init(vf))
		return false;

	if (nse_vf_has_no_qs_ena(vf))
		return false;
	else if (vf->link_forced)
		return vf->link_up;
	else
		return pi->lmac_phy_info.link_info.link_status & NSE_AQ_LINK_UP;
}

