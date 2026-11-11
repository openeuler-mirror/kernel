// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* WangXun(R) Ethernet Connection AM Series Linux Driver */

#include "nse_vsi_vlan_lib.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse.h"

static void print_invalid_tpid(struct nse_vsi *vsi, u16 tpid)
{
	dev_err(nse_pf_to_dev(vsi->back), "%s vsi_abs_id=%d specified invalid VLAN tpid 0x%04x\n",
		nse_vsi_type_str(vsi->type), vsi->vsi_abs_num, tpid);
}

/**
 * validate_vlan - check if the nse_vlan passed in is valid
 * @vsi: VSI used for printing error message
 * @vlan: nse_vlan structure to validate
 *
 * Return true if the VLAN TPID is valid or if the VLAN TPID is 0 and the VLAN
 * VID is 0, which allows for non-zero VLAN filters with the specified VLAN TPID
 * and untagged VLAN 0 filters to be added to the prune list respectively.
 */
static bool validate_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_hw *hw = &vsi->back->hw;

	if (vlan->tpid != hw->stag_ethertype && (vlan->tpid || vlan->vid)) {
		print_invalid_tpid(vsi, vlan->tpid);
		return false;
	}

	return true;
}

/**
 * nse_vsi_add_vlan - default add VLAN implementation for all VSI types
 * @vsi: VSI being configured
 * @vlan: VLAN filter to add
 */
int nse_vsi_add_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	enum nse_status status;
	int err = 0;

	if (!validate_vlan(vsi, vlan))
		return -EINVAL;

	status = nse_fltr_add_vlan(vsi, vlan);
	if (status && status != NSE_ERR_ALREADY_EXISTS) {
		err = -ENODEV;
		dev_err(nse_pf_to_dev(vsi->back), "Failure Adding VLAN %d on VSI(abs_num=%i), status %s\n",
			vlan->vid, vsi->vsi_abs_num, nse_stat_str(status));
	} else {
		vsi->num_vlan++;
	}

	return err;
}

/**
 * nse_vsi_del_vlan - default del VLAN implementation for all VSI types
 * @vsi: VSI being configured
 * @vlan: VLAN filter to delete
 */
int nse_vsi_del_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_pf *pf = vsi->back;
	enum nse_status status;
	struct device *dev;
	int err = 0;

	dev = nse_pf_to_dev(pf);

	if (!validate_vlan(vsi, vlan))
		return -EINVAL;

	status = nse_fltr_remove_vlan(vsi, vlan);
	if (!status) {
		vsi->num_vlan--;
	} else if (status != NSE_ERR_DOES_NOT_EXIST &&
		   status != NSE_ERR_HIGH_RESET_ONGOING) {
		dev_err(dev, "Error removing VLAN %d on VSI(abs_num=%i) error: %s\n",
			vlan->vid, vsi->vsi_abs_num, nse_stat_str(status));
		err = nse_status_to_errno(status);
	}

	return err;
}

/**
 * nse_vsi_manage_vlan_insertion - Manage VLAN insertion for the VSI for Tx
 * @vsi: the VSI being changed
 */
static int nse_vsi_manage_vlan_insertion(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	ctxt->info.ctag_port_based = 0;
	ctxt->info.ctag_port_based_tci = 0;
	ctxt->info.ctag_host_insertion_mode =
		cpu_to_le16(NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_ACCEPT_ALL);

	/* Preserve existing VLAN strip setting */
	/* --- no need, because we memcpy() above.
	 * ctxt->info.ctag_host_expose_mode = vsi->info.ctag_host_expose_mode;
	 */

	ctxt->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_CTAG_VALID);

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI for VLAN insert failed, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
		goto out;
	}

	/* save temp ctxt->info changed content, into vsi->info */
	vsi->info.ctag_port_based = ctxt->info.ctag_port_based;
	vsi->info.ctag_port_based_tci = ctxt->info.ctag_port_based_tci;
	vsi->info.ctag_host_insertion_mode = ctxt->info.ctag_host_insertion_mode;

out:
	kfree(ctxt);
	return err;
}

/**
 * nse_vsi_manage_vlan_stripping - Manage VLAN stripping for the VSI for Rx
 * @vsi: the VSI being changed
 * @ena: boolean value indicating if this is a enable or disable request
 */
static int nse_vsi_manage_vlan_stripping(struct nse_vsi *vsi, bool ena)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	/* do not allow modifying VLAN stripping when a port VLAN is configured
	 * on this VSI
	 */
	if (vsi->info.ctag_port_based)
		return 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	/* Here we are configuring what the VSI should do with the VLAN tag in
	 * the Rx packet. We can either leave the tag in the packet or put it in
	 * the Rx descriptor.
	 */
	if (ena)
		/* Strip VLAN tag from Rx packet and put it in the desc */
		ctxt->info.ctag_host_expose_mode =
			NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_SHOW_ALL_IN_DESC;
	else
		/* Disable stripping. Leave tag in packet */
		ctxt->info.ctag_host_expose_mode = NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_DO_NOTHING;

	/* Allow all packets untagged/tagged */
	ctxt->info.ctag_host_insertion_mode = NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_ACCEPT_ALL;

	ctxt->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_CTAG_VALID);

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI for VLAN strip failed, ena = %d err %s aq_err %s\n",
			ena, nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
		goto out;
	}

	/* save temp ctxt->info changed content, into vsi->info */
	vsi->info.ctag_host_expose_mode = ctxt->info.ctag_host_expose_mode;
	vsi->info.ctag_host_insertion_mode = ctxt->info.ctag_host_insertion_mode;

out:
	kfree(ctxt);
	return err;
}

int nse_vsi_ena_inner_stripping(struct nse_vsi *vsi, const u16 tpid)
{
	if (tpid != ETH_P_8021Q) {
		print_invalid_tpid(vsi, tpid);
		return -EINVAL;
	}

	return nse_vsi_manage_vlan_stripping(vsi, true);
}

int nse_vsi_dis_inner_stripping(struct nse_vsi *vsi)
{
	return nse_vsi_manage_vlan_stripping(vsi, false);
}

int nse_vsi_ena_inner_insertion(struct nse_vsi *vsi, const u16 tpid)
{
	if (tpid != ETH_P_8021Q) {
		print_invalid_tpid(vsi, tpid);
		return -EINVAL;
	}

	return nse_vsi_manage_vlan_insertion(vsi);
}

int nse_vsi_dis_inner_insertion(struct nse_vsi *vsi)
{
	return nse_vsi_manage_vlan_insertion(vsi);
}

/**
 * nse_cfg_vlan_pruning - enable or disable VLAN pruning on the VSI
 * @vsi: VSI to enable or disable VLAN pruning on
 * @enable: set to true to enable VLAN pruning and false to disable it
 *
 * returns 0 if VSI is updated, negative otherwise
 */
static int nse_cfg_vlan_pruning_flex(struct nse_vsi *vsi, bool enable)
{
	if (nse_bypass_switch)
		return 0;

	if (!vsi)
		return -EINVAL;

	/* Don't enable VLAN pruning if the netdev is currently in promiscuous
	 * mode. VLAN pruning will be enabled when the interface exits
	 * promiscuous mode if any VLAN filters are active.
	 */
	if (vsi->netdev && vsi->netdev->flags & IFF_PROMISC && enable)
		return 0;

	if (enable)
		return nse_vsi_update_switch(vsi, nse_vsi_ctx_set_vlan_rx_filter);
	else
		return nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_vlan_rx_filter);
}

static int nse_cfg_vlan_pruning_legacy(struct nse_vsi *vsi, bool enable)
{
	if (nse_bypass_switch)
		return 0;

	if (!vsi)
		return -EINVAL;

	/* Don't enable VLAN pruning if the netdev is currently in promiscuous
	 * mode. VLAN pruning will be enabled when the interface exits
	 * promiscuous mode if any VLAN filters are active.
	 */
	if (vsi->netdev && vsi->netdev->flags & IFF_PROMISC && enable)
		return 0;

	/*when enable rx vlan filter, we should clear vaccept,
	 * which means that we don't receive unmatch vlan pkt
	 */
	if (enable)
		return nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_vaccept);
	else
		return nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_vaccept);
}

int nse_vsi_ena_rx_vlan_filtering(struct nse_vsi *vsi)
{
	struct nse_hw *hw = NULL;
	int err = 0;

	if (!vsi)
		return -EINVAL;

	hw = &vsi->back->hw;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_cfg_vlan_pruning_flex(vsi, true);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_cfg_vlan_pruning_legacy(vsi, true);

	return err;
}

int nse_vsi_dis_rx_vlan_filtering(struct nse_vsi *vsi)
{
	struct nse_hw *hw = NULL;
	int err = 0;

	if (!vsi)
		return -EINVAL;

	hw = &vsi->back->hw;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_cfg_vlan_pruning_flex(vsi, false);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_cfg_vlan_pruning_legacy(vsi, false);

	return err;
}

static int nse_cfg_vlan_antispoof_flex(struct nse_vsi *vsi, bool enable)
{
	if (nse_bypass_switch)
		return 0;

	if (!vsi)
		return -EINVAL;

	if (enable)
		return nse_vsi_update_switch(vsi, nse_vsi_ctx_set_vlan_antispoof);
	else
		return nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_vlan_antispoof);
}

static int nse_cfg_vlan_antispoof_legacy(struct nse_vsi *vsi, bool enable)
{
	/*there is no anti spoof feature in hardware legacy switch*/
	return 0;
}

int nse_vsi_ena_tx_vlan_filtering(struct nse_vsi *vsi)
{
	struct nse_hw *hw = NULL;
	int err = 0;

	if (!vsi)
		return -EINVAL;

	hw = &vsi->back->hw;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_cfg_vlan_antispoof_flex(vsi, true);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_cfg_vlan_antispoof_legacy(vsi, true);

	return err;
}

int nse_vsi_dis_tx_vlan_filtering(struct nse_vsi *vsi)
{
	struct nse_hw *hw = NULL;
	int err = 0;

	if (!vsi)
		return -EINVAL;

	hw = &vsi->back->hw;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_cfg_vlan_antispoof_flex(vsi, false);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_cfg_vlan_antispoof_legacy(vsi, false);

	return err;
}

/**
 * nse_vsi_ena_outer_stripping - enable outer VLAN stripping
 * @vsi: VSI to configure
 * @tpid: TPID to enable outer VLAN stripping for
 *
 * Enable outer VLAN stripping via VSI context. This function should only be
 * used if DVM is supported. Also, this function should never be called directly
 * as it should be part of nse_vsi_vlan_ops if it's needed.
 *
 * Since the VSI context only supports a single TPID for insertion and
 * stripping, setting the TPID for stripping will affect the TPID for insertion.
 * Callers need to be aware of this limitation.
 *
 * Only modify outer VLAN stripping settings and the VLAN TPID. Outer VLAN
 * insertion settings are unmodified.
 *
 * This enables hardware to strip a VLAN tag with the specified TPID to be
 * stripped from the packet and placed in the receive descriptor.
 */
int nse_vsi_ena_outer_stripping(struct nse_vsi *vsi, u16 tpid)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	/* do not allow modifying VLAN stripping when a port VLAN is configured
	 * on this VSI
	 */
	if (vsi->info.stag_port_based)
		return 0;

	if (tpid != hw->stag_ethertype)
		return -EINVAL;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	ctxt->info.valid_sections =
		cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_STAG_VALID);

	ctxt->info.stag_host_expose_mode =
		cpu_to_le16(NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_SHOW_ALL_IN_DESC);

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI for enabling outer VLAN stripping failed, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
	} else {
		/* save temp ctxt->info changed content, into vsi->info */
		vsi->info.stag_host_expose_mode = ctxt->info.stag_host_expose_mode;
	}

	kfree(ctxt);
	return err;
}

/**
 * nse_vsi_dis_outer_stripping - disable outer VLAN stripping
 * @vsi: VSI to configure
 *
 * Disable outer VLAN stripping via VSI context. This function should only be
 * used if DVM is supported. Also, this function should never be called directly
 * as it should be part of nse_vsi_vlan_ops if it's needed.
 *
 * Only modify the outer VLAN stripping settings. The VLAN TPID and outer VLAN
 * insertion settings are unmodified.
 *
 * This tells the hardware to not strip any VLAN tagged packets, thus leaving
 * them in the packet. This enables software offloaded VLAN stripping and
 * disables hardware offloaded VLAN stripping.
 */
int nse_vsi_dis_outer_stripping(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	if (vsi->info.stag_port_based)
		return 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	ctxt->info.valid_sections =
		cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_STAG_VALID);

	ctxt->info.stag_host_expose_mode = cpu_to_le16(NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_DO_NOTHING);

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI for disabling outer VLAN stripping failed, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
	} else {
		/* save temp ctxt->info changed content, into vsi->info */
		vsi->info.stag_host_expose_mode = ctxt->info.stag_host_expose_mode;
	}

	kfree(ctxt);
	return err;
}

/**
 * nse_vsi_ena_outer_insertion - enable outer VLAN insertion
 * @vsi: VSI to configure
 * @tpid: TPID to enable outer VLAN insertion for
 *
 * Enable outer VLAN insertion via VSI context. This function should only be
 * used if DVM is supported. Also, this function should never be called directly
 * as it should be part of nse_vsi_vlan_ops if it's needed.
 *
 * Since the VSI context only supports a single TPID for insertion and
 * stripping, setting the TPID for insertion will affect the TPID for stripping.
 * Callers need to be aware of this limitation.
 *
 * Only modify outer VLAN insertion settings and the VLAN TPID. Outer VLAN
 * stripping settings are unmodified.
 *
 * This allows a VLAN tag with the specified TPID to be inserted in the transmit
 * descriptor.
 */
int nse_vsi_ena_outer_insertion(struct nse_vsi *vsi, u16 tpid)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	if (vsi->info.stag_port_based)
		return 0;

	if (tpid != hw->stag_ethertype)
		return -EINVAL;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	ctxt->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_STAG_VALID);

	ctxt->info.stag_port_based = 0;
	ctxt->info.stag_port_based_tci = 0;
	ctxt->info.stag_host_insertion_mode = NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_ALL;

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI for enabling outer VLAN insertion failed, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
	} else {
		/* save temp ctxt->info changed content, into vsi->info */
		vsi->info.stag_port_based = ctxt->info.stag_port_based;
		vsi->info.stag_port_based_tci = ctxt->info.stag_port_based_tci;
		vsi->info.stag_host_insertion_mode = ctxt->info.stag_host_insertion_mode;
	}

	kfree(ctxt);
	return err;
}

/**
 * nse_vsi_dis_outer_insertion - disable outer VLAN insertion
 * @vsi: VSI to configure
 *
 * Disable outer VLAN insertion via VSI context. This function should only be
 * used if DVM is supported. Also, this function should never be called directly
 * as it should be part of nse_vsi_vlan_ops if it's needed.
 *
 * Only modify the outer VLAN insertion settings. The VLAN TPID and outer VLAN
 * settings are unmodified.
 *
 * This tells the hardware to not allow any VLAN tagged packets in the transmit
 * descriptor. This enables software offloaded VLAN insertion and disables
 * hardware offloaded VLAN insertion.
 */
int nse_vsi_dis_outer_insertion(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	if (vsi->info.stag_port_based)
		return 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	ctxt->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_STAG_VALID);

	ctxt->info.stag_port_based = 0;
	ctxt->info.stag_port_based_tci = 0;
	ctxt->info.stag_host_insertion_mode = NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_ALL;

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI for enabling outer VLAN insertion failed, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
	} else {
		/* save temp ctxt->info changed content, into vsi->info */
		vsi->info.stag_port_based = ctxt->info.stag_port_based;
		vsi->info.stag_port_based_tci = ctxt->info.stag_port_based_tci;
		vsi->info.stag_host_insertion_mode = ctxt->info.stag_host_insertion_mode;
	}

	kfree(ctxt);
	return err;
}

/**
 * __nse_vsi_set_outer_port_vlan - set the outer port VLAN and related settings
 * @vsi: VSI to configure
 * @vlan_info: packed u16 that contains the VLAN prio and ID
 * @tpid: TPID of the port VLAN
 *
 * Set the port VLAN prio, ID, and TPID.
 *
 * Enable VLAN pruning so the VSI doesn't receive any traffic that doesn't match
 * a VLAN prune rule. The caller should take care to add a VLAN prune rule that
 * matches the port VLAN ID and TPID.
 *
 * Tell hardware to strip outer VLAN tagged packets on receive and don't put
 * them in the receive descriptor. VSI(s) in port VLANs should not be aware of
 * the port VLAN ID or TPID they are assigned to.
 *
 * Tell hardware to prevent outer VLAN tag insertion on transmit and only allow
 * untagged outer packets from the transmit descriptor.
 *
 * Also, tell the hardware to insert the port VLAN on transmit.
 */
int
__nse_vsi_set_outer_port_vlan(struct nse_vsi *vsi, u16 vlan_info, u16 tpid)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID)) {
		dev_err(dev, "[%s] BAD: this mac_type does not support port-based VLAN\n",
			__func__);
		return -EOPNOTSUPP;
	}

	nse_debug(hw, NSE_DBG_LAN, "[%s], vlan_info=0x%X, tpid=0x%X, outer_tag_tpid=0x%X\n",
								__func__, vlan_info, tpid,
									hw->stag_ethertype);

	if (tpid != hw->stag_ethertype) {
		dev_err(dev, "[%s] BAD: tpid(0x%X) != outer_tag_tpid(0x%X)\n",
			__func__, tpid, hw->stag_ethertype);
		return -EINVAL;
	}

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	nse_vsi_ctx_set_vlan_rx_filter(ctxt);

	ctxt->info.stag_port_based = cpu_to_le16(1);
	ctxt->info.stag_port_based_tci = cpu_to_le16(vlan_info);
	ctxt->info.stag_host_insertion_mode =
		cpu_to_le16(NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_UNTAGGED);
	ctxt->info.stag_host_expose_mode = cpu_to_le16(NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_SHOW_NONE);

	ctxt->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_STAG_VALID);
	ctxt->info.valid_sections |= cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_SW_VALID);

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(dev, "[%s] FAIL: update_vsi() for setting outer port based VLAN failed, err %s aq_err %s\n",
						__func__, nse_stat_str(status),
							nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
	} else {
		/* save temp ctxt->info changed content, into vsi->info */
		vsi->info.stag_port_based = ctxt->info.stag_port_based;
		vsi->info.stag_port_based_tci = ctxt->info.stag_port_based_tci;
		vsi->info.stag_host_insertion_mode = ctxt->info.stag_host_insertion_mode;
		vsi->info.stag_host_expose_mode = ctxt->info.stag_host_expose_mode;
		vsi->info.rpp_per_vsi_ctxt = ctxt->info.rpp_per_vsi_ctxt;
		vsi->info.tpp_per_vsi_ctxt = ctxt->info.tpp_per_vsi_ctxt;
	}

	kfree(ctxt);
	return err;
}

/**
 * nse_vsi_set_outer_port_vlan - public version of __nse_vsi_set_outer_port_vlan
 * @vsi: VSI to configure
 * @vlan: nse_vlan structure used to set the port VLAN
 *
 * Set the outer port VLAN via VSI context. This function should only be
 * used if DVM is supported. Also, this function should never be called directly
 * as it should be part of nse_vsi_vlan_ops if it's needed.
 *
 * This function does not support clearing the port VLAN as there is currently
 * no use case for this.
 *
 * Use the nse_vlan structure passed in to set this VSI in a port VLAN.
 */
int nse_vsi_set_outer_port_vlan(struct nse_vsi *vsi, struct nse_vlan *vlan)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 port_vlan_info;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID)) {
		dev_err(nse_pf_to_dev(pf),
			"[%s] BAD: this mac_type does not support port-based VLAN\n", __func__);
		return -EOPNOTSUPP;
	}

	if (vlan->prio > (VLAN_PRIO_MASK >> VLAN_PRIO_SHIFT)) {
		dev_err(nse_pf_to_dev(pf), "[%s] BAD vlan-prio=%d\n", __func__, vlan->prio);
		return -EINVAL;
	}

	port_vlan_info = vlan->vid | (vlan->prio << VLAN_PRIO_SHIFT);

	return __nse_vsi_set_outer_port_vlan(vsi, port_vlan_info, vlan->tpid);
}

