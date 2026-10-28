// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_common.h"
#include "nse_lib.h"
#include "nse_switch.h"
#include "nse_flex_type.h"
#include "nse_flow.h"
#include "nse_neigh.h"

void nse_dump_vsi_props(struct nse_hw *hw, struct nse_aqc_vsi_props *props)
{
	u32 val32;
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "====== VSI props (nse_aqc_vsi_props)\n");

	dev_info(dev, "lan_id: %d\n", props->hdr.lan_id);
	dev_info(dev, "chan_id: %d\n", props->hdr.chan_id);
	dev_info(dev, "dma_id: %d\n", props->hdr.dma_id);
	dev_info(dev, "vsi_abs_num: %d\n", le16_to_cpu(props->vsi_abs_num));
	dev_info(dev, "valid_sections: %X", le16_to_cpu(props->valid_sections));

	if (le16_to_cpu(props->valid_sections) & NSE_AQ_VSI_PROP_SECTION_SW_VALID) {
		dev_info(dev, "--- section: SW\n");

		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX)) {
			val32 = le32_to_cpu(props->rpp_per_vsi_ctxt);
			dev_info(dev, "rpp_per_vsi_ctxt: %X\n", val32);

			dev_info(dev, "\t prune_rx_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_RX_PRUNE));
			dev_info(dev, "\t src_prune_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_SRC_PRUNE));
			dev_info(dev, "\t en: %d\n", !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_VSI_EN));
			dev_info(dev, "\t ovs_miss_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_OVS_MISS));
			dev_info(dev, "\t dflt_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_DFLT_VSI));
			dev_info(dev, "\t mac_sp_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_MAC_SRC_PRUNE));
			dev_info(dev, "\t mirr_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_RPP_MIRR_EN));
			dev_info(dev, "\t mirr_vsi: %d\n",
				 ((val32 & NSE_AQ_VSI_SW_FLAG_RPP_MIRR_VSI_M) >>
				  NSE_AQ_VSI_SW_FLAG_RPP_MIRR_VSI_S));
			dev_info(dev, "\t swid: %d\n", ((val32 & NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_M) >>
				 NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_S));

			val32 = le32_to_cpu(props->tpp_per_vsi_ctxt);
			dev_info(dev, "tpp_per_vsi_ctxt: %X\n", val32);
			dev_info(dev, "\t prune_tx_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_TX_PRUNE));
			dev_info(dev, "\t prune_rx_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_RX_PRUNE));
			dev_info(dev, "\t dest_ovrd_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_ALLOW_DEST_OVRD));
			dev_info(dev, "\t src_prune_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_SRC_PRUNE));
			dev_info(dev, "\t en: %d\n", !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_VSI_EN));
			dev_info(dev, "\t lan_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_LAN_ENA));
			dev_info(dev, "\t lb_tx_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_TX_ALLOW_LB));
			dev_info(dev, "\t lb_rx_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_RX_ALLOW_LB));
			dev_info(dev, "\t ovs_miss_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_OVS_MISS));
			dev_info(dev, "\t mac_as_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_MAC_ANTI_SPOOF));
			dev_info(dev, "\t vlan_as_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_VLAN_ANTI_SPOOF));
			dev_info(dev, "\t mirr_en: %d\n",
				 !!(val32 & NSE_AQ_VSI_SW_FLAG_TPP_MIRR_EN));
			dev_info(dev, "\t mirr_vsi: %d\n",
				 ((val32 & NSE_AQ_VSI_SW_FLAG_TPP_MIRR_VSI_M) >>
				  NSE_AQ_VSI_SW_FLAG_TPP_MIRR_VSI_S));
			dev_info(dev, "\t swid: %d\n", ((val32 & NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_M) >>
				 NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_S));

		}		else if (nse_is_hw_static_fea_set(hw,
					 NSE_HW_STATIC_FEA_SWITCH_LEGACY)) {
			val32 = le32_to_cpu(props->rsw_per_vsi_l2ctxt);
			dev_info(dev, "rsw_per_vsi_l2ctxt: %X\n", val32);

			dev_info(dev, "\t UPE: %d\n", !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_UPE));
			dev_info(dev, "\t MPE: %d\n", !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_MPE));
			dev_info(dev, "\t BAM: %d\n", !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_BAM));
			dev_info(dev, "\t VPE: %d\n", !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VPE));
			dev_info(dev, "\t VACCEPT: %d\n",
				 !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VACCEPT));
			dev_info(dev, "\t AUPE: %d\n",
				 !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_AUPE));
			dev_info(dev, "\t RX_DEF: %d\n",
				 !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_RX_DEF));
			dev_info(dev, "\t MAC_SRC_PRUNE: %d\n",
				 !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_MAC_SRC_PRUNE));
			dev_info(dev, "\t EG_MIRROR: %d\n",
				 !!(val32 & NSE_AQ_VSI_L2_CTRL_FLAG_RSW_EG_MIRROR));

		} else {
			dev_info(dev, "sw_section_dummy: %X\n", props->sw_section_dummy);
		}
	}

	if (le16_to_cpu(props->valid_sections) & NSE_AQ_VSI_PROP_SECTION_RXMAX_VALID) {
		dev_info(dev, "--- section: RXMAX\n");

		dev_info(dev, "rxmax: %d\n", le32_to_cpu(props->rxmax));
	}

	if (le16_to_cpu(props->valid_sections) & NSE_AQ_VSI_PROP_SECTION_CTAG_VALID) {
		dev_info(dev, "--- section: CTAG\n");

		dev_info(dev, "ctag_port_based_tci: %X\n", le16_to_cpu(props->ctag_port_based_tci));
		dev_info(dev, "ctag_host_insertion_mode: %X\n",
			 le16_to_cpu(props->ctag_host_insertion_mode));
		dev_info(dev, "ctag_port_based: %X\n", le16_to_cpu(props->ctag_port_based));
		dev_info(dev, "ctag_host_expose_mode: %X\n",
			 le16_to_cpu(props->ctag_host_expose_mode));
	}

	if (le16_to_cpu(props->valid_sections) & NSE_AQ_VSI_PROP_SECTION_STAG_VALID) {
		dev_info(dev, "--- section: STAG\n");

		dev_info(dev, "stag_port_based_tci: %X\n", le16_to_cpu(props->stag_port_based_tci));
		dev_info(dev, "stag_host_insertion_mode: %X\n",
			 le16_to_cpu(props->stag_host_insertion_mode));
		dev_info(dev, "stag_port_based: %X\n", le16_to_cpu(props->stag_port_based));
		dev_info(dev, "stag_host_expose_mode: %X\n",
			 le16_to_cpu(props->stag_host_expose_mode));
	}

	if (le16_to_cpu(props->valid_sections) & NSE_AQ_VSI_PROP_SECTION_PE_VALID) {
		dev_info(dev, "--- section: PE\n");

		dev_info(dev, "pe_flags: %X\n", props->pe_flags);
	}

	if (le16_to_cpu(props->valid_sections) & NSE_AQ_VSI_PROP_SECTION_PASID_VALID) {
		dev_info(dev, "--- section: PASID\n");

		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_SIOV))  {
			dev_info(dev, "pasid_flags: %X\n", le32_to_cpu(props->pasid_flags));
			dev_info(dev, "pasid_id: %X\n", le32_to_cpu(props->pasid_id));
		} else {
			dev_info(dev, "pasid_section_dummy: %X\n",
				 le32_to_cpu(props->pasid_section_dummy));
		}
	}
}

void nse_set_dflt_vsi_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_vsi_ctx *ctxt)
{
	struct nse_aqc_vsi_props *props = &ctxt->info;
	u16 valid_sections = 0;

	memset(&ctxt->info, 0, sizeof(ctxt->info));

	nse_aqc_fill_generic_common_hdr_dft(hw, &ctxt->info.hdr, vsi->vsi_abs_num);

	ctxt->vsi_abs_num = vsi->vsi_abs_num;
	ctxt->info.vsi_abs_num = cpu_to_le16(vsi->vsi_abs_num);

	/* section: Switching
	 */
	valid_sections |= NSE_AQ_VSI_PROP_SECTION_SW_VALID;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX)) {
		props->sw_section_dummy = 0;

	} else {
		/* Src pruning enabled by default
		 * Traffic from VSI can be sent to LAN
		 */
		props->rpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_VSI_EN);
		props->rpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_SRC_PRUNE);

		props->tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_VSI_EN);
		props->tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_SRC_PRUNE |
						       NSE_AQ_VSI_SW_FLAG_TPP_LAN_ENA);

		/* overwrite the setting above */
		if (nse_bypass_switch) {
			/* rpp_per_vsi_ctxt
			 *
			 *		mac_sp_en = 0
			 *
			 *		others are all 0
			 */
			props->rpp_per_vsi_ctxt = cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_VSI_EN);

			props->tpp_per_vsi_ctxt =
				cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_ALLOW_DEST_OVRD |
					    NSE_AQ_VSI_SW_FLAG_TPP_VSI_EN |
					    NSE_AQ_VSI_SW_FLAG_TPP_LAN_ENA |
					    NSE_AQ_VSI_SW_FLAG_TPP_TX_ALLOW_LB |
					    NSE_AQ_VSI_SW_FLAG_TPP_RX_ALLOW_LB);
		}

		/* if the switch is in VEB mode, allow VSI loopback */
		if (vsi->vsw->bridge_mode == BRIDGE_MODE_VEB)
			props->tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_TX_ALLOW_LB |
						NSE_AQ_VSI_SW_FLAG_TPP_RX_ALLOW_LB);

		props->tpp_per_vsi_ctxt |= cpu_to_le32(((u32)vsi->port_info->sw_id <<
						NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_S) &
							NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_M);
		props->rpp_per_vsi_ctxt |= cpu_to_le32(((u32)vsi->port_info->sw_id <<
						NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_S) &
							NSE_AQ_VSI_SW_FLAG_RPP_SW_ID_M);

		/* Allow control frames out of main VSI */
		if (vsi->type == NSE_VSI_PF)
			props->tpp_per_vsi_ctxt |=
				cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_ALLOW_DEST_OVRD);
	}

	/* section: RXMAX
	 */
	valid_sections |= NSE_AQ_VSI_PROP_SECTION_RXMAX_VALID;

	props->rxmax = cpu_to_le32(NSE_AQ_SET_MAC_FRAME_SIZE_MAX);

	/* section: "STag Handling"
	 * section: "CTag Handling"
	 */
	valid_sections |= NSE_AQ_VSI_PROP_SECTION_STAG_VALID;
	valid_sections |= NSE_AQ_VSI_PROP_SECTION_CTAG_VALID;

	props->stag_port_based = 0;
	props->stag_port_based_tci = 0;
	props->stag_host_insertion_mode = NSE_AQ_VSI_STAG_HOST_INSERTION_MODE_ACCEPT_ALL;
	props->stag_host_expose_mode = NSE_AQ_VSI_STAG_HOST_EXPOSE_MODE_DO_NOTHING;

	props->ctag_port_based = 0;
	props->ctag_port_based_tci = 0;
	props->ctag_host_insertion_mode = NSE_AQ_VSI_CTAG_HOST_INSERTION_MODE_ACCEPT_ALL;
	props->ctag_host_expose_mode = NSE_AQ_VSI_CTAG_HOST_EXPOSE_MODE_DO_NOTHING;

	/*  section: "PASID" - all-0 by default, util we implement SIOV, and configure ADI-VSI.
	 */

	props->valid_sections = cpu_to_le16(valid_sections);
}

/**
 * nse_aq_add_vsi
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Add a VSI context to the hardware (0x0210)
 */
static enum nse_status
nse_aq_add_vsi(struct nse_hw *hw, struct nse_vsi_ctx *vsi_ctx,
	       struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_CFG_VSI);

	nse_aqc_fill_generic_common_hdr_dft(hw, &vsi_ctx->info.hdr, vsi_ctx->vsi_abs_num);

	vsi_ctx->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_VALID_ALL);

	if (hw->debug_mask & NSE_DBG_SW)
		nse_dump_vsi_props(hw, &vsi_ctx->info);

	status = nse_aq_send_cmd(hw, &desc, &vsi_ctx->info,
				 sizeof(vsi_ctx->info), cd);

	return status;
}

/**
 * nse_aq_free_vsi
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @keep_vsi_alloc: keep VSI allocation as part of this PF's resources
 * @cd: pointer to command details structure or NULL
 *
 * Free VSI context info from hardware (0x0213)
 */
static enum nse_status
nse_aq_free_vsi(struct nse_hw *hw, struct nse_vsi_ctx *vsi_ctx,
	       struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_FREE_VSI);

	nse_aqc_fill_generic_common_hdr_dft(hw, &vsi_ctx->info.hdr, vsi_ctx->vsi_abs_num);

	if (hw->debug_mask & NSE_DBG_SW)
		nse_dump_vsi_props(hw, &vsi_ctx->info);

	status = nse_aq_send_cmd(hw, &desc, &vsi_ctx->info,
				sizeof(vsi_ctx->info), cd);

	return status;
}

/**
 * nse_aq_update_vsi
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Update VSI context in the hardware (0x0211)
 */
static enum nse_status
nse_aq_update_vsi(struct nse_hw *hw, struct nse_vsi_ctx *vsi_ctx,
		  struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_CFG_VSI);

	nse_aqc_fill_generic_common_hdr_dft(hw, &vsi_ctx->info.hdr, vsi_ctx->vsi_abs_num);

	if (hw->debug_mask & NSE_DBG_SW)
		nse_dump_vsi_props(hw, &vsi_ctx->info);

	status = nse_aq_send_cmd(hw, &desc, &vsi_ctx->info,
				 sizeof(vsi_ctx->info), cd);

	return status;
}

/**
 * nse_is_vsi_valid - check whether the VSI is valid or not
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * check whether the VSI is valid or not
 */
bool nse_is_vsi_valid(struct nse_hw *hw, u16 vsi_handle)
{
	return vsi_handle < NSE_MAX_VSI && hw->vsi_ctx[vsi_handle];
}

/**
 * nse_get_hw_vsi_num - return the HW VSI number
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * return the HW VSI number
 * Caution: call this function only if VSI is valid (nse_is_vsi_valid)
 */
u16 nse_get_hw_vsi_num(struct nse_hw *hw, u16 vsi_handle)
{
	return hw->vsi_ctx[vsi_handle]->vsi_abs_num;
}

/**
 * nse_get_vsi_ctx - return the VSI context entry for a given VSI handle
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * return the VSI context entry for a given VSI handle
 */
struct nse_vsi_ctx *nse_get_vsi_ctx(struct nse_hw *hw, u16 vsi_handle)
{
	return (vsi_handle >= NSE_MAX_VSI) ? NULL : hw->vsi_ctx[vsi_handle];
}

/**
 * nse_save_vsi_ctx - save the VSI context for a given VSI handle
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 * @vsi: VSI context pointer
 *
 * save the VSI context entry for a given VSI handle
 */
static void
nse_save_vsi_ctx(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi)
{
	hw->vsi_ctx[vsi_handle] = vsi;
}

/**
 * nse_clear_vsi_q_ctx - clear VSI queue contexts for all TCs
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 */
static void nse_clear_vsi_q_ctx(struct nse_hw *hw, u16 vsi_handle)
{
	struct nse_vsi_ctx *vsi;
	u8 i;

	vsi = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi)
		return;
	nse_for_each_traffic_class(i) {
		if (vsi->lan_q_ctx[i]) {
			devm_kfree(nse_hw_to_dev(hw), vsi->lan_q_ctx[i]);
			vsi->lan_q_ctx[i] = NULL;
		}
		if (vsi->rdma_q_ctx[i]) {
			devm_kfree(nse_hw_to_dev(hw), vsi->rdma_q_ctx[i]);
			vsi->rdma_q_ctx[i] = NULL;
		}
	}
}

/**
 * nse_clear_vsi_ctx - clear the VSI context entry
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * clear the VSI context entry
 */
static void nse_clear_vsi_ctx(struct nse_hw *hw, u16 vsi_handle)
{
	struct nse_vsi_ctx *vsi;

	vsi = nse_get_vsi_ctx(hw, vsi_handle);
	if (vsi) {
		nse_clear_vsi_q_ctx(hw, vsi_handle);
		devm_kfree(nse_hw_to_dev(hw), vsi);
		hw->vsi_ctx[vsi_handle] = NULL;
	}
}

/**
 * nse_clear_all_vsi_ctx - clear all the VSI context entries
 * @hw: pointer to the HW struct
 */
void nse_clear_all_vsi_ctx(struct nse_hw *hw)
{
	u16 i;

	for (i = 0; i < NSE_MAX_VSI; i++)
		nse_clear_vsi_ctx(hw, i);
}

/**
 * nse_add_vsi - add VSI context to the hardware and VSI handle list
 * @hw: pointer to the HW struct
 * @vsi_handle: unique VSI handle provided by drivers
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Add a VSI context to the hardware also add it into the VSI handle list.
 * If this function gets called after reset for existing VSIs then update
 * with the new HW VSI number in the corresponding VSI handle list entry.
 */
enum nse_status
nse_add_vsi(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi_ctx,
	    struct nse_sq_cd *cd)
{
	struct nse_vsi_ctx *tmp_vsi_ctx;
	enum nse_status status;

	if (vsi_handle >= NSE_MAX_VSI)
		return NSE_ERR_PARAM;
	status = nse_aq_add_vsi(hw, vsi_ctx, cd);
	if (status)
		return status;
	tmp_vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!tmp_vsi_ctx) {
		/* Create a new VSI context */
		tmp_vsi_ctx = devm_kzalloc(nse_hw_to_dev(hw),
					   sizeof(*tmp_vsi_ctx), GFP_KERNEL);
		if (!tmp_vsi_ctx) {
			nse_aq_free_vsi(hw, vsi_ctx, cd);
			return NSE_ERR_NO_MEMORY;
		}
		*tmp_vsi_ctx = *vsi_ctx;

		nse_save_vsi_ctx(hw, vsi_handle, tmp_vsi_ctx);
	} else {
		/* update with new HW VSI num */
		tmp_vsi_ctx->vsi_abs_num = vsi_ctx->vsi_abs_num;
	}

	return 0;
}

/**
 * nse_free_vsi- free VSI context from hardware and VSI handle list
 * @hw: pointer to the HW struct
 * @vsi_handle: unique VSI handle
 * @vsi_ctx: pointer to a VSI context struct
 * @keep_vsi_alloc: keep VSI allocation as part of this PF's resources
 * @cd: pointer to command details structure or NULL
 *
 * Free VSI context info from hardware as well as from VSI handle list
 */
enum nse_status
nse_free_vsi(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi_ctx,
	    struct nse_sq_cd *cd)
{
	enum nse_status status;

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;
	status = nse_aq_free_vsi(hw, vsi_ctx, cd);
	if (!status)
		nse_clear_vsi_ctx(hw, vsi_handle);
	return status;
}

/**
 * nse_update_vsi
 * @hw: pointer to the HW struct
 * @vsi_handle: unique VSI handle
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Update VSI context in the hardware
 */
enum nse_status
nse_update_vsi(struct nse_hw *hw, u16 vsi_handle, struct nse_vsi_ctx *vsi_ctx,
	       struct nse_sq_cd *cd)
{
	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;
	return nse_aq_update_vsi(hw, vsi_ctx, cd);
}

enum nse_status
nse_cfg_roce_fltr(struct nse_hw *hw, u16 vsi_handle, bool enable)
{
	struct nse_vsi_ctx *ctx, *cached_ctx;
	enum nse_status status;

	if (!nse_rdma_ena || !nse_is_hw_dyn_fea_set(hw, NSE_HW_DYN_FEA_SUPPORT_RDMA))
		return NSE_SUCCESS;

	cached_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!cached_ctx)
		return NSE_ERR_DOES_NOT_EXIST;

	ctx = devm_kcalloc(nse_hw_to_dev(hw), 1, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NSE_ERR_NO_MEMORY;

	memcpy(ctx, cached_ctx, sizeof(*ctx));

	/* only configure PE sections */
	ctx->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_PE_VALID);

	if (enable)
		ctx->info.pe_flags |= NSE_AQ_VSI_PE_FLAG_FLTR_EN;
	else
		ctx->info.pe_flags &= ~NSE_AQ_VSI_PE_FLAG_FLTR_EN;

	status = nse_update_vsi(hw, vsi_handle, ctx, NULL);
	if (!status) {
		cached_ctx->info.pe_flags = ctx->info.pe_flags;
		cached_ctx->info.valid_sections |= ctx->info.valid_sections;
	}

	devm_kfree(nse_hw_to_dev(hw), ctx);
	return status;
}

/**
 * nse_init_def_lut - initialize the software book keeping tables
 * @hw: pointer to the HW struct
 * @lut_list: pointer to sw recipe list
 *
 */
enum nse_status
nse_init_def_lut(struct nse_hw *hw, struct nse_lut_info **lut_list)
{
	struct nse_lut_info *luts;
	u16 i;

	luts = devm_kcalloc(nse_hw_to_dev(hw), NSE_MAX_NUM_LUTS,
			     sizeof(*luts), GFP_KERNEL);

	if (!luts)
		return NSE_ERR_NO_MEMORY;

	for (i = 0; i < NSE_MAX_NUM_LUTS; i++) {
		luts[i].lut_id = i;
		INIT_LIST_HEAD(&luts[i].filt_rules);
		INIT_LIST_HEAD(&luts[i].filt_replay_rules);
		INIT_LIST_HEAD(&luts[i].fv_list);
		INIT_LIST_HEAD(&luts[i].lut_group_list);
		mutex_init(&luts[i].filt_rule_lock);
	}

	*lut_list = luts;

	return NSE_SUCCESS;
}

/**
 * nse_aq_get_sw_cfg - get switch configuration
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_get_sw_cfg(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_GET_SW_CFG);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_aq_vsi_list_rules - add/update vsi list content
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_vsi_list_rules(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_VSI_LIST &&
	    opc != NSE_AQ_OPC_UPDATE_VSI_LIST)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_VSI_LIST &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_get_remove_vsi_list_rules - get/remove vsi list content
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_get_remove_vsi_list(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_REMOVE_VSI_LIST &&
	    opc != NSE_AQ_OPC_GET_VSI_LIST)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_lut_nodes - add/update/remove lut nodes
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
enum nse_status
nse_aq_lut_nodes(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_LUT_NODE &&
	    opc != NSE_AQ_OPC_UPDATE_LUT_NODE &&
	    opc != NSE_AQ_OPC_REMOVE_LUT_NODE &&
	    opc != NSE_AQ_OPC_GET_LUT_NODE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_LUT_NODE &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_fast_nodes - add/update/remove lut fast nodes
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_fast_nodes(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_LUT_FAST_NODE &&
	    opc != NSE_AQ_OPC_UPDATE_LUT_FAST_NODE &&
	    opc != NSE_AQ_OPC_REMOVE_LUT_FAST_NODE &&
	    opc != NSE_AQ_OPC_GET_LUT_FAST_NODE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_LUT_FAST_NODE &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_alloc_free_res - command to allocate/free resources
 * @hw: pointer to the HW struct
 * @num_entries: number of resource entries in buffer
 * @buf: Indirect buffer to hold data parameters and response
 * @buf_size: size of buffer for indirect commands
 * @opc: pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 * Helper function to allocate/free resources using the admin queue commands
 */
enum nse_status
nse_aq_alloc_free_res(struct nse_hw *hw, u16 num_entries,
		      struct nse_aqc_alloc_free_res_elem *buf, u16 buf_size,
		      enum nse_adminq_opc_category_switch_subcodes opc,
		      struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;

	if (!buf)
		return NSE_ERR_PARAM;

	if (buf_size < flex_array_size(buf, res_id, num_entries))
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	return nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
}

/**
 * nse_aq_alloc_free_vsi_list
 * @hw: pointer to the HW struct
 * @vsi_list_id: VSI list ID returned or used for lookup
 * @lkup_type: switch rule filter lookup type
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a VSI list resource
 */
static enum nse_status
nse_aq_alloc_free_vsi_list(struct nse_hw *hw, u16 *vsi_list_id,
			   enum nse_sw_lkup_type lkup_type,
			   enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;
	buf->num_elems = cpu_to_le16(1);

	if (lkup_type == NSE_SW_LKUP_MAC ||
	    lkup_type == NSE_SW_LKUP_MAC_VLAN ||
	    lkup_type == NSE_SW_LKUP_ETHERTYPE ||
	    lkup_type == NSE_SW_LKUP_ETHERTYPE_MAC ||
	    lkup_type == NSE_SW_LKUP_VLAN ||
		lkup_type == NSE_SW_LKUP_PROMISC ||
		lkup_type == NSE_SW_LKUP_PROMISC_VLAN ||
	    lkup_type == NSE_SW_LKUP_LAST) {
		buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_VSI_LIST_ID);
	} else {
		status = NSE_ERR_PARAM;
		goto nse_aq_alloc_free_vsi_list_exit;
	}

	if (opc == NSE_AQ_OPC_FREE_RESOURCE)
		buf->res_id[0] = cpu_to_le16(*vsi_list_id);

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_vsi_list_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*vsi_list_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced vsi list id = %d\n",
			__func__, __LINE__, *vsi_list_id);

	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free vsi list id = %d\n",
			__func__, __LINE__, *vsi_list_id);
	}

nse_aq_alloc_free_vsi_list_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_get_profile_cfg - get profile configuration
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_get_profile_cfg(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH,
				      NSE_AQ_OPC_GET_PROFILE_CFG);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_aq_update_profile_cfg - update profile configuration
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_update_profile_cfg(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH,
				      NSE_AQ_OPC_UPDATE_PROFILE_CFG);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_aq_node_states - add/update/remove node states
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_recipes(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_RECIPE &&
	    opc != NSE_AQ_OPC_UPDATE_RECIPE &&
	    opc != NSE_AQ_OPC_REMOVE_RECIPE &&
	    opc != NSE_AQ_OPC_GET_RECIPE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_RECIPE &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/* nse_init_port_info - Initialize port_info with switch configuration data
 * @pi: pointer to port_info
 * @vsi_port_num: VSI number or port number
 * @type: Type of switch element (port or VSI)
 * @swid: switch ID of the switch the element is attached to
 * @pf_vf_num: PF or VF number
 * @is_vf: true if the element is a VF, false otherwise
 */
static void
nse_init_port_info(struct nse_port_info *pi, u16 vsi_port_num, u8 type,
		   u16 swid, u16 pf_vf_num, bool is_vf)
{
	switch (type) {
	case NSE_AQC_GET_SW_CONF_RESP_PHYS_PORT:
		pi->lport = (u8)(vsi_port_num & NSE_LPORT_MASK);
		pi->sw_id = swid;
		pi->pf_vf_num = pf_vf_num;
		pi->is_vf = is_vf;
		break;
	default:
		dev_err(nse_hw_to_dev(pi->hw), "incorrect VSI/port type received\n");
		break;
	}
}

/**
 * nse_get_prof_index_max - get the max profile index for used profile
 * @hw: pointer to the HW struct
 *
 * Calling this function will get the max profile index for used profile
 * and store the index number in struct nse_switch_info *switch_info
 * in hw for following use.
 */
void nse_get_prof_index_max(struct nse_hw *hw)
{
	u16 prof_index = 0, j, max_prof_index = 0;
	bool flag = false;
	struct nse_fv *fv;
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	u32 offset;

	sw = hw->switch_info;
	for (offset = 0; offset < NSE_MAX_NUM_PROFILES; offset++) {
		profile = &sw->profile_list[offset];
		fv = &profile->fv_ptr;

		for (j = 0; j < NSE_MAX_FV_WORDS; j++)
			if (fv->ew[j].enable == NSE_FV_ENABLE)
				flag = true;

		/*update final max_prof_index when it's valid profile*/
		if (flag && prof_index > max_prof_index)
			max_prof_index = prof_index;

		/*even when current profile is invalid,
		 * prof_index still should be increased
		 */
		prof_index++;
		flag = false;
	}
	sw->max_used_prof_index = max_prof_index;
}

/**
 * nse_init_def_profiles - initialize the software profiles information
 * @hw: pointer to the HW struct
 * @profile_list: pointer to sw profile list
 *
 */
enum nse_status
nse_init_def_profiles(struct nse_hw *hw, struct nse_profile_info **profile_list)
{
	struct nse_profile_info *profiles = NULL;
	struct nse_aqc_profile_cfg *buf;
	enum nse_status status;
	u16 start_id = 0;
	u16 max_loop = NSE_AQ_GET_PRFL_MAX_LOOP, loop_cnt = 0;

	/* alloc software golbal memory DB */
	profiles = devm_kcalloc(nse_hw_to_dev(hw), NSE_MAX_NUM_PROFILES,
			     sizeof(*profiles), GFP_KERNEL);
	if (!profiles)
		return NSE_ERR_NO_MEMORY;

	/* alloc aqc buf temporary memory */
	buf = devm_kzalloc(nse_hw_to_dev(hw), NSE_AQ_MAX_BUF_LEN,
				GFP_KERNEL);
	if (!buf) {
		devm_kfree(nse_hw_to_dev(hw), profiles);
		return NSE_ERR_NO_MEMORY;
	}

	do {
		struct nse_aqc_profile_cfg_elem *ele;
		u32 num_elems;
		u32 i, j;
		u16 profile_id;

		/* set count to 0, means read all profiles*/
		buf->count = cpu_to_le16(0);
		buf->start_id = cpu_to_le16(start_id);
		dev_info(nse_hw_to_dev(hw), "request profile next start id = 0x%x\n", start_id);
		status = nse_aq_get_profile_cfg(hw, buf, NSE_AQ_MAX_BUF_LEN);
		if (status)
			goto err;

		num_elems = le16_to_cpu(buf->count);
		/* used for next get profiles aqc*/
		start_id = le16_to_cpu(buf->start_id);
		dev_info(nse_hw_to_dev(hw), "response profile next start id = 0x%x\n", start_id);
		ele = buf->elems;
		for (i = 0; i < num_elems; i++, ele++) {
			profile_id = le16_to_cpu(ele->profile_id);

			if (profile_id >= NSE_MAX_NUM_PROFILES) {
				dev_err(nse_hw_to_dev(hw), "profile id is invalid\n");
				status = NSE_ERR_HW_TABLE;
				goto err;
			}

			profiles[profile_id].profile_id = profile_id;
			profiles[profile_id].chain_id = ele->chain_id;
			profiles[profile_id].en = 1;
			profiles[profile_id].total_recipe_num =	ele->total_recipe_num;
			profiles[profile_id].used_recipe_num = ele->used_recipe_num;
			profiles[profile_id].fe_num = le16_to_cpu(ele->fe_num) &
									NSE_AQC_PROFILE_FENUM_M;
			profiles[profile_id].local_rcp = (le16_to_cpu(ele->fe_num) >>
							  NSE_AQC_PROFILE_LOCAL_RCP_S) &
									NSE_AQC_PROFILE_LOCAL_RCP_M;
			/* luts are defined by FW, a contiguous range from LUT 0 */
			for (j = 0; j < NSE_AQ_MAX_FV_WORDS; j++) {
				u32 fec_val = le32_to_cpu(ele->fvw[j].fec);

				profiles[profile_id].fv_ptr.ew[j].prot_id =
					(u8)((fec_val >> NSE_AQ_PROFILE_FEC_PROT_ID_S) &
						NSE_AQ_PROFILE_FEC_PROT_ID_M);

				profiles[profile_id].fv_ptr.ew[j].off =
					(u16)((fec_val >> NSE_AQ_PROFILE_FEC_OFF_S) &
						NSE_AQ_PROFILE_FEC_OFF_M);

				profiles[profile_id].fv_ptr.ew[j].enable =
					(u8)((fec_val >> NSE_AQ_PROFILE_FEC_EN_S) &
						NSE_AQ_PROFILE_FEC_EN_M);
			}
		}

		loop_cnt++;
		if (loop_cnt > max_loop) {
			dev_err(nse_hw_to_dev(hw), "profile total num exceeds the max value\n");
			status = NSE_ERR_HW_TABLE;
			goto err;
		}
	} while (start_id && !status);

	devm_kfree(nse_hw_to_dev(hw), buf);
	*profile_list = profiles;
	return NSE_SUCCESS;

err:
	devm_kfree(nse_hw_to_dev(hw), buf);
	devm_kfree(nse_hw_to_dev(hw), profiles);
	return status;
}

/**
 * nse_dump_sw_aq_profile_all - get and print profile config as seen by firmware
 * @hw: nse hardware struct
 */
void
nse_dump_sw_aq_profile_all(struct nse_hw *hw)
{
	struct nse_aqc_profile_cfg *buf;
	enum nse_status status;
	u16 start_id = 0;
	u16 max_loop = NSE_AQ_GET_PRFL_MAX_LOOP, loop_cnt = 0;

	/* alloc aqc buf temporary memory */
	buf = devm_kzalloc(nse_hw_to_dev(hw), NSE_AQ_MAX_BUF_LEN,
				GFP_KERNEL);
	if (!buf)
		return;

	do {
		struct nse_aqc_profile_cfg_elem *ele;
		u32 num_elems;
		u32 i, j;
		u16 profile_id;

		/* set count to 0, means read all profiles*/
		buf->count = cpu_to_le16(0);
		buf->start_id = cpu_to_le16(start_id);
		status = nse_aq_get_profile_cfg(hw, buf, NSE_AQ_MAX_BUF_LEN);
		if (status)
			goto out;

		num_elems = le16_to_cpu(buf->count);
		/* used for next get profiles aqc*/
		start_id = le16_to_cpu(buf->start_id);

		dev_info(nse_hw_to_dev(hw), "get_profile cmd 0x%x, total number is 0x%x\n",
				loop_cnt, num_elems);

		ele = buf->elems;
		for (i = 0; i < num_elems; i++, ele++) {
			profile_id = le16_to_cpu(ele->profile_id);

			if (profile_id >= NSE_MAX_NUM_PROFILES) {
				dev_err(nse_hw_to_dev(hw), "profile id is invalid\n");
				status = NSE_ERR_HW_TABLE;
				goto out;
			}
			dev_info(nse_hw_to_dev(hw), "\tPrfl_element[%d]:\n", i);
			dev_info(nse_hw_to_dev(hw), "\t\tprofile_id = 0x%x\n", profile_id);
			dev_info(nse_hw_to_dev(hw), "\t\tchain_id = 0x%x\n", ele->chain_id);
			dev_info(nse_hw_to_dev(hw), "\t\ttotal_rcp_num = 0x%x\n",
				 ele->total_recipe_num);
			dev_info(nse_hw_to_dev(hw), "\t\tused_rcp_num = 0x%x\n",
				 ele->used_recipe_num);
			dev_info(nse_hw_to_dev(hw), "\t\tfe_num = 0x%x\n",
				 le16_to_cpu(ele->fe_num) &
									NSE_AQC_PROFILE_FENUM_M);
			dev_info(nse_hw_to_dev(hw), "\t\tlocal_rcp = 0x%x\n",
				 (le16_to_cpu(ele->fe_num) >>
				 NSE_AQC_PROFILE_LOCAL_RCP_S) &
				 NSE_AQC_PROFILE_LOCAL_RCP_M);

			for (j = 0; j < NSE_AQ_MAX_FV_WORDS; j++) {
				u32 fec_val = le32_to_cpu(ele->fvw[j].fec);
				u8 prot_id, enable;
				u16 offset;

				prot_id = (u8)((fec_val >> NSE_AQ_PROFILE_FEC_PROT_ID_S) &
						NSE_AQ_PROFILE_FEC_PROT_ID_M);

				offset = (u16)((fec_val >> NSE_AQ_PROFILE_FEC_OFF_S) &
						NSE_AQ_PROFILE_FEC_OFF_M);

				enable = (u8)((fec_val >> NSE_AQ_PROFILE_FEC_EN_S) &
						NSE_AQ_PROFILE_FEC_EN_M);

				if (prot_id != 255)
					dev_info(nse_hw_to_dev(hw),
						"\t\tField Vector [%d]: En = %d, Prot id = %d, Offset = %d\n",
						j, enable, prot_id, offset);
				else
					dev_info(nse_hw_to_dev(hw),
						"\t\tField Vector [%d]: En = %d, Prot id = %d, MDID = %d\n",
						j, enable, prot_id, offset);
			}
		}

		loop_cnt++;
		if (loop_cnt > max_loop) {
			dev_err(nse_hw_to_dev(hw), "profile total num exceeds the max value\n");
			goto out;
		}
	} while (start_id && !status);

out:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

/**
 * nse_dump_sw_aq_recipe - get and print one recipe as seen by firmware
 * @hw: nse hardware struct
 * @rcp_id: recipe id wanted to be get
 */
void nse_dump_sw_aq_recipe(struct nse_hw *hw, u8 rcp_id)
{
	struct nse_aqc_recipe_cfg *buf;
	struct nse_aqc_recipe_data_elem *rcp_elems;
	enum nse_status status;
	bool en;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw),
			      buf_size, GFP_KERNEL);
	if (!buf)
		return;

	buf->count = cpu_to_le16(1);
	rcp_elems = buf->elem;
	rcp_elems->profile_id = cpu_to_le16(0);
	rcp_elems->recipe_id = rcp_id;
	status = nse_aq_recipes(hw, buf, buf_size,
				 NSE_AQ_OPC_GET_RECIPE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "nse_aq_recipes err: %d\n", status);
	} else {
		dev_info(nse_hw_to_dev(hw),
			"Profile ID = 0x%x, Relative Recipe ID = 0x%x, LUT ID = 0x%x\n",
			le16_to_cpu(rcp_elems->profile_id), rcp_elems->recipe_id,
			le16_to_cpu(rcp_elems->content.lut_id));
		dev_info(nse_hw_to_dev(hw),
			"Masks[0~4]: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
			le16_to_cpu(rcp_elems->content.mask[0]),
			le16_to_cpu(rcp_elems->content.mask[1]),
			le16_to_cpu(rcp_elems->content.mask[2]),
			le16_to_cpu(rcp_elems->content.mask[3]),
			le16_to_cpu(rcp_elems->content.mask[4]));
		dev_info(nse_hw_to_dev(hw),
			"Lkup_idx[0~4]: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
			rcp_elems->content.lkup_indx[0],
			rcp_elems->content.lkup_indx[1],
			rcp_elems->content.lkup_indx[2],
			rcp_elems->content.lkup_indx[3],
			rcp_elems->content.lkup_indx[4]);
		en = !!(rcp_elems->content.ctrl_flg & NSE_AQ_RECIPE_DFLT_ACT_EN);
		dev_info(nse_hw_to_dev(hw),
			"dflt act en = %d, dflt_action = 0x%x\n",
			en,	le16_to_cpu(rcp_elems->content.dflt_action));
		en = !!(rcp_elems->content.ctrl_flg & NSE_AQ_RECIPE_RESULT_EN);
		dev_info(nse_hw_to_dev(hw),
			"rslt index en = %d, result index = 0x%x\n",
			en, rcp_elems->content.result_indx >> NSE_AQ_RECIPE_RSLT_INDX_S);
		en = !!(rcp_elems->content.ignore_vld & NSE_AQ_RECIPE_RESULT_SEL);
		dev_info(nse_hw_to_dev(hw),
			"result sel = %d, priority = 0x%x\n",
			en, rcp_elems->content.priority);
		en = !!(rcp_elems->content.ctrl_flg & NSE_AQ_RECIPE_IS_ROOT);
		dev_info(nse_hw_to_dev(hw),
			"is_root = %d, ignore valid = 0x%x\n",
			en,	rcp_elems->content.ignore_vld & NSE_AQ_RECIPE_IGNORE_VLD_M);
		dev_info(nse_hw_to_dev(hw),
			"inverse en = %d, inverse index = %d\n",
			!!(rcp_elems->content.ignore_vld & NSE_AQ_RECIPE_INVERSE_EN),
			!!(rcp_elems->content.ignore_vld & NSE_AQ_RECIPE_INVERSE_INDX));
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
}

/**
 * nse_dump_sw_aq_lut_node - get and print one lut node as seen by firmware
 * @hw: nse hardware struct
 * @node_id: lut node id wanted to be get
 */
void nse_dump_sw_aq_lut_node(struct nse_hw *hw, u16 node_id)
{
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	enum nse_status status;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw),
			      buf_size, GFP_KERNEL);
	if (!buf)
		return;

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;
	lut_node->node_id = cpu_to_le16(node_id);
	status = nse_aq_lut_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_GET_LUT_NODE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "nse_aq_lut_nodes err: %d\n", status);
	} else {
		dev_info(nse_hw_to_dev(hw),
			"lut[%d]_node[%d] Keys[0~4]: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
			le16_to_cpu(lut_node->lut_id), node_id, le16_to_cpu(lut_node->key[0]),
			le16_to_cpu(lut_node->key[1]), le16_to_cpu(lut_node->key[2]),
			le16_to_cpu(lut_node->key[3]), le16_to_cpu(lut_node->key[4]));
		dev_info(nse_hw_to_dev(hw),
			"lut[%d]_node[%d] Action is 0x%x, \tleft_ptr is 0x%x, \tright_ptr is 0x%x\n",
			le16_to_cpu(lut_node->lut_id), node_id, le16_to_cpu(lut_node->action),
			le16_to_cpu(lut_node->left_ptr), le16_to_cpu(lut_node->right_ptr));
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
}

/**
 * nse_dump_sw_aq_cfg - get and print switch config as seen by firmware
 * @hw: nse hardware struct
 */
void
nse_dump_sw_aq_cfg(struct nse_hw *hw)
{
	struct nse_aqc_get_sw_cfg *buf;
	struct nse_aqc_get_sw_cfg_resp_elem *ele;
	enum nse_status status;
	u32 num_elems;
	u16 i;

	buf = devm_kzalloc(nse_hw_to_dev(hw), NSE_AQ_MAX_BUF_LEN,
				GFP_KERNEL);
	if (!buf)
		return;

	/* set count&start_id to 0, means read all from element 0*/
	buf->count = cpu_to_le16(0);
	buf->start_id = cpu_to_le16(0);
	status = nse_aq_get_sw_cfg(hw, buf, NSE_AQ_MAX_BUF_LEN);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "nse_aq_get_sw_cfg err\n");
		goto out;
	}

	num_elems = le16_to_cpu(buf->count);
	dev_info(nse_hw_to_dev(hw), "sw_cfg's num_elems is 0x%x\n", num_elems);

	ele = buf->elems;
	for (i = 0; i < num_elems; i++, ele++) {
		u16 pf_vf_num, swid, vsi_port_num;
		bool is_vf = false;
		u8 res_type;

		vsi_port_num = (le16_to_cpu(ele->vsi_port_num) >>
			NSE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_S) &
			NSE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_M;

		pf_vf_num = (le16_to_cpu(ele->pf_vf_num) >>
			NSE_AQC_GET_SW_CONF_RESP_FUNC_NUM_S) &
			NSE_AQC_GET_SW_CONF_RESP_FUNC_NUM_M;

		swid = le16_to_cpu(ele->swid);

		if (le16_to_cpu(ele->pf_vf_num) &
			NSE_AQC_GET_SW_CONF_RESP_IS_VF)
			is_vf = true;

		res_type = (u8)((le16_to_cpu(ele->vsi_port_num) >>
			NSE_AQC_GET_SW_CONF_RESP_TYPE_S) &
			NSE_AQC_GET_SW_CONF_RESP_TYPE_M);

		dev_info(nse_hw_to_dev(hw), "element[%d]\n", i);
		dev_info(nse_hw_to_dev(hw), "\tres_type = 0x%x\n", res_type);
		dev_info(nse_hw_to_dev(hw), "\tswitch id = 0x%x\n", swid);
		if (is_vf) {
			dev_info(nse_hw_to_dev(hw), "\tpf num  = 0x%x\n", pf_vf_num);
			dev_info(nse_hw_to_dev(hw), "\tphysical port = 0x%x\n", vsi_port_num);
		} else {
			dev_info(nse_hw_to_dev(hw), "\tvf num  = 0x%x\n", pf_vf_num);
			dev_info(nse_hw_to_dev(hw), "\tvsi port = 0x%x\n", vsi_port_num);
		}
	}

out:
	devm_kfree(nse_hw_to_dev(hw), buf);
}

/**
 * nse_dump_lkup_filters
 * @hw: pointer to the hardware structure
 * @rule_lock: pointer to lock that's protecting filter list
 * @rule_head: pointer to head of filter list
 * @lkup: type of switch lookup rule
 *
 * Helper function that prints all filters for a particular switch
 * lookup type
 */
static void nse_dump_lkup_filters(struct nse_hw *hw, struct mutex *rule_lock,
				  struct list_head *rule_head,
				  enum nse_sw_lkup_type lkup)
{
	struct nse_fltr_mgmt_list_entry *fm_entry;
	char extra_param[128] = {'\0'};
	char mac_addr[ETH_ALEN];

	memset(mac_addr, 0, ETH_ALEN);
	mutex_lock(rule_lock);
	list_for_each_entry(fm_entry, rule_head, list_entry) {
		struct nse_fltr_info *fi = &fm_entry->fltr_info;

		if (lkup == NSE_SW_LKUP_MAC ||
			lkup == NSE_SW_LKUP_PROMISC ||
			lkup == NSE_SW_LKUP_BMC_MAC) {
			ether_addr_copy(mac_addr, fi->l_data.mac.mac_addr);
		} else if (lkup == NSE_SW_LKUP_MAC_VLAN) {
			ether_addr_copy(mac_addr,
					fi->l_data.mac_vlan.mac_addr);
			snprintf(extra_param, sizeof(extra_param),
				 "vlan_id = %d", fi->l_data.mac_vlan.vlan_id);
		} else if (lkup == NSE_SW_LKUP_ETHERTYPE_MAC) {
			ether_addr_copy(mac_addr,
					fi->l_data.ethertype_mac.mac_addr);
			snprintf(extra_param, sizeof(extra_param),
				 "ethertype = %d",
				 fi->l_data.ethertype_mac.ethertype);
		}

		dev_info(nse_hw_to_dev(hw),
			 "\tmac: %pM, vsi_count = %d, vsi_id/vsi_list_id = %d, lb_en = %d, lan_en = %d, filt_act = %d, node_id = %d %s\n",
			 mac_addr, fm_entry->vsi_count, fi->fwd_id.hw_vsi_id, fi->lb_en,
			 fi->lan_en, fi->fltr_act, fi->fltr_node_id,
			 extra_param);
	}
	mutex_unlock(rule_lock);
}

/**
 * nse_dump_all_sw_rules
 * @hw: pointer to the hardware structure
 * @lkup: switch rule filter lookup type
 * @lut: pointer to luts
 *
 * Helper function to print filter information of all entries in the list for a
 * given lookup type
 */
static void
nse_dump_all_sw_rules(struct nse_hw *hw, enum nse_sw_lkup_type lkup,
		      struct nse_lut_info *lut)
{
	struct nse_fltr_mgmt_list_entry *fm_entry;
	struct list_head *rule_head;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	struct nse_fltr_info *fi;

	rule_lock = &lut->filt_rule_lock;
	rule_head = &lut->filt_rules;

	switch (lkup) {
	case NSE_SW_LKUP_MAC:
		/* dump MAC hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump MAC hash list of Lut[%d]\n", lkup);
		nse_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case NSE_SW_LKUP_VLAN:
		/* dump VLAN hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump VLAN hash list of Lut[%d]\n", lkup);
		mutex_lock(rule_lock);
		list_for_each_entry(fm_entry, rule_head, list_entry) {
			fi = &fm_entry->fltr_info;
			dev_info(nse_hw_to_dev(hw),
				 "\tvlan_id = %d, vlan_tpid = 0x%04x, vsi_count = %d, vsi_id/vsi_list_id = %d, filt_act = %d, lb_en = %d, lan_en = %d, node_id = %d\n",
				 fi->l_data.vlan.vlan_id,
				 fi->l_data.vlan.tpid_valid ? fi->l_data.vlan.tpid : ETH_P_8021Q,
				 fm_entry->vsi_count, fi->fwd_id.hw_vsi_id, fi->fltr_act,
				 fi->lb_en, fi->lan_en, fi->fltr_node_id);
		}
		mutex_unlock(rule_lock);
		break;
	case NSE_SW_LKUP_MAC_VLAN:
		/* dump MAC VLAN hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump MAC VLAN hash list of Lut[%d]\n",
			 lkup);
		nse_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case NSE_SW_LKUP_ETHERTYPE:
		/* dump Ethertype/Ethertype MAC hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump Ethertype hash list of Lut[%d]\n",
			 lkup);
		mutex_lock(rule_lock);
		list_for_each_entry(fm_entry, rule_head, list_entry) {
			fi = &fm_entry->fltr_info;
			dev_info(nse_hw_to_dev(hw),
				 "\tethertype = %d, vsi_count = %d, vsi_id/vsi_list_id = %d, filt_act = %d, lb_en = %d, lan_en = %d, node_id = %d\n",
				 fi->l_data.ethertype_mac.ethertype,
				 fm_entry->vsi_count, fi->fwd_id.hw_vsi_id, fi->fltr_act,
				 fi->lb_en, fi->lan_en, fi->fltr_node_id);
		}
		mutex_unlock(rule_lock);
		break;
	case NSE_SW_LKUP_ETHERTYPE_MAC:
		/* dump Ethertype/Ethertype MAC hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump Ethertype MAC hash list of Lut[%d]\n",
			 lkup);
		nse_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case NSE_SW_LKUP_PROMISC:
		/* dump Promisc mode hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump Promisc hash list of Lut[%d]\n", lkup);
		mutex_lock(rule_lock);
		list_for_each_entry(fm_entry, rule_head, list_entry) {
			fi = &fm_entry->fltr_info;
			dev_info(nse_hw_to_dev(hw),
				 "\tmactype = %d, vsi_count = %d, vsi_id/vsi_list_id = %d, filt_act = %d, lb_en = %d, lan_en = %d, node_id = %d\n",
				 fi->l_data.promisc.mactype,
				 fm_entry->vsi_count, fi->fwd_id.hw_vsi_id, fi->fltr_act,
				 fi->lb_en, fi->lan_en, fi->fltr_node_id);
		}
		mutex_unlock(rule_lock);
		break;

	case NSE_SW_LKUP_PROMISC_VLAN:
		/* dump Promisc mode hash list */
		dev_info(nse_hw_to_dev(hw),
			 "\tDump Promisc VLAN hash list of Lut[%d]\n",
			 lkup);
		mutex_lock(rule_lock);
		list_for_each_entry(fm_entry, rule_head, list_entry) {
			fi = &fm_entry->fltr_info;
			dev_info(nse_hw_to_dev(hw),
				 "\tmactype = %d, vlan_id = %d, vsi_count = %d, vsi_id/vsi_list_id = %d, filt_act = %d, lb_en = %d, lan_en = %d, node_id = %d\n",
				 fi->l_data.promisc.mactype, fi->l_data.promisc.vlan_id,
				 fm_entry->vsi_count, fi->fwd_id.hw_vsi_id, fi->fltr_act,
				 fi->lb_en, fi->lan_en, fi->fltr_node_id);
		}
		mutex_unlock(rule_lock);
		break;
	case NSE_SW_LKUP_BMC_MAC:
		dev_info(nse_hw_to_dev(hw),
			 "\tDump Default VSI's VLAN mode hash list of Lut[%d]\n",
			 lkup);
		nse_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case NSE_SW_LKUP_ROCE_MAC:
	case NSE_SW_LKUP_LAST:
		dev_info(nse_hw_to_dev(hw),
			 "\tDump for this lookup type hasn't been implemented yet\n");
		break;
	}
}

/**
 * nse_dump_sw_fltr_rules - Function to dump sw db rules
 * @hw: pointer to the hardware structure
 * @lkup: rules type to be dumped
 */
void nse_dump_sw_fltr_rules(struct nse_hw *hw, enum nse_sw_lkup_type lkup)
{
	nse_dump_all_sw_rules(hw, lkup, &hw->switch_info->lut_list[lkup]);
}

/* nse_get_initial_sw_cfg - Get initial port and default VSI data
 *                                     - Get switch id of initial physical port only now
 * @hw: pointer to the hardware structure
 */
static enum nse_status nse_get_initial_sw_cfg_flex(struct nse_hw *hw)
{
	struct nse_aqc_get_sw_cfg *buf;
	struct nse_aqc_get_sw_cfg_resp_elem *ele;
	enum nse_status status;
	u32 num_elems, max_num_elems;
	u16 i;
	u8 num_total_ports = 1;
	u8 j = 0;

	if (nse_bypass_switch) {
		nse_debug(hw, NSE_DBG_SW, "[%s, %d] kmod param: bypass_switch = true\n",
			  __func__, __LINE__);
		return NSE_SUCCESS;
	}

	buf = devm_kzalloc(nse_hw_to_dev(hw), NSE_AQ_MAX_BUF_LEN,
				GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	/* set count&start_id to 0, means read all from element 0*/
	buf->count = cpu_to_le16(0);
	buf->start_id = cpu_to_le16(0);
	status = nse_aq_get_sw_cfg(hw, buf, NSE_AQ_MAX_BUF_LEN);
	if (status)
		goto out;

	num_elems = le16_to_cpu(buf->count);
	max_num_elems = (NSE_AQ_MAX_BUF_LEN - sizeof(buf->count)) /
					sizeof(struct nse_aqc_get_sw_cfg_resp_elem);

	if (num_elems > max_num_elems) {
		dev_err(nse_hw_to_dev(hw),
			"invalid switch cfg elements, num_elems is 0x%x\n", num_elems);
		status = NSE_ERR_INVAL_SIZE;
		goto out;
	}

	ele = buf->elems;
	for (i = 0; i < num_elems; i++, ele++) {
		u16 pf_vf_num, swid, vsi_port_num;
		bool is_vf = false;
		u8 res_type;

		vsi_port_num = (le16_to_cpu(ele->vsi_port_num) >>
			NSE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_S) &
			NSE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_M;

		pf_vf_num = (le16_to_cpu(ele->pf_vf_num) >>
			NSE_AQC_GET_SW_CONF_RESP_FUNC_NUM_S) &
			NSE_AQC_GET_SW_CONF_RESP_FUNC_NUM_M;

		swid = le16_to_cpu(ele->swid);

		if (le16_to_cpu(ele->pf_vf_num) &
			NSE_AQC_GET_SW_CONF_RESP_IS_VF)
			is_vf = true;

		res_type = (u8)((le16_to_cpu(ele->vsi_port_num) >>
			NSE_AQC_GET_SW_CONF_RESP_TYPE_S) &
			NSE_AQC_GET_SW_CONF_RESP_TYPE_M);

		switch (res_type) {
		case NSE_AQC_GET_SW_CONF_RESP_PHYS_PORT:
		case NSE_AQC_GET_SW_CONF_RESP_VIRT_PORT:
			if (j == num_total_ports) {
				dev_err(nse_hw_to_dev(hw), "more ports than expected\n");
				status = NSE_ERR_INVAL_SIZE;
				goto out;
			}
			nse_init_port_info(hw->port_info,
					vsi_port_num, res_type, swid,
					pf_vf_num, is_vf);
			j++;
			break;
		default:
			break;
		}
	}

out:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

static enum nse_status nse_get_initial_sw_cfg_legacy(struct nse_hw *hw)
{
	return NSE_SUCCESS;
}

enum nse_status nse_get_initial_sw_cfg(struct nse_hw *hw)
{
	enum nse_status status = NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_get_initial_sw_cfg_flex(hw);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_get_initial_sw_cfg_legacy(hw);

	return status;
}

/**
 * nse_fill_sw_info - Helper function to populate lb_en and lan_en
 * @hw: pointer to the hardware structure
 * @fi: filter info structure to fill/update
 *
 * This helper function populates the lb_en and lan_en elements of the provided
 * nse_fltr_info struct using the switch's type and characteristics of the
 * switch rule being configured.
 */
static void nse_fill_sw_info(struct nse_hw *hw, struct nse_fltr_info *fi)
{
	fi->lb_en = false;
	fi->lan_en = false;
	if (fi->fltr_act == NSE_FWD_TO_VSI ||
	     fi->fltr_act == NSE_FWD_TO_VSI_LIST ||
	     fi->fltr_act == NSE_FWD_BMC) {
		/* Setting LB for prune actions will result in replicated
		 * packets to the internal switch that will be dropped.
		 */
		if (fi->lkup_type != NSE_SW_LKUP_VLAN)
			fi->lb_en = true;

		if (hw->evb_veb) {
			if (fi->lkup_type == NSE_SW_LKUP_ETHERTYPE ||
			    fi->lkup_type == NSE_SW_LKUP_PROMISC ||
			    fi->lkup_type == NSE_SW_LKUP_ETHERTYPE_MAC ||
			    fi->lkup_type == NSE_SW_LKUP_PROMISC_VLAN ||
			    fi->lkup_type == NSE_SW_LKUP_VLAN ||
			    (fi->lkup_type == NSE_SW_LKUP_BMC_MAC &&
			     !is_unicast_ether_addr(fi->l_data.mac.mac_addr)) ||
			    (fi->lkup_type == NSE_SW_LKUP_MAC &&
			     !is_unicast_ether_addr(fi->l_data.mac.mac_addr)) ||
			    (fi->lkup_type == NSE_SW_LKUP_MAC_VLAN &&
			     !is_unicast_ether_addr(fi->l_data.mac.mac_addr)))
				fi->lan_en = true;
		} else {
			fi->lan_en = true;
		}
	}
}

/**
 * nse_fill_lut_node - Helper function to fill one lut node structure
 * @hw: pointer to the hardware structure
 * @f_info: entry containing packet forwarding information
 * @lut_node: lut node structure to be filled in based on f_info
 * @opc: lut nodes population command type - pass in the command opcode
 */
static void
nse_fill_lut_node(struct nse_hw *hw, struct nse_fltr_info *f_info,
		 struct nse_aqc_lut_node_elem *lut_node,
		 enum nse_adminq_opc_category_switch_subcodes opc)
{
	u16 act = NSE_SINGLE_FWD_LAN_DISABLE;

	if (opc == NSE_AQ_OPC_REMOVE_LUT_NODE || opc == NSE_AQ_OPC_GET_LUT_NODE) {
		lut_node->action = 0;
		lut_node->lut_id = cpu_to_le16(f_info->lkup_type);
		lut_node->node_id = cpu_to_le16(f_info->fltr_node_id);
		return;
	}

	nse_fill_sw_info(hw, f_info);

	switch (f_info->fltr_act) {
	case NSE_FWD_TO_VSI:
		act |= (f_info->fwd_id.hw_vsi_id << NSE_SINGLE_FWD_VSI_ID_S) &
			NSE_SINGLE_FWD_VSI_ID_M;

		if (f_info->lkup_type != NSE_SW_LKUP_VLAN) {
			/* set action type to fwd */
			act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
				NSE_SINGLE_ACT_TYPE_FWD_M;

			if (f_info->lb_en)
				act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
						NSE_SINGLE_FWD_TYPE_M;
			else
				act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
						NSE_SINGLE_FWD_TYPE_M;

		} else {
			/* set action type to prune */
			act |= (NSE_SINGLE_ACT_TYPE_PRUNE << NSE_SINGLE_ACT_TYPE_PRUNE_S) &
				NSE_SINGLE_ACT_TYPE_PRUNE_M;
		}

		if (f_info->lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;

		break;
	case NSE_FWD_TO_VSI_LIST:
		act |= (f_info->fwd_id.vsi_list_id << NSE_SINGLE_FWD_VSI_LIST_ID_S) &
			NSE_SINGLE_FWD_VSI_LIST_ID_M;

		if (f_info->lkup_type != NSE_SW_LKUP_VLAN) {
			/* set action type to fwd */
			act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
				NSE_SINGLE_ACT_TYPE_FWD_M;

			if (f_info->lb_en)
				act |= (NSE_SINGLE_FWD_VSI_LIST_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
						NSE_SINGLE_FWD_TYPE_M;
			else
				act |= (NSE_SINGLE_FWD_VSI_LIST_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
						NSE_SINGLE_FWD_TYPE_M;
		} else {
			/* set action type to prune */
			act |= (NSE_SINGLE_ACT_TYPE_PRUNE << NSE_SINGLE_ACT_TYPE_PRUNE_S) &
				NSE_SINGLE_ACT_TYPE_PRUNE_M;

			act |= NSE_SINGLE_PRUNE_VSI_LIST;
		}

		if (f_info->lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;

		break;

	case NSE_DROP_PACKET:
		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		/* set fwd type to Drop */
		act |= (NSE_SINGLE_FWD_DROP << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;
		break;

	case NSE_FWD_BMC:
		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		/* set fwd type to FWD BMC */
		act |= (NSE_SINGLE_FWD_BMC << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

		if (f_info->lan_en)
			act &= ~NSE_SINGLE_FWD_LAN_DISABLE;

		break;

	default:
		return;
	}

	switch (f_info->lkup_type) {
	case NSE_SW_LKUP_ROCE_MAC:
		lut_node->key[4] = cpu_to_le16(NSE_LUT_KEY_ROCE_FLAG_VLD_BIT);
		fallthrough;
	case NSE_SW_LKUP_MAC:
	case NSE_SW_LKUP_BMC_MAC:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[0] << 8 |
								f_info->l_data.mac.mac_addr[1]));
		lut_node->key[2] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[2] << 8 |
								f_info->l_data.mac.mac_addr[3]));
		lut_node->key[3] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[4] << 8 |
								f_info->l_data.mac.mac_addr[5]));
		break;
	case NSE_SW_LKUP_VLAN:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16(f_info->l_data.vlan.vlan_id);
		break;
	case NSE_SW_LKUP_ETHERTYPE:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16(f_info->l_data.ethertype_mac.ethertype);
		lut_node->key[2] = cpu_to_le16(f_info->dir);
		break;
	case NSE_SW_LKUP_ETHERTYPE_MAC:
		lut_node->key[0] = cpu_to_le16(f_info->dir);
		lut_node->key[1] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[0] << 8 |
								f_info->l_data.mac.mac_addr[1]));
		lut_node->key[2] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[2] << 8 |
								f_info->l_data.mac.mac_addr[3]));
		lut_node->key[3] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[4] << 8 |
								f_info->l_data.mac.mac_addr[5]));
		lut_node->key[4] = cpu_to_le16(f_info->l_data.ethertype_mac.ethertype);
		break;
	case NSE_SW_LKUP_MAC_VLAN:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[0] << 8 |
								f_info->l_data.mac.mac_addr[1]));
		lut_node->key[2] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[2] << 8 |
								f_info->l_data.mac.mac_addr[3]));
		lut_node->key[3] = cpu_to_le16((u16)(f_info->l_data.mac.mac_addr[4] << 8 |
								f_info->l_data.mac.mac_addr[5]));
		lut_node->key[4] = cpu_to_le16(f_info->l_data.mac_vlan.vlan_id);
		break;
	case NSE_SW_LKUP_PROMISC_VLAN:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16(f_info->l_data.promisc.mactype);
		lut_node->key[2] = cpu_to_le16(f_info->l_data.promisc.vlan_id);
		lut_node->key[3] = cpu_to_le16(f_info->dir);
		break;
	case NSE_SW_LKUP_PROMISC:
		lut_node->key[0] = cpu_to_le16(f_info->sw_id);
		lut_node->key[1] = cpu_to_le16(f_info->l_data.promisc.mactype);
		lut_node->key[2] = cpu_to_le16(f_info->dir);
		break;
	/* NSE_SW_LKUP_LAST is  used by advanced rule, keys are filled not here*/
	case NSE_SW_LKUP_LAST:
	default:
		break;
	}

	lut_node->lut_id = cpu_to_le16(f_info->lkup_type);
	lut_node->action = cpu_to_le16(act);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->lut_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] original node_id is 0x%x\n",
		 __func__, __LINE__, cpu_to_le16(lut_node->node_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key0 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[0]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key1 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[1]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key2 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[2]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key3 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[3]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] key4 is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->key[4]));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] action is 0x%x\n",
		 __func__, __LINE__, le16_to_cpu(lut_node->action));
}

/**
 * nse_create_vsi_list_map
 * @hw: pointer to the hardware structure
 * @vsi_handle_arr: array of VSI handles to set in the VSI mapping
 * @num_vsi: number of VSI handles in the array
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 *
 * Helper function to create a new entry of VSI list ID to VSI mapping
 * using the given VSI list ID
 */
static struct nse_vsi_list_map_info *
nse_create_vsi_list_map(struct nse_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			u16 vsi_list_id, enum nse_vsi_list_type vlist_type)
{
	struct nse_vsi_list_map_info *v_map;
	int i;

	v_map = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*v_map), GFP_KERNEL);
	if (!v_map)
		return NULL;

	v_map->vsi_list_id = vsi_list_id;
	refcount_set(&v_map->ref_cnt, 1);
	v_map->type = vlist_type;
	v_map->vsi_cnt = num_vsi;
	for (i = 0; i < num_vsi; i++)
		set_bit(vsi_handle_arr[i], v_map->vsi_map);

	return v_map;
}

/**
 * nse_operate_vsi_list_rule, add/update vsi list content
 * @hw: pointer to the hardware structure
 * @vsi_handle_arr: array of VSI handles to form a VSI list
 * @num_vsi: number of VSI handles in the array
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 * @clear: Boolean value to indicate if this is a clear action
 * @opc: switch rules population command type - pass in the command opcode
 * @lkup_type: lookup type of the filter
 *
 *			used by NSE_AQ_OPC_ADD_VSI_LIST and NSE_AQ_OPC_UPDATE_VSI_LIST
 */
static enum nse_status
nse_operate_vsi_list_rule(struct nse_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			 u16 vsi_list_id, bool clear,
			 enum nse_adminq_opc_category_switch_subcodes opc,
			 enum nse_sw_lkup_type lkup_type)
{
	struct nse_aqc_vsi_lists_elem *buf;
	u16 buf_size;
	u16 opc_type;
	enum nse_status status;
	int i;

	if (!num_vsi)
		return NSE_ERR_PARAM;

	if (lkup_type == NSE_SW_LKUP_MAC ||
	    lkup_type == NSE_SW_LKUP_MAC_VLAN ||
	    lkup_type == NSE_SW_LKUP_ETHERTYPE ||
	    lkup_type == NSE_SW_LKUP_ETHERTYPE_MAC ||
	    lkup_type == NSE_SW_LKUP_VLAN ||
		lkup_type == NSE_SW_LKUP_PROMISC ||
		lkup_type == NSE_SW_LKUP_PROMISC_VLAN ||
	    lkup_type == NSE_SW_LKUP_LAST)
		opc_type = clear ? NSE_AQC_SW_RULES_T_VSI_LIST_CLEAR :
			NSE_AQC_SW_RULES_T_VSI_LIST_SET;

	buf_size = struct_size(buf, vsi, num_vsi);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	for (i = 0; i < num_vsi; i++) {
		if (!nse_is_vsi_valid(hw, vsi_handle_arr[i])) {
			status = NSE_ERR_PARAM;
			goto exit;
		}
		buf->vsi[i] =
			cpu_to_le16(nse_get_hw_vsi_num(hw, vsi_handle_arr[i]));
	}
	buf->op_type = opc_type;
	buf->num_vsi = cpu_to_le16(num_vsi);
	buf->vsi_list_id = cpu_to_le16(vsi_list_id);

	status = nse_aq_vsi_list_rules(hw, buf, buf_size, opc, NULL);

exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_get_remove_vsi_list, get/remove vsi list content
 * @hw: pointer to the hardware structure
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 * @opc: switch rules population command type - pass in the command opcode
 * @vsi_bm_arr: vsi bitmap array, u32 unit.
 * @num_arr: element number of vsi bitmap array
 *
 *	used by NSE_AQ_OPC_GET_VSI_LIST and NSE_AQ_OPC_REMOVE_VSI_LIST
 */
enum nse_status
nse_get_remove_vsi_list(struct nse_hw *hw, u16 vsi_list_id,
			 enum nse_adminq_opc_category_switch_subcodes opc,
			 u32 *vsi_bm_arr, int num_arr)
{
	struct nse_aqc_get_remove_vsi_lists_elem *buf;
	enum nse_status status;
	int i;

	if (num_arr > NSE_AQC_MAX_VSI_BM_BYTE_SIZE)
		return NSE_ERR_MAX_LIMIT;

	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->vsi_list_id = cpu_to_le16(vsi_list_id);
	status = nse_aq_get_remove_vsi_list(hw, buf, sizeof(*buf), opc, NULL);
	if (!status && opc == NSE_AQ_OPC_GET_VSI_LIST) {
		for (i = 0; i < num_arr; i++)
			vsi_bm_arr[i] = le32_to_cpu(buf->vsi_bm[i]);
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_create_vsi_list_rule - Creates and populates a VSI list rule
 * @hw: pointer to the HW struct
 * @vsi_handle_arr: array of VSI handles to form a VSI list
 * @num_vsi: number of VSI handles in the array
 * @vsi_list_id: stores the ID of the VSI list to be created
 * @lkup_type: switch rule filter's lookup type
 */
enum nse_status
nse_create_vsi_list_rule(struct nse_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			 u16 *vsi_list_id, enum nse_sw_lkup_type lkup_type)
{
	enum nse_status status;

	/*first, alloc a vsi list id*/
	status = nse_aq_alloc_free_vsi_list(hw, vsi_list_id, lkup_type,
					    NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status)
		return status;

	/*second, add the vsi list content*/
	return nse_operate_vsi_list_rule(hw, vsi_handle_arr, num_vsi,
					*vsi_list_id, false,
					NSE_AQ_OPC_ADD_VSI_LIST, lkup_type);
}

/**
 * nse_update_pkt_fwd_rule
 * @hw: pointer to the hardware structure
 * @f_info: filter information for switch rule
 *
 * Call AQ command to update a previously created lut node with a
 * VSI list ID
 */
static enum nse_status
nse_update_pkt_fwd_rule(struct nse_hw *hw, struct nse_fltr_info *f_info)
{
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	enum nse_status status;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw),
			      buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;

	nse_fill_lut_node(hw, f_info, lut_node, NSE_AQ_OPC_ADD_LUT_NODE);

	lut_node->node_id = cpu_to_le16(f_info->fltr_node_id);

	dev_info(nse_hw_to_dev(hw), "[%s, %d] start to update node\n", __func__, __LINE__);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
		 __func__, __LINE__, cpu_to_le16(lut_node->lut_id));
	dev_info(nse_hw_to_dev(hw), "[%s, %d] node_id is 0x%x\n",
		 __func__, __LINE__, cpu_to_le16(lut_node->node_id));

	/* Update lut node with new rule to forward VSI list */
	status = nse_aq_lut_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_UPDATE_LUT_NODE, NULL);

	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_create_pkt_fwd_rule
 * @hw: pointer to the hardware structure
 * @lut: corresponding filter management lut
 * @f_entry: entry containing packet forwarding information
 *
 * Create lut node with given filter information and add an entry
 * to the corresponding filter management list to track this lut node
 * and VSI mapping
 */
static enum nse_status
nse_create_pkt_fwd_rule(struct nse_hw *hw, struct nse_lut_info *lut,
			struct nse_fltr_list_entry *f_entry)
{
	struct nse_fltr_mgmt_list_entry *fm_entry;
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	enum nse_status status;
	u16 buf_size = struct_size(buf, elem, 1);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;

	fm_entry = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*fm_entry),
				GFP_KERNEL);
	if (!fm_entry) {
		status = NSE_ERR_NO_MEMORY;
		goto nse_create_pkt_fwd_rule_exit;
	}

	fm_entry->fltr_info = f_entry->fltr_info;
	fm_entry->vsi_count = 1;
	fm_entry->node_state_id = NSE_NODE_STATE_ID_INVALID;

	nse_fill_lut_node(hw, &fm_entry->fltr_info, lut_node,
			 NSE_AQ_OPC_ADD_LUT_NODE);

	status = nse_aq_lut_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_LUT_NODE, NULL);
	if (status) {
		devm_kfree(nse_hw_to_dev(hw), fm_entry);
		goto nse_create_pkt_fwd_rule_exit;
	}

	f_entry->fltr_info.fltr_node_id = le16_to_cpu(lut_node->node_id);
	fm_entry->fltr_info.fltr_node_id = le16_to_cpu(lut_node->node_id);
	/*add entry to software filter DB after populating to HW*/
	list_add_tail(&fm_entry->list_entry, &lut->filt_rules);
	dev_info(nse_hw_to_dev(hw), "[%s, %d] returned node_id is %d\n", __func__, __LINE__,
				f_entry->fltr_info.fltr_node_id);
nse_create_pkt_fwd_rule_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_add_update_vsi_list
 * @hw: pointer to the hardware structure
 * @m_entry: pointer to current filter management list entry
 * @cur_fltr: filter information from the book keeping entry
 * @new_fltr: filter information with the new VSI to be added
 *
 * Call AQ command to add or update previously created VSI list with new VSI.
 *
 * Helper function to do book keeping associated with adding filter information
 * The algorithm to do the book keeping is described below :
 * When a VSI needs to subscribe to a given filter (MAC/VLAN/Ethtype etc.)
 *	if only one VSI has been added till now
 *		Allocate a new VSI list and add two VSIs
 *		to this list using switch rule command
 *		Update the previously created switch rule with the
 *		newly created VSI list ID
 *	if a VSI list was previously created
 *		Add the new VSI to the previously created VSI list set
 *		using the update switch rule command
 */
static enum nse_status
nse_add_update_vsi_list(struct nse_hw *hw,
			struct nse_fltr_mgmt_list_entry *m_entry,
			struct nse_fltr_info *cur_fltr,
			struct nse_fltr_info *new_fltr)
{
	u16 vsi_list_id = 0;
	enum nse_status status = NSE_SUCCESS;
	struct nse_switch_info *sw = hw->switch_info;

	if ((cur_fltr->fltr_act == NSE_FWD_TO_Q ||
	     cur_fltr->fltr_act == NSE_FWD_TO_QGRP))
		return NSE_ERR_NOT_SUPPORTED;

	if ((new_fltr->fltr_act == NSE_FWD_TO_Q ||
	     new_fltr->fltr_act == NSE_FWD_TO_QGRP) &&
	    (cur_fltr->fltr_act == NSE_FWD_TO_VSI ||
	     cur_fltr->fltr_act == NSE_FWD_TO_VSI_LIST))
		return NSE_ERR_NOT_SUPPORTED;

	if (m_entry->vsi_count < 2 && !m_entry->vsi_list_info) {
		/*creat a vsi list when first time*/
		struct nse_fltr_info tmp_fltr;
		u16 vsi_handle_arr[2];

		if (cur_fltr->fwd_id.hw_vsi_id == new_fltr->fwd_id.hw_vsi_id)
			return NSE_ERR_ALREADY_EXISTS;

		vsi_handle_arr[0] = cur_fltr->vsi_handle;
		vsi_handle_arr[1] = new_fltr->vsi_handle;
		status = nse_create_vsi_list_rule(hw, &vsi_handle_arr[0], 2,
						  &vsi_list_id,
						  new_fltr->lkup_type);
		if (status)
			return status;

		tmp_fltr = *new_fltr;
		tmp_fltr.fltr_node_id = cur_fltr->fltr_node_id;
		tmp_fltr.fltr_act = NSE_FWD_TO_VSI_LIST;
		tmp_fltr.fwd_id.vsi_list_id = vsi_list_id;

		/* Update the existed lut node from "forward to VSI" to  "fwd to VSI list" */
		status = nse_update_pkt_fwd_rule(hw, &tmp_fltr);
		if (status)
			return status;

		/* Update software filter DB */
		cur_fltr->fwd_id.vsi_list_id = vsi_list_id;
		cur_fltr->fltr_act = NSE_FWD_TO_VSI_LIST;

		/* Create software vsi map DB entry*/
		m_entry->vsi_list_info =
			nse_create_vsi_list_map(hw, &vsi_handle_arr[0], 2,
						vsi_list_id, NSE_VSI_LIST_TYPE_LEGACY);

		if (!m_entry->vsi_list_info)
			return NSE_ERR_NO_MEMORY;

		mutex_lock(&sw->vsi_list_lock);
		list_add_tail(&m_entry->vsi_list_info->list_entry, &sw->vsi_list_map_head);
		mutex_unlock(&sw->vsi_list_lock);

	} else {
		/*vsi list is existed, add new vsi to it*/
		u16 vsi_handle = new_fltr->vsi_handle;

		if (!m_entry->vsi_list_info)
			return NSE_ERR_BAD_PTR;

		/* A rule already exists with the new VSI being added */
		if (test_bit(vsi_handle, m_entry->vsi_list_info->vsi_map))
			return NSE_SUCCESS;

		/* Update the exsited VSI list with new VSI */
		vsi_list_id = cur_fltr->fwd_id.vsi_list_id;
		status = nse_operate_vsi_list_rule(hw, &vsi_handle, 1,
						  vsi_list_id, false,
						  NSE_AQ_OPC_UPDATE_VSI_LIST,
						  new_fltr->lkup_type);

		/* Update software VSI list mapping DB */
		if (!status)
			set_bit(vsi_handle, m_entry->vsi_list_info->vsi_map);
	}
	if (!status)
		m_entry->vsi_count++;
	return status;
}

/**
 * nse_find_rule_entry - Search a rule entry
 * @list_head: head of rule list
 * @f_info: rule information
 *
 * Helper function to search for a given rule entry
 * Returns pointer to entry storing the rule if found
 */
static struct nse_fltr_mgmt_list_entry *
nse_find_rule_entry(struct list_head *list_head,
		    struct nse_fltr_info *f_info)
{
	struct nse_fltr_mgmt_list_entry *list_itr, *ret = NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (!memcmp(&f_info->l_data, &list_itr->fltr_info.l_data,
			    sizeof(f_info->l_data)) &&
		    f_info->dir == list_itr->fltr_info.dir &&
		    f_info->sw_id == list_itr->fltr_info.sw_id) {
			ret = list_itr;
			break;
		}
	}
	return ret;
}

/**
 * nse_add_rule_internal - add rule for a given lookup type
 * @hw: pointer to the hardware structure
 * @lut: lut table for which rule has to be added
 * @f_entry: structure containing MAC forwarding information
 *
 * Adds or updates the rule lists for a given recipe
 */
static enum nse_status
nse_add_rule_internal(struct nse_hw *hw, struct nse_lut_info *lut,
		      struct nse_fltr_list_entry *f_entry)
{
	struct nse_fltr_info *new_fltr, *cur_fltr;
	struct nse_fltr_mgmt_list_entry *m_entry;
	struct mutex *rule_lock;
	enum nse_status status = NSE_SUCCESS;

	if (!nse_is_vsi_valid(hw, f_entry->fltr_info.vsi_handle))
		return NSE_ERR_PARAM;

	if (f_entry->fltr_info.fltr_act == NSE_FWD_TO_VSI)
		f_entry->fltr_info.fwd_id.hw_vsi_id =
			nse_get_hw_vsi_num(hw, f_entry->fltr_info.vsi_handle);

	rule_lock = &lut->filt_rule_lock;

	mutex_lock(rule_lock);
	new_fltr = &f_entry->fltr_info;
	m_entry = nse_find_rule_entry(&lut->filt_rules, new_fltr);
	if (!m_entry) {
		status = nse_create_pkt_fwd_rule(hw, lut, f_entry);
		goto exit_add_rule_internal;
	}

	cur_fltr = &m_entry->fltr_info;
	status = nse_add_update_vsi_list(hw, m_entry, cur_fltr, new_fltr);

exit_add_rule_internal:
	mutex_unlock(rule_lock);
	return status;
}

/**
 * nse_release_vsi_list
 * @hw: pointer to the hardware structure
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 * @lkup_type: switch rule filter lookup type
 *
 */
enum nse_status
nse_release_vsi_list(struct nse_hw *hw, u16 vsi_list_id,
			 enum nse_sw_lkup_type lkup_type)
{
	/* Free the vsi_list resource that we allocated. It is assumed that the
	 * list is empty at this point.
	 */
	return nse_aq_alloc_free_vsi_list(hw, &vsi_list_id, lkup_type,
					    NSE_AQ_OPC_FREE_RESOURCE);
}

/**
 * nse_rem_update_vsi_list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle of the VSI to remove
 * @fm_entry: filter management entry for which the VSI list management needs to
 *	     be done
 */
static enum nse_status
nse_rem_update_vsi_list(struct nse_hw *hw, u16 vsi_handle,
			struct nse_fltr_mgmt_list_entry *fm_entry)
{
	enum nse_sw_lkup_type lkup_type;
	u16 vsi_list_id;
	enum nse_status status = NSE_SUCCESS;

	if (fm_entry->fltr_info.fltr_act != NSE_FWD_TO_VSI_LIST ||
	    fm_entry->vsi_count == 0)
		return NSE_ERR_PARAM;

	/* A rule with the VSI being removed does not exist */
	if (!test_bit(vsi_handle, fm_entry->vsi_list_info->vsi_map))
		return NSE_ERR_DOES_NOT_EXIST;

	lkup_type = fm_entry->fltr_info.lkup_type;
	vsi_list_id = fm_entry->fltr_info.fwd_id.vsi_list_id;

	/* clear the given vsi bitmap in vsi_list, */
	status = nse_operate_vsi_list_rule(hw, &vsi_handle, 1, vsi_list_id, true,
					  NSE_AQ_OPC_UPDATE_VSI_LIST, lkup_type);
	if (status)
		return status;

	/*Update sofware filter DB and sofware vsi map DB, after modify hw vsi list content*/
	fm_entry->vsi_count--;
	clear_bit(vsi_handle, fm_entry->vsi_list_info->vsi_map);

	if (fm_entry->vsi_count == 1) {
		/* only one vsi is left */
		struct nse_fltr_info tmp_fltr_info = fm_entry->fltr_info;
		struct nse_vsi_list_map_info *vsi_list_info =
			fm_entry->vsi_list_info;
		u16 rem_vsi_handle;

		rem_vsi_handle = find_first_bit(vsi_list_info->vsi_map,
						NSE_MAX_VSI);
		if (!nse_is_vsi_valid(hw, rem_vsi_handle))
			return NSE_ERR_CFG;

		/* 1. clear the last left vsi bitmap in the vsi list */
		status = nse_operate_vsi_list_rule(hw, &rem_vsi_handle, 1,
						  vsi_list_id, true,
						  NSE_AQ_OPC_UPDATE_VSI_LIST,
						  lkup_type);
		if (status)
			return status;

		/* 2. update lut node from to_vsi_list to to_vsi*/
		tmp_fltr_info.fltr_act = NSE_FWD_TO_VSI;
		tmp_fltr_info.fwd_id.hw_vsi_id =
			nse_get_hw_vsi_num(hw, rem_vsi_handle);
		tmp_fltr_info.vsi_handle = rem_vsi_handle;
		status = nse_update_pkt_fwd_rule(hw, &tmp_fltr_info);
		if (status) {
			nse_debug(hw, NSE_DBG_SW, "Failed to update pkt fwd rule to FWD_TO_VSI on HW VSI %d, error %d\n",
				  tmp_fltr_info.fwd_id.hw_vsi_id, status);
			return status;
		}
		fm_entry->fltr_info = tmp_fltr_info;

		/*3. at last release the vsi list resource*/
		status = nse_release_vsi_list(hw, vsi_list_id, lkup_type);
		if (status) {
			nse_debug(hw, NSE_DBG_SW, "Failed to release VSI list resource %d, error %d\n",
				  vsi_list_id, status);
			return status;
		}

		/*4. update software vsi list DB*/
		mutex_lock(&hw->switch_info->vsi_list_lock);
		list_del(&vsi_list_info->list_entry);
		mutex_unlock(&hw->switch_info->vsi_list_lock);

		devm_kfree(nse_hw_to_dev(hw), vsi_list_info);
		fm_entry->vsi_list_info = NULL;
	}

	return status;
}

/**
 * nse_remove_rule_internal - Remove a filter rule of a given type
 *
 * @hw: pointer to the hardware structure
 * @lut: lut info for which the rule needs to removed
 * @f_entry: rule entry containing filter information
 */
static enum nse_status
nse_remove_rule_internal(struct nse_hw *hw, struct nse_lut_info *lut,
			 struct nse_fltr_list_entry *f_entry)
{
	struct nse_fltr_mgmt_list_entry *fm_entry;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	bool remove_node = false;
	enum nse_status status = NSE_SUCCESS;
	u16 vsi_handle;

	if (!nse_is_vsi_valid(hw, f_entry->fltr_info.vsi_handle))
		return NSE_ERR_PARAM;

	f_entry->fltr_info.fwd_id.hw_vsi_id =
		nse_get_hw_vsi_num(hw, f_entry->fltr_info.vsi_handle);

	rule_lock = &lut->filt_rule_lock;
	mutex_lock(rule_lock);
	fm_entry = nse_find_rule_entry(&lut->filt_rules,
					&f_entry->fltr_info);
	if (!fm_entry) {
		status = NSE_ERR_DOES_NOT_EXIST;
		goto exit;
	}

	if (fm_entry->fltr_info.fltr_act != NSE_FWD_TO_VSI_LIST) {
		remove_node = true;
	} else if (!fm_entry->vsi_list_info) {
		status = NSE_ERR_DOES_NOT_EXIST;
		goto exit;
	} else if (refcount_read(&fm_entry->vsi_list_info->ref_cnt) > 1) {
		/*not used now*/
		refcount_dec(&fm_entry->vsi_list_info->ref_cnt);
		remove_node = true;
	} else {
		/* a ref_cnt of 1 indicates the vsi_list is only used by one rule.
		 * so clear the given vsi, remove rule when vsi list is empty
		 */
		vsi_handle = f_entry->fltr_info.vsi_handle;
		status = nse_rem_update_vsi_list(hw, vsi_handle, fm_entry);
		if (status)
			goto exit;
		/* if VSI count goes to zero after updating the VSI list
		 * and VSI list is removed in nse_rem_update_vsi_list
		 */
		if (fm_entry->vsi_count == 0)
			remove_node = true;
	}

	if (remove_node) {
		/* Remove the lut node */
		struct nse_aqc_lut_nodes *buf;
		struct nse_aqc_lut_node_elem *lut_node;
		u16 buf_size = struct_size(buf, elem, 1);

		buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
		if (!buf) {
			status = NSE_ERR_NO_MEMORY;
			goto exit;
		}

		buf->count = cpu_to_le16(1);
		lut_node = buf->elem;
		nse_fill_lut_node(hw, &fm_entry->fltr_info, lut_node,
				 NSE_AQ_OPC_REMOVE_LUT_NODE);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] start to remove node\n",
			 __func__, __LINE__);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] lut id is 0x%x\n",
			 __func__, __LINE__, le16_to_cpu(lut_node->lut_id));
		dev_info(nse_hw_to_dev(hw), "[%s, %d] node_id is 0x%x\n",
			 __func__, __LINE__, le16_to_cpu(lut_node->node_id));
		status = nse_aq_lut_nodes(hw, buf, buf_size,
			NSE_AQ_OPC_REMOVE_LUT_NODE, NULL);

		devm_kfree(nse_hw_to_dev(hw), buf);
		if (status)
			goto exit;

		/* Remove the software filter DB entry from the list */
		list_del(&fm_entry->list_entry);
		devm_kfree(nse_hw_to_dev(hw), fm_entry);
	}
exit:
	mutex_unlock(rule_lock);
	return status;
}

/**
 * nse_vsi_uses_fltr - Determine if given VSI uses specified filter
 * @fm_entry: filter entry to inspect
 * @vsi_handle: VSI handle to compare with filter info
 */
static bool
nse_vsi_uses_fltr(struct nse_fltr_mgmt_list_entry *fm_entry, u16 vsi_handle)
{
	return ((fm_entry->fltr_info.fltr_act == NSE_FWD_TO_VSI &&
		 fm_entry->fltr_info.vsi_handle == vsi_handle) ||
		(fm_entry->fltr_info.fltr_act == NSE_FWD_TO_VSI_LIST &&
		 fm_entry->vsi_list_info &&
		 (test_bit(vsi_handle, fm_entry->vsi_list_info->vsi_map))));
}

/**
 * nse_add_entry_to_vsi_fltr_list - Add copy of fltr_list_entry to remove list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @vsi_list_head: pointer to the list to add entry to
 * @fi: pointer to fltr_info of filter entry to copy & add
 *
 * Helper function, used when creating a list of filters to remove from
 * a specific VSI. The entry added to vsi_list_head is a COPY of the
 * original filter entry, with the exception of fltr_info.fltr_act and
 * fltr_info.fwd_id fields. These are set such that later logic can
 * extract which VSI to remove the fltr from, and pass on that information.
 */
static enum nse_status
nse_add_entry_to_vsi_fltr_list(struct nse_hw *hw, u16 vsi_handle,
			       struct list_head *vsi_list_head,
			       struct nse_fltr_info *fi)
{
	struct nse_fltr_list_entry *tmp;

	/* this memory is freed up in the caller function
	 * once filters for this VSI are removed
	 */
	tmp = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return NSE_ERR_NO_MEMORY;

	tmp->fltr_info = *fi;

	/* Overwrite these fields to indicate which VSI to remove filter from,
	 * so find and remove logic can extract the information from the
	 * list entries. Note that original entries will still have proper values.
	 */
	tmp->fltr_info.fltr_act = NSE_FWD_TO_VSI;
	tmp->fltr_info.vsi_handle = vsi_handle;
	tmp->fltr_info.fwd_id.hw_vsi_id = nse_get_hw_vsi_num(hw, vsi_handle);

	list_add_tail(&tmp->list_entry, vsi_list_head);

	return NSE_SUCCESS;
}

/**
 * nse_add_to_vsi_fltr_list - Add VSI filters to the list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @lkup_list_head: pointer to the list that has certain lookup type filters
 * @vsi_list_head: pointer to the list pertaining to VSI with vsi_handle
 *
 * Locates all filters in lkup_list_head that are used by the given VSI,
 * and adds COPIES of those entries to vsi_list_head (intended to be used
 * to remove the listed filters).
 * Note that this means all entries in vsi_list_head must be explicitly
 * deallocated by the caller when done with list.
 */
static enum nse_status
nse_add_to_vsi_fltr_list(struct nse_hw *hw, u16 vsi_handle,
			 struct list_head *lkup_list_head,
			 struct list_head *vsi_list_head)
{
	struct nse_fltr_mgmt_list_entry *fm_entry;
	enum nse_status status = NSE_SUCCESS;

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;

	list_for_each_entry(fm_entry, lkup_list_head, list_entry) {
		if (!nse_vsi_uses_fltr(fm_entry, vsi_handle))
			continue;

		status = nse_add_entry_to_vsi_fltr_list(hw, vsi_handle,
							vsi_list_head,
							&fm_entry->fltr_info);
		if (status)
			return status;
	}
	return status;
}

/**
 * nse_add_mac_rule - Add a MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @sw: pointer to switch info struct for which function add rule
 *
 */
static enum nse_status
nse_add_mac_rule(struct nse_hw *hw, struct list_head *m_list,
		 struct nse_switch_info *sw)
{
	struct nse_lut_info *lut = &sw->lut_list[NSE_SW_LKUP_MAC];
	struct nse_fltr_list_entry *m_list_itr;

	list_for_each_entry(m_list_itr, m_list, list_entry) {
		u8 *addr = &m_list_itr->fltr_info.l_data.mac.mac_addr[0];
		u16 vsi_handle;
		u16 hw_vsi_id;

		/*check the validation one by one first*/
		vsi_handle = m_list_itr->fltr_info.vsi_handle;
		if (!nse_is_vsi_valid(hw, vsi_handle))
			return NSE_ERR_PARAM;

		hw_vsi_id = nse_get_hw_vsi_num(hw, vsi_handle);
		if (m_list_itr->fltr_info.fltr_act == NSE_FWD_TO_VSI)
			m_list_itr->fltr_info.fwd_id.hw_vsi_id = hw_vsi_id;

		if (m_list_itr->fltr_info.lkup_type != NSE_SW_LKUP_MAC ||
		    is_zero_ether_addr(addr))
			return NSE_ERR_PARAM;

		/*add the rule one by one */
		m_list_itr->status = nse_add_rule_internal(hw, lut, m_list_itr);

		if (m_list_itr->status)
			return m_list_itr->status;
	}

	return NSE_SUCCESS;
}

/**
 * nse_add_mac - Add a MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 * Function add MAC rule for logical port from HW struct
 */
enum nse_status nse_add_mac(struct nse_hw *hw, struct list_head *m_list)
{
	if (!m_list || !hw)
		return NSE_ERR_PARAM;

	return nse_add_mac_rule(hw, m_list, hw->switch_info);
}

/**
 * nse_add_bmc_mac_rule - Add a BMC MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @sw: pointer to switch info struct for which function add rule
 *
 */
static enum nse_status
nse_add_bmc_mac_rule(struct nse_hw *hw, struct list_head *m_list,
		 struct nse_switch_info *sw)
{
	struct nse_lut_info *lut = &sw->lut_list[NSE_SW_LKUP_BMC_MAC];
	struct nse_fltr_list_entry *m_list_itr;

	list_for_each_entry(m_list_itr, m_list, list_entry) {
		struct nse_fltr_info *new_fltr;
		struct nse_fltr_mgmt_list_entry *m_entry = NULL;
		struct mutex *rule_lock;
		u8 *addr = &m_list_itr->fltr_info.l_data.mac.mac_addr[0];

		if (m_list_itr->fltr_info.lkup_type != NSE_SW_LKUP_BMC_MAC ||
		    is_zero_ether_addr(addr))
			return NSE_ERR_PARAM;

		rule_lock = &lut->filt_rule_lock;
		mutex_lock(rule_lock);
		new_fltr = &m_list_itr->fltr_info;
		m_entry = nse_find_rule_entry(&lut->filt_rules, new_fltr);
		if (!m_entry)
			m_list_itr->status = nse_create_pkt_fwd_rule(hw, lut, m_list_itr);
		else
			dev_info(nse_hw_to_dev(hw), "[%s, %d] Mac(%pM) is already existed in BMC Lut\n",
				__func__, __LINE__, addr);
		mutex_unlock(rule_lock);

		if (m_list_itr->status)
			return m_list_itr->status;
	}

	return NSE_SUCCESS;
}

/**
 * nse_add_bmc_mac - Add a BMC MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 * Function add BMC MAC rule for logical port from HW struct
 */
enum nse_status nse_add_bmc_mac(struct nse_hw *hw, struct list_head *m_list)
{
	if (!m_list || !hw)
		return NSE_ERR_PARAM;

	return nse_add_bmc_mac_rule(hw, m_list, hw->switch_info);
}

/**
 * nse_add_roce_mac_rule - Add a roce MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @sw: pointer to switch info struct for which function add rule
 *
 */
static enum nse_status
nse_add_roce_mac_rule(struct nse_hw *hw, struct list_head *m_list,
		 struct nse_switch_info *sw)
{
	struct nse_lut_info *lut = &sw->lut_list[NSE_SW_LKUP_ROCE_MAC];
	struct nse_fltr_list_entry *m_list_itr;

	list_for_each_entry(m_list_itr, m_list, list_entry) {
		struct nse_fltr_info *new_fltr;
		struct nse_fltr_mgmt_list_entry *m_entry = NULL;
		struct mutex *rule_lock;
		u8 *addr = &m_list_itr->fltr_info.l_data.mac.mac_addr[0];

		if (m_list_itr->fltr_info.lkup_type != NSE_SW_LKUP_ROCE_MAC)
			return NSE_ERR_PARAM;

		rule_lock = &lut->filt_rule_lock;
		mutex_lock(rule_lock);
		new_fltr = &m_list_itr->fltr_info;
		m_entry = nse_find_rule_entry(&lut->filt_rules, new_fltr);
		if (!m_entry)
			m_list_itr->status = nse_create_pkt_fwd_rule(hw, lut, m_list_itr);
		else
			dev_info(nse_hw_to_dev(hw), "[%s, %d] Mac(%pM) is already existed in ROCE MAC Lut\n",
				__func__, __LINE__, addr);
		mutex_unlock(rule_lock);

		if (m_list_itr->status)
			return m_list_itr->status;
	}

	return NSE_SUCCESS;
}

/**
 * nse_add_roce_mac - Add a roce MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 * Function add roce MAC rule for logical port from HW struct
 */
enum nse_status nse_add_roce_mac(struct nse_hw *hw, struct list_head *m_list)
{
	if (!m_list || !hw)
		return NSE_ERR_PARAM;

	return nse_add_roce_mac_rule(hw, m_list, hw->switch_info);
}

/**
 * nse_add_vlan_rule - Add VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN entries and forwarding information
 * @sw: pointer to switch info struct for which function add rule
 */
static enum nse_status
nse_add_vlan_rule(struct nse_hw *hw, struct list_head *v_list,
		  struct nse_switch_info *sw)
{
	struct nse_fltr_list_entry *v_list_itr;
	struct nse_lut_info *lut;

	lut = &sw->lut_list[NSE_SW_LKUP_VLAN];
	list_for_each_entry(v_list_itr, v_list, list_entry) {
		if (v_list_itr->fltr_info.lkup_type != NSE_SW_LKUP_VLAN)
			return NSE_ERR_PARAM;
		v_list_itr->status = nse_add_rule_internal(hw, lut,
							   v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_add_vlan - Add a VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN and forwarding information
 *
 * Function add VLAN rule for logical port from HW struct
 */
enum nse_status nse_add_vlan(struct nse_hw *hw, struct list_head *v_list)
{
	if (!v_list || !hw)
		return NSE_ERR_PARAM;

	return nse_add_vlan_rule(hw, v_list, hw->switch_info);
}

/**
 * nse_add_mac_vlan_rule - Add MAC and VLAN pair based filter rule
 * @hw: pointer to the hardware structure
 * @mv_list: list of MAC and VLAN filters
 * @sw: pointer to switch info struct for which function add rule
 *
 * If the VSI on which the MAC-VLAN pair has to be added has Rx and Tx VLAN
 * pruning bits enabled, then it is the responsibility of the caller to make
 * sure to add a VLAN only filter on the same VSI. Packets belonging to that
 * VLAN won't be received on that VSI otherwise.
 */
static enum nse_status
nse_add_mac_vlan_rule(struct nse_hw *hw, struct list_head *mv_list,
		      struct nse_switch_info *sw)
{
	struct nse_fltr_list_entry *mv_list_itr;
	struct nse_lut_info *lut;

	if (!mv_list || !hw)
		return NSE_ERR_PARAM;

	lut = &sw->lut_list[NSE_SW_LKUP_MAC_VLAN];
	list_for_each_entry(mv_list_itr, mv_list, list_entry) {
		enum nse_sw_lkup_type l_type =
			mv_list_itr->fltr_info.lkup_type;

		if (l_type != NSE_SW_LKUP_MAC_VLAN)
			return NSE_ERR_PARAM;

		mv_list_itr->status =
			nse_add_rule_internal(hw, lut, mv_list_itr);
		if (mv_list_itr->status)
			return mv_list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_add_mac_vlan - Add a MAC VLAN address based filter rule
 * @hw: pointer to the hardware structure
 * @mv_list: list of MAC VLAN addresses and forwarding information
 *
 * Function add MAC VLAN rule for logical port from HW struct
 */
enum nse_status
nse_add_mac_vlan(struct nse_hw *hw, struct list_head *mv_list)
{
	if (!mv_list || !hw)
		return NSE_ERR_PARAM;

	return nse_add_mac_vlan_rule(hw, mv_list, hw->switch_info);
}

/**
 * nse_add_eth_mac_rule - Add ethertype and MAC based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ether type MAC filter, MAC is optional
 * @sw: pointer to switch info struct for which function add rule
 *
 */
static enum nse_status
nse_add_eth_mac_rule(struct nse_hw *hw, struct list_head *em_list,
		     struct nse_switch_info *sw)
{
	struct nse_fltr_list_entry *em_list_itr;

	list_for_each_entry(em_list_itr, em_list, list_entry) {
		struct nse_lut_info *lut;
		enum nse_sw_lkup_type l_type;

		l_type = em_list_itr->fltr_info.lkup_type;
		lut = &sw->lut_list[l_type];

		if (l_type != NSE_SW_LKUP_ETHERTYPE_MAC &&
		    l_type != NSE_SW_LKUP_ETHERTYPE)
			return NSE_ERR_PARAM;

		em_list_itr->status = nse_add_rule_internal(hw, lut,
							    em_list_itr);
		if (em_list_itr->status)
			return em_list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_add_eth_mac - Add a ethertype based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ethertype and forwarding information
 *
 * Function add ethertype rule for logical port from HW struct
 */
enum nse_status
nse_add_eth_mac(struct nse_hw *hw, struct list_head *em_list)
{
	if (!em_list || !hw)
		return NSE_ERR_PARAM;

	return nse_add_eth_mac_rule(hw, em_list, hw->switch_info);
}

/**
 * nse_remove_mac_rule - remove a MAC based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @lut: lut from which function remove MAC address
 *
 * This function removes either a MAC filter rule or a specific VSI from a
 * VSI list for a multicast MAC address.
 *
 */
static enum nse_status
nse_remove_mac_rule(struct nse_hw *hw, struct list_head *m_list,
		    struct nse_lut_info *lut)
{
	struct nse_fltr_list_entry *list_itr, *tmp;

	if (!m_list)
		return NSE_ERR_PARAM;

	list_for_each_entry_safe(list_itr, tmp, m_list, list_entry) {
		enum nse_sw_lkup_type l_type = list_itr->fltr_info.lkup_type;
		u16 vsi_handle;

		if (l_type != NSE_SW_LKUP_MAC)
			return NSE_ERR_PARAM;

		vsi_handle = list_itr->fltr_info.vsi_handle;
		if (!nse_is_vsi_valid(hw, vsi_handle))
			return NSE_ERR_PARAM;

		list_itr->fltr_info.fwd_id.hw_vsi_id =
					nse_get_hw_vsi_num(hw, vsi_handle);

		list_itr->status = nse_remove_rule_internal(hw, lut,
							    list_itr);
		if (list_itr->status)
			return list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_remove_mac - remove a MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 */
enum nse_status nse_remove_mac(struct nse_hw *hw, struct list_head *m_list)
{
	struct nse_lut_info *lut;

	lut = &hw->switch_info->lut_list[NSE_SW_LKUP_MAC];
	return nse_remove_mac_rule(hw, m_list, lut);
}

/**
 * nse_remove_bmc_mac_rule - remove a BMC MAC based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @lut: lut from which function remove MAC address
 *
 * This function removes either a MAC filter rule or a specific VSI from a
 * VSI list for a multicast MAC address.
 *
 */
static enum nse_status
nse_remove_bmc_mac_rule(struct nse_hw *hw, struct list_head *m_list,
		    struct nse_lut_info *lut)
{
	struct nse_fltr_list_entry *list_itr, *tmp;

	if (!m_list)
		return NSE_ERR_PARAM;

	list_for_each_entry_safe(list_itr, tmp, m_list, list_entry) {
		enum nse_sw_lkup_type l_type = list_itr->fltr_info.lkup_type;

		if (l_type != NSE_SW_LKUP_BMC_MAC)
			return NSE_ERR_PARAM;

		list_itr->status = nse_remove_rule_internal(hw, lut,
							    list_itr);
		if (list_itr->status)
			return list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_remove_bmc_mac - remove a BMC MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 */
enum nse_status nse_remove_bmc_mac(struct nse_hw *hw, struct list_head *m_list)
{
	struct nse_lut_info *lut;

	lut = &hw->switch_info->lut_list[NSE_SW_LKUP_BMC_MAC];
	return nse_remove_bmc_mac_rule(hw, m_list, lut);
}

/**
 * nse_remove_roce_mac_rule - remove a roce MAC based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @lut: lut from which function remove MAC address
 *
 *
 */
static enum nse_status
nse_remove_roce_mac_rule(struct nse_hw *hw, struct list_head *m_list,
		    struct nse_lut_info *lut)
{
	struct nse_fltr_list_entry *list_itr, *tmp;

	if (!m_list)
		return NSE_ERR_PARAM;

	list_for_each_entry_safe(list_itr, tmp, m_list, list_entry) {
		enum nse_sw_lkup_type l_type = list_itr->fltr_info.lkup_type;

		if (l_type != NSE_SW_LKUP_ROCE_MAC)
			return NSE_ERR_PARAM;

		list_itr->status = nse_remove_rule_internal(hw, lut,
							    list_itr);
		if (list_itr->status)
			return list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_remove_roce_mac - remove a roce MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 */
enum nse_status nse_remove_roce_mac(struct nse_hw *hw, struct list_head *m_list)
{
	struct nse_lut_info *lut;

	lut = &hw->switch_info->lut_list[NSE_SW_LKUP_ROCE_MAC];
	return nse_remove_roce_mac_rule(hw, m_list, lut);
}

/**
 * nse_remove_vlan_rule - Remove VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN entries and forwarding information
 * @lut: lut from which function remove VLAN
 */
static enum nse_status
nse_remove_vlan_rule(struct nse_hw *hw, struct list_head *v_list,
		     struct nse_lut_info *lut)
{
	struct nse_fltr_list_entry *v_list_itr, *tmp;

	list_for_each_entry_safe(v_list_itr, tmp, v_list, list_entry) {
		enum nse_sw_lkup_type l_type = v_list_itr->fltr_info.lkup_type;

		if (l_type != NSE_SW_LKUP_VLAN)
			return NSE_ERR_PARAM;

		v_list_itr->status = nse_remove_rule_internal(hw, lut,
							      v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_remove_vlan - remove a VLAN address based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN and forwarding information
 *
 */
enum nse_status nse_remove_vlan(struct nse_hw *hw, struct list_head *v_list)
{
	struct nse_lut_info *lut;

	if (!v_list || !hw)
		return NSE_ERR_PARAM;

	lut = &hw->switch_info->lut_list[NSE_SW_LKUP_VLAN];
	return nse_remove_vlan_rule(hw, v_list, lut);
}

/**
 * nse_remove_mac_vlan_rule - Remove MAC VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of MAC VLAN entries and forwarding information
 * @lut: lut from which function remove MAC VLAN
 */
static enum nse_status
nse_remove_mac_vlan_rule(struct nse_hw *hw, struct list_head *v_list,
			 struct nse_lut_info *lut)
{
	struct nse_fltr_list_entry *v_list_itr, *tmp;

	list_for_each_entry_safe(v_list_itr, tmp, v_list, list_entry) {
		enum nse_sw_lkup_type l_type = v_list_itr->fltr_info.lkup_type;

		if (l_type != NSE_SW_LKUP_MAC_VLAN)
			return NSE_ERR_PARAM;

		v_list_itr->status =
			nse_remove_rule_internal(hw, lut, v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_remove_mac_vlan - remove a MAC VLAN address based filter rule
 * @hw: pointer to the hardware structure
 * @mv_list: list of MAC VLAN and forwarding information
 */
enum nse_status
nse_remove_mac_vlan(struct nse_hw *hw, struct list_head *mv_list)
{
	struct nse_lut_info *lut;

	if (!mv_list || !hw)
		return NSE_ERR_PARAM;

	lut = &hw->switch_info->lut_list[NSE_SW_LKUP_MAC_VLAN];
	return nse_remove_mac_vlan_rule(hw, mv_list, lut);
}

/**
 * nse_remove_eth_mac_rule - Remove an ethertype (or MAC) based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ethertype or ethertype MAC entries
 * @sw: pointer to switch info struct for which function add rule
 */
static enum nse_status
nse_remove_eth_mac_rule(struct nse_hw *hw, struct list_head *em_list,
			struct nse_switch_info *sw)
{
	struct nse_fltr_list_entry *em_list_itr, *tmp;

	list_for_each_entry_safe(em_list_itr, tmp, em_list, list_entry) {
		struct nse_lut_info *lut;
		enum nse_sw_lkup_type l_type;

		l_type = em_list_itr->fltr_info.lkup_type;

		if (l_type != NSE_SW_LKUP_ETHERTYPE_MAC &&
		    l_type != NSE_SW_LKUP_ETHERTYPE)
			return NSE_ERR_PARAM;

		lut = &sw->lut_list[l_type];

		dev_info(nse_hw_to_dev(hw), "[%s, %d] start to remove Lut[%d] node, node id = %d\n",
			__func__, __LINE__, lut->lut_id, em_list_itr->fltr_info.fltr_node_id);

		em_list_itr->status = nse_remove_rule_internal(hw, lut,
							       em_list_itr);
		if (em_list_itr->status)
			return em_list_itr->status;
	}
	return NSE_SUCCESS;
}

/**
 * nse_remove_eth_mac - remove a ethertype based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ethertype and forwarding information
 *
 */
enum nse_status
nse_remove_eth_mac(struct nse_hw *hw, struct list_head *em_list)
{
	if (!em_list || !hw)
		return NSE_ERR_PARAM;

	return nse_remove_eth_mac_rule(hw, em_list, hw->switch_info);
}

/**
 * nse_remove_promisc - Remove promisc based filter rules
 * @hw: pointer to the hardware structure
 * @recp_id: recipe ID for which the rule needs to removed
 * @v_list: list of promisc entries
 */
static enum nse_status
nse_remove_promisc(struct nse_hw *hw, u8 lut_id,
				   struct list_head *v_list)
{
	struct nse_fltr_list_entry *v_list_itr, *tmp;
	struct nse_lut_info *lut_info;

	lut_info = &hw->switch_info->lut_list[lut_id];
	list_for_each_entry_safe(v_list_itr, tmp, v_list, list_entry) {
		v_list_itr->status =
			nse_remove_rule_internal(hw, lut_info, v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return 0;
}

/**
 * nse_remove_vsi_lkup_fltr - Remove lookup type filters for a VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @lut_list: lut list from which function remove fltr
 * @lkup: switch rule filter lookup type
 */
static void
nse_remove_vsi_lkup_fltr(struct nse_hw *hw, u16 vsi_handle,
			 struct nse_lut_info *lut_list,
			 enum nse_sw_lkup_type lkup_type)
{
	struct nse_fltr_list_entry *f_entry;
	struct list_head remove_list_head;
	struct list_head *rule_head;
	struct nse_fltr_list_entry *tmp;
	struct mutex *rule_lock;
	enum nse_status status;

	INIT_LIST_HEAD(&remove_list_head);
	rule_lock = &lut_list[lkup_type].filt_rule_lock;
	rule_head = &lut_list[lkup_type].filt_rules;
	mutex_lock(rule_lock);
	/* copy filter enties of this vsi from software DB to tmp list head
	 * [Note] struct in rule_head is nse_fltr_mgmt_list_entry,
	 *            but struct in remove_list_head is nse_fltr_list_entry
	 */
	status = nse_add_to_vsi_fltr_list(hw, vsi_handle, rule_head,
					  &remove_list_head);
	mutex_unlock(rule_lock);
	if (status)
		goto free_fltr_list;

	/*remove the list entries including firmware and software DBs*/
	switch (lkup_type) {
	case NSE_SW_LKUP_MAC:
		nse_remove_mac_rule(hw, &remove_list_head, &lut_list[lkup_type]);
		break;
	case NSE_SW_LKUP_VLAN:
		nse_remove_vlan_rule(hw, &remove_list_head, &lut_list[lkup_type]);
		break;
	case NSE_SW_LKUP_MAC_VLAN:
		nse_remove_mac_vlan(hw, &remove_list_head);
		break;
	case NSE_SW_LKUP_ETHERTYPE:
	case NSE_SW_LKUP_ETHERTYPE_MAC:
		nse_remove_eth_mac(hw, &remove_list_head);
		break;
	case NSE_SW_LKUP_BMC_MAC:
		nse_debug(hw, NSE_DBG_SW, "BMC MAC should be removed by fw event\n");
		break;
	case NSE_SW_LKUP_ROCE_MAC:
	case NSE_SW_LKUP_LAST:
		nse_debug(hw, NSE_DBG_SW, "Unsupported lookup type\n");
		break;
	case NSE_SW_LKUP_PROMISC:
	case NSE_SW_LKUP_PROMISC_VLAN:
		nse_remove_promisc(hw, (u8)lkup_type, &remove_list_head);
		break;
	}

free_fltr_list:
	list_for_each_entry_safe(f_entry, tmp, &remove_list_head, list_entry) {
		list_del(&f_entry->list_entry);
		devm_kfree(nse_hw_to_dev(hw), f_entry);
	}
}

/**
 * nse_remove_vsi_fltr_rule - Remove all filters for a VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @sw: pointer to switch info struct
 */
static void
nse_remove_vsi_fltr_rule(struct nse_hw *hw, u16 vsi_handle,
			 struct nse_switch_info *sw)
{
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_MAC);
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_MAC_VLAN);
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_VLAN);
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_ETHERTYPE);
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_ETHERTYPE_MAC);
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_PROMISC);
	nse_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->lut_list, NSE_SW_LKUP_PROMISC_VLAN);
}

/**
 * nse_remove_vsi_fltr - Remove all filters for a given VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 */
void nse_remove_vsi_fltr(struct nse_hw *hw, u16 vsi_handle)
{
	if (nse_bypass_switch)
		return;

	nse_remove_vsi_fltr_rule(hw, vsi_handle, hw->switch_info);
}

/**
 * nse_determine_promisc_mask
 * @fi: filter info to parse
 *
 * Helper function to determine which NSE_PROMISC_ mask corresponds
 * to given filter into.
 */
static u8 nse_determine_promisc_mask(struct nse_fltr_info *fi)
{
	u16 vid = fi->l_data.promisc.vlan_id;
	u16 mactype = fi->l_data.promisc.mactype;
	bool is_tx_fltr = false;
	u8 promisc_mask = 0;

	/* replace dir with flag  */
	if (fi->dir == NSE_FILTER_DIR_TX)
		is_tx_fltr = true;

	if (mactype == NSE_PROMISC_MACTYPE_BCAST)
		promisc_mask |= is_tx_fltr ?
			NSE_PROMISC_BCAST_TX : NSE_PROMISC_BCAST_RX;
	else if (mactype == NSE_PROMISC_MACTYPE_MCAST)
		promisc_mask |= is_tx_fltr ?
			NSE_PROMISC_MCAST_TX : NSE_PROMISC_MCAST_RX;
	else if (mactype == NSE_PROMISC_MACTYPE_UCAST)
		promisc_mask |= is_tx_fltr ?
			NSE_PROMISC_UCAST_TX : NSE_PROMISC_UCAST_RX;
	if (vid)
		promisc_mask |= is_tx_fltr ?
			NSE_PROMISC_VLAN_TX : NSE_PROMISC_VLAN_RX;

	return promisc_mask;
}

/**
 * _nse_clear_vsi_promisc - clear specified promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to clear mode
 * @promisc_mask: mask of promiscuous config bits to clear
 * @vid: VLAN ID to clear VLAN promiscuous
 * @sw: pointer to switch info struct for which function add rule
 */
static enum nse_status
_nse_clear_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
					   u16 vid, struct nse_switch_info *sw)
{
	struct nse_fltr_list_entry *fm_entry, *tmp;
	struct list_head remove_list_head;
	struct nse_fltr_mgmt_list_entry *itr;
	struct list_head *rule_head;
	struct mutex *rule_lock;    /* Lock to protect filter rule list */
	enum nse_status status = 0;
	u8 lut_id;

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;

	if (promisc_mask & (NSE_PROMISC_VLAN_RX | NSE_PROMISC_VLAN_TX))
		lut_id = NSE_SW_LKUP_PROMISC_VLAN;
	else
		lut_id = NSE_SW_LKUP_PROMISC;

	rule_head = &sw->lut_list[lut_id].filt_rules;
	rule_lock = &sw->lut_list[lut_id].filt_rule_lock;

	INIT_LIST_HEAD(&remove_list_head);

	mutex_lock(rule_lock);
	list_for_each_entry(itr, rule_head, list_entry) {
		struct nse_fltr_info *fltr_info;
		u8 fltr_promisc_mask = 0;

		if (!nse_vsi_uses_fltr(itr, vsi_handle))
			continue;
		fltr_info = &itr->fltr_info;

		if (lut_id == NSE_SW_LKUP_PROMISC_VLAN &&
			vid != fltr_info->l_data.promisc.vlan_id)
			continue;

		fltr_promisc_mask |= nse_determine_promisc_mask(fltr_info);

		/* Skip if filter is not completely specified by given mask */
		if (fltr_promisc_mask & ~promisc_mask)
			continue;

		status = nse_add_entry_to_vsi_fltr_list(hw, vsi_handle,
							&remove_list_head,
							fltr_info);
		if (status) {
			mutex_unlock(rule_lock);
			goto free_fltr_list;
		}
	}
	mutex_unlock(rule_lock);

	status = nse_remove_promisc(hw, lut_id, &remove_list_head);

free_fltr_list:
	list_for_each_entry_safe(fm_entry, tmp, &remove_list_head, list_entry) {
		list_del(&fm_entry->list_entry);
		devm_kfree(nse_hw_to_dev(hw), fm_entry);
	}

	return status;
}

/**
 * nse_clear_vsi_promisc - clear specified promiscuous mode(s) for given VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to clear mode
 * @promisc_mask: mask of promiscuous config bits to clear
 * @vid: VLAN ID to clear VLAN promiscuous
 */
enum nse_status
nse_clear_vsi_promisc(struct nse_hw *hw, u16 vsi_handle,
		      u8 promisc_mask, u16 vid)
{
	if (nse_bypass_switch)
		return NSE_SUCCESS;

	return _nse_clear_vsi_promisc(hw, vsi_handle, promisc_mask,
						 vid, hw->switch_info);
}

/**
 * _nse_set_vsi_promisc - set given VSI to given promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: mask of promiscuous config bits
 * @vid: VLAN ID to set VLAN promiscuous
 * @sw: pointer to switch info struct for which function add rule
 */
static enum nse_status
_nse_set_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
					 u16 vid, struct nse_switch_info *sw)
{
	enum { UCAST_FLTR = 1, MCAST_FLTR, BCAST_FLTR };
	struct nse_fltr_list_entry f_list_entry;
	struct nse_fltr_info new_fltr;
	struct nse_vsi_ctx *vsi_ctx;
	bool is_tx_fltr;
	enum nse_status status = 0;
	u16 hw_vsi_id;
	int pkt_type;
	u8 lut_id;

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;
	hw_vsi_id = nse_get_hw_vsi_num(hw, vsi_handle);
	vsi_ctx = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi_ctx)
		return NSE_ERR_PARAM;

	memset(&new_fltr, 0, sizeof(new_fltr));

	if (promisc_mask & (NSE_PROMISC_VLAN_RX | NSE_PROMISC_VLAN_TX)) {
		new_fltr.lkup_type = NSE_SW_LKUP_PROMISC_VLAN;
		new_fltr.l_data.promisc.vlan_id = vid;
		lut_id = NSE_SW_LKUP_PROMISC_VLAN;
	} else {
		new_fltr.lkup_type = NSE_SW_LKUP_PROMISC;
		lut_id = NSE_SW_LKUP_PROMISC;
	}

	while (promisc_mask) {
		struct nse_lut_info *lut_list;

		pkt_type = 0;
		is_tx_fltr = false;

		if (promisc_mask & NSE_PROMISC_UCAST_RX) {
			promisc_mask &= ~NSE_PROMISC_UCAST_RX;
			pkt_type = UCAST_FLTR;
		} else if (promisc_mask & NSE_PROMISC_UCAST_TX) {
			promisc_mask &= ~NSE_PROMISC_UCAST_TX;
			pkt_type = UCAST_FLTR;
			is_tx_fltr = true;
		} else if (promisc_mask & NSE_PROMISC_MCAST_RX) {
			promisc_mask &= ~NSE_PROMISC_MCAST_RX;
			pkt_type = MCAST_FLTR;
		} else if (promisc_mask & NSE_PROMISC_MCAST_TX) {
			promisc_mask &= ~NSE_PROMISC_MCAST_TX;
			pkt_type = MCAST_FLTR;
			is_tx_fltr = true;
		} else if (promisc_mask & NSE_PROMISC_BCAST_RX) {
			promisc_mask &= ~NSE_PROMISC_BCAST_RX;
			pkt_type = BCAST_FLTR;
		} else if (promisc_mask & NSE_PROMISC_BCAST_TX) {
			promisc_mask &= ~NSE_PROMISC_BCAST_TX;
			pkt_type = BCAST_FLTR;
			is_tx_fltr = true;
		}

		if (promisc_mask & NSE_PROMISC_VLAN_RX) {
			promisc_mask &= ~NSE_PROMISC_VLAN_RX;
		} else if (promisc_mask & NSE_PROMISC_VLAN_TX) {
			promisc_mask &= ~NSE_PROMISC_VLAN_TX;
			is_tx_fltr = true;
		}

		if (pkt_type == BCAST_FLTR)
			new_fltr.l_data.promisc.mactype = NSE_PROMISC_MACTYPE_BCAST;
		else if (pkt_type == MCAST_FLTR)
			new_fltr.l_data.promisc.mactype = NSE_PROMISC_MACTYPE_MCAST;
		else
			new_fltr.l_data.promisc.mactype = NSE_PROMISC_MACTYPE_UCAST;

		if (is_tx_fltr)
			new_fltr.dir = NSE_FILTER_DIR_TX;
		else
			new_fltr.dir = NSE_FILTER_DIR_RX;

		new_fltr.sw_id = ((le32_to_cpu(vsi_ctx->info.tpp_per_vsi_ctxt) &
						NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_M) >>
						NSE_AQ_VSI_SW_FLAG_TPP_SW_ID_S);
		new_fltr.fltr_act = NSE_FWD_TO_VSI;
		new_fltr.vsi_handle = vsi_handle;
		new_fltr.fwd_id.hw_vsi_id = hw_vsi_id;

		f_list_entry.fltr_info = new_fltr;
		lut_list = &sw->lut_list[lut_id];

		status = nse_add_rule_internal(hw, lut_list,
									   &f_list_entry);
		if (status)
			goto set_promisc_exit;
	}

set_promisc_exit:
	return status;
}

/**
 * nse_set_vsi_promisc - set given VSI to given promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: mask of promiscuous config bits
 * @vid: VLAN ID to set VLAN promiscuous
 */
enum nse_status
nse_set_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
		  u16 vid)
{
	if (nse_bypass_switch)
		return NSE_SUCCESS;

	return _nse_set_vsi_promisc(hw, vsi_handle, promisc_mask, vid,
				  hw->switch_info);
}

/**
 * _nse_set_vlan_vsi_promisc
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: mask of promiscuous config bits
 * @rm_vlan_promisc: Clear VLANs VSI promisc mode
 * @lport: logical port number to configure promisc mode
 * @sw: pointer to switch info struct for which function add rule
 *
 * Configure VSI with all associated VLANs to given promiscuous mode(s)
 */
static enum nse_status
_nse_set_vlan_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
						  bool rm_vlan_promisc,
						  struct nse_switch_info *sw)
{
	struct nse_fltr_list_entry *list_itr, *tmp;
	struct list_head vsi_list_head;
	struct list_head *vlan_head;
	struct mutex *vlan_lock; /* Lock to protect filter rule list */
	enum nse_status status;
	u16 vlan_id;

	INIT_LIST_HEAD(&vsi_list_head);
	vlan_lock = &sw->lut_list[NSE_SW_LKUP_VLAN].filt_rule_lock;
	vlan_head = &sw->lut_list[NSE_SW_LKUP_VLAN].filt_rules;
	mutex_lock(vlan_lock);
	status = nse_add_to_vsi_fltr_list(hw, vsi_handle, vlan_head,
									  &vsi_list_head);
	mutex_unlock(vlan_lock);
	if (status)
		goto free_fltr_list;

	list_for_each_entry(list_itr, &vsi_list_head, list_entry) {
		/* Avoid enabling or disabling vlan zero twice when in double
		 * vlan mode
		 */
		if (list_itr->fltr_info.l_data.vlan.tpid == 0)
			continue;

		vlan_id = list_itr->fltr_info.l_data.vlan.vlan_id;
		if (rm_vlan_promisc)
			status = _nse_clear_vsi_promisc(hw, vsi_handle,
						   promisc_mask,
						   vlan_id, sw);
		else
			status = _nse_set_vsi_promisc(hw, vsi_handle,
							 promisc_mask, vlan_id,
							 sw);
		if (status && status != -EEXIST)
			break;
	}

free_fltr_list:
	list_for_each_entry_safe(list_itr, tmp, &vsi_list_head, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(nse_hw_to_dev(hw), list_itr);
	}
	return status;
}

/**
 * nse_set_vlan_vsi_promisc
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: mask of promiscuous config bits
 * @rm_vlan_promisc: Clear VLANs VSI promisc mode
 *
 * Configure VSI with all associated VLANs to given promiscuous mode(s)
 */
enum nse_status
nse_set_vlan_vsi_promisc(struct nse_hw *hw, u16 vsi_handle, u8 promisc_mask,
						 bool rm_vlan_promisc)
{
	if (nse_bypass_switch)
		return NSE_SUCCESS;

	return _nse_set_vlan_vsi_promisc(hw, vsi_handle, promisc_mask,
									 rm_vlan_promisc,
									 hw->switch_info);
}

/**
 * nse_replay_vsi_fltr - Replay filters for requested VSI
 * @hw: pointer to the hardware structure
 * @sw: pointer to switch info struct for which function replays filters
 * @vsi_handle: driver VSI handle
 * @lut_id: lut ID for which rules need to be replayed
 * @list_head: list for which filters need to be replayed
 *
 * Replays the filter of recipe recp_id for a VSI represented via vsi_handle.
 * It is required to pass valid VSI handle.
 */
static enum nse_status
nse_replay_vsi_fltr(struct nse_hw *hw, struct nse_switch_info *sw,
			u16 vsi_handle, u16 lut_id,
		    struct list_head *list_head)
{
	struct nse_fltr_mgmt_list_entry *itr;
	struct nse_lut_info *lut;
	int status = 0;

	if (list_empty(list_head))
		return status;

	lut = &sw->lut_list[lut_id];

	list_for_each_entry(itr, list_head, list_entry) {
		struct nse_fltr_list_entry f_entry;

		f_entry.fltr_info = itr->fltr_info;
		if (itr->vsi_count < 2 &&
		    itr->fltr_info.vsi_handle == vsi_handle) {
			status = nse_add_rule_internal(hw, lut, &f_entry);
			if (status)
				goto end;

			continue;
		}

		if (!itr->vsi_list_info ||
		    !test_bit(vsi_handle, itr->vsi_list_info->vsi_map))
			continue;

		/* Clearing it so that the logic can add it back */
		clear_bit(vsi_handle, itr->vsi_list_info->vsi_map);
		f_entry.fltr_info.vsi_handle = vsi_handle;
		f_entry.fltr_info.fltr_act = NSE_FWD_TO_VSI;
		status = nse_add_rule_internal(hw, lut, &f_entry);
		if (status)
			goto end;
	}
end:
	return status;
}

/**
 * nse_replay_vsi_all_fltr - replay all filters stored in bookkeeping lists
 * @hw: pointer to the hardware structure
 * @vsi_handle: driver VSI handle
 *
 * Replays filters for requested VSI via vsi_handle.
 */
enum nse_status
nse_replay_vsi_all_fltr_flex(struct nse_hw *hw,
			u16 vsi_handle)
{
	struct nse_switch_info *sw = hw->switch_info;
	enum nse_status status;
	u16 i;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	/* Update the recipes that were created */
	for (i = 0; i < NSE_SW_LKUP_LAST; i++) {
		struct list_head *head;

		if (i == NSE_SW_LKUP_BMC_MAC)
			continue;

		head = &sw->lut_list[i].filt_replay_rules;
		status = nse_replay_vsi_fltr(hw, sw, vsi_handle, i,
						     head);
		if (status)
			return status;
	}

	return NSE_SUCCESS;
}

/**
 * nse_rem_sw_rule_info
 * @hw: pointer to the hardware structure
 * @rule_head: pointer to the switch list structure that we want to delete
 */
static void
nse_rem_sw_rule_info(struct nse_hw *hw, struct list_head *rule_head)
{
	if (!list_empty(rule_head)) {
		struct nse_fltr_mgmt_list_entry *entry;
		struct nse_fltr_mgmt_list_entry *tmp;

		list_for_each_entry_safe(entry, tmp, rule_head, list_entry) {
			list_del(&entry->list_entry);
			devm_kfree(nse_hw_to_dev(hw), entry);
		}
	}
}

/**
 * nse_rm_sw_replay_rule_info - helper function to delete filter replay rules
 * @hw: pointer to the HW struct
 * @sw: pointer to switch info struct for which function removes filters
 *
 * Deletes the filter replay rules for given switch
 */
static void nse_rm_sw_replay_rule_info(struct nse_hw *hw, struct nse_switch_info *sw)
{
	u8 i;

	if (!sw)
		return;

	for (i = 0; i < NSE_SW_LKUP_LAST; i++) {
		if (!list_empty(&sw->lut_list[i].filt_replay_rules)) {
			struct list_head *l_head;

			l_head = &sw->lut_list[i].filt_replay_rules;
			nse_rem_sw_rule_info(hw, l_head);
		}
	}
}

/**
 * nse_rm_all_sw_replay_rule_info - deletes filter replay rules
 * @hw: pointer to the HW struct
 *
 * Deletes the filter replay rules.
 */
void nse_drain_sw_replay_list_flex(struct nse_hw *hw)
{
	if (nse_bypass_switch)
		return;

	nse_rm_sw_replay_rule_info(hw, hw->switch_info);
}

void nse_replace_sw_replay_list_flex(struct nse_hw *hw)
{
	struct nse_switch_info *sw = NULL;
	u8 i;

	if (nse_bypass_switch)
		return;

	sw = hw->switch_info;

	for (i = 0; i < NSE_SW_LKUP_LAST; i++)
		list_replace_init(&sw->lut_list[i].filt_rules,
				  &sw->lut_list[i].filt_replay_rules);
}

/* This is mapping table entry that maps every word within a given protocol
 * structure to the real byte offset as per the specification of that
 * protocol header.
 * for example dst address is 3 words in ethertype header and corresponding
 * bytes are 0, 2, 3 in the actual packet header and src address is at 4, 6, 8
 * IMPORTANT: Every structure part of "nse_prot_hdr" union should have a
 * matching entry describing its field. This needs to be updated if new
 * structure is added to that union.
 */
static const struct nse_prot_ext_tbl_entry nse_prot_ext[NSE_PROTOCOL_LAST] = {
	{ NSE_MAC_OFOS,		{ 0, 2, 4, 6, 8, 10, 12 } },
	{ NSE_MAC_IL,		{ 0, 2, 4, 6, 8, 10, 12 } },
	{ NSE_ETYPE_OLOS,	{ 0 } },
	{ NSE_ETYPE_IL,		{ 0 } },
	{ NSE_VLAN_OFOS,	{ 2, 0 } },
	{ NSE_IPV4_OFOS,	{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18 } },
	{ NSE_IPV4_IL,		{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18 } },
	{ NSE_IPV6_OFOS,	{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24,
				 26, 28, 30, 32, 34, 36, 38 } },
	{ NSE_IPV6_IL,		{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24,
				 26, 28, 30, 32, 34, 36, 38 } },
	{ NSE_IN_PORT,		{ NSE_INPORT_MDID_HW } },
	{ NSE_CT_STATE,		{ NSE_CT_STATE_MDID_HW } },
	{ NSE_FTE_ID,		{ NSE_FTE_ID_MDID_HW } },
	{ NSE_ZONE_ID,		{ NSE_ZONE_ID_MDID_HW } },
	{ NSE_TCP_IL,		{ 0, 2, 4, 6, 8, 10, 12 } },
	{ NSE_UDP_OF,		{ 0, 2 } },
	{ NSE_UDP_ILOS,		{ 0, 2 } },
	{ NSE_SCTP_IL,		{ 0, 2 } },
	{ NSE_VXLAN,		{ 8, 10, 12, 14 } },
	{ NSE_GENEVE,		{ 8, 10, 12, 14 } },
	{ NSE_VXLAN_GPE,	{ 8, 10, 12, 14 } },
	{ NSE_NVGRE,		{ 0, 2, 4, 6 } },
	{ NSE_GTP,		{ 8, 10, 12, 14, 16, 18, 20, 22 } },
	{ NSE_GTP_NO_PAY,	{ 8, 10, 12, 14 } },
	{ NSE_PPPOE,		{ 0, 2, 4, 6 } },
	{ NSE_VLAN_EX,		{ 2, 0 } },
	{ NSE_VLAN_IN,		{ 2, 0 } },
};

/* The following table describes preferred grouping of recipes.
 * If a recipe that needs to be programmed is a superset or matches one of the
 * following combinations, then the recipe needs to be chained as per the
 * following policy.
 */

static struct nse_protocol_entry nse_prot_id_tbl[NSE_PROTOCOL_LAST] = {
	{ NSE_MAC_OFOS,		NSE_MAC_OFOS_HW },
	{ NSE_MAC_IL,		NSE_MAC_IL_HW },
	{ NSE_ETYPE_OLOS,	NSE_ETYPE_OLOS_HW },
	{ NSE_ETYPE_IL,		NSE_ETYPE_IL_HW },
	{ NSE_VLAN_OFOS,	NSE_VLAN_OFOS_HW },
	{ NSE_IPV4_OFOS,	NSE_IPV4_OFOS_HW },
	{ NSE_IPV4_IL,		NSE_IPV4_IL_HW },
	{ NSE_IPV6_OFOS,	NSE_IPV6_OFOS_HW },
	{ NSE_IPV6_IL,		NSE_IPV6_IL_HW },
	{ NSE_IN_PORT,		NSE_MD_PROT_HW },
	{ NSE_CT_STATE,		NSE_MD_PROT_HW },
	{ NSE_FTE_ID,		NSE_MD_PROT_HW },
	{ NSE_ZONE_ID,		NSE_MD_PROT_HW },
	{ NSE_TCP_IL,		NSE_TCP_IL_HW },
	{ NSE_UDP_OF,		NSE_UDP_OF_HW },
	{ NSE_UDP_ILOS,		NSE_UDP_ILOS_HW },
	{ NSE_SCTP_IL,		NSE_SCTP_IL_HW },
	{ NSE_VXLAN,		NSE_UDP_OF_HW },
	{ NSE_GENEVE,		NSE_UDP_OF_HW },
	{ NSE_VXLAN_GPE,	NSE_UDP_OF_HW },
	{ NSE_NVGRE,		NSE_GRE_OF_HW },
	{ NSE_GTP,		NSE_UDP_OF_HW },
	{ NSE_GTP_NO_PAY,	NSE_UDP_ILOS_HW },
	{ NSE_PPPOE,		NSE_PPPOE_HW },
	{ NSE_PFCP,		NSE_UDP_ILOS_HW },
	{ NSE_L2TPV3,		NSE_L2TPV3_HW },
	{ NSE_ESP,		NSE_ESP_HW },
	{ NSE_AH,		NSE_AH_HW },
	{ NSE_NAT_T,		NSE_UDP_ILOS_HW },
	{ NSE_VLAN_EX,		NSE_VLAN_OFOS_HW },
	{ NSE_VLAN_IN,		NSE_VLAN_OL_HW },
	{ NSE_FLG_DIR,		NSE_META_DATA_ID_HW},
};

/**
 * nse_collect_result_idx - copy result index to software lut.
 * @buf: buffer that contains the result index
 * @lut: point to global software lut struct
 */
void nse_collect_result_idx(struct nse_aqc_recipe_data_elem *buf,
				   struct nse_lut_info *lut)
{
	u8 tmp;

	if (buf->content.ctrl_flg & NSE_AQ_RECIPE_RESULT_EN) {
		tmp = buf->content.result_indx >> NSE_AQ_RECIPE_RSLT_INDX_S;
		set_bit(tmp, lut->res_idxs);
	}
}

/**
 * nse_aq_sw_feature - set/get switch feature
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_sw_feature(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_SET_FEATURE &&
	    opc != NSE_AQ_OPC_GET_FEATURE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	return status;
}

/**
 * nse_aq_sflow - add/update/remove sflow
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_sflow(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_SET_SFLOW &&
	    opc != NSE_AQ_OPC_GET_SFLOW)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);

	return status;
}

/**
 * nse_aq_meters - add/update/remove meters
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_meters(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_METER &&
	    opc != NSE_AQ_OPC_UPDATE_METER &&
	    opc != NSE_AQ_OPC_REMOVE_METER &&
	    opc != NSE_AQ_OPC_GET_METER)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_METER &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_task_lists - add/update/remove task lists
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_task_lists(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_TASK_LIST &&
	    opc != NSE_AQ_OPC_UPDATE_TASK_LIST &&
	    opc != NSE_AQ_OPC_REMOVE_TASK_LIST &&
	    opc != NSE_AQ_OPC_GET_TASK_LIST)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_TASK_LIST &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_du_datas - add/update/remove du datas
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_du_datas(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_DU_DATA &&
		opc != NSE_AQ_OPC_UPDATE_DU_DATA &&
		opc != NSE_AQ_OPC_REMOVE_DU_DATA &&
		opc != NSE_AQ_OPC_GET_DU_DATA)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_DU_DATA &&
		hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_node_states - add/update/remove node states
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_node_states(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_NODE_STATE &&
	    opc != NSE_AQ_OPC_UPDATE_NODE_STATE &&
	    opc != NSE_AQ_OPC_REMOVE_NODE_STATE &&
	    opc != NSE_AQ_OPC_GET_NODE_STATE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_NODE_STATE &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_lite_node_states - add/update/remove lite node states
 * @hw: pointer to the HW struct
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @opc: lut nodes population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 */
static enum nse_status
nse_aq_lite_node_states(struct nse_hw *hw, void *buf, u16 buf_size,
		enum nse_adminq_opc_category_switch_subcodes opc,
		struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ADD_LITE_NODE_STATE &&
	    opc != NSE_AQ_OPC_UPDATE_LITE_NODE_STATE &&
	    opc != NSE_AQ_OPC_REMOVE_LITE_NODE_STATE &&
	    opc != NSE_AQ_OPC_GET_LITE_NODE_STATE)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, opc);

	status = nse_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (opc != NSE_AQ_OPC_ADD_LITE_NODE_STATE &&
	    hw->adminq.sq_last_status == NSE_AQ_RC_ENOENT)
		status = NSE_ERR_DOES_NOT_EXIST;

	return status;
}

/**
 * nse_aq_add_recipe - add switch recipe
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_add_recipe(struct nse_hw *hw, void *buf, u16 buf_size)
{
	return nse_aq_recipes(hw, buf, buf_size, NSE_AQ_OPC_ADD_RECIPE, NULL);
}

/**
 * nse_aq_alloc_free_lpm_lut_id
 * @hw: pointer to the HW struct
 * @lut_id: VSI list ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a Lut id resource
 */
enum nse_status
nse_aq_alloc_free_lpm_lut_id(struct nse_hw *hw, u16 *lut_id,
			   enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_LUT_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		buf->res_id[0] = cpu_to_le16(*lut_id);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] start to free lpm lut, id = 0x%x\n",
			__func__, __LINE__, le16_to_cpu(buf->res_id[0]));
	}

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		buf->res_id[0] |= cpu_to_le16(NSE_AQC_RES_TYPE_PLUT_BIT);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] start to allocated lpm lut, type = 0x%x\n",
			__func__, __LINE__, le16_to_cpu(buf->res_id[0]));
	}

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_lut_id_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*lut_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] allocated lpm lut id = 0x%x\n",
			__func__, __LINE__, le16_to_cpu(buf->res_id[0]));
		if (*lut_id >= NSE_MAX_NUM_LUTS)
			status = NSE_ERR_MAX_LIMIT;
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw), "[%s, %d] Success to free lpm lut id = 0x%x\n",
			__func__, __LINE__, *lut_id);
	}
nse_aq_alloc_free_lut_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_lut_id
 * @hw: pointer to the HW struct
 * @lut_id: VSI list ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a Lut id resource
 */
static enum nse_status
nse_aq_alloc_free_lut_id(struct nse_hw *hw, u16 *lut_id,
			   enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_LUT_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		buf->res_id[0] = cpu_to_le16(*lut_id);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] start to free lut, id = 0x%x\n",
			__func__, __LINE__, le16_to_cpu(buf->res_id[0]));
	}

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		buf->res_id[0] |= cpu_to_le16(NSE_AQC_RES_TYPE_TLUT_BIT);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] start to allocated lut, type = 0x%x\n",
			__func__, __LINE__, le16_to_cpu(buf->res_id[0]));
	}

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_lut_id_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*lut_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw), "[%s, %d] allocated lut id = 0x%x\n",
			__func__, __LINE__, le16_to_cpu(buf->res_id[0]));
		if (*lut_id >= NSE_MAX_NUM_LUTS)
			status = NSE_ERR_MAX_LIMIT;
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw), "[%s, %d] Success to free lut id = 0x%x\n",
			__func__, __LINE__, *lut_id);
	}
nse_aq_alloc_free_lut_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_counter_pair
 * @hw: pointer to the HW struct
 * @counter_id1: counter ID returned or used for lookup
 * @counter_id2: counter ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a counter ID resource
 */
static enum nse_status
nse_aq_alloc_free_counter_pair(struct nse_hw *hw, u16 *counter_id1,
			   u16 *counter_id2, enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 2);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_COUNTER_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		buf->num_elems = cpu_to_le16(2);
		buf->res_id[0] = cpu_to_le16(*counter_id1);
		buf->res_id[1] = cpu_to_le16(*counter_id2);
	} else if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		buf->num_elems = cpu_to_le16(1);
		buf->res_id[0] = cpu_to_le16(2);
	}

	status = nse_aq_alloc_free_res(hw, 2, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_counter_pair_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		if (le16_to_cpu(buf->res_id[0]) == 0xFFFF)
			status = NSE_ERR_MAX_LIMIT;
		else {
			*counter_id1 = le16_to_cpu(buf->res_id[0]);
			*counter_id2 = le16_to_cpu(buf->res_id[0]) + 1;
			dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced counter_id1 = %d, counter_id2 = %d\n",
			__func__, __LINE__, *counter_id1, *counter_id2);
		}
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free counter_id1 = %d, counter_id2 = %d\n",
			__func__, __LINE__, *counter_id1, *counter_id2);
	}

nse_aq_alloc_free_counter_pair_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_node_state_id
 * @hw: pointer to the HW struct
 * @node_state_id: node state ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a Lut id resource
 */
static enum nse_status
nse_aq_alloc_free_node_state_id(struct nse_hw *hw,
			u16 *node_state_id,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_NODE_STATE_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE)
		buf->res_id[0] = cpu_to_le16(*node_state_id);

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_node_state_id_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*node_state_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced node state id = %d\n",
			__func__, __LINE__, *node_state_id);
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free node state id = %d\n",
			__func__, __LINE__, *node_state_id);
	}

nse_aq_alloc_free_node_state_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_lite_node_state
 * @hw: pointer to the HW struct
 * @node_state_id: node state ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a Lut id resource
 */
static enum nse_status
nse_aq_alloc_free_lite_node_state(struct nse_hw *hw,
			u16 *node_state_id,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_LITE_NODE_STATE);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE)
		buf->res_id[0] = cpu_to_le16(*node_state_id);

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_node_state_id_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*node_state_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced lite node state id = %d\n",
			__func__, __LINE__, *node_state_id);
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free lite node state id = %d\n",
			__func__, __LINE__, *node_state_id);
	}

nse_aq_alloc_free_node_state_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_du_data
 * @hw: pointer to the HW struct
 * @du_data: du desc set, contains several du desc info.
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a du desc set resource
 */
static enum nse_status
nse_aq_alloc_free_du_data(struct nse_hw *hw,
			struct nse_sw_du_data *du_data,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size, i;
	enum nse_status status;
	u16 cnt = du_data->du_desc_cnt;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, cnt);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(cnt);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_DU_DATA_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		for (i = 0; i < cnt; i++)
			buf->res_id[i] =
				cpu_to_le16(du_data->du_desc.du_data_id);
	} else { /*if (opc == NSE_AQ_OPC_ALLOC_RESOURCE)*/
		for (i = 0; i < cnt; i++)
			/*when request, res id is used to desc size*/
			buf->res_id[i] = cpu_to_le16(du_data->du_desc.data_size >>
						     NSE_AQC_DU_DATA_SHIFT);
	}

	status = nse_aq_alloc_free_res(hw, cnt, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_du_data_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		for (i = 0; i < cnt; i++)
			du_data->du_desc.du_data_id =
						le16_to_cpu(buf->res_id[i]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced du data id = %d, size = %d\n",
			__func__, __LINE__, du_data->du_desc.du_data_id,
			du_data->du_desc.data_size);
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free du data id = %d, size = %d\n",
			__func__, __LINE__, du_data->du_desc.du_data_id,
			du_data->du_desc.data_size);
	}

nse_aq_alloc_free_du_data_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_task_list_id
 * @hw: pointer to the HW struct
 * @task_list_id: task list ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a task list id resource
 */
static enum nse_status
nse_aq_alloc_free_task_list_id(struct nse_hw *hw,
			u16 *task_list_id,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_TASK_LIST_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE)
		buf->res_id[0] = cpu_to_le16(*task_list_id);

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_task_list_id_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*task_list_id = le16_to_cpu(buf->res_id[0]) &
						NSE_AQC_TSK_LST_ID_M;
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced task list id = %d\n",
			__func__, __LINE__, *task_list_id);
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free task list id = %d\n",
			__func__, __LINE__, *task_list_id);
	}

nse_aq_alloc_free_task_list_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_meter_id
 * @hw: pointer to the HW struct
 * @meter_id: meter ID returned or used for lookup
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a meter id resource
 */
static enum nse_status
nse_aq_alloc_free_meter_id(struct nse_hw *hw,
			u16 *meter_id,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_METER_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE)
		buf->res_id[0] = cpu_to_le16(*meter_id);

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_meter_id_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		*meter_id = le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced meter id = %d\n",
			__func__, __LINE__, *meter_id);
	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free meter id = %d\n",
			__func__, __LINE__, *meter_id);
	}

nse_aq_alloc_free_meter_id_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_encap_data
 * @hw: pointer to the HW struct
 * @du_data: du desc set, contains several du desc info.
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a du desc set resource
 */
static enum nse_status
nse_aq_alloc_free_encap_data(struct nse_hw *hw,
			struct nse_sw_encap_entry *encap_entry,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_DU_DATA_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		buf->res_id[0] =
				cpu_to_le16(encap_entry->du_desc.du_data_id);
	} else { /*if (opc == NSE_AQ_OPC_ALLOC_RESOURCE)*/
		/*when request, res id is used to desc size*/
		buf->res_id[0] = cpu_to_le16(encap_entry->du_desc.data_size >>
					     NSE_AQC_DU_DATA_SHIFT);
	}

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_encap_data_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		encap_entry->du_desc.du_data_id =
						le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced encap du data id = %d, size = %d\n",
			__func__, __LINE__, encap_entry->du_desc.du_data_id,
			encap_entry->du_desc.data_size);

	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free encap du data id = %d, size = %d\n",
			__func__, __LINE__, encap_entry->du_desc.du_data_id,
			encap_entry->du_desc.data_size);
	}

nse_aq_alloc_free_encap_data_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_alloc_free_m_encap_data
 * @hw: pointer to the HW struct
 * @du_data: du desc set, contains several du desc info.
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a du desc set resource
 */
static enum nse_status
nse_aq_alloc_free_m_encap_data(struct nse_hw *hw,
			struct nse_sw_m_encap_entry *m_encap_entry,
			enum nse_adminq_opc_category_switch_subcodes opc)
{
	struct nse_aqc_alloc_free_res_elem *buf;
	u16 buf_size;
	enum nse_status status;

	if (opc != NSE_AQ_OPC_ALLOC_RESOURCE && opc != NSE_AQ_OPC_FREE_RESOURCE)
		return NSE_ERR_PARAM;

	buf_size = struct_size(buf, res_id, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

	buf->num_elems = cpu_to_le16(1);
	buf->res_type = cpu_to_le16(NSE_AQC_RES_TYPE_DU_DATA_ID);

	if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		buf->res_id[0] =
				cpu_to_le16(m_encap_entry->du_desc.du_data_id);
	} else { /*if (opc == NSE_AQ_OPC_ALLOC_RESOURCE)*/
		/*when request, res id is used to desc size*/
		buf->res_id[0] = cpu_to_le16(m_encap_entry->du_desc.data_size >>
					     NSE_AQC_DU_DATA_SHIFT);
	}

	status = nse_aq_alloc_free_res(hw, 1, buf, buf_size, opc, NULL);
	if (status)
		goto nse_aq_alloc_free_encap_data_exit;

	if (opc == NSE_AQ_OPC_ALLOC_RESOURCE) {
		m_encap_entry->du_desc.du_data_id =
						le16_to_cpu(buf->res_id[0]);
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] alloced multi encap du data id = %d, size = %d\n",
			__func__, __LINE__, m_encap_entry->du_desc.du_data_id,
			m_encap_entry->du_desc.data_size);

	} else if (opc == NSE_AQ_OPC_FREE_RESOURCE) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Success to free multi encap du data id = %d, size = %d\n",
			__func__, __LINE__, m_encap_entry->du_desc.du_data_id,
			m_encap_entry->du_desc.data_size);
	}

nse_aq_alloc_free_encap_data_exit:
	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_aq_get_counter_val - get switch configuration
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_get_counter_val(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_GET_COUNTER);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_aq_get_pol_counter_val
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_get_pol_counter_val(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc,
		NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_GET_POLICY_COUNTER);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_aq_get_sw_cap - get switch capbility
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_get_sw_cap(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_GET_CAPBILITY);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_aq_get_res_usage - get resource usage
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 */
enum nse_status
nse_aq_get_res_usage(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_GET_RESOURCE);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

/**
 * nse_set_du_action_lan_flag - common function to set LAN flag
 *					- similar as nse_set_rinfo_action_lan
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_lan_flag(struct nse_du_action *du_action,
		u16 *act)
{
	*act |= NSE_SINGLE_FWD_LAN_DISABLE;

	if (du_action->flags_info.act_valid && !du_action->rx)
		if (du_action->flags_info.act & NSE_LAN_ENABLE)
			*act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
}

/**
 * nse_set_du_action_drop - common function to set drop
 *
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_drop(u16 *act)
{
	/* set action type to fwd */
	*act |= (NSE_SINGLE_ACT_TYPE_FWD <<
		NSE_SINGLE_ACT_TYPE_FWD_S) &
		NSE_SINGLE_ACT_TYPE_FWD_M;

	/* set fwd type to Drop */
	*act |= (NSE_SINGLE_FWD_DROP << NSE_SINGLE_FWD_TYPE_S) &
			NSE_SINGLE_FWD_TYPE_M;
}

/**
 * nse_set_du_action_count - common function to set  count
 *
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_count(struct nse_du_action *du_action,
		u16 *act, u16 *ctrl_info)
{
	/* set action type to count */
	*act |= (NSE_SINGLE_ACT_TYPE_COUNT <<
		NSE_SINGLE_ACT_TYPE_COUNT_S) &
		NSE_SINGLE_ACT_TYPE_COUNT_M;

	/* set hw count id */
	*ctrl_info |= du_action->hw_cnt_id & NSE_AQC_DU_STAT_MSB_M;
	*act |= (du_action->hw_cnt_id << NSE_SINGLE_COUNT_ID_S) &
		NSE_SINGLE_COUNT_ID_M;
}

/**
 * nse_set_du_action_meter - common function to set meter action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_meter(struct nse_du_action *du_action,
		u16 *act)
{
	/* set action type to meter */
	*act |= (NSE_SINGLE_ACT_TYPE_METER <<
		NSE_SINGLE_ACT_TYPE_METER_S) &
		NSE_SINGLE_ACT_TYPE_METER_M;

	/* set hw meter id */
	*act |= (du_action->meter_id << NSE_SINGLE_METER_ID_S) &
		NSE_SINGLE_METER_ID_M;
}

/**
 * nse_set_du_action_dup - common function to set duplicate action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_dup(struct nse_du_action *du_action,
		u16 *act)
{
	/* set action type to dup action */
	*act |= (NSE_SINGLE_ACT_TYPE_DUP <<
		NSE_SINGLE_ACT_TYPE_DUP_S) &
		NSE_SINGLE_ACT_TYPE_DUP_M;

	/*set copy num*/
	*act |= (du_action->copy_num << NSE_SINGLE_ACT_TYPE_DUP_CP_NUM_S) &
		NSE_SINGLE_ACT_TYPE_DUP_CP_NUM_M;
}

/**
 * nse_set_du_action_goto - common function to set goto chain action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_goto(struct nse_du_action *du_action,
		u16 *act)
{
	/* set action type to goto action */
	*act |= (NSE_SINGLE_ACT_TYPE_GOTO <<
		NSE_SINGLE_ACT_TYPE_GOTO_S) &
		NSE_SINGLE_ACT_TYPE_GOTO_M;

	/*set dest chain id*/
	*act |= (du_action->dest_chain << NSE_SINGLE_ACT_TYPE_GOTO_CHAIN_ID_S) &
		NSE_SINGLE_ACT_TYPE_GOTO_CHAIN_ID_M;
}

/**
 * nse_set_du_action_sflow - common function to set sflow action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_sflow(struct nse_du_action *du_action,
		u16 *act)
{
	/* set action type to sflow action */
	*act |= (NSE_SINGLE_ACT_TYPE_SFLOW <<
		NSE_SINGLE_ACT_TYPE_SFLOW_S) &
		NSE_SINGLE_ACT_TYPE_SFLOW_M;

	/*set sflow dest vsi id*/
	*act |= (du_action->sflow_vsi_id << NSE_SINGLE_ACT_TYPE_SFLOW_VSI_ID_S) &
		NSE_SINGLE_ACT_TYPE_SFLOW_VSI_ID_M;
}

/**
 * nse_set_du_action_decap - common function to set decap action
 *
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_decap(u16 *act)
{
	/* set action type to decap action */
	*act |= (NSE_SINGLE_ACT_TYPE_DECAP <<
		NSE_SINGLE_ACT_TYPE_DECAP_S) &
		NSE_SINGLE_ACT_TYPE_DECAP_M;

	/*set inherit bit*/
	*act |= NSE_SINGLE_ACT_TYPE_DECAP_ECN |
			NSE_SINGLE_ACT_TYPE_DECAP_DSCP;
}

/**
 * nse_set_du_action_tolan - common function to set toLAN action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_tolan(struct nse_du_action *du_action,
		u16 *act)
{
	if (du_action->flags_info.act & NSE_LB_ENABLE)
		*act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;
	else
		*act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

	/*set LAN flag*/
	nse_set_du_action_lan_flag(du_action, act);
}

/**
 * nse_set_du_action_tovsi - common function to set toVSI action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_tovsi(struct nse_du_action *du_action,
		u16 *act)
{
	*act |= (du_action->fwd_id.hw_vsi_id << NSE_SINGLE_FWD_VSI_ID_S) &
		NSE_SINGLE_FWD_VSI_ID_M;

	/* set action type to fwd */
	*act |= (NSE_SINGLE_ACT_TYPE_FWD <<
		NSE_SINGLE_ACT_TYPE_FWD_S) &
		NSE_SINGLE_ACT_TYPE_FWD_M;

	if (du_action->flags_info.act & NSE_LB_ENABLE)
		*act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;
	else
		*act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

	/*set LAN flag*/
	nse_set_du_action_lan_flag(du_action, act);
}

/**
 * nse_set_du_action_tovlist - common function to set toVSI List action
 *
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
static void
nse_set_du_action_tovlist(struct nse_du_action *du_action,
		u16 *act)
{
	*act |= (du_action->fwd_id.vsi_list_id  << NSE_SINGLE_FWD_VSI_LIST_ID_S) &
		NSE_SINGLE_FWD_VSI_LIST_ID_M;

	/* set action type to fwd */
	*act |= (NSE_SINGLE_ACT_TYPE_FWD <<
		NSE_SINGLE_ACT_TYPE_FWD_S) &
		NSE_SINGLE_ACT_TYPE_FWD_M;

	if (du_action->flags_info.act & NSE_LB_ENABLE)
		*act |= (NSE_SINGLE_FWD_VSI_LIST_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;
	else
		*act |= (NSE_SINGLE_FWD_VSI_LIST_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

	/*set LAN flag*/
	nse_set_du_action_lan_flag(du_action, act);
}

void nse_dump_all_profiles(struct nse_hw *hw)
{
	struct nse_fv *fv;
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	u16 offset, i;

	sw = hw->switch_info;

	dev_info(nse_hw_to_dev(hw), "profiles max used index = %d\n",
			sw->max_used_prof_index);
	dev_info(nse_hw_to_dev(hw), "profiles max number = %d\n",
		sw->max_used_prof_index + 1);

	for (offset = 0; offset < sw->max_used_prof_index + 1; offset++) {
		profile = &sw->profile_list[offset];
		dev_info(nse_hw_to_dev(hw),
			"profile[%d]: fec num = %d, local rcp = %d, total rcp = %d, used rcp = %d, chain_id = %d, enabled = %d\n",
			profile->profile_id, profile->fe_num,
				profile->local_rcp, profile->total_recipe_num,
			profile->used_recipe_num, profile->chain_id, profile->en);

		dev_info(nse_hw_to_dev(hw),
			"profile[%d]'s available result idx:", profile->profile_id);

		print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
			16, 1, sw->prof_res_bm[profile->profile_id],
				BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

		print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
			16, 1, sw->prof_res_bm[profile->profile_id],
				BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

		dev_info(nse_hw_to_dev(hw),
			"profile[%d]'s associated lut_bitmap:", profile->profile_id);

		print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
			16, 1, profile->lut_bitmap,
				BITS_TO_LONGS(NSE_MAX_NUM_LUTS) * sizeof(long), false);

		print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
			16, 1, profile->lut_bitmap,
				BITS_TO_LONGS(NSE_MAX_NUM_LUTS) * sizeof(long), false);

		fv = &profile->fv_ptr;
		for (i = 0; i < profile->fe_num; i++) {
			if (fv->ew[i].enable)
				dev_info(nse_hw_to_dev(hw),
					"\t fec[%d]: en = %d, off = %d, prot_id = %d\n",
					i, fv->ew[i].enable, fv->ew[i].off, fv->ew[i].prot_id);
		}
	}
}

void nse_del_all_adv_rcp_per_profile(struct nse_hw *hw)
{
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	struct nse_aqc_recipe_cfg *buf;
	struct nse_aqc_recipe_data_elem *rcp_elems;
	u16 offset, buf_size;
	enum nse_status nse_status = NSE_SUCCESS;

	if (nse_bypass_switch)
		return;

	sw = hw->switch_info;

	for (offset = 0; offset < sw->max_used_prof_index + 1; offset++) {
		u8 del_recps = 0, lut_id, recp_id;
		int i;

		profile = &sw->profile_list[offset];

		if (profile->used_recipe_num <= profile->local_rcp)
			continue;

		del_recps = profile->used_recipe_num - profile->local_rcp;

		buf_size = struct_size(buf, elem, del_recps);
		buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
		if (!buf) {
			dev_err(nse_hw_to_dev(hw), "failed to devm_kzalloc for nse_aqc_recipe_cfg\n");
			return;
		}

		buf->count = cpu_to_le16(del_recps);
		rcp_elems = buf->elem;

	dev_info(nse_hw_to_dev(hw),
		"Start to remove %d recipes in Profile[%d]\n",
		del_recps, profile->profile_id);

		for (i = 0; i < del_recps; i++) {
			recp_id = profile->used_recipe_num - i - 1;
			lut_id = profile->lut_id[recp_id];
			rcp_elems[i].profile_id = cpu_to_le16(profile->profile_id);
			rcp_elems[i].recipe_id = recp_id;
			rcp_elems[i].content.lut_id = cpu_to_le16(lut_id);
		dev_info(nse_hw_to_dev(hw),
			"\tRemoved recipe id = %d in Profile[%d], and lut_id = %d\n",
			 recp_id, profile->profile_id, lut_id);
		}

		/*del recipes to HW*/
		nse_status = nse_aq_recipes(hw, buf, buf_size, NSE_AQ_OPC_REMOVE_RECIPE, NULL);
		if (nse_status)
			dev_err(nse_hw_to_dev(hw),
				"Failed to remove %d recipes in Profile[%d], err = %d\n",
				del_recps, profile->profile_id, nse_status);

		devm_kfree(nse_hw_to_dev(hw), buf);

		for (i = 0; i < del_recps; i++) {
			recp_id = profile->used_recipe_num - i - 1;
			lut_id = profile->lut_id[recp_id];
			clear_bit(lut_id, profile->lut_bitmap);
			profile->lut_id[recp_id] = 0;
		}
		profile->used_recipe_num -= del_recps;
	}
}

void nse_dump_all_adv_luts(struct nse_hw *hw)
{
	struct nse_lut_info *lut;
	u16 i, j;

	lut = hw->switch_info->lut_list;

	for (i = 0; i < NSE_MAX_NUM_LUTS; i++) {
		if (!lut[i].lut_created)
			continue;

		dev_info(nse_hw_to_dev(hw),
			"adv lut[%d]: lut_id = 0x%x, is_root = %d, is_lpm = %d, tunnel_type = %d\n",
			i, lut[i].lut_id, lut[i].is_root, lut[i].is_lpm, lut[i].tun_type);

		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: chain_id = %d\n", i, lut[i].chain_id);
		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: hw_prio = %d, sw_prio = %d, has_rule = %d\n",
						i, lut[i].hw_prio, lut[i].priority,
							lut[i].adv_rule);
		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: rslt_idx_en = %d, result_index = %d\n",
						i, !!(lut[i].result_index != NSE_INVALID_RSLT_IDX),
						lut[i].result_index);

		dev_info(nse_hw_to_dev(hw),
			"adv lut[%d]'s used_rst_idx:", i);

		print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
			16, 1, lut[i].res_idxs,
				BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

		print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
			16, 1, lut[i].res_idxs,
				BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: is_chained = %d, rcps num = %d\n",
						i, lut[i].big_lut, lut[i].n_grp_count);

		dev_info(nse_hw_to_dev(hw), "\t fv word cfg(exclude rslt_idx&sw_id): fv num = %d\n",
				lut[i].n_ext_words);
		dev_info(nse_hw_to_dev(hw), "\t\t fv word[1]: en = %d, prot_id = %d, off = %d\n",
				lut[i].ext_words[0].enable,	lut[i].ext_words[0].prot_id,
					lut[i].ext_words[0].off);
		dev_info(nse_hw_to_dev(hw), "\t\t fv word[2]: en = %d, prot_id = %d, off = %d\n",
				lut[i].ext_words[1].enable,	lut[i].ext_words[1].prot_id,
					lut[i].ext_words[1].off);
		dev_info(nse_hw_to_dev(hw), "\t\t fv word[3]: en = %d, prot_id = %d, off = %d\n",
				lut[i].ext_words[2].enable,	lut[i].ext_words[2].prot_id,
					lut[i].ext_words[2].off);
		dev_info(nse_hw_to_dev(hw), "\t\t fv word[4]: en = %d, prot_id = %d, off = %d\n",
				lut[i].ext_words[3].enable,	lut[i].ext_words[3].prot_id,
					lut[i].ext_words[3].off);

		if (lut[i].is_root) {
			struct nse_lut_grp_entry *lut_entry;

			j = 0;

			list_for_each_entry(lut_entry, &lut[i].lut_group_list, l_entry) {
				dev_info(nse_hw_to_dev(hw), "\t sub rcp[%d]: lut id = %d\n",
							j, lut_entry->lut_id);
				j++;
			}

			dev_info(nse_hw_to_dev(hw), "Start to dump root rcp's user lkups\n");

			for (j = 0; j < lut[i].lkup_exts.n_val_words; j++)
				dev_info(nse_hw_to_dev(hw),
					"\t user lkups[%d]: en = %d, prot_id = %d, off = %d, fv mask = 0x%x\n",
					j, lut[i].lkup_exts.fv_words[j].enable,
						lut[i].lkup_exts.fv_words[j].prot_id,
					lut[i].lkup_exts.fv_words[j].off,
						lut[i].lkup_exts.field_mask[j]);
		}
	}
}

void nse_dump_root_adv_luts(struct nse_hw *hw)
{
	struct nse_lut_info *lut;
	u16 i, j;

	lut = hw->switch_info->lut_list;

	for (i = 0; i < NSE_MAX_NUM_LUTS; i++) {
		if (!lut[i].lut_created || !lut[i].is_root)
			continue;

		dev_info(nse_hw_to_dev(hw),
			"adv lut[%d]: lut_id = 0x%x, is_root = %d, is_lpm = %d, tunnel_type = %d\n",
			i, lut[i].lut_id, lut[i].is_root, lut[i].is_lpm, lut[i].tun_type);

		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: chain_id = %d\n", i, lut[i].chain_id);
		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: hw_prio = %d, sw_prio = %d, has_rule = %d\n",
						i, lut[i].hw_prio, lut[i].priority,
							lut[i].adv_rule);
		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: rslt_idx_en = %d, result_index = %d\n",
						i, !!(lut[i].result_index != NSE_INVALID_RSLT_IDX),
						lut[i].result_index);

		dev_info(nse_hw_to_dev(hw), "adv lut[%d]: is_chained = %d, rcps num = %d\n",
						i, lut[i].big_lut, lut[i].n_grp_count);

		dev_info(nse_hw_to_dev(hw),
			"adv lut[%d]'s used_rst_idx:", i);

		print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
			16, 1, lut[i].res_idxs,
				BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

		print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
			16, 1, lut[i].res_idxs,
				BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

		if (lut[i].is_root) {
			struct nse_lut_grp_entry *lut_entry;

			j = 0;

			list_for_each_entry(lut_entry, &lut[i].lut_group_list, l_entry) {
				dev_info(nse_hw_to_dev(hw), "\t sub rcp[%d]: lut id = %d\n",
							j, lut_entry->lut_id);
				j++;
			}

			dev_info(nse_hw_to_dev(hw), "Start to dump root rcp's user lkups\n");

			for (j = 0; j < lut[i].lkup_exts.n_val_words; j++)
				dev_info(nse_hw_to_dev(hw),
					"\t user lkups[%d]: en = %d, prot_id = %d, off = %d, fv mask = 0x%x\n",
					j, lut[i].lkup_exts.fv_words[j].enable,
						lut[i].lkup_exts.fv_words[j].prot_id,
					lut[i].lkup_exts.fv_words[j].off,
						lut[i].lkup_exts.field_mask[j]);
		}
	}
}

void nse_del_all_adv_luts(struct nse_hw *hw)
{
	struct nse_lut_info *lut;
	enum nse_status status = NSE_SUCCESS;
	struct nse_adv_fltr_mgmt_list_entry *tmp_entry;
	struct nse_adv_fltr_mgmt_list_entry *lst_itr;
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	struct nse_lut_grp_entry *lut_entry, *lut_tmp;
	struct nse_sw_fv_list_entry *fv_entry, *fv_tmp;

	int i;
	u16 j, buf_size;

	if (nse_bypass_switch)
		return;

	lut = hw->switch_info->lut_list;

	for (i = NSE_MAX_NUM_LUTS; i > 0; i--) {
		if (!lut[i].lut_created || lut[i].is_lpm)
			continue;

		dev_info(nse_hw_to_dev(hw),
			"start to free lut id[%d]'s nodes\n", lut[i].lut_id);

		if (lut[i].adv_rule) {
			mutex_destroy(&lut[i].filt_rule_lock);

			list_for_each_entry_safe(lst_itr, tmp_entry,
						 &lut[i].filt_rules, list_entry) {
				j = 0;
				list_for_each_entry(lut_entry,
								&lut[i].lut_group_list, l_entry) {
					buf_size = struct_size(buf, elem, 1);
					buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
					if (!buf) {
						dev_err(nse_hw_to_dev(hw),
							"failed to devm_kzalloc for nse_aqc_lut_nodes\n");
						return;
					}

					buf->count = cpu_to_le16(1);
					lut_node = buf->elem;

					lut_node->lut_id = cpu_to_le16(lut_entry->lut_id);
					lut_node->node_id =
						cpu_to_le16(lst_itr->node_info.sub_fltr_node_id[j]);

					dev_info(nse_hw_to_dev(hw),
						"Start to remove lut[%d] node[%d]\n",
						lut_entry->lut_id,
						lst_itr->node_info.sub_fltr_node_id[j]);

					status = nse_aq_lut_nodes(hw, buf, buf_size,
								 NSE_AQ_OPC_REMOVE_LUT_NODE, NULL);

					if (status && status != NSE_ERR_DOES_NOT_EXIST) {
						dev_err(nse_hw_to_dev(hw),
							"failed to remove lut[%d] node[%d]\n",
							lut_entry->lut_id,
							lst_itr->node_info.sub_fltr_node_id[j]);
					}
					j++;
					devm_kfree(nse_hw_to_dev(hw), buf);
				}

				list_del(&lst_itr->list_entry);
				devm_kfree(nse_hw_to_dev(hw), lst_itr->lkups);
				devm_kfree(nse_hw_to_dev(hw), lst_itr);
			}
		} else
			dev_info(nse_hw_to_dev(hw),
				"Lut[%d] is a NULL Lkup Table\n", lut[i].lut_id);

		dev_info(nse_hw_to_dev(hw),
			"start to free lut id[%d]\n", lut[i].lut_id);

		status = nse_aq_alloc_free_lut_id(hw,
				&lut[i].lut_id, NSE_AQ_OPC_FREE_RESOURCE);
		if (status)
			dev_err(nse_hw_to_dev(hw),
				"Failed to free lut id[%d], err = %d\n",
				lut[i].lut_id, status);

		/*reinit software bookkeeping of lut information*/
		list_for_each_entry_safe(lut_entry, lut_tmp,
			&lut[i].lut_group_list, l_entry) {
			list_del(&lut_entry->l_entry);
			devm_kfree(nse_hw_to_dev(hw), lut_entry);
		}

		list_for_each_entry_safe(fv_entry, fv_tmp,
			&lut[i].fv_list, list_entry) {
			list_del(&fv_entry->list_entry);
			devm_kfree(nse_hw_to_dev(hw), fv_entry);
		}

		memset(&lut[i], 0, sizeof(struct nse_lut_info));
		lut[i].lut_id = i;
		INIT_LIST_HEAD(&lut[i].filt_rules);
		INIT_LIST_HEAD(&lut[i].filt_replay_rules);
		INIT_LIST_HEAD(&lut[i].fv_list);
		INIT_LIST_HEAD(&lut[i].lut_group_list);
		mutex_init(&lut[i].filt_rule_lock);
	}
}

void nse_dump_adv_lut_nodes(struct nse_hw *hw, u8 lut_id)
{
	struct nse_switch_info *sw;
	struct nse_adv_fltr_mgmt_list_entry *adv_fltr = NULL;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	u16 j, i = 0;

	sw = hw->switch_info;
	rule_lock = &sw->lut_list[lut_id].filt_rule_lock;

	if (!sw->lut_list[lut_id].adv_rule) {
		dev_info(nse_hw_to_dev(hw), "Lut[%d] is a NULL Lkup Table\n", lut_id);
		return;
	}

	if (sw->lut_list[lut_id].is_lpm) {
		dev_info(nse_hw_to_dev(hw), "Lut[%d] is a lpm Table\n", lut_id);
		return;
	}

	mutex_lock(rule_lock);

	list_for_each_entry(adv_fltr, &sw->lut_list[lut_id].filt_rules,
			    list_entry) {
		dev_info(nse_hw_to_dev(hw), "Lut[%d] - Entry[%d]:\n", lut_id, i);
		if (adv_fltr->node_info.sw_act.fltr_act == NSE_FWD_TO_VSI) {
			dev_info(nse_hw_to_dev(hw), "It is to Single VSI: %d\n",
				adv_fltr->node_info.sw_act.fwd_id.vsi_id);
		} else if (adv_fltr->node_info.sw_act.fltr_act == NSE_LARGE_ACT) {
			dev_info(nse_hw_to_dev(hw), "It is a Large Action: node state id = %d\n",
				adv_fltr->node_info.sw_act.large_act_id);
		} else if (adv_fltr->node_info.sw_act.fltr_act == NSE_FWD_TO_VSI_LIST) {
			dev_info(nse_hw_to_dev(hw), "It is to VSI List: %d\n",
				adv_fltr->node_info.sw_act.fwd_id.vsi_list_id);
		}
		dev_info(nse_hw_to_dev(hw),
					"is_lpm = %d, prefix_len = %d, rx = %d, lb_en = %d, lan_en = %d\n",
					adv_fltr->node_info.is_lpm, adv_fltr->node_info.prefix_len,
					adv_fltr->node_info.rx,
					!!(adv_fltr->node_info.flags_info.act & NSE_LB_ENABLE),
					!!(adv_fltr->node_info.flags_info.act & NSE_LAN_ENABLE));
		dev_info(nse_hw_to_dev(hw), "tun_type = %d, act_type = %d, fwd_id = 0x%x, lg_act_id = 0x%x\n",
					adv_fltr->node_info.tun_type,
						adv_fltr->node_info.sw_act.fltr_act,
					adv_fltr->node_info.sw_act.fwd_id.vsi_id,
						adv_fltr->node_info.sw_act.large_act_id);
		dev_info(nse_hw_to_dev(hw), "root_node_id = 0x%x\n",
					adv_fltr->node_info.fltr_node_id);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[0] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[0]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[1] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[1]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[2] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[2]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[3] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[3]);
		dev_info(nse_hw_to_dev(hw), "sub_node_id[4] = 0x%x\n",
			 adv_fltr->node_info.sub_fltr_node_id[4]);

		dev_info(nse_hw_to_dev(hw), "\t user match protocol header cnt = %d\n",
					adv_fltr->lkups_cnt);
		for (j = 0; j < adv_fltr->lkups_cnt; j++) {
			dev_info(nse_hw_to_dev(hw), "\t lkups[%d]: prot hdr type= %d\n",
				j, adv_fltr->lkups[j].type);

			if (adv_fltr->lkups[j].type == NSE_MAC_OFOS
				|| adv_fltr->lkups[j].type == NSE_MAC_IL) {
				dev_info(nse_hw_to_dev(hw), "\t DMac Address Value = %pM\n",
					adv_fltr->lkups[j].h_u.eth_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t SMac Address Value = %pM\n",
					adv_fltr->lkups[j].h_u.eth_hdr.src_addr);
				dev_info(nse_hw_to_dev(hw), "\t DMac Address Mask = %pM\n",
					adv_fltr->lkups[j].m_u.eth_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t SMac Address Mask = %pM\n",
					adv_fltr->lkups[j].m_u.eth_hdr.src_addr);
			} else if (adv_fltr->lkups[j].type == NSE_IPV4_OFOS
					|| adv_fltr->lkups[j].type == NSE_IPV4_IL) {
				dev_info(nse_hw_to_dev(hw), "\t IPV4 DIP Value = %pI4\n",
					&adv_fltr->lkups[j].h_u.ipv4_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV4 SIP Value = %pI4\n",
					&adv_fltr->lkups[j].h_u.ipv4_hdr.src_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV4 DIP Mask = %pI4\n",
					&adv_fltr->lkups[j].m_u.ipv4_hdr.dst_addr);
				dev_info(nse_hw_to_dev(hw), "\t IPV4 SIP Mask = %pI4\n",
					&adv_fltr->lkups[j].m_u.ipv4_hdr.src_addr);
			} else
				dev_info(nse_hw_to_dev(hw),
						"\t Not Supported to parse the key values\n");
		}

		i++;
	}

	mutex_unlock(rule_lock);
}

/**
 * nse_init_prof_result_bm - Initialize the profile result index bitmap
 * @hw: pointer to hardware structure
 */
void nse_init_prof_result_bm(struct nse_hw *hw)
{
	struct nse_fv *fv;
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	u16 offset;

	sw = hw->switch_info;

	for (offset = 0; offset < sw->max_used_prof_index + 1; offset++) {
		u16 i;

		profile = &sw->profile_list[offset];
		fv = &profile->fv_ptr;
		bitmap_zero(sw->prof_res_bm[offset],
			NSE_MAX_FV_WORDS);

		/* Determine empty field vector indices of this profile,
		 * which can be used for intermediate recipe's result index.
		 */
		for (i = 0; i < NSE_MAX_FV_WORDS; i++) {
			if (fv->ew[i].enable == NSE_FV_DISABLE)
				set_bit(i, sw->prof_res_bm[offset]);
		}

		/* one fv word is reserved by fw, let's clear it and don't use */
		clear_bit(NSE_FW_RSV_FV_WORD_OFF, sw->prof_res_bm[offset]);
	}
}

/**
 * nse_prot_type_to_id - get protocol ID from protocol type
 * @type: protocol type
 * @id: pointer to variable that will receive the ID
 *
 * Returns true if found, false otherwise
 */
static bool nse_prot_type_to_id(enum nse_protocol_type type, u8 *id)
{
	u8 i;

	for (i = 0; i < ARRAY_SIZE(nse_prot_id_tbl); i++)
		if (nse_prot_id_tbl[i].type == type) {
			*id = nse_prot_id_tbl[i].protocol_id;
			return true;
		}
	return false;
}

/**
 * nse_fill_valid_words - count valid words
 * @lkups: advanced lkup element with one lookup Protocol ID Header,
 *			if one match has many Protocol Headers, input one by one
 * @lkup_exts: input repeated. fv words format of one match,
 *                  this match may contain many lkup elem
 */
u8
nse_fill_valid_words(struct nse_adv_lkup_elem *lkup_elem,
		     struct nse_prot_lkup_ext *lkup_exts)
{
	u8 j, word, prot_id, ret_val;

	if (!nse_prot_type_to_id(lkup_elem->type, &prot_id))
		return 0;

	/*n_val_words is additive*/
	word = lkup_exts->n_val_words;

	for (j = 0; j < sizeof(lkup_elem->m_u) / sizeof(u16); j++)
		if (((u16 *)&lkup_elem->m_u)[j] &&
		    lkup_elem->type < ARRAY_SIZE(nse_prot_ext)) {
			/* No more space to accommodate */
			if (word >= NSE_MAX_CHAIN_LKUP_WORDS)
				return 0;

			lkup_exts->fv_words[word].off =
				nse_prot_ext[lkup_elem->type].offs[j];
			lkup_exts->fv_words[word].prot_id =
				nse_prot_id_tbl[lkup_elem->type].protocol_id;
			lkup_exts->field_mask[word] =
				be16_to_cpu(((__force __be16 *)&lkup_elem->m_u)[j]);
			word++;
		}

	ret_val = word - lkup_exts->n_val_words;
	lkup_exts->n_val_words = word;

	return ret_val;
}

/**
 * nse_get_sw_prof_type - determine switch profile type
 * @hw: pointer to the HW structure
 * @fv: pointer to the switch field vector
 */
static enum nse_prof_type
nse_get_sw_prof_type(struct nse_hw *hw, struct nse_fv *fv)
{
	u16 i;

	for (i = 0; i < NSE_MAX_FV_WORDS; i++) {
		/* UDP tunnel will have UDP_OF protocol ID and VNI offset */
		if (fv->ew[i].prot_id == (u8)NSE_PROT_UDP_OF &&
		    fv->ew[i].off == NSE_VNI_OFFSET)
			return NSE_PROF_TUN_UDP;

		/* GRE tunnel will have GRE protocol */
		if (fv->ew[i].prot_id == (u8)NSE_PROT_GRE_OF)
			return NSE_PROF_TUN_GRE;
	}

	return NSE_PROF_NON_TUN;
}

/**
 * nse_get_sw_fv_bitmap - Get switch profile bitmap based on profile type
 * @hw: pointer to hardware structure
 * @req_profs: type of profiles requested
 * @bm: pointer to memory for returning the bitmap of profiles
 */
void
nse_get_sw_fv_bitmap(struct nse_hw *hw, enum nse_prof_type req_profs,
		     struct nse_adv_node_info *rinfo, unsigned long *bm)
{
	struct nse_fv *fv;
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	u16 offset;

	if (req_profs == NSE_PROF_ALL) {
		bitmap_set(bm, 0, NSE_MAX_NUM_PROFILES);
		return;
	}

	bitmap_zero(bm, NSE_MAX_NUM_PROFILES);
	sw = hw->switch_info;

	for (offset = 0; offset < sw->max_used_prof_index + 1; offset++) {
		enum nse_prof_type prof_type;

		profile = &sw->profile_list[offset];

		if (!profile->en)
			continue;

		if (rinfo->chain_id != profile->chain_id)
			continue;

		if (nse_tcam_less) {
			/* in tcam less mode, profiles in one chain are all in a big group */
			set_bit(offset, bm);
			dev_info(nse_hw_to_dev(hw),
				"Request profile type %d, in tcam_less mode we get every profile, cur_id = %d\n",
				req_profs, offset);
		} else {
			fv = &profile->fv_ptr;
			if (fv) {
				/* Determine profile type */
				prof_type = nse_get_sw_prof_type(hw, fv);

				if (req_profs & prof_type) {
					set_bit(offset, bm);
					dev_info(nse_hw_to_dev(hw), "Request tunnel type is %d, get profile[%d]\n",
						req_profs, offset);
				}
			}
		}
	}
}

/* nse_get_compat_fv_bitmap - Get compatible field vector bitmap for rule
 * @hw: pointer to hardware structure
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @bm: pointer to memory for returning the bitmap of profiles
 */
void
nse_get_compat_fv_bitmap(struct nse_hw *hw, struct nse_adv_node_info *rinfo,
			 unsigned long *bm)
{
	enum nse_prof_type prof_type;

	bitmap_zero(bm, NSE_MAX_NUM_PROFILES);

	switch (rinfo->tun_type) {
	case NSE_NON_TUN:
		prof_type = NSE_PROF_NON_TUN;
		break;

	case NSE_ALL_TUNNELS:
		prof_type = NSE_PROF_TUN_ALL;
		break;

	case NSE_SW_TUN_VXLAN_GPE:
	case NSE_SW_TUN_GENEVE:
	case NSE_SW_TUN_GENEVE_VLAN:
	case NSE_SW_TUN_VXLAN:
	case NSE_SW_TUN_VXLAN_VLAN:
	case NSE_SW_TUN_UDP:
		prof_type = NSE_PROF_TUN_UDP;
		break;

	/* Support for GTP tunnel + L3 */
	case NSE_SW_TUN_IPV4_GTPU_IPV4:
	case NSE_SW_TUN_IPV4_GTPU_IPV6:
	case NSE_SW_TUN_IPV6_GTPU_IPV4:
	case NSE_SW_TUN_IPV6_GTPU_IPV6:
	/* Support for GTP tunnel + L3 + L4 */
	case NSE_SW_TUN_IPV4_GTP_IPV4_UDP:
	case NSE_SW_TUN_IPV4_GTP_IPV6_TCP:
	case NSE_SW_TUN_IPV4_GTP_IPV6_UDP:
	case NSE_SW_TUN_IPV6_GTP_IPV4_TCP:
	case NSE_SW_TUN_IPV6_GTP_IPV4_UDP:
	case NSE_SW_TUN_IPV6_GTP_IPV6_TCP:
	case NSE_SW_TUN_IPV6_GTP_IPV6_UDP:
	case NSE_SW_TUN_GTP_IPV4:
	case NSE_SW_TUN_GTP_IPV6:
	case NSE_SW_TUN_GTP_IPV4_TCP:
	case NSE_SW_TUN_GTP_IPV4_UDP:
	case NSE_SW_TUN_GTP_IPV6_TCP:
	case NSE_SW_TUN_GTP_IPV6_UDP:
		prof_type = NSE_PROF_TUN_UDP;
		break;

	case NSE_SW_TUN_NVGRE:
		prof_type = NSE_PROF_TUN_GRE;
		break;

	case NSE_SW_TUN_AND_NON_TUN:
	default:
		prof_type = NSE_PROF_ALL;
		break;
	}

	nse_get_sw_fv_bitmap(hw, prof_type, rinfo, bm);
}

/**
 * nse_get_fv - get field vectors/extraction sequences for spec. lookup types
 * @hw: pointer to hardware structure
 * @lkup_exts: fv word format of lookups for the advanced recipe
 * @bm: bitmap of field vectors to consider
 * @fv_list: pointer to a list that holds the returned field vectors
 *
 * NOTE:
 *	The caller of the function is responsible for freeing the memory
 *	allocated for every list entry.
 */
int
nse_get_fv(struct nse_hw *hw, struct nse_prot_lkup_ext *lkup_exts,
	   unsigned long *bm, struct list_head *fv_list)
{
	struct nse_sw_fv_list_entry *fv_entry;
	struct nse_sw_fv_list_entry *tmp;
	struct nse_fv *fv;
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	u16 offset;

	if (!lkup_exts->n_val_words)
		return -EINVAL;

	sw = hw->switch_info;

	for (offset = 0; offset < sw->max_used_prof_index + 1; offset++) {
		u16 i;

		profile = &sw->profile_list[offset];
		fv = &profile->fv_ptr;

		if (!fv)
			break;

		if (!test_bit(offset, bm))
			continue;

		for (i = 0; i < lkup_exts->n_val_words; i++) {
			int j;

			dev_info(nse_hw_to_dev(hw),
				"Searching in Profile[%d], User match fv word[%d]: prot_id = %d, off = %d\n",
				offset, i, lkup_exts->fv_words[i].prot_id,
					lkup_exts->fv_words[i].off);
			for (j = 0; j < NSE_MAX_FV_WORDS; j++) {
				/*check whether is there any field vector config of current profile
				 * can match current lookup word.
				 */
				if (fv->ew[j].enable == NSE_FV_ENABLE &&
					fv->ew[j].prot_id ==
					lkup_exts->fv_words[i].prot_id &&
					fv->ew[j].off == lkup_exts->fv_words[i].off)
					break;
			}

			if (j >= NSE_MAX_FV_WORDS)
				break;

			/*if current profile's fv config can match all lookup word,
			 * profile info is allocated, and added into fv list.
			 */
			if (i + 1 == lkup_exts->n_val_words) {
				fv_entry = devm_kzalloc(nse_hw_to_dev(hw),
						   sizeof(*fv_entry), GFP_KERNEL);
				if (!fv_entry)
					goto err;

				dev_info(nse_hw_to_dev(hw),
					"Congratulation! Profile[%d] can match user's all lookup words\n",
					offset);

				fv_entry->fv_ptr = fv;
				fv_entry->profile_id = offset;
				list_add_tail(&fv_entry->list_entry, fv_list);
				break;
			}
		}
	}

	if (list_empty(fv_list)) {
		dev_warn(nse_hw_to_dev(hw), "Required profiles are not found\n");
		return -EIO;
	}

	return 0;

err:
	list_for_each_entry_safe(fv_entry, tmp, fv_list, list_entry) {
		list_del(&fv_entry->list_entry);
		devm_kfree(nse_hw_to_dev(hw), fv_entry);
	}

	return -ENOMEM;
}

/**
 * nse_create_first_fit_lut_def - Create a lut/recipe grouping
 * @hw: pointer to the hardware structure
 * @lkup_exts: an array of protocol header extractions
 * @rg_list: pointer to a list that stores new recipe groups
 * @recp_cnt: pointer to a variable that stores returned number of recipe groups
 *
 * Using exact match algorithm, take all the words that are still not done,
 * and start grouping them in 4-word groups.
 * Each group makes up one recipe template(lut)
 */
static int
nse_create_first_fit_lut_def(struct nse_hw *hw,
			      struct nse_prot_lkup_ext *lkup_exts,
			      struct list_head *lut_group_list,
			      u8 *lut_cnt)
{
	struct nse_pref_lut_group *grp = NULL;
	u8 j;

	*lut_cnt = 0;

	/* Iterate every word in the lkups to check whether it is not done.
	 *  If yes then this word needs to be part of a new recipe.
	 */
	for (j = 0; j < lkup_exts->n_val_words; j++)
		if (!test_bit(j, lkup_exts->done)) {
			if (!grp ||
			    grp->n_val_pairs == NSE_NUM_WORDS_RECIPE) {
				struct nse_lut_grp_entry *entry;

				entry = devm_kzalloc(nse_hw_to_dev(hw),
						     sizeof(*entry),
						     GFP_KERNEL);
				if (!entry)
					return -ENOMEM;

				list_add_tail(&entry->l_entry, lut_group_list);
				grp = &entry->lut_group;
				grp->n_val_pairs = 0;
				(*lut_cnt)++;
			}

			grp->pairs[grp->n_val_pairs].prot_id =
				lkup_exts->fv_words[j].prot_id;
			grp->pairs[grp->n_val_pairs].off =
				lkup_exts->fv_words[j].off;
			grp->mask[grp->n_val_pairs] = lkup_exts->field_mask[j];
			grp->n_val_pairs++;
		}

	return 0;
}

/**
 * nse_create_lut_group - creates lut/recipe group
 * @hw: pointer to hardware structure
 * @rm: recipe management list entry
 * @lkup_exts: lookup elements
 */
static int
nse_create_lut_group(struct nse_hw *hw, struct nse_lut_info *lut_info,
			struct nse_prot_lkup_ext *lkup_exts)
{
	u8 lut_count = 0;
	int status;

	lut_info->n_grp_count = 0;

	status = nse_create_first_fit_lut_def(hw, lkup_exts,
					       &lut_info->lut_group_list, &lut_count);
	if (!status) {
		lut_info->n_grp_count += lut_count;
		lut_info->n_ext_words = lkup_exts->n_val_words;
		memcpy(lut_info->ext_words, lkup_exts->fv_words,
			   sizeof(lut_info->ext_words));
		memcpy(lut_info->word_masks, lkup_exts->field_mask,
		       sizeof(lut_info->word_masks));
	}

	return status;
}

/**
 * nse_fill_fv_word_index - fill the field vector indices for a lut group
 * @hw: pointer to the hardware structure
 * @fv_list: profiles with fv config that can match current lkups
 * @lut_group_list: lut groupings with protocol-offset pairs
 *
 * Helper function to fill in the field vector indices for protocol-offset pairs.
 * These indexes are then ultimately programmed into a recipe template.
 */
int
nse_fill_fv_word_index(struct nse_hw *hw, struct list_head *fv_list,
		       struct list_head *lut_group_list)
{
	struct nse_sw_fv_list_entry *fv;
	struct nse_lut_grp_entry *lut_g;
	struct nse_fv_word *fv_ext;

	if (list_empty(fv_list))
		return 0;

	/* use first fit algorithm, all profiles to extract same protocol word
	 *  need use the same fv idx
	 */
	fv = list_first_entry(fv_list, struct nse_sw_fv_list_entry,
			      list_entry);
	fv_ext = fv->fv_ptr->ew;

	list_for_each_entry(lut_g, lut_group_list, l_entry) {
		u8 i;

		for (i = 0; i < lut_g->lut_group.n_val_pairs; i++) {
			struct nse_fv_word *pr;
			bool found = false;
			u16 mask;
			u8 j;

			pr = &lut_g->lut_group.pairs[i];
			mask = lut_g->lut_group.mask[i];

			for (j = 0; j < NSE_MAX_FV_WORDS; j++)
				if (fv_ext[j].prot_id == pr->prot_id &&
				    fv_ext[j].off == pr->off) {
					found = true;
					lut_g->fv_idx[i] = j;
					lut_g->fv_mask[i] = mask;
					break;
				}
			if (!found)
				return -EINVAL;
		}
	}

	return 0;
}

/**
 * nse_find_lut - find a lut
 * @hw: pointer to the hardware structure
 * @lkup_exts: fv word of lkups to match
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 *
 * Returns index of matching lut, otherwise NSE_MAX_NUM_LUTS if not found.
 */
u16 nse_find_lut(struct nse_hw *hw, struct nse_prot_lkup_ext *lkup_exts,
			 struct nse_adv_node_info *rinfo, bool is_lpm)
{
	struct nse_lut_info *lut;
	u16 i;

	/* Iterate existing luts to find a match */
	lut = hw->switch_info->lut_list;
	for (i = 0; i < NSE_MAX_NUM_LUTS; i++) {
		if (!lut[i].lut_created || !lut[i].is_root || lut[i].is_lpm != is_lpm)
			continue;

		if (rinfo->chain_id != lut[i].chain_id)
			continue;

		/* whether words number of current lkups is equal
		 * words number of existed lut.
		 * n_val_words is valid only on root lut.
		 */
		if (lkup_exts->n_val_words == lut[i].lkup_exts.n_val_words) {
			struct nse_fv_word *ar = lut[i].lkup_exts.fv_words;
			struct nse_fv_word *be = lkup_exts->fv_words;
			u16 *cr = lut[i].lkup_exts.field_mask;
			u16 *de = lkup_exts->field_mask;
			bool found = true;
			u8 pe, qr;

			/* ar, cr, and qr are related to the existed lut words, while
			 * be, de, and pe are related to the current lookup words
			 */
			for (pe = 0; pe < lkup_exts->n_val_words; pe++) {
				for (qr = 0; qr < lut[i].lkup_exts.n_val_words; qr++) {
					if (ar[qr].off == be[pe].off &&
					    ar[qr].prot_id == be[pe].prot_id &&
					    cr[qr] == de[pe])
						/* Found the "pe"th fv word of current lkups is
						 * equal "qr"th fv word in the given exsited lut.
						 */
						break;
				}
				/* if one word of current lkups is not found in existed lut,
				 *  we consider this lut as failed. break to next lut.
				 */
				if (qr >= lut[i].lkup_exts.n_val_words) {
					found = false;
					break;
				}
			}
			/* when every word of current lkups can match in existed lut,
			 * then "found" is true
			 */
			if (rinfo->tun_type == lut[i].tun_type && found &&
			    rinfo->priority == lut[i].priority)
				return i;
		}
	}
	return NSE_MAX_NUM_LUTS;
}

/**
 * nse_find_free_recp_res_idx - find free result indexes for recipe
 * @hw: pointer to hardware structure
 * @profiles_bm: bitmap of profiles that will be associated with the new recipe
 * @free_idx_bm: pointer to variable to receive the free index bitmap
 *
 * The algorithm used here is:
 *	1. When creating a new recipe, create a set P which contains all
 *	   Profiles that will be associated with our new recipe
 *
 *	2. For each Profile p in set P:
 *	    a. Add all recipes associated with Profile p into set R
 *	    b. Optional : PossibleIndexes &= profile[p].possibleIndexes
 *		[initially PossibleIndexes should be 0xFFFFFFFFFFFFFFFF]
 *		i. Or just assume they all have the same possible indexes:
 *			44, 45, 46, 47
 *			i.e., PossibleIndexes = 0x0000F00000000000
 *
 *	3. For each Recipe r in set R:
 *	    a. UsedIndexes |= (bitwise or ) recipe[r].res_indexes
 *	    b. FreeIndexes = UsedIndexes ^ PossibleIndexes
 *
 *	FreeIndexes will contain the bits indicating the indexes free for use,
 *      then the code needs to update the recipe[r].used_result_idx_bits to
 *      indicate which indexes were selected for use by this recipe.
 */
u16
nse_find_free_recp_res_idx(struct nse_hw *hw,
				const unsigned long *profiles_bm,
			    unsigned long *free_idx_bm)
{
	DECLARE_BITMAP(possible_idx_bm, NSE_MAX_FV_WORDS);
	DECLARE_BITMAP(luts_bm, NSE_MAX_NUM_LUTS);
	DECLARE_BITMAP(used_idx_bm, NSE_MAX_FV_WORDS);
	u16 bit;

	bitmap_zero(possible_idx_bm, NSE_MAX_FV_WORDS);
	bitmap_zero(luts_bm, NSE_MAX_NUM_LUTS);
	bitmap_zero(used_idx_bm, NSE_MAX_FV_WORDS);
	bitmap_zero(free_idx_bm, NSE_MAX_FV_WORDS);

	bitmap_set(possible_idx_bm, 0, NSE_MAX_FV_WORDS);

	/* possible_idx_bm is used to collect same free bits
	 *  among associated profiles.
	 *  switch_info->prof_res_bm is got from FW, never change.
	 */
	for_each_set_bit(bit, profiles_bm, NSE_MAX_NUM_PROFILES) {
		bitmap_and(possible_idx_bm, possible_idx_bm,
			   hw->switch_info->prof_res_bm[bit],
			   NSE_MAX_FV_WORDS);
		/* find out the luts that already associated with current profile.*/
		bitmap_or(luts_bm, luts_bm,
			hw->switch_info->profile_list[bit].lut_bitmap,
			NSE_MAX_NUM_LUTS);
	}

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to print associated profiles_bm", __func__, __LINE__);

	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
		16, 1, profiles_bm, BITS_TO_LONGS(NSE_MAX_NUM_PROFILES) * sizeof(long), false);

	print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
		16, 1, profiles_bm, BITS_TO_LONGS(NSE_MAX_NUM_PROFILES) * sizeof(long), false);

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to print possible_idx_bm", __func__, __LINE__);

	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
		16, 1, possible_idx_bm, BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

	print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
		16, 1, possible_idx_bm, BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to print associated luts_bm", __func__, __LINE__);

	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
		16, 1, luts_bm, BITS_TO_LONGS(NSE_MAX_NUM_LUTS) * sizeof(long), false);

	print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
		16, 1, luts_bm, BITS_TO_LONGS(NSE_MAX_NUM_LUTS) * sizeof(long), false);
	/*switch_info->lut_list[bit].res_idxs is the result index
	 *      already be used, which will be changed dynamic by driver.
	 * Iterate the luts associated with profiles_bm,
	 *      remove the used result index, we should not use it again.
	 */
	for_each_set_bit(bit, luts_bm, NSE_MAX_NUM_LUTS)
		bitmap_or(used_idx_bm, used_idx_bm,
			  hw->switch_info->lut_list[bit].res_idxs,
			  NSE_MAX_FV_WORDS);

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to print used_idx_bm", __func__, __LINE__);

	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
		16, 1, used_idx_bm, BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

	print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
		16, 1, used_idx_bm, BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

	bitmap_xor(free_idx_bm, used_idx_bm, possible_idx_bm, NSE_MAX_FV_WORDS);

	/*  bitmap_xor is unsafe(used idx is 0b'1, possible idx is 0b'0), used rst index should not
	 * be used again
	 */
	for_each_set_bit(bit, used_idx_bm, NSE_MAX_FV_WORDS)
		clear_bit(bit, free_idx_bm);

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Start to print free_idx_bm", __func__, __LINE__);

	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS,
		16, 1, free_idx_bm, BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

	print_hex_dump_debug("\t", DUMP_PREFIX_ADDRESS,
		16, 1, free_idx_bm, BITS_TO_LONGS(NSE_MAX_FV_WORDS) * sizeof(long), false);

	/* return count of free indexes */
	return (u16) bitmap_weight(free_idx_bm, NSE_MAX_FV_WORDS);
}

/**
 * nse_find_adv_rule_entry_by_id - Search a node entry
 * @hw: pointer to the hardware structure
 * @lut_id: lut ID for which we are finding the node
 * @node_id: node id, which we are finding the node
 *
 * Helper function to search for a given advance node id
 * Returns pointer to entry storing the rule if found
 */
static struct nse_adv_fltr_mgmt_list_entry *
nse_find_adv_rule_entry_by_id(struct nse_hw *hw,
			u16 lut_id, u16 node_id)
{
	struct nse_adv_fltr_mgmt_list_entry *list_itr;
	struct nse_switch_info *sw = hw->switch_info;

	list_for_each_entry(list_itr, &sw->lut_list[lut_id].filt_rules,
			    list_entry) {
		if (list_itr->node_info.fltr_node_id == node_id)
			return list_itr;
	}
	return NULL;
}

/**
 * nse_find_adv_rule_entry - Search a rule entry
 * @hw: pointer to the hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe, one
 *	   structure per protocol header
 * @lkups_cnt: number of protocols
 * @lut_id: lut ID for which we are finding the rule
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 *
 * Helper function to search for a given advance rule entry
 * Returns pointer to entry storing the rule if found
 */
struct nse_adv_fltr_mgmt_list_entry *
nse_find_adv_rule_entry(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
			u16 lkups_cnt, u16 lut_id,
			struct nse_adv_node_info *rinfo)
{
	struct nse_adv_fltr_mgmt_list_entry *list_itr;
	struct nse_switch_info *sw = hw->switch_info;
	int i;

	list_for_each_entry(list_itr, &sw->lut_list[lut_id].filt_rules,
			    list_entry) {
		bool lkups_matched = true;

		if (lkups_cnt != list_itr->lkups_cnt)
			continue;
		for (i = 0; i < list_itr->lkups_cnt; i++)
			if (memcmp(&list_itr->lkups[i], &lkups[i],
				   sizeof(*lkups))) {
				lkups_matched = false;
				break;
			}
		if (rinfo->sw_act.flag == list_itr->node_info.sw_act.flag &&
		    rinfo->tun_type == list_itr->node_info.tun_type &&
		    lkups_matched)
			return list_itr;
	}
	return NULL;
}

/**
 * nse_set_rinfo_action_lan - common function to set LAN flag
 *						- similar as nse_set_du_action_lan
 * @du_action: built du aciton information
 * @act: return act value used to fill buf
 */
void
nse_set_rinfo_action_lan(struct nse_adv_node_info *rinfo,
		u16 *act)
{
	*act |= NSE_SINGLE_FWD_LAN_DISABLE;

	if (rinfo->flags_info.act_valid && !rinfo->rx) {
		if (rinfo->flags_info.act & NSE_LAN_ENABLE)
			*act &= ~NSE_SINGLE_FWD_LAN_DISABLE;
	}
}

/**
 * nse_fill_lkup_key_word - get lkup key word from lkups,
 *						according to the pair fv word cfg.
 * @hw: pointer to the hardware structure
 * @lkups: information on the words that needs to be looked up.
 *		   All words together makes one recipe or chained recipes
 *		   lkups based on HW protocol ID format
 * @lkups_cnt: num of entries in the lkups array
 * @pair: fv word cfg pair, including protocol id and offset.
 * @key: returned key value after extract from lkups,
 *		which is little endian.
 */
int
nse_fill_lkup_key_word(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct nse_fv_word *pair, __le16 *key)
{
	u8 i, prot_id;
	u16 tmp;

	for (i = 0; i < lkups_cnt; i++) {
		u8 j;
		/* i is index of lkups elem in current lkups,
		 *  j is index of fv word in current lkups elem (lkups[i])
		 */

		if (lkups[i].type >= NSE_PROTOCOL_LAST)
			goto err;

		if (!nse_prot_type_to_id(lkups[i].type, &prot_id))
			goto err;

		if (prot_id != pair->prot_id)
			continue;

		for (j = 0; j < sizeof(lkups[i].m_u) / sizeof(u16); j++)
			if (((u16 *)&lkups[i].m_u)[j] &&
				lkups[i].type < ARRAY_SIZE(nse_prot_ext) &&
				pair->off == nse_prot_ext[lkups[i].type].offs[j]) {
				/*it is big endian in lkups, turn into little endian*/
				tmp = be16_to_cpu((((__force __be16 *)&lkups[i].h_u)[j]) &
						(((__force __be16 *)&lkups[i].m_u)[j]));

				*key = cpu_to_le16(tmp);
				return 0;
			}
	}

err:
	return -EIO;
}

/**
 * nse_build_adv_action_field - build node hw action filed via rinfo
 *
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @out_act: output of action filed, hw format.
 * @out_lg_act: output of large action flag, hw format.
 *
 */
int
nse_build_adv_action_field(struct nse_adv_node_info *rinfo,
		u16 *out_act, u16 *out_lg_act)
{
	u16 act = *out_act;
	u16 lg_act = *out_lg_act;

	switch (rinfo->sw_act.fltr_act) {
	case NSE_FWD_TO_VSI:
		act |= (rinfo->sw_act.fwd_id.hw_vsi_id << NSE_SINGLE_FWD_VSI_ID_S) &
			NSE_SINGLE_FWD_VSI_ID_M;

		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		if (rinfo->flags_info.act & NSE_LB_ENABLE)
			act |= (NSE_SINGLE_FWD_VSI_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		else
			act |= (NSE_SINGLE_FWD_VSI_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;

		/*set LAN flag*/
		nse_set_rinfo_action_lan(rinfo, &act);
		break;
	case NSE_FWD_TO_VSI_LIST:
		act |= (rinfo->sw_act.fwd_id.vsi_list_id << NSE_SINGLE_FWD_VSI_LIST_ID_S) &
			NSE_SINGLE_FWD_VSI_LIST_ID_M;

		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		if (rinfo->flags_info.act & NSE_LB_ENABLE)
			act |= (NSE_SINGLE_FWD_VSI_LIST_EN_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;
		else
			act |= (NSE_SINGLE_FWD_VSI_LIST_DIS_LB << NSE_SINGLE_FWD_TYPE_S) &
					NSE_SINGLE_FWD_TYPE_M;

		/*set LAN flag*/
		nse_set_rinfo_action_lan(rinfo, &act);
		break;
	case NSE_LARGE_ACT:
		lg_act |= NSE_LUT_NODE_LARGE_ACTION_EN;
		act |= (rinfo->sw_act.large_act_id << NSE_SINGLE_LARGE_ACT_ID_S) &
			NSE_SINGLE_LARGE_ACT_ID_M;
		if (!rinfo->sw_act.is_lite)
			act |= NSE_SINGLE_LARGE_ACT_FULL;
		break;
	case NSE_DROP_PACKET:
		/* set action type to fwd */
		act |= (NSE_SINGLE_ACT_TYPE_FWD << NSE_SINGLE_ACT_TYPE_FWD_S) &
			NSE_SINGLE_ACT_TYPE_FWD_M;

		/* set fwd type to Drop */
		act |= (NSE_SINGLE_FWD_DROP << NSE_SINGLE_FWD_TYPE_S) &
				NSE_SINGLE_FWD_TYPE_M;

		/*set LAN flag*/
		nse_set_rinfo_action_lan(rinfo, &act);
		break;
	case NSE_FWD_TO_LAN:
		/*set LAN flag*/
		nse_set_rinfo_action_lan(rinfo, &act);
		break;
	default:
		return -EIO;
}

	*out_act = act;
	*out_lg_act = lg_act;

	return 0;
}
/**
 * nse_add_lut_internal - function to call AQ to alloc switch lut,
 *				   and, bind current lut to profile's recipe.
 *				meanwhile, update profile's used_recipe_num.
 * @hw: pointer to hardware structure
 * @rm: recipe management list entry
 */
static int
nse_add_lut_internal(struct nse_hw *hw, struct nse_lut_info *lut_info)
{
	DECLARE_BITMAP(profiles_bm, NSE_MAX_NUM_PROFILES);
	DECLARE_BITMAP(result_idx_bm, NSE_MAX_FV_WORDS);
	struct nse_sw_fv_list_entry *fv_entry;
	struct nse_aqc_recipe_cfg *buf;
	struct nse_aqc_recipe_data_elem *rcp_elems;
	struct nse_lut_grp_entry *lut_entry;
	struct nse_switch_info *sw = hw->switch_info;
	u16 free_idx_count;
	u16 buf_size;
	int status = 0;
	u8 recps = 0;
	u8 result_idx;
	u8 lut_index = 0;

	/*Get bitmap of all profiles that current new lut is associated with*/
	bitmap_zero(profiles_bm, NSE_MAX_NUM_PROFILES);

	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		set_bit(fv_entry->profile_id, profiles_bm);
	}

	/* Find the bitmap of free result index that can be used by
	 *  intermediate lut. all associated profile need be checked.
	 */
	bitmap_zero(result_idx_bm, NSE_MAX_FV_WORDS);
	free_idx_count = nse_find_free_recp_res_idx(hw, profiles_bm,
						result_idx_bm);
	dev_info(nse_hw_to_dev(hw), "Free result idx count: %d, need %d\n",
		free_idx_count,	(lut_info->n_grp_count == 1) ? 0 : lut_info->n_grp_count);
	nse_debug(hw, NSE_DBG_SW, "Free result idx count: %d, need %d\n",
		  free_idx_count, (lut_info->n_grp_count == 1) ? 0 : lut_info->n_grp_count);
	if (lut_info->n_grp_count > 1) {
		/* one free result index is needed per lut group.
		 * if free result index count can't match current lkup, return err
		 */
		if (lut_info->n_grp_count > free_idx_count)
			return -ENOSPC;

		/* last root lut group is needed if it's chained lut */
		lut_info->n_grp_count++;
	}

	if (lut_info->n_grp_count > NSE_MAX_CHAIN_RECIPE)
		return -ENOSPC;

	/* Start to add signal or chained recipe in multi profiles.
	 *  recipe aqc buf is same in different profiles.
	 *
	 *  Total two Steps:
	 *
	 *  Step1: build the common recipe aqc buf, signal or chained recipe.
	 *		In fact, lut_info is lut template, which is recipe format yet.
	 *
	 *	 PS: at chained recipe situation, we need update occupied
	 *		 result idx to global hw->switch_info->lut_list[bit].res_idxs
	 *
	 *  Step2: Iterate the profiles, add signal/chained recipe per profile.
	 *		and, update used_recipe_num in profile
	 *
	 *	 PS: we need update hw->switch_info->profile_list[bit].lut_bitmap
	 *		if signal recipe, set 1 lut_bitmap
	 *		if chained recipe, set multi lut_bitmap
	 *
	 *  Step3: Updata Software Lut List and Software Profile List
	 *
	 */
	buf_size = struct_size(buf, elem, lut_info->n_grp_count);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rcp_elems = buf->elem;

	/* Step1.1: Start to build aqc buf per recipe*/
	result_idx = (u8)find_first_bit(result_idx_bm, NSE_MAX_FV_WORDS);
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		enum nse_status rt;
		u8 i;

		/* 1) alloc a new lut id */
		rt = nse_aq_alloc_free_lut_id(hw, &lut_entry->lut_id,
				NSE_AQ_OPC_ALLOC_RESOURCE);
		if (rt) {
			dev_err(nse_hw_to_dev(hw), "Failed to alloc lut id, err = %d\n", rt);
			status = -EIO;
			goto err_unroll;
		}

		/* 2) build recipe aqc info, except root flag & priority*/
		rcp_elems[recps].content.lut_id = cpu_to_le16(lut_entry->lut_id);

		for (i = 0; i < lut_entry->lut_group.n_val_pairs; i++) {
			rcp_elems[recps].content.lkup_indx[i] =
				(u8)lut_entry->fv_idx[i];
			rcp_elems[recps].content.mask[i] =
				cpu_to_le16(lut_entry->fv_mask[i]);
		}

		/* handle result_index in buf, if current is chained recipe*/
		lut_entry->result_idx = NSE_INVALID_RSLT_IDX;
		if (lut_info->n_grp_count > 1) {
			/* check prefetched result index whether valid or not */
			if (result_idx >= NSE_MAX_FV_WORDS) {
				nse_debug(hw, NSE_DBG_SW, "No result index available\n");
				dev_err(nse_hw_to_dev(hw), "No result index available\n");
				status = -ENOSPC;
				goto err_unroll;
			}
			lut_entry->result_idx = result_idx;
			rcp_elems[recps].content.result_indx |=
				(result_idx << NSE_AQ_RECIPE_RSLT_INDX_S) &
					NSE_AQ_RECIPE_RSLT_INDX_M;
			rcp_elems[recps].content.ctrl_flg |= NSE_AQ_RECIPE_RESULT_EN;
			rcp_elems[recps].content.ignore_vld |= NSE_AQ_RECIPE_RESULT_SEL;
			/* prefetch result idx for next recipe */
			clear_bit(result_idx, result_idx_bm);
			result_idx = (u8)find_first_bit(result_idx_bm,
							NSE_MAX_FV_WORDS);
		}

		/*3) go to next recipe */
		recps++;
	}

	/* Step1.2: Start to handle root recipe*/
	if (lut_info->n_grp_count == 1) {
		/* signal recipe, set its ctrl flag's root_enable */
		rcp_elems[0].content.ctrl_flg |= NSE_AQ_RECIPE_IS_ROOT;
		lut_info->root_lut_id = le16_to_cpu(rcp_elems[0].content.lut_id);
	} else {
		/* chained recipe, need alloc a new last root recipe here*/
		struct nse_lut_grp_entry *last_root_lut;
		enum nse_status rt;
		u16 lut_id;
		u8 i;

		/* 1) alloc a new lut id */
		rt = nse_aq_alloc_free_lut_id(hw, &lut_id,
				NSE_AQ_OPC_ALLOC_RESOURCE);
		if (rt) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to alloc last root lut id, err = %d\n", rt);
			status = -EIO;
			goto err_unroll;
		}

		last_root_lut = devm_kzalloc(nse_hw_to_dev(hw),
							sizeof(*last_root_lut), GFP_KERNEL);
		if (!last_root_lut) {
			status = -ENOMEM;
			goto err_unroll;
		}

		/* 2) build recipe aqc info, except priority*/
		last_root_lut->lut_id = lut_id;
		rcp_elems[recps].content.lut_id = cpu_to_le16(lut_id);
		/* fill sub lut's result index to last root lut*/
		i = 0;
		last_root_lut->result_idx = NSE_INVALID_RSLT_IDX;
		list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
			rcp_elems[recps].content.lkup_indx[i] = lut_entry->result_idx;
			rcp_elems[recps].content.mask[i++] = cpu_to_le16(0xFFFF);
		}
		rcp_elems[recps].content.ctrl_flg |= NSE_AQ_RECIPE_IS_ROOT;

		/* 3) add last_root_lut to lut_group_list */
		list_add_tail(&last_root_lut->l_entry, &lut_info->lut_group_list);
		lut_info->root_lut_id = last_root_lut->lut_id;
		recps++;
	}

	/*recps should be equal lut_info->n_grp_count*/
	if (lut_info->n_grp_count != recps) {
		nse_debug(hw, NSE_DBG_SW,
			"Expected recps is not equal real recps\n");
		dev_err(nse_hw_to_dev(hw), "Expected recps is not equal real recps\n");
		status = -EIO;
		goto err_unroll;
	}

	/*Step2: add recipe per profile.
	 * except recipe's priority, common recipe aqc buf is built
	 */
	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		struct nse_profile_info *profile;
		u8 start_rcp_id;

		profile = &sw->profile_list[fv_entry->profile_id];
		start_rcp_id = profile->used_recipe_num;
		/* check profile's rcp resource one by one before add recipe adminq cmd
		 */
		if (profile->total_recipe_num < (profile->used_recipe_num + recps)) {
			dev_err(nse_hw_to_dev(hw),
				"Need %d recipes in profile[%d] but not enough, total = %d, used = %d\n",
				recps, profile->profile_id, profile->total_recipe_num,
				profile->used_recipe_num);
			status = -EIO;
			goto err_prfl_fail;
		}
	}

	buf->count = cpu_to_le16(recps);

	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		struct nse_profile_info *profile;
		enum nse_status rt;
		u8 start_rcp_id;
		u8 i;

		profile = &sw->profile_list[fv_entry->profile_id];
		start_rcp_id = profile->used_recipe_num;
		dev_info(nse_hw_to_dev(hw), "Start to add %d recps to Profile[%d]\n",
			 recps, profile->profile_id);
		for (i = 0; i < recps; i++) {
			buf->elem[i].profile_id = cpu_to_le16(profile->profile_id);
			buf->elem[i].recipe_id = start_rcp_id + i;
			/* it's hw internal priority, which is set to recipe id.
			 * 1 has higher priority than 2
			 */
			buf->elem[i].content.priority = buf->elem[i].recipe_id;
			dev_info(nse_hw_to_dev(hw), "\t Profile[%d] start to add recipe[%d]: lut id = %d, priority = %d\n",
				profile->profile_id, buf->elem[i].recipe_id,
				le16_to_cpu(buf->elem[i].content.lut_id),
					buf->elem[i].content.priority);

			dev_info(nse_hw_to_dev(hw), "\t\t mask[0~4] = [0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
				le16_to_cpu(buf->elem[i].content.mask[0]),
				le16_to_cpu(buf->elem[i].content.mask[1]),
				le16_to_cpu(buf->elem[i].content.mask[2]),
				le16_to_cpu(buf->elem[i].content.mask[3]),
				le16_to_cpu(buf->elem[i].content.mask[4]));

			dev_info(nse_hw_to_dev(hw), "\t\t lkup_Index[0~4] = [0x%x, 0x%x, 0x%x, 0x%x, 0x%x]\n",
				(buf->elem[i].content.lkup_indx[0]),
				(buf->elem[i].content.lkup_indx[1]),
				(buf->elem[i].content.lkup_indx[2]),
				(buf->elem[i].content.lkup_indx[3]),
				(buf->elem[i].content.lkup_indx[4]));

			dev_info(nse_hw_to_dev(hw), "\t\t ctrl_flag = 0x%x, ignore_vld = 0x%x, rslt_idx = 0x%x\n",
				(buf->elem[i].content.ctrl_flg),
				(buf->elem[i].content.ignore_vld),
				(buf->elem[i].content.result_indx >> NSE_AQ_RECIPE_RSLT_INDX_S));
		}

		/*add recipes to HW*/
		rt = nse_aq_add_recipe(hw, buf, buf_size);
		if (rt) {
			dev_err(nse_hw_to_dev(hw), "Failed to adminq add recipe, err = %d\n", rt);
			status = -EIO;
			goto err_prfl_fail;
		}
		for (i = 0; i < recps; i++)
			dev_info(nse_hw_to_dev(hw), "\t Profile[%d] finish to add recipe[%d]: lut id = %d\n",
				profile->profile_id, buf->elem[i].recipe_id,
				le16_to_cpu(buf->elem[i].content.lut_id));
	}

	/*Step3: Updata Software Lut List and Software Profile List */
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_lut_info *lut;
		bool is_root, idx_found = false;
		u16 idx, buf_idx = 0;

		/*Step3.1 Start to updata Software Lut List*/

		/* find buffer index for copying some data */
		for (idx = 0; idx < lut_info->n_grp_count; idx++) {
			if (rcp_elems[idx].content.lut_id == cpu_to_le16(lut_entry->lut_id)) {
				buf_idx = idx;
				idx_found = true;
			}
		}

		if (!idx_found) {
			dev_err(nse_hw_to_dev(hw), "Failed to find correct Lut in recp adminq buf\n");
			status = -EIO;
			goto err_prfl_fail;
		}

		lut = &sw->lut_list[lut_entry->lut_id];
		is_root = (lut_info->root_lut_id == lut_entry->lut_id);
		lut->is_root = is_root;
		lut->lut_id = lut_entry->lut_id;
		lut->big_lut = (is_root && lut_info->n_grp_count > 1);
		memcpy(&lut->ext_words, lut_entry->lut_group.pairs,
		    lut_entry->lut_group.n_val_pairs * sizeof(struct nse_fv_word));

		/* set used rslt idx bitmap of global software lut DB */
		nse_collect_result_idx(&buf->elem[buf_idx], lut);

		/* for non-root recipes, also copy to the root, this
		 * allows easier matching of a complete chained recipe
		 */
		if (!is_root)
			nse_collect_result_idx(&buf->elem[buf_idx],
					       &sw->lut_list[lut_info->root_lut_id]);

		lut->n_ext_words = lut_entry->lut_group.n_val_pairs;
		lut->result_index = lut_entry->result_idx;
		lut->hw_prio = buf->elem[buf_idx].content.priority;
		lut->priority = lut_info->priority;
		lut->n_grp_count = lut_info->n_grp_count;
		lut->tun_type = lut_info->tun_type;
		lut->lut_created = true;
		lut->chain_id = lut_info->chain_id;

		/* Step3.2: update lut_bitmap per Software Profile */
		list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
			struct nse_profile_info *profile;
			u8 rcp_id;

			profile = &sw->profile_list[fv_entry->profile_id];
			set_bit(lut_entry->lut_id, profile->lut_bitmap);
			rcp_id = profile->used_recipe_num + lut_index;
			profile->lut_id[rcp_id] = lut_entry->lut_id;
			dev_info(nse_hw_to_dev(hw), "Lut_id of Profile[%d]_Recipe[%d] = %d\n",
					profile->profile_id, rcp_id, profile->lut_id[rcp_id]);
		}
		lut_index++;
	}

	/* Step3.3: update used_recipe_num per Software Profile */
	list_for_each_entry(fv_entry, &lut_info->fv_list, list_entry) {
		struct nse_profile_info *profile;

		profile = &sw->profile_list[fv_entry->profile_id];
		profile->used_recipe_num += recps;
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return 0;

err_prfl_fail:
err_unroll:
	devm_kfree(nse_hw_to_dev(hw), buf);

	/*rollback allocated lut id when fail*/
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		enum nse_status rt = 0;

		if (!lut_entry->lut_id)
			continue;

		rt = nse_aq_alloc_free_lut_id(hw, &lut_entry->lut_id,
				NSE_AQ_OPC_FREE_RESOURCE);
		if (rt)
			dev_err(nse_hw_to_dev(hw),
				"Failed to free lut id(%d), err = %d\n", lut_entry->lut_id, rt);
	}

	return status;
}

/**
 * nse_add_adv_lut - Add an advanced lut that is not part of the default
 *				 the associated recipes of this lut can match lkups keys.
 * @hw: pointer to hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe,
 *			one structure per protocol header (protocol id)
 * @lkups_cnt: number of protocol headers
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @lut_id: return the lut ID of the recipe created
 */
int
nse_add_adv_lut(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		   u16 lkups_cnt, struct nse_adv_node_info *rinfo, u16 *lut_id)
{
	DECLARE_BITMAP(fv_bitmap, NSE_MAX_NUM_PROFILES);

	/*lkup_exts: total match lkup extract from user,
	 * not including rsult_index, but including in_port
	 */
	struct nse_prot_lkup_ext *lkup_exts;
	struct nse_lut_grp_entry *lut_entry;
	struct nse_sw_fv_list_entry *fv_entry;
	struct nse_lut_grp_entry *lut_tmp;
	struct nse_sw_fv_list_entry *fv_tmp;
	struct nse_lut_info *lut_info;
	int status = 0;
	u8 i;

	if (!lkups_cnt)
		return -EINVAL;

	lkup_exts = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*lkup_exts),
				 GFP_KERNEL);
	if (!lkup_exts)
		return -ENOMEM;

	/* Determine the number of words to be matched.
	 *  and check whether it exceeds chained_recipe's restriction or not
	 */
	for (i = 0; i < lkups_cnt; i++) {
		u16 count;

		if (lkups[i].type >= NSE_PROTOCOL_LAST) {
			dev_err(nse_hw_to_dev(hw), "Unsupported match filed\n");
			status = -EIO;
			goto err_free_lkup_exts;
		}
		/*transform lkups from Protocol ID header to FV word format*/
		count = nse_fill_valid_words(&lkups[i], lkup_exts);
		if (!count) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to change Protocol header to FV word\n");
			status = -EIO;
			goto err_free_lkup_exts;
		}
	}

	lut_info = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*lut_info),
				GFP_KERNEL);
	if (!lut_info) {
		status = -ENOMEM;
		goto err_free_lkup_exts;
	}

	INIT_LIST_HEAD(&lut_info->fv_list);
	INIT_LIST_HEAD(&lut_info->lut_group_list);

	/* Get the profiles which can match current lkups, total 2 steps:
	 *        step1: Get profile type according to tunnel type of current lkups
	 *	    step2: Get exact profile IDs among profile type of step1
	 */
	nse_get_compat_fv_bitmap(hw, rinfo, fv_bitmap);
	status = nse_get_fv(hw, lkup_exts, fv_bitmap, &lut_info->fv_list);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "Failed to get fv\n");
		goto err_unroll;
	}

	/* Calculate how many luts are needed to match current lkups */
	status = nse_create_lut_group(hw, lut_info, lkup_exts);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "Failed to creat lut group, err = %d\n", status);
		goto err_unroll;
	}

	/* set the recipe priority if specified */
	lut_info->priority = (u8)rinfo->priority;

	/* fill nse_lut_grp_entry's fv_idx of lut group */
	status = nse_fill_fv_word_index(hw, &lut_info->fv_list,
				&lut_info->lut_group_list);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "Failed to fill_fv_word_index, err = %d\n", status);
		goto err_unroll;
	}

	/* Look for a lut which can matches our requested lkups */
	*lut_id = nse_find_lut(hw, lkup_exts, rinfo, false);
	if (*lut_id < NSE_MAX_NUM_LUTS) {
		dev_info(nse_hw_to_dev(hw), "LUT is existed, lut id = %d\n", *lut_id);
		goto err_unroll;
	}

	lut_info->tun_type = rinfo->tun_type;

	lut_info->chain_id = rinfo->chain_id;

	/* Find lut failed, new single or chained lut need be added*/
	status = nse_add_lut_internal(hw, lut_info);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "Failed to add_lut_internal, err = %d\n", status);
		goto err_unroll;
	}

	*lut_id = lut_info->root_lut_id;

	/* root lut's lkup_exts is copied from current lkups,
	 *   and intermediate lut is not.
	 */
	memcpy(&hw->switch_info->lut_list[*lut_id].lkup_exts, lkup_exts,
	       sizeof(*lkup_exts));

	/* Store fv_list/lut_group_list to golbal LUT DB,
	 * and fv_list/lut_group_list of local lut_info will be NULL,
	 * so we can fall to next code
	 */
	list_replace_init(&lut_info->fv_list,
		&hw->switch_info->lut_list[*lut_id].fv_list);

	list_replace_init(&lut_info->lut_group_list,
		&hw->switch_info->lut_list[*lut_id].lut_group_list);

err_unroll:
	list_for_each_entry_safe(lut_entry, lut_tmp,
		&lut_info->lut_group_list, l_entry) {
		list_del(&lut_entry->l_entry);
		devm_kfree(nse_hw_to_dev(hw), lut_entry);
	}

	list_for_each_entry_safe(fv_entry, fv_tmp,
		&lut_info->fv_list, list_entry) {
		list_del(&fv_entry->list_entry);
		devm_kfree(nse_hw_to_dev(hw), fv_entry);
	}

	/* lut_info is temporary,  lkup_exts/fv_list/lut_group_list
	 *  are copied to global switch_info->lut_list
	 */
	devm_kfree(nse_hw_to_dev(hw), lut_info);

err_free_lkup_exts:
	devm_kfree(nse_hw_to_dev(hw), lkup_exts);

	return status;
}

/**
 * nse_add_adv_fast_node - Add an advanced fast node
 *
 * @hw: pointer to hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe,
 *			one structure per protocol header (protocol id)
 * @lkups_cnt: number of protocol headers
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @lut_id:  lut ID of the fast node need to be added.
 * @node_id: returned root node id when add to hw successfully.
 * @sub_node_id: returned sub node id when add to hw successfully.
 */
static int
nse_add_adv_fast_node(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		   u16 lkups_cnt, struct nse_adv_node_info *rinfo, u16 lut_id,
		   u16 *node_id, u16 *sub_node_id)
{
	struct nse_node_state *node_state = rinfo->node_state;
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_lut_info *lut_info = &sw->lut_list[lut_id];
	struct nse_lut_grp_entry *lut_entry = NULL;
	struct nse_aqc_lut_fast_nodes *buf = NULL;
	struct nse_aqc_lut_fast_node_elem *fast_node = NULL;
	struct nse_aqc_lut_fast_node_action *action = NULL;
	struct nse_aqc_lut_fast_node_match *match = NULL;
	enum nse_status status;
	u16 du_act_cnt = 0, buf_size;
	u16 act_ctrl = 0;
	u8 n_grp_count = 0, lut_idx = 0;
	int err = 0, i;

	if (!node_state || !lut_info) {
		dev_err(nse_hw_to_dev(hw),
			"Node state or Lut is NULL when add adv fast node!\n");
		err = -EINVAL;
		goto out;
	}

	du_act_cnt = node_state->du_act_cnt;
	n_grp_count = lut_info->n_grp_count;
	buf_size = struct_size(buf, elem, 1) +
			   struct_size(action, act, du_act_cnt) +
			   struct_size(match, lut, n_grp_count);

	dev_info(nse_hw_to_dev(hw),
		"Start to build fast node: du_act_cnt = %d, n_grp_count = %d, buf_size = %d\n",
		du_act_cnt, n_grp_count, buf_size);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}

	buf->count = cpu_to_le16(1);
	fast_node = buf->elem;

	/*start to handle action field*/
	action = &fast_node->action;

	act_ctrl |= (du_act_cnt << NSE_FAST_ACT_DU_CNT_S) &
					NSE_FAST_ACT_DU_CNT_M;
	action->node_state_id = cpu_to_le16(0);
	action->act_ctrl = cpu_to_le16(act_ctrl);
	for (i = 0; i < du_act_cnt; i++) {
		struct nse_du_action *du_action = &node_state->du_action[i];
		u16 act = 0;
		u16 res_type = NSE_FAST_ACT_INV_RES_TYPE;

		switch (du_action->du_act) {
		case NSE_DU_ACT_COUNT_BYTE:
			act |= NSE_SINGLE_COUNT_BYTE;
			fallthrough;
		case NSE_DU_ACT_COUNT_PACKET:
			/* set action type to count */
			act |= (NSE_SINGLE_ACT_TYPE_COUNT <<
				NSE_SINGLE_ACT_TYPE_COUNT_S) &
				NSE_SINGLE_ACT_TYPE_COUNT_M;

			res_type = NSE_AQC_RES_TYPE_COUNTER_ID;
			break;
		case NSE_DU_ACT_DROP_PACKET:
			nse_set_du_action_drop(&act);
			break;
		case NSE_DU_ACT_FWD_TO_LAN:
			nse_set_du_action_tolan(du_action, &act);
			break;
		case NSE_DU_ACT_FWD_TO_VSI:
			nse_set_du_action_tovsi(du_action, &act);
			break;
		default:
			dev_err(nse_hw_to_dev(hw),
				"Du action type is not supported when add adv fast node, type = %d!\n",
				du_action->du_act);
			goto out;
		}

		action->act[i].action = cpu_to_le16(act);
		action->act[i].res_type = cpu_to_le16(res_type);
	}

	/*start to handle match field*/
	match = (struct nse_aqc_lut_fast_node_match *)((void *)fast_node
				+ struct_size(action, act, du_act_cnt));

	match->lut_num = n_grp_count;

	lut_idx = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_aqc_fast_lut_info *lut = &match->lut[lut_idx];
		int j;
		bool is_root = false;

		if (lut_idx >= NSE_MAX_SUB_NODE_NUM) {
			dev_err(nse_hw_to_dev(hw),
				"Too many sub recipes to be supported in fast node\n");
			err = -EINVAL;
			goto out;
		}

		lut->lut_id = cpu_to_le16(lut_entry->lut_id);
		lut->node_id = cpu_to_le16(0);

		if (lut_entry->lut_id == lut_id) {
			match->rt_idx = lut_idx;
			is_root = true;
		} else
			lut->key_idx = cpu_to_le16(lut_idx);

		if (lut_info->n_grp_count == 1 || (!is_root)) {
			for (j = 0; j < lut_entry->lut_group.n_val_pairs; j++) {
				/*get key word from lkups,
				 * according to the pair fv word cfg
				 */
				err = nse_fill_lkup_key_word(hw, lkups, lkups_cnt,
					&lut_entry->lut_group.pairs[j],
					&lut->key[j]);
				if (err) {
					dev_err(nse_hw_to_dev(hw),
						"Failed to fill lkup key word when add fast node\n");
					goto out;
				}
			}
		}
		lut_idx++;
	}

	dev_info(nse_hw_to_dev(hw),	"Start to add fast node to hw: count = %d\n",
		 le16_to_cpu(buf->count));
	dev_info(nse_hw_to_dev(hw), "\t Action Part:\n");
	dev_info(nse_hw_to_dev(hw), "\t\t node_state_id = %d, act_ctl = %d\n",
		le16_to_cpu(action->node_state_id),  le16_to_cpu(action->act_ctrl));
	for (i = 0; i < du_act_cnt; i++)
		dev_info(nse_hw_to_dev(hw), "\t\t Action[%d]: act_val = 0x%x, res_type = %d\n",
			i, le16_to_cpu(action->act[i].action),
				le16_to_cpu(action->act[i].res_type));

	dev_info(nse_hw_to_dev(hw), "\t Match Part:\n");
	dev_info(nse_hw_to_dev(hw), "\t\t lut_num = %d, root_lut_idx = %d\n",
		match->lut_num, match->rt_idx);
	lut_idx = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_aqc_fast_lut_info *lut = &match->lut[lut_idx];

		dev_info(nse_hw_to_dev(hw),
			"\t\t Lut[%d]: lut_id = %d, node_id = %d, result key index in Root Lut is %d\n",
			lut_idx, le16_to_cpu(lut->lut_id), le16_to_cpu(lut->node_id),
				le16_to_cpu(lut->key_idx));
		dev_info(nse_hw_to_dev(hw), "\t\t key_value[0~4]: [0x%x, 0x%x, 0x%x, 0x%x, 0x%x,]\n",
			le16_to_cpu(lut->key[0]), le16_to_cpu(lut->key[1]),
			le16_to_cpu(lut->key[2]), le16_to_cpu(lut->key[3]),
			le16_to_cpu(lut->key[4]));
		lut_idx++;
	}

	/* request fast node adminq cmd */
	status = nse_aq_fast_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_LUT_FAST_NODE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to add nse_aq_fast_nodes\n");
		err = -EIO;
		goto out;
	}

	dev_info(nse_hw_to_dev(hw), "=======================\n");
	dev_info(nse_hw_to_dev(hw), "Return from fw after add fast node: count = %d\n",
		 le16_to_cpu(buf->count));
	dev_info(nse_hw_to_dev(hw), "\t Action Part:\n");
	dev_info(nse_hw_to_dev(hw), "\t\t node_state_id = %d, act_ctl = %d\n",
		le16_to_cpu(action->node_state_id),  le16_to_cpu(action->act_ctrl));
	for (i = 0; i < du_act_cnt; i++)
		dev_info(nse_hw_to_dev(hw), "\t\t Action[%d]: act_val = 0x%x, res_type = %d\n",
			i, le16_to_cpu(action->act[i].action),
				le16_to_cpu(action->act[i].res_type));

	dev_info(nse_hw_to_dev(hw), "\t Match Part:\n");
	dev_info(nse_hw_to_dev(hw), "\t\t lut_num = %d, root_lut_idx = %d\n",
		match->lut_num, match->rt_idx);
	lut_idx = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_aqc_fast_lut_info *lut = &match->lut[lut_idx];

		dev_info(nse_hw_to_dev(hw),
			"\t\t Lut[%d]: lut_id = %d, node_id = %d, result key index in Root Lut is %d\n",
			lut_idx, le16_to_cpu(lut->lut_id), le16_to_cpu(lut->node_id),
				le16_to_cpu(lut->key_idx));
		dev_info(nse_hw_to_dev(hw), "\t key_value[0~4]: [0x%x, 0x%x, 0x%x, 0x%x, 0x%x,]\n",
			le16_to_cpu(lut->key[0]), le16_to_cpu(lut->key[1]),
			le16_to_cpu(lut->key[2]), le16_to_cpu(lut->key[3]),
			le16_to_cpu(lut->key[4]));
		lut_idx++;
	}

	/* prcoess returned info*/
	node_state->node_state_id = le16_to_cpu(action->node_state_id);
	act_ctrl = le16_to_cpu(action->act_ctrl);

	for (i = 0; i < du_act_cnt; i++) {
		struct nse_du_action *du_action = &node_state->du_action[i];
		u16 val = le16_to_cpu(action->act[i].action);

		switch (du_action->du_act) {
		case NSE_DU_ACT_COUNT_BYTE:
		case NSE_DU_ACT_COUNT_PACKET:
			du_action->hw_cnt_id = (act_ctrl & NSE_AQC_DU_STAT_MSB_M) |
					((val << NSE_SINGLE_COUNT_ID_S) & NSE_SINGLE_COUNT_ID_M);
			break;
		case NSE_DU_ACT_DROP_PACKET:
		case NSE_DU_ACT_FWD_TO_LAN:
		case NSE_DU_ACT_FWD_TO_VSI:
			break;
		default:
			dev_err(nse_hw_to_dev(hw),
				"Du action type is not supported when add adv fast node, type = %d!\n",
				du_action->du_act);
			err = -EIO;
			goto out;
		}
	}

	lut_idx = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_aqc_fast_lut_info *lut = &match->lut[lut_idx];

		sub_node_id[lut_idx] = le16_to_cpu(lut->node_id);
		if (lut_entry->lut_id == lut_id)
			*node_id = le16_to_cpu(lut->node_id);

		lut_idx++;
	}

out:
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return err;
}

/**
 * nse_add_adv_node - create an advanced node to HW lut
 * @hw: pointer to the hardware structure
 * @lkups: information on the words that needs to be looked up.
 *		   All words together makes one recipe or chained recipes
 *		   lkups based on HW protocol ID format
 * @lkups_cnt: num of entries in the lkups array
 * @rinfo: other information regarding the rule/node e.g. priority and action info
 * @added_entry: this will return lut_id, node_id and vsi_handle.
 *				should be ignored is case of error.
 *
 * This function can program only 1 rule at a time. The lkups is used to
 * describe the all the words that forms the "lookup" portion of the recipe.
 * These words can span multiple protocols. Callers to this function need to
 * pass in a list of protocol headers with lookup information along and mask
 * that determines which words are valid from the given protocol header.
 * rinfo describes other information related to this rule such as forwarding
 * IDs, priority of this rule, etc.
 */
int
nse_add_adv_node(struct nse_hw *hw, struct nse_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct nse_adv_node_info *rinfo,
		 struct nse_node_query_data *added_entry)
{
	struct nse_adv_fltr_mgmt_list_entry *m_entry, *adv_fltr = NULL;
	struct nse_switch_info *sw;
	struct nse_aqc_lut_nodes *buf = NULL;
	struct nse_aqc_lut_node_elem *lut_node;
	struct list_head *rule_head;
	struct nse_lut_grp_entry *lut_entry;
	struct nse_lut_info *lut_info;
	struct mutex *rule_lock;
	u16 lut_id = 0, i;
	u16 word_cnt, buf_size;
	u16 act = 0;
	u16 lg_act = 0;
	int status;
	bool is_fast_created = false;
	u16 node_id = 0, sub_node_id[NSE_MAX_SUB_NODE_NUM] = { 0 };

	/* Initialize profiles' result index bitmap */
	if (!hw->switch_info->prof_res_bm_init) {
		hw->switch_info->prof_res_bm_init = 1;
		nse_init_prof_result_bm(hw);
	}

	if (!lkups_cnt) {
		dev_err(nse_hw_to_dev(hw), "it's error due to lkups_cnt is 0\n");
		return -EINVAL;
	}

	/* get num of FV words we need to match */
	word_cnt = 0;
	for (i = 0; i < lkups_cnt; i++) {
		u16 j, *ptr;

		ptr = (u16 *)&lkups[i].m_u;
		for (j = 0; j < sizeof(lkups->m_u) / sizeof(u16); j++)
			if (ptr[j] != 0)
				word_cnt++;
	}

	if (!word_cnt) {
		dev_err(nse_hw_to_dev(hw), "it's error due to match word is 0\n");
		return -EINVAL;
	}

	if (word_cnt > NSE_MAX_CHAIN_LKUP_WORDS) { /*NSE_MAX_CHAIN_WORDS*/
		dev_err(nse_hw_to_dev(hw), "match words(%d) up to max num\n", word_cnt);
		return -ENOSPC;
	}

	if (!(rinfo->sw_act.fltr_act == NSE_LARGE_ACT ||
		  rinfo->sw_act.fltr_act == NSE_FAST_ACT ||
	      rinfo->sw_act.fltr_act == NSE_FWD_TO_LAN ||
		  rinfo->sw_act.fltr_act == NSE_FWD_TO_VSI ||
		  rinfo->sw_act.fltr_act == NSE_FWD_TO_VSI_LIST ||
	      rinfo->sw_act.fltr_act == NSE_DROP_PACKET)) {
		dev_err(nse_hw_to_dev(hw), "Unsupported action type\n");
		return -EIO;
	}

	/* returned lut_id is root lut id */
	status = nse_add_adv_lut(hw, lkups, lkups_cnt, rinfo, &lut_id);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "Failed to add advanced LUT\n");
		return status;
	}

	sw = hw->switch_info;
	lut_info = &sw->lut_list[lut_id];
	rule_lock = &lut_info->filt_rule_lock;

	mutex_lock(rule_lock);

	m_entry = nse_find_adv_rule_entry(hw, lkups, lkups_cnt, lut_id, rinfo);
	if (m_entry) {
		dev_err(nse_hw_to_dev(hw), "advanced node is existed\n");
		status = -EEXIST;
		goto err_nse_add_adv_node;
	}

	/* not find existed rule, start to add new rule/node.
	 * total 3 Steps.
	 */
	if (rinfo->sw_act.is_fast) {
		/* fast flower has own adminq cmd, should bypass normal process*/
		status = nse_add_adv_fast_node(hw, lkups, lkups_cnt, rinfo,
					lut_id, &node_id, sub_node_id);
		if (status) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to add adv fast node, err = %d\n", status);
			goto err_nse_add_adv_node;
		}

		is_fast_created = true;
		goto add_adv_entry_to_sw_db;
	}

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		status = -ENOMEM;
		goto err_nse_add_adv_node;
	}

	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;

	/* Step1: Build action info for root Lut node*/
	status = nse_build_adv_action_field(rinfo, &act, &lg_act);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to build action field info\n",
			__func__, __LINE__);
		goto err_nse_add_adv_node;
	}

	/* Step2: Based on returned root lut_id,
	 *		iterate lut group in lut_group_list of lut list info.
	 *		add node one by one per lut group.
	 */
	i = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		bool is_root = false;
		enum nse_status rt_status;
		u16 j;

		buf->count = cpu_to_le16(1);
		memset(lut_node, 0, sizeof(*lut_node));

		/*2.1 build key*/
		if (lut_info->n_grp_count == 1) {
			is_root = true;
			for (j = 0; j < lut_entry->lut_group.n_val_pairs; j++) {
				/*get key word from lkups,
				 * according to the pair fv word cfg
				 */
				status = nse_fill_lkup_key_word(hw, lkups, lkups_cnt,
					&lut_entry->lut_group.pairs[j],
					&lut_node->key[j]);
				if (status) {
					dev_err(nse_hw_to_dev(hw),
						"Failed to fill lkup key word when single recipe\n");
					goto err_nse_add_adv_node;
				}
			}
		} else {
			if (lut_entry->lut_id == lut_id)
				is_root = true;
			if (is_root) {
				for (j = 0; j < NSE_MAX_CHAIN_SUB_RECIPE; j++)
					lut_node->key[j] = cpu_to_le16(sub_node_id[j]);
			} else {
				for (j = 0; j < NSE_MAX_CHAIN_SUB_RECIPE; j++)
					lut_node->key[j] = 0;

				for (j = 0; j < lut_entry->lut_group.n_val_pairs; j++) {
					/*get key word from lkups,
					 * according to the pair fv word cfg
					 */
					status = nse_fill_lkup_key_word(hw, lkups, lkups_cnt,
						&lut_entry->lut_group.pairs[j],
						&lut_node->key[j]);
					if (status) {
						dev_err(nse_hw_to_dev(hw),
							"Failed to fill lkup key word when chained recipe\n");
						goto err_nse_add_adv_node;
					}
				}
			}
		}

		/*2.2 build action, only root is needed*/
		if (is_root) {
			lut_node->action = cpu_to_le16(act);
			lut_node->left_ptr = cpu_to_le16(lg_act);
		}

		/*2.3 request "add lut node" adminq cmd per lut group*/
		lut_node->lut_id = cpu_to_le16(lut_entry->lut_id);

		dev_info(nse_hw_to_dev(hw), "Start add advanced node to lut[%d], is_root = %d\n",
			lut_entry->lut_id, !!is_root);
		dev_info(nse_hw_to_dev(hw), "\t is_lg_act = %d, action/lg_id = 0x%x\n",
			!!(le16_to_cpu(lut_node->left_ptr) & NSE_LUT_NODE_LARGE_ACTION_EN),
			le16_to_cpu(lut_node->action));
		dev_info(nse_hw_to_dev(hw), "\t key_value[0~4]: [0x%x, 0x%x, 0x%x, 0x%x, 0x%x,]\n",
			le16_to_cpu(lut_node->key[0]), le16_to_cpu(lut_node->key[1]),
			le16_to_cpu(lut_node->key[2]), le16_to_cpu(lut_node->key[3]),
			le16_to_cpu(lut_node->key[4]));
		rt_status = nse_aq_lut_nodes(hw, buf, buf_size,
					 NSE_AQ_OPC_ADD_LUT_NODE, NULL);
		if (rt_status) {
			dev_err(nse_hw_to_dev(hw),
				"Failed to add nse_aq_lut_nodes\n");
			status = -EIO;
			goto err_nse_add_adv_node;
		}
		dev_info(nse_hw_to_dev(hw), "\t return node_id = 0x%x\n",
			le16_to_cpu(lut_node->node_id));
		sub_node_id[i] = le16_to_cpu(lut_node->node_id);
		if (is_root)
			node_id = le16_to_cpu(lut_node->node_id);

		i++;
	}

add_adv_entry_to_sw_db:
	/* Step3: add adv entry to software filter DB */
	adv_fltr = devm_kzalloc(nse_hw_to_dev(hw),
				sizeof(struct nse_adv_fltr_mgmt_list_entry),
				GFP_KERNEL);
	if (!adv_fltr) {
		status = -ENOMEM;
		goto err_nse_add_adv_node;
	}

	if (lkups_cnt) {
		adv_fltr->lkups = devm_kmemdup(nse_hw_to_dev(hw), lkups,
					       lkups_cnt * sizeof(*lkups),
					       GFP_KERNEL);
	} else {
		adv_fltr->lkups = NULL;
	}

	if (!adv_fltr->lkups) {
		status = -ENOMEM;
		goto err_nse_add_adv_node;
	}

	adv_fltr->lkups_cnt = lkups_cnt;
	rinfo->node_state->is_fast_created = is_fast_created;
	adv_fltr->node_info = *rinfo;

	/* root node id & chained sub lut node id, used for removing */
	adv_fltr->node_info.fltr_node_id = node_id;
	memcpy(adv_fltr->node_info.sub_fltr_node_id, sub_node_id,
		sizeof(sub_node_id));

	/* Add rule entry to software DB list */
	sw = hw->switch_info;
	sw->lut_list[lut_id].adv_rule = true;
	rule_head = &sw->lut_list[lut_id].filt_rules;
	list_add_tail(&adv_fltr->list_entry, rule_head);

	if (added_entry) {
		added_entry->lut_id = lut_id;
		added_entry->node_id = adv_fltr->node_info.fltr_node_id;
	}

err_nse_add_adv_node:

	mutex_unlock(rule_lock);

	if (status && adv_fltr) {
		if (adv_fltr->lkups)
			devm_kfree(nse_hw_to_dev(hw), adv_fltr->lkups);
		devm_kfree(nse_hw_to_dev(hw), adv_fltr);
	}

	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return status;
}

/**
 * nse_init_node_state - initial node state some non-zero field.
 *
 * @node_state: node state obj, which need initial.
 */
void
nse_init_node_state(struct nse_node_state *node_state)
{
	int i;

	node_state->node_state_id = NSE_NODE_STATE_ID_INVALID;
	node_state->task_list_id = NSE_TASK_LIST_ID_INVALID;
	node_state->is_lite = false;
	node_state->is_slowpath = false;
	node_state->is_fast = false;
	node_state->is_fast_created = false;
	node_state->is_slowp_orig = false;
	for (i = 0; i < NSE_MAX_DU_DESC_NUM; i++)
		node_state->du_desc[i].du_data_id = NSE_DU_DATA_ID_INVALID;
}

/**
 * nse_rem_adv_fast_node - removes existing advanced fast node
 *
 * @hw: pointer to the hardware structure
 * @remove_entry: data struct which holds rule_id, VSI handle and recipe ID
 *
 */
int
nse_rem_adv_fast_node(struct nse_hw *hw,
				struct nse_node_query_data *remove_entry)
{
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_lut_info *lut_info = &sw->lut_list[remove_entry->lut_id];
	struct nse_lut_grp_entry *lut_entry;
	struct nse_adv_node_info *node_info;
	struct nse_adv_fltr_mgmt_list_entry *list_elem;
	struct nse_aqc_lut_fast_nodes *buf;
	struct nse_node_state *node_state = NULL;
	struct nse_aqc_lut_fast_node_elem *fast_node = NULL;
	struct nse_aqc_lut_fast_node_action *action = NULL;
	struct nse_aqc_lut_fast_node_match *match = NULL;
	struct mutex *rule_lock;
	enum nse_status status;
	u16 lut_id = remove_entry->lut_id;
	u16 du_act_cnt = 0, buf_size;
	u16 act_ctrl = 0;
	u8 n_grp_count = 0, lut_idx = 0;
	int ret = 0, i;

	if (!lut_info || !lut_info->lut_created) {
		dev_err(nse_hw_to_dev(hw), "rem_lut[%d] is not created\n", lut_id);
		return -EINVAL;
	}

	rule_lock = &lut_info->filt_rule_lock;
	mutex_lock(rule_lock);
	list_elem = nse_find_adv_rule_entry_by_id(hw, lut_id, remove_entry->node_id);
	if (!list_elem) {
		dev_info(nse_hw_to_dev(hw), "adv rule is already removed\n");
		ret = 0;
		goto err_nse_rem_fast_node;
	}

	node_info = &list_elem->node_info;
	node_state = node_info->node_state;
	if (!node_state) {
		dev_err(nse_hw_to_dev(hw), "Node state is NULL when del fast node\n");
		ret = -EIO;
		goto err_nse_rem_fast_node;
	}

	du_act_cnt = node_state->du_act_cnt;
	n_grp_count = lut_info->n_grp_count;
	buf_size = struct_size(buf, elem, 1) +
			   struct_size(action, act, du_act_cnt) +
			   struct_size(match, lut, n_grp_count);

	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto err_nse_rem_fast_node;
	}

	buf->count = cpu_to_le16(1);
	fast_node = buf->elem;

	/*start to handle action field*/
	action = &fast_node->action;
	act_ctrl |= (du_act_cnt << NSE_FAST_ACT_DU_CNT_S) &
					NSE_FAST_ACT_DU_CNT_M;
	for (i = 0; i < du_act_cnt; i++) {
		struct nse_du_action *du_action = &node_state->du_action[i];
		u16 act = 0;
		u16 res_type = NSE_FAST_ACT_INV_RES_TYPE;

		switch (du_action->du_act) {
		case NSE_DU_ACT_COUNT_BYTE:
			act |= NSE_SINGLE_COUNT_BYTE;
			fallthrough;
		case NSE_DU_ACT_COUNT_PACKET:
			nse_set_du_action_count(du_action, &act, &act_ctrl);
			res_type = NSE_AQC_RES_TYPE_COUNTER_ID;
			break;
		case NSE_DU_ACT_DROP_PACKET:
			nse_set_du_action_drop(&act);
			break;
		case NSE_DU_ACT_FWD_TO_LAN:
			nse_set_du_action_tolan(du_action, &act);
			break;
		case NSE_DU_ACT_FWD_TO_VSI:
			nse_set_du_action_tovsi(du_action, &act);
			break;
		default:
			dev_err(nse_hw_to_dev(hw),
				"Du action type is not supported when add adv fast node, type = %d!\n",
				du_action->du_act);
			goto err_nse_rem_fast_node;
		}

		action->act[i].action = cpu_to_le16(act);
		action->act[i].res_type = cpu_to_le16(res_type);
	}

	action->node_state_id = cpu_to_le16(node_state->node_state_id);
	action->act_ctrl = cpu_to_le16(act_ctrl);

	/*start to handle match field*/
	match = (struct nse_aqc_lut_fast_node_match *)((void *)fast_node
				+ struct_size(action, act, du_act_cnt));
	match->lut_num = n_grp_count;
	lut_idx = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_aqc_fast_lut_info *lut = &match->lut[lut_idx];

		if (lut_idx >= NSE_MAX_SUB_NODE_NUM) {
			dev_err(nse_hw_to_dev(hw),
				"Too many sub recipes to be supported in fast node\n");
			ret = -EINVAL;
			goto err_nse_rem_fast_node;
		}

		lut->lut_id = cpu_to_le16(lut_entry->lut_id);
		lut->node_id = cpu_to_le16(node_info->sub_fltr_node_id[lut_idx]);
		lut_idx++;
	}

	dev_info(nse_hw_to_dev(hw), "Start to remove fast node to hw: count = %d\n",
		 le16_to_cpu(buf->count));
	dev_info(nse_hw_to_dev(hw), "\t Action Part:\n");
	dev_info(nse_hw_to_dev(hw), "\t\t node_state_id = %d, act_ctl = %d\n",
		le16_to_cpu(action->node_state_id),  le16_to_cpu(action->act_ctrl));
	for (i = 0; i < du_act_cnt; i++)
		dev_info(nse_hw_to_dev(hw), "\t\t Action[%d]: act_val = 0x%x, res_type = %d\n",
			i, le16_to_cpu(action->act[i].action),
				le16_to_cpu(action->act[i].res_type));

	dev_info(nse_hw_to_dev(hw), "\t Match Part:\n");
	dev_info(nse_hw_to_dev(hw), "\t\t lut_num = %d\n", match->lut_num);
	lut_idx = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		struct nse_aqc_fast_lut_info *lut = &match->lut[lut_idx];

		dev_info(nse_hw_to_dev(hw),
			"\t\t Lut[%d]: lut_id = %d, node_id = %d\n",
			lut_idx, le16_to_cpu(lut->lut_id), le16_to_cpu(lut->node_id));
		lut_idx++;
	}

	/* request fast node adminq cmd */
	status = nse_aq_fast_nodes(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_LUT_FAST_NODE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to remove nse_aq_fast_nodes\n");
		ret = -EIO;
		goto err_nse_rem_fast_node;
	}

	/* release software adv entry memory */
	list_del(&list_elem->list_entry);
	devm_kfree(nse_hw_to_dev(hw), list_elem->lkups);
	devm_kfree(nse_hw_to_dev(hw), list_elem);
	if (list_empty(&sw->lut_list[lut_id].filt_rules))
		sw->lut_list[lut_id].adv_rule = false;

err_nse_rem_fast_node:

	mutex_unlock(rule_lock);
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return ret;
}

/**
 * nse_rem_adv_node_by_id - removes existing advanced switch node by ID
 * @hw: pointer to the hardware structure
 * @remove_entry: data struct which holds rule_id, VSI handle and recipe ID
 *
 * This function is used to remove 1 rule at a time. The removal is based on
 * the remove_entry parameter. This function will remove rule for a given
 * vsi_handle with a given rule_id which is passed as parameter in remove_entry
 */
int
nse_rem_adv_node_by_id(struct nse_hw *hw,
		       struct nse_node_query_data *remove_entry)
{
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_aqc_lut_nodes *buf;
	struct nse_aqc_lut_node_elem *lut_node;
	struct nse_lut_info *lut_info = &sw->lut_list[remove_entry->lut_id];
	struct nse_lut_grp_entry *lut_entry;
	struct nse_adv_node_info *node_info;
	struct nse_adv_fltr_mgmt_list_entry *list_elem;
	struct mutex *rule_lock;
	enum nse_status status;
	u16 lut_id = remove_entry->lut_id;
	u16 buf_size, i;
	int ret = 0;

	if (!lut_info || !lut_info->lut_created) {
		dev_err(nse_hw_to_dev(hw), "rem_lut[%d] is not created\n", lut_id);
		return -EINVAL;
	}

	rule_lock = &lut_info->filt_rule_lock;

	mutex_lock(rule_lock);
	list_elem = nse_find_adv_rule_entry_by_id(hw, lut_id, remove_entry->node_id);
	if (!list_elem) {
		dev_info(nse_hw_to_dev(hw), "adv rule is already removed\n");
		ret = 0;
		goto err_nse_rem_adv_rule;
	}

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto err_nse_rem_adv_rule;
	}

	node_info = &list_elem->node_info;
	buf->count = cpu_to_le16(1);
	lut_node = buf->elem;
	i = 0;
	list_for_each_entry(lut_entry, &lut_info->lut_group_list, l_entry) {
		lut_node->lut_id = cpu_to_le16(lut_entry->lut_id);
		lut_node->node_id = cpu_to_le16(node_info->sub_fltr_node_id[i]);

		status = nse_aq_lut_nodes(hw, buf, buf_size,
					 NSE_AQ_OPC_REMOVE_LUT_NODE, NULL);
		if (status && status != NSE_ERR_DOES_NOT_EXIST) {
			dev_err(nse_hw_to_dev(hw), "Failed to remove lut[%d] node_id[%d]\n",
				lut_entry->lut_id, node_info->sub_fltr_node_id[i]);
			ret = -EIO;
			goto err_nse_rem_adv_rule;
		}
		dev_info(nse_hw_to_dev(hw), "Success to remove lut[%d] node_id[%d]\n",
			lut_entry->lut_id, node_info->sub_fltr_node_id[i]);
		i++;
	}

	/* release software adv entry memory */
	list_del(&list_elem->list_entry);
	devm_kfree(nse_hw_to_dev(hw), list_elem->lkups);
	devm_kfree(nse_hw_to_dev(hw), list_elem);
	if (list_empty(&sw->lut_list[lut_id].filt_rules))
		sw->lut_list[lut_id].adv_rule = false;

err_nse_rem_adv_rule:

	mutex_unlock(rule_lock);
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return ret;
}

/**
 * nse_sw_init_counter - initial a counter for statistic
 * @hw: pointer to the hardware structure
 * @counter: pointer to the counter structure
 * @aging: aging is enable or not
 */
static enum nse_status
nse_sw_init_counter(struct nse_hw *hw, struct nse_sw_stats *sw_stats,
			struct nse_sw_counter *counter, bool aging)
{
	int err;

	INIT_LIST_HEAD(&counter->list);

	if (aging) {
		u32 id = counter->hw_id;

		counter->cache.lastuse = jiffies;
		counter->last_val = counter->cache.val;
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Start to idr_alloc_u32, id = %d\n",
			__func__, __LINE__, id);
		idr_preload(GFP_KERNEL);
		spin_lock(&sw_stats->counters_idr_lock);

		err = idr_alloc_u32(&sw_stats->counters_idr, counter, &id, id,
				    GFP_NOWAIT);

		spin_unlock(&sw_stats->counters_idr_lock);
		idr_preload_end();
		if (err) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] counters_idr idr_alloc_u32 err, err = %d, id = %d\n",
				__func__, __LINE__, err, id);
			return NSE_ERR_NO_MEMORY;
		}

		llist_add(&counter->addlist, &sw_stats->addlist);
	}

	return NSE_SUCCESS;
}

/**
 * nse_sw_creat_counter_pair - creat a counter pair for statistic
 * @hw: pointer to the hardware structure
 * @aging: aging is enable or not
 */
struct nse_sw_counter_pair *
nse_sw_creat_counter_pair(struct nse_hw *hw, bool aging)
{
	struct nse_sw_counter_pair *counter_p = NULL;
	enum nse_status status = NSE_SUCCESS;
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;

	counter_p = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*counter_p),
				 GFP_KERNEL);
	if (!counter_p)
		goto creat_counter_fail;

	status = nse_aq_alloc_free_counter_pair(hw, &counter_p->p_counter.hw_id,
		&counter_p->b_counter.hw_id, NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status)
		goto creat_counter_fail;

	status = nse_sw_init_counter(hw, sw_stats, &counter_p->p_counter, aging);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] nse_sw_init_counter err, err = %d, hw_id = %d\n",
			__func__, __LINE__, status, counter_p->p_counter.hw_id);
		goto init_counter_fail;
	}

	status = nse_sw_init_counter(hw, sw_stats, &counter_p->b_counter, aging);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] nse_sw_init_counter err, err = %d, hw_id = %d\n",
			__func__, __LINE__, status, counter_p->b_counter.hw_id);
		goto init_counter_fail;
	}

	counter_p->p_counter.cnt_type = NSE_SW_CNTR_TYPE_PACKET;
	counter_p->b_counter.cnt_type = NSE_SW_CNTR_TYPE_BYTE;
	counter_p->aging = aging;

	if (aging)
		mod_delayed_work(sw_stats->wq, &sw_stats->work, 0);

	return counter_p;

init_counter_fail:
	nse_aq_alloc_free_counter_pair(hw, &counter_p->p_counter.hw_id,
		&counter_p->b_counter.hw_id, NSE_AQ_OPC_FREE_RESOURCE);

creat_counter_fail:
	if (!counter_p)
		devm_kfree(nse_hw_to_dev(hw), counter_p);

	return NULL;
}

/**
 * nse_sw_creat_fast_counter_p - creat a counter pair for statistic for fast node
 * @hw: pointer to the hardware structure
 * @p_hw_id: packet counter hw id
 * @b_hw_id: byte counter hw id
 * @aging: aging is enable or not
 */
struct nse_sw_counter_pair *
nse_sw_creat_fast_counter_p(struct nse_hw *hw,
			u16 p_hw_id, u16 b_hw_id, bool aging)
{
	struct nse_sw_counter_pair *counter_p = NULL;
	enum nse_status status = NSE_SUCCESS;
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;

	counter_p = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*counter_p),
				 GFP_KERNEL);
	if (!counter_p)
		goto creat_counter_fail;

	counter_p->p_counter.hw_id = p_hw_id;
	counter_p->b_counter.hw_id = b_hw_id;

	status = nse_sw_init_counter(hw, sw_stats, &counter_p->p_counter, aging);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] nse_sw_init_counter err, err = %d, hw_id = %d\n",
			__func__, __LINE__, status, counter_p->p_counter.hw_id);
		goto init_counter_fail;
	}

	status = nse_sw_init_counter(hw, sw_stats, &counter_p->b_counter, aging);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] nse_sw_init_counter err, err = %d, hw_id = %d\n",
			__func__, __LINE__, status, counter_p->b_counter.hw_id);
		goto init_counter_fail;
	}

	counter_p->p_counter.cnt_type = NSE_SW_CNTR_TYPE_PACKET;
	counter_p->b_counter.cnt_type = NSE_SW_CNTR_TYPE_BYTE;
	counter_p->aging = aging;
	counter_p->fast_node = true;

	if (aging)
		mod_delayed_work(sw_stats->wq, &sw_stats->work, 0);

	return counter_p;

init_counter_fail:
creat_counter_fail:
	if (!counter_p)
		devm_kfree(nse_hw_to_dev(hw), counter_p);

	return NULL;
}

/**
 * nse_sw_free_counter_pair - free a counter pair resource and mem
 * @hw: pointer to the hardware structure
 * @counter_p: the counter pair that is needed to destroy
 */
static enum nse_status
nse_sw_free_counter_pair(struct nse_hw *hw,
	struct nse_sw_counter_pair *counter_p)
{
	enum nse_status status = NSE_SUCCESS;

	if (!counter_p->fast_node)
		status = nse_aq_alloc_free_counter_pair(hw,
				&counter_p->p_counter.hw_id,
				&counter_p->b_counter.hw_id,
				NSE_AQ_OPC_FREE_RESOURCE);

	devm_kfree(nse_hw_to_dev(hw), counter_p);

	return status;
}

/**
 * nse_sw_destroy_counter_pair - destroy a counter pair
 * @hw: pointer to the hardware structure
 * @counter: the counter pair that is needed to destroy
 */
int
nse_sw_destroy_counter_pair(struct nse_hw *hw,
	struct nse_sw_counter_pair *counter_p)
{
	enum nse_status status = NSE_SUCCESS;
	int ret = 0;
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;

	if (counter_p->aging) {
		llist_add(&counter_p->dellist, &sw_stats->dellist);
		mod_delayed_work(sw_stats->wq, &sw_stats->work, 0);
		return ret;
	}

	status = nse_sw_free_counter_pair(hw, counter_p);

	if (status)
		ret = -EIO;

	return ret;
}

/**
 * nse_sw_counters_lookup_next - lookup counter obj from id+1.
 * @hw: pointer to the hardware structure
 * @id: current counter hw id
 */
static struct list_head *
nse_sw_counters_lookup_next(struct nse_hw *hw, u16 id)
{
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
	unsigned long next_id = (unsigned long)id + 1;
	struct nse_sw_counter *counter;
	unsigned long tmp;

	rcu_read_lock();
	/* find the existed counter that is already in counter list from id+1.
	 * skip counters that are in idr, but not yet in counters list.
	 */
	idr_for_each_entry_continue_ul(&sw_stats->counters_idr,
					   counter, tmp, next_id) {
		if (!list_empty(&counter->list))
			break;
	}
	rcu_read_unlock();

	return counter ? &counter->list : &sw_stats->counters;
}

/**
 * nse_sw_stats_insert - insert counter from addlist to counter list
 * @hw: pointer to the hardware structure
 * @counter: pointer to the counter structure
 */
static void
nse_sw_stats_insert(struct nse_hw *hw, struct nse_sw_counter *counter)
{
	struct list_head *next = nse_sw_counters_lookup_next(hw, counter->hw_id);
	/* list add tail is Insert a new entry before the specified head.
	 *  it is order counters list, based on hw_id that from little to big.
	 */
	list_add_tail(&counter->list, next);
}

/**
 * nse_sw_stats_remove - remove counter from counter list
 * @hw: pointer to the hardware structure
 * @counter: pointer to the counter structure
 */
static void
nse_sw_stats_remove(struct nse_hw *hw,
				struct nse_sw_counter *counter)
{
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;

	list_del(&counter->list);

	spin_lock(&sw_stats->counters_idr_lock);
	WARN_ON(!idr_remove(&sw_stats->counters_idr, counter->hw_id));
	spin_unlock(&sw_stats->counters_idr_lock);
}

/**
 * nse_sw_stats_remove_pair - remove counter pair
 * @hw: pointer to the hardware structure
 * @counter_p: pointer to the counter pair structure
 */
void
nse_sw_stats_remove_pair(struct nse_hw *hw,
				struct nse_sw_counter_pair *counter_p)
{
	nse_sw_stats_remove(hw, &counter_p->p_counter);
	nse_sw_stats_remove(hw, &counter_p->b_counter);
}

/**
 * nse_sw_stats_read_range -
 *	read continuous range counters from hw.
 * @first: first counter obj need to read.
 * @last_hw_id: last counter hw id need to read.
 */
static enum nse_status
nse_sw_stats_read_range(struct nse_hw *hw,
			struct nse_sw_counter *first, u16 last_hw_id)
{
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
	bool need_query = (first->hw_id <= last_hw_id);
#ifdef NSE_SUPPORT_DMA_RD_STATS
	struct nse_aqc_sw_dma_counters *buf;
	struct nse_dma_mem *dma = &sw_stats->dma_buf;
#else
	struct nse_aqc_sw_counters *buf;
#endif
	struct nse_aqc_sw_counter_elem *elem;
	enum nse_status status = NSE_SUCCESS;
	u16 buf_size, cntr_num;
#ifndef NSE_SUPPORT_RD_STATS_ASYN
	struct nse_sw_counter *counter = first;
	u16 i = 0;
#endif

	if (!need_query) {
		dev_info(nse_hw_to_dev(hw),	"There is no counter need to query!\n");
		return status;
	}

	cntr_num = last_hw_id - first->hw_id + 1;
#ifdef NSE_SUPPORT_DMA_RD_STATS
	buf_size = sizeof(*buf);
#else
	buf_size = struct_size(buf, elem, cntr_num);
#endif
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return NSE_ERR_NO_MEMORY;

#ifdef NSE_SUPPORT_DMA_RD_STATS
	elem = (struct nse_aqc_sw_counter_elem *)dma->va;
	buf->count = cpu_to_le16(cntr_num);
	buf->start_id = cpu_to_le16(first->hw_id);
	buf->addr_low = cpu_to_le32(lower_32_bits(dma->pa));
	buf->addr_high = cpu_to_le32(upper_32_bits(dma->pa));
#else
	elem = buf->elem;
	buf->count = cpu_to_le16(cntr_num);
	buf->start_id = cpu_to_le16(first->hw_id);
#endif

	mutex_lock(&sw_stats->rd_lock);
	status = nse_aq_get_counter_val(hw, buf, buf_size);
	if (status) {
		dev_err(nse_hw_to_dev(hw),	"Failed to query counter val, err = %d\n", status);
		goto read_range_fail;
	}

#ifndef NSE_SUPPORT_RD_STATS_ASYN
#ifdef NSE_SUPPORT_DMA_RD_STATS
	list_for_each_entry_from(counter, &sw_stats->counters, list) {
		u16 index = counter->hw_id;

		if (++i > cntr_num || index >= NSE_MAX_DMA_RD_STATS_NUM)
			break;

		/*update hw val to cache*/
		counter->cache.val = le64_to_cpu(elem[index].counter_val);
		counter->cache.lastuse = jiffies;
	}
#else
	list_for_each_entry_from(counter, &sw_stats->counters, list) {
		u16 index = counter->hw_id - first->hw_id;

		if (++i > cntr_num || index >= cntr_num)
			break;

		/*update hw val to cache*/
		counter->cache.val = le64_to_cpu(elem[index].counter_val);
		counter->cache.lastuse = jiffies;
	}

#endif
#endif

read_range_fail:
	mutex_unlock(&sw_stats->rd_lock);

	devm_kfree(nse_hw_to_dev(hw), buf);
	return status;
}

/**
 * nse_sw_stats_read_event -
 *	 handle function to process fw read stats event.
 * @hw: pointer to the hardware structure.
 * @event: event info from fw.
 */
void
nse_sw_stats_read_event(struct nse_hw *hw,
			struct nse_rq_event_info *event)
{
#if defined(NSE_SUPPORT_RD_STATS_ASYN) && defined(NSE_SUPPORT_DMA_RD_STATS)
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
	struct nse_sw_counter *counter = NULL;
	struct nse_aqc_sw_counter_elem *elem;
	struct nse_aqc_sw_dma_counters *buf;
	struct nse_dma_mem *dma = &sw_stats->dma_buf;
	u16 start_id, cntr_num, i = 0;

	if (!event->msg_buf)
		return;

	elem = (struct nse_aqc_sw_counter_elem *)dma->va;
	buf = (struct nse_aqc_sw_dma_counters *)event->msg_buf;
	start_id = le16_to_cpu(buf->start_id);
	cntr_num = le16_to_cpu(buf->count);

	mutex_lock(&sw_stats->rd_lock);

	/* lookup the first counter according to start_id */
	rcu_read_lock();
	counter = idr_find(&sw_stats->counters_idr, start_id);
	rcu_read_unlock();

	if (!counter) {
		mutex_unlock(&sw_stats->rd_lock);
		return;
	}

	list_for_each_entry_from(counter, &sw_stats->counters, list) {
		u16 index = counter->hw_id;

		if (++i > cntr_num || index >= NSE_MAX_DMA_RD_STATS_NUM)
			break;

		/*update hw val to cache*/
		counter->cache.val = le64_to_cpu(elem[index].counter_val);
		counter->cache.lastuse = jiffies;
	}
	mutex_unlock(&sw_stats->rd_lock);

	return;

#else

	return;
#endif
}

/**
 * nse_sw_stats_work - switch stat work's handle func
 * @work: pointer to switch stat work structure
 */
static void nse_sw_stats_work(struct work_struct *work)
{
	struct nse_switch_info *sw = container_of(work, struct nse_switch_info,
						 sw_stats.work.work);
	struct nse_sw_stats *sw_stats = &sw->sw_stats;
	struct nse_hw *hw = sw->hw;

	/* Take dellist first to ensure that counters cannot be deleted before
	 * they are inserted.
	 */
	struct llist_node *dellist = llist_del_all(&sw_stats->dellist);
	struct llist_node *addlist = llist_del_all(&sw_stats->addlist);
	struct nse_sw_counter *counter = NULL, *last = NULL;
	struct nse_sw_counter_pair *counter_p = NULL, *tmp_p;

	unsigned long now = jiffies;

	if (addlist || !list_empty(&sw_stats->counters))
		queue_delayed_work(sw_stats->wq, &sw_stats->work,
				   sw_stats->sampling_interval);

	/*protect read counter event*/
	mutex_lock(&sw_stats->rd_lock);

	/*transfer counter obj from addlist to counter list*/
	llist_for_each_entry(counter, addlist, addlist)
		nse_sw_stats_insert(hw, counter);

	/*remove counter obj from counter list,
	 * it is counter pair obj in dellist.
	 */
	llist_for_each_entry_safe(counter_p, tmp_p, dellist, dellist) {
		dev_info(nse_hw_to_dev(hw), "Real to destroy hw cnt[%d] and cnt[%d]\n",
			counter_p->p_counter.hw_id,	counter_p->b_counter.hw_id);
		nse_sw_stats_remove_pair(hw, counter_p);
		nse_sw_free_counter_pair(hw, counter_p);
	}

	mutex_unlock(&sw_stats->rd_lock);

	if (time_before(now, sw_stats->next_query) ||
			list_empty(&sw_stats->counters))
		return;

	last = list_last_entry(&sw_stats->counters,
					struct nse_sw_counter, list);
	counter = list_first_entry(&sw_stats->counters,
					struct nse_sw_counter, list);

	/*read counter value from hw*/
	if (counter)
		nse_sw_stats_read_range(hw, counter, last->hw_id);

	sw_stats->next_query = now + sw_stats->sampling_interval;
}

void nse_sw_dump_stats(struct nse_hw *hw)
{
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;
	struct nse_sw_counter *counter = NULL;

	if (list_empty(&sw_stats->counters)) {
		dev_info(nse_hw_to_dev(hw),	"There is no counter!\n");
		return;
	}

	list_for_each_entry(counter, &sw_stats->counters, list)
		dev_info(nse_hw_to_dev(hw),
			"counter's hw_id = 0x%x, val = %llu, lastuse = %llu\n",
			counter->hw_id, counter->cache.val, counter->cache.lastuse);
}
/**
 * nse_init_fc_stats - initial switch statistic counter
 * @hw: pointer to the hardware structure
 */
enum nse_status nse_init_sw_stats(struct nse_hw *hw)
{
	struct nse_sw_stats *sw_stats = &hw->switch_info->sw_stats;

	if (nse_bypass_switch)
		return NSE_SUCCESS;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	spin_lock_init(&sw_stats->counters_idr_lock);
	idr_init(&sw_stats->counters_idr);
	INIT_LIST_HEAD(&sw_stats->counters);
	init_llist_head(&sw_stats->addlist);
	init_llist_head(&sw_stats->dellist);
	mutex_init(&sw_stats->rd_lock);

	sw_stats->dma_buf.size = NSE_MAX_DMA_RD_STATS_SIZE;
	sw_stats->dma_buf.va = dmam_alloc_coherent(nse_hw_to_dev(hw),
			sw_stats->dma_buf.size, &sw_stats->dma_buf.pa,
			GFP_KERNEL | __GFP_ZERO);
	if (!sw_stats->dma_buf.va) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to alloc stats dma read memory\n");
		goto err_dma_alloc;
	}

	sw_stats->wq = create_singlethread_workqueue("nse_sw_stats");
	if (!sw_stats->wq)
		goto err_wq_create;

	sw_stats->sampling_interval = NSE_SW_STATS_PERIOD;
	INIT_DELAYED_WORK(&sw_stats->work, nse_sw_stats_work);
	return NSE_SUCCESS;

err_wq_create:
	dmam_free_coherent(nse_hw_to_dev(hw), sw_stats->dma_buf.size,
			   sw_stats->dma_buf.va, sw_stats->dma_buf.pa);

err_dma_alloc:

	return NSE_ERR_NO_MEMORY;
}

void nse_cleanup_sw_stats(struct nse_hw *hw)
{
	struct nse_sw_stats *sw_stats = NULL;

	if (nse_bypass_switch)
		return;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return;

	sw_stats = &hw->switch_info->sw_stats;

	cancel_delayed_work_sync(&sw_stats->work);
	destroy_workqueue(sw_stats->wq);
	idr_destroy(&sw_stats->counters_idr);
	dmam_free_coherent(nse_hw_to_dev(hw), sw_stats->dma_buf.size,
			   sw_stats->dma_buf.va, sw_stats->dma_buf.pa);

	mutex_destroy(&sw_stats->rd_lock);

/*todo - @hujiwei, need free counter software resource and hw_id*/
}

/**
 * nse_sw_add_lite_node_state - add a lite node state to hw
 * @hw: pointer to the hardware structure
 * @node_state: software node state information
 * @du_act_cnt: du action count
 */
int
nse_sw_add_lite_node_state(struct nse_hw *hw,
				struct nse_node_state *node_state, u16 du_act_cnt)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_lite_node_states *buf = NULL;
	struct nse_aqc_lite_node_state_elem *elem;
	u16 node_state_id = NSE_NODE_STATE_ID_INVALID;
	u16 ctrl_info = 0;
	u16 i, j, buf_size;

	if (du_act_cnt > NSE_MAX_LITE_DU_ACTION_NUM) {
		dev_err(nse_hw_to_dev(hw),
			"lite Du Action num exceeds 3, du_act_cnt = %d\n", du_act_cnt);
		return -EINVAL;
	}

	/*1. alloc a node state id first */
	status = nse_aq_alloc_free_lite_node_state(hw, &node_state_id,
			NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status || node_state_id == NSE_NODE_STATE_ID_INVALID) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to alloc lite node_state_id, err = %d, id = %d\n",
			status, node_state_id);
		return -ENOMEM;
	}

	/* 2. build aqc buf of node state */
	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto nse_sw_add_lite_node_state_fail;
	}
	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->node_state_id = cpu_to_le16(node_state_id);

	/* 2.1 handle du_action */
	for (i = 0; i < du_act_cnt; i++) {
		struct nse_du_action *du_action;
		u16 act = 0;

		du_action = &node_state->du_action[i];

		switch (du_action->du_act) {
		case NSE_DU_ACT_FWD_TO_VSI:
			nse_set_du_action_tovsi(du_action, &act);
			break;
		case NSE_DU_ACT_FWD_TO_VSI_LIST:
			nse_set_du_action_tovlist(du_action, &act);
			break;
		case NSE_DU_ACT_FWD_TO_LAN:
			nse_set_du_action_tolan(du_action, &act);
			break;
		case NSE_DU_ACT_DROP_PACKET:
			nse_set_du_action_drop(&act);
			break;
		case NSE_DU_ACT_COUNT_BYTE:
			/* set count type to byte count, default is pkt count */
			act |= NSE_SINGLE_COUNT_BYTE;
			fallthrough;
		case NSE_DU_ACT_COUNT_PACKET:
			nse_set_du_action_count(du_action, &act, &ctrl_info);
			break;
		case NSE_DU_ACT_METER:
			nse_set_du_action_meter(du_action, &act);
			break;
		case NSE_DU_ACT_DECAP:
			nse_set_du_action_decap(&act);
			break;
		case NSE_DU_ACT_DUP:
			nse_set_du_action_dup(du_action, &act);
			break;
		case NSE_DU_ACT_GOTO_CHAIN:
			nse_set_du_action_goto(du_action, &act);
			break;
		case NSE_DU_ACT_SFLOW:
			nse_set_du_action_sflow(du_action, &act);
			break;
		case NSE_DU_ACT_SET_GENERIC_MD:
			/* set action type to set md action */
			act |= (NSE_SINGLE_ACT_TYPE_SET_MD <<
				NSE_SINGLE_ACT_TYPE_SET_MD_S) &
				NSE_SINGLE_ACT_TYPE_SET_MD_M;

			act |= (du_action->dest_mdid <<
				NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_S) &
				NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_M;

			/* word unit offset in node state*/
			act |= ((NSE_LITE_NODE_STATE_CTRL_WORD + i + node_state->md_num) <<
				NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_S) &
				NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_M;

			break;
		default:
			ret = -EIO;
			goto nse_sw_add_lite_node_state_fail;
		}

		elem->act[i] = cpu_to_le16(act);
	}

	for (j = 0; j < node_state->md_num; j++)
		elem->act[i++] = cpu_to_le16(node_state->md_value[j]);

	ctrl_info |= (du_act_cnt << NSE_AQC_DU_ACTION_CNT_S) &
				NSE_AQC_DU_ACTION_CNT_M;
	if (node_state->is_slowp_orig)
		ctrl_info |= NSE_AQC_LITE_SLOWPATH_ORIGINAL;

	dev_info(nse_hw_to_dev(hw),
			"Start to add lite node_state, id = %d\n", node_state_id);
	dev_info(nse_hw_to_dev(hw),
			"\t du_act_cnt = %d, md_num = %d\n", du_act_cnt, node_state->md_num);
	for (j = 0; j < i; j++)
		dev_info(nse_hw_to_dev(hw),
				"\t du action = 0x%x\n", le16_to_cpu(elem->act[j]));
	/*3. send add node state adminq cmd*/
	elem->ctrl_info = cpu_to_le16(ctrl_info);
	status = nse_aq_lite_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_LITE_NODE_STATE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to add node_state, err = %d, id = %d\n",
			status, node_state_id);
		ret = -EIO;
		goto nse_sw_add_lite_node_state_fail;
	}

	node_state->node_state_id = node_state_id;

	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;

nse_sw_add_lite_node_state_fail:
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	if (node_state_id != NSE_NODE_STATE_ID_INVALID)
		nse_aq_alloc_free_lite_node_state(hw, &node_state_id,
					NSE_AQ_OPC_FREE_RESOURCE);
	return ret;
}

/**
 * nse_sw_add_node_state - add a node state to hw
 * @hw: pointer to the hardware structure
 * @node_state: software node state information
 * @du_act_cnt: du action count
 * @au_task_cnt: au task count
 * @du_desc_cnt: du desc count
 */
int
nse_sw_add_node_state(struct nse_hw *hw,
				struct nse_node_state *node_state,
				u16 du_act_cnt, u16 au_task_cnt, u16 du_desc_cnt)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_node_states *buf = NULL;
	struct nse_aqc_node_state_elem *elem;
	u16 node_state_id = NSE_NODE_STATE_ID_INVALID;
	u16 ctrl_info = 0;
	u16 i, j, buf_size;

	if (du_act_cnt + du_desc_cnt  + node_state->md_num > NSE_MAX_TOTAL_DU_DESC_ACTION) {
		dev_err(nse_hw_to_dev(hw),
			"Du Action num exceeds 14, du_act_cnt = %d, du_desc_cnt = %d\n",
			du_act_cnt, du_desc_cnt);
		return -EINVAL;
	}

	/*1. alloc a node state id first */
	status = nse_aq_alloc_free_node_state_id(hw, &node_state_id,
			NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status || node_state_id == NSE_NODE_STATE_ID_INVALID) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to alloc node_state_id, err = %d, id = %d\n",
			status, node_state_id);
		return -ENOMEM;
	}

	/* 2. build aqc buf of node state */
	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto nse_sw_add_node_state_fail;
	}
	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->node_state_id = cpu_to_le16(node_state_id);

	/* 2.1 handle du_action */
	for (i = 0; i < du_act_cnt; i++) {
		struct nse_du_action *du_action;
		u16 act = 0;

		du_action = &node_state->du_action[i];

		switch (du_action->du_act) {
		case NSE_DU_ACT_FWD_TO_VSI:
			nse_set_du_action_tovsi(du_action, &act);
			break;
		case NSE_DU_ACT_FWD_TO_VSI_LIST:
			nse_set_du_action_tovlist(du_action, &act);
			break;
		case NSE_DU_ACT_FWD_TO_LAN:
			nse_set_du_action_tolan(du_action, &act);
			break;
		case NSE_DU_ACT_DROP_PACKET:
			nse_set_du_action_drop(&act);
			break;
		case NSE_DU_ACT_COUNT_BYTE:
			/* set count type to byte count, default is pkt count */
			act |= NSE_SINGLE_COUNT_BYTE;
			fallthrough;
		case NSE_DU_ACT_COUNT_PACKET:
			nse_set_du_action_count(du_action, &act, &ctrl_info);
			break;
		case NSE_DU_ACT_METER:
			nse_set_du_action_meter(du_action, &act);
			break;
		case NSE_DU_ACT_DECAP:
			nse_set_du_action_decap(&act);
			break;
		case NSE_DU_ACT_DUP:
			nse_set_du_action_dup(du_action, &act);
			break;
		case NSE_DU_ACT_GOTO_CHAIN:
			nse_set_du_action_goto(du_action, &act);
			break;
		case NSE_DU_ACT_SFLOW:
			nse_set_du_action_sflow(du_action, &act);
			break;
		case NSE_DU_ACT_SET_GENERIC_MD:
			/* set action type to set md action */
			act |= (NSE_SINGLE_ACT_TYPE_SET_MD <<
				NSE_SINGLE_ACT_TYPE_SET_MD_S) &
				NSE_SINGLE_ACT_TYPE_SET_MD_M;

			act |= (du_action->dest_mdid <<
				NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_S) &
				NSE_SINGLE_ACT_TYPE_SET_MD_DST_ID_M;

			/* word unit offset in node state*/
			if (au_task_cnt)
				act |= ((NSE_TASK_LIST_WORD_SIZE +
					NSE_FULL_NODE_STATE_CTRL_WORD +	i +
						node_state->md_num + du_desc_cnt) <<
					NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_S) &
					NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_M;
			else
				act |= ((NSE_FULL_NODE_STATE_CTRL_WORD + i + node_state->md_num) <<
					NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_S) &
					NSE_SINGLE_ACT_TYPE_SET_MD_SRC_SELECT_M;

			break;
		default:
			ret = -EIO;
			goto nse_sw_add_node_state_fail;
		}

		elem->act_or_desc[i] = cpu_to_le16(act);
	}

	ctrl_info |= (du_act_cnt << NSE_AQC_DU_ACTION_CNT_S) &
				NSE_AQC_DU_ACTION_CNT_M;

	/* 2.2 handle au task & du data */
	if (au_task_cnt) {
		ctrl_info |= (au_task_cnt << NSE_AQC_AU_TASK_CNT_S) &
				NSE_AQC_AU_TASK_CNT_M;
		elem->task_list_id =
			cpu_to_le16(node_state->task_list_id & NSE_AQC_TSK_LST_ID_M);

		for (j = 0; j < du_desc_cnt; j++) {
			struct nse_du_desc *du_desc;
			u16 desc = 0;

			du_desc = &node_state->du_desc[j];

			switch (du_desc->data_size) {
			case NSE_DU_DATE_SIZE_32:
				desc |= (NSE_AQC_DU_DESC_SIZE_32B <<
					NSE_AQC_DU_DESC_SIZE_S) &
					NSE_AQC_DU_DESC_SIZE_M;
				break;

			case NSE_DU_DATE_SIZE_64:
				desc |= (NSE_AQC_DU_DESC_SIZE_64B <<
					NSE_AQC_DU_DESC_SIZE_S) &
					NSE_AQC_DU_DESC_SIZE_M;
				break;

			case NSE_DU_DATE_SIZE_96:
				desc |= (NSE_AQC_DU_DESC_SIZE_96B <<
					NSE_AQC_DU_DESC_SIZE_S) &
					NSE_AQC_DU_DESC_SIZE_M;
				break;

			case NSE_DU_DATE_SIZE_128:
				desc |= (NSE_AQC_DU_DESC_SIZE_128B <<
					NSE_AQC_DU_DESC_SIZE_S) &
					NSE_AQC_DU_DESC_SIZE_M;
				break;

			default:
				ret = -EIO;
				goto nse_sw_add_node_state_fail;
			}

			desc |= (du_desc->du_data_id <<
				NSE_AQC_DU_DESC_DATA_ID_S) &
				NSE_AQC_DU_DESC_DATA_ID_M;

			elem->act_or_desc[i++] = cpu_to_le16(desc);
		}

		ctrl_info |= (du_desc_cnt << NSE_AQC_DU_DESC_CNT_S) &
					NSE_AQC_DU_DESC_CNT_M;
	}

	for (j = 0; j < node_state->md_num; j++)
		elem->act_or_desc[i++] = cpu_to_le16(node_state->md_value[j]);

	if (node_state->is_slowp_orig)
		elem->task_list_id =
			cpu_to_le16(le16_to_cpu(elem->task_list_id) | NSE_AQC_SLOWPATH_ORIGINAL);

	dev_info(nse_hw_to_dev(hw),
			"Start to add node_state, id = %d\n", node_state_id);
	dev_info(nse_hw_to_dev(hw),
			"\t du_desc_cnt = %d, du_act_cnt = %d, au_task_cnt = %d, task_list_id = %d, md_num = %d\n",
			du_desc_cnt, du_act_cnt, au_task_cnt,
				le16_to_cpu(elem->task_list_id), node_state->md_num);
	for (j = 0; j < i; j++)
		dev_info(nse_hw_to_dev(hw),
				"\t du action OR du desc = 0x%x\n",
					le16_to_cpu(elem->act_or_desc[j]));
	/*3. send add node state adminq cmd*/
	elem->ctrl_info = cpu_to_le16(ctrl_info);
	status = nse_aq_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_NODE_STATE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to add node_state, err = %d, id = %d\n",
			status, node_state_id);
		ret = -EIO;
		goto nse_sw_add_node_state_fail;
	}

	node_state->node_state_id = node_state_id;

	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;

nse_sw_add_node_state_fail:
	if (buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	if (node_state_id != NSE_NODE_STATE_ID_INVALID)
		nse_aq_alloc_free_node_state_id(hw, &node_state_id,
					NSE_AQ_OPC_FREE_RESOURCE);
	return ret;
}

/**
 * nse_sw_rem_lite_node_state -
 *	remove a lite node state in hw, free the lite node state id
 * @hw: pointer to the hardware structure
 * @node_state_id: node state id that need to be removed.
 */
int
nse_sw_rem_lite_node_state(struct nse_hw *hw, u16 *node_state_id)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_lite_node_states *buf = NULL;
	struct nse_aqc_lite_node_state_elem *elem;
	u16 buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->node_state_id = cpu_to_le16(*node_state_id);

	status = nse_aq_lite_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_LITE_NODE_STATE, NULL);
	if (status)
		ret = -EIO;

	status = nse_aq_alloc_free_lite_node_state(hw, node_state_id,
				NSE_AQ_OPC_FREE_RESOURCE);
	if (status)
		ret = -EIO;

	return ret;
}

/**
 * nse_sw_rem_node_state -
 *	remove a node state in hw, free the node state id
 * @hw: pointer to the hardware structure
 * @node_state_id: node state id that need to be removed.
 */
int
nse_sw_rem_node_state(struct nse_hw *hw, u16 *node_state_id)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_node_states *buf = NULL;
	struct nse_aqc_node_state_elem *elem;
	u16 buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->node_state_id = cpu_to_le16(*node_state_id);

	status = nse_aq_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_NODE_STATE, NULL);
	if (status)
		ret = -EIO;

	status = nse_aq_alloc_free_node_state_id(hw, node_state_id,
				NSE_AQ_OPC_FREE_RESOURCE);
	if (status)
		ret = -EIO;

	return ret;
}

/**
 * nse_sw_slowpath_lite_node_state -enable/disable slowpath of a lite node state
 * @hw: pointer to the hardware structure
 * @node_state: pointer to node state information
 * @enable: true means enable slowpath, false means disable
 */
static int
nse_sw_slowpath_lite_node_state(struct nse_hw *hw,
		struct nse_node_state *node_state, bool enable)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_lite_node_states *buf = NULL;
	struct nse_aqc_lite_node_state_elem *elem;
	u16 buf_size, ctrl_info = 0;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->node_state_id = cpu_to_le16(node_state->node_state_id);

	status = nse_aq_lite_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_GET_LITE_NODE_STATE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to get lite node_state, err = %d, id = %d\n",
			status, node_state->node_state_id);
		ret = -EIO;
		goto nse_sw_slowpath_node_state_fail;
	}

	ctrl_info = le16_to_cpu(elem->ctrl_info);

	if (enable)
		ctrl_info |= NSE_AQC_LITE_SLOWPATH;
	else
		ctrl_info &= ~NSE_AQC_LITE_SLOWPATH;

	elem->ctrl_info = cpu_to_le16(ctrl_info);

	status = nse_aq_lite_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_UPDATE_LITE_NODE_STATE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to update lite node_state, err = %d, id = %d\n",
			status, node_state->node_state_id);
		ret = -EIO;
		goto nse_sw_slowpath_node_state_fail;
	}
nse_sw_slowpath_node_state_fail:
	return ret;
}

/**
 * nse_sw_slowpath_node_state -enable/disable slowpath of a node state
 * @hw: pointer to the hardware structure
 * @node_state: pointer to node state information
 * @enable: true means enable slowpath, false means disable
 */
static int
nse_sw_slowpath_node_state(struct nse_hw *hw,
		struct nse_node_state *node_state, bool enable)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_node_states *buf = NULL;
	struct nse_aqc_node_state_elem *elem;
	u16 buf_size, ctrl_info = 0;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->node_state_id = cpu_to_le16(node_state->node_state_id);

	status = nse_aq_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_GET_NODE_STATE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to get node_state, err = %d, id = %d\n",
			status, node_state->node_state_id);
		ret = -EIO;
		goto nse_sw_slowpath_node_state_fail;
	}

	/*note: slowpath bit is shared with tasklist field in normal node state*/
	ctrl_info = le16_to_cpu(elem->task_list_id);

	if (enable)
		ctrl_info |= NSE_AQC_SLOWPATH;
	else
		ctrl_info &= ~NSE_AQC_SLOWPATH;

	elem->task_list_id = cpu_to_le16(ctrl_info);

	status = nse_aq_node_states(hw, buf, buf_size,
				 NSE_AQ_OPC_UPDATE_NODE_STATE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to update node_state, err = %d, id = %d\n",
			status, node_state->node_state_id);
		ret = -EIO;
		goto nse_sw_slowpath_node_state_fail;
	}
nse_sw_slowpath_node_state_fail:
	return ret;
}

/**
 * nse_sw_set_slowpath -enable/disable slowpath of a given node state
 * @hw: pointer to the hardware structure
 * @node_state: pointer to node state information
 * @enable: true means enable slowpath, false means disable
 */
int
nse_sw_set_slowpath(struct nse_hw *hw,
		struct nse_node_state *node_state, bool enable)
{
	int err = 0;

	if (!node_state)
		return -EINVAL;

	if (node_state->is_lite) {
		dev_info(nse_hw_to_dev(hw), "Start to set slowpath in lite node state(id = %d): enable = %d\n",
			node_state->node_state_id, enable);

		err = nse_sw_slowpath_lite_node_state(hw, node_state, enable);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] set lite node state slowpath err, node state id = %d\n",
				__func__, __LINE__, node_state->node_state_id);
	} else {
		dev_info(nse_hw_to_dev(hw), "Start to set slowpath in node state(id = %d): enable = %d\n",
			node_state->node_state_id, enable);

		err = nse_sw_slowpath_node_state(hw, node_state, enable);
		if (err)
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] set node state slowpath err, node state id = %d\n",
				__func__, __LINE__, node_state->node_state_id);
	}
	return err;
}

/**
 * nse_sw_creat_du_data -creat a du data list,
 *			which contains several du descs.
 * @hw: pointer to the hardware structure
 * @d_size: total byte size of one filter action.
 */
struct nse_sw_du_data *
nse_sw_creat_du_data(struct nse_hw *hw, u16 d_size)
{
	struct nse_sw_du_data *du_data = NULL;
	struct nse_du_desc *du_desc;
	enum nse_status status = NSE_SUCCESS;
	struct nse_switch_info *sw = hw->switch_info;
	u16 i, cnt = 0, alloc_size;
	u16 data_size;

	if (!d_size || d_size > NSE_DU_DATE_SIZE_128)
		return NULL;

	/*one desc in du_data obj now, can be increased in future*/
	cnt = 1;

	data_size = ALIGN(d_size, 32);

	alloc_size = struct_size(du_desc, data, data_size) +
				sizeof(*du_data) - sizeof(*du_desc);

	du_data = devm_kzalloc(nse_hw_to_dev(hw), alloc_size, GFP_KERNEL);
	if (!du_data)
		goto nse_sw_creat_du_data_fail;

	du_data->du_desc_cnt = cnt;

	for (i = 0; i < cnt; i++)
		du_data->du_desc.data_size = data_size;

	status = nse_aq_alloc_free_du_data(hw, du_data,
				NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Alloc du data id err, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_du_data_fail;
	}

	dev_info(nse_hw_to_dev(hw), "Alloc du data id success, id = %d\n",
		du_data->du_desc.du_data_id);

	mutex_lock(&sw->du_data_lock);
	list_add_tail(&du_data->list_entry, &sw->ddata_list_head);
	mutex_unlock(&sw->du_data_lock);

	return du_data;

nse_sw_creat_du_data_fail:
	if (!du_data)
		devm_kfree(nse_hw_to_dev(hw), du_data);

	return NULL;
}

/**
 * nse_sw_destroy_du_data - destroy a du data
 * @hw: pointer to the hardware structure
 * @du_data: the du data that is needed to destroy
 */
int
nse_sw_destroy_du_data(struct nse_hw *hw,
	struct nse_sw_du_data *du_data)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_du_datas *buf = NULL;
	struct nse_aqc_du_data_elem *elem;
	int ret = 0;
	u16 buf_size;
	u16 data_size;

	data_size = du_data->du_desc.data_size;
	buf_size = struct_size(elem, usr_data, data_size) + sizeof(*buf);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->du_data_id = cpu_to_le16(du_data->du_desc.du_data_id);
	elem->data_len = cpu_to_le16(data_size >> NSE_AQC_DU_DATA_SHIFT);

	status = nse_aq_du_datas(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_DU_DATA, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Remove du data err, err = %d, id = %d, data_len = %d\n",
			__func__, __LINE__, status, du_data->du_desc.du_data_id, data_size);
		ret = -EIO;
	}

	status = nse_aq_alloc_free_du_data(hw, du_data,
				NSE_AQ_OPC_FREE_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Free du data id err, err = %d, id = %d\n",
			__func__, __LINE__, status, du_data->du_desc.du_data_id);
		ret = -EIO;
	}

	devm_kfree(nse_hw_to_dev(hw), buf);

	mutex_lock(&hw->switch_info->du_data_lock);
	list_del(&du_data->list_entry);
	mutex_unlock(&hw->switch_info->du_data_lock);

	devm_kfree(nse_hw_to_dev(hw), du_data);

	return ret;
}

/**
 * nse_sw_add_du_data - add du data content to HW
 * @hw: pointer to the hardware structure
 * @du_data: the du data that is needed to destroy
 */
int
nse_sw_add_du_data(struct nse_hw *hw,
	struct nse_sw_du_data *du_data)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_du_datas *buf = NULL;
	struct nse_aqc_du_data_elem *elem;

	u16 buf_size;
	u16 data_size;
	u32 i, data = 0;

	data_size = du_data->du_desc.data_size;
	buf_size = struct_size(elem, usr_data, data_size) + sizeof(*buf);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->du_data_id = cpu_to_le16(du_data->du_desc.du_data_id);
	elem->data_len = cpu_to_le16(data_size >> NSE_AQC_DU_DATA_SHIFT);
	memcpy(elem->usr_data, du_data->du_desc.data, data_size);

	dev_info(nse_hw_to_dev(hw), "Start to add du data, id = %d, data_len = %d\n",
		du_data->du_desc.du_data_id, data_size);

	for (i = 0; i < du_data->du_desc.data_size; i++) {
		u32 j;

		j = 0x3 - (i & 0x3);
		j = j << 0x3;

		data |= du_data->du_desc.data[i]<< j;
		if (j == 0) {
			dev_info(nse_hw_to_dev(hw),
				"du_data's content(BE) = 0x%08x\n", data);
			data = 0;
		}
	}

	status = nse_aq_du_datas(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_DU_DATA, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Add du data err, err = %d\n",
			__func__, __LINE__, status);
		ret = -EIO;
	}
	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

void nse_sw_dump_du_datas(struct nse_hw *hw)
{
	struct nse_sw_du_data *du_data = NULL;
	struct list_head *list_head = &hw->switch_info->ddata_list_head;
	u32 i, data = 0;

	if (list_empty(list_head)) {
		dev_info(nse_hw_to_dev(hw),	"There is no du data!\n");
		return;
	}

	mutex_lock(&hw->switch_info->du_data_lock);
	list_for_each_entry(du_data, list_head, list_entry) {
		dev_info(nse_hw_to_dev(hw),
			"du_data's hw_id = 0x%x, data size = %d\n",
			du_data->du_desc.du_data_id, du_data->du_desc.data_size);
		for (i = 0; i < du_data->du_desc.data_size; i++) {
			u32 j;

			j = 0x3 - (i & 0x3);
			j = j << 0x3;

			data |= du_data->du_desc.data[i]<< j;
			if (j == 0) {
				dev_info(nse_hw_to_dev(hw),
					"du_data's content(BE) = 0x%08x\n", data);
				data = 0;
			}
		}
	}
	mutex_unlock(&hw->switch_info->du_data_lock);
}

/**
 * nse_sw_creat_task_list - creat a task list from FW
 *
 * @hw: pointer to the hardware structure
 * @cur_task_list: temp task list info of cur filter
 */
static struct nse_sw_task_list *
nse_sw_creat_task_list(struct nse_hw *hw,
			struct nse_sw_task_list *cur_task_list)
{
	struct nse_sw_task_list *task_list = NULL;
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_task_lists *buf = NULL;
	struct nse_aqc_task_list_elem *elem;
	u16 buf_size, i, alloc_size, task_list_id = NSE_TASK_LIST_ID_INVALID;

	/*step1: alloc a task list id resource*/
	status = nse_aq_alloc_free_task_list_id(hw,
				&task_list_id, NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] alloc hw task list err, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_task_list_fail;
	}

	dev_info(nse_hw_to_dev(hw),
		"Alloc task list id success, id = %d\n", task_list_id);

	/*step2: alloc a task list obj in kernel,
	 * and fill based on cur_task_list.
	 */
	alloc_size = struct_size(cur_task_list, task, cur_task_list->task_cnt);
	task_list = devm_kzalloc(nse_hw_to_dev(hw), alloc_size, GFP_KERNEL);
	if (!task_list)
		goto nse_sw_creat_task_list_fail;

	memcpy(task_list, cur_task_list, alloc_size);
	refcount_set(&task_list->ref_cnt, 1);
	task_list->task_list_id = task_list_id;

	/*step3: bulid aqc add task list buf*/
	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		goto nse_sw_creat_task_list_fail;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->task_list_id = cpu_to_le16(task_list_id);

	dev_info(nse_hw_to_dev(hw),
		"Start to add task list, id = %d\n", task_list_id);

	for (i = 0; i < task_list->task_cnt; i++) {
		struct nse_sw_task *task;

		task = &task_list->task[i];
		elem->task[i].task_id |= (task->task_id << NSE_AQC_TASK_ID_S) &
			NSE_AQC_TASK_ID_M;
		elem->task[i].task_param = task->data_para;
		dev_info(nse_hw_to_dev(hw),
			"\t task_id = %d, task_param = %d\n", task->task_id,
			task->data_para);
	}

	/*step4: request add task list adminq command*/
	status = nse_aq_task_lists(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_TASK_LIST, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] aqc add task list err, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_task_list_fail;
	}

	devm_kfree(nse_hw_to_dev(hw), buf);
	return task_list;

nse_sw_creat_task_list_fail:
	if (!task_list)
		devm_kfree(nse_hw_to_dev(hw), task_list);
	if (!buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	if (task_list_id != NSE_TASK_LIST_ID_INVALID)
		nse_aq_alloc_free_task_list_id(hw, &task_list_id,
						NSE_AQ_OPC_FREE_RESOURCE);
	return NULL;
}

/**
 * nse_sw_destroy_task_list - destroy a task list to FW.
 *
 * @hw: pointer to the hardware structure
 * @task_list: the task list that is needed to free
 */
int
nse_sw_destroy_task_list(struct nse_hw *hw,
					struct nse_sw_task_list *task_list)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_task_lists *buf = NULL;
	struct nse_aqc_task_list_elem *elem;
	int ret = 0;
	u16 buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->task_list_id = cpu_to_le16(task_list->task_list_id);
	status = nse_aq_task_lists(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_TASK_LIST, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"Failed to aq remove task list, err = %d\n", status);
		ret = -EIO;
	}

	status = nse_aq_alloc_free_task_list_id(hw, &task_list->task_list_id,
				NSE_AQ_OPC_FREE_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] aqc free task list id err, err = %d\n",
			__func__, __LINE__, status);
		ret = -EIO;
	}

	mutex_lock(&hw->switch_info->task_list_lock);
	list_del(&task_list->list_entry);
	mutex_unlock(&hw->switch_info->task_list_lock);

	devm_kfree(nse_hw_to_dev(hw), task_list);
	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_find_task_list - find a task list from table
 *
 * @hw: pointer to the hardware structure
 * @cur_task_list: temp task list info of cur filter, used to search
 */
static struct nse_sw_task_list *
nse_find_task_list(struct nse_hw *hw, struct nse_sw_task_list *cur_list)
{
	struct nse_sw_task_list *old_list = NULL, *list_itr;
	struct list_head *list_head = &hw->switch_info->task_list_head;

	if (!cur_list->task_cnt)
		return NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (cur_list->task_cnt == list_itr->task_cnt &&
			!memcmp(cur_list->task, list_itr->task,
				sizeof(struct nse_sw_task)*cur_list->task_cnt)) {
			old_list = list_itr;
			break;
		}
	}

	return old_list;
}

/**
 * nse_sw_get_task_list - get a global task list from table
 *	if not found, create a new task list obj.
 *	if found, increase the existed obj's ref count.
 *
 * @hw: pointer to the hardware structure
 * @cur_task_list: temp task list info of cur filter, used to search
 */
struct nse_sw_task_list *
nse_sw_get_task_list(struct nse_hw *hw, struct nse_sw_task_list *cur_task_list)
{
	struct nse_sw_task_list *old_list = NULL, *new_list = NULL;
	struct nse_switch_info *sw = hw->switch_info;

	mutex_lock(&sw->task_list_lock);
	old_list = nse_find_task_list(hw, cur_task_list);
	if (old_list) {
		refcount_inc(&old_list->ref_cnt);
		mutex_unlock(&sw->task_list_lock);
		return old_list;
	}

	new_list = nse_sw_creat_task_list(hw, cur_task_list);
	if (!new_list) {
		mutex_unlock(&sw->task_list_lock);
		return NULL;
	}

	list_add_tail(&new_list->list_entry, &sw->task_list_head);
	mutex_unlock(&sw->task_list_lock);
	return new_list;
}

/**
 * nse_sw_put_task_list - put a task list to table.
 *	decrease the task list's ref cnt, free it when ref cnt reach 0.
 * @hw: pointer to the hardware structure
 * @task_list: the task list that is needed to free
 */
int
nse_sw_put_task_list(struct nse_hw *hw, struct nse_sw_task_list *task_list)
{
	if (!refcount_dec_and_test(&task_list->ref_cnt))
		return 0;

	return nse_sw_destroy_task_list(hw, task_list);
}

void nse_sw_dump_task_lists(struct nse_hw *hw)
{
	struct nse_sw_task_list *task_list = NULL;
	struct list_head *list_head = &hw->switch_info->task_list_head;
	int i;

	if (list_empty(list_head)) {
		dev_info(nse_hw_to_dev(hw),	"There is no task list!\n");
		return;
	}

	mutex_lock(&hw->switch_info->task_list_lock);
	list_for_each_entry(task_list, list_head, list_entry) {
		dev_info(nse_hw_to_dev(hw),
			"task list's hw_id = 0x%x, ref_cnt = %d, task cnt = 0x%x\n",
			task_list->task_list_id, refcount_read(&task_list->ref_cnt),
				task_list->task_cnt);
		for (i = 0; i < task_list->task_cnt; i++)
			dev_info(nse_hw_to_dev(hw),
				"\t task[%d]: task_id = %d, task_data_off(param) = %d\n",
				i, task_list->task[i].task_id, task_list->task[i].data_para);
	}
	mutex_unlock(&hw->switch_info->task_list_lock);
}

/**
 * nse_sw_set_mode - set switch mode.
 * @hw: pointer to the hardware structure
 * @nse_sw_meter: the meter that is needed to free
 */
int
nse_sw_set_mode(struct nse_hw *hw, enum nse_sw_mode *mode)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_sw_feature *buf = NULL;
	struct nse_aqc_sw_feature_elem *elem = NULL;
	u16 buf_size;
	int ret = 0;

	if (nse_bypass_switch)
		return 0;

	buf_size = struct_size(buf, elem, 3);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(3);
	elem = buf->elem;
	elem[0].feature = cpu_to_le16(NSE_AQC_FEATURE_TYPE_SW_MODE);
	elem[0].param = cpu_to_le16(*mode);

	if (*mode == NSE_SW_MODE_SWITCHDEV) {
		elem[1].feature = cpu_to_le16(NSE_AQC_FEATURE_TYPE_GOTO);
		elem[1].param = cpu_to_le16(NSE_AQC_GOTO_ENABLE);
		elem[2].feature = cpu_to_le16(NSE_AQC_FEATURE_TYPE_AU_DUP);
		elem[2].param = cpu_to_le16(NSE_MAX_FLOW_ENCAP_CNT);
	} else {
		elem[1].feature = cpu_to_le16(NSE_AQC_FEATURE_TYPE_GOTO);
		elem[1].param = cpu_to_le16(NSE_AQC_GOTO_DISABLE);
		elem[2].feature = cpu_to_le16(NSE_AQC_FEATURE_TYPE_AU_DUP);
		elem[2].param = cpu_to_le16(0);
	}

	status = nse_aq_sw_feature(hw, buf, buf_size,
				 NSE_AQ_OPC_SET_FEATURE, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to aqc set sw mode, err = %d\n",
			__func__, __LINE__, status);
		ret = -EIO;
		goto nse_sw_set_mode_fail;
	}

	dev_info(nse_hw_to_dev(hw),
		"[%s, %d] Success to set sw mode to %d\n",
		__func__, __LINE__, *mode);

nse_sw_set_mode_fail:
	if (!buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_sw_calc_hw_rate - transfer rate_ps to hw format
 *
 * @hw: pointer to the hardware structure
 * @rate: rate from user, byte per second
 * @hw_rate: rate format used by hw
 */
enum nse_status
nse_sw_meter_calc_hw_rate(struct nse_hw *hw, u64 rate, u32 *hw_rate)
{
	enum nse_status status = NSE_SUCCESS;
	u32 tick_ns = hw->hw_conf.meter_tick_ns;
	u8 y;

	rate = rate * tick_ns;
	rate = div_u64(rate << 12, 1000 * 1000 * 1000);

	for (y = 0; y < 2; y++) {
		if (rate < POLICY_HW_SPEED_LIMIT)
			break;
		rate = rate >> 3;
	}

	if (rate >= POLICY_HW_SPEED_LIMIT)
		return NSE_ERR_PARAM;

	*hw_rate = (rate << 2) | y;

	return status;
}

/**
 * nse_sw_creat_meter - creat a meter from FW
 *
 * @hw: pointer to the hardware structure
 * @meter_param: meter info of cur filter
 */
static struct nse_sw_meter *
nse_sw_creat_meter(struct nse_hw *hw,
			struct nse_sw_meter_param *meter_param)
{
	struct nse_sw_meter *meter = NULL;
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_meters *buf = NULL;
	struct nse_aqc_meter_elem *elem;
	u32 policy_type = 0, cir = 0, cbs = 0;
	u16 buf_size, meter_id = NSE_METER_ID_INVALID;
#if !NSE_TC_FLWR_METER_IN_DU
	struct nse_sw_counter_pair *red_cnt = NULL;
	struct nse_sw_counter_pair *green_cnt = NULL;
#endif

	/*step1: alloc a meter id resource*/
	status = nse_aq_alloc_free_meter_id(hw,
				&meter_id, NSE_AQ_OPC_ALLOC_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] alloc hw meter err, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_meter_fail;
	}

	/*step2: alloc a meter obj in kernel,
	 * and fill based on meter_param.
	 */
	meter = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*meter),
				 GFP_KERNEL);
	if (!meter)
		goto nse_sw_creat_meter_fail;

	memcpy(&meter->meter_param, meter_param, sizeof(*meter_param));
	refcount_set(&meter->ref_cnt, 1);
	meter->meter_id = meter_id;

	/*step3: bulid aqc add meter buf*/
	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		goto nse_sw_creat_meter_fail;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->meter_id = cpu_to_le16(meter_id);
	policy_type |= NSE_AQC_METER_ALG_CBSR;

	if (meter_param->mode == NSE_RATE_LIMIT_BPS)
		policy_type &= ~NSE_AQC_METER_MODE_PPS;
	else if (meter_param->mode == NSE_RATE_LIMIT_PPS)
		policy_type |= NSE_AQC_METER_MODE_PPS;
	else {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] alloc hw meter err, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_meter_fail;
	}

	status = nse_sw_meter_calc_hw_rate(hw, meter_param->rate, &cir);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] calculat hw_rate err, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_meter_fail;
	}

	cbs = (meter_param->burst >> NSE_AQC_METER_CBS_S) &
				NSE_AQC_METER_CBS_M;
	cir = (cir >> NSE_AQC_METER_CIR_S) & NSE_AQC_METER_CIR_M;
	elem->cfg.policy_type = cpu_to_le32(policy_type);
	elem->cfg.cbs = cpu_to_le32(cbs);
	elem->cfg.cir = cpu_to_le32(cir);

	dev_info(nse_hw_to_dev(hw),
		"Start to add meter: pol_type = 0x%x, cir = 0x%x, cbs = 0x%x, pir = 0x%x, pbs = 0x%x\n",
		policy_type, cir, cbs, le32_to_cpu(elem->cfg.pir), le32_to_cpu(elem->cfg.pbs));

	/*step4: request add meter adminq command*/
	status = nse_aq_meters(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_METER, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to aqc add meter, err = %d\n",
			__func__, __LINE__, status);
		goto nse_sw_creat_meter_fail;
	}

#if !NSE_TC_FLWR_METER_IN_DU
	red_cnt = nse_sw_creat_counter_pair(hw, true);
	if (!red_cnt) {
		dev_err(nse_hw_to_dev(hw), "Unable to creat red counter for AU meter\n");
		goto nse_sw_creat_meter_fail;
	}
	green_cnt = nse_sw_creat_counter_pair(hw, true);
	if (!green_cnt) {
		dev_err(nse_hw_to_dev(hw), "Unable to creat green counter for AU meter\n");
		goto nse_sw_creat_meter_fail;
	}
	meter->red_cnt_p = red_cnt;
	meter->green_cnt_p = green_cnt;
#endif

	devm_kfree(nse_hw_to_dev(hw), buf);
	return meter;

nse_sw_creat_meter_fail:
	if (!meter)
		devm_kfree(nse_hw_to_dev(hw), meter);
	if (!buf)
		devm_kfree(nse_hw_to_dev(hw), buf);
	if (meter_id != NSE_METER_ID_INVALID)
		nse_aq_alloc_free_meter_id(hw, &meter_id,
						NSE_AQ_OPC_FREE_RESOURCE);
#if !NSE_TC_FLWR_METER_IN_DU
	if (red_cnt)
		nse_sw_destroy_counter_pair(hw, red_cnt);
	if (green_cnt)
		nse_sw_destroy_counter_pair(hw, green_cnt);
#endif

	return NULL;
}

/**
 * nse_sw_destroy_meter - destroy a meter to FW.
 *
 * @hw: pointer to the hardware structure
 * @meter_param: meter info of cur filter
 */
int
nse_sw_destroy_meter(struct nse_hw *hw,
					struct nse_sw_meter *meter)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_aqc_meters *buf = NULL;
	struct nse_aqc_meter_elem *elem;
	int ret = 0;
	u16 buf_size;

	buf_size = struct_size(buf, elem, 1);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->meter_id = cpu_to_le16(meter->meter_id);
	status = nse_aq_meters(hw, buf, buf_size,
				 NSE_AQ_OPC_REMOVE_METER, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),	"Failed to aq remove meters, err = %d\n", status);
		ret = -EIO;
	}

	status = nse_aq_alloc_free_meter_id(hw, &meter->meter_id,
				NSE_AQ_OPC_FREE_RESOURCE);
	if (status) {
		dev_err(nse_hw_to_dev(hw),	"Failed to aq free meter id, id = %d!\n",
					meter->meter_id);
		ret = -EIO;
	}

	if (meter->red_cnt_p) {
		ret = nse_sw_destroy_counter_pair(hw, meter->red_cnt_p);
		meter->red_cnt_p = NULL;
		if (ret)
			dev_err(nse_hw_to_dev(hw), "Fail to destroy red hw counter of AU meter\n");
	}
	if (meter->green_cnt_p) {
		ret = nse_sw_destroy_counter_pair(hw, meter->green_cnt_p);
		meter->green_cnt_p = NULL;
		if (ret)
			dev_err(nse_hw_to_dev(hw), "Fail to destroy green hw counter of AU meter\n");
	}

	mutex_lock(&hw->switch_info->meter_list_lock);
	list_del(&meter->list_entry);
	mutex_unlock(&hw->switch_info->meter_list_lock);

	devm_kfree(nse_hw_to_dev(hw), meter);
	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_sw_find_meter - find a meter obj from table
 *
 * @hw: pointer to the hardware structure
 * @meter_param: meter info of cur filter, used to search
 */
struct nse_sw_meter *
nse_sw_find_meter(struct nse_hw *hw, struct nse_sw_meter_param *meter_param)
{
	struct nse_sw_meter *old_meter = NULL, *list_itr;
	struct list_head *list_head = &hw->switch_info->meter_list_head;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (list_itr->meter_param.index == meter_param->index) {
			old_meter = list_itr;
			break;
		}
	}
	return old_meter;
}

/**
 * nse_sw_get_meter - get a global meter from table
 *	if not found, create a new meter obj.
 *	if found, increase the existed obj's ref count.
 *
 * @hw: pointer to the hardware structure
 * @meter_param: meter info of cur filter, used to search
 */
struct nse_sw_meter *
nse_sw_get_meter(struct nse_hw *hw, struct nse_sw_meter_param *meter_param)
{
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_sw_meter *old_meter = NULL, *new_meter = NULL;

	mutex_lock(&sw->meter_list_lock);
	old_meter = nse_sw_find_meter(hw, meter_param);
	if (old_meter) {
		refcount_inc(&old_meter->ref_cnt);
		mutex_unlock(&sw->meter_list_lock);
		return old_meter;
	}

	new_meter = nse_sw_creat_meter(hw, meter_param);
	if (!new_meter) {
		mutex_unlock(&sw->meter_list_lock);
		return NULL;
	}

	list_add_tail(&new_meter->list_entry, &sw->meter_list_head);
	mutex_unlock(&sw->meter_list_lock);
	return new_meter;
}

/**
 * nse_sw_put_meter - put a meter to table.
 *	decrease the meter's ref cnt, free it when ref cnt reach 0.
 * @hw: pointer to the hardware structure
 * @nse_sw_meter: the meter that is needed to free
 */
int
nse_sw_put_meter(struct nse_hw *hw, struct nse_sw_meter *meter)
{
	if (!refcount_dec_and_test(&meter->ref_cnt))
		return 0;

	return nse_sw_destroy_meter(hw, meter);
}

void nse_sw_dump_meters(struct nse_hw *hw)
{
	struct nse_sw_meter *meter = NULL;
	struct list_head *list_head = &hw->switch_info->meter_list_head;

	if (list_empty(list_head)) {
		dev_info(nse_hw_to_dev(hw),	"There is no meter!\n");
		return;
	}

	mutex_lock(&hw->switch_info->meter_list_lock);
	list_for_each_entry(meter, list_head, list_entry)
		dev_info(nse_hw_to_dev(hw),
			"meter's hw_id = 0x%x, ref_cnt = %d, meter mode = 0x%x, user rate = %llu, burst = 0x%x\n",
			meter->meter_id, refcount_read(&meter->ref_cnt),
			meter->meter_param.mode, meter->meter_param.rate,
			meter->meter_param.burst);
	mutex_unlock(&hw->switch_info->meter_list_lock);
}

/**
 * nse_sw_find_adv_vlist - find a adv vsi list obj from table
 *
 * @hw: pointer to the hardware structure
 * @meter_param: meter info of cur filter, used to search
 */
struct nse_vsi_list_map_info *
nse_sw_find_adv_vlist(struct nse_hw *hw, u16 *vsi_handle_arr, u16 num_vsi)
{
	struct nse_vsi_list_map_info *old_vlist = NULL, *list_itr;
	struct list_head *list_head = &hw->switch_info->vsi_list_map_head;
	DECLARE_BITMAP(vsi_map, NSE_MAX_VSI) = { 0 };
	int i;

	for (i = 0; i < num_vsi; i++)
		set_bit(vsi_handle_arr[i], vsi_map);

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (list_itr->type == NSE_VSI_LIST_TYPE_ADVANCED &&
			list_itr->vsi_cnt == num_vsi &&
			!memcmp(vsi_map, list_itr->vsi_map, sizeof(vsi_map))) {
			old_vlist = list_itr;
			break;
		}
	}

	return old_vlist;
}

/**
 * nse_sw_get_adv_vlist - get a advanced vsi list from table
 *	if not found, create a new vsi list obj.
 *	if found, increase the existed obj's ref count.
 *
 * @hw: pointer to the hardware structure
 * @vsi_handle_arr: array of VSI handles to form a VSI list
 * @num_vsi: number of VSI handles in the array
 */
struct nse_vsi_list_map_info *
nse_sw_get_adv_vlist(struct nse_hw *hw,
		u16 *vsi_handle_arr, u16 num_vsi)
{
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_vsi_list_map_info *vlist = NULL;
	u16 vsi_list_id;
	enum nse_status status;

	mutex_lock(&sw->vsi_list_lock);
	vlist = nse_sw_find_adv_vlist(hw, vsi_handle_arr, num_vsi);
	if (vlist) {
		refcount_inc(&vlist->ref_cnt);
		mutex_unlock(&sw->vsi_list_lock);
		return vlist;
	}

	status = nse_create_vsi_list_rule(hw, vsi_handle_arr, num_vsi,
							  &vsi_list_id, NSE_SW_LKUP_LAST);
	if (status) {
		mutex_unlock(&sw->vsi_list_lock);
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to create adv vsi list rule, err = %d\n",
			__func__, __LINE__, status);
		return NULL;
	}

	vlist = nse_create_vsi_list_map(hw, vsi_handle_arr, num_vsi,
					vsi_list_id, NSE_VSI_LIST_TYPE_ADVANCED);

	if (!vlist) {
		mutex_unlock(&sw->vsi_list_lock);
		return NULL;
	}

	list_add_tail(&vlist->list_entry, &sw->vsi_list_map_head);
	mutex_unlock(&sw->vsi_list_lock);

	return vlist;
}

/**
 * nse_sw_put_adv_vlist - put a advanced vsi list from table
 * @hw: pointer to the hardware structure
 * @vsi_list_map: VSI list obj need to be released
 */
int
nse_sw_put_adv_vlist(struct nse_hw *hw,
		struct nse_vsi_list_map_info *vsi_list_info)
{
	enum nse_status status;

	if (!refcount_dec_and_test(&vsi_list_info->ref_cnt))
		return 0;

	status = nse_release_vsi_list(hw, vsi_list_info->vsi_list_id, NSE_SW_LKUP_LAST);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to release adv vsi list info, err = %d\n",
			__func__, __LINE__, status);
		return -EIO;
	}

	mutex_lock(&hw->switch_info->vsi_list_lock);
	list_del(&vsi_list_info->list_entry);
	mutex_unlock(&hw->switch_info->vsi_list_lock);

	devm_kfree(nse_hw_to_dev(hw), vsi_list_info);
	return 0;
}

void nse_sw_dump_vsi_list(struct nse_hw *hw)
{
	struct nse_vsi_list_map_info *vsi_list_info = NULL;
	struct list_head *list_head = &hw->switch_info->vsi_list_map_head;

	if (list_empty(list_head)) {
		dev_info(nse_hw_to_dev(hw),	"There is no vsi list!\n");
		return;
	}

	mutex_lock(&hw->switch_info->vsi_list_lock);
	list_for_each_entry(vsi_list_info, list_head, list_entry)
		dev_info(nse_hw_to_dev(hw),
			"vsi_list's hw_id = %d, ref_cnt = %d, vsi_cnt= %d, list type = %s\n",
			vsi_list_info->vsi_list_id, refcount_read(&vsi_list_info->ref_cnt),
				vsi_list_info->vsi_cnt,
			vsi_list_info->type == NSE_VSI_LIST_TYPE_ADVANCED ? "adv" : "legacy");
	mutex_unlock(&hw->switch_info->vsi_list_lock);
}

/**
 * nse_find_encap_entry - find a encap entry from table
 *
 * @hw: pointer to the hardware structure
 * @key: key used to search
 */
struct nse_sw_encap_entry *
nse_sw_find_encap_entry(struct nse_hw *hw, struct nse_sw_encap_key *key)
{
	struct nse_sw_encap_entry *old_list = NULL, *list_itr;
	struct list_head *list_head = &hw->switch_info->encap_list_head;

	if (!key || !key->ip_tun_key)
		return NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (key->tun_type == list_itr->tun_type &&
			list_itr->tun_info &&
			!memcmp(key->ip_tun_key, &list_itr->tun_info->key,
				sizeof(*(key->ip_tun_key)))) {
			old_list = list_itr;
			break;
		}
	}
	return old_list;
}

/**
 * nse_find_m_encap_entry - find a multi encap entry from table
 *
 * @hw: pointer to the hardware structure
 * @key: key used to search
 */
struct nse_sw_m_encap_entry *
nse_sw_find_m_encap_entry(struct nse_hw *hw, struct nse_sw_m_encap_key *key)
{
	struct nse_sw_m_encap_entry *old_list = NULL, *list_itr;
	struct list_head *list_head = &hw->switch_info->m_encap_list_head;

	if (!key || !key->encap_cnt)
		return NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (key->tun_type == list_itr->tun_type &&
			key->encap_cnt == list_itr->encap_cnt &&
			!memcmp(key->encap_entry, list_itr->encap_entry,
				sizeof(struct nse_sw_encap_entry *) * key->encap_cnt)) {
			old_list = list_itr;
			break;
		}
	}

	return old_list;
}

/**
 * nse_sw_update_encap_entry - update a encap entry's content to hw
 * @hw: pointer to the hardware structure
 * @encap_entry: the encap entry that is needed to add
 */
int
nse_sw_update_encap_entry(struct nse_hw *hw,
					struct nse_sw_encap_entry *encap_entry)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_du_datas *buf = NULL;
	struct nse_aqc_du_data_elem *elem;
	u32 i, data = 0;
	u16 buf_size;
	u16 data_size;

	data_size = encap_entry->du_desc.data_size;
	buf_size = struct_size(elem, usr_data, data_size) + sizeof(*buf);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->du_data_id = cpu_to_le16(encap_entry->du_desc.du_data_id);
	elem->data_len = cpu_to_le16(data_size >> NSE_AQC_DU_DATA_SHIFT);
	memcpy(elem->usr_data, encap_entry->du_desc.data, data_size);

	dev_info(nse_hw_to_dev(hw), "Start to update encap du data, id = %d, data_len = %d\n",
		encap_entry->du_desc.du_data_id, data_size);

	for (i = 0; i < encap_entry->du_desc.data_size; i++) {
		u32 j;

		j = 0x3 - (i & 0x3);
		j = j << 0x3;

		data |= encap_entry->du_desc.data[i]<< j;
		if (j == 0) {
			dev_info(nse_hw_to_dev(hw),
				"du_data's content(BE) = 0x%08x\n", data);
			data = 0;
		}
	}

	status = nse_aq_du_datas(hw, buf, buf_size,
				 NSE_AQ_OPC_UPDATE_DU_DATA, NULL);
	if (status)
		ret = -EIO;

	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_sw_creat_encap_entry -creat a encap entry
 *			which contains one du desc.
 * @hw: pointer to the hardware structure.
 * @d_size: encap byte size.
 */
struct nse_sw_encap_entry *
nse_sw_creat_encap_entry(struct nse_hw *hw, u16 d_size)
{
	struct nse_sw_encap_entry *encap_entry = NULL;
	struct nse_du_desc *du_desc;
	enum nse_status status = NSE_SUCCESS;
	u16 alloc_size, data_size;

	if (!d_size || d_size > NSE_DU_DATE_SIZE_128)
		return NULL;

	data_size = ALIGN(d_size, 32);

	alloc_size = struct_size(du_desc, data, data_size) + sizeof(*encap_entry);
	encap_entry = devm_kzalloc(nse_hw_to_dev(hw), alloc_size, GFP_KERNEL);
	if (!encap_entry)
		goto creat_encap_entry_fail;

	encap_entry->du_desc.data_size = data_size;

	status = nse_aq_alloc_free_encap_data(hw, encap_entry,
				NSE_AQ_OPC_ALLOC_RESOURCE);

	if (status)
		goto creat_encap_entry_fail;

	dev_info(nse_hw_to_dev(hw),
		"Alloc encap's du data id successfully, id = %d, data_size = %d\n",
		encap_entry->du_desc.du_data_id, encap_entry->du_desc.data_size);

	return encap_entry;

creat_encap_entry_fail:
	if (encap_entry)
		devm_kfree(nse_hw_to_dev(hw), encap_entry);
	return NULL;
}

/**
 * nse_sw_creat_m_encap_entry -creat a multi encap entry
 *			which contains one du desc.
 * @hw: pointer to the hardware structure.
 * @d_size: encap byte size.
 */
struct nse_sw_m_encap_entry *
nse_sw_creat_m_encap_entry(struct nse_hw *hw, u16 d_size)
{
	struct nse_sw_m_encap_entry *m_encap_entry = NULL;
	struct nse_du_desc *du_desc;
	enum nse_status status = NSE_SUCCESS;
	u16 alloc_size, data_size;

	if (!d_size || d_size > NSE_DU_DATE_SIZE_128)
		return NULL;

	data_size = ALIGN(d_size, 32);

	alloc_size = struct_size(du_desc, data, data_size) + sizeof(*m_encap_entry);
	m_encap_entry = devm_kzalloc(nse_hw_to_dev(hw), alloc_size, GFP_KERNEL);
	if (!m_encap_entry)
		goto creat_encap_entry_fail;

	m_encap_entry->du_desc.data_size = data_size;

	status = nse_aq_alloc_free_m_encap_data(hw, m_encap_entry,
				NSE_AQ_OPC_ALLOC_RESOURCE);

	if (status)
		goto creat_encap_entry_fail;

	dev_info(nse_hw_to_dev(hw), "Alloc multi encap's du data id success, id = %d, data_size = %d\n",
		m_encap_entry->du_desc.du_data_id, m_encap_entry->du_desc.data_size);

	return m_encap_entry;

creat_encap_entry_fail:
	if (!m_encap_entry)
		devm_kfree(nse_hw_to_dev(hw), m_encap_entry);
	return NULL;
}

/**
 * nse_sw_add_encap_entry - add a encap entry's content to hw
 * @hw: pointer to the hardware structure
 * @encap_entry: the encap entry that is needed to add
 */
int
nse_sw_add_encap_entry(struct nse_hw *hw,
					struct nse_sw_encap_entry *encap_entry)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_du_datas *buf = NULL;
	struct nse_aqc_du_data_elem *elem;
	u32 i, data = 0;
	u16 buf_size;
	u16 data_size;

	data_size = encap_entry->du_desc.data_size;
	buf_size = struct_size(elem, usr_data, data_size) + sizeof(*buf);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->du_data_id = cpu_to_le16(encap_entry->du_desc.du_data_id);
	elem->data_len = cpu_to_le16(data_size >> NSE_AQC_DU_DATA_SHIFT);
	memcpy(elem->usr_data, encap_entry->du_desc.data, data_size);

	dev_info(nse_hw_to_dev(hw), "Start to add encap du data, id = %d, data_len = %d\n",
		encap_entry->du_desc.du_data_id, data_size);

	for (i = 0; i < encap_entry->du_desc.data_size; i++) {
		u32 j;

		j = 0x3 - (i & 0x3);
		j = j << 0x3;

		data |= encap_entry->du_desc.data[i]<< j;
		if (j == 0) {
			dev_info(nse_hw_to_dev(hw),
				"du_data's content(BE) = 0x%08x\n", data);
			data = 0;
		}
	}

	status = nse_aq_du_datas(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_DU_DATA, NULL);
	if (status)
		ret = -EIO;

	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_sw_add_m_encap_entry - add a  multi encap entry's content to hw
 * @hw: pointer to the hardware structure
 * @m_encap_entry: the m encap entry that is needed to add
 */
int
nse_sw_add_m_encap_entry(struct nse_hw *hw,
					struct nse_sw_m_encap_entry *m_encap_entry)
{
	int ret = 0;
	enum nse_status status;
	struct nse_aqc_du_datas *buf = NULL;
	struct nse_aqc_du_data_elem *elem;
	u32 i, data = 0;
	u16 buf_size;
	u16 data_size;

	data_size = m_encap_entry->du_desc.data_size;
	buf_size = struct_size(elem, usr_data, data_size) + sizeof(*buf);
	buf = devm_kzalloc(nse_hw_to_dev(hw), buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->count = cpu_to_le16(1);
	elem = buf->elem;
	elem->du_data_id = cpu_to_le16(m_encap_entry->du_desc.du_data_id);
	elem->data_len = cpu_to_le16(data_size >> NSE_AQC_DU_DATA_SHIFT);
	memcpy(elem->usr_data, m_encap_entry->du_desc.data, data_size);

	dev_info(nse_hw_to_dev(hw), "Start to add multi encap du data, id = %d, data_len = %d\n",
		m_encap_entry->du_desc.du_data_id, data_size);

	for (i = 0; i < m_encap_entry->du_desc.data_size; i++) {
		u32 j;

		j = 0x3 - (i & 0x3);
		j = j << 0x3;

		data |= m_encap_entry->du_desc.data[i]<< j;
		if (j == 0) {
			dev_info(nse_hw_to_dev(hw),
				"du_data's content(BE) = 0x%08x\n", data);
			data = 0;
		}
	}

	status = nse_aq_du_datas(hw, buf, buf_size,
				 NSE_AQ_OPC_ADD_DU_DATA, NULL);
	if (status)
		ret = -EIO;

	devm_kfree(nse_hw_to_dev(hw), buf);
	return ret;
}

/**
 * nse_sw_destroy_encap_entry - destroy a encap entry
 * @hw: pointer to the hardware structure
 * @encap_entry: the encap entry that is needed to destroy
 */
int
nse_sw_destroy_encap_entry(struct nse_hw *hw,
					struct nse_sw_encap_entry *encap_entry)
{
	enum nse_status status = NSE_SUCCESS;
	struct nse_switch_info *sw = hw->switch_info;
	int ret = 0;

	mutex_lock(&sw->encap_tbl_lock);
	if (!list_empty(&encap_entry->list_entry))
		list_del(&encap_entry->list_entry);
	mutex_unlock(&sw->encap_tbl_lock);

	ret = nse_encap_entry_detach_neigh(hw, encap_entry);
	if (ret)
		dev_info(nse_hw_to_dev(hw),	"Failed to detach encap entry to neigh\n");

	status = nse_aq_alloc_free_encap_data(hw, encap_entry,
				NSE_AQ_OPC_FREE_RESOURCE);
	if (status)
		ret = -EIO;

	kfree(encap_entry->tun_info);
	devm_kfree(nse_hw_to_dev(hw), encap_entry);
	return ret;
}

/**
 * nse_sw_destroy_m_encap_entry - destroy a multi encap entry
 * @hw: pointer to the hardware structure
 * @m_encap_entry: the multi encap entry that is needed to destroy
 */
int
nse_sw_destroy_m_encap_entry(struct nse_hw *hw,
					struct nse_sw_m_encap_entry *m_encap_entry)
{
	enum nse_status status = NSE_SUCCESS;
	int ret = 0, i;

	status = nse_aq_alloc_free_m_encap_data(hw, m_encap_entry,
				NSE_AQ_OPC_FREE_RESOURCE);

	if (status)
		ret = -EIO;

	mutex_lock(&hw->switch_info->m_encap_lock);
	list_del(&m_encap_entry->list_entry);
	mutex_unlock(&hw->switch_info->m_encap_lock);

	for (i = 0; i < m_encap_entry->encap_cnt; i++)
		nse_sw_put_encap_entry(hw, m_encap_entry->encap_entry[i]);

	devm_kfree(nse_hw_to_dev(hw), m_encap_entry);
	return ret;
}

/**
 * nse_sw_put_encap_entry - put a encap entry to table.
 *	decrease the encap entryt's ref cnt, free it when ref cnt reach 0.
 * @hw: pointer to the hardware structure
 * @encap_entry: the encap entry that is needed to free
 */
int
nse_sw_put_encap_entry(struct nse_hw *hw, struct nse_sw_encap_entry *encap_entry)
{
	if (!refcount_dec_and_test(&encap_entry->ref_cnt))
		return 0;

	return nse_sw_destroy_encap_entry(hw, encap_entry);
}

/**
 * nse_sw_put_m_encap_entry - put a multi encap entry to table.
 *	decrease the multi encap entryt's ref cnt, free it when ref cnt reach 0.
 * @hw: pointer to the hardware structure
 * @m_encap_entry: the multi encap entry that is needed to free
 */
int
nse_sw_put_m_encap_entry(struct nse_hw *hw, struct nse_sw_m_encap_entry *m_encap_entry)
{
	int i;

	if (!refcount_dec_and_test(&m_encap_entry->ref_cnt)) {
		for (i = 0; i < m_encap_entry->encap_cnt; i++)
			nse_sw_put_encap_entry(hw, m_encap_entry->encap_entry[i]);
		return 0;
	}

	return nse_sw_destroy_m_encap_entry(hw, m_encap_entry);
}

/**
 * nse_sw_creat_sflow - create a global sflow obj
 *
 * @hw: pointer to the hardware structure
 * @sflow_info: sflow info of cur filter, used to search
 * @sflow: returned global sflow obj.
 */
static int
nse_sw_creat_sflow(struct nse_hw *hw, struct nse_sw_sflow_info *sflow_info,
					struct nse_sw_sflow **sflow)
{
	struct nse_sw_sflow *new_sflow = NULL;
	struct nse_aqc_sflow *buf = NULL;
	struct nse_switch_info *sw = hw->switch_info;
	enum nse_status status = NSE_SUCCESS;
	int ret = 0;

	/*step1: alloc a sflow obj in kernel,
	 * and fill based on sflow_info.
	 */
	new_sflow = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*new_sflow),
				 GFP_KERNEL);
	if (!new_sflow) {
		ret = -ENOMEM;
		goto nse_sw_creat_sflow_fail;
	}
	refcount_set(&new_sflow->ref_cnt, 1);
	memcpy(&new_sflow->sflow_info, sflow_info, sizeof(*sflow_info));

	/*step2: bulid aqc add sflow buf*/
	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto nse_sw_creat_sflow_fail;
	}

	buf->rate = cpu_to_le16((u16)sflow_info->rate);

	/*step3: request add sflow adminq command*/
	status = nse_aq_sflow(hw, buf, sizeof(*buf),
				 NSE_AQ_OPC_SET_SFLOW, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to aqc add sflow, err = %d\n",
			__func__, __LINE__, status);
		ret = -EIO;
		goto nse_sw_creat_sflow_fail;
	}

	sw->sflow = new_sflow;
	*sflow = new_sflow;
	return 0;

nse_sw_creat_sflow_fail:
	if (!new_sflow)
		devm_kfree(nse_hw_to_dev(hw), new_sflow);
	if (!buf)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return ret;
}

/**
 * nse_sw_destroy_sflow - destroy a global sflow obj
 *
 * @hw: pointer to the hardware structure
 * @sflow: returned global sflow obj.
 */
static int
nse_sw_destroy_sflow(struct nse_hw *hw, struct nse_sw_sflow *sflow)
{
	struct nse_aqc_sflow *buf = NULL;
	struct nse_switch_info *sw = hw->switch_info;
	enum nse_status status = NSE_SUCCESS;
	int ret = 0;

	buf = devm_kzalloc(nse_hw_to_dev(hw), sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->rate = cpu_to_le16(0);
	status = nse_aq_sflow(hw, buf, sizeof(*buf),
				 NSE_AQ_OPC_SET_SFLOW, NULL);
	if (status) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to aqc free sflow, err = %d\n",
			__func__, __LINE__, status);
		ret = -EIO;
	}

	sw->sflow = NULL;
	devm_kfree(nse_hw_to_dev(hw), buf);
	devm_kfree(nse_hw_to_dev(hw), sflow);

	return 0;
}

/**
 * nse_sw_get_sflow - get a global sflow obj
 *	if global obj is NULL, create a new global sflow obj.
 *	if found,  compare the sflow, increase the existed obj's ref count
 *
 * @hw: pointer to the hardware structure
 * @sflow_info: sflow info of cur filter, used to search
 * @sflow: returned global sflow obj.
 */
int
nse_sw_get_sflow(struct nse_hw *hw, struct nse_sw_sflow_info *sflow_info,
					struct nse_sw_sflow **sflow)
{
	struct nse_sw_sflow *old_sflow = hw->switch_info->sflow;

	*sflow = NULL;

	if (!old_sflow)
		return nse_sw_creat_sflow(hw, sflow_info, sflow);

	if (old_sflow->sflow_info.rate == sflow_info->rate) {
		refcount_inc(&old_sflow->ref_cnt);
		*sflow = old_sflow;
		return 0;
	}

	dev_err(nse_hw_to_dev(hw),
		"Only unique sampler is supported, Current rate = %d, group = %d, trunc_size = %d\n",
		old_sflow->sflow_info.rate, old_sflow->sflow_info.group_num,
		old_sflow->sflow_info.trunc_size);

	return -ENOMEM;
}

/**
 * nse_sw_put_sflow - put a sflow to table.
 *	decrease the sflow's ref cnt, free it when ref cnt reach 0.
 * @hw: pointer to the hardware structure
 * @nse_sw_sflow: the sflow that is needed to free
 */
int
nse_sw_put_sflow(struct nse_hw *hw, struct nse_sw_sflow *sflow)
{
	if (!refcount_dec_and_test(&sflow->ref_cnt))
		return 0;

	return nse_sw_destroy_sflow(hw, sflow);
}

/**
 * nse_cleanup_sw_sflow - nse_cleanup_sw_sflow a sflow .
 * @hw: pointer to the hardware structure
 */
void
nse_cleanup_sw_sflow(struct nse_hw *hw)
{
	struct nse_sw_sflow *sflow = NULL;

	if (nse_bypass_switch)
		return;

	sflow = hw->switch_info->sflow;
	if (!sflow)
		return;

	nse_sw_destroy_sflow(hw, sflow);
}

