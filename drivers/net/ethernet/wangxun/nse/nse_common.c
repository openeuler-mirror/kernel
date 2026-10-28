// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_adminq_cmd.h"
#include "nse_common.h"
#include "nse_flow.h"
#include "nse_lib.h"
#include "nse_fwmng.h"
#include "nse_sched.h"
#include "nse_sched_aqc.h"
#include "nse_sched_internal.h"
#include "nse_switch.h"
#include "nse_tc_lib.h"
#include "nse_lpm.h"

/**
 * nse_set_mac_type - Sets MAC type
 * @hw: pointer to the HW structure
 *
 * This function sets the MAC type of the adapter based on the
 * vendor ID and device ID stored in the HW structure.
 */
static enum nse_status nse_set_mac_type(struct nse_hw *hw)
{
	if (hw->vendor_id != PCI_VENDOR_ID_TRUSTNETIC)
		return NSE_ERR_DEVICE_NOT_SUPPORTED;

	if (hw->device_id == NSE_DEV_ID_AMBER_FPGA ||
		hw->device_id == NSE_DEV_ID_AMBER_FDBTACXX ||
		hw->device_id == NSE_DEV_ID_AMBER_FDBTACRX ||
		hw->device_id == NSE_DEV_ID_AMBER_DDATACRX ||
		hw->device_id == NSE_DEV_ID_AMBER_DDATAIRX ||
		hw->device_id == NSE_DEV_ID_AMBER_FQATACRX ||
		hw->device_id == NSE_DEV_ID_AMBER_DQATACXX)
		hw->mac_type = NSE_MAC_TYPE_AMBER;
	else if (hw->device_id == NSE_DEV_ID_MOONSTONE)
		hw->mac_type = NSE_MAC_TYPE_MOONSTONE;
	else
		return NSE_ERR_DEVICE_NOT_SUPPORTED;

	return NSE_SUCCESS;
}

enum nse_status
nse_clear_pf_cfg(struct nse_hw *hw)
{
	struct nse_aq_desc desc;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH, NSE_AQ_OPC_CLEAR_PF_CFG);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

static enum nse_status nse_init_fltr_mgmt_legacy(struct nse_hw *hw)
{
	struct nse_legacy_switch *legacy_sw;
	enum nse_status status = NSE_SUCCESS;

	hw->legacy_switch = devm_kzalloc(nse_hw_to_dev(hw),
					   sizeof(*hw->legacy_switch), GFP_KERNEL);
	legacy_sw = hw->legacy_switch;
	if (!legacy_sw)
		return NSE_ERR_NO_MEMORY;

	legacy_sw->hw = hw;

	INIT_LIST_HEAD(&legacy_sw->mac_replay_list);
	mutex_init(&legacy_sw->mac_tbl_lock);
	legacy_sw->num_mac_entries = NSE_LEGACY_MAC_TALBE_ENTRY_NUM;

	INIT_LIST_HEAD(&legacy_sw->vlan_replay_list);
	mutex_init(&legacy_sw->vlan_tbl_lock);
	legacy_sw->num_vlan_entries = NSE_LEGACY_VLAN_TALBE_ENTRY_NUM;

	INIT_LIST_HEAD(&legacy_sw->ethtype_replay_list);
	mutex_init(&legacy_sw->ethtype_tbl_lock);
	legacy_sw->num_ethtype_entries = NSE_LEGACY_ETHTYPE_TALBE_ENTRY_NUM;
	return status;
}

static enum nse_status nse_init_fltr_mgmt_flex(struct nse_hw *hw)
{
	struct nse_switch_info *sw;
	enum nse_status status;

#ifdef NSE_ESWITH_SET_MODE
	nse_eswitch_set_mode(hw->back, DEVLINK_ESWITCH_MODE_LEGACY);
#endif

	hw->switch_info = devm_kzalloc(nse_hw_to_dev(hw),
					   sizeof(*hw->switch_info), GFP_KERNEL);
	sw = hw->switch_info;
	if (!sw)
		return NSE_ERR_NO_MEMORY;

	INIT_LIST_HEAD(&sw->vsi_list_map_head);
	mutex_init(&sw->vsi_list_lock);

	INIT_LIST_HEAD(&sw->task_list_head);
	mutex_init(&sw->task_list_lock);

	INIT_LIST_HEAD(&sw->ddata_list_head);
	mutex_init(&sw->du_data_lock);

	INIT_LIST_HEAD(&sw->encap_list_head);
	mutex_init(&sw->encap_tbl_lock);

	INIT_LIST_HEAD(&sw->m_encap_list_head);
	mutex_init(&sw->m_encap_lock);

	INIT_LIST_HEAD(&sw->meter_list_head);
	mutex_init(&sw->meter_list_lock);

	sw->sflow = NULL;
	sw->hw = hw;

	status = nse_init_def_lut(hw, &hw->switch_info->lut_list);
	if (status) {
		devm_kfree(nse_hw_to_dev(hw), hw->switch_info);
		return status;
	}

	dev_info(nse_hw_to_dev(hw), "[%s, %d] nse_init_def_lut is done\n", __func__, __LINE__);

	status = nse_init_def_profiles(hw, &hw->switch_info->profile_list);
	if (status) {
		devm_kfree(nse_hw_to_dev(hw), hw->switch_info->lut_list);
		devm_kfree(nse_hw_to_dev(hw), hw->switch_info);
		return status;
	}

	dev_info(nse_hw_to_dev(hw), "[%s, %d] nse_init_def_profiles is done\n",
		 __func__, __LINE__);

	nse_get_prof_index_max(hw);

	return NSE_SUCCESS;
}

/**
 * nse_init_fltr_mgmt_struct - initializes filter management list and locks
 * @hw: pointer to the HW struct
 */
static enum nse_status nse_init_fltr_mgmt_struct(struct nse_hw *hw)
{
	enum nse_status status = NSE_SUCCESS;

	if (nse_bypass_switch) {
		nse_debug(hw, NSE_DBG_SW, "[%s, %d] nse_bypass_switch\n", __func__, __LINE__);
		return NSE_SUCCESS;
	}

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		status = nse_init_fltr_mgmt_flex(hw);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		status = nse_init_fltr_mgmt_legacy(hw);

	return status;
}

static void nse_cleanup_fltr_mgmt_legacy(struct nse_hw *hw)
{
	struct nse_legacy_switch *legacy_sw;

	legacy_sw = hw->legacy_switch;
	if (!legacy_sw)
		return;

	mutex_destroy(&legacy_sw->mac_tbl_lock);
	mutex_destroy(&legacy_sw->vlan_tbl_lock);
	mutex_destroy(&legacy_sw->ethtype_tbl_lock);
	devm_kfree(nse_hw_to_dev(hw), legacy_sw);
}

/**
 * nse_cleanup_fltr_mgmt_struct - cleanup filter management list and locks
 * @hw: pointer to the HW struct
 */
static void nse_cleanup_fltr_mgmt_flex(struct nse_hw *hw)
{
	struct nse_vsi_list_map_info *v_pos_map, *v_tmp_map;
	struct nse_sw_task_list *task_list, *task_list_tmp;
	struct nse_sw_du_data *du_data, *du_data_tmp;
	struct nse_sw_encap_entry *encap_entry, *encap_entry_tmp;
	struct nse_sw_m_encap_entry *m_encap, *m_encap_tmp;
	struct nse_sw_meter *meter, *meter_tmp;
	struct nse_lut_info *luts;
	struct nse_switch_info *sw;
	u16 i;

	sw = hw->switch_info;
	if (!sw)
		return;

	/*release lpm fltr enties */
	nse_disable_erouter_mode(hw);

	nse_cleanup_sw_stats(hw);

	nse_cleanup_sw_sflow(hw);

	/*release global vsi map memory */
	list_for_each_entry_safe(v_pos_map, v_tmp_map, &sw->vsi_list_map_head,
				 list_entry) {
		list_del(&v_pos_map->list_entry);
		devm_kfree(nse_hw_to_dev(hw), v_pos_map);
	}
	mutex_destroy(&sw->vsi_list_lock);

	/*release global task list memory */
	list_for_each_entry_safe(task_list, task_list_tmp, &sw->task_list_head,
				 list_entry) {
		list_del(&task_list->list_entry);
		devm_kfree(nse_hw_to_dev(hw), task_list);
	}
	mutex_destroy(&sw->task_list_lock);

	/*release global du_data memory */
	list_for_each_entry_safe(du_data, du_data_tmp, &sw->ddata_list_head,
				 list_entry) {
		list_del(&du_data->list_entry);
		devm_kfree(nse_hw_to_dev(hw), du_data);
	}
	mutex_destroy(&sw->du_data_lock);

	/*release global encap entry memory */
	list_for_each_entry_safe(encap_entry, encap_entry_tmp, &sw->encap_list_head,
				 list_entry) {
		list_del(&encap_entry->list_entry);
		kfree(encap_entry->tun_info);
		devm_kfree(nse_hw_to_dev(hw), encap_entry);
	}
	mutex_destroy(&sw->encap_tbl_lock);

	/*release global m_encap memory */
	list_for_each_entry_safe(m_encap, m_encap_tmp, &sw->m_encap_list_head,
				 list_entry) {
		list_del(&m_encap->list_entry);
		devm_kfree(nse_hw_to_dev(hw), m_encap);
	}
	mutex_destroy(&sw->m_encap_lock);

	/*release global meter memory */
	list_for_each_entry_safe(meter, meter_tmp, &sw->meter_list_head,
				 list_entry) {
		list_del(&meter->list_entry);
		if (meter->green_cnt_p)
			devm_kfree(nse_hw_to_dev(hw), meter->green_cnt_p);
		if (meter->red_cnt_p)
			devm_kfree(nse_hw_to_dev(hw), meter->red_cnt_p);
		devm_kfree(nse_hw_to_dev(hw), meter);
	}
	mutex_destroy(&sw->meter_list_lock);

	/*release global fltr enties */
	luts = sw->lut_list;
	for (i = 0; i < NSE_MAX_NUM_LUTS; i++) {
		struct nse_lut_grp_entry *lut_entry, *tmplut_entry;
		struct nse_sw_fv_list_entry *fv_entry, *tmpfv_entry;

		luts[i].lut_id = i;

		list_for_each_entry_safe(lut_entry, tmplut_entry,
					 &luts[i].lut_group_list, l_entry) {
			list_del(&lut_entry->l_entry);
			devm_kfree(nse_hw_to_dev(hw), lut_entry);
		}

		list_for_each_entry_safe(fv_entry, tmpfv_entry,
					 &luts[i].fv_list, list_entry) {
			list_del(&fv_entry->list_entry);
			devm_kfree(nse_hw_to_dev(hw), fv_entry);
		}

		if (luts[i].adv_rule) {
			struct nse_adv_fltr_mgmt_list_entry *tmp_entry;
			struct nse_adv_fltr_mgmt_list_entry *lst_itr;

			mutex_destroy(&luts[i].filt_rule_lock);
			list_for_each_entry_safe(lst_itr, tmp_entry,
						 &luts[i].filt_rules,
						 list_entry) {
				list_del(&lst_itr->list_entry);
				if (lst_itr->lkups)
					devm_kfree(nse_hw_to_dev(hw), lst_itr->lkups);
				devm_kfree(nse_hw_to_dev(hw), lst_itr);
			}
		} else {
			struct nse_fltr_mgmt_list_entry *lst_itr, *tmp_entry;

			/* release legacy filter entries one by one*/
			mutex_destroy(&luts[i].filt_rule_lock);
			list_for_each_entry_safe(lst_itr, tmp_entry,
						 &luts[i].filt_rules,
						 list_entry) {
				list_del(&lst_itr->list_entry);
				devm_kfree(nse_hw_to_dev(hw), lst_itr);
			}
		}
	}

	devm_kfree(nse_hw_to_dev(hw), sw->profile_list);
	devm_kfree(nse_hw_to_dev(hw), sw->lut_list);
	devm_kfree(nse_hw_to_dev(hw), sw);
}

static void nse_cleanup_fltr_mgmt_struct(struct nse_hw *hw)
{
	if (nse_bypass_switch) {
		nse_debug(hw, NSE_DBG_SW, "[%s, %d] nse_bypass_switch\n", __func__, __LINE__);
		return;
	}

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		nse_cleanup_fltr_mgmt_flex(hw);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		nse_cleanup_fltr_mgmt_legacy(hw);
}

/**
 * nse_get_itr_intrl_gran
 * @hw: pointer to the HW struct
 *
 * Determines the ITR/INTRL granularities based on the maximum aggregate
 * bandwidth according to the device's configuration during power-on.
 */
static void nse_get_itr_intrl_gran(struct nse_hw *hw)
{
	hw->itr_gran = NSE_ITR_GRAN_FIXED;
	hw->intrl_gran = NSE_INTRL_GRAN_FIXED;
}

/**
 * nse_set_umac_shared
 * @hw: pointer to the hw struct
 *
 * Set boolean flag to allow unicast MAC sharing
 */
void nse_set_umac_shared(struct nse_hw *hw)
{
	hw->umac_shared = true;
}

void nse_init_pf_fw_opt_features(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;
	u32 val32;

	if (nse_is_fw_fea_set(hw, NSE_FW_FEA_SUPPORT_LLDP)) {
		nse_debug(hw, NSE_DBG_SYS, "[%s] handle fw-lldp\n", __func__);

		status = nse_aq_fw_lldp_agent_get_status(hw, &val32);
		if (!status) {
			nse_debug(hw, NSE_DBG_SYS, "[%s] fw-lldp-agent status=%X\n",
				  __func__, val32);

			if (val32 & FW_LLDP_AGENT_NVM_DEFAULT_RUN)
				set_bit(NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA, pf->flags);
			else
				clear_bit(NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA, pf->flags);

			if (val32 & FW_LLDP_AGENT_CUR_RUNNING)
				set_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags);
			else {
				clear_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags);
				clear_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags);
			}
		} else {
			nse_debug(hw, NSE_DBG_SYS,
				  "[%s] fw-lldp-agent fail to get status\n", __func__);

			clear_bit(NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA, pf->flags);
			clear_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags);
			clear_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags);
		}
	}
}

void nse_deinit_pf_fw_opt_features(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;

	if (nse_is_fw_fea_set(hw, NSE_FW_FEA_SUPPORT_LLDP)) {
		nse_debug(hw, NSE_DBG_SYS, "[%s] handle fw-lldp\n", __func__);

		(void)nse_aq_fw_lldp_dcbx_subagent_start_stop(hw, false);

		if (test_bit(NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA, pf->flags))
			(void)nse_aq_fw_lldp_agent_start_stop(hw, true);
		else
			(void)nse_aq_fw_lldp_agent_start_stop(hw, false);
	}
}

void nse_rebuild_pf_fw_ot_features(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	if (!nse_is_high_reset_type(reset_type))
		return;

	if (nse_is_fw_fea_set(hw, NSE_FW_FEA_SUPPORT_LLDP)) {
		if (test_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags)) {
			(void)nse_aq_fw_lldp_agent_start_stop(hw, true);

			if (test_bit(NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA, pf->flags))
				(void)nse_aq_fw_lldp_dcbx_subagent_start_stop(hw, true);

		} else {
			(void)nse_aq_fw_lldp_agent_start_stop(hw, false);
		}
	}
}

/**
 * nse_init_hw - main hardware initialization routine
 * @hw: pointer to the hardware structure
 */
enum nse_status nse_init_hw(struct nse_hw *hw)
{
	enum nse_status status;
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	u8 factory_addr[ETH_ALEN];

	/* Set MAC type based on DeviceID */
	status = nse_set_mac_type(hw);
	if (status) {
		dev_err(dev, "FAIL: set_mac_type(), status=%d(%s)\n",
						status, nse_stat_str(status));
		return status;
	}

	fwmng_clear_rsp(hw, false, NSE_FWMNG_CLEAR_RSP_ALL);

	status = nse_reset(hw, NSE_RESET_PFR);
	if (status) {
		dev_err(dev, "FAIL: reset(PFR), status=%d(%s)\n",
						status, nse_stat_str(status));
		return status;
	}

	nse_get_itr_intrl_gran(hw);

	status = nse_create_all_ctrlq(hw);
	if (status) {
		dev_err(dev, "FAIL: create_all_ctrlq(), status=%d(%s)\n",
						status, nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	status = nse_determine_stag_type(hw);
	if (status) {
		dev_err(dev, "FAIL: determine_stag_type(), status=%d(%s)\n",
						status, nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	status = nse_get_caps(hw);
	if (status) {
		dev_err(dev, "[%s, %d] FAIL: get_caps(), status=%d(%s)\n",
						__func__, __LINE__, status,
							nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	if (hw->debug_mask & NSE_DBG_SYS)
		nse_dump_caps(hw);

	status = nse_init_hw_conf(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: init_hw_conf(), status=%d(%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	status = nse_sanity_check_caps(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: sanity_check_caps(), status=%d(%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	status = nse_init_fw_conf(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: init_fw_conf(), status=%d(%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	status = nse_clear_pf_cfg(hw);
	if (status) {
		dev_err(dev, "FAIL: clear_pf_cfg(), status=%d(%s)\n",
						status, nse_stat_str(status));
		goto err_unroll_cqinit;
	}

	nse_download_ddp(pf);

	hw->port_info = devm_kzalloc(nse_hw_to_dev(hw),
				     sizeof(*hw->port_info), GFP_KERNEL);
	if (!hw->port_info) {
		status = NSE_ERR_NO_MEMORY;
		goto err_unroll_cqinit;
	}

	/* set the back pointer to HW */
	hw->port_info->hw = hw;

	hw->port_info->sched_info.factor_tbl = devm_kzalloc(nse_hw_to_dev(hw),
					sizeof(u64) * NSE_SCHED_FACTOR_TBL_LEN, GFP_KERNEL);
	if (!hw->port_info->sched_info.factor_tbl) {
		status = NSE_ERR_NO_MEMORY;
		goto err_unroll_alloc_port_info;
	}

	/* Initialize port_info struct with switch configuration data */
	status = nse_get_initial_sw_cfg(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: get_initial_sw_cfg(), %d (%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_unroll_alloc_port_info;
	}

	hw->evb_veb = true;
	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_ONLY_VEPA))
		hw->evb_veb = false;

	status = nse_sched_init(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: sched_init(): %d (%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_unroll_sched;
	}

	status = nse_init_fltr_mgmt_struct(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: init_fltr_mgmt_struct(), status=%d(%s)\n",
					__func__, status, nse_stat_str(status));
		goto err_unroll_sched;
	}

	status = nse_init_sw_stats(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: init_sw_stats(), status=%d(%s)\n",
					__func__, status, nse_stat_str(status));
		goto err_unroll_fltr_mgmt_struct;
	}

	status = nse_lmac_phy_init_early(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: lmac_phy_init_early(), status=%d(%s)\n",
					__func__, status, nse_stat_str(status));
		goto err_unroll_sw_stats;
	}

	/* Get MAC information */
	status = nse_manage_mac_read(hw, factory_addr, NULL, NULL);
	if (status) {
		dev_err(dev, "[%s] FAIL: manage_mac_read(factory_addr) fail: %d (%s)\n",
					__func__, status, nse_stat_str(status));
		goto err_unroll_sw_stats;
	}

	if (is_valid_ether_addr(factory_addr) &&
		!hw->is_mh_dpu_secondary_pf) {
		ether_addr_copy(hw->port_info->mac.perm_addr, factory_addr);
	} else {
		eth_random_addr(hw->port_info->mac.perm_addr);
	}

	ether_addr_copy(hw->port_info->mac.lan_addr, hw->port_info->mac.perm_addr);

	/* set LAN/WoL address to HW */
	if (!hw->is_mh_dpu_secondary_pf) {
		u16 wflags;

		wflags = NSE_AQC_MAN_MAC_WFLAG_UPDATE_LMAC_ADDR;
		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL))
			wflags |= NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_ADDR;

		status = nse_aq_manage_mac_write(hw, hw->port_info->mac.lan_addr,
										wflags, 0);
		if (status) {
			dev_err(dev, "[%s] FAIL: aq_manage_mac_write(lmac_addr, wol_addr), status=%d(%s)\n",
						__func__, status, nse_stat_str(status));
			goto err_unroll_sw_stats;
		}
	}

	return 0;

err_unroll_sw_stats:
	nse_cleanup_sw_stats(hw);
err_unroll_fltr_mgmt_struct:
	nse_cleanup_fltr_mgmt_struct(hw);
err_unroll_sched:
	nse_sched_cleanup_all(hw);
err_unroll_alloc_port_info:
	if (hw->port_info) {
		if (hw->port_info->sched_info.factor_tbl)
			devm_kfree(nse_hw_to_dev(hw), hw->port_info->sched_info.factor_tbl);

		devm_kfree(nse_hw_to_dev(hw), hw->port_info);
	}
	hw->port_info = NULL;
err_unroll_cqinit:
	nse_destroy_all_ctrlq(hw, true);
	return status;
}

/**
 * nse_deinit_hw - unroll initialization operations done by nse_init_hw
 * @hw: pointer to the hardware structure
 *
 * This should be called only during nominal operation, not as a result of
 * nse_init_hw() failing since nse_init_hw() will take care of unrolling
 * applicable initializations if it fails for any reason.
 */
void nse_deinit_hw(struct nse_hw *hw)
{
	nse_cleanup_fltr_mgmt_struct(hw);

	nse_sched_cleanup_all(hw);

	if (hw->port_info) {
		if (hw->port_info->sched_info.factor_tbl)
			devm_kfree(nse_hw_to_dev(hw), hw->port_info->sched_info.factor_tbl);

		devm_kfree(nse_hw_to_dev(hw), hw->port_info);
		hw->port_info = NULL;
	}

	nse_destroy_all_ctrlq(hw, true);

	/* Clear VSI contexts if not already cleared */
	nse_clear_all_vsi_ctx(hw);
}

void nse_high_reset_detect_on_fwmng(struct nse_hw *hw, struct nse_fwmng_cmd_rsp_generic *cmd_rsp)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);

	dev_info(dev, "[%s] detect high_reset (type=0x%X, who=0x%X, reset_status=0x%X)\n",
						__func__,
						cmd_rsp->rsp_buf[0], cmd_rsp->rsp_buf[1],
							cmd_rsp->rsp_buf[2]);

	pf->high_reset_oicr_swint_count++;

	if (cmd_rsp->rsp_buf[0] != 0x0)
		dev_info(dev, "\t (type=0x%X --- just handle it as CORER, anyway)\n",
			 cmd_rsp->rsp_buf[0]);

	if (!test_and_set_bit(NSE_RESET_OICR_RECV, pf->state)) {
		set_bit(NSE_HIGH_RESET_CORER_RECV, pf->state);
		hw->high_reset_ongoing = true;
	}
}

void nse_high_reset_detect_on_oicr_core_reset(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);

	dev_info(dev, "[%s] detect high_reset\n", __func__);

	pf->high_reset_oicr_corer_count++;

	if (!test_and_set_bit(NSE_RESET_OICR_RECV, pf->state)) {
		set_bit(NSE_HIGH_RESET_CORER_RECV, pf->state);
		hw->high_reset_ongoing = true;
	}
}

/* wait for underlying-FW-cleanup is done --- FW would give signal for SW.
 */
enum nse_status nse_reset_wait_complete(struct nse_hw *hw, bool fwmng_locked,
					unsigned int wait_flags)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_fwmng_cmd_rsp_generic fwmng_rsp;
	u32 cnt, reg = 0;
	u32 rsp_id;
	enum nse_status status = NSE_SUCCESS;
	unsigned int high_reset_wait_timeout, pf_reset_wait_timeout;

	high_reset_wait_timeout = (NSE_HIGH_RESET_WAIT_TIMEOUT_BASE * nse_timeout_scale);
	pf_reset_wait_timeout = (NSE_PF_RESET_WAIT_TIMEOUT_BASE * nse_timeout_scale);

	nse_debug(hw, NSE_DBG_SYS, "[%s] fwmng_locked=%d, wait_flags=0x%X, high_reset_wait_timeout=%d, pf_reset_wait_timeout=%d\n",
								__func__, fwmng_locked,
									wait_flags,
								high_reset_wait_timeout,
									pf_reset_wait_timeout);

	if (!fwmng_locked && (wait_flags & NSE_RESET_WAIT_FLAG_WAIT_FWMNG))
		mutex_lock(&hw->fwmng_lock);

	if (wait_flags & NSE_RESET_WAIT_FLAG_WAIT_FWMNG) {
		memset(&fwmng_rsp, 0, sizeof(fwmng_rsp));

		for (cnt = 0; cnt < high_reset_wait_timeout; cnt++) {
			msleep(NSE_RESET_WAIT_TICK);

				fwmng_read_clear_rsp(hw, &fwmng_rsp, true, 0);

				rsp_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(fwmng_rsp.rsp);

				if (rsp_id == fwmng_cmd_id_high_reset &&
					fwmng_rsp.rsp_buf[2] == 0) {
					fwmng_clear_rsp(hw, true, NSE_FWMNG_CLEAR_RSP_VALID_ONLY);

					dev_info(dev, "[%s, %d] saw fwmng_rsp high_reset DONE, reset_type=%d, wait_times=%d times\n",
						 __func__, __LINE__, fwmng_rsp.rsp_buf[0], cnt);
					break;
				}
		}

		if (cnt == high_reset_wait_timeout) {
			dev_err(dev, "[%s, %d] timeout wait for fwmng_rsp high_reset DONE\n",
							__func__, __LINE__);
			status = NSE_ERR_RESET_FAILED;
			goto out;
		}
	}

	if (wait_flags & NSE_RESET_WAIT_FLAG_WAIT_FRTRIG) {
		for (cnt = 0; cnt < pf_reset_wait_timeout; cnt++) {
			reg = rd32(hw, NSE_REG_CTL);

			/* underlying-FW/HW-cleanup done, FW clear this bit */
			if (!(reg & NSE_REG_CTL_FRTRIG_STATUS_M)) {
				dev_info(dev, "[%s, %d] saw PF FRTRIG cleared by high_reset underlying-cleanup, wait_times=%d\n",
								__func__, __LINE__, cnt);
				break;
			}

			msleep(NSE_RESET_WAIT_TICK);
		}

		if (cnt == pf_reset_wait_timeout) {
			dev_err(dev, "[%s, %d] timeout wait for PF FRTRIG cleared, reg_ctl=0x%X\n",
							__func__, __LINE__, reg);
			status = NSE_ERR_RESET_FAILED;
			goto out;
		}
	}

	if (wait_flags & NSE_RESET_WAIT_FLAG_WAIT_ST_MNG) {
		for (cnt = 0; cnt < high_reset_wait_timeout; cnt++) {
			reg = rd32(hw, NSE_REG_ST);

			if ((reg & NSE_REG_ST_MNG_INIT_DN_M) &&
			    !(reg & NSE_REG_ST_MNG_INIT_FAIL_M)) {
				dev_info(dev, "[%s, %d] saw ST->mng_init status OK, wait_times=%d\n",
								__func__, __LINE__, cnt);
				break;
			}

			msleep(NSE_RESET_WAIT_TICK);
		}

		if (cnt == high_reset_wait_timeout) {
			dev_err(dev, "[%s, %d] timeout wait for ST->mng_init status OK, reg_ST=0x%X\n",
							__func__, __LINE__, reg);
			status = NSE_ERR_RESET_FAILED;
			goto out;
		}
	}

	status = NSE_SUCCESS;

out:
	if (!fwmng_locked && (wait_flags & NSE_RESET_WAIT_FLAG_WAIT_FWMNG))
		mutex_unlock(&hw->fwmng_lock);

	return status;
}

/**
 * nse_pf_reset - Reset the PF, trigger a PFR
 * @hw: pointer to the hardware structure
 *
 * If a global reset has been triggered, this function checks
 * for its completion and then issues the PF reset
 */
enum nse_status nse_pf_reset(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	unsigned int reset_wait_flags;
	u32 reg;
	enum nse_status status;

	pf->pfr_count++;

	reg = rd32(hw, NSE_REG_CTL);
	if (reg & NSE_REG_CTL_FRTRIG_STATUS_M) {
		nse_debug(hw, NSE_DBG_SYS,
"[%s] detect FRTRIG is already set, possibly by high_reset, just wait it to be clear\n", __func__);
	} else {
		nse_debug(hw, NSE_DBG_SYS, "[%s] write FRTRIG to trigger\n", __func__);

		wr32(hw, NSE_REG_CTL, NSE_REG_CTL_SET_FRTRIG_M);
	}

	reset_wait_flags = (NSE_RESET_WAIT_FLAG_WAIT_FRTRIG |
						NSE_RESET_WAIT_FLAG_WAIT_ST_MNG);

	status = nse_reset_wait_complete(hw, false, reset_wait_flags);

	if (status)
		dev_err(dev, "[%s] FAIL: reset_wait_complete(), status=%d",
			__func__, (int)status);
	else
		nse_debug(hw, NSE_DBG_SYS, "[%s] SUCCESS: reset_wait_complete()\n", __func__);

	return status;
}

/**
 * nse_reset - Perform different types of reset
 * @hw: pointer to the hardware structure
 * @req: reset request
 *
 * This function triggers a reset as specified by the req parameter.
 */
enum nse_status nse_reset(struct nse_hw *hw, enum nse_reset_req req)
{
	struct device *dev = nse_hw_to_dev(hw);
	unsigned int reset_wait_flags;
	int trigger_ret = 0;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, req);

	if (nse_no_reset) {
		nse_debug(hw, NSE_DBG_SYS, "[%s] return early with no_reset=true\n", __func__);
		return NSE_SUCCESS;
	}

	switch (req) {
	case NSE_RESET_PFR:
		status = nse_pf_reset(hw);
		break;

	case NSE_RESET_HIGH_RESET_CORER:

		mutex_lock(&hw->fwmng_lock);

		trigger_ret = fwmng_high_reset_send_request_only(hw, req, true);
		if (!trigger_ret) {
			reset_wait_flags = (NSE_RESET_WAIT_FLAG_WAIT_FRTRIG |
					    NSE_RESET_WAIT_FLAG_WAIT_FWMNG |
								NSE_RESET_WAIT_FLAG_WAIT_ST_MNG);

			status = nse_reset_wait_complete(hw, true, reset_wait_flags);
		} else {
			dev_err(dev, "[%s, %d] FAIL: high_reset_send_request_only(), ret=%d\n",
				__func__, __LINE__, trigger_ret);
			status = NSE_ERR_RESET_FAILED;
		}

		mutex_unlock(&hw->fwmng_lock);

		break;

	default:
		dev_err(dev, "[%s] unsupported reset_req=%d\n",
									__func__, req);
		status = NSE_ERR_PARAM;
		break;
	}

	return status;
}

static void nse_print_aqm_error(struct nse_hw *hw, struct nse_fwmng_cmd_rsp_generic *cmd_rsp)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_err(dev, "receive AQM error event reported by FW, error_type=%d, expect core-reset happen soon\n",
					cmd_rsp->rsp_buf[0]);
}

void nse_misc_intr_handle_oicr_swint(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_fwmng_cmd_rsp_generic cmd_rsp;
	u32 rsp_id;

	nse_debug(hw, NSE_DBG_SYS, "[%s] oicr_sw_int_tmp_poll=%d\n",
		  __func__, pf->oicr_sw_int_tmp_poll);

	if (pf->oicr_sw_int_tmp_poll)
		return;

	fwmng_read_clear_rsp(hw, &cmd_rsp, true, NSE_FWMNG_CLEAR_RSP_VALID_ONLY);

	rsp_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(cmd_rsp.rsp);

	if (rsp_id == fwmng_cmd_id_high_reset)
		nse_high_reset_detect_on_fwmng(hw, &cmd_rsp);
	else if (rsp_id == fwmng_evt_id_aqm_err)
		nse_print_aqm_error(hw, &cmd_rsp);
	else
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] unknown rsp_id = 0x%X\n",
			  __func__, __LINE__, rsp_id);
}

void nse_oicr_sw_int_tmp_poll_timer(struct timer_list *t)
{
	struct nse_pf *pf = from_timer(pf, t, oicr_sw_int_tmp_poll_timer);
	struct nse_hw *hw = &pf->hw;
	struct nse_fwmng_cmd_rsp_generic cmd_rsp;
	u32 rsp_id;

	pf->oicr_sw_int_tmp_poll_timer_run_cnt++;

	if (!pf->oicr_sw_int_tmp_poll)
		return;

	fwmng_read_clear_rsp(hw, &cmd_rsp, true, 0);

	rsp_id = NSE_FWMNG_CMD_REQ_RSP_GET_ID(cmd_rsp.rsp);

	if (rsp_id == fwmng_cmd_id_high_reset) {
		if (!nse_is_high_reset_in_progress(pf->state)) {
			nse_debug(hw, NSE_DBG_SYS, "[%s] detect high reset\n", __func__);

			nse_high_reset_detect_on_fwmng(hw, &cmd_rsp);

			nse_service_task_schedule(pf);	/* submit reset_subtask */
		}
	} else if (rsp_id == fwmng_evt_id_aqm_err) {
		nse_print_aqm_error(hw, &cmd_rsp);
	}

	mod_timer(&pf->oicr_sw_int_tmp_poll_timer, (jiffies + 128));
}

/**
 * nse_get_lan_q_ctx - get the LAN queue context for the given VSI and TC
 * @hw: pointer to the HW struct
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @q_handle: software queue handle
 */
struct nse_q_ctx *
nse_get_lan_q_ctx(struct nse_hw *hw, u16 vsi_handle, u8 tc, u16 q_handle)
{
	struct nse_vsi_ctx *vsi;
	struct nse_q_ctx *q_ctx;

	vsi = nse_get_vsi_ctx(hw, vsi_handle);
	if (!vsi)
		return NULL;
	if (q_handle >= vsi->num_lan_q_entries[tc])
		return NULL;
	if (!vsi->lan_q_ctx[tc])
		return NULL;
	q_ctx = vsi->lan_q_ctx[tc];
	return &q_ctx[q_handle];
}

/**
 * nse_cfg_vsi_qs - configure the new/existing VSI queues
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_bitmap: TC bitmap
 * @maxqs: max queues array per TC
 * @owner: LAN or RDMA
 *
 * This function adds/updates the VSI queues per TC.
 */
static enum nse_status
nse_cfg_vsi_qs(struct nse_port_info *pi, u16 vsi_handle, u16 tc_bitmap,
	       u16 *maxqs, u8 owner)
{
	enum nse_status status = 0;
	u8 i;

	if (!pi || pi->sched_info.sched_state != NSE_SCHED_STATE_READY)
		return NSE_ERR_CFG;

	if (!nse_is_vsi_valid(pi->hw, vsi_handle))
		return NSE_ERR_PARAM;

	mutex_lock(&pi->sched_info.sched_lock);

	nse_for_each_traffic_class(i) {
		/* configuration is possible only if TC node is present */
		if (!nse_sched_get_tc_node(pi, i))
			continue;

		status = nse_sched_cfg_vsi(pi, vsi_handle, i, maxqs[i], owner,
					   nse_is_tc_ena((unsigned long)tc_bitmap, i));
		if (status)
			break;
	}

	mutex_unlock(&pi->sched_info.sched_lock);
	return status;
}

/**
 * nse_cfg_vsi_lan - configure VSI LAN queues
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_bitmap: TC bitmap
 * @max_lanqs: max LAN queues array per TC
 *
 * This function adds/updates the VSI LAN queues per TC.
 */
enum nse_status
nse_cfg_vsi_lan(struct nse_port_info *pi, u16 vsi_handle, u16 tc_bitmap,
		u16 *max_lanqs)
{
	return nse_cfg_vsi_qs(pi, vsi_handle, tc_bitmap, max_lanqs,
			      NSE_SCHED_NODE_OWNER_LAN);
}

/**
 * nse_cfg_vsi_rdma - configure the VSI RDMA queues
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc_bitmap: TC bitmap
 * @max_rdmaqs: max RDMA queues array per TC
 *
 * This function adds/updates the VSI RDMA queues per TC.
 */
enum nse_status
nse_cfg_vsi_rdma(struct nse_port_info *pi, u16 vsi_handle, u16 tc_bitmap,
		 u16 *max_rdmaqs)
{
	return nse_cfg_vsi_qs(pi, vsi_handle, tc_bitmap, max_rdmaqs,
			      NSE_SCHED_NODE_OWNER_RDMA);
}

enum nse_status
nse_ena_vsi_txq(struct nse_port_info *pi, u16 vsi_handle, u8 tc, struct nse_ring *tx_ring,
		u32 *leaf_node_tnid)
{
	struct nse_hw *hw;
	struct nse_pf *pf;
	struct device *dev;
	struct nse_sched_node *parent = NULL, *prev_sibling = NULL,
		*next_sibling = NULL, *tc_node = NULL, *new_node = NULL;
	struct nse_q_ctx *q_ctx = NULL;
	struct nse_aqc_qos_sch_add_node_one *cmd_data = NULL;
	u16 q_abs_id = 0;
	enum nse_status status;

	if (!pi || pi->sched_info.sched_state != NSE_SCHED_STATE_READY)
		return NSE_ERR_CFG;

	hw = pi->hw;
	pf = (struct nse_pf *)hw->back;
	dev = nse_pf_to_dev(pf);

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(dev, "FAIL: invalid vsi_handle=%d\n", vsi_handle);
		return NSE_ERR_PARAM;
	}

	tc_node = nse_sched_get_tc_node(pi, tc);
	if (!tc_node) {
		dev_err(dev, "FAIL: SW-TC-node (tc=%d) not exist?\n", tc);
		return NSE_ERR_PARAM;
	}

	q_abs_id = tx_ring->reg_idx + pf->lan_txq_space_start;

	cmd_data = devm_kzalloc(dev, sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	mutex_lock(&pi->sched_info.sched_lock);

	q_ctx = nse_get_lan_q_ctx(hw, vsi_handle, tc, tx_ring->q_handle);
	if (!q_ctx) {
		dev_err(dev, "FAIL: invalid queue handle %d\n",
			  tx_ring->q_handle);
		status = NSE_ERR_PARAM;
		goto ena_txq_exit;
	}

	/* find a parent node */
	parent = nse_sched_get_free_qparent(pi, vsi_handle, tc,
					    NSE_SCHED_NODE_OWNER_LAN);
	if (!parent) {
		dev_err(dev, "FAIL: sched_get_free_qparent() return NULL");
		status = NSE_ERR_PARAM;
		goto ena_txq_exit;
	}

	nse_sched_fill_cmd_data_add_node_one(pi, cmd_data,
					     parent,
					     &prev_sibling, &next_sibling,
					     true, q_abs_id, QID_TYPE_LAN_TXQ);

	nse_sched_aqc_fill_node_default_sch_param(hw, &cmd_data->sch_param, true, tc);

	status = nse_sched_aqc_add_node_one(hw, cmd_data);

	if (status) {
		dev_err(dev, "FAIL: sched_aqc_add_node_one(), status=%d(%s)\n",
						status, nse_stat_str(status));
		goto ena_txq_exit;
	}

	*leaf_node_tnid = le32_to_cpu(cmd_data->new_child_tnid);

	q_ctx->q_handle = tx_ring->q_handle;
	q_ctx->q_tnid = *leaf_node_tnid;

	status = nse_sched_add_one_sw_node(pi, tc_node, parent, pi->sched_info.layer_id_leaf,
					   prev_sibling, next_sibling,
					   *leaf_node_tnid,
											cmd_data,
											&new_node);
	if (status) {
		dev_err(dev, "FAIL: sched_add_one_sw_node(), status=%d(%s), HW-LEAF-node (tnid=%d, LAN-TXQ=%d) not functional\n",
						status, nse_stat_str(status),
						*leaf_node_tnid, q_abs_id);

		goto ena_txq_exit;
	}

	new_node->qid = q_abs_id;
	new_node->qid_type = QID_TYPE_LAN_TXQ;

	status = nse_sched_set_leaf_qid2lnid(hw, q_abs_id, QID_TYPE_LAN_TXQ,
					     new_node->tnid, new_node->suid,
						     new_node->logic_idx_in_su);

	if (status) {
		dev_err(dev, "FAIL: sched_set_leaf_qid2lnid(), status=%d(%s), HW-LEAF-node (tnid=%d, LAN-TXQ=%d) not functional\n",
						status, nse_stat_str(status),
						*leaf_node_tnid, q_abs_id);

		goto ena_txq_exit;
	}

	status = nse_sched_replay_q_bw(pi, q_ctx);
	if (status)
		dev_info(dev, "WARN: sched_replay_q_bw(tnid=%d)\n", new_node->tnid);

	status = NSE_SUCCESS;

ena_txq_exit:
	mutex_unlock(&pi->sched_info.sched_lock);

	if (cmd_data)
		devm_kfree(dev, cmd_data);

	return status;
}

enum nse_status
nse_dis_vsi_txq(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u16 q_handle, u16 q_abs_id, u32 q_tnid)
{
	struct nse_hw *hw;
	struct device *dev;
	struct nse_q_ctx *q_ctx;
	struct nse_sched_node *node, *parent, *prev_sibling, *next_sibling, *dummy;
	struct nse_aqc_qos_sch_del_node_one *cmd_data = NULL;
	bool already_unlinked = false;
	enum nse_status status = NSE_ERR_DOES_NOT_EXIST;

	if (!pi || pi->sched_info.sched_state != NSE_SCHED_STATE_READY)
		return NSE_ERR_CFG;

	hw = pi->hw;
	dev = nse_hw_to_dev(hw);

	cmd_data = devm_kzalloc(dev, sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	mutex_lock(&pi->sched_info.sched_lock);

	node = nse_sched_find_node_by_tnid(pi->sched_info.root, q_tnid);
	if (!node) {
		dev_warn(dev, "WARN: node (q_tnid=%d) not exist in SW-tree --- maybe freeing a VF-VSI without TXQ LEAF-node allocated yet\n",
						q_tnid);
		goto out;
	}

	parent = node->parent;
	if (!parent) {
		dev_err(dev, "FAIL: how come node (q_tnid=%d) does not have parent\n", q_tnid);
		goto out;
	}

	q_ctx = nse_get_lan_q_ctx(hw, vsi_handle, tc, q_handle);
	if (!q_ctx) {
		dev_err(dev, "FAIL: lan_q_ctx (vsi_handle=%d, tc=%d, q_handle=%d) not exist\n",
					vsi_handle, tc, q_handle);
		goto out;
	}

	if (q_ctx->q_handle != q_handle) {
		dev_err(dev, "FAIL: lan_q_ctx->q_handle=%d, != q_handle=%d\n",
					q_ctx->q_handle, q_handle);
		goto out;
	}

	if (nse_sched_no_need_to_del_hw_node(hw)) {
		dev_info(dev, "current status make no need to delete HW-node, delete SW-node only\n");

		goto delete_sw_node;
	}

	status = nse_sched_unset_node_cir(pi, node, true);
	if (status)
		dev_info(dev, "[%s] WARN: status=%d(%s), sched_unset_node_cir(LAN-TXQ q_abs_id=%d, tnid=%d)\n",
							__func__, status, nse_stat_str(status),
							q_abs_id, node->tnid);

	status = nse_sched_fill_cmd_data_del_node_one_and_unlink_sw_node(pi, cmd_data,
							parent, node->tnid, &dummy,
								&prev_sibling, &next_sibling,
							true);
	if (status) {
		dev_err(dev, "FAIL: sched_fill_cmd_data_del_node_one_and_unlink_sw_node() return %d(%s)\n",
					status, nse_stat_str(status));

		if (node == dummy)
			already_unlinked = true;

		goto delete_sw_node;
	}

	already_unlinked = true;

	status = nse_sched_aqc_del_node_one(hw, cmd_data);

	if (status)
		dev_err(dev, "FAIL: sched_aqc_del_node_one() to delete HW-node, status=%d(%s)\n",
						status, nse_stat_str(status));

delete_sw_node:

	nse_sched_del_one_sw_node(hw, parent, node, already_unlinked);

	q_ctx->q_handle = NSE_INVAL_Q_HANDLE;
	q_ctx->q_tnid = NSE_SCHED_INVAL_TNID;

	status = NSE_SUCCESS;

out:
	mutex_unlock(&pi->sched_info.sched_lock);

	if (cmd_data)
		devm_kfree(dev, cmd_data);

	return status;
}

/**
 * nse_ena_vsi_rdma_qset
 * @pi: port information structure
 * @vsi_handle: software VSI handle
 * @tc: TC number
 * @rdma_qset: pointer to RDMA qset
 * @num_qsets: number of RDMA qsets
 * @qset_teid: pointer to qset node teids
 *
 * This function adds RDMA qset
 */
enum nse_status
nse_ena_vsi_rdma_qset(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		      u16 rdma_qset_abs_id, u32 *leaf_node_tnid)
{
	struct nse_hw *hw;
	struct nse_pf *pf;
	struct device *dev;
	struct nse_sched_node *parent = NULL, *prev_sibling = NULL,
		*next_sibling = NULL, *tc_node = NULL, *new_node = NULL;
	struct nse_aqc_qos_sch_add_node_one *cmd_data = NULL;
	enum nse_status status;

	if (!pi || pi->sched_info.sched_state != NSE_SCHED_STATE_READY)
		return NSE_ERR_CFG;

	hw = pi->hw;
	pf = (struct nse_pf *)hw->back;
	dev = nse_pf_to_dev(pf);

	if (!nse_is_vsi_valid(hw, vsi_handle)) {
		dev_err(dev, "FAIL: invalid vsi_handle=%d\n", vsi_handle);
		return NSE_ERR_PARAM;
	}

	tc_node = nse_sched_get_tc_node(pi, tc);
	if (!tc_node) {
		dev_err(dev, "FAIL: SW-TC-node (tc=%d) not exist?\n", tc);
		return NSE_ERR_PARAM;
	}

	cmd_data = devm_kzalloc(dev, sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	mutex_lock(&pi->sched_info.sched_lock);

	/* find a parent node */
	parent = nse_sched_get_free_qparent(pi, vsi_handle, tc,
					    NSE_SCHED_NODE_OWNER_RDMA);
	if (!parent) {
		status = NSE_ERR_PARAM;
		goto rdma_error_exit;
	}

	nse_sched_fill_cmd_data_add_node_one(pi, cmd_data,
					     parent,
					     &prev_sibling, &next_sibling,
					     true, rdma_qset_abs_id, QID_TYPE_RDMA_QSET);

	nse_sched_aqc_fill_node_default_sch_param(hw, &cmd_data->sch_param, true, tc);

	status = nse_sched_aqc_add_node_one(hw, cmd_data);

	if (status) {
		dev_err(dev, "FAIL: sched_aqc_add_node_one(), status=%d(%s)\n",
						status, nse_stat_str(status));
		goto rdma_error_exit;
	}

	*leaf_node_tnid = le32_to_cpu(cmd_data->new_child_tnid);

	status = nse_sched_add_one_sw_node(pi, tc_node, parent, pi->sched_info.layer_id_leaf,
					   prev_sibling, next_sibling,
					   *leaf_node_tnid,
											cmd_data,
											&new_node);
	if (status) {
		dev_err(dev, "FAIL: sched_add_one_sw_node(), status=%d(%s), HW-LEAF-node (tnid=%d, RDMA-QSET=%d) not functional\n",
						status, nse_stat_str(status),
						*leaf_node_tnid, rdma_qset_abs_id);

		goto rdma_error_exit;
	}

	new_node->qid = rdma_qset_abs_id;
	new_node->qid_type = QID_TYPE_RDMA_QSET;

	status = nse_sched_set_leaf_qid2lnid(hw, rdma_qset_abs_id, QID_TYPE_RDMA_QSET,
					     new_node->tnid, new_node->suid,
						     new_node->logic_idx_in_su);

	if (status) {
		dev_err(dev, "FAIL: sched_set_leaf_qid2lnid(), status=%d(%s), HW-LEAF-node (tnid=%d, RDMA-QSET=%d) not functional\n",
						status, nse_stat_str(status),
						*leaf_node_tnid, rdma_qset_abs_id);

		goto rdma_error_exit;
	}

rdma_error_exit:
	mutex_unlock(&pi->sched_info.sched_lock);

	if (cmd_data)
		devm_kfree(dev, cmd_data);

	return status;
}

/**
 * nse_dis_vsi_rdma_qset - free RDMA resources
 * @pi: port_info struct
 * @count: number of RDMA qsets to free
 * @qset_teid: TEID of qset node
 * @q_id: list of queue IDs being disabled
 */
enum nse_status
nse_dis_vsi_rdma_qset(struct nse_port_info *pi, u32 leaf_node_tnid,
		      u16 rdma_qset_abs_id)
{
	struct nse_hw *hw;
	struct device *dev;
	struct nse_sched_node *node, *parent, *prev_sibling, *next_sibling, *dummy;
	struct nse_aqc_qos_sch_del_node_one *cmd_data = NULL;
	bool already_unlinked = false;
	enum nse_status status = NSE_ERR_DOES_NOT_EXIST;

	if (!pi || pi->sched_info.sched_state != NSE_SCHED_STATE_READY)
		return NSE_ERR_CFG;

	hw = pi->hw;
	dev = nse_hw_to_dev(hw);

	nse_debug(hw, NSE_DBG_SCHED, "[%s] leaf_node_tnid=%d, rdma_qset_abs_id=%d\n",
		  __func__, leaf_node_tnid, rdma_qset_abs_id);

	cmd_data = devm_kzalloc(dev, sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	mutex_lock(&pi->sched_info.sched_lock);

	node = nse_sched_find_node_by_tnid(pi->sched_info.root, leaf_node_tnid);
	if (!node) {
		dev_err(dev, "FAIL: node (leaf_node_tnid=%d) not exist in SW-tree --- maybe freeing a VF-VSI without RDMA LEAF-node allocated yet\n",
					leaf_node_tnid);
		goto out;
	}

	parent = node->parent;
	if (!parent) {
		dev_err(dev, "FAIL: how come node (leaf_node_tnid=%d) does not have parent\n",
			leaf_node_tnid);
		goto out;
	}

	if (nse_sched_no_need_to_del_hw_node(hw)) {
		dev_info(dev, "current status make no need to delete HW-node, delete SW-node only\n");

		goto delete_sw_node;
	}

	status = nse_sched_fill_cmd_data_del_node_one_and_unlink_sw_node(pi, cmd_data,
							parent, node->tnid, &dummy,
								&prev_sibling, &next_sibling,
							true);
	if (status) {
		dev_err(dev, "FAIL: sched_fill_cmd_data_del_node_one_and_unlink_sw_node() return %d(%s)\n",
					status, nse_stat_str(status));

		if (node == dummy)
			already_unlinked = true;

		goto delete_sw_node;
	}

	already_unlinked = true;

	status = nse_sched_aqc_del_node_one(hw, cmd_data);

	if (status)
		dev_err(dev, "FAIL: sched_aqc_del_node_one() to delete HW-node, status=%d(%s)\n",
						status, nse_stat_str(status));

delete_sw_node:

	nse_sched_del_one_sw_node(hw, parent, node, already_unlinked);

	status = NSE_SUCCESS;

out:
	mutex_unlock(&pi->sched_info.sched_lock);

	if (cmd_data)
		devm_kfree(dev, cmd_data);

	return status;
}

/**
 * nse_is_main_vsi - checks whether the VSI is main VSI
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * Checks whether the VSI is the main VSI (the first PF VSI created on
 * given PF).
 */
bool nse_is_main_vsi(struct nse_hw *hw, u16 vsi_handle)
{
	return vsi_handle == NSE_MAIN_VSI_HANDLE && hw->vsi_ctx[vsi_handle];
}

/**
 * nse_is_two_port - checks whether is two lan ports in hw
 * @hw: pointer to the HW struct
 *
 */
bool nse_is_two_lan_ports(struct nse_hw *hw)
{
	return bitmap_weight((unsigned long *)&hw->lan_bitmap, NSE_MAX_LAN_PORT_NUM) == 2;
}

/**
 * nse_replay_pre_init - replay pre initialization
 * @hw: pointer to the HW struct
 * @sw: pointer to switch info struct for which function initializes filters
 *
 * Initializes required config data for VSI, FD, ACL, and RSS before replay.
 */
void
nse_replay_pre_init(struct nse_hw *hw,
					enum nse_reset_req reset_type)
{
/*	Our current HW/SW design is:	# unlike E810
 *
 *		Our HW RPP/TPP switch filters table is per-LAN-channel
 *
 *		PF reset (PFR or PFLR) only reset this PF and port, not per-LAN-channel.
 *
 *
 *		So if just PF reset, the HW switch filters and recipes
 *		should persist in LAN-channel, not flushed by HW.
 *
 *		There is no need to replay them.
 *
 *
 *		But if any high-reset (like LAN-channel reset or chip-level global reset),
 *		the HW switch filters and recipes should be flushed and lost.
 *
 *		PF driver should replay recipes and filters.
 */

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n",
								__func__, reset_type);

	if (nse_bypass_switch)
		return;

	if (nse_is_high_reset_type(reset_type)) {
		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX)) {
			/* Delete old entries from replay filter list head if there is any */
			nse_drain_sw_replay_list_flex(hw);
			/* In start of replay, move entries into replay_rules list, it
			 * will allow adding rules entries back to filt_rules list,
			 * which is operational list.
			 */
			nse_replace_sw_replay_list_flex(hw);

		} else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY)) {
			nse_drain_sw_replay_list_legacy(hw);
			nse_replace_sw_replay_list_legacy(hw);
		}
	}
}

void
nse_replay_post(struct nse_hw *hw,
				enum nse_reset_req reset_type)
{
	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	if (nse_bypass_switch)
		return;

	if (nse_is_high_reset_type(reset_type)) {
		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX)) {
			/* Delete old entries from replay filter list head if there is any */
			nse_drain_sw_replay_list_flex(hw);
		} else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY)) {
			nse_drain_sw_replay_list_legacy(hw);
		}
	}
}

/**
 * nse_replay_vsi - replay VSI configuration
 * @hw: pointer to the HW struct
 * @vsi_handle: driver VSI handle
 *
 * Restore all VSI configuration after reset. It is required to call this
 * function with main VSI first.
 */
enum nse_status
nse_replay_vsi(struct nse_hw *hw,
				u16 vsi_handle,
				enum nse_reset_req reset_type)
{
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi_handle=%d, reset_type=%d\n",
								__func__, vsi_handle,
									reset_type);

	if (!nse_is_vsi_valid(hw, vsi_handle))
		return NSE_ERR_PARAM;

	/* Replay per VSI all filters */
	if (nse_is_high_reset_type(reset_type)) {
		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
			status = nse_replay_vsi_all_fltr_flex(hw, vsi_handle);
		else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
			status = nse_replay_vsi_all_fltr_legacy(hw, vsi_handle);
	}

	return status;
}

void
nse_stat_update64(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat)
{
	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (U64_MAX - *prev_stat) + new_data;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

void
nse_stat_update48(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat)
{
	new_data &= (BIT_ULL(48) - 1);

	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(48)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

void
nse_stat_update32(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat)
{
	new_data &= (BIT_ULL(32) - 1);

	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(32)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

void
nse_stat_update16(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat)
{
	new_data &= (BIT_ULL(16) - 1);

	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (new_data + BIT_ULL(16)) - *prev_stat;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

static enum nse_status
__nse_aq_lan_read_write_rxq_txq_ctx(struct nse_hw *hw,
				    struct nse_aqc_lan_rxq_txq_ctx *cmd_data, u8 opc_subcode)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, opc_subcode);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_write_rxq_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_lan_rxq_ctx *rlan_ctx,
		  u16 rxq_abs_id)
{
	struct nse_aqc_lan_rxq_txq_ctx *cmd_data = NULL;
	int i;
	enum nse_status ret;

	if (!rlan_ctx)
		return NSE_ERR_BAD_PTR;

	if (!rlan_ctx->ctx_data_len || rlan_ctx->ctx_data_len > NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MAX) {
		dev_err(nse_hw_to_dev(hw), "[%s] BAD: ctx_data_len=%d\n",
			__func__, rlan_ctx->ctx_data_len);
		return NSE_ERR_INVAL_SIZE;
	}

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, vsi->vsi_abs_num);

	cmd_data->q_abs_id = cpu_to_le16(rxq_abs_id);

	for (i = 0; i < rlan_ctx->ctx_data_len; i++)
		cmd_data->ctx_data[i] = cpu_to_le32(rlan_ctx->data[i]);

	ret = __nse_aq_lan_read_write_rxq_txq_ctx(hw, cmd_data, NSE_AQ_OPC_WRITE_LAN_RXQ_CTX);

	kfree(cmd_data);

	return ret;
}

enum nse_status
nse_write_txq_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_lan_txq_ctx *tlan_ctx,
		  u16 txq_abs_id)
{
	struct nse_aqc_lan_rxq_txq_ctx *cmd_data = NULL;
	int i;
	enum nse_status ret;

	if (!tlan_ctx)
		return NSE_ERR_BAD_PTR;

	if (!tlan_ctx->ctx_data_len || tlan_ctx->ctx_data_len > NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MAX) {
		dev_err(nse_hw_to_dev(hw), "[%s] BAD: ctx_data_len=%d\n",
			__func__, tlan_ctx->ctx_data_len);
		return NSE_ERR_INVAL_SIZE;
	}

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, vsi->vsi_abs_num);

	cmd_data->q_abs_id = cpu_to_le16(txq_abs_id);

	for (i = 0; i < tlan_ctx->ctx_data_len; i++)
		cmd_data->ctx_data[i] = cpu_to_le32(tlan_ctx->data[i]);

	ret = __nse_aq_lan_read_write_rxq_txq_ctx(hw, cmd_data, NSE_AQ_OPC_WRITE_LAN_TXQ_CTX);

	kfree(cmd_data);

	return ret;
}

enum nse_status
nse_read_rxq_ctx(struct nse_hw *hw, struct nse_lan_rxq_ctx *rlan_ctx,
		  u16 rxq_abs_id)
{
	enum nse_status ret;
	struct nse_aqc_lan_rxq_txq_ctx *cmd_data = NULL;
	int i;

	if (!rlan_ctx)
		return NSE_ERR_BAD_PTR;

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->q_abs_id = cpu_to_le16(rxq_abs_id);

	ret = __nse_aq_lan_read_write_rxq_txq_ctx(hw, cmd_data, NSE_AQ_OPC_READ_LAN_RXQ_CTX);
	if (!ret) {
		for (i = 0; i < NSE_LAN_RXQ_CTX_LEN_IN_DWORD_MAX; i++)
			rlan_ctx->data[i] = le32_to_cpu(cmd_data->ctx_data[i]);
	}

	kfree(cmd_data);

	return ret;
}

enum nse_status
nse_read_txq_ctx(struct nse_hw *hw, struct nse_lan_txq_ctx *tlan_ctx,
		  u16 txq_abs_id)
{
	enum nse_status ret;
	struct nse_aqc_lan_rxq_txq_ctx *cmd_data = NULL;
	int i;

	if (!tlan_ctx)
		return NSE_ERR_BAD_PTR;

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->q_abs_id = cpu_to_le16(txq_abs_id);

	ret = __nse_aq_lan_read_write_rxq_txq_ctx(hw, cmd_data, NSE_AQ_OPC_READ_LAN_TXQ_CTX);
	if (!ret) {
		for (i = 0; i < NSE_LAN_TXQ_CTX_LEN_IN_DWORD_MAX; i++)
			tlan_ctx->data[i] = le32_to_cpu(cmd_data->ctx_data[i]);
	}

	kfree(cmd_data);

	return ret;
}

static enum nse_status
__nse_aq_lan_dis_ena_lan_rxq_txq(struct nse_hw *hw, u8 opc_subcode, u16 q_abs_id, u16 irqll_msix)
{
	struct nse_aq_desc desc;
	struct nse_aqc_lan_ena_dis_rxq_txq cmd_data;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, opc_subcode);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	cmd_data.q_abs_id = cpu_to_le16(q_abs_id);
	cmd_data.irqll_msix = cpu_to_le16(irqll_msix);

	return nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);
}

enum nse_status
nse_aq_lan_disable_rxq(struct nse_hw *hw, u16 rxq_abs_id, u16 irqll_msix)
{
	return __nse_aq_lan_dis_ena_lan_rxq_txq(hw, NSE_AQ_OPC_DISABLE_LAN_RXQ,
						rxq_abs_id, irqll_msix);
}

enum nse_status
nse_aq_lan_disable_txq(struct nse_hw *hw, u16 txq_abs_id, u16 irqll_msix)
{
	return __nse_aq_lan_dis_ena_lan_rxq_txq(hw, NSE_AQ_OPC_DISABLE_LAN_TXQ,
						txq_abs_id, irqll_msix);
}

enum nse_status
nse_aq_lan_enable_rxq(struct nse_hw *hw, u16 rxq_abs_id, u16 irqll_msix)
{
	return __nse_aq_lan_dis_ena_lan_rxq_txq(hw, NSE_AQ_OPC_ENABLE_LAN_RXQ,
						rxq_abs_id, irqll_msix);
}

enum nse_status
nse_aq_lan_enable_txq(struct nse_hw *hw, u16 txq_abs_id, u16 irqll_msix)
{
	return __nse_aq_lan_dis_ena_lan_rxq_txq(hw, NSE_AQ_OPC_ENABLE_LAN_TXQ,
						txq_abs_id, irqll_msix);
}

enum nse_status
__nse_aq_lan_ena_dis_rxq_txq_many(struct nse_hw *hw, u32 ena_or_dis, u32 qtype,
						u16 firstq_abs_id, u16 lastq_abs_id,
							u16 *irqll_msix)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_aq_desc desc;
	struct nse_aqc_lan_ena_dis_rxq_txq_many *cmd_data = NULL;
	unsigned int cmd_data_size, q_cnt;
	u16 i;
	enum nse_status status = 0;

	if (firstq_abs_id > lastq_abs_id) {
		dev_err(dev, "[%s] sanity BAD: firstq_abs_id (%d) > lastq_abs_id (%d)\n",
						__func__, firstq_abs_id, lastq_abs_id);
		status = NSE_ERR_PARAM;
		goto out;
	}

	q_cnt = (lastq_abs_id - firstq_abs_id + 1);
	if ((!qtype && q_cnt > pf->lan_rxq_space_size) ||
		(qtype && q_cnt > pf->lan_txq_space_size)) {
		dev_err(dev, "[%s] sanity BAD: q_cnt (%d) out of range\n",
						__func__, q_cnt);
		status = NSE_ERR_PARAM;
		goto out;
	}

	cmd_data_size = sizeof(struct nse_aqc_lan_ena_dis_rxq_txq_many);
	cmd_data_size += (sizeof(u16) * q_cnt);
	cmd_data_size = roundup(cmd_data_size, 4);

	if (cmd_data_size > NSE_AQ_MAX_BUF_LEN) {
		dev_err(dev, "[%s] cmd_data_size=%d too large\n",
						__func__, cmd_data_size);
		status = NSE_ERR_PARAM;
		goto out;
	}

	nse_debug(hw, NSE_DBG_LAN, "[%s] ena_or_dis=%d, qtype=%d, firstq_abs_id=%d, lastq_abs_id=%d, q_cnt=%d, cmd_data_size=%d\n",
				__func__, ena_or_dis, qtype, firstq_abs_id,
					lastq_abs_id, q_cnt, cmd_data_size);

	cmd_data = kzalloc(cmd_data_size, GFP_KERNEL);
	if (!cmd_data) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN,
				      NSE_AQ_OPC_ENA_DIS_LAN_RXQ_TXQ_MANY);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->ena_or_dis = ena_or_dis;
	cmd_data->qtype = qtype;

	cmd_data->firstq_abs_id = cpu_to_le16(firstq_abs_id);
	cmd_data->lastq_abs_id = cpu_to_le16(lastq_abs_id);

	if (irqll_msix != NULL) {
		for (i = 0; i < q_cnt; i++)
			cmd_data->irqll_msix[i] = cpu_to_le16(irqll_msix[i]);
	} else {
		for (i = 0; i < q_cnt; i++)
			cmd_data->irqll_msix[i] = cpu_to_le16(NSE_AQC_CONF_IRQLL_INVALID_MSIX);
	}

	status = nse_aq_send_cmd(hw, &desc, cmd_data, cmd_data_size, NULL);

out:
	kfree(cmd_data);

	return status;
}

enum nse_status
nse_aq_lan_ena_rxq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix)
{
	return __nse_aq_lan_ena_dis_rxq_txq_many(hw, 1, 0, firstq_abs_id, lastq_abs_id, irqll_msix);
}

enum nse_status
nse_aq_lan_dis_rxq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix)
{
	return __nse_aq_lan_ena_dis_rxq_txq_many(hw, 0, 0, firstq_abs_id, lastq_abs_id, irqll_msix);
}

enum nse_status
nse_aq_lan_ena_txq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix)
{
	return __nse_aq_lan_ena_dis_rxq_txq_many(hw, 1, 1, firstq_abs_id, lastq_abs_id, irqll_msix);
}

enum nse_status
nse_aq_lan_dis_txq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix)
{
	return __nse_aq_lan_ena_dis_rxq_txq_many(hw, 0, 1, firstq_abs_id, lastq_abs_id, irqll_msix);
}

static enum nse_status
__nse_aq_lan_read_rxq_txq_status(struct nse_hw *hw, u16 q_abs_id, u8 opc_subcode, u16 *q_stat)
{
	struct nse_aq_desc desc;
	struct nse_aqc_lan_rxq_txq_status cmd_data;
	enum nse_status ret;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, opc_subcode);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	cmd_data.q_abs_id = cpu_to_le16(q_abs_id);

	ret = nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);
	if (!ret)
		*q_stat = le16_to_cpu(cmd_data.q_status);

	return ret;
}

enum nse_status
nse_aq_lan_read_rxq_status(struct nse_hw *hw, u16 rxq_abs_id, u16 *q_stat)
{
	return __nse_aq_lan_read_rxq_txq_status(hw, rxq_abs_id,
						NSE_AQ_OPC_READ_LAN_RXQ_STATUS, q_stat);
}

enum nse_status
nse_aq_lan_read_txq_status(struct nse_hw *hw, u16 txq_abs_id, u16 *q_stat)
{
	return __nse_aq_lan_read_rxq_txq_status(hw, txq_abs_id,
						NSE_AQ_OPC_READ_LAN_TXQ_STATUS, q_stat);
}

static enum nse_status
__nse_aq_lan_read_write_cq_ctx(struct nse_hw *hw,
			       struct nse_aqc_read_write_lan_cq_ctx *cmd_data, u8 opc_subcode)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, opc_subcode);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

static enum nse_status
__nse_aq_lan_dis_ena_cq(struct nse_hw *hw,
			struct nse_aqc_disable_enable_lan_cq *cmd_data, u8 opc_subcode)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, opc_subcode);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

static enum nse_status
nse_aq_lan_read_cq_status(struct nse_hw *hw, struct nse_aqc_read_lan_cq_status *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN,
				      NSE_AQ_OPC_READ_LAN_CQ_STATUS);

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_read_lan_txcq_ctx(struct nse_hw *hw, struct nse_lan_txcq_ctx *cq_ctx,
		  u16 cq_abs_id)
{
	struct nse_aqc_read_write_lan_cq_ctx *cmd_data = NULL;
	int i;
	enum nse_status ret;

	if (!cq_ctx)
		return NSE_ERR_BAD_PTR;

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->cq_abs_id = cpu_to_le16(cq_abs_id);

	ret = __nse_aq_lan_read_write_cq_ctx(hw, cmd_data, NSE_AQ_OPC_READ_LAN_CQ_CTX);
	if (!ret) {
		for (i = 0; i < NSE_LAN_TXCQ_CTX_LEN_IN_DWORD; i++)
			cq_ctx->data[i] = le32_to_cpu(cmd_data->ctx_data[i]);
	}

	kfree(cmd_data);

	return ret;
}

enum nse_status
nse_write_lan_txcq_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_lan_txcq_ctx *cq_ctx,
		  u16 cq_abs_id)
{
	struct nse_aqc_read_write_lan_cq_ctx *cmd_data = NULL;
	int i;
	enum nse_status ret;

	if (!cq_ctx)
		return NSE_ERR_BAD_PTR;

	cmd_data = kzalloc(sizeof(*cmd_data), GFP_KERNEL);
	if (!cmd_data)
		return NSE_ERR_NO_MEMORY;

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, vsi->vsi_abs_num);

	cmd_data->cq_abs_id = cpu_to_le16(cq_abs_id);

	for (i = 0; i < NSE_LAN_TXCQ_CTX_LEN_IN_DWORD; i++)
		cmd_data->ctx_data[i] = cpu_to_le32(cq_ctx->data[i]);

	ret = __nse_aq_lan_read_write_cq_ctx(hw, cmd_data, NSE_AQ_OPC_WRITE_LAN_CQ_CTX);

	kfree(cmd_data);

	return ret;
}

enum nse_status
nse_disable_lan_txcq(struct nse_hw *hw, struct nse_vsi *vsi, u16 cq_abs_id, u16 irqll_msix)
{
	struct nse_aqc_disable_enable_lan_cq cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, vsi->vsi_abs_num);

	cmd_data.cq_abs_id = cpu_to_le16(cq_abs_id);
	cmd_data.irqll_msix = cpu_to_le16(irqll_msix);

	return __nse_aq_lan_dis_ena_cq(hw, &cmd_data, NSE_AQ_OPC_DISABLE_LAN_CQ);
}

enum nse_status
nse_enable_lan_txcq(struct nse_hw *hw, struct nse_vsi *vsi, u16 cq_abs_id, u16 irqll_msix)
{
	struct nse_aqc_disable_enable_lan_cq cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, vsi->vsi_abs_num);

	cmd_data.cq_abs_id = cpu_to_le16(cq_abs_id);
	cmd_data.irqll_msix = cpu_to_le16(irqll_msix);

	return __nse_aq_lan_dis_ena_cq(hw, &cmd_data, NSE_AQ_OPC_ENABLE_LAN_CQ);
}

enum nse_status
nse_read_lan_txcq_status(struct nse_hw *hw, struct nse_vsi *vsi, u16 cq_abs_id, u16 *q_stat)
{
	enum nse_status ret;
	struct nse_aqc_read_lan_cq_status cmd_data;

	memset(&cmd_data, 0, sizeof(cmd_data));

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, vsi ?
					    vsi->vsi_abs_num : NSE_VSI_INVAL_ID);

	cmd_data.cq_abs_id = cpu_to_le16(cq_abs_id);

	ret = nse_aq_lan_read_cq_status(hw, &cmd_data);
	if (!ret)
		*q_stat = le16_to_cpu(cmd_data.status);

	return ret;
}

void nse_lan_txcq_ctx_dump(struct nse_hw *hw, u16 qid_pf, u16 qid_abs,
			   struct nse_lan_txcq_ctx *cq_ctx, unsigned int dump_dword_bitmap)
{
	struct device *dev = nse_hw_to_dev(hw);
	u64 val64;
	u32 val32;

	/* don't dump qid because caller don't provide valid one */
	if (qid_pf == -1 || qid_abs == -1)
		dev_info(dev, "=== LAN-TX-CQ context\n");
	else
		dev_info(dev, "=== LAN-TX-CQ context: qid_pf=%d, qid_abs=%d\n", qid_pf, qid_abs);

	/* DATA[0]: BASE_low */
	/* DATA[1]: BASE_high */
	if ((dump_dword_bitmap & BIT(0)) ||
		(dump_dword_bitmap & BIT(1))) {
		dev_info(dev, "\t raw_data[0]: %X\n", cq_ctx->data[0]);
		dev_info(dev, "\t raw_data[1]: %X\n", cq_ctx->data[1]);

		/* get the base */
		val64 = cq_ctx->data[1] & LAN_TXCQ_CTX_BASE_HIGH_M;
		val64 <<= 32;
		val64 |= cq_ctx->data[0];
		val64 <<= LAN_TXCQ_BASE_SHIFT;

		dev_info(dev, "BASE: 0x%lX\n", (unsigned long)val64);
	}

	/* DATA[2]: Queue length */
	if (dump_dword_bitmap & BIT(2)) {
		dev_info(dev, "\t raw_data[2]: %X\n", cq_ctx->data[2]);

		val32 = (cq_ctx->data[2] & LAN_TXCQ_CTX_QLEN_M);

		dev_info(dev, "QLEN: %d (x 16 desc unit = %d)\n", val32, (val32 * 16));
	}

	/* DATA[3]: src_vsi, desc_coalesce_en, cause_en, msix_idx, tphwr_desc, cpuid */
	if (dump_dword_bitmap & BIT(3)) {
		dev_info(dev, "\t raw_data[3]: %X\n", cq_ctx->data[3]);

		val32 = (cq_ctx->data[3] & LAN_TXCQ_CTX_SRC_VSI_M) >> LAN_TXCQ_CTX_SRC_VSI_S;
		dev_info(dev, "SRC_VSI: %d\n", val32);

		val32 = (cq_ctx->data[3] & LAN_TXCQ_CTX_DESC_COALESCE_EN_M) >>
			LAN_TXCQ_CTX_DESC_COALESCE_EN_S;
		dev_info(dev, "DESC_COALESCE_EN: %d\n", val32);

		val32 = (cq_ctx->data[3] & LAN_TXCQ_CTX_CAUSE_EN_M) >> LAN_TXCQ_CTX_CAUSE_EN_S;
		dev_info(dev, "CAUSE_EN: %d\n", val32);

		val32 = (cq_ctx->data[3] & LAN_TXCQ_CTX_MSIX_IDX_M) >> LAN_TXCQ_CTX_MSIX_IDX_S;
		dev_info(dev, "MSIX_IDX: %d\n", val32);

		val32 = (cq_ctx->data[3] & LAN_TXCQ_CTX_TPHWRDESC_M) >> LAN_TXCQ_CTX_TPHWRDESC_S;
		dev_info(dev, "TPHWRDESC: %d\n", val32);

		val32 = (cq_ctx->data[3] & LAN_TXCQ_CTX_CPUID_M) >> LAN_TXCQ_CTX_CPUID_S;
		dev_info(dev, "CPUID: %d\n", val32);
	}

	/* DATA[4]: cq_wptr, generation */
	if (dump_dword_bitmap & BIT(4)) {
		dev_info(dev, "\t raw_data[4]: %X\n", cq_ctx->data[4]);

		val32 = (cq_ctx->data[4] & LAN_TXCQ_CTX_WPTR_M) >> LAN_TXCQ_CTX_WPTR_S;
		dev_info(dev, "WPTR: %d\n", val32);

		val32 = (cq_ctx->data[4] & LAN_TXCQ_CTX_GENERATION_M) >> LAN_TXCQ_CTX_GENERATION_S;
		dev_info(dev, "GENERATION: %d\n", val32);
	}
}

void nse_lan_txcq_ctx_compare(struct nse_hw *hw, struct nse_lan_txcq_ctx *ctx_0,
			      struct nse_lan_txcq_ctx *ctx_1, unsigned int dword_num)
{
	struct device *dev = nse_hw_to_dev(hw);
	unsigned int diff_dword_bitmap = 0;
	unsigned int i;

	dev_info(dev, "=== Compare LAN-TX-CQ context: ctx_0 is saved one, ctx_1 is newly read one\n");

	for (i = 0; i < 5 && i < dword_num; i++) {
		if (ctx_0->data[i] != ctx_1->data[i])
			diff_dword_bitmap |= BIT(i);
	}

	if (!diff_dword_bitmap) {
		dev_info(dev, "Result: Same\n");
	} else {
		dev_err(dev, "!!! Result: Different, dump different parts\n");

		nse_lan_txcq_ctx_dump(hw, -1, -1, ctx_0, diff_dword_bitmap);

		nse_lan_txcq_ctx_dump(hw, -1, -1, ctx_1, diff_dword_bitmap);
	}
}

enum nse_status
nse_aq_lan_set_tso_hsb(struct nse_hw *hw, dma_addr_t dma_addr)
{
	struct nse_aq_desc desc;
	struct nse_aqc_set_tso_hsb cmd_buf;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, NSE_AQ_OPC_SET_TSO_HSB);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, NSE_VSI_INVAL_ID);

	cmd_buf.reg_id = hw->pcore_pf_id;

	dma_addr >>= 12;	/* 4KB boundary */

	cmd_buf.hsb_lsb = cpu_to_le32(lower_32_bits(dma_addr));
	cmd_buf.hsb_msb = cpu_to_le32(upper_32_bits(dma_addr));

	return nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
}

int nse_lan_init_tso_hsb(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	int ret = 0;

/* 512 KB */
#define TSO_HSB_SIZE (512 * 1024)

	pf->tso_hsb_pages = dev_alloc_pages(get_order(TSO_HSB_SIZE));
	if (!pf->tso_hsb_pages) {
		dev_info(dev, "[%s, %d] tso_hsb_pages alloc fails, should not use TSO for all VSI of this PF\n",
						__func__, __LINE__);

		ret = -ENOMEM;
		goto fail;
	}

	/* map page for use */
	pf->tso_hsb_daddr = dma_map_page_attrs(dev, pf->tso_hsb_pages, 0, TSO_HSB_SIZE,
					       DMA_FROM_DEVICE, NSE_RX_DMA_ATTR);
	if (dma_mapping_error(dev, pf->tso_hsb_daddr)) {
		dev_info(dev, "[%s, %d] tso_hsb_daddr dma_map fails, should not use TSO for all VSI of this PF\n",
						__func__, __LINE__);

		ret = -EIO;
		goto fail;
	}

	if (nse_aq_lan_set_tso_hsb(hw, pf->tso_hsb_daddr)) {
		dev_info(dev, "[%s, %d] tso_hsb_daddr set to HW fails, should not use TSO for all VSI of this PF\n",
						__func__, __LINE__);

		ret = -EIO;
		goto fail;
	}

	nse_debug(hw, NSE_DBG_LAN, "[%s] install tso_hsb daddr=0x%lX to HW\n",
		  __func__, (unsigned long)pf->tso_hsb_daddr);

	pf->tso_hsb_usable = true;

	ret = 0;

out:
	return ret;

fail:
	if (pf->tso_hsb_pages) {
		__free_pages(pf->tso_hsb_pages, get_order(TSO_HSB_SIZE));
		pf->tso_hsb_pages = NULL;
	}

	pf->tso_hsb_usable = false;

	goto out;
}

void nse_lan_deinit_tso_hsb(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	pf->tso_hsb_usable = false;

	if (!pf->tso_hsb_pages)
		return;

	dma_sync_single_range_for_cpu(dev, pf->tso_hsb_daddr, 0, TSO_HSB_SIZE, DMA_FROM_DEVICE);

	dma_unmap_page_attrs(dev, pf->tso_hsb_daddr, TSO_HSB_SIZE,
						DMA_FROM_DEVICE, NSE_RX_DMA_ATTR);

	__free_pages(pf->tso_hsb_pages, get_order(TSO_HSB_SIZE));

	pf->tso_hsb_pages = NULL;
}

void nse_lan_reinstall_tso_hsb(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);

	pf->tso_hsb_usable = false;

	if (!pf->tso_hsb_pages)
		return;

	if (nse_aq_lan_set_tso_hsb(hw, pf->tso_hsb_daddr))
		dev_info(dev,
"[%s] FAIL: re-install tso_hsb set to HW, should not use TSO for all VSI of this PF\n", __func__);
	else {
		nse_debug(hw, NSE_DBG_LAN, "[%s] re-install tso_hsb daddr=0x%lX to HW\n",
			  __func__, (unsigned long)pf->tso_hsb_daddr);

		pf->tso_hsb_usable = true;
	}
}

enum nse_status
nse_aq_read_or_clear_dma_chan_total_stats(struct nse_hw *hw, u8 read_or_clear,
					  struct nse_aqc_rc_dma_chan_total_stats *total_stats)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN,
				      NSE_AQ_OPC_RC_DMA_CHAN_TOTAL_STATS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &total_stats->hdr, NSE_VSI_INVAL_ID);

	total_stats->read_or_clear = read_or_clear;

	return nse_aq_send_cmd(hw, &desc, total_stats, sizeof(*total_stats), NULL);
}

enum nse_status
nse_aq_read_or_clear_dma_chan_per_vsi_stats(struct nse_hw *hw, u16 vsi_abs_id, u8 read_or_clear,
					    struct nse_aqc_rc_dma_chan_per_vsi_stats *vsi_stats)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN,
				      NSE_AQ_OPC_RC_DMA_CHAN_PER_VSI_STATS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &vsi_stats->hdr, vsi_abs_id);

	vsi_stats->read_or_clear = read_or_clear;

	return nse_aq_send_cmd(hw, &desc, vsi_stats, sizeof(*vsi_stats), NULL);
}

enum nse_status
nse_read_dma_chan_total_stats(struct nse_hw *hw,
			      struct nse_aqc_rc_dma_chan_total_stats *total_stats)
{
	return nse_aq_read_or_clear_dma_chan_total_stats(hw, 1, total_stats);
}

enum nse_status
nse_clear_dma_chan_total_stats(struct nse_hw *hw)
{
	struct nse_aqc_rc_dma_chan_total_stats *dummy = NULL;
	enum nse_status ret;

	dummy = kmalloc(sizeof(*dummy), GFP_ATOMIC);
	if (!dummy)
		return NSE_ERR_NO_MEMORY;

	ret = nse_aq_read_or_clear_dma_chan_total_stats(hw, 0, dummy);

	kfree(dummy);

	return ret;
}

void
nse_dump_dma_chan_total_stats(struct nse_hw *hw, struct nse_aqc_rc_dma_chan_total_stats *stats)
{
	struct device *dev = nse_hw_to_dev(hw);

#define PRINT_LAN_CHANNEL_STATS(sname)	\
	dev_info(dev, "%s: 0x%X (%d)\n", #sname, le32_to_cpu(stats->sname), le32_to_cpu(stats->sname))

	PRINT_LAN_CHANNEL_STATS(rdm_total_gpkt_cnt_lo);
	PRINT_LAN_CHANNEL_STATS(rdm_total_gpkt_cnt_hi);
	PRINT_LAN_CHANNEL_STATS(rdm_total_goct_cnt_lo);
	PRINT_LAN_CHANNEL_STATS(rdm_total_goct_cnt_hi);
	PRINT_LAN_CHANNEL_STATS(rdm_total_dpkt_cnt_lo);
	PRINT_LAN_CHANNEL_STATS(rdm_total_dpkt_cnt_high);
	PRINT_LAN_CHANNEL_STATS(rdm_total_b2os_cnt_lo);
	PRINT_LAN_CHANNEL_STATS(rdm_total_b2os_cnt_hi);
	PRINT_LAN_CHANNEL_STATS(rdm_total_vlen_256_cnt);
	PRINT_LAN_CHANNEL_STATS(rdm_total_vlen_1024_cnt);
	PRINT_LAN_CHANNEL_STATS(rdm_total_vlen_1534_cnt);
	PRINT_LAN_CHANNEL_STATS(rdm_total_vlen_over1534_cnt);
	PRINT_LAN_CHANNEL_STATS(rdm_total_rel_cnt_lo);
	PRINT_LAN_CHANNEL_STATS(rdm_total_rel_cnt_hi);
	PRINT_LAN_CHANNEL_STATS(rdm_total_fetch_cnt_lo);
	PRINT_LAN_CHANNEL_STATS(rdm_total_fetch_cnt_hi);

	PRINT_LAN_CHANNEL_STATS(tdm_total_gptc_lo);
	PRINT_LAN_CHANNEL_STATS(tdm_total_gptc_hi);
	PRINT_LAN_CHANNEL_STATS(tdm_total_gotc_lo);
	PRINT_LAN_CHANNEL_STATS(tdm_total_gotc_hi);
	PRINT_LAN_CHANNEL_STATS(tdm_total_dptc_lo);
	PRINT_LAN_CHANNEL_STATS(tdm_total_dptc_hi);
}

enum nse_status
nse_read_dma_chan_per_vsi_stats(struct nse_hw *hw, u16 vsi_abs_id,
				struct nse_aqc_rc_dma_chan_per_vsi_stats *vsi_stats)
{
	return nse_aq_read_or_clear_dma_chan_per_vsi_stats(hw, vsi_abs_id, 1, vsi_stats);
}

enum nse_status
nse_clear_dma_chan_per_vsi_stats(struct nse_hw *hw, u16 vsi_abs_id)
{
	struct nse_aqc_rc_dma_chan_per_vsi_stats *dummy = NULL;
	enum nse_status ret;

	dummy = kmalloc(sizeof(*dummy), GFP_ATOMIC);
	if (!dummy)
		return NSE_ERR_NO_MEMORY;

	ret = nse_aq_read_or_clear_dma_chan_per_vsi_stats(hw, vsi_abs_id, 0, dummy);

	kfree(dummy);

	return ret;
}

enum nse_status
nse_lan_set_rsc_ctrl(struct nse_hw *hw, u32 rsc_ctrl)
{
	struct nse_aqc_set_rsc_ctrl cmd_data;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, NSE_AQ_OPC_SET_RSC_CTRL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	cmd_data.rsc_ctrl = cpu_to_le32(rsc_ctrl);

	return nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);
}

enum nse_status
nse_aqc_lan_set_logall(struct nse_hw *hw, struct nse_aqc_set_logall *ctrl_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN, NSE_AQ_OPC_ENA_DIS_LOGALL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &ctrl_data->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, ctrl_data, sizeof(*ctrl_data), NULL);
}

enum nse_status
nse_lan_set_tdm_legacy_wb_mode(struct nse_hw *hw, u32 val)
{
	struct nse_aq_desc desc;
	struct nse_aqc_conf_tdm_legacy_wb_mode cmd = {0};

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LAN,
				      NSE_AQ_OPC_CONF_TDM_LEGACY_WB_MODE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd.hdr, NSE_VSI_INVAL_ID);

	cmd.rw = 0;
	cmd.val = val ? cpu_to_le32(1) : 0;

	return nse_aq_send_cmd(hw, &desc, &cmd, sizeof(cmd), NULL);
}

/**
 * nse_dump_caps - Dump a list of capabilities
 * @hw: pointer to the nse_hw instance
 */
void nse_dump_caps(struct nse_hw *hw)
{
	char const *prefix = "func cap";
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_hw_func_caps *func_caps = &hw->func_caps;

	dev_info(dev, "%s: func_caps_valid = %d\n",
								prefix,
								func_caps->func_caps_valid);

	dev_info(dev, "%s: hw_platform: hw_platform_valid=%d, hw_platform=%d\n",
								prefix,
								(int)func_caps->hw_platform_valid,
								(int)func_caps->hw_platform);

	dev_info(dev, "%s: basic: pcore_id=%d, pcore_pf_id=%d, dma_id=%d, dma_pf_id=%d, chan_id=%d, chan_pf_id=%d, lan_id=%d, pf_type=%d, lan_bitmap=%X, cur_pcore_pf_bitmap=%X\n",
								prefix,
								(int)func_caps->pcore_id,
								(int)func_caps->pcore_pf_id,
								(int)func_caps->dma_id,
								(int)func_caps->dma_pf_id,
								(int)func_caps->chan_id,
								(int)func_caps->chan_pf_id,
								(int)func_caps->lan_id,
								(int)func_caps->pf_type,
								(int)func_caps->lan_bitmap,
		 (int)func_caps->cur_pcore_pf_bitmap);

	dev_info(dev, "%s: basic: mh_dpu_peer_pcore_id=%d, mh_dpu_peer_pcore_pf_id=%d\n",
								prefix,
		 (int)func_caps->mh_dpu_peer_pcore_pf_id,
		 (int)func_caps->mh_dpu_peer_pcore_id);

	dev_info(dev, "%s: vsi space: vsi_space_valid=%d, first_vsi=%d, last_vsi=%d\n",
								prefix,
								(int)func_caps->vsi_space_valid,
								(int)func_caps->first_vsi,
									(int)func_caps->last_vsi);

	dev_info(dev, "%s: lanrxq space: lanrxq_space_valid=%d, first_lanrxq=%d, last_lanrxq=%d\n",
								prefix,
								(int)func_caps->lanrxq_space_valid,
		 (int)func_caps->first_lanrxq, (int)func_caps->last_lanrxq);

	dev_info(dev, "%s: lantxq space: lantxq_space_valid=%d, first_lantxq=%d, last_lantxq=%d\n",
								prefix,
								(int)func_caps->lantxq_space_valid,
		 (int)func_caps->first_lantxq, (int)func_caps->last_lantxq);

	dev_info(dev, "%s: irq space: irq_space_valid=%d, first_irq=%d, last_irq=%d\n",
								prefix,
								(int)func_caps->irq_space_valid,
								(int)func_caps->first_irq,
									(int)func_caps->last_irq);

	dev_info(dev, "%s: vf space: vf_space_valid=%d, first_vf=%d, vf_num=%d\n",
								prefix,
								(int)func_caps->vf_space_valid,
								(int)func_caps->first_vf,
									(int)func_caps->vf_num);

	dev_info(dev, "%s: lan_txcq space: lan_txcq_space_valid=%d, first_lan_txcq=%d, last_lan_txcq=%d\n",
								prefix,
		 (int)func_caps->lan_txcq_space_valid,
		 (int)func_caps->first_lan_txcq, (int)func_caps->last_lan_txcq);

	dev_info(dev, "%s: rdma_qset space: rdma_qset_space_valid=%d, first_rdma_qset=%d, last_rdma_qset=%d\n",
								prefix,
		 (int)func_caps->rdma_qset_space_valid,
		 (int)func_caps->first_rdma_qset, (int)func_caps->last_rdma_qset);

	dev_info(dev, "%s: link_types_speeds: suggest_from_fw=%d, supported_link_speeds=0x%X, supported_link_types=0x%lX\n",
								prefix,
		 func_caps->supported_link_types_speeds_from_fw,
		 func_caps->supported_link_speeds, (unsigned long)func_caps->supported_link_types);
}

/**
 * nse_aq_xchg_sw_fw_ver
 * @hw: pointer to the HW struct
 *
 * Send cmd: nse_aqc_opc_xchg_sw_fw_ver to FW.
 * and save FW version in response into nse_hw->fw_ver.
 */
enum nse_status
nse_aq_xchg_sw_fw_ver(struct nse_hw *hw)
{
	enum nse_status ret;
	struct nse_aq_desc desc;
	struct nse_aqc_xchg_sw_fw_ver sw_fw_ver;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_XCHG_SW_FW_VER);

	memset(&sw_fw_ver, 0, sizeof(sw_fw_ver));

	sw_fw_ver.sw_ver.major_ver	= DRV_VERSION_MAJOR;
	sw_fw_ver.sw_ver.minor_ver	= DRV_VERSION_MINOR;
	sw_fw_ver.sw_ver.mini_ver	= DRV_VERSION_MINI;
	sw_fw_ver.sw_ver.patch_ver	= DRV_VERSION_PATCH;
	sw_fw_ver.sw_ver.build_ver	= DRV_VERSION_BUILD;
	sw_fw_ver.sw_ver.sw_drv_type = cpu_to_le32(NSE_SW_DRV_TYPE_LINUX);

	ret = nse_aq_send_cmd(hw, &desc, &sw_fw_ver, sizeof(sw_fw_ver), NULL);

	if (!ret) {
		memcpy(&hw->fw_ver, &sw_fw_ver.fw_ver, sizeof(hw->fw_ver));
		hw->refused_by_fw = !!sw_fw_ver.refused_by_fw;
	}

	return ret;
}

/**
 * nse_aq_ping_fw
 * @hw: pointer to the HW struct
 *
 * Send cmd: nse_aqc_opc_ping_fw to FW.
 */
enum nse_status
nse_aq_ping_fw(struct nse_hw *hw)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_PING_FW);

	desc.param0 = 0x8088;
	desc.param1 = 0x8088;

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);

	return ret;
}

/**
 * nse_aq_q_shutdown
 * @hw: pointer to the HW struct
 *
 * Send the cmd: nse_aqc_opc_q_shutdown to FW.
 */
enum nse_status
nse_aq_adminq_shutdown(struct nse_hw *hw, bool drv_unloading)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_Q_SHUTDOWN);

	if (drv_unloading)
		desc.param0 = cpu_to_le32(1);

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);

	hw->controlq_stats.aq_cmd_shutdown_time = ktime_to_ns(ktime_get());
	hw->controlq_stats.aq_cmd_shutdown_cnt++;

	return ret;
}

/**
 * nse_aq_discover_func_caps
 * @hw: pointer to the HW struct
 *
 * Send cmd: nse_aqc_opc_discover_func_caps to FW
 *
 * Caller should provide buf and buf_size as IN/OUT arguments.
 */
enum nse_status
nse_aq_discover_func_caps(struct nse_hw *hw, void *buf, u16 buf_size)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC,
				      NSE_AQ_OPC_DISCOVER_FUNC_CAPS);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

	return ret;
}

enum nse_status
nse_parse_func_caps(struct nse_hw *hw, struct nse_aqc_discover_func_caps *aqc_func_caps)
{
	u32 cap_elem_count = le32_to_cpu(aqc_func_caps->count);
	u16 cap_elem_id = 0;
	struct nse_aqc_discover_cap_elem *cap_elem = NULL;
	u32 val = 0;
	int i = 0;

	memset(&hw->func_caps, 0, sizeof(hw->func_caps));

	if (cap_elem_count <= 0)
		return NSE_ERR_INVAL_SIZE;

	for (i = 0; i < cap_elem_count; i++) {
		cap_elem = &aqc_func_caps->caps[i];
		cap_elem_id = le16_to_cpu(cap_elem->cap_id);

		nse_debug(hw, NSE_DBG_SYS, "[%s] cap_elem_id = %d, val0=%X, val1=%X, val2=%X, val32=%X, val64=%lX\n",
									__func__, cap_elem_id,
									cap_elem->val0,
										cap_elem->val1,
										cap_elem->val2,
			  cap_elem->val32, (unsigned long)cap_elem->val64);

		if (cap_elem_id == NSE_AQC_CAP_ID_BASIC) {
			val = le32_to_cpu(cap_elem->val0);

			hw->func_caps.pcore_id		= (val) & 0xF;
			hw->func_caps.pcore_pf_id	= (val >> 4) & 0xF;

			hw->func_caps.dma_id		= (val >> 8) & 0xF;
			hw->func_caps.dma_pf_id		= (val >> 12) & 0xF;

			hw->func_caps.chan_id		= (val >> 16) & 0xF;
			hw->func_caps.chan_pf_id	= (val >> 20) & 0xF;

			hw->func_caps.lan_id		= (val >> 24) & 0xF;

			hw->func_caps.pf_type		= (val >> 28) & 0xF;

			val = le32_to_cpu(cap_elem->val1);
			hw->func_caps.lan_bitmap		= val & 0xF;

			hw->func_caps.pcore_0_pf_bitmap = (val >> 8) & 0xF;
			hw->func_caps.pcore_1_pf_bitmap = (val >> 16) & 0xF;

			if (!hw->func_caps.pcore_id)
				hw->func_caps.cur_pcore_pf_bitmap = hw->func_caps.pcore_0_pf_bitmap;
			else
				hw->func_caps.cur_pcore_pf_bitmap = hw->func_caps.pcore_1_pf_bitmap;

			val = le32_to_cpu(cap_elem->val2);

			hw->func_caps.mh_dpu_peer_pcore_id		= val & 0xF;
			hw->func_caps.mh_dpu_peer_pcore_pf_id	= (val >> 4) & 0xF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_VSI_SPACE) {
			hw->func_caps.vsi_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_vsi = le32_to_cpu(cap_elem->val1) & 0xFF;
			hw->func_caps.last_vsi = le32_to_cpu(cap_elem->val2) & 0xFF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_LANRXQ_SPACE) {
			hw->func_caps.lanrxq_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_lanrxq = le32_to_cpu(cap_elem->val1) & 0xFFFF;
			hw->func_caps.last_lanrxq = le32_to_cpu(cap_elem->val2) & 0xFFFF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_LANTXQ_SPACE) {
			hw->func_caps.lantxq_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_lantxq = le32_to_cpu(cap_elem->val1) & 0xFFFF;
			hw->func_caps.last_lantxq = le32_to_cpu(cap_elem->val2) & 0xFFFF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_IRQ_SPACE) {
			hw->func_caps.irq_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_irq = le32_to_cpu(cap_elem->val1) & 0xFFFF;
			hw->func_caps.last_irq = le32_to_cpu(cap_elem->val2) & 0xFFFF;

		} else if (cap_elem->cap_id == NSE_AQC_CAP_ID_VF_SPACE) {
			hw->func_caps.vf_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_vf = le32_to_cpu(cap_elem->val1) & 0xFF;
			hw->func_caps.vf_num = le32_to_cpu(cap_elem->val2) & 0xFF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_LAN_TX_CQ_SPACE) {
			hw->func_caps.lan_txcq_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_lan_txcq = le32_to_cpu(cap_elem->val1) & 0xFFFF;
			hw->func_caps.last_lan_txcq = le32_to_cpu(cap_elem->val2) & 0xFFFF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_RDMA_QSET_SPACE) {
			hw->func_caps.rdma_qset_space_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.first_rdma_qset = le32_to_cpu(cap_elem->val1) & 0xFFFF;
			hw->func_caps.last_rdma_qset = le32_to_cpu(cap_elem->val2) & 0xFFFF;

		} else if (cap_elem_id == NSE_AQC_CAP_ID_HW_PLATFORM) {
			hw->func_caps.hw_platform_valid = le32_to_cpu(cap_elem->val0) & 0x1;
			hw->func_caps.hw_platform = le32_to_cpu(cap_elem->val1);

		} else if (cap_elem_id == NSE_AQC_CAP_ID_LINK_TYPES_SPEEDS) {
			hw->func_caps.supported_link_types_speeds_from_fw = 1;

			hw->func_caps.supported_link_speeds = le32_to_cpu(cap_elem->val32);
			hw->func_caps.supported_link_types = le64_to_cpu(cap_elem->val64);

		} else {
			dev_info(nse_hw_to_dev(hw), "unknown func_cap element ID: %d",
					cap_elem_id);
		}
	}

	hw->func_caps.func_caps_valid = true;

	return NSE_SUCCESS;
}

/**
 * nse_get_caps
 * @hw: pointer to the HW struct
 *
 * Send the cmd: nse_aqc_opc_discover_func_caps to FW
 * Parse the response, and init nse_hw -> struct nse_hw_func_caps func_caps
 */
enum nse_status
nse_get_caps(struct nse_hw *hw)
{
	enum nse_status status;
	u32 cap_elem_count = 0;
	struct nse_aqc_discover_func_caps *aqc_func_caps = NULL;

	aqc_func_caps = devm_kzalloc(nse_hw_to_dev(hw), NSE_AQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!aqc_func_caps)
		return NSE_ERR_NO_MEMORY;

	cap_elem_count = (NSE_AQ_MAX_BUF_LEN - sizeof(__le32)) /
							sizeof(struct nse_aqc_discover_cap_elem);

	aqc_func_caps->count = cpu_to_le32(cap_elem_count);

	status = nse_aq_discover_func_caps(hw, aqc_func_caps, NSE_AQ_MAX_BUF_LEN);
	if (!status)
		status = nse_parse_func_caps(hw, aqc_func_caps);

	devm_kfree(nse_hw_to_dev(hw), aqc_func_caps);

	return status;
}

/**
 * nse_sanity_check_caps
 * @hw: pointer to the HW struct
 *
 *  This function is called right after nse_get_caps(), to sanity check to nse_hw->func_caps
 * retrieved from FW.
 */
enum nse_status
nse_sanity_check_caps(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	/* we do all check in one session, instead of doing one check and return */
	enum nse_status status = NSE_SUCCESS;
	struct nse_hw_func_caps *func_caps = &hw->func_caps;
	struct nse_hw_conf *hw_conf = &hw->hw_conf;
	u8 peer_lan_id = 0;

	if (!func_caps->func_caps_valid) {
		dev_err(dev, "the whole func_caps_valid = false\n");
		status = NSE_ERR_PARAM;
	}

	/* copy these fields from func_caps to hw, for later runtime easy reference */
	hw->pcore_id		= func_caps->pcore_id;
	hw->pcore_pf_id		= func_caps->pcore_pf_id;
	hw->dma_id			= func_caps->dma_id;
	hw->dma_pf_id		= func_caps->dma_pf_id;
	hw->chan_id		= func_caps->chan_id;
	hw->chan_pf_id		= func_caps->chan_pf_id;
	hw->lan_id			= func_caps->lan_id;

	hw->pf_type			= func_caps->pf_type;
	if (hw->pf_type == NSE_PF_TYPE_MH_DPU_SECONDARY)
		hw->is_mh_dpu_secondary_pf = true;
	else
		hw->is_mh_dpu_secondary_pf = false;

	hw->lan_bitmap		= func_caps->lan_bitmap;
	hw->cur_pcore_pf_bitmap = func_caps->cur_pcore_pf_bitmap;

	/* shortcut for future check */
	if (hw->lan_id & 0x1)
		peer_lan_id = hw->lan_id & ~(0x1);
	else
		peer_lan_id = hw->lan_id | 0x1;

	if (hw->lan_bitmap & (1 << peer_lan_id))
		/* I have alive sibling LAN in same channel */
		hw->is_only_lan_in_chan = false;
	else
		hw->is_only_lan_in_chan = true;	/* I don't */

	if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		hw->is_only_lan_in_chan = true;		/* always */

	if (!func_caps->vsi_space_valid ||
		func_caps->first_vsi > func_caps->last_vsi ||
		(func_caps->last_vsi - func_caps->first_vsi) >= hw_conf->max_vsi_space) {
		dev_err(dev, "vsi space not valid: vsi_space_valid=%d, first_vsi=%d, last_vsi=%d\n",
			(int)func_caps->vsi_space_valid,
			(int)func_caps->first_vsi, (int)func_caps->last_vsi);
		status = NSE_ERR_PARAM;
	}

	if (!func_caps->lanrxq_space_valid ||
		func_caps->first_lanrxq > func_caps->last_lanrxq ||
		(func_caps->last_lanrxq - func_caps->first_lanrxq) >= hw_conf->max_lan_rxq_space) {
		dev_err(dev, "lanrxq space not valid: lanrxq_space_valid=%d, first_lanrxq=%d, last_lanrxq=%d\n",
			(int)func_caps->lanrxq_space_valid,
			(int)func_caps->first_lanrxq, (int)func_caps->last_lanrxq);
		status = NSE_ERR_PARAM;
	}

	if (!func_caps->lantxq_space_valid ||
		func_caps->first_lantxq > func_caps->last_lantxq ||
		(func_caps->last_lantxq - func_caps->first_lantxq) >= hw_conf->max_lan_txq_space) {
		dev_err(dev, "lantxq space not valid: lantxq_space_valid=%d, first_lantxq=%d, last_lantxq=%d\n",
			(int)func_caps->lantxq_space_valid,
			(int)func_caps->first_lantxq, (int)func_caps->last_lantxq);
		status = NSE_ERR_PARAM;
	}

	/* need symmetric lan-rxq/txq space */
	if (func_caps->first_lanrxq != func_caps->first_lantxq ||
		func_caps->last_lanrxq != func_caps->last_lantxq) {
		dev_err(dev, "lan rxq / txq space not symmetric\n");
		dev_err(dev, "\tfirst_lanrxq=%d, last_lanrxq=%d\n",
			(int)func_caps->first_lanrxq, (int)func_caps->last_lanrxq);
		dev_err(dev, "\tfirst_lantxq=%d, last_lantxq=%d\n",
			(int)func_caps->first_lantxq, (int)func_caps->last_lantxq);
		status = NSE_ERR_PARAM;
	}

	if (!func_caps->irq_space_valid ||
		func_caps->first_irq > func_caps->last_irq ||
		(func_caps->last_irq - func_caps->first_irq) >= hw_conf->max_irq_space) {
		dev_err(dev, "irq space not valid: irq_space_valid=%d, first_irq=%d, last_irq=%d\n",
			(int)func_caps->irq_space_valid,
									(int)func_caps->first_irq,
									(int)func_caps->last_irq);
		status = NSE_ERR_PARAM;
	}

	/* no need to check vf space, because FW may force disabling SRIOV */

	if (func_caps->lan_txcq_space_valid &&
		((func_caps->first_lan_txcq > func_caps->last_lan_txcq) ||
		((func_caps->last_lan_txcq -
		 func_caps->first_lan_txcq) >= hw_conf->max_lan_txcq_space))) {
		dev_warn(dev, "lan_txcq space not right: lan_txcq_space_valid=%d, first_lan_txcq=%d, last_lan_txcq=%d\n",
			 (int)func_caps->lan_txcq_space_valid,
			 (int)func_caps->first_lan_txcq, (int)func_caps->last_lan_txcq);

		/*  Even CQ space not right, we can still use LAN with TXQ traditional mode, without
		 * CQ
		 */

		func_caps->lan_txcq_space_valid = 0;
	}

	if (func_caps->rdma_qset_space_valid &&
		((func_caps->first_rdma_qset > func_caps->last_rdma_qset) ||
		((func_caps->last_rdma_qset -
		 func_caps->first_rdma_qset) >= hw_conf->max_rdma_qset_space))) {
		dev_warn(dev, "rdma_qset space not right: rdma_qset_space_valid=%d, first_rdma_qset=%d, last_rdma_qset=%d, max_rdma_qset_space=%d\n",
			 (int)func_caps->rdma_qset_space_valid,
			 (int)func_caps->first_rdma_qset, (int)func_caps->last_rdma_qset,
				 (int)hw_conf->max_rdma_qset_space);

		func_caps->rdma_qset_space_valid = 0;
	}

	return status;
}

enum nse_status
nse_aq_set_sriov_res(struct nse_hw *hw)
{
	struct nse_aq_desc desc;
	struct nse_aqc_set_unset_sriov_res buf;
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_vfs *vfs = &pf->vfs;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_SET_SRIOV_RES);

	nse_aqc_fill_generic_common_hdr_dft(hw, &buf.hdr, NSE_VSI_INVAL_ID);

	/* convert rel ID to abs ID*/
	buf.vf_vsialloc_firstvsi = cpu_to_le16(pf->vsi_space_start + vfs->vf_vsialloc_firstvsi);

	buf.vf_rx_qbase_firstq = cpu_to_le16(pf->lan_rxq_space_start + vfs->vf_rx_qbase_firstq);
	buf.vf_rx_qbase_numq = cpu_to_le16((vfs->vf_rx_qbase_numq - 1));

	buf.vf_tx_qbase_firstq = cpu_to_le16(pf->lan_txq_space_start + vfs->vf_tx_qbase_firstq);
	buf.vf_tx_qbase_numq = cpu_to_le16((vfs->vf_tx_qbase_numq - 1));

	buf.vfint_alloc_first = cpu_to_le16(pf->irq_space_start + vfs->vfint_alloc_first);
	buf.vfint_alloc_vecnum = cpu_to_le16((vfs->vfint_alloc_vecnum - 1));

	return nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
}

enum nse_status
nse_aq_unset_sriov_res(struct nse_hw *hw)
{
	struct nse_aq_desc desc;
	struct nse_aqc_set_unset_sriov_res buf;

	memset(&buf, 0, sizeof(buf));

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_UNSET_SRIOV_RES);

	/* hdr->pcore_id, pcore_pf_id set inside */
	nse_aqc_fill_generic_common_hdr_dft(hw, &buf.hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
}

enum nse_status
nse_aq_query_stag_type(struct nse_hw *hw, u16 *stag_ethertype)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_QUERY_STAG_TYPE);

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);

	if (ret == NSE_SUCCESS)
		*stag_ethertype = le32_to_cpu(desc.param0);

	return ret;
}

enum nse_status
nse_determine_stag_type(struct nse_hw *hw)
{
	enum nse_status ret;

	ret = nse_aq_query_stag_type(hw, &hw->stag_ethertype);
	if (ret)
		return ret;

	if (hw->stag_ethertype != ETH_P_8021Q && hw->stag_ethertype != ETH_P_8021AD)
		ret = NSE_ERR_NOT_SUPPORTED;

	return ret;
}

enum nse_status
nse_aq_read_chip_temperature(struct nse_hw *hw, int *temperature)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC,
				      NSE_AQ_OPC_READ_CHIP_TEMPERATURE);

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (ret) {
		*temperature = 0;	/* return 0 for compromise */

		ret = NSE_SUCCESS;
	} else {
		*temperature = (int)le32_to_cpu(desc.param0);

		*temperature = (*temperature) / 100;	/* trim to 1 degree */
	}

	return ret;
}

enum nse_status
nse_aq_fw_lldp_agent_get_status(struct nse_hw *hw, u32 *status)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fw_lldp_agent_get_status cmd_data = {0};
	enum nse_status ret;

	if (!nse_fw_lldp) {
		*status = 0;
		return NSE_SUCCESS;
	}

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC,
				      NSE_AQ_OPC_FW_LLDP_AGENT_GET_STATUS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	ret = nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);

	if (ret == NSE_SUCCESS)
		*status = le32_to_cpu(cmd_data.status);

	return ret;
}

enum nse_status
nse_aq_fw_lldp_agent_start_stop(struct nse_hw *hw, bool start_or_stop)
{
	struct nse_aq_desc desc;
	struct nse_aqc_fw_lldp_agent_start_stop cmd_data = {0};

	if (!nse_fw_lldp)
		return NSE_SUCCESS;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC,
				      NSE_AQ_OPC_FW_LLDP_AGENT_START_STOP);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	if (start_or_stop)
		cmd_data.start_or_stop = cpu_to_le32(1);
	else
		cmd_data.start_or_stop = cpu_to_le32(0);

	return nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);
}

enum nse_status
nse_aq_fw_lldp_dcbx_subagent_get_status(struct nse_hw *hw, u32 *status)
{
	struct nse_aq_desc desc;
	struct nse_aqc_qos_fw_lldp_dcbx_subagent_get_status cmd_data = {0};
	enum nse_status ret;

	if (!nse_fw_lldp) {
		*status = 0;
		return NSE_SUCCESS;
	}

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_FW_LLDP_DCBX_SUBAGENT_GET_STATUS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	ret = nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);

	if (ret == NSE_SUCCESS)
		*status = le32_to_cpu(cmd_data.status);

	return ret;
}

enum nse_status
nse_aq_fw_lldp_dcbx_subagent_start_stop(struct nse_hw *hw, bool start_or_stop)
{
	struct nse_aq_desc desc;
	struct nse_aqc_qos_fw_dcbx_subagent_start_stop cmd_data = {0};

	if (!nse_fw_lldp)
		return NSE_SUCCESS;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_FW_LLDP_DCBX_SUBAGENT_START_STOP);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data.hdr, NSE_VSI_INVAL_ID);

	if (start_or_stop)
		cmd_data.start_or_stop = cpu_to_le32(1);
	else
		cmd_data.start_or_stop = 0;

	return nse_aq_send_cmd(hw, &desc, &cmd_data, sizeof(cmd_data), NULL);
}

enum nse_status
nse_aq_qos_db_set_cfg(struct nse_hw *hw, struct nse_aqc_qos_db_cfg *cfg)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS, NSE_AQ_OPC_QOS_DB_SET_CFG);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cfg->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cfg, sizeof(*cfg), NULL);
}

enum nse_status
nse_aq_qos_db_get_cfg(struct nse_hw *hw, struct nse_aqc_qos_db_cfg *cfg)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS, NSE_AQ_OPC_QOS_DB_GET_CFG);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cfg->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cfg, sizeof(*cfg), NULL);
}

enum nse_status
nse_aq_qos_db_flush_disable(struct nse_hw *hw, struct nse_aqc_qos_db_flush_disable *fdis)
{
	struct nse_aq_desc desc;

	if (nse_bypass_qos_db_flush_disable) {
		nse_debug(hw, NSE_DBG_DCB, "nse_bypass_qos_db_flush_disable\n");
		return NSE_SUCCESS;
	}

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_DB_FLUSH_DISABLE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &fdis->hdr, NSE_VSI_INVAL_ID);

	fdis->eth_grp_id = hw->port_info->curr_eth_grp_id;

	return nse_aq_send_cmd(hw, &desc, fdis, sizeof(*fdis), NULL);
}

enum nse_status
nse_qos_db_flush_disable_this_lan(struct nse_hw *hw)
{
	struct nse_aqc_qos_db_flush_disable fdis;
	u32 val;

	memset(&fdis, 0, sizeof(fdis));

	val = NSE_AQC_QOS_DB_FLUSH_DISABLE_TRT_THIS_LAN;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_DB_RPB_SHARED_BY_MULTI_PORTS))
		val |= NSE_AQC_QOS_DB_FLUSH_DISABLE_RPB;

	fdis.flags = cpu_to_le32(val);

	return nse_aq_qos_db_flush_disable(hw, &fdis);
}

enum nse_status
nse_qos_db_flush_disable_this_channel(struct nse_hw *hw)
{
	struct nse_aqc_qos_db_flush_disable fdis;
	u32 val;

	memset(&fdis, 0, sizeof(fdis));

	val = NSE_AQC_QOS_DB_FLUSH_DISABLE_RPB |
			NSE_AQC_QOS_DB_FLUSH_DISABLE_RDB |
			NSE_AQC_QOS_DB_FLUSH_DISABLE_TDB;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_DB_HAVE_TRT))
		val |= NSE_AQC_QOS_DB_FLUSH_DISABLE_TRT_ALL_LAN;

	fdis.flags = cpu_to_le32(val);

	return nse_aq_qos_db_flush_disable(hw, &fdis);
}

enum nse_status
nse_qos_db_flush_disable(struct nse_hw *hw)
{
	if (hw->is_only_lan_in_chan)
		return nse_qos_db_flush_disable_this_channel(hw);
	else
		return nse_qos_db_flush_disable_this_lan(hw);
}

enum nse_status
nse_aq_qos_db_get_stat_cnt(struct nse_hw *hw, struct nse_aqc_qos_db_stat_cnt *db_stat_cnt)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_DB_GET_STAT_CNT);

	nse_aqc_fill_generic_common_hdr_dft(hw, &db_stat_cnt->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, db_stat_cnt, sizeof(*db_stat_cnt), NULL);
}

static void
nse_qos_db_dump_stat_cnt_amber(struct nse_hw *hw, struct nse_aqc_qos_db_stat_cnt_amber *db_stat_cnt)
{
	struct device *dev = nse_hw_to_dev(hw);
	int i, j, k;
	struct nse_aqc_qos_db_rpb_stat_cnt_amber *rpb = NULL;
	struct nse_aqc_qos_db_rdb_stat_cnt_amber *rdb = NULL;
	struct nse_aqc_qos_db_tdb_stat_cnt_amber *tdb = NULL;
	struct nse_aqc_qos_db_trt_stat_cnt_amber *trt = NULL;

	for (i = 0; i < 4; i++) {
		rpb = &db_stat_cnt->rpb[i];

		dev_info(dev, "=== rpb_stat_cnt[%d]\n", i);

		dev_info(dev, "rpb_stat: 0x%X\n", le32_to_cpu(rpb->rpb_stat));
		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_pb_sz_used[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_pb_sz_used[j]));
		}
		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_tc_share_sz_used[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_tc_share_sz_used[j]));
		}
		dev_info(dev, "rpb_share_sz_used: 0x%X\n", le32_to_cpu(rpb->rpb_share_sz_used));
		dev_info(dev, "rpb_global_sz_used: 0x%X\n", le32_to_cpu(rpb->rpb_global_sz_used));
		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_exist_pkt_cnt[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_exist_pkt_cnt[j]));
		}
		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_pb_linklist_ptr[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_pb_linklist_ptr[j]));
		}
		dev_info(dev, "rpb_fbcb_linklist_ptr: 0x%X\n",
			 le32_to_cpu(rpb->rpb_fbcb_linklist_ptr));

		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_tc_tail_stat1[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_tc_tail_stat1[j]));
		}

		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_tc_tail_stat2[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_tc_tail_stat2[j]));
		}

		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_rx_pkt[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_rx_pkt[j]));
		}
		for (j = 0; j < 8; j++) {
			dev_info(dev, "rpb_miss_pkt[%d]: 0x%X\n",
						j, le32_to_cpu(rpb->rpb_miss_pkt[j]));
		}
	}

	for (i = 0; i < 2; i++) {
		rdb = &db_stat_cnt->rdb[i];

		dev_info(dev, "=== rdb_stat_cnt[%d]\n", i);

		dev_info(dev, "rdb_stat: 0x%X\n", le32_to_cpu(rdb->rdb_stat));
		dev_info(dev, "rdb_pb_sz_used: 0x%X\n", le32_to_cpu(rdb->rdb_pb_sz_used));
		dev_info(dev, "rdb_exist_pkt_cnt: 0x%X\n", le32_to_cpu(rdb->rdb_exist_pkt_cnt));
		dev_info(dev, "rdb_exist_mpo_cnt: 0x%X\n", le32_to_cpu(rdb->rdb_exist_mpo_cnt));
		dev_info(dev, "rdb_pb_linklist_ptr: 0x%X\n", le32_to_cpu(rdb->rdb_pb_linklist_ptr));
		dev_info(dev, "rdb_fbcb_linklist_ptr: 0x%X\n",
			 le32_to_cpu(rdb->rdb_fbcb_linklist_ptr));
		dev_info(dev, "rdb_inter_buf_stat: 0x%X\n", le32_to_cpu(rdb->rdb_inter_buf_stat));

		dev_info(dev, "rdb_rx_pkt: 0x%X\n", le32_to_cpu(rdb->rdb_rx_pkt));
		dev_info(dev, "rdb_drp_pkt: 0x%X\n", le32_to_cpu(rdb->rdb_drp_pkt));
		dev_info(dev, "rdb_miss_pkt: 0x%X\n", le32_to_cpu(rdb->rdb_miss_pkt));
	}

	for (i = 0; i < 2; i++) {
		tdb = &db_stat_cnt->tdb[i];

		dev_info(dev, "=== tdb_stat_cnt[%d]\n", i);

		dev_info(dev, "tdb_stat: 0x%X\n", le32_to_cpu(tdb->tdb_stat));
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "tdb_pb_sz_used[%d][%d]: 0x%X\n",
						j, k, le32_to_cpu(tdb->tdb_pb_sz_used[((j * 8) +
								  k)]));
			}
		}
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "tdb_tc_share_sz_used[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(tdb->tdb_tc_share_sz_used[((j * 8) +
							   k)]));
			}
		}
		dev_info(dev, "tdb_share_sz_used: 0x%X\n", le32_to_cpu(tdb->tdb_share_sz_used));
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "tdb_exist_pkt_cnt[%d][%d]: 0x%X\n",
						j, k, le32_to_cpu(tdb->tdb_exist_pkt_cnt[((j * 8) +
								  k)]));
			}
		}
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "tdb_exist_mpo_cnt[%d][%d]: 0x%X\n",
						j, k, le32_to_cpu(tdb->tdb_exist_mpo_cnt[((j * 8) +
								  k)]));
			}
		}
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "tdb_pb_linklist_ptr[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(tdb->tdb_pb_linklist_ptr[((j * 8) +
							   k)]));
			}
		}
		dev_info(dev, "tdb_fbcb_linklist_ptr: 0x%X\n",
			 le32_to_cpu(tdb->tdb_fbcb_linklist_ptr));

		for (j = 0; j < 4; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "tdb_rx_pkt[%d][%d]: 0x%X\n",
						j, k, le32_to_cpu(tdb->tdb_rx_pkt[((j * 8) + k)]));
			}
		}
	}

	for (i = 0; i < 2; i++) {
		trt = &db_stat_cnt->trt[i];

		dev_info(dev, "=== trt_stat_cnt[%d]\n", i);

		dev_info(dev, "trt_stat: 0x%X\n", le32_to_cpu(trt->trt_stat));

		for (j = 0; j < 2; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "trt_pb_sz_used[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(trt->trt_pb_sz_used[((j * 8) + k)]));
			}
		}
		dev_info(dev, "trt_pb_sz_used[16]: 0x%X\n", le32_to_cpu(trt->trt_pb_sz_used[16]));

		for (j = 0; j < 2; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "trt_tc_share_sz_used[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(trt->trt_tc_share_sz_used[((j * 8) +
							   k)]));
			}
		}
		dev_info(dev, "trt_tc_share_sz_used[16]: 0x%X\n",
			 le32_to_cpu(trt->trt_tc_share_sz_used[16]));

		dev_info(dev, "trt_share_sz_used: 0x%X\n", le32_to_cpu(trt->trt_share_sz_used));

		for (j = 0; j < 2; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "trt_exist_pkt_cnt[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(trt->trt_exist_pkt_cnt[((j * 8) + k)]));
			}
		}
		dev_info(dev, "trt_exist_pkt_cnt[16]: 0x%X\n",
			 le32_to_cpu(trt->trt_exist_pkt_cnt[16]));

		for (j = 0; j < 2; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "trt_pb_linklist_ptr[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(trt->trt_pb_linklist_ptr[((j * 8) +
							   k)]));
			}
		}
		dev_info(dev, "trt_pb_linklist_ptr[16]: 0x%X\n",
			 le32_to_cpu(trt->trt_pb_linklist_ptr[16]));

		dev_info(dev, "trt_fbcb_linklist_ptr: 0x%X\n",
			 le32_to_cpu(trt->trt_fbcb_linklist_ptr));
		dev_info(dev, "trt_rfcs: 0x%X\n", le32_to_cpu(trt->trt_rfcs));
		dev_info(dev, "trt_frsz_ctl_stat: 0x%X\n", le32_to_cpu(trt->trt_frsz_ctl_stat));
		dev_info(dev, "trt_frsz_ctl_stat1: 0x%X\n", le32_to_cpu(trt->trt_frsz_ctl_stat1));
		dev_info(dev, "trt_tx_ctl_stat: 0x%X\n", le32_to_cpu(trt->trt_tx_ctl_stat));
		dev_info(dev, "trt_pkt_rel_stat: 0x%X\n", le32_to_cpu(trt->trt_pkt_rel_stat));

		for (j = 0; j < 2; j++)
			dev_info(dev, "out_pkt[%d]: 0x%X\n", j, le32_to_cpu(trt->out_pkt[j]));
		dev_info(dev, "lpbk_pkt: 0x%X\n", le32_to_cpu(trt->lpbk_pkt));
		dev_info(dev, "mng_pkt: 0x%X\n", le32_to_cpu(trt->mng_pkt));
		dev_info(dev, "lpbk_drp_pkt: 0x%X\n", le32_to_cpu(trt->lpbk_drp_pkt));
		dev_info(dev, "mng_drp_pkt: 0x%X\n", le32_to_cpu(trt->mng_drp_pkt));
		dev_info(dev, "mng_oversz_drp_pkt: 0x%X\n", le32_to_cpu(trt->mng_oversz_drp_pkt));
		dev_info(dev, "nodst_drp_pkt: 0x%X\n", le32_to_cpu(trt->nodst_drp_pkt));
		dev_info(dev, "mpos_drp_pkt: 0x%X\n", le32_to_cpu(trt->mpos_drp_pkt));
		for (j = 0; j < 2; j++) {
			for (k = 0; k < 8; k++) {
				dev_info(dev, "flush_drp_pkt[%d][%d]: 0x%X\n",
					 j, k, le32_to_cpu(trt->flush_drp_pkt[((j * 8) + k)]));
			}
		}
	}
}

static void
nse_qos_db_dump_stat_cnt_ms(struct nse_hw *hw, struct nse_aqc_qos_db_stat_cnt_ms *db_stat_cnt)
{
	struct device *dev = nse_hw_to_dev(hw);
	int i;
	struct nse_aqc_qos_db_rpb_stat_cnt_ms *rpb = NULL;
	struct nse_aqc_qos_db_rdb_stat_cnt_ms *rdb = NULL;
	struct nse_aqc_qos_db_tdb_stat_cnt_ms *tdb = NULL;

		dev_info(dev, "=== rpb_stat_cnt\n");

		rpb = &db_stat_cnt->rpb;

		dev_info(dev, "port_global_used: 0x%X\n", le32_to_cpu(rpb->port_global_used));

		dev_info(dev, "port_share_used: 0x%X\n", le32_to_cpu(rpb->port_share_used));

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tc_share_used[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->tc_share_used[i]));
		}

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tc_dedicate_used[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->tc_dedicate_used[i]));
		}

		dev_info(dev, "rpb_stat: 0x%X\n", le32_to_cpu(rpb->rpb_stat));

		dev_info(dev, "tc_pfc_stat: 0x%X\n", le32_to_cpu(rpb->tc_pfc_stat));

		dev_info(dev, "rpb_fifo_stat1: 0x%X\n", le32_to_cpu(rpb->rpb_fifo_stat1));

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tc_linklist_ptr[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->tc_linklist_ptr[i]));
		}

		dev_info(dev, "free_linklist_ptr: 0x%X\n", le32_to_cpu(rpb->free_linklist_ptr));

		for (i = 0; i < 9; i++) {
			dev_info(dev, "rpb_exist_cnt[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->rpb_exist_cnt[i]));
		}

		for (i = 0; i < 9; i++) {
			dev_info(dev, "rpb_rx_cnt[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->rpb_rx_cnt[i]));
		}

		for (i = 0; i < 9; i++) {
			dev_info(dev, "rpb_mcast_cnt[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->rpb_mcast_cnt[i]));
		}

		for (i = 0; i < 9; i++) {
			dev_info(dev, "rpb_miss_cnt[%d]: 0x%X\n",
						i, le32_to_cpu(rpb->rpb_miss_cnt[i]));
		}

		dev_info(dev, "=== rdb_stat_cnt\n");

		rdb = &db_stat_cnt->rdb;

		dev_info(dev, "rdb_stat: 0x%X\n", le32_to_cpu(rdb->rdb_stat));
		dev_info(dev, "rdb_pb_sz_used: 0x%X\n", le32_to_cpu(rdb->rdb_pb_sz_used));
		dev_info(dev, "rdb_exist_pkt_cnt: 0x%X\n", le32_to_cpu(rdb->rdb_exist_pkt_cnt));
		dev_info(dev, "rdb_exist_mpo_cnt: 0x%X\n", le32_to_cpu(rdb->rdb_exist_mpo_cnt));
		dev_info(dev, "rdb_pb_linklist_ptr: 0x%X\n", le32_to_cpu(rdb->rdb_pb_linklist_ptr));
		dev_info(dev, "rdb_fbcb_linklist_ptr: 0x%X\n",
			 le32_to_cpu(rdb->rdb_fbcb_linklist_ptr));

		dev_info(dev, "rdb_rx_pkt: 0x%X\n", le32_to_cpu(rdb->rdb_rx_pkt));
		dev_info(dev, "rdb_drp_pkt: 0x%X\n", le32_to_cpu(rdb->rdb_drp_pkt));
		dev_info(dev, "rdb_miss_pkt: 0x%X\n", le32_to_cpu(rdb->rdb_miss_pkt));

		dev_info(dev, "=== tdb_stat_cnt\n");

		tdb = &db_stat_cnt->tdb;

		dev_info(dev, "tdb_stat: 0x%X\n", le32_to_cpu(tdb->tdb_stat));

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tdb_pb_sz_used[%d]: 0x%X\n",
						i, le32_to_cpu(tdb->tdb_pb_sz_used[i]));
		}

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tdb_tc_share_sz_used[%d]: 0x%X\n",
						i, le32_to_cpu(tdb->tdb_tc_share_sz_used[i]));
		}

		dev_info(dev, "tdb_share_sz_used: 0x%X\n", le32_to_cpu(tdb->tdb_share_sz_used));

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tdb_exist_pkt_cnt[%d]: 0x%X\n",
						i, le32_to_cpu(tdb->tdb_exist_pkt_cnt[i]));
		}

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tdb_exist_mpo_cnt[%d]: 0x%X\n",
						i, le32_to_cpu(tdb->tdb_exist_mpo_cnt[i]));
		}

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tdb_pb_linklist_ptr[%d]: 0x%X\n",
						i, le32_to_cpu(tdb->tdb_pb_linklist_ptr[i]));
		}

		dev_info(dev, "tdb_fbcb_linklist_ptr: 0x%X\n",
			 le32_to_cpu(tdb->tdb_fbcb_linklist_ptr));

		for (i = 0; i < 8; i++) {
			dev_info(dev, "tdb_rx_pkt[%d]: 0x%X\n",
						i, le32_to_cpu(tdb->tdb_rx_pkt[i]));
		}
}

void
nse_qos_db_dump_stat_cnt(struct nse_hw *hw, struct nse_aqc_qos_db_stat_cnt *db_stat_cnt)
{
	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		nse_qos_db_dump_stat_cnt_amber(hw, &db_stat_cnt->amber);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		nse_qos_db_dump_stat_cnt_ms(hw, &db_stat_cnt->ms);
}

static enum nse_status
__nse_aq_qos_db_conf_up_enforcement(struct nse_hw *hw, u8 rw,
				    struct nse_aqc_qos_db_conf_up_enforcement *cmd_data)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_QOS,
				      NSE_AQ_OPC_QOS_DB_CONF_UP_ENFORCEMENT);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_data->hdr, NSE_VSI_INVAL_ID);

	cmd_data->eth_grp_id = hw->port_info->curr_eth_grp_id;
	cmd_data->rw = rw;

	return nse_aq_send_cmd(hw, &desc, cmd_data, sizeof(*cmd_data), NULL);
}

enum nse_status
nse_aq_qos_db_read_up_enforcement(struct nse_hw *hw,
				  struct nse_aqc_qos_db_conf_up_enforcement *cmd_data)
{
	return __nse_aq_qos_db_conf_up_enforcement(hw, 0, cmd_data);
}

enum nse_status
nse_aq_qos_db_write_up_enforcement(struct nse_hw *hw,
				   struct nse_aqc_qos_db_conf_up_enforcement *cmd_data)
{
	return __nse_aq_qos_db_conf_up_enforcement(hw, 1, cmd_data);
}

/**
 * nse_aq_clear_pxe_mode
 * @hw: pointer to the HW struct
 *
 * Tell the firmware that the driver is taking over from PXE.
 */
static enum nse_status nse_aq_clear_pxe_mode(struct nse_hw *hw)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_CLEAR_PXE_MODE);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

/**
 * nse_clear_pxe_mode - clear pxe operations mode
 * @hw: pointer to the HW struct
 *
 * Make sure all PXE mode settings are cleared, including things
 * like descriptor fetch/write-back mode.
 */
void nse_clear_pxe_mode(struct nse_hw *hw)
{
	if (nse_check_sq_alive(hw, &hw->adminq, NULL))
		(void)nse_aq_clear_pxe_mode(hw);
}

enum nse_status
nse_aq_set_itr_interval(struct nse_hw *hw, u16 irq_abs_id, u32 interval)
{
	struct nse_aq_desc desc;
	u32 tmp = 0;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_SET_ITR_INTERVAL);

	if (!interval)
		interval = 1;

	tmp = (hw->pcore_id << 16) | irq_abs_id;
	desc.param0 = cpu_to_le32(tmp);
	desc.param1 = cpu_to_le32(interval);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_set_intrl_interval(struct nse_hw *hw, u16 irq_abs_id, u32 interval)
{
	struct nse_aq_desc desc;
	u32 tmp = 0;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC,
				      NSE_AQ_OPC_SET_INTRL_INTERVAL);

	tmp = (hw->pcore_id << 16) | irq_abs_id;
	desc.param0 = cpu_to_le32(tmp);
	desc.param1 = cpu_to_le32(interval);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_ptp_get_sys_time(struct nse_hw *hw, u32 *sec, u32 *nsec, u64 *ns)
{
	struct nse_aqc_ptp_get_set_adj_sys_time buf;
	struct nse_aq_desc desc;
	struct timespec64 ts;
	enum nse_status ret;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_GET_SYS_TIME);

	buf.lan_id = hw->lan_id;

	ret = nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
	if (!ret) {
		if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
			*sec = le32_to_cpu(buf.amber.sec);
			*nsec = le32_to_cpu(buf.amber.nsec);

			ts.tv_sec = *sec;
			ts.tv_nsec = *nsec;

			*ns = timespec64_to_ns(&ts);

		} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
			*ns = le32_to_cpu(buf.ms.val_l);
			*ns |= (((u64)le32_to_cpu(buf.ms.val_h)) << 32);

			ts = ns_to_timespec64(*ns);

			*sec = ts.tv_sec;
			*nsec = ts.tv_nsec;

		} else
			ret = NSE_ERR_NOT_SUPPORTED;
	}

	return ret;
}

static enum nse_status
__nse_aq_ptp_set_sys_time(struct nse_hw *hw, struct nse_aqc_ptp_get_set_adj_sys_time *buf)
{
	struct nse_aq_desc desc;

	buf->lan_id = hw->lan_id;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_SET_SYS_TIME);

	return nse_aq_send_cmd(hw, &desc, buf, sizeof(*buf), NULL);
}

enum nse_status
nse_aq_ptp_set_sys_time_by_nsec(struct nse_hw *hw, u64 ns)
{
	struct nse_aqc_ptp_get_set_adj_sys_time buf;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		struct timespec64 ts;

		ts = ns_to_timespec64((s64)ns);

		buf.amber.sec = cpu_to_le32((u32)ts.tv_sec);
		buf.amber.nsec = cpu_to_le32((u32)ts.tv_nsec);
	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		buf.ms.val_h = cpu_to_le32((u32)(ns >> 32));
		buf.ms.val_l = cpu_to_le32((u32)(ns));
	} else
		return NSE_ERR_NOT_SUPPORTED;

	return __nse_aq_ptp_set_sys_time(hw, &buf);
}

enum nse_status
nse_aq_ptp_set_sys_time_by_sec_nsec(struct nse_hw *hw, u32 sec, u32 nsec)
{
	struct nse_aqc_ptp_get_set_adj_sys_time buf;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		buf.amber.sec = cpu_to_le32(sec);
		buf.amber.nsec = cpu_to_le32(nsec);
	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		struct timespec64 ts;
		u64 ns;

		ts.tv_sec = sec;
		ts.tv_nsec = nsec;

		ns = (u64)timespec64_to_ns(&ts);

		buf.ms.val_h = cpu_to_le32((u32)(ns >> 32));
		buf.ms.val_l = cpu_to_le32((u32)(ns));
	} else
		return NSE_ERR_NOT_SUPPORTED;

	return __nse_aq_ptp_set_sys_time(hw, &buf);
}

enum nse_status
nse_aq_ptp_adj_sys_time_amber(struct nse_hw *hw, u32 sec, u32 nsec)
{
	struct nse_aqc_ptp_get_set_adj_sys_time buf;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_ADJ_SYS_TIME);

	buf.lan_id = hw->lan_id;
	buf.amber.sec = cpu_to_le32(sec);
	buf.amber.nsec = cpu_to_le32(nsec);

	return nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
}

enum nse_status
nse_aq_ptp_adj_sys_time_ms(struct nse_hw *hw, u32 val_h, u32 val_l)
{
	struct nse_aqc_ptp_get_set_adj_sys_time buf;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_ADJ_SYS_TIME);

	buf.lan_id = hw->lan_id;
	buf.ms.val_h = cpu_to_le32(val_h);
	buf.ms.val_l = cpu_to_le32(val_l);

	return nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
}

enum nse_status
nse_aq_ptp_get_control(struct nse_hw *hw, u32 *control)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_GET_CONTROL);

	desc.param0 = cpu_to_le32((u32)hw->lan_id);

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (!ret)
		*control = le32_to_cpu(desc.param1);

	return ret;
}

enum nse_status
nse_aq_ptp_set_control(struct nse_hw *hw, u32 control)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_SET_CONTROL);

	desc.param0 = cpu_to_le32((u32)hw->lan_id);
	desc.param1 = cpu_to_le32(control);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_ptp_get_incval(struct nse_hw *hw, u32 *incval)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_GET_INCVAL);

	desc.param0 = cpu_to_le32((u32)hw->lan_id);

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (!ret)
		*incval = le32_to_cpu(desc.param1);

	return ret;
}

enum nse_status
nse_aq_ptp_set_incval(struct nse_hw *hw, u32 incval)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_SET_INCVAL);

	desc.param0 = cpu_to_le32((u32)hw->lan_id);
	desc.param1 = cpu_to_le32(incval);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_ptp_get_addend(struct nse_hw *hw, u32 *addend)
{
	enum nse_status ret;
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_GET_ADDEND);

	desc.param0 = cpu_to_le32((u32)hw->lan_id);

	ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (!ret)
		*addend = le32_to_cpu(desc.param1);

	return ret;
}

enum nse_status
nse_aq_ptp_set_addend(struct nse_hw *hw, u32 addend)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_SET_ADDEND);

	desc.param0 = cpu_to_le32((u32)hw->lan_id);
	desc.param1 = cpu_to_le32(addend);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_ptp_init(struct nse_hw *hw, struct nse_aqc_ptp_init *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_INIT);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_aq_ptp_read_tx_ts(struct nse_hw *hw, struct nse_aqc_ptp_rd_clr_tx_ts *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_RD_TX_TS);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_aq_ptp_clear_tx_ts(struct nse_hw *hw, struct nse_aqc_ptp_rd_clr_tx_ts *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PTP_CLR_TX_TS);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_aq_psr_set_ctrl(struct nse_hw *hw, struct nse_aqc_psr_set_ctrl *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_PSR_SET_CTRL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_aq_set_port_params(struct nse_hw *hw, u16 bad_frame_vsi,
		       bool save_bad_pac, bool pad_short_pac)
{
	struct nse_aqc_set_port_params buf;
	struct nse_aq_desc desc;

	memset(&buf, 0, sizeof(buf));

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH,
				      NSE_AQ_OPC_SET_PORT_PARAMS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &buf.hdr, NSE_VSI_INVAL_ID);

	if (save_bad_pac) {
		buf.cmd_flags |= cpu_to_le16(NSE_AQC_SET_P_PARAMS_SAVE_BAD_PACKETS);
		buf.bad_frame_vsi = cpu_to_le16(bad_frame_vsi);
	}
	if (pad_short_pac)
		buf.cmd_flags |= cpu_to_le16(NSE_AQC_SET_P_PARAMS_PAD_SHORT_PACKETS);

	/* never set buf.swid */

	return nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
}

/* nse_aq_manage_mac_read() - read MAC address of specified type
 */
enum nse_status
nse_aq_manage_mac_read(struct nse_hw *hw, struct nse_aqc_manage_mac *buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_MANAGE_MAC_READ);

	buf->lan_id = hw->lan_id;

	return nse_aq_send_cmd(hw, &desc, buf, sizeof(*buf), NULL);
}

enum nse_status
nse_manage_mac_read(struct nse_hw *hw, void *factory_addr, void *lmac_addr, void *wol_addr)
{
	struct nse_aqc_manage_mac *buf = NULL;
	enum nse_status status;

	buf = devm_kcalloc(nse_hw_to_dev(hw), 1, sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	status = nse_aq_manage_mac_read(hw, buf);
	if (status)
		goto out;

	/* return address value into OUTPUT arguments if not NULL */
	if (factory_addr)
		ether_addr_copy(factory_addr,
				buf->addrs[NSE_AQC_MAN_MAC_ADDR_TYPE_FACTORY].mac_addr);

	if (lmac_addr)
		ether_addr_copy(lmac_addr, buf->addrs[NSE_AQC_MAN_MAC_ADDR_TYPE_LMAC].mac_addr);

	if (wol_addr)
		ether_addr_copy(wol_addr, buf->addrs[NSE_AQC_MAN_MAC_ADDR_TYPE_WOL].mac_addr);

out:
	if (buf != NULL)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return status;
}

/**
 * nse_aq_manage_mac_write - manage MAC address write command
 */
enum nse_status
nse_aq_manage_mac_write(struct nse_hw *hw, const u8 *addr, u16 wflags, u8 wol_mpe)
{
	enum nse_status status;
	struct nse_aqc_manage_mac *buf = NULL;
	struct nse_aq_desc desc;

	if (!addr) {
		status = NSE_ERR_PARAM;
		goto out;
	}

	buf = devm_kcalloc(nse_hw_to_dev(hw), 1, sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_MANAGE_MAC_WRITE);

	buf->lan_id = hw->lan_id;
	buf->wflags = cpu_to_le16(wflags);
	buf->wol_mpe = wol_mpe;

	ether_addr_copy(buf->addrs[NSE_AQC_MAN_MAC_ADDR_TYPE_LMAC].mac_addr, addr);
	ether_addr_copy(buf->addrs[NSE_AQC_MAN_MAC_ADDR_TYPE_WOL].mac_addr, addr);

	status = nse_aq_send_cmd(hw, &desc, buf, sizeof(*buf), NULL);

out:
	if (buf != NULL)
		devm_kfree(nse_hw_to_dev(hw), buf);

	return status;
}

enum nse_status
nse_aq_rss_get_ctl(struct nse_vsi *vsi, u32 *rssctl)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_aq_desc desc;
	struct nse_aqc_rss_get_set_ctl cmd_buf;
	enum nse_status ret;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_RSS_GET_CTL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, vsi->vsi_abs_num);

	ret = nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
	if (!ret)
		*rssctl = le32_to_cpu(cmd_buf.ctl);

	return ret;
}

enum nse_status
nse_aq_rss_set_ctl(struct nse_vsi *vsi, u32 rssctl)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_aq_desc desc;
	struct nse_aqc_rss_get_set_ctl cmd_buf;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_RSS_SET_CTL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf.hdr, vsi->vsi_abs_num);

	cmd_buf.ctl = cpu_to_le32(rssctl);

	return nse_aq_send_cmd(hw, &desc, &cmd_buf, sizeof(cmd_buf), NULL);
}

enum nse_status
nse_aq_rss_get_key(struct nse_vsi *vsi, u8 *key)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_aqc_rss_get_set_key *cmd_buf;
	struct nse_aq_desc desc;
	enum nse_status ret;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_KERNEL);
	if (!cmd_buf)
		return NSE_ERR_NO_MEMORY;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_RSS_GET_KEY);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, vsi->vsi_abs_num);

	ret = nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
	if (!ret)
		memcpy(key, cmd_buf->key, NSE_RSS_KEY_SIZE);

	kfree(cmd_buf);

	return ret;
}

enum nse_status
nse_aq_rss_set_key(struct nse_vsi *vsi, u8 *key)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_aqc_rss_get_set_key *cmd_buf;
	struct nse_aq_desc desc;
	enum nse_status ret;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_KERNEL);
	if (!cmd_buf)
		return NSE_ERR_NO_MEMORY;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_RSS_SET_KEY);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, vsi->vsi_abs_num);

	memcpy(cmd_buf->key, key, NSE_RSS_KEY_SIZE);

	ret = nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);

	kfree(cmd_buf);

	return ret;
}

enum nse_status
nse_aq_rss_get_lut(struct nse_vsi *vsi, u16 lut_start, u16 lut_size, u16 *lut_data)
{
	enum nse_status ret;
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_aqc_rss_get_set_lut *buf;
	size_t buf_size;
	struct nse_aq_desc desc;
	u16 i = 0;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_RSS_GET_LUT);

	buf_size = sizeof(*buf) + (lut_size * sizeof(u16));
	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		ret = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_aqc_fill_generic_common_hdr_dft(hw, &buf->hdr, vsi->vsi_abs_num);

	buf->lut_start = cpu_to_le16(lut_start);
	buf->lut_size = cpu_to_le16(lut_size);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);
	if (!ret) {
		/* need to convert to host order */
		for (i = 0; i < lut_size; i++)
			lut_data[i] = le16_to_cpu(buf->lut_data[i]);
	}

out:
	kfree(buf);

	return ret;
}

enum nse_status
nse_aq_rss_set_lut(struct nse_vsi *vsi, u16 lut_start, u16 lut_size, u16 *lut_data)
{
	enum nse_status ret;
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_aqc_rss_get_set_lut *buf;
	size_t buf_size;
	struct nse_aq_desc desc;
	u16 i = 0;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_RCF, NSE_AQ_OPC_RSS_SET_LUT);

	buf_size = sizeof(*buf) + (lut_size * sizeof(u16));
	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		ret = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_aqc_fill_generic_common_hdr_dft(hw, &buf->hdr, vsi->vsi_abs_num);

	buf->lut_start = cpu_to_le16(lut_start);
	buf->lut_size = cpu_to_le16(lut_size);

	/* need to convert to LE order */
	for (i = 0; i < lut_size; i++)
		buf->lut_data[i] = cpu_to_le16(lut_data[i]);

	ret = nse_aq_send_cmd(hw, &desc, buf, buf_size, NULL);

out:
	kfree(buf);

	return ret;
}

/**
 * nse_fw_supports_lldp_fltr_ctrl - check NVM version supports lldp_fltr_ctrl
 * @hw: pointer to HW struct
 */
bool nse_fw_supports_lldp_fltr_ctrl(struct nse_hw *hw)
{
	/* @xzhao - todo-5: nse_fw_supports_lldp_fltr_ctrl() - FW-LLDP-agent */
	return false;
}

/**
 * nse_lldp_fltr_add_remove - add or remove a LLDP Rx switch filter
 * @hw: pointer to HW struct
 * @vsi_num: absolute HW index for VSI
 * @add: boolean for if adding or removing a filter
 */
enum nse_status
nse_lldp_fltr_add_remove(struct nse_hw *hw, u16 vsi_num, bool add)
{
	/* @xzhao - todo-5: nse_lldp_fltr_add_remove() - FW-LLDP-agent */
	return 0;
}

enum nse_status
nse_aq_dbg_ping_fw_with_buf(struct nse_hw *hw, u8 *cmd_buf, u32 buf_len)
{
	struct nse_aq_desc desc;

	if (cmd_buf == NULL)
		return NSE_ERR_PARAM;

	if (buf_len > NSE_AQ_MAX_BUF_LEN)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_DBG,
				      NSE_AQ_OPC_DBG_PING_FW_WITH_BUF);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, buf_len, NULL);
}

enum nse_status
nse_aq_dbg_ping_fw_rq_req(struct nse_hw *hw, u8 *cmd_buf, u32 buf_len)
{
	struct nse_aq_desc desc;

	if (cmd_buf == NULL)
		return NSE_ERR_PARAM;

	if (buf_len > NSE_AQ_MAX_BUF_LEN)
		return NSE_ERR_PARAM;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_DBG,
				      NSE_AQ_OPC_DBG_PING_FW_RQ_REQ);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, buf_len, NULL);
}

void
nse_aq_handle_dbg_ping_fw_rq_rsp(struct nse_hw *hw, struct nse_rq_event_info *event)
{
	struct device *dev = nse_hw_to_dev(hw);
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	static unsigned long ping_fw_rq_rsp_cnt;

	dev_info(dev, "Receiving PING_FW_RQ_RSP, ping_fw_rq_rsp_cnt = %ld\n", ping_fw_rq_rsp_cnt++);

	dev_info(dev, "PING_FW_RQ_RSP event_buf content (first 8 bytes in total %d bytes):\n",
		 msglen);
	dev_info(dev, "    %02X %02X %02X %02X %02X %02X %02X %02X\n",
						msg[0], msg[1], msg[2], msg[3], msg[4],
							msg[5], msg[6], msg[7]);
}

enum nse_status
nse_aq_dbg_req_dummy_event(struct nse_hw *hw, u32 times, u32 interval)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_DBG,
				      NSE_AQ_OPC_DBG_REQ_DUMMY_EVENT);

	desc.param0 = cpu_to_le32(times);
	desc.param1 = cpu_to_le32(interval);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

void
nse_aq_handle_dbg_dummy_event(struct nse_hw *hw, struct nse_rq_event_info *event)
{
	struct device *dev = nse_hw_to_dev(hw);
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	static unsigned long dbg_dummy_event_cnt;

	dev_info(dev, "Receiving DBG_DUMMY_EVENT, dbg_dummy_event_cnt = %ld\n",
		 dbg_dummy_event_cnt++);

	dev_info(dev, "DBG_DUMMY_EVENT event_buf content (first 8 bytes in total %d bytes):\n",
		 msglen);
	dev_info(dev, "    %02X %02X %02X %02X %02X %02X %02X %02X\n",
						msg[0], msg[1], msg[2], msg[3], msg[4],
							msg[5], msg[6], msg[7]);
}

enum nse_status
nse_aq_dbg_rw_registers(struct nse_hw *hw, u32 reg_base_addr, u16 reg_cnt,
			u16 rw_flag, u32 *reg_values, unsigned int sq_send_cmd_flags)
{
	struct nse_aqc_dbg_rw_regs *cmd_buf = NULL;
	unsigned int cmd_buf_size;
	struct nse_aq_desc desc;
	int i;
	enum nse_status ret;

	if (!reg_base_addr || (reg_base_addr & 0x3) ||	/* base addr need to align to 4 bytes */
		!reg_cnt || !reg_values)
		return NSE_ERR_PARAM;

	cmd_buf_size = sizeof(struct nse_aqc_dbg_rw_regs) + sizeof(__le32) * reg_cnt;
	if (cmd_buf_size > NSE_AQ_MAX_BUF_LEN)
		return NSE_ERR_MAX_LIMIT;

	cmd_buf = devm_kzalloc(nse_hw_to_dev(hw), cmd_buf_size, GFP_KERNEL);
	if (!cmd_buf)
		return NSE_ERR_NO_MEMORY;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_DBG, NSE_AQ_OPC_DBG_RW_REGS);

	cmd_buf->reg_base_addr = cpu_to_le32(reg_base_addr);
	cmd_buf->reg_cnt = cpu_to_le16(reg_cnt);
	cmd_buf->rw_flag = cpu_to_le16(rw_flag);	/* 0 for read, non-0 for write */

	if (rw_flag) {	/* write cmd */
		for (i = 0; i < reg_cnt; i++)
			cmd_buf->reg_values[i] = cpu_to_le32(reg_values[i]);
	}

	ret = nse_sq_send_cmd_with_flags(hw, &hw->adminq, &desc, cmd_buf,
					 cmd_buf_size, NULL, sq_send_cmd_flags);

	if (!ret && !rw_flag) {	/* read cmd, and success, then copy to OUTPUT argument */
		for (i = 0; i < reg_cnt; i++)
			reg_values[i] = le32_to_cpu(cmd_buf->reg_values[i]);
	}

	if (cmd_buf)
		devm_kfree(nse_hw_to_dev(hw), cmd_buf);

	return ret;
}

enum nse_status
nse_switch_rpp_set_bypass(struct nse_hw *hw, bool en, u16 vsi_abs_num, u8 ll_tc_map)
{
	struct nse_aq_desc desc;
	struct nse_aqc_switch_rpp_set_bypass buf;
	u32 ll_ctrl;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		return NSE_SUCCESS;

	memset(&buf, 0, sizeof(buf));

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_SWITCH,
				      NSE_AQ_OPC_SWITCH_RPP_SET_BYPASS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &buf.hdr, vsi_abs_num);

	if (en) {
		buf.rpp_bypass = cpu_to_le32(1);

		ll_ctrl = BIT(27) |		//vsi_en = true
					(((u32)vsi_abs_num & 0xFF) << 19) |	//vsi
					((u32)ll_tc_map);
	} else {
		buf.rpp_bypass = cpu_to_le32(0);

		ll_ctrl = 0;
	}

	buf.ll_ctrl_val = cpu_to_le32(ll_ctrl);

	return nse_aq_send_cmd(hw, &desc, &buf, sizeof(buf), NULL);
}

static enum nse_status
nse_aq_conf_irqll(struct nse_hw *hw, struct nse_aqc_conf_irqll *cmd_buf)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_CONF_IRQLL);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd_buf->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, cmd_buf, sizeof(*cmd_buf), NULL);
}

enum nse_status
nse_conf_irqll_reset_one(struct nse_hw *hw, u16 msix)
{
	struct nse_aqc_conf_irqll *cmd_buf = NULL;
	enum nse_status status;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_KERNEL);
	if (!cmd_buf)
		return NSE_ERR_NO_MEMORY;

	cmd_buf->op = NSE_AQC_CONF_IRQLL_OP_RESET;
	cmd_buf->msix = cpu_to_le16(msix);

	status = nse_aq_conf_irqll(hw, cmd_buf);

	kfree(cmd_buf);

	return status;
}

enum nse_status
nse_conf_irqll_reset_many(struct nse_hw *hw, u16 msix_first, u16 msix_last)
{
	struct nse_aqc_conf_irqll *cmd_buf = NULL;
	enum nse_status status;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_KERNEL);
	if (!cmd_buf)
		return NSE_ERR_NO_MEMORY;

	cmd_buf->flags = cpu_to_le32(NSE_AQC_CONF_IRQLL_FLAG_RESET_MANY);

	cmd_buf->op = NSE_AQC_CONF_IRQLL_OP_RESET;
	cmd_buf->msix = cpu_to_le16(msix_first);

	cmd_buf->msix_first = cpu_to_le16(msix_first);
	cmd_buf->msix_last = cpu_to_le16(msix_last);

	status = nse_aq_conf_irqll(hw, cmd_buf);

	kfree(cmd_buf);

	return status;
}

enum nse_status
nse_conf_irqll_lanq(struct nse_hw *hw, u8 op, u8 qtype, u16 qid, u16 msix)
{
	struct nse_aqc_conf_irqll *cmd_buf = NULL;
	enum nse_status status;

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_KERNEL);
	if (!cmd_buf)
		return NSE_ERR_NO_MEMORY;

	cmd_buf->qid = cpu_to_le16(qid);
	cmd_buf->qtype = qtype;
	cmd_buf->op = op;

	cmd_buf->msix = cpu_to_le16(msix);

	status = nse_aq_conf_irqll(hw, cmd_buf);
	if (!status) {
		/* check op_result */
		if ((op == NSE_AQC_CONF_IRQLL_OP_ADD) &&
			(cmd_buf->conf_result != 0x0)) {
			status = NSE_ERR_CFG;
		} else if ((op == NSE_AQC_CONF_IRQLL_OP_DEL) &&
					/*  for op = DEL, result: b'00, 01, 11 are all considered
					 * success
					 */
					(cmd_buf->conf_result == 0x2)) {
			status = NSE_ERR_CFG;
		}
	}

	kfree(cmd_buf);

	return status;
}

enum nse_status
nse_aq_request_reset_rdma(struct nse_hw *hw, bool reset_vsi, u16 vsi_abs_num)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_RESET_RDMA);

	if (reset_vsi) {
		desc.param0 = 0;
		desc.param1 = cpu_to_le32((u32)vsi_abs_num);
	} else {
		desc.param0 = cpu_to_le32(1);
	}

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_write_ddp(struct nse_hw *hw, const unsigned char *data, unsigned int data_len)
{
	struct nse_aq_desc desc;
	struct nse_aqc_ddp *cmd_buf = NULL;
	unsigned int cmd_buf_len;
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_DDP);

	if (!data || !data_len) {
		status = NSE_ERR_PARAM;
		goto out;
	}

	cmd_buf_len = sizeof(*cmd_buf) + data_len;
	if (cmd_buf_len > NSE_AQ_MAX_BUF_LEN) {
		status = NSE_ERR_INVAL_SIZE;
		goto out;
	}

	cmd_buf = kzalloc(cmd_buf_len, GFP_KERNEL);
	if (!cmd_buf) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	//cmd_buf->flags = 0;	# write
	cmd_buf->data_len = cpu_to_le32(data_len);
	memcpy(cmd_buf->data, data, data_len);

	status = nse_aq_send_cmd(hw, &desc, cmd_buf, cmd_buf_len, NULL);

out:
	kfree(cmd_buf);

	return status;
}

