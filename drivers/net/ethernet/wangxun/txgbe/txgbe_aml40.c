// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_bp_base.h"
#include "txgbe_e56.h"
#include "txgbe_e56_bp.h"
#include "txgbe_phy.h"
#include "txgbe_mng_phy.h"

/**
 *  txgbe_reset_hw_aml40 - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
static int txgbe_reset_hw_aml40(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	int ret;

	ret = txgbe_reset_hw_generic(hw);
	if (ret)
		goto out;

	/* special mac and link configure for aml. */
	wr32(hw, TXGBE_LINKUP_FILTER, TXGBE_LINKUP_FILTER_TIME);
	wr32m(hw, TXGBE_MAC_MISC_CTL, TXGBE_MAC_MISC_LINK_STS_MOD,
	      TXGBE_LINK_BOTH_PCS_MAC);
	/* amlite: bme */
	wr32(hw, PX_PF_BME, 0x1);
	/* amlite: rdm_rsc_ctl_free_ctl set to 1 */
	wr32m(hw, TXGBE_RDM_RSC_CTL, TXGBE_RDM_RSC_CTL_FREE_CTL,
	      TXGBE_RDM_RSC_CTL_FREE_CTL);
	adapter->an_done = false;
	adapter->cur_fec_link = TXGBE_PHY_FEC_AUTO;

out:
	return ret;
}

/**
 *  txgbe_get_media_type_aml40 - Get media type
 *  @hw: pointer to hardware structure
 *
 *  Returns the media type (fiber, copper, backplane)
 **/
static enum txgbe_media_type txgbe_get_media_type_aml40(struct txgbe_hw *hw)
{
	u8 device_type = hw->subsystem_device_id & 0xF0;
	enum txgbe_media_type media_type;

	switch (device_type) {
	case TXGBE_ID_KR_KX_KX4:
		media_type = txgbe_media_type_backplane;
		break;
	case TXGBE_ID_SFP:
		media_type = txgbe_media_type_fiber_qsfp;
		break;
	default:
		media_type = txgbe_media_type_unknown;
		break;
	}

	return media_type;
}

/**
 *  txgbe_setup_mac_link_aml40 - Set MAC link speed
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Set the link speed in the AUTOC register and restarts link.
 **/
static int txgbe_setup_mac_link_aml40(struct txgbe_hw *hw,
				      u32 speed,
			       bool autoneg_wait_to_complete)
{
	u32 link_capabilities = TXGBE_LINK_SPEED_UNKNOWN;
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	struct txgbe_adapter *adapter = hw->back;
	bool link_up = false;
	bool autoneg = false;
	int ret_status = 0;
	int i = 0;
	int status = 0;

	/* Check to see if speed passed in is supported. */
	status = hw->mac.ops.get_link_capabilities(hw,
				   &link_capabilities, &autoneg);
	if (status)
		goto out;

	speed &= link_capabilities;

	if (speed == TXGBE_LINK_SPEED_UNKNOWN) {
		status = TXGBE_ERR_LINK_SETUP;
		goto out;
	}

	if (test_bit(TXGBE_FLAG_FW_CONTROL_PHY, adapter->flag)) {
		status = txgbe_set_phy_link_hostif(hw, speed, autoneg, 1);
		goto out;
	}

	if (txgbe_xpcs_an_enabled(hw)) {
		/* If XPCS_AN73 is enabled */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up && adapter->an_done)
			goto out;
		mutex_lock(&adapter->e56_lock);
		txgbe_e56_set_phylinkmode(adapter, 40, hw->bypass_ctle);
		mutex_unlock(&adapter->e56_lock);
		goto out;
	}

	if (autoneg_wait_to_complete)
		goto reset_up;

	if (txgbe_is_backplane(hw) || txgbe_is_dac_cable(hw) ||
	    adapter->ffe_set) {
		mutex_lock(&adapter->e56_lock);
		txgbe_xlgpcs_txffe_set(adapter, speed);
		mutex_unlock(&adapter->e56_lock);
	}

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			break;
		msleep(250);
	}

	if (link_speed == speed && link_up && !adapter->ffe_set)
		goto out;

reset_up:
	mutex_lock(&adapter->e56_lock);
	ret_status = txgbe_set_link_to_amlite(hw, speed);
	mutex_unlock(&adapter->e56_lock);

	if (ret_status == TXGBE_ERR_TIMEOUT)
		adapter->link_valid = false;

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			goto out;
		msleep(250);
	}

	adapter->flags |= TXGBE_FLAG_NEED_LINK_CONFIG;

out:
	return status;
}

static int txgbe_is_40g_fiber_qsfp(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type == txgbe_qsfp_type_40g_sr_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_sr_core1 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_lr_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_lr_core1 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_active_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_active_core1)
		return true;

	return false;
}

/**
 *  txgbe_get_link_capabilities_aml40 - Determines link capabilities
 *  @hw: pointer to hardware structure
 *  @speed: pointer to link speed
 *  @autoneg: true when autoneg or autotry is enabled
 *
 *  Determines the link capabilities by reading the AUTOC register.
 **/
static int txgbe_get_link_capabilities_aml40(struct txgbe_hw *hw, u32 *speed,
					     bool *autoneg)
{
	struct txgbe_adapter *adapter = hw->back;
	int status = 0;

	/* Backplane*/
	if (txgbe_is_backplane(hw)) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_40GB_FULL;
		if (hw->phy.link_info.req_speeds)
			*speed &= hw->phy.link_info.req_speeds;
		/* Backplane supports autonegotiation */
		*autoneg = adapter->backplane_an;
		txgbe_ephy_oem_config(hw, speed, autoneg);
		return status;
	}

	/* Fiber or DAC cable */
	if (txgbe_is_dac_cable(hw)) {
		if (hw->phy.fiber_suppport_speed ==
		    TXGBE_LINK_SPEED_10GB_FULL && AUTO <= 1) {
			adapter->backplane_an = false;
			*autoneg = false;
		} else {
			*autoneg = adapter->backplane_an;
		}
		*speed = hw->phy.fiber_suppport_speed;
		if (hw->phy.link_info.req_speeds)
			*speed &= hw->phy.link_info.req_speeds;
		txgbe_ephy_oem_config(hw, speed, autoneg);
	} else if (hw->phy.multispeed_fiber) {
		/* multispeed fiber must before single fiber */
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = true;
		adapter->autoneg = *autoneg;
	} else if (txgbe_is_40g_fiber_qsfp(hw)) {
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = false;
	} else if (txgbe_is_10g_fiber_sfp(hw)) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
		*autoneg = false;
	} else {
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = false;
	}

	return status;
}

/**
 *  txgbe_check_mac_link_aml40 - Determine link and speed status
 *  @hw: pointer to hardware structure
 *  @speed: pointer to link speed
 *  @link_up: true when link is up
 *  @link_up_wait_to_complete: bool used to wait for link up or not
 *
 *  Reads the links register to determine if link is up and the current speed
 **/
static int txgbe_check_mac_link_aml40(struct txgbe_hw *hw, u32 *speed,
				      bool *link_up, bool link_up_wait_to_complete)
{
	struct txgbe_adapter *adapter = hw->back;
	u32 links_reg = 0;
	u32 i;

	if (link_up_wait_to_complete) {
		for (i = 0; i < TXGBE_LINK_UP_TIME; i++) {
			links_reg = rd32(hw,
					 TXGBE_CFG_PORT_ST);

			if (!adapter->link_valid) {
				*link_up = false;

				msleep(100);
				continue;
			}

			if (!(links_reg & TXGBE_CFG_PORT_ST_LINK_UP)) {
				*link_up = false;
			} else {
				*link_up = true;
				break;
			}
			msleep(100);
		}
	} else {
		links_reg = rd32(hw, TXGBE_CFG_PORT_ST);
		if (links_reg & TXGBE_CFG_PORT_ST_LINK_UP)
			*link_up = true;
		else
			*link_up = false;
	}

	if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_40G) ==
	    TXGBE_CFG_PORT_ST_AML_LINK_40G)
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
	else if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_25G) ==
		 TXGBE_CFG_PORT_ST_AML_LINK_25G)
		*speed = TXGBE_LINK_SPEED_25GB_FULL;
	else if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_10G) ==
		 TXGBE_CFG_PORT_ST_AML_LINK_10G)
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
	else
		*speed = TXGBE_LINK_SPEED_UNKNOWN;

	if (!adapter->link_valid) {
		*link_up = false;
		*speed = TXGBE_LINK_SPEED_UNKNOWN;
	}

	/* When fw control phy, check an_done after maclink in watchdog_is_up */
	if (test_bit(TXGBE_FLAG_FW_CONTROL_PHY, adapter->flag))
		return 0;

	if (!txgbe_xpcs_an_enabled(hw))
		return 0;

	if (!adapter->an_done) {
		*link_up = false;
		*speed = TXGBE_LINK_SPEED_UNKNOWN;
	}

	return 0;
}

static void txgbe_init_mac_link_ops_aml40(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;

	mac->ops.disable_tx_laser = txgbe_disable_tx_laser_multispeed_fiber;
	mac->ops.enable_tx_laser = txgbe_enable_tx_laser_multispeed_fiber;
	mac->ops.flap_tx_laser = txgbe_flap_tx_laser_multispeed_fiber;
}

static int txgbe_setup_sfp_modules_aml40(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type != txgbe_sfp_type_unknown) {
		txgbe_init_mac_link_ops_aml40(hw);
		return 0;
	}
	hw_dbg(hw, "unknown SFP type: %d\n", hw->phy.sfp_type);
	/* If SFP type is unknown, we cannot set up the link */
	return TXGBE_ERR_SFP_NOT_SUPPORTED;
}

/**
 *  txgbe_init_phy_ops_aml40 - PHY/SFP specific init
 *  @hw: pointer to hardware structure
 *
 *  Initialize any function pointers that were not able to be
 *  set during init_shared_code because the PHY/SFP type was
 *  not known.  Perform the SFP init if necessary.
 *
 **/
static int txgbe_init_phy_ops_aml40(struct txgbe_hw *hw)
{
	int ret_val = 0;

	txgbe_init_i2c(hw);
	wr32(hw, TXGBE_MAC_MDIO_CLAUSE_22_PORT,
	     TXGBE_MAC_MDIO_CLAUSE_ALL_PRTCL22);

	/* Identify the PHY or SFP module */
	ret_val = hw->phy.ops.identify(hw);
	if (ret_val == TXGBE_ERR_SFP_NOT_SUPPORTED)
		goto init_phy_ops_out;

	/* Setup function pointers based on detected SFP module and speeds */
	txgbe_init_mac_link_ops_aml40(hw);

init_phy_ops_out:
	return ret_val;
}

static const struct txgbe_mac_operations mac_ops_aml40 = {
	/* MAC */
	.init_hw		= &txgbe_init_hw,
	.reset_hw		= &txgbe_reset_hw_aml40,
	.start_hw		= &txgbe_start_hw,
	.clear_hw_cntrs		= &txgbe_clear_hw_cntrs,
	.get_media_type		= &txgbe_get_media_type_aml40,
	.get_mac_addr		= &txgbe_get_mac_addr,
	.stop_adapter		= &txgbe_stop_adapter,
	.get_bus_info		= &txgbe_get_bus_info,
	.set_lan_id		= &txgbe_set_lan_id_multi_port_pcie,
	.setup_sfp		= &txgbe_setup_sfp_modules_aml40,
	.enable_rx_dma		= &txgbe_enable_rx_dma,
	.disable_sec_rx_path	= &txgbe_disable_sec_rx_path,
	.enable_sec_rx_path	= &txgbe_enable_sec_rx_path,
	.disable_sec_tx_path	= &txgbe_disable_sec_tx_path,
	.enable_sec_tx_path	= &txgbe_enable_sec_tx_path,

	/* Link */
	.disable_tx_laser	= NULL,
	.enable_tx_laser	= NULL,
	.flap_tx_laser		= NULL,
	.setup_link		= &txgbe_setup_mac_link_aml40,
	.setup_mac_link		= NULL,
	.check_link		= &txgbe_check_mac_link_aml40,
	.get_link_capabilities	= &txgbe_get_link_capabilities_aml40,
	.set_rate_select_speed	= &txgbe_set_hard_rate_select_speed,

	/* Packet Buffer manipulation */
	.setup_rxpba		= &txgbe_set_rxpba,

	/* RAR, Multicast, VLAN */
	.set_rar		= &txgbe_set_rar,
	.clear_rar		= &txgbe_clear_rar,
	.set_vmdq_san_mac	= &txgbe_set_vmdq_san_mac,
	.init_rx_addrs		= &txgbe_init_rx_addrs,
	.update_mc_addr_list	= &txgbe_update_mc_addr_list,
	.clear_vfta		= &txgbe_clear_vfta,
	.set_vfta		= &txgbe_set_vfta,
	.init_uta_tables	= &txgbe_init_uta_tables,
	.set_vlan_anti_spoofing	= &txgbe_set_vlan_anti_spoofing,

	/* Flow Control */
	.fc_enable		= &txgbe_fc_enable,
	.setup_fc		= &txgbe_setup_fc,

	/* Manageability interface */
	.get_thermal_sensor_data	= &txgbe_get_thermal_sensor_data,
	.init_thermal_sensor_thresh	= &txgbe_init_thermal_sensor_thresh,
	.get_rtrup2tc		= &txgbe_dcb_get_rtrup2tc,
	.enable_rx		= &txgbe_enable_rx,
	.disable_rx		= &txgbe_disable_rx,
	.set_ethertype_anti_spoofing	= &txgbe_set_ethertype_anti_spoofing,
	.setup_eee		= &txgbe_setup_eee,
	.dmac_config		= NULL,
};

static const struct txgbe_phy_operations phy_ops_aml40 = {
	/* PHY */
	.identify		= &txgbe_identify_phy_generic,
	.identify_sfp		= &txgbe_identify_module_aml,
	.init			= &txgbe_init_phy_ops_aml40,
	.setup_link		= &txgbe_setup_phy_link,
	.setup_link_speed	= &txgbe_setup_phy_link_speed,
	.read_i2c_byte		= &txgbe_read_i2c_byte,
	.write_i2c_byte		= &txgbe_write_i2c_byte,
	.read_i2c_sff8472	= &txgbe_read_i2c_sff8472,
	.read_i2c_sff8636	= &txgbe_read_i2c_sff8636,
	.read_i2c_eeprom	= &txgbe_read_i2c_eeprom,
	.read_i2c_sfp_phy	= &txgbe_read_i2c_sfp_phy,
	.write_i2c_eeprom	= &txgbe_write_i2c_eeprom,
	.check_overtemp		= &txgbe_tn_check_overtemp,
};

static int txgbe_get_invariants_aml40(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	int ret;

	ret = txgbe_get_invariants_generic(hw);
	hw->mac.orig_link_settings_stored = false;

	adapter->desc_reserved = DESC_RESERVED_AML;
	adapter->link_valid = true;
	adapter->cur_fec_link = TXGBE_PHY_FEC_AUTO;

	hw->phy.curr_user_fec_req = TXGBE_PHY_FEC_AUTO;
	hw->phy.link_fec_options = TXGBE_PHY_FEC_10G_KR_40G_KR4_EN |
				   TXGBE_PHY_FEC_10G_KR_40G_KR4_REQ;

	return ret;
}

const struct txgbe_info txgbe_aml40_info = {
	.mac			= txgbe_mac_aml40,
	.get_invariants		= &txgbe_get_invariants_aml40,
	.mac_ops		= &mac_ops_aml40,
	.phy_ops		= &phy_ops_aml40,
};

