// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_bp_base.h"
#include "txgbe_e56.h"
#include "txgbe_e56_bp.h"
#include "txgbe_phy.h"
#include "txgbe_mng_phy.h"

/**
 *  txgbe_reset_hw_aml - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
static int txgbe_reset_hw_aml(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	int ret;

	/* take driver control when do reset */
	txgbe_get_hw_control(adapter);

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
	txgbe_release_hw_control(adapter);
	return ret;
}

/**
 *  txgbe_get_media_type_aml - Get media type
 *  @hw: pointer to hardware structure
 *
 *  Returns the media type (fiber, copper, backplane)
 **/
static enum txgbe_media_type txgbe_get_media_type_aml(struct txgbe_hw *hw)
{
	u8 device_type = hw->subsystem_device_id & 0xF0;
	enum txgbe_media_type media_type;

	switch (device_type) {
	case TXGBE_ID_KR_KX_KX4:
		media_type = txgbe_media_type_backplane;
		break;
	case TXGBE_ID_SFP:
		media_type = txgbe_media_type_fiber;
		break;
	default:
		media_type = txgbe_media_type_unknown;
		break;
	}

	return media_type;
}

/**
 *  txgbe_setup_mac_link_aml - Set MAC link speed
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Set the link speed in the AUTOC register and restarts link.
 **/
static int txgbe_setup_mac_link_aml(struct txgbe_hw *hw,
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
		if (status) {
			hw_err(hw, "fw Set link failed %s %d\n",
			       __func__, __LINE__);
		}
		goto out;
	}

	if (txgbe_xpcs_an_enabled(hw)) {
		/* If XPCS_AN73 is enabled */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up && adapter->an_done)
			goto out;
		mutex_lock(&adapter->e56_lock);
		txgbe_e56_set_phylinkmode(adapter, 25, hw->bypass_ctle);
		mutex_unlock(&adapter->e56_lock);
		goto out;
	}

	if (txgbe_gpio_ext_check(hw, TXGBE_SFP1_MOD_ABS_LS |
				 TXGBE_SFP1_RX_LOS_LS))
		goto out;

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			break;
		msleep(250);
	}
	if (speed == TXGBE_LINK_SPEED_25GB_FULL)
		adapter->cur_fec_link = txgbe_get_cur_fec_mode(hw);

	if (link_speed == speed && link_up &&
	    !(speed == TXGBE_LINK_SPEED_25GB_FULL &&
			!(hw->phy.curr_user_fec_req & adapter->cur_fec_link)))
		goto out;

	if (speed == TXGBE_LINK_SPEED_25GB_FULL &&
	    link_speed == TXGBE_LINK_SPEED_25GB_FULL) {
		txgbe_e56_fec_mode_polling(hw, &link_up);

		if (link_up && !adapter->ffe_set)
			goto out;
	}

	mutex_lock(&adapter->e56_lock);
	ret_status = txgbe_set_link_to_amlite(hw, speed);
	mutex_unlock(&adapter->e56_lock);

	if (ret_status == TXGBE_ERR_PHY_INIT_NOT_DONE)
		goto out;

	if (ret_status == TXGBE_ERR_TIMEOUT) {
		adapter->link_valid = false;
		adapter->flags |= TXGBE_FLAG_NEED_LINK_CONFIG;
		goto out;
	} else {
		adapter->link_valid = true;
	}

	if (speed == TXGBE_LINK_SPEED_25GB_FULL &&
	    hw->phy.curr_user_fec_req == TXGBE_PHY_FEC_AUTO) {
		txgbe_e56_fec_mode_polling(hw, &link_up);
	} else {
		for (i = 0; i < 4; i++) {
			txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
			if (link_up)
				goto out;
			msleep(250);
		}
	}

out:
	return status;
}

/**
 *  txgbe_get_link_capabilities_aml - Determines link capabilities
 *  @hw: pointer to hardware structure
 *  @speed: pointer to link speed
 *  @autoneg: true when autoneg or autotry is enabled
 *
 *  Determines the link capabilities by reading the AUTOC register.
 **/
static int txgbe_get_link_capabilities_aml(struct txgbe_hw *hw, u32 *speed,
					 bool *autoneg)
{
	struct txgbe_adapter *adapter = hw->back;
	int status = 0;

	if (hw->phy.multispeed_fiber) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_25GB_FULL;
		*autoneg = true;
	} else if (hw->phy.sfp_type == txgbe_sfp_type_da_cu_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_da_cu_core1) {
		if (hw->phy.fiber_suppport_speed ==
		    TXGBE_LINK_SPEED_10GB_FULL) {
			adapter->backplane_an = false;
			*autoneg = false;
		} else {
			*autoneg = adapter->backplane_an;
		}
		*speed = hw->phy.fiber_suppport_speed;
	} else if (hw->phy.sfp_type == txgbe_sfp_type_25g_sr_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_sr_core1 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_lr_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_lr_core1 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_aoc_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_aoc_core1) {
		*speed = TXGBE_LINK_SPEED_25GB_FULL;
		*autoneg = false;
	} else if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_backplane) {
		/* Backplane */
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_25GB_FULL;
		/* Backplane supports autonegotiation */
		*autoneg = adapter->backplane_an;
	} else if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber) {
		/* Fiber */
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_25GB_FULL;
		*autoneg = false;
	} else {
		/* Unknown */
		status = TXGBE_ERR_LINK_SETUP;
		*speed = TXGBE_LINK_SPEED_UNKNOWN;
		*autoneg = false;
		e_dev_err("GET link capabilities failed\n");
	}

	return status;
}

static int txgbe_check_mac_link_aml(struct txgbe_hw *hw, u32 *speed,
				    bool *link_up, bool link_up_wait_to_complete)
{
	struct txgbe_adapter *adapter = hw->back;
	u32 links_reg = 0;
	u32 i;

	if (link_up_wait_to_complete) {
		for (i = 0; i < TXGBE_LINK_UP_TIME; i++) {
			links_reg = rd32(hw,
					 TXGBE_CFG_PORT_ST);
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

	if (hw->phy.sfp_type == txgbe_sfp_type_10g_cu_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_10g_cu_core1) {
		*link_up = hw->f2c_mod_status;

		if (*link_up)
			wr32(hw, TXGBE_CFG_LED_CTL, 0);
		else
			txgbe_led_off(hw, TXGBE_LED_LINK_UP | TXGBE_AMLITE_LED_LINK_25G |
				TXGBE_AMLITE_LED_LINK_10G | TXGBE_AMLITE_LED_LINK_ACTIVE);
	}

	if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_25G) ==
	    TXGBE_CFG_PORT_ST_AML_LINK_25G)
		*speed = TXGBE_LINK_SPEED_25GB_FULL;
	else if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_10G) ==
		 TXGBE_CFG_PORT_ST_AML_LINK_10G)
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
	else
		*speed = TXGBE_LINK_SPEED_UNKNOWN;

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

/**
 *  txgbe_setup_mac_link_multispeed_fiber_aml - Set MAC link speed
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Set the link speed in the MAC and/or PHY register and restarts link.
 **/
static int txgbe_setup_mac_link_multispeed_fiber_aml(struct txgbe_hw *hw,
						     u32 speed,
					  bool autoneg_wait_to_complete)
{
	u32 highest_link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	struct txgbe_adapter *adapter = hw->back;
	bool autoneg, link_up = false;
	u32 speedcnt = 0;
	int status = 0;

	/* Mask off requested but non-supported speeds */
	status = hw->mac.ops.get_link_capabilities(hw,
				&link_speed, &autoneg);
	if (status != 0)
		return status;

	speed &= link_speed;

	/* Try each speed one by one, highest priority first.  We do this in
	 * software because 10Gb fiber doesn't support speed autonegotiation.
	 */
	if (speed & TXGBE_LINK_SPEED_25GB_FULL) {
		speedcnt++;
		highest_link_speed = TXGBE_LINK_SPEED_25GB_FULL;

		/* If we already have link at this speed, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		adapter->cur_fec_link = txgbe_get_cur_fec_mode(hw);

		if (link_speed == TXGBE_LINK_SPEED_25GB_FULL && link_up &&
		    hw->phy.curr_user_fec_req & adapter->cur_fec_link)
			goto out;

		/* Allow module to change analog characteristics (10G->25G) */
		msec_delay(40);

		status = hw->mac.ops.setup_mac_link(hw,
				TXGBE_LINK_SPEED_25GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/*aml wait link in setup,no need to repeatly wait*/
		/* If we have link, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if (link_up)
			goto out;
	}

	if (speed & TXGBE_LINK_SPEED_10GB_FULL) {
		speedcnt++;
		if (highest_link_speed == TXGBE_LINK_SPEED_UNKNOWN)
			highest_link_speed = TXGBE_LINK_SPEED_10GB_FULL;

		/* If we already have link at this speed, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if (link_speed == TXGBE_LINK_SPEED_10GB_FULL && link_up)
			goto out;

		/* Allow module to change analog characteristics (25G->10G) */
		msec_delay(40);

		status = hw->mac.ops.setup_mac_link(hw,
				TXGBE_LINK_SPEED_10GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/*aml wait link in setup,no need to repeatly wait*/
		/* If we have link, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if (link_up) {
			int i = 0;

			for (; i < 10; i++) {
				int rdata = rd32(hw, 0x14404);

				if (rdata & 0x1) {
					adapter->flags &= ~TXGBE_FLAG_NEED_LINK_CONFIG;
					mutex_lock(&adapter->e56_lock);
					txgbe_wr32_ephy(hw,
							E56PHY_INTR_1_ADDR,
						E56PHY_INTR_1_IDLE_EXIT1);
					mutex_unlock(&adapter->e56_lock);
					goto out;
				}
				msleep(100);
			}
		}
	}

	/* We didn't get link.  Configure back to the highest speed we tried,
	 * (if there was more than one).  We call ourselves back with just the
	 * single highest speed that the user requested.
	 */
	if (speedcnt > 1)
		status = txgbe_setup_mac_link_multispeed_fiber_aml(hw,
								   highest_link_speed,
						      autoneg_wait_to_complete);

out:
	/* Set autoneg_advertised value based on input link speed */
	hw->phy.autoneg_advertised = 0;

	if (speed & TXGBE_LINK_SPEED_25GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_25GB_FULL;

	if (speed & TXGBE_LINK_SPEED_10GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_10GB_FULL;

	return status;
}

static void txgbe_init_mac_link_ops_aml(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;

	mac->ops.disable_tx_laser = txgbe_disable_tx_laser_multispeed_fiber;
	mac->ops.enable_tx_laser = txgbe_enable_tx_laser_multispeed_fiber;
	mac->ops.flap_tx_laser = txgbe_flap_tx_laser_multispeed_fiber;

	if (hw->phy.multispeed_fiber) {
		/* Set up dual speed SFP+ support */
		mac->ops.setup_link = txgbe_setup_mac_link_multispeed_fiber_aml;
		mac->ops.setup_mac_link = txgbe_setup_mac_link_aml;
		mac->ops.set_rate_select_speed = txgbe_set_hard_rate_select_speed;
	}
}

static int txgbe_setup_sfp_modules_aml(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type != txgbe_sfp_type_unknown) {
		txgbe_init_mac_link_ops_aml(hw);
		return 0;
	}
	hw_dbg(hw, "unknown SFP type: %d\n", hw->phy.sfp_type);
	/* If SFP type is unknown, we cannot set up the link */
	return TXGBE_ERR_SFP_NOT_SUPPORTED;
}

/**
 *  txgbe_init_phy_ops_aml - PHY/SFP specific init
 *  @hw: pointer to hardware structure
 *
 *  Initialize any function pointers that were not able to be
 *  set during init_shared_code because the PHY/SFP type was
 *  not known.  Perform the SFP init if necessary.
 *
 **/
static int txgbe_init_phy_ops_aml(struct txgbe_hw *hw)
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
	txgbe_init_mac_link_ops_aml(hw);

init_phy_ops_out:
	return ret_val;
}

static const struct txgbe_mac_operations mac_ops_aml = {
	/* MAC */
	.init_hw		= &txgbe_init_hw,
	.reset_hw		= &txgbe_reset_hw_aml,
	.start_hw		= &txgbe_start_hw,
	.clear_hw_cntrs		= &txgbe_clear_hw_cntrs,
	.get_media_type		= &txgbe_get_media_type_aml,
	.get_mac_addr		= &txgbe_get_mac_addr,
	.stop_adapter		= &txgbe_stop_adapter,
	.get_bus_info		= &txgbe_get_bus_info,
	.set_lan_id		= &txgbe_set_lan_id_multi_port_pcie,
	.setup_sfp		= &txgbe_setup_sfp_modules_aml,
	.enable_rx_dma		= &txgbe_enable_rx_dma,
	.disable_sec_rx_path	= &txgbe_disable_sec_rx_path,
	.enable_sec_rx_path	= &txgbe_enable_sec_rx_path,
	.disable_sec_tx_path	= &txgbe_disable_sec_tx_path,
	.enable_sec_tx_path	= &txgbe_enable_sec_tx_path,

	/* Link */
	.disable_tx_laser	= NULL,
	.enable_tx_laser	= NULL,
	.flap_tx_laser		= NULL,
	.setup_link		= &txgbe_setup_mac_link_aml,
	.setup_mac_link		= NULL,
	.check_link		= &txgbe_check_mac_link_aml,
	.get_link_capabilities	= &txgbe_get_link_capabilities_aml,
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

static const struct txgbe_phy_operations phy_ops_aml = {
	/* PHY */
	.identify		= &txgbe_identify_phy_generic,
	.identify_sfp		= &txgbe_identify_module_aml,
	.init			= &txgbe_init_phy_ops_aml,
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

static int txgbe_get_invariants_aml(struct txgbe_hw *hw)
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
				   TXGBE_PHY_FEC_10G_KR_40G_KR4_REQ |
				   TXGBE_PHY_FEC_25G_KR_REQ |
				   TXGBE_PHY_FEC_25G_RS_528_REQ |
				   TXGBE_PHY_FEC_25G_KR_CLAUSE74_EN |
				   TXGBE_PHY_FEC_25G_RS_CLAUSE91_EN;

	return ret;
}

const struct txgbe_info txgbe_aml_info = {
	.mac			= txgbe_mac_aml,
	.get_invariants		= &txgbe_get_invariants_aml,
	.mac_ops		= &mac_ops_aml,
	.phy_ops		= &phy_ops_aml,
};

