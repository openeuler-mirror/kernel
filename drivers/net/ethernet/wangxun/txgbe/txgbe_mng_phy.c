// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_bp_base.h"
#include "txgbe_e56.h"
#include "txgbe_e56_bp.h"
#include "txgbe_sp.h"
#include "txgbe_hw.h"
#include "txgbe_phy.h"
#include "txgbe_mng_phy.h"

#define TXGBE_DUPLEX_FULL             0x01
#define TXGBE_POWER_ON                0x01

/* AUTO: auto-negotiate/identify sfp module type, do not force the type */
#define AUTO 1

static int txgbe_get_module_info_hostif(struct txgbe_hw *hw,
					struct txgbe_hic_get_sfp_info *buffer)
{
	buffer->hdr.cmd = FW_READ_SFP_INFO_CMD;
	buffer->hdr.buf_len = sizeof(struct txgbe_hic_get_sfp_info) -
			      sizeof(struct txgbe_hic_hdr);
	buffer->hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	return txgbe_host_interface_command(hw, (u32 *)buffer,
					    sizeof(struct txgbe_hic_get_sfp_info),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

int txgbe_set_phy_link_hostif(struct txgbe_hw *hw, int speed, bool autoneg, u8 duplex)
{
	struct txgbe_adapter *adapter = hw->back;
	struct txgbe_hic_ephy_setlink buffer;

	buffer.hdr.cmd = FW_PHY_CONFIG_LINK_CMD;
	buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_setlink) -
			     sizeof(struct txgbe_hic_hdr);
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	buffer.fec_mode = adapter->fec_link_mode;
	buffer.speed = speed;
	buffer.autoneg = autoneg;
	buffer.duplex = duplex;

	return txgbe_host_interface_command(hw, (u32 *)&buffer,
					    sizeof(struct txgbe_hic_ephy_setlink),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

int txgbe_test_phy_status_hostif(struct txgbe_hw *hw)
{
	struct txgbe_hic_ephy_status buffer;

	buffer.hdr.cmd = FW_PHY_CONFIG_READ_CMD;
	buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_status) -
			     sizeof(struct txgbe_hic_hdr);
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	return txgbe_host_interface_command(hw, (u32 *)&buffer,
					    sizeof(struct txgbe_hic_ephy_status),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

int txgbe_get_phy_status_hostif(struct txgbe_hw *hw, struct txgbe_hic_ephy_status *buffer)
{
	buffer->hdr.cmd = FW_PHY_CONFIG_READ_CMD;
	buffer->hdr.buf_len = sizeof(struct txgbe_hic_ephy_status) -
			      sizeof(struct txgbe_hic_hdr);
	buffer->hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	return txgbe_host_interface_command(hw, (u32 *)buffer,
					    sizeof(struct txgbe_hic_ephy_status),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

int txgbe_get_cur_fec_mode_mbx(struct txgbe_hw *hw)
{
	struct txgbe_hic_ephy_status buffer;

	return txgbe_get_phy_status_hostif(hw, &buffer);
}

int txgbe_set_phy_fc_hostif(struct txgbe_hw *hw, u8 fc)
{
	struct txgbe_hic_ephy_fc buffer;

	buffer.hdr.cmd = FW_PHY_CONFIG_FC_CMD;
	buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_fc) -
			     sizeof(struct txgbe_hic_hdr);
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	buffer.flow_ctl = fc;

	return txgbe_host_interface_command(hw, (u32 *)&buffer,
					    sizeof(buffer),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT,
					    false);
}

int txgbe_set_phy_power_hostif(struct txgbe_hw *hw, u8 power)
{
	struct txgbe_hic_ephy_power buffer;

	buffer.hdr.cmd = FW_PHY_CONFIG_POWER_CMD;
	buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_power) -
			     sizeof(struct txgbe_hic_hdr);
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	buffer.power = power;

	return txgbe_host_interface_command(hw, (u32 *)&buffer,
					    sizeof(buffer),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, false);
}

int txgbe_phy_reset_hostif(struct txgbe_hw *hw)
{
	struct txgbe_hic_ephy_power buffer;

	buffer.hdr.cmd = FW_PHY_CONFIG_RESET_CMD;
	buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_power) -
			     sizeof(struct txgbe_hic_hdr);
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	return txgbe_host_interface_command(hw, (u32 *)&buffer,
					    sizeof(buffer),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

/**
 *  txgbe_identify_sfp_module_aml - Identifies SFP modules
 *  @hw: pointer to hardware structure
 *
 *  Searches for and identifies the SFP module and assigns appropriate PHY type.
 **/
static int txgbe_identify_sfp_module_hostif(struct txgbe_hw *hw)
{
	u8 identifier = 0, cable_tech = 0, cable_spec = 0, oui_bytes[3] = {0};
	u8 comp_codes_1g = 0, comp_codes_10g = 0, comp_codes_25g = 0;
	enum txgbe_sfp_type stored_sfp_type = hw->phy.sfp_type;
	int ret = 0, status = 0;
	struct txgbe_hic_get_sfp_info buffer;

	/* if SFP module is not present just skip read */
	if (txgbe_gpio_ext_check(hw, TXGBE_SFP1_MOD_ABS_LS)) {
		hw->phy.sfp_type = txgbe_sfp_type_not_present;
		goto out;
	}

	if (hw->mac.ops.get_media_type(hw) != txgbe_media_type_fiber) {
		hw->phy.sfp_type = txgbe_sfp_type_not_present;
		status = TXGBE_ERR_SFP_NOT_PRESENT;
		goto out;
	}

	ret = txgbe_get_module_info_hostif(hw, &buffer);
	if (ret) {
		hw_info(hw, " %s %d ret : %d\n", __func__, __LINE__, ret);
		status = TXGBE_ERR_SFP_NOT_PRESENT;
		goto out;
	}

	identifier = buffer.identifier;
	comp_codes_1g = buffer.com_1g_code;
	comp_codes_10g = buffer.com_10g_code;
	comp_codes_25g = buffer.com_25g_code;
	cable_spec = buffer.cable_spec;
	cable_tech = buffer.cable_tech;
	oui_bytes[0] = buffer.vendor_oui0;
	oui_bytes[1] = buffer.vendor_oui1;
	oui_bytes[2] = buffer.vendor_oui2;

	if (ret)
		goto err_read_i2c_eeprom;

	if (identifier != TXGBE_SFF_IDENTIFIER_SFP) {
		hw->phy.type = txgbe_phy_sfp_unsupported;
		status = TXGBE_ERR_SFP_NOT_SUPPORTED;
	} else {
		 /* ID Module
		  * =========
		  * 0   SFP_DA_CU
		  * 1   SFP_SR
		  * 2   SFP_LR
		  * 3   SFP_DA_CORE0
		  * 4   SFP_DA_CORE1
		  * 5   SFP_SR/LR_CORE0
		  * 6   SFP_SR/LR_CORE1
		  * 7   SFP_act_lmt_DA_CORE0
		  * 8   SFP_act_lmt_DA_CORE1
		  * 9   SFP_1g_cu_CORE0
		  * 10  SFP_1g_cu_CORE1
		  * 11  SFP_1g_sx_CORE0
		  * 12  SFP_1g_sx_CORE1
		  */
		{
			if (cable_tech & TXGBE_SFF_DA_PASSIVE_CABLE) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type =
						     txgbe_sfp_type_da_cu_core0;
				else
					hw->phy.sfp_type =
						     txgbe_sfp_type_da_cu_core1;

				if (comp_codes_25g == TXGBE_SFF_25GBASECR_91FEC ||
				    comp_codes_25g == TXGBE_SFF_25GBASECR_74FEC ||
				    comp_codes_25g == TXGBE_SFF_25GBASECR_NOFEC) {
					hw->phy.fiber_suppport_speed =
						TXGBE_LINK_SPEED_25GB_FULL |
						TXGBE_LINK_SPEED_10GB_FULL;
				} else {
					hw->phy.fiber_suppport_speed |=
						TXGBE_LINK_SPEED_10GB_FULL;
				}
				if (!AUTO) {
					if (hw->bus.lan_id == 0)
						hw->phy.sfp_type = txgbe_sfp_type_25g_sr_core0;
					else
						hw->phy.sfp_type = txgbe_sfp_type_25g_sr_core1;
				}

			} else if (cable_tech & TXGBE_SFF_DA_ACTIVE_CABLE) {
				if (cable_spec &
				    TXGBE_SFF_DA_SPEC_ACTIVE_LIMITING) {
					if (hw->bus.lan_id == 0)
						hw->phy.sfp_type =
								txgbe_sfp_type_da_act_lmt_core0;
					else
						hw->phy.sfp_type =
						txgbe_sfp_type_da_act_lmt_core1;
				} else {
					hw->phy.sfp_type = txgbe_sfp_type_unknown;
				}

				if (comp_codes_25g == TXGBE_SFF_25GAUI_C2M_AOC_BER_5 ||
					comp_codes_25g == TXGBE_SFF_25GAUI_C2M_ACC_BER_5 ||
					comp_codes_25g == TXGBE_SFF_25GAUI_C2M_AOC_BER_12 ||
					comp_codes_25g == TXGBE_SFF_25GAUI_C2M_ACC_BER_12) {
					if (hw->bus.lan_id == 0)
						hw->phy.sfp_type =
						txgbe_sfp_type_25g_aoc_core0;
					else
						hw->phy.sfp_type =
						txgbe_sfp_type_25g_aoc_core1;
				}
			} else if (comp_codes_25g == TXGBE_SFF_25GAUI_C2M_AOC_BER_5 ||
					comp_codes_25g == TXGBE_SFF_25GAUI_C2M_ACC_BER_5 ||
					comp_codes_25g == TXGBE_SFF_25GAUI_C2M_AOC_BER_12 ||
					comp_codes_25g == TXGBE_SFF_25GAUI_C2M_ACC_BER_12) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type = txgbe_sfp_type_25g_aoc_core0;
				else
					hw->phy.sfp_type = txgbe_sfp_type_25g_aoc_core1;
			} else if (comp_codes_25g == TXGBE_SFF_25GBASESR_CAPABLE ||
					comp_codes_25g == TXGBE_SFF_25GBASEER_CAPABLE) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type = txgbe_sfp_type_25g_sr_core0;
				else
					hw->phy.sfp_type = txgbe_sfp_type_25g_sr_core1;
			} else if (comp_codes_25g == TXGBE_SFF_25GBASELR_CAPABLE) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type = txgbe_sfp_type_25g_lr_core0;
				else
					hw->phy.sfp_type = txgbe_sfp_type_25g_lr_core1;
			} else if (comp_codes_10g &
				   (TXGBE_SFF_10GBASESR_CAPABLE |
				    TXGBE_SFF_10GBASELR_CAPABLE)) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type =
						      txgbe_sfp_type_srlr_core0;
				else
					hw->phy.sfp_type =
						      txgbe_sfp_type_srlr_core1;
			} else {
				hw->phy.sfp_type = txgbe_sfp_type_unknown;
			}
		}

		if (hw->phy.sfp_type != stored_sfp_type)
			hw->phy.sfp_setup_needed = true;

		/* Determine if the SFP+ PHY is dual speed or not. */
		hw->phy.multispeed_fiber = false;
		if ((comp_codes_25g == TXGBE_SFF_25GBASESR_CAPABLE ||
			comp_codes_25g == TXGBE_SFF_25GBASELR_CAPABLE ||
			comp_codes_25g == TXGBE_SFF_25GBASEER_CAPABLE) &&
			((comp_codes_10g & TXGBE_SFF_10GBASESR_CAPABLE) ||
			(comp_codes_10g & TXGBE_SFF_10GBASELR_CAPABLE)))
			hw->phy.multispeed_fiber = true;
	}

out:
	return status;

err_read_i2c_eeprom:
	hw->phy.sfp_type = txgbe_sfp_type_not_present;
	hw->phy.id = 0;
	hw->phy.type = txgbe_phy_unknown;
	return TXGBE_ERR_SFP_NOT_PRESENT;
}

/**
 *  txgbe_identify_sfp_module_aml - Identifies SFP modules
 *  @hw: pointer to hardware structure
 *
 *  Searches for and identifies the SFP module and assigns appropriate PHY type.
 **/
static int txgbe_identify_qsfp_module_hostif(struct txgbe_hw *hw)
{
	u8 identifier = 0, comp_codes_1g = 0, comp_codes_10g = 0;
	u8 comp_codes_25g = 0, cable_tech = 0, cable_spec = 0;
	int ret = 0, status = 0;
	struct txgbe_hic_get_sfp_info buffer;
	u8 transceiver_type = 0;

	/* if QSFP module is not present just skip read */
	if (txgbe_gpio_ext_check(hw, TXGBE_SFP1_MOD_PRST_LS)) {
		hw->phy.sfp_type = txgbe_sfp_type_not_present;
		goto out;
	}

	if (hw->mac.ops.get_media_type(hw) != txgbe_media_type_fiber_qsfp) {
		hw->phy.sfp_type = txgbe_sfp_type_not_present;
		status = TXGBE_ERR_SFP_NOT_PRESENT;
		goto out;
	}

	/* Read the QSFP EEPROM */
	ret = txgbe_get_module_info_hostif(hw, &buffer);
	if (ret) {
		hw_info(hw, " %s %d ret : %d\n", __func__, __LINE__, ret);
		status = TXGBE_ERR_SFP_NOT_PRESENT;
		goto out;
	}

	identifier = buffer.identifier;
	comp_codes_1g = buffer.com_1g_code;
	comp_codes_10g = buffer.com_10g_code;
	comp_codes_25g = buffer.com_25g_code;
	cable_spec = buffer.cable_spec;
	cable_tech = buffer.cable_tech;
	transceiver_type = buffer.transceiver_type;

	if (ret)
		goto err_read_i2c_eeprom;

	if (identifier == TXGBE_SFF_IDENTIFIER_QSFP ||
		identifier == TXGBE_SFF_IDENTIFIER_QSFP_PLUS) {
		hw->phy.type = txgbe_phy_sfp_unknown;

		if (transceiver_type & TXGBE_SFF_ETHERNET_40G_CR4) {
			if (hw->bus.lan_id == 0)
				hw->phy.sfp_type = txgbe_qsfp_type_40g_cu_core0;
			else
				hw->phy.sfp_type = txgbe_qsfp_type_40g_cu_core1;
			hw->phy.fiber_suppport_speed =
						TXGBE_LINK_SPEED_40GB_FULL |
						TXGBE_LINK_SPEED_10GB_FULL;

			if (!AUTO) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type = txgbe_qsfp_type_40g_sr_core0;
				else
					hw->phy.sfp_type = txgbe_qsfp_type_40g_sr_core1;
			}
		}

		if (transceiver_type & TXGBE_SFF_ETHERNET_40G_SR4) {
			if (hw->bus.lan_id == 0)
				hw->phy.sfp_type = txgbe_qsfp_type_40g_sr_core0;
			else
				hw->phy.sfp_type = txgbe_qsfp_type_40g_sr_core1;
		}

		if (transceiver_type & TXGBE_SFF_ETHERNET_40G_LR4) {
			if (hw->bus.lan_id == 0)
				hw->phy.sfp_type = txgbe_qsfp_type_40g_lr_core0;
			else
				hw->phy.sfp_type = txgbe_qsfp_type_40g_lr_core1;
		}

		if (transceiver_type & TXGBE_SFF_ETHERNET_40G_ACTIVE) {
			if (hw->bus.lan_id == 0)
				hw->phy.sfp_type = txgbe_qsfp_type_40g_active_core0;
			else
				hw->phy.sfp_type = txgbe_qsfp_type_40g_active_core1;
		}
	} else {
		hw->phy.type = txgbe_phy_sfp_unsupported;
		status = TXGBE_ERR_SFP_NOT_SUPPORTED;
	}

out:
	return status;

err_read_i2c_eeprom:

	hw->phy.sfp_type = txgbe_sfp_type_not_present;
	hw->phy.id = 0;
	hw->phy.type = txgbe_phy_unknown;
	return TXGBE_ERR_SFP_NOT_PRESENT;
}

int txgbe_identify_module_aml(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	int status = TXGBE_ERR_SFP_NOT_PRESENT;

	if (!test_bit(TXGBE_FLAG_FW_CONTROL_PHY, adapter->flag))
		return txgbe_identify_module(hw);

	switch (hw->mac.ops.get_media_type(hw)) {
	case txgbe_media_type_fiber_qsfp:
		status = txgbe_identify_qsfp_module_hostif(hw);
		break;
	case txgbe_media_type_fiber:
		status = txgbe_identify_sfp_module_hostif(hw);
		break;
	default:
		hw->phy.sfp_type = txgbe_sfp_type_not_present;
		break;
	}

	return status;
}
