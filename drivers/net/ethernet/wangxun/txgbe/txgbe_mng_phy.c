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
	struct txgbe_hic_ephy_setlink set_buffer;

	set_buffer.hdr.cmd = FW_PHY_CONFIG_SET_LINK_CMD;
	set_buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_setlink) -
				 sizeof(struct txgbe_hic_hdr);
	set_buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	set_buffer.fec_mode = hw->phy.curr_user_fec_req;
	set_buffer.speed = speed;
	set_buffer.autoneg = autoneg;
	set_buffer.duplex = duplex;
	hw_info(hw, "[fw] Setting link speed to 0x%x, autoneg %s, fec 0x%x.\n",
		speed, autoneg ? "enabled" : "disabled", set_buffer.fec_mode);

	if (!SW_OEM_EPHY)
		goto send_cmd;

	hw_info(hw, "Applying SW_OEM to FW.\n");
	set_buffer.sw_oem.txeq_main = adapter->ffe_main;
	set_buffer.sw_oem.txeq_pre1 = adapter->ffe_pre1;
	set_buffer.sw_oem.txeq_pre2 = adapter->ffe_pre2;
	set_buffer.sw_oem.txeq_post = adapter->ffe_post;
	set_buffer.sw_oem.training_mode = KR_TRAINNING_MODE;
	set_buffer.sw_oem.linkfail_timeout = CL74_KRTR_TRAINNING_TIMEOUT;
	set_buffer.sw_oem.ctlebypass = CTLE_BYPASS ? 1 : 0;
	set_buffer.sw_oem_flag = EPHY_OEM_FROM_SW;

send_cmd:
	return txgbe_host_interface_command(hw, (u32 *)&set_buffer,
					    sizeof(struct txgbe_hic_ephy_setlink),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

int txgbe_test_phy_status_hostif(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	struct txgbe_hic_ephy_status get_buffer;
	int ret, i;

	get_buffer.hdr.cmd = FW_PHY_CONFIG_GET_LINK_CMD;
	get_buffer.hdr.buf_len = sizeof(struct txgbe_hic_ephy_status) -
				 sizeof(struct txgbe_hic_hdr);
	get_buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	ret = txgbe_host_interface_command(hw, (u32 *)&get_buffer,
					   sizeof(struct txgbe_hic_ephy_status),
					   TXGBE_HI_COMMAND_TIMEOUT_SHORT,
					   true);
	switch (ret) {
	case TXGBE_ERR_MNG_UNKNOWN_CMD:
	case 0:
		goto oem_check;
	case TXGBE_ERR_MNG_UNSUPPORT_SFP:
		e_dev_info("Unsupported SFP module.\n");
		fallthrough;
	default:
		e_dev_info("Failed to test link info, ret=%d\n", ret);
		return ret;
	}

oem_check:
	if (SW_CTRL_EPHY_FORCE)
		return -EINVAL;

	if (!((get_buffer.fw_oem_flag & U16_MAX) == EPHY_OEM_FROM_FW ||
	      (get_buffer.fw_oem_flag & U16_MAX) == EPHY_OEM_SW_OVERRIDE_FW))
		return ret;

	e_dev_info("[fw] Get OEM settings from firmware, oem_flag %x.\n",
		   get_buffer.fw_oem_flag);

	for (i = 0; i < sizeof(struct txgbe_hic_ephy_status) / sizeof(u32); i++)
		e_dev_info("[fw] OEM[%d]: %08x\n", i,
			   *((u32 *)&get_buffer + i));

	hw->phy.oem.sr_an_adv1 = get_buffer.oem.sr_an_adv1;
	hw->phy.oem.sr_an_adv2 = get_buffer.oem.sr_an_adv2;
	hw->phy.oem.sr_an_adv3 = get_buffer.oem.sr_an_adv3;
	hw->phy.oem.oem_auto = get_buffer.oem.oem_auto;
	hw->phy.oem.txeq_main = get_buffer.oem.txeq_main;
	hw->phy.oem.txeq_pre1 = get_buffer.oem.txeq_pre1;
	hw->phy.oem.txeq_pre2 = get_buffer.oem.txeq_pre2;
	hw->phy.oem.txeq_post = get_buffer.oem.txeq_post;
	hw->phy.oem.training_mode = get_buffer.oem.training_mode;
	hw->phy.oem.linkfail_timeout = get_buffer.oem.linkfail_timeout;
	hw->phy.oem.ctlebypass = get_buffer.oem.ctlebypass;
	hw->phy.oem_flag = get_buffer.fw_oem_flag;

	return 0;
}

static int txgbe_get_phy_status_hostif(struct txgbe_hw *hw,
				       struct txgbe_hic_ephy_status *buffer)
{
	buffer->hdr.cmd = FW_PHY_CONFIG_GET_LINK_CMD;
	buffer->hdr.buf_len = sizeof(struct txgbe_hic_ephy_status) -
			      sizeof(struct txgbe_hic_hdr);
	buffer->hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	return txgbe_host_interface_command(hw, (u32 *)buffer,
					    sizeof(struct txgbe_hic_ephy_status),
					    TXGBE_HI_COMMAND_TIMEOUT_SHORT, true);
}

int txgbe_get_link_info_mbx(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	struct txgbe_hic_ephy_status buffer;
	int ret;

	ret = txgbe_get_phy_status_hostif(hw, &buffer);
	if (ret) {
		hw_info(hw, "Failed to get link info, ret=%d\n", ret);
		return ret;
	}

	/* speed can read from mac, duplex can ignore */
	/* just printf autoneg and flow_ctl*/
	hw->bypass_ctle = buffer.bypassctle;
	adapter->cur_fec_link = buffer.fec_mode;
	adapter->an_done = buffer.an_done;

	return 0;
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

int txgbe_read_eeprom_i2c_hostif(struct txgbe_hw *hw,
				 struct txgbe_hic_i2c_read *buffer,
				 u32 length, u8 *data)
{
	u32 dword_len, offset, value, i;
	int ret;

	buffer->hdr.cmd = FW_READ_EEPROM_I2C_CMD;
	buffer->hdr.buf_len = sizeof(struct txgbe_hic_i2c_read) -
			      sizeof(struct txgbe_hic_hdr);
	buffer->hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	ret = txgbe_host_interface_command(hw, (u32 *)buffer,
					   sizeof(struct txgbe_hic_i2c_read),
					   TXGBE_HI_COMMAND_TIMEOUT_SHORT,
					   false);
	if (ret)
		return ret;

	/* buffer length offset to read return data */
	offset = sizeof(struct txgbe_hic_i2c_read) >> 2;
	dword_len = round_up(length, 4) >> 2;

	for (i = 0; i < dword_len; i++) {
		value = rd32a(hw, TXGBE_AML_MNG_MBOX_FW2SW, i + offset);
		le32_to_cpus(&value);

		memcpy(data, &value, 4);
		data += 4;
	}

	return 0;
}

/**
 *  txgbe_identify_sfp_module_aml - Identifies SFP modules
 *  @hw: pointer to hardware structure
 *
 *  Searches for and identifies the SFP module and assigns appropriate PHY type.
 **/
static int txgbe_identify_sfp_module_hostif(struct txgbe_hw *hw)
{
	enum txgbe_sfp_type stored_sfp_type = hw->phy.sfp_type;
	u8 identifier = 0, cable_tech = 0, cable_spec = 0;
	u8 comp_codes_10g = 0, comp_codes_25g = 0;
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

	/* comp_codes_1g and oui_bytes not use in this func */
	identifier = buffer.identifier;
	comp_codes_10g = buffer.com_10g_code;
	comp_codes_25g = buffer.com_25g_code;
	cable_spec = buffer.cable_spec;
	cable_tech = buffer.cable_tech;

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
	u8 identifier = 0, sff_opt1 = 0, transceiver_type = 0;
	int ret = 0, status = 0;
	struct txgbe_hic_get_sfp_info buffer;

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
	transceiver_type = buffer.transceiver_type;
	sff_opt1 = buffer.sff_opt1;

	if (ret)
		goto err_read_i2c_eeprom;

	if (identifier == TXGBE_SFF_IDENTIFIER_QSFP ||
	    identifier == TXGBE_SFF_IDENTIFIER_QSFP_PLUS ||
	    identifier == TXGBE_SFF_IDENTIFIER_QSFP28) {
		hw->phy.type = txgbe_phy_sfp_unknown;

		if (transceiver_type & TXGBE_SFF_ETHERNET_40G_CR4) {
			if (hw->bus.lan_id == 0)
				hw->phy.sfp_type = txgbe_qsfp_type_40g_cu_core0;
			else
				hw->phy.sfp_type = txgbe_qsfp_type_40g_cu_core1;
			hw->phy.fiber_suppport_speed =
						TXGBE_LINK_SPEED_40GB_FULL |
						TXGBE_LINK_SPEED_10GB_FULL;
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

		if (transceiver_type & TXGBE_SFF_ETHERNET_RSRVD) {
			if (sff_opt1 == TXGBE_SFF_ETHERNET_100G_CR4) {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type = txgbe_qsfp_type_40g_cu_core0;
				else
					hw->phy.sfp_type = txgbe_qsfp_type_40g_cu_core1;
				hw->phy.fiber_suppport_speed =
							TXGBE_LINK_SPEED_40GB_FULL |
							TXGBE_LINK_SPEED_25GB_FULL |
							TXGBE_LINK_SPEED_10GB_FULL;
			} else {
				if (hw->bus.lan_id == 0)
					hw->phy.sfp_type = txgbe_qsfp_type_40g_sr_core0;
				else
					hw->phy.sfp_type = txgbe_qsfp_type_40g_sr_core1;
			}
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
