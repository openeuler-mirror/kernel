// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_bp_base.h"

u32 rd32_ephy(struct txgbe_hw *hw, u32 addr)
{
	unsigned int port_reg_offset;
	u32 data;

	/* Set the LAN port indicator to port_reg_offset[1] */
	/* 1st, write the regOffset to IDA_ADDR register */
	port_reg_offset = TXGBE_ETHPHY_IDA_ADDR;
	wr32(hw, port_reg_offset, addr);

	/* 2nd, read the data from IDA_DATA register */
	port_reg_offset = TXGBE_ETHPHY_IDA_DATA;
	data = rd32(hw, port_reg_offset);
	return data;
}

u32 txgbe_rd32_epcs(struct txgbe_hw *hw, u32 addr)
{
	unsigned int port_reg_offset;
	u32 data;
	/* Set the LAN port indicator to port_reg_offset[1] */
	/* 1st, write the regOffset to IDA_ADDR register */
	port_reg_offset = TXGBE_XPCS_IDA_ADDR;
	wr32(hw, port_reg_offset, addr);

	/* 2nd, read the data from IDA_DATA register */
	port_reg_offset = TXGBE_XPCS_IDA_DATA;
	data = rd32(hw, port_reg_offset);

	return data;
}

void txgbe_wr32_ephy(struct txgbe_hw *hw, u32 addr, u32 data)
{
	unsigned int port_reg_offset;

	/* Set the LAN port indicator to port_reg_offset[1] */
	/* 1st, write the regOffset to IDA_ADDR register */
	port_reg_offset = TXGBE_ETHPHY_IDA_ADDR;
	wr32(hw, port_reg_offset, addr);

	/* 2nd, read the data from IDA_DATA register */
	port_reg_offset = TXGBE_ETHPHY_IDA_DATA;
	wr32(hw, port_reg_offset, data);
}

void txgbe_wr32_epcs(struct txgbe_hw *hw, u32 addr, u32 data)
{
	unsigned int port_reg_offset;

	/* Set the LAN port indicator to port_reg_offset[1] */
	/* 1st, write the regOffset to IDA_ADDR register */
	port_reg_offset = TXGBE_XPCS_IDA_ADDR;
	wr32(hw, port_reg_offset, addr);

	/* 2nd, read the data from IDA_DATA register */
	port_reg_offset = TXGBE_XPCS_IDA_DATA;
	wr32(hw, port_reg_offset, data);
}

void txgbe_field_set(u32 *psrcdata, u32 bithigh, u32 bitlow, u32 setvalue)
{
	*psrcdata &= ~GENMASK(bithigh, bitlow);
#if defined(CONFIG_ARM) || defined(CONFIG_RISCV)
	/* The mask is a runtime value here, so __bf_shf_m() expands to a real
	 * __builtin_ffsll() call.  GCC lowers that to a call to __ffsdi2 on
	 * architectures without a native ffsdi2 (arm, riscv), and the kernel
	 * does not provide that symbol, so compute the shift from bitlow
	 * directly instead.
	 */
	*psrcdata |= (setvalue << bitlow) & GENMASK(bithigh, bitlow);
#else
	*psrcdata |= FIELD_PREP_M(GENMASK(bithigh, bitlow), setvalue);
#endif
}

int txgbe_is_dac_cable(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type == txgbe_sfp_type_da_cu_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_da_cu_core1 ||
	    hw->phy.sfp_type == txgbe_sfp_type_da_act_lmt_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_da_act_lmt_core1 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_cu_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_cu_core1)
		return true;

	return false;
}

int txgbe_xpcs_an_enabled(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;

	if (!(txgbe_is_dac_cable(hw) || txgbe_is_backplane(hw)))
		return false;

	return adapter->backplane_an ? true : false;
}

void txgbe_bp_mode_setting(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;

	/* default to open an73 */
	if ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_KR_KX_KX4)
		adapter->backplane_an = 1;

	switch (hw->mac.type) {
	case txgbe_mac_sp:
		adapter->backplane_an = 0;
		break;
	case txgbe_mac_aml40:
	case txgbe_mac_aml:
	default:
		hw->bypass_ctle = CTLE_BYPASS ? 1 : 0;
		adapter->backplane_an = AUTO ? 1 : 0;

		/* OEM init */
		/* SR AN ADV do not use latter, so can be ignored */
		hw->phy.oem.sr_an_adv1 = 0;
		hw->phy.oem.sr_an_adv2 = 0;
		hw->phy.oem.sr_an_adv3 = 0;

		hw->phy.oem.oem_auto = adapter->backplane_an;

		/* tx_eq do not use latter, so can be ignored */
		hw->phy.oem.txeq_main = 0;
		hw->phy.oem.txeq_pre1 = 0;
		hw->phy.oem.txeq_pre2 = 0;
		hw->phy.oem.txeq_post = 0;

		hw->phy.oem.training_mode = KR_TRAINNING_MODE;
		hw->phy.oem.linkfail_timeout = CL74_KRTR_TRAINNING_TIMEOUT;
		hw->phy.oem.ctlebypass = hw->bypass_ctle;
		hw->phy.oem_flag = EPHY_OEM_NONE;
		break;
	}

	adapter->autoneg = 1;
	switch (adapter->backplane_mode) {
	case TXGBE_BP_M_KR:
		hw->subsystem_device_id = TXGBE_ID_WX1820_KR_KX_KX4;
		break;
	case TXGBE_BP_M_KX4:
		hw->subsystem_device_id = TXGBE_ID_WX1820_MAC_XAUI;
		break;
	case TXGBE_BP_M_KX:
		hw->subsystem_device_id = TXGBE_ID_WX1820_MAC_SGMII;
		break;
	case TXGBE_BP_M_SFI:
		hw->subsystem_device_id = TXGBE_ID_WX1820_SFP;
		break;
	default:
		break;
	}

	switch (hw->subsystem_device_id & TXGBE_DEV_MASK) {
	case TXGBE_ID_KR_KX_KX4:
		adapter->backplane_mode = TXGBE_BP_M_KR;
		break;
	case TXGBE_ID_MAC_XAUI:
		adapter->backplane_mode = TXGBE_BP_M_KX4;
		break;
	case TXGBE_ID_MAC_SGMII:
		adapter->backplane_mode = TXGBE_BP_M_KX;
		break;
	case TXGBE_ID_SFP:
		adapter->backplane_mode = TXGBE_BP_M_SFI;
		break;
	default:
		break;
	}

	if (adapter->backplane_auto == TXGBE_BP_M_AUTO) {
		adapter->backplane_an = 1;
		adapter->autoneg = 1;
	} else if (adapter->backplane_auto == TXGBE_BP_M_NAUTO) {
		adapter->backplane_an = 0;
		adapter->autoneg = 0;
	}

	if (hw->mac.type == txgbe_mac_aml40 ||
	    hw->mac.type == txgbe_mac_aml) {
		if (adapter->ffe_set)
			return;
		adapter->ffe_main = S25G_TX_FFE_CFG_DAC_MAIN;
		adapter->ffe_pre1 = S25G_TX_FFE_CFG_DAC_PRE1;
		adapter->ffe_pre2 = S25G_TX_FFE_CFG_DAC_PRE2;
		adapter->ffe_post = S25G_TX_FFE_CFG_DAC_POST;
	} else {
		if (!adapter->ffe_set && !KR_SET && !KX4_SET && !KX_SET && !SFI_SET)
			return;
	}

	if (KR_SET &&
	    ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_KR_KX_KX4)) {
		adapter->ffe_main = KR_MAIN;
		adapter->ffe_pre1 = KR_PRE;
		adapter->ffe_post = KR_POST;
		adapter->ffe_set = TXGBE_BP_M_KR;
	}
	if (KX4_SET &&
	    ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_MAC_XAUI)) {
		adapter->ffe_main = KX4_MAIN;
		adapter->ffe_pre1 = KX4_PRE;
		adapter->ffe_post = KX4_POST;
	}
	if (KX_SET &&
	    ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_MAC_SGMII)) {
		adapter->ffe_main = KX_MAIN;
		adapter->ffe_pre1 = KX_PRE;
		adapter->ffe_post = KX_POST;
	}
	if (SFI_SET &&
	    ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_SFP)) {
		adapter->ffe_main = SFI_MAIN;
		adapter->ffe_pre1 = SFI_PRE;
		adapter->ffe_post = SFI_POST;
		adapter->ffe_set = TXGBE_BP_M_SFI;
	}
}

void txgbe_xpcs_txffe_set(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 value;

	if (hw->mac.type != txgbe_mac_sp)
		return;

	if (!adapter->ffe_set && !KR_SET && !KX4_SET && !KX_SET && !SFI_SET)
		return;

	if (adapter->ffe_set != adapter->backplane_mode) {
		hw_info(hw, "FFE set mode %d does not match backplane mode %d\n",
			adapter->ffe_set, adapter->backplane_mode);
		return;
	}

	value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_EQ_CTL0);
	value = (value & ~0x3F3F) |
		(adapter->ffe_main << 8) | adapter->ffe_pre1;
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_EQ_CTL0, value);

	value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_EQ_CTL1);
	value = (value & ~0x7F) | adapter->ffe_post | BIT(6);
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_EQ_CTL1, value);

	hw_info(hw, "Set BAKPLANE_MODE: %d TX_EQ MAIN:%d PRE:%d POST:%d\n",
		adapter->ffe_set,
		adapter->ffe_main, adapter->ffe_pre1, adapter->ffe_post);
}

void txgbe_xlgpcs_txffe_set(struct txgbe_adapter *adapter, u32 speed)
{
	u32 ffe_main = 0, ffe_pre1 = 0, ffe_pre2 = 0, ffe_post = 0;
	struct txgbe_hw *hw = &adapter->hw;

	if (hw->mac.type != txgbe_mac_aml40 &&
	    hw->mac.type != txgbe_mac_aml)
		return;

	if (speed == TXGBE_LINK_SPEED_10GB_FULL ||
	    speed == TXGBE_LINK_SPEED_40GB_FULL) {
		ffe_main = S10G_TX_FFE_CFG_MAIN;
		ffe_pre1 = S10G_TX_FFE_CFG_PRE1;
		ffe_pre2 = S10G_TX_FFE_CFG_PRE2;
		ffe_post = S10G_TX_FFE_CFG_POST;
	} else if (speed == TXGBE_LINK_SPEED_25GB_FULL) {
		ffe_main = S25G_TX_FFE_CFG_MAIN;
		ffe_pre1 = S25G_TX_FFE_CFG_PRE1;
		ffe_pre2 = S25G_TX_FFE_CFG_PRE2;
		ffe_post = S25G_TX_FFE_CFG_POST;
	} else {
		hw_err(hw, "Unsupported speed for TX FFE setting: %d\n", speed);
		return;
	}

	if (txgbe_is_dac_cable(hw) || txgbe_is_backplane(hw)) {
		ffe_main = 0x2b2b2b2b;
		ffe_pre1 = 0x03030303;
		ffe_pre2 = 0;
		ffe_post = 0x11111111;
	}

	if (hw->phy.oem_flag == EPHY_OEM_FROM_FW ||
	    hw->phy.oem_flag == EPHY_OEM_SW_OVERRIDE_FW) {
		ffe_main = hw->phy.oem.txeq_main;
		ffe_pre1 = hw->phy.oem.txeq_pre1;
		ffe_pre2 = hw->phy.oem.txeq_pre2;
		ffe_post = hw->phy.oem.txeq_post;
	}

	if (!adapter->ffe_set && !KR_SET && !SFI_SET)
		goto ffe_set;

	if (adapter->ffe_set != adapter->backplane_mode) {
		hw_info(hw, "FFE set mode %d does not match backplane mode %d\n",
			adapter->ffe_set, adapter->backplane_mode);
		goto ffe_set;
	}

	ffe_main = adapter->ffe_main;
	ffe_pre1 = adapter->ffe_pre1;
	ffe_pre2 = adapter->ffe_pre2;
	ffe_post = adapter->ffe_post;
	hw_info(hw, "Set BAKPLANE_MODE: %d TX_EQ MAIN:%x PRE1:%x PRE2:%x POST:%x\n",
		adapter->ffe_set,
		ffe_main, ffe_pre1, ffe_pre2, ffe_post);
ffe_set:
	txgbe_wr32_epcs(hw, 0x141c, ffe_main);
	txgbe_wr32_epcs(hw, 0x1420, ffe_pre1);
	txgbe_wr32_epcs(hw, 0x1424, ffe_pre2);
	txgbe_wr32_epcs(hw, 0x1428, ffe_post);

}

int txgbe_chk_bkp_ability(struct txgbe_adapter *adapter,
			  struct bkpan73ability bkp_an73_ability,
			  struct bkpan73ability lpbkp_an73_ability)
{
	unsigned int com_link_ability;

	kr_dbg(KR_MODE, "CheckBkpAn73Ability():\n");
	/* Check the common link ability and take action based on the result */
	com_link_ability = bkp_an73_ability.link_ability &
			   lpbkp_an73_ability.link_ability;
	kr_dbg(KR_MODE, "comAbility= 0x%x, Ability= 0x%x, lpAbility= 0x%x\n",
	       com_link_ability, bkp_an73_ability.link_ability,
	       lpbkp_an73_ability.link_ability);

	if (com_link_ability == 0) {
		adapter->bp_link_mode = 0;
		kr_dbg(KR_MODE, "Do not support any compatible speed mode!\n");
		return -EINVAL;
	} else if (com_link_ability & BIT(ABILITY_40GBASE_KR4)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_40GBASE_KR4].\n");
		adapter->bp_link_mode = 40;
	} else if (com_link_ability & BIT(ABILITY_40GBASE_CR4)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_40GBASE_CR4].\n");
		adapter->bp_link_mode = 40;
	} else if (com_link_ability & BIT(ABILITY_25GBASE_KRCR_S)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_25GBASE_KRCR_S].\n");
		adapter->fec_mode = TXGBE_25G_RS_FEC_REQ;
		adapter->bp_link_mode = 25;
	} else if (com_link_ability & BIT(ABILITY_25GBASE_KRCR)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_25GBASE_KRCR].\n");
		adapter->bp_link_mode = 25;
	} else if (com_link_ability & BIT(ABILITY_10GBASE_KR)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_10GBASE_KR].\n");
		adapter->bp_link_mode = 10;
	} else if (com_link_ability & BIT(ABILITY_10GBASE_KX4)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_10GBASE_KX4].\n");
		adapter->bp_link_mode = 10;
	} else if (com_link_ability & BIT(ABILITY_1000BASE_KX)) {
		kr_dbg(KR_MODE, "Link mode is [ABILITY_1000BASE_KX].\n");
		adapter->bp_link_mode = 1;
	} else {
		kr_dbg(KR_MODE, "Unknown link mode!\n");
		return -EINVAL;
	}

	return 0;
}
