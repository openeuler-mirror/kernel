// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_bp_base.h"

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
		adapter->backplane_an = 1;
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

	if (adapter->backplane_auto == TXGBE_BP_M_AUTO) {
		adapter->backplane_an = 1;
		adapter->autoneg = 1;
	} else if (adapter->backplane_auto == TXGBE_BP_M_NAUTO) {
		adapter->backplane_an = 0;
		adapter->autoneg = 0;
	}
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
