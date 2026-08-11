// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */
#include "txgbe_bp_base.h"
#include "txgbe_phy.h"
#include "txgbe_sp.h"

/**
 *  txgbe_reset_hw_sp - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
static int txgbe_reset_hw_sp(struct txgbe_hw *hw)
{
	u32 sr_an_mmd_ctl, sr_an_mmd_adv_reg2, sr_pcs_ctl, sr_pma_mmd_ctl1;
	u32 curr_sr_an_mmd_ctl, curr_sr_an_mmd_adv_reg2;
	u32 curr_sr_pcs_ctl, curr_sr_pma_mmd_ctl1;
	struct txgbe_adapter *adapter = hw->back;
	u32 curr_vr_xs_or_pcs_mmd_digi_ctl1;
	u32 vr_xs_or_pcs_mmd_digi_ctl1;
	int ret;

	/* remember internal phy regs from before we reset */
	curr_sr_pcs_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_PCS_CTL2);
	curr_sr_pma_mmd_ctl1 = txgbe_rd32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1);
	curr_sr_an_mmd_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_CTL);
	curr_sr_an_mmd_adv_reg2 = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_ADV_REG2);
	curr_vr_xs_or_pcs_mmd_digi_ctl1 =
			txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1);

	ret = txgbe_reset_hw_generic(hw);
	if (ret)
		return ret;

	adapter->an_done = false;
	/* Store the original AUTOC/AUTOC2 values if they have not been
	 * stored off yet.  Otherwise restore the stored original
	 * values since the reset operation sets back to defaults.
	 */
	sr_pcs_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_PCS_CTL2);
	sr_pma_mmd_ctl1 = txgbe_rd32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1);
	sr_an_mmd_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_CTL);
	sr_an_mmd_adv_reg2 = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_ADV_REG2);
	vr_xs_or_pcs_mmd_digi_ctl1 =
			txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1);

	if (!hw->mac.orig_link_settings_stored) {
		hw->mac.orig_sr_pcs_ctl2 = sr_pcs_ctl;
		hw->mac.orig_sr_pma_mmd_ctl1 = sr_pma_mmd_ctl1;
		hw->mac.orig_sr_an_mmd_ctl = sr_an_mmd_ctl;
		hw->mac.orig_sr_an_mmd_adv_reg2 = sr_an_mmd_adv_reg2;
		hw->mac.orig_vr_xs_or_pcs_mmd_digi_ctl1 =
						vr_xs_or_pcs_mmd_digi_ctl1;
		hw->mac.orig_link_settings_stored = true;
	} else {
		/* If MNG FW is running on a multi-speed device that
		 * doesn't autoneg with out driver support we need to
		 * leave LMS in the state it was before we MAC reset.
		 * Likewise if we support WoL we don't want change the
		 * LMS state.
		 */

		hw->mac.orig_sr_pcs_ctl2 = curr_sr_pcs_ctl;
		hw->mac.orig_sr_pma_mmd_ctl1 = curr_sr_pma_mmd_ctl1;
		hw->mac.orig_sr_an_mmd_ctl = curr_sr_an_mmd_ctl;
		hw->mac.orig_sr_an_mmd_adv_reg2 = curr_sr_an_mmd_adv_reg2;
		hw->mac.orig_vr_xs_or_pcs_mmd_digi_ctl1 =
						curr_vr_xs_or_pcs_mmd_digi_ctl1;
	}
	/*make sure phy power is up*/
	msleep(100);
	txgbe_xpcs_txffe_set(adapter);

	return 0;
}

int txgbe_set_sgmii_an37_ability(struct txgbe_hw *hw)
{
	u32 value;
	struct txgbe_adapter *adapter = hw->back;

	txgbe_wr32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1, 0x3002);

	/* for sgmii + external phy, set to 0x0105 (phy sgmii mode) */
	/* for sgmii direct link, set to 0x010c (mac sgmii mode) */
	if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_MAC_SGMII ||
	    hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber)
		txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_AN_CTL, 0x010c);
	else if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_SGMII ||
		 (hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI)
		txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_AN_CTL, 0x0105);

	txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_DIGI_CTL, 0x0200);

	value = txgbe_rd32_epcs(hw, TXGBE_SR_MII_MMD_CTL);
	value = (value & ~0x1200) | (0x1 << 9);
	if (adapter->autoneg)
		value |= (0x1 << 12);

	txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_CTL, value);

	return 0;
}

int txgbe_set_link_to_kr(struct txgbe_hw *hw, bool autoneg)
{
	u32 i;
	int status = 0;
	u32 value = 0;
	struct txgbe_adapter *adapter = hw->back;

	/* 1. Wait xpcs power-up good */
	for (i = 0; i < TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_MASK) ==
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_POWER_GOOD)
			break;
		usleep_range(10000, 20000);
	}
	if (i == TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME) {
		status = TXGBE_ERR_XPCS_POWER_UP_FAILED;
		goto out;
	}

	txgbe_wr32_epcs(hw, 0x78002, 0x0);
	txgbe_wr32_epcs(hw, 0x78001, 0x7);
	txgbe_wr32_epcs(hw, TXGBE_VR_AN_KR_MODE_CL, 0x1);

	/* 2. Disable xpcs AN-73 */
	if (adapter->backplane_an == 1) {
		adapter->an_done = false;
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x3000);
		/* bit8:CA_TX_EQ bit7:an_preset bit6:TX_EQ_OVR_RIDE */
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_EQ_CTL1);
		value &= ~0x40;
		value |= BIT(8);
		txgbe_wr32_epcs(hw, 0x18037, value);
	} else {
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x0);
		txgbe_wr32_epcs(hw, TXGBE_VR_AN_KR_MODE_CL, 0x0);
	}

	/* 3. Set VR_XS_PMA_Gen5_12G_MPLLA_CTRL3 Register */
	/* Bit[10:0](MPLLA_BANDWIDTH) = 11'd123 (default: 11'd16) */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL3,
			TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_10GBASER_KR);

	/* 4. Set VR_XS_PMA_Gen5_12G_MISC_CTRL0 Register */
	/* Bit[12:8](RX_VREF_CTRL) = 5'hF (default: 5'h11) */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0,
			0xCF00);

	/* 5. Set VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0 Register
	 * Bit[15:8](VGA1/2_GAIN_0) = 8'h77, Bit[7:5](CTLE_POLE_0) = 3'h2
	 * Bit[4:0](CTLE_BOOST_0) = 4'hA
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0,
			0x774A);

	/* 6. Set VR_MII_Gen5_12G_RX_GENCTRL3 Register
	 * Bit[2:0](LOS_TRSHLD_0) = 3'h4 (default: 3)
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL3,
			0x0004);
	/* 7. Initialize the mode by setting VR XS or PCS MMD Digital
	 * Control1 Register Bit[15](VR_RST)
	 */
	txgbe_wr32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1,
			0xA000);
	/* wait phy initialization done */
	for (i = 0; i < TXGBE_PHY_INIT_DONE_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw,
				     TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1_VR_RST) == 0)
			break;
		msleep(100);
	}
	if (i == TXGBE_PHY_INIT_DONE_POLLING_TIME) {
		status = TXGBE_ERR_PHY_INIT_NOT_DONE;
		goto out;
	}

	txgbe_xpcs_txffe_set(adapter);
out:
	return status;
}

int txgbe_set_link_to_kx4(struct txgbe_hw *hw, bool autoneg)
{
	u32 i;
	int status = 0;
	u32 value;
	struct txgbe_adapter *adapter = hw->back;

	/* check link status, if already set, skip setting it again */
	if (hw->link_status == TXGBE_LINK_STATUS_KX4)
		goto out;

	e_dev_info("It is set to kx4.\n");

	/* 1. Wait xpcs power-up good */
	for (i = 0; i < TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_MASK) ==
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_POWER_GOOD)
			break;
		usleep_range(10000, 20000);
	}
	if (i == TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME) {
		status = TXGBE_ERR_XPCS_POWER_UP_FAILED;
		goto out;
	}

	wr32m(hw, TXGBE_MAC_TX_CFG, TXGBE_MAC_TX_CFG_TE,
	      ~TXGBE_MAC_TX_CFG_TE);
	wr32m(hw, TXGBE_MAC_RX_CFG, TXGBE_MAC_RX_CFG_RE,
	      ~TXGBE_MAC_RX_CFG_RE);

	/* 2. Disable xpcs AN-73 */
	if (!autoneg)
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x0);
	else
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x3000);

	if (hw->revision_id == TXGBE_SP_MPW) {
		/* Disable PHY MPLLA */
		txgbe_wr32_ephy(hw, 0x4, 0x2501);
		/* Reset rx lane0-3 clock */
		txgbe_wr32_ephy(hw, 0x1005, 0x4001);
		txgbe_wr32_ephy(hw, 0x1105, 0x4001);
		txgbe_wr32_ephy(hw, 0x1205, 0x4001);
		txgbe_wr32_ephy(hw, 0x1305, 0x4001);
	} else {
		/* Disable PHY MPLLA for eth mode change(after ECO) */
		txgbe_wr32_ephy(hw, 0x4, 0x250A);
		TXGBE_WRITE_FLUSH(hw);
		usleep_range(1000, 2000);

		/* Set the eth change_mode bit first in mis_rst register
		 * for corresponding LAN port
		 */
		if (hw->bus.lan_id == 0)
			wr32(hw, TXGBE_MIS_RST,
			     TXGBE_MIS_RST_LAN0_CHG_ETH_MODE);
		else
			wr32(hw, TXGBE_MIS_RST,
			     TXGBE_MIS_RST_LAN1_CHG_ETH_MODE);
	}

	/* Set SR PCS Control2 Register Bits[1:0] = 2'b01  PCS_TYPE_SEL: non KR */
	txgbe_wr32_epcs(hw, TXGBE_SR_PCS_CTL2,
			TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_X);
	/* Set SR PMA MMD Control1 Register Bit[13] = 1'b1  SS13: 10G speed */
	txgbe_wr32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1,
			TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_10G);

	value = (0xf5f0 & ~0x7F0) |  (0x5 << 8) | (0x7 << 5) | 0xF0;
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GENCTRL1, value);

	if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_MAC_XAUI)
		txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, 0xCF00);
	else
		txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, 0x4F00);

	for (i = 0; i < 4; i++) {
		if (i == 0)
			value = (0x45 & ~0xFFFF) | (0x7 << 12) | (0x7 << 8) | 0x6;
		else
			value = (0xff06 & ~0xFFFF) | (0x7 << 12) | (0x7 << 8) | 0x6;
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0 + i, value);
	}

	value = 0x0 & ~0x7777;
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_ATT_LVL0, value);

	txgbe_wr32_epcs(hw, TXGBE_PHY_DFE_TAP_CTL0, 0x0);

	value = (0x6db & ~0xFFF) | (0x1 << 9) | (0x1 << 6) | (0x1 << 3) | 0x1;
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL3, value);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY MPLLA */
	/* Control 0 Register Bit[7:0] = 8'd40  MPLLA_MULTIPLIER */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL0,
			TXGBE_PHY_MPLLA_CTL0_MULTIPLIER_OTHER);
	/* Set VR XS, PMA or MII Synopsys Enterprise Gen5 12G PHY MPLLA */
	/* Control 3 Register Bit[10:0] = 11'd86  MPLLA_BANDWIDTH */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL3,
			TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_OTHER);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO */
	/* Calibration Load 0 Register  Bit[12:0] = 13'd1360 VCO_LD_VAL_0 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD0,
			TXGBE_PHY_VCO_CAL_LD0_OTHER);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO */
	/* Calibration Load 1 Register  Bit[12:0] = 13'd1360 VCO_LD_VAL_1 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD1,
			TXGBE_PHY_VCO_CAL_LD0_OTHER);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO */
	/* Calibration Load 2 Register  Bit[12:0] = 13'd1360 VCO_LD_VAL_2 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD2,
			TXGBE_PHY_VCO_CAL_LD0_OTHER);
	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO */
	/* Calibration Load 3 Register  Bit[12:0] = 13'd1360 VCO_LD_VAL_3 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD3,
			TXGBE_PHY_VCO_CAL_LD0_OTHER);
	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO */
	/* Calibration Reference 0 Register Bit[5:0] = 6'd34 VCO_REF_LD_0/1 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_REF0,
			0x2222);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO */
	/* Calibration Reference 1 Register Bit[5:0] = 6'd34 VCO_REF_LD_2/3 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_REF1,
			0x2222);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY AFE-DFE */
	/* Enable Register Bit[7:0] = 8'd0  AFE_EN_0/3_1, DFE_EN_0/3_1 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE,
			0x0);

	/* Set  VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx */
	/* Equalization Control 4 Register Bit[3:0] = 4'd0 CONT_ADAPT_0/3_1 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL,
			0x00F0);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Tx Rate */
	/* Control Register Bit[14:12], Bit[10:8], Bit[6:4], Bit[2:0],
	 * all rates to 3'b010  TX0/1/2/3_RATE
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_RATE_CTL,
			0x2222);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx Rate */
	/* Control Register Bit[13:12], Bit[9:8], Bit[5:4], Bit[1:0],
	 * all rates to 2'b10  RX0/1/2/3_RATE
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_RATE_CTL,
			0x2222);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Tx General */
	/* Control 2 Register Bit[15:8] = 2'b01  TX0/1/2/3_WIDTH: 10bits */
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GEN_CTL2,
			0x5500);
	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx General */
	/* Control 2 Register Bit[15:8] = 2'b01  RX0/1/2/3_WIDTH: 10bits */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL2,
			0x5500);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY MPLLA Control
	 * 2 Register Bit[10:8] = 3'b010
	 * MPLLA_DIV16P5_CLK_EN=0, MPLLA_DIV10_CLK_EN=1, MPLLA_DIV8_CLK_EN=0
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL2,
			TXGBE_PHY_MPLLA_CTL2_DIV_CLK_EN_10);

	txgbe_wr32_epcs(hw, 0x1f0000, 0x0);
	txgbe_wr32_epcs(hw, 0x1f8001, 0x0);
	txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_DIGI_CTL, 0x0);

	/* 10. Initialize the mode by setting VR XS or PCS MMD Digital Control1
	 * Register Bit[15](VR_RST)
	 */
	txgbe_wr32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1, 0xA000);
	/* wait phy initialization done */
	for (i = 0; i < TXGBE_PHY_INIT_DONE_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1_VR_RST) == 0)
			break;
		msleep(100);
	}

	/* if success, set link status */
	hw->link_status = TXGBE_LINK_STATUS_KX4;

	if (i == TXGBE_PHY_INIT_DONE_POLLING_TIME) {
		status = TXGBE_ERR_PHY_INIT_NOT_DONE;
		goto out;
	}

	txgbe_xpcs_txffe_set(adapter);

out:
	hw->mac.ops.enable_sec_tx_path(hw);
	wr32m(hw, TXGBE_MAC_RX_CFG, TXGBE_MAC_RX_CFG_RE,
	      TXGBE_MAC_RX_CFG_RE);

	return status;
}

int txgbe_set_link_to_kx(struct txgbe_hw *hw,
			 u32 speed,
			       bool autoneg)
{
	u32 i;
	int status = 0;
	u32 wdata = 0;
	u32 value;
	struct txgbe_adapter *adapter = hw->back;

	/* check link status, if already set, skip setting it again */
	if (hw->link_status == TXGBE_LINK_STATUS_KX &&
	    (hw->subsystem_device_id & 0xF0) != TXGBE_ID_MAC_SGMII)
		goto out;

	e_dev_info("It is set to kx. speed =0x%x\n", speed);

	/* 1. Wait xpcs power-up good */
	for (i = 0; i < TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_MASK) ==
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_POWER_GOOD)
			break;
		usleep_range(10000, 20000);
	}
	if (i == TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME) {
		status = TXGBE_ERR_XPCS_POWER_UP_FAILED;
		goto out;
	}

	wr32m(hw, TXGBE_MAC_TX_CFG, TXGBE_MAC_TX_CFG_TE,
	      ~TXGBE_MAC_TX_CFG_TE);

	wr32m(hw, TXGBE_MAC_RX_CFG, TXGBE_MAC_RX_CFG_RE,
	      ~TXGBE_MAC_RX_CFG_RE);

	/* 2. Disable xpcs AN-73 */
	if (!autoneg)
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x0);
	else
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x3000);

	if (hw->revision_id == TXGBE_SP_MPW) {
		/* Disable PHY MPLLA */
		txgbe_wr32_ephy(hw, 0x4, 0x2401);
		/* Reset rx lane0 clock */
		txgbe_wr32_ephy(hw, 0x1005, 0x4001);
	} else {
		/* Disable PHY MPLLA for eth mode change(after ECO) */
		txgbe_wr32_ephy(hw, 0x4, 0x240A);
		TXGBE_WRITE_FLUSH(hw);
		usleep_range(1000, 2000);

		/* Set the eth change_mode bit first in mis_rst register */
		/* for corresponding LAN port */
		if (hw->bus.lan_id == 0)
			wr32(hw, TXGBE_MIS_RST,
			     TXGBE_MIS_RST_LAN0_CHG_ETH_MODE);
		else
			wr32(hw, TXGBE_MIS_RST,
			     TXGBE_MIS_RST_LAN1_CHG_ETH_MODE);
	}

	/* Set SR PCS Control2 Register Bits[1:0] = 2'b01  PCS_TYPE_SEL: non KR */
	txgbe_wr32_epcs(hw, TXGBE_SR_PCS_CTL2,
			TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_X);

	/* Set SR PMA MMD Control1 Register Bit[13] = 1'b0 SS13: 1G speed */
	txgbe_wr32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1,
			TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_1G);

	/* Set SR MII MMD Control Register to corresponding speed: {Bit[6],
	 * Bit[13]}=[2'b00,2'b01,2'b10]->[10M,100M,1G]
	 */
	if (speed == TXGBE_LINK_SPEED_100_FULL)
		wdata = 0x2100;
	else if (speed == TXGBE_LINK_SPEED_1GB_FULL)
		wdata = 0x0140;
	else if (speed == TXGBE_LINK_SPEED_10_FULL)
		wdata = 0x0100;
	txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_CTL,
			wdata);

	value = (0xf5f0 & ~0x710) |  (0x5 << 8) | 0x10;
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GENCTRL1, value);

	txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, 0xCF00);

	for (i = 0; i < 4; i++) {
		if (i)
			value = 0xff06;
		else
			value = (0x45 & ~0xFFFF) | (0x7 << 12) | (0x7 << 8) | 0x6;

		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0 + i, value);
	}

	value = 0x0 & ~0x7;
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_ATT_LVL0, value);

	txgbe_wr32_epcs(hw, TXGBE_PHY_DFE_TAP_CTL0, 0x0);

	value = (0x6db & ~0x7) | 0x4;
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL3, value);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY MPLLA Control
	 * 0 Register Bit[7:0] = 8'd32  MPLLA_MULTIPLIER
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL0,
			TXGBE_PHY_MPLLA_CTL0_MULTIPLIER_1GBASEX_KX);

	/* Set VR XS, PMA or MII Synopsys Enterprise Gen5 12G PHY MPLLA Control 3
	 * Register Bit[10:0] = 11'd70  MPLLA_BANDWIDTH
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL3,
			TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_1GBASEX_KX);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO
	 * Calibration Load 0 Register  Bit[12:0] = 13'd1344  VCO_LD_VAL_0
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD0,
			TXGBE_PHY_VCO_CAL_LD0_1GBASEX_KX);

	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD1, 0x549);
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD2, 0x549);
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD3, 0x549);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO
	 * Calibration Reference 0 Register Bit[5:0] = 6'd42  VCO_REF_LD_0
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_REF0,
			TXGBE_PHY_VCO_CAL_REF0_LD0_1GBASEX_KX);

	txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_REF1, 0x2929);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY AFE-DFE Enable
	 * Register Bit[4], Bit[0] = 1'b0  AFE_EN_0, DFE_EN_0
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE,
			0x0);
	/* Set	VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx
	 * Equalization Control 4 Register Bit[0] = 1'b0  CONT_ADAPT_0
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL,
			0x0010);
	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Tx Rate
	 * Control Register Bit[2:0] = 3'b011  TX0_RATE
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_RATE_CTL,
			TXGBE_PHY_TX_RATE_CTL_TX0_RATE_1GBASEX_KX);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx Rate
	 * Control Register Bit[2:0] = 3'b011 RX0_RATE
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_RATE_CTL,
			TXGBE_PHY_RX_RATE_CTL_RX0_RATE_1GBASEX_KX);

	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Tx General
	 * Control 2 Register Bit[9:8] = 2'b01  TX0_WIDTH: 10bits
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GEN_CTL2,
			TXGBE_PHY_TX_GEN_CTL2_TX0_WIDTH_OTHER);
	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx General
	 * Control 2 Register Bit[9:8] = 2'b01  RX0_WIDTH: 10bits
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL2,
			TXGBE_PHY_RX_GEN_CTL2_RX0_WIDTH_OTHER);
	/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY MPLLA Control
	 * 2 Register Bit[10:8] = 3'b010	MPLLA_DIV16P5_CLK_EN=0,
	 * MPLLA_DIV10_CLK_EN=1, MPLLA_DIV8_CLK_EN=0
	 */
	txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL2,
			TXGBE_PHY_MPLLA_CTL2_DIV_CLK_EN_10);
	/* VR MII MMD AN Control Register Bit[8] = 1'b1 MII_CTRL */
	/* Set to 8bit MII (required in 10M/100M SGMII) */
	txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_AN_CTL,
			0x0100);

	/* 10. Initialize the mode by setting VR XS or PCS MMD Digital Control1
	 * Register Bit[15](VR_RST)
	 */
	txgbe_wr32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1, 0xA000);
	/* wait phy initialization done */
	for (i = 0; i < TXGBE_PHY_INIT_DONE_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1_VR_RST) == 0)
			break;
		msleep(100);
	}

	/* if success, set link status */
	hw->link_status = TXGBE_LINK_STATUS_KX;

	if (i == TXGBE_PHY_INIT_DONE_POLLING_TIME) {
		status = TXGBE_ERR_PHY_INIT_NOT_DONE;
		goto out;
	}

	txgbe_xpcs_txffe_set(adapter);

out:
	hw->mac.ops.enable_sec_tx_path(hw);
	wr32m(hw, TXGBE_MAC_RX_CFG, TXGBE_MAC_RX_CFG_RE,
	      TXGBE_MAC_RX_CFG_RE);

	return status;
}

static int txgbe_set_link_to_sfi(struct txgbe_hw *hw,
				 u32 speed)
{
	u32 i;
	int status = 0;
	u32 value = 0;
	struct txgbe_adapter *adapter = hw->back;

	/* Set the module link speed */
	hw->mac.ops.set_rate_select_speed(hw, speed);

	/* 1. Wait xpcs power-up good */
	for (i = 0; i < TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_MASK) ==
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_POWER_GOOD)
			break;
		usleep_range(10000, 20000);
	}
	if (i == TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME) {
		status = TXGBE_ERR_XPCS_POWER_UP_FAILED;
		goto out;
	}

	wr32m(hw, TXGBE_MAC_TX_CFG, TXGBE_MAC_TX_CFG_TE,
	      ~TXGBE_MAC_TX_CFG_TE);
	wr32m(hw, TXGBE_MAC_RX_CFG, TXGBE_MAC_RX_CFG_RE,
	      ~TXGBE_MAC_RX_CFG_RE);

	/* 2. Disable xpcs AN-73 */
	txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_CTL, 0x0);

	if (hw->revision_id != TXGBE_SP_MPW) {
		/* Disable PHY MPLLA for eth mode change(after ECO) */
		txgbe_wr32_ephy(hw, 0x4, 0x243A);
		TXGBE_WRITE_FLUSH(hw);
		usleep_range(1000, 2000);
		/* Set the eth change_mode bit first in mis_rst register
		 * for corresponding LAN port
		 */
		if (hw->bus.lan_id == 0)
			wr32(hw, TXGBE_MIS_RST,
			     TXGBE_MIS_RST_LAN0_CHG_ETH_MODE);
		else
			wr32(hw, TXGBE_MIS_RST,
			     TXGBE_MIS_RST_LAN1_CHG_ETH_MODE);
	}
	if (speed == TXGBE_LINK_SPEED_10GB_FULL) {
		/* @. Set SR PCS Control2 Register Bits[1:0] = 2'b00 PCS_TYPE_SEL: KR */
		txgbe_wr32_epcs(hw, TXGBE_SR_PCS_CTL2, 0);
		value = txgbe_rd32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1);
		value = value | 0x2000;
		txgbe_wr32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1, value);
		/* @. Set VR_XS_PMA_Gen5_12G_MPLLA_CTRL0 Register Bit[7:0] = 8'd33
		 * MPLLA_MULTIPLIER
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL0, 0x0021);
		/* 3. Set VR_XS_PMA_Gen5_12G_MPLLA_CTRL3 Register
		 * Bit[10:0](MPLLA_BANDWIDTH) = 11'd0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL3, 0);
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_GENCTRL1);
		value = (value & ~0x700) | 0x500;
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GENCTRL1, value);
		/* 4.Set VR_XS_PMA_Gen5_12G_MISC_CTRL0 Register Bit[12:8](RX_VREF_CTRL)
		 * = 5'hF
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, 0xCF00);
		/* @. Set VR_XS_PMA_Gen5_12G_VCO_CAL_LD0 Register  Bit[12:0] = 13'd1353
		 * VCO_LD_VAL_0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD0, 0x0549);
		/* @. Set VR_XS_PMA_Gen5_12G_VCO_CAL_REF0 Register Bit[5:0] = 6'd41
		 * VCO_REF_LD_0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_REF0, 0x0029);
		/* @. Set VR_XS_PMA_Gen5_12G_TX_RATE_CTRL Register Bit[2:0] = 3'b000
		 * TX0_RATE
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_RATE_CTL, 0);
		/* @. Set VR_XS_PMA_Gen5_12G_RX_RATE_CTRL Register Bit[2:0] = 3'b000
		 * RX0_RATE
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_RATE_CTL, 0);
		/* @. Set VR_XS_PMA_Gen5_12G_TX_GENCTRL2 Register Bit[9:8] = 2'b11
		 * TX0_WIDTH: 20bits
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GEN_CTL2, 0x0300);
		/* @. Set VR_XS_PMA_Gen5_12G_RX_GENCTRL2 Register Bit[9:8] = 2'b11
		 * RX0_WIDTH: 20bits
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL2, 0x0300);
		/* @. Set VR_XS_PMA_Gen5_12G_MPLLA_CTRL2 Register Bit[10:8] = 3'b110
		 * MPLLA_DIV16P5_CLK_EN=1, MPLLA_DIV10_CLK_EN=1, MPLLA_DIV8_CLK_EN=0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL2, 0x0600);

		if (hw->phy.sfp_type == txgbe_sfp_type_da_cu_core0 ||
		    hw->phy.sfp_type == txgbe_sfp_type_da_cu_core1) {
			/* 7. Set VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0 Register
			 * Bit[15:8](VGA1/2_GAIN_0) = 8'h77, Bit[7:5]
			 * (CTLE_POLE_0) = 3'h2, Bit[4:0](CTLE_BOOST_0) = 4'hF
			 */
			txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0, 0x774F);

		} else {
			/* 7. Set VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0 Register Bit[15:8]
			 * (VGA1/2_GAIN_0) = 8'h00, Bit[7:5](CTLE_POLE_0) = 3'h2,
			 * Bit[4:0](CTLE_BOOST_0) = 4'hA
			 */
			value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0);
			value = (value & ~0xFFFF) | (2 << 5) | 0x05;
			txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0, value);
		}
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_ATT_LVL0);
		value = (value & ~0x7) | 0x0;
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_ATT_LVL0, value);

		if (hw->phy.sfp_type == txgbe_sfp_type_da_cu_core0 ||
		    hw->phy.sfp_type == txgbe_sfp_type_da_cu_core1) {
			/* 8. Set VR_XS_PMA_Gen5_12G_DFE_TAP_CTRL0 Register Bit[7:0](DFE_TAP1_0)
			 * = 8'd20
			 */
			txgbe_wr32_epcs(hw, TXGBE_PHY_DFE_TAP_CTL0, 0x0014);
			value = txgbe_rd32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE);
			value = (value & ~0x11) | 0x11;
			txgbe_wr32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE, value);
		} else {
			/* 8. Set VR_XS_PMA_Gen5_12G_DFE_TAP_CTRL0 Register Bit[7:0](DFE_TAP1_0)
			 * = 8'd20
			 */
			txgbe_wr32_epcs(hw, TXGBE_PHY_DFE_TAP_CTL0, 0xBE);
			/* 9. Set VR_MII_Gen5_12G_AFE_DFE_EN_CTRL Register Bit[4](DFE_EN_0) =
			 * 1'b0, Bit[0](AFE_EN_0) = 1'b0
			 */
			value = txgbe_rd32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE);
			value = (value & ~0x11) | 0x0;
			txgbe_wr32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE, value);
		}
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_CTL);
		value = value & ~0x1;
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL, value);
	} else {
		if (hw->revision_id == TXGBE_SP_MPW) {
			/* Disable PHY MPLLA */
			txgbe_wr32_ephy(hw, 0x4, 0x2401);
			/* Reset rx lane0 clock */
			txgbe_wr32_ephy(hw, 0x1005, 0x4001);
		}
		/* @. Set SR PCS Control2 Register Bits[1:0] = 2'b00 PCS_TYPE_SEL: KR */
		txgbe_wr32_epcs(hw, TXGBE_SR_PCS_CTL2, 0x1);
		/* Set SR PMA MMD Control1 Register Bit[13] = 1'b0  SS13: 1G speed */
		txgbe_wr32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1, 0x0000);
		/* Set SR MII MMD Control Register to corresponding speed: */
		txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_CTL, 0x0140);

		value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_GENCTRL1);
		value = (value & ~0x710) | 0x500;
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GENCTRL1, value);

		txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, 0xCF00);
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_EQ_CTL0);
		value = (value & ~0x3F3F) | (24 << 8) | 4;
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_EQ_CTL0, value);

		value = txgbe_rd32_epcs(hw, TXGBE_PHY_TX_EQ_CTL1);
		value = (value & ~0x7F) | 16 | (1 << 6);
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_EQ_CTL1, value);
		if (hw->phy.sfp_type == txgbe_sfp_type_da_cu_core0 ||
		    hw->phy.sfp_type == txgbe_sfp_type_da_cu_core1) {
			txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0, 0x774F);
		} else {
			/* 7. Set VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0 Register Bit[15:8]
			 * (VGA1/2_GAIN_0) = 8'h00, Bit[7:5](CTLE_POLE_0) = 3'h2,
			 * Bit[4:0](CTLE_BOOST_0) = 4'hA
			 */
			value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0);
			value = (value & ~0xFFFF) | 0x7706;
			txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL0, value);
		}
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_ATT_LVL0);
		value = (value & ~0x7) | 0x0;
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_ATT_LVL0, value);
		/* 8. Set VR_XS_PMA_Gen5_12G_DFE_TAP_CTRL0 Register Bit[7:0](DFE_TAP1_0)
		 * = 8'd00
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_DFE_TAP_CTL0, 0x0);
		/* Set VR_XS_PMA_Gen5_12G_RX_GENCTRL3 Register Bit[2:0] LOS_TRSHLD_0 = 4 */
		value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_GEN_CTL3);
		value = (value & ~0x7) | 0x4;
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL3, value);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY
		 * MPLLA Control 0 Register Bit[7:0] = 8'd32  MPLLA_MULTIPLIER
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL0, 0x0020);
		/* Set VR XS, PMA or MII Synopsys Enterprise Gen5 12G PHY MPLLA Control
		 * 3 Register Bit[10:0] = 11'd70  MPLLA_BANDWIDTH
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL3, 0x0046);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO
		 * Calibration Load 0 Register  Bit[12:0] = 13'd1344  VCO_LD_VAL_0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_LD0, 0x0540);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY VCO
		 * Calibration Reference 0 Register Bit[5:0] = 6'd42  VCO_REF_LD_0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_VCO_CAL_REF0, 0x002A);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY AFE-DFE
		 * Enable Register Bit[4], Bit[0] = 1'b0  AFE_EN_0, DFE_EN_0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_AFE_DFE_ENABLE, 0x0);
		/* Set  VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx
		 * Equalization Control 4 Register Bit[0] = 1'b0  CONT_ADAPT_0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL, 0x0010);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Tx Rate
		 * Control Register Bit[2:0] = 3'b011  TX0_RATE
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_RATE_CTL, 0x0003);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx Rate
		 * Control Register Bit[2:0] = 3'b011
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_RATE_CTL, 0x0003);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Tx General
		 * Control 2 Register Bit[9:8] = 2'b01  TX0_WIDTH: 10bits
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_TX_GEN_CTL2, 0x0100);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY Rx General
		 * Control 2 Register Bit[9:8] = 2'b01  RX0_WIDTH: 10bits
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_RX_GEN_CTL2, 0x0100);
		/* Set VR XS, PMA, or MII Synopsys Enterprise Gen5 12G PHY MPLLA
		 * Control 2 Register Bit[10:8] = 3'b010  MPLLA_DIV16P5_CLK_EN=0,
		 * MPLLA_DIV10_CLK_EN=1, MPLLA_DIV8_CLK_EN=0
		 */
		txgbe_wr32_epcs(hw, TXGBE_PHY_MPLLA_CTL2, 0x0200);
		/* VR MII MMD AN Control Register Bit[8] = 1'b1 MII_CTRL */
		txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_AN_CTL, 0x0100);
	}
	/* 10. Initialize the mode by setting VR XS or PCS MMD Digital Control1
	 * Register Bit[15](VR_RST)
	 */
	txgbe_wr32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1, 0xA000);
	/* wait phy initialization done */
	for (i = 0; i < TXGBE_PHY_INIT_DONE_POLLING_TIME; i++) {
		if ((txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1) &
			TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1_VR_RST) == 0)
			break;
		msleep(100);
	}
	if (i == TXGBE_PHY_INIT_DONE_POLLING_TIME) {
		status = TXGBE_ERR_PHY_INIT_NOT_DONE;
		goto out;
	}

	txgbe_xpcs_txffe_set(adapter);
out:
	hw->mac.ops.enable_sec_tx_path(hw);
	wr32m(hw, TXGBE_MAC_RX_CFG, TXGBE_MAC_RX_CFG_RE,
	      TXGBE_MAC_RX_CFG_RE);

	return status;
}

static int txgbe_get_link_capabilities_sp(struct txgbe_hw *hw,
					  u32 *speed,
					     bool *autoneg)
{
	u32 sr_pcs_ctl, sr_pma_mmd_ctl1, sr_an_mmd_ctl, sr_an_mmd_adv_reg2;
	struct txgbe_adapter *adapter = hw->back;
	int status = 0;

	if (hw->phy.multispeed_fiber) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_1GB_FULL;
		*autoneg = true;
	} else if (txgbe_is_dac_cable(hw)) {
		*autoneg = adapter->backplane_an;
		hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_10GBASE_KR;
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
	} else if (hw->phy.sfp_type == txgbe_sfp_type_1g_cu_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_1g_cu_core1 ||
	    hw->phy.sfp_type == txgbe_sfp_type_1g_lx_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_1g_lx_core1 ||
	    hw->phy.sfp_type == txgbe_sfp_type_1g_sx_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_1g_sx_core1) {
	    /* Check if 1G SFP module. */
		*speed = TXGBE_LINK_SPEED_1GB_FULL;
		*autoneg = true;
	}
	/* SFP */
	else if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
		*autoneg = false;
	}
	/* XAUI */
	else if ((hw->mac.ops.get_media_type(hw) == txgbe_media_type_copper) &&
		 ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI ||
			 (hw->subsystem_device_id & 0xF0) == TXGBE_ID_SFI_XAUI)) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
		*autoneg = false;
		hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_10GBASE_T;
	}
	/* SGMII */
	else if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_SGMII) {
		*speed = TXGBE_LINK_SPEED_1GB_FULL |
			TXGBE_LINK_SPEED_100_FULL |
			TXGBE_LINK_SPEED_10_FULL;
		*autoneg = false;
		hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_1000BASE_T |
				TXGBE_PHYSICAL_LAYER_100BASE_TX;
	/* MAC XAUI */
	} else if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_MAC_XAUI) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
		*autoneg = false;
		hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_10GBASE_KX4;
		/* MAC SGMII */
	} else if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_MAC_SGMII) {
		*speed = TXGBE_LINK_SPEED_1GB_FULL;
		*autoneg = false;
		hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_1000BASE_KX;
	} else {
		/* Determine link capabilities based on the stored value,
		 * which represents EEPROM defaults.  If value has not
		 * been stored, use the current register values.
		 */
		if (hw->mac.orig_link_settings_stored) {
			sr_pcs_ctl = hw->mac.orig_sr_pcs_ctl2;
			sr_pma_mmd_ctl1 = hw->mac.orig_sr_pma_mmd_ctl1;
			sr_an_mmd_ctl = hw->mac.orig_sr_an_mmd_ctl;
			sr_an_mmd_adv_reg2 = hw->mac.orig_sr_an_mmd_adv_reg2;
		} else {
			sr_pcs_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_PCS_CTL2);
			sr_pma_mmd_ctl1 = txgbe_rd32_epcs(hw,
							  TXGBE_SR_PMA_MMD_CTL1);
			sr_an_mmd_ctl = txgbe_rd32_epcs(hw,
							TXGBE_SR_AN_MMD_CTL);
			sr_an_mmd_adv_reg2 = txgbe_rd32_epcs(hw,
							     TXGBE_SR_AN_MMD_ADV_REG2);
		}

		if ((sr_pcs_ctl & TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_MASK) ==
			TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_X &&
			(sr_pma_mmd_ctl1 & TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_MASK)
			== TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_1G &&
			(sr_an_mmd_ctl & TXGBE_SR_AN_MMD_CTL_ENABLE) == 0) {
			/* 1G or KX - no backplane auto-negotiation */
			*speed = TXGBE_LINK_SPEED_1GB_FULL;
			*autoneg = false;
			hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_1000BASE_KX;
		} else if ((sr_pcs_ctl & TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_MASK) ==
			TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_X &&
			(sr_pma_mmd_ctl1 & TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_MASK)
			== TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_10G &&
			(sr_an_mmd_ctl & TXGBE_SR_AN_MMD_CTL_ENABLE) == 0) {
			*speed = TXGBE_LINK_SPEED_10GB_FULL;
			*autoneg = false;
			hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_10GBASE_KX4;
		} else if ((sr_pcs_ctl & TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_MASK) ==
			TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_R &&
			(sr_an_mmd_ctl & TXGBE_SR_AN_MMD_CTL_ENABLE) == 0) {
			/* 10 GbE serial link (KR -no backplane auto-negotiation) */
			*speed = TXGBE_LINK_SPEED_10GB_FULL;
			*autoneg = false;
			hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_10GBASE_KR;
		} else if ((sr_an_mmd_ctl & TXGBE_SR_AN_MMD_CTL_ENABLE)) {
			/* KX/KX4/KR backplane auto-negotiation enable */
			*speed = TXGBE_LINK_SPEED_UNKNOWN;
			if (sr_an_mmd_adv_reg2 &
				TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_KR)
				*speed |= TXGBE_LINK_SPEED_10GB_FULL;
			if (sr_an_mmd_adv_reg2 &
				TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_KX4)
				*speed |= TXGBE_LINK_SPEED_10GB_FULL;
			if (sr_an_mmd_adv_reg2 &
				TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_KX)
				*speed |= TXGBE_LINK_SPEED_1GB_FULL;
			*autoneg = true;
			hw->phy.link_mode = TXGBE_PHYSICAL_LAYER_10GBASE_KR |
					TXGBE_PHYSICAL_LAYER_10GBASE_KX4 |
					TXGBE_PHYSICAL_LAYER_1000BASE_KX;
		} else {
			status = TXGBE_ERR_LINK_SETUP;
			goto out;
		}
	}

out:
	return status;
}

static int txgbe_setup_mac_link_sp(struct txgbe_hw *hw,
				   u32 speed,
				      bool autoneg_wait_to_complete)
{
	bool autoneg = false;
	int status = 0;
	u32 link_capabilities = TXGBE_LINK_SPEED_UNKNOWN;
	struct txgbe_adapter *adapter = hw->back;
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	bool link_up = false;
	u32 curr_autoneg = 2;

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

	if (!(((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_KR_KX_KX4) ||
	      ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_MAC_XAUI) ||
			((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_MAC_SGMII) ||
			txgbe_is_dac_cable(hw))) {
		status = hw->mac.ops.check_link(hw,
				&link_speed, &link_up, false);

		if (link_speed == TXGBE_LINK_SPEED_1GB_FULL) {
			curr_autoneg = txgbe_rd32_epcs(hw, TXGBE_SR_MII_MMD_CTL);
			curr_autoneg = !!(curr_autoneg & (0x1 << 12));
		}

		if (status != 0)
			goto out;

		if (link_speed == speed && link_up &&
		    !(speed == TXGBE_LINK_SPEED_1GB_FULL &&
			adapter->autoneg != curr_autoneg))
			goto out;
	}

	if ((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_KR_KX_KX4 ||
	    txgbe_is_dac_cable(hw)) {
		txgbe_set_link_to_kr(hw, autoneg);
	} else if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI ||
		((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_MAC_XAUI) ||
		(hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_SGMII ||
		((hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_MAC_SGMII) ||
		(hw->mac.ops.get_media_type(hw) == txgbe_media_type_copper &&
		(hw->subsystem_device_id & TXGBE_DEV_MASK) == TXGBE_ID_SFI_XAUI)) {
		if (speed == TXGBE_LINK_SPEED_10GB_FULL) {
			txgbe_set_link_to_kx4(hw, 0);
		} else {
			txgbe_set_link_to_kx(hw, speed, 0);
			txgbe_set_sgmii_an37_ability(hw);
			hw->phy.autoneg_advertised |= speed;
		}
	} else if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber) {
		if (!((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP &&
		      (hw->phy.sfp_type == txgbe_sfp_type_1g_cu_core0 ||
			hw->phy.sfp_type == txgbe_sfp_type_1g_cu_core1))) {
			txgbe_set_link_to_sfi(hw, speed);
			if (speed == TXGBE_LINK_SPEED_1GB_FULL) {
				txgbe_setup_fc(hw);
				txgbe_set_sgmii_an37_ability(hw);
				hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_1GB_FULL;
			}
		}
	}

out:
	return status;
}

static int txgbe_setup_copper_link(struct txgbe_hw *hw,
				   u32 speed,
					 bool autoneg_wait_to_complete)
{
	int status;
	u32 link_speed;

	/* Setup the PHY according to input speed */
	link_speed = hw->phy.ops.setup_link_speed(hw, speed,
						autoneg_wait_to_complete);

	if (link_speed != TXGBE_LINK_SPEED_UNKNOWN)
		status = txgbe_setup_mac_link_sp(hw, link_speed, autoneg_wait_to_complete);
	else
		status = 0;

	return status;
}

static enum txgbe_media_type txgbe_get_media_type_sp(struct txgbe_hw *hw)
{
	enum txgbe_media_type media_type;
	u8 device_type = hw->subsystem_device_id & 0xF0;

	/* Detect if there is a copper PHY attached. */
	switch (hw->phy.type) {
	case txgbe_phy_cu_unknown:
	case txgbe_phy_tn:
		media_type = txgbe_media_type_copper;
		goto out;
	default:
		break;
	}

	switch (device_type) {
	case TXGBE_ID_MAC_XAUI:
	case TXGBE_ID_MAC_SGMII:
	case TXGBE_ID_KR_KX_KX4:
		/* Default device ID is mezzanine card KX/KX4 */
		media_type = txgbe_media_type_backplane;
		break;
	case TXGBE_ID_SFP:
		media_type = txgbe_media_type_fiber;
		break;
	case TXGBE_ID_XAUI:
	case TXGBE_ID_SGMII:
		media_type = txgbe_media_type_copper;
		break;
	case TXGBE_ID_SFI_XAUI:
		if (hw->bus.lan_id == 0)
			media_type = txgbe_media_type_fiber;
		else
			media_type = txgbe_media_type_copper;
		break;
	default:
		media_type = txgbe_media_type_unknown;
		break;
	}
out:
	return media_type;
}

static int txgbe_check_mac_link_sp(struct txgbe_hw *hw, u32 *speed,
			    bool *link_up, bool link_up_wait_to_complete)
{
	struct txgbe_adapter *adapter = hw->back;
	u32 links_reg = 0;
	u16 value = 0;
	u32 i;

	if (link_up_wait_to_complete) {
		for (i = 0; i < TXGBE_LINK_UP_TIME; i++) {
			if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_copper &&
			    ((hw->subsystem_device_id & 0xF0) != TXGBE_ID_SFI_XAUI)) {
				/* read ext phy link status */
				txgbe_read_mdio(&hw->phy_dev, hw->phy.addr, 0x03, 0x8008, &value);
				if (value & 0x400)
					*link_up = true;
				else
					*link_up = false;
			} else {
				*link_up = true;
			}

			if (*link_up) {
				links_reg = rd32(hw,
						 TXGBE_CFG_PORT_ST);
				if (!(links_reg & TXGBE_CFG_PORT_ST_LINK_UP)) {
					*link_up = false;
				} else {
					*link_up = true;
					break;
				}
			}
			msleep(100);
		}
	} else {
		if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_copper  &&
		    ((hw->subsystem_device_id & 0xF0) != TXGBE_ID_SFI_XAUI)) {
			/* read ext phy link status */
			txgbe_read_mdio(&hw->phy_dev, hw->phy.addr, 0x03, 0x8008, &value);
			if (value & 0x400)
				*link_up = true;
			else
				*link_up = false;
		} else {
			*link_up = true;
		}
		if (*link_up) {
			links_reg = rd32(hw, TXGBE_CFG_PORT_ST);
			if (links_reg & TXGBE_CFG_PORT_ST_LINK_UP)
				*link_up = true;
			else
				*link_up = false;
		}
	}

	/* sync link status to fw for ocp card */
	if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI)
		wr32(hw, TXGBE_TSC_LSEC_PKTNUM0, value);

	if (hw->phy.sfp_type == txgbe_sfp_type_1g_cu_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_1g_cu_core1 ||
		hw->phy.sfp_type == txgbe_sfp_type_10g_cu_core0 ||
		hw->phy.sfp_type == txgbe_sfp_type_10g_cu_core1) {
		*link_up = hw->f2c_mod_status;

		if (*link_up)
			/* recover led configure when link up */
			wr32(hw, TXGBE_CFG_LED_CTL, 0);
		else
			/* over write led when link down */
			txgbe_led_off(hw, TXGBE_LED_LINK_UP | TXGBE_LED_LINK_10G |
							 TXGBE_LED_LINK_1G | TXGBE_LED_LINK_ACTIVE);
	}

	if (*link_up) {
		if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_copper  &&
		    ((hw->subsystem_device_id & 0xF0) != TXGBE_ID_SFI_XAUI)) {
			if ((value & 0xc000) == 0xc000)
				*speed = TXGBE_LINK_SPEED_10GB_FULL;
			else if ((value & 0xc000) == 0x8000)
				*speed = TXGBE_LINK_SPEED_1GB_FULL;
			else if ((value & 0xc000) == 0x4000)
				*speed = TXGBE_LINK_SPEED_100_FULL;
			else if ((value & 0xc000) == 0x0000)
				*speed = TXGBE_LINK_SPEED_10_FULL;
		} else {
			if ((links_reg & TXGBE_CFG_PORT_ST_LINK_10G) ==
					TXGBE_CFG_PORT_ST_LINK_10G)
				*speed = TXGBE_LINK_SPEED_10GB_FULL;
			else if ((links_reg & TXGBE_CFG_PORT_ST_LINK_1G) ==
					TXGBE_CFG_PORT_ST_LINK_1G)
				*speed = TXGBE_LINK_SPEED_1GB_FULL;
			else if ((links_reg & TXGBE_CFG_PORT_ST_LINK_100M) ==
						TXGBE_CFG_PORT_ST_LINK_100M)
				*speed = TXGBE_LINK_SPEED_100_FULL;
			else
				*speed = TXGBE_LINK_SPEED_10_FULL;
		}
	} else {
		*speed = TXGBE_LINK_SPEED_UNKNOWN;
	}

	if (txgbe_xpcs_an_enabled(hw)) {
		if (!adapter->an_done) {
			*link_up = false;
			*speed = TXGBE_LINK_SPEED_UNKNOWN;
		}
	}

	return 0;
}

static void txgbe_init_mac_link_ops_sp(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;

	/* enable the laser control functions for SFP+ fiber
	 * and MNG not enabled
	 */
	mac->ops.disable_tx_laser = txgbe_disable_tx_laser_multispeed_fiber;
	mac->ops.enable_tx_laser = txgbe_enable_tx_laser_multispeed_fiber;
	mac->ops.flap_tx_laser = txgbe_flap_tx_laser_multispeed_fiber;

	if (hw->phy.multispeed_fiber) {
		/* Set up dual speed SFP+ support */
		mac->ops.setup_link = txgbe_setup_mac_link_multispeed_fiber;
		mac->ops.setup_mac_link = txgbe_setup_mac_link_sp;
		mac->ops.set_rate_select_speed =
					       txgbe_set_hard_rate_select_speed;
	}
}

static int txgbe_init_phy_ops_sp(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;
	int ret_val = 0;

	/* Identify the PHY or SFP module */
	ret_val = hw->phy.ops.identify(hw);
	if (ret_val == TXGBE_ERR_SFP_NOT_SUPPORTED)
		goto init_phy_ops_out;

	/* Setup function pointers based on detected SFP module and speeds */
	txgbe_init_mac_link_ops_sp(hw);

	/* If copper media, overwrite with copper function pointers */
	if (hw->mac.ops.get_media_type(hw) == txgbe_media_type_copper) {
		hw->phy.type = txgbe_phy_xaui;
		if ((hw->subsystem_device_id & 0xF0) != TXGBE_ID_SFI_XAUI) {
			mac->ops.setup_link = txgbe_setup_copper_link;
			mac->ops.get_link_capabilities =
				  txgbe_get_copper_link_capabilities;
		}
	}

init_phy_ops_out:
	return ret_val;
}

static int txgbe_setup_sfp_modules_sp(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type != txgbe_sfp_type_unknown) {
		txgbe_init_mac_link_ops_sp(hw);
		return 0;
	}
	hw_dbg(hw, "unknown SFP type: %d\n", hw->phy.sfp_type);
	/* If SFP type is unknown, we cannot set up the link */
	return TXGBE_ERR_SFP_NOT_SUPPORTED;
}

static const struct txgbe_mac_operations mac_ops_sp = {
	/* MAC */
	.init_hw		= &txgbe_init_hw,
	.reset_hw		= &txgbe_reset_hw_sp,
	.start_hw		= &txgbe_start_hw,
	.clear_hw_cntrs		= &txgbe_clear_hw_cntrs,
	.get_media_type		= &txgbe_get_media_type_sp,
	.get_mac_addr		= &txgbe_get_mac_addr,
	.stop_adapter		= &txgbe_stop_adapter,
	.get_bus_info		= &txgbe_get_bus_info,
	.set_lan_id		= &txgbe_set_lan_id_multi_port_pcie,
	.setup_sfp		= &txgbe_setup_sfp_modules_sp,
	.enable_rx_dma		= &txgbe_enable_rx_dma,
	.disable_sec_rx_path	= &txgbe_disable_sec_rx_path,
	.enable_sec_rx_path	= &txgbe_enable_sec_rx_path,
	.disable_sec_tx_path	= &txgbe_disable_sec_tx_path,
	.enable_sec_tx_path	= &txgbe_enable_sec_tx_path,

	/* Link */
	.disable_tx_laser	= NULL,
	.enable_tx_laser	= NULL,
	.flap_tx_laser		= NULL,
	.setup_link		= &txgbe_setup_mac_link_sp,
	.setup_mac_link		= NULL,
	.check_link		= &txgbe_check_mac_link_sp,
	.get_link_capabilities	= &txgbe_get_link_capabilities_sp,
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

static const struct txgbe_phy_operations phy_ops_sp = {
	/* PHY */
	.identify		= &txgbe_identify_phy_generic,
	.identify_sfp		= &txgbe_identify_module,
	.init			= &txgbe_init_phy_ops_sp,
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

static int txgbe_get_invariants_sp(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	int ret;

	ret = txgbe_get_invariants_generic(hw);
	hw->mac.orig_link_settings_stored = false;

	adapter->desc_reserved = DESC_RESERVED;

	adapter->cur_fec_link = TXGBE_PHY_FEC_AUTO;
	hw->phy.curr_user_fec_req = TXGBE_PHY_FEC_AUTO;
	hw->phy.link_fec_options = TXGBE_PHY_FEC_10G_KR_40G_KR4_EN |
				   TXGBE_PHY_FEC_10G_KR_40G_KR4_REQ;

	return ret;
}

const struct txgbe_info txgbe_sp_info = {
	.mac			= txgbe_mac_sp,
	.get_invariants		= &txgbe_get_invariants_sp,
	.mac_ops		= &mac_ops_sp,
	.phy_ops		= &phy_ops_sp,
};
