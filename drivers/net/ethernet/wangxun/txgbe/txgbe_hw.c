// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#include "linux/compiler_attributes.h"
#include "linux/delay.h"
#include "txgbe_type.h"
#include "txgbe_phy.h"
#include "txgbe_dcb.h"
#include "txgbe_bp_base.h"
#include "txgbe_e56.h"
#include "txgbe_e56_bp.h"
#include "txgbe_sp.h"
#include "txgbe_hw.h"
#include "txgbe.h"

/**
 * txgbe_dcb_get_rtrup2tc - read rtrup2tc reg
 * @hw: pointer to hardware structure
 * @map: pointer to u8 arr for returning map
 *
 * Read the rtrup2tc HW register and resolve its content into map
 **/
void txgbe_dcb_get_rtrup2tc(struct txgbe_hw *hw, u8 *map)
{
	u32 reg, i;

	reg = rd32(hw, TXGBE_RDB_UP2TC);
	for (i = 0; i < TXGBE_DCB_MAX_USER_PRIORITY; i++)
		map[i] = TXGBE_RDB_UP2TC_UP_MASK &
			(reg >> (i * TXGBE_RDB_UP2TC_UP_SHIFT));
}

/**
 *  txgbe_get_pcie_msix_count - Gets MSI-X vector count
 *  @hw: pointer to hardware structure
 *
 *  Read PCIe configuration space, and get the MSI-X vector count from
 *  the capabilities table.
 **/
static u16 txgbe_get_pcie_msix_count(struct txgbe_hw *hw)
{
	u16 msix_count = 1;
	u16 max_msix_count;
	u32 pos;

	max_msix_count = TXGBE_MAX_MSIX_VECTORS_SAPPHIRE;
	pos = pci_find_capability(((struct txgbe_adapter *)hw->back)->pdev, PCI_CAP_ID_MSIX);
	if (!pos)
		return msix_count;
	pci_read_config_word(((struct txgbe_adapter *)hw->back)->pdev,
			     pos + PCI_MSIX_FLAGS, &msix_count);

	if (TXGBE_REMOVED(hw->hw_addr))
		msix_count = 0;
	msix_count &= TXGBE_PCIE_MSIX_TBL_SZ_MASK;

	/* MSI-X count is zero-based in HW */
	msix_count++;

	if (msix_count > max_msix_count)
		msix_count = max_msix_count;

	return msix_count;
}

/**
 *  txgbe_init_hw - Generic hardware initialization
 *  @hw: pointer to hardware structure
 *
 *  Initialize the hardware by resetting the hardware, filling the bus info
 *  structure and media type, clears all on chip counters, initializes receive
 *  address registers, multicast table, VLAN filter table, calls routine to set
 *  up link and flow control settings, and leaves transmit and receive units
 *  disabled and uninitialized
 **/
int txgbe_init_hw(struct txgbe_hw *hw)
{
	int status;

	/* Reset the hardware */
	status = hw->mac.ops.reset_hw(hw);

	if (status == 0) {
		/* Start the HW */
		status = hw->mac.ops.start_hw(hw);
	}

	return status;
}

/**
 *  txgbe_clear_hw_cntrs - Generic clear hardware counters
 *  @hw: pointer to hardware structure
 *
 *  Clears all hardware statistics counters by reading them from the hardware
 *  Statistics counters are clear on read.
 **/
int txgbe_clear_hw_cntrs(struct txgbe_hw *hw)
{
	u16 i = 0;

	rd32(hw, TXGBE_RX_CRC_ERROR_FRAMES_LOW);
	for (i = 0; i < 8; i++)
		rd32(hw, TXGBE_RDB_MPCNT(i));

	rd32(hw, TXGBE_RX_LEN_ERROR_FRAMES_LOW);
	rd32(hw, TXGBE_RDB_LXONTXC);
	rd32(hw, TXGBE_RDB_LXOFFTXC);
	rd32(hw, TXGBE_MAC_LXONRXC);
	rd32(hw, TXGBE_MAC_LXOFFRXC);

	for (i = 0; i < 8; i++) {
		rd32(hw, TXGBE_RDB_PXONTXC(i));
		rd32(hw, TXGBE_RDB_PXOFFTXC(i));
		if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
			wr32(hw, TXGBE_AML_MAC_PXONRXC(i), 0);
			wr32(hw, TXGBE_AML_MAC_PXOFFRXC(i), 0);
		} else {
			rd32(hw, TXGBE_MAC_PXONRXC(i));
			wr32m(hw, TXGBE_MMC_CONTROL, TXGBE_MMC_CONTROL_UP, i << 16);
			rd32(hw, TXGBE_MAC_PXOFFRXC);
		}
	}
	for (i = 0; i < 8; i++)
		rd32(hw, TXGBE_RDB_PXON2OFFCNT(i));
	for (i = 0; i < 128; i++)
		wr32(hw, TXGBE_PX_MPRC(i), 0);

	rd32(hw, TXGBE_PX_GPRC);
	rd32(hw, TXGBE_PX_GPTC);
	rd32(hw, TXGBE_PX_GORC_MSB);
	rd32(hw, TXGBE_PX_GOTC_MSB);

	rd32(hw, TXGBE_RX_BC_FRAMES_GOOD_LOW);
	rd32(hw, TXGBE_RX_UNDERSIZE_FRAMES_GOOD);
	rd32(hw, TXGBE_RX_OVERSIZE_FRAMES_GOOD);
	rd32(hw, TXGBE_RX_FRAME_CNT_GOOD_BAD_LOW);
	rd32(hw, TXGBE_TX_FRAME_CNT_GOOD_BAD_LOW);
	rd32(hw, TXGBE_TX_MC_FRAMES_GOOD_LOW);
	rd32(hw, TXGBE_TX_BC_FRAMES_GOOD_LOW);
	rd32(hw, TXGBE_RDM_DRP_PKT);

	return 0;
}

/* txgbe_device_supports_autoneg_fc - Check if device supports autonegotiation
 * of flow control
 * @hw: pointer to hardware structure
 *
 * This function returns true if the device supports flow control
 * autonegotiation, and false if it does not.
 */
bool txgbe_device_supports_autoneg_fc(struct txgbe_hw *hw)
{
	bool supported = false;
	u32 speed;
	bool link_up = false;
	u8 device_type = hw->subsystem_device_id & 0xF0;

	switch (hw->phy.media_type) {
	case txgbe_media_type_fiber_qsfp:
	case txgbe_media_type_fiber:
		hw->mac.ops.check_link(hw, &speed, &link_up, false);
		/* if link is down, assume supported */
		/* amlite TODO*/
		if (link_up)
			supported = speed == TXGBE_LINK_SPEED_1GB_FULL ?
				true : false;
		else
			supported = true;
		break;
	case txgbe_media_type_backplane:
		supported = (device_type != TXGBE_ID_MAC_XAUI &&
					device_type != TXGBE_ID_MAC_SGMII);
		break;
	case txgbe_media_type_copper:
		/* only some copper devices support flow control autoneg */
		supported = true;
		break;
	default:
		break;
	}

	ERROR_REPORT2(TXGBE_ERROR_UNSUPPORTED,
		      "Device %x does not support flow control autoneg",
		      hw->device_id);
	return supported;
}

/* txgbe_setup_fc - Set up flow control
 * @hw: pointer to hardware structure
 *
 * Called at init time to set up flow control.
 */
int txgbe_setup_fc(struct txgbe_hw *hw)
{
	int ret_val = 0;
	u32 pcap = 0;
	u32 value = 0;
	u32 pcap_backplane = 0;

	/*amlite TODO*/
	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40)
		return 0;

	/* Validate the requested mode */
	if (hw->fc.strict_ieee && hw->fc.requested_mode == txgbe_fc_rx_pause) {
		ERROR_REPORT1(TXGBE_ERROR_UNSUPPORTED,
			      "txgbe_fc_rx_pause not valid in strict IEEE mode\n");
		ret_val = TXGBE_ERR_INVALID_LINK_SETTINGS;
		goto out;
	}

	/* 10gig parts do not have a word in the EEPROM to determine the
	 * default flow control setting, so we explicitly set it to full.
	 */
	if (hw->fc.requested_mode == txgbe_fc_default)
		hw->fc.requested_mode = txgbe_fc_full;

	/* Set up the 1G and 10G flow control advertisement registers so the
	 * HW will be able to do fc autoneg once the cable is plugged in.  If
	 * we link at 10G, the 1G advertisement is harmless and vice versa.
	 */

	/* The possible values of fc.requested_mode are:
	 * 0: Flow control is completely disabled
	 * 1: Rx flow control is enabled (we can receive pause frames,
	 *    but not send pause frames).
	 * 2: Tx flow control is enabled (we can send pause frames but
	 *    we do not support receiving pause frames).
	 * 3: Both Rx and Tx flow control (symmetric) are enabled.
	 * other: Invalid.
	 */
	switch (hw->fc.requested_mode) {
	case txgbe_fc_none:
		/* Flow control completely disabled by software override. */
		break;
	case txgbe_fc_tx_pause:
		/* Tx Flow control is enabled, and Rx Flow control is
		 * disabled by software override.
		 */
		pcap |= TXGBE_SR_MII_MMD_AN_ADV_PAUSE_ASM;
		pcap_backplane |= TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_ASM;
		break;
	case txgbe_fc_rx_pause:
		/* Rx Flow control is enabled and Tx Flow control is
		 * disabled by software override. Since there really
		 * isn't a way to advertise that we are capable of RX
		 * Pause ONLY, we will advertise that we support both
		 * symmetric and asymmetric Rx PAUSE, as such we fall
		 * through to the fc_full statement.  Later, we will
		 * disable the adapter's ability to send PAUSE frames.
		 */
	case txgbe_fc_full:
		/* Flow control (both Rx and Tx) is enabled by SW override. */
		pcap |= TXGBE_SR_MII_MMD_AN_ADV_PAUSE_SYM |
			TXGBE_SR_MII_MMD_AN_ADV_PAUSE_ASM;
		pcap_backplane |= TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_SYM |
			TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_ASM;
		break;
	default:
		ERROR_REPORT1(TXGBE_ERROR_ARGUMENT,
			      "Flow control param set incorrectly\n");
		ret_val = TXGBE_ERR_CONFIG;
		goto out;
	}

	/* Enable auto-negotiation between the MAC & PHY;
	 * the MAC will advertise clause 37 flow control.
	 */
	value = txgbe_rd32_epcs(hw, TXGBE_SR_MII_MMD_AN_ADV);
	value = (value & ~(TXGBE_SR_MII_MMD_AN_ADV_PAUSE_ASM |
		TXGBE_SR_MII_MMD_AN_ADV_PAUSE_SYM)) | pcap;
	txgbe_wr32_epcs(hw, TXGBE_SR_MII_MMD_AN_ADV, value);

	/* AUTOC restart handles negotiation of 1G and 10G on backplane
	 * and copper.
	 */
	if (hw->phy.media_type == txgbe_media_type_backplane) {
		value = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_ADV_REG1);
		value = (value & ~(TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_ASM |
			TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_SYM)) |
			pcap_backplane;
		txgbe_wr32_epcs(hw, TXGBE_SR_AN_MMD_ADV_REG1, value);

	} else if ((hw->phy.media_type == txgbe_media_type_copper) &&
		   (txgbe_device_supports_autoneg_fc(hw))) {
		/* avoid fw access phy */
		if (((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI) &&
		    ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP)) {
			/* Let firmware know the driver has taken over */
			wr32m(hw, TXGBE_CFG_PORT_CTL,
			      TXGBE_CFG_PORT_CTL_DRV_LOAD, TXGBE_CFG_PORT_CTL_DRV_LOAD);

			mdelay(100);
		}

		ret_val = txgbe_set_phy_pause_advertisement(hw, pcap_backplane);

		/* Let firmware take over control of h/w */
		if (((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI) &&
		    ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP))
			wr32m(hw, TXGBE_CFG_PORT_CTL,
			      TXGBE_CFG_PORT_CTL_DRV_LOAD, 0);
	}
out:
	return ret_val;
}

/* txgbe_read_pba_string - Reads part number string from EEPROM
 * @hw: pointer to hardware structure
 * @pba_num: stores the part number string from the EEPROM
 * @pba_num_size: part number string buffer length
 * Reads the part number string from the EEPROM.
 */
int txgbe_read_pba_string(struct txgbe_hw *hw, u8 *pba_num,
			  u32 pba_num_size)
{
	int ret_val;
	u16 data;
	u16 pba_ptr;
	u16 offset;
	u16 length;

	if (!pba_num)
		return TXGBE_ERR_INVALID_ARGUMENT;

	ret_val = txgbe_read_ee_hostif(hw,
			hw->eeprom.sw_region_offset + TXGBE_PBANUM0_PTR,
			&data);
	if (ret_val)
		return ret_val;

	ret_val = txgbe_read_ee_hostif(hw,
			hw->eeprom.sw_region_offset + TXGBE_PBANUM1_PTR,
			&pba_ptr);
	if (ret_val)
		return ret_val;

	/* if data is not ptr guard the PBA must be in legacy format which
	 * means pba_ptr is actually our second data word for the PBA number
	 * and we can decode it into an ascii string
	 */
	if (data != TXGBE_PBANUM_PTR_GUARD) {
		/* we will need 11 characters to store the PBA */
		if (pba_num_size < 11)
			return TXGBE_ERR_NO_SPACE;

		/* extract hex string from data and pba_ptr */
		pba_num[0] = (data >> 12) & 0xF;
		pba_num[1] = (data >> 8) & 0xF;
		pba_num[2] = (data >> 4) & 0xF;
		pba_num[3] = data & 0xF;
		pba_num[4] = (pba_ptr >> 12) & 0xF;
		pba_num[5] = (pba_ptr >> 8) & 0xF;
		pba_num[6] = '-';
		pba_num[7] = 0;
		pba_num[8] = (pba_ptr >> 4) & 0xF;
		pba_num[9] = pba_ptr & 0xF;

		/* put a null character on the end of our string */
		pba_num[10] = '\0';

		/* switch all the data but the '-' to hex char */
		for (offset = 0; offset < 10; offset++) {
			if (pba_num[offset] < 0xA)
				pba_num[offset] += '0';
			else if (pba_num[offset] < 0x10)
				pba_num[offset] += 'A' - 0xA;
		}

		return 0;
	}

	ret_val = txgbe_read_ee_hostif(hw, pba_ptr, &length);
	if (ret_val)
		return ret_val;

	if (length == 0xFFFF || length == 0)
		return TXGBE_ERR_PBA_SECTION;

	/* check if pba_num buffer is big enough */
	if (pba_num_size  < (((u32)length * 2) - 1))
		return TXGBE_ERR_NO_SPACE;

	/* trim pba length from start of string */
	pba_ptr++;
	length--;

	for (offset = 0; offset < length; offset++) {
		ret_val = txgbe_read_ee_hostif(hw, pba_ptr + offset, &data);
		if (ret_val)
			return ret_val;

		pba_num[offset * 2] = (u8)(data >> 8);
		pba_num[(offset * 2) + 1] = (u8)(data & 0xFF);
	}
	pba_num[offset * 2] = '\0';

	return 0;
}

/* txgbe_get_mac_addr - Generic get MAC address
 * @hw: pointer to hardware structure
 * @mac_addr: Adapter MAC address
 * Reads the adapter's MAC address from first Receive Address Register (RAR0)
 * A reset of the adapter must be performed prior to calling this function
 * in order for the MAC address to have been loaded from the EEPROM into RAR0
 */
int txgbe_get_mac_addr(struct txgbe_hw *hw, u8 *mac_addr)
{
	u32 rar_high;
	u32 rar_low;
	u16 i;

	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, 0);
	rar_high = rd32(hw, TXGBE_PSR_MAC_SWC_AD_H);
	rar_low = rd32(hw, TXGBE_PSR_MAC_SWC_AD_L);

	for (i = 0; i < 2; i++)
		mac_addr[i] = (u8)(rar_high >> (1 - i) * 8);

	for (i = 0; i < 4; i++)
		mac_addr[i + 2] = (u8)(rar_low >> (3 - i) * 8);

	return 0;
}

/* txgbe_set_pci_config_data - Generic store PCI bus info
 * @hw: pointer to hardware structure
 * @link_status: the link status returned by the PCI config space
 * * Stores the PCI bus info (speed, width, type) within the txgbe_hw structure
 */
static void txgbe_set_pci_config_data(struct txgbe_hw *hw, u16 link_status)
{
	/* amlite: TODO */
	if (hw->bus.type == txgbe_bus_type_unknown)
		hw->bus.type = txgbe_bus_type_pci_express;

	switch (link_status & TXGBE_PCI_LINK_WIDTH) {
	case TXGBE_PCI_LINK_WIDTH_1:
		hw->bus.width = PCIE_LNK_X1;
		break;
	case TXGBE_PCI_LINK_WIDTH_2:
		hw->bus.width = PCIE_LNK_X2;
		break;
	case TXGBE_PCI_LINK_WIDTH_4:
		hw->bus.width = PCIE_LNK_X4;
		break;
	case TXGBE_PCI_LINK_WIDTH_8:
		hw->bus.width = PCIE_LNK_X8;
		break;
	default:
		hw->bus.width = PCIE_LNK_WIDTH_UNKNOWN;
		break;
	}

	switch (link_status & TXGBE_PCI_LINK_SPEED) {
	case TXGBE_PCI_LINK_SPEED_2500:
		hw->bus.speed = PCIE_SPEED_2_5GT;
		break;
	case TXGBE_PCI_LINK_SPEED_5000:
		hw->bus.speed = PCIE_SPEED_5_0GT;
		break;
	case TXGBE_PCI_LINK_SPEED_8000:
		hw->bus.speed = PCIE_SPEED_8_0GT;
		break;
	default:
		hw->bus.speed = PCI_SPEED_UNKNOWN;
		break;
	}
}

/* txgbe_get_bus_info - Generic set PCI bus info
 * @hw: pointer to hardware structure
 * Gets the PCI bus info (speed, width, type) then calls helper function to
 * store this data within the txgbe_hw structure.
 */
int txgbe_get_bus_info(struct txgbe_hw *hw)
{
	u16 link_status;

	/* Get the negotiated link width and speed from PCI config space */
	link_status = TXGBE_READ_PCIE_WORD(hw, TXGBE_PCI_LINK_STATUS);

	txgbe_set_pci_config_data(hw, link_status);

	return 0;
}

/* txgbe_set_lan_id_multi_port_pcie - Set LAN id for PCIe multiple port devices
 * @hw: pointer to the HW structure
 * Determines the LAN function id by reading memory-mapped registers
 * and swaps the port value if requested.
 */
void txgbe_set_lan_id_multi_port_pcie(struct txgbe_hw *hw)
{
	struct txgbe_bus_info *bus = &hw->bus;
	u32 reg;

	reg = rd32(hw, TXGBE_CFG_PORT_ST);
	bus->lan_id = TXGBE_CFG_PORT_ST_LAN_ID(reg);

	/* check for a port swap */
	reg = rd32(hw, TXGBE_MIS_PWR);
	if (TXGBE_MIS_PWR_LAN_ID(reg) == TXGBE_MIS_PWR_LAN_ID_1)
		bus->func = 0;
	else
		bus->func = bus->lan_id;
}

/**
 *  txgbe_stop_adapter - Generic stop Tx/Rx units
 *  @hw: pointer to hardware structure
 *
 *  Sets the adapter_stopped flag within txgbe_hw struct. Clears interrupts,
 *  disables transmit and receive units. The adapter_stopped flag is used by
 *  the shared code and drivers to determine if the adapter is in a stopped
 *  state and should not touch the hardware.
 **/
int txgbe_stop_adapter(struct txgbe_hw *hw)
{
	u16 i;
	struct txgbe_adapter *adapter = hw->back;

	/*Set the adapter_stopped flag so other driver functions stop touching
	 * the hardware
	 */
	hw->adapter_stopped = true;

	/* Disable the receive unit */
	hw->mac.ops.disable_rx(hw);

	/* Set interrupt mask to stop interrupts from being generated */
	txgbe_intr_disable(hw, TXGBE_INTR_ALL);

	/* Clear any pending interrupts, flush previous writes */
	wr32(hw, TXGBE_PX_MISC_IC, 0xffffffff);
	wr32(hw, TXGBE_BME_CTL, 0x3);

	/* Disable the transmit unit.  Each queue must be disabled. */
	for (i = 0; i < hw->mac.max_tx_queues; i++) {
		wr32m(hw, TXGBE_PX_TR_CFG(i),
		      TXGBE_PX_TR_CFG_SWFLSH | TXGBE_PX_TR_CFG_ENABLE,
			TXGBE_PX_TR_CFG_SWFLSH);
	}

	/* Disable the receive unit by stopping each queue */
	for (i = 0; i < hw->mac.max_rx_queues; i++) {
		wr32m(hw, TXGBE_PX_RR_CFG(i),
		      TXGBE_PX_RR_CFG_RR_EN, 0);
	}

	/* flush all queues disables */
	TXGBE_WRITE_FLUSH(hw);

	/* Prevent the PCI-E bus from hanging by disabling PCI-E master
	 * access and verify no pending requests
	 */
	if (!(adapter->flags2 & TXGBE_FLAG2_ECC_ERR_RESET))
		return txgbe_disable_pcie_master(hw);
	else
		return 0;
}

/**
 *  txgbe_led_on - Turns on the software controllable LEDs.
 *  @hw: pointer to hardware structure
 *  @index: led number to turn on
 **/
int txgbe_led_on(struct txgbe_hw *hw, u32 index)
{
	u32 led_reg = rd32(hw, TXGBE_CFG_LED_CTL);
	u16 value = 0;

	if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI) {
		txgbe_read_mdio(&hw->phy_dev, hw->phy.addr, 31, 0xF021, &value);
		txgbe_write_mdio(&hw->phy_dev, hw->phy.addr, 31, 0xF021, (value & 0xFFFC) | 0x0);
	}
	/* To turn on the LED, set mode to ON. */
	led_reg |= index | (index << TXGBE_CFG_LED_CTL_LINK_OD_SHIFT);
	wr32(hw, TXGBE_CFG_LED_CTL, led_reg);
	TXGBE_WRITE_FLUSH(hw);

	return 0;
}

/**
 *  txgbe_led_off - Turns off the software controllable LEDs.
 *  @hw: pointer to hardware structure
 *  @index: led number to turn off
 **/
int txgbe_led_off(struct txgbe_hw *hw, u32 index)
{
	u32 led_reg = rd32(hw, TXGBE_CFG_LED_CTL);
	u16 value = 0;

	if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI) {
		txgbe_read_mdio(&hw->phy_dev, hw->phy.addr, 31, 0xF021, &value);
		txgbe_write_mdio(&hw->phy_dev, hw->phy.addr, 31, 0xF021, (value & 0xFFFC) | 0x1);
	}

	/* To turn off the LED, set mode to OFF. */
	led_reg &= ~(index << TXGBE_CFG_LED_CTL_LINK_OD_SHIFT);
	led_reg |= index;
	wr32(hw, TXGBE_CFG_LED_CTL, led_reg);
	TXGBE_WRITE_FLUSH(hw);
	return 0;
}

/**
 *  txgbe_release_eeprom_semaphore - Release hardware semaphore
 *  @hw: pointer to hardware structure
 *
 *  This function clears hardware semaphore bits.
 **/
static void txgbe_release_eeprom_semaphore(struct txgbe_hw *hw)
{
	if (txgbe_check_mng_access(hw)) {
		wr32m(hw, TXGBE_MNG_SW_SM,
		      TXGBE_MNG_SW_SM_SM, 0);
		wr32m(hw, TXGBE_MIS_SWSM,
		      TXGBE_MIS_SWSM_SMBI, 0);
		TXGBE_WRITE_FLUSH(hw);
	}
}

/**
 *  txgbe_get_eeprom_semaphore - Get hardware semaphore
 *  @hw: pointer to hardware structure
 *
 *  Sets the hardware semaphores so EEPROM access can occur for bit-bang method
 **/
static int txgbe_get_eeprom_semaphore(struct txgbe_hw *hw)
{
	int status = TXGBE_ERR_EEPROM;
	u32 timeout = 4000;
	u32 i;
	u32 swsm;

	/* Get SMBI software semaphore between device drivers first */
	for (i = 0; i < timeout; i++) {
		/* If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = rd32(hw, TXGBE_MIS_SWSM);
		if (!(swsm & TXGBE_MIS_SWSM_SMBI)) {
			status = 0;
			break;
		}
		usec_delay(50);
	}

	if (i == timeout) {
		/* this release is particularly important because our attempts
		 * above to get the semaphore may have succeeded, and if there
		 * was a timeout, we should unconditionally clear the semaphore
		 * bits to free the driver to make progress
		 */
		txgbe_release_eeprom_semaphore(hw);

		usec_delay(50);
		/* one last try
		 * If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = rd32(hw, TXGBE_MIS_SWSM);
		if (!(swsm & TXGBE_MIS_SWSM_SMBI))
			status = 0;
	}

	/* Now get the semaphore between SW/FW through the SWESMBI bit */
	if (status == 0) {
		for (i = 0; i < timeout; i++) {
			if (txgbe_check_mng_access(hw)) {
			/* Set the SW EEPROM semaphore bit to request access */
				wr32m(hw, TXGBE_MNG_SW_SM,
				      TXGBE_MNG_SW_SM_SM, TXGBE_MNG_SW_SM_SM);

				/* If we set the bit successfully then we got
				 * semaphore.
				 */
				swsm = rd32(hw, TXGBE_MNG_SW_SM);
				if (swsm & TXGBE_MNG_SW_SM_SM)
					break;
			}
			usec_delay(50);
		}

		/* Release semaphores and return error if SW EEPROM semaphore
		 * was not granted because we don't have access to the EEPROM
		 */
		if (i >= timeout) {
			ERROR_REPORT1(TXGBE_ERROR_POLLING,
				      "SWESMBI Software EEPROM semaphore not granted, MNG_SW_SM_SM is 0x%08x.\n",
				swsm);
			txgbe_release_eeprom_semaphore(hw);
			status = TXGBE_ERR_EEPROM;
		}
	} else {
		ERROR_REPORT1(TXGBE_ERROR_POLLING,
			      "Software semaphore SMBI is not granted, MNG_SW_SM_SM is 0x%08x.\n",
				swsm);
	}

	return status;
}


/**
 *  txgbe_validate_mac_addr - Validate MAC address
 *  @mac_addr: pointer to MAC address.
 *
 *  Tests a MAC address to ensure it is a valid Individual Address
 **/
static int txgbe_validate_mac_addr(u8 *mac_addr)
{
	int status = 0;

	/* Make sure it is not a multicast address */
	if (TXGBE_IS_MULTICAST(mac_addr)) {
		status = TXGBE_ERR_INVALID_MAC_ADDR;
	/* Not a broadcast address */
	} else if (TXGBE_IS_BROADCAST(mac_addr)) {
		status = TXGBE_ERR_INVALID_MAC_ADDR;
	/* Reject the zero address */
	} else if (mac_addr[0] == 0 && mac_addr[1] == 0 && mac_addr[2] == 0 &&
		   mac_addr[3] == 0 && mac_addr[4] == 0 && mac_addr[5] == 0) {
		status = TXGBE_ERR_INVALID_MAC_ADDR;
	}
	return status;
}

/**
 *  txgbe_set_rar - Set Rx address register
 *  @hw: pointer to hardware structure
 *  @index: Receive address register to write
 *  @addr: Address to put into receive address register
 *  @pools: VMDq "set" or "pool" index
 *  @enable_addr: set flag that address is active
 *
 *  Puts an ethernet address into a receive address register.
 **/
int txgbe_set_rar(struct txgbe_hw *hw, u32 index, u8 *addr, u64 pools,
		  u32 enable_addr)
{
	u32 rar_low, rar_high;
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (index >= rar_entries) {
		ERROR_REPORT2(TXGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", index);
		return TXGBE_ERR_INVALID_ARGUMENT;
	}

	/* select the MAC address */
	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, index);

	/* setup VMDq pool mapping */
	wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, pools & 0xFFFFFFFF);
	wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, pools >> 32);

	/* HW expects these in little endian so we reverse the byte
	 * order from network order (big endian) to little endian
	 *
	 * Some parts put the VMDq setting in the extra RAH bits,
	 * so save everything except the lower 16 bits that hold part
	 * of the address and the address valid bit.
	 */
	rar_low = ((u32)addr[5] |
		  ((u32)addr[4] << 8) |
		  ((u32)addr[3] << 16) |
		  ((u32)addr[2] << 24));
	rar_high = ((u32)addr[1] |
		   ((u32)addr[0] << 8));
	if (enable_addr != 0)
		rar_high |= TXGBE_PSR_MAC_SWC_AD_H_AV;

	wr32(hw, TXGBE_PSR_MAC_SWC_AD_L, rar_low);
	wr32m(hw, TXGBE_PSR_MAC_SWC_AD_H,
	      (TXGBE_PSR_MAC_SWC_AD_H_AD(~0) |
		 TXGBE_PSR_MAC_SWC_AD_H_ADTYPE(~0) |
		 TXGBE_PSR_MAC_SWC_AD_H_AV),
		rar_high);

	return 0;
}

/**
 *  txgbe_clear_rar - Remove Rx address register
 *  @hw: pointer to hardware structure
 *  @index: Receive address register to write
 *
 *  Clears an ethernet address from a receive address register.
 **/
int txgbe_clear_rar(struct txgbe_hw *hw, u32 index)
{
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (index >= rar_entries) {
		ERROR_REPORT2(TXGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", index);
		return TXGBE_ERR_INVALID_ARGUMENT;
	}

	/* Some parts put the VMDq setting in the extra RAH bits,
	 * so save everything except the lower 16 bits that hold part
	 * of the address and the address valid bit.
	 */
	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, index);

	wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, 0);
	wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, 0);

	wr32(hw, TXGBE_PSR_MAC_SWC_AD_L, 0);
	wr32m(hw, TXGBE_PSR_MAC_SWC_AD_H,
	      (TXGBE_PSR_MAC_SWC_AD_H_AD(~0) |
		 TXGBE_PSR_MAC_SWC_AD_H_ADTYPE(~0) |
		 TXGBE_PSR_MAC_SWC_AD_H_AV),
		0);

	return 0;
}

/**
 *  txgbe_init_rx_addrs - Initializes receive address filters.
 *  @hw: pointer to hardware structure
 *
 *  Places the MAC address in receive address register 0 and clears the rest
 *  of the receive address registers. Clears the multicast table. Assumes
 *  the receiver is in reset when the routine is called.
 **/
int txgbe_init_rx_addrs(struct txgbe_hw *hw)
{
	u32 i;
	u32 rar_entries = hw->mac.num_rar_entries;
	u32 psrctl;

	/* If the current mac address is valid, assume it is a software override
	 * to the permanent address.
	 * Otherwise, use the permanent address from the eeprom.
	 */
	if (txgbe_validate_mac_addr(hw->mac.addr) ==
		TXGBE_ERR_INVALID_MAC_ADDR) {
		/* Get the MAC address from the RAR0 for later reference */
		hw->mac.ops.get_mac_addr(hw, hw->mac.addr);
	} else {
		/* Setup the receive address. */
		hw->mac.ops.set_rar(hw, 0, hw->mac.addr, 0,
			TXGBE_PSR_MAC_SWC_AD_H_AV);
	}
	hw->addr_ctrl.overflow_promisc = 0;

	hw->addr_ctrl.rar_used_count = 1;

	/* Zero out the other receive addresses. */
	for (i = 1; i < rar_entries; i++) {
		wr32(hw, TXGBE_PSR_MAC_SWC_IDX, i);
		wr32(hw, TXGBE_PSR_MAC_SWC_AD_L, 0);
		wr32(hw, TXGBE_PSR_MAC_SWC_AD_H, 0);
	}

	/* Clear the MTA */
	hw->addr_ctrl.mta_in_use = 0;
	psrctl = rd32(hw, TXGBE_PSR_CTL);
	psrctl &= ~(TXGBE_PSR_CTL_MO | TXGBE_PSR_CTL_MFE);
	psrctl |= hw->mac.mc_filter_type << TXGBE_PSR_CTL_MO_SHIFT;
	wr32(hw, TXGBE_PSR_CTL, psrctl);

	for (i = 0; i < hw->mac.mcft_size; i++)
		wr32(hw, TXGBE_PSR_MC_TBL(i), 0);

	hw->mac.ops.init_uta_tables(hw);

	return 0;
}

/**
 *  txgbe_mta_vector - Determines bit-vector in multicast table to set
 *  @hw: pointer to hardware structure
 *  @mc_addr: the multicast address
 *
 *  Extracts the 12 bits, from a multicast address, to determine which
 *  bit-vector to set in the multicast table. The hardware uses 12 bits, from
 *  incoming rx multicast addresses, to determine the bit-vector to check in
 *  the MTA. Which of the 4 combination, of 12-bits, the hardware uses is set
 *  by the MO field of the MCSTCTRL. The MO field is set during initialization
 *  to mc_filter_type.
 **/
static int txgbe_mta_vector(struct txgbe_hw *hw, u8 *mc_addr)
{
	u32 vector = 0;

	switch (hw->mac.mc_filter_type) {
	case 0:   /* use bits [47:36] of the address */
		vector = ((mc_addr[4] >> 4) | (((u16)mc_addr[5]) << 4));
		break;
	case 1:   /* use bits [46:35] of the address */
		vector = ((mc_addr[4] >> 3) | (((u16)mc_addr[5]) << 5));
		break;
	case 2:   /* use bits [45:34] of the address */
		vector = ((mc_addr[4] >> 2) | (((u16)mc_addr[5]) << 6));
		break;
	case 3:   /* use bits [43:32] of the address */
		vector = ((mc_addr[4]) | (((u16)mc_addr[5]) << 8));
		break;
	default:  /* Invalid mc_filter_type */
		WARN_ON(1);
		break;
	}

	/* vector can only be 12-bits or boundary will be exceeded */
	vector &= 0xFFF;
	return vector;
}

/**
 *  txgbe_set_mta - Set bit-vector in multicast table
 *  @hw: pointer to hardware structure
 *  @mc_addr: Multicast address hash value
 *
 *  Sets the bit-vector in the multicast table.
 **/
static void txgbe_set_mta(struct txgbe_hw *hw, u8 *mc_addr)
{
	u32 vector;
	u32 vector_bit;
	u32 vector_reg;

	hw->addr_ctrl.mta_in_use++;

	vector = txgbe_mta_vector(hw, mc_addr);
	/* The MTA is a register array of 128 32-bit registers. It is treated
	 * like an array of 4096 bits.  We want to set bit
	 * BitArray[vector_value]. So we figure out what register the bit is
	 * in, read it, OR in the new bit, then write back the new value.  The
	 * register is determined by the upper 7 bits of the vector value and
	 * the bit within that register are determined by the lower 5 bits of
	 * the value.
	 */
	vector_reg = (vector >> 5) & 0x7F;
	vector_bit = vector & 0x1F;
	hw->mac.mta_shadow[vector_reg] |= (1 << vector_bit);
}

/**
 *  txgbe_update_mc_addr_list - Updates MAC list of multicast addresses
 *  @hw: pointer to hardware structure
 *  @mc_addr_list: the list of new multicast addresses
 *  @mc_addr_count: number of addresses
 *  @next: iterator function to walk the multicast address list
 *  @clear: flag, when set clears the table beforehand
 *
 *  When the clear flag is set, the given list replaces any existing list.
 *  Hashes the given addresses into the multicast table.
 **/
int txgbe_update_mc_addr_list(struct txgbe_hw *hw, u8 *mc_addr_list,
			      u32 mc_addr_count, txgbe_mc_addr_itr next,
				      bool clear)
{
	u32 i;
	u32 vmdq;
	u32 psrctl;

	/* Set the new number of MC addresses that we
	 * are being requested to use.
	 */
	hw->addr_ctrl.num_mc_addrs = mc_addr_count;
	hw->addr_ctrl.mta_in_use = 0;

	/* Clear mta_shadow */
	if (clear)
		memset(&hw->mac.mta_shadow, 0, sizeof(hw->mac.mta_shadow));

	/* Update mta_shadow */
	for (i = 0; i < mc_addr_count; i++)
		txgbe_set_mta(hw, next(hw, &mc_addr_list, &vmdq));

	/* Enable mta */
	for (i = 0; i < hw->mac.mcft_size; i++)
		wr32a(hw, TXGBE_PSR_MC_TBL(0), i,
		      hw->mac.mta_shadow[i]);

	if (hw->addr_ctrl.mta_in_use > 0) {
		psrctl = rd32(hw, TXGBE_PSR_CTL);
		psrctl &= ~(TXGBE_PSR_CTL_MO | TXGBE_PSR_CTL_MFE);
		psrctl |= TXGBE_PSR_CTL_MFE |
			(hw->mac.mc_filter_type << TXGBE_PSR_CTL_MO_SHIFT);
		wr32(hw, TXGBE_PSR_CTL, psrctl);
	}

	return 0;
}


/**
 *  txgbe_negotiate_fc - Negotiate flow control
 *  @hw: pointer to hardware structure
 *  @adv_reg: flow control advertised settings
 *  @lp_reg: link partner's flow control settings
 *  @adv_sym: symmetric pause bit in advertisement
 *  @adv_asm: asymmetric pause bit in advertisement
 *  @lp_sym: symmetric pause bit in link partner advertisement
 *  @lp_asm: asymmetric pause bit in link partner advertisement
 *
 *  Find the intersection between advertised settings and link partner's
 *  advertised settings
 **/
static int txgbe_negotiate_fc(struct txgbe_hw *hw, u32 adv_reg, u32 lp_reg,
			      u32 adv_sym, u32 adv_asm, u32 lp_sym, u32 lp_asm)
{
	if ((!(adv_reg)) ||  (!(lp_reg)))
		return TXGBE_ERR_FC_NOT_NEGOTIATED;

	if ((adv_reg & adv_sym) && (lp_reg & lp_sym)) {
		if (hw->fc.requested_mode == txgbe_fc_full)
			hw->fc.current_mode = txgbe_fc_full;
		else
			hw->fc.current_mode = txgbe_fc_rx_pause;
	} else if (!(adv_reg & adv_sym) && (adv_reg & adv_asm) &&
		   (lp_reg & lp_sym) && (lp_reg & lp_asm)) {
		hw->fc.current_mode = txgbe_fc_tx_pause;
	} else if ((adv_reg & adv_sym) && (adv_reg & adv_asm) &&
		   !(lp_reg & lp_sym) && (lp_reg & lp_asm)) {
		hw->fc.current_mode = txgbe_fc_rx_pause;
	} else {
		hw->fc.current_mode = txgbe_fc_none;
	}
	return 0;
}

/**
 *  txgbe_fc_autoneg_fiber - Enable flow control on 1 gig fiber
 *  @hw: pointer to hardware structure
 *
 *  Enable flow control according on 1 gig fiber.
 **/
static int txgbe_fc_autoneg_fiber(struct txgbe_hw *hw)
{
	u32 pcs_anadv_reg, pcs_lpab_reg;
	int ret_val = TXGBE_ERR_FC_NOT_NEGOTIATED;

	pcs_anadv_reg = txgbe_rd32_epcs(hw, TXGBE_SR_MII_MMD_AN_ADV);
	pcs_lpab_reg = txgbe_rd32_epcs(hw, TXGBE_SR_MII_MMD_LP_BABL);

	ret_val =  txgbe_negotiate_fc(hw, pcs_anadv_reg,
				      pcs_lpab_reg,
				      TXGBE_SR_MII_MMD_AN_ADV_PAUSE_SYM,
				      TXGBE_SR_MII_MMD_AN_ADV_PAUSE_ASM,
				      TXGBE_SR_MII_MMD_AN_ADV_PAUSE_SYM,
				      TXGBE_SR_MII_MMD_AN_ADV_PAUSE_ASM);

	return ret_val;
}

/**
 *  txgbe_fc_autoneg_backplane - Enable flow control IEEE clause 37
 *  @hw: pointer to hardware structure
 *
 *  Enable flow control according to IEEE clause 37.
 **/
static int txgbe_fc_autoneg_backplane(struct txgbe_hw *hw)
{
	u32 anlp1_reg, autoc_reg;
	int ret_val = TXGBE_ERR_FC_NOT_NEGOTIATED;

	/* Read the 10g AN autoc and LP ability registers and resolve
	 * local flow control settings accordingly
	 */
	autoc_reg = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_ADV_REG1);
	anlp1_reg = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_LP_ABL1);

	ret_val = txgbe_negotiate_fc(hw, autoc_reg,
				     anlp1_reg, TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_SYM,
		TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_ASM,
		TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_SYM,
		TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_ASM);

	return ret_val;
}

/**
 *  txgbe_fc_autoneg_copper - Enable flow control IEEE clause 37
 *  @hw: pointer to hardware structure
 *
 *  Enable flow control according to IEEE clause 37.
 **/
static int txgbe_fc_autoneg_copper(struct txgbe_hw *hw)
{
	u8 technology_ability_reg = 0;
	u8 lp_technology_ability_reg = 0;

	txgbe_get_phy_advertised_pause(hw, &technology_ability_reg);
	txgbe_get_lp_advertised_pause(hw, &lp_technology_ability_reg);

	return txgbe_negotiate_fc(hw, (u32)technology_ability_reg,
				  (u32)lp_technology_ability_reg,
				  TXGBE_TAF_SYM_PAUSE, TXGBE_TAF_ASM_PAUSE,
				  TXGBE_TAF_SYM_PAUSE, TXGBE_TAF_ASM_PAUSE);
}

/**
 *  txgbe_fc_autoneg - Configure flow control
 *  @hw: pointer to hardware structure
 *
 *  Compares our advertised flow control capabilities to those advertised by
 *  our link partner, and determines the proper flow control mode to use.
 **/
static void txgbe_fc_autoneg(struct txgbe_hw *hw)
{
	int ret_val = TXGBE_ERR_FC_NOT_NEGOTIATED;
	u32 speed;
	bool link_up = 0;

	/* AN should have completed when the cable was plugged in.
	 * Look for reasons to bail out.  Bail out if:
	 * - FC autoneg is disabled, or if
	 * - link is not up.
	 */
	if (hw->fc.disable_fc_autoneg) {
		ERROR_REPORT1(TXGBE_ERROR_UNSUPPORTED,
			      "Flow control autoneg is disabled");
		goto out;
	}

	hw->mac.ops.check_link(hw, &speed, &link_up, false);
	if (!link_up) {
		ERROR_REPORT1(TXGBE_ERROR_SOFTWARE, "The link is down");
		goto out;
	}

	switch (hw->phy.media_type) {
	/* Autoneg flow control on fiber adapters */
	case txgbe_media_type_fiber:
		if (speed == TXGBE_LINK_SPEED_1GB_FULL)
			ret_val = txgbe_fc_autoneg_fiber(hw);
		break;

	/* Autoneg flow control on backplane adapters */
	case txgbe_media_type_backplane:
		ret_val = txgbe_fc_autoneg_backplane(hw);
		break;

	/* Autoneg flow control on copper adapters */
	case txgbe_media_type_copper:
		if (txgbe_device_supports_autoneg_fc(hw))
			ret_val = txgbe_fc_autoneg_copper(hw);
		break;

	default:
		break;
	}

out:
	if (ret_val == 0) {
		hw->fc.fc_was_autonegged = true;
	} else {
		hw->fc.fc_was_autonegged = false;
		hw->fc.current_mode = hw->fc.requested_mode;
	}
}

/**
 *  txgbe_fc_enable - Enable flow control
 *  @hw: pointer to hardware structure
 *
 *  Enable flow control according to the current settings.
 **/
int txgbe_fc_enable(struct txgbe_hw *hw)
{
	u32 mflcn_reg = 0;
	u32 fccfg_reg = 0;
	int ret_val = 0;
	u32 fcrtl = 0;
	u32 fcrth = 0;
	u32 reg = 0;
	int i = 0;

	/* Validate the water mark configuration */
	if (!hw->fc.pause_time) {
		ret_val = TXGBE_ERR_INVALID_LINK_SETTINGS;
		goto out;
	}

	/* Low water mark of zero causes XOFF floods */
	for (i = 0; i < TXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		if ((hw->fc.current_mode & txgbe_fc_tx_pause) &&
		    hw->fc.high_water[i]) {
			if (!hw->fc.low_water[i] ||
			    hw->fc.low_water[i] >= hw->fc.high_water[i]) {
				ret_val = TXGBE_ERR_INVALID_LINK_SETTINGS;
				goto out;
			}
		}
	}

	/* Negotiate the fc mode to use */
	txgbe_fc_autoneg(hw);

	/* Disable any previous flow control settings */
	mflcn_reg = rd32(hw, TXGBE_MAC_RX_FLOW_CTRL);
	mflcn_reg &= ~(TXGBE_MAC_RX_FLOW_CTRL_PFCE |
		TXGBE_MAC_RX_FLOW_CTRL_RFE);

	fccfg_reg = rd32(hw, TXGBE_RDB_RFCC);
	fccfg_reg &= ~(TXGBE_RDB_RFCC_RFCE_802_3X |
		TXGBE_RDB_RFCC_RFCE_PRIORITY);

	/* The possible values of fc.current_mode are:
	 * 0: Flow control is completely disabled
	 * 1: Rx flow control is enabled (we can receive pause frames,
	 *    but not send pause frames).
	 * 2: Tx flow control is enabled (we can send pause frames but
	 *    we do not support receiving pause frames).
	 * 3: Both Rx and Tx flow control (symmetric) are enabled.
	 * other: Invalid.
	 */
	switch (hw->fc.current_mode) {
	case txgbe_fc_none:
		/* Flow control is disabled by software override or autoneg.
		 * The code below will actually disable it in the HW.
		 */
		break;
	case txgbe_fc_rx_pause:
		/* Rx Flow control is enabled and Tx Flow control is
		 * disabled by software override. Since there really
		 * isn't a way to advertise that we are capable of RX
		 * Pause ONLY, we will advertise that we support both
		 * symmetric and asymmetric Rx PAUSE.  Later, we will
		 * disable the adapter's ability to send PAUSE frames.
		 */
		mflcn_reg |= TXGBE_MAC_RX_FLOW_CTRL_RFE;
		break;
	case txgbe_fc_tx_pause:
		/* Tx Flow control is enabled, and Rx Flow control is
		 * disabled by software override.
		 */
		fccfg_reg |= TXGBE_RDB_RFCC_RFCE_802_3X;
		break;
	case txgbe_fc_full:
		/* Flow control (both Rx and Tx) is enabled by SW override. */
		mflcn_reg |= TXGBE_MAC_RX_FLOW_CTRL_RFE;
		fccfg_reg |= TXGBE_RDB_RFCC_RFCE_802_3X;
		break;
	default:
		ERROR_REPORT1(TXGBE_ERROR_ARGUMENT,
			      "Flow control param set incorrectly\n");
		ret_val = TXGBE_ERR_CONFIG;
		goto out;
	}

	/* Set 802.3x based flow control settings. */
	wr32(hw, TXGBE_MAC_RX_FLOW_CTRL, mflcn_reg);
	wr32(hw, TXGBE_RDB_RFCC, fccfg_reg);

	/* Set up and enable Rx high/low water mark thresholds, enable XON. */
	for (i = 0; i < TXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		if ((hw->fc.current_mode & txgbe_fc_tx_pause) &&
		    hw->fc.high_water[i]) {
			fcrtl = (hw->fc.low_water[i] << 10);
			if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40)
				fcrtl |= TXGBE_RDB_RFCL_XONE;
			wr32(hw, TXGBE_RDB_RFCL(i), fcrtl);
			fcrth = (hw->fc.high_water[i] << 10) |
				TXGBE_RDB_RFCH_XOFFE;
		} else {
			wr32(hw, TXGBE_RDB_RFCL(i), 0);
			/* In order to prevent Tx hangs when the internal Tx
			 * switch is enabled we must set the high water mark
			 * to the Rx packet buffer size - 24KB.  This allows
			 * the Tx switch to function even under heavy Rx
			 * workloads.
			 */
			fcrth = rd32(hw, TXGBE_RDB_PB_SZ(i)) - 24576;
		}

		wr32(hw, TXGBE_RDB_RFCH(i), fcrth);
	}

	/* Configure pause time (2 TCs per register) */
	reg = hw->fc.pause_time * 0x00010001;
	for (i = 0; i < (TXGBE_DCB_MAX_TRAFFIC_CLASS / 2); i++)
		wr32(hw, TXGBE_RDB_RFCV(i), reg);

	/* Configure flow control refresh threshold value */
	wr32(hw, TXGBE_RDB_RFCRT, hw->fc.pause_time / 2);

out:
	return ret_val;
}

/**
 *  txgbe_disable_pcie_master - Disable PCI-express master access
 *  @hw: pointer to hardware structure
 *
 *  Disables PCI-Express master access and verifies there are no pending
 *  requests. TXGBE_ERR_MASTER_REQUESTS_PENDING is returned if master disable
 *  bit hasn't caused the master requests to be disabled, else 0
 *  is returned signifying master requests disabled.
 **/
int txgbe_disable_pcie_master(struct txgbe_hw *hw)
{
	int status = 0;
	u32 i;
	struct txgbe_adapter *adapter = hw->back;
	unsigned int num_vfs = adapter->num_vfs;
	u16 dev_ctl;
	u32 vf_bme_clear = 0;
	u16 vid = 0;
	u16 cmd = 0;
	u32 reg32 = 0;

	/* Always set this bit to ensure any future transactions are blocked */
	pci_clear_master(((struct txgbe_adapter *)hw->back)->pdev);

	/* Exit if master requests are blocked */
	if (!(rd32(hw, TXGBE_PX_TRANSACTION_PENDING)) ||
	    TXGBE_REMOVED(hw->hw_addr))
		goto out;

	/* BME disable handshake will not be finished if any VF BME is 0 */
	for (i = 0; i < num_vfs; i++) {
		struct pci_dev *vfdev = NULL;

		if (!adapter->vfinfo)
			break;
		vfdev = adapter->vfinfo[i].vfdev;
		if (!vfdev)
			continue;
		pci_read_config_word(vfdev, 0x4, &dev_ctl);
		if ((dev_ctl & 0x4) == 0) {
			vf_bme_clear = 1;
			break;
		}
	}

	/* Poll for master request bit to clear */
	for (i = 0; i < TXGBE_PCI_MASTER_DISABLE_TIMEOUT; i++) {
		usec_delay(100);
		if (!(rd32(hw, TXGBE_PX_TRANSACTION_PENDING)))
			goto out;
	}

	if (!vf_bme_clear) {
		ERROR_REPORT1(TXGBE_ERROR_POLLING,
			      "PCIe transaction pending bit did not clear.\n");
		status = TXGBE_ERR_MASTER_REQUESTS_PENDING;

		/* print out PCI configuration space value */
		txgbe_print_tx_hang_status(adapter);
		pci_read_config_word(adapter->pdev, PCI_VENDOR_ID, &vid);
		ERROR_REPORT1(TXGBE_ERROR_POLLING, "PCI VID is 0x%x\n", vid);

		pci_read_config_word(adapter->pdev, PCI_COMMAND, &cmd);
		ERROR_REPORT1(TXGBE_ERROR_POLLING, "PCI COMMAND value is 0x%x.\n", cmd);

		reg32 = rd32(hw, 0x10000);
		ERROR_REPORT1(TXGBE_ERROR_POLLING, "read 0x10000 value is 0x%08x\n", reg32);
	}

out:
	return status;
}

/**
 *  txgbe_acquire_swfw_sync - Acquire SWFW semaphore
 *  @hw: pointer to hardware structure
 *  @mask: Mask to specify which semaphore to acquire
 *
 *  Acquires the SWFW semaphore through the GSSR register for the specified
 *  function (CSR, PHY0, PHY1, EEPROM, Flash)
 **/
int txgbe_acquire_swfw_sync(struct txgbe_hw *hw, u32 mask)
{
	u32 gssr = 0;
	u32 swmask = mask;
	u32 fwmask = mask << 16;
	u32 timeout = 200;
	u32 i;

	for (i = 0; i < timeout; i++) {
		/* SW NVM semaphore bit is used for access to all
		 * SW_FW_SYNC bits (not just NVM)
		 */
		if (txgbe_get_eeprom_semaphore(hw))
			return TXGBE_ERR_SWFW_SYNC;

		if (txgbe_check_mng_access(hw)) {
			gssr = rd32(hw, TXGBE_MNG_SWFW_SYNC);
			if (gssr & (fwmask | swmask)) {
				/* Resource is currently in use by FW or SW */
				txgbe_release_eeprom_semaphore(hw);
				msec_delay(5);
			} else {
				gssr |= swmask;
				wr32(hw, TXGBE_MNG_SWFW_SYNC, gssr);
				txgbe_release_eeprom_semaphore(hw);
				return 0;
			}
		}
	}

	/* If time expired clear the bits holding the lock and retry */
	if (gssr & (fwmask | swmask))
		txgbe_release_swfw_sync(hw, gssr & (fwmask | swmask));

	msec_delay(5);
	return TXGBE_ERR_SWFW_SYNC;
}

/**
 *  txgbe_release_swfw_sync - Release SWFW semaphore
 *  @hw: pointer to hardware structure
 *  @mask: Mask to specify which semaphore to release
 *
 *  Releases the SWFW semaphore through the GSSR register for the specified
 *  function (CSR, PHY0, PHY1, EEPROM, Flash)
 **/
void txgbe_release_swfw_sync(struct txgbe_hw *hw, u32 mask)
{
	txgbe_get_eeprom_semaphore(hw);
	if (txgbe_check_mng_access(hw))
		wr32m(hw, TXGBE_MNG_SWFW_SYNC, mask, 0);

	txgbe_release_eeprom_semaphore(hw);
}

/**
 *  txgbe_disable_sec_rx_path - Stops the receive data path
 *  @hw: pointer to hardware structure
 *
 *  Stops the receive data path and waits for the HW to internally empty
 *  the Rx security block
 **/
int txgbe_disable_sec_rx_path(struct txgbe_hw *hw)
{
#define TXGBE_MAX_SECRX_POLL 40
	int i;
	int secrxreg;

	wr32m(hw, TXGBE_RSC_CTL,
	      TXGBE_RSC_CTL_RX_DIS, TXGBE_RSC_CTL_RX_DIS);
	for (i = 0; i < TXGBE_MAX_SECRX_POLL; i++) {
		secrxreg = rd32(hw, TXGBE_RSC_ST);
		if (!(secrxreg & TXGBE_RSC_ST_RSEC_RDY))
			usec_delay(1000);
		else
			break;
	}

	return 0;
}

/**
 *  txgbe_enable_sec_rx_path - Enables the receive data path
 *  @hw: pointer to hardware structure
 *
 *  Enables the receive data path.
 **/
int txgbe_enable_sec_rx_path(struct txgbe_hw *hw)
{
	wr32m(hw, TXGBE_RSC_CTL,
	      TXGBE_RSC_CTL_RX_DIS, 0);
	TXGBE_WRITE_FLUSH(hw);

	return 0;
}

/**
 *  txgbe_disable_sec_tx_path - Stops the transmit data path
 *  @hw: pointer to hardware structure
 *
 *  Stops the transmit data path and waits for the HW to internally empty
 *  the tx security block
 **/
int txgbe_disable_sec_tx_path(struct txgbe_hw *hw)
{
#define TXGBE_MAX_SECTX_POLL 40

	int i;
	int secrxreg;

	wr32m(hw, TXGBE_TSC_CTL,
	      TXGBE_TSC_CTL_TX_DIS, TXGBE_TSC_CTL_TX_DIS);
	for (i = 0; i < TXGBE_MAX_SECTX_POLL; i++) {
		secrxreg = rd32(hw, TXGBE_TSC_ST);
		if (!(secrxreg & TXGBE_TSC_ST_SECTX_RDY))
			usec_delay(1000);
		else
			break;
	}

	return 0;
}

/**
 *  txgbe_enable_sec_tx_path - Enables the transmit data path
 *  @hw: pointer to hardware structure
 *
 *  Enables the transmit data path.
 **/
int txgbe_enable_sec_tx_path(struct txgbe_hw *hw)
{
	wr32m(hw, TXGBE_TSC_CTL,
	      TXGBE_TSC_CTL_TX_DIS, 0);
	TXGBE_WRITE_FLUSH(hw);

	return 0;
}




/**
 *  txgbe_set_vmdq_san_mac - Associate default VMDq pool index with a rx address
 *  @hw: pointer to hardware struct
 *  @vmdq: VMDq pool index
 *
 *  This function should only be involved in the IOV mode.
 *  In IOV mode, Default pool is next pool after the number of
 *  VFs advertized and not 0.
 *  MPSAR table needs to be updated for SAN_MAC RAR [hw->mac.san_mac_rar_index]
 **/
int txgbe_set_vmdq_san_mac(struct txgbe_hw *hw, u32 vmdq)
{
	u32 rar = hw->mac.san_mac_rar_index;

	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, rar);
	if (vmdq < 32) {
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, 1 << vmdq);
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, 0);
	} else {
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, 0);
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, 1 << (vmdq - 32));
	}

	return 0;
}

/**
 *  txgbe_init_uta_tables - Initialize the Unicast Table Array
 *  @hw: pointer to hardware structure
 **/
int txgbe_init_uta_tables(struct txgbe_hw *hw)
{
	int i;

	for (i = 0; i < 128; i++)
		wr32(hw, TXGBE_PSR_UC_TBL(i), 0);

	return 0;
}

/**
 *  txgbe_find_vlvf_slot - find the vlanid or the first empty slot
 *  @hw: pointer to hardware structure
 *  @vlan: VLAN id to write to VLAN filter
 *
 *  return the VLVF index where this VLAN id should be placed
 *
 **/
static int txgbe_find_vlvf_slot(struct txgbe_hw *hw, u32 vlan)
{
	u32 bits = 0;
	u32 first_empty_slot = 0;
	int regindex;

	/* short cut the special case */
	if (vlan == 0)
		return 0;

	/* Search for the vlan id in the VLVF entries. Save off the first empty
	 * slot found along the way
	 */
	for (regindex = 1; regindex < TXGBE_PSR_VLAN_SWC_ENTRIES; regindex++) {
		wr32(hw, TXGBE_PSR_VLAN_SWC_IDX, regindex);
		bits = rd32(hw, TXGBE_PSR_VLAN_SWC);
		if (!bits && !(first_empty_slot))
			first_empty_slot = regindex;
		else if ((bits & 0x0FFF) == vlan)
			break;
	}

	/* If regindex is less than TXGBE_VLVF_ENTRIES, then we found the vlan
	 * in the VLVF. Else use the first empty VLVF register for this
	 * vlan id.
	 */
	if (regindex >= TXGBE_PSR_VLAN_SWC_ENTRIES) {
		if (first_empty_slot) {
			regindex = first_empty_slot;
		} else {
			ERROR_REPORT1(TXGBE_ERROR_SOFTWARE,
				      "No space in VLVF.\n");
			regindex = TXGBE_ERR_NO_SPACE;
		}
	}

	return regindex;
}

/**
 *  txgbe_set_vlvf - Set VLAN Pool Filter
 *  @hw: pointer to hardware structure
 *  @vlan: VLAN id to write to VLAN filter
 *  @vind: VMDq output index that maps queue to VLAN id in VFVFB
 *  @vlan_on: boolean flag to turn on/off VLAN in VFVF
 *  @vfta_changed: pointer to boolean flag which indicates whether VFTA
 *                 should be changed
 *
 *  Turn on/off specified bit in VLVF table.
 **/
static int txgbe_set_vlvf(struct txgbe_hw *hw, u32 vlan, u32 vind,
			  bool vlan_on, bool *vfta_changed)
{
	u32 vt;

	if (vlan > 4095)
		return TXGBE_ERR_PARAM;

	/* If VT Mode is set
	 *   Either vlan_on
	 *     make sure the vlan is in VLVF
	 *     set the vind bit in the matching VLVFB
	 *   Or !vlan_on
	 *     clear the pool bit and possibly the vind
	 */
	vt = rd32(hw, TXGBE_CFG_PORT_CTL);
	if (vt & TXGBE_CFG_PORT_CTL_NUM_VT_MASK) {
		int vlvf_index;
		u32 bits;

		vlvf_index = txgbe_find_vlvf_slot(hw, vlan);
		if (vlvf_index < 0)
			return vlvf_index;

		wr32(hw, TXGBE_PSR_VLAN_SWC_IDX, vlvf_index);
		if (vlan_on) {
			/* set the pool bit */
			if (vind < 32) {
				bits = rd32(hw,
					    TXGBE_PSR_VLAN_SWC_VM_L);
				bits |= (1 << vind);
				wr32(hw,
				     TXGBE_PSR_VLAN_SWC_VM_L,
						bits);
			} else {
				bits = rd32(hw,
					    TXGBE_PSR_VLAN_SWC_VM_H);
				bits |= (1 << (vind - 32));
				wr32(hw,
				     TXGBE_PSR_VLAN_SWC_VM_H,
					bits);
			}
		} else {
			/* clear the pool bit */
			if (vind < 32) {
				bits = rd32(hw,
					    TXGBE_PSR_VLAN_SWC_VM_L);
				bits &= ~(1 << vind);
				wr32(hw,
				     TXGBE_PSR_VLAN_SWC_VM_L,
						bits);
				bits |= rd32(hw,
					TXGBE_PSR_VLAN_SWC_VM_H);
			} else {
				bits = rd32(hw,
					    TXGBE_PSR_VLAN_SWC_VM_H);
				bits &= ~(1 << (vind - 32));
				wr32(hw,
				     TXGBE_PSR_VLAN_SWC_VM_H,
					bits);
				bits |= rd32(hw,
						TXGBE_PSR_VLAN_SWC_VM_L);
			}
		}

		/* If there are still bits set in the VLVFB registers
		 * for the VLAN ID indicated we need to see if the
		 * caller is requesting that we clear the VFTA entry bit.
		 * If the caller has requested that we clear the VFTA
		 * entry bit but there are still pools/VFs using this VLAN
		 * ID entry then ignore the request.  We're not worried
		 * about the case where we're turning the VFTA VLAN ID
		 * entry bit on, only when requested to turn it off as
		 * there may be multiple pools and/or VFs using the
		 * VLAN ID entry.  In that case we cannot clear the
		 * VFTA bit until all pools/VFs using that VLAN ID have also
		 * been cleared.  This will be indicated by "bits" being
		 * zero.
		 */
		if (bits) {
			wr32(hw, TXGBE_PSR_VLAN_SWC,
			     (TXGBE_PSR_VLAN_SWC_VIEN | vlan));
			if (!vlan_on && !vfta_changed) {
				/* someone wants to clear the vfta entry
				 * but some pools/VFs are still using it.
				 * Ignore it.
				 */
				*vfta_changed = false;
			}
		} else {
			wr32(hw, TXGBE_PSR_VLAN_SWC, 0);
		}
	}

	return 0;
}

/**
 *  txgbe_set_vfta - Set VLAN filter table
 *  @hw: pointer to hardware structure
 *  @vlan: VLAN id to write to VLAN filter
 *  @vind: VMDq output index that maps queue to VLAN id in VFVFB
 *  @vlan_on: boolean flag to turn on/off VLAN in VFVF
 *
 *  Turn on/off specified VLAN in the VLAN filter table.
 **/
int txgbe_set_vfta(struct txgbe_hw *hw, u32 vlan, u32 vind,
		   bool vlan_on)
{
	int regindex;
	u32 bitindex;
	u32 vfta;
	u32 targetbit;
	int ret_val = 0;
	bool vfta_changed = false;

	if (vlan > 4095)
		return TXGBE_ERR_PARAM;

	regindex = (vlan >> 5) & 0x7F;
	bitindex = vlan & 0x1F;
	targetbit = (1 << bitindex);
	vfta = rd32(hw, TXGBE_PSR_VLAN_TBL(regindex));
	if (vlan_on) {
		if (!(vfta & targetbit)) {
			vfta |= targetbit;
			vfta_changed = true;
		}
	} else {
		if ((vfta & targetbit)) {
			vfta &= ~targetbit;
			vfta_changed = true;
		}
	}

	/* Part 2
	 * Call txgbe_set_vlvf to set VLVFB and VLVF
	 */
	ret_val = txgbe_set_vlvf(hw, vlan, vind, vlan_on,
				 &vfta_changed);
	if (ret_val != 0)
		return ret_val;

	if (vfta_changed)
		wr32(hw, TXGBE_PSR_VLAN_TBL(regindex), vfta);
	return 0;
}

/**
 *  txgbe_clear_vfta - Clear VLAN filter table
 *  @hw: pointer to hardware structure
 *
 *  Clears the VLAN filer table, and the VMDq index associated with the filter
 **/
int txgbe_clear_vfta(struct txgbe_hw *hw)
{
	u32 offset;

	for (offset = 0; offset < hw->mac.vft_size; offset++) {
		wr32(hw, TXGBE_PSR_VLAN_TBL(offset), 0);
	}

	for (offset = 0; offset < TXGBE_PSR_VLAN_SWC_ENTRIES; offset++) {
		wr32(hw, TXGBE_PSR_VLAN_SWC_IDX, offset);
		wr32(hw, TXGBE_PSR_VLAN_SWC, 0);
		wr32(hw, TXGBE_PSR_VLAN_SWC_VM_L, 0);
		wr32(hw, TXGBE_PSR_VLAN_SWC_VM_H, 0);
	}

	return 0;
}

/**
 *  txgbe_set_vlan_anti_spoofing - Enable/Disable VLAN anti-spoofing
 *  @hw: pointer to hardware structure
 *  @enable: enable or disable switch for VLAN anti-spoofing
 *  @vf: Virtual Function pool - VF Pool to set for VLAN anti-spoofing
 *
 **/
void txgbe_set_vlan_anti_spoofing(struct txgbe_hw *hw, bool enable, int vf)
{
	u32 pfvfspoof;

	if (vf < 32) {
		pfvfspoof = rd32(hw, TXGBE_TDM_VLAN_AS_L);
		if (enable)
			pfvfspoof |= (1 << vf);
		else
			pfvfspoof &= ~(1 << vf);
		wr32(hw, TXGBE_TDM_VLAN_AS_L, pfvfspoof);
	} else {
		pfvfspoof = rd32(hw, TXGBE_TDM_VLAN_AS_H);
		if (enable)
			pfvfspoof |= (1 << (vf - 32));
		else
			pfvfspoof &= ~(1 << (vf - 32));
		wr32(hw, TXGBE_TDM_VLAN_AS_H, pfvfspoof);
	}
}

/**
 *  txgbe_set_ethertype_anti_spoofing - Enable/Disable Ethertype anti-spoofing
 *  @hw: pointer to hardware structure
 *  @enable: enable or disable switch for Ethertype anti-spoofing
 *  @vf: Virtual Function pool - VF Pool to set for Ethertype anti-spoofing
 *
 **/
void txgbe_set_ethertype_anti_spoofing(struct txgbe_hw *hw,
				       bool enable, int vf)
{
	u32 pfvfspoof;

	if (vf < 32) {
		pfvfspoof = rd32(hw, TXGBE_TDM_ETYPE_AS_L);
		if (enable)
			pfvfspoof |= (1 << vf);
		else
			pfvfspoof &= ~(1 << vf);
		wr32(hw, TXGBE_TDM_ETYPE_AS_L, pfvfspoof);
	} else {
		pfvfspoof = rd32(hw, TXGBE_TDM_ETYPE_AS_H);
		if (enable)
			pfvfspoof |= (1 << (vf - 32));
		else
			pfvfspoof &= ~(1 << (vf - 32));
		wr32(hw, TXGBE_TDM_ETYPE_AS_H, pfvfspoof);
	}
}

/**
 *  txgbe_calculate_checksum - Calculate checksum for buffer
 *  @buffer: pointer to EEPROM
 *  @length: size of EEPROM to calculate a checksum for
 *  Calculates the checksum for some buffer on a specified length.  The
 *  checksum calculated is returned.
 **/
static u8 txgbe_calculate_checksum(u8 *buffer, u32 length)
{
	u32 i;
	u8 sum = 0;

	if (!buffer)
		return 0;

	for (i = 0; i < length; i++)
		sum += buffer[i];

	return (0 - sum);
}

/**
 *  txgbe_host_interface_command - Issue command to manageability block
 *  @hw: pointer to the HW structure
 *  @buffer: contains the command to write and where the return status will
 *   be placed
 *  @length: length of buffer, must be multiple of 4 bytes
 *  @timeout: time in ms to wait for command completion
 *  @return_data: read and return data from the buffer (true) or not (false)
 *   Needed because FW structures are big endian and decoding of
 *   these fields can be 8 bit or 16 bit based on command. Decoding
 *   is not easily understood without making a table of commands.
 *   So we will leave this up to the caller to read back the data
 *   in these cases.
 *
 *  Communicates with the manageability block.  On success return 0
 *  else return TXGBE_ERR_HOST_INTERFACE_COMMAND.
 **/
int txgbe_host_interface_command(struct txgbe_hw *hw, u32 *buffer,
				 u32 length, u32 timeout, bool return_data)
{
	struct txgbe_adapter *adapter = (struct txgbe_adapter *)hw->back;
	struct txgbe_hic_hdr *send_hdr = (struct txgbe_hic_hdr *)buffer;
	u32 hdr_size = sizeof(struct txgbe_hic_hdr);
	struct txgbe_hic_hdr *recv_hdr;
	u32 buf[64] = {};
	u32 hicr, i, bi;
	int status = 0;
	u32 dword_len;
	u16 buf_len;
	u8 send_cmd;

	if (length == 0 || length > TXGBE_HI_MAX_BLOCK_BYTE_LENGTH) {
		ERROR_REPORT1(TXGBE_ERROR_CAUTION,
			      "Buffer length failure buffersize=%d.\n", length);
		return TXGBE_ERR_HOST_INTERFACE_COMMAND;
	}
	if (hw->mac.type == txgbe_mac_sp)
		if (txgbe_acquire_swfw_sync(hw, TXGBE_MNG_SWFW_SYNC_SW_MB) != 0)
			return TXGBE_ERR_SWFW_SYNC;

	/* Calculate length in DWORDs. We must be DWORD aligned */
	if ((length % (sizeof(u32))) != 0) {
		ERROR_REPORT1(TXGBE_ERROR_CAUTION,
			      "Buffer length failure, not aligned to dword");
		status = TXGBE_ERR_INVALID_ARGUMENT;
		goto rel_out;
	}

	dword_len = length >> 2;

	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
		WARN_ON(in_interrupt());
		while (test_and_set_bit(__TXGBE_SWFW_BUSY, &adapter->state)) {
			timeout--;
			if (!timeout)
				return TXGBE_ERR_TIMEOUT;
			usleep_range(1000, 2000);
		}

		/* index to unique seq id for each mbox message */
		send_hdr->cksum_or_index.index = adapter->swfw_index;
		send_cmd = send_hdr->cmd;

		/* write data to SW-FW mbox array */
		for (i = 0; i < dword_len; i++) {
			wr32a(hw, TXGBE_AML_MNG_MBOX_SW2FW,
			      i, TXGBE_CPU_TO_LE32(buffer[i]));
			/* write flush */
			buf[i] = rd32a(hw, TXGBE_AML_MNG_MBOX_SW2FW, i);
		}

		/* amlite: generate interrupt to notify FW */
		wr32m(hw, TXGBE_AML_MNG_MBOX_CTL_SW2FW,
		      TXGBE_AML_MNG_MBOX_NOTIFY, 0);
		wr32m(hw, TXGBE_AML_MNG_MBOX_CTL_SW2FW,
		      TXGBE_AML_MNG_MBOX_NOTIFY, TXGBE_AML_MNG_MBOX_NOTIFY);

		/* Calculate length in DWORDs */
		dword_len = hdr_size >> 2;

		/* polling reply from FW */
		do {
			timeout--;
			usleep_range(1000, 2000);

			/* read hdr */
			for (bi = 0; bi < dword_len; bi++) {
				buffer[bi] = rd32a(hw, TXGBE_AML_MNG_MBOX_FW2SW, bi);
				TXGBE_LE32_TO_CPUS(&buffer[bi]);
			}

			/* check hdr */
			recv_hdr = (struct txgbe_hic_hdr *)buffer;

			if (recv_hdr->cmd == send_cmd &&
			    recv_hdr->cksum_or_index.index == adapter->swfw_index)
				break;

		} while (timeout);

		buf[0] = rd32(hw, TXGBE_AML_MNG_MBOX_FW2SW);
		if ((buf[0] & 0xff0000) >> 16 == 0x80) {
			hw_info(hw, "It's unknown cmd : %08x.\n", buf[0]);
			status = TXGBE_ERR_MNG_ACCESS_FAILED;
			goto rel_out;
		}

		if (!timeout) {
			ERROR_REPORT1(TXGBE_ERROR_CAUTION,
				      "Polling from FW messages timeout, cmd is 0x%x, index is %d\n",
				send_cmd, adapter->swfw_index);
			status = TXGBE_ERR_TIMEOUT;
			goto rel_out;
		}

		if (!return_data)
			goto rel_out;

		/* If there is any thing in data position pull it in */
		buf_len = recv_hdr->buf_len;
		if (buf_len == 0)
			goto rel_out;

		if (length < buf_len + hdr_size) {
			ERROR_REPORT1(TXGBE_ERROR_CAUTION,
				      "Buffer not large enough for reply message.\n");
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
			goto rel_out;
		}

		/* Calculate length in DWORDs, add 3 for odd lengths */
		dword_len = (buf_len + 3) >> 2;
		for (; bi <= dword_len; bi++) {
			buffer[bi] = rd32a(hw, TXGBE_AML_MNG_MBOX_FW2SW, bi);
			TXGBE_LE32_TO_CPUS(&buffer[bi]);
		}
	} else if (hw->mac.type == txgbe_mac_sp) {
		/* legacy sw-fw mbox
		 * The device driver writes the relevant command block
		 * into the ram area.
		 */
		for (i = 0; i < dword_len; i++) {
			if (txgbe_check_mng_access(hw)) {
				wr32a(hw, TXGBE_MNG_MBOX,
				      i, TXGBE_CPU_TO_LE32(buffer[i]));
				/* write flush */
				buf[i] = rd32a(hw, TXGBE_MNG_MBOX, i);
			} else {
				status = TXGBE_ERR_MNG_ACCESS_FAILED;
				goto rel_out;
			}
		}
		/* Setting this bit tells the ARC that a new command is pending. */
		if (txgbe_check_mng_access(hw)) {
			wr32m(hw, TXGBE_MNG_MBOX_CTL,
			      TXGBE_MNG_MBOX_CTL_SWRDY, TXGBE_MNG_MBOX_CTL_SWRDY);
		} else {
			status = TXGBE_ERR_MNG_ACCESS_FAILED;
			goto rel_out;
		}

		for (i = 0; i < timeout; i++) {
			if (txgbe_check_mng_access(hw)) {
				hicr = rd32(hw, TXGBE_MNG_MBOX_CTL);
				if ((hicr & TXGBE_MNG_MBOX_CTL_FWRDY))
					break;
			}
			msec_delay(1);
		}

		buf[0] = rd32(hw, TXGBE_MNG_MBOX);

		if ((buf[0] & 0xff0000) >> 16 == 0x80) {
			ERROR_REPORT1(TXGBE_ERROR_UNSUPPORTED, "It's unknown cmd.\n");
			status = TXGBE_ERR_MNG_ACCESS_FAILED;
			goto rel_out;
		}

		/* Check command completion */
		if (timeout != 0 && i == timeout) {
			ERROR_REPORT1(TXGBE_ERROR_CAUTION,
				      "Command has failed with no status valid.\n");

			ERROR_REPORT1(TXGBE_ERROR_CAUTION, "write value:\n");
			for (i = 0; i < dword_len; i++)
				ERROR_REPORT1(TXGBE_ERROR_CAUTION, "%x ", buffer[i]);

			ERROR_REPORT1(TXGBE_ERROR_CAUTION, "read value:\n");
			for (i = 0; i < dword_len; i++)
				ERROR_REPORT1(TXGBE_ERROR_CAUTION, "%x ", buf[i]);

			ERROR_REPORT1(TXGBE_ERROR_CAUTION,
				      "===%x= %x=\n", buffer[0] & 0xff, (~buf[0] >> 24));
			if ((buffer[0] & 0xff) != (~buf[0] >> 24)) {
				status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
				goto rel_out;
			}
		}

		if (!return_data)
			goto rel_out;

		/* Calculate length in DWORDs */
		dword_len = hdr_size >> 2;

		/* first pull in the header so we know the buffer length */
		for (bi = 0; bi < dword_len; bi++) {
			if (txgbe_check_mng_access(hw)) {
				buffer[bi] = rd32a(hw, TXGBE_MNG_MBOX,
						   bi);
				TXGBE_LE32_TO_CPUS(&buffer[bi]);
			} else {
				status = TXGBE_ERR_MNG_ACCESS_FAILED;
				goto rel_out;
			}
		}

		/* If there is any thing in data position pull it in */
		buf_len = ((struct txgbe_hic_hdr *)buffer)->buf_len;
		if (buf_len == 0)
			goto rel_out;

		if (length < buf_len + hdr_size) {
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
			goto rel_out;
		}

		/* Calculate length in DWORDs, add 3 for odd lengths */
		dword_len = (buf_len + 3) >> 2;

		/* Pull in the rest of the buffer (bi is where we left off) */
		for (; bi <= dword_len; bi++) {
			if (txgbe_check_mng_access(hw)) {
				buffer[bi] = rd32a(hw, TXGBE_MNG_MBOX, bi);
				TXGBE_LE32_TO_CPUS(&buffer[bi]);
			} else {
				status = TXGBE_ERR_MNG_ACCESS_FAILED;
				goto rel_out;
			}
		}
	}

rel_out:
	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
		/* index++, index replace txgbe_hic_hdr.checksum */
		adapter->swfw_index = send_hdr->cksum_or_index.index == TXGBE_HIC_HDR_INDEX_MAX ?
						  0 : send_hdr->cksum_or_index.index + 1;

		clear_bit(__TXGBE_SWFW_BUSY, &adapter->state);
	} else {
		txgbe_release_swfw_sync(hw, TXGBE_MNG_SWFW_SYNC_SW_MB);
	}

	return status;
}


/**
 *  txgbe_reset_hostif - send reset cmd to fw
 *  @hw: pointer to hardware structure
 *
 *  Sends reset cmd to firmware through the manageability
 *  block.  On success return 0
 *  else returns TXGBE_ERR_SWFW_SYNC when encountering an error acquiring
 *  semaphore or TXGBE_ERR_HOST_INTERFACE_COMMAND when command fails.
 **/
int txgbe_reset_hostif(struct txgbe_hw *hw)
{
	struct txgbe_hic_reset reset_cmd;
	int i;
	int status = 0;

	reset_cmd.hdr.cmd = FW_RESET_CMD;
	reset_cmd.hdr.buf_len = FW_RESET_LEN;
	reset_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	reset_cmd.lan_id = hw->bus.lan_id;
	reset_cmd.reset_type = (u16)hw->reset_type;
	if (hw->mac.type == txgbe_mac_sp) {
		reset_cmd.hdr.cksum_or_index.checksum = 0;
		reset_cmd.hdr.cksum_or_index.checksum = txgbe_calculate_checksum((u8 *)&reset_cmd,
										 (FW_CEM_HDR_LEN + reset_cmd.hdr.buf_len));
	}

	for (i = 0; i <= FW_CEM_MAX_RETRIES; i++) {
		status = txgbe_host_interface_command(hw, (u32 *)&reset_cmd,
						      sizeof(reset_cmd),
						       TXGBE_HI_COMMAND_TIMEOUT,
						       true);
		if (status != 0)
			continue;

		if (reset_cmd.hdr.cmd_or_resp.ret_status ==
			FW_CEM_RESP_STATUS_SUCCESS) {
			status = 0;
			hw->link_status = TXGBE_LINK_STATUS_NONE;
		} else {
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
		}

		break;
	}

	return status;
}

static u16 txgbe_crc16_ccitt(const u8 *buf, int size)
{
	u16 crc = 0;
	int i;

	while (--size >= 0) {
		crc ^= (u16)*buf++ << 8;
		for (i = 0; i < 8; i++) {
			if (crc & 0x8000)
				crc = crc << 1 ^ 0x1021;
			else
				crc <<= 1;
		}
	}
	return crc;
}

int txgbe_upgrade_flash_hostif(struct txgbe_hw *hw, u32 region,
			       const u8 *data, u32 size)
{
	struct txgbe_hic_upg_start start_cmd;
	struct txgbe_hic_upg_write write_cmd;
	struct txgbe_hic_upg_verify verify_cmd;
	u32 offset;
	int status = 0;

	start_cmd.hdr.cmd = FW_FLASH_UPGRADE_START_CMD;
	start_cmd.hdr.buf_len = FW_FLASH_UPGRADE_START_LEN;
	start_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	start_cmd.module_id = (u8)region;
	if (hw->mac.type == txgbe_mac_sp) {
		start_cmd.hdr.cksum_or_index.checksum = 0;
		start_cmd.hdr.cksum_or_index.checksum = txgbe_calculate_checksum((u8 *)&start_cmd,
										 (FW_CEM_HDR_LEN + start_cmd.hdr.buf_len));
	}
	start_cmd.pad2 = 0;
	start_cmd.pad3 = 0;

	status = txgbe_host_interface_command(hw, (u32 *)&start_cmd,
					      sizeof(start_cmd),
					       TXGBE_HI_FLASH_ERASE_TIMEOUT,
					       true);

	if (start_cmd.hdr.cmd_or_resp.ret_status == FW_CEM_RESP_STATUS_SUCCESS) {
		status = 0;
	} else {
		status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
		return status;
	}

	for (offset = 0; offset < size;) {
		write_cmd.hdr.cmd = FW_FLASH_UPGRADE_WRITE_CMD;
		if (size - offset > 248) {
			write_cmd.data_len = 248 / 4;
			write_cmd.eof_flag = 0;
		} else {
			write_cmd.data_len = (u8)((size - offset) / 4);
			write_cmd.eof_flag = 1;
		}
		memcpy((u8 *)write_cmd.data, &data[offset], write_cmd.data_len * 4);
		write_cmd.hdr.buf_len = (write_cmd.data_len + 1) * 4;
		write_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
		write_cmd.check_sum = txgbe_crc16_ccitt((u8 *)write_cmd.data,
							write_cmd.data_len * 4);

		status = txgbe_host_interface_command(hw, (u32 *)&write_cmd,
						      sizeof(write_cmd),
						TXGBE_HI_FLASH_UPDATE_TIMEOUT,
						true);
		if (start_cmd.hdr.cmd_or_resp.ret_status ==
						FW_CEM_RESP_STATUS_SUCCESS) {
			status = 0;
		} else {
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
			return status;
		}
		offset += write_cmd.data_len * 4;
	}

	verify_cmd.hdr.cmd = FW_FLASH_UPGRADE_VERIFY_CMD;
	verify_cmd.hdr.buf_len = FW_FLASH_UPGRADE_VERIFY_LEN;
	verify_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	switch (region) {
	case TXGBE_MODULE_EEPROM:
		verify_cmd.action_flag = TXGBE_RELOAD_EEPROM;
		break;
	case TXGBE_MODULE_FIRMWARE:
		verify_cmd.action_flag = TXGBE_RESET_FIRMWARE;
		break;
	case TXGBE_MODULE_HARDWARE:
		verify_cmd.action_flag = TXGBE_RESET_LAN;
		break;
	default:
		return status;
	}

	if (hw->mac.type == txgbe_mac_sp)
		verify_cmd.hdr.cksum_or_index.checksum = txgbe_calculate_checksum((u8 *)&verify_cmd,
										  (FW_CEM_HDR_LEN + verify_cmd.hdr.buf_len));
	status = txgbe_host_interface_command(hw, (u32 *)&verify_cmd,
					      sizeof(verify_cmd),
					       TXGBE_HI_FLASH_VERIFY_TIMEOUT,
					       true);

	if (verify_cmd.hdr.cmd_or_resp.ret_status == FW_CEM_RESP_STATUS_SUCCESS)
		status = 0;
	else
		status = TXGBE_ERR_HOST_INTERFACE_COMMAND;

	return status;
}

/* cmd_addr is used for some special command:
 *	 1. to be sector address, when implemented erase sector command
 *	 2. to be flash address when implemented read, write flash address
 */
static int txgbe_fmgr_cmd_op(struct txgbe_hw *hw, u32 cmd, u32 cmd_addr)
{
	u32 cmd_val = 0, time_out = 0;

	cmd_val = (cmd << SPI_CLK_CMD_OFFSET) | (SPI_CLK_DIV << SPI_CLK_DIV_OFFSET) | cmd_addr;
	wr32(hw, SPI_H_CMD_REG_ADDR, cmd_val);
	while (1) {
		if (rd32(hw, SPI_H_STA_REG_ADDR) & 0x1)
			break;

		if (time_out == SPI_TIME_OUT_VALUE)
			return -ETIMEDOUT;

		time_out = time_out + 1;
		usleep_range(50, 100);
	}

	return 0;
}

static int fmgr_usr_cmd_op(struct txgbe_hw *hw, u32 usr_cmd)
{
	u8 status = 0;

	wr32(hw, SPI_H_USR_CMD_REG_ADDR, usr_cmd);
	status = txgbe_fmgr_cmd_op(hw, SPI_CMD_USER_CMD, 0);

	return status;
}

static int txgbe_flash_erase_chip(struct txgbe_hw *hw)
{
	return txgbe_fmgr_cmd_op(hw, SPI_CMD_ERASE_CHIP, 0);
}

static int txgbe_flash_erase_sector(struct txgbe_hw *hw, u32 sec_addr)
{
	return txgbe_fmgr_cmd_op(hw, SPI_CMD_ERASE_SECTOR, sec_addr);
}

static int txgbe_flash_write_dword(struct txgbe_hw *hw, u32 addr, u32 dword)
{
	int status = 0;
	u32 data;

	wr32(hw, SPI_H_DAT_REG_ADDR, dword);
	status = txgbe_fmgr_cmd_op(hw, SPI_CMD_WRITE_DWORD, addr);
	if (status)
		return status;

	txgbe_flash_read_dword(hw, addr, &data);
	if (dword != data)
		return -EIO;

	return 0;
}

int txgbe_flash_read_dword(struct txgbe_hw *hw, u32 addr, u32 *data)
{
	int ret = 0;

	ret = txgbe_fmgr_cmd_op(hw, SPI_CMD_READ_DWORD, addr);
	if (ret < 0)
		return ret;

	*data = rd32(hw, SPI_H_DAT_REG_ADDR);

	return ret;
}

static int txgbe_flash_write_unlock(struct txgbe_hw *hw)
{
	int status;
	struct txgbe_hic_read_shadow_ram buffer;

	buffer.hdr.req.cmd = 0x40;
	buffer.hdr.req.buf_lenh = 0;
	buffer.hdr.req.buf_lenl = 0;

	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.req.cksum_or_index.checksum = 0xFF;

	/* convert offset from words to bytes */
	buffer.address = 0;
	/* one word */
	buffer.length = 0;

	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer), 5000, false);

	return status;
}

int txgbe_upgrade_flash(struct txgbe_hw *hw, u32 region,
			const u8 *data, u32 size)
{
	u32 mac_addr0_dword0_t, mac_addr0_dword1_t, mac_addr1_dword0_t, mac_addr1_dword1_t;
	u32 serial_num_dword0_t, serial_num_dword1_t, serial_num_dword2_t;
	struct txgbe_adapter *adapter = hw->back;
	u8 status = 0, skip = 0, flash_vendor = 0;
	u32 sector_num = 0, read_data = 0, i = 0;
	u32 sn[24];
	char sn_str[40];
	u8 sn_is_str = true;
	u8 *vpd_tend = NULL;
	u32 curadr = 0;
	u32 vpdadr = 0;
	u8 id_str_len, pn_str_len, sn_str_len, rv_str_len;
	u32 mac_addr0_dword0_addr, mac_addr0_dword1_addr;
	u32 mac_addr1_dword0_addr, mac_addr1_dword1_addr;
	u16 subsystem_device_id;
	u16 device_id;
	u16 vpd_ro_len;
	u32 chksum = 0;
	u32 upgrade_check = 0x0;
	int err = 0;

	if (hw->mac.type == txgbe_mac_sp) {
		upgrade_check = PRB_CTL;
		subsystem_device_id = data[0xfffdc] << 8  | data[0xfffdd];
		device_id = data[0xfffde] << 8 | data[0xfffdf];
	} else {
		upgrade_check = PRB_SCRATCH;
		if (data[0x3000] == 0x25 && data[0x3001] == 0x20) {
			subsystem_device_id = data[0x302c] << 8  | data[0x302d];
			device_id = data[0x302e] << 8 | data[0x302f];
		} else {
			subsystem_device_id = data[0xfffdc] << 8  | data[0xfffdd];
			device_id = data[0xfffde] << 8 | data[0xfffdf];
		}
	}

	read_data = rd32(hw, upgrade_check);
	if (read_data & 0x80000000) {
		e_info(drv, "The flash has been successfully upgraded once, please reboot to make it work.\n");
		return -EOPNOTSUPP;
	}

	/*check sub_id*/;
	e_info(drv, "Checking sub_id .......\n");
	e_info(drv, "The card's sub_id : %04x\n", hw->subsystem_device_id);
	e_info(drv, "The image's sub_id : %04x\n", subsystem_device_id);

	if ((hw->subsystem_device_id & 0xfff) == (subsystem_device_id & 0xfff)) {
		e_info(drv, "It is a right image\n");
	} else if (hw->subsystem_device_id == 0xffff) {
		e_info(drv, "update anyway\n");
	} else {
		e_err(drv, "====The Gigabit image is not match the Gigabit card====\n");
		e_err(drv, "====Please check your image====\n");
		return -EOPNOTSUPP;
	}

	/*check dev_id*/
	e_info(drv, "Checking dev_id .......\n");
	e_info(drv, "The image's dev_id : %04x\n", device_id);
	e_info(drv, "The card's dev_id : %04x\n", hw->device_id);
	if (!((hw->device_id & 0xfff0) == (device_id & 0xfff0)) &&
	    !(hw->device_id == 0xffff)) {
		e_err(drv, "====The Gigabit image is not match the Gigabit card====\n");
		e_err(drv, "====Please check your image====\n");
		return -EOPNOTSUPP;
	}

	/* unlock flash write protect*/
	wr32(hw, TXGBE_SPI_CMDCFG0, 0x9f050206);
	wr32(hw, 0x10194, 0x9f050206);

	msleep(1000);

	switch (hw->mac.type) {
	case txgbe_mac_sp:
		mac_addr0_dword0_addr = MAC_ADDR0_WORD0_OFFSET_1G;
		mac_addr0_dword1_addr = MAC_ADDR0_WORD1_OFFSET_1G;
		mac_addr1_dword0_addr = MAC_ADDR1_WORD0_OFFSET_1G;
		mac_addr1_dword1_addr = MAC_ADDR1_WORD1_OFFSET_1G;
		break;
	case txgbe_mac_aml:
	case txgbe_mac_aml40:
		mac_addr0_dword0_addr = AMLITE_MAC_ADDR0_WORD0_OFFSET;
		mac_addr0_dword1_addr = AMLITE_MAC_ADDR0_WORD1_OFFSET;
		mac_addr1_dword0_addr = AMLITE_MAC_ADDR1_WORD0_OFFSET;
		mac_addr1_dword1_addr = AMLITE_MAC_ADDR1_WORD1_OFFSET;
		break;
	default:
		e_err(drv, "====Error mac type====\n");
		return -EOPNOTSUPP;
	}

	txgbe_flash_read_dword(hw, mac_addr0_dword0_addr, &mac_addr0_dword0_t);
	txgbe_flash_read_dword(hw, mac_addr0_dword1_addr, &mac_addr0_dword1_t);
	mac_addr0_dword1_t = mac_addr0_dword1_t & U16_MAX;
	txgbe_flash_read_dword(hw, mac_addr1_dword0_addr, &mac_addr1_dword0_t);
	txgbe_flash_read_dword(hw, mac_addr1_dword1_addr, &mac_addr1_dword1_t);
	mac_addr1_dword1_t = mac_addr1_dword1_t & U16_MAX;

	for (i = 0; i < 24; i++)
		txgbe_flash_read_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G + 4 * i, &sn[i]);

	if (sn[23] == U32_MAX)
		sn_is_str = false;

	txgbe_flash_read_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G, &serial_num_dword0_t);
	txgbe_flash_read_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G + 4, &serial_num_dword1_t);
	txgbe_flash_read_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G + 8, &serial_num_dword2_t);
	e_info(drv, "Old: MAC Address0 is: 0x%04x%08x\n", mac_addr0_dword1_t, mac_addr0_dword0_t);
	e_info(drv, "     MAC Address1 is: 0x%04x%08x\n", mac_addr1_dword1_t, mac_addr1_dword0_t);

	status = fmgr_usr_cmd_op(hw, 0x6);	/* write enable*/
	status = fmgr_usr_cmd_op(hw, 0x98); /* global protection un-lock*/
	txgbe_flash_write_unlock(hw);
	msleep(1000);

	//rebuild vpd
	vpd_tend = kcalloc(256, sizeof(u8), GFP_KERNEL);
	if (!vpd_tend)
		return -ENOMEM;

	memset(vpd_tend, 0xff, 256 * sizeof(u8));

	curadr = TXGBE_VPD_OFFSET + 1;
	id_str_len = data[curadr] | data[curadr + 1] << 8;
	curadr += (7 + id_str_len);
	pn_str_len = data[curadr];
	curadr += 1 + pn_str_len;

	for (i = 0; i < curadr - TXGBE_VPD_OFFSET; i++)
		vpd_tend[i] = data[TXGBE_VPD_OFFSET + i];

	memset(sn_str, 0x0, sizeof(sn_str));
	if (sn_is_str) {
		for (i = 0; i < 24; i++)
			sn_str[i] = sn[23 - i];

		sn_str_len = strlen(sn_str);
	} else {
		sn_str_len = 0x12;
		sprintf(sn_str, "%02x%08x%08x",
			(serial_num_dword2_t & 0xff),
			serial_num_dword1_t, serial_num_dword0_t);
	}

	vpdadr = curadr - TXGBE_VPD_OFFSET;

	if (data[curadr] == 'S' && data[curadr + 1] == 'N') {
		if (data[curadr + 2]) {
			for (i = sn_str_len; i < data[curadr + 2]; i++)
				sn_str[i] = 0x20;
			sn_str_len = data[curadr + 2];
		}
		curadr += 3 + data[curadr + 2];
		rv_str_len = data[2 + curadr];
	} else {
		rv_str_len = data[2 + curadr];
	}

	vpd_tend[vpdadr] = 'S';
	vpd_tend[vpdadr + 1] = 'N';
	vpd_tend[vpdadr + 2] = sn_str_len;

	for (i = 0; i < sn_str_len; i++)
		vpd_tend[vpdadr + 3 + i] = sn_str[i];

	vpdadr = vpdadr + 3 + sn_str_len;

	for (i = 0; i < 3; i++)
		vpd_tend[vpdadr + i] = data[curadr + i];

	vpdadr += 3;
	for (i = 0; i < rv_str_len; i++)
		vpd_tend[vpdadr + i] = 0x0;

	vpdadr += rv_str_len;
	vpd_ro_len = pn_str_len + sn_str_len + rv_str_len + 9;
	vpd_tend[4 + id_str_len] = vpd_ro_len & 0xff;
	vpd_tend[5 + id_str_len] = (vpd_ro_len >> 8) & 0xff;

	for (i = 0; i < vpdadr; i++)
		chksum += vpd_tend[i];
	chksum = ~(chksum & 0xff) + 1;
	vpd_tend[vpdadr - rv_str_len] = chksum;
	vpd_tend[vpdadr] = 0x78;

	if (flash_vendor == 1) {
		wr32(hw, SPI_CMD_CFG1_ADDR, 0x0103c720);
		for (i = 0; i < 8; i++) {
			txgbe_flash_erase_sector(hw, i * 128);
			msleep(20);
		}
		wr32(hw, SPI_CMD_CFG1_ADDR, 0x0103c7d8);
	}

	sector_num = size / SPI_SECTOR_SIZE;
	/* Winbond Flash, erase chip command is okay, but erase sector doestn't work*/
	if (flash_vendor == 2) {
		status = txgbe_flash_erase_chip(hw);
		e_err(drv, "Erase chip command, return status = %0d\n", status);
		msleep(1000);
	} else {
		wr32(hw, SPI_CMD_CFG1_ADDR, 0x0103c720);
		for (i = 0; i < sector_num; i++) {
			status = txgbe_flash_erase_sector(hw, i * SPI_SECTOR_SIZE);
			if (status)
				e_err(drv, "Erase sector[%2d] command, return status = %0d\n",
				      i, status);
			msleep(50);
		}
		wr32(hw, SPI_CMD_CFG1_ADDR, 0x0103c7d8);
	}

	/* Program Image file in dword*/
	for (i = 0; i < size / 4; i++) {
		read_data = data[4 * i + 3] << 24 |
					data[4 * i + 2] << 16 |
					data[4 * i + 1] << 8 | data[4 * i];
		read_data = __le32_to_cpu(read_data);
		skip = ((i * 4 == mac_addr0_dword0_addr) ||
				(i * 4 == mac_addr0_dword1_addr) ||
				(i * 4 == mac_addr1_dword0_addr) ||
				(i * 4 == mac_addr1_dword1_addr) ||
				(i * 4 >= PRODUCT_SERIAL_NUM_OFFSET_1G &&
				i * 4 <= PRODUCT_SERIAL_NUM_OFFSET_1G + 92) ||
				(i * 4 >= TXGBE_VPD_OFFSET && i * 4 < TXGBE_VPD_END) ||
				(i * 4 == 0x15c));
		if (read_data != U32_MAX && !skip) {
			status = txgbe_flash_write_dword(hw, i * 4, read_data);
			if (status) {
				e_err(drv, "ERROR: Program 0x%08x @addr: 0x%08x is failed !!\n",
				      read_data, i * 4);
				txgbe_flash_read_dword(hw, i * 4, &read_data);
				e_err(drv, "		 Read data from Flash is: 0x%08x\n",
				      read_data);
				err = -EBUSY;
				goto err_exit;
			}
		}
	}

	for (i = 0; i < 256 / 4; i++) {
		read_data = vpd_tend[4 * i + 3] << 24 |
					vpd_tend[4 * i + 2] << 16 |
					vpd_tend[4 * i + 1] << 8 |
					vpd_tend[4 * i];
		read_data = __le32_to_cpu(read_data);
		if (read_data != U32_MAX) {
			status = txgbe_flash_write_dword(hw,
							 TXGBE_VPD_OFFSET + i * 4, read_data);
			if (status) {
				e_err(drv, "ERROR: Program 0x%08x @addr: 0x%08x is failed !!\n",
				      read_data, i * 4);
				txgbe_flash_read_dword(hw, i * 4, &read_data);
				e_err(drv, "		 Read data from Flash is: 0x%08x\n",
				      read_data);
				err = -EBUSY;
				goto err_exit;
			}
		}
	}

	txgbe_flash_write_dword(hw, mac_addr0_dword0_addr,
				mac_addr0_dword0_t);
	txgbe_flash_write_dword(hw, mac_addr0_dword1_addr,
				(mac_addr0_dword1_t | 0x80000000));//lan0
	txgbe_flash_write_dword(hw, mac_addr1_dword0_addr,
				mac_addr1_dword0_t);
	txgbe_flash_write_dword(hw, mac_addr1_dword1_addr,
				(mac_addr1_dword1_t | 0x80000000));//lan1
	if (sn_is_str) {
		for (i = 0; i < 24; i++)
			txgbe_flash_write_dword(hw,
						PRODUCT_SERIAL_NUM_OFFSET_1G + 4 * i, sn[i]);
	} else {
		txgbe_flash_write_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G,
					serial_num_dword0_t);
		txgbe_flash_write_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G + 4,
					serial_num_dword1_t);
		txgbe_flash_write_dword(hw, PRODUCT_SERIAL_NUM_OFFSET_1G + 8,
					serial_num_dword2_t);
	}

	wr32(hw, upgrade_check, rd32(hw, upgrade_check) | 0x80000000);

err_exit:
	kfree(vpd_tend);
	return err;
}

/**
 * txgbe_set_rxpba - Initialize Rx packet buffer
 * @hw: pointer to hardware structure
 * @num_pb: number of packet buffers to allocate
 * @headroom: reserve n KB of headroom
 * @strategy: packet buffer allocation strategy
 **/
void txgbe_set_rxpba(struct txgbe_hw *hw, int num_pb, u32 headroom,
		     int strategy)
{
	u32 pbsize = hw->mac.rx_pb_size;
	int i = 0;
	u32 rxpktsize, txpktsize, txpbthresh;

	/* Reserve headroom */
	pbsize -= headroom;

	if (!num_pb)
		num_pb = 1;

	/* Divide remaining packet buffer space amongst the number of packet
	 * buffers requested using supplied strategy.
	 */
	switch (strategy) {
	case PBA_STRATEGY_WEIGHTED:
		/* txgbe_dcb_pba_80_48 strategy weight first half of packet
		 * buffer with 5/8 of the packet buffer space.
		 */
		rxpktsize = (pbsize * 5) / (num_pb * 4);
		pbsize -= rxpktsize * (num_pb / 2);
		rxpktsize <<= TXGBE_RDB_PB_SZ_SHIFT;
		for (; i < (num_pb / 2); i++)
			wr32(hw, TXGBE_RDB_PB_SZ(i), rxpktsize);
		fallthrough;
	case PBA_STRATEGY_EQUAL:
		rxpktsize = (pbsize / (num_pb - i)) << TXGBE_RDB_PB_SZ_SHIFT;
		for (; i < num_pb; i++)
			wr32(hw, TXGBE_RDB_PB_SZ(i), rxpktsize);
		break;
	default:
		break;
	}

	/* Only support an equally distributed Tx packet buffer strategy. */
	txpktsize = TXGBE_TDB_PB_SZ_MAX / num_pb;
	txpbthresh = (txpktsize / 1024) - TXGBE_TXPKT_SIZE_MAX;
	for (i = 0; i < num_pb; i++) {
		wr32(hw, TXGBE_TDB_PB_SZ(i), txpktsize);
		wr32(hw, TXGBE_TDM_PB_THRE(i), txpbthresh);
	}

	/* Clear unused TCs, if any, to zero buffer size*/
	for (; i < TXGBE_MAX_PB; i++) {
		wr32(hw, TXGBE_RDB_PB_SZ(i), 0);
		wr32(hw, TXGBE_TDB_PB_SZ(i), 0);
		wr32(hw, TXGBE_TDM_PB_THRE(i), 0);
	}
}

/**
 *  txgbe_get_thermal_sensor_data - Gathers thermal sensor data
 *  @hw: pointer to hardware structure
 *
 * algorithm:
 * T = (-4.8380E+01)N^0 + (3.1020E-01)N^1 + (-1.8201E-04)N^2 +
 *     (8.1542E-08)N^3 + (-1.6743E-11)N^4
 * algorithm with 5% more deviation, easy for implementation
 * T = (-50)N^0 + (0.31)N^1 + (-0.0002)N^2 + (0.0000001)N^3
 *
 *  Returns the thermal sensor data structure
 **/
int txgbe_get_thermal_sensor_data(struct txgbe_hw *hw)
{
	s64 tsv;
	int i = 0;
	struct txgbe_thermal_sensor_data *data = &hw->mac.thermal_sensor_data;
	u32 data_code;
	int temp_data, temp_fraction;
	struct txgbe_adapter *adapter = hw->back;

	/* Only support thermal sensors attached to physical port 0 */
	if (hw->bus.lan_id)
		return TXGBE_NOT_IMPLEMENTED;

	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
		wr32(hw, TXGBE_AML_TS_ENA, 0x0001);

		while (1) {
			data_code = rd32(hw, TXGBE_AML_TS_STS);
			if ((data_code & TXGBE_AML_TS_STS_VLD) != 0)
				break;
			usleep_range(1000, 2000);
			if (i++ > PHYINIT_TIMEOUT) {
				e_info(drv, "ERROR: Wait 0x1033c Timeout!!!\n");
				return -1;
			}
		}

		data_code = data_code & 0xFFF;
		temp_data = 419400 + 2205 * (data_code * 1000 / 4094 - 500);

		//Change double Temperature to int
		tsv = temp_data / 10000;
		temp_fraction = temp_data - (tsv * 10000);
		if (temp_fraction >= 5000)
			tsv += 1;

		data->sensor.temp = (s16)tsv;
	} else {
		tsv = (s64)(rd32(hw, TXGBE_TS_ST) &
			TXGBE_TS_ST_DATA_OUT_MASK);

		tsv = tsv < 1200 ? tsv : 1200;
		tsv = -(48380 << 8) / 1000
		  + div64_s64(tsv * (31020 << 8), 100000)
		  - div64_s64(tsv * tsv * (18201 << 8), 100000000)
		  + div64_s64(tsv * tsv * tsv * (81542 << 8), 1000000000000)
		  - div64_s64(tsv * tsv * tsv * tsv * (16743 << 8), 1000000000000000);
		tsv >>= 8;

		data->sensor.temp = (s16)tsv;

		for (i = 0; i < 100; i++) {
			tsv = (s64)rd32(hw, TXGBE_TS_ST);
			if (tsv >> 16 != 0x1) {
				usleep_range(1000, 2000);
				continue;
			} else {
				tsv = tsv & TXGBE_TS_ST_DATA_OUT_MASK;
				tsv = tsv < 1200 ? tsv : 1200;
				tsv = -(48380 << 8) / 1000 +
				      div64_s64(tsv * (31020 << 8), 100000) -
				      div64_s64(tsv * tsv * (18201 << 8), 100000000) +
				      div64_s64(tsv * tsv * tsv * (81542 << 8),
					   1000000000000) -
				      div64_s64(tsv * tsv * tsv * tsv * (16743 << 8),
					  1000000000000000);

				tsv >>= 8;

				data->sensor.temp = (s16)tsv;
				break;
			}
		}
	}

	return 0;
}

/**
 *  txgbe_init_thermal_sensor_thresh - Inits thermal sensor thresholds
 *  @hw: pointer to hardware structure
 *
 *  Inits the thermal sensor thresholds according to the NVM map
 *  and save off the threshold and location values into mac.thermal_sensor_data
 **/
int txgbe_init_thermal_sensor_thresh(struct txgbe_hw *hw)
{
	int status = 0;

	struct txgbe_thermal_sensor_data *data = &hw->mac.thermal_sensor_data;

	memset(data, 0, sizeof(struct txgbe_thermal_sensor_data));

	/* Only support thermal sensors attached to SP physical port 0 */
	if (hw->bus.lan_id)
		return TXGBE_NOT_IMPLEMENTED;

	data->sensor.alarm_thresh = 100;
	data->sensor.dalarm_thresh = 90;

	if (hw->mac.type == txgbe_mac_aml  || hw->mac.type == txgbe_mac_aml40) {
		wr32(hw, TXGBE_AML_TS_ENA, 0x0);
		wr32(hw, TXGBE_AML_INTR_RAW_LO, TXGBE_AML_INTR_CL_LO);
		wr32(hw, TXGBE_AML_INTR_RAW_HI, TXGBE_AML_INTR_CL_HI);

		wr32(hw, TXGBE_AML_INTR_HIGH_EN, TXGBE_AML_INTR_EN_HI);
		wr32(hw, TXGBE_AML_INTR_LOW_EN, TXGBE_AML_INTR_EN_LO);

		wr32m(hw, TXGBE_AML_TS_CTL1, TXGBE_AML_EVAL_MODE_MASK, 0x10);
		wr32m(hw, TXGBE_AML_TS_CTL1, TXGBE_AML_ALARM_THRE_MASK, 0x186a0000);
		wr32m(hw, TXGBE_AML_TS_CTL1, TXGBE_AML_DALARM_THRE_MASK, 0x16f60);
		wr32(hw, TXGBE_AML_TS_ENA, 0x1);
	} else {
		wr32(hw, TXGBE_TS_CTL, TXGBE_TS_CTL_EVAL_MD);
		wr32(hw, TXGBE_TS_INT_EN,
		     TXGBE_TS_INT_EN_ALARM_INT_EN | TXGBE_TS_INT_EN_DALARM_INT_EN);
		wr32(hw, TXGBE_TS_EN, TXGBE_TS_EN_ENA);

		wr32(hw, TXGBE_TS_ALARM_THRE, 677);
		wr32(hw, TXGBE_TS_DALARM_THRE, 614);
	}
	return status;
}

void txgbe_disable_rx(struct txgbe_hw *hw)
{
	u32 pfdtxgswc;
	u32 rxctrl;

	rxctrl = rd32(hw, TXGBE_RDB_PB_CTL);
	if (rxctrl & TXGBE_RDB_PB_CTL_RXEN) {
		pfdtxgswc = rd32(hw, TXGBE_PSR_CTL);
		if (pfdtxgswc & TXGBE_PSR_CTL_SW_EN) {
			pfdtxgswc &= ~TXGBE_PSR_CTL_SW_EN;
			wr32(hw, TXGBE_PSR_CTL, pfdtxgswc);
			hw->mac.set_lben = true;
		} else {
			hw->mac.set_lben = false;
		}
		rxctrl &= ~TXGBE_RDB_PB_CTL_RXEN;
		wr32(hw, TXGBE_RDB_PB_CTL, rxctrl);

		if (!(((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP) ||
		      ((hw->subsystem_device_id & TXGBE_WOL_MASK) == TXGBE_WOL_SUP))) {
			/* disable mac receiver */
			wr32m(hw, TXGBE_MAC_RX_CFG,
			      TXGBE_MAC_RX_CFG_RE, 0);
		}
	}
}

void txgbe_enable_rx(struct txgbe_hw *hw)
{
	u32 pfdtxgswc;

	/* enable mac receiver */
	wr32m(hw, TXGBE_MAC_RX_CFG,
	      TXGBE_MAC_RX_CFG_RE, TXGBE_MAC_RX_CFG_RE);

	wr32m(hw, TXGBE_RDB_PB_CTL,
	      TXGBE_RDB_PB_CTL_RXEN, TXGBE_RDB_PB_CTL_RXEN);

	if (hw->mac.set_lben) {
		pfdtxgswc = rd32(hw, TXGBE_PSR_CTL);
		pfdtxgswc |= TXGBE_PSR_CTL_SW_EN;
		wr32(hw, TXGBE_PSR_CTL, pfdtxgswc);
		hw->mac.set_lben = false;
	}
}

/**
 * txgbe_mng_present - returns true when management capability is present
 * @hw: pointer to hardware structure
 */
bool txgbe_mng_present(struct txgbe_hw *hw)
{
	u32 fwsm;

	fwsm = rd32(hw, TXGBE_MIS_ST);
	return fwsm & TXGBE_MIS_ST_MNG_INIT_DN;
}

bool txgbe_check_mng_access(struct txgbe_hw *hw)
{
	bool ret = false;
	u32 rst_delay;
	u32 i;

	struct txgbe_adapter *adapter = hw->back;

	if (!txgbe_mng_present(hw))
		return false;
	if (adapter->hw.revision_id != TXGBE_SP_MPW)
		return true;
	if (!(adapter->flags2 & TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED))
		return true;

	rst_delay = (rd32(&adapter->hw, TXGBE_MIS_RST_ST) &
			TXGBE_MIS_RST_ST_RST_INIT) >>
			TXGBE_MIS_RST_ST_RST_INI_SHIFT;
	for (i = 0; i < rst_delay + 2; i++) {
		if (!(adapter->flags2 & TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED)) {
			ret = true;
			break;
		}
		msleep(100);
	}
	return ret;
}

/**
 *  txgbe_setup_mac_link_multispeed_fiber - Set MAC link speed
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Set the link speed in the MAC and/or PHY register and restarts link.
 **/
int txgbe_setup_mac_link_multispeed_fiber(struct txgbe_hw *hw,
					  u32 speed,
					  bool autoneg_wait_to_complete)
{
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	u32 highest_link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	int status = 0;
	u32 speedcnt = 0;
	u32 i = 0;
	bool autoneg, link_up = false;
	struct txgbe_adapter *adapter = hw->back;

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
		status = hw->mac.ops.check_link(hw,
					&link_speed, &link_up, false);
		if (status != 0)
			return status;

		if (link_speed == TXGBE_LINK_SPEED_25GB_FULL && link_up)
			goto out;

		/* Allow module to change analog characteristics (1G->10G) */
		msec_delay(40);

		status = hw->mac.ops.setup_mac_link(hw,
				TXGBE_LINK_SPEED_25GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/* Flap the Tx laser if it has not already been done */
		if (hw->mac.ops.flap_tx_laser)
			hw->mac.ops.flap_tx_laser(hw);

		/* Wait for the controller to acquire link.  Per IEEE 802.3ap,
		 * Section 73.10.2, we may have to wait up to 500ms if KR is
		 * attempted.  sapphire uses the same timing for 10g SFI.
		 */
		for (i = 0; i < 5; i++) {
			/* Wait for the link partner to also set speed */
			msec_delay(100);

			/* If we have link, just jump out */
			status = hw->mac.ops.check_link(hw,
						&link_speed, &link_up, false);
			if (status != 0)
				return status;

			if (link_up)
				goto out;
		}
	}

	if (speed & TXGBE_LINK_SPEED_10GB_FULL) {
		speedcnt++;
		if (highest_link_speed == TXGBE_LINK_SPEED_UNKNOWN)
			highest_link_speed = TXGBE_LINK_SPEED_10GB_FULL;

		/* If we already have link at this speed, just jump out */
		status = hw->mac.ops.check_link(hw,
					&link_speed, &link_up, false);
		if (status != 0)
			return status;

		if (link_speed == TXGBE_LINK_SPEED_10GB_FULL && link_up)
			goto out;

		/* Allow module to change analog characteristics (1G->10G) */
		msec_delay(40);

		status = hw->mac.ops.setup_mac_link(hw,
				TXGBE_LINK_SPEED_10GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/* Flap the Tx laser if it has not already been done */
		if (hw->mac.ops.flap_tx_laser)
			hw->mac.ops.flap_tx_laser(hw);

		/* Wait for the controller to acquire link.  Per IEEE 802.3ap,
		 * Section 73.10.2, we may have to wait up to 500ms if KR is
		 * attempted.  sapphire uses the same timing for 10g SFI.
		 */
		for (i = 0; i < 5; i++) {
			/* Wait for the link partner to also set speed */
			msec_delay(100);

			/* If we have link, just jump out */
			status = hw->mac.ops.check_link(hw,
						&link_speed, &link_up, false);
			if (status != 0)
				return status;

			if (link_up)
				goto out;
		}
	}

	if (speed & TXGBE_LINK_SPEED_1GB_FULL) {
		u32 curr_autoneg = 2;

		speedcnt++;
		if (highest_link_speed == TXGBE_LINK_SPEED_UNKNOWN)
			highest_link_speed = TXGBE_LINK_SPEED_1GB_FULL;

		/* If we already have link at this speed, just jump out */
		status = hw->mac.ops.check_link(hw,
					&link_speed, &link_up, false);
		if (status != 0)
			return status;

		if (link_speed == TXGBE_LINK_SPEED_1GB_FULL) {
			curr_autoneg = txgbe_rd32_epcs(hw, TXGBE_SR_MII_MMD_CTL);
			curr_autoneg = !!(curr_autoneg & (0x1 << 12));
		}

		if (link_speed == TXGBE_LINK_SPEED_1GB_FULL &&
		    link_up &&
			adapter->autoneg == curr_autoneg)
			goto out;

		/* Allow module to change analog characteristics (10G->1G) */
		msec_delay(40);

		status = hw->mac.ops.setup_mac_link(hw,
				TXGBE_LINK_SPEED_1GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/* Flap the Tx laser if it has not already been done */
		if (hw->mac.ops.flap_tx_laser)
			hw->mac.ops.flap_tx_laser(hw);

		/* Wait for the link partner to also set speed */
		msec_delay(100);

		/* If we have link, just jump out */
		status = hw->mac.ops.check_link(hw,
					&link_speed, &link_up, false);
		if (status != 0)
			return status;

		if (link_up)
			goto out;
	}

	/* We didn't get link.  Configure back to the highest speed we tried,
	 * (if there was more than one).  We call ourselves back with just the
	 * single highest speed that the user requested.
	 */
	if (speedcnt > 1)
		status = txgbe_setup_mac_link_multispeed_fiber(hw,
							       highest_link_speed,
						      autoneg_wait_to_complete);

out:
	/* Set autoneg_advertised value based on input link speed */
	hw->phy.autoneg_advertised = 0;

	if (speed & TXGBE_LINK_SPEED_40GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_40GB_FULL;

	if (speed & TXGBE_LINK_SPEED_25GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_25GB_FULL;

	if (speed & TXGBE_LINK_SPEED_10GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_10GB_FULL;

	if (speed & TXGBE_LINK_SPEED_1GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_1GB_FULL;

	return status;
}

int txgbe_check_flash_load(struct txgbe_hw *hw, u32 check_bit)
{
	u32 i = 0;
	u32 reg = 0;
	int err = 0;
	/* if there's flash existing */
	if (!(rd32(hw, TXGBE_SPI_STATUS) &
		TXGBE_SPI_STATUS_FLASH_BYPASS)) {
		/* wait hw load flash done */
		for (i = 0; i < TXGBE_MAX_FLASH_LOAD_POLL_TIME; i++) {
			reg = rd32(hw, TXGBE_SPI_ILDR_STATUS);
			if (!(reg & check_bit))
				break;
			msleep(200);
		}
		if (i == TXGBE_MAX_FLASH_LOAD_POLL_TIME)
			err = TXGBE_ERR_FLASH_LOADING_FAILED;
	}
	return err;
}

/* The txgbe_ptype_lookup is used to convert from the 8-bit ptype in the
 * hardware to a bit-field that can be used by SW to more easily determine the
 * packet type.
 *
 * Macros are used to shorten the table lines and make this table human
 * readable.
 *
 * We store the PTYPE in the top byte of the bit field - this is just so that
 * we can check that the table doesn't have a row missing, as the index into
 * the table should be the PTYPE.
 *
 * Typical work flow:
 *
 * IF NOT txgbe_ptype_lookup[ptype].known
 * THEN
 *      Packet is unknown
 * ELSE IF txgbe_ptype_lookup[ptype].mac == TXGBE_DEC_PTYPE_MAC_IP
 *      Use the rest of the fields to look at the tunnels, inner protocols, etc
 * ELSE
 *      Use the enum txgbe_l2_ptypes to decode the packet type
 * ENDIF
 */

/* macro to make the table lines short */
#define TXGBE_PTT(ptype, mac, ip, etype, eip, proto, layer)\
	{       ptype, \
		1, \
		/* mac     */ TXGBE_DEC_PTYPE_MAC_##mac, \
		/* ip      */ TXGBE_DEC_PTYPE_IP_##ip, \
		/* etype   */ TXGBE_DEC_PTYPE_ETYPE_##etype, \
		/* eip     */ TXGBE_DEC_PTYPE_IP_##eip, \
		/* proto   */ TXGBE_DEC_PTYPE_PROT_##proto, \
		/* layer   */ TXGBE_DEC_PTYPE_LAYER_##layer }

#define TXGBE_UKN(ptype) \
		{ ptype, 0, 0, 0, 0, 0, 0, 0 }

/* Lookup table mapping the HW PTYPE to the bit field for decoding */
/* for ((pt=0;pt<256;pt++)); do printf "macro(0x%02X),\n" $pt; done */
struct txgbe_dec_ptype txgbe_ptype_lookup[256] = {
	TXGBE_UKN(0x00),
	TXGBE_UKN(0x01),
	TXGBE_UKN(0x02),
	TXGBE_UKN(0x03),
	TXGBE_UKN(0x04),
	TXGBE_UKN(0x05),
	TXGBE_UKN(0x06),
	TXGBE_UKN(0x07),
	TXGBE_UKN(0x08),
	TXGBE_UKN(0x09),
	TXGBE_UKN(0x0A),
	TXGBE_UKN(0x0B),
	TXGBE_UKN(0x0C),
	TXGBE_UKN(0x0D),
	TXGBE_UKN(0x0E),
	TXGBE_UKN(0x0F),

	/* L2: mac */
	TXGBE_UKN(0x10),
	TXGBE_PTT(0x11, L2, NONE, NONE, NONE, NONE, PAY2),
	TXGBE_PTT(0x12, L2, NONE, NONE, NONE, TS,   PAY2),
	TXGBE_PTT(0x13, L2, NONE, NONE, NONE, NONE, PAY2),
	TXGBE_PTT(0x14, L2, NONE, NONE, NONE, NONE, PAY2),
	TXGBE_PTT(0x15, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x16, L2, NONE, NONE, NONE, NONE, PAY2),
	TXGBE_PTT(0x17, L2, NONE, NONE, NONE, NONE, NONE),

	/* L2: ethertype filter */
	TXGBE_PTT(0x18, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x19, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x1A, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x1B, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x1C, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x1D, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x1E, L2, NONE, NONE, NONE, NONE, NONE),
	TXGBE_PTT(0x1F, L2, NONE, NONE, NONE, NONE, NONE),

	/* L3: ip non-tunnel */
	TXGBE_UKN(0x20),
	TXGBE_PTT(0x21, IP, FGV4, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x22, IP, IPV4, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x23, IP, IPV4, NONE, NONE, UDP,  PAY4),
	TXGBE_PTT(0x24, IP, IPV4, NONE, NONE, TCP,  PAY4),
	TXGBE_PTT(0x25, IP, IPV4, NONE, NONE, SCTP, PAY4),
	TXGBE_UKN(0x26),
	TXGBE_UKN(0x27),
	TXGBE_UKN(0x28),
	TXGBE_PTT(0x29, IP, FGV6, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x2A, IP, IPV6, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x2B, IP, IPV6, NONE, NONE, UDP,  PAY3),
	TXGBE_PTT(0x2C, IP, IPV6, NONE, NONE, TCP,  PAY4),
	TXGBE_PTT(0x2D, IP, IPV6, NONE, NONE, SCTP, PAY4),
	TXGBE_UKN(0x2E),
	TXGBE_UKN(0x2F),

	/* L2: fcoe */
	TXGBE_PTT(0x30, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x31, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x32, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x33, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x34, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_UKN(0x35),
	TXGBE_UKN(0x36),
	TXGBE_UKN(0x37),
	TXGBE_PTT(0x38, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x39, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x3A, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x3B, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_PTT(0x3C, FCOE, NONE, NONE, NONE, NONE, PAY3),
	TXGBE_UKN(0x3D),
	TXGBE_UKN(0x3E),
	TXGBE_UKN(0x3F),

	TXGBE_UKN(0x40),
	TXGBE_UKN(0x41),
	TXGBE_UKN(0x42),
	TXGBE_UKN(0x43),
	TXGBE_UKN(0x44),
	TXGBE_UKN(0x45),
	TXGBE_UKN(0x46),
	TXGBE_UKN(0x47),
	TXGBE_UKN(0x48),
	TXGBE_UKN(0x49),
	TXGBE_UKN(0x4A),
	TXGBE_UKN(0x4B),
	TXGBE_UKN(0x4C),
	TXGBE_UKN(0x4D),
	TXGBE_UKN(0x4E),
	TXGBE_UKN(0x4F),
	TXGBE_UKN(0x50),
	TXGBE_UKN(0x51),
	TXGBE_UKN(0x52),
	TXGBE_UKN(0x53),
	TXGBE_UKN(0x54),
	TXGBE_UKN(0x55),
	TXGBE_UKN(0x56),
	TXGBE_UKN(0x57),
	TXGBE_UKN(0x58),
	TXGBE_UKN(0x59),
	TXGBE_UKN(0x5A),
	TXGBE_UKN(0x5B),
	TXGBE_UKN(0x5C),
	TXGBE_UKN(0x5D),
	TXGBE_UKN(0x5E),
	TXGBE_UKN(0x5F),
	TXGBE_UKN(0x60),
	TXGBE_UKN(0x61),
	TXGBE_UKN(0x62),
	TXGBE_UKN(0x63),
	TXGBE_UKN(0x64),
	TXGBE_UKN(0x65),
	TXGBE_UKN(0x66),
	TXGBE_UKN(0x67),
	TXGBE_UKN(0x68),
	TXGBE_UKN(0x69),
	TXGBE_UKN(0x6A),
	TXGBE_UKN(0x6B),
	TXGBE_UKN(0x6C),
	TXGBE_UKN(0x6D),
	TXGBE_UKN(0x6E),
	TXGBE_UKN(0x6F),
	TXGBE_UKN(0x70),
	TXGBE_UKN(0x71),
	TXGBE_UKN(0x72),
	TXGBE_UKN(0x73),
	TXGBE_UKN(0x74),
	TXGBE_UKN(0x75),
	TXGBE_UKN(0x76),
	TXGBE_UKN(0x77),
	TXGBE_UKN(0x78),
	TXGBE_UKN(0x79),
	TXGBE_UKN(0x7A),
	TXGBE_UKN(0x7B),
	TXGBE_UKN(0x7C),
	TXGBE_UKN(0x7D),
	TXGBE_UKN(0x7E),
	TXGBE_UKN(0x7F),

	/* IPv4 --> IPv4/IPv6 */
	TXGBE_UKN(0x80),
	TXGBE_PTT(0x81, IP, IPV4, IPIP, FGV4, NONE, PAY3),
	TXGBE_PTT(0x82, IP, IPV4, IPIP, IPV4, NONE, PAY3),
	TXGBE_PTT(0x83, IP, IPV4, IPIP, IPV4, UDP,  PAY4),
	TXGBE_PTT(0x84, IP, IPV4, IPIP, IPV4, TCP,  PAY4),
	TXGBE_PTT(0x85, IP, IPV4, IPIP, IPV4, SCTP, PAY4),
	TXGBE_UKN(0x86),
	TXGBE_UKN(0x87),
	TXGBE_UKN(0x88),
	TXGBE_PTT(0x89, IP, IPV4, IPIP, FGV6, NONE, PAY3),
	TXGBE_PTT(0x8A, IP, IPV4, IPIP, IPV6, NONE, PAY3),
	TXGBE_PTT(0x8B, IP, IPV4, IPIP, IPV6, UDP,  PAY4),
	TXGBE_PTT(0x8C, IP, IPV4, IPIP, IPV6, TCP,  PAY4),
	TXGBE_PTT(0x8D, IP, IPV4, IPIP, IPV6, SCTP, PAY4),
	TXGBE_UKN(0x8E),
	TXGBE_UKN(0x8F),

	/* IPv4 --> GRE/NAT --> NONE/IPv4/IPv6 */
	TXGBE_PTT(0x90, IP, IPV4, IG, NONE, NONE, PAY3),
	TXGBE_PTT(0x91, IP, IPV4, IG, FGV4, NONE, PAY3),
	TXGBE_PTT(0x92, IP, IPV4, IG, IPV4, NONE, PAY3),
	TXGBE_PTT(0x93, IP, IPV4, IG, IPV4, UDP,  PAY4),
	TXGBE_PTT(0x94, IP, IPV4, IG, IPV4, TCP,  PAY4),
	TXGBE_PTT(0x95, IP, IPV4, IG, IPV4, SCTP, PAY4),
	TXGBE_UKN(0x96),
	TXGBE_UKN(0x97),
	TXGBE_UKN(0x98),
	TXGBE_PTT(0x99, IP, IPV4, IG, FGV6, NONE, PAY3),
	TXGBE_PTT(0x9A, IP, IPV4, IG, IPV6, NONE, PAY3),
	TXGBE_PTT(0x9B, IP, IPV4, IG, IPV6, UDP,  PAY4),
	TXGBE_PTT(0x9C, IP, IPV4, IG, IPV6, TCP,  PAY4),
	TXGBE_PTT(0x9D, IP, IPV4, IG, IPV6, SCTP, PAY4),
	TXGBE_UKN(0x9E),
	TXGBE_UKN(0x9F),

	/* IPv4 --> GRE/NAT --> MAC --> NONE/IPv4/IPv6 */
	TXGBE_PTT(0xA0, IP, IPV4, IGM, NONE, NONE, PAY3),
	TXGBE_PTT(0xA1, IP, IPV4, IGM, FGV4, NONE, PAY3),
	TXGBE_PTT(0xA2, IP, IPV4, IGM, IPV4, NONE, PAY3),
	TXGBE_PTT(0xA3, IP, IPV4, IGM, IPV4, UDP,  PAY4),
	TXGBE_PTT(0xA4, IP, IPV4, IGM, IPV4, TCP,  PAY4),
	TXGBE_PTT(0xA5, IP, IPV4, IGM, IPV4, SCTP, PAY4),
	TXGBE_UKN(0xA6),
	TXGBE_UKN(0xA7),
	TXGBE_UKN(0xA8),
	TXGBE_PTT(0xA9, IP, IPV4, IGM, FGV6, NONE, PAY3),
	TXGBE_PTT(0xAA, IP, IPV4, IGM, IPV6, NONE, PAY3),
	TXGBE_PTT(0xAB, IP, IPV4, IGM, IPV6, UDP,  PAY4),
	TXGBE_PTT(0xAC, IP, IPV4, IGM, IPV6, TCP,  PAY4),
	TXGBE_PTT(0xAD, IP, IPV4, IGM, IPV6, SCTP, PAY4),
	TXGBE_UKN(0xAE),
	TXGBE_UKN(0xAF),

	/* IPv4 --> GRE/NAT --> MAC+VLAN --> NONE/IPv4/IPv6 */
	TXGBE_PTT(0xB0, IP, IPV4, IGMV, NONE, NONE, PAY3),
	TXGBE_PTT(0xB1, IP, IPV4, IGMV, FGV4, NONE, PAY3),
	TXGBE_PTT(0xB2, IP, IPV4, IGMV, IPV4, NONE, PAY3),
	TXGBE_PTT(0xB3, IP, IPV4, IGMV, IPV4, UDP,  PAY4),
	TXGBE_PTT(0xB4, IP, IPV4, IGMV, IPV4, TCP,  PAY4),
	TXGBE_PTT(0xB5, IP, IPV4, IGMV, IPV4, SCTP, PAY4),
	TXGBE_UKN(0xB6),
	TXGBE_UKN(0xB7),
	TXGBE_UKN(0xB8),
	TXGBE_PTT(0xB9, IP, IPV4, IGMV, FGV6, NONE, PAY3),
	TXGBE_PTT(0xBA, IP, IPV4, IGMV, IPV6, NONE, PAY3),
	TXGBE_PTT(0xBB, IP, IPV4, IGMV, IPV6, UDP,  PAY4),
	TXGBE_PTT(0xBC, IP, IPV4, IGMV, IPV6, TCP,  PAY4),
	TXGBE_PTT(0xBD, IP, IPV4, IGMV, IPV6, SCTP, PAY4),
	TXGBE_UKN(0xBE),
	TXGBE_UKN(0xBF),

	/* IPv6 --> IPv4/IPv6 */
	TXGBE_UKN(0xC0),
	TXGBE_PTT(0xC1, IP, IPV6, IPIP, FGV4, NONE, PAY3),
	TXGBE_PTT(0xC2, IP, IPV6, IPIP, IPV4, NONE, PAY3),
	TXGBE_PTT(0xC3, IP, IPV6, IPIP, IPV4, UDP,  PAY4),
	TXGBE_PTT(0xC4, IP, IPV6, IPIP, IPV4, TCP,  PAY4),
	TXGBE_PTT(0xC5, IP, IPV6, IPIP, IPV4, SCTP, PAY4),
	TXGBE_UKN(0xC6),
	TXGBE_UKN(0xC7),
	TXGBE_UKN(0xC8),
	TXGBE_PTT(0xC9, IP, IPV6, IPIP, FGV6, NONE, PAY3),
	TXGBE_PTT(0xCA, IP, IPV6, IPIP, IPV6, NONE, PAY3),
	TXGBE_PTT(0xCB, IP, IPV6, IPIP, IPV6, UDP,  PAY4),
	TXGBE_PTT(0xCC, IP, IPV6, IPIP, IPV6, TCP,  PAY4),
	TXGBE_PTT(0xCD, IP, IPV6, IPIP, IPV6, SCTP, PAY4),
	TXGBE_UKN(0xCE),
	TXGBE_UKN(0xCF),

	/* IPv6 --> GRE/NAT -> NONE/IPv4/IPv6 */
	TXGBE_PTT(0xD0, IP, IPV6, IG,   NONE, NONE, PAY3),
	TXGBE_PTT(0xD1, IP, IPV6, IG,   FGV4, NONE, PAY3),
	TXGBE_PTT(0xD2, IP, IPV6, IG,   IPV4, NONE, PAY3),
	TXGBE_PTT(0xD3, IP, IPV6, IG,   IPV4, UDP,  PAY4),
	TXGBE_PTT(0xD4, IP, IPV6, IG,   IPV4, TCP,  PAY4),
	TXGBE_PTT(0xD5, IP, IPV6, IG,   IPV4, SCTP, PAY4),
	TXGBE_UKN(0xD6),
	TXGBE_UKN(0xD7),
	TXGBE_UKN(0xD8),
	TXGBE_PTT(0xD9, IP, IPV6, IG,   FGV6, NONE, PAY3),
	TXGBE_PTT(0xDA, IP, IPV6, IG,   IPV6, NONE, PAY3),
	TXGBE_PTT(0xDB, IP, IPV6, IG,   IPV6, UDP,  PAY4),
	TXGBE_PTT(0xDC, IP, IPV6, IG,   IPV6, TCP,  PAY4),
	TXGBE_PTT(0xDD, IP, IPV6, IG,   IPV6, SCTP, PAY4),
	TXGBE_UKN(0xDE),
	TXGBE_UKN(0xDF),

	/* IPv6 --> GRE/NAT -> MAC -> NONE/IPv4/IPv6 */
	TXGBE_PTT(0xE0, IP, IPV6, IGM,  NONE, NONE, PAY3),
	TXGBE_PTT(0xE1, IP, IPV6, IGM,  FGV4, NONE, PAY3),
	TXGBE_PTT(0xE2, IP, IPV6, IGM,  IPV4, NONE, PAY3),
	TXGBE_PTT(0xE3, IP, IPV6, IGM,  IPV4, UDP,  PAY4),
	TXGBE_PTT(0xE4, IP, IPV6, IGM,  IPV4, TCP,  PAY4),
	TXGBE_PTT(0xE5, IP, IPV6, IGM,  IPV4, SCTP, PAY4),
	TXGBE_UKN(0xE6),
	TXGBE_UKN(0xE7),
	TXGBE_UKN(0xE8),
	TXGBE_PTT(0xE9, IP, IPV6, IGM,  FGV6, NONE, PAY3),
	TXGBE_PTT(0xEA, IP, IPV6, IGM,  IPV6, NONE, PAY3),
	TXGBE_PTT(0xEB, IP, IPV6, IGM,  IPV6, UDP,  PAY4),
	TXGBE_PTT(0xEC, IP, IPV6, IGM,  IPV6, TCP,  PAY4),
	TXGBE_PTT(0xED, IP, IPV6, IGM,  IPV6, SCTP, PAY4),
	TXGBE_UKN(0xEE),
	TXGBE_UKN(0xEF),

	/* IPv6 --> GRE/NAT -> MAC--> NONE/IPv */
	TXGBE_PTT(0xF0, IP, IPV6, IGMV, NONE, NONE, PAY3),
	TXGBE_PTT(0xF1, IP, IPV6, IGMV, FGV4, NONE, PAY3),
	TXGBE_PTT(0xF2, IP, IPV6, IGMV, IPV4, NONE, PAY3),
	TXGBE_PTT(0xF3, IP, IPV6, IGMV, IPV4, UDP,  PAY4),
	TXGBE_PTT(0xF4, IP, IPV6, IGMV, IPV4, TCP,  PAY4),
	TXGBE_PTT(0xF5, IP, IPV6, IGMV, IPV4, SCTP, PAY4),
	TXGBE_UKN(0xF6),
	TXGBE_UKN(0xF7),
	TXGBE_UKN(0xF8),
	TXGBE_PTT(0xF9, IP, IPV6, IGMV, FGV6, NONE, PAY3),
	TXGBE_PTT(0xFA, IP, IPV6, IGMV, IPV6, NONE, PAY3),
	TXGBE_PTT(0xFB, IP, IPV6, IGMV, IPV6, UDP,  PAY4),
	TXGBE_PTT(0xFC, IP, IPV6, IGMV, IPV6, TCP,  PAY4),
	TXGBE_PTT(0xFD, IP, IPV6, IGMV, IPV6, SCTP, PAY4),
	TXGBE_UKN(0xFE),
	TXGBE_UKN(0xFF),
};





static void txgbe_get_mac_type(struct txgbe_hw *hw)
{
	switch (hw->device_id) {
	case TXGBE_DEV_ID_SP1000:
	case TXGBE_DEV_ID_WX1820:
		hw->mac.type = txgbe_mac_sp;
		break;
	case TXGBE_DEV_ID_AML:
	case TXGBE_DEV_ID_AML5025:
	case TXGBE_DEV_ID_AML5125:
		hw->mac.type = txgbe_mac_aml;
		break;
	case TXGBE_DEV_ID_AML5040:
	case TXGBE_DEV_ID_AML5140:
		hw->mac.type = txgbe_mac_aml40;
		break;
	default:
		hw->mac.type = txgbe_mac_unknown;
		break;
	}
}

static const struct txgbe_info *txgbe_info_tbl[] = {
	[txgbe_mac_sp]		= &txgbe_sp_info,
	[txgbe_mac_aml]		= &txgbe_aml_info,
	[txgbe_mac_aml40]	= &txgbe_aml40_info,
};

/**
 *  txgbe_init_shared_code - Initialize the shared code
 *  @hw: pointer to hardware structure
 *
 *  This will assign function pointers and assign the MAC type and PHY code.
 *  Does not touch the hardware. This function must be called prior to any
 *  other function in the shared code. The txgbe_hw structure should be
 *  memset to 0 prior to calling this function.  The following fields in
 *  hw structure should be filled in prior to calling this function:
 *  hw_addr, back, device_id, vendor_id, subsystem_device_id,
 *  subsystem_vendor_id, and revision_id
 **/
int txgbe_init_shared_code(struct txgbe_hw *hw)
{
	u32 flash_header = 0, flash_header_index = 0, ssid_addr = 0xfffdc;
	u32 fw_version, control_rate_led = 0, ocp_led_flag = 0, ssid;
	struct txgbe_adapter *adapter = hw->back;
	struct txgbe_mac_info *mac = &hw->mac;
	struct txgbe_phy_info *phy = &hw->phy;
	struct pci_dev *pdev = adapter->pdev;
	const struct txgbe_info *ti;
	int ret = 0;

	txgbe_get_mac_type(hw);
	ti = txgbe_info_tbl[hw->mac.type];

	if (hw->mac.type == txgbe_mac_sp)
		goto skip_flash_header_check;

	ret = txgbe_flash_read_dword(hw, 0x0, &flash_header);
	if (ret || flash_header == 0x1) {
		e_err(probe, "SPI access is bad.\n");
		return -EIO;
	}
	if (flash_header == U32_MAX) {
		txgbe_flash_read_dword(hw, 0x10000, &flash_header);
		if (((flash_header >> 16) & U16_MAX) ==
		    TXGBE_FLASH_HEADER_FLAG) {
			flash_header_index = 0x1;
		} else {
			e_err(probe, "Flash maybe empty.\n");
			return -EIO;
		}
	}

skip_flash_header_check:
	if (pdev->subsystem_vendor == 0x8088) {
		hw->subsystem_vendor_id = pdev->subsystem_vendor;
		hw->subsystem_device_id = pdev->subsystem_device;
	} else {
		if (hw->mac.type == txgbe_mac_aml ||
		    hw->mac.type == txgbe_mac_aml40)
			ssid_addr = (flash_header_index * 0x10000) + 0x302c;
		ret = txgbe_flash_read_dword(hw, ssid_addr, &ssid);
		if (ssid == 0x1) {
			e_err(probe, "read of internal subsystem device id failed\n");
			return ret;
		}
		hw->subsystem_device_id = swab16((u16)ssid);
	}

	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
		ocp_led_flag = (flash_header_index * 0x10000) + 0x3030;
		txgbe_flash_read_dword(hw, ocp_led_flag, &control_rate_led);
	} else {
		txgbe_flash_read_dword(hw, 0xfffc4, &control_rate_led);
	}
	if (!(control_rate_led & 0xff))
		set_bit(TXGBE_FLAG_CONTROL_RATE_LED, adapter->flag);

	txgbe_flash_read_dword(hw, (flash_header_index * 0x10000) + 0x13a, &fw_version);
	snprintf(adapter->fl_version, sizeof(adapter->fl_version), "0x%08x", fw_version);

	/* get_invariants needs the device IDs */
	ti->get_invariants(hw);
	mac->ops = *ti->mac_ops;
	phy->ops = *ti->phy_ops;

	return 0;
}

int txgbe_get_invariants_generic(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	struct txgbe_mac_info *mac = &hw->mac;
	struct txgbe_phy_info *phy = &hw->phy;

	/* Call PHY identify routine to get the phy type */
	txgbe_identify_phy_generic(hw);

	phy->sfp_type = txgbe_sfp_type_unknown;

	adapter->ring_feature[RING_F_FDIR].limit = min_t(int,
							 TXGBE_MAX_FDIR_INDICES,
							 num_online_cpus());

	adapter->max_q_vectors = TXGBE_MAX_MSIX_Q_VECTORS_SAPPHIRE;
	mac->rar_highwater = 1;
	/* Link */
	mac->mcft_size          = TXGBE_SP_MC_TBL_SIZE;
	mac->vft_size           = TXGBE_SP_VFT_TBL_SIZE;
	mac->num_rar_entries    = TXGBE_SP_RAR_ENTRIES;
	mac->rx_pb_size         = TXGBE_SP_RX_PB_SIZE;
	mac->max_rx_queues      = TXGBE_SP_MAX_RX_QUEUES;
	mac->max_tx_queues      = TXGBE_SP_MAX_TX_QUEUES;
	mac->max_msix_vectors   = txgbe_get_pcie_msix_count(hw);

	mac->arc_subsystem_valid = (rd32(hw, TXGBE_MIS_ST) &
				   TXGBE_MIS_ST_MNG_INIT_DN) ? true : false;

	/* default flow control settings */
	hw->fc.requested_mode = txgbe_fc_full;
	hw->fc.current_mode = txgbe_fc_full;    /* init for ethtool output */

	adapter->last_lfc_mode = hw->fc.current_mode;
	hw->fc.pause_time = TXGBE_DEFAULT_FCPAUSE;
	hw->fc.send_xon = true;
	hw->fc.disable_fc_autoneg = false;

	/* set default ring sizes */
	adapter->tx_ring_count = TXGBE_DEFAULT_TXD;
	adapter->rx_ring_count = TXGBE_DEFAULT_RXD;

	/* set default work limits */
	adapter->tx_work_limit = TXGBE_DEFAULT_TX_WORK;
	adapter->rx_work_limit = TXGBE_DEFAULT_RX_WORK;

	adapter->tx_timeout_recovery_level = 0;
	adapter->cmplt_to_dis = false;

	return 0;
}

static int txgbe_close_notify(struct txgbe_hw *hw)
{
	int tmp;
	int status;
	struct txgbe_hic_write_shadow_ram buffer;

	buffer.hdr.req.cmd = FW_DW_CLOSE_NOTIFY;
	buffer.hdr.req.buf_lenh = 0;
	buffer.hdr.req.buf_lenl = 0;

	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.req.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	/* one word */
	buffer.length = 0;
	buffer.address = 0;

	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer),
					      500, false);
	if (status)
		return status;

	if (txgbe_check_mng_access(hw)) {
		tmp = (u32)rd32a(hw, TXGBE_MNG_MBOX, 1);
		if (tmp == TXGBE_CHECKSUM_CAP_ST_PASS)
			status = 0;
		else
			status = TXGBE_ERR_EEPROM_CHECKSUM;
	} else {
		status = TXGBE_ERR_MNG_ACCESS_FAILED;
	}

	return status;
}

static int txgbe_open_notify(struct txgbe_hw *hw)
{
	int tmp;
	int status;
	struct txgbe_hic_write_shadow_ram buffer;

	buffer.hdr.req.cmd = FW_DW_OPEN_NOTIFY;
	buffer.hdr.req.buf_lenh = 0;
	buffer.hdr.req.buf_lenl = 0;

	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.req.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	/* one word */
	buffer.length = 0;
	buffer.address = 0;

	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer),
					      500, false);
	if (status)
		return status;

	if (txgbe_check_mng_access(hw)) {
		tmp = (u32)rd32a(hw, TXGBE_MNG_MBOX, 1);
		if (tmp == TXGBE_CHECKSUM_CAP_ST_PASS)
			status = 0;
		else
			status = TXGBE_ERR_EEPROM_CHECKSUM;
	} else {
		status = TXGBE_ERR_MNG_ACCESS_FAILED;
	}

	return status;
}

/**
 * txgbe_check_reset_blocked - check status of MNG FW veto bit
 * @hw: pointer to the hardware structure
 *
 * This function checks the MMNGC.MNG_VETO bit to see if there are
 * any constraints on link from manageability.  For MAC's that don't
 * have this bit just return faluse since the link can not be blocked
 * via this method.
 **/
int txgbe_check_reset_blocked(struct txgbe_hw *hw)
{
	u32 mmngc = rd32(hw, TXGBE_MIS_ST);

	if (mmngc & TXGBE_MIS_ST_MNG_VETO)
		return true;

	return false;
}

/**
 *  txgbe_disable_tx_laser_multispeed_fiber - Disable Tx laser
 *  @hw: pointer to hardware structure
 *
 *  The base drivers may require better control over SFP+ module
 *  PHY states.  This includes selectively shutting down the Tx
 *  laser on the PHY, effectively halting physical link.
 **/
void txgbe_disable_tx_laser_multispeed_fiber(struct txgbe_hw *hw)
{
	u32 esdp_reg = rd32(hw, TXGBE_GPIO_DR);

	if (!((hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber) ||
	      (hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber_qsfp)))
		return;
	/* Blocked by MNG FW so bail */
	txgbe_check_reset_blocked(hw);

	if (txgbe_close_notify(hw)) {
		/* over write led when ifconfig down */
		if (hw->mac.type == txgbe_mac_aml40)
			txgbe_led_off(hw, TXGBE_LED_LINK_UP | TXGBE_AMLITE_LED_LINK_40G |
					TXGBE_AMLITE_LED_LINK_ACTIVE);
		else if (hw->mac.type == txgbe_mac_aml)
			txgbe_led_off(hw, TXGBE_LED_LINK_UP | TXGBE_AMLITE_LED_LINK_25G |
					TXGBE_AMLITE_LED_LINK_10G | TXGBE_AMLITE_LED_LINK_ACTIVE);
		else
			txgbe_led_off(hw, TXGBE_LED_LINK_UP |
							TXGBE_LED_LINK_10G | TXGBE_LED_LINK_1G |
							TXGBE_LED_LINK_ACTIVE);
	}

	/* Disable Tx laser; allow 100us to go dark per spec */
	if (hw->mac.type == txgbe_mac_aml40) {
		wr32m(hw, TXGBE_GPIO_DDR, TXGBE_GPIO_DR_1, TXGBE_GPIO_DR_1);
		esdp_reg &= ~TXGBE_GPIO_DR_1;
	} else if (hw->mac.type == txgbe_mac_aml) {
		esdp_reg |= TXGBE_GPIO_DR_1;
	} else {
		esdp_reg |= TXGBE_GPIO_DR_1 | TXGBE_GPIO_DR_0;
	}

	wr32(hw, TXGBE_GPIO_DR, esdp_reg);
	TXGBE_WRITE_FLUSH(hw);
	usec_delay(100);
}

/**
 *  txgbe_enable_tx_laser_multispeed_fiber - Enable Tx laser
 *  @hw: pointer to hardware structure
 *
 *  The base drivers may require better control over SFP+ module
 *  PHY states.  This includes selectively turning on the Tx
 *  laser on the PHY, effectively starting physical link.
 **/
void txgbe_enable_tx_laser_multispeed_fiber(struct txgbe_hw *hw)
{
	if (!((hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber) ||
	      (hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber_qsfp)))
		return;
	if (txgbe_open_notify(hw))
		/* recover led configure when ifconfig up */
		wr32(hw, TXGBE_CFG_LED_CTL, 0);

	/* Enable Tx laser; allow 100ms to light up */
	if (hw->mac.type == txgbe_mac_aml40) {
		wr32m(hw, TXGBE_GPIO_DDR, TXGBE_GPIO_DR_1, TXGBE_GPIO_DR_1);
		wr32m(hw, TXGBE_GPIO_DR, TXGBE_GPIO_DR_1, TXGBE_GPIO_DR_1);
	} else {
		wr32m(hw, TXGBE_GPIO_DR,
		      TXGBE_GPIO_DR_0 | TXGBE_GPIO_DR_1, 0);
	}
	TXGBE_WRITE_FLUSH(hw);
	msec_delay(100);
}

/**
 *  txgbe_flap_tx_laser_multispeed_fiber - Flap Tx laser
 *  @hw: pointer to hardware structure
 *
 *  When the driver changes the link speeds that it can support,
 *  it sets autotry_restart to true to indicate that we need to
 *  initiate a new autotry session with the link partner.  To do
 *  so, we set the speed then disable and re-enable the Tx laser, to
 *  alert the link partner that it also needs to restart autotry on its
 *  end.  This is consistent with true clause 37 autoneg, which also
 *  involves a loss of signal.
 **/
void txgbe_flap_tx_laser_multispeed_fiber(struct txgbe_hw *hw)
{
	if (!((hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber) ||
	      (hw->mac.ops.get_media_type(hw) == txgbe_media_type_fiber_qsfp)))
		return;

	/* Blocked by MNG FW so bail */
	txgbe_check_reset_blocked(hw);

	if (hw->mac.autotry_restart) {
		txgbe_disable_tx_laser_multispeed_fiber(hw);
		txgbe_enable_tx_laser_multispeed_fiber(hw);
		hw->mac.autotry_restart = false;
	}
}

/**
 *  txgbe_set_hard_rate_select_speed - Set module link speed
 *  @hw: pointer to hardware structure
 *  @speed: link speed to set
 *
 *  Set module link speed via RS0/RS1 rate select pins.
 */
void txgbe_set_hard_rate_select_speed(struct txgbe_hw *hw,
				      u32 speed)
{
	u32 esdp_reg = rd32(hw, TXGBE_GPIO_DR);

	switch (speed) {
	case TXGBE_LINK_SPEED_25GB_FULL:
		/*amlite TODO*/
		break;
	case TXGBE_LINK_SPEED_10GB_FULL:
		esdp_reg |= TXGBE_GPIO_DR_5 | TXGBE_GPIO_DR_4;
		break;
	case TXGBE_LINK_SPEED_1GB_FULL:
		esdp_reg &= ~(TXGBE_GPIO_DR_5 | TXGBE_GPIO_DR_4);
		break;
	default:
		return;
	}

	wr32(hw, TXGBE_GPIO_DDR,
	     TXGBE_GPIO_DDR_5 | TXGBE_GPIO_DDR_4 |
		TXGBE_GPIO_DDR_1 | TXGBE_GPIO_DDR_0);

	wr32(hw, TXGBE_GPIO_DR, esdp_reg);

	TXGBE_WRITE_FLUSH(hw);
}


int txgbe_enable_rx_adapter(struct txgbe_hw *hw)
{
	int ret = 0;
	u32 value;

	value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_CTL);
	value |= BIT(12);
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL, value);

	value = 0;
	ret = read_poll_timeout(txgbe_rd32_epcs, value, (value & BIT(11)), 1000,
				200000, false, hw, TXGBE_PHY_RX_AD_ACK);
	if (ret)
		return -ETIMEDOUT;

	value = txgbe_rd32_epcs(hw, TXGBE_PHY_RX_EQ_CTL);
	value &= ~BIT(12);
	txgbe_wr32_epcs(hw, TXGBE_PHY_RX_EQ_CTL, value);

	return 0;
}







int txgbe_reconfig_mac(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	u32 mac_wdg_timeout;
	u32 mac_flow_ctrl;

	if (test_bit(TXGBE_FLAG_FW_CONTROL_PHY, adapter->flag))
		return 0;

	mac_wdg_timeout = rd32(hw, TXGBE_MAC_WDG_TIMEOUT);
	mac_flow_ctrl = rd32(hw, TXGBE_MAC_RX_FLOW_CTRL);

	if (hw->bus.lan_id == 0)
		wr32(hw, TXGBE_MIS_RST, TXGBE_MIS_RST_LAN0_MAC_RST);
	else if (hw->bus.lan_id == 1)
		wr32(hw, TXGBE_MIS_RST, TXGBE_MIS_RST_LAN1_MAC_RST);

	/* wait for mac rst complete */
	usec_delay(1500);
	wr32m(hw, TXGBE_MAC_MISC_CTL, TXGBE_MAC_MISC_LINK_STS_MOD,
	      TXGBE_LINK_BOTH_PCS_MAC);

	/* receive packets that size > 2048 */
	wr32m(hw, TXGBE_MAC_RX_CFG,
	      TXGBE_MAC_RX_CFG_JE, TXGBE_MAC_RX_CFG_JE);

	/* clear counters on read */
	wr32m(hw, TXGBE_MMC_CONTROL,
	      TXGBE_MMC_CONTROL_RSTONRD, TXGBE_MMC_CONTROL_RSTONRD);

	wr32m(hw, TXGBE_MAC_RX_FLOW_CTRL,
	      TXGBE_MAC_RX_FLOW_CTRL_RFE, TXGBE_MAC_RX_FLOW_CTRL_RFE);

	wr32(hw, TXGBE_MAC_PKT_FLT,
	     TXGBE_MAC_PKT_FLT_PR);

	wr32(hw, TXGBE_MAC_WDG_TIMEOUT, mac_wdg_timeout);
	wr32(hw, TXGBE_MAC_RX_FLOW_CTRL, mac_flow_ctrl);

	return 0;
}

static int txgbe_reset_misc(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = hw->back;
	u32 value;
	u32 err;
	int i;

	if (hw->mac.type == txgbe_mac_aml40) {
		if (!(rd32(hw, TXGBE_EPHY_STAT) & TXGBE_EPHY_STAT_PPL_LOCK)) {
			err = hw->mac.ops.setup_link(hw, TXGBE_LINK_SPEED_40GB_FULL, false);
			if (err) {
				e_dev_info("%s setup phy failed\n", __func__);
				return err;
			}
		}
	} else if (hw->mac.type == txgbe_mac_aml) {
		if ((rd32(hw, TXGBE_EPHY_STAT) & TXGBE_EPHY_STAT_PPL_LOCK)
								!= TXGBE_EPHY_STAT_PPL_LOCK) {
			err = hw->mac.ops.setup_link(hw, TXGBE_LINK_SPEED_AMLITE_AUTONEG, false);
			if (err) {
				e_dev_info("%s setup phy failed\n", __func__);
				return err;
			}
		}
	} else {
		value = txgbe_rd32_epcs(hw, TXGBE_SR_PCS_CTL2);
		if ((value & 0x3) != TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_X)
			hw->link_status = TXGBE_LINK_STATUS_NONE;
	}

	/* receive packets that size > 2048 */
	wr32m(hw, TXGBE_MAC_RX_CFG,
	      TXGBE_MAC_RX_CFG_JE, TXGBE_MAC_RX_CFG_JE);

	/* clear counters on read */
	wr32m(hw, TXGBE_MMC_CONTROL,
	      TXGBE_MMC_CONTROL_RSTONRD, TXGBE_MMC_CONTROL_RSTONRD);

	wr32m(hw, TXGBE_MAC_RX_FLOW_CTRL,
	      TXGBE_MAC_RX_FLOW_CTRL_RFE, TXGBE_MAC_RX_FLOW_CTRL_RFE);

	wr32(hw, TXGBE_MAC_PKT_FLT,
	     TXGBE_MAC_PKT_FLT_PR);

	wr32m(hw, TXGBE_MIS_RST_ST,
	      TXGBE_MIS_RST_ST_RST_INIT, 0xA00);

	wr32(hw, TXGBE_PSR_LAN_FLEX_SEL, 0);
	for (i = 0; i < 16; i++) {
		wr32(hw, TXGBE_PSR_LAN_FLEX_DW_L(i), 0);
		wr32(hw, TXGBE_PSR_LAN_FLEX_DW_H(i), 0);
		wr32(hw, TXGBE_PSR_LAN_FLEX_MSK(i), 0);
	}

	/* set pause frame dst mac addr */
	wr32(hw, TXGBE_RDB_PFCMACDAL, 0xC2000001);
	wr32(hw, TXGBE_RDB_PFCMACDAH, 0x0180);

	txgbe_init_thermal_sensor_thresh(hw);

	return 0;
}

/**
 *  txgbe_reset_hw - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
int txgbe_reset_hw(struct txgbe_hw *hw)
{
	u32 sr_pcs_ctl, sr_pma_mmd_ctl1, sr_an_mmd_ctl, sr_an_mmd_adv_reg2;
	u32 curr_sr_an_mmd_ctl = 0, curr_sr_an_mmd_adv_reg2 = 0;
	u32 curr_sr_pcs_ctl = 0, curr_sr_pma_mmd_ctl1 = 0;
	struct txgbe_adapter *adapter = hw->back;
	u32 curr_vr_xs_or_pcs_mmd_digi_ctl1 = 0;
	u32 vr_xs_or_pcs_mmd_digi_ctl1;
	u32 reset_status = 0;
	u32 rst_delay = 0;
	u32 reset = 0;
	int status;
	u32 i;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	status = hw->mac.ops.stop_adapter(hw);
	if (status != 0)
		goto reset_hw_out;

	/* Identify PHY and related function pointers */
	status = hw->phy.ops.init(hw);

	if (status == TXGBE_ERR_SFP_NOT_SUPPORTED)
		goto reset_hw_out;

	if (hw->mac.type == txgbe_mac_sp) {
		/* remember internal phy regs from before we reset */
		curr_sr_pcs_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_PCS_CTL2);
		curr_sr_pma_mmd_ctl1 = txgbe_rd32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1);
		curr_sr_an_mmd_ctl = txgbe_rd32_epcs(hw, TXGBE_SR_AN_MMD_CTL);
		curr_sr_an_mmd_adv_reg2 = txgbe_rd32_epcs(hw,
							  TXGBE_SR_AN_MMD_ADV_REG2);
		curr_vr_xs_or_pcs_mmd_digi_ctl1 =
			txgbe_rd32_epcs(hw, TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1);
	}

	/* Issue global reset to the MAC.  Needs to be SW reset if link is up.
	 * If link reset is used when link is up, it might reset the PHY when
	 * mng is using it.  If link is down or the flag to force full link
	 * reset is set, then perform link reset.
	 */
	if (hw->force_full_reset) {
		rst_delay = (rd32(hw, TXGBE_MIS_RST_ST) &
			TXGBE_MIS_RST_ST_RST_INIT) >>
			TXGBE_MIS_RST_ST_RST_INI_SHIFT;
		if (hw->reset_type == TXGBE_SW_RESET) {
			for (i = 0; i < rst_delay + 20; i++) {
				reset_status =
					rd32(hw, TXGBE_MIS_RST_ST);
				if (!(reset_status &
				    TXGBE_MIS_RST_ST_DEV_RST_ST_MASK))
					break;
				msleep(100);
			}

			if (reset_status & TXGBE_MIS_RST_ST_DEV_RST_ST_MASK) {
				status = TXGBE_ERR_RESET_FAILED;
				goto reset_hw_out;
			}
			status = txgbe_check_flash_load(hw,
							TXGBE_SPI_ILDR_STATUS_SW_RESET);
			if (status != 0)
				goto reset_hw_out;
			/* errata 7 */
			if (txgbe_mng_present(hw) &&
			    hw->revision_id == TXGBE_SP_MPW) {
				struct txgbe_adapter *adapter =
					(struct txgbe_adapter *)hw->back;
				adapter->flags2 &=
					~TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED;
			}
		} else if (hw->reset_type == TXGBE_GLOBAL_RESET) {
			struct txgbe_adapter *adapter =
					(struct txgbe_adapter *)hw->back;
			msleep(100 * rst_delay + 2000);
			pci_restore_state(adapter->pdev);
			pci_save_state(adapter->pdev);
			pci_wake_from_d3(adapter->pdev, false);
		}
	} else {
		if (hw->bus.lan_id == 0)
			reset = TXGBE_MIS_RST_LAN0_RST;
		else
			reset = TXGBE_MIS_RST_LAN1_RST;

		wr32(hw, TXGBE_MIS_RST,
		     reset | rd32(hw, TXGBE_MIS_RST));
		TXGBE_WRITE_FLUSH(hw);
		usec_delay(10);

		if (hw->bus.lan_id == 0) {
			status = txgbe_check_flash_load(hw,
							TXGBE_SPI_ILDR_STATUS_LAN0_SW_RST);
		} else {
			status = txgbe_check_flash_load(hw,
							TXGBE_SPI_ILDR_STATUS_LAN1_SW_RST);
		}
		if (status != 0)
			goto reset_hw_out;
	}

	status = txgbe_reset_misc(hw);
	if (status != 0)
		goto reset_hw_out;

	status = txgbe_reset_misc(hw);
	if (status != 0)
		goto reset_hw_out;

	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
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
	} else {
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
			hw->mac.orig_sr_an_mmd_adv_reg2 =
						curr_sr_an_mmd_adv_reg2;
			hw->mac.orig_vr_xs_or_pcs_mmd_digi_ctl1 =
						curr_vr_xs_or_pcs_mmd_digi_ctl1;
		}
	}

	/*make sure phy power is up*/
	msleep(100);
	txgbe_xpcs_txffe_set(adapter);

	/* Store MAC address from RAR0, clear receive address registers, and
	 * clear the multicast table.  Also reset num_rar_entries to 128,
	 * since we modify this value when programming the SAN MAC address.
	 */
	hw->mac.num_rar_entries = 128;
	hw->mac.ops.init_rx_addrs(hw);

	/* Add the SAN MAC address to the RAR only if it's a valid address */
	if (txgbe_validate_mac_addr(hw->mac.san_addr) == 0) {
		hw->mac.ops.set_rar(hw, hw->mac.num_rar_entries - 1,
		      hw->mac.san_addr, 0, TXGBE_PSR_MAC_SWC_AD_H_AV);

		/* Save the SAN MAC RAR index */
		hw->mac.san_mac_rar_index = hw->mac.num_rar_entries - 1;

		/* Reserve the last RAR for the SAN MAC address */
		hw->mac.num_rar_entries--;
	}

	pci_set_master(((struct txgbe_adapter *)hw->back)->pdev);

reset_hw_out:
	return status;
}

/**
 * txgbe_fdir_check_cmd_complete - poll to check whether FDIRCMD is complete
 * @hw: pointer to hardware structure
 * @fdircmd: current value of FDIRCMD register
 */
static int txgbe_fdir_check_cmd_complete(struct txgbe_hw *hw, u32 *fdircmd)
{
	int i;

	for (i = 0; i < TXGBE_RDB_FDIR_CMD_CMD_POLL; i++) {
		*fdircmd = rd32(hw, TXGBE_RDB_FDIR_CMD);
		if (!(*fdircmd & TXGBE_RDB_FDIR_CMD_CMD_MASK))
			return 0;
		usec_delay(10);
	}

	return TXGBE_ERR_FDIR_CMD_INCOMPLETE;
}

/**
 *  txgbe_reinit_fdir_tables - Reinitialize Flow Director tables.
 *  @hw: pointer to hardware structure
 **/
int txgbe_reinit_fdir_tables(struct txgbe_hw *hw)
{
	int err;
	int i;
	u32 fdirctrl = rd32(hw, TXGBE_RDB_FDIR_CTL);
	u32 fdircmd;

	fdirctrl &= ~TXGBE_RDB_FDIR_CTL_INIT_DONE;

	/* Before starting reinitialization process,
	 * FDIRCMD.CMD must be zero.
	 */
	err = txgbe_fdir_check_cmd_complete(hw, &fdircmd);
	if (err)
		return err;

	wr32(hw, TXGBE_RDB_FDIR_FREE, 0);
	TXGBE_WRITE_FLUSH(hw);
	/* sapphire/amber-lite adapters flow director init flow cannot be
	 * restarted, Workaround sapphire/amber-lite
	 * silicon errata by performing the following steps
	 * before re-writing the FDIRCTRL control register with the same value.
	 * - write 1 to bit 8 of FDIRCMD register &
	 * - write 0 to bit 8 of FDIRCMD register
	 */
	wr32m(hw, TXGBE_RDB_FDIR_CMD,
	      TXGBE_RDB_FDIR_CMD_CLEARHT, TXGBE_RDB_FDIR_CMD_CLEARHT);
	TXGBE_WRITE_FLUSH(hw);
	wr32m(hw, TXGBE_RDB_FDIR_CMD,
	      TXGBE_RDB_FDIR_CMD_CLEARHT, 0);
	TXGBE_WRITE_FLUSH(hw);
	/* Clear FDIR Hash register to clear any leftover hashes
	 * waiting to be programmed.
	 */
	wr32(hw, TXGBE_RDB_FDIR_HASH, 0x00);
	TXGBE_WRITE_FLUSH(hw);

	wr32(hw, TXGBE_RDB_FDIR_CTL, fdirctrl);
	TXGBE_WRITE_FLUSH(hw);

	/* Poll init-done after we write FDIRCTRL register */
	for (i = 0; i < TXGBE_FDIR_INIT_DONE_POLL; i++) {
		if (rd32(hw, TXGBE_RDB_FDIR_CTL) &
				   TXGBE_RDB_FDIR_CTL_INIT_DONE)
			break;
		msec_delay(1);
	}
	if (i >= TXGBE_FDIR_INIT_DONE_POLL)
		return TXGBE_ERR_FDIR_REINIT_FAILED;

	/* Clear FDIR statistics registers (read to clear) */
	rd32(hw, TXGBE_RDB_FDIR_USE_ST);
	rd32(hw, TXGBE_RDB_FDIR_FAIL_ST);
	rd32(hw, TXGBE_RDB_FDIR_MATCH);
	rd32(hw, TXGBE_RDB_FDIR_MISS);
	rd32(hw, TXGBE_RDB_FDIR_LEN);

	return 0;
}

/**
 *  txgbe_fdir_enable - Initialize Flow Director control registers
 *  @hw: pointer to hardware structure
 *  @fdirctrl: value to write to flow director control register
 **/
static void txgbe_fdir_enable(struct txgbe_hw *hw, u32 fdirctrl)
{
	int i;

	/* Prime the keys for hashing */
	wr32(hw, TXGBE_RDB_FDIR_HKEY, TXGBE_ATR_BUCKET_HASH_KEY);
	wr32(hw, TXGBE_RDB_FDIR_SKEY, TXGBE_ATR_SIGNATURE_HASH_KEY);

	/* Poll init-done after we write the register.  Estimated times:
	 *      10G: PBALLOC = 11b, timing is 60us
	 *       1G: PBALLOC = 11b, timing is 600us
	 *     100M: PBALLOC = 11b, timing is 6ms
	 *
	 *     Multiple these timings by 4 if under full Rx load
	 *
	 * So we'll poll for TXGBE_FDIR_INIT_DONE_POLL times, sleeping for
	 * 1 msec per poll time.  If we're at line rate and drop to 100M, then
	 * this might not finish in our poll time, but we can live with that
	 * for now.
	 */
	wr32(hw, TXGBE_RDB_FDIR_CTL, fdirctrl);
	TXGBE_WRITE_FLUSH(hw);
	for (i = 0; i < TXGBE_RDB_FDIR_INIT_DONE_POLL; i++) {
		if (rd32(hw, TXGBE_RDB_FDIR_CTL) &
				   TXGBE_RDB_FDIR_CTL_INIT_DONE)
			break;
		msec_delay(1);
	}
}

/**
 *  txgbe_init_fdir_signature -Initialize Flow Director sig filters
 *  @hw: pointer to hardware structure
 *  @fdirctrl: value to write to flow director control register, initially
 *           contains just the value of the Rx packet buffer allocation
 **/
int txgbe_init_fdir_signature(struct txgbe_hw *hw, u32 fdirctrl)
{
	struct txgbe_adapter *adapter = (struct txgbe_adapter *)hw->back;

	int i = VMDQ_P(0) / 4;
	int j = VMDQ_P(0) % 4;
	u32 flex = rd32m(hw, TXGBE_RDB_FDIR_FLEX_CFG(i),
		~((TXGBE_RDB_FDIR_FLEX_CFG_BASE_MSK |
		TXGBE_RDB_FDIR_FLEX_CFG_MSK |
		TXGBE_RDB_FDIR_FLEX_CFG_OFST) <<
		(TXGBE_RDB_FDIR_FLEX_CFG_VM_SHIFT * j)));

	flex |= (TXGBE_RDB_FDIR_FLEX_CFG_BASE_MAC |
		0x6 << TXGBE_RDB_FDIR_FLEX_CFG_OFST_SHIFT) <<
		(TXGBE_RDB_FDIR_FLEX_CFG_VM_SHIFT * j);
	wr32(hw, TXGBE_RDB_FDIR_FLEX_CFG(i), flex);

	/* Continue setup of fdirctrl register bits:
	 *  Move the flexible bytes to use the ethertype - shift 6 words
	 *  Set the maximum length per hash bucket to 0xA filters
	 *  Send interrupt when 64 filters are left
	 */
	fdirctrl |= (0xF << TXGBE_RDB_FDIR_CTL_HASH_BITS_SHIFT) |
		    (0xA << TXGBE_RDB_FDIR_CTL_MAX_LENGTH_SHIFT) |
		    (4 << TXGBE_RDB_FDIR_CTL_FULL_THRESH_SHIFT);

	/* write hashes and fdirctrl register, poll for completion */
	txgbe_fdir_enable(hw, fdirctrl);

	if (hw->revision_id == TXGBE_SP_MPW)
		wr32m(hw, TXGBE_PX_RR_CFG(0),
		      TXGBE_PX_RR_CFG_RSC, ~TXGBE_PX_RR_CFG_RSC);

	return 0;
}

/**
 *  txgbe_init_fdir_perfect - Initialize Flow Director perfect filters
 *  @hw: pointer to hardware structure
 *  @fdirctrl: value to write to flow director control register, initially
 *           contains just the value of the Rx packet buffer allocation
 **/
int txgbe_init_fdir_perfect(struct txgbe_hw *hw, u32 fdirctrl)
{
	/* Continue setup of fdirctrl register bits:
	 * Turn perfect match filtering on
	 * Report hash in RSS field of Rx wb descriptor
	 * Initialize the drop queue
	 * Move the flexible bytes to use the ethertype - shift 6 words
	 * Set the maximum length per hash bucket to 0xA filters
	 * Send interrupt when 64 (0x4 * 16) filters are left
	 */
	fdirctrl |= TXGBE_RDB_FDIR_CTL_PERFECT_MATCH |
		    (TXGBE_RDB_FDIR_DROP_QUEUE <<
		    TXGBE_RDB_FDIR_CTL_DROP_Q_SHIFT) |
		    (0xF << TXGBE_RDB_FDIR_CTL_HASH_BITS_SHIFT) |
		    (0xA << TXGBE_RDB_FDIR_CTL_MAX_LENGTH_SHIFT) |
		    (4 << TXGBE_RDB_FDIR_CTL_FULL_THRESH_SHIFT);

	/* write hashes and fdirctrl register, poll for completion */
	txgbe_fdir_enable(hw, fdirctrl);

	if (hw->revision_id == TXGBE_SP_MPW) {
		if (((struct txgbe_adapter *)hw->back)->num_rx_queues >
			TXGBE_RDB_FDIR_DROP_QUEUE)
			/* errata 1: disable RSC of drop ring */
			wr32m(hw,
			      TXGBE_PX_RR_CFG(TXGBE_RDB_FDIR_DROP_QUEUE),
					TXGBE_PX_RR_CFG_RSC, ~TXGBE_PX_RR_CFG_RSC);
	}
	return 0;
}

/* These defines allow us to quickly generate all of the necessary instructions
 * in the function below by simply calling out TXGBE_COMPUTE_SIG_HASH_ITERATION
 * for values 0 through 15
 */
#define TXGBE_ATR_COMMON_HASH_KEY \
		(TXGBE_ATR_BUCKET_HASH_KEY & TXGBE_ATR_SIGNATURE_HASH_KEY)
#define TXGBE_COMPUTE_SIG_HASH_ITERATION(_n) \
do { \
	u32 n = (_n); \
	if (TXGBE_ATR_COMMON_HASH_KEY & (0x01 << n)) \
		common_hash ^= lo_hash_dword >> n; \
	else if (TXGBE_ATR_BUCKET_HASH_KEY & (0x01 << n)) \
		bucket_hash ^= lo_hash_dword >> n; \
	else if (TXGBE_ATR_SIGNATURE_HASH_KEY & (0x01 << n)) \
		sig_hash ^= lo_hash_dword << (16 - n); \
	if (TXGBE_ATR_COMMON_HASH_KEY & (0x01 << (n + 16))) \
		common_hash ^= hi_hash_dword >> n; \
	else if (TXGBE_ATR_BUCKET_HASH_KEY & (0x01 << (n + 16))) \
		bucket_hash ^= hi_hash_dword >> n; \
	else if (TXGBE_ATR_SIGNATURE_HASH_KEY & (0x01 << (n + 16))) \
		sig_hash ^= hi_hash_dword << (16 - n); \
} while (0)

/**
 *  txgbe_atr_compute_sig_hash - Compute the signature hash
 *  @input: unique input dword
 *  @common: compressed common input dword
 *
 *  This function is almost identical to the function above but contains
 *  several optimizations such as unwinding all of the loops, letting the
 *  compiler work out all of the conditional ifs since the keys are static
 *  defines, and computing two keys at once since the hashed dword stream
 *  will be the same for both keys.
 **/
static u32 txgbe_atr_compute_sig_hash(union txgbe_atr_hash_dword input,
				      union txgbe_atr_hash_dword common)
{
	u32 hi_hash_dword, lo_hash_dword, flow_vm_vlan;
	u32 sig_hash = 0, bucket_hash = 0, common_hash = 0;

	/* record the flow_vm_vlan bits as they are a key part to the hash */
	flow_vm_vlan = TXGBE_NTOHL(input.dword);

	/* generate common hash dword */
	hi_hash_dword = TXGBE_NTOHL(common.dword);

	/* low dword is word swapped version of common */
	lo_hash_dword = (hi_hash_dword >> 16) | (hi_hash_dword << 16);

	/* apply flow ID/VM pool/VLAN ID bits to hash words */
	hi_hash_dword ^= flow_vm_vlan ^ (flow_vm_vlan >> 16);

	/* Process bits 0 and 16 */
	TXGBE_COMPUTE_SIG_HASH_ITERATION(0);

	/* apply flow ID/VM pool/VLAN ID bits to lo hash dword, we had to
	 * delay this because bit 0 of the stream should not be processed
	 * so we do not add the VLAN until after bit 0 was processed
	 */
	lo_hash_dword ^= flow_vm_vlan ^ (flow_vm_vlan << 16);

	/* Process remaining 30 bit of the key */
	TXGBE_COMPUTE_SIG_HASH_ITERATION(1);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(2);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(3);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(4);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(5);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(6);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(7);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(8);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(9);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(10);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(11);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(12);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(13);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(14);
	TXGBE_COMPUTE_SIG_HASH_ITERATION(15);

	/* combine common_hash result with signature and bucket hashes */
	bucket_hash ^= common_hash;
	bucket_hash &= TXGBE_ATR_HASH_MASK;

	sig_hash ^= common_hash << 16;
	sig_hash &= TXGBE_ATR_HASH_MASK << 16;

	/* return completed signature hash */
	return sig_hash ^ bucket_hash;
}

/**
 *  txgbe_fdir_add_signature_filter - Adds a signature hash filter
 *  @hw: pointer to hardware structure
 *  @input: unique input dword
 *  @common: compressed common input dword
 *  @queue: queue index to direct traffic to
 **/
int txgbe_fdir_add_signature_filter(struct txgbe_hw *hw,
				    union txgbe_atr_hash_dword input,
					  union txgbe_atr_hash_dword common,
					  u8 queue)
{
	u32 fdirhashcmd = 0;
	u8 flow_type;
	u32 fdircmd;
	int err;

	/* Get the flow_type in order to program FDIRCMD properly
	 * lowest 2 bits are FDIRCMD.L4TYPE, third lowest bit is FDIRCMD.IPV6
	 * fifth is FDIRCMD.TUNNEL_FILTER
	 */
	flow_type = input.formatted.flow_type;
	switch (flow_type) {
	case TXGBE_ATR_FLOW_TYPE_TCPV4:
	case TXGBE_ATR_FLOW_TYPE_UDPV4:
	case TXGBE_ATR_FLOW_TYPE_SCTPV4:
	case TXGBE_ATR_FLOW_TYPE_TCPV6:
	case TXGBE_ATR_FLOW_TYPE_UDPV6:
	case TXGBE_ATR_FLOW_TYPE_SCTPV6:
		break;
	default:
		return TXGBE_ERR_CONFIG;
	}

	/* configure FDIRCMD register */
	fdircmd = TXGBE_RDB_FDIR_CMD_CMD_ADD_FLOW |
		  TXGBE_RDB_FDIR_CMD_FILTER_UPDATE |
		  TXGBE_RDB_FDIR_CMD_LAST | TXGBE_RDB_FDIR_CMD_QUEUE_EN;
	fdircmd |= (u32)flow_type << TXGBE_RDB_FDIR_CMD_FLOW_TYPE_SHIFT;
	fdircmd |= (u32)queue << TXGBE_RDB_FDIR_CMD_RX_QUEUE_SHIFT;

	fdirhashcmd |= txgbe_atr_compute_sig_hash(input, common);
	fdirhashcmd |= 0x1 << TXGBE_RDB_FDIR_HASH_BUCKET_VALID_SHIFT;
	wr32(hw, TXGBE_RDB_FDIR_HASH, fdirhashcmd);

	wr32(hw, TXGBE_RDB_FDIR_CMD, fdircmd);

	err = txgbe_fdir_check_cmd_complete(hw, &fdircmd);
	if (err)
		return err;

	return 0;
}

#define TXGBE_COMPUTE_BKT_HASH_ITERATION(_n) \
do { \
	u32 n = (_n); \
	if (TXGBE_ATR_BUCKET_HASH_KEY & (0x01 << n)) \
		bucket_hash ^= lo_hash_dword >> n; \
	if (TXGBE_ATR_BUCKET_HASH_KEY & (0x01 << (n + 16))) \
		bucket_hash ^= hi_hash_dword >> n; \
} while (0)

/**
 *  txgbe_atr_compute_perfect_hash - Compute the perfect filter hash
 *  @input: input bitstream to compute the hash on
 *  @input_mask: mask for the input bitstream
 *
 *  This function serves two main purposes.  First it applies the input_mask
 *  to the atr_input resulting in a cleaned up atr_input data stream.
 *  Secondly it computes the hash and stores it in the bkt_hash field at
 *  the end of the input byte stream.  This way it will be available for
 *  future use without needing to recompute the hash.
 **/
void txgbe_atr_compute_perfect_hash(union txgbe_atr_input *input,
				    union txgbe_atr_input *input_mask)
{
	u32 hi_hash_dword, lo_hash_dword, flow_vm_vlan;
	u32 bucket_hash = 0;
	u32 hi_dword = 0;
	u32 i = 0;

	/* Apply masks to input data */
	for (i = 0; i < 11; i++)
		input->dword_stream[i]  &= input_mask->dword_stream[i];

	/* record the flow_vm_vlan bits as they are a key part to the hash */
	flow_vm_vlan = TXGBE_NTOHL(input->dword_stream[0]);

	/* generate common hash dword */
	for (i = 1; i <= 10; i++)
		hi_dword ^= input->dword_stream[i];
	hi_hash_dword = TXGBE_NTOHL(hi_dword);

	/* low dword is word swapped version of common */
	lo_hash_dword = (hi_hash_dword >> 16) | (hi_hash_dword << 16);

	/* apply flow ID/VM pool/VLAN ID bits to hash words */
	hi_hash_dword ^= flow_vm_vlan ^ (flow_vm_vlan >> 16);

	/* Process bits 0 and 16 */
	TXGBE_COMPUTE_BKT_HASH_ITERATION(0);

	/* apply flow ID/VM pool/VLAN ID bits to lo hash dword, we had to
	 * delay this because bit 0 of the stream should not be processed
	 * so we do not add the VLAN until after bit 0 was processed
	 */
	lo_hash_dword ^= flow_vm_vlan ^ (flow_vm_vlan << 16);

	/* Process remaining 30 bit of the key */
	for (i = 1; i <= 15; i++)
		TXGBE_COMPUTE_BKT_HASH_ITERATION(i);

	/* Limit hash to 13 bits since max bucket count is 8K.
	 * Store result at the end of the input stream.
	 */
	input->formatted.bkt_hash = bucket_hash & 0x1FFF;
}

/**
 *  txgbe_get_fdirtcpm - generate a TCP port from atr_input_masks
 *  @input_mask: mask to be bit swapped
 *
 *  The source and destination port masks for flow director are bit swapped
 *  in that bit 15 effects bit 0, 14 effects 1, 13, 2 etc.  In order to
 *  generate a correctly swapped value we need to bit swap the mask and that
 *  is what is accomplished by this function.
 **/
static u32 txgbe_get_fdirtcpm(union txgbe_atr_input *input_mask)
{
	u32 mask = TXGBE_NTOHS(input_mask->formatted.dst_port);

	mask <<= TXGBE_RDB_FDIR_TCP_MSK_DPORTM_SHIFT;
	mask |= TXGBE_NTOHS(input_mask->formatted.src_port);

	return mask;
}

/* These two macros are meant to address the fact that we have registers
 * that are either all or in part big-endian.  As a result on big-endian
 * systems we will end up byte swapping the value to little-endian before
 * it is byte swapped again and written to the hardware in the original
 * big-endian format.
 */
#define TXGBE_STORE_AS_BE32(_value) \
	(((u32)(_value) >> 24) | (((u32)(_value) & 0x00FF0000) >> 8) | \
	 (((u32)(_value) & 0x0000FF00) << 8) | ((u32)(_value) << 24))

#define TXGBE_WRITE_REG_BE32(a, reg, value) \
	wr32((a), (reg), TXGBE_STORE_AS_BE32(TXGBE_NTOHL(value)))

#define TXGBE_STORE_AS_BE16(_value) \
	TXGBE_NTOHS(((u16)(_value) >> 8) | ((u16)(_value) << 8))

int txgbe_fdir_set_input_mask(struct txgbe_hw *hw,
			      union txgbe_atr_input *input_mask)
{
	/* mask IPv6 since it is currently not supported */
	u32 fdirm = 0;
	u32 fdirtcpm;
	struct txgbe_adapter *adapter = (struct txgbe_adapter *)hw->back;

	/* Program the relevant mask registers.  If src/dst_port or src/dst_addr
	 * are zero, then assume a full mask for that field.  Also assume that
	 * a VLAN of 0 is unspecified, so mask that out as well.  L4type
	 * cannot be masked out in this implementation.
	 *
	 * This also assumes IPv4 only.  IPv6 masking isn't supported at this
	 * point in time.
	 */

	/* verify bucket hash is cleared on hash generation */
	if (input_mask->formatted.bkt_hash)
		e_info(drv, " bucket hash should always be 0 in mask\n");

	/* Program FDIRM and verify partial masks */
	switch (input_mask->formatted.vm_pool & 0x7F) {
	case 0x0:
		fdirm |= TXGBE_RDB_FDIR_OTHER_MSK_POOL;
	case 0x7F:
		break;
	default:
		return TXGBE_ERR_CONFIG;
	}

	switch (input_mask->formatted.flow_type & TXGBE_ATR_L4TYPE_MASK) {
	case 0x0:
		fdirm |= TXGBE_RDB_FDIR_OTHER_MSK_L4P;
		if (input_mask->formatted.dst_port ||
		    input_mask->formatted.src_port)
			return TXGBE_ERR_CONFIG;
	case TXGBE_ATR_L4TYPE_MASK:
		break;
	default:
		return TXGBE_ERR_CONFIG;
	}

	/* Now mask VM pool and destination IPv6 - bits 5 and 2 */
	wr32(hw, TXGBE_RDB_FDIR_OTHER_MSK, fdirm);



	/* store the TCP/UDP port masks,
	 * bit reversed from port layout
	 */
	fdirtcpm = txgbe_get_fdirtcpm(input_mask);

	/* write both the same so that UDP and TCP use the same mask */
	wr32(hw, TXGBE_RDB_FDIR_TCP_MSK, ~fdirtcpm);
	wr32(hw, TXGBE_RDB_FDIR_UDP_MSK, ~fdirtcpm);
	wr32(hw, TXGBE_RDB_FDIR_SCTP_MSK, ~fdirtcpm);

	/* store source and destination IP masks (little-endian) */
	wr32(hw, TXGBE_RDB_FDIR_SA4_MSK,
	     TXGBE_NTOHL(~input_mask->formatted.src_ip[0]));
	wr32(hw, TXGBE_RDB_FDIR_DA4_MSK,
	     TXGBE_NTOHL(~input_mask->formatted.dst_ip[0]));
	return 0;
}

int txgbe_fdir_set_flex_conf(struct txgbe_hw *hw,
			     struct txgbe_fdir_filter *input,
			     union txgbe_atr_input *input_mask)
{
	u32 flex = 0;
	int i, j;

	i = input->filter.formatted.vm_pool / 4;
	j = input->filter.formatted.vm_pool % 4;
	flex = rd32m(hw, TXGBE_RDB_FDIR_FLEX_CFG(i),
		~((TXGBE_RDB_FDIR_FLEX_CFG_BASE_MSK |
		   TXGBE_RDB_FDIR_FLEX_CFG_MSK |
		   TXGBE_RDB_FDIR_FLEX_CFG_OFST) <<
		   (TXGBE_RDB_FDIR_FLEX_CFG_VM_SHIFT * j)));

	switch (input_mask->formatted.flex_bytes & 0xFFFF) {
	case 0x0000:
		flex |= TXGBE_RDB_FDIR_FLEX_CFG_MSK <<
			(TXGBE_RDB_FDIR_FLEX_CFG_VM_SHIFT * j);
		break;
	case 0xFFFF:
		flex |= (TXGBE_RDB_FDIR_FLEX_CFG_BASE_MAC |
			 ((input->flex_offset / 2) <<
			  TXGBE_RDB_FDIR_FLEX_CFG_OFST_SHIFT)) <<
			(TXGBE_RDB_FDIR_FLEX_CFG_VM_SHIFT * j);
		break;
	default:
		return TXGBE_ERR_CONFIG;
	}
	wr32(hw, TXGBE_RDB_FDIR_FLEX_CFG(i), flex);
	return 0;
}

int txgbe_fdir_write_perfect_filter(struct txgbe_hw *hw,
				    union txgbe_atr_input *input,
				    u16 soft_id, u8 queue)
{
	u32 fdirport, fdirvlan, fdirhash, fdircmd;
	int err;

	/* currently IPv6 is not supported, must be programmed with 0 */
	wr32(hw, TXGBE_RDB_FDIR_IP6(2),
		     TXGBE_NTOHL(input->formatted.src_ip[0]));
	wr32(hw, TXGBE_RDB_FDIR_IP6(1),
		     TXGBE_NTOHL(input->formatted.src_ip[1]));
	wr32(hw, TXGBE_RDB_FDIR_IP6(0),
		     TXGBE_NTOHL(input->formatted.src_ip[2]));

	/* record the source address (little-endian) */
	wr32(hw, TXGBE_RDB_FDIR_SA,
		     TXGBE_NTOHL(input->formatted.src_ip[0]));

	/* record the first 32 bits of the destination address
	 * (little-endian)
	 */
	wr32(hw, TXGBE_RDB_FDIR_DA,
		     TXGBE_NTOHL(input->formatted.dst_ip[0]));

	/* record source and destination port (little-endian)*/
	fdirport = TXGBE_NTOHS(input->formatted.dst_port);
	fdirport <<= TXGBE_RDB_FDIR_PORT_DESTINATION_SHIFT;
	fdirport |= TXGBE_NTOHS(input->formatted.src_port);
	wr32(hw, TXGBE_RDB_FDIR_PORT, fdirport);

	/* record packet type and flex_bytes(little-endian) */
	fdirvlan = TXGBE_NTOHS(input->formatted.flex_bytes);
	fdirvlan <<= TXGBE_RDB_FDIR_FLEX_FLEX_SHIFT;

	fdirvlan |= TXGBE_NTOHS(input->formatted.pkt_type);
	wr32(hw, TXGBE_RDB_FDIR_FLEX, fdirvlan);

	/* configure FDIRHASH register */
	fdirhash = input->formatted.bkt_hash |
		0x1 << TXGBE_RDB_FDIR_HASH_BUCKET_VALID_SHIFT;
	fdirhash |= soft_id << TXGBE_RDB_FDIR_HASH_SIG_SW_INDEX_SHIFT;
	wr32(hw, TXGBE_RDB_FDIR_HASH, fdirhash);

	/* flush all previous writes to make certain registers are
	 * programmed prior to issuing the command
	 */
	TXGBE_WRITE_FLUSH(hw);

	/* configure FDIRCMD register */
	fdircmd = TXGBE_RDB_FDIR_CMD_CMD_ADD_FLOW |
		  TXGBE_RDB_FDIR_CMD_FILTER_UPDATE |
		  TXGBE_RDB_FDIR_CMD_LAST | TXGBE_RDB_FDIR_CMD_QUEUE_EN;
	if (queue == TXGBE_RDB_FDIR_DROP_QUEUE)
		fdircmd |= TXGBE_RDB_FDIR_CMD_DROP;
	fdircmd |= input->formatted.flow_type <<
			TXGBE_RDB_FDIR_CMD_FLOW_TYPE_SHIFT;
	fdircmd |= (u32)queue << TXGBE_RDB_FDIR_CMD_RX_QUEUE_SHIFT;
	fdircmd |= (u32)input->formatted.vm_pool <<
			TXGBE_RDB_FDIR_CMD_VT_POOL_SHIFT;

	wr32(hw, TXGBE_RDB_FDIR_CMD, fdircmd);
	err = txgbe_fdir_check_cmd_complete(hw, &fdircmd);
	if (err)
		return err;

	return 0;
}

int txgbe_fdir_erase_perfect_filter(struct txgbe_hw *hw,
				    union txgbe_atr_input *input,
					  u16 soft_id)
{
	u32 fdirhash;
	u32 fdircmd;
	int err;

	/* configure FDIRHASH register */
	fdirhash = input->formatted.bkt_hash;
	fdirhash |= soft_id << TXGBE_RDB_FDIR_HASH_SIG_SW_INDEX_SHIFT;
	wr32(hw, TXGBE_RDB_FDIR_HASH, fdirhash);

	/* flush hash to HW */
	TXGBE_WRITE_FLUSH(hw);

	/* Query if filter is present */
	wr32(hw, TXGBE_RDB_FDIR_CMD,
	     TXGBE_RDB_FDIR_CMD_CMD_QUERY_REM_FILT);

	err = txgbe_fdir_check_cmd_complete(hw, &fdircmd);
	if (err)
		return err;

	/* if filter exists in hardware then remove it */
	if (fdircmd & TXGBE_RDB_FDIR_CMD_FILTER_VALID) {
		wr32(hw, TXGBE_RDB_FDIR_HASH, fdirhash);
		TXGBE_WRITE_FLUSH(hw);
		wr32(hw, TXGBE_RDB_FDIR_CMD,
		     TXGBE_RDB_FDIR_CMD_CMD_REMOVE_FLOW);
	}

	return 0;
}

/**
 *  txgbe_start_hw - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 *
 *  Starts the hardware using the generic start_hw function
 *  and the generation start_hw function.
 *  Then performs revision-specific operations, if any.
 **/
int txgbe_start_hw(struct txgbe_hw *hw)
{
	int ret_val = 0;
	u32 i;

	/* Set the media type */
	hw->phy.media_type = hw->mac.ops.get_media_type(hw);

	/* PHY ops initialization must be done in reset_hw() */

	/* Clear the VLAN filter table */
	hw->mac.ops.clear_vfta(hw);

	/* Clear statistics registers */
	hw->mac.ops.clear_hw_cntrs(hw);

	TXGBE_WRITE_FLUSH(hw);
	/* Setup flow control */
	ret_val = hw->mac.ops.setup_fc(hw);

	if (hw->mac.type == txgbe_mac_sp) {
		/* Clear the rate limiters */
		for (i = 0; i < hw->mac.max_tx_queues; i++) {
			wr32(hw, TXGBE_TDM_RP_IDX, i);
			wr32(hw, TXGBE_TDM_RP_RATE, 0);
		}
	}
	TXGBE_WRITE_FLUSH(hw);

	/* Clear adapter stopped flag */
	hw->adapter_stopped = false;

	/* We need to run link autotry after the driver loads */
	hw->mac.autotry_restart = true;

	return ret_val;
}

/**
 *  txgbe_identify_phy_generic - Get physical layer module
 *  @hw: pointer to hardware structure
 *
 *  Determines the physical layer module found on the current adapter.
 *  If PHY already detected, maintains current PHY type in hw struct,
 *  otherwise executes the PHY detection routine.
 **/
int txgbe_identify_phy_generic(struct txgbe_hw *hw)
{
	/* Detect PHY if not unknown - returns success if already detected. */
	int status = TXGBE_ERR_PHY_ADDR_INVALID;

	/* avoid fw access phy */
	if (((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI) &&
	    ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP)) {
		/* Let firmware know the driver has taken over */
		wr32m(hw, TXGBE_CFG_PORT_CTL,
		      TXGBE_CFG_PORT_CTL_DRV_LOAD, TXGBE_CFG_PORT_CTL_DRV_LOAD);
		mdelay(100);
	}

	if (!hw->phy.phy_semaphore_mask)
		hw->phy.phy_semaphore_mask = TXGBE_MNG_SWFW_SYNC_SW_PHY;

	/* Let firmware take over control of h/w */
	if (((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI) &&
	    ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP))
		wr32m(hw, TXGBE_CFG_PORT_CTL,
		      TXGBE_CFG_PORT_CTL_DRV_LOAD, 0);

	/* Return error if SFP module has been detected but is not supported */
	if (hw->phy.type == txgbe_phy_sfp_unsupported)
		return TXGBE_ERR_SFP_NOT_SUPPORTED;

	return status;
}

int txgbe_set_pps(struct txgbe_hw *hw, bool enable, u64 nsec, u64 cycles)
{
	int status;
	struct txgbe_hic_set_pps pps_cmd;
	int i;

	pps_cmd.hdr.cmd = FW_PPS_SET_CMD;
	pps_cmd.hdr.buf_len = FW_PPS_SET_LEN;
	pps_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	pps_cmd.lan_id = hw->bus.lan_id;
	pps_cmd.enable = enable;
	pps_cmd.nsec = nsec;
	pps_cmd.cycles = cycles;
	pps_cmd.hdr.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	/* send reset request to FW and wait for response */
	for (i = 0; i <= FW_CEM_MAX_RETRIES; i++) {
		status = txgbe_host_interface_command(hw, (u32 *)&pps_cmd,
						      sizeof(pps_cmd),
						       TXGBE_HI_COMMAND_TIMEOUT,
						       true);
		usleep_range(1000, 2000);
		if (status != 0)
			continue;

		if (pps_cmd.hdr.cmd_or_resp.ret_status ==
			FW_CEM_RESP_STATUS_SUCCESS)
			status = 0;
		else
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
		break;
	}

	return status;
}

/**
 *  txgbe_enable_rx_dma - Enable the Rx DMA unit on sapphire/amber-lite
 *  @hw: pointer to hardware structure
 *  @regval: register value to write to RXCTRL
 *
 *  Enables the Rx DMA unit for sapphire/amber-lite
 **/
int txgbe_enable_rx_dma(struct txgbe_hw *hw, u32 regval)
{
	hw->mac.ops.disable_sec_rx_path(hw);

	if (regval & TXGBE_RDB_PB_CTL_RXEN)
		hw->mac.ops.enable_rx(hw);
	else
		hw->mac.ops.disable_rx(hw);

	hw->mac.ops.enable_sec_rx_path(hw);

	return 0;
}


/**
 *  txgbe_write_flash_buffer - Write FLASH dword(s) using
 *  fastest available method
 *
 *  @hw: pointer to hardware structure
 *  @offset: offset of  dword in EEPROM to write
 *  @dwords: number of dwords
 *  @data: dword(s) write from to EEPROM
 *
 **/
int txgbe_write_flash_buffer(struct txgbe_hw *hw, u32 offset,
			     u32 dwords, u32 *data)
{
	int status = 0;
	u32 i;

	txgbe_init_eeprom_params(hw);

	if (!dwords || offset + dwords >= hw->flash.dword_size) {
		status = TXGBE_ERR_INVALID_ARGUMENT;
		ERROR_REPORT1(TXGBE_ERROR_ARGUMENT, "Invalid FLASH arguments");
		return status;
	}

	for (i = 0; i < dwords; i++) {
		wr32(hw, TXGBE_SPI_CMD,
		     TXGBE_SPI_CMD_ADDR(offset + i) |
			TXGBE_SPI_CMD_CMD(0x1));

		status = po32m(hw, TXGBE_SPI_STATUS,
			       TXGBE_SPI_STATUS_OPDONE, TXGBE_SPI_STATUS_OPDONE,
			TXGBE_SPI_TIMEOUT, 0);
		if (status != 0)
			break;

		data[i] = rd32(hw, TXGBE_SPI_DATA);
	}

	return status;
}

/**
 *  txgbe_init_eeprom_params - Initialize EEPROM params
 *  @hw: pointer to hardware structure
 *
 *  Initializes the EEPROM parameters txgbe_eeprom_info within the
 *  txgbe_hw struct in order to set up EEPROM access.
 **/
int txgbe_init_eeprom_params(struct txgbe_hw *hw)
{
	struct txgbe_eeprom_info *eeprom = &hw->eeprom;
	u16 eeprom_size;
	int status = 0;
	u16 data;

	if (eeprom->type == txgbe_eeprom_uninitialized) {
		eeprom->semaphore_delay = 10;
		eeprom->type = txgbe_eeprom_none;

		if (!(rd32(hw, TXGBE_SPI_STATUS) &
			TXGBE_SPI_STATUS_FLASH_BYPASS)) {
			eeprom->type = txgbe_flash;

			eeprom_size = 4096;
			eeprom->word_size = eeprom_size >> 1;
		}
	}

	status = txgbe_read_ee_hostif(hw, TXGBE_SW_REGION_PTR,
			&data);
	if (status)
		return status;

	eeprom->sw_region_offset = data >> 1;

	return status;
}

/**
 *  txgbe_read_ee_hostif_data - Read EEPROM word using a host interface cmd
 *  assuming that the semaphore is already obtained.
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @data: word read from the EEPROM
 *
 *  Reads a 16 bit word from the EEPROM using the hostif.
 **/
static int txgbe_read_ee_hostif_data(struct txgbe_hw *hw, u16 offset,
				     u16 *data)
{
	int status;
	struct txgbe_hic_read_shadow_ram buffer;

	buffer.hdr.req.cmd = FW_READ_SHADOW_RAM_CMD;
	buffer.hdr.req.buf_lenh = 0;
	buffer.hdr.req.buf_lenl = FW_READ_SHADOW_RAM_LEN;

	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.req.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	/* convert offset from words to bytes */
	buffer.address = TXGBE_CPU_TO_BE32(offset * 2);
	/* one word */
	buffer.length = TXGBE_CPU_TO_BE16(sizeof(u16));

	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer),
					      TXGBE_HI_COMMAND_TIMEOUT, false);

	if (status)
		return status;

	if (txgbe_check_mng_access(hw)) {
		if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40)
			*data = (u16)rd32a(hw, TXGBE_AML_MNG_MBOX_FW2SW,
						FW_NVM_DATA_OFFSET);
		else if (hw->mac.type == txgbe_mac_sp)
			*data = (u16)rd32a(hw, TXGBE_MNG_MBOX,
						FW_NVM_DATA_OFFSET);
	} else {
		status = TXGBE_ERR_MNG_ACCESS_FAILED;
		return status;
	}

	return 0;
}

/**
 *  txgbe_read_ee_hostif - Read EEPROM word using a host interface cmd
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @data: word read from the EEPROM
 *
 *  Reads a 16 bit word from the EEPROM using the hostif.
 **/
int txgbe_read_ee_hostif(struct txgbe_hw *hw, u16 offset,
			 u16 *data)
{
	int status = 0;

	if (txgbe_acquire_swfw_sync(hw,
					  TXGBE_MNG_SWFW_SYNC_SW_FLASH) == 0) {
		status = txgbe_read_ee_hostif_data(hw, offset, data);
		txgbe_release_swfw_sync(hw,
			TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	} else {
		status = TXGBE_ERR_SWFW_SYNC;
	}

	return status;
}

/**
 *  txgbe_read_ee_hostif_buffer- Read EEPROM word(s) using hostif
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @words: number of words
 *  @data: word(s) read from the EEPROM
 *
 *  Reads a 16 bit word(s) from the EEPROM using the hostif.
 **/
int txgbe_read_ee_hostif_buffer(struct txgbe_hw *hw,
				u16 offset, u16 words, u16 *data)
{
	struct txgbe_hic_read_shadow_ram buffer;
	u32 current_word = 0;
	u16 words_to_read;
	int status;
	u32 reg;
	u32 i;
	u32 value = 0;

	/* Take semaphore for the entire operation. */
	status = txgbe_acquire_swfw_sync(hw,
			TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	if (status)
		return status;

	while (words) {
		if (words > FW_MAX_READ_BUFFER_SIZE / 2)
			words_to_read = FW_MAX_READ_BUFFER_SIZE / 2;
		else
			words_to_read = words;

		buffer.hdr.req.cmd = FW_READ_SHADOW_RAM_CMD;
		buffer.hdr.req.buf_lenh = 0;
		buffer.hdr.req.buf_lenl = FW_READ_SHADOW_RAM_LEN;

		if (hw->mac.type == txgbe_mac_sp)
			buffer.hdr.req.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

		/* convert offset from words to bytes */
		buffer.address = TXGBE_CPU_TO_BE32((offset + current_word) * 2);
		buffer.length = TXGBE_CPU_TO_BE16(words_to_read * 2);

		status = txgbe_host_interface_command(hw, (u32 *)&buffer,
						      sizeof(buffer),
						      TXGBE_HI_COMMAND_TIMEOUT,
						      false);

		if (status)
			goto out;

		if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40)
			reg = TXGBE_AML_MNG_MBOX_FW2SW;
		else
			reg = TXGBE_MNG_MBOX;

		for (i = 0; i < words_to_read; i++) {
			if (txgbe_check_mng_access(hw)) {
				value = rd32(hw, reg + (FW_NVM_DATA_OFFSET << 2) + 2 * i);
			} else {
				status = TXGBE_ERR_MNG_ACCESS_FAILED;
				return status;
			}
			data[current_word] = (u16)(value & 0xffff);
			current_word++;
			i++;
			if (i < words_to_read) {
				value >>= 16;
				data[current_word] = (u16)(value & 0xffff);
				current_word++;
			}
		}
		words -= words_to_read;
	}

out:
	txgbe_release_swfw_sync(hw,
		TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	return status;
}

/**
 *  txgbe_write_ee_hostif_data - Write EEPROM word using hostif
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to write
 *  @data: word write to the EEPROM
 *
 *  Write a 16 bit word to the EEPROM using the hostif.
 **/
static int txgbe_write_ee_hostif_data(struct txgbe_hw *hw, u16 offset,
				      u16 data)
{
	int status;
	struct txgbe_hic_write_shadow_ram buffer;

	buffer.hdr.req.cmd = FW_WRITE_SHADOW_RAM_CMD;
	buffer.hdr.req.buf_lenh = 0;
	buffer.hdr.req.buf_lenl = FW_WRITE_SHADOW_RAM_LEN;
	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.req.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	/* one word */
	buffer.length = TXGBE_CPU_TO_BE16(sizeof(u16));
	buffer.data = data;
	buffer.address = TXGBE_CPU_TO_BE32(offset * 2);

	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer),
					      TXGBE_HI_COMMAND_TIMEOUT, false);

	return status;
}

/**
 *  txgbe_write_ee_hostif - Write EEPROM word using hostif
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to write
 *  @data: word write to the EEPROM
 *
 *  Write a 16 bit word to the EEPROM using the hostif.
 **/
static int txgbe_write_ee_hostif(struct txgbe_hw *hw, u16 offset, u16 data)
{
	int status = 0;

	if (txgbe_acquire_swfw_sync(hw,
					  TXGBE_MNG_SWFW_SYNC_SW_FLASH) == 0) {
		status = txgbe_write_ee_hostif_data(hw, offset, data);
		txgbe_release_swfw_sync(hw,
			TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	} else {
		status = TXGBE_ERR_SWFW_SYNC;
	}

	return status;
}

/**
 *  txgbe_write_ee_hostif_buffer - Write EEPROM word(s) using hostif
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to write
 *  @words: number of words
 *  @data: word(s) write to the EEPROM
 *
 *  Write a 16 bit word(s) to the EEPROM using the hostif.
 **/
int txgbe_write_ee_hostif_buffer(struct txgbe_hw *hw,
				 u16 offset, u16 words, u16 *data)
{
	int status = 0;
	u16 i = 0;

	/* Take semaphore for the entire operation. */
	status = txgbe_acquire_swfw_sync(hw,
		       TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	if (status != 0)
		goto out;

	for (i = 0; i < words; i++) {
		status = txgbe_write_ee_hostif_data(hw, offset + i,
						    data[i]);
		if (status != 0)
			break;
	}

	txgbe_release_swfw_sync(hw, TXGBE_MNG_SWFW_SYNC_SW_FLASH);
out:

	return status;
}

/**
 *  txgbe_calc_eeprom_checksum - Calculates and returns the checksum
 *  @hw: pointer to hardware structure
 *
 *  Returns a negative error code on error, or the 16-bit checksum
 **/
static int txgbe_calc_eeprom_checksum(struct txgbe_hw *hw)
{
	u16 *buffer = NULL;
	u32 buffer_size = 0;

	u16 *eeprom_ptrs = NULL;
	u16 *local_buffer;
	int status;
	u16 checksum = 0;
	u16 i;

	txgbe_init_eeprom_params(hw);

	if (!buffer) {
		eeprom_ptrs = vmalloc(TXGBE_EEPROM_LAST_WORD * sizeof(u16));
		if (!eeprom_ptrs)
			return TXGBE_ERR_NO_SPACE;
		/* Read pointer area */
		status = txgbe_read_ee_hostif_buffer(hw, 0,
						     TXGBE_EEPROM_LAST_WORD,
						     eeprom_ptrs);
		if (status)
			return status;

		local_buffer = eeprom_ptrs;
	} else {
		if (buffer_size < TXGBE_EEPROM_LAST_WORD)
			return TXGBE_ERR_PARAM;
		local_buffer = buffer;
	}

	for (i = 0; i < TXGBE_EEPROM_LAST_WORD; i++) {
		if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40)
			if ((i > (TXGBE_SHOWROM_I2C_PTR / 2)) && (i < (TXGBE_SHOWROM_I2C_END / 2)))
				local_buffer[i] = 0xffff;
		if (i != hw->eeprom.sw_region_offset + TXGBE_EEPROM_CHECKSUM)
			checksum += local_buffer[i];
	}

	checksum = (u16)TXGBE_EEPROM_SUM - checksum;
	if (eeprom_ptrs)
		vfree(eeprom_ptrs);

	return (int)checksum;
}

/**
 * txgbe_update_eeprom_checksum - Updates the EEPROM checksum and flash
 * @hw: pointer to hardware structure
 *
 * After writing EEPROM to shadow RAM using EEWR register, software calculates
 * checksum and updates the EEPROM and instructs the hardware to update
 * the flash.
 **/
int txgbe_update_eeprom_checksum(struct txgbe_hw *hw)
{
	int status;
	u16 checksum = 0;

	/* Read the first word from the EEPROM. If this times out or fails, do
	 * not continue or we could be in for a very long wait while every
	 * EEPROM read fails
	 */
	status = txgbe_read_ee_hostif(hw, 0, &checksum);
	if (status)
		return status;

	status = txgbe_calc_eeprom_checksum(hw);
	if (status < 0)
		return status;

	checksum = (u16)(status & 0xffff);

	status = txgbe_write_ee_hostif(hw, TXGBE_EEPROM_CHECKSUM,
				       checksum);

	return status;
}

/**
 *  txgbe_validate_eeprom_checksum - Validate EEPROM checksum
 *  @hw: pointer to hardware structure
 *  @checksum_val: calculated checksum
 *
 *  Performs checksum calculation and validates the EEPROM checksum.  If the
 *  caller does not need checksum_val, the value can be NULL.
 **/
int txgbe_validate_eeprom_checksum(struct txgbe_hw *hw,
				   u16 *checksum_val)
{
	int status;
	u16 checksum;
	u16 read_checksum = 0;

	/* Read the first word from the EEPROM. If this times out or fails, do
	 * not continue or we could be in for a very long wait while every
	 * EEPROM read fails
	 */
	status = txgbe_read_ee_hostif(hw, 0, &checksum);
	if (status)
		return status;

	status = txgbe_calc_eeprom_checksum(hw);
	if (status < 0)
		return status;

	checksum = (u16)(status & 0xffff);

	status = txgbe_read_ee_hostif(hw, hw->eeprom.sw_region_offset +
					TXGBE_EEPROM_CHECKSUM,
					&read_checksum);
	if (status)
		return status;

	/* Verify read checksum from EEPROM is the same as
	 * calculated checksum
	 */
	if (read_checksum != checksum) {
		status = TXGBE_ERR_EEPROM_CHECKSUM;
		ERROR_REPORT1(TXGBE_ERROR_INVALID_STATE,
			      "Invalid EEPROM checksum\n");
	}

	/* If the user cares, return the calculated checksum */
	if (checksum_val)
		*checksum_val = checksum;

	return status;
}

/**
 *  txgbe_setup_eee - Enable/disable EEE support
 *  @hw: pointer to the HW structure
 *  @enable_eee: boolean flag to enable EEE
 *
 *  Enable/disable EEE based on enable_eee flag.
 *  Auto-negotiation must be started after BASE-T EEE bits in PHY register 7.3C
 *  are modified.
 *
 **/
int txgbe_setup_eee(struct txgbe_hw *hw, bool enable_eee)
{
	return 0;
}

int txgbe_hic_write_lldp(struct txgbe_hw *hw, u32 open)
{
	int status;
	struct txgbe_adapter *adapter = hw->back;
	struct pci_dev *pdev = adapter->pdev;
	struct txgbe_hic_write_lldp buffer;

	buffer.hdr.cmd = 0xf1 - open;
	buffer.hdr.buf_len = 0x1;
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	buffer.func = PCI_FUNC(pdev->devfn);
	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer), 5000, false);
	return status;
}

static int txgbe_hic_get_lldp(struct txgbe_hw *hw)
{
	struct txgbe_hic_write_lldp buffer;
	int status;

	buffer.hdr.cmd = 0xf2;
	buffer.hdr.buf_len = 0x1;
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;

	if (hw->mac.type == txgbe_mac_sp)
		buffer.hdr.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	buffer.func = hw->bus.lan_id;
	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer), 5000, true);
	if (status)
		return status;
	if (buffer.hdr.cmd_or_resp.ret_status != FW_CEM_RESP_STATUS_SUCCESS)
		return -EBUSY;

	return (int)buffer.func;
}

int txgbe_is_lldp(struct txgbe_hw *hw)
{
	u32 tmp = 0, lldp_flash_data = 0, i = 0;
	struct txgbe_adapter *adapter = hw->back;
	int status = 0;

	status = txgbe_hic_get_lldp(hw);
	if (status != -1) {
		if (status)
			adapter->eth_priv_flags |= TXGBE_ETH_PRIV_FLAG_LLDP;
		else
			adapter->eth_priv_flags &= ~TXGBE_ETH_PRIV_FLAG_LLDP;
		goto out;
	} else {
		for (; i < 0x1000 / sizeof(u32); i++) {
			status = txgbe_flash_read_dword(hw, TXGBE_LLDP_REG + i * 4, &tmp);
			if (status)
				return status;
			if (tmp == U32_MAX)
				break;
			lldp_flash_data = tmp;
		}
		if (lldp_flash_data & BIT(hw->bus.lan_id))
			adapter->eth_priv_flags |= TXGBE_ETH_PRIV_FLAG_LLDP;
		else
			adapter->eth_priv_flags &= ~TXGBE_ETH_PRIV_FLAG_LLDP;
	}
out:
	return 0;
}

void txgbe_hic_write_autoneg_status(struct txgbe_hw *hw, bool autoneg)
{
	struct txgbe_hic_write_autoneg buffer;

	buffer.hdr.cmd = FW_AN_STA_CMD;
	buffer.hdr.buf_len = FW_AN_STA_LEN;
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	buffer.lan_id = hw->bus.lan_id;
	buffer.autoneg = autoneg;
	buffer.hdr.cksum_or_index.checksum = FW_DEFAULT_CHECKSUM;

	txgbe_host_interface_command(hw, (u32 *)&buffer, sizeof(buffer),
				     TXGBE_HI_COMMAND_TIMEOUT, false);
}

void txgbe_set_queue_rate_limit(struct txgbe_hw *hw, int queue, u16 max_tx_rate)
{
	struct txgbe_adapter *adapter = hw->back;
	int factor_int;
	int factor_fra;
	int link_speed;
	int bcnrc_val;

	/* Set global transmit compensation time to the MMW_SIZE in RTTBCNRM
	 * register. Typically MMW_SIZE=0x014 if 9728-byte jumbo is supported
	 * and 0x004 otherwise.
	 */

	wr32(hw, TXGBE_TDM_MMW, 0x14);

	if (hw->mac.type == txgbe_mac_aml || hw->mac.type == txgbe_mac_aml40) {
		if (max_tx_rate) {
			u16 frac;

			link_speed = txgbe_link_mbps(adapter);
			max_tx_rate  = max_tx_rate * 105 / 100; //necessary offset by test
			/* Calculate the rate factor values to set */
			factor_int = link_speed / max_tx_rate;
			frac = (link_speed % max_tx_rate) * 10000 / max_tx_rate;
			factor_fra = txgbe_frac_to_bi(frac, 10000, 14);
			if (max_tx_rate > link_speed) {
				factor_int = 1;
				factor_fra = 0;
			}

			wr32(hw, TXGBE_TDM_RL_QUEUE_IDX, queue);
			wr32m(hw, TXGBE_TDM_RL_QUEUE_CFG,
			      TXGBE_TDM_FACTOR_INT_MASK, factor_int << TXGBE_TDM_FACTOR_INT_SHIFT);
			wr32m(hw, TXGBE_TDM_RL_QUEUE_CFG,
			      TXGBE_TDM_FACTOR_FRA_MASK, factor_fra << TXGBE_TDM_FACTOR_FRA_SHIFT);
			wr32m(hw, TXGBE_TDM_RL_QUEUE_CFG,
			      TXGBE_TDM_RL_EN, TXGBE_TDM_RL_EN);
		} else {
			wr32(hw, TXGBE_TDM_RL_QUEUE_IDX, queue);
			wr32m(hw, TXGBE_TDM_RL_QUEUE_CFG,
			      TXGBE_TDM_RL_EN, 0);
		}
	} else {
		bcnrc_val = TXGBE_TDM_RP_RATE_MAX(max_tx_rate);

		wr32(hw, TXGBE_TDM_RP_IDX, queue);
		wr32(hw, TXGBE_TDM_RP_RATE, bcnrc_val);
		if (max_tx_rate)
			wr32m(hw, TXGBE_TDM_RP_CTL,
			      TXGBE_TDM_RP_CTL_RLEN, TXGBE_TDM_RP_CTL_RLEN);
		else
			wr32m(hw, TXGBE_TDM_RP_CTL,
			      TXGBE_TDM_RP_CTL_RLEN, 0);
	}
}

int txgbe_hic_notify_led_active(struct txgbe_hw *hw, int active_flag)
{
	struct txgbe_led_active_set buffer = {0};

	buffer.hdr.cmd = 0xf8;
	buffer.hdr.buf_len = 0x1;
	buffer.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	buffer.active_flag = active_flag;

	return txgbe_host_interface_command(hw, (u32 *)&buffer,
					    sizeof(buffer), 5000, true);
}

bool txgbe_is_backplane(struct txgbe_hw *hw)
{
	return hw->mac.ops.get_media_type(hw) == txgbe_media_type_backplane ?
						 true : false;
}

bool txgbe_gpio_ext_check(struct txgbe_hw *hw, u8 gpio_ext_mask)
{
	u32 gpio_ext = rd32(hw, TXGBE_GPIO_EXT);

	if (txgbe_is_backplane(hw))
		return false;

	if (gpio_ext & gpio_ext_mask)
		return true;
	return false;
}
