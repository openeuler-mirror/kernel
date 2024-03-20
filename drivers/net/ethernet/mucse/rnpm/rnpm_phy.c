// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/mdio.h>

#include "rnpm_common.h"
#include "rnpm_phy.h"
#include "rnpm_mbx_fw.h"

#define RNPM_PHY_REVISION_MASK 0xFFFFFFF0
#define RNPM_MAX_PHY_ADDR 32

static void rnpm_i2c_start(struct rnpm_hw *hw);
static void rnpm_i2c_stop(struct rnpm_hw *hw);
static s32 rnpm_clock_in_i2c_byte(struct rnpm_hw *hw, u8 *data);
static s32 rnpm_clock_out_i2c_byte(struct rnpm_hw *hw, u8 data);
static s32 rnpm_get_i2c_ack(struct rnpm_hw *hw);
static s32 rnpm_clock_in_i2c_bit(struct rnpm_hw *hw, bool *data);
static s32 rnpm_clock_out_i2c_bit(struct rnpm_hw *hw, bool data);
static void rnpm_raise_i2c_clk(struct rnpm_hw *hw, u32 *i2cctl);
static void rnpm_lower_i2c_clk(struct rnpm_hw *hw, u32 *i2cctl);
static s32 rnpm_set_i2c_data(struct rnpm_hw *hw, u32 *i2cctl, bool data);
static bool rnpm_get_i2c_data(u32 *i2cctl);
static void rnpm_i2c_bus_clear(struct rnpm_hw *hw);
static enum rnpm_phy_type rnpm_get_phy_type_from_id(u32 phy_id);
static s32 rnpm_get_phy_id(struct rnpm_hw *hw);

/**
 *  rnpm_identify_phy_generic - Get physical layer module
 *  @hw: pointer to hardware structure
 *
 *  Determines the physical layer module found on the current adapter.
 **/
s32 rnpm_identify_phy_generic(struct rnpm_hw *hw)
{
	s32 status = RNPM_ERR_PHY_ADDR_INVALID;

	return status;
}

/**
 *  rnpm_get_phy_id - Get the phy type
 *  @hw: pointer to hardware structure
 *
 **/
__maybe_unused static s32 rnpm_get_phy_id(struct rnpm_hw *hw)
{
	u32 status;
	u16 phy_id_high = 0;
	u16 phy_id_low = 0;

	status = hw->phy.ops.read_reg(hw, MDIO_DEVID1, MDIO_MMD_PMAPMD,
				      &phy_id_high);

	if (status == 0) {
		hw->phy.id = (u32)(phy_id_high << 16);
		status = hw->phy.ops.read_reg(hw, MDIO_DEVID2, MDIO_MMD_PMAPMD,
					      &phy_id_low);
		hw->phy.id |= (u32)(phy_id_low & RNPM_PHY_REVISION_MASK);
		hw->phy.revision = (u32)(phy_id_low & ~RNPM_PHY_REVISION_MASK);
	}
	return status;
}

/**
 *  rnpm_get_phy_type_from_id - Get the phy type
 *  @hw: pointer to hardware structure
 *
 **/
__maybe_unused static enum rnpm_phy_type rnpm_get_phy_type_from_id(u32 phy_id)
{
	enum rnpm_phy_type phy_type = rnpm_phy_unknown;

	return phy_type;
}

/**
 *  rnpm_reset_phy_generic - Performs a PHY reset
 *  @hw: pointer to hardware structure
 **/
s32 rnpm_reset_phy_generic(struct rnpm_hw *hw)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_read_phy_reg_generic - Reads a value from a specified PHY register
 *  @hw: pointer to hardware structure
 *  @reg_addr: 32 bit address of PHY register to read
 *  @phy_data: Pointer to read data from PHY register
 **/
s32 rnpm_read_phy_reg_generic(struct rnpm_hw *hw, u32 reg_addr, u32 device_type,
			      u16 *phy_data)
{
	s32 status = 0;
	u32 data = 0;

	status = rnpm_mbx_phy_read(hw, reg_addr, &data);
	*phy_data = data & 0xffff;

	return status;
}

/**
 *  rnpm_write_phy_reg_generic - Writes a value to specified PHY register
 *  @hw: pointer to hardware structure
 *  @reg_addr: 32 bit PHY register to write
 *  @device_type: 5 bit device type
 *  @phy_data: Data to write to the PHY register
 **/
s32 rnpm_write_phy_reg_generic(struct rnpm_hw *hw, u32 reg_addr,
			       u32 device_type, u16 phy_data)
{
	s32 status = 0;

	status = rnpm_mbx_phy_write(hw, reg_addr, (u32)phy_data);

	return status;
}

/**
 *  rnpm_setup_phy_link_generic - Set and restart autoneg
 *  @hw: pointer to hardware structure
 *
 *  Restart autonegotiation and PHY and waits for completion.
 **/
s32 rnpm_setup_phy_link_generic(struct rnpm_hw *hw)
{
	s32 status = 0;

	rnpm_mbx_phy_link_set(hw, hw->phy.autoneg_advertised);
	return status;
}

/**
 *  rnpm_setup_phy_link_speed_generic - Sets the auto advertised capabilities
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 **/
s32 rnpm_setup_phy_link_speed_generic(struct rnpm_hw *hw, rnpm_link_speed speed,
				      bool autoneg_wait_to_complete)
{
	struct rnpm_adapter *adpt = hw->back;
	u32 value = 0;
	u32 value_r4 = 0;
	u32 value_r9 = 0;

	rnpm_logd(LOG_PHY,
		  "%s setup phy: phy_addr=%d speed=%d duplex=%d autoneg=%d ",
		  __func__, adpt->phy_addr, speed, hw->mac.duplex,
		  hw->mac.autoneg);
	rnpm_logd(LOG_PHY, "is_backplane=%d is_sgmii=%d mdix=%d\n",
		  hw->is_backplane, hw->is_sgmii, hw->phy.mdix);

	if (hw->is_backplane) {
		/* Backplane type, support AN, unsupport set speed */
		return rnpm_set_lane_fun(hw, LANE_FUN_AN, hw->mac.autoneg, 0, 0,
					 0);
	}

	/* Fiber only support force speed 1G/10G*/
	if (!hw->is_sgmii) {
		if (adpt->pf_adapter->force_10g_1g_speed_ablity) {
			rnpm_mbx_force_speed(hw, speed);
			/* Update port link info when firber is absent */
			set_bit(RNPM_PF_LINK_CHANGE, &adpt->pf_adapter->flags);
		}
		return 0;
	}

	/* Set MDI/MDIX mode */
	rnpm_mbx_phy_read(hw, RNPM_YT8531_PHY_SPEC_CTRL, &value);
	value &= ~RNPM_YT8531_PHY_SPEC_CTRL_MDIX_CFG_MASK;
	/* Options: 0: Auto (default)  1: MDI mode  2: MDI-X mode */
	switch (hw->phy.mdix) {
	case 1:
		break;
	case 2:
		value |= RNPM_YT8531_PHY_SPEC_CTRL_FORCE_MDIX;
		break;
	case 0:
	default:
		value |= RNPM_YT8531_PHY_SPEC_CTRL_AUTO_MDI_MDIX;
		break;
	}
	rnpm_mbx_phy_write(hw, RNPM_YT8531_PHY_SPEC_CTRL, value);

	if (speed == RNPM_LINK_SPEED_UNKNOWN) {
		rnpm_mbx_phy_read(hw, 0x0, &value);
		value |= RNPM_MDI_PHY_RESET;
		rnpm_mbx_phy_write(hw, 0x0, value);
		goto skip_an;
	}
	/* Clear autoneg_advertised and set new values based on input link
	 * speed.
	 */
	hw->phy.autoneg_advertised = speed;

	if (!hw->mac.autoneg) {
		switch (speed) {
		case RNPM_LINK_SPEED_1GB_FULL:
		case RNPM_LINK_SPEED_1GB_HALF:
			value = RNPM_MDI_PHY_SPEED_SELECT1;
			// if (hw->phy.id == RNPM_YT8531_PHY_ID) {
			speed = RNPM_LINK_SPEED_1GB_FULL;
			goto out;
			// }
			break;
		case RNPM_LINK_SPEED_100_FULL:
		case RNPM_LINK_SPEED_100_HALF:
			value = RNPM_MDI_PHY_SPEED_SELECT0;
			break;
		case RNPM_LINK_SPEED_10_FULL:
		case RNPM_LINK_SPEED_10_HALF:
			value = 0;
			break;
		default:
			value = RNPM_MDI_PHY_SPEED_SELECT0 |
				RNPM_MDI_PHY_SPEED_SELECT1;
			hw_dbg(hw, "unknown speed = 0x%x.\n", speed);
			break;
		}
		/* duplex full */
		if (hw->mac.duplex)
			value |= RNPM_MDI_PHY_DUPLEX;
		value |= RNPM_MDI_PHY_RESET;
		value &= ~RNPM_MDI_PHY_ANE;
		rnpm_mbx_phy_write(hw, 0x0, value);

		goto skip_an;
	}

	// start_an:
	value_r4 = 0x1E0;
	value_r9 = 0x300;
	/*disable 100/10base-T Self-negotiation ability*/
	rnpm_mbx_phy_read(hw, 0x4, &value);
	value &= ~value_r4;
	rnpm_mbx_phy_write(hw, 0x4, value);

	/*disable 1000base-T Self-negotiation ability*/
	rnpm_mbx_phy_read(hw, 0x9, &value);
	value &= ~value_r9;
	rnpm_mbx_phy_write(hw, 0x9, value);

	value_r4 = 0x0;
	value_r9 = 0x0;

	if (speed & RNPM_LINK_SPEED_1GB_FULL) {
		hw->phy.autoneg_advertised |= RNPM_LINK_SPEED_1GB_FULL;
		value_r9 |= 0x200;
	}
	if (speed & RNPM_LINK_SPEED_100_FULL) {
		hw->phy.autoneg_advertised |= RNPM_LINK_SPEED_100_FULL;
		value_r4 |= 0x100;
	}
	if (speed & RNPM_LINK_SPEED_10_FULL) {
		hw->phy.autoneg_advertised |= RNPM_LINK_SPEED_10_FULL;
		value_r4 |= 0x40;
	}

	if (speed & RNPM_LINK_SPEED_1GB_HALF) {
		hw->phy.autoneg_advertised |= RNPM_LINK_SPEED_1GB_HALF;
		value_r9 |= 0x100;
	}
	if (speed & RNPM_LINK_SPEED_100_HALF) {
		hw->phy.autoneg_advertised |= RNPM_LINK_SPEED_100_HALF;
		value_r4 |= 0x80;
	}
	if (speed & RNPM_LINK_SPEED_10_HALF) {
		hw->phy.autoneg_advertised |= RNPM_LINK_SPEED_10_HALF;
		value_r4 |= 0x20;
	}

	/* enable 1000base-T Self-negotiation ability */
	rnpm_mbx_phy_read(hw, 0x9, &value);
	value |= value_r9;
	rnpm_mbx_phy_write(hw, 0x9, value);

	/* enable 100/10base-T Self-negotiation ability */
	rnpm_mbx_phy_read(hw, 0x4, &value);
	value |= value_r4;
	rnpm_mbx_phy_write(hw, 0x4, value);

	/* software reset to make the above configuration take effect*/
	rnpm_mbx_phy_read(hw, 0x0, &value);
	value |= 0x9200;
	rnpm_mbx_phy_write(hw, 0x0, value);
skip_an:
	/* power on in UTP mode */
	rnpm_mbx_phy_read(hw, 0x0, &value);
	value &= ~0x800;
	rnpm_mbx_phy_write(hw, 0x0, value);

out:
	return 0;
}

/**
 * rnpm_get_copper_link_capabilities_generic - Determines link capabilities
 * @hw: pointer to hardware structure
 * @speed: pointer to link speed
 * @autoneg: boolean auto-negotiation value
 *
 * Determines the link capabilities by reading the AUTOC register.
 */
s32 rnpm_get_copper_link_capabilities_generic(struct rnpm_hw *hw,
					      rnpm_link_speed *speed,
					      bool *autoneg)
{
	s32 status = RNPM_ERR_LINK_SETUP;
	u16 speed_ability;

	*speed = 0;
	*autoneg = true;

	status = hw->phy.ops.read_reg(hw, MDIO_SPEED, MDIO_MMD_PMAPMD,
				      &speed_ability);

	if (status == 0) {
		if (speed_ability & MDIO_SPEED_10G)
			*speed |= RNPM_LINK_SPEED_10GB_FULL;
		if (speed_ability & MDIO_PMA_SPEED_1000)
			*speed |= RNPM_LINK_SPEED_1GB_FULL;
		if (speed_ability & MDIO_PMA_SPEED_100)
			*speed |= RNPM_LINK_SPEED_100_FULL;
	}

	return status;
}

/**
 *  rnpm_check_phy_link_tnx - Determine link and speed status
 *  @hw: pointer to hardware structure
 *
 *  Reads the VS1 register to determine if link is up and the current speed for
 *  the PHY.
 **/
s32 rnpm_check_phy_link_tnx(struct rnpm_hw *hw, rnpm_link_speed *speed,
			    bool *link_up)
{
	s32 status = 0;

	return status;
}

/**
 *	rnpm_setup_phy_link_tnx - Set and restart autoneg
 *	@hw: pointer to hardware structure
 *
 *	Restart autonegotiation and PHY and waits for completion.
 **/
s32 rnpm_setup_phy_link_tnx(struct rnpm_hw *hw)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_get_phy_firmware_version_tnx - Gets the PHY Firmware Version
 *  @hw: pointer to hardware structure
 *  @firmware_version: pointer to the PHY Firmware Version
 **/
s32 rnpm_get_phy_firmware_version_tnx(struct rnpm_hw *hw, u16 *firmware_version)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_get_phy_firmware_version_generic - Gets the PHY Firmware Version
 *  @hw: pointer to hardware structure
 *  @firmware_version: pointer to the PHY Firmware Version
 **/
s32 rnpm_get_phy_firmware_version_generic(struct rnpm_hw *hw,
					  u16 *firmware_version)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_reset_phy_nl - Performs a PHY reset
 *  @hw: pointer to hardware structure
 **/
s32 rnpm_reset_phy_nl(struct rnpm_hw *hw)
{
	s32 ret_val = 0;

	return ret_val;
}

/**
 *  rnpm_identify_sfp_module_generic - Identifies SFP modules
 *  @hw: pointer to hardware structure
 *
 *  Searches for and identifies the SFP module and assigns appropriate PHY type.
 **/
s32 rnpm_identify_sfp_module_generic(struct rnpm_hw *hw)
{
	return RNPM_ERR_SFP_NOT_PRESENT;
}

/**
 *  rnpm_get_sfp_init_sequence_offsets - Provides offset of PHY init sequence
 *  @hw: pointer to hardware structure
 *  @list_offset: offset to the SFP ID list
 *  @data_offset: offset to the SFP data block
 *
 *  Checks the MAC's EEPROM to see if it supports a given SFP+ module type, if
 *  so it returns the offsets to the phy init sequence block.
 **/
s32 rnpm_get_sfp_init_sequence_offsets(struct rnpm_hw *hw, u16 *list_offset,
				       u16 *data_offset)
{
	return 0;
}

/**
 *  rnpm_read_i2c_eeprom_generic - Reads 8 bit EEPROM word over I2C interface
 *  @hw: pointer to hardware structure
 *  @byte_offset: EEPROM byte offset to read at address 0xA0
 *  @eeprom_data: value read
 *
 *  Performs byte read operation to SFP module's EEPROM over I2C interface.
 **/
s32 rnpm_read_i2c_eeprom_generic(struct rnpm_hw *hw, u8 byte_offset,
				 u8 *eeprom_data)
{
	return -EIO;
}

/**
 *  rnpm_read_i2c_sff8472_generic - Reads 8 bit word over I2C interface
 *  @hw: pointer to hardware structure
 *  @byte_offset: byte offset at address 0xA2
 *  @eeprom_data: value read
 *
 *  Performs byte read operation to SFP module's SFF-8472 data over I2C
 **/
s32 rnpm_read_i2c_sff8472_generic(struct rnpm_hw *hw, u8 byte_offset,
				  u8 *sff8472_data)
{
	// *sff8472_data = rnpm_mbx_sfp_read(hw, RNPM_I2C_EEPROM_DEV_ADDR2,
	// byte_offset); return hw->phy.ops.read_i2c_byte(hw, byte_offset,
	// RNPM_I2C_EEPROM_DEV_ADDR2, sff8472_data);
	return -EIO;
}

/**
 *  rnpm_write_i2c_eeprom_generic - Writes 8 bit EEPROM word over I2C interface
 *  @hw: pointer to hardware structure
 *  @byte_offset: EEPROM byte offset to write
 *  @eeprom_data: value to write
 *
 *  Performs byte write operation to SFP module's EEPROM over I2C interface.
 **/
s32 rnpm_write_i2c_eeprom_generic(struct rnpm_hw *hw, u8 byte_offset,
				  u8 eeprom_data)
{
	// return hw->phy.ops.write_i2c_byte(hw, byte_offset,
	// RNPM_I2C_EEPROM_DEV_ADDR, eeprom_data);
	return -EIO;
}

/**
 *  rnpm_read_i2c_byte_generic - Reads 8 bit word over I2C
 *  @hw: pointer to hardware structure
 *  @byte_offset: byte offset to read
 *  @data: value read
 *
 *  Performs byte read operation to SFP module's EEPROM over I2C interface at
 *  a specified device address.
 **/
s32 rnpm_read_i2c_byte_generic(struct rnpm_hw *hw, u8 byte_offset, u8 dev_addr,
			       u8 *data)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_write_i2c_byte_generic - Writes 8 bit word over I2C
 *  @hw: pointer to hardware structure
 *  @byte_offset: byte offset to write
 *  @data: value to write
 *
 *  Performs byte write operation to SFP module's EEPROM over I2C interface at
 *  a specified device address.
 **/
s32 rnpm_write_i2c_byte_generic(struct rnpm_hw *hw, u8 byte_offset, u8 dev_addr,
				u8 data)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_i2c_start - Sets I2C start condition
 *  @hw: pointer to hardware structure
 *
 *  Sets I2C start condition (High -> Low on SDA while SCL is High)
 **/
__maybe_unused static void rnpm_i2c_start(struct rnpm_hw *hw)
{
}

/**
 *  rnpm_i2c_stop - Sets I2C stop condition
 *  @hw: pointer to hardware structure
 *
 *  Sets I2C stop condition (Low -> High on SDA while SCL is High)
 **/
__maybe_unused static void rnpm_i2c_stop(struct rnpm_hw *hw)
{
}

/**
 *  rnpm_clock_in_i2c_byte - Clocks in one byte via I2C
 *  @hw: pointer to hardware structure
 *  @data: data byte to clock in
 *
 *  Clocks in one byte data via I2C data/clock
 **/
__maybe_unused static s32 rnpm_clock_in_i2c_byte(struct rnpm_hw *hw, u8 *data)
{
	s32 i;
	bool bit = false;

	for (i = 7; i >= 0; i--) {
		rnpm_clock_in_i2c_bit(hw, &bit);
		*data |= bit << i;
	}

	return 0;
}

/**
 *  rnpm_clock_out_i2c_byte - Clocks out one byte via I2C
 *  @hw: pointer to hardware structure
 *  @data: data byte clocked out
 *
 *  Clocks out one byte data via I2C data/clock
 **/
__maybe_unused static s32 rnpm_clock_out_i2c_byte(struct rnpm_hw *hw, u8 data)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_get_i2c_ack - Polls for I2C ACK
 *  @hw: pointer to hardware structure
 *
 *  Clocks in/out one bit via I2C data/clock
 **/
__maybe_unused static s32 rnpm_get_i2c_ack(struct rnpm_hw *hw)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_clock_in_i2c_bit - Clocks in one bit via I2C data/clock
 *  @hw: pointer to hardware structure
 *  @data: read data value
 *
 *  Clocks in one bit via I2C data/clock
 **/
__maybe_unused static s32 rnpm_clock_in_i2c_bit(struct rnpm_hw *hw, bool *data)
{
	return 0;
}

/**
 *  rnpm_clock_out_i2c_bit - Clocks in/out one bit via I2C data/clock
 *  @hw: pointer to hardware structure
 *  @data: data value to write
 *
 *  Clocks out one bit via I2C data/clock
 **/
__maybe_unused static s32 rnpm_clock_out_i2c_bit(struct rnpm_hw *hw, bool data)
{
	s32 status = 0;

	return status;
}
/**
 *  rnpm_raise_i2c_clk - Raises the I2C SCL clock
 *  @hw: pointer to hardware structure
 *  @i2cctl: Current value of I2CCTL register
 *
 *  Raises the I2C clock line '0'->'1'
 **/
__maybe_unused static void rnpm_raise_i2c_clk(struct rnpm_hw *hw, u32 *i2cctl)
{
}

/**
 *  rnpm_lower_i2c_clk - Lowers the I2C SCL clock
 *  @hw: pointer to hardware structure
 *  @i2cctl: Current value of I2CCTL register
 *
 *  Lowers the I2C clock line '1'->'0'
 **/
__maybe_unused static void rnpm_lower_i2c_clk(struct rnpm_hw *hw, u32 *i2cctl)
{
}

/**
 *  rnpm_set_i2c_data - Sets the I2C data bit
 *  @hw: pointer to hardware structure
 *  @i2cctl: Current value of I2CCTL register
 *  @data: I2C data value (0 or 1) to set
 *
 *  Sets the I2C data bit
 **/
__maybe_unused static s32 rnpm_set_i2c_data(struct rnpm_hw *hw, u32 *i2cctl,
					    bool data)
{
	s32 status = 0;

	return status;
}

/**
 *  rnpm_get_i2c_data - Reads the I2C SDA data bit
 *  @hw: pointer to hardware structure
 *  @i2cctl: Current value of I2CCTL register
 *
 *  Returns the I2C data bit value
 **/
__maybe_unused static bool rnpm_get_i2c_data(u32 *i2cctl)
{
	bool data = false;

	return data;
}

/**
 *  rnpm_i2c_bus_clear - Clears the I2C bus
 *  @hw: pointer to hardware structure
 *
 *  Clears the I2C bus by sending nine clock pulses.
 *  Used when data line is stuck low.
 **/
__maybe_unused static void rnpm_i2c_bus_clear(struct rnpm_hw *hw)
{
}

/**
 *  rnpm_tn_check_overtemp - Checks if an overtemp occurred.
 *  @hw: pointer to hardware structure
 *
 *  Checks if the LASI temp alarm status was triggered due to overtemp
 **/
s32 rnpm_tn_check_overtemp(struct rnpm_hw *hw)
{
	s32 status = 0;

	return status;
}
