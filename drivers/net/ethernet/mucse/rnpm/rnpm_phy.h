/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef _RNPM_PHY_H_
#define _RNPM_PHY_H_

#include "rnpm_type.h"
#define RNPM_I2C_EEPROM_DEV_ADDR 0xA0
#define RNPM_I2C_EEPROM_DEV_ADDR2 0xA2

/* PHY YT8531S*/
#define RNPM_YT8531_PHY_ID 0x4f51e91a
#define RNPM_YT8531_PHY_SPEC_CTRL 0x10
#define RNPM_YT8531_PHY_SPEC_CTRL_FORCE_MDIX 0x0020
#define RNPM_YT8531_PHY_SPEC_CTRL_AUTO_MDI_MDIX 0x0060
#define RNPM_YT8531_PHY_SPEC_CTRL_MDIX_CFG_MASK 0x0060

/* EEPROM byte offsets */
#define SFF_MODULE_ID_OFFSET 0x00
#define SFF_DIAG_SUPPORT_OFFSET 0x5c
#define SFF_MODULE_ID_SFF 0x2
#define SFF_MODULE_ID_SFP 0x3
#define SFF_MODULE_ID_QSFP 0xc
#define SFF_MODULE_ID_QSFP_PLUS 0xd
#define SFF_MODULE_ID_QSFP28 0x11

/* Bitmasks */
#define RNPM_SFF_DA_PASSIVE_CABLE 0x4
#define RNPM_SFF_DA_ACTIVE_CABLE 0x8
#define RNPM_SFF_DA_SPEC_ACTIVE_LIMITING 0x4
#define RNPM_SFF_1GBASESX_CAPABLE 0x1
#define RNPM_SFF_1GBASELX_CAPABLE 0x2
#define RNPM_SFF_1GBASET_CAPABLE 0x8
#define RNPM_SFF_10GBASESR_CAPABLE 0x10
#define RNPM_SFF_10GBASELR_CAPABLE 0x20
#define RNPM_SFF_ADDRESSING_MODE 0x4
#define RNPM_I2C_EEPROM_READ_MASK 0x100
#define RNPM_I2C_EEPROM_STATUS_MASK 0x3
#define RNPM_I2C_EEPROM_STATUS_NO_OPERATION 0x0
#define RNPM_I2C_EEPROM_STATUS_PASS 0x1
#define RNPM_I2C_EEPROM_STATUS_FAIL 0x2
#define RNPM_I2C_EEPROM_STATUS_IN_PROGRESS 0x3

/* Flow control defines */
#define RNPM_TAF_SYM_PAUSE 0x400
#define RNPM_TAF_ASM_PAUSE 0x800

/* Bit-shift macros */
#define RNPM_SFF_VENDOR_OUI_BYTE0_SHIFT 24
#define RNPM_SFF_VENDOR_OUI_BYTE1_SHIFT 16
#define RNPM_SFF_VENDOR_OUI_BYTE2_SHIFT 8

/* Vendor OUIs: format of OUI is 0x[byte0][byte1][byte2][00] */
#define RNPM_SFF_VENDOR_OUI_TYCO 0x00407600
#define RNPM_SFF_VENDOR_OUI_FTL 0x00906500
#define RNPM_SFF_VENDOR_OUI_AVAGO 0x00176A00
#define RNPM_SFF_VENDOR_OUI_INTEL 0x001B2100

/* I2C SDA and SCL timing parameters for standard mode */
#define RNPM_I2C_T_HD_STA 4
#define RNPM_I2C_T_LOW 5
#define RNPM_I2C_T_HIGH 4
#define RNPM_I2C_T_SU_STA 5
#define RNPM_I2C_T_HD_DATA 5
#define RNPM_I2C_T_SU_DATA 1
#define RNPM_I2C_T_RISE 1
#define RNPM_I2C_T_FALL 1
#define RNPM_I2C_T_SU_STO 4
#define RNPM_I2C_T_BUF 5

#define RNPM_TN_LASI_STATUS_REG 0x9005
#define RNPM_TN_LASI_STATUS_TEMP_ALARM 0x0008

/* SFP+ SFF-8472 Compliance code */
#define RNPM_SFF_SFF_8472_UNSUP 0x00

s32 rnpm_init_phy_ops_generic(struct rnpm_hw *hw);
s32 rnpm_identify_phy_generic(struct rnpm_hw *hw);
s32 rnpm_reset_phy_generic(struct rnpm_hw *hw);
s32 rnpm_read_phy_reg_generic(struct rnpm_hw *hw, u32 reg_addr, u32 device_type,
			      u16 *phy_data);
s32 rnpm_write_phy_reg_generic(struct rnpm_hw *hw, u32 reg_addr,
			       u32 device_type, u16 phy_data);
s32 rnpm_setup_phy_link_generic(struct rnpm_hw *hw);
s32 rnpm_setup_phy_link_speed_generic(struct rnpm_hw *hw, rnpm_link_speed speed,
				      bool autoneg_wait_to_complete);
s32 rnpm_get_copper_link_capabilities_generic(struct rnpm_hw *hw,
					      rnpm_link_speed *speed,
					      bool *autoneg);

/* PHY specific */
s32 rnpm_check_phy_link_tnx(struct rnpm_hw *hw, rnpm_link_speed *speed,
			    bool *link_up);
s32 rnpm_setup_phy_link_tnx(struct rnpm_hw *hw);
s32 rnpm_get_phy_firmware_version_tnx(struct rnpm_hw *hw,
				      u16 *firmware_version);
s32 rnpm_get_phy_firmware_version_generic(struct rnpm_hw *hw,
					  u16 *firmware_version);

s32 rnpm_reset_phy_nl(struct rnpm_hw *hw);
s32 rnpm_identify_sfp_module_generic(struct rnpm_hw *hw);
s32 rnpm_get_sfp_init_sequence_offsets(struct rnpm_hw *hw, u16 *list_offset,
				       u16 *data_offset);
s32 rnpm_tn_check_overtemp(struct rnpm_hw *hw);
s32 rnpm_read_i2c_byte_generic(struct rnpm_hw *hw, u8 byte_offset, u8 dev_addr,
			       u8 *data);
s32 rnpm_write_i2c_byte_generic(struct rnpm_hw *hw, u8 byte_offset, u8 dev_addr,
				u8 data);
s32 rnpm_read_i2c_eeprom_generic(struct rnpm_hw *hw, u8 byte_offset,
				 u8 *eeprom_data);
s32 rnpm_read_i2c_sff8472_generic(struct rnpm_hw *hw, u8 byte_offset,
				  u8 *sff8472_data);
s32 rnpm_write_i2c_eeprom_generic(struct rnpm_hw *hw, u8 byte_offset,
				  u8 eeprom_data);
#endif /* _RNPM_PHY_H_ */
