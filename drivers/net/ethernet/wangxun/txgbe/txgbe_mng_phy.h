/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */
#ifndef _TXGBE_MNG_PHY_H_
#define _TXGBE_MNG_PHY_H_

#define TXGBE_HI_COMMAND_TIMEOUT_SHORT  500

#define FW_PHY_CONFIG_READ_CMD          0xc0
#define FW_PHY_CONFIG_LINK_CMD          0xc1
#define FW_PHY_CONFIG_FC_CMD            0xc2
#define FW_PHY_CONFIG_POWER_CMD         0xc3
#define FW_PHY_CONFIG_RESET_CMD         0xc4
#define FW_READ_SFP_INFO_CMD            0xc5
#define FW_READ_EEPROM_I2C_CMD          0xc6 /* read i2c store in shadow ram through mbox by fw */
#define FW_READ_I2C_CMD                 0xc7 /* read i2c through mbox by fw */
#define FW_WRITE_I2C_CMD                0xc8 /* write i2c through mbox by fw */

#define TXGBE_EEPROM_I2C_SRART_PTR      0x580
#define TXGBE_EEPROM_I2C_END_PTR        0x780
#define TXGBE_EEPROM_I2C_LAN0_PTR       0x580
#define TXGBE_EEPROM_I2C_LAN1_PTR       0x680

struct txgbe_hic_ephy_setlink {
	struct txgbe_hic_hdr hdr;
	u8 speed;
	u8 duplex;
	u8 autoneg;
	u8 fec_mode;
	u8 resv[4];
};

struct txgbe_hic_ephy_fc {
	struct txgbe_hic_hdr hdr;
	u8 flow_ctl;
	u8 resv[3];
};

struct txgbe_hic_ephy_power {
	struct txgbe_hic_hdr hdr;
	u8 power;
	u8 resv[3];
};

struct txgbe_hic_ephy_reset {
	struct txgbe_hic_hdr hdr;
};

struct txgbe_hic_ephy_status {
	struct txgbe_hic_hdr hdr;
	u8 speed;
	u8 duplex;
	u8 autoneg;
	u8 flow_ctl;
	u8 power;
	u8 fec_mode;
	u8 resv[6];
};

struct txgbe_hic_get_sfp_info {
	struct txgbe_hic_hdr hdr;
	u8 identifier;		//A0H 0x0
	u8 com_1g_code;		//A0H 0x6
	u8 com_10g_code;	//A0H 0x3
	u8 com_25g_code;	//A0H 0x24
	u8 cable_spec;		//A0H 0x3C
	u8 cable_tech;		//A0H 0x8
	u8 vendor_oui0;		//A0H 0x25
	u8 vendor_oui1;		//A0H 0x26
	u8 vendor_oui2;		//A0H 0x27
	u8 transceiver_type;//A0H 0x83
	u8 reserved[6];
};

struct txgbe_hic_i2c_read {
	struct txgbe_hic_hdr hdr;
	u32	offset;
	u32	length;
	u8	page;
	u8	bank;
	u8	i2c_address;
	u8	*data;
};

int txgbe_test_phy_status_hostif(struct txgbe_hw *hw);
int txgbe_set_phy_link_hostif(struct txgbe_hw *hw, int speed, bool autoneg, u8 duplex);
int txgbe_get_phy_status_hostif(struct txgbe_hw *hw,
				struct txgbe_hic_ephy_status *buffer);
int txgbe_set_phy_fc_hostif(struct txgbe_hw *hw, u8 fc);
int txgbe_set_phy_power_hostif(struct txgbe_hw *hw, u8 power);
int txgbe_identify_module_aml(struct txgbe_hw *hw);

#endif /* _TXGBE_MNG_PHY_H_ */
