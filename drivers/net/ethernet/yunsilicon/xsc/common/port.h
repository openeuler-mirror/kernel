/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_PORT_H__
#define __XSC_PORT_H__

enum xsc_module_id {
	XSC_MODULE_ID_SFP              = 0x3,
	XSC_MODULE_ID_QSFP             = 0xC,
	XSC_MODULE_ID_QSFP_PLUS        = 0xD,
	XSC_MODULE_ID_QSFP28           = 0x11,
	XSC_MODULE_ID_DSFP		= 0x1B,
};

#define XSC_EEPROM_MAX_BYTES			32
#define XSC_EEPROM_IDENTIFIER_BYTE_MASK	0x000000ff
#define XSC_I2C_ADDR_LOW		0x50
#define XSC_I2C_ADDR_HIGH		0x51
#define XSC_EEPROM_PAGE_LENGTH		256
#define XSC_EEPROM_HIGH_PAGE_LENGTH	128

struct xsc_module_eeprom_query_params {
	u16 size;
	u16 offset;
	u16 i2c_address;
	u32 page;
	u32 bank;
	u32 module_number;
};

int xsc_query_module_eeprom(struct xsc_core_device *dev,
			    u16 offset, u16 size, u8 *data);
int xsc_query_module_eeprom_by_page(struct xsc_core_device *dev,
				    struct xsc_module_eeprom_query_params *params,
				    u8 *data);
#endif
