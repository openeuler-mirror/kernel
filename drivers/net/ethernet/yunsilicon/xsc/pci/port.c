// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include "common/driver.h"
#include "common/port.h"

int xsc_core_access_reg(struct xsc_core_device *xdev, void *data_in,
			int size_in, void *data_out, int size_out,
			u16 reg_num, int arg, int write)
{
	struct xsc_access_reg_mbox_in *in = NULL;
	struct xsc_access_reg_mbox_out *out = NULL;
	int err = -ENOMEM;

	in = xsc_vzalloc(sizeof(*in) + size_in);
	if (!in)
		return -ENOMEM;

	out = xsc_vzalloc(sizeof(*out) + size_out);
	if (!out)
		goto ex1;

	memcpy(in->data, data_in, size_in);
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_ACCESS_REG);
	in->hdr.opmod = cpu_to_be16(!write);
	in->arg = cpu_to_be32(arg);
	in->register_id = cpu_to_be16(reg_num);
	err = xsc_cmd_exec(xdev, in, sizeof(*in) + size_in, out,
			   sizeof(*out) + size_out);
	if (err)
		goto ex2;

	if (out->hdr.status)
		return xsc_cmd_status_to_err(&out->hdr);

	if (!err)
		memcpy(data_out, out->data, size_out);

ex2:
	xsc_vfree(out);
ex1:
	xsc_vfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_access_reg);

struct xsc_reg_pcap {
	u8			rsvd0;
	u8			port_num;
	u8			rsvd1[2];
	__be32			caps_127_96;
	__be32			caps_95_64;
	__be32			caps_63_32;
	__be32			caps_31_0;
};

int xsc_set_port_caps(struct xsc_core_device *xdev, int port_num, u32 caps)
{
	struct xsc_reg_pcap in;
	struct xsc_reg_pcap out;
	int err;

	memset(&in, 0, sizeof(in));
	in.caps_127_96 = cpu_to_be32(caps);
	in.port_num = port_num;

	err = xsc_core_access_reg(xdev, &in, sizeof(in), &out,
				  sizeof(out), XSC_REG_PCAP, 0, 1);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_set_port_caps);

static int xsc_query_module_num(struct xsc_core_device *dev, int *module_num)
{
	*module_num = dev->mac_port;
	return 0;
}

static int xsc_query_module_id(struct xsc_core_device *dev, int module_num,
			       u8 *module_id)
{
	struct xsc_reg_mcia in;
	struct xsc_reg_mcia out;
	int err, status;
	u8 *ptr;

	in.i2c_device_address = XSC_I2C_ADDR_LOW;
	in.module = module_num;
	in.device_address = 0;
	in.page_number = 0;
	in.size = 1;

	err = xsc_core_access_reg(dev, &in, sizeof(in), &out,
				  sizeof(out), XSC_REG_MCIA, 0, 0);
	if (err)
		return err;

	status = out.status;
	if (status) {
		xsc_core_err(dev, "query_mcia_reg failed: status: 0x%x\n",
			     status);
		return -EIO;
	}
	ptr = out.dword_0;

	*module_id = ptr[0];

	return 0;
}

static int xsc_qsfp_eeprom_page(u16 offset)
{
	if (offset < XSC_EEPROM_PAGE_LENGTH)
		/* Addresses between 0-255 - page 00 */
		return 0;

	/* Addresses between 256 - 639 belongs to pages 01, 02 and 03
	 * For example, offset = 400 belongs to page 02:
	 * 1 + ((400 - 256)/128) = 2
	 */
	return 1 + ((offset - XSC_EEPROM_PAGE_LENGTH) /
		    XSC_EEPROM_HIGH_PAGE_LENGTH);
}

static int xsc_qsfp_eeprom_high_page_offset(int page_num)
{
	if (!page_num) /* Page 0 always start from low page */
		return 0;

	/* High page */
	return page_num * XSC_EEPROM_HIGH_PAGE_LENGTH;
}

static void xsc_qsfp_eeprom_params_set(u16 *i2c_addr, int *page_num, u16 *offset)
{
	*i2c_addr = XSC_I2C_ADDR_LOW;
	*page_num = xsc_qsfp_eeprom_page(*offset);
	*offset -=  xsc_qsfp_eeprom_high_page_offset(*page_num);
}

static void xsc_sfp_eeprom_params_set(u16 *i2c_addr, int *page_num, u16 *offset)
{
	*i2c_addr = XSC_I2C_ADDR_LOW;
	*page_num = 0;

	if (*offset < XSC_EEPROM_PAGE_LENGTH)
		return;

	*i2c_addr = XSC_I2C_ADDR_HIGH;
	*offset -= XSC_EEPROM_PAGE_LENGTH;
}

static int xsc_query_mcia(struct xsc_core_device *dev,
			  struct xsc_module_eeprom_query_params *params, u8 *data)
{
	struct xsc_reg_mcia in;
	struct xsc_reg_mcia out;
	int status, err;
	void *ptr;
	u16 size;

	size = min_t(int, params->size, XSC_EEPROM_MAX_BYTES);

	in.i2c_device_address = params->i2c_address;
	in.module = params->module_number;
	in.device_address = params->offset;
	in.page_number = params->page;
	in.size = size;

	err = xsc_core_access_reg(dev, &in, sizeof(in), &out,
				  sizeof(out), XSC_REG_MCIA, 0, 0);
	if (err)
		return err;

	status = out.status;
	if (status) {
		xsc_core_err(dev, "query_mcia_reg failed: status: 0x%x\n",
			     status);
		return -EIO;
	}

	ptr = out.dword_0;
	memcpy(data, ptr, size);

	return size;
}

int xsc_query_module_eeprom(struct xsc_core_device *dev,
			    u16 offset, u16 size, u8 *data)
{
	struct xsc_module_eeprom_query_params query = {0};
	u8 module_id;
	int err;

	err = xsc_query_module_num(dev, &query.module_number);
	if (err)
		return err;

	err = xsc_query_module_id(dev, query.module_number, &module_id);
	if (err)
		return err;

	switch (module_id) {
	case XSC_MODULE_ID_SFP:
		xsc_sfp_eeprom_params_set(&query.i2c_address, &query.page, &offset);
		break;
	case XSC_MODULE_ID_QSFP:
	case XSC_MODULE_ID_QSFP_PLUS:
	case XSC_MODULE_ID_QSFP28:
	case XSC_MODULE_ID_QSFP_DD:
	case XSC_MODULE_ID_QSFP_PLUS_CMIS:
		xsc_qsfp_eeprom_params_set(&query.i2c_address, &query.page, &offset);
		break;
	default:
		xsc_core_err(dev, "Module ID not recognized: 0x%x\n", module_id);
		return -EINVAL;
	}

	if (offset + size > XSC_EEPROM_PAGE_LENGTH)
		/* Cross pages read, read until offset 256 in low page */
		size = XSC_EEPROM_PAGE_LENGTH - offset;

	query.size = size;
	query.offset = offset;

	return xsc_query_mcia(dev, &query, data);
}
EXPORT_SYMBOL_GPL(xsc_query_module_eeprom);

int xsc_query_module_eeprom_by_page(struct xsc_core_device *dev,
				    struct xsc_module_eeprom_query_params *params,
				    u8 *data)
{
	u8 module_id;
	int err;

	err = xsc_query_module_num(dev, &params->module_number);
	if (err)
		return err;

	err = xsc_query_module_id(dev, params->module_number, &module_id);
	if (err)
		return err;

	switch (module_id) {
	case XSC_MODULE_ID_SFP:
		if (params->page > 0)
			return -EINVAL;
		break;
	case XSC_MODULE_ID_QSFP:
	case XSC_MODULE_ID_QSFP28:
	case XSC_MODULE_ID_QSFP_PLUS:
		if (params->page > 3)
			return -EINVAL;
		break;
	case XSC_MODULE_ID_DSFP:
		break;
	default:
		xsc_core_err(dev, "Module ID not recognized: 0x%x\n", module_id);
		return -EINVAL;
	}

	if (params->i2c_address != XSC_I2C_ADDR_HIGH &&
	    params->i2c_address != XSC_I2C_ADDR_LOW) {
		xsc_core_err(dev, "I2C address not recognized: 0x%x\n", params->i2c_address);
		return -EINVAL;
	}

	return xsc_query_mcia(dev, params, data);
}
EXPORT_SYMBOL_GPL(xsc_query_module_eeprom_by_page);

