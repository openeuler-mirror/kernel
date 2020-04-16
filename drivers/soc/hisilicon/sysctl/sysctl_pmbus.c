// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/io.h>
#include <linux/delay.h>
#include "sysctl_drv.h"
#include "sysctl_pmbus.h"

#define SLAVE_ADDR_MAX (1 << 7)
#define CPU_VOL_MIN 500

static void __iomem *g_sysctl_pmbus_base[CHIP_ID_NUM_MAX];

static void his_sysctrl_reg_rd(const void __iomem *addr, u32 reg, unsigned int *val)
{
	*val = readl(addr + reg);
}

static void his_sysctrl_reg_wr(void __iomem *addr, u32 reg, unsigned int val)
{
	writel(val, addr + reg);
}

static int sysctl_pmbus_init(void)
{
	u32 chip_id;
	u64 addr;
	u64 chip_module_base;

	pr_info("[INFO] %s.\n", __func__);
	chip_module_base = get_chip_base();

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		addr = (u64)chip_id * chip_module_base + PMBUS_REG_BASE;
		g_sysctl_pmbus_base[chip_id] = ioremap(addr, (u64)0x10000);
		if (!g_sysctl_pmbus_base[chip_id])
			pr_err("chip=%u, pmbus ioremap failed\n", chip_id);
	}

	return SYSCTL_ERR_OK;
}

static void sysctl_pmbus_deinit(void)
{
	u8 chip_id;

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		if (g_sysctl_pmbus_base[chip_id])
			iounmap((void *)g_sysctl_pmbus_base[chip_id]);
	}
}

int sysctl_reg_read8(u64 addr, u32 data_len)
{
	u32 loop;
	u8  data;
	void __iomem *reg_addr = NULL;
	void __iomem *reg_base = NULL;

	if ((data_len >= 0x10000) || (data_len == 0)) {
		pr_err("%s: data_len[%u] is ERR, be range (0x0--0x10000).\n",
			__func__, data_len);
		return SYSCTL_ERR_PARAM;
	}

	reg_base = ioremap(addr, (u64)0x10000);
	if (!reg_base) {
		pr_err("%s ioremap failed\n", __func__);
		return SYSCTL_ERR_FAILED;
	}

	for (loop = 0; loop < data_len; loop++) {
		reg_addr = reg_base + loop;
		data = readb(reg_addr);
		pr_info("0x%llx: 0x%2.2x\n", addr + loop, data);
	}

	if (reg_base)
		iounmap((void *)reg_base);

	return SYSCTL_ERR_OK;
}

int sysctl_reg_write8(u64 addr, u8 data)
{
	void __iomem *reg_base = NULL;

	reg_base = ioremap(addr, (u64)0x100);
	if (!reg_base) {
		pr_err("%s ioremap failed\n", __func__);
		return SYSCTL_ERR_FAILED;
	}

	writeb(data, reg_base);

	if (reg_base)
		iounmap((void *)reg_base);

	return SYSCTL_ERR_OK;
}

int sysctl_reg_read32(u64 addr, u32 data_len)
{
	u32 loop;
	u32 data;
	void __iomem *reg_addr = NULL;
	void __iomem *reg_base = NULL;

	if ((data_len >= 0x10000) ||
		(data_len == 0) ||
		((addr % 0x4) != 0)) {
		pr_err("%s: data_len[%u] is ERR, be range[0x0--0x10000].\n", __func__, data_len);
		return SYSCTL_ERR_PARAM;
	}

	reg_base = ioremap(addr, (u64)0x10000);
	if (!reg_base) {
		pr_err("%s ioremap failed\n", __func__);
		return SYSCTL_ERR_FAILED;
	}

	for (loop = 0; loop < data_len; loop++) {
		reg_addr = reg_base + loop * 0x4;
		data = readl(reg_addr);
		pr_info("0x%llx: 0x%8.8x\n", addr + (u64)loop * 0x4, data);
	}

	if (reg_base)
		iounmap((void *)reg_base);

	return SYSCTL_ERR_OK;
}

int sysctl_reg_write32(u64 addr, u32 data)
{
	void __iomem *reg_base = NULL;

	if ((addr % 0x4) != 0) {
		pr_err("%s: reg_addr is err.\n", __func__);
		return SYSCTL_ERR_PARAM;
	}

	reg_base = ioremap(addr, (u64)0x100);
	if (!reg_base) {
		pr_err("%s ioremap failed\n", __func__);
		return SYSCTL_ERR_FAILED;
	}

	writel(data, reg_base);

	if (reg_base)
		iounmap((void *)reg_base);

	return SYSCTL_ERR_OK;
}

int InitPmbus(u8 chip_id)
{
	void __iomem *base = NULL;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	debug_sysctrl_print("Initialize Pmbus\n");

	his_sysctrl_reg_wr(base, PMBUS_WR_OPEN_OFFSET, 0x1ACCE551);
	his_sysctrl_reg_wr(base, AVS_WR_OPEN_OFFSET, 0x1ACCE551);
	his_sysctrl_reg_wr(base, I2C_LOCK_OFFSET, 0x36313832);

	his_sysctrl_reg_wr(base, I2C_ENABLE_OFFSET, 0);
	his_sysctrl_reg_wr(base, I2C_CON_OFFSET, 0x63);
	/* ulSclHigh > 1us */
	his_sysctrl_reg_wr(base, I2C_SS_SCL_HCNT_OFFSET, I2C_SS_SCLHCNT);
	/* ulSclLow > 1.5us */
	his_sysctrl_reg_wr(base, I2C_SS_SCL_LCNT_OFFSET, I2C_SS_SCLLCNT);
	his_sysctrl_reg_wr(base, I2C_ENABLE_OFFSET, 0x1);

	debug_sysctrl_print("Initialize Pmbus end\n");

	return 0;
}

int DeInitPmbus(u8 chip_id)
{
	void __iomem *base = NULL;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus]read chip_id range[0x0-0x3]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	his_sysctrl_reg_wr(base, PMBUS_WR_OPEN_OFFSET, 0);
	his_sysctrl_reg_wr(base, AVS_WR_OPEN_OFFSET, 0);

	return 0;
}

int sysctl_pmbus_cfg(u8 chip_id, u8 addr, u8 page, u32 slave_addr)
{
	void __iomem *base = NULL;

	if ((chip_id >= CHIP_ID_NUM_MAX) || (slave_addr >= SLAVE_ADDR_MAX)) {
		pr_err("[sysctl pmbus] cfg param err,chipid=0x%x,slave_addr=0x%x\n",
			chip_id, slave_addr);
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x2 << 0x8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x4 << 0x8) | page);

	return 0;
}

int sysctl_pmbus_write(u8 chip_id, u8 addr, u32 slave_addr, u32 data_len, u32 buf)
{
	u32 i = 0;
	u32 temp = 0;
	u32 loop = 0x1000;
	u32 temp_data = addr;
	void __iomem *base = NULL;

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(data_len > DATA_NUM_MAX) ||
		(slave_addr >= SLAVE_ADDR_MAX)) {
		pr_err("[sysctl pmbus] write param err,chipid=0x%x,data_len=0x%x,slave_addr=0x%x!\n",
			chip_id, data_len, slave_addr);
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3ffff);

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x2 << 0x8) | slave_addr);
	if (data_len != 0) {
		his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, addr);

		for (i = 0; i < data_len - 1; i++)
			his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0xff & (buf >> (i * 0x8)));

		temp_data = (0xff & (buf >> (i * 0x8)));
	}
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x4 << 0x8) | temp_data);

	/* poll until send done */
	for (;;) {
		udelay(100); /* Delay 100 subtleties */

		his_sysctrl_reg_rd(base, I2C_INTR_RAW_OFFSET, &temp);

		/* send data failed */
		if (temp & I2C_TX_ABRT) {
			his_sysctrl_reg_rd(base, I2C_TX_ABRT_SRC_REG, &temp);
			pr_err("[sysctl pmbus]write data fail, chip_id:0x%x,slave_addr:0x%x, addr:0x%x!\r\n",
				chip_id, slave_addr, addr);

			his_sysctrl_reg_rd(base, I2C_CLR_TX_ABRT_REG, &temp);
			return SYSCTL_ERR_FAILED;
		}

		his_sysctrl_reg_rd(base, I2C_STATUS_REG, &temp);
		if (temp & I2C_TX_FIFO_EMPTY) {
			his_sysctrl_reg_rd(base, I2C_TX_FIFO_DATA_NUM_REG, &temp);
			if (temp == 0)
				break;
		}

		loop--;
		if (loop == 0) {
			pr_err("[sysctl pmbus]write data retry fail, chip_id:0x%x,slave_addr:0x%x, addr:0x%x!\r\n",
				chip_id, slave_addr, addr);
			return SYSCTL_ERR_FAILED;
		}
	}

	return SYSCTL_ERR_OK;
}

static int sysctl_pmbus_read_pre(void __iomem *base, u8 addr, u32 slave_addr, u32 data_len)
{
	u32 i = 0;
	u32 fifo_num = 0;
	u32 temp_byte = 0;

	if (base == NULL) {
		pr_err("[sysctl pmbus] pmbus_read_pre, base is null.\n");
		return SYSCTL_ERR_PARAM;
	}

	his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3ffff);
	his_sysctrl_reg_rd(base, I2C_RXFLR_OFFSET, &fifo_num);
	debug_sysctrl_print("[sysctl_pmbus_read_byte]read pmbus , read empty rx fifo num:%d\r\n", fifo_num);
	for (i = 0; i < fifo_num; i++)
		his_sysctrl_reg_rd(base, I2C_DATA_CMD_OFFSET, &temp_byte);

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x2 << 0x8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x3 << 0x8) | slave_addr);

	i = data_len;
	while ((i - 1) > 0) {
		his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x100);
		i--;
	}

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x500);

	return 0;
}

static int sysctl_pmbus_wait_data(void __iomem *base, u32 data_len)
{
	u32 i = 0;
	u32 loop = 0x100;
	u32 fifo_num = 0;
	u32 temp_byte = 0;

	if (base == NULL) {
		pr_err("[sysctl pmbus] pmbus_wait_data, base is null.\n");
		return SYSCTL_ERR_PARAM;
	}

	while (loop) {
		udelay(100); /* Delay 100 subtleties */
		his_sysctrl_reg_rd(base, I2C_RXFLR_OFFSET, &fifo_num);
		debug_sysctrl_print("[sysctl_pmbus_read_byte]read pmbus, read rx fifo num:%d\r\n", fifo_num);
		if (data_len == fifo_num) {
			debug_sysctrl_print("[sysctl_pmbus_read_byte]read pmbus, Loop:%d\r\n", 0xffff - loop);
			break;
		}

		loop -= 1;
	}

	if (loop == 0) {
		pr_err("[sysctl pmbus]read pmbus error, I2C_RXFLR = %d\n", fifo_num);
		for (i = 0; i < fifo_num; i++)
			his_sysctrl_reg_rd(base, I2C_DATA_CMD_OFFSET, &temp_byte);

		his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3FFFF);
		return SYSCTL_ERR_TIMEOUT;
	}

	return SYSCTL_ERR_OK;
}

int sysctl_pmbus_read(u8 chip_id, u8 addr, u32 slave_addr, u32 data_len, u32 *buf)
{
	u32 ret;
	u32 i = 0;
	u32 temp_byte = 0;
	u32 temp = 0;
	void __iomem *base = NULL;

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(data_len > DATA_NUM_MAX) ||
		(data_len == 0x0) ||
		(slave_addr >= SLAVE_ADDR_MAX)) {
		pr_err("[sysctl pmbus]read param err,chipid=0x%x,data_len=0x%x,slave_addr=0x%x!\n",
			chip_id, data_len, slave_addr);
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	ret = sysctl_pmbus_read_pre(base, addr, slave_addr, data_len);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	ret = sysctl_pmbus_wait_data(base, data_len);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	for (i = 0; i < data_len; i++) {
		his_sysctrl_reg_rd(base, I2C_DATA_CMD_OFFSET, &temp_byte);
		temp |= temp_byte << (i * 0x8);
	}

	pr_info("[sysctl pmbus]read pmbus temp = 0x%x\n", temp);

	if (!buf) {
		pr_err("[sysctl pmbus]read pmbus error, buf is NULL\n");
		return SYSCTL_ERR_PARAM;
	}

	*buf = temp;

	return 0;
}

int sysctl_cpu_voltage_password_cfg(u8 chip_id, u32 slave_addr)
{
	void __iomem *base = NULL;

	if ((chip_id >= CHIP_ID_NUM_MAX) || (slave_addr >= SLAVE_ADDR_MAX)) {
		pr_err("[sysctl pmbus]  voltage_password_cfg param err,chipid=0x%x,slave_addr=0x%x!\n",
			chip_id, slave_addr);
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x2 << 0x8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x27);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x7c);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x4 << 0x8) | 0xb3);

	return 0;
}

static int hi_vrd_info_check_params(u8 chip_id, u8 page, u32 data_len, u32 slave_addr)
{
	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus] read chip_id range[0x0-0x3]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	if (page >= PAGE_NUM_MAX) {
		pr_err("[sysctl pmbus] read page range[0x0-0x6f]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	if ((data_len > DATA_NUM_MAX) || (data_len == 0)) {
		pr_err("[sysctl pmbus] read data len range[0x1-0x4]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	if (slave_addr >= SLAVE_ADDR_MAX) {
		pr_err("[sysctl pmbus] vrd_info slave_addr=0x%x err!\n", slave_addr);
		return SYSCTL_ERR_PARAM;
	}

	return SYSCTL_ERR_OK;
}

int hi_vrd_info_get(u8 chip_id, u8 addr, u8 page, u32 slave_addr, u32 data_len, u32 *buf)
{
	u32 retry_time = 0x10;
	u32 ret;

	ret = hi_vrd_info_check_params(chip_id, page, data_len, slave_addr);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	ret = InitPmbus(chip_id);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	/* read val */
	ret = sysctl_pmbus_cfg(chip_id, 0x0, page, slave_addr);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	while (retry_time) {
		ret = sysctl_pmbus_read(chip_id, addr, slave_addr, data_len, buf);
		if (ret != SYSCTL_ERR_TIMEOUT)
			break;

		retry_time--;

		udelay(100); /* Delay 100 subtleties */
	}

	if (!retry_time) {
		pr_err("[sysctl pmbus] read voltage mode time out!\n");
		ret = DeInitPmbus(chip_id);
		if (ret != SYSCTL_ERR_OK)
			return ret;

		return SYSCTL_ERR_TIMEOUT;
	}

	if (!buf) {
		pr_err("[sysctl pmbus]read vrd info error, buf is NULL\n");
		return SYSCTL_ERR_PARAM;
	}

	pr_info("read val:0x%x !\n", *buf);

	ret = DeInitPmbus(chip_id);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	return 0;
}

int sysctl_cpu_voltage_read(u8 chip_id, u8 loop, u32 slave_addr)
{
	pmbus_vout_mode vout_mode;
	u32 val = 0;
	u32 ret;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("[sysctl pmbus] read chip_id range[0x0-0x3]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	if (loop >= VOL_LOOP_NUM_MAX) {
		pr_err("[sysctl pmbus] read voltage loop range[0x0-0x2]is err!\n");
		return SYSCTL_ERR_PARAM;
	}

	if (slave_addr >= SLAVE_ADDR_MAX) {
		pr_err("[sysctl pmbus] cpu_voltage_read slave_addr=0x%x err!\n", slave_addr);
		return SYSCTL_ERR_PARAM;
	}

	/* read voltage mode */
	ret = hi_vrd_info_get(chip_id, 0x20, loop, slave_addr, 0x1, (u32 *)&vout_mode);
	if (ret)
		return ret;

	if (vout_mode.bits.vout_mode_surport != 0x1)
		pr_err("[sysctl pmbus]Warning: voltage mode is not supported!\n");

	/* read voltage vlave */
	ret = hi_vrd_info_get (chip_id, 0x8b, loop, slave_addr, 0x2, (u32 *)&val);
	if (ret)
		return ret;

	if (vout_mode.bits.vid_table == CPU_VOUT_MODE_VR125)
		val = 2 * ((val - 1) * 5 + 250); /* 2 1 5 and 250 are the number of relationships. */
	else if (vout_mode.bits.vid_table == CPU_VOUT_MODE_VR120)
		val = (val - 1) * 5 + 250; /* 1 5 and 250 are the number of relationships. */
	else
		pr_err("vout mode[0x%x] is err, voltage is invalid!\n", vout_mode.bits.vid_table);

	pr_info("voltage :%dmV!\n", val);

	return 0;
}

static int sysctl_cpu_convert_vol_to_vid(u32 vid_table, u32 value, u32 *vid)
{
	if (vid_table == CPU_VOUT_MODE_VR125) {
		*vid = (value / 2 - 250) / 5 + 1; /* 2 1 5 and 250 are the number of relationships. */
	} else if (vid_table == CPU_VOUT_MODE_VR120) {
		*vid = (value - 250) / 5 + 1; /* 1 5 and 250 are the number of relationships. */
	} else {
		pr_err("voltage adjust vout mode[0x%x] is err!\n", vid_table);
		return SYSCTL_ERR_FAILED;
	}

	return SYSCTL_ERR_OK;
}

int sysctl_cpu_voltage_adjust (u8 chip_id, u8 loop, u32 slave_addr, u32 value)
{
	u32 ret;
	u32 vid;
	pmbus_vout_mode vout_mode;
	void __iomem *base = NULL;

	if ((chip_id >= CHIP_ID_NUM_MAX) ||
		(slave_addr >= SLAVE_ADDR_MAX) ||
		(value < CPU_VOL_MIN)) {
		pr_err("[sysctl pmbus]cpu_voltage_adjust param err,chipid=0x%x,slave_addr=0x%x,value=0x%x!\n",
			chip_id, slave_addr, value);
		return SYSCTL_ERR_PARAM;
	}

	base = g_sysctl_pmbus_base[chip_id];

	/* read voltage mode */
	ret = hi_vrd_info_get(chip_id, 0x20, loop, slave_addr, 0x1, (u32 *)&vout_mode);
	if (ret)
		return ret;

	if (vout_mode.bits.vout_mode_surport != 0x1)
		pr_err("[sysctl pmbus]Warning: voltage mode is not supported!\n");

	ret = sysctl_cpu_convert_vol_to_vid(vout_mode.bits.vid_table, value, &vid);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	ret = InitPmbus(chip_id);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	ret = sysctl_pmbus_cfg(chip_id, 0x0, 0x3f, slave_addr);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	ret = sysctl_cpu_voltage_password_cfg (chip_id, slave_addr);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	ret = sysctl_pmbus_cfg(chip_id, 0x0, loop, slave_addr);
	if (ret != SYSCTL_ERR_OK)
		return ret;

	his_sysctrl_reg_wr(base, I2C_INTR_RAW_OFFSET, 0x3ffff);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x2 << 0x8) | slave_addr);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0x21);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, 0xff & vid);
	his_sysctrl_reg_wr(base, I2C_DATA_CMD_OFFSET, (0x4 << 0x8) | (0xff & (vid >> 0x8)));

	udelay(100); /* Delay 100 subtleties */

	his_sysctrl_reg_wr(base, PMBUS_WR_OPEN_OFFSET, 0x0);
	his_sysctrl_reg_wr(base, AVS_WR_OPEN_OFFSET, 0x0);

	return SYSCTL_ERR_OK;
}

int hip_sysctl_pmbus_init(void)
{
	int ret;

	ret = sysctl_pmbus_init();
	if (ret != SYSCTL_ERR_OK)
		pr_err("[ERROR] %s fail, ret:[0x%x].\n", __func__, ret);

	return ret;
}

void hip_sysctl_pmbus_exit(void)
{
	sysctl_pmbus_deinit();
	pr_info("[INFO] hip sysctl pmbus exit.\n");
}

EXPORT_SYMBOL(sysctl_cpu_voltage_read);
EXPORT_SYMBOL(hi_vrd_info_get);
EXPORT_SYMBOL(sysctl_cpu_voltage_adjust);
EXPORT_SYMBOL(sysctl_pmbus_write);
EXPORT_SYMBOL(sysctl_pmbus_read);
EXPORT_SYMBOL(InitPmbus);
EXPORT_SYMBOL(DeInitPmbus);
