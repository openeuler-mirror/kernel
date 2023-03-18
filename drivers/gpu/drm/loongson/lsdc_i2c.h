/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#ifndef __LSDC_I2C__
#define __LSDC_I2C__

#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>
#include <linux/of.h>

struct lsdc_i2c {
	struct i2c_adapter adapter;
	struct i2c_algo_bit_data bit;

	struct drm_device *ddev;

	void __iomem *dir_reg;
	void __iomem *dat_reg;
	/* pin bit mask */
	u8 sda;
	u8 scl;
};

struct lsdc_i2c *lsdc_create_i2c_chan(struct drm_device *ddev,
				      void *reg_base,
				      unsigned int index);

struct lsdc_i2c *lsdc_of_create_i2c_adapter(struct device *dev,
					    void *reg_base,
					    struct device_node *i2c_np);

#endif
