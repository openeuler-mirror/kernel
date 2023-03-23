// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <linux/i2c.h>
#include <linux/io.h>

#include <drm/drm_print.h>
#include <drm/drm_device.h>
#include <drm/drm_managed.h>

#include "lsdc_regs.h"
#include "lsdc_i2c.h"
#include "lsdc_drv.h"

/*
 * ls7a_gpio_i2c_set - set the state of a gpio pin, either high or low.
 * @mask: gpio pin mask indicate which pin to set
 */
static void ls7a_gpio_i2c_set(struct lsdc_i2c * const li2c, int mask, int state)
{
	struct lsdc_device *ldev = to_lsdc(li2c->ddev);
	unsigned long flags;
	u8 val;

	spin_lock_irqsave(&ldev->reglock, flags);

	if (state) {
		/*
		 * The high state is achieved by setting the direction as
		 * input, because the GPIO is open drained with external
		 * pull up resistance.
		 */
		val = readb(li2c->dir_reg);
		val |= mask;
		writeb(val, li2c->dir_reg);
	} else {
		/* First, set this pin as output */
		val = readb(li2c->dir_reg);
		val &= ~mask;
		writeb(val, li2c->dir_reg);

		/* Then, set the state to it */
		val = readb(li2c->dat_reg);
		val &= ~mask;
		writeb(val, li2c->dat_reg);
	}

	spin_unlock_irqrestore(&ldev->reglock, flags);
}

/*
 * ls7a_gpio_i2c_get - read value back from gpio pin
 * @mask: gpio pin mask indicate which pin to read from
 */
static int ls7a_gpio_i2c_get(struct lsdc_i2c * const li2c, int mask)
{
	struct lsdc_device *ldev = to_lsdc(li2c->ddev);
	unsigned long flags;
	u8 val;

	spin_lock_irqsave(&ldev->reglock, flags);

	/* First, set this pin as input */
	val = readb(li2c->dir_reg);
	val |= mask;
	writeb(val, li2c->dir_reg);

	/* Then, get level state from this pin */
	val = readb(li2c->dat_reg);

	spin_unlock_irqrestore(&ldev->reglock, flags);

	return (val & mask) ? 1 : 0;
}

/* set the state on the i2c->sda pin */
static void ls7a_i2c_set_sda(void *i2c, int state)
{
	struct lsdc_i2c * const li2c = (struct lsdc_i2c *)i2c;

	return ls7a_gpio_i2c_set(li2c, li2c->sda, state);
}

/* set the state on the i2c->scl pin */
static void ls7a_i2c_set_scl(void *i2c, int state)
{
	struct lsdc_i2c * const li2c = (struct lsdc_i2c *)i2c;

	return ls7a_gpio_i2c_set(li2c, li2c->scl, state);
}

/* read the value from the i2c->sda pin */
static int ls7a_i2c_get_sda(void *i2c)
{
	struct lsdc_i2c * const li2c = (struct lsdc_i2c *)i2c;

	return ls7a_gpio_i2c_get(li2c, li2c->sda);
}

/* read the value from the i2c->scl pin */
static int ls7a_i2c_get_scl(void *i2c)
{
	struct lsdc_i2c * const li2c = (struct lsdc_i2c *)i2c;

	return ls7a_gpio_i2c_get(li2c, li2c->scl);
}

/*
 * Mainly for dc in ls7a1000 which have dedicated gpio hardware
 */
static void lsdc_of_release_i2c_adapter(void *res)
{
	struct lsdc_i2c *li2c = res;
	struct i2c_adapter *adapter;
	struct device_node *i2c_np;

	adapter = &li2c->adapter;
	i2c_np = adapter->dev.of_node;
	if (i2c_np)
		of_node_put(i2c_np);

	i2c_del_adapter(adapter);

	kfree(li2c);
}

struct lsdc_i2c *lsdc_of_create_i2c_adapter(struct device *parent,
					    void *reg_base,
					    struct device_node *i2c_np)
{
	unsigned int udelay = 5;
	unsigned int timeout = 2200;
	int nr = -1;
	struct i2c_adapter *adapter;
	struct lsdc_i2c *li2c;
	u32 sda, scl;
	int ret;

	li2c = kzalloc(sizeof(*li2c), GFP_KERNEL);
	if (!li2c)
		return ERR_PTR(-ENOMEM);

	ret = of_property_read_u32(i2c_np, "loongson,sda", &sda);
	if (ret) {
		dev_err(parent, "No sda pin number provided\n");
		return ERR_PTR(ret);
	}

	ret = of_property_read_u32(i2c_np, "loongson,scl", &scl);
	if (ret) {
		dev_err(parent, "No scl pin number provided\n");
		return ERR_PTR(ret);
	}

	ret = of_property_read_u32(i2c_np, "loongson,nr", &nr);
	if (ret) {
		int id;

		if (ret == -EINVAL)
			dev_dbg(parent, "no nr provided\n");

		id = of_alias_get_id(i2c_np, "i2c");
		if (id >= 0)
			nr = id;
	}

	li2c->sda = 1 << sda;
	li2c->scl = 1 << scl;

	/* Optional properties which made the driver more flexible */
	of_property_read_u32(i2c_np, "loongson,udelay", &udelay);
	of_property_read_u32(i2c_np, "loongson,timeout", &timeout);

	li2c->dir_reg = reg_base + LS7A_DC_GPIO_DIR_REG;
	li2c->dat_reg = reg_base + LS7A_DC_GPIO_DAT_REG;

	li2c->bit.setsda = ls7a_i2c_set_sda;
	li2c->bit.setscl = ls7a_i2c_set_scl;
	li2c->bit.getsda = ls7a_i2c_get_sda;
	li2c->bit.getscl = ls7a_i2c_get_scl;
	li2c->bit.udelay = udelay;
	li2c->bit.timeout = usecs_to_jiffies(timeout);
	li2c->bit.data = li2c;

	adapter = &li2c->adapter;
	adapter->algo_data = &li2c->bit;
	adapter->owner = THIS_MODULE;
	adapter->class = I2C_CLASS_DDC;
	adapter->dev.parent = parent;
	adapter->nr = nr;
	adapter->dev.of_node = i2c_np;

	snprintf(adapter->name, sizeof(adapter->name), "gpio-i2c-%d", nr);

	i2c_set_adapdata(adapter, li2c);

	ret = i2c_bit_add_numbered_bus(adapter);
	if (ret) {
		if (i2c_np)
			of_node_put(i2c_np);

		kfree(li2c);
		return ERR_PTR(ret);
	}

	dev_info(parent, "sda=%u, scl=%u, nr=%d, udelay=%u, timeout=%u\n",
		 li2c->sda, li2c->scl, nr, udelay, timeout);

	ret = devm_add_action_or_reset(parent, lsdc_of_release_i2c_adapter, li2c);
	if (ret)
		return NULL;

	return li2c;
}

static void lsdc_release_i2c_chan(struct drm_device *dev, void *res)
{
	struct lsdc_i2c *li2c = res;

	i2c_del_adapter(&li2c->adapter);

	kfree(li2c);
}

struct lsdc_i2c *lsdc_create_i2c_chan(struct drm_device *ddev,
				      void *reg_base,
				      unsigned int index)
{
	struct i2c_adapter *adapter;
	struct lsdc_i2c *li2c;
	int ret;

	li2c = kzalloc(sizeof(*li2c), GFP_KERNEL);
	if (!li2c)
		return ERR_PTR(-ENOMEM);

	if (index == 0) {
		li2c->sda = 0x01;
		li2c->scl = 0x02;
	} else if (index == 1) {
		li2c->sda = 0x04;
		li2c->scl = 0x08;
	}

	li2c->ddev = ddev;
	li2c->dir_reg = reg_base + LS7A_DC_GPIO_DIR_REG;
	li2c->dat_reg = reg_base + LS7A_DC_GPIO_DAT_REG;

	li2c->bit.setsda = ls7a_i2c_set_sda;
	li2c->bit.setscl = ls7a_i2c_set_scl;
	li2c->bit.getsda = ls7a_i2c_get_sda;
	li2c->bit.getscl = ls7a_i2c_get_scl;
	li2c->bit.udelay = 5;
	li2c->bit.timeout = usecs_to_jiffies(2200);
	li2c->bit.data = li2c;

	adapter = &li2c->adapter;
	adapter->algo_data = &li2c->bit;
	adapter->owner = THIS_MODULE;
	adapter->class = I2C_CLASS_DDC;
	adapter->dev.parent = ddev->dev;
	adapter->nr = -1;

	snprintf(adapter->name, sizeof(adapter->name), "gpio-i2c-%d", index);

	i2c_set_adapdata(adapter, li2c);

	ret = i2c_bit_add_bus(adapter);
	if (ret) {
		kfree(li2c);
		return ERR_PTR(ret);
	}

	ret = drmm_add_action_or_reset(ddev, lsdc_release_i2c_chan, li2c);
	if (ret)
		return NULL;

	drm_info(ddev, "%s: sda=%u, scl=%u\n",
		 adapter->name, li2c->sda, li2c->scl);

	return li2c;
}
