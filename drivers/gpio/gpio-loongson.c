/*
 *  Loongson-3A/3B/3C/7A GPIO Support
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/gpio/driver.h>
#include <linux/platform_device.h>
#include <linux/bitops.h>
#include <linux/property.h>
#include <asm/types.h>

/* ============== Data structrues =============== */

/* gpio data */
struct platform_gpio_data {
	u32 gpio_conf;
	u32 gpio_out;
	u32 gpio_in;
	u32 in_start_bit;
	u32 support_irq;
	char *label;
	int gpio_base;
	int ngpio;
};

#define GPIO_IO_CONF(x)	                (x->base + x->conf_offset)
#define GPIO_OUT(x)	                (x->base + x->out_offset)
#define GPIO_IN(x)	                (x->base + x->in_offset)

#define LS7A_GPIO_OEN_BYTE(x, gpio)	(x->base + x->conf_offset + gpio)
#define LS7A_GPIO_OUT_BYTE(x, gpio)	(x->base + x->out_offset + gpio)
#define LS7A_GPIO_IN_BYTE(x, gpio)	(x->base + x->in_offset + gpio)

struct loongson_gpio_chip {
	struct gpio_chip	chip;
	spinlock_t		lock;
	void __iomem		*base;
	int conf_offset;
	int out_offset;
	int in_offset;
	int in_start_bit;
	u16 *gsi_idx_map;
	u16 mapsize;
	bool support_irq;
};

/*
 * GPIO primitives.
 */
static int loongson_gpio_request(struct gpio_chip *chip, unsigned int pin)
{
	if (pin >= chip->ngpio)
		return -EINVAL;
	else
		return 0;
}

static inline void
__set_direction(struct loongson_gpio_chip *lgpio, unsigned int pin, int input)
{
	u64 temp;
	u8  value;

	if (!strcmp(lgpio->chip.label, "loongson,loongson3-gpio") ||
			!strncmp(lgpio->chip.label, "LOON0007", 8)) {
		temp = readq(GPIO_IO_CONF(lgpio));
		if (input)
			temp |= 1ULL << pin;
		else
			temp &= ~(1ULL << pin);
		writeq(temp, GPIO_IO_CONF(lgpio));
		return;
	}
	if (!strcmp(lgpio->chip.label, "loongson,ls7a-gpio") ||
			!strncmp(lgpio->chip.label, "LOON0002", 8)) {
		if (input)
			value = 1;
		else
			value = 0;
		writeb(value, LS7A_GPIO_OEN_BYTE(lgpio, pin));
		return;
	}
}

static void __set_level(struct loongson_gpio_chip *lgpio, unsigned int pin, int high)
{
	u64 temp;
	u8 value;

	/* If GPIO controller is on 3A,then... */
	if (!strcmp(lgpio->chip.label, "loongson,loongson3-gpio") ||
			!strncmp(lgpio->chip.label, "LOON0007", 8)) {
		temp = readq(GPIO_OUT(lgpio));
		if (high)
			temp |= 1ULL << pin;
		else
			temp &= ~(1ULL << pin);
		writeq(temp, GPIO_OUT(lgpio));
		return;
	}

	if (!strcmp(lgpio->chip.label, "loongson,ls7a-gpio") ||
			!strncmp(lgpio->chip.label, "LOON0002", 8)) {
		if (high)
			value = 1;
		else
			value = 0;
		writeb(value, LS7A_GPIO_OUT_BYTE(lgpio, pin));
		return;
	}
}

static int loongson_gpio_direction_input(struct gpio_chip *chip, unsigned int pin)
{
	unsigned long flags;
	struct loongson_gpio_chip *lgpio =
		container_of(chip, struct loongson_gpio_chip, chip);

	spin_lock_irqsave(&lgpio->lock, flags);
	__set_direction(lgpio, pin, 1);
	spin_unlock_irqrestore(&lgpio->lock, flags);

	return 0;
}

static int loongson_gpio_direction_output(struct gpio_chip *chip,
		unsigned int pin, int value)
{
	struct loongson_gpio_chip *lgpio =
		container_of(chip, struct loongson_gpio_chip, chip);
	unsigned long flags;

	spin_lock_irqsave(&lgpio->lock, flags);
	__set_level(lgpio, pin, value);
	__set_direction(lgpio, pin, 0);
	spin_unlock_irqrestore(&lgpio->lock, flags);

	return 0;
}

static int loongson_gpio_get(struct gpio_chip *chip, unsigned int pin)
{
	struct loongson_gpio_chip *lgpio =
		container_of(chip, struct loongson_gpio_chip, chip);
	u64 temp;
	u8 value;

	/* GPIO controller in 3A is different for 7A */
	if (!strcmp(lgpio->chip.label, "loongson,loongson3-gpio") ||
			!strncmp(lgpio->chip.label, "LOON0007", 8)) {
		temp = readq(GPIO_IN(lgpio));
		return ((temp & (1ULL << (pin + lgpio->in_start_bit))) != 0);
	}

	if (!strcmp(lgpio->chip.label, "loongson,ls7a-gpio") ||
			!strncmp(lgpio->chip.label, "LOON0002", 8)) {
		value = readb(LS7A_GPIO_IN_BYTE(lgpio, pin));
		return (value & 1);
	}

	return -ENXIO;
}

static void loongson_gpio_set(struct gpio_chip *chip, unsigned int pin, int value)
{
	struct loongson_gpio_chip *lgpio =
		container_of(chip, struct loongson_gpio_chip, chip);
	unsigned long flags;

	spin_lock_irqsave(&lgpio->lock, flags);
	__set_level(lgpio, pin, value);
	spin_unlock_irqrestore(&lgpio->lock, flags);
}

static int loongson_gpio_to_irq(struct gpio_chip *chip, unsigned int offset)
{
	struct platform_device *pdev =
		container_of(chip->parent, struct platform_device, dev);
	struct loongson_gpio_chip *lgpio =
		container_of(chip, struct loongson_gpio_chip, chip);

	if (offset >= chip->ngpio)
		return -EINVAL;

	if ((lgpio->gsi_idx_map != NULL) && (offset < lgpio->mapsize))
		offset = lgpio->gsi_idx_map[offset];

	return platform_get_irq(pdev, offset);
}

static int loongson_gpio_init(struct device *dev, struct loongson_gpio_chip *lgpio,
				struct device_node *np,
				void __iomem *base)
{
	lgpio->chip.request = loongson_gpio_request;
	lgpio->chip.direction_input = loongson_gpio_direction_input;
	lgpio->chip.get = loongson_gpio_get;
	lgpio->chip.direction_output = loongson_gpio_direction_output;
	lgpio->chip.set = loongson_gpio_set;
	lgpio->chip.can_sleep = 0;
	lgpio->chip.fwnode = dev_fwnode(dev);
	lgpio->chip.parent = dev;
	spin_lock_init(&lgpio->lock);
	lgpio->base = (void __iomem *)base;

	if (!strcmp(lgpio->chip.label, "loongson,ls7a-gpio") ||
		!strncmp(lgpio->chip.label, "LOON0002", 8) ||
		!strcmp(lgpio->chip.label, "loongson,loongson3-gpio") ||
		!strncmp(lgpio->chip.label, "LOON0007", 8)) {

		lgpio->chip.to_irq = loongson_gpio_to_irq;
	}
	gpiochip_add(&lgpio->chip);

	return 0;
}


static void of_loongson_gpio_get_props(struct device_node *np,
				  struct loongson_gpio_chip *lgpio)
{
	const char *name;

	of_property_read_u32(np, "ngpios", (u32 *)&lgpio->chip.ngpio);
	of_property_read_u32(np, "gpio_base", (u32 *)&lgpio->chip.base);
	of_property_read_u32(np, "conf_offset", (u32 *)&lgpio->conf_offset);
	of_property_read_u32(np, "out_offset", (u32 *)&lgpio->out_offset);
	of_property_read_u32(np, "in_offset", (u32 *)&lgpio->in_offset);
	of_property_read_string(np, "compatible", &name);
	if (!strcmp(name, "loongson,loongson3-gpio")) {
		of_property_read_u32(np, "in_start_bit",
					(u32 *)&lgpio->in_start_bit);
		if (of_property_read_bool(np, "support_irq"))
			lgpio->support_irq = true;
	}
	lgpio->chip.label = kstrdup(name, GFP_KERNEL);
}

static void acpi_loongson_gpio_get_props(struct platform_device *pdev,
				  struct loongson_gpio_chip *lgpio)
{

	struct device *dev = &pdev->dev;
	int rval;

	device_property_read_u32(dev, "ngpios", (u32 *)&lgpio->chip.ngpio);
	device_property_read_u32(dev, "gpio_base", (u32 *)&lgpio->chip.base);
	device_property_read_u32(dev, "conf_offset", (u32 *)&lgpio->conf_offset);
	device_property_read_u32(dev, "out_offset", (u32 *)&lgpio->out_offset);
	device_property_read_u32(dev, "in_offset", (u32 *)&lgpio->in_offset);
	rval = device_property_read_u16_array(dev, "gsi_idx_map", NULL, 0);
	if (rval > 0) {
		lgpio->gsi_idx_map =
			kmalloc_array(rval, sizeof(*lgpio->gsi_idx_map),
					GFP_KERNEL);
		if (unlikely(!lgpio->gsi_idx_map)) {
			dev_err(dev, "Alloc gsi_idx_map fail!\n");
		} else {
			lgpio->mapsize = rval;
			device_property_read_u16_array(dev, "gsi_idx_map",
					lgpio->gsi_idx_map, lgpio->mapsize);
		}
	}
	if (!strcmp(pdev->name, "LOON0007")) {
		device_property_read_u32(dev, "in_start_bit",
						(u32 *)&lgpio->in_start_bit);
		if (device_property_read_bool(dev, "support_irq"))
			lgpio->support_irq = true;
	}
	lgpio->chip.label = kstrdup(pdev->name, GFP_KERNEL);
}

static void platform_loongson_gpio_get_props(struct platform_device *pdev,
				  struct loongson_gpio_chip *lgpio)
{
	struct platform_gpio_data *gpio_data =
		(struct platform_gpio_data *)pdev->dev.platform_data;

	lgpio->chip.ngpio = gpio_data->ngpio;
	lgpio->chip.base = gpio_data->gpio_base;
	lgpio->conf_offset = gpio_data->gpio_conf;
	lgpio->out_offset = gpio_data->gpio_out;
	lgpio->in_offset = gpio_data->gpio_in;
	if (!strcmp(gpio_data->label, "loongson,loongson3-gpio")) {
		lgpio->in_start_bit = gpio_data->in_start_bit;
		lgpio->support_irq = gpio_data->support_irq;
	}
	lgpio->chip.label = kstrdup(gpio_data->label, GFP_KERNEL);
}

static int loongson_gpio_probe(struct platform_device *pdev)
{
	struct resource *iores;
	void __iomem *base;
	struct loongson_gpio_chip *lgpio;
	struct device_node *np = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	int ret = 0;

	lgpio = kzalloc(sizeof(struct loongson_gpio_chip), GFP_KERNEL);
	if (!lgpio)
		return -ENOMEM;

	if (np)
		of_loongson_gpio_get_props(np, lgpio);
	else if (ACPI_COMPANION(&pdev->dev))
		acpi_loongson_gpio_get_props(pdev, lgpio);
	else
		platform_loongson_gpio_get_props(pdev, lgpio);

	iores = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!iores) {
		ret = -ENODEV;
		goto out;
	}
	if (!request_mem_region(iores->start, resource_size(iores),
				pdev->name)) {
		ret = -EBUSY;
		goto out;
	}
	base = ioremap(iores->start, resource_size(iores));
	if (!base) {
		ret = -ENOMEM;
		goto out;
	}
	platform_set_drvdata(pdev, lgpio);
	loongson_gpio_init(dev, lgpio, np, base);

	return 0;
out:
	pr_err("%s: %s: missing mandatory property\n", __func__, np->name);
	return ret;
}

static int loongson_gpio_remove(struct platform_device *pdev)
{
	struct loongson_gpio_chip *lgpio = platform_get_drvdata(pdev);
	struct resource		*mem;

	platform_set_drvdata(pdev, NULL);
	gpiochip_remove(&lgpio->chip);
	iounmap(lgpio->base);
	kfree(lgpio->gsi_idx_map);
	kfree(lgpio);
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(mem->start, resource_size(mem));
	return 0;
}

static const struct of_device_id loongson_gpio_dt_ids[] = {
	{ .compatible = "loongson,loongson3-gpio"},
	{ .compatible = "loongson,ls7a-gpio"},
	{}
};
MODULE_DEVICE_TABLE(of, loongson_gpio_dt_ids);

static const struct acpi_device_id loongson_gpio_acpi_match[] = {
	{"LOON0002"},
	{"LOON0007"},
	{}
};
MODULE_DEVICE_TABLE(acpi, loongson_gpio_acpi_match);

static struct platform_driver ls_gpio_driver = {
	.driver = {
		.name = "loongson-gpio",
		.owner	= THIS_MODULE,
		.of_match_table = loongson_gpio_dt_ids,
		.acpi_match_table = ACPI_PTR(loongson_gpio_acpi_match),
	},
	.probe = loongson_gpio_probe,
	.remove = loongson_gpio_remove,
};

static int __init loongson_gpio_setup(void)
{
	return platform_driver_register(&ls_gpio_driver);
}
subsys_initcall(loongson_gpio_setup);

static void __exit loongson_gpio_driver(void)
{
	platform_driver_unregister(&ls_gpio_driver);
}
module_exit(loongson_gpio_driver);
MODULE_AUTHOR("Loongson Technology Corporation Limited");
MODULE_DESCRIPTION("LOONGSON GPIO");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:loongson_gpio");
