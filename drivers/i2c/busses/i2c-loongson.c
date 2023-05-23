// SPDX-License-Identifier: GPL-2.0
/*
 * Loongson-7A I2C master mode driver
 *
 * Copyright (C) 2013 Loongson Technology Corporation Limited
 * Copyright (C) 2014-2017 Lemote, Inc.
 *
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/slab.h>

#define DRIVER_NAME "loongson_i2c"

#define LOONGSON_I2C_PRER_LO_REG	0x0
#define LOONGSON_I2C_PRER_HI_REG	0x1
#define LOONGSON_I2C_CTR_REG	0x2
#define LOONGSON_I2C_TXR_REG	0x3
#define LOONGSON_I2C_RXR_REG	0x3
#define LOONGSON_I2C_CR_REG		0x4
#define LOONGSON_I2C_SR_REG		0x4
#define LOONGSON_I2C_BLTOP_REG	0x5
#define LOONGSON_I2C_SADDR_REG	0x7

#define CTR_EN			0x80
#define CTR_IEN			0x40
#define CTR_TXROK		0x90
#define CTR_RXROK		0x88

#define CR_START		0x81
#define CR_STOP			0x41
#define CR_READ			0x21
#define CR_WRITE		0x11
#define CR_ACK			0x8
#define CR_IACK			0x1

#define SR_NOACK		0x80
#define SR_BUSY			0x40
#define SR_AL			0x20
#define SR_SLAVE_ADDRESSED	0x10
#define SR_SLAVE_RW		0x8
#define SR_TIP			0x2
#define SR_IF			0x1

#define i2c_readb(addr)		readb(dev->base + addr)
#define i2c_writeb(val, addr)	writeb(val, dev->base + addr)

#ifdef LOONGSON_I2C_DEBUG
#define i2c_debug(fmt, args...)	printk(KERN_CRIT fmt, ##args)
#else
#define i2c_debug(fmt, args...)
#endif

static bool repeated_start = 1;
module_param(repeated_start, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(repeated_start, "Compatible with devices that support repeated start");

enum loongson_i2c_slave_state {
	LOONGSON_I2C_SLAVE_STOP,
	LOONGSON_I2C_SLAVE_START,
	LOONGSON_I2C_SLAVE_READ_REQUESTED,
	LOONGSON_I2C_SLAVE_READ_PROCESSED,
	LOONGSON_I2C_SLAVE_WRITE_REQUESTED,
	LOONGSON_I2C_SLAVE_WRITE_RECEIVED,
};

struct loongson_i2c_dev {
	spinlock_t		lock;
	unsigned int		suspended:1;
	struct device		*dev;
	void __iomem		*base;
	int			irq;
	struct completion	cmd_complete;
	struct resource		*ioarea;
	struct i2c_adapter	adapter;
#if IS_ENABLED(CONFIG_I2C_SLAVE)
	struct i2c_client	*slave;
	enum loongson_i2c_slave_state	slave_state;
#endif /* CONFIG_I2C_SLAVE */
};

static int i2c_stop(struct loongson_i2c_dev *dev)
{
	unsigned long time_left;

again:
	i2c_writeb(CR_STOP, LOONGSON_I2C_CR_REG);
	time_left = wait_for_completion_timeout(
		&dev->cmd_complete,
		(&dev->adapter)->timeout);
	if (!time_left) {
		pr_info("Timeout abort message cmd\n");
		return -1;
	}

	i2c_readb(LOONGSON_I2C_SR_REG);
	while (i2c_readb(LOONGSON_I2C_SR_REG) & SR_BUSY)
		goto again;

	return 0;
}

static int i2c_start(struct loongson_i2c_dev *dev,
		int dev_addr, int flags)
{
	unsigned long time_left;
	int retry = 5;
	unsigned char addr = (dev_addr & 0x7f) << 1;
	addr |= (flags & I2C_M_RD)? 1:0;

start:
	mdelay(1);
	i2c_writeb(addr, LOONGSON_I2C_TXR_REG);
	i2c_debug("%s <line%d>: i2c device address: 0x%x\n",
			__func__, __LINE__, addr);
	i2c_writeb((CR_START | CR_WRITE), LOONGSON_I2C_CR_REG);
	time_left = wait_for_completion_timeout(
		&dev->cmd_complete,
		(&dev->adapter)->timeout);
	if (!time_left) {
		pr_info("Timeout abort message cmd\n");
		return -1;
	}

	if (i2c_readb(LOONGSON_I2C_SR_REG) & SR_NOACK) {
		if (i2c_stop(dev) < 0)
			return -1;
		while (retry--)
			goto start;
		pr_debug("There is no i2c device ack\n");
		return 0;
	}
	return 1;
}

#if IS_ENABLED(CONFIG_I2C_SLAVE)
static void __loongson_i2c_reg_slave(struct loongson_i2c_dev *dev, u16 slave_addr)
{
	/* Set slave addr. */
	i2c_writeb(slave_addr & 0x7f, LOONGSON_I2C_SADDR_REG);

	/* Turn on slave mode. */
	i2c_writeb(0xc0, LOONGSON_I2C_CTR_REG);
}

static int loongson_i2c_reg_slave(struct i2c_client *client)
{
	struct loongson_i2c_dev *dev = i2c_get_adapdata(client->adapter);
	unsigned long flags;

	if (dev->slave) {
		return -EINVAL;
	}

	__loongson_i2c_reg_slave(dev, client->addr);

	dev->slave = client;
	dev->slave_state = LOONGSON_I2C_SLAVE_STOP;

	return 0;
}

static int loongson_i2c_unreg_slave(struct i2c_client *client)
{
	struct loongson_i2c_dev *dev = i2c_get_adapdata(client->adapter);
	unsigned long flags;

	if (!dev->slave) {
		return -EINVAL;
	}

	/* Turn off slave mode. */
	i2c_writeb(0xa0, LOONGSON_I2C_CTR_REG);

	dev->slave = NULL;

	return 0;
}
#endif /* CONFIG_I2C_SLAVE */

static void loongson_i2c_reginit(struct loongson_i2c_dev *dev)
{
#if IS_ENABLED(CONFIG_I2C_SLAVE)
	if (dev->slave) {
		__loongson_i2c_reg_slave(dev, dev->slave->addr);
		return;
	}
#endif /* CONFIG_I2C_SLAVE */
	i2c_writeb(i2c_readb(LOONGSON_I2C_CR_REG) | 0x01, LOONGSON_I2C_CR_REG);
	i2c_writeb(i2c_readb(LOONGSON_I2C_CTR_REG) & ~0x80, LOONGSON_I2C_CTR_REG);
	i2c_writeb(0x2c, LOONGSON_I2C_PRER_LO_REG);
	i2c_writeb(0x1, LOONGSON_I2C_PRER_HI_REG);
	i2c_writeb(i2c_readb(LOONGSON_I2C_CTR_REG) | 0xe0, LOONGSON_I2C_CTR_REG);
}

static int i2c_read(struct loongson_i2c_dev *dev,
		unsigned char *buf, int count)
{
	int i;
	unsigned long time_left;

	for (i = 0; i < count; i++) {
		i2c_writeb((i == count - 1)?
				(CR_READ | CR_ACK) : CR_READ,
				LOONGSON_I2C_CR_REG);
		time_left = wait_for_completion_timeout(
			&dev->cmd_complete,
			(&dev->adapter)->timeout);
		if (!time_left) {
			pr_info("Timeout abort message cmd\n");
			return -1;
		}

		buf[i] = i2c_readb(LOONGSON_I2C_RXR_REG);
		i2c_debug("%s <line%d>: read buf[%d] <= %02x\n",
				__func__, __LINE__, i, buf[i]);
        }

        return i;
}

static int i2c_write(struct loongson_i2c_dev *dev,
		unsigned char *buf, int count)
{
        int i;
	unsigned long time_left;

        for (i = 0; i < count; i++) {
		i2c_writeb(buf[i], LOONGSON_I2C_TXR_REG);
		i2c_debug("%s <line%d>: write buf[%d] => %02x\n",
				__func__, __LINE__, i, buf[i]);
		i2c_writeb(CR_WRITE, LOONGSON_I2C_CR_REG);
		time_left = wait_for_completion_timeout(
			&dev->cmd_complete,
			(&dev->adapter)->timeout);
		if (!time_left) {
			pr_info("Timeout abort message cmd\n");
			return -1;
		}

		if (i2c_readb(LOONGSON_I2C_SR_REG) & SR_NOACK) {
			i2c_debug("%s <line%d>: device no ack\n",
					__func__, __LINE__);
			if (i2c_stop(dev) < 0)
				return -1;
			return 0;
		}
        }

        return i;
}

static int i2c_doxfer(struct loongson_i2c_dev *dev,
		struct i2c_msg *msgs, int num)
{
	struct i2c_msg *m = msgs;
	int i, err;

	for (i = 0; i < num; i++) {
		reinit_completion(&dev->cmd_complete);
		err = i2c_start(dev, m->addr, m->flags);
		if (err <= 0)
			return err;

		if (m->flags & I2C_M_RD) {
			if (i2c_read(dev, m->buf, m->len) < 0)
				return -1;
		} else {
			if (i2c_write(dev, m->buf, m->len) < 0)
				return -1;
		}
		++m;
		if (!repeated_start && i2c_stop(dev) < 0)
			return -1;
	}
	if (repeated_start && i2c_stop(dev) < 0)
		return -1;
	return i;
}

static int i2c_xfer(struct i2c_adapter *adap,
                        struct i2c_msg *msgs, int num)
{
	int ret;
	int retry;
	struct loongson_i2c_dev *dev;

	dev = i2c_get_adapdata(adap);
	for (retry = 0; retry < adap->retries; retry++) {
		ret = i2c_doxfer(dev, msgs, num);
		if (ret != -EAGAIN)
			return ret;

		udelay(100);
	}

	return -EREMOTEIO;
}

static unsigned int i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm loongson_i2c_algo = {
	.master_xfer	= i2c_xfer,
	.functionality	= i2c_func,
#if IS_ENABLED(CONFIG_I2C_SLAVE)
	.reg_slave	= loongson_i2c_reg_slave,
	.unreg_slave	= loongson_i2c_unreg_slave,
#endif /* CONFIG_I2C_SLAVE */
};

#if IS_ENABLED(CONFIG_I2C_SLAVE)
static bool loongson_i2c_slave_irq(struct loongson_i2c_dev *dev)
{
	u32 stat;
	struct i2c_client *slave = dev->slave;
	u8 value;

	stat = i2c_readb(LOONGSON_I2C_SR_REG);

	/* Slave was requested, restart state machine. */
	if (stat & SR_SLAVE_ADDRESSED) {
		dev->slave_state = LOONGSON_I2C_SLAVE_START;
		i2c_writeb(CTR_RXROK | CTR_IEN, LOONGSON_I2C_CTR_REG);
	}

	/* Slave is not currently active, irq was for someone else. */
	if (dev->slave_state == LOONGSON_I2C_SLAVE_STOP) {
		return IRQ_NONE;
	}

	/* Handle address frame. */
	if (dev->slave_state == LOONGSON_I2C_SLAVE_START) {
		if (stat & SR_SLAVE_RW)	//slave be read
			dev->slave_state =
				LOONGSON_I2C_SLAVE_READ_REQUESTED;
		else
			dev->slave_state =
				LOONGSON_I2C_SLAVE_WRITE_REQUESTED;
	}

	/* Slave was asked to stop. */
	if (stat & SR_NOACK) {
		dev->slave_state = LOONGSON_I2C_SLAVE_STOP;
	}

	value = i2c_readb(LOONGSON_I2C_RXR_REG);
	switch (dev->slave_state) {
	case LOONGSON_I2C_SLAVE_READ_REQUESTED:
		dev->slave_state = LOONGSON_I2C_SLAVE_READ_PROCESSED;
		i2c_slave_event(slave, I2C_SLAVE_READ_REQUESTED, &value);
		i2c_writeb(value, LOONGSON_I2C_TXR_REG);
		i2c_writeb(CTR_TXROK | CTR_IEN, LOONGSON_I2C_CTR_REG);
		break;
	case LOONGSON_I2C_SLAVE_READ_PROCESSED:
		i2c_slave_event(slave, I2C_SLAVE_READ_PROCESSED, &value);
		i2c_writeb(value, LOONGSON_I2C_TXR_REG);
		i2c_writeb(CTR_TXROK | CTR_IEN, LOONGSON_I2C_CTR_REG);
		break;
	case LOONGSON_I2C_SLAVE_WRITE_REQUESTED:
		dev->slave_state = LOONGSON_I2C_SLAVE_WRITE_RECEIVED;
		i2c_slave_event(slave, I2C_SLAVE_WRITE_REQUESTED, &value);
		break;
	case LOONGSON_I2C_SLAVE_WRITE_RECEIVED:
		i2c_slave_event(slave, I2C_SLAVE_WRITE_RECEIVED, &value);
		i2c_writeb(CTR_RXROK | CTR_IEN, LOONGSON_I2C_CTR_REG);
		break;
	case LOONGSON_I2C_SLAVE_STOP:
		i2c_slave_event(slave, I2C_SLAVE_STOP, &value);
		i2c_writeb(0, LOONGSON_I2C_TXR_REG);
		i2c_writeb(CTR_TXROK | CTR_IEN, LOONGSON_I2C_CTR_REG);
		break;
	default:
		dev_err(dev->dev, "unhandled slave_state: %d\n",
			dev->slave_state);
		break;
	}

out:
	return IRQ_HANDLED;
}
#endif /* CONFIG_I2C_SLAVE */

/*
 * Interrupt service routine. This gets called whenever an I2C interrupt
 * occurs.
 */
static irqreturn_t i2c_loongson_isr(int this_irq, void *dev_id)
{
	unsigned char iflag;
	struct loongson_i2c_dev *dev = dev_id;

	iflag = i2c_readb(LOONGSON_I2C_SR_REG);

	if (iflag & SR_IF) {
		i2c_writeb(CR_IACK, LOONGSON_I2C_CR_REG);
#if IS_ENABLED(CONFIG_I2C_SLAVE)
		if (dev->slave) {
			loongson_i2c_slave_irq(dev);
		}
#endif
		if (!(iflag & SR_TIP))
			complete(&dev->cmd_complete);
	} else
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static int loongson_i2c_probe(struct platform_device *pdev)
{
	struct loongson_i2c_dev	*dev;
	struct i2c_adapter	*adap;
	struct resource		*mem, *ioarea;
	int r, irq;

	/* NOTE: driver uses the static register mapping */
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		dev_err(&pdev->dev, "no mem resource?\n");
		return -ENODEV;
	}
	irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev, "no irq resource?\n");
		return -ENODEV;
	}

	ioarea = request_mem_region(mem->start, resource_size(mem),
			pdev->name);
	if (!ioarea) {
		dev_err(&pdev->dev, "I2C region already claimed\n");
		return -EBUSY;
	}

	dev = kzalloc(sizeof(struct loongson_i2c_dev), GFP_KERNEL);
	if (!dev) {
		r = -ENOMEM;
		goto err_release_region;
	}

	init_completion(&dev->cmd_complete);

	dev->dev = &pdev->dev;
	dev->irq = irq;
	dev->base = ioremap(mem->start, resource_size(mem));
	if (!dev->base) {
		r = -ENOMEM;
		goto err_free_mem;
	}

	platform_set_drvdata(pdev, dev);

	loongson_i2c_reginit(dev);

	r = request_irq(dev->irq, i2c_loongson_isr, IRQF_SHARED, DRIVER_NAME, dev);
	if (r)
		dev_err(&pdev->dev, "failure requesting irq %i\n", dev->irq);

	adap = &dev->adapter;
	i2c_set_adapdata(adap, dev);
	adap->nr = pdev->id;
	strlcpy(adap->name, pdev->name, sizeof(adap->name));
	adap->owner = THIS_MODULE;
	adap->class = I2C_CLASS_HWMON;
	adap->retries = 5;
	adap->algo = &loongson_i2c_algo;
	adap->dev.parent = &pdev->dev;
	adap->dev.of_node = pdev->dev.of_node;
	ACPI_COMPANION_SET(&adap->dev, ACPI_COMPANION(&pdev->dev));
	adap->timeout = msecs_to_jiffies(100);

	/* i2c device drivers may be active on return from add_adapter() */
	r = i2c_add_adapter(adap);
	if (r) {
		dev_err(dev->dev, "failure adding adapter\n");
		goto err_iounmap;
	}

	return 0;

err_iounmap:
	iounmap(dev->base);
err_free_mem:
	platform_set_drvdata(pdev, NULL);
	kfree(dev);
err_release_region:
	release_mem_region(mem->start, resource_size(mem));

	return r;
}

static int loongson_i2c_remove(struct platform_device *pdev)
{
	struct loongson_i2c_dev	*dev = platform_get_drvdata(pdev);
	struct resource		*mem;

	platform_set_drvdata(pdev, NULL);
	i2c_del_adapter(&dev->adapter);
	free_irq(dev->irq, dev);
	iounmap(dev->base);
	kfree(dev);
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(mem->start, resource_size(mem));
	return 0;
}

#ifdef CONFIG_PM
static int loongson_i2c_suspend_noirq(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct loongson_i2c_dev *i2c_dev = platform_get_drvdata(pdev);

	i2c_dev->suspended = 1;

	return 0;
}

static int loongson_i2c_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct loongson_i2c_dev *i2c_dev = platform_get_drvdata(pdev);

	i2c_dev->suspended = 0;
	loongson_i2c_reginit(i2c_dev);

	return 0;
}

static const struct dev_pm_ops loongson_i2c_dev_pm_ops = {
	.suspend_noirq	= loongson_i2c_suspend_noirq,
	.resume		= loongson_i2c_resume,
};

#define LOONGSON_DEV_PM_OPS (&loongson_i2c_dev_pm_ops)
#else
#define LOONGSON_DEV_PM_OPS NULL
#endif

#ifdef CONFIG_OF
static struct of_device_id loongson_i2c_id_table[] = {
	{.compatible = "loongson,ls7a-i2c"},
	{},
};
MODULE_DEVICE_TABLE(of, loongson_i2c_id_table);
#endif
static const struct acpi_device_id loongson_i2c_acpi_match[] = {
	{"LOON0004"},
	{}
};
MODULE_DEVICE_TABLE(acpi, loongson_i2c_acpi_match);

static struct platform_driver loongson_i2c_driver = {
	.probe		= loongson_i2c_probe,
	.remove		= loongson_i2c_remove,
	.driver		= {
		.name	= "loongson-i2c",
		.owner	= THIS_MODULE,
		.pm	= LOONGSON_DEV_PM_OPS,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(loongson_i2c_id_table),
#endif
		.acpi_match_table = ACPI_PTR(loongson_i2c_acpi_match),
	},
};

static int __init loongson_i2c_init_driver(void)
{
	return platform_driver_register(&loongson_i2c_driver);
}
subsys_initcall(loongson_i2c_init_driver);

static void __exit loongson_i2c_exit_driver(void)
{
	platform_driver_unregister(&loongson_i2c_driver);
}
module_exit(loongson_i2c_exit_driver);

MODULE_AUTHOR("Loongson Technology Corporation Limited");
MODULE_DESCRIPTION("Loongson LOONGSON I2C bus adapter");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:loongson-i2c");
