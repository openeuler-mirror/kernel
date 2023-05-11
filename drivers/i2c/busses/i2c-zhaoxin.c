// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * i2c-zhaoxin-i2c.c - Zhaoxin I2C controller driver
 *
 * Copyright(c) 2021 Shanghai Zhaoxin Corporation. All rights reserved.
 *
 */

#define DRIVER_VERSION "1.3.0"

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#include <linux/platform_device.h>
#include <linux/pci.h>

#define ZX_I2C_NAME	"Zhaoxin-I2C"

/*
 * registers
 */
/* I2C MMIO Address Constants */
#define IICCR_L                  0x00
#define   MST_RST          BIT(7)
#define   MST_RST_PATCH    BIT(6)
#define   CPU_RDY          BIT(3)
#define   TX_END           BIT(2)
#define   RX_ACK           BIT(1)
#define IICCR_H                  0x01
#define   FIFO_EN          BIT(6)
#define IICSLVADDR               0x02
#define IICTCR                   0x03
#define   FAST_SEL         BIT(7)
#define   MASTER_RECV      BIT(6)
#define   HS_SEL           BIT(5)
#define IICSR                    0x04
#define   SDA_I            BIT(3)
#define   SCL_I            BIT(2)
#define   READY            BIT(1)
#define   RCV_NACK         BIT(0)
#define IICISR                   0x06
#define   IRQ_STS_BYTENACK BIT(5)
#define   IRQ_STS_FIFONACK BIT(4)
#define   IRQ_STS_FIFOEND  BIT(3)
#define   IRQ_SCL_TIMEOUT  BIT(2)
#define   IRQ_STS_BYTEEND  BIT(1)
#define   IRQ_STS_ADDRNACK BIT(0)
#define   IRQ_STS_MASK   (IRQ_STS_FIFOEND | IRQ_SCL_TIMEOUT | \
			IRQ_STS_BYTEEND | IRQ_STS_ADDRNACK)
#define IICIMR                   0x08
#define   IRQ_EN_FIFOEND   BIT(3)
#define   IRQ_EN_TIMEOUT   BIT(2)
#define   IRQ_EN_BYTEEND   BIT(1)
#define   IRQ_EN_ADDRNACK  BIT(0)
#define IICDATA2IIC              0x0A
#define IICDATA2CPU              0x0B
#define IICTR_FSTP               0x0C
#define IICTR_SCLTP              0x0D
#define IICMCR                   0x0E
#define   DYCLK_EN         BIT(0)
#define IIC_MST_CODE             0x0F
#define IICCS                    0x10
#define   CLKSEL_50M       BIT(0)
#define IICREV                   0x11
#define IICHCR                   0x12
#define   FIFO_RST         (BIT(1) | BIT(0))
#define IICHTDR                  0x13
#define IICHRDR                  0x14
#define IICHTLR                  0x15
#define IICHRLR                  0x16
#define IICHWCNTR                0x18
#define IICHRCNTR                0x19

enum {
	STANDARD_MODE_50M = 1,
	STANDARD_MODE_27M,
	FAST_MODE_50M,
	FAST_MODE_27M,
	FAST_PLUSE_MODE_50M,
	FAST_PLUSE_MODE_27M,
	HIGH_SPEED_MODE,
	SPEED_MODE_CNT = HIGH_SPEED_MODE
};

#define FIFO_SIZE	32
#define RETRY_TIME	3

struct zxi2c {
	/* controller resources information */
	struct device    *dev;
	struct pci_dev   *pci;
	struct i2c_adapter adap;
	void __iomem *regs;
	u8 irq;
	const char *bus_uid;
	u8 hrv;		/* Hardware Revision */
	u8 speed_mode;
	unsigned long speed;
	u8 fstp;	/* freq control */

	/* process control information */
	u8 event;
	u16 timeout;
	u16 byte_left;
	wait_queue_head_t waitq;
	u8 retry;
	bool busy;

	/* current msg information */
	u8 addr;
	u16 len;
	bool is_read;
	bool is_last_msg;
	bool dynamic;
};

#define set_byte(r, d)           iowrite8(d, r+IICDATA2IIC)
#define get_byte(r)              ioread8(r+IICDATA2CPU)
#define is_ready(r)              (ioread8(r+IICSR)&READY)
#define is_nack(r)               (ioread8(r+IICSR)&RCV_NACK)
#define get_irq_status(r)        ioread8(r+IICISR)
#define get_reversion(r)         ioread8(r+IICREV)
#define clear_irq_status(r)      iowrite8(IRQ_STS_MASK, r+IICISR)
#define set_fifo_byte(r, d)      iowrite8(d, r+IICHTDR)
#define get_fifo_byte(r)         ioread8(r+IICHRDR)
#define set_fifo_wr_len(r, d)    iowrite8(d, r+IICHTLR)
#define set_fifo_rd_len(r, d)    iowrite8(d, r+IICHRLR)
#define get_fifo_wr_cnt(r)       ioread8(r+IICHWCNTR)
#define get_fifo_rd_cnt(r)       ioread8(r+IICHRCNTR)
#define master_regs_reset(r)     iowrite8(MST_RST|0x41, r+IICCR_L)
#define set_dynamic_clock(r, d)  iowrite8(d, r+IICMCR)
#define get_dynamic_clock(r)     (ioread8(r+IICMCR) & DYCLK_EN)
#define stop_write_byte(r)       iowrite8(TX_END|0x41, r+IICCR_L)
#define get_fstp_value(r)         ioread8(r+IICTR_FSTP)

static inline void zxi2c_prepare_next_read(void __iomem *regs, u16 left)
{
	u8 tmp = ioread8(regs + IICCR_L);

	if (left > 1)
		tmp &= ~RX_ACK;
	else
		tmp |= RX_ACK;

	iowrite8(tmp, regs + IICCR_L);
}

static inline void zxi2c_enable_irq(void __iomem *regs, u8 type, int mode)
{
	if (mode == true)
		iowrite8(IRQ_EN_ADDRNACK | type,
			regs + IICIMR);
	else
		iowrite8(0, regs + IICIMR);
}

static inline void zxi2c_continue(struct zxi2c *i2c)
{
	u8 tmp;

	i2c->event = 0;
	tmp = ioread8(i2c->regs + IICCR_L);
	iowrite8(tmp |= CPU_RDY, i2c->regs + IICCR_L);
}

static void zxi2c_enable_fifo(void __iomem *regs, int mode)
{
	if (mode == true)
		iowrite8(FIFO_EN, regs + IICCR_H);
	else
		iowrite8(0, regs + IICCR_H);
}

static void zxi2c_reset_fifo(void __iomem *regs)
{
	u8 tmp;
	u8 count;

	tmp = ioread8(regs + IICHCR);
	iowrite8(tmp | FIFO_RST, regs + IICHCR);
	for (count = 0; count < 50; count++)
		if (!(ioread8(regs + IICHCR) & FIFO_RST))
			break;
	if (count >= 50)
		pr_err("%s failed\n", __func__);
}

static void zxi2c_set_wr(void __iomem *regs, bool is_read)
{
	u8 tmp;

	tmp = ioread8(regs + IICTCR);
	if (is_read)
		tmp |= MASTER_RECV;
	else
		tmp &= ~MASTER_RECV;
	iowrite8(tmp, regs + IICTCR);
}

static void zxi2c_start(struct zxi2c *i2c)
{
	i2c->event = 0;
	iowrite8(i2c->addr & 0x7f, i2c->regs + IICSLVADDR);
}

static const u8 speed_params_table[SPEED_MODE_CNT][5] = {
	/* speed_mode, IICTCR, IICTR_FSTP, IICCS, IICTR_SCLTP */
	{ STANDARD_MODE_27M, 0, 0x83, 0, 0x80 },
	{ FAST_MODE_27M, FAST_SEL, 0x1e, 0, 0x80 },
	{ FAST_PLUSE_MODE_27M, FAST_SEL, 10, 0, 0x80 },
	{ STANDARD_MODE_50M, 0, 0xF3, CLKSEL_50M, 0xff },
	{ FAST_MODE_50M, FAST_SEL, 0x38, CLKSEL_50M, 0xff },
	{ FAST_PLUSE_MODE_50M, FAST_SEL, 19, CLKSEL_50M, 0xff },
	{ HIGH_SPEED_MODE, HS_SEL, 0x37, CLKSEL_50M, 0xff }

};

static void zxi2c_set_bus_speed(struct zxi2c *i2c)
{
	u8 i;
	const u8 *params = NULL;

	for (i = 0; i < SPEED_MODE_CNT; i++) {
		if (speed_params_table[i][0] == i2c->speed_mode) {
			params = speed_params_table[i];
			break;
		}
	}
	iowrite8(params[1], i2c->regs + IICTCR);
	if (abs(i2c->fstp - params[2]) > 0x10) {
		/* if BIOS setting value far from golden value,
		 * use golden value and warn user */
		dev_warn(i2c->dev,
			"speed:%ld, fstp:0x%x, golden:0x%x\n",
			i2c->speed, i2c->fstp, params[2]);
		iowrite8(params[2], i2c->regs + IICTR_FSTP);
	} else
		iowrite8(i2c->fstp, i2c->regs + IICTR_FSTP);
	iowrite8(params[3], i2c->regs + IICCS);
	iowrite8(params[4], i2c->regs + IICTR_SCLTP);

	/* for Hs-mode, use 0000 1000 as master code */
	if (i2c->speed_mode == HIGH_SPEED_MODE)
		iowrite8(0x08, i2c->regs + IIC_MST_CODE);
}

static void zxi2c_module_reset(struct zxi2c *i2c)
{
	unsigned long uid;
	u8 tmp;
	u8 bit;

	bit = kstrtoul(i2c->bus_uid, 10, &uid) ? 0 : (1 << (4 + uid));

	pci_read_config_byte(i2c->pci, 0x4F, &tmp);
	usleep_range(3000, 5000);
	pci_write_config_byte(i2c->pci, 0x4F, tmp & ~bit);
	usleep_range(3000, 5000);
	pci_write_config_byte(i2c->pci, 0x4F, tmp | bit);
	usleep_range(3000, 5000);

	set_dynamic_clock(i2c->regs, i2c->dynamic);
}

static irqreturn_t zxi2c_irq_handle(int irq, void *dev_id)
{
	struct zxi2c *i2c = (struct zxi2c *)dev_id;
	void __iomem *regs = i2c->regs;
	u8 status = get_irq_status(regs);

	if ((status & IRQ_STS_MASK) == 0)
		return IRQ_NONE;

	if (status & IRQ_SCL_TIMEOUT)
		dev_warn(i2c->dev, "timeout(HW), ID: 0x%X\n", i2c->addr);

	if (status & IRQ_STS_ADDRNACK)
		dev_err(i2c->dev, "addr NACK, ID: 0x%X\n", i2c->addr);
	else if (status & IRQ_STS_BYTEEND) {
		i2c->byte_left--;
		if (!i2c->is_read) {
			if (is_nack(regs)) {
				status = IRQ_STS_BYTENACK;
				i2c->byte_left++;
				dev_err(i2c->dev, "data NACK, ID: 0x%X\n", i2c->addr);
			} else if (i2c->byte_left == 0 && i2c->is_last_msg)
				stop_write_byte(regs);
		}
	}

	i2c->event = status;
	clear_irq_status(regs);
	wake_up(&i2c->waitq);

	return IRQ_HANDLED;
}

static int zxi2c_wait_event(struct zxi2c *i2c, u8 event)
{
	int timeout;

	timeout = wait_event_interruptible_timeout(i2c->waitq, i2c->event != 0,
					msecs_to_jiffies(i2c->timeout));

	if (timeout == 0) {
		dev_err(i2c->dev, "timeout(SW), ID: 0x%X\n", i2c->addr);
		/* Clock streching timeout, do recovery */
		if (!is_nack(i2c->regs))
			dev_err(i2c->dev, "device hang? pls reset, ID: 0x%X\n", i2c->addr);

		master_regs_reset(i2c->regs);
		zxi2c_set_bus_speed(i2c);
		return -ENODEV;
	} else if ((i2c->event & event) == 0) {
		/* device NACK and so on, already print in interrupt */
		return -ENODEV;
	}
	return 0;
}

static int zxi2c_byte_xfer(struct zxi2c *i2c, struct i2c_msg *msgs, int num)
{
	u16 i, finished;
	int error;
	u8 index, ret = 0;
	struct i2c_msg *msg;
	void __iomem *regs = i2c->regs;

	clear_irq_status(regs);
	zxi2c_enable_fifo(regs, false);
	zxi2c_enable_irq(regs, IRQ_EN_BYTEEND, true);

	for (index = 0; index < num; index++) {
		msg = msgs + index;

		i2c->addr = msg->addr;
		i2c->is_read = !!(msg->flags & I2C_M_RD);
		i2c->byte_left = i2c->len = msg->len;

		zxi2c_set_wr(regs, i2c->is_read);
		if (i2c->is_read) {
			zxi2c_prepare_next_read(regs, i2c->byte_left);
			zxi2c_start(i2c);
			/* create restart for non-first msg*/
			if (index)
				zxi2c_continue(i2c);

			for (i = 1; i <= msg->len; i++) {
				error = zxi2c_wait_event(i2c, IRQ_STS_BYTEEND);
				if (error)
					break;

				msg->buf[i - 1] = get_byte(regs);
				if (i2c->byte_left == 0)
					break;

				zxi2c_prepare_next_read(regs, i2c->byte_left);
				zxi2c_continue(i2c);
			}
		} else {
			set_byte(regs, msg->buf[0]);
			/* mark whether this is the last msg */
			i2c->is_last_msg = index == !!(num - 1);
			zxi2c_start(i2c);
			/* create restart for non-first msg */
			if (index)
				zxi2c_continue(i2c);

			for (i = 1; i <= msg->len; i++) {
				error = zxi2c_wait_event(i2c, IRQ_STS_BYTEEND);
				if (error)
					break;

				if (i2c->byte_left == 0)
					break;
				set_byte(regs, msg->buf[i]);
				zxi2c_continue(i2c);
			}
		}

		if (error) {
			finished = msg->len - i2c->byte_left;

			/* check if NACK during transmitting */
			if (finished)
				dev_err(i2c->dev,
					"%s: %s finished %d bytes: %*ph\n",
					__func__, i2c->is_read ? "read" : "write",
					finished, finished, msg->buf);
			return error;
		}
		ret++;
	}

	zxi2c_enable_irq(regs, IRQ_EN_BYTEEND, false);
	return ret;
}

static int zxi2c_fifo_xfer(struct zxi2c *i2c, struct i2c_msg *msgs)
{
	void __iomem *regs = i2c->regs;
	struct i2c_msg *msg = msgs;
	int i;
	u8 finished;

	i2c->addr = msg->addr;
	i2c->is_read = !!(msg->flags & I2C_M_RD);
	i2c->len = msg->len;

	zxi2c_reset_fifo(regs);
	zxi2c_enable_fifo(regs, true);

	clear_irq_status(regs);
	zxi2c_enable_irq(regs, IRQ_EN_FIFOEND, true);

	zxi2c_set_wr(regs, i2c->is_read);
	if (i2c->is_read)
		set_fifo_rd_len(regs, msg->len - 1);
	else {
		set_fifo_wr_len(regs, msg->len - 1);
		for (i = 0; i < msg->len; i++)
			set_fifo_byte(regs, msg->buf[i]);
	}

	zxi2c_start(i2c);
	if (zxi2c_wait_event(i2c, IRQ_STS_FIFOEND))
		return -ENODEV;

	if (i2c->is_read) {
		finished = get_fifo_rd_cnt(regs);
		for (i = 0; i < finished; i++)
			msg->buf[i] = get_fifo_byte(regs);
	} else
		finished = get_fifo_wr_cnt(regs);

	/* check if NACK during transmitting */
	if (finished != msg->len) {
		if (finished)
			dev_err(i2c->dev,
				"%s: %s only finished %d/%d bytes: %*ph\n",
				__func__, i2c->is_read ? "read" : "write",
				finished, msg->len, finished, msg->buf);
		return -EAGAIN;
	}

	zxi2c_enable_irq(regs, IRQ_EN_FIFOEND, false);
	return 1;
}

static int zxi2c_master_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
	struct zxi2c *i2c;
	int ret;

	i2c = (struct zxi2c *)i2c_get_adapdata(adap);
	if (!is_ready(i2c->regs)) {
		if (i2c->busy == false) {
			zxi2c_module_reset(i2c);
			zxi2c_set_bus_speed(i2c);
			dev_dbg(i2c->dev, "not ready, reset and retry\n");
		}
		if (i2c->retry >= RETRY_TIME) {
			dev_err(i2c->dev, "retried %d times, dropped\n", i2c->retry);
			i2c->retry = 0;
		} else
			i2c->retry++;
		return -EAGAIN;
	}
	i2c->retry = 0;
	i2c->busy = true;
	i2c->timeout = 1000;

	/* Freedom mode */
	if (num == 1 && msgs->len <= FIFO_SIZE && msgs->len >= 3)
		ret = zxi2c_fifo_xfer(i2c, msgs);
	else
		ret = zxi2c_byte_xfer(i2c, msgs, num);

	i2c->busy = false;
	return ret;
}

static u32 zxi2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm zxi2c_algorithm = {
	.master_xfer	= zxi2c_master_xfer,
	.functionality	= zxi2c_func,
};

static const struct i2c_adapter_quirks zxi2c_quirks = {
	.flags = I2C_AQ_NO_ZERO_LEN | I2C_AQ_COMB_WRITE_THEN_READ,
};

static void zxi2c_get_speed_mode(struct zxi2c *i2c)
{
	u32 speed = 400000;

	speed = i2c_acpi_find_bus_speed(i2c->dev);
	if (speed >= 3400000)
		i2c->speed_mode = HIGH_SPEED_MODE;
	else if (speed >= 1000000)
		i2c->speed_mode = FAST_PLUSE_MODE_50M;
	else if (speed >= 400000)
		i2c->speed_mode = FAST_MODE_50M;
	else if (speed >= 100000)
		i2c->speed_mode = STANDARD_MODE_50M;
	else
		i2c->speed_mode = FAST_MODE_50M;
	i2c->speed = speed;
}

static int zxi2c_parse_resources(struct zxi2c *i2c)
{
	struct resource *res;
	struct platform_device *pdev = to_platform_device(i2c->dev);
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);

	/* get IO resource */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (IS_ERR(res)) {
		dev_err(&pdev->dev, "IORESOURCE_MEM failed\n");
		return -ENODEV;
	}
	i2c->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(i2c->regs)) {
		dev_err(&pdev->dev, "devm ioremap failed\n");
		return -ENOMEM;
	}

	/* get irq */
	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (IS_ERR(res)) {
		dev_err(&pdev->dev, "get IORESOURCE_IRQ failed\n");
		return -ENODEV;
	}
	i2c->irq = res->start;

	/* get _UID */
	i2c->bus_uid = adev->pnp.unique_id;
	if (!i2c->bus_uid) {
		dev_err(&pdev->dev, "missing/incorrect UID/bus id!\n");
		return -ENODEV;
	}

	/* get speed */
	zxi2c_get_speed_mode(i2c);

	return 0;
}

static int zxi2c_probe(struct platform_device *pdev)
{
	int error;
	struct zxi2c *i2c;
	struct pci_dev *pci;
	struct device *dev;

	dev = pdev->dev.parent;
	if (dev && dev_is_pci(dev)) {
		pci = to_pci_dev(dev);
		if (pci->vendor != 0x1d17 || pci->device != 0x1001)
			return -ENODEV;
	} else
		return -ENODEV;

	i2c = devm_kzalloc(&pdev->dev, sizeof(*i2c), GFP_KERNEL);
	if (IS_ERR(i2c)) {
		dev_err(&pdev->dev, "devm_kzalloc FAILED\n");
		return -ENOMEM;
	}

	i2c->dev = &pdev->dev;
	error = zxi2c_parse_resources(i2c);
	if (error)
		return error;

	i2c->pci = pci;
	i2c->hrv = get_reversion(i2c->regs);

	platform_set_drvdata(pdev, (void *)i2c);

	if (devm_request_irq(&pdev->dev, i2c->irq, zxi2c_irq_handle, IRQF_SHARED,
			pdev->name, i2c)) {
		dev_err(i2c->dev, "i2c IRQ%d allocate failed.\n", i2c->irq);
		return -ENODEV;
	}

	init_waitqueue_head(&i2c->waitq);
	i2c->retry = 0;
	i2c->busy = false;

	i2c->adap.owner = THIS_MODULE;
	i2c->adap.algo = &zxi2c_algorithm;
	i2c->adap.class = I2C_CLASS_HWMON | I2C_CLASS_SPD;
	i2c->adap.retries = RETRY_TIME + 1;
	i2c->adap.quirks = &zxi2c_quirks;

	i2c->adap.owner = THIS_MODULE;
	i2c->adap.dev.parent = &pdev->dev;
	ACPI_COMPANION_SET(&i2c->adap.dev, ACPI_COMPANION(&pdev->dev));
	snprintf(i2c->adap.name, sizeof(i2c->adap.name), "%s.%s", ZX_I2C_NAME, i2c->bus_uid);
	i2c_set_adapdata(&i2c->adap, i2c);

	i2c->dynamic = get_dynamic_clock(i2c->regs);
	set_dynamic_clock(i2c->regs, i2c->dynamic);
	i2c->fstp = get_fstp_value(i2c->regs);
	zxi2c_set_bus_speed(i2c);

	error = i2c_add_adapter(&i2c->adap);
	if (unlikely(error)) {
		dev_err(i2c->dev, "failed to register i2c, err: %d\n", error);
		return error;
	}

	dev_info(i2c->dev, "Adapter %s registered at /dev/i2c-%d\n", i2c->adap.name, i2c->adap.nr);

	return 0;
}

static int zxi2c_remove(struct platform_device *pdev)
{
	struct zxi2c *i2c = platform_get_drvdata(pdev);

	zxi2c_module_reset(i2c);
	master_regs_reset(i2c->regs);

	devm_free_irq(&pdev->dev, i2c->irq, i2c);

	i2c_del_adapter(&i2c->adap);

	platform_set_drvdata(pdev, NULL);
	devm_kfree(&pdev->dev, i2c);

	dev_info(&pdev->dev, "i2c adapter unregistered.\n");

	return 0;
}

static int zxi2c_suspend(struct device *dev)
{
	return 0;
}

static int zxi2c_resume(struct device *dev)
{
	struct zxi2c *i2c = dev_get_drvdata(dev);

	zxi2c_module_reset(i2c);
	zxi2c_set_bus_speed(i2c);

	return 0;
}

const struct dev_pm_ops zxi2c_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(zxi2c_suspend, zxi2c_resume)
};

static const struct acpi_device_id zxi2c_acpi_match[] = {
	{"IIC1D17", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, zxi2c_acpi_match);

static struct platform_driver zxi2c_driver = {
	.probe   = zxi2c_probe,
	.remove  = zxi2c_remove,
	.driver  = {
		.name = ZX_I2C_NAME,
		.owner = THIS_MODULE,
		.acpi_match_table = ACPI_PTR(zxi2c_acpi_match),
		.pm = &zxi2c_pm,
	},
};

module_platform_driver(zxi2c_driver);

MODULE_AUTHOR("HansHu@zhaoxin.com");
MODULE_DESCRIPTION("Shanghai Zhaoxin IIC driver");
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
