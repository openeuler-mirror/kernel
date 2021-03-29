// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Kylin Tech. Co., Ltd.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/acpi.h>
#include <linux/spi/spi.h>

#include "tcm.h"

static int is_ft_all(void) {
	return 0;
}

#define TCM_HEADER_SIZE 10

static bool tcm_debug;
module_param_named(debug, tcm_debug, bool, 0600);
MODULE_PARM_DESC(debug, "Turn TCM debugging mode on and off");

#define tcm_dbg(fmt, args...)	\
{					\
	if (tcm_debug)		\
		pr_err(fmt, ## args);	\
}

enum tis_access {
	TCM_ACCESS_VALID = 0x80,
	TCM_ACCESS_ACTIVE_LOCALITY = 0x20,
	TCM_ACCESS_REQUEST_PENDING = 0x04,
	TCM_ACCESS_REQUEST_USE = 0x02,
};

enum tis_status {
	TCM_STS_VALID = 0x80,
	TCM_STS_COMMAND_READY = 0x40,
	TCM_STS_GO = 0x20,
	TCM_STS_DATA_AVAIL = 0x10,
	TCM_STS_DATA_EXPECT = 0x08,
};

enum tis_int_flags {
	TCM_GLOBAL_INT_ENABLE = 0x80000000,
	TCM_INTF_BURST_COUNT_STATIC = 0x100,
	TCM_INTF_CMD_READY_INT = 0x080,
	TCM_INTF_INT_EDGE_FALLING = 0x040,
	TCM_INTF_INT_EDGE_RISING = 0x020,
	TCM_INTF_INT_LEVEL_LOW = 0x010,
	TCM_INTF_INT_LEVEL_HIGH = 0x008,
	TCM_INTF_LOCALITY_CHANGE_INT = 0x004,
	TCM_INTF_STS_VALID_INT = 0x002,
	TCM_INTF_DATA_AVAIL_INT = 0x001,
};

enum tis_defaults {
	TIS_SHORT_TIMEOUT = 750,	/* ms */
	TIS_LONG_TIMEOUT = 2000,	/* 2 sec */
};

#define	TCM_ACCESS(l)			(0x0000 | ((l) << 12))
#define	TCM_INT_ENABLE(l)		(0x0008 | ((l) << 12)) /* interperet */
#define	TCM_INT_VECTOR(l)		(0x000C | ((l) << 12))
#define	TCM_INT_STATUS(l)		(0x0010 | ((l) << 12))
#define	TCM_INTF_CAPS(l)		(0x0014 | ((l) << 12))
#define	TCM_STS(l)				(0x0018 | ((l) << 12))
#define	TCM_DATA_FIFO(l)		(0x0024 | ((l) << 12))

#define	TCM_DID_VID(l)			(0x0F00 | ((l) << 12))
#define	TCM_RID(l)				(0x0F04 | ((l) << 12))

#define TIS_MEM_BASE_huawei     0x3fed40000LL

#define MAX_SPI_FRAMESIZE 64

//
#define _CPU_FT2000A4
#define REUSE_CONF_REG_BASE		0x28180208
#define REUSE_GPIO1_A5_BASE		0x28005000

static void *__iomem reuse_conf_reg;
static void *__iomem gpio1_a5;

//
static LIST_HEAD(tis_chips);
static DEFINE_SPINLOCK(tis_lock);

struct chip_data {
	u8 cs;
	u8 tmode;
	u8 type;
	u8 poll_mode;
	u16 clk_div;
	u32 speed_hz;
	void (*cs_control)(u32 command);
};

struct tcm_tis_spi_phy {
	struct spi_device *spi_device;
	struct completion ready;
	u8 *iobuf;
};

int tcm_tis_spi_transfer(struct device *dev, u32 addr, u16 len,
		u8 *in, const u8 *out)
{
	struct tcm_tis_spi_phy *phy = dev_get_drvdata(dev);
	int ret = 0;
	struct spi_message m;
	struct spi_transfer spi_xfer;
	u8 transfer_len;

	tcm_dbg("TCM-dbg: %s, addr: 0x%x, len: %x, %s\n",
			__func__, addr, len, (in) ? "in" : "out");

	spi_bus_lock(phy->spi_device->master);

	/* set gpio1_a5 to LOW */
	if (is_ft_all() && (phy->spi_device->chip_select == 0)) {
		iowrite32(0x0, gpio1_a5);
	}

	while (len) {
		transfer_len = min_t(u16, len, MAX_SPI_FRAMESIZE);

		phy->iobuf[0] = (in ? 0x80 : 0) | (transfer_len - 1);
		phy->iobuf[1] = 0xd4;
		phy->iobuf[2] = addr >> 8;
		phy->iobuf[3] = addr;

		memset(&spi_xfer, 0, sizeof(spi_xfer));
		spi_xfer.tx_buf = phy->iobuf;
		spi_xfer.rx_buf = phy->iobuf;
		spi_xfer.len = 4;
		spi_xfer.cs_change = 1;

		spi_message_init(&m);
		spi_message_add_tail(&spi_xfer, &m);
		ret = spi_sync_locked(phy->spi_device, &m);
		if (ret < 0)
			goto exit;

		spi_xfer.cs_change = 0;
		spi_xfer.len = transfer_len;
		spi_xfer.delay_usecs = 5;

		if (in) {
			spi_xfer.tx_buf = NULL;
		} else if (out) {
			spi_xfer.rx_buf = NULL;
			memcpy(phy->iobuf, out, transfer_len);
			out += transfer_len;
		}

		spi_message_init(&m);
		spi_message_add_tail(&spi_xfer, &m);
		reinit_completion(&phy->ready);
		ret = spi_sync_locked(phy->spi_device, &m);
		if (ret < 0)
			goto exit;

		if (in) {
			memcpy(in, phy->iobuf, transfer_len);
			in += transfer_len;
		}

		len -= transfer_len;
	}

exit:
	/* set gpio1_a5 to HIGH */
	if (is_ft_all() && (phy->spi_device->chip_select == 0)) {
		iowrite32(0x20, gpio1_a5);
	}

	spi_bus_unlock(phy->spi_device->master);
	tcm_dbg("TCM-dbg: ret: %d\n", ret);
	return ret;
}

static int tcm_tis_read8(struct device *dev,
		u32 addr, u16 len, u8 *result)
{
	return tcm_tis_spi_transfer(dev, addr, len, result, NULL);
}

static int tcm_tis_write8(struct device *dev,
		u32 addr, u16 len, u8 *value)
{
	return tcm_tis_spi_transfer(dev, addr, len, NULL, value);
}

static int tcm_tis_readb(struct device *dev, u32 addr, u8 *value)
{
	return tcm_tis_read8(dev, addr, sizeof(u8), value);
}

static int tcm_tis_writeb(struct device *dev, u32 addr, u8 value)
{
	return tcm_tis_write8(dev, addr, sizeof(u8), &value);
}

static int tcm_tis_readl(struct device *dev, u32 addr, u32 *result)
{
	int rc;
	__le32 result_le;

	rc = tcm_tis_read8(dev, addr, sizeof(u32), (u8 *)&result_le);
	tcm_dbg("TCM-dbg: result_le: 0x%x\n", result_le);
	if (!rc)
		*result = le32_to_cpu(result_le);

	return rc;
}

static int tcm_tis_writel(struct device *dev, u32 addr, u32 value)
{
	int rc;
	__le32 value_le;

	value_le = cpu_to_le32(value);
	rc = tcm_tis_write8(dev, addr, sizeof(u32), (u8 *)&value_le);

	return rc;
}

static int request_locality(struct tcm_chip *chip, int l);
static void release_locality(struct tcm_chip *chip, int l, int force);
static void cleanup_tis(void)
{
	int ret;
	u32 inten;
	struct tcm_vendor_specific *i, *j;
	struct tcm_chip *chip;

	spin_lock(&tis_lock);
	list_for_each_entry_safe(i, j, &tis_chips, list) {
		chip = to_tcm_chip(i);
		ret = tcm_tis_readl(chip->dev,
				TCM_INT_ENABLE(chip->vendor.locality), &inten);
		if (ret < 0)
			return;

		tcm_tis_writel(chip->dev, TCM_INT_ENABLE(chip->vendor.locality),
				~TCM_GLOBAL_INT_ENABLE & inten);
		release_locality(chip, chip->vendor.locality, 1);
	}
	spin_unlock(&tis_lock);
}

static void tcm_tis_init(struct tcm_chip *chip)
{
	int ret;
	u8 rid;
	u32 vendor, intfcaps;

	ret = tcm_tis_readl(chip->dev, TCM_DID_VID(0), &vendor);

	if ((vendor & 0xffff) != 0x19f5 && (vendor & 0xffff) != 0x1B4E)
		pr_info("there is no Nationz TCM on you computer\n");

	ret = tcm_tis_readb(chip->dev, TCM_RID(0), &rid);
	if (ret < 0)
		return;
	pr_info("kylin: 2019-09-21 1.2 TCM (device-id 0x%X, rev-id %d)\n",
		vendor >> 16, rid);

	/* Figure out the capabilities */
	ret = tcm_tis_readl(chip->dev,
			TCM_INTF_CAPS(chip->vendor.locality), &intfcaps);
	if (ret < 0)
		return;

	if (request_locality(chip, 0) != 0)
		pr_err("tcm request_locality err\n");

	atomic_set(&chip->data_pending, 0);
}

static void tcm_handle_err(struct tcm_chip *chip)
{
	cleanup_tis();
	tcm_tis_init(chip);
}

static bool check_locality(struct tcm_chip *chip, int l)
{
	int ret;
	u8 access;

	ret = tcm_tis_readb(chip->dev, TCM_ACCESS(l), &access);
	tcm_dbg("TCM-dbg: access: 0x%x\n", access);
	if (ret < 0)
		return false;

	if ((access & (TCM_ACCESS_ACTIVE_LOCALITY | TCM_ACCESS_VALID)) ==
					(TCM_ACCESS_ACTIVE_LOCALITY | TCM_ACCESS_VALID)) {
		chip->vendor.locality = l;
		return true;
	}

	return false;
}

static int request_locality(struct tcm_chip *chip, int l)
{
	unsigned long stop;

	if (check_locality(chip, l))
		return l;

	tcm_tis_writeb(chip->dev, TCM_ACCESS(l), TCM_ACCESS_REQUEST_USE);

	/* wait for burstcount */
	stop = jiffies + chip->vendor.timeout_a;
	do {
		if (check_locality(chip, l))
			return l;
		msleep(TCM_TIMEOUT);
	} while (time_before(jiffies, stop));

	return -1;
}

static void release_locality(struct tcm_chip *chip, int l, int force)
{
	int ret;
	u8 access;

	ret = tcm_tis_readb(chip->dev, TCM_ACCESS(l), &access);
	if (ret < 0)
		return;
	if (force || (access & (TCM_ACCESS_REQUEST_PENDING | TCM_ACCESS_VALID)) ==
			(TCM_ACCESS_REQUEST_PENDING | TCM_ACCESS_VALID))
		tcm_tis_writeb(chip->dev,
				TCM_ACCESS(l), TCM_ACCESS_ACTIVE_LOCALITY);
}

static u8 tcm_tis_status(struct tcm_chip *chip)
{
	int ret;
	u8 status;

	ret = tcm_tis_readb(chip->dev,
			TCM_STS(chip->vendor.locality), &status);
	tcm_dbg("TCM-dbg: status: 0x%x\n", status);
	if (ret < 0)
		return 0;

	return status;
}

static void tcm_tis_ready(struct tcm_chip *chip)
{
	/* this causes the current command to be aboreted */
	tcm_tis_writeb(chip->dev, TCM_STS(chip->vendor.locality),
			TCM_STS_COMMAND_READY);
}

static int get_burstcount(struct tcm_chip *chip)
{
	int ret;
	unsigned long stop;
	u8 tmp, tmp1;
	int burstcnt = 0;

	/* wait for burstcount */
	/* which timeout value, spec has 2 answers (c & d) */
	stop = jiffies + chip->vendor.timeout_d;
	do {
		ret = tcm_tis_readb(chip->dev,
				TCM_STS(chip->vendor.locality) + 1,
				&tmp);
		tcm_dbg("TCM-dbg: burstcnt: 0x%x\n", burstcnt);
		if (ret < 0)
			return -EINVAL;
		ret = tcm_tis_readb(chip->dev,
				(TCM_STS(chip->vendor.locality) + 2),
				&tmp1);
		tcm_dbg("TCM-dbg: burstcnt: 0x%x\n", burstcnt);
		if (ret < 0)
			return -EINVAL;

		burstcnt = tmp | (tmp1 << 8);
		if (burstcnt)
			return burstcnt;
		msleep(TCM_TIMEOUT);
	} while (time_before(jiffies, stop));

	return -EBUSY;
}

static int wait_for_stat(struct tcm_chip *chip, u8 mask,
		unsigned long timeout,
		wait_queue_head_t *queue)
{
	unsigned long stop;
	u8 status;

	/* check current status */
	status = tcm_tis_status(chip);
	if ((status & mask) == mask)
		return 0;

	stop = jiffies + timeout;
	do {
		msleep(TCM_TIMEOUT);
		status = tcm_tis_status(chip);
		if ((status & mask) == mask)
			return 0;
	} while (time_before(jiffies, stop));

	return -ETIME;
}

static int recv_data(struct tcm_chip *chip, u8 *buf, size_t count)
{
	int ret;
	int size = 0, burstcnt;

	while (size < count && wait_for_stat(chip,
				TCM_STS_DATA_AVAIL | TCM_STS_VALID,
				chip->vendor.timeout_c,
				&chip->vendor.read_queue) == 0) {
		burstcnt = get_burstcount(chip);

		if (burstcnt < 0) {
			dev_err(chip->dev, "Unable to read burstcount\n");
			return burstcnt;
		}

		for (; burstcnt > 0 && size < count; burstcnt--) {
			ret = tcm_tis_readb(chip->dev,
					TCM_DATA_FIFO(chip->vendor.locality),
					&buf[size]);
			tcm_dbg("TCM-dbg: buf[%d]: 0x%x\n", size, buf[size]);
			size++;
		}
	}

	return size;
}

static int tcm_tis_recv(struct tcm_chip *chip, u8 *buf, size_t count)
{
	int size = 0;
	int expected, status;
	unsigned long stop;

	if (count < TCM_HEADER_SIZE) {
		dev_err(chip->dev, "read size is to small: %d\n", (u32)(count));
		size = -EIO;
		goto out;
	}

	/* read first 10 bytes, including tag, paramsize, and result */
	size = recv_data(chip, buf, TCM_HEADER_SIZE);
	if (size < TCM_HEADER_SIZE) {
		dev_err(chip->dev, "Unable to read header\n");
		goto out;
	}

	expected = be32_to_cpu(*(__be32 *)(buf + 2));
	if (expected > count) {
		dev_err(chip->dev, "Expected data count\n");
		size = -EIO;
		goto out;
	}

	size += recv_data(chip, &buf[TCM_HEADER_SIZE],
				expected - TCM_HEADER_SIZE);
	if (size < expected) {
		dev_err(chip->dev, "Unable to read remainder of result\n");
		size = -ETIME;
		goto out;
	}

	wait_for_stat(chip, TCM_STS_VALID, chip->vendor.timeout_c,
		      &chip->vendor.int_queue);

	stop = jiffies + chip->vendor.timeout_c;
	do {
		msleep(TCM_TIMEOUT);
		status = tcm_tis_status(chip);
		if ((status & TCM_STS_DATA_AVAIL) == 0)
			break;

	} while (time_before(jiffies, stop));

	status = tcm_tis_status(chip);
	if (status & TCM_STS_DATA_AVAIL) {	/* retry? */
		dev_err(chip->dev, "Error left over data\n");
		size = -EIO;
		goto out;
	}

out:
	tcm_tis_ready(chip);
	release_locality(chip, chip->vendor.locality, 0);
	if (size < 0)
		tcm_handle_err(chip);
	return size;
}

/*
 * If interrupts are used (signaled by an irq set in the vendor structure)
 * tcm.c can skip polling for the data to be available as the interrupt is
 * waited for here
 */
static int tcm_tis_send(struct tcm_chip *chip, u8 *buf, size_t len)
{
	int rc, status, burstcnt;
	size_t count = 0;
	u32 ordinal;
	unsigned long stop;
	int send_again = 0;

tcm_tis_send_again:
	count = 0;
	if (request_locality(chip, 0) < 0) {
		dev_err(chip->dev, "send, tcm is busy\n");
		return -EBUSY;
	}
	status = tcm_tis_status(chip);

	if ((status & TCM_STS_COMMAND_READY) == 0) {
		tcm_tis_ready(chip);
		if (wait_for_stat(chip, TCM_STS_COMMAND_READY,
					chip->vendor.timeout_b, &chip->vendor.int_queue) < 0) {
			dev_err(chip->dev, "send, tcm wait time out1\n");
			rc = -ETIME;
			goto out_err;
		}
	}

	while (count < len - 1) {
		burstcnt = get_burstcount(chip);
		if (burstcnt < 0) {
			dev_err(chip->dev, "Unable to read burstcount\n");
			rc = burstcnt;
			goto out_err;
		}
		for (; burstcnt > 0 && count < len - 1; burstcnt--) {
			tcm_tis_writeb(chip->dev,
					TCM_DATA_FIFO(chip->vendor.locality), buf[count]);
			count++;
		}

		wait_for_stat(chip, TCM_STS_VALID, chip->vendor.timeout_c,
				&chip->vendor.int_queue);
	}

	/* write last byte */
	tcm_tis_writeb(chip->dev,
			TCM_DATA_FIFO(chip->vendor.locality), buf[count]);

	wait_for_stat(chip, TCM_STS_VALID,
			chip->vendor.timeout_c, &chip->vendor.int_queue);
	stop = jiffies + chip->vendor.timeout_c;
	do {
		msleep(TCM_TIMEOUT);
		status = tcm_tis_status(chip);
		if ((status & TCM_STS_DATA_EXPECT) == 0)
			break;

	} while (time_before(jiffies, stop));

	if ((status & TCM_STS_DATA_EXPECT) != 0) {
		dev_err(chip->dev, "send, tcm expect data\n");
		rc = -EIO;
		goto out_err;
	}

	/* go and do it */
	tcm_tis_writeb(chip->dev, TCM_STS(chip->vendor.locality), TCM_STS_GO);

	ordinal = be32_to_cpu(*((__be32 *)(buf + 6)));
	if (wait_for_stat(chip, TCM_STS_DATA_AVAIL | TCM_STS_VALID,
				tcm_calc_ordinal_duration(chip, ordinal),
				&chip->vendor.read_queue) < 0) {
		dev_err(chip->dev, "send, tcm wait time out2\n");
		rc = -ETIME;
		goto out_err;
	}

	return len;

out_err:
	tcm_tis_ready(chip);
	release_locality(chip, chip->vendor.locality, 0);
	tcm_handle_err(chip);
	if (send_again++ < 3) {
		goto tcm_tis_send_again;
	}

	dev_err(chip->dev, "kylin send, err: %d\n", rc);
	return rc;
}

static struct file_operations tis_ops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.open = tcm_open,
	.read = tcm_read,
	.write = tcm_write,
	.release = tcm_release,
};

static DEVICE_ATTR(pubek, S_IRUGO, tcm_show_pubek, NULL);
static DEVICE_ATTR(pcrs, S_IRUGO, tcm_show_pcrs, NULL);
static DEVICE_ATTR(enabled, S_IRUGO, tcm_show_enabled, NULL);
static DEVICE_ATTR(active, S_IRUGO, tcm_show_active, NULL);
static DEVICE_ATTR(owned, S_IRUGO, tcm_show_owned, NULL);
static DEVICE_ATTR(temp_deactivated, S_IRUGO, tcm_show_temp_deactivated,
			NULL);
static DEVICE_ATTR(caps, S_IRUGO, tcm_show_caps, NULL);
static DEVICE_ATTR(cancel, S_IWUSR | S_IWGRP, NULL, tcm_store_cancel);

static struct attribute *tis_attrs[] = {
	&dev_attr_pubek.attr,
	&dev_attr_pcrs.attr,
	&dev_attr_enabled.attr,
	&dev_attr_active.attr,
	&dev_attr_owned.attr,
	&dev_attr_temp_deactivated.attr,
	&dev_attr_caps.attr,
	&dev_attr_cancel.attr, NULL,
};

static struct attribute_group tis_attr_grp = {
	.attrs = tis_attrs
};

static struct tcm_vendor_specific tcm_tis = {
	.status = tcm_tis_status,
	.recv = tcm_tis_recv,
	.send = tcm_tis_send,
	.cancel = tcm_tis_ready,
	.req_complete_mask = TCM_STS_DATA_AVAIL | TCM_STS_VALID,
	.req_complete_val = TCM_STS_DATA_AVAIL | TCM_STS_VALID,
	.req_canceled = TCM_STS_COMMAND_READY,
	.attr_group = &tis_attr_grp,
	.miscdev = {
		.fops = &tis_ops,
	},
};

static struct tcm_chip *chip;
static int tcm_tis_spi_probe(struct spi_device *spi)
{
	int ret;
	u8 revid;
	u32 vendor, intfcaps;
	struct tcm_tis_spi_phy *phy;
	struct chip_data *spi_chip;

	pr_info("TCM(ky): __func__(v=%d) ..\n",
				10);

	tcm_dbg("TCM-dbg: %s/%d, enter\n", __func__, __LINE__);
	phy = devm_kzalloc(&spi->dev, sizeof(struct tcm_tis_spi_phy),
			GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	phy->iobuf = devm_kmalloc(&spi->dev, MAX_SPI_FRAMESIZE, GFP_KERNEL);
	if (!phy->iobuf)
		return -ENOMEM;

	phy->spi_device = spi;
	init_completion(&phy->ready);

	tcm_dbg("TCM-dbg: %s/%d\n", __func__, __LINE__);
	/* init spi dev */
	spi->chip_select = 0;		/* cs0 */
	spi->mode = SPI_MODE_0;
	spi->bits_per_word = 8;
	spi->max_speed_hz = spi->max_speed_hz ? : 24000000;
	spi_setup(spi);

	spi_chip = spi_get_ctldata(spi);
	if (!spi_chip) {
		pr_err("There was wrong in spi master\n");
		return -ENODEV;
	}
	/* tcm does not support interrupt mode, we use poll mode instead. */
	spi_chip->poll_mode = 1;

	tcm_dbg("TCM-dbg: %s/%d\n", __func__, __LINE__);
	/* regiter tcm hw */
	chip = tcm_register_hardware(&spi->dev, &tcm_tis);
	if (!chip) {
		dev_err(chip->dev, "tcm register hardware err\n");
		return -ENODEV;
	}

	dev_set_drvdata(chip->dev, phy);

	/**
	 * phytium2000a4 spi controller's clk clk level is unstable,
	 * so it is solved by using the low level of gpio output.
	 **/
	if (is_ft_all() && (spi->chip_select == 0)) {
		/* reuse conf reg base */
		reuse_conf_reg = ioremap(REUSE_CONF_REG_BASE, 0x10);
		if (!reuse_conf_reg) {
			dev_err(&spi->dev, "Failed to ioremap reuse conf reg\n");
			ret = -ENOMEM;
			goto out_err;
		}

		/* gpio1 a5 base addr */
		gpio1_a5 = ioremap(REUSE_GPIO1_A5_BASE, 0x10);
		if (!gpio1_a5) {
			dev_err(&spi->dev, "Failed to ioremap gpio1 a5\n");
			ret = -ENOMEM;
			goto out_err;
		}

		/* reuse cs0 to gpio1_a5 */
		iowrite32((ioread32(reuse_conf_reg) | 0xFFFF0) & 0xFFF9004F,
				reuse_conf_reg);
		/* set gpio1 a5 to output */
		iowrite32(0x20, gpio1_a5 + 0x4);
	}

	tcm_dbg("TCM-dbg: %s/%d\n",
			__func__, __LINE__);
	ret = tcm_tis_readl(chip->dev, TCM_DID_VID(0), &vendor);
	if (ret < 0)
		goto out_err;

	tcm_dbg("TCM-dbg: %s/%d, vendor: 0x%x\n",
			__func__, __LINE__, vendor);
	if ((vendor & 0xffff) != 0x19f5 && (vendor & 0xffff) != 0x1B4E) {
		dev_err(chip->dev, "there is no Nationz TCM on you computer\n");
		goto out_err;
	}

	ret = tcm_tis_readb(chip->dev, TCM_RID(0), &revid);
	tcm_dbg("TCM-dbg: %s/%d, revid: 0x%x\n",
			__func__, __LINE__, revid);
	if (ret < 0)
		goto out_err;
	dev_info(chip->dev, "kylin: 2019-09-21 1.2 TCM "
				"(device-id 0x%X, rev-id %d)\n",
			vendor >> 16, revid);

	/* Default timeouts */
	chip->vendor.timeout_a = msecs_to_jiffies(TIS_SHORT_TIMEOUT);
	chip->vendor.timeout_b = msecs_to_jiffies(TIS_LONG_TIMEOUT);
	chip->vendor.timeout_c = msecs_to_jiffies(TIS_SHORT_TIMEOUT);
	chip->vendor.timeout_d = msecs_to_jiffies(TIS_SHORT_TIMEOUT);

	tcm_dbg("TCM-dbg: %s/%d\n",
			__func__, __LINE__);
	/* Figure out the capabilities */
	ret = tcm_tis_readl(chip->dev,
			TCM_INTF_CAPS(chip->vendor.locality), &intfcaps);
	if (ret < 0)
		goto out_err;

	tcm_dbg("TCM-dbg: %s/%d, intfcaps: 0x%x\n",
			__func__, __LINE__, intfcaps);
	if (request_locality(chip, 0) != 0) {
		dev_err(chip->dev, "tcm request_locality err\n");
		ret = -ENODEV;
		goto out_err;
	}

	INIT_LIST_HEAD(&chip->vendor.list);
	spin_lock(&tis_lock);
	list_add(&chip->vendor.list, &tis_chips);
	spin_unlock(&tis_lock);

	tcm_get_timeouts(chip);
	tcm_startup(chip);

	tcm_dbg("TCM-dbg: %s/%d, exit\n", __func__, __LINE__);
	return 0;

out_err:
	if (is_ft_all()) {
		if (reuse_conf_reg)
			iounmap(reuse_conf_reg);
		if (gpio1_a5)
			iounmap(gpio1_a5);
	}
	tcm_dbg("TCM-dbg: %s/%d, error\n", __func__, __LINE__);
	dev_set_drvdata(chip->dev, chip);
	tcm_remove_hardware(chip->dev);

	return ret;
}

static int tcm_tis_spi_remove(struct spi_device *dev)
{
	if (is_ft_all()) {
		if (reuse_conf_reg)
			iounmap(reuse_conf_reg);
		if (gpio1_a5)
			iounmap(gpio1_a5);
	}

	dev_info(&dev->dev, "%s\n", __func__);
	dev_set_drvdata(chip->dev, chip);
	tcm_remove_hardware(&dev->dev);

	return 0;
}

static const struct acpi_device_id tcm_tis_spi_acpi_match[] = {
	{"TCMS0001", 0},
	{"SMO0768", 0},
	{"ZIC0601", 0},
	{}
};
MODULE_DEVICE_TABLE(acpi, tcm_tis_spi_acpi_match);

static const struct spi_device_id tcm_tis_spi_id_table[] = {
	{"SMO0768", 0},
	{"ZIC0601", 0},
	{}
};
MODULE_DEVICE_TABLE(spi, tcm_tis_spi_id_table);

static struct spi_driver tcm_tis_spi_drv = {
	.driver = {
		.name = "tcm_tis_spi",
		.acpi_match_table = ACPI_PTR(tcm_tis_spi_acpi_match),
	},
	.id_table = tcm_tis_spi_id_table,
	.probe = tcm_tis_spi_probe,
	.remove = tcm_tis_spi_remove,
};

module_spi_driver(tcm_tis_spi_drv);

MODULE_AUTHOR("xiongxin<xiongxin(a)tj.kylinos.cn>");
MODULE_DESCRIPTION("TCM Driver Base Spi");
MODULE_VERSION("6.1.0.2");
MODULE_LICENSE("GPL");
