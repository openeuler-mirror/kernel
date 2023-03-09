/*
 * Loongson SPI driver
 *
 * Copyright (C) 2013 Loongson Technology Corporation Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/spi/spi.h>
#include <linux/pci.h>
#include <linux/of.h>

/*define spi register */
#define	SPCR	0x00
#define	SPSR	0x01
#define FIFO	0x02
#define	SPER	0x03
#define	PARA	0x04
#define	SPCS	0x04
#define	SFCS	0x05
#define	TIMI	0x06

#define PARA_MEM_EN	0x01
#define SPSR_SPIF	0x80
#define SPSR_WCOL	0x40
#define SPCR_SPE	0x40

extern unsigned long bus_clock;
struct loongson_spi {
	struct work_struct	work;
	spinlock_t			lock;

	struct	list_head	msg_queue;
	struct	spi_master	*master;
	void	__iomem		*base;
	int cs_active;
	unsigned int hz;
	unsigned char spcr, sper, spsr;
	unsigned char para, sfcs, timi;
	struct workqueue_struct	*wq;
	unsigned int mode;
} *loongson_spi_dev;

static inline int set_cs(struct loongson_spi *loongson_spi, struct spi_device  *spi, int val);

static void loongson_spi_write_reg(struct loongson_spi *spi,
		unsigned char reg, unsigned char data)
{
	writeb(data, spi->base +reg);
}

static char loongson_spi_read_reg(struct loongson_spi *spi,
		unsigned char reg)
{
	return readb(spi->base + reg);
}

static int loongson_spi_update_state(struct loongson_spi *loongson_spi,struct spi_device *spi,
		struct spi_transfer *t)
{
	unsigned int hz;
	unsigned int div, div_tmp;
	unsigned int bit;
	unsigned long clk;
	unsigned char val;
	const char rdiv[12] = {0, 1, 4, 2, 3, 5, 6, 7, 8, 9, 10, 11};

	hz  = t ? t->speed_hz : spi->max_speed_hz;

	if (!hz)
		hz = spi->max_speed_hz;

	if ((hz && loongson_spi->hz != hz) || ((spi->mode ^ loongson_spi->mode) & (SPI_CPOL | SPI_CPHA))) {
		clk = 100000000;
		div = DIV_ROUND_UP(clk, hz);

		if (div < 2)
			div = 2;

		if (div > 4096)
			div = 4096;

		bit = fls(div) - 1;
		if ((1<<bit) == div)
			bit--;
		div_tmp = rdiv[bit];

		dev_dbg(&spi->dev, "clk = %ld hz = %d div_tmp = %d bit = %d\n",
				clk, hz, div_tmp, bit);

		loongson_spi->hz = hz;
		loongson_spi->spcr = div_tmp & 3;
		loongson_spi->sper = (div_tmp >> 2) & 3;

		val = loongson_spi_read_reg(loongson_spi, SPCR);
		val &= ~0xc;
		if (spi->mode & SPI_CPOL)
		   val |= 8;
		if (spi->mode & SPI_CPHA)
		   val |= 4;
		loongson_spi_write_reg(loongson_spi, SPCR, (val & ~3) | loongson_spi->spcr);
		val = loongson_spi_read_reg(loongson_spi, SPER);
		loongson_spi_write_reg(loongson_spi, SPER, (val & ~3) | loongson_spi->sper);
		loongson_spi->mode &= SPI_NO_CS;
		loongson_spi->mode |= spi->mode;
	}

	return 0;
}



static int loongson_spi_setup(struct spi_device *spi)
{
	struct loongson_spi *loongson_spi;

	loongson_spi = spi_master_get_devdata(spi->master);
	if (spi->bits_per_word %8)
		return -EINVAL;

	if(spi->chip_select >= spi->master->num_chipselect)
		return -EINVAL;

	loongson_spi_update_state(loongson_spi, spi, NULL);

	set_cs(loongson_spi, spi, 1);

	return 0;
}

static int loongson_spi_write_read_8bit( struct spi_device *spi,
		const u8 **tx_buf, u8 **rx_buf, unsigned int num)
{
	struct loongson_spi *loongson_spi;
	loongson_spi = spi_master_get_devdata(spi->master);

	if (tx_buf && *tx_buf){
		loongson_spi_write_reg(loongson_spi, FIFO, *((*tx_buf)++));
		while((loongson_spi_read_reg(loongson_spi, SPSR) & 0x1) == 1);
	}else{
		loongson_spi_write_reg(loongson_spi, FIFO, 0);
		while((loongson_spi_read_reg(loongson_spi, SPSR) & 0x1) == 1);
	}

	if (rx_buf && *rx_buf) {
		*(*rx_buf)++ = loongson_spi_read_reg(loongson_spi, FIFO);
	}else{
		loongson_spi_read_reg(loongson_spi, FIFO);
	}

	return 1;
}


static unsigned int loongson_spi_write_read(struct spi_device *spi, struct spi_transfer *xfer)
{
	struct loongson_spi *loongson_spi;
	unsigned int count;
	const u8 *tx = xfer->tx_buf;
	u8 *rx = xfer->rx_buf;

	loongson_spi = spi_master_get_devdata(spi->master);
	count = xfer->len;

	do {
		if (loongson_spi_write_read_8bit(spi, &tx, &rx, count) < 0)
			goto out;
		count--;
	} while (count);

out:
	return xfer->len - count;

}

static inline int set_cs(struct loongson_spi *loongson_spi, struct spi_device  *spi, int val)
{
	if (spi->mode  & SPI_CS_HIGH)
		val = !val;
	if (loongson_spi->mode & SPI_NO_CS) {
		loongson_spi_write_reg(loongson_spi, SPCS, val);
	} else {
		int cs = loongson_spi_read_reg(loongson_spi, SFCS) & ~(0x11 << spi->chip_select);
		loongson_spi_write_reg(loongson_spi, SFCS, (val ? (0x11 << spi->chip_select):(0x1 << spi->chip_select)) | cs);
	}
	return 0;
}

static void loongson_spi_work(struct work_struct *work)
{
	struct loongson_spi *loongson_spi =
		container_of(work, struct loongson_spi, work);
	int param;

	spin_lock(&loongson_spi->lock);
	param = loongson_spi_read_reg(loongson_spi, PARA);
	loongson_spi_write_reg(loongson_spi, PARA, param&~1);
	while (!list_empty(&loongson_spi->msg_queue)) {

		struct spi_message *m;
		struct spi_device  *spi;
		struct spi_transfer *t = NULL;

		m = container_of(loongson_spi->msg_queue.next, struct spi_message, queue);

		list_del_init(&m->queue);
		spin_unlock(&loongson_spi->lock);

		spi = m->spi;

		/*in here set cs*/
		set_cs(loongson_spi, spi, 0);

		list_for_each_entry(t, &m->transfers, transfer_list) {

			/*setup spi clock*/
			loongson_spi_update_state(loongson_spi, spi, t);

			if (t->len)
				m->actual_length +=
					loongson_spi_write_read(spi, t);
		}

		set_cs(loongson_spi, spi, 1);
		m->complete(m->context);


		spin_lock(&loongson_spi->lock);
	}

	loongson_spi_write_reg(loongson_spi, PARA, param);
	spin_unlock(&loongson_spi->lock);
}



static int loongson_spi_transfer(struct spi_device *spi, struct spi_message *m)
{
	struct loongson_spi	*loongson_spi;
	struct spi_transfer *t = NULL;

	m->actual_length = 0;
	m->status		 = 0;
	if (list_empty(&m->transfers) || !m->complete)
		return -EINVAL;

	loongson_spi = spi_master_get_devdata(spi->master);

	list_for_each_entry(t, &m->transfers, transfer_list) {

		if (t->tx_buf == NULL && t->rx_buf == NULL && t->len) {
			dev_err(&spi->dev,
					"message rejected : "
					"invalid transfer data buffers\n");
			goto msg_rejected;
		}
		/*other things not check*/
	}

	spin_lock(&loongson_spi->lock);
	list_add_tail(&m->queue, &loongson_spi->msg_queue);
	queue_work(loongson_spi->wq, &loongson_spi->work);
	spin_unlock(&loongson_spi->lock);

	return 0;
msg_rejected:

	m->status = -EINVAL;
	if (m->complete)
		m->complete(m->context);
	return -EINVAL;
}

static void loongson_spi_reginit(void)
{
	unsigned char val;

	val = loongson_spi_read_reg(loongson_spi_dev, SPCR);
	val &= ~SPCR_SPE;
	loongson_spi_write_reg(loongson_spi_dev, SPCR, val);

	loongson_spi_write_reg(loongson_spi_dev, SPSR, (SPSR_SPIF | SPSR_WCOL));

	val = loongson_spi_read_reg(loongson_spi_dev, SPCR);
	val |= SPCR_SPE;
	loongson_spi_write_reg(loongson_spi_dev, SPCR, val);
}

static int loongson_spi_probe(struct platform_device *pdev)
{
	struct spi_master	*master;
	struct loongson_spi		*spi;
	struct resource		*res;
	int ret;
	master = spi_alloc_master(&pdev->dev, sizeof(struct loongson_spi));

	if (master == NULL) {
		dev_dbg(&pdev->dev, "master allocation failed\n");
		return-ENOMEM;
	}

	if (pdev->id != -1)
		master->bus_num	= pdev->id;

	master->mode_bits = SPI_CPOL | SPI_CPHA | SPI_CS_HIGH ;
	master->setup = loongson_spi_setup;
	master->transfer = loongson_spi_transfer;
	master->num_chipselect = 4;
#ifdef CONFIG_OF
	master->dev.of_node = of_node_get(pdev->dev.of_node);
#endif
	dev_set_drvdata(&pdev->dev, master);

	spi = spi_master_get_devdata(master);

	loongson_spi_dev = spi;

	spi->wq	= create_singlethread_workqueue(pdev->name);

	spi->master = master;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "Cannot get IORESOURCE_MEM\n");
		ret = -ENOENT;
		goto free_master;
	}

	spi->base = ioremap(res->start, (res->end - res->start)+1);
	if (spi->base == NULL) {
		dev_err(&pdev->dev, "Cannot map IO\n");
		ret = -ENXIO;
		goto unmap_io;
	}

	loongson_spi_reginit();

	spi->mode = 0;
	if (of_get_property(pdev->dev.of_node, "spi-nocs", NULL))
		spi->mode |= SPI_NO_CS;

	INIT_WORK(&spi->work, loongson_spi_work);

	spin_lock_init(&spi->lock);
	INIT_LIST_HEAD(&spi->msg_queue);

	ret = spi_register_master(master);
	if (ret < 0)
		goto unmap_io;

	return ret;

unmap_io:
	iounmap(spi->base);
free_master:
	kfree(master);
	spi_master_put(master);
	return ret;

}

#ifdef CONFIG_PM
static int loongson_spi_suspend(struct device *dev)
{
	struct loongson_spi *loongson_spi;
	struct spi_master *master;

	master = dev_get_drvdata(dev);
	loongson_spi = spi_master_get_devdata(master);

	loongson_spi->spcr = loongson_spi_read_reg(loongson_spi, SPCR);
	loongson_spi->sper = loongson_spi_read_reg(loongson_spi, SPER);
	loongson_spi->spsr = loongson_spi_read_reg(loongson_spi, SPSR);
	loongson_spi->para = loongson_spi_read_reg(loongson_spi, PARA);
	loongson_spi->sfcs = loongson_spi_read_reg(loongson_spi, SFCS);
	loongson_spi->timi = loongson_spi_read_reg(loongson_spi, TIMI);

	return 0;
}

static int loongson_spi_resume(struct device *dev)
{
	struct loongson_spi *loongson_spi;
	struct spi_master *master;

	master = dev_get_drvdata(dev);
	loongson_spi = spi_master_get_devdata(master);

	loongson_spi_write_reg(loongson_spi, SPCR, loongson_spi->spcr);
	loongson_spi_write_reg(loongson_spi, SPER, loongson_spi->sper);
	loongson_spi_write_reg(loongson_spi, SPSR, loongson_spi->spsr);
	loongson_spi_write_reg(loongson_spi, PARA, loongson_spi->para);
	loongson_spi_write_reg(loongson_spi, SFCS, loongson_spi->sfcs);
	loongson_spi_write_reg(loongson_spi, TIMI, loongson_spi->timi);

	return 0;
}

static const struct dev_pm_ops loongson_spi_dev_pm_ops = {
	.suspend	= loongson_spi_suspend,
	.resume		= loongson_spi_resume,
};

#define LS_DEV_PM_OPS (&loongson_spi_dev_pm_ops)
#else
#define LS_DEV_PM_OPS NULL
#endif


#ifdef CONFIG_OF
static struct of_device_id loongson_spi_id_table[] = {
	{ .compatible = "loongson,ls7a-spi", },
	{ },
};
MODULE_DEVICE_TABLE(of, loongson_spi_id_table);
#endif
static struct platform_driver loongson_spi_driver = {
	.probe = loongson_spi_probe,
	.driver	= {
		.name	= "loongson-spi",
		.owner	= THIS_MODULE,
		.bus = &platform_bus_type,
		.pm = LS_DEV_PM_OPS,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(loongson_spi_id_table),
#endif
	},
};

#ifdef CONFIG_PCI
static struct resource loongson_spi_resources[] = {
    [0] = {
        .flags  = IORESOURCE_MEM,
    },
    [1] = {
        .flags  = IORESOURCE_IRQ,
    },
};

static struct platform_device loongson_spi_device = {
    .name           = "loongson-spi",
    .id             = 0,
    .num_resources  = ARRAY_SIZE(loongson_spi_resources),
    .resource   = loongson_spi_resources,
};


static int loongson_spi_pci_register(struct pci_dev *pdev,
                 const struct pci_device_id *ent)
{
    int ret;
    unsigned char v8;

    pr_debug("loongson_spi_pci_register BEGIN\n");
    /* Enable device in PCI config */
    ret = pci_enable_device(pdev);
    if (ret < 0) {
        printk(KERN_ERR "loongson-pci (%s): Cannot enable PCI device\n",
               pci_name(pdev));
        goto err_out;
    }

    /* request the mem regions */
    ret = pci_request_region(pdev, 0, "loongson-spi io");
    if (ret < 0) {
        printk( KERN_ERR "loongson-spi (%s): cannot request region 0.\n",
            pci_name(pdev));
        goto err_out;
    }

    loongson_spi_resources[0].start = pci_resource_start (pdev, 0);
    loongson_spi_resources[0].end = pci_resource_end(pdev, 0);
    /* need api from pci irq */
    ret = pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &v8);

    if (ret == PCIBIOS_SUCCESSFUL) {

        loongson_spi_resources[1].start = v8;
        loongson_spi_resources[1].end = v8;
        platform_device_register(&loongson_spi_device);
    }

err_out:
    return ret;
}

static void loongson_spi_pci_unregister(struct pci_dev *pdev)
{
    pci_release_region(pdev, 0);
}

static struct pci_device_id loongson_spi_devices[] = {
    {PCI_DEVICE(0x14, 0x7a0b)},
    {0, 0, 0, 0, 0, 0, 0}
};

static struct pci_driver loongson_spi_pci_driver = {
    .name       = "loongson-spi-pci",
    .id_table   = loongson_spi_devices,
    .probe      = loongson_spi_pci_register,
    .remove     = loongson_spi_pci_unregister,
};
#endif


static int __init loongson_spi_init(void)
{
	int ret;

	ret =  platform_driver_register(&loongson_spi_driver);
#ifdef CONFIG_PCI
	if(!ret)
		ret = pci_register_driver(&loongson_spi_pci_driver);
#endif
	return ret;
}

static void __exit loongson_spi_exit(void)
{
	platform_driver_unregister(&loongson_spi_driver);
#ifdef CONFIG_PCI
	pci_unregister_driver(&loongson_spi_pci_driver);
#endif
}

subsys_initcall(loongson_spi_init);
module_exit(loongson_spi_exit);

MODULE_AUTHOR("Loongson Technology Corporation Limited");
MODULE_DESCRIPTION("Loongson SPI driver");
MODULE_LICENSE("GPL");
