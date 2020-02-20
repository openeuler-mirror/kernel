// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018-2019 HiSilicon Limited. */
/**
 * This module is used to test the framework of WarpDrive.
 *
 * It support a simular device as dummy_wd_dev in qemu and do almost the same.
 * But it is a "real" hardware to the OS, so we can test the iommu feature
 */

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uacce.h>
#include <linux/uaccess.h>

#include "wd_dummy_usr_if.h"
#include "dummy_hw_usr_if.h"

#define DUMMY2_WD	"dummy_wd2"
#define MAX_PT_ENTRIES  64
#define RING_NUM 3
#define HEADER_WORDS 12		/* reseved words in page 0 */
#define DUMMY2_DMA_PAGE_SHIFT 12
#define DUMMY2_DMA_PAGE_SIZE (1<<DUMMY2_DMA_PAGE_SHIFT)

#define DUMMY2_IO_TAG		0
#define DUMMY2_IO_PTPA		(sizeof(uint64_t))
#define DUMMY2_IO_PTSZ		(sizeof(uint64_t) * 2)
#define DUMMY2_IO_MAX_COPY_SIZE (sizeof(uint64_t) * 4)
#define DUMMY2_IO_RING_BEGIN	(sizeof(uint64_t) * HEADER_WORDS)

struct pt_entry {
	uint64_t asid;		/*
				 *-1 means entry invalid, 0 means kernel,
				 *others are valid pasid.
				 */
	uint64_t iova;
		  /*-1 means entry invalid */
	uint64_t pa;
};

/* ring io struct in hardware mmio space */
struct ring_io {
	uint64_t rbpa;
	uint64_t rbsz;
	uint64_t asid;
};

struct dummy_wd2_hw;

struct dummy_wd2_iommu_domain {
	struct iommu_domain domain;
	struct dummy_wd2_hw *hw;
	uint64_t asid;
};
#define to_dummy_wd2_iommu_domain(d) \
	container_of(d, struct dummy_wd2_iommu_domain, domain)

struct dummy_wd2_hw_queue {
	bool used;
	struct dummy_wd2_hw *hw;
	struct uacce_queue q;
	void __iomem *db_pa;
	void *ring_io_base;

	dma_addr_t bd_dma;
};

struct dummy_wd2_hw {
	int max_copy_size;
	int ver;
	struct dummy_wd2_hw_queue qs[RING_NUM];
	struct platform_device *pdev;
	struct mutex mutex;
	struct device dummy_wd2_dev;
	struct iommu_group *iommu_group;

	void *io_base;
	struct pt_entry *pt;
	dma_addr_t pt_dma;
};

static int dummy_wd2_bus_probe(struct device *dev)
{
	dev_info(dev, "bus probe dev\n");
	return 0;
}

static int dummy_wd2_bus_remove(struct device *dev)
{
	dev_info(dev, "bus remove dev");
	return 0;
}

static bool dummy_wd2_iommu_capable(enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;
	default:
		return false;
	}
}

static struct iommu_domain *dummy_wd2_iommu_domain_alloc(
		unsigned int iommu_domain_type);
static void dummy_wd2_iommu_domain_free(struct iommu_domain *domain);

static int dummy_wd2_iommu_attach_dev(struct iommu_domain *domain,
				      struct device *dev)
{
	struct dummy_wd2_iommu_domain *d = to_dummy_wd2_iommu_domain(domain);

	pr_info("%s\n", __func__);
	d->hw = dev_get_drvdata(dev);
	d->asid = 0;

	if (d->hw)
		return 0;
	else
		return -ENODEV;
}

static void dummy_wd2_iommu_detach_dev(struct iommu_domain *domain,
				       struct device *dev)
{
	struct dummy_wd2_iommu_domain *d = to_dummy_wd2_iommu_domain(domain);

	d->hw = NULL;
	d->asid = (u64)-1;
	pr_info("%s\n", __func__);
}

static int dummy_wd2_iommu_map(struct iommu_domain *domain, unsigned long iova,
			       phys_addr_t paddr, size_t size, int prot)
{
	struct dummy_wd2_iommu_domain *d = to_dummy_wd2_iommu_domain(domain);
	int i;

	if (size != 4096)
		return -EIO;

	for (i = 0; i < MAX_PT_ENTRIES; i++) {
		if (d->hw->pt[i].asid == (uint64_t)-1) {
			d->hw->pt[i].asid = d->asid;
			d->hw->pt[i].iova = iova;
			d->hw->pt[i].pa = paddr;
			dev_dbg(&d->hw->dummy_wd2_dev,
				"iommu_map %d asid=%lld, %llx=>%llx\n", i,
				d->hw->pt[i].asid,
				d->hw->pt[i].iova,
				d->hw->pt[i].pa);
			/* flush to hardware */
			writeq(MAX_PT_ENTRIES,
			       d->hw->io_base + DUMMY2_IO_PTSZ);
			return 0;
		}
	}

	return -EBUSY;
}

static size_t dummy_wd2_iommu_unmap(struct iommu_domain *domain,
				    unsigned long iova, size_t size)
{
	struct dummy_wd2_iommu_domain *d = to_dummy_wd2_iommu_domain(domain);
	int i;

	if (size != DUMMY2_DMA_PAGE_SHIFT)
		return 0;

	for (i = 0; i < MAX_PT_ENTRIES; i++) {
		if (d->hw->pt[i].asid == d->asid && d->hw->pt[i].iova == iova) {
			dev_dbg(&d->hw->dummy_wd2_dev,
				"iommu_unmap %d asid=%lld, %llx=>%llx\n", i,
				d->hw->pt[i].asid,
				d->hw->pt[i].iova,
				d->hw->pt[i].pa);
			d->hw->pt[i].asid = (uint64_t)-1;
			/* flush to hardware */
			writeq(MAX_PT_ENTRIES,
			       d->hw->io_base + DUMMY2_IO_PTSZ);
			return DUMMY2_DMA_PAGE_SIZE;
		}
	}

	return 0;
}

static struct iommu_ops dummy_wd2_iommu_ops = {
	.capable = dummy_wd2_iommu_capable,
	.domain_alloc = dummy_wd2_iommu_domain_alloc,
	.domain_free = dummy_wd2_iommu_domain_free,
	.attach_dev = dummy_wd2_iommu_attach_dev,
	.detach_dev = dummy_wd2_iommu_detach_dev,
	.map = dummy_wd2_iommu_map,
	.unmap = dummy_wd2_iommu_unmap,
	.pgsize_bitmap = SZ_4K,
};

static struct iommu_domain *dummy_wd2_iommu_domain_alloc(
		unsigned int iommu_domain_type)
{
	struct dummy_wd2_iommu_domain *domain = kzalloc(
		sizeof(struct iommu_domain), GFP_KERNEL);

	if (!domain)
		return NULL;

	domain->domain.ops = &dummy_wd2_iommu_ops;

	return &domain->domain;
}

static void dummy_wd2_iommu_domain_free(struct iommu_domain *domain)
{
	struct dummy_wd2_iommu_domain *d = to_dummy_wd2_iommu_domain(domain);

	kfree(d);
}

static struct bus_type dummy_wd2_bus_type = {
	.name		= "dummy_wd2_bus",
	.probe		= dummy_wd2_bus_probe,
	.remove		= dummy_wd2_bus_remove,
	.iommu_ops	= &dummy_wd2_iommu_ops,
};

static int dummy_wd2_is_q_updated(struct uacce_queue *q)
{
	return 0;
}

static int dummy_wd2_get_queue(struct uacce *uacce, unsigned long arg,
			   struct uacce_queue **q)
{
	int i;
	struct dummy_wd2_hw *hw = (struct dummy_wd2_hw *)uacce->priv;

	mutex_lock(&hw->mutex);
	for (i = 0; i < RING_NUM; i++) {
		if (!hw->qs[i].used) {
			hw->qs[i].used = true;
			*q = &hw->qs[i].q;
			dev_dbg(uacce->pdev, "allocate hw q %d\n", i);
			break;
		}
	}
	mutex_unlock(&hw->mutex);

	if (i < RING_NUM)
		return 0;

	return -ENODEV;
}

static void dummy_wd2_put_queue(struct uacce_queue *q)
{
	struct dummy_wd2_hw_queue *hwq = (struct dummy_wd2_hw_queue *)q->priv;
	struct dummy_wd2_hw *hw = hwq->hw;

	mutex_lock(&hw->mutex);
	hwq->used = false;
	mutex_unlock(&hw->mutex);
}

static int dummy_wd2_mmap(struct uacce_queue *q, struct vm_area_struct *vma,
		      struct uacce_qfile_region *qfr)
{
	struct dummy_wd2_hw_queue *hwq = (struct dummy_wd2_hw_queue *)q->priv;

	if (vma->vm_pgoff != 0 || qfr->nr_pages > 1 ||
	    !(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start,
			       (u64)hwq->db_pa >> PAGE_SHIFT,
			       DUMMY2_DMA_PAGE_SIZE,
			       pgprot_noncached(vma->vm_page_prot));
}

static void dummy_wd2_mask_notify(struct uacce_queue *q, int event_mask)
{
	dev_dbg(&q->uacce->dev, "mask notify: %x\n", event_mask);
}

static inline void dummy_wd2_hw_set_rb(struct dummy_wd2_hw_queue *hwq,
				       uint64_t rbpa, uint64_t rbsz,
				       uint64_t asid)
{
#define ring_io_off(member) offsetof(struct ring_io, member)
	writeq(rbpa, hwq->ring_io_base + ring_io_off(rbpa));
	writeq(rbsz, hwq->ring_io_base + ring_io_off(rbsz));
	writeq(asid, hwq->ring_io_base + ring_io_off(asid));
}

static int dummy_wd2_start_queue(struct uacce_queue *q)
{
	struct dummy_wd2_hw_queue *hwq = (struct dummy_wd2_hw_queue *)q->priv;

	dev_dbg(&q->uacce->dev, "queue start\n");

	hwq->bd_dma = q->qfrs[UACCE_QFRT_DUS]->iova;
	if (!hwq->bd_dma) {
		dev_err(&q->uacce->dev, "DUS is not created\n");
		return -EINVAL;
	}

	if (!hwq->ring_io_base) {
		dev_err(&q->uacce->dev, "ring_iobase is not set\n");
		return -EINVAL;
	}

	dummy_wd2_hw_set_rb(hwq, hwq->bd_dma, Q_BDS, 0);

	return 0;
}

void dummy_wd2_stop_queue(struct uacce_queue *q)
{
	struct dummy_wd2_hw_queue *hwq = (struct dummy_wd2_hw_queue *)q->priv;

	dev_dbg(&q->uacce->dev, "stop queue\n");
	dummy_wd2_hw_set_rb(hwq, 0, 0, (uint64_t)-1);
}

static int dummy_wd2_get_available_instances(struct uacce *uacce)
{
	int i, ret;
	struct dummy_wd2_hw *hw = (struct dummy_wd2_hw *)uacce->priv;

	mutex_lock(&hw->mutex);
	for (i = 0, ret = 0; i < RING_NUM; i++) {
		if (!hw->qs[i].used)
			ret++;
	}
	mutex_unlock(&hw->mutex);

	return ret;
}

static struct uacce_ops dummy_wd2_ops = {
	.get_queue = dummy_wd2_get_queue,
	.put_queue = dummy_wd2_put_queue,
	.start_queue = dummy_wd2_start_queue,
	.stop_queue = dummy_wd2_stop_queue,
	.is_q_updated = dummy_wd2_is_q_updated,
	.mmap = dummy_wd2_mmap,
	.mask_notify = dummy_wd2_mask_notify,
	.get_available_instances = dummy_wd2_get_available_instances,
};

static void dummy_wd2_dev_release(struct device *dev)
{
	dev_info(dev, "dummy_wd2 dev release\n");
}

static int dummy_wd2_probe(struct platform_device *pdev)
{
	struct uacce *uacce;
	struct device *dev = &pdev->dev;
	struct dummy_wd2_hw *hw;
	struct resource *res;
	int i, ret;

	if (!of_device_is_compatible(dev->of_node, "warpdrive,wd_dummy_v2"))
		return -EINVAL;

	hw = devm_kzalloc(dev, sizeof(*hw), GFP_KERNEL);
	if (!hw)
		return -ENOMEM;

	hw->ver = 2;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "cannot find io space!\n");
		return -ENODEV;
	}
	hw->io_base = devm_ioremap_resource(dev, res);
	if (IS_ERR(hw->io_base))
		return PTR_ERR(hw->io_base);

	hw->pt = dmam_alloc_coherent(dev,
			sizeof(struct pt_entry) * MAX_PT_ENTRIES,
			&hw->pt_dma, GFP_KERNEL);
	if (!hw->pt)
		return -ENOMEM;

	hw->max_copy_size = (int)readq(hw->io_base + DUMMY2_IO_MAX_COPY_SIZE);
	mutex_init(&hw->mutex);

	for (i = 0; i < MAX_PT_ENTRIES; i++) {
		hw->pt[i].asid = (uint64_t)-1;
		hw->pt[i].iova = 0x1111222233334444;
		hw->pt[i].pa = 0x5555666677778888;
	}

	dev_info(dev, "v2 device (%llx, %llx), header: %llx\n",
		 (u64)hw->pt, hw->pt_dma, readq(hw->io_base + DUMMY2_IO_TAG));

	/* set page tables */
	writeq(hw->pt_dma, hw->io_base + DUMMY2_IO_PTPA);
	writeq(MAX_PT_ENTRIES, hw->io_base + DUMMY2_IO_PTSZ);
	for (i = 0; i < RING_NUM; i++) {
		hw->qs[i].used = false;
		hw->qs[i].db_pa = (void __iomem *)res->start +
			((i+1)<<DUMMY2_DMA_PAGE_SHIFT);
		hw->qs[i].ring_io_base = hw->io_base + DUMMY2_IO_RING_BEGIN +
			sizeof(struct ring_io) * i;
		hw->qs[i].hw = hw;
		hw->qs[i].q.priv = &hw->qs[i];
	}

	hw->dummy_wd2_dev.parent = dev;
	hw->dummy_wd2_dev.bus = &dummy_wd2_bus_type;
	hw->dummy_wd2_dev.release = dummy_wd2_dev_release;
	/* assume I have only one device now */
	dev_set_name(&hw->dummy_wd2_dev, "dummy_wd2-%d", 0);
	dev_set_drvdata(&hw->dummy_wd2_dev, hw);
	ret = device_register(&hw->dummy_wd2_dev);
	if (ret) {
		/* device_register have 2 steps, the first one always success
		 * and set refcount to 1
		 */
		goto err_with_device;
	}

	hw->iommu_group = iommu_group_alloc();
	if (IS_ERR(hw->iommu_group)) {
		ret = -ENOMEM;
		goto err_with_device;
	}

	iommu_group_set_name(hw->iommu_group, "dummy_hw2_iommu");
	iommu_group_set_iommudata(hw->iommu_group, &hw, NULL);
	ret = iommu_group_add_device(hw->iommu_group, &hw->dummy_wd2_dev);
	if (ret)
		goto err_with_group;

	uacce = devm_kzalloc(&pdev->dev, sizeof(struct uacce), GFP_KERNEL);
	if (!uacce) {
		ret = -ENOMEM;
		goto err_with_group;
	}

	platform_set_drvdata(pdev, uacce);
	uacce->name = DUMMY2_WD;
	uacce->pdev = &hw->dummy_wd2_dev;
	uacce->priv = hw;
	uacce->ops = &dummy_wd2_ops;
	uacce->drv_name = DUMMY2_WD;
	uacce->algs = "memcpy\n";
	uacce->api_ver = "dummy_v2";
	uacce->flags = 0;
	uacce->qf_pg_start[UACCE_QFRT_MMIO] = 0;
	uacce->qf_pg_start[UACCE_QFRT_DUS] = 1;
	uacce->qf_pg_start[UACCE_QFRT_SS] = 2;

	ret = uacce_register(uacce);
	if (ret) {
		dev_warn(uacce->pdev, "uacce register fail %d\n", ret);
		goto err_with_group;
	}

	return 0;

err_with_group:
	iommu_group_put(hw->iommu_group);
err_with_device:
	put_device(&hw->dummy_wd2_dev);
	return ret;
}

static int dummy_wd2_remove(struct platform_device *pdev)
{
	struct uacce *uacce = (struct uacce *)pdev->dev.driver_data;

	uacce_unregister(uacce);
	return 0;
}

static struct platform_driver dummy_wd2_pdrv = {
	.probe		= dummy_wd2_probe,
	.remove		= dummy_wd2_remove,
	.driver		= {
		.name		= DUMMY2_WD,
	},
};

static int __init dummy_wd2_init(void)
{
	int ret;

	ret = bus_register(&dummy_wd2_bus_type);
	if (ret)
		return ret;

	ret = platform_driver_register(&dummy_wd2_pdrv);
	if (ret) {
		bus_unregister(&dummy_wd2_bus_type);
		return ret;
	}

	return 0;
}

static void __exit dummy_wd2_exit(void)
{
	platform_driver_unregister(&dummy_wd2_pdrv);
	bus_unregister(&dummy_wd2_bus_type);
}

module_init(dummy_wd2_init);
module_exit(dummy_wd2_exit);

MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
MODULE_LICENSE("GPL v2");
