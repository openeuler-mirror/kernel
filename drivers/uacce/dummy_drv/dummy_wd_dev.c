// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018-2019 HiSilicon Limited. */
/**
 * This module is used to test the framework of WarpDrive.
 *
 * It creates MAX_DEV platform devices with MAX_QUEUE queue for each. When the
 * queue is gotten, a kernel thread is created and handle request put into the
 * queue by the user application.
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

#define MAX_DEV 3
#define MAX_QUEUE 4
#define QUEUE_YEILD_MS 50
#define VERBOSE_LOG

#define MODE_MMIO 0	/* use mmio region for bd */
#define MODE_DSU  1	/* use dsu region for bd */
static int mode = MODE_DSU;
module_param(mode, int, 0);

static DEFINE_MUTEX(qsmutex);

struct dummy_hw;

struct dummy_hw_queue {
	bool used;
	struct task_struct *tsk;
	__u32 tail;
	struct uacce_qfile_region *ss_qfr;

	struct uacce_queue wdq;
	struct dummy_hw_queue_reg *reg;
	struct dummy_hw *hw;
	struct task_struct *work_thread;
	struct mutex mutex;
	int is_updated;
	int devid, qid;
};

static struct dummy_hw {
	int max_copy_size;
	int aflags;
	struct dummy_hw_queue qs[MAX_QUEUE];
	struct platform_device *pdev;
} hws[MAX_DEV];

static int _do_copy(struct uacce_queue *q, void *tgt, void *src, size_t len)
{
	struct uacce_qfile_region *ss_qfr = q->qfrs[UACCE_QFRT_SS];
	int ret = 0;
	size_t iova_base = q->qfrs[UACCE_QFRT_SS]->iova;
	size_t ktgt = (unsigned long)tgt - iova_base;
	size_t ksrc = (unsigned long)src - iova_base;
	size_t range = ss_qfr->nr_pages << PAGE_SHIFT;

	if (ktgt + len > range) {
		dev_dbg(&q->uacce->dev, "ktgt(%lx, %lx) not in range(%lx)\n",
			ktgt, len, range);
		ret = -EINVAL;
		goto out;
	}

	if (ksrc + len > range) {
		dev_dbg(&q->uacce->dev, "ksrc(%lx, %lx) not in range(%lx)\n",
			ksrc, len, range);
		ret = -EINVAL;
		goto out;
	}

	ktgt += (unsigned long)ss_qfr->kaddr;
	ksrc += (unsigned long)ss_qfr->kaddr;
	memcpy((void *)ktgt, (void *)ksrc, len);

out:
	return ret;
}

static void _queue_work(struct dummy_hw_queue *hwq)
{
	int bd_num;
	__u32 head;
	__u32 tail;
	struct device *dev = &hwq->wdq.uacce->dev;

	mutex_lock(&hwq->mutex);

	bd_num = hwq->reg->ring_bd_num;
	head = readl(&hwq->reg->head);

	if (head >= bd_num) {
		dev_err(dev, "dummy_wd io error, head=%d\n", head);
		mutex_unlock(&hwq->mutex);
		return;
	}

	tail = hwq->tail;
	while (hwq->tail != head) {
		if (hwq->reg->ring[hwq->tail].size > hwq->hw->max_copy_size)
			hwq->reg->ring[hwq->tail].ret = -EINVAL;
		else
			hwq->reg->ring[hwq->tail].ret = _do_copy(&hwq->wdq,
				 hwq->reg->ring[hwq->tail].tgt_addr,
				 hwq->reg->ring[hwq->tail].src_addr,
				 hwq->reg->ring[hwq->tail].size);
		dev_dbg(dev, "memcpy(%pK, %pK, %ld) = %d",
			hwq->reg->ring[hwq->tail].tgt_addr,
			hwq->reg->ring[hwq->tail].src_addr,
			hwq->reg->ring[hwq->tail].size,
			hwq->reg->ring[hwq->tail].ret);
		hwq->tail = (hwq->tail+1)%bd_num;
	}

	if (tail != hwq->tail) {
		dev_dbg(dev, "write back tail %d\n", hwq->tail);
		writel(hwq->tail, &hwq->reg->tail);
		hwq->is_updated = 1;
		uacce_wake_up(&hwq->wdq);
	}

	mutex_unlock(&hwq->mutex);
}

static int dummy_is_q_updated(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;
	int updated;

	mutex_lock(&hwq->mutex);

	updated = hwq->is_updated;
	hwq->is_updated = 0;

	mutex_unlock(&hwq->mutex);

	dev_dbg(&q->uacce->dev, "check q updated: %d\n", updated);

	return updated;
}

static int dummy_get_queue(struct uacce *uacce, unsigned long arg,
			   struct uacce_queue **q)
{
	int i;
	struct dummy_hw *hw = (struct dummy_hw *)uacce->priv;
	struct dummy_hw_queue *devqs = hw->qs;

	WARN_ON(!devqs);

	mutex_lock(&qsmutex);
	for (i = 0; i < MAX_QUEUE; i++) {
		if (!devqs[i].used) {
			devqs[i].used = 1;
			devqs[i].reg->head = 0;
			devqs[i].reg->tail = 0;
			devqs[i].tail = 0;
			devqs[i].is_updated = 0;
			*q = &devqs[i].wdq;
			devqs[i].wdq.priv = &devqs[i];
			dev_dbg(uacce->pdev, "allocate hw q %d\n", i);
			break;
		}
	}
	mutex_unlock(&qsmutex);

	if (i < MAX_QUEUE)
		return 0;

	return -ENODEV;
}

static void dummy_put_queue(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;

	mutex_lock(&qsmutex);
	hwq->used = 0;
	mutex_unlock(&qsmutex);
}

static int dummy_mmap(struct uacce_queue *q, struct vm_area_struct *vma,
		      struct uacce_qfile_region *qfr)
{
	struct dummy_hw_queue *hwq = (struct dummy_hw_queue *)q->priv;
	struct page *page = virt_to_page(hwq->reg);

	dev_dbg(&q->uacce->dev, "mmap mmio space (ref=%d)\n",
		page_ref_count(page));
	if (vma->vm_pgoff != 0 || qfr->nr_pages > 1 ||
	    !(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, __pa(hwq->reg)>>PAGE_SHIFT,
			       PAGE_SIZE, vma->vm_page_prot);
}

static long dummy_ioctl(struct uacce_queue *q, unsigned int cmd,
				unsigned long arg)
{
	struct dummy_hw_queue *hwq = q->priv;

	switch (cmd) {
	case DUMMY_CMD_FLUSH:
		_queue_work(hwq);
		return 0;

	default:
		return -EINVAL;
	}
}

static void dummy_mask_notify(struct uacce_queue *q, int event_mask)
{
	dev_dbg(&q->uacce->dev, "mask notify: %x\n", event_mask);
}

int queue_worker(void *data)
{
	struct dummy_hw_queue *hwq = data;

	do {
		_queue_work(hwq);
		schedule_timeout_interruptible(
			msecs_to_jiffies(QUEUE_YEILD_MS));
	} while (!kthread_should_stop());
	hwq->work_thread = NULL;

	return 0;
}

static int dummy_start_queue(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;

	hwq->work_thread = kthread_run(queue_worker, hwq,
				       "dummy_queue_worker %d-%d",
				       hwq->devid, hwq->qid);
	if (PTR_ERR_OR_ZERO(hwq->work_thread))
		return PTR_ERR(hwq->work_thread);

	dev_dbg(&q->uacce->dev, "queue start\n");
	return 0;
}

void dummy_stop_queue(struct uacce_queue *q)
{
	struct dummy_hw_queue *hwq = q->priv;

	if (hwq->work_thread)
		kthread_stop(hwq->work_thread);

}

static int dummy_get_available_instances(struct uacce *uacce)
{
	int i, ret;
	struct dummy_hw *hw = (struct dummy_hw *)uacce->priv;
	struct dummy_hw_queue *devqs = hw->qs;

	mutex_lock(&qsmutex);
	for (i = 0, ret = 0; i < MAX_QUEUE; i++) {
		if (!devqs[i].used)
			ret++;
	}
	mutex_unlock(&qsmutex);

	return ret;
}

static struct uacce_ops dummy_ops = {
	.get_queue = dummy_get_queue,
	.put_queue = dummy_put_queue,
	.start_queue = dummy_start_queue,
	.stop_queue = dummy_stop_queue,
	.is_q_updated = dummy_is_q_updated,
	.mmap = dummy_mmap,
	.ioctl = dummy_ioctl,
	.mask_notify = dummy_mask_notify,
	.get_available_instances = dummy_get_available_instances,
};

static int dummy_wd_probe(struct platform_device *pdev)
{
	struct uacce *uacce;
	struct dummy_hw *hw;
	int i, ret;

	if (pdev->id >= MAX_DEV) {
		dev_err(&pdev->dev, "invalid id (%d) for dummy_wd\n", pdev->id);
		return -EINVAL;
	}

	ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret < 0)
		return -EINVAL;

	hw = &hws[pdev->id];
	hw->aflags = 0;
	hw->max_copy_size = 4096;

	uacce = devm_kzalloc(&pdev->dev, sizeof(struct uacce), GFP_KERNEL);
	if (!uacce)
		return -ENOMEM;

	platform_set_drvdata(pdev, uacce);
	uacce->name = DUMMY_WD;
	uacce->pdev = &pdev->dev;
	uacce->priv = hw;
	uacce->ops = &dummy_ops;
	uacce->drv_name = DUMMY_WD;
	uacce->algs = "memcpy\n";
	uacce->api_ver = "dummy_v1";
	uacce->flags = UACCE_DEV_NOIOMMU;
	uacce->qf_pg_start[UACCE_QFRT_MMIO] = 0;
	uacce->qf_pg_start[UACCE_QFRT_DUS] = UACCE_QFR_NA;
	uacce->qf_pg_start[UACCE_QFRT_SS] = 1;

#ifdef CONFIG_NUMA
	/*
	 * Emulate numa id if there's no platform dummy device.
	 * Try to bind each dummy device to each numa node. If there're more
	 * dummy devices than numa nodes, the numa_node should be binded to
	 * the last numa node.
	 */
	if (uacce->pdev->numa_node < 0) {
		if (cpu_to_node(nr_cpu_ids - 1) > pdev->id)
			uacce->pdev->numa_node = pdev->id;
		else
			uacce->pdev->numa_node = cpu_to_node(nr_cpu_ids - 1);
	}
#endif

	for (i = 0; i < MAX_QUEUE; i++) {
		hw->qs[i].wdq.uacce = uacce;
		hw->qs[i].hw = hw;
		hw->qs[i].reg = (struct dummy_hw_queue_reg *)
			__get_free_page(GFP_KERNEL);
		memcpy(hw->qs[i].reg->hw_tag, DUMMY_HW_TAG, DUMMY_HW_TAG_SZ);
		hw->qs[i].reg->ring_bd_num = Q_BDS;
		hw->qs[i].reg->head = 0;
		hw->qs[i].reg->tail = 0;
		hw->qs[i].tail = 0;
		hw->qs[i].is_updated = 0;
		hw->qs[i].devid = pdev->id;
		hw->qs[i].qid = i;

		mutex_init(&hw->qs[i].mutex);
	}

	return uacce_register(uacce);
}

static int dummy_wd_remove(struct platform_device *pdev)
{
	struct uacce *uacce = (struct uacce *)pdev->dev.driver_data;
	struct dummy_hw *hw = &hws[pdev->id];
	int i;

	uacce_unregister(uacce);
	for (i = 0; i < MAX_QUEUE; i++)
		free_page((unsigned long)hw->qs[i].reg);
	return 0;
}

static struct platform_driver dummy_pdrv = {
	.probe		= dummy_wd_probe,
	.remove		= dummy_wd_remove,
	.driver		= {
		.name		= DUMMY_WD,
	},
};

static int __init dummy_uacce_init(void)
{
	int i, j;
	int ret = platform_driver_register(&dummy_pdrv);

	if (ret)
		return ret;

	for (i = 0; i < MAX_DEV; i++) {
		hws[i].pdev = platform_device_alloc(DUMMY_WD, i);
		WARN_ON(!hws[i].pdev);
		ret = platform_device_add(hws[i].pdev);
		if (ret)
			goto dev_reg_fail;
	}

	return 0;


dev_reg_fail:
	for (j = i - 1; j >= 0; j--) {
		if (hws[i].pdev)
			platform_device_put(hws[i].pdev);
	}

	platform_driver_unregister(&dummy_pdrv);

	return ret;
}

static void __exit dummy_uacce_exit(void)
{
	int i;

	for (i = MAX_DEV - 1; i >= 0; i--)
		platform_device_unregister(hws[i].pdev);

	platform_driver_unregister(&dummy_pdrv);
}

module_init(dummy_uacce_init);
module_exit(dummy_uacce_exit);

MODULE_AUTHOR("Kenneth Lee<liguozhu@hisilicon.com>");
MODULE_LICENSE("GPL v2");
