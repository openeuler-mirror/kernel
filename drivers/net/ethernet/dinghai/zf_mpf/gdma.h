/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __GDMA_H
#define __GDMA_H

#include <linux/bitfield.h>
#include <linux/dinghai/driver.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_dma.h>
#include <linux/spinlock.h>

#include "./epc/virt-dma.h"

#define ZF_GDMA_CHAN_NUM (4)
#define ZF_GDMA_CHAN_BASE (58)

enum zf_gdma_chan_status { GDMA_CHAN_IDLE = 0, GDMA_CHAN_BUSY, GDMA_CHAN_ERR };

struct zf_gdma_chan {
	enum zf_gdma_chan_status status;
	u16 chan_id;

	struct list_head desc_list;
	spinlock_t chan_lock;

	struct zf_gdma_dev *gdev;
	struct zxdh_virt_dma_chan vc;
	struct zf_gdma_desc *desc;
	struct tasklet_struct task;
};

struct zf_gdma_desc {
	u64 src; /* src addr */
	u64 dst;
	u64 len;
	u32 user;
	struct zxdh_virt_dma_desc vd;
	struct list_head node;
	struct zf_gdma_chan *chan;
};

struct zf_gdma_dev {
	u64 base_addr;
	struct dma_device *dd;
	struct pci_dev *pdev;
	struct zf_gdma_chan chan[ZF_GDMA_CHAN_NUM];
};

s32 dh_zf_mpf_gdma_init(struct dh_core_dev *dh_dev);
void dh_zf_mpf_gdma_uninit(struct dh_core_dev *dh_dev);
s32 zf_gdma_err_irq_handle(struct notifier_block *nb, unsigned long action, void *data);
s32 zf_gdma_chan_irq_handle(struct notifier_block *nb, unsigned long action, void *data);
void gchan_irq_tasklet_process(unsigned long data);
static void zf_gdma_enqueue_buff(struct zf_gdma_chan *gchan);

#endif
