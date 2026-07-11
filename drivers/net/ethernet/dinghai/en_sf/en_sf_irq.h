/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_SF_IRQ_H__
#define __EN_SF_IRQ_H__
#include <linux/dinghai/dinghai_irq.h>
#include <linux/dinghai/driver.h>

struct dh_irq *dh_pf_async_irq_request(struct dh_core_dev *dev);
s32 dh_pf_irq_table_create(struct dh_core_dev *dev);
void dh_pf_irq_table_destroy(struct dh_core_dev *dev);
s32 dh_pf_irq_table_init(struct dh_core_dev *dev);

struct dh_en_sf_irq_table {
	struct dh_irq_pool *sf_vq_pool;
};

#endif
