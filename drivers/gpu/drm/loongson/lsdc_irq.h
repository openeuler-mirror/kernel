/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#ifndef __LSDC_IRQ_H__
#define __LSDC_IRQ_H__

irqreturn_t lsdc_irq_thread_cb(int irq, void *arg);
irqreturn_t lsdc_irq_handler_cb(int irq, void *arg);

#endif
