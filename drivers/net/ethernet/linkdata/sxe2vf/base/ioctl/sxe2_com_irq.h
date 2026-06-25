/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_irq.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_COM_IRQ_H__
#define __SXE2_COM_IRQ_H__

#include <linux/notifier.h>

#include "sxe2_ioctl_chnl.h"

struct sxe2_com_context;

struct sxe2_nb {
	struct notifier_block nb;
	u32 event_type;
	void *priv;
};

#define sxe2_nb_cof(ptr, type, member) \
	(container_of(container_of(ptr, struct sxe2_nb, nb), type, member))

#define sxe2_nb_priv(ptr) (((struct sxe2_nb *)(container_of(ptr, struct sxe2_nb, nb)))->priv)

#define SXE2_NB_INIT(name, handler, event) \
do { \
	typeof(name) _name = (name); \
	_name->nb.notifier_call = handler; \
	_name->event_type = event; \
} while (0)

struct sxe2_com_irq_entry {
	s32 vector;
	char *name;
	struct eventfd_ctx *trigger;
};

struct sxe2_com_irqs_ctxt {
	/* in order to protect the data */
	struct mutex lock;
	struct atomic_notifier_head irq_nh;
	u32 num_irqs;
	struct sxe2_com_irq_entry *entry;
	/* in order to protect the data */
	spinlock_t evt_lock;
	struct eventfd_ctx *evt_trigger;
	u64 evt_cause;
	u64 evt_sub_map;
	struct sxe2_nb evt_nb;

	struct eventfd_ctx *rst_trigger;
	struct sxe2_nb rst_nb;
};

s32 sxe2_com_irq_notifier_call_chain(struct sxe2_com_context *com_ctxt,
				     enum sxe2_com_event_cause ec);

s32 sxe2_com_io_irq_req(struct sxe2_com_context *com_ctxt, unsigned long arg);

s32 sxe2_com_event_irq_req(struct sxe2_com_context *com_ctxt, unsigned long arg);
s32 sxe2_com_reset_irq_req(struct sxe2_com_context *com_ctxt, unsigned long arg);

s32 sxe2_com_event_cause_get(struct sxe2_com_context *com_ctxt, unsigned long arg);

void sxe2_com_irqs_deinit(struct sxe2_com_context *com_ctxt);

s32 sxe2_com_irqs_init(struct sxe2_com_context *com_ctxt);
void sxe2_com_irqs_clear(struct sxe2_com_context *com_ctxt);

#endif
