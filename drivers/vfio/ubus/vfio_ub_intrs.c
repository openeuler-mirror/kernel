// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 * Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * Thanks to Alex Williamson and Tom Lyon for their original
 * vfio implementation.
 *
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "vfio ub: " fmt

#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/vfio.h>
#include <linux/eventfd.h>
#include <linux/slab.h>

#include "vfio_ub_private.h"

static const char *ub_get_name(const struct ub_entity *uent)
{
	return dev_name(&uent->dev);
}

static irqreturn_t vfio_ub_intr_handler(int irq, void *arg)
{
	struct eventfd_ctx *trigger = (struct eventfd_ctx *)arg;

	eventfd_signal(trigger, 1);
	return IRQ_HANDLED;
}

static int vfio_ub_intr_tid_update(struct vfio_ub_core_device *vdev, int vector)
{
	void __iomem *vaddr;
	u32 tid, addr_num;
	u16 addr_idx;
	int ret;

	vaddr = ub_iomap(vdev->uent, 0, 0);
	if (!vaddr)
		return -ENOMEM;

	ret = ub_cfg_read_dword(vdev->uent, UB_ENTITY_TOKEN_ID, &tid);
	if (ret) {
		ub_iounmap(vaddr);
		return ret;
	}

	addr_num = ub_intr_addr_count(vdev->uent);
	addr_idx = readl(vaddr + vdev->usi_vector_offset +
			 vector * UB_INTR_VECTOR_ENTRY_SIZE +
			 UB_INTR_VECTOR_ADDR_INDEX) & GENMASK(15, 0);
	if (addr_idx >= addr_num) {
		ub_iounmap(vaddr);
		ub_err(vdev->uent, "invalid usi addr table info, addr_idx=%#x, addr_num=%#x\n",
		       addr_idx, addr_num);
		return -EFAULT;
	}

	writel(0, vaddr + vdev->usi_addr_offset + addr_idx * UB_INTR_ADDR_ENTRY_SIZE +
		UB_INTR_ADDR_TOKENID);
	writel((tid & UB_INTR_ADDR_TOKENID_MASK) | (0x1 << UB_INTR_ADDR_VALID_BIT),
		vaddr + vdev->usi_addr_offset + addr_idx * UB_INTR_ADDR_ENTRY_SIZE +
		UB_INTR_ADDR_TOKENID);

	ub_iounmap(vaddr);
	return 0;
}

static int vfio_ub_intr_set_vector_signal(struct vfio_ub_core_device *vdev,
					  int vector, int eventfd)
{
	struct ub_entity *uent = vdev->uent;
	struct eventfd_ctx *trigger;
	int irq_vec, ret;

	irq_vec = ub_irq_vector(uent, vector);

	/* if already assigned interrupts, just free it and reassigned it later. */
	if (vdev->ctx[vector].trigger != NULL) {
		irq_bypass_unregister_producer(&vdev->ctx[vector].producer);
		free_irq(irq_vec, vdev->ctx[vector].trigger);
		kfree(vdev->ctx[vector].name);
		eventfd_ctx_put(vdev->ctx[vector].trigger);
		vdev->ctx[vector].trigger = NULL;
	}

	if (eventfd < 0)
		return 0;

	vdev->ctx[vector].name = kasprintf(GFP_KERNEL, "vfio-ub-intr[%d](%s)",
					   vector, ub_get_name(uent));
	if (!vdev->ctx[vector].name)
		return -ENOMEM;

	trigger = eventfd_ctx_fdget(eventfd);
	if (IS_ERR(trigger)) {
		ret = PTR_ERR(trigger);
		goto err_kasprintf;
	}

	ret = request_irq(irq_vec, vfio_ub_intr_handler, 0,
			  vdev->ctx[vector].name, trigger);
	if (ret)
		goto err_eventfd;

	ret = vfio_ub_intr_tid_update(vdev, vector);
	if (ret)
		goto err_irq;

	vdev->ctx[vector].producer.irq = irq_vec;
	vdev->ctx[vector].producer.token = trigger;
	ret = irq_bypass_register_producer(&vdev->ctx[vector].producer);
	if (unlikely(ret)) {
		ub_info(uent,
			"irq bypass producer registration failed, ret=%d\n", ret);
		vdev->ctx[vector].producer.token = NULL;
	}
	vdev->ctx[vector].trigger = trigger;

	return 0;

err_irq:
	free_irq(irq_vec, trigger);
err_eventfd:
	eventfd_ctx_put(trigger);
err_kasprintf:
	kfree(vdev->ctx[vector].name);
	vdev->ctx[vector].name = NULL;
	return ret;
}

static int vfio_ub_intr_set_block(struct vfio_ub_core_device *vdev, unsigned int start,
				  unsigned int count, int32_t *fds)
{
	int i, j, ret = 0;

	if ((start >= vdev->num_ctx) || ((start + count) > vdev->num_ctx))
		return -EINVAL;

	for (i = 0, j = (int)start; i < (int)count; i++, j++) {
		int fd = fds ? fds[i] : -1;

		ret = vfio_ub_intr_set_vector_signal(vdev, j, fd);
		if (ret)
			break;
	}

	if (ret) {
		for (--j; j >= (int)start; j--)
			vfio_ub_intr_set_vector_signal(vdev, j, -1);
	}

	return ret;
}

static void vfio_ub_intr_disable(struct vfio_ub_core_device *vdev)
{
	struct ub_entity *uent = vdev->uent;

	vfio_ub_intr_set_block(vdev, 0, vdev->num_ctx, NULL);

	ub_disable_intr(uent);

	vdev->irq_type = VFIO_UB_NUM_IRQS;
	vdev->num_ctx = 0;
	kfree(vdev->ctx);
	vdev->ctx = NULL;
}

static int vfio_ub_intr_enable(struct vfio_ub_core_device *vdev, int nvec)
{
	struct ub_entity *uent = vdev->uent;
	int ret;

	vdev->ctx = kcalloc(nvec, sizeof(struct vfio_ub_irq_ctx), GFP_KERNEL);
	if (!vdev->ctx)
		return -ENOMEM;

	ret = ub_alloc_irq_vectors(uent, 1, nvec);
	if (ret < nvec) {
		if (ret > 0)
			ub_disable_intr(uent);
		kfree(vdev->ctx);
		vdev->ctx = NULL;
		return ret;
	}

	vdev->num_ctx = nvec;
	vdev->irq_type = VFIO_UB_INTR_IRQ_INDEX;

	return 0;
}

static int vfio_ub_intr_irq_trigger(struct vfio_ub_core_device *vdev,
				    unsigned int index, unsigned int start,
				    unsigned int count, uint32_t flags, void *data)
{
	int ret;
	unsigned int i;

	if (irq_is(vdev, index) && !count && (flags & VFIO_IRQ_SET_DATA_NONE)) {
		vfio_ub_intr_disable(vdev);
		return 0;
	}

	/* DATA_EVENTFD with ACTION_TRIGGER means set irqs */
	if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		int32_t *fds = (int32_t *)data;

		/* if ub device irq has setted, then update irq eventfd handler */
		if (irq_is(vdev, index))
			return vfio_ub_intr_set_block(vdev, start, count, fds);

		ret = vfio_ub_intr_enable(vdev, start + count);
		if (ret)
			return ret;

		ret = vfio_ub_intr_set_block(vdev, start, count, fds);
		if (ret)
			vfio_ub_intr_disable(vdev);

		return ret;
	}

	if (!irq_is(vdev, index) || ((start + count) > vdev->num_ctx))
		return -EINVAL;

	for (i = start; i < (start + count); i++) {
		if (!vdev->ctx[i].trigger)
			continue;
		/* DATA_NONE with ACTION_TRIGGER means trigger all irqs */
		if (flags & VFIO_IRQ_SET_DATA_NONE) {
			eventfd_signal(vdev->ctx[i].trigger, 1);
		} else if (flags & VFIO_IRQ_SET_DATA_BOOL) {
			/* DATA_BOOL with ACTION_TRIGGER means trigger sparse irqs */
			uint8_t *bools = (uint8_t *)data;

			if (bools[i - start])
				eventfd_signal(vdev->ctx[i].trigger, 1);
		}
	}

	return 0;
}

static int vfio_ub_set_ctx_trigger_single(struct eventfd_ctx **ctx_pptr,
					  unsigned int num, uint32_t flags,
					  void *data)
{
	struct eventfd_ctx *efdctx;
	int32_t file_desc;

	if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		if (!num)
			return -EINVAL;

		file_desc = *(int32_t *)data;
		if (file_desc == -1) {
			if (*ctx_pptr)
				eventfd_ctx_put(*ctx_pptr);
			*ctx_pptr = NULL;
		} else if (file_desc >= 0) {
			efdctx = eventfd_ctx_fdget(file_desc);
			if (IS_ERR(efdctx))
				return PTR_ERR(efdctx);

			if (*ctx_pptr)
				eventfd_ctx_put(*ctx_pptr);

			*ctx_pptr = efdctx;
		}
		return 0;
	}

	return -EINVAL;
}

static int vfio_ub_set_req_trigger(struct vfio_ub_core_device *vdev,
				   unsigned int index, unsigned int start,
				   unsigned int count, uint32_t flags, void *data)
{
	if (index != VFIO_UB_REQ_IRQ_INDEX || start != 0 || count > 1)
		return -EINVAL;

	return vfio_ub_set_ctx_trigger_single(&vdev->req_trigger, count, flags, data);
}

static int vfio_ub_set_reinit_trigger(struct vfio_ub_core_device *vdev,
				      unsigned int index, unsigned int start,
				      unsigned int count, uint32_t flags,
				      void *data)
{
	if (index != VFIO_UB_REINIT_IRQ_INDEX || start != 0 || count > 1)
		return -EINVAL;

	return vfio_ub_set_ctx_trigger_single(&vdev->reinit_trigger, count, flags, data);
}

int vfio_ub_set_irqs_ioctl(struct vfio_ub_core_device *vdev, uint32_t flags,
			   unsigned int index, unsigned int start,
			   unsigned int count, void *data)
{
	int ret = 0;

	switch (index) {
	case VFIO_UB_INTR_IRQ_INDEX:
		if (flags & VFIO_IRQ_SET_ACTION_TRIGGER)
			ret = vfio_ub_intr_irq_trigger(vdev, index, start,
						       count, flags, data);
		break;
	case VFIO_UB_REQ_IRQ_INDEX:
		if (flags & VFIO_IRQ_SET_ACTION_TRIGGER)
			ret = vfio_ub_set_req_trigger(vdev, index, start,
						      count, flags, data);
		break;
	case VFIO_UB_REINIT_IRQ_INDEX:
		if (flags & VFIO_IRQ_SET_ACTION_TRIGGER)
			ret = vfio_ub_set_reinit_trigger(vdev, index, start,
							 count, flags, data);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}
