// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_irq.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/eventfd.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/irqreturn.h>
#include <linux/notifier.h>

#include "sxe2_com_cdev.h"
#include "sxe2_com_irq.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_compat.h"

STATIC irqreturn_t sxe2_com_io_irq_handler(int irq, void *dev)
{
	struct sxe2_com_irq_entry *entry = dev;

	if (likely(entry->trigger))
		eventfd_signal(entry->trigger, 1);

	return IRQ_HANDLED;
}

static s32 sxe2_com_io_set_trigger(struct sxe2_com_context *com_ctxt,
				   int index, int fd, irq_handler_t handler)
{
	struct sxe2_com_irq_entry *entry = &com_ctxt->irqs.entry[index];
	struct eventfd_ctx *trigger;
	int ret;

	if (entry->trigger) {
		synchronize_irq(entry->vector);
		free_irq(entry->vector, entry);
		kfree(entry->name);
		eventfd_ctx_put(entry->trigger);
		entry->trigger = NULL;
	}

	if (fd < 0)
		return 0;

	entry->name = kasprintf(GFP_KERNEL, "sxe2-com-irq[%d](%s)",
				entry->vector, com_ctxt->com_log_param.dev_name);
	if (!entry->name)
		return -ENOMEM;

	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		kfree(entry->name);
		return PTR_ERR(trigger);
	}

	entry->trigger = trigger;

	ret = request_irq(entry->vector, handler, 0, entry->name, entry);
	if (ret) {
		kfree(entry->name);
		eventfd_ctx_put(trigger);
		entry->trigger = NULL;
		return ret;
	}

	return 0;
}

STATIC s32 sxe2_com_io_irq_init(struct sxe2_com_context *com_ctxt)
{
	s32 ret;
	u32 num_irq;
	u32 i;

	if (!com_ctxt->ops || !com_ctxt->ops->get_irq_num || !com_ctxt->ops->get_vector)
		return -EFAULT;

	ret = com_ctxt->ops->get_irq_num(com_ctxt->adapter);
	if (ret <= 0) {
		LOG_ERROR_BDF_COM("get irq num failed: %d\n", ret);
		return -ENOMEM;
	}
	num_irq = ret;

	com_ctxt->irqs.entry = kcalloc(num_irq, sizeof(*com_ctxt->irqs.entry), GFP_KERNEL);
	if (!com_ctxt->irqs.entry)
		return -ENOMEM;

	for (i = 0; i < num_irq; i++) {
		com_ctxt->irqs.entry[i].vector = com_ctxt->ops->get_vector(com_ctxt->adapter, i);
		if (com_ctxt->irqs.entry[i].vector < 0)
			goto l_err;
	}
	com_ctxt->irqs.num_irqs = num_irq;

	return 0;
l_err:
	kfree(com_ctxt->irqs.entry);
	com_ctxt->irqs.entry = NULL;
	return -EINVAL;
}

STATIC void sxe2_com_io_irq_clear(struct sxe2_com_context *com_ctxt)
{
	int i;

	for (i = 0; i < com_ctxt->irqs.num_irqs; i++)
		sxe2_com_io_set_trigger(com_ctxt, i, -1, NULL);
}

STATIC void sxe2_com_io_irq_deinit(struct sxe2_com_context *com_ctxt)
{
	sxe2_com_io_irq_clear(com_ctxt);

	com_ctxt->irqs.num_irqs = 0;
	kfree(com_ctxt->irqs.entry);
}

s32 sxe2_com_io_irq_req(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_irq_set param = {};
	u32 arg_sz;
	u32 i;
	s32 *fd;

	mutex_lock(&com_ctxt->com_lock);
	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_IO_IRQS_REQ);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("get arg sz failed, ver: %d, cmd:%d\n", com_ctxt->dpdk_ver,
				  SXE2_DEVICE_IO_IRQS_REQ);
		ret = -EINVAL;
		goto l_end;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&param, (void __user *)arg, arg_sz)) {
		ret = -EFAULT;
		goto l_end;
	}

	if (param.cnt == 0 || param.cnt > com_ctxt->irqs.num_irqs ||
	    param.base_irq_in_com + param.cnt - 1 > com_ctxt->irqs.num_irqs - 1 ||
	    !param.event_fd) {
		ret = -EINVAL;
		goto l_end;
	}

	fd = memdup_user((void __user *)(param.event_fd), param.cnt * sizeof(*param.event_fd));
	if (IS_ERR(fd)) {
		ret = PTR_ERR(fd);
		goto l_end;
	}

	for (i = 0; i < param.cnt; i++) {
		ret = sxe2_com_io_set_trigger(com_ctxt, i + param.base_irq_in_com,
					      fd[i], sxe2_com_io_irq_handler);
		if (ret)
			goto l_roll_back;
	}

	goto l_free;

l_roll_back:
	for (i = 0; i < param.cnt; i++)
		(void)sxe2_com_io_set_trigger(com_ctxt, i + param.base_irq_in_com, -1, NULL);
l_free:
	kfree(fd);
l_end:
	LOG_INFO_BDF_COM("cnt:%u:%u, base_irq_in_com: %u, ret: %d.\n", param.cnt,
			 com_ctxt->irqs.num_irqs, param.base_irq_in_com, ret);
	mutex_unlock(&com_ctxt->com_lock);
	return ret;
}

STATIC s32 sxe2_com_irq_notifier_register(struct sxe2_com_context *com_ctxt,
					  struct sxe2_nb *irq_nb)
{
	return atomic_notifier_chain_register(&com_ctxt->irqs.irq_nh, &irq_nb->nb);
}

STATIC s32 sxe2_com_irq_notifier_unregister(struct sxe2_com_context *com_ctxt,
					    struct sxe2_nb *irq_nb)
{
	return atomic_notifier_chain_unregister(&com_ctxt->irqs.irq_nh, &irq_nb->nb);
}

s32 sxe2_com_irq_notifier_call_chain(struct sxe2_com_context *com_ctxt,
				     enum sxe2_com_event_cause ec)
{
	SXE2_BUG_ON(ec >= SXE2_COM_EC_MAX);
	if (ec >= SXE2_COM_EC_MAX)
		return -EFAULT;

	return atomic_notifier_call_chain(&com_ctxt->irqs.irq_nh, ec, NULL);
}

STATIC u64 sxe2_com_event_cause_rc(struct sxe2_com_context *com_ctxt)
{
	u64 ec;
	unsigned long flags;

	spin_lock_irqsave(&com_ctxt->irqs.evt_lock, flags);
	ec = com_ctxt->irqs.evt_cause;
	com_ctxt->irqs.evt_cause = 0;
	spin_unlock_irqrestore(&com_ctxt->irqs.evt_lock, flags);

	return ec;
}

STATIC s32 sxe2_com_event_nb_call(struct notifier_block *nb, unsigned long event, void *data)
{
	struct sxe2_com_irqs_ctxt *irqs = sxe2_nb_cof(nb, struct sxe2_com_irqs_ctxt, evt_nb);
	enum sxe2_com_event_cause ec = (enum sxe2_com_event_cause)event;
	unsigned long flags;

	SXE2_BUG_ON(ec >= SXE2_COM_EC_MAX);
	if (ec >= SXE2_COM_EC_MAX)
		return NOTIFY_BAD;

	if (ec == SXE2_COM_EC_RESET)
		return NOTIFY_DONE;

	spin_lock_irqsave(&irqs->evt_lock, flags);
	if (!test_bit(ec, (unsigned long *)&irqs->evt_sub_map)) {
		spin_unlock_irqrestore(&irqs->evt_lock, flags);
		return NOTIFY_DONE;
	}

	set_bit(ec, (unsigned long *)&irqs->evt_cause);
	spin_unlock_irqrestore(&irqs->evt_lock, flags);

	eventfd_signal(irqs->evt_trigger, 1);

	return NOTIFY_OK;
}

STATIC void sxe2_com_event_irq_init(struct sxe2_com_context *com_ctxt)
{
	spin_lock_init(&com_ctxt->irqs.evt_lock);
	com_ctxt->irqs.evt_sub_map = 0;
	com_ctxt->irqs.evt_trigger = NULL;

	SXE2_NB_INIT(&com_ctxt->irqs.evt_nb, sxe2_com_event_nb_call, 0);
}

STATIC void sxe2_com_event_irq_clear(struct sxe2_com_context *com_ctxt)
{
	com_ctxt->irqs.evt_sub_map = 0;

	if (com_ctxt->irqs.evt_trigger) {
		eventfd_ctx_put(com_ctxt->irqs.evt_trigger);
		com_ctxt->irqs.evt_trigger = NULL;
		sxe2_com_irq_notifier_unregister(com_ctxt, &com_ctxt->irqs.evt_nb);
	}
}

STATIC void sxe2_com_event_irq_deinit(struct sxe2_com_context *com_ctxt)
{
	sxe2_com_event_irq_clear(com_ctxt);
	SXE2_NB_INIT(&com_ctxt->irqs.evt_nb, NULL, 0);
}

s32 sxe2_com_event_irq_req(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_other_evt_set param = {};
	u32 arg_sz;
	struct eventfd_ctx *trigger;

	mutex_lock(&com_ctxt->com_lock);
	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_EVT_IRQ_REQ);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("sxe2_com_get_arg_sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver,
				  SXE2_DEVICE_EVT_IRQ_REQ);
		goto l_end;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&param, (void __user *)arg, arg_sz)) {
		ret = -EFAULT;
		goto l_end;
	}

	if ((param.eventfd >= 0 && com_ctxt->irqs.evt_trigger) ||
	    (param.eventfd < 0 && !com_ctxt->irqs.evt_trigger) ||
	    (param.eventfd >= 0 && param.filter_table == 0)) {
		ret = -EINVAL;
		goto l_end;
	}

	if (param.eventfd < 0) {
		sxe2_com_irq_notifier_unregister(com_ctxt, &com_ctxt->irqs.evt_nb);
		eventfd_ctx_put(com_ctxt->irqs.evt_trigger);
		com_ctxt->irqs.evt_trigger = NULL;
		com_ctxt->irqs.evt_sub_map = 0;
		goto l_end;
	}

	trigger = eventfd_ctx_fdget(param.eventfd);
	if (IS_ERR(trigger)) {
		ret = PTR_ERR(trigger);
		goto l_end;
	}
	com_ctxt->irqs.evt_trigger = trigger;
	com_ctxt->irqs.evt_sub_map = param.filter_table;
	sxe2_com_irq_notifier_register(com_ctxt, &com_ctxt->irqs.evt_nb);

l_end:
	LOG_INFO_BDF_COM("eventfd:%d, filter_table: %llu, ret: %d.\n", param.eventfd,
			 param.filter_table, ret);
	mutex_unlock(&com_ctxt->com_lock);
	return ret;
}

s32 sxe2_com_event_cause_get(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_other_evt_get ec = {};
	u32 arg_sz;

	mutex_lock(&com_ctxt->com_lock);
	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_EVT_CAUSE_GET);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("get arg sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver,
				  SXE2_DEVICE_EVT_CAUSE_GET);
		goto l_end;
	}

	arg_sz = ret;
	ret = 0;

	ec.evt_cause = sxe2_com_event_cause_rc(com_ctxt);

	if (copy_to_user((void __user *)arg, &ec, arg_sz)) {
		ret = -EFAULT;
		goto l_end;
	}

	LOG_INFO_BDF_COM("ec:%llu, ret: %d.\n", ec.evt_cause, ret);

l_end:
	mutex_unlock(&com_ctxt->com_lock);
	return ret;
}

s32 sxe2_com_reset_irq_req(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_reset_sub_set param = {};
	u32 arg_sz;
	struct eventfd_ctx *trigger;

	mutex_lock(&com_ctxt->com_lock);
	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_RST_IRQ_REQ);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("sxe2_com_get_arg_sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver,
				  SXE2_DEVICE_RST_IRQ_REQ);
		goto l_end;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&param, (void __user *)arg, arg_sz)) {
		ret = -EFAULT;
		goto l_end;
	}

	if ((param.eventfd >= 0 && com_ctxt->irqs.rst_trigger) ||
	    (param.eventfd < 0 && !com_ctxt->irqs.rst_trigger)) {
		ret = -EINVAL;
		goto l_end;
	}

	if (param.eventfd < 0) {
		sxe2_com_irq_notifier_unregister(com_ctxt, &com_ctxt->irqs.rst_nb);
		eventfd_ctx_put(com_ctxt->irqs.rst_trigger);
		com_ctxt->irqs.rst_trigger = NULL;
		goto l_end;
	}

	trigger = eventfd_ctx_fdget(param.eventfd);
	if (IS_ERR(trigger)) {
		ret = PTR_ERR(trigger);
		goto l_end;
	}
	com_ctxt->irqs.rst_trigger = trigger;
	sxe2_com_irq_notifier_register(com_ctxt, &com_ctxt->irqs.rst_nb);

l_end:
	LOG_INFO_BDF_COM("eventfd:%d, ret: %d.\n", param.eventfd, ret);
	mutex_unlock(&com_ctxt->com_lock);
	return ret;
}

static s32 sxe2_com_reset_nb_call(struct notifier_block *nb, unsigned long event, void *data)
{
	struct sxe2_com_irqs_ctxt *irqs = sxe2_nb_cof(nb, struct sxe2_com_irqs_ctxt, rst_nb);
	enum sxe2_com_event_cause ec = (enum sxe2_com_event_cause)event;

	if (ec != SXE2_COM_EC_RESET)
		return NOTIFY_DONE;

	eventfd_signal(irqs->rst_trigger, 1);

	return NOTIFY_OK;
}

STATIC void sxe2_com_reset_irq_init(struct sxe2_com_context *com_ctxt)
{
	com_ctxt->irqs.rst_trigger = NULL;
	SXE2_NB_INIT(&com_ctxt->irqs.rst_nb, sxe2_com_reset_nb_call, 0);
}

STATIC void sxe2_com_reset_irq_clear(struct sxe2_com_context *com_ctxt)
{
	if (com_ctxt->irqs.rst_trigger) {
		eventfd_ctx_put(com_ctxt->irqs.rst_trigger);
		com_ctxt->irqs.rst_trigger = NULL;
		sxe2_com_irq_notifier_unregister(com_ctxt, &com_ctxt->irqs.rst_nb);
	}
}

STATIC void sxe2_com_reset_irq_deinit(struct sxe2_com_context *com_ctxt)
{
	sxe2_com_reset_irq_clear(com_ctxt);

	SXE2_NB_INIT(&com_ctxt->irqs.rst_nb, NULL, 0);
}

s32 sxe2_com_irqs_init(struct sxe2_com_context *com_ctxt)
{
	(void)sxe2_com_io_irq_init(com_ctxt);

	sxe2_com_event_irq_init(com_ctxt);

	sxe2_com_reset_irq_init(com_ctxt);

	return 0;
}

void sxe2_com_irqs_clear(struct sxe2_com_context *com_ctxt)
{
	mutex_lock(&com_ctxt->com_lock);

	sxe2_com_reset_irq_clear(com_ctxt);
	sxe2_com_event_irq_clear(com_ctxt);
	sxe2_com_io_irq_clear(com_ctxt);
	mutex_unlock(&com_ctxt->com_lock);
}

void sxe2_com_irqs_deinit(struct sxe2_com_context *com_ctxt)
{
	sxe2_com_reset_irq_deinit(com_ctxt);
	sxe2_com_event_irq_deinit(com_ctxt);
	sxe2_com_io_irq_deinit(com_ctxt);
}
