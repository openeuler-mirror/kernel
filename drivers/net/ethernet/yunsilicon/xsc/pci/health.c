// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "common/driver.h"
#include "health.h"
#include "devlink.h"

static char *syndstr(u8 syndrome)
{
	switch (syndrome) {
	case XSC_HEALTH_SYNDROME_FW_INTERNAL_ERR:
		return "fw internal error";
	case XSC_HEALTH_SYNDROME_HIGH_TEMP_ERR:
		return "high temperature";
	case XSC_HEALTH_SYNDROME_HW_FATAL_ERR:
		return "unrecoverable hardware error";
	case XSC_HEALTH_SYNDROME_PCI_ERR:
		return "pci error";
	default:
		return "unrecognized error";
	}
}

static u32 xsc_get_nic_state(struct xsc_core_device *dev)
{
	struct xsc_core_health *h = &dev->priv.health;

	return h->nic_state ? *h->nic_state : 0;
}

static void xsc_handle_bad_state(struct xsc_core_device *dev)
{
	xsc_disable_device(dev);
}

int xsc_pci_not_working(struct xsc_core_device *dev)
{
	struct xsc_core_health *h = &dev->priv.health;

	return h->nic_state ? *h->nic_state == 0xffffffff : 0;
}

static int xsc_health_wait_pci_up(struct xsc_core_device *dev)
{
	unsigned long end;

	end = jiffies + msecs_to_jiffies(XSC_FW_RESET_MS);
	while (xsc_pci_not_working(dev)) {
		if (time_after(jiffies, end))
			return -ETIMEDOUT;
		if (pci_channel_offline(dev->pdev)) {
			xsc_core_err(dev, "PCI channel offline, stop waiting for PCI.\n");
			return -EACCES;
		}
		msleep(100);
	}

	return 0;
}

static int xsc_health_try_recover_device(struct xsc_core_device *dev)
{
	struct xsc_core_health *h = &dev->priv.health;

	xsc_core_warn(dev, "handling bad device here.\n");
	xsc_handle_bad_state(dev);

	if (xsc_health_wait_pci_up(dev)) {
		xsc_core_err(dev, "health recovery aborted, PCI read still not working.\n");
		goto err;
	}

	if (xsc_recover_device(dev)) {
		xsc_core_err(dev, "health recovery failed.\n");
		goto err;
	}

	h->failed_in_seq = 0;
	xsc_core_info(dev, "health recovery succeeded.\n");
	return 0;
err:
	h->failed_in_seq++;
	return -EIO;
}

static void xsc_fw_fatal_err_report_work(struct work_struct *work)
{
	struct xsc_core_health *h = container_of(work, struct xsc_core_health, fatal_report_work);
	struct xsc_core_device *dev = container_of(h, struct xsc_core_device, priv.health);

	mutex_lock(&dev->intf_state_mutex);
	if (test_bit(XSC_DROP_HEALTH_WORK, &h->flags)) {
		xsc_core_err(dev, "drop incomplete health work\n");
		mutex_unlock(&dev->intf_state_mutex);
		return;
	}
	mutex_unlock(&dev->intf_state_mutex);

		mutex_lock(&h->recover_lock);
		if (xsc_health_try_recover_device(dev))
			xsc_core_err(dev, "health recovery failed.\n");
		mutex_unlock(&h->recover_lock);
		return;
}

u32 xsc_health_check_fatal_sensors(struct xsc_core_device *dev)
{
	if (xsc_pci_not_working(dev))
		return XSC_SENSOR_COMMON_ERR;

	if (pci_channel_offline(dev->pdev))
		return XSC_SENSOR_PCI_ERR;

	if (xsc_get_nic_state(dev) == XSC_NIC_STATE_DISABLED)
		return XSC_SENSOR_NIC_DISABLED;

	return XSC_SENSOR_NO_ERR;
}

static unsigned long get_next_poll_jiffies(void)
{
	unsigned long next;

	get_random_bytes(&next, sizeof(next));
	next %= HZ;
	next += jiffies + msecs_to_jiffies(XSC_HEALTH_POLL_INTERVAL_MS);

	return next;
}

static void xsc_trigger_health_work(struct xsc_core_device *dev)
{
	struct xsc_core_health *health = &dev->priv.health;

	queue_work(health->wq, &health->fatal_report_work);
}

static void enter_error_state(struct xsc_core_device *dev, bool force)
{
	u32 fatal_error = xsc_health_check_fatal_sensors(dev);

	if (fatal_error || force) {
		dev->state = XSC_DEVICE_STATE_INTERNAL_ERROR;
		return;
	}
}

static void print_health_check(struct xsc_core_device *dev)
{
	struct xsc_core_health *h = &dev->priv.health;
	struct health_buffer *hb = h->health;
	u8 syndrome = hb->syndrome;

	if (!syndrome)
		return;

	xsc_core_err(dev, "health issue observed, %s", syndstr(syndrome));
}

static void _health_poll(struct xsc_core_health *health)
{
	struct xsc_core_device *dev = container_of(health, struct xsc_core_device, priv.health);
	u32 fatal_error;

	fatal_error = xsc_health_check_fatal_sensors(dev);
	enter_error_state(dev, false);
	if (fatal_error && !health->fatal_error) {
		xsc_core_err(dev, "Fatal error %u detected\n", fatal_error);
		health->fatal_error = fatal_error;
		health->sick = true;
		print_health_check(dev);
		xsc_trigger_health_work(dev);
		return;
	}

	mod_timer(&health->timer, get_next_poll_jiffies());
}

static void health_poll(struct timer_list *timer)
{
	struct xsc_core_health *health = container_of(timer, struct xsc_core_health, timer);

	_health_poll(health);
}

void xsc_start_health_poll(struct xsc_core_device *dev)
{
	struct xsc_core_health *health = &dev->priv.health;

	if (!is_support_health_check(dev))
		return;

	health->sick = false;
	health->fatal_error = 0;
	health->prev = 0;
	health->miss_counter = 0;
	clear_bit(XSC_DROP_HEALTH_WORK, &health->flags);
	health->nic_state = (u32 *)(dev->bar + XSC_HEALTH_NIC_STATE_OFFSET);
	health->health_counter = (u32 *)(dev->bar + XSC_HEALTH_COUNTER_OFFSET);
	health->health = (struct health_buffer *)(dev->bar + XSC_HEALTH_BUFFER_OFFSET);
	timer_setup(&health->timer, health_poll, 0);
	health->timer.expires = jiffies + msecs_to_jiffies(XSC_HEALTH_POLL_INTERVAL_MS);
	add_timer(&health->timer);
}

void xsc_stop_health_poll(struct xsc_core_device *dev)
{
	struct xsc_core_health *health = &dev->priv.health;

	if (!is_support_health_check(dev))
		return;

	del_timer_sync(&health->timer);
}

void xsc_drain_health_wq(struct xsc_core_device *dev)
{
	struct xsc_core_health *health = &dev->priv.health;

	if (!is_support_health_check(dev))
		return;

	set_bit(XSC_DROP_HEALTH_WORK, &health->flags);
	cancel_work_sync(&health->fatal_report_work);
}

int xsc_health_init(struct xsc_core_device *dev)
{
	struct xsc_core_health *health = &dev->priv.health;
	char name[64];

	snprintf(name, 64, "xsc_health%s", dev_name(dev->device));
	health->wq = create_singlethread_workqueue(name);
	if (!health->wq)
		return -ENOMEM;

	INIT_WORK(&health->fatal_report_work, xsc_fw_fatal_err_report_work);
	mutex_init(&health->recover_lock);

	return 0;
}

void xsc_health_cleanup(struct xsc_core_device *dev)
{
	struct xsc_core_health *health = &dev->priv.health;

	destroy_workqueue(health->wq);
}
