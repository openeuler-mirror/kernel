// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"

LIST_HEAD(intf_list);
LIST_HEAD(xsc_dev_list);
DEFINE_MUTEX(xsc_intf_mutex); /* protect intf_list and xsc_dev_list */

static void xsc_add_device(struct xsc_interface *intf, struct xsc_priv *priv)
{
	struct xsc_device_context *dev_ctx;
	struct xsc_core_device *dev;

	dev = container_of(priv, struct xsc_core_device, priv);
	dev_ctx = kzalloc(sizeof(*dev_ctx), GFP_KERNEL);
	if (!dev_ctx)
		return;

	dev_ctx->intf = intf;

	dev_ctx->context = intf->add(dev);
	if (dev_ctx->context) {
		set_bit(XSC_INTERFACE_ADDED, &dev_ctx->state);
		if (intf->attach)
			set_bit(XSC_INTERFACE_ATTACHED, &dev_ctx->state);

		spin_lock_irq(&priv->ctx_lock);
		list_add_tail(&dev_ctx->list, &priv->ctx_list);
		spin_unlock_irq(&priv->ctx_lock);
	} else {
		kfree(dev_ctx);
	}
}

static struct xsc_device_context *xsc_get_device(struct xsc_interface *intf,
						 struct xsc_priv *priv)
{
	struct xsc_device_context *dev_ctx;

	/* caller of this function has mutex protection */
	list_for_each_entry(dev_ctx, &priv->ctx_list, list)
		if (dev_ctx->intf == intf)
			return dev_ctx;

	return NULL;
}

static void xsc_remove_device(struct xsc_interface *intf, struct xsc_priv *priv)
{
	struct xsc_device_context *dev_ctx;
	struct xsc_core_device *dev = container_of(priv, struct xsc_core_device, priv);

	dev_ctx = xsc_get_device(intf, priv);
	if (!dev_ctx)
		return;

	spin_lock_irq(&priv->ctx_lock);
	list_del(&dev_ctx->list);
	spin_unlock_irq(&priv->ctx_lock);

	if (test_bit(XSC_INTERFACE_ADDED, &dev_ctx->state))
		intf->remove(dev, dev_ctx->context);

	kfree(dev_ctx);
}

int xsc_register_interface(struct xsc_interface *intf)
{
	struct xsc_priv *priv;

	if (!intf->add || !intf->remove)
		return -EINVAL;

	mutex_lock(&xsc_intf_mutex);
	list_add_tail(&intf->list, &intf_list);
	list_for_each_entry(priv, &xsc_dev_list, dev_list) {
		xsc_add_device(intf, priv);
	}
	mutex_unlock(&xsc_intf_mutex);

	return 0;
}
EXPORT_SYMBOL(xsc_register_interface);

void xsc_unregister_interface(struct xsc_interface *intf)
{
	struct xsc_priv *priv;

	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry(priv, &xsc_dev_list, dev_list)
		xsc_remove_device(intf, priv);
	list_del(&intf->list);
	mutex_unlock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_unregister_interface);

static void xsc_attach_interface(struct xsc_interface *intf,
				 struct xsc_priv *priv)
{
	struct xsc_device_context *dev_ctx;
	struct xsc_core_device *dev = container_of(priv, struct xsc_core_device, priv);

	dev_ctx = xsc_get_device(intf, priv);
	if (!dev_ctx)
		return;

	if (intf->attach) {
		if (test_bit(XSC_INTERFACE_ATTACHED, &dev_ctx->state))
			return;
		if (intf->attach(dev, dev_ctx->context))
			return;
		set_bit(XSC_INTERFACE_ATTACHED, &dev_ctx->state);
	} else {
		if (test_bit(XSC_INTERFACE_ADDED, &dev_ctx->state))
			return;
		dev_ctx->context = intf->add(dev);
		if (!dev_ctx->context)
			return;
		set_bit(XSC_INTERFACE_ADDED, &dev_ctx->state);
	}
}

static void xsc_detach_interface(struct xsc_interface *intf,
				 struct xsc_priv *priv)
{
	struct xsc_device_context *dev_ctx;
	struct xsc_core_device *dev = container_of(priv, struct xsc_core_device, priv);

	dev_ctx = xsc_get_device(intf, priv);
	if (!dev_ctx)
		return;

	if (intf->detach) {
		if (!test_bit(XSC_INTERFACE_ATTACHED, &dev_ctx->state))
			return;
		intf->detach(dev, dev_ctx->context);
		clear_bit(XSC_INTERFACE_ATTACHED, &dev_ctx->state);
	} else {
		if (!test_bit(XSC_INTERFACE_ADDED, &dev_ctx->state))
			return;
		intf->remove(dev, dev_ctx->context);
		clear_bit(XSC_INTERFACE_ADDED, &dev_ctx->state);
	}
}

void xsc_attach_device(struct xsc_core_device *dev)
{
	struct xsc_priv *priv = &dev->priv;
	struct xsc_interface *intf;

	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry(intf, &intf_list, list) {
		xsc_attach_interface(intf, priv);
	}
	mutex_unlock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_attach_device);

void xsc_detach_device(struct xsc_core_device *dev)
{
	struct xsc_priv *priv = &dev->priv;
	struct xsc_interface *intf;

	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry(intf, &intf_list, list)
		xsc_detach_interface(intf, priv);
	mutex_unlock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_detach_device);

bool xsc_device_registered(struct xsc_core_device *dev)
{
	struct xsc_priv *priv;
	bool found = false;

	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry(priv, &xsc_dev_list, dev_list)
		if (priv == &dev->priv)
			found = true;
	mutex_unlock(&xsc_intf_mutex);

	return found;
}

int xsc_register_device(struct xsc_core_device *dev)
{
	struct xsc_priv *priv = &dev->priv;
	struct xsc_interface *intf;

	mutex_lock(&xsc_intf_mutex);
	list_add_tail(&priv->dev_list, &xsc_dev_list);
	list_for_each_entry(intf, &intf_list, list)
		xsc_add_device(intf, priv);
	mutex_unlock(&xsc_intf_mutex);

	return 0;
}
EXPORT_SYMBOL(xsc_register_device);

void xsc_unregister_device(struct xsc_core_device *dev)
{
	struct xsc_priv *priv = &dev->priv;
	struct xsc_interface *intf;

	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry_reverse(intf, &intf_list, list)
		xsc_remove_device(intf, priv);
	list_del(&priv->dev_list);
	mutex_unlock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_unregister_device);

void xsc_add_dev_by_protocol(struct xsc_core_device *dev, int protocol)
{
	struct xsc_interface *intf;

	list_for_each_entry(intf, &intf_list, list)
		if (intf->protocol == protocol) {
			xsc_add_device(intf, &dev->priv);
			break;
		}
}
EXPORT_SYMBOL(xsc_add_dev_by_protocol);

void xsc_remove_dev_by_protocol(struct xsc_core_device *dev, int protocol)
{
	struct xsc_interface *intf;

	list_for_each_entry(intf, &intf_list, list)
		if (intf->protocol == protocol) {
			xsc_remove_device(intf, &dev->priv);
			break;
		}
}
EXPORT_SYMBOL(xsc_remove_dev_by_protocol);

void xsc_dev_list_lock(void)
{
	mutex_lock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_dev_list_lock);

void xsc_dev_list_unlock(void)
{
	mutex_unlock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_dev_list_unlock);

int xsc_dev_list_trylock(void)
{
	return mutex_trylock(&xsc_intf_mutex);
}
EXPORT_SYMBOL(xsc_dev_list_trylock);

static int (*_xsc_get_mdev_info_func)(void *data);

void xsc_register_get_mdev_info_func(int (*get_mdev_info)(void *data))
{
	_xsc_get_mdev_info_func = get_mdev_info;
}
EXPORT_SYMBOL(xsc_register_get_mdev_info_func);

void xsc_get_devinfo(u8 *data, u32 len)
{
	struct xsc_cmd_get_ioctl_info_mbox_out *out =
		(struct xsc_cmd_get_ioctl_info_mbox_out *)data;
	struct xsc_ioctl_get_devinfo *info;
	struct xsc_devinfo *devinfo;
	struct xsc_priv *priv;
	struct xsc_core_device *xdev;
	int used = 0;

	out->hdr.status = 0;
	used += sizeof(struct xsc_outbox_hdr) + sizeof(u64);
	info = (struct xsc_ioctl_get_devinfo *)(data + used);
	info->dev_num = 0;
	used += sizeof(u32);
	devinfo = (struct xsc_devinfo *)info->data;
	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry(priv, &xsc_dev_list, dev_list) {
		if (used + sizeof(*devinfo) > len)
			break;

		xdev = container_of(priv, struct xsc_core_device, priv);
		if (!xsc_core_is_pf(xdev))
			continue;
		devinfo->domain = cpu_to_be32(pci_domain_nr(xdev->pdev->bus));
		devinfo->bus = cpu_to_be32(xdev->pdev->bus->number);
		devinfo->devfn = cpu_to_be32(xdev->pdev->devfn);
		if (xdev->get_ifname)
			xdev->get_ifname(xdev, devinfo->ifname, MAX_IFNAME_LEN);
		if (xdev->get_ibdev_name)
			xdev->get_ibdev_name(xdev, devinfo->ibdev_name, MAX_IFNAME_LEN);
		if (xdev->get_ip_addr) {
			xdev->get_ip_addr(xdev, &devinfo->ip_addr);
			devinfo->ip_addr = cpu_to_be32(devinfo->ip_addr);
		}
		devinfo->vendor_id = cpu_to_be32(xdev->pdev->vendor);
		devinfo += 1;
		info->dev_num++;
	}
	mutex_unlock(&xsc_intf_mutex);

	info->dev_num += _xsc_get_mdev_info_func((void *)devinfo);
	info->dev_num = cpu_to_be32(info->dev_num);
}

