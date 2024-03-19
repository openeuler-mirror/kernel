// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"

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

void xsc_attach_device_by_protocol(struct xsc_core_device *dev, int protocol)
{
	struct xsc_priv *priv = &dev->priv;
	struct xsc_interface *intf;

	mutex_lock(&xsc_intf_mutex);
	list_for_each_entry(intf, &intf_list, list)
		if (intf->protocol == protocol)
			xsc_attach_interface(intf, priv);
	mutex_unlock(&xsc_intf_mutex);
}

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

/* Must be called with intf_mutex held */
static bool xsc_has_added_dev_by_protocol(struct xsc_core_device *dev, int protocol)
{
	struct xsc_device_context *dev_ctx;
	struct xsc_interface *intf;
	bool found = false;

	list_for_each_entry(intf, &intf_list, list) {
		if (intf->protocol == protocol) {
			dev_ctx = xsc_get_device(intf, &dev->priv);
			if (dev_ctx && test_bit(XSC_INTERFACE_ADDED, &dev_ctx->state))
				found = true;
			break;
		}
	}

	return found;
}

/* Must be called with intf_mutex held */
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

/* Must be called with intf_mutex held */
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

void xsc_reload_interfaces(struct xsc_core_device *dev,
			   int protocol1, int protocol2,
			   bool valid1, bool valid2)
{
	bool reload1;
	bool reload2;

	mutex_lock(&xsc_intf_mutex);

	reload1 = valid1 && xsc_has_added_dev_by_protocol(dev, protocol1);
	reload2 = valid2 && xsc_has_added_dev_by_protocol(dev, protocol2);

	if (reload2)
		xsc_remove_dev_by_protocol(dev, protocol2);
	if (reload1)
		xsc_remove_dev_by_protocol(dev, protocol1);
	if (reload1)
		xsc_add_dev_by_protocol(dev, protocol1);
	if (reload2)
		xsc_add_dev_by_protocol(dev, protocol2);
	mutex_unlock(&xsc_intf_mutex);
}

void xsc_reload_interface(struct xsc_core_device *dev, int protocol)
{
	mutex_lock(&xsc_intf_mutex);
	if (xsc_has_added_dev_by_protocol(dev, protocol)) {
		xsc_remove_dev_by_protocol(dev, protocol);
		xsc_add_dev_by_protocol(dev, protocol);
	}
	mutex_unlock(&xsc_intf_mutex);
}

static u32 xsc_gen_pci_id(struct xsc_core_device *dev)
{
	return (u32)((pci_domain_nr(dev->pdev->bus) << 16) |
		     (dev->pdev->bus->number << 8) |
		     PCI_SLOT(dev->pdev->devfn));
}

struct xsc_core_device *xsc_get_next_phys_dev(struct xsc_core_device *dev)
{
	struct xsc_core_device *res = NULL;
	struct xsc_core_device *tmp_dev;
	struct xsc_priv *priv;
	u32 pci_id;

	if (!xsc_core_is_pf(dev))
		return NULL;

	pci_id = xsc_gen_pci_id(dev);
	list_for_each_entry(priv, &xsc_dev_list, dev_list) {
		tmp_dev = container_of(priv, struct xsc_core_device, priv);
		if (!xsc_core_is_pf(tmp_dev))
			continue;

		if (dev != tmp_dev && (xsc_gen_pci_id(tmp_dev) == pci_id)) {
			res = tmp_dev;
			break;
		}
	}

	return res;
}
EXPORT_SYMBOL(xsc_get_next_phys_dev);
