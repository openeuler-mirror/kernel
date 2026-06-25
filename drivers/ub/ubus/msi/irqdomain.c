// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <linux/msi.h>
#include <ub/ubus/ubus.h>
#include <linux/fwnode.h>
#include <linux/irqdomain.h>

static irq_hw_number_t ub_msi_domain_calc_hwirq(struct msi_desc *desc)
{
	struct ub_entity *uent = msi_desc_to_ub_entity(desc);

	return (irq_hw_number_t)(desc->msi_index | (uent->intr_device_id << 11));
}

static void ub_msi_domain_set_desc(msi_alloc_info_t *arg, struct msi_desc *desc)
{
	arg->desc = desc;
	arg->hwirq = ub_msi_domain_calc_hwirq(desc);
}

static struct msi_domain_ops ub_msi_domain_ops_default = {
	.set_desc = ub_msi_domain_set_desc,
};

static void ub_msi_domain_update_dom_ops(struct msi_domain_info *info)
{
	struct msi_domain_ops *ops = info->ops;

	if (ops == NULL)
		info->ops = &ub_msi_domain_ops_default;
	else if (!ops->set_desc)
		ops->set_desc = ub_msi_domain_set_desc;
}

static void ub_msi_domain_write_msg(struct irq_data *irq_data, struct msi_msg *msg)
{
	struct msi_desc *desc = irq_data_get_msi_desc(irq_data);

	if (desc->irq == irq_data->irq)
		__ub_write_msi_msg(desc, msg);
}

static void ub_msi_domain_update_chip_ops(struct msi_domain_info *info)
{
	struct irq_chip *chip = info->chip;

	WARN_ON_ONCE(!chip);
	chip->irq_write_msi_msg = chip->irq_write_msi_msg ?
					  chip->irq_write_msi_msg :
					  ub_msi_domain_write_msg;
	chip->irq_mask = chip->irq_mask ? chip->irq_mask : ub_msi_mask_irq;
	chip->irq_unmask = chip->irq_unmask ? chip->irq_unmask :
					      ub_msi_unmask_irq;
}

struct irq_domain *ub_msi_create_irq_domain(struct fwnode_handle *fwnode,
					    struct msi_domain_info *info,
					    struct irq_domain *parent)
{
	struct irq_domain *domain;

	if (info->flags & MSI_FLAG_USE_DEF_DOM_OPS)
		ub_msi_domain_update_dom_ops(info);
	if (info->flags & MSI_FLAG_USE_DEF_CHIP_OPS)
		ub_msi_domain_update_chip_ops(info);
	if (WARN_ON(info->flags & MSI_FLAG_LEVEL_CAPABLE))
		info->flags &= ~MSI_FLAG_LEVEL_CAPABLE;

	info->flags |= MSI_FLAG_FREE_MSI_DESCS | MSI_FLAG_ACTIVATE_EARLY |
		       MSI_FLAG_DEV_SYSFS;

	if (IS_ENABLED(CONFIG_GENERIC_IRQ_RESERVATION_MODE))
		info->flags |= MSI_FLAG_MUST_REACTIVATE;

	info->chip->flags |= IRQCHIP_ONESHOT_SAFE;
	info->bus_token = DOMAIN_BUS_UB_MSI;

	domain = msi_create_irq_domain(fwnode, info, parent);

	return domain;
}
EXPORT_SYMBOL_GPL(ub_msi_create_irq_domain);

static bool ub_create_device_domain(struct ub_entity *uent,
				    const struct msi_domain_template *tmpl,
				    unsigned int hwsize)
{
	struct irq_domain *domain = dev_get_msi_domain(&uent->dev);

	if (!domain || !irq_domain_is_msi_parent(domain))
		return true;

	if (WARN_ON_ONCE(1))
		pr_err("Create device irq domain failed.\n");

	return false;
}

bool ub_setup_usi_device_domain(struct ub_entity *uent, unsigned int hwsize)
{
	if (WARN_ON_ONCE(uent->intr_enabled))
		return false;

	if (msi_match_device_irq_domain(&uent->dev, MSI_DEFAULT_DOMAIN,
					DOMAIN_BUS_UB_MSI))
		return true;

	return ub_create_device_domain(uent, NULL, hwsize);
}
EXPORT_SYMBOL_GPL(ub_setup_usi_device_domain);
