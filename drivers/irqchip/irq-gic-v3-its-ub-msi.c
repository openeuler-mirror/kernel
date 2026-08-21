// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <linux/acpi_iort.h>
#include <linux/idr.h>
#include <linux/msi.h>
#include <linux/irq.h>
#include <linux/spinlock_types.h>
#include <linux/compiler_types.h>
#include <linux/irqdomain.h>
#include <ub/ubfi/ubfi.h>
#include <ub/ubus/ubus.h>

static void its_mask_msi_irq(struct irq_data *d)
{
	ub_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void its_unmask_msi_irq(struct irq_data *d)
{
	ub_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static struct irq_chip its_msi_irq_chip = {
	.name = "ITS-MSI",
	.irq_unmask = its_unmask_msi_irq,
	.irq_mask = its_mask_msi_irq,
	.irq_eoi = irq_chip_eoi_parent,
};

static int its_ub_msi_prepare(struct irq_domain *domain, struct device *dev,
			      int nvec, msi_alloc_info_t *info)
{
	struct msi_domain_info *msi_info;
	int alias_count = 0, minnvec = 1;
	struct ub_entity *uent = to_ub_entity(dev);
	int cnt, ret;

	msi_info = msi_get_domain_info(domain->parent);

	ret = ub_interrupt_id_alloc(uent);
	if (ret) {
		dev_err(&uent->dev, "device id alloc failed, ret = %d.\n", ret);
		return ret;
	}

	info->scratchpad[0].ul = uent->intr_device_id;
	dev_info(&uent->dev, "device id alloc success, id: %u.\n", uent->intr_device_id);
	ub_write_interruptid(uent);

	cnt = max(nvec, alias_count);
	cnt = max_t(int, minnvec, roundup_pow_of_two((u32)cnt));

	ret = msi_info->ops->msi_prepare(domain->parent, dev, cnt, info);
	if (ret) {
		ub_interrupt_id_free(uent);
		dev_err(&uent->dev, "msi prepare failed %d.\n", ret);
	}

	return ret;
}

static struct msi_domain_ops its_ub_msi_ops = {
	.msi_prepare = its_ub_msi_prepare,
};

static struct msi_domain_info its_ub_msi_domain_info = {
	.flags = (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		  MSI_FLAG_UB_INTR),
	.ops = &its_ub_msi_ops,
	.chip = &its_msi_irq_chip,
};

static int its_ub_msi_init_one(struct fwnode_handle *handle,
			       const char *name)
{
	struct irq_domain *parent;

	parent = irq_find_matching_fwnode(handle, DOMAIN_BUS_NEXUS);
	if (!parent || !msi_get_domain_info(parent)) {
		pr_err("%s: Unable to locate ITS domain\n", name);
		return -ENXIO;
	}

	if (!ub_msi_create_irq_domain(handle, &its_ub_msi_domain_info, parent)) {
		pr_err("%s: Unable to create UB domain\n", name);
		return -ENOMEM;
	}

	return 0;
}

static int its_ub_msi_parse_madt(union acpi_subtable_headers *header,
				 const unsigned long end)
{
	struct acpi_madt_generic_translator *its_entry;
	struct fwnode_handle *dom_handle;
	char *node_name;
	int err = -ENXIO;

	its_entry = (struct acpi_madt_generic_translator *)header;
	node_name = kasprintf(GFP_KERNEL, "ITS@0x%lx",
			      (long)its_entry->base_address);

	dom_handle = iort_find_domain_token(its_entry->translation_id);
	if (!dom_handle) {
		pr_err("%s: Unable to locate ITS domain handle\n", node_name);
		goto out;
	}

	err = its_ub_msi_init_one(dom_handle, (const char *)node_name);
	if (!err)
		pr_info("UB/USI: %s domain created\n", node_name);
out:
	kfree(node_name);
	return err;
}

static int its_ub_acpi_msi_init(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_GENERIC_TRANSLATOR,
			      its_ub_msi_parse_madt, 0);
	return 0;
}

static const struct of_device_id its_device_id[] = {
	{	.compatible	= "arm,gic-v3-its",	},
	{},
};

static int its_ub_of_msi_init(void)
{
	struct device_node *np;

	for (np = of_find_matching_node(NULL, its_device_id); np;
	     np = of_find_matching_node(np, its_device_id)) {
		if (!of_device_is_available(np))
			continue;
		if (!of_property_read_bool(np, "msi-controller"))
			continue;

		if (its_ub_msi_init_one(of_node_to_fwnode(np), np->full_name))
			continue;

		pr_info("UB/USI: %pOF domain created\n", np);
	}

	return 0;
}

static int __init its_ub_msi_init(void)
{
	its_ub_of_msi_init();
	its_ub_acpi_msi_init();

	return 0;
}
early_initcall(its_ub_msi_init);
