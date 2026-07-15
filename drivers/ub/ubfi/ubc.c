// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubfi ubc: " fmt

#include <linux/acpi.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <ub/ubfi/ubfi.h>
#include <ub/ubus/ubus.h>

#include "ubrt.h"
#include "ub_fi.h"
#include "ubc.h"

#define UB_MSGQ_INT_TRIGGER_MASK BIT(0)
#define UB_MSGQ_INT_POLARITY_MASK BIT(1)

#define ACPI_UBC_DEVICE_HID "HISI0541"

#define to_ub_ubc(n) container_of(n, struct ub_bus_controller, dev)

LIST_HEAD(ubc_list);
EXPORT_SYMBOL_GPL(ubc_list);

u32 ubc_eid_start;
EXPORT_SYMBOL_GPL(ubc_eid_start);

u32 ubc_eid_end;
EXPORT_SYMBOL_GPL(ubc_eid_end);

u32 ubc_cna_start;
EXPORT_SYMBOL_GPL(ubc_cna_start);

u32 ubc_cna_end;
EXPORT_SYMBOL_GPL(ubc_cna_end);

u8 ubc_feature;
EXPORT_SYMBOL_GPL(ubc_feature);

static bool cluster_mode;

static acpi_status acpi_processor_ubc(acpi_handle handle, u32 lvl,
				      void *context, void **rv)
{
	struct ub_bus_controller *ubc = context;
	struct acpi_device *adev;
	unsigned long long uid;
	acpi_status status;
	struct device *dev;
	int ret;

	status = acpi_evaluate_integer(handle, "_UID", NULL, &uid);
	if (ACPI_FAILURE(status))
		return AE_CTRL_TERMINATE;

	pr_info("ubc acpi ubc->ctl_no %u, uid: %llu\n", ubc->ctl_no, uid);
	if (ubc->ctl_no != (u32)uid)
		return AE_OK;

	adev = acpi_get_acpi_dev(handle);
	if (!adev)
		return AE_CTRL_TERMINATE;

	dev = bus_find_device_by_acpi_dev(&platform_bus_type, adev);
	if (!dev) {
		status = AE_CTRL_TERMINATE;
		goto out;
	}
	ret = ub_update_msi_domain(dev, DOMAIN_BUS_UB_MSI);
	if (ret) {
		status = AE_CTRL_TERMINATE;
		goto out;
	}
	dev_set_msi_domain(&ubc->dev, dev->msi.domain);
	pr_debug("set ubc msi domain success by acpi\n");

out:
	acpi_put_acpi_dev(adev);
	return status;
}

static int acpi_update_ubc_msi_domain(void)
{
	struct ub_bus_controller *ubc;
	acpi_status status;

	list_for_each_entry(ubc, &ubc_list, node) {
		/* Get UB Bus Controller from DSDT */
		status = acpi_get_devices(ACPI_UBC_DEVICE_HID,
					  acpi_processor_ubc,
					  ubc, NULL);
		if (ACPI_FAILURE(status))
			return -ENODEV;
	}

	return 0;
}

static struct irq_domain *of_usi_get_domain(struct device_node *np,
					    enum irq_domain_bus_token token)
{
	struct device_node *usi_np;
	struct irq_domain *d;

	usi_np = of_parse_phandle(np, "msi-parent", 0);
	if (!usi_np)
		return NULL;

	d = irq_find_matching_host(usi_np, token);
	if (!d)
		of_node_put(usi_np);

	return d;
}

static int dts_update_ubc_msi_domain(void)
{
	struct ub_bus_controller *ubc;
	struct device_node *np;
	struct irq_domain *d;
	u32 ctl_no;
	bool find;
	int ret;

	for_each_compatible_node(np, NULL, "ub,ubc") {
		ret = of_property_read_u32(np, "index", &ctl_no);
		if (ret) {
			pr_err("dts can't find ubc index\n");
			continue;
		}

		find = false;
		list_for_each_entry(ubc, &ubc_list, node) {
			if (ubc->ctl_no == ctl_no) {
				find = true;
				break;
			}
		}
		if (!find) {
			pr_err("can't find ubc no=%u\n", ctl_no);
			continue;
		}

		d = of_usi_get_domain(np, DOMAIN_BUS_UB_MSI);
		if (!d) {
			pr_err("can't find ub irq domain\n");
			continue;
		}

		dev_set_msi_domain(&ubc->dev, d);
		pr_debug("set ubc[%u] msi domain success\n", ctl_no);
	}
	return 0;
}

static int parse_ubc_info(struct ubc_node *node, struct ub_bus_controller *ubc)
{
	ubc->attr.int_id_start = node->int_id_start;
	ubc->attr.int_id_end = node->int_id_end;
	ubc->attr.hpa_base = node->hpa_base;
	ubc->attr.hpa_size = node->hpa_size;
	ubc->attr.mem_size_limit = node->mem_size_limit;
	ubc->attr.dma_cca = node->dma_cca;
	ubc->attr.ummu_map = node->ummu_mapping;
	ubc->attr.proximity_domain = node->proximity_domain;
	ubc->attr.queue_addr = node->msg_queue_base;
	ubc->attr.queue_size = node->msg_queue_size;
	ubc->attr.queue_depth = node->msg_queue_depth;
	ubc->attr.msg_int = node->msg_int;
	ubc->attr.msg_int_attr = node->msg_int_attr;
	ubc->attr.ubc_guid_low = node->ubc_guid_low;
	ubc->attr.ubc_guid_high = node->ubc_guid_high;
	pr_info("ubc interrupt id [0x%x-0x%x], ubc_guid [%llx-%llx], msg_int [0x%x]\n",
		ubc->attr.int_id_start, ubc->attr.int_id_end,
		ubc->attr.ubc_guid_high, ubc->attr.ubc_guid_low,
		ubc->attr.msg_int);

	ubc->data = kzalloc(UBC_VENDOR_INFO_SIZE, GFP_KERNEL);
	if (!ubc->data)
		return -ENOMEM;
	memcpy(ubc->data, node->vendor_info, UBC_VENDOR_INFO_SIZE);

	ubc->cluster = cluster_mode;
	pr_info("ubc real cluster mode is %d\n", ubc->cluster);
	INIT_LIST_HEAD(&ubc->resources);
	(void)snprintf(ubc->name, sizeof(ubc->name), "UB_BUS_CTL%u", ubc->ctl_no);
	pr_info("create ubc success, ubc name=%s\n", ubc->name);
	return 0;
}

static int ubc_dev_new_resource_entry(struct resource *res,
				      struct list_head *resources)
{
	struct resource_entry *rentry;

	rentry = resource_list_create_entry(NULL, 0);
	if (!rentry)
		return -ENOMEM;

	*rentry->res = *res;
	rentry->offset = 0;
	resource_list_add_tail(rentry, resources);
	return 0;
}

static int dts_register_irq(u32 ctl_no, int irq_idx, const char *name,
			    struct resource *res)
{
	struct device_node *np;
	u32 irq = 0, index;
	int ret;

	for_each_compatible_node(np, NULL, "ub,ubc") {
		ret = of_property_read_u32(np, "index", &index);
		if (ret) {
			pr_err("dts can't find ubc index\n");
			continue;
		}
		if (ctl_no != index)
			continue;

		irq = irq_of_parse_and_map(np, irq_idx);
		if (!irq)
			continue;
	}

	if (!irq) {
		pr_err("irq_idx %d parse and map failed\n", irq_idx);
		return -EINVAL;
	}
	pr_info("irq_idx %d register successfully, irq=%u\n", irq_idx, irq);

	res->name = name;
	res->start = irq;
	res->end = irq;
	res->flags = IORESOURCE_IRQ;
	return 0;
}

static void remove_ubc_resource(struct ub_bus_controller *ubc)
{
	struct resource_entry *entry;
	struct resource *res;

	resource_list_for_each_entry(entry, &ubc->resources) {
		res = entry->res;
		if (res->parent && (res->flags & IORESOURCE_MEM))
			release_resource(res);
		if ((res->flags & IORESOURCE_IRQ)
		    && !strcmp(res->name, "UBUS")
		    && !ubc->ctl_no) {
			if (firmware_mode == ACPI)
				ubrt_unregister_gsi(ubc->attr.msg_int);
			else
				irq_dispose_mapping(ubc->queue_virq);
		}
	}

	resource_list_free(&ubc->resources);
}

static int add_ubc_mmio_resource(struct ubc_node *node,
				 struct ub_bus_controller *ubc)
{
	struct resource res = {};
	int ret;

	res.start = node->hpa_base;
	res.end = node->hpa_base + node->hpa_size - 1;
	res.flags = IORESOURCE_MEM;
	res.name = ubc->name;

	ret = ubc_dev_new_resource_entry(&res, &ubc->resources);
	if (!ret)
		pr_info("add %s resource success, %pR\n", res.name, &res);

	return ret;
}

static int add_ubc_irq_resource(struct ubc_node *node,
				struct ub_bus_controller *ubc)
{
	int hwirq, trigger, polarity, ret;
	struct resource res = {};

	hwirq = ubc->attr.msg_int;
	trigger = !!(ubc->attr.msg_int_attr & UB_MSGQ_INT_TRIGGER_MASK);
	polarity = !!(ubc->attr.msg_int_attr & UB_MSGQ_INT_POLARITY_MASK);

	if (firmware_mode == ACPI)
		ret = ubrt_register_gsi(hwirq, trigger, polarity, "UBUS", &res);
	else
		ret = dts_register_irq(ubc->ctl_no, 0, "UBUS", &res);

	if (ret) {
		pr_err("register irq failed, ret=%d\n", ret);
		return ret;
	}

	ret = ubc_dev_new_resource_entry(&res, &ubc->resources);
	if (ret)
		goto out;

	ubc->queue_virq = res.start;

	pr_info("ubc msgq irq register success\n");
	return 0;

out:
	if (firmware_mode == ACPI)
		ubrt_unregister_gsi(hwirq);
	else
		irq_dispose_mapping(res.start);

	return ret;
}

static void ub_release_ubc_dev(struct device *dev)
{
	struct ub_bus_controller *ubc = to_ub_ubc(dev);
	struct device_node *usi_np;

	pr_info("%s release ub bus controller device.\n", ubc->name);

	if (firmware_mode == DTS) {
		usi_np = irq_domain_get_of_node(dev->msi.domain);
		if (usi_np)
			of_node_put(usi_np);
	}

	remove_ubc_resource(ubc);
	kfree(ubc->data);
	list_del(&ubc->node);
	kfree(ubc);
}

static int init_ubc(struct ub_bus_controller *ubc)
{
	struct device *dev = &ubc->dev;
	int ret;

	INIT_LIST_HEAD(&ubc->devs);
	device_initialize(dev);

	dev->release = ub_release_ubc_dev;
	dev->coherent_dma_mask = GENMASK_ULL(31, 0);
	dev_set_name(dev, "ub_bus_controller%u", ubc->ctl_no);

	if (firmware_mode == ACPI) {
		set_dev_node(dev, pxm_to_node(ubc->attr.proximity_domain));
		pr_info("%s numa node is %d\n", ubc->name, pxm_to_node(ubc->attr.proximity_domain));
	} else {
		set_dev_node(dev, ubc->attr.proximity_domain);
		pr_info("%s numa node is %u\n", ubc->name, ubc->attr.proximity_domain);
	}

	ret = device_add(dev);
	if (ret) {
		pr_err("Add ub bus controller device failed.\n");
		put_device(&ubc->dev);
	}

	return ret;
}

static void ubc_validate_resources(struct list_head *resources,
				   unsigned long type)
{
	struct resource_entry *tmp, *entry, *entry2;
	struct resource *res1, *res2, *root = NULL;
	LIST_HEAD(list);

	WARN_ON((type & IORESOURCE_MEM) == 0);
	root = &iomem_resource;

	list_splice_init(resources, &list);
	resource_list_for_each_entry_safe(entry, tmp, &list) {
		bool can_free = false;
		resource_size_t end;

		res1 = entry->res;
		if (!(type & res1->flags))
			goto next;

		end = min(res1->end, root->end);
		if (end <= res1->start) {
			pr_info("ub bus controller resources %pR (ignored, not CPU addressable)\n",
				res1);
			can_free = true;
			goto next;
		} else if (res1->end != end) {
			pr_info("ub bus controller resources %pR ([%#llx-%#llx] ignored, not CPU addressable)\n",
				res1, (unsigned long long)end + 1,
				(unsigned long long)res1->end);
			res1->end = end;
		}

		resource_list_for_each_entry(entry2, resources) {
			res2 = entry2->res;
			if (!(type & res2->flags))
				continue;

			if (resource_overlaps(res1, res2)) {
				res2->start = min(res1->start, res2->start);
				res2->end = max(res1->end, res2->end);
				pr_warn("ub bus controller resources expanded to %pR; %pR ignored\n",
					res2, res1);
				can_free = true;
				goto next;
			}
		}

next:
		resource_list_del(entry);
		if (can_free)
			resource_list_free_entry(entry);
		else
			resource_list_add_tail(entry, resources);
	}
}

static void ubc_device_add_resources(struct list_head *resources)
{
	struct resource *res, *root = NULL;
	struct resource_entry *entry, *tmp;
	int ret;

	resource_list_for_each_entry_safe(entry, tmp, resources) {
		res = entry->res;
		if (!(res->flags & IORESOURCE_MEM))
			continue;

		root = &iomem_resource;
		if (res == root)
			continue;

		ret = insert_resource(root, res);
		if (ret) {
			pr_warn("conflict, ignoring controller resources %pR\n",
				res);
			resource_list_destroy_entry(entry);
		}
	}
}

static void ubc_declare_resources(struct ub_bus_controller *ubc)
{
	struct resource_entry *window;
	resource_size_t offset;
	char addr[SZ_64];
	struct resource *res;

	/* Show ub bus controller's resources */
	resource_list_for_each_entry(window, &ubc->resources) {
		offset = window->offset;
		res = window->res;
		if (offset)
			snprintf(addr, sizeof(addr),
				 " (bus address [0x%#010llx-0x%#010llx])",
				 (unsigned long long)(res->start - offset),
				 (unsigned long long)(res->end - offset));
		else
			addr[0] = '\0';

		pr_info("ubc resource %pR%s\n", res, addr);
	}
}

static void ubc_check_and_add_resources(struct ub_bus_controller *ubc)
{
	struct resource_entry *entry, *tmp;

	resource_list_for_each_entry_safe(entry, tmp, &ubc->resources)
		if (entry->res->flags & IORESOURCE_DISABLED)
			resource_list_destroy_entry(entry);

	ubc_validate_resources(&ubc->resources, IORESOURCE_MEM);

	/* Insert resources into kernel */
	ubc_device_add_resources(&ubc->resources);

	ubc_declare_resources(ubc);
}

static int create_ubc(struct ubc_node *node, u32 ctl_no)
{
	struct ub_bus_controller *ubc;
	int ret;

	ubc = kzalloc(sizeof(*ubc), GFP_KERNEL);
	if (!ubc)
		return -ENOMEM;
	ubc->ctl_no = ctl_no;

	ret = parse_ubc_info(node, ubc);
	if (ret)
		goto free_ubc;

	ret = add_ubc_mmio_resource(node, ubc);
	if (ret)
		goto free_vendor;

	ret = add_ubc_irq_resource(node, ubc);
	if (ret)
		goto free_resource;

	/* after init_ubc, if failed, ubc resources will be released in the dev->release */
	ret = init_ubc(ubc);
	if (ret)
		return ret;

	ubc_check_and_add_resources(ubc);
	list_add_tail(&ubc->node, &ubc_list);

	return 0;

free_resource:
	remove_ubc_resource(ubc);
free_vendor:
	kfree(ubc->data);
free_ubc:
	kfree(ubc);
	return ret;
}

static int parse_ubc_table(void *info_node)
{
	struct ubrt_ubc_table *ubc_table = info_node;
	struct ubc_node *node = ubc_table->ubcs;
	u32 count, i;
	int ret;

	count = ubc_table->ubc_count;
	if (!count) {
		pr_warn("ubc table has no ubc.\n");
		return 0;
	}

	/* get ubc common attribute */
	ubc_cna_start = ubc_table->cna_start;
	ubc_cna_end = ubc_table->cna_end;
	ubc_eid_start = ubc_table->eid_start;
	ubc_eid_end = ubc_table->eid_end;
	ubc_feature = ubc_table->feature;
	cluster_mode = ubc_table->cluster_mode;

	pr_info("cna_start=%u, cna_end=%u\n", ubc_cna_start, ubc_cna_end);
	pr_info("eid_start=%u, eid_end=%u\n", ubc_eid_start, ubc_eid_end);
	pr_info("ubc_count=%u, firmware_cluster_mode=%u, feature=%u\n", count,
		cluster_mode, ubc_feature);
	if (ubc_cna_start > ubc_cna_end || ubc_eid_start > ubc_eid_end ||
	    ubc_cna_start == 0 || ubc_eid_start == 0) {
		pr_err("eid or cna range is incorrect\n");
		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		ret = create_ubc(node, i);
		if (ret) {
			pr_err("Create No.%u ubc failed, ret=%d\n", i, ret);
			return ret;
		}
		node++;
	}

	return 0;
}

static void ub_destroy_bus_controllers(void)
{
	struct ub_bus_controller *ubc, *tmp;

	list_for_each_entry_safe_reverse(ubc, tmp, &ubc_list, node)
		device_unregister(&ubc->dev);

	pr_info("ubc destroy success\n");
}

void destroy_ubc(void)
{
	ub_destroy_bus_controllers();
}

int handle_ubc_table(u64 pointer)
{
	void *info_node = ub_table_get(pointer);
	int ret;

	if (!info_node)
		return -EINVAL;

	ret = parse_ubc_table(info_node);
	if (ret)
		goto err_handle;

	pr_debug("Update msi domain for ub bus controller\n");
	/* Update msi domain for ub bus controller */
	if (firmware_mode == ACPI)
		ret = acpi_update_ubc_msi_domain();
	else
		ret = dts_update_ubc_msi_domain();

	if (ret)
		goto err_handle;

	ub_table_put(info_node);
	return 0;

err_handle:
	ub_table_put(info_node);
	destroy_ubc();
	return ret;
}
