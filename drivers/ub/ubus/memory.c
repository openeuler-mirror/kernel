// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus memory: " fmt

#include <linux/acpi.h>
#include "ubus.h"
#include "ubus_controller.h"
#include "memory.h"

static ubmem_ras_handler handler;

static bool ub_mem_uent_valid(struct ub_entity *uent)
{
	if (!uent || !uent->ubc)
		return false;

	return is_ibus_controller(uent);
}

void ub_mem_decoder_init(struct ub_entity *uent)
{
	struct ub_bus_controller *ubc;
	int ret;

	if (!ub_mem_uent_valid(uent))
		return;

	ubc = uent->ubc;
	if (ubc->ops && ubc->ops->mem_decoder_create) {
		ret = ubc->ops->mem_decoder_create(ubc);
		WARN_ON(ret);
	} else {
		dev_warn(&ubc->dev,
			 "ubc ops or ubc ops mem_decoder_create is null.\n");
	}
}

void ub_mem_decoder_uninit(struct ub_entity *uent)
{
	struct ub_bus_controller *ubc;

	if (!ub_mem_uent_valid(uent))
		return;

	ubc = uent->ubc;
	if (ubc->ops && ubc->ops->mem_decoder_remove)
		ubc->ops->mem_decoder_remove(ubc);
	else
		dev_warn(&ubc->dev, "ubc ops mem_decoder_remove is null.\n");
}

void ub_mem_ras_handler_register(ubmem_ras_handler rh)
{
	handler = rh;
}
EXPORT_SYMBOL_GPL(ub_mem_ras_handler_register);

void ub_mem_ras_handler_unregister(void)
{
	handler = NULL;
}
EXPORT_SYMBOL_GPL(ub_mem_ras_handler_unregister);

ubmem_ras_handler ub_mem_ras_handler_get(void)
{
	return handler;
}
EXPORT_SYMBOL_GPL(ub_mem_ras_handler_get);

void ub_mem_init_usi(struct ub_entity *uent)
{
	if (!uent->ubc) {
		pr_err("ubc not exist, can't init usi\n");
		return;
	}

	if (uent->ubc->ops && uent->ubc->ops->register_ubmem_irq)
		uent->ubc->ops->register_ubmem_irq(uent->ubc);
	else
		dev_warn(&uent->ubc->dev, "ubc ops register_ubmem_irq is null.\n");
}

void ub_mem_uninit_usi(struct ub_entity *uent)
{
	if (!uent->ubc) {
		pr_err("ubc not exist, can't uninit usi\n");
		return;
	}

	if (uent->ubc->ops && uent->ubc->ops->unregister_ubmem_irq)
		uent->ubc->ops->unregister_ubmem_irq(uent->ubc);
	else
		dev_warn(&uent->ubc->dev, "ubc ops unregister_ubmem_irq is null.\n");
}

void ub_mem_drain_start(u32 scna)
{
	struct ub_mem_device *mem_device;
	struct ub_bus_controller *ubc;

	ubc = ub_find_bus_controller_by_cna(scna);
	if (!ubc) {
		pr_err("No ubc has cna of %u\n", scna);
		return;
	}

	mem_device = ubc->mem_device;
	if (!mem_device) {
		dev_err(&ubc->dev, "ubc mem_device is null.\n");
		return;
	}

	if (mem_device->ops && mem_device->ops->mem_drain_start)
		mem_device->ops->mem_drain_start(ubc);
	else
		dev_warn(mem_device->dev, "ub mem_device ops mem_drain_start is null.\n");
}
EXPORT_SYMBOL_GPL(ub_mem_drain_start);

int ub_mem_drain_state(u32 scna)
{
	struct ub_mem_device *mem_device;
	struct ub_bus_controller *ubc;

	ubc = ub_find_bus_controller_by_cna(scna);
	if (!ubc) {
		pr_err("No ubc has cna of %u\n", scna);
		return -ENODEV;
	}

	mem_device = ubc->mem_device;
	if (!mem_device) {
		dev_err(&ubc->dev, "ubc mem_device is null.\n");
		return -EINVAL;
	}

	if (mem_device->ops && mem_device->ops->mem_drain_state)
		return mem_device->ops->mem_drain_state(ubc);

	dev_warn(mem_device->dev, "ub memory decoder ops mem_drain_state is null.\n");
	return 0;
}
EXPORT_SYMBOL_GPL(ub_mem_drain_state);

void ub_mem_drain_start_enhanced(void)
{
	struct ub_mem_device *mem_device;
	struct ub_bus_controller *ubc;

	list_for_each_entry(ubc, &ubc_list, node) {
		mem_device = ubc->mem_device;
		if (!mem_device) {
			dev_warn(&ubc->dev, "ubc mem_device is null.\n");
			continue;
		}
		if (mem_device->ops && mem_device->ops->mem_drain_start)
			mem_device->ops->mem_drain_start(ubc);
		else
			dev_warn(&ubc->dev, "ub mem_device ops mem_drain_start is null.\n");
	}
}
EXPORT_SYMBOL_GPL(ub_mem_drain_start_enhanced);

int ub_mem_drain_state_enhanced(void)
{
	struct ub_mem_device *mem_device;
	struct ub_bus_controller *ubc;
	int ret = 0;

	list_for_each_entry(ubc, &ubc_list, node) {
		mem_device = ubc->mem_device;
		if (!mem_device) {
			dev_warn(&ubc->dev, "ubc mem_device is null.\n");
			continue;
		}

		if (mem_device->ops && mem_device->ops->mem_drain_state) {
			ret = mem_device->ops->mem_drain_state(ubc);
			if (!ret)
				return ret;
		} else {
			dev_warn(&ubc->dev, "ub memory decoder ops mem_drain_state is null.\n");
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(ub_mem_drain_state_enhanced);

int ub_mem_get_numa_id(u32 scna)
{
	struct ub_bus_controller *ubc;

	ubc = ub_find_bus_controller_by_cna(scna);
	if (!ubc) {
		pr_err("No ubc has cna of %u\n", scna);
		return NUMA_NO_NODE;
	}

	return pxm_to_node(ubc->attr.proximity_domain);
}
EXPORT_SYMBOL_GPL(ub_mem_get_numa_id);

bool ub_memory_validate_pa(u32 scna, u64 pa_start, u64 pa_end, bool cacheable)
{
	struct ub_mem_device *mem_device;
	struct ub_bus_controller *ubc;

	ubc = ub_find_bus_controller_by_cna(scna);
	if (!ubc) {
		pr_err("No ubc has cna of %u\n", scna);
		return false;
	}

	mem_device = ubc->mem_device;
	if (!mem_device) {
		dev_err(&ubc->dev, "ubc mem_device is null.\n");
		return false;
	}

	if (mem_device->ops && mem_device->ops->mem_validate_pa)
		return mem_device->ops->mem_validate_pa(ubc, pa_start, pa_end,
							cacheable);

	dev_warn(mem_device->dev, "ub memory decoder ops memory_validate_pa is null.\n");
	return false;
}
EXPORT_SYMBOL_GPL(ub_memory_validate_pa);
