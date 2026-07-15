// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus hisi ctl: " fmt

#include <linux/debugfs.h>
#include <linux/resource_ext.h>
#include <ub/ubus/ubus.h>

#include "../../ubus_controller.h"
#include "hisi-decoder.h"
#include "hisi-ubus.h"
#include "hisi-msg.h"

static struct ub_bus_controller_ops hi_ubc_ops = {
	.eu_table_init = hi_eu_table_init,
	.eu_table_uninit = hi_eu_table_uninit,
	.eu_cfg = hi_eu_cfg,
	.mem_decoder_create = hi_mem_decoder_create,
	.mem_decoder_remove = hi_mem_decoder_remove,
	.register_ubmem_irq = hi_register_ubmem_irq,
	.unregister_ubmem_irq = hi_unregister_ubmem_irq,
	.init_decoder_queue = hi_init_decoder_queue,
	.uninit_decoder_queue = hi_uninit_decoder_queue,
	.entity_enable = hi_send_entity_enable_msg,
	.create_decoder_table = hi_create_decoder_table,
	.free_decoder_table = hi_free_decoder_table,
	.decoder_map = hi_decoder_map,
	.decoder_unmap = hi_decoder_unmap,
	.decoder_event_deal = hi_decoder_event_deal,
};

static void ub_bus_controller_debugfs_init(struct ub_bus_controller *ubc)
{
	if (!debugfs_initialized())
		return;

	ubc->debug_root = debugfs_create_dir(ubc->name, NULL);
}

static void ub_bus_controller_debugfs_uninit(struct ub_bus_controller *ubc)
{
	debugfs_remove_recursive(ubc->debug_root);
	ubc->debug_root = NULL;
}

int ub_bus_controller_probe(struct ub_bus_controller *ubc)
{
	int ret;

	ubc->ops = &hi_ubc_ops;
	ub_bus_controller_debugfs_init(ubc);

	ret = hi_msg_device_probe(ubc);
	if (ret)
		goto msg_fail;

	return 0;

msg_fail:
	ub_bus_controller_debugfs_uninit(ubc);
	ubc->ops = NULL;
	return ret;
}

void ub_bus_controller_remove(struct ub_bus_controller *ubc)
{
	if (ubc->mdev)
		hi_msg_device_remove(ubc);

	ub_bus_controller_debugfs_uninit(ubc);
	ubc->ops = NULL;
}

unsigned long long hi_feature_get(void)
{
	struct ub_bus_controller *ubc;
	u64 raw, feature;

	if (list_empty(&ubc_list))
		return U64_MAX;

	ubc = list_first_entry(&ubc_list, struct ub_bus_controller, node);
	if (!ubc->data)
		return U64_MAX;

#define UBC_VENDOR_FEATURE_SETS_OFFSET 144
#define UBC_VENDOR_FEATURE_SETS_SIZE 8
	memcpy(&raw, (u8 *)ubc->data + UBC_VENDOR_FEATURE_SETS_OFFSET,
	       UBC_VENDOR_FEATURE_SETS_SIZE);
	feature = raw >> SZ_32;
	if (!feature) {
		dev_info(&ubc->dev, "Feature sets data is not initialized.\n");
		return U64_MAX;
	}

	return feature;
}
