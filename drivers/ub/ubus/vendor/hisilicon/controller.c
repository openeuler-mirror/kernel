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

static void hi_ver_exch(struct ub_bus_controller *ubc)
{
	struct hi_ver_exch_pld pld = {};
	struct msg_info info = {};
	int ret;

	hi_firmware_lowest_ver = FIRMWARE_VER_DEFAULT;
	hi_firmware_highest_ver = FIRMWARE_VER_DEFAULT;
	pld.req.ubus_lowest_ver = HI_UBUS_LOWEST_VER;
	pld.req.ubus_highest_ver = HI_UBUS_HIGHEST_VER;

	message_info_init(&info, NULL, &pld, &pld,
			  (HI_VER_EXCH_REQ_SIZE << MSG_REQ_SIZE_OFFSET) |
			  HI_VER_EXCH_RSP_SIZE);
	ret = hi_message_private(ubc->mdev, &info, VER_EXCH_CMD);
	if (ret) {
		dev_info(&ubc->dev,
			 "unsupported ver-exchange msg for firmware, ret=%d, "
			 "ubus highest_version: 0x%x, lowest_version: 0x%x, "
			 "default firmware version: 0x%x\n",
			 ret, HI_UBUS_HIGHEST_VER, HI_UBUS_LOWEST_VER,
			 hi_firmware_highest_ver);
		return;
	}

	hi_firmware_lowest_ver = pld.rsp.firmware_lowest_ver;
	hi_firmware_highest_ver = pld.rsp.firmware_highest_ver;
	dev_info(&ubc->dev,
		 "ubus highest_version: 0x%x, firmware highest_version: 0x%x, "
		 "ubus lowest_version: 0x%x, firmware lowest_version: 0x%x\n",
		 HI_UBUS_HIGHEST_VER, hi_firmware_highest_ver,
		 HI_UBUS_LOWEST_VER, hi_firmware_lowest_ver);
}

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

	if (ubc->ctl_no == 0)
		hi_ver_exch(ubc);

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
