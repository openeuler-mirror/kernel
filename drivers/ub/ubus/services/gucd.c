// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus gucd: " fmt

#include "../ubus.h"
#include "../decoder.h"
#include "../ubus_driver.h"
#include "../memory.h"
#include "../services.h"
#include "service.h"

static const struct ub_device_id component_device_ids[] = {
	{ UB_ENTITY_CLASS(UB_CLASS_BUS_CONTROLLER, (u16)~0)},
	{ UB_ENTITY_CLASS(UB_CLASS_SWITCH_UB, (u16)~0)},
	{}
};
MODULE_DEVICE_TABLE(ub, component_device_ids);

static int get_component_service_capability(struct ub_entity *uent)
{
	int services = 0;
	u32 val;
	int ret;

	ret = ub_cfg_read_dword(uent, UB_CFG0_CAP_BITMAP, &val);
	if (ret)
		return services;

	if (val & (1 << UB_SHP_CAP))
		services |= UB_SERVICE_HP;

	return services;
}

static void release_service_device(struct device *dev)
{
	kfree(to_ub_service_device(dev));
}

static int ub_component_service_init(struct ub_entity *uent, int service)
{
	struct ub_service_device *sdev;
	struct device *dev;
	int ret;

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev)
		return -ENOMEM;

	sdev->uent = uent;
	sdev->service = service;

	dev = &sdev->device;
	dev->bus = &ub_service_bus_type;
	dev->release = release_service_device;
	dev_set_name(dev, "%s:service%03x", ub_name(uent), (u32)service);
	dev->parent = &uent->dev;

	ret = device_register(dev);
	if (ret)
		put_device(dev);

	return ret;
}

static int ub_component_service_register(struct ub_entity *uent)
{
	int nr_service = 0;
	int capabilities;
	int i;

	if (is_ibus_controller(uent) && uent->ubc->cluster)
		return 0;

	/* Get and check component services */
	capabilities = get_component_service_capability(uent);
	if (!capabilities)
		return 0;

	for (i = 0; i < UB_MAXSERVICES; i++) {
		int service = 1 << i;

		if (!(capabilities & service))
			continue;
		if (!ub_component_service_init(uent, service))
			nr_service++;
	}

	if (!nr_service)
		return -ENODEV;

	return 0;
}

static void ub_setup_bus_controller(struct ub_entity *uent)
{
	u32 vec_num_max;
	int usi_count;

	if (ub_cc_supported(uent) && !uent->ubc->cluster)
		ub_cc_enable(uent);

	ub_set_user_info(uent);
	vec_num_max = ub_int_type1_vec_count(uent);
	usi_count = ub_alloc_irq_vectors(uent, vec_num_max, vec_num_max);
	if (usi_count < 0) {
		ub_err(uent, "alloc irq for ub bus controller failed, usi_count=%d\n",
		       usi_count);
		return;
	}

	if ((u32)usi_count < vec_num_max) {
		ub_err(uent, "alloc irq vectors failed, usi count=%d, vec_num_max=%u\n",
		       usi_count, vec_num_max);
	} else {
		ub_init_decoder_usi(uent);
		ub_mem_init_usi(uent);
	}
}

static void ub_unset_bus_controller(struct ub_entity *uent)
{
	ub_mem_uninit_usi(uent);
	ub_uninit_decoder_usi(uent);
	ub_disable_intr(uent);
	ub_unset_user_info(uent);

	if (ub_cc_supported(uent) && !uent->ubc->cluster)
		ub_cc_disable(uent);
}

static ub_ers_result_t ub_gucd_err_detected(struct ub_entity *uent, ub_channel_state_t state)
{
	if (state == ub_channel_io_normal)
		return UB_ERS_RESULT_NEED_RESET;

	if (state == ub_channel_io_frozen)
		return UB_ERS_RESULT_NEED_RESET;

	return UB_ERS_RESULT_CAN_RECOVER;
}

static const struct ub_error_handlers gucd_err_handler = {
	.ub_error_detected = ub_gucd_err_detected,
};

static int ub_component_probe(struct ub_entity *uent,
			      const struct ub_device_id *id)
{
	if (is_ibus_controller(uent))
		ub_setup_bus_controller(uent);

	return ub_component_service_register(uent);
}

static int remove_iter(struct device *dev, void *data)
{
	if (dev->bus == &ub_service_bus_type)
		device_unregister(dev);

	return 0;
}

static void ub_component_remove(struct ub_entity *uent)
{
	device_for_each_child(&uent->dev, NULL, remove_iter);
	if (is_ibus_controller(uent))
		ub_unset_bus_controller(uent);
}

static struct ub_driver ub_component_device_driver = {
	.name = "ub_generic_component",
	.id_table = component_device_ids,
	.probe = ub_component_probe,
	.remove = ub_component_remove,
	.err_handler = &gucd_err_handler,
	.driver_managed_dma = true,
};

static void ub_init_services(void)
{
	ub_ras_init();
	ubhp_service_init();
}

static void ub_uninit_services(void)
{
	ubhp_service_uninit();
	ub_ras_uninit();
}

int ub_services_init(void)
{
	ub_init_services();

	return ub_register_driver(&ub_component_device_driver);
}

void ub_services_exit(void)
{
	ub_unregister_driver(&ub_component_device_driver);
	ub_uninit_services();
}
