// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubus/ub_black_box.h>

#include "ubase_cmd.h"
#include "ubase_dev.h"
#include "ubase_reset.h"
#include "ubase_ubus.h"

static const char ubase_ubus_driver_name[] = "ubase";

static const struct ub_device_id ubase_ubus_tbl[] = {
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_0_URMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_0_URMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_0_CDMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_0_CDMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_0_PMU_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_0_PMU_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_URMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_URMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_CDMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_CDMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_PMU_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_PMU_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_UBOE_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_0_UBOE_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_S_0_URMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_S_0_PMU_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_S_0_CDMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_V2_URMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_V2_URMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_V2_CDMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_V2_CDMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_V2_PMU_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_K_V2_PMU_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_URMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_URMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_CDMA_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_CDMA_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_PMU_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_PMU_UE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_UBOE_MUE), 0, 0},
	{UB_ENTITY(UBASE_VENDOR_ID, UBASE_DEV_ID_A_V2_UBOE_UE), 0, 0},
	/* required last entry */
	{0},
};
MODULE_DEVICE_TABLE(ub, ubase_ubus_tbl);

static int ubase_ubus_init(struct ub_entity *ue)
{
#define UBASE_UBUS_DMA_BIT	48

	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);
	int ret;

	ub_entity_enable(ue, 1);

	ret = dma_set_mask_and_coherent(&ue->dev,
					DMA_BIT_MASK(UBASE_UBUS_DMA_BIT));
	if (ret) {
		ubase_err(udev,
			  "can't set consistent UBUS DMA, ret = %d.\n", ret);
		goto err_enable_device;
	}

	udev->hw.io_base.addr_unmapped = ub_resource_start(ue, UBASE_UBUS_IO_RESOURCE);
	udev->hw.io_base.addr = ub_iomap(ue, UBASE_UBUS_IO_RESOURCE, 0);
	if (!udev->hw.io_base.addr) {
		ubase_err(udev, "failed to map io base.\n");
		ret = -ENOMEM;
		goto err_enable_device;
	}

	udev->hw.mem_base.addr_unmapped = ub_resource_start(ue, UBASE_UBUS_MEM_RESOURCE);
	udev->hw.mem_base.addr = devm_ioremap_wc(&ue->dev,
					ub_resource_start(ue, UBASE_UBUS_MEM_RESOURCE),
					ub_resource_len(ue, UBASE_UBUS_MEM_RESOURCE));
	if (!udev->hw.mem_base.addr) {
		ubase_err(udev, "failed to map memory base.\n");
		ret = -ENOMEM;
		goto err_unmap_io_base;
	}

	udev->hw.rs0_base.addr_unmapped = ub_resource_start(ue, UBASE_UBUS_RESOURCE_0);
	udev->hw.rs0_base.addr = ub_iomap(ue, UBASE_UBUS_RESOURCE_0, 0);
	if (!udev->hw.rs0_base.addr) {
		ubase_err(udev, "failed to map resource0 addr.\n");
		ret = -ENOMEM;
		goto err_unmap_mem_base;
	}

	return 0;

err_unmap_mem_base:
	devm_iounmap(&ue->dev, udev->hw.mem_base.addr);
	udev->hw.mem_base.addr = NULL;
err_unmap_io_base:
	ub_iounmap(udev->hw.io_base.addr);
	udev->hw.io_base.addr = NULL;
err_enable_device:
	ub_entity_enable(ue, 0);

	return ret;
}

static void ubase_ubus_uninit(struct ub_entity *ue)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	if (udev->hw.io_base.addr) {
		ub_iounmap(udev->hw.io_base.addr);
		udev->hw.io_base.addr = NULL;
	}

	if (udev->hw.mem_base.addr) {
		devm_iounmap(&ue->dev, udev->hw.mem_base.addr);
		udev->hw.mem_base.addr = NULL;
	}

	if (udev->hw.rs0_base.addr) {
		ub_iounmap(udev->hw.rs0_base.addr);
		udev->hw.rs0_base.addr = NULL;
	}

	ub_entity_enable(ue, 0);
}

static void ubase_port_event_notify(struct ub_entity *ue, u16 port_id, int event)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	if (event == UB_PORT_EVENT_RESET_PREPARE) {
		ubase_info(udev, "port %u reset prepare.\n", port_id);
		ubase_port_down(udev);
	} else if (event == UB_PORT_EVENT_RESET_DONE) {
		ubase_port_up(udev);
		ubase_info(udev, "port %u reset done.\n", port_id);
		udev->reset_stat.port_reset_cnt++;
	}
}

static struct ub_share_port_ops ubase_share_port_ops = {
	.event_notify = ubase_port_event_notify
};

static bool ubase_dev_reg_share_port_must_succ(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	switch (uent_device(ue)) {
	case UBASE_DEV_ID_K_0_URMA_MUE:
	case UBASE_DEV_ID_K_0_CDMA_MUE:
	case UBASE_DEV_ID_A_0_URMA_MUE:
	case UBASE_DEV_ID_A_0_CDMA_MUE:
	case UBASE_DEV_ID_S_0_URMA_MUE:
	case UBASE_DEV_ID_S_0_CDMA_MUE:
	case UBASE_DEV_ID_K_V2_URMA_MUE:
	case UBASE_DEV_ID_K_V2_CDMA_MUE:
	case UBASE_DEV_ID_A_V2_URMA_MUE:
	case UBASE_DEV_ID_A_V2_CDMA_MUE:
		break;
	default:
		return false;
	}

	return true;
}

static int ubase_ubus_reg_share_port(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);
	struct ubase_caps *caps = &udev->caps.dev_caps;
	int ret;

	if (!ubase_dev_ubl_supported(udev))
		return 0;

	ret = ub_register_share_port(ue, caps->ub_port_logic_id,
				     &ubase_share_port_ops);

	ret = ubase_dev_reg_share_port_must_succ(udev) ? ret : 0;
	if (ret)
		ubase_err(udev,
			  "failed to register share logical port %hu, ret = %d.\n",
			  caps->ub_port_logic_id, ret);

	return ret;
}

static void ubase_ubus_unreg_share_port(struct ubase_dev *udev)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);
	struct ubase_caps *caps = &udev->caps.dev_caps;

	if (!ubase_dev_ubl_supported(udev))
		return;

	ub_unregister_share_port(ue, caps->ub_port_logic_id,
				 &ubase_share_port_ops);
}

/* ubase_ubus_probe - Device initialization routine
 * @ue: ub entity information struct
 * @utbl_entry: entry in ubase_ubus_tbl
 *
 * ubase_ubus_probe initializes an UE identified by an ub_entity structure.
 *
 * Returns 0 on success, negative on failure
 */
static int ubase_ubus_probe(struct ub_entity *ue,
			    const struct ub_device_id *utbl_entry)
{
	struct ubase_dev *udev;
	int ret;

	ub_set_user_info(ue);

	udev = devm_kzalloc(&ue->dev, sizeof(*udev), GFP_KERNEL);
	if (!udev) {
		dev_err(&ue->dev, "failed to alloc ubase dev.\n");
		return -ENOMEM;
	}

	udev->dev = &ue->dev;
	udev->dev_id = ubase_adev_idx_alloc();
	if (udev->dev_id < 0) {
		ubase_err(udev,
			  "failed to alloc dev id(%d).\n", udev->dev_id);
		devm_kfree(&ue->dev, udev);
		return udev->dev_id;
	}

	udev->caps.dev_caps.tid = ue->tid;
	udev->caps.dev_caps.eid = ue->eid;
	udev->caps.dev_caps.upi = ue->upi;
	udev->caps.dev_caps.ctl_no = ue->ubc->ctl_no;

	dev_set_drvdata(&ue->dev, udev);

	ret = ubase_ubus_init(ue);
	if (ret) {
		ubase_err(udev,
			  "failed to init ubus, ret = %d.\n", ret);
		goto err_ubus_init;
	}

	ret = ubase_dev_init(udev);
	if (ret) {
		ubase_err(udev,
			  "failed to init ubase dev, ret = %d.\n", ret);
		goto err_udev_init;
	}

	ret = ubase_ubus_reg_share_port(udev);
	if (ret)
		goto err_register_share_port;

	return 0;

err_register_share_port:
	ubase_dev_uninit(udev);
err_udev_init:
	ubase_ubus_uninit(ue);
err_ubus_init:
	dev_set_drvdata(&ue->dev, NULL);
	ubase_adev_idx_free(udev->dev_id);
	devm_kfree(&ue->dev, udev);
	ub_unset_user_info(ue);

	return ret;
}

static void __ubase_ubus_remove(struct ub_entity *ue)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_ubus_unreg_share_port(udev);
	ubase_dev_uninit(udev);
	ubase_ubus_uninit(ue);
	ub_unset_user_info(ue);
	ubase_adev_idx_free(udev->dev_id);
	dev_set_drvdata(&ue->dev, NULL);
	devm_kfree(&ue->dev, udev);
}

/* ubase_remove - Device removal routine
 * @ue: ub entity information struct
 */
static void ubase_ubus_remove(struct ub_entity *ue)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	while (test_and_set_bit(UBASE_STATE_DISABLED_B, &udev->state_bits))
		msleep(UBASE_RST_WAIT_TIME);

	ub_disable_entities(ue);
	__ubase_ubus_remove(ue);
}

static void ubase_ubus_shutdown(struct ub_entity *ue)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	while (test_and_set_bit(UBASE_STATE_DISABLED_B, &udev->state_bits))
		msleep(UBASE_RST_WAIT_TIME);

	set_bit(UBASE_STATE_SHUTDOWN, &udev->state_bits);

	ubase_info(udev, "ubase shutdown start.\n");

	__ubase_ubus_remove(ue);

	dev_info(&ue->dev, "ubase shutdown end.\n");
}

int ubase_ubus_irq_vectors_alloc(struct device *dev)
{
	struct ub_entity *ue = container_of(dev, struct ub_entity, dev);
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);
	int irqs_num;

	udev->irq_table.irqs_num = udev->caps.dev_caps.num_aeq_vectors +
				   udev->caps.dev_caps.num_ceq_vectors +
				   udev->caps.dev_caps.num_misc_vectors;

	irqs_num = ub_alloc_irq_vectors(ue, UBASE_MIN_IRQ_NUM,
					udev->irq_table.irqs_num);
	if (irqs_num == -ENOSPC) {
		ubase_err(udev,
			  "bus is unable to provide sufficient number of interrupts.\n");
		goto out;
	}

	if (irqs_num < 0) {
		ubase_err(udev,
			  "failed to allocate USI vectors, irqs_num = %d.\n",
			  irqs_num);
		goto out;
	}

	if ((u32)irqs_num < udev->irq_table.irqs_num) {
		ubase_warn(udev,
			   "need to allocate %u USI resource, but only allocated %d.\n",
			   udev->irq_table.irqs_num, irqs_num);
		udev->irq_table.irqs_num = (u32)irqs_num;
	}

	return 0;

out:
	ub_disable_intr(ue);
	return -EFAULT;
}

void ubase_ubus_irq_vectors_free(struct device *dev)
{
	struct ub_entity *ue = container_of(dev, struct ub_entity, dev);

	ub_disable_intr(ue);
}

int ubase_ubus_irq_vector(struct device *dev, u32 idx)
{
	struct ub_entity *ue = container_of(dev, struct ub_entity, dev);

	return ub_irq_vector(ue, idx);
}

static int ubase_ubus_suspend(struct device *dev)
{
	struct ubase_dev *udev = dev_get_drvdata(dev);

	ubase_info(udev, "UBUS suspend start.\n");
	ubase_suspend(udev);

	return 0;
}

static int ubase_ubus_resume(struct device *dev)
{
	struct ubase_dev *udev = dev_get_drvdata(dev);

	ubase_info(udev, "UBUS resume start.\n");
	ubase_resume(udev);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(ubase_ubus_pm_ops, ubase_ubus_suspend, ubase_ubus_resume);

static int ubase_ubus_virt_configure(struct ub_entity *ue, int bus_ue_id, bool is_en)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);
	int ret;

	/*
	 * The ubus framework have ensure that only mue can come
	 * here, so we not need to check is this a mue again.
	 */
	ubase_info(udev, "ubase virt configure set idx = %d en = %d.\n",
		   bus_ue_id, is_en);

	if (!is_en)
		ret = ub_disable_ue(ue, bus_ue_id);
	else
		ret = ub_enable_ue(ue, bus_ue_id);

	return ret;
}

static int ubase_ubus_virt_notify(struct ub_entity *ue, int bus_ue_id, bool is_en)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_info(udev, "ubase virt notify, ue id = %d, en = %d.\n",
		   bus_ue_id, is_en);

	ubase_virt_handler(udev, (u16)bus_ue_id, is_en);

	return 0;
}

static int ubase_ubus_activate(struct ub_entity *ue, u32 bus_ue_id)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_info(udev, "ubase activate ue id = %u.\n", bus_ue_id);

	return ubase_activate_handler(udev, bus_ue_id);
}

static int ubase_ubus_deactivate(struct ub_entity *ue, u32 bus_ue_id)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_info(udev, "ubase deactivate ue id = %u.\n", bus_ue_id);

	return ubase_deactivate_handler(udev, bus_ue_id);
}

static void ubase_ubus_reset_prepare(struct ub_entity *ue)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_info(udev, "UBUS ELR start.\n");
	ubase_suspend(udev);
}

static void ubase_ubus_reset_done(struct ub_entity *ue)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_resume(udev);
	ubase_info(udev, "UBUS ELR done.\n");
}

static ub_ers_result_t ubase_ubus_error_detected(struct ub_entity *ue,
						 ub_channel_state_t state)
{
	struct ubase_dev *udev = dev_get_drvdata(&ue->dev);

	ubase_info(udev, "UBUS error detected, state = %u.\n", state);

	switch (state) {
	case ub_channel_io_normal:
		return UB_ERS_RESULT_NEED_RESET;
	case ub_channel_io_frozen:
		return UB_ERS_RESULT_DISCONNECT;
	case ub_channel_io_perm_failure:
	default:
		return UB_ERS_RESULT_NONE;
	}
}

static const struct ub_error_handlers ubase_ubus_err_handler = {
	.ub_reset_prepare	= ubase_ubus_reset_prepare,
	.ub_reset_done		= ubase_ubus_reset_done,
	.ub_error_detected	= ubase_ubus_error_detected,
};

static struct ub_driver ubase_ubus_driver = {
	.name		= ubase_ubus_driver_name,
	.id_table	= ubase_ubus_tbl,
	.probe		= ubase_ubus_probe,
	.remove		= ubase_ubus_remove,
	.shutdown	= ubase_ubus_shutdown,
	.virt_configure	= ubase_ubus_virt_configure,
	.virt_notify	= ubase_ubus_virt_notify,
	.err_handler	= &ubase_ubus_err_handler,
	.activate	= ubase_ubus_activate,
	.deactivate	= ubase_ubus_deactivate,
	.driver		= {
		.pm = &ubase_ubus_pm_ops,
	},
};

int ubase_ubus_register_driver(void)
{
	return ub_register_driver(&ubase_ubus_driver);
}

void ubase_ubus_unregister_driver(void)
{
	ub_unregister_driver(&ubase_ubus_driver);
}

int ubase_ubus_reset_entry(struct device *dev)
{
	struct ub_entity *ue = container_of(dev, struct ub_entity, dev);
	struct ubase_dev *udev = dev_get_drvdata(dev);
	int ret;

	ret = ub_reset_entity(ue);
	if (ret)
		ubase_err(udev, "failed to trigger reset, ret = %d.\n", ret);

	return ret;
}

void ubase_ubus_reinit(struct device *dev)
{
	struct ub_entity *ue = container_of(dev, struct ub_entity, dev);

	ub_set_user_info(ue);
	ub_entity_enable(ue, 1);
}

void ubase_ubus_fault_log(struct ubase_dev *udev, u32 event_id, void *data)
{
	struct ub_entity *ue = container_of(udev->dev, struct ub_entity, dev);

	ub_fault_log(ue, event_id, data);
}
