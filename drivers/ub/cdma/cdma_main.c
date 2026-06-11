// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define pr_fmt(fmt) "CDMA: " fmt
#define dev_fmt pr_fmt

#include <linux/module.h>
#include <linux/delay.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "cdma.h"
#include "cdma_dev.h"
#include "cdma_chardev.h"
#include "cdma_cmd.h"
#include "cdma_types.h"
#include "cdma_mmap.h"
#include "cdma_context.h"
#include "cdma_uobj.h"
#include "cdma_event.h"

#define CDMA_RX_MIN_SLEEP_MS	100
#define CDMA_RX_MAX_SLEEP_MS	800
#define CDMA_RX_SLEEP_MULT	2

static bool is_rmmod;
DEFINE_MUTEX(cdma_reset_mutex);

/* Enabling jfc_arm_mode will cause jfc to report cqe; otherwise, it will not. */
uint jfc_arm_mode;
module_param(jfc_arm_mode, uint, 0444);
MODULE_PARM_DESC(jfc_arm_mode,
		 "Set the ARM mode of the JFC, default: 0(0:Always ARM, others: NO ARM)");

bool cqe_mode = true;
module_param(cqe_mode, bool, 0444);
MODULE_PARM_DESC(cqe_mode, "Set cqe reporting mode, default: 1 (0:BY_COUNT, 1:BY_CI_PI_GAP)");

struct class *cdma_cdev_class;

typedef void (*cdma_client_handlers)(struct cdma_dev *cdev,
				     struct dma_client *client);

static void cdma_client_stop(struct cdma_dev *cdev, struct dma_client *client)
{
	if (!client->stop)
		return;

	client->stop(cdev->eid);
	dev_info(cdev->dev, "client:%s stop, eid: 0x%x\n",
		 client->client_name, cdev->eid);
}

static void cdma_client_remove(struct cdma_dev *cdev, struct dma_client *client)
{
	if (!client->remove)
		return;

	client->remove(cdev->eid);
	dev_info(cdev->dev, "client:%s remove, eid: 0x%x\n",
		 client->client_name, cdev->eid);
}

static void cdma_client_add(struct cdma_dev *cdev, struct dma_client *client)
{
	int ret;

	if (!client->add)
		return;

	ret = client->add(cdev->eid);
	dev_info(cdev->dev, "client:%s add, eid: 0x%x, ret: %d\n",
		 client->client_name, cdev->eid, ret);
}

static cdma_client_handlers cdma_client_handler[] = {
	[CDMA_CLIENT_OP_STOP] = cdma_client_stop,
	[CDMA_CLIENT_OP_REMOVE] = cdma_client_remove,
	[CDMA_CLIENT_OP_ADD] = cdma_client_add,
};

static void cdma_client_callback(struct cdma_dev *cdev,
				 enum cdma_client_op client_ops)
{
	struct dma_client *client;

	down_write(&cdma_clients_rwsem);
	list_for_each_entry(client, &cdma_client_list, list_node)
		cdma_client_handler[client_ops](cdev, client);
	up_write(&cdma_clients_rwsem);
}

static void cdma_reset_unmap_vma_pages(struct cdma_dev *cdev, bool is_reset)
{
	struct cdma_file *cfile;

	mutex_lock(&cdev->file_mutex);
	list_for_each_entry(cfile, &cdev->file_list, list) {
		mutex_lock(&cfile->ctx_mutex);
		cdma_unmap_vma_pages(cfile);
		if (is_reset && cfile->uctx != NULL)
			cfile->uctx->invalid = true;
		mutex_unlock(&cfile->ctx_mutex);
	}
	mutex_unlock(&cdev->file_mutex);
}

static void cdma_free_cfile_uobj(struct cdma_dev *cdev)
{
	struct cdma_file *cfile, *next_cfile;
	struct cdma_jfae *jfae;

	mutex_lock(&cdev->file_mutex);
	list_for_each_entry_safe(cfile, next_cfile, &cdev->file_list, list) {
		list_del(&cfile->list);
		mutex_lock(&cfile->ctx_mutex);
		cdma_cleanup_context_uobj(cfile, CDMA_REMOVE_DRIVER_REMOVE);
		cfile->cdev = NULL;
		if (cfile->uctx) {
			jfae = cfile->jfae;
			if (jfae)
				wake_up_interruptible(&jfae->jfe.poll_wait);
			cdma_cleanup_context_res(cfile->uctx);
		}
		cfile->uctx = NULL;
		cfile->jfae = NULL;
		mutex_unlock(&cfile->ctx_mutex);
	}
	mutex_unlock(&cdev->file_mutex);
}

static int cdma_reset_down(struct auxiliary_device *adev)
{
	struct cdma_dev *cdev;

	mutex_lock(&cdma_reset_mutex);
	cdev = get_cdma_dev(adev);
	if (!cdev) {
		dev_warn(&adev->dev, "reset down cdev does not exist\n");
		goto unlock;
	}

	if (cdev->status >= CDMA_STATUS_SUSPENDED) {
		dev_warn(&adev->dev, "reset down status = %u\n", cdev->status);
		goto unlock;
	}

	cdev->status = CDMA_STATUS_INVALID;
	cdma_cmd_flush(cdev);
	cdma_reset_unmap_vma_pages(cdev, true);
	cdma_client_callback(cdev, CDMA_CLIENT_OP_STOP);

unlock:
	mutex_unlock(&cdma_reset_mutex);

	return 0;
}

static int cdma_reset_abort(struct auxiliary_device *adev)
{
	dev_warn(&adev->dev, "reset abort\n");
	return 0;
}

static int cdma_reset_uninit(struct auxiliary_device *adev)
{
	struct cdma_dev *cdev;

	mutex_lock(&cdma_reset_mutex);
	cdev = get_cdma_dev(adev);
	if (!cdev) {
		dev_warn(&adev->dev, "reset uninit cdev does not exist\n");
		goto unlock;
	}

	if (cdev->status != CDMA_STATUS_INVALID) {
		dev_warn(&adev->dev, "reset uninit status = %u\n", cdev->status);
		goto unlock;
	}

	cdma_client_callback(cdev, CDMA_CLIENT_OP_REMOVE);
	cdma_destroy_chardev(cdev);
	cdma_free_cfile_uobj(cdev);
	cdma_kcmd_flush(cdev);
	cdma_destroy_dev(cdev);

unlock:
	mutex_unlock(&cdma_reset_mutex);

	return 0;
}

static int cdma_reset_init(struct auxiliary_device *adev)
{
	struct cdma_dev *cdev;
	int ret;

	mutex_lock(&cdma_reset_mutex);

	cdev = cdma_create_dev(adev);
	if (IS_ERR(cdev)) {
		if (PTR_ERR(cdev) == -ETIMEDOUT) {
			ret = -EAGAIN;
			dev_warn(&adev->dev,
				 "reset init ctrlq timeout, notify ubase. ret = %d\n",
				 ret);
		} else {
			ret = PTR_ERR(cdev);
		}
		goto unlock;
	}

	ret = cdma_create_chardev(cdev);
	if (ret) {
		cdma_destroy_dev(cdev);
		goto unlock;
	}

	cdma_client_callback(cdev, CDMA_CLIENT_OP_ADD);

unlock:
	mutex_unlock(&cdma_reset_mutex);

	return ret;
}

typedef int (*cdma_reset_func_t)(struct auxiliary_device *adev);

static cdma_reset_func_t cdma_reset_table[] = {
	[UBASE_RESET_STAGE_NONE] = NULL,
	[UBASE_RESET_STAGE_DOWN] = cdma_reset_down,
	[UBASE_RESET_STAGE_UNINIT] = cdma_reset_uninit,
	[UBASE_RESET_STAGE_INIT] = cdma_reset_init,
	[UBASE_RESET_STAGE_UP] = NULL,
	[UBASE_RESET_STAGE_ABORT] = cdma_reset_abort,
};

static int cdma_reset_handler(struct auxiliary_device *adev,
			      enum ubase_reset_stage stage)
{
	if (!adev || stage < UBASE_RESET_STAGE_NONE ||
	    stage > UBASE_RESET_STAGE_ABORT)
		return -EINVAL;

	if (!cdma_reset_table[stage])
		return 0;

	return cdma_reset_table[stage](adev);
}

static int cdma_probe(struct auxiliary_device *auxdev,
		      const struct auxiliary_device_id *auxdev_id)
{
	struct cdma_dev *cdev;
	int ret;

	dev_info(&auxdev->dev, "%s called, matched aux dev(%s.%u)\n", __func__,
		 auxdev->name, auxdev->id);

	cdev = cdma_create_dev(auxdev);
	if (IS_ERR(cdev)) {
		if (PTR_ERR(cdev) == -ETIMEDOUT) {
			dev_warn(&auxdev->dev,
				 "create dev ctrlq timeout, notify ubase\n");
			ubase_update_adev_status(auxdev, UBASE_ADEV_PROBE_FAIL);
			return -EAGAIN;
		}
		return PTR_ERR(cdev);
	}

	ret = cdma_create_chardev(cdev);
	if (ret) {
		cdma_destroy_dev(cdev);
		return ret;
	}

	cdma_client_callback(cdev, CDMA_CLIENT_OP_ADD);
	ubase_reset_register(auxdev, cdma_reset_handler);

	return 0;
}

static void cdma_wait_rx(struct auxiliary_device *auxdev)
{
	u32 wait_time = CDMA_RX_MIN_SLEEP_MS;
	bool first_fail = true;

	if (is_rmmod)
		return;

	while (true) {
		if (!ubase_deactivate_dev(auxdev)) {
			dev_info(&auxdev->dev, "cdma close ue rx success\n");
			return;
		}

		if (ubase_adev_shutting_down(auxdev)) {
			dev_warn(&auxdev->dev, "enter shutdown process\n");
			return;
		}

		if (first_fail) {
			dev_err(&auxdev->dev,
				"cdma close ue rx failed, retrying...\n");
			first_fail = false;
		}

		msleep(wait_time);
		if (wait_time < CDMA_RX_MAX_SLEEP_MS)
			wait_time *= CDMA_RX_SLEEP_MULT;
	}
}

static void cdma_restore_rx(struct auxiliary_device *auxdev)
{
	int ret;

	if (is_rmmod)
		return;

	ret = ubase_activate_dev(auxdev);
	if (ret) {
		dev_warn(&auxdev->dev, "cdma restore ue rx failed, ret=%d\n",
			 ret);
		ubase_update_dev_status(auxdev, UBASE_DEV_NEED_TO_ACTIVATE);
	} else {
		dev_info(&auxdev->dev, "cdma restore ue rx success\n");
	}
}

static void cdma_remove(struct auxiliary_device *auxdev)
{
	struct cdma_dev *cdev;

	dev_info(&auxdev->dev, "%s called, matched aux dev(%s.%u)\n",
		 __func__, auxdev->name, auxdev->id);

	ubase_reset_unregister(auxdev);
	mutex_lock(&cdma_reset_mutex);
	cdev = (struct cdma_dev *)dev_get_drvdata(&auxdev->dev);
	if (!cdev) {
		mutex_unlock(&cdma_reset_mutex);
		dev_err(&auxdev->dev, "cdma device does not exist\n");
		return;
	}

	cdev->status = CDMA_STATUS_SUSPENDED;
	cdma_cmd_flush(cdev);
	cdma_reset_unmap_vma_pages(cdev, false);
	cdma_client_callback(cdev, CDMA_CLIENT_OP_STOP);
	cdma_client_callback(cdev, CDMA_CLIENT_OP_REMOVE);
	cdma_wait_rx(auxdev);
	cdma_destroy_chardev(cdev);
	cdma_free_cfile_uobj(cdev);
	cdma_kcmd_flush(cdev);
	cdma_destroy_dev(cdev);
	cdma_restore_rx(auxdev);

	mutex_unlock(&cdma_reset_mutex);
	dev_info(&auxdev->dev, "cdma device remove success\n");
}

static const struct auxiliary_device_id cdma_id_table[] = {
	{
		.name = UBASE_ADEV_NAME ".cdma",
	},
	{},
};
MODULE_DEVICE_TABLE(auxiliary, cdma_id_table);

static struct auxiliary_driver cdma_driver = {
	.probe = cdma_probe,
	.remove = cdma_remove,
	.name = "cdma",
	.driver = {
		.probe_type = PROBE_FORCE_SYNCHRONOUS,
	},
	.id_table = cdma_id_table,
};

static int __init cdma_init(void)
{
	int ret;

	cdma_cdev_class = class_create("cdma");
	if (IS_ERR(cdma_cdev_class)) {
		pr_err("create cdma class failed\n");
		return PTR_ERR(cdma_cdev_class);
	}

	ret = auxiliary_driver_register(&cdma_driver);
	if (ret) {
		pr_err("auxiliary register failed, ret = %d\n", ret);
		goto free_class;
	}

	return 0;

free_class:
	class_destroy(cdma_cdev_class);

	return ret;
}

static void __exit cdma_exit(void)
{
	is_rmmod = true;
	auxiliary_driver_unregister(&cdma_driver);
	class_destroy(cdma_cdev_class);
	pr_info("cdma driver exit success\n");
}

module_init(cdma_init);
module_exit(cdma_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hisilicon UBus Crystal DMA Driver");
