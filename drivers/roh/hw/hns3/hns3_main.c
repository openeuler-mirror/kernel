// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2022 Hisilicon Limited.

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "core.h"
#include "hnae3.h"
#include "hns3_common.h"
#include "hns3_cmdq.h"

static const struct pci_device_id hns3_roh_pci_tbl[] = {
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_100G_ROH), 0 },
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_200G_ROH), 0 },
	{ PCI_VDEVICE(HUAWEI, HNAE3_DEV_ID_400G_ROH), 0 },
	{
		0,
	}
};
MODULE_DEVICE_TABLE(pci, hns3_roh_pci_tbl);

static void hns3_roh_unregister_device(struct hns3_roh_device *hroh_dev)
{
	hroh_dev->active = false;
	roh_unregister_device(&hroh_dev->roh_dev);
}

static int hns3_roh_register_device(struct hns3_roh_device *hroh_dev)
{
	struct roh_device *rohdev = &hroh_dev->roh_dev;
	struct device *dev = hroh_dev->dev;
	int ret;

	if (!strlen(rohdev->name))
		strscpy(rohdev->name, "hns3_%d", ROH_DEVICE_NAME_MAX);

	rohdev->owner = THIS_MODULE;
	rohdev->dev.parent = dev;
	rohdev->netdev = hroh_dev->netdev;

	ret = roh_register_device(rohdev);
	if (ret) {
		dev_err(dev, "failed to register roh device, ret = %d\n", ret);
		return ret;
	}

	hroh_dev->active = true;

	return 0;
}

static int hns3_roh_init_hw(struct hns3_roh_device *hroh_dev)
{
	struct device *dev = hroh_dev->dev;
	int ret;

	ret = hroh_dev->hw->cmdq_init(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to init cmdq, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static void hns3_roh_uninit_hw(struct hns3_roh_device *hroh_dev)
{
	hroh_dev->hw->cmdq_exit(hroh_dev);
}

static int hns3_roh_init(struct hns3_roh_device *hroh_dev)
{
	struct device *dev = hroh_dev->dev;
	int ret;

	ret = hns3_roh_init_hw(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to init hw resources, ret = %d\n", ret);
		return ret;
	}

	ret = hns3_roh_register_device(hroh_dev);
	if (ret) {
		dev_err(dev, "failed to register roh device, ret = %d\n", ret);
		goto err_uninit_hw;
	}

	dev_info(dev, "%s driver init success.\n", HNS3_ROH_NAME);

	return 0;

err_uninit_hw:
	hns3_roh_uninit_hw(hroh_dev);
	return ret;
}

static void hns3_roh_exit(struct hns3_roh_device *hroh_dev)
{
	hns3_roh_unregister_device(hroh_dev);

	hns3_roh_uninit_hw(hroh_dev);

	dev_info(&hroh_dev->pdev->dev,
		 "%s driver uninit success.\n", HNS3_ROH_NAME);
}

static const struct hns3_roh_hw hns3_roh_hw = {
	.cmdq_init = hns3_roh_cmdq_init,
	.cmdq_exit = hns3_roh_cmdq_exit,
};

static void hns3_roh_get_cfg_from_frame(struct hns3_roh_device *hroh_dev,
					struct hnae3_handle *handle)
{
	hroh_dev->pdev = handle->pdev;
	hroh_dev->dev = &handle->pdev->dev;

	hroh_dev->netdev = handle->rohinfo.netdev;
	hroh_dev->reg_base = handle->rohinfo.roh_io_base;

	hroh_dev->hw = &hns3_roh_hw;

	hroh_dev->priv->handle = handle;
}

static int __hns3_roh_init_instance(struct hnae3_handle *handle)
{
	struct hns3_roh_device *hroh_dev;
	int ret;

	hroh_dev = (struct hns3_roh_device *)roh_alloc_device(sizeof(*hroh_dev));
	if (!hroh_dev) {
		dev_err(&handle->pdev->dev, "failed to alloc roh dev.\n");
		return -ENOMEM;
	}

	hroh_dev->priv = kzalloc(sizeof(*hroh_dev->priv), GFP_KERNEL);
	if (!hroh_dev->priv) {
		ret = -ENOMEM;
		goto err_roh_alloc_device;
	}

	hns3_roh_get_cfg_from_frame(hroh_dev, handle);

	ret = hns3_roh_init(hroh_dev);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to init roh, ret = %d\n", ret);
		goto err_kzalloc;
	}
	handle->priv = hroh_dev;

	return 0;

err_kzalloc:
	kfree(hroh_dev->priv);
err_roh_alloc_device:
	roh_dealloc_device(&hroh_dev->roh_dev);
	return ret;
}

static void __hns3_roh_uninit_instance(struct hnae3_handle *handle)
{
	struct hns3_roh_device *hroh_dev = (struct hns3_roh_device *)handle->priv;

	if (!hroh_dev)
		return;

	handle->priv = NULL;

	hns3_roh_exit(hroh_dev);

	kfree(hroh_dev->priv);

	roh_dealloc_device(&hroh_dev->roh_dev);
}

static int hns3_roh_init_instance(struct hnae3_handle *handle)
{
	struct device *dev = &handle->pdev->dev;
	const struct pci_device_id *id;
	int ret;

	id = pci_match_id(hns3_roh_pci_tbl, handle->pdev);
	if (!id) {
		dev_err(dev, "failed to match pci id.\n");
		return 0;
	}

	if (id->driver_data) {
		dev_err(dev, "not support vf.\n");
		return -EINVAL;
	}

	ret = __hns3_roh_init_instance(handle);
	if (ret) {
		dev_err(dev, "failed to init instance, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static void hns3_roh_uninit_instance(struct hnae3_handle *handle, bool reset)
{
	__hns3_roh_uninit_instance(handle);
}

static const struct hnae3_client_ops hns3_roh_ops = {
	.init_instance = hns3_roh_init_instance,
	.uninit_instance = hns3_roh_uninit_instance,
};

static struct hnae3_client hns3_roh_client = {
	.name = "hns3_roh_hw",
	.type = HNAE3_CLIENT_ROH,
	.ops = &hns3_roh_ops,
};

static int __init hns3_roh_module_init(void)
{
	return hnae3_register_client(&hns3_roh_client);
}

static void __exit hns3_roh_module_cleanup(void)
{
	hnae3_unregister_client(&hns3_roh_client);
}

module_init(hns3_roh_module_init);
module_exit(hns3_roh_module_cleanup);

MODULE_LICENSE("GPL");
MODULE_VERSION(HNS3_ROH_VERSION);
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("Hisilicon Hip09 Family ROH Driver");
