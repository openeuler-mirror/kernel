// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include <linux/aer.h>
#include "nbl_core.h"

static struct nbl_software_tool_table nbl_st_table;
static struct dentry *nbl_debugfs_root;

static struct nbl_product_base_ops nbl_product_base_ops[NBL_PRODUCT_MAX] = {
	{
		.phy_init	= nbl_phy_init_leonis,
		.phy_remove	= nbl_phy_remove_leonis,
		.res_init	= nbl_res_init_leonis,
		.res_remove	= nbl_res_remove_leonis,
		.chan_init	= nbl_chan_init_common,
		.chan_remove	= nbl_chan_remove_common,
	},
};

int nbl_core_start(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	int ret = 0;

	ret = nbl_dev_start(adapter, param);
	return ret;
}

void nbl_core_stop(struct nbl_adapter *adapter)
{
	nbl_dev_stop(adapter);
}

void nbl_core_setup_product_ops(struct nbl_adapter *adapter, struct nbl_init_param *param,
				struct nbl_product_base_ops **product_base_ops)
{
	adapter->product_base_ops = &nbl_product_base_ops[param->product_type];
	*product_base_ops = adapter->product_base_ops;
}

struct nbl_adapter *nbl_core_init(struct pci_dev *pdev, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter;
	struct nbl_common_info *common;
	struct nbl_product_base_ops *product_base_ops;
	int ret = 0;

	if (!pdev)
		return NULL;

	adapter = devm_kzalloc(&pdev->dev, sizeof(struct nbl_adapter), GFP_KERNEL);
	if (!adapter)
		return NULL;

	adapter->pdev = pdev;
	common = NBL_ADAPTER_TO_COMMON(adapter);

	NBL_COMMON_TO_PDEV(common) = pdev;
	NBL_COMMON_TO_DEV(common) = &pdev->dev;
	NBL_COMMON_TO_DMA_DEV(common) = &pdev->dev;
	NBL_COMMON_TO_DEBUG_LVL(common) |= NBL_DEBUG_ALL;
	NBL_COMMON_TO_VF_CAP(common) = param->caps.is_vf;
	NBL_COMMON_TO_PCI_USING_DAC(common) = param->pci_using_dac;
	NBL_COMMON_TO_PCI_FUNC_ID(common) = PCI_FUNC(pdev->devfn);
	common->devid    = PCI_SLOT(pdev->devfn);
	common->bus      = pdev->bus->number;
	common->product_type = param->product_type;

	memcpy(&adapter->init_param, param, sizeof(adapter->init_param));

	nbl_core_setup_product_ops(adapter, param, &product_base_ops);

	/* every product's phy/chan/res layer has a great difference, so call their own init ops */
	ret = product_base_ops->phy_init(adapter, param);
	if (ret)
		goto phy_init_fail;

	ret = product_base_ops->chan_init(adapter, param);
	if (ret)
		goto chan_init_fail;

	ret = product_base_ops->res_init(adapter, param);
	if (ret)
		goto res_init_fail;

	ret = nbl_disp_init(adapter, param);
	if (ret)
		goto disp_init_fail;

	ret = nbl_serv_init(adapter, param);
	if (ret)
		goto serv_init_fail;

	ret = nbl_dev_init(adapter, param);
	if (ret)
		goto dev_init_fail;

	nbl_debugfs_func_init(adapter, param);

	return adapter;

dev_init_fail:
	nbl_serv_remove(adapter);
serv_init_fail:
	nbl_disp_remove(adapter);
disp_init_fail:
	product_base_ops->res_remove(adapter);
res_init_fail:
	product_base_ops->chan_remove(adapter);
chan_init_fail:
	product_base_ops->phy_remove(adapter);
phy_init_fail:
	devm_kfree(&pdev->dev, adapter);
	return NULL;
}

void nbl_core_remove(struct nbl_adapter *adapter)
{
	struct device *dev;
	struct nbl_common_info *common;
	struct nbl_product_base_ops *product_base_ops;

	if (!adapter)
		return;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	common = NBL_ADAPTER_TO_COMMON(adapter);
	product_base_ops = NBL_ADAPTER_TO_RPDUCT_BASE_OPS(adapter);

	nbl_debugfs_func_remove(adapter);
	nbl_dev_remove(adapter);
	nbl_serv_remove(adapter);
	nbl_disp_remove(adapter);
	product_base_ops->res_remove(adapter);
	product_base_ops->chan_remove(adapter);
	product_base_ops->phy_remove(adapter);
	devm_kfree(dev, adapter);
}

int nbl_st_init(struct nbl_software_tool_table *st_table)
{
	dev_t devid;
	int ret = 0;

	ret = alloc_chrdev_region(&devid, 0, NBL_ST_MAX_DEVICE_NUM, "nblst");
	if (ret < 0)
		return ret;

	st_table->major = MAJOR(devid);
	st_table->devno = devid;

	st_table->cls = class_create("nblst_cls");

	if (IS_ERR(st_table->cls)) {
		unregister_chrdev(st_table->major, "nblst");
		unregister_chrdev_region(st_table->devno, NBL_ST_MAX_DEVICE_NUM);
		ret = -EBUSY;
	}

	return ret;
}

void nbl_st_remove(struct nbl_software_tool_table *st_table)
{
	class_destroy(st_table->cls);
	unregister_chrdev(st_table->major, "nblst");
	unregister_chrdev_region(st_table->devno, NBL_ST_MAX_DEVICE_NUM);
}

struct nbl_software_tool_table *nbl_get_st_table(void)
{
	return &nbl_st_table;
}

static void nbl_debugfs_init(void)
{
	nbl_debugfs_root = debugfs_create_dir(NBL_DRIVER_NAME, NULL);
}

static void nbl_debugfs_remove(void)
{
	debugfs_remove_recursive(nbl_debugfs_root);
	nbl_debugfs_root = NULL;
}

struct dentry *nbl_get_debugfs_root(void)
{
	return nbl_debugfs_root;
}

static void nbl_get_func_param(struct pci_dev *pdev, kernel_ulong_t driver_data,
			       struct nbl_init_param *param)
{
	param->caps.has_ctrl = NBL_CAP_IS_CTRL(driver_data);
	param->caps.has_net = NBL_CAP_IS_NET(driver_data);
	param->caps.is_vf = NBL_CAP_IS_VF(driver_data);
	param->caps.support_lag = NBL_CAP_SUPPORT_LAG(driver_data);
	param->caps.has_user = NBL_CAP_IS_USER(driver_data);
	param->caps.has_grc = NBL_CAP_IS_GRC(driver_data);
	param->caps.is_nic = NBL_CAP_IS_NIC(driver_data);
	param->caps.has_factory_ctrl = NBL_CAP_IS_FACTORY_CTRL(driver_data);

	if (NBL_CAP_IS_LEONIS(driver_data))
		param->product_type = NBL_LEONIS_TYPE;

	/**
	 * Leonis only PF0 has ctrl capability, but PF0's pcie device_id is same with other PF.
	 * So hanle it special.
	 **/
	if (param->product_type == NBL_LEONIS_TYPE && !param->caps.is_vf &&
	    (PCI_FUNC(pdev->devfn) == 0) && !param->caps.has_factory_ctrl) {
		param->caps.has_ctrl = 1;
		param->caps.has_grc = 1;
	}

	if (param->caps.has_ctrl && param->caps.has_factory_ctrl) {
		dev_err(&pdev->dev, "Do not support ctrl & factory_ctrl simutaneously, skip ctrl");
		memset(&param->caps, 0, sizeof(param->caps));
		param->caps.has_factory_ctrl = true;
	}
}

static int nbl_probe(struct pci_dev *pdev, const struct pci_device_id __always_unused *id)
{
	struct device *dev = &pdev->dev;
	struct nbl_adapter *adapter = NULL;
	struct nbl_init_param param = {{0}};
	int err;

	dev_info(dev, "nbl probe\n");

	err = pci_enable_device(pdev);
	if (err)
		return err;

	param.pci_using_dac = true;
	nbl_get_func_param(pdev, id->driver_data, &param);

	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		dev_info(dev, "Configure DMA 64 bit mask failed, err = %d\n", err);
		param.pci_using_dac = false;
		err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(dev, "Configure DMA 32 bit mask failed, err = %d\n", err);
			goto configure_dma_err;
		}
	}

	pci_set_master(pdev);

	pci_save_state(pdev);

	adapter = nbl_core_init(pdev, &param);
	if (!adapter) {
		dev_err(dev, "Nbl adapter init fail\n");
		err = -EAGAIN;
		goto adapter_init_err;
	}

	pci_set_drvdata(pdev, adapter);

	err = nbl_core_start(adapter, &param);
	if (err)
		goto core_start_err;

	dev_info(dev, "nbl probe finished\n");

	return 0;

core_start_err:
	nbl_core_remove(adapter);
adapter_init_err:
	pci_clear_master(pdev);
configure_dma_err:
	pci_disable_device(pdev);
	return err;
}

static void nbl_remove(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	dev_info(&pdev->dev, "nbl remove\n");
	pci_disable_sriov(pdev);

	nbl_core_stop(adapter);
	nbl_core_remove(adapter);

	pci_clear_master(pdev);
	pci_disable_device(pdev);

	dev_info(&pdev->dev, "nbl remove OK!\n");
}

static void nbl_shutdown(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	if (!NBL_COMMON_TO_VF_CAP(NBL_ADAPTER_TO_COMMON(adapter)))
		nbl_remove(pdev);

	dev_info(&pdev->dev, "nbl shutdown OK\n");
}

static __maybe_unused int nbl_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	int err;

	if (!num_vfs) {
		pci_disable_sriov(pdev);
		return 0;
	}

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		dev_err(&pdev->dev, "nbl enable sriov failed %d!\n", err);
		return err;
	}

	return num_vfs;
}

#define NBL_VENDOR_ID			(0x1F0F)

/**
 *  Leonis DeviceID
 * 0x3403-0x340d for snic v3r1 product
 **/
#define NBL_DEVICE_ID_M18110			(0x3403)
#define NBL_DEVICE_ID_M18110_LX			(0x3404)
#define NBL_DEVICE_ID_M18110_BASE_T		(0x3405)
#define NBL_DEVICE_ID_M18110_LX_BASE_T		(0x3406)
#define NBL_DEVICE_ID_M18110_OCP		(0x3407)
#define NBL_DEVICE_ID_M18110_LX_OCP		(0x3408)
#define NBL_DEVICE_ID_M18110_BASE_T_OCP		(0x3409)
#define NBL_DEVICE_ID_M18110_LX_BASE_T_OCP	(0x340a)
#define NBL_DEVICE_ID_M18120			(0x340b)
#define NBL_DEVICE_ID_M18120_LX			(0x340c)
#define NBL_DEVICE_ID_M18120_BASE_T		(0x340d)
#define NBL_DEVICE_ID_M18120_LX_BASE_T		(0x340e)
#define NBL_DEVICE_ID_M18120_OCP		(0x340f)
#define NBL_DEVICE_ID_M18120_LX_OCP		(0x3410)
#define NBL_DEVICE_ID_M18120_BASE_T_OCP		(0x3411)
#define NBL_DEVICE_ID_M18120_LX_BASE_T_OCP	(0x3412)
#define NBL_DEVICE_ID_M18100_VF			(0x3413)

static const struct pci_device_id nbl_id_table[] = {
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	   NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	   NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	   NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18120_LX_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	/* required as sentinel */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, nbl_id_table);

static int nbl_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	return nbl_dev_suspend(adapter);
}

static int nbl_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	return nbl_dev_resume(adapter);
}

static SIMPLE_DEV_PM_OPS(nbl_pm_ops, nbl_suspend, nbl_resume);
static struct pci_driver nbl_driver = {
	.name = NBL_DRIVER_NAME,
	.id_table = nbl_id_table,
	.probe = nbl_probe,
	.remove = nbl_remove,
	.shutdown = nbl_shutdown,
	.driver.pm = &nbl_pm_ops,
};

static int __init nbl_module_init(void)
{
	int status;

	nbl_dev_user_module_init();
	status = nbl_common_create_wq();
	if (status) {
		pr_err("Failed to create wq, err = %d\n", status);
		goto wq_create_failed;
	}

	nbl_st_init(nbl_get_st_table());
	nbl_debugfs_init();

	nbl_event_init();

	status = pci_register_driver(&nbl_driver);
	if (status) {
		pr_err("Failed to register PCI driver, err = %d\n", status);
		goto pci_register_driver_failed;
	}

	return 0;

pci_register_driver_failed:
	nbl_debugfs_remove();
	nbl_common_destroy_wq();
wq_create_failed:
	nbl_dev_user_module_destroy();
	return status;
}

static void __exit nbl_module_exit(void)
{
	pci_unregister_driver(&nbl_driver);

	nbl_st_remove(nbl_get_st_table());

	nbl_common_destroy_wq();

	nbl_dev_user_module_destroy();

	nbl_debugfs_remove();

	nbl_event_remove();

	pr_info("nbl module unloaded\n");
}

module_init(nbl_module_init);
module_exit(nbl_module_exit);
MODULE_LICENSE("GPL");

#define NBL_FW_PATH			"nbl/"
#define NBL_FW_SNIC_PATH		NBL_FW_PATH "snic_v3r1/"
#define NBL_FW_TUNNEL_TOE_P4		NBL_FW_SNIC_PATH

MODULE_FIRMWARE(NBL_FW_SNIC_PATH "nbl_single_tunnel_toe_enhance.elf");
