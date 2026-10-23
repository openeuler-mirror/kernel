// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include <linux/aer.h>
#include "nbl_core.h"

static struct nbl_software_tool_table nbl_st_table;
static struct dentry *nbl_debugfs_root;

/* global cmdq and tc flow related structures */
static struct nbl_tc_insts_info g_tc_insts[NBL_TC_FLOW_INST_COUNT] = { { 0 } };

static struct nbl_product_base_ops nbl_product_base_ops[NBL_PRODUCT_MAX] = {
	{
		.phy_init	= nbl_phy_init_leonis,
		.phy_remove	= nbl_phy_remove_leonis,
		.res_init	= nbl_res_init_leonis,
		.res_remove	= nbl_res_remove_leonis,
		.chan_init	= nbl_chan_init_common,
		.chan_remove	= nbl_chan_remove_common,
	},
	{
		.phy_init	= nbl_phy_init_draco,
		.phy_remove	= nbl_phy_remove_draco,
		.res_init	= nbl_res_init_draco,
		.res_remove	= nbl_res_remove_draco,
		.chan_init	= nbl_chan_init_draco,
		.chan_remove	= nbl_chan_remove_common,
	},
};

static char *nblst_cdevnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "nblst/%s", dev_name(dev));
}

int nbl_core_start(struct nbl_adapter *adapter, struct nbl_init_param *param)
{
	int ret = 0;

	ret = nbl_dev_start(adapter, param, true);
	return ret;
}

void nbl_core_stop(struct nbl_adapter *adapter)
{
	nbl_dev_stop(adapter, true);
}

static void nbl_core_setup_product_ops(struct nbl_adapter *adapter, struct nbl_init_param *param,
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
	NBL_COMMON_TO_OCP_CAP(common) = param->caps.is_ocp;
	NBL_COMMON_TO_PCI_USING_DAC(common) = param->pci_using_dac;
	NBL_COMMON_TO_PCI_FUNC_ID(common) = PCI_FUNC(pdev->devfn);
	common->devid    = PCI_SLOT(pdev->devfn);
	common->bus      = pdev->bus->number;
	common->tc_inst_id = NBL_TC_FLOW_INST_COUNT;
	common->product_type = param->product_type;
	common->has_ctrl = param->caps.has_ctrl;

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
	struct nbl_product_base_ops *product_base_ops;

	if (!adapter)
		return;

	dev = NBL_ADAPTER_TO_DEV(adapter);
	product_base_ops = NBL_ADAPTER_TO_RPDUCT_BASE_OPS(adapter);

	nbl_dev_remove(adapter);
	nbl_serv_remove(adapter);
	nbl_disp_remove(adapter);
	product_base_ops->res_remove(adapter);
	product_base_ops->chan_remove(adapter);
	product_base_ops->phy_remove(adapter);
	devm_kfree(dev, adapter);
}

void nbl_tc_set_cmdq_info(int (*send_cmdq)(void *, const void *, void *),
			  void *priv, u8 index)
{
	g_tc_insts[index].send_cmdq = send_cmdq;
	g_tc_insts[index].chan_mgt = priv;
}

void nbl_tc_unset_cmdq_info(u8 index)
{
	g_tc_insts[index].send_cmdq = NULL;
	g_tc_insts[index].chan_mgt = NULL;
	g_tc_insts[index].locked = 0;
}

void nbl_tc_set_flow_info(void *priv, u8 index)
{
	g_tc_insts[index].tc_flow_mgt = priv;
}

void nbl_tc_unset_flow_info(u8 index)
{
	g_tc_insts[index].tc_flow_mgt = NULL;
}

void *nbl_tc_get_flow_info(u8 index)
{
	return g_tc_insts[index].tc_flow_mgt;
}

u8 nbl_tc_alloc_inst_id(void)
{
	u8 inst_id = 0;

	spin_lock(&nbl_tc_flow_inst_lock);
	for (inst_id = 0; inst_id < NBL_TC_FLOW_INST_COUNT; inst_id++)
		if (!g_tc_insts[inst_id].locked) {
			g_tc_insts[inst_id].locked = 1;
			spin_unlock(&nbl_tc_flow_inst_lock);
			return inst_id;
		}

	/* return invalid index */
	spin_unlock(&nbl_tc_flow_inst_lock);
	return NBL_TC_FLOW_INST_COUNT;
}

int nbl_tc_call_inst_cmdq(u8 inst_id, const void *hdr, void *cmd)
{
	void *priv = NULL;

	if (!g_tc_insts[inst_id].chan_mgt || !g_tc_insts[inst_id].send_cmdq)
		return NBL_CMDQ_NOT_READY;

	priv = g_tc_insts[inst_id].chan_mgt;
	return g_tc_insts[inst_id].send_cmdq(priv, hdr, cmd);
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
	st_table->cls->devnode = nblst_cdevnode;
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
	param->caps.is_blk = NBL_CAP_IS_BLK(driver_data);
	param->caps.is_nic = NBL_CAP_IS_NIC(driver_data);
	param->caps.is_ocp = NBL_CAP_IS_OCP(driver_data);

	if (NBL_CAP_IS_DRACO(driver_data))
		param->product_type = NBL_DRACO_TYPE;
	if (NBL_CAP_IS_LEONIS(driver_data))
		param->product_type = NBL_LEONIS_TYPE;

	/**
	 * Leonis only PF0 has ctrl capability, but PF0's pcie device_id is same with other PF.
	 * So hanle it special.
	 **/
	if (param->product_type == NBL_LEONIS_TYPE && !param->caps.is_vf &&
	    (PCI_FUNC(pdev->devfn) == 0)) {
		param->caps.has_ctrl = 1;
		param->caps.has_grc = 1;
	}

	/**
	 * Draco only PF0-PF3 has ctrl capability,
	 * but PF4-PF7's pcie device_id is same with other PF.
	 * So hanle it special.
	 **/
	if (param->product_type == NBL_DRACO_TYPE && !param->caps.is_vf &&
	    (PCI_FUNC(pdev->devfn) >= 4)) {
		param->caps.has_ctrl = 0;
		param->caps.has_grc = 0;
		param->caps.support_lag = 0;
		param->caps.has_user = 0;
		param->caps.is_vf = 1;
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

	if (param.caps.is_blk) {
		/* Set adapter NULL */
		pci_set_drvdata(pdev, adapter);
		dev_info(dev, "nbl_vdpa_blk probe OK\n");
		return NBL_OK;
	}

	device_disable_async_suspend(dev);

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

	nbl_debugfs_func_init(adapter, &param);

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

/**
 * check if pci link is err, set phy_layer hw_status. And nbl_dev_stop\
 * nbl_dev_remove will skip chip status check
 **/
static void nbl_check_fast_remove(struct nbl_adapter *adapter)
{
	nbl_dev_check_fast_remove(adapter);
}

static int nbl_core_drain_pci_err_resume(struct pci_dev *pdev, struct nbl_adapter *adapter)
{
	int i = 0;

	if (!adapter)
		return 0;

	if (!test_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return 0;

	while (i++ < 30) {
		dev_info(&pdev->dev, "wait pci err resume\n");
		msleep(2000);

		if (!test_bit(NBL_PCI_ERR_RECOVERING, adapter->state)) {
			dev_info(&pdev->dev, "pci err resume finish\n");
			return 0;
		}
	}

	dev_info(&pdev->dev, "pci err resume failed\n");

	return -EIO;
}

static void nbl_remove(struct pci_dev *pdev)
{
	int ret;
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	dev_info(&pdev->dev, "nbl remove\n");
	ret = nbl_core_drain_pci_err_resume(pdev, adapter);
	if (ret)
		goto release_device;

	pci_disable_sriov(pdev);
	if (!adapter)
		goto release_device;

	nbl_debugfs_func_remove(adapter);
	nbl_check_fast_remove(adapter);
	nbl_core_stop(adapter);
	nbl_core_remove(adapter);

release_device:
	pci_clear_master(pdev);
	pci_disable_device(pdev);

	dev_info(&pdev->dev, "nbl remove OK!\n");
}

static void nbl_shutdown(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	bool wol_ena = common->wol_ena;

	if (!adapter || !NBL_COMMON_TO_VF_CAP(NBL_ADAPTER_TO_COMMON(adapter)))
		nbl_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wol_ena);
		pci_set_power_state(pdev, PCI_D3hot);
	}

	dev_info(&pdev->dev, "nbl shutdown OK\n");
}

static __maybe_unused int nbl_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	int err;

	if (!num_vfs) {
		pci_disable_sriov(pdev);
		if (!adapter)
			return 0;

		err = nbl_dev_destroy_rep(adapter);
		if (err) {
			dev_err(&pdev->dev, "nbl destroy repr dev failed %d!\n", err);
			return err;
		}

		nbl_dev_remove_vf_config(adapter);
		return 0;
	}

	/* register pf_name to AF first, cuz vf_name depends on pf_anme */
	nbl_dev_register_dev_name(adapter);

	err = nbl_dev_setup_vf_config(adapter, num_vfs);
	if (err) {
		dev_err(&pdev->dev, "nbl setup vf config failed %d!\n", err);
		return err;
	}

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		nbl_dev_remove_vf_config(adapter);
		dev_err(&pdev->dev, "nbl enable sriov failed %d!\n", err);
		return err;
	}

	err = nbl_dev_create_rep(adapter, num_vfs);
	if (err) {
		dev_err(&pdev->dev, "nbl create repr dev failed %d!\n", err);
		pci_disable_sriov(pdev);
		nbl_dev_remove_vf_config(adapter);
		return err;
	}

	return num_vfs;
}

#define NBL_VENDOR_ID			(0x1F0F)

/**
 * Draco DeviceID
 * 0x3500-0x3501 reserve for internal test
 * 0x3502-0x350a for snic v5r1 product
 **/
#define NBL_DEVICE_ID_M18305			(0x3502)
#define NBL_DEVICE_ID_M18305_LX			(0x3503)
#define NBL_DEVICE_ID_M18305_BASE_T		(0x3504)
#define NBL_DEVICE_ID_M18305_LX_BASE_T		(0x3505)
#define NBL_DEVICE_ID_M18305_OCP		(0x3506)
#define NBL_DEVICE_ID_M18305_LX_OCP		(0x3507)
#define NBL_DEVICE_ID_M18305_BASE_T_OCP		(0x3508)
#define NBL_DEVICE_ID_M18305_LX_BASE_T_OCP	(0x3509)
#define NBL_DEVICE_ID_M18305_VF			(0x350a)

/**
 *  Leonis DeviceID
 * 0x3400-0x3402 reserve for internal test
 * 0x3403-0x340d for snic v3r1 product
 **/
#define NBL_DEVICE_ID_LEONIS_PF			(0x3401)
#define NBL_DEVICE_ID_LEONIS_VF			(0x3402)
#define NBL_DEVICE_ID_M18110			(0x3403)
#define NBL_DEVICE_ID_M18110_LX			(0x3404)
#define NBL_DEVICE_ID_M18110_BASE_T		(0x3405)
#define NBL_DEVICE_ID_M18110_LX_BASE_T		(0x3406)
#define NBL_DEVICE_ID_M18110_OCP		(0x3407)
#define NBL_DEVICE_ID_M18110_LX_OCP		(0x3408)
#define NBL_DEVICE_ID_M18110_BASE_T_OCP		(0x3409)
#define NBL_DEVICE_ID_M18110_LX_BASE_T_OCP	(0x340a)
#define NBL_DEVICE_ID_M18000			(0x340b)
#define NBL_DEVICE_ID_M18000_LX			(0x340c)
#define NBL_DEVICE_ID_M18000_BASE_T		(0x340d)
#define NBL_DEVICE_ID_M18000_LX_BASE_T		(0x340e)
#define NBL_DEVICE_ID_M18000_OCP		(0x340f)
#define NBL_DEVICE_ID_M18000_LX_OCP		(0x3410)
#define NBL_DEVICE_ID_M18000_BASE_T_OCP		(0x3411)
#define NBL_DEVICE_ID_M18000_LX_BASE_T_OCP	(0x3412)
#define NBL_DEVICE_ID_M18000_VF			(0x3413)

static const struct pci_device_id nbl_id_table[] = {
	/* draco */
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_LX), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_LX_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_LX_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_LX_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_CTRL_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) | NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_GRC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18305_VF), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_DRACO_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_VF_BIT) },

	/* leonis */
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_LEONIS_PF), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_LEONIS_VF), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_VF_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) },
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
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18110_LX_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX_BASE_T), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_LX_BASE_T_OCP), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) | NBL_CAP_SET_BIT(NBL_CAP_HAS_USER_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_SUPPORT_LAG_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_OCP_BIT)},
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_M18000_VF), .driver_data =
	  NBL_CAP_SET_BIT(NBL_CAP_HAS_NET_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_VF_BIT) |
	  NBL_CAP_SET_BIT(NBL_CAP_IS_NIC_BIT) | NBL_CAP_SET_BIT(NBL_CAP_IS_LEONIS_BIT) },

	/* required as sentinel */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, nbl_id_table);

static pci_ers_result_t nbl_pci_err_detected(struct pci_dev *pdev,
					     pci_channel_state_t state)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	enum pci_ers_result res;

	dev_info(dev, "pci channel state:%s\n", state == pci_channel_io_perm_failure ?
		 "disconnect" : "need_reset");

	/* vblk has't alloc struct adapter */
	if (adapter)
		nbl_dev_pci_err_stop(adapter);
	pci_disable_device(pdev);

	res = state == pci_channel_io_perm_failure ?
		PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_NEED_RESET;
	return res;
}

static void nbl_pci_reset_prepare(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	dev_info(dev, "pci reset prepare\n");
	if (adapter)
		nbl_dev_pci_err_stop(adapter);
}

static void nbl_pci_reset_done(struct pci_dev *pdev)
{
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	dev_info(dev, "pci reset done\n");
	if (adapter)
		nbl_dev_pci_err_start(adapter);
}

static pci_ers_result_t nbl_pci_slot_reset(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	enum pci_ers_result res = PCI_ERS_RESULT_DISCONNECT;
	int err;

	err = pci_enable_device(pdev);
	if (err)
		goto out;

	pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);
	res = PCI_ERS_RESULT_RECOVERED;
out:
	dev_info(dev, "pci slot reset, ret:%s\n", res == PCI_ERS_RESULT_RECOVERED ?
		 "recovered" : "disconnect");
	return res;
}

static void nbl_pci_resume(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	dev_info(dev, "pci channel resume\n");

	/* vblk has't alloc struct adapter */
	if (adapter)
		nbl_dev_pci_err_start(adapter);
}

static int __maybe_unused nbl_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	return nbl_dev_suspend(adapter);
}

static int __maybe_unused nbl_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);

	return nbl_dev_resume(adapter);
}

static SIMPLE_DEV_PM_OPS(nbl_pm_ops, nbl_suspend, nbl_resume);

static const struct pci_error_handlers nbl_err_handler = {
	.error_detected = nbl_pci_err_detected,
	.slot_reset	= nbl_pci_slot_reset,
	.resume		= nbl_pci_resume,
	.reset_prepare  = nbl_pci_reset_prepare,
	.reset_done	= nbl_pci_reset_done,
};

static struct pci_driver nbl_driver = {
	.name = NBL_DRIVER_NAME,
	.id_table = nbl_id_table,
	.probe = nbl_probe,
	.remove = nbl_remove,
	.shutdown = nbl_shutdown,
	.err_handler = &nbl_err_handler,
	.sriov_configure = nbl_sriov_configure,
	.driver.pm = &nbl_pm_ops,
};

static void nbl_print_compile_macro(void)
{
	pr_info("Nebula-Matrix nbl-core compile macro: ");

	pr_info("NBL_VXLAN_TOE_ENHANCE=0,");

	pr_info("NBL_NOEN_ACCEL=0,");

	pr_info("NBL_RDMA_COMPILE=1,");

	pr_info("WITH_OFED=0");
}

static int __init nbl_module_init(void)
{
	int status;

	pr_info("Nebula-Matrix nbl-core git version %s\n", GIT_COMMIT);
	nbl_print_compile_macro();

	nbl_dev_user_module_init();
	status = nbl_common_create_wq();
	if (status) {
		pr_err("Failed to create wq, err = %d\n", status);
		goto wq_create_failed;
	}

	spin_lock_init(&nbl_tc_flow_inst_lock);

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
MODULE_DESCRIPTION("Nebula-Matrix Ethernet Controller M18110/M18000/M18305 driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(NBL_DRIVER_VERSION);

#define NBL_FW_PATH			"nbl/"
#define NBL_FW_SNIC_PATH		NBL_FW_PATH "snic_v3r1/"
#define NBL_FW_TUNNEL_TOE_P4		NBL_FW_SNIC_PATH

MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_single_port_vxlan_toe_enhance");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_dual_port_vxlan_toe_enhance");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_quad_port_vxlan_toe_enhance");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_single_port_p4_hg");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_dual_port_p4_hg");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_quad_port_p4_hg");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_single_port_p4_lg");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_dual_port_p4_lg");
MODULE_FIRMWARE(NBL_FW_SNIC_PATH "m18xxx_quad_port_p4_lg");
