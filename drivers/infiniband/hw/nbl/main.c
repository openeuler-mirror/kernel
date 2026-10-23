// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/pci.h>
#include "nbl_core_common.h"
#include "debug.h"
#include "version.h"
#include "nbl_adapt.h"
#include "nbl_rdma_module.h"
#include "shared.h"

MODULE_AUTHOR("Nebula-Matrix Corporation");
MODULE_DESCRIPTION("NBL(R) Ethernet Protocol Driver for RDMA");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(NBL_DRIVER_VERSION);
MODULE_ALIAS("auxiliary:nbl.nbl.roce2");
MODULE_ALIAS("auxiliary:nbl.nbl.roce_bond2");

static int nbl_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	int ret = -ENODEV;
	struct nbl_adev *adev = container_of(aux_dev, struct nbl_adev, adev);
	struct nbl_core_export *core_info = adev->core_info;

	if (!core_info || !core_info->pdev) {
		nbl_pr_err("core_info pointer is NULL\n");
		return -ENODEV;
	}

	switch (core_info->pdev->device) {
	case SNIC_RDMA_PF_START_DEVICE_ID...SNIC_RDMA_PF_END_DEVICE_ID:
	case SNIC_RDMA_VF_DEVICE_ID:
		ret = nbl_probe_v1(aux_dev, id);
		break;

	case DF200_ECPU_PF2_DEVICE_ID:
	case DF200_ECPU_PF3_DEVICE_ID:
	case DF200_HOST_RDMA_DEVICE_ID:
	case ASIC_V2R1_PF_DEVICE_ID:
	case ASIC_V2R1_VF_DEVICE_ID:
	case DRACO_RDMA_PF_START_DEVICE_ID...DRACO_RDMA_PF_END_DEVICE_ID:
	case DRACO_RDMA_VF_DEVICE_ID:
	case ORION_RDMA_PF_DEVICE_ID:
	case ORION_RDMA_VF_DEVICE_ID:
	case RNIC400_PF_DEVICE_ID:
		ret = nbl_probe_v2(aux_dev, id);
		break;
	default:
		nbl_pr_err("unsupported rdma device_id=%#x\n", core_info->pdev->device);
		break;
	}

	return ret;
}

static void nbl_remove(struct auxiliary_device *aux_dev)
{
	struct nbl_adev *adev = container_of(aux_dev, struct nbl_adev, adev);
	struct nbl_core_export *core_info = adev->core_info;

	switch (core_info->pdev->device) {
	case SNIC_RDMA_PF_START_DEVICE_ID...SNIC_RDMA_PF_END_DEVICE_ID:
	case SNIC_RDMA_VF_DEVICE_ID:
		nbl_remove_v1(aux_dev);
		break;

	case DF200_ECPU_PF2_DEVICE_ID:
	case DF200_ECPU_PF3_DEVICE_ID:
	case DF200_HOST_RDMA_DEVICE_ID:
	case ASIC_V2R1_PF_DEVICE_ID:
	case ASIC_V2R1_VF_DEVICE_ID:
	case DRACO_RDMA_PF_START_DEVICE_ID...DRACO_RDMA_PF_END_DEVICE_ID:
	case DRACO_RDMA_VF_DEVICE_ID:
	case ORION_RDMA_PF_DEVICE_ID:
	case ORION_RDMA_VF_DEVICE_ID:
	case RNIC400_PF_DEVICE_ID:
		nbl_remove_v2(aux_dev);
		break;
	default:
		nbl_pr_err("unsupported rdma device_id=%#x\n", core_info->pdev->device);
		break;
	}
}

static int nbl_grc_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct nbl_adev *adev = container_of(aux_dev, struct nbl_adev, adev);
	struct nbl_core_export *core_info = adev->core_info;
	int ret = -ENODEV;

	if (!core_info || !core_info->pdev) {
		nbl_pr_err("core_info pointer is NULL\n");
		return -ENODEV;
	}

	switch (core_info->pdev->device) {
	case ASIC_V2R1_PF_DEVICE_ID:
	case DRACO_RDMA_PF_START_DEVICE_ID...DRACO_RDMA_PF_END_DEVICE_ID:
	case ORION_RDMA_PF_DEVICE_ID:
		ret = nbl_grc_probe_v2(aux_dev, id);
		break;

	case SNIC_RDMA_PF_START_DEVICE_ID...SNIC_RDMA_PF_END_DEVICE_ID:
		ret = nbl_grc_probe_v1(aux_dev, id);
		break;
	default:
		nbl_pr_err("unsupported rdma device_id=%#x\n", core_info->pdev->device);
		break;
	}

	return ret;
}

static void nbl_grc_remove(struct auxiliary_device *aux_dev)
{
	struct nbl_adev *adev = container_of(aux_dev, struct nbl_adev, adev);
	struct nbl_core_export *core_info = adev->core_info;

	switch (core_info->pdev->device) {
	case ASIC_V2R1_PF_DEVICE_ID:
	case DRACO_RDMA_PF_START_DEVICE_ID...DRACO_RDMA_PF_END_DEVICE_ID:
	case ORION_RDMA_PF_DEVICE_ID:
		nbl_grc_remove_v2(aux_dev);
		break;
	case SNIC_RDMA_PF_START_DEVICE_ID...SNIC_RDMA_PF_END_DEVICE_ID:
		nbl_grc_remove_v1(aux_dev);
		break;
	default:
		nbl_pr_err("unsupported rdma device_id=%#x\n", core_info->pdev->device);
		break;
	}
}

static const struct auxiliary_device_id nbl_grc_id_table[] = {
	{
		.name = "nbl.nbl.roce_grc2",
	},
	{},
};

static struct auxiliary_driver nbl_grc_driver = {
	.name = "rdma_grc",
	.probe = nbl_grc_probe,
	.remove = nbl_grc_remove,
	.id_table = nbl_grc_id_table,
};

static const struct auxiliary_device_id nbl_id_table[] = {
	{
		.name = "nbl.nbl.roce2",
	},
	{
		.name = "nbl.nbl.roce_bond2",
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, nbl_id_table);

static struct auxiliary_driver nbl_driver = {
	.name = "rdma",
	.probe = nbl_probe,
	.remove = nbl_remove,
	.id_table = nbl_id_table,
};

static int __init nbl_init_module(void)
{
	int ret;

	pr_info("Nebula-Matrix RDMA driver version: %s git version:%s\n",
		NBL_DRIVER_VERSION, GIT_VERSION);

	ret = auxiliary_driver_register(&nbl_grc_driver);
	if (ret) {
		nbl_pr_err("init nbl_grc module failed, and the ret is:%d\n", ret);
		return ret;
	}

	ret = nbl_df200_host_notify_init();
	if (ret) {
		nbl_pr_err("init df200 host notify failed, ret=%d\n", ret);
		goto err_unregister_grc_driver;
	}

	nbl_debugfs_init();

	ret = nbl_reset_init();
	if (ret) {
		nbl_pr_err("init rdma reset failed, ret=%d\n", ret);
		goto err_exit_debugfs;
	}

	ret = auxiliary_driver_register(&nbl_driver);
	if (ret) {
		nbl_pr_err("init nbl module failed, and the ret is:%d\n", ret);
		goto err_deinit_reset;
	}

	return 0;

err_deinit_reset:
	nbl_reset_deinit();
err_exit_debugfs:
	nbl_debugfs_exit();
	nbl_df200_host_notify_deinit();
err_unregister_grc_driver:
	auxiliary_driver_unregister(&nbl_grc_driver);
	return ret;
}

static void __exit nbl_exit_module(void)
{
	auxiliary_driver_unregister(&nbl_driver);
	nbl_debugfs_exit();
	nbl_reset_deinit();
	nbl_df200_host_notify_deinit();
	auxiliary_driver_unregister(&nbl_grc_driver);
}

module_init(nbl_init_module);
module_exit(nbl_exit_module);
