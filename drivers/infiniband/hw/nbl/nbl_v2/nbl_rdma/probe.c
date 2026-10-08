// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/nbl-v2-abi.h>
#include <linux/bitfield.h>
#include <net/addrconf.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include "nbl_compat.h"
#include "shared.h"
#include "cqp.h"
#include "device.h"
#include "main.h"
#include "counters.h"
#include "dbgfs.h"
#include "lag.h"
#include "umr.h"
#include "probe.h"
#include "resource.h"

int nbl_probe_v2(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct nbl_adev *adev = container_of(aux_dev, struct nbl_adev, adev);
	struct nbl_core_export *core_info = adev->core_info;
	struct nbl_pci_f *rf = NULL;
	struct nbl_device *nbl_dev = ib_alloc_device(nbl_device, ibdev);
	int err;
	size_t size;

	size = sizeof(struct nbl_device) +
	       BUILD_BUG_ON_ZERO(offsetof(struct nbl_device, ibdev));

	if (!nbl_dev) {
		nbl_dev_err(&aux_dev->dev, "ib alloc device get NULL");
		return -ENOMEM;
	}

	dev_set_drvdata(&aux_dev->dev, nbl_dev);
	nbl_dev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!nbl_dev->rf) {
		dev_set_drvdata(&aux_dev->dev, NULL);
		ib_dealloc_device(&nbl_dev->ibdev);
		nbl_dev_err(&aux_dev->dev, "ib alloc rf mem err");
		return -ENOMEM;
	}
	rf = nbl_dev->rf;
	err = nbl_fill_device_info(nbl_dev, adev);
	if (err)
		goto err_init_device_type;

	err = nbl_debugfs_function_pre_init(nbl_dev);
	if (err)
		goto err_init_device_type;

	nbl_init_src_addr(rf);
	nbl_dev_info(&aux_dev->dev, "probe rdma device for %s\n",
		     nbl_dev->netdev->name);
	err = nbl_init_device_type(rf);
	if (err)
		goto err_init_debugfs;

	nbl_fill_default_cfg(nbl_dev);

	nbl_init_global_cfg(rf);
	nbl_init_rd_atomic_num(rf);

	err = nbl_channel_init(rf);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "channel init return err=%d", err);
		goto err_init_debugfs;
	}

	nbl_set_hw_attr(rf);

	err = nbl_get_init_params(rf);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "get init params err=%d", err);
		goto err_init;
	}
	nbl_pci_set_atomic(nbl_dev, rf->pcidev);

	err = nbl_get_function_num(rf);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "get function_id return err=%d", err);
		goto err_init;
	}

	err = nbl_register_client(rf, true);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "vf=%u register FLR client err=%d",
			    rf->sc_dev.function_id, err);
		goto err_vf_reg;
	}
	err = nbl_qp_res_init(rf);
	if (err)
		goto err_set_hdma_vf_enable;
	err = nbl_set_hdma_vf_enable(rf, 1);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "set hdma vf enable err=%d", err);
		goto err_set_hdma_vf_enable;
	}

	nbl_rdma_dsch_init(rf, NBL_RDMA_DSCH_VALID);
	if (nbl_ctrl_init_hw(rf)) {
		err = -EIO;
		nbl_dev_err(&aux_dev->dev, "nbl ctrl init hw err");
		goto err_ctrl_init;
	}

	err = nbl_shadow_init(rf);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "nbl shadow init err");
		goto err_shadow_init;
	}

	if (nbl_rt_init_hw(nbl_dev)) {
		err = -EIO;
		nbl_dev_err(&aux_dev->dev, "nbl rt init err");
		goto err_rt_init;
	}

	if (nbl_counters_func_init(nbl_dev)) {
		err = -EIO;
		nbl_dev_err(&aux_dev->dev, "nbl counters init err");
		goto err_cnts_init;
	}

	err = nbl_set_qm_vfid_vsi_map(rf, 1);
	if (err)
		goto err_set_vfid_vsi_map;

	err = nbl_ib_register_device(adev, nbl_dev);
	if (err) {
		nbl_dev_err(&aux_dev->dev, "nbl ib register device err=%d", err);
		goto err_ib_reg;
	}

	nbl_debugfs_function_init(nbl_dev);

	err = nbl_umr_resource_init(nbl_dev);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev, "nbl umr init err\n");
		goto err_umr_init;
	}

	nbl_get_fw_ver(rf);

	err = nbl_alloc_abnormal_evt_wq(nbl_dev);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev,
			    "create rdma abnormal_q init err=%d", err);
		goto err_alloc_abnormal_evt_wq;
	}

	err = nbl_init_lag(nbl_dev, core_info);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev, "nbl init lag err=%d\n", err);
		goto err_init_lag;
	}
	err = nbl_register_rdma_event_notifiers(nbl_dev, core_info);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev,
			    "nbl register event notifiers err=%d\n", err);
		goto err_register_event_notifiers;
	}
	nbl_set_mtu(nbl_dev->netdev->mtu, nbl_dev);
	err = nbl_add_mtu_notifier(nbl_dev);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev,
			    "nbl add mtu notifier err=%d\n", err);
		goto err_add_mtu_notifier;
	}
	err = nbl_add_dev_pci_node(nbl_dev, aux_dev, id);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev,
			    "add rdma device pcie node err=%d\n", err);
		goto err_add_dev_pci_node;
	}
	nbl_sysfs_init(nbl_dev);
	err = nbl_add_netdev_notifier(nbl_dev);
	if (err) {
		nbl_dev_err(&nbl_dev->ibdev.dev, "nbl add netdev notifier err=%d\n", err);
		goto err_add_netdev_notifier;
	}

	nbl_init_qpn_info_record(nbl_dev);

	nbl_dev_info(&nbl_dev->ibdev.dev, "probe rdma device %s for %s OK\n",
		     nbl_dev->ibdev.name, nbl_dev->netdev->name);
	return 0;

err_add_netdev_notifier:
	nbl_sysfs_exit(nbl_dev);
	nbl_free_dev_pci_node(nbl_dev);
err_add_dev_pci_node:
	nbl_remove_mtu_notifier(nbl_dev);
err_add_mtu_notifier:
	nbl_unregister_rdma_event_notifiers(nbl_dev, core_info);
err_register_event_notifiers:
	nbl_deinit_lag(nbl_dev, core_info);
err_init_lag:
	nbl_free_abnormal_evt_wq(nbl_dev);
err_alloc_abnormal_evt_wq:
	nbl_umr_resource_cleanup(nbl_dev);
err_umr_init:
	nbl_debugfs_function_exit(nbl_dev);
	nbl_ib_unregister_device(nbl_dev);
err_ib_reg:
	nbl_set_qm_vfid_vsi_map(rf, 0);
err_set_vfid_vsi_map:
	nbl_counters_func_deinit(nbl_dev);
err_cnts_init:
	nbl_rt_deinit_hw(nbl_dev);
err_rt_init:
	nbl_shadow_exit(nbl_dev->rf);
err_shadow_init:
	nbl_ctrl_deinit_hw(nbl_dev->rf);
err_ctrl_init:
	nbl_rdma_dsch_init(rf, NBL_RDMA_DSCH_INVALID);
	nbl_set_hdma_vf_enable(rf, 0);
err_set_hdma_vf_enable:
	nbl_register_client(rf, false);
err_vf_reg:
	nbl_free_function_num(rf);
err_init:
	nbl_channel_exit(rf);
err_init_debugfs:
	nbl_deinit_src_addr(rf);
	nbl_debugfs_function_pre_exit(nbl_dev);
err_init_device_type:
	kfree(nbl_dev->rf);
	dev_set_drvdata(&aux_dev->dev, NULL);
	ib_dealloc_device(&nbl_dev->ibdev);

	return err;
}

void nbl_remove_v2(struct auxiliary_device *adev)
{
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);
	struct nbl_core_export *core_info = nbl_dev->rf->cdev;

	nbl_dev_info(&nbl_dev->ibdev.dev, "remove rdma device %s\n",
		     nbl_dev->ibdev.name);

	nbl_remove_mtu_notifier(nbl_dev);
	nbl_unregister_rdma_event_notifiers(nbl_dev, core_info);
	nbl_free_abnormal_evt_wq(nbl_dev);
	nbl_deinit_lag(nbl_dev, core_info);
	nbl_free_dev_pci_node(nbl_dev);
	nbl_umr_resource_cleanup(nbl_dev);
	nbl_sysfs_exit(nbl_dev);
	nbl_debugfs_function_exit(nbl_dev);
	nbl_ib_unregister_device(nbl_dev);
	/* after ib_unregister_device to keep rdma connection is working */
	nbl_set_qm_vfid_vsi_map(nbl_dev->rf, 0);
	nbl_counters_func_deinit(nbl_dev);

	nbl_cqp_v2_flush_s1_cache_cmd(0, nbl_dev->rf->sc_dev.function_id, nbl_dev->rf, true);
	nbl_confqp_flush(nbl_dev->rf);

	nbl_rdma_dsch_init(nbl_dev->rf, NBL_RDMA_DSCH_INVALID);

	nbl_rt_deinit_hw(nbl_dev);
	nbl_remove_netdev_notifier(nbl_dev);
	nbl_shadow_exit(nbl_dev->rf);
	nbl_ctrl_deinit_hw(nbl_dev->rf);
	/* close hdma at last */
	nbl_set_hdma_vf_enable(nbl_dev->rf, 0);
	nbl_register_client(nbl_dev->rf, false);
	nbl_free_function_num(nbl_dev->rf);
	nbl_channel_exit(nbl_dev->rf);
	nbl_dev_info(&nbl_dev->ibdev.dev, "remove rdma device %s OK\n",
		     nbl_dev->ibdev.name);

	nbl_deinit_src_addr(nbl_dev->rf);

	nbl_debugfs_function_pre_exit(nbl_dev);
	kfree(nbl_dev->rf);
	dev_set_drvdata(&adev->dev, NULL);
	ib_dealloc_device(&nbl_dev->ibdev);
}
