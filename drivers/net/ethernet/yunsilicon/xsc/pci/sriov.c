// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/pci.h>
#include "common/xsc_core.h"
#include "common/xsc_lag.h"
#include "common/vport.h"
#ifdef CONFIG_XSC_ESWITCH
#include "eswitch.h"
#endif
#include "fw/xsc_tbm.h"
#include "xsc_pci_ctrl.h"

static int xsc_device_enable_sriov(struct xsc_core_device *dev, int num_vfs)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	u16 vf;
	u16 max_msix = 0;
	int err;

	max_msix = xsc_get_irq_matrix_global_available(dev);
	xsc_core_info(dev, "global_available=%u\n", max_msix);
	err = xsc_cmd_enable_hca(dev, num_vfs, max_msix);
	if (err)
		return err;

	if (!XSC_ESWITCH_MANAGER(dev))
		goto enable_vfs;

#ifdef CONFIG_XSC_ESWITCH
	err = xsc_eswitch_enable(dev->priv.eswitch, XSC_ESWITCH_LEGACY,
				 num_vfs);
	if (err) {
		xsc_core_warn(dev, "failed to enable eswitch SRIOV (%d)\n", err);
		return err;
	}
#endif

enable_vfs:
	err = xsc_create_vfs_sysfs(dev, num_vfs);
	if (err) {
		xsc_core_warn(dev, "failed to create SRIOV sysfs (%d)\n", err);
#ifdef CONFIG_XSC_ESWITCH
		if (XSC_ESWITCH_MANAGER(dev))
			xsc_eswitch_disable(dev->priv.eswitch, true);
#endif
		return err;
	}

	xsc_lag_disable(dev);
	for (vf = 0; vf < num_vfs; vf++)
		sriov->vfs_ctx[vf].enabled = 1;
	xsc_lag_enable(dev);

	return 0;
}

static void xsc_device_disable_sriov(struct xsc_core_device *dev,
				     int num_vfs, bool clear_vf)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	int vf, err;

	err = xsc_cmd_disable_hca(dev, (u16)num_vfs);
	if (err) {
		xsc_core_warn(dev, "failed to disable hca, num_vfs=%d, err=%d\n",
			      num_vfs, err);
		return;
	}

	for (vf = num_vfs - 1; vf >= 0; vf--) {
		if (!sriov->vfs_ctx[vf].enabled)
			continue;

		sriov->vfs_ctx[vf].enabled = 0;
	}

#ifdef CONFIG_XSC_ESWITCH
	if (XSC_ESWITCH_MANAGER(dev)) {
		xsc_lag_disable(dev);
		xsc_eswitch_disable(dev->priv.eswitch, clear_vf);
		xsc_lag_enable(dev);
	}
#endif

	xsc_destroy_vfs_sysfs(dev, num_vfs);
}

static int xsc_sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	struct xsc_core_device *dev = pci_get_drvdata(pdev);
	int err;

	if (num_vfs > dev->caps.max_vfs) {
		xsc_core_warn(dev,
			      "invalid sriov param, num_vfs(%d) > total_vfs(%d)\n",
			      num_vfs, dev->caps.max_vfs);
		return -EINVAL;
	}

	if (num_vfs && pci_num_vf(dev->pdev)) {
		if (num_vfs == pci_num_vf(dev->pdev))
			return 0;

		xsc_core_warn(dev, "VFs already enabled. Disable before enabling %d VFs\n",
			      num_vfs);
		return -EBUSY;
	}

	xsc_core_info(dev, "%s: num_vfs=%d\n", __func__, num_vfs);

	err = xsc_device_enable_sriov(dev, num_vfs);
	if (err) {
		xsc_core_warn(dev, "xsc_device_enable_sriov failed : %d\n", err);
		return err;
	}

	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		xsc_core_warn(dev, "pci_enable_sriov failed : %d\n", err);
		xsc_device_disable_sriov(dev, num_vfs, true);
	}

	return err;
}

static void xsc_sriov_disable(struct pci_dev *pdev)
{
	struct xsc_core_device *dev  = pci_get_drvdata(pdev);
	int num_vfs = pci_num_vf(dev->pdev);

	xsc_core_info(dev, "%s: num_vfs=%d\n", __func__, num_vfs);
	pci_disable_sriov(pdev);

	xsc_device_disable_sriov(dev, num_vfs, true);
}

int xsc_core_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct xsc_core_device *dev  = pci_get_drvdata(pdev);
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	int err = 0;

	xsc_core_info(dev, "%s: requested num_vfs %d\n",
		      __func__, num_vfs);

	if (num_vfs)
		err = xsc_sriov_enable(pdev, num_vfs);
	else
		xsc_sriov_disable(pdev);

	if (!err)
		sriov->num_vfs = num_vfs;
	return err ? err : num_vfs;
}

int xsc_sriov_attach(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;
	struct xsc_core_device *pf_xdev;
	struct xsc_core_sriov *sriov;

	if (!xsc_core_is_pf(dev)) {
		if (!pdev->physfn)    /*for vf passthrough vm*/
			return 0;

		pf_xdev = pci_get_drvdata(pdev->physfn);
		sriov = &pf_xdev->priv.sriov;

		sriov->vfs[dev->vf_id].vf = dev->vf_id;
		sriov->vfs[dev->vf_id].dev = dev;
		return 0;
	}

	if (!dev->priv.sriov.num_vfs)
		return 0;

	/* If sriov VFs exist in PCI level, enable them in device level */
	return xsc_device_enable_sriov(dev, pci_num_vf(dev->pdev));
}

void xsc_sriov_detach(struct xsc_core_device *dev)
{
	if (!xsc_core_is_pf(dev) || !dev->priv.sriov.num_vfs)
		return;

	xsc_device_disable_sriov(dev, pci_num_vf(dev->pdev), false);
}

static u16 xsc_get_max_vfs(struct xsc_core_device *dev)
{
	return (pci_sriov_get_totalvfs(dev->pdev) < 0) ? 0 :
		pci_sriov_get_totalvfs(dev->pdev);
}

static int xsc_sriov_pci_cfg_info(struct xsc_core_device *dev,
				  struct xsc_pci_sriov *iov)
{
	int pos;
	struct pci_dev *pdev = dev->pdev;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		xsc_core_err(dev, "%s: failed to find SRIOV capability in device\n",
			     __func__);
		return -ENODEV;
	}

	iov->pos = pos;
	pci_read_config_dword(pdev, pos + PCI_SRIOV_CAP, &iov->cap);
	pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL, &iov->ctrl);
	pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &iov->total_vfs);
	pci_read_config_word(pdev, pos + PCI_SRIOV_INITIAL_VF, &iov->initial_vfs);
	pci_read_config_word(pdev, pos + PCI_SRIOV_NUM_VF, &iov->num_vfs);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_OFFSET, &iov->offset);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_STRIDE, &iov->stride);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID, &iov->vf_device);
	pci_read_config_dword(pdev, pos + PCI_SRIOV_SUP_PGSIZE, &iov->pgsz);
	pci_read_config_byte(pdev, pos + PCI_SRIOV_FUNC_LINK, &iov->link);

	return 0;
}

int xsc_sriov_init(struct xsc_core_device *dev)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	struct pci_dev *pdev = dev->pdev;
	struct xsc_pci_sriov *iov = &sriov->pci_sriov;
	int total_vfs;
	u32 vf_bus, vf_devfn;
	int err;

	if (!xsc_core_is_pf(dev))
		return 0;

	err = xsc_sriov_pci_cfg_info(dev, iov);
	if (err) {
		xsc_core_warn(dev, "%s: pci not support sriov, err=%d\n",
			      __func__, err);
		return 0;
	}

	total_vfs = pci_sriov_get_totalvfs(pdev);
	if (unlikely(iov->total_vfs == 0)) {
		xsc_core_warn(dev, "%s: pci not support sriov, total_vfs=%d, cur_vfs=%d\n",
			      __func__, iov->total_vfs, sriov->num_vfs);
		return 0;
	}
	sriov->max_vfs = xsc_get_max_vfs(dev);
	sriov->num_vfs = pci_num_vf(pdev);

	vf_bus = pdev->bus->number + ((pdev->devfn + iov->offset) >> 8);
	vf_devfn = (pdev->devfn + iov->offset) & 0xff;
	sriov->vf_bdf_base = (u16)((vf_bus << 8) | vf_devfn);

	sriov->vfs_ctx = kcalloc(total_vfs, sizeof(*sriov->vfs_ctx), GFP_KERNEL);
	if (!sriov->vfs_ctx)
		return -ENOMEM;

	xsc_core_info(dev, "%s: total_vfs=%d, cur_vfs=%d, vf_bdf_base=0x%02x\n",
		      __func__, total_vfs, sriov->num_vfs, sriov->vf_bdf_base);
	xsc_core_info(dev, "%s: vf_offset=%d, stride=%d, vf_device_id=0x%x\n",
		      __func__, iov->offset, iov->stride, iov->vf_device);
	err = xsc_sriov_sysfs_init(dev);
	if (err) {
		xsc_core_warn(dev, "failed to init SRIOV sysfs (%d)\n", err);
		kfree(sriov->vfs_ctx);
		return err;
	}

	return 0;
}

void xsc_sriov_cleanup(struct xsc_core_device *dev)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;

	if (!xsc_core_is_pf(dev))
		return;

	xsc_sriov_sysfs_cleanup(dev);
	kfree(sriov->vfs_ctx);
}
