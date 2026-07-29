// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_lib.h"
#include "mcevf_idc.h"

struct iidc_core_dev_info my_cdev_info;
struct iidc_auxiliary_dev my_aux_dev;

static void rnp_adev_release_cb(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
}

int mcevf_plug_aux_devs(struct mcevf_pf *pf, const char *name)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	struct iidc_auxiliary_dev *iadev = NULL;
	struct auxiliary_device *adev = NULL;
	struct mcevf_hw *hw = &pf->hw;
	int ret = 0;

	if (!pf->vsi[0])
		return -EFAULT;

	if (!pf->vsi[0]->netdev)
		return -EFAULT;

	cdev_info = kzalloc(sizeof(*cdev_info), GFP_KERNEL);
	if (!cdev_info)
		return -ENOMEM;

	pf->cdev_infos = cdev_info;
	memset(cdev_info, 0, sizeof(*cdev_info));

	cdev_info->ver.major = IIDC_MAJOR_VER;
	cdev_info->ver.minor = IIDC_MINOR_VER;
	cdev_info->pdev = pf->pdev;
	cdev_info->netdev = pf->vsi[0]->netdev;
	cdev_info->eth_bar_base  = pf->hw.eth_bar_base;
	cdev_info->rdma_bar_base = pf->hw.rdma_bar_base;
	cdev_info->rdma_bar_phy = pf->hw.rdma_bar_phy;
	cdev_info->acmr_4m_base = NULL;
	cdev_info->ftype = IIDC_FUNCTION_TYPE_VF;
	cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_ROCEV2;
	cdev_info->pname = pf->vsi[0]->netdev->name;
	cdev_info->num_q_vectors = pf->vsi[0]->num_q_vectors;
	cdev_info->msix_count = 1;
	/* TODO: tmp modify */
	//pf->rdma_irq_base = 5;
	cdev_info->msix_entries = &pf->msix_entries[pf->rdma_irq_base];
	cdev_info->func_num = _vfnum(hw->vfnum);

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		ret = -ENOMEM;
		goto err_alloc_iadev;
	}

	adev = &iadev->adev;

	mutex_lock(&pf->adev_mutex);
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;
	mutex_unlock(&pf->adev_mutex);

	adev->id = (pf->pdev->bus->number << 8) | pf->pdev->devfn;
	adev->dev.release = rnp_adev_release_cb;
	adev->dev.parent = &pf->pdev->dev;
	adev->name = name;

	ret = auxiliary_device_init(adev);
	if (ret)
		goto err_init_aux_dev;

	ret = auxiliary_device_add(adev);
	if (ret)
		goto err_add_aux_dev;

	return 0;
err_add_aux_dev:
	auxiliary_device_uninit(adev);
	iadev = NULL;
err_init_aux_dev:
	kfree(iadev);
err_alloc_iadev:
	pf->cdev_infos = NULL;
	kfree(cdev_info);

	return ret;
}

/* mcevf_unplug_aux_devs - unregister and free aux devs
 * @pf: pointer to pf struct
 */
void mcevf_unplug_aux_devs(struct mcevf_pf *pf)
{
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;

	if (!cdev_info)
		return;

	/* if this aux dev has already been unplugged move on */
	mutex_lock(&pf->adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&pf->adev_mutex);
		return;
	}

	auxiliary_device_delete(cdev_info->adev);
	auxiliary_device_uninit(cdev_info->adev);
	cdev_info->adev = NULL;
	mutex_unlock(&pf->adev_mutex);

	kfree(cdev_info);
	pf->cdev_infos = NULL;
}
