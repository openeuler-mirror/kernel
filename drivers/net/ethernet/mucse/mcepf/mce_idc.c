// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_lib.h"

static void mce_adev_release_cb(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
}

static void idc_dev_event(struct iidc_core_dev_info *cdev_info,
			  struct iidc_event *event)
{
	struct net_device *netdev = cdev_info->netdev;
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;

	/* detect mrdma insmod or rmmod */
	if (test_bit(IIDC_EVENT_INSMOD, event->type))
		pf->m_status = MRDMA_INSMOD;
	if (test_bit(IIDC_EVENT_RMMOD, event->type))
		pf->m_status = MRDMA_REMOVE;

	set_bit(MCE_FLAG_MRDMA_CHANGED,	pf->flags);
}

int mce_plug_aux_dev(struct mce_pf *pf)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	struct iidc_auxiliary_dev *iadev = NULL;
	struct auxiliary_device *adev = NULL;
	struct iidc_qos_params *qos_info;
	const char *name = "mrdma_roce";
	struct mce_dcb *dcb = pf->dcb;
	struct mce_ets_cfg *etscfg = &dcb->cur_etscfg;
	int ret = 0;
	int i;

	if (pf->cdev_infos)
		return 0;

	if (!pf->vsi[0])
		return -EFAULT;

	if (!pf->vsi[0]->netdev)
		return -EFAULT;

	cdev_info = kzalloc(sizeof(*cdev_info), GFP_KERNEL);
	if (!cdev_info)
		return -ENOMEM;

	qos_info = &cdev_info->qos_info;

	memset(cdev_info, 0, sizeof(*cdev_info));

	cdev_info->ver.major = IIDC_MAJOR_VER;
	cdev_info->ver.minor = IIDC_MINOR_VER;
	cdev_info->pdev = pf->pdev;
	cdev_info->netdev = pf->vsi[0]->netdev;
	cdev_info->eth_bar_base  = pf->hw.eth_bar_base;
	cdev_info->rdma_bar_base = pf->hw.rdma_bar_base;
	cdev_info->rdma_bar_phy = pf->hw.rdma_bar_phy;
	if (pf->hw.bar_2th_sz >= (4 * 1024 * 1024))
		cdev_info->acmr_4m_base = pf->hw.bar_2th;
	else
		cdev_info->acmr_4m_base = NULL;
	cdev_info->ftype = IIDC_FUNCTION_TYPE_PF;
	cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_ROCEV2;
	cdev_info->pname = pf->vsi[0]->netdev->name;
	cdev_info->num_q_vectors = pf->vsi[0]->num_q_vectors;
	cdev_info->msix_count = 1;
	cdev_info->msix_entries = &pf->msix_entries[pf->rdma_irq_base];
	cdev_info->func_num = 0;
	cdev_info->valid_prio = 0;
	/* update qos info */
	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		qos_info->up2tc[i] = etscfg->prio_table[i];
	/* mode is dscp or pcp */
	if (test_bit(MCE_DSCP_EN, dcb->flags))
		qos_info->map_mode = IIDC_DSCP_PFC_MODE;
	else
		qos_info->map_mode = IIDC_VLAN_PFC_MODE;

	if (test_bit(MCE_PFC_EN, dcb->flags))
		qos_info->pfc_en = IIDC_PFC_ON;
	else
		qos_info->pfc_en = IIDC_PFC_OFF;

	memcpy(qos_info->dscp_map, dcb->dscp_map, MCE_MAX_DSCP);

	qos_info->valid_prio = cdev_info->valid_prio;

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		ret = -ENOMEM;
		goto err_alloc_iadev;
	}

	adev = &iadev->adev;

	mutex_lock(&pf->adev_mutex);
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;
	iadev->event_handler = idc_dev_event;
	mutex_unlock(&pf->adev_mutex);
	adev->id = ((u32)pci_domain_nr(pf->pdev->bus) << 16) |
		    (pf->pdev->bus->number << 8) |
		    (pf->pdev->devfn & 0xff);
	adev->dev.release = mce_adev_release_cb;
	adev->dev.parent = &pf->pdev->dev;
	adev->name = name;

	ret = auxiliary_device_init(adev);
	if (ret)
		goto err_init_aux_dev;

	ret = auxiliary_device_add(adev);
	if (ret)
		goto err_add_aux_dev;

	pf->cdev_infos = cdev_info;

	return 0;
err_add_aux_dev:
	auxiliary_device_uninit(adev);
	kfree(cdev_info);
	return ret;
err_init_aux_dev:
	kfree(iadev);
err_alloc_iadev:
	kfree(cdev_info);

	return ret;
}

/* mce_unplug_aux_dev - unregister and free aux devs
 * @pf: pointer to pf struct
 */
void mce_unplug_aux_dev(struct mce_pf *pf)
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

bool mce_aux_dev_is_bound(struct mce_pf *pf)
{
	struct iidc_core_dev_info *cdev_info;
	bool bound = false;

	mutex_lock(&pf->adev_mutex);
	cdev_info = pf->cdev_infos;
	if (cdev_info && cdev_info->adev) {
		device_lock(&cdev_info->adev->dev);
		bound = !!cdev_info->adev->dev.driver;
		device_unlock(&cdev_info->adev->dev);
	}
	mutex_unlock(&pf->adev_mutex);

	return bound;
}

bool mce_aux_dev_is_registered(struct mce_pf *pf)
{
	bool registered;

	mutex_lock(&pf->adev_mutex);
	registered = pf->cdev_infos && pf->cdev_infos->adev;
	mutex_unlock(&pf->adev_mutex);

	return registered;
}

/**
 * mce_get_auxiliary_drv - retrieve iidc_auxiliary_drv struct
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions for auxiliary
 * driver unload, and the mutex pf->adev_mutex locked to avoid
 * plug/unplug race conditions..
 */
static struct iidc_auxiliary_drv *
mce_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;
	struct mce_pf *pf;

	if (!cdev_info)
		return NULL;
	pf = pci_get_drvdata(cdev_info->pdev);

	lockdep_assert_held(&pf->adev_mutex);

	adev = cdev_info->adev;
	if (!adev || !adev->dev.driver)
		return NULL;

	return container_of(adev->dev.driver, struct iidc_auxiliary_drv,
			    adrv.driver);
}

/**
 * mce_send_event_to_aux - send event to a specific aux driver
 * @cdev_info: pointer to iidc_core_dev_info struct for this aux
 * @data: opaque pointer used to pass event struct
 */
static int
mce_send_event_to_aux(struct iidc_core_dev_info *cdev_info, void *data)
{
	struct iidc_auxiliary_drv *iadrv;
	struct iidc_event *event = data;
	struct mce_pf *pf;
	int me_lock = 0;

	if (WARN_ON_ONCE(!in_task()))
		return -EINVAL;

	if (!cdev_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!pf)
		return -EINVAL;

	mutex_lock(&pf->adev_mutex);

	if (!cdev_info->adev || !event) {
		mutex_unlock(&pf->adev_mutex);
		return 0;
	}

	if (device_trylock(&cdev_info->adev->dev) == 0)
		me_lock = 0;
	else
		me_lock = 1;

	iadrv = mce_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->event_handler)
		iadrv->event_handler(cdev_info, event);

	if (me_lock)
		device_unlock(&cdev_info->adev->dev);
	mutex_unlock(&pf->adev_mutex);

	return 0;
}

/*  */
/*  */
/*  */
/*  */

/**
 * mce_send_event_to_auxs - send event to all auxiliary drivers
 * @pf: pointer to PF struct
 * @event: pointer to iidc_event to propagate
 *
 * event struct to be populated by caller
 */
void mce_send_event_to_auxs(struct mce_pf *pf, struct iidc_event *event)
{
	struct iidc_core_dev_info *cdev_info;
	struct iidc_qos_params *qos_info;
	struct mce_ets_cfg *etscfg;
	struct mce_dcb *dcb;

	if (!pf || !event)
		return;

	cdev_info = pf->cdev_infos;
	if (!cdev_info)
		return;

	qos_info = &cdev_info->qos_info;
	dcb = pf->dcb;
	etscfg = &dcb->cur_etscfg;

	if (test_bit(IIDC_EVENT_PRIO_MODE_CHNG, event->type)) {
		if (test_bit(MCE_DSCP_EN, dcb->flags))
			qos_info->map_mode = IIDC_DSCP_PFC_MODE;
		else
			qos_info->map_mode = IIDC_VLAN_PFC_MODE;
	}
	qos_info->valid_prio = cdev_info->valid_prio;
	/* if dcb change update qos */
	if (test_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type)) {
		int i;

		for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
			qos_info->up2tc[i] = etscfg->prio_table[i];
		/* mode is dscp or pcp */
		if (test_bit(MCE_PFC_EN, dcb->flags))
			qos_info->pfc_en = IIDC_PFC_ON;
		else
			qos_info->pfc_en = IIDC_PFC_OFF;

		qos_info->num_tc = etscfg->curtcs;
		memcpy(qos_info->dscp_map, dcb->dscp_map, MCE_MAX_DSCP);
	}
	/* copy to info */
	event->info.port_qos = cdev_info->qos_info;

	if (bitmap_weight(event->type, IIDC_EVENT_NBITS) != 1) {
		dev_warn(mce_pf_to_dev(pf),
			 "Event with not exactly one type bit set\n");
		return;
	}

	mce_send_event_to_aux(cdev_info, event);
}
