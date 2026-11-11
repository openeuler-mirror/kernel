// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/smp.h>

#include "nse.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_dcb_lib.h"
#include "nse_ptp.h"

static DEFINE_IDA(nse_cdev_info_ida);

static struct cdev_info_id nse_cdev_ids[] = ASSIGN_IIDC_INFO;

/**
 * nse_get_auxiliary_drv - retrieve iidc_auxiliary_drv struct
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions for auxiliary
 * driver unload, and the mutex pf->adev_mutex locked to avoid
 * plug/unplug race conditions..
 */
struct iidc_auxiliary_drv
*nse_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;
	struct nse_pf *pf;

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
 * nse_aux_iterate - iterate across and call function for each aux driver
 * @pf: pointer to private board struct
 * @data: data to pass to function on each call
 * @fn: pointer to function to call for each peer
 */
int nse_aux_iterate(struct nse_pf *pf, void *data,
		    int (*fn)(struct iidc_core_dev_info *, void *))
{
	unsigned int i;

	if (!pf->cdev_infos)
		return 0;

	for (i = 0; i < ARRAY_SIZE(nse_cdev_ids); i++) {
		struct iidc_core_dev_info *cdev_info;

		cdev_info = pf->cdev_infos[i];
		if (cdev_info) {
			int ret = fn(cdev_info, data);

			if (ret)
				return ret;
		}
	}

	return 0;
}

/**
 * nse_send_event_to_aux - send event to a specific aux driver
 * @cdev_info: pointer to iidc_core_dev_info struct for this aux
 * @data: opaque pointer used to pass event struct
 */
static int
nse_send_event_to_aux(struct iidc_core_dev_info *cdev_info, void *data)
{
	struct iidc_event *event = (struct iidc_event *)data;
	struct iidc_auxiliary_drv *iadrv;
	struct nse_pf *pf;

	if (!cdev_info)
		return 0;
	pf = pci_get_drvdata(cdev_info->pdev);

	if (!test_bit(NSE_RDMA_IS_RUNNING, pf->state))
		return 0;

	mutex_lock(&pf->adev_mutex);

	if (!cdev_info->adev || !event) {
		mutex_unlock(&pf->adev_mutex);
		return 0;
	}

	device_lock(&cdev_info->adev->dev);
	iadrv = nse_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->event_handler)
		iadrv->event_handler(cdev_info, event);
	device_unlock(&cdev_info->adev->dev);
	mutex_unlock(&pf->adev_mutex);

	return 0;
}

/**
 * nse_send_event_to_auxs - send event to all auxiliary drivers
 * @pf: pointer to PF struct
 * @event: pointer to iidc_event to propagate
 *
 * event struct to be populated by caller
 */
void nse_send_event_to_auxs(struct nse_pf *pf, struct iidc_event *event)
{
	if (!event || !pf)
		return;

	if (bitmap_weight(event->type, IIDC_EVENT_NBITS) != 1) {
		dev_warn(nse_pf_to_dev(pf), "Event with not exactly one type bit set\n");
		return;
	}

	nse_aux_iterate(pf, event, nse_send_event_to_aux);
}

/**
 * nse_unroll_cdev_info - destroy cdev_info resources
 * @cdev_info: ptr to cdev_info struct
 * @data: ptr to opaque data
 *
 * This function releases resources for cdev_info objects.
 * Meant to be called from a nse_aux_iterate invocation
 */
int nse_unroll_cdev_info(struct iidc_core_dev_info *cdev_info,
			 void __always_unused *data)
{
	if (!cdev_info)
		return 0;

	kfree(cdev_info);

	return 0;
}

#ifdef CONFIG_PM
/**
 * nse_cdev_info_refresh_msix - load new values into iidc_core_dev_info structs
 * @pf: pointer to private board struct
 */
void nse_cdev_info_refresh_msix(struct nse_pf *pf)
{
	struct iidc_core_dev_info *cdev_info;
	unsigned int i;

	if (!pf->cdev_infos)
		return;

	for (i = 0; i < ARRAY_SIZE(nse_cdev_ids); i++) {
		if (!pf->cdev_infos[i])
			continue;

		cdev_info = pf->cdev_infos[i];

		switch (cdev_info->cdev_info_id) {
		case IIDC_RDMA_ID:
			cdev_info->msix_count = pf->num_rdma_msix;
			cdev_info->msix_entries =
				&pf->msix_entries[pf->rdma_base_vector];
			break;
		default:
			break;
		}
	}
}

#endif /* CONFIG_PM */

/**
 * nse_alloc_rdma_qsets - Allocate Leaf Nodes for RDMA Qset
 * @cdev_info: aux driver that is requesting the Leaf Nodes
 * @qset: Resource to be allocated
 *
 * This function allocates Leaf Nodes for given RDMA Qset resources
 * for the peer object.
 */
static int
nse_alloc_rdma_qsets(struct iidc_core_dev_info *cdev_info,
		     struct iidc_rdma_qset_params *qset)
{
	u16 max_rdmaqs[NSE_MAX_TRAFFIC_CLASS];
	enum nse_status status;
	struct nse_vsi *vsi;
	struct device *dev;
	struct nse_pf *pf;
	struct nse_hw *hw;
	u32 leaf_node_tnid;
	u16 rdma_qset_abs_id;
	int i;

	if (!cdev_info || !qset)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	hw = &pf->hw;
	dev = nse_pf_to_dev(pf);

	if (!nse_chk_rdma_cap(pf) || !pf->rdma_qset_space_valid) {
		dev_err(dev, "[%s, %d] RDMA not enable on this PF: chk_rdma_cap()=%d, rdma_qset_space_valid=%d\n",
					__func__, __LINE__, nse_chk_rdma_cap(pf),
						pf->rdma_qset_space_valid);
		return -EINVAL;
	}

	nse_debug(hw, NSE_DBG_RDMA, "[%s] qset (vsi_abs_id=%d, tc=%d, qs_handle=%d)\n",
								__func__,
								qset->vsi_abs_id, qset->tc,
									qset->qs_handle);

	nse_for_each_traffic_class(i)
		max_rdmaqs[i] = 0;

	max_rdmaqs[qset->tc]++;
	rdma_qset_abs_id = qset->qs_handle;

	if (rdma_qset_abs_id < pf->rdma_qset_space_start ||
		rdma_qset_abs_id >= (pf->rdma_qset_space_start + pf->rdma_qset_space_size)) {
		dev_err(dev, "[%s, %d] RDMA-Qset ID (%d) out of PF space range [%d, %d)\n",
					__func__, __LINE__, rdma_qset_abs_id,
					pf->rdma_qset_space_start, (pf->rdma_qset_space_start +
								    pf->rdma_qset_space_size));
		return -EINVAL;
	}

	vsi = nse_find_vsi_by_abs_id(pf, qset->vsi_abs_id);
	if (!vsi) {
		dev_err(dev, "RDMA QSet invalid VSI\n");
		return -EINVAL;
	}

	status = nse_cfg_vsi_rdma(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				  max_rdmaqs);
	if (status) {
		dev_err(dev, "Failed VSI RDMA qset config\n");
		return -EINVAL;
	}

	status = nse_ena_vsi_rdma_qset(vsi->port_info, vsi->idx, qset->tc,
				       rdma_qset_abs_id, &leaf_node_tnid);
	if (status) {
		dev_err(dev, "Failed VSI RDMA qset enable\n");
		return -EINVAL;
	}
	vsi->qset_handle[qset->tc] = rdma_qset_abs_id;
	qset->teid = leaf_node_tnid;

	nse_debug(hw, NSE_DBG_RDMA, "[%s] DONE: qset (vsi_abs_id=%d, tc=%d, qs_handle=%d) (teid=%d)\n",
								__func__,
								qset->vsi_abs_id, qset->tc,
									qset->qs_handle,
									leaf_node_tnid);

	return 0;
}

/**
 * nse_free_rdma_qsets - Free leaf nodes for RDMA Qset
 * @cdev_info: aux driver that requested qsets to be freed
 * @qset: Resource to be freed
 */
static int
nse_free_rdma_qsets(struct iidc_core_dev_info *cdev_info,
		    struct iidc_rdma_qset_params *qset)
{
	enum nse_status status;
	struct nse_vsi *vsi;
	struct device *dev;
	struct nse_pf *pf;
	struct nse_hw *hw = NULL;
	u16 vsi_abs_id;
	u32 leaf_node_tnid;
	u16 rdma_qset_abs_id;
	int ret = -EINVAL;

	if (!cdev_info || !qset)
		goto out;

	pf = pci_get_drvdata(cdev_info->pdev);
	hw = &pf->hw;
	dev = nse_pf_to_dev(pf);

	vsi_abs_id = qset->vsi_abs_id;
	vsi = nse_find_vsi_by_abs_id(pf, vsi_abs_id);
	if (!vsi) {
		dev_err(dev, "[%s] RDMA Invalid VSI, vsi_abs_id=%d\n", __func__, vsi_abs_id);
		goto out;
	}

	nse_debug(hw, NSE_DBG_SCHED, "[%s] vsi_abs_id=%d", __func__, vsi_abs_id);

	rdma_qset_abs_id = qset->qs_handle;

	if (rdma_qset_abs_id < pf->rdma_qset_space_start ||
		rdma_qset_abs_id >= (pf->rdma_qset_space_start + pf->rdma_qset_space_size)) {
		dev_err(dev, "[%s, %d] RDMA-Qset ID (%d) out of PF space range [%d, %d)\n",
					__func__, __LINE__, rdma_qset_abs_id,
					pf->rdma_qset_space_start, (pf->rdma_qset_space_start +
								    pf->rdma_qset_space_size));
		goto out;
	}

	leaf_node_tnid = qset->teid;

	vsi->qset_handle[qset->tc] = 0;

	status = nse_dis_vsi_rdma_qset(vsi->port_info, leaf_node_tnid, rdma_qset_abs_id);
	if (status)
		ret = -EIO;
	else
		ret = 0;

out:
	nse_debug(hw, NSE_DBG_SCHED, "[%s] out, status=%d, ret=%d", __func__, status, ret);

	return ret;
}

/**
 * nse_cdev_info_alloc_res - Allocate requested resources for aux driver
 * @cdev_info: struct for aux driver that is requesting resources
 * @qset: Resource to be allocated
 */
static int
nse_cdev_info_alloc_res(struct iidc_core_dev_info *cdev_info,
			struct iidc_rdma_qset_params *qset)
{
	struct nse_pf *pf;

	if (!cdev_info || !qset)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!nse_pf_state_is_nominal(pf))
		return -EBUSY;

	return nse_alloc_rdma_qsets(cdev_info, qset);
}

/**
 * nse_cdev_info_free_res - Free resources associated with aux driver
 * @cdev_info: struct for aux driver that is requesting freeing of resources
 * @qset: Resource to be freed
 */
static int
nse_cdev_info_free_res(struct iidc_core_dev_info *cdev_info,
		       struct iidc_rdma_qset_params *qset)
{
	if (!cdev_info || !qset)
		return -EINVAL;

	return nse_free_rdma_qsets(cdev_info, qset);
}

/**
 * nse_cdev_info_request_reset - accept request from peer to perform a reset
 * @cdev_info: struct for aux driver that is requesting a reset
 * @reset_type: type of reset the peer is requesting
 */
int
nse_cdev_info_request_reset(struct iidc_core_dev_info *cdev_info,
			    enum iidc_reset_type reset_type)
{
	enum nse_reset_req reset;
	struct nse_pf *pf;
	struct nse_hw *hw;

	if (!cdev_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s]: iidc_reset_type=%d\n", __func__, reset_type);

	switch (reset_type) {
	case IIDC_PFR:
		reset = NSE_RESET_PFR;
		break;
	case IIDC_CORER:
	case IIDC_GLOBR:
		reset = NSE_RESET_HIGH_RESET_CORER;
		break;
	default:
		dev_err(nse_pf_to_dev(pf), "incorrect reset request from peer\n");
		return -EINVAL;
	}

	return nse_schedule_reset(pf, reset);
}

/**
 * nse_cdev_info_update_vsi_filter - update main VSI filters for RDMA
 * @cdev_info: pointer to struct for aux device updating filters
 * @vsi_id: vsi HW idx to update filter on
 * @enable: bool whether to enable or disable filters
 */
static int
nse_cdev_info_update_vsi_filter(struct iidc_core_dev_info *cdev_info,
				u16 vsi_abs_id, bool enable)
{
	struct nse_vsi *vsi;
	struct nse_pf *pf;
	int ret;

	if (!cdev_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);

	vsi = nse_find_vsi_by_abs_id(pf, vsi_abs_id);
	if (!vsi)
		return -EINVAL;

	if (nse_get_main_vsi(pf) == vsi) {
		pf->switchdev.pf_roce_en = enable;
		dev_info(nse_pf_to_dev(pf),
			"main vsi (id = %d) is configurated roce fltr, en = %d\n",
			vsi_abs_id, enable);

		/*main vsi roce offload is unsupported when switchdev is running*/
		if (nse_is_switchdev_running(pf))
			return 0;
	}

	ret = nse_cfg_roce_fltr(&pf->hw, vsi->idx, enable);

	if (ret) {
		dev_err(nse_pf_to_dev(pf), "Failed to  %sable RoCE filtering\n",
			enable ? "en" : "dis");
	} else {
		if (enable)
			vsi->info.pe_flags |= NSE_AQ_VSI_PE_FLAG_FLTR_EN;
		else
			vsi->info.pe_flags &= ~NSE_AQ_VSI_PE_FLAG_FLTR_EN;
	}

	return ret;
}

/**
 * nse_cdev_info_vc_send - send a virt channel message from an aux driver
 * @cdev_info: pointer to cdev_info struct for aux driver
 * @vf_id: the VF ID of recipient of message
 * @msg: pointer to message contents
 * @len: len of message
 *
 * Note that the VF ID is absolute for RDMA operations.
 */
static int
nse_cdev_info_vc_send(struct iidc_core_dev_info *cdev_info, u32 vf_id,
		      u8 *msg, u16 len)
{
	enum nse_status status;
	struct nse_pf *pf;
	struct nse_vf *vf;
	u32 rel_vf_id;

	if (!cdev_info)
		return -EINVAL;
	if (!msg || !len)
		return -ENOMEM;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (len > NSE_AQ_MAX_BUF_LEN)
		return -EINVAL;

	if (nse_is_reset_in_progress(pf->state))
		return -EBUSY;

	switch (cdev_info->cdev_info_id) {
	case IIDC_RDMA_ID:
		/* The ID is absolute so it must be converted first */
		rel_vf_id = nse_rel_vf_id(&pf->hw, vf_id);

		vf = nse_get_vf_by_id(pf, rel_vf_id);
		if (!vf)
			return -ENODEV;

		/* VIRTCHNL_OP_RDMA is being used for RoCEv2 msg also */
		if (vf->use_pv_msgbox)
			status = nse_msgbox_p2v_send_msg_to_vf(&pf->hw, vf->vf_vsi_abs_id,
						       VIRTCHNL_OP_RDMA, 0, msg, len);
		else
			status = nse_aq_send_msg_to_vf(&pf->hw, vf->vf_vsi_abs_id,
						       VIRTCHNL_OP_RDMA, 0, msg, len, NULL);

		nse_put_vf(vf);

		break;
	default:
		dev_err(nse_pf_to_dev(pf),
			"Can't send message to VF, Aux not supported, %u\n",
			(u32)cdev_info->cdev_info_id);
		return -ENODEV;
	}

	if (status)
		dev_err(nse_pf_to_dev(pf), "Unable to send msg to VF, error %s\n",
			nse_stat_str(status));
	return nse_status_to_errno(status);
}

/**
 * nse_reserve_cdev_info_qvector - Reserve vector resources for aux drivers
 * @pf: board private structure to initialize
 */
static int nse_reserve_cdev_info_qvector(struct nse_pf *pf)
{
	if (nse_chk_rdma_cap(pf)) {
		int index;

		index = nse_get_res(pf, pf->irq_tracker_self_region,
				    pf->num_rdma_msix, NSE_RES_IRQ_ID_RDMA);
		if (index < 0)
			return index;
		pf->num_avail_sw_msix -= pf->num_rdma_msix;
		pf->rdma_base_vector = (u16)index;
	}
	return 0;
}

/**
 * nse_send_vf_reset_to_aux - send a VF reset notification to the aux driver
 * @cdev_info: pointer to the cdev_info object
 * @vf_id: VF ID to query
 *
 * Tell the RDMA auxiliary driver that a VF is resetting
 */
void nse_send_vf_reset_to_aux(struct nse_pf *pf, struct iidc_core_dev_info *cdev_info, u16 vf_id)
{
	struct nse_hw *hw = &pf->hw;
	struct iidc_event *event;

	nse_debug(hw, NSE_DBG_SYS, "[%s] vf_id=%d\n", __func__, vf_id);

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return;
	set_bit(IIDC_EVENT_VF_RESET, event->type);
	event->info.vf_id = (u32)vf_id;
	nse_send_event_to_aux(cdev_info, event);
	kfree(event);
}

/**
 * nse_cdev_info_get_vf_port_info - get a VF's information
 * @cdev_info: pointer to the cdev_info object
 * @abs_vf_id: Absolute VF ID to query
 * @vf_port_info: structure to populate for the caller
 *
 * Allow the RDMA auxiliary driver to query a VF's information
 */
static int
nse_cdev_info_get_vf_port_info(struct iidc_core_dev_info *cdev_info,
			       u16 abs_vf_id,
			       struct iidc_vf_port_info *vf_port_info)
{
	struct nse_pf *pf;

	if (!cdev_info || !vf_port_info)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);

	return nse_get_vf_port_info(pf, nse_rel_vf_id(&pf->hw, abs_vf_id),
				    vf_port_info);
}

/**
 * nse_find_cdev_info_by_id - find cdev_info instance by its id
 * @pf: pointer to private board struct
 * @cdev_info_id: peer driver ID
 */
struct iidc_core_dev_info
*nse_find_cdev_info_by_id(struct nse_pf *pf, int cdev_info_id)
{
	struct iidc_core_dev_info *cdev_info = NULL;
	unsigned int i;

	if (!pf->cdev_infos)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(nse_cdev_ids); i++) {
		cdev_info = pf->cdev_infos[i];
		if (cdev_info &&
		    cdev_info->cdev_info_id == cdev_info_id)
			break;
		cdev_info = NULL;
	}
	return cdev_info;
}

/**
 * nse_cdev_info_update_vsi - update the pf_vsi info in cdev_info struct
 * @cdev_info: pointer to cdev_info struct
 * @vsi: VSI to be updated
 */
void nse_cdev_info_update_vsi(struct iidc_core_dev_info *cdev_info,
			      struct nse_vsi *vsi)
{
	if (!cdev_info)
		return;

	cdev_info->vsi_abs_id = vsi->vsi_abs_num;
}

/* Initialize the nse_ops struct, which is used in 'nse_init_aux_devices' */
static const struct iidc_core_ops ops = {
	.alloc_res			= nse_cdev_info_alloc_res,
	.free_res			= nse_cdev_info_free_res,
	.request_reset			= nse_cdev_info_request_reset,
	.update_vport_filter		= nse_cdev_info_update_vsi_filter,
	.get_vf_info			= nse_cdev_info_get_vf_port_info,
	.vc_send			= nse_cdev_info_vc_send,

};

/**
 * nse_cdev_info_adev_release - function to be mapped to aux dev's release op
 * @dev: pointer to device to free
 */
static void nse_cdev_info_adev_release(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
}

/* nse_plug_aux_dev - allocate and register aux dev for cdev_info
 * @cdev_info: pointer to cdev_info struct
 * @name: name of peer_aux_dev
 *
 * The cdev_info must be setup before calling this function
 */
int nse_plug_aux_dev(struct iidc_core_dev_info *cdev_info, const char *name)
{
	struct iidc_auxiliary_dev *iadev;
	struct auxiliary_device *adev;
	struct nse_pf *pf;
	int ret = 0;

	if (!cdev_info || !name)
		return -EINVAL;

	pf = pci_get_drvdata(cdev_info->pdev);
	if (!pf)
		return -EINVAL;

	/* if this PF does not support a technology that requires auxiliary
	 * devices, then exit gracefully
	 */
	if (!nse_is_aux_ena(pf))
		return ret;
	mutex_lock(&pf->adev_mutex);
	if (cdev_info->adev)
		goto aux_plug_out;

	if (cdev_info->cdev_info_id == IIDC_RDMA_ID && !nse_chk_rdma_cap(pf))
		goto aux_plug_out;

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		ret = -ENOMEM;
		goto aux_plug_out;
	}

	adev = &iadev->adev;
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;

	cdev_info->unplug_preset_reset = 0;

	adev->id = pf->aux_idx;
	adev->dev.release = nse_cdev_info_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;
	adev->name = name;

	ret = auxiliary_device_init(adev);
	if (ret) {
		cdev_info->adev = NULL;
		kfree(iadev);
		goto aux_plug_out;
	}

	ret = auxiliary_device_add(adev);
	if (ret) {
		cdev_info->adev = NULL;
		auxiliary_device_uninit(adev);
	}

aux_plug_out:
	mutex_unlock(&pf->adev_mutex);
	set_bit(NSE_RDMA_IS_RUNNING, pf->state);
	return ret;
}

/* nse_unplug_aux_dev - unregister and free aux dev
 * @cdev_info: pointer cdev_info struct
 */
void nse_unplug_aux_dev(struct iidc_core_dev_info *cdev_info, unsigned int unplug_preset_reset)
{
	struct nse_pf *pf;
	struct nse_hw *hw = NULL;

	if (!cdev_info)
		return;
	pf = pci_get_drvdata(cdev_info->pdev);
	hw = &pf->hw;

	clear_bit(NSE_RDMA_IS_RUNNING, pf->state);

	/* if this aux dev has already been unplugged move on */
	mutex_lock(&pf->adev_mutex);
	if (!cdev_info->adev) {
		mutex_unlock(&pf->adev_mutex);
		return;
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] enter: _delete, _uninit(adev), unplug_preset_reset=%d\n",
								__func__, unplug_preset_reset);

	cdev_info->unplug_preset_reset = unplug_preset_reset;

	auxiliary_device_delete(cdev_info->adev);
	auxiliary_device_uninit(cdev_info->adev);
	cdev_info->adev = NULL;
	mutex_unlock(&pf->adev_mutex);
}

/* nse_plug_aux_devs - allocate and register aux dev for cdev_info
 * @pf: pointer to pf struct
 *
 * The PFs cdev_infos array must be setup before calling this function
 */
int nse_plug_aux_devs(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	int ret = 0;
	u8 i;

	if (!pf->cdev_infos)
		return 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] enter, cpu_id=%d\n",
								__func__,
									raw_smp_processor_id());

	for (i = 0; i < ARRAY_SIZE(nse_cdev_ids); i++) {
		const char *name;

		if (!pf->cdev_infos[i])
			continue;

		if (pf->cdev_infos[i]->cdev_info_id == IIDC_RDMA_ID)
			name = IIDC_RDMA_ROCE_NAME;
		else
			name = nse_cdev_ids[i].name;

		ret = nse_plug_aux_dev(pf->cdev_infos[i], name);
		if (ret)
			goto out;
	}

	ret = 0;

out:
	nse_debug(hw, NSE_DBG_SYS, "[%s] exit: ret=%d, cpu_id=%d\n",
								__func__, ret,
									raw_smp_processor_id());

	return ret;
}

/* nse_unplug_aux_devs - unregister and free aux devs
 * @pf: pointer to pf struct
 */
void nse_unplug_aux_devs(struct nse_pf *pf, unsigned int unplug_preset_reset,
			 unsigned int force_preset_reset)
{
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;
	u8 i;

	if (!pf->cdev_infos)
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s] enter: unplug_preset_reset=%d, force_preset_reset=%d, cpu_id=%d\n",
							__func__, unplug_preset_reset,
								force_preset_reset,
								raw_smp_processor_id());

	if (!unplug_preset_reset && force_preset_reset) {
		nse_debug(hw, NSE_DBG_SYS,
"[%s] try early request FW to clean PF RDMA resource, by aq_request_reset_rdma()\n", __func__);

		status = nse_aq_request_reset_rdma(hw, false, NSE_VSI_INVAL_ID);

		if (!status) {
			nse_debug(hw, NSE_DBG_SYS,
"[%s] DONE: early request FW to clean PF RDMA resource, set unplug_preset_reset=1\n", __func__);

			unplug_preset_reset = 1;

		} else {
			/* let PF-RDMA driver unplug decide what to do */

			nse_debug(hw, NSE_DBG_SYS, "[%s] FAIL: early request FW to clean PF RDMA resource, status=%d, keep unplug_preset_reset=0\n",
										__func__,
											status);
		}
	}

	for (i = 0; i < ARRAY_SIZE(nse_cdev_ids); i++)
		nse_unplug_aux_dev(pf->cdev_infos[i], unplug_preset_reset);

	nse_debug(hw, NSE_DBG_SYS, "[%s] exit, cpu_id=%d\n",
								__func__,
									raw_smp_processor_id());
}

/**
 * nse_cdev_init_rdma_qos_info - initialize qos_info for RDMA peer
 * @pf: pointer to ice_pf
 * @qos_info: pointer to qos_info struct
 */
static void nse_cdev_init_rdma_qos_info(struct nse_pf *pf,
					struct iidc_qos_params *qos_info)
{
	int j;

	/* setup qos_info fields with defaults */
	//qos_info->num_apps = 0;//rdma driver doesn't use the var
	qos_info->num_tc = 1;

	for (j = 0; j < IIDC_MAX_USER_PRIORITY; j++)
		qos_info->up2tc[j] = 0;

	qos_info->tc_info[0].rel_bw = 100;
	for (j = 1; j < IEEE_8021QAZ_MAX_TCS; j++)
		qos_info->tc_info[j].rel_bw = 0;
	/* for DCB, override the qos_info defaults. */
	nse_setup_dcb_qos_info(pf, qos_info);
}

/**
 * nse_init_aux_devices - initializes cdev_info objects and aux devices
 * @pf: ptr to nse_pf
 */
int nse_init_aux_devices(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vsi = pf->vsi[0];
	struct pci_dev *pdev = pf->pdev;
	struct device *dev = &pdev->dev;
	int err;
	unsigned int i;

	nse_debug(hw, NSE_DBG_SYS, "[%s] enter, cpu_id=%d\n",
								__func__,
									raw_smp_processor_id());

	/* Reserve vector resources */
	err = nse_reserve_cdev_info_qvector(pf);
	if (err < 0) {
		dev_err(dev, "failed to reserve vectors for aux drivers\n");
		goto out;
	}

	/* This PFs auxiliary id value */
	pf->aux_idx = ida_alloc(&nse_cdev_info_ida, GFP_KERNEL);
	if (pf->aux_idx < 0) {
		dev_err(dev, "failed to allocate device ID for aux drvs\n");
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(nse_cdev_ids); i++) {
		struct msix_entry *entry = NULL;
		struct iidc_core_dev_info *cdev_info;

		/* structure layout needed for container_of's looks like:
		 * iidc_auxiliary_dev (container_of super-struct for adev)
		 * |--> auxiliary_device
		 * |--> *iidc_core_dev_info (pointer from cdev_info struct)
		 *
		 * The iidc_auxiliary_device has a lifespan as long as it
		 * is on the bus.  Once removed it will be freed and a new
		 * one allocated if needed to re-add.
		 *
		 * The iidc_core_dev_info is tied to the life of the PF, and
		 * will exist as long as the PF driver is loaded.  It will be
		 * freed in the remove flow for the PF driver.
		 */
		cdev_info = kzalloc(sizeof(*cdev_info), GFP_KERNEL);
		if (!cdev_info) {
			ida_simple_remove(&nse_cdev_info_ida, pf->aux_idx);
			pf->aux_idx = -1;
			err = -ENOMEM;
			goto out;
		}

		pf->cdev_infos[i] = cdev_info;

		cdev_info->hw_addr = (u8 __iomem *)hw->hw_addr;
		if (nse_is_hw_dyn_fea_set(hw, NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_PE))
			cdev_info->hmc_va = (u8 __iomem *)hw->hw_addr_bar2;
		else
			cdev_info->hmc_va = NULL;

		cdev_info->ver.major = IIDC_MAJOR_VER;
		cdev_info->ver.minor = IIDC_MINOR_VER;

		if (hw->mac_type == NSE_MAC_TYPE_AMBER)
			cdev_info->rdma_caps.gen = IIDC_RDMA_GEN_AMBER;
		else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
			cdev_info->rdma_caps.gen = IIDC_RDMA_GEN_MOONSTONE;
		else
			cdev_info->rdma_caps.gen = IIDC_RDMA_GEN_UNKNOWN;

		if (hw->device_id == NSE_DEV_ID_AMBER_FPGA)
			cdev_info->rdma_caps.protocols = IIDC_RDMA_NIC_PORT_NUM_2;
		else if (hw->device_id == NSE_DEV_ID_AMBER_FDBTACXX ||
			 hw->device_id == NSE_DEV_ID_AMBER_FDBTACRX ||
			 hw->device_id == NSE_DEV_ID_AMBER_DDATACRX ||
			 hw->device_id == NSE_DEV_ID_AMBER_DDATAIRX)
			cdev_info->rdma_caps.protocols = IIDC_RDMA_NIC_PORT_NUM_2;
		else if (hw->device_id == NSE_DEV_ID_AMBER_FQATACRX ||
			 hw->device_id == NSE_DEV_ID_AMBER_DQATACXX)
			cdev_info->rdma_caps.protocols = IIDC_RDMA_NIC_PORT_NUM_4;
		else if (hw->device_id == NSE_DEV_ID_MOONSTONE)
			cdev_info->rdma_caps.protocols = IIDC_RDMA_NIC_PORT_NUM_1;
		else
			cdev_info->rdma_caps.protocols = IIDC_RDMA_NIC_PORT_NUM_UNKNOWN;

		cdev_info->cdev_info_id = nse_cdev_ids[i].id;
		cdev_info->pdev = pdev;
		/* Initialize ice_ops */
		cdev_info->ops = &ops;

		/* make sure peer specific resources such as msix_count and
		 * msix_entries are initialized
		 */
		switch (nse_cdev_ids[i].id) {
		case IIDC_RDMA_ID:
			if (!nse_chk_rdma_cap(pf)) {
				pf->cdev_infos[i] = NULL;
				kfree(cdev_info);
				continue;
			}
			cdev_info->vsi_abs_id = vsi->vsi_abs_num;
			cdev_info->netdev = vsi->netdev;
			//cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_ROCEV2;
			cdev_info->cdev_info_id = IIDC_RDMA_ID;
			cdev_info->pf_id = pf->hw.pcore_pf_id;
			nse_cdev_init_rdma_qos_info(pf, &cdev_info->qos_info);
			/* make sure peer specific resources such as msix_count
			 * and msix_entries are initialized
			 */
			cdev_info->msix_count = pf->num_rdma_msix;
			entry = &pf->msix_entries[pf->rdma_base_vector];
			break;
		default:
			break;
		}
		cdev_info->msix_entries = entry;
	}
	set_bit(NSE_FLAG_PLUG_AUX_DEV, pf->flags);

out:
	nse_debug(hw, NSE_DBG_SYS, "[%s] exit, ret=%d, cpu_id=%d\n",
								__func__, err,
									raw_smp_processor_id());
	return err;
}

/**
 * nse_is_rdma_aux_loaded - check if RDMA auxiliary driver is loaded
 * @pf: ptr to nse_pf
 */
bool nse_is_rdma_aux_loaded(struct nse_pf *pf)
{
	struct iidc_core_dev_info *rcdi;
	struct iidc_auxiliary_drv *iadrv;
	bool loaded;

	rcdi = nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (!rcdi || !rcdi->adev)
		return false;

	if (!test_bit(NSE_RDMA_IS_RUNNING, pf->state))
		return false;

	mutex_lock(&pf->adev_mutex);
	device_lock(&rcdi->adev->dev);
	iadrv = nse_get_auxiliary_drv(rcdi);
	loaded = iadrv ? true : false;
	device_unlock(&rcdi->adev->dev);
	mutex_unlock(&pf->adev_mutex);

	dev_dbg(nse_pf_to_dev(pf), "RDMA Auxiliary Driver status: %s\n",
		loaded ? "loaded" : "not loaded");

	return loaded;
}

