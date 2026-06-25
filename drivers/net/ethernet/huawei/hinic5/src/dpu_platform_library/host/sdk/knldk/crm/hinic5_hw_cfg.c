/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw_cfg.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/semaphore.h>

#include "ossl_knl.h"
#include "hinic5_typedef_inner.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hwdev.h"
#include "hinic5_hwif_inner.h"
#include "comm_defs.h"
#include "cfg_mgmt_mpu_cmd.h"
#include "cfg_mgmt_mpu_cmd_defs.h"
#include "hinic5_bus.h"
#include "mag_mpu_cmd.h"
#include "hinic5_hw_cfg.h"

#define SVC_CAP_EN_OFFSET_BIT 16

static void parse_pub_res_cap_dfx(struct hinic5_hwdev *hwdev,
				  const struct service_cap *cap)
{
	sdk_info(hwdev->dev_hdl, "Get public resource capbility: svc_cap_en: 0x%x\n",
		 cap->svc_type);
	sdk_info(hwdev->dev_hdl, "Host_id: 0x%x, ep_id: 0x%x, er_id: 0x%x, port_id: 0x%x\n",
		 cap->host_id, cap->ep_id, cap->er_id, cap->port_id);
	sdk_info(hwdev->dev_hdl, "cos_bitmap: 0x%x, flexq: 0x%x, virtio_vq_size: 0x%x\n",
		 cap->cos_valid_bitmap, cap->flexq_en, cap->virtio_vq_size);
	sdk_info(hwdev->dev_hdl, "Host_total_function: 0x%x, host_oq_id_mask_val: 0x%x, max_vf: 0x%x\n",
		 cap->host_total_function, cap->host_oq_id_mask_val,
		 cap->max_vf);
	sdk_info(hwdev->dev_hdl, "Host_pf_num: 0x%x, pf_id_start: 0x%x, host_vf_num: 0x%x, vf_id_start: 0x%x\n",
		 cap->pf_num, cap->pf_id_start, cap->vf_num, cap->vf_id_start);
	sdk_info(hwdev->dev_hdl, "host_valid_bitmap: 0x%x, master_host_id: 0x%x, srv_multi_host_mode: 0x%x\n",
		 cap->host_valid_bitmap, cap->master_host_id, cap->srv_multi_host_mode);
	sdk_info(hwdev->dev_hdl,
		 "fake_vf_start_id: 0x%x, fake_vf_num: 0x%x, fake_vf_max_pctx: 0x%x\n",
		 cap->fake_vf_start_id, cap->fake_vf_num, cap->fake_vf_max_pctx);
	sdk_info(hwdev->dev_hdl, "fake_vf_bfilter_start_addr: 0x%x, fake_vf_bfilter_len: 0x%x\n",
		 cap->fake_vf_bfilter_start_addr, cap->fake_vf_bfilter_len);
}

static void parse_hinic5_cqm_res_cap(const struct hinic5_hwdev *hwdev, struct service_cap *cap,
				     struct cfg_cmd_dev_cap *dev_cap)
{
	struct dev_sf_svc_attr *attr = &cap->sf_svc_attr;

	cap->fake_vf_start_id = dev_cap->fake_vf_start_id;
	cap->fake_vf_num = dev_cap->fake_vf_num;
	cap->fake_vf_num_cfg = dev_cap->fake_vf_num;

	cap->fake_vf_max_pctx = dev_cap->fake_vf_max_pctx;
	/* other fake_vf_max_XXX are parsed from ext_dev_cap(extent devcie capability) */

	cap->fake_vf_bfilter_start_addr = dev_cap->fake_vf_bfilter_start_addr;
	cap->fake_vf_bfilter_len = dev_cap->fake_vf_bfilter_len;

	if (COMM_SUPPORT_VIRTIO_VQ_SIZE(hwdev))
		cap->virtio_vq_size = (u16)(VIRTIO_BASE_VQ_SIZE << dev_cap->virtio_vq_size);
	else
		cap->virtio_vq_size = VIRTIO_DEFAULT_VQ_SIZE;
	cap->virtio_vq_num = dev_cap->virtio_vq_num;
	cap->vio_func_num = dev_cap->vio_func_num;
	cap->nvme_qp_num = dev_cap->nvme_qp_num;

	if ((dev_cap->sf_svc_attr & SF_SVC_FT_BIT) != 0)
		attr->ft_en = true;
	else
		attr->ft_en = false;

	if ((dev_cap->sf_svc_attr & SF_SVC_RDMA_BIT) != 0)
		attr->rdma_en = true;
	else
		attr->rdma_en = false;

	/* PPF will overwrite it when parse dynamic resource */
	if (dev_cap->func_sf_en != 0)
		cap->sf_en = true;
	else
		cap->sf_en = false;

	cap->lb_mode = dev_cap->lb_mode;
	cap->smf_pg = dev_cap->smf_pg;

#ifndef __UEFI__
	cap->timer_en = dev_cap->timer_en;
#else
	cap->timer_en = 0;
#endif
	cap->host_oq_id_mask_val = dev_cap->host_oq_id_mask_val;
	cap->max_connect_num = dev_cap->max_conn_num;
	cap->max_stick2cache_num = dev_cap->max_stick2cache_num;
	cap->bfilter_start_addr = dev_cap->max_bfilter_start_addr;
	cap->bfilter_len = dev_cap->bfilter_len;
	cap->hash_bucket_num = dev_cap->hash_bucket_num;
}

static void parse_pub_res_cap(struct hinic5_hwdev *hwdev,
			      struct service_cap *cap,
			      struct cfg_cmd_dev_cap *dev_cap,
			      enum func_type type)
{
	cap->host_id = dev_cap->host_id;
	cap->ep_id = dev_cap->ep_id;
	cap->er_id = dev_cap->er_id;
	cap->port_id = dev_cap->port_id;

	cap->svc_type = ((dev_cap->svc_cap_en) | (dev_cap->svc_cap_en_h << SVC_CAP_EN_OFFSET_BIT));
	cap->chip_svc_type = cap->svc_type;

	cap->cos_valid_bitmap = (dev_cap->dev_cos_valid_bitmap == 0) ?
		dev_cap->valid_cos_bitmap : dev_cap->dev_cos_valid_bitmap;
	cap->cos_mask_mode = (dev_cap->cos_mask_mode == 0) ?
		COS_DEFAULT_MASK_MODE : dev_cap->cos_mask_mode;
	cap->dcb_state.default_cos = dev_cap->dev_default_cos;
	cap->port_cos_valid_bitmap = dev_cap->port_cos_valid_bitmap;
	cap->func_gpa_spu_en = dev_cap->func_gpa_spu_en;
	cap->flexq_en = dev_cap->flexq_en;

	cap->host_total_function = dev_cap->host_total_func;
	cap->host_valid_bitmap = dev_cap->host_valid_bitmap;
	cap->master_host_id = dev_cap->master_host_id;
	cap->srv_multi_host_mode = dev_cap->srv_multi_host_mode;

	if (type != TYPE_VF) {
		cap->max_vf = dev_cap->max_vf;
		cap->pf_num = dev_cap->host_pf_num;
		cap->pf_id_start = dev_cap->pf_id_start;
		cap->vf_num = dev_cap->host_vf_num;
		cap->vf_id_start = dev_cap->vf_id_start;
	} else {
		cap->max_vf = 0;
	}

	parse_hinic5_cqm_res_cap(hwdev, cap, dev_cap);
	parse_pub_res_cap_dfx(hwdev, cap);
}

static void parse_dynamic_share_res_cap(struct service_cap *cap,
					const struct cfg_cmd_dev_cap *dev_cap)
{
	if (dev_cap->host_sf_en != 0)
		cap->sf_en = true;
	else
		cap->sf_en = false;
}

static void parse_l2nic_res_cap(struct hinic5_hwdev *hwdev,
				struct service_cap *cap,
				struct cfg_cmd_dev_cap *dev_cap,
				enum func_type type)
{
	struct nic_service_cap *nic_cap = &cap->nic_cap;

	nic_cap->max_sqs = dev_cap->nic_max_sq_id + 1;
	nic_cap->max_rqs = dev_cap->nic_max_rq_id + 1;
	nic_cap->default_num_queues = dev_cap->nic_default_num_queues;

	sdk_info(hwdev->dev_hdl, "L2nic resource capbility, max_sqs: 0x%x, max_rqs: 0x%x\n",
		 nic_cap->max_sqs, nic_cap->max_rqs);

	/* Check parameters from firmware */
	if (nic_cap->max_sqs > HINIC5_CFG_MAX_QP ||
	    nic_cap->max_rqs > HINIC5_CFG_MAX_QP) {
		sdk_info(hwdev->dev_hdl, "Number of qp exceed limit[1-%d]: sq: %u, rq: %u\n",
			 HINIC5_CFG_MAX_QP, nic_cap->max_sqs, nic_cap->max_rqs);
		nic_cap->max_sqs = HINIC5_CFG_MAX_QP;
		nic_cap->max_rqs = HINIC5_CFG_MAX_QP;
	}
}

static void parse_fc_res_cap(struct hinic5_hwdev *hwdev,
			     struct service_cap *cap,
			     struct cfg_cmd_dev_cap *dev_cap,
			     enum func_type type)
{
	struct dev_fc_svc_cap *fc_cap = &cap->fc_cap.dev_fc_cap;

	fc_cap->max_parent_qpc_num = dev_cap->fc_max_pctx;
	fc_cap->scq_num = dev_cap->fc_max_scq;
	fc_cap->srq_num = dev_cap->fc_max_srq;
	fc_cap->max_child_qpc_num = dev_cap->fc_max_cctx;
	fc_cap->child_qpc_id_start = dev_cap->fc_cctx_id_start;
	fc_cap->vp_id_start = dev_cap->fc_vp_id_start;
	fc_cap->vp_id_end = dev_cap->fc_vp_id_end;

	sdk_info(hwdev->dev_hdl, "Get fc resource capbility\n");
	sdk_info(hwdev->dev_hdl,
		 "Max_parent_qpc_num: 0x%x, scq_num: 0x%x, srq_num: 0x%x, max_child_qpc_num: 0x%x, child_qpc_id_start: 0x%x\n",
		 fc_cap->max_parent_qpc_num, fc_cap->scq_num, fc_cap->srq_num,
		 fc_cap->max_child_qpc_num, fc_cap->child_qpc_id_start);
	sdk_info(hwdev->dev_hdl, "Vp_id_start: 0x%x, vp_id_end: 0x%x\n",
		 fc_cap->vp_id_start, fc_cap->vp_id_end);
}

static void parse_roce_res_cap(struct hinic5_hwdev *hwdev,
			       struct service_cap *cap,
			       struct cfg_cmd_dev_cap *dev_cap,
			       enum func_type type)
{
	struct dev_roce_svc_own_cap *roce_cap =
		&cap->rdma_cap.dev_rdma_cap.roce_own_cap;

	roce_cap->max_qps = dev_cap->roce_max_qp;
	roce_cap->max_cqs = dev_cap->roce_max_cq;
	roce_cap->max_srqs = dev_cap->roce_max_srq;
	roce_cap->max_mpts = dev_cap->roce_max_mpt;
	roce_cap->max_drc_qps = dev_cap->roce_max_drc_qp;

	roce_cap->wqe_cl_start = dev_cap->roce_wqe_cl_start;
	roce_cap->wqe_cl_end = dev_cap->roce_wqe_cl_end;
	roce_cap->wqe_cl_sz = dev_cap->roce_wqe_cl_size;
	roce_cap->qpc_entry_sz = (dev_cap->hyper_qpc_entry_size_en == 0) ?
		ROCE_QPC_ENTRY_SZ : HYPER_ROCE_QPC_ENTRY_SZ;

	sdk_info(hwdev->dev_hdl, "Get roce resource capbility, type: 0x%x\n",
		 type);
	sdk_info(hwdev->dev_hdl, "Max_qps: 0x%x, max_cqs: 0x%x, max_srqs: 0x%x, max_mpts: 0x%x, max_drcts: 0x%x\n",
		 roce_cap->max_qps, roce_cap->max_cqs, roce_cap->max_srqs,
		 roce_cap->max_mpts, roce_cap->max_drc_qps);

	sdk_info(hwdev->dev_hdl, "Wqe_start: 0x%x, wqe_end: 0x%x, wqe_sz: 0x%x. qpc_entry_sz:0x%x\n",
		 roce_cap->wqe_cl_start, roce_cap->wqe_cl_end,
		 roce_cap->wqe_cl_sz, roce_cap->qpc_entry_sz);

	if (roce_cap->max_qps == 0) {
		if (type == TYPE_PF || type == TYPE_PPF) {
			roce_cap->max_qps = 0x400;
			roce_cap->max_cqs = 0x800;
			roce_cap->max_srqs = 0x400;
			roce_cap->max_mpts = 0x400;
			roce_cap->max_drc_qps = 0x40;
		} else {
			roce_cap->max_qps = 0x200;
			roce_cap->max_cqs = 0x400;
			roce_cap->max_srqs = 0x200;
			roce_cap->max_mpts = 0x200;
			roce_cap->max_drc_qps = 0x40;
		}
	}

	roce_cap->max_child_ctx_num = dev_cap->roce_max_child_ctx_num;
}

static void parse_roce_ext_res_cap(struct hinic5_hwdev *hwdev,
				   struct cfg_cmd_ext_dev_cap *ext_dev_cap,
				   struct service_cap *cap, u32 index)
{
	struct dev_roce_svc_own_cap *roce_cap = &cap->rdma_cap.dev_rdma_cap.roce_own_cap;
	struct cfg_roce_ext_caps *roce_ext_caps = NULL;

	roce_ext_caps = (struct cfg_roce_ext_caps *)(&ext_dev_cap->ext_cap[index]);

	roce_cap->reserved_qps = roce_ext_caps->rsvd_qp;
	roce_cap->reserved_qps_back = roce_ext_caps->rsvd_qp_back;
	roce_cap->reserved_cqs = roce_ext_caps->rsvd_cq;
	roce_cap->reserved_cqs_back = roce_ext_caps->rsvd_cq_back;
	roce_cap->reserved_srqs = roce_ext_caps->rsvd_srq;
	roce_cap->reserved_srqs_back = roce_ext_caps->rsvd_srq_back;
	roce_cap->max_pd = roce_ext_caps->max_pd;
	roce_cap->max_xrcd = roce_ext_caps->max_xrcd;
	roce_cap->max_gid = roce_ext_caps->max_gid;

	sdk_info(hwdev->dev_hdl, "reserved_qps: 0x%x, reserved_qps_back: 0x%x, reserved_cqs: 0x%x\n",
		 roce_cap->reserved_qps, roce_cap->reserved_qps_back, roce_cap->reserved_cqs);
	sdk_info(hwdev->dev_hdl, "reserved_cqs_back: 0x%x, reserved_srqs: 0x%x, reserved_srqs_back: 0x%x\n",
		 roce_cap->reserved_cqs_back, roce_cap->reserved_srqs, roce_cap->reserved_srqs_back);
	sdk_info(hwdev->dev_hdl, "max_pd: 0x%x, max_xrcd: 0x%x, max_gid: 0x%x\n",
		 roce_cap->max_pd, roce_cap->max_xrcd, roce_cap->max_gid);
}

static void parse_rdma_res_cap(struct hinic5_hwdev *hwdev,
			       struct service_cap *cap,
			       struct cfg_cmd_dev_cap *dev_cap,
			       enum func_type type)
{
	struct dev_roce_svc_own_cap *roce_cap =
		&cap->rdma_cap.dev_rdma_cap.roce_own_cap;

	roce_cap->cmtt_cl_start = dev_cap->roce_cmtt_cl_start;
	roce_cap->cmtt_cl_end = dev_cap->roce_cmtt_cl_end;
	roce_cap->cmtt_cl_sz = dev_cap->roce_cmtt_cl_size;

	roce_cap->dmtt_cl_start = dev_cap->roce_dmtt_cl_start;
	roce_cap->dmtt_cl_end = dev_cap->roce_dmtt_cl_end;
	roce_cap->dmtt_cl_sz = dev_cap->roce_dmtt_cl_size;

	sdk_info(hwdev->dev_hdl, "Get rdma resource capbility, Cmtt_start: 0x%x, cmtt_end: 0x%x, cmtt_sz: 0x%x\n",
		 roce_cap->cmtt_cl_start, roce_cap->cmtt_cl_end,
		 roce_cap->cmtt_cl_sz);

	sdk_info(hwdev->dev_hdl, "Dmtt_start: 0x%x, dmtt_end: 0x%x, dmtt_sz: 0x%x\n",
		 roce_cap->dmtt_cl_start, roce_cap->dmtt_cl_end,
		 roce_cap->dmtt_cl_sz);
}

static void parse_ovs_res_cap(struct hinic5_hwdev *hwdev,
			      struct service_cap *cap,
			      struct cfg_cmd_dev_cap *dev_cap,
			      enum func_type type)
{
	struct ovs_service_cap *ovs_cap = &cap->ovs_cap;

	ovs_cap->dev_ovs_cap.max_pctxs = dev_cap->ovs_max_qpc;
	ovs_cap->dev_ovs_cap.fake_vf_max_pctx = dev_cap->fake_vf_max_pctx;
	ovs_cap->dev_ovs_cap.fake_vf_start_id = dev_cap->fake_vf_start_id;
	ovs_cap->dev_ovs_cap.fake_vf_num = dev_cap->fake_vf_num;
	ovs_cap->dev_ovs_cap.dynamic_qp_en = dev_cap->flexq_en;

	sdk_info(hwdev->dev_hdl,
		 "Get ovs resource capbility, max_qpc: 0x%x, fake_vf_start_id: 0x%x, fake_vf_num: 0x%x\n",
		 ovs_cap->dev_ovs_cap.max_pctxs,
		 ovs_cap->dev_ovs_cap.fake_vf_start_id,
		 ovs_cap->dev_ovs_cap.fake_vf_num);
	sdk_info(hwdev->dev_hdl,
		 "fake_vf_max_qpc: 0x%x, dynamic_qp_en: 0x%x\n",
		 ovs_cap->dev_ovs_cap.fake_vf_max_pctx,
		 ovs_cap->dev_ovs_cap.dynamic_qp_en);
}

static void parse_ppa_res_cap(struct hinic5_hwdev *hwdev,
			      struct service_cap *cap,
			      struct cfg_cmd_dev_cap *dev_cap,
			      enum func_type type)
{
	struct ppa_service_cap *dip_cap = &cap->ppa_cap;

	dip_cap->qpc_fake_vf_ctx_num = dev_cap->fake_vf_max_pctx;
	dip_cap->qpc_fake_vf_start = dev_cap->fake_vf_start_id;
	dip_cap->qpc_fake_vf_num = dev_cap->fake_vf_num;
	dip_cap->bloomfilter_en = (dev_cap->fake_vf_bfilter_len != 0) ? 1 : 0;
	dip_cap->bloomfilter_length = dev_cap->fake_vf_bfilter_len;
	sdk_info(hwdev->dev_hdl,
		 "Get ppa resource capbility, fake_vf_start_id: 0x%x, fake_vf_num: 0x%x, fake_vf_max_qpc: 0x%x\n",
		 dip_cap->qpc_fake_vf_start,
		 dip_cap->qpc_fake_vf_num,
		 dip_cap->qpc_fake_vf_ctx_num);
}

static void parse_toe_res_cap(struct hinic5_hwdev *hwdev,
			      struct service_cap *cap,
			      struct cfg_cmd_dev_cap *dev_cap,
			      enum func_type type)
{
	struct dev_toe_svc_cap *toe_cap = &cap->toe_cap.dev_toe_cap;

	toe_cap->max_pctxs = dev_cap->toe_max_pctx;
	toe_cap->max_cqs = dev_cap->toe_max_cq;
	toe_cap->max_srqs = dev_cap->toe_max_srq;
	toe_cap->srq_id_start = dev_cap->toe_srq_id_start;
	toe_cap->max_mpts = dev_cap->toe_max_mpt;
	toe_cap->max_cctxt = dev_cap->toe_max_cctxt;

	sdk_info(hwdev->dev_hdl,
		 "Get toe resource capbility, max_pctxs: 0x%x, max_cqs: 0x%x, max_srqs: 0x%x, srq_id_start: 0x%x, max_mpts: 0x%x\n",
		 toe_cap->max_pctxs, toe_cap->max_cqs, toe_cap->max_srqs,
		 toe_cap->srq_id_start, toe_cap->max_mpts);
}

static void parse_ipsec_res_cap(struct hinic5_hwdev *hwdev,
				struct service_cap *cap,
				struct cfg_cmd_dev_cap *dev_cap,
				enum func_type type)
{
	struct ipsec_service_cap *ipsec_cap = &cap->ipsec_cap;

	ipsec_cap->dev_ipsec_cap.max_sactxs = dev_cap->ipsec_max_sactxs;
	ipsec_cap->dev_ipsec_cap.max_spctxs = dev_cap->ipsec_max_spctxs;
	ipsec_cap->dev_ipsec_cap.max_cqs = dev_cap->ipsec_max_cq;
	ipsec_cap->dev_ipsec_cap.sa_hash_bucket_num = dev_cap->ipsec_sa_hash_bucket_num;
	ipsec_cap->dev_ipsec_cap.sp_hash_bucket_num = dev_cap->ipsec_sp_hash_bucket_num;

	sdk_info(hwdev->dev_hdl,
		"Get IPsec resource capbility, max_sactxs: 0x%x, sa hash bucket num: 0x%x\n",
		dev_cap->ipsec_max_sactxs, dev_cap->ipsec_sa_hash_bucket_num);
	sdk_info(hwdev->dev_hdl,
		 "Get IPsec resource capbility, max_spctxs: 0x%x, " \
		 "sp hash bucket num: 0x%x, max cq: 0x%x\n",
		 dev_cap->ipsec_max_spctxs, dev_cap->ipsec_sp_hash_bucket_num,
		 dev_cap->ipsec_max_cq);
}

static void parse_vbs_res_cap(struct hinic5_hwdev *hwdev,
			      struct service_cap *cap,
			      struct cfg_cmd_dev_cap *dev_cap,
			      enum func_type type)
{
	struct vbs_service_cap *vbs_cap = &cap->vbs_cap;

	vbs_cap->vbs_max_volq = dev_cap->vbs_max_volq;
	vbs_cap->vbs_host_dma_data_cos = dev_cap->vbs_host_dma_data_cos;
	vbs_cap->vbs_volq_cos = dev_cap->vbs_volq_cos;
	vbs_cap->vbs_main_pf_enable = dev_cap->vbs_main_pf_enable;
	vbs_cap->vbs_vsock_pf_enable = dev_cap->vbs_vsock_pf_enable;
	vbs_cap->vbs_fushion_queue_pf_enable = dev_cap->vbs_fushion_queue_pf_enable;
	vbs_cap->vbs_child_ctx_num = dev_cap->vbs_child_ctx_num;
	vbs_cap->vbs_hash_bucket_num = dev_cap->vbs_hash_bucket_num;

	sdk_info(hwdev->dev_hdl, "Get VBS resource capbility, vbs_max_volq: 0x%x, vbs_child_ctx_num: 0x%x, vbs_hash_bucket_num: 0x%x\n",
		 dev_cap->vbs_max_volq, dev_cap->vbs_child_ctx_num, dev_cap->vbs_hash_bucket_num);
}

static void parse_jbof_res_cap(struct hinic5_hwdev *hwdev,
			       struct cfg_cmd_ext_dev_cap *ext_dev_cap,
			       struct service_cap *cap, u32 index)
{
	struct jbof_service_cap *jbof_cap = &cap->jbof_cap;
	struct cfg_jbof_ext_caps *jbof_ext_caps = NULL;

	jbof_ext_caps = (struct cfg_jbof_ext_caps *)(&ext_dev_cap->ext_cap[index]);

	jbof_cap->max_parent_qpc_num = jbof_ext_caps->jbof_max_pctx;
	jbof_cap->max_child_qpc_num = jbof_ext_caps->jbof_max_cctx;
	jbof_cap->hash_bucket_num = jbof_ext_caps->jbof_hash_bucket_num;

	sdk_info(hwdev->dev_hdl,
		 "Get jbof resource capbility, max_parent_qpc_num: 0x%x max_child_qpc_num:0x%x, hash_bucket_num: 0x%x\n",
		 jbof_cap->max_parent_qpc_num, jbof_cap->max_child_qpc_num,
		 jbof_cap->hash_bucket_num);
}

static void parse_dmmu_res_cap(struct hinic5_hwdev *hwdev,
			       struct service_cap *cap,
			       struct cfg_cmd_dev_cap *dev_cap,
			       enum func_type type)
{
	struct dmmu_service_cap *dmmu_cap = &cap->dmmu_cap;

	dmmu_cap->pasid_min = dev_cap->min_fake_pasid;
	dmmu_cap->pasid_max = dev_cap->max_fake_pasid;
	dmmu_cap->cl_start = dev_cap->dmmu_cl_start;
	dmmu_cap->cl_end = dev_cap->dmmu_cl_end;

	sdk_info(hwdev->dev_hdl, "Get DMMU resource capbility, pasid_max: 0x%x\n",
		 dmmu_cap->pasid_max);
}

static void parse_ub_res_cap(struct hinic5_hwdev *dev,
			     struct cfg_cmd_ext_dev_cap *ext_dev_cap,
			     struct service_cap *cap, u32 index)
{
	struct ub_service_cap *ub_caps = &cap->ub_cap;
	struct ub_firmware_caps *ub_ext_caps = NULL;

	ub_ext_caps = (struct ub_firmware_caps *)(&ext_dev_cap->ext_cap[index]);

	ub_caps->sdk_res.max_jfc = ub_ext_caps->max_jfc;
	ub_caps->sdk_res.max_jetty = ub_ext_caps->max_jetty;
	ub_caps->sdk_res.max_jetty_grp = ub_ext_caps->max_jetty_grp;
	ub_caps->sdk_res.max_jfr = ub_ext_caps->max_jfr;
	ub_caps->sdk_res.max_mpts = ub_ext_caps->max_mpts;
	ub_caps->sdk_res.max_tp = ub_ext_caps->max_tp;
	ub_caps->sdk_res.max_tpg = ub_ext_caps->max_tpg;
	ub_caps->sdk_res.max_vtp = ub_ext_caps->max_vtp;
	ub_caps->sdk_res.max_gid = ub_ext_caps->max_gid;
	ub_caps->sdk_res.max_utp = ub_ext_caps->max_utp;
	ub_caps->sdk_res.max_jfrc = ub_ext_caps->max_jfrc;
	ub_caps->sdk_res.cqc_entry_sz = ub_ext_caps->cqc_entry_sz; // 128
	ub_caps->sdk_res.srqc_entry_sz = ub_ext_caps->srqc_entry_sz; // 64
	ub_caps->sdk_res.qpc_entry_sz = ub_ext_caps->qpc_entry_sz; // 1024

	ub_caps->net_dev_cap.is_tpf = ub_ext_caps->is_tpf;
	ub_caps->net_dev_cap.max_mtu = ub_ext_caps->max_mtu; // 8192
	ub_caps->net_dev_cap.vf_cnt = ub_ext_caps->vf_cnt;

	sdk_info(dev->dev_hdl, "Max_jfc: 0x%x, max_jfr: 0x%x, max_jetty: 0x%x, max_mpts: 0x%x, max_tp: 0x%x\n",
		 ub_caps->sdk_res.max_jfc, ub_caps->sdk_res.max_jfr,
		 ub_caps->sdk_res.max_jetty, ub_caps->sdk_res.max_mpts, ub_caps->sdk_res.max_tp);

	sdk_info(dev->dev_hdl, "cqc_entry_sz: 0x%x, srqc_entry_sz: 0x%x, qpc_entry_sz: 0x%x\n",
		 ub_caps->sdk_res.cqc_entry_sz, ub_caps->sdk_res.srqc_entry_sz,
		 ub_caps->sdk_res.qpc_entry_sz);
}

static void parse_fake_vf_ext_cap(struct hinic5_hwdev *hwdev,
				  struct cfg_cmd_ext_dev_cap *ext_dev_cap,
				  struct service_cap *cap, u32 index)
{
	struct cfg_fake_vf_ext_caps *ext_cap =
		(struct cfg_fake_vf_ext_caps *)(&ext_dev_cap->ext_cap[index]);

	cap->fake_vf_parent_func_id = ext_cap->fake_vf_parent_func_id;
	cap->fake_vf_lazy_init      = ext_cap->fake_vf_lazy_init != 0;

	cap->fake_vf_max_scqc_ctx = ext_cap->scqc_fake_vf_ctx_num;
	cap->fake_vf_max_srqc_ctx = ext_cap->srqc_fake_vf_ctx_num;
	cap->fake_vf_max_gid_ctx = ext_cap->gid_fake_vf_ctx_num;
	cap->fake_vf_max_mpt_ctx = ext_cap->mpt_fake_vf_ctx_num;
	cap->fake_vf_max_childc_ctx = ext_cap->childc_fake_vf_ctx_num;
	cap->fake_vf_qpc_ctx_size_en = ext_cap->qpc_fake_vf_ctx_size_order_en != 0;
	cap->fake_vf_qpc_ctx_size_order = ext_cap->qpc_fake_vf_ctx_size_order;

	sdk_info(hwdev->dev_hdl,
		 "Get fake vf capbility, parent func id 0x%x, lazy init %u\n",
		 cap->fake_vf_parent_func_id, ext_cap->fake_vf_lazy_init);
	sdk_info(hwdev->dev_hdl,
		 "Get fake vf ctx max capbility, scqc 0x%x, srqc 0x%x, gid 0x%x, mpt 0x%x, childc 0x%x\n",
		 cap->fake_vf_max_scqc_ctx, cap->fake_vf_max_srqc_ctx, cap->fake_vf_max_gid_ctx,
		 cap->fake_vf_max_mpt_ctx, cap->fake_vf_max_childc_ctx);
	sdk_info(hwdev->dev_hdl,
		 "Get fake vf ctx size capbility. qpc ctx size en %u, order %u\n",
		 cap->fake_vf_qpc_ctx_size_en, cap->fake_vf_qpc_ctx_size_order);
}

static void parse_fw_update_ext_cap(struct hinic5_hwdev *hwdev,
				    struct cfg_cmd_ext_dev_cap *ext_dev_cap,
				    struct service_cap *cap, u32 index)
{
	cfg_fw_update_ext_caps *ext_caps = (cfg_fw_update_ext_caps *)(&ext_dev_cap->ext_cap[index]);

	*(&cap->fw_update_cap) = *ext_caps;
	sdk_info(hwdev->dev_hdl,
		 "Get fw udpate capbility, fw_img_hdr_size 0x%x, fw_tile_text_size 0x%x\n",
		 cap->fw_update_cap.fw_img_hdr_size, cap->fw_update_cap.fw_tile_text_size);
}

static void parse_comm_info_ext_cap(struct hinic5_hwdev *hwdev,
				    struct cfg_cmd_ext_dev_cap *ext_dev_cap,
				    struct service_cap *cap, u32 index)
{
	struct comm_info_ext_cap *ext_caps;
	struct cfm_service_cap *cfm_cap = &cap->cfm_cap;

	ext_caps = (struct comm_info_ext_cap *)(&ext_dev_cap->ext_cap[index]);

	/* BAT capabilities */
	cap->bat_cid_index_bit_width = ext_caps->bat_cid_index_bit_width;

	/* SMF capabilities */
	cap->smf_max_num = ext_caps->max_smf_num;

	/* SRIOV ext capabilities */
	cap->vf_isolation = (ext_caps->vf_isolation != 0);

	sdk_info(hwdev->dev_hdl,
		 "Get common ext cap: bat cid index bits %u, smf_max_num %u, vf iso %d\n",
		 cap->bat_cid_index_bit_width, cap->smf_max_num,
		 cap->vf_isolation);

	/* CFM CCP capabilities */
	cfm_cap->ccp_child_ctx_sz  = ext_caps->ccp_child_ctx_sz;
	cfm_cap->ccp_max_child_ctx = ext_caps->ccp_max_child_ctx;

	sdk_info(hwdev->dev_hdl, "Get CFM CCP cap: childc basic size %u, max %u\n",
		 cfm_cap->ccp_child_ctx_sz, cfm_cap->ccp_max_child_ctx);
}

static void parse_dev_cap(struct hinic5_hwdev *dev,
			  struct cfg_cmd_dev_cap *dev_cap, enum func_type type)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;

	/* Public resource */
	parse_pub_res_cap(dev, cap, dev_cap, type);

	/* PPF managed dynamic resource */
	if (type == TYPE_PPF)
		parse_dynamic_share_res_cap(cap, dev_cap);

	/* L2 NIC resource */
	if (IS_NIC_TYPE(dev) != 0)
		parse_l2nic_res_cap(dev, cap, dev_cap, type);

	/* FC without virtulization */
	if (type == TYPE_PF || type == TYPE_PPF) {
		if (IS_FC_TYPE(dev) != 0)
			parse_fc_res_cap(dev, cap, dev_cap, type);
	}

	/* toe resource */
	if (IS_TOE_TYPE(dev) != 0)
		parse_toe_res_cap(dev, cap, dev_cap, type);

	/* mtt cache line */
	if (IS_RDMA_ENABLE(dev))
		parse_rdma_res_cap(dev, cap, dev_cap, type);

	/* RoCE resource */
	if (IS_ROCE_TYPE(dev) != 0)
		parse_roce_res_cap(dev, cap, dev_cap, type);

	if (IS_OVS_TYPE(dev) != 0)
		parse_ovs_res_cap(dev, cap, dev_cap, type);

	if (IS_IPSEC_TYPE(dev) != 0)
		parse_ipsec_res_cap(dev, cap, dev_cap, type);

	if (IS_PPA_TYPE(dev) != 0)
		parse_ppa_res_cap(dev, cap, dev_cap, type);

	if (IS_VBS_TYPE(dev) != 0)
		parse_vbs_res_cap(dev, cap, dev_cap, type);

	if (IS_DMMU_TYPE(dev) != 0)
		parse_dmmu_res_cap(dev, cap, dev_cap, type);
}

static void parse_all_res_cap(struct hinic5_hwdev *dev,
			      struct cfg_cmd_ext_dev_cap *ext_dev_cap,
			      struct service_cap *cap, u32 type, u32 index)
{
	switch (type) {
	// Different types between SERVICE_BIT_UB and EXT_CAP_FAKE_VF, to eliminate warning
	case (u32)SERVICE_BIT_UB:
		parse_ub_res_cap(dev, ext_dev_cap, cap, index);
		break;
	case (u32)SERVICE_BIT_ROCE:
		parse_roce_ext_res_cap(dev, ext_dev_cap, cap, index);
		break;
	case (u32)SERVICE_BIT_JBOF:
		parse_jbof_res_cap(dev, ext_dev_cap, cap, index);
		break;
	case (u32)EXT_CAP_FAKE_VF:
		parse_fake_vf_ext_cap(dev, ext_dev_cap, cap, index);
		break;
	case (u32)EXT_CAP_FW_UPDATE:
		parse_fw_update_ext_cap(dev, ext_dev_cap, cap, index);
		break;
	case (u32)EXT_CAP_COMM_INFO:
		parse_comm_info_ext_cap(dev, ext_dev_cap, cap, index);
		break;
	default:
		break;
	}
}

static void parse_ext_dev_cap(struct hinic5_hwdev *dev,
			      struct cfg_cmd_ext_dev_cap *ext_dev_cap, enum func_type type)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	u32 index = 0;
	struct cfg_cmd_tlv_hdr *tlv_hdr = NULL;

	do {
		tlv_hdr = (struct cfg_cmd_tlv_hdr *)&ext_dev_cap->ext_cap[index];
		if (tlv_hdr->len == 0x0 || tlv_hdr->len % 0x4 != 0x0)
			return;

		parse_all_res_cap(dev, ext_dev_cap, cap, tlv_hdr->type, index + sizeof(*tlv_hdr));

		index += (tlv_hdr->len + sizeof(*tlv_hdr));
	} while (index < MAX_CAP_LEN_QWORD);
}

static int get_legacy_dev_cap(struct hinic5_hwdev *hwdev, enum func_type type)
{
	struct cfg_cmd_dev_cap dev_cap;
	u16 out_len = sizeof(dev_cap);
	int err;

	memset(&dev_cap, 0, sizeof(dev_cap));
	dev_cap.func_id = hinic5_global_func_id(hwdev);
	sdk_info(hwdev->dev_hdl, "Get cap from fw, func_idx: %u\n",
		 dev_cap.func_id);

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_CFGM, CFG_CMD_GET_DEV_CAP,
				      &dev_cap, sizeof(dev_cap),
				      &dev_cap, &out_len, 0,
				      HINIC5_CHANNEL_COMM);
	if (err != 0 || dev_cap.head.status != 0 || out_len == 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to get capability from FW, err: %d, status: 0x%x, out size: 0x%x\n",
			err, dev_cap.head.status, out_len);
		return -EIO;
	}

	parse_dev_cap(hwdev, &dev_cap, type);

	return 0;
}

static int get_extend_dev_cap(struct hinic5_hwdev *hwdev, enum func_type type)
{
	struct cfg_cmd_ext_dev_cap *ext_dev_cap = NULL;
	u16 out_len = sizeof(struct cfg_cmd_ext_dev_cap);
	int err;

	if (!COMM_SUPPORT_EXTEND_CAPBILITY(hwdev))
		return 0;

	ext_dev_cap = (struct cfg_cmd_ext_dev_cap *)kzalloc(sizeof(*ext_dev_cap), GFP_KERNEL);
	if (!ext_dev_cap)
		return -ENOMEM;
	ext_dev_cap->func_id = hinic5_global_func_id(hwdev);

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_CFGM, CFG_CMD_GET_EXTEND_DEV_CAP,
				      ext_dev_cap, sizeof(*ext_dev_cap),
				      ext_dev_cap, &out_len, 0,
				      HINIC5_CHANNEL_COMM);
	if (err != 0 || ext_dev_cap->head.status != 0 || out_len == 0) {
		sdk_err(hwdev->dev_hdl,
			"Failed to get extern capability from FW, err: %d, status: 0x%x, out size: 0x%x\n",
			err, ext_dev_cap->head.status, out_len);
		kfree(ext_dev_cap);
		return -EIO;
	}

	parse_ext_dev_cap(hwdev, ext_dev_cap, type);
	kfree(ext_dev_cap);

	return 0;
}

STATIC int valid_smf_cap(struct service_cap *cap)
{
	const u8 smf_num_whitelist[] = {0x2, 0x4, 0x8};
	const u8 smf_max_num = cap->smf_max_num;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(smf_num_whitelist); i++) {
		if (smf_num_whitelist[i] == smf_max_num)
			return 0;
	}

	return -EINVAL;
}

static int get_smf_max_and_enabled_num(struct hinic5_hwdev *hwdev)
{
	struct service_cap *cap = &hwdev->cfg_mgmt->svc_cap;
	u8 smf_id, smf_enabled_num = 0;
	int err;

	if (cap->smf_max_num == 0)
		cap->smf_max_num = CHIP_SMF_NUM_MIN;

	err = valid_smf_cap(cap);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Not supported max number of SMFs: %u\n", cap->smf_max_num);
		return err;
	}

	/* count smf_enabled_num */
	for (smf_id = 0; smf_id < cap->smf_max_num; ++smf_id) {
		if ((cap->smf_pg & (1U << smf_id)) != 0)
			smf_enabled_num++;
	}
	cap->smf_enabled_num = smf_enabled_num;

	sdk_info(hwdev->dev_hdl, "SMF cap: max %u, enabled %u\n", cap->smf_max_num,
		 cap->smf_enabled_num);

	return 0;
}

static int get_cap_from_fw(struct hinic5_hwdev *dev, enum func_type type)
{
	int err;

	err = get_legacy_dev_cap(dev, type);
	if (err != 0)
		return err;

	err = get_extend_dev_cap(dev, type);
	if (err != 0)
		return err;

	return get_smf_max_and_enabled_num(dev);
}

int hinic5_get_dev_cap(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	enum func_type type;
	int err;

	if (!hwdev)
		return -EINVAL;

	type = HINIC5_FUNC_TYPE(dev);

	switch (type) {
	case TYPE_PF:
	case TYPE_PPF:
	case TYPE_VF:
		err = get_cap_from_fw(dev, type);
		if (err != 0) {
			sdk_err(dev->dev_hdl, "Failed to get PF/PPF capability\n");
			return err;
		}
		break;
	default:
		sdk_err(dev->dev_hdl, "Unsupported PCI Function type: %d\n",
			type);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(hinic5_get_dev_cap);

STATIC int parse_host_timer_cfg(struct service_cap *cap,
				struct cfg_cmd_host_timer *cfg)
{
	struct timer_vf_info_seg *segs = cap->timer_vf_segs;
	struct timer_vf_info_fake *fake_info = &cfg->timer_vf_info.fake;

	cap->timer_pf_id_start = cfg->timer_pf_id_start;
	cap->timer_pf_num      = cfg->timer_pf_num;
	cap->timer_vf_id_start = cfg->timer_vf_id_start;
	cap->timer_vf_num      = cfg->timer_vf_num;

	memset(segs, 0, sizeof(cap->timer_vf_segs));

	if (cfg->timer_vf_info_mode_segs != 0) {
		memcpy(segs,
		       &cfg->timer_vf_info.segs,
		       sizeof(cfg->timer_vf_info.segs));
	}

	if (cfg->timer_vf_info_mode_fake != 0 &&
	    fake_info->timer_normal_vf_num != 0) {
		segs[0].start   = cfg->timer_vf_id_start;
		segs[0].num     = fake_info->timer_normal_vf_num;
		segs[0x1].start = fake_info->timer_fake_vf_id_start;
		segs[0x1].num   = fake_info->timer_fake_vf_num;
	}

	return 0;
}

STATIC int check_host_timer_segments(struct service_cap *cap)
{
	struct timer_vf_info_seg *segs = cap->timer_vf_segs;
	u16 vf_start = cap->timer_vf_id_start;
	u16 vf_end   = cap->timer_vf_id_start + cap->timer_vf_num;
	u16 vf_last  = vf_start;
	int i, err = 0;

	for (i = 0; i < TIMER_VF_SEGS_NUM; i++) {
		if (segs[i].start == 0)
			break;
		if (segs[i].num == 0) {
			pr_err("seg %d start is %u, but num is zero\n",
			       i, segs[i].start);
			err = -EINVAL;
			goto fail;
		}

		if (segs[i].start < vf_last) {
			pr_err("seg %d conflict with last, seg start %u, last end %u\n",
			       i, segs[i].start, vf_last);
			err = -EINVAL;
			goto fail;
		}
		vf_last = segs[i].start + segs[i].num;
		if (vf_last > vf_end) {
			pr_err("seg %d end %u > vf end %u", i, vf_last, vf_end);
			err = -ERANGE;
			goto fail;
		}
	}

	return 0;

fail:
	pr_err("vf timer segs: %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u %u-%u\n",
	       segs[0x0].start, segs[0x0].start + segs[0x0].num,
	       segs[0x1].start, segs[0x1].start + segs[0x1].num,
	       segs[0x2].start, segs[0x2].start + segs[0x2].num,
	       segs[0x3].start, segs[0x3].start + segs[0x3].num,
	       segs[0x4].start, segs[0x4].start + segs[0x4].num,
	       segs[0x5].start, segs[0x5].start + segs[0x5].num,
	       segs[0x6].start, segs[0x6].start + segs[0x6].num);
	return err;
}

int hinic5_get_ppf_timer_cfg(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	struct cfg_cmd_host_timer cfg_host_timer;
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	u16 out_len = sizeof(cfg_host_timer);
	int err;

	memset(&cfg_host_timer, 0, sizeof(cfg_host_timer));
	cfg_host_timer.host_id = dev->cfg_mgmt->svc_cap.host_id;

	err = hinic5_msg_to_mgmt_sync(dev, HINIC5_MOD_CFGM, CFG_CMD_GET_HOST_TIMER,
				      &cfg_host_timer, sizeof(cfg_host_timer),
				      &cfg_host_timer, &out_len, 0,
				      HINIC5_CHANNEL_COMM);
	if (err != 0 || cfg_host_timer.head.status != 0 || out_len == 0) {
		sdk_err(dev->dev_hdl,
			"Failed to get host timer cfg from FW, err: %d, status: 0x%x, out size: 0x%x\n",
			err, cfg_host_timer.head.status, out_len);
		return -EIO;
	}

	err = parse_host_timer_cfg(cap, &cfg_host_timer);
	if (err != 0) {
		sdk_err(dev->dev_hdl,
			"Failed to parse host timer config, err %d\n", err);
		return err;
	}

	sdk_info(dev->dev_hdl, "Get host timer cfg with vf info mode: segs %u, fake %u\n",
		 cfg_host_timer.timer_vf_info_mode_segs,
		 cfg_host_timer.timer_vf_info_mode_fake);

	err = check_host_timer_segments(cap);
	if (err != 0) {
		sdk_err(dev->dev_hdl,
			"Failed to check host timer config, err %d\n", err);
		return err;
	}

	return 0;
}

static void nic_param_fix(struct hinic5_hwdev *dev)
{
}

static void rdma_mtt_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct rdma_service_cap *rdma_cap = &cap->rdma_cap;

	rdma_cap->log_mtt = LOG_MTT_SEG;
	rdma_cap->log_mtt_seg = LOG_MTT_SEG;
	rdma_cap->mtt_entry_sz = MTT_ENTRY_SZ;
	rdma_cap->mpt_entry_sz = RDMA_MPT_ENTRY_SZ;
	rdma_cap->num_mtts = RDMA_NUM_MTTS;
}

static void rdma_param_fix_part(struct rdma_service_cap *rdma_cap)
{
	rdma_cap->max_fmr_maps = RDMA_FRMR_MAP_NUM;
	rdma_cap->num_mtts = RDMA_NUM_MTTS;
	rdma_cap->log_mtt_seg = LOG_MTT_SEG;
	rdma_cap->mtt_entry_sz = MTT_ENTRY_SZ;
	rdma_cap->log_rdmarc_seg = LOG_RDMARC_SEG;
	rdma_cap->local_ca_ack_delay = LOCAL_ACK_DELAY;
	rdma_cap->num_ports = RDMA_NUM_PORTS;
	rdma_cap->db_page_size = DB_PAGE_SZ;
	rdma_cap->direct_wqe_size = DWQE_SZ;
	rdma_cap->num_pds = NUM_PD;
	rdma_cap->reserved_pds = RSVD_PD;
	rdma_cap->max_xrcds = MAX_XRCDS;
	rdma_cap->reserved_xrcds = RSVD_XRCDS;
	rdma_cap->max_gid_per_port = MAX_GID_PER_PORT;
	rdma_cap->gid_entry_sz = GID_ENTRY_SZ;
	rdma_cap->reserved_lkey = RSVD_LKEY;
}

static void rdma_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct rdma_service_cap *rdma_cap = &cap->rdma_cap;
	struct dev_roce_svc_own_cap *roce_cap =
		&rdma_cap->dev_rdma_cap.roce_own_cap;

	rdma_cap->log_mtt = LOG_MTT_SEG;
	rdma_cap->log_rdmarc = LOG_RDMARC_SEG;
	rdma_cap->reserved_qps = RDMA_RSVD_QPS;
	rdma_cap->max_sq_sg = RDMA_MAX_SQ_SGE;

	/* RoCE */
	if (IS_ROCE_TYPE(dev) != 0) {
		roce_cap->max_wqes = ROCE_MAX_WQES;
		roce_cap->max_rq_sg = ROCE_MAX_RQ_SGE;
		roce_cap->max_sq_inline_data_sz = ROCE_MAX_SQ_INLINE_DATA_SZ;
		roce_cap->max_rq_desc_sz = ROCE_MAX_RQ_DESC_SZ;
		roce_cap->rdmarc_entry_sz = ROCE_RDMARC_ENTRY_SZ;
		roce_cap->max_qp_init_rdma = ROCE_MAX_QP_INIT_RDMA;
		roce_cap->max_qp_dest_rdma = ROCE_MAX_QP_DEST_RDMA;
		roce_cap->max_srq_wqes = ROCE_MAX_SRQ_WQES;
		roce_cap->max_srq_sge = ROCE_MAX_SRQ_SGE;
		roce_cap->srqc_entry_sz = ROCE_SRQC_ENTERY_SZ;
		roce_cap->max_msg_sz = ROCE_MAX_MSG_SZ;
	}

	rdma_cap->max_sq_desc_sz = RDMA_MAX_SQ_DESC_SZ;
	rdma_cap->wqebb_size = WQEBB_SZ;
	rdma_cap->max_cqes = RDMA_MAX_CQES;
	rdma_cap->reserved_cqs = RDMA_RSVD_CQS;
	rdma_cap->cqc_entry_sz = RDMA_CQC_ENTRY_SZ;
	rdma_cap->cqe_size = RDMA_CQE_SZ;
	rdma_cap->reserved_mrws = RDMA_RSVD_MRWS;
	rdma_cap->mpt_entry_sz = RDMA_MPT_ENTRY_SZ;

	/* 2^8 - 1
	 *	+------------------------+-----------+
	 *	|   4B   |      1M(20b)  | Key(8b)   |
	 *	+------------------------+-----------+
	 * key = 8bit key + 24bit index,
	 * now Lkey of SGE uses 2bit(bit31 and bit30), so key only have 10bit,
	 * we use original 8bits directly for simpilification
	 */
	rdma_param_fix_part(rdma_cap);
	rdma_cap->num_comp_vectors = (u32)dev->cfg_mgmt->eq_info.num_ceq;
	rdma_cap->page_size_cap = PAGE_SZ_CAP;
	rdma_cap->flags = (RDMA_BMME_FLAG_LOCAL_INV |
			   RDMA_BMME_FLAG_REMOTE_INV |
			   RDMA_BMME_FLAG_FAST_REG_WR |
			   RDMA_DEV_CAP_FLAG_XRC |
			   RDMA_DEV_CAP_FLAG_MEM_WINDOW |
			   RDMA_BMME_FLAG_TYPE_2_WIN |
			   RDMA_BMME_FLAG_WIN_TYPE_2B |
			   RDMA_DEV_CAP_FLAG_ATOMIC);
	rdma_cap->max_frpl_len = MAX_FRPL_LEN;
	rdma_cap->max_pkeys = MAX_PKEYS;
}

static void toe_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct toe_service_cap *toe_cap = &cap->toe_cap;

	toe_cap->pctx_sz = TOE_PCTX_SZ;
	toe_cap->scqc_sz = TOE_CQC_SZ;
}

static void ovs_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct ovs_service_cap *ovs_cap = &cap->ovs_cap;

	ovs_cap->pctx_sz = OVS_PCTX_SZ;
}

static void ppa_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct ppa_service_cap *ppa_cap = &cap->ppa_cap;

	ppa_cap->pctx_sz = PPA_PCTX_SZ;
}

static void fc_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct fc_service_cap *fc_cap = &cap->fc_cap;

	fc_cap->parent_qpc_size = FC_PCTX_SZ;
	fc_cap->child_qpc_size = FC_CCTX_SZ;
	fc_cap->sqe_size = FC_SQE_SZ;

	fc_cap->scqc_size = FC_SCQC_SZ;
	fc_cap->scqe_size = FC_SCQE_SZ;

	fc_cap->srqc_size = FC_SRQC_SZ;
	fc_cap->srqe_size = FC_SRQE_SZ;
}

static void ipsec_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct ipsec_service_cap *ipsec_cap = &cap->ipsec_cap;

	ipsec_cap->sactx_sz = IPSEC_SACTX_SZ;
}

static void ub_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct ub_service_cap *ub_cap = &cap->ub_cap;

	ub_cap->sdk_res.mpt_entry_sz = UB_MPT_ENTRY_SZ;

	ub_cap->sdk_res.cmtt_cl_start = UB_CMTT_CL_START;
	ub_cap->sdk_res.cmtt_cl_end = UB_CMTT_CL_END;
	ub_cap->sdk_res.cmtt_cl_sz = UB_CMTT_CL_SIZE;

	ub_cap->sdk_res.wqe_cl_start = UB_WQE_CL_START;
	ub_cap->sdk_res.wqe_cl_end = UB_WQE_CL_END;
	ub_cap->sdk_res.wqe_cl_sz = UB_WQE_CL_SIZE;

	ub_cap->sdk_res.dmtt_cl_start = UB_DMTT_CL_START;
	ub_cap->sdk_res.dmtt_cl_end = UB_DMTT_CL_END;
	ub_cap->sdk_res.dmtt_cl_sz = UB_DMTT_CL_SIZE;

	ub_cap->net_dev_cap.comp_vector_cnt = (u32)dev->cfg_mgmt->eq_info.num_ceq;
	ub_cap->net_dev_cap.port_cnt = 1;
}

static void jbof_param_fix(struct hinic5_hwdev *dev)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;
	struct jbof_service_cap *jbof_cap = &cap->jbof_cap;

	jbof_cap->parent_qpc_size = JBOF_PCTX_SZ;
	jbof_cap->child_qpc_size = JBOF_CCTX_SZ;
}

static void init_service_param(struct hinic5_hwdev *dev)
{
	if (IS_NIC_TYPE(dev) != 0)
		nic_param_fix(dev);
	if (IS_RDMA_ENABLE(dev))
		rdma_mtt_fix(dev);
	if (IS_ROCE_TYPE(dev) != 0)
		rdma_param_fix(dev);
	if (IS_FC_TYPE(dev) != 0)
		fc_param_fix(dev);
	if (IS_TOE_TYPE(dev) != 0)
		toe_param_fix(dev);
	if (IS_OVS_TYPE(dev) != 0)
		ovs_param_fix(dev);
	if (IS_IPSEC_TYPE(dev) != 0)
		ipsec_param_fix(dev);
	if (IS_PPA_TYPE(dev) != 0)
		ppa_param_fix(dev);
	if (IS_UB_TYPE(dev) != 0)
		ub_param_fix(dev);
	if (IS_JBOF_TYPE(dev) != 0)
		jbof_param_fix(dev);
}

static void cfg_get_eq_num(struct hinic5_hwdev *dev)
{
	struct cfg_eq_info *eq_info = &dev->cfg_mgmt->eq_info;

	eq_info->num_ceq = dev->hwif->attr.num_ceqs;
	eq_info->num_ceq_remain = eq_info->num_ceq;
}

static int cfg_init_eq(struct hinic5_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;
	struct cfg_eq *eq = NULL;
	u8 num_ceq, i = 0;

	cfg_get_eq_num(dev);
	num_ceq = cfg_mgmt->eq_info.num_ceq;

	sdk_info(dev->dev_hdl, "Cfg mgmt: ceqs=0x%x, remain=0x%x\n",
		 cfg_mgmt->eq_info.num_ceq, cfg_mgmt->eq_info.num_ceq_remain);

	if (num_ceq == 0)
		return 0;

	eq = kcalloc(num_ceq, sizeof(*eq), GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	for (i = 0; i < num_ceq; ++i) {
		eq[i].eqn = i;
		eq[i].free = CFG_FREE;
		eq[i].type = SERVICE_T_MAX;
	}

	cfg_mgmt->eq_info.eq = eq;

	mutex_init(&cfg_mgmt->eq_info.eq_mutex);

	return 0;
}

int hinic5_vector_to_eqn(void *hwdev, enum hinic5_service_type type, int vector)
{
	struct hinic5_hwdev *dev = hwdev;
	struct cfg_mgmt_info *cfg_mgmt = NULL;
	struct cfg_eq *eq = NULL;
	int eqn = -EINVAL;
	int vector_num = vector;

	if (!hwdev || vector < 0)
		return -EINVAL;

	if (type != SERVICE_T_ROCE) {
		sdk_err(dev->dev_hdl,
			"Service type :%d, only RDMA service could get eqn by vector.\n",
			type);
		return -EINVAL;
	}

	cfg_mgmt = dev->cfg_mgmt;
	if (!cfg_mgmt) {
		sdk_err(dev->dev_hdl, "Service type :%d, cfg_mgmt is null.\n", type);
		return -EINVAL;
	}

	vector_num = (vector_num % cfg_mgmt->eq_info.num_ceq) + CFG_RDMA_CEQ_BASE;

	eq = cfg_mgmt->eq_info.eq;
	if (eq[vector_num].type == SERVICE_T_ROCE && eq[vector_num].free == CFG_BUSY)
		eqn = eq[vector_num].eqn;

	return eqn;
}
EXPORT_SYMBOL(hinic5_vector_to_eqn);

static int cfg_init_interrupt(struct hinic5_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;
	struct cfg_irq_info *irq_info = &cfg_mgmt->irq_param_info;
	u16 intr_num = dev->hwif->attr.num_irqs;
	u16 intr_needed = (dev->hwif->attr.msix_flex_en != 0) ? (dev->hwif->attr.num_aeqs +
			  dev->hwif->attr.num_ceqs + dev->hwif->attr.num_sq) : intr_num;

	if (intr_num == 0) {
		sdk_err(dev->dev_hdl, "Irq num cfg in fw is zero, msix_flex_en %d\n",
			dev->hwif->attr.msix_flex_en);
		return -EFAULT;
	}

	if (intr_needed > intr_num) {
		sdk_warn(dev->dev_hdl, "Irq num cfg(%u) is less than the needed irq num(%u) msix_flex_en %u\n",
			 intr_num, intr_needed, dev->hwif->attr.msix_flex_en);
		intr_needed = intr_num;
	}

	irq_info->alloc_info = kcalloc(intr_num, sizeof(*irq_info->alloc_info),
				       GFP_KERNEL);
	if (!irq_info->alloc_info)
		return -ENOMEM;

	irq_info->num_irq_hw = intr_needed;
	/* Production requires only surppots MSI-X */
	cfg_mgmt->svc_cap.interrupt_type = INTR_TYPE_MSIX;

	mutex_init(&irq_info->irq_mutex);

	return 0;
}

static int cfg_enable_interrupt(struct hinic5_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;
	u16 nreq = cfg_mgmt->irq_param_info.num_irq_hw;
	struct irq_alloc_info_st *irq_info = NULL;
	struct msix_entry *entry = NULL;
	u16 i = 0;
	int actual_irq, irq_id;

	irq_info = cfg_mgmt->irq_param_info.alloc_info;

	sdk_info(dev->dev_hdl, "Interrupt type: %d, irq num: %u.\n",
		 cfg_mgmt->svc_cap.interrupt_type, nreq);

	switch (cfg_mgmt->svc_cap.interrupt_type) {
	case INTR_TYPE_MSIX:
		if (nreq == 0) {
			sdk_err(dev->dev_hdl, "Interrupt number cannot be zero\n");
			return -EINVAL;
		}
		entry = kcalloc(nreq, sizeof(*entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		for (i = 0; i < nreq; i++)
			entry[i].entry = i;

		actual_irq = hinic5_adev_irq_vectors_alloc(dev->adapter_hdl, entry,
							   VECTOR_THRESHOLD, nreq);
		if (actual_irq < 0) {
			sdk_err(dev->dev_hdl, "Alloc msix entries with threshold 2 failed. actual_irq: %d\n",
				actual_irq);
			kfree(entry);
			return -ENOMEM;
		}

		nreq = (u16)actual_irq;
		cfg_mgmt->irq_param_info.num_total = nreq;
		cfg_mgmt->irq_param_info.num_irq_remain = nreq;
		sdk_info(dev->dev_hdl, "Request %u msix vector success.\n",
			 nreq);

		for (i = 0; i < nreq; ++i) {
			/* u16 driver uses to specify entry, OS writes */
			irq_info[i].info.msix_entry_idx = i;
			/* u32 kernel uses to write allocated vector */
			irq_id = hinic5_adev_irq_vector(dev->adapter_hdl, i);
			if (irq_id < 0) {
				sdk_err(dev->dev_hdl, "Unable to get idx %d, irq %d\n", i,
					irq_id);
				hinic5_adev_irq_vectors_free(dev->adapter_hdl);
				kfree(entry);
				return -ENOMEM;
			}
			irq_info[i].info.irq_id = (u32)irq_id;
			irq_info[i].type = SERVICE_T_MAX;
			irq_info[i].free = CFG_FREE;
		}

		kfree(entry);

		break;

	default:
		sdk_err(dev->dev_hdl, "Unsupport interrupt type %d\n",
			cfg_mgmt->svc_cap.interrupt_type);
		break;
	}

	return 0;
}

int hinic5_alloc_irqs(void *hwdev, enum hinic5_service_type type, u16 num,
		      struct irq_info *irq_info_array, u16 *act_num)
{
	struct hinic5_hwdev *dev = hwdev;
	struct cfg_irq_info *irq_info = NULL;
	struct irq_alloc_info_st *alloc_info = NULL;
	int max_num_irq, i, j;
	u16 free_num_irq;
	u16 alloc_num = num;

	if (!hwdev || !dev->cfg_mgmt || num == 0 || !irq_info_array || !act_num)
		return -EINVAL;

	if (type > SERVICE_T_HINIC5_CQM) {
		pr_err("type is out of bounds\n");
		return -EINVAL;
	}

	irq_info = &dev->cfg_mgmt->irq_param_info;
	mutex_lock(&irq_info->irq_mutex);

	free_num_irq = irq_info->num_irq_remain;
	if (free_num_irq == 0) {
		sdk_err(dev->dev_hdl, "no free irq resource in cfg mgmt.\n");
		mutex_unlock(&irq_info->irq_mutex);
		return -ENOMEM;
	}
	if (alloc_num > free_num_irq) {
		sdk_warn(dev->dev_hdl, "only %u irq resource in cfg mgmt.\n", free_num_irq);
		alloc_num = free_num_irq;
	}

	alloc_info = irq_info->alloc_info;
	max_num_irq = irq_info->num_total;
	*act_num = 0;

	for (i = 0; i < alloc_num; i++) {
		for (j = 0; j < max_num_irq; j++) {
			if (alloc_info[j].free != CFG_FREE)
				continue;

			if (irq_info->num_irq_remain == 0) {
				/* irq_info->num_irq_remain is not updated correctly */
				sdk_err(dev->dev_hdl, "No free irq resource in cfg mgmt\n");
				mutex_unlock(&irq_info->irq_mutex);
				return -EINVAL;
			}
			alloc_info[j].type = type;
			alloc_info[j].free = CFG_BUSY;

			irq_info_array[i].msix_entry_idx =
				alloc_info[j].info.msix_entry_idx;
			irq_info_array[i].irq_id = alloc_info[j].info.irq_id;
			(*act_num)++;
			irq_info->num_irq_remain--;

			break;
		}
	}

	mutex_unlock(&irq_info->irq_mutex);
	return 0;
}
EXPORT_SYMBOL(hinic5_alloc_irqs);

void hinic5_free_irq(void *hwdev, enum hinic5_service_type type, u32 irq_id)
{
	struct hinic5_hwdev *dev = hwdev;
	struct cfg_irq_info *irq_info = NULL;
	struct irq_alloc_info_st *alloc_info = NULL;
	int max_num_irq;
	int i;

	if (!hwdev || !dev->cfg_mgmt)
		return;

	irq_info = &dev->cfg_mgmt->irq_param_info;
	alloc_info = irq_info->alloc_info;
	max_num_irq = irq_info->num_total;

	if (max_num_irq > irq_info->num_irq_hw) {
		sdk_err(dev->dev_hdl, "alloc_info over range\n");
		return;
	}

	mutex_lock(&irq_info->irq_mutex);

	for (i = 0; i < max_num_irq; i++) {
		if (irq_id == alloc_info[i].info.irq_id &&
		    type == alloc_info[i].type) {
			if (alloc_info[i].free != CFG_BUSY)
				continue;

			alloc_info[i].free = CFG_FREE;
			irq_info->num_irq_remain++;
			if (irq_info->num_irq_remain > max_num_irq) {
				sdk_err(dev->dev_hdl, "Find target,but over range\n");
				mutex_unlock(&irq_info->irq_mutex);
				return;
			}
			break;
		}
	}

	if (i >= max_num_irq)
		sdk_warn(dev->dev_hdl, "Irq %u don`t need to free\n", irq_id);

	mutex_unlock(&irq_info->irq_mutex);
}
EXPORT_SYMBOL(hinic5_free_irq);

int hinic5_alloc_ceqs(void *hwdev, enum hinic5_service_type type, int num,
		      int *ceq_id_array, int *act_num)
{
	struct hinic5_hwdev *dev = hwdev;
	struct cfg_mgmt_info *cfg_mgmt = NULL;
	struct cfg_eq_info *eq = NULL;
	int free_ceq;
	int i, j;
	int num_new = num;

	if (!hwdev || !dev->cfg_mgmt || !ceq_id_array || !act_num)
		return -EINVAL;

	cfg_mgmt = dev->cfg_mgmt;
	eq = &cfg_mgmt->eq_info;
	free_ceq = eq->num_ceq_remain;

	mutex_lock(&eq->eq_mutex);

	if (num > free_ceq) {
		if (free_ceq <= 0) {
			sdk_err(dev->dev_hdl, "No free ceq resource in cfg mgmt\n");
			mutex_unlock(&eq->eq_mutex);
			return -ENOMEM;
		}

		sdk_warn(dev->dev_hdl, "Only %d ceq resource in cfg mgmt\n",
			 free_ceq);
	}

	*act_num = 0;

	num_new = min(num_new, eq->num_ceq - CFG_RDMA_CEQ_BASE);
	for (i = 0; i < num_new; i++) {
		if (eq->num_ceq_remain == 0) {
			sdk_warn(dev->dev_hdl, "Alloc %d ceqs, less than required %d ceqs\n",
				 *act_num, num_new);
			mutex_unlock(&eq->eq_mutex);
			return 0;
		}

		for (j = CFG_RDMA_CEQ_BASE; j < eq->num_ceq; j++) {
			if (eq->eq[j].free == CFG_FREE) {
				eq->eq[j].type = type;
				eq->eq[j].free = CFG_BUSY;
				eq->num_ceq_remain--;
				ceq_id_array[i] = eq->eq[j].eqn;
				(*act_num)++;
				break;
			}
		}
	}

	mutex_unlock(&eq->eq_mutex);
	return 0;
}
EXPORT_SYMBOL(hinic5_alloc_ceqs);

void hinic5_free_ceq(void *hwdev, enum hinic5_service_type type, int ceq_id)
{
	struct hinic5_hwdev *dev = hwdev;
	struct cfg_mgmt_info *cfg_mgmt = NULL;
	struct cfg_eq_info *eq = NULL;
	u8 num_ceq;
	u8 i = 0;

	if (!hwdev || !dev->cfg_mgmt)
		return;

	cfg_mgmt = dev->cfg_mgmt;
	eq = &cfg_mgmt->eq_info;
	num_ceq = eq->num_ceq;

	mutex_lock(&eq->eq_mutex);

	for (i = 0; i < num_ceq; i++) {
		if (ceq_id == eq->eq[i].eqn && type == cfg_mgmt->eq_info.eq[i].type) {
			if (eq->eq[i].free != CFG_BUSY)
				continue;

			eq->eq[i].free = CFG_FREE;
			eq->num_ceq_remain++;
			if (eq->num_ceq_remain > num_ceq)
				eq->num_ceq_remain %= num_ceq;

			mutex_unlock(&eq->eq_mutex);
			return;
		}
	}

	if (i >= num_ceq)
		sdk_warn(dev->dev_hdl, "ceq %d don`t need to free.\n", ceq_id);

	mutex_unlock(&eq->eq_mutex);
}
EXPORT_SYMBOL(hinic5_free_ceq);

int hinic5_init_cfg_mgmt(struct hinic5_hwdev *dev)
{
	int err;
	struct cfg_mgmt_info *cfg_mgmt = NULL;

	cfg_mgmt = kzalloc(sizeof(*cfg_mgmt), GFP_KERNEL);
	if (!cfg_mgmt)
		return -ENOMEM;

	dev->cfg_mgmt = cfg_mgmt;
	cfg_mgmt->hwdev = dev;

	err = cfg_init_eq(dev);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to init cfg event queue, err: %d\n",
			err);
		goto free_mgmt_mem;
	}

	err = cfg_init_interrupt(dev);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to init cfg interrupt, err: %d\n",
			err);
		goto free_eq_mem;
	}

	err = cfg_enable_interrupt(dev);
	if (err != 0) {
		sdk_err(dev->dev_hdl, "Failed to enable cfg interrupt, err: %d\n",
			err);
		goto free_interrupt_mem;
	}

	return 0;

free_interrupt_mem:
	kfree(cfg_mgmt->irq_param_info.alloc_info);
	mutex_deinit(&((cfg_mgmt->irq_param_info).irq_mutex));
	cfg_mgmt->irq_param_info.alloc_info = NULL;

free_eq_mem:
	kfree(cfg_mgmt->eq_info.eq);
	mutex_deinit(&cfg_mgmt->eq_info.eq_mutex);
	cfg_mgmt->eq_info.eq = NULL;

free_mgmt_mem:
	kfree(cfg_mgmt);
	dev->cfg_mgmt = NULL;
	return err;
}

void hinic5_free_cfg_mgmt(struct hinic5_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;

	/* if the allocated resource were recycled */
	if (cfg_mgmt->irq_param_info.num_irq_remain !=
	    cfg_mgmt->irq_param_info.num_total ||
	    cfg_mgmt->eq_info.num_ceq_remain != cfg_mgmt->eq_info.num_ceq)
		sdk_err(dev->dev_hdl, "Can't reclaim all irq and event queue, please check\n");

	hinic5_adev_irq_vectors_free(dev->adapter_hdl);

	kfree(cfg_mgmt->irq_param_info.alloc_info);
	cfg_mgmt->irq_param_info.alloc_info = NULL;
	mutex_deinit(&((cfg_mgmt->irq_param_info).irq_mutex));

	if (cfg_mgmt->eq_info.num_ceq != 0) {
		kfree(cfg_mgmt->eq_info.eq);
		cfg_mgmt->eq_info.eq = NULL;
		mutex_deinit(&cfg_mgmt->eq_info.eq_mutex);
	}

	kfree(cfg_mgmt);
}

int hinic5_init_capability(struct hinic5_hwdev *dev)
{
	int err;
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;

	cfg_mgmt->svc_cap.sf_svc_attr.ft_pf_en = false;
	cfg_mgmt->svc_cap.sf_svc_attr.rdma_pf_en = false;

	err = hinic5_get_dev_cap(dev);
	if (err != 0)
		return err;

	init_service_param(dev);

	sdk_info(dev->dev_hdl, "Init capability success\n");
	return 0;
}

void hinic5_free_capability(struct hinic5_hwdev *dev)
{
	sdk_info(dev->dev_hdl, "Free capability success");
}

bool hinic5_support_nic(void *hwdev, struct nic_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_NIC_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.nic_cap,
		       sizeof(struct nic_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_nic);

bool hinic5_support_ppa(void *hwdev, struct ppa_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_PPA_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.ppa_cap,
		       sizeof(struct ppa_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_ppa);

bool hinic5_support_migr(void *hwdev, struct migr_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_MIGR_TYPE(dev) == 0)
		return false;

	if (cap)
		cap->master_host_id = dev->cfg_mgmt->svc_cap.master_host_id;

	return true;
}
EXPORT_SYMBOL(hinic5_support_migr);

bool hinic5_support_ipsec(void *hwdev, struct ipsec_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_IPSEC_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.ipsec_cap,
		       sizeof(struct ipsec_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_ipsec);

bool hinic5_support_macsec(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_MACSEC_TYPE(dev) == 0)
		return false;

	return true;
}
EXPORT_SYMBOL(hinic5_support_macsec);

bool hinic5_support_roce(void *hwdev, struct rdma_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_ROCE_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.rdma_cap,
		       sizeof(struct rdma_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_roce);

bool hinic5_support_fc(void *hwdev, struct fc_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_FC_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.fc_cap,
		       sizeof(struct fc_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_fc);

bool hinic5_support_rdma(void *hwdev, struct rdma_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_RDMA_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.rdma_cap,
		       sizeof(struct rdma_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_rdma);

bool hinic5_is_rdma_en(void *hwdev, struct rdma_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (!IS_RDMA_ENABLE(dev))
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.rdma_cap, sizeof(struct rdma_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_is_rdma_en);

bool hinic5_support_ovs(void *hwdev, struct ovs_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_OVS_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.ovs_cap,
		       sizeof(struct ovs_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_ovs);

bool hinic5_support_vbs(void *hwdev, struct vbs_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_VBS_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.vbs_cap,
		       sizeof(struct vbs_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_vbs);

/* Only PPF support it, PF is not */
bool hinic5_support_toe(void *hwdev, struct toe_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_TOE_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.toe_cap,
		       sizeof(struct toe_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_toe);

bool hinic5_support_ub(void *hwdev, struct ub_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_UB_TYPE(dev) == 0) {
		sdk_info(dev->dev_hdl, "dev not ub type\n");
		return false;
	}

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.ub_cap,
		       sizeof(struct ub_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_ub);

bool hinic5_support_jbof(void *hwdev, struct jbof_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_JBOF_TYPE(dev) == 0) {
		sdk_err(dev->dev_hdl, "dev not jbof type\n");
		return false;
	}

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.jbof_cap,
		       sizeof(struct jbof_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_jbof);

bool hinic5_support_vroce(void *hwdev, struct rdma_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_VROCE_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.rdma_cap,
		       sizeof(struct rdma_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_vroce);

bool hinic5_support_dmmu(void *hwdev, struct dmmu_service_cap *cap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_DMMU_TYPE(dev) == 0)
		return false;

	if (cap)
		memcpy(cap, &dev->cfg_mgmt->svc_cap.dmmu_cap,
		       sizeof(struct dmmu_service_cap));

	return true;
}
EXPORT_SYMBOL(hinic5_support_dmmu);

bool hinic5_support_bifur(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	return IS_BIFUR_TYPE(dev) != 0;
}
EXPORT_SYMBOL(hinic5_support_bifur);

bool hinic5_func_for_mgmt(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (dev->cfg_mgmt->svc_cap.chip_svc_type != 0)
		return false;
	else
		return true;
}

bool hinic5_support_hihtr(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	if (IS_HIHTR_TYPE(dev) == 0)
		return false;

	return true;
}
EXPORT_SYMBOL(hinic5_support_hihtr);

bool hinic5_get_stateful_enable(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return false;

	return dev->cfg_mgmt->svc_cap.sf_en;
}
EXPORT_SYMBOL(hinic5_get_stateful_enable);

u8 hinic5_host_oq_id_mask(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting host oq id mask\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.host_oq_id_mask_val;
}
EXPORT_SYMBOL(hinic5_host_oq_id_mask);

u8 hinic5_host_id(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting host id\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.host_id;
}
EXPORT_SYMBOL(hinic5_host_id);

u16 hinic5_host_total_func(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting host total function number\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.host_total_function;
}
EXPORT_SYMBOL(hinic5_host_total_func);

u16 hinic5_func_max_qnum(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting function max queue number\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.nic_cap.max_sqs;
}
EXPORT_SYMBOL(hinic5_func_max_qnum);

u16 hinic5_func_max_nic_qnum(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting function max queue number\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.nic_cap.max_sqs;
}
EXPORT_SYMBOL(hinic5_func_max_nic_qnum);

u8 hinic5_func_cos_mask_mode(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting function cos mask mode\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.cos_mask_mode;
}
EXPORT_SYMBOL(hinic5_func_cos_mask_mode);

u8 hinic5_func_dev_default_cos(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting function default cos\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.dcb_state.default_cos;
}
EXPORT_SYMBOL(hinic5_func_dev_default_cos);

u8 hinic5_ep_id(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting ep id\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.ep_id;
}
EXPORT_SYMBOL(hinic5_ep_id);

u8 hinic5_er_id(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting er id\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.er_id;
}
EXPORT_SYMBOL(hinic5_er_id);

u8 hinic5_physical_port_id(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting physical port id\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.port_id;
}
EXPORT_SYMBOL(hinic5_physical_port_id);

u16 hinic5_func_max_vf(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting max vf number\n");
		return 0;
	}
	return dev->cfg_mgmt->svc_cap.max_vf;
}
EXPORT_SYMBOL(hinic5_func_max_vf);

int hinic5_cos_valid_bitmap(void *hwdev, u8 *func_dft_cos, u8 *port_cos_bitmap)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev || !dev->cfg_mgmt) {
		pr_err("Hwdev pointer is NULL for getting cos valid bitmap\n");
		return 1;
	}
	*func_dft_cos = dev->cfg_mgmt->svc_cap.cos_valid_bitmap;
	*port_cos_bitmap = dev->cfg_mgmt->svc_cap.port_cos_valid_bitmap;

	return 0;
}
EXPORT_SYMBOL(hinic5_cos_valid_bitmap);

void hinic5_shutdown_hwdev(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return;

	if (IS_SLAVE_HOST(dev) != 0)
		hinic5_set_slave_host_enable(hwdev, hinic5_pcie_itf_id(hwdev), false);
}

u32 hinic5_host_pf_num(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting pf number capability\n");
		return 0;
	}

	return dev->cfg_mgmt->svc_cap.pf_num;
}
EXPORT_SYMBOL(hinic5_host_pf_num);

u32 hinic5_host_pf_id_start(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!dev) {
		pr_err("Hwdev pointer is NULL for getting pf id start capability\n");
		return 0;
	}

	return dev->cfg_mgmt->svc_cap.pf_id_start;
}
EXPORT_SYMBOL(hinic5_host_pf_id_start);

u8 hinic5_flexq_en(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev)
		return 0;

	return dev->cfg_mgmt->svc_cap.flexq_en;
}
EXPORT_SYMBOL(hinic5_flexq_en);

bool hinic5_support_htn(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;

	if (!hwdev) {
		pr_err("Hwdev pointer is NULL for getting HTN support capability\n");
		return false;
	}

	return COMM_SUPPORT_HTN_CMD(dev);
}
EXPORT_SYMBOL(hinic5_support_htn);

bool hinic5_is_vf_isolation(void *hwdev)
{
	struct hinic5_hwdev *dev = hwdev;
	struct service_cap *cap = NULL;

	if (unlikely(!dev || !dev->cfg_mgmt)) {
		pr_err("Hwdev pointer or cfg_mgmt is NULL\n");
		return false;
	}

	cap = &dev->cfg_mgmt->svc_cap;
	return cap->vf_isolation;
}
EXPORT_SYMBOL(hinic5_is_vf_isolation);

/**
 * Prototype    : hinic5_bat_get_l3i_entry_config
 * Description  : Gets L3I entry config corresponding to BAT register file.
 * Input        : const struct hinic5_hwdev *hwdev
 * Output       : struct hinic5_bat_entry_config *entry_config
 * Return Value : int
 * 1.Date : 2024/7/30
 *   Modification : Created function
 */
int hinic5_bat_get_l3i_entry_config(const struct hinic5_hwdev *hwdev,
				    struct hinic5_bat_entry_config *entry_config)
{
	struct hinic5_func_attr *func_attr = NULL;
	struct service_cap *svc_cap = NULL;
	enum func_type func_type;
	bool ft_enable;
	bool rdma_enable;

	if (!hwdev || !hwdev->hwif || !hwdev->cfg_mgmt || !entry_config)
		return -EINVAL;

	func_attr = &hwdev->hwif->attr;
	svc_cap   = &hwdev->cfg_mgmt->svc_cap;
	func_type = func_attr->func_type;
	ft_enable = svc_cap->sf_svc_attr.ft_en;
	rdma_enable = svc_cap->sf_svc_attr.rdma_en;

	if (func_type != TYPE_PF && func_type != TYPE_PPF) {
		entry_config->mapping          = false;
		entry_config->bat_entry_offset = 0;
		entry_config->bat_entry_size   = 0;
		return 0;
	}

	entry_config->mapping        = true;
	entry_config->bat_entry_size = HINIC5_BAT_ENTRY_SIZE;

	if (ft_enable && rdma_enable)
		entry_config->bat_entry_offset = HINIC5_BAT_L3I_OFF_FT_RDMA_PF;
	else if (ft_enable)
		entry_config->bat_entry_offset = HINIC5_BAT_L3I_OFF_FT_PF;
	else if (rdma_enable)
		entry_config->bat_entry_offset = HINIC5_BAT_L3I_OFF_RDMA_PF;
	else
		entry_config->bat_entry_offset = HINIC5_BAT_L3I_OFF_PF;

	return 0;
}

int hinic5_dcb_state_op(void *hwdev, enum hisdk5_dcb_state_op op,
			struct hisdk5_dcb_state *dcb_state)
{
	struct hinic5_hwdev *dev = hwdev;
	struct hisdk5_dcb_state *state = NULL;

	if (!dev || !dev->cfg_mgmt || !dcb_state) {
		pr_err("Hwdev pointer or dcb_state pointer is NULL\n");
		return -EINVAL;
	}

	state = &dev->cfg_mgmt->svc_cap.dcb_state;
	if (op == HISDK5_DCB_STATE_GET)
		memcpy(dcb_state, state, sizeof(struct hisdk5_dcb_state));
	else
		memcpy(state, dcb_state, sizeof(struct hisdk5_dcb_state));

	return 0;
}
EXPORT_SYMBOL(hinic5_dcb_state_op);

int hinic5_get_port_info(void *hwdev, struct mag_port_info *port_info, u16 channel)
{
	struct mag_cmd_get_port_info port_msg = { 0 };
	u16 out_size = sizeof(port_msg);
	int err;
	struct hinic5_hwdev *dev = hwdev;

	if (unlikely(!hwdev || !port_info))
		return -EINVAL;

	port_msg.port_id = hinic5_physical_port_id(hwdev);

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_HILINK, MAG_CMD_GET_PORT_INFO, &port_msg,
				      sizeof(port_msg),  &port_msg, &out_size, 0, channel);
	if (err != 0 || out_size == 0 || port_msg.head.status != 0) {
		sdk_err(dev->dev_hdl,
			"Failed to get port info, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, port_msg.head.status, out_size, channel);
		return -EIO;
	}

	port_info->autoneg_cap = port_msg.an_support;
	port_info->autoneg_state = port_msg.an_en;
	port_info->duplex = port_msg.duplex;
	port_info->port_type = port_msg.wire_type;
	port_info->speed = port_msg.speed;
	port_info->fec = port_msg.fec;
	port_info->supported_mode = port_msg.supported_mode;
	port_info->advertised_mode = port_msg.advertised_mode;
	port_info->supported_fec_mode = port_msg.supported_fec_mode;

	return 0;
}
EXPORT_SYMBOL(hinic5_get_port_info);

int hinic5_get_speed(void *hwdev, enum mag_cmd_port_speed *speed, u16 channel)
{
	struct mag_port_info port_info = {0};
	int err;

	if (unlikely(!hwdev || !speed))
		return -EINVAL;

	err = hinic5_get_port_info(hwdev, &port_info, channel);
	if (err != 0)
		return err;

	*speed = port_info.speed;

	return 0;
}
EXPORT_SYMBOL(hinic5_get_speed);
