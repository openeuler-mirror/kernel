// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_device_port.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_device_port.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_db.h"
#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/netdevice.h>
#include <rdma/ib_mad.h>
#include <net/addrconf.h>

#ifdef NEED_KALLOC_UCONTEXT_V1
struct ib_ucontext *sxe2_rdma_kalloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev	  = to_dev(ibdev);
	struct sxe2_rdma_pci_f *rdma_func	  = rdma_dev->rdma_func;
	struct sxe2_alloc_ucontext_req req	  = {};
	struct sxe2_alloc_ucontext_resp uresp = {};
	struct sxe2_rdma_kcontext *ucontext   = NULL;
	struct sxe2_common_attrs *uk_attrs =
		&rdma_dev->rdma_func->ctx_dev.hw_attrs.uk_attrs;
	struct sxe2_db_ucontext *db_ucontext_entry = NULL;

	DRV_RDMA_LOG_DEV_DEBUG(
		"device:kalloc uctx start inlen=%zu outlen=%zu\n", udata->inlen,
		udata->outlen);
	DRV_RDMA_LOG_DEV_DEBUG("device:inlen min=%zu outlen min=%zu\n",
				   SXE2_ALLOC_UCTX_MIN_REQ_LEN,
				   SXE2_ALLOC_UCTX_MIN_RESP_LEN);
	if (udata->inlen < SXE2_ALLOC_UCTX_MIN_REQ_LEN ||
		udata->outlen < SXE2_ALLOC_UCTX_MIN_RESP_LEN) {
		DRV_RDMA_LOG_DEV_ERR(
			"device:inlen or out len size err inlen=%zu outlen=%zu\n",
			udata->inlen, udata->outlen);
		ret = -EINVAL;
		goto end;
	}
	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen))) {
		DRV_RDMA_LOG_DEV_ERR("device:copy from udata err\n");
		ret = -EINVAL;
		goto end;
	}
	if (req.userspace_ver < SXE2_MIN_USER_SPACE_VER ||
		req.userspace_ver > SXE2_MAX_USER_SPACE_VER) {
		DRV_RDMA_LOG_DEV_ERR("device:user space ver %u err\n",
					 req.userspace_ver);
		ret = -EINVAL;
		goto end;
	}

	ucontext = kzalloc(sizeof(*ucontext), GFP_KERNEL);
	if (!ucontext) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("ucontext kzalloc failed\n");
		goto end;
	}

	INIT_LIST_HEAD(&ucontext->vma_list);
	mutex_init(&ucontext->vma_list_mutex);

	ucontext->rdma_dev = rdma_dev;
	ucontext->ibucontext.device = ibdev;
	ucontext->abi_ver  = req.userspace_ver;
	DRV_RDMA_LOG_DEV_DEBUG("device:rdma dev=%p	userspace ver=%u\n",
				   ucontext->rdma_dev, ucontext->abi_ver);
	if (udata->outlen == SXE2_ALLOC_UCTX_MIN_RESP_LEN) {
		uresp.max_qps = rdma_dev->rdma_func->max_qp;
		uresp.max_pds =
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_hw_pds;
		uresp.wq_size =
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_qp_wr * 2;
		uresp.kernel_ver = req.userspace_ver;
		if (ib_copy_to_udata(udata, &uresp,
					 min(sizeof(uresp), udata->outlen))) {
			DRV_RDMA_LOG_DEV_ERR("device:copy from udata err\n");
			ret = -EFAULT;
			goto end;
		}
	} else {
		uresp.kernel_ver	= SXE2_RDMA_ABI_VER;
		uresp.feature_flags = uk_attrs->feature_flags;
		uresp.max_hw_wq_frags	= uk_attrs->max_hw_wq_frags;
		uresp.max_hw_read_sges	= uk_attrs->max_hw_read_sges;
		uresp.max_hw_inline = uk_attrs->max_hw_inline;
		uresp.max_hw_rq_quanta	= uk_attrs->max_hw_rq_quanta;
		uresp.max_hw_wq_quanta	= uk_attrs->max_hw_wq_quanta;
		uresp.max_hw_sq_chunk	= uk_attrs->max_hw_sq_chunk;
		uresp.max_hw_cq_size	= uk_attrs->max_hw_cq_size;
		uresp.min_hw_cq_size	= uk_attrs->min_hw_cq_size;
		uresp.hw_rev		= uk_attrs->hw_rev;
		uresp.min_hw_wq_size	= uk_attrs->min_hw_wq_size;
		uresp.max_hw_srq_quanta = uk_attrs->max_hw_srq_quanta;
		uresp.max_hw_srq_wr = uk_attrs->max_hw_srq_wr;
		uresp.comp_mask |= SXE2_ALLOC_UCTX_MIN_HW_WQ_SIZE;
		DRV_RDMA_LOG_DEV_DEBUG(
			"device:max hw wq frages=%u min hw wq size=%u\n",
			uresp.max_hw_wq_frags, uresp.min_hw_wq_size);
		strscpy(uresp.bdf, rdma_dev->bdf, sizeof(uresp.bdf) - 1);
		uresp.max_db = (__u32)sxe2_ucount_bitmap_zero_bits(
			rdma_func->allocated_dbs, rdma_func->max_dbs);
		uresp.is_pf = (__u8)rdma_dev->rdma_func->ftype ?
					  SXE2_UCTX_IS_VF :
					  SXE2_UCTX_IS_PF;
		spin_lock_init(&ucontext->mmap_tbl_lock);
		ucontext->db_mmap_entry = rdma_user_mmap_entry_add_hash(
			ucontext, SXE2_DRV_DB_MMAP_TYPE_NC, &uresp.db_mmap_key);

		if (!ucontext->db_mmap_entry) {
			DRV_RDMA_LOG_DEV_ERR(
				"device:db insert user mmap entry err\n");
			ret = -ENOMEM;
			goto end;
		}
		if (ib_copy_to_udata(udata, &uresp,
					 min(sizeof(uresp), udata->outlen))) {
			DRV_RDMA_LOG_DEV_ERR("device:copy from udata err\n");
			ret = -EFAULT;
			goto free_mmap_entry;
		}
	}
	INIT_LIST_HEAD(&ucontext->cq_reg_mem_list);
	spin_lock_init(&ucontext->cq_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->qp_reg_mem_list);
	spin_lock_init(&ucontext->qp_reg_mem_list_lock);
	db_ucontext_entry = kzalloc(sizeof(*db_ucontext_entry), GFP_KERNEL);
	if (!db_ucontext_entry) {
		DRV_RDMA_LOG_DEV_ERR(
				"device:db alloc db ucontext entry failed.\n");
			ret = -ENOMEM;
			goto free_mmap_entry;
	}
	INIT_LIST_HEAD(&db_ucontext_entry->db_pageid_list);
	INIT_LIST_HEAD(&db_ucontext_entry->entry_list);
	db_ucontext_entry->ibucontext = &ucontext->ibucontext;
	mutex_lock(&rdma_func->db_mmap_entry_head.lock);
	list_add_tail(&db_ucontext_entry->list, &rdma_func->db_mmap_entry_head.list);
	mutex_unlock(&rdma_func->db_mmap_entry_head.lock);
	goto end;
free_mmap_entry:
	rdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
end:
	return ret ? ERR_PTR(ret) : &ucontext->ibucontext;
}
#else
int sxe2_rdma_kalloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	int ret				      = SXE2_OK;
	struct ib_device *ibdev		      = uctx->device;
	struct sxe2_rdma_device *rdma_dev     = to_dev(ibdev);
	struct sxe2_rdma_pci_f *rdma_func     = rdma_dev->rdma_func;
	struct sxe2_alloc_ucontext_req req    = {};
	struct sxe2_alloc_ucontext_resp uresp = {};
	struct sxe2_rdma_kcontext *ucontext   = ibuctxto_kctx(uctx);
	struct sxe2_common_attrs *uk_attrs =
		&rdma_dev->rdma_func->ctx_dev.hw_attrs.uk_attrs;
	struct sxe2_db_ucontext *db_ucontext_entry = NULL;

	DRV_RDMA_LOG_DEV_DEBUG(
		"device:kalloc uctx start inlen=%zu outlen=%zu\n", udata->inlen,
		udata->outlen);
	DRV_RDMA_LOG_DEV_DEBUG("device:inlen min=%zu outlen min=%zu\n",
			       SXE2_ALLOC_UCTX_MIN_REQ_LEN,
			       SXE2_ALLOC_UCTX_MIN_RESP_LEN);
	if (udata->inlen < SXE2_ALLOC_UCTX_MIN_REQ_LEN ||
	    udata->outlen < SXE2_ALLOC_UCTX_MIN_RESP_LEN) {
		DRV_RDMA_LOG_DEV_ERR(
			"device:inlen or out len size err inlen=%zu outlen=%zu\n",
			udata->inlen, udata->outlen);
		ret = -EINVAL;
		goto end;
	}
	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen))) {
		DRV_RDMA_LOG_DEV_ERR("device:copy from udata err\n");
		ret = -EINVAL;
		goto end;
	}
	if (req.userspace_ver < SXE2_MIN_USER_SPACE_VER ||
	    req.userspace_ver > SXE2_MAX_USER_SPACE_VER) {
		DRV_RDMA_LOG_DEV_ERR("device:user space ver %u err\n",
				     req.userspace_ver);
		ret = -EINVAL;
		goto end;
	}
	ucontext->rdma_dev = rdma_dev;
	ucontext->abi_ver  = req.userspace_ver;
	DRV_RDMA_LOG_DEV_DEBUG("device:rdma dev=%p  userspace ver=%u\n",
			       ucontext->rdma_dev, ucontext->abi_ver);
	if (udata->outlen == SXE2_ALLOC_UCTX_MIN_RESP_LEN) {
		uresp.max_qps = rdma_dev->rdma_func->max_qp;
		uresp.max_pds =
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_hw_pds;
		uresp.wq_size =
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_qp_wr * 2;
		uresp.kernel_ver = req.userspace_ver;
		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
			DRV_RDMA_LOG_DEV_ERR("device:copy from udata err\n");
			ret = -EFAULT;
			goto end;
		}
	} else {
		uresp.kernel_ver	= SXE2_RDMA_ABI_VER;
		uresp.feature_flags	= uk_attrs->feature_flags;
		uresp.max_hw_wq_frags	= uk_attrs->max_hw_wq_frags;
		uresp.max_hw_read_sges	= uk_attrs->max_hw_read_sges;
		uresp.max_hw_inline	= uk_attrs->max_hw_inline;
		uresp.max_hw_rq_quanta	= uk_attrs->max_hw_rq_quanta;
		uresp.max_hw_wq_quanta	= uk_attrs->max_hw_wq_quanta;
		uresp.max_hw_sq_chunk	= uk_attrs->max_hw_sq_chunk;
		uresp.max_hw_cq_size	= uk_attrs->max_hw_cq_size;
		uresp.min_hw_cq_size	= uk_attrs->min_hw_cq_size;
		uresp.hw_rev		= uk_attrs->hw_rev;
		uresp.min_hw_wq_size	= uk_attrs->min_hw_wq_size;
		uresp.max_hw_srq_quanta = uk_attrs->max_hw_srq_quanta;
		uresp.max_hw_srq_wr	= uk_attrs->max_hw_srq_wr;
		uresp.comp_mask |= SXE2_ALLOC_UCTX_MIN_HW_WQ_SIZE;
		DRV_RDMA_LOG_DEV_DEBUG(
			"device:max hw wq frages=%u min hw wq size=%u\n",
			uresp.max_hw_wq_frags, uresp.min_hw_wq_size);
		strscpy(uresp.bdf, rdma_dev->bdf, sizeof(uresp.bdf) - 1);
		uresp.max_db = (__u32)sxe2_ucount_bitmap_zero_bits(
			rdma_func->allocated_dbs, rdma_func->max_dbs);
		uresp.is_pf = (__u8)rdma_dev->rdma_func->ftype ?
				      SXE2_UCTX_IS_VF :
				      SXE2_UCTX_IS_PF;
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
		ucontext->db_mmap_entry = sxe2_kinsert_user_mmap_entry(
			ucontext, SXE2_DRV_DB_MMAP_TYPE_NC, &uresp.db_mmap_key);
#else
		spin_lock_init(&ucontext->mmap_tbl_lock);
		ucontext->db_mmap_entry = rdma_user_mmap_entry_add_hash(
			ucontext, SXE2_DRV_DB_MMAP_TYPE_NC, &uresp.db_mmap_key);
#endif

		if (!ucontext->db_mmap_entry) {
			DRV_RDMA_LOG_DEV_ERR(
				"device:db insert user mmap entry err\n");
			ret = -ENOMEM;
			goto end;
		}
		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
			DRV_RDMA_LOG_DEV_ERR("device:copy from udata err\n");
			ret = -EFAULT;
			goto free_mmap_entry;
		}
	}
	INIT_LIST_HEAD(&ucontext->cq_reg_mem_list);
	spin_lock_init(&ucontext->cq_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->qp_reg_mem_list);
	spin_lock_init(&ucontext->qp_reg_mem_list_lock);
	db_ucontext_entry = kzalloc(sizeof(*db_ucontext_entry), GFP_KERNEL);
	if (!db_ucontext_entry) {
		DRV_RDMA_LOG_DEV_ERR(
				"device:db alloc db ucontext entry failed.\n");
			ret = -ENOMEM;
			goto free_mmap_entry;
	}
	INIT_LIST_HEAD(&db_ucontext_entry->db_pageid_list);
	INIT_LIST_HEAD(&db_ucontext_entry->entry_list);
	db_ucontext_entry->ibucontext = uctx;
	mutex_lock(&rdma_func->db_mmap_entry_head.lock);
	list_add_tail(&db_ucontext_entry->list, &rdma_func->db_mmap_entry_head.list);
	mutex_unlock(&rdma_func->db_mmap_entry_head.lock);
	goto end;

free_mmap_entry:
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#else
	rdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
#endif
end:
	return ret;
}
#endif

#ifdef DEVICE_OPS_V1
int sxe2_rdma_kdealloc_ucontext(struct ib_ucontext *uctx)
#else
void sxe2_rdma_kdealloc_ucontext(struct ib_ucontext *uctx)
#endif
{
	struct sxe2_rdma_kcontext *ucontext = ibuctxto_kctx(uctx);
	struct ib_device *ibdev		    = uctx->device;
	struct sxe2_rdma_device *rdma_dev   = to_dev(ibdev);
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct sxe2_db_ucontext *db_ucontext_entry;
	struct sxe2_db_ucontext *uconetxt_next;
	struct sxe2_db_mmap_entry *db_mmap_entry;
	struct sxe2_db_mmap_entry *entry_next;
	struct sxe2_db_page_idx *db_page_idx_entry;
	struct sxe2_db_page_idx *idx_entry_next;

	DRV_RDMA_LOG_DEV_DEBUG("device:dealloc uncontext start\n");
	mutex_lock(&rdma_func->db_mmap_entry_head.lock);

	list_for_each_entry_safe(db_ucontext_entry,
		uconetxt_next, &rdma_func->db_mmap_entry_head.list, list) {
		if (db_ucontext_entry->ibucontext == uctx) {
			list_for_each_entry_safe(db_page_idx_entry, idx_entry_next,
				&db_ucontext_entry->db_pageid_list, list) {
				sxe2_kfree_rsrc(rdma_func, rdma_func->allocated_dbs,
					db_page_idx_entry->db_page_idx);
				list_del(&db_page_idx_entry->list);
				kfree(db_page_idx_entry);
				db_page_idx_entry = NULL;
			}
			list_for_each_entry_safe(db_mmap_entry,
				entry_next, &db_ucontext_entry->entry_list, list) {
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
				rdma_user_mmap_entry_remove(db_mmap_entry->mmap_entry);
#else
				rdma_user_mmap_entry_del_hash(db_mmap_entry->mmap_entry);
#endif
				list_del(&db_mmap_entry->list);
				kfree(db_mmap_entry);
				db_mmap_entry = NULL;
			}
			list_del(&db_ucontext_entry->list);
			kfree(db_ucontext_entry);
			db_ucontext_entry = NULL;
		}
	}
	mutex_unlock(&rdma_func->db_mmap_entry_head.lock);
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#else
	rdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
#endif
	DRV_RDMA_LOG_DEV_DEBUG("device:dealloc uncontext finish\n");
#ifdef DEVICE_OPS_V1
	return 0;
#endif
}

int sxe2_rdma_kquery_device(struct ib_device *ibdev,
			    struct ib_device_attr *props,
			    struct ib_udata *udata)
{
	int ret				    = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev   = to_dev(ibdev);
	struct sxe2_rdma_pci_f *rdma_func   = rdma_dev->rdma_func;
	struct pci_dev *pcidev		    = rdma_dev->rdma_func->pcidev;
	struct sxe2_rdma_hw_attrs *hw_attrs = &rdma_func->ctx_dev.hw_attrs;

	if (udata->inlen || udata->outlen) {
		DRV_RDMA_LOG_DEV_ERR(
			"device:kquery device inlen or out len err\n");
		ret = -EINVAL;
		goto end;
	}
	memset(props, 0, sizeof(*props));
	addrconf_addr_eui48((u8 *)&props->sys_image_guid,
			    rdma_dev->netdev->dev_addr);
	props->fw_ver = (u64)rdma_func->ctx_dev.fw_ver;
	props->device_cap_flags =
		IB_DEVICE_MEM_MGT_EXTENSIONS | IB_DEVICE_RC_RNR_NAK_GEN;
	props->vendor_id      = pcidev->vendor;
	props->vendor_part_id = pcidev->device;
	props->hw_ver	      = pcidev->revision;
	props->page_size_cap  = hw_attrs->page_size_cap;
	props->max_mr_size    = hw_attrs->max_mr_size;
	props->max_qp	      = (s32)(rdma_func->max_qp - SXE2_QP_USED_NUM);
	props->max_qp_wr      = (s32)hw_attrs->max_qp_wr;
	set_max_sge(props, rdma_func);
	props->max_cq	  = (s32)(rdma_func->max_cq - SXE2_CQ_USED_NUM);
	props->max_cqe	  = (s32)(rdma_func->max_cqe - 1);
	props->max_mr	  = (s32)(rdma_func->max_mr - SXE2_MR_USED_NUM);
	props->max_mw	  = 0;
	props->max_pd	  = (s32)(rdma_func->max_pd - SXE2_PD_USED_NUM);
	props->max_sge_rd = (s32)hw_attrs->uk_attrs.max_hw_read_sges;
	props->max_qp_rd_atom	   = (s32)hw_attrs->max_rra;
	props->max_qp_init_rd_atom = hw_attrs->max_sra;
	props->max_pkeys	   = SXE2_PKEY_TBL_SZ;
	props->max_ah		   = (s32)rdma_func->max_ah - SXE2_AH_USED_NUM;
	props->max_mcast_grp	   = SXE2_MAX_MCGS;
	props->max_mcast_qp_attach = SXE2_MAX_QPS_PER_MGN;
	props->max_total_mcast_qp_attach =
		(SXE2_MAX_MCGS * SXE2_MAX_QPS_PER_MGN);
	props->max_fast_reg_page_list_len = SXE2_MAX_PAGES_PER_FMR;

	props->max_srq	   = (s32)(rdma_func->max_srq - rdma_func->used_srqs);
	props->max_srq_wr  = SXE2_MAX_SRQ_WRS;
	props->max_srq_sge = (s32)hw_attrs->uk_attrs.max_hw_wq_frags;

	props->timestamp_mask = GENMASK(31, 0);
	props->hca_core_clock = SXE2_HCA_CORE_CLOCK_KHZ;

	props->cq_caps.max_cq_moderation_count	= SXE2_MAX_CQ_MODERATION_COUNT;
	props->cq_caps.max_cq_moderation_period = SXE2_MAX_CQ_MODERATION_PERIOD;
end:
	return ret;
}

#ifdef QUERY_PORT_V1
int sxe2_rdma_kquery_port(struct ib_device *ibdev, u8 port,
			  struct ib_port_attr *props)

#else
int sxe2_rdma_kquery_port(struct ib_device *ibdev, u32 port,
			  struct ib_port_attr *props)
#endif
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);
	struct net_device *netdev	  = rdma_dev->netdev;
	enum ib_mtu ndev_ib_mtu;

	props->max_mtu	  = IB_MTU_4096;
	ndev_ib_mtu	  = sxe2_iboe_get_mtu((int)netdev->mtu);
	props->active_mtu = min(props->max_mtu, ndev_ib_mtu);

	props->lid    = 1;
	props->lmc    = 0;
	props->sm_lid = 0;
	props->sm_sl  = 0;
	if (netif_carrier_ok(netdev) && netif_running(netdev)) {
		props->state	  = IB_PORT_ACTIVE;
		props->phys_state = SXE2_PORT_PHYS_STATE_LINK_UP;
	} else {
		props->state	  = IB_PORT_DOWN;
		props->phys_state = SXE2_PORT_PHYS_STATE_DISABLED;
	}
	ib_get_eth_speed(ibdev, port, &props->active_speed,
			 &props->active_width);
	props->gid_tbl_len = SXE2_GID_TABLE_LEN;
	kc_set_props_ip_gid_caps(props);
	props->pkey_tbl_len   = SXE2_PKEY_TBL_SZ;
	props->qkey_viol_cntr = 0;
	props->port_cap_flags |= IB_PORT_CM_SUP | IB_PORT_REINIT_SUP;
	props->max_msg_sz = (u32)rdma_dev->rdma_func->ctx_dev.hw_attrs
				    .max_hw_outbound_msg_size;
	return SXE2_OK;
}

void sxe2_rdma_kget_dev_fw_str(struct ib_device *ibdev, char *str)
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);
	struct sxe2_rdma_ctx_dev *dev = &rdma_dev->rdma_func->ctx_dev;

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%u.%u.%u.%u",
		dev->feature_info[SXE2_RDMA_FW_MAIN_VERSION],
		dev->feature_info[SXE2_RDMA_FW_SUB_VERSION],
		dev->feature_info[SXE2_RDMA_FW_FIX_VERSION],
		dev->feature_info[SXE2_RDMA_FW_BUILD_NUMBER]);
}

#ifdef QUERY_GID_ROCE_V1
int sxe2_rdma_kquery_gid(struct ib_device *ibdev, u8 port, int index,
			 union ib_gid *gid)
#else
int sxe2_rdma_kquery_gid(struct ib_device *ibdev, u32 port, int index,
			 union ib_gid *gid)
#endif
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);

	memset(gid->raw, 0, sizeof(gid->raw));
	ether_addr_copy(gid->raw, rdma_dev->netdev->dev_addr);

	return ret;
}

#ifdef GET_LINK_LAYER_V1
enum rdma_link_layer sxe2_rdma_kget_link_layer(struct ib_device *ibdev,
					       u8 port_num)
#else
enum rdma_link_layer sxe2_rdma_kget_link_layer(struct ib_device *ibdev,
					       u32 port_num)
#endif
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef GET_NETDEV_OP_V1
struct net_device *sxe2_rdma_kget_net_dev(struct ib_device *ibdev, u8 port_num)
#else
struct net_device *sxe2_rdma_kget_net_dev(struct ib_device *ibdev, u32 port_num)
#endif
{
	struct net_device *net_dev	  = NULL;
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);

	if (rdma_dev->netdev) {
		net_dev = rdma_dev->netdev;
		dev_hold(net_dev);
	}

	return net_dev;
}

#ifdef MODIFY_PORT_V1
int sxe2_rdma_kmodify_port(struct ib_device *ibdev, u8 port, int mask,
			   struct ib_port_modify *props)
#else
int sxe2_rdma_kmodify_port(struct ib_device *ibdev, u32 port, int mask,
			   struct ib_port_modify *props)
#endif
{
	int ret = SXE2_OK;

	if (port > 1)
		ret = -EINVAL;

	return ret;
}
#ifdef ROCE_PORT_IMMUTABLE_V1
int sxe2_kget_port_immutable(struct ib_device *ibdev, u8 port_num,
			     struct ib_port_immutable *immutable)
#else
int sxe2_kget_port_immutable(struct ib_device *ibdev, u32 port_num,
				    struct ib_port_immutable *immutable)
#endif
{
	struct ib_port_attr attr;
	int err;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	err			  = ib_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len	= attr.gid_tbl_len;

	return 0;
}

