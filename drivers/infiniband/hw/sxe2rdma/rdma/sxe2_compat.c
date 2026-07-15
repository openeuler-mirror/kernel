// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_compat.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/hugetlb_inline.h>
#include <linux/hugetlb.h>
#include <rdma/ib_verbs.h>

#include "sxe2_compat.h"
#include "sxe2_drv_main.h"
#include "sxe2_version.h"
#include "sxe2_drv_aux.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_db.h"
#include "sxe2_drv_stats.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_hw.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_device_port.h"
#include "sxe2_drv_cq.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_pd.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_qos.h"
#include "sxe2_drv_ah.h"
#include "sxe2_drv_io.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_srq.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_qos_debugfs.h"
#include "sxe2_drv_mc.h"
#include "sxe2_drv_rdma_inject.h"
#include "sxe2_drv_rdma_inject_debugfs.h"
#include "sxe2_drv_rdma_inject_reg.h"
#include "sxe2_drv_cc_debugfs.h"
#include "sxe2_drv_rdma_configfs.h"

#ifdef HAVE_NO_IB_DEVICE_OPS
void sxe2_set_device_ops(struct ib_device *dev_ops)
{
	dev_ops->uverbs_abi_ver = 1;
	dev_ops->driver_id = RDMA_DRIVER_SXE2;
	dev_ops->owner = THIS_MODULE;

	dev_ops->alloc_ucontext   = sxe2_rdma_kalloc_ucontext;
	dev_ops->dealloc_ucontext = sxe2_rdma_kdealloc_ucontext;
	dev_ops->query_device	  = sxe2_rdma_kquery_device;
	dev_ops->query_port   = sxe2_rdma_kquery_port;
	dev_ops->query_gid	  = sxe2_rdma_kquery_gid;
	dev_ops->get_link_layer   = sxe2_rdma_kget_link_layer;
	dev_ops->query_pkey   = sxe2_query_pkey;
	dev_ops->get_dev_fw_str   = sxe2_rdma_kget_dev_fw_str;
#ifndef CREATE_AH_NOT_SUPPORT
	dev_ops->create_user_ah = sxe2_kcreate_ah;
#endif
	dev_ops->create_ah	   = sxe2_kcreate_ah;
	dev_ops->query_ah	   = sxe2_kquery_ah;
	dev_ops->destroy_ah    = sxe2_kdestroy_ah;
	dev_ops->alloc_mr	   = sxe2_kalloc_mr;
	dev_ops->reg_user_mr   = sxe2_kreg_user_mr;
	dev_ops->rereg_user_mr = sxe2_krereg_user_mr;
	dev_ops->get_dma_mr    = sxe2_kget_dma_mr;
	dev_ops->dereg_mr	   = sxe2_kdereg_mr;
#ifndef REG_USER_MR_DMABUF_VER_1
	dev_ops->reg_user_mr_dmabuf = sxe2_kreg_user_mr_dmabuf;
#endif
	dev_ops->poll_cq		= sxe2_kpoll_cq;
	dev_ops->post_recv		= sxe2_kpost_recv;
	dev_ops->post_send		= sxe2_kpost_send;
	dev_ops->post_srq_recv		= sxe2_kpost_srq_recv;
	dev_ops->req_notify_cq		= sxe2_kreq_notify_cq;
	dev_ops->map_mr_sg		= sxe2_kmap_mr_sg;
	dev_ops->get_port_immutable = sxe2_kget_port_immutable;
	dev_ops->create_qp		= sxe2_kcreate_qp;
	dev_ops->destroy_qp		= sxe2_kdestroy_qp;
	dev_ops->modify_qp		= sxe2_kmodify_qp;
	dev_ops->query_qp		= sxe2_kquery_qp;
	dev_ops->create_srq		= sxe2_kcreate_srq;
	dev_ops->modify_srq		= sxe2_kmodify_srq;
	dev_ops->query_srq		= sxe2_kquery_srq;
	dev_ops->destroy_srq		= sxe2_kdestroy_srq;
#ifdef ALLOC_HW_STATS_V1
	dev_ops->alloc_hw_stats = sxe2_kalloc_hw_port_stats;
#else
	dev_ops->alloc_hw_port_stats = sxe2_kalloc_hw_port_stats;
#endif
	dev_ops->get_hw_stats = sxe2_kget_hw_stats;
	dev_ops->mmap		  = sxe2_kmmap;
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	dev_ops->mmap_free = sxe2_kmmap_free;
#endif
	dev_ops->alloc_pd		   = sxe2_kalloc_pd;
	dev_ops->dealloc_pd		   = sxe2_kdealloc_pd;
	dev_ops->create_cq		   = sxe2_kcreate_cq;
	dev_ops->modify_cq		   = sxe2_kmodify_cq;
	dev_ops->destroy_cq		   = sxe2_kdestroy_cq;
	dev_ops->modify_port	   = sxe2_rdma_kmodify_port;
	dev_ops->get_netdev		   = sxe2_rdma_kget_net_dev;
	dev_ops->disassociate_ucontext = sxe2_rdma_disassociate_ucontext;
	dev_ops->attach_mcast		   = sxe2_kattach_mcast;
	dev_ops->detach_mcast		   = sxe2_kdetach_mcast;
}
#endif

#ifdef NEED_RDMA_MMAP_IO
static void sxe2_vma_open(struct vm_area_struct *vma)
{
	vma->vm_ops = NULL;
}

static void sxe2_vma_close(struct vm_area_struct *vma)
{
	struct sxe2_vma_data *vma_data;

	vma_data = vma->vm_private_data;
	vma->vm_private_data = NULL;
	vma_data->vma = NULL;
	mutex_lock(vma_data->vma_list_mutex);
	list_del(&vma_data->list);
	mutex_unlock(vma_data->vma_list_mutex);
	kfree(vma_data);
}

static const struct vm_operations_struct sxe2_vm_ops = {
	.open = sxe2_vma_open,
	.close = sxe2_vma_close
};

static int sxe2_set_vma_data(struct vm_area_struct *vma,
			      struct sxe2_rdma_kcontext *context)
{
	struct list_head *vma_head = &context->vma_list;
	struct sxe2_vma_data *vma_entry;

	vma_entry = kzalloc(sizeof(*vma_entry), GFP_KERNEL);
	if (!vma_entry)
		return -ENOMEM;

	vma->vm_private_data = vma_entry;
	vma->vm_ops = &sxe2_vm_ops;

	vma_entry->vma = vma;
	vma_entry->vma_list_mutex = &context->vma_list_mutex;

	mutex_lock(&context->vma_list_mutex);
	list_add(&vma_entry->list, vma_head);
	mutex_unlock(&context->vma_list_mutex);

	return 0;
}

int rdma_user_mmap_io(struct ib_ucontext *context, struct vm_area_struct *vma,
		      unsigned long pfn, unsigned long size, pgprot_t prot)
{
	struct sxe2_rdma_kcontext *kcontext = ibuctxto_kctx(context);

	if (io_remap_pfn_range(vma, vma->vm_start, pfn, size, prot))
		return -EAGAIN;

	return sxe2_set_vma_data(vma, kcontext);
}
#endif

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
u64 sxe2_set_best_pagesz(u64 addr, struct ib_umem *region, u64 page_size_cap)
{
	struct vm_area_struct *vma;
	struct hstate *h;

	if (!region->hugetlb)
		return PAGE_SIZE;

	vma = find_vma(current->mm, addr);
	if (vma && is_vm_hugetlb_page(vma)) {
		h = hstate_vma(vma);
		if ((huge_page_size(h) == SZ_2M && (page_size_cap & SZ_2M)) ||
		    (huge_page_size(h) == SZ_1G && (page_size_cap & SZ_1G))) {
			return huge_page_size(h);
		}
	}
	return PAGE_SIZE;
}
#endif

#ifdef HAVE_NO_GET_CONST
int _uverbs_get_const(s64 *to, const struct uverbs_attr_bundle *attrs_bundle,
		      size_t idx, s64 lower_bound, u64 upper_bound,
		      s64  *def_val)
{
	const struct uverbs_attr *attr;

	attr = uverbs_attr_get(attrs_bundle, idx);
	if (IS_ERR(attr)) {
		if ((PTR_ERR(attr) != -ENOENT) || !def_val)
			return PTR_ERR(attr);

		*to = *def_val;
	} else {
		*to = attr->ptr_attr.data;
	}

	if (*to < lower_bound || (*to > 0 && (u64)*to > upper_bound))
		return -EINVAL;

	return 0;
}
#endif
