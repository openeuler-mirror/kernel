// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd
#include <linux/module.h>
#include <linux/netdevice.h>
#include "hinic3_hw.h"
#include "hinic3_hw_cfg.h"
#include "hinic3_crm.h"

#include "hmm_comp.h"
#include "hinic3_hmm.h"

#define ROCE_MAX_RDMA_RC_EXTEND 384 /* 扩展表为12K */

u32 g_mtt_page_size;
module_param(g_mtt_page_size, uint, 0444);
MODULE_PARM_DESC(g_mtt_page_size, "0:4K,1:64K,2:2M,default:4K");

static int hmm_init_table(void *hwdev, struct hmm_comp_priv *comp_priv, u32 srv_type)
{
	int ret;

	ret = hmm_init_mtt_table(comp_priv);
	if (ret != 0) {
		pr_err("%s: Initialize mtt's table failed, ret(%d)\n", __func__, ret);
		kfree(comp_priv);
		return ret;
	}

	ret = hinic3_register_service_adapter((void *)hwdev, (void *)comp_priv,
		(enum hinic3_service_type)srv_type);
	if (ret != 0) {
		pr_err("%s: put hmm_comp_res failed, ret(%d)\n", __func__, ret);
		goto err_init;
	}
	pr_info("%s: Hmm init resource successful\n", __func__);
	return 0;

err_init:
	hmm_cleanup_mtt_table(comp_priv);
	kfree(comp_priv);
	return ret;
}

void hmm_cleanup_resource(void *hwdev, u32 service_type)
{
	struct rdma_service_cap rdma_cap;
	struct hmm_comp_priv *comp_priv = NULL;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return;
	}

	if (!hinic3_support_rdma(hwdev, &rdma_cap)) {
		pr_err("%s: Not support rdma service\n", __func__);
		return;
	}

	comp_priv = get_hmm_comp_priv(hwdev, service_type);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return;
	}

	hmm_cleanup_mtt_table(comp_priv);

	kfree(comp_priv);

	hinic3_unregister_service_adapter((void *)hwdev, (enum hinic3_service_type)service_type);

	pr_info("%s: Rdma cleanup resource successful", __func__);
}

int hmm_init_resource(void *hwdev, u32 service_type)
{
	struct hmm_comp_priv *comp_priv = NULL;
	struct rdma_service_cap rdma_cap;
	int ret;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return -EINVAL;
	}
	if (!hinic3_support_rdma(hwdev, &rdma_cap)) {
		pr_info("%s: Don't support hmm dev\n", __func__);
		return 0;
	}
	comp_priv = kzalloc(sizeof(struct hmm_comp_priv), GFP_KERNEL);
	if (comp_priv == NULL)
		return -ENOMEM;
	comp_priv->hwdev = hwdev;
	comp_priv->pdev = (struct pci_dev *)((struct hinic3_hwdev *)hwdev)->pcidev_hdl;
	comp_priv->rdma_cap.log_mtt = rdma_cap.log_mtt;
	comp_priv->rdma_cap.log_mtt_seg = rdma_cap.log_mtt_seg;
	comp_priv->rdma_cap.mtt_entry_sz = rdma_cap.mtt_entry_sz;
	comp_priv->rdma_cap.mpt_entry_sz = rdma_cap.mpt_entry_sz;
	comp_priv->rdma_cap.num_mtts = rdma_cap.num_mtts;

	comp_priv->rdma_cap.dmtt_cl_start = rdma_cap.dev_rdma_cap.roce_own_cap.dmtt_cl_start;
	comp_priv->rdma_cap.dmtt_cl_end = rdma_cap.dev_rdma_cap.roce_own_cap.dmtt_cl_end;
	comp_priv->rdma_cap.dmtt_cl_sz = rdma_cap.dev_rdma_cap.roce_own_cap.dmtt_cl_sz;

	switch (g_mtt_page_size) {
	case RDMA_MTT_PAGE_SIZE_4K:
		comp_priv->mtt_page_size = PAGE_SIZE_4k;   /* page size is 4K */
		comp_priv->mtt_page_shift = PAGE_SHIFT_4K; /* page size is 1 left shift 12 */
		break;
	case RDMA_MTT_PAGE_SIZE_64K:
		comp_priv->mtt_page_size = PAGE_SIZE_64k;   /* page size is 64K */
		comp_priv->mtt_page_shift = PAGE_SHIFT_64K; /* page size is 1 left shift 16 */
		break;
	case RDMA_MTT_PAGE_SIZE_2M:
		comp_priv->mtt_page_size = PAGE_SIZE_2M;   /* page size is 2M */
		comp_priv->mtt_page_shift = PAGE_SHIFT_2M; /* page size is 1 left shift 21 */
		break;
	default:
		comp_priv->mtt_page_size = PAGE_SIZE_4k;   /* page size is 4K */
		comp_priv->mtt_page_shift = PAGE_SHIFT_4K; /* page size is 1 left shift 12 */
		break;
	}
	ret = hmm_init_table(hwdev, comp_priv, service_type);
	return ret;
}
