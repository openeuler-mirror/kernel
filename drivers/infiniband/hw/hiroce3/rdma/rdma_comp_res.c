// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "rdma_comp.h"
#include "hmm_em.h"
#include "hmm_buddy.h"

static int rdma_check_map_param(const void *hwdev, const struct rdma_fmr *fmr,
	const u64 *page_list, int npages,
	u64 iova)
{
	u32 page_mask = 0;

	if ((hwdev == NULL) || (fmr == NULL) || (page_list == NULL)) {
		pr_err("%s: Hwdev or fmr or page_list is null\n", __func__);
		return -EINVAL;
	}

	if ((u32)npages > fmr->max_pages) {
		pr_err("%s: Npages is bigger than fmr->max_pages, ret(%d)\n",
			__func__, -EINVAL);
		return -EINVAL;
	}

	page_mask = (1U << fmr->page_shift) - 1;
	if ((iova & (u64)page_mask) != 0) {
		pr_err("%s: Iova isn't page aligned, ret(%d)\n", __func__, -EINVAL);
		return -EINVAL;
	}

	if (fmr->maps >= fmr->max_maps) {
		pr_err("%s: Maps over range(fmr->max_maps), ret(%d)\n", __func__, -EINVAL);
		return -EINVAL;
	}

	return 0;
}

int roce3_rdma_map_phys_fmr(void *hwdev, struct rdma_fmr *fmr, u64 *page_list,
	int npages, u64 iova, u32 service_type)
{
	__be64 *mtt_vaddr = NULL;
	struct rdma_comp_priv *comp_priv = NULL;
	int ret = 0;
	int i = 0;
	u32 mpt_index = 0;
	u64 length = 0;
	u32 new_key = 0;
	u64 iova_tmp = iova;
	u16 sign_val = 0;

	ret = rdma_check_map_param(hwdev, fmr, page_list, npages, iova_tmp);
	if (ret != 0) {
		pr_err("%s: Rdma check map param failed\n", __func__);
		return ret;
	}
	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	fmr->mr.enabled = RDMA_MPT_EN_SW;
	mpt_index = fmr->mr.mpt.mpt_index;
	length = (u64)((unsigned int)npages * (1UL << fmr->page_shift));
	if ((fmr->mr.access & RDMA_IB_ACCESS_ZERO_BASED) != 0)
		iova_tmp = 0;

	new_key = (fmr->mr.key & (~0xFF)) | ((fmr->mr.key + 1) & 0xFF);
	ret = hmm_modify_roce_mpt(hwdev, mpt_index, new_key, length, iova_tmp, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("%s: Modify mpt failed, ret(%d), new_key(%d)\n", __func__, ret, new_key);
		return ret;
	}
#ifdef RDMA_SIGN_MTT_EN
	sign_val = hmm_gen_mtt_sign(fmr->mr.mtt.mtt_paddr, fmr->mr.mtt.mtt_type);
#endif
	mtt_vaddr = fmr->mr.mtt.mtt_vaddr;
	for (i = 0; i < npages; i++)
		mtt_vaddr[i] = cpu_to_be64(page_list[i] | RDMA_MTT_PA_VALID | (sign_val << 1));

	fmr->maps++;
	fmr->mr.key = new_key;
	fmr->mr.enabled = RDMA_MPT_EN_HW;
	return 0;
}

int roce3_rdma_unmap_fmr(void *hwdev, struct rdma_fmr *fmr, u32 service_type)
{
	struct rdma_comp_priv *comp_priv = NULL;
	int ret = 0;
	u32 new_key = 0;

	if ((hwdev == NULL) || (fmr == NULL)) {
		pr_err("%s: Hwdev or fmr is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	if (fmr->maps == 0)
		return 0;

	new_key = fmr->mr.key & RDMA_KEY_MASK;

	if (service_type == RDMA_SERVICE_TYPE_ROCE) {
		ret = hmm_modify_roce_mpt(hwdev, fmr->mr.mpt.mpt_index, new_key, 0ULL,
			0ULL, HINIC3_CHANNEL_ROCE);
	} else {
		pr_err("%s: service_type not support\n", __func__);
		return -EINVAL;
	}

	if (ret != 0) {
		pr_err("%s: Modify mpt failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	fmr->maps = 0;
	fmr->mr.key = new_key;

	return 0;
}

static int roce3_rdma_rdmarc_alloc_check(struct rdma_comp_priv **comp_priv, void *hwdev,
	const struct rdma_rdmarc *rdmarc, u32 *log_rdmarc_per_seg, u32 num)
{
	if ((hwdev == NULL) || (rdmarc == NULL)) {
		pr_err("%s: Hwdev or rdmarc is null\n", __func__);
		return -EINVAL;
	}

	*comp_priv = get_rdma_comp_priv(hwdev);
	if (*comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	*log_rdmarc_per_seg = (*comp_priv)->rdma_cap.log_rdmarc_seg;

	if ((num < ROCE3_RDMARC_MIN_DEPTH) || (num > ROCE3_RDMARC_MAX_DEPTH)) {
		pr_err("%s: Num is invalid, ret(%d)\n", __func__, -EINVAL);
		return -EINVAL;
	}

	return 0;
}

static void roce3_rdma_rdmarc_order_set(struct rdma_rdmarc *rdmarc, u32 order,
	u32 ext_order, u32 log_rdmarc_per_seg)
{
	rdmarc->order = order;
	rdmarc->ext_order = ext_order + log_rdmarc_per_seg;
}

int roce3_rdma_rdmarc_alloc(void *hwdev, u32 num, struct rdma_rdmarc *rdmarc)
{
	struct rdma_comp_priv *comp_priv = NULL;
	int ret = 0;
	u32 i = 0;
	u32 order = 0;
	u32 ext_order = 0;
	u32 ext_num = num + ROCE3_RDMARC_EXT_ENTRY;
	u32 offset = 0;
	void *vaddr = NULL;
	u32 log_rdmarc_per_seg = 0;
	u32 chip_num = (num < ROCE3_RDMARC_MIN_ENTRY) ? ROCE3_RDMARC_MIN_ENTRY : num;

	ret = roce3_rdma_rdmarc_alloc_check(&comp_priv, hwdev, rdmarc, &log_rdmarc_per_seg, num);
	if (ret != 0)
		return ret;

	for (i = 1; i < chip_num; i <<= 1)
		order++;

	for (i = 1; i < ext_num; i <<= 1)
		ext_order++;

	ext_order = ext_order > log_rdmarc_per_seg ? (ext_order - log_rdmarc_per_seg) : 0;
	roce3_rdma_rdmarc_order_set(rdmarc, order, ext_order, log_rdmarc_per_seg);
	offset = hmm_buddy_alloc(&comp_priv->rdmarc_buddy, ext_order);
	if (offset == RDMA_INVALID_INDEX) {
		pr_err("%s: Alloc rdmarc index failed, ret(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}
	rdmarc->offset = offset << log_rdmarc_per_seg;
	ret = hmm_em_table_get_range(comp_priv->pdev, &comp_priv->rdmarc_em_table, rdmarc->offset,
		rdmarc->offset + (1U << rdmarc->ext_order) - 1);
	if (ret != 0) {
		pr_err("%s: Alloc rdmarc entry failed, ret(%d)\n", __func__, -ENOMEM);
		goto err_table_get;
	}
	vaddr = hmm_em_table_find(&comp_priv->rdmarc_em_table, rdmarc->offset, &rdmarc->dma_addr);
	if (vaddr == NULL) {
		ret = -ENOMEM;
		pr_err("%s: Can't find va and pa of rdmarc entry, ret(%d)\n",
			__func__, -ENOMEM);
		goto err_rdmarc_find;
	}
	rdmarc->vaddr = vaddr;
	return 0;
err_rdmarc_find:
	hmm_em_table_put_range(comp_priv->pdev, &comp_priv->rdmarc_em_table, rdmarc->offset,
		rdmarc->offset + (1U << rdmarc->ext_order) - 1);
err_table_get:
	hmm_buddy_free(&comp_priv->rdmarc_buddy, offset, ext_order);
	return ret;
}

void roce3_rdma_rdmarc_free(void *hwdev, struct rdma_rdmarc *rdmarc)
{
	struct rdma_comp_priv *comp_priv = NULL;
	u32 order = 0;
	u32 offset = 0;
	u32 log_rdmarc_per_seg = 0;

	if ((hwdev == NULL) || (rdmarc == NULL)) {
		pr_err("%s: Hwdev or rdmarc is null\n", __func__);
		return;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return;
	}

	hmm_em_table_put_range(comp_priv->pdev, &comp_priv->rdmarc_em_table, rdmarc->offset,
		rdmarc->offset + (1U << rdmarc->ext_order) - 1);

	log_rdmarc_per_seg = comp_priv->rdma_cap.log_rdmarc_seg;

	order = rdmarc->ext_order - log_rdmarc_per_seg;
	offset = rdmarc->offset >> log_rdmarc_per_seg;

	hmm_buddy_free(&comp_priv->rdmarc_buddy, offset, order);
}
