// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "hinic3_rdma.h"
#include "hmm_comp.h"
#include "hinic3_hmm.h"
#include "hmm_mr.h"

static int hmm_set_mtt_layer(const struct hmm_comp_priv *comp_priv,
	struct rdma_mtt *mtt, u32 npages)
{
	u32 one_layer_flag = 0;
	u64 two_layer_flag = 0;
	u64 three_layer_flag = 0;

	one_layer_flag = comp_priv->mtt_page_size / RDMA_PA_SIZE;
	two_layer_flag = ((u64)one_layer_flag) * ((u64)one_layer_flag);
	three_layer_flag = (u64)one_layer_flag * two_layer_flag;

	if (npages <= 1) {
		mtt->mtt_layers = RDMA_MTT_ZERO_LAYER;
		return 0;
	} else if (npages <= one_layer_flag) {
		mtt->mtt_layers = RDMA_MTT_ONE_LAYER;
	} else if (npages <= two_layer_flag) {
		mtt->mtt_layers = RDMA_MTT_TWO_LAYER;
	} else if ((u64)npages <= three_layer_flag) {
		mtt->mtt_layers = RDMA_MTT_THREE_LAYER;
	} else {
		pr_err("%s: Npages(0x%x) over range, ret(%d)\n", __func__, npages, -EINVAL);
		return -EINVAL;
	}

	return 0;
}

#ifdef RDMA_SIGN_MTT_EN

u16 hmm_gen_cmtt_sign(u64 mtt_base_gpa)
{
	u16 sign0 = (mtt_base_gpa >> RDMA_CMTT_SIGN_SHIFT0) & RDMA_CMTT_SIGN_MASK;
	u16 sign1 = (mtt_base_gpa >> RDMA_CMTT_SIGN_SHIFT1) & RDMA_CMTT_SIGN_MASK;
	u16 sign2 = (mtt_base_gpa >> RDMA_CMTT_SIGN_SHIFT2) & RDMA_CMTT_SIGN_MASK;
	u16 cmtt_sign = ~(sign0 ^ sign1 ^ sign2);

	cmtt_sign &= RDMA_CMTT_SIGN_MASK;
	return cmtt_sign;
}

u16 hmm_gen_dmtt_sign(u64 mtt_base_gpa)
{
	u16 sign0 = ((u16)(mtt_base_gpa >> RDMA_DMTT_SIGN_SHIFT0) <<
		RDMA_DMTT_ADD_SHIFT0) & RDMA_DMTT_SIGN_MASK;
	u16 sign1 = (mtt_base_gpa >> RDMA_DMTT_SIGN_SHIFT1) & RDMA_DMTT_SIGN_MASK;
	u16 sign2 = (mtt_base_gpa >> RDMA_DMTT_SIGN_SHIFT2) & RDMA_DMTT_SIGN_MASK;
	u16 sign3 = (mtt_base_gpa >> RDMA_DMTT_SIGN_SHIFT3) & RDMA_DMTT_SIGN_MASK;
	u16 dmtt_sign = ~(sign0 ^ sign1 ^ sign2 ^ sign3);

	dmtt_sign &= RDMA_DMTT_SIGN_MASK;
	return dmtt_sign;
}


u64 hmm_gen_mtt_sign(u64 mtt_base_gpa, enum mtt_data_type_e type)
{
	if (type == MTT_CMTT_TYPE)
		return hmm_gen_cmtt_sign(mtt_base_gpa);

	return (u64)hmm_gen_dmtt_sign(mtt_base_gpa) << 1;
}

#endif

static int hmm_find_mtt_page_list(struct hmm_comp_priv *comp_priv, struct rdma_mtt_seg *mtt_seg,
	u32 npages, u64 *page_list)
{
	void *vaddr = NULL;
	u32 i = 0;
	u32 mtt_index = 0;
	u32 mtts_per_page = 0;

	mtts_per_page = comp_priv->mtt_page_size / RDMA_PA_SIZE;
	if ((mtt_seg->offset % mtts_per_page) != 0) {
		pr_err("%s: First mtt isn't in the head of page, ret(%d)\n", __func__, -EINVAL);
		return -EINVAL;
	}

	mtt_index = mtt_seg->offset;
	for (i = 0; i < npages; i++) {
		vaddr = hmm_em_table_find(&comp_priv->mtt_em_table, mtt_index, &page_list[i]);
		if (vaddr == NULL) {
			pr_err("%s: Can't find va and pa of mtt entry, ret(%d)\n",
				__func__, -EINVAL);
			return -EINVAL;
		}

		mtt_index += comp_priv->mtt_page_size / RDMA_PA_SIZE;
	}

	return 0;
}

static int hmm_write_mtt_chunk(struct hmm_comp_priv *comp_priv, struct rdma_mtt *mtt,
	u32 mtt_level_index, u32 start_index, u32 npages, const u64 *page_list)
{
	u32 i = 0;
	u16 sign_val = 0;
	__be64 *mtts = NULL;

	mtts = (__be64 *)hmm_em_table_find(&comp_priv->mtt_em_table,
		mtt->mtt_seg[mtt_level_index]->offset + start_index, NULL);
	if (mtts == NULL) {
		pr_err("%s: Can't find va and pa of mtt entry, ret(%d)\n", __func__, -EINVAL);
		return -EINVAL;
	}
#ifdef RDMA_SIGN_MTT_EN
	sign_val = hmm_gen_mtt_sign(mtt->mtt_paddr, mtt->mtt_type);
#endif
	for (i = 0; i < npages; i++)
		mtts[i] = cpu_to_be64(page_list[i] | RDMA_MTT_PA_VALID | (sign_val << 1));

	return 0;
}

static int hmm_write_mtt_seg(struct hmm_comp_priv *comp_priv, struct rdma_mtt *mtt,
	u32 mtt_level_index, u32 start_index, u32 npages, u64 *page_list)
{
	int ret = 0;
	u32 chunk = 0;
	u32 mtts_per_page = 0;
	u32 max_mtts_first_page = 0;
	u32 tmp_npages = npages;
	u32 tmp_start_index = start_index;
	u64 *tmp_page_list = page_list;

	/* calculate how may mtts fit in the first page */
	mtts_per_page = comp_priv->mtt_page_size / RDMA_PA_SIZE;
	max_mtts_first_page = mtts_per_page - ((mtt->mtt_seg[mtt_level_index]->offset
		+ tmp_start_index) % mtts_per_page);

	chunk = (tmp_npages < max_mtts_first_page) ? tmp_npages : max_mtts_first_page;

	while ((int)tmp_npages > 0) {
		ret = hmm_write_mtt_chunk(comp_priv, mtt, mtt_level_index,
			tmp_start_index, chunk, tmp_page_list);
		if (ret != 0) {
			pr_err("%s: Write mtt chunk failed, ret(%d)\n", __func__, ret);
			return ret;
		}

		tmp_npages -= chunk;
		tmp_start_index += chunk;
		tmp_page_list += chunk;

		chunk = (tmp_npages < mtts_per_page) ? tmp_npages : mtts_per_page;
	}

	return 0;
}

static int hmm_alloc_mtt_seg(struct hmm_comp_priv *comp_priv, struct rdma_mtt_seg *mtt_seg)
{
	int ret = 0;
	u32 seg_offset = 0;
	u32 seg_order = 0;
	u32 log_mtts_per_seg = 0;

	log_mtts_per_seg = comp_priv->rdma_cap.log_mtt_seg;

	seg_order = (mtt_seg->order > log_mtts_per_seg) ? (mtt_seg->order - log_mtts_per_seg) : 0;
	mtt_seg->order = seg_order + log_mtts_per_seg;

	seg_offset = hmm_buddy_alloc(&comp_priv->mtt_buddy, seg_order);
	if (seg_offset == HMM_INVALID_INDEX) {
		pr_err("%s: Alloc mtt index failed\n", __func__);
		return -ENOMEM;
	}

	mtt_seg->offset = seg_offset << log_mtts_per_seg;

	ret = hmm_em_table_get_range(comp_priv->pdev, &comp_priv->mtt_em_table, mtt_seg->offset,
		mtt_seg->offset + (u32)(1U << mtt_seg->order) - 1);
	if (ret != 0) {
		pr_err("%s: Alloc mtt entry failed, ret(%d)\n", __func__, ret);
		goto err_get_entry;
	}

	mtt_seg->vaddr = hmm_em_table_find(&comp_priv->mtt_em_table, mtt_seg->offset,
		&mtt_seg->paddr);
	if (mtt_seg->vaddr == NULL) {
		pr_err("%s: Can't find start address of mtt_seg\n", __func__);
		goto err_find_entry;
	}

	return 0;

err_find_entry:
	hmm_em_table_put_range(comp_priv->pdev, &comp_priv->mtt_em_table, mtt_seg->offset,
		mtt_seg->offset + (u32)(1U << mtt_seg->order) - 1);

err_get_entry:
	hmm_buddy_free(&comp_priv->mtt_buddy, seg_offset, seg_order);

	return -ENOMEM;
}

static void hmm_free_mtt_seg(struct hmm_comp_priv *comp_priv, struct rdma_mtt_seg *mtt_seg)
{
	u32 seg_offset = 0;
	u32 seg_order = 0;
	int log_mtts_per_seg = 0;

	hmm_em_table_put_range(comp_priv->pdev, &comp_priv->mtt_em_table, mtt_seg->offset,
		mtt_seg->offset + (1U << mtt_seg->order) - 1);

	log_mtts_per_seg = (int)comp_priv->rdma_cap.log_mtt_seg;
	seg_order = mtt_seg->order - (u32)log_mtts_per_seg;
	seg_offset = mtt_seg->offset >> (unsigned int)log_mtts_per_seg;

	hmm_buddy_free(&comp_priv->mtt_buddy, seg_offset, seg_order);
}

static int hmm_init_mtt_seg(struct hmm_comp_priv *comp_priv, struct rdma_mtt *mtt, u32 npages)
{
	u32 i;
	int ret;

	if ((comp_priv == NULL) || (mtt == NULL)) {
		pr_err("%s: Comp_priv or mtt is null\n", __func__);
		return -EINVAL;
	}

	if (npages >= comp_priv->rdma_cap.num_mtts) {
		pr_err("%s: Npages(0x%x) over range, ret(%d)\n", __func__, npages, -EINVAL);
		return -EINVAL;
	}

	ret = hmm_set_mtt_layer(comp_priv, mtt, npages);
	if (ret != 0)
		return ret;

	mtt->mtt_seg = kcalloc(mtt->mtt_layers, sizeof(struct rdma_mtt_seg *), GFP_KERNEL);
	if (mtt->mtt_seg == NULL)
		return -ENOMEM;

	for (i = 0; i < mtt->mtt_layers; i++) {
		mtt->mtt_seg[i] = kzalloc(sizeof(struct rdma_mtt_seg), GFP_KERNEL);
		if (mtt->mtt_seg[i] == NULL)
			goto err_out;
	}

	return 0;

err_out:
	for (i = 0; i < mtt->mtt_layers; i++) {
		kfree(mtt->mtt_seg[i]);
		mtt->mtt_seg[i] = NULL;
	}

	kfree(mtt->mtt_seg);
	mtt->mtt_seg = NULL;

	return -ENOMEM;
}

static int hmm_rdma_mtt_alloc_prepare(void *hwdev, u32 npages, struct rdma_mtt *mtt,
	struct hmm_comp_priv **comp_priv, u32 service_type)
{
	int ret = 0;

	if ((hwdev == NULL) || (mtt == NULL)) {
		pr_err("%s: Hwdev or mtt is null\n", __func__);
		return -EINVAL;
	}

	*comp_priv = get_hmm_comp_priv(hwdev, service_type);
	if (*comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	ret = hmm_init_mtt_seg(*comp_priv, mtt, npages);
	if (ret != 0) {
		pr_err("%s: Initialize mtt_seg failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	return ret;
}

static int hmm_enable_mtt_related(struct hmm_comp_priv *comp_priv, struct rdma_mtt *mtt,
	u32 low_layer_index)
{
	u64 *page_list = NULL;
	struct rdma_mtt_seg *low_mtt_seg = NULL;
	u32 npages = 0;
	int ret = 0;

	low_mtt_seg = mtt->mtt_seg[low_layer_index];
	npages = (u32)((1UL << low_mtt_seg->order) / (comp_priv->mtt_page_size / RDMA_PA_SIZE));
	page_list = kzalloc(npages * RDMA_PA_SIZE, GFP_KERNEL);
	if (page_list == NULL)
		return -ENOMEM;

	ret = hmm_find_mtt_page_list(comp_priv, low_mtt_seg, npages, page_list);
	if (ret != 0) {
		pr_err("%s: Can't find page_list of mtt_seg, ret(%d)\n", __func__, ret);
		goto out;
	}

	ret = hmm_write_mtt_seg(comp_priv, mtt, low_layer_index + 1, 0, npages, page_list);
	if (ret != 0) {
		pr_err("%s: Write mtt_seg failed, ret(%d)\n", __func__, ret);
		goto out;
	}

out:
	kfree(page_list);

	return ret;
}

static void hmm_cleanup_mtt_seg(struct rdma_mtt *mtt)
{
	u32 i = 0;

	for (i = 0; i < mtt->mtt_layers; i++) {
		kfree(mtt->mtt_seg[i]);
		mtt->mtt_seg[i] = NULL;
	}

	kfree(mtt->mtt_seg);
	mtt->mtt_seg = NULL;
}

int hmm_rdma_mtt_alloc(void *hwdev, u32 npages, u32 page_shift, struct rdma_mtt *mtt,
	u32 service_type)
{
	struct hmm_comp_priv *comp_priv = NULL;
	int ret = 0;
	u32 i = 0;
	u32 cur_layer = 0;
	u32 order = 0;
	u32 tmp_npages = npages;

	ret = hmm_rdma_mtt_alloc_prepare(hwdev, npages, mtt, &comp_priv, service_type);
	if (ret != 0)
		return ret;

	for (cur_layer = 1; cur_layer <= mtt->mtt_layers; cur_layer++) {
		tmp_npages = (tmp_npages < HMM_MTT_NUM_PER_CACHELINE) ?
			HMM_MTT_NUM_PER_CACHELINE : tmp_npages;
		for (i = 1; i < tmp_npages; i <<= 1)
			order++;

		mtt->mtt_seg[cur_layer - 1]->order = order;
		ret = hmm_alloc_mtt_seg(comp_priv, mtt->mtt_seg[cur_layer - 1]);
		if (ret != 0) {
			pr_err("%s: Alloc mtt_seg failed, npages(%d), ret(%d)\n",
				__func__, tmp_npages, ret);
			goto err_out;
		}

		tmp_npages = (u32)(1U << mtt->mtt_seg[cur_layer - 1]->order) /
			(comp_priv->mtt_page_size / RDMA_PA_SIZE);
		order = 0;
	}
	if (mtt->mtt_layers > 0) {
		mtt->mtt_vaddr = (__be64 *)mtt->mtt_seg[mtt->mtt_layers - 1]->vaddr;
		mtt->mtt_paddr = mtt->mtt_seg[mtt->mtt_layers - 1]->paddr;
	}
	for (i = 1; i < mtt->mtt_layers; i++) {
		ret = hmm_enable_mtt_related(comp_priv, mtt, i - 1);
		if (ret != 0) {
			pr_err("%s: Cant't get multi mtt_seg related, i(%d), ret(%d)\n",
				__func__, i, ret);
			goto err_out;
		}
	}
	mtt->buf_page_shift = page_shift;
	mtt->mtt_page_shift = comp_priv->mtt_page_shift;
	return 0;
err_out:
	for (i = cur_layer - 1; i > 0; i--)
		hmm_free_mtt_seg(comp_priv, mtt->mtt_seg[i - 1]);

	hmm_cleanup_mtt_seg(mtt);
	return -ENOMEM;
}

void hmm_rdma_mtt_free(void *hwdev, struct rdma_mtt *mtt, u32 service_type)
{
	struct hmm_comp_priv *comp_priv = NULL;
	u32 i = 0;

	if ((hwdev == NULL) || (mtt == NULL)) {
		pr_err("%s: Hwdev or mtt is null\n", __func__);
		return;
	}

	comp_priv = get_hmm_comp_priv(hwdev, service_type);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return;
	}

	if (mtt->mtt_layers == 0)
		return;

	for (i = 0; i < mtt->mtt_layers; i++)
		hmm_free_mtt_seg(comp_priv, mtt->mtt_seg[i]);

	hmm_cleanup_mtt_seg(mtt);
}

int hmm_rdma_write_mtt(void *hwdev, struct rdma_mtt *mtt, u32 start_index, u32 npages,
	u64 *page_list, u32 service_type)
{
	struct hmm_comp_priv *comp_priv = NULL;
	int ret = 0;

	if ((hwdev == NULL) || (mtt == NULL)) {
		pr_err("%s: Hwdev or mtt is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_hmm_comp_priv(hwdev, service_type);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	if (mtt->mtt_layers == 0) {
		mtt->mtt_paddr = page_list[0];
		return 0;
	}

	ret = hmm_write_mtt_seg(comp_priv, mtt, 0, start_index, npages, page_list);
	if (ret != 0) {
		pr_err("%s: Write mtt seg failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

int hmm_init_mtt_table(struct hmm_comp_priv *comp_priv)
{
	int ret = 0;
	u32 i = 0;
	u32 max_order = 0;
	u32 mtt_num = 0;
	u32 mtt_size = 0;
	u32 log_mtts_per_seg = 0;

	mtt_num = comp_priv->rdma_cap.num_mtts;
	log_mtts_per_seg = comp_priv->rdma_cap.log_mtt_seg;
	mtt_size = comp_priv->rdma_cap.mtt_entry_sz;

	for (i = 1; i < mtt_num; i <<= 1)
		max_order++;

	max_order = (max_order > log_mtts_per_seg) ? (max_order - log_mtts_per_seg) : 0;

	ret = hmm_buddy_init(&comp_priv->mtt_buddy, max_order);
	if (ret != 0) {
		pr_err("%s: Initialize mtt's buddy failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	ret = hmm_em_init_table(comp_priv->pdev, &comp_priv->mtt_em_table, mtt_size, mtt_num, 0,
		(int)(comp_priv->mtt_page_shift - PAGE_SHIFT_4K));
	if (ret != 0) {
		pr_err("%s: Initialize mtt's em_table failed, ret(%d)\n", __func__, ret);
		goto err_out;
	}

	return 0;

err_out:
	hmm_buddy_cleanup(&comp_priv->mtt_buddy);

	return ret;
}

void hmm_cleanup_mtt_table(struct hmm_comp_priv *comp_priv)
{
	hmm_em_cleanup_table(comp_priv->pdev, &comp_priv->mtt_em_table);

	hmm_buddy_cleanup(&comp_priv->mtt_buddy);
}
