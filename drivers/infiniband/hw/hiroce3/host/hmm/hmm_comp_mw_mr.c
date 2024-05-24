// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "hmm_comp.h"
#include "hmm_mr.h"

static void hmm_roce_mpt_to_big_endian(struct roce_mpt_context *mpt_ctx)
{
	mpt_ctx->dw0.value = cpu_to_be32(mpt_ctx->dw0.value);
	mpt_ctx->dw1.value = cpu_to_be32(mpt_ctx->dw1.value);
	mpt_ctx->dw2.value = cpu_to_be32(mpt_ctx->dw2.value);
	mpt_ctx->dw3.value = cpu_to_be32(mpt_ctx->dw3.value);
	mpt_ctx->iova = cpu_to_be64(mpt_ctx->iova);
	mpt_ctx->length = cpu_to_be64(mpt_ctx->length);
	mpt_ctx->mtt_base_addr = cpu_to_be64(mpt_ctx->mtt_base_addr);
	mpt_ctx->mtt_sz = cpu_to_be32(mpt_ctx->mtt_sz);
}

static void hmm_set_roce_mr_access(struct roce_mpt_context *mpt_ctx, const struct rdma_mr *mr)
{
	mpt_ctx->dw0.bs.access_lr = 1; /* Local access enabled by default */

	if ((RDMA_IB_ACCESS_LOCAL_WRITE & mr->access) != 0)
		mpt_ctx->dw0.bs.access_lw = 1;

	if ((RDMA_IB_ACCESS_REMOTE_READ & mr->access) != 0)
		mpt_ctx->dw0.bs.access_rr = 1;

	if ((RDMA_IB_ACCESS_REMOTE_WRITE & mr->access) != 0)
		mpt_ctx->dw0.bs.access_rw = 1;

	if ((RDMA_IB_ACCESS_REMOTE_ATOMIC & mr->access) != 0)
		mpt_ctx->dw0.bs.access_ra = 1;

	if ((RDMA_IB_ACCESS_MW_BIND & mr->access) != 0)
		mpt_ctx->dw0.bs.access_bind = 1;
}

static void hmm_set_mptc_type_above_phy_mr(struct roce_mpt_context *mpt_ctx, struct rdma_mr *mr)
{
	switch (mr->mr_type) {
	case RDMA_PHYS_MR:
		mpt_ctx->mtt_base_addr = mr->mtt.mtt_paddr;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_VALID;
		break;

	case RDMA_RSVD_LKEY:
		mpt_ctx->dw0.bs.rkey = 1;
		mpt_ctx->dw0.bs.bpd = 0;
		mpt_ctx->dw0.bs.invalid_en = 0;
		mpt_ctx->dw0.bs.remote_invalid_en = 0;
		mpt_ctx->dw0.bs.pa = 1;
		mpt_ctx->mtt_base_addr = 0;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_VALID;
		break;

	case RDMA_SIG_MR:
		mpt_ctx->mtt_base_addr = mr->mtt.mtt_paddr;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_FREE;
		break;

	case RDMA_INDIRECT_MR:
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_FREE;
		break;
	default:
		pr_err("%s: RoCE unsupport mr type(%d)\n", __func__, mr->mr_type);
		break;
	}
}

static void hmm_set_mptc_type_below_phy_mr(struct roce_mpt_context *mpt_ctx, struct rdma_mr *mr)
{
	switch (mr->mr_type) {
	case RDMA_DMA_MR:
		mpt_ctx->dw0.bs.pa = 1;
		mpt_ctx->mtt_base_addr = 0;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_VALID;
		break;

	case RDMA_USER_MR:
		mpt_ctx->mtt_base_addr = mr->mtt.mtt_paddr;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_VALID;
		break;

	case RDMA_FRMR:
		mpt_ctx->mtt_base_addr = mr->mtt.mtt_paddr;
		mpt_ctx->dw0.bs.fast_reg_en = 1;
		mpt_ctx->dw0.bs.remote_access_en = 1;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_FREE;
		mpt_ctx->mtt_sz = (mr->mtt.mtt_layers > 0) ? 1U <<
			mr->mtt.mtt_seg[mr->mtt.mtt_layers - 1]->order : 0;
		break;

	case RDMA_FMR:
		mpt_ctx->mtt_base_addr = mr->mtt.mtt_paddr;
		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_VALID;
		break;
	default:
		pr_err("%s: RoCE unsupport mr type(%d)\n", __func__, mr->mr_type);
		break;
	}
}

static void hmm_set_mptc_according_to_mr_type(struct roce_mpt_context *mpt_ctx, struct rdma_mr *mr)
{
	if (mr->mr_type < RDMA_PHYS_MR)
		hmm_set_mptc_type_below_phy_mr(mpt_ctx, mr);
	else
		hmm_set_mptc_type_above_phy_mr(mpt_ctx, mr);
}

static void hmm_set_roce_mr_cmd_buf(struct roce_mpt_context *mpt_ctx, struct rdma_mr *mr)
{
	hmm_set_roce_mr_access(mpt_ctx, mr);

	mpt_ctx->dw0.bs.invalid_en = 1;
	mpt_ctx->dw0.bs.remote_invalid_en = 1;
	mpt_ctx->dw0.bs.r_w = RDMA_MPT_MR;
	mpt_ctx->dw0.bs.bpd = 1;
	mpt_ctx->dw2.bs.pdn = mr->pdn & 0x3ffff;

	if (mr->mr_type != RDMA_INDIRECT_MR) {
		mpt_ctx->dw0.bs.mtt_page_size =
			(mr->mtt.mtt_page_shift > PAGE_SHIFT_4K) ?
			(mr->mtt.mtt_page_shift - PAGE_SHIFT_4K) : 0;
		mpt_ctx->dw0.bs.mtt_layer_num = mr->mtt.mtt_layers;
		mpt_ctx->dw0.bs.buf_page_size =
			(mr->mtt.buf_page_shift > PAGE_SHIFT_4K) ?
			(mr->mtt.buf_page_shift - PAGE_SHIFT_4K) : 0;
		mpt_ctx->dw1.bs.dma_attr_idx = RDMA_MPT_DMA_ATTR_IDX;
		mpt_ctx->dw1.bs.so_ro = 0;
		mpt_ctx->dw2.bs.block_size = (mr->block_size / BLOCK_SIZE_DEVIDE_SECTOR) & 0x3f;
		if (mr->block_size > 0)
			mpt_ctx->dw3.bs.page_mode = 1;

		mpt_ctx->iova = mr->iova;
		mpt_ctx->length = mr->size;
		mpt_ctx->dw3.bs.fbo = 0;
		if ((mr->access & RDMA_IB_ACCESS_ZERO_BASED) != 0) {
			mpt_ctx->dw0.bs.zbva = 1;
			mpt_ctx->dw3.bs.fbo = mr->iova & PAGE_MASK;
			mpt_ctx->iova = 0;
		}
	} else {
		mpt_ctx->dw2.bs.indirect_mr = 1;
	}

	mpt_ctx->dw3.bs.mkey = mr->key & 0xFF;

	hmm_set_mptc_according_to_mr_type(mpt_ctx, mr);
	hmm_roce_mpt_to_big_endian(mpt_ctx);
}

int hmm_rdma_disable_mr_mpt(void *hwdev, struct rdma_mr *mr, u32 service_type, u16 channel)
{
	struct hmm_comp_priv *comp_priv = NULL;
	int ret = 0;

	if ((hwdev == NULL) || (mr == NULL)) {
		pr_err("%s: Hwdev or mr is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_hmm_comp_priv(hwdev, service_type);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	if (mr->enabled == RDMA_MPT_EN_HW) {
		ret = hmm_disable_roce_mpt(comp_priv, &mr->mpt, channel);
		if (ret != 0) {
			pr_err("%s: Disable mr's mpt failed, ret(%d)\n", __func__, ret);
			return ret;
		}

		mr->enabled = RDMA_MPT_EN_SW;
	}
	return 0;
}

int hmm_rdma_enable_mr_mpt(void *hwdev, struct rdma_mr *mr, u16 channel)
{
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct rdma_mpt_entry *mpt_entry = NULL;
	struct rdma_mpt_sw2hw_inbuf *mpt_sw2hw_inbuf = NULL;
	int ret = 0;

	if ((hwdev == NULL) || (mr == NULL)) {
		pr_err("%s: Hwdev or mr is null\n", __func__);
		return -EINVAL;
	}

	cqm_cmd_inbuf = cqm_cmd_alloc(hwdev);
	if (cqm_cmd_inbuf == NULL) {
		pr_err("%s: Alloc cmd_buf failed, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	cqm_cmd_inbuf->size = (u16)sizeof(struct rdma_mpt_sw2hw_inbuf);
	mpt_sw2hw_inbuf = (struct rdma_mpt_sw2hw_inbuf *)cqm_cmd_inbuf->buf;
	memset(mpt_sw2hw_inbuf, 0, sizeof(*mpt_sw2hw_inbuf));
	mpt_sw2hw_inbuf->com.dw0.bs.cmd_bitmask = (u16)cpu_to_be16(VERBS_CMD_TYPE_MR_BITMASK);
	mpt_sw2hw_inbuf->com.index = cpu_to_be32(mr->mpt.mpt_index);
	mpt_entry = &mpt_sw2hw_inbuf->mpt_entry;

	hmm_set_roce_mr_cmd_buf(&mpt_entry->roce_mpt_ctx, mr);
	ret = hmm_enable_roce_mpt(hwdev, cqm_cmd_inbuf, channel);
	if (ret != 0) {
		pr_err("%s: Enable mr's mpt failed, ret(%d)\n", __func__, ret);
		goto out;
	}
	mr->enabled = RDMA_MPT_EN_HW;
out:
	cqm_cmd_free(hwdev, cqm_cmd_inbuf);
	return ret;
}
