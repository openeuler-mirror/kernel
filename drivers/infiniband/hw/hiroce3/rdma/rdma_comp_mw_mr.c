// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "rdma_comp.h"
#include "roce_cqm_cmd.h"
#include "hmm_mr.h"

static void rdma_roce3_mpt_to_big_endian(struct roce_mpt_context *mpt_ctx)
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

static void rdma_set_roce3_mw_cmd_buf(struct roce_mpt_context *mpt_ctx, struct rdma_mw *mw)
{
	/* fill mpt_entry */
	mpt_ctx->dw0.bs.bpd = 1;
	mpt_ctx->dw0.bs.r_w = RDMA_MPT_MW;
	mpt_ctx->dw0.bs.access_lr = 1;
	mpt_ctx->dw0.bs.access_lw = 1;

	mpt_ctx->dw1.bs.dma_attr_idx = RDMA_MPT_DMA_ATTR_IDX;
	mpt_ctx->dw1.bs.so_ro = RDMA_MPT_SO_RO;

	mpt_ctx->dw2.bs.pdn = mw->pdn;
	mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_VALID;

	mpt_ctx->dw3.bs.mkey = mw->key & 0xFF;

	/* only type2 mw binds with QP and suppoort invalid operation, init value is FREE */
	if (mw->type == RDMA_MW_TYPE_2) {
		mpt_ctx->dw0.bs.invalid_en = 1;
		mpt_ctx->dw0.bs.remote_invalid_en = 1;
		mpt_ctx->dw0.bs.bqp = 1;

		mpt_ctx->dw2.bs.status = RDMA_MPT_STATUS_FREE;
	}

	rdma_roce3_mpt_to_big_endian(mpt_ctx);
}

int roce3_rdma_enable_mw_mpt(void *hwdev, struct rdma_mw *mw, u32 service_type)
{
	int ret = 0;
	struct rdma_comp_priv *comp_priv = NULL;
	struct tag_cqm_cmd_buf *cqm_cmd_inbuf = NULL;
	struct roce_mpt_context *mpt_entry = NULL;
	struct tag_roce_sw2hw_mpt *mpt_sw2hw_inbuf = NULL;

	if ((hwdev == NULL) || (mw == NULL)) {
		pr_err("%s: Hwdev or mw is null\n", __func__);
		return -EINVAL;
	}

	if (service_type != RDMA_SERVICE_TYPE_ROCE) {
		pr_err("%s: service_type not support\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	ret = roce3_cqm_cmd_zalloc_inoutbuf(hwdev, &cqm_cmd_inbuf,
		(u16)sizeof(struct tag_roce_sw2hw_mpt), NULL, 0);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to alloc cqm_cmd_inoutbuf, ret(%d)\n",
			__func__, ret);
		return -ENOMEM;
	}

	/* cmd_buf: mpt_index + mpt_entry */
	mpt_sw2hw_inbuf = (struct tag_roce_sw2hw_mpt *)cqm_cmd_inbuf->buf;
	mpt_sw2hw_inbuf->com.index = cpu_to_be32(mw->mpt.mpt_index);
	mpt_sw2hw_inbuf->com.dw0.bs.cmd_bitmask =
		cpu_to_be16(VERBS_CMD_TYPE_MR_BITMASK); //lint !e778
	mpt_entry = &mpt_sw2hw_inbuf->mpt_entry;
	rdma_set_roce3_mw_cmd_buf(mpt_entry, mw);
	ret = hmm_enable_roce_mpt(hwdev, cqm_cmd_inbuf, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("%s: Enable mr's mpt failed, ret(%d)\n", __func__, ret);
		goto out;
	}
	mw->enabled = RDMA_MPT_EN_HW;
out:
	roce3_cqm_cmd_free_inoutbuf(hwdev, cqm_cmd_inbuf, NULL);
	return ret;
}

int roce3_rdma_disable_mw_mpt(void *hwdev, struct rdma_mw *mw, u32 service_type)
{
	struct rdma_comp_priv *comp_priv = NULL;
	int ret = 0;

	if ((hwdev == NULL) || (mw == NULL)) {
		pr_err("%s: Hwdev or mw is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	if (mw->enabled == RDMA_MPT_EN_HW) {
		if (service_type == RDMA_SERVICE_TYPE_ROCE) {
			ret = hmm_disable_roce_mpt((struct hmm_comp_priv *)(void *)comp_priv,
				&mw->mpt, HINIC3_CHANNEL_ROCE);
		} else {
			pr_err("%s: service_type not support\n", __func__);
			return -EINVAL;
		}

		if (ret != 0) {
			pr_err("%s: Disable mw's mpt failed, ret(%d)\n", __func__, ret);
			return ret;
		}

		mw->enabled = RDMA_MPT_EN_SW;
	}

	return 0;
}

static int rdma_mpt_alloc_rsvd_lkey(struct rdma_comp_priv *comp_priv, struct rdma_mpt *mpt)
{
	struct rdma_mpt_entry *mpt_entry = NULL;
	u32 mpt_entry_size = 0;

	mpt_entry_size = comp_priv->rdma_cap.mpt_entry_sz;

	/* 调用cqm接口分配mpt，并将mpt_index和vaddr保存在rdma_mpt结构 */
	mpt->mpt_object = (void *)cqm_object_qpc_mpt_create(comp_priv->hwdev,
		RDMA_SERVICE_TYPE_ROCE, CQM_OBJECT_MPT,
		mpt_entry_size, mpt, mpt->mpt_index, false);
	if (mpt->mpt_object == NULL) {
		pr_err("[ROCE, ERR]%s: Alloc mpt_object failed, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	mpt->vaddr = (void *)((struct tag_cqm_qpc_mpt *)mpt->mpt_object)->vaddr;
	if (!cqm_need_secure_mem(comp_priv->hwdev)) {
		memset(mpt->vaddr, 0, sizeof(struct rdma_mpt_entry));

		mpt_entry = (struct rdma_mpt_entry *)mpt->vaddr;
		mpt_entry->roce_mpt_ctx.dw2.bs.status = RDMA_MPT_STATUS_MEM_INIT;
		mpt_entry->roce_mpt_ctx.dw2.value = cpu_to_be32(mpt_entry->roce_mpt_ctx.dw2.value);
	}

	return 0;
}

int roce3_rdma_init_rsvd_lkey(void *hwdev)
{
	struct rdma_mr *mr = NULL;
	struct rdma_service_cap *rdma_cap = NULL;
	struct rdma_comp_priv *comp_priv = NULL;
	int ret = 0;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR]%s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("[ROCE, ERR]%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}

	rdma_cap = &comp_priv->rdma_cap;
	mr = &comp_priv->rsvd_lkey;
	mr->mpt.mpt_index = rdma_cap->reserved_lkey >> MR_KEY_LEFT_SHIFT_OFS;
	if (mr->mpt.mpt_index >= rdma_cap->reserved_mrws) {
		pr_err("[ROCE, ERR]%s: Cfg err, reserved_lkey(0x%x), reserved_mrws(0x%x)\n",
			__func__, rdma_cap->reserved_lkey, rdma_cap->reserved_mrws);
		return -EINVAL;
	}
	/* Alloc MPT */
	ret = rdma_mpt_alloc_rsvd_lkey(comp_priv, &mr->mpt);
	if (ret != 0) {
		pr_err("[ROCE, ERR]%s: Rdma_mpt_alloc_rsvd_lkey failed, ret(%d)\n",
			__func__, ret);
		return ret;
	}
	mr->mtt.mtt_layers = 0;
	mr->iova = 0;
	mr->size = ~0ULL;
	mr->key = comp_priv->rdma_cap.reserved_lkey;
	mr->mr_type = RDMA_RSVD_LKEY;
	mr->access = RDMA_IB_ACCESS_LOCAL_WRITE;
	/* Enable MPT */
	ret = hmm_rdma_enable_mr_mpt(hwdev, mr, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("[ROCE, ERR]%s: Rdma_enable_mr_mpt failed, ret(%d)\n", __func__, ret);
		goto err_out;
	}
	return 0;
err_out:
	hmm_rdma_mpt_free(hwdev, &mr->mpt);
	return ret;
}

void roce3_rdma_free_rsvd_lkey(void *hwdev)
{
	struct rdma_mr *mr = NULL;
	struct rdma_comp_priv *comp_priv = NULL;
	int ret = 0;

	if (hwdev == NULL) {
		pr_err("[ROCE, ERR]%s: Hwdev is null\n", __func__);
		return;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("[ROCE, ERR]%s: Comp_priv is null\n", __func__);
		return;
	}

	mr = &comp_priv->rsvd_lkey;
	ret = hmm_rdma_disable_mr_mpt(hwdev, mr, RDMA_SERVICE_TYPE_ROCE, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_err("[ROCE, ERR]%s: Disable mpt of mr failed, ret(%d)\n", __func__, ret);
		return;
	}

	hmm_rdma_mpt_free(hwdev, &mr->mpt);
}
