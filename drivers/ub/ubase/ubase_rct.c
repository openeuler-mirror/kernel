// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include "ubase_mailbox.h"
#include "ubase_usc.h"
#include "ubase_rct.h"

static dma_addr_t ubase_get_rc_queue_iova_from_pmem(struct ubase_dev *udev,
						    u32 rc_queue_idx)
{
	u32 buf_num_per_hugepage;
	dma_addr_t iova;
	u32 rcq_size;

	rcq_size = ALIGN(udev->caps.udma_caps.rc_que_depth * UBASE_RCE_SIZE,
			 PAGE_SIZE);
	if (rcq_size > UBASE_PMEM_PAGE_SIZE) {
		iova = udev->pmem_info.udma.dma_addr + rc_queue_idx * rcq_size;
	} else {
		buf_num_per_hugepage = UBASE_PMEM_PAGE_SIZE / rcq_size;
		iova = udev->pmem_info.udma.dma_addr +
		       rc_queue_idx / buf_num_per_hugepage * UBASE_PMEM_PAGE_SIZE +
		       rc_queue_idx % buf_num_per_hugepage * rcq_size;
	}

	return iova;
}

static int ubase_alloc_rc_buf(struct ubase_dev *udev, u32 rc_queue_idx)
{
	size_t size = udev->caps.udma_caps.rc_que_depth * UBASE_RCE_SIZE;
	struct ubase_rc_queue *entry = &udev->rc_entry[rc_queue_idx];

	if (ubase_dev_usc_supported(udev))
		return ubase_alloc_rc_buf_usc(udev, entry, size);

	if (test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits)) {
		entry->iova = ubase_get_rc_queue_iova_from_pmem(udev,
								rc_queue_idx);
		return 0;
	}

	entry->va = dma_alloc_coherent(udev->dev, size, &entry->iova, GFP_KERNEL);
	if (!entry->va)
		return -ENOMEM;

	return 0;
}

static void ubase_free_rc_buf(struct ubase_dev *udev, u32 rc_queue_idx)
{
	size_t size = udev->caps.udma_caps.rc_que_depth * UBASE_RCE_SIZE;
	struct ubase_rc_queue *entry = &udev->rc_entry[rc_queue_idx];

	if (ubase_dev_usc_supported(udev)) {
		ubase_free_rc_buf_usc(udev, entry, size);
		return;
	}

	if (test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits))
		return;

	if (!entry->va || !entry->iova)
		return;

	dma_free_coherent(udev->dev, size, entry->va, entry->iova);

	entry->va = NULL;
	entry->iova = 0;
	entry->page = NULL;
}

int ubase_create_rc_queue_ctx(struct ubase_dev *udev, u32 rc_queue_idx)
{
	u32 depth = udev->caps.udma_caps.rc_que_depth;
	u32 tid = udev->caps.dev_caps.tid;
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	struct ubase_rc_ctx ctx = {0};
	dma_addr_t rc_queue_iova;
	int ret;

	ctx.type = UBASE_RC_TYPE;
	ctx.state = UBASE_RC_READY_STATE;
	ctx.rce_token_id_l = tid & (u32)UBASE_RCE_TOKEN_ID_L_MASK;
	ctx.rce_token_id_h = tid >> UBASE_RCE_TOKEN_ID_H_OFFSET;
	rc_queue_iova = udev->rc_entry[rc_queue_idx].iova;
	ctx.rce_base_addr_l = (rc_queue_iova >> UBASE_RCE_ADDR_L_OFFSET) &
			      (u32)UBASE_RCE_ADDR_L_MASK;
	ctx.rce_base_addr_h = rc_queue_iova >> UBASE_RCE_ADDR_H_OFFSET;
	ctx.rce_shift = ilog2(roundup_pow_of_two(depth));
	ctx.avail_sgmt_ost = UBASE_RC_AVAIL_SGMT_OST;

	mailbox = __ubase_alloc_cmd_mailbox(udev);
	if (!mailbox) {
		ubase_err(udev, "failed to alloc mailbox for rc queue.\n");
		return -ENOMEM;
	}

	memcpy(mailbox->buf, &ctx, sizeof(ctx));

	ubase_fill_mbx_attr(&attr, rc_queue_idx, UBASE_MB_CREATE_RC_CONTEXT, 0);
	ret = __ubase_hw_upgrade_ctx_ex(udev, &attr, mailbox);
	if (ret)
		ubase_err(udev, "failed to post mailbox for rc queue, ret = %d.\n",
			  ret);

	__ubase_free_cmd_mailbox(udev, mailbox);

	return ret;
}

int ubase_destroy_rc_queue_ctx(struct ubase_dev *udev, u32 rc_queue_idx)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	int ret;

	mailbox = __ubase_alloc_cmd_mailbox(udev);
	if (!mailbox) {
		ubase_err(udev, "failed to alloc mailbox for rc queue.\n");
		return -ENOMEM;
	}

	ubase_fill_mbx_attr(&attr, rc_queue_idx, UBASE_MB_DESTROY_RC_CONTEXT, 0);
	ret = __ubase_hw_upgrade_ctx_ex(udev, &attr, mailbox);
	if (ret)
		ubase_err(udev, "failed to destroy rc queue ctx, ret = %d.\n", ret);

	__ubase_free_cmd_mailbox(udev, mailbox);

	return ret;
}

int ubase_rc_init(struct ubase_dev *udev)
{
	u32 rc_max_cnt = udev->caps.udma_caps.rc_max_cnt;
	int ret;
	u32 i;

	udev->rc_entry = kcalloc(rc_max_cnt, sizeof(struct ubase_rc_queue),
				 GFP_KERNEL);
	if (!udev->rc_entry)
		return -ENOMEM;

	for (i = 0; i < rc_max_cnt; i++) {
		ret = ubase_alloc_rc_buf(udev, i);
		if (ret) {
			ubase_err(udev, "failed to init rc entry[%u], ret = %d.\n",
				  i, ret);
			goto err_rc_init;
		}

		ret = ubase_create_rc_queue_ctx(udev, i);
		if (ret) {
			ubase_err(udev, "failed to create ctx for rc entry[%u], ret = %d.\n",
				  i, ret);
			ubase_free_rc_buf(udev, i);
			goto err_rc_init;
		}
	}

	return 0;

err_rc_init:
	for (; i > 0; i--) {
		(void)ubase_destroy_rc_queue_ctx(udev, i - 1);
		ubase_free_rc_buf(udev, i - 1);
	}

	kfree(udev->rc_entry);
	udev->rc_entry = NULL;

	return ret;
}

void ubase_rc_uninit(struct ubase_dev *udev)
{
	u32 rc_max_cnt = udev->caps.udma_caps.rc_max_cnt;
	u32 i;

	if (!udev->rc_entry)
		return;

	for (i = rc_max_cnt; i > 0; i--) {
		(void)ubase_destroy_rc_queue_ctx(udev, i - 1);
		ubase_free_rc_buf(udev, i - 1);
	}

	kfree(udev->rc_entry);
	udev->rc_entry = NULL;
}

int ubase_adev_query_rc_ctx(struct auxiliary_device *adev, u32 rc_queue_idx,
			    void *ctx, u32 ctx_size)
{
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr = {0};
	struct ubase_rc_ctx *rc_ctx;
	struct ubase_dev *udev;
	int ret;

	if (!adev || !ctx || !ctx_size)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(adev);
	if (rc_queue_idx >= udev->caps.udma_caps.rc_max_cnt)
		return -EINVAL;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	mailbox = __ubase_alloc_cmd_mailbox(udev);
	if (!mailbox) {
		ubase_err(udev, "failed to alloc mailbox for rc queue.\n");
		return -ENOMEM;
	}

	ubase_fill_mbx_attr(&attr, rc_queue_idx, UBASE_MB_QUERY_RC_CONTEXT, 0);
	ret = __ubase_hw_upgrade_ctx_ex(udev, &attr, mailbox);
	if (ret) {
		ubase_err(udev, "failed to query rc queue ctx[%u], ret = %d.\n",
			  rc_queue_idx, ret);
		goto err_query_rc_ctx;
	}

	rc_ctx = (struct ubase_rc_ctx *)mailbox->buf;
	rc_ctx->rce_base_addr_l = 0;
	rc_ctx->rce_base_addr_h = 0;

	memcpy(ctx, rc_ctx, min(ctx_size, sizeof(*rc_ctx)));

err_query_rc_ctx:
	__ubase_free_cmd_mailbox(udev, mailbox);

	return ret;
}
EXPORT_SYMBOL(ubase_adev_query_rc_ctx);
