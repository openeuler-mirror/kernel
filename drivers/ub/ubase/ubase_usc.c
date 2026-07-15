// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include "ubase_dev.h"
#include "ubase_hw.h"
#include "ubase_mailbox.h"
#include "ubase_pmem.h"
#include "ubase_rct.h"
#include "ubase_usc.h"

static const u8 ubase_usc_opcodes[] = {
	UBASE_MB_WRITE_JFS_CONTEXT_VA,
	UBASE_MB_CREATE_JFS_CONTEXT,
	UBASE_MB_MODIFY_JFS_CONTEXT,
	UBASE_MB_QUERY_JFS_CONTEXT,
	UBASE_MB_DESTROY_JFS_CONTEXT,

	UBASE_MB_WRITE_JFR_CONTEXT_VA,
	UBASE_MB_CREATE_JFR_CONTEXT,
	UBASE_MB_MODIFY_JFR_CONTEXT,
	UBASE_MB_QUERY_JFR_CONTEXT,
	UBASE_MB_DESTROY_JFR_CONTEXT,

	UBASE_MB_WRITE_JFC_CONTEXT_VA,
	UBASE_MB_CREATE_JFC_CONTEXT,
	UBASE_MB_MODIFY_JFC_CONTEXT,
	UBASE_MB_QUERY_JFC_CONTEXT,
	UBASE_MB_DESTROY_JFC_CONTEXT,

	UBASE_MB_WRITE_RC_CONTEXT_VA,
	UBASE_MB_CREATE_RC_CONTEXT,
	UBASE_MB_MODIFY_RC_CONTEXT,
	UBASE_MB_QUERY_RC_CONTEXT,
	UBASE_MB_DESTROY_RC_CONTEXT,
};

bool ubase_ctx_in_usc(u8 mb_attr_op)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(ubase_usc_opcodes); i++) {
		if (mb_attr_op == ubase_usc_opcodes[i])
			return true;
	}
	return false;
}

int ubase_usc_init(struct ubase_dev *udev)
{
	int ret;

	if (!ubase_dev_usc_supported(udev))
		return 0;

	udev->mem_init_ops.mem_init = (mem_init_t)symbol_get(usc_mem_init);
	if (!udev->mem_init_ops.mem_init) {
		ubase_err(udev, "failed to get usc_mem_init symbol.\n");
		return -ENOENT;
	}

	udev->mem_init_ops.mem_uninit = (mem_uninit_t)symbol_get(usc_mem_uninit);
	if (!udev->mem_init_ops.mem_uninit) {
		ubase_err(udev, "failed to get usc_mem_uninit symbol.\n");
		symbol_put(usc_mem_init);
		udev->mem_init_ops.mem_init = NULL;
		return -ENOENT;
	}

	ret = udev->mem_init_ops.mem_init(udev->dev, &udev->mm_ops);
	if (ret) {
		symbol_put(usc_mem_init);
		symbol_put(usc_mem_uninit);
		udev->mem_init_ops.mem_init = NULL;
		udev->mem_init_ops.mem_uninit = NULL;
	}

	return ret;
}

void ubase_usc_uninit(struct ubase_dev *udev)
{
	if (!ubase_dev_usc_supported(udev))
		return;

	if (!udev->mem_init_ops.mem_uninit)
		return;

	udev->mem_init_ops.mem_uninit(udev->dev, &udev->mm_ops);

	symbol_put(usc_mem_init);
	symbol_put(usc_mem_uninit);
}

int ubase_cmd_ctx_buf_alloc_usc(struct ubase_dev *udev,
				struct ubase_ctx_buf_cap *ctx_buf,
				struct ubase_mbx_attr *attr)
{
	size_t size = ctx_buf->entry_cnt * ctx_buf->entry_size;

	ctx_buf->dma_ctx_buf_ba = 0;

	if (!size)
		return 0;

	udev->mm_ops.alloc_mem(udev->dev, &ctx_buf->dma_ctx_buf_ba, size, attr->op);

	if (!ctx_buf->dma_ctx_buf_ba)
		return -ENOMEM;

	return ubase_config_ctx_buf_to_hw(udev, ctx_buf, attr);
}

void ubase_cmd_ctx_buf_free_usc(struct ubase_dev *udev,
				struct ubase_ctx_buf_cap *ctx_buf,
				u16 mb_cmd)
{
	size_t size;

	if (!ctx_buf || !ctx_buf->dma_ctx_buf_ba)
		return;

	size = ctx_buf->entry_cnt * ctx_buf->entry_size;
	if (!size)
		return;

	udev->mm_ops.free_mem(udev->dev, &ctx_buf->dma_ctx_buf_ba, size, mb_cmd);
	ctx_buf->dma_ctx_buf_ba = 0;
}

int ubase_alloc_rc_buf_usc(struct ubase_dev *udev,
			   struct ubase_rc_queue *entry, size_t size)
{
	entry->va = udev->mm_ops.alloc_mem(udev->dev,
					   &entry->iova,
					   size,
					   UBASE_ALLOC_RC_ENTRY);
	if (!entry->va)
		return -ENOMEM;

	return 0;
}

void ubase_free_rc_buf_usc(struct ubase_dev *udev,
			   struct ubase_rc_queue *entry, size_t size)
{
	if (!entry->va)
		return;

	udev->mm_ops.free_mem(udev->dev, &entry->iova,
			      size, UBASE_FREE_RC_ENTRY);
	entry->va = NULL;
}
