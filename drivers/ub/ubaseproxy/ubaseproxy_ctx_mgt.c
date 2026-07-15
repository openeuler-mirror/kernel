// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/dmapool.h>
#include <linux/slab.h>
#include <linux/ummu_core.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "ubaseproxy_dev.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_jfs.h"
#include "ubaseproxy_ctx_mgt.h"

#define UBASEPROXY_DEFINE_CTX_VA_BUFS(ctx_buf) \
	struct ubaseproxy_ctx_buf_map map[] = { \
		{ &ctx_buf->jfr, UBASE_MB_WRITE_JFR_CONTEXT_VA }, \
		{ &ctx_buf->jfs, UBASE_MB_WRITE_JFS_CONTEXT_VA }, \
		{ &ctx_buf->jfc, UBASE_MB_WRITE_JFC_CONTEXT_VA }, \
		{ &ctx_buf->jtg, UBASE_MB_WRITE_JETTY_GROUP_CONTEXT_VA }, \
		{ &ctx_buf->rc, UBASE_MB_WRITE_RC_CONTEXT_VA } \
	}

static void ubaseproxy_risk_stats_init(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++)
		UBASEPROXY_RATELIMIT_INIT(udev, i);
}

static void ubaseproxy_destroy_ctx_page(struct ubaseproxy_dev *udev,
					struct ubase_ctx_buf_cap *ctx_buf,
					struct ubaseproxy_ctx_page *ctx_page)
{
	int ret;

	ret = ummu_core_drain_pages(ctx_buf->slot, ctx_page->iova,
				    UBASE_IOVA_COMM_PFN_CNT);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to drain pages in ummu, npage = %u, ret = %d.\n",
			       ctx_page->npage, ret);

	kfree(ctx_page);
}

static void ubaseproxy_free_and_clear_ctx_buf(struct ubaseproxy_dev *udev,
					      struct ubase_ctx_buf_cap *ctx_buf)
{
	struct ubaseproxy_ctx_page *ctx_page;
	size_t npage;

	if (!xa_empty(&ctx_buf->ctx_xa)) {
		xa_for_each(&ctx_buf->ctx_xa, npage, ctx_page)
			ubaseproxy_destroy_ctx_page(udev, ctx_buf, ctx_page);
	}

	if (ctx_buf->slot) {
		dma_free_iova(ctx_buf->slot);
		ctx_buf->slot = NULL;
	}

	ctx_buf->dma_ctx_buf_ba = 0;
}

static void ubaseproxy_cmd_ctx_buf_free(struct ubaseproxy_dev *udev,
					struct ubase_ctx_buf_cap *ctx_buf)
{
	size_t size;

	if (!ctx_buf || !ctx_buf->slot)
		return;

	size = ctx_buf->entry_cnt * ctx_buf->entry_size;
	if (!size)
		return;

	ubaseproxy_free_and_clear_ctx_buf(udev, ctx_buf);
	xa_destroy(&ctx_buf->ctx_xa);
}

static void ubaseproxy_init_res_info_lock(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++)
		mutex_init(&udev->ue_res_info[i].ue_ctx_buf.jfc.ctx_mutex);
}

static void ubaseproxy_uninit_res_info_lock(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++)
		mutex_destroy(&udev->ue_res_info[i].ue_ctx_buf.jfc.ctx_mutex);
}

static void ubaseproxy_get_ue_entry_caps(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++) {
		udev->ue_res_info[i].ue_ctx_buf.jfs.entry_cnt = ue_caps->jfs_max_cnt;
		udev->ue_res_info[i].ue_ctx_buf.jfr.entry_cnt = ue_caps->jfr_max_cnt;
		udev->ue_res_info[i].ue_ctx_buf.jfc.entry_cnt = ue_caps->jfc_max_cnt;
		udev->ue_res_info[i].ue_ctx_buf.jtg.entry_cnt = ue_caps->jtg_max_cnt;
		udev->ue_res_info[i].ue_ctx_buf.rc.entry_cnt = ue_caps->rc_max_cnt;
		udev->ue_res_info[i].ue_ctx_buf.jfs.entry_size = UBASE_JFS_CTX_SIZE;
		udev->ue_res_info[i].ue_ctx_buf.jfr.entry_size = UBASE_JFR_CTX_SIZE;
		udev->ue_res_info[i].ue_ctx_buf.jfc.entry_size = UBASE_JFC_CTX_SIZE;
		udev->ue_res_info[i].ue_ctx_buf.jtg.entry_size = UBASE_JTG_CTX_SIZE;
		udev->ue_res_info[i].ue_ctx_buf.rc.entry_size = UBASE_RC_CTX_SIZE;
	}
}

static void ubaseproxy_init_ue_ctx_xarray(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++)
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.jfc);
}

int ubaseproxy_ue_res_info_init(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1;

	udev->tid = ubase_caps->tid;
	udev->ue_res_info = kcalloc(managed_ue_num,
				    sizeof(struct ubaseproxy_ue_res_info),
				    GFP_KERNEL);
	if (!udev->ue_res_info)
		return -ENOMEM;

	ubaseproxy_init_res_info_lock(udev);
	ubaseproxy_get_ue_entry_caps(udev);
	ubaseproxy_init_ue_ctx_xarray(udev);
	ubaseproxy_risk_stats_init(udev);

	return 0;
}

int ubaseproxy_update_ctx_va_status(struct ubaseproxy_dev *udev,
				    u16 bus_ue_id, u16 bitmap, u8 status)
{
	struct ubaseproxy_update_va_status_cmd req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.bus_ue_id = cpu_to_le16(bus_ue_id);
	req.ctx_bitmap = cpu_to_le16(bitmap);
	req.status = status;

	ubase_fill_inout_buf(&in, UBASE_OPC_UPDATE_CTX_VA_STATUS, false,
			     sizeof(req), &req);
	ret = ubase_cmd_send_in(udev->comdev.adev, &in);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to update ctx va status, ret = %d.\n",
			       ret);

	return ret;
}

int ubaseproxy_ue_ctx_default_init(struct ubaseproxy_dev *udev)
{
	int ret;

	ret = ubaseproxy_init_ue_jfc_ctx_default(udev);

	return ret;
}

void ubaseproxy_ue_ctx_default_uninit(struct ubaseproxy_dev *udev)
{
	ubaseproxy_uninit_ue_jfc_ctx_default(udev);
}

static void ubaseproxy_erase_common_ctx_resources(struct xarray *arr)
{
	unsigned long index = 0;
	void *item = NULL;

	if (!xa_empty(arr)) {
		xa_for_each(arr, index, item) {
			xa_erase(arr, index);
			kfree(item);
			item = NULL;
		}
	}
}

void ubaseproxy_erase_ue_ctx_resources(struct ubaseproxy_dev *udev,
				       struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	ubaseproxy_erase_common_ctx_resources(&ue_ctx_xa->jfc);
}

static void ubaseproxy_destroy_ue_ctx_xa(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	xa_destroy(&ue_ctx_xa->jfc);
}

static void ubaseproxy_uninit_ue_ctx_resources(struct ubaseproxy_dev *udev,
					       struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	ubaseproxy_erase_ue_ctx_resources(udev, ue_ctx_xa);
	ubaseproxy_destroy_ue_ctx_xa(ue_ctx_xa);
}

void ubaseproxy_ue_ctx_buf_free(struct ubaseproxy_dev *udev,
				struct ubaseproxy_ue_ctx_buf *ctx_buf)
{
	int i;

	UBASEPROXY_DEFINE_CTX_VA_BUFS(ctx_buf);

	for (i = ARRAY_SIZE(map) - 1; i >= 0; i--)
		ubaseproxy_cmd_ctx_buf_free(udev, map[i].ctx);
}

void ubaseproxy_ue_res_info_uninit(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;
	int ret;

	ret = ubaseproxy_update_ctx_va_status(udev, UBASEPROXY_ALL_UES,
					      UBASEPROXY_UE_ALL_CTX_VA,
					      UBASEPROXY_CTX_VA_UNINTED);
	if (ret)
		ubaseproxy_warn(udev,
				"failed to update ctx va status when uninit, ret = %d.\n",
				ret);

	for (i = 0; i < managed_ue_num; i++) {
		ubaseproxy_uninit_ue_ctx_resources(udev, &udev->ue_res_info[i].ue_ctx_xa);
		ubaseproxy_ue_ctx_buf_free(udev, &udev->ue_res_info[i].ue_ctx_buf);
	}

	ubaseproxy_uninit_res_info_lock(udev);

	kfree(udev->ue_res_info);
	udev->ue_res_info = NULL;
}

int ubaseproxy_check_ctx_mask_value(struct ubaseproxy_dev *udev,
				    void *ctx_value, void *mask_value,
				    void *default_value, u16 size)
{
	u32 *default_arr, *mask_arr, *ctx_arr;
	u16 i;

	ctx_arr = (u32 *)ctx_value;
	mask_arr = (u32 *)mask_value;
	default_arr = (u32 *)default_value;

	for (i = 0; i < size; i++) {
		if ((ctx_arr[i] & mask_arr[i]) != default_arr[i]) {
			ubaseproxy_err(udev,
				       "failed to check ctx(%u) value, ctx: 0x%x, mask: 0x%x, default: 0x%x.\n",
				       i, ctx_arr[i], mask_arr[i],
				       default_arr[i]);
			return -EINVAL;
		}
	}

	return 0;
}
