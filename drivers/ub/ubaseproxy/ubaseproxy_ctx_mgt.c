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
#include "ubaseproxy_eq.h"
#include "ubaseproxy_jetty_grp.h"
#include "ubaseproxy_jfc.h"
#include "ubaseproxy_jfr.h"
#include "ubaseproxy_jfs.h"
#include "ubaseproxy_rc.h"
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

static int ubaseproxy_create_ctx_page(struct ubaseproxy_dev *udev,
				      struct ubase_ctx_buf_cap *ctx_buf,
				      struct ubaseproxy_ctx_page **ctx_page,
				      u32 npage)
{
	int ret;

	*ctx_page = kzalloc(sizeof(struct ubaseproxy_ctx_page), GFP_KERNEL);
	if (!(*ctx_page))
		return -ENOMEM;

	(*ctx_page)->iova = ctx_buf->dma_ctx_buf_ba + npage * PAGE_SIZE;
	refcount_set(&(*ctx_page)->refcount, 1);
	(*ctx_page)->npage = npage;
	ret = ummu_core_fill_pages(ctx_buf->slot, (*ctx_page)->iova,
				   UBASE_IOVA_COMM_PFN_CNT,
				   udev->gfp | __GFP_ZERO);
	if (ret) {
		ubaseproxy_err(udev, "failed to fill pages in ummu, ret = %d\n",
			       ret);
		kfree(*ctx_page);
		*ctx_page = NULL;
	}

	return ret;
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

int ubaseproxy_use_buf_ctx_page(struct ubaseproxy_dev *udev,
				struct ubase_ctx_buf_cap *ctx_buf, u32 tag)
{
	u32 cnt_per_page_shift = ctx_buf->cnt_per_page_shift;
	u32 npage = tag >> cnt_per_page_shift;
	struct ubaseproxy_ctx_page *ctx_page;
	int ret;

	mutex_lock(&ctx_buf->ctx_mutex);

	ctx_page = (struct ubaseproxy_ctx_page *)xa_load(&ctx_buf->ctx_xa, npage);
	if (!ctx_page) {
		ret = ubaseproxy_create_ctx_page(udev, ctx_buf, &ctx_page, npage);
		if (ret) {
			ubaseproxy_err(udev,
				       "failed to create context page, ret = %d.\n",
				       ret);
			goto err_create;
		}

		ret = xa_err(xa_store(&ctx_buf->ctx_xa, npage, ctx_page,
				      GFP_KERNEL));
		if (ret) {
			ubaseproxy_err(udev, "failed to store page, ret = %d.\n",
				       ret);
			goto err_store;
		}
	}

	refcount_inc(&ctx_page->refcount);
	mutex_unlock(&ctx_buf->ctx_mutex);

	return 0;
err_store:
	ubaseproxy_destroy_ctx_page(udev, ctx_buf, ctx_page);
err_create:
	mutex_unlock(&ctx_buf->ctx_mutex);

	return ret;
}

void ubaseproxy_free_buf_ctx_page(struct ubaseproxy_dev *udev,
				  struct ubase_ctx_buf_cap *ctx_buf,
				  u32 tag)
{
	struct ubaseproxy_ctx_page *ctx_page;
	u32 cnt_per_page_shift;
	u32 npage;

	if (!ctx_buf)
		return;

	cnt_per_page_shift = ctx_buf->cnt_per_page_shift;
	npage = tag >> cnt_per_page_shift;

	mutex_lock(&ctx_buf->ctx_mutex);

	ctx_page = (struct ubaseproxy_ctx_page *)xa_load(&ctx_buf->ctx_xa, npage);
	if (!ctx_page) {
		ubaseproxy_err(udev,
			       "no find ctx page in free buf page, npage = %u.\n",
			       npage);
		mutex_unlock(&ctx_buf->ctx_mutex);
		return;
	}

	refcount_dec(&ctx_page->refcount);
	if (refcount_dec_if_one(&ctx_page->refcount)) {
		ubaseproxy_info(udev,
				"refcount of ctx page is equal to one and the ctx_page is going to be erased.\n");
		xa_erase(&ctx_buf->ctx_xa, npage);
		ubaseproxy_destroy_ctx_page(udev, ctx_buf, ctx_page);
	}

	mutex_unlock(&ctx_buf->ctx_mutex);
}

static int ubaseproxy_alloc_and_fill_ctx_buf(struct ubaseproxy_dev *udev,
					     struct ubase_ctx_buf_cap *ctx_buf,
					     struct ubase_mbx_attr *attr,
					     size_t size)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	size_t sizep;
	int ret;

	ctx_buf->cnt_per_page_shift =
		ilog2(roundup_pow_of_two(PAGE_SIZE / ctx_buf->entry_size));
	ctx_buf->slot = dma_alloc_iova(adev->dev.parent, size, 0,
				       &ctx_buf->dma_ctx_buf_ba, &sizep);
	if (IS_ERR(ctx_buf->slot)) {
		ret = PTR_ERR(ctx_buf->slot);
		ubaseproxy_err(udev,
			       "failed to alloc iova slot, cmd = 0x%x, size = %lu, ret = %d.\n",
			       attr->op, size, ret);
		return ret;
	}

	return 0;
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

static int ubaseproxy_config_ctx_buf_to_hw(struct ubaseproxy_dev *udev,
					   struct ubase_ctx_buf_cap *ctx_buf,
					   struct ubase_mbx_attr *attr)
{
	struct auxiliary_device *adev = udev->comdev.adev;
	struct ubase_cmd_mailbox mailbox;
	int ret;

	mailbox.dma = ctx_buf->dma_ctx_buf_ba;
	ret = ubase_hw_upgrade_ctx_for_proxy(adev, attr, &mailbox);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to config ctx_buf to hw, cmd = 0x%x, ret = %d.\n",
			       attr->op, ret);
	return ret;
}

static int ubaseproxy_cmd_ctx_buf_alloc(struct ubaseproxy_dev *udev,
					struct ubase_ctx_buf_cap *ctx_buf,
					struct ubase_mbx_attr *attr)
{
	size_t size = ctx_buf->entry_cnt * ctx_buf->entry_size;
	int ret;

	if (!size)
		return 0;

	xa_init(&ctx_buf->ctx_xa);
	ret = ubaseproxy_alloc_and_fill_ctx_buf(udev, ctx_buf, attr, size);
	if (ret)
		goto err_ctx_alloc;

	ret = ubaseproxy_config_ctx_buf_to_hw(udev, ctx_buf, attr);
	if (ret)
		goto err_ctx_to_hw;

	return 0;

err_ctx_to_hw:
	ubaseproxy_free_and_clear_ctx_buf(udev, ctx_buf);
err_ctx_alloc:
	xa_destroy(&ctx_buf->ctx_xa);

	return ret;
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

	for (i = 0; i < managed_ue_num; i++) {
		mutex_init(&udev->ue_res_info[i].ue_ctx_buf.jfs.ctx_mutex);
		mutex_init(&udev->ue_res_info[i].ue_ctx_buf.jfr.ctx_mutex);
		mutex_init(&udev->ue_res_info[i].ue_ctx_buf.jfc.ctx_mutex);
		mutex_init(&udev->ue_res_info[i].ue_ctx_buf.jtg.ctx_mutex);
		mutex_init(&udev->ue_res_info[i].ue_ctx_buf.rc.ctx_mutex);
		spin_lock_init(&udev->ue_res_info[i].ue_seid_table.seid_lock);
	}
}

static void ubaseproxy_uninit_res_info_lock(struct ubaseproxy_dev *udev)
{
	struct ubase_caps *ubase_caps = ubase_get_dev_caps(udev->comdev.adev);
	u8 managed_ue_num = ubase_caps->ue_num - 1, i;

	for (i = 0; i < managed_ue_num; i++) {
		mutex_destroy(&udev->ue_res_info[i].ue_ctx_buf.jfs.ctx_mutex);
		mutex_destroy(&udev->ue_res_info[i].ue_ctx_buf.jfr.ctx_mutex);
		mutex_destroy(&udev->ue_res_info[i].ue_ctx_buf.jfc.ctx_mutex);
		mutex_destroy(&udev->ue_res_info[i].ue_ctx_buf.jtg.ctx_mutex);
		mutex_destroy(&udev->ue_res_info[i].ue_ctx_buf.rc.ctx_mutex);
	}
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

	for (i = 0; i < managed_ue_num; i++) {
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.jfc);
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.jfr);
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.jetty);
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.jetty_grp);
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.aeq);
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.ceq);
		xa_init(&udev->ue_res_info[i].ue_ctx_xa.rc);
	}
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
	if (ret)
		return ret;

	ret = ubaseproxy_init_ue_jfr_ctx_default(udev);
	if (ret)
		goto err_init_jfr;

	ret = ubaseproxy_init_ue_jetty_ctx_default(udev);
	if (ret)
		goto err_init_jetty;

	ret = ubaseproxy_init_ue_eq_ctx_default(udev);
	if (ret)
		goto err_init_eq;

	ret = ubaseproxy_init_ue_rc_ctx_default(udev);
	if (ret)
		goto err_init_rc;

	return 0;

err_init_rc:
	ubaseproxy_uninit_ue_eq_ctx_default(udev);
err_init_eq:
	ubaseproxy_uninit_ue_jetty_ctx_default(udev);
err_init_jetty:
	ubaseproxy_uninit_ue_jfr_ctx_default(udev);
err_init_jfr:
	ubaseproxy_uninit_ue_jfc_ctx_default(udev);
	return ret;
}

void ubaseproxy_ue_ctx_default_uninit(struct ubaseproxy_dev *udev)
{
	ubaseproxy_uninit_ue_rc_ctx_default(udev);
	ubaseproxy_uninit_ue_eq_ctx_default(udev);
	ubaseproxy_uninit_ue_jetty_ctx_default(udev);
	ubaseproxy_uninit_ue_jfr_ctx_default(udev);
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
	ubaseproxy_erase_rc_ctx_resources(udev, ue_ctx_xa);
	ubaseproxy_erase_common_ctx_resources(&ue_ctx_xa->aeq);
	ubaseproxy_erase_common_ctx_resources(&ue_ctx_xa->ceq);
	ubaseproxy_erase_jetty_ctx_resources(udev, ue_ctx_xa);
	ubaseproxy_erase_common_ctx_resources(&ue_ctx_xa->jetty_grp);
	ubaseproxy_erase_common_ctx_resources(&ue_ctx_xa->jfr);
	ubaseproxy_erase_common_ctx_resources(&ue_ctx_xa->jfc);
}

static void ubaseproxy_destroy_ue_ctx_xa(struct ubaseproxy_ue_ctx_xarray *ue_ctx_xa)
{
	xa_destroy(&ue_ctx_xa->rc);
	xa_destroy(&ue_ctx_xa->aeq);
	xa_destroy(&ue_ctx_xa->ceq);
	xa_destroy(&ue_ctx_xa->jetty);
	xa_destroy(&ue_ctx_xa->jetty_grp);
	xa_destroy(&ue_ctx_xa->jfr);
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

static void ubaseproxy_send_set_ctx_va_resp(struct ubaseproxy_dev *udev,
					    struct ubase_proxy_set_ctx_va_cmd *cmd,
					    int result)
{
	struct ubase_proxy_set_ctx_va_cmd resp = {0};
	struct ubase_cmd_buf in;
	int ret;

	resp.bus_ue_id = cmd->bus_ue_id;
	resp.mbx_ue_id = cmd->mbx_ue_id;
	resp.ctx_type = cmd->ctx_type;
	resp.result = (u16)(-result);

	ubase_fill_inout_buf(&in, UBASE_OPC_SET_CTX_VA_RESP, false, sizeof(resp),
			     &resp);
	ret = ubase_cmd_send_in(udev->comdev.adev, &in);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to send set ctx va resp, ctx type = %u, ret = %d.\n",
			       le16_to_cpu(cmd->ctx_type), ret);
}

static int ubaseproxy_set_ue_ctx_va(struct ubaseproxy_dev *udev,
				    struct ubase_proxy_set_ctx_va_cmd *cmd)
{
	u16 bus_ue_id = le16_to_cpu(cmd->bus_ue_id);
	u16 mbx_ue_id = le16_to_cpu(cmd->mbx_ue_id);
	u16 ctx_type = le16_to_cpu(cmd->ctx_type);
	struct ubaseproxy_ue_ctx_buf *ctx_buf;
	struct ubase_mbx_attr attr = {0};
	u16 bitmap = 1 << ctx_type;
	int ret;

	ctx_buf = ubaseproxy_get_ue_ctx_buf(udev, mbx_ue_id);
	UBASEPROXY_DEFINE_CTX_VA_BUFS(ctx_buf);

	attr.op = map[ctx_type].mb_cmd;
	attr.mbx_ue_id = mbx_ue_id;
	ret = ubaseproxy_cmd_ctx_buf_alloc(udev, map[ctx_type].ctx, &attr);
	if (ret) {
		ubaseproxy_err(udev,
			       "failed to alloc ue ctx va, ctx type = %u, mbx ue id = %u, ret = %d.\n",
			       ctx_type, mbx_ue_id, ret);
		goto out;
	}

	ret = ubaseproxy_update_ctx_va_status(udev, bus_ue_id, bitmap,
					      UBASEPROXY_CTX_VA_INTED);
	if (ret)
		ubaseproxy_err(udev,
			       "failed to update ctx va status when alloc, ctx type = %u, vf id = %u, ret = %d.\n",
			       ctx_type, mbx_ue_id, ret);

out:
	ubaseproxy_send_set_ctx_va_resp(udev, cmd, ret);

	return ret;
}

int ubaseproxy_handle_ue_ctx_va_req(void *dev, void *data, u32 len)
{
	struct ubase_proxy_set_ctx_va_cmd *cmd = data;
	struct auxiliary_device *adev = dev;
	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);
	u16 ctx_type;

	if (len != sizeof(*cmd)) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(cmd->mbx_ue_id),
				   ctx_msg_len,
				   "ubaseproxy handle ctx va event msg len error, len = %u.\n",
				   len);
		return -EINVAL;
	}

	ctx_type = le16_to_cpu(cmd->ctx_type);
	if (ctx_type >= UBASE_CTX_VA_TYPE_NUM) {
		ubaseproxy_risk_rl(udev, le16_to_cpu(cmd->mbx_ue_id),
				   ctx_ctx_type,
				   "ubaseproxy handle ctx va event ctx type error, ctx_type = %u.\n",
				   ctx_type);
		return -EINVAL;
	}

	return ubaseproxy_set_ue_ctx_va(udev, cmd);
}
