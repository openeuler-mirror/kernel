// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_cmd.h"

#include "xsc_reg_struct.h"
#include "xsc_fw.h"
#include "xsc_flow.h"

#include <linux/log2.h>

int xsc_alloc_iae_idx(struct xsc_core_device *dev, int *iae_idx)
{
	ACQUIRE_IA_LOCK(dev, *iae_idx);
	return *iae_idx != -1 ? 0 : -1;
}

void xsc_release_iae_idx(struct xsc_core_device *dev, int *iae_idx)
{
	RELEASE_IA_LOCK(dev, *iae_idx);
	*iae_idx = -1;
}

int xsc_get_iae_idx(struct xsc_core_device *dev)
{
	struct xsc_resources *res = get_xsc_res(dev);

	return res->iae_idx;
}

static int xsc_cmd_exec_create_mkey(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_create_mkey_mbox_out *resp = out;
	u32 mpt_idx = 0;

	if (alloc_mpt_entry(xdev, &mpt_idx))
		return -EINVAL;

	resp->mkey = cpu_to_be32(mpt_idx & 0xffffff);
	resp->hdr.status = 0;

	return 0;
}

int xsc_create_mkey(struct xsc_core_device *xdev, void *in, void *out)
{
	unsigned long flags;
	struct xsc_resources *xres = get_xsc_res(xdev);
	int ret = 0;

	xsc_acquire_lock(&xres->lock, &flags);
	ret = xsc_cmd_exec_create_mkey(xdev, in, out);
	xsc_release_lock(&xres->lock, flags);
	return ret;
}

static int xsc_cmd_exec_destroy_mkey(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_destroy_mkey_mbox_in *req = in;
	struct xsc_destroy_mkey_mbox_out *resp = out;
	u32 mkey = be32_to_cpu(req->mkey);
	u32 mpt_idx = xsc_mkey_to_idx(mkey);

	dealloc_mpt_entry(xdev, &mpt_idx);

	resp->hdr.status = 0;

	return 0;
}

int xsc_destroy_mkey(struct xsc_core_device *xdev, void *in, void *out)
{
	unsigned long flags;
	struct xsc_resources *xres = get_xsc_res(xdev);
	int ret = 0;

	xsc_acquire_lock(&xres->lock, &flags);
	ret = xsc_cmd_exec_destroy_mkey(xdev, in, out);
	xsc_release_lock(&xres->lock, flags);
	return ret;
}

static int xsc_cmd_exec_reg_mr(struct xsc_core_device *dev, void *in, void *out)
{
	struct xsc_register_mr_mbox_in *req = in;
	struct xsc_register_mr_mbox_out *resp = out;
	struct xsc_mpt_entry mpt_ent;
	u32 mpt_idx = 0;
	u32 mtt_base;
	u64 va = be64_to_cpu(req->req.va_base);
	u32 mem_size = be32_to_cpu(req->req.len);
	u32 pdn = be32_to_cpu(req->req.pdn);
	u32 key = be32_to_cpu(req->req.mkey);
	int pa_num = be32_to_cpu(req->req.pa_num);
	u32 *ptr;
	u64 reg_addr;
	int i;
	int reg_stride;

	if (pa_num && alloc_mtt_entry(dev, pa_num, &mtt_base))
		return -EINVAL;

	mpt_idx = xsc_mkey_to_idx(key);
	mpt_ent.va_l = va & 0xFFFFFFFF;
	mpt_ent.va_h = va >> 32;
	mpt_ent.mem_size = mem_size;
	mpt_ent.pdn = pdn;
	mpt_ent.key = key & 0xFF;
	mpt_ent.mtt_base = mtt_base;
	mpt_ent.acc = req->req.acc;
	mpt_ent.page_mode = req->req.page_mode;
	mpt_ent.mem_map_en = req->req.map_en;
	mpt_ent.rsv = 0;

	get_xsc_res(dev)->mpt_entry[mpt_idx].va = va;
	get_xsc_res(dev)->mpt_entry[mpt_idx].mtt_base = mtt_base;
	get_xsc_res(dev)->mpt_entry[mpt_idx].page_num = pa_num;

	ptr = (u32 *)&mpt_ent;
	reg_stride = REG_WIDTH_TO_STRIDE(MMC_MPT_TBL_MEM_WIDTH);
	reg_addr = MMC_MPT_TBL_MEM_ADDR +
		mpt_idx * roundup_pow_of_two(reg_stride);

	IA_WRITE_REG_MR(dev, reg_addr, ptr, sizeof(mpt_ent) / sizeof(u32),
			xsc_get_iae_idx(dev));

	xsc_core_dbg(dev, "reg mr, write mpt[%u]: va=%llx, mem_size=%u, pdn=%u\n",
		     mpt_idx, va, mpt_ent.mem_size, mpt_ent.pdn);
	xsc_core_dbg(dev, "key=%u, mtt_base=%u, acc=%u, page_mode=%u, mem_map_en=%u\n",
		     mpt_ent.key, mpt_ent.mtt_base, mpt_ent.acc,
		     mpt_ent.page_mode, mpt_ent.mem_map_en);

	for (i = 0; i < pa_num; i++) {
		u64 pa = req->req.pas[i];

		pa = be64_to_cpu(pa);
		pa = pa >> PAGE_SHIFT_4K;
		ptr = (u32 *)&pa;
		reg_addr = MMC_MTT_TBL_MEM_ADDR +
			(mtt_base + i) * REG_WIDTH_TO_STRIDE(MMC_MTT_TBL_MEM_WIDTH);

		IA_WRITE_REG_MR(dev, reg_addr, ptr, sizeof(pa) / sizeof(u32),
				xsc_get_iae_idx(dev));

		xsc_core_dbg(dev, "reg mr, write mtt: pa[%u]=%llx\n", i, pa);
	}

	resp->hdr.status = 0;
	return 0;
}

int xsc_reg_mr(struct xsc_core_device *xdev, void *in, void *out)
{
	unsigned long flags;
	struct xsc_resources *xres = get_xsc_res(xdev);
	int ret;

	xsc_acquire_lock(&xres->lock, &flags);
	ret = xsc_cmd_exec_reg_mr(xdev, in, out);
	xsc_release_lock(&xres->lock, flags);
	return ret;
}

static int xsc_cmd_exec_dereg_mr(struct xsc_core_device *dev, void *in, void *out)
{
	struct xsc_unregister_mr_mbox_in *req;
	struct xsc_unregister_mr_mbox_out *resp;
	u32 mpt_idx;
	u32 mtt_base;
	int pages_num;

	req = in;
	resp = out;
	resp->hdr.status = -EINVAL;

	mpt_idx = be32_to_cpu(req->mkey);
	xsc_core_dbg(dev, "mpt idx:%u\n", mpt_idx);

	pages_num = get_xsc_res(dev)->mpt_entry[mpt_idx].page_num;
	mtt_base = get_xsc_res(dev)->mpt_entry[mpt_idx].mtt_base;
	if (pages_num > 0)
		dealloc_mtt_entry(dev, pages_num, mtt_base);

	resp->hdr.status = 0;
	return 0;
}

int xsc_dereg_mr(struct xsc_core_device *xdev, void *in, void *out)
{
	unsigned long flags;
	struct xsc_resources *xres = get_xsc_res(xdev);
	int ret;

	xsc_acquire_lock(&xres->lock, &flags);
	ret = xsc_cmd_exec_dereg_mr(xdev, in, out);
	xsc_release_lock(&xres->lock, flags);
	return ret;
}

static int xsc_cmd_exec_ioctl_flow(struct xsc_core_device *dev,
				   void *in, void *out)
{
	struct xsc_ioctl_mbox_in *req;
	struct xsc_ioctl_mbox_out *resp;
	struct xsc_ioctl_data_tl *tl;
	char *data;
	u16 datalen;
	u16 tllen = sizeof(struct xsc_ioctl_data_tl);
	int opmod;
	int table;
	int length;
	int ret  = -EINVAL;

	req = in;
	resp = out;
	resp->hdr.status = -EINVAL;

	data = (char *)req->data;
	datalen = be16_to_cpu(req->len);

	if (datalen < tllen)
		goto out;

	tl = (struct xsc_ioctl_data_tl *)data;
	opmod = tl->opmod;
	table = tl->table;
	length = tl->length;

	switch (opmod) {
	case XSC_IOCTL_OP_ADD:
		ret = xsc_flow_add(dev, table, length, tl + 1);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	xsc_core_dbg(dev, "table=%d, opcode=0x%x, ret=%d\n", table, opmod, ret);

out:
	resp->hdr.status = 0;
	resp->error = cpu_to_be32(ret);
	return ret;
}

int xsc_cmd_write_reg_directly(struct xsc_core_device *dev, void *in, int in_size, void *out,
			       int out_size, int func_id)
{
	int opcode, ret = 0;
	unsigned long flags;
	struct xsc_inbox_hdr *hdr;

	hdr = (struct xsc_inbox_hdr *)in;
	opcode = be16_to_cpu(hdr->opcode);
	xsc_core_dbg(dev, "opcode: %x\n", opcode);

	xsc_acquire_lock(&dev->reg_access_lock, &flags);
	switch (opcode) {
	case XSC_CMD_OP_IOCTL_FLOW:
		ret = xsc_cmd_exec_ioctl_flow(dev, in, out);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	/* ensure pci sequence */
	xsc_mmiowb();

	xsc_release_lock(&dev->reg_access_lock, flags);

	return ret;
}

