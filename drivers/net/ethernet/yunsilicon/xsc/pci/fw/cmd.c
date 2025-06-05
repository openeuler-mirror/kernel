// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_cmd.h"

#include "xsc_fw.h"
#include "xsc_flow.h"

#include <linux/log2.h>

static inline void xsc_iae_lock(struct xsc_core_device *dev, int grp)
{
	spin_lock_bh(&get_xsc_res(dev)->iae_lock[grp]);
}

static inline void xsc_iae_unlock(struct xsc_core_device *dev, int grp)
{
	spin_unlock_bh(&get_xsc_res(dev)->iae_lock[grp]);
}

static inline int xsc_iae_idx_get(struct xsc_core_device *dev, int grp)
{
	return get_xsc_res(dev)->iae_idx[grp];
}

static inline int xsc_iae_grp_get(struct xsc_core_device *dev)
{
	struct xsc_resources *xres = get_xsc_res(dev);

	return atomic_inc_return(&xres->iae_grp) & XSC_RES_IAE_GRP_MASK;
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

	spin_lock_irqsave(&xres->lock, flags);
	ret = xsc_cmd_exec_create_mkey(xdev, in, out);
	spin_unlock_irqrestore(&xres->lock, flags);
	return ret;
}

static int xsc_cmd_exec_destroy_mkey(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_destroy_mkey_mbox_in *req = in;
	struct xsc_destroy_mkey_mbox_out *resp = out;
	u32 mkey = be32_to_cpu(req->mkey);
	u32 mpt_idx = xsc_mkey_to_idx(xdev, mkey);

	dealloc_mpt_entry(xdev, &mpt_idx);

	resp->hdr.status = 0;

	return 0;
}

int xsc_destroy_mkey(struct xsc_core_device *xdev, void *in, void *out)
{
	unsigned long flags;
	struct xsc_resources *xres = get_xsc_res(xdev);
	int ret = 0;

	spin_lock_irqsave(&xres->lock, flags);
	ret = xsc_cmd_exec_destroy_mkey(xdev, in, out);
	spin_unlock_irqrestore(&xres->lock, flags);
	return ret;
}

static int xsc_cmd_exec_reg_mr(struct xsc_core_device *dev, void *in, void *out)
{
	struct xsc_register_mr_mbox_in *req = in;
	struct xsc_register_mr_mbox_out *resp = out;
	u32 mtt_base;
	u64 va = be64_to_cpu(req->req.va_base);
	u32 key = be32_to_cpu(req->req.mkey);
	u32 mpt_idx = xsc_mkey_to_idx(dev, key);
	int pa_num = be32_to_cpu(req->req.pa_num);
	int iae_idx, iae_grp;

	if (pa_num && alloc_mtt_entry(dev, pa_num, &mtt_base))
		return -EINVAL;

	xsc_core_info(dev, "mpt idx:%u,va=0x%llx, mtt_base=%d, pa_num=%d\n",
		      mpt_idx, va, mtt_base, pa_num);

	get_xsc_res(dev)->mpt_entry[mpt_idx].va = va;
	get_xsc_res(dev)->mpt_entry[mpt_idx].mtt_base = mtt_base;
	get_xsc_res(dev)->mpt_entry[mpt_idx].page_num = pa_num;

	iae_grp = xsc_iae_grp_get(dev);
	iae_idx = xsc_iae_idx_get(dev, iae_grp);

	xsc_iae_lock(dev, iae_grp);
	xsc_set_mpt(dev, iae_idx, mtt_base, &req->req);
	xsc_set_mtt(dev, iae_idx, mtt_base, &req->req);
	xsc_iae_unlock(dev, iae_grp);

	resp->hdr.status = 0;
	return 0;
}

void xsc_sync_mr_to_fw(struct xsc_core_device *dev)
{
	struct xsc_cmd_sync_mr_to_fw_mbox_in *in;
	struct xsc_cmd_sync_mr_to_fw_mbox_out out;
	int mpt_idx;
	int max_sync_mr_num;
	int mr_num = 0;
	struct xsc_resources *xres = get_xsc_res(dev);

	max_sync_mr_num = (dev->caps.max_cmd_in_len - sizeof(*in)) / sizeof(struct xsc_mr_info);
	in = kvzalloc(dev->caps.max_cmd_in_len, GFP_KERNEL);
	if (!in)
		return;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SYNC_MR_TO_FW);
	mpt_idx = find_next_zero_bit((unsigned long *)xres->mpt_tbl, xres->max_mpt_num, 1);
	while (mpt_idx < xres->max_mpt_num) {
		in->data[mr_num].mpt_idx = cpu_to_be32(mpt_idx);
		in->data[mr_num].mtt_base = cpu_to_be32(xres->mpt_entry[mpt_idx].mtt_base);
		in->data[mr_num].mtt_num = cpu_to_be32(xres->mpt_entry[mpt_idx].page_num);
		mr_num++;
		if (mr_num == max_sync_mr_num) {
			in->mr_num = cpu_to_be16(mr_num);
			memset(&out, 0, sizeof(out));
			xsc_cmd_exec(dev, in, dev->caps.max_cmd_in_len, &out, sizeof(out));
			mr_num = 0;
		}
		mpt_idx = find_next_zero_bit((unsigned long *)xres->mpt_tbl,
					     xres->max_mpt_num, mpt_idx + 1);
	}

	if (!mr_num)
		goto out;

	in->mr_num = cpu_to_be16(mr_num);
	memset(&out, 0, sizeof(out));
	xsc_cmd_exec(dev, in, dev->caps.max_cmd_in_len, &out, sizeof(out));
out:
	kfree(in);
}

void xsc_sync_mr_from_fw(struct xsc_core_device *dev)
{
	struct xsc_cmd_sync_mr_from_fw_mbox_in in;
	struct xsc_cmd_sync_mr_from_fw_mbox_out *out;
	int max_sync_mr_num;
	int ret;
	int i = 0;
	struct xsc_resources *xres = get_xsc_res(dev);
	u32 mpt_idx = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SYNC_MR_FROM_FW);
	out = kvzalloc(dev->caps.max_cmd_out_len, GFP_KERNEL);
	if (!out)
		return;
	in.start = cpu_to_be32(1);
	ret = xsc_cmd_exec(dev, &in, sizeof(in), out, dev->caps.max_cmd_out_len);
	if (ret || out->hdr.status)
		goto out;
	max_sync_mr_num = (dev->caps.max_cmd_out_len - sizeof(*out)) / sizeof(struct xsc_mr_info);
	while (be16_to_cpu(out->mr_num) == max_sync_mr_num) {
		for (i = 0; i < max_sync_mr_num; i++) {
			mpt_idx = be32_to_cpu(out->data[i].mpt_idx);
			xres->mpt_entry[mpt_idx].mtt_base = be32_to_cpu(out->data[i].mtt_base);
			xres->mpt_entry[mpt_idx].page_num = be32_to_cpu(out->data[i].mtt_num);
			clear_bit(mpt_idx, (unsigned long *)xres->mpt_tbl);
			save_mtt_to_free_list(dev, xres->mpt_entry[mpt_idx].mtt_base,
					      xres->mpt_entry[mpt_idx].page_num);
		}
		in.start = cpu_to_be32(mpt_idx + 1);
		ret = xsc_cmd_exec(dev, &in, sizeof(in), out, dev->caps.max_cmd_out_len);
		if (ret || out->hdr.status)
			goto out;
	}
	for (i = 0; i < be16_to_cpu(out->mr_num); i++) {
		mpt_idx = be32_to_cpu(out->data[i].mpt_idx);
		xres->mpt_entry[mpt_idx].mtt_base = be32_to_cpu(out->data[i].mtt_base);
		xres->mpt_entry[mpt_idx].page_num = be32_to_cpu(out->data[i].mtt_num);
		clear_bit(mpt_idx, (unsigned long *)xres->mpt_tbl);
		save_mtt_to_free_list(dev, xres->mpt_entry[mpt_idx].mtt_base,
				      xres->mpt_entry[mpt_idx].page_num);
	}

out:
	kfree(out);
}

int xsc_reg_mr(struct xsc_core_device *xdev, void *in, void *out)
{
	return xsc_cmd_exec_reg_mr(xdev, in, out);
}

static int xsc_cmd_exec_dereg_mr(struct xsc_core_device *dev, void *in, void *out)
{
	struct xsc_unregister_mr_mbox_in *req;
	struct xsc_unregister_mr_mbox_out *resp;
	u64 va;
	u32 mpt_idx;
	u32 mtt_base = 0;
	int pages_num;
	int iae_idx, iae_grp;

	req = in;
	resp = out;
	resp->hdr.status = -EINVAL;

	mpt_idx = be32_to_cpu(req->mkey);
	xsc_core_info(dev, "mpt idx:%u\n", mpt_idx);

	/*clear mpt entry*/
	iae_grp = xsc_iae_grp_get(dev);
	iae_idx = xsc_iae_idx_get(dev, iae_grp);

	xsc_iae_lock(dev, iae_grp);
	xsc_clear_mpt(dev, iae_idx, mtt_base, req);
	xsc_iae_unlock(dev, iae_grp);

	va = get_xsc_res(dev)->mpt_entry[mpt_idx].va;
	pages_num = get_xsc_res(dev)->mpt_entry[mpt_idx].page_num;
	mtt_base = get_xsc_res(dev)->mpt_entry[mpt_idx].mtt_base;
	if (pages_num > 0) {
		dealloc_mtt_entry(dev, pages_num, mtt_base);
		get_xsc_res(dev)->mpt_entry[mpt_idx].page_num = 0;
	} else {
		xsc_core_dbg(dev, "no mtt entries to be freed, mpt_idx=%d\n", mpt_idx);
	}

	resp->hdr.status = 0;

	xsc_core_info(dev, "dereg mr, clear mpt[%u]: va=%llx\n",
		      mpt_idx, va);

	return 0;
}

int xsc_dereg_mr(struct xsc_core_device *xdev, void *in, void *out)
{
	return xsc_cmd_exec_dereg_mr(xdev, in, out);
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

	spin_lock_irqsave(&dev->reg_access_lock, flags);
	switch (opcode) {
	case XSC_CMD_OP_IOCTL_FLOW:
		ret = xsc_cmd_exec_ioctl_flow(dev, in, out);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	/* ensure pci sequence */
	mmiowb();

	spin_unlock_irqrestore(&dev->reg_access_lock, flags);

	return ret;
}

