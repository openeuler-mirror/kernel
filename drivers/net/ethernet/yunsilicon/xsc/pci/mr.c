// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "common/driver.h"
#include "common/xsc_cmd.h"

int xsc_core_create_mkey(struct xsc_core_device *dev, struct xsc_core_mr *mr)
{
	struct xsc_create_mkey_mbox_in in;
	struct xsc_create_mkey_mbox_out out;
	int err;
	u8 key;

	memset(&out, 0, sizeof(out));
	spin_lock(&dev->dev_res->mkey_lock);
	key = 0x80 + dev->dev_res->mkey_key++;
	spin_unlock(&dev->dev_res->mkey_lock);
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_MKEY);
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
#else
	err = xsc_create_mkey(dev, &in, &out);
#endif
	if (err) {
		xsc_core_err(dev, "cmd exec faile %d\n", err);
		return err;
	}

	if (out.hdr.status) {
		xsc_core_err(dev, "status %d\n", out.hdr.status);
		return xsc_cmd_status_to_err(&out.hdr);
	}

	mr->key = xsc_idx_to_mkey(be32_to_cpu(out.mkey) & 0xffffff) | key;
	xsc_core_dbg(dev, "out 0x%x, key 0x%x, mkey 0x%x\n", be32_to_cpu(out.mkey), key, mr->key);

	return err;
}
EXPORT_SYMBOL(xsc_core_create_mkey);

int xsc_core_destroy_mkey(struct xsc_core_device *dev, struct xsc_core_mr *mr)
{
	struct xsc_destroy_mkey_mbox_in in;
	struct xsc_destroy_mkey_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_MKEY);
	in.mkey = cpu_to_be32(mr->key);
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
#else
	err = xsc_destroy_mkey(dev, &in, &out);
#endif
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	return err;
}
EXPORT_SYMBOL(xsc_core_destroy_mkey);

#ifdef REG_MR_VIA_CMDQ
int xsc_set_mpt_via_cmdq(struct xsc_core_device *dev, struct xsc_register_mr_mbox_in *in_cmd,
			 u32 *mtt_base)
{
	struct xsc_set_mpt_mbox_in *in;
	struct xsc_set_mpt_mbox_out out;
	struct xsc_register_mr_request *req = &in_cmd->req;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		return err;
	}
	in->mpt_item.pdn = req->pdn;
	in->mpt_item.pa_num = req->pa_num;
	in->mpt_item.len = req->len;
	in->mpt_item.mkey = req->mkey;
	in->mpt_item.acc = req->acc;
	in->mpt_item.page_mode = req->page_mode;
	in->mpt_item.map_en = req->map_en;
	in->mpt_item.va_base = req->va_base;
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_MPT);
	memset(&out, 0, sizeof(out));
	err = xsc_cmd_exec(dev, in, sizeof(*in), &out, sizeof(out));
	if (err) {
		xsc_core_err(dev, "set mpt failed\n");
		kfree(in);
		return err;
	}
	*mtt_base = be32_to_cpu(out.mtt_base);
	kfree(in);
	return 0;
}

int xsc_set_mtt_via_cmdq(struct xsc_core_device *dev, struct xsc_register_mr_mbox_in *in_cmd,
			 u32 mtt_base)
{
#define PA_NUM_PER_CMD 1024
	struct xsc_set_mtt_mbox_in *seg_in;
	struct xsc_set_mtt_mbox_out seg_out;
	struct xsc_register_mr_request *req = &in_cmd->req;
	int tot_pg_num = be32_to_cpu(req->pa_num);
	int seg_idx, tot_seg_num, seg_pa_num;
	int pa_idx_base = 0;
	int i;
	int in_len;
	int err;

	tot_seg_num = (tot_pg_num & 0x7FF) ? ((tot_pg_num >> 10) + 1) :
				  (tot_pg_num >> 10);
	for (seg_idx = 0; seg_idx < tot_seg_num; seg_idx++) {
		seg_pa_num = (seg_idx != tot_seg_num - 1) ? PA_NUM_PER_CMD :
					 (tot_pg_num - ((tot_seg_num - 1) << 10));
		in_len = (seg_pa_num << 3) + sizeof(*seg_in);
		seg_in = kzalloc(in_len, GFP_KERNEL);
		if (!seg_in) {
			err = -ENOMEM;
			return err;
		}
		seg_in->mtt_setting.mtt_base = cpu_to_be32(mtt_base);
		seg_in->mtt_setting.pa_num = cpu_to_be32(seg_pa_num);
		for (i = 0; i < seg_pa_num; i++)
			seg_in->mtt_setting.pas[i] = req->pas[pa_idx_base + i];
		seg_in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_MTT);

		memset(&seg_out, 0, sizeof(seg_out));
		xsc_core_dbg(dev, "set mtt seg %d, pa_num %d, pa_idx_base %d, tot_seg %d\n",
			     seg_idx, seg_pa_num, pa_idx_base, tot_seg_num);
		err = xsc_cmd_exec(dev, seg_in, in_len, &seg_out, sizeof(seg_out));
		if (err) {
			xsc_core_err(dev, "set mtt seg %d failed\n", seg_idx);
			kfree(seg_in);
			return err;
		}
		kfree(seg_in);
		pa_idx_base += seg_pa_num;
		mtt_base += seg_pa_num;
	}
	return 0;
}

int xsc_dereg_mr_via_cmdq(struct xsc_core_device *dev,  struct xsc_register_mr_mbox_in *in_cmd)
{
	struct xsc_unregister_mr_mbox_in in;
	struct xsc_unregister_mr_mbox_out out;
	int err;

	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEREG_MR);
	in.mkey = in_cmd->req.mkey;
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err) {
		xsc_core_err(dev, "cmd exec failed %d\n", err);
		return err;
	}
	return 0;
}

int xsc_reg_mr_via_cmdq(struct xsc_core_device *dev, struct xsc_register_mr_mbox_in *in)
{
	u32 mtt_base;
	int err;

	err = xsc_set_mpt_via_cmdq(dev, in, &mtt_base);
	if (err) {
		xsc_core_err(dev, "set mpt via cmdq failed\n");
		return err;
	}

	err = xsc_set_mtt_via_cmdq(dev, in, mtt_base);
	if (err) {
		xsc_core_err(dev, "set mtt via cmdq failed\n");
		goto set_mtt_err;
	}
	return 0;

set_mtt_err:
	err = xsc_dereg_mr_via_cmdq(dev, in);
	if (err)
		xsc_core_err(dev, "dereg error mr failed\n");
	return err;
}
#endif

int xsc_core_register_mr(struct xsc_core_device *dev, struct xsc_core_mr *mr,
			 struct xsc_register_mr_mbox_in *in, int inlen)
{
	struct xsc_register_mr_mbox_out out;
	int err;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_REG_MR);
#ifdef REG_MR_VIA_CMDQ
	err = xsc_reg_mr_via_cmdq(dev, in);
#else
	err = xsc_reg_mr(dev, in, &out);
#endif
	if (err) {
		xsc_core_err(dev, "cmd exec failed %d\n", err);
		return err;
	}
	if (out.hdr.status) {
		xsc_core_err(dev, "status %d\n", out.hdr.status);
		return xsc_cmd_status_to_err(&out.hdr);
	}

	return 0;
}
EXPORT_SYMBOL(xsc_core_register_mr);

int xsc_core_dereg_mr(struct xsc_core_device *dev, struct xsc_core_mr *mr)
{
	struct xsc_unregister_mr_mbox_in in;
	struct xsc_unregister_mr_mbox_out out;
	int err;

	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEREG_MR);
	in.mkey = cpu_to_be32(xsc_mkey_to_idx(mr->key));
#ifdef REG_MR_VIA_CMDQ
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
#else
	err = xsc_dereg_mr(dev, &in, &out);
#endif
	if (err) {
		xsc_core_err(dev, "cmd exec failed %d\n", err);
		return err;
	}
	if (out.hdr.status) {
		xsc_core_err(dev, "status %d\n", out.hdr.status);
		return xsc_cmd_status_to_err(&out.hdr);
	}

	return 0;
}
EXPORT_SYMBOL(xsc_core_dereg_mr);

