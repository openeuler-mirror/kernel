// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <common/xsc_core.h>
#include <common/xsc_ioctl.h>
#include <common/xsc_hsi.h>
#include <common/xsc_lag.h>
#include <common/xsc_port_ctrl.h>

#define FEATURE_ONCHIP_FT_MASK		(1<<4)
#define FEATURE_DMA_RW_TBL_MASK		(1<<8)
#define FEATURE_PCT_EXP_MASK		(1<<9)

#define XSC_PCI_CTRL_NAME "pci_ctrl"

static int xsc_pci_ctrl_modify_qp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0, i = 0;
	struct xsc_ioctl_qp_range *resp;
	struct xsc_ioctl_data_tl *tl;
	int insize;
	struct xsc_modify_qp_mbox_in *mailin;
	struct xsc_modify_qp_mbox_out mailout;
	u32 qpn;

	tl = (struct xsc_ioctl_data_tl *)out;
	resp = (struct xsc_ioctl_qp_range *)(tl + 1);
	xsc_core_dbg(xdev, "xsc_ioctl_qp_range: qpn:%d, num:%d, opcode:%d\n",
		resp->qpn, resp->num, resp->opcode);
	if (resp->num == 0) {
		xsc_core_dbg(xdev, "xsc_ioctl_qp_range: resp->num ==0\n");
		return 0;
	}
	qpn = resp->qpn;
	insize = sizeof(struct xsc_modify_qp_mbox_in);
	mailin = kvzalloc(insize, GFP_KERNEL);
	if (!mailin) {
		xsc_core_dbg(xdev, "xsc_ioctl_qp_range: enomem\n");
		return -ENOMEM;
	}
	if (resp->opcode == XSC_CMD_OP_RTR2RTS_QP) {
		for (i = 0; i < resp->num; i++) {
			mailin->hdr.opcode = cpu_to_be16(XSC_CMD_OP_RTR2RTS_QP);
			mailin->qpn = cpu_to_be32(qpn + 0);
			ret = xsc_cmd_exec(xdev, mailin, insize, &mailout, sizeof(mailout));
			xsc_core_dbg(xdev, "modify qp state qpn:%d\n", qpn + i);
		}
	}

	kvfree(mailin);

	return ret;
}

static int xsc_pci_ctrl_get_phy(struct xsc_core_device *xdev,
	void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_data_tl *tl = (struct xsc_ioctl_data_tl *)out;
	struct xsc_ioctl_get_phy_info_res *resp;
	struct xsc_ioctl_get_vf_info_res *vf_res;
	struct xsc_vf_info vf_info;
	struct xsc_lag *ldev = xsc_lag_dev_get(xdev);
	u16 lag_id = U16_MAX;

	if (ldev && __xsc_lag_is_active(ldev))
		lag_id = ldev->lag_id;

	switch (tl->opmod) {
	case XSC_IOCTL_OP_GET_LOCAL:
		resp = (struct xsc_ioctl_get_phy_info_res *)(tl + 1);

		resp->phy_port = xdev->pcie_port;
		resp->func_id = xdev->glb_func_id;
		resp->logic_in_port = xdev->logic_port;
		resp->mac_phy_port = xdev->mac_port;
		resp->mac_logic_in_port = xdev->mac_logic_port;
		resp->lag_id = lag_id;
		resp->raw_qp_id_base = xdev->caps.raweth_qp_id_base;
		resp->lag_port_start = XSC_LAG_PORT_START;
		resp->send_seg_num = xdev->caps.send_ds_num;
		resp->recv_seg_num = xdev->caps.recv_ds_num;
		resp->raw_tpe_qp_num = xdev->caps.raw_tpe_qp_num;
		resp->chip_version = xdev->chip_ver_l;
		resp->on_chip_tbl_vld =
				(xdev->feature_flag & FEATURE_ONCHIP_FT_MASK) ? 1 : 0;
		resp->dma_rw_tbl_vld =
				(xdev->feature_flag & FEATURE_DMA_RW_TBL_MASK) ? 1 : 0;
		resp->pct_compress_vld =
				(xdev->feature_flag & FEATURE_PCT_EXP_MASK) ? 1 : 0;

		xsc_core_dbg(xdev, "%d,%d,%d,%d,%d,%d\n", resp->phy_port,
			resp->func_id, resp->logic_in_port,
			resp->mac_phy_port, resp->mac_logic_in_port,
			resp->lag_id);
		resp->funcid_encode[0] = XSC_PCIE0_VF0_FUNC_ID;
		resp->funcid_encode[1] = XSC_PCIE0_VF_FUNC_ID_END;
		resp->funcid_encode[2] = XSC_PCIE0_PF0_FUNC_ID;
		resp->funcid_encode[3] = XSC_PCIE0_PF_FUNC_ID_END;
		resp->funcid_encode[4] = XSC_PCIE1_VF0_FUNC_ID;
		resp->funcid_encode[5] = XSC_PCIE1_VF_FUNC_ID_END;
		resp->funcid_encode[6] = XSC_PCIE1_PF0_FUNC_ID;
		resp->funcid_encode[7] = XSC_PCIE1_PF_FUNC_ID_END;
		break;

	case XSC_IOCTL_OP_GET_VF_INFO:
		vf_res = (struct xsc_ioctl_get_vf_info_res *)(tl + 1);
		memcpy(&vf_info, vf_res, sizeof(struct xsc_vf_info));

		xsc_pci_get_vf_info(xdev, &vf_info);

		vf_res->func_id = vf_info.func_id;
		vf_res->logic_port = vf_info.logic_port;
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int xsc_pci_ctrl_get_contextinfo(struct xsc_core_device *xdev,
	void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_data_tl *tl = (struct xsc_ioctl_data_tl *)out;
	struct xsc_alloc_ucontext_resp *resp;

	if (tl->opmod != XSC_IOCTL_OP_GET_CONTEXT)
		ret = -EINVAL;

	resp = (struct xsc_alloc_ucontext_resp *)(tl + 1);

	// resp->qp_tab_size      = 1 << xdev->caps.log_max_qp;
	// resp->cache_line_size  = L1_CACHE_BYTES;
	// resp->max_sq_desc_sz = xdev->caps.max_sq_desc_sz;
	// resp->max_rq_desc_sz = xdev->caps.max_rq_desc_sz;
	// resp->max_send_wqebb = xdev->caps.max_wqes;
	// resp->max_recv_wr = xdev->caps.max_wqes;

	resp->max_cq = 1 << xdev->caps.log_max_cq;
	resp->max_qp = 1 << xdev->caps.log_max_qp;
	resp->max_rwq_indirection_table_size = xdev->caps.max_rwq_indirection_table_size;
	resp->qpm_tx_db = xdev->regs.tx_db;
	resp->qpm_rx_db = xdev->regs.rx_db;
	resp->cqm_next_cid_reg = xdev->regs.complete_reg;
	resp->cqm_armdb = xdev->regs.complete_db;
	resp->send_ds_num = xdev->caps.send_ds_num;
	resp->recv_ds_num = xdev->caps.recv_ds_num;
	resp->send_ds_shift = xdev->caps.send_wqe_shift;
	resp->recv_ds_shift = xdev->caps.recv_wqe_shift;
	resp->glb_func_id = xdev->glb_func_id;

	resp->max_wqes = xdev->caps.max_wqes;

	xsc_core_dbg(xdev, "xsc_tdi_alloc_context:\n");
	xsc_core_dbg(xdev, "resp->max_cq=%u\n", resp->max_cq);
	xsc_core_dbg(xdev, "resp->max_qp=%u\n", resp->max_qp);
	xsc_core_dbg(xdev, "resp->qpm_tx_db=%llx\n", resp->qpm_tx_db);
	xsc_core_dbg(xdev, "resp->qpm_rx_db=%llx\n", resp->qpm_rx_db);
	xsc_core_dbg(xdev, "resp->cqm_next_cid_reg=%llx\n", resp->cqm_next_cid_reg);
	xsc_core_dbg(xdev, "resp->cqm_armdb=%llx\n", resp->cqm_armdb);
	xsc_core_dbg(xdev, "resp->send_ds_num=%u\n", resp->send_ds_num);
	xsc_core_dbg(xdev, "resp->send_ds_shift=%u\n", resp->send_ds_shift);
	xsc_core_dbg(xdev, "resp->:recv_ds_num=%u\n", resp->recv_ds_num);
	xsc_core_dbg(xdev, "resp->recv_ds_shift=%u\n", resp->recv_ds_shift);
	xsc_core_dbg(xdev, "resp->glb_func_id=%u\n", resp->glb_func_id);

	return ret;
}

int xsc_pci_ctrl_exec_ioctl(struct xsc_core_device *xdev, void *in, int in_size, void *out,
		 int out_size)
{
	int opcode, ret = 0;
	struct xsc_ioctl_attr *hdr;

	hdr = (struct xsc_ioctl_attr *)in;
	opcode = hdr->opcode;
	switch (opcode) {
	case XSC_IOCTL_GET_PHY_INFO:
		ret = xsc_pci_ctrl_get_phy(xdev, in, out);
		break;
	case XSC_IOCTL_SET_QP_STATUS:
		xsc_core_dbg(xdev, "case XSC_IOCTL_SET_QP_STATUS:\n");
		ret = xsc_pci_ctrl_modify_qp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_CONTEXT:
		xsc_core_dbg(xdev, "case XSC_IOCTL_GET_CONTEXT:\n");
		ret = xsc_pci_ctrl_get_contextinfo(xdev, in, out);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static long xsc_pci_ctrl_getinfo(struct xsc_core_device *xdev,
				struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	struct xsc_ioctl_hdr *in;
	int in_size;
	int err;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_GET_PHY_INFO:
	case XSC_IOCTL_SET_QP_STATUS:
	case XSC_IOCTL_GET_CONTEXT:
		break;
	default:
		return -EINVAL;
	}
	in_size = sizeof(struct xsc_ioctl_hdr) + hdr.attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -EFAULT;
	in->attr.opcode = hdr.attr.opcode;
	in->attr.length = hdr.attr.length;
	err = copy_from_user(in->attr.data, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}
	err = xsc_pci_ctrl_exec_ioctl(xdev, &in->attr, (in_size-sizeof(u32)), in->attr.data,
		hdr.attr.length);
	in->attr.error = err;
	if (copy_to_user((void *)user_hdr, in, in_size))
		err = -EFAULT;
	kvfree(in);
	return err;
}

static int xsc_ioctl_flow_cmdq(struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mbox_in *in;
	struct xsc_ioctl_mbox_out *out;
	int in_size;
	int out_size;
	int err;

	in_size = sizeof(struct xsc_ioctl_mbox_in) + hdr->attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -EFAULT;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->len = __cpu_to_be16(hdr->attr.length);
	err = copy_from_user(in->data, user_hdr->attr.data, hdr->attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}

	out_size = sizeof(struct xsc_ioctl_mbox_out) + hdr->attr.length;
	out = kvzalloc(out_size, GFP_KERNEL);
	if (!out) {
		kvfree(in);
		return -ENOMEM;
	}
	memcpy(out->data, in->data, hdr->attr.length);
	out->len = in->len;
	err = xsc_cmd_exec(xdev, in, in_size, out, out_size);

	hdr->attr.error = __be32_to_cpu(out->error);
	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, out->data, hdr->attr.length))
		err = -EFAULT;

	kvfree(in);
	kvfree(out);
	return err;
}

static int xsc_ioctl_modify_raw_qp(struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_modify_raw_qp_mbox_in *in;
	struct xsc_modify_raw_qp_mbox_out *out;
	int err;

	if (hdr->attr.length != sizeof(struct xsc_modify_raw_qp_request))
		return -EINVAL;

	in = kvzalloc(sizeof(struct xsc_modify_raw_qp_mbox_in), GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(struct xsc_modify_raw_qp_mbox_out), GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->req, user_hdr->attr.data,
		sizeof(struct xsc_modify_raw_qp_request));
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->pcie_no = xsc_get_pcie_no();

	err = xsc_cmd_exec(xdev, in, sizeof(struct xsc_modify_raw_qp_mbox_in),
		out, sizeof(struct xsc_modify_raw_qp_mbox_out));

	hdr->attr.error = __be32_to_cpu(out->hdr.status);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static long xsc_pci_ctrl_cmdq(struct xsc_core_device *xdev,
				struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	int err;
	void *in;
	void *out;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_CMD_OP_IOCTL_FLOW:
		return xsc_ioctl_flow_cmdq(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_MODIFY_RAW_QP:
		return xsc_ioctl_modify_raw_qp(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_CREATE_QP:
		break;
	case XSC_CMD_OP_DESTROY_QP:
		break;
	case XSC_CMD_OP_2RST_QP:
		break;
	case XSC_CMD_OP_CREATE_CQ:
		break;
	case XSC_CMD_OP_DESTROY_CQ:
		break;
	case XSC_CMD_OP_CREATE_MULTI_QP:
		break;
	case XSC_CMD_OP_ALLOC_MULTI_VIRTQ_CQ:
		break;
	case XSC_CMD_OP_RELEASE_MULTI_VIRTQ_CQ:
		break;
	case XSC_CMD_OP_ALLOC_MULTI_VIRTQ:
		break;
	case XSC_CMD_OP_RELEASE_MULTI_VIRTQ:
		break;

	default:
		return -EINVAL;
	}

	in = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	err = copy_from_user(in, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		err = -EFAULT;
		goto err_exit;
	}

	xsc_cmd_exec(xdev, in, hdr.attr.length, out, hdr.attr.length);
	if (copy_to_user((void *)user_hdr->attr.data, out, hdr.attr.length))
		err = -EFAULT;
err_exit:
	kfree(in);
	kfree(out);
	return err;
}

static void xsc_pci_ctrl_reg_cb(struct xsc_core_device *xdev, unsigned int cmd,
			struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = xsc_pci_ctrl_cmdq(xdev, user_hdr);
		break;
	case XSC_IOCTL_DRV_GET:
	case XSC_IOCTL_DRV_SET:
		err = xsc_pci_ctrl_getinfo(xdev, user_hdr);
		break;
	default:
		err = -EFAULT;
		break;
	}
}

void xsc_pci_ctrl_fini(void)
{
	xsc_port_ctrl_cb_dereg(XSC_PCI_CTRL_NAME);
}

int xsc_pci_ctrl_init(void)
{
	int ret;

	ret = xsc_port_ctrl_cb_reg(XSC_PCI_CTRL_NAME, xsc_pci_ctrl_reg_cb, NULL);
	if (ret != 0)
		pr_err("failed to register port control node for %s\n", XSC_PCI_CTRL_NAME);

	return ret;
}
