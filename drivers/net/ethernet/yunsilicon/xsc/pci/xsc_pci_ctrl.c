// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/device.h>
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_hsi.h"
#include "common/xsc_lag.h"
#include "common/xsc_port_ctrl.h"
#include "common/qp.h"
#include "common/xsc_eswitch.h"
#include <linux/pci.h>
#include "xsc_pci_ctrl.h"
#include "common/res_obj.h"
#include "common/tunnel_cmd.h"

#define FEATURE_ONCHIP_FT_MASK		BIT(4)
#define FEATURE_DMA_RW_TBL_MASK		BIT(8)
#define FEATURE_PCT_EXP_MASK		BIT(19)

#define XSC_PCI_CTRL_NAME "pci_ctrl"

static int xsc_pci_ctrl_modify_qp(struct xsc_core_device *xdev, void *in, int in_size,
				  void *out, int out_size)
{
	int ret = 0, i = 0;
	struct xsc_ioctl_qp_range *resp;
	struct xsc_ioctl_data_tl *tl;
	int insize;
	struct xsc_modify_qp_mbox_in *mailin;
	struct xsc_modify_qp_mbox_out mailout;
	struct xsc_ioctl_hdr *hdr = (struct xsc_ioctl_hdr *)in;
	u32 qpn;

	if (out_size < sizeof(struct xsc_ioctl_data_tl) +
	    sizeof(struct xsc_ioctl_qp_range)) {
		xsc_core_err(xdev,
			     "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
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
	for (i = 0; i < resp->num; i++) {
		mailin->hdr.opcode = cpu_to_be16(resp->opcode);
		mailin->qpn = cpu_to_be32(qpn + i);
		ret = xsc_cmd_exec(xdev, mailin, insize, &mailout, sizeof(mailout));
		xsc_core_dbg(xdev, "modify qp state qpn:%d\n", qpn + i);
	}
	kvfree(mailin);

	if (mailout.hdr.status) {
		ret = xsc_cmd_status_to_err(&mailout.hdr);
		hdr->attr.error = mailout.hdr.status;
	}

	return ret;
}

static struct pci_dev *xsc_pci_get_pcidev_by_bus_and_slot(int domain, uint32_t bus, uint32_t devfn)
{
	return pci_get_domain_bus_and_slot(domain, bus, devfn);
}

struct xsc_core_device *xsc_pci_get_xdev_by_bus_and_slot(int domain, uint32_t bus, uint32_t devfn)
{
	struct pci_dev *pdev = NULL;
	struct xsc_core_device *xdev = NULL;

	pdev = xsc_pci_get_pcidev_by_bus_and_slot(domain, bus, devfn);
	if (!pdev)
		return NULL;

	if (pdev->vendor != XSC_PCI_VENDOR_ID &&
	    pdev->vendor != XSC_PCI_VENDOR_ID_CUSTOM) {
		pr_err("dismatch vendor id:%x\n", pdev->vendor);
		return NULL;
	}

	xdev = pci_get_drvdata(pdev);

	return xdev;
}

static int xsc_pci_ctrl_get_board_esw_info(struct xsc_core_device *xdev, void *out)
{
	struct xsc_ioctl_board_esw_info *info_tbl = (struct xsc_ioctl_board_esw_info *)out;

	xsc_get_board_esw_info(xdev, info_tbl);

	info_tbl->vf_funcid_base[0][0] =  xdev->caps.vf_funcid_base[0][0];
	info_tbl->vf_funcid_top[0][0] = xdev->caps.vf_funcid_top[0][0];
	info_tbl->vf_funcid_base[0][1] =  xdev->caps.vf_funcid_base[0][1];
	info_tbl->vf_funcid_top[0][1] = xdev->caps.vf_funcid_top[0][1];
	info_tbl->vf_funcid_base[1][0] = xdev->caps.vf_funcid_base[1][0];
	info_tbl->vf_funcid_top[1][0] = xdev->caps.vf_funcid_top[1][0];
	info_tbl->vf_funcid_base[1][1] = xdev->caps.vf_funcid_base[1][1];
	info_tbl->vf_funcid_top[1][1] = xdev->caps.vf_funcid_top[1][1];

	return 0;
}

static int xsc_cmd_query_aidpu_mode(struct xsc_core_device *xdev, uint32_t *mode)
{
	struct xsc_get_aidpu_mode_mbox_in in;
	struct xsc_get_aidpu_mode_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_AIDPU_MODE);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	*mode = out.aidpu_mode;

	return 0;
}

static int xsc_pci_ctrl_get_phy(struct xsc_core_device *xdev,
				void *in, int in_size, void *out, int out_size)
{
	int ret = 0;
	struct xsc_eswitch *esw = xdev->priv.eswitch;
	struct xsc_ioctl_data_tl *tl = (struct xsc_ioctl_data_tl *)out;
	struct xsc_ioctl_get_phy_info_res *resp;
	u16 lag_id;
	struct xsc_core_device *rl_xdev;
	u32 mode;

	if (out_size < sizeof(struct xsc_ioctl_data_tl)) {
		xsc_core_err(xdev,
			     "ioctl user data length input length is too small\n");
		return -EFAULT;
	}

	if (xsc_lag_is_kernel(xdev) && !xsc_lag_mode_support(xdev))
		lag_id = LAG_ID_INVALID;
	else
		lag_id = xsc_get_lag_id(xdev);

	switch (tl->opmod) {
	case XSC_IOCTL_OP_GET_LOCAL:
		if (out_size < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_ioctl_get_phy_info_res)) {
			xsc_core_err(xdev,
				     "ioctl user data length input length is too small\n");
			return -EFAULT;
		}
		resp = (struct xsc_ioctl_get_phy_info_res *)(tl + 1);

		resp->pcie_no = xdev->pcie_no;
		resp->func_id = xdev->glb_func_id;
		resp->pcie_host = xdev->caps.pcie_host;
		resp->mac_phy_port = xdev->mac_port;
		resp->funcid_to_logic_port_off = xdev->caps.funcid_to_logic_port;
		resp->lag_id = lag_id;
		resp->raw_qp_id_base = xdev->caps.raweth_qp_id_base;
		resp->raw_rss_qp_id_base = xdev->caps.raweth_rss_qp_id_base;
		resp->lag_port_start = xdev->caps.lag_logic_port_ofst;
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

		xsc_core_dbg(xdev, "%d,%d,%d,%d,%d,%d\n",
			     resp->pcie_no, resp->func_id, resp->pcie_host,
			     resp->mac_phy_port, resp->lag_id,
			     resp->funcid_to_logic_port_off);

		resp->pf0_vf_funcid_base = xdev->caps.pf0_vf_funcid_base;
		resp->pf0_vf_funcid_top  = xdev->caps.pf0_vf_funcid_top;
		resp->pf1_vf_funcid_base = xdev->caps.pf1_vf_funcid_base;
		resp->pf1_vf_funcid_top  = xdev->caps.pf1_vf_funcid_top;
		resp->pcie0_pf_funcid_base = xdev->caps.pcie0_pf_funcid_base;
		resp->pcie0_pf_funcid_top = xdev->caps.pcie0_pf_funcid_top;
		resp->pcie1_pf_funcid_base = xdev->caps.pcie1_pf_funcid_base;
		resp->pcie1_pf_funcid_top = xdev->caps.pcie1_pf_funcid_top;
		resp->hca_core_clock = xdev->caps.hca_core_clock;
		resp->mac_bit = xdev->caps.mac_bit;
		if (xsc_core_is_pf(xdev)) {
			down_write(&esw->mode_lock);
			resp->esw_mode = esw->mode;
			up_write(&esw->mode_lock);
		} else {
			resp->esw_mode = 0;
		}
		resp->board_id = xdev->board_info->board_id;
		ret = xsc_cmd_query_aidpu_mode(xdev, &mode);
		if (ret == 0)
			resp->aidpu_mode = mode;
		else
			ret = -EINVAL;
		break;

	case XSC_IOCTL_OP_GET_INFO_BY_BDF:
		if (out_size < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_ioctl_get_phy_info_res)) {
			xsc_core_err(xdev,
				     "ioctl user data length input length is too small\n");
			return -EFAULT;
		}
		resp = (struct xsc_ioctl_get_phy_info_res *)(tl + 1);

		xsc_core_dbg(xdev, "ioctrl get_pcidev. domain=%u, bus=%u, devfn=%u\n",
			     resp->domain, resp->bus, resp->devfn);

		rl_xdev = xsc_pci_get_xdev_by_bus_and_slot(resp->domain, resp->bus, resp->devfn);
		if (!rl_xdev)
			return -1;

		resp->pcie_no = rl_xdev->pcie_no;
		resp->func_id = rl_xdev->glb_func_id;
		resp->pcie_host = rl_xdev->caps.pcie_host;
		resp->mac_phy_port = rl_xdev->mac_port;
		resp->funcid_to_logic_port_off = rl_xdev->caps.funcid_to_logic_port;
		resp->lag_id = lag_id;
		resp->raw_qp_id_base = rl_xdev->caps.raweth_qp_id_base;
		resp->raw_rss_qp_id_base = xdev->caps.raweth_rss_qp_id_base;
		resp->lag_port_start = xdev->caps.lag_logic_port_ofst;
		resp->send_seg_num = rl_xdev->caps.send_ds_num;
		resp->recv_seg_num = rl_xdev->caps.recv_ds_num;
		resp->raw_tpe_qp_num = rl_xdev->caps.raw_tpe_qp_num;
		resp->chip_version = rl_xdev->chip_ver_l;
		resp->on_chip_tbl_vld =
				(rl_xdev->feature_flag & FEATURE_ONCHIP_FT_MASK) ? 1 : 0;
		resp->dma_rw_tbl_vld =
				(rl_xdev->feature_flag & FEATURE_DMA_RW_TBL_MASK) ? 1 : 0;
		resp->pct_compress_vld =
				(rl_xdev->feature_flag & FEATURE_PCT_EXP_MASK) ? 1 : 0;

		xsc_core_dbg(xdev, "%d,%d,%d,%d,%d,%d\n",
			     resp->pcie_no, resp->func_id, resp->pcie_host,
			     resp->mac_phy_port, resp->lag_id,
			     resp->funcid_to_logic_port_off);
		resp->pf0_vf_funcid_base = rl_xdev->caps.pf0_vf_funcid_base;
		resp->pf0_vf_funcid_top  = rl_xdev->caps.pf0_vf_funcid_top;
		resp->pf1_vf_funcid_base = rl_xdev->caps.pf1_vf_funcid_base;
		resp->pf1_vf_funcid_top  = rl_xdev->caps.pf1_vf_funcid_top;
		resp->pcie0_pf_funcid_base = rl_xdev->caps.pcie0_pf_funcid_base;
		resp->pcie0_pf_funcid_top  = rl_xdev->caps.pcie0_pf_funcid_top;
		resp->pcie1_pf_funcid_base = rl_xdev->caps.pcie1_pf_funcid_base;
		resp->pcie1_pf_funcid_top  = rl_xdev->caps.pcie1_pf_funcid_top;
		resp->board_id = xdev->board_info->board_id;
		break;
	case XSC_IOCTL_OP_GET_BOARD_ESW_INFO:
		if (out_size < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_ioctl_board_esw_info)) {
			xsc_core_err(xdev,
				     "ioctl user data length input length is too small\n");
			return -EFAULT;
		}
		resp = (struct xsc_ioctl_get_phy_info_res *)(tl + 1);
		xsc_core_dbg(xdev, "case XSC_IOCTL_OP_GET_BOARD_ESW_INFO:\n");
		ret = xsc_pci_ctrl_get_board_esw_info(xdev, resp);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int xsc_pci_ctrl_get_contextinfo(struct xsc_core_device *xdev,
					void *in, int in_size, void *out, int out_size)
{
	int ret = 0;
	struct xsc_ioctl_data_tl *tl = (struct xsc_ioctl_data_tl *)out;
	struct xsc_alloc_ucontext_req *req;
	struct xsc_alloc_ucontext_resp *resp;
	struct xsc_core_device *rl_xdev = NULL;

	if (out_size < sizeof(struct xsc_ioctl_data_tl) +
	    sizeof(struct xsc_alloc_ucontext_resp)) {
		xsc_core_err(xdev,
			     "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
	if (tl->opmod != XSC_IOCTL_OP_GET_CONTEXT)
		return -EINVAL;

	req = (struct xsc_alloc_ucontext_req *)(tl + 1);
	xsc_core_dbg(xdev, "xsc_tdi_alloc_context req:\n");
	xsc_core_dbg(xdev, "req->domain=%u\n", req->domain);
	xsc_core_dbg(xdev, "req->bus=%u\n", req->bus);
	xsc_core_dbg(xdev, "req->devfn=%u\n", req->devfn);

	rl_xdev = xsc_pci_get_xdev_by_bus_and_slot(req->domain, req->bus, req->devfn);
	if (!rl_xdev)
		return -1;

	resp = (struct xsc_alloc_ucontext_resp *)(tl + 1);

	resp->max_cq = rl_xdev->caps.max_cq;
	resp->max_qp = rl_xdev->caps.max_qp;
	resp->max_rwq_indirection_table_size = rl_xdev->caps.max_rwq_indirection_table_size;
	xsc_get_db_addr(rl_xdev, &resp->qpm_tx_db, &resp->qpm_rx_db, &resp->cqm_next_cid_reg,
			&resp->cqm_armdb, NULL);
	resp->send_ds_num = rl_xdev->caps.send_ds_num;
	resp->recv_ds_num = rl_xdev->caps.recv_ds_num;
	resp->send_ds_shift = rl_xdev->caps.send_wqe_shift;
	resp->recv_ds_shift = rl_xdev->caps.recv_wqe_shift;
	resp->glb_func_id = rl_xdev->glb_func_id;

	resp->max_wqes = rl_xdev->caps.max_wqes;

	xsc_core_dbg(xdev, "xsc_tdi_alloc_context resp:\n");
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

static int xsc_pci_ctrl_get_devinfo(struct xsc_core_device *xdev, void *in, int in_size,
				    void *out, int out_size)
{
	struct xsc_cmd_get_ioctl_info_mbox_in _in;
	struct xsc_cmd_get_ioctl_info_mbox_out *_out;
	int outlen;
	int err;
	int i;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr = {0};
	struct xsc_ioctl_attr *hdr = (struct xsc_ioctl_attr *)in;
	struct xsc_devinfo *devinfo = NULL;
	struct xsc_ioctl_get_devinfo *info = NULL;

	if (out_size < sizeof(struct xsc_ioctl_get_devinfo)) {
		xsc_core_err(xdev,
			     "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
	outlen = sizeof(*_out) + out_size;
	_out = kvzalloc(outlen, GFP_KERNEL);
	if (!_out)
		return -ENOMEM;

	memset(&_in, 0, sizeof(_in));
	_in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_IOCTL_INFO);
	_in.ioctl_opcode = cpu_to_be16(hdr->opcode);
	err = xsc_tunnel_cmd_exec(xdev, &_in, sizeof(_in), _out, outlen, &tunnel_hdr);
	if (err)
		goto out;
	if (_out->hdr.status) {
		err = xsc_cmd_status_to_err(&_out->hdr);
		hdr->error = _out->hdr.status;
		goto out;
	}

	info = (struct xsc_ioctl_get_devinfo *)_out->data;
	info->dev_num = be32_to_cpu(info->dev_num);
	if (out_size < sizeof(struct xsc_ioctl_get_devinfo) +
	    info->dev_num * sizeof(struct xsc_devinfo)) {
		xsc_core_err(xdev,
			     "ioctl user data length input length is too small\n");
		err = -EFAULT;
		goto out;
	}
	devinfo = info->data;
	for (i = 0; i < info->dev_num; i++) {
		devinfo->domain = be32_to_cpu(devinfo->domain);
		devinfo->bus = be32_to_cpu(devinfo->bus);
		devinfo->devfn = be32_to_cpu(devinfo->devfn);
		devinfo->ip_addr = be32_to_cpu(devinfo->ip_addr);
		devinfo->vendor_id = be32_to_cpu(devinfo->vendor_id);
		devinfo += 1;
	}

	memcpy(out, _out->data, out_size);
out:
	kfree(_out);
	return err;
}

static int xsc_pci_ctrl_get_runinfo(struct xsc_core_device *xdev, void *out, int out_size)
{
	struct xsc_device_run_info *runinfo = (struct xsc_device_run_info *)out;

	if (out_size < sizeof(struct xsc_device_run_info)) {
		xsc_core_err(xdev,
			     "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
	memcpy(runinfo->board_sn, xdev->board_info->board_sn, XSC_BOARD_SN_LEN);
	runinfo->global_func_id = xdev->glb_func_id;
	runinfo->msix_vec_base = xdev->msix_vec_base;
	runinfo->bond_id = xdev->bond_id;
	runinfo->user_mode = xdev->user_mode;
	runinfo->read_flush = xdev->read_flush;
	runinfo->resource_access_mode = xdev->board_info->resource_access_mode;
	if (xdev->board_info->resource_access_mode != SHARE_MODE) {
		xsc_get_mtt_info(xdev, &runinfo->mtt_total_avail, &runinfo->mtt_node_num);
		xsc_show_mtt_node(xdev);
	}

	return 0;
}

static int xsc_pci_ctrl_get_board_info(struct xsc_core_device *xdev, void *out, int out_size)
{
	unsigned int board_coun = xsc_get_global_board_cnt();

	if (out_size < sizeof(struct xsc_ioctl_board_info) * board_coun) {
		xsc_core_err(xdev, "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
	xsc_get_global_board_info((struct xsc_ioctl_board_info *)out);

	return 0;
}

static int xsc_pci_ctrl_get_board_count(struct xsc_core_device *xdev, void *out, int out_size)
{
	unsigned int board_count;

	if (out_size < sizeof(unsigned int)) {
		xsc_core_err(xdev, "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
	board_count = xsc_get_global_board_cnt();
	memcpy(out, &board_count, sizeof(unsigned int));

	return 0;
}

static int xsc_pci_ctrl_get_qp_base_info(struct xsc_core_device *xdev, void *in, int in_size,
					 void *out, int out_size)
{
	struct xsc_ioctl_qp_base_info *qp_base_info = (struct xsc_ioctl_qp_base_info *)out;
	int err;

	if (out_size < sizeof(struct xsc_ioctl_qp_base_info)) {
		xsc_core_err(xdev, "ioctl user data length input length is too small\n");
		return -EFAULT;
	}
	err = xsc_get_qp_base_info(xdev, in, qp_base_info, out_size);

	return err;
}

static int xsc_pci_ctrl_get_ib_tbl_count(struct xsc_core_device *xdev, void *out, int out_length)
{
	struct xsc_ioctl_ib_tbl_cnt *ib_tbl_cnt = (struct xsc_ioctl_ib_tbl_cnt *)out;
	int err;
	struct xsc_cmd_get_ib_tbl_cnt_mbox_in *_in;
	struct xsc_cmd_get_ib_tbl_cnt_mbox_out *_out;
	size_t in_size, out_size;

	if (out_length < sizeof(struct xsc_ioctl_ib_tbl_cnt)) {
		xsc_core_err(xdev, "ioctl user data length input length is too small\n");
		return -EFAULT;
	}

	in_size = sizeof(*_in);
	_in = kvzalloc(in_size, GFP_KERNEL);
	if (!_in)
		return -ENOMEM;

	out_size = sizeof(*_out) + sizeof(struct xsc_ioctl_ib_tbl_cnt);
	_out = kvzalloc(out_size, GFP_KERNEL);
	if (!_out) {
		kfree(_in);
		return -ENOMEM;
	}

	_in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_IB_MAPPING_TABLE_USAGE_CNT);
	err = xsc_cmd_exec(xdev, _in, in_size, _out, out_size);
	if (err)
		goto err_out;

	if (_out->hdr.status) {
		err = xsc_cmd_status_to_err(&_out->hdr);
		goto err_out;
	}

	memcpy(ib_tbl_cnt, _out->data, sizeof(struct xsc_ioctl_ib_tbl_cnt));
err_out:
	kfree(_in);
	kfree(_out);
	return err;
}

static int xsc_get_nic_ddr_status(struct xsc_core_device *xdev, void *outbuf, int out_size)
{
	struct xsc_cmd_get_nic_ddr_status_mbox_in in;
	struct xsc_cmd_get_nic_ddr_status_mbox_out out;
	int err;

	if (out_size < sizeof(out.status)) {
		xsc_core_err(xdev, "unexpected out buffer size.\n");
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_NIC_DDR_STATUS);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status) {
		err = xsc_cmd_status_to_err(&out.hdr);
		return err;
	}

	memcpy(outbuf, &out.status, out_size);
	return 0;
}

static int xsc_pci_ctrl_exec_ioctl(struct xsc_core_device *xdev,
				   void *in, int in_size,
				   void *out, int out_size)
{
	int opcode, ret = 0;
	struct xsc_ioctl_attr *hdr;

	hdr = (struct xsc_ioctl_attr *)in;
	opcode = hdr->opcode;
	switch (opcode) {
	case XSC_IOCTL_GET_PHY_INFO:
		ret = xsc_pci_ctrl_get_phy(xdev, in, in_size, out, out_size);
		break;
	case XSC_IOCTL_SET_QP_STATUS:
		xsc_core_dbg(xdev, "case XSC_IOCTL_SET_QP_STATUS:\n");
		ret = xsc_pci_ctrl_modify_qp(xdev, in, in_size, out, out_size);
		break;
	case XSC_IOCTL_GET_CONTEXT:
		xsc_core_dbg(xdev, "case XSC_IOCTL_GET_CONTEXT:\n");
		ret = xsc_pci_ctrl_get_contextinfo(xdev, in, in_size, out, out_size);
		break;
	case XSC_IOCTL_GET_DEVINFO:
		ret = xsc_pci_ctrl_get_devinfo(xdev, in, in_size, out, out_size);
		break;
	case XSC_IOCTL_GET_RUN_INFO:
		ret = xsc_pci_ctrl_get_runinfo(xdev, out, out_size);
		break;
	case XSC_IOCTL_GET_BOARD_INFO:
		xsc_core_dbg(xdev, "case XSC_IOCTL_GET_BOARD_INFO:\n");
		ret = xsc_pci_ctrl_get_board_info(xdev, out, out_size);
		break;
	case XSC_IOCTL_GET_BOARD_CNT:
		xsc_core_dbg(xdev, "case XSC_IOCTL_GET_BOARD_CNT:\n");
		ret = xsc_pci_ctrl_get_board_count(xdev, out, out_size);
		break;
	case XSC_IOCTL_GET_QP_BASE_INFO:
		xsc_core_dbg(xdev, "case XSC_IOCTL_GET_QP_BASE_INFO:\n");
		ret = xsc_pci_ctrl_get_qp_base_info(xdev, in, in_size,
						    out, out_size);
		break;
	case XSC_IOCTL_GET_IB_TBL_CNT:
		xsc_core_dbg(xdev, "case XSC_IOCTL_GET_IB_TBL_CNT:\n");
		ret = xsc_pci_ctrl_get_ib_tbl_count(xdev, out, out_size);
		break;
	case XSC_IOCTL_GET_NIC_DDR_STATUS:
		ret = xsc_get_nic_ddr_status(xdev, out, out_size);
		hdr->error = -ret;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static long xsc_pci_ctrl_setinfo(struct xsc_core_device *xdev,
				 struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	int err;
	struct xsc_set_debug_info_mbox_in in;
	struct xsc_set_debug_info_mbox_out out;
	struct xsc_ioctl_set_debug_info info;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err) {
		xsc_core_err(xdev, "copy user_hdr from user failed, err = %d\n", err);
		return -EFAULT;
	}

	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED) {
		xsc_core_err(xdev, "incorrect check field, check field=%#x\n", hdr.check_filed);
		return -EFAULT;
	}

	if (hdr.attr.length != sizeof(info)) {
		xsc_core_err(xdev, "unexpected length, length=%d\n", hdr.attr.length);
		return -EFAULT;
	}

	err = copy_from_user(&info, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		xsc_core_err(xdev, "copy attr.data from user failed, err = %d\n", err);
		return -EFAULT;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_DEBUG_INFO);
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_SET_LOG_LEVEL:
		in.set_field = 0;
		in.log_level = info.log_level;
		break;
	case XSC_IOCTL_SET_CMD_VERBOSE:
		in.set_field = 1;
		in.cmd_verbose = info.cmd_verbose;
		break;
	default:
		xsc_core_err(xdev, "invalid opcode %d\n", hdr.attr.opcode);
		return -EINVAL;
	}

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(xdev, "failed to set debug info to fw, err = %d, status = %d\n",
			     err, out.hdr.status);
		return -EFAULT;
	}

	return 0;
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
	case XSC_IOCTL_GET_DEVINFO:
	case XSC_IOCTL_GET_RUN_INFO:
	case XSC_IOCTL_GET_BOARD_INFO:
	case XSC_IOCTL_GET_BOARD_CNT:
	case XSC_IOCTL_GET_QP_BASE_INFO:
	case XSC_IOCTL_GET_IB_TBL_CNT:
	case XSC_IOCTL_GET_NIC_DDR_STATUS:
		break;
	default:
		return TRY_NEXT_CB;
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
	err = xsc_pci_ctrl_exec_ioctl(xdev, &in->attr,
				      (in_size - offsetof(struct xsc_ioctl_hdr, attr)),
				      in->attr.data, hdr.attr.length);

	if (copy_to_user((void *)user_hdr, in, in_size))
		err = -EFAULT;

	kvfree(in);
	return err;
}

static int xsc_ioctl_flow_add_obj(struct xsc_bdf_file *file, struct xsc_ioctl_data_tl *tl,
				  char *data, unsigned int datalen)
{
	int err = 0;
	struct xsc_flow_pct_v4_add *pct_v4;
	struct xsc_flow_pct_v6_add *pct_v6;
	struct xsc_flow_wct_add *wct;

	switch (tl->table) {
	case XSC_FLOW_TBL_PCT_V4:
	case XSC_FLOW_TBL_BM_PCT_V4:
		if (datalen < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_flow_pct_v4_add)) {
			xsc_core_err(file->xdev,
				     "ioctl flow add user data length input length is too small\n");
			return -EFAULT;
		}
		pct_v4 = (struct xsc_flow_pct_v4_add *)(tl + 1);
		err = xsc_alloc_pct_obj(file, pct_v4->priority, data, datalen);
		break;
	case XSC_FLOW_TBL_PCT_V6:
	case XSC_FLOW_TBL_BM_PCT_V6:
		if (datalen < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_flow_pct_v6_add)) {
			xsc_core_err(file->xdev,
				     "ioctl flow add user data length input length is too small\n");
			return -EFAULT;
		}
		pct_v6 = (struct xsc_flow_pct_v6_add *)(tl + 1);
		err = xsc_alloc_pct_obj(file, pct_v6->priority, data, datalen);
		break;
	case XSC_FLOW_TBL_WCT:
		if (datalen < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_flow_wct_add)) {
			xsc_core_err(file->xdev,
				     "ioctl flow add user data length input length is too small\n");
			return -EFAULT;
		}
		wct = (struct xsc_flow_wct_add *)(tl + 1);
		err = xsc_alloc_wct_obj(file, wct->priority, data, datalen);
		break;
	default:
		break;
	}

	return err;
}

static void xsc_ioctl_flow_destroy_obj(struct xsc_bdf_file *file, struct xsc_ioctl_data_tl *tl,
				       unsigned int datalen, bool *tbl_op)
{
	struct xsc_flow_pct_v4_del *pct_v4;
	struct xsc_flow_pct_v6_del *pct_v6;
	struct xsc_flow_wct_del *wct;

	switch (tl->table) {
	case XSC_FLOW_TBL_PCT_V4:
	case XSC_FLOW_TBL_BM_PCT_V4:
		if (datalen < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_flow_pct_v4_del)) {
			xsc_core_err(file->xdev,
				     "ioctl flow destroy user data length input length is too small\n");
		}
		pct_v4 = (struct xsc_flow_pct_v4_del *)(tl + 1);
		xsc_destroy_pct_obj(file, pct_v4->priority, tbl_op);
		break;
	case XSC_FLOW_TBL_PCT_V6:
	case XSC_FLOW_TBL_BM_PCT_V6:
		if (datalen < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_flow_pct_v6_del)) {
			xsc_core_err(file->xdev,
				     "ioctl flow destroy user data length input length is too small\n");
		}
		pct_v6 = (struct xsc_flow_pct_v6_del *)(tl + 1);
		xsc_destroy_pct_obj(file, pct_v6->priority, tbl_op);
		break;
	case XSC_FLOW_TBL_WCT:
		if (datalen < sizeof(struct xsc_ioctl_data_tl) +
		    sizeof(struct xsc_flow_wct_del)) {
			xsc_core_err(file->xdev,
				     "ioctl flow destroy user data length input length is too small\n");
		}
		wct = (struct xsc_flow_wct_del *)(tl + 1);
		xsc_destroy_pct_obj(file, wct->priority, tbl_op);
		break;
	default:
		break;
	}
}

static int xsc_ioctl_flow_cmdq_handle_res_obj(struct xsc_bdf_file *file,
					      char *data, unsigned int datalen, bool *tbl_op)
{
	struct xsc_ioctl_data_tl *tl;
	int err = 0;

	if (datalen < sizeof(struct xsc_ioctl_data_tl)) {
		xsc_core_err(file->xdev, "ioctl flow cmdq user data length input length is too small\n");
		return -EFAULT;
	}

	tl = (struct xsc_ioctl_data_tl *)data;

	switch (tl->opmod) {
	case XSC_IOCTL_OP_ADD:
		err = xsc_ioctl_flow_add_obj(file, tl, data, datalen);
		break;
	case XSC_IOCTL_OP_DEL:
		xsc_ioctl_flow_destroy_obj(file, tl, datalen, tbl_op);
		break;
	default:
		break;
	}

	return err;
}

static int xsc_ioctl_flow_cmdq(struct xsc_bdf_file *file,
			       struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mbox_in *in;
	struct xsc_ioctl_mbox_out *out;
	int in_size;
	int out_size;
	int err;
	bool tbl_op = true;

	in_size = sizeof(struct xsc_ioctl_mbox_in) + hdr->attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -EFAULT;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	in->len = __cpu_to_be16(hdr->attr.length);
	err = copy_from_user(in->data, user_hdr->attr.data, hdr->attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}

	err = xsc_ioctl_flow_cmdq_handle_res_obj(file, in->data, hdr->attr.length, &tbl_op);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}

	if (!tbl_op) {
		kvfree(in);
		return 0;
	}

	out_size = sizeof(struct xsc_ioctl_mbox_out) + hdr->attr.length;
	out = kvzalloc(out_size, GFP_KERNEL);
	if (!out) {
		kvfree(in);
		return -ENOMEM;
	}
	memcpy(out->data, in->data, hdr->attr.length);
	out->len = in->len;
	err = xsc_cmd_exec(file->xdev, in, in_size, out, out_size);

	hdr->attr.error = __be32_to_cpu(out->error);
	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, out->data, hdr->attr.length))
		err = -EFAULT;

	kvfree(in);
	kvfree(out);
	return err;
}

static int xsc_ioctl_emu_cmd(struct xsc_core_device *xdev,
			     struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mbox_in *in;
	struct xsc_ioctl_mbox_out *out;
	struct xsc_ioctl_emu_hdr *emu_hdr;
	u8 *buffer;
	int in_size;
	int out_size;
	int err;

	if (hdr->attr.length < sizeof(struct xsc_ioctl_emu_hdr)) {
		xsc_core_err(xdev, "ioctl emu user data length input length is too small\n");
		return -EFAULT;
	}
	buffer = kvzalloc(hdr->attr.length, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	err = copy_from_user(buffer, user_hdr->attr.data, hdr->attr.length);
	if (err)
		goto err_copy_user_data;

	emu_hdr = (struct xsc_ioctl_emu_hdr *)buffer;
	if (hdr->attr.length < sizeof(struct xsc_ioctl_emu_hdr) + emu_hdr->in_length ||
	    hdr->attr.length < sizeof(struct xsc_ioctl_emu_hdr) + emu_hdr->out_length ||
	    emu_hdr->in_length < sizeof(struct xsc_ioctl_mbox_in) ||
	    emu_hdr->out_length < sizeof(struct xsc_ioctl_mbox_out)) {
		xsc_core_err(xdev, "ioctl emu user data length input length is too small\n");
		err = -EFAULT;
		goto err_copy_user_data;
	}
	in_size = emu_hdr->in_length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_alloc_in_mem;
	}
	memcpy(in, emu_hdr->data, emu_hdr->in_length);

	out_size = emu_hdr->out_length;
	out = kvzalloc(out_size, GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto err_alloc_out_mem;
	}

	err = xsc_cmd_exec(xdev, in, in_size, out, out_size);

	hdr->attr.error = __be32_to_cpu(out->error);
	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data + sizeof(struct xsc_ioctl_emu_hdr),
			 out, out_size))
		err = -EFAULT;

	kvfree(out);
	kvfree(in);
	kvfree(buffer);
	return err;

err_alloc_out_mem:
	kvfree(in);
err_alloc_in_mem:
err_copy_user_data:
	kvfree(buffer);
	return err;
}

static int xsc_ioctl_update_assoc_pid(struct xsc_bdf_file *bdf_file, u32 assoc_pid)
{
	struct xsc_port_ctrl *ctrl = &bdf_file->xdev->port_ctrl;
	struct xsc_port_ctrl_file *local_file = bdf_file->port_ctrl_file;
	struct xsc_port_ctrl_file *file, *n;
	u32 local_pid;

	if (!ctrl || !local_file) {
		xsc_core_err(bdf_file->xdev, "port ctrl or local_file is NULL");
		return -EINVAL;
	}

	local_pid = local_file->pid;
	spin_lock(&ctrl->file_lock);
	list_for_each_entry_safe(file, n, &ctrl->file_list, file_node) {
		if (file->pid == local_pid) {
			file->assoc_pid = assoc_pid;
			xsc_core_info(bdf_file->xdev, "port_ctrl_file addr:%p, pid:%d, assoc_pid:%d",
				      file, file->pid, file->assoc_pid);
		}
		if (file->pid == assoc_pid) {
			file->assoc_pid = local_pid;
			xsc_core_info(bdf_file->xdev, "port_ctrl_file addr:%p, pid:%d, assoc_pid:%d",
				      file, file->pid, file->assoc_pid);
		}
	}
	spin_unlock(&ctrl->file_lock);

	return 0;
}

static int xsc_ioctl_set_user_info(struct xsc_bdf_file *file,
				   struct xsc_ioctl_hdr __user *user_hdr,
				   struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_user_info *user_info;
	struct xsc_port_ctrl_file *port_ctrl_file = file->port_ctrl_file;
	u8 *data;
	u8 flags;
	u32 assoc_pid;
	int err = 0;

	if (hdr->attr.length < sizeof(struct xsc_ioctl_user_info)) {
		xsc_core_err(file->xdev, "ioctl set user info input length is too small\n");
		return -EFAULT;
	}

	if (!port_ctrl_file) {
		xsc_core_err(file->xdev, "port ctrl file is null\n");
		return -EFAULT;
	}

	data = kvzalloc(hdr->attr.length, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	err = copy_from_user(data, user_hdr->attr.data, hdr->attr.length);
	if (err) {
		xsc_core_err(file->xdev, "copy from user failed\n");
		goto error;
	}

	user_info = (struct xsc_ioctl_user_info *)data;
	flags = user_info->flags;
	assoc_pid = user_info->assoc_pid;
	xsc_core_info(file->xdev, "user_idx %d, assoc_pid %d, flags %d",
		      user_info->user_idx, assoc_pid, flags);

	if (flags & XSC_USER_INFO_FLAG_ASSOC_PID) {
		if (!assoc_pid || port_ctrl_file->pid == assoc_pid) {
			xsc_core_err(file->xdev, " assoc_pid %d invalid or same with local pid %d",
				     assoc_pid, port_ctrl_file->pid);
			err = -EINVAL;
			goto error;
		}

		err = xsc_ioctl_update_assoc_pid(file, assoc_pid);
		if (err)
			goto error;
	}

	if (flags & XSC_USER_INFO_FLAG_USER_IDX) {
		err = xsc_alloc_user_idx_obj(file, user_info->user_idx, NULL, 0);
		if (err)
			goto error;
	}

error:
	hdr->attr.error = err;
	kfree(data);
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

	in = kvzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->req, user_hdr->attr.data,
			     sizeof(struct xsc_modify_raw_qp_request));
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	in->pcie_no = xdev->pcie_no;

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

static void xsc_handle_multiqp_create(struct xsc_bdf_file *file, void *in,
				      unsigned int inlen, void *out)
{
	u16 qp_num = 0;
	int i = 0;
	struct xsc_create_qp_request *req = NULL;
	void *ptr = NULL;
	int len = 0;
	u32 qpn_base = be32_to_cpu(((struct xsc_create_multiqp_mbox_out *)out)->qpn_base);

	qp_num = be16_to_cpu(((struct xsc_create_multiqp_mbox_in *)in)->qp_num);
	ptr = ((struct xsc_create_multiqp_mbox_in *)in)->data;
	for (i = 0; i < qp_num; i++) {
		req = (struct xsc_create_qp_request *)ptr;
		len = sizeof(struct xsc_create_qp_request) +
			     be16_to_cpu(req->pa_num) * sizeof(u64);
		xsc_alloc_qp_obj(file, qpn_base + i, (char *)req, len);
		ptr += len;
	}
}

static void xsc_pci_ctrl_cmdq_handle_res_obj(struct xsc_bdf_file *file, void *in,
					     unsigned int inlen, void *out, unsigned int outlen,
					     int opcode)
{
	unsigned int idx;

	switch (opcode) {
	case XSC_CMD_OP_ALLOC_PD:
		if (outlen < sizeof(struct xsc_alloc_pd_mbox_out)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_alloc_pd_mbox_out *)out)->pdn);
		xsc_alloc_pd_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_DEALLOC_PD:
		if (inlen < sizeof(struct xsc_dealloc_pd_mbox_in)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_dealloc_pd_mbox_in *)in)->pdn);
		xsc_destroy_pd_obj(file, idx);
		break;
	case XSC_CMD_OP_CREATE_MKEY:
		if (outlen < sizeof(struct xsc_create_mkey_mbox_out)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_create_mkey_mbox_out *)out)->mkey);
		xsc_alloc_mr_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_DESTROY_MKEY:
		if (inlen < sizeof(struct xsc_destroy_mkey_mbox_in)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_destroy_mkey_mbox_in *)in)->mkey);
		xsc_destroy_mr_obj(file, idx);
		break;
	case XSC_CMD_OP_DESTROY_CQ:
		if (inlen < sizeof(struct xsc_destroy_cq_mbox_in)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_destroy_cq_mbox_in *)in)->cqn);
		xsc_destroy_cq_obj(file, idx);
		break;
	case XSC_CMD_OP_CREATE_CQ:
	case XSC_CMD_OP_CREATE_CQ_EX:
		if (outlen < sizeof(struct xsc_create_cq_mbox_out)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_create_cq_mbox_out *)out)->cqn);
		xsc_alloc_cq_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_CREATE_QP:
		if (inlen < sizeof(struct xsc_create_qp_mbox_in) ||
		    outlen < sizeof(struct xsc_create_qp_mbox_out)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_create_qp_mbox_out *)out)->qpn);
		xsc_alloc_qp_obj(file, idx,
				 (char *)&(((struct xsc_create_qp_mbox_in *)in)->req),
				 inlen);
		break;
	case XSC_CMD_OP_DESTROY_QP:
		if (inlen < sizeof(struct xsc_destroy_qp_mbox_in)) {
			xsc_core_err(file->xdev, "user data length is too small\n");
			return;
		}
		idx = be32_to_cpu(((struct xsc_destroy_qp_mbox_in *)in)->qpn);
		xsc_destroy_qp_obj(file, idx);
		break;
	case XSC_CMD_OP_CREATE_MULTI_QP:
		xsc_handle_multiqp_create(file, in, inlen, out);
		break;
	default:
		break;
	}
}

static long xsc_pci_ctrl_cmdq(struct xsc_bdf_file *file,
			      struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_core_device *xdev = file->xdev;
	struct xsc_ioctl_hdr hdr;
	int err;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EINVAL;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_CMD_OP_IOCTL_FLOW:
		return xsc_ioctl_flow_cmdq(file, user_hdr, &hdr);
	case XSC_CMD_OP_MODIFY_RAW_QP:
		return xsc_ioctl_modify_raw_qp(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_USER_EMU_CMD:
		return xsc_ioctl_emu_cmd(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_IOCTL_USER_INFO:
		return xsc_ioctl_set_user_info(file, user_hdr, &hdr);
	default:
		err = TRY_NEXT_CB;
		break;
	}

	return err;
}

static long xsc_pci_ctrl_cmdq_raw(struct xsc_bdf_file *file,
				  struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	int err;
	void *in;
	void *out;
	int op;
	struct xsc_core_device *dev = file->xdev;
	struct xsc_create_mkey_mbox_out *resp;
	struct xsc_unregister_mr_mbox_in *req;
	u8 key;
	u16 out_len;
	int qpn = 0;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err) {
		xsc_core_err(dev, "fail to copy from user_hdr\n");
		return -EFAULT;
	}

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED) {
		xsc_core_err(dev, "invalid check filed %u\n", hdr.check_filed);
		return -EINVAL;
	}

	if (hdr.attr.length < sizeof(struct xsc_inbox_hdr)) {
		xsc_core_err(dev, "user data length is too small %u\n", hdr.attr.length);
		return -EINVAL;
	}

	in = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out_len = min(hdr.attr.length, dev->caps.max_cmd_out_len);
	out = kvzalloc(out_len, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	err = copy_from_user(in, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		err = -EFAULT;
		xsc_core_err(dev, "fail to copy_from_user user hdr attr\n");
		goto err_exit;
	}

	op = be16_to_cpu(((struct xsc_inbox_hdr *)in)->opcode);
	switch (op) {
	case XSC_CMD_OP_CREATE_MKEY:
		if (out_len < sizeof(struct xsc_create_mkey_mbox_out)) {
			err = -EFAULT;
			xsc_core_err(dev, "user data length is too small\n");
			goto err_exit;
		}
		spin_lock(&dev->dev_res->mkey_lock);
		key = 0x80 + dev->dev_res->mkey_key++;
		spin_unlock(&dev->dev_res->mkey_lock);
		down_read(&dev->board_info->mr_sync_lock);
		if (dev->board_info->resource_access_mode == SHARE_MODE)
			err = xsc_cmd_exec(dev, in, hdr.attr.length, out, hdr.attr.length);
		else
			err = xsc_create_mkey(dev, in, out);
		up_read(&dev->board_info->mr_sync_lock);

		resp = (struct xsc_create_mkey_mbox_out *)out;
		resp->mkey = xsc_idx_to_mkey(dev, be32_to_cpu(resp->mkey) & 0xffffff) | key;
		resp->mkey = cpu_to_be32(resp->mkey);
		break;
	case XSC_CMD_OP_DESTROY_MKEY:
		down_read(&dev->board_info->mr_sync_lock);
		if (!(dev->board_info->resource_access_mode == SHARE_MODE)) {
			if (hdr.attr.length < sizeof(struct xsc_destroy_mkey_mbox_in) ||
			    out_len < sizeof(struct xsc_destroy_mkey_mbox_out)) {
				err = -EFAULT;
				xsc_core_err(dev, "user data length is too small\n");
				up_read(&dev->board_info->mr_sync_lock);
				goto err_exit;
			}
			err = xsc_destroy_mkey(dev, in, out);
		}
		up_read(&dev->board_info->mr_sync_lock);
		break;
	case XSC_CMD_OP_REG_MR:
		down_read(&dev->board_info->mr_sync_lock);
		if (!(dev->board_info->resource_access_mode == SHARE_MODE)) {
			if (hdr.attr.length < sizeof(struct xsc_register_mr_mbox_in) ||
			    out_len < sizeof(struct xsc_register_mr_mbox_out)) {
				err = -EFAULT;
				xsc_core_err(dev, "user data length is too small\n");
				up_read(&dev->board_info->mr_sync_lock);
				goto err_exit;
			}
			err = xsc_reg_mr(dev, in, out);
		}
		up_read(&dev->board_info->mr_sync_lock);
		break;
	case XSC_CMD_OP_DEREG_MR:
		if (hdr.attr.length < sizeof(struct xsc_unregister_mr_mbox_in)) {
			err = -EFAULT;
			xsc_core_err(dev, "user data length is too small\n");
			goto err_exit;
		}
		req = (struct xsc_unregister_mr_mbox_in *)in;
		req->mkey = be32_to_cpu(req->mkey);
		req->mkey = cpu_to_be32(xsc_mkey_to_idx(dev, req->mkey));
		down_read(&dev->board_info->mr_sync_lock);
		if (dev->board_info->resource_access_mode == SHARE_MODE) {
			err = xsc_cmd_exec(dev, in, hdr.attr.length, out, hdr.attr.length);
		} else {
			if (out_len < sizeof(struct xsc_unregister_mr_mbox_out)) {
				err = -EFAULT;
				xsc_core_err(dev, "user data length is too small\n");
				up_read(&dev->board_info->mr_sync_lock);
				goto err_exit;
			}
			err = xsc_dereg_mr(dev, in, out);
		}
		up_read(&dev->board_info->mr_sync_lock);
		break;
	case XSC_CMD_OP_DESTROY_QP:
		if (hdr.attr.length < sizeof(struct xsc_destroy_qp_mbox_in)) {
			err = -EFAULT;
			xsc_core_err(dev, "user data length is too small\n");
			goto err_exit;
		}
		qpn = be32_to_cpu(((struct xsc_destroy_qp_mbox_in *)in)->qpn);
		xsc_send_cmd_2rst_qp(dev, qpn);
		err = xsc_cmd_exec(dev, in, hdr.attr.length, out, out_len);
		break;
	case XSC_CMD_OP_CREATE_MULTI_QP:
		if (hdr.attr.length < sizeof(struct xsc_create_multiqp_mbox_in) ||
		    out_len < sizeof(struct xsc_create_multiqp_mbox_out)) {
			err = -EFAULT;
			xsc_core_err(dev, "user data length is too small\n");
			goto err_exit;
		}
		xsc_eth_create_multiqp(dev, in, hdr.attr.length, out, out_len);
		break;
	default:
		err = xsc_cmd_exec(dev, in, hdr.attr.length, out, out_len);
		break;
	}
	xsc_pci_ctrl_cmdq_handle_res_obj(file, in, hdr.attr.length, out, out_len, hdr.attr.opcode);

	if (copy_to_user((void *)user_hdr->attr.data, out, out_len)) {
		xsc_core_err(dev, "fail to copy_to_user user hdr attr\n");
		err = -EFAULT;
	}
err_exit:
	kfree(in);
	kfree(out);
	return err;
}

static int xsc_pci_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			       struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = xsc_pci_ctrl_cmdq(file, user_hdr);
		break;
	case XSC_IOCTL_DRV_GET:
		err = xsc_pci_ctrl_getinfo(file->xdev, user_hdr);
		break;
	case XSC_IOCTL_DRV_SET:
		err = xsc_pci_ctrl_setinfo(file->xdev, user_hdr);
		break;
	case XSC_IOCTL_CMDQ_RAW:
		if (xsc_not_support_cmdq_raw(file->xdev)) {
			xsc_core_err(file->xdev, "not support cmdq raw\n");
			err = -EOPNOTSUPP;
		} else {
			err = xsc_pci_ctrl_cmdq_raw(file, user_hdr);
		}
		break;
	default:
		err = TRY_NEXT_CB;
		break;
	}

	return err;
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

