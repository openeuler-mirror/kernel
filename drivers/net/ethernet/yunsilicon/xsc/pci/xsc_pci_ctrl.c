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
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include "xsc_pci_ctrl.h"
#include "common/res_obj.h"

#define FEATURE_ONCHIP_FT_MASK		BIT(4)
#define FEATURE_DMA_RW_TBL_MASK		BIT(8)
#define FEATURE_PCT_EXP_MASK		BIT(19)

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

	xdev = pci_get_drvdata(pdev);

	return xdev;
}

static int xsc_pci_ctrl_get_phy(struct xsc_core_device *xdev,
				void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_data_tl *tl = (struct xsc_ioctl_data_tl *)out;
	struct xsc_ioctl_get_phy_info_res *resp;
	struct xsc_lag *ldev = xsc_lag_dev_get(xdev);
	u16 lag_id = U16_MAX;
	struct xsc_core_device *rl_xdev;

	if (ldev && __xsc_lag_is_active(ldev))
		lag_id = ldev->lag_id;

	switch (tl->opmod) {
	case XSC_IOCTL_OP_GET_LOCAL:
		resp = (struct xsc_ioctl_get_phy_info_res *)(tl + 1);

		resp->pcie_no = xdev->pcie_no;
		resp->func_id = xdev->glb_func_id;
		resp->pcie_host = xdev->caps.pcie_host;
		resp->mac_phy_port = xdev->mac_port;
		resp->funcid_to_logic_port_off = xdev->caps.funcid_to_logic_port;
		resp->lag_id = lag_id;
		resp->raw_qp_id_base = xdev->caps.raweth_qp_id_base;
		resp->raw_rss_qp_id_base = xdev->caps.raweth_rss_qp_id_base;
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
		break;

	case XSC_IOCTL_OP_GET_INFO_BY_BDF:
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
		resp->lag_port_start = XSC_LAG_PORT_START;
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
	struct xsc_alloc_ucontext_req *req;
	struct xsc_alloc_ucontext_resp *resp;
	struct xsc_core_device *rl_xdev = NULL;

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

	resp->max_cq = 1 << rl_xdev->caps.log_max_cq;
	resp->max_qp = 1 << rl_xdev->caps.log_max_qp;
	resp->max_rwq_indirection_table_size = rl_xdev->caps.max_rwq_indirection_table_size;
	resp->qpm_tx_db = rl_xdev->regs.tx_db;
	resp->qpm_rx_db = rl_xdev->regs.rx_db;
	resp->cqm_next_cid_reg = rl_xdev->regs.complete_reg;
	resp->cqm_armdb = rl_xdev->regs.complete_db;
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

int noop_pre(struct kprobe *p, struct pt_regs *regs) { return 0; }

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name",
};

unsigned long (*kallsyms_lookup_name_func)(const char *name) = NULL;

int find_kallsyms_lookup_name(void)
{
	int ret = -1;

	kp.addr = 0;
	kp.pre_handler = noop_pre;
	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;

	kallsyms_lookup_name_func = (void *)kp.addr;
	unregister_kprobe(&kp);
	return ret;
}

u16 xsc_get_irq_matrix_global_available(struct xsc_core_device *dev)
{
	struct db_irq_matrix *m;
	unsigned long addr;
	char *name = "vector_matrix";
	int ret;

	ret = find_kallsyms_lookup_name();
	if (ret < 0) {
		xsc_core_err(dev, "find kallsyms_lookup_name failed\n");
		return 0xffff;
	}

	addr = kallsyms_lookup_name_func(name);
	xsc_core_dbg(dev, "vector_matrix addr=0x%lx\n", addr);
	if (addr == 0) {
		xsc_core_err(dev, "not support, arch maybe not X86?\n");
		return 0xffff;
	}
	m = (struct db_irq_matrix *)(*(long *)addr);
	if (!m) {
		xsc_core_err(dev, "vector_matrix is NULL\n");
		return 0xffff;
	}
	xsc_core_info(dev, "vector_matrix global_available=%u\n", m->global_available);
	return m->global_available;
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
	u16 global_available;
	u16 totalvfs;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_GET_PHY_INFO:
	case XSC_IOCTL_SET_QP_STATUS:
	case XSC_IOCTL_GET_CONTEXT:
	case XSC_IOCTL_GET_VECTOR_MATRIX:
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

	if (hdr.attr.opcode == XSC_IOCTL_GET_VECTOR_MATRIX) {
		global_available = xsc_get_irq_matrix_global_available(xdev);
		totalvfs = (pci_sriov_get_totalvfs(xdev->pdev) < 0) ? 0 :
					pci_sriov_get_totalvfs(xdev->pdev);
		in->attr.error = err;
		memcpy(in->attr.data, (void *)&global_available, sizeof(u16));
		memcpy(in->attr.data + sizeof(u16), (void *)&totalvfs, sizeof(u16));
		goto next;
	}

	err = copy_from_user(in->attr.data, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}
	err = xsc_pci_ctrl_exec_ioctl(xdev, &in->attr,
				      (in_size - offsetof(struct xsc_ioctl_hdr, attr)),
				      in->attr.data, hdr.attr.length);
	in->attr.error = err;
next:
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

	switch (tl->table) {
	case XSC_FLOW_TBL_PCT_V4:
	case XSC_FLOW_TBL_BM_PCT_V4:
		pct_v4 = (struct xsc_flow_pct_v4_add *)(tl + 1);
		err = xsc_alloc_pct_obj(file, pct_v4->priority, data, datalen);
		break;
	case XSC_FLOW_TBL_PCT_V6:
	case XSC_FLOW_TBL_BM_PCT_V6:
		pct_v6 = (struct xsc_flow_pct_v6_add *)(tl + 1);
		err = xsc_alloc_pct_obj(file, pct_v6->priority, data, datalen);
		break;
	default:
		break;
	}

	return err;
}

static void xsc_ioctl_flow_destroy_obj(struct xsc_bdf_file *file, struct xsc_ioctl_data_tl *tl)
{
	struct xsc_flow_pct_v4_del *pct_v4;
	struct xsc_flow_pct_v6_del *pct_v6;

	switch (tl->table) {
	case XSC_FLOW_TBL_PCT_V4:
	case XSC_FLOW_TBL_BM_PCT_V4:
		pct_v4 = (struct xsc_flow_pct_v4_del *)(tl + 1);
		xsc_destroy_pct_obj(file, pct_v4->priority);
		break;
	case XSC_FLOW_TBL_PCT_V6:
	case XSC_FLOW_TBL_BM_PCT_V6:
		pct_v6 = (struct xsc_flow_pct_v6_del *)(tl + 1);
		xsc_destroy_pct_obj(file, pct_v6->priority);
		break;
	default:
		break;
	}
}

static int xsc_ioctl_flow_cmdq_handle_res_obj(struct xsc_bdf_file *file,
					      char *data, unsigned int datalen)
{
	struct xsc_ioctl_data_tl *tl;
	int err = 0;

	tl = (struct xsc_ioctl_data_tl *)data;

	switch (tl->opmod) {
	case XSC_IOCTL_OP_ADD:
		err = xsc_ioctl_flow_add_obj(file, tl, data, datalen);
		break;
	case XSC_IOCTL_OP_DEL:
		xsc_ioctl_flow_destroy_obj(file, tl);
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

	err = xsc_ioctl_flow_cmdq_handle_res_obj(file, in->data, hdr->attr.length);
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

	buffer = kvzalloc(hdr->attr.length, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	err = copy_from_user(buffer, user_hdr->attr.data, hdr->attr.length);
	if (err)
		goto err_copy_user_data;

	emu_hdr = (struct xsc_ioctl_emu_hdr *)buffer;
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

static void xsc_pci_ctrl_cmdq_handle_res_obj(struct xsc_bdf_file *file, void *in,
					     unsigned int inlen, void *out, int opcode)
{
	unsigned int idx;

	switch (opcode) {
	case XSC_CMD_OP_ALLOC_PD:
		idx = be32_to_cpu(((struct xsc_alloc_pd_mbox_out *)out)->pdn);
		xsc_alloc_pd_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_DEALLOC_PD:
		idx = be32_to_cpu(((struct xsc_dealloc_pd_mbox_in *)in)->pdn);
		xsc_destroy_pd_obj(file, idx);
		break;
	case XSC_CMD_OP_CREATE_MKEY:
		idx = be32_to_cpu(((struct xsc_create_mkey_mbox_out *)out)->mkey);
		xsc_alloc_mr_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_DESTROY_MKEY:
		idx = be32_to_cpu(((struct xsc_destroy_mkey_mbox_in *)in)->mkey);
		xsc_destroy_mr_obj(file, idx);
		break;
	case XSC_CMD_OP_DESTROY_CQ:
		idx = be32_to_cpu(((struct xsc_destroy_cq_mbox_in *)in)->cqn);
		xsc_destroy_cq_obj(file, idx);
		break;
	case XSC_CMD_OP_CREATE_CQ:
		idx = be32_to_cpu(((struct xsc_create_cq_mbox_out *)out)->cqn);
		xsc_alloc_cq_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_CREATE_QP:
		idx = be32_to_cpu(((struct xsc_create_qp_mbox_out *)out)->qpn);
		xsc_alloc_qp_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_DESTROY_QP:
		idx = be32_to_cpu(((struct xsc_destroy_qp_mbox_in *)in)->qpn);
		xsc_destroy_qp_obj(file, idx);
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

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err) {
		xsc_core_err(dev, "fail to copy_from_user user hdr\n");
		return -EFAULT;
	}

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED) {
		xsc_core_err(dev, "invalid check filed %u\n", hdr.check_filed);
		return -EINVAL;
	}

	in = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	out = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!out) {
		kfree(in);
		xsc_core_err(dev, "fail to alloc hdr length for mbox out\n");
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
		spin_lock(&dev->dev_res->mkey_lock);
		key = 0x80 + dev->dev_res->mkey_key++;
		spin_unlock(&dev->dev_res->mkey_lock);
#ifdef REG_MR_VIA_CMDQ
		err = xsc_cmd_exec(dev, in, hdr.attr.length, out, hdr.attr.length);
#else
		err = xsc_create_mkey(dev, in, out);
#endif
		resp = (struct xsc_create_mkey_mbox_out *)out;
		resp->mkey = xsc_idx_to_mkey(be32_to_cpu(resp->mkey) & 0xffffff) | key;
		resp->mkey = cpu_to_be32(resp->mkey);
		break;

#ifndef REG_MR_VIA_CMDQ
	case XSC_CMD_OP_DESTROY_MKEY:
		err = xsc_destroy_mkey(dev, in, out);
		break;

	case XSC_CMD_OP_REG_MR:
		err = xsc_reg_mr(dev, in, out);
		break;
#endif

	case XSC_CMD_OP_DEREG_MR:
		req = (struct xsc_unregister_mr_mbox_in *)in;
		req->mkey = be32_to_cpu(req->mkey);
		req->mkey = cpu_to_be32(xsc_mkey_to_idx(req->mkey));
#ifdef REG_MR_VIA_CMDQ
		err = xsc_cmd_exec(dev, in, hdr.attr.length, out, hdr.attr.length);
#else
		err = xsc_dereg_mr(dev, in, out);
#endif
		break;
	default:
		err = xsc_cmd_exec(dev, in, hdr.attr.length, out, hdr.attr.length);
		break;
	}
	xsc_pci_ctrl_cmdq_handle_res_obj(file, in, hdr.attr.length, out, hdr.attr.opcode);
	if (copy_to_user((void *)user_hdr->attr.data, out, hdr.attr.length)) {
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
		err = xsc_pci_ctrl_cmdq_raw(file, user_hdr);
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

