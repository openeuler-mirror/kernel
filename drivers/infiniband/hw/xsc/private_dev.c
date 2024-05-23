// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
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
#include "common/res_obj.h"
#include "global.h"

#define FEATURE_ONCHIP_FT_MASK		BIT(4)
#define FEATURE_DMA_RW_TBL_MASK		BIT(8)
#define FEATURE_PCT_EXP_MASK		BIT(9)

static int xsc_priv_dev_open(struct inode *inode, struct file *file)
{
	struct xsc_priv_device *priv_dev =
		container_of(inode->i_cdev, struct xsc_priv_device, cdev);
	struct xsc_core_device *xdev =
		container_of(priv_dev, struct xsc_core_device, priv_device);
	struct xsc_bdf_file *bdf_file;

	bdf_file = kzalloc(sizeof(*bdf_file), GFP_KERNEL);
	if (!file)
		return -ENOMEM;
	INIT_RADIX_TREE(&bdf_file->obj_tree, GFP_ATOMIC);
	spin_lock_init(&bdf_file->obj_lock);
	bdf_file->xdev = xdev;
	bdf_file->key = bdf_to_key(pci_domain_nr(xdev->pdev->bus),
				   xdev->pdev->bus->number, xdev->pdev->devfn);
	radix_tree_preload(GFP_KERNEL);
	spin_lock(&priv_dev->bdf_lock);
	radix_tree_insert(&priv_dev->bdf_tree, bdf_file->key, bdf_file);
	spin_unlock(&priv_dev->bdf_lock);
	radix_tree_preload_end();
	file->private_data = bdf_file;

	return 0;
}

static int xsc_priv_dev_release(struct inode *inode, struct file *filp)
{
	struct xsc_bdf_file *bdf_file = filp->private_data;

	xsc_close_bdf_file(bdf_file);
	spin_lock(&bdf_file->xdev->priv_device.bdf_lock);
	radix_tree_delete(&bdf_file->xdev->priv_device.bdf_tree, bdf_file->key);
	spin_unlock(&bdf_file->xdev->priv_device.bdf_lock);
	kfree(bdf_file);

	return 0;
}

static long xsc_ioctl_mem_free(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
			       struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mem_info *minfo;
	struct xsc_ioctl_data_tl *tl;
	struct xsc_ioctl_mbox_in *in;
	struct xsc_mem_entry *m_ent;
	char tname[TASK_COMM_LEN];
	int in_size;
	int err = 0;
	u8 lfound = 0;

	in_size = sizeof(struct xsc_ioctl_mbox_in) + hdr->attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->len = hdr->attr.length;
	err = copy_from_user(in->data, user_hdr->attr.data, hdr->attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}

	if (in->len > sizeof(struct xsc_ioctl_data_tl)) {
		tl = (struct xsc_ioctl_data_tl *)(in->data);
		if (tl->length != sizeof(struct xsc_ioctl_mem_info)) {
			kvfree(in);
			return -EFAULT;
		}
		minfo = (struct xsc_ioctl_mem_info *)(tl + 1);
		if (minfo->vir_addr && minfo->phy_addr) {
			memset(tname, 0, sizeof(tname));
			get_task_comm(tname, current);

			spin_lock_irq(&priv_dev->mem_lock);
			list_for_each_entry(m_ent, &priv_dev->mem_list, list) {
				if ((!strcmp(m_ent->task_name, tname)) &&
				    m_ent->mem_info.mem_num == minfo->mem_num &&
				    m_ent->mem_info.size == minfo->size) {
					if (m_ent->mem_info.phy_addr == minfo->phy_addr &&
					    m_ent->mem_info.vir_addr == minfo->vir_addr) {
						lfound = 1;
						list_del(&m_ent->list);
					} else {
						err = -ENOMEM;
					}
					break;
				}
			}
			spin_unlock_irq(&priv_dev->mem_lock);

			if (lfound) {
				dma_free_coherent(&xdev->pdev->dev,
						  minfo->size,
						  (void *)minfo->vir_addr,
						  minfo->phy_addr);
			}
		} else {
			kvfree(in);
			return -EFAULT;
		}
	}

	hdr->attr.error = err;
	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, in->data, in->len))
		err = -EFAULT;

	kvfree(in);
	return err;
}

static long xsc_ioctl_mem_alloc(struct xsc_priv_device *priv_dev,
				struct xsc_core_device *xdev,
				struct xsc_ioctl_hdr __user *user_hdr,
				struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mem_info *minfo;
	struct xsc_ioctl_data_tl *tl;
	struct xsc_ioctl_mbox_in *in;
	struct xsc_mem_entry *m_ent;
	char tname[TASK_COMM_LEN];
	u64 vaddr = 0;
	u64 paddr = 0;
	int in_size;
	int err = 0;
	u8 lfound = 0;
	u8 needfree = 0;

	in_size = sizeof(struct xsc_ioctl_mbox_in) + hdr->attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->len = hdr->attr.length;
	err = copy_from_user(in->data, user_hdr->attr.data, hdr->attr.length);
	if (err) {
		kvfree(in);
		return -EFAULT;
	}

	if (in->len > sizeof(struct xsc_ioctl_data_tl)) {
		tl = (struct xsc_ioctl_data_tl *)(in->data);
		if (tl->length != sizeof(struct xsc_ioctl_mem_info)) {
			kvfree(in);
			return -EFAULT;
		}
		minfo = (struct xsc_ioctl_mem_info *)(tl + 1);
		memset(tname, 0, sizeof(tname));
		get_task_comm(tname, current);

		spin_lock_irq(&priv_dev->mem_lock);
		list_for_each_entry(m_ent, &priv_dev->mem_list, list) {
			if ((!strcmp(m_ent->task_name, tname)) &&
			    m_ent->mem_info.mem_num == minfo->mem_num) {
				if (m_ent->mem_info.size == minfo->size) {
					minfo->phy_addr = m_ent->mem_info.phy_addr;
					minfo->vir_addr = m_ent->mem_info.vir_addr;
					lfound = 1;
				} else {
					needfree = 1;
					list_del(&m_ent->list);
				}
				break;
			}
		}
		spin_unlock_irq(&priv_dev->mem_lock);

		if (needfree) {
			dma_free_coherent(&xdev->pdev->dev,
					  m_ent->mem_info.size,
					  (void *)m_ent->mem_info.vir_addr,
					  m_ent->mem_info.phy_addr);
		}

		if (!lfound) {
			vaddr = (u64)dma_alloc_coherent(&xdev->pdev->dev,
						minfo->size,
						(dma_addr_t *)&paddr,
						GFP_KERNEL);
			if (vaddr) {
				memset((void *)vaddr, 0, minfo->size);
				minfo->phy_addr = paddr;
				minfo->vir_addr = vaddr;
				m_ent = kzalloc(sizeof(*m_ent), GFP_KERNEL);
				if (!m_ent) {
					kvfree(in);
					return -ENOMEM;
				}
				strcpy(m_ent->task_name, tname);
				m_ent->mem_info.mem_num = minfo->mem_num;
				m_ent->mem_info.size = minfo->size;
				m_ent->mem_info.phy_addr = paddr;
				m_ent->mem_info.vir_addr = vaddr;
				spin_lock_irq(&priv_dev->mem_lock);
				list_add(&m_ent->list, &priv_dev->mem_list);
				spin_unlock_irq(&priv_dev->mem_lock);
			} else {
				kvfree(in);
				return -ENOMEM;
			}
		}
	}

	hdr->attr.error = err;
	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, in->data, in->len))
		err = -EFAULT;

	kvfree(in);
	return err;
}

static long xsc_priv_dev_ioctl_mem(struct file *filp, unsigned long arg)
{
	struct xsc_bdf_file *bdf_file = filp->private_data;
	struct xsc_core_device *xdev = bdf_file->xdev;
	struct xsc_priv_device *priv_dev = &xdev->priv_device;
	struct xsc_ioctl_hdr __user *user_hdr =
		(struct xsc_ioctl_hdr __user *)arg;
	struct xsc_ioctl_hdr hdr;
	int err;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_MEM_ALLOC:
		return xsc_ioctl_mem_alloc(priv_dev, xdev, user_hdr, &hdr);
	case XSC_IOCTL_MEM_FREE:
		return xsc_ioctl_mem_free(priv_dev, xdev, user_hdr, &hdr);
	default:
		return -EINVAL;
	}
}

static int xsc_priv_modify_qp(struct xsc_core_device *xdev, void *in, void *out)
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
		xsc_core_err(xdev, "xsc_ioctl_qp_range: resp->num == 0\n");
		return 0;
	}
	qpn = resp->qpn;
	insize = sizeof(struct xsc_modify_qp_mbox_in);
	mailin = kvzalloc(insize, GFP_KERNEL);
	if (!mailin)
		return -ENOMEM;
	if (resp->opcode == XSC_CMD_OP_RTR2RTS_QP) {
		for (i = 0; i < resp->num; i++) {
			mailin->hdr.opcode = cpu_to_be16(XSC_CMD_OP_RTR2RTS_QP);
			mailin->qpn = cpu_to_be32(qpn + i);
			ret = xsc_cmd_exec(xdev, mailin, insize, &mailout, sizeof(mailout));
			xsc_core_dbg(xdev, "modify qp state qpn:%d\n", qpn + i);
		}
	}
	kvfree(mailin);

	return ret;
}

static int xsc_priv_dev_ioctl_get_phy(struct xsc_core_device *xdev,
				      void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_data_tl *tl = (struct xsc_ioctl_data_tl *)out;
	struct xsc_ioctl_get_phy_info_res *resp;
	struct xsc_lag *ldev = xsc_lag_dev_get(xdev);
	u16 lag_id = U16_MAX;

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
		resp->pcie0_pf_funcid_base     = xdev->caps.pcie0_pf_funcid_base;
		resp->pcie0_pf_funcid_top      = xdev->caps.pcie0_pf_funcid_top;
		resp->pcie1_pf_funcid_base     = xdev->caps.pcie1_pf_funcid_base;
		resp->pcie1_pf_funcid_top      = xdev->caps.pcie1_pf_funcid_top;
		resp->hca_core_clock = xdev->caps.hca_core_clock;
		resp->mac_num = xdev->caps.mac_num;
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int xsc_priv_dev_ioctl_get_global_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_pcp *resp = (struct xsc_ioctl_global_pcp *)out;

	if (!xsc_core_is_pf(xdev)) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	resp->pcp = get_global_force_pcp();
	return 0;
}

static int xsc_priv_dev_ioctl_get_global_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_dscp *resp = (struct xsc_ioctl_global_dscp *)out;

	if (!xsc_core_is_pf(xdev)) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	resp->dscp = get_global_force_dscp();
	return 0;
}

static int xsc_priv_dev_ioctl_set_global_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_pcp *req = (struct xsc_ioctl_global_pcp *)out;

	if (!xsc_core_is_pf(xdev)) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	ret = set_global_force_pcp(req->pcp);
	return ret;
}

static int xsc_priv_dev_ioctl_set_global_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_dscp *req = (struct xsc_ioctl_global_dscp *)out;

	if (!xsc_core_is_pf(xdev)) {
		ret = -EOPNOTSUPP;
		return ret;
	}

	ret = set_global_force_dscp(req->dscp);
	return ret;
}

int xsc_priv_dev_exec_ioctl(struct xsc_core_device *xdev, void *in, int in_size, void *out,
			    int out_size)
{
	int opcode, ret = 0;
	struct xsc_ioctl_attr *hdr;

	hdr = (struct xsc_ioctl_attr *)in;
	opcode = hdr->opcode;
	switch (opcode) {
	case XSC_IOCTL_GET_PHY_INFO:
		ret = xsc_priv_dev_ioctl_get_phy(xdev, in, out);
		break;
	case XSC_IOCTL_GET_GLOBAL_PCP:
		xsc_core_dbg(xdev, "getting global pcp\n");
		ret = xsc_priv_dev_ioctl_get_global_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_GLOBAL_DSCP:
		ret = xsc_priv_dev_ioctl_get_global_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_QP_STATUS:
		xsc_core_dbg(xdev, "case XSC_IOCTL_SET_QP_STATUS:\n");
		ret = xsc_priv_modify_qp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_GLOBAL_PCP:
		xsc_core_dbg(xdev, "setting global pcp\n");
		ret = xsc_priv_dev_ioctl_set_global_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_GLOBAL_DSCP:
		xsc_core_dbg(xdev, "setting global dscp\n");
		ret = xsc_priv_dev_ioctl_set_global_dscp(xdev, in, out);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	xsc_core_dbg(xdev, "xsc_priv_dev exec_ioctl.ret=%u\n", ret);

	return ret;
}

static long xsc_priv_dev_ioctl_getinfo(struct file *filp, unsigned long arg)
{
	struct xsc_bdf_file *bdf_file = filp->private_data;
	struct xsc_core_device *xdev = bdf_file->xdev;
	struct xsc_ioctl_hdr __user *user_hdr =
		(struct xsc_ioctl_hdr __user *)arg;
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
	case XSC_IOCTL_GET_GLOBAL_PCP:
	case XSC_IOCTL_GET_GLOBAL_DSCP:
	case XSC_IOCTL_SET_QP_STATUS:
	case XSC_IOCTL_SET_GLOBAL_PCP:
	case XSC_IOCTL_SET_GLOBAL_DSCP:
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
	err = xsc_priv_dev_exec_ioctl(xdev, &in->attr,
				      (in_size - offsetof(struct xsc_ioctl_hdr, attr)),
				      in->attr.data,
		hdr.attr.length);
	in->attr.error = err;
	if (copy_to_user((void *)arg, in, in_size))
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
			       struct xsc_ioctl_hdr __user *user_hdr,
			       struct xsc_ioctl_hdr *hdr)
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

static int xsc_ioctl_modify_raw_qp(struct xsc_priv_device *priv_dev,
				   struct xsc_core_device *xdev,
				   struct xsc_ioctl_hdr __user *user_hdr,
				   struct xsc_ioctl_hdr *hdr)
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

static void xsc_pci_ctrl_cmdq_handle_res_obj(struct xsc_bdf_file *file,
					     void *in, unsigned int inlen, void *out, int opcode)
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
	case XSC_CMD_OP_CREATE_CQ:
		idx = be32_to_cpu(((struct xsc_create_cq_mbox_out *)out)->cqn);
		xsc_alloc_cq_obj(file, idx, in, inlen);
		break;
	case XSC_CMD_OP_DESTROY_CQ:
		idx = be32_to_cpu(((struct xsc_destroy_cq_mbox_in *)in)->cqn);
		xsc_destroy_cq_obj(file, idx);
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

static long xsc_priv_dev_ioctl_cmdq(struct file *filp, unsigned long arg)
{
	struct xsc_bdf_file *bdf_file = filp->private_data;
	struct xsc_priv_device *priv_dev = &bdf_file->xdev->priv_device;
	struct xsc_core_device *xdev = bdf_file->xdev;
	struct xsc_ioctl_hdr __user *user_hdr =
		(struct xsc_ioctl_hdr __user *)arg;
	struct xsc_ioctl_hdr hdr;
	int err;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_CMD_OP_IOCTL_FLOW:
		return xsc_ioctl_flow_cmdq(bdf_file, user_hdr, &hdr);
	case XSC_CMD_OP_MODIFY_RAW_QP:
		return xsc_ioctl_modify_raw_qp(priv_dev, xdev, user_hdr, &hdr);
	default:
		return -EINVAL;
	}
}

static long xsc_priv_dev_ioctl_cmdq_raw(struct file *filp, unsigned long arg)
{
	struct xsc_bdf_file *bdf_file = filp->private_data;
	struct xsc_core_device *xdev = bdf_file->xdev;
	struct xsc_ioctl_hdr __user *user_hdr =
		(struct xsc_ioctl_hdr __user *)arg;
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
	xsc_pci_ctrl_cmdq_handle_res_obj(bdf_file, in, hdr.attr.length, out, hdr.attr.opcode);

	if (copy_to_user((void *)user_hdr, &hdr, sizeof(hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, out, hdr.attr.length))
		err = -EFAULT;
err_exit:
	kfree(in);
	kfree(out);
	return err;
}

static long xsc_priv_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = xsc_priv_dev_ioctl_cmdq(filp, arg);
		break;
	case XSC_IOCTL_DRV_GET:
	case XSC_IOCTL_DRV_SET:
		// TODO refactor to split driver get and set
		err = xsc_priv_dev_ioctl_getinfo(filp, arg);
		break;
	case XSC_IOCTL_MEM:
		err = xsc_priv_dev_ioctl_mem(filp, arg);
		break;
	case XSC_IOCTL_CMDQ_RAW:
		err = xsc_priv_dev_ioctl_cmdq_raw(filp, arg);
		break;
	default:
		err = -EFAULT;
		break;
	}
	return err;
}

static const struct file_operations dev_fops = {
	.owner	= THIS_MODULE,
	.open	= xsc_priv_dev_open,
	.unlocked_ioctl = xsc_priv_dev_ioctl,
	.compat_ioctl   = xsc_priv_dev_ioctl,
	.release	= xsc_priv_dev_release,
};

int xsc_priv_dev_init(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	int ret;
	struct xsc_priv_device *priv_dev = &dev->priv_device;

	sprintf(priv_dev->device_name, "%s", ib_dev->name);

	xsc_core_dbg(dev, "device_name %s\n", priv_dev->device_name);

	ret = alloc_chrdev_region(&priv_dev->devno, 0, 1, priv_dev->device_name);
	if (ret) {
		xsc_core_err(dev, "%s cant't get major %d\n",
			     priv_dev->device_name, MAJOR(priv_dev->devno));
		return ret;
	}

	cdev_init(&priv_dev->cdev, &dev_fops);
	priv_dev->cdev.owner = THIS_MODULE;

	ret = cdev_add(&priv_dev->cdev, priv_dev->devno, 1);
	if (ret) {
		xsc_core_err(dev, "%s cdev_add error ret:%d major:%d\n",
			     priv_dev->device_name, ret, MAJOR(priv_dev->devno));
		return ret;
	}

	priv_dev->priv_class = class_create(THIS_MODULE, priv_dev->device_name);
	device_create(priv_dev->priv_class, NULL, priv_dev->devno,
		      NULL, "%s", priv_dev->device_name);

	INIT_LIST_HEAD(&priv_dev->mem_list);
	spin_lock_init(&priv_dev->mem_lock);

	INIT_RADIX_TREE(&priv_dev->bdf_tree, GFP_ATOMIC);
	spin_lock_init(&priv_dev->bdf_lock);

	xsc_core_dbg(dev, "init success\n");

	return 0;
}

void xsc_priv_dev_fini(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	struct xsc_priv_device *priv_dev;
	struct cdev *char_dev;
	struct xsc_bdf_file *bdf_file;
	struct radix_tree_iter iter;
	void **slot;

	if (!dev || !ib_dev) {
		pr_err("[%s:%d] device is null pointer\n", __func__, __LINE__);
		return;
	}

	priv_dev = &dev->priv_device;
	if (!priv_dev || !priv_dev->priv_class)
		return;
	char_dev = &priv_dev->cdev;
	if (!char_dev)
		return;

	spin_lock(&priv_dev->bdf_lock);
	radix_tree_for_each_slot(slot, &priv_dev->bdf_tree, &iter, 0) {
		bdf_file = (struct xsc_bdf_file *)(*slot);
		xsc_close_bdf_file(bdf_file);
		radix_tree_iter_delete(&priv_dev->bdf_tree, &iter, slot);
		kfree(bdf_file);
	}
	spin_unlock(&priv_dev->bdf_lock);
	device_destroy(priv_dev->priv_class, priv_dev->devno);
	cdev_del(&priv_dev->cdev);
	unregister_chrdev_region(priv_dev->devno, 1);
	class_destroy(priv_dev->priv_class);

	xsc_core_dbg(dev, "fini success\n");
}
