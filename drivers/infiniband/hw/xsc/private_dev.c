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
#include "global.h"

#define FEATURE_ONCHIP_FT_MASK		(1<<4)
#define FEATURE_DMA_RW_TBL_MASK		(1<<8)
#define FEATURE_PCT_EXP_MASK		(1<<9)

static int xsc_priv_dev_open(struct inode *inode, struct file *file)
{
	struct xsc_priv_device *priv_dev
		= container_of(inode->i_cdev, struct xsc_priv_device, cdev);

	file->private_data = priv_dev;

	pr_err("[%s:%d] %s succ\n",
		__func__, __LINE__, priv_dev->device_name);
	return 0;
}

static long xsc_ioctl_mem_free(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mem_info *minfo;
	struct xsc_ioctl_data_tl *tl;
	struct xsc_ioctl_mbox_in *in;
	struct xsc_mem_entry *mem_ent;
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
			list_for_each_entry(mem_ent, &priv_dev->mem_list, list) {
				if ((!strcmp(mem_ent->task_name, tname)) &&
					(mem_ent->mem_info.mem_num == minfo->mem_num) &&
					(mem_ent->mem_info.size == minfo->size)) {
					if ((mem_ent->mem_info.phy_addr == minfo->phy_addr) &&
						(mem_ent->mem_info.vir_addr == minfo->vir_addr)) {
						lfound = 1;
						list_del(&mem_ent->list);
					} else
						err = -ENOMEM;
					break;
				}
			}
			spin_unlock_irq(&priv_dev->mem_lock);

			if (lfound) {
				dma_free_coherent(&(xdev->pdev->dev),
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

static long xsc_ioctl_mem_alloc(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_mem_info *minfo;
	struct xsc_ioctl_data_tl *tl;
	struct xsc_ioctl_mbox_in *in;
	struct xsc_mem_entry *mem_ent;
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
		list_for_each_entry(mem_ent, &priv_dev->mem_list, list) {
			if ((!strcmp(mem_ent->task_name, tname)) &&
				(mem_ent->mem_info.mem_num == minfo->mem_num)) {
				if (mem_ent->mem_info.size == minfo->size) {
					minfo->phy_addr = mem_ent->mem_info.phy_addr;
					minfo->vir_addr = mem_ent->mem_info.vir_addr;
					lfound = 1;
				} else {
					needfree = 1;
					list_del(&mem_ent->list);
				}
				break;
			}
		}
		spin_unlock_irq(&priv_dev->mem_lock);

		if (needfree) {
			dma_free_coherent(&(xdev->pdev->dev),
					mem_ent->mem_info.size,
					(void *)mem_ent->mem_info.vir_addr,
					mem_ent->mem_info.phy_addr);
		}

		if (!lfound) {
			vaddr = (u64)dma_alloc_coherent(&(xdev->pdev->dev),
						minfo->size,
						(dma_addr_t *)&paddr,
						GFP_KERNEL);
			if (vaddr) {
				memset((void *)vaddr, 0, minfo->size);
				minfo->phy_addr = paddr;
				minfo->vir_addr = vaddr;
				mem_ent = kzalloc(sizeof(struct xsc_mem_entry), GFP_KERNEL);
				if (!mem_ent) {
					kvfree(in);
					return -ENOMEM;
				}
				strcpy(mem_ent->task_name, tname);
				mem_ent->mem_info.mem_num = minfo->mem_num;
				mem_ent->mem_info.size = minfo->size;
				mem_ent->mem_info.phy_addr = paddr;
				mem_ent->mem_info.vir_addr = vaddr;
				spin_lock_irq(&priv_dev->mem_lock);
				list_add(&mem_ent->list, &priv_dev->mem_list);
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
	struct xsc_priv_device *priv_dev = filp->private_data;
	struct xsc_core_device *xdev;
	struct xsc_ioctl_hdr __user *user_hdr =
		(struct xsc_ioctl_hdr __user *)arg;
	struct xsc_ioctl_hdr hdr;
	int err;

	/* get xdev */
	xdev = container_of(priv_dev, struct xsc_core_device, priv_device);

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

static int xsc_priv_dev_ioctl_get_phy(struct xsc_core_device *xdev,
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

static int xsc_priv_dev_ioctl_get_global_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	int ret = 0;
	struct xsc_ioctl_global_pcp *resp = (struct xsc_ioctl_global_pcp *)out;

	if (!XSC_IS_PF(xdev->glb_func_id)) {
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

	if (!XSC_IS_PF(xdev->glb_func_id)) {
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

	if (!XSC_IS_PF(xdev->glb_func_id)) {
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

	if (!XSC_IS_PF(xdev->glb_func_id)) {
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

	xsc_core_dbg(xdev, "%s failed ret=%u\n", __func__, ret);

	return ret;
}

static long xsc_priv_dev_ioctl_getinfo(struct file *filp, unsigned long arg)
{
	struct xsc_priv_device *priv_dev = filp->private_data;
	struct xsc_core_device *xdev;
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
	xdev = container_of(priv_dev, struct xsc_core_device, priv_device);
	err = xsc_priv_dev_exec_ioctl(xdev, &in->attr, (in_size-sizeof(u32)), in->attr.data,
		hdr.attr.length);
	in->attr.error = err;
	if (copy_to_user((void *)arg, in, in_size))
		err = -EFAULT;
	kvfree(in);
	return err;
}

static int xsc_ioctl_flow_cmdq(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
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

static int xsc_ioctl_qos(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr, u16 expect_req_size,
	u16 expect_resp_size, void (*encode)(void *, u32), void (*decode)(void *))
{
	struct xsc_qos_mbox_in *in;
	struct xsc_qos_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(struct xsc_qos_mbox_in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(struct xsc_qos_mbox_out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->req_prfx.mac_port = xdev->mac_port;

	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(
		xdev, in, sizeof(*in) + expect_req_size, out, sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
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

static int xsc_ioctl_cc(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr, u16 expect_req_size,
	u16 expect_resp_size, void (*encode)(void *, u32), void (*decode)(void *))
{
	struct xsc_cc_mbox_in *in;
	struct xsc_cc_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(struct xsc_cc_mbox_in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(struct xsc_cc_mbox_out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(
		xdev, in, sizeof(*in) + expect_req_size, out, sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
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

static int xsc_ioctl_hwconfig(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
	struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr, u16 expect_req_size,
	u16 expect_resp_size, void (*encode)(void *, u32), void (*decode)(void *))
{
	struct xsc_hwc_mbox_in *in;
	struct xsc_hwc_mbox_out *out;
	u16 user_size;
	int err;

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(struct xsc_hwc_mbox_in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(struct xsc_hwc_mbox_out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
	if (err)
		goto err;

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	err = xsc_cmd_exec(
		xdev, in, sizeof(*in) + expect_req_size, out, sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
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

static int xsc_ioctl_modify_raw_qp(struct xsc_priv_device *priv_dev, struct xsc_core_device *xdev,
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

static void encode_rlimit_set(void *data, u32 mac_port)
{
	struct xsc_rate_limit_set *req = (struct xsc_rate_limit_set *) data;

	req->rate_cir = __cpu_to_be32(req->rate_cir);
	req->limit_id = __cpu_to_be32(req->limit_id);
}

static void decode_rlimit_get(void *data)
{
	struct xsc_rate_limit_get *resp = (struct xsc_rate_limit_get *) data;
	int i;

	for (i = 0; i <= QOS_PRIO_MAX; i++)
		resp->rate_cir[i] = __be32_to_cpu(resp->rate_cir[i]);

	resp->max_limit_id = __be32_to_cpu(resp->max_limit_id);
}

static void encode_cc_cmd_enable_rp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_enable_rp *cc_cmd = (struct xsc_cc_cmd_enable_rp *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->enable = __cpu_to_be32(cc_cmd->enable);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_enable_np(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_enable_np *cc_cmd = (struct xsc_cc_cmd_enable_np *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->enable = __cpu_to_be32(cc_cmd->enable);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_init_alpha(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_init_alpha *cc_cmd = (struct xsc_cc_cmd_init_alpha *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->alpha = __cpu_to_be32(cc_cmd->alpha);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_g(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_g *cc_cmd = (struct xsc_cc_cmd_g *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->g = __cpu_to_be32(cc_cmd->g);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_ai(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_ai *cc_cmd = (struct xsc_cc_cmd_ai *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->ai = __cpu_to_be32(cc_cmd->ai);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_hai(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_hai *cc_cmd = (struct xsc_cc_cmd_hai *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->hai = __cpu_to_be32(cc_cmd->hai);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_th(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_th *cc_cmd = (struct xsc_cc_cmd_th *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->threshold = __cpu_to_be32(cc_cmd->threshold);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_bc(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_bc *cc_cmd = (struct xsc_cc_cmd_bc *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bytecount = __cpu_to_be32(cc_cmd->bytecount);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_cnp_opcode(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_opcode *cc_cmd = (struct xsc_cc_cmd_cnp_opcode *) data;

	cc_cmd->opcode = __cpu_to_be32(cc_cmd->opcode);
}

static void encode_cc_cmd_cnp_bth_b(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_bth_b *cc_cmd = (struct xsc_cc_cmd_cnp_bth_b *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bth_b = __cpu_to_be32(cc_cmd->bth_b);
}

static void encode_cc_cmd_cnp_bth_f(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_bth_f *cc_cmd = (struct xsc_cc_cmd_cnp_bth_f *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bth_f = __cpu_to_be32(cc_cmd->bth_f);
}

static void encode_cc_cmd_cnp_ecn(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_ecn *cc_cmd = (struct xsc_cc_cmd_cnp_ecn *) data;

	cc_cmd->ecn = __cpu_to_be32(cc_cmd->ecn);
}

static void encode_cc_cmd_data_ecn(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_data_ecn *cc_cmd = (struct xsc_cc_cmd_data_ecn *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->ecn = __cpu_to_be32(cc_cmd->ecn);
}

static void encode_cc_cmd_cnp_tx_interval(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_tx_interval *cc_cmd = (struct xsc_cc_cmd_cnp_tx_interval *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->interval = __cpu_to_be32(cc_cmd->interval);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_evt_rsttime(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_evt_rsttime *cc_cmd =
			(struct xsc_cc_cmd_evt_rsttime *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->period = __cpu_to_be32(cc_cmd->period);
}

static void encode_cc_cmd_cnp_dscp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_dscp *cc_cmd = (struct xsc_cc_cmd_cnp_dscp *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->dscp = __cpu_to_be32(cc_cmd->dscp);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_cnp_pcp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_pcp *cc_cmd = (struct xsc_cc_cmd_cnp_pcp *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->pcp = __cpu_to_be32(cc_cmd->pcp);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_evt_period_alpha(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_evt_period_alpha *cc_cmd = (struct xsc_cc_cmd_evt_period_alpha *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->period = __cpu_to_be32(cc_cmd->period);
}

static void encode_cc_get_cfg(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_get_cfg *cc_cmd = (struct xsc_cc_cmd_get_cfg *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void decode_cc_get_cfg(void *data)
{
	struct xsc_cc_cmd_get_cfg *cc_cmd = (struct xsc_cc_cmd_get_cfg *) data;

	cc_cmd->cmd = __be16_to_cpu(cc_cmd->cmd);
	cc_cmd->len = __be16_to_cpu(cc_cmd->len);
	cc_cmd->enable_rp = __be32_to_cpu(cc_cmd->enable_rp);
	cc_cmd->enable_np = __be32_to_cpu(cc_cmd->enable_np);
	cc_cmd->init_alpha = __be32_to_cpu(cc_cmd->init_alpha);
	cc_cmd->g = __be32_to_cpu(cc_cmd->g);
	cc_cmd->ai = __be32_to_cpu(cc_cmd->ai);
	cc_cmd->hai = __be32_to_cpu(cc_cmd->hai);
	cc_cmd->threshold = __be32_to_cpu(cc_cmd->threshold);
	cc_cmd->bytecount = __be32_to_cpu(cc_cmd->bytecount);
	cc_cmd->opcode = __be32_to_cpu(cc_cmd->opcode);
	cc_cmd->bth_b = __be32_to_cpu(cc_cmd->bth_b);
	cc_cmd->bth_f = __be32_to_cpu(cc_cmd->bth_f);
	cc_cmd->cnp_ecn = __be32_to_cpu(cc_cmd->cnp_ecn);
	cc_cmd->data_ecn = __be32_to_cpu(cc_cmd->data_ecn);
	cc_cmd->cnp_tx_interval = __be32_to_cpu(cc_cmd->cnp_tx_interval);
	cc_cmd->evt_period_rsttime = __be32_to_cpu(cc_cmd->evt_period_rsttime);
	cc_cmd->cnp_dscp = __be32_to_cpu(cc_cmd->cnp_dscp);
	cc_cmd->cnp_pcp = __be32_to_cpu(cc_cmd->cnp_pcp);
	cc_cmd->evt_period_alpha = __be32_to_cpu(cc_cmd->evt_period_alpha);
	cc_cmd->section = __be32_to_cpu(cc_cmd->section);
}

static void encode_cc_get_stat(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_get_stat *cc_cmd = (struct xsc_cc_cmd_get_stat *) data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void decode_cc_get_stat(void *data)
{
	struct xsc_cc_cmd_stat *cc_cmd = (struct xsc_cc_cmd_stat *) data;

	cc_cmd->cnp_handled = __be32_to_cpu(cc_cmd->cnp_handled);
	cc_cmd->alpha_recovery = __be32_to_cpu(cc_cmd->alpha_recovery);
	cc_cmd->reset_timeout = __be32_to_cpu(cc_cmd->reset_timeout);
	cc_cmd->reset_bytecount = __be32_to_cpu(cc_cmd->reset_bytecount);
}

static long xsc_priv_dev_ioctl_cmdq(struct file *filp, unsigned long arg)
{
	struct xsc_priv_device *priv_dev = filp->private_data;
	struct xsc_core_device *xdev;
	struct xsc_ioctl_hdr __user *user_hdr =
		(struct xsc_ioctl_hdr __user *)arg;
	struct xsc_ioctl_hdr hdr;
	int err;
	void *in;
	void *out;

	/* get xdev */
	xdev = container_of(priv_dev, struct xsc_core_device, priv_device);

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_CMD_OP_IOCTL_FLOW:
		return xsc_ioctl_flow_cmdq(priv_dev, xdev, user_hdr, &hdr);
	case XSC_CMD_OP_CREATE_QP:
		break;
	case XSC_CMD_OP_DESTROY_QP:
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
	case XSC_CMD_OP_IOCTL_SET_DSCP_PMT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_dscp_pmt_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_DSCP_PMT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	0, sizeof(struct xsc_dscp_pmt_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_TRUST_MODE:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_trust_mode_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_TRUST_MODE:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	0, sizeof(struct xsc_trust_mode_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_PCP_PMT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_pcp_pmt_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_PCP_PMT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	0, sizeof(struct xsc_pcp_pmt_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_DEFAULT_PRI:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_default_pri_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_DEFAULT_PRI:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	0, sizeof(struct xsc_default_pri_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_PFC:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_pfc_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_PFC:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr, 0, sizeof(struct xsc_pfc_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_RATE_LIMIT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_rate_limit_set), 0,
			encode_rlimit_set, NULL);
	case XSC_CMD_OP_IOCTL_GET_RATE_LIMIT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_rate_limit_get),
			sizeof(struct xsc_rate_limit_get), NULL, decode_rlimit_get);
	case XSC_CMD_OP_IOCTL_SET_SP:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_sp_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_SP:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	0, sizeof(struct xsc_sp_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_WEIGHT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	sizeof(struct xsc_weight_set), 0,
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_WEIGHT:
		return xsc_ioctl_qos(
			priv_dev, xdev, user_hdr, &hdr,	0, sizeof(struct xsc_weight_get),
			NULL, NULL);
	case XSC_CMD_OP_IOCTL_SET_ENABLE_RP:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_enable_rp),
			0, encode_cc_cmd_enable_rp, NULL);
	case XSC_CMD_OP_IOCTL_SET_ENABLE_NP:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_enable_np),
			0, encode_cc_cmd_enable_np, NULL);
	case XSC_CMD_OP_IOCTL_SET_INIT_ALPHA:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_init_alpha),
			0, encode_cc_cmd_init_alpha, NULL);
	case XSC_CMD_OP_IOCTL_SET_G:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_g),
			0, encode_cc_cmd_g, NULL);
	case XSC_CMD_OP_IOCTL_SET_AI:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_ai),
			0, encode_cc_cmd_ai, NULL);
	case XSC_CMD_OP_IOCTL_SET_HAI:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_hai),
			0, encode_cc_cmd_hai, NULL);
	case XSC_CMD_OP_IOCTL_SET_TH:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_th),
			0, encode_cc_cmd_th, NULL);
	case XSC_CMD_OP_IOCTL_SET_BC_TH:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_bc),
			0, encode_cc_cmd_bc, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_OPCODE:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_opcode),
			0, encode_cc_cmd_cnp_opcode, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_B:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_bth_b),
			0, encode_cc_cmd_cnp_bth_b, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_F:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_bth_f),
			0, encode_cc_cmd_cnp_bth_f, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_ECN:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_ecn),
			0, encode_cc_cmd_cnp_ecn, NULL);
	case XSC_CMD_OP_IOCTL_SET_DATA_ECN:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_data_ecn),
			0, encode_cc_cmd_data_ecn, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_TX_INTERVAL:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_tx_interval),
			0, encode_cc_cmd_cnp_tx_interval, NULL);
	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_RSTTIME:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr,
			sizeof(struct xsc_cc_cmd_evt_rsttime), 0, encode_cc_cmd_evt_rsttime, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_DSCP:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_dscp),
			0, encode_cc_cmd_cnp_dscp, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_PCP:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_pcp),
			0, encode_cc_cmd_cnp_pcp, NULL);
	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_ALPHA:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_evt_period_alpha),
			0, encode_cc_cmd_evt_period_alpha, NULL);
	case XSC_CMD_OP_IOCTL_GET_CC_CFG:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_get_cfg),
			sizeof(struct xsc_cc_cmd_get_cfg), encode_cc_get_cfg, decode_cc_get_cfg);
	case XSC_CMD_OP_IOCTL_GET_CC_STAT:
		return xsc_ioctl_cc(
			priv_dev, xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_get_stat),
			sizeof(struct xsc_cc_cmd_stat), encode_cc_get_stat, decode_cc_get_stat);
	case XSC_CMD_OP_IOCTL_SET_HWC:
		return xsc_ioctl_hwconfig(priv_dev, xdev, user_hdr, &hdr,
			sizeof(struct hwc_set_t), 0, NULL, NULL);
	case XSC_CMD_OP_IOCTL_GET_HWC:
		return xsc_ioctl_hwconfig(priv_dev, xdev, user_hdr, &hdr,
			sizeof(struct hwc_get_t), sizeof(struct hwc_get_t), NULL, NULL);
	case XSC_CMD_OP_MODIFY_RAW_QP:
		return xsc_ioctl_modify_raw_qp(priv_dev, xdev, user_hdr, &hdr);
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

	xsc_core_dbg(dev, "init success\n");

	return 0;
}

void xsc_priv_dev_fini(struct ib_device *ib_dev, struct xsc_core_device *dev)
{
	struct xsc_priv_device *priv_dev;
	struct cdev *char_dev;

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

	device_destroy(priv_dev->priv_class, priv_dev->devno);
	cdev_del(&priv_dev->cdev);
	unregister_chrdev_region(priv_dev->devno, 1);
	class_destroy(priv_dev->priv_class);

	xsc_core_dbg(dev, "fini success\n");
}
