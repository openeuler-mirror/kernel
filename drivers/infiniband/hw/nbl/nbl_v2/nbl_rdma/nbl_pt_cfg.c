// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2022, nebula-matrix Limited */

#include <linux/debugfs.h>

#include "grc.h"
#include "main.h"
#include "nbl_pt_cfg.h"

/*
 * ATTENTION: DON'T CHANGE ARRAY ORDER!
 */
static const char *const nbl_dbg_pt_name[] = {
	"pt_en",
	"pt_code_trimmed",
	"pt_code_trimmed_last",
	"pt_code_trimmable",
	"pt_code_control",
	"pt_nak_pri_same_as_cnp_en",
};

/* Get pointer to the cached pt_params */
static struct nbl_pt_params *nbl_pt_get_params(struct nbl_device *dev)
{
	return &dev->rf->sc_dev.pt_params;
}

/* Write PT_EN register: read-modify-write, only modify the single field for @offset */
static int nbl_pt_write_en_reg(struct nbl_pci_f *rf, int offset, bool val)
{
	union nbl_pt_en_reg reg;
	u32 reg_val;
	int ret;

	ret = nbl_grc_read_reg(rf, NBL_RDMA_TOP_PT_EN_V4, &reg_val);
	if (ret) {
		nbl_pr_err("failed to read PT_EN reg:%#x\n", NBL_RDMA_TOP_PT_EN_V4);
		return ret;
	}
	reg.data = reg_val;

	switch (offset) {
	case NBL_CFG_PT_EN:
		reg.pt_en = val;
		break;
	case NBL_CFG_PT_NAK_PRI_SAME_AS_CNP_EN:
		reg.pt_nak_pri_same_as_cnp_en = val;
		break;
	default:
		return -EINVAL;
	}

	ret = nbl_grc_write_reg(rf, NBL_RDMA_TOP_PT_EN_V4, reg.data);
	if (ret)
		nbl_pr_err("failed to write PT_EN reg:%#x val:%#x\n",
			   NBL_RDMA_TOP_PT_EN_V4, reg.data);
	return ret;
}

/* Write PT_CODE_VAL register: read-modify-write, only modify the single field for @offset */
static int nbl_pt_write_code_reg(struct nbl_pci_f *rf, int offset, u32 val)
{
	union nbl_pt_code_val_reg reg;
	int ret;

	ret = nbl_grc_read_reg(rf, NBL_RDMA_TOP_PT_CODE_V4, &reg.data);
	if (ret) {
		nbl_pr_err("failed to read PT_CODE_VAL reg:%#x\n", NBL_RDMA_TOP_PT_CODE_V4);
		return ret;
	}

	switch (offset) {
	case NBL_CFG_PT_CODE_TRIMMED:
		reg.pt_code_trimmed = val;
		break;
	case NBL_CFG_PT_CODE_TRIMMED_LAST:
		reg.pt_code_trimmed_last = val;
		break;
	case NBL_CFG_PT_CODE_TRIMMABLE:
		reg.pt_code_trimmable = val;
		break;
	case NBL_CFG_PT_CODE_CONTROL:
		reg.pt_code_control = val;
		break;
	default:
		return -EINVAL;
	}

	ret = nbl_grc_write_reg(rf, NBL_RDMA_TOP_PT_CODE_V4, reg.data);
	if (ret)
		nbl_pr_err("failed to write PT_CODE_VAL reg:%#x val:%#x\n",
			   NBL_RDMA_TOP_PT_CODE_V4, reg.data);
	return ret;
}

static int nbl_pt_check_param_val(int offset, u32 *var_arr)
{
	switch (offset) {
	case NBL_CFG_PT_EN:
	case NBL_CFG_PT_NAK_PRI_SAME_AS_CNP_EN:
		if (var_arr[0] > NBL_ENABLE_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_PT_CODE_CONTROL:
	case NBL_CFG_PT_CODE_TRIMMABLE:
	case NBL_CFG_PT_CODE_TRIMMED:
	case NBL_CFG_PT_CODE_TRIMMED_LAST:
		if (var_arr[0] > NBL_DSCP_MAX) {
			nbl_pr_err("pt params %s val:%d is invalid (must be 0-63).\n",
				   nbl_dbg_pt_name[offset], var_arr[0]);
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* Update cached struct and write the corresponding register field */
static int nbl_pt_set_param_into_reg(struct nbl_device *dev, int offset, u32 val)
{
	struct nbl_pt_params *pt_params = nbl_pt_get_params(dev);
	int ret;

	switch (offset) {
	case NBL_CFG_PT_EN:
		ret = nbl_pt_write_en_reg(dev->rf, offset, !!val);
		if (!ret) {
			pt_params->en.pt_en = !!val;
			nbl_try_init_net_tc_tbl_pt(dev, true, false, false, !!val);
		}
		break;
	case NBL_CFG_PT_NAK_PRI_SAME_AS_CNP_EN:
		ret = nbl_pt_write_en_reg(dev->rf, offset, !!val);
		if (!ret) {
			pt_params->en.pt_nak_pri_same_as_cnp_en = !!val;
			nbl_try_init_net_tc_tbl_pt(dev, false, true, false, !!val);
		}
		break;
	case NBL_CFG_PT_CODE_TRIMMED:
		ret = nbl_pt_write_code_reg(dev->rf, offset, val);
		if (!ret)
			pt_params->code.pt_code_trimmed = val;
		break;
	case NBL_CFG_PT_CODE_TRIMMED_LAST:
		ret = nbl_pt_write_code_reg(dev->rf, offset, val);
		if (!ret)
			pt_params->code.pt_code_trimmed_last = val;
		break;
	case NBL_CFG_PT_CODE_TRIMMABLE:
		ret = nbl_pt_write_code_reg(dev->rf, offset, val);
		if (!ret)
			pt_params->code.pt_code_trimmable = val;
		break;
	case NBL_CFG_PT_CODE_CONTROL:
		ret = nbl_pt_write_code_reg(dev->rf, offset, val);
		if (!ret) {
			pt_params->code.pt_code_control = val;
			nbl_try_init_net_tc_tbl_pt(dev, false, false, false, false);
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/* Read a single PT parameter value from cached struct by offset */
static u32 nbl_pt_get_param_val(struct nbl_pt_params *pt_params, int offset)
{
	switch (offset) {
	case NBL_CFG_PT_EN:
		return pt_params->en.pt_en;
	case NBL_CFG_PT_NAK_PRI_SAME_AS_CNP_EN:
		return pt_params->en.pt_nak_pri_same_as_cnp_en;
	case NBL_CFG_PT_CODE_TRIMMED:
		return pt_params->code.pt_code_trimmed;
	case NBL_CFG_PT_CODE_TRIMMED_LAST:
		return pt_params->code.pt_code_trimmed_last;
	case NBL_CFG_PT_CODE_TRIMMABLE:
		return pt_params->code.pt_code_trimmable;
	case NBL_CFG_PT_CODE_CONTROL:
		return pt_params->code.pt_code_control;
	default:
		return 0;
	}
}

static void nbl_init_net_tc_tbl_when_pt_en(struct nbl_device *dev)
{
	struct nbl_hw *hw = &dev->rf->hw;
	union nbl_pt_net_tc_tbl_reg reg;
	void *reg_addr;
	u32 dscp_low;
	int i;

	/* Read pt_control_val low 3 bits from cached pt params */
	dscp_low = dev->rf->sc_dev.pt_params.code.pt_code_control & 0x7;

	/* Read-modify-write each table entry: only update dscp_low field */
	reg_addr = hw->hw_addr + NBL_REG_TXM_BASE(hw);
	for (i = 0; i < NBL_TXM_NET_TC_TBL_ENTRY_NUM; i++) {
		reg.data = readl(NBL_TXM_NET_TC_TBL_ADDR(reg_addr, i));
		reg.dscp_low = dscp_low;
		writel(reg.data, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, i));
	}
}

/* Check if all three PT remark enables are set and try to init net tc tbl */
void nbl_try_init_net_tc_tbl_pt(struct nbl_device *dev, bool pt_en_changed,
				bool pt_nak_pri_changed, bool cc_oamack_changed,
				bool new_val)
{
	struct nbl_pt_params *pt_params = nbl_pt_get_params(dev);
	bool pt_en, pt_nak_pri_same_as_cnp_en, cc_oamack_tc_en;

	if (!nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_PT))
		return;

	/* Determine current values considering the pending write */
	pt_en = pt_en_changed ? new_val : pt_params->en.pt_en;
	pt_nak_pri_same_as_cnp_en = pt_nak_pri_changed ? new_val :
		pt_params->en.pt_nak_pri_same_as_cnp_en;
	cc_oamack_tc_en = cc_oamack_changed ? new_val :
		dev->rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_OAMACK_TC_EN];

	if (pt_en && pt_nak_pri_same_as_cnp_en && cc_oamack_tc_en)
		nbl_init_net_tc_tbl_when_pt_en(dev);
	else
		nbl_set_net_tc_tbl(dev->rf);
}

static int nbl_pt_do_set_param(struct nbl_device *dev, int offset, u32 var)
{
	int ret;

	ret = nbl_pt_check_param_val(offset, &var);
	if (ret) {
		nbl_pr_err("config pt param:%s is invalid, please check the param.\n",
			   nbl_dbg_pt_name[offset]);
		return ret;
	}

	ret = nbl_pt_set_param_into_reg(dev, offset, var);
	if (ret) {
		nbl_pr_err("failed to set pt params into reg.\n");
		return ret;
	}

	nbl_pr_dbg("save %s:%u\n", nbl_dbg_pt_name[offset],
		   nbl_pt_get_param_val(nbl_pt_get_params(dev), offset));
	return 0;
}

static ssize_t nbl_pt_set_param(struct file *filp, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	int offset = param->offset;
	char lbuf[32] = {};
	u32 var;
	int ret;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	nbl_pr_dbg("config pt param:%s val:%s count:%zu\n",
		   param->dentry->d_iname, lbuf, count);

	if (kstrtou32(strim(lbuf), 0, &var))
		return -EINVAL;

	ret = nbl_pt_do_set_param(param->dev, offset, var);
	return ret ? ret : count;
}

static ssize_t nbl_pt_get_param(struct file *filp, char __user *buf, size_t count,
				loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *dev = param->dev;
	int offset = param->offset;
	char lbuf[32];
	int ret;

	ret = snprintf(lbuf, sizeof(lbuf), "%u\n",
		       nbl_pt_get_param_val(nbl_pt_get_params(dev), offset));
	return simple_read_from_buffer(buf, count, pos, lbuf, ret);
}

static void nbl_pt_default_cfg(struct nbl_device *dev)
{
	struct nbl_pt_params *pt_params = nbl_pt_get_params(dev);
	union nbl_pt_en_reg en_reg;
	union nbl_pt_code_val_reg code_reg;

	if (!nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_PT))
		return;

	/* Packet Trim default: pt_event_to_cc enabled, others disabled */
	en_reg.data = 0;
	en_reg.pt_event_to_cc_en = true;
	nbl_grc_write_reg(dev->rf, NBL_RDMA_TOP_PT_EN_V4, en_reg.data);
	pt_params->en.data = en_reg.data;

	code_reg.data = 0;
	nbl_grc_write_reg(dev->rf, NBL_RDMA_TOP_PT_CODE_V4, code_reg.data);
	pt_params->code.data = code_reg.data;
}

static const struct file_operations dbg_pt_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = nbl_pt_set_param,
	.read = nbl_pt_get_param,
};

int __nbl_pt_debugfs_init(struct nbl_device *dev)
{
	struct nbl_ib_dbg_param *params;
	struct dentry *pt_root;
	int i;

	if (!dev->func_dbg_dir)
		return -EINVAL;

	pt_root = debugfs_create_dir("packet_trimming", dev->func_dbg_dir);
	if (!pt_root) {
		nbl_pr_err("init packet_trimming directory failed\n");
		return -ENOMEM;
	}

	params = kzalloc(sizeof(*params) * NBL_CFG_PT_TYPE_MAX, GFP_KERNEL);
	if (!params) {
		debugfs_remove_recursive(pt_root);
		return -ENOMEM;
	}

	for (i = 0; i < NBL_CFG_PT_TYPE_MAX; i++) {
		params[i].offset = i;
		params[i].dev = dev;
		params[i].dentry = debugfs_create_file(
			nbl_dbg_pt_name[i], 0600, pt_root,
			&params[i], &dbg_pt_fops);
	}

	dev->pt_params = params;
	dev->pt_root = pt_root;

	nbl_pt_default_cfg(dev);

	return 0;
}

void __nbl_pt_debugfs_cleanup(struct nbl_device *dev)
{
	if (!dev->pt_root)
		return;

	debugfs_remove_recursive(dev->pt_root);
	kfree(dev->pt_params);
	dev->pt_root = NULL;
	dev->pt_params = NULL;
}

int nbl_pt_debugfs_init(struct nbl_device *dev)
{
	const struct nbl_feature_ops *ops = dev->rf->product->feature_ops;

	if (!nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_PT))
		return 0;

	return ops->pt_debugfs_init(dev);
}

void nbl_pt_debugfs_cleanup(struct nbl_device *dev)
{
	const struct nbl_feature_ops *ops = dev->rf->product->feature_ops;

	if (nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_PT))
		ops->pt_debugfs_cleanup(dev);
}
