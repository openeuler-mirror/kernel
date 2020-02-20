// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/acpi.h>
#include <linux/aer.h>
#include <linux/bitops.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/seq_file.h>
#include <linux/topology.h>
#include <linux/uacce.h>
#include "rde.h"

#define HRDE_VF_NUM		63
#define HRDE_QUEUE_NUM_V1	4096
#define HRDE_QUEUE_NUM_V2	1024
#define HRDE_PCI_DEVICE_ID	0xa25a
#define HRDE_SQE_SIZE		64
#define HRDE_SQ_SIZE		(HRDE_SQE_SIZE * QM_Q_DEPTH)
#define HRDE_PF_DEF_Q_NUM	64
#define HRDE_PF_DEF_Q_BASE	0
#define HRDE_RD_INTVRL_US	10
#define HRDE_RD_TMOUT_US	1000
#define FORMAT_DECIMAL		10
#define HRDE_RST_TMOUT_MS	400
#define HRDE_ENABLE		1
#define HRDE_DISABLE		0
#define HRDE_PCI_COMMAND_INVALID	0xFFFFFFFF

#define HRDE_RAS_INT_MSK	0x310290
#define HRDE_RAS_CE_MSK		BIT(2)
#define HRDE_RAS_NFE_MSK	BIT(1)
#define HRDE_RAS_ENABLE		BIT(0)
#define HRDE_INT_MSK		0x310314
#define HRDE_INT_ENABLE		0x0
#define HRDE_INT_DISABLE	0x3ffff
#define HRDE_BD_PREFETCH	BIT(8)
#define HRDE_INT_SOURCE		0x31030c
#define HRDE_INT_SOURCE_CLEAR	GENMASK(17, 0)
#define HRDE_INT_STATUS		0x310318
#define HRDE_DFX_CTRL_0		0x310240
#define HRDE_ECC_ERR		0x310234
#define HRDE_ECC_ERR_CNT	0x310238
#define HRDE_OP_DONE_CNT	0x310250
#define HRDE_OP_ERR_CNT		0x310254
#define HRDE_OP_ABORT_CNT	0x310258
#define HRDE_FIFO_STAT_0	0x310200
#define HRDE_DFX_STAT_7		0x310334
#define HRDE_DFX_STAT_8		0x310338
#define DFX_CTRL0		0x3
#define WRITE_CLEAR_VAL		GENMASK(31, 0)
#define HRDE_AWCACHE		0x310154
#define HRDE_ARCACHE		0x31015c
#define AWCACHE			0xff0
#define ARCACHE			0xfff0
#define HRDE_CFG		0x310000
#define CHN_CFG			0x5010101
#define HRDE_AXI_SHUTDOWN_EN	BIT(26)
#define HRDE_AXI_SHUTDOWN_DIS	0xFBFFFFFF
#define HRDE_WR_MSI_PORT	0xFFFE
#define HRDE_AWUSER_BD_1	0x310104
#define HRDE_ARUSER_BD_1	0x310114
#define HRDE_ARUSER_SGL_1	0x310124
#define HRDE_AWUSER_DAT_1	0x310134
#define HRDE_ARUSER_DAT_1	0x310144
#define HRDE_USER_SMMU		0x40001070
#define HRDE_ERR_CNT		0x310238
#define HRDE_ECC_1BIT_ERR	BIT(0)
#define HRDE_ECC_2BIT_ERR	BIT(1)
#define HRDE_ECC_1BIT_SHIFT	16
#define HRDE_ECC_2BIT_CNT_MSK	GENMASK(15, 0)
#define HRDE_STATE_INT_ERR	GENMASK(11, 2)
#define HRDE_AM_CURR_PORT_STS	0x300100
#define HRDE_MASTER_TRANS_RET	0x300150
#define HRDE_FSM_MAX_CNT	0x310280
#define HRDE_QM_IDEL_STATUS	0x1040e4
#define HRDE_QM_PEH_DFX_INFO0	0x1000fc
#define PEH_MSI_MASK_SHIFT	0x90
#define HRDE_MASTER_GLOBAL_CTRL		0x300000
#define MASTER_GLOBAL_CTRL_SHUTDOWN	0x1
#define MASTER_TRANS_RETURN_RW	0x3
#define CACHE_CTL		0x1833
#define HRDE_DBGFS_VAL_MAX_LEN	20
#define HRDE_PROBE_ADDR		0x31025c
#define HRDE_PROBE_DATA		0x310260
#define HRDE_PROBE_EN		BIT(16)
#define HRDE_PROBE_DATA_EN	BIT(17)
#define HRDE_STRB_CS_SHIFT	9

static const char hisi_rde_name[] = "hisi_rde";
static struct dentry *hrde_debugfs_root;
LIST_HEAD(hisi_rde_list);
DEFINE_MUTEX(hisi_rde_list_lock);
static void hisi_rde_ras_proc(struct work_struct *work);

struct hisi_rde_resource {
	struct hisi_rde *hrde;
	int distance;
	struct list_head list;
};

static const struct hisi_rde_hw_error rde_hw_error[] = {
	{.int_msk = BIT(0), .msg = "Rde_ecc_1bitt_err"},
	{.int_msk = BIT(1), .msg = "Rde_ecc_2bit_err"},
	{.int_msk = BIT(2), .msg = "Rde_stat_mgmt_state_timeout_err"},
	{.int_msk = BIT(3), .msg = "Rde_data_wr_state_timeout_err"},
	{.int_msk = BIT(4), .msg = "Rde_alg_state_timeout_err"},
	{.int_msk = BIT(5), .msg = "Rde_data_ar_state_timeout_err"},
	{.int_msk = BIT(6), .msg = "Rde_bd_mgmt_state_timeout_err"},
	{.int_msk = BIT(7), .msg = "Rde_list_parse_ar_state_timeout_err"},
	{.int_msk = BIT(8), .msg = "Rde_bd_prefetch_state_timeout_err"},
	{.int_msk = BIT(9), .msg = "Rde_dst_buf_parse_state_timeout_err"},
	{.int_msk = BIT(10), .msg = "Rde_src_buf_parse_state_timeout_err"},
	{.int_msk = BIT(11), .msg = "Rde_chn_timeout_err"},
	{.int_msk = BIT(12), .msg = "Rde_bd_bresp_err"},
	{.int_msk = BIT(13), .msg = "Rde_data_bresp_err"},
	{.int_msk = BIT(14), .msg = "Rde_data_rresp_err"},
	{.int_msk = BIT(15), .msg = "Rde_sgl_rresp_err"},
	{.int_msk = BIT(16), .msg = "Rde_list_rresp_err"},
	{.int_msk = BIT(17), .msg = "Rde_bd_rresp_err"},
	{ /* sentinel */ }
};

enum ctrl_debug_file_index {
	HRDE_CURRENT_FUNCTION,
	HRDE_CURRENT_BD,
	HRDE_DEBUG_FILE_NUM,
	/* RDE not support CNT_CLR_CE config, default enable */
};

static const char *const ctrl_debug_file_name[] = {
	[HRDE_CURRENT_FUNCTION] = "current_function_id",
	[HRDE_CURRENT_BD] = "current_bd",
};

struct ctrl_debug_file {
	enum ctrl_debug_file_index index;
	spinlock_t lock;
	struct hisi_rde_ctrl *ctrl;
};

/*
 * One RDE controller has one PF and multiple VFs, some global configurations
 * which PF has need this structure.
 * Just relevant for PF.
 */
struct hisi_rde_ctrl {
	struct hisi_rde *hisi_rde;
	struct dentry *debug_root;
	struct ctrl_debug_file files[HRDE_DEBUG_FILE_NUM];
};

static struct debugfs_reg32 hrde_dfx_regs[] = {
	{"HRDE_DFX_STAT_0", 0x310220ull},
	{"HRDE_DFX_STAT_1", 0x310224ull},
	{"HRDE_DFX_STAT_2", 0x310320ull},
	{"HRDE_DFX_STAT_3", 0x310324ull},
	{"HRDE_DFX_STAT_4", 0x310328ull},
	{"HRDE_DFX_STAT_5", 0x31032cull},
	{"HRDE_DFX_STAT_6", 0x310330ull},
	{"HRDE_DFX_STAT_7", 0x310334ull},
	{"HRDE_DFX_STAT_8", 0x310338ull},
	{"HRDE_FIFO_STAT_0", 0x310200ull},
	{"HRDE_FIFO_STAT_1", 0x310204ull},
	{"HRDE_OP_TAG_0", 0x310214ull},
	{"HRDE_OP_TAG_1", 0x310218ull},
	{"HRDE_OP_TAG_2", 0x31021cull},
	{"HRDE_ECC_ERR", 0x310234ull},
	{"HRDE_ECC_ERR_CNT", 0x310238ull},
	{"HRDE_OP_DONE_CNT", 0x310250ull},
	{"HRDE_OP_ERR_CNT", 0x310254ull},
	{"HRDE_OP_ABORT_CNT", 0x310258ull},
	{"HRDE_TMP_ADDR_HIGH", 0x310270ull},
	{"HRDE_TMP_ADDR_LOW", 0x310274ull},
	{"HRDE_TMP_LENGTH", 0x310278ull},
	{"HRDE_INT_STATUS", 0x310318ull},
};

static struct debugfs_reg32 hrde_ooo_dfx_regs[] = {
	{"HRDE_AM_CURR_PORT_STS", 0x300100ull},
	{"HRDE_AM_ROB_ECC_ERR_ADDR", 0x30010cull},
	{"HRDE_AM_CURR_TRANS_RETURN", 0x300150ull},
	{"HRDE_AM_CURR_RD_TXID_STS_0", 0x300160ull},
	{"HRDE_AM_CURR_RD_TXID_STS_1", 0x300164ull},
	{"HRDE_AM_CURR_RD_TXID_STS_2", 0x300168ull},
	{"HRDE_AM_CURR_WR_TXID_STS_0", 0x300170ull},
	{"HRDE_AM_CURR_WR_TXID_STS_1", 0x300174ull},
	{"HRDE_AM_CURR_WR_TXID_STS_2", 0x300178ull},
};

static int pf_q_num_set(const char *val, const struct kernel_param *kp)
{
	struct pci_dev *pdev;
	u32 n;
	u32 q_num;
	u8 rev_id;
	int ret;

	if (!val)
		return -EINVAL;

	pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI, HRDE_PCI_DEVICE_ID, NULL);
	if (unlikely(!pdev)) {
		q_num = min_t(u32, HRDE_QUEUE_NUM_V1, HRDE_QUEUE_NUM_V2);
		pr_info
		    ("No device found currently, suppose queue number is %d.\n",
		     q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case QM_HW_V1:
			q_num = HRDE_QUEUE_NUM_V1;
			break;
		case QM_HW_V2:
			q_num = HRDE_QUEUE_NUM_V2;
			break;
		default:
			return -EINVAL;
		}
	}

	ret = kstrtou32(val, 10, &n);
	if (ret != 0 || n > q_num)
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops pf_q_num_ops = {
	.set = pf_q_num_set,
	.get = param_get_int,
};

static int uacce_mode_set(const char *val, const struct kernel_param *kp)
{
	u32 n;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, FORMAT_DECIMAL, &n);
	if (ret != 0 || (n != UACCE_MODE_NOIOMMU && n != UACCE_MODE_NOUACCE))
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops uacce_mode_ops = {
	.set = uacce_mode_set,
	.get = param_get_int,
};


static u32 pf_q_num = HRDE_PF_DEF_Q_NUM;
module_param_cb(pf_q_num, &pf_q_num_ops, &pf_q_num, 0444);
MODULE_PARM_DESC(pf_q_num, "Number of queues in PF(v1 0-4096, v2 0-1024)");

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param_cb(uacce_mode, &uacce_mode_ops, &uacce_mode, 0444);
MODULE_PARM_DESC(uacce_mode, "Mode of UACCE can be 0(default), 2");

static const struct pci_device_id hisi_rde_dev_ids[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HRDE_PCI_DEVICE_ID)},
	{0,}
};

MODULE_DEVICE_TABLE(pci, hisi_rde_dev_ids);

static void free_list(struct list_head *head)
{
	struct hisi_rde_resource *res;
	struct hisi_rde_resource *tmp;

	list_for_each_entry_safe(res, tmp, head, list) {
		list_del(&res->list);
		kfree(res);
	}
}

struct hisi_rde *find_rde_device(int node)
{
	struct hisi_rde *ret = NULL;
#ifdef CONFIG_NUMA
	struct hisi_rde_resource *res, *tmp;
	struct hisi_rde *hisi_rde;
	struct list_head *n;
	struct device *dev;
	LIST_HEAD(head);

	mutex_lock(&hisi_rde_list_lock);

	list_for_each_entry(hisi_rde, &hisi_rde_list, list) {
		res = kzalloc(sizeof(*res), GFP_KERNEL);
		if (!res)
			goto err;

		dev = &hisi_rde->qm.pdev->dev;
		res->hrde = hisi_rde;
		res->distance = node_distance(dev->numa_node, node);
		n = &head;
		list_for_each_entry(tmp, &head, list) {
			if (res->distance < tmp->distance) {
				n = &tmp->list;
				break;
			}
		}
		list_add_tail(&res->list, n);
	}

	list_for_each_entry(tmp, &head, list) {
		if (tmp->hrde->q_ref + 1 <= pf_q_num) {
			tmp->hrde->q_ref = tmp->hrde->q_ref + 1;
			ret = tmp->hrde;
			break;
		}
	}

	free_list(&head);
#else
	mutex_lock(&hisi_rde_list_lock);
	ret = list_first_entry(&hisi_rde_list, struct hisi_rde, list);
#endif
	mutex_unlock(&hisi_rde_list_lock);
	return ret;

err:
	free_list(&head);
	mutex_unlock(&hisi_rde_list_lock);
	return NULL;
}

static inline void hisi_rde_add_to_list(struct hisi_rde *hisi_rde)
{
	mutex_lock(&hisi_rde_list_lock);
	list_add_tail(&hisi_rde->list, &hisi_rde_list);
	mutex_unlock(&hisi_rde_list_lock);
}

static inline void hisi_rde_remove_from_list(struct hisi_rde *hisi_rde)
{
	mutex_lock(&hisi_rde_list_lock);
	list_del(&hisi_rde->list);
	mutex_unlock(&hisi_rde_list_lock);
}

static void hisi_rde_engine_init(struct hisi_rde *hisi_rde)
{
	writel(DFX_CTRL0, hisi_rde->qm.io_base + HRDE_DFX_CTRL_0);

	/* usr domain */
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_AWUSER_BD_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_ARUSER_BD_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_AWUSER_DAT_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_ARUSER_DAT_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_ARUSER_SGL_1);
	/* rde cache */
	writel(AWCACHE, hisi_rde->qm.io_base + HRDE_AWCACHE);
	writel(ARCACHE, hisi_rde->qm.io_base + HRDE_ARCACHE);

	/* rde chn enable + outstangding config */
	writel(CHN_CFG, hisi_rde->qm.io_base + HRDE_CFG);
}

static void hisi_rde_set_user_domain_and_cache(struct hisi_rde *hisi_rde)
{
	/* qm user domain */
	writel(AXUSER_BASE, hisi_rde->qm.io_base + QM_ARUSER_M_CFG_1);
	writel(ARUSER_M_CFG_ENABLE, hisi_rde->qm.io_base +
	       QM_ARUSER_M_CFG_ENABLE);
	writel(AXUSER_BASE, hisi_rde->qm.io_base + QM_AWUSER_M_CFG_1);
	writel(AWUSER_M_CFG_ENABLE, hisi_rde->qm.io_base +
	       QM_AWUSER_M_CFG_ENABLE);
	writel(WUSER_M_CFG_ENABLE, hisi_rde->qm.io_base +
	       QM_WUSER_M_CFG_ENABLE);

	/* qm cache */
	writel(AXI_M_CFG, hisi_rde->qm.io_base + QM_AXI_M_CFG);
	writel(AXI_M_CFG_ENABLE, hisi_rde->qm.io_base + QM_AXI_M_CFG_ENABLE);

	/* disable BME/PM/SRIOV FLR*/
	writel(PEH_AXUSER_CFG, hisi_rde->qm.io_base + QM_PEH_AXUSER_CFG);
	writel(PEH_AXUSER_CFG_ENABLE, hisi_rde->qm.io_base +
	       QM_PEH_AXUSER_CFG_ENABLE);

	writel(CACHE_CTL, hisi_rde->qm.io_base + QM_CACHE_CTL);

	hisi_rde_engine_init(hisi_rde);
}

static void hisi_rde_debug_regs_clear(struct hisi_qm *qm)
{
	/* clear rde debug regs */
	readl(qm->io_base + HRDE_ECC_ERR);
	readl(qm->io_base + HRDE_ECC_ERR_CNT);
	readl(qm->io_base + HRDE_OP_DONE_CNT);
	readl(qm->io_base + HRDE_OP_ERR_CNT);
	readl(qm->io_base + HRDE_OP_ABORT_CNT);
	writel(WRITE_CLEAR_VAL, qm->io_base + HRDE_FIFO_STAT_0);
	writel(WRITE_CLEAR_VAL, qm->io_base + HRDE_DFX_STAT_7);
	writel(WRITE_CLEAR_VAL, qm->io_base + HRDE_DFX_STAT_8);

	/* clear current_qm */
	writel(0x0, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(0x0, qm->io_base + QM_DFX_DB_CNT_VF);

	hisi_qm_debug_regs_clear(qm);
}

static void hisi_rde_hw_error_set_state(struct hisi_rde *hisi_rde, bool state)
{
	u32 ras_msk = (HRDE_RAS_CE_MSK | HRDE_RAS_NFE_MSK);
	u32 val;

	val = readl(hisi_rde->qm.io_base + HRDE_CFG);
	if (state) {
		writel(HRDE_INT_SOURCE_CLEAR,
		       hisi_rde->qm.io_base + HRDE_INT_SOURCE);
		writel(HRDE_RAS_ENABLE,
		       hisi_rde->qm.io_base + HRDE_RAS_INT_MSK);
		/* bd prefetch should bd masked to prevent misreport */
		writel((HRDE_INT_ENABLE | HRDE_BD_PREFETCH),
		       hisi_rde->qm.io_base + HRDE_INT_MSK);
		/* make master ooo close, when m-bits error happens*/
		val = val | HRDE_AXI_SHUTDOWN_EN;
	} else {
		writel(ras_msk, hisi_rde->qm.io_base + HRDE_RAS_INT_MSK);
		writel(HRDE_INT_DISABLE, hisi_rde->qm.io_base + HRDE_INT_MSK);
		/* make master ooo open, when m-bits error happens*/
		val = val & HRDE_AXI_SHUTDOWN_DIS;
	}

	writel(val, hisi_rde->qm.io_base + HRDE_CFG);
}

static inline struct hisi_qm *file_to_qm(struct ctrl_debug_file *file)
{
	struct hisi_rde *hisi_rde = file->ctrl->hisi_rde;

	return &hisi_rde->qm;
}

static u32 current_qm_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_DFX_MB_CNT_VF);
}

static int current_qm_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val > 0) {
		pr_err("Function id should be smaller than 0.\n");
		return -EINVAL;
	}

	writel(val, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(val, qm->io_base + QM_DFX_DB_CNT_VF);

	tmp = val |
	      (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);

	tmp = val |
	      (readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return 0;
}

static int current_bd_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + HRDE_PROBE_DATA);
}

static int current_bd_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp = 0;

	if (val >= (HRDE_SQE_SIZE / sizeof(u32))) {
		pr_err("Width index should be smaller than 16.\n");
		return -EINVAL;
	}

	tmp = HRDE_PROBE_DATA_EN | HRDE_PROBE_EN | (val << HRDE_STRB_CS_SHIFT);
	writel(tmp, qm->io_base + HRDE_PROBE_ADDR);

	return 0;
}

static ssize_t ctrl_debug_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[HRDE_DBGFS_VAL_MAX_LEN];
	u32 val;
	int ret;

	spin_lock_irq(&file->lock);
	switch (file->index) {
	case HRDE_CURRENT_FUNCTION:
		val = current_qm_read(file);
		ret = snprintf(tbuf, HRDE_DBGFS_VAL_MAX_LEN, "%u\n", val);
		break;
	case HRDE_CURRENT_BD:
		val = current_bd_read(file);
		ret = snprintf(tbuf, HRDE_DBGFS_VAL_MAX_LEN, "%x\n", val);
		break;
	default:
		spin_unlock_irq(&file->lock);
		return -EINVAL;
	}
	spin_unlock_irq(&file->lock);

	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static ssize_t ctrl_debug_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[20];
	unsigned long val;
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= HRDE_DBGFS_VAL_MAX_LEN)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, HRDE_DBGFS_VAL_MAX_LEN - 1,
			pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	spin_lock_irq(&file->lock);
	switch (file->index) {
	case HRDE_CURRENT_FUNCTION:
		ret = current_qm_write(file, val);
		if (ret)
			goto err_input;
		break;
	case HRDE_CURRENT_BD:
		ret = current_bd_write(file, val);
		if (ret)
			goto err_input;
		break;
	default:
		ret = -EINVAL;
		goto err_input;
	}
	spin_unlock_irq(&file->lock);

	return count;

 err_input:
	spin_unlock_irq(&file->lock);
	return ret;
}

static const struct file_operations ctrl_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = ctrl_debug_read,
	.write = ctrl_debug_write,
};

static int hisi_rde_chn_debug_init(struct hisi_rde_ctrl *ctrl)
{
	struct hisi_rde *hisi_rde = ctrl->hisi_rde;
	struct hisi_qm *qm = &hisi_rde->qm;
	struct device *dev = &qm->pdev->dev;
	struct debugfs_regset32 *regset, *regset_ooo;
	struct dentry *tmp_d, *tmp;
	char buf[HRDE_DBGFS_VAL_MAX_LEN];
	int ret;

	ret = snprintf(buf, HRDE_DBGFS_VAL_MAX_LEN, "rde_dfx");
	if (ret < 0)
		return -ENOENT;

	tmp_d = debugfs_create_dir(buf, ctrl->debug_root);
	if (!tmp_d)
		return -ENOENT;

	regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
	if (!regset)
		return -ENOENT;
	regset->regs = hrde_dfx_regs;
	regset->nregs = ARRAY_SIZE(hrde_dfx_regs);
	regset->base = qm->io_base;
	tmp = debugfs_create_regset32("chn_regs", 0444, tmp_d, regset);
	if (!tmp)
		return -ENOENT;

	regset_ooo = devm_kzalloc(dev, sizeof(*regset_ooo), GFP_KERNEL);
	if (!regset_ooo)
		return -ENOENT;
	regset_ooo->regs = hrde_ooo_dfx_regs;
	regset_ooo->nregs = ARRAY_SIZE(hrde_ooo_dfx_regs);
	regset_ooo->base = qm->io_base;
	tmp = debugfs_create_regset32("ooo_regs", 0444, tmp_d, regset_ooo);
	if (!tmp)
		return -ENOENT;

	return 0;
}

static int hisi_rde_ctrl_debug_init(struct hisi_rde_ctrl *ctrl)
{
	struct dentry *tmp;
	int i;

	for (i = HRDE_CURRENT_FUNCTION; i < HRDE_DEBUG_FILE_NUM; i++) {
		spin_lock_init(&ctrl->files[i].lock);
		ctrl->files[i].ctrl = ctrl;
		ctrl->files[i].index = i;

		tmp = debugfs_create_file(ctrl_debug_file_name[i], 0600,
					  ctrl->debug_root, ctrl->files + i,
					  &ctrl_debug_fops);
		if (!tmp)
			return -ENOENT;
	}

	return hisi_rde_chn_debug_init(ctrl);
}

static int hisi_rde_debugfs_init(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct device *dev = &qm->pdev->dev;
	struct dentry *dev_d;
	int ret;

	dev_d = debugfs_create_dir(dev_name(dev), hrde_debugfs_root);
	if (!dev_d)
		return -ENOENT;

	qm->debug.debug_root = dev_d;
	ret = hisi_qm_debug_init(qm);
	if (ret)
		goto failed_to_create;

	if (qm->pdev->device == HRDE_PCI_DEVICE_ID) {
		hisi_rde->ctrl->debug_root = dev_d;
		ret = hisi_rde_ctrl_debug_init(hisi_rde->ctrl);
		if (ret)
			goto failed_to_create;
	}

	return 0;

 failed_to_create:
	debugfs_remove_recursive(qm->debug.debug_root);
	return ret;
}

static void hisi_rde_debugfs_exit(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;

	debugfs_remove_recursive(qm->debug.debug_root);
	if (qm->fun_type == QM_HW_PF) {
		hisi_rde_debug_regs_clear(qm);
		qm->debug.curr_qm_qp_num = 0;
	}
}

static void hisi_rde_set_hw_error(struct hisi_rde *hisi_rde, bool state)
{
	if (state)
		hisi_qm_hw_error_init(&hisi_rde->qm, QM_BASE_CE,
				      QM_BASE_NFE | QM_ACC_DO_TASK_TIMEOUT,
				      0, 0);
	else
		hisi_qm_hw_error_uninit(&hisi_rde->qm);

	hisi_rde_hw_error_set_state(hisi_rde, state);
}

static void hisi_rde_open_master_ooo(struct hisi_qm *qm)
{
	u32 val;

	val = readl(qm->io_base + HRDE_CFG);
	writel(val & HRDE_AXI_SHUTDOWN_DIS, qm->io_base + HRDE_CFG);
	writel(val | HRDE_AXI_SHUTDOWN_EN, qm->io_base + HRDE_CFG);
}

static u32 hisi_rde_get_hw_err_status(struct hisi_qm *qm)
{
	return readl(qm->io_base + HRDE_INT_STATUS);
}

static void hisi_rde_clear_hw_err_status(struct hisi_qm *qm, u32 err_sts)
{
	writel(err_sts, qm->io_base + HRDE_INT_SOURCE);
}

static void hisi_rde_hw_error_log(struct hisi_qm *qm, u32 err_sts)
{
	const struct hisi_rde_hw_error *err = rde_hw_error;
	struct device *dev = &qm->pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts)
			dev_err_ratelimited(dev,
				"[%s] [Error status=0x%x] found.\n",
				err->msg, err->int_msk);
		err++;
	}

	if (HRDE_ECC_2BIT_ERR & err_sts) {
		err_val = (readl(qm->io_base + HRDE_ERR_CNT) &
			  HRDE_ECC_2BIT_CNT_MSK);
		dev_err_ratelimited(dev,
				    "Rde ecc 2bit sram num=0x%x.\n", err_val);
	}

	if (HRDE_STATE_INT_ERR & err_sts) {
		err_val = readl(qm->io_base + HRDE_AM_CURR_PORT_STS);
		dev_err_ratelimited(dev,
				    "Rde ooo cur port sts=0x%x.\n", err_val);
		err_val = readl(qm->io_base + HRDE_MASTER_TRANS_RET);
		dev_err_ratelimited(dev,
				    "Rde ooo outstanding sts=0x%x.\n", err_val);
	}
}

static int hisi_rde_pf_probe_init(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct hisi_rde_ctrl *ctrl;

	ctrl = devm_kzalloc(&qm->pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	hisi_rde->ctrl = ctrl;
	ctrl->hisi_rde = hisi_rde;

	switch (qm->ver) {
	case QM_HW_V1:
		qm->ctrl_q_num = HRDE_QUEUE_NUM_V1;
		break;

	case QM_HW_V2:
		qm->ctrl_q_num = HRDE_QUEUE_NUM_V2;
		break;

	default:
		return -EINVAL;
	}

	qm->err_ini.qm_wr_port = HRDE_WR_MSI_PORT;
	qm->err_ini.ecc_2bits_mask = HRDE_ECC_2BIT_ERR;
	qm->err_ini.open_axi_master_ooo = hisi_rde_open_master_ooo;
	qm->err_ini.get_dev_hw_err_status = hisi_rde_get_hw_err_status;
	qm->err_ini.clear_dev_hw_err_status = hisi_rde_clear_hw_err_status;
	qm->err_ini.log_dev_hw_err = hisi_rde_hw_error_log;
	hisi_rde_set_user_domain_and_cache(hisi_rde);
	hisi_rde_set_hw_error(hisi_rde, true);
	qm->err_ini.open_axi_master_ooo(qm);
	hisi_rde_debug_regs_clear(qm);

	return 0;
}

static int hisi_rde_qm_pre_init(struct hisi_qm *qm, struct pci_dev *pdev)
{
	enum qm_hw_ver rev_id;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id == QM_HW_UNKNOWN)
		return -EINVAL;

	qm->pdev = pdev;
	qm->ver = rev_id;
	qm->sqe_size = HRDE_SQE_SIZE;
	qm->dev_name = hisi_rde_name;
	qm->fun_type = QM_HW_PF;
	qm->algs = "ec\n";

	switch (uacce_mode) {
	case UACCE_MODE_NOUACCE:
		qm->use_uacce = false;
		break;
	case UACCE_MODE_NOIOMMU:
		qm->use_uacce = true;
		break;
	default:
		return -EINVAL;
	}

	qm->qp_base = HRDE_PF_DEF_Q_BASE;
	qm->qp_num = pf_q_num;
	qm->debug.curr_qm_qp_num = pf_q_num;
	qm->abnormal_fix = hisi_rde_abnormal_fix;

	return 0;
}

static u32 hisi_rde_smmu_state(struct device *dev)
{
	struct iommu_domain *domain;

	domain = iommu_get_domain_for_dev(dev);
	if (domain) {
		if (domain->type == IOMMU_DOMAIN_DMA)
			return true;
		else
			return false;
	} else {
		return false;
	}
}

static int hisi_rde_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_rde *hisi_rde;
	struct hisi_qm *qm;
	int ret;

	hisi_rde = devm_kzalloc(&pdev->dev, sizeof(*hisi_rde), GFP_KERNEL);
	if (!hisi_rde)
		return -ENOMEM;

	pci_set_drvdata(pdev, hisi_rde);
	INIT_WORK(&hisi_rde->reset_work, hisi_rde_ras_proc);
	hisi_rde->smmu_state = hisi_rde_smmu_state(&pdev->dev);

	qm = &hisi_rde->qm;
	ret = hisi_rde_qm_pre_init(qm, pdev);
	if (ret) {
		pci_err(pdev, "Pre init qm failed!\n");
		return ret;
	}

	ret = hisi_qm_init(qm);
	if (ret) {
		pci_err(pdev, "Init qm failed!\n");
		return ret;
	}

	ret = hisi_rde_pf_probe_init(hisi_rde);
	if (ret) {
		pci_err(pdev, "Init pf failed!\n");
		goto err_qm_uninit;
	}

	ret = hisi_qm_start(qm);
	if (ret) {
		pci_err(pdev, "Start qm failed!\n");
		goto err_qm_uninit;
	}

	ret = hisi_rde_debugfs_init(hisi_rde);
	if (ret)
		pci_warn(pdev, "Init debugfs failed!\n");

	hisi_rde_add_to_list(hisi_rde);
	hisi_rde->rde_list_lock = &hisi_rde_list_lock;

	return 0;

 err_qm_uninit:
	hisi_qm_uninit(qm);

	return ret;
}

static void hisi_rde_remove(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_rde->qm;

	qm->abnormal_fix = NULL;
	hisi_rde_hw_error_set_state(hisi_rde, false);
	cancel_work_sync(&hisi_rde->reset_work);
	hisi_rde_remove_from_list(hisi_rde);
	hisi_rde_debugfs_exit(hisi_rde);
	hisi_qm_stop(qm, QM_NORMAL);
	hisi_qm_uninit(qm);
}

static void hisi_rde_shutdown(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);

	hisi_qm_stop(&hisi_rde->qm, QM_NORMAL);
}

static int hisi_rde_reset_prepare_rdy(struct hisi_rde *hisi_rde)
{
	int delay = 0;

	while (test_and_set_bit(HISI_RDE_RESET, &hisi_rde->status)) {
		msleep(++delay);
		if (delay > HRDE_RST_TMOUT_MS)
			return -EBUSY;
	}

	return 0;
}

static int hisi_rde_controller_reset_prepare(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = hisi_rde_reset_prepare_rdy(hisi_rde);
	if (ret) {
		dev_err(&pdev->dev, "Controller reset not ready!\n");
		return ret;
	}

	ret = hisi_qm_stop(qm, QM_SOFT_RESET);
	if (ret) {
		dev_err(&pdev->dev, "Stop QM failed!\n");
		return ret;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce) {
		ret = uacce_hw_err_isolate(&qm->uacce);
		if (ret) {
			dev_err(&pdev->dev, "Isolate hw err failed!\n");
			return ret;
		}
	}
#endif

	return 0;
}

static int hisi_rde_soft_reset(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct device *dev = &qm->pdev->dev;
	unsigned long long value;
	int ret;
	u32 val;

	/* Check PF stream stop */
	ret = hisi_qm_reg_test(qm);
	if (ret)
		return ret;

	/* Disable PEH MSI */
	ret = hisi_qm_set_msi(qm, HRDE_DISABLE);
	if (ret) {
		dev_err(dev, "Disable peh msi bit failed.\n");
		return ret;
	}

	/* Set qm ecc if dev ecc happened to hold on ooo */
	hisi_qm_set_ecc(qm);

	/* OOO register set and check */
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN,
	       hisi_rde->qm.io_base + HRDE_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hisi_rde->qm.io_base +
					 HRDE_MASTER_TRANS_RET, val,
					 (val == MASTER_TRANS_RETURN_RW),
					 HRDE_RD_INTVRL_US, HRDE_RD_TMOUT_US);
	if (ret) {
		dev_emerg(dev, "Bus lock! Please reset system.\n");
		return ret;
	}

	/* Disable PF MSE bit */
	ret = hisi_qm_set_pf_mse(qm, HRDE_DISABLE);
	if (ret) {
		dev_err(dev, "Disable pf mse bit failed.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(dev)) {
		acpi_status s;

		s = acpi_evaluate_integer(ACPI_HANDLE(dev), "RRST",
						      NULL, &value);
		if (ACPI_FAILURE(s)) {
			dev_err(dev, "No controller reset method.\n");
			return -EIO;
		}

		if (value) {
			dev_err(dev, "Reset step %llu failed.\n", value);
			return -EIO;
		}
	} else {
		dev_err(dev, "No reset method!\n");
		return -EINVAL;
	}

	return 0;
}

static int hisi_rde_controller_reset_done(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct pci_dev *pdev = qm->pdev;
	int ret;

	/* Enable PEH MSI */
	ret = hisi_qm_set_msi(qm, HRDE_ENABLE);
	if (ret) {
		dev_err(&pdev->dev, "Enable peh msi bit failed!\n");
		return ret;
	}

	/* Enable PF MSE bit */
	ret = hisi_qm_set_pf_mse(qm, HRDE_ENABLE);
	if (ret) {
		dev_err(&pdev->dev, "Enable pf mse bit failed!\n");
		return ret;
	}

	hisi_rde_set_user_domain_and_cache(hisi_rde);
	hisi_qm_restart_prepare(qm);

	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(&pdev->dev, "Start QM failed!\n");
		return -EPERM;
	}

	hisi_qm_restart_done(qm);
	hisi_rde_set_hw_error(hisi_rde, true);

	return 0;
}

static int hisi_rde_controller_reset(struct hisi_rde *hisi_rde)
{
	struct device *dev = &hisi_rde->qm.pdev->dev;
	int ret;

	dev_info_ratelimited(dev, "Controller resetting...\n");

	ret = hisi_rde_controller_reset_prepare(hisi_rde);
	if (ret)
		return ret;

	ret = hisi_rde_soft_reset(hisi_rde);
	if (ret) {
		dev_err(dev, "Controller reset failed (%d).\n", ret);
		return ret;
	}

	ret = hisi_rde_controller_reset_done(hisi_rde);
	if (ret)
		return ret;

	clear_bit(HISI_RDE_RESET, &hisi_rde->status);
	dev_info_ratelimited(dev, "Controller reset complete.\n");

	return 0;
}

static void hisi_rde_ras_proc(struct work_struct *work)
{
	struct pci_dev *pdev;
	struct hisi_rde *hisi_rde;
	pci_ers_result_t ret;

	hisi_rde = container_of(work, struct hisi_rde, reset_work);
	pdev = hisi_rde->qm.pdev;
	if (!pdev)
		return;

	ret = hisi_qm_process_dev_error(pdev);
	if (ret == PCI_ERS_RESULT_NEED_RESET)
		if (hisi_rde_controller_reset(hisi_rde))
			dev_err(&pdev->dev, "Hisi_rde reset fail.\n");

}

int hisi_rde_abnormal_fix(struct hisi_qm *qm)
{
	struct pci_dev *pdev;
	struct hisi_rde *hisi_rde;

	if (!qm)
		return -EINVAL;

	pdev = qm->pdev;
	if (!pdev)
		return -EINVAL;

	hisi_rde = pci_get_drvdata(pdev);
	if (!hisi_rde) {
		dev_err(&pdev->dev, "Hisi_rde is NULL.\n");
		return -EINVAL;
	}

	return schedule_work(&hisi_rde->reset_work);
}

static int hisi_rde_get_hw_error_status(struct hisi_rde *hisi_rde)
{
	u32 err_sts;

	err_sts = readl(hisi_rde->qm.io_base + HRDE_INT_STATUS) &
		  HRDE_ECC_2BIT_ERR;
	if (err_sts)
		return err_sts;

	return 0;
}

static int hisi_rde_check_hw_error(struct hisi_rde *hisi_rde)
{
	int ret;

	ret = hisi_qm_get_hw_error_status(&hisi_rde->qm);
	if (ret)
		return ret;

	return hisi_rde_get_hw_error_status(hisi_rde);
}

static void hisi_rde_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_rde->qm;
	u32 delay = 0;
	int ret;

	hisi_rde_set_hw_error(hisi_rde, false);

	while (hisi_rde_check_hw_error(hisi_rde)) {
		msleep(++delay);
		if (delay > HRDE_RST_TMOUT_MS)
			return;
	}

	ret = hisi_rde_reset_prepare_rdy(hisi_rde);
	if (ret) {
		dev_err(&pdev->dev, "FLR not ready!\n");
		return;
	}

	ret = hisi_qm_stop(qm, QM_FLR);
	if (ret) {
		dev_err(&pdev->dev, "Stop QM failed!\n");
		return;
	}

	dev_info(&pdev->dev, "FLR resetting...\n");
}

static void hisi_rde_flr_reset_complete(struct pci_dev *pdev,
	struct hisi_rde *hisi_rde)
{
	u32 id;

	pci_read_config_dword(pdev, PCI_COMMAND, &id);
	if (id == HRDE_PCI_COMMAND_INVALID)
		dev_err(&pdev->dev, "Device can not be used!\n");

	clear_bit(HISI_RDE_RESET, &hisi_rde->status);
}

static void hisi_rde_reset_done(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_rde->qm;
	int ret;

	hisi_rde_set_hw_error(hisi_rde, true);

	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(&pdev->dev, "Start QM failed!\n");
		goto flr_done;
	}

	hisi_rde_set_user_domain_and_cache(hisi_rde);

flr_done:
	hisi_rde_flr_reset_complete(pdev, hisi_rde);
	dev_info(&pdev->dev, "FLR reset complete.\n");
}

static const struct pci_error_handlers hisi_rde_err_handler = {
	.reset_prepare = hisi_rde_reset_prepare,
	.reset_done = hisi_rde_reset_done,
};

static struct pci_driver hisi_rde_pci_driver = {
	.name = "hisi_rde",
	.id_table = hisi_rde_dev_ids,
	.probe = hisi_rde_probe,
	.remove = hisi_rde_remove,
	.err_handler = &hisi_rde_err_handler,
	.shutdown = hisi_rde_shutdown,
};

static void hisi_rde_register_debugfs(void)
{
	if (!debugfs_initialized())
		return;

	hrde_debugfs_root = debugfs_create_dir("hisi_rde", NULL);
	if (IS_ERR_OR_NULL(hrde_debugfs_root))
		hrde_debugfs_root = NULL;
}

static void hisi_rde_unregister_debugfs(void)
{
	debugfs_remove_recursive(hrde_debugfs_root);
}

static int __init hisi_rde_init(void)
{
	int ret;

	hisi_rde_register_debugfs();

	ret = pci_register_driver(&hisi_rde_pci_driver);
	if (ret < 0) {
		hisi_rde_unregister_debugfs();
		pr_err("Register pci driver failed.\n");
	}

	return ret;
}

static void __exit hisi_rde_exit(void)
{
	pci_unregister_driver(&hisi_rde_pci_driver);
	hisi_rde_unregister_debugfs();
}

module_init(hisi_rde_init);
module_exit(hisi_rde_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yu'an Wang<wangyuan46@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon RDE accelerator");
