// SPDX-License-Identifier: GPL-2.0+
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

#define HRDE_VF_NUM				63
#define HRDE_QUEUE_NUM_V1		4096
#define HRDE_QUEUE_NUM_V2		1024
#define HRDE_PCI_DEVICE_ID		0xa25a

#define HRDE_RAS_INT_MSK		0x310290
#define HRDE_RAS_CE_MSK		BIT(2)
#define HRDE_RAS_NFE_MSK		BIT(1)
#define HRDE_RAS_ENABLE			BIT(0)
#define HRDE_INT_MSK				0x310314
#define HRDE_INT_ENABLE			0x0
#define HRDE_INT_DISABLE		0x3ffff

#define HRDE_INT_SOURCE			0x31030c
#define HRDE_INT_STATUS			0x310318
#define HRDE_DFX_CTRL_0			0x310240
#define HRDE_ECC_ERR			0x310234
#define HRDE_ECC_ERR_CNT		0x310238
#define HRDE_OP_DONE_CNT		0x310250
#define HRDE_OP_ERR_CNT		0x310254
#define HRDE_OP_ABORT_CNT		0x310258
#define HRDE_FIFO_STAT_0			0x310200
#define HRDE_DFX_STAT_7			0x310334
#define HRDE_DFX_STAT_8			0x310338
#define DFX_CTRL0					0x2
#define WRITE_CLEAR_VAL			GENMASK(31, 0)

#define HRDE_AWCACHE			0x310154
#define HRDE_ARCACHE			0x31015c
#define AWCACHE					0xff0
#define ARCACHE					0xfff0

#define HRDE_CFG					0x310000
#define CHN_CFG					0x1010101

#define HRDE_AWUSER_BD_1		0x310104
#define HRDE_ARUSER_BD_1		0x310114
#define HRDE_ARUSER_SGL_1		0x310124
#define HRDE_AWUSER_DAT_1		0x310134
#define HRDE_ARUSER_DAT_1		0x310144
#define HRDE_USER_SMMU			0x40001070

#define HRDE_ERR_CNT			0x310238
#define HRDE_ECC_1BIT_ERR		BIT(0)
#define HRDE_ECC_2BIT_ERR		BIT(1)
#define HRDE_ECC_1BIT_SHIFT		16

#define HRDE_FSM_MAX_CNT		0x310280
#define HRDE_QM_IDEL_STATUS				0x1040e4
#define HRDE_MASTER_GLOBAL_CTRL		0x300000
#define MASTER_GLOBAL_CTRL_SHUTDOWN	0x1
#define HRDE_MASTER_TRANS_RETURN		0x300150
#define MASTER_TRANS_RETURN_RW		0x3
#define CACHE_CTL			0x1833
#define HRDE_DBGFS_VAL_MAX_LEN		20
#define HRDE_COM_OFFSET		0x310000

#define HRDE_SQE_SIZE			64
#define HRDE_SQ_SIZE				(HRDE_SQE_SIZE * QM_Q_DEPTH)
#define HRDE_PF_DEF_Q_NUM		64
#define HRDE_PF_DEF_Q_BASE		0
#define HRDE_RD_INTVRL_US		10
#define HRDE_RD_TMOUT_US		1000

static const char hisi_rde_name[] = "hisi_rde";
static struct dentry *hrde_debugfs_root;
LIST_HEAD(hisi_rde_list);
DEFINE_MUTEX(hisi_rde_list_lock);

struct hisi_rde *find_rde_device(int node)
{
	struct hisi_rde *ret = NULL;
#ifdef CONFIG_NUMA
	struct hisi_rde *hisi_rde;
	int min_distance = 100;
	struct device *dev;

	mutex_lock(&hisi_rde_list_lock);

	list_for_each_entry(hisi_rde, &hisi_rde_list, list) {
		dev = &hisi_rde->qm.pdev->dev;
		if (node_distance(dev->numa_node, node) < min_distance) {
			ret = hisi_rde;
			min_distance = node_distance(dev->numa_node, node);
		}
	}
#else
	mutex_lock(&hisi_rde_list_lock);

	ret = list_first_entry(&hisi_rde_list, struct hisi_rde, list);
#endif
	mutex_unlock(&hisi_rde_list_lock);

	return ret;
}

struct hisi_rde_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hisi_rde_hw_error rde_hw_error[] = {
	{.int_msk = BIT(0), .msg = "rde_ecc_1bitt_err"},
	{.int_msk = BIT(1), .msg = "rde_ecc_2bit_err"},
	{.int_msk = BIT(2), .msg = "rde_stat_mgmt_state_timeout_err"},
	{.int_msk = BIT(3), .msg = "rde_data_wr_state_timeout_err"},
	{.int_msk = BIT(4), .msg = "rde_alg_state_timeout_err"},
	{.int_msk = BIT(5), .msg = "rde_data_ar_state_timeout_err"},
	{.int_msk = BIT(6), .msg = "rde_bd_mgmt_state_timeout_err"},
	{.int_msk = BIT(7), .msg = "rde_list_parse_ar_state_timeout_err"},
	{.int_msk = BIT(8), .msg = "rde_bd_prefetch_state_timeout_err"},
	{.int_msk = BIT(9), .msg = "rde_dst_buf_parse_state_timeout_err"},
	{.int_msk = BIT(10), .msg = "rde_src_buf_parse_state_timeout_err"},
	{.int_msk = BIT(11), .msg = "rde_chn_timeout_err"},
	{.int_msk = BIT(12), .msg = "rde_bd_bresp_err"},
	{.int_msk = BIT(13), .msg = "rde_data_bresp_err"},
	{.int_msk = BIT(14), .msg = "rde_data_rresp_err"},
	{.int_msk = BIT(15), .msg = "rde_sgl_rresp_err"},
	{.int_msk = BIT(16), .msg = "rde_list_rresp_err"},
	{.int_msk = BIT(17), .msg = "rde_bd_rresp_err"},
	{ /* sentinel */ }
};

enum ctrl_debug_file_index {
	HRDE_CURRENT_FUNCTION,
	HRDE_DEBUG_FILE_NUM,
	/*RDE not support CNT_CLR_CE config, default enable */
};

static const char *const ctrl_debug_file_name[] = {
	[HRDE_CURRENT_FUNCTION] = "current_function_id",
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
	u32 ctrl_q_num;
	u32 num_vfs;
	struct hisi_rde *hisi_rde;
	struct dentry *debug_root;
	struct ctrl_debug_file files[HRDE_DEBUG_FILE_NUM];
};

static struct debugfs_reg32 hrde_dfx_regs[] = {
	{"HRDE_FIFO_STAT_0	", 0x200ull},
	{"HRDE_FIFO_STAT_1	", 0x204ull},
	{"HRDE_OP_TAG_0		", 0x214ull},
	{"HRDE_OP_TAG_1		", 0x218ull},
	{"HRDE_OP_TAG_2		", 0x21cull},
	{"HRDE_ECC_ERR		", 0x234ull},
	{"HRDE_ECC_ERR_CNT	", 0x238ull},
	{"HRDE_OP_DONE_CNT	", 0x250ull},
	{"HRDE_OP_ERR_CNT		", 0x254ull},
	{"HRDE_OP_ABORT_CNT	", 0x258ull},
	{"HRDE_TMP_ADDR_HIGH	", 0x270ull},
	{"HRDE_TMP_ADDR_LOW	", 0x274ull},
	{"HRDE_TMP_LENGTH		", 0x278ull},
	{"HRDE_INT_STATUS		", 0x318ull},
	{"HRDE_DFX_STAT_0		", 0x220ull},
	{"HRDE_DFX_STAT_1		", 0x224ull},
	{"HRDE_DFX_STAT_2		", 0x320ull},
	{"HRDE_DFX_STAT_3		", 0x324ull},
	{"HRDE_DFX_STAT_4		", 0x328ull},
	{"HRDE_DFX_STAT_5		", 0x32cull},
	{"HRDE_DFX_STAT_6		", 0x330ull},
	{"HRDE_DFX_STAT_7		", 0x334ull},
	{"HRDE_DFX_STAT_8		", 0x338ull},
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
		    ("No device found currently, suppose queue number is %d\n",
		     q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case QM_HW_VER1_ID:
			q_num = HRDE_QUEUE_NUM_V1;
			break;
		case QM_HW_VER2_ID:
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

static u32 pf_q_num = HRDE_PF_DEF_Q_NUM;
module_param_cb(pf_q_num, &pf_q_num_ops, &pf_q_num, 0444);
MODULE_PARM_DESC(pf_q_num, "Number of queues in PF(v1 0-4096, v2 0-1024)");

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param(uacce_mode, int, 0444);

static const struct pci_device_id hisi_rde_dev_ids[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HRDE_PCI_DEVICE_ID)},
	{0,}
};

MODULE_DEVICE_TABLE(pci, hisi_rde_dev_ids);

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
	readl(hisi_rde->qm.io_base + HRDE_ECC_ERR);
	readl(hisi_rde->qm.io_base + HRDE_ECC_ERR_CNT);
	readl(hisi_rde->qm.io_base + HRDE_OP_DONE_CNT);
	readl(hisi_rde->qm.io_base + HRDE_OP_ERR_CNT);
	readl(hisi_rde->qm.io_base + HRDE_OP_ABORT_CNT);
	writel(WRITE_CLEAR_VAL, hisi_rde->qm.io_base + HRDE_FIFO_STAT_0);
	writel(WRITE_CLEAR_VAL, hisi_rde->qm.io_base + HRDE_INT_SOURCE);
	writel(WRITE_CLEAR_VAL, hisi_rde->qm.io_base + HRDE_DFX_STAT_7);
	writel(WRITE_CLEAR_VAL, hisi_rde->qm.io_base + HRDE_DFX_STAT_8);

	/*usr domain */
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_AWUSER_BD_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_ARUSER_BD_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_AWUSER_DAT_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_ARUSER_DAT_1);
	writel(HRDE_USER_SMMU, hisi_rde->qm.io_base + HRDE_ARUSER_SGL_1);
	/*rde cache */
	writel(AWCACHE, hisi_rde->qm.io_base + HRDE_AWCACHE);
	writel(ARCACHE, hisi_rde->qm.io_base + HRDE_ARCACHE);

	/*rde chn enable + outstangding config */
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
	writel(PEH_AXUSER_CFG_ENABLE, hisi_rde->qm.io_base +
	       QM_PEH_AXUSER_CFG_ENABLE);

	writel(CACHE_CTL, hisi_rde->qm.io_base + QM_CACHE_CTL);

	hisi_rde_engine_init(hisi_rde);
}

static void hisi_rde_hw_error_set_state(struct hisi_rde *hisi_rde, bool state)
{
	u32 ras_msk = (HRDE_RAS_CE_MSK | HRDE_RAS_NFE_MSK);

	/*
	 * if enable RDE hw error interrupts, bd prefetch should bd
	 * masked,otherwise ras int will misreport
	 */
	if (state) {
		writel(HRDE_RAS_ENABLE,
		       hisi_rde->qm.io_base + HRDE_RAS_INT_MSK);
		writel((HRDE_INT_ENABLE | BIT(8)),
		       hisi_rde->qm.io_base + HRDE_INT_MSK);
	} else {
		writel(ras_msk, hisi_rde->qm.io_base + HRDE_RAS_INT_MSK);
		writel(HRDE_INT_DISABLE, hisi_rde->qm.io_base + HRDE_INT_MSK);
	}
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
	struct hisi_rde_ctrl *ctrl = file->ctrl;

	if (val > ctrl->num_vfs) {
		pr_err("function id should be smaller than %d\n",
		       ctrl->num_vfs);
		return -EINVAL;
	}

	writel(val, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(val, qm->io_base + QM_DFX_DB_CNT_VF);

	return 0;
}

static ssize_t ctrl_debug_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[20];
	u32 val;
	int ret;

	spin_lock_irq(&file->lock);
	switch (file->index) {
	case HRDE_CURRENT_FUNCTION:
		val = current_qm_read(file);
		break;
	default:
		spin_unlock_irq(&file->lock);
		return -EINVAL;
	}
	spin_unlock_irq(&file->lock);
	ret = sprintf(tbuf, "%u\n", val);
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
	struct debugfs_regset32 *regset;
	struct dentry *tmp;

	regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
	if (!regset)
		return -ENOENT;

	regset->regs = hrde_dfx_regs;
	regset->nregs = ARRAY_SIZE(hrde_dfx_regs);
	regset->base = qm->io_base + HRDE_COM_OFFSET;

	tmp =
	    debugfs_create_regset32("rde_chn_dfx_regs", 0444, ctrl->debug_root,
				    regset);
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
}

static void hisi_rde_hw_error_init(struct hisi_rde *hisi_rde)
{
	hisi_qm_hw_error_init(&hisi_rde->qm, QM_BASE_CE,
			      QM_BASE_NFE | QM_ACC_DO_TASK_TIMEOUT |
			      QM_SQ_CQ_VF_INVALID | QM_CQ_VF_INVALID |
			      QM_SQ_VF_INVALID | QM_DB_RANDOM_INVALID, 0, 0);
	hisi_rde_hw_error_set_state(hisi_rde, true);
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
	ctrl->num_vfs = 0;

	switch (qm->ver) {
	case QM_HW_V1:
		ctrl->ctrl_q_num = HRDE_QUEUE_NUM_V1;
		break;

	case QM_HW_V2:
		ctrl->ctrl_q_num = HRDE_QUEUE_NUM_V2;
		break;

	default:
		return -EINVAL;
	}

	hisi_rde_set_user_domain_and_cache(hisi_rde);
	hisi_rde_hw_error_init(hisi_rde);

	return 0;
}

static int hisi_rde_qm_pre_init(struct hisi_qm *qm, struct pci_dev *pdev)
{
	enum qm_hw_ver rev_id;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id < 0)
		return -ENODEV;

	qm->pdev = pdev;
	qm->ver = rev_id;
	qm->sqe_size = HRDE_SQE_SIZE;
	qm->dev_name = hisi_rde_name;
	qm->fun_type = QM_HW_PF;
	qm->algs = "rde\nraid\n";

	switch (uacce_mode) {
	case UACCE_MODE_NOUACCE:
		qm->use_dma_api = true;
		qm->use_uacce = false;
		break;
	case UACCE_MODE_UACCE:
#ifdef CONFIG_IOMMU_SVA
		qm->use_dma_api = true;
		qm->use_sva = true;
#else
		qm->use_dma_api = false;
#endif
		qm->use_uacce = true;
		break;
	case UACCE_MODE_NOIOMMU:
		qm->use_dma_api = true;
		qm->use_uacce = true;
		break;
	default:
		return -EINVAL;
	}

	qm->qp_base = HRDE_PF_DEF_Q_BASE;
	qm->qp_num = pf_q_num;

	return 0;
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
	qm = &hisi_rde->qm;
	ret = hisi_rde_qm_pre_init(qm, pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to pre init qm!\n");
		return ret;
	}

	ret = hisi_qm_init(qm);
	if (ret) {
		dev_err(&pdev->dev, "Failed to init qm!\n");
		return ret;
	}

	ret = hisi_rde_pf_probe_init(hisi_rde);
	if (ret) {
		dev_err(&pdev->dev, "Failed to init pf!\n");
		goto err_qm_uninit;
	}

	ret = hisi_qm_start(qm);
	if (ret) {
		dev_err(&pdev->dev, "Failed to start qm!\n");
		goto err_qm_uninit;
	}

	ret = hisi_rde_debugfs_init(hisi_rde);
	if (ret)
		dev_warn(&pdev->dev, "Failed to init debugfs!\n");

	hisi_rde_add_to_list(hisi_rde);
	return 0;

 err_qm_uninit:
	hisi_qm_uninit(qm);

	return ret;
}

/* now we only support equal assignment */
static int hisi_rde_vf_q_assign(struct hisi_rde *hisi_rde, int num_vfs)
{
	struct hisi_rde_ctrl *ctrl = hisi_rde->ctrl;
	struct hisi_qm *qm = &hisi_rde->qm;
	u32 qp_num = qm->qp_num;
	u32 q_base = qp_num;
	u32 q_num, remain_q_num, i;
	int ret;

	if (!num_vfs)
		return -EINVAL;

	remain_q_num = ctrl->ctrl_q_num - qp_num;
	q_num = remain_q_num / num_vfs;

	for (i = 1; i <= num_vfs; i++) {
		if (i == num_vfs)
			q_num += remain_q_num % num_vfs;
		ret = hisi_qm_set_vft(qm, i, q_base, q_num);
		if (ret)
			return ret;
		q_base += q_num;
	}

	return 0;
}

static void hisi_rde_remove(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_rde->qm;

	hisi_rde_remove_from_list(hisi_rde);
	hisi_rde_debugfs_exit(hisi_rde);
	hisi_qm_stop(qm);
	hisi_rde_hw_error_set_state(hisi_rde, false);
	hisi_qm_uninit(qm);
}

static void hisi_rde_log_hw_error(struct hisi_rde *hisi_rde, u32 err_sts)
{
	const struct hisi_rde_hw_error *err = rde_hw_error;
	struct device *dev = &hisi_rde->qm.pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts) {
			dev_warn(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);
			if (HRDE_ECC_1BIT_ERR & err_sts) {
				err_val =
				    (readl(hisi_rde->qm.io_base + HRDE_ERR_CNT)
				     >> HRDE_ECC_1BIT_SHIFT);
				dev_warn(dev, "rde ecc 1bit sram num=0x%x\n",
					 err_val);
			}
			if (HRDE_ECC_2BIT_ERR & err_sts) {
				err_val =
				    (readl(hisi_rde->qm.io_base + HRDE_ERR_CNT)
				     & GENMASK(15, 0));
				dev_warn(dev, "rde ecc 2bit sram num=0x%x\n",
					 err_val);
			}
		}
		err++;
	}
}

static pci_ers_result_t hisi_rde_handle_hw_error(struct hisi_rde *hisi_rde)
{
	u32 err_sts;

	/*msk err interrupts */

	/* read err sts */
	err_sts = readl(hisi_rde->qm.io_base + HRDE_INT_STATUS);
	if (err_sts) {
		hisi_rde_log_hw_error(hisi_rde, err_sts);

		/* clear error interrupts */
		writel(err_sts, hisi_rde->qm.io_base + HRDE_INT_SOURCE);
		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t hisi_rde_process_hw_error(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	pci_ers_result_t qm_ret, rde_ret, ret;

	if (!hisi_rde) {
		dev_err(dev, "Can't recover rde-error at dev init\n");
		return PCI_ERS_RESULT_NONE;
	}

	/* log qm error */
	qm_ret = hisi_qm_hw_error_handle(&hisi_rde->qm);

	/* log rde error */
	rde_ret = hisi_rde_handle_hw_error(hisi_rde);
	ret = (qm_ret == PCI_ERS_RESULT_NEED_RESET ||
	       rde_ret == PCI_ERS_RESULT_NEED_RESET) ?
	    PCI_ERS_RESULT_NEED_RESET : PCI_ERS_RESULT_RECOVERED;

	return ret;
}

static pci_ers_result_t hisi_rde_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_NONE;

	dev_info(&pdev->dev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hisi_rde_process_hw_error(pdev);
}

static int hisi_rde_controller_reset_prepare(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = hisi_qm_stop(qm);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop QM!\n");
		return ret;
	}

	if (test_and_set_bit(QM_RESET, &qm->status.flags)) {
		dev_warn(&pdev->dev, "Failed to set reset flag!");
		return -EPERM;
	}

	return 0;
}

static int hisi_rde_soft_reset(struct hisi_rde *hisi_rde)
{
	struct hisi_qm *qm = &hisi_rde->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;
	u32 val;

	/* OOO register set and check */
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN,
	       hisi_rde->qm.io_base + HRDE_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hisi_rde->qm.io_base +
					 HRDE_MASTER_TRANS_RETURN, val,
					 (val == MASTER_TRANS_RETURN_RW),
					 HRDE_RD_INTVRL_US, HRDE_RD_TMOUT_US);
	if (ret) {
		dev_emerg(dev, "Bus lock! Please reset system.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(dev)) {
		acpi_status s;

		s = acpi_evaluate_object(ACPI_HANDLE(dev), "ZRST", NULL, NULL);
		if (ACPI_FAILURE(s)) {
			dev_err(dev, "Controller reset fails\n");
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
	struct hisi_qp *qp;
	int i, ret;

	hisi_qm_clear_queues(qm);

	hisi_rde_set_user_domain_and_cache(hisi_rde);
	hisi_rde_hw_error_init(hisi_rde);

	ret = hisi_qm_start(qm);
	if (ret) {
		dev_err(&pdev->dev, "Failed to start QM!\n");
		return -EPERM;
	}

	for (i = 0; i < qm->qp_num; i++) {
		qp = qm->qp_array[i];
		if (qp) {
			ret = hisi_qm_start_qp(qp, 0);
			if (ret < 0) {
				dev_err(&pdev->dev, "Start qp%d failed\n", i);
				return -EPERM;
			}
		}
	}

	if (hisi_rde->ctrl->num_vfs)
		hisi_rde_vf_q_assign(hisi_rde, hisi_rde->ctrl->num_vfs);

	return 0;
}

static int hisi_rde_controller_reset(struct hisi_rde *hisi_rde)
{
	struct device *dev = &hisi_rde->qm.pdev->dev;
	int ret;

	dev_info(dev, "Controller resetting...\n");

	ret = hisi_rde_controller_reset_prepare(hisi_rde);
	if (ret)
		return ret;

	ret = hisi_rde_soft_reset(hisi_rde);
	if (ret) {
		dev_err(dev, "Controller reset failed (%d)\n", ret);
		return ret;
	}

	ret = hisi_rde_controller_reset_done(hisi_rde);
	if (ret)
		return ret;

	dev_info(dev, "Controller reset complete\n");
	clear_bit(QM_RESET, &hisi_rde->qm.status.flags);

	return 0;
}

static pci_ers_result_t hisi_rde_slot_reset(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	int ret;

	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_RECOVERED;

	dev_info(&pdev->dev, "Requesting reset due to PCI error\n");

	pci_cleanup_aer_uncorrect_error_status(pdev);

	/* reset rde controller */
	ret = hisi_rde_controller_reset(hisi_rde);
	if (ret) {
		dev_warn(&pdev->dev, "hisi_rde controller reset failed (%d)\n",
			 ret);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static void hisi_rde_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_rde->qm;
	struct device *dev = &pdev->dev;
	int ret;

	ret = hisi_qm_stop(qm);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop QM!\n");
		return;
	}

	if (test_and_set_bit(QM_RESET, &qm->status.flags)) {
		dev_warn(dev, "Failed to set reset flag!");
		return;
	}

	dev_info(dev, "FLR resetting...\n");
}

static void hisi_rde_reset_done(struct pci_dev *pdev)
{
	struct hisi_rde *hisi_rde = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_rde->qm;
	struct device *dev = &pdev->dev;
	struct hisi_qp *qp;
	int i, ret;

	if (pdev->is_physfn) {
		hisi_qm_clear_queues(qm);

		hisi_rde_set_user_domain_and_cache(hisi_rde);
		hisi_rde_hw_error_init(hisi_rde);

		ret = hisi_qm_start(qm);
		if (ret) {
			dev_err(dev, "Failed to start QM!\n");
			return;
		}

		for (i = 0; i < qm->qp_num; i++) {
			qp = qm->qp_array[i];
			if (qp) {
				ret = hisi_qm_start_qp(qp, 0);
				if (ret < 0) {
					dev_err(dev, "Start qp%d failed\n", i);
					return;
				}
			}
		}

		if (hisi_rde->ctrl->num_vfs)
			hisi_rde_vf_q_assign(hisi_rde, hisi_rde->ctrl->num_vfs);

		dev_info(dev, "FLR reset complete\n");
	}
}

static const struct pci_error_handlers hisi_rde_err_handler = {
	.error_detected = hisi_rde_error_detected,
	.slot_reset = hisi_rde_slot_reset,
	.reset_prepare = hisi_rde_reset_prepare,
	.reset_done = hisi_rde_reset_done,
};

static struct pci_driver hisi_rde_pci_driver = {
	.name = "hisi_rde",
	.id_table = hisi_rde_dev_ids,
	.probe = hisi_rde_probe,
	.remove = hisi_rde_remove,
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
		pr_err("Failed to register pci driver.\n");
		goto err_pci;
	}
#ifndef CONFIG_IOMMU_SVA
	if (uacce_mode == UACCE_MODE_UACCE)
		return 0;
#endif

	return 0;

 err_pci:
	hisi_rde_unregister_debugfs();

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
MODULE_AUTHOR("Thales Hu<hucheng.hu@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon RDE accelerator");
