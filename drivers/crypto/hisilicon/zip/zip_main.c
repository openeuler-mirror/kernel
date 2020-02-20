// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018-2019 HiSilicon Limited. */

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
#include "zip.h"

#define HZIP_VF_NUM			63
#define HZIP_QUEUE_NUM_V1		4096
#define HZIP_QUEUE_NUM_V2		1024

#define PCI_DEVICE_ID_ZIP_PF		0xa250
#define PCI_DEVICE_ID_ZIP_VF		0xa251

#define HZIP_CLOCK_GATE_CTRL		0x301004
#define COMP0_ENABLE			BIT(0)
#define COMP1_ENABLE			BIT(1)
#define DECOMP0_ENABLE			BIT(2)
#define DECOMP1_ENABLE			BIT(3)
#define DECOMP2_ENABLE			BIT(4)
#define DECOMP3_ENABLE			BIT(5)
#define DECOMP4_ENABLE			BIT(6)
#define DECOMP5_ENABLE			BIT(7)
#define HZIP_ALL_COMP_DECOMP_EN		(COMP0_ENABLE | COMP1_ENABLE | \
					 DECOMP0_ENABLE | DECOMP1_ENABLE | \
					 DECOMP2_ENABLE | DECOMP3_ENABLE | \
					 DECOMP4_ENABLE | DECOMP5_ENABLE)
#define HZIP_DECOMP_CHECK_ENABLE	BIT(16)
#define HZIP_FSM_MAX_CNT		0x301008

#define HZIP_PORT_ARCA_CHE_0		0x301040
#define HZIP_PORT_ARCA_CHE_1		0x301044
#define HZIP_PORT_AWCA_CHE_0		0x301060
#define HZIP_PORT_AWCA_CHE_1		0x301064
#define HZIP_CACHE_ALL_EN		0xffffffff

#define HZIP_BD_RUSER_32_63		0x301110
#define HZIP_SGL_RUSER_32_63		0x30111c
#define HZIP_DATA_RUSER_32_63		0x301128
#define HZIP_DATA_WUSER_32_63		0x301134
#define HZIP_BD_WUSER_32_63		0x301140

#define HZIP_QM_IDEL_STATUS		0x3040e4
#define HZIP_MASTER_GLOBAL_CTRL		0x300000
#define HZIP_MASTER_GLOBAL_CTRL_SHUTDOWN	0x1
#define HZIP_MASTER_TRANS_RETURN	0x300150
#define HZIP_MASTER_TRANS_RETURN_RW	0x3

#define HZIP_CORE_DEBUG_COMP_0		0x302000
#define HZIP_CORE_DEBUG_COMP_1		0x303000
#define HZIP_CORE_DEBUG_DECOMP_0	0x304000
#define HZIP_CORE_DEBUG_DECOMP_1	0x305000
#define HZIP_CORE_DEBUG_DECOMP_2	0x306000
#define HZIP_CORE_DEBUG_DECOMP_3	0x307000
#define HZIP_CORE_DEBUG_DECOMP_4	0x308000
#define HZIP_CORE_DEBUG_DECOMP_5	0x309000

#define HZIP_CORE_INT_SOURCE		0x3010A0
#define HZIP_CORE_INT_MASK		0x3010A4
#define HZIP_CORE_INT_SET		0x3010A8
#define HZIP_HW_ERROR_IRQ_ENABLE	1
#define HZIP_HW_ERROR_IRQ_DISABLE	0
#define HZIP_CORE_INT_STATUS		0x3010AC
#define HZIP_CORE_INT_STATUS_M_ECC	BIT(1)
#define HZIP_CORE_SRAM_ECC_ERR_INFO	0x301148
#define HZIP_CORE_INT_RAS_CE_ENB	0x301160
#define HZIP_CORE_INT_RAS_NFE_ENB	0x301164
#define HZIP_RAS_NFE_MBIT_DISABLE	~HZIP_CORE_INT_STATUS_M_ECC
#define HZIP_CORE_INT_RAS_FE_ENB        0x301168
#define HZIP_CORE_INT_RAS_NFE_ENABLE	0x7FE
#define HZIP_SRAM_ECC_ERR_NUM_SHIFT	16
#define HZIP_SRAM_ECC_ERR_ADDR_SHIFT	24
#define HZIP_CORE_INT_DISABLE		0x000007FF
#define HZIP_COMP_CORE_NUM		2
#define HZIP_DECOMP_CORE_NUM		6
#define HZIP_CORE_NUM			(HZIP_COMP_CORE_NUM + \
					 HZIP_DECOMP_CORE_NUM)
#define HZIP_SQE_SIZE			128
#define HZIP_SQ_SIZE			(HZIP_SQE_SIZE * QM_Q_DEPTH)
#define HZIP_PF_DEF_Q_NUM		64
#define HZIP_PF_DEF_Q_BASE		0

#define HZIP_SOFT_CTRL_CNT_CLR_CE	0x301000
#define HZIP_SOFT_CTRL_CNT_CLR_CE_BIT	BIT(0)
#define HZIP_SOFT_CTRL_ZIP_CONTROL	0x30100C
#define HZIP_AXI_SHUTDOWN_ENABLE	BIT(14)
#define HZIP_AXI_SHUTDOWN_DISABLE	0xFFFFBFFF
#define HZIP_WR_MSI_PORT		0xF7FF

#define HZIP_ENABLE			1
#define HZIP_DISABLE			0
#define HZIP_NUMA_DISTANCE		100
#define HZIP_BUF_SIZE			22
#define FORMAT_DECIMAL			10
#define HZIP_REG_RD_INTVRL_US		10
#define HZIP_REG_RD_TMOUT_US		1000
#define HZIP_RESET_WAIT_TIMEOUT		400
#define HZIP_PCI_COMMAND_INVALID	0xFFFFFFFF

#define FROZEN_RANGE_MIN		10
#define FROZEN_RANGE_MAX		20

static const char hisi_zip_name[] = "hisi_zip";
static struct dentry *hzip_debugfs_root;
static LIST_HEAD(hisi_zip_list);
static DEFINE_MUTEX(hisi_zip_list_lock);

struct hisi_zip_resource {
	struct hisi_zip *hzip;
	int distance;
	struct list_head list;
};

static void free_list(struct list_head *head)
{
	struct hisi_zip_resource *res, *tmp;

	list_for_each_entry_safe(res, tmp, head, list) {
		list_del(&res->list);
		kfree(res);
	}
}

struct hisi_zip *find_zip_device(int node)
{
	struct hisi_zip *ret = NULL;
#ifdef CONFIG_NUMA
	struct hisi_zip_resource *res, *tmp;
	struct hisi_zip *hisi_zip;
	struct list_head *n;
	struct device *dev;
	LIST_HEAD(head);

	mutex_lock(&hisi_zip_list_lock);

	list_for_each_entry(hisi_zip, &hisi_zip_list, list) {
		res = kzalloc(sizeof(*res), GFP_KERNEL);
		if (!res)
			goto err;

		dev = &hisi_zip->qm.pdev->dev;
		res->hzip = hisi_zip;
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
		if (hisi_qm_get_free_qp_num(&tmp->hzip->qm)) {
			ret = tmp->hzip;
			break;
		}
	}

	free_list(&head);
#else
	mutex_lock(&hisi_zip_list_lock);

	ret = list_first_entry(&hisi_zip_list, struct hisi_zip, list);
#endif
	mutex_unlock(&hisi_zip_list_lock);

	return ret;

err:
	free_list(&head);
	mutex_unlock(&hisi_zip_list_lock);
	return NULL;
}

struct hisi_zip_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hisi_zip_hw_error zip_hw_error[] = {
	{ .int_msk = BIT(0), .msg = "zip_ecc_1bitt_err" },
	{ .int_msk = BIT(1), .msg = "zip_ecc_2bit_err" },
	{ .int_msk = BIT(2), .msg = "zip_axi_rresp_err" },
	{ .int_msk = BIT(3), .msg = "zip_axi_bresp_err" },
	{ .int_msk = BIT(4), .msg = "zip_src_addr_parse_err" },
	{ .int_msk = BIT(5), .msg = "zip_dst_addr_parse_err" },
	{ .int_msk = BIT(6), .msg = "zip_pre_in_addr_err" },
	{ .int_msk = BIT(7), .msg = "zip_pre_in_data_err" },
	{ .int_msk = BIT(8), .msg = "zip_com_inf_err" },
	{ .int_msk = BIT(9), .msg = "zip_enc_inf_err" },
	{ .int_msk = BIT(10), .msg = "zip_pre_out_err" },
	{ /* sentinel */ }
};

enum ctrl_debug_file_index {
	HZIP_CURRENT_QM,
	HZIP_CLEAR_ENABLE,
	HZIP_DEBUG_FILE_NUM,
};

static const char * const ctrl_debug_file_name[] = {
	[HZIP_CURRENT_QM]   = "current_qm",
	[HZIP_CLEAR_ENABLE] = "clear_enable",
};

struct ctrl_debug_file {
	enum ctrl_debug_file_index index;
	spinlock_t lock;
	struct hisi_zip_ctrl *ctrl;
};

/*
 * One ZIP controller has one PF and multiple VFs, some global configurations
 * which PF has need this structure.
 *
 * Just relevant for PF.
 */
struct hisi_zip_ctrl {
	u32 num_vfs;
	struct hisi_zip *hisi_zip;
	struct dentry *debug_root;
	struct ctrl_debug_file files[HZIP_DEBUG_FILE_NUM];
};

enum {
	HZIP_COMP_CORE0,
	HZIP_COMP_CORE1,
	HZIP_DECOMP_CORE0,
	HZIP_DECOMP_CORE1,
	HZIP_DECOMP_CORE2,
	HZIP_DECOMP_CORE3,
	HZIP_DECOMP_CORE4,
	HZIP_DECOMP_CORE5,
};

static const u64 core_offsets[] = {
	[HZIP_COMP_CORE0]   = 0x302000,
	[HZIP_COMP_CORE1]   = 0x303000,
	[HZIP_DECOMP_CORE0] = 0x304000,
	[HZIP_DECOMP_CORE1] = 0x305000,
	[HZIP_DECOMP_CORE2] = 0x306000,
	[HZIP_DECOMP_CORE3] = 0x307000,
	[HZIP_DECOMP_CORE4] = 0x308000,
	[HZIP_DECOMP_CORE5] = 0x309000,
};

static struct debugfs_reg32 hzip_dfx_regs[] = {
	{"HZIP_GET_BD_NUM                ",  0x00ull},
	{"HZIP_GET_RIGHT_BD              ",  0x04ull},
	{"HZIP_GET_ERROR_BD              ",  0x08ull},
	{"HZIP_DONE_BD_NUM               ",  0x0cull},
	{"HZIP_WORK_CYCLE                ",  0x10ull},
	{"HZIP_IDLE_CYCLE                ",  0x18ull},
	{"HZIP_MAX_DELAY                 ",  0x20ull},
	{"HZIP_MIN_DELAY                 ",  0x24ull},
	{"HZIP_AVG_DELAY                 ",  0x28ull},
	{"HZIP_MEM_VISIBLE_DATA          ",  0x30ull},
	{"HZIP_MEM_VISIBLE_ADDR          ",  0x34ull},
	{"HZIP_COMSUMED_BYTE             ",  0x38ull},
	{"HZIP_PRODUCED_BYTE             ",  0x40ull},
	{"HZIP_COMP_INF                  ",  0x70ull},
	{"HZIP_PRE_OUT                   ",  0x78ull},
	{"HZIP_BD_RD                     ",  0x7cull},
	{"HZIP_BD_WR                     ",  0x80ull},
	{"HZIP_GET_BD_AXI_ERR_NUM        ",  0x84ull},
	{"HZIP_GET_BD_PARSE_ERR_NUM      ",  0x88ull},
	{"HZIP_ADD_BD_AXI_ERR_NUM        ",  0x8cull},
	{"HZIP_DECOMP_STF_RELOAD_CURR_ST ",  0x94ull},
	{"HZIP_DECOMP_LZ77_CURR_ST       ",  0x9cull},
};

static int pf_q_num_set(const char *val, const struct kernel_param *kp)
{
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI,
					      PCI_DEVICE_ID_ZIP_PF, NULL);
	u32 n, q_num;
	u8 rev_id;
	int ret;

	if (!val)
		return -EINVAL;

	if (!pdev) {
		q_num = min_t(u32, HZIP_QUEUE_NUM_V1, HZIP_QUEUE_NUM_V2);
		pr_info("No device found currently, suppose queue number is %d\n",
			q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case QM_HW_V1:
			q_num = HZIP_QUEUE_NUM_V1;
			break;
		case QM_HW_V2:
			q_num = HZIP_QUEUE_NUM_V2;
			break;
		default:
			return -EINVAL;
		}
	}

	ret = kstrtou32(val, 10, &n);
	if (ret != 0 || n == 0 || n > q_num)
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

static u32 pf_q_num = HZIP_PF_DEF_Q_NUM;
module_param_cb(pf_q_num, &pf_q_num_ops, &pf_q_num, 0444);
MODULE_PARM_DESC(pf_q_num, "Number of queues in PF(v1 1-4096, v2 1-1024)");

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param_cb(uacce_mode, &uacce_mode_ops, &uacce_mode, 0444);
MODULE_PARM_DESC(uacce_mode, "Mode of UACCE can be 0(default), 2");

static const struct pci_device_id hisi_zip_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_ZIP_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_ZIP_VF) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, hisi_zip_dev_ids);

static inline void hisi_zip_add_to_list(struct hisi_zip *hisi_zip)
{
	mutex_lock(&hisi_zip_list_lock);
	list_add_tail(&hisi_zip->list, &hisi_zip_list);
	mutex_unlock(&hisi_zip_list_lock);
}

static inline void hisi_zip_remove_from_list(struct hisi_zip *hisi_zip)
{
	mutex_lock(&hisi_zip_list_lock);
	list_del(&hisi_zip->list);
	mutex_unlock(&hisi_zip_list_lock);
}

static void hisi_zip_set_user_domain_and_cache(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;

	/* qm user domain */
	writel(AXUSER_BASE, hisi_zip->qm.io_base + QM_ARUSER_M_CFG_1);
	writel(ARUSER_M_CFG_ENABLE, hisi_zip->qm.io_base +
	       QM_ARUSER_M_CFG_ENABLE);
	writel(AXUSER_BASE, hisi_zip->qm.io_base + QM_AWUSER_M_CFG_1);
	writel(AWUSER_M_CFG_ENABLE, hisi_zip->qm.io_base +
	       QM_AWUSER_M_CFG_ENABLE);
	writel(WUSER_M_CFG_ENABLE, hisi_zip->qm.io_base +
	       QM_WUSER_M_CFG_ENABLE);

	/* qm cache */
	writel(AXI_M_CFG, hisi_zip->qm.io_base + QM_AXI_M_CFG);
	writel(AXI_M_CFG_ENABLE, hisi_zip->qm.io_base + QM_AXI_M_CFG_ENABLE);
	/* disable FLR triggered by BME(bus master enable) */
	writel(PEH_AXUSER_CFG, hisi_zip->qm.io_base + QM_PEH_AXUSER_CFG);
	writel(PEH_AXUSER_CFG_ENABLE, hisi_zip->qm.io_base +
	       QM_PEH_AXUSER_CFG_ENABLE);

	/* cache */
	writel(HZIP_CACHE_ALL_EN, hisi_zip->qm.io_base + HZIP_PORT_ARCA_CHE_0);
	writel(HZIP_CACHE_ALL_EN, hisi_zip->qm.io_base + HZIP_PORT_ARCA_CHE_1);
	writel(HZIP_CACHE_ALL_EN, hisi_zip->qm.io_base + HZIP_PORT_AWCA_CHE_0);
	writel(HZIP_CACHE_ALL_EN, hisi_zip->qm.io_base + HZIP_PORT_AWCA_CHE_1);

	/* user domain configurations */
	writel(AXUSER_BASE, hisi_zip->qm.io_base + HZIP_BD_RUSER_32_63);
	writel(AXUSER_BASE, hisi_zip->qm.io_base + HZIP_SGL_RUSER_32_63);
	writel(AXUSER_BASE, hisi_zip->qm.io_base + HZIP_BD_WUSER_32_63);

	if (qm->use_sva) {
		writel(AXUSER_BASE | AXUSER_SSV, hisi_zip->qm.io_base +
		       HZIP_DATA_RUSER_32_63);
		writel(AXUSER_BASE | AXUSER_SSV, hisi_zip->qm.io_base +
		       HZIP_DATA_WUSER_32_63);
	} else {
		writel(AXUSER_BASE, hisi_zip->qm.io_base +
		       HZIP_DATA_RUSER_32_63);
		writel(AXUSER_BASE, hisi_zip->qm.io_base +
		       HZIP_DATA_WUSER_32_63);
	}

	/* let's open all compression/decompression cores */
	writel(HZIP_DECOMP_CHECK_ENABLE | HZIP_ALL_COMP_DECOMP_EN,
	       hisi_zip->qm.io_base + HZIP_CLOCK_GATE_CTRL);

	/* enable sqc,cqc writeback */
	writel(SQC_CACHE_ENABLE | CQC_CACHE_ENABLE | SQC_CACHE_WB_ENABLE |
	       CQC_CACHE_WB_ENABLE | FIELD_PREP(SQC_CACHE_WB_THRD, 1) |
	       FIELD_PREP(CQC_CACHE_WB_THRD, 1),
	       hisi_zip->qm.io_base + QM_CACHE_CTL);
}

/* hisi_zip_debug_regs_clear() - clear the zip debug regs */
static void hisi_zip_debug_regs_clear(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;

	/* clear current_qm */
	writel(0x0, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(0x0, qm->io_base + QM_DFX_DB_CNT_VF);

	/* clear rdclr_en */
	writel(0x0, qm->io_base + HZIP_SOFT_CTRL_CNT_CLR_CE);

	hisi_qm_debug_regs_clear(qm);
}


static void hisi_zip_hw_error_set_state(struct hisi_zip *hisi_zip, bool state)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	u32 val;

	if (qm->ver == QM_HW_V1) {
		writel(HZIP_CORE_INT_DISABLE, qm->io_base + HZIP_CORE_INT_MASK);
		dev_info(&qm->pdev->dev, "ZIP v%d does not support hw error handle\n",
			 qm->ver);
		return;
	}

	/* configure error type */
	writel(0x1, hisi_zip->qm.io_base + HZIP_CORE_INT_RAS_CE_ENB);
	writel(0x0, hisi_zip->qm.io_base + HZIP_CORE_INT_RAS_FE_ENB);
	writel(HZIP_CORE_INT_RAS_NFE_ENABLE,
		hisi_zip->qm.io_base + HZIP_CORE_INT_RAS_NFE_ENB);


	val = readl(hisi_zip->qm.io_base + HZIP_SOFT_CTRL_ZIP_CONTROL);
	if (state) {
		/* clear ZIP hw error source if having */
		writel(HZIP_CORE_INT_DISABLE, hisi_zip->qm.io_base +
					      HZIP_CORE_INT_SOURCE);
		/* enable ZIP hw error interrupts */
		writel(0, hisi_zip->qm.io_base + HZIP_CORE_INT_MASK);

		/* enable ZIP block master OOO when m-bit error occur */
		val = val | HZIP_AXI_SHUTDOWN_ENABLE;
	} else {
		/* disable ZIP hw error interrupts */
		writel(HZIP_CORE_INT_DISABLE,
		       hisi_zip->qm.io_base + HZIP_CORE_INT_MASK);

		/* disable ZIP block master OOO when m-bit error occur */
		val = val & HZIP_AXI_SHUTDOWN_DISABLE;
	}

	writel(val, hisi_zip->qm.io_base + HZIP_SOFT_CTRL_ZIP_CONTROL);
}

static inline struct hisi_qm *file_to_qm(struct ctrl_debug_file *file)
{
	struct hisi_zip *hisi_zip = file->ctrl->hisi_zip;

	return &hisi_zip->qm;
}

static u32 current_qm_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_DFX_MB_CNT_VF);
}

static int current_qm_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	struct hisi_zip_ctrl *ctrl = file->ctrl;
	u32 vfq_num;
	u32 tmp;

	if (val > ctrl->num_vfs)
		return -EINVAL;

	/* According PF or VF Dev ID to calculation curr_qm_qp_num and store */
	if (val == 0) {
		qm->debug.curr_qm_qp_num = qm->qp_num;
	} else {
		vfq_num = (qm->ctrl_q_num - qm->qp_num) / ctrl->num_vfs;
		if (val == ctrl->num_vfs) {
			qm->debug.curr_qm_qp_num =
				qm->ctrl_q_num - qm->qp_num -
				(ctrl->num_vfs - 1) * vfq_num;
		} else {
			qm->debug.curr_qm_qp_num = vfq_num;
		}
	}

	writel(val, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(val, qm->io_base + QM_DFX_DB_CNT_VF);

	tmp = val |
	      (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);

	tmp = val |
	      (readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & CURRENT_Q_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return  0;
}

static u32 clear_enable_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + HZIP_SOFT_CTRL_CNT_CLR_CE) &
		     HZIP_SOFT_CTRL_CNT_CLR_CE_BIT;
}

static int clear_enable_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val != 1 && val != 0)
		return -EINVAL;

	tmp = (readl(qm->io_base + HZIP_SOFT_CTRL_CNT_CLR_CE) &
	       ~HZIP_SOFT_CTRL_CNT_CLR_CE_BIT) | val;
	writel(tmp, qm->io_base + HZIP_SOFT_CTRL_CNT_CLR_CE);

	return  0;
}

static ssize_t hisi_zip_ctrl_debug_read(struct file *filp, char __user *buf,
			     size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[HZIP_BUF_SIZE];
	u32 val;
	int ret;

	spin_lock(&file->lock);
	switch (file->index) {
	case HZIP_CURRENT_QM:
		val = current_qm_read(file);
		break;
	case HZIP_CLEAR_ENABLE:
		val = clear_enable_read(file);
		break;
	default:
		spin_unlock(&file->lock);
		return -EINVAL;
	}
	spin_unlock(&file->lock);
	ret = snprintf(tbuf, HZIP_BUF_SIZE, "%u\n", val);
	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static ssize_t hisi_zip_ctrl_debug_write(struct file *filp,
					 const char __user *buf,
					 size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[HZIP_BUF_SIZE];
	unsigned long val;
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= HZIP_BUF_SIZE)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, HZIP_BUF_SIZE - 1, pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	spin_lock(&file->lock);
	switch (file->index) {
	case HZIP_CURRENT_QM:
		ret = current_qm_write(file, val);
		if (ret)
			goto err_input;
		break;
	case HZIP_CLEAR_ENABLE:
		ret = clear_enable_write(file, val);
		if (ret)
			goto err_input;
		break;
	default:
		ret = -EINVAL;
		goto err_input;
	}
	spin_unlock(&file->lock);

	return count;

err_input:
	spin_unlock(&file->lock);
	return ret;
}

static const struct file_operations ctrl_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = hisi_zip_ctrl_debug_read,
	.write = hisi_zip_ctrl_debug_write,
};

static int hisi_zip_core_debug_init(struct hisi_zip_ctrl *ctrl)
{
	struct hisi_zip *hisi_zip = ctrl->hisi_zip;
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &qm->pdev->dev;
	struct debugfs_regset32 *regset;
	struct dentry *tmp_d, *tmp;
	char buf[HZIP_BUF_SIZE];
	int i, ret;

	for (i = 0; i < HZIP_CORE_NUM; i++) {
		if (i < HZIP_COMP_CORE_NUM)
			ret = snprintf(buf, HZIP_BUF_SIZE, "comp_core%d", i);
		else
			ret = snprintf(buf, HZIP_BUF_SIZE,
				"decomp_core%d", i - HZIP_COMP_CORE_NUM);
		if (ret < 0)
			return -EINVAL;

		tmp_d = debugfs_create_dir(buf, ctrl->debug_root);
		if (!tmp_d)
			return -ENOENT;

		regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
		if (!regset)
			return -ENOENT;

		regset->regs = hzip_dfx_regs;
		regset->nregs = ARRAY_SIZE(hzip_dfx_regs);
		regset->base = qm->io_base + core_offsets[i];

		tmp = debugfs_create_regset32("regs", 0444, tmp_d, regset);
		if (!tmp)
			return -ENOENT;
	}

	return 0;
}

static int hisi_zip_ctrl_debug_init(struct hisi_zip_ctrl *ctrl)
{
	struct dentry *tmp;
	int i;

	for (i = HZIP_CURRENT_QM; i < HZIP_DEBUG_FILE_NUM; i++) {
		spin_lock_init(&ctrl->files[i].lock);
		ctrl->files[i].ctrl = ctrl;
		ctrl->files[i].index = i;

		tmp = debugfs_create_file(ctrl_debug_file_name[i], 0600,
					  ctrl->debug_root, ctrl->files + i,
					  &ctrl_debug_fops);
		if (!tmp)
			return -ENOENT;
	}

	return hisi_zip_core_debug_init(ctrl);
}

static int hisi_zip_debugfs_init(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &qm->pdev->dev;
	struct dentry *dev_d;
	int ret;

	dev_d = debugfs_create_dir(dev_name(dev), hzip_debugfs_root);
	if (!dev_d)
		return -ENOENT;

	qm->debug.debug_root = dev_d;
	ret = hisi_qm_debug_init(qm);
	if (ret)
		goto failed_to_create;

	if (qm->fun_type == QM_HW_PF) {
		hisi_zip->ctrl->debug_root = dev_d;
		ret = hisi_zip_ctrl_debug_init(hisi_zip->ctrl);
		if (ret)
			goto failed_to_create;
	}

	return 0;

failed_to_create:
	debugfs_remove_recursive(hzip_debugfs_root);
	return ret;
}

static void hisi_zip_debugfs_exit(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;

	debugfs_remove_recursive(qm->debug.debug_root);

	if (qm->fun_type == QM_HW_PF) {
		hisi_zip_debug_regs_clear(hisi_zip);
		qm->debug.curr_qm_qp_num = 0;
	}
}

static void hisi_zip_hw_error_init(struct hisi_zip *hisi_zip)
{
	hisi_qm_hw_error_init(&hisi_zip->qm, QM_BASE_CE,
			      QM_BASE_NFE | QM_ACC_WB_NOT_READY_TIMEOUT, 0,
			      QM_DB_RANDOM_INVALID);
	hisi_zip_hw_error_set_state(hisi_zip, true);
}

static u32 hisi_zip_get_hw_err_status(struct hisi_qm *qm)
{
	return readl(qm->io_base + HZIP_CORE_INT_STATUS);
}

static void hisi_zip_clear_hw_err_status(struct hisi_qm *qm, u32 err_sts)
{
	writel(err_sts, qm->io_base + HZIP_CORE_INT_SOURCE);
}

static void hisi_zip_set_ecc(struct hisi_qm *qm)
{
	u32 nfe_enb;

	nfe_enb = readl(qm->io_base + HZIP_CORE_INT_RAS_NFE_ENB);
	writel(nfe_enb & HZIP_RAS_NFE_MBIT_DISABLE,
	       qm->io_base + HZIP_CORE_INT_RAS_NFE_ENB);
	writel(HZIP_CORE_INT_STATUS_M_ECC, qm->io_base + HZIP_CORE_INT_SET);
	qm->err_ini.is_dev_ecc_mbit = 1;
}

static void hisi_zip_log_hw_error(struct hisi_qm *qm, u32 err_sts)
{
	const struct hisi_zip_hw_error *err = zip_hw_error;
	struct device *dev = &qm->pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts) {
			dev_err(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);

			if (err->int_msk & HZIP_CORE_INT_STATUS_M_ECC) {
				err_val = readl(qm->io_base +
						HZIP_CORE_SRAM_ECC_ERR_INFO);
				dev_err(dev, "hisi-zip multi ecc sram num=0x%x\n",
					 ((err_val >>
					   HZIP_SRAM_ECC_ERR_NUM_SHIFT) &
					   0xFF));
				dev_err(dev, "hisi-zip multi ecc sram addr=0x%x\n",
					 (err_val >>
					  HZIP_SRAM_ECC_ERR_ADDR_SHIFT));
			}
		}
		err++;
	}
}

static int hisi_zip_pf_probe_init(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	struct hisi_zip_ctrl *ctrl;

	ctrl = devm_kzalloc(&qm->pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	hisi_zip->ctrl = ctrl;
	ctrl->hisi_zip = hisi_zip;

	switch (qm->ver) {
	case QM_HW_V1:
		qm->ctrl_q_num = HZIP_QUEUE_NUM_V1;
		break;

	case QM_HW_V2:
		qm->ctrl_q_num = HZIP_QUEUE_NUM_V2;
		break;

	default:
		return -EINVAL;
	}

	qm->err_ini.qm_wr_port = HZIP_WR_MSI_PORT;
	qm->err_ini.ecc_2bits_mask = HZIP_CORE_INT_STATUS_M_ECC;
	qm->err_ini.get_dev_hw_err_status = hisi_zip_get_hw_err_status;
	qm->err_ini.clear_dev_hw_err_status = hisi_zip_clear_hw_err_status;
	qm->err_ini.log_dev_hw_err = hisi_zip_log_hw_error;
	qm->err_ini.inject_dev_hw_err = hisi_zip_set_ecc;

	hisi_zip_set_user_domain_and_cache(hisi_zip);
	hisi_zip_hw_error_init(hisi_zip);
	hisi_zip_debug_regs_clear(hisi_zip);

	return 0;
}

static int hisi_zip_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_zip *hisi_zip;
	enum qm_hw_ver rev_id;
	struct hisi_qm *qm;
	int ret;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id == QM_HW_UNKNOWN)
		return -EINVAL;

	hisi_zip = devm_kzalloc(&pdev->dev, sizeof(*hisi_zip), GFP_KERNEL);
	if (!hisi_zip)
		return -ENOMEM;

	pci_set_drvdata(pdev, hisi_zip);

	hisi_zip_add_to_list(hisi_zip);

	hisi_zip->status = 0;
	qm = &hisi_zip->qm;
	qm->pdev = pdev;
	qm->ver = rev_id;

	qm->sqe_size = HZIP_SQE_SIZE;
	qm->dev_name = hisi_zip_name;
	qm->fun_type = (pdev->device == PCI_DEVICE_ID_ZIP_PF) ? QM_HW_PF :
								QM_HW_VF;
	qm->algs = "zlib\ngzip\nxts(sm4)\nxts(aes)\n";

	switch (uacce_mode) {
	case UACCE_MODE_NOUACCE:
		qm->use_uacce = false;
		break;
	case UACCE_MODE_NOIOMMU:
		qm->use_uacce = true;
		break;
	default:
		ret = -EINVAL;
		goto err_remove_from_list;
	}

	ret = hisi_qm_init(qm);
	if (ret) {
		dev_err(&pdev->dev, "Failed to init qm!\n");
		goto err_remove_from_list;
	}

	if (qm->fun_type == QM_HW_PF) {
		ret = hisi_zip_pf_probe_init(hisi_zip);
		if (ret)
			goto err_remove_from_list;

		qm->qp_base = HZIP_PF_DEF_Q_BASE;
		qm->qp_num = pf_q_num;
		qm->debug.curr_qm_qp_num = pf_q_num;
	} else if (qm->fun_type == QM_HW_VF) {
		/*
		 * have no way to get qm configure in VM in v1 hardware,
		 * so currently force PF to uses HZIP_PF_DEF_Q_NUM, and force
		 * to trigger only one VF in v1 hardware.
		 *
		 * v2 hardware has no such problem.
		 */
		if (qm->ver == QM_HW_V1) {
			qm->qp_base = HZIP_PF_DEF_Q_NUM;
			qm->qp_num = HZIP_QUEUE_NUM_V1 - HZIP_PF_DEF_Q_NUM;
		} else if (qm->ver == QM_HW_V2) {
			/* v2 starts to support get vft by mailbox */
			ret = hisi_qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
			if (ret)
				goto err_remove_from_list;
		}
	}

	ret = hisi_qm_start(qm);
	if (ret)
		goto err_qm_uninit;

	ret = hisi_zip_debugfs_init(hisi_zip);
	if (ret)
		dev_err(&pdev->dev, "Failed to init debugfs (%d)!\n", ret);

	ret = hisi_zip_register_to_crypto();
	if (ret < 0) {
		pr_err("Failed to register driver to crypto.\n");
		goto err_qm_stop;
	}
	return 0;

err_qm_stop:
	hisi_zip_debugfs_exit(hisi_zip);
	hisi_qm_stop(qm, QM_NORMAL);
err_qm_uninit:
	hisi_qm_uninit(qm);
err_remove_from_list:
	hisi_zip_remove_from_list(hisi_zip);
	return ret;
}

/* now we only support equal assignment */
static int hisi_zip_vf_q_assign(struct hisi_zip *hisi_zip, u32 num_vfs)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	u32 qp_num = qm->qp_num;
	u32 q_base = qp_num;
	u32 q_num, remain_q_num, i;
	int ret;

	if (!num_vfs)
		return -EINVAL;

	remain_q_num = qm->ctrl_q_num - qp_num;
	/* If remain queues not enough, return error. */
	if (remain_q_num < num_vfs)
		return -EINVAL;

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

static int hisi_zip_clear_vft_config(struct hisi_zip *hisi_zip)
{
	struct hisi_zip_ctrl *ctrl = hisi_zip->ctrl;
	struct hisi_qm *qm = &hisi_zip->qm;
	u32 i, num_vfs = ctrl->num_vfs;
	int ret;

	for (i = 1; i <= num_vfs; i++) {
		ret = hisi_qm_set_vft(qm, i, 0, 0);
		if (ret)
			return ret;
	}

	ctrl->num_vfs = 0;

	return 0;
}

static int hisi_zip_sriov_enable(struct pci_dev *pdev, int max_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	int pre_existing_vfs, num_vfs, ret;

	pre_existing_vfs = pci_num_vf(pdev);
	if (pre_existing_vfs) {
		dev_err(&pdev->dev,
			"Can't enable VF. Please disable pre-enabled VFs!\n");
		return 0;
	}

	num_vfs = min_t(int, max_vfs, HZIP_VF_NUM);

	ret = hisi_zip_vf_q_assign(hisi_zip, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't assign queues for VF!\n");
		return ret;
	}

	hisi_zip->ctrl->num_vfs = num_vfs;

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't enable VF!\n");
		hisi_zip_clear_vft_config(hisi_zip);
		return ret;
	}

	return num_vfs;
#else
	return 0;
#endif
}

static int hisi_zip_try_frozen_vfs(struct pci_dev *pdev)
{
	struct hisi_zip *zip, *vf_zip;
	struct pci_dev *dev;
	int ret = 0;

	/* Try to frozen all the VFs as disable SRIOV */
	mutex_lock(&hisi_zip_list_lock);
	list_for_each_entry(zip, &hisi_zip_list, list) {
		dev = zip->qm.pdev;
		if (dev == pdev)
			continue;
		if (pci_physfn(dev) == pdev) {
			vf_zip = pci_get_drvdata(dev);
			ret = hisi_qm_frozen(&vf_zip->qm);
			if (ret)
				goto frozen_fail;
		}
	}

frozen_fail:
	mutex_unlock(&hisi_zip_list_lock);
	return ret;
}

static int hisi_zip_sriov_disable(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);

	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev,
			"Can't disable VFs while VFs are assigned!\n");
		return -EPERM;
	}

	if (hisi_zip_try_frozen_vfs(pdev)) {
		dev_err(&pdev->dev, "try frozen VFs failed!\n");
		return -EBUSY;
	}

	/* remove in hisi_zip_pci_driver will be called to free VF resources */
	pci_disable_sriov(pdev);

	return hisi_zip_clear_vft_config(hisi_zip);
}

static int hisi_zip_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return hisi_zip_sriov_disable(pdev);
	else
		return hisi_zip_sriov_enable(pdev, num_vfs);
}

static void hisi_zip_remove_wait_delay(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;

	while (hisi_qm_frozen(qm) || ((qm->fun_type == QM_HW_PF) &&
		hisi_zip_try_frozen_vfs(qm->pdev)))
		usleep_range(FROZEN_RANGE_MIN, FROZEN_RANGE_MAX);

	udelay(ZIP_WAIT_DELAY);
}

static void hisi_zip_remove(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_zip->qm;

	if (uacce_mode != UACCE_MODE_NOUACCE)
		hisi_zip_remove_wait_delay(hisi_zip);

	if (qm->fun_type == QM_HW_PF && hisi_zip->ctrl->num_vfs != 0)
		(void)hisi_zip_sriov_disable(pdev);

	hisi_zip_unregister_from_crypto();
	hisi_zip_debugfs_exit(hisi_zip);
	hisi_qm_stop(qm, QM_NORMAL);

	if (qm->fun_type == QM_HW_PF)
		hisi_zip_hw_error_set_state(hisi_zip, false);

	hisi_qm_uninit(qm);
	hisi_zip_remove_from_list(hisi_zip);
}

static void hisi_zip_shutdown(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);

	hisi_qm_stop(&hisi_zip->qm, QM_NORMAL);
}

static pci_ers_result_t hisi_zip_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_NONE;

	dev_info(&pdev->dev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hisi_qm_process_dev_error(pdev);
}

static int hisi_zip_reset_prepare_ready(struct hisi_zip *hisi_zip)
{
	struct pci_dev *pdev = hisi_zip->qm.pdev;
	struct hisi_zip *zip = pci_get_drvdata(pci_physfn(pdev));
	int delay = 0;

	while (test_and_set_bit(HISI_ZIP_RESET, &zip->status)) {
		msleep(++delay);
		if (delay > HZIP_RESET_WAIT_TIMEOUT)
			return -EBUSY;
	}

	return 0;
}

static int hisi_zip_vf_reset_prepare(struct hisi_zip *hisi_zip,
				     enum qm_stop_reason stop_reason)
{
	struct pci_dev *pdev = hisi_zip->qm.pdev;
	struct pci_dev *dev;
	struct hisi_qm *qm;
	int ret = 0;

	mutex_lock(&hisi_zip_list_lock);
	if (pdev->is_physfn) {
		list_for_each_entry(hisi_zip, &hisi_zip_list, list) {
			dev = hisi_zip->qm.pdev;
			if (dev == pdev)
				continue;

			if (pci_physfn(dev) == pdev) {
				qm = &hisi_zip->qm;

				ret = hisi_qm_stop(qm, stop_reason);
				if (ret)
					goto prepare_fail;
			}
		}
	}

prepare_fail:
	mutex_unlock(&hisi_zip_list_lock);
	return ret;
}

static int hisi_zip_controller_reset_prepare(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;

	ret = hisi_zip_reset_prepare_ready(hisi_zip);
	if (ret) {
		dev_err(dev, "Controller reset not ready!\n");
		return ret;
	}

	ret = hisi_zip_vf_reset_prepare(hisi_zip, QM_SOFT_RESET);
	if (ret) {
		dev_err(dev, "Fails to stop VFs!\n");
		return ret;
	}

	ret = hisi_qm_stop(qm, QM_SOFT_RESET);
	if (ret) {
		dev_err(dev, "Fails to stop QM!\n");
		return ret;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce) {
		ret = uacce_hw_err_isolate(&qm->uacce);
		if (ret) {
			dev_err(dev, "Fails to isolate hw err!\n");
			return ret;
		}
	}
#endif

	return 0;
}

static int hisi_zip_soft_reset(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &qm->pdev->dev;
	unsigned long long value;
	int ret;
	u32 val;

	ret = hisi_qm_reg_test(qm);
	if (ret)
		return ret;

	ret = hisi_qm_set_vf_mse(qm, HZIP_DISABLE);
	if (ret) {
		dev_err(dev, "Fails to disable vf mse bit.\n");
		return ret;
	}

	ret = hisi_qm_set_msi(qm, HZIP_DISABLE);
	if (ret) {
		dev_err(dev, "Fails to disable peh msi bit.\n");
		return ret;
	}

	/* Set qm ecc if dev ecc happened to hold on ooo */
	hisi_qm_set_ecc(qm);

	/* OOO register set and check */
	writel(HZIP_MASTER_GLOBAL_CTRL_SHUTDOWN,
	       hisi_zip->qm.io_base + HZIP_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hisi_zip->qm.io_base +
					 HZIP_MASTER_TRANS_RETURN, val,
					 (val == HZIP_MASTER_TRANS_RETURN_RW),
					 HZIP_REG_RD_INTVRL_US,
					 HZIP_REG_RD_TMOUT_US);
	if (ret) {
		dev_emerg(dev, "Bus lock! Please reset system.\n");
		return ret;
	}

	ret = hisi_qm_set_pf_mse(qm, HZIP_DISABLE);
	if (ret) {
		dev_err(dev, "Fails to disable pf mse bit.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(dev)) {
		acpi_status s;

		s = acpi_evaluate_integer(ACPI_HANDLE(dev), "ZRST",
					  NULL, &value);
		if (ACPI_FAILURE(s)) {
			dev_err(dev, "NO controller reset method!\n");
			return -EIO;
		}

		if (value) {
			dev_err(dev, "Reset step %llu failed!\n", value);
			return -EIO;
		}
	} else {
		dev_err(dev, "No reset method!\n");
		return -EINVAL;
	}

	return 0;
}

static int hisi_zip_vf_reset_done(struct hisi_zip *hisi_zip)
{
	struct pci_dev *pdev = hisi_zip->qm.pdev;
	struct pci_dev *dev;
	struct hisi_qm *qm;
	int ret = 0;

	mutex_lock(&hisi_zip_list_lock);
	list_for_each_entry(hisi_zip, &hisi_zip_list, list) {
		dev = hisi_zip->qm.pdev;
		if (dev == pdev)
			continue;

		if (pci_physfn(dev) == pdev) {
			qm = &hisi_zip->qm;

			ret = hisi_qm_restart(qm);
			if (ret)
				goto reset_fail;
		}
	}

reset_fail:
	mutex_unlock(&hisi_zip_list_lock);
	return ret;
}

static int hisi_zip_controller_reset_done(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;

	ret = hisi_qm_set_msi(qm, HZIP_ENABLE);
	if (ret) {
		dev_err(dev, "Fails to enable peh msi bit!\n");
		return ret;
	}

	ret = hisi_qm_set_pf_mse(qm, HZIP_ENABLE);
	if (ret) {
		dev_err(dev, "Fails to enable pf mse bit!\n");
		return ret;
	}

	ret = hisi_qm_set_vf_mse(qm, HZIP_ENABLE);
	if (ret) {
		dev_err(dev, "Fails to enable vf mse bit!\n");
		return ret;
	}

	hisi_zip_set_user_domain_and_cache(hisi_zip);
	hisi_qm_restart_prepare(qm);

	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(dev, "Failed to start QM!\n");
		return -EPERM;
	}

	if (hisi_zip->ctrl->num_vfs) {
		ret = hisi_zip_vf_q_assign(hisi_zip, hisi_zip->ctrl->num_vfs);
		if (ret) {
			dev_err(dev, "Failed to assign vf queues!\n");
			return ret;
		}
	}

	ret = hisi_zip_vf_reset_done(hisi_zip);
	if (ret) {
		dev_err(dev, "Failed to start VFs!\n");
		return -EPERM;
	}

	hisi_qm_restart_done(qm);
	hisi_zip_hw_error_init(hisi_zip);

	return 0;
}

static int hisi_zip_controller_reset(struct hisi_zip *hisi_zip)
{
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;

	dev_info(dev, "Controller resetting...\n");

	ret = hisi_zip_controller_reset_prepare(hisi_zip);
	if (ret)
		return ret;

	ret = hisi_zip_soft_reset(hisi_zip);
	if (ret) {
		dev_err(dev, "Controller reset failed (%d)\n", ret);
		return ret;
	}

	ret = hisi_zip_controller_reset_done(hisi_zip);
	if (ret)
		return ret;

	clear_bit(HISI_ZIP_RESET, &hisi_zip->status);

	dev_info(dev, "Controller reset complete\n");

	return ret;
}

static pci_ers_result_t hisi_zip_slot_reset(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	int ret;

	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_RECOVERED;

	dev_info(&pdev->dev, "Requesting reset due to PCI error\n");

	pci_cleanup_aer_uncorrect_error_status(pdev);

	ret = hisi_zip_controller_reset(hisi_zip);
	if (ret) {
		dev_err(&pdev->dev, "hisi_zip controller reset failed (%d)\n",
			 ret);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static void hisi_zip_set_hw_error(struct hisi_zip *hisi_zip, bool state)
{
	struct pci_dev *pdev = hisi_zip->qm.pdev;
	struct hisi_zip *zip = pci_get_drvdata(pci_physfn(pdev));
	struct hisi_qm *qm = &zip->qm;

	if (qm->fun_type == QM_HW_VF)
		return;

	if (state)
		hisi_qm_hw_error_init(qm, QM_BASE_CE,
				      QM_BASE_NFE | QM_ACC_WB_NOT_READY_TIMEOUT,
				      0, QM_DB_RANDOM_INVALID);
	else
		hisi_qm_hw_error_uninit(qm);

	hisi_zip_hw_error_set_state(zip, state);
}

static int hisi_zip_get_hw_error_status(struct hisi_zip *hisi_zip)
{
	u32 err_sts;

	err_sts = readl(hisi_zip->qm.io_base + HZIP_CORE_INT_STATUS) &
			HZIP_CORE_INT_STATUS_M_ECC;
	if (err_sts)
		return err_sts;

	return 0;
}

static int hisi_zip_check_hw_error(struct hisi_zip *hisi_zip)
{
	struct pci_dev *pdev = hisi_zip->qm.pdev;
	struct hisi_zip *zip = pci_get_drvdata(pci_physfn(pdev));
	struct hisi_qm *qm = &zip->qm;
	int ret;

	if (qm->fun_type == QM_HW_VF)
		return 0;

	ret = hisi_qm_get_hw_error_status(qm);
	if (ret)
		return ret;

	return hisi_zip_get_hw_error_status(zip);
}

static void hisi_zip_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &pdev->dev;
	u32 delay = 0;
	int ret;

	hisi_zip_set_hw_error(hisi_zip, HZIP_HW_ERROR_IRQ_DISABLE);

	while (hisi_zip_check_hw_error(hisi_zip)) {
		msleep(++delay);
		if (delay > HZIP_RESET_WAIT_TIMEOUT)
			return;
	}

	ret = hisi_zip_reset_prepare_ready(hisi_zip);
	if (ret) {
		dev_err(dev, "FLR not ready!\n");
		return;
	}

	ret = hisi_zip_vf_reset_prepare(hisi_zip, QM_FLR);
	if (ret) {
		dev_err(dev, "Fails to prepare reset!\n");
		return;
	}

	ret = hisi_qm_stop(qm, QM_FLR);
	if (ret) {
		dev_err(dev, "Fails to stop QM!\n");
		return;
	}

	dev_info(dev, "FLR resetting...\n");
}

static void hisi_zip_flr_reset_complete(struct hisi_zip *hisi_zip)
{
	struct pci_dev *pdev = hisi_zip->qm.pdev;
	struct hisi_zip *zip = pci_get_drvdata(pci_physfn(pdev));
	struct device *dev = &zip->qm.pdev->dev;
	u32 id;

	pci_read_config_dword(zip->qm.pdev, PCI_COMMAND, &id);
	if (id == HZIP_PCI_COMMAND_INVALID)
		dev_err(dev, "Device can not be used!\n");

	clear_bit(HISI_ZIP_RESET, &zip->status);
}

static void hisi_zip_reset_done(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_zip->qm;
	struct device *dev = &pdev->dev;
	int ret;

	hisi_zip_set_hw_error(hisi_zip, HZIP_HW_ERROR_IRQ_ENABLE);

	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(dev, "Failed to start QM!\n");
		goto flr_done;
	}

	if (pdev->is_physfn) {
		hisi_zip_set_user_domain_and_cache(hisi_zip);
		if (hisi_zip->ctrl->num_vfs)
			hisi_zip_vf_q_assign(hisi_zip,
				hisi_zip->ctrl->num_vfs);
		ret = hisi_zip_vf_reset_done(hisi_zip);
		if (ret) {
			dev_err(dev, "Failed to start VFs!\n");
			goto flr_done;
		}
	}

flr_done:
	hisi_zip_flr_reset_complete(hisi_zip);

	dev_info(dev, "FLR reset complete\n");
}

static const struct pci_error_handlers hisi_zip_err_handler = {
	.error_detected	= hisi_zip_error_detected,
	.slot_reset	= hisi_zip_slot_reset,
	.reset_prepare	= hisi_zip_reset_prepare,
	.reset_done	= hisi_zip_reset_done,
};

static struct pci_driver hisi_zip_pci_driver = {
	.name		= "hisi_zip",
	.id_table	= hisi_zip_dev_ids,
	.probe		= hisi_zip_probe,
	.remove		= hisi_zip_remove,
	.sriov_configure = hisi_zip_sriov_configure,
	.err_handler	= &hisi_zip_err_handler,
	.shutdown	= hisi_zip_shutdown,
};

static void hisi_zip_register_debugfs(void)
{
	if (!debugfs_initialized())
		return;

	hzip_debugfs_root = debugfs_create_dir("hisi_zip", NULL);
	if (IS_ERR_OR_NULL(hzip_debugfs_root))
		hzip_debugfs_root = NULL;
}

static void hisi_zip_unregister_debugfs(void)
{
	debugfs_remove_recursive(hzip_debugfs_root);
}

static int __init hisi_zip_init(void)
{
	int ret;

	hisi_zip_register_debugfs();

	ret = pci_register_driver(&hisi_zip_pci_driver);
	if (ret < 0) {
		hisi_zip_unregister_debugfs();
		pr_err("Failed to register pci driver.\n");
	}

	return ret;
}

static void __exit hisi_zip_exit(void)
{
	pci_unregister_driver(&hisi_zip_pci_driver);
	hisi_zip_unregister_debugfs();
}

module_init(hisi_zip_init);
module_exit(hisi_zip_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("Driver for HiSilicon ZIP accelerator");
