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
#include "sec.h"
#include "sec_crypto.h"

#define SEC_VF_NUM			63
#define SEC_QUEUE_NUM_V1		4096
#define SEC_QUEUE_NUM_V2		1024
#define SEC_PCI_DEVICE_ID_PF		0xa255
#define SEC_PCI_DEVICE_ID_VF		0xa256

#define SEC_COMMON_REG_OFF		0x1000

#define SEC_MASTER_GLOBAL_CTRL		0x300000
#define SEC_MASTER_GLOBAL_CTRL_SHUTDOWN	0x1
#define SEC_MASTER_TRANS_RETURN		0x300150
#define SEC_MASTER_TRANS_RETURN_RW	0x3
#define SEC_AM_CFG_SIG_PORT_MAX_TRANS	0x300014
#define SEC_SINGLE_PORT_MAX_TRANS	0x2060

#define SEC_CORE_INT_SOURCE		0x301010
#define SEC_CORE_INT_MASK		0x301000
#define SEC_CORE_INT_STATUS		0x301008
#define SEC_CORE_INT_STATUS_M_ECC	BIT(2)
#define SEC_CORE_ECC_INFO		0x301C14
#define SEC_ECC_NUM(err_val)		(((err_val) >> 16) & 0xFFFF)
#define SEC_ECC_ADDR(err_val)		((err_val) & 0xFFFF)

#define SEC_CORE_INT_DISABLE		0x0
#define SEC_CORE_INT_ENABLE		0x1ff
#define SEC_HW_ERROR_IRQ_ENABLE		1
#define SEC_HW_ERROR_IRQ_DISABLE	0

#define SEC_BD_ERR_CHK_EN0		0xEFFFFFFF
#define SEC_BD_ERR_CHK_EN1		0x7FFFF7FD
#define SEC_BD_ERR_CHK_EN3		0xFFFFBFFF
#define SEC_BD_ERR_CHK_EN_REG0		0x0380
#define SEC_BD_ERR_CHK_EN_REG1		0x0384
#define SEC_BD_ERR_CHK_EN_REG3		0x038c

#define SEC_SQE_SIZE			128
#define SEC_SQ_SIZE			(SEC_SQE_SIZE * QM_Q_DEPTH)
#define SEC_PF_DEF_Q_NUM		64
#define SEC_PF_DEF_Q_BASE		0

#define SEC_CTRL_CNT_CLR_CE		0x301120
#define SEC_CTRL_CNT_CLR_CE_BIT		BIT(0)

#define SEC_ENGINE_PF_CFG_OFF		0x300000
#define SEC_ACC_COMMON_REG_OFF		0x1000

#define SEC_RAS_CE_REG			0x50
#define SEC_RAS_FE_REG			0x54
#define SEC_RAS_NFE_REG			0x58
#define SEC_RAS_CE_ENB_MSK		0x88
#define SEC_RAS_FE_ENB_MSK		0x0
#define SEC_RAS_NFE_ENB_MSK		0x177
#define SEC_RAS_DISABLE			0x0

#define SEC_SAA_EN_REG			0x270
#define SEC_SAA_EN			0x17F

#define SEC_MEM_START_INIT_REG		0x0100
#define SEC_MEM_INIT_DONE_REG		0x0104

#define SEC_CONTROL_REG			0x0200
#define SEC_TRNG_EN_SHIFT		8
#define SEC_CLK_GATE_DISABLE		(~BIT(3))
#define SEC_AXI_SHUTDOWN_ENABLE		BIT(12)
#define SEC_AXI_SHUTDOWN_DISABLE	0xFFFFEFFF
#define SEC_WR_MSI_PORT			0xFFFE

#define SEC_INTERFACE_USER_CTRL0_REG	0x0220
#define SEC_INTERFACE_USER_CTRL1_REG	0x0224

#define SEC_USER0_SMMU_NORMAL		(BIT(23) | BIT(15))
#define SEC_USER1_SMMU_NORMAL		(BIT(31) | BIT(23) | BIT(15) | BIT(7))

#define SEC_DELAY_10_US			10
#define SEC_POLL_TIMEOUT_US		1000
#define SEC_WAIT_DELAY			1000

#define SEC_DBGFS_VAL_MAX_LEN		20

#define SEC_CHAIN_ABN_LEN		128UL
#define SEC_ENABLE			1
#define SEC_DISABLE			0
#define SEC_RESET_WAIT_TIMEOUT		400
#define SEC_PCI_COMMAND_INVALID		0xFFFFFFFF

#define FORMAT_DECIMAL			10
#define FROZEN_RANGE_MIN		10
#define FROZEN_RANGE_MAX		20

static const char sec_name[] = "hisi_sec2";
static struct dentry *sec_debugfs_root;
static u32 pf_q_num = SEC_PF_DEF_Q_NUM;
static struct workqueue_struct *sec_wq;

LIST_HEAD(hisi_sec_list);
DEFINE_MUTEX(hisi_sec_list_lock);

struct hisi_sec_resource {
	struct hisi_sec *sec;
	int distance;
	struct list_head list;
};

static void free_list(struct list_head *head)
{
	struct hisi_sec_resource *res, *tmp;

	list_for_each_entry_safe(res, tmp, head, list) {
		list_del(&res->list);
		kfree(res);
	}
}

struct hisi_sec *find_sec_device(int node)
{
	struct hisi_sec *ret = NULL;
#ifdef CONFIG_NUMA
	struct hisi_sec_resource *res, *tmp;
	struct hisi_sec *hisi_sec;
	struct list_head *n;
	struct device *dev;
	LIST_HEAD(head);

	mutex_lock(&hisi_sec_list_lock);

	list_for_each_entry(hisi_sec, &hisi_sec_list, list) {
		res = kzalloc(sizeof(*res), GFP_KERNEL);
		if (!res)
			goto err;

		dev = &hisi_sec->qm.pdev->dev;
		res->sec = hisi_sec;
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
		if (tmp->sec->q_ref + tmp->sec->ctx_q_num <= pf_q_num) {
			tmp->sec->q_ref += tmp->sec->ctx_q_num;
			ret = tmp->sec;
			break;
		}
	}

	free_list(&head);
#else
	mutex_lock(&hisi_sec_list_lock);

	ret = list_first_entry(&hisi_sec_list, struct hisi_sec, list);
#endif
	mutex_unlock(&hisi_sec_list_lock);

	return ret;

err:
	free_list(&head);
	mutex_unlock(&hisi_sec_list_lock);
	return NULL;
}

struct hisi_sec_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hisi_sec_hw_error sec_hw_error[] = {
	{.int_msk = BIT(0), .msg = "sec_axi_rresp_err_rint"},
	{.int_msk = BIT(1), .msg = "sec_axi_bresp_err_rint"},
	{.int_msk = BIT(2), .msg = "sec_ecc_2bit_err_rint"},
	{.int_msk = BIT(3), .msg = "sec_ecc_1bit_err_rint"},
	{.int_msk = BIT(4), .msg = "sec_req_trng_timeout_rint"},
	{.int_msk = BIT(5), .msg = "sec_fsm_hbeat_rint"},
	{.int_msk = BIT(6), .msg = "sec_channel_req_rng_timeout_rint"},
	{.int_msk = BIT(7), .msg = "sec_bd_err_rint"},
	{.int_msk = BIT(8), .msg = "sec_chain_buff_err_rint"},
	{ /* sentinel */ }
};

enum ctrl_debug_file_index {
	SEC_CURRENT_QM,
	SEC_CLEAR_ENABLE,
	SEC_DEBUG_FILE_NUM,
};

static const char * const ctrl_debug_file_name[] = {
	[SEC_CURRENT_QM] = "current_qm",
	[SEC_CLEAR_ENABLE] = "clear_enable",
};

struct ctrl_debug_file {
	enum ctrl_debug_file_index index;
	spinlock_t lock;
	struct hisi_sec_ctrl *ctrl;
};

/*
 * One SEC controller has one PF and multiple VFs, some global configurations
 * which PF has need this structure.
 *
 * Just relevant for PF.
 */
struct hisi_sec_ctrl {
	u32 num_vfs;
	struct hisi_sec *hisi_sec;
	struct dentry *debug_root;
	struct ctrl_debug_file files[SEC_DEBUG_FILE_NUM];
};

static struct debugfs_reg32 sec_dfx_regs[] = {
	{"SEC_PF_ABNORMAL_INT_SOURCE     ",  0x301010},
	{"SEC_SAA_EN                    ",  0x301270},
	{"SEC_BD_LATENCY_MIN            ",  0x301600},
	{"SEC_BD_LATENCY_MAX            ",  0x301608},
	{"SEC_BD_LATENCY_AVG            ",  0x30160C},
	{"SEC_BD_NUM_IN_SAA0            ",  0x301670},
	{"SEC_BD_NUM_IN_SAA1            ",  0x301674},
	{"SEC_BD_NUM_IN_SEC             ",  0x301680},
	{"SEC_ECC_1BIT_CNT              ",  0x301C00},
	{"SEC_ECC_1BIT_INFO             ",  0x301C04},
	{"SEC_ECC_2BIT_CNT              ",  0x301C10},
	{"SEC_ECC_2BIT_INFO             ",  0x301C14},
	{"SEC_BD_SAA0                   ",  0x301C20},
	{"SEC_BD_SAA1                   ",  0x301C24},
	{"SEC_BD_SAA2                   ",  0x301C28},
	{"SEC_BD_SAA3                   ",  0x301C2C},
	{"SEC_BD_SAA4                   ",  0x301C30},
	{"SEC_BD_SAA5                   ",  0x301C34},
	{"SEC_BD_SAA6                   ",  0x301C38},
	{"SEC_BD_SAA7                   ",  0x301C3C},
	{"SEC_BD_SAA8                   ",  0x301C40},
};

static int pf_q_num_set(const char *val, const struct kernel_param *kp)
{
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI,
						  SEC_PCI_DEVICE_ID_PF, NULL);
	u32 n, q_num;
	u8 rev_id;
	int ret;

	if (!val)
		return -EINVAL;

	if (unlikely(!pdev)) {
		q_num = min_t(u32, SEC_QUEUE_NUM_V1, SEC_QUEUE_NUM_V2);
		pr_info
		    ("No device found currently, suppose queue number is %d\n",
		     q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case QM_HW_V1:
			q_num = SEC_QUEUE_NUM_V1;
			break;
		case QM_HW_V2:
			q_num = SEC_QUEUE_NUM_V2;
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

static int ctx_q_num_set(const char *val, const struct kernel_param *kp)
{
	u32 ctx_q_num;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, FORMAT_DECIMAL, &ctx_q_num);
	if (ret)
		return -EINVAL;

	if (ctx_q_num == 0 || ctx_q_num > QM_Q_DEPTH || ctx_q_num % 2 == 1) {
		pr_err("ctx_q_num[%u] is invalid\n", ctx_q_num);
		return -EINVAL;
	}

	return param_set_int(val, kp);
}

static const struct kernel_param_ops ctx_q_num_ops = {
	.set = ctx_q_num_set,
	.get = param_get_int,
};

static int fusion_limit_set(const char *val, const struct kernel_param *kp)
{
	u32 fusion_limit;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, FORMAT_DECIMAL, &fusion_limit);
	if (ret)
		return ret;

	if (fusion_limit == 0 || fusion_limit > FUSION_LIMIT_MAX) {
		pr_err("fusion_limit[%u] is't at range(0, %d)", fusion_limit,
			FUSION_LIMIT_MAX);
		return -EINVAL;
	}

	return param_set_int(val, kp);
}

static const struct kernel_param_ops fusion_limit_ops = {
	.set = fusion_limit_set,
	.get = param_get_int,
};

static int fusion_tmout_nsec_set(const char *val, const struct kernel_param *kp)
{
	u32 fusion_tmout_nsec;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, FORMAT_DECIMAL, &fusion_tmout_nsec);
	if (ret)
		return ret;

	if (fusion_tmout_nsec > NSEC_PER_SEC) {
		pr_err("fusion_tmout_nsec[%u] is too large", fusion_tmout_nsec);
		return -EINVAL;
	}

	return param_set_int(val, kp);
}

static const struct kernel_param_ops fusion_tmout_nsec_ops = {
	.set = fusion_tmout_nsec_set,
	.get = param_get_int,
};

module_param_cb(pf_q_num, &pf_q_num_ops, &pf_q_num, 0444);
MODULE_PARM_DESC(pf_q_num, "Number of queues in PF(v1 0-4096, v2 0-1024)");

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param_cb(uacce_mode, &uacce_mode_ops, &uacce_mode, 0444);
MODULE_PARM_DESC(uacce_mode, "Mode of UACCE can be 0(default), 2");

static int ctx_q_num = CTX_Q_NUM_DEF;
module_param_cb(ctx_q_num, &ctx_q_num_ops, &ctx_q_num, 0444);
MODULE_PARM_DESC(ctx_q_num, "Number of queue in ctx (2, 4, 6, ..., 1024)");

static int fusion_limit = FUSION_LIMIT_DEF;
module_param_cb(fusion_limit, &fusion_limit_ops, &fusion_limit, 0444);
MODULE_PARM_DESC(fusion_limit, "(1, acc_sgl_sge_nr)");

static int fusion_tmout_nsec = FUSION_TMOUT_NSEC_DEF;
module_param_cb(fusion_tmout_nsec, &fusion_tmout_nsec_ops, &fusion_tmout_nsec,
	0444);
MODULE_PARM_DESC(fusion_tmout_nsec, "(0, NSEC_PER_SEC)");

static const struct pci_device_id hisi_sec_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, SEC_PCI_DEVICE_ID_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, SEC_PCI_DEVICE_ID_VF) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, hisi_sec_dev_ids);

static inline void hisi_sec_add_to_list(struct hisi_sec *hisi_sec)
{
	mutex_lock(&hisi_sec_list_lock);
	list_add_tail(&hisi_sec->list, &hisi_sec_list);
	mutex_unlock(&hisi_sec_list_lock);
}

static inline void hisi_sec_remove_from_list(struct hisi_sec *hisi_sec)
{
	mutex_lock(&hisi_sec_list_lock);
	list_del(&hisi_sec->list);
	mutex_unlock(&hisi_sec_list_lock);
}

u8 sec_get_endian(struct hisi_sec *hisi_sec)
{
	u32 reg;

	/*
	 * As for VF, it is a wrong way to get endian setting by
	 * reading a register of the engine
	 */
	if (hisi_sec->qm.pdev->is_virtfn) {
		dev_err_ratelimited(&hisi_sec->qm.pdev->dev,
			"error! shouldn't access a register in VF\n");
		return SEC_LE;
	}
	reg = readl_relaxed(hisi_sec->qm.io_base + SEC_ENGINE_PF_CFG_OFF +
			    SEC_ACC_COMMON_REG_OFF + SEC_CONTROL_REG);
	/* BD little endian mode */
	if (!(reg & BIT(0)))
		return SEC_LE;
	/* BD 32-bits big endian mode */
	else if (!(reg & BIT(1)))
		return SEC_32BE;
	/* BD 64-bits big endian mode */
	else
		return SEC_64BE;
}

static int sec_engine_init(struct hisi_sec *hisi_sec)
{
	int ret;
	u32 reg;
	struct hisi_qm *qm = &hisi_sec->qm;
	void *base = qm->io_base + SEC_ENGINE_PF_CFG_OFF +
		SEC_ACC_COMMON_REG_OFF;

	/* config sec single port max outstanding */
	writel(SEC_SINGLE_PORT_MAX_TRANS,
	       qm->io_base + SEC_AM_CFG_SIG_PORT_MAX_TRANS);

	/* config sec saa enable */
	writel(SEC_SAA_EN, base + SEC_SAA_EN_REG);

	/* disable clock gate control */
	reg = readl_relaxed(base + SEC_CONTROL_REG);
	reg &= SEC_CLK_GATE_DISABLE;
	writel(reg, base + SEC_CONTROL_REG);

	writel(0x1, base + SEC_MEM_START_INIT_REG);
	ret = readl_relaxed_poll_timeout(base +
					 SEC_MEM_INIT_DONE_REG, reg, reg & 0x1,
					 SEC_DELAY_10_US, SEC_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(&qm->pdev->dev, "fail to init sec mem\n");
		return ret;
	}

	reg = readl_relaxed(base + SEC_CONTROL_REG);
	reg |= (0x1 << SEC_TRNG_EN_SHIFT);
	writel(reg, base + SEC_CONTROL_REG);

	reg = readl_relaxed(base + SEC_INTERFACE_USER_CTRL0_REG);
	reg |= SEC_USER0_SMMU_NORMAL;
	writel(reg, base + SEC_INTERFACE_USER_CTRL0_REG);

	reg = readl_relaxed(base + SEC_INTERFACE_USER_CTRL1_REG);
	reg |= SEC_USER1_SMMU_NORMAL;
	writel(reg, base + SEC_INTERFACE_USER_CTRL1_REG);

	/* Enable sm4 extra mode, as ctr/ecb */
	writel(SEC_BD_ERR_CHK_EN0, base + SEC_BD_ERR_CHK_EN_REG0);
	/* Enable sm4 xts mode multiple iv */
	writel(SEC_BD_ERR_CHK_EN1, base + SEC_BD_ERR_CHK_EN_REG1);
	writel(SEC_BD_ERR_CHK_EN3, base + SEC_BD_ERR_CHK_EN_REG3);

	/* config endian */
	reg = readl_relaxed(base + SEC_CONTROL_REG);
	reg |= sec_get_endian(hisi_sec);
	writel(reg, base + SEC_CONTROL_REG);

	return 0;
}

static void hisi_sec_set_user_domain_and_cache(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	/* qm user domain */
	writel(AXUSER_BASE, qm->io_base + QM_ARUSER_M_CFG_1);
	writel(ARUSER_M_CFG_ENABLE, qm->io_base + QM_ARUSER_M_CFG_ENABLE);
	writel(AXUSER_BASE, qm->io_base + QM_AWUSER_M_CFG_1);
	writel(AWUSER_M_CFG_ENABLE, qm->io_base + QM_AWUSER_M_CFG_ENABLE);
	writel(WUSER_M_CFG_ENABLE, qm->io_base + QM_WUSER_M_CFG_ENABLE);

	/* qm cache */
	writel(AXI_M_CFG, qm->io_base + QM_AXI_M_CFG);
	writel(AXI_M_CFG_ENABLE, qm->io_base + QM_AXI_M_CFG_ENABLE);

	/* disable FLR triggered by BME(bus master enable) */
	writel(PEH_AXUSER_CFG, qm->io_base + QM_PEH_AXUSER_CFG);
	writel(PEH_AXUSER_CFG_ENABLE, qm->io_base +
	       QM_PEH_AXUSER_CFG_ENABLE);

	/* enable sqc,cqc writeback */
	writel(SQC_CACHE_ENABLE | CQC_CACHE_ENABLE | SQC_CACHE_WB_ENABLE |
	       CQC_CACHE_WB_ENABLE | FIELD_PREP(SQC_CACHE_WB_THRD, 1) |
	       FIELD_PREP(CQC_CACHE_WB_THRD, 1), qm->io_base + QM_CACHE_CTL);

	if (sec_engine_init(hisi_sec))
		dev_err(&qm->pdev->dev, "sec_engine_init failed");
}

static void hisi_sec_debug_regs_clear(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	/* clear current_qm */
	writel(0x0, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(0x0, qm->io_base + QM_DFX_DB_CNT_VF);

	/* clear rdclr_en */
	writel(0x0, qm->io_base + SEC_CTRL_CNT_CLR_CE);

	hisi_qm_debug_regs_clear(qm);
}

static void hisi_sec_hw_error_set_state(struct hisi_sec *hisi_sec, bool state)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	void *base = qm->io_base + SEC_ENGINE_PF_CFG_OFF +
		SEC_ACC_COMMON_REG_OFF;
	u32 val;

	if (qm->ver == QM_HW_V1) {
		writel(SEC_CORE_INT_DISABLE, qm->io_base + SEC_CORE_INT_MASK);
		dev_info(&qm->pdev->dev, "v%d don't support hw error handle\n",
			 qm->ver);
		return;
	}

	val = readl(base + SEC_CONTROL_REG);
	if (state) {
		/* clear SEC hw error source if having */
		writel(SEC_CORE_INT_ENABLE,
		       hisi_sec->qm.io_base + SEC_CORE_INT_SOURCE);

		/* enable SEC hw error interrupts */
		writel(SEC_CORE_INT_ENABLE, qm->io_base + SEC_CORE_INT_MASK);

		/* enable RAS int */
		writel(SEC_RAS_CE_ENB_MSK, base + SEC_RAS_CE_REG);
		writel(SEC_RAS_FE_ENB_MSK, base + SEC_RAS_FE_REG);
		writel(SEC_RAS_NFE_ENB_MSK, base + SEC_RAS_NFE_REG);

		/* enable SEC block master OOO when m-bit error occur */
		val = val | SEC_AXI_SHUTDOWN_ENABLE;
	} else {
		/* disable RAS int */
		writel(SEC_RAS_DISABLE, base + SEC_RAS_CE_REG);
		writel(SEC_RAS_DISABLE, base + SEC_RAS_FE_REG);
		writel(SEC_RAS_DISABLE, base + SEC_RAS_NFE_REG);

		/* disable SEC hw error interrupts */
		writel(SEC_CORE_INT_DISABLE, qm->io_base + SEC_CORE_INT_MASK);

		/* disable SEC block master OOO when m-bit error occur */
		val = val & SEC_AXI_SHUTDOWN_DISABLE;
	}

	writel(val, base + SEC_CONTROL_REG);
}

static inline struct hisi_qm *file_to_qm(struct ctrl_debug_file *file)
{
	struct hisi_sec *hisi_sec = file->ctrl->hisi_sec;

	return &hisi_sec->qm;
}

static u32 current_qm_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_DFX_MB_CNT_VF);
}

static int current_qm_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	struct hisi_sec_ctrl *ctrl = file->ctrl;
	u32 tmp, vfq_num;

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

	return 0;
}

static u32 clear_enable_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + SEC_CTRL_CNT_CLR_CE) &
	    SEC_CTRL_CNT_CLR_CE_BIT;
}

static int clear_enable_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val != 1 && val != 0)
		return -EINVAL;

	tmp = (readl(qm->io_base + SEC_CTRL_CNT_CLR_CE) &
	       ~SEC_CTRL_CNT_CLR_CE_BIT) | val;
	writel(tmp, qm->io_base + SEC_CTRL_CNT_CLR_CE);

	return 0;
}

static ssize_t ctrl_debug_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[SEC_DBGFS_VAL_MAX_LEN];
	u32 val;
	int ret;

	spin_lock_irq(&file->lock);
	switch (file->index) {
	case SEC_CURRENT_QM:
		val = current_qm_read(file);
		break;
	case SEC_CLEAR_ENABLE:
		val = clear_enable_read(file);
		break;
	default:
		spin_unlock_irq(&file->lock);
		return -EINVAL;
	}
	spin_unlock_irq(&file->lock);
	ret = snprintf(tbuf, SEC_DBGFS_VAL_MAX_LEN, "%u\n", val);
	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static ssize_t ctrl_debug_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct ctrl_debug_file *file = filp->private_data;
	char tbuf[SEC_DBGFS_VAL_MAX_LEN];
	unsigned long val;
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= SEC_DBGFS_VAL_MAX_LEN)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, SEC_DBGFS_VAL_MAX_LEN - 1,
		pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	spin_lock_irq(&file->lock);
	switch (file->index) {
	case SEC_CURRENT_QM:
		ret = current_qm_write(file, val);
		if (ret)
			goto err_input;
		break;
	case SEC_CLEAR_ENABLE:
		ret = clear_enable_write(file, val);
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

static int hisi_sec_core_debug_init(struct hisi_sec_ctrl *ctrl)
{
	struct hisi_sec *hisi_sec = ctrl->hisi_sec;
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &qm->pdev->dev;
	struct hisi_sec_dfx *dfx = &hisi_sec->sec_dfx;
	struct debugfs_regset32 *regset;
	struct dentry *tmp_d, *tmp;
	char buf[SEC_DBGFS_VAL_MAX_LEN];
	int ret;

	ret = snprintf(buf, SEC_DBGFS_VAL_MAX_LEN, "sec_dfx");
	if (ret < 0)
		return -ENOENT;

	tmp_d = debugfs_create_dir(buf, ctrl->debug_root);
	if (!tmp_d)
		return -ENOENT;

	regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
	if (!regset)
		return -ENOENT;

	regset->regs = sec_dfx_regs;
	regset->nregs = ARRAY_SIZE(sec_dfx_regs);
	regset->base = qm->io_base;

	tmp = debugfs_create_regset32("regs", 0444, tmp_d, regset);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("send_cnt", 0444, tmp_d, &dfx->send_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("send_by_tmout", 0444, tmp_d,
		&dfx->send_by_tmout);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("send_by_full", 0444, tmp_d,
		&dfx->send_by_full);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("recv_cnt", 0444, tmp_d, &dfx->recv_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("get_task_cnt", 0444, tmp_d,
		&dfx->get_task_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("put_task_cnt", 0444, tmp_d,
		&dfx->put_task_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("gran_task_cnt", 0444, tmp_d,
		&dfx->gran_task_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("thread_cnt", 0444, tmp_d, &dfx->thread_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("fake_busy_cnt", 0444,
		tmp_d, &dfx->fake_busy_cnt);
	if (!tmp)
		return -ENOENT;

	tmp = debugfs_create_u64("busy_comp_cnt", 0444, tmp_d,
		&dfx->busy_comp_cnt);
	if (!tmp)
		return -ENOENT;

	return 0;
}

static int hisi_sec_ctrl_debug_init(struct hisi_sec_ctrl *ctrl)
{
	struct dentry *tmp;
	int i;

	for (i = SEC_CURRENT_QM; i < SEC_DEBUG_FILE_NUM; i++) {
		spin_lock_init(&ctrl->files[i].lock);
		ctrl->files[i].ctrl = ctrl;
		ctrl->files[i].index = i;

		tmp = debugfs_create_file(ctrl_debug_file_name[i], 0600,
					  ctrl->debug_root, ctrl->files + i,
					  &ctrl_debug_fops);
		if (!tmp)
			return -ENOENT;
	}

	return hisi_sec_core_debug_init(ctrl);
}

static int hisi_sec_debugfs_init(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &qm->pdev->dev;
	struct dentry *dev_d;
	int ret;

	dev_d = debugfs_create_dir(dev_name(dev), sec_debugfs_root);
	if (!dev_d)
		return -ENOENT;

	qm->debug.debug_root = dev_d;
	ret = hisi_qm_debug_init(qm);
	if (ret)
		goto failed_to_create;

	if (qm->pdev->device == SEC_PCI_DEVICE_ID_PF) {
		hisi_sec->ctrl->debug_root = dev_d;
		ret = hisi_sec_ctrl_debug_init(hisi_sec->ctrl);
		if (ret)
			goto failed_to_create;
	}

	return 0;

 failed_to_create:
	debugfs_remove_recursive(sec_debugfs_root);
	return ret;
}

static void hisi_sec_debugfs_exit(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	debugfs_remove_recursive(qm->debug.debug_root);
	if (qm->fun_type == QM_HW_PF) {
		hisi_sec_debug_regs_clear(hisi_sec);
		qm->debug.curr_qm_qp_num = 0;
	}
}

static void hisi_sec_hw_error_init(struct hisi_sec *hisi_sec)
{
	hisi_qm_hw_error_init(&hisi_sec->qm, QM_BASE_CE,
			      QM_BASE_NFE | QM_ACC_DO_TASK_TIMEOUT
			      | QM_ACC_WB_NOT_READY_TIMEOUT, 0,
			      QM_DB_RANDOM_INVALID);
	hisi_sec_hw_error_set_state(hisi_sec, true);
}

static void hisi_sec_open_master_ooo(struct hisi_qm *qm)
{
	u32 val;
	void *base = qm->io_base + SEC_ENGINE_PF_CFG_OFF +
		     SEC_ACC_COMMON_REG_OFF;

	val = readl(base + SEC_CONTROL_REG);
	writel(val & SEC_AXI_SHUTDOWN_DISABLE, base + SEC_CONTROL_REG);
	writel(val | SEC_AXI_SHUTDOWN_ENABLE, base + SEC_CONTROL_REG);
}

static u32 hisi_sec_get_hw_err_status(struct hisi_qm *qm)
{
	return readl(qm->io_base + SEC_CORE_INT_STATUS);
}

static void hisi_sec_clear_hw_err_status(struct hisi_qm *qm, u32 err_sts)
{
	writel(err_sts, qm->io_base + SEC_CORE_INT_SOURCE);
}

static void hisi_sec_log_hw_error(struct hisi_qm *qm, u32 err_sts)
{
	const struct hisi_sec_hw_error *err = sec_hw_error;
	struct device *dev = &qm->pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts)
			dev_err(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);
		err++;
	}

	if (SEC_CORE_INT_STATUS_M_ECC & err_sts) {
		err_val = readl(qm->io_base + SEC_CORE_ECC_INFO);
		dev_err(dev, "hisi-sec multi ecc sram num=0x%x\n",
			SEC_ECC_NUM(err_val));
	}
}

static int hisi_sec_pf_probe_init(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	struct hisi_sec_ctrl *ctrl;

	ctrl = devm_kzalloc(&qm->pdev->dev, sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	hisi_sec->ctrl = ctrl;
	ctrl->hisi_sec = hisi_sec;

	switch (qm->ver) {
	case QM_HW_V1:
		qm->ctrl_q_num = SEC_QUEUE_NUM_V1;
		break;

	case QM_HW_V2:
		qm->ctrl_q_num = SEC_QUEUE_NUM_V2;
		break;

	default:
		return -EINVAL;
	}

	qm->err_ini.qm_wr_port = SEC_WR_MSI_PORT;
	qm->err_ini.ecc_2bits_mask = SEC_CORE_INT_STATUS_M_ECC;
	qm->err_ini.open_axi_master_ooo = hisi_sec_open_master_ooo;
	qm->err_ini.get_dev_hw_err_status = hisi_sec_get_hw_err_status;
	qm->err_ini.clear_dev_hw_err_status = hisi_sec_clear_hw_err_status;
	qm->err_ini.log_dev_hw_err = hisi_sec_log_hw_error;
	hisi_sec_set_user_domain_and_cache(hisi_sec);
	hisi_sec_hw_error_init(hisi_sec);
	qm->err_ini.open_axi_master_ooo(qm);
	hisi_sec_debug_regs_clear(hisi_sec);

	return 0;
}

static int hisi_sec_qm_init(struct hisi_qm *qm, struct pci_dev *pdev)
{
	enum qm_hw_ver rev_id;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id == QM_HW_UNKNOWN)
		return -ENODEV;

	qm->pdev = pdev;
	qm->ver = rev_id;

	qm->sqe_size = SEC_SQE_SIZE;
	qm->dev_name = sec_name;
	qm->fun_type = (pdev->device == SEC_PCI_DEVICE_ID_PF) ?
		QM_HW_PF : QM_HW_VF;
	qm->algs = "sec\ncipher\ndigest\n";
	qm->wq = sec_wq;

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

	return hisi_qm_init(qm);
}

static int hisi_sec_probe_init(struct hisi_qm *qm, struct hisi_sec *hisi_sec)
{
	if (qm->fun_type == QM_HW_PF) {
		qm->qp_base = SEC_PF_DEF_Q_BASE;
		qm->qp_num = pf_q_num;
		qm->debug.curr_qm_qp_num = pf_q_num;
		return hisi_sec_pf_probe_init(hisi_sec);
	} else if (qm->fun_type == QM_HW_VF) {
		/*
		 * have no way to get qm configure in VM in v1 hardware,
		 * so currently force PF to uses SEC_PF_DEF_Q_NUM, and force
		 * to trigger only one VF in v1 hardware.
		 *
		 * v2 hardware has no such problem.
		 */
		if (qm->ver == QM_HW_V1) {
			qm->qp_base = SEC_PF_DEF_Q_NUM;
			qm->qp_num = SEC_QUEUE_NUM_V1 - SEC_PF_DEF_Q_NUM;
		} else if (qm->ver == QM_HW_V2) {
			/* v2 starts to support get vft by mailbox */
			return hisi_qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
		}
	}

	return 0;
}

static int hisi_sec_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_sec *hisi_sec;
	struct hisi_qm *qm;
	int ret;

	hisi_sec = devm_kzalloc(&pdev->dev, sizeof(*hisi_sec), GFP_KERNEL);
	if (!hisi_sec)
		return -ENOMEM;

	pci_set_drvdata(pdev, hisi_sec);

	hisi_sec_add_to_list(hisi_sec);

	hisi_sec->hisi_sec_list_lock = &hisi_sec_list_lock;

	hisi_sec->ctx_q_num = ctx_q_num;
	hisi_sec->fusion_limit = fusion_limit;

	hisi_sec->fusion_tmout_nsec = fusion_tmout_nsec;

	qm = &hisi_sec->qm;

	ret = hisi_sec_qm_init(qm, pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to pre init qm!\n");
		goto err_remove_from_list;
	}

	ret = hisi_sec_probe_init(qm, hisi_sec);
	if (ret) {
		dev_err(&pdev->dev, "Failed to probe!\n");
		goto err_qm_uninit;
	}

	ret = hisi_qm_start(qm);
	if (ret)
		goto err_qm_uninit;

	ret = hisi_sec_debugfs_init(hisi_sec);
	if (ret)
		dev_err(&pdev->dev, "Failed to init debugfs (%d)!\n", ret);

	return 0;

 err_qm_uninit:
	hisi_qm_uninit(qm);
 err_remove_from_list:
	hisi_sec_remove_from_list(hisi_sec);
	return ret;
}

/* now we only support equal assignment */
static int hisi_sec_vf_q_assign(struct hisi_sec *hisi_sec, u32 num_vfs)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	u32 qp_num = qm->qp_num;
	u32 q_base = qp_num;
	u32 q_num, remain_q_num, i;
	int ret;

	if (!num_vfs)
		return -EINVAL;

	remain_q_num = qm->ctrl_q_num - qp_num;
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

static int hisi_sec_clear_vft_config(struct hisi_sec *hisi_sec)
{
	struct hisi_sec_ctrl *ctrl = hisi_sec->ctrl;
	struct hisi_qm *qm = &hisi_sec->qm;
	u32 num_vfs = ctrl->num_vfs;
	int ret;
	u32 i;

	for (i = 1; i <= num_vfs; i++) {
		ret = hisi_qm_set_vft(qm, i, 0, 0);
		if (ret)
			return ret;
	}

	ctrl->num_vfs = 0;

	return 0;
}

static int hisi_sec_sriov_enable(struct pci_dev *pdev, int max_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	u32 num_vfs;
	int pre_existing_vfs, ret;

	pre_existing_vfs = pci_num_vf(pdev);

	if (pre_existing_vfs) {
		dev_err(&pdev->dev,
			"Can't enable VF. Please disable pre-enabled VFs!\n");
		return 0;
	}

	num_vfs = min_t(u32, max_vfs, SEC_VF_NUM);

	ret = hisi_sec_vf_q_assign(hisi_sec, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't assign queues for VF!\n");
		return ret;
	}

	hisi_sec->ctrl->num_vfs = num_vfs;

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		dev_err(&pdev->dev, "Can't enable VF!\n");
		hisi_sec_clear_vft_config(hisi_sec);
		return ret;
	}

	return num_vfs;
#else
	return 0;
#endif
}

static int hisi_sec_try_frozen_vfs(struct pci_dev *pdev)
{
	struct hisi_sec *sec, *vf_sec;
	struct pci_dev *dev;
	int ret = 0;

	/* Try to frozen all the VFs as disable SRIOV */
	mutex_lock(&hisi_sec_list_lock);
	list_for_each_entry(sec, &hisi_sec_list, list) {
		dev = sec->qm.pdev;
		if (dev == pdev)
			continue;
		if (pci_physfn(dev) == pdev) {
			vf_sec = pci_get_drvdata(dev);
			ret = hisi_qm_frozen(&vf_sec->qm);
			if (ret)
				goto frozen_fail;
		}
	}

frozen_fail:
	mutex_unlock(&hisi_sec_list_lock);
	return ret;
}

static int hisi_sec_sriov_disable(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);

	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev,
			"Can't disable VFs while VFs are assigned!\n");
		return -EPERM;
	}

	if (hisi_sec_try_frozen_vfs(pdev)) {
		dev_err(&pdev->dev, "try frozen VFs failed!\n");
		return -EBUSY;
	}

	/* remove in hisi_sec_pci_driver will be called to free VF resources */
	pci_disable_sriov(pdev);
	return hisi_sec_clear_vft_config(hisi_sec);
}

static int hisi_sec_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return hisi_sec_sriov_disable(pdev);
	else
		return hisi_sec_sriov_enable(pdev, num_vfs);
}

static void hisi_sec_remove_wait_delay(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	while (hisi_qm_frozen(qm) || ((qm->fun_type == QM_HW_PF) &&
		hisi_sec_try_frozen_vfs(qm->pdev)))
		usleep_range(FROZEN_RANGE_MIN, FROZEN_RANGE_MAX);

	udelay(SEC_WAIT_DELAY);
}

static void hisi_sec_remove(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_sec->qm;

	if (uacce_mode != UACCE_MODE_NOUACCE)
		hisi_sec_remove_wait_delay(hisi_sec);

	if (qm->fun_type == QM_HW_PF && hisi_sec->ctrl->num_vfs != 0)
		(void)hisi_sec_sriov_disable(pdev);

	hisi_sec_debugfs_exit(hisi_sec);
	(void)hisi_qm_stop(qm, QM_NORMAL);

	if (qm->fun_type == QM_HW_PF)
		hisi_sec_hw_error_set_state(hisi_sec, false);

	hisi_qm_uninit(qm);
	hisi_sec_remove_from_list(hisi_sec);
}

static void hisi_sec_shutdown(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);

	hisi_qm_stop(&hisi_sec->qm, QM_NORMAL);
}

static pci_ers_result_t hisi_sec_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_NONE;

	dev_info(&pdev->dev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hisi_qm_process_dev_error(pdev);
}

static int hisi_sec_reset_prepare_ready(struct hisi_sec *hisi_sec)
{
	struct pci_dev *pdev = hisi_sec->qm.pdev;
	struct hisi_sec *sec = pci_get_drvdata(pci_physfn(pdev));
	int delay = 0;

	while (test_and_set_bit(HISI_SEC_RESET, &sec->status)) {
		msleep(++delay);
		if (delay > SEC_RESET_WAIT_TIMEOUT)
			return -EBUSY;
	}

	return 0;
}

static int hisi_sec_vf_reset_prepare(struct pci_dev *pdev,
				     enum qm_stop_reason stop_reason)
{
	struct hisi_sec *hisi_sec;
	struct pci_dev *dev;
	struct hisi_qm *qm;
	int ret = 0;

	mutex_lock(&hisi_sec_list_lock);
	if (pdev->is_physfn) {
		list_for_each_entry(hisi_sec, &hisi_sec_list, list) {
			dev = hisi_sec->qm.pdev;
			if (dev == pdev)
				continue;

			if (pci_physfn(dev) == pdev) {
				qm = &hisi_sec->qm;

				ret = hisi_qm_stop(qm, stop_reason);
				if (ret)
					goto prepare_fail;
			}
		}
	}

prepare_fail:
	mutex_unlock(&hisi_sec_list_lock);
	return ret;
}

static int hisi_sec_controller_reset_prepare(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = hisi_sec_reset_prepare_ready(hisi_sec);
	if (ret) {
		dev_err(&pdev->dev, "Controller reset not ready!\n");
		return ret;
	}

	ret = hisi_sec_vf_reset_prepare(pdev, QM_SOFT_RESET);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop VFs!\n");
		return ret;
	}

	ret = hisi_qm_stop(qm, QM_SOFT_RESET);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop QM!\n");
		return ret;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce) {
		ret = uacce_hw_err_isolate(&qm->uacce);
		if (ret) {
			dev_err(&pdev->dev, "Fails to isolate hw err!\n");
			return ret;
		}
	}
#endif

	return 0;
}

static int hisi_sec_soft_reset(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &qm->pdev->dev;
	unsigned long long value;
	int ret;
	u32 val;

	ret = hisi_qm_reg_test(qm);
	if (ret)
		return ret;

	ret = hisi_qm_set_vf_mse(qm, SEC_DISABLE);
	if (ret) {
		dev_err(dev, "Fails to disable vf mse bit.\n");
		return ret;
	}

	ret = hisi_qm_set_msi(qm, SEC_DISABLE);
	if (ret) {
		dev_err(dev, "Fails to disable peh msi bit.\n");
		return ret;
	}

	/* Set qm ecc if dev ecc happened to hold on ooo */
	hisi_qm_set_ecc(qm);

	/* OOO register set and check */
	writel(SEC_MASTER_GLOBAL_CTRL_SHUTDOWN,
	       hisi_sec->qm.io_base + SEC_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hisi_sec->qm.io_base +
					 SEC_MASTER_TRANS_RETURN,
					 val,
					 (val == SEC_MASTER_TRANS_RETURN_RW),
					 SEC_DELAY_10_US,
					 SEC_POLL_TIMEOUT_US);
	if (ret) {
		dev_emerg(dev, "Bus lock! Please reset system.\n");
		return ret;
	}

	ret = hisi_qm_set_pf_mse(qm, SEC_DISABLE);
	if (ret) {
		dev_err(dev, "Fails to disable pf mse bit.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(dev)) {
		acpi_status s;

		s = acpi_evaluate_integer(ACPI_HANDLE(dev), "SRST",
			NULL, &value);
		if (ACPI_FAILURE(s) || value) {
			dev_err(dev, "Controller reset fails %lld\n", value);
			return -EIO;
		}
	} else {
		dev_err(dev, "No reset method!\n");
		return -EINVAL;
	}

	return 0;
}

static int hisi_sec_vf_reset_done(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec;
	struct pci_dev *dev;
	struct hisi_qm *qm;
	int ret = 0;

	mutex_lock(&hisi_sec_list_lock);
	list_for_each_entry(hisi_sec, &hisi_sec_list, list) {
		dev = hisi_sec->qm.pdev;
		if (dev == pdev)
			continue;

		if (pci_physfn(dev) == pdev) {
			qm = &hisi_sec->qm;

			ret = hisi_qm_restart(qm);
			if (ret)
				goto reset_fail;
		}
	}

reset_fail:
	mutex_unlock(&hisi_sec_list_lock);
	return ret;
}

static int hisi_sec_controller_reset_done(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	int ret;

	ret = hisi_qm_set_msi(qm, SEC_ENABLE);
	if (ret) {
		dev_err(dev, "Fails to enable peh msi bit!\n");
		return ret;
	}

	ret = hisi_qm_set_pf_mse(qm, SEC_ENABLE);
	if (ret) {
		dev_err(dev, "Fails to enable pf mse bit!\n");
		return ret;
	}

	ret = hisi_qm_set_vf_mse(qm, SEC_ENABLE);
	if (ret) {
		dev_err(dev, "Fails to enable vf mse bit!\n");
		return ret;
	}

	hisi_sec_set_user_domain_and_cache(hisi_sec);
	hisi_qm_restart_prepare(qm);

	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(dev, "Failed to start QM!\n");
		return -EPERM;
	}

	if (hisi_sec->ctrl->num_vfs) {
		ret = hisi_sec_vf_q_assign(hisi_sec, hisi_sec->ctrl->num_vfs);
		if (ret) {
			dev_err(dev, "Failed to assign vf queues!\n");
			return ret;
		}
	}

	ret = hisi_sec_vf_reset_done(pdev);
	if (ret) {
		dev_err(dev, "Failed to start VFs!\n");
		return -EPERM;
	}

	hisi_qm_restart_done(qm);
	hisi_sec_hw_error_init(hisi_sec);

	return 0;
}

static int hisi_sec_controller_reset(struct hisi_sec *hisi_sec)
{
	struct device *dev = &hisi_sec->qm.pdev->dev;
	int ret;

	dev_info(dev, "Controller resetting...\n");

	ret = hisi_sec_controller_reset_prepare(hisi_sec);
	if (ret)
		return ret;

	ret = hisi_sec_soft_reset(hisi_sec);
	if (ret) {
		dev_err(dev, "Controller reset failed (%d)\n", ret);
		return ret;
	}

	ret = hisi_sec_controller_reset_done(hisi_sec);
	if (ret)
		return ret;

	clear_bit(HISI_SEC_RESET, &hisi_sec->status);
	dev_info(dev, "Controller reset complete\n");

	return 0;
}

static pci_ers_result_t hisi_sec_slot_reset(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	int ret;

	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_RECOVERED;

	dev_info(&pdev->dev, "Requesting reset due to PCI error\n");

	pci_cleanup_aer_uncorrect_error_status(pdev);

	/* reset sec controller */
	ret = hisi_sec_controller_reset(hisi_sec);
	if (ret) {
		dev_warn(&pdev->dev, "hisi_sec controller reset failed (%d)\n",
			 ret);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static void hisi_sec_set_hw_error(struct hisi_sec *hisi_sec, bool state)
{
	struct pci_dev *pdev = hisi_sec->qm.pdev;
	struct hisi_sec *sec = pci_get_drvdata(pci_physfn(pdev));
	struct hisi_qm *qm = &sec->qm;

	if (qm->fun_type == QM_HW_VF)
		return;

	if (state)
		hisi_qm_hw_error_init(qm, QM_BASE_CE,
				      QM_BASE_NFE | QM_ACC_WB_NOT_READY_TIMEOUT,
				      0, QM_DB_RANDOM_INVALID);
	else
		hisi_qm_hw_error_uninit(qm);

	hisi_sec_hw_error_set_state(sec, state);
}

static int hisi_sec_get_hw_error_status(struct hisi_sec *hisi_sec)
{
	u32 err_sts;

	err_sts = readl(hisi_sec->qm.io_base + SEC_CORE_INT_STATUS) &
			SEC_CORE_INT_STATUS_M_ECC;
	if (err_sts)
		return err_sts;

	return 0;
}

static int hisi_sec_check_hw_error(struct hisi_sec *hisi_sec)
{
	struct pci_dev *pdev = hisi_sec->qm.pdev;
	struct hisi_sec *sec = pci_get_drvdata(pci_physfn(pdev));
	struct hisi_qm *qm = &sec->qm;
	int ret;

	if (qm->fun_type == QM_HW_VF)
		return 0;

	ret = hisi_qm_get_hw_error_status(qm);
	if (ret)
		return ret;

	return hisi_sec_get_hw_error_status(sec);
}

static void hisi_sec_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &pdev->dev;
	u32 delay = 0;
	int ret;

	hisi_sec_set_hw_error(hisi_sec, SEC_HW_ERROR_IRQ_DISABLE);

	while (hisi_sec_check_hw_error(hisi_sec)) {
		msleep(++delay);
		if (delay > SEC_RESET_WAIT_TIMEOUT)
			return;
	}

	ret = hisi_sec_reset_prepare_ready(hisi_sec);
	if (ret) {
		dev_err(dev, "FLR not ready!\n");
		return;
	}

	ret = hisi_sec_vf_reset_prepare(pdev, QM_FLR);
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

static void hisi_sec_flr_reset_complete(struct pci_dev *pdev)
{
	struct pci_dev *pf_pdev = pci_physfn(pdev);
	struct hisi_sec *hisi_sec = pci_get_drvdata(pf_pdev);
	struct device *dev = &hisi_sec->qm.pdev->dev;
	u32 id;

	pci_read_config_dword(hisi_sec->qm.pdev, PCI_COMMAND, &id);
	if (id == SEC_PCI_COMMAND_INVALID)
		dev_err(dev, "Device can not be used!\n");

	clear_bit(HISI_SEC_RESET, &hisi_sec->status);
}

static void hisi_sec_reset_done(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &pdev->dev;
	int ret;

	hisi_sec_set_hw_error(hisi_sec, SEC_HW_ERROR_IRQ_ENABLE);

	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(dev, "Failed to start QM!\n");
		goto flr_done;
	}

	if (pdev->is_physfn) {
		hisi_sec_set_user_domain_and_cache(hisi_sec);
		if (hisi_sec->ctrl->num_vfs) {
			ret = hisi_sec_vf_q_assign(hisi_sec,
				hisi_sec->ctrl->num_vfs);
			if (ret) {
				dev_err(dev, "Failed to assign vf queue\n");
				goto flr_done;
			}
		}

		ret = hisi_sec_vf_reset_done(pdev);
		if (ret) {
			dev_err(dev, "Failed to reset vf\n");
			goto flr_done;
		}
	}

flr_done:
	hisi_sec_flr_reset_complete(pdev);

	dev_info(dev, "FLR reset complete\n");
}

static const struct pci_error_handlers hisi_sec_err_handler = {
	.error_detected = hisi_sec_error_detected,
	.slot_reset = hisi_sec_slot_reset,
	.reset_prepare = hisi_sec_reset_prepare,
	.reset_done = hisi_sec_reset_done,
};

static struct pci_driver hisi_sec_pci_driver = {
	.name = "hisi_sec2",
	.id_table = hisi_sec_dev_ids,
	.probe = hisi_sec_probe,
	.remove = hisi_sec_remove,
	.sriov_configure = hisi_sec_sriov_configure,
	.err_handler = &hisi_sec_err_handler,
	.shutdown = hisi_sec_shutdown,
};

static void hisi_sec_register_debugfs(void)
{
	if (!debugfs_initialized())
		return;

	sec_debugfs_root = debugfs_create_dir("hisi_sec2", NULL);
	if (IS_ERR_OR_NULL(sec_debugfs_root))
		sec_debugfs_root = NULL;
}

static void hisi_sec_unregister_debugfs(void)
{
	debugfs_remove_recursive(sec_debugfs_root);
}

static int __init hisi_sec_init(void)
{
	int ret;

	sec_wq = alloc_workqueue("hisi_sec2", WQ_HIGHPRI | WQ_CPU_INTENSIVE |
		WQ_MEM_RECLAIM | WQ_UNBOUND, num_online_cpus());

	if (!sec_wq) {
		pr_err("Fallied to alloc workqueue\n");
		return -ENOMEM;
	}

	hisi_sec_register_debugfs();

	ret = pci_register_driver(&hisi_sec_pci_driver);
	if (ret < 0) {
		pr_err("Failed to register pci driver.\n");
		goto err_pci;
	}

	pr_info("hisi_sec: register to crypto\n");
	ret = hisi_sec_register_to_crypto(fusion_limit);
	if (ret < 0) {
		pr_err("Failed to register driver to crypto.\n");
		goto err_probe_device;
	}

	return 0;

 err_probe_device:
	pci_unregister_driver(&hisi_sec_pci_driver);
 err_pci:
	hisi_sec_unregister_debugfs();
	if (sec_wq)
		destroy_workqueue(sec_wq);
	return ret;
}

static void __exit hisi_sec_exit(void)
{
	hisi_sec_unregister_from_crypto(fusion_limit);
	pci_unregister_driver(&hisi_sec_pci_driver);
	hisi_sec_unregister_debugfs();
	if (sec_wq)
		destroy_workqueue(sec_wq);
}

module_init(hisi_sec_init);
module_exit(hisi_sec_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhang Wei <zhangwei375@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon SEC accelerator");
