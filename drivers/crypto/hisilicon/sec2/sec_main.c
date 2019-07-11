// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2018-2019 HiSilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
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

#define HSEC_VF_NUM			63
#define HSEC_QUEUE_NUM_V1		4096
#define HSEC_QUEUE_NUM_V2		1024
#define PCI_DEVICE_ID_SEC_PF    0xa255
#define PCI_DEVICE_ID_SEC_VF    0xa256

#define HSEC_COMMON_REG_OFF	0x1000

#define HSEC_FSM_MAX_CNT		0x301008

#define HSEC_PORT_ARCA_CHE_0		0x301040
#define HSEC_PORT_ARCA_CHE_1		0x301044
#define HSEC_PORT_AWCA_CHE_0		0x301060
#define HSEC_PORT_AWCA_CHE_1		0x301064

#define HSEC_BD_RUSER_32_63		0x301110
#define HSEC_SGL_RUSER_32_63		0x30111c
#define HSEC_DATA_RUSER_32_63		0x301128
#define HSEC_DATA_WUSER_32_63		0x301134
#define HSEC_BD_WUSER_32_63		0x301140

#define HSEC_QM_IDEL_STATUS		0x3040e4
#define HSEC_MASTER_GLOBAL_CTRL		0x300000
#define MASTER_GLOBAL_CTRL_SHUTDOWN	0x1
#define HSEC_MASTER_TRANS_RETURN	0x300150
#define MASTER_TRANS_RETURN_RW		0x3

#define HSEC_CORE_INT_SOURCE		0x301010
#define HSEC_CORE_INT_MASK		    0x301000
#define HSEC_CORE_INT_STATUS		0x301008
#define HSEC_CORE_INT_STATUS_M_ECC	BIT(1)
#define HSEC_CORE_SRAM_ECC_ERR_INFO	0x301148
#define SRAM_ECC_ERR_NUM_SHIFT		16
#define SRAM_ECC_ERR_ADDR_SHIFT		24
#define HSEC_CORE_INT_DISABLE		0x000001FF

#define HSEC_SM4_CTR_ENABLE_REG     0X301380
#define HSEC_SM4_CTR_ENABLE_MSK     0XEFFFFFFF
#define HSEC_SM4_CTR_DISABLE_MSK     0XFFFFFFFF

#define HSEC_SQE_SIZE			128
#define HSEC_SQ_SIZE			(HSEC_SQE_SIZE * QM_Q_DEPTH)
#define HSEC_PF_DEF_Q_NUM		64
#define HSEC_PF_DEF_Q_BASE		0

#define HSEC_SOFT_CTRL_CNT_CLR_CE	0x301000
#define SOFT_CTRL_CNT_CLR_CE_BIT	BIT(0)

#define AM_CURR_ALL_RET_MASK	GENMASK(1, 0)

#define SC_SEC_ICG_EN_REG	0x390
#define SC_SEC_ICG_DIS_REG	0x394
#define SC_SEC_RESET_REQ_REG	0xA28
#define SC_SEC_RESET_DREQ_REG	0xA2C
#define SC_SEC_ICG_ST_REG	0x5390
#define SC_SEC_RESET_ST_REG	0x5A28

#define SEC_RESET_MASK	GENMASK(1, 0)

#define SEC_ENGINE_PF_CFG_OFF 0x300000
#define SEC_ACC_COMMON_REG_OFF	0x1000

#define SEC_PF_ABNORMAL_INT_ENABLE_REG	0x000
#define SEC_PF_INT_MSK	0x1ff
#define SEC_PF_ABNORMAL_INT_STATUS_REG	0x0008
#define SEC_PF_ABNORMAL_INT_SOURCE_REG	0x0010
#define SEC_PF_ABNORMAL_INT_SET_REG	0x0018
#define SEC_RAS_CE_INT_COUNT_REG	0x0030
#define SEC_RAS_INT_WIDTH_PLUS_REG	0x0034
#define SEC_RAS_CE_ENABLE_REG		0x50
#define SEC_RAS_FE_ENABLE_REG		0x54
#define SEC_RAS_NFE_ENABLE_REG	0x58
#define SEC_RAS_CE_ENB_MSK			0x88
#define SEC_RAS_FE_ENB_MSK			0x0
#define SEC_RAS_NFE_ENB_MSK		0x177
#define SEC_MEM_START_INIT_REG	0x0100
#define SEC_MEM_INIT_DONE_REG	0x0104
#define SEC_MEM_TIMING_REG	0x0108
#define SEC_ECC_ENABLE_REG	0x010c
#define SEC_CNT_CLR_CE_REG	0x0120
#define SEC_FSM_MAX_CNT_REG	0x0124
#define SEC_SGL_OFFSET_CONTROL_REG	0x0130
#define SEC_PAGE_SIZE_CONTROL_REG	0x0134
#define SEC_DIF_CRC_INIT_REG	0x0138

#define SEC_CONTROL_REG	0x0200
#define SEC_TRNG_EN_SHIFT	8

#define SEC_AXI_CACHE_CFG_REG	0x0210
#define SEC_AXI_CACHE_CFG_1_REG	0x0214
#define SEC_SNPATTR_CFG_REG	0x0218
#define SEC_INTERFACE_USER_CTRL0_REG	0x0220
#define SEC_INTERFACE_USER_CTRL1_REG	0x0224
#define SEC_BD_CS_PACKET_OST_CFG_REG	0x0240
#define SEC_DATA_OST_CFG_REG	0x0248
#define SEC_SAA_CLK_EN_REG	0x0260
#define SEC_SAA_EN_REG	0x0270
#define SEC_REQ_TRNG_TIME_TH_REG	0x0280
#define SEC_BD_ERR_CHK_EN_REG(n)	(0x0380 + (n) * 0x04)

#define BD_LATENCY_MIN_REG	0x0600
#define BD_LATENCY_MAX_REG	0x0608
#define BD_LATENCY_AVG_REG	0x060C
#define BD_NUM_IN_SAA_0_REG	0x0670
#define BD_NUM_IN_SAA_1_REG	0x0674
#define BD_NUM_IN_SEC_REG		0x0680

#define SEC_PF_FSM_HBEAT_INFO_REG(n)	(0x20 + (n) * 0x4)
#define SEC_FSM_USE_REG_NUM	2
#define SEC_BD_M_FSM_REG		0x700
#define SEC_KEY_FSM_REG			0x704
#define SEC_IV_FSM_REG			0x708
#define SEC_IV_KEY_FSM_REG		0x70c
#define SEC_CLU_ALG_FSM_REG	0x710
#define SEC_RD_SGE_FSM_REG	0x72c
#define SEC_RD_HAC_SGE_FSM_REG(n)	(0x730 + (n) * 0x4)
#define SEC_AW_HAC_FSM_REG(n)	(0x750 + (n) * 0x4)
#define SEC_SGE_CBB_NUM		3
#define SEC_DIF_SHAPE_REG(n)	(0x760 + (n) * 0x4)
#define SEC_CHANNEL_NUM		9
#define SEC_BD_TOP_FSM_REG	0x7A0

#define SEC_ECC_1BIT_CNT_REG	0xC00
#define SEC_ECC_1BIT_INFO_REG	0xC04
#define SEC_ECC_2BIT_CNT_REG	0xC10
#define SEC_ECC_2BIT_INFO_REG	0xC14

#define SEC_USER0_SMMU_NORMAL	(BIT(23) | BIT(15))
#define SEC_USER1_SMMU_NORMAL	(BIT(31) | BIT(23) | BIT(15) | BIT(7))

#define BD_CIPHER_SHIFT	4
#define BD_AUTH_SHIFT	6
#define BD_SCENE_SHIFT	11
#define BD_A_ALG_SHIFT	11
#define BD_AKEY_LEN_SHIFT	5
#define BD_C_WIDTH_SHIFT	6
#define BD_CKEY_LEN_SHIFT	9
#define BD_C_MODE_SHIFT	12
#define BD_C_ALG_SHIFT	16
#define BD_CIPHER_SRC_OFFSET_SHIFT	16

#define BD_DK_LEN_SHIFT	16

#define BD_PAGE_PAD_TYPE_SHIFT	4
#define BD_CHK_GRD_CTRL_SHIFT	8
#define BD_CHK_REF_CTRL_SHIFT	12
#define BD_BLOCK_SIZE_SHIFT	16

#define BD_TAG_MASK	GENMASK(15, 0)
#define BD_TYPE_MASK	GENMASK(3, 0)

#define BD_ICV_MASK	GENMASK(3, 1)
#define BD_ICV_SHIFT	1
#define BD_ICV_CHECK_FAIL	0x2
#define BD_ICV_ERROR	0x3

#define BD_CSC_MASK	GENMASK(6, 4)
#define BD_CSC_SHIFT	4
#define BD_CSC_CHECK_FAIL	0x2

#define BD_FLAG_MASK	GENMASK(10, 7)
#define BD_FLAG_SHIFT	7

#define BD_DC_MASK	GENMASK(13, 11)
#define BD_DC_SHIFT	11
#define BD_DC_FAIL	0x2

#define BD_ERROR_TYPE_MASK	GENMASK(23, 16)
#define BD_ERROR_TYPE_SHIFT	16

#define BD_WARNING_TYPE_MASK	GENMASK(31, 24)
#define BD_WARNING_TYPE_SHIFT	24

#define SEC_NO_SCENE	0x0
#define SEC_IPSEC_SCENE	0x1
#define SEC_BASEBAND_SCENE	0x2
#define SEC_SSLTLS_SCENE	0x3
#define SEC_DTLS_SCENE	0x4
#define SEC_STORAGE_ACCESS_DISK_SCENE	0x5
#define SEC_STORAGE_NAS_SCENE	0x6
#define SEC_STREAM_DATA_SCENE	0x7
#define SEC_PBKDF2_SCENE	0x8
#define SEC_SMB_SCENE	0x9

#define C_ALG_DES	0x0
#define C_ALG_3DES	0x1
#define C_ALG_AES	0x2
#define C_ALG_SM4	0x3

#define C_MODE_ECB	0x0
#define C_MODE_CBC	0x1
#define C_MODE_CTR	0x4
#define C_MODE_CCM	0x5
#define C_MODE_GCM	0x6
#define C_MODE_XTS	0x7
#define C_MODE_CBC_CS	0x9

#define CKEY_LEN_128_BIT	0x0
#define CKEY_LEN_192_BIT	0x1
#define CKEY_LEN_256_BIT	0x2

#define C_ICV_LEN_16_BYTE	0x10

#define C_WIDTH_CS1	0x1
#define C_WIDTH_CS2	0x2
#define C_WIDTH_CS3	0x3

#define A_ALG_HMAC_SHA1	0x10
#define A_ALG_HMAC_SHA256	0x11
#define A_ALG_AES_CMAC	0x21
#define A_ALG_AES_GMAC	0x22

#define AKEY_LEN_128_BIT	0x4

#define MAC_LEN_96_BIT	0x3
#define MAC_LEN_128_BIT	0x4
#define MAC_LEN_256_BIT	0x8

#define SEC_DELAY_10_US   10
#define SEC_POLL_TIMEOUT_US   1000	/* 1ms */

#define SEC_CHAIN_ABN_RD_ADDR_LOW 0x300
#define SEC_CHAIN_ABN_RD_ADDR_HIG 0x304
#define SEC_CHAIN_ABN_RD_LEN 0x308
#define SEC_CHAIN_ABN_WR_ADDR_LOW 0x310
#define SEC_CHAIN_ABN_WR_ADDR_HIG 0x314
#define SEC_CHAIN_ABN_WR_LEN 0x318

#define SEC_CHAIN_ABN_LEN 128UL
#define FORMAT_DECIMAL			10

static const char hisi_sec_name[] = "hisi_sec";
static struct dentry *hsec_debugfs_root;
LIST_HEAD(hisi_sec_list);
DEFINE_MUTEX(hisi_sec_list_lock);

struct hisi_sec *find_sec_device(int node)
{
	struct hisi_sec *ret = NULL;
#ifdef CONFIG_NUMA
	struct hisi_sec *hisi_sec;
	int min_distance = 100;
	struct device *dev;

	mutex_lock(&hisi_sec_list_lock);

	list_for_each_entry(hisi_sec, &hisi_sec_list, list) {
		dev = &hisi_sec->qm.pdev->dev;
		if (node_distance(dev->numa_node, node) < min_distance) {
			ret = hisi_sec;
			min_distance = node_distance(dev->numa_node, node);
		}
	}
#else
	mutex_lock(&hisi_sec_list_lock);

	ret = list_first_entry(&hisi_sec_list, struct hisi_sec, list);
#endif
	mutex_unlock(&hisi_sec_list_lock);

	return ret;
}

struct hisi_sec_hw_error {
	u32 int_msk;
	const char *msg;
};

static const struct hisi_sec_hw_error sec_hw_error[] = {
	{.int_msk = BIT(0), .msg = "sec_ecc_1bitt_err"},
	{.int_msk = BIT(1), .msg = "sec_ecc_2bit_err"},
	{.int_msk = BIT(2), .msg = "sec_axi_rresp_err"},
	{.int_msk = BIT(3), .msg = "sec_axi_bresp_err"},
	{.int_msk = BIT(4), .msg = "sec_src_addr_parse_err"},
	{.int_msk = BIT(5), .msg = "sec_dst_addr_parse_err"},
	{.int_msk = BIT(6), .msg = "sec_pre_in_addr_err"},
	{.int_msk = BIT(7), .msg = "sec_pre_in_data_err"},
	{.int_msk = BIT(8), .msg = "sec_com_inf_err"},
	{.int_msk = BIT(9), .msg = "sec_enc_inf_err"},
	{.int_msk = BIT(10), .msg = "sec_pre_out_err"},
	{ /* sentinel */ }
};

enum ctrl_debug_file_index {
	HSEC_CURRENT_QM,
	HSEC_CLEAR_ENABLE,
	HSEC_DEBUG_FILE_NUM,
};

static const char *const ctrl_debug_file_name[] = {
	[HSEC_CURRENT_QM] = "current_qm",
	[HSEC_CLEAR_ENABLE] = "clear_enable",
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
	u32 ctrl_q_num;
	u32 num_vfs;
	struct hisi_sec *hisi_sec;
	struct dentry *debug_root;
	struct ctrl_debug_file files[HSEC_DEBUG_FILE_NUM];
};

static struct debugfs_reg32 hsec_dfx_regs[] = {
	{"SEC_PF_ABNORMAL_INT_SOURCE     ",  0x301010},
	{"HSEC_BD_LATENCY_MIN            ",  0x301600},
	{"HSEC_BD_LATENCY_MAX            ",  0x301608},
	{"HSEC_BD_LATENCY_AVG            ",  0x30160C},
	{"HSEC_BD_NUM_IN_SAA0            ",  0x301670},
	{"HSEC_BD_NUM_IN_SAA1            ",  0x301674},
	{"HSEC_BD_NUM_IN_SEC             ",  0x301680},
	{"HSEC_ECC_1BIT_CNT              ",  0x301C00},
	{"HSEC_ECC_1BIT_INFO             ",  0x301C04},
	{"HSEC_ECC_2BIT_CNT              ",  0x301C10},
	{"HSEC_ECC_2BIT_INFO             ",  0x301C14},
	{"HSEC_BD_SAA0                   ",  0x301C20},
	{"HSEC_BD_SAA1                   ",  0x301C24},
	{"HSEC_BD_SAA2                   ",  0x301C28},
	{"HSEC_BD_SAA3                   ",  0x301C2C},
	{"HSEC_BD_SAA4                   ",  0x301C30},
	{"HSEC_BD_SAA5                   ",  0x301C34},
	{"HSEC_BD_SAA6                   ",  0x301C38},
	{"HSEC_BD_SAA7                   ",  0x301C3C},
	{"HSEC_BD_SAA8                   ",  0x301C40},
};

static int pf_q_num_set(const char *val, const struct kernel_param *kp)
{
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI,
						  PCI_DEVICE_ID_SEC_PF, NULL);
	u32 n, q_num;
	u8 rev_id;
	int ret;

	if (!val)
		return -EINVAL;

	if (unlikely(!pdev)) {
		q_num = min_t(u32, HSEC_QUEUE_NUM_V1, HSEC_QUEUE_NUM_V2);
		pr_info
		    ("No device found currently, suppose queue number is %d\n",
		     q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case QM_HW_VER1_ID:
			q_num = HSEC_QUEUE_NUM_V1;
			break;
		case QM_HW_VER2_ID:
			q_num = HSEC_QUEUE_NUM_V2;
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
	if (ret != 0 || n > UACCE_MODE_NOIOMMU)
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops uacce_mode_ops = {
	.set = uacce_mode_set,
	.get = param_get_int,
};

static u32 pf_q_num = HSEC_PF_DEF_Q_NUM;
module_param_cb(pf_q_num, &pf_q_num_ops, &pf_q_num, 0444);
MODULE_PARM_DESC(pf_q_num, "Number of queues in PF(v1 0-4096, v2 0-1024)");

static int uacce_mode = UACCE_MODE_NOUACCE;
module_param_cb(uacce_mode, &uacce_mode_ops, &uacce_mode, 0444);
MODULE_PARM_DESC(uacce_mode, "Mode of UACCE can be 0(default), 1, 2");

static int enable_sm4_ctr;
module_param(enable_sm4_ctr, int, 0444);

static int ctx_q_num = 64;
module_param(ctx_q_num, int, 0444);

static const struct pci_device_id hisi_sec_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_SEC_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_SEC_VF) },
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
				    "error! shouldn't access a register of the engine in a VF\n");
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

	writel_relaxed(0x1, base + SEC_MEM_START_INIT_REG);
	ret = readl_relaxed_poll_timeout(base +
					 SEC_MEM_INIT_DONE_REG, reg, reg & 0x1,
					 SEC_DELAY_10_US, SEC_POLL_TIMEOUT_US);
	if (ret) {
		dev_err(&qm->pdev->dev, "fail to init sec mem\n");
		return ret;
	}

	reg = readl_relaxed(base + SEC_CONTROL_REG);
	reg |= (0x1 << SEC_TRNG_EN_SHIFT);
	writel_relaxed(reg, base + SEC_CONTROL_REG);

	reg = readl_relaxed(base + SEC_INTERFACE_USER_CTRL0_REG);
	reg |= SEC_USER0_SMMU_NORMAL;
	writel_relaxed(reg, base + SEC_INTERFACE_USER_CTRL0_REG);

	reg = readl_relaxed(base + SEC_INTERFACE_USER_CTRL1_REG);
	reg |= SEC_USER1_SMMU_NORMAL;
	writel_relaxed(reg, base + SEC_INTERFACE_USER_CTRL1_REG);

	writel_relaxed(0xfffff7fd, base + SEC_BD_ERR_CHK_EN_REG(1));
	writel_relaxed(0xffffbfff, base + SEC_BD_ERR_CHK_EN_REG(3));

	/* enable abnormal int */
	writel_relaxed(SEC_PF_INT_MSK, base + SEC_PF_ABNORMAL_INT_ENABLE_REG);
	writel_relaxed(SEC_RAS_CE_ENB_MSK, base + SEC_RAS_CE_ENABLE_REG);
	writel_relaxed(SEC_RAS_FE_ENB_MSK, base + SEC_RAS_FE_ENABLE_REG);
	writel_relaxed(SEC_RAS_NFE_ENB_MSK, base + SEC_RAS_NFE_ENABLE_REG);

	/* enable clock gate control */
	reg = readl_relaxed(base + SEC_CONTROL_REG);
	reg |= BIT(3);
	writel_relaxed(reg, base + SEC_CONTROL_REG);

	/*config endian */
	reg = readl_relaxed(base + SEC_CONTROL_REG);
	reg |= sec_get_endian(hisi_sec);
	writel_relaxed(reg, base + SEC_CONTROL_REG);

	if (enable_sm4_ctr)
		writel_relaxed(HSEC_SM4_CTR_ENABLE_MSK,
			qm->io_base + HSEC_SM4_CTR_ENABLE_REG);

	return 0;
}

static void hisi_sec_disable_sm4_ctr(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	if (enable_sm4_ctr)
		writel_relaxed(HSEC_SM4_CTR_DISABLE_MSK,
			qm->io_base + HSEC_SM4_CTR_ENABLE_REG);
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
	writel(PEH_AXUSER_CFG_ENABLE, qm->io_base + QM_PEH_AXUSER_CFG_ENABLE);

	/* enable sqc,cqc writeback */
	writel(SQC_CACHE_ENABLE | CQC_CACHE_ENABLE | SQC_CACHE_WB_ENABLE |
	       CQC_CACHE_WB_ENABLE | FIELD_PREP(SQC_CACHE_WB_THRD, 1) |
	       FIELD_PREP(CQC_CACHE_WB_THRD, 1), qm->io_base + QM_CACHE_CTL);

	if (sec_engine_init(hisi_sec))
		dev_err(&qm->pdev->dev, "sec_engine_init failed");
}

static void hisi_sec_hw_error_set_state(struct hisi_sec *hisi_sec, bool state)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	if (qm->ver == QM_HW_V1) {
		writel(HSEC_CORE_INT_DISABLE, qm->io_base + HSEC_CORE_INT_MASK);
		dev_info(&qm->pdev->dev, "SEC v%d does not support hw error handle\n",
			 qm->ver);
		return;
	}


	if (state) {
		/* enable SEC hw error interrupts */
		writel(0, hisi_sec->qm.io_base + HSEC_CORE_INT_MASK);
	} else {
		/* disable SEC hw error interrupts */
		writel(HSEC_CORE_INT_DISABLE,
		       hisi_sec->qm.io_base + HSEC_CORE_INT_MASK);
	}
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
	u32 tmp;

	if (val > ctrl->num_vfs)
		return -EINVAL;

	writel(val, qm->io_base + QM_DFX_MB_CNT_VF);
	writel(val, qm->io_base + QM_DFX_DB_CNT_VF);

	tmp = val |
	      (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & QM_VF_CNT_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);

	tmp = val |
	      (readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & QM_VF_CNT_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return 0;
}

static u32 clear_enable_read(struct ctrl_debug_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + HSEC_SOFT_CTRL_CNT_CLR_CE) &
	    SOFT_CTRL_CNT_CLR_CE_BIT;
}

static int clear_enable_write(struct ctrl_debug_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val != 1 && val != 0)
		return -EINVAL;

	tmp = (readl(qm->io_base + HSEC_SOFT_CTRL_CNT_CLR_CE) &
	       ~SOFT_CTRL_CNT_CLR_CE_BIT) | val;
	writel(tmp, qm->io_base + HSEC_SOFT_CTRL_CNT_CLR_CE);

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
	case HSEC_CURRENT_QM:
		val = current_qm_read(file);
		break;
	case HSEC_CLEAR_ENABLE:
		val = clear_enable_read(file);
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

	if (count >= 20)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, 20 - 1, pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	spin_lock_irq(&file->lock);
	switch (file->index) {
	case HSEC_CURRENT_QM:
		ret = current_qm_write(file, val);
		if (ret)
			goto err_input;
		break;
	case HSEC_CLEAR_ENABLE:
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
	struct debugfs_regset32 *regset;
	struct dentry *tmp_d, *tmp;
	char buf[20];

	sprintf(buf, "hisi_sec_dfx");

	tmp_d = debugfs_create_dir(buf, ctrl->debug_root);
	if (!tmp_d)
		return -ENOENT;

	regset = devm_kzalloc(dev, sizeof(*regset), GFP_KERNEL);
	if (!regset)
		return -ENOENT;

	regset->regs = hsec_dfx_regs;
	regset->nregs = ARRAY_SIZE(hsec_dfx_regs);
	regset->base = qm->io_base;

	tmp = debugfs_create_regset32("regs", 0444, tmp_d, regset);
	if (!tmp)
		return -ENOENT;

	return 0;
}

static int hisi_sec_ctrl_debug_init(struct hisi_sec_ctrl *ctrl)
{
	struct dentry *tmp;
	int i;

	for (i = HSEC_CURRENT_QM; i < HSEC_DEBUG_FILE_NUM; i++) {
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

	dev_d = debugfs_create_dir(dev_name(dev), hsec_debugfs_root);
	if (!dev_d)
		return -ENOENT;

	qm->debug.debug_root = dev_d;
	ret = hisi_qm_debug_init(qm);
	if (ret)
		goto failed_to_create;

	if (qm->pdev->device == PCI_DEVICE_ID_SEC_PF) {
		hisi_sec->ctrl->debug_root = dev_d;
		ret = hisi_sec_ctrl_debug_init(hisi_sec->ctrl);
		if (ret)
			goto failed_to_create;
	}

	return 0;

 failed_to_create:
	debugfs_remove_recursive(hsec_debugfs_root);
	return ret;
}

static void hisi_sec_debugfs_exit(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;

	debugfs_remove_recursive(qm->debug.debug_root);
}

static void hisi_sec_hw_error_init(struct hisi_sec *hisi_sec)
{
	hisi_qm_hw_error_init(&hisi_sec->qm, QM_BASE_CE,
			      QM_BASE_NFE | QM_ACC_WB_NOT_READY_TIMEOUT, 0,
			      QM_DB_RANDOM_INVALID);
	hisi_sec_hw_error_set_state(hisi_sec, true);
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
		qm->ctrl_q_num = HSEC_QUEUE_NUM_V1;
		break;

	case QM_HW_V2:
		qm->ctrl_q_num = HSEC_QUEUE_NUM_V2;
		break;

	default:
		return -EINVAL;
	}

	hisi_sec_set_user_domain_and_cache(hisi_sec);
	hisi_sec_hw_error_init(hisi_sec);

	return 0;
}

static int hisi_sec_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_sec *hisi_sec;
	enum qm_hw_ver rev_id;
	struct hisi_qm *qm;
	int ret;

	rev_id = hisi_qm_get_hw_version(pdev);
	if (rev_id == QM_HW_UNKNOWN)
		return -EINVAL;

	hisi_sec = devm_kzalloc(&pdev->dev, sizeof(*hisi_sec), GFP_KERNEL);
	if (!hisi_sec)
		return -ENOMEM;

	pci_set_drvdata(pdev, hisi_sec);

	hisi_sec_add_to_list(hisi_sec);

	hisi_sec->sgl_pool = acc_create_sgl_pool(&pdev->dev, "hsec-sgl");
	if (!hisi_sec->sgl_pool)
		return -ENOMEM;

	hisi_sec->ctx_q_num = ctx_q_num;

	qm = &hisi_sec->qm;
	qm->pdev = pdev;
	qm->ver = rev_id;

	qm->sqe_size = HSEC_SQE_SIZE;
	qm->dev_name = hisi_sec_name;
	qm->fun_type = (pdev->device == 0xa255) ? QM_HW_PF : QM_HW_VF;
	qm->algs = "sec\n";

	switch (uacce_mode) {
	case UACCE_MODE_NOUACCE:
		qm->use_dma_api = true;
		qm->use_uacce = false;
		break;
	case UACCE_MODE_UACCE:
#ifdef CONFIG_IOMMU_SVA2
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
		ret = -EINVAL;
		goto err_remove_from_list;
	}

	ret = hisi_qm_init(qm);
	if (ret) {
		dev_err(&pdev->dev, "Failed to init qm!\n");
		goto err_remove_from_list;
	}

	if (qm->fun_type == QM_HW_PF) {
		ret = hisi_sec_pf_probe_init(hisi_sec);
		if (ret)
			goto err_remove_from_list;

		qm->qp_base = HSEC_PF_DEF_Q_BASE;
		qm->qp_num = pf_q_num;
	} else if (qm->fun_type == QM_HW_VF) {
		/*
		 * have no way to get qm configure in VM in v1 hardware,
		 * so currently force PF to uses HSEC_PF_DEF_Q_NUM, and force
		 * to trigger only one VF in v1 hardware.
		 *
		 * v2 hardware has no such problem.
		 */
		if (qm->ver == QM_HW_V1) {
			qm->qp_base = HSEC_PF_DEF_Q_NUM;
			qm->qp_num = HSEC_QUEUE_NUM_V1 - HSEC_PF_DEF_Q_NUM;
		} else if (qm->ver == QM_HW_V2)
			/* v2 starts to support get vft by mailbox */
			hisi_qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
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
static int hisi_sec_vf_q_assign(struct hisi_sec *hisi_sec, int num_vfs)
{
	struct hisi_sec_ctrl *ctrl = hisi_sec->ctrl;
	struct hisi_qm *qm = &hisi_sec->qm;
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

static int hisi_sec_clear_vft_config(struct hisi_sec *hisi_sec)
{
	struct hisi_sec_ctrl *ctrl = hisi_sec->ctrl;
	struct hisi_qm *qm = &hisi_sec->qm;
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

static int hisi_sec_sriov_enable(struct pci_dev *pdev, int max_vfs)
{
#ifdef CONFIG_PCI_IOV
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	int pre_existing_vfs, num_vfs, ret;

	pre_existing_vfs = pci_num_vf(pdev);

	if (pre_existing_vfs) {
		dev_err(&pdev->dev,
			"Can't enable VF. Please disable pre-enabled VFs!\n");
		return 0;
	}

	num_vfs = min_t(int, max_vfs, HSEC_VF_NUM);

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

static int hisi_sec_sriov_disable(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);

	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev,
			"Can't disable VFs while VFs are assigned!\n");
		return -EPERM;
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

static void hisi_sec_remove(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_sec->qm;

	if (qm->fun_type == QM_HW_PF && hisi_sec->ctrl->num_vfs != 0)
		hisi_sec_sriov_disable(pdev);

	hisi_sec_debugfs_exit(hisi_sec);
	hisi_qm_stop(qm, QM_NORMAL);

	if (qm->fun_type == QM_HW_PF) {
		hisi_sec_hw_error_set_state(hisi_sec, false);
		hisi_sec_disable_sm4_ctr(hisi_sec);
	}

	hisi_qm_uninit(qm);
	hisi_sec_remove_from_list(hisi_sec);
}

static void hisi_sec_log_hw_error(struct hisi_sec *hisi_sec, u32 err_sts)
{
	const struct hisi_sec_hw_error *err = sec_hw_error;
	struct device *dev = &hisi_sec->qm.pdev->dev;
	u32 err_val;

	while (err->msg) {
		if (err->int_msk & err_sts) {
			dev_err(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);

			if (HSEC_CORE_INT_STATUS_M_ECC & err_sts) {
				err_val = readl(hisi_sec->qm.io_base +
						HSEC_CORE_SRAM_ECC_ERR_INFO);
				dev_err(dev,
					 "hisi-sec multi ecc sram num=0x%x\n",
					 ((err_val >> SRAM_ECC_ERR_NUM_SHIFT) &
					  0xFF));
				dev_err(dev,
					 "hisi-sec multi ecc sram addr=0x%x\n",
					 (err_val >> SRAM_ECC_ERR_ADDR_SHIFT));
			}
		}
		err++;
	}
}

static pci_ers_result_t hisi_sec_hw_error_handle(struct hisi_sec *hisi_sec)
{
	u32 err_sts;

	/* read err sts */
	err_sts = readl(hisi_sec->qm.io_base + HSEC_CORE_INT_STATUS);

	if (err_sts) {
		hisi_sec_log_hw_error(hisi_sec, err_sts);
		/* clear error interrupts */
		writel(err_sts, hisi_sec->qm.io_base + HSEC_CORE_INT_SOURCE);

		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t hisi_sec_process_hw_error(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	pci_ers_result_t qm_ret, sec_ret;

	if (!hisi_sec) {
		dev_err(dev,
			"Can't recover SEC-error occurred during device init\n");
		return PCI_ERS_RESULT_NONE;
	}

	/* log qm error */
	qm_ret = hisi_qm_hw_error_handle(&hisi_sec->qm);

	/* log sec error */
	sec_ret = hisi_sec_hw_error_handle(hisi_sec);

	return (qm_ret == PCI_ERS_RESULT_NEED_RESET ||
		sec_ret == PCI_ERS_RESULT_NEED_RESET) ?
	    PCI_ERS_RESULT_NEED_RESET : PCI_ERS_RESULT_RECOVERED;
}

static pci_ers_result_t hisi_sec_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_NONE;

	dev_info(&pdev->dev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hisi_sec_process_hw_error(pdev);
}

static int hisi_sec_reset_prepare_rdy(struct hisi_sec *hisi_sec)
{
	int delay = 1;
	u32 flag = 1;
	int ret = 0;

#define RESET_WAIT_TIMEOUT 20000

	while (flag) {
		flag = 0;
		if (delay > RESET_WAIT_TIMEOUT) {
			ret = -EBUSY;
			break;
		}

		msleep(delay);
		delay *= 2;

		if (test_and_set_bit(HISI_SEC_RESET, &hisi_sec->status))
			flag = 1;
	}

	return ret;
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
	int retry = 0;
	int ret;

	ret = hisi_sec_reset_prepare_rdy(hisi_sec);
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
	/* wait 10s for uacce_queue to release */
	while (retry++ < 1000) {
		msleep(20);
		if (!uacce_unregister(&qm->uacce))
			break;

		if (retry == 1000)
			return -EBUSY;
	}
#endif
	return 0;
}

static void hisi_sec_set_mse(struct hisi_sec *hisi_sec, bool set)
{
	struct pci_dev *pdev = hisi_sec->qm.pdev;
	u16 sriov_ctrl;
	int pos;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL, &sriov_ctrl);
	if (set)
		sriov_ctrl |= PCI_SRIOV_CTRL_MSE;
	else
		sriov_ctrl &= ~PCI_SRIOV_CTRL_MSE;
	pci_write_config_word(pdev, pos + PCI_SRIOV_CTRL, sriov_ctrl);
}

static int hisi_sec_soft_reset(struct hisi_sec *hisi_sec)
{
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;
	u32 val;

	/* Set VF MSE bit */
	hisi_sec_set_mse(hisi_sec, 0);

	/* OOO register set and check */
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN,
	       hisi_sec->qm.io_base + HSEC_MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(hisi_sec->qm.io_base +
					 HSEC_MASTER_TRANS_RETURN, val,
					 (val == MASTER_TRANS_RETURN_RW), 10,
					 1000);
	if (ret) {
		dev_emerg(dev, "Bus lock! Please reset system.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(dev)) {
		acpi_status s;
		s = acpi_evaluate_object(ACPI_HANDLE(dev), "SRST", NULL, NULL);
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

			hisi_qm_clear_queues(qm);
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
	struct hisi_qp *qp;
	int i, ret;

	hisi_qm_clear_queues(qm);

	hisi_sec_set_user_domain_and_cache(hisi_sec);
	hisi_sec_hw_error_init(hisi_sec);

	ret = hisi_qm_restart(qm);
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

	if (hisi_sec->ctrl->num_vfs)
		hisi_sec_vf_q_assign(hisi_sec, hisi_sec->ctrl->num_vfs);

	/* Clear VF MSE bit */
	hisi_sec_set_mse(hisi_sec, 1);

	ret = hisi_sec_vf_reset_done(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to start VFs!\n");
		return -EPERM;
	}

#ifdef CONFIG_CRYPTO_QM_UACCE
	if (qm->use_uacce)
		uacce_register(&qm->uacce);
#endif

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

static void hisi_sec_flr_prepare_rdy(struct pci_dev *pdev)
{
	struct pci_dev *pf_pdev = pci_physfn(pdev);
	struct hisi_sec *hisi_sec = pci_get_drvdata(pf_pdev);
	int delay = 1;
	u32 flag = 1;

#define FLR_WAIT_TIMEOUT 60000
#define FLR_DELAY_INC 2000

	while (flag) {
		flag = 0;
		msleep(delay);
		if (delay > FLR_WAIT_TIMEOUT) {
			flag = 1;
			delay = 1;
			dev_err(&pdev->dev, "Device error, please exit FLR!\n");
		} else if (test_and_set_bit(HISI_SEC_RESET, &hisi_sec->status))
			flag = 1;

		delay += FLR_DELAY_INC;
	}
}

static void hisi_sec_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &pdev->dev;
	int ret;

	hisi_sec_flr_prepare_rdy(pdev);

	ret = hisi_sec_vf_reset_prepare(pdev, QM_FLR);
	if (ret) {
		dev_err(&pdev->dev, "Fails to prepare reset!\n");
		return;
	}

	ret = hisi_qm_stop(qm, QM_FLR);
	if (ret) {
		dev_err(&pdev->dev, "Fails to stop QM!\n");
		return;
	}

	dev_info(dev, "FLR resetting...\n");
}

static void hisi_sec_flr_reset_complete(struct pci_dev *pdev)
{
	struct pci_dev *pf_pdev = pci_physfn(pdev);
	struct hisi_sec *hisi_sec = pci_get_drvdata(pf_pdev);

	clear_bit(HISI_SEC_RESET, &hisi_sec->status);
}

static void hisi_sec_reset_done(struct pci_dev *pdev)
{
	struct hisi_sec *hisi_sec = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_sec->qm;
	struct device *dev = &pdev->dev;
	int ret;

	hisi_qm_clear_queues(qm);
	ret = hisi_qm_restart(qm);
	if (ret) {
		dev_err(dev, "Failed to start QM!\n");
		return;
	}

	if (pdev->is_physfn) {
		hisi_sec_set_user_domain_and_cache(hisi_sec);
		hisi_sec_hw_error_init(hisi_sec);
		if (hisi_sec->ctrl->num_vfs)
			hisi_sec_vf_q_assign(hisi_sec, hisi_sec->ctrl->num_vfs);

		hisi_sec_vf_reset_done(pdev);
	}
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
	.name = "hisi_sec",
	.id_table = hisi_sec_dev_ids,
	.probe = hisi_sec_probe,
	.remove = hisi_sec_remove,
	.sriov_configure = hisi_sec_sriov_configure,
	.err_handler = &hisi_sec_err_handler,
};

static void hisi_sec_register_debugfs(void)
{
	if (!debugfs_initialized())
		return;

	hsec_debugfs_root = debugfs_create_dir("hisi_sec", NULL);
	if (IS_ERR_OR_NULL(hsec_debugfs_root))
		hsec_debugfs_root = NULL;
}

static void hisi_sec_unregister_debugfs(void)
{
	debugfs_remove_recursive(hsec_debugfs_root);
}

static int __init hisi_sec_init(void)
{
	int ret;

	hisi_sec_register_debugfs();

	ret = pci_register_driver(&hisi_sec_pci_driver);
	if (ret < 0) {
		pr_err("Failed to register pci driver.\n");
		goto err_pci;
	}
#ifndef CONFIG_IOMMU_SVA2
	if (uacce_mode == UACCE_MODE_UACCE)
		return 0;
#endif
	pr_info("hisi_sec: register to crypto\n");
	ret = hisi_sec_register_to_crypto();
	if (ret < 0) {
		pr_err("Failed to register driver to crypto.\n");
		goto err_crypto;
	}

	return 0;

 err_crypto:
	pci_unregister_driver(&hisi_sec_pci_driver);
 err_pci:
	hisi_sec_unregister_debugfs();

	return ret;
}

static void __exit hisi_sec_exit(void)
{
#ifndef CONFIG_IOMMU_SVA2
	if (uacce_mode != UACCE_MODE_UACCE)
		hisi_sec_unregister_from_crypto();
#else
	hisi_sec_unregister_from_crypto();
#endif
	pci_unregister_driver(&hisi_sec_pci_driver);
	hisi_sec_unregister_debugfs();
}

module_init(hisi_sec_init);
module_exit(hisi_sec_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhang Wei <zhangwei375@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon SEC accelerator");
