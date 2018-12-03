// SPDX-License-Identifier: GPL-2.0+
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/vfio_spimdev.h>
#include "hpre.h"

#define HPRE_VF_NUM			63
#define HPRE_QUEUE_NUM_V1		4096
#define HPRE_QUEUE_NUM_V2		1024
#define HPRE_CLUSTERS_NUM		4
#define HPRE_CLUSTER_CORES		4
#define HPRE_QM_ABNML_INT_MASK		0x100004
#define HPRE_COMM_CNT_CLR_CE		0x0
#define HPRE_FSM_MAX_CNT		0x301008
#define HPRE_VFG_AXQOS			0x30100c
#define HPRE_VFG_AXCACHE		0x301010
#define HPRE_RDCHN_INI_CFG		0x301014
#define HPRE_BD_ENDIAN			0x301020
#define HPRE_ECC_BYPASS			0x301024
#define HPRE_POISON_BYPASS		0x30102c
#define HPRE_ARUSR_CFG			0x301030
#define HPRE_AWUSR_CFG			0x301034
#define HPRE_INT_MASK			0x301400
#define HPRE_RAS_ECC_1BIT_TH		0x30140c

#define HPRE_TYPES_ENB			0x301038
#define HPRE_PORT_ARCA_CHE_0		0x301040
#define HPRE_PORT_ARCA_CHE_1		0x301044
#define HPRE_PORT_AWCA_CHE_0		0x301060
#define HPRE_PORT_AWCA_CHE_1		0x301064

#define HPRE_BD_RUSER_32_63		0x301110
#define HPRE_SGL_RUSER_32_63		0x30111c
#define HPRE_DATA_RUSER_32_63		0x301128
#define HPRE_DATA_WUSER_32_63		0x301134
#define HPRE_BD_WUSER_32_63		0x301140
#define HPRE_RDCHN_INI_ST		0x301a00
#define HPRE_CORE_ENB			0x302004
#define HPRE_CORE_INI_CFG		0x302020
#define HPRE_CORE_INI_STATUS		0x302080

LIST_HEAD(hisi_hpre_list);
DEFINE_MUTEX(hisi_hpre_list_lock);

static const struct pci_device_id hisi_hpre_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa258) },
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa259) },
	{ 0, }
};


static inline void hisi_hpre_add_to_list(struct hisi_hpre *hisi_hpre)
{
	mutex_lock(&hisi_hpre_list_lock);
	list_add_tail(&hisi_hpre->list, &hisi_hpre_list);
	mutex_unlock(&hisi_hpre_list_lock);
}

static inline void hisi_hpre_remove_from_list(struct hisi_hpre *hisi_hpre)
{
	mutex_lock(&hisi_hpre_list_lock);
	list_del(&hisi_hpre->list);
	mutex_unlock(&hisi_hpre_list_lock);
}

static int hisi_hpre_set_user_domain_and_cache(struct hisi_hpre *hisi_hpre)
{
	int ret, i;
	u32 val;
	unsigned long offset;

	writel(0x1, hisi_hpre->qm.io_base + HPRE_TYPES_ENB);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_VFG_AXQOS);
	writel(0xff, hisi_hpre->qm.io_base + HPRE_VFG_AXCACHE);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_BD_ENDIAN);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_INT_MASK);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_RAS_ECC_1BIT_TH);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_POISON_BYPASS);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_COMM_CNT_CLR_CE);
	writel(0x0, hisi_hpre->qm.io_base + HPRE_ECC_BYPASS);

#ifndef CONFIG_ARM_SMMU_V3
	writel(0x1, hisi_hpre->qm.io_base + HPRE_ARUSR_CFG);
	writel(0x1, hisi_hpre->qm.io_base + HPRE_AWUSR_CFG);
#endif
	writel(0x1, hisi_hpre->qm.io_base + HPRE_RDCHN_INI_CFG);
	ret = readl_relaxed_poll_timeout(hisi_hpre->qm.io_base +
					 HPRE_RDCHN_INI_ST, val,
					 val & BIT(0), 10, 1000);
	if (ret) {
		pr_err("\nHPRE:INI ST TIMEOUT");
		return -ETIMEDOUT;
	}
	for (i = 0; i < HPRE_CLUSTERS_NUM; i++) {
		offset = i * 0x1000;

		/* clusters initiating */
		writel(0xf, hisi_hpre->qm.io_base + offset + HPRE_CORE_ENB);
		writel(0x1, hisi_hpre->qm.io_base + offset + HPRE_CORE_INI_CFG);
		ret = readl_relaxed_poll_timeout(hisi_hpre->qm.io_base +
						 offset + HPRE_CORE_INI_STATUS,
						 val, ((val & 0xf) == 0xf),
						 10, 1000);
		if (ret) {
			pr_err("\nHPRE:CLUSTER %d INI ST STATUS timeout!", i);
			return -ETIMEDOUT;
		}
	}

	return ret;
}

static int hisi_hpre_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_hpre *hisi_hpre;
	struct hisi_qm *qm;
	enum qm_hw_ver rev_id;
	int ret;
	u32 val;

	hisi_hpre = devm_kzalloc(&pdev->dev, sizeof(*hisi_hpre), GFP_KERNEL);
	if (!hisi_hpre)
		return -ENOMEM;
	hisi_hpre_add_to_list(hisi_hpre);
	pci_set_drvdata(pdev, hisi_hpre);
	qm = &hisi_hpre->qm;
	qm->pdev = pdev;

	rev_id = hisi_qm_get_hw_version(qm);
	if (rev_id < 0)
		return rev_id;
	qm->ver = rev_id;

	qm->sqe_size = HPRE_SQE_SIZE;
	qm->type = HPRE;
	ret = hisi_qm_init(qm);
	if (ret)
		goto err_with_hisi_hpre;

#define HPRE_ADDR(offset) QM_ADDR(qm, offset)
/*
 * hi zaibo: Remove this in qm.h in upstream, so hack here to pass compiling,
 * please fix it
 */
#define QM_ADDR(qm, off) ((qm)->io_base + off)

	if (pdev->is_physfn) {
		/* user domain */
		writel(0x40000070, HPRE_ADDR(QM_ARUSER_M_CFG_1));
		writel(0x007ffffc, HPRE_ADDR(QM_ARUSER_M_CFG_ENABLE));
		writel(0x40000070, HPRE_ADDR(QM_AWUSER_M_CFG_1));
		writel(0x007ffffc, HPRE_ADDR(QM_AWUSER_M_CFG_ENABLE));
		writel(0x00000001, HPRE_ADDR(QM_WUSER_M_CFG_ENABLE));
		writel(0x1833, HPRE_ADDR(QM_CACHE_CTL));
		writel(0x00400001, HPRE_ADDR(QM_PEH_AXUSER_CFG));
#ifdef CONFIG_ARM_SMMU_V3
		writel(0x40000070, HPRE_ADDR(QM_ARUSER_M_CFG_1));
		writel(0xfffffffe, HPRE_ADDR(QM_ARUSER_M_CFG_ENABLE));
		writel(0x40000070, HPRE_ADDR(QM_AWUSER_M_CFG_1));
		writel(0xfffffffe, HPRE_ADDR(QM_AWUSER_M_CFG_ENABLE));

		val = readl_relaxed(HPRE_ADDR(QM_ARUSER_M_CFG_1));
		val &= ~GENMASK(14, 12);
		val |= (1 << 12);
		writel(val, HPRE_ADDR(QM_ARUSER_M_CFG_1));

		val = readl_relaxed(HPRE_ADDR(QM_AWUSER_M_CFG_1));
		val &= ~GENMASK(14, 12);
		val |= (1 << 12);
		writel(val, HPRE_ADDR(QM_AWUSER_M_CFG_1));

		val = readl_relaxed(HPRE_ADDR(QM_ARUSER_M_CFG_ENABLE));
		val &= ~0x1;
		writel(val, HPRE_ADDR(QM_ARUSER_M_CFG_ENABLE));

		val = readl_relaxed(HPRE_ADDR(QM_AWUSER_M_CFG_ENABLE));
		val &= ~0x1;
		writel(val, HPRE_ADDR(QM_AWUSER_M_CFG_ENABLE));
#endif
		/* cache */
		writel_relaxed(0x0303, /* 0xffff IT */
			HPRE_ADDR(QM_AXI_M_CFG));
		writel_relaxed(0xf,
			HPRE_ADDR(QM_AXI_M_CFG_ENABLE));
		writel_relaxed(0x7f,
			HPRE_ADDR(QM_PEH_AXUSER_CFG_ENABLE));
#ifdef CONFIG_ARM_SMMU_V3
		writel_relaxed(0xffff,
			HPRE_ADDR(QM_AXI_M_CFG));
		writel_relaxed(0xffffffff,
			HPRE_ADDR(QM_AXI_M_CFG_ENABLE));
		writel_relaxed(0xffffffff,
			HPRE_ADDR(QM_PEH_AXUSER_CFG_ENABLE));
#endif
		val = readl_relaxed(HPRE_ADDR(HPRE_QM_ABNML_INT_MASK));
		val |= (1 << 6);
		writel_relaxed(val, HPRE_ADDR(HPRE_QM_ABNML_INT_MASK));

		ret = hisi_qm_mem_start(qm);
		if (ret)
			goto err_with_qm_init;
		ret = hisi_hpre_set_user_domain_and_cache(hisi_hpre);
		if (ret)
			return ret;
		qm->qp_base = HPRE_PF_DEF_Q_BASE;
		qm->qp_num = HPRE_PF_DEF_Q_NUM;
		qm->free_qp = qm->qp_num;
	}

	/*
	 * hi zaibo: Adding this new interface in upstream version,
	 * so let use it
	 */
	ret = hisi_qm_mem_init(qm);
	if (ret)
		goto err_with_qm_init;

	ret = hisi_qm_start(qm);
	if (ret)
		goto err_with_qm_mem_uninit;

	return 0;

err_with_qm_mem_uninit:
	hisi_qm_mem_uninit(qm);
err_with_qm_init:
	hisi_qm_uninit(qm);
err_with_hisi_hpre:
	hisi_hpre_remove_from_list(hisi_hpre);

	return ret;
}

static void hisi_hpre_remove(struct pci_dev *pdev)
{
	struct hisi_hpre *hisi_hpre = pci_get_drvdata(pdev);
	struct hisi_qm *qm = &hisi_hpre->qm;

	hisi_qm_stop(qm);
	hisi_qm_mem_uninit(qm);
	hisi_qm_uninit(qm);
	hisi_hpre_remove_from_list(hisi_hpre);
}

static int hisi_hpre_pci_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	/* todo: set queue number for VFs */

	return 0;
}

static struct pci_driver hisi_hpre_pci_driver = {
	.name			= "hisi_hpre",
	.id_table		= hisi_hpre_dev_ids,
	.probe			= hisi_hpre_probe,
	.remove			= hisi_hpre_remove,
	.sriov_configure	= hisi_hpre_pci_sriov_configure
};

static int __init hisi_hpre_init(void)
{
	int ret;

	ret = pci_register_driver(&hisi_hpre_pci_driver);
	if (ret < 0) {
		pr_err("hpre: can't register hisi hpre driver.\n");
		return ret;
	}

	ret = hpre_algs_register();
	if (ret < 0) {
		pr_err("hpre: can't register hisi hpre to crypto.\n");
		pci_unregister_driver(&hisi_hpre_pci_driver);
		return ret;
	}

	return 0;
}

static void __exit hisi_hpre_exit(void)
{
	hpre_algs_unregister();
	pci_unregister_driver(&hisi_hpre_pci_driver);
}

module_init(hisi_hpre_init);
module_exit(hisi_hpre_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zaibo Xu <xuzaibo@huawei.com>");
MODULE_DESCRIPTION("Driver for HiSilicon HPRE accelerator");
MODULE_DEVICE_TABLE(pci, hisi_hpre_dev_ids);
