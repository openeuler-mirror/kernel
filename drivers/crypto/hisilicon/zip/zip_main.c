// SPDX-License-Identifier: GPL-2.0+
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "zip.h"
#include "zip_crypto.h"

#define HZIP_VF_NUM			63
#define HZIP_QUEUE_NUM_V1		4096
#define HZIP_QUEUE_NUM_V2		1024

#define HZIP_FSM_MAX_CNT		0x301008

#define HZIP_PORT_ARCA_CHE_0		0x301040
#define HZIP_PORT_ARCA_CHE_1		0x301044
#define HZIP_PORT_AWCA_CHE_0		0x301060
#define HZIP_PORT_AWCA_CHE_1		0x301064

#define HZIP_BD_RUSER_32_63		0x301110
#define HZIP_SGL_RUSER_32_63		0x30111c
#define HZIP_DATA_RUSER_32_63		0x301128
#define HZIP_DATA_WUSER_32_63		0x301134
#define HZIP_BD_WUSER_32_63		0x301140

LIST_HEAD(hisi_zip_list);
DEFINE_MUTEX(hisi_zip_list_lock);

static const struct pci_device_id hisi_zip_dev_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa250) },
	{ 0, }
};

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
	u32 val;

	/* qm user domain */
	writel(0x40001070, hisi_zip->qm.io_base + QM_ARUSER_M_CFG_1);
	writel(0xfffffffe, hisi_zip->qm.io_base + QM_ARUSER_M_CFG_ENABLE);
	writel(0x40001070, hisi_zip->qm.io_base + QM_AWUSER_M_CFG_1);
	writel(0xfffffffe, hisi_zip->qm.io_base + QM_AWUSER_M_CFG_ENABLE);
	writel(0xffffffff, hisi_zip->qm.io_base + QM_WUSER_M_CFG_ENABLE);

	val = readl(hisi_zip->qm.io_base + QM_PEH_AXUSER_CFG);
	val |= (1 << 11);
	writel(val, hisi_zip->qm.io_base + QM_PEH_AXUSER_CFG);

	/* qm cache */
	writel(0xffff,     hisi_zip->qm.io_base + QM_AXI_M_CFG);
	writel(0xffffffff, hisi_zip->qm.io_base + QM_AXI_M_CFG_ENABLE);
	writel(0xffffffff, hisi_zip->qm.io_base + QM_PEH_AXUSER_CFG_ENABLE);

	/* cache */
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_ARCA_CHE_0);
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_ARCA_CHE_1);
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_AWCA_CHE_0);
	writel(0xffffffff, hisi_zip->qm.io_base + HZIP_PORT_AWCA_CHE_1);

	/* user domain configurations */
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_BD_RUSER_32_63);
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_SGL_RUSER_32_63);
#ifdef CONFIG_IOMMU_SVA
	writel(0x40001071, hisi_zip->qm.io_base + HZIP_DATA_RUSER_32_63);
	writel(0x40001071, hisi_zip->qm.io_base + HZIP_DATA_WUSER_32_63);
#else
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_DATA_RUSER_32_63);
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_DATA_WUSER_32_63);
#endif
	writel(0x40001070, hisi_zip->qm.io_base + HZIP_BD_WUSER_32_63);

	/* fsm count */
	writel(0xfffffff, hisi_zip->qm.io_base + HZIP_FSM_MAX_CNT);

	/* clock gating, core, decompress verify enable */
	writel(0x10005, hisi_zip->qm.io_base + 0x301004);
}

static int hisi_zip_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct hisi_zip *hisi_zip;
	struct qm_info *qm;
	int ret;
	u8 rev_id;

	hisi_zip = devm_kzalloc(&pdev->dev, sizeof(*hisi_zip), GFP_KERNEL);
	if (!hisi_zip)
		return -ENOMEM;
	hisi_zip_add_to_list(hisi_zip);
	pci_set_drvdata(pdev, hisi_zip);

	qm = &hisi_zip->qm;
	qm->pdev = pdev;

	pci_read_config_byte(pdev, PCI_REVISION_ID, &rev_id);
	if (rev_id == 0x20)
		qm->ver = QM_HW_V1;
	else if (rev_id == 0x21)
		qm->ver = QM_HW_V2;
	qm->sqe_size = HZIP_SQE_SIZE;

	ret = hisi_qm_init(qm, ZIP);
	if (ret)
		goto err_with_hisi_zip;

	if (pdev->is_physfn) {
		ret = hisi_qm_mem_start(qm);
		if (ret) {
			dev_err(&pdev->dev, "Can't start QM mem of Hisilicon!\n");
			goto err_with_qm_init;
		}

		hisi_zip_set_user_domain_and_cache(hisi_zip);

		qm->qp_base = HZIP_PF_DEF_Q_BASE;
		qm->qp_num = HZIP_PF_DEF_Q_NUM;
		qm->free_qp = qm->qp_num;
	}
	ret = hisi_qm_start(qm);
	if (ret) {
		dev_err(&pdev->dev, "Can't start QM of Hisilicon!\n");
		goto err_with_qm_init;
	}

	return 0;

err_with_qm_init:
	hisi_qm_uninit(qm);
err_with_hisi_zip:
	hisi_zip_remove_from_list(hisi_zip);
	kfree(hisi_zip);
	return ret;
}

static void hisi_zip_remove(struct pci_dev *pdev)
{
	struct hisi_zip *hisi_zip = pci_get_drvdata(pdev);
	struct qm_info *qm = &hisi_zip->qm;

	hisi_qm_stop(qm);
	hisi_qm_uninit(qm);
	hisi_zip_remove_from_list(hisi_zip);
	kfree(hisi_zip);
}

static struct pci_driver hisi_zip_pci_driver = {
	.name		= "hisi_zip",
	.id_table	= hisi_zip_dev_ids,
	.probe		= hisi_zip_probe,
	.remove		= hisi_zip_remove,
};

static int __init hisi_zip_init(void)
{
	int ret;

	ret = pci_register_driver(&hisi_zip_pci_driver);
	if (ret < 0) {
		pr_err("zip: can't register hisi zip driver.\n");
		return ret;
	}

	ret = hisi_zip_register_to_crypto();
	if (ret < 0) {
		pr_err("zip: can't register hisi zip to crypto.\n");
		pci_unregister_driver(&hisi_zip_pci_driver);
		return ret;
	}

	return 0;
}

static void __exit hisi_zip_exit(void)
{
	hisi_zip_unregister_from_crypto();
	pci_unregister_driver(&hisi_zip_pci_driver);
}

module_init(hisi_zip_init);
module_exit(hisi_zip_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("Driver for HiSilicon ZIP accelerator");
MODULE_DEVICE_TABLE(pci, hisi_zip_dev_ids);
