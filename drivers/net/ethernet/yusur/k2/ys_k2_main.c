// SPDX-License-Identifier: GPL-2.0
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/rtc.h>

#include "ys_k2_core.h"
#include "../platform/ys_init.h"
#include "../platform/ys_pdev.h"
#include "../platform/ys_auxiliary.h"

const struct ys_pdev_hw k2_pf_type = {
	.irq_flag = PCI_IRQ_MSIX | PCI_IRQ_MSI,
	.ndev_sum = 1,
	.bar_status = { 0x00 },
	.func_name = YS_DEV_NAME("k2_pf"),
	.bar_base = 0,
	.dma_flag = DMA_BIT_MASK(64),
	.dma_coherent_flag = DMA_BIT_MASK(64),
	.is_vf = false,
	.hw_pdev_init = ysk2_pdev_init,
	.hw_pdev_uninit = ysk2_pdev_uninit,
};

const struct ys_pdev_hw k2_vf_type = {
	.irq_flag = PCI_IRQ_MSIX | PCI_IRQ_MSI,
	.ndev_sum = 1,
	.bar_status = { 0x00 },
	.func_name = YS_DEV_NAME("k2_vf"),
	.bar_base = 0,
	.dma_flag = DMA_BIT_MASK(64),
	.dma_coherent_flag = DMA_BIT_MASK(64),
	.is_vf = true,
	.hw_pdev_init = ysk2_pdev_init,
	.hw_pdev_uninit = ysk2_pdev_uninit,
};

#define YS_K2_NIC_DEVICE_PF(device_id)                            \
	{                                                         \
		PCI_DEVICE(PCI_YS_VENDOR_ID, device_id),          \
			.driver_data = (unsigned long)&k2_pf_type \
	}

#define YS_K2_NIC_DEVICE_VF(device_id)                            \
	{                                                         \
		PCI_DEVICE(PCI_YS_VENDOR_ID, device_id),          \
			.driver_data = (unsigned long)&k2_vf_type \
	}

static const struct pci_device_id ys_k2_pdev_ids[] = {
	YS_K2_NIC_DEVICE_PF(0x1001),
	YS_K2_NIC_DEVICE_VF(0x1101),
	YS_K2_NIC_DEVICE_VF(0x110f),
	{ 0 /* end */ }
};

static struct pci_driver ys_k2_driver = {
	.name = YS_DEV_NAME("k2"),
	.id_table = ys_k2_pdev_ids,
	.probe = ys_pdev_probe,
	.remove = ys_pdev_remove,
	.shutdown = ys_pdev_shutdown, /* callback Function while reboot */
};

static const struct auxiliary_device_id ys_k2_sf_id_table[] = {
	{ .name = YS_DEV_NAME("k2") "." AUX_NAME_SF },
	{ },
};

static const struct auxiliary_device_id ys_k2_eth_id_table[] = {
	{ .name = YS_DEV_NAME("k2") "." AUX_NAME_ETH },
	{ },
};

static struct auxiliary_driver ys_k2_adrvs[] = {
	YS_AUX_DRV(AUX_NAME_SF, ys_aux_sf_probe,
		   ys_aux_sf_remove, ys_k2_sf_id_table),
	YS_AUX_DRV(AUX_NAME_ETH, ys_aux_eth_probe,
		   ys_aux_eth_remove, ys_k2_eth_id_table),
	YS_AUX_DRV(NULL, NULL, NULL, NULL) /* end */
};

static int __init ys_k2_init(void)
{
	return ys_init(&ys_k2_driver, ys_k2_adrvs);
}

static void __exit ys_k2_exit(void)
{
	ys_exit(&ys_k2_driver, ys_k2_adrvs);
}

module_init(ys_k2_init);
module_exit(ys_k2_exit);

MODULE_DESCRIPTION("Yusur KPU FLEXFLOW-2100P PCI Express Device Driver");
MODULE_AUTHOR("YUSUR Technology Co., Ltd.");
MODULE_LICENSE("GPL");
