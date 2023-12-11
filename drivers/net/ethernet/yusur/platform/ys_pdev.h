/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_PDEV_H_
#define __YS_PDEV_H_

#include <linux/miscdevice.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/types.h>

#include "ys_auxiliary.h"
#include "ys_sysfs.h"
#include "ys_intr.h"

#include "ys_adapter.h"
#include "ys_utils.h"

#define YS_DEV_NAME(name) YS_HW_STRING("ysnic_", name)

#define YS_FUNC_NAME_LEN 32

#define YS_DEV_TYPE_PF 0x01
#define YS_DEV_TYPE_VF 0x10

#define PCI_QDMA_VENDOR_ID 0x10ee
#define PCI_YS_VENDOR_ID 0x1f47

#define YS_DEV_PTON_PARA_MAX_LEN 128

#define YS_MAX_IRQ 2048
#define YS_NDEV_MAX 8
#define YS_MAX_I2C 8
enum BAR { BAR0 = 0, BAR1, BAR2, BAR3, BAR4, BAR5, BAR_MAX };

#define MAX_MISC_DEV_NAME_BYTES (16)
struct ys_pdev_priv {
	struct device *dev;
	struct pci_dev *pdev;

	const struct ys_pdev_hw *nic_type;
	void __iomem *bar_addr[BAR_MAX];
	u64 bar_size[BAR_MAX];
	u64 bar_offset[BAR_MAX];
	u64 bar_pa[BAR_MAX];

	struct ys_irq_table irq_table;

	/* Logically, pf_id should not be in the platform abstraction layer.
	 * But for some hardware module, registers is designed without logic,
	 * hardware pf_id is necessary for platform and must be set by
	 * adapter driver.
	 *
	 * For example, pf0mac is based on 0x600_0000 and pf1mac is based on
	 * 0x608_0000 instead of based on the same address.
	 */
	u8 pf_id;

	/* total queue numbers for this function, include own netdeive,
	 * all its sub-function's netdevice and representor's netdevice.
	 * pdev_priv->total_qnum = pdev_priv->netdev_qnum +
	 *                         Sum-of-all(ys_adev->netdev_qnum) +
	 *                         Sum-of-all(ys_repdev->netdev_qnum) +
	 *                         unuesd_qnum
	 */
	u16 total_qnum;
	/* max combined queue numbers for ndev[0] */
	u16 netdev_qnum;

	/* sf device list */
	struct list_head adev_list;
	struct hw_adapter_ops *ops;
	void *padp_priv;
	struct list_head sysfs_list;
};

/* bar_status:
 * BIT(x):BAR x IOREMAP FUNC
 * 0: ioremap_nocache
 * 1: ioremap_wc
 * bar_addr:
 * 0:bar0
 * 1:bar1
 * 2:bar2
 */
struct ys_pdev_hw {
	char func_name[YS_FUNC_NAME_LEN];

	int irq_flag;
	int irq_sum;

	int ndev_sum;
	int ndev_qcount;
	int bar_base;
	DECLARE_BITMAP(bar_status, 6);

	u64 dma_flag;
	u64 dma_coherent_flag;
	u8 is_vf;

	int (*hw_pdev_init)(struct ys_pdev_priv *priv);
	void (*hw_pdev_uninit)(struct ys_pdev_priv *priv);
};

int ys_pdev_init(struct pci_driver *pdrv);
void ys_pdev_uninit(struct pci_driver *pdrv);
int ys_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ys_pdev_remove(struct pci_dev *pdev);
void ys_pdev_shutdown(struct pci_dev *pdev);

#endif /* __YS_PDEV_H_ */
