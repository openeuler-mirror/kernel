/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 3snic Technologies Co., Ltd */

#ifndef SSS_ADAPTER_MGMT_H
#define SSS_ADAPTER_MGMT_H

#include <linux/types.h>
#include <linux/bitops.h>

#include "sss_adapter.h"

#define SSS_DRV_NAME	"sssdk"
#define SSS_CHIP_NAME	"sssnic"

#define SSS_VF_PCI_CFG_REG_BAR	0
#define SSS_PF_PCI_CFG_REG_BAR	1

#define SSS_PCI_INTR_REG_BAR	2
#define SSS_PCI_MGMT_REG_BAR	3 /* Only PF have mgmt bar */
#define SSS_PCI_DB_BAR			4

#define SSS_IS_VF_DEV(pdev)		((pdev)->device == SSS_DEV_ID_VF)

enum {
	SSS_NO_PROBE = 1,
	SSS_PROBE_START = 2,
	SSS_PROBE_OK = 3,
	SSS_IN_REMOVE = 4,
};

struct list_head *sss_get_chip_list(void);
int sss_alloc_chip_node(struct sss_pci_adapter *adapter);
void sss_free_chip_node(struct sss_pci_adapter *adapter);
void sss_pre_init(void);
struct sss_pci_adapter *sss_get_adapter_by_pcidev(struct pci_dev *pdev);
void sss_add_func_list(struct sss_pci_adapter *adapter);
void sss_del_func_list(struct sss_pci_adapter *adapter);
void sss_hold_chip_node(void);
void sss_put_chip_node(void);

void sss_set_adapter_probe_state(struct sss_pci_adapter *adapter, int state);

#endif
