/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_SRIOV_H
#define SPNIC_SRIOV_H
#include <linux/types.h>

enum spnic_sriov_state {
	SPNIC_SRIOV_DISABLE,
	SPNIC_SRIOV_ENABLE,
	SPNIC_FUNC_PERSENT,
};

struct spnic_sriov_info {
	bool sriov_enabled;
	unsigned int num_vfs;
	unsigned long state;
};

struct spnic_sriov_info *spnic_get_sriov_info_by_pcidev(struct pci_dev *pdev);
int spnic_pci_sriov_disable(struct pci_dev *dev);
int spnic_pci_sriov_enable(struct pci_dev *dev, int num_vfs);
int spnic_pci_sriov_configure(struct pci_dev *dev, int num_vfs);
#endif
