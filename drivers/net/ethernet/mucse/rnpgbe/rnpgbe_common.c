// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2026 Mucse Corporation. */

#include <linux/module.h>
#include <linux/pci.h>

#include "rnpgbe_common.h"

unsigned int rnpgbe_loglevel;
module_param(rnpgbe_loglevel, uint, 0600);

int pci_device_check_offline(struct pci_dev *pdev)
{
	if (pci_channel_offline(pdev) || !pci_device_is_present(pdev))
		return 1;

	return 0;
}
