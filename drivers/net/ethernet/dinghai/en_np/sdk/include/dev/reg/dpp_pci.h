/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_PCI_H_
#define _DPP_PCI_H_
#include "dpp_dev.h"
#include "dpp_module.h"

u32 dpp_pci_write32(struct dpp_dev_t *dev, ZXIC_ADDR_T abs_addr, u32 *p_data);
u32 dpp_pci_read32(struct dpp_dev_t *dev, ZXIC_ADDR_T abs_addr, u32 *p_data);

#endif
