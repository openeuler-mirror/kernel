/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026. Huawei Technologies Co., Ltd. All rights reserved.
 */

#ifndef __CCA_CVM_DOMAIN_H
#define __CCA_CVM_DOMAIN_H
#include <linux/device.h>

struct pci_dev;

#ifdef CONFIG_HISI_CCADA_HOST

bool is_realm_device(struct device *dev, struct device_driver *drv);
bool is_support_rme(void);
bool is_dev_delegated(struct pci_dev *pdev);
bool is_dev_ecam_protected(u16 dev_bdf);
int cca_add_protected_virtfn(struct pci_dev *virtfn);
int ccada_pci_generic_config_read(void __iomem *addr, unsigned char bus_num,
				   unsigned int devfn, u32 size, u32 *val);
int ccada_pci_generic_config_write(void __iomem *addr, unsigned char bus_num,
				    unsigned int devfn, u32 size, u32 val);
#else

static inline bool is_realm_device(struct device *dev, struct device_driver *drv)
{
	return false;
}

static inline bool is_support_rme(void)
{
	return false;
}

static inline bool is_dev_delegated(struct pci_dev *pdev)
{
	return false;
}

static inline bool is_dev_ecam_protected(u16 dev_bdf)
{
	return false;
}

static inline int cca_add_protected_virtfn(struct pci_dev *virtfn)
{
	return 0;
}

static inline int ccada_pci_generic_config_read(void __iomem *addr, unsigned char bus_num,
				   unsigned int devfn, u32 size, u32 *val)
{
	return 0;
}

static inline int ccada_pci_generic_config_write(void __iomem *addr, unsigned char bus_num,
				    unsigned int devfn, u32 size, u32 val)
{
	return 0;
}
#endif /* CONFIG_HISI_CCADA_HOST */
#endif /* __CCA_CVM_DOMAIN_H */
