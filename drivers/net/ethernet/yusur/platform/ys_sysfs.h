/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_SYSFS_H_
#define __YS_SYSFS_H_

int ys_sysfs_init(struct pci_dev *pdev);
void ys_sysfs_uninit(struct pci_dev *pdev);

#endif /* __YS_SYSFS_H_ */
