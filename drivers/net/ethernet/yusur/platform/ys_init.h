/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_INIT_H_
#define __YS_INIT_H_

#include <linux/pci.h>
#include <linux/auxiliary_bus.h>

int ys_init(struct pci_driver *pdrv, struct auxiliary_driver *adrvs);
void ys_exit(struct pci_driver *pdrv, struct auxiliary_driver *adrvs);

#endif /* __YS_INIT_H_ */
