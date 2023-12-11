// SPDX-License-Identifier: GPL-2.0

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/rtc.h>

#include "ys_init.h"
#include "ys_auxiliary.h"
#include "ys_pdev.h"

#include "ys_debug.h"

int ys_init(struct pci_driver *pdrv, struct auxiliary_driver *adrvs)
{
	int ret;

	ret = ys_aux_init(adrvs);
	if (ret)
		goto err_aux_init;

	ret = ys_pdev_init(pdrv);
	if (ret)
		goto err_pdev_init;

	return 0;

err_pdev_init:
	ys_pdev_uninit(pdrv);
err_aux_init:
	ys_aux_uninit(adrvs);

	return ret;
}

void ys_exit(struct pci_driver *pdrv, struct auxiliary_driver *adrvs)
{
	ys_pdev_uninit(pdrv);
	ys_aux_uninit(adrvs);
}
