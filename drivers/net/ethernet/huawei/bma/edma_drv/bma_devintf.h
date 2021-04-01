/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _BMA_DEVINTF_H_
#define _BMA_DEVINTF_H_

#include <linux/mutex.h>
#include "bma_pci.h"
#include "edma_host.h"

struct bma_dev_s {
	/* proc */
	struct proc_dir_entry *proc_bma_root;

	atomic_t au_count[TYPE_MAX];

	struct list_head priv_list;
	/* spinlock for priv list */
	spinlock_t priv_list_lock;

	struct bma_pci_dev_s *bma_pci_dev;
	struct edma_host_s edma_host;
};

int bma_devinft_init(struct bma_pci_dev_s *bma_pci_dev);
void bma_devinft_cleanup(struct bma_pci_dev_s *bma_pci_dev);

#endif
