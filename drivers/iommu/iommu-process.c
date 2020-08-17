// SPDX-License-Identifier: GPL-2.0
/*
 * Track processes bound to devices
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.
 *
 * Copyright (C) 2017 ARM Ltd.
 *
 * Author: Jean-Philippe Brucker <jean-philippe.brucker@arm.com>
 */

#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/* Link between a domain and a process */
struct iommu_context {
	struct iommu_process	*process;
	struct iommu_domain	*domain;

	struct list_head	process_head;
	struct list_head	domain_head;

	/* Number of devices that use this context */
	refcount_t		ref;
};

/**
 * iommu_set_process_exit_handler() - set a callback for stopping the use of
 * PASID in a device.
 * @dev: the device
 * @handler: exit handler
 * @token: user data, will be passed back to the exit handler
 *
 * Users of the bind/unbind API should call this function to set a
 * device-specific callback telling them when a process is exiting.
 *
 * After the callback returns, the device must not issue any more transaction
 * with the PASIDs given as argument to the handler. It can be a single PASID
 * value or the special IOMMU_PROCESS_EXIT_ALL.
 *
 * The handler itself should return 0 on success, and an appropriate error code
 * otherwise.
 */
void iommu_set_process_exit_handler(struct device *dev,
				    iommu_process_exit_handler_t handler,
				    void *token)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (WARN_ON(!domain))
		return;

	domain->process_exit = handler;
	domain->process_exit_token = token;
}
EXPORT_SYMBOL_GPL(iommu_set_process_exit_handler);
