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

/*
 * Because we're using an IDR, PASIDs are limited to 31 bits (the sign bit is
 * used for returning errors). In practice implementations will use at most 20
 * bits, which is the PCI limit.
 */
static DEFINE_IDR(iommu_process_idr);

/*
 * For the moment this is an all-purpose lock. It serializes
 * access/modifications to contexts (process-domain links), access/modifications
 * to the PASID IDR, and changes to process refcount as well.
 */
static DEFINE_SPINLOCK(iommu_process_lock);

static void iommu_process_release(struct kref *kref)
{
	struct iommu_process *process;
	void (*release)(struct iommu_process *);

	assert_spin_locked(&iommu_process_lock);

	process = container_of(kref, struct iommu_process, kref);
	release = process->release;

	WARN_ON(!list_empty(&process->domains));

	idr_remove(&iommu_process_idr, process->pasid);
	put_pid(process->pid);
	release(process);
}

/*
 * Returns non-zero if a reference to the process was successfully taken.
 * Returns zero if the process is being freed and should not be used.
 */
static int iommu_process_get_locked(struct iommu_process *process)
{
	assert_spin_locked(&iommu_process_lock);

	if (process)
		return kref_get_unless_zero(&process->kref);

	return 0;
}

static void iommu_process_put_locked(struct iommu_process *process)
{
	assert_spin_locked(&iommu_process_lock);

	kref_put(&process->kref, iommu_process_release);
}

/**
 * iommu_process_put - Put reference to process, freeing it if necessary.
 */
void iommu_process_put(struct iommu_process *process)
{
	spin_lock(&iommu_process_lock);
	iommu_process_put_locked(process);
	spin_unlock(&iommu_process_lock);
}
EXPORT_SYMBOL_GPL(iommu_process_put);

/**
 * iommu_process_find - Find process associated to the given PASID
 *
 * Returns the IOMMU process corresponding to this PASID, or NULL if not found.
 * A reference to the iommu_process is kept, and must be released with
 * iommu_process_put.
 */
struct iommu_process *iommu_process_find(int pasid)
{
	struct iommu_process *process;

	spin_lock(&iommu_process_lock);
	process = idr_find(&iommu_process_idr, pasid);
	if (process) {
		if (!iommu_process_get_locked(process))
			/* kref is 0, process is defunct */
			process = NULL;
	}
	spin_unlock(&iommu_process_lock);

	return process;
}
EXPORT_SYMBOL_GPL(iommu_process_find);

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
