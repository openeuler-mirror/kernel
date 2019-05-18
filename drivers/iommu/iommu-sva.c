// SPDX-License-Identifier: GPL-2.0
/*
 * Manage PASIDs and bind process address spaces to devices.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/mmu_notifier.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/**
 * DOC: io_mm model
 *
 * The io_mm keeps track of process address spaces shared between CPU and IOMMU.
 * The following example illustrates the relation between structures
 * iommu_domain, io_mm and iommu_bond. An iommu_bond is a link between io_mm and
 * device. A device can have multiple io_mm and an io_mm may be bound to
 * multiple devices.
 *              ___________________________
 *             |  IOMMU domain A           |
 *             |  ________________         |
 *             | |  IOMMU group   |        +------- io_pgtables
 *             | |                |        |
 *             | |   dev 00:00.0 ----+------- bond --- io_mm X
 *             | |________________|   \    |
 *             |                       '----- bond ---.
 *             |___________________________|           \
 *              ___________________________             \
 *             |  IOMMU domain B           |           io_mm Y
 *             |  ________________         |           / /
 *             | |  IOMMU group   |        |          / /
 *             | |                |        |         / /
 *             | |   dev 00:01.0 ------------ bond -' /
 *             | |   dev 00:01.1 ------------ bond --'
 *             | |________________|        |
 *             |                           +------- io_pgtables
 *             |___________________________|
 *
 * In this example, device 00:00.0 is in domain A, devices 00:01.* are in domain
 * B. All devices within the same domain access the same address spaces. Device
 * 00:00.0 accesses address spaces X and Y, each corresponding to an mm_struct.
 * Devices 00:01.* only access address space Y. In addition each
 * IOMMU_DOMAIN_DMA domain has a private address space, io_pgtable, that is
 * managed with iommu_map()/iommu_unmap(), and isn't shared with the CPU MMU.
 *
 * To obtain the above configuration, users would for instance issue the
 * following calls:
 *
 *     iommu_sva_bind_device(dev 00:00.0, mm X, ...) -> PASID 1
 *     iommu_sva_bind_device(dev 00:00.0, mm Y, ...) -> PASID 2
 *     iommu_sva_bind_device(dev 00:01.0, mm Y, ...) -> PASID 2
 *     iommu_sva_bind_device(dev 00:01.1, mm Y, ...) -> PASID 2
 *
 * A single Process Address Space ID (PASID) is allocated for each mm. In the
 * example, devices use PASID 1 to read/write into address space X and PASID 2
 * to read/write into address space Y.
 *
 * Hardware tables describing this configuration in the IOMMU would typically
 * look like this:
 *
 *                                PASID tables
 *                                 of domain A
 *                              .->+--------+
 *                             / 0 |        |-------> io_pgtable
 *                            /    +--------+
 *            Device tables  /   1 |        |-------> pgd X
 *              +--------+  /      +--------+
 *      00:00.0 |      A |-'     2 |        |--.
 *              +--------+         +--------+   \
 *              :        :       3 |        |    \
 *              +--------+         +--------+     --> pgd Y
 *      00:01.0 |      B |--.                    /
 *              +--------+   \                  |
 *      00:01.1 |      B |----+   PASID tables  |
 *              +--------+     \   of domain B  |
 *                              '->+--------+   |
 *                               0 |        |-- | --> io_pgtable
 *                                 +--------+   |
 *                               1 |        |   |
 *                                 +--------+   |
 *                               2 |        |---'
 *                                 +--------+
 *                               3 |        |
 *                                 +--------+
 *
 * With this model, a single call binds all devices in a given domain to an
 * address space. Other devices in the domain will get the same bond implicitly.
 * However, users must issue one bind() for each device, because IOMMUs may
 * implement SVA differently. Furthermore, mandating one bind() per device
 * allows the driver to perform sanity-checks on device capabilities.
 *
 * On Arm and AMD IOMMUs, entry 0 of the PASID table can be used to hold
 * non-PASID translations. In this case PASID 0 is reserved and entry 0 points
 * to the io_pgtable base. On Intel IOMMU, the io_pgtable base would be held in
 * the device table and PASID 0 would be available to the allocator.
 */

struct iommu_bond {
	struct io_mm		*io_mm;
	struct device		*dev;
	struct iommu_domain	*domain;

	struct list_head	mm_head;
	struct list_head	dev_head;
	struct list_head	domain_head;
	refcount_t		refs;
	struct wait_queue_head	mm_exit_wq;
	bool			mm_exit_active;

	void			*drvdata;
};

/*
 * Because we're using an IDR, PASIDs are limited to 31 bits (the sign bit is
 * used for returning errors). In practice implementations will use at most 20
 * bits, which is the PCI limit.
 */
static DEFINE_IDR(iommu_pasid_idr);

/*
 * For the moment this is an all-purpose lock. It serializes
 * access/modifications to bonds, access/modifications to the PASID IDR, and
 * changes to io_mm refcount as well.
 */
static DEFINE_SPINLOCK(iommu_sva_lock);

static struct mmu_notifier_ops iommu_mmu_notifier;

static struct io_mm *
io_mm_alloc(struct iommu_domain *domain, struct device *dev,
	    struct mm_struct *mm, unsigned long flags)
{
	int ret;
	int pasid;
	struct io_mm *io_mm;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	if (!domain->ops->mm_alloc || !domain->ops->mm_free)
		return ERR_PTR(-ENODEV);

	io_mm = domain->ops->mm_alloc(domain, mm, flags);
	if (IS_ERR(io_mm))
		return io_mm;
	if (!io_mm)
		return ERR_PTR(-ENOMEM);

	/*
	 * The mm must not be freed until after the driver frees the io_mm
	 * (which may involve unpinning the CPU ASID for instance, requiring a
	 * valid mm struct.)
	 */
	mmgrab(mm);

	io_mm->flags		= flags;
	io_mm->mm		= mm;
	io_mm->notifier.ops	= &iommu_mmu_notifier;
	io_mm->release		= domain->ops->mm_free;
	INIT_LIST_HEAD(&io_mm->devices);

	idr_preload(GFP_KERNEL);
	spin_lock(&iommu_sva_lock);
	pasid = idr_alloc(&iommu_pasid_idr, io_mm, param->min_pasid,
			  param->max_pasid + 1, GFP_ATOMIC);
	io_mm->pasid = pasid;
	spin_unlock(&iommu_sva_lock);
	idr_preload_end();

	if (pasid < 0) {
		ret = pasid;
		goto err_free_mm;
	}

	ret = mmu_notifier_register(&io_mm->notifier, mm);
	if (ret)
		goto err_free_pasid;

	/*
	 * Now that the MMU notifier is valid, we can allow users to grab this
	 * io_mm by setting a valid refcount. Before that it was accessible in
	 * the IDR but invalid.
	 *
	 * The following barrier ensures that users, who obtain the io_mm with
	 * kref_get_unless_zero, don't read uninitialized fields in the
	 * structure.
	 */
	smp_wmb();
	kref_init(&io_mm->kref);

	return io_mm;

err_free_pasid:
	/*
	 * Even if the io_mm is accessible from the IDR at this point, kref is
	 * 0 so no user could get a reference to it. Free it manually.
	 */
	spin_lock(&iommu_sva_lock);
	idr_remove(&iommu_pasid_idr, io_mm->pasid);
	spin_unlock(&iommu_sva_lock);

err_free_mm:
	domain->ops->mm_free(io_mm);
	mmdrop(mm);

	return ERR_PTR(ret);
}

static void io_mm_free(struct rcu_head *rcu)
{
	struct io_mm *io_mm;
	struct mm_struct *mm;

	io_mm = container_of(rcu, struct io_mm, rcu);
	mm = io_mm->mm;

	io_mm->release(io_mm);
	mmdrop(mm);
}

static void io_mm_release(struct kref *kref)
{
	struct io_mm *io_mm;

	io_mm = container_of(kref, struct io_mm, kref);
	WARN_ON(!list_empty(&io_mm->devices));

	idr_remove(&iommu_pasid_idr, io_mm->pasid);

	/*
	 * If we're being released from mm exit, the notifier callback ->release
	 * has already been called. Otherwise we don't need ->release, the io_mm
	 * isn't attached to anything anymore. Hence no_release.
	 */
	mmu_notifier_unregister_no_release(&io_mm->notifier, io_mm->mm);

	/*
	 * We can't free the structure here, because if mm exits during
	 * unbind(), then ->release might be attempting to grab the io_mm
	 * concurrently. And in the other case, if ->release is calling
	 * io_mm_release, then __mmu_notifier_release expects to still have a
	 * valid mn when returning. So free the structure when it's safe, after
	 * the RCU grace period elapsed.
	 */
	mmu_notifier_call_srcu(&io_mm->rcu, io_mm_free);
}

/*
 * Returns non-zero if a reference to the io_mm was successfully taken.
 * Returns zero if the io_mm is being freed and should not be used.
 */
static int io_mm_get_locked(struct io_mm *io_mm)
{
	if (io_mm && kref_get_unless_zero(&io_mm->kref)) {
		/*
		 * kref_get_unless_zero doesn't provide ordering for reads. This
		 * barrier pairs with the one in io_mm_alloc.
		 */
		smp_rmb();
		return 1;
	}

	return 0;
}

static void io_mm_put_locked(struct io_mm *io_mm)
{
	kref_put(&io_mm->kref, io_mm_release);
}

static void io_mm_put(struct io_mm *io_mm)
{
	spin_lock(&iommu_sva_lock);
	io_mm_put_locked(io_mm);
	spin_unlock(&iommu_sva_lock);
}

static int io_mm_attach(struct iommu_domain *domain, struct device *dev,
			struct io_mm *io_mm, void *drvdata)
{
	int ret;
	bool attach_domain = true;
	int pasid = io_mm->pasid;
	struct iommu_bond *bond, *tmp;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	if (!domain->ops->mm_attach || !domain->ops->mm_detach ||
	    !domain->ops->mm_invalidate)
		return -ENODEV;

	if (pasid > param->max_pasid || pasid < param->min_pasid)
		return -ERANGE;

	bond = kzalloc(sizeof(*bond), GFP_KERNEL);
	if (!bond)
		return -ENOMEM;

	bond->domain		= domain;
	bond->io_mm		= io_mm;
	bond->dev		= dev;
	bond->drvdata		= drvdata;
	refcount_set(&bond->refs, 1);
	init_waitqueue_head(&bond->mm_exit_wq);

	spin_lock(&iommu_sva_lock);
	/*
	 * Check if this io_mm is already bound to the domain. In which case the
	 * IOMMU driver doesn't have to install the PASID table entry.
	 */
	list_for_each_entry(tmp, &domain->mm_list, domain_head) {
		if (tmp->io_mm == io_mm) {
			attach_domain = false;
			break;
		}
	}

	ret = domain->ops->mm_attach(domain, dev, io_mm, attach_domain);
	if (ret) {
		kfree(bond);
		spin_unlock(&iommu_sva_lock);
		return ret;
	}

	list_add(&bond->mm_head, &io_mm->devices);
	list_add(&bond->domain_head, &domain->mm_list);
	list_add(&bond->dev_head, &param->mm_list);
	spin_unlock(&iommu_sva_lock);

	return 0;
}

static void io_mm_detach_locked(struct iommu_bond *bond, bool wait)
{
	struct iommu_bond *tmp;
	bool detach_domain = true;
	struct iommu_domain *domain = bond->domain;

	if (wait) {
		bool do_detach = true;
		/*
		 * If we're unbind() then we're deleting the bond no matter
		 * what. Tell the mm_exit thread that we're cleaning up, and
		 * wait until it finishes using the bond.
		 *
		 * refs is guaranteed to be one or more, otherwise it would
		 * already have been removed from the list. Check is someone is
		 * already waiting, in which case we wait but do not free.
		 */
		if (refcount_read(&bond->refs) > 1)
			do_detach = false;

		refcount_inc(&bond->refs);
		wait_event_lock_irq(bond->mm_exit_wq, !bond->mm_exit_active,
				    iommu_sva_lock);
		if (!do_detach)
			return;

	} else if (!refcount_dec_and_test(&bond->refs)) {
		/* unbind() is waiting to free the bond */
		return;
	}

	list_for_each_entry(tmp, &domain->mm_list, domain_head) {
		if (tmp->io_mm == bond->io_mm && tmp->dev != bond->dev) {
			detach_domain = false;
			break;
		}
	}

	domain->ops->mm_detach(domain, bond->dev, bond->io_mm, detach_domain);

	list_del(&bond->mm_head);
	list_del(&bond->domain_head);
	list_del(&bond->dev_head);
	io_mm_put_locked(bond->io_mm);

	kfree(bond);
}

static int iommu_signal_mm_exit(struct iommu_bond *bond)
{
	struct device *dev = bond->dev;
	struct io_mm *io_mm = bond->io_mm;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	/*
	 * We can't hold the device's param_lock. If we did and the device
	 * driver used a global lock around io_mm, we would risk getting the
	 * following deadlock:
	 *
	 *   exit_mm()                 |  Shutdown SVA
	 *    mutex_lock(param->lock)  |   mutex_lock(glob lock)
	 *     param->mm_exit()        |    sva_device_shutdown()
	 *      mutex_lock(glob lock)  |     mutex_lock(param->lock)
	 *
	 * Fortunately unbind() waits for us to finish, and sva_device_shutdown
	 * requires that any bond is removed, so we can safely access mm_exit
	 * and drvdata without taking any lock.
	 */
	if (!param || !param->mm_exit)
		return 0;

	return param->mm_exit(dev, io_mm->pasid, bond->drvdata);
}

/* Called when the mm exits. Can race with unbind(). */
static void iommu_notifier_release(struct mmu_notifier *mn,
					struct mm_struct *mm)
{
	struct iommu_bond *bond, *next;
	struct io_mm *io_mm = container_of(mn, struct io_mm, notifier);

	/*
	 * If the mm is exiting then devices are still bound to the io_mm.
	 * A few things need to be done before it is safe to release:
	 *
	 * - As the mmu notifier doesn't hold any reference to the io_mm when
	 *   calling ->release(), try to take a reference.
	 * - Tell the device driver to stop using this PASID.
	 * - Clear the PASID table and invalidate TLBs.
	 * - Drop all references to this io_mm by freeing the bonds.
	 */
	spin_lock(&iommu_sva_lock);
	if (!io_mm_get_locked(io_mm)) {
		/* Someone's already taking care of it. */
		spin_unlock(&iommu_sva_lock);
		return;
	}

	list_for_each_entry_safe(bond, next, &io_mm->devices, mm_head) {
		/*
		 * Release the lock to let the handler sleep. We need to be
		 * careful about concurrent modifications to the list and to the
		 * bond. Tell unbind() not to free the bond until we're done.
		 */
		bond->mm_exit_active = true;
		spin_unlock(&iommu_sva_lock);

		if (iommu_signal_mm_exit(bond))
			dev_WARN(bond->dev, "possible leak of PASID %u",
				 io_mm->pasid);

		iopf_queue_flush_dev(bond->dev);

		spin_lock(&iommu_sva_lock);
		next = list_next_entry(bond, mm_head);

		/* If someone is waiting, let them delete the bond now */
		bond->mm_exit_active = false;
		wake_up_all(&bond->mm_exit_wq);

		/* Otherwise, do it ourselves */
		io_mm_detach_locked(bond, false);
	}
	spin_unlock(&iommu_sva_lock);

	/*
	 * We're now reasonably certain that no more fault is being handled for
	 * this io_mm, since we just flushed them all out of the fault queue.
	 * Release the last reference to free the io_mm.
	 */
	io_mm_put(io_mm);
}

static void iommu_notifier_invalidate_range(struct mmu_notifier *mn,
					    struct mm_struct *mm,
					    unsigned long start,
					    unsigned long end)
{
	struct iommu_bond *bond;
	struct io_mm *io_mm = container_of(mn, struct io_mm, notifier);

	spin_lock(&iommu_sva_lock);
	list_for_each_entry(bond, &io_mm->devices, mm_head) {
		struct iommu_domain *domain = bond->domain;

		domain->ops->mm_invalidate(domain, bond->dev, io_mm, start,
					   end - start);
	}
	spin_unlock(&iommu_sva_lock);
}

static int iommu_notifier_clear_flush_young(struct mmu_notifier *mn,
					    struct mm_struct *mm,
					    unsigned long start,
					    unsigned long end)
{
	iommu_notifier_invalidate_range(mn, mm, start, end);
	return 0;
}

static void iommu_notifier_change_pte(struct mmu_notifier *mn,
				      struct mm_struct *mm,
				      unsigned long address, pte_t pte)
{
	iommu_notifier_invalidate_range(mn, mm, address, address + PAGE_SIZE);
}

static struct mmu_notifier_ops iommu_mmu_notifier = {
	.release		= iommu_notifier_release,
	.clear_flush_young	= iommu_notifier_clear_flush_young,
	.change_pte		= iommu_notifier_change_pte,
	.invalidate_range	= iommu_notifier_invalidate_range,
};

/**
 * iommu_sva_device_init() - Initialize Shared Virtual Addressing for a device
 * @dev: the device
 * @features: bitmask of features that need to be initialized
 * @max_pasid: max PASID value supported by the device
 * @mm_exit: callback to notify the device driver of an mm exiting
 *
 * Users of the bind()/unbind() API must call this function to initialize all
 * features required for SVA.
 *
 * The device must support multiple address spaces (e.g. PCI PASID). By default
 * the PASID allocated during bind() is limited by the IOMMU capacity, and by
 * the device PASID width defined in the PCI capability or in the firmware
 * description. Setting @max_pasid to a non-zero value smaller than this limit
 * overrides it.
 *
 * If the device should support recoverable I/O Page Faults (e.g. PCI PRI), the
 * IOMMU_SVA_FEAT_IOPF feature must be requested.
 *
 * If the driver intends to share process address spaces, it should pass a valid
 * @mm_exit handler. Otherwise @mm_exit can be NULL. After @mm_exit returns, the
 * device must not issue any more transaction with the PASID given as argument.
 * The handler gets an opaque pointer corresponding to the drvdata passed as
 * argument of bind().
 *
 * The @mm_exit handler is allowed to sleep. Be careful about the locks taken in
 * @mm_exit, because they might lead to deadlocks if they are also held when
 * dropping references to the mm. Consider the following call chain:
 *   mutex_lock(A); mmput(mm) -> exit_mm() -> @mm_exit() -> mutex_lock(A)
 * Using mmput_async() prevents this scenario.
 *
 * The device should not be performing any DMA while this function is running,
 * otherwise the behavior is undefined.
 *
 * Return 0 if initialization succeeded, or an error.
 */
int iommu_sva_device_init(struct device *dev, unsigned long features,
			  unsigned int max_pasid,
			  iommu_mm_exit_handler_t mm_exit)
{
	int ret;
	struct iommu_sva_param *param;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (!domain || !domain->ops->sva_device_init)
		return -ENODEV;

	if (features & ~IOMMU_SVA_FEAT_IOPF)
		return -EINVAL;

	if (features & IOMMU_SVA_FEAT_IOPF) {
		ret = iommu_register_device_fault_handler(dev, iommu_queue_iopf,
							  dev);
		if (ret)
			return ret;
	}

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto err_remove_handler;
	}

	param->features		= features;
	param->max_pasid	= max_pasid;
	param->mm_exit		= mm_exit;
	INIT_LIST_HEAD(&param->mm_list);

	/*
	 * IOMMU driver updates the limits depending on the IOMMU and device
	 * capabilities.
	 */
	ret = domain->ops->sva_device_init(dev, param);
	if (ret)
		goto err_free_param;

	mutex_lock(&dev->iommu_param->lock);
	if (dev->iommu_param->sva_param)
		ret = -EEXIST;
	else
		dev->iommu_param->sva_param = param;
	mutex_unlock(&dev->iommu_param->lock);
	if (ret)
		goto err_device_shutdown;

	return 0;

err_device_shutdown:
	if (domain->ops->sva_device_shutdown)
		domain->ops->sva_device_shutdown(dev, param);

err_free_param:
	kfree(param);

err_remove_handler:
	iommu_unregister_device_fault_handler(dev);

	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_device_init);

/**
 * iommu_sva_device_shutdown() - Shutdown Shared Virtual Addressing for a device
 * @dev: the device
 *
 * Disable SVA. Device driver should ensure that the device isn't performing any
 * DMA while this function is running. In addition all faults should have been
 * flushed to the IOMMU.
 */
int iommu_sva_device_shutdown(struct device *dev)
{
	struct iommu_sva_param *param;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	if (!domain)
		return -ENODEV;

	__iommu_sva_unbind_dev_all(dev);

	mutex_lock(&dev->iommu_param->lock);
	param = dev->iommu_param->sva_param;
	dev->iommu_param->sva_param = NULL;
	mutex_unlock(&dev->iommu_param->lock);
	if (!param)
		return -ENODEV;

	if (domain->ops->sva_device_shutdown)
		domain->ops->sva_device_shutdown(dev, param);

	kfree(param);

	iommu_unregister_device_fault_handler(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(iommu_sva_device_shutdown);

int __iommu_sva_bind_device(struct device *dev, struct mm_struct *mm,
			    int *pasid, unsigned long flags, void *drvdata)
{
	int i, ret = 0;
	struct io_mm *io_mm = NULL;
	struct iommu_domain *domain;
	struct iommu_bond *bond = NULL, *tmp;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return -EINVAL;

	/*
	 * The device driver does not call sva_device_init/shutdown and
	 * bind/unbind concurrently, so no need to take the param lock.
	 */
	if (WARN_ON_ONCE(!param) || (flags & ~param->features))
		return -EINVAL;

	/* If an io_mm already exists, use it */
	spin_lock(&iommu_sva_lock);
	idr_for_each_entry(&iommu_pasid_idr, io_mm, i) {
		if (io_mm->mm == mm && io_mm_get_locked(io_mm)) {
			/* ... Unless it's already bound to this device */
			list_for_each_entry(tmp, &io_mm->devices, mm_head) {
				if (tmp->dev == dev) {
					bond = tmp;
					io_mm_put_locked(io_mm);
					break;
				}
			}
			break;
		}
	}
	spin_unlock(&iommu_sva_lock);

	if (bond) {
		*pasid = bond->io_mm->pasid;
		return ret;
	}
	/* Require identical features within an io_mm for now */
	if (io_mm && (flags != io_mm->flags)) {
		io_mm_put(io_mm);
		return -EDOM;
	}

	if (!io_mm) {
		io_mm = io_mm_alloc(domain, dev, mm, flags);
		if (IS_ERR(io_mm))
			return PTR_ERR(io_mm);
	}

	ret = io_mm_attach(domain, dev, io_mm, drvdata);
	if (ret)
		io_mm_put(io_mm);
	else
		*pasid = io_mm->pasid;

	return ret;
}
EXPORT_SYMBOL_GPL(__iommu_sva_bind_device);

int __iommu_sva_unbind_device(struct device *dev, int pasid)
{
	int ret = -ESRCH;
	struct iommu_domain *domain;
	struct iommu_bond *bond = NULL;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	domain = iommu_get_domain_for_dev(dev);
	if (!param || WARN_ON(!domain))
		return -EINVAL;

	/*
	 * Caller stopped the device from issuing PASIDs, now make sure they are
	 * out of the fault queue.
	 */
	iopf_queue_flush_dev(dev);

	/* spin_lock_irq matches the one in wait_event_lock_irq */
	spin_lock_irq(&iommu_sva_lock);
	list_for_each_entry(bond, &param->mm_list, dev_head) {
		if (bond->io_mm->pasid == pasid) {
			io_mm_detach_locked(bond, true);
			ret = 0;
			break;
		}
	}
	spin_unlock_irq(&iommu_sva_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(__iommu_sva_unbind_device);

/**
 * __iommu_sva_unbind_dev_all() - Detach all address spaces from this device
 * @dev: the device
 *
 * When detaching @device from a domain, IOMMU drivers should use this helper.
 * This function may sleep while waiting for bonds to be released.
 */
void __iommu_sva_unbind_dev_all(struct device *dev)
{
	struct iommu_sva_param *param;
	struct iommu_bond *bond, *next;

	iopf_queue_flush_dev(dev);

	/*
	 * io_mm_detach_locked might wait, so we shouldn't call it with the dev
	 * param lock held. It's fine to read sva_param outside the lock because
	 * it can only be freed by iommu_sva_device_shutdown when there are no
	 * more bonds in the list.
	 */
	param = dev->iommu_param->sva_param;
	if (param) {
		spin_lock_irq(&iommu_sva_lock);
		list_for_each_entry_safe(bond, next, &param->mm_list, dev_head)
			io_mm_detach_locked(bond, true);
		spin_unlock_irq(&iommu_sva_lock);
	}
}
EXPORT_SYMBOL_GPL(__iommu_sva_unbind_dev_all);

/**
 * iommu_sva_find() - Find mm associated to the given PASID
 * @pasid: Process Address Space ID assigned to the mm
 *
 * Returns the mm corresponding to this PASID, or NULL if not found. A reference
 * to the mm is taken, and must be released with mmput().
 */
struct mm_struct *iommu_sva_find(int pasid)
{
	struct io_mm *io_mm;
	struct mm_struct *mm = NULL;

	spin_lock(&iommu_sva_lock);
	io_mm = idr_find(&iommu_pasid_idr, pasid);
	if (io_mm && io_mm_get_locked(io_mm)) {
		if (mmget_not_zero(io_mm->mm))
			mm = io_mm->mm;

		io_mm_put_locked(io_mm);
	}
	spin_unlock(&iommu_sva_lock);

	return mm;
}
EXPORT_SYMBOL_GPL(iommu_sva_find);
