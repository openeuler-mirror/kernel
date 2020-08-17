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
#include <linux/mmu_notifier.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
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

static struct mmu_notifier_ops iommu_process_mmu_notfier;

/*
 * Allocate a iommu_process structure for the given task.
 *
 * Ideally we shouldn't need the domain parameter, since iommu_process is
 * system-wide, but we use it to retrieve the driver's allocation ops and a
 * PASID range.
 */
static struct iommu_process *
iommu_process_alloc(struct iommu_domain *domain, struct task_struct *task)
{
	int err;
	int pasid;
	struct iommu_process *process;

	if (WARN_ON(!domain->ops->process_alloc || !domain->ops->process_free))
		return ERR_PTR(-ENODEV);

	process = domain->ops->process_alloc(task);
	if (IS_ERR(process))
		return process;
	if (!process)
		return ERR_PTR(-ENOMEM);

	process->pid		= get_task_pid(task, PIDTYPE_PID);
	process->mm		= get_task_mm(task);
	process->notifier.ops	= &iommu_process_mmu_notfier;
	process->release	= domain->ops->process_free;
	INIT_LIST_HEAD(&process->domains);

	if (!process->pid) {
		err = -EINVAL;
		goto err_free_process;
	}

	if (!process->mm) {
		err = -EINVAL;
		goto err_put_pid;
	}

	idr_preload(GFP_KERNEL);
	spin_lock(&iommu_process_lock);
	pasid = idr_alloc_cyclic(&iommu_process_idr, process, domain->min_pasid,
				 domain->max_pasid + 1, GFP_ATOMIC);
	process->pasid = pasid;
	spin_unlock(&iommu_process_lock);
	idr_preload_end();

	if (pasid < 0) {
		err = pasid;
		goto err_put_mm;
	}

	err = mmu_notifier_register(&process->notifier, process->mm);
	if (err)
		goto err_free_pasid;

	/*
	 * Now that the MMU notifier is valid, we can allow users to grab this
	 * process by setting a valid refcount. Before that it was accessible in
	 * the IDR but invalid.
	 *
	 * Users of the process structure obtain it with inc_not_zero, which
	 * provides a control dependency to ensure that they don't modify the
	 * structure if they didn't acquire the ref. So I think we need a write
	 * barrier here to pair with that control dependency (XXX probably
	 * nonsense.)
	 */
	smp_wmb();
	kref_init(&process->kref);

	/* A mm_count reference is kept by the notifier */
	mmput(process->mm);

	return process;

err_free_pasid:
	/*
	 * Even if the process is accessible from the IDR at this point, kref is
	 * 0 so no user could get a reference to it. Free it manually.
	 */
	spin_lock(&iommu_process_lock);
	idr_remove(&iommu_process_idr, process->pasid);
	spin_unlock(&iommu_process_lock);

err_put_mm:
	mmput(process->mm);

err_put_pid:
	put_pid(process->pid);

err_free_process:
	domain->ops->process_free(process);

	return ERR_PTR(err);
}

static void iommu_process_free(struct rcu_head *rcu)
{
	struct iommu_process *process;
	void (*release)(struct iommu_process *);

	process = container_of(rcu, struct iommu_process, rcu);
	release = process->release;

	release(process);
}

static void iommu_process_release(struct kref *kref)
{
	struct iommu_process *process;

	assert_spin_locked(&iommu_process_lock);

	process = container_of(kref, struct iommu_process, kref);
	WARN_ON(!list_empty(&process->domains));

	idr_remove(&iommu_process_idr, process->pasid);
	put_pid(process->pid);

	/*
	 * If we're being released from process exit, the notifier callback
	 * ->release has already been called. Otherwise we don't need to go
	 * through there, the process isn't attached to anything anymore. Hence
	 * no_release.
	 */
	mmu_notifier_unregister_no_release(&process->notifier, process->mm);

	/*
	 * We can't free the structure here, because ->release might be
	 * attempting to grab it concurrently. And in the other case, if the
	 * structure is being released from within ->release, then
	 * __mmu_notifier_release expects to still have a valid mn when
	 * returning. So free the structure when it's safe, after the RCU grace
	 * period elapsed.
	 */
	mmu_notifier_call_srcu(&process->rcu, iommu_process_free);
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

static int iommu_process_attach(struct iommu_domain *domain, struct device *dev,
				struct iommu_process *process)
{
	int err;
	int pasid = process->pasid;
	struct iommu_context *context;

	if (WARN_ON(!domain->ops->process_attach || !domain->ops->process_detach ||
		    !domain->ops->process_exit || !domain->ops->process_invalidate))
		return -ENODEV;

	if (pasid > domain->max_pasid || pasid < domain->min_pasid)
		return -ENOSPC;

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;

	context->process	= process;
	context->domain		= domain;
	refcount_set(&context->ref, 1);

	spin_lock(&iommu_process_lock);
	err = domain->ops->process_attach(domain, dev, process, true);
	if (err) {
		kfree(context);
		spin_unlock(&iommu_process_lock);
		return err;
	}

	list_add(&context->process_head, &process->domains);
	list_add(&context->domain_head, &domain->processes);
	spin_unlock(&iommu_process_lock);

	return 0;
}

static void iommu_context_free(struct iommu_context *context)
{
	assert_spin_locked(&iommu_process_lock);

	if (WARN_ON(!context->process || !context->domain))
		return;

	list_del(&context->process_head);
	list_del(&context->domain_head);
	iommu_process_put_locked(context->process);

	kfree(context);
}

/* Attach an existing context to the device */
static int iommu_process_attach_locked(struct iommu_context *context,
				       struct device *dev)
{
	assert_spin_locked(&iommu_process_lock);

	refcount_inc(&context->ref);
	return context->domain->ops->process_attach(context->domain, dev,
						    context->process, false);
}

/* Detach device from context and release it if necessary */
static void iommu_process_detach_locked(struct iommu_context *context,
					struct device *dev)
{
	bool last = false;
	struct iommu_domain *domain = context->domain;

	assert_spin_locked(&iommu_process_lock);

	if (refcount_dec_and_test(&context->ref))
		last = true;

	domain->ops->process_detach(domain, dev, context->process, last);

	if (last)
		iommu_context_free(context);
}

/*
 * Called when the process exits. Might race with unbind or any other function
 * dropping the last reference to the process. As the mmu notifier doesn't hold
 * any reference to the process when calling ->release, try to take a reference.
 */
static void iommu_notifier_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct iommu_context *context, *next;
	struct iommu_process *process = container_of(mn, struct iommu_process, notifier);

	/*
	 * If the process is exiting then domains are still attached to the
	 * process. A few things need to be done before it is safe to release
	 *
	 * 1) Tell the IOMMU driver to stop using this PASID (and forward the
	 *    message to attached device drivers. It can then clear the PASID
	 *    table and invalidate relevant TLBs.
	 *
	 * 2) Drop all references to this process, by freeing the contexts.
	 */
	spin_lock(&iommu_process_lock);
	if (!iommu_process_get_locked(process)) {
		/* Someone's already taking care of it. */
		spin_unlock(&iommu_process_lock);
		return;
	}

	list_for_each_entry_safe(context, next, &process->domains, process_head) {
		context->domain->ops->process_exit(context->domain, process);
		iommu_context_free(context);
	}
	spin_unlock(&iommu_process_lock);

	/*
	 * We're now reasonably certain that no more fault is being handled for
	 * this process, since we just flushed them all out of the fault queue.
	 * Release the last reference to free the process.
	 */
	iommu_process_put(process);
}

static void iommu_notifier_invalidate_range(struct mmu_notifier *mn, struct mm_struct *mm,
					    unsigned long start, unsigned long end)
{
	struct iommu_context *context;
	struct iommu_process *process = container_of(mn, struct iommu_process, notifier);

	spin_lock(&iommu_process_lock);
	list_for_each_entry(context, &process->domains, process_head) {
		context->domain->ops->process_invalidate(context->domain,
						 process, start, end - start);
	}
	spin_unlock(&iommu_process_lock);
}

static int iommu_notifier_clear_flush_young(struct mmu_notifier *mn,
					    struct mm_struct *mm,
					    unsigned long start,
					    unsigned long end)
{
	iommu_notifier_invalidate_range(mn, mm, start, end);
	return 0;
}

static void iommu_notifier_change_pte(struct mmu_notifier *mn, struct mm_struct *mm,
				      unsigned long address, pte_t pte)
{
	iommu_notifier_invalidate_range(mn, mm, address, address + PAGE_SIZE);
}

static struct mmu_notifier_ops iommu_process_mmu_notfier = {
	.release		= iommu_notifier_release,
	.clear_flush_young	= iommu_notifier_clear_flush_young,
	.change_pte		= iommu_notifier_change_pte,
	.invalidate_range	= iommu_notifier_invalidate_range,
};

/**
 * iommu_process_bind_device - Bind a process address space to a device
 * @dev: the device
 * @task: the process to bind
 * @pasid: valid address where the PASID will be stored
 * @flags: bond properties (IOMMU_PROCESS_BIND_*)
 *
 * Create a bond between device and task, allowing the device to access the
 * process address space using the returned PASID.
 *
 * On success, 0 is returned and @pasid contains a valid ID. Otherwise, an error
 * is returned.
 */
int iommu_process_bind_device(struct device *dev, struct task_struct *task,
			      int *pasid, int flags)
{
	int err, i;
	int nesting;
	struct pid *pid;
	struct iommu_domain *domain;
	struct iommu_process *process;
	struct iommu_context *cur_context;
	struct iommu_context *context = NULL;

	domain = iommu_get_domain_for_dev(dev);
	if (WARN_ON(!domain))
		return -EINVAL;

	if (!iommu_domain_get_attr(domain, DOMAIN_ATTR_NESTING, &nesting) &&
	    nesting)
		return -EINVAL;

	pid = get_task_pid(task, PIDTYPE_PID);
	if (!pid)
		return -EINVAL;

	/* If an iommu_process already exists, use it */
	spin_lock(&iommu_process_lock);
	idr_for_each_entry(&iommu_process_idr, process, i) {
		if (process->pid != pid)
			continue;

		if (!iommu_process_get_locked(process)) {
			/* Process is defunct, create a new one */
			process = NULL;
			break;
		}

		/* Great, is it also bound to this domain? */
		list_for_each_entry(cur_context, &process->domains,
				    process_head) {
			if (cur_context->domain != domain)
				continue;

			context = cur_context;
			*pasid = process->pasid;

			/* Splendid, tell the driver and increase the ref */
			err = iommu_process_attach_locked(context, dev);
			if (err)
				iommu_process_put_locked(process);

			break;
		}
		break;
	}
	spin_unlock(&iommu_process_lock);
	put_pid(pid);

	if (context)
		return err;

	if (!process) {
		process = iommu_process_alloc(domain, task);
		if (IS_ERR(process))
			return PTR_ERR(process);
	}

	err = iommu_process_attach(domain, dev, process);
	if (err) {
		iommu_process_put(process);
		return err;
	}

	*pasid = process->pasid;

	return 0;
}
EXPORT_SYMBOL_GPL(iommu_process_bind_device);

/**
 * iommu_process_unbind_device - Remove a bond created with
 * iommu_process_bind_device.
 *
 * @dev: the device
 * @pasid: the pasid returned by bind
 */
int iommu_process_unbind_device(struct device *dev, int pasid)
{
	struct iommu_domain *domain;
	struct iommu_process *process;
	struct iommu_context *cur_context;
	struct iommu_context *context = NULL;

	domain = iommu_get_domain_for_dev(dev);
	if (WARN_ON(!domain))
		return -EINVAL;

	spin_lock(&iommu_process_lock);
	process = idr_find(&iommu_process_idr, pasid);
	if (!process) {
		spin_unlock(&iommu_process_lock);
		return -ESRCH;
	}

	list_for_each_entry(cur_context, &process->domains, process_head) {
		if (cur_context->domain == domain) {
			context = cur_context;
			break;
		}
	}

	if (context)
		iommu_process_detach_locked(context, dev);
	spin_unlock(&iommu_process_lock);

	return context ? 0 : -ESRCH;
}
EXPORT_SYMBOL_GPL(iommu_process_unbind_device);

/*
 * __iommu_process_unbind_dev_all - Detach all processes attached to this
 * device.
 *
 * When detaching @device from @domain, IOMMU drivers have to use this function.
 */
void __iommu_process_unbind_dev_all(struct iommu_domain *domain, struct device *dev)
{
	struct iommu_context *context, *next;

	/* Ask device driver to stop using all PASIDs */
	spin_lock(&iommu_process_lock);
	if (domain->process_exit) {
		list_for_each_entry(context, &domain->processes, domain_head)
			domain->process_exit(domain, dev,
					     context->process->pasid,
					     domain->process_exit_token);
	}

	list_for_each_entry_safe(context, next, &domain->processes, domain_head)
		iommu_process_detach_locked(context, dev);
	spin_unlock(&iommu_process_lock);
}
EXPORT_SYMBOL_GPL(__iommu_process_unbind_dev_all);

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
