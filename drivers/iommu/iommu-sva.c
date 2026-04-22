// SPDX-License-Identifier: GPL-2.0
/*
 * Helpers for IOMMU drivers implementing SVA
 */
#include <linux/mmu_context.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/iommu.h>

#include "iommu-priv.h"

static DEFINE_MUTEX(iommu_sva_lock);
static DEFINE_MUTEX(iommu_sva_grant_lock);
static struct iommu_domain *iommu_sva_domain_alloc(struct device *dev,
						   struct mm_struct *mm);

/* Allocate a PASID for the mm within range (inclusive) */
static struct iommu_mm_data *iommu_alloc_mm_data(struct mm_struct *mm, struct device *dev)
{
	struct iommu_mm_data *iommu_mm;
	ioasid_t pasid;

	lockdep_assert_held(&iommu_sva_lock);

	if (!arch_pgtable_dma_compat(mm))
		return ERR_PTR(-EBUSY);

	iommu_mm = mm->iommu_mm;
	/* Is a PASID already associated with this mm? */
	if (iommu_mm) {
		if (iommu_mm->pasid >= dev->iommu->max_pasids)
			return ERR_PTR(-EOVERFLOW);
		return iommu_mm;
	}

	iommu_mm = kzalloc(sizeof(struct iommu_mm_data), GFP_KERNEL);
	if (!iommu_mm)
		return ERR_PTR(-ENOMEM);

	pasid = iommu_alloc_global_pasid(dev);
	if (pasid == IOMMU_PASID_INVALID) {
		kfree(iommu_mm);
		return ERR_PTR(-ENOSPC);
	}
	iommu_mm->pasid = pasid;
	INIT_LIST_HEAD(&iommu_mm->sva_domains);
	/*
	 * Make sure the write to mm->iommu_mm is not reordered in front of
	 * initialization to iommu_mm fields. If it does, readers may see a
	 * valid iommu_mm with uninitialized values.
	 */
	smp_store_release(&mm->iommu_mm, iommu_mm);
	return iommu_mm;
}

/**
 * iommu_sva_bind_device() - Bind a process address space to a device
 * @dev: the device
 * @mm: the mm to bind, caller must hold a reference to mm_users
 *
 * Create a bond between device and address space, allowing the device to
 * access the mm using the PASID returned by iommu_sva_get_pasid(). If a
 * bond already exists between @device and @mm, an additional internal
 * reference is taken. Caller must call iommu_sva_unbind_device()
 * to release each reference.
 *
 * iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA) must be called first, to
 * initialize the required SVA features.
 *
 * On error, returns an ERR_PTR value.
 */
struct iommu_sva *iommu_sva_bind_device(struct device *dev, struct mm_struct *mm)
{
	struct iommu_group *group = dev->iommu_group;
	struct iommu_attach_handle *attach_handle;
	struct iommu_mm_data *iommu_mm;
	struct iommu_domain *domain;
	struct iommu_sva *handle;
	int ret;

	if (!group)
		return ERR_PTR(-ENODEV);

	if (IS_ENABLED(CONFIG_X86))
		return ERR_PTR(-EOPNOTSUPP);

	if (IS_ENABLED(CONFIG_X86))
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&iommu_sva_lock);

	/* Allocate mm->pasid if necessary. */
	iommu_mm = iommu_alloc_mm_data(mm, dev);
	if (IS_ERR(iommu_mm)) {
		ret = PTR_ERR(iommu_mm);
		goto out_unlock;
	}

	/* A bond already exists, just take a reference`. */
	attach_handle = iommu_attach_handle_get(group, iommu_mm->pasid, IOMMU_DOMAIN_SVA);
	if (!IS_ERR(attach_handle)) {
		handle = container_of(attach_handle, struct iommu_sva, handle);
		if (attach_handle->domain->mm != mm) {
			ret = -EBUSY;
			goto out_unlock;
		}
		refcount_inc(&handle->users);
		mutex_unlock(&iommu_sva_lock);
		return handle;
	}

	if (PTR_ERR(attach_handle) != -ENOENT) {
		ret = PTR_ERR(attach_handle);
		goto out_unlock;
	}

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* Search for an existing domain. */
	list_for_each_entry(domain, &mm->iommu_mm->sva_domains, next) {
		ret = iommu_attach_device_pasid(domain, dev, iommu_mm->pasid,
						&handle->handle);
		if (!ret) {
			domain->users++;
			goto out;
		}
	}

	/* Allocate a new domain and set it on device pasid. */
	domain = iommu_sva_domain_alloc(dev, mm);
	if (IS_ERR(domain)) {
		ret = PTR_ERR(domain);
		goto out_free_handle;
	}

	ret = iommu_attach_device_pasid(domain, dev, iommu_mm->pasid,
					&handle->handle);
	if (ret)
		goto out_free_domain;
	domain->users = 1;
	list_add(&domain->next, &mm->iommu_mm->sva_domains);

out:
	refcount_set(&handle->users, 1);
	mutex_unlock(&iommu_sva_lock);
	handle->dev = dev;
	return handle;

out_free_domain:
	iommu_domain_free(domain);
out_free_handle:
	kfree(handle);
out_unlock:
	mutex_unlock(&iommu_sva_lock);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(iommu_sva_bind_device);

/**
 * iommu_sva_unbind_device() - Remove a bond created with iommu_sva_bind_device
 * @handle: the handle returned by iommu_sva_bind_device()
 *
 * Put reference to a bond between device and address space. The device should
 * not be issuing any more transaction for this PASID. All outstanding page
 * requests for this PASID must have been flushed to the IOMMU.
 */
void iommu_sva_unbind_device(struct iommu_sva *handle)
{
	struct iommu_domain *domain = handle->handle.domain;
	struct iommu_mm_data *iommu_mm = domain->mm->iommu_mm;
	struct device *dev = handle->dev;

	mutex_lock(&iommu_sva_lock);
	if (!refcount_dec_and_test(&handle->users)) {
		mutex_unlock(&iommu_sva_lock);
		return;
	}

	iommu_detach_device_pasid(domain, dev, iommu_mm->pasid);
	if (--domain->users == 0) {
		list_del(&domain->next);
		iommu_domain_free(domain);
	}
	mutex_unlock(&iommu_sva_lock);
	kfree(handle);
}
EXPORT_SYMBOL_GPL(iommu_sva_unbind_device);

u32 iommu_sva_get_pasid(struct iommu_sva *handle)
{
	struct iommu_domain *domain = handle->handle.domain;

	return mm_get_enqcmd_pasid(domain->mm);
}
EXPORT_SYMBOL_GPL(iommu_sva_get_pasid);

void mm_pasid_drop(struct mm_struct *mm)
{
	struct iommu_mm_data *iommu_mm = mm->iommu_mm;

	if (!iommu_mm)
		return;

	iommu_free_global_pasid(iommu_mm->pasid);
	kfree(iommu_mm);
}

/*
 * I/O page fault handler for SVA
 */
static enum iommu_page_response_code
iommu_sva_handle_mm(struct iommu_fault *fault, struct mm_struct *mm)
{
	vm_fault_t ret;
	struct vm_area_struct *vma;
	unsigned int access_flags = 0;
	unsigned int fault_flags = FAULT_FLAG_REMOTE;
	struct iommu_fault_page_request *prm = &fault->prm;
	enum iommu_page_response_code status = IOMMU_PAGE_RESP_INVALID;

	if (!(prm->flags & IOMMU_FAULT_PAGE_REQUEST_PASID_VALID))
		return status;

	if (!mmget_not_zero(mm))
		return status;

	mmap_read_lock(mm);

	vma = vma_lookup(mm, prm->addr);
	if (!vma)
		/* Unmapped area */
		goto out_put_mm;

	if (prm->perm & IOMMU_FAULT_PERM_READ)
		access_flags |= VM_READ;

	if (prm->perm & IOMMU_FAULT_PERM_WRITE) {
		access_flags |= VM_WRITE;
		fault_flags |= FAULT_FLAG_WRITE;
	}

	if (prm->perm & IOMMU_FAULT_PERM_EXEC) {
		access_flags |= VM_EXEC;
		fault_flags |= FAULT_FLAG_INSTRUCTION;
	}

	if (!(prm->perm & IOMMU_FAULT_PERM_PRIV))
		fault_flags |= FAULT_FLAG_USER;

	if (access_flags & ~vma->vm_flags)
		/* Access fault */
		goto out_put_mm;

	ret = handle_mm_fault(vma, prm->addr, fault_flags, NULL);
	status = ret & VM_FAULT_ERROR ? IOMMU_PAGE_RESP_INVALID :
		IOMMU_PAGE_RESP_SUCCESS;

out_put_mm:
	mmap_read_unlock(mm);
	mmput(mm);

	return status;
}

static void iommu_sva_handle_iopf(struct work_struct *work)
{
	struct iopf_fault *iopf;
	struct iopf_group *group;
	enum iommu_page_response_code status = IOMMU_PAGE_RESP_SUCCESS;

	group = container_of(work, struct iopf_group, work);
	list_for_each_entry(iopf, &group->faults, list) {
		/*
		 * For the moment, errors are sticky: don't handle subsequent
		 * faults in the group if there is an error.
		 */
		if (status != IOMMU_PAGE_RESP_SUCCESS)
			break;

		status = iommu_sva_handle_mm(&iopf->fault,
					     group->attach_handle->domain->mm);
	}

	iopf_group_response(group, status);
	iopf_free_group(group);
}

static int iommu_sva_iopf_handler(struct iopf_group *group)
{
	struct iommu_fault_param *fault_param = group->fault_param;

	INIT_WORK(&group->work, iommu_sva_handle_iopf);
	if (!queue_work(fault_param->queue->wq, &group->work))
		return -EBUSY;

	return 0;
}

static struct iommu_domain *iommu_sva_domain_alloc(struct device *dev,
						   struct mm_struct *mm)
{
	const struct iommu_ops *ops = dev_iommu_ops(dev);
	struct iommu_domain *domain;

	if (ops->domain_alloc_sva) {
		domain = ops->domain_alloc_sva(dev, mm);
		if (IS_ERR(domain))
			return domain;
	} else {
		domain = ops->domain_alloc(IOMMU_DOMAIN_SVA);
		if (!domain)
			return ERR_PTR(-ENOMEM);
	}

	domain->type = IOMMU_DOMAIN_SVA;
	mmgrab(mm);
	domain->mm = mm;
	domain->owner = ops;
	domain->iopf_handler = iommu_sva_iopf_handler;
#ifdef CONFIG_IOMMU_KSVA
	domain->isolated_pasid = IOMMU_NO_PASID;
	if (iommu_is_ksva_domain(domain))
		domain->iopf_handler = NULL;
#endif

	return domain;
}

#ifdef CONFIG_IOMMU_KSVA
/**
 * iommu_sva_bind_device_isolated() - Create a isolated sva bond.
 * @dev: the device to bind
 * @mm: the memory management structure to bind
 * @data: driver-specific data for the binding domain
 *
 * This function is an extension of iommu_sva_bind_device.
 * Unlike the latter, which may reuse the binding, this function creates a
 * isolated binding between the device and the process address space. It
 * allocates a non shareable PASID for the binding. IOMMU Drivers can use the
 * provided `data` to configure the binding context.
 *
 * Notice:
 * 1. The PASID is not stored in the `mm` struct. Multiple PASIDs may be bond to
 *    the same process address space, making this function incompatible with `enqcmd`.
 * 2. The PASID is released during the unbinding process. The device must stop
 *    using the PASID before calling `iommu_sva_unbind_device()`.
 *
 * On error, returns an ERR_PTR value.
 */
struct iommu_sva *iommu_sva_bind_device_isolated(struct device *dev,
					    struct mm_struct *mm,
					    void *data)
{
	struct iommu_group *group = dev->iommu_group;
	struct iommu_domain *domain;
	struct iommu_sva *handle;
	u32 pasid;
	int ret;

	if (!group)
		return ERR_PTR(-ENODEV);

	mutex_lock(&iommu_sva_lock);
	pasid = iommu_alloc_global_pasid(dev);
	if (pasid == IOMMU_PASID_INVALID) {
		ret = -ENOSPC;
		goto out_unlock;
	}

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle) {
		ret = -ENOMEM;
		goto out_release_pasid;
	}

	/* Allocate a new domain and set it on device pasid. */
	domain = iommu_sva_domain_alloc(dev, mm);
	if (IS_ERR(domain)) {
		ret = PTR_ERR(domain);
		goto out_free_handle;
	}
	domain->sva_data = data;
	domain->isolated_pasid = pasid;
	ret = iommu_attach_device_pasid(domain, dev, pasid, &handle->handle);
	if (ret)
		goto out_free_domain;

	mutex_unlock(&iommu_sva_lock);
	handle->dev = dev;
	return handle;

out_free_domain:
	iommu_domain_free(domain);
out_free_handle:
	kfree(handle);
out_release_pasid:
	iommu_free_global_pasid(pasid);
out_unlock:
	mutex_unlock(&iommu_sva_lock);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(iommu_sva_bind_device_isolated);

/**
 * iommu_sva_unbind_device_isolated() - Remove a bond created with isolated bond
 * @handle: the handle returned by iommu_sva_unbind_device_isolated()
 *
 * Release the bond and related private pasid.
 */
void iommu_sva_unbind_device_isolated(struct iommu_sva *handle)
{
	struct iommu_domain *domain = handle->handle.domain;
	struct device *dev = handle->dev;

	mutex_lock(&iommu_sva_lock);
	iommu_detach_device_pasid(domain, dev, domain->isolated_pasid);
	iommu_free_global_pasid(domain->isolated_pasid);
	iommu_domain_free(domain);
	mutex_unlock(&iommu_sva_lock);
	kfree(handle);
}
EXPORT_SYMBOL_GPL(iommu_sva_unbind_device_isolated);

/**
 * iommu_ksva_bind_device() - Create a bond for the kernel address space and a
 *			      device.
 * @dev: the device to bind
 * @data: driver-specific data for this binding
 *
 * This function lets devices safely access the kernel address space by an
 * isolated pasid provided by iommu_sva_bind_device_ioslated. The access is
 * protected by permisson grant operations.
 *
 * On error, returns an ERR_PTR value.
 */
struct iommu_sva *iommu_ksva_bind_device(struct device *dev, void *data)
{
	const struct iommu_perm_ops *perm_ops;
	struct iommu_sva *handle;

	handle = iommu_sva_bind_device_isolated(dev, &init_mm, data);
	if (IS_ERR(handle))
		return handle;

	perm_ops = handle->handle.domain->perm_ops;
	if (!perm_ops || !perm_ops->grant || !perm_ops->ungrant) {
		iommu_ksva_unbind_device(handle);
		return ERR_PTR(-EOPNOTSUPP);
	}

	return handle;
}
EXPORT_SYMBOL_GPL(iommu_ksva_bind_device);

/**
 * iommu_ksva_unbind_device() - Remove a ksva bond created with isolated bond
 * @handle: the handle returned by iommu_ksva_bind_device()
 *
 * Release the bond and related private pasid.
 */
void iommu_ksva_unbind_device(struct iommu_sva *handle)
{
	struct iommu_domain *domain = handle->handle.domain;

	if (WARN_ON(domain->mm != &init_mm))
		return;

	iommu_sva_unbind_device_isolated(handle);
}
EXPORT_SYMBOL_GPL(iommu_ksva_unbind_device);

u32 iommu_sva_get_isolated_pasid(struct iommu_sva *handle)
{
	struct iommu_domain *domain = handle->handle.domain;

	return domain->isolated_pasid;
}
EXPORT_SYMBOL_GPL(iommu_sva_get_isolated_pasid);

/**
 * iommu_sva_grant() - grant sva access permission with specific cookie
 * @sva: iommu sva handler
 * @va: grant va/kva
 * @size: grant size
 * @perm: the access permission. drivers define permission type/value.
 * @cookie: grant with specific cookie.
 *
 */
int iommu_sva_grant(struct iommu_sva *sva, void *va, size_t size, int perm,
		    void *cookie)
{
	struct iommu_domain *domain = sva->handle.domain;
	struct iommu_plb_gather plb_gather;
	int ret;

	if (!domain->perm_ops || !domain->perm_ops->grant)
		return -EOPNOTSUPP;

	mutex_lock(&iommu_sva_grant_lock);
	ret = domain->perm_ops->grant(domain, va, size, perm, cookie,
					&plb_gather);
	iommu_plb_sync(domain, &plb_gather);

	mutex_unlock(&iommu_sva_grant_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_grant);

int iommu_sva_ungrant(struct iommu_sva *sva, void *va, size_t size,
		      void *cookie)
{
	struct iommu_domain *domain = sva->handle.domain;
	struct iommu_plb_gather plb_gather;
	int ret;

	if (!domain->perm_ops || !domain->perm_ops->ungrant)
		return -EOPNOTSUPP;

	mutex_lock(&iommu_sva_grant_lock);
	ret = domain->perm_ops->ungrant(domain, va, size, cookie,
					&plb_gather);
	iommu_plb_sync(domain, &plb_gather);

	mutex_unlock(&iommu_sva_grant_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_ungrant);

bool iommu_is_ksva_domain(struct iommu_domain *domain)
{
	return domain->mm == &init_mm;
}
EXPORT_SYMBOL_GPL(iommu_is_ksva_domain);
#endif
