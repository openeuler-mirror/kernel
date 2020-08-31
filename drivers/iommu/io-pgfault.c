// SPDX-License-Identifier: GPL-2.0
/*
 * Handle device page faults
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

/**
 * struct iopf_queue - IO Page Fault queue
 * @wq: the fault workqueue
 * @flush: low-level flush callback
 * @flush_arg: flush() argument
 * @refs: references to this structure taken by producers
 */
struct iopf_queue {
	struct workqueue_struct		*wq;
	iopf_queue_flush_t		flush;
	void				*flush_arg;
	refcount_t			refs;
};

/**
 * struct iopf_device_param - IO Page Fault data attached to a device
 * @queue: IOPF queue
 * @partial: faults that are part of a Page Request Group for which the last
 *           request hasn't been submitted yet.
 */
struct iopf_device_param {
	struct iopf_queue		*queue;
	struct list_head		partial;
};

struct iopf_context {
	struct device			*dev;
	struct iommu_fault_event	evt;
	struct list_head		head;
};

struct iopf_group {
	struct iopf_context		last_fault;
	struct list_head		faults;
	struct work_struct		work;
};

static int enable_iopf_hipri __read_mostly;

static int iopf_complete(struct device *dev, struct iommu_fault_event *evt,
			 enum page_response_code status)
{
	struct page_response_msg resp = {
		.addr			= evt->addr,
		.pasid			= evt->pasid,
		.pasid_present		= evt->pasid_valid,
		.page_req_group_id	= evt->page_req_group_id,
		.private_data		= evt->iommu_private,
		.resp_code		= status,
	};

	return iommu_page_response(dev, &resp);
}

static enum page_response_code
iopf_handle_single(struct iopf_context *fault)
{
	int ret;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned int access_flags = 0;
	unsigned int fault_flags = FAULT_FLAG_REMOTE;
	struct iommu_fault_event *evt = &fault->evt;
	enum page_response_code status = IOMMU_PAGE_RESP_INVALID;

	if (!evt->pasid_valid)
		return status;

	mm = iommu_sva_find(evt->pasid);
	if (!mm)
		return status;

	down_read(&mm->mmap_sem);

	vma = find_extend_vma(mm, evt->addr);
	if (!vma)
		/* Unmapped area */
		goto out_put_mm;

	if (evt->prot & IOMMU_FAULT_READ)
		access_flags |= VM_READ;

	if (evt->prot & IOMMU_FAULT_WRITE) {
		access_flags |= VM_WRITE;
		fault_flags |= FAULT_FLAG_WRITE;
	}

	if (evt->prot & IOMMU_FAULT_EXEC) {
		access_flags |= VM_EXEC;
		fault_flags |= FAULT_FLAG_INSTRUCTION;
	}

	if (!(evt->prot & IOMMU_FAULT_PRIV))
		fault_flags |= FAULT_FLAG_USER;

	if (access_flags & ~vma->vm_flags)
		/* Access fault */
		goto out_put_mm;

	ret = handle_mm_fault(vma, evt->addr, fault_flags);
	status = ret & VM_FAULT_ERROR ? IOMMU_PAGE_RESP_INVALID :
		IOMMU_PAGE_RESP_SUCCESS;

out_put_mm:
	up_read(&mm->mmap_sem);

	/*
	 * If the process exits while we're handling the fault on its mm, we
	 * can't do mmput(). exit_mmap() would release the MMU notifier, calling
	 * iommu_notifier_release(), which has to flush the fault queue that
	 * we're executing on... So mmput_async() moves the release of the mm to
	 * another thread, if we're the last user.
	 */
	mmput_async(mm);

	return status;
}

static void iopf_handle_group(struct work_struct *work)
{
	struct iopf_group *group;
	struct iopf_context *fault, *next;
	enum page_response_code status = IOMMU_PAGE_RESP_SUCCESS;

	group = container_of(work, struct iopf_group, work);

	list_for_each_entry_safe(fault, next, &group->faults, head) {
		struct iommu_fault_event *evt = &fault->evt;
		/*
		 * Errors are sticky: don't handle subsequent faults in the
		 * group if there is an error.
		 */
		if (status == IOMMU_PAGE_RESP_SUCCESS)
			status = iopf_handle_single(fault);

		if (!evt->last_req)
			kfree(fault);
	}

	iopf_complete(group->last_fault.dev, &group->last_fault.evt, status);
	kfree(group);
}

/**
 * iommu_queue_iopf - IO Page Fault handler
 * @evt: fault event
 * @cookie: struct device, passed to iommu_register_device_fault_handler.
 *
 * Add a fault to the device workqueue, to be handled by mm.
 *
 * This module doesn't handle PCI PASID Stop Marker; IOMMU drivers must discard
 * them before reporting faults. A PASID Stop Marker (LRW = 0b100) doesn't
 * expect a response. It may be generated when disabling a PASID (issuing a
 * PASID stop request) by some PCI devices.
 *
 * The PASID stop request is triggered by the mm_exit() callback. When the
 * callback returns from the device driver, no page request is generated for
 * this PASID anymore and outstanding ones have been pushed to the IOMMU (as per
 * PCIe 4.0r1.0 - 6.20.1 and 10.4.1.2 - Managing PASID TLP Prefix Usage). Some
 * PCI devices will wait for all outstanding page requests to come back with a
 * response before completing the PASID stop request. Others do not wait for
 * page responses, and instead issue this Stop Marker that tells us when the
 * PASID can be reallocated.
 *
 * It is safe to discard the Stop Marker because it is an optimization.
 * a. Page requests, which are posted requests, have been flushed to the IOMMU
 *    when mm_exit() returns,
 * b. We flush all fault queues after mm_exit() returns and before freeing the
 *    PASID.
 *
 * So even though the Stop Marker might be issued by the device *after* the stop
 * request completes, outstanding faults will have been dealt with by the time
 * we free the PASID.
 */
int iommu_queue_iopf(struct iommu_fault_event *evt, void *cookie)
{
	struct iopf_group *group;
	struct iopf_context *fault, *next;
	struct iopf_device_param *iopf_param;

	struct device *dev = cookie;
	struct iommu_param *param = dev->iommu_param;

	if (WARN_ON(!mutex_is_locked(&param->lock)))
		return -EINVAL;

	if (evt->type != IOMMU_FAULT_PAGE_REQ)
		/* Not a recoverable page fault */
		return IOMMU_PAGE_RESP_CONTINUE;

	/*
	 * As long as we're holding param->lock, the queue can't be unlinked
	 * from the device and therefore cannot disappear.
	 */
	iopf_param = param->iopf_param;
	if (!iopf_param)
		return -ENODEV;

	if (!evt->last_req) {
		fault = kzalloc(sizeof(*fault), GFP_KERNEL);
		if (!fault)
			return -ENOMEM;

		fault->evt = *evt;
		fault->dev = dev;

		/* Non-last request of a group. Postpone until the last one */
		list_add(&fault->head, &iopf_param->partial);

		return IOMMU_PAGE_RESP_HANDLED;
	}

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return -ENOMEM;

	group->last_fault.evt = *evt;
	group->last_fault.dev = dev;
	INIT_LIST_HEAD(&group->faults);
	list_add(&group->last_fault.head, &group->faults);
	INIT_WORK(&group->work, iopf_handle_group);

	/* See if we have partial faults for this group */
	list_for_each_entry_safe(fault, next, &iopf_param->partial, head) {
		if (fault->evt.page_req_group_id == evt->page_req_group_id)
			/* Insert *before* the last fault */
			list_move(&fault->head, &group->faults);
	}

	queue_work(iopf_param->queue->wq, &group->work);

	/* Postpone the fault completion */
	return IOMMU_PAGE_RESP_HANDLED;
}
EXPORT_SYMBOL_GPL(iommu_queue_iopf);

/**
 * iopf_queue_flush_dev - Ensure that all queued faults have been processed
 * @dev: the endpoint whose faults need to be flushed.
 *
 * Users must call this function when releasing a PASID, to ensure that all
 * pending faults for this PASID have been handled, and won't hit the address
 * space of the next process that uses this PASID.
 *
 * Return 0 on success.
 */
int iopf_queue_flush_dev(struct device *dev)
{
	int ret = 0;
	struct iopf_queue *queue;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return -ENODEV;

	/*
	 * It is incredibly easy to find ourselves in a deadlock situation if
	 * we're not careful, because we're taking the opposite path as
	 * iommu_queue_iopf:
	 *
	 *   iopf_queue_flush_dev()   |  PRI queue handler
	 *    lock(mutex)             |   iommu_queue_iopf()
	 *     queue->flush()         |    lock(mutex)
	 *      wait PRI queue empty  |
	 *
	 * So we can't hold the device param lock while flushing. We don't have
	 * to, because the queue or the device won't disappear until all flush
	 * are finished.
	 */
	mutex_lock(&param->lock);
	if (param->iopf_param)
		queue = param->iopf_param->queue;
	else
		ret = -ENODEV;
	mutex_unlock(&param->lock);
	if (ret)
		return ret;

	queue->flush(queue->flush_arg, dev);

	/*
	 * No need to clear the partial list. All PRGs containing the PASID that
	 * needs to be decommissioned are whole (the device driver made sure of
	 * it before this function was called). They have been submitted to the
	 * queue by the above flush().
	 */
	flush_workqueue(queue->wq);

	return 0;
}
EXPORT_SYMBOL_GPL(iopf_queue_flush_dev);

/**
 * iopf_queue_add_device - Add producer to the fault queue
 * @queue: IOPF queue
 * @dev: device to add
 */
int iopf_queue_add_device(struct iopf_queue *queue, struct device *dev)
{
	int ret = -EINVAL;
	struct iopf_device_param *iopf_param;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return -ENODEV;

	iopf_param = kzalloc(sizeof(*iopf_param), GFP_KERNEL);
	if (!iopf_param)
		return -ENOMEM;

	INIT_LIST_HEAD(&iopf_param->partial);
	iopf_param->queue = queue;

	mutex_lock(&param->lock);
	if (!param->iopf_param) {
		refcount_inc(&queue->refs);
		param->iopf_param = iopf_param;
		ret = 0;
	}
	mutex_unlock(&param->lock);

	if (ret)
		kfree(iopf_param);

	return ret;
}
EXPORT_SYMBOL_GPL(iopf_queue_add_device);

/**
 * iopf_queue_remove_device - Remove producer from fault queue
 * @dev: device to remove
 *
 * Caller makes sure that no more fault is reported for this device, and no more
 * flush is scheduled for this device.
 *
 * Note: safe to call unconditionally on a cleanup path, even if the device
 * isn't registered to any IOPF queue.
 *
 * Return 0 if the device was attached to the IOPF queue
 */
int iopf_queue_remove_device(struct device *dev)
{
	struct iopf_context *fault, *next;
	struct iopf_device_param *iopf_param;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return -EINVAL;

	mutex_lock(&param->lock);
	iopf_param = param->iopf_param;
	if (iopf_param) {
		refcount_dec(&iopf_param->queue->refs);
		param->iopf_param = NULL;
	}
	mutex_unlock(&param->lock);
	if (!iopf_param)
		return -EINVAL;

	list_for_each_entry_safe(fault, next, &iopf_param->partial, head)
		kfree(fault);

	/*
	 * No more flush is scheduled, and the caller removed all bonds from
	 * this device. unbind() waited until any concurrent mm_exit() finished,
	 * therefore there is no flush() running anymore and we can free the
	 * param.
	 */
	kfree(iopf_param);

	return 0;
}
EXPORT_SYMBOL_GPL(iopf_queue_remove_device);

/**
 * iopf_queue_alloc - Allocate and initialize a fault queue
 * @name: a unique string identifying the queue (for workqueue)
 * @flush: a callback that flushes the low-level queue
 * @cookie: driver-private data passed to the flush callback
 *
 * The callback is called before the workqueue is flushed. The IOMMU driver must
 * commit all faults that are pending in its low-level queues at the time of the
 * call, into the IOPF queue (with iommu_report_device_fault). The callback
 * takes a device pointer as argument, hinting what endpoint is causing the
 * flush. When the device is NULL, all faults should be committed.
 */
struct iopf_queue *
iopf_queue_alloc(const char *name, iopf_queue_flush_t flush, void *cookie)
{
	struct iopf_queue *queue;
	unsigned int type = WQ_UNBOUND;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return NULL;

	/*
	 * The WQ is unordered because the low-level handler enqueues faults by
	 * group. PRI requests within a group have to be ordered, but once
	 * that's dealt with, the high-level function can handle groups out of
	 * order.
	 */
	if (enable_iopf_hipri)
		type = WQ_HIGHPRI;

	queue->wq = alloc_workqueue("iopf_queue/%s", type, 0, name);
	if (!queue->wq) {
		kfree(queue);
		return NULL;
	}

	queue->flush = flush;
	queue->flush_arg = cookie;
	refcount_set(&queue->refs, 1);

	return queue;
}
EXPORT_SYMBOL_GPL(iopf_queue_alloc);

/**
 * iopf_queue_free - Free IOPF queue
 * @queue: queue to free
 *
 * Counterpart to iopf_queue_alloc(). Caller must make sure that all producers
 * have been removed.
 */
void iopf_queue_free(struct iopf_queue *queue)
{

	/* Caller should have removed all producers first */
	if (WARN_ON(!refcount_dec_and_test(&queue->refs)))
		return;

	destroy_workqueue(queue->wq);
	kfree(queue);
}
EXPORT_SYMBOL_GPL(iopf_queue_free);

#ifdef CONFIG_ASCEND_IOPF_HIPRI

static int __init ascend_enable_iopf_hipri(char *s)
{
	enable_iopf_hipri = 1;

	pr_info("Ascend enable iopf workqueue highpri\n");

	return 1;
}
__setup("enable_iopf_hipri", ascend_enable_iopf_hipri);

#endif
