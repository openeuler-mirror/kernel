// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018 HiSilicon Limited. */
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/irqdomain.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uacce.h>
#include <linux/wait.h>

/*
 * This will set the page mapping to user space without page fault.
 *
 * fixme: make it as a config item when it is mature
 * If this is ok in practice, we can change the queue lock to semaphore
 */
#define CONFIG_UACCE_FIX_MMAP

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;

/* lock to protect all queues management */
#ifdef CONFIG_UACCE_FIX_MMAP
static DECLARE_RWSEM(uacce_qs_lock);
#define uacce_qs_rlock() down_read(&uacce_qs_lock)
#define uacce_qs_runlock() up_read(&uacce_qs_lock)
#define uacce_qs_wlock() down_write(&uacce_qs_lock)
#define uacce_qs_wunlock() up_write(&uacce_qs_lock)
#else
static DEFINE_RWLOCK(uacce_qs_lock);
#define uacce_qs_rlock() read_lock_irq(&uacce_qs_lock)
#define uacce_qs_runlock() read_unlock_irq(&uacce_qs_lock)
#define uacce_qs_wlock() write_lock_irq(&uacce_qs_lock)
#define uacce_qs_wunlock() write_unlock_irq(&uacce_qs_lock)
#endif

#define UACCE_RESET_DELAY_MS        10

static const struct file_operations uacce_fops;
static int uacce_fops_fasync(int fd, struct file *file, int mode);
static long uacce_put_queue(struct uacce_queue *q);

/* match with enum uacce_qfrt */
static const char *const qfrt_str[] = {
	"mmio",
	"dko",
	"dus",
	"ss",
	"invalid"
};

const char *uacce_qfrt_str(struct uacce_qfile_region *qfr)
{
	enum uacce_qfrt type = qfr->type;

	if (type > UACCE_QFRT_INVALID)
		type = UACCE_QFRT_INVALID;

	return qfrt_str[type];
}
EXPORT_SYMBOL_GPL(uacce_qfrt_str);

/**
 * uacce_send_sig_to_client - notify users uacce_queue should be released.
 * @q: the uacce_queue which will be stopped.
 *
 * This function sends signal to process which is using uacce_queue.
 *
 * Note: This function can be called in low level driver, which may bring a race
 *       with uacce_fops_release. The problem is this function may be called
 *       when q is NULL. Low level driver should avoid this by locking hardware
 *       queue pool and check if there is related hardware queue before calling
 *       this function.
 *
 *       And from view of uacce_queue state, uacce_queue state does not be
 *       changed. Operation of queue should also be protected by low level
 *       driver.
 */
void uacce_send_sig_to_client(struct uacce_queue *q)
{
	if (!q)
		return;

	kill_fasync(&q->async_queue, SIGIO, POLL_IN);
}
EXPORT_SYMBOL_GPL(uacce_send_sig_to_client);

/**
 * uacce_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	dev_dbg(&q->uacce->dev, "wake up\n");
	wake_up_interruptible(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static bool uacce_q_avail_ioctl(struct uacce_queue *q, unsigned int cmd)
{
	enum uacce_q_state state = q->state;
	bool avail = false;

	switch (state) {
	case UACCE_Q_INIT:
		switch (cmd) {
		case UACCE_CMD_SHARE_SVAS:
		case UACCE_CMD_GET_SS_DMA:
		case UACCE_CMD_PUT_Q:
			avail = true;
			break;
		case UACCE_CMD_START:
			if (q->qfrs[UACCE_QFRT_MMIO] &&
			    q->qfrs[UACCE_QFRT_DUS])
				avail = true;
			break;
		/* acc specific ioctl */
		default:
			avail = true;
		}
		break;
	case UACCE_Q_STARTED:
		switch (cmd) {
		case UACCE_CMD_SHARE_SVAS:
		case UACCE_CMD_GET_SS_DMA:
		case UACCE_CMD_PUT_Q:
			avail = true;
			break;
		case UACCE_CMD_START:
			break;
		default:
			avail = true;
		}
		break;
	case UACCE_Q_ZOMBIE:
		break;
	default:
		break;
	}

	return avail;
}

static bool uacce_q_avail_mmap(struct uacce_queue *q, unsigned int type)
{
	enum uacce_q_state state = q->state;
	bool avail = false;

	switch (state) {
	case UACCE_Q_INIT:
		avail = true;
		break;
	case UACCE_Q_STARTED:
		switch (type) {
		case UACCE_QFRT_DKO:
		/* fix me: ss map should be done before start queue */
		case UACCE_QFRT_SS:
			avail = true;
			break;
		case UACCE_QFRT_MMIO:
		case UACCE_QFRT_DUS:
		default:
			break;
		}
		break;
	case UACCE_Q_ZOMBIE:
		break;
	default:
		break;
	}

	return avail;
}

static inline int uacce_iommu_map_qfr(struct uacce_queue *q,
				      struct uacce_qfile_region *qfr)
{
	struct device *dev = q->uacce->pdev;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i, j, ret;

	if (!domain)
		return -ENODEV;

	for (i = 0; i < qfr->nr_pages; i++) {
		ret = iommu_map(domain, qfr->iova + i * PAGE_SIZE,
				page_to_phys(qfr->pages[i]),
				PAGE_SIZE, qfr->prot | q->uacce->prot);
		if (ret) {
			dev_err(dev, "iommu_map page %i fail %d\n", i, ret);
			goto err_with_map_pages;
		}
		get_page(qfr->pages[i]);
	}

	return 0;

err_with_map_pages:
	for (j = i - 1; j >= 0; j--) {
		iommu_unmap(domain, qfr->iova + j * PAGE_SIZE, PAGE_SIZE);
		put_page(qfr->pages[j]);
	}
	return ret;
}

static inline void uacce_iommu_unmap_qfr(struct uacce_queue *q,
					 struct uacce_qfile_region *qfr)
{
	struct device *dev = q->uacce->pdev;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i;

	if (!domain || !qfr)
		return;

	for (i = qfr->nr_pages - 1; i >= 0; i--) {
		iommu_unmap(domain, qfr->iova + i * PAGE_SIZE, PAGE_SIZE);
		put_page(qfr->pages[i]);
	}
}

static int uacce_queue_map_qfr(struct uacce_queue *q,
			       struct uacce_qfile_region *qfr)
{
	if (!(qfr->flags & UACCE_QFRF_MAP) || (qfr->flags & UACCE_QFRF_DMA))
		return 0;

	dev_dbg(&q->uacce->dev, "queue map %s qfr(npage=%d, iova=%lx)\n",
		uacce_qfrt_str(qfr), qfr->nr_pages, qfr->iova);

	return uacce_iommu_map_qfr(q, qfr);
}

static void uacce_queue_unmap_qfr(struct uacce_queue *q,
				  struct uacce_qfile_region *qfr)
{
	if (!(qfr->flags & UACCE_QFRF_MAP) || (qfr->flags & UACCE_QFRF_DMA))
		return;

	dev_dbg(&q->uacce->dev, "queue map %s qfr(npage=%d, iova=%lx)\n",
		uacce_qfrt_str(qfr), qfr->nr_pages, qfr->iova);

	uacce_iommu_unmap_qfr(q, qfr);
}

static vm_fault_t uacce_shm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct uacce_qfile_region *qfr;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	int ret;

	uacce_qs_rlock();

	qfr = vma->vm_private_data;
	if (!qfr) {
		pr_info("this page is not valid to user space\n");
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	pr_debug("uacce: fault on %s qfr page %ld/%d\n", uacce_qfrt_str(qfr),
		 page_offset, qfr->nr_pages);

	if (page_offset >= qfr->nr_pages) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	get_page(qfr->pages[page_offset]);
	vmf->page = qfr->pages[page_offset];
	ret = 0;

out:
	uacce_qs_runlock();
	return ret;
}

static const struct vm_operations_struct uacce_shm_vm_ops = {
	.fault = uacce_shm_vm_fault,
};

static int uacce_qfr_alloc_pages(struct uacce_qfile_region *qfr)
{
	int gfp_mask = GFP_ATOMIC | __GFP_ZERO;
	int i, j;

	qfr->pages = kcalloc(qfr->nr_pages, sizeof(*qfr->pages), gfp_mask);
	if (!qfr->pages)
		return -ENOMEM;

	for (i = 0; i < qfr->nr_pages; i++) {
		qfr->pages[i] = alloc_page(gfp_mask);
		if (!qfr->pages[i])
			goto err_with_pages;
	}

	return 0;

err_with_pages:
	for (j = i - 1; j >= 0; j--)
		put_page(qfr->pages[j]);

	kfree(qfr->pages);
	return -ENOMEM;
}

static void uacce_qfr_free_pages(struct uacce_qfile_region *qfr)
{
	int i;

	for (i = 0; i < qfr->nr_pages; i++)
		put_page(qfr->pages[i]);

	kfree(qfr->pages);
}

static inline int uacce_queue_mmap_qfr(struct uacce_queue *q,
				       struct uacce_qfile_region *qfr,
				       struct vm_area_struct *vma)
{
#ifdef CONFIG_UACCE_FIX_MMAP
	int i, ret;

	if (qfr->nr_pages)
		dev_dbg(q->uacce->pdev, "mmap qfr (page ref=%d)\n",
			page_ref_count(qfr->pages[0]));
	for (i = 0; i < qfr->nr_pages; i++) {
		get_page(qfr->pages[i]);
		ret = remap_pfn_range(vma, vma->vm_start + i * PAGE_SIZE,
				      page_to_pfn(qfr->pages[i]), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret)
			return ret;
	}

#else
	vma->vm_private_data = qfr;
	vma->vm_ops = &uacce_shm_vm_ops;
#endif

	return 0;
}

static struct uacce_qfile_region *uacce_create_region(struct uacce_queue *q,
					struct vm_area_struct *vma,
					enum uacce_qfrt type, u32 flags)
{
	struct uacce_qfile_region *qfr;
	struct uacce *uacce = q->uacce;
	unsigned long vm_pgoff;
	int ret = -ENOMEM;

	dev_dbg(uacce->pdev, "create qfr (type=%x, flags=%x)\n", type, flags);
	qfr = kzalloc(sizeof(*qfr), GFP_ATOMIC);
	if (!qfr)
		return ERR_PTR(-ENOMEM);

	qfr->type = type;
	qfr->flags = flags;
	qfr->iova = vma->vm_start;
	qfr->nr_pages = vma_pages(vma);

	if (vma->vm_flags & VM_READ)
		qfr->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		qfr->prot |= IOMMU_WRITE;

	if (flags & UACCE_QFRF_SELFMT) {
		ret = uacce->ops->mmap(q, vma, qfr);
		if (ret)
			goto err_with_qfr;
		return qfr;
	}

	/* allocate memory */
	if (flags & UACCE_QFRF_DMA) {
		dev_dbg(uacce->pdev, "allocate dma %d pages\n", qfr->nr_pages);
		qfr->kaddr = dma_alloc_coherent(uacce->pdev, qfr->nr_pages <<
						PAGE_SHIFT, &qfr->dma,
						GFP_KERNEL);
		if (!qfr->kaddr) {
			ret = -ENOMEM;
			goto err_with_qfr;
		}
	} else {
		dev_dbg(uacce->pdev, "allocate %d pages\n", qfr->nr_pages);
		ret = uacce_qfr_alloc_pages(qfr);
		if (ret)
			goto err_with_qfr;
	}

	/* map to device */
	ret = uacce_queue_map_qfr(q, qfr);
	if (ret)
		goto err_with_pages;

	/* mmap to user space */
	if (flags & UACCE_QFRF_MMAP) {
		if (flags & UACCE_QFRF_DMA) {

			/* dma_mmap_coherent() requires vm_pgoff as 0
			 * restore vm_pfoff to initial value for mmap()
			 */
			dev_dbg(uacce->pdev, "mmap dma qfr\n");
			vm_pgoff = vma->vm_pgoff;
			vma->vm_pgoff = 0;
			ret = dma_mmap_coherent(uacce->pdev, vma, qfr->kaddr,
						qfr->dma,
						qfr->nr_pages << PAGE_SHIFT);
			vma->vm_pgoff = vm_pgoff;
		} else {
			ret = uacce_queue_mmap_qfr(q, qfr, vma);
		}

		if (ret)
			goto err_with_mapped_qfr;
	}

	return qfr;

err_with_mapped_qfr:
	uacce_queue_unmap_qfr(q, qfr);
err_with_pages:
	if (flags & UACCE_QFRF_DMA)
		dma_free_coherent(uacce->pdev, qfr->nr_pages << PAGE_SHIFT,
				  qfr->kaddr, qfr->dma);
	else
		uacce_qfr_free_pages(qfr);
err_with_qfr:
	kfree(qfr);

	return ERR_PTR(ret);
}

/* we assume you have uacce_queue_unmap_qfr(q, qfr) from all related queues */
static void uacce_destroy_region(struct uacce_queue *q,
				 struct uacce_qfile_region *qfr)
{
	struct uacce *uacce = q->uacce;

	if (qfr->flags & UACCE_QFRF_DMA) {
		dev_dbg(uacce->pdev, "free dma qfr %s (kaddr=%lx, dma=%llx)\n",
			uacce_qfrt_str(qfr), (unsigned long)qfr->kaddr,
			qfr->dma);
		if (current->mm)
			vm_munmap((unsigned long)qfr->iova,
				  qfr->nr_pages << PAGE_SHIFT);
		dma_free_coherent(uacce->pdev, qfr->nr_pages << PAGE_SHIFT,
				  qfr->kaddr, qfr->dma);
	} else if (qfr->pages) {
		if (qfr->flags & UACCE_QFRF_KMAP && qfr->kaddr) {
			dev_dbg(uacce->pdev, "vunmap qfr %s\n",
				uacce_qfrt_str(qfr));
			vunmap(qfr->kaddr);
			qfr->kaddr = NULL;
		}

		uacce_qfr_free_pages(qfr);
	}
	kfree(qfr);
}

static long uacce_cmd_share_qfr(struct uacce_queue *tgt, int fd)
{
	struct file *filep = fget(fd);
	struct uacce_queue *src;
	int ret = -EINVAL;

	if (!filep)
		return ret;

	if (filep->f_op != &uacce_fops)
		goto out_with_fd;

	src = filep->private_data;
	if (!src)
		goto out_with_fd;

	/* no ssva is needed if the dev can do fault-from-dev */
	if (tgt->uacce->flags & UACCE_DEV_FAULT_FROM_DEV)
		goto out_with_fd;

	dev_dbg(&src->uacce->dev, "share ss with %s\n",
		dev_name(&tgt->uacce->dev));

	if (!src->qfrs[UACCE_QFRT_SS] || tgt->qfrs[UACCE_QFRT_SS])
		goto out_with_fd;

	ret = uacce_queue_map_qfr(tgt, src->qfrs[UACCE_QFRT_SS]);
	if (ret)
		goto out_with_fd;

	tgt->qfrs[UACCE_QFRT_SS] = src->qfrs[UACCE_QFRT_SS];
	list_add(&tgt->list, &src->qfrs[UACCE_QFRT_SS]->qs);
	ret = 0;

out_with_fd:
	fput(filep);
	return ret;
}

static int uacce_start_queue(struct uacce_queue *q)
{
	struct device *dev = &q->uacce->dev;
	struct uacce_qfile_region *qfr;
	int ret, i, j;

	/*
	 * map KMAP qfr to kernel
	 * vmap should be done in non-spinlocked context!
	 */
	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (qfr && (qfr->flags & UACCE_QFRF_KMAP) && !qfr->kaddr) {
			qfr->kaddr = vmap(qfr->pages, qfr->nr_pages, VM_MAP,
					  PAGE_KERNEL);
			if (!qfr->kaddr) {
				ret = -ENOMEM;
				dev_dbg(dev, "fail to kmap %s qfr(%d pages)\n",
					uacce_qfrt_str(qfr), qfr->nr_pages);
				goto err_with_vmap;
			}

			dev_dbg(dev, "kernel vmap %s qfr(%d pages) to %lx\n",
				uacce_qfrt_str(qfr), qfr->nr_pages,
				(unsigned long)qfr->kaddr);
		}
	}

	ret = q->uacce->ops->start_queue(q);
	if (ret < 0)
		goto err_with_vmap;

	dev_dbg(&q->uacce->dev, "uacce queue state switch to STARTED\n");
	q->state = UACCE_Q_STARTED;

	return 0;

err_with_vmap:
	for (j = i - 1; j >= 0; j--) {
		qfr = q->qfrs[j];
		if (qfr && qfr->kaddr) {
			vunmap(qfr->kaddr);
			qfr->kaddr = NULL;
		}
	}
	return ret;
}

static long uacce_get_ss_dma(struct uacce_queue *q, unsigned long *arg)
{
	struct uacce *uacce = q->uacce;
	unsigned long dma = 0;

	if (!(uacce->flags & UACCE_DEV_NOIOMMU))
		return -EINVAL;

	if (q->qfrs[UACCE_QFRT_SS]) {
		dma = (unsigned long)(q->qfrs[UACCE_QFRT_SS]->dma);
		dev_dbg(&uacce->dev, "%s(%lx)\n", __func__, dma);
	} else {
		return -EINVAL;
	}

	*arg = dma;

	return 0;
}

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	unsigned long dma = 0;
	long ret = 0;

	uacce_qs_wlock();

	if (unlikely(!filep->private_data)) {
		uacce_qs_wunlock();
		return -EBADF;
	}
	q = filep->private_data;
	uacce = q->uacce;

	if (!uacce_q_avail_ioctl(q, cmd)) {
		uacce_qs_wunlock();
		return -EINVAL;
	}

	switch (cmd) {
	case UACCE_CMD_SHARE_SVAS:
		ret = uacce_cmd_share_qfr(q, arg);
		break;
	case UACCE_CMD_START:
		ret = uacce_start_queue(q);
		break;
	case UACCE_CMD_GET_SS_DMA:
		ret = uacce_get_ss_dma(q, &dma);
		break;
	case UACCE_CMD_PUT_Q:
		ret = uacce_put_queue(q);
		break;
	default:
		uacce_qs_wunlock();
		if (uacce->ops->ioctl)
			/* This is not protected by uacce_qs_lock */
			return uacce->ops->ioctl(q, cmd, arg);

		dev_err(&uacce->dev, "ioctl cmd (%d) is not supported!\n", cmd);
		return -EINVAL;
	}

	uacce_qs_wunlock();

	if (cmd == UACCE_CMD_GET_SS_DMA && !ret)
		if (copy_to_user((void __user *)arg, &dma, sizeof(dma)))
			ret = -EFAULT;

	return ret;
}

#ifdef CONFIG_COMPAT
static long uacce_fops_compat_ioctl(struct file *filep,
				   unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return uacce_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int uacce_dev_open_check(struct uacce *uacce)
{
	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return 0;

	/*
	 * The device can be opened once if it dose not support multiple page
	 * table. The better way to check this is counting it per iommu_domain,
	 * this is just a temporary solution
	 */
	if (uacce->flags & (UACCE_DEV_PASID | UACCE_DEV_NOIOMMU))
		return 0;
	else {
		if (!atomic_read(&uacce->ref))
			return 0;

		dev_info(&uacce->dev, "this device can be openned only once\n");
		return -EBUSY;
	}
}

/* To be fixed: only drain queue relatives */
static int uacce_queue_drain(struct uacce_queue *q)
{
	struct uacce *uacce = q->uacce;
	struct uacce_qfile_region *qfr;
	bool is_to_free_region;
	int i;

	if ((q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) &&
	    uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (!qfr)
			continue;

		is_to_free_region = false;
		uacce_queue_unmap_qfr(q, qfr);
		if (i == UACCE_QFRT_SS) {
			list_del(&q->list);
			if (list_empty(&qfr->qs))
				is_to_free_region = true;
		} else
			is_to_free_region = true;

		if (is_to_free_region)
			uacce_destroy_region(q, qfr);
	}
#ifdef CONFIG_IOMMU_SVA2
	if (uacce->flags & UACCE_DEV_SVA)
		iommu_sva_unbind_device(uacce->pdev, q->pasid);
#endif
	if ((q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) &&
	     uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	/*
	 * Put_queue above just put hardware queue, but not free uacce_q.
	 *
	 * Put_queue(and stop_queue) is used to support UACCE_PUT_QUEUE
	 * ioctl, UACCE_PUT_QUEUE is defined only to put low level hardware
	 * queue, after UACCE_PUT_QUEUE ioctl, uacce_queue enters into zombie
	 * state. So uacce_queue can only be freed here.
	 */
	kfree(q);
	atomic_dec(&uacce->ref);

	return 0;
}

/*
 * While user space releases a queue, all the relatives on the queue
 * should be released imediately by this putting.
 */
static long uacce_put_queue(struct uacce_queue *q)
{
	struct uacce *uacce = q->uacce;

	/*
	 * To do: we should vm_munmap mmio and dus regions, currently we munmap
	 * mmio and dus region before put queue.
	 */

	if (uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	q->state = UACCE_Q_ZOMBIE;

	return 0;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	int ret;
	int pasid = 0;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (!uacce->ops->get_queue)
		return -EINVAL;

	if (!try_module_get(uacce->pdev->driver->owner))
		return -ENODEV;
	ret = uacce_dev_open_check(uacce);
	if (ret)
		goto err_open;
#ifdef CONFIG_IOMMU_SVA2
	if (uacce->flags & UACCE_DEV_PASID) {
		ret = iommu_sva_bind_device(uacce->pdev, current->mm, &pasid,
					    IOMMU_SVA_FEAT_IOPF, NULL);
		if (ret)
			goto err_open;
	}
#endif
	uacce_qs_wlock();

	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0) {
		uacce_qs_wunlock();
		goto err_unbind;
	}

	q->pasid = pasid;
	q->uacce = uacce;
	q->mm = current->mm;
	memset(q->qfrs, 0, sizeof(q->qfrs));
	INIT_LIST_HEAD(&q->list);
	init_waitqueue_head(&q->wait);
	filep->private_data = q;
	q->state = UACCE_Q_INIT;
	atomic_inc(&uacce->ref);

	uacce_qs_wunlock();

	return 0;

err_unbind:
#ifdef CONFIG_IOMMU_SVA2
	if (uacce->flags & UACCE_DEV_PASID)
		iommu_sva_unbind_device(uacce->pdev, pasid);
#endif
err_open:
	module_put(uacce->pdev->driver->owner);
	return ret;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	int ret = 0;

	uacce_qs_wlock();

	uacce_fops_fasync(-1, filep, 0);

	q = filep->private_data;
	if (q) {
		uacce = q->uacce;
		/*
		 * As user space exception(without release queue), it will
		 * fall into this logic as the task exits to prevent hardware
		 * resources leaking.
		 */
		ret = uacce_queue_drain(q);
		filep->private_data = NULL;
	}

	uacce_qs_wunlock();

	if (q)
		module_put(uacce->pdev->driver->owner);

	return ret;
}

static enum uacce_qfrt uacce_get_region_type(struct uacce *uacce,
					     struct vm_area_struct *vma)
{
	enum uacce_qfrt type = UACCE_QFRT_MAX;
	int i;
	size_t next_start = UACCE_QFR_NA;

	for (i = UACCE_QFRT_MAX - 1; i >= 0; i--) {
		if (vma->vm_pgoff >= uacce->qf_pg_start[i]) {
			type = i;
			break;
		}
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
		if (!uacce->ops->mmap) {
			dev_err(&uacce->dev, "no driver mmap!\n");
			return UACCE_QFRT_INVALID;
		}
		break;

	case UACCE_QFRT_DKO:
		if ((uacce->flags & UACCE_DEV_PASID) ||
		    (uacce->flags & UACCE_DEV_NOIOMMU))
			return UACCE_QFRT_INVALID;
		break;

	case UACCE_QFRT_DUS:
		break;

	case UACCE_QFRT_SS:
		/* todo: this can be valid to protect the process space */
		if (uacce->flags & UACCE_DEV_FAULT_FROM_DEV)
			return UACCE_QFRT_INVALID;
		break;

	default:
		dev_err(&uacce->dev, "uacce bug (%d)!\n", type);
		return UACCE_QFRT_INVALID;
	}

	/* make sure the mapping size is exactly the same as the region */
	if (type < UACCE_QFRT_SS) {
		for (i = type + 1; i < UACCE_QFRT_MAX; i++)
			if (uacce->qf_pg_start[i] != UACCE_QFR_NA) {
				next_start = uacce->qf_pg_start[i];
				break;
			}

		if (next_start == UACCE_QFR_NA) {
			dev_err(&uacce->dev, "uacce config error. \
				make sure setting SS offset properly\n");
			return UACCE_QFRT_INVALID;
		}

		if (vma_pages(vma) !=
		    next_start - uacce->qf_pg_start[type]) {
			dev_err(&uacce->dev, "invalid mmap size "
				"(%ld vs %ld pages) for region %s.\n",
				vma_pages(vma),
				next_start - uacce->qf_pg_start[type],
				qfrt_str[type]);
			return UACCE_QFRT_INVALID;
		}
	}

	return type;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	enum uacce_qfrt type;
	struct uacce_qfile_region *qfr;
	unsigned int flags = 0;
	int ret;

	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;

	uacce_qs_wlock();

	if (unlikely(!filep->private_data)) {
		uacce_qs_wunlock();
		return -EBADF;
	}
	q = filep->private_data;
	uacce = q->uacce;
	type = uacce_get_region_type(uacce, vma);

	dev_dbg(&uacce->dev, "mmap q file(t=%s, off=%lx, start=%lx, end=%lx)\n",
		 qfrt_str[type], vma->vm_pgoff, vma->vm_start, vma->vm_end);

	if (type == UACCE_QFRT_INVALID) {
		ret = -EINVAL;
		goto out_with_lock;
	}

	if (q->qfrs[type]) {
		ret = -EBUSY;
		goto out_with_lock;
	}

	if (!uacce_q_avail_mmap(q, type)) {
		ret = -EINVAL;
		goto out_with_lock;
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
		flags = UACCE_QFRF_SELFMT;
		break;

	case UACCE_QFRT_SS:
		flags = UACCE_QFRF_MAP | UACCE_QFRF_MMAP;

		if (uacce->flags & UACCE_DEV_NOIOMMU)
			flags |= UACCE_QFRF_DMA;
		break;

	case UACCE_QFRT_DKO:
		flags = UACCE_QFRF_MAP | UACCE_QFRF_KMAP;

		if (uacce->flags & UACCE_DEV_NOIOMMU)
			flags |= UACCE_QFRF_DMA;
		break;

	case UACCE_QFRT_DUS:
		if (q->uacce->flags & UACCE_DEV_DRVMAP_DUS) {
			flags = UACCE_QFRF_SELFMT;
			break;
		}

		flags = UACCE_QFRF_MAP | UACCE_QFRF_MMAP;
		if (q->uacce->flags & UACCE_DEV_KMAP_DUS)
			flags |= UACCE_QFRF_KMAP;
		if (q->uacce->flags & UACCE_DEV_NOIOMMU)
			flags |= UACCE_QFRF_DMA;
		break;

	default:
		WARN_ON(&uacce->dev);
		break;
	}

	qfr = uacce_create_region(q, vma, type, flags);
	if (IS_ERR(qfr)) {
		ret = PTR_ERR(qfr);
		goto out_with_lock;
	}
	q->qfrs[type] = qfr;

	if (type == UACCE_QFRT_SS) {
		INIT_LIST_HEAD(&qfr->qs);
		list_add(&q->list, &q->qfrs[type]->qs);
	}

	uacce_qs_wunlock();

	return 0;

out_with_lock:
	uacce_qs_wunlock();
	return ret;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q;
	struct uacce *uacce;
	int ret = 0;

	uacce_qs_wlock();

	if (unlikely(!file->private_data)) {
		uacce_qs_wunlock();
		ret = EPOLLERR;
		return ret;
	}
	q = file->private_data;
	uacce = q->uacce;

	poll_wait(file, &q->wait, wait);
	if (uacce->ops->is_q_updated && uacce->ops->is_q_updated(q))
		ret = EPOLLIN | EPOLLRDNORM;

	uacce_qs_wunlock();

	return ret;
}

static int uacce_fops_fasync(int fd, struct file *file, int mode)
{
	struct uacce_queue *q = file->private_data;

	return fasync_helper(fd, file, mode, &q->async_queue);
}

static const struct file_operations uacce_fops = {
	.owner		= THIS_MODULE,
	.open		= uacce_fops_open,
	.release	= uacce_fops_release,
	.unlocked_ioctl	= uacce_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= uacce_fops_compat_ioctl,
#endif
	.mmap		= uacce_fops_mmap,
	.poll		= uacce_fops_poll,
	.fasync		= uacce_fops_fasync,
};

#define UACCE_FROM_CDEV_ATTR(dev) container_of(dev, struct uacce, dev)

static ssize_t uacce_dev_show_id(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->dev_id);
}
static DEVICE_ATTR(id, S_IRUGO, uacce_dev_show_id, NULL);

static ssize_t uacce_dev_show_api(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%s\n", uacce->api_ver);
}
static DEVICE_ATTR(api, S_IRUGO, uacce_dev_show_api, NULL);

static ssize_t uacce_dev_show_numa_distance(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int distance = 0;

#ifdef CONFIG_NUMA
	distance = cpu_to_node(smp_processor_id()) - uacce->pdev->numa_node;
#endif
	return sprintf(buf, "%d\n", abs(distance));
}
static DEVICE_ATTR(numa_distance, S_IRUGO, uacce_dev_show_numa_distance, NULL);

static ssize_t uacce_dev_show_node_id(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int node_id = -1;

#ifdef CONFIG_NUMA
	node_id = uacce->pdev->numa_node;
#endif
	return sprintf(buf, "%d\n", node_id);
}
static DEVICE_ATTR(node_id, S_IRUGO, uacce_dev_show_node_id, NULL);

static ssize_t uacce_dev_show_flags(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->flags);
}
static DEVICE_ATTR(flags, S_IRUGO, uacce_dev_show_flags, NULL);

static ssize_t uacce_dev_show_available_instances(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->ops->get_available_instances(uacce));
}
static DEVICE_ATTR(available_instances, S_IRUGO,
		   uacce_dev_show_available_instances, NULL);

static ssize_t uacce_dev_show_algorithms(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%s", uacce->algs);
}
static DEVICE_ATTR(algorithms, S_IRUGO, uacce_dev_show_algorithms, NULL);

static ssize_t uacce_dev_show_qfrs_offset(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int i, ret;
	unsigned long offset;

	for (i = 0, ret = 0; i < UACCE_QFRT_MAX; i++) {
		offset = uacce->qf_pg_start[i];
		if (offset != UACCE_QFR_NA)
			offset = offset << PAGE_SHIFT;
		if (i == UACCE_QFRT_SS)
			break;
		ret += sprintf(buf + ret, "%lu\t", offset);
	}
	ret += sprintf(buf + ret, "%lu\n", offset);

	return ret;
}
static DEVICE_ATTR(qfrs_offset, S_IRUGO, uacce_dev_show_qfrs_offset, NULL);

static struct attribute *uacce_dev_attrs[] = {
	&dev_attr_id.attr,
	&dev_attr_api.attr,
	&dev_attr_node_id.attr,
	&dev_attr_numa_distance.attr,
	&dev_attr_flags.attr,
	&dev_attr_available_instances.attr,
	&dev_attr_algorithms.attr,
	&dev_attr_qfrs_offset.attr,
	NULL,
};

static const struct attribute_group uacce_dev_attr_group = {
	.name	= UACCE_DEV_ATTRS,
	.attrs	= uacce_dev_attrs,
};

static const struct attribute_group *uacce_dev_attr_groups[] = {
	&uacce_dev_attr_group,
	NULL
};

static void uacce_dev_release(struct device *dev) {}

static int uacce_create_chrdev(struct uacce *uacce)
{
	int ret;

	ret = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (ret < 0)
		return ret;

	cdev_init(&uacce->cdev, &uacce_fops);
	uacce->dev_id = ret;
	uacce->cdev.owner = THIS_MODULE;
	device_initialize(&uacce->dev);
	uacce->dev.devt = MKDEV(MAJOR(uacce_devt), uacce->dev_id);
	uacce->dev.class = uacce_class;
	uacce->dev.groups = uacce_dev_attr_groups;
	uacce->dev.parent = uacce->pdev;
	uacce->dev.release = uacce_dev_release;
	dev_set_name(&uacce->dev, "%s-%d", uacce->drv_name, uacce->dev_id);
	ret = cdev_device_add(&uacce->cdev, &uacce->dev);
	if (ret)
		goto err_with_idr;

	dev_dbg(&uacce->dev, "create uacce minior=%d\n", uacce->dev_id);
	return 0;

err_with_idr:
	idr_remove(&uacce_idr, uacce->dev_id);
	return ret;
}

static void uacce_destroy_chrdev(struct uacce *uacce)
{
	cdev_device_del(&uacce->cdev, &uacce->dev);
	put_device(&uacce->dev);
	memset(&uacce->dev, 0, sizeof(struct device));
	idr_remove(&uacce_idr, uacce->dev_id);
}

static int uacce_default_get_available_instances(struct uacce *uacce)
{
	return -1;
}

static int uacce_default_start_queue(struct uacce_queue *q)
{
	dev_dbg(&q->uacce->dev, "fake start queue\n");
	return 0;
}

#ifndef CONFIG_IOMMU_SVA2
static int uacce_dev_match(struct device *dev, void *data)
{
	if (dev->parent == data)
		return -EBUSY;

	return 0;
}

/* Borrowed from VFIO */
static bool uacce_iommu_has_sw_msi(struct iommu_group *group,
				   phys_addr_t *base)
{
	struct list_head group_resv_regions;
	struct iommu_resv_region *region, *next;
	bool ret = false;

	INIT_LIST_HEAD(&group_resv_regions);
	iommu_get_group_resv_regions(group, &group_resv_regions);
	list_for_each_entry(region, &group_resv_regions, list) {
		pr_debug("uacce: find a resv region (%d) on %llx\n",
			 region->type, region->start);

		/*
		 * The presence of any 'real' MSI regions should take
		 * precedence over the software-managed one if the
		 * IOMMU driver happens to advertise both types.
		 */
		if (region->type == IOMMU_RESV_MSI) {
			ret = false;
			break;
		}

		if (region->type == IOMMU_RESV_SW_MSI) {
			*base = region->start;
			ret = true;
		}
	}
	list_for_each_entry_safe(region, next, &group_resv_regions, list)
		kfree(region);
	return ret;
}

static int uacce_set_iommu_domain(struct uacce *uacce)
{
	struct iommu_domain *domain;
	struct iommu_group *group;
	struct device *dev = uacce->pdev;
	bool resv_msi;
	phys_addr_t resv_msi_base = 0;
	int ret;

	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return 0;

	/*
	 * We don't support multiple register for the same dev in RFC version ,
	 * will add it in formal version
	 */
	ret = class_for_each_device(uacce_class, NULL, dev, uacce_dev_match);
	if (ret) {
		dev_err(dev, "no matching device in uacce class!\n");
		return ret;
	}

	/* allocate and attach a unmanged domain */
	domain = iommu_domain_alloc(dev->bus);
	if (!domain) {
		dev_err(dev, "fail to allocate domain on its bus\n");
		return -ENODEV;
	}

	ret = iommu_attach_device(domain, dev);
	if (ret) {
		dev_err(dev, "iommu attach device failing!\n");
		goto err_with_domain;
	}

	if (iommu_capable(dev->bus, IOMMU_CAP_CACHE_COHERENCY)) {
		uacce->prot |= IOMMU_CACHE;
		dev_dbg(dev, "Enable uacce with c-coherent capa\n");
	} else {
		dev_dbg(dev, "Enable uacce without c-coherent capa\n");
	}

	group = iommu_group_get(dev);
	if (!group) {
		dev_err(dev, "fail to get iommu group!\n");
		ret = -EINVAL;
		goto err_with_domain;
	}

	resv_msi = uacce_iommu_has_sw_msi(group, &resv_msi_base);
	iommu_group_put(group);

	if (resv_msi) {
		if (!irq_domain_check_msi_remap() &&
		    !iommu_capable(dev->bus, IOMMU_CAP_INTR_REMAP)) {
			dev_err(dev, "No interrupt remapping support!\n");
			ret = -EPERM;
			goto err_with_domain;
		}

		dev_dbg(dev, "Set resv msi %llx on iommu domain!\n",
			(u64)resv_msi_base);
		ret = iommu_get_msi_cookie(domain, resv_msi_base);
		if (ret) {
			dev_err(dev, "fail to get msi cookie from domain!\n");
			goto err_with_domain;
		}
	}

	return 0;

err_with_domain:
	iommu_domain_free(domain);
	return ret;
}

static void uacce_unset_iommu_domain(struct uacce *uacce)
{
	struct iommu_domain *domain;
	struct device *dev = uacce->pdev;

	if (uacce->flags & UACCE_DEV_NOIOMMU)
		return;

	domain = iommu_get_domain_for_dev(dev);
	if (domain) {
		iommu_detach_device(domain, dev);
		iommu_domain_free(domain);
	} else {
		dev_err(dev, "no domain attached to device\n");
	}
}
#endif

/**
 * uacce_register - register an accelerator
 * @uacce: the accelerator structure
 */
int uacce_register(struct uacce *uacce)
{
	struct device *dev = uacce->pdev;
	int ret;

	if (!dev) {
		pr_err("uacce parent device not set\n");
		return -ENODEV;
	}

	if (uacce->flags & UACCE_DEV_NOIOMMU) {
		add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);
		dev_warn(dev, "register to noiommu mode, this may be attacked\n");
	}

	/* if dev support fault-from-dev, it should support pasid */
	if ((uacce->flags & UACCE_DEV_FAULT_FROM_DEV) &&
	    !(uacce->flags & UACCE_DEV_PASID)) {
		dev_err(dev, "SVM/SVA device should support PASID\n");
		return -EINVAL;
	}

	if (!uacce->ops->start_queue)
		uacce->ops->start_queue = uacce_default_start_queue;

	if (!uacce->ops->get_available_instances)
		uacce->ops->get_available_instances =
			uacce_default_get_available_instances;

#ifndef CONFIG_IOMMU_SVA2
	ret = uacce_set_iommu_domain(uacce);
	if (ret)
		return ret;
#endif

	ret = uacce_create_chrdev(uacce);
	if (ret) {
		dev_err(dev, "uacce creates cdev fail!\n");
		return ret;
	}

	if (uacce->flags & UACCE_DEV_PASID) {
#ifdef CONFIG_IOMMU_SVA2
		ret = iommu_sva_init_device(uacce->pdev, IOMMU_SVA_FEAT_IOPF,
					    0, 0, NULL);
		if (ret) {
			dev_err(dev, "uacce sva init fail!\n");
			uacce_destroy_chrdev(uacce);
			return ret;
		}
#else
		uacce->flags &= ~(UACCE_DEV_FAULT_FROM_DEV | UACCE_DEV_PASID);
#endif
	}

	dev_dbg(&uacce->dev, "register to uacce!\n");
	atomic_set(&uacce->ref, 0);

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_register);

/**
 * uacce_unregister - unregisters a uacce
 * @uacce: the accelerator to unregister
 *
 * Unregister an accelerator that wat previously successully registered with
 * uacce_register().
 */
int uacce_unregister(struct uacce *uacce)
{
	if (atomic_read(&uacce->ref) > 0) {
		printk_ratelimited("Fail to unregister uacce, please close all uacce queues!\n");
		return -EAGAIN;
	}

#ifdef CONFIG_IOMMU_SVA2
	iommu_sva_shutdown_device(uacce->pdev);
#else
	uacce_unset_iommu_domain(uacce);
#endif

	uacce_destroy_chrdev(uacce);

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_unregister);

static int __init uacce_init(void)
{
	int ret;

	uacce_class = class_create(THIS_MODULE, UACCE_CLASS_NAME);
	if (IS_ERR(uacce_class)) {
		ret = PTR_ERR(uacce_class);
		goto err;
	}

	ret = alloc_chrdev_region(&uacce_devt, 0, MINORMASK, "uacce");
	if (ret)
		goto err_with_class;

	pr_info("uacce init with major number:%d\n", MAJOR(uacce_devt));
	pr_debug("uacce debug enabled\n");

	return 0;

err_with_class:
	class_destroy(uacce_class);
err:
	return ret;
}

static __exit void uacce_exit(void)
{
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_destroy(uacce_class);
	idr_destroy(&uacce_idr);
}

subsys_initcall(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
