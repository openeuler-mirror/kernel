// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018 HiSilicon Limited. */
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/sched/mm.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uacce.h>
#include <linux/wait.h>

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;

static DECLARE_RWSEM(uacce_qs_lock);
#define uacce_qs_rlock() down_read(&uacce_qs_lock)
#define uacce_qs_runlock() up_read(&uacce_qs_lock)
#define uacce_qs_wlock() down_write(&uacce_qs_lock)
#define uacce_qs_wunlock() up_write(&uacce_qs_lock)

#define UACCE_RESET_DELAY_MS        10
#define UACCE_FROM_CDEV_ATTR(dev) container_of(dev, struct uacce, dev)

static const struct file_operations uacce_fops;
static void uacce_put_queue(struct uacce_queue *q);

/* match with enum uacce_qfrt */
static const char *const qfrt_str[] = {
	"mmio",
	"dus",
	"ss",
	"invalid"
};

static int cdev_get(struct device *dev, void *data)
{
	struct uacce *uacce;
	struct device **t_dev = data;

	uacce = UACCE_FROM_CDEV_ATTR(dev);
	if (uacce->pdev == *t_dev) {
		*t_dev = dev;
		return 1;
	}

	return 0;
}

/**
 * dev_to_uacce - Get structure uacce from its device
 * @dev the device
 */
struct uacce *dev_to_uacce(struct device *dev)
{
	struct device **tdev = &dev;
	int ret;

	ret = class_for_each_device(uacce_class, NULL, tdev, cdev_get);
	if (ret) {
		dev = *tdev;
		return UACCE_FROM_CDEV_ATTR(dev);
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(dev_to_uacce);

/**
 * uacce_hw_err_isolate - Try to isolate the uacce device with its VFs
 * according to user's configuration of isolation strategy. Warning: this
 * API should be called while there is no user on the device, or the users
 * on this device are suspended by slot resetting preparation of PCI AER.
 * @uacce the uacce device
 */
int uacce_hw_err_isolate(struct uacce *uacce)
{
	struct uacce_err_isolate *isolate = uacce->isolate;
	struct uacce_hw_err *err, *tmp, *hw_err;
	u32 count = 0;

#define SECONDS_PER_HOUR	3600

	/* all the hw errs are processed by PF driver */
	if (uacce->is_vf || atomic_read(&isolate->is_isolate) ||
		!isolate->hw_err_isolate_hz)
		return 0;

	hw_err = kzalloc(sizeof(*hw_err), GFP_ATOMIC);
	if (!hw_err)
		return -ENOMEM;
	hw_err->tick_stamp = jiffies;
	list_for_each_entry_safe(err, tmp, &isolate->hw_errs, list) {
		if ((hw_err->tick_stamp - err->tick_stamp) / HZ >
		    SECONDS_PER_HOUR) {
			list_del(&err->list);
			kfree(err);
		} else {
			count++;
		}
	}
	list_add(&hw_err->list, &isolate->hw_errs);

	if (count >= isolate->hw_err_isolate_hz)
		atomic_set(&isolate->is_isolate, 1);

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_hw_err_isolate);

static void uacce_hw_err_destroy(struct uacce *uacce)
{
	struct uacce_hw_err *err, *tmp;

	list_for_each_entry_safe(err, tmp, &uacce->isolate_data.hw_errs, list) {
		list_del(&err->list);
		kfree(err);
	}
}

const char *uacce_qfrt_str(struct uacce_qfile_region *qfr)
{
	return qfrt_str[qfr->type];
}
EXPORT_SYMBOL_GPL(uacce_qfrt_str);

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

static void uacce_free_dma_buffers(struct uacce_queue *q)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct uacce *uacce = q->uacce;
	int i = 0;

	if (!qfr->dma_list)
		return;
	while (i < qfr->dma_list[0].total_num) {
		WARN_ON(!qfr->dma_list[i].size || !qfr->dma_list[i].dma);
		dev_dbg(uacce->pdev, "free dma qfr %s (kaddr=%lx, dma=%llx)\n",
			uacce_qfrt_str(qfr),
			(unsigned long)qfr->dma_list[i].kaddr,
			qfr->dma_list[i].dma);
		dma_free_coherent(uacce->pdev, qfr->dma_list[i].size,
				  qfr->dma_list[i].kaddr,
				  qfr->dma_list[i].dma);
		i++;
	}
	kfree(qfr->dma_list);
	qfr->dma_list = NULL;
}

static int get_sort_base(struct uacce_dma_slice *list, int low, int high,
			 struct uacce_dma_slice *tmp)
{
	tmp->kaddr = list[low].kaddr;
	tmp->size = list[low].size;
	tmp->dma = list[low].dma;

	if (low >= high)
		return -EINVAL;
	while (low < high) {
		while (low < high && list[high].dma > tmp->dma)
			high--;
		list[low].kaddr = list[high].kaddr;
		list[low].dma = list[high].dma;
		list[low].size = list[high].size;
		while (low < high && list[low].dma < tmp->dma)
			low++;
		list[high].kaddr = list[low].kaddr;
		list[high].dma = list[low].dma;
		list[high].size = list[low].size;
	}
	list[low].kaddr = tmp->kaddr;
	list[low].dma = tmp->dma;
	list[low].size = tmp->size;

	return low;
}

static void uacce_sort_dma_buffers(struct uacce_dma_slice *list, int low,
				   int high, struct uacce_dma_slice *tmp)
{
	int pilot, top = 0;
	int *idx_list;

	idx_list = kcalloc(list[0].total_num, sizeof(int),
			   GFP_KERNEL | __GFP_ZERO);
	if (!idx_list)
		return;

	pilot = get_sort_base(list, low, high, tmp);
	if (pilot < 0) {
		kfree(idx_list);
		return;
	}
	if (pilot > low + 1) {
		idx_list[top++] = low;
		idx_list[top++] = pilot - 1;
	}
	if (pilot < high - 1) {
		idx_list[top++] = pilot + 1;
		idx_list[top++] = high;
	}
	while (top > 0) {
		high = idx_list[--top];
		low = idx_list[--top];
		pilot = get_sort_base(list, low, high, tmp);
		if (pilot > low + 1) {
			idx_list[top++] = low;
			idx_list[top++] = pilot - 1;
		}
		if (pilot < high - 1) {
			idx_list[top++] = pilot + 1;
			idx_list[top++] = high;
		}
	}

	kfree(idx_list);
}

static int uacce_alloc_dma_buffers(struct uacce_queue *q,
				   struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long max_size = PAGE_SIZE << (MAX_ORDER - 1);
	unsigned long start = vma->vm_start;
	struct uacce *uacce = q->uacce;
	struct uacce_dma_slice *slice;
	int i, ss_num;

	/* Set maximum slice size is 128MB */
	if (max_size > UACCE_GRAN_NUM_MASK << UACCE_GRAN_SHIFT)
		max_size = (UACCE_GRAN_NUM_MASK + 1) << (UACCE_GRAN_SHIFT - 1);

	ss_num = (size + max_size - 1) / max_size;
	slice = kcalloc(ss_num + 1, sizeof(*slice), GFP_KERNEL | __GFP_ZERO);
	if (!slice)
		return -ENOMEM;

	qfr->dma_list = slice;
	for (i = 0; i < ss_num; i++) {
		if (start + max_size > vma->vm_end)
			size = vma->vm_end - start;
		else
			size = max_size;
		dev_dbg(uacce->pdev, "allocate dma %ld pages\n",
			(size + PAGE_SIZE - 1) >> PAGE_SHIFT);
		slice[i].kaddr = dma_alloc_coherent(uacce->pdev, (size +
						    PAGE_SIZE - 1) & PAGE_MASK,
						    &slice[i].dma, GFP_KERNEL);
		if (!slice[i].kaddr) {
			dev_err(uacce->pdev, "alloc dma slice(sz=%ld) fail!\n",
				size);
			slice[0].total_num = i;
			return -ENOMEM;
		}
		slice[i].size = (size + PAGE_SIZE - 1) & PAGE_MASK;
		slice[i].total_num = ss_num;
		start += size;
	}

	uacce_sort_dma_buffers(slice, 0, slice[0].total_num - 1,
			       &slice[ss_num]);

	return 0;
}

static int uacce_mmap_dma_buffers(struct uacce_queue *q,
				  struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct uacce_dma_slice *slice = qfr->dma_list;
	struct uacce *uacce = q->uacce;
	unsigned long vm_pgoff;
	int ret = 0;
	int i = 0;

	/*
	 * dma_mmap_coherent() requires vm_pgoff as 0
	 * restore vm_pfoff to initial value for mmap()
	 */
	vm_pgoff = vma->vm_pgoff;
	vma->vm_pgoff = 0;
	while (i < slice[0].total_num && slice[i].size) {
		vma->vm_end = vma->vm_start + slice[i].size;
		ret = dma_mmap_coherent(uacce->pdev, vma, slice[i].kaddr,
					slice[i].dma,
					slice[i].size);
		if (ret) {
			dev_err(uacce->pdev,
				"mmap dma buf fail(dma=0x%llx,size=0x%x)!\n",
				slice[i].dma, slice[i].size);
			goto DMA_MMAP_FAIL;
		}

		i++;
		vma->vm_start = vma->vm_end;
	}

	/* System unmap_region will clean the results, we need do nothing */
DMA_MMAP_FAIL:
	vma->vm_pgoff = vm_pgoff;
	vma->vm_start = qfr->iova;
	vma->vm_end = vma->vm_start + (qfr->nr_pages << PAGE_SHIFT);

	return ret;
}

static int uacce_mmap_region(u32 flags, struct uacce_queue *q,
			     struct vm_area_struct *vma,
			     struct uacce_qfile_region *qfr)
{
	struct uacce *uacce = q->uacce;
	int ret = 0;

	if (flags & UACCE_QFRF_SELFMT)
		return uacce->ops->mmap(q, vma, qfr);

	/* mmap to user space */
	if (flags & UACCE_QFRF_MMAP) {
		if (flags & UACCE_QFRF_DMA)
			ret = uacce_mmap_dma_buffers(q, vma);
	}

	return ret;
}

static struct
uacce_qfile_region *uacce_create_region(struct uacce_queue *q,
					struct vm_area_struct *vma,
					enum uacce_qfrt type, u32 flags)
{
	struct uacce_qfile_region *qfr;
	struct uacce *uacce = q->uacce;
	int ret = -ENOMEM;

	qfr = kzalloc(sizeof(*qfr), GFP_ATOMIC);
	if (!qfr)
		return ERR_PTR(ret);

	qfr->type = type;
	qfr->flags = flags;
	qfr->iova = vma->vm_start;
	qfr->nr_pages = vma_pages(vma);
	q->qfrs[type] = qfr;

	if (vma->vm_flags & VM_READ)
		qfr->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		qfr->prot |= IOMMU_WRITE;

	/* allocate memory */
	if (flags & UACCE_QFRF_DMA) {
		ret = uacce_alloc_dma_buffers(q, vma);
		if (ret) {
			uacce_free_dma_buffers(q);
			goto err_with_qfr;
		}
	}
	ret = uacce_mmap_region(flags, q, vma, qfr);
	if (ret) {
		dev_err(uacce->pdev, "uacce mmap region fail!\n");
		goto err_with_pages;
	}

	return qfr;

err_with_pages:
	if (flags & UACCE_QFRF_DMA)
		uacce_free_dma_buffers(q);
err_with_qfr:
	kfree(qfr);
	q->qfrs[type] = NULL;
	return ERR_PTR(ret);
}

static struct uacce_qfile_region noiommu_ss_default_qfr = {
	.type	=	UACCE_QFRT_SS,
	.flags	=	UACCE_QFRF_DMA,
};

/* we assume you have uacce_queue_unmap_qfr(q, qfr) from all related queues */
static void uacce_destroy_region(struct uacce_queue *q,
				 struct uacce_qfile_region *qfr)
{
	if (qfr->flags & UACCE_QFRF_DMA)
		uacce_free_dma_buffers(q);

	if (qfr != &noiommu_ss_default_qfr)
		kfree(qfr);
}

static long uacce_cmd_share_qfr(struct uacce_queue *src, int fd)
{
	struct device *dev = &src->uacce->dev;
	struct file *filep = fget(fd);
	struct uacce_queue *tgt;
	int ret = -EINVAL;

	if (!filep) {
		dev_err(dev, "filep is NULL!\n");
		return ret;
	}

	if (filep->f_op != &uacce_fops) {
		dev_err(dev, "file ops mismatch!\n");
		goto out_with_fd;
	}

	tgt = filep->private_data;
	if (!tgt) {
		dev_err(dev, "target queue is not exist!\n");
		goto out_with_fd;
	}

	/* no SVA is needed if the dev can do fault-from-dev */
	if (tgt->uacce->flags & UACCE_DEV_FAULT_FROM_DEV) {
		dev_err(dev, "No need to share in SVA device\n");
		goto out_with_fd;
	}

	dev_dbg(&src->uacce->dev, "share ss with %s\n",
		dev_name(&tgt->uacce->dev));

	if (!src->qfrs[UACCE_QFRT_SS] || tgt->qfrs[UACCE_QFRT_SS]) {
		dev_err(dev, "src q's SS not exists or target q's SS exists!\n");
		goto out_with_fd;
	}

	/* In No-IOMMU mode, taget queue uses default SS qfr */
	if (src->qfrs[UACCE_QFRT_SS]->flags & UACCE_QFRF_DMA) {
		tgt->qfrs[UACCE_QFRT_SS] = &noiommu_ss_default_qfr;
	} else {
		tgt->qfrs[UACCE_QFRT_SS] = src->qfrs[UACCE_QFRT_SS];
		list_add(&tgt->list, &src->qfrs[UACCE_QFRT_SS]->qs);
	}
	ret = 0;

out_with_fd:
	fput(filep);
	return ret;
}

static int uacce_start_queue(struct uacce_queue *q)
{
	struct device *dev = &q->uacce->dev;
	int ret;

	ret = q->uacce->ops->start_queue(q);
	if (ret < 0) {
		dev_err(dev, "uacce fails to start queue!\n");
		return ret;
	}

	dev_dbg(&q->uacce->dev, "uacce queue state switch to STARTED\n");
	q->state = UACCE_Q_STARTED;

	return 0;
}

static long uacce_get_ss_dma(struct uacce_queue *q, void __user *arg)
{
	struct uacce *uacce = q->uacce;
	struct uacce_dma_slice *slice;
	unsigned long slice_idx = 0;
	unsigned long dma, size;
	long ret = -EFAULT;

	if (!(uacce->flags & UACCE_DEV_NOIOMMU) || !q->qfrs[UACCE_QFRT_SS]) {
		dev_err(&uacce->dev, "no ss dma region!\n");
		return -EINVAL;
	}

	slice = q->qfrs[UACCE_QFRT_SS]->dma_list;
	if (copy_from_user(&slice_idx, arg, sizeof(unsigned long)))
		return ret;

	if (slice[0].total_num - 1 < slice_idx) {
		dev_err(&uacce->dev, "no ss slice idx %ld err!\n", slice_idx);
		return -EINVAL;
	}
	dma = slice[slice_idx].dma;
	size = slice[slice_idx].size;
	if (!dma || !size) {
		dev_err(&uacce->dev, "%ldth ss region no exist!\n", slice_idx);
		return -ENODEV;
	}
	dma = dma | (size >> UACCE_GRAN_SHIFT);
	if (copy_to_user(arg, &dma, sizeof(unsigned long)))
		return ret;

	return (long)(slice[0].total_num - 1 - slice_idx);
}

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q;
	struct uacce *uacce;
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
		ret = uacce_cmd_share_qfr(q, (int)arg);
		break;
	case UACCE_CMD_START:
		ret = uacce_start_queue(q);
		break;
	case UACCE_CMD_GET_SS_DMA:
		uacce_qs_wunlock();
		ret = uacce_get_ss_dma(q, (void __user *)arg);
		return ret;
	case UACCE_CMD_PUT_Q:
		uacce_put_queue(q);
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

	if (!atomic_read(&uacce->ref))
		return 0;

	dev_info(&uacce->dev, "this device can be openned only once\n");
	return -EBUSY;
}

static void uacce_queue_drain(struct uacce_queue *q)
{
	struct uacce_qfile_region *qfr;
	bool is_to_free_region;
	struct uacce *uacce;
	int state;
	int i;

	uacce = q->uacce;

	state = (q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) ? 1 :
									    0;
	if (state && uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (!qfr)
			continue;

		is_to_free_region = false;

		if (i == UACCE_QFRT_SS && !(qfr->flags & UACCE_QFRF_DMA)) {
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
	if (state && uacce->ops->put_queue)
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
}

/*
 * While user space releases a queue, all the relatives on the queue
 * should be released imediately by this putting.
 */
static void uacce_put_queue(struct uacce_queue *q)
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
	q->filep->private_data = NULL;
	uacce_queue_drain(q);
	if (module_refcount(uacce->pdev->driver->owner) > 0)
		module_put(uacce->pdev->driver->owner);
}

static int uacce_get_queue(struct uacce *uacce, struct file *filep)
{
	struct uacce_queue *q;
	int ret;
	int pasid = 0;

#ifdef CONFIG_IOMMU_SVA2
	if (uacce->flags & UACCE_DEV_PASID) {
		ret = iommu_sva_bind_device(uacce->pdev, current->mm, &pasid,
					    IOMMU_SVA_FEAT_IOPF, NULL);
		if (ret) {
			dev_err(uacce->pdev, "iommu SVA binds fail!\n");
			return ret;
		}
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
	q->filep = filep;
	memset(q->qfrs, 0, sizeof(q->qfrs));
	INIT_LIST_HEAD(&q->list);
	init_waitqueue_head(&q->wait);
	q->state = UACCE_Q_INIT;
	filep->private_data = q;
	atomic_inc(&uacce->ref);

	uacce_qs_wunlock();

	return 0;

err_unbind:
#ifdef CONFIG_IOMMU_SVA2
	if (uacce->flags & UACCE_DEV_PASID)
		iommu_sva_unbind_device(uacce->pdev, pasid);
#endif
	return ret;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce *uacce;
	int ret;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce) {
		pr_err("fail to find uacce device!\n");
		return -ENODEV;
	}

	if (!uacce->ops->get_queue) {
		dev_err(uacce->pdev, "uacce driver get_queue is NULL!\n");
		return -EINVAL;
	}

	ret = uacce_dev_open_check(uacce);
	if (ret)
		return ret;

	ret = uacce_get_queue(uacce, filep);
	if (ret) {
		dev_err(uacce->pdev, "uacce get queue fail!\n");
		return ret;
	}

	if (!try_module_get(uacce->pdev->driver->owner)) {
		uacce_put_queue(filep->private_data);
		dev_err(uacce->pdev, "uacce try to get module(%s) fail!\n",
			uacce->pdev->driver->name);
		return -ENODEV;
	}

	return 0;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct uacce *uacce;

	uacce_qs_wlock();

	q = filep->private_data;
	if (q) {
		uacce = q->uacce;
		/*
		 * As user space exception(without release queue), it will
		 * fall into this logic as the task exits to prevent hardware
		 * resources leaking.
		 */
		uacce_queue_drain(q);
		filep->private_data = NULL;
	}

	uacce_qs_wunlock();

	if (q)
		module_put(uacce->pdev->driver->owner);

	return 0;
}

static enum uacce_qfrt uacce_get_region_type(struct uacce *uacce,
					     struct vm_area_struct *vma)
{
	enum uacce_qfrt type = UACCE_QFRT_MAX;
	size_t next_start = UACCE_QFR_NA;
	int i;

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

	case UACCE_QFRT_DUS:
		break;

	case UACCE_QFRT_SS:

		/* todo: this can be valid to protect the process space */
		if (uacce->flags & UACCE_DEV_FAULT_FROM_DEV) {
			dev_err(&uacce->dev, "no SS in SVA mode!\n");
			return UACCE_QFRT_INVALID;
		}
		break;

	default:
		dev_err(&uacce->dev, "uacce invalid type(%d)!\n", type);
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
			dev_err(&uacce->dev, "uacce config error. make sure setting SS offset properly\n");
			return UACCE_QFRT_INVALID;
		}

		if (vma_pages(vma) !=
		    next_start - uacce->qf_pg_start[type]) {
			dev_err(&uacce->dev, "invalid mmap size, (%ld vs %ld pages) for region %s.\n",
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
	struct uacce_qfile_region *qfr;
	struct uacce_queue *q;
	struct uacce *uacce;
	enum uacce_qfrt type;
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

	dev_dbg(&uacce->dev, "mmap q file(t=%s, off=%lx, start=%pK, end=%pK)\n",
		 qfrt_str[type], vma->vm_pgoff,
		(void *)vma->vm_start, (void *)vma->vm_end);

	if (type == UACCE_QFRT_INVALID) {
		ret = -EINVAL;
		goto out_with_lock;
	}

	/* this type of qfr has mapped already */
	if (q->qfrs[type]) {
		dev_err(uacce->pdev, "%d type qfr is existing!\n", type);
		ret = -EEXIST;
		goto out_with_lock;
	}

	if (!uacce_q_avail_mmap(q, type)) {
		ret = -EINVAL;
		goto out_with_lock;
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
	case UACCE_QFRT_DUS:
		flags = UACCE_QFRF_SELFMT;
		break;
	case UACCE_QFRT_SS:
		flags = UACCE_QFRF_MMAP | UACCE_QFRF_DMA;
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
	__poll_t ret = 0;

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
};

static ssize_t id_show(struct device *dev,
		       struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->dev_id);
}
static DEVICE_ATTR_RO(id);

static ssize_t api_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%s\n", uacce->api_ver);
}
static DEVICE_ATTR_RO(api);

static ssize_t numa_distance_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int distance = 0;

#ifdef CONFIG_NUMA
	distance = node_distance(uacce->pdev->numa_node,
		cpu_to_node(smp_processor_id()));
#endif
	return sprintf(buf, "%d\n", distance);
}
static DEVICE_ATTR_RO(numa_distance);

static ssize_t node_id_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int node_id = -1;

#ifdef CONFIG_NUMA
	node_id = uacce->pdev->numa_node;
#endif
	return sprintf(buf, "%d\n", node_id);
}
static DEVICE_ATTR_RO(node_id);

static ssize_t flags_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->flags);
}
static DEVICE_ATTR_RO(flags);

static ssize_t available_instances_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->ops->get_available_instances(uacce));
}
static DEVICE_ATTR_RO(available_instances);

static ssize_t algorithms_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%s", uacce->algs);
}
static DEVICE_ATTR_RO(algorithms);

static ssize_t qfrs_offset_show(struct device *dev,
				struct device_attribute *attr, char *buf)
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

static DEVICE_ATTR_RO(qfrs_offset);

static ssize_t isolate_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", atomic_read(&uacce->isolate->is_isolate));
}
static DEVICE_ATTR_RO(isolate);

static ssize_t isolate_strategy_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%u\n", uacce->isolate->hw_err_isolate_hz);
}

static ssize_t isolate_strategy_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	unsigned long val = 0;

#define MAX_ISOLATE_STRATEGY	65535

	/* must be set by PF */
	if (uacce->is_vf)
		return -EINVAL;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val > MAX_ISOLATE_STRATEGY)
		return -EINVAL;

	if (atomic_read(&uacce->ref))
		return -EBUSY;

	uacce->isolate->hw_err_isolate_hz = val;

	return count;
}
static DEVICE_ATTR_RW(isolate_strategy);

static ssize_t dev_state_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->ops->get_dev_state(uacce));
}
static DEVICE_ATTR_RO(dev_state);

static struct attribute *uacce_dev_attrs[] = {
	&dev_attr_id.attr,
	&dev_attr_api.attr,
	&dev_attr_node_id.attr,
	&dev_attr_numa_distance.attr,
	&dev_attr_flags.attr,
	&dev_attr_available_instances.attr,
	&dev_attr_algorithms.attr,
	&dev_attr_qfrs_offset.attr,
	&dev_attr_isolate.attr,
	&dev_attr_isolate_strategy.attr,
	&dev_attr_dev_state.attr,
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
		dev_warn(dev, "register to noiommu mode, it's not safe for kernel\n");
	}

	/* if dev support fault-from-dev, it should support pasid */
	if ((uacce->flags & UACCE_DEV_FAULT_FROM_DEV) &&
	    !(uacce->flags & UACCE_DEV_PASID)) {
		dev_err(dev, "SVM/SVA device should support PASID\n");
		return -EINVAL;
	}

	if (!uacce->ops) {
		dev_err(dev, "uacce ops is null\n");
		return -EINVAL;
	}

	if (!uacce->ops->start_queue)
		uacce->ops->start_queue = uacce_default_start_queue;

	if (!uacce->ops->get_available_instances)
		uacce->ops->get_available_instances =
			uacce_default_get_available_instances;

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
	INIT_LIST_HEAD(&uacce->isolate_data.hw_errs);

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
#endif
	uacce_hw_err_destroy(uacce);
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
