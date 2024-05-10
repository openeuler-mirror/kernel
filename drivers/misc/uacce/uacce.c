// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/compat.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uacce.h>
#include <linux/wait.h>

static dev_t uacce_devt;
static DEFINE_XARRAY_ALLOC(uacce_xa);
static const struct file_operations uacce_fops;

static const struct class uacce_class = {
	.name = UACCE_NAME,
};

static struct uacce_qfile_region noiommu_ss_default_qfr = {
	.type	=	UACCE_QFRT_SS,
};

/*
 * If the parent driver or the device disappears, the queue state is invalid and
 * ops are not usable anymore.
 */
static bool uacce_queue_is_valid(struct uacce_queue *q)
{
	return q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED;
}

static int uacce_start_queue(struct uacce_queue *q)
{
	int ret;

	if (q->state != UACCE_Q_INIT)
		return -EINVAL;

	if (q->uacce->ops->start_queue) {
		ret = q->uacce->ops->start_queue(q);
		if (ret < 0)
			return ret;
	}

	q->state = UACCE_Q_STARTED;
	return 0;
}

static int uacce_put_queue(struct uacce_queue *q)
{
	struct uacce_device *uacce = q->uacce;

	if ((q->state == UACCE_Q_STARTED) && uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	if ((q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) &&
	     uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	q->state = UACCE_Q_ZOMBIE;

	return 0;
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

	mutex_lock(&src->mutex);
	if (tgt->state == UACCE_Q_ZOMBIE || src->state == UACCE_Q_ZOMBIE) {
		dev_err(dev, "target or source queue is zombie!\n");
		goto out_with_fd;
	}

	if (!src->qfrs[UACCE_QFRT_SS] || tgt->qfrs[UACCE_QFRT_SS]) {
		dev_err(dev, "src q's SS not exists or target q's SS exists!\n");
		goto out_with_fd;
	}

	/* In No-IOMMU mode, taget queue uses default SS qfr */
	tgt->qfrs[UACCE_QFRT_SS] = &noiommu_ss_default_qfr;

	ret = 0;

out_with_fd:
	mutex_unlock(&src->mutex);
	fput(filep);

	return ret;
}

static long uacce_get_ss_dma(struct uacce_queue *q, void __user *arg)
{
	struct uacce_device *uacce = q->uacce;
	struct uacce_dma_slice *slice;
	unsigned long slice_idx = 0;
	unsigned long dma, size;
	unsigned int max_idx;
	long ret = -EFAULT;

	if (q->state == UACCE_Q_ZOMBIE) {
		dev_err(&uacce->dev, "queue is zombie!\n");
		ret = -EINVAL;
		goto param_check;
	}

	if (!q->qfrs[UACCE_QFRT_SS]) {
		dev_err(&uacce->dev, "no ss dma region!\n");
		ret = -EINVAL;
		goto param_check;
	}

	slice = q->qfrs[UACCE_QFRT_SS]->dma_list;
	if (copy_from_user(&slice_idx, arg, sizeof(unsigned long))) {
		dev_err(&uacce->dev, "copy_from_user fail!\n");
		goto param_check;
	}

	if (slice[0].total_num - 1 < slice_idx) {
		dev_err(&uacce->dev, "no ss slice idx %lu err, total %u!\n",
			slice_idx, slice[0].total_num);
		ret = -EINVAL;
		goto param_check;
	}

	dma = slice[slice_idx].dma;
	size = slice[slice_idx].size;
	if (!size) {
		max_idx = slice[0].total_num - 1;
		dev_err(&uacce->dev, "%luth ss region[size = %lu] no exist, range[[0](size = %llu) -> [%u](size = %llu)]\n",
			slice_idx, size, slice[0].size, max_idx, slice[max_idx].size);
		ret = -ENODEV;
		goto param_check;
	}
	dma = dma | ((size >> UACCE_GRAN_SHIFT) & UACCE_GRAN_NUM_MASK);
	if (copy_to_user(arg, &dma, sizeof(unsigned long))) {
		dev_err(&uacce->dev, "copy_to_user fail!\n");
		goto param_check;
	}

	ret = (long)(slice[0].total_num - 1 - slice_idx);

param_check:
	return ret;
}

static void uacce_free_dma_buffers(struct uacce_queue *q)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct device *pdev = q->uacce->parent;
	int i = 0;

	if (!qfr->dma_list)
		return;

	while (i < qfr->dma_list[0].total_num) {
		WARN_ON(!qfr->dma_list[i].size || !qfr->dma_list[i].dma);
		dev_dbg(pdev, "free dma qfr (index = %d)\n", i);
		dma_free_coherent(pdev, qfr->dma_list[i].size,
				  qfr->dma_list[i].kaddr,
				  qfr->dma_list[i].dma);
		i++;
	}
	kfree(qfr->dma_list);
	qfr->dma_list = NULL;
}

/**
 * uacce_wake_up - Wake up the process who is waiting this queue
 * @q: the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	if (unlikely(!q))
		return;

	wake_up_interruptible(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;
	long ret = -ENXIO;

	/*
	 * uacce->ops->ioctl() may take the mmap_lock when copying arg to/from
	 * user. Avoid a circular lock dependency with uacce_fops_mmap(), which
	 * gets called with mmap_lock held, by taking uacce->mutex instead of
	 * q->mutex. Doing this in uacce_fops_mmap() is not possible because
	 * uacce_fops_open() calls iommu_sva_bind_device(), which takes
	 * mmap_lock, while holding uacce->mutex.
	 */
	mutex_lock(&uacce->mutex);
	if (!uacce_queue_is_valid(q))
		goto out_unlock;

	switch (cmd) {
	case UACCE_CMD_START_Q:
		ret = uacce_start_queue(q);
		break;
	case UACCE_CMD_PUT_Q:
		ret = uacce_put_queue(q);
		break;
	case UACCE_CMD_SHARE_SVAS:
		ret = uacce_cmd_share_qfr(q, (int)arg);
		break;
	case UACCE_CMD_GET_SS_DMA:
		ret = uacce_get_ss_dma(q, (void __user *)(uintptr_t)arg);
		break;
	default:
		if (uacce->ops->ioctl)
			ret = uacce->ops->ioctl(q, cmd, arg);
		else
			ret = -EINVAL;
	}
out_unlock:
	mutex_unlock(&uacce->mutex);
	return ret;
}

#ifdef CONFIG_COMPAT
static long uacce_fops_compat_ioctl(struct file *filep,
				   unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)(uintptr_t)compat_ptr(arg);

	return uacce_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int uacce_bind_queue(struct uacce_device *uacce, struct uacce_queue *q)
{
	u32 pasid;
	struct iommu_sva *handle;

	if (!(uacce->flags & UACCE_DEV_SVA))
		return 0;

	handle = iommu_sva_bind_device(uacce->parent, current->mm);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	pasid = iommu_sva_get_pasid(handle);
	if (pasid == IOMMU_PASID_INVALID) {
		iommu_sva_unbind_device(handle);
		return -ENODEV;
	}

	q->handle = handle;
	q->pasid = pasid;
	return 0;
}

static void uacce_unbind_queue(struct uacce_queue *q)
{
	if (!q->handle)
		return;
	iommu_sva_unbind_device(q->handle);
	q->handle = NULL;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_device *uacce;
	struct uacce_queue *q;
	int ret;

	uacce = xa_load(&uacce_xa, iminor(inode));
	if (!uacce)
		return -ENODEV;

	q = kzalloc(sizeof(struct uacce_queue), GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	mutex_lock(&uacce->mutex);

	if (!uacce->parent) {
		ret = -EINVAL;
		goto out_with_mem;
	}

	ret = uacce_bind_queue(uacce, q);
	if (ret)
		goto out_with_mem;

	q->uacce = uacce;
	q->filep = filep;

	if (uacce->ops->get_queue) {
		ret = uacce->ops->get_queue(uacce, q->pasid, q);
		if (ret < 0)
			goto out_with_bond;
	}

	init_waitqueue_head(&q->wait);
	filep->private_data = q;
	q->state = UACCE_Q_INIT;
	q->mapping = filep->f_mapping;
	mutex_init(&q->mutex);
	list_add(&q->list, &uacce->queues);
	mutex_unlock(&uacce->mutex);

	return 0;

out_with_bond:
	uacce_unbind_queue(q);
out_with_mem:
	kfree(q);
	mutex_unlock(&uacce->mutex);
	return ret;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;
	struct uacce_qfile_region *ss;

	mutex_lock(&uacce->mutex);
	uacce_put_queue(q);
	uacce_unbind_queue(q);
	ss = q->qfrs[UACCE_QFRT_SS];
	if (ss && ss != &noiommu_ss_default_qfr) {
		uacce_free_dma_buffers(q);
		kfree(ss);
	}
	list_del(&q->list);
	mutex_unlock(&uacce->mutex);
	kfree(q);

	return 0;
}

static void uacce_vma_close(struct vm_area_struct *vma)
{
	struct uacce_queue *q = vma->vm_private_data;
	struct uacce_qfile_region *qfr = NULL;
	struct uacce_device *uacce = q->uacce;
	struct device *dev = &q->uacce->dev;

	if (vma->vm_pgoff >= UACCE_MAX_REGION)
		return;

	qfr = q->qfrs[vma->vm_pgoff];
	if (!qfr) {
		dev_err(dev, "qfr NULL, type %lu!\n", vma->vm_pgoff);
		return;
	}

	if (qfr->type == UACCE_QFRT_SS &&
	    atomic_read(&current->active_mm->mm_users) > 0) {
		/*
		 * uacce_vma_close() and uacce_remove() may be executed concurrently.
		 * To avoid accessing the same address at the same time, takes the uacce->mutex.
		 */
		mutex_lock(&uacce->mutex);
		if ((q->state == UACCE_Q_STARTED) && uacce->ops->stop_queue)
			uacce->ops->stop_queue(q);
		uacce_free_dma_buffers(q);
		q->qfrs[vma->vm_pgoff] = NULL;
		mutex_unlock(&uacce->mutex);
		kfree(qfr);
	} else if (qfr->type != UACCE_QFRT_SS) {
		mutex_lock(&q->mutex);
		q->qfrs[vma->vm_pgoff] = NULL;
		mutex_unlock(&q->mutex);
		kfree(qfr);
	}
}

static const struct vm_operations_struct uacce_vm_ops = {
	.close = uacce_vma_close,
};

static int get_sort_base(struct uacce_dma_slice *list, int low, int high,
			 struct uacce_dma_slice *tmp)
{
	tmp->kaddr = list[low].kaddr;
	tmp->size = list[low].size;
	tmp->dma = list[low].dma;

	if (low > high)
		return -EINVAL;
	else if (low == high)
		return 0;

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

static int uacce_sort_dma_buffers(struct uacce_dma_slice *list, int low,
				   int high, struct uacce_dma_slice *tmp)
{
	int *idx_list;
	int top = 0;
	int pilot;

	idx_list = kcalloc(list[0].total_num, sizeof(int),
			   GFP_KERNEL | __GFP_ZERO);
	if (!idx_list)
		return -ENOMEM;

	pilot = get_sort_base(list, low, high, tmp);
	if (pilot <= 0) {
		if (pilot)
			pr_err("fail to sort base!\n");
		kfree(idx_list);
		return pilot;
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
	return 0;
}

static int uacce_alloc_dma_buffers(struct uacce_queue *q,
				   struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long max_size = PAGE_SIZE << (MAX_ORDER - 1);
	struct device *pdev = q->uacce->parent;
	struct uacce_device *uacce = q->uacce;
	unsigned long start = vma->vm_start;
	struct uacce_dma_slice *slice;
	unsigned long ss_num;
	int ret, i;

	/*
	 * When IOMMU closed, set maximum slice size is 128M, default is 4M
	 * when IOMMU opened, set maxinum slice size base on actual size
	 */
	if (uacce->flags & UACCE_DEV_IOMMU)
		max_size = size;
	else if (max_size > UACCE_GRAN_NUM_MASK << UACCE_GRAN_SHIFT)
		max_size = (UACCE_GRAN_NUM_MASK + 1) << (UACCE_GRAN_SHIFT - 1);

	ss_num = size / max_size + (size % max_size ? 1 : 0);
	slice = kcalloc(ss_num + 1, sizeof(*slice), GFP_KERNEL | __GFP_ZERO);
	if (!slice)
		return -ENOMEM;

	qfr->dma_list = slice;
	for (i = 0; i < ss_num; i++) {
		if (start + max_size > vma->vm_end)
			size = vma->vm_end - start;
		else
			size = max_size;
		dev_dbg(pdev, "allocate dma %ld pages\n",
			(size + PAGE_SIZE - 1) >> PAGE_SHIFT);
		slice[i].kaddr = dma_alloc_coherent(pdev, (size +
						    PAGE_SIZE - 1) & PAGE_MASK,
						    &slice[i].dma, GFP_KERNEL);
		if (!slice[i].kaddr) {
			dev_err(pdev, "get dma slice(sz = %lu, dma index = %d) fail!\n",
			size, i);
			slice[0].total_num = i;
			ret = -ENOMEM;
			goto free_buffer;
		}
		slice[i].size = (size + PAGE_SIZE - 1) & PAGE_MASK;
		slice[i].total_num = ss_num;
		start += size;
	}

	ret = uacce_sort_dma_buffers(slice, 0, slice[0].total_num - 1,
				      &slice[ss_num]);
	if (ret) {
		dev_err(pdev, "failed to sort dma buffers.\n");
		goto free_buffer;
	}

	return 0;
free_buffer:
	uacce_free_dma_buffers(q);

	return ret;
}

static int uacce_mmap_dma_buffers(struct uacce_queue *q,
				  struct vm_area_struct *vma)
{
	struct uacce_qfile_region *qfr = q->qfrs[UACCE_QFRT_SS];
	struct uacce_dma_slice *slice = qfr->dma_list;
	struct device *pdev = q->uacce->parent;
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
		ret = dma_mmap_coherent(pdev, vma, slice[i].kaddr,
					slice[i].dma,
					slice[i].size);
		if (ret) {
			dev_err(pdev, "dma mmap fail(dma index = %d, size = %llu)!\n",
				i, slice[i].size);
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

static int uacce_create_region(struct uacce_queue *q,
					struct vm_area_struct *vma,
					struct uacce_qfile_region *qfr)
{
	int ret;

	qfr->iova = vma->vm_start;
	qfr->nr_pages = vma_pages(vma);

	/* allocate memory */
	ret = uacce_alloc_dma_buffers(q, vma);
	if (ret)
		return ret;

	ret = uacce_mmap_dma_buffers(q, vma);
	if (ret)
		goto err_with_pages;

	return ret;

err_with_pages:
	uacce_free_dma_buffers(q);
	return ret;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;
	struct uacce_qfile_region *qfr;
	enum uacce_qfrt type = UACCE_MAX_REGION;
	int ret = 0;

	if (vma->vm_pgoff < UACCE_MAX_REGION)
		type = vma->vm_pgoff;
	else
		return -EINVAL;

	if (q->qfrs[type])
		return -EEXIST;

	qfr = kzalloc(sizeof(*qfr), GFP_KERNEL);
	if (!qfr)
		return -ENOMEM;

	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_WIPEONFORK);
	vma->vm_ops = &uacce_vm_ops;
	vma->vm_private_data = q;
	qfr->type = type;

	mutex_lock(&q->mutex);
	if (!uacce_queue_is_valid(q)) {
		ret = -ENXIO;
		goto out_with_lock;
	}

	q->qfrs[type] = qfr;

	switch (type) {
	case UACCE_QFRT_MMIO:
	case UACCE_QFRT_DUS:
		if (!uacce->ops->mmap) {
			ret = -EINVAL;
			goto out_with_lock;
		}

		ret = uacce->ops->mmap(q, vma, qfr);
		if (ret)
			goto out_with_lock;
		break;

	case UACCE_QFRT_SS:
		ret = uacce_create_region(q, vma, qfr);
		if (ret)
			goto out_with_lock;
		break;

	default:
		ret = -EINVAL;
		goto out_with_lock;
	}

	mutex_unlock(&q->mutex);

	return ret;

out_with_lock:
	mutex_unlock(&q->mutex);
	kfree(qfr);
	q->qfrs[type] = NULL;
	return ret;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q = file->private_data;
	struct uacce_device *uacce = q->uacce;
	__poll_t ret = 0;

	mutex_lock(&q->mutex);
	if (!uacce_queue_is_valid(q))
		goto out_unlock;

	poll_wait(file, &q->wait, wait);

	if (uacce->ops->is_q_updated && uacce->ops->is_q_updated(q))
		ret = EPOLLIN | EPOLLRDNORM;

out_unlock:
	mutex_unlock(&q->mutex);
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

#define to_uacce_device(dev) container_of(dev, struct uacce_device, dev)

static ssize_t api_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%s\n", uacce->api_ver);
}

static ssize_t flags_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%u\n", uacce->flags);
}

static ssize_t available_instances_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	if (!uacce->ops->get_available_instances)
		return -ENODEV;

	return sysfs_emit(buf, "%d\n",
		       uacce->ops->get_available_instances(uacce));
}

static ssize_t algorithms_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%s\n", uacce->algs);
}

static ssize_t region_mmio_size_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%lu\n",
		       uacce->qf_pg_num[UACCE_QFRT_MMIO] << PAGE_SHIFT);
}

static ssize_t region_dus_size_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%lu\n",
		       uacce->qf_pg_num[UACCE_QFRT_DUS] << PAGE_SHIFT);
}

static ssize_t isolate_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sysfs_emit(buf, "%d\n", uacce->ops->get_isolate_state(uacce));
}

static ssize_t isolate_strategy_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	u32 val;

	val = uacce->ops->isolate_err_threshold_read(uacce);

	return sysfs_emit(buf, "%u\n", val);
}

static ssize_t isolate_strategy_store(struct device *dev, struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	unsigned long val;
	int ret;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val > UACCE_MAX_ERR_THRESHOLD)
		return -EINVAL;

	ret = uacce->ops->isolate_err_threshold_write(uacce, val);
	if (ret)
		return ret;

	return count;
}

static ssize_t node_id_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	int node_id = -1;

#ifdef CONFIG_NUMA
	struct uacce_device *uacce = to_uacce_device(dev);

	node_id = uacce->parent->numa_node;
#endif
	return sysfs_emit(buf, "%d\n", node_id);
}

static ssize_t numa_distance_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	int distance = 0;

#ifdef CONFIG_NUMA
	struct uacce_device *uacce = to_uacce_device(dev);

	distance = node_distance(uacce->parent->numa_node,
		cpu_to_node(smp_processor_id()));
#endif
	return sysfs_emit(buf, "%d\n", distance);
}

static DEVICE_ATTR_RO(api);
static DEVICE_ATTR_RO(flags);
static DEVICE_ATTR_RO(node_id);
static DEVICE_ATTR_RO(available_instances);
static DEVICE_ATTR_RO(algorithms);
static DEVICE_ATTR_RO(region_mmio_size);
static DEVICE_ATTR_RO(region_dus_size);
static DEVICE_ATTR_RO(isolate);
static DEVICE_ATTR_RW(isolate_strategy);
static DEVICE_ATTR_RO(numa_distance);

static struct attribute *uacce_dev_attrs[] = {
	&dev_attr_api.attr,
	&dev_attr_flags.attr,
	&dev_attr_node_id.attr,
	&dev_attr_available_instances.attr,
	&dev_attr_algorithms.attr,
	&dev_attr_region_mmio_size.attr,
	&dev_attr_region_dus_size.attr,
	&dev_attr_isolate.attr,
	&dev_attr_isolate_strategy.attr,
	&dev_attr_numa_distance.attr,
	NULL,
};

static umode_t uacce_dev_is_visible(struct kobject *kobj,
				    struct attribute *attr, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct uacce_device *uacce = to_uacce_device(dev);

	if (((attr == &dev_attr_region_mmio_size.attr) &&
	    (!uacce->qf_pg_num[UACCE_QFRT_MMIO])) ||
	    ((attr == &dev_attr_region_dus_size.attr) &&
	    (!uacce->qf_pg_num[UACCE_QFRT_DUS])))
		return 0;

	if (attr == &dev_attr_isolate_strategy.attr &&
	    (!uacce->ops->isolate_err_threshold_read &&
	     !uacce->ops->isolate_err_threshold_write))
		return 0;

	if (attr == &dev_attr_isolate.attr && !uacce->ops->get_isolate_state)
		return 0;

	return attr->mode;
}

static struct attribute_group uacce_dev_group = {
	.is_visible	= uacce_dev_is_visible,
	.attrs		= uacce_dev_attrs,
};

__ATTRIBUTE_GROUPS(uacce_dev);

static void uacce_release(struct device *dev)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	kfree(uacce);
}

static unsigned int uacce_enable_sva(struct device *parent, unsigned int flags)
{
	int ret;

	if (!(flags & UACCE_DEV_SVA))
		return flags;

	flags &= ~UACCE_DEV_SVA;

	ret = iommu_dev_enable_feature(parent, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		dev_err(parent, "failed to enable IOPF feature! ret = %pe\n", ERR_PTR(ret));
		return flags;
	}

	ret = iommu_dev_enable_feature(parent, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		dev_err(parent, "failed to enable SVA feature! ret = %pe\n", ERR_PTR(ret));
		iommu_dev_disable_feature(parent, IOMMU_DEV_FEAT_IOPF);
		return flags;
	}

	return flags | UACCE_DEV_SVA;
}

static void uacce_disable_sva(struct uacce_device *uacce)
{
	if (!(uacce->flags & UACCE_DEV_SVA))
		return;

	iommu_dev_disable_feature(uacce->parent, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(uacce->parent, IOMMU_DEV_FEAT_IOPF);
}

/**
 * uacce_alloc() - alloc an accelerator
 * @parent: pointer of uacce parent device
 * @interface: pointer of uacce_interface for register
 *
 * Returns uacce pointer if success and ERR_PTR if not
 * Need check returned negotiated uacce->flags
 */
struct uacce_device *uacce_alloc(struct device *parent,
				 struct uacce_interface *interface)
{
	struct uacce_device *uacce;
	unsigned int flags;
	int ret;

	if (!parent || !interface)
		return ERR_PTR(-EINVAL);

	uacce = kzalloc(sizeof(struct uacce_device), GFP_KERNEL);
	if (!uacce)
		return ERR_PTR(-ENOMEM);

	flags = interface->flags;
	flags = uacce_enable_sva(parent, flags);

	uacce->parent = parent;
	uacce->flags = flags;
	uacce->ops = interface->ops;

	ret = xa_alloc(&uacce_xa, &uacce->dev_id, uacce, xa_limit_32b,
		       GFP_KERNEL);
	if (ret < 0)
		goto err_with_uacce;

	INIT_LIST_HEAD(&uacce->queues);
	mutex_init(&uacce->mutex);
	device_initialize(&uacce->dev);
	uacce->dev.devt = MKDEV(MAJOR(uacce_devt), uacce->dev_id);
	uacce->dev.class = &uacce_class;
	uacce->dev.groups = uacce_dev_groups;
	uacce->dev.parent = uacce->parent;
	uacce->dev.release = uacce_release;
	dev_set_name(&uacce->dev, "%s-%u", interface->name, uacce->dev_id);

	if (flags & UACCE_DEV_NOIOMMU)
		dev_warn(&uacce->dev, "register to noiommu mode, it's not safe for kernel\n");

	return uacce;

err_with_uacce:
	uacce_disable_sva(uacce);
	kfree(uacce);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(uacce_alloc);

/**
 * uacce_register() - add the accelerator to cdev and export to user space
 * @uacce: The initialized uacce device
 *
 * Return 0 if register succeeded, or an error.
 */
int uacce_register(struct uacce_device *uacce)
{
	int ret;

	if (!uacce)
		return -ENODEV;

	uacce->cdev = cdev_alloc();
	if (!uacce->cdev)
		return -ENOMEM;

	uacce->cdev->ops = &uacce_fops;
	uacce->cdev->owner = THIS_MODULE;

	ret = cdev_device_add(uacce->cdev, &uacce->dev);
	if (ret) {
		cdev_del(uacce->cdev);
		uacce->cdev = NULL;
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(uacce_register);

/**
 * uacce_remove() - remove the accelerator
 * @uacce: the accelerator to remove
 */
void uacce_remove(struct uacce_device *uacce)
{
	struct uacce_queue *q, *next_q;

	if (!uacce)
		return;

	/*
	 * uacce_fops_open() may be running concurrently, even after we remove
	 * the cdev. Holding uacce->mutex ensures that open() does not obtain a
	 * removed uacce device.
	 */
	mutex_lock(&uacce->mutex);
	/* ensure no open queue remains */
	list_for_each_entry_safe(q, next_q, &uacce->queues, list) {
		struct uacce_qfile_region *ss = q->qfrs[UACCE_QFRT_SS];
		/*
		 * Taking q->mutex ensures that fops do not use the defunct
		 * uacce->ops after the queue is disabled.
		 */
		mutex_lock(&q->mutex);
		uacce_put_queue(q);
		mutex_unlock(&q->mutex);
		uacce_unbind_queue(q);

		/*
		 * unmap remaining mapping from user space, preventing user still
		 * access the mmaped area while parent device is already removed
		 */
		unmap_mapping_range(q->mapping, 0, 0, 1);
		if (ss && ss != &noiommu_ss_default_qfr)
			uacce_free_dma_buffers(q);
	}

	/* disable sva now since no opened queues */
	uacce_disable_sva(uacce);

	if (uacce->cdev)
		cdev_device_del(uacce->cdev, &uacce->dev);
	xa_erase(&uacce_xa, uacce->dev_id);
	/*
	 * uacce exists as long as there are open fds, but ops will be freed
	 * now. Ensure that bugs cause NULL deref rather than use-after-free.
	 */
	uacce->ops = NULL;
	uacce->parent = NULL;
	mutex_unlock(&uacce->mutex);
	put_device(&uacce->dev);
}
EXPORT_SYMBOL_GPL(uacce_remove);

static int __init uacce_init(void)
{
	int ret;

	ret = class_register(&uacce_class);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&uacce_devt, 0, MINORMASK, UACCE_NAME);
	if (ret)
		class_unregister(&uacce_class);

	return ret;
}

static __exit void uacce_exit(void)
{
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_unregister(&uacce_class);
}

subsys_initcall(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HiSilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
