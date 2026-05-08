// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_cdev.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/wait.h>

#include "sxe2_compat.h"
#include "sxe2_log.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_com_cdev.h"
#include "sxe2_com_ver_compat.h"

#define SXE2_MAX_COM_CMDS (1)

STATIC dev_t sxe2_com_cdev_major;
STATIC struct class *sxe2_com_cdev_class;
STATIC struct sxe2_com_dev_mgr sxe2_com_mgr;
STATIC struct mutex sxe2_com_minor_lock;
STATIC DEFINE_IDR(sxe2_com_minor_idr);

static struct sxe2_com_dev_mgr *sxe2_com_dev_get(void)
{
	return &sxe2_com_mgr;
}

STATIC s32 sxe2_com_handshake(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret = 0;
	struct sxe2_ioctl_cmd_common_hdr hdr = {};
	u32 arg_sz;
	u32 dpdk_ver;

	mutex_lock(&com_ctxt->com_lock);
	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_HANDSHAKE);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("sxe2_com_get_arg_sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver,
				  SXE2_DEVICE_HANDSHAKE);
		goto l_unlock;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&hdr, (void __user *)arg, arg_sz)) {
		ret = -EFAULT;
		LOG_ERROR_BDF_COM("copy user arg failed ver: 0x%x arg_sz:%u.\n",
				  com_ctxt->dpdk_ver, arg_sz);
		goto l_unlock;
	}

	if (SXE2_MK_VER_MAJOR(hdr.dpdk_ver) != SXE2_MK_VER_MAJOR(SXE2_COM_VER)) {
		LOG_ERROR_BDF_COM("incompatible dpdk ver: 0x%x.\n", hdr.dpdk_ver);
		ret = -EINVAL;
		goto l_unlock;
	}

	dpdk_ver = hdr.dpdk_ver;

	memset(&hdr, 0, sizeof(hdr));
	hdr.drv_ver = SXE2_COM_VER;
	hdr.msg_len = arg_sz;

	if (sxe2_com_iommu_supp(&com_ctxt->dma_dev))
		hdr.cap |= (1 << SXE2_COM_CAP_IOMMU_MAP);

	if (copy_to_user((void __user *)arg, &hdr, arg_sz)) {
		ret = -EFAULT;
		LOG_ERROR_BDF_COM("copy user hdr failed ver: 0x%x.\n", com_ctxt->dpdk_ver);
		goto l_unlock;
	}

	com_ctxt->dpdk_ver = dpdk_ver;
	com_ctxt->is_handshake = true;

l_unlock:
	mutex_unlock(&com_ctxt->com_lock);
	return ret;
}

static s32 sxe2_com_cmd_exec(struct sxe2_com_context *com_ctxt, unsigned long arg)
{
	s32 ret;
	struct sxe2_drv_cmd_params param = {};
	u32 arg_sz;

	ret = sxe2_com_get_arg_sz(com_ctxt->dpdk_ver, SXE2_DEVICE_PASSTHROUGH);
	if (ret < 0) {
		LOG_ERROR_BDF_COM("sxe2_com_get_arg_sz failed, ver: %d, cmd:%d\n",
				  com_ctxt->dpdk_ver,
				  SXE2_DEVICE_PASSTHROUGH);
		return ret;
	}

	arg_sz = ret;
	ret = 0;

	if (copy_from_user(&param, (void __user *)arg, arg_sz))
		return -EFAULT;

	if (!com_ctxt->ops || !com_ctxt->ops->cmd_exec)
		return -EFAULT;

	ret = com_ctxt->ops->cmd_exec(com_ctxt->adapter, &com_ctxt->obj, &param);

	LOG_DEBUG_BDF_COM("result:%d\n", ret);

	return ret;
}

STATIC long sxe2_com_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct sxe2_com_context *com_ctxt = (struct sxe2_com_context *)filep->private_data;
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();

	if (!filep || cmd == 0 || arg == 0 || !com_ctxt) {
		LOG_ERROR_BDF_COM("filep=%pK cmd=%d arg=%ld, com_ctxt=%pK\n",
				  filep, cmd, arg, com_ctxt);
		ret = -EINVAL;
		goto l_end;
	}

	LOG_DEBUG_BDF_COM("driver dpdk cmd=%x, arg=0x%lx\n", cmd, arg);

	mutex_lock(&dev_mgr->lock);
	if (com_ctxt->status == SXE2_COM_CDEV_STATUS_UNACCESS) {
		mutex_unlock(&dev_mgr->lock);
		ret = -EACCES;
		goto l_end;
	}
	mutex_unlock(&dev_mgr->lock);

	if (!com_ctxt->is_handshake && cmd != SXE2_COM_CMD_HANDSHAKE) {
		LOG_WARN_BDF_COM("plase handshake first\n");
		ret = -ERESTARTSYS;
		goto l_end;
	}

	if (down_interruptible(&com_ctxt->cdev_info.cdev_sem)) {
		LOG_WARN_BDF_COM("ioctl concurrency full\n");
		ret = -ERESTARTSYS;
		goto l_end;
	}

	switch (cmd) {
	case SXE2_COM_CMD_HANDSHAKE:
		ret = sxe2_com_handshake(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_IO_IRQS_REQ:
		ret = sxe2_com_io_irq_req(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_EVT_IRQ_REQ:
		ret = sxe2_com_event_irq_req(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_EVT_CAUSE_GET:
		ret = sxe2_com_event_cause_get(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_RST_IRQ_REQ:
		ret = sxe2_com_reset_irq_req(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_DMA_MAP:
		ret = sxe2_com_dma_map(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_DMA_UNMAP:
		ret = sxe2_com_dma_unmap(com_ctxt, arg);
		break;
	case SXE2_COM_CMD_PASSTHROUGH:
		ret = sxe2_com_cmd_exec(com_ctxt, arg);
		break;
	default:
		ret = -EINVAL;
		LOG_ERROR_BDF_COM("unknown ioctl cmd, filep=%p, cmd=%d, arg=0x%8.8lx\n",
				  filep, cmd, arg);
		break;
	}

	up(&com_ctxt->cdev_info.cdev_sem);

l_end:
	if (ret) {
		LOG_ERROR_BDF_COM("driver ioctl filep=%p, cmd=%x, arg=0x%lx end, ret:%ld\n",
				  filep, cmd, arg, ret);
	} else {
		LOG_DEBUG_BDF_COM("driver ioctl filep=%p, cmd=%x, arg=0x%lx end, ret:%ld\n",
				  filep, cmd, arg, ret);
	}

	return ret;
}

static s32 sxe2_com_add_vma(struct sxe2_com_context *com_ctxt, struct vm_area_struct *vma)
{
	struct sxe2_com_vma_device *mmap_vma;

	mmap_vma = kmalloc(sizeof(*mmap_vma), GFP_KERNEL);
	if (!mmap_vma)
		return -ENOMEM;

	mmap_vma->vma = vma;
	list_add(&mmap_vma->vma_next, &com_ctxt->vma.vma_list);

	return 0;
}

STATIC vm_fault_t __sxe2_com_mmap(struct vm_area_struct *vma)
{
	struct sxe2_com_context *com_ctxt = vma->vm_private_data;
	struct sxe2_com_vma_device *mmap_vma;
	vm_fault_t ret = VM_FAULT_NOPAGE;

	mutex_lock(&com_ctxt->vma.vma_lock);

	list_for_each_entry(mmap_vma, &com_ctxt->vma.vma_list, vma_next) {
		if (mmap_vma->vma == vma)
			goto l_out;
	}
	if (io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		ret = VM_FAULT_SIGBUS;
		zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
		goto l_out;
	}

	if (sxe2_com_add_vma(com_ctxt, vma)) {
		ret = VM_FAULT_OOM;
		zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	}

l_out:
	mutex_unlock(&com_ctxt->vma.vma_lock);
	return ret;
}

STATIC vm_fault_t __sxe2_com_mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct sxe2_com_context *com_ctxt = vma->vm_private_data;
	s32 ret = VM_FAULT_NOPAGE;
	struct page *new_page = NULL;
	unsigned long pfn;

	mutex_lock(&com_ctxt->vma.vma_lock);

	if (vma->vm_flags & FAULT_FLAG_WRITE) {
		new_page = com_ctxt->vma.write_page;
		LOG_WARN_BDF_COM("write fault at VA 0x%lx\n", vmf->address);
	} else {
		new_page = com_ctxt->vma.read_page;
		LOG_WARN_BDF_COM("read fault at VA 0x%lx\n", vmf->address);
	}

	pfn = page_to_pfn(new_page);

	ret = vmf_insert_pfn(vma, vmf->address, pfn);
	if (ret & VM_FAULT_ERROR) {
		LOG_ERROR_BDF_COM("failed to insert pfn into page tables\n");
		goto l_out;
	}

	LOG_INFO_BDF_COM("successfully handled page fault\n");

l_out:
	mutex_unlock(&com_ctxt->vma.vma_lock);
	return ret;
}

static vm_fault_t sxe2_com_mmap_fault(struct vm_fault *vmf)
{
	vm_fault_t ret = VM_FAULT_SIGBUS;
	struct vm_area_struct *vma = vmf->vma;
	struct sxe2_com_context *com_ctxt = vma->vm_private_data;
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();

	mutex_lock(&dev_mgr->lock);

	if (com_ctxt->status == SXE2_COM_CDEV_STATUS_UNACCESS)
		ret = __sxe2_com_mmap_fault(vmf);
	else
		ret = __sxe2_com_mmap(vma);

	mutex_unlock(&dev_mgr->lock);

	return ret;
}

static void sxe2_com_mmap_open(struct vm_area_struct *vma)
{
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

static void sxe2_com_mmap_clear(struct sxe2_com_context *com_ctxt)
{
	struct sxe2_com_vma_device *mmap_vma;
	struct sxe2_com_vma_device *tmp;

	mutex_lock(&com_ctxt->vma.vma_lock);
	list_for_each_entry_safe(mmap_vma, tmp, &com_ctxt->vma.vma_list, vma_next) {
		struct vm_area_struct *vma = mmap_vma->vma;

		zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);

		list_del(&mmap_vma->vma_next);
		kfree(mmap_vma);
	}

	mutex_unlock(&com_ctxt->vma.vma_lock);
}

static void sxe2_com_mmap_close(struct vm_area_struct *vma)
{
	struct sxe2_com_context *com_ctxt = vma->vm_private_data;
	struct sxe2_com_vma_device *mmap_vma;

	mutex_lock(&com_ctxt->vma.vma_lock);
	list_for_each_entry(mmap_vma, &com_ctxt->vma.vma_list, vma_next) {
		if (mmap_vma->vma == vma) {
			list_del(&mmap_vma->vma_next);
			kfree(mmap_vma);
			break;
		}
	}
	mutex_unlock(&com_ctxt->vma.vma_lock);
}

static const struct vm_operations_struct sxe2_com_mmap_ops = {
	.open = sxe2_com_mmap_open,
	.close = sxe2_com_mmap_close,
	.fault = sxe2_com_mmap_fault,
};

STATIC s32 sxe2_com_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct sxe2_com_context *com_ctxt = (struct sxe2_com_context *)filp->private_data;
	struct pci_dev *pdev = com_ctxt->pdev;
	u32 bar_idx;
	u64 phys_len, req_len, pgoff, req_start;

	bar_idx = vma->vm_pgoff >> (SXE2_COM_PCI_OFFSET_SHIFT - PAGE_SHIFT);

	if (bar_idx >= DEVICE_COUNT_RESOURCE) {
		return -EINVAL;
		(void)pdev;
	}

	if (vma->vm_end <= vma->vm_start) {
		LOG_WARN_BDF_COM("end:%lu large than start:%lu.\n", vma->vm_end, vma->vm_start);
		return -EINVAL;
		(void)pdev;
	}
	if ((vma->vm_flags & VM_SHARED) == 0) {
		return -EINVAL;
		(void)pdev;
	}

	phys_len = PAGE_ALIGN(pci_resource_len(pdev, bar_idx));
	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff & ((1U << (SXE2_COM_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (req_start + req_len > phys_len)
		return -EINVAL;

	vma->vm_private_data = com_ctxt;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (pci_resource_start(pdev, bar_idx) >> PAGE_SHIFT) + pgoff;

	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &sxe2_com_mmap_ops;

	return 0;
}

STATIC void fill_page_with_ff(struct page *page)
{
	void *kaddr;

	kaddr = kmap_local_page(page);
	if (kaddr) {
		memset(kaddr, 0xFF, PAGE_SIZE);
		kunmap_local(kaddr);
	}
}

STATIC int sxe2_com_bar_init(struct sxe2_com_context *com_ctxt)
{
	int ret = 0;

	com_ctxt->vma.read_page = dev_alloc_pages(0);
	if (unlikely(!com_ctxt->vma.read_page)) {
		LOG_ERROR_BDF_COM("failed to allocate page in fault handler\n");
		ret = -ENOMEM;
		goto l_out;
	}
	fill_page_with_ff(com_ctxt->vma.read_page);

	com_ctxt->vma.write_page = dev_alloc_pages(0);
	if (unlikely(!com_ctxt->vma.write_page)) {
		LOG_ERROR_BDF_COM("failed to allocate page in fault handler\n");
		ret = -ENOMEM;
		goto l_read_page_failed;
	}

	return ret;
l_read_page_failed:
	__free_pages(com_ctxt->vma.read_page, 0);
l_out:
	return ret;
}

STATIC void sxe2_com_bar_deinit(struct sxe2_com_context *com_ctxt)
{
	__free_pages(com_ctxt->vma.read_page, 0);
	__free_pages(com_ctxt->vma.write_page, 0);
}

STATIC s32 sxe2_com_open(struct inode *node, struct file *filep)
{
	s32 ret = 0;
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();
	struct sxe2_com_context *com_ctxt;

	com_ctxt = container_of(node->i_cdev, struct sxe2_com_context, cdev_info.cdev);

	filep->private_data = com_ctxt;

	mutex_lock(&dev_mgr->lock);

	if (!atomic_read(&com_ctxt->ref_count) == 0) {
		LOG_DEV_WARN_COM("only allow open once\n");
		ret = -EBUSY;
		goto l_unlock;
	}

	if (com_ctxt->status == SXE2_COM_CDEV_STATUS_UNACCESS) {
		ret = -EACCES;
		goto l_unlock;
	}

	atomic_inc(&com_ctxt->ref_count);

	com_ctxt->obj.func_type = com_ctxt->func_type;
	com_ctxt->obj.drv_type = SXE2_DPDK_DRV;
	com_ctxt->obj.pf_id = com_ctxt->pf_id;
	com_ctxt->obj.vf_id = com_ctxt->vf_id;
	com_ctxt->obj.drv_id = 0;

l_unlock:
	mutex_unlock(&dev_mgr->lock);
	return ret;
}

STATIC void sxe2_com_ctxt_clear(struct sxe2_com_context *com_ctxt)
{
	mutex_lock(&com_ctxt->com_lock);
	com_ctxt->dpdk_ver = SXE2_COM_INVAL_U32;
	com_ctxt->is_handshake = false;
	mutex_unlock(&com_ctxt->com_lock);
}

STATIC void sxe2_com_resource_clear(struct sxe2_com_context *com_ctxt)
{
	sxe2_com_mmap_clear(com_ctxt);

	sxe2_com_irqs_clear(com_ctxt);

	sxe2_com_dma_clear(com_ctxt);
}

STATIC void sxe2_com_clear(struct sxe2_com_context *com_ctxt)
{
	sxe2_com_ctxt_clear(com_ctxt);

	if (com_ctxt->ops && com_ctxt->ops->release)
		com_ctxt->ops->release(com_ctxt->adapter, &com_ctxt->obj);

	(void)sxe2_com_irq_notifier_call_chain(com_ctxt, SXE2_COM_EC_RESET);

	sxe2_com_resource_clear(com_ctxt);
}

STATIC s32 sxe2_com_close(struct inode *node, struct file *filep)
{
	struct sxe2_com_context *com_ctxt = (struct sxe2_com_context *)filep->private_data;
	s32 ref_count = 0;
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();

	sxe2_com_clear(com_ctxt);

	mutex_lock(&dev_mgr->lock);
	ref_count = atomic_dec_return(&com_ctxt->ref_count);
	if (ref_count == 0)
		wake_up(&com_ctxt->waitq);
	mutex_unlock(&dev_mgr->lock);

	return 0;
}

void sxe2_com_disable(struct sxe2_com_context *com_ctxt)
{
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();

	if (!com_ctxt->ops || !com_ctxt->ops->com_mode_get ||
	    (com_ctxt->ops->com_mode_get(com_ctxt->adapter) == SXE2_COM_MODULE_KERNEL))
		return;

	mutex_lock(&dev_mgr->lock);
	com_ctxt->status = SXE2_COM_CDEV_STATUS_UNACCESS;
	sxe2_com_clear(com_ctxt);
	mutex_unlock(&dev_mgr->lock);
}

void sxe2_com_enable(struct sxe2_com_context *com_ctxt)
{
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();

	mutex_lock(&dev_mgr->lock);
	com_ctxt->status = SXE2_COM_CDEV_STATUS_NORMAL;
	mutex_unlock(&dev_mgr->lock);
}

static void sxe2_com_cdev_wait_clear(struct sxe2_com_context *com_ctxt)
{
	s32 ret;
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();
	unsigned long cur_jiffies;

	mutex_lock(&dev_mgr->lock);
	com_ctxt->status = SXE2_COM_CDEV_STATUS_UNACCESS;
	mutex_unlock(&dev_mgr->lock);

	do {
		cur_jiffies = msecs_to_jiffies(SXE2_COM_CMD_DFLT_TIMEOUT_MS);
		ret = (s32)wait_event_timeout(com_ctxt->waitq,
					      (atomic_read(&com_ctxt->ref_count) == 0),
					      (long)cur_jiffies);
		if (!ret) {
			LOG_INFO_BDF_COM("cdev wait ref count time out.\n");
		} else {
			mutex_lock(&dev_mgr->lock);
			if (atomic_read(&com_ctxt->ref_count) == 0) {
				mutex_unlock(&dev_mgr->lock);
				break;
			}
			mutex_unlock(&dev_mgr->lock);
		}
	} while (1);
}

static s32 sxe2_com_minor_get(s32 *dev_minor)
{
	s32 ret = -ENOMEM;

	mutex_lock(&sxe2_com_minor_lock);
	ret = idr_alloc(&sxe2_com_minor_idr, NULL, 0, (s32)SXE2_MAX_DEVICES_NUM, GFP_KERNEL);
	if (ret >= 0) {
		*dev_minor = ret;
		ret = 0;
	}
	mutex_unlock(&sxe2_com_minor_lock);
	return ret;
}

static void sxe2_com_minor_free(s32 dev_minor)
{
	mutex_lock(&sxe2_com_minor_lock);
	idr_remove(&sxe2_com_minor_idr, dev_minor);
	mutex_unlock(&sxe2_com_minor_lock);
}

const struct file_operations sxe2_com_cdev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = sxe2_com_ioctl,
	.mmap = sxe2_com_mmap,
	.open = sxe2_com_open,
	.release = sxe2_com_close,
};

STATIC s32 sxe2_com_cdev_create(struct sxe2_com_context *com_ctxt)
{
	s32 ret;
	s32 dev_major, dev_minor;
	struct pci_dev *pdev = com_ctxt->pdev;
	struct sxe2_cdev_info *cdev_info = NULL;

	ret = sxe2_com_minor_get(&dev_minor);
	if (ret) {
		LOG_ERROR_BDF_COM("cdev minor get failed, ret=%d\n", ret);
		ret = -ENOMEM;
		goto l_get_minor_failed;
	}

	cdev_info = &com_ctxt->cdev_info;
	dev_major = (s32)MAJOR(sxe2_com_cdev_major);
	cdev_info->dev_no = (dev_t)MKDEV(dev_major, dev_minor);
	cdev_init(&cdev_info->cdev, &sxe2_com_cdev_fops);
	cdev_info->cdev.owner = THIS_MODULE;

	LOG_INFO_BDF_COM("cdev_add: dev_major: %d, dev_minor: %d.\n", dev_major, dev_minor);

	ret = cdev_add(&cdev_info->cdev, cdev_info->dev_no, 1);
	if (ret) {
		LOG_ERROR_BDF_COM("failed to add cdev dev_no=%ld, ret=%d\n",
				  (unsigned long)cdev_info->dev_no, ret);
		goto l_add_cdev_failed;
	}

	cdev_info->device = device_create(sxe2_com_cdev_class, NULL, cdev_info->dev_no, NULL,
					  SXE2_COM_CHRDEV_NAME "-%04x:%02x:%02x.%x",
					  pci_domain_nr(pdev->bus),
					  pdev->bus->number, PCI_SLOT(pdev->devfn),
					  PCI_FUNC(pdev->devfn));
	if (IS_ERR(cdev_info->device)) {
		ret = (s32)PTR_ERR(cdev_info->device);
		LOG_ERROR_BDF_COM("failed to create device, dev_no=%ld\n",
				  (unsigned long)cdev_info->dev_no);
		goto l_create_dev_failed;
	}

	LOG_INFO_BDF_COM("create char dev[%p] dev_no[major:minor=%u:%u] on pci_dev[%p] \t"
			 "belongs to class dev[%p] success\n",
			 &cdev_info->cdev, dev_major, dev_minor, pdev, cdev_info->device);

	return 0;

l_create_dev_failed:
	cdev_del(&cdev_info->cdev);
l_add_cdev_failed:
	sxe2_com_minor_free(dev_minor);
l_get_minor_failed:
	return ret;
}

STATIC void sxe2_com_cdev_delete(struct sxe2_com_context *com_ctxt)
{
	s32 dev_minor;
	struct sxe2_cdev_info *cdev_info = &com_ctxt->cdev_info;

	dev_minor = (s32)MINOR(cdev_info->dev_no);

	sxe2_com_cdev_wait_clear(com_ctxt);

	LOG_INFO_BDF_COM("delete char dev[%p], dev_no[major:minor=%u:%u]\n",
			 &cdev_info->cdev, MAJOR(cdev_info->dev_no),
			 dev_minor);

	device_destroy(sxe2_com_cdev_class, cdev_info->dev_no);
	cdev_del(&cdev_info->cdev);
	sxe2_com_minor_free(dev_minor);
}

STATIC s32 sxe2_com_ctxt_init_once(struct sxe2_com_context *com_ctxt,
				   void *adapter, struct sxe2_com_ops *ops)
{
	const char *device_name;
	u32 device_len;
	size_t copy_result;

	com_ctxt->adapter = adapter;
	com_ctxt->ops = ops;

	com_ctxt->ops->com_ctxt_fill(adapter);

	com_ctxt->com_log_param.pdev = com_ctxt->pdev;
	com_ctxt->dma_dev.dev = &com_ctxt->pdev->dev;
	atomic_set(&com_ctxt->ref_count, 0);
	com_ctxt->dpdk_mode = ops->com_mode_get(adapter);
	com_ctxt->status = SXE2_COM_CDEV_STATUS_UNACCESS;

	device_name = dev_name(&com_ctxt->pdev->dev);
	device_len = (u32)(strlen(device_name) + 1);
	copy_result =
		SXE2_STRCPY(com_ctxt->com_log_param.dev_name,
			    device_name, min_t(u32, device_len, SXE2_COM_DEV_NAME));

	sema_init(&com_ctxt->cdev_info.cdev_sem, SXE2_MAX_COM_CMDS);
	init_waitqueue_head(&com_ctxt->waitq);
	mutex_init(&com_ctxt->vma.vma_lock);
	INIT_LIST_HEAD(&com_ctxt->vma.vma_list);
	mutex_init(&com_ctxt->dma_dev.lock);
	INIT_LIST_HEAD(&com_ctxt->dma_dev.buffer_list);
	INIT_LIST_HEAD(&com_ctxt->list);
	mutex_init(&com_ctxt->irqs.lock);

	mutex_init(&com_ctxt->com_lock);

	sxe2_com_ctxt_clear(com_ctxt);

	(void)copy_result;
	return 0;
}

STATIC void sxe2_com_ctxt_deinit_once(struct sxe2_com_context *com_ctxt)
{
	com_ctxt->adapter = NULL;
	com_ctxt->pdev = NULL;
	com_ctxt->ops = NULL;
	com_ctxt->dma_dev.dev = NULL;
	com_ctxt->dpdk_ver = SXE2_COM_INVAL_U32;
	memset(&com_ctxt->com_log_param, 0, sizeof(com_ctxt->com_log_param));

	mutex_destroy(&com_ctxt->com_lock);
	mutex_destroy(&com_ctxt->vma.vma_lock);
	mutex_destroy(&com_ctxt->dma_dev.lock);
	mutex_destroy(&com_ctxt->irqs.lock);
}

s32 sxe2_com_init(struct sxe2_com_context *com_ctxt, void *adapter, struct sxe2_com_ops *ops)
{
	s32 ret;

	if (!com_ctxt || !ops || !ops->com_ctxt_fill || !ops->com_mode_get || !adapter) {
		LOG_DEV_ERR_COM("sxe2_com_ctxt_init_once failed,\t"
				"com_ctxt: %pK, adapter:%pK, ops: %pK\n",
				com_ctxt, adapter, ops);
		return -EINVAL;
	}

	if (ops->com_mode_get(adapter) == SXE2_COM_MODULE_KERNEL)
		return 0;

	ret = sxe2_com_ctxt_init_once(com_ctxt, adapter, ops);
	if (ret)
		goto l_end;

	ret = sxe2_com_irqs_init(com_ctxt);
	if (ret) {
		LOG_DEV_ERR_COM("dpdk irqs init failed, ret: %d\n", ret);
		goto l_com_deinit;
	}

	ret = sxe2_com_bar_init(com_ctxt);
	if (ret) {
		LOG_DEV_ERR_COM("dpdk irqs init failed, ret: %d\n", ret);
		goto l_irqs_deinit;
	}

	ret = sxe2_com_cdev_create(com_ctxt);
	if (ret != 0) {
		LOG_DEV_ERR_COM("eth dpdk cdev create failed, ret=%d\n", ret);
		goto l_bar_deinit;
	}

	sxe2_com_enable(com_ctxt);

	return 0;

l_bar_deinit:
	sxe2_com_bar_deinit(com_ctxt);
l_irqs_deinit:
	sxe2_com_irqs_deinit(com_ctxt);
l_com_deinit:
	sxe2_com_ctxt_deinit_once(com_ctxt);
l_end:
	return ret;
}

void sxe2_com_deinit(struct sxe2_com_context *com_ctxt)
{
	if (!com_ctxt->adapter || !com_ctxt->ops || !com_ctxt->ops->com_mode_get ||
	    (com_ctxt->ops->com_mode_get(com_ctxt->adapter) == SXE2_COM_MODULE_KERNEL))
		return;

	sxe2_com_disable(com_ctxt);
	sxe2_com_cdev_delete(com_ctxt);
	sxe2_com_bar_deinit(com_ctxt);
	sxe2_com_irqs_deinit(com_ctxt);
	sxe2_com_ctxt_deinit_once(com_ctxt);
}

s32 sxe2_com_adapter_register(enum sxe2_func_type func_type)
{
	s32 ret;

	memset(&sxe2_com_mgr, 0, sizeof(sxe2_com_mgr));
	mutex_init(&sxe2_com_mgr.lock);

	ret = alloc_chrdev_region(&sxe2_com_cdev_major, 0, SXE2_MAX_DEVICES_NUM,
				  func_type ==
					SXE2_PF ? SXE2_COM_CHRDEV_NAME : SXE2VF_COM_CHRDEV_NAME);
	if (ret) {
		LOG_ERROR("alloc cdev number failed: %d\n", ret);
		goto l_alloc_cdev_failed;
	}

	sxe2_com_cdev_class =
	    class_create(THIS_MODULE,
			 func_type == SXE2_PF ? SXE2_COM_CHRDEV_NAME : SXE2VF_COM_CHRDEV_NAME);
	if (IS_ERR(sxe2_com_cdev_class)) {
		ret = (s32)PTR_ERR(sxe2_com_cdev_class);
		LOG_ERROR("create cdev class failed: %d\n", ret);
		goto l_create_class_failed;
	}

	mutex_init(&sxe2_com_minor_lock);

	return 0;

l_create_class_failed:
	unregister_chrdev_region(sxe2_com_cdev_major, SXE2_MAX_DEVICES_NUM);
l_alloc_cdev_failed:
	return ret;
}

void sxe2_com_adapter_unregister(void)
{
	class_destroy(sxe2_com_cdev_class);
	unregister_chrdev_region(sxe2_com_cdev_major, SXE2_MAX_DEVICES_NUM);
	idr_destroy(&sxe2_com_minor_idr);

	mutex_destroy(&sxe2_com_minor_lock);
	mutex_destroy(&sxe2_com_mgr.lock);
}

void sxe2_com_info_print(struct sxe2_com_context *com_ctxt)
{
	struct sxe2_com_dev_mgr *dev_mgr = sxe2_com_dev_get();

	mutex_lock(&dev_mgr->lock);

	if (!com_ctxt->adapter)
		return;

	LOG_DEV_INFO_COM("com cdev status: %s\n", com_ctxt->status == 0 ? "Unaccess" : "Normal");

	sxe2_com_dma_print(com_ctxt);

	mutex_unlock(&dev_mgr->lock);
}
