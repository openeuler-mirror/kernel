// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 * Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * Thanks to Alex Williamson and Tom Lyon for their original
 * vfio implementation.
 *
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "vfio ub: " fmt

#include <linux/module.h>
#include <linux/vfio.h>
#include <linux/types.h>
#include <linux/eventfd.h>

#include "vfio_ub_private.h"

static bool is_ub_entity_support_used(struct ub_entity *uent)
{
	if (!((uent_type(uent) == UB_TYPE_CONTROLLER ||
	    uent_type(uent) == UB_TYPE_ICONTROLLER) &&
	    uent_base_code(uent) != UB_BASE_CODE_BUS_CONTROLLER))
		return false;

	if (!list_empty(&uent->ue_list))
		return false;

	return true;
}

int vfio_ub_core_register_device(struct vfio_ub_core_device *vdev)
{
	struct ub_entity *uent = vdev->uent;
	struct device *dev = &uent->dev;

	/* Drivers must set the vfio_ub_core_device to their drvdata */
	if (WARN_ON(vdev != dev_get_drvdata(dev)))
		return -EINVAL;

	if (!is_ub_entity_support_used(uent)) {
		ub_err(uent, "Cannot bind to vfio driver\n");
		return -EBUSY;
	}

	return vfio_register_group_dev(&vdev->vdev);
}

void vfio_ub_core_unregister_device(struct vfio_ub_core_device *vdev)
{
	vfio_unregister_group_dev(&vdev->vdev);
}

static int vfio_usi_info_init(struct vfio_ub_core_device *vdev)
{
	struct ub_entity *uent = vdev->uent;
	u32 low32;
	u32 high32;
	u16 num;
	int ret;

	/* when device supports int type2, read usi info from cfgspace */
	if (uent->no_intr == 0 && uent->intr_type1 == 0) {
		ret = ub_cfg_read_dword(vdev->uent, UB_INT_VECTOR_TBL_SA_L, &low32);
		ret |= ub_cfg_read_dword(vdev->uent, UB_INT_VECTOR_TBL_SA_H, &high32);
		ret |= ub_cfg_read_word(vdev->uent, UB_NUM_OF_INTR_VECTOR_TBL, &num);
		if (ret)
			return -EFAULT;

		vdev->usi_vector_offset = (u64)high32 << 32 | low32;
		vdev->usi_vector_size = (num + 1) * UB_INTR_VECTOR_ENTRY_SIZE;

		ret = ub_cfg_read_dword(vdev->uent, UB_INT_ADDR_TBL_SA_L, &low32);
		ret |= ub_cfg_read_dword(vdev->uent, UB_INT_ADDR_TBL_SA_H, &high32);
		ret |= ub_cfg_read_word(vdev->uent, UB_NUM_OF_INTR_ADDR_TBL, &num);
		if (ret)
			return -EFAULT;

		vdev->usi_addr_offset = (u64)high32 << 32 | low32;
		vdev->usi_addr_size = (num + 1) * UB_INTR_ADDR_ENTRY_SIZE;
	} else {
		vdev->usi_vector_offset = 0;
		vdev->usi_vector_size = 0;
		vdev->usi_addr_offset = 0;
		vdev->usi_addr_size = 0;
	}

	return 0;
}

static int vfio_ub_enable(struct vfio_ub_core_device *vdev)
{
	int ret;

	vdev->num_ext_irqs = 0;
	vdev->num_regions = 0;
	vdev->num_vendor_irqs = 0;
	vdev->num_vendor_regions = 0;
	vdev->reset_works = 1; /* we assume ub support ELR for now. */

	ret = vfio_usi_info_init(vdev);
	if (ret)
		return ret;

	return vfio_ub_config_init(vdev);
}

static void vfio_ub_disable(struct vfio_ub_core_device *vdev)
{
	vfio_ub_config_uninit(vdev);
	vfio_ub_set_irqs_ioctl(vdev, VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
			       vdev->irq_type, 0, 0, NULL);

	/* clear device caches when vm exit or crash */
	if (vdev->reset_works)
		ub_reset_entity(vdev->uent);
}

int vfio_ub_core_open_device(struct vfio_device *core_vdev)
{
	struct vfio_ub_core_device *vdev = container_of(core_vdev,
					   struct vfio_ub_core_device, vdev);

	return vfio_ub_enable(vdev);
}

void vfio_ub_core_close_device(struct vfio_device *core_vdev)
{
	struct vfio_ub_core_device *vdev = container_of(core_vdev,
					   struct vfio_ub_core_device, vdev);

	vfio_ub_disable(vdev);
	vfio_ub_unset_resmap(vdev);

	mutex_lock(&vdev->igate);
	if (vdev->req_trigger) {
		eventfd_ctx_put(vdev->req_trigger);
		vdev->req_trigger = NULL;
	}

	if (vdev->reinit_trigger) {
		eventfd_ctx_put(vdev->reinit_trigger);
		vdev->reinit_trigger = NULL;
	}

	mutex_unlock(&vdev->igate);
}

static int vfio_ub_get_device_info(struct vfio_ub_core_device *vdev, unsigned long arg)
{
	unsigned long minsz = offsetofend(struct vfio_device_info, num_irqs);
	struct vfio_device_info info;

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	info.flags = VFIO_DEVICE_FLAGS_UB;

	if (vdev->reset_works)
		info.flags |= VFIO_DEVICE_FLAGS_RESET;

	info.num_regions = VFIO_UB_NUM_REGIONS + vdev->num_regions +
			   vdev->num_vendor_regions;
	info.num_irqs = VFIO_UB_NUM_IRQS + vdev->num_ext_irqs +
			vdev->num_vendor_irqs;

	return copy_to_user((void __user *)arg, &info, minsz) ?
		-EFAULT : 0;
}

static int vfio_ub_get_region_info(struct vfio_ub_core_device *vdev, unsigned long arg)
{
	unsigned long minsz = offsetofend(struct vfio_region_info, offset);
	struct ub_entity *uent = vdev->uent;
	struct vfio_region_info info;

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if ((info.argsz < minsz) ||
	    (info.index >= (VFIO_UB_NUM_REGIONS + vdev->num_regions)))
		return -EINVAL;

	switch (info.index) {
	case VFIO_UB_REGION0_INDEX:
	case VFIO_UB_REGION1_INDEX:
	case VFIO_UB_REGION2_INDEX:
		info.offset = VFIO_UB_INDEX_TO_OFFSET(info.index);
		info.size = ub_resource_len(uent, info.index);
		if (!info.size) {
			info.flags = 0;
			break;
		}

		info.flags = VFIO_REGION_INFO_FLAG_READ |
			     VFIO_REGION_INFO_FLAG_WRITE |
			     VFIO_REGION_INFO_FLAG_MMAP;
		break;
	case VFIO_UB_CONFIG_REGION_INDEX:
		info.offset = VFIO_UB_INDEX_TO_OFFSET(info.index);
		info.flags = VFIO_REGION_INFO_FLAG_READ |
			     VFIO_REGION_INFO_FLAG_WRITE;
		info.size = 0;
		break;
	default:
		return -EINVAL;
	}

	return copy_to_user((void __user *)arg, &info, minsz) ?
		-EFAULT : 0;
}

static int vfio_ub_entity_reset(struct vfio_ub_core_device *vdev)
{
	if (!vdev->reset_works)
		return -EINVAL;

	return ub_reset_entity(vdev->uent);
}

static int vfio_ub_get_irq_count(struct vfio_ub_core_device *vdev, int irq_type)
{
	struct ub_entity *uent = vdev->uent;

	if (irq_type == VFIO_UB_INTR_IRQ_INDEX) {
		if (!(uent->no_intr == 0 && uent->intr_type1 == 0))
			return 0;
		return ub_intr_vec_count(vdev->uent);
	} else if (irq_type == VFIO_UB_REQ_IRQ_INDEX ||
		   irq_type == VFIO_UB_REINIT_IRQ_INDEX) {
		return 1;
	}

	return 0;
}

static int vfio_ub_get_irq_info(struct vfio_ub_core_device *vdev, unsigned long arg)
{
	unsigned long minsz = offsetofend(struct vfio_irq_info, count);
	struct vfio_irq_info info;
	int ret;

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if ((info.argsz < minsz) ||
	    (info.index >= (VFIO_UB_NUM_IRQS + vdev->num_ext_irqs)))
		return -EINVAL;

	info.flags = VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE;

	switch (info.index) {
	case VFIO_UB_INTR_IRQ_INDEX:
		ret = vfio_ub_get_irq_count(vdev, info.index);
		if (ret < 0)
			return -EFAULT;

		info.count = (u32)ret;
		break;
	case VFIO_UB_REQ_IRQ_INDEX:
	case VFIO_UB_REINIT_IRQ_INDEX:
		info.count = (u32)vfio_ub_get_irq_count(vdev, info.index);
		break;
	default:
		return -EINVAL;
	}

	return copy_to_user((void __user *)arg, &info, minsz) ?
		-EFAULT : 0;
}

static int vfio_ub_set_irqs(struct vfio_ub_core_device *vdev, unsigned long arg)
{
	struct vfio_irq_set hdr;
	u32 sz = sizeof(hdr);
	size_t data_size = 0;
	u8 *data = NULL;
	int max;
	int ret;

	if (copy_from_user(&hdr, (void __user *)arg, sz))
		return -EFAULT;

	max = vfio_ub_get_irq_count(vdev, hdr.index);
	if (max <= 0)
		return -EINVAL;

	ret = vfio_set_irqs_validate_and_prepare(&hdr, max,
		VFIO_UB_NUM_IRQS + vdev->num_ext_irqs, &data_size);
	if (ret)
		return ret;

	if (data_size) {
		data = (u8 *)memdup_user((void __user *)(arg + sz), data_size);
		if (IS_ERR(data))
			return PTR_ERR(data);
	}

	mutex_lock(&vdev->igate);
	ret = vfio_ub_set_irqs_ioctl(vdev, hdr.flags, hdr.index, hdr.start,
				     hdr.count, data);
	mutex_unlock(&vdev->igate);
	kfree(data);

	return ret;
}

long vfio_ub_core_ioctl(struct vfio_device *core_vdev, unsigned int cmd, unsigned long arg)
{
	struct vfio_ub_core_device *vdev = container_of(core_vdev,
					   struct vfio_ub_core_device, vdev);

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return vfio_ub_get_device_info(vdev, arg);
	case VFIO_DEVICE_GET_REGION_INFO:
		return vfio_ub_get_region_info(vdev, arg);
	case VFIO_DEVICE_GET_IRQ_INFO:
		return vfio_ub_get_irq_info(vdev, arg);
	case VFIO_DEVICE_SET_IRQS:
		return vfio_ub_set_irqs(vdev, arg);
	case VFIO_DEVICE_RESET:
		return vfio_ub_entity_reset(vdev);
	default:
		return -ENOTTY;
	}
}

static ssize_t vfio_ub_rw(struct vfio_ub_core_device *vdev, char __user *buf, size_t count,
			  loff_t *ppos, bool iswrite)
{
	unsigned int index = VFIO_UB_OFFSET_TO_INDEX(*ppos);

	if (index >= (VFIO_UB_NUM_REGIONS + vdev->num_regions))
		return -EINVAL;

	switch (index) {
	case VFIO_UB_CONFIG_REGION_INDEX:
		return vfio_ub_config_rw(vdev, buf, count, ppos, iswrite);
	case VFIO_UB_REGION0_INDEX:
	case VFIO_UB_REGION1_INDEX:
	case VFIO_UB_REGION2_INDEX:
		return vfio_ub_res_rw(vdev, buf, count, ppos, iswrite);
	default:
		return -EINVAL;
	}
}

ssize_t vfio_ub_core_read(struct vfio_device *core_vdev, char __user *buf, size_t count,
			  loff_t *ppos)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);

	if (!count)
		return 0;

	return vfio_ub_rw(vdev, buf, count, ppos, false);
}

ssize_t vfio_ub_core_write(struct vfio_device *core_vdev, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);

	if (!count)
		return 0;

	return vfio_ub_rw(vdev, (char __user *)buf, count, ppos, true);
}

int vfio_ub_core_mmap(struct vfio_device *core_vdev, struct vm_area_struct *vma)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);
	u64 phys_len, req_len, pgoff, req_start;
	struct ub_entity *uent = vdev->uent;
	unsigned int index;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	/*
	 * VM_SHARED means user's changing to mmio can immediately arrive ub device,
	 * or it is unspecified.
	 */
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;

	index = vma->vm_pgoff >> (VFIO_UB_OFFSET_SHIFT - PAGE_SHIFT);

	if (index > VFIO_UB_REGION2_INDEX)
		return -EINVAL;

	phys_len = PAGE_ALIGN(ub_resource_len(uent, index));
	req_len = vma->vm_end - vma->vm_start;
	pgoff = vma->vm_pgoff & ((1U << (VFIO_UB_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	req_start = pgoff << PAGE_SHIFT;

	if (req_start + req_len > phys_len)
		return -EINVAL;

	vm_flags_set(vma, VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP |
		     VM_PFNMAP | VM_WIPEONFORK);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (ub_resource_start(uent, index) >> PAGE_SHIFT) + pgoff;
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
		vma->vm_end - vma->vm_start, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

int vfio_ub_core_init_dev(struct vfio_device *core_vdev)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);

	vdev->uent = to_ub_entity(core_vdev->dev);
	vdev->irq_type = VFIO_UB_NUM_IRQS;
	mutex_init(&vdev->igate);
	return 0;
}

void vfio_ub_core_release_dev(struct vfio_device *core_vdev)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);

	mutex_destroy(&vdev->igate);
}

void vfio_ub_core_request(struct vfio_device *core_vdev, unsigned int count)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);

	mutex_lock(&vdev->igate);

	if (vdev->req_trigger) {
		if (!(count % 10))
			dev_notice_ratelimited(&vdev->uent->dev,
				"Relaying device request to user #%u\n", count);
		eventfd_signal(vdev->req_trigger, 1);
	} else if (count == 0) {
		ub_warn(vdev->uent,
			"No device request channel registered, blocked until released by user\n");
	}

	mutex_unlock(&vdev->igate);
}

void vfio_ub_iommufd_physical_unbind(struct vfio_device *core_vdev)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);

	vfio_iommufd_physical_unbind(core_vdev);

	/* Now, valid tid are allocated at attach_ioas interface,
	 * but tid free at this unbind interface.
	 * detach_ioas interface are not called at vfio_compt mode.
	 */
	ub_unset_user_info(vdev->uent);
}

void vfio_ub_core_disable_all(struct vfio_ub_core_device *vdev)
{
	struct ub_entity *uent = vdev->uent;

	if (!list_empty(&uent->ue_list))
		ub_disable_entities(uent);
}

int vfio_ub_iommufd_physical_attach_ioas(struct vfio_device *core_vdev, u32 *pt_id)
{
	struct vfio_ub_core_device *vdev =
		container_of(core_vdev, struct vfio_ub_core_device, vdev);
	int ret;

	ret = vfio_iommufd_physical_attach_ioas(core_vdev, pt_id);
	if (!ret)
		ub_set_user_info(vdev->uent);

	return ret;
}

void vfio_ub_iommufd_physical_detach_ioas(struct vfio_device *core_vdev)
{
	vfio_iommufd_physical_detach_ioas(core_vdev);
}
