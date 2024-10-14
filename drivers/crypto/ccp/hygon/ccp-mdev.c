// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON Cryptographic Coprocessor (CCP) crypto driver for Mediated devices
 *
 * Copyright (C) 2022 Hygon Info Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/uuid.h>
#include <linux/vfio.h>
#include <linux/iommu.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/pci.h>
#include <linux/kfifo.h>
#include <linux/eventfd.h>
#include <linux/mem_encrypt.h>

#include "ccp-mdev.h"
#include "../ccp-dev.h"

#define MCCP_VFIO_PCI_OFFSET_SHIFT		40
#define MCCP_PCI_BAR2_RES_MAP_LEN		0x8000
#define MCCP_VFIO_PCI_OFFSET_TO_INDEX(off) \
				(off >> MCCP_VFIO_PCI_OFFSET_SHIFT)
#define MCCP_VFIO_PCI_INDEX_TO_OFFSET(index) \
				((u64)(index) << MCCP_VFIO_PCI_OFFSET_SHIFT)
#define MCCP_VFIO_PCI_OFFSET_MASK \
				(((u64)(1) << MCCP_VFIO_PCI_OFFSET_SHIFT) - 1)

#define VERSION_STRING				"0.7"
#define VERSION_SIZE				16
#define MCCP_CLASS_NAME				"ccp_mdev"
#define MCCP_NAME				"ccp_mdev"
#define MCCP_CHRDEV_COUNT			256

#define MCCP_SHARE_IOC_TYPE			'C'
#define MCCP_SHARE_OP				0x01
#define MCCP_SHARE_OP_DMA_MAP			0x01
#define MCCP_SHARE_OP_DMA_UNMAP_ALL		0x02
#define MCCP_SHARE_OP_GET_ID			0x03
#define MCCP_SHARE_OP_GET_PASID			0x04
#define MCCP_SHARE_OP_DMA_UNMAP			0x05
#define MCCP_SHARE_OP_GET_VERSION		0x06

#define VFIO_DEVICE_CCP_SET_MODE		_IO(VFIO_TYPE, VFIO_BASE + 32)
#define VFIO_DEVICE_CCP_GET_MODE		_IO(VFIO_TYPE, VFIO_BASE + 33)
#define VFIO_DEVICE_GET_PCI_ADDR		_IO(VFIO_TYPE, VFIO_BASE + 34)
#define VFIO_DEVICE_GET_PCI_ID			_IO(VFIO_TYPE, VFIO_BASE + 35)

#define MCCP_SHARE_IOMMU_MAGIC			0x3d6a9c5728633b9e
#define MCCP_DEV_ID_SIZE			8
#define MCCP_DMA_IOVA_OFFSET			0
#define MCCP_DMA_IOVA_SIZE			(1ul << 30)
#define MCCP_INSTANCE_OFFSET			8
#define MCCP_INSTANCE_MASK			(~((1u << MCCP_INSTANCE_OFFSET) - 1))
#define MCCP_PASID_SIZE				(1 << 8)
#define MCCP_PASID_MASK_BIT			0x03
#define MCCP_IOVA_MAX_SLOT			1024
#define MCCP_DEV_MAX				48
#define MCCP_DEV_QUEUE_MAX			8
#define MCCP_SHARED_SIZE			(MCCP_DEV_MAX * PAGE_SIZE)
#define MCCP_QUEUES_MAX				(MCCP_DEV_MAX * MCCP_DEV_QUEUE_MAX)
#define MCCP_QUEUE_NEED_INIT			0x01
#define PHY_ADDR_MASK				0x7FFFFFFFFFFF
#define MCCP_GET_QUEUE_FLAG			(0x55)
#define MCCP_PUT_QUEUE_FLAG			(0xAA)

struct ccp_shared_cfg {
	unsigned int iova_slot[MCCP_IOVA_MAX_SLOT];
	unsigned int ccp_queue_state[MCCP_QUEUES_MAX];
	unsigned int ccps_ref[MCCP_DEV_MAX];
	unsigned int ccps_ref_lock;
	int rsvd[15];
	u64 qidx[MCCP_QUEUES_MAX];
	unsigned int ccp_state[MCCP_DEV_MAX];
} __aligned(PAGE_SIZE);

struct ccp_shr_pg_cfg {
	unsigned int ccp_queue_state[MCCP_DEV_QUEUE];
	unsigned long mdev_bitmap[BITS_TO_LONGS(MCCP_INSTANCE_MAX)];
	unsigned long userid[MCCP_DEV_QUEUE];
	unsigned int vq_work_mode[MCCP_DEV_QUEUE];
	unsigned int dev_lock_state;
	unsigned int dev_init_state;
	unsigned int numa_node;
} ____cacheline_aligned;

struct ccp_mdev_ctrl {
	unsigned char op;
	unsigned char rsvd[3];
	union {
		unsigned char version[VERSION_SIZE];
		unsigned int id;
		unsigned int pasid;
		struct {
			unsigned long vaddr;
			unsigned long iova;
			unsigned long size;
		};
	};
};

struct ccp_dma {
	struct list_head next;
	unsigned long vaddr;
	unsigned long iova;
	size_t size;
	struct page **pages;
	unsigned long npages;
	unsigned int pfnmap_flag;
};

struct ccp_iommu {
	unsigned long magic;
	struct mutex lock;
	struct pci_dev *pdev;
	struct hygon_ccp_dev_wrapper *wrapper;
	unsigned long id;
	unsigned long ref;
};

static struct ccp_mdev_data {
	struct ccp_iommu iommu[MCCP_DEV_MAX];
	struct mutex lock;
	unsigned long bitmap;
	struct iommu_domain *domain;
	int prot;
	dma_addr_t dma_share_iova;
	size_t dma_share_size;
	unsigned long dma_share_ref;
	unsigned long ids[BITS_TO_LONGS(MCCP_INSTANCE_MAX)];
	unsigned long pasids[BITS_TO_LONGS(MCCP_PASID_SIZE)];
} ccp_mdev_data;

static struct ccp_share_cfg {
	long ref;
	struct mutex lock;
	struct page *pages[MCCP_DEV_MAX];
	u64 pagecount;
	void *vaddr;
	u64 size;
} ccp_share;

static struct ccp_mdev {
	dev_t vd_devt;
	int major;
	struct class *vd_class;
	struct cdev vd_cdev;
} ccp_mdev;

struct mdev_region_info {
	u64 start;
	u64 phys_start;
	u32 size;
	u64 vfio_offset;
};

struct mdev_state {
	struct mutex ops_lock;
	struct ccp_iommu *iommu;
	struct mdev_region_info region_info[VFIO_PCI_NUM_REGIONS];
	struct list_head next;
	struct vfio_device_info dev_info;
	struct eventfd_ctx *trigger[MCCP_DEV_QUEUE_MAX];
	u8 efd_start;
	u8 efd_count;
};

struct mccp_pci_addr {
	u32 domain;
	u8 bus;
	u8 devid;
	u8 function;
	u8 numa_node;
};

struct mccp_pci_id {
	u32 class;
	u16 vendor;
	u16 device;
	u16 subsystem_vendor;
	u16 subsystem_device;
};

static LIST_HEAD(ccp_dev_wrapper_list);
static DEFINE_MUTEX(ccp_dev_wrapper_lock);

static int handle_pci_cfg_read(struct mdev_state *mdev_state, int offset,
				 __le32 *val, int count)
{
	struct pci_dev *pdev = NULL;
	u32 tmp_val = 0;
	int ret = -EINVAL;

	if (!mdev_state || !mdev_state->iommu) {
		pr_err("ccp: invalid mdev_state.\n");
		return ret;
	}

	pdev = mdev_state->iommu->pdev;

	if (count == 1) {
		u8 tmp;

		ret = pci_user_read_config_byte(pdev, offset, &tmp);
		tmp_val = tmp;
	} else if (count == 2) {
		u16 tmp;

		ret = pci_user_read_config_word(pdev, offset, &tmp);
		tmp_val = tmp;
	} else if (count == 4)
		ret = pci_user_read_config_dword(pdev, offset, &tmp_val);

	*val = cpu_to_le32(tmp_val);
	return ret;
}

static int handle_pci_cfg_write(struct mdev_state *mdev_state, u16 offset,
				 u8 *buf, u32 count)
{
	u32 tmp_val = le32_to_cpu(*(u32 *)buf);
	struct pci_dev *pdev = NULL;
	int ret = -EINVAL;

	if (!mdev_state || !mdev_state->iommu) {
		pr_err("ccp: invalid mdev_state.\n");
		return ret;
	}

	pdev = mdev_state->iommu->pdev;

	if (count == 1)
		ret = pci_user_write_config_byte(pdev, offset, tmp_val);
	else if (count == 2)
		ret = pci_user_write_config_word(pdev, offset, tmp_val);
	else if (count == 4)
		ret = pci_user_write_config_dword(pdev, offset, tmp_val);

	return ret;
}

static ssize_t ccp_access(struct mdev_state *mdev_state, u8 *buf,
			size_t count, loff_t pos, bool is_write)
{
	unsigned int index;
	loff_t offset;
	int ret = 0;

	if (!mdev_state || !buf)
		return -EINVAL;

	mutex_lock(&mdev_state->ops_lock);

	index = MCCP_VFIO_PCI_OFFSET_TO_INDEX(pos);
	offset = pos & MCCP_VFIO_PCI_OFFSET_MASK;
	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (is_write)
			ret = handle_pci_cfg_write(mdev_state, offset, buf, count);
		else
			ret = handle_pci_cfg_read(mdev_state, offset, (__le32 *)buf, count);
		break;
	default:
		ret = -1;
	}

	if (!ret)
		ret = count;

	mutex_unlock(&mdev_state->ops_lock);

	return ret;
}

static ssize_t ccp_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct mdev_state *mdev_state = file->private_data;
	unsigned int done = 0;
	size_t filled;
	u32 val;
	int ret;

	while (count) {
		if (count >= 4 && !(*ppos % 4)) {
			ret = ccp_access(mdev_state, (u8 *)&val, sizeof(u32), *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(u32)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			ret = ccp_access(mdev_state, (u8 *)&val, sizeof(u16), *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(u16)))
				goto read_err;

			filled = 2;
		} else {
			ret = ccp_access(mdev_state, (u8 *)&val, sizeof(u8), *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(u8)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;

read_err:
	return -EFAULT;
}

static ssize_t ccp_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	struct mdev_state *mdev_state = file->private_data;
	unsigned int done = 0;
	size_t filled;
	u64 val;
	int ret;

	while (count) {
		if (count == MCCP_DEV_ID_SIZE && *ppos == MCCP_GET_QUEUE_FLAG) {
			struct pci_dev *pdev = mdev_state->iommu->pdev;
			struct sp_device *sp = dev_get_drvdata(&pdev->dev);
			struct ccp_device *ccp = sp->ccp_data;
			struct hygon_ccp_dev_wrapper *ccp_wrapper = NULL;
			u8 i = 0;

			if (copy_from_user(&val, buf, sizeof(u64)) ||
					val >= MCCP_DEV_QUEUE_MAX ||
					val < mdev_state->efd_start)
				goto write_err;

			ccp_wrapper = hygon_ccp_dev_wrapper_get(ccp);
			if (!ccp_wrapper)
				goto write_err;

			i = val - mdev_state->efd_start;

			mutex_lock(&mdev_state->iommu->lock);
			if (kfifo_avail(&ccp_wrapper->ectx_q[i].ectx_fifo))
				kfifo_put(&ccp_wrapper->ectx_q[i].ectx_fifo,
						mdev_state->trigger[i]);
			mutex_unlock(&mdev_state->iommu->lock);

			filled = MCCP_DEV_ID_SIZE;
		} else if (count >= 4 && !(*ppos % 4)) {
			if (copy_from_user(&val, buf, sizeof(u32)))
				goto write_err;

			ret = ccp_access(mdev_state, (u8 *)&val, sizeof(u32), *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			if (copy_from_user(&val, buf, sizeof(u16)))
				goto write_err;

			ret = ccp_access(mdev_state, (u8 *)&val, sizeof(u16), *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 2;
		} else {
			if (copy_from_user(&val, buf, sizeof(u8)))
				goto write_err;

			ret = ccp_access(mdev_state, (u8 *)&val, sizeof(u8), *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 1;
		}
		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
write_err:
	return -EFAULT;
}

static int ccp_reset(struct mdev_state *mdev_state)
{
	if (!mdev_state)
		return -EINVAL;

	return 0;
}

static int ccp_get_region_info(struct mdev_state *mdev_state,
			 struct vfio_region_info *region_info,
			 u16 *cap_type_id, void **cap_type)
{
	struct pci_dev *pdev = NULL;
	unsigned int size = 0;
	u32 bar_index;

	if (!mdev_state)
		return -EINVAL;

	pdev = mdev_state->iommu->pdev;
	bar_index = region_info->index;
	if (bar_index >= VFIO_PCI_NUM_REGIONS)
		return -EINVAL;

	mutex_lock(&mdev_state->ops_lock);

	switch (bar_index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		size = pdev->cfg_size;
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
		size = MCCP_PCI_BAR2_RES_MAP_LEN;
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
		size = pci_resource_len(pdev, bar_index);
		break;
	default:
		size = 0;
		break;
	}

	mdev_state->region_info[bar_index].size = size;
	mdev_state->region_info[bar_index].vfio_offset =
		MCCP_VFIO_PCI_INDEX_TO_OFFSET(bar_index);

	region_info->size = size;
	region_info->offset = MCCP_VFIO_PCI_INDEX_TO_OFFSET(bar_index);
	region_info->flags = VFIO_REGION_INFO_FLAG_READ |
		VFIO_REGION_INFO_FLAG_WRITE;
	if (size >= PAGE_SIZE)
		region_info->flags |= VFIO_REGION_INFO_FLAG_MMAP;

	mutex_unlock(&mdev_state->ops_lock);
	return 0;
}

static int ccp_get_irq_info(struct mdev_state *mdev_state,
			     struct vfio_irq_info *irq_info)
{
	switch (irq_info->index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
	case VFIO_PCI_MSI_IRQ_INDEX:
	case VFIO_PCI_MSIX_IRQ_INDEX:
	case VFIO_PCI_REQ_IRQ_INDEX:
		break;

	default:
		return -EINVAL;
	}

	irq_info->flags = VFIO_IRQ_INFO_EVENTFD;
	irq_info->count = 1;

	if (irq_info->index == VFIO_PCI_INTX_IRQ_INDEX)
		irq_info->flags |= (VFIO_IRQ_INFO_MASKABLE |
				VFIO_IRQ_INFO_AUTOMASKED);
	else
		irq_info->flags |= VFIO_IRQ_INFO_NORESIZE;

	return 0;
}

static int ccp_get_device_info(struct mdev_state *mdev_state,
			 struct vfio_device_info *dev_info)
{
	dev_info->flags = VFIO_DEVICE_FLAGS_PCI;
	dev_info->num_regions = VFIO_PCI_NUM_REGIONS;
	dev_info->num_irqs = VFIO_PCI_NUM_IRQS;
	return 0;
}

static int ccp_set_irqs_validate_and_prepare(struct vfio_irq_set *hdr,
			int num_irqs, int max_irq_type, size_t *data_size)
{
	unsigned long minsz;
	size_t size;

	minsz = offsetofend(struct vfio_irq_set, count);

	if ((hdr->argsz < minsz) || (hdr->index >= max_irq_type) ||
			(hdr->count >= (U32_MAX - hdr->start)) ||
			(hdr->flags & ~(VFIO_IRQ_SET_DATA_TYPE_MASK |
					VFIO_IRQ_SET_ACTION_TYPE_MASK)))
		return -EINVAL;

	if (data_size)
		*data_size = 0;

	if (hdr->start >= num_irqs || hdr->start + hdr->count > num_irqs)
		return -EINVAL;

	switch (hdr->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
	case VFIO_IRQ_SET_DATA_NONE:
		size = 0;
		break;
	case VFIO_IRQ_SET_DATA_BOOL:
		size = sizeof(uint8_t);
		break;
	case VFIO_IRQ_SET_DATA_EVENTFD:
		size = sizeof(int32_t);
		break;
	default:
		return -EINVAL;
	}

	if (size) {
		if (hdr->argsz - minsz < hdr->count * size)
			return -EINVAL;

		if (!data_size)
			return -EINVAL;

		*data_size = hdr->count * size;
	}

	return 0;
}

static int ccp_set_irq_efds(struct mdev_state *mdev_state,
			struct vfio_irq_set *hdr,
			void *data)
{
	struct eventfd_ctx *trigger = NULL;
	int *fd = (int *)data;
	int i;

	if (!mdev_state || !data)
		return -EINVAL;

	if (hdr->index != VFIO_PCI_MSIX_IRQ_INDEX)
		return -EINVAL;

	if ((hdr->flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) != VFIO_IRQ_SET_ACTION_TRIGGER)
		return -EINVAL;

	if (hdr->start + hdr->count > MCCP_DEV_QUEUE_MAX)
		return -EINVAL;

	mdev_state->efd_start = hdr->start;
	for (i = 0; i < hdr->count; i++) {
		trigger = eventfd_ctx_fdget(fd[i]);
		if (IS_ERR(trigger)) {
			while (--i >= 0) {
				mdev_state->efd_count--;
				eventfd_ctx_put(mdev_state->trigger[mdev_state->efd_count]);
				mdev_state->trigger[mdev_state->efd_count] = NULL;
			}
			return -1;
		}


		mdev_state->trigger[mdev_state->efd_count++] = trigger;
	}

	return 0;
}

static void ccp_ectx_list_init(struct hygon_ccp_dev_wrapper *ccp_wrapper)
{
	int i;

	for (i = 0; i < MCCP_DEV_QUEUE; i++)
		INIT_KFIFO(ccp_wrapper->ectx_q[i].ectx_fifo);
}

static void ccp_dev_queue_switch(struct ccp_device *ccp)
{
	struct ccp_cmd_queue *cmd_q = NULL;
	u32 dma_addr_lo = 0;
	int i = 0;

	for (i = 0; i < ccp->cmd_q_count; i++) {
		cmd_q = &ccp->cmd_q[i];
		dma_addr_lo = (u32)cmd_q->qdma_tail;
		iowrite32(0, cmd_q->reg_control);
		iowrite32((u32)dma_addr_lo, cmd_q->reg_tail_lo);
		iowrite32((u32)dma_addr_lo, cmd_q->reg_head_lo);
		iowrite32(cmd_q->qcontrol, cmd_q->reg_control);
		cmd_q->qidx = 0;
	}
}

static int ccp_dev_iommu_attach_device(struct pci_dev *pdev)
{
	int ret;

	if (iommu_capable(pdev->dev.bus, IOMMU_CAP_CACHE_COHERENCY))
		ccp_mdev_data.prot |= IOMMU_CACHE;

	ret = iommu_attach_device(ccp_mdev_data.domain, &pdev->dev);
	if (ret) {
		pr_err("iommu_attach_device fail, ret = %d.\n", ret);
		return ret;
	}

	return 0;
}

static void ccp_dev_iommu_free(struct ccp_iommu *iommu)
{
	struct iommu_domain *domain = NULL;

	if (!iommu || iommu->magic != MCCP_SHARE_IOMMU_MAGIC)
		return;

	domain = iommu_get_domain_for_dev(&iommu->pdev->dev);

	if (iommu->pdev && domain == ccp_mdev_data.domain)
		iommu_detach_device(domain, &iommu->pdev->dev);
}

static void ccp_dev_iommu_detach_device(struct pci_dev *pdev)
{
	struct ccp_iommu *iommu = NULL;
	int i;

	for (i = 0; i < MCCP_DEV_MAX; i++) {
		iommu = &ccp_mdev_data.iommu[i];
		if (iommu->pdev && iommu->pdev == pdev) {
			ccp_dev_iommu_free(iommu);
			break;
		}
	}
}

static void ccp_dev_usermode_restore(struct pci_dev *pdev)
{
	struct hygon_ccp_dev_wrapper *ccp_wrapper = NULL;

	list_for_each_entry(ccp_wrapper, &ccp_dev_wrapper_list, entry) {
		if (ccp_wrapper->pdev != pdev)
			continue;
		if (ccp_wrapper->used_mode == _USER_SPACE_USED) {
			ccp_wrapper->used_mode = _KERNEL_SPACE_USED;
			ccp_dev_iommu_detach_device(ccp_wrapper->pdev);
			ccp_dev_queue_switch(ccp_wrapper->cdev);
			ccp_add_device(ccp_wrapper->cdev);
			ccp_wrapper->del_flag = 0;
		}
		if (ccp_wrapper->del_flag == 1) {
			ccp_add_device(ccp_wrapper->cdev);
			ccp_wrapper->del_flag = 0;
		}
		break;
	}
}

static void ccp_dev_usermode_userid_clear(int ccp_id)
{
	struct ccp_shr_pg_cfg *shr_cfg = NULL;

	/* For qemu, not clear the value of userid. */
	if (!ccp_share.pages[ccp_id])
		return;

	shr_cfg = (void *)page_to_virt(ccp_share.pages[ccp_id]);
	memset(shr_cfg->userid, 0, sizeof(unsigned long) * MCCP_DEV_QUEUE);
}

static int ccp_dev_kernel_mode_used_state(struct ccp_device *ccp)
{
	int i;

	if (ccp->cmd_count > 0)
		return 1;

	for (i = 0; i < ccp->cmd_q_count; i++) {
		if (ccp->cmd_q[i].active)
			return 1;
	}

	return 0;
}

static long ccp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct mdev_state *mdev_state = file->private_data;
	unsigned long minsz;
	int ret = 0;

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		ret = ccp_get_device_info(mdev_state, &info);
		if (ret)
			return ret;

		memcpy(&mdev_state->dev_info, &info, sizeof(info));

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;
		u16 cap_type_id = 0;
		void *cap_type = NULL;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		ret = ccp_get_region_info(mdev_state, &info, &cap_type_id,
					   &cap_type);
		if (ret)
			return ret;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_IRQ_INFO:
	{
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if ((info.argsz < minsz) ||
		    (info.index >= mdev_state->dev_info.num_irqs))
			return -EINVAL;

		ret = ccp_get_irq_info(mdev_state, &info);
		if (ret)
			return ret;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_SET_IRQS:
	{
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		size_t data_size = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		ret = ccp_set_irqs_validate_and_prepare(&hdr, mdev_state->dev_info.num_irqs,
				mdev_state->dev_info.num_irqs, &data_size);
		if (ret)
			return ret;

		if (data_size) {
			data = memdup_user((void __user *)(arg + minsz), data_size);
			if (IS_ERR(data))
				return PTR_ERR(data);
		}

		mutex_lock(&mdev_state->ops_lock);
		ret = ccp_set_irq_efds(mdev_state, &hdr, data);
		mutex_unlock(&mdev_state->ops_lock);
		kfree(data);

		return ret;
	}
	case VFIO_DEVICE_CCP_SET_MODE:
	{
		struct hygon_ccp_dev_wrapper *ccp_wrapper = mdev_state->iommu->wrapper;
		unsigned long flags;

		if (!write_trylock_irqsave(&ccp_wrapper->q_lock, flags))
			return -EAGAIN;

		if (ccp_wrapper->used_mode == arg) {
			write_unlock_irqrestore(&ccp_wrapper->q_lock, flags);
			return 0;
		}

		switch (arg) {
		case _KERNEL_SPACE_USED:
			ccp_wrapper->used_mode = _KERNEL_SPACE_USED;
			ccp_dev_iommu_detach_device(ccp_wrapper->pdev);
			ccp_dev_queue_switch(ccp_wrapper->cdev);
			ccp_add_device(ccp_wrapper->cdev);
			break;
		case _USER_SPACE_USED:
			if (ccp_wrapper->del_flag == 0) {
				ccp_del_device(ccp_wrapper->cdev);
				ccp_wrapper->del_flag = 1;
			}
			if (ccp_dev_kernel_mode_used_state(ccp_wrapper->cdev)) {
				ret = -EAGAIN;
				break;
			}
			if (ccp_dev_iommu_attach_device(ccp_wrapper->pdev)) {
				ccp_add_device(ccp_wrapper->cdev);
				ccp_wrapper->del_flag = 0;
				ret = -EINVAL;
			} else {
				ccp_wrapper->used_mode = _USER_SPACE_USED;
				ccp_ectx_list_init(ccp_wrapper);
				ccp_dev_usermode_userid_clear(mdev_state->iommu->id);
			}
			break;
		default:
			pr_err("arg = %lu, invalid.\n", arg);
			ret = -EINVAL;
			break;
		}

		write_unlock_irqrestore(&ccp_wrapper->q_lock, flags);
		return ret;
	}
	case VFIO_DEVICE_CCP_GET_MODE:
	{
		struct hygon_ccp_dev_wrapper *ccp_wrapper = mdev_state->iommu->wrapper;

		if (put_user(ccp_wrapper->used_mode, (int __user *)arg))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_PCI_ADDR:
	{
		struct pci_dev *pdev = mdev_state->iommu->pdev;
		struct mccp_pci_addr addr;

		if (copy_from_user(&addr, (void __user *)arg, sizeof(addr)))
			return -EFAULT;

		addr.domain = pci_domain_nr(pdev->bus);
		addr.bus = pdev->bus->number;
		addr.devid = PCI_SLOT(pdev->devfn);
		addr.function = PCI_FUNC(pdev->devfn);
		if (pdev->dev.numa_node >= 0)
			addr.numa_node = pdev->dev.numa_node;
		else
			addr.numa_node = 0;

		if (copy_to_user((void __user *)arg, &addr, sizeof(addr)))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_PCI_ID:
	{
		struct pci_dev *pdev = mdev_state->iommu->pdev;
		struct mccp_pci_id pid;

		if (copy_from_user(&pid, (void __user *)arg, sizeof(pid)))
			return -EFAULT;

		pid.class = pdev->class;
		pid.vendor = pdev->vendor;
		pid.device = pdev->device;
		pid.subsystem_vendor = pdev->subsystem_vendor;
		pid.subsystem_device = pdev->subsystem_device;

		if (copy_to_user((void __user *)arg, &pid, sizeof(pid)))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_RESET:
		return ccp_reset(mdev_state);
	}
	return -ENOTTY;
}

static int ccp_open(struct inode *inode, struct file *file)
{
	struct mdev_state *mdev_state = NULL;
	int ccp_idx = iminor(inode);

	mdev_state = kzalloc(sizeof(struct mdev_state), GFP_KERNEL);
	if (mdev_state == NULL)
		return -ENOMEM;

	mutex_init(&mdev_state->ops_lock);
	mdev_state->iommu = &ccp_mdev_data.iommu[ccp_idx];

	mutex_lock(&mdev_state->iommu->lock);
	mdev_state->iommu->ref++;
	mutex_unlock(&mdev_state->iommu->lock);

	file->private_data = mdev_state;
	return 0;
}

static int ccp_close(struct inode *inode, struct file *file)
{
	struct mdev_state *mdev_state = file->private_data;
	struct hygon_ccp_dev_wrapper *ccp_wrapper = mdev_state->iommu->wrapper;
	unsigned long flags;

	mutex_lock(&mdev_state->iommu->lock);
	mdev_state->iommu->ref--;
	if (!mdev_state->iommu->ref) {
		write_lock_irqsave(&ccp_wrapper->q_lock, flags);
		ccp_dev_usermode_restore(mdev_state->iommu->pdev);
		write_unlock_irqrestore(&ccp_wrapper->q_lock, flags);
	}
	mutex_unlock(&mdev_state->iommu->lock);

	kfree(mdev_state);
	return 0;
}

static void ccp_mmap_open(struct vm_area_struct *vma)
{
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

static void ccp_mmap_close(struct vm_area_struct *vma)
{
}

static vm_fault_t ccp_mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret = VM_FAULT_NOPAGE;

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			vma->vm_end - vma->vm_start,
			pgprot_decrypted(vma->vm_page_prot)))
		ret = VM_FAULT_SIGBUS;
	return ret;
}

static const struct vm_operations_struct ccp_mmap_ops = {
	.open = ccp_mmap_open,
	.close = ccp_mmap_close,
	.fault = ccp_mmap_fault,
};

static int ccp_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct mdev_state *mdev_state = file->private_data;
	struct pci_dev *pdev = mdev_state->iommu->pdev;
	unsigned int index;

	index = vma->vm_pgoff >> (40 - PAGE_SHIFT);
	vma->vm_private_data = pdev;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = pci_resource_start(pdev, index) >> PAGE_SHIFT;
	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &ccp_mmap_ops;

	return 0;
}

static const struct file_operations ccp_fops = {
	.owner		= THIS_MODULE,
	.open		= ccp_open,
	.release	= ccp_close,
	.read		= ccp_read,
	.write		= ccp_write,
	.unlocked_ioctl	= ccp_ioctl,
	.mmap		= ccp_mmap,
};

struct ccp_private {
	struct list_head head;
	struct mutex lock;
	unsigned long vm_start;
	unsigned int id;
	unsigned int pasid;
};

static int ccp_share_open(struct inode *inode, struct file *file)
{
	struct ccp_private *private = NULL;
	u32 id;
	int ret = 0;

	private = kzalloc(sizeof(*private), GFP_KERNEL);
	if (!private)
		return -ENOMEM;

	mutex_lock(&ccp_mdev_data.lock);
	id = (u32)find_first_zero_bit(ccp_mdev_data.ids, MCCP_INSTANCE_MAX);
	if (id < MCCP_INSTANCE_MAX)
		bitmap_set(ccp_mdev_data.ids, id, 1);
	mutex_unlock(&ccp_mdev_data.lock);

	if (id >= MCCP_INSTANCE_MAX) {
		kfree(private);
		return -EBUSY;
	}

	mutex_lock(&ccp_share.lock);
	ccp_share.ref++;
	ccp_share.pagecount = MCCP_DEV_MAX;
	mutex_unlock(&ccp_share.lock);

	file->private_data = private;
	/*
	 * At user space, each process is assigned a different number
	 * which cannot be 0, as the identifier for the process.
	 * The number is assigned by id, so the value of id needs to
	 * start from 1, and cannot be 0.
	 */
	private->id = (++id) << MCCP_INSTANCE_OFFSET;
	INIT_LIST_HEAD(&private->head);
	mutex_init(&private->lock);

	return ret;
}

static bool is_invalid_reserved_pfn(unsigned long pfn)
{
	if (pfn_valid(pfn))
		return PageReserved(pfn_to_page(pfn));

	return true;
}

static int follow_fault_pfn(struct vm_area_struct *vma,
				struct mm_struct *mm,
				unsigned long vaddr,
				unsigned long *pfn,
				bool write_fault)
{
	bool unlocked = false;
	int ret;

	ret = follow_pfn(vma, vaddr, pfn);
	if (ret) {
		ret = fixup_user_fault(mm, vaddr,
				FAULT_FLAG_REMOTE |
				(write_fault ? FAULT_FLAG_WRITE : 0),
				&unlocked);
		if (unlocked)
			return -EAGAIN;

		if (ret)
			return ret;

		ret = follow_pfn(vma, vaddr, pfn);
	}

	return ret;
}

static int vaddr_get_pfn(struct mm_struct *mm, unsigned long vaddr,
			 int prot, unsigned long *pfn)
{
	struct page *page[1];
	struct vm_area_struct *vma = NULL;
	unsigned int flags = 0;
	int ret;

	if (prot & IOMMU_WRITE)
		flags |= FOLL_WRITE;

	mmap_read_lock(mm);
	ret = pin_user_pages_remote(mm, vaddr, 1, flags | FOLL_LONGTERM,
				    page, NULL, NULL);
	if (ret == 1) {
		*pfn = page_to_pfn(page[0]);
		ret = 0;
		goto done;
	}

	vaddr = untagged_addr(vaddr);

retry:
	vma = find_vma_intersection(mm, vaddr, vaddr + 1);

	if (vma && vma->vm_flags & VM_PFNMAP) {
		ret = follow_fault_pfn(vma, mm, vaddr, pfn, prot & IOMMU_WRITE);
		if (ret == -EAGAIN)
			goto retry;

		if (!ret && !is_invalid_reserved_pfn(*pfn))
			ret = -EFAULT;
	}
done:
	mmap_read_unlock(mm);

	return ret;
}

struct page **ccp_pin_memory(struct ccp_private *private, unsigned long uaddr,
			unsigned long ulen, unsigned long *n)
{
	struct page **pages;
	unsigned long npages, size;
	unsigned long first, last;
	int npinned;

	if (ulen == 0 || uaddr + ulen < uaddr)
		return NULL;

	first = (uaddr & PAGE_MASK) >> PAGE_SHIFT;
	last = ((uaddr + ulen - 1) & PAGE_MASK) >> PAGE_SHIFT;
	npages = (last - first + 1);

	if (WARN_ON_ONCE(npages > INT_MAX))
		return NULL;

	size = npages * sizeof(struct page *);
	if (size > PAGE_SIZE)
		pages = vmalloc(size);
	else
		pages = kmalloc(size, GFP_KERNEL);

	if (!pages)
		return NULL;

	/* Pin the user virtual address. */
	npinned = pin_user_pages_fast(uaddr, npages, FOLL_WRITE, pages);
	if (npinned != npages)
		goto err;

	*n = npages;
	return pages;

err:
	if (npinned > 0)
		unpin_user_pages(pages, npinned);
	kvfree(pages);
	return NULL;
}

static void ccp_unpin_memory(struct ccp_private *private, struct page **pages,
			     unsigned long npages)
{
	unpin_user_pages(pages, npages);
	kvfree(pages);
}

static inline int is_dma_share(dma_addr_t dma_iova, size_t dma_size)
{
	if (dma_iova >= MCCP_DMA_IOVA_OFFSET &&
	    dma_iova + dma_size <= MCCP_DMA_IOVA_OFFSET + MCCP_DMA_IOVA_SIZE)
		return 1;
	else
		return 0;
}

static int ccp_add_dma_share_unsafe(dma_addr_t dma_iova, size_t dma_size)
{
	int ret = 0;

	if (!is_dma_share(dma_iova, dma_size))
		return 0;

	if (!ccp_mdev_data.dma_share_size) {
		ccp_mdev_data.dma_share_iova = dma_iova;
		ccp_mdev_data.dma_share_size = dma_size;
	}

	if (dma_iova != ccp_mdev_data.dma_share_iova ||
	    dma_size != ccp_mdev_data.dma_share_size)
		ret = -EINVAL;
	else
		ccp_mdev_data.dma_share_ref++;

	return ret;
}

static int ccp_unmap_dma_share_unsafe(dma_addr_t dma_iova, size_t dma_size)
{
	if (!is_dma_share(dma_iova, dma_size))
		return -EINVAL;

	if (ccp_mdev_data.dma_share_size) {
		if (ccp_mdev_data.dma_share_iova == dma_iova &&
		    ccp_mdev_data.dma_share_size == dma_size)
			ccp_mdev_data.dma_share_ref--;

		if (ccp_mdev_data.dma_share_ref == 0) {
			iommu_unmap(ccp_mdev_data.domain, ccp_mdev_data.dma_share_iova,
				ccp_mdev_data.dma_share_size);
			ccp_mdev_data.dma_share_size = 0;
		}
	}

	return 0;
}

static int ccp_iommu_iova_check_unsafe(dma_addr_t dma_iova, size_t dma_size,
				phys_addr_t phys_addr,
				struct iommu_domain *domain)
{
	dma_addr_t iova;
	size_t mapped = 0;
	int ret = 0;

	iova = dma_iova;
	while (iova < dma_iova + dma_size) {
		phys_addr_t phys;

		phys = iommu_iova_to_phys(domain, iova);
		if (phys) {
			if ((phys_addr & PHY_ADDR_MASK) != (phys & PHY_ADDR_MASK)) {
				pr_err("iova:0x%llx phys_addr:0x%llx phys:0x%llx, fail.\n",
							iova, phys_addr, phys);
				ret = -1;
				break;
			}
			mapped += PAGE_SIZE;
		}
		iova += PAGE_SIZE;
		phys_addr += PAGE_SIZE;
	}

	if (ret == 0 && mapped == dma_size)
		ret = 1;

	return ret;
}

static unsigned long get_num_contig_pages(unsigned long idx,
				struct page **inpages, unsigned long npages)
{
	unsigned long paddr, next_paddr;
	unsigned long i = idx + 1, pages = 1;

	/* find the number of contiguous pages starting from idx */
	paddr = page_to_phys(inpages[idx]);
	while (i < npages) {
		next_paddr = page_to_phys(inpages[i++]);
		if ((paddr + PAGE_SIZE) == next_paddr) {
			pages++;
			paddr = next_paddr;
			continue;
		}
		break;
	}

	return pages;
}

static struct ccp_dma *ccp_find_dma(struct ccp_private *private,
				      dma_addr_t start, size_t size)
{
	struct ccp_dma *dma = NULL, *tmp = NULL;

	list_for_each_entry_safe(dma, tmp, &private->head, next) {
		if (dma->iova <= start &&
		    dma->iova + dma->size >= start + size)
			return dma;
	}

	return NULL;
}

/*
 * Turns out AMD IOMMU has a page table bug where it won't map large pages
 * to a region that previously mapped smaller pages.  This should be fixed
 * soon, so this is just a temporary workaround to break mappings down into
 * PAGE_SIZE.  Better to map smaller pages than nothing.
 */
static int map_try_harder(struct iommu_domain *domain, dma_addr_t iova,
			  unsigned long pfn, long npage, int prot)
{
	long i;
	int ret = 0;

	for (i = 0; i < npage; i++, pfn++, iova += PAGE_SIZE) {
		ret = iommu_map(domain, iova,
				(phys_addr_t)pfn << PAGE_SHIFT,
				PAGE_SIZE, prot);
		if (ret)
			break;
	}

	for (; i < npage && i > 0; i--, iova -= PAGE_SIZE)
		iommu_unmap(domain, iova, PAGE_SIZE);

	return ret;
}

/*
 * only handle io-memory [vm_flags | VM_PFNMAP == true]
 */
static int ccp_iommu_pfnmap(struct ccp_private *private, struct ccp_dma *dma)
{
	unsigned long pfn;
	unsigned long vaddr;
	dma_addr_t iova;
	size_t mapped_size = 0;
	size_t size;
	int ret = 0;

	if (!private || !dma)
		return -EINVAL;

	dma->pfnmap_flag = 1;
	vaddr = dma->vaddr;
	iova = dma->iova;
	size = dma->size;

	mutex_lock(&ccp_mdev_data.lock);
	while (size) {
		ret = vaddr_get_pfn(current->mm, vaddr, ccp_mdev_data.prot, &pfn);
		if (ret)
			goto map_fail;

		ret = iommu_map(ccp_mdev_data.domain, iova,
				(phys_addr_t)pfn << PAGE_SHIFT,
				1 << PAGE_SHIFT, ccp_mdev_data.prot);
		if (ret)
			goto map_fail;

		size -= 1 << PAGE_SHIFT;
		vaddr += 1 << PAGE_SHIFT;
		iova += 1 << PAGE_SHIFT;
		mapped_size += 1 << PAGE_SHIFT;
	}
	mutex_unlock(&ccp_mdev_data.lock);

	list_add(&dma->next, &private->head);
	return 0;

map_fail:
	mutex_unlock(&ccp_mdev_data.lock);
	iommu_unmap(ccp_mdev_data.domain, dma->iova, mapped_size);
	return ret;
}

static int ccp_iommu_map(struct ccp_private *private, unsigned long vaddr,
			dma_addr_t dma_iova, size_t dma_size)
{
	struct ccp_dma *dma = NULL;
	struct page **pages;
	unsigned long n, i, npages;
	dma_addr_t iova, iova_end, iova_next;
	size_t mapped_size = 0;
	size_t iova_size = dma_size;
	int ret = 0;

	if (!dma_size || (vaddr | dma_iova | dma_size) & (PAGE_SIZE - 1))
		return -EINVAL;

	if (ccp_find_dma(private, dma_iova, dma_size))
		return 0;

	dma = kzalloc(sizeof(*dma), GFP_KERNEL);
	if (!dma)
		return -ENOMEM;

	pages = ccp_pin_memory(private, vaddr, dma_size, &n);
	if (!pages) {
		/* We will think the vm_flags includes VM_PFNMAP. */
		dma->vaddr = vaddr;
		dma->iova = dma_iova;
		dma->size = dma_size;
		ret = ccp_iommu_pfnmap(private, dma);
		if (ret)
			kfree(dma);
		return ret;
	}

	dma->vaddr = vaddr;
	dma->iova = dma_iova;
	dma->pages = pages;
	dma->size = dma_size;
	dma->npages = n;

	iova = dma_iova;
	iova_end = dma_iova + dma_size;
	iova_size = dma_size;

	mutex_lock(&ccp_mdev_data.lock);
	for (i = 0; iova < iova_end && i < n; iova = iova_next, i += npages) {
		size_t len;
		phys_addr_t phys;

		npages = get_num_contig_pages(i, pages, n);

		/* When the value of npages is 524288, the value of npages * PAGE_SIZE
		 * will be 0x80000000 (bit31 is 1).
		 * When the value of npages is not less than 524288, if the type of len is int,
		 * the len will be a negative value.
		 */
		len = min_t(size_t, (npages * PAGE_SIZE), iova_size);
		phys = page_to_phys(pages[i]);

		iova_size -= len;
		iova_next = iova + len;

		ret = ccp_iommu_iova_check_unsafe(iova, len, phys, ccp_mdev_data.domain);
		if (ret < 0) {
			ret = -EBUSY;
			goto map_fail;
		} else if (ret > 0) {
			ret = 0;
			continue;
		}

		ret = iommu_map(ccp_mdev_data.domain, iova, phys, len, ccp_mdev_data.prot);
		if (ret) {
			if (ret == -EBUSY)
				ret = map_try_harder(ccp_mdev_data.domain, iova,
						     phys >> PAGE_SHIFT,
						     len >> PAGE_SHIFT,
						     ccp_mdev_data.prot);
			if (ret)
				goto map_fail;
		}
		mapped_size += len;
		cond_resched();
	}

	ret = ccp_add_dma_share_unsafe(dma_iova, dma_size);
	if (ret)
		goto map_fail;

	mutex_unlock(&ccp_mdev_data.lock);
	list_add(&dma->next, &private->head);
	return 0;
map_fail:
	if (mapped_size)
		iommu_unmap(ccp_mdev_data.domain, dma_iova, mapped_size);
	mutex_unlock(&ccp_mdev_data.lock);
	ccp_unpin_memory(private, pages, n);
	kfree(dma);
	return ret;
}

static void ccp_iommu_unmap(struct ccp_private *private,
			dma_addr_t iova, size_t size)
{
	struct iommu_domain *domain = ccp_mdev_data.domain;
	struct ccp_dma *dma = NULL;

	if (!size || (iova | size) & (PAGE_SIZE - 1))
		return;

	dma = ccp_find_dma(private, iova, size);
	if (!dma)
		return;

	mutex_lock(&ccp_mdev_data.lock);
	iommu_unmap(domain, dma->iova, dma->size);
	if (dma->pfnmap_flag == 0)
		ccp_unpin_memory(private, dma->pages, dma->npages);
	list_del(&dma->next);
	kfree(dma);
	mutex_unlock(&ccp_mdev_data.lock);
}

static void ccp_iommu_unmap_all(struct ccp_private *private)
{
	struct iommu_domain *domain = ccp_mdev_data.domain;
	struct ccp_dma *dma = NULL, *tmp = NULL;

	mutex_lock(&ccp_mdev_data.lock);
	list_for_each_entry_safe(dma, tmp, &private->head, next) {
		if (ccp_unmap_dma_share_unsafe(dma->iova, dma->size))
			iommu_unmap(domain, dma->iova, dma->size);
		if (dma->pfnmap_flag == 0)
			ccp_unpin_memory(private, dma->pages, dma->npages);
		cond_resched();
		list_del(&dma->next);
		kfree(dma);
	}
	mutex_unlock(&ccp_mdev_data.lock);
}

static struct page *ccp_get_page(pgoff_t page_idx)
{
	struct ccp_shr_pg_cfg *shr_cfg = NULL;
	int numa_node;

	mutex_lock(&ccp_share.lock);
	if (ccp_mdev_data.iommu[page_idx].pdev == NULL) {
		mutex_unlock(&ccp_share.lock);
		return NULL;
	}

	if (!ccp_share.pages[page_idx]) {
		ccp_share.pages[page_idx] =
			alloc_pages(GFP_HIGHUSER | __GFP_ZERO, 0);
		if (!ccp_share.pages[page_idx]) {
			mutex_unlock(&ccp_share.lock);
			return NULL;
		}
	}
	get_page(ccp_share.pages[page_idx]);

	numa_node = ccp_mdev_data.iommu[page_idx].pdev->dev.numa_node;
	if (numa_node < 0)
		numa_node = 0;

	shr_cfg = (void *)page_to_virt(ccp_share.pages[page_idx]);
	shr_cfg->numa_node = numa_node;
	mutex_unlock(&ccp_share.lock);

	return ccp_share.pages[page_idx];
}

static void ccp_put_pages(void)
{
	int i;

	for (i = 0; i < ccp_share.pagecount; i++) {
		if (!ccp_share.pages[i])
			continue;

		put_page(ccp_share.pages[i]);
		ccp_share.pages[i] = NULL;
	}
}

static void ccp_shared_page_memory_clear(unsigned int gid)
{
	struct ccp_shr_pg_cfg *shr_cfg = NULL;
	int i, q;

	for (i = 0; i < MCCP_DEV_MAX; i++) {
		if (!ccp_share.pages[i])
			continue;

		shr_cfg = (void *)page_to_virt(ccp_share.pages[i]);
		if ((shr_cfg->dev_init_state & MCCP_INSTANCE_MASK) == gid)
			shr_cfg->dev_init_state = 0;
		if (shr_cfg->dev_lock_state == gid)
			shr_cfg->dev_lock_state = 0;

		for (q = 0; q < MCCP_DEV_QUEUE; q++)
			if (shr_cfg->ccp_queue_state[q] == gid)
				shr_cfg->ccp_queue_state[q] = MCCP_QUEUE_NEED_INIT;
	}
}

static long ccp_share_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	struct ccp_private *private = file->private_data;
	struct ccp_mdev_ctrl dev_ctrl;
	unsigned int cmd_id;
	unsigned int len;
	unsigned int pasid;
	int ret = 0;

	if (_IOC_TYPE(ioctl) != MCCP_SHARE_IOC_TYPE)
		return -EINVAL;

	cmd_id = _IOC_NR(ioctl);
	len = _IOC_SIZE(ioctl);

	if (cmd_id != MCCP_SHARE_OP)
		return -EINVAL;

	if (len != sizeof(dev_ctrl))
		return -EINVAL;

	if (copy_from_user(&dev_ctrl, (void __user *)arg, sizeof(dev_ctrl)))
		return -EINVAL;

	mutex_lock(&private->lock);
	switch (dev_ctrl.op) {
	case MCCP_SHARE_OP_DMA_MAP:
		ret = ccp_iommu_map(private, dev_ctrl.vaddr, dev_ctrl.iova, dev_ctrl.size);
		break;
	case MCCP_SHARE_OP_DMA_UNMAP:
		ccp_iommu_unmap(private, dev_ctrl.iova, dev_ctrl.size);
		ret = 0;
		break;
	case MCCP_SHARE_OP_DMA_UNMAP_ALL:
		ccp_iommu_unmap_all(private);
		ret = 0;
		break;
	case MCCP_SHARE_OP_GET_ID:
		dev_ctrl.id = private->id;
		if (copy_to_user((void __user *)arg, &dev_ctrl, sizeof(dev_ctrl)))
			ret = -EINVAL;
		else
			ret = 0;
		break;
	case MCCP_SHARE_OP_GET_PASID:
		mutex_lock(&ccp_mdev_data.lock);
		pasid = find_first_zero_bit(ccp_mdev_data.pasids, MCCP_PASID_SIZE);
		if (pasid >= MCCP_PASID_SIZE) {
			ret = -EINVAL;
			mutex_unlock(&ccp_mdev_data.lock);
			break;
		}
		private->pasid = pasid;
		dev_ctrl.pasid = pasid;
		bitmap_set(ccp_mdev_data.pasids, pasid, 1);
		if (copy_to_user((void __user *)arg, &dev_ctrl, sizeof(dev_ctrl)))
			ret = -EINVAL;
		mutex_unlock(&ccp_mdev_data.lock);
		break;
	case MCCP_SHARE_OP_GET_VERSION:
		memcpy(dev_ctrl.version, VERSION_STRING, sizeof(VERSION_STRING));
		if (copy_to_user((void __user *)arg, &dev_ctrl, sizeof(dev_ctrl)))
			ret = -EINVAL;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&private->lock);

	return ret;
}

static int ccp_share_close(struct inode *inode, struct file *file)
{
	struct ccp_private *private = file->private_data;
	unsigned int id = private->id >> MCCP_INSTANCE_OFFSET;

	mutex_lock(&ccp_share.lock);
	/* For the vm scenario, the ccp_share.vaddr value is NULL. */
	if (ccp_share.vaddr) {
		struct ccp_shared_cfg *cfg = ccp_share.vaddr;
		int i;

		if (private->id == cfg->ccps_ref_lock)
			cfg->ccps_ref_lock = 0;

		for (i = 0; i < MCCP_IOVA_MAX_SLOT; i++)
			if (private->id == cfg->iova_slot[i])
				cfg->iova_slot[i] = 0;
	}

	ccp_shared_page_memory_clear(private->id);

	ccp_share.ref--;
	if (!ccp_share.ref)
		ccp_put_pages();
	mutex_unlock(&ccp_share.lock);

	mutex_lock(&ccp_mdev_data.lock);
	if (--id < MCCP_INSTANCE_MAX)
		bitmap_clear(ccp_mdev_data.ids, id, 1);
	if (private->pasid)
		bitmap_clear(ccp_mdev_data.pasids, private->pasid, 1);
	mutex_unlock(&ccp_mdev_data.lock);

	mutex_lock(&private->lock);
	ccp_iommu_unmap_all(private);
	mutex_unlock(&private->lock);

	kfree(private);
	return 0;
}

static vm_fault_t ccp_cdev_vma_fault(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct ccp_private *private = file->private_data;
	pgoff_t page_idx = (vmf->address - private->vm_start) >> PAGE_SHIFT;

	if (page_idx >= ccp_share.pagecount)
		return VM_FAULT_SIGBUS;

	vmf->page = ccp_get_page(page_idx);
	if (!vmf->page)
		return VM_FAULT_SIGBUS;

	return 0;
}

static const struct vm_operations_struct ccp_cdev_vm_ops = {
	.fault = ccp_cdev_vma_fault,
};

static int ccp_share_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct ccp_private *private = file->private_data;
	unsigned long len;
	int ret = 0;

	mutex_lock(&ccp_share.lock);
	len = vma->vm_end - vma->vm_start;
	if (len == MCCP_SHARED_SIZE) {
		private->vm_start = vma->vm_start;
		vma->vm_ops = &ccp_cdev_vm_ops;
		goto exit;
	}

	if (unlikely(!ccp_share.vaddr)) {
		ccp_share.size = (vma->vm_end - vma->vm_start);
		ccp_share.vaddr = kzalloc(ccp_share.size, GFP_KERNEL);
	}

	if (!ccp_share.vaddr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (ccp_share.size != (vma->vm_end - vma->vm_start)) {
		pr_err("invalid ccp share size\n");
		ret = -EINVAL;
		goto exit;
	}

	ret = remap_pfn_range(vma, vma->vm_start,
			virt_to_phys(ccp_share.vaddr) >> PAGE_SHIFT,
			ccp_share.size,
			vma->vm_page_prot);
exit:
	mutex_unlock(&ccp_share.lock);
	return ret;
}

static const struct file_operations ccp_share_fops = {
	.owner		= THIS_MODULE,
	.open		= ccp_share_open,
	.release	= ccp_share_close,
	.mmap		= ccp_share_mmap,
	.unlocked_ioctl	= ccp_share_ioctl,
};

static struct miscdevice ccp_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ccp_share",
	.fops = &ccp_share_fops,
	.mode = 0666,
};

static int ccp_share_init(void)
{
	int i;
	int ret;

	memset(&ccp_mdev_data, 0x00, sizeof(ccp_mdev_data));
	mutex_init(&ccp_mdev_data.lock);

	for (i = 0; i < MCCP_DEV_MAX; i++)
		mutex_init(&ccp_mdev_data.iommu[i].lock);

	ret = misc_register(&ccp_misc);
	if (!ret) {
		ccp_mdev_data.domain = iommu_domain_alloc(&pci_bus_type);
		if (!ccp_mdev_data.domain) {
			misc_deregister(&ccp_misc);
			if (!pci_bus_type.iommu_ops) {
				pr_err("iommu is disabled\n");
				return -ENODEV;
			}
			return -ENOMEM;
		}
		ccp_mdev_data.prot = IOMMU_READ | IOMMU_WRITE;
	}

	/* When the pasid value is 0 or 1, the address space overlaps with the host,
	 * so the pasid needs to start from 2.
	 */
	ccp_mdev_data.pasids[0] |= MCCP_PASID_MASK_BIT;
	return ret;
}

static void ccp_share_exit(void)
{
	struct ccp_iommu *iommu = NULL;
	struct iommu_domain *domain = NULL;
	struct pci_dev *pdev = NULL;
	int i;

	mutex_lock(&ccp_mdev_data.lock);
	for (i = 0; i < MCCP_DEV_MAX; i++) {
		iommu = &ccp_mdev_data.iommu[i];
		pdev = iommu->pdev;
		if (pdev) {
			domain = iommu_get_domain_for_dev(&pdev->dev);
			if (domain == ccp_mdev_data.domain)
				iommu_detach_device(domain, &pdev->dev);
		}
	}
	mutex_unlock(&ccp_mdev_data.lock);

	if (ccp_mdev_data.domain)
		iommu_domain_free(ccp_mdev_data.domain);

	misc_deregister(&ccp_misc);
	kfree(ccp_share.vaddr);
}

struct hygon_ccp_dev_wrapper *hygon_ccp_dev_wrapper_get(struct ccp_device *ccp)
{
	struct hygon_ccp_dev_wrapper *ccp_wrapper = NULL;

	if (list_empty(&ccp_dev_wrapper_list))
		return NULL;

	list_for_each_entry(ccp_wrapper, &ccp_dev_wrapper_list, entry) {
		if (ccp_wrapper->cdev == ccp)
			return ccp_wrapper;
	}

	return NULL;
}

int ccp_dev_wrapper_list_empty(void)
{
	return list_empty(&ccp_dev_wrapper_list);
}

static int ccp_pci_device_create(struct pci_dev *pdev,
		struct hygon_ccp_dev_wrapper *ccp_wrapper)
{
	struct device *device = NULL;
	unsigned long i;
	int ret = -EINVAL;

	mutex_lock(&ccp_mdev_data.lock);
	i = find_first_zero_bit(&ccp_mdev_data.bitmap, MCCP_DEV_MAX);
	if (i != MCCP_DEV_MAX)
		bitmap_set(&ccp_mdev_data.bitmap, i, 1);
	mutex_unlock(&ccp_mdev_data.lock);

	if (i == MCCP_DEV_MAX)
		return -EINVAL;

	mutex_lock(&ccp_mdev_data.iommu[i].lock);
	ccp_mdev_data.iommu[i].pdev = pdev;
	ccp_mdev_data.iommu[i].wrapper = ccp_wrapper;
	ccp_mdev_data.iommu[i].id = i;
	ccp_mdev_data.iommu[i].magic = MCCP_SHARE_IOMMU_MAGIC;
	mutex_unlock(&ccp_mdev_data.iommu[i].lock);

	device = device_create(ccp_mdev.vd_class, NULL,
			MKDEV(ccp_mdev.major, i), NULL, "ccp%lu", i);
	if (device == NULL) {
		pr_err("device_create for /dev/ccp%lu fail.\n", i);
		goto exit;
	}

	ret = 0;
exit:
	if (ret)
		bitmap_clear(&ccp_mdev_data.bitmap, i, 1);
	return ret;
}

static void ccp_pci_device_remove(struct pci_dev *pdev)
{
	struct ccp_iommu *iommu = NULL;
	int i;

	for (i = 0; i < MCCP_DEV_MAX; i++) {
		iommu = &ccp_mdev_data.iommu[i];
		if (iommu->pdev && iommu->pdev == pdev) {
			mutex_lock(&iommu->lock);
			iommu->pdev = NULL;
			iommu->wrapper = NULL;
			iommu->magic = 0;
			mutex_unlock(&iommu->lock);

			mutex_lock(&ccp_mdev_data.lock);
			if (iommu->id < MCCP_DEV_MAX)
				bitmap_clear(&ccp_mdev_data.bitmap, i, 1);
			mutex_unlock(&ccp_mdev_data.lock);

			device_destroy(ccp_mdev.vd_class, MKDEV(ccp_mdev.major, i));
			break;
		}
	}
}

int ccp_dev_wrapper_alloc(struct pci_dev *pdev)
{
	struct sp_device *sp = dev_get_drvdata(&pdev->dev);
	struct ccp_device *ccp = sp->ccp_data;
	struct hygon_ccp_dev_wrapper *ccp_wrapper = NULL;
	int ret;

	if (!ccp)
		return 0;

	ccp_wrapper = kzalloc(sizeof(struct hygon_ccp_dev_wrapper), GFP_KERNEL);
	if (!ccp_wrapper)
		return -ENOMEM;

	rwlock_init(&ccp_wrapper->q_lock);
	ccp_wrapper->used_mode = _KERNEL_SPACE_USED;
	ccp_wrapper->pdev = pdev;
	ccp_wrapper->cdev = ccp;
	mutex_lock(&ccp_dev_wrapper_lock);
	list_add_tail(&ccp_wrapper->entry, &ccp_dev_wrapper_list);
	mutex_unlock(&ccp_dev_wrapper_lock);

	ret = ccp_pci_device_create(pdev, ccp_wrapper);
	if (ret) {
		pr_err("Error: ccp pci device create failed.\n");
		kfree(ccp_wrapper);
		return ret;
	}
	return 0;
}

void ccp_dev_wrapper_free(struct pci_dev *pdev)
{
	struct hygon_ccp_dev_wrapper *ccp_wrapper = NULL;
	struct hygon_ccp_dev_wrapper *tmp_wrapper = NULL;
	struct ccp_device *ccp = NULL;

	if (list_empty(&ccp_dev_wrapper_list))
		return;

	ccp_pci_device_remove(pdev);

	mutex_lock(&ccp_dev_wrapper_lock);
	list_for_each_entry_safe(ccp_wrapper, tmp_wrapper, &ccp_dev_wrapper_list, entry) {
		if (ccp_wrapper->pdev == pdev) {
			ccp = ccp_wrapper->cdev;
			if (ccp_wrapper->used_mode == _USER_SPACE_USED) {
				ccp_wrapper->used_mode = _KERNEL_SPACE_USED;
				ccp_dev_iommu_detach_device(pdev);
				ccp_dev_queue_switch(ccp);
				ccp_add_device(ccp);
			}
			list_del(&ccp_wrapper->entry);
			kfree(ccp_wrapper);
			break;
		}
	}
	mutex_unlock(&ccp_dev_wrapper_lock);
}

int ccp_mdev_init(void)
{
	int ret = 0;

	if (!iommu_present(&pci_bus_type)) {
		pr_info("iommu is disabled\n");
		return 0;
	}

	memset(&ccp_mdev, 0, sizeof(ccp_mdev));

	ret = alloc_chrdev_region(&ccp_mdev.vd_devt, 0, MCCP_CHRDEV_COUNT, MCCP_NAME);
	if (ret < 0) {
		pr_err("Error: failed to register ccp_mdev, err:%d\n", ret);
		return ret;
	}

	ccp_mdev.major = MAJOR(ccp_mdev.vd_devt);
	cdev_init(&ccp_mdev.vd_cdev, &ccp_fops);
	cdev_add(&ccp_mdev.vd_cdev, ccp_mdev.vd_devt, MCCP_CHRDEV_COUNT);
	ccp_mdev.vd_class = class_create(THIS_MODULE, MCCP_CLASS_NAME);
	if (IS_ERR(ccp_mdev.vd_class)) {
		pr_err("Error: failed to register ccp_mdev class\n");
		ret = PTR_ERR(ccp_mdev.vd_class);
		goto fail0;
	}

	ret = ccp_share_init();
	if (ret)
		goto fail1;

	memset(&ccp_share, 0x00, sizeof(ccp_share));
	mutex_init(&ccp_share.lock);
	goto done;

fail1:
	class_destroy(ccp_mdev.vd_class);
fail0:
	cdev_del(&ccp_mdev.vd_cdev);
	unregister_chrdev_region(ccp_mdev.vd_devt, MCCP_CHRDEV_COUNT);
done:
	return ret;
}

void ccp_mdev_exit(void)
{
	if (!iommu_present(&pci_bus_type)) {
		pr_info("iommu is disabled\n");
		return;
	}

	ccp_share_exit();
	class_destroy(ccp_mdev.vd_class);
	cdev_del(&ccp_mdev.vd_cdev);
	unregister_chrdev_region(ccp_mdev.vd_devt, MCCP_CHRDEV_COUNT);
}
