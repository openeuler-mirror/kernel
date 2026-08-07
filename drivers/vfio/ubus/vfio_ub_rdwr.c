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

#include <linux/vfio.h>
#include <linux/uaccess.h>

#include "vfio_ub_private.h"

#ifdef __LITTLE_ENDIAN
#define vfio_mmio_read32 ioread32
#define vfio_mmio_write32 iowrite32
#define vfio_mmio_read16 ioread16
#define vfio_mmio_write16 iowrite16
#else
#define vfio_mmio_read32 ioread32be
#define vfio_mmio_write32 iowrite32be
#define vfio_mmio_read16 ioread16be
#define vfio_mmio_write16 iowrite16be
#endif
#define vfio_mmio_read8 ioread8
#define vfio_mmio_write8 iowrite8

#define VFIO_UB_IOWRITE(size) \
static void vfio_ub_iowrite##size(struct vfio_ub_core_device *vdev,	\
				 u##size val, void __iomem *io)		\
{									\
	vfio_mmio_write##size(val, io);					\
}

VFIO_UB_IOWRITE(8)
VFIO_UB_IOWRITE(16)
VFIO_UB_IOWRITE(32)

#define VFIO_UB_IOREAD(size) \
static void vfio_ub_ioread##size(struct vfio_ub_core_device *vdev,	\
				u##size * val, void __iomem *io)	\
{									\
	*val = vfio_mmio_read##size(io);				\
}

VFIO_UB_IOREAD(8)
VFIO_UB_IOREAD(16)
VFIO_UB_IOREAD(32)

static int vfio_ub_setup_resmap(struct vfio_ub_core_device *vdev, int res)
{
	struct ub_entity *uent = vdev->uent;
	void __iomem *io_addr;

	mutex_lock(&vdev->resmap_lock);
	if (vdev->resmap[res]) {
		mutex_unlock(&vdev->resmap_lock);
		return 0;
	}

	io_addr = ub_iomap(uent, res, 0);
	if (!io_addr) {
		mutex_unlock(&vdev->resmap_lock);
		return -ENOMEM;
	}

	vdev->resmap[res] = io_addr;
	mutex_unlock(&vdev->resmap_lock);
	return 0;
}

void vfio_ub_unset_resmap(struct vfio_ub_core_device *vdev)
{
	int res;

	mutex_lock(&vdev->resmap_lock);
	for (res = 0; res < MAX_UB_RES_NUM; res++) {
		if (!vdev->resmap[res])
			continue;

		ub_iounmap(vdev->resmap[res]);
		vdev->resmap[res] = NULL;
	}
	mutex_unlock(&vdev->resmap_lock);
}

static int do_io_rw32(struct vfio_ub_core_device *vdev, char __user *buf,
		      void __iomem *io, loff_t off, bool iswrite)
{
	u32 val;

	if (iswrite) {
		if (copy_from_user(&val, buf, DWORD_SIZE))
			return -EFAULT;

		vfio_ub_iowrite32(vdev, val, io + off);
	} else {
		vfio_ub_ioread32(vdev, &val, io + off);
		if (copy_to_user(buf, &val, DWORD_SIZE))
			return -EFAULT;
	}

	return 0;
}

static int do_io_rw16(struct vfio_ub_core_device *vdev, char __user *buf,
		      void __iomem *io, loff_t off, bool iswrite)
{
	u16 val;

	if (iswrite) {
		if (copy_from_user(&val, buf, WORD_SIZE))
			return -EFAULT;

		vfio_ub_iowrite16(vdev, val, io + off);
	} else {
		vfio_ub_ioread16(vdev, &val, io + off);
		if (copy_to_user(buf, &val, WORD_SIZE))
			return -EFAULT;
	}

	return 0;
}

static int do_io_rw8(struct vfio_ub_core_device *vdev, char __user *buf,
		     void __iomem *io, loff_t off, bool iswrite)
{
	u8 val;

	if (iswrite) {
		if (copy_from_user(&val, buf, BYTE_SIZE))
			return -EFAULT;

		vfio_ub_iowrite8(vdev, val, io + off);
	} else {
		vfio_ub_ioread8(vdev, &val, io + off);
		if (copy_to_user(buf, &val, BYTE_SIZE))
			return -EFAULT;
	}

	return 0;
}

static size_t cal_io_rw_cnt(struct vfio_ub_core_device *vdev, int res, loff_t off, size_t count)
{
	size_t cnt = 0;
	u64 left_start;
	u32 left_size;
	u64 right_start;
	u32 right_size;

	/* Now usi info was installed at resource0 */
	if (res != VFIO_UB_REGION0_INDEX)
		return count;

	if (vdev->usi_vector_offset < vdev->usi_addr_offset) {
		left_start = vdev->usi_vector_offset;
		left_size = vdev->usi_vector_size;
		right_start = vdev->usi_addr_offset;
		right_size = vdev->usi_addr_size;
	} else {
		left_start = vdev->usi_addr_offset;
		left_size = vdev->usi_addr_size;
		right_start = vdev->usi_vector_offset;
		right_size = vdev->usi_vector_size;
	}

	if (off < left_start)
		cnt = min(count, (size_t)(left_start - off));
	else if (off >= left_start + left_size && off < right_start)
		cnt = min(count, (size_t)(right_start - off));
	else if (off >= right_start + right_size)
		cnt = count;

	return cnt;
}

static ssize_t do_io_rw(struct vfio_ub_core_device *vdev, void __iomem *io,
			char __user *buf, int res, loff_t off, size_t count, bool iswrite)
{
	ssize_t done = 0;
	u64 tmp_addr;
	u64 tmp_vec;
	int ret;

	while (count) {
		size_t fillable, filled;

		fillable = cal_io_rw_cnt(vdev, res, off, count);
		if (fillable >= DWORD_SIZE && !(off % DWORD_SIZE)) {
			ret = do_io_rw32(vdev, buf, io, off, iswrite);
			if (ret)
				return ret;

			filled = DWORD_SIZE;
		} else if (fillable >= WORD_SIZE && !(off % WORD_SIZE)) {
			ret = do_io_rw16(vdev, buf, io, off, iswrite);
			if (ret)
				return ret;

			filled = WORD_SIZE;
		} else if (fillable) {
			ret = do_io_rw8(vdev, buf, io, off, iswrite);
			if (ret)
				return ret;

			filled = BYTE_SIZE;
		} else {
			tmp_vec = vdev->usi_vector_offset + vdev->usi_vector_size;
			tmp_addr = vdev->usi_addr_offset + vdev->usi_addr_size;
			if (off >= vdev->usi_vector_offset && off < tmp_vec)
				filled = min(count, (size_t)(tmp_vec - off));
			else if (off >= vdev->usi_addr_offset && off < tmp_addr)
				filled = min(count, (size_t)(tmp_addr - off));
			else
				return -EFAULT;

			if (!iswrite) {
				u8 val = 0xff;

				for (size_t i = 0; i < filled; i++) {
					if (copy_to_user(buf + i, &val, 1))
						return -EFAULT;
				}
			}
		}

		count -= filled;
		done += filled;
		off += filled;
		buf += filled;
	}

	return done;
}

ssize_t vfio_ub_res_rw(struct vfio_ub_core_device *vdev, char __user *buf,
		       size_t count, loff_t *ppos, bool iswrite)
{
	struct ub_entity *uent = vdev->uent;
	loff_t pos = *ppos & VFIO_UB_OFFSET_MASK;
	int res = VFIO_UB_OFFSET_TO_INDEX(*ppos);
	resource_size_t end;
	void __iomem *io_addr;
	int ret;
	ssize_t done;

	if (ub_resource_start(uent, res))
		end = ub_resource_len(uent, res);
	else
		return -EINVAL;

	if (pos >= end)
		return -EINVAL;

	count = min(count, (size_t)(end - pos));

	ret = vfio_ub_setup_resmap(vdev, res);
	if (ret)
		return ret;

	io_addr = vdev->resmap[res];

	done = do_io_rw(vdev, io_addr, buf, res, pos, count, iswrite);
	if (done > 0)
		*ppos += done;

	return done;
}
