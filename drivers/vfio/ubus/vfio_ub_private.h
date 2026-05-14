/* SPDX-License-Identifier: GPL-2.0+ */
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
#ifndef __VFIO_UB_PRIVATE_H__
#define __VFIO_UB_PRIVATE_H__

#include <uapi/ub/ubus/ubus_regs.h>
#include <linux/irqbypass.h>
#include <ub/ubus/ubus.h>

#define UB_CFG0_MAX_CAP 255
#define UB_CFG1_MAX_CAP 511 /* cfg1 cap start from 256 */

struct vfio_ub_irq_ctx {
	struct eventfd_ctx *trigger;
	char *name;
	bool masked;
	struct irq_bypass_producer producer;
};

struct vfio_ub_core_device;
struct perm_bits {
	u8 *virt;
	u8 *write;
	u8 *entnro;
	u8 *ent0eo;
	u8 *exist;
	int (*readfn)(struct vfio_ub_core_device *vdev, u64 pos, int count,
		      __le32 *val);
	int (*writefn)(struct vfio_ub_core_device *vdev, u64 pos, int count,
		       __le32 val);
};

struct vfio_ub_slice {
	u8 *cfg;
	u32 cap_id;
	int used_size;
};

struct vfio_ub_config {
	struct vfio_ub_slice *slice;
	int nums;
	u8 final_slice_supported[UB_CFG1_MAX_CAP + 1]; /* do not incude port basic && port cap */
	int map[UB_CFG1_MAX_CAP + 1];
};

struct vfio_ub_core_device {
	struct vfio_device vdev;
	struct ub_entity *uent;
	struct vfio_ub_config vconfig;
	void __iomem *resmap[MAX_UB_RES_NUM];
	int num_ctx; /* num of enabled irqs */
	int irq_type; /* interrupt type of this uent */
	struct vfio_ub_irq_ctx *ctx;
	int num_regions; /* vfio-ub additional regions */
	int num_ext_irqs; /* vfio-ub additional extended irqs */
	int num_vendor_regions; /* vfio-ub additional vendor-defined regions */
	int num_vendor_irqs; /* vfio-ub additional vendor-defined irqs */
	bool reset_works; /* vfio-ub support reset flag */
	u64 usi_vector_offset;
	u32 usi_vector_size;
	u64 usi_addr_offset;
	u32 usi_addr_size;
	struct eventfd_ctx *req_trigger;
	struct eventfd_ctx *reinit_trigger;
	struct mutex igate;
};

#define VFIO_UB_OFFSET_SHIFT 40
#define VFIO_UB_OFFSET_TO_INDEX(off) ((off) >> VFIO_UB_OFFSET_SHIFT)
#define VFIO_UB_INDEX_TO_OFFSET(index) ((u64)(index) << VFIO_UB_OFFSET_SHIFT)
#define VFIO_UB_OFFSET_MASK (((u64)(1) << VFIO_UB_OFFSET_SHIFT) - 1)

#define irq_is(vdev, type) ((vdev)->irq_type == (type))
#define BYTE_SIZE 1
#define WORD_SIZE 2
#define DWORD_SIZE 4
#define DWORD_BITS 32
#define BYTE_BITS 8

int vfio_ub_init_perm_bits(void);
void vfio_ub_uninit_perm_bits(void);
int vfio_ub_config_init(struct vfio_ub_core_device *vdev);
void vfio_ub_config_uninit(struct vfio_ub_core_device *vdev);
ssize_t vfio_ub_config_rw(struct vfio_ub_core_device *vdev, char __user *buf,
			  size_t count, loff_t *ppos, bool iswrite);
ssize_t vfio_ub_res_rw(struct vfio_ub_core_device *vdev, char __user *buf,
		       size_t count, loff_t *ppos, bool iswrite);
int vfio_ub_set_irqs_ioctl(struct vfio_ub_core_device *vdev, uint32_t flags,
			   unsigned int index, unsigned int start,
			   unsigned int count, void *data);
int vfio_ub_core_register_device(struct vfio_ub_core_device *vdev);
void vfio_ub_core_unregister_device(struct vfio_ub_core_device *vdev);
int vfio_ub_core_open_device(struct vfio_device *core_vdev);
void vfio_ub_core_close_device(struct vfio_device *core_vdev);
long vfio_ub_core_ioctl(struct vfio_device *core_vdev, unsigned int cmd, unsigned long arg);
ssize_t vfio_ub_core_write(struct vfio_device *core_vdev, const char __user *buf,
			   size_t count, loff_t *ppos);
ssize_t vfio_ub_core_read(struct vfio_device *core_vdev, char __user *buf, size_t count,
			  loff_t *ppos);
int vfio_ub_core_mmap(struct vfio_device *core_vdev, struct vm_area_struct *vma);
int vfio_ub_core_init_dev(struct vfio_device *core_vdev);
void vfio_ub_core_release_dev(struct vfio_device *core_dev);
void vfio_ub_core_request(struct vfio_device *core_vdev, unsigned int count);
void vfio_ub_core_disable_all(struct vfio_ub_core_device *vdev);
int vfio_ub_iommufd_physical_attach_ioas(struct vfio_device *vdev, u32 *pt_id);
void vfio_ub_iommufd_physical_detach_ioas(struct vfio_device *vdev);
void vfio_ub_iommufd_physical_unbind(struct vfio_device *core_vdev);
void vfio_ub_unset_resmap(struct vfio_ub_core_device *vdev);

#endif /* __VFIO_UB_PRIVATE_H__ */
