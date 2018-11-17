/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef __VFIO_SPIMDEV_H
#define __VFIO_SPIMDEV_H

#include <linux/device.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <uapi/linux/vfio_spimdev.h>

struct vfio_spimdev_queue;
struct vfio_spimdev;

/**
 * struct vfio_spimdev_ops - WD device operations
 * @get_queue: get a queue from the device according to algorithm
 * @put_queue: free a queue to the device
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @reset: reset the WD device
 * @reset_queue: reset the queue
 * @ioctl:   ioctl for user space users of the queue
 * @get_available_instances: get numbers of the queue remained
 */
struct vfio_spimdev_ops {
	int (*get_queue)(struct vfio_spimdev *spimdev, const char *alg,
			 struct vfio_spimdev_queue **q);
	int (*put_queue)(struct vfio_spimdev_queue *q);
	int (*is_q_updated)(struct vfio_spimdev_queue *q);
	void (*mask_notify)(struct vfio_spimdev_queue *q, int event_mask);
	int (*mmap)(struct vfio_spimdev_queue *q, struct vm_area_struct *vma);
	int (*reset)(struct vfio_spimdev *spimdev);
	int (*reset_queue)(struct vfio_spimdev_queue *q);
	long (*ioctl)(struct vfio_spimdev_queue *q, unsigned int cmd,
		      unsigned long arg);
	int (*get_available_instances)(struct vfio_spimdev *spimdev);
};

struct vfio_spimdev_queue {
	struct mutex mutex;
	struct vfio_spimdev *spimdev;
	int qid;
	__u32 flags;
	void *priv;
	const char *alg;
	wait_queue_head_t wait;
	struct mdev_device *mdev;
	int fd;
	int container;
#ifdef CONFIG_IOMMU_SVA
	int pasid;
#endif
};

/**
 * struct vfio_spimdev - Warpdrive device description
 * @name:  device name
 * @status:  device status
 * @ref:  referrence count
 * @owner: module owner
 * @ops:  wd device operations
 * @dev:  its kernel device
 * @cls_dev:  its class device
 * @is_vf:  denotes wether it is virtual function
 * @iommu_type:  iommu type of hardware
 * @dev_id:   device ID
 * @priv: driver private data
 * @mstate: for the mdev state
 * @node_id: socket ID
 * @priority: priority while being selected, also can be set by users
 * @latency: latency while doing acceleration
 * @throughput: throughput while doing acceleration
 * @flags: device attributions
 * @api_ver: API version of WD
 * @mdev_fops: mediated device's parent operations
 */
struct vfio_spimdev {
	const char *name;
	int status;
	atomic_t ref;
	struct module *owner;
	const struct vfio_spimdev_ops *ops;
	struct device *dev;
	struct device cls_dev;
	bool is_vf;
	u32 iommu_type;
	u32 dma_flag;
	u32 node_id;
	u32 priority;
	u32 dev_id;
	void *priv;
	void *mstate;
	int flags;
	const char *api_ver;
	struct mdev_parent_ops mdev_fops;
};

int vfio_spimdev_register(struct vfio_spimdev *spimdev);
void vfio_spimdev_unregister(struct vfio_spimdev *spimdev);
void vfio_spimdev_wake_up(struct vfio_spimdev_queue *q);
int vfio_spimdev_is_spimdev(struct device *dev);
struct vfio_spimdev *vfio_spimdev_pdev_spimdev(struct device *dev);
struct vfio_spimdev *mdev_spimdev(struct mdev_device *mdev);

extern struct mdev_type_attribute mdev_type_attr_type;
extern struct mdev_type_attribute mdev_type_attr_device_api;
extern struct mdev_type_attribute mdev_type_attr_available_instances;
extern struct device_attribute dev_attr_pid;


#define VFIO_SPIMDEV_MAX_TYPES			(32)

/* VFIO_SPIMDEV queue attribution flags */

/* Different queue support the same algorithm */
#define VFIO_SPIMDEV_SAME_ALG_QFLG		(1 << 0)

/* Different queue only support different algorithm */
#define VFIO_SPIMDEV_DIFF_ALG_QFLG		(1 << 1)


#define _VFIO_SPIMDEV_REGION(vm_pgoff)	(vm_pgoff & 0xf)

#endif
