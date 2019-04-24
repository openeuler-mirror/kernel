/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __UACCE_H
#define __UACCE_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include <uapi/linux/uacce.h>

struct uacce_queue;
struct uacce;

#define UACCE_QFRF_MAP		BIT(0)	/* map to current queue */
#define UACCE_QFRF_MMAP		BIT(1)	/* map to user space */
#define UACCE_QFRF_KMAP		BIT(2)	/* map to kernel space */
#define UACCE_QFRF_DMA		BIT(3)	/* use dma api for the region */
#define UACCE_QFRF_SELFMT	BIT(4)	/* self maintained qfr */

struct uacce_qfile_region {
	enum uacce_qfrt type;
	unsigned long iova;	/* iova share between user and device space */
	struct page **pages;
	unsigned int nr_pages;
	int prot;
	unsigned int flags;
	struct list_head qs;	/* qs sharing the same region, for ss */
	void *kaddr;		/* kernel addr, for dko */
	dma_addr_t dma;		/* dma address, if created by dma api */
};

/**
 * struct uacce_ops - WD device operations
 * @get_queue: get a queue from the device according to algorithm
 * @put_queue: free a queue to the device
 * @start_queue: make the queue start work after get_queue
 * @stop_queue: make the queue stop work before put_queue
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @reset: reset the WD device
 * @reset_queue: reset the queue
 * @ioctl:   ioctl for user space users of the queue
 */
struct uacce_ops {
	int (*get_available_instances)(struct uacce *uacce);
	int (*get_queue)(struct uacce *uacce, unsigned long arg,
			struct uacce_queue **q);
	void (*put_queue)(struct uacce_queue *q);
	int (*start_queue)(struct uacce_queue *q);
	void (*stop_queue)(struct uacce_queue *q);
	int (*is_q_updated)(struct uacce_queue *q);
	void (*mask_notify)(struct uacce_queue *q, int event_mask);
	int (*mmap)(struct uacce_queue *q, struct vm_area_struct *vma,
			struct uacce_qfile_region *qfr);
	int (*reset)(struct uacce *uacce);
	int (*reset_queue)(struct uacce_queue *q);
	long (*ioctl)(struct uacce_queue *q, unsigned int cmd,
		       unsigned long arg);
};

struct uacce_queue {
	struct uacce *uacce;
	__u32 flags;
	void *priv;
	wait_queue_head_t wait;
	int pasid;

	struct list_head list;	/* as list for as->qs */

	struct mm_struct *mm;

	struct uacce_qfile_region *qfrs[UACCE_QFRT_MAX];

	struct fasync_struct *async_queue;
	struct list_head q_dev;
};

#define UACCE_ST_INIT		0
#define UACCE_ST_OPENNED	1
#define UACCE_ST_STARTED	2
#define UACCE_ST_RST		3

struct uacce {
	const char *name;
	const char *drv_name;
	const char *algs;
	const char *api_ver;
	unsigned int flags;
	unsigned long qf_pg_start[UACCE_QFRT_MAX];
	int status;
	struct uacce_ops *ops;
	struct device *pdev;
	bool is_vf;
	u32 dev_id;
	struct cdev cdev;
	struct device dev;
	void *priv;
	atomic_t state;
	atomic_t ref;
	int prot;
	struct mutex q_lock;
	struct list_head qs;
};

int uacce_register(struct uacce *uacce);
void uacce_unregister(struct uacce *uacce);
void uacce_wake_up(struct uacce_queue *q);
void uacce_reset_prepare(struct uacce *uacce);
void uacce_reset_done(struct uacce *uacce);
const char *uacce_qfrt_str(struct uacce_qfile_region *qfr);

#endif
