/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2018-2019 HiSilicon Limited. */
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

#define UACCE_QFRF_MMAP		BIT(0)	/* map to user space */
#define UACCE_QFRF_DMA		BIT(1)	/* use dma api for the region */
#define UACCE_QFRF_SELFMT	BIT(2)	/* self maintained qfr */

struct uacce_hw_err {
	struct list_head list;
	unsigned long long tick_stamp;
};

struct uacce_err_isolate {
	struct list_head hw_errs;
	u32 hw_err_isolate_hz;	/* user cfg freq which triggers isolation */
	atomic_t is_isolate;
};

struct uacce_dma_slice {
	void *kaddr;	/* kernel address for ss */
	dma_addr_t dma;	/* dma address, if created by dma api */
	u32 size;	/* Size of this dma slice */
	u32 total_num;	/* Total slices in this dma list */
};

struct uacce_qfile_region {
	enum uacce_qfrt type;
	unsigned long iova;	/* iova share between user and device space */
	unsigned long nr_pages;
	int prot;
	unsigned int flags;
	struct list_head qs;	/* qs sharing the same region, for ss */
	void *kaddr;		/* kernel address for dko */
	struct uacce_dma_slice *dma_list;
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
	enum uacce_dev_state (*get_dev_state)(struct uacce *uacce);
};

enum uacce_dev_state {
	UACCE_DEV_ERR = -1,
	UACCE_DEV_NORMAL,
};

enum uacce_q_state {
	UACCE_Q_INIT,
	UACCE_Q_STARTED,
	UACCE_Q_ZOMBIE,
	UACCE_Q_CLOSED,
};

struct uacce_queue {
	struct uacce *uacce;
	__u32 flags;
	atomic_t status;
	void *priv;
	wait_queue_head_t wait;
	int pasid;
	struct list_head list; /* as list for as->qs */
	struct mm_struct *mm;
	struct uacce_qfile_region *qfrs[UACCE_QFRT_MAX];
	struct fasync_struct *async_queue;
	struct file *filep;
	enum uacce_q_state state;
};

struct uacce {
	const char *name;
	const char *drv_name;
	const char *algs;
	const char *api_ver;
	unsigned long qf_pg_start[UACCE_QFRT_MAX];
	int status;
	unsigned int flags;
	struct uacce_ops *ops;
	struct device *pdev;
	bool is_vf;
	u32 dev_id;
	struct cdev cdev;
	struct device dev;
	void *priv;
	atomic_t ref;
	int prot;
	struct uacce_err_isolate isolate_data;
	struct uacce_err_isolate *isolate;
};

int uacce_register(struct uacce *uacce);
int uacce_unregister(struct uacce *uacce);
void uacce_wake_up(struct uacce_queue *q);
const char *uacce_qfrt_str(struct uacce_qfile_region *qfr);
struct uacce *dev_to_uacce(struct device *dev);
int uacce_hw_err_isolate(struct uacce *uacce);

#endif
