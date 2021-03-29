// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009 Nationz Technologies Inc.
 *
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/io.h>

struct device;
struct tcm_chip;

enum tcm_timeout {
	TCM_TIMEOUT = 5,
};

/* TCM addresses */
enum tcm_addr {
	TCM_SUPERIO_ADDR = 0x2E,
	TCM_ADDR = 0x4E,
};

extern ssize_t tcm_show_pubek(struct device *, struct device_attribute *attr,
				char *);
extern ssize_t tcm_show_pcrs(struct device *, struct device_attribute *attr,
				char *);
extern ssize_t tcm_show_caps(struct device *, struct device_attribute *attr,
				char *);
extern ssize_t tcm_store_cancel(struct device *, struct device_attribute *attr,
				const char *, size_t);
extern ssize_t tcm_show_enabled(struct device *, struct device_attribute *attr,
				char *);
extern ssize_t tcm_show_active(struct device *, struct device_attribute *attr,
				char *);
extern ssize_t tcm_show_owned(struct device *, struct device_attribute *attr,
				char *);
extern ssize_t tcm_show_temp_deactivated(struct device *,
					 struct device_attribute *attr, char *);

struct tcm_vendor_specific {
	const u8 req_complete_mask;
	const u8 req_complete_val;
	const u8 req_canceled;
	void __iomem *iobase;		/* ioremapped address */
	void __iomem *iolbc;
	unsigned long base;		/* TCM base address */

	int irq;

	int region_size;
	int have_region;

	int (*recv)(struct tcm_chip *, u8 *, size_t);
	int (*send)(struct tcm_chip *, u8 *, size_t);
	void (*cancel)(struct tcm_chip *);
	u8 (*status)(struct tcm_chip *);
	struct miscdevice miscdev;
	struct attribute_group *attr_group;
	struct list_head list;
	int locality;
	unsigned long timeout_a, timeout_b, timeout_c, timeout_d; /* jiffies */
	unsigned long duration[3]; /* jiffies */

	wait_queue_head_t read_queue;
	wait_queue_head_t int_queue;
};

struct tcm_chip {
	struct device *dev;	/* Device stuff */

	int dev_num;		/* /dev/tcm# */
	int num_opens;		/* only one allowed */
	int time_expired;

	/* Data passed to and from the tcm via the read/write calls */
	u8 *data_buffer;
	atomic_t data_pending;
	struct mutex buffer_mutex;

	struct timer_list user_read_timer;	/* user needs to claim result */
	struct work_struct work;
	struct mutex tcm_mutex;	       /* tcm is processing */

	struct tcm_vendor_specific vendor;

	struct dentry **bios_dir;

	struct list_head list;
};

#define to_tcm_chip(n) container_of(n, struct tcm_chip, vendor)

static inline int tcm_read_index(int base, int index)
{
	outb(index, base);
	return inb(base+1) & 0xFF;
}

static inline void tcm_write_index(int base, int index, int value)
{
	outb(index, base);
	outb(value & 0xFF, base+1);
}
extern void tcm_startup(struct tcm_chip *);
extern void tcm_get_timeouts(struct tcm_chip *);
extern unsigned long tcm_calc_ordinal_duration(struct tcm_chip *, u32);
extern struct tcm_chip *tcm_register_hardware(struct device *,
				 const struct tcm_vendor_specific *);
extern int tcm_open(struct inode *, struct file *);
extern int tcm_release(struct inode *, struct file *);
extern ssize_t tcm_write(struct file *, const char __user *, size_t,
			 loff_t *);
extern ssize_t tcm_read(struct file *, char __user *, size_t, loff_t *);
extern void tcm_remove_hardware(struct device *);
extern int tcm_pm_suspend(struct device *, pm_message_t);
extern int tcm_pm_suspend_p(struct device *);
extern int tcm_pm_resume(struct device *);
