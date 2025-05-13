/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __COUNTERS_H__
#define __COUNTERS_H__

#define STRING_LEN		32
#define XSC_DECLARE_STAT(type, fld)	""#fld, offsetof(type, fld)

struct counter_desc {
	char		format[STRING_LEN];
	size_t		offset; /* Byte offset */
};

struct xsc_counters_attribute {
	struct attribute    attr;
	ssize_t (*show)(struct kobject *kobj,
			struct attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *kobj,
			 struct attribute *attr, const char *buf,
			 size_t count);
	struct xsc_core_device *dev;
};

struct xsc_counters_bin_attribute {
	struct attribute	attr;
	size_t			size;
	void			*private;
	ssize_t (*read)(struct file *f, struct kobject *k, struct bin_attribute *bin_attr,
			char *buf, loff_t l, size_t s);
	ssize_t (*write)(struct file *f, struct kobject *k, struct bin_attribute *bin_attr,
			 char *buf, loff_t l, size_t s);
	int (*mmap)(struct file *f, struct kobject *k, struct bin_attribute *bin_attr,
		    struct vm_area_struct *vma);
};

struct xsc_global_cnt_interface {
	struct xsc_core_device  *xdev;
	struct kobject		kobj;
};

struct xsc_global_cnt_attributes {
	struct attribute attr;
	ssize_t (*show)(struct xsc_global_cnt_interface *g, struct xsc_global_cnt_attributes *a,
			char *buf);
	ssize_t (*store)(struct xsc_global_cnt_interface *g, struct xsc_global_cnt_attributes *a,
			 const char *buf, size_t count);
};

#endif
