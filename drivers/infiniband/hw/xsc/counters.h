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
	int     id;
	struct xsc_core_device *dev;
	const struct counter_desc *desc;
	int desc_size;
};

struct xsc_counters_bin_attribute {
	struct attribute  attr;
	ssize_t (*read)(struct file *file,
			struct kobject *kobj,
			struct bin_attribute *bin_attr,
			char *buf, loff_t off, size_t size);
	ssize_t (*write)(struct file *file,
			 struct kobject *kobj,
			 struct bin_attribute *bin_attr,
			 char *buf, loff_t off, size_t size);
	int (*mmap)(struct file *file,
		    struct kobject *kobj,
		    struct bin_attribute *attr,
		    struct vm_area_struct *vma);
	int    id;
	struct xsc_core_device *dev;
	const struct counter_desc *desc;
	int desc_size;
	size_t    size;
};

ssize_t counters_vf_names_show(struct kobject *kobjs,
			       struct attribute *attr, char *buf);

ssize_t counters_vf_value_read(struct file *file,
			       struct kobject *kob,
			       struct bin_attribute *bin_attr,
			       char *buf, loff_t loff, size_t size);

ssize_t counters_vf_show(struct kobject *kobjs,
			 struct attribute *attr, char *buf);

#endif
