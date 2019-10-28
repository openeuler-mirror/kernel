// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2017-2018 Hisilicon Limited.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/esr.h>
#include <linux/mmu_context.h>

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/miscdevice.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/hugetlb.h>
#include <linux/sched/mm.h>
#include <linux/msi.h>
#include <linux/acpi.h>

#define SVM_DEVICE_NAME "svm"

struct core_device {
	struct device		dev;
	struct iommu_group      *group;
	struct iommu_domain     *domain;
	bool			smmu_bypass;
};

struct svm_device {
	unsigned long long	id;
	struct miscdevice	miscdev;
	struct device		*dev;
	phys_addr_t l2buff;
	unsigned long		l2size;
};

struct svm_bind_process {
	pid_t			vpid;
	u64			ttbr;
	u64			tcr;
	int			pasid;
	u32			flags;
#define SVM_BIND_PID		(1 << 0)
};

struct svm_process {
	struct pid		*pid;
	struct mm_struct	*mm;
	unsigned long		asid;
	struct kref		kref;
	struct rb_node		rb_node;
	struct mmu_notifier	notifier;
	/* For postponed release */
	struct rcu_head		rcu;
	struct list_head	contexts;
	int			pasid;
	struct mutex		mutex;
	struct rb_root		sdma_list;
};

/* keep the relationship of svm_process and svm_device */
struct svm_context {
	struct svm_process	*process;
	struct svm_device	*sdev;
	struct list_head	process_head;
	atomic_t		ref;
};

static int svm_open(struct inode *inode, struct file *file)
{
	return 0;
}

/*svm ioctl will include some case for HI1980 and HI1910*/
static long svm_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	/*TODO add svm ioctl*/
		return 0;
}

static const struct file_operations svm_fops = {
	.owner			= THIS_MODULE,
	.open			= svm_open,
	.unlocked_ioctl		= svm_ioctl,
};
/*svm device probe this is init the svm device*/
static int svm_device_probe(struct platform_device *pdev)
{
	/*TODO svm device init*/
	return 0;
}
/*svm device remove this is device remove*/
static int svm_device_remove(struct platform_device *pdev)
{
	/*TODO svm device remove*/
	return 0;
}

static const struct acpi_device_id svm_acpi_match[] = {
	{ "HSVM1980", 0},
	{ }
};
MODULE_DEVICE_TABLE(acpi, svm_acpi_match);
/*svm acpi probe and remove*/
static struct platform_driver svm_driver = {
	.probe	=	svm_device_probe,
	.remove	=	svm_device_remove,
	.driver	=	{
		.name = SVM_DEVICE_NAME,
		.acpi_match_table = ACPI_PTR(svm_acpi_match),
	},
};

module_platform_driver(svm_driver);

MODULE_DESCRIPTION("Hisilicon SVM driver");
MODULE_AUTHOR("JianKang Chen <chenjiankang1@huawei.com>");
MODULE_LICENSE("GPL v2");
