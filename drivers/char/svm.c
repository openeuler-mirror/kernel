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
#ifdef CONFIG_ACPI
#include <linux/acpi.h>
#endif

#define SVM_DEVICE_NAME "svm"

#ifndef CONFIG_ACPI
static int probe_index;
#endif

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

#ifdef CONFIG_ACPI
static int svm_init_core(struct svm_device *sdev)
{
	/*TODO init hi1910 and hi1980 cores for ai*/
	return 0;
}
#else
static int svm_init_core(struct svm_device *sdev, struct device_node *np)
{
	/*TODO*/
	return 0;
}
#endif
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
	int err = -1;
	struct device *dev = &pdev->dev;
	struct svm_device *sdev = NULL;
#ifndef CONFIG_ACPI
	struct device_node *np = dev->of_node;
	int alias_id;

	if (np == NULL)
		return -ENODEV;
#endif

	if (!dev->bus->iommu_ops) {
		dev_dbg(dev, "defer probe svm device\n");
		return -EPROBE_DEFER;
	}

	sdev = devm_kzalloc(dev, sizeof(*sdev), GFP_KERNEL);
	if (sdev == NULL)
		return -ENOMEM;

#ifdef CONFIG_ACPI
	err = device_property_read_u64(dev, "svmid", &sdev->id);
	if (err) {
		dev_err(dev, "failed to get this svm device id\n");
		return err;
	}
#else
	alias_id = of_alias_get_id(np, "svm");
	if (alias_id < 0)
		sdev->id = probe_index;
	else
		sdev->id = alias_id;
#endif

	sdev->dev = dev;
	sdev->miscdev.minor = MISC_DYNAMIC_MINOR;
	sdev->miscdev.fops = &svm_fops;
	sdev->miscdev.name = devm_kasprintf(dev, GFP_KERNEL,
			SVM_DEVICE_NAME"%llu", sdev->id);
	if (sdev->miscdev.name == NULL)
		err = -ENOMEM;

	dev_set_drvdata(dev, sdev);
	err = misc_register(&sdev->miscdev);
	if (err) {
		dev_err(dev, "Unable to register misc device\n");
		return err;
	}
#ifdef CONFIG_ACPI
	err = svm_init_core(sdev);
#else
	err = svm_init_core(sdev, np);
#endif

	if (err) {
		dev_err(dev, "failed to init cores\n");
		goto err_unregister_misc;
	}

#ifndef CONFIG_ACPI
	probe_index++;
#endif

	return err;

err_unregister_misc:
	misc_deregister(&sdev->miscdev);

	return err;
}
/*svm device remove this is device remove*/
static int svm_device_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct svm_device *sdev = dev_get_drvdata(dev);

	misc_deregister(&sdev->miscdev);

	return 0;
}

#ifdef CONFIG_ACPI
static const struct acpi_device_id svm_acpi_match[] = {
	{ "HSVM1980", 0},
	{ }
};
MODULE_DEVICE_TABLE(acpi, svm_acpi_match);
#else
static const struct of_device_id svm_of_match[] = {
	{ .compatible = "hisilicon,svm" },
	{ }
};
MODULE_DEVICE_TABLE(of, svm_of_match);
#endif

/*svm acpi probe and remove*/
static struct platform_driver svm_driver = {
	.probe	=	svm_device_probe,
	.remove	=	svm_device_remove,
	.driver	=	{
		.name = SVM_DEVICE_NAME,
#ifdef CONFIG_ACPI
		.acpi_match_table = ACPI_PTR(svm_acpi_match),
#else
		.of_match_table = svm_of_match,
#endif
	},
};

module_platform_driver(svm_driver);

MODULE_DESCRIPTION("Hisilicon SVM driver");
MODULE_AUTHOR("JianKang Chen <chenjiankang1@huawei.com>");
MODULE_LICENSE("GPL v2");
