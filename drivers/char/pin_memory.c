// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * Pin memory driver for checkpoint and restore.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/processor.h>
#include <uapi/asm-generic/ioctl.h>
#include <uapi/asm-generic/mman-common.h>
#include <uapi/asm/setup.h>
#include <linux/pin_mem.h>
#include <linux/sched/mm.h>

#define MAX_PIN_MEM_AREA_NUM  16
struct _pin_mem_area {
	unsigned long virt_start;
	unsigned long virt_end;
};

struct pin_mem_area_set {
	unsigned int pid;
	unsigned int area_num;
	struct _pin_mem_area mem_area[MAX_PIN_MEM_AREA_NUM];
};

#define PIN_MEM_MAGIC 0x59
#define _SET_PIN_MEM_AREA    1
#define _CLEAR_PIN_MEM_AREA  2
#define _REMAP_PIN_MEM_AREA  3
#define _FINISH_PIN_MEM_DUMP 4
#define _INIT_PAGEMAP_READ   5
#define _PIN_MEM_IOC_MAX_NR  5
#define SET_PIN_MEM_AREA        _IOW(PIN_MEM_MAGIC, _SET_PIN_MEM_AREA, struct pin_mem_area_set)
#define CLEAR_PIN_MEM_AREA      _IOW(PIN_MEM_MAGIC, _CLEAR_PIN_MEM_AREA, int)
#define REMAP_PIN_MEM_AREA      _IOW(PIN_MEM_MAGIC, _REMAP_PIN_MEM_AREA, int)
#define FINISH_PIN_MEM_DUMP     _IOW(PIN_MEM_MAGIC, _FINISH_PIN_MEM_DUMP, int)
#define INIT_PAGEMAP_READ       _IOW(PIN_MEM_MAGIC, _INIT_PAGEMAP_READ, int)
static int set_pin_mem(struct pin_mem_area_set *pmas)
{
	int i;
	int ret = 0;
	struct _pin_mem_area *pma;
	struct mm_struct *mm;
	struct task_struct *task;
	struct pid *pid_s;

	pid_s = find_get_pid(pmas->pid);
	if (!pid_s) {
		pr_warn("Get pid struct fail:%d.\n", pmas->pid);
		return -EFAULT;
	}
	rcu_read_lock();
	task = pid_task(pid_s, PIDTYPE_PID);
	if (!task) {
		pr_warn("Get task struct fail:%d.\n", pmas->pid);
		goto fail;
	}
	mm = get_task_mm(task);
	for (i = 0; i < pmas->area_num; i++) {
		pma = &(pmas->mem_area[i]);
		ret = pin_mem_area(task, mm, pma->virt_start, pma->virt_end);
		if (ret) {
			mmput(mm);
			goto fail;
		}
	}
	mmput(mm);
	rcu_read_unlock();
	put_pid(pid_s);
	return ret;

fail:
	rcu_read_unlock();
	put_pid(pid_s);
	return -EFAULT;
}

static int set_pin_mem_area(unsigned long arg)
{
	struct pin_mem_area_set pmas;
	void __user *buf = (void __user *)arg;

	if (!access_ok(buf, sizeof(pmas)))
		return -EFAULT;
	if (copy_from_user(&pmas, buf, sizeof(pmas)))
		return -EINVAL;
	if (pmas.area_num > MAX_PIN_MEM_AREA_NUM) {
		pr_warn("Input area_num is too large.\n");
		return -EINVAL;
	}

	return set_pin_mem(&pmas);
}

static int pin_mem_remap(unsigned long arg)
{
	int pid;
	struct task_struct *task;
	struct mm_struct *mm;
	vm_fault_t ret;
	void __user *buf = (void __user *)arg;
	struct pid *pid_s;

	if (!access_ok(buf, sizeof(int)))
		return -EINVAL;
	if (copy_from_user(&pid, buf, sizeof(int)))
		return -EINVAL;

	pid_s = find_get_pid(pid);
	if (!pid_s) {
		pr_warn("Get pid struct fail:%d.\n", pid);
		return -EINVAL;
	}
	rcu_read_lock();
	task = pid_task(pid_s, PIDTYPE_PID);
	if (!task) {
		pr_warn("Get task struct fail:%d.\n", pid);
		goto fault;
	}
	mm = get_task_mm(task);
	ret = do_mem_remap(pid, mm);
	if (ret) {
		pr_warn("Handle pin memory remap fail.\n");
		mmput(mm);
		goto fault;
	}
	mmput(mm);
	rcu_read_unlock();
	put_pid(pid_s);
	return 0;

fault:
	rcu_read_unlock();
	put_pid(pid_s);
	return -EFAULT;
}

static long pin_memory_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;

	if (_IOC_TYPE(cmd) != PIN_MEM_MAGIC)
		return -EINVAL;
	if (_IOC_NR(cmd) > _PIN_MEM_IOC_MAX_NR)
		return -EINVAL;

	switch (cmd) {
	case SET_PIN_MEM_AREA:
		ret = set_pin_mem_area(arg);
		break;
	case CLEAR_PIN_MEM_AREA:
		clear_pin_memory_record();
		break;
	case REMAP_PIN_MEM_AREA:
		ret = pin_mem_remap(arg);
		break;
	case FINISH_PIN_MEM_DUMP:
		ret = finish_pin_mem_dump();
		break;
	case INIT_PAGEMAP_READ:
		ret = init_pagemap_read();
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static const struct file_operations pin_memory_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = pin_memory_ioctl,
	.compat_ioctl   = pin_memory_ioctl,
};

static struct miscdevice pin_memory_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "pinmem",
	.fops	= &pin_memory_fops,
};

static int pin_memory_init(void)
{
	int err = misc_register(&pin_memory_miscdev);

	if (!err)
		pr_info("pin_memory init\n");
	else
		pr_warn("pin_memory init failed!\n");
	return err;
}

static void pin_memory_exit(void)
{
	misc_deregister(&pin_memory_miscdev);
	pr_info("pin_memory ko exists!\n");
}

module_init(pin_memory_init);
module_exit(pin_memory_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Euler");
MODULE_DESCRIPTION("pin memory");
