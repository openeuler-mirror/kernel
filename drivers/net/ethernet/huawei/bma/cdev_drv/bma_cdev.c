// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include "../edma_drv/bma_include.h"
#include "../include/bma_ker_intf.h"

#define CDEV_NAME_PREFIX	"hwibmc"

#ifdef DRV_VERSION
#define CDEV_VERSION		MICRO_TO_STR(DRV_VERSION)
#else
#define CDEV_VERSION		"0.3.6"
#endif

#define CDEV_DEFAULT_NUM	4
#define CDEV_MAX_NUM		8

#define CDEV_NAME_MAX_LEN	32
#define CDEV_INVALID_ID		(0xffffffff)

struct cdev_statistics_s {
	unsigned int recv_bytes;
	unsigned int send_bytes;
	unsigned int send_pkgs;
	unsigned int recv_pkgs;
	unsigned int send_failed_count;
	unsigned int recv_failed_count;
	unsigned int open_status;
};

struct cdev_dev {
	struct miscdevice dev_struct;
	struct cdev_statistics_s s;
	char dev_name[CDEV_NAME_MAX_LEN];
	dev_t dev_id;
	void *dev_data;
	atomic_t open;
	int type;
};

struct cdev_dev_set {
	struct cdev_dev dev_list[CDEV_MAX_NUM];
	int dev_num;
	unsigned int init_time;
};

int dev_num = CDEV_DEFAULT_NUM;	/* the dev num want to create */
int debug = DLOG_ERROR;                  /* debug switch */
module_param(dev_num, int, 0640);
MODULE_PARM_DESC(dev_num, "cdev num you want");
MODULE_PARM_DESC(debug, "Debug switch (0=close debug, 1=open debug)");

#define CDEV_LOG(level, fmt, args...) do {\
	if (debug >= (level)) {\
		netdev_info(0, "edma_cdev: %s, %d, " fmt "\n", \
		__func__, __LINE__, ## args);\
	} \
} while (0)

static int cdev_open(struct inode *inode, struct file *filp);
static int cdev_release(struct inode *inode, struct file *filp);
static unsigned int cdev_poll(struct file *file, poll_table *wait);
static ssize_t cdev_read(struct file *filp, char __user  *data, size_t count,
			 loff_t *ppos);
static ssize_t cdev_write(struct file *filp, const char __user *data,
			  size_t count, loff_t *ppos);

struct cdev_dev_set g_cdev_set;

#define GET_PRIVATE_DATA(f) (((struct cdev_dev *)((f)->private_data))->dev_data)

module_param_call(debug, &edma_param_set_debug, &param_get_int, &debug, 0644);

static int cdev_param_get_statics(char *buf, const struct kernel_param *kp)
{
	int len = 0;
	int i = 0;
	__kernel_time_t running_time = 0;

	if (!buf)
		return 0;

	GET_SYS_SECONDS(running_time);
	running_time -= g_cdev_set.init_time;
	len += sprintf(buf + len,
		       "============================CDEV_DRIVER_INFO=======================\n");
	len += sprintf(buf + len, "version      :%s\n", CDEV_VERSION);

	len += sprintf(buf + len, "running_time :%luD %02lu:%02lu:%02lu\n",
		       running_time / (SECONDS_PER_DAY),
		       running_time % (SECONDS_PER_DAY) / SECONDS_PER_HOUR,
		       running_time % SECONDS_PER_HOUR / SECONDS_PER_MINUTE,
		       running_time % SECONDS_PER_MINUTE);

	for (i = 0; i < g_cdev_set.dev_num; i++) {
		len += sprintf(buf + len,
			       "===================================================\n");
		len += sprintf(buf + len, "name      :%s\n",
			       g_cdev_set.dev_list[i].dev_name);
		len +=
		    sprintf(buf + len, "dev_id    :%08x\n",
			    g_cdev_set.dev_list[i].dev_id);
		len += sprintf(buf + len, "type      :%u\n",
			       g_cdev_set.dev_list[i].type);
		len += sprintf(buf + len, "status    :%s\n",
			       g_cdev_set.dev_list[i].s.open_status ==
			       1 ? "open" : "close");
		len += sprintf(buf + len, "send_pkgs :%u\n",
			       g_cdev_set.dev_list[i].s.send_pkgs);
		len +=
		    sprintf(buf + len, "send_bytes:%u\n",
			    g_cdev_set.dev_list[i].s.send_bytes);
		len += sprintf(buf + len, "send_failed_count:%u\n",
			       g_cdev_set.dev_list[i].s.send_failed_count);
		len += sprintf(buf + len, "recv_pkgs :%u\n",
			       g_cdev_set.dev_list[i].s.recv_pkgs);
		len += sprintf(buf + len, "recv_bytes:%u\n",
			       g_cdev_set.dev_list[i].s.recv_bytes);
		len += sprintf(buf + len, "recv_failed_count:%u\n",
			       g_cdev_set.dev_list[i].s.recv_failed_count);
	}

	return len;
}
module_param_call(statistics, NULL, cdev_param_get_statics, &debug, 0444);
MODULE_PARM_DESC(statistics, "Statistics info of cdev driver,readonly");

const struct file_operations g_bma_cdev_fops = {
	.owner = THIS_MODULE,
	.open = cdev_open,
	.release = cdev_release,
	.poll = cdev_poll,
	.read = cdev_read,
	.write = cdev_write,
};

static int __init bma_cdev_init(void)
{
	int i = 0;

	int ret = 0;
	int err_count = 0;

	if (!bma_intf_check_edma_supported())
		return -ENXIO;

	if (dev_num <= 0 || dev_num > CDEV_MAX_NUM)
		return -EINVAL;

	memset(&g_cdev_set, 0, sizeof(struct cdev_dev_set));
	g_cdev_set.dev_num = dev_num;

	for (i = 0; i < dev_num; i++) {
		struct cdev_dev *pdev = &g_cdev_set.dev_list[i];

		sprintf(pdev->dev_name, "%s%d", CDEV_NAME_PREFIX, i);
		pdev->dev_struct.name = pdev->dev_name;
		pdev->dev_struct.minor = MISC_DYNAMIC_MINOR;
		pdev->dev_struct.fops = &g_bma_cdev_fops;

		pdev->dev_id = CDEV_INVALID_ID;

		ret = misc_register(&pdev->dev_struct);

		if (ret) {
			CDEV_LOG(DLOG_DEBUG, "misc_register failed %d", i);
			err_count++;
			continue;
		}

		pdev->dev_id = MKDEV(MISC_MAJOR, pdev->dev_struct.minor);

		ret = bma_intf_register_type(TYPE_CDEV + i, 0, INTR_DISABLE,
					     &pdev->dev_data);

		if (ret) {
			CDEV_LOG(DLOG_ERROR,
				 "cdev %d open failed ,result = %d",
				 i, ret);
			misc_deregister(&pdev->dev_struct);
			pdev->dev_id = CDEV_INVALID_ID;
			err_count++;
			continue;
		} else {
			pdev->type = TYPE_CDEV + i;
			atomic_set(&pdev->open, 1);
		}

		CDEV_LOG(DLOG_DEBUG, "%s id is %08x", pdev->dev_struct.name,
			 pdev->dev_id);
	}

	if (err_count == dev_num) {
		CDEV_LOG(DLOG_ERROR, "init cdev failed!");
		return -EFAULT;
	}
	GET_SYS_SECONDS(g_cdev_set.init_time);
	return 0;
}

static void __exit bma_cdev_exit(void)
{
	while (dev_num--) {
		struct cdev_dev *pdev = &g_cdev_set.dev_list[dev_num];

		if (pdev->dev_id != CDEV_INVALID_ID) {
			if (pdev->dev_data && pdev->type != 0)
				(void)bma_intf_unregister_type(&pdev->dev_data);

			(void)misc_deregister
				(&g_cdev_set.dev_list[dev_num].dev_struct);
		}
	}
}

int cdev_open(struct inode *inode_prt, struct file *filp)
{
	int i = 0;
	struct cdev_dev *pdev = NULL;

	if (!inode_prt)
		return -EFAULT;
	if (!filp)
		return -EFAULT;

	if (dev_num <= 0) {
		CDEV_LOG(DLOG_ERROR, "dev_num error");
		return -EFAULT;
	}

	for (i = 0; i < dev_num; i++) {
		pdev = &g_cdev_set.dev_list[i];

		if (pdev->dev_id == inode_prt->i_rdev)
			break;
	}

	if (i == dev_num) {
		CDEV_LOG(DLOG_ERROR, "can not find dev id %08x",
			 inode_prt->i_rdev);
		return -ENODEV;
	}
	/*each device can be opened only onece */
	if (atomic_dec_and_test(&pdev->open) == 0) {
		CDEV_LOG(DLOG_ERROR, "%s is already opened",
			 pdev->dev_name);
			atomic_inc(&pdev->open);
			return -EBUSY;	/* already opened */
	}

	filp->private_data = &g_cdev_set.dev_list[i];
	bma_intf_set_open_status(pdev->dev_data, DEV_OPEN);
	((struct cdev_dev *)filp->private_data)->s.open_status++;

	return 0;
}

int cdev_release(struct inode *inode_prt, struct file *filp)
{
	struct cdev_dev *pdev = NULL;

	if (!filp)
		return 0;

	pdev = (struct cdev_dev *)filp->private_data;
	if (pdev) {
		((struct cdev_dev *)filp->private_data)->s.open_status--;
		bma_intf_set_open_status(pdev->dev_data, DEV_CLOSE);
		atomic_inc(&pdev->open);
		filp->private_data = NULL;
	}

	return 0;
}

unsigned int cdev_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	wait_queue_head_t *queue_head = NULL;

	if (!filp)
		return 0;
	queue_head = (wait_queue_head_t *)
	    bma_cdev_get_wait_queue(GET_PRIVATE_DATA(filp));

	if (!queue_head)
		return 0;

	poll_wait(filp, queue_head, wait);

	if (bma_cdev_check_recv(GET_PRIVATE_DATA(filp)))
		mask |= (POLLIN | POLLRDNORM);

	CDEV_LOG(DLOG_DEBUG, "poll return %08x", mask);

	return mask;
}

ssize_t cdev_read(struct file *filp, char __user *data, size_t count,
		  loff_t *ppos)
{
	int ret = 0;

	CDEV_LOG(DLOG_DEBUG, "data is %p,count is %u", data,
		 (unsigned int)count);

	if (!data || count <= 0)
		return -EFAULT;

	ret = bma_cdev_recv_msg(GET_PRIVATE_DATA(filp), data, count);

	if (ret > 0) {
		((struct cdev_dev *)filp->private_data)->s.recv_bytes += ret;
		((struct cdev_dev *)filp->private_data)->s.recv_pkgs++;
	} else {
		((struct cdev_dev *)filp->private_data)->s.recv_failed_count++;
	}

	return ret;
}

ssize_t cdev_write(struct file *filp, const char __user *data, size_t count,
		   loff_t *ppos)
{
	int ret = 0;

	if (!data || count <= 0)
		return -EFAULT;

	CDEV_LOG(DLOG_DEBUG, "data is %p,count is %u", data,
		 (unsigned int)count);
	ret = bma_cdev_add_msg(GET_PRIVATE_DATA(filp), data, count);

	if (ret > 0) {
		((struct cdev_dev *)filp->private_data)->s.send_bytes += ret;
		((struct cdev_dev *)filp->private_data)->s.send_pkgs++;
	} else {
		((struct cdev_dev *)filp->private_data)->s.send_failed_count++;
	}

	return ret;
}

MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("HUAWEI CDEV DRIVER");
MODULE_LICENSE("GPL");
MODULE_VERSION(CDEV_VERSION);

module_init(bma_cdev_init);
module_exit(bma_cdev_exit);
