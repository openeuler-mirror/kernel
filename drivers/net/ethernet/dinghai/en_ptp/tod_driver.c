// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/termios.h>
#include "tod_driver.h"
//#include "../msg_chan_driver/msg_chan_pub.h"
#include <linux/dinghai/dh_cmd.h>
#include <linux/dinghai/zxdh_compat.h>
#include "zxdh_ptp_common.h"

#define DEVICE_NUM 3
#define TOD_AGENT_NAME_LEN 15
#define TOD_DEVICE_NAME "tod-dev"
#define TOD_DEVICE_CLASS "tod_class"

static u64 virt_addr;
static u64 pcie_id;
static dev_t tod_device_no;
static struct class *tod_device_class;

struct tod_device {
	struct cdev tod_cdev;
	// gps:"/dev/ttyAMA1", recv tod: "/dev/ttyAMA2", send tod: "/dev/ttyAMA3"
	char tod_agent_name[TOD_AGENT_NAME_LEN];
	struct file *tod_device_file;
};

struct tod_device tod_dev_array[DEVICE_NUM];

s32 tod_device_set_bar_virtual_addr(u64 virtaddr, u16 pcieid)
{
	virt_addr = virtaddr;
	pcie_id = pcieid;
	PTP_LOG_INFO("%s: bar msg virtaddr: 0x%llx\n", __func__, virtaddr);
	return 0;
}
EXPORT_SYMBOL(tod_device_set_bar_virtual_addr);

static s32 tod_device_sync_msg_send(u8 *req, u32 req_len, u8 *resp, u32 resp_len)
{
	s32 result = 0;
	u32 payload_len = 0;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem out = { 0 };

	if (!req || req_len < 4) {
		PTP_LOG_ERR("%s: arg invalid, req: %p, req_len: %u.\n", __func__, req, req_len);
		return -EINVAL;
	}

	out.buffer_len = 4 + 4 + resp_len;
	out.recv_buffer = kmalloc(out.buffer_len, GFP_KERNEL);
	if (!out.recv_buffer) {
		PTP_LOG_ERR("%s: no space left on device.\n", __func__);
		return -ENOSPC;
	}
	memset(out.recv_buffer, 0, out.buffer_len);

	in.virt_addr = virt_addr;
	in.event_id = MODULE_TOD;
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.payload_addr = req;
	in.payload_len = req_len;
	in.src_pcieid = pcie_id;

	if (zxdh_bar_chan_sync_msg_send(&in, &out) != BAR_MSG_OK) {
		kfree(out.recv_buffer);
		PTP_LOG_ERR("%s: zxdh_bar_chan_sync_msg_send failed.\n", __func__);
		return -EINVAL;
	}

	payload_len = *(u16 *)((u8 *)out.recv_buffer + 1);
	if (payload_len < 4) {
		kfree(out.recv_buffer);
		PTP_LOG_ERR("%s: payload_len: %u check failed.\n", __func__, payload_len);
		return -EINVAL;
	}

	result = *(s32 *)((u8 *)out.recv_buffer + 4);
	if (result != 0) {
		kfree(out.recv_buffer);
		PTP_LOG_ERR("%s: result: %d check failed.\n", __func__, result);
		return result;
	}

	if (payload_len > 4 && resp) {
		memcpy(resp, out.recv_buffer + 8,
		       (((payload_len - 4) > resp_len) ? resp_len : (payload_len - 4)));
	}

	kfree(out.recv_buffer);

	return 0;
}

static int tod_device_open(struct inode *inode, struct file *file)
{
	s32 result = 0;
	struct tod_device_msg msg;
	struct tod_device *tod;

	file->private_data = (void *)(container_of(inode->i_cdev, struct tod_device, tod_cdev));
	tod = (struct tod_device *)file->private_data;

	PTP_LOG_INFO("%s. dev_name: %s\n", __func__, (tod->tod_agent_name));

	if (tod->tod_device_file) {
		PTP_LOG_INFO("%s: device already open.\n", __func__);
		return 0;
	}

	memset(&msg, 0x00, sizeof(struct tod_device_msg));
	msg.type = TOD_DEVICE_MSG_OPEN;
	memcpy(msg.data, tod->tod_agent_name, strlen(tod->tod_agent_name) + 1);

	result = tod_device_sync_msg_send((u8 *)(&msg), sizeof(struct tod_device_msg),
					  (u8 *)(&tod->tod_device_file), sizeof(struct file *));
	if (result != 0) {
		tod->tod_device_file = NULL;
		PTP_LOG_ERR("%s: tod_device_sync_msg_send failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}
	PTP_LOG_INFO("%s: file %p open success.\n", __func__, tod->tod_device_file);

	return 0;
}

static int tod_device_release(struct inode *inode, struct file *file)
{
	s32 result = 0;
	struct tod_device_msg msg;
	struct tod_device *tod;

	tod = (struct tod_device *)file->private_data;

	PTP_LOG_INFO("%s  tod_agent_name: %s.\n", __func__, tod->tod_agent_name);

	if (!tod->tod_device_file) {
		PTP_LOG_ERR("%s: device already close.\n", __func__);
		return 0;
	}

	memset(&msg, 0x00, sizeof(struct tod_device_msg));
	msg.type = TOD_DEVICE_MSG_CLOSE;
	msg.file = tod->tod_device_file;

	result = tod_device_sync_msg_send((u8 *)(&msg), sizeof(struct tod_device_msg), NULL, 0);
	if (result != 0) {
		PTP_LOG_ERR("%s: tod_device_sync_msg_send failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}
	PTP_LOG_INFO("%s: file %p close success.\n", __func__, tod->tod_device_file);
	tod->tod_device_file = NULL;

	return 0;
}

static ssize_t tod_device_read(struct file *file, char *buf, size_t count, loff_t *f_pos)
{
	s32 result = 0;
	u8 *resp = NULL;
	struct tod_device_msg msg;
	struct tod_device *tod;

	tod = (struct tod_device *)file->private_data;

	PTP_LOG_INFO("%s  tod_agent_name: %s.\n", __func__, tod->tod_agent_name);

	if (!tod->tod_device_file) {
		PTP_LOG_ERR("%s: no such device.\n", __func__);
		return -ENODEV;
	}

	if (count > (2048 - 12 - sizeof(s32) -
		     sizeof(size_t))) { // common bar: 2048 - 12, result: 4, count: 8.
		PTP_LOG_ERR("%s: no space left on device.\n", __func__);
		return -ENOSPC;
	}

	resp = kmalloc(sizeof(size_t) + count, GFP_KERNEL);
	if (!resp)
		return -ENOSPC;

	memset(&msg, 0x00, sizeof(struct tod_device_msg));
	msg.type = TOD_DEVICE_MSG_READ;
	msg.count = count;
	msg.file = tod->tod_device_file;

	result = tod_device_sync_msg_send((u8 *)(&msg), sizeof(struct tod_device_msg), resp,
					  sizeof(size_t) + count);
	if (result != 0) {
		kfree(resp);
		PTP_LOG_ERR("%s: tod_device_sync_msg_send failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}

	count = *((size_t *)(resp));
	if (count > msg.count) {
		PTP_LOG_ERR("%s: no space left on device.\n", __func__);
		kfree(resp);
		return -ENOSPC;
	}

	result = copy_to_user(buf, resp + sizeof(size_t), count);
	if (result != 0) {
		kfree(resp);
		PTP_LOG_ERR("%s: copy_to_user failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}

	kfree(resp);
	PTP_LOG_INFO("%s: file %p read %lu bytes success.\n", __func__, tod->tod_device_file,
		     count);

	return count;
}

static ssize_t tod_device_write(struct file *file, const char *buf, size_t count, loff_t *f_pos)
{
	s32 result = 0;
	struct tod_device_msg msg;
	struct tod_device *tod;

	tod = (struct tod_device *)file->private_data;

	PTP_LOG_INFO("%s  tod_agent_name: %s.\n", __func__, tod->tod_agent_name);

	if (!tod->tod_device_file) {
		PTP_LOG_ERR("%s: no such device.\n", __func__);
		return -ENODEV;
	}

	if (count > sizeof(msg.data)) {
		PTP_LOG_ERR("%s: no space left on device.\n", __func__);
		return -ENOSPC;
	}

	memset(&msg, 0x00, sizeof(struct tod_device_msg));
	msg.type = TOD_DEVICE_MSG_WRITE;
	msg.count = count;
	msg.file = tod->tod_device_file;
	result = copy_from_user(msg.data, buf, count);
	if (result != 0) {
		PTP_LOG_ERR("%s: copy_from_user failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}

	result = tod_device_sync_msg_send((u8 *)(&msg), sizeof(struct tod_device_msg),
					  (u8 *)(&count), sizeof(size_t));
	if (result != 0) {
		PTP_LOG_ERR("%s: tod_device_sync_msg_send failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}
	PTP_LOG_INFO("%s: file %p write %lu bytes success.\n", __func__, tod->tod_device_file,
		     count);

	return count;
}

static __poll_t tod_device_poll(struct file *file, struct poll_table_struct *wait)
{
	s32 result = 0;
	u16 poll_mask = 0;
	struct tod_device_msg msg;
	struct tod_device *tod;

	tod = (struct tod_device *)file->private_data;
	PTP_LOG_INFO("%s  tod_agent_name: %s.\n", __func__, tod->tod_agent_name);

	if (!tod->tod_device_file) {
		PTP_LOG_ERR("%s: no such device.\n", __func__);
		return POLLERR;
	}

	memset(&msg, 0x00, sizeof(struct tod_device_msg));
	msg.type = TOD_DEVICE_MSG_POLL;
	msg.file = tod->tod_device_file;

	result = tod_device_sync_msg_send((u8 *)(&msg), sizeof(struct tod_device_msg),
					  (u8 *)(&poll_mask), sizeof(u16));
	if (result != 0) {
		PTP_LOG_ERR("%s: tod_device_sync_msg_send failed, result: %d.\n", __func__, result);
		return POLLERR;
	}
	PTP_LOG_INFO("%s: file %p poll mask 0x%04x success.\n", __func__, tod->tod_device_file,
		     poll_mask);

	return poll_mask;
}

static long tod_device_ioctl(struct file *file, u32 request, unsigned long args)
{
	s32 result = 0;
	u8 *resp = NULL;
	struct tod_device_msg msg;
	struct tod_device *tod;

	tod = (struct tod_device *)file->private_data;

	PTP_LOG_INFO("%s  tod_agent_name: %s.\n", __func__, tod->tod_agent_name);

	if (!tod->tod_device_file) {
		PTP_LOG_ERR("%s: no such device.\n", __func__);
		return -ENODEV;
	}

	resp = kmalloc(sizeof(struct termios), GFP_KERNEL);
	if (!resp) {
		PTP_LOG_ERR("%s: no space left on device.\n", __func__);
		return -ENOSPC;
	}

	memset(&msg, 0x00, sizeof(struct tod_device_msg));
	msg.type = TOD_DEVICE_MSG_IOCTL;
	msg.file = tod->tod_device_file;
	msg.command = request;

	if ((struct termios *)args) {
		result = copy_from_user(msg.data, (u8 *)args, sizeof(struct termios));
		if (result != 0) {
			PTP_LOG_ERR("%s: copy_from_user failed, result: %d.\n", __func__, result);
			kfree(resp);
			return -EINVAL;
		}
	}

	result = tod_device_sync_msg_send((u8 *)(&msg), sizeof(struct tod_device_msg), resp,
					  sizeof(struct termios));
	if (result != 0) {
		kfree(resp);
		PTP_LOG_ERR("%s: tod_device_sync_msg_send failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}

	if ((struct termios *)args) {
		result = copy_to_user((u8 *)args, resp, sizeof(struct termios));
		if (result != 0) {
			kfree(resp);
			PTP_LOG_ERR("%s: copy_to_user failed, result: %d.\n", __func__, result);
			return -EINVAL;
		}
	}

	kfree(resp);
	PTP_LOG_INFO("%s: file %p ioctl success.\n", __func__, tod->tod_device_file);

	return 0;
}

const struct file_operations tod_device_ops = { .owner = THIS_MODULE,
						.open = tod_device_open,
						.release = tod_device_release,
						.read = tod_device_read,
						.write = tod_device_write,
						.poll = tod_device_poll,
						.unlocked_ioctl = tod_device_ioctl };

static s32 __init tod_device_init(void)
{
	s32 result = 0;
	s32 i = 0;
	s32 j = 0;
	struct device *dev = NULL;

	result = alloc_chrdev_region(&tod_device_no, 0, DEVICE_NUM, TOD_DEVICE_NAME);
	if (result < 0) {
		PTP_LOG_ERR("%s: alloc_chrdev_region failed, result: %d.\n", __func__, result);
		return -EINVAL;
	}

	for (i = 0; i < DEVICE_NUM; i++) {
		cdev_init(&tod_dev_array[i].tod_cdev, &tod_device_ops);
		tod_dev_array[i].tod_cdev.owner = THIS_MODULE;
		snprintf(tod_dev_array[i].tod_agent_name, TOD_AGENT_NAME_LEN, "/dev/ttyAMA%d",
			 i + 1);

		result = cdev_add(&tod_dev_array[i].tod_cdev,
				  MKDEV(MAJOR(tod_device_no), MINOR(tod_device_no) + i), 1);
		if (result != 0) {
			PTP_LOG_ERR("%s: cdev_add failed, result: %d.\n", __func__, result);
			if (i > 0) {
				for (j = i - 1; j >= 0; j--)
					cdev_del(&tod_dev_array[j].tod_cdev);
			}
			goto cdev_add_fail;
		}
	}

	tod_device_class = class_create(TOD_DEVICE_CLASS);

	if (IS_ERR(tod_device_class)) {
		PTP_LOG_ERR("%s: class_create failed, err: %lu.\n", __func__,
			    PTR_ERR(tod_device_class));

		goto class_create_fail;
	}

	for (i = 0; i < DEVICE_NUM; i++) {
		dev = device_create(tod_device_class, NULL,
				    MKDEV(MAJOR(tod_device_no), MINOR(tod_device_no) + i), NULL,
				    "tod_device%d", i);
		if (IS_ERR(dev)) {
			PTP_LOG_ERR("%s: device_create failed, err: %lu.\n", __func__,
				    PTR_ERR(dev));
			if (i > 0) {
				for (j = i - 1; j >= 0; j--) {
					device_destroy(tod_device_class,
						       MKDEV(MAJOR(tod_device_no),
							     MINOR(tod_device_no) + j));
				}
			}

			goto device_create_fail;
		}
	}

	return 0;

device_create_fail:
	class_destroy(tod_device_class);
class_create_fail:
	for (i = 0; i < DEVICE_NUM; i++)
		cdev_del(&tod_dev_array[i].tod_cdev);
cdev_add_fail:
	unregister_chrdev_region(tod_device_no, DEVICE_NUM);
	return -EINVAL;
}

static void __exit tod_device_exit(void)
{
	s32 i;

	for (i = 0; i < DEVICE_NUM; i++) {
		device_destroy(tod_device_class,
			       MKDEV(MAJOR(tod_device_no), MINOR(tod_device_no) + i));
	}

	class_destroy(tod_device_class);

	for (i = 0; i < DEVICE_NUM; i++)
		cdev_del(&tod_dev_array[i].tod_cdev);

	unregister_chrdev_region(tod_device_no, DEVICE_NUM);

	PTP_LOG_ERR("%s: success.\n", __func__);
}

module_init(tod_device_init);
module_exit(tod_device_exit);

MODULE_LICENSE("GPL");
