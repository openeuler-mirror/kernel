// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_host_cli.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/atomic.h>
#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_log.h"
#include "sxe2_host_cli.h"
#include "sxe2_ioctl.h"
#include "sxe2_cli_drv_priv.h"

#define SXE2_CLI_CMD_DFLT_TIMEOUT (30)

#define SXE2_CLI_CMD_DFLT_TIMEOUT_MS                                                \
	(30000)

#define SXE2_MAX_IOCTL_CMDS (1)

#define SXE2_IOCTL_MEMDUP_LEN (56)

STATIC dev_t sxe2_cdev_major;
STATIC struct class *sxe2_cdev_class;
STATIC struct sxe2_cli_dev_mgr sxe2_cdev_mgr;

STATIC struct mutex sxe2_minor_lock;
STATIC DEFINE_IDR(sxe2_minor_idr);

struct sxe2_cli_dev_mgr *sxe2_cdev_mgr_get(void)
{
	return &sxe2_cdev_mgr;
}

STATIC s32 sxe2_cli_open(struct inode *inode, struct file *filep)
{
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();
	s32 ret = 0;
	struct sxe2_cli_dev_mgr_data *cdev_mgr;

	cdev_mgr = container_of(inode->i_cdev, struct sxe2_cli_dev_mgr_data,
				cdev_info.cdev);

	filep->private_data = cdev_mgr;

	mutex_lock(&cli_dev_mgr->lock);

	atomic_inc(&cdev_mgr->ref_count);

	if (cdev_mgr->status == SXE2_CDEV_STATUS_UNACCESS) {
		ret = -EACCES;
		atomic_dec(&cdev_mgr->ref_count);
		goto l_unlock;
	}

l_unlock:
	mutex_unlock(&cli_dev_mgr->lock);
	return ret;
}

STATIC s32 sxe2_cli_close(struct inode *inode, struct file *filep)
{
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();
	struct sxe2_cli_dev_mgr_data *cdev_mgr =
			(struct sxe2_cli_dev_mgr_data *)filep->private_data;
	s32 ref_count = 0;

	mutex_lock(&cli_dev_mgr->lock);
	ref_count = atomic_dec_return(&cdev_mgr->ref_count);
	if (ref_count == 0) {
		mutex_unlock(&cli_dev_mgr->lock);
		wake_up(&cdev_mgr->waitq);
	} else {
		mutex_unlock(&cli_dev_mgr->lock);
	}

	return 0;
}

STATIC s32 sxe2_do_cli_cmd(struct sxe2_adapter *adapter, unsigned int cmd_code,
			   unsigned long arg)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_ioctl_sync_cmd *cmd_buf;

	void __user *argp = (void __user *)arg;

	cmd_buf = memdup_user(argp, SXE2_IOCTL_MEMDUP_LEN);
	if (IS_ERR(cmd_buf)) {
		ret = (s32)PTR_ERR(cmd_buf);
		LOG_ERROR_BDF("memdup_user mem failed, ret=%d\n", ret);
		(void)cmd_buf;
		goto l_end;
	}

	LOG_DEBUG_BDF("get user cmd: trace_id=0x%llx, in_len=%u, out_len=%u, cli_ver 0x%x\n",
		      cmd_buf->trace_id, cmd_buf->in_len, cmd_buf->out_len,
		      cmd_buf->ver);

	if (SXE2_MK_VER_MAJOR(cmd_buf->ver) != SXE2_DRV_CLI_VER_MAJOR) {
		ret = -EOPNOTSUPP;
		goto l_free;
	}

	cmd.opcode = SXE2_CMD_MAX;
	cmd.req_data = cmd_buf->in_data;
	cmd.req_len = (u16)cmd_buf->in_len;
	cmd.resp_data = cmd_buf->out_data;
	cmd.resp_len = (u16)cmd_buf->out_len;
	cmd.is_interruptible = true;
	cmd.timeout = cmd_buf->timeout ? cmd_buf->timeout
				       : SXE2_CLI_CMD_DFLT_TIMEOUT;
	cmd.trace_id = cmd_buf->trace_id;

	if (cmd_code == SXE2_CMD_IOCTL_SYNC_CMD)
		ret = sxe2_cmd_cli_exec(adapter, &cmd);
	else if (cmd_code == SXE2_CMD_IOCTL_SYNC_DRV_CMD)
		ret = sxe2_cmd_cli_drv_exec(adapter, &cmd);
	else
		ret = -EFAULT;

	if (ret) {
		LOG_ERROR_BDF("sxe2 cli cmd(%d) trace_id=0x%llx error, ret=%d\n",
			      cmd_code, cmd.trace_id, ret);
		goto l_free;
	}

	cmd_buf->ver = SXE2_DRV_CLI_VER;
	if (ret == 0 && copy_to_user(argp, cmd_buf, sizeof(*cmd_buf))) {
		LOG_ERROR_BDF("copy_to_user failed, len=%zu\n", sizeof(*cmd_buf));
		ret = -EFAULT;
		goto l_free;
	}

l_free:
	kfree(cmd_buf);
l_end:
	return ret;
}

STATIC long sxe2_cli_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	long ret;
	struct sxe2_adapter *adapter = NULL;
	struct sxe2_cli_dev_mgr_data *cdev_mgr = NULL;
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();

	if (!filep || cmd == 0 || arg == 0) {
		LOG_ERROR("filep=%p cmd=%d arg=%ld\n", filep, cmd, arg);
		ret = -EINVAL;
		goto l_end;
	}

	cdev_mgr = (struct sxe2_cli_dev_mgr_data *)filep->private_data;

	mutex_lock(&cli_dev_mgr->lock);
	if (cdev_mgr->status == SXE2_CDEV_STATUS_UNACCESS) {
		mutex_unlock(&cli_dev_mgr->lock);
		ret = -EACCES;
		goto l_end;
	}
	mutex_unlock(&cli_dev_mgr->lock);

	adapter = (struct sxe2_adapter *)cdev_mgr->adapter;

	LOG_DEBUG_BDF("driver ioctl cmd=%x, arg=0x%lx\n", cmd, arg);

	if (down_interruptible(&adapter->cdev_mgr->cdev_info.cdev_sem)) {
		LOG_WARN_BDF("ioctl concurrency full\n");
		ret = -ERESTARTSYS;
		goto l_end;
	}
	LOG_DEBUG_BDF("driver ioctl cmd=%x, arg=0x%lx get sem\n", cmd, arg);

	switch (cmd) {
	case SXE2_CMD_IOCTL_SYNC_CMD:
	case SXE2_CMD_IOCTL_SYNC_DRV_CMD:
		ret = sxe2_do_cli_cmd(adapter, cmd, arg);
		break;
	default:
		ret = -EINVAL;
		LOG_ERROR_BDF("unknown ioctl cmd, filep=%p, cmd=%d,arg=0x%8.8lx\n",
			      filep, cmd, arg);
		break;
	}

	if (ret) {
		LOG_ERROR_BDF("filep=%p, cmd=%d, arg=%lx, ret=%ld\n", filep, cmd,
			      arg, ret);
	}

	up(&adapter->cdev_mgr->cdev_info.cdev_sem);

l_end:
	LOG_DEBUG_BDF("driver ioctl cmd=%x, arg=0x%lx end, ret:%ld\n", cmd, arg,
		      ret);
	return ret;
}

const struct file_operations sxe2_cdev_fops = {
		.owner = THIS_MODULE,
		.unlocked_ioctl = sxe2_cli_ioctl,
		.open = sxe2_cli_open,
		.release = sxe2_cli_close,
};

s32 sxe2_cli_cdev_register(void)
{
	s32 ret;
	u16 i;

	memset(&sxe2_cdev_mgr, 0, sizeof(sxe2_cdev_mgr));
	mutex_init(&sxe2_cdev_mgr.lock);
	for (i = 0; i < SXE2_CLI_DEV_MGR_DATA_SIZE; i++) {
		sxe2_cdev_mgr.cdev_mgr[i].id = i;
		sema_init(&sxe2_cdev_mgr.cdev_mgr[i].cdev_info.cdev_sem,
			  SXE2_MAX_IOCTL_CMDS);
	}

	ret = alloc_chrdev_region(&sxe2_cdev_major, 0, SXE2_MAX_DEVICES_NUM,
				  SXE2_CHRDEV_NAME);
	if (ret) {
		LOG_ERROR("alloc cdev number failed: %d\n", ret);
		goto l_alloc_cdev_failed;
	}

	sxe2_cdev_class = class_create(THIS_MODULE, SXE2_CHRDEV_CLASS_NAME);
	if (IS_ERR(sxe2_cdev_class)) {
		ret = (s32)PTR_ERR(sxe2_cdev_class);
		LOG_ERROR("create cdev class failed: %d\n", ret);
		goto l_create_class_failed;
	}

	mutex_init(&sxe2_minor_lock);

	return 0;

l_create_class_failed:
	unregister_chrdev_region(sxe2_cdev_major, SXE2_MAX_DEVICES_NUM);
l_alloc_cdev_failed:
	return ret;
}

void sxe2_cli_cdev_unregister(void)
{
	class_destroy(sxe2_cdev_class);
	unregister_chrdev_region(sxe2_cdev_major, SXE2_MAX_DEVICES_NUM);
	idr_destroy(&sxe2_minor_idr);

	mutex_destroy(&sxe2_minor_lock);
	mutex_destroy(&sxe2_cdev_mgr.lock);
}

STATIC s32 sxe2_minor_get(s32 *dev_minor)
{
	s32 ret = -ENOMEM;

	mutex_lock(&sxe2_minor_lock);
	ret = idr_alloc(&sxe2_minor_idr, NULL, 0, (s32)SXE2_MAX_DEVICES_NUM,
			GFP_KERNEL);
	if (ret >= 0) {
		*dev_minor = ret;
		ret = 0;
	}
	mutex_unlock(&sxe2_minor_lock);
	return ret;
}

STATIC void sxe2_minor_free(s32 dev_minor)
{
	mutex_lock(&sxe2_minor_lock);
	idr_remove(&sxe2_minor_idr, dev_minor);
	mutex_unlock(&sxe2_minor_lock);
}

STATIC void sxe2_cli_cdev_mgr_init(struct sxe2_adapter *adapter)
{
	atomic_set(&adapter->cdev_mgr->ref_count, 0);
	adapter->cdev_mgr->status = SXE2_CDEV_STATUS_NORMAL;

	init_waitqueue_head(&adapter->cdev_mgr->waitq);
}

STATIC s32 sxe2_cli_cdev_mgr_get(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	unsigned long offset;
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();
	unsigned long *map = cli_dev_mgr->map;

	mutex_lock(&cli_dev_mgr->lock);

	offset = bitmap_find_next_zero_area(map, SXE2_CLI_DEV_MGR_DATA_SIZE, 0,
					    SXE2_CLI_DEV_MGR_DATA_CNT, 0);
	if (offset >= SXE2_CLI_DEV_MGR_DATA_SIZE) {
		LOG_INFO("get cdev mgr(%ld) over max pf count(%d).\n", offset,
			 SXE2_CLI_DEV_MGR_DATA_SIZE);
		ret = -EPERM;
		goto end;
	}

	bitmap_set(map, (u32)offset, SXE2_CLI_DEV_MGR_DATA_CNT);
	adapter->cdev_mgr = &cli_dev_mgr->cdev_mgr[offset];
	cli_dev_mgr->cdev_mgr[offset].adapter = adapter;
	sxe2_cli_cdev_mgr_init(adapter);

end:
	mutex_unlock(&cli_dev_mgr->lock);
	return ret;
}

STATIC void sxe2_cli_cdev_wait_clear(struct sxe2_adapter *adapter)
{
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();
	s32 ret;
	int is_ref_count_zero;
	unsigned long cur_jiffies;

	if (adapter->cdev_mgr) {
		mutex_lock(&cli_dev_mgr->lock);
		adapter->cdev_mgr->status = SXE2_CDEV_STATUS_UNACCESS;
		mutex_unlock(&cli_dev_mgr->lock);

		do {
			is_ref_count_zero =
					(atomic_read(&adapter->cdev_mgr
								      ->ref_count) ==
					 0);
			cur_jiffies = msecs_to_jiffies(SXE2_CLI_CMD_DFLT_TIMEOUT_MS);
			ret = (s32)wait_event_timeout(adapter->cdev_mgr->waitq,
						      is_ref_count_zero,
						      (long)cur_jiffies);
			(void)is_ref_count_zero;
			(void)cur_jiffies;
			if (!ret) {
				LOG_INFO_BDF("cdev(%d) wait ref count time out.",
					     adapter->cdev_mgr->id);
			} else {
				mutex_lock(&cli_dev_mgr->lock);
				if (atomic_read(&adapter->cdev_mgr->ref_count) ==
				    0) {
					mutex_unlock(&cli_dev_mgr->lock);
					break;
				}
				mutex_unlock(&cli_dev_mgr->lock);
			}
		} while (1);
	}
}

STATIC void sxe2_cli_cdev_mgr_put(struct sxe2_adapter *adapter)
{
	struct sxe2_cli_dev_mgr *cli_dev_mgr = sxe2_cdev_mgr_get();
	unsigned long *map = cli_dev_mgr->map;
	u16 dev_mgr_id;

	if (adapter->cdev_mgr) {
		dev_mgr_id = adapter->cdev_mgr->id;
		adapter->cdev_mgr->adapter = NULL;
		adapter->cdev_mgr = NULL;
		bitmap_clear(map, dev_mgr_id, SXE2_CLI_DEV_MGR_DATA_CNT);
	}
}

s32 sxe2_cli_cdev_create(struct sxe2_adapter *adapter)
{
	s32 ret;
	s32 dev_major, dev_minor;
	struct pci_dev *pdev = adapter->pdev;
	struct sxe2_cdev_info *cdev_info = NULL;

	ret = sxe2_cli_cdev_mgr_get(adapter);
	if (ret) {
		LOG_DEV_ERR("register netdev notifier failed, ret=%d\n", ret);
		goto l_cdev_mgr_get_failed;
	}

	ret = sxe2_minor_get(&dev_minor);
	if (ret) {
		LOG_DEV_ERR("cdev minor get failed, ret=%d\n", ret);
		ret = -ENOMEM;
		goto l_get_minor_failed;
	}

	cdev_info = &adapter->cdev_mgr->cdev_info;
	dev_major = (s32)MAJOR(sxe2_cdev_major);
	cdev_info->dev_no = (dev_t)MKDEV(dev_major, dev_minor);
	cdev_init(&cdev_info->cdev, &sxe2_cdev_fops);
	cdev_info->cdev.owner = THIS_MODULE;
	cdev_info->cdev.ops = &sxe2_cdev_fops;

	LOG_INFO_BDF("cdev_add: dev_major: %d, dev_minor: %d.\n", dev_major,
		     dev_minor);

	ret = cdev_add(&cdev_info->cdev, cdev_info->dev_no, 1);
	if (ret) {
		LOG_DEV_ERR("failed to add cdev dev_no=%ld, ret=%d\n",
			    (unsigned long)cdev_info->dev_no, ret);
		goto l_add_cdev_failed;
	}

	cdev_info->device =
			device_create(sxe2_cdev_class, NULL, cdev_info->dev_no, NULL,
				      SXE2_CHRDEV_NAME "-%04x:%02x:%02x.%x",
				      pci_domain_nr(pdev->bus), pdev->bus->number,
				      PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	if (IS_ERR(cdev_info->device)) {
		ret = (s32)PTR_ERR(cdev_info->device);
		LOG_DEV_ERR("failed to create device, dev_no=%ld\n",
			    (unsigned long)cdev_info->dev_no);
		goto l_create_dev_failed;
	}

	LOG_INFO("create char dev[%p] dev_no[major:minor=%u:%u] on pci_dev[%p]\t"
		 "belongs to class dev[%p] success\n",
		 &cdev_info->cdev, dev_major, dev_minor, adapter->pdev,
		 cdev_info->device);

	return 0;

l_create_dev_failed:
	cdev_del(&cdev_info->cdev);
l_add_cdev_failed:
	sxe2_minor_free(dev_minor);
l_get_minor_failed:
	sxe2_cli_cdev_mgr_put(adapter);
l_cdev_mgr_get_failed:
	return ret;
}

void sxe2_cli_cdev_delete(struct sxe2_adapter *adapter)
{
	s32 dev_minor;
	struct sxe2_cdev_info *cdev_info = &adapter->cdev_mgr->cdev_info;

	dev_minor = (s32)MINOR(cdev_info->dev_no);

	sxe2_cli_cdev_wait_clear(adapter);

	LOG_INFO("delete char dev[%p], dev_no[major:minor=%u:%u]\n",
		 &cdev_info->cdev, MAJOR(cdev_info->dev_no), dev_minor);

	device_destroy(sxe2_cdev_class, cdev_info->dev_no);
	cdev_del(&cdev_info->cdev);
	sxe2_minor_free(dev_minor);

	sxe2_cli_cdev_mgr_put(adapter);
}
