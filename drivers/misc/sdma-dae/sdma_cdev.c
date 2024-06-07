// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/platform_device.h>
#include <linux/sort.h>
#include "sdma_hal.h"

static struct hisi_sdma_global_info g_info;

struct file_open_data {
	int ida;
	u32 pasid;
	struct iommu_sva *handle;
	struct hisi_sdma_device *psdma_dev;
};

static int __do_sdma_open(struct hisi_sdma_device *psdma_dev, struct file *file)
{
	struct file_open_data *data;
	struct iommu_sva *handle;
	int id, ret;
	u32 pasid;

	id = ida_alloc(g_info.fd_ida, GFP_KERNEL);
	if (id < 0)
		return id;

	dev_dbg(&psdma_dev->pdev->dev, "%s: ida alloc id = %d\n", __func__, id);
	data = kmalloc_node(sizeof(struct file_open_data), GFP_KERNEL, psdma_dev->node_idx);
	if (!data) {
		ret = -ENOMEM;
		goto free_ida;
	}

	handle = iommu_sva_bind_device(&psdma_dev->pdev->dev, current->mm, NULL);
	if (IS_ERR(handle)) {
		dev_err(&psdma_dev->pdev->dev, "failed to bind sva, %ld\n", PTR_ERR(handle));
		ret = PTR_ERR(handle);
		goto free_privt_data;
	}

	pasid = iommu_sva_get_pasid(handle);
	if (pasid == IOMMU_PASID_INVALID) {
		ret = -ENODEV;
		goto sva_unbind;
	}

	data->ida = id;
	data->pasid = pasid;
	data->psdma_dev = psdma_dev;
	data->handle = handle;
	file->private_data = data;

	return 0;

sva_unbind:
	iommu_sva_unbind_device(handle);
free_privt_data:
	kfree(data);
free_ida:
	ida_free(g_info.fd_ida, id);
	return ret;
}

static int ioctl_sdma_get_process_id(struct file *file, unsigned long arg)
{
	u32 pid = (u32)current->tgid;

	if (copy_to_user((u32 __user *)(uintptr_t)arg, &pid, sizeof(u32)))
		return -EFAULT;

	return 0;
}

static int ioctl_sdma_get_streamid(struct file *file, unsigned long arg)
{
	struct file_open_data *data = file->private_data;
	struct hisi_sdma_device *pdev = data->psdma_dev;
	u32 streamid = pdev->streamid;

	if (copy_to_user((u32 __user *)(uintptr_t)arg, &streamid, sizeof(u32)))
		return -EFAULT;

	return 0;
}

struct hisi_sdma_ioctl_func_list g_ioctl_funcs[] = {
	{IOCTL_SDMA_GET_PROCESS_ID,        ioctl_sdma_get_process_id},
	{IOCTL_SDMA_GET_STREAMID,          ioctl_sdma_get_streamid},
};

static long sdma_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int cmd_num;
	int i;

	cmd_num = sizeof(g_ioctl_funcs) / sizeof(struct hisi_sdma_ioctl_func_list);
	for (i = 0; i < cmd_num; i++) {
		if (g_ioctl_funcs[i].cmd == cmd)
			return g_ioctl_funcs[i].ioctl_func(file, arg);
	}

	return -ENOIOCTLCMD;
}

static int sdma_core_open(struct inode *inode, struct file *file)
{
	struct hisi_sdma_device *psdma_dev;
	dev_t sdma_dev;
	u32 sdma_idx;

	if (g_info.core_dev->sdma_device_num == 0) {
		pr_err("cannot find a sdma device\n");
		return -ENODEV;
	}
	sdma_dev = inode->i_rdev;
	sdma_idx = MINOR(sdma_dev);
	if (sdma_idx >= HISI_SDMA_MAX_DEVS) {
		pr_err("secondary device number overflow\n");
		return -ENODEV;
	}
	psdma_dev = g_info.core_dev->sdma_devices[sdma_idx];
	return __do_sdma_open(psdma_dev, file);
}

static int sdma_dev_release(struct inode *inode, struct file *file)
{
	struct file_open_data *data = file->private_data;

	if (data->handle) {
		iommu_sva_unbind_device(data->handle);
		data->handle = NULL;
	}

	ida_free(g_info.fd_ida, data->ida);
	kfree(file->private_data);
	return 0;
}

static const struct file_operations sdma_core_fops = {
	.owner = THIS_MODULE,
	.open = sdma_core_open,
	.read = NULL,
	.release = sdma_dev_release,
	.unlocked_ioctl = sdma_dev_ioctl,
	.mmap = NULL,
};

void sdma_cdev_init(struct cdev *cdev)
{
	cdev_init(cdev, &sdma_core_fops);
	cdev->owner = THIS_MODULE;
}

void sdma_info_sync_cdev(struct hisi_sdma_global_info *g_info_input)
{
	g_info.core_dev = g_info_input->core_dev;
	g_info.fd_ida = g_info_input->fd_ida;
}
