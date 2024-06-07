// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/sort.h>
#include "sdma_hal.h"

static struct hisi_sdma_global_info g_info;

static const struct file_operations sdma_core_fops = {
	.owner = THIS_MODULE,
	.open = NULL,
	.read = NULL,
	.release = NULL,
	.unlocked_ioctl = NULL,
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
