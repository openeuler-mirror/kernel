/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HISI_SDMA_HAL_H__
#define __HISI_SDMA_HAL_H__

#include <linux/bitfield.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/io.h>

#include "hisi_sdma.h"

/**
 * struct hisi_sdma_channel - Information about one channel in the SDMA device
 * @idx: SDMA channel's ID
 * @sq_base: Base address of the CQE queue in the DDR
 * @cq_base: Base address of the SQE queue in the DDR
 * @sync_info_base: Share information for user driver in the DDR
 * @io_base: SDMA channel address
 * @cnt_used: Number of times that the channel is used
 */
struct hisi_sdma_channel {
	u16 idx;
	struct hisi_sdma_device *pdev;

	/* must be page-aligned and continuous physical memory */
	struct hisi_sdma_sq_entry *sq_base;
	struct hisi_sdma_cq_entry *cq_base;
	struct hisi_sdma_queue_info *sync_info_base;

	void __iomem *io_base;
	u16 cnt_used;
};


/**
 * struct hisi_sdma_device - SDMA device structure
 * @idx: SDMA device's ID
 * @nr_channel: Number of channels owned by SDMA devices
 * @nr_channel_used: Number of channels used by SDMA devices
 * @channels: Pointer to the hisi_sdma_channel structure
 * @channel_map: Bitmap indicating the usage of the SDMA channel
 * @io_orig_base: I/O base address after mapping
 * @io_base: io_orig_base + 32 channel address offsets
 * @base_addr: SDMA I/O base phyisical address
 * @name: SDMA device name in the /dev directory
 */

struct hisi_sdma_device {
	u16 idx;
	u16 node_idx;
	u16 nr_channel;
	u16 nr_channel_used;
	spinlock_t channel_lock;
	struct hisi_sdma_channel *channels;
	char name[HISI_SDMA_DEVICE_NAME_MAX];
	DECLARE_BITMAP(channel_map, HISI_SDMA_DEFAULT_CHANNEL_NUM);

	struct platform_device *pdev;
	struct cdev cdev;
	u32 streamid;

	void __iomem *io_orig_base;
	void __iomem *io_base;
	void __iomem *common_base;
	u64 base_addr;
	resource_size_t base_addr_size;
	u64 common_base_addr;
	resource_size_t common_base_addr_size;
};

struct hisi_sdma_core_device {
	u32 sdma_major;
	u32 sdma_device_num;
	struct hisi_sdma_device *sdma_devices[HISI_SDMA_MAX_DEVS];
};

struct hisi_sdma_global_info {
	struct hisi_sdma_core_device *core_dev;
	struct ida *fd_ida;
};

void sdma_cdev_init(struct cdev *cdev);
void sdma_info_sync_cdev(struct hisi_sdma_global_info *g_info);
#endif
