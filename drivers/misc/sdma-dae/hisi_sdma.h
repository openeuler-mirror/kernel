/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HISI_SDMA_H__
#define __HISI_SDMA_H__

#include <asm-generic/ioctl.h>
#include <linux/errno.h>
#include <linux/types.h>

#define HISI_SDMA_DEVICE_NAME			"sdma"
#define HISI_SDMA_MAX_DEVS			4

#define HISI_STARS_CHN_NUM			32
#define HISI_SDMA_DEFAULT_CHANNEL_NUM		(192 - HISI_STARS_CHN_NUM)
#define HISI_SDMA_REG_SIZE			4096
#define HISI_SDMA_CH_OFFSET			(HISI_STARS_CHN_NUM * HISI_SDMA_REG_SIZE)
#define HISI_SDMA_DEVICE_NAME_MAX		20

#endif
