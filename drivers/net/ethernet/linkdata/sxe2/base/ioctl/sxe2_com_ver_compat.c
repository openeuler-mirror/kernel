// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_ver_compat.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/stddef.h>

#include "sxe2_com_cdev.h"
#include "sxe2_com_ver_compat.h"

#define SXE2_COM_VER_ARG_SZ_END { SXE2_COM_INVAL_U32, SXE2_COM_INVAL_U32 }

struct sxe2_com_ver_arg_sz io_irq_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_ioctl_irq_set, event_fd) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_ver_arg_sz other_evt_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_ioctl_other_evt_set, filter_table) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_ver_arg_sz reset_irqs_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_ioctl_reset_sub_set, resv) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_ver_arg_sz evt_cause_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_ioctl_other_evt_get, resv) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_ver_arg_sz dma_map_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_ioctl_iommu_dma_map, resv) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_ver_arg_sz dma_unmap_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_ioctl_iommu_dma_unmap, iova) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_ver_arg_sz cmd_send_sz[] = {
	{ SXE2_COM_VER, offsetofend(struct sxe2_drv_cmd_params, resv) },
	SXE2_COM_VER_ARG_SZ_END,
};

struct sxe2_com_cmd_arg_sz g_cmd_arg_sz[] = {
	[SXE2_DEVICE_IO_IRQS_REQ] = { io_irq_sz },
	[SXE2_DEVICE_EVT_IRQ_REQ] = { other_evt_sz },
	[SXE2_DEVICE_RST_IRQ_REQ] = { reset_irqs_sz },
	[SXE2_DEVICE_DMA_MAP] = { dma_map_sz },
	[SXE2_DEVICE_DMA_UNMAP] = { dma_unmap_sz },
	[SXE2_DEVICE_PASSTHROUGH] = { cmd_send_sz },
	[SXE2_DEVICE_EVT_CAUSE_GET] = { evt_cause_sz },
	[SXE2_DEVICE_MAX] = {},
};

s32 sxe2_com_get_arg_sz(u32 ver, u32 cmd)
{
	struct sxe2_com_ver_arg_sz *ver_arg_sz;
	u32 minor_ver = SXE2_MK_VER_MINOR(ver);

	if (cmd == SXE2_DEVICE_HANDSHAKE)
		return sizeof(struct sxe2_ioctl_cmd_common_hdr);

	if (cmd >= SXE2_DEVICE_MAX)
		return -EINVAL;

	if (ver == SXE2_COM_INVAL_U32)
		return -EINVAL;

	ver_arg_sz = g_cmd_arg_sz[cmd].ver_arg_sz;

	if (ver_arg_sz->arg_size == 0)
		return ver_arg_sz->arg_size;

	while (ver_arg_sz->ver != SXE2_COM_INVAL_U32) {
		if (SXE2_MK_VER_MINOR(ver_arg_sz->ver) <= minor_ver)
			break;

		ver_arg_sz++;
	}

	return ver_arg_sz->arg_size == SXE2_COM_INVAL_U32 ? -EINVAL : ver_arg_sz->arg_size;
}
