/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ioctl_chnl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_IOCTL_CHNL_H__
#define __SXE2_IOCTL_CHNL_H__

#ifdef SXE2_DPDK_DRIVER

#include <rte_version.h>
#if (RTE_VERSION_NUM(22, 0, 0, 0) <= RTE_VERSION)
#include <bus_pci_driver.h>
#else
#include <rte_pci.h>
#include <rte_bus_pci.h>
#endif

#include "sxe2_type.h"
#endif

#ifdef SXE2_LINUX_DRIVER
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#endif
#endif

#include "sxe2_internal_ver.h"

#define SXE2_COM_INVAL_U32 0xFFFFFFFF

#define SXE2_COM_PCI_OFFSET_SHIFT 40

#define SXE2_COM_PCI_INDEX_TO_OFFSET(index)	((u64)(index) << SXE2_COM_PCI_OFFSET_SHIFT)
#define SXE2_COM_PCI_OFFSET_MASK	(((u64)(1) << SXE2_COM_PCI_OFFSET_SHIFT) - 1)
#define SXE2_COM_PCI_OFFSET_GEN(index, off) ((((u64)(index)) << SXE2_COM_PCI_OFFSET_SHIFT) | \
		(((u64)(off)) & SXE2_COM_PCI_OFFSET_MASK))

#define SXE2_DRV_TRACE_ID_COUNT_MASK 0x003FFFFFFFFFFFFFLLU

#define SXE2_DRV_CMD_DFLT_TIMEOUT (30)

#define SXE2_COM_VER_MAJOR 1
#define SXE2_COM_VER_MINOR 0
#define SXE2_COM_VER       SXE2_MK_VER(SXE2_COM_VER_MAJOR, SXE2_COM_VER_MINOR)

enum SXE2_COM_CMD {
	SXE2_DEVICE_HANDSHAKE = 1,
	SXE2_DEVICE_IO_IRQS_REQ,
	SXE2_DEVICE_EVT_IRQ_REQ,
	SXE2_DEVICE_RST_IRQ_REQ,
	SXE2_DEVICE_EVT_CAUSE_GET,
	SXE2_DEVICE_DMA_MAP,
	SXE2_DEVICE_DMA_UNMAP,
	SXE2_DEVICE_PASSTHROUGH,
	SXE2_DEVICE_MAX,
};

#define SXE2_CMD_TYPE 'S'

#define SXE2_COM_CMD_HANDSHAKE     _IO(SXE2_CMD_TYPE, SXE2_DEVICE_HANDSHAKE)
#define SXE2_COM_CMD_IO_IRQS_REQ   _IO(SXE2_CMD_TYPE, SXE2_DEVICE_IO_IRQS_REQ)
#define SXE2_COM_CMD_EVT_IRQ_REQ   _IO(SXE2_CMD_TYPE, SXE2_DEVICE_EVT_IRQ_REQ)
#define SXE2_COM_CMD_RST_IRQ_REQ   _IO(SXE2_CMD_TYPE, SXE2_DEVICE_RST_IRQ_REQ)
#define SXE2_COM_CMD_EVT_CAUSE_GET _IO(SXE2_CMD_TYPE, SXE2_DEVICE_EVT_CAUSE_GET)
#define SXE2_COM_CMD_DMA_MAP       _IO(SXE2_CMD_TYPE, SXE2_DEVICE_DMA_MAP)
#define SXE2_COM_CMD_DMA_UNMAP     _IO(SXE2_CMD_TYPE, SXE2_DEVICE_DMA_UNMAP)
#define SXE2_COM_CMD_PASSTHROUGH   _IO(SXE2_CMD_TYPE, SXE2_DEVICE_PASSTHROUGH)

enum sxe2_com_cap {
	SXE2_COM_CAP_IOMMU_MAP = 0,
};

struct sxe2_ioctl_cmd_common_hdr {
	u32 dpdk_ver;
	u32 drv_ver;
	u32 msg_len;
	u32 cap;
	u8  reserved[32];
};

struct sxe2_drv_cmd_params {
	u64 trace_id;
	u32 timeout;
	u32 opcode;
	u16 vsi_id;
	u16 repr_id;
	u32 req_len;
	u32 resp_len;
	void *req_data;
	void *resp_data;
	u8    resv[32];
};

struct sxe2_ioctl_irq_set {
	u32  cnt;
	u8   resv[4];
	u32  base_irq_in_com;
	s32 *event_fd;
};

enum sxe2_com_event_cause {
	SXE2_COM_EC_LINK_CHG = 0,
	SXE2_COM_SW_MODE_LEGACY,
	SXE2_COM_SW_MODE_SWITCHDEV,
	SXE2_COM_FC_ST_CHANGE,

	SXE2_COM_EC_RESET = 62,
	SXE2_COM_EC_MAX = 63,
};

struct sxe2_ioctl_other_evt_set {
	s32 eventfd;
	u8  resv[4];
	u64 filter_table;
};

struct sxe2_ioctl_other_evt_get {
	u64 evt_cause;
	u8  resv[8];
};

struct sxe2_ioctl_reset_sub_set {
	s32 eventfd;
	u8  resv[4];
};

struct sxe2_ioctl_iommu_dma_map {
	u64 vaddr;
	u64 iova;
	u64 size;
	u8  resv[4];
};

struct sxe2_ioctl_iommu_dma_unmap {
	u64 iova;
};

union sxe2_drv_trace_info {
	u64 id;
	struct {
		u64 count : 54;
		u64 cpu_id : 10;
	} sxe2_drv_trace_id_param;
};
#endif
