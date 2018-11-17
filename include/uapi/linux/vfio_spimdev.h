/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _UAPIVFIO_SPIMDEV_H
#define _UAPIVFIO_SPIMDEV_H

#include <linux/ioctl.h>

#define VFIO_SPIMDEV_CLASS_NAME		"spimdev"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_SPIMDEV_PDEV_ATTRS_GRP	"spimdev_para"

/* Device ATTRs in parent dev SYSFS DIR */
#define VFIO_SPIMDEV_MDEV_ATTRS_GRP	"spi_attr"

/* Parent device attributes */
#define SPIMDEV_IOMMU_TYPE	"iommu_type"
#define SPIMDEV_DMA_FLAG	"dma_flag"
#define SPIMDEV_NODE_ID		"node_id"
#define SPIMDEV_MDEV_GET		"mdev_get"

/* For getting node distance of current process */
#define SPIMDEV_NUMA_DISTANCE	"numa_distance"

/* Maximum length of algorithm name string */
#define VFIO_SPIMDEV_ALG_NAME_SIZE		64

/* A new VFIO IOMMU type for spimdev while support no-iommu. This is
 * VFIO MDEV driver's NOIOMMU mode cannot be used by us. Or I think
 * there is a bug in it while MDEV is compatible with VFIO_NOIOMMU.
 * So, we need this IOMMU type currently.
 */
#define VFIO_SPIMDEV_IOMMU			64

/* the bits used in SPIMDEV_DMA_FLAG attributes */
#define VFIO_SPIMDEV_DMA_INVALID		0
#define VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP	1
#define VFIO_SPIMDEV_DMA_MULTI_PROC_MAP		2
#define VFIO_SPIMDEV_DMA_SVM			4
#define VFIO_SPIMDEV_DMA_SVM_NO_FAULT		8
#define VFIO_SPIMDEV_DMA_PHY			16
#define VFIO_SPIMDEV_DMA_SGL			32

#define VFIO_SPIMDEV_CMD_GET_Q	_IO('W', 1)

#endif
