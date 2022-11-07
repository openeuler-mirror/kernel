/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2022 Hisilicon Limited.
#ifndef __HNS3_ROH_COMMON_H__
#define __HNS3_ROH_COMMON_H__

#include "core.h"
#include "hnae3.h"

#define HNS3_ROH_VERSION "1.0"

#define HNS3_ROH_NAME "roh"

struct hns3_roh_priv {
	struct hnae3_handle *handle;
	unsigned long state;
};

struct hns3_roh_device {
	struct roh_device roh_dev;
	struct pci_dev *pdev;
	struct device *dev;
	bool active;
	struct net_device *netdev;

	u8 __iomem *reg_base;
	struct hns3_roh_priv *priv;
};

static inline struct hns3_roh_device *to_hroh_dev(struct roh_device *rohdev)
{
	return container_of(rohdev, struct hns3_roh_device, roh_dev);
}

#define hns3_roh_set_field(origin, mask, shift, val) \
	do { \
		(origin) &= (~(mask)); \
		(origin) |= ((val) << (shift)) & (mask); \
	} while (0)
#define hns3_roh_get_field(origin, mask, shift) (((origin) & (mask)) >> (shift))

#define hns3_roh_set_bit(origin, shift, val) \
	hns3_roh_set_field(origin, 0x1 << (shift), shift, val)
#define hns3_roh_get_bit(origin, shift) \
	hns3_roh_get_field(origin, 0x1 << (shift), shift)

#endif
