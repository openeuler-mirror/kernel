/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
 *
 * Copyright (c) 2023 Hisilicon Limited.
 */

#ifndef __HNS_ROCE_EXT_H
#define __HNS_ROCE_EXT_H
#include <linux/types.h>

/**
 * rdma_register_notify_addr - Register an POE channel for this RDMA device.
 * @channel - POE channel index.
 * @poe_addr - POE channel address.
 *
 * If the current POE device is not associated with CQ, then it will be
 * allowed to be re-registered. Otherwise, re-registration or
 * de-registration will report an EBUSY error.
 */
int rdma_register_poe_channel(struct ib_device *ib_dev, u8 channel, u64 poe_addr);
int rdma_unregister_poe_channel(struct ib_device *ib_dev, u8 channel);

/**
 * rdma_support_stars - Helper function to determine whether the
 * current device supports STARS.
 */
bool rdma_support_stars(struct ib_device *ib_dev);

/**
 * rdma_query_qp_db - Helper function to get the doorbell address of this
 * device. Currently, it only supports use in STARS scenarios.
 * @qp_index - QP number.
 */
u64 rdma_query_qp_db(struct ib_device *ib_dev, int qp_index);

/**
 * rdma_query_hw_id - Get the relevant hardware ID of the current device.
 * @chip_id - The ID of the chip where the current device is located.
 * @die_id - The ID of the IO DIE where the current device is located.
 * @func_id - The function ID of this device.
 */
int rdma_query_hw_id(struct ib_device *ib_dev, u32 *chip_id,
		     u32 *die_id, u32 *func_id);
#endif
