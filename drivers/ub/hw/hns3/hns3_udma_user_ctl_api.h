/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _HNS3_UDMA_USER_CTL_API_H
#define _HNS3_UDMA_USER_CTL_API_H

struct hns3_udma_user_ctl_poe_init_attr {
	uint64_t rsv; /* reserved for extension, now must be 0 */
	uint64_t poe_addr; /* 0 for disable */
};

struct hns3_udma_user_ctl_cfg_poe_channel_in {
	struct hns3_udma_user_ctl_poe_init_attr *init_attr;
	uint8_t poe_channel;
};

struct hns3_udma_user_ctl_config_notify_attr {
	uint64_t notify_addr;
	uint64_t reserved;
};

struct hns3_udma_user_ctl_query_hw_id_out {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t func_id;
	uint32_t reserved;
};

enum hns3_udma_k_user_ctl_opcode {
	HNS3_UDMA_K_USER_CTL_CONFIG_POE_CHANNEL,
	HNS3_UDMA_K_USER_CTL_CONFIG_NOTIFY_ATTR,
	HNS3_UDMA_K_USER_CTL_QUERY_HW_ID,
	HNS3_UDMA_K_USER_CTL_OPCODE_NUM,
};

#endif /* _HNS3_UDMA_USER_CTL_API_H */
